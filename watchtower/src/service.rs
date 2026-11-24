//! Core keyless watchtower state machine (p2pFiat Experiment 13).

use crate::adaptor::{attestation_outcome_string, finalize_exit_tx, sum_attestation_scalars, AdaptorSig};
use crate::bounty::{parse_xonly, BountyScript, WatchtowerRole};
use crate::client::{parse_outpoint, ArkIndexerClient, ArkVtxoState, ChainClient};
use crate::config::Config;
use crate::storage::{WatchState, WatchedContract, WatchtowerPackage, WatchtowerStorage};
use crate::wallet::WatchtowerWallet;
use anyhow::{anyhow, ensure, Context, Result};
use kormir::bitcoin::consensus::encode::{deserialize, serialize_hex};
use kormir::bitcoin::taproot::ControlBlock;
use kormir::bitcoin::{OutPoint, ScriptBuf, Transaction};
use kormir::OracleAttestation;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const CPFP_CHILD_VBYTES: f64 = 165.0;
const SWEEP_TX_VBYTES: f64 = 140.0;

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// Messages sent to a watchtower over NIP-17 private messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WatchtowerRequest {
    RegisterPackage { package: Box<WatchtowerPackage> },
}

/// Replies sent by a watchtower over NIP-17 private messages.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WatchtowerReply {
    Registered { package_id: String, role: String, bounty_sats: u64 },
    Rejected { package_id: String, reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WatchtowerStatus {
    pub pubkey: String,
    pub address: String,
    pub packages_total: usize,
    pub watching: usize,
    pub unrolling: usize,
    pub waiting_exit: usize,
    pub waiting_sweep: usize,
    pub swept: usize,
    pub settled_offchain: usize,
    pub skipped_unprofitable: usize,
    pub total_cpfp_fees_spent: u64,
    pub total_sweep_fees_spent: u64,
    pub total_bounties_earned: u64,
    pub total_net_profit_sats: i64,
}

pub struct WatchtowerService {
    pub cfg: Config,
    pub wallet: WatchtowerWallet,
    pub storage: WatchtowerStorage,
    chain: Arc<dyn ChainClient>,
    indexer: Arc<dyn ArkIndexerClient>,
}

impl WatchtowerService {
    pub fn new(
        cfg: Config,
        wallet: WatchtowerWallet,
        storage: WatchtowerStorage,
        chain: Arc<dyn ChainClient>,
        indexer: Arc<dyn ArkIndexerClient>,
    ) -> Self {
        Self { cfg, wallet, storage, chain, indexer }
    }

    pub fn register_package(&self, pkg: WatchtowerPackage, now: u64) -> Result<WatchtowerRole> {
        ensure!(!pkg.id.trim().is_empty(), "package id must not be empty");
        ensure!(!pkg.unroll_txs.is_empty(), "unroll_txs must not be empty");
        ensure!(
            !pkg.payouts.is_empty() || pkg.refund.is_some(),
            "package must contain at least one payout or refund transaction"
        );
        parse_outpoint(&pkg.vtxo_outpoint)?;
        parse_xonly(&pkg.user_pubkey)?;
        parse_xonly(&pkg.lp_pubkey)?;
        hex::decode(&pkg.vtxo_pk_script).context("invalid vtxo_pk_script hex")?;
        hex::decode(&pkg.exit_script).context("invalid exit_script hex")?;
        let ctrl_bytes = hex::decode(&pkg.exit_control_block).context("invalid exit_control_block hex")?;
        ControlBlock::decode(&ctrl_bytes).map_err(|e| anyhow!("invalid exit control block: {e}"))?;

        let compiled = BountyScript::compile(pkg.bounty.clone())?;
        let role = compiled
            .role_of(&self.wallet.xonly_pubkey)
            .ok_or_else(|| anyhow!("watchtower pubkey {} is not in bounty script", self.wallet.xonly_pubkey))?;
        ensure!(
            pkg.bounty.amount_sats >= self.cfg.min_bounty_sats,
            "bounty {} sats is below configured minimum {} sats",
            pkg.bounty.amount_sats,
            self.cfg.min_bounty_sats
        );

        for (idx, raw) in pkg.unroll_txs.iter().enumerate() {
            let _: Transaction = decode_tx_hex(raw)
                .with_context(|| format!("invalid unroll_txs[{idx}]"))?;
        }

        let verify_exit_bounty = |label: &str, tx_hex: &str| -> Result<()> {
            let tx = decode_tx_hex(tx_hex).with_context(|| format!("invalid {label} tx"))?;
            let out = tx
                .output
                .get(pkg.bounty.vout as usize)
                .ok_or_else(|| anyhow!("{label} tx missing bounty output vout {}", pkg.bounty.vout))?;
            ensure!(
                out.value.to_sat() == pkg.bounty.amount_sats,
                "{label} tx bounty value {} != expected {}",
                out.value.to_sat(),
                pkg.bounty.amount_sats
            );
            ensure!(
                out.script_pubkey == compiled.script_pubkey,
                "{label} tx bounty script_pubkey does not match compiled tiered bounty script"
            );
            Ok(())
        };

        for p in &pkg.payouts {
            verify_exit_bounty(&format!("payout({})", p.outcome), &p.tx_hex)?;
            if !p.precompleted {
                AdaptorSig::from_hex(&p.user_adaptor_sig)?;
                AdaptorSig::from_hex(&p.lp_adaptor_sig)?;
            }
        }
        if let Some(r) = &pkg.refund {
            verify_exit_bounty("refund", &r.tx_hex)?;
        }

        self.storage.insert(pkg, now)?;
        Ok(role)
    }

    pub async fn estimate_cost(&self, pkg: &WatchtowerPackage) -> Result<(usize, u64, u64, u64)> {
        let mut remaining_hops = 0usize;
        for raw in &pkg.unroll_txs {
            let tx = decode_tx_hex(raw)?;
            let txid = tx.compute_txid().to_string();
            let confirmed = self
                .chain
                .tx_status(&txid)
                .await?
                .is_some_and(|s| s.confirmed);
            if !confirmed {
                remaining_hops += 1;
            }
        }
        let (cpfp_fee, sweep_fee) = self.current_fees().await;
        let total = (remaining_hops as u64)
            .saturating_mul(cpfp_fee)
            .saturating_add(sweep_fee);
        Ok((remaining_hops, cpfp_fee, sweep_fee, total))
    }

    async fn current_fees(&self) -> (u64, u64) {
        if let Ok(Some(sat_vb)) = self.chain.fee_rate_sat_vb(2).await {
            if sat_vb.is_finite() && sat_vb > 0.0 {
                let dyn_cpfp = (sat_vb * CPFP_CHILD_VBYTES).ceil() as u64;
                let dyn_sweep = (sat_vb * SWEEP_TX_VBYTES).ceil() as u64;
                return (
                    dyn_cpfp.max(self.cfg.cpfp_fee_sats),
                    dyn_sweep.max(self.cfg.sweep_fee_sats),
                );
            }
        }
        (self.cfg.cpfp_fee_sats, self.cfg.sweep_fee_sats)
    }

    pub async fn tick(
        &self,
        attestations: &HashMap<String, OracleAttestation>,
        now: u64,
    ) -> Result<()> {
        let tip = self.chain.tip_height().await.context("fetch bitcoin tip height")?;
        for contract in self.storage.list() {
            if let Err(e) = self.step_contract(&contract, tip, attestations, now).await {
                log::warn!("watchtower {}: {e:#}", contract.package.id);
                let _ = self.storage.update(&contract.package.id, |c| {
                    c.last_error = Some(format!("{e:#}"));
                    c.updated_at = now;
                });
            }
        }
        Ok(())
    }

    async fn step_contract(
        &self,
        contract: &WatchedContract,
        tip: u32,
        attestations: &HashMap<String, OracleAttestation>,
        now: u64,
    ) -> Result<()> {
        let pkg = &contract.package;
        match &contract.state {
            WatchState::BountySwept { .. }
            | WatchState::SettledOffchain
            | WatchState::SpentOnchain
            | WatchState::SkippedUnprofitable { .. } => return Ok(()),

            WatchState::Watching => {
                // 1. Stale exit guard.
                let indexer_url = pkg
                    .ark_indexer_url
                    .as_deref()
                    .or(self.cfg.ark_indexer_url.as_deref());
                let operator_state = if let Some(url) = indexer_url {
                    self.indexer
                        .check_vtxo(url, &pkg.vtxo_pk_script, &pkg.vtxo_outpoint)
                        .await?
                } else {
                    ArkVtxoState::OperatorUnreachable
                };

                match operator_state {
                    ArkVtxoState::SpentOffchain => {
                        log::info!("{}: already settled offchain; skipping exit", pkg.id);
                        self.storage.update(&pkg.id, |c| {
                            c.state = WatchState::SettledOffchain;
                            c.updated_at = now;
                            c.last_error = None;
                        })?;
                        return Ok(());
                    }
                    ArkVtxoState::Unspent => {
                        if pkg.trigger_height == 0 || tip < pkg.trigger_height {
                            return Ok(());
                        }
                    }
                    ArkVtxoState::OperatorUnreachable => {}
                }

                // 2. Check if already spent onchain.
                let vtxo_op = parse_outpoint(&pkg.vtxo_outpoint)?;
                let outspend = self
                    .chain
                    .outspend(&vtxo_op.txid.to_string(), vtxo_op.vout)
                    .await?;
                if outspend.spent {
                    log::info!("{}: VTXO already spent onchain", pkg.id);
                    self.storage.update(&pkg.id, |c| {
                        c.state = WatchState::SpentOnchain;
                        c.updated_at = now;
                    })?;
                    return Ok(());
                }

                // 3. Profitability guard.
                let (hops, _cpfp_fee, _sweep_fee, est_cost) = self.estimate_cost(pkg).await?;
                if est_cost.saturating_add(self.cfg.min_profit_sats) > pkg.bounty.amount_sats {
                    log::warn!(
                        "{}: unprofitable ({hops} hops, est cost {est_cost} + min profit {} > {} bounty); skipping",
                        pkg.id,
                        self.cfg.min_profit_sats,
                        pkg.bounty.amount_sats
                    );
                    self.storage.update(&pkg.id, |c| {
                        c.state = WatchState::SkippedUnprofitable {
                            estimated_cost_sats: est_cost,
                            bounty_sats: pkg.bounty.amount_sats,
                        };
                        c.updated_at = now;
                        c.last_error = None;
                    })?;
                    return Ok(());
                }

                self.storage.update(&pkg.id, |c| {
                    c.state = WatchState::Unrolling { hops_done: 0, last_cpfp_txid: None };
                    c.updated_at = now;
                    c.last_error = None;
                })?;
                let updated = self.storage.get(&pkg.id).unwrap();
                Box::pin(self.step_contract(&updated, tip, attestations, now)).await
            }

            WatchState::Unrolling { hops_done, last_cpfp_txid } => {
                if let Some(cpfp_txid) = last_cpfp_txid {
                    let confirmed = self
                        .chain
                        .tx_status(cpfp_txid)
                        .await?
                        .is_some_and(|s| s.confirmed);
                    if !confirmed {
                        return Ok(());
                    }
                }

                let mut next_unconfirmed: Option<(usize, String, Transaction)> = None;
                for (i, raw) in pkg.unroll_txs.iter().enumerate() {
                    let tx = decode_tx_hex(raw)?;
                    let txid = tx.compute_txid().to_string();
                    let confirmed = self
                        .chain
                        .tx_status(&txid)
                        .await?
                        .is_some_and(|s| s.confirmed);
                    if !confirmed {
                        next_unconfirmed = Some((i, raw.clone(), tx));
                        break;
                    }
                }

                let Some((hop_idx, parent_hex, parent_tx)) = next_unconfirmed else {
                    let vtxo_op = parse_outpoint(&pkg.vtxo_outpoint)?;
                    log::info!("{}: VTXO {} confirmed onchain", pkg.id, vtxo_op.txid);
                    self.storage.update(&pkg.id, |c| {
                        c.state = WatchState::VtxoConfirmed { vtxo_txid: vtxo_op.txid.to_string() };
                        c.updated_at = now;
                        c.last_error = None;
                    })?;
                    return Ok(());
                };

                let (_rem, cpfp_fee, _sweep_fee, est_remaining) = self.estimate_cost(pkg).await?;
                if contract.cpfp_fees_spent.saturating_add(est_remaining) > pkg.bounty.amount_sats {
                    log::warn!("{}: fee spike mid-unroll, pausing", pkg.id);
                    return Ok(());
                }

                let utxos = self.chain.get_utxos(&self.wallet.address.to_string()).await?;
                let fee_utxo = self.wallet.select_cpfp_utxo(&utxos, cpfp_fee)?;
                let (child_tx, _) = self.wallet.build_cpfp_child(&parent_tx, fee_utxo, cpfp_fee)?;
                let child_hex = serialize_hex(&child_tx);
                let child_txid = child_tx.compute_txid().to_string();

                self.chain.broadcast_package(&parent_hex, &child_hex).await?;
                log::info!(
                    "{}: broadcast unroll hop {}/{} (parent {}, cpfp {}, fee {} sats)",
                    pkg.id,
                    hop_idx + 1,
                    pkg.unroll_txs.len(),
                    parent_tx.compute_txid(),
                    child_txid,
                    cpfp_fee
                );

                self.storage.update(&pkg.id, |c| {
                    c.cpfp_fees_spent += cpfp_fee;
                    c.cpfp_txs_sent += 1;
                    c.state = WatchState::Unrolling {
                        hops_done: (*hops_done).max(hop_idx + 1),
                        last_cpfp_txid: Some(child_txid),
                    };
                    c.updated_at = now;
                    c.last_error = None;
                })?;
                Ok(())
            }

            WatchState::VtxoConfirmed { vtxo_txid } => {
                let vtxo_op = parse_outpoint(&pkg.vtxo_outpoint)?;
                let outspend = self.chain.outspend(vtxo_txid, vtxo_op.vout).await?;
                if outspend.spent {
                    if let Some(exit_txid) = outspend.txid {
                        self.storage.update(&pkg.id, |c| {
                            c.state = WatchState::ExitBroadcast {
                                exit_txid,
                                bounty_vout: pkg.bounty.vout,
                                is_refund: false,
                            };
                            c.updated_at = now;
                        })?;
                    } else {
                        self.storage.update(&pkg.id, |c| {
                            c.state = WatchState::SpentOnchain;
                            c.updated_at = now;
                        })?;
                    }
                    return Ok(());
                }

                let Some(st) = self.chain.tx_status(vtxo_txid).await? else { return Ok(()) };
                let Some(conf_h) = st.block_height else { return Ok(()) };
                if let Some(csv_secs) = pkg.exit_csv_seconds {
                    let Some(vtxo_time) = st.block_time else { return Ok(()) };
                    let tip_mtp = self.chain.tip_mediantime().await?;
                    if tip_mtp < vtxo_time.saturating_add(csv_secs as u64) {
                        return Ok(());
                    }
                } else {
                    let confs = tip.saturating_sub(conf_h).saturating_add(1);
                    if confs < pkg.exit_csv as u32 {
                        return Ok(());
                    }
                }

                let vtxo_script = ScriptBuf::from_bytes(hex::decode(&pkg.vtxo_pk_script)?);
                let exit_script = ScriptBuf::from_bytes(hex::decode(&pkg.exit_script)?);
                let exit_ctrl = ControlBlock::decode(&hex::decode(&pkg.exit_control_block)?)
                    .map_err(|e| anyhow!("decode exit control block: {e}"))?;
                let u_pub = parse_xonly(&pkg.user_pubkey)?;
                let l_pub = parse_xonly(&pkg.lp_pubkey)?;

                let mut finalized: Option<(Transaction, bool)> = None;
                if let Some(ev_id) = &pkg.oracle_event_id {
                    if let Some(att) = attestations.get(ev_id) {
                        let outcome_str = attestation_outcome_string(att);
                        if let Some(payout) = pkg
                            .payouts
                            .iter()
                            .find(|p| outcome_str.starts_with(&p.outcome))
                        {
                            let unsigned = decode_tx_hex(&payout.tx_hex)?;
                            let (u_sig, l_sig) = if payout.precompleted {
                                (
                                    parse_schnorr_sig(&payout.user_adaptor_sig)?,
                                    parse_schnorr_sig(&payout.lp_adaptor_sig)?,
                                )
                            } else {
                                let prefix_len = if att.outcomes.len() == 1 {
                                    1
                                } else {
                                    payout.outcome.len().min(att.signatures.len())
                                };
                                let scalar = sum_attestation_scalars(att, prefix_len)?;
                                let u_ad = AdaptorSig::from_hex(&payout.user_adaptor_sig)?;
                                let l_ad = AdaptorSig::from_hex(&payout.lp_adaptor_sig)?;
                                (u_ad.complete(&scalar)?, l_ad.complete(&scalar)?)
                            };
                            let tx = finalize_exit_tx(
                                &unsigned,
                                pkg.vtxo_amount_sats,
                                &vtxo_script,
                                &exit_script,
                                &exit_ctrl,
                                &u_pub,
                                &l_pub,
                                &u_sig,
                                &l_sig,
                            )?;
                            finalized = Some((tx, false));
                        }
                    }
                } else if let Some(payout) = pkg.payouts.iter().find(|p| p.precompleted) {
                    let unsigned = decode_tx_hex(&payout.tx_hex)?;
                    let u_sig = parse_schnorr_sig(&payout.user_adaptor_sig)?;
                    let l_sig = parse_schnorr_sig(&payout.lp_adaptor_sig)?;
                    let tx = finalize_exit_tx(
                        &unsigned,
                        pkg.vtxo_amount_sats,
                        &vtxo_script,
                        &exit_script,
                        &exit_ctrl,
                        &u_pub,
                        &l_pub,
                        &u_sig,
                        &l_sig,
                    )?;
                    finalized = Some((tx, false));
                }

                // Fallback to timelocked onchain refund if no attestation arrived by refund_height.
                if finalized.is_none() {
                    if let Some(refund) = &pkg.refund {
                        if tip >= refund.refund_height {
                            let unsigned = decode_tx_hex(&refund.tx_hex)?;
                            let u_sig = parse_schnorr_sig(&refund.user_sig)?;
                            let l_sig = parse_schnorr_sig(&refund.lp_sig)?;
                            let tx = finalize_exit_tx(
                                &unsigned,
                                pkg.vtxo_amount_sats,
                                &vtxo_script,
                                &exit_script,
                                &exit_ctrl,
                                &u_pub,
                                &l_pub,
                                &u_sig,
                                &l_sig,
                            )?;
                            finalized = Some((tx, true));
                        }
                    }
                }

                let Some((exit_tx, is_refund)) = finalized else {
                    return Ok(());
                };
                let exit_hex = serialize_hex(&exit_tx);
                let exit_txid = self.chain.broadcast_tx(&exit_hex).await?;
                log::info!(
                    "{}: broadcast {} exit tx {exit_txid}",
                    pkg.id,
                    if is_refund { "refund" } else { "DLC payout" }
                );
                self.storage.update(&pkg.id, |c| {
                    c.state = WatchState::ExitBroadcast {
                        exit_txid,
                        bounty_vout: pkg.bounty.vout,
                        is_refund,
                    };
                    c.updated_at = now;
                    c.last_error = None;
                })?;
                Ok(())
            }

            WatchState::ExitBroadcast { exit_txid, bounty_vout, .. } => {
                let outspend = self.chain.outspend(exit_txid, *bounty_vout).await?;
                if outspend.spent {
                    log::info!("{}: bounty output already spent", pkg.id);
                    self.storage.update(&pkg.id, |c| {
                        c.state = WatchState::SpentOnchain;
                        c.updated_at = now;
                    })?;
                    return Ok(());
                }

                let Some(st) = self.chain.tx_status(exit_txid).await? else { return Ok(()) };
                let Some(conf_h) = st.block_height else { return Ok(()) };
                let confs = tip.saturating_sub(conf_h).saturating_add(1);

                let compiled = BountyScript::compile(pkg.bounty.clone())?;
                let role = compiled
                    .role_of(&self.wallet.xonly_pubkey)
                    .ok_or_else(|| anyhow!("watchtower key not in bounty"))?;
                if let WatchtowerRole::Backup { csv_blocks } = role {
                    if confs < csv_blocks as u32 {
                        return Ok(());
                    }
                }

                let (_, sweep_fee) = self.current_fees().await;
                let bounty_op = OutPoint {
                    txid: exit_txid.parse().context("parse exit txid")?,
                    vout: *bounty_vout,
                };
                let sweep_tx = compiled.build_sweep_tx(
                    bounty_op,
                    self.wallet.keypair(),
                    self.wallet.script_pubkey.clone(),
                    sweep_fee,
                )?;
                let sweep_hex = serialize_hex(&sweep_tx);
                let sweep_txid = self.chain.broadcast_tx(&sweep_hex).await?;

                let exit_txid_owned = exit_txid.clone();
                let updated = self.storage.update(&pkg.id, |c| {
                    c.sweep_fee_spent += sweep_fee;
                    c.bounty_earned += pkg.bounty.amount_sats;
                    let net = c.net_profit_sats();
                    c.state = WatchState::BountySwept {
                        exit_txid: exit_txid_owned,
                        sweep_txid: sweep_txid.clone(),
                        net_profit_sats: net,
                    };
                    c.updated_at = now;
                    c.last_error = None;
                })?;
                log::info!(
                    "{}: swept {} sat bounty ({sweep_txid}), net profit = {:+} sats",
                    pkg.id,
                    pkg.bounty.amount_sats,
                    updated.net_profit_sats()
                );
                Ok(())
            }
        }
    }

    pub fn summary(&self) -> WatchtowerStatus {
        let mut s = WatchtowerStatus {
            pubkey: self.wallet.xonly_pubkey.to_string(),
            address: self.wallet.address.to_string(),
            ..Default::default()
        };
        for c in self.storage.list() {
            s.packages_total += 1;
            match c.state {
                WatchState::Watching => s.watching += 1,
                WatchState::Unrolling { .. } => s.unrolling += 1,
                WatchState::VtxoConfirmed { .. } => s.waiting_exit += 1,
                WatchState::ExitBroadcast { .. } => s.waiting_sweep += 1,
                WatchState::BountySwept { .. } => s.swept += 1,
                WatchState::SettledOffchain => s.settled_offchain += 1,
                WatchState::SkippedUnprofitable { .. } => s.skipped_unprofitable += 1,
                WatchState::SpentOnchain => {}
            }
        }
        let (cpfp, sweep, bounty) = self.storage.totals();
        s.total_cpfp_fees_spent = cpfp;
        s.total_sweep_fees_spent = sweep;
        s.total_bounties_earned = bounty;
        s.total_net_profit_sats = bounty as i64 - cpfp as i64 - sweep as i64;
        s
    }
}

pub fn decode_tx_hex(tx_hex: &str) -> Result<Transaction> {
    let bytes = hex::decode(tx_hex.trim()).context("tx is not valid hex")?;
    deserialize(&bytes).context("deserialize bitcoin transaction")
}

fn parse_schnorr_sig(hex_str: &str) -> Result<kormir::bitcoin::secp256k1::schnorr::Signature> {
    let bytes = hex::decode(hex_str.trim()).context("schnorr sig is not valid hex")?;
    kormir::bitcoin::secp256k1::schnorr::Signature::from_slice(&bytes)
        .map_err(|e| anyhow!("invalid schnorr sig: {e}"))
}
