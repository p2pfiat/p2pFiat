//! Crash-safe JSON storage for registered watchtower exit packages and
//! per-contract fee / bounty accounting.

use crate::bounty::BountySpec;
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExitPayout {
    /// Outcome label or binary prefix (e.g. `"BTCUSD-settles-up"` or `"010110"`).
    pub outcome: String,
    /// Unsigned v2 exit transaction hex spending the contract VTXO outpoint.
    pub tx_hex: String,
    /// User's 64/65-byte adaptor signature hex (or completed signature if `precompleted` is true).
    pub user_adaptor_sig: String,
    /// LP's 64/65-byte adaptor signature hex (or completed signature if `precompleted` is true).
    pub lp_adaptor_sig: String,
    #[serde(default)]
    pub precompleted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExitRefund {
    /// Unsigned v2 refund transaction hex with `nLockTime == refund_height`.
    pub tx_hex: String,
    /// Block height at which the refund becomes valid.
    pub refund_height: u32,
    /// Full 64-byte Schnorr signature hex from the user.
    pub user_sig: String,
    /// Full 64-byte Schnorr signature hex from the LP.
    pub lp_sig: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DisputeOracleEntry {
    #[serde(default)]
    pub name: Option<String>,
    /// Oracle x-only secp256k1 / Nostr pubkey (64 hex chars).
    pub pubkey: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DisputeQuorum {
    pub threshold: usize,
    pub oracles: Vec<DisputeOracleEntry>,
}

/// 2-party BIP-340 signed Contract Manifest binding immutable contract terms and payout scripts
/// for autonomous Leaf 2 (`k-of-n` Nostracle) On-Demand Mid-Term Disputes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DisputeManifest {
    pub contract_id: String,
    pub vtxo_outpoint: String,
    pub currency: String,
    #[serde(default = "default_dispute_side")]
    pub side: String,
    pub total_collateral_sats: u64,
    pub notional_fiat: f64,
    pub opened_at: u64,
    pub funding_rate_bps_per_day: f64,
    pub user_pubkey_hex: String,
    pub lp_pubkey_hex: String,
    pub vtxo_pk_script_hex: String,
    /// The primary dispute leaf. In a v1 manifest this is the only committed leaf.
    pub dispute_script_hex: String,
    pub user_payout_script_hex: String,
    pub lp_payout_script_hex: String,
    pub user_manifest_sig_hex: String,
    pub lp_manifest_sig_hex: String,
    /// `1` (commits to `dispute_script_hex`) or `2` (commits to `dispute_leaf_hashes_hex`).
    #[serde(default = "default_manifest_version")]
    pub manifest_version: u8,
    /// v2: BIP-341 leaf hashes of every committed k-of-n subset dispute leaf.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dispute_leaf_hashes_hex: Vec<String>,
}

fn default_manifest_version() -> u8 {
    1
}

/// One k-of-n subset dispute leaf and its control block in the contract taptree.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DisputeLeafSpec {
    pub script_hex: String,
    pub control_block_hex: String,
}

fn default_dispute_side() -> String {
    "short".to_string()
}

/// Leaf 2 BIP-342 `k-of-n` Nostracle On-Demand Dispute specification attached to a WatchtowerPackage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DisputePackageSpec {
    pub script_hex: String,
    pub control_block_hex: String,
    pub csv_sequence: u32,
    pub oracle_quorum: DisputeQuorum,
    #[serde(default)]
    pub manifest: Option<DisputeManifest>,
    /// Every committed dispute leaf (manifest v2). Empty for older packages: then only
    /// `script_hex` / `control_block_hex` is usable.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub leaves: Vec<DisputeLeafSpec>,
}

/// Everything a keyless watchtower receives at contract opening.
/// Contains ZERO user or LP private keys.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WatchtowerPackage {
    pub id: String,
    pub vtxo_outpoint: String,
    pub vtxo_amount_sats: u64,
    pub vtxo_pk_script: String,
    pub ark_indexer_url: Option<String>,
    pub unroll_txs: Vec<String>,
    pub exit_script: String,
    pub exit_control_block: String,
    pub user_pubkey: String,
    pub lp_pubkey: String,
    /// Relative block CSV delay on the contract exit leaf (ignored when `exit_csv_seconds` is set).
    pub exit_csv: u16,
    /// Optional BIP-68 time-based CSV delay in seconds (e.g. `2048` on Arkade Mutinynet,
    /// which enforces time-based CSV on custom exit closures).
    #[serde(default)]
    pub exit_csv_seconds: Option<u32>,
    pub bounty: BountySpec,
    /// External DLC oracle pubkey (hex x-only or npub) whose kind-88/89 events
    /// settle this contract. Keeps the oracle completely separate from the watchtower.
    #[serde(default)]
    pub oracle_pubkey: Option<String>,
    /// DLC oracle event id (e.g. `btcusd-1798000000`).
    pub oracle_event_id: Option<String>,
    #[serde(default)]
    pub payouts: Vec<ExitPayout>,
    pub refund: Option<ExitRefund>,
    /// Optional Leaf 2 BIP-342 `k-of-n` Nostracle On-Demand Mid-Term Dispute package.
    #[serde(default)]
    pub dispute: Option<DisputePackageSpec>,
    #[serde(default)]
    pub trigger_height: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum WatchState {
    Watching,
    Unrolling {
        hops_done: usize,
        #[serde(default)]
        last_cpfp_txid: Option<String>,
    },
    VtxoConfirmed { vtxo_txid: String },
    ExitBroadcast {
        exit_txid: String,
        bounty_vout: u32,
        is_refund: bool,
    },
    BountySwept {
        exit_txid: String,
        sweep_txid: String,
        net_profit_sats: i64,
    },
    SettledOffchain,
    SpentOnchain,
    SkippedUnprofitable { estimated_cost_sats: u64, bounty_sats: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchedContract {
    pub package: WatchtowerPackage,
    pub state: WatchState,
    pub registered_at: u64,
    pub updated_at: u64,
    pub cpfp_fees_spent: u64,
    pub cpfp_txs_sent: u32,
    pub sweep_fee_spent: u64,
    pub bounty_earned: u64,
    #[serde(default)]
    pub last_error: Option<String>,
    /// The first dispute attempt's inputs. A Nostracle that signed a dispute tx refuses every
    /// other tx for that coin, so retries must rebuild exactly the same tx from these values.
    #[serde(default)]
    pub pending_dispute: Option<PendingDispute>,
}

/// Inputs that fix the dispute tx (with the package's manifest and bounty).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PendingDispute {
    pub dispute_timestamp: u64,
    pub live_spot: f64,
}

impl WatchedContract {
    pub fn net_profit_sats(&self) -> i64 {
        self.bounty_earned as i64 - self.cpfp_fees_spent as i64 - self.sweep_fee_spent as i64
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct StoreState {
    contracts: BTreeMap<String, WatchedContract>,
    #[serde(default)]
    total_cpfp_fees_spent: u64,
    #[serde(default)]
    total_sweep_fees_spent: u64,
    #[serde(default)]
    total_bounties_earned: u64,
    /// One-time Mutinynet/testnet faucet claims keyed by requester Nostr pubkey hex -> txid.
    #[serde(default)]
    faucet_claims: BTreeMap<String, String>,
}

pub struct WatchtowerStorage {
    path: PathBuf,
    state: Mutex<StoreState>,
}

impl WatchtowerStorage {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let state = if path.exists() {
            let bytes = std::fs::read(&path).with_context(|| format!("read {path:?}"))?;
            serde_json::from_slice(&bytes).with_context(|| format!("parse {path:?}"))?
        } else {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            StoreState::default()
        };
        Ok(Self { path, state: Mutex::new(state) })
    }

    fn persist(&self, state: &StoreState) -> Result<()> {
        let tmp = self.path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(state)?;
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    pub fn insert(&self, package: WatchtowerPackage, now: u64) -> Result<bool> {
        let mut st = self.state.lock().unwrap();
        if st.contracts.contains_key(&package.id) {
            return Ok(false);
        }
        let id = package.id.clone();
        st.contracts.insert(
            id,
            WatchedContract {
                package,
                state: WatchState::Watching,
                registered_at: now,
                updated_at: now,
                cpfp_fees_spent: 0,
                cpfp_txs_sent: 0,
                sweep_fee_spent: 0,
                bounty_earned: 0,
                last_error: None,
                pending_dispute: None,
            },
        );
        self.persist(&st)?;
        Ok(true)
    }

    pub fn get(&self, id: &str) -> Option<WatchedContract> {
        self.state.lock().unwrap().contracts.get(id).cloned()
    }

    pub fn list(&self) -> Vec<WatchedContract> {
        self.state.lock().unwrap().contracts.values().cloned().collect()
    }

    pub fn update(&self, id: &str, f: impl FnOnce(&mut WatchedContract)) -> Result<WatchedContract> {
        let mut st = self.state.lock().unwrap();
        let (d_cpfp, d_sweep, d_bounty, out) = {
            let c = st
                .contracts
                .get_mut(id)
                .ok_or_else(|| anyhow!("unknown watched contract {id}"))?;
            let old_cpfp = c.cpfp_fees_spent;
            let old_sweep = c.sweep_fee_spent;
            let old_bounty = c.bounty_earned;
            f(c);
            (
                c.cpfp_fees_spent.saturating_sub(old_cpfp),
                c.sweep_fee_spent.saturating_sub(old_sweep),
                c.bounty_earned.saturating_sub(old_bounty),
                c.clone(),
            )
        };
        st.total_cpfp_fees_spent += d_cpfp;
        st.total_sweep_fees_spent += d_sweep;
        st.total_bounties_earned += d_bounty;
        self.persist(&st)?;
        Ok(out)
    }

    pub fn totals(&self) -> (u64, u64, u64) {
        let st = self.state.lock().unwrap();
        (st.total_cpfp_fees_spent, st.total_sweep_fees_spent, st.total_bounties_earned)
    }

    pub fn get_faucet_claim(&self, sender_hex: &str) -> Option<String> {
        let key = sender_hex.trim().to_lowercase();
        self.state.lock().unwrap().faucet_claims.get(&key).cloned()
    }

    pub fn record_faucet_claim(&self, sender_hex: &str, txid: &str) -> Result<()> {
        let key = sender_hex.trim().to_lowercase();
        let mut st = self.state.lock().unwrap();
        st.faucet_claims.insert(key, txid.to_string());
        self.persist(&st)?;
        Ok(())
    }
}
