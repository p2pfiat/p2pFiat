//! Integration tests for standalone `ark-watchtower` (p2pFiat Experiment 13).
//!
//! Scenarios:
//! 1. Tiered Taproot bounty script (W1 immediate, W2/W3 CSV(4), attacker rejected)
//! 2. Stale-exit guard (contract already settled offchain on Ark indexer)
//! 3. Profitability guard (fee spike exceeds bounty -> refuse to unroll)
//! 4. Primary watchtower W1 unrolls 3 hops with TRUC v3 CPFP, completes real
//!    kormir numeric DLC adaptor signatures, broadcasts payout, sweeps bounty (+2,800 sats net)
//! 5. Backup watchtower W2 steps in when W1 is offline, blocked before CSV(4), claims at CSV(4) (+2,800 sats net)
//! 6. Operator & oracle both gone: W1 executes timelocked onchain refund and claims bounty (+2,800 sats net)
//! 7. Full decoupled Nostr flow on a local MockRelay:
//!    - Independent external oracle publishes kind-88 announcement & kind-89 attestation
//!    - User registers WatchtowerPackage privately via NIP-17 DM
//!    - Watchtower verifies external kind-88/89 events from relay, unrolls, settles DLC, sweeps bounty

use anyhow::Result;
use ark_watchtower::bounty::{nums_internal_key, BountyScript, BountySpec, WatchtowerRole};
use ark_watchtower::client::{ArkIndexerClient, ArkVtxoState, BoxFuture, ChainClient, OutspendStatus, TxStatus};
use ark_watchtower::config::Config;
use ark_watchtower::nostr_io::{self, KIND_ANNOUNCEMENT, KIND_ATTESTATION};
use ark_watchtower::service::{WatchtowerReply, WatchtowerRequest, WatchtowerService};
use ark_watchtower::storage::{ExitPayout, ExitRefund, WatchState, WatchtowerPackage, WatchtowerStorage};
use ark_watchtower::wallet::{WalletUtxo, WatchtowerWallet, P2A_SCRIPT_BYTES};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use kormir::bitcoin::absolute::LockTime;
use kormir::bitcoin::consensus::encode::{deserialize, serialize_hex};
use kormir::bitcoin::hashes::{sha256, Hash, HashEngine};
use kormir::bitcoin::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGADD, OP_CSV, OP_DROP, OP_EQUAL};
use kormir::bitcoin::script::Builder;
use kormir::bitcoin::secp256k1::{Keypair, Message, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};
use kormir::bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use kormir::bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash, TaprootBuilder};
use kormir::bitcoin::transaction::Version;
use kormir::bitcoin::{Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use kormir::storage::MemoryStorage;
use kormir::{Oracle, Writeable};
use nostr_relay_builder::MockRelay;
use nostr_sdk::prelude::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const CONTRACT_AMOUNT: u64 = 25_000;
const EXIT_TX_FEE: u64 = 500;
const BOUNTY_AMOUNT: u64 = 5_000;
const CPFP_FEE: u64 = 600;
const SWEEP_FEE: u64 = 400;
const BACKUP_CSV: u16 = 4;
const EXIT_CSV: u16 = 20;

#[derive(Default)]
struct ChainState {
    tip: u32,
    tip_time: u64,
    fee_rate_sat_vb: Option<f64>,
    utxos: HashMap<String, Vec<WalletUtxo>>,
    tx_status: HashMap<String, TxStatus>,
    txs: HashMap<String, Transaction>,
    outspends: HashMap<(String, u32), OutspendStatus>,
    bounty_validator: Option<BountyScript>,
}

struct MockChain {
    state: Mutex<ChainState>,
}

impl MockChain {
    fn new(tip: u32) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(ChainState { tip, tip_time: 1_700_000_000, ..Default::default() }),
        })
    }

    fn advance_time(&self, secs: u64) {
        self.state.lock().unwrap().tip_time += secs;
    }

    fn set_bounty_validator(&self, bounty: BountyScript) {
        self.state.lock().unwrap().bounty_validator = Some(bounty);
    }

    fn set_fee_rate(&self, sat_vb: Option<f64>) {
        self.state.lock().unwrap().fee_rate_sat_vb = sat_vb;
    }

    fn fund_wallet(&self, wallet: &WatchtowerWallet, sats: u64, seed: u8) {
        let mut st = self.state.lock().unwrap();
        let txid = Txid::from_byte_array([seed; 32]);
        st.utxos.entry(wallet.address.to_string()).or_default().push(WalletUtxo {
            outpoint: OutPoint { txid, vout: 0 },
            value_sats: sats,
            confirmed: true,
            is_v3: false,
        });
    }

    fn mine_blocks(&self, n: u32) {
        let mut st = self.state.lock().unwrap();
        st.tip += n;
        st.tip_time += (n as u64) * 30;
        let tip = st.tip;
        let tip_time = st.tip_time;
        for status in st.tx_status.values_mut() {
            if !status.confirmed {
                status.confirmed = true;
                status.block_height = Some(tip);
                status.block_time = Some(tip_time);
            }
        }
        for list in st.utxos.values_mut() {
            for u in list.iter_mut() {
                u.confirmed = true;
            }
        }
    }

    fn wallet_balance(&self, wallet: &WatchtowerWallet) -> u64 {
        let st = self.state.lock().unwrap();
        st.utxos
            .get(&wallet.address.to_string())
            .map(|v| v.iter().map(|u| u.value_sats).sum())
            .unwrap_or(0)
    }

    fn record_tx(st: &mut ChainState, tx: &Transaction) {
        let txid = tx.compute_txid().to_string();
        for inp in &tx.input {
            let prev = (inp.previous_output.txid.to_string(), inp.previous_output.vout);
            st.outspends.insert(prev, OutspendStatus { spent: true, txid: Some(txid.clone()) });
            for list in st.utxos.values_mut() {
                list.retain(|u| u.outpoint != inp.previous_output);
            }
        }
        for (vout, out) in tx.output.iter().enumerate() {
            if let Ok(addr) = kormir::bitcoin::Address::from_script(&out.script_pubkey, Network::Regtest) {
                let addr_s = addr.to_string();
                if st.utxos.contains_key(&addr_s) {
                    st.utxos.get_mut(&addr_s).unwrap().push(WalletUtxo {
                        outpoint: OutPoint { txid: tx.compute_txid(), vout: vout as u32 },
                        value_sats: out.value.to_sat(),
                        confirmed: false,
                        is_v3: tx.version == Version(3),
                    });
                }
            }
        }
        st.tx_status.insert(txid.clone(), TxStatus { confirmed: false, block_height: None, block_time: None });
        st.txs.insert(txid, tx.clone());
    }
}

impl ChainClient for MockChain {
    fn tip_height(&self) -> BoxFuture<'_, u32> {
        let tip = self.state.lock().unwrap().tip;
        Box::pin(async move { Ok(tip) })
    }

    fn tip_mediantime(&self) -> BoxFuture<'_, u64> {
        let t = self.state.lock().unwrap().tip_time;
        Box::pin(async move { Ok(t) })
    }

    fn get_utxos(&self, address: &str) -> BoxFuture<'_, Vec<WalletUtxo>> {
        let list = self.state.lock().unwrap().utxos.get(address).cloned().unwrap_or_default();
        Box::pin(async move { Ok(list) })
    }

    fn tx_status(&self, txid: &str) -> BoxFuture<'_, Option<TxStatus>> {
        let s = self.state.lock().unwrap().tx_status.get(txid).cloned();
        Box::pin(async move { Ok(s) })
    }

    fn outspend(&self, txid: &str, vout: u32) -> BoxFuture<'_, OutspendStatus> {
        let s = self
            .state
            .lock()
            .unwrap()
            .outspends
            .get(&(txid.to_string(), vout))
            .cloned()
            .unwrap_or(OutspendStatus { spent: false, txid: None });
        Box::pin(async move { Ok(s) })
    }

    fn fee_rate_sat_vb(&self, _target_blocks: u16) -> BoxFuture<'_, Option<f64>> {
        let r = self.state.lock().unwrap().fee_rate_sat_vb;
        Box::pin(async move { Ok(r) })
    }

    fn broadcast_tx(&self, tx_hex: &str) -> BoxFuture<'_, String> {
        let res = (|| -> Result<String> {
            let tx: Transaction = deserialize(&hex::decode(tx_hex)?)?;
            let mut st = self.state.lock().unwrap();
            if let LockTime::Blocks(h) = tx.lock_time {
                anyhow::ensure!(
                    st.tip >= h.to_consensus_u32(),
                    "non-final: tip {} < nLockTime {}",
                    st.tip,
                    h.to_consensus_u32()
                );
            }
            if let Some(bounty) = &st.bounty_validator {
                let prev_txid = tx.input[0].previous_output.txid.to_string();
                let prev_vout = tx.input[0].previous_output.vout;
                if let Some(prev_tx) = st.txs.get(&prev_txid) {
                    if let Some(prev_out) = prev_tx.output.get(prev_vout as usize) {
                        if prev_out.script_pubkey == bounty.script_pubkey {
                            let confs = st
                                .tx_status
                                .get(&prev_txid)
                                .and_then(|s| s.block_height)
                                .map(|h| st.tip.saturating_sub(h).saturating_add(1))
                                .unwrap_or(0);
                            bounty.verify_sweep_tx(&tx, confs)?;
                        }
                    }
                }
            }
            let txid = tx.compute_txid().to_string();
            Self::record_tx(&mut st, &tx);
            Ok(txid)
        })();
        Box::pin(async move { res })
    }

    fn broadcast_package(&self, parent_hex: &str, child_hex: &str) -> BoxFuture<'_, String> {
        let res = (|| -> Result<String> {
            let parent: Transaction = deserialize(&hex::decode(parent_hex)?)?;
            let child: Transaction = deserialize(&hex::decode(child_hex)?)?;
            anyhow::ensure!(child.version == Version(3), "CPFP child must be TRUC v3");
            let mut st = self.state.lock().unwrap();
            let p_txid = parent.compute_txid().to_string();
            Self::record_tx(&mut st, &parent);
            Self::record_tx(&mut st, &child);
            Ok(p_txid)
        })();
        Box::pin(async move { res })
    }
}

struct MockArkIndexer {
    state: Mutex<ArkVtxoState>,
}

impl MockArkIndexer {
    fn new(initial: ArkVtxoState) -> Arc<Self> {
        Arc::new(Self { state: Mutex::new(initial) })
    }
}

impl ArkIndexerClient for MockArkIndexer {
    fn check_vtxo(&self, _url: &str, _pk: &str, _op: &str) -> BoxFuture<'_, ArkVtxoState> {
        let s = *self.state.lock().unwrap();
        Box::pin(async move { Ok(s) })
    }
}

fn tagged_hash(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag.as_bytes());
    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_byte_array());
    engine.input(tag_hash.as_byte_array());
    for p in parts {
        engine.input(p);
    }
    sha256::Hash::from_engine(engine).to_byte_array()
}

fn adaptor_sign(
    signer: &Keypair,
    msg: &[u8; 32],
    anticipation_point: &PublicKey,
    nonce_seed: u8,
) -> String {
    let secp = Secp256k1::new();
    let (pub_xonly, pub_parity) = signer.x_only_public_key();
    let mut d = SecretKey::from_keypair(signer);
    if pub_parity == kormir::bitcoin::secp256k1::Parity::Odd {
        d = d.negate();
    }

    let mut k = SecretKey::from_slice(&[nonce_seed; 32]).unwrap();
    let k_pub = PublicKey::from_secret_key(&secp, &k);
    let r_eff = k_pub.combine(anticipation_point).unwrap();
    let (_, r_parity) = r_eff.x_only_public_key();
    if r_parity == kormir::bitcoin::secp256k1::Parity::Odd {
        for bump in 1u8..=255 {
            let mut seed = [nonce_seed; 32];
            seed[0] = seed[0].wrapping_add(bump);
            let k2 = SecretKey::from_slice(&seed).unwrap();
            let r2 = PublicKey::from_secret_key(&secp, &k2).combine(anticipation_point).unwrap();
            if r2.x_only_public_key().1 == kormir::bitcoin::secp256k1::Parity::Even {
                k = k2;
                break;
            }
        }
    }
    let r_eff = PublicKey::from_secret_key(&secp, &k).combine(anticipation_point).unwrap();
    let (r_xonly, r_parity) = r_eff.x_only_public_key();
    assert_eq!(r_parity, kormir::bitcoin::secp256k1::Parity::Even);

    let e_bytes = tagged_hash("BIP0340/challenge", &[&r_xonly.serialize(), &pub_xonly.serialize(), msg]);
    let e_scalar = Scalar::from_be_bytes(e_bytes).unwrap();
    let ed = d.mul_tweak(&e_scalar).unwrap();
    let ed_scalar = Scalar::from_be_bytes(ed.secret_bytes()).unwrap();
    let s_prime = k.add_tweak(&ed_scalar).unwrap();

    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&r_xonly.serialize());
    out[32..64].copy_from_slice(&s_prime.secret_bytes());
    hex::encode(out)
}

fn kormir_anticipation_point(
    oracle_pub: &XOnlyPublicKey,
    nonces: &[XOnlyPublicKey],
    outcomes: &[&str],
) -> PublicKey {
    let secp = Secp256k1::new();
    let p_even = PublicKey::from_x_only_public_key(*oracle_pub, kormir::bitcoin::secp256k1::Parity::Even);
    let mut sum: Option<PublicKey> = None;
    for (nonce, outcome) in nonces.iter().zip(outcomes.iter()) {
        let r_even = PublicKey::from_x_only_public_key(*nonce, kormir::bitcoin::secp256k1::Parity::Even);
        let msg = tagged_hash("DLC/oracle/attestation/v0", &[outcome.as_bytes()]);
        let e = tagged_hash("BIP0340/challenge", &[&nonce.serialize(), &oracle_pub.serialize(), &msg]);
        let e_scalar = Scalar::from_be_bytes(e).unwrap();
        let ep = p_even.mul_tweak(&secp, &e_scalar).unwrap();
        let s_point = r_even.combine(&ep).unwrap();
        sum = Some(match sum {
            None => s_point,
            Some(acc) => acc.combine(&s_point).unwrap(),
        });
    }
    sum.unwrap()
}

fn build_contract_fixture(
    id: &str,
    bounty_spec: BountySpec,
    oracle_pubkey: Option<String>,
    oracle_event_id: Option<String>,
    anticipation_point: Option<(String, PublicKey)>,
    refund_height: u32,
    seed: u8,
) -> WatchtowerPackage {
    let secp = Secp256k1::new();
    let u_kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[seed.wrapping_add(10); 32]).unwrap());
    let l_kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[seed.wrapping_add(20); 32]).unwrap());
    let (u_pub, _) = u_kp.x_only_public_key();
    let (l_pub, _) = l_kp.x_only_public_key();

    let exit_script = Builder::new()
        .push_int(EXIT_CSV as i64)
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_x_only_key(&u_pub)
        .push_opcode(OP_CHECKSIG)
        .push_x_only_key(&l_pub)
        .push_opcode(OP_CHECKSIGADD)
        .push_int(2)
        .push_opcode(OP_EQUAL)
        .into_script();

    let spend_info = TaprootBuilder::new()
        .add_leaf(0, exit_script.clone())
        .unwrap()
        .finalize(&secp, nums_internal_key())
        .unwrap();
    let vtxo_pk_script = ScriptBuf::new_p2tr_tweaked(spend_info.output_key());
    let exit_ctrl: ControlBlock = spend_info
        .control_block(&(exit_script.clone(), LeafVersion::TapScript))
        .unwrap();

    let p2a = ScriptBuf::from_bytes(P2A_SCRIPT_BYTES.to_vec());
    let mut unroll_txs = Vec::new();
    let mut prev_txid = Txid::from_byte_array([seed.wrapping_add(1); 32]);
    for hop in 0..3u32 {
        let out_script = if hop == 2 {
            vtxo_pk_script.clone()
        } else {
            ScriptBuf::new_p2tr(&secp, u_pub, None)
        };
        let tx = Transaction {
            version: Version(3),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: prev_txid, vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![
                TxOut { value: Amount::from_sat(CONTRACT_AMOUNT), script_pubkey: out_script },
                TxOut { value: Amount::ZERO, script_pubkey: p2a.clone() },
            ],
        };
        prev_txid = tx.compute_txid();
        unroll_txs.push(serialize_hex(&tx));
    }
    let vtxo_outpoint = OutPoint { txid: prev_txid, vout: 0 };

    let compiled_bounty = BountyScript::compile(bounty_spec.clone()).unwrap();
    let deduct = (EXIT_TX_FEE + BOUNTY_AMOUNT) / 2;
    let u_dest = ScriptBuf::new_p2tr(&secp, u_pub, None);
    let l_dest = ScriptBuf::new_p2tr(&secp, l_pub, None);

    let build_exit = |u_amt: u64, l_amt: u64, lock_time: LockTime| -> (Transaction, [u8; 32]) {
        let tx = Transaction {
            version: Version::TWO,
            lock_time,
            input: vec![TxIn {
                previous_output: vtxo_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::from_height(EXIT_CSV),
                witness: Witness::new(),
            }],
            output: vec![
                TxOut { value: Amount::from_sat(u_amt - deduct), script_pubkey: u_dest.clone() },
                TxOut { value: Amount::from_sat(l_amt - deduct), script_pubkey: l_dest.clone() },
                TxOut { value: Amount::from_sat(BOUNTY_AMOUNT), script_pubkey: compiled_bounty.script_pubkey.clone() },
            ],
        };
        let prevout = TxOut {
            value: Amount::from_sat(CONTRACT_AMOUNT),
            script_pubkey: vtxo_pk_script.clone(),
        };
        let leaf_hash = TapLeafHash::from_script(&exit_script, LeafVersion::TapScript);
        let sh = SighashCache::new(&tx)
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&[prevout]),
                leaf_hash,
                TapSighashType::Default,
            )
            .unwrap();
        let mut msg = [0u8; 32];
        msg.copy_from_slice(sh.as_ref());
        (tx, msg)
    };

    let mut payouts = Vec::new();
    if let Some((outcome_prefix, t_point)) = anticipation_point {
        let (tx, msg) = build_exit(17_000, 8_000, LockTime::ZERO);
        payouts.push(ExitPayout {
            outcome: outcome_prefix,
            tx_hex: serialize_hex(&tx),
            user_adaptor_sig: adaptor_sign(&u_kp, &msg, &t_point, seed.wrapping_add(31)),
            lp_adaptor_sig: adaptor_sign(&l_kp, &msg, &t_point, seed.wrapping_add(41)),
            precompleted: false,
        });
    }

    let (refund_tx, refund_msg) =
        build_exit(12_500, 12_500, LockTime::from_height(refund_height).unwrap());
    let m = Message::from_digest_slice(&refund_msg).unwrap();
    let u_refund_sig = secp.sign_schnorr_no_aux_rand(&m, &u_kp);
    let l_refund_sig = secp.sign_schnorr_no_aux_rand(&m, &l_kp);

    WatchtowerPackage {
        id: id.to_string(),
        vtxo_outpoint: format!("{}:0", vtxo_outpoint.txid),
        vtxo_amount_sats: CONTRACT_AMOUNT,
        vtxo_pk_script: hex::encode(vtxo_pk_script.as_bytes()),
        ark_indexer_url: Some("http://arkd.local".into()),
        unroll_txs,
        exit_script: hex::encode(exit_script.as_bytes()),
        exit_control_block: hex::encode(exit_ctrl.serialize()),
        user_pubkey: u_pub.to_string(),
        lp_pubkey: l_pub.to_string(),
        exit_csv: EXIT_CSV,
        exit_csv_seconds: None,
        bounty: bounty_spec,
        oracle_pubkey,
        oracle_event_id,
        payouts,
        refund: Some(ExitRefund {
            tx_hex: serialize_hex(&refund_tx),
            refund_height,
            user_sig: hex::encode(u_refund_sig.as_ref()),
            lp_sig: hex::encode(l_refund_sig.as_ref()),
        }),
        trigger_height: 0,
    }
}

fn wt_config(dir: &std::path::Path) -> Config {
    Config {
        wallet_key_file: dir.join("wt.key"),
        db_file: dir.join("wt.json"),
        network: "regtest".into(),
        esplora_url: "http://localhost:3000".into(),
        ark_indexer_url: Some("http://arkd.local".into()),
        relays: vec![],
        cpfp_fee_sats: CPFP_FEE,
        sweep_fee_sats: SWEEP_FEE,
        min_bounty_sats: 2_000,
        min_profit_sats: 500,
        tick_secs: 30,
        accept_nostr_packages: true,
    }
}

#[test]
fn bounty_script_primary_backup_and_attacker() {
    let w1 = WatchtowerWallet::from_secret(SecretKey::from_slice(&[1u8; 32]).unwrap(), Network::Regtest);
    let w2 = WatchtowerWallet::from_secret(SecretKey::from_slice(&[2u8; 32]).unwrap(), Network::Regtest);
    let w3 = WatchtowerWallet::from_secret(SecretKey::from_slice(&[3u8; 32]).unwrap(), Network::Regtest);
    let attacker = WatchtowerWallet::from_secret(SecretKey::from_slice(&[99u8; 32]).unwrap(), Network::Regtest);

    let spec = BountySpec {
        amount_sats: BOUNTY_AMOUNT,
        vout: 2,
        primary_pubkey: w1.xonly_pubkey.to_string(),
        backup_pubkeys: vec![w2.xonly_pubkey.to_string(), w3.xonly_pubkey.to_string()],
        backup_csv: BACKUP_CSV,
    };
    let bounty = BountyScript::compile(spec).unwrap();
    let op = OutPoint { txid: Txid::from_byte_array([7u8; 32]), vout: 2 };

    let w1_sweep = bounty.build_sweep_tx(op, w1.keypair(), w1.script_pubkey.clone(), SWEEP_FEE).unwrap();
    assert_eq!(bounty.verify_sweep_tx(&w1_sweep, 0).unwrap(), WatchtowerRole::Primary);

    let bad = bounty
        .build_sweep_tx_for_role(op, attacker.keypair(), WatchtowerRole::Primary, attacker.script_pubkey.clone(), SWEEP_FEE)
        .unwrap();
    assert!(bounty.verify_sweep_tx(&bad, 100).unwrap_err().to_string().contains("mempool-script-verify-flag-failed"));

    let w2_sweep = bounty.build_sweep_tx(op, w2.keypair(), w2.script_pubkey.clone(), SWEEP_FEE).unwrap();
    assert!(bounty.verify_sweep_tx(&w2_sweep, 0).unwrap_err().to_string().contains("non-BIP68-final"));
    assert!(bounty.verify_sweep_tx(&w2_sweep, 3).is_err());
    assert_eq!(bounty.verify_sweep_tx(&w2_sweep, 4).unwrap(), WatchtowerRole::Backup { csv_blocks: 4 });
}

#[tokio::test(flavor = "current_thread")]
async fn stale_exit_guard_skips_settled_contract() {
    let dir = tempfile::tempdir().unwrap();
    let w1 = WatchtowerWallet::from_secret(SecretKey::from_slice(&[1u8; 32]).unwrap(), Network::Regtest);
    let chain = MockChain::new(100);
    chain.fund_wallet(&w1, 1_000_000, 1);
    let indexer = MockArkIndexer::new(ArkVtxoState::SpentOffchain);

    let spec = BountySpec {
        amount_sats: BOUNTY_AMOUNT,
        vout: 2,
        primary_pubkey: w1.xonly_pubkey.to_string(),
        backup_pubkeys: vec![],
        backup_csv: BACKUP_CSV,
    };
    let pkg = build_contract_fixture("settled-1", spec, None, None, None, 180, 1);
    let svc = WatchtowerService::new(
        wt_config(dir.path()),
        w1.clone(),
        WatchtowerStorage::open(dir.path().join("wt.json")).unwrap(),
        chain.clone(),
        indexer,
    );
    svc.register_package(pkg, 1000).unwrap();
    svc.tick(&HashMap::new(), 1001).await.unwrap();

    let rec = svc.storage.get("settled-1").unwrap();
    assert_eq!(rec.state, WatchState::SettledOffchain);
    assert_eq!(rec.cpfp_fees_spent, 0);
    assert_eq!(chain.wallet_balance(&w1), 1_000_000);
}

#[tokio::test(flavor = "current_thread")]
async fn profitability_guard_refuses_loss_making_unroll() {
    let dir = tempfile::tempdir().unwrap();
    let w1 = WatchtowerWallet::from_secret(SecretKey::from_slice(&[1u8; 32]).unwrap(), Network::Regtest);
    let chain = MockChain::new(100);
    chain.fund_wallet(&w1, 1_000_000, 2);
    chain.set_fee_rate(Some(20.0));
    let indexer = MockArkIndexer::new(ArkVtxoState::OperatorUnreachable);

    let spec = BountySpec {
        amount_sats: BOUNTY_AMOUNT,
        vout: 2,
        primary_pubkey: w1.xonly_pubkey.to_string(),
        backup_pubkeys: vec![],
        backup_csv: BACKUP_CSV,
    };
    let pkg = build_contract_fixture("fee-spike-1", spec, None, None, None, 180, 2);
    let svc = WatchtowerService::new(
        wt_config(dir.path()),
        w1.clone(),
        WatchtowerStorage::open(dir.path().join("wt.json")).unwrap(),
        chain.clone(),
        indexer,
    );
    svc.register_package(pkg, 1000).unwrap();
    svc.tick(&HashMap::new(), 1001).await.unwrap();

    let rec = svc.storage.get("fee-spike-1").unwrap();
    assert!(matches!(rec.state, WatchState::SkippedUnprofitable { .. }));
    assert_eq!(rec.cpfp_fees_spent, 0);
    assert_eq!(chain.wallet_balance(&w1), 1_000_000);
}

#[tokio::test(flavor = "current_thread")]
async fn primary_watchtower_unrolls_settles_dlc_and_profits() {
    let dir = tempfile::tempdir().unwrap();
    let oracle_key = SecretKey::from_slice(&[7u8; 32]).unwrap();
    let oracle = Oracle::from_signing_key(MemoryStorage::default(), oracle_key).unwrap();
    let ann = oracle.create_numeric_event("btcusd-2000".into(), 20, false, 0, "USD".into(), 2000).await.unwrap();
    let att = oracle.sign_numeric_event("btcusd-2000".into(), 97_123).await.unwrap();
    let outcome_strs: Vec<&str> = att.outcomes[..10].iter().map(String::as_str).collect();
    let prefix = outcome_strs.concat();
    let t_point = kormir_anticipation_point(&ann.oracle_public_key, &ann.oracle_event.oracle_nonces[..10], &outcome_strs);

    let w1 = WatchtowerWallet::from_secret(SecretKey::from_slice(&[1u8; 32]).unwrap(), Network::Regtest);
    let w2 = WatchtowerWallet::from_secret(SecretKey::from_slice(&[2u8; 32]).unwrap(), Network::Regtest);
    let spec = BountySpec {
        amount_sats: BOUNTY_AMOUNT,
        vout: 2,
        primary_pubkey: w1.xonly_pubkey.to_string(),
        backup_pubkeys: vec![w2.xonly_pubkey.to_string()],
        backup_csv: BACKUP_CSV,
    };

    let chain = MockChain::new(100);
    chain.set_bounty_validator(BountyScript::compile(spec.clone()).unwrap());
    chain.fund_wallet(&w1, 1_000_000, 3);
    let indexer = MockArkIndexer::new(ArkVtxoState::OperatorUnreachable);

    let pkg = build_contract_fixture(
        "primary-dlc-1",
        spec,
        Some(ann.oracle_public_key.to_string()),
        Some("btcusd-2000".into()),
        Some((prefix, t_point)),
        250,
        3,
    );
    let svc = WatchtowerService::new(
        wt_config(dir.path()),
        w1.clone(),
        WatchtowerStorage::open(dir.path().join("wt.json")).unwrap(),
        chain.clone(),
        indexer,
    );
    assert_eq!(svc.register_package(pkg, 1000).unwrap(), WatchtowerRole::Primary);

    let mut atts = HashMap::new();
    atts.insert("btcusd-2000".to_string(), att);

    for _ in 0..3 {
        svc.tick(&atts, 1010).await.unwrap();
        chain.mine_blocks(1);
    }
    svc.tick(&atts, 1020).await.unwrap();
    chain.mine_blocks(EXIT_CSV as u32);
    svc.tick(&atts, 1030).await.unwrap();
    chain.mine_blocks(1);
    svc.tick(&atts, 1040).await.unwrap();
    chain.mine_blocks(1);

    let rec = svc.storage.get("primary-dlc-1").unwrap();
    assert!(matches!(rec.state, WatchState::BountySwept { net_profit_sats: 2800, .. }));
    assert_eq!(rec.cpfp_txs_sent, 3);
    assert_eq!(rec.cpfp_fees_spent, 1_800);
    assert_eq!(rec.sweep_fee_spent, 400);
    assert_eq!(rec.bounty_earned, 5_000);
    assert_eq!(chain.wallet_balance(&w1), 1_002_800);
}

#[tokio::test(flavor = "current_thread")]
async fn backup_watchtower_claims_after_csv_delay() {
    let dir = tempfile::tempdir().unwrap();
    let oracle_key = SecretKey::from_slice(&[8u8; 32]).unwrap();
    let oracle = Oracle::from_signing_key(MemoryStorage::default(), oracle_key).unwrap();
    let ann = oracle.create_numeric_event("btcusd-3000".into(), 20, false, 0, "USD".into(), 3000).await.unwrap();
    let att = oracle.sign_numeric_event("btcusd-3000".into(), 88_000).await.unwrap();
    let outcome_strs: Vec<&str> = att.outcomes[..8].iter().map(String::as_str).collect();
    let prefix = outcome_strs.concat();
    let t_point = kormir_anticipation_point(&ann.oracle_public_key, &ann.oracle_event.oracle_nonces[..8], &outcome_strs);

    let w1 = WatchtowerWallet::from_secret(SecretKey::from_slice(&[1u8; 32]).unwrap(), Network::Regtest);
    let w2 = WatchtowerWallet::from_secret(SecretKey::from_slice(&[2u8; 32]).unwrap(), Network::Regtest);
    let spec = BountySpec {
        amount_sats: BOUNTY_AMOUNT,
        vout: 2,
        primary_pubkey: w1.xonly_pubkey.to_string(),
        backup_pubkeys: vec![w2.xonly_pubkey.to_string()],
        backup_csv: BACKUP_CSV,
    };

    let chain = MockChain::new(200);
    chain.set_bounty_validator(BountyScript::compile(spec.clone()).unwrap());
    chain.fund_wallet(&w2, 1_000_000, 4);
    let indexer = MockArkIndexer::new(ArkVtxoState::OperatorUnreachable);

    let pkg = build_contract_fixture(
        "backup-dlc-1",
        spec,
        Some(ann.oracle_public_key.to_string()),
        Some("btcusd-3000".into()),
        Some((prefix, t_point)),
        350,
        4,
    );
    let svc = WatchtowerService::new(
        wt_config(dir.path()),
        w2.clone(),
        WatchtowerStorage::open(dir.path().join("wt.json")).unwrap(),
        chain.clone(),
        indexer,
    );
    assert_eq!(svc.register_package(pkg, 2000).unwrap(), WatchtowerRole::Backup { csv_blocks: BACKUP_CSV });

    let mut atts = HashMap::new();
    atts.insert("btcusd-3000".to_string(), att);

    for _ in 0..3 {
        svc.tick(&atts, 2010).await.unwrap();
        chain.mine_blocks(1);
    }
    svc.tick(&atts, 2020).await.unwrap();
    chain.mine_blocks(EXIT_CSV as u32);
    svc.tick(&atts, 2030).await.unwrap();
    chain.mine_blocks(1);

    // At 1 confirmation (< CSV 4), W2 must wait.
    svc.tick(&atts, 2040).await.unwrap();
    assert!(matches!(svc.storage.get("backup-dlc-1").unwrap().state, WatchState::ExitBroadcast { .. }));

    // At 4 confirmations (== CSV 4), W2 sweeps!
    chain.mine_blocks(3);
    svc.tick(&atts, 2050).await.unwrap();
    chain.mine_blocks(1);

    let rec = svc.storage.get("backup-dlc-1").unwrap();
    assert!(matches!(rec.state, WatchState::BountySwept { net_profit_sats: 2800, .. }));
    assert_eq!(chain.wallet_balance(&w2), 1_002_800);
}

#[tokio::test(flavor = "current_thread")]
async fn operator_and_oracle_gone_executes_refund_and_profits() {
    let dir = tempfile::tempdir().unwrap();
    let w1 = WatchtowerWallet::from_secret(SecretKey::from_slice(&[1u8; 32]).unwrap(), Network::Regtest);
    let spec = BountySpec {
        amount_sats: BOUNTY_AMOUNT,
        vout: 2,
        primary_pubkey: w1.xonly_pubkey.to_string(),
        backup_pubkeys: vec![],
        backup_csv: BACKUP_CSV,
    };

    let chain = MockChain::new(100);
    chain.set_bounty_validator(BountyScript::compile(spec.clone()).unwrap());
    chain.fund_wallet(&w1, 1_000_000, 5);
    let indexer = MockArkIndexer::new(ArkVtxoState::OperatorUnreachable);

    let refund_height = 160;
    let pkg = build_contract_fixture(
        "refund-1",
        spec,
        None,
        Some("btcusd-missed".into()),
        None,
        refund_height,
        5,
    );
    let svc = WatchtowerService::new(
        wt_config(dir.path()),
        w1.clone(),
        WatchtowerStorage::open(dir.path().join("wt.json")).unwrap(),
        chain.clone(),
        indexer,
    );
    svc.register_package(pkg, 3000).unwrap();

    for _ in 0..3 {
        svc.tick(&HashMap::new(), 3010).await.unwrap();
        chain.mine_blocks(1);
    }
    svc.tick(&HashMap::new(), 3020).await.unwrap();
    chain.mine_blocks(EXIT_CSV as u32);

    svc.tick(&HashMap::new(), 3030).await.unwrap();
    assert!(matches!(svc.storage.get("refund-1").unwrap().state, WatchState::VtxoConfirmed { .. }));

    chain.mine_blocks(40);
    svc.tick(&HashMap::new(), 3040).await.unwrap();
    assert!(matches!(svc.storage.get("refund-1").unwrap().state, WatchState::ExitBroadcast { is_refund: true, .. }));

    chain.mine_blocks(1);
    svc.tick(&HashMap::new(), 3050).await.unwrap();
    chain.mine_blocks(1);

    let rec = svc.storage.get("refund-1").unwrap();
    assert!(matches!(rec.state, WatchState::BountySwept { net_profit_sats: 2800, .. }));
    assert_eq!(chain.wallet_balance(&w1), 1_002_800);
}

#[tokio::test(flavor = "current_thread")]
async fn decoupled_external_oracle_and_nip17_flow_on_local_relay() {
    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    let dir = tempfile::tempdir().unwrap();

    // 1. Independent external oracle (completely separate key & process role from watchtower).
    let oracle_secret = SecretKey::from_slice(&[55u8; 32]).unwrap();
    let oracle = Oracle::from_signing_key(MemoryStorage::default(), oracle_secret).unwrap();
    let oracle_nostr_keys = oracle.nostr_keys();
    let ann = oracle.create_numeric_event("btcusd-9000".into(), 20, false, 0, "USD".into(), 9000).await.unwrap();
    let att = oracle.sign_numeric_event("btcusd-9000".into(), 102_400).await.unwrap();

    // External oracle publishes kind-88 announcement & kind-89 attestation on the relay.
    let oracle_client = nostr_io::connect_client(oracle_nostr_keys.clone(), &[url.clone()]).await.unwrap();
    let ann_ev = EventBuilder::new(Kind::Custom(KIND_ANNOUNCEMENT), B64.encode(ann.encode()))
        .sign_with_keys(&oracle_nostr_keys)
        .unwrap();
    let att_ev = EventBuilder::new(Kind::Custom(KIND_ATTESTATION), B64.encode(att.encode()))
        .tag(Tag::event(ann_ev.id))
        .sign_with_keys(&oracle_nostr_keys)
        .unwrap();
    oracle_client.send_event(&ann_ev).await.unwrap();
    oracle_client.send_event(&att_ev).await.unwrap();

    // 2. Independent watchtower W1 with its own key & P2TR wallet.
    let w1 = WatchtowerWallet::from_secret(SecretKey::from_slice(&[11u8; 32]).unwrap(), Network::Regtest);
    let wt_client = nostr_io::connect_client(w1.nostr_keys(), &[url.clone()]).await.unwrap();
    let spec = BountySpec {
        amount_sats: BOUNTY_AMOUNT,
        vout: 2,
        primary_pubkey: w1.xonly_pubkey.to_string(),
        backup_pubkeys: vec![],
        backup_csv: BACKUP_CSV,
    };
    let chain = MockChain::new(500);
    chain.set_bounty_validator(BountyScript::compile(spec.clone()).unwrap());
    chain.fund_wallet(&w1, 1_000_000, 9);
    let indexer = MockArkIndexer::new(ArkVtxoState::OperatorUnreachable);
    let svc = WatchtowerService::new(
        wt_config(dir.path()),
        w1.clone(),
        WatchtowerStorage::open(dir.path().join("wt.json")).unwrap(),
        chain.clone(),
        indexer,
    );

    // 3. User sends WatchtowerPackage privately via NIP-17 DM to watchtower W1.
    let outcome_strs: Vec<&str> = att.outcomes[..10].iter().map(String::as_str).collect();
    let prefix = outcome_strs.concat();
    let t_point = kormir_anticipation_point(&ann.oracle_public_key, &ann.oracle_event.oracle_nonces[..10], &outcome_strs);
    let pkg = build_contract_fixture(
        "decoupled-1",
        spec,
        Some(oracle_nostr_keys.public_key().to_hex()),
        Some("btcusd-9000".into()),
        Some((prefix, t_point)),
        700,
        9,
    );

    let user = Keys::generate();
    let user_client = nostr_io::connect_client(user.clone(), &[url.clone()]).await.unwrap();
    let req = WatchtowerRequest::RegisterPackage { package: Box::new(pkg) };
    user_client
        .send_private_msg(w1.nostr_keys().public_key(), serde_json::to_string(&req).unwrap(), [])
        .await
        .unwrap();

    // 4. Watchtower processes NIP-17 DM, fetches external oracle's kind-88/89 from relay, and settles!
    let t = ark_watchtower::service::now();
    let count = nostr_io::process_incoming_packages(&wt_client, &svc, t).await.unwrap();
    assert_eq!(count, 1);

    // Verify user got NIP-17 confirmation.
    let wraps = user_client
        .fetch_events(Filter::new().kind(Kind::GiftWrap).pubkey(user.public_key()), Duration::from_secs(3))
        .await
        .unwrap();
    let mut got_reply = None;
    for w in wraps.iter() {
        let Ok(g) = UnwrappedGift::from_gift_wrap(&user, w).await else { continue };
        if g.sender == w1.nostr_keys().public_key() {
            if let Ok(r) = serde_json::from_str::<WatchtowerReply>(&g.rumor.content) {
                got_reply = Some(r);
            }
        }
    }
    assert_eq!(
        got_reply,
        Some(WatchtowerReply::Registered {
            package_id: "decoupled-1".into(),
            role: "primary".into(),
            bounty_sats: BOUNTY_AMOUNT,
        })
    );

    // Fetch external oracle attestation from relay & run watchtower lifecycle to completion!
    let atts = nostr_io::fetch_external_attestations(&wt_client, &svc).await.unwrap();
    assert!(atts.contains_key("btcusd-9000"), "external oracle attestation must be fetched & verified");

    for _ in 0..3 {
        svc.tick(&atts, t).await.unwrap();
        chain.mine_blocks(1);
    }
    svc.tick(&atts, t).await.unwrap();
    chain.mine_blocks(EXIT_CSV as u32);
    svc.tick(&atts, t).await.unwrap();
    chain.mine_blocks(1);
    svc.tick(&atts, t).await.unwrap();
    chain.mine_blocks(1);

    let rec = svc.storage.get("decoupled-1").unwrap();
    assert!(matches!(rec.state, WatchState::BountySwept { net_profit_sats: 2800, .. }));
    assert_eq!(chain.wallet_balance(&w1), 1_002_800);
}

#[tokio::test(flavor = "current_thread")]
async fn time_based_csv_exit_waits_for_mediantime() {
    let dir = tempfile::tempdir().unwrap();
    let oracle_key = SecretKey::from_slice(&[77u8; 32]).unwrap();
    let oracle = Oracle::from_signing_key(MemoryStorage::default(), oracle_key).unwrap();
    let ann = oracle.create_numeric_event("btcusd-timecsv".into(), 20, false, 0, "USD".into(), 4000).await.unwrap();
    let att = oracle.sign_numeric_event("btcusd-timecsv".into(), 95_000).await.unwrap();
    let outcome_strs: Vec<&str> = att.outcomes[..10].iter().map(String::as_str).collect();
    let prefix = outcome_strs.concat();
    let t_point = kormir_anticipation_point(&ann.oracle_public_key, &ann.oracle_event.oracle_nonces[..10], &outcome_strs);

    let w1 = WatchtowerWallet::from_secret(SecretKey::from_slice(&[1u8; 32]).unwrap(), Network::Regtest);
    let spec = BountySpec {
        amount_sats: BOUNTY_AMOUNT,
        vout: 2,
        primary_pubkey: w1.xonly_pubkey.to_string(),
        backup_pubkeys: vec![],
        backup_csv: BACKUP_CSV,
    };
    let chain = MockChain::new(100);
    chain.set_bounty_validator(BountyScript::compile(spec.clone()).unwrap());
    chain.fund_wallet(&w1, 1_000_000, 12);
    let indexer = MockArkIndexer::new(ArkVtxoState::OperatorUnreachable);

    let mut pkg = build_contract_fixture(
        "time-csv-1",
        spec,
        Some(ann.oracle_public_key.to_string()),
        Some("btcusd-timecsv".into()),
        Some((prefix, t_point)),
        500,
        12,
    );
    // Matches live Arkade Mutinynet `unilateralExitDelay = 2048` seconds!
    pkg.exit_csv_seconds = Some(2048);

    let svc = WatchtowerService::new(
        wt_config(dir.path()),
        w1.clone(),
        WatchtowerStorage::open(dir.path().join("wt.json")).unwrap(),
        chain.clone(),
        indexer,
    );
    svc.register_package(pkg, 1000).unwrap();

    let mut atts = HashMap::new();
    atts.insert("btcusd-timecsv".to_string(), att);

    for _ in 0..3 {
        svc.tick(&atts, 1010).await.unwrap();
        chain.mine_blocks(1);
    }
    svc.tick(&atts, 1020).await.unwrap();
    assert!(matches!(svc.storage.get("time-csv-1").unwrap().state, WatchState::VtxoConfirmed { .. }));

    // Even after 30 blocks (900s < 2048s), watchtower must wait for BIP-68 time-based CSV.
    chain.mine_blocks(30);
    svc.tick(&atts, 1030).await.unwrap();
    assert!(matches!(svc.storage.get("time-csv-1").unwrap().state, WatchState::VtxoConfirmed { .. }));

    // Advance MTP past 2048s -> watchtower broadcasts DLC exit payout and sweeps bounty!
    chain.advance_time(1200);
    svc.tick(&atts, 1040).await.unwrap();
    assert!(matches!(svc.storage.get("time-csv-1").unwrap().state, WatchState::ExitBroadcast { is_refund: false, .. }));

    chain.mine_blocks(1);
    svc.tick(&atts, 1050).await.unwrap();
    chain.mine_blocks(1);
    let rec = svc.storage.get("time-csv-1").unwrap();
    assert!(matches!(rec.state, WatchState::BountySwept { net_profit_sats: 2800, .. }));
}
