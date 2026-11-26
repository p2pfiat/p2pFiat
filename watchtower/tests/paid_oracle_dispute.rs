//! End-to-end Pay-on-Dispute integration test:
//! 1. A paid blind oracle publishes ONLY its public `kind: 88` announcement (no public `kind: 89`).
//! 2. `ark-watchtower` verifies profitability (`bounty > onchain_fees + M * zap_sats`),
//!    sees 0 public attestations, and builds a valid NIP-57 `Kind::ZapRequest`.
//! 3. After payment, the paid oracle delivers the signed `kind: 89` attestation privately
//!    over NIP-17 Gift Wrap (`OracleBuyerMessage::Attestation`).
//! 4. A spoofed NIP-17 attestation from another pubkey is rejected, while the genuine
//!    oracle's NIP-17 attestation is unwrapped, verified against `kind: 88`, and returned!

use ark_watchtower::bounty::{BountyScript, BountySpec};
use ark_watchtower::client::{ArkIndexerClient, ArkVtxoState, BoxFuture, ChainClient, OutspendStatus, TxStatus};
use ark_watchtower::config::Config;
use ark_watchtower::nostr_io::{
    build_attestation_zap_request, connect_client, estimate_dispute_economics,
    fetch_external_attestations, select_cheapest_quorum, OracleBuyerMessage, OracleQuote,
    KIND_ANNOUNCEMENT, KIND_ATTESTATION,
};
use ark_watchtower::service::WatchtowerService;
use ark_watchtower::storage::{ExitRefund, WatchtowerPackage, WatchtowerStorage};
use ark_watchtower::wallet::{WalletUtxo, WatchtowerWallet};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use kormir::bitcoin::absolute::LockTime;
use kormir::bitcoin::consensus::encode::serialize_hex;
use kormir::bitcoin::hashes::Hash as _;
use kormir::bitcoin::secp256k1::SecretKey as BtcSecretKey;
use kormir::bitcoin::taproot::{ControlBlock, LeafVersion, TaprootBuilder};
use kormir::bitcoin::transaction::Version;
use kormir::bitcoin::{Amount, Network, ScriptBuf, Transaction, TxIn, TxOut, Txid};
use kormir::storage::MemoryStorage;
use kormir::{Oracle, Writeable};
use nostr_relay_builder::MockRelay;
use nostr_sdk::prelude::*;
use std::sync::Arc;
use tempfile::tempdir;

struct DummyChain;
impl ChainClient for DummyChain {
    fn tip_height(&self) -> BoxFuture<'_, u32> { Box::pin(async { Ok(100) }) }
    fn tip_mediantime(&self) -> BoxFuture<'_, u64> { Box::pin(async { Ok(1_764_000_000) }) }
    fn get_utxos(&self, _address: &str) -> BoxFuture<'_, Vec<WalletUtxo>> { Box::pin(async { Ok(vec![]) }) }
    fn tx_status(&self, _txid: &str) -> BoxFuture<'_, Option<TxStatus>> { Box::pin(async { Ok(None) }) }
    fn outspend(&self, _txid: &str, _vout: u32) -> BoxFuture<'_, OutspendStatus> {
        Box::pin(async { Ok(OutspendStatus { spent: false, txid: None }) })
    }
    fn fee_rate_sat_vb(&self, _target_blocks: u16) -> BoxFuture<'_, Option<f64>> { Box::pin(async { Ok(Some(2.0)) }) }
    fn broadcast_tx(&self, _tx_hex: &str) -> BoxFuture<'_, String> { Box::pin(async { Ok("00".repeat(32)) }) }
    fn broadcast_package(&self, _parent_hex: &str, _child_hex: &str) -> BoxFuture<'_, String> {
        Box::pin(async { Ok("00".repeat(32)) })
    }
}

struct DummyIndexer;
impl ArkIndexerClient for DummyIndexer {
    fn check_vtxo(&self, _u: &str, _s: &str, _o: &str) -> BoxFuture<'_, ArkVtxoState> {
        Box::pin(async { Ok(ArkVtxoState::Unspent) })
    }
}

fn dummy_package(wt_xonly: &str, oracle_hex: &str, event_id: &str) -> WatchtowerPackage {
    let bounty = BountySpec {
        vout: 0,
        amount_sats: 4_000,
        primary_pubkey: wt_xonly.to_string(),
        backup_pubkeys: vec![],
        backup_csv: 6,
    };
    let compiled_bounty = BountyScript::compile(bounty.clone()).unwrap();
    let exit_script = ScriptBuf::from_bytes(vec![0x51]); // OP_TRUE placeholder
    let secp = kormir::bitcoin::secp256k1::Secp256k1::new();
    let internal_key = ark_watchtower::bounty::parse_xonly(wt_xonly).unwrap();
    let spend_info = TaprootBuilder::new()
        .add_leaf(0, exit_script.clone())
        .unwrap()
        .finalize(&secp, internal_key)
        .unwrap();
    let ctrl: ControlBlock = spend_info
        .control_block(&(exit_script.clone(), LeafVersion::TapScript))
        .unwrap();

    let dummy_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn::default()],
        output: vec![TxOut {
            value: Amount::from_sat(4_000),
            script_pubkey: compiled_bounty.script_pubkey.clone(),
        }],
    };
    let raw_hex = serialize_hex(&dummy_tx);

    WatchtowerPackage {
        id: "pkg-paid-dispute-1".into(),
        vtxo_outpoint: format!("{}:0", Txid::from_slice(&[1u8; 32]).unwrap()),
        vtxo_amount_sats: 50_000,
        vtxo_pk_script: hex::encode(compiled_bounty.script_pubkey.as_bytes()),
        ark_indexer_url: Some("https://mutinynet.arkade.sh".into()),
        unroll_txs: vec![raw_hex.clone()],
        exit_script: hex::encode(exit_script.as_bytes()),
        exit_control_block: hex::encode(ctrl.serialize()),
        exit_csv: 6,
        exit_csv_seconds: None,
        user_pubkey: wt_xonly.to_string(),
        lp_pubkey: wt_xonly.to_string(),
        oracle_pubkey: Some(oracle_hex.to_string()),
        oracle_event_id: Some(event_id.to_string()),
        payouts: vec![],
        refund: Some(ExitRefund {
            tx_hex: raw_hex,
            refund_height: 200,
            user_sig: "00".repeat(64),
            lp_sig: "00".repeat(64),
        }),
        bounty,
        trigger_height: 100,
    }
}

#[tokio::test(flavor = "current_thread")]
async fn paid_oracle_dispute_flow_over_nip17() {
    // 1. Check profitability economics: 4000 sat bounty covers 1200 sat onchain + 2 * 250 sat zaps
    let econ = estimate_dispute_economics(4_000, 1_200, 250, 2, 1_000);
    assert!(econ.profitable);
    assert_eq!(econ.total_oracle_zap_sats, 500);
    assert_eq!(econ.net_profit_sats, 2_300);

    let unprofitable = estimate_dispute_economics(1_500, 1_200, 250, 2, 100);
    assert!(!unprofitable.profitable);

    // 2. Start local MockRelay, Watchtower, and a Paid Blind Oracle (kormir)
    let relay = MockRelay::run().await.unwrap();
    let relay_url = relay.url().await.to_string();
    let dir = tempdir().unwrap();

    let wt_key_path = dir.path().join("wt.key");
    let wt_wallet = WatchtowerWallet::generate_and_save(&wt_key_path, Network::Signet).unwrap();
    let wt_keys = wt_wallet.nostr_keys();
    let wt_storage = WatchtowerStorage::open(dir.path().join("wt.json")).unwrap();
    let cfg = Config {
        wallet_key_file: wt_key_path,
        db_file: dir.path().join("wt.json"),
        network: "signet".into(),
        esplora_url: "http://127.0.0.1:1".into(),
        ark_indexer_url: Some("http://127.0.0.1:1".into()),
        relays: vec![relay_url.clone()],
        cpfp_fee_sats: 600,
        sweep_fee_sats: 400,
        min_bounty_sats: 1_000,
        min_profit_sats: 100,
        tick_secs: 30,
        accept_nostr_packages: true,
    };
    let wt_svc = WatchtowerService::new(
        cfg,
        wt_wallet,
        wt_storage,
        Arc::new(DummyChain),
        Arc::new(DummyIndexer),
    );

    let oracle_sk = BtcSecretKey::new(&mut rand::thread_rng());
    let oracle = Oracle::from_signing_key(MemoryStorage::default(), oracle_sk).unwrap();
    let oracle_keys = oracle.nostr_keys();
    let oracle_pk = oracle_keys.public_key();
    let event_id = "btcusd-1764028800";

    // Register package referencing this paid oracle
    let pkg = dummy_package(&wt_svc.wallet.xonly_pubkey.to_string(), &oracle_pk.to_hex(), event_id);
    wt_svc.register_package(pkg, 1_764_000_000).unwrap();

    // Oracle creates & publishes ONLY the public kind:88 announcement (kind:89 stays PRIVATE!)
    let ann = oracle
        .create_numeric_event(event_id.into(), 20, false, 0, "USD".into(), 1_764_028_800)
        .await
        .unwrap();
    let ann_ev = EventBuilder::new(Kind::Custom(KIND_ANNOUNCEMENT), B64.encode(ann.encode()))
        .sign_with_keys(&oracle_keys)
        .unwrap();

    let oracle_client = connect_client(oracle_keys.clone(), &[relay_url.clone()]).await.unwrap();
    oracle_client.send_event(&ann_ev).await.unwrap();

    let wt_client = connect_client(wt_keys.clone(), &[relay_url.clone()]).await.unwrap();

    // 3. Before paying zap: watchtower sees 0 public attestations
    let before = fetch_external_attestations(&wt_client, &wt_svc).await.unwrap();
    assert!(before.is_empty(), "paid oracle attestation must not be public yet");

    // 4. Watchtower builds a valid NIP-57 ZapRequest for 250 sats targeting the announcement
    let zap_req = build_attestation_zap_request(
        &wt_keys,
        oracle_pk,
        ann_ev.id,
        250,
        &[relay_url.clone()],
    )
    .unwrap();
    assert_eq!(zap_req.kind, Kind::ZapRequest);
    assert!(zap_req.verify().is_ok());

    // 5. Oracle signs the numeric outcome (96,500 USD) and delivers kind:89 PRIVATELY via NIP-17!
    let att = oracle.sign_numeric_event(event_id.into(), 96_500).await.unwrap();
    let att_ev = EventBuilder::new(Kind::Custom(KIND_ATTESTATION), B64.encode(att.encode()))
        .tag(Tag::event(ann_ev.id))
        .sign_with_keys(&oracle_keys)
        .unwrap();

    // First: an attacker sends a spoofed NIP-17 message claiming to be the attestation -> must be ignored
    let attacker_keys = Keys::generate();
    let attacker_client = connect_client(attacker_keys, &[relay_url.clone()]).await.unwrap();
    let spoof_msg = OracleBuyerMessage::Attestation {
        event_id: event_id.into(),
        announcement_id: ann_ev.id.to_hex(),
        attestation: att_ev.as_json(),
    };
    attacker_client
        .send_private_msg(wt_keys.public_key(), serde_json::to_string(&spoof_msg).unwrap(), [])
        .await
        .unwrap();
    let after_spoof = fetch_external_attestations(&wt_client, &wt_svc).await.unwrap();
    assert!(after_spoof.is_empty(), "spoofed NIP-17 sender must be rejected");

    // Now the genuine paid oracle delivers the private NIP-17 attestation
    let real_msg = OracleBuyerMessage::Attestation {
        event_id: event_id.into(),
        announcement_id: ann_ev.id.to_hex(),
        attestation: att_ev.as_json(),
    };
    oracle_client
        .send_private_msg(wt_keys.public_key(), serde_json::to_string(&real_msg).unwrap(), [])
        .await
        .unwrap();

    // 6. Watchtower unwraps NIP-17 GiftWrap, verifies kind:89 against kind:88, and recovers exact price!
    let after_pay = fetch_external_attestations(&wt_client, &wt_svc).await.unwrap();
    let recovered = after_pay
        .get(event_id)
        .expect("watchtower must recover paid NIP-17 attestation");
    let bits = recovered.outcomes.concat();
    let recovered_usd = u64::from_str_radix(&bits, 2).unwrap();
    assert_eq!(recovered_usd, 96_500);

    wt_client.disconnect().await;
    oracle_client.disconnect().await;
    attacker_client.disconnect().await;
}

#[test]
fn nostracle_fee_competition_and_security_guards() {
    let pks: Vec<PublicKey> = (0..5).map(|_| Keys::generate().public_key()).collect();
    let quotes = vec![
        OracleQuote { oracle_pk: pks[0], announcement_id: EventId::all_zeros(), event_id: "btcusd-1".into(), fee_sats: 900 },
        OracleQuote { oracle_pk: pks[1], announcement_id: EventId::all_zeros(), event_id: "btcusd-1".into(), fee_sats: 150 },
        OracleQuote { oracle_pk: pks[2], announcement_id: EventId::all_zeros(), event_id: "btcusd-1".into(), fee_sats: 2500 },
        OracleQuote { oracle_pk: pks[3], announcement_id: EventId::all_zeros(), event_id: "btcusd-1".into(), fee_sats: 100 },
        OracleQuote { oracle_pk: pks[4], announcement_id: EventId::all_zeros(), event_id: "btcusd-1".into(), fee_sats: 200 },
        // Duplicate cheap pubkey must NOT count as two distinct oracles!
        OracleQuote { oracle_pk: pks[3], announcement_id: EventId::all_zeros(), event_id: "btcusd-1".into(), fee_sats: 50 },
    ];

    // 1. 3-of-5 selects the 3 cheapest distinct oracles: 50 + 150 + 200 = 400 sats (skips 900 & 2500)
    let chosen = select_cheapest_quorum(&quotes, 3, 1_000, false).unwrap();
    assert_eq!(chosen.len(), 3);
    assert_eq!(chosen.iter().map(|q| q.fee_sats).collect::<Vec<_>>(), vec![50, 150, 200]);

    // 2. Anti-bribery guard refuses threshold=1 by default
    assert!(select_cheapest_quorum(&quotes, 1, 1_000, false).is_err());

    // 3. Budget guard refuses if cheapest 3 exceed max_total_zap_sats
    assert!(select_cheapest_quorum(&quotes, 3, 300, false).is_err());
}
