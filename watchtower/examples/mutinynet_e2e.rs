//! Experiment 15: Live Mutinynet + public Nostr relays end-to-end test for
//! `ark-watchtower` (keyless Ark watchtower with tiered Taproot exit bounty).
//!
//! Runs against:
//! - Public Mutinynet Bitcoin network (`https://mutinynet.com/api`, incl. `/txs/package`)
//! - Public Nostr relays (`wss://nos.lol`, `wss://relay.damus.io`, `wss://relay.primal.net`)
//! - Real `kormir` 20-bit numeric DLC oracle (independent key from the watchtower)
//! - Real NIP-17 private package registration + external kind-88/89 verification
//! - Real v3 TRUC 1p1c CPFP with 0-sat P2A anchor, DLC adaptor payout, and tiered bounty sweep

use anyhow::{anyhow, Context, Result};
use ark_watchtower::bounty::{nums_internal_key, BountyScript, BountySpec};
use ark_watchtower::client::{ArkIndexerClient, ArkVtxoState, BoxFuture, ChainClient, EsploraClient};
use ark_watchtower::config::Config;
use ark_watchtower::nostr_io::{self, KIND_ANNOUNCEMENT, KIND_ATTESTATION};
use ark_watchtower::service::{now, WatchtowerRequest, WatchtowerService};
use ark_watchtower::storage::{ExitPayout, ExitRefund, WatchState, WatchtowerPackage, WatchtowerStorage};
use ark_watchtower::wallet::{parse_network, WatchtowerWallet, P2A_SCRIPT_BYTES};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use kormir::bitcoin::absolute::LockTime;
use kormir::bitcoin::consensus::encode::serialize_hex;
use kormir::bitcoin::hashes::{sha256, Hash, HashEngine};
use kormir::bitcoin::key::TapTweak;
use kormir::bitcoin::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGADD, OP_CSV, OP_DROP, OP_EQUAL};
use kormir::bitcoin::script::Builder;
use kormir::bitcoin::secp256k1::{Keypair, Message, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};
use kormir::bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use kormir::bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash, TaprootBuilder};
use kormir::bitcoin::transaction::Version;
use kormir::bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use kormir::storage::MemoryStorage;
use kormir::{Oracle, Writeable};
use nostr_sdk::prelude::*;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

const CONTRACT_AMOUNT: u64 = 25_000;
const EXIT_TX_FEE: u64 = 500;
const BOUNTY_AMOUNT: u64 = 5_000;
const EXIT_CSV: u16 = 4; // ~2 minutes on Mutinynet (30s blocks)
const BACKUP_CSV: u16 = 4;

struct OfflineOperatorIndexer;
impl ArkIndexerClient for OfflineOperatorIndexer {
    fn check_vtxo(&self, _url: &str, _pk: &str, _op: &str) -> BoxFuture<'_, ArkVtxoState> {
        // Simulate Ark operator offline so watchtower proceeds to onchain exit.
        Box::pin(async move { Ok(ArkVtxoState::OperatorUnreachable) })
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
    if r_eff.x_only_public_key().1 == kormir::bitcoin::secp256k1::Parity::Odd {
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

fn sign_p2tr_keyspend(
    tx: &mut Transaction,
    input_idx: usize,
    prevouts: &[TxOut],
    untweaked_kp: &Keypair,
) -> Result<()> {
    let secp = Secp256k1::new();
    let tweaked = untweaked_kp.tap_tweak(&secp, None).to_keypair();
    let sh = SighashCache::new(&*tx)
        .taproot_key_spend_signature_hash(input_idx, &Prevouts::All(prevouts), TapSighashType::Default)
        .map_err(|e| anyhow!("sighash: {e}"))?;
    let msg = Message::from_digest_slice(sh.as_ref())?;
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &tweaked);
    let mut w = Witness::new();
    w.push(sig.as_ref());
    tx.input[input_idx].witness = w;
    Ok(())
}

async fn wait_for_confirmations(chain: &EsploraClient, txid: &str, min_confs: u32) -> Result<u32> {
    loop {
        let tip = chain.tip_height().await?;
        if let Some(st) = chain.tx_status(txid).await? {
            if let Some(h) = st.block_height {
                let confs = tip.saturating_sub(h).saturating_add(1);
                println!("  tx {txid}: {confs}/{min_confs} confirmations (tip {tip})");
                if confs >= min_confs {
                    return Ok(tip);
                }
            } else {
                println!("  tx {txid}: in mempool (tip {tip}), waiting for confirmation...");
            }
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cfg_path = Path::new("watchtower/data/mutinynet.toml");
    let mut cfg = Config::load(cfg_path).context("load mutinynet.toml")?;
    // Use a fresh run-specific DB file so each Experiment 15 run starts clean.
    let run_id = now();
    cfg.db_file = format!("watchtower/data/mutinynet-run-{run_id}.json").into();
    let net = parse_network(&cfg.network)?;

    let w1 = WatchtowerWallet::load(&cfg.wallet_key_file, net)?;
    let http = reqwest::Client::builder().user_agent("ark-watchtower-exp15/0.1").build()?;
    let chain = Arc::new(EsploraClient::new(http.clone(), cfg.esplora_url.clone()));

    println!("=== Experiment 15: Live Mutinynet + Public Nostr E2E ===");
    println!("Watchtower W1 pubkey : {}", w1.xonly_pubkey);
    println!("Watchtower W1 address: {}", w1.address);

    // 1. Wait for confirmed funding UTXO on Mutinynet.
    let funding_utxo = loop {
        let utxos = chain.get_utxos(&w1.address.to_string()).await?;
        if let Some(u) = utxos.iter().find(|u| u.confirmed && u.value_sats >= CONTRACT_AMOUNT + 5_000) {
            break u.clone();
        }
        println!("Waiting for confirmed UTXO (>= 30,000 sats) at {} (found {} utxos)...", w1.address, utxos.len());
        tokio::time::sleep(Duration::from_secs(10)).await;
    };
    println!(
        "Found confirmed UTXO: {} ({} sats)",
        funding_utxo.outpoint, funding_utxo.value_sats
    );

    // 2. Broadcast setup tx splitting into:
    //    - output 0: 25,000 sats simulated confirmed Ark batch commitment output
    //    - output 1: change back to W1 P2TR fee wallet
    let secp = Secp256k1::new();
    let commit_secret = SecretKey::new(&mut rand::thread_rng());
    let commit_kp = Keypair::from_secret_key(&secp, &commit_secret);
    let (commit_xonly, _) = commit_kp.x_only_public_key();
    let commit_script = ScriptBuf::new_p2tr(&secp, commit_xonly, None);

    let setup_fee = 500u64;
    let w1_fee_change = funding_utxo.value_sats - CONTRACT_AMOUNT - setup_fee;
    let mut setup_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: funding_utxo.outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut { value: Amount::from_sat(CONTRACT_AMOUNT), script_pubkey: commit_script.clone() },
            TxOut { value: Amount::from_sat(w1_fee_change), script_pubkey: w1.script_pubkey.clone() },
        ],
    };
    sign_p2tr_keyspend(
        &mut setup_tx,
        0,
        &[TxOut {
            value: Amount::from_sat(funding_utxo.value_sats),
            script_pubkey: w1.script_pubkey.clone(),
        }],
        w1.keypair(),
    )?;
    let setup_txid = chain.broadcast_tx(&serialize_hex(&setup_tx)).await?;
    println!("\n[1/6] Setup commitment tx broadcast: https://mutinynet.com/tx/{setup_txid}");
    let tip = wait_for_confirmations(&chain, &setup_txid, 1).await?;

    let w1_bal_before = w1_fee_change;
    println!("Watchtower W1 confirmed balance before exit: {w1_bal_before} sats");

    // 3. Create independent external DLC oracle (separate key from watchtower!) + contract parties.
    let oracle_secret = SecretKey::new(&mut rand::thread_rng());
    let oracle = Oracle::from_signing_key(MemoryStorage::default(), oracle_secret)?;
    let oracle_nostr_keys = oracle.nostr_keys();
    let event_id = format!("btcusd-mutinynet-{run_id}");
    let ann = oracle.create_numeric_event(event_id.clone(), 20, false, 0, "USD".into(), (run_id + 60) as u32).await?;
    let att = oracle.sign_numeric_event(event_id.clone(), 97_123).await?;
    let outcome_strs: Vec<&str> = att.outcomes[..10].iter().map(String::as_str).collect();
    let prefix = outcome_strs.concat();
    let t_point = kormir_anticipation_point(&ann.oracle_public_key, &ann.oracle_event.oracle_nonces[..10], &outcome_strs);

    let w2 = WatchtowerWallet::from_secret(SecretKey::new(&mut rand::thread_rng()), net);
    let bounty_spec = BountySpec {
        amount_sats: BOUNTY_AMOUNT,
        vout: 2,
        primary_pubkey: w1.xonly_pubkey.to_string(),
        backup_pubkeys: vec![w2.xonly_pubkey.to_string()],
        backup_csv: BACKUP_CSV,
    };
    let compiled_bounty = BountyScript::compile(bounty_spec.clone())?;

    let u_kp = Keypair::from_secret_key(&secp, &SecretKey::new(&mut rand::thread_rng()));
    let l_kp = Keypair::from_secret_key(&secp, &SecretKey::new(&mut rand::thread_rng()));
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
    let vtxo_spend = TaprootBuilder::new()
        .add_leaf(0, exit_script.clone())
        .unwrap()
        .finalize(&secp, nums_internal_key())
        .unwrap();
    let vtxo_pk_script = ScriptBuf::new_p2tr_tweaked(vtxo_spend.output_key());
    let exit_ctrl: ControlBlock = vtxo_spend
        .control_block(&(exit_script.clone(), LeafVersion::TapScript))
        .unwrap();

    // Build signed 0-fee v3 (TRUC) virtual tx with 0-sat P2A anchor!
    let mut vtxo_tx = Transaction {
        version: Version(3),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: setup_tx.compute_txid(), vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut { value: Amount::from_sat(CONTRACT_AMOUNT), script_pubkey: vtxo_pk_script.clone() },
            TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::from_bytes(P2A_SCRIPT_BYTES.to_vec()) },
        ],
    };
    sign_p2tr_keyspend(
        &mut vtxo_tx,
        0,
        &[TxOut { value: Amount::from_sat(CONTRACT_AMOUNT), script_pubkey: commit_script }],
        &commit_kp,
    )?;
    let vtxo_txid = vtxo_tx.compute_txid();
    let vtxo_outpoint = OutPoint { txid: vtxo_txid, vout: 0 };

    // Build adaptor-signed DLC exit payout tx + pre-signed refund tx.
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
        let prevout = TxOut { value: Amount::from_sat(CONTRACT_AMOUNT), script_pubkey: vtxo_pk_script.clone() };
        let leaf_hash = TapLeafHash::from_script(&exit_script, LeafVersion::TapScript);
        let sh = SighashCache::new(&tx)
            .taproot_script_spend_signature_hash(0, &Prevouts::All(&[prevout]), leaf_hash, TapSighashType::Default)
            .unwrap();
        let mut msg = [0u8; 32];
        msg.copy_from_slice(sh.as_ref());
        (tx, msg)
    };

    let (payout_tx, payout_msg) = build_exit(17_000, 8_000, LockTime::ZERO);
    let refund_height = tip + 100;
    let (refund_tx, refund_msg) = build_exit(12_500, 12_500, LockTime::from_height(refund_height).unwrap());
    let rm = Message::from_digest_slice(&refund_msg)?;

    let pkg = WatchtowerPackage {
        id: format!("mutinynet-dlc-{run_id}"),
        vtxo_outpoint: format!("{vtxo_txid}:0"),
        vtxo_amount_sats: CONTRACT_AMOUNT,
        vtxo_pk_script: hex::encode(vtxo_pk_script.as_bytes()),
        ark_indexer_url: cfg.ark_indexer_url.clone(),
        unroll_txs: vec![serialize_hex(&vtxo_tx)],
        exit_script: hex::encode(exit_script.as_bytes()),
        exit_control_block: hex::encode(exit_ctrl.serialize()),
        user_pubkey: u_pub.to_string(),
        lp_pubkey: l_pub.to_string(),
        exit_csv: EXIT_CSV,
        bounty: bounty_spec,
        oracle_pubkey: Some(oracle_nostr_keys.public_key().to_hex()),
        oracle_event_id: Some(event_id.clone()),
        payouts: vec![ExitPayout {
            outcome: prefix,
            tx_hex: serialize_hex(&payout_tx),
            user_adaptor_sig: adaptor_sign(&u_kp, &payout_msg, &t_point, 11),
            lp_adaptor_sig: adaptor_sign(&l_kp, &payout_msg, &t_point, 22),
            precompleted: false,
        }],
        refund: Some(ExitRefund {
            tx_hex: serialize_hex(&refund_tx),
            refund_height,
            user_sig: hex::encode(secp.sign_schnorr_no_aux_rand(&rm, &u_kp).as_ref()),
            lp_sig: hex::encode(secp.sign_schnorr_no_aux_rand(&rm, &l_kp).as_ref()),
        }),
        trigger_height: 0,
    };
    let _ = (u_kp, l_kp, commit_kp); // User, LP, and commitment keys are gone!

    // 4. Publish kind-88/89 from external oracle & send WatchtowerPackage via NIP-17 on PUBLIC Nostr relays!
    println!("\n[2/6] Connecting to public Nostr relays: {:?}", cfg.relays);
    let oracle_client = nostr_io::connect_client(oracle_nostr_keys.clone(), &cfg.relays).await?;
    let ann_ev = EventBuilder::new(Kind::Custom(KIND_ANNOUNCEMENT), B64.encode(ann.encode()))
        .sign_with_keys(&oracle_nostr_keys)?;
    let att_ev = EventBuilder::new(Kind::Custom(KIND_ATTESTATION), B64.encode(att.encode()))
        .tag(Tag::event(ann_ev.id))
        .sign_with_keys(&oracle_nostr_keys)?;
    let out_ann = oracle_client.send_event(&ann_ev).await?;
    let out_att = oracle_client.send_event(&att_ev).await?;
    println!(
        "  Published external oracle kind-88 ({} relays) & kind-89 ({} relays) for {event_id} = $97,123",
        out_ann.success.len(),
        out_att.success.len()
    );

    let user_nostr = Keys::generate();
    let user_client = nostr_io::connect_client(user_nostr, &cfg.relays).await?;
    let req = WatchtowerRequest::RegisterPackage { package: Box::new(pkg.clone()) };
    let dm_out = user_client
        .send_private_msg(w1.nostr_keys().public_key(), serde_json::to_string(&req)?, [])
        .await?;
    println!("  Sent NIP-17 RegisterPackage DM to W1 ({} relays)", dm_out.success.len());

    // 5. Watchtower receives NIP-17 DM & fetches external oracle attestation from public relays.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let wt_client = nostr_io::connect_client(w1.nostr_keys(), &cfg.relays).await?;
    let svc = WatchtowerService::new(
        cfg.clone(),
        w1.clone(),
        WatchtowerStorage::open(&cfg.db_file)?,
        chain.clone(),
        Arc::new(OfflineOperatorIndexer),
    );
    let mut registered = 0;
    for _ in 0..6 {
        registered += nostr_io::process_incoming_packages(&wt_client, &svc, now()).await?;
        if registered > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    anyhow::ensure!(registered == 1, "watchtower did not receive NIP-17 package from public relays");
    println!("\n[3/6] Watchtower W1 received & validated keyless package via NIP-17 DM!");

    let mut atts = Default::default();
    for _ in 0..6 {
        atts = nostr_io::fetch_external_attestations(&wt_client, &svc).await?;
        if atts.contains_key(&event_id) {
            break;
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    anyhow::ensure!(atts.contains_key(&event_id), "watchtower failed to fetch external kind-88/89 from public relays");
    println!("  Watchtower W1 fetched & verified external oracle attestation from public relays!");

    // 6. Execute live Mutinynet TRUC v3 CPFP unroll -> CSV(4) -> DLC exit payout -> Bounty sweep!
    println!("\n[4/6] Broadcasting v3 TRUC virtual tx + P2A CPFP child via Mutinynet /txs/package...");
    svc.tick(&atts, now()).await?;
    let state = svc.storage.get(&pkg.id).unwrap();
    let cpfp_txid = match state.state {
        WatchState::Unrolling { last_cpfp_txid: Some(ref id), .. } => id.clone(),
        other => anyhow::bail!("expected Unrolling state, got {other:?}"),
    };
    println!("  VTXO tx : https://mutinynet.com/tx/{vtxo_txid}");
    println!("  CPFP tx : https://mutinynet.com/tx/{cpfp_txid}");
    wait_for_confirmations(&chain, &vtxo_txid.to_string(), EXIT_CSV as u32).await?;

    // Tick 1: marks VtxoConfirmed; Tick 2: broadcasts finalized DLC exit payout!
    svc.tick(&atts, now()).await?;
    svc.tick(&atts, now()).await?;
    let exit_txid = match svc.storage.get(&pkg.id).unwrap().state {
        WatchState::ExitBroadcast { exit_txid, .. } => exit_txid,
        other => anyhow::bail!("expected ExitBroadcast state, got {other:?}"),
    };
    println!("\n[5/6] Finalized DLC exit payout broadcast: https://mutinynet.com/tx/{exit_txid}");
    wait_for_confirmations(&chain, &exit_txid, 1).await?;

    // Tick 3: W1 sweeps tiered Taproot bounty immediately!
    svc.tick(&atts, now()).await?;
    let (sweep_txid, net_profit) = match svc.storage.get(&pkg.id).unwrap().state {
        WatchState::BountySwept { sweep_txid, net_profit_sats, .. } => (sweep_txid, net_profit_sats),
        other => anyhow::bail!("expected BountySwept state, got {other:?}"),
    };
    println!("\n[6/6] Primary W1 bounty sweep broadcast: https://mutinynet.com/tx/{sweep_txid}");
    wait_for_confirmations(&chain, &sweep_txid, 1).await?;

    let final_utxos = chain.get_utxos(&w1.address.to_string()).await?;
    let w1_bal_after: u64 = final_utxos.iter().map(|u| u.value_sats).sum();
    let actual_delta = w1_bal_after as i64 - w1_bal_before as i64;
    println!("\n=== EXPERIMENT 15 RESULT: SUCCESS ===");
    println!("W1 balance before : {w1_bal_before} sats");
    println!("W1 balance after  : {w1_bal_after} sats");
    println!("W1 onchain profit : {:+} sats (recorded: {:+} sats)", actual_delta, net_profit);
    Ok(())
}
