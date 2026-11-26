//! Autonomous Leaf 2 (`k-of-n` Nostracle BIP-342) On-Demand Mid-Term Dispute execution.
//!
//! Enables a keyless `ark-watchtower` to settle a confirmed DLC VTXO onchain even when
//! BOTH the User and LP are offline, using:
//! 1. The 2-party BIP-340 signed `DisputeManifest` (prevents address spoofing / terms forgery),
//! 2. An unsigned v2 Bitcoin transaction paying:
//!    - `output[0]`: User's contract-bound P2TR payout script,
//!    - `output[1]`: LP's contract-bound P2TR payout script,
//!    - `output[2]`: Compiled tiered NUMS P2TR Watchtower Bounty script (`BountyScript::compile`),
//!    - leaving a bounded L1 miner fee (default 350 sats) so the tx passes mempool min-relay-fee,
//! 3. `k-of-n` BIP-340 Schnorr signatures collected over NIP-17 RPC (`sign_dispute`) from the
//!    contract's Nostracle quorum, assembled into a standard BIP-342 `OP_CHECKSIGADD` witness.

use crate::bounty::{parse_xonly, BountyScript, BountySpec};
use crate::client::parse_outpoint;
use crate::storage::{DisputeManifest, DisputePackageSpec};
use anyhow::{anyhow, ensure, Context, Result};
use kormir::bitcoin::absolute::LockTime;
use kormir::bitcoin::consensus::encode::serialize_hex;
use kormir::bitcoin::hashes::{sha256, Hash};
use kormir::bitcoin::secp256k1::schnorr::Signature as SchnorrSig;
use kormir::bitcoin::secp256k1::{Message, Secp256k1};
use kormir::bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use kormir::bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash};
use kormir::bitcoin::transaction::Version;
use kormir::bitcoin::{Amount, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use serde_json::{json, Value};
use std::collections::HashMap;

pub const DUST_SATS: u64 = 350;
pub const DEFAULT_DISPUTE_MINER_FEE_SATS: u64 = 350;
pub const MAX_DISPUTE_MINER_FEE_SATS: u64 = 5_000;
const MANIFEST_TAG: &[u8] = b"p2pfiat/dispute-manifest/v1";

/// Deterministic BIP-340 tagged hash (`p2pfiat/dispute-manifest/v1`) matching
/// `nostracle::dispute::compute_manifest_hash` and `mvp/src/contract.mjs`.
pub fn compute_manifest_hash(m: &DisputeManifest) -> [u8; 32] {
    let notional_cents = (m.notional_fiat * 100.0).round() as i64;
    let funding_bps_x100 = (m.funding_rate_bps_per_day * 100.0).round() as i64;
    let canonical = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        m.contract_id.trim(),
        m.vtxo_outpoint.trim().to_lowercase(),
        m.currency.trim().to_uppercase(),
        m.side.trim().to_lowercase(),
        m.total_collateral_sats,
        notional_cents,
        m.opened_at,
        funding_bps_x100,
        m.user_pubkey_hex.trim().to_lowercase(),
        m.lp_pubkey_hex.trim().to_lowercase(),
        m.vtxo_pk_script_hex.trim().to_lowercase(),
        m.dispute_script_hex.trim().to_lowercase(),
        m.user_payout_script_hex.trim().to_lowercase(),
        m.lp_payout_script_hex.trim().to_lowercase(),
    );
    let tag_hash = sha256::Hash::hash(MANIFEST_TAG);
    let mut preimage = Vec::with_capacity(64 + canonical.len());
    preimage.extend_from_slice(tag_hash.as_byte_array());
    preimage.extend_from_slice(tag_hash.as_byte_array());
    preimage.extend_from_slice(canonical.as_bytes());
    sha256::Hash::hash(&preimage).to_byte_array()
}

/// Cryptographically verify BOTH User and LP BIP-340 signatures on a `DisputeManifest`.
pub fn verify_dispute_manifest(m: &DisputeManifest) -> Result<()> {
    let secp = Secp256k1::verification_only();
    let digest = compute_manifest_hash(m);
    let msg = Message::from_digest(digest);

    let u_pk = parse_xonly(&m.user_pubkey_hex).context("manifest user_pubkey_hex")?;
    let u_sig_bytes = hex::decode(m.user_manifest_sig_hex.trim())
        .context("manifest user_manifest_sig_hex")?;
    let u_sig = SchnorrSig::from_slice(&u_sig_bytes).context("manifest user schnorr sig")?;
    secp.verify_schnorr(&u_sig, &msg, &u_pk)
        .context("manifest user BIP-340 signature invalid")?;

    let l_pk = parse_xonly(&m.lp_pubkey_hex).context("manifest lp_pubkey_hex")?;
    let l_sig_bytes = hex::decode(m.lp_manifest_sig_hex.trim())
        .context("manifest lp_manifest_sig_hex")?;
    let l_sig = SchnorrSig::from_slice(&l_sig_bytes).context("manifest lp schnorr sig")?;
    secp.verify_schnorr(&l_sig, &msg, &l_pk)
        .context("manifest LP BIP-340 signature invalid")?;

    Ok(())
}

fn clamp_fiat_sats(target_fiat: f64, spot_price: f64, distributable: u64) -> u64 {
    let raw = ((target_fiat.max(0.01) / spot_price) * 1e8).round() as u64;
    let max_out = distributable.saturating_sub(DUST_SATS);
    raw.clamp(DUST_SATS, max_out.max(DUST_SATS))
}

/// Unsigned Leaf 2 dispute transaction + sighash + `sign_dispute` NIP-17 RPC parameters.
#[derive(Debug, Clone)]
pub struct BuiltDisputeTx {
    pub unsigned_tx: Transaction,
    pub raw_tx_hex: String,
    pub sighash: [u8; 32],
    pub sighash_hex: String,
    pub user_payout_sats: u64,
    pub lp_payout_sats: u64,
    pub bounty_sats: u64,
    pub miner_fee_sats: u64,
    pub rpc_params: Value,
}

/// Build an unsigned v2 Leaf 2 dispute transaction including the tiered NUMS P2TR watchtower
/// bounty in `output[2]` and a bounded L1 miner fee (`miner_fee_sats`), compute its BIP-342
/// Tapscript sighash, and assemble the `sign_dispute` RPC params for `nostracle`.
pub fn build_watchtower_dispute_tx(
    dispute: &DisputePackageSpec,
    bounty: &BountySpec,
    live_spot_price: f64,
    dispute_timestamp: u64,
    miner_fee_sats: u64,
) -> Result<BuiltDisputeTx> {
    ensure!(
        live_spot_price.is_finite() && live_spot_price > 0.0,
        "live_spot_price must be > 0"
    );
    ensure!(
        miner_fee_sats <= MAX_DISPUTE_MINER_FEE_SATS,
        "miner_fee_sats {miner_fee_sats} exceeds max {MAX_DISPUTE_MINER_FEE_SATS}"
    );
    let manifest = dispute
        .manifest
        .as_ref()
        .ok_or_else(|| anyhow!("dispute package missing 2-party signed manifest"))?;
    verify_dispute_manifest(manifest)?;
    ensure!(
        dispute_timestamp >= manifest.opened_at,
        "dispute_timestamp {} precedes opened_at {}",
        dispute_timestamp,
        manifest.opened_at
    );

    let bounty_sats = bounty.amount_sats;
    let compiled_bounty = if bounty_sats > 0 {
        Some(BountyScript::compile(bounty.clone())?)
    } else {
        None
    };

    ensure!(
        manifest.total_collateral_sats >= bounty_sats + miner_fee_sats + DUST_SATS * 2,
        "total_collateral_sats {} too small for bounty {} + miner fee {} + 2*dust",
        manifest.total_collateral_sats,
        bounty_sats,
        miner_fee_sats
    );

    let distributable = manifest.total_collateral_sats - bounty_sats - miner_fee_sats;
    let elapsed_secs = (dispute_timestamp - manifest.opened_at) as f64;
    let accrued_fiat =
        manifest.notional_fiat * (manifest.funding_rate_bps_per_day / 10_000.0) * (elapsed_secs / 86_400.0);

    let (user_payout_sats, lp_payout_sats) = if manifest.side.eq_ignore_ascii_case("long") {
        let lp_target = (manifest.notional_fiat - accrued_fiat).max(0.01);
        let lp = clamp_fiat_sats(lp_target, live_spot_price, distributable);
        (distributable - lp, lp)
    } else {
        let user_target = (manifest.notional_fiat + accrued_fiat).max(0.01);
        let user = clamp_fiat_sats(user_target, live_spot_price, distributable);
        (user, distributable - user)
    };

    let outpoint = parse_outpoint(&manifest.vtxo_outpoint)?;
    let user_script = ScriptBuf::from_bytes(
        hex::decode(manifest.user_payout_script_hex.trim()).context("user_payout_script_hex")?,
    );
    let lp_script = ScriptBuf::from_bytes(
        hex::decode(manifest.lp_payout_script_hex.trim()).context("lp_payout_script_hex")?,
    );
    let vtxo_script = ScriptBuf::from_bytes(
        hex::decode(manifest.vtxo_pk_script_hex.trim()).context("vtxo_pk_script_hex")?,
    );
    let dispute_script = ScriptBuf::from_bytes(
        hex::decode(dispute.script_hex.trim()).context("dispute.script_hex")?,
    );

    let mut outputs = vec![
        TxOut {
            value: Amount::from_sat(user_payout_sats),
            script_pubkey: user_script,
        },
        TxOut {
            value: Amount::from_sat(lp_payout_sats),
            script_pubkey: lp_script,
        },
    ];
    if let Some(cb) = compiled_bounty {
        outputs.push(TxOut {
            value: Amount::from_sat(bounty_sats),
            script_pubkey: cb.script_pubkey,
        });
    }

    let unsigned_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::from_consensus(dispute.csv_sequence),
            witness: Witness::new(),
        }],
        output: outputs,
    };

    let prevout = TxOut {
        value: Amount::from_sat(manifest.total_collateral_sats),
        script_pubkey: vtxo_script,
    };
    let leaf_hash = TapLeafHash::from_script(&dispute_script, LeafVersion::TapScript);
    let sighash_obj = SighashCache::new(&unsigned_tx)
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[prevout]),
            leaf_hash,
            TapSighashType::Default,
        )
        .map_err(|e| anyhow!("dispute tx sighash: {e}"))?;
    let mut sighash = [0u8; 32];
    sighash.copy_from_slice(sighash_obj.as_ref());
    let sighash_hex = hex::encode(sighash);
    let raw_tx_hex = serialize_hex(&unsigned_tx);

    let rpc_params = json!({
        "contract_id": manifest.contract_id,
        "vtxo_outpoint": manifest.vtxo_outpoint,
        "currency": manifest.currency,
        "side": manifest.side,
        "total_collateral_sats": manifest.total_collateral_sats,
        "notional_fiat": manifest.notional_fiat,
        "opened_at": manifest.opened_at,
        "dispute_timestamp": dispute_timestamp,
        "funding_rate_bps_per_day": manifest.funding_rate_bps_per_day,
        "bounty_sats": bounty_sats,
        "miner_fee_sats": miner_fee_sats,
        "fee_paid_sats": 0,
        "user_pubkey_hex": manifest.user_pubkey_hex,
        "lp_pubkey_hex": manifest.lp_pubkey_hex,
        "user_manifest_sig_hex": manifest.user_manifest_sig_hex,
        "lp_manifest_sig_hex": manifest.lp_manifest_sig_hex,
        "raw_tx_hex": raw_tx_hex,
        "vtxo_pk_script_hex": manifest.vtxo_pk_script_hex,
        "dispute_script_hex": manifest.dispute_script_hex,
        "user_payout_script_hex": manifest.user_payout_script_hex,
        "lp_payout_script_hex": manifest.lp_payout_script_hex,
        "sighash_hex": sighash_hex,
    });

    Ok(BuiltDisputeTx {
        unsigned_tx,
        raw_tx_hex,
        sighash,
        sighash_hex,
        user_payout_sats,
        lp_payout_sats,
        bounty_sats,
        miner_fee_sats,
        rpc_params,
    })
}

/// Verify `>= threshold` BIP-340 oracle Schnorr signatures and attach the BIP-342
/// `OP_CHECKSIGADD` Tapscript witness stack (reverse pubkey order, empty element for non-signers).
pub fn assemble_dispute_tx_witness(
    built: &BuiltDisputeTx,
    dispute: &DisputePackageSpec,
    sigs_by_pubkey: &HashMap<String, String>,
) -> Result<Transaction> {
    let threshold = dispute.oracle_quorum.threshold;
    let oracles = &dispute.oracle_quorum.oracles;
    ensure!(threshold >= 1, "dispute threshold must be >= 1");
    ensure!(
        oracles.len() >= threshold,
        "dispute quorum has {} oracles, need at least {threshold}",
        oracles.len()
    );

    let dispute_script = ScriptBuf::from_bytes(
        hex::decode(dispute.script_hex.trim()).context("dispute.script_hex")?,
    );
    let control_block_bytes =
        hex::decode(dispute.control_block_hex.trim()).context("dispute.control_block_hex")?;
    let control_block = ControlBlock::decode(&control_block_bytes)
        .map_err(|e| anyhow!("invalid dispute control block: {e}"))?;

    let secp = Secp256k1::verification_only();
    let msg = Message::from_digest(built.sighash);

    let mut verified: HashMap<String, [u8; 64]> = HashMap::new();
    for entry in oracles {
        let pk_key = entry.pubkey.trim().to_lowercase();
        let Some(sig_hex) = sigs_by_pubkey.get(&pk_key) else { continue };
        let Ok(pk) = parse_xonly(&pk_key) else { continue };
        let Ok(sig_bytes) = hex::decode(sig_hex.trim()) else { continue };
        let Ok(sig) = SchnorrSig::from_slice(&sig_bytes) else { continue };
        if secp.verify_schnorr(&sig, &msg, &pk).is_ok() {
            verified.insert(pk_key, sig.serialize());
        }
    }

    ensure!(
        verified.len() >= threshold,
        "only {}/{} valid Nostracle signatures collected for Leaf 2 dispute",
        verified.len(),
        threshold
    );

    // BIP-342 OP_CHECKSIGADD witness stack: reverse order of pubkeys in script,
    // empty byte vector for non-signing oracles, followed by script and control block.
    let mut witness = Witness::new();
    for entry in oracles.iter().rev() {
        let pk_key = entry.pubkey.trim().to_lowercase();
        if let Some(sig) = verified.get(&pk_key) {
            witness.push(sig);
        } else {
            witness.push([]);
        }
    }
    witness.push(dispute_script.as_bytes());
    witness.push(control_block.serialize());

    let mut final_tx = built.unsigned_tx.clone();
    final_tx.input[0].witness = witness;
    Ok(final_tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounty::nums_internal_key;
    use crate::storage::{DisputeOracleEntry, DisputeQuorum};
    use kormir::bitcoin::opcodes::all::{
        OP_CHECKSIG, OP_CHECKSIGADD, OP_CSV, OP_DROP, OP_GREATERTHANOREQUAL,
    };
    use kormir::bitcoin::script::Builder;
    use kormir::bitcoin::secp256k1::{Keypair, SecretKey};
    use kormir::bitcoin::taproot::TaprootBuilder;

    fn kp(seed: u8) -> Keypair {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[seed; 32]).unwrap();
        Keypair::from_secret_key(&secp, &sk)
    }

    fn p2tr_script(kp: &Keypair) -> ScriptBuf {
        let secp = Secp256k1::new();
        let (xonly, _) = kp.x_only_public_key();
        ScriptBuf::new_p2tr(&secp, xonly, None)
    }

    fn make_fixture() -> (
        DisputePackageSpec,
        BountySpec,
        [Keypair; 3],
    ) {
        let secp = Secp256k1::new();
        let user_kp = kp(1);
        let lp_kp = kp(2);
        let wt_kp = kp(3);
        let o1 = kp(11);
        let o2 = kp(12);
        let o3 = kp(13);

        let csv_seq: u32 = (1 << 22) | 4; // 2048s time-based CSV
        let (o1_pk, _) = o1.x_only_public_key();
        let (o2_pk, _) = o2.x_only_public_key();
        let (o3_pk, _) = o3.x_only_public_key();

        let dispute_script = Builder::new()
            .push_int(csv_seq as i64)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            .push_x_only_key(&o1_pk)
            .push_opcode(OP_CHECKSIG)
            .push_x_only_key(&o2_pk)
            .push_opcode(OP_CHECKSIGADD)
            .push_x_only_key(&o3_pk)
            .push_opcode(OP_CHECKSIGADD)
            .push_int(2)
            .push_opcode(OP_GREATERTHANOREQUAL)
            .into_script();

        let spend_info = TaprootBuilder::new()
            .add_leaf(0, dispute_script.clone())
            .unwrap()
            .finalize(&secp, nums_internal_key())
            .unwrap();
        let vtxo_pk_script = ScriptBuf::new_p2tr_tweaked(spend_info.output_key());
        let ctrl = spend_info
            .control_block(&(dispute_script.clone(), LeafVersion::TapScript))
            .unwrap();

        let (u_pk, _) = user_kp.x_only_public_key();
        let (l_pk, _) = lp_kp.x_only_public_key();
        let (wt_pk, _) = wt_kp.x_only_public_key();

        let mut manifest = DisputeManifest {
            contract_id: "pos-wt-dispute-test".into(),
            vtxo_outpoint: format!("{}:0", "aa".repeat(32)),
            currency: "USD".into(),
            side: "short".into(),
            total_collateral_sats: 200_000,
            notional_fiat: 100.0,
            opened_at: 1_760_000_000,
            funding_rate_bps_per_day: 3.0,
            user_pubkey_hex: u_pk.to_string(),
            lp_pubkey_hex: l_pk.to_string(),
            vtxo_pk_script_hex: hex::encode(vtxo_pk_script.as_bytes()),
            dispute_script_hex: hex::encode(dispute_script.as_bytes()),
            user_payout_script_hex: hex::encode(p2tr_script(&user_kp).as_bytes()),
            lp_payout_script_hex: hex::encode(p2tr_script(&lp_kp).as_bytes()),
            user_manifest_sig_hex: String::new(),
            lp_manifest_sig_hex: String::new(),
        };
        let digest = compute_manifest_hash(&manifest);
        let msg = Message::from_digest(digest);
        manifest.user_manifest_sig_hex =
            hex::encode(secp.sign_schnorr_no_aux_rand(&msg, &user_kp).serialize());
        manifest.lp_manifest_sig_hex =
            hex::encode(secp.sign_schnorr_no_aux_rand(&msg, &lp_kp).serialize());

        let dispute = DisputePackageSpec {
            script_hex: hex::encode(dispute_script.as_bytes()),
            control_block_hex: hex::encode(ctrl.serialize()),
            csv_sequence: csv_seq,
            oracle_quorum: DisputeQuorum {
                threshold: 2,
                oracles: vec![
                    DisputeOracleEntry { name: Some("O1".into()), pubkey: o1_pk.to_string() },
                    DisputeOracleEntry { name: Some("O2".into()), pubkey: o2_pk.to_string() },
                    DisputeOracleEntry { name: Some("O3".into()), pubkey: o3_pk.to_string() },
                ],
            },
            manifest: Some(manifest),
        };
        let bounty = BountySpec {
            amount_sats: 1_000,
            vout: 2,
            primary_pubkey: wt_pk.to_string(),
            backup_pubkeys: vec![],
            backup_csv: 4,
        };
        (dispute, bounty, [o1, o2, o3])
    }

    #[test]
    fn builds_dispute_tx_with_bounty_and_miner_fee() {
        let (dispute, bounty, _) = make_fixture();
        let built = build_watchtower_dispute_tx(
            &dispute,
            &bounty,
            100_000.0,
            1_760_086_400, // +1 day
            DEFAULT_DISPUTE_MINER_FEE_SATS,
        )
        .unwrap();

        assert_eq!(built.unsigned_tx.output.len(), 3);
        assert_eq!(built.bounty_sats, 1_000);
        assert_eq!(built.miner_fee_sats, 350);
        // Exact collateral conservation: user + lp + bounty + miner_fee == 200_000
        assert_eq!(
            built.user_payout_sats + built.lp_payout_sats + built.bounty_sats + built.miner_fee_sats,
            200_000
        );
        // Output 2 must match compiled tiered NUMS P2TR bounty script
        let compiled = BountyScript::compile(bounty).unwrap();
        assert_eq!(built.unsigned_tx.output[2].script_pubkey, compiled.script_pubkey);
        assert_eq!(built.unsigned_tx.output[2].value.to_sat(), 1_000);
        assert_eq!(built.rpc_params["miner_fee_sats"], 350);
        assert_eq!(built.rpc_params["bounty_sats"], 1_000);
    }

    #[test]
    fn assembles_2_of_3_witness_and_rejects_insufficient_or_tampered() {
        let secp = Secp256k1::new();
        let (mut dispute, bounty, [o1, _o2, o3]) = make_fixture();
        let built = build_watchtower_dispute_tx(
            &dispute,
            &bounty,
            100_000.0,
            1_760_086_400,
            DEFAULT_DISPUTE_MINER_FEE_SATS,
        )
        .unwrap();

        let msg = Message::from_digest(built.sighash);
        let sig1 = hex::encode(secp.sign_schnorr_no_aux_rand(&msg, &o1).serialize());
        let sig3 = hex::encode(secp.sign_schnorr_no_aux_rand(&msg, &o3).serialize());

        // 1-of-3 must fail
        let mut only_one = HashMap::new();
        only_one.insert(o1.x_only_public_key().0.to_string(), sig1.clone());
        assert!(assemble_dispute_tx_witness(&built, &dispute, &only_one).is_err());

        // 2-of-3 (O1 + O3, with O2 offline) must succeed with reverse-order witness stack
        let mut two = HashMap::new();
        two.insert(o1.x_only_public_key().0.to_string(), sig1);
        two.insert(o3.x_only_public_key().0.to_string(), sig3);
        let final_tx = assemble_dispute_tx_witness(&built, &dispute, &two).unwrap();
        // Witness elements: [sig_O3, empty_O2, sig_O1, dispute_script, control_block]
        assert_eq!(final_tx.input[0].witness.len(), 5);
        assert_eq!(final_tx.input[0].witness.nth(0).unwrap().len(), 64);
        assert_eq!(final_tx.input[0].witness.nth(1).unwrap().len(), 0);
        assert_eq!(final_tx.input[0].witness.nth(2).unwrap().len(), 64);

        // Tampered manifest must be rejected
        dispute.manifest.as_mut().unwrap().notional_fiat = 999.0;
        assert!(verify_dispute_manifest(dispute.manifest.as_ref().unwrap()).is_err());
    }
}
