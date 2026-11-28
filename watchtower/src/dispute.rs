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
//!    contract's Nostracle quorum, assembled into the witness of ONE dispute leaf.
//!
//! Since p2pFiat 06f8e70 a k-of-n quorum is one arkd `CSVMultisigTapscript` leaf per k-subset
//! (`<csv> CSV DROP <O_1> CHECKSIGVERIFY ... <O_k> CHECKSIG`): all k keys of the spent leaf must
//! sign. Older contracts use one `OP_CHECKSIGADD` leaf (empty pushes for non-signers).
//! A v2 manifest (`p2pfiat/dispute-manifest/v2`, p2pFiat#20) commits to every subset leaf, so
//! when an oracle of the primary leaf is offline the watchtower asks k oracles that did sign to
//! sign the same tx for their own leaf (see `nostr_io::resolve_pending_disputes`).

use crate::bounty::{parse_xonly, BountyScript, BountySpec};
use crate::client::parse_outpoint;
use crate::storage::{DisputeLeafSpec, DisputeManifest, DisputePackageSpec};
use anyhow::{anyhow, ensure, Context, Result};
use kormir::bitcoin::absolute::LockTime;
use kormir::bitcoin::consensus::encode::serialize_hex;
use kormir::bitcoin::hashes::{sha256, Hash};
use kormir::bitcoin::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGADD, OP_CHECKSIGVERIFY, OP_CSV, OP_DROP};
use kormir::bitcoin::opcodes::Opcode;
use kormir::bitcoin::script::Instruction;
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
const MANIFEST_TAG_V2: &[u8] = b"p2pfiat/dispute-manifest/v2";

/// Deterministic BIP-340 tagged hash of a Contract Manifest, matching
/// `nostracle::dispute::compute_manifest_hash` and `mvp/web/src/dispute-manifest.js`:
/// v1 over `dispute_script_hex`, v2 over the sorted, comma-joined committed leaf hashes.
pub fn compute_manifest_hash(m: &DisputeManifest) -> [u8; 32] {
    let (tag, dispute_field) = if m.manifest_version == 2 {
        let mut hashes: Vec<String> = m
            .dispute_leaf_hashes_hex
            .iter()
            .map(|h| h.trim().to_lowercase())
            .collect();
        hashes.sort();
        (MANIFEST_TAG_V2, hashes.join(","))
    } else {
        (MANIFEST_TAG, m.dispute_script_hex.trim().to_lowercase())
    };
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
        dispute_field,
        m.user_payout_script_hex.trim().to_lowercase(),
        m.lp_payout_script_hex.trim().to_lowercase(),
    );
    let tag_hash = sha256::Hash::hash(tag);
    let mut preimage = Vec::with_capacity(64 + canonical.len());
    preimage.extend_from_slice(tag_hash.as_byte_array());
    preimage.extend_from_slice(tag_hash.as_byte_array());
    preimage.extend_from_slice(canonical.as_bytes());
    sha256::Hash::hash(&preimage).to_byte_array()
}

/// Cryptographically verify BOTH User and LP BIP-340 signatures on a `DisputeManifest`.
pub fn verify_dispute_manifest(m: &DisputeManifest) -> Result<()> {
    ensure!(
        m.manifest_version == 1 || m.manifest_version == 2,
        "unsupported manifest_version {}",
        m.manifest_version
    );
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
    let mut rpc_params = rpc_params;
    if manifest.manifest_version == 2 {
        rpc_params["manifest_version"] = json!(2);
        rpc_params["dispute_leaf_hashes_hex"] = json!(manifest.dispute_leaf_hashes_hex);
    }

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

/// Oracle keys of a dispute leaf in script order, and whether it is the legacy
/// `OP_CHECKSIGADD` shape. Strict: the leaf must start with `<csv> CSV DROP` and then be exactly
/// `(<pk> CHECKSIGVERIFY)* <pk> CHECKSIG` or `<pk> CHECKSIG (<pk> CHECKSIGADD)* <k> GREATERTHANOREQUAL`.
/// Opcodes are parsed, never found by byte search (0xba also occurs inside pubkeys).
pub fn dispute_leaf_keys(script: &ScriptBuf) -> Result<(Vec<String>, bool)> {
    let ins: Vec<Instruction> = script
        .instructions()
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow!("undecodable dispute leaf: {e}"))?;
    let op = |i: usize| match ins.get(i) {
        Some(Instruction::Op(o)) => Some(*o),
        _ => None,
    };
    let bad = || anyhow!("unrecognised dispute leaf script");
    ensure!(op(1) == Some(OP_CSV) && op(2) == Some(OP_DROP), bad());
    let is_sig_op = |o: Opcode| o == OP_CHECKSIG || o == OP_CHECKSIGVERIFY || o == OP_CHECKSIGADD;
    let mut keys = Vec::new();
    let mut sig_ops = Vec::new();
    let mut i = 3;
    let mut tail = Vec::new();
    while i < ins.len() {
        match &ins[i] {
            Instruction::PushBytes(b) if b.len() == 32 => {
                let next = op(i + 1).filter(|o| is_sig_op(*o)).ok_or_else(bad)?;
                keys.push(hex::encode(b.as_bytes()));
                sig_ops.push(next);
                i += 2;
            }
            Instruction::Op(o) if is_sig_op(*o) => return Err(bad()),
            other => {
                tail.push(*other);
                i += 1;
            }
        }
    }
    ensure!(keys.len() >= 2, "dispute leaf has fewer than 2 oracle keys");
    if sig_ops.contains(&OP_CHECKSIGADD) {
        ensure!(
            sig_ops[0] == OP_CHECKSIG && sig_ops[1..].iter().all(|o| *o == OP_CHECKSIGADD),
            bad()
        );
        // <k> GREATERTHANOREQUAL
        ensure!(tail.len() == 2, bad());
        return Ok((keys, true));
    }
    ensure!(
        tail.is_empty()
            && sig_ops.last() == Some(&OP_CHECKSIG)
            && sig_ops[..sig_ops.len() - 1].iter().all(|o| *o == OP_CHECKSIGVERIFY),
        bad()
    );
    Ok((keys, false))
}

/// Every dispute leaf the watchtower may spend, primary (`script_hex`) first. For a v2 manifest
/// only committed leaves are returned; v1 and older packages yield just the primary leaf.
pub fn dispute_leaves(dispute: &DisputePackageSpec) -> Vec<DisputeLeafSpec> {
    let primary = DisputeLeafSpec {
        script_hex: dispute.script_hex.trim().to_lowercase(),
        control_block_hex: dispute.control_block_hex.trim().to_lowercase(),
    };
    let Some(m) = dispute.manifest.as_ref().filter(|m| m.manifest_version == 2) else {
        return vec![primary];
    };
    let committed: std::collections::HashSet<String> = m
        .dispute_leaf_hashes_hex
        .iter()
        .map(|h| h.trim().to_lowercase())
        .collect();
    let mut out = vec![primary.clone()];
    for leaf in &dispute.leaves {
        let Ok(bytes) = hex::decode(leaf.script_hex.trim()) else { continue };
        let h = TapLeafHash::from_script(&ScriptBuf::from_bytes(bytes), LeafVersion::TapScript);
        if committed.contains(&h.to_string()) && leaf.script_hex.trim().to_lowercase() != primary.script_hex {
            out.push(leaf.clone());
        }
    }
    out
}

/// The `sign_dispute` request and witness data for spending ONE dispute leaf with a built tx.
#[derive(Debug, Clone)]
pub struct DisputeLeafRequest {
    pub script: ScriptBuf,
    pub control_block: ControlBlock,
    /// Oracle keys in script order (lowercase x-only hex).
    pub keys: Vec<String>,
    pub legacy_checksigadd: bool,
    pub sighash: [u8; 32],
    pub rpc_params: Value,
}

/// Sighash and RPC params for spending `leaf` with the (fixed) `built` dispute tx. The tx and
/// its txid do not depend on the leaf, so an oracle that already approved the tx for one
/// committed leaf will sign it for another.
pub fn leaf_request(
    built: &BuiltDisputeTx,
    dispute: &DisputePackageSpec,
    leaf: &DisputeLeafSpec,
) -> Result<DisputeLeafRequest> {
    let manifest = dispute
        .manifest
        .as_ref()
        .ok_or_else(|| anyhow!("dispute package missing 2-party signed manifest"))?;
    let script = ScriptBuf::from_bytes(hex::decode(leaf.script_hex.trim()).context("leaf script_hex")?);
    let cb_bytes = hex::decode(leaf.control_block_hex.trim()).context("leaf control_block_hex")?;
    let control_block =
        ControlBlock::decode(&cb_bytes).map_err(|e| anyhow!("invalid dispute control block: {e}"))?;
    let (keys, legacy_checksigadd) = dispute_leaf_keys(&script)?;
    let prevout = TxOut {
        value: Amount::from_sat(manifest.total_collateral_sats),
        script_pubkey: ScriptBuf::from_bytes(
            hex::decode(manifest.vtxo_pk_script_hex.trim()).context("vtxo_pk_script_hex")?,
        ),
    };
    let leaf_hash = TapLeafHash::from_script(&script, LeafVersion::TapScript);
    let sighash_obj = SighashCache::new(&built.unsigned_tx)
        .taproot_script_spend_signature_hash(0, &Prevouts::All(&[prevout]), leaf_hash, TapSighashType::Default)
        .map_err(|e| anyhow!("dispute tx sighash: {e}"))?;
    let mut sighash = [0u8; 32];
    sighash.copy_from_slice(sighash_obj.as_ref());
    let mut rpc_params = built.rpc_params.clone();
    rpc_params["dispute_script_hex"] = json!(hex::encode(script.as_bytes()));
    rpc_params["sighash_hex"] = json!(hex::encode(sighash));
    Ok(DisputeLeafRequest {
        script,
        control_block,
        keys,
        legacy_checksigadd,
        sighash,
        rpc_params,
    })
}

/// Oracle keys of `leaf` whose returned signature verifies against `leaf.sighash`.
pub fn verified_signers(
    leaf: &DisputeLeafRequest,
    sigs_by_pubkey: &HashMap<String, String>,
) -> HashMap<String, [u8; 64]> {
    let secp = Secp256k1::verification_only();
    let msg = Message::from_digest(leaf.sighash);
    let mut verified = HashMap::new();
    for (pk_hex, sig_hex) in sigs_by_pubkey {
        let pk_key = pk_hex.trim().to_lowercase();
        let Ok(pk) = parse_xonly(&pk_key) else { continue };
        let Ok(sig_bytes) = hex::decode(sig_hex.trim()) else { continue };
        let Ok(sig) = SchnorrSig::from_slice(&sig_bytes) else { continue };
        if secp.verify_schnorr(&sig, &msg, &pk).is_ok() {
            verified.insert(pk_key, sig.serialize());
        }
    }
    verified
}

/// Verify the oracle signatures for `leaf` and attach its Tapscript witness to the tx:
/// - CSVMultisig leaf: every one of its k keys must sign; signatures in reverse script order
///   (first key's signature on top), no empty slots.
/// - Legacy CHECKSIGADD leaf: `>= threshold` signatures, empty push for each non-signer.
pub fn assemble_dispute_tx_witness(
    built: &BuiltDisputeTx,
    leaf: &DisputeLeafRequest,
    threshold: usize,
    sigs_by_pubkey: &HashMap<String, String>,
) -> Result<Transaction> {
    ensure!(threshold >= 1, "dispute threshold must be >= 1");
    let verified = verified_signers(leaf, sigs_by_pubkey);
    let signed_in_leaf = leaf.keys.iter().filter(|k| verified.contains_key(*k)).count();
    if leaf.legacy_checksigadd {
        ensure!(
            signed_in_leaf >= threshold,
            "only {signed_in_leaf}/{threshold} valid Nostracle signatures collected for Leaf 2 dispute"
        );
    } else {
        let missing: Vec<&str> = leaf
            .keys
            .iter()
            .filter(|k| !verified.contains_key(*k))
            .map(|k| &k[..8])
            .collect();
        ensure!(
            missing.is_empty(),
            "dispute leaf needs all {} of its oracles to sign; missing {}",
            leaf.keys.len(),
            missing.join(", ")
        );
    }

    let mut witness = Witness::new();
    for k in leaf.keys.iter().rev() {
        match verified.get(k) {
            Some(sig) => witness.push(sig),
            None => witness.push([]), // legacy CHECKSIGADD only
        }
    }
    witness.push(leaf.script.as_bytes());
    witness.push(leaf.control_block.serialize());

    let mut final_tx = built.unsigned_tx.clone();
    final_tx.input[0].witness = witness;
    Ok(final_tx)
}

/// Round 1 of a dispute: which leaf (index into `leaves`, primary first) each oracle is asked
/// to sign. A Nostracle only signs a leaf that contains its own key, so asking every oracle for
/// the primary leaf would make the online oracles outside it look offline. Each oracle gets the
/// primary leaf if it holds the oracle's key, else the first leaf that does. All requests are
/// for the same fixed tx, which the Nostracle txid lock allows across leaves. Oracles in no
/// leaf are left out.
pub fn plan_round1(leaves: &[DisputeLeafRequest], oracles: &[String]) -> Vec<(usize, Vec<String>)> {
    let mut groups: Vec<(usize, Vec<String>)> = Vec::new();
    for raw in oracles {
        let pk = raw.trim().to_lowercase();
        let Some(idx) = leaves.iter().position(|l| l.keys.contains(&pk)) else { continue };
        match groups.iter_mut().find(|(i, _)| *i == idx) {
            Some((_, pks)) => pks.push(pk),
            None => groups.push((idx, vec![pk])),
        }
    }
    groups.sort_by_key(|(i, _)| *i);
    groups
}

/// After round 1: every oracle with a verified signature for any leaf is live. Pick the primary
/// leaf (index 0) if all its oracles are live, else the first leaf whose oracles all are.
/// `verified_by_leaf[i]` holds the verified signatures for `leaves[i]`. Returns the chosen leaf
/// index and the oracles of that leaf that still have to sign it, or None when no leaf has all
/// its oracles live. A legacy CHECKSIGADD primary leaf only needs `threshold` signers.
pub fn plan_round2(
    leaves: &[DisputeLeafRequest],
    verified_by_leaf: &[HashMap<String, [u8; 64]>],
    threshold: usize,
) -> Option<(usize, Vec<String>)> {
    let primary = leaves.first()?;
    if primary.legacy_checksigadd {
        let have = verified_by_leaf.first().map(|m| m.len()).unwrap_or(0);
        return (have >= threshold).then(|| (0, Vec::new()));
    }
    let live: std::collections::HashSet<&String> = verified_by_leaf.iter().flat_map(|m| m.keys()).collect();
    let idx = leaves
        .iter()
        .position(|l| !l.legacy_checksigadd && l.keys.iter().all(|k| live.contains(k)))?;
    let have = verified_by_leaf.get(idx);
    let missing = leaves[idx]
        .keys
        .iter()
        .filter(|k| !have.is_some_and(|m| m.contains_key(*k)))
        .cloned()
        .collect();
    Some((idx, missing))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounty::nums_internal_key;
    use crate::storage::{DisputeOracleEntry, DisputeQuorum};
    use kormir::bitcoin::opcodes::all::OP_GREATERTHANOREQUAL;
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
            manifest_version: 1,
            dispute_leaf_hashes_hex: Vec::new(),
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
            leaves: Vec::new(),
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

        let leaf = leaf_request(&built, &dispute, &dispute_leaves(&dispute)[0]).unwrap();
        assert!(leaf.legacy_checksigadd);
        assert_eq!(leaf.sighash, built.sighash);

        // 1-of-3 must fail
        let mut only_one = HashMap::new();
        only_one.insert(o1.x_only_public_key().0.to_string(), sig1.clone());
        assert!(assemble_dispute_tx_witness(&built, &leaf, 2, &only_one).is_err());

        // 2-of-3 (O1 + O3, with O2 offline) must succeed with reverse-order witness stack
        let mut two = HashMap::new();
        two.insert(o1.x_only_public_key().0.to_string(), sig1);
        two.insert(o3.x_only_public_key().0.to_string(), sig3);
        let final_tx = assemble_dispute_tx_witness(&built, &leaf, 2, &two).unwrap();
        // Witness elements: [sig_O3, empty_O2, sig_O1, dispute_script, control_block]
        assert_eq!(final_tx.input[0].witness.len(), 5);
        assert_eq!(final_tx.input[0].witness.nth(0).unwrap().len(), 64);
        assert_eq!(final_tx.input[0].witness.nth(1).unwrap().len(), 0);
        assert_eq!(final_tx.input[0].witness.nth(2).unwrap().len(), 64);

        // Tampered manifest must be rejected
        dispute.manifest.as_mut().unwrap().notional_fiat = 999.0;
        assert!(verify_dispute_manifest(dispute.manifest.as_ref().unwrap()).is_err());
    }

    // ---- manifest v2 + arkd CSVMultisig subset leaves ----

    fn csv_multisig_leaf(keys: &[Keypair]) -> ScriptBuf {
        let mut b = Builder::new()
            .push_int(((1 << 22) | 4) as i64)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP);
        for (i, k) in keys.iter().enumerate() {
            b = b.push_x_only_key(&k.x_only_public_key().0);
            b = b.push_opcode(if i + 1 == keys.len() { OP_CHECKSIG } else { OP_CHECKSIGVERIFY });
        }
        b.into_script()
    }

    /// 3-of-5 quorum, 10 subset leaves in one taptree, v2 manifest committing to all of them.
    /// The primary leaf is oracles #1,#2,#3.
    fn make_v2_fixture() -> (DisputePackageSpec, BountySpec, Vec<Keypair>) {
        let secp = Secp256k1::new();
        let (user_kp, lp_kp, wt_kp) = (kp(1), kp(2), kp(3));
        let oracles: Vec<Keypair> = (21u8..26).map(kp).collect();
        let mut subsets = Vec::new();
        for a in 0..5 {
            for b in a + 1..5 {
                for c in b + 1..5 {
                    subsets.push([a, b, c]);
                }
            }
        }
        let scripts: Vec<ScriptBuf> = subsets
            .iter()
            .map(|ix| csv_multisig_leaf(&[oracles[ix[0]], oracles[ix[1]], oracles[ix[2]]]))
            .collect();
        let spend_info = TaprootBuilder::with_huffman_tree(scripts.iter().map(|s| (1u32, s.clone())))
            .unwrap()
            .finalize(&secp, nums_internal_key())
            .unwrap();
        let vtxo_pk_script = ScriptBuf::new_p2tr_tweaked(spend_info.output_key());
        let leaves: Vec<DisputeLeafSpec> = scripts
            .iter()
            .map(|s| DisputeLeafSpec {
                script_hex: hex::encode(s.as_bytes()),
                control_block_hex: hex::encode(
                    spend_info.control_block(&(s.clone(), LeafVersion::TapScript)).unwrap().serialize(),
                ),
            })
            .collect();
        let mut hashes: Vec<String> = scripts
            .iter()
            .map(|s| TapLeafHash::from_script(s, LeafVersion::TapScript).to_string())
            .collect();
        hashes.sort();

        let mut manifest = DisputeManifest {
            contract_id: "pos-wt-v2".into(),
            vtxo_outpoint: format!("{}:0", "bb".repeat(32)),
            currency: "USD".into(),
            side: "short".into(),
            total_collateral_sats: 200_000,
            notional_fiat: 100.0,
            opened_at: 1_760_000_000,
            funding_rate_bps_per_day: 3.0,
            user_pubkey_hex: user_kp.x_only_public_key().0.to_string(),
            lp_pubkey_hex: lp_kp.x_only_public_key().0.to_string(),
            vtxo_pk_script_hex: hex::encode(vtxo_pk_script.as_bytes()),
            dispute_script_hex: leaves[0].script_hex.clone(),
            user_payout_script_hex: hex::encode(p2tr_script(&user_kp).as_bytes()),
            lp_payout_script_hex: hex::encode(p2tr_script(&lp_kp).as_bytes()),
            user_manifest_sig_hex: String::new(),
            lp_manifest_sig_hex: String::new(),
            manifest_version: 2,
            dispute_leaf_hashes_hex: hashes,
        };
        let msg = Message::from_digest(compute_manifest_hash(&manifest));
        manifest.user_manifest_sig_hex = hex::encode(secp.sign_schnorr_no_aux_rand(&msg, &user_kp).serialize());
        manifest.lp_manifest_sig_hex = hex::encode(secp.sign_schnorr_no_aux_rand(&msg, &lp_kp).serialize());

        let dispute = DisputePackageSpec {
            script_hex: leaves[0].script_hex.clone(),
            control_block_hex: leaves[0].control_block_hex.clone(),
            csv_sequence: (1 << 22) | 4,
            oracle_quorum: DisputeQuorum {
                threshold: 3,
                oracles: oracles
                    .iter()
                    .map(|o| DisputeOracleEntry { name: None, pubkey: o.x_only_public_key().0.to_string() })
                    .collect(),
            },
            manifest: Some(manifest),
            leaves,
        };
        let bounty = BountySpec {
            amount_sats: 1_000,
            vout: 2,
            primary_pubkey: wt_kp.x_only_public_key().0.to_string(),
            backup_pubkeys: vec![],
            backup_csv: 4,
        };
        (dispute, bounty, oracles)
    }

    fn sign_all(leaf: &DisputeLeafRequest, who: &[&Keypair]) -> HashMap<String, String> {
        let secp = Secp256k1::new();
        let msg = Message::from_digest(leaf.sighash);
        who.iter()
            .map(|k| {
                (
                    k.x_only_public_key().0.to_string(),
                    hex::encode(secp.sign_schnorr_no_aux_rand(&msg, k).serialize()),
                )
            })
            .collect()
    }

    #[test]
    fn csv_multisig_primary_leaf_needs_all_k_signers_and_has_no_empty_slots() {
        let (dispute, bounty, o) = make_v2_fixture();
        let built = build_watchtower_dispute_tx(&dispute, &bounty, 100_000.0, 1_760_086_400, 350).unwrap();
        assert_eq!(built.rpc_params["manifest_version"], 2);
        assert_eq!(built.rpc_params["dispute_leaf_hashes_hex"].as_array().unwrap().len(), 10);
        let leaves = dispute_leaves(&dispute);
        assert_eq!(leaves.len(), 10, "primary + 9 other committed leaves");
        let primary = leaf_request(&built, &dispute, &leaves[0]).unwrap();
        assert!(!primary.legacy_checksigadd);
        assert_eq!(primary.sighash, built.sighash);

        // #1 and #3 only: the primary leaf (#1,#2,#3) cannot be completed
        let partial = sign_all(&primary, &[&o[0], &o[2]]);
        let err = assemble_dispute_tx_witness(&built, &primary, 3, &partial).unwrap_err();
        assert!(err.to_string().contains("missing"), "unexpected err: {err}");

        let full = sign_all(&primary, &[&o[0], &o[1], &o[2]]);
        let tx = assemble_dispute_tx_witness(&built, &primary, 3, &full).unwrap();
        let w = &tx.input[0].witness;
        assert_eq!(w.len(), 5, "3 sigs + script + control block");
        assert!((0..3).all(|i| w.nth(i).unwrap().len() == 64));
        // top of stack (last sig pushed) is the first key's signature
        assert_eq!(hex::encode(w.nth(2).unwrap()), full[&o[0].x_only_public_key().0.to_string()]);
    }

    #[test]
    fn v2_falls_back_to_the_signers_committed_leaf_for_the_same_tx() {
        let (dispute, bounty, o) = make_v2_fixture();
        let built = build_watchtower_dispute_tx(&dispute, &bounty, 100_000.0, 1_760_086_400, 350).unwrap();
        let leaves = dispute_leaves(&dispute);
        let primary = leaf_request(&built, &dispute, &leaves[0]).unwrap();

        // Round 1: #2 is offline; #1, #3, #5 sign the primary leaf
        let round1 = sign_all(&primary, &[&o[0], &o[2], &o[4]]);
        let signers = verified_signers(&primary, &round1);
        let fb = leaves[1..]
            .iter()
            .filter_map(|l| leaf_request(&built, &dispute, l).ok())
            .find(|l| l.keys.iter().all(|k| signers.contains_key(k)))
            .expect("a committed leaf of #1,#3,#5");
        let want: Vec<String> = [0, 2, 4].iter().map(|i| o[*i].x_only_public_key().0.to_string()).collect();
        assert_eq!(fb.keys, want);
        assert_ne!(fb.sighash, primary.sighash, "sighash commits to the leaf");
        assert_eq!(fb.rpc_params["raw_tx_hex"], primary.rpc_params["raw_tx_hex"], "same tx, same txid");
        assert_eq!(fb.rpc_params["dispute_script_hex"], json!(hex::encode(fb.script.as_bytes())));

        // Round 2: the same three sign the fallback leaf
        let round2 = sign_all(&fb, &[&o[0], &o[2], &o[4]]);
        let tx = assemble_dispute_tx_witness(&built, &fb, 3, &round2).unwrap();
        assert_eq!(tx.compute_txid(), built.unsigned_tx.compute_txid());
        assert_eq!(tx.input[0].witness.len(), 5);
        // Round-1 signatures are for the other leaf and must not be accepted here
        assert!(assemble_dispute_tx_witness(&built, &fb, 3, &round1).is_err());
    }

    /// A Nostracle (nostracle#7) signs only a leaf that contains its own key; offline ones
    /// never answer. Returns the signatures `asked` would give for `leaf`.
    fn nostracle_answers(
        leaf: &DisputeLeafRequest,
        asked: &[String],
        o: &[Keypair],
        pks: &[String],
        offline: &[usize],
    ) -> HashMap<String, String> {
        let who: Vec<&Keypair> = asked
            .iter()
            .filter_map(|pk| {
                let i = pks.iter().position(|p| p == pk)?;
                (!offline.contains(&i) && leaf.keys.contains(pk)).then_some(&o[i])
            })
            .collect();
        sign_all(leaf, &who)
    }

    #[test]
    fn rounds_work_with_nostracles_that_only_sign_their_own_leaves() {
        let (dispute, bounty, o) = make_v2_fixture();
        let built = build_watchtower_dispute_tx(&dispute, &bounty, 100_000.0, 1_760_086_400, 350).unwrap();
        let reqs: Vec<DisputeLeafRequest> = dispute_leaves(&dispute)
            .iter()
            .map(|l| leaf_request(&built, &dispute, l).unwrap())
            .collect();
        let pks: Vec<String> = o.iter().map(|k| k.x_only_public_key().0.to_string()).collect();

        // The old flow: everyone is asked for the primary leaf (#1,#2,#3) while #2 is offline.
        // #4 and #5 refuse a leaf without their key, so no other leaf can be completed.
        let old = verified_signers(&reqs[0], &nostracle_answers(&reqs[0], &pks, &o, &pks, &[1]));
        assert!(reqs[1..].iter().all(|l| !l.keys.iter().all(|k| old.contains_key(k))));

        for (offline, expect) in [
            (vec![], Some(0usize)),
            (vec![1], None),
            (vec![1, 3], None),
            (vec![0, 1, 2], None),
        ] {
            let mut sigs_by_leaf: Vec<HashMap<String, String>> = vec![HashMap::new(); reqs.len()];
            for (idx, asked) in plan_round1(&reqs, &pks) {
                sigs_by_leaf[idx] = nostracle_answers(&reqs[idx], &asked, &o, &pks, &offline);
            }
            let verified: Vec<HashMap<String, [u8; 64]>> =
                reqs.iter().zip(&sigs_by_leaf).map(|(r, s)| verified_signers(r, s)).collect();
            let plan = plan_round2(&reqs, &verified, 3);
            if offline.len() > 2 {
                assert!(plan.is_none(), "offline {offline:?}: fewer than 3 live, no leaf");
                continue;
            }
            let (idx, missing) = plan.expect("3 or more live oracles form a leaf");
            if let Some(want) = expect {
                assert_eq!(idx, want, "all online: primary leaf");
                assert!(missing.is_empty(), "all online: no round 2");
            }
            assert!(
                reqs[idx].keys.iter().all(|k| !offline.iter().any(|i| &pks[*i] == k)),
                "offline {offline:?}: chosen leaf uses only live oracles"
            );
            let mut sigs = sigs_by_leaf[idx].clone();
            sigs.extend(nostracle_answers(&reqs[idx], &missing, &o, &pks, &offline));
            let tx = assemble_dispute_tx_witness(&built, &reqs[idx], 3, &sigs).unwrap();
            assert_eq!(tx.compute_txid(), built.unsigned_tx.compute_txid(), "same tx in both rounds");
            assert_eq!(tx.input[0].witness.len(), 5);
        }
    }

    #[test]
    fn dispute_leaves_only_offers_committed_leaves() {
        let (mut dispute, _, o) = make_v2_fixture();
        let rogue = csv_multisig_leaf(&[o[0], o[1]]);
        dispute.leaves.push(DisputeLeafSpec {
            script_hex: hex::encode(rogue.as_bytes()),
            control_block_hex: dispute.leaves[0].control_block_hex.clone(),
        });
        assert_eq!(dispute_leaves(&dispute).len(), 10, "uncommitted leaf dropped");

        let (v1, _, _) = make_fixture();
        assert_eq!(dispute_leaves(&v1).len(), 1, "v1 packages only use the primary leaf");
    }

    #[test]
    fn dispute_leaf_parser_is_strict_and_not_fooled_by_0xba_in_keys() {
        // find three oracle keys whose leaf bytes contain 0xba (OP_CHECKSIGADD) inside a pubkey
        let mut seed = 30u8;
        let leaf = loop {
            let l = csv_multisig_leaf(&[kp(seed), kp(seed + 1), kp(seed + 2)]);
            if l.as_bytes().contains(&0xba) {
                break l;
            }
            seed += 1;
        };
        let (keys, legacy) = dispute_leaf_keys(&leaf).unwrap();
        assert!(!legacy);
        assert_eq!(keys.len(), 3);

        let k = |s: u8| kp(s).x_only_public_key().0;
        let csv = ((1 << 22) | 4) as i64;
        let stray = Builder::new()
            .push_int(csv).push_opcode(OP_CSV).push_opcode(OP_DROP)
            .push_slice([9u8; 32]).push_opcode(OP_DROP)
            .push_x_only_key(&k(1)).push_opcode(OP_CHECKSIGVERIFY)
            .push_x_only_key(&k(2)).push_opcode(OP_CHECKSIG)
            .into_script();
        let trailing = Builder::new()
            .push_int(csv).push_opcode(OP_CSV).push_opcode(OP_DROP)
            .push_x_only_key(&k(1)).push_opcode(OP_CHECKSIGVERIFY)
            .push_x_only_key(&k(2)).push_opcode(OP_CHECKSIG)
            .push_opcode(OP_DROP)
            .into_script();
        let no_csv = Builder::new()
            .push_x_only_key(&k(1)).push_opcode(OP_CHECKSIGVERIFY)
            .push_x_only_key(&k(2)).push_opcode(OP_CHECKSIG)
            .into_script();
        for s in [stray, trailing, no_csv] {
            assert!(dispute_leaf_keys(&s).is_err(), "must refuse {s:?}");
        }
        let legacy = Builder::new()
            .push_int(csv).push_opcode(OP_CSV).push_opcode(OP_DROP)
            .push_x_only_key(&k(1)).push_opcode(OP_CHECKSIG)
            .push_x_only_key(&k(2)).push_opcode(OP_CHECKSIGADD)
            .push_int(2).push_opcode(OP_GREATERTHANOREQUAL)
            .into_script();
        assert!(dispute_leaf_keys(&legacy).unwrap().1);
    }

    /// Cross-language vector shared with p2pFiat `mvp/test/dispute-manifest-v2.test.mjs` and
    /// nostracle `dispute::tests::manifest_v2_hash_matches_cross_language_vector`.
    #[test]
    fn manifest_v2_hash_matches_cross_language_vector() {
        let m = DisputeManifest {
            contract_id: "pos-vector-1".into(),
            vtxo_outpoint: format!("{}:0", "aa".repeat(32)),
            currency: "USD".into(),
            side: "short".into(),
            total_collateral_sats: 333_334,
            notional_fiat: 100.0,
            opened_at: 1_795_000_000,
            funding_rate_bps_per_day: 3.0,
            user_pubkey_hex: "11".repeat(32),
            lp_pubkey_hex: "22".repeat(32),
            vtxo_pk_script_hex: format!("5120{}", "33".repeat(32)),
            dispute_script_hex: "51".into(),
            user_payout_script_hex: format!("5120{}", "44".repeat(32)),
            lp_payout_script_hex: format!("5120{}", "55".repeat(32)),
            user_manifest_sig_hex: String::new(),
            lp_manifest_sig_hex: String::new(),
            manifest_version: 2,
            dispute_leaf_hashes_hex: vec!["bb".repeat(32), "aa".repeat(32), "CC".repeat(32)],
        };
        assert_eq!(
            hex::encode(compute_manifest_hash(&m)),
            "362770732e8595c4c6c159e5aa17b142188bbd8e1ed09f7fde9547b801005116"
        );
    }

    #[test]
    fn packages_stored_before_v2_still_load() {
        let (v1, _, _) = make_fixture();
        let mut json = serde_json::to_value(&v1).unwrap();
        let m = json["manifest"].as_object_mut().unwrap();
        m.remove("manifest_version");
        m.remove("dispute_leaf_hashes_hex");
        json.as_object_mut().unwrap().remove("leaves");
        let back: DisputePackageSpec = serde_json::from_value(json).unwrap();
        assert_eq!(back.manifest.unwrap().manifest_version, 1);
        assert!(back.leaves.is_empty());
    }
}
