//! BIP-340 Schnorr adaptor signature completion and contract exit finalization.

use anyhow::{anyhow, ensure, Result};
use kormir::bitcoin::secp256k1::{Message, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};
use kormir::bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use kormir::bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash};
use kormir::bitcoin::{Amount, ScriptBuf, Transaction, TxOut, Witness};
use kormir::OracleAttestation;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdaptorSig {
    pub r_xonly: [u8; 32],
    pub s_prime: [u8; 32],
}

impl AdaptorSig {
    /// Parse a 64-byte `(R_x || s')` or 65-byte `(compressed R || s')` hex adaptor signature.
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s.trim()).map_err(|e| anyhow!("adaptor sig hex: {e}"))?;
        match bytes.len() {
            64 => {
                let mut r_xonly = [0u8; 32];
                let mut s_prime = [0u8; 32];
                r_xonly.copy_from_slice(&bytes[..32]);
                s_prime.copy_from_slice(&bytes[32..64]);
                Ok(Self { r_xonly, s_prime })
            }
            65 => {
                let pk = PublicKey::from_slice(&bytes[..33])
                    .map_err(|e| anyhow!("adaptor R point: {e}"))?;
                let (xonly, _) = pk.x_only_public_key();
                let mut s_prime = [0u8; 32];
                s_prime.copy_from_slice(&bytes[33..65]);
                Ok(Self { r_xonly: xonly.serialize(), s_prime })
            }
            n => anyhow::bail!("adaptor signature must be 64 or 65 bytes, got {n}"),
        }
    }

    /// Complete the adaptor signature with the oracle attestation scalar `t`:
    /// `s = (s' + t) mod n`, returning a standard 64-byte BIP-340 Schnorr signature.
    pub fn complete(&self, attestation_scalar: &[u8; 32]) -> Result<kormir::bitcoin::secp256k1::schnorr::Signature> {
        let mut s_key = SecretKey::from_slice(&self.s_prime)
            .map_err(|e| anyhow!("invalid adaptor s': {e}"))?;
        let tweak = Scalar::from_be_bytes(*attestation_scalar)
            .map_err(|e| anyhow!("invalid attestation scalar: {e}"))?;
        s_key = s_key
            .add_tweak(&tweak)
            .map_err(|e| anyhow!("scalar addition overflow: {e}"))?;

        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&self.r_xonly);
        sig_bytes[32..64].copy_from_slice(&s_key.secret_bytes());
        kormir::bitcoin::secp256k1::schnorr::Signature::from_slice(&sig_bytes)
            .map_err(|e| anyhow!("completed schnorr sig: {e}"))
    }
}

/// Sum the `s` scalars (bytes 32..64) of the first `prefix_len` BIP-340 oracle
/// attestation signatures modulo the secp256k1 curve order `n`.
pub fn sum_attestation_scalars(att: &OracleAttestation, prefix_len: usize) -> Result<[u8; 32]> {
    ensure!(prefix_len > 0, "prefix_len must be > 0");
    ensure!(
        att.signatures.len() >= prefix_len,
        "attestation has {} signatures, need {prefix_len}",
        att.signatures.len()
    );
    let mut acc = SecretKey::from_slice(&att.signatures[0].as_ref()[32..64])
        .map_err(|e| anyhow!("invalid first oracle sig scalar: {e}"))?;
    for sig in &att.signatures[1..prefix_len] {
        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&sig.as_ref()[32..64]);
        let tweak = Scalar::from_be_bytes(s_bytes)
            .map_err(|e| anyhow!("invalid oracle sig scalar: {e}"))?;
        acc = acc
            .add_tweak(&tweak)
            .map_err(|e| anyhow!("oracle scalar sum overflow: {e}"))?;
    }
    Ok(acc.secret_bytes())
}

/// Extract the attested binary outcome string from a kormir `OracleAttestation`.
pub fn attestation_outcome_string(att: &OracleAttestation) -> String {
    att.outcomes.concat()
}

/// Attach Tapscript witness `[lp_sig, user_sig, exit_script, exit_control_block]`
/// and verify both BIP-340 Schnorr signatures against the contract VTXO prevout.
pub fn finalize_exit_tx(
    unsigned_tx: &Transaction,
    vtxo_amount_sats: u64,
    vtxo_script_pubkey: &ScriptBuf,
    exit_script: &ScriptBuf,
    exit_control_block: &ControlBlock,
    user_pubkey: &XOnlyPublicKey,
    lp_pubkey: &XOnlyPublicKey,
    user_sig: &kormir::bitcoin::secp256k1::schnorr::Signature,
    lp_sig: &kormir::bitcoin::secp256k1::schnorr::Signature,
) -> Result<Transaction> {
    ensure!(unsigned_tx.input.len() == 1, "exit tx must have 1 input");
    let prevout = TxOut {
        value: Amount::from_sat(vtxo_amount_sats),
        script_pubkey: vtxo_script_pubkey.clone(),
    };
    let leaf_hash = TapLeafHash::from_script(exit_script, LeafVersion::TapScript);
    let sighash = SighashCache::new(unsigned_tx)
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[prevout]),
            leaf_hash,
            TapSighashType::Default,
        )
        .map_err(|e| anyhow!("exit tx sighash: {e}"))?;

    let secp = Secp256k1::verification_only();
    let msg = Message::from_digest_slice(sighash.as_ref())?;
    secp.verify_schnorr(user_sig, &msg, user_pubkey)
        .map_err(|e| anyhow!("invalid user exit signature: {e}"))?;
    secp.verify_schnorr(lp_sig, &msg, lp_pubkey)
        .map_err(|e| anyhow!("invalid LP exit signature: {e}"))?;

    let mut final_tx = unsigned_tx.clone();
    let mut witness = Witness::new();
    witness.push(lp_sig.as_ref());
    witness.push(user_sig.as_ref());
    witness.push(exit_script.as_bytes());
    witness.push(exit_control_block.serialize());
    final_tx.input[0].witness = witness;

    Ok(final_tx)
}
