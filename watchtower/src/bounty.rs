//! Tiered Taproot bounty locking script and sweep transaction builder.
//!
//! Matches Experiment 13 (`13-watchtower-bounty`):
//! - Internal key: unspendable BIP-341 NUMS point `H` (key-path spend impossible,
//!   so miners and unauthorized mempool snipers cannot steal the bounty).
//! - Primary leaf (`W1`): `<W1> OP_CHECKSIG` — immediate claim (0-block delay).
//! - Backup leaves (`W2, W3, ...`): `<backup_csv> OP_CSV OP_DROP <Wi> OP_CHECKSIG`
//!   — CSV-delayed claim so backups can step in if `W1` is offline, but cannot
//!   front-run `W1` in the mempool.

use anyhow::{anyhow, ensure, Result};
use kormir::bitcoin::absolute::LockTime;
use kormir::bitcoin::opcodes::all::{OP_CHECKSIG, OP_CSV, OP_DROP};
use kormir::bitcoin::script::Builder;
use kormir::bitcoin::secp256k1::{Keypair, Message, Secp256k1, XOnlyPublicKey};
use kormir::bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use kormir::bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash, TaprootBuilder, TaprootSpendInfo};
use kormir::bitcoin::transaction::Version;
use kormir::bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Unspendable BIP-341 NUMS internal key.
pub const NUMS_INTERNAL_KEY_HEX: &str =
    "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

/// Specification of a tiered watchtower bounty output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BountySpec {
    /// Bounty output value in satoshis.
    pub amount_sats: u64,
    /// Output index of the bounty in the pre-signed exit transactions (default 2).
    #[serde(default = "default_bounty_vout")]
    pub vout: u32,
    /// Primary watchtower x-only pubkey (hex, 32 bytes). Can claim immediately.
    pub primary_pubkey: String,
    /// Backup watchtower x-only pubkeys (hex, 32 bytes each). Can claim after `backup_csv`.
    #[serde(default)]
    pub backup_pubkeys: Vec<String>,
    /// Relative block delay (BIP-68 CSV) enforced on backup watchtower leaves.
    #[serde(default = "default_backup_csv")]
    pub backup_csv: u16,
}

fn default_bounty_vout() -> u32 {
    2
}

fn default_backup_csv() -> u16 {
    4
}

/// Role of a watchtower key within a `BountySpec`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchtowerRole {
    /// Immediate claim (0-block delay).
    Primary,
    /// Delayed claim after `csv_blocks` confirmations of the exit transaction.
    Backup { csv_blocks: u16 },
}

/// Compiled Taproot bounty script with merkle proofs for primary and backup leaves.
#[derive(Debug, Clone)]
pub struct BountyScript {
    pub spec: BountySpec,
    pub script_pubkey: ScriptBuf,
    pub spend_info: TaprootSpendInfo,
    pub primary_key: XOnlyPublicKey,
    pub primary_leaf: ScriptBuf,
    pub primary_control: ControlBlock,
    pub backup_leaves: BTreeMap<XOnlyPublicKey, (ScriptBuf, ControlBlock)>,
}

pub fn nums_internal_key() -> XOnlyPublicKey {
    let bytes = hex::decode(NUMS_INTERNAL_KEY_HEX).expect("valid NUMS hex");
    XOnlyPublicKey::from_slice(&bytes).expect("valid NUMS x-only pubkey")
}

/// Build `<pk> OP_CHECKSIG`.
pub fn primary_leaf_script(pk: &XOnlyPublicKey) -> ScriptBuf {
    Builder::new()
        .push_x_only_key(pk)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// Build `<csv_blocks> OP_CSV OP_DROP <pk> OP_CHECKSIG`.
pub fn backup_leaf_script(pk: &XOnlyPublicKey, csv_blocks: u16) -> ScriptBuf {
    Builder::new()
        .push_int(csv_blocks as i64)
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_x_only_key(pk)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

impl BountyScript {
    /// Compile a `BountySpec` into its Taproot output script and leaf control blocks.
    pub fn compile(spec: BountySpec) -> Result<Self> {
        ensure!(spec.amount_sats > 546, "bounty amount {} is dust", spec.amount_sats);
        ensure!(
            spec.backup_pubkeys.is_empty() || spec.backup_csv > 0,
            "backup_csv must be > 0 when backup watchtowers are configured"
        );
        let primary_key = parse_xonly(&spec.primary_pubkey)?;
        let mut backup_keys = Vec::with_capacity(spec.backup_pubkeys.len());
        for hex_pk in &spec.backup_pubkeys {
            let pk = parse_xonly(hex_pk)?;
            ensure!(pk != primary_key, "backup pubkey duplicates primary pubkey");
            ensure!(!backup_keys.contains(&pk), "duplicate backup pubkey");
            backup_keys.push(pk);
        }

        let primary_leaf = primary_leaf_script(&primary_key);
        let mut all_leaves: Vec<(Option<XOnlyPublicKey>, ScriptBuf)> =
            vec![(None, primary_leaf.clone())];
        for pk in &backup_keys {
            all_leaves.push((Some(*pk), backup_leaf_script(pk, spec.backup_csv)));
        }

        let weights: Vec<(u32, ScriptBuf)> =
            all_leaves.iter().map(|(_, s)| (1u32, s.clone())).collect();
        let builder = TaprootBuilder::with_huffman_tree(weights)
            .map_err(|e| anyhow!("taproot huffman tree: {e:?}"))?;
        let secp = Secp256k1::verification_only();
        let spend_info = builder
            .finalize(&secp, nums_internal_key())
            .map_err(|e| anyhow!("finalize taproot tree: {e:?}"))?;
        let script_pubkey = ScriptBuf::new_p2tr_tweaked(spend_info.output_key());

        let primary_control = spend_info
            .control_block(&(primary_leaf.clone(), LeafVersion::TapScript))
            .ok_or_else(|| anyhow!("missing primary control block"))?;

        let mut backup_leaves = BTreeMap::new();
        for (maybe_pk, script) in all_leaves {
            if let Some(pk) = maybe_pk {
                let ctrl = spend_info
                    .control_block(&(script.clone(), LeafVersion::TapScript))
                    .ok_or_else(|| anyhow!("missing backup control block"))?;
                backup_leaves.insert(pk, (script, ctrl));
            }
        }

        Ok(Self {
            spec,
            script_pubkey,
            spend_info,
            primary_key,
            primary_leaf,
            primary_control,
            backup_leaves,
        })
    }

    /// Return the role of `our_pubkey` in this bounty script, if authorized.
    pub fn role_of(&self, our_pubkey: &XOnlyPublicKey) -> Option<WatchtowerRole> {
        if *our_pubkey == self.primary_key {
            Some(WatchtowerRole::Primary)
        } else if self.backup_leaves.contains_key(our_pubkey) {
            Some(WatchtowerRole::Backup { csv_blocks: self.spec.backup_csv })
        } else {
            None
        }
    }

    /// Build a signed v2 transaction sweeping the bounty output to `dest_script`
    /// using either the primary leaf (immediate) or the signer's backup leaf (CSV).
    pub fn build_sweep_tx(
        &self,
        bounty_outpoint: OutPoint,
        signer: &Keypair,
        dest_script: ScriptBuf,
        fee_sats: u64,
    ) -> Result<Transaction> {
        let (signer_xonly, _) = signer.x_only_public_key();
        let role = self
            .role_of(&signer_xonly)
            .ok_or_else(|| anyhow!("pubkey {signer_xonly} is not authorized in this bounty"))?;
        self.build_sweep_tx_for_role(bounty_outpoint, signer, role, dest_script, fee_sats)
    }

    /// Build a sweep transaction targeting a specific leaf.
    pub fn build_sweep_tx_for_role(
        &self,
        bounty_outpoint: OutPoint,
        signer: &Keypair,
        role: WatchtowerRole,
        dest_script: ScriptBuf,
        fee_sats: u64,
    ) -> Result<Transaction> {
        ensure!(
            self.spec.amount_sats > fee_sats + 546,
            "bounty {} too small for sweep fee {} + dust",
            self.spec.amount_sats,
            fee_sats
        );
        let (sequence, leaf_script, control_block) = match role {
            WatchtowerRole::Primary => (Sequence::MAX, &self.primary_leaf, &self.primary_control),
            WatchtowerRole::Backup { csv_blocks } => {
                let (pk, _) = signer.x_only_public_key();
                let (s, c) = self
                    .backup_leaves
                    .get(&pk)
                    .ok_or_else(|| anyhow!("no backup leaf for {pk}"))?;
                (Sequence::from_height(csv_blocks), s, c)
            }
        };

        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bounty_outpoint,
                script_sig: ScriptBuf::new(),
                sequence,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(self.spec.amount_sats - fee_sats),
                script_pubkey: dest_script,
            }],
        };

        let prevout = TxOut {
            value: Amount::from_sat(self.spec.amount_sats),
            script_pubkey: self.script_pubkey.clone(),
        };
        let leaf_hash = TapLeafHash::from_script(leaf_script, LeafVersion::TapScript);
        let sighash = SighashCache::new(&tx)
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&[prevout]),
                leaf_hash,
                TapSighashType::Default,
            )
            .map_err(|e| anyhow!("bounty sighash: {e}"))?;

        let secp = Secp256k1::new();
        let msg = Message::from_digest_slice(sighash.as_ref())?;
        let sig = secp.sign_schnorr_no_aux_rand(&msg, signer);

        let mut witness = Witness::new();
        witness.push(sig.as_ref());
        witness.push(leaf_script.as_bytes());
        witness.push(control_block.serialize());
        tx.input[0].witness = witness;

        Ok(tx)
    }

    /// Verify a sweep transaction's Tapscript witness and BIP-68 CSV sequence
    /// against `confirmations` of the bounty output.
    pub fn verify_sweep_tx(&self, tx: &Transaction, confirmations: u32) -> Result<WatchtowerRole> {
        ensure!(tx.input.len() == 1, "expected 1 input");
        let inp = &tx.input[0];
        let witness = &inp.witness;
        ensure!(witness.len() == 3, "expected 3 witness elements (sig, script, control)");
        let sig_bytes = witness.nth(0).ok_or_else(|| anyhow!("missing sig"))?;
        let script_bytes = witness.nth(1).ok_or_else(|| anyhow!("missing script"))?;
        let ctrl_bytes = witness.nth(2).ok_or_else(|| anyhow!("missing control block"))?;

        let sig = kormir::bitcoin::secp256k1::schnorr::Signature::from_slice(sig_bytes)
            .map_err(|e| anyhow!("invalid schnorr sig: {e}"))?;
        let script = ScriptBuf::from_bytes(script_bytes.to_vec());
        let ctrl = ControlBlock::decode(ctrl_bytes)
            .map_err(|e| anyhow!("invalid control block: {e}"))?;

        let secp = Secp256k1::verification_only();
        ensure!(
            ctrl.verify_taproot_commitment(
                &secp,
                self.spend_info.output_key().to_x_only_public_key(),
                &script
            ),
            "control block does not commit to bounty taproot output"
        );

        let (role, expected_pk) = if script == self.primary_leaf {
            (WatchtowerRole::Primary, self.primary_key)
        } else if let Some((pk, _)) = self.backup_leaves.iter().find(|(_, (s, _))| *s == script) {
            let csv = self.spec.backup_csv;
            ensure!(
                inp.sequence.is_relative_lock_time()
                    && inp.sequence.to_consensus_u32() >= Sequence::from_height(csv).to_consensus_u32(),
                "backup sweep missing CSV({csv}) sequence"
            );
            ensure!(
                confirmations >= csv as u32,
                "non-BIP68-final: backup sweep needs {csv} confirmations, have {confirmations}"
            );
            (WatchtowerRole::Backup { csv_blocks: csv }, *pk)
        } else {
            anyhow::bail!("script is not a known bounty leaf");
        };

        let prevout = TxOut {
            value: Amount::from_sat(self.spec.amount_sats),
            script_pubkey: self.script_pubkey.clone(),
        };
        let leaf_hash = TapLeafHash::from_script(&script, LeafVersion::TapScript);
        let sighash = SighashCache::new(tx)
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&[prevout]),
                leaf_hash,
                TapSighashType::Default,
            )
            .map_err(|e| anyhow!("verify sighash: {e}"))?;
        let msg = Message::from_digest_slice(sighash.as_ref())?;
        secp.verify_schnorr(&sig, &msg, &expected_pk)
            .map_err(|e| anyhow!("mempool-script-verify-flag-failed: {e}"))?;

        Ok(role)
    }
}

pub fn parse_xonly(hex_str: &str) -> Result<XOnlyPublicKey> {
    let bytes = hex::decode(hex_str.trim()).map_err(|e| anyhow!("invalid x-only pubkey hex: {e}"))?;
    XOnlyPublicKey::from_slice(&bytes).map_err(|e| anyhow!("invalid x-only pubkey: {e}"))
}
