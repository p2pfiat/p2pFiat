//! Independent onchain P2TR fee wallet for the keyless watchtower.
//!
//! Holds only the watchtower's own BTC key (no user or LP keys).
//! Builds version-3 (TRUC) CPFP child transactions spending 0-sat P2A anchors
//! (`OP_1 <0x4e73>`) alongside a confirmed P2TR fee UTXO.

use anyhow::{anyhow, ensure, Context, Result};
use kormir::bitcoin::absolute::LockTime;
use kormir::bitcoin::key::TapTweak;
use kormir::bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use kormir::bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use kormir::bitcoin::transaction::Version;
use kormir::bitcoin::{Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use nostr_sdk::prelude::{Keys as NostrKeys, SecretKey as NostrSecretKey};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Standard Pay-to-Anchor (P2A) witness v1 2-byte program: `OP_1 OP_PUSHBYTES_2 0x4e73`.
pub const P2A_SCRIPT_BYTES: [u8; 4] = [0x51, 0x02, 0x4e, 0x73];

/// A confirmed or spendable UTXO belonging to the watchtower wallet.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletUtxo {
    pub outpoint: OutPoint,
    pub value_sats: u64,
    /// True if confirmed onchain (required for v2 UTXOs spent by a v3 TRUC CPFP child).
    pub confirmed: bool,
    /// True if this UTXO was created by a v3 (TRUC) tx.
    #[serde(default)]
    pub is_v3: bool,
}

/// Independent P2TR wallet owned by the watchtower for paying CPFP fees and
/// receiving swept bounties.
#[derive(Debug, Clone)]
pub struct WatchtowerWallet {
    secret: SecretKey,
    keypair: Keypair,
    tweaked_keypair: Keypair,
    pub xonly_pubkey: XOnlyPublicKey,
    pub network: Network,
    pub address: Address,
    pub script_pubkey: ScriptBuf,
}

impl WatchtowerWallet {
    pub fn from_secret(secret: SecretKey, network: Network) -> Self {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let (xonly_pubkey, _) = keypair.x_only_public_key();
        let tweaked_keypair = keypair.tap_tweak(&secp, None).to_keypair();
        let address = Address::p2tr(&secp, xonly_pubkey, None, network);
        let script_pubkey = address.script_pubkey();
        Self {
            secret,
            keypair,
            tweaked_keypair,
            xonly_pubkey,
            network,
            address,
            script_pubkey,
        }
    }

    pub fn load(path: &Path, network: Network) -> Result<Self> {
        let raw = std::fs::read_to_string(path).with_context(|| format!("read watchtower key {path:?}"))?;
        let bytes = hex::decode(raw.trim()).context("watchtower key file is not valid hex")?;
        let secret = SecretKey::from_slice(&bytes).context("invalid watchtower secret key")?;
        Ok(Self::from_secret(secret, network))
    }

    pub fn generate_and_save(path: &Path, network: Network) -> Result<Self> {
        ensure!(!path.exists(), "watchtower key {path:?} already exists; refusing to overwrite");
        let secret = SecretKey::new(&mut rand::thread_rng());
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, hex::encode(secret.secret_bytes()))?;
        Ok(Self::from_secret(secret, network))
    }

    /// Nostr identity matching this watchtower's x-only pubkey (for NIP-17 DMs).
    pub fn nostr_keys(&self) -> NostrKeys {
        NostrKeys::new(
            NostrSecretKey::from_slice(&self.secret.secret_bytes())
                .expect("valid secp256k1 secret key"),
        )
    }

    /// Raw (untweaked) keypair used for Tapscript leaf spends (bounty sweep).
    pub fn keypair(&self) -> &Keypair {
        &self.keypair
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.secret_bytes()
    }

    /// Select a UTXO eligible to fund a v3 (TRUC) CPFP child transaction.
    pub fn select_cpfp_utxo<'a>(&self, utxos: &'a [WalletUtxo], fee_sats: u64) -> Result<&'a WalletUtxo> {
        utxos
            .iter()
            .filter(|u| u.confirmed && u.value_sats > fee_sats + 546)
            .max_by_key(|u| u.value_sats)
            .ok_or_else(|| {
                anyhow!(
                    "no confirmed watchtower UTXO with > {} sats (TRUC v3 requires confirmed fee UTXO)",
                    fee_sats + 546
                )
            })
    }

    /// Build a signed v3 (TRUC) CPFP child transaction spending the parent's P2A
    /// anchor (input 0, empty witness) and `fee_utxo` (input 1, P2TR key-path spend).
    pub fn build_cpfp_child(
        &self,
        parent: &Transaction,
        fee_utxo: &WalletUtxo,
        fee_sats: u64,
    ) -> Result<(Transaction, WalletUtxo)> {
        ensure!(
            fee_utxo.confirmed,
            "TRUC-violation guard: CPFP fee UTXO {} must be confirmed",
            fee_utxo.outpoint
        );
        let (anchor_vout, anchor_txout) = find_p2a_anchor(parent)?;
        let anchor_outpoint = OutPoint { txid: parent.compute_txid(), vout: anchor_vout };
        let anchor_val = anchor_txout.value.to_sat();
        let total_in = fee_utxo
            .value_sats
            .checked_add(anchor_val)
            .ok_or_else(|| anyhow!("input value overflow"))?;
        ensure!(
            total_in > fee_sats + 546,
            "watchtower UTXO ({total_in} sats) insufficient for CPFP fee ({fee_sats} sats) + dust"
        );
        let change_val = total_in - fee_sats;

        let mut child = Transaction {
            version: Version(3),
            lock_time: LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: anchor_outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                },
                TxIn {
                    previous_output: fee_utxo.outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                },
            ],
            output: vec![TxOut {
                value: Amount::from_sat(change_val),
                script_pubkey: self.script_pubkey.clone(),
            }],
        };

        let prevouts = [
            anchor_txout.clone(),
            TxOut {
                value: Amount::from_sat(fee_utxo.value_sats),
                script_pubkey: self.script_pubkey.clone(),
            },
        ];
        let sighash = SighashCache::new(&child)
            .taproot_key_spend_signature_hash(
                1,
                &Prevouts::All(&prevouts),
                TapSighashType::Default,
            )
            .map_err(|e| anyhow!("cpfp sighash: {e}"))?;

        let secp = Secp256k1::new();
        let msg = Message::from_digest_slice(sighash.as_ref())?;
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &self.tweaked_keypair);

        let mut w = Witness::new();
        w.push(sig.as_ref());
        child.input[1].witness = w;

        let change_utxo = WalletUtxo {
            outpoint: OutPoint { txid: child.compute_txid(), vout: 0 },
            value_sats: change_val,
            confirmed: false,
            is_v3: true,
        };
        Ok((child, change_utxo))
    }
}

/// Find the P2A (`OP_1 <0x4e73>`) anchor output in a virtual transaction.
pub fn find_p2a_anchor(tx: &Transaction) -> Result<(u32, &TxOut)> {
    for (idx, out) in tx.output.iter().enumerate() {
        if out.script_pubkey.as_bytes() == P2A_SCRIPT_BYTES {
            return Ok((idx as u32, out));
        }
    }
    anyhow::bail!("no P2A anchor output found in tx {}", tx.compute_txid())
}

/// Parse Bitcoin network name (`bitcoin`/`mainnet`, `testnet`, `signet`, `regtest`).
pub fn parse_network(s: &str) -> Result<Network> {
    match s.trim().to_ascii_lowercase().as_str() {
        "bitcoin" | "mainnet" => Ok(Network::Bitcoin),
        "testnet" | "testnet3" => Ok(Network::Testnet),
        "signet" => Ok(Network::Signet),
        "regtest" => Ok(Network::Regtest),
        other => anyhow::bail!("unknown bitcoin network {other:?}"),
    }
}
