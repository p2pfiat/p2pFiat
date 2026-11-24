use crate::wallet::parse_network;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Hex-encoded 32-byte secret key for the watchtower's independent P2TR fee wallet
    /// (also used as its Nostr identity for NIP-17 package intake).
    #[serde(default = "d_key_file")]
    pub wallet_key_file: PathBuf,
    /// JSON database storing watched exit packages and profit accounting.
    #[serde(default = "d_db_file")]
    pub db_file: PathBuf,
    /// Bitcoin network: bitcoin, testnet, signet, or regtest.
    #[serde(default = "d_network")]
    pub network: String,
    /// Esplora-compatible Bitcoin REST API URL (e.g. http://localhost:3000 or https://mempool.space/api).
    pub esplora_url: String,
    /// Optional default Ark indexer HTTP URL for stale-exit checks.
    pub ark_indexer_url: Option<String>,
    /// Nostr relays for NIP-17 package intake and reading external kind-88/89 oracle events.
    #[serde(default)]
    pub relays: Vec<String>,
    /// Minimum / fallback CPFP fee per unroll hop (sats).
    #[serde(default = "d_cpfp_fee")]
    pub cpfp_fee_sats: u64,
    /// Minimum / fallback fee to sweep the bounty output (sats).
    #[serde(default = "d_sweep_fee")]
    pub sweep_fee_sats: u64,
    /// Minimum bounty amount required to accept a package (sats).
    #[serde(default = "d_min_bounty")]
    pub min_bounty_sats: u64,
    /// Minimum expected net profit required before starting an unroll (sats).
    #[serde(default = "d_min_profit")]
    pub min_profit_sats: u64,
    /// Main loop period in seconds.
    #[serde(default = "d_tick")]
    pub tick_secs: u64,
    /// Accept watchtower exit packages over NIP-17 private messages.
    #[serde(default = "d_true")]
    pub accept_nostr_packages: bool,
}

fn d_key_file() -> PathBuf {
    "data/watchtower.key".into()
}
fn d_db_file() -> PathBuf {
    "data/watchtower.json".into()
}
fn d_network() -> String {
    "bitcoin".into()
}
fn d_cpfp_fee() -> u64 {
    600
}
fn d_sweep_fee() -> u64 {
    400
}
fn d_min_bounty() -> u64 {
    2000
}
fn d_min_profit() -> u64 {
    500
}
fn d_tick() -> u64 {
    30
}
fn d_true() -> bool {
    true
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let s = std::fs::read_to_string(path).with_context(|| format!("read {path:?}"))?;
        let cfg: Config = toml::from_str(&s).with_context(|| format!("parse {path:?}"))?;
        cfg.check()?;
        Ok(cfg)
    }

    pub fn check(&self) -> Result<()> {
        parse_network(&self.network)?;
        anyhow::ensure!(!self.esplora_url.trim().is_empty(), "esplora_url required");
        anyhow::ensure!(self.cpfp_fee_sats > 0, "cpfp_fee_sats must be > 0");
        anyhow::ensure!(self.sweep_fee_sats > 0, "sweep_fee_sats must be > 0");
        anyhow::ensure!(
            self.min_bounty_sats > self.sweep_fee_sats + 546,
            "min_bounty_sats must exceed sweep_fee_sats + dust"
        );
        anyhow::ensure!(self.tick_secs >= 1, "tick_secs must be >= 1");
        Ok(())
    }
}
