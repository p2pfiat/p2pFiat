//! Bitcoin chain (Esplora) and Ark indexer HTTP clients, abstracted behind
//! async traits for deterministic testing.

use crate::wallet::WalletUtxo;
use anyhow::{anyhow, Context, Result};
use kormir::bitcoin::{OutPoint, Txid};
use serde::Deserialize;
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::time::Duration;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxStatus {
    pub confirmed: bool,
    pub block_height: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutspendStatus {
    pub spent: bool,
    pub txid: Option<String>,
}

pub trait ChainClient: Send + Sync {
    fn tip_height(&self) -> BoxFuture<'_, u32>;
    fn get_utxos(&self, address: &str) -> BoxFuture<'_, Vec<WalletUtxo>>;
    fn tx_status(&self, txid: &str) -> BoxFuture<'_, Option<TxStatus>>;
    fn outspend(&self, txid: &str, vout: u32) -> BoxFuture<'_, OutspendStatus>;
    fn fee_rate_sat_vb(&self, target_blocks: u16) -> BoxFuture<'_, Option<f64>>;
    fn broadcast_tx(&self, tx_hex: &str) -> BoxFuture<'_, String>;
    fn broadcast_package(&self, parent_hex: &str, child_hex: &str) -> BoxFuture<'_, String>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArkVtxoState {
    Unspent,
    SpentOffchain,
    OperatorUnreachable,
}

pub trait ArkIndexerClient: Send + Sync {
    fn check_vtxo(
        &self,
        indexer_url: &str,
        pk_script_hex: &str,
        outpoint: &str,
    ) -> BoxFuture<'_, ArkVtxoState>;
}

pub struct EsploraClient {
    http: reqwest::Client,
    base_url: String,
}

impl EsploraClient {
    pub fn new(http: reqwest::Client, base_url: impl Into<String>) -> Self {
        Self { http, base_url: base_url.into().trim_end_matches('/').to_string() }
    }
}

#[derive(Deserialize)]
struct EsploraUtxo {
    txid: String,
    vout: u32,
    value: u64,
    status: EsploraStatus,
}

#[derive(Deserialize)]
struct EsploraStatus {
    confirmed: bool,
    block_height: Option<u32>,
}

#[derive(Deserialize)]
struct EsploraOutspend {
    spent: bool,
    txid: Option<String>,
}

impl ChainClient for EsploraClient {
    fn tip_height(&self) -> BoxFuture<'_, u32> {
        Box::pin(async move {
            let url = format!("{}/blocks/tip/height", self.base_url);
            let text = self
                .http
                .get(&url)
                .timeout(Duration::from_secs(10))
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            text.trim().parse::<u32>().context("parse tip height")
        })
    }

    fn get_utxos(&self, address: &str) -> BoxFuture<'_, Vec<WalletUtxo>> {
        let addr = address.to_string();
        Box::pin(async move {
            let url = format!("{}/address/{addr}/utxo", self.base_url);
            let rows: Vec<EsploraUtxo> = self
                .http
                .get(&url)
                .timeout(Duration::from_secs(10))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            let mut out = Vec::with_capacity(rows.len());
            for r in rows {
                let txid = Txid::from_str(&r.txid).context("parse utxo txid")?;
                out.push(WalletUtxo {
                    outpoint: OutPoint { txid, vout: r.vout },
                    value_sats: r.value,
                    confirmed: r.status.confirmed,
                    is_v3: false,
                });
            }
            Ok(out)
        })
    }

    fn tx_status(&self, txid: &str) -> BoxFuture<'_, Option<TxStatus>> {
        let txid = txid.to_string();
        Box::pin(async move {
            let url = format!("{}/tx/{txid}/status", self.base_url);
            let resp = self
                .http
                .get(&url)
                .timeout(Duration::from_secs(10))
                .send()
                .await?;
            if resp.status() == reqwest::StatusCode::NOT_FOUND {
                return Ok(None);
            }
            let st: EsploraStatus = resp.error_for_status()?.json().await?;
            Ok(Some(TxStatus { confirmed: st.confirmed, block_height: st.block_height }))
        })
    }

    fn outspend(&self, txid: &str, vout: u32) -> BoxFuture<'_, OutspendStatus> {
        let txid = txid.to_string();
        Box::pin(async move {
            let url = format!("{}/tx/{txid}/outspend/{vout}", self.base_url);
            let resp = self
                .http
                .get(&url)
                .timeout(Duration::from_secs(10))
                .send()
                .await?;
            if resp.status() == reqwest::StatusCode::NOT_FOUND {
                return Ok(OutspendStatus { spent: false, txid: None });
            }
            let row: EsploraOutspend = resp.error_for_status()?.json().await?;
            Ok(OutspendStatus { spent: row.spent, txid: row.txid })
        })
    }

    fn fee_rate_sat_vb(&self, target_blocks: u16) -> BoxFuture<'_, Option<f64>> {
        Box::pin(async move {
            let url = format!("{}/fee-estimates", self.base_url);
            let Ok(resp) = self.http.get(&url).timeout(Duration::from_secs(10)).send().await else {
                return Ok(None);
            };
            let Ok(map) = resp.json::<std::collections::HashMap<String, f64>>().await else {
                return Ok(None);
            };
            Ok(map.get(&target_blocks.to_string()).copied().or_else(|| map.get("1").copied()))
        })
    }

    fn broadcast_tx(&self, tx_hex: &str) -> BoxFuture<'_, String> {
        let body = tx_hex.to_string();
        Box::pin(async move {
            let url = format!("{}/tx", self.base_url);
            let resp = self
                .http
                .post(&url)
                .timeout(Duration::from_secs(15))
                .body(body)
                .send()
                .await?;
            let status = resp.status();
            let text = resp.text().await?;
            if !status.is_success() {
                anyhow::bail!("broadcast_tx failed ({status}): {text}");
            }
            Ok(text.trim().to_string())
        })
    }

    fn broadcast_package(&self, parent_hex: &str, child_hex: &str) -> BoxFuture<'_, String> {
        let payload = serde_json::json!([parent_hex, child_hex]);
        Box::pin(async move {
            let url = format!("{}/txs/package", self.base_url);
            let resp = self
                .http
                .post(&url)
                .timeout(Duration::from_secs(15))
                .json(&payload)
                .send()
                .await?;
            let status = resp.status();
            let text = resp.text().await?;
            if !status.is_success() {
                anyhow::bail!("broadcast_package failed ({status}): {text}");
            }
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                if let Some(msg) = v.get("package_msg").and_then(|m| m.as_str()) {
                    if msg != "success" {
                        anyhow::bail!("package rejected: {text}");
                    }
                }
                if let Some(obj) = v.get("tx-results").and_then(|r| r.as_object()) {
                    if let Some(first_txid) = obj.keys().next() {
                        return Ok(first_txid.clone());
                    }
                }
            }
            Ok(text.trim().to_string())
        })
    }
}

pub struct HttpArkIndexer {
    http: reqwest::Client,
}

impl HttpArkIndexer {
    pub fn new(http: reqwest::Client) -> Self {
        Self { http }
    }
}

#[derive(Deserialize)]
struct ArkVtxosResp {
    #[serde(default)]
    vtxos: Vec<ArkVtxoItem>,
}

#[derive(Deserialize)]
struct ArkVtxoItem {
    outpoint: ArkOutpoint,
    #[serde(default, alias = "isSpent")]
    is_spent: bool,
}

#[derive(Deserialize)]
struct ArkOutpoint {
    txid: String,
    vout: u32,
}

impl ArkIndexerClient for HttpArkIndexer {
    fn check_vtxo(
        &self,
        indexer_url: &str,
        pk_script_hex: &str,
        outpoint: &str,
    ) -> BoxFuture<'_, ArkVtxoState> {
        let base = indexer_url.trim_end_matches('/').to_string();
        let script = pk_script_hex.to_string();
        let target = outpoint.to_string();
        Box::pin(async move {
            let url = format!("{base}/v1/indexer/vtxos?scripts={script}&spentOnly=true");
            let resp = match self.http.get(&url).timeout(Duration::from_secs(5)).send().await {
                Ok(r) if r.status().is_success() => r,
                _ => return Ok(ArkVtxoState::OperatorUnreachable),
            };
            let Ok(body) = resp.json::<ArkVtxosResp>().await else {
                return Ok(ArkVtxoState::OperatorUnreachable);
            };
            for v in body.vtxos {
                let op = format!("{}:{}", v.outpoint.txid, v.outpoint.vout);
                if op == target && v.is_spent {
                    return Ok(ArkVtxoState::SpentOffchain);
                }
            }
            Ok(ArkVtxoState::Unspent)
        })
    }
}

pub fn parse_outpoint(s: &str) -> Result<OutPoint> {
    let (txid_s, vout_s) = s
        .split_once(':')
        .ok_or_else(|| anyhow!("outpoint {s:?} must be <txid>:<vout>"))?;
    let txid = Txid::from_str(txid_s.trim()).context("invalid outpoint txid")?;
    let vout = vout_s.trim().parse::<u32>().context("invalid outpoint vout")?;
    Ok(OutPoint { txid, vout })
}
