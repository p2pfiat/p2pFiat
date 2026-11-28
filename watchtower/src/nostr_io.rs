//! Nostr transport for the standalone watchtower:
//! 1. Receive `WatchtowerRequest::RegisterPackage` over NIP-17 private messages
//!    and reply with `WatchtowerReply::Registered` / `Rejected`.
//! 2. Fetch and cryptographically verify DLC oracle announcements (kind 88) and
//!    attestations (kind 89) published by *any* external oracle (single nostracle
//!    or 4-of-7 threshold oracle) on Nostr relays.

use crate::bounty::WatchtowerRole;
use crate::dispute::{
    assemble_dispute_tx_witness, build_watchtower_dispute_tx, dispute_leaves, leaf_request,
    verified_signers, DEFAULT_DISPUTE_MINER_FEE_SATS,
};
use crate::service::{WatchtowerReply, WatchtowerRequest, WatchtowerService};
use crate::storage::WatchState;
use anyhow::{anyhow, ensure, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use kormir::bitcoin::secp256k1::Secp256k1;
use kormir::bitcoin::Transaction;
use kormir::{OracleAnnouncement, OracleAttestation, Readable};
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const KIND_ANNOUNCEMENT: u16 = 88;
pub const KIND_ATTESTATION: u16 = 89;

/// Private NIP-17 delivery schema emitted by paid `nostracle` instances
/// (wire-compatible with `nostracle::zaps::BuyerMessage`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OracleBuyerMessage {
    Paid {
        event_id: String,
        announcement_id: String,
        maturity: u32,
    },
    Attestation {
        event_id: String,
        announcement_id: String,
        attestation: String,
    },
    Error {
        payment_hash: String,
        message: String,
    },
}

/// Economic viability check for a watchtower deciding whether to pay `nostracle`
/// zap fees on a unilateral exit dispute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisputeEconomics {
    pub bounty_sats: u64,
    pub onchain_fee_sats: u64,
    pub total_oracle_zap_sats: u64,
    pub net_profit_sats: i64,
    pub profitable: bool,
}

pub fn estimate_dispute_economics(
    bounty_sats: u64,
    onchain_fee_sats: u64,
    oracle_zap_sats: u64,
    quorum_threshold: u64,
    min_profit_sats: u64,
) -> DisputeEconomics {
    let total_oracle_zap_sats = oracle_zap_sats.saturating_mul(quorum_threshold);
    let total_cost = onchain_fee_sats.saturating_add(total_oracle_zap_sats);
    let net_profit_sats = bounty_sats as i64 - total_cost as i64;
    let profitable = bounty_sats >= total_cost.saturating_add(min_profit_sats);
    DisputeEconomics {
        bounty_sats,
        onchain_fee_sats,
        total_oracle_zap_sats,
        net_profit_sats,
        profitable,
    }
}

/// Placeholder for the future Nostracle Reputation & Trust Scoring mechanism.
///
/// Security invariant: quorum membership MUST be decided by reputation, track record,
/// historical price accuracy, and operator independence — NEVER by lowest `fee_sats`
/// (which would enable lowball / bait-and-switch Sybil attacks). `select_cheapest_quorum`
/// below is only meant to order zaps *within* an already-trusted quorum.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct OracleReputation {
    pub active_days: u64,
    pub fulfillment_rate: Option<f64>,
    pub avg_median_deviation_bps: Option<f64>,
    pub fee_commitment_violations: u32,
}

/// Advertised price quote from a competing `nostracle` on its `kind: 88` announcement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OracleQuote {
    pub oracle_pk: PublicKey,
    pub announcement_id: EventId,
    pub event_id: String,
    pub fee_sats: u64,
}

/// Extract the advertised `["fee_sats", "<sats>"]` tag from a `kind: 88` announcement.
pub fn announcement_fee_sats(ev: &Event) -> u64 {
    ev.tags
        .iter()
        .map(|t| t.as_slice())
        .find(|s| s.first().map(String::as_str) == Some("fee_sats"))
        .and_then(|s| s.get(1))
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0)
}

/// Select the cheapest `threshold` distinct Nostracles from a pool of competing
/// `kind: 88` announcements within `max_total_zap_sats`.
///
/// Security invariants:
/// - Enforces `threshold >= 2` unless `allow_single_oracle` is explicitly true (prevents
///   single-oracle bribery where one cheap corrupt oracle could hijack settlement).
/// - Deduplicates by `oracle_pk` (keeps lowest fee per distinct oracle identity).
/// - Enforces `sum(fee_sats) <= max_total_zap_sats`.
pub fn select_cheapest_quorum(
    quotes: &[OracleQuote],
    threshold: usize,
    max_total_zap_sats: u64,
    allow_single_oracle: bool,
) -> Result<Vec<OracleQuote>> {
    ensure!(threshold >= 1, "quorum threshold must be >= 1");
    ensure!(
        threshold >= 2 || allow_single_oracle,
        "quorum threshold must be >= 2 to prevent single-oracle bribery"
    );

    let mut by_pk: HashMap<PublicKey, OracleQuote> = HashMap::new();
    for q in quotes {
        by_pk
            .entry(q.oracle_pk)
            .and_modify(|cur| {
                if q.fee_sats < cur.fee_sats {
                    *cur = q.clone();
                }
            })
            .or_insert_with(|| q.clone());
    }

    let mut distinct: Vec<OracleQuote> = by_pk.into_values().collect();
    ensure!(
        distinct.len() >= threshold,
        "only {} distinct oracles available, need {threshold}",
        distinct.len()
    );
    distinct.sort_by(|a, b| a.fee_sats.cmp(&b.fee_sats).then_with(|| a.oracle_pk.cmp(&b.oracle_pk)));

    let chosen: Vec<OracleQuote> = distinct.into_iter().take(threshold).collect();
    let total_cost: u64 = chosen.iter().map(|q| q.fee_sats).sum();
    ensure!(
        total_cost <= max_total_zap_sats,
        "cheapest {threshold} oracles cost {total_cost} sats, exceeding budget {max_total_zap_sats} sats"
    );
    Ok(chosen)
}

/// Build a NIP-57 `Kind::ZapRequest` to purchase a private `kind: 89` attestation
/// from a paid `nostracle` for `announcement_id`.
pub fn build_attestation_zap_request(
    buyer_keys: &Keys,
    oracle_pk: PublicKey,
    announcement_id: EventId,
    sats: u64,
    relays: &[String],
) -> Result<Event> {
    ensure!(sats > 0, "zap amount must be > 0 sats");
    let msat = sats.checked_mul(1000).ok_or_else(|| anyhow!("zap amount overflow"))?;
    let tags = vec![
        Tag::public_key(oracle_pk),
        Tag::event(announcement_id),
        Tag::custom(TagKind::custom("amount"), [msat.to_string()]),
        Tag::custom(TagKind::custom("relays"), relays.iter().cloned()),
    ];
    Ok(EventBuilder::new(Kind::ZapRequest, "").tags(tags).sign_with_keys(buyer_keys)?)
}

/// Connect a Nostr client using the watchtower's identity and configured relays.
pub async fn connect_client(keys: Keys, relays: &[String]) -> Result<Client> {
    let client = Client::new(keys);
    for r in relays {
        client.add_relay(r.as_str()).await?;
    }
    client.connect().await;
    client.wait_for_connection(Duration::from_secs(10)).await;
    Ok(client)
}

/// Scan incoming NIP-17 GiftWraps addressed to this watchtower, register valid
/// exit packages, and send NIP-17 replies back to the sender.
pub async fn process_incoming_packages(
    client: &Client,
    wt: &WatchtowerService,
    now: u64,
) -> Result<usize> {
    let own_pk = wt.wallet.nostr_keys().public_key();
    // NIP-59 randomizes gift-wrap timestamps up to 2 days into the past.
    let since = Timestamp::from(now.saturating_sub(3 * 86400));
    let filter = Filter::new()
        .kind(Kind::GiftWrap)
        .pubkey(own_pk)
        .since(since);
    let wraps = client.fetch_events(filter, Duration::from_secs(10)).await?;
    let mut registered = 0;
    let mut chunk_buf: HashMap<(PublicKey, String), (usize, BTreeMap<usize, String>)> =
        HashMap::new();

    for wrap in wraps.iter() {
        let Ok(gift) = client.unwrap_gift_wrap(wrap).await else { continue };
        let Ok(req) = serde_json::from_str::<WatchtowerRequest>(&gift.rumor.content) else {
            continue;
        };
        let maybe_pkg: Option<Box<crate::storage::WatchtowerPackage>> = match req {
            WatchtowerRequest::RequestFaucet { address } => {
                let sender_hex = gift.sender.to_hex();
                if wt.storage.get_faucet_claim(&sender_hex).is_some() {
                    continue;
                }
                let reply = match wt.send_mutinynet_faucet(&sender_hex, &address).await {
                    Ok((txid, amount_sats)) => WatchtowerReply::FaucetSent {
                        txid,
                        amount_sats,
                        address,
                    },
                    Err(e) => {
                        log::warn!("faucet request from {} rejected: {e:#}", &sender_hex[..12]);
                        WatchtowerReply::Rejected {
                            package_id: "faucet".to_string(),
                            reason: format!("{e:#}"),
                        }
                    }
                };
                let _ = client
                    .send_private_msg(gift.sender, serde_json::to_string(&reply)?, [])
                    .await;
                continue;
            }
            WatchtowerRequest::RegisterPackage { package } => Some(package),
            WatchtowerRequest::RegisterPackageChunk {
                package_id,
                chunk_index,
                total_chunks,
                data,
            } => {
                if total_chunks == 0 || total_chunks > 32 || chunk_index >= total_chunks {
                    continue;
                }
                if wt.storage.get(&package_id).is_some() {
                    continue;
                }
                let entry = chunk_buf
                    .entry((gift.sender, package_id.clone()))
                    .or_insert_with(|| (total_chunks, BTreeMap::new()));
                if entry.0 != total_chunks {
                    continue;
                }
                entry.1.insert(chunk_index, data);
                if entry.1.len() < total_chunks {
                    None
                } else {
                    let assembled: String = (0..total_chunks)
                        .filter_map(|i| entry.1.get(&i).map(String::as_str))
                        .collect();
                    chunk_buf.remove(&(gift.sender, package_id.clone()));
                    match serde_json::from_str::<crate::storage::WatchtowerPackage>(&assembled) {
                        Ok(pkg) => Some(Box::new(pkg)),
                        Err(e) => {
                            log::warn!("invalid chunked package {package_id}: {e:#}");
                            let reply = WatchtowerReply::Rejected {
                                package_id,
                                reason: format!("invalid chunked package JSON: {e}"),
                            };
                            let _ = client
                                .send_private_msg(gift.sender, serde_json::to_string(&reply)?, [])
                                .await;
                            None
                        }
                    }
                }
            }
        };

        let Some(package) = maybe_pkg else { continue };
        let pkg_id = package.id.clone();
        if wt.storage.get(&pkg_id).is_some() {
            continue;
        }
        let bounty_sats = package.bounty.amount_sats;
        let reply = match wt.register_package(*package, now) {
            Ok(role) => {
                registered += 1;
                let role_str = match role {
                    WatchtowerRole::Primary => "primary".to_string(),
                    WatchtowerRole::Backup { csv_blocks } => {
                        format!("backup(csv={csv_blocks})")
                    }
                };
                log::info!(
                    "registered package {pkg_id} via NIP-17 ({role_str}, bounty {bounty_sats} sats)"
                );
                WatchtowerReply::Registered {
                    package_id: pkg_id,
                    role: role_str,
                    bounty_sats,
                }
            }
            Err(e) => {
                log::warn!("rejected package {pkg_id}: {e:#}");
                WatchtowerReply::Rejected {
                    package_id: pkg_id,
                    reason: format!("{e:#}"),
                }
            }
        };
        let _ = client
            .send_private_msg(gift.sender, serde_json::to_string(&reply)?, [])
            .await;
    }
    Ok(registered)
}

/// Fetch and verify kind-88/89 DLC attestations from Nostr relays for all
/// external `(oracle_pubkey, oracle_event_id)` pairs referenced by active
/// watched contracts.
///
/// Returns a map keyed by `oracle_event_id`.
pub async fn fetch_external_attestations(
    client: &Client,
    wt: &WatchtowerService,
) -> Result<HashMap<String, OracleAttestation>> {
    let mut oracles: BTreeSet<PublicKey> = BTreeSet::new();
    let mut wanted_events: BTreeSet<(PublicKey, String)> = BTreeSet::new();

    for c in wt.storage.list() {
        if let (Some(pk_str), Some(ev_id)) = (&c.package.oracle_pubkey, &c.package.oracle_event_id) {
            if let Ok(pk) = PublicKey::parse(pk_str) {
                oracles.insert(pk);
                wanted_events.insert((pk, ev_id.clone()));
            }
        }
    }

    let mut out = HashMap::new();
    if oracles.is_empty() {
        return Ok(out);
    }

    let mut anns_by_oracle: HashMap<(PublicKey, EventId), OracleAnnouncement> = HashMap::new();

    for oracle_pk in &oracles {
        let filter = Filter::new()
            .author(*oracle_pk)
            .kinds([Kind::Custom(KIND_ANNOUNCEMENT), Kind::Custom(KIND_ATTESTATION)]);
        let Ok(events) = client.fetch_events(filter, Duration::from_secs(10)).await else {
            continue;
        };
        let mut anns: HashMap<EventId, OracleAnnouncement> = HashMap::new();
        let mut atts: Vec<Event> = Vec::new();
        for ev in events.into_iter() {
            if ev.kind == Kind::Custom(KIND_ANNOUNCEMENT) {
                if let Ok(ann) = verify_announcement(&ev, oracle_pk) {
                    anns_by_oracle.insert((*oracle_pk, ev.id), ann.clone());
                    anns.insert(ev.id, ann);
                }
            } else if ev.kind == Kind::Custom(KIND_ATTESTATION) {
                atts.push(ev);
            }
        }
        for att_ev in atts {
            let Some(ann_id) = att_ev.tags.event_ids().next().copied() else { continue };
            let Some(ann) = anns.get(&ann_id) else { continue };
            let Ok(att) = verify_attestation(&att_ev, ann) else { continue };
            if wanted_events.contains(&(*oracle_pk, att.event_id.clone())) {
                out.insert(att.event_id.clone(), att);
            }
        }
    }

    // Pay-on-Dispute path: also scan private NIP-17 GiftWraps addressed to this watchtower
    // for paid `nostracle` attestations (`OracleBuyerMessage::Attestation`).
    let missing_any = wanted_events.iter().any(|(_, ev_id)| !out.contains_key(ev_id));
    if missing_any {
        let own_pk = wt.wallet.nostr_keys().public_key();
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let since = Timestamp::from(now_secs.saturating_sub(3 * 86400));
        let wrap_filter = Filter::new()
            .kind(Kind::GiftWrap)
            .pubkey(own_pk)
            .since(since);
        if let Ok(wraps) = client.fetch_events(wrap_filter, Duration::from_secs(10)).await {
            for wrap in wraps.iter() {
                let Ok(gift) = client.unwrap_gift_wrap(wrap).await else { continue };
                if !oracles.contains(&gift.sender) {
                    continue;
                }
                let Ok(OracleBuyerMessage::Attestation {
                    event_id,
                    announcement_id,
                    attestation,
                }) = serde_json::from_str::<OracleBuyerMessage>(&gift.rumor.content)
                else {
                    continue;
                };
                if !wanted_events.contains(&(gift.sender, event_id.clone())) {
                    continue;
                }
                let Ok(ann_id) = EventId::from_hex(&announcement_id) else { continue };
                let Some(ann) = anns_by_oracle.get(&(gift.sender, ann_id)) else { continue };
                let Ok(att_ev) = Event::from_json(&attestation) else { continue };
                if att_ev.pubkey != gift.sender {
                    continue;
                }
                if let Ok(att) = verify_attestation(&att_ev, ann) {
                    out.insert(att.event_id.clone(), att);
                }
            }
        }
    }
    Ok(out)
}

/// Verify a kind-88 DLC oracle announcement against `expected_oracle`.
pub fn verify_announcement(ev: &Event, expected_oracle: &PublicKey) -> Result<OracleAnnouncement> {
    ensure!(ev.kind == Kind::Custom(KIND_ANNOUNCEMENT), "not kind 88");
    ev.verify().context("nostr announcement signature")?;
    let bytes = B64.decode(ev.content.trim()).context("announcement not base64")?;
    let ann = OracleAnnouncement::read(&mut std::io::Cursor::new(bytes))
        .map_err(|e| anyhow!("decode announcement: {e:?}"))?;
    ensure!(
        ann.oracle_public_key.serialize() == expected_oracle.to_bytes(),
        "announcement oracle_public_key mismatch"
    );
    ann.validate(&Secp256k1::verification_only())
        .map_err(|e| anyhow!("announcement signature invalid: {e:?}"))?;
    Ok(ann)
}

/// Verify a kind-89 DLC oracle attestation against its verified announcement.
pub fn verify_attestation(ev: &Event, ann: &OracleAnnouncement) -> Result<OracleAttestation> {
    ensure!(ev.kind == Kind::Custom(KIND_ATTESTATION), "not kind 89");
    ev.verify().context("nostr attestation signature")?;
    let bytes = B64.decode(ev.content.trim()).context("attestation not base64")?;
    let att = OracleAttestation::read(&mut std::io::Cursor::new(bytes))
        .map_err(|e| anyhow!("decode attestation: {e:?}"))?;
    ensure!(att.event_id == ann.oracle_event.event_id, "event_id mismatch");
    att.validate(&Secp256k1::verification_only(), ann)
        .map_err(|e| anyhow!("attestation signatures invalid: {e:?}"))?;
    Ok(att)
}

/// Fetch live BTC/<currency> median spot price from Coinbase, Kraken, and Bitstamp.
pub async fn fetch_live_spot_price(http: &reqwest::Client, currency: &str) -> Result<f64> {
    let cur = currency.trim().to_uppercase();
    let mut prices: Vec<f64> = Vec::new();

    // 1. Coinbase
    if let Ok(resp) = http
        .get(format!("https://api.coinbase.com/v2/prices/BTC-{cur}/spot"))
        .timeout(Duration::from_secs(5))
        .send()
        .await
    {
        if let Ok(val) = resp.json::<serde_json::Value>().await {
            if let Some(p) = val
                .pointer("/data/amount")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<f64>().ok())
            {
                if p.is_finite() && p > 0.0 {
                    prices.push(p);
                }
            }
        }
    }

    // 2. Kraken
    let kraken_pair = match cur.as_str() {
        "EUR" => "XXBTZEUR",
        _ => "XXBTZUSD",
    };
    if let Ok(resp) = http
        .get(format!("https://api.kraken.com/0/public/Ticker?pair={kraken_pair}"))
        .timeout(Duration::from_secs(5))
        .send()
        .await
    {
        if let Ok(val) = resp.json::<serde_json::Value>().await {
            if let Some(p) = val
                .pointer(&format!("/result/{kraken_pair}/c/0"))
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<f64>().ok())
            {
                if p.is_finite() && p > 0.0 {
                    prices.push(p);
                }
            }
        }
    }

    // 3. Bitstamp
    let bs_pair = format!("btc{}", cur.to_lowercase());
    if let Ok(resp) = http
        .get(format!("https://www.bitstamp.net/api/v2/ticker/{bs_pair}/"))
        .timeout(Duration::from_secs(5))
        .send()
        .await
    {
        if let Ok(val) = resp.json::<serde_json::Value>().await {
            if let Some(p) = val
                .pointer("/last")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<f64>().ok())
            {
                if p.is_finite() && p > 0.0 {
                    prices.push(p);
                }
            }
        }
    }

    ensure!(
        !prices.is_empty(),
        "failed to fetch live BTC/{cur} spot price from any exchange"
    );
    prices.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    Ok(prices[prices.len() / 2])
}

/// Request BIP-340 Schnorr signatures over NIP-17 RPC (`sign_dispute`) from `oracle_pubkeys`
/// and wait up to `timeout` for `>= need` replies. `round` keeps request ids of a second round
/// apart from the first.
pub async fn request_dispute_signatures(
    client: &Client,
    own_pk: PublicKey,
    oracle_pubkeys: &[String],
    need: usize,
    rpc_params: &serde_json::Value,
    timeout: Duration,
    round: &str,
) -> Result<HashMap<String, String>> {
    let threshold = need;
    let mut req_ids: HashMap<String, String> = HashMap::new();
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    for (idx, oracle_pk) in oracle_pubkeys.iter().enumerate() {
        let Ok(pk) = PublicKey::parse(oracle_pk) else { continue };
        let req_id = format!("wt-dispute-{round}-{now_secs}-{idx}");
        let envelope = serde_json::json!({
            "type": "p2pfiat-rpc-req",
            "reqId": req_id,
            "method": "sign_dispute",
            "params": rpc_params,
        });
        if client
            .send_private_msg(pk, envelope.to_string(), [])
            .await
            .is_ok()
        {
            req_ids.insert(req_id, oracle_pk.trim().to_lowercase());
        }
    }

    ensure!(
        req_ids.len() >= threshold,
        "only sent sign_dispute to {}/{} oracles",
        req_ids.len(),
        threshold
    );

    let deadline = tokio::time::Instant::now() + timeout;
    let mut sigs_by_pubkey: HashMap<String, String> = HashMap::new();
    // NIP-59 randomizes gift-wrap timestamps up to 48 hours into the past.
    let since = Timestamp::from(now_secs.saturating_sub(3 * 86400));

    while tokio::time::Instant::now() < deadline && sigs_by_pubkey.len() < threshold {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let filter = Filter::new()
            .kind(Kind::GiftWrap)
            .pubkey(own_pk)
            .since(since);
        let Ok(wraps) = client.fetch_events(filter, Duration::from_secs(5)).await else {
            continue;
        };
        for wrap in wraps.iter() {
            let Ok(gift) = client.unwrap_gift_wrap(wrap).await else { continue };
            let Ok(val) = serde_json::from_str::<serde_json::Value>(&gift.rumor.content) else {
                continue;
            };
            if val.get("type").and_then(|v| v.as_str()) != Some("p2pfiat-rpc-res") {
                continue;
            }
            let Some(req_id) = val.get("reqId").and_then(|v| v.as_str()) else { continue };
            let Some(expected_pk) = req_ids.get(req_id) else { continue };
            if gift.sender.to_hex().to_lowercase() != *expected_pk {
                continue;
            }
            if val.get("ok").and_then(|v| v.as_bool()) != Some(true) {
                continue;
            }
            if let Some(sig_hex) = val
                .pointer("/result/signature_hex")
                .and_then(|v| v.as_str())
            {
                sigs_by_pubkey.insert(expected_pk.clone(), sig_hex.to_string());
            }
        }
    }

    Ok(sigs_by_pubkey)
}

/// For any watched contract in `VtxoConfirmed` with a Leaf 2 `dispute` package & signed manifest,
/// fetch live spot, build the bounty-paying dispute tx, collect `k-of-n` Nostracle signatures
/// over NIP-17 RPC, and return the finalized consensus-ready transactions keyed by `package.id`.
pub async fn resolve_pending_disputes(
    client: &Client,
    http: &reqwest::Client,
    wt: &WatchtowerService,
    now: u64,
) -> Result<HashMap<String, Transaction>> {
    let own_pk = wt.wallet.nostr_keys().public_key();
    let mut resolved: HashMap<String, Transaction> = HashMap::new();
    let mut spot_cache: HashMap<String, f64> = HashMap::new();

    for c in wt.storage.list() {
        if !matches!(c.state, WatchState::VtxoConfirmed { .. }) {
            continue;
        }
        let Some(dispute) = &c.package.dispute else { continue };
        let Some(manifest) = &dispute.manifest else { continue };

        let cur = manifest.currency.trim().to_uppercase();
        let live_spot = if let Some(&p) = spot_cache.get(&cur) {
            p
        } else {
            match fetch_live_spot_price(http, &cur).await {
                Ok(p) => {
                    spot_cache.insert(cur.clone(), p);
                    p
                }
                Err(e) => {
                    log::warn!("{}: Leaf 2 dispute skipped (no {cur} spot): {e:#}", c.package.id);
                    continue;
                }
            }
        };

        let built = match build_watchtower_dispute_tx(
            dispute,
            &c.package.bounty,
            live_spot,
            now,
            DEFAULT_DISPUTE_MINER_FEE_SATS,
        ) {
            Ok(b) => b,
            Err(e) => {
                log::warn!("{}: build Leaf 2 dispute tx failed: {e:#}", c.package.id);
                continue;
            }
        };

        let threshold = dispute.oracle_quorum.threshold;
        let leaves = dispute_leaves(dispute);
        let primary = match leaf_request(&built, dispute, &leaves[0]) {
            Ok(l) => l,
            Err(e) => {
                log::warn!("{}: Leaf 2 dispute leaf invalid: {e:#}", c.package.id);
                continue;
            }
        };

        // Round 1: every quorum oracle is asked to sign the primary leaf. Each one that signs
        // locks this exact tx, so it will sign the same tx for another committed leaf.
        let all_oracles: Vec<String> = dispute
            .oracle_quorum
            .oracles
            .iter()
            .map(|o| o.pubkey.trim().to_lowercase())
            .collect();
        let round1 = match request_dispute_signatures(
            client,
            own_pk,
            &all_oracles,
            threshold,
            &primary.rpc_params,
            Duration::from_secs(20),
            "r1",
        )
        .await
        {
            Ok(s) => s,
            Err(e) => {
                log::warn!("{}: Leaf 2 sign_dispute RPC failed: {e:#}", c.package.id);
                continue;
            }
        };
        let signers = verified_signers(&primary, &round1);
        let primary_ok = if primary.legacy_checksigadd {
            primary.keys.iter().filter(|k| signers.contains_key(*k)).count() >= threshold
        } else {
            primary.keys.iter().all(|k| signers.contains_key(k))
        };

        // Round 2 (manifest v2): a primary oracle did not sign but k others did; ask those k
        // to sign the same tx for their own committed leaf.
        let (leaf, sigs) = if primary_ok {
            (primary, round1)
        } else {
            let fallback = leaves[1..].iter().find_map(|spec| {
                let req = leaf_request(&built, dispute, spec).ok()?;
                (!req.legacy_checksigadd && req.keys.iter().all(|k| signers.contains_key(k))).then_some(req)
            });
            match fallback {
                Some(fb) => {
                    log::info!(
                        "{}: primary dispute leaf incomplete; asking {} for their committed leaf",
                        c.package.id,
                        fb.keys.iter().map(|k| &k[..8]).collect::<Vec<_>>().join(", ")
                    );
                    match request_dispute_signatures(
                        client,
                        own_pk,
                        &fb.keys,
                        fb.keys.len(),
                        &fb.rpc_params,
                        Duration::from_secs(20),
                        "r2",
                    )
                    .await
                    {
                        Ok(s) => (fb, s),
                        Err(e) => {
                            log::warn!("{}: Leaf 2 round-2 sign_dispute failed: {e:#}", c.package.id);
                            continue;
                        }
                    }
                }
                None => (primary, round1),
            }
        };

        match assemble_dispute_tx_witness(&built, &leaf, threshold, &sigs) {
            Ok(final_tx) => {
                log::info!(
                    "{}: assembled autonomous Leaf 2 dispute tx ({cur} @ {live_spot:.2}, user={} sats, lp={} sats, bounty={} sats)",
                    c.package.id,
                    built.user_payout_sats,
                    built.lp_payout_sats,
                    built.bounty_sats
                );
                resolved.insert(c.package.id.clone(), final_tx);
            }
            Err(e) => {
                log::warn!("{}: Leaf 2 witness assembly failed: {e:#}", c.package.id);
            }
        }
    }

    Ok(resolved)
}
