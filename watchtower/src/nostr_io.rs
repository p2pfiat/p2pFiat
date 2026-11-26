//! Nostr transport for the standalone watchtower:
//! 1. Receive `WatchtowerRequest::RegisterPackage` over NIP-17 private messages
//!    and reply with `WatchtowerReply::Registered` / `Rejected`.
//! 2. Fetch and cryptographically verify DLC oracle announcements (kind 88) and
//!    attestations (kind 89) published by *any* external oracle (single nostracle
//!    or 4-of-7 threshold oracle) on Nostr relays.

use crate::bounty::WatchtowerRole;
use crate::service::{WatchtowerReply, WatchtowerRequest, WatchtowerService};
use anyhow::{anyhow, ensure, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use kormir::bitcoin::secp256k1::Secp256k1;
use kormir::{OracleAnnouncement, OracleAttestation, Readable};
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
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

    for wrap in wraps.iter() {
        let Ok(gift) = client.unwrap_gift_wrap(wrap).await else { continue };
        let Ok(req) = serde_json::from_str::<WatchtowerRequest>(&gift.rumor.content) else {
            continue;
        };
        match req {
            WatchtowerRequest::RegisterPackage { package } => {
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
        }
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
