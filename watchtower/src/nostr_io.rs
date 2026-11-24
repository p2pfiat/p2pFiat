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
use std::collections::{BTreeSet, HashMap};
use std::time::Duration;

pub const KIND_ANNOUNCEMENT: u16 = 88;
pub const KIND_ATTESTATION: u16 = 89;

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

    for oracle_pk in oracles {
        let filter = Filter::new()
            .author(oracle_pk)
            .kinds([Kind::Custom(KIND_ANNOUNCEMENT), Kind::Custom(KIND_ATTESTATION)]);
        let Ok(events) = client.fetch_events(filter, Duration::from_secs(10)).await else {
            continue;
        };
        let mut anns: HashMap<EventId, OracleAnnouncement> = HashMap::new();
        let mut atts: Vec<Event> = Vec::new();
        for ev in events.into_iter() {
            if ev.kind == Kind::Custom(KIND_ANNOUNCEMENT) {
                if let Ok(ann) = verify_announcement(&ev, &oracle_pk) {
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
            if wanted_events.contains(&(oracle_pk, att.event_id.clone())) {
                out.insert(att.event_id.clone(), att);
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
