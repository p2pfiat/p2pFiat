/**
 * Browser-native kormir `kind: 88` announcement adaptor point math (`DLC/oracle/attestation/v0`).
 */

import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hex, bech32 } from "@scure/base";

export const P2PFIAT_CURATOR_NPUB =
  "npub1p2ppegcr9j875e2d76vzn9za9s3rd6npgvde8d5cwjza8c80en3sj72l43";
export const NOSTRACLE_LIST_D_TAG = "p2pfiat-nostracles";
export const WATCHTOWER_LIST_D_TAG = "p2pfiat-watchtowers";

const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const enc = new TextEncoder();

function concatBytes(...arrays) {
  const len = arrays.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(len);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

function taggedHash(tag, ...parts) {
  const th = sha256(enc.encode(tag));
  return sha256(concatBytes(th, th, ...parts));
}

function bytesToBigInt(b) {
  return BigInt("0x" + hex.encode(b));
}

export function computeKormirOutcomePoint(oraclePubXOnly, noncesHex, binaryPrefix) {
  if (!binaryPrefix || binaryPrefix.length === 0) {
    throw new Error("binaryPrefix must be non-empty");
  }
  if (noncesHex.length < binaryPrefix.length) {
    throw new Error(`Not enough nonces (${noncesHex.length}) for prefix length ${binaryPrefix.length}`);
  }
  const P = schnorr.Point.fromBytes(Uint8Array.from([0x02, ...oraclePubXOnly]));
  let acc = null;
  for (let i = 0; i < binaryPrefix.length; i++) {
    const bitStr = binaryPrefix[i];
    const rBytes = hex.decode(noncesHex[i]);
    const Ri = schnorr.Point.fromBytes(Uint8Array.from([0x02, ...rBytes]));
    const msg = taggedHash("DLC/oracle/attestation/v0", enc.encode(bitStr));
    const e = bytesToBigInt(taggedHash("BIP0340/challenge", rBytes, oraclePubXOnly, msg)) % N;
    const Si = Ri.add(P.multiply(e));
    acc = acc ? acc.add(Si) : Si;
  }
  return acc;
}

/**
 * Scan Nostr relays for real reliability metrics per Nostracle pubkey:
 * - online status (recent kind:88/89/1 activity)
 * - age / track record (days since earliest signed event on relays)
 * - count of kind:88 announcements & kind:89 attestations
 * - live advertised `fee_sats` tag from latest kind:88 announcement
 */
export async function scanNostracleReputation(pubkeys, relays, timeoutMs = 3500) {
  const stats = new Map();
  for (const pk of pubkeys) {
    stats.set(pk, {
      pubkey: pk,
      online: false,
      earliestTs: null,
      latestTs: null,
      announcements: 0,
      attestations: 0,
      socialPosts: 0,
      advertisedFeeSats: null,
      seenIds: new Set(),
    });
  }
  if (!pubkeys.length || !relays?.length) return Object.fromEntries(stats);

  const nowSecs = Math.floor(Date.now() / 1000);
  await Promise.all(
    relays.map(
      (relayUrl) =>
        new Promise((resolve) => {
          let ws;
          let done = false;
          const finish = () => {
            if (done) return;
            done = true;
            clearTimeout(timer);
            try {
              ws?.close();
            } catch {}
            resolve();
          };
          const timer = setTimeout(finish, timeoutMs);
          try {
            ws = new WebSocket(relayUrl);
            ws.onopen = () => {
              ws.send(
                JSON.stringify([
                  "REQ",
                  "nrep",
                  { kinds: [88, 89, 1], authors: pubkeys, limit: 200 },
                ])
              );
            };
            ws.onmessage = (msg) => {
              try {
                const frame = JSON.parse(String(msg.data));
                if (frame[0] === "EVENT" && frame[2]) {
                  const ev = frame[2];
                  const st = stats.get(ev.pubkey);
                  if (!st || st.seenIds.has(ev.id)) return;
                  st.seenIds.add(ev.id);
                  const ts = Number(ev.created_at || 0);
                  if (ts > 0) {
                    if (st.earliestTs === null || ts < st.earliestTs) st.earliestTs = ts;
                    if (st.latestTs === null || ts > st.latestTs) st.latestTs = ts;
                  }
                  if (ev.kind === 88) {
                    st.announcements++;
                    const feeTag = (ev.tags || []).find((t) => Array.isArray(t) && t[0] === "fee_sats");
                    if (feeTag && feeTag[1] !== undefined) {
                      const f = Number(feeTag[1]);
                      if (Number.isFinite(f) && f >= 0) st.advertisedFeeSats = f;
                    }
                  } else if (ev.kind === 89) {
                    st.attestations++;
                  } else if (ev.kind === 1) {
                    st.socialPosts++;
                  }
                } else if (frame[0] === "EOSE") {
                  finish();
                }
              } catch {}
            };
            ws.onerror = finish;
          } catch {
            finish();
          }
        })
    )
  );

  const out = {};
  for (const [pk, st] of stats.entries()) {
    const ageSecs = st.earliestTs ? Math.max(0, nowSecs - st.earliestTs) : 0;
    const lastSeenAgeSecs = st.latestTs ? Math.max(0, nowSecs - st.latestTs) : null;
    // Consider online if active in the last 48 hours or has active kind:88 announcements
    const online = st.announcements > 0 || (lastSeenAgeSecs !== null && lastSeenAgeSecs < 48 * 3600);
    out[pk] = {
      pubkey: pk,
      online,
      ageDays: st.earliestTs ? Math.floor(ageSecs / 86_400) : null,
      lastSeenAgeSecs,
      announcements: st.announcements,
      attestations: st.attestations,
      socialPosts: st.socialPosts,
      advertisedFeeSats: st.advertisedFeeSats,
    };
  }
  return out;
}

/**
 * Placeholder for the future Nostracle Reputation & Trust Scoring mechanism.
 *
 * Security invariant: NEVER use lowest `fee_sats` to admit or rank oracles into a quorum
 * (prevents lowball / bait-and-switch Sybil attacks). Future scoring inputs:
 *   - Track-record age (days active on Nostr relays)
 *   - Attestation fulfillment rate (attested vs. missed maturities)
 *   - Historical price deviation vs. multi-oracle median
 *   - Bait-and-switch / fee-commitment violation penalties (signed `fee_sats` on kind:88)
 *   - Operator & jurisdiction independence / Web-of-Trust attestations
 */
export function scoreNostracleReputation(_rep) {
  // TODO: implement verifiable multi-factor oracle reputation scoring
  return null;
}

async function fetchCuratedNip51List(
  dTag,
  defaultPrefix,
  relays,
  curatorNpubOrHex = P2PFIAT_CURATOR_NPUB,
  timeoutMs = 3500
) {
  if (!Array.isArray(relays) || relays.length === 0) return null;
  let curatorHex = String(curatorNpubOrHex || "").trim();
  if (curatorHex.toLowerCase().startsWith("npub1")) {
    const dec = bech32.decode(curatorHex.toLowerCase());
    curatorHex = hex.encode(new Uint8Array(bech32.fromWords(dec.words)));
  }
  if (!/^[0-9a-f]{64}$/i.test(curatorHex)) return null;
  curatorHex = curatorHex.toLowerCase();

  let latest = null;
  await Promise.all(
    relays.map(
      (relayUrl) =>
        new Promise((resolve) => {
          let ws;
          let done = false;
          const finish = () => {
            if (done) return;
            done = true;
            try { ws?.close(); } catch {}
            resolve();
          };
          const timer = setTimeout(finish, timeoutMs);
          try {
            ws = new WebSocket(relayUrl);
            const subId = `dir-${Math.random().toString(16).slice(2, 8)}`;
            ws.onopen = () => {
              ws.send(
                JSON.stringify([
                  "REQ",
                  subId,
                  { kinds: [30000], authors: [curatorHex], "#d": [dTag], limit: 1 },
                ])
              );
            };
            ws.onmessage = (msg) => {
              try {
                const frame = JSON.parse(String(msg.data));
                if (frame[0] === "EVENT" && frame[2]) {
                  const ev = frame[2];
                  if (ev.kind !== 30000 || ev.pubkey !== curatorHex) return;
                  const serialized = JSON.stringify([0, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content]);
                  const expectedId = hex.encode(sha256(enc.encode(serialized)));
                  if (expectedId !== ev.id) return;
                  if (!schnorr.verify(hex.decode(ev.sig), hex.decode(ev.id), hex.decode(ev.pubkey))) return;
                  if (!latest || ev.created_at > latest.created_at) latest = ev;
                } else if (frame[0] === "EOSE") {
                  clearTimeout(timer);
                  finish();
                }
              } catch {}
            };
            ws.onerror = () => { clearTimeout(timer); finish(); };
            ws.onclose = () => { clearTimeout(timer); finish(); };
          } catch {
            clearTimeout(timer);
            finish();
          }
        })
    )
  );

  if (!latest) return null;
  const seen = new Set();
  const list = [];
  for (const t of latest.tags || []) {
    if (!Array.isArray(t) || t[0] !== "p" || !/^[0-9a-f]{64}$/i.test(t[1] || "")) continue;
    const pk = t[1].toLowerCase();
    if (seen.has(pk)) continue;
    seen.add(pk);
    list.push({
      name: (t[3] || `${defaultPrefix}-${list.length + 1}`).trim(),
      pubkey: pk,
      npub: bech32.encode("npub", bech32.toWords(hex.decode(pk))),
    });
  }
  return list.length > 0 ? list : null;
}

/**
 * Fetch and cryptographically verify the live NIP-51 `kind: 30000` (`d: "p2pfiat-nostracles"`)
 * curated Nostracle directory published by `curatorNpubOrHex`.
 */
export async function fetchCuratedNostracleList(
  relays,
  curatorNpubOrHex = P2PFIAT_CURATOR_NPUB,
  timeoutMs = 3500
) {
  return fetchCuratedNip51List(NOSTRACLE_LIST_D_TAG, "Nostracle", relays, curatorNpubOrHex, timeoutMs);
}

/**
 * Fetch and cryptographically verify the live NIP-51 `kind: 30000` (`d: "p2pfiat-watchtowers"`)
 * curated Watchtower directory (entry 0 = Primary, entries 1..n = Backups for tiered bounties).
 */
export async function fetchCuratedWatchtowerList(
  relays,
  curatorNpubOrHex = P2PFIAT_CURATOR_NPUB,
  timeoutMs = 3500
) {
  return fetchCuratedNip51List(WATCHTOWER_LIST_D_TAG, "Watchtower", relays, curatorNpubOrHex, timeoutMs);
}
