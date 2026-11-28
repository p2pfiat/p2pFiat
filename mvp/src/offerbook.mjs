/**
 * p2pFiat Nostr Offer Book Protocol v1 (Node.js ESM).
 *
 * Parameterized Replaceable Events (kind 38384, NIP-33 + NIP-40 expiration).
 * Zero extra dependencies: uses `@noble/curves`, `@noble/hashes`, `@scure/base`,
 * and Node's built-in `globalThis.WebSocket`.
 */

import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hex, bech32 } from "@scure/base";
import { schnorrSign } from "./crypto.mjs";

export const OFFER_KIND = 38384;
export const DEFAULT_RELAYS = [
  "wss://relay.primal.net",
  "wss://relay.snort.social",
  "wss://relay.noswhere.com",
  "wss://relay.satlantis.io",
  "wss://relay.nostr.net",
];

const enc = new TextEncoder();

export function pubkeyHexToNpub(pubHex) {
  return bech32.encode("npub", bech32.toWords(hex.decode(pubHex.trim())));
}

export function npubToPubkeyHex(npub) {
  const { prefix, words } = bech32.decode(npub.trim());
  if (prefix !== "npub") throw new Error("Expected npub bech32 string");
  return hex.encode(new Uint8Array(bech32.fromWords(words)));
}

/**
 * Default 2-of-3 Mutinynet Nostracle oracle quorum (override via NOSTRACLE_NPUBS env).
 * Keys are deterministically derived x-only pubkeys for local/Mutinynet testing.
 */
export const DEFAULT_NOSTRACLE_QUORUM = (() => {
  const pubkeys = [
    { name: "Nostracle-1", pubkey: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" },
    { name: "Nostracle-2", pubkey: "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5" },
    { name: "Nostracle-3", pubkey: "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9" },
  ];
  return {
    threshold: 2,
    oracles: pubkeys.map((o) => ({ ...o, npub: pubkeyHexToNpub(o.pubkey) })),
  };
})();

function randomSubId() {
  const b = new Uint8Array(4);
  crypto.getRandomValues(b);
  return `p2pfiat-${hex.encode(b)}`;
}

export function computeEventId(evt) {
  const serialized = JSON.stringify([
    0,
    evt.pubkey,
    evt.created_at,
    evt.kind,
    evt.tags,
    evt.content,
  ]);
  return hex.encode(sha256(enc.encode(serialized)));
}

/**
 * Create & BIP-340 Schnorr-sign a Nostr `kind: 38384` LP Offer event.
 */
export function createSignedOfferEvent(
  lpKey,
  offerPayload,
  { ttlSecs = 120, extraTags = [], createdAt } = {}
) {
  const now = Number.isInteger(createdAt) ? createdAt : Math.floor(Date.now() / 1000);
  const expiresAt = now + ttlSecs;
  const pair = offerPayload.pair || "BTC-USD";
  const rail = offerPayload.rail || "arkade-mutinynet";
  const dTag = offerPayload.dTag || `p2pfiat:v1:${pair}:${rail}`;

  const contentObj = {
    version: "p2pfiat-offer/v1",
    lpName: offerPayload.lpName || "p2pFiat-LP",
    lpPubkey: lpKey.pubHex,
    pair,
    currency: offerPayload.currency || (pair.includes("-") ? pair.split("-")[1] : "USD"),
    rail,
    spotPrice: Number(offerPayload.spotPrice ?? offerPayload.spotUsd),
    spotUsd: Number(offerPayload.spotUsd ?? offerPayload.spotPrice),
    bidPrice: Number(offerPayload.bidPrice ?? offerPayload.bidUsd ?? offerPayload.spotPrice ?? offerPayload.spotUsd),
    askPrice: Number(offerPayload.askPrice ?? offerPayload.askUsd ?? offerPayload.spotPrice ?? offerPayload.spotUsd),
    bidUsd: Number(offerPayload.bidUsd ?? offerPayload.bidPrice ?? offerPayload.spotUsd ?? offerPayload.spotPrice),
    askUsd: Number(offerPayload.askUsd ?? offerPayload.askPrice ?? offerPayload.spotUsd ?? offerPayload.spotPrice),
    spreadBps: Number(offerPayload.spreadBps ?? 10),
    fundingRateBpsPerDay: Number(offerPayload.fundingRateBpsPerDay ?? 10),
    minNotionalUsd: Number(offerPayload.minNotionalUsd ?? 1),
    maxNotionalUsd: Number(offerPayload.maxNotionalUsd ?? 100),
    availableLiquiditySats: Number(offerPayload.availableLiquiditySats ?? 0),
    termSecs: Number(offerPayload.termSecs ?? 86_400),
    endpointUrl: String(offerPayload.endpointUrl || ""),
    transports: Array.isArray(offerPayload.transports)
      ? offerPayload.transports
      : offerPayload.endpointUrl
      ? ["http", "nostr-nip17"]
      : ["nostr-nip17"],
    nip17Relays: Array.isArray(offerPayload.nip17Relays)
      ? offerPayload.nip17Relays.filter((r) => typeof r === "string" && (r.startsWith("wss://") || r.startsWith("ws://")))
      : [],
    oracleMode: offerPayload.oracleMode || "nostracle-quorum-2of3",
    oracleQuorum: offerPayload.oracleQuorum || DEFAULT_NOSTRACLE_QUORUM,
    proofMode: offerPayload.proofMode || "arkade-default-vtxo",
    updatedAt: now,
  };

  const tags = [
    ["d", dTag],
    ["t", "p2pfiat-offer"],
    ["pair", pair],
    ["rail", rail],
    ["side", "lp-long"],
    ["expiration", String(expiresAt)],
    ...extraTags,
  ];

  const evt = {
    pubkey: lpKey.pubHex,
    created_at: now,
    kind: OFFER_KIND,
    tags,
    content: JSON.stringify(contentObj),
  };
  evt.id = computeEventId(evt);
  evt.sig = hex.encode(schnorrSign(lpKey, hex.decode(evt.id)));
  if (!schnorr.verify(hex.decode(evt.sig), hex.decode(evt.id), hex.decode(evt.pubkey))) {
    throw new Error("Self-check failed: invalid Schnorr signature on offer event");
  }
  return evt;
}

/**
 * Cryptographically verify a `kind: 38384` LP offer event.
 * Returns normalized offer object or `null` if invalid/expired/tampered.
 */
export function verifyOfferEvent(event, nowSecs = Math.floor(Date.now() / 1000)) {
  try {
    if (!event || typeof event !== "object") return null;
    if (event.kind !== OFFER_KIND) return null;
    if (typeof event.pubkey !== "string" || !/^[0-9a-f]{64}$/.test(event.pubkey)) return null;
    if (typeof event.id !== "string" || !/^[0-9a-f]{64}$/.test(event.id)) return null;
    if (typeof event.sig !== "string" || !/^[0-9a-f]{128}$/.test(event.sig)) return null;
    if (!Number.isInteger(event.created_at) || !Array.isArray(event.tags) || typeof event.content !== "string") {
      return null;
    }

    if (computeEventId(event) !== event.id) return null;
    const okSig = schnorr.verify(
      hex.decode(event.sig),
      hex.decode(event.id),
      hex.decode(event.pubkey)
    );
    if (!okSig) return null;

    const expTag = event.tags.find((t) => Array.isArray(t) && t[0] === "expiration");
    const expiresAt = Number(expTag?.[1]);
    if (!Number.isFinite(expiresAt) || expiresAt <= nowSecs) return null;

    const content = JSON.parse(event.content);
    if (!content || typeof content !== "object") return null;
    if (content.lpPubkey !== event.pubkey) return null;
    const spotVal = Number(content.spotPrice ?? content.spotUsd);
    if (!Number.isFinite(spotVal) || spotVal <= 0) return null;
    if (!Number.isFinite(content.availableLiquiditySats) || content.availableLiquiditySats < 0) return null;
    if (!Number.isFinite(content.spreadBps) || content.spreadBps < 0) return null;
    if (!Number.isFinite(content.fundingRateBpsPerDay)) return null;

    const pair = content.pair || "BTC-USD";
    const currency = content.currency || (pair.includes("-") ? pair.split("-")[1] : "USD");
    const bidVal = Number(content.bidPrice ?? content.bidUsd ?? spotVal);
    const askVal = Number(content.askPrice ?? content.askUsd ?? spotVal);

    return {
      ...content,
      pair,
      currency,
      spotPrice: spotVal,
      spotUsd: spotVal,
      bidPrice: bidVal,
      askPrice: askVal,
      bidUsd: bidVal,
      askUsd: askVal,
      eventId: event.id,
      pubkey: event.pubkey,
      createdAt: event.created_at,
      expiresAt,
      rawEvent: event,
    };
  } catch {
    return null;
  }
}

/**
 * Publish a signed Nostr event to relays via WebSocket and wait for OK/timeout.
 */
export async function publishOfferToRelays(
  event,
  relays = DEFAULT_RELAYS,
  timeoutMs = 9000
) {
  if (!relays || relays.length === 0) return { okRelays: [], failedRelays: [] };

  const results = await Promise.all(
    relays.map(
      (relayUrl) =>
        new Promise((resolve) => {
          let settled = false;
          let ws;
          const done = (ok, reason = "") => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            try {
              ws?.close();
            } catch {}
            resolve({ relayUrl, ok, reason });
          };
          const timer = setTimeout(() => done(false, "timeout"), timeoutMs);
          try {
            ws = new WebSocket(relayUrl);
            ws.onopen = () => {
              ws.send(JSON.stringify(["EVENT", event]));
            };
            ws.onmessage = (msg) => {
              try {
                const frame = JSON.parse(String(msg.data));
                if (Array.isArray(frame) && frame[0] === "OK" && frame[1] === event.id) {
                  done(Boolean(frame[2]), String(frame[3] || ""));
                }
              } catch {}
            };
            ws.onerror = () => done(false, "ws error");
          } catch (e) {
            done(false, e?.message || "connect failed");
          }
        })
    )
  );

  return {
    okRelays: results.filter((r) => r.ok).map((r) => r.relayUrl),
    failedRelays: results.filter((r) => !r.ok),
  };
}

function weightedMedian(items) {
  const sorted = [...items].sort((a, b) => a.value - b.value);
  const totalWeight = sorted.reduce((s, it) => s + it.weight, 0);
  if (totalWeight <= 0) return null;
  const half = totalWeight / 2;
  let acc = 0;
  for (let i = 0; i < sorted.length; i++) {
    acc += sorted[i].weight;
    if (acc > half) return sorted[i].value;
    if (acc === half && i + 1 < sorted.length) {
      return (sorted[i].value + sorted[i + 1].value) / 2;
    }
  }
  return sorted[sorted.length - 1].value;
}

/**
 * In-memory local orderbook maintained by each wallet/client from verified Nostr events,
 * with Arkade VTXO Proof-of-Funds verification and Sybil-resistant price oracle output.
 */
export class LocalOrderBook {
  constructor() {
    this.offers = new Map();
    this.verifications = new Map();
  }

  ingest(event, nowSecs = Math.floor(Date.now() / 1000)) {
    const offer = verifyOfferEvent(event, nowSecs);
    if (!offer) return false;
    const key = `${offer.pubkey}:${offer.pair}`;
    const prev = this.offers.get(key);
    if (prev) {
      if (offer.createdAt < prev.createdAt) return false;
      if (offer.createdAt === prev.createdAt && offer.eventId === prev.eventId) return false;
    }
    this.offers.set(key, offer);
    return true;
  }

  setVerification(pubkey, record) {
    this.verifications.set(pubkey, {
      verifiedLiquiditySats: Number(record.verifiedLiquiditySats || 0),
      maxVtxoSats: Number(record.maxVtxoSats || 0),
      vtxoCount: Number(record.vtxoCount || 0),
      verifiedAt: record.verifiedAt || Date.now(),
    });
  }

  /**
   * Cryptographically verify active LPs' real spendable Arkade VTXOs on the Arkade Indexer
   * using their deterministic `DefaultVtxo` script derived from `event.pubkey`.
   */
  async verifyOffersOnArkade({
    indexerProvider,
    serverXOnly,
    exitDelaySecs,
    DefaultVtxo,
    cacheTtlMs = 30_000,
    force = false,
  }) {
    this.pruneExpired();
    const nowMs = Date.now();
    const checkedPubs = new Set();
    const toCheck = [];
    for (const offer of this.offers.values()) {
      if (checkedPubs.has(offer.pubkey)) continue;
      checkedPubs.add(offer.pubkey);
      const existing = this.verifications.get(offer.pubkey);
      if (!force && existing && nowMs - existing.verifiedAt < cacheTtlMs) continue;
      toCheck.push(offer);
    }
    if (toCheck.length === 0) return 0;

    let updated = 0;
    await Promise.all(
      toCheck.map(async (offer) => {
        try {
          const script = new DefaultVtxo.Script({
            pubKey: hex.decode(offer.pubkey),
            serverPubKey: serverXOnly,
            csvTimelock: { type: "seconds", value: exitDelaySecs },
          });
          const res = await indexerProvider.getVtxos({
            scripts: [hex.encode(script.pkScript)],
            spendableOnly: true,
          });
          const vtxos = res?.vtxos || [];
          let total = 0;
          let maxVtxo = 0;
          for (const v of vtxos) {
            const val = Number(v.value || 0);
            total += val;
            if (val > maxVtxo) maxVtxo = val;
          }
          this.setVerification(offer.pubkey, {
            verifiedLiquiditySats: total,
            maxVtxoSats: maxVtxo,
            vtxoCount: vtxos.length,
            verifiedAt: Date.now(),
          });
          updated++;
        } catch {
          // Keep previous verification state on transient indexer errors
        }
      })
    );
    return updated;
  }

  pruneExpired(nowSecs = Math.floor(Date.now() / 1000)) {
    for (const [pk, offer] of this.offers.entries()) {
      if (offer.expiresAt <= nowSecs) this.offers.delete(pk);
    }
  }

  getOffers({
    pair = null,
    minSats = 0,
    notionalUsd = 0,
    notionalFiat = 0,
    verifiedOnly = false,
    nowSecs = Math.floor(Date.now() / 1000),
  } = {}) {
    this.pruneExpired(nowSecs);
    const notional = notionalFiat || notionalUsd;
    const list = [];
    for (const rawOffer of this.offers.values()) {
      if (pair && rawOffer.pair !== pair) continue;
      const ver = this.verifications.get(rawOffer.pubkey) || null;
      const pofVerified = ver !== null;
      const verifiedLiquiditySats = ver ? ver.verifiedLiquiditySats : null;
      const maxVtxoSats = ver ? ver.maxVtxoSats : null;
      const vtxoCount = ver ? ver.vtxoCount : null;
      const effectiveLiquiditySats = pofVerified
        ? verifiedLiquiditySats
        : rawOffer.availableLiquiditySats;

      if (verifiedOnly && (!pofVerified || verifiedLiquiditySats <= 0)) continue;
      if (effectiveLiquiditySats < minSats) continue;
      if (notional > 0) {
        if (Number.isFinite(rawOffer.minNotionalUsd) && notional < rawOffer.minNotionalUsd) continue;
        if (Number.isFinite(rawOffer.maxNotionalUsd) && notional > rawOffer.maxNotionalUsd) continue;
      }

      const spotRef = rawOffer.spotPrice || rawOffer.spotUsd;
      const requiredSats =
        notional > 0 && spotRef > 0
          ? Math.max(1_000, Math.round((notional / spotRef) * 1e8))
          : minSats;
      const canFill = pofVerified
        ? verifiedLiquiditySats > 0 && maxVtxoSats >= requiredSats
        : rawOffer.availableLiquiditySats >= requiredSats;

      list.push({
        ...rawOffer,
        pofVerified,
        verifiedLiquiditySats,
        maxVtxoSats,
        vtxoCount,
        effectiveLiquiditySats,
        canFill,
      });
    }

    list.sort((a, b) => {
      if (a.canFill !== b.canFill) return a.canFill ? -1 : 1;
      if (a.pofVerified !== b.pofVerified) return a.pofVerified ? -1 : 1;
      // Lower spread and higher positive user yield (fundingRateBpsPerDay > 0) rank better.
      const netCostA = a.spreadBps - a.fundingRateBpsPerDay;
      const netCostB = b.spreadBps - b.fundingRateBpsPerDay;
      if (netCostA !== netCostB) return netCostA - netCostB;
      const liqDiff = b.effectiveLiquiditySats - a.effectiveLiquiditySats;
      if (liqDiff !== 0) return liqDiff;
      return b.createdAt - a.createdAt;
    });
    return list;
  }

  getBestOffer(notionalUsd = 0, minSats = 0, pair = null) {
    return this.getOffers({ pair, notionalUsd, minSats })[0] || null;
  }

  /**
   * Aggregated median mid-price across active LP offers (optionally filtered by `pair`).
   * When Arkade Proof-of-Funds is verified, computes a Sybil-resistant
   * liquidity-weighted median over funded VTXO LPs only (0-sat Sybil LPs get weight 0).
   */
  getOrderbookPrice({ pair = null, nowSecs = Math.floor(Date.now() / 1000), verifiedOnly = false } = {}) {
    // Backwards compatibility if caller passes a number directly: getOrderbookPrice(baseTime)
    const ts = typeof arguments[0] === "number" ? arguments[0] : nowSecs;
    const offers = this.getOffers({ pair, nowSecs: ts });
    if (offers.length === 0) {
      return {
        medianMidUsd: null,
        lpCount: 0,
        verifiedLpCount: 0,
        totalVerifiedSats: 0,
        spreadMinBps: null,
        isSybilResistant: false,
      };
    }

    const midOf = (o) =>
      Number.isFinite(o.bidUsd) && Number.isFinite(o.askUsd)
        ? (o.bidUsd + o.askUsd) / 2
        : o.spotUsd;

    const verifiedFunded = offers.filter((o) => o.pofVerified && o.verifiedLiquiditySats > 0);
    if (verifiedFunded.length > 0) {
      const totalVerifiedSats = verifiedFunded.reduce((s, o) => s + o.verifiedLiquiditySats, 0);
      const wm = weightedMedian(
        verifiedFunded.map((o) => ({ value: midOf(o), weight: o.verifiedLiquiditySats }))
      );
      return {
        medianMidUsd: Math.round(wm),
        lpCount: offers.length,
        verifiedLpCount: verifiedFunded.length,
        totalVerifiedSats,
        spreadMinBps: Math.min(...verifiedFunded.map((o) => o.spreadBps)),
        isSybilResistant: true,
      };
    }

    if (verifiedOnly) {
      return {
        medianMidUsd: null,
        lpCount: offers.length,
        verifiedLpCount: 0,
        totalVerifiedSats: 0,
        spreadMinBps: null,
        isSybilResistant: false,
      };
    }

    const mids = offers.map(midOf).sort((a, b) => a - b);
    const midIdx = Math.floor(mids.length / 2);
    const median =
      mids.length % 2 === 1 ? mids[midIdx] : (mids[midIdx - 1] + mids[midIdx]) / 2;
    return {
      medianMidUsd: Math.round(median),
      lpCount: offers.length,
      verifiedLpCount: 0,
      totalVerifiedSats: 0,
      spreadMinBps: Math.min(...offers.map((o) => o.spreadBps)),
      isSybilResistant: false,
    };
  }

  subscribeRelays(
    relays = DEFAULT_RELAYS,
    { tag = "p2pfiat-offer", onUpdate, onStatus } = {}
  ) {
    const subId = randomSubId();
    const statuses = new Map();
    const sockets = [];
    const emitStatus = () => onStatus?.(Object.fromEntries(statuses));

    for (const relayUrl of relays) {
      statuses.set(relayUrl, "connecting");
      try {
        const ws = new WebSocket(relayUrl);
        sockets.push(ws);
        ws.onopen = () => {
          statuses.set(relayUrl, "connected");
          emitStatus();
          ws.send(JSON.stringify(["REQ", subId, { kinds: [OFFER_KIND], "#t": [tag], limit: 50 }]));
        };
        ws.onmessage = (msg) => {
          try {
            const frame = JSON.parse(String(msg.data));
            if (!Array.isArray(frame)) return;
            if (frame[0] === "EVENT" && frame[2]) {
              if (this.ingest(frame[2])) {
                onUpdate?.(this.getOffers(), this.getOrderbookPrice());
              }
            } else if (frame[0] === "EOSE") {
              statuses.set(relayUrl, "live");
              emitStatus();
            }
          } catch {}
        };
        ws.onerror = () => {
          statuses.set(relayUrl, "error");
          emitStatus();
        };
        ws.onclose = () => {
          if (statuses.get(relayUrl) !== "error") statuses.set(relayUrl, "closed");
          emitStatus();
        };
      } catch {
        statuses.set(relayUrl, "error");
        emitStatus();
      }
    }
    emitStatus();

    return {
      close: () => {
        for (const ws of sockets) {
          try {
            if (ws.readyState === 1) ws.send(JSON.stringify(["CLOSE", subId]));
            ws.close();
          } catch {}
        }
      },
    };
  }
}
