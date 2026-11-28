/**
 * Pure browser-native Nostr Offer Book Protocol v1 (`kind: 38384`).
 * Subscribes to relays over WebSocket, cryptographically verifies BIP-340 Schnorr
 * signatures and NIP-40 expirations, ranks LPs locally, and computes an aggregated
 * orderbook median price as a decentralized oracle input.
 */

import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hex, bech32 } from "@scure/base";

export const OFFER_KIND = 38384;
export const DEFAULT_RELAYS = [
  "wss://relay.primal.net",
  "wss://relay.snort.social",
  "wss://relay.noswhere.com",
  "wss://relay.satlantis.io",
  "wss://relay.nostr.net",
];
// Retired default relays kept for read-fallback (wallet seed backups & profiles)
// and automatic localStorage migration.
export const LEGACY_RELAYS = [
  "wss://relay.damus.io",
  "wss://nos.lol",
  "wss://nostr.oxtr.dev",
  "wss://nostr.bitcoiner.social",
];

/** Return `relays` (or `DEFAULT_RELAYS`) unioned with retired `LEGACY_RELAYS` for read-fallback. */
export function withLegacyReadRelays(relays) {
  const base = Array.isArray(relays) && relays.length > 0 ? relays : DEFAULT_RELAYS;
  return [...new Set([...base, ...LEGACY_RELAYS])];
}

const enc = new TextEncoder();

export function pubkeyHexToNpub(pubHex) {
  return bech32.encode("npub", bech32.toWords(hex.decode(pubHex.trim())));
}

// Fallback pool when the curated NIP-51 directory (p2pfiat-nostracles) cannot be fetched:
// the three live Nostracles from that directory. Never use small-scalar test keys here
// (1·G, 2·G, … have publicly known private keys, so anyone could sign a dispute payout).
export const NOSTRACLE_POOL = [
  { name: "Nostracle-1", pubkey: "32bf77878296c74d4ec5740a572b748c0a758d875aaf4429ccd268c1339b9e2a", feeSats: 100 },
  { name: "Nostracle-2", pubkey: "4d6247e2c75922d662be9e97c55f775f42735d32d954366f4ac16d1e13e83bee", feeSats: 150 },
  { name: "Nostracle-3", pubkey: "550a7fa2d48c5a5937f4b164d3377f7646b4617df3dc812d2bf9634e3dba2f68", feeSats: 200 },
].map((o) => ({ ...o, npub: pubkeyHexToNpub(o.pubkey) }));

export const QUORUM_PRESETS = {
  "2-of-3": {
    threshold: 2,
    total: 3,
    label: "2-of-3 (Default while 3 Nostracles are live)",
    note: "Tolerates 1 offline or 1 dishonest oracle. Lowest dispute zap cost.",
  },
  "3-of-5": {
    threshold: 3,
    total: 5,
    label: "3-of-5 (Balanced)",
    note: "Tolerates 2 offline AND 2 dishonest oracles. Strong fee competition (cheapest 3 win).",
  },
  "4-of-7": {
    threshold: 4,
    total: 7,
    label: "4-of-7 (Max Security — Exp 17)",
    note: "Tolerates 3 offline AND 3 dishonest oracles. Strongest fee competition (cheapest 4 win); highest resilience for larger balances.",
  },
};

export const DEFAULT_QUORUM_PRESET = "2-of-3";

// The pool quorums are built from: the curated directory plus custom Nostracles, online
// ones first (set by the UI after each relay scan), and how many of them are live.
let activePool = NOSTRACLE_POOL;
let availableCount = NOSTRACLE_POOL.length;

export function setActiveNostraclePool(pool, liveCount = pool?.length || 0) {
  if (Array.isArray(pool) && pool.length > 0) activePool = pool;
  availableCount = Math.max(0, Number(liveCount) || 0);
}

/** A preset is selectable when enough Nostracles are live; 2-of-3 is always allowed. */
export function isQuorumPresetAvailable(presetId, liveCount = availableCount) {
  const p = QUORUM_PRESETS[presetId];
  if (!p) return false;
  return presetId === DEFAULT_QUORUM_PRESET || p.total <= liveCount;
}

export function buildQuorumForPreset(presetId = DEFAULT_QUORUM_PRESET, pool = activePool) {
  const id = isQuorumPresetAvailable(presetId) ? presetId : DEFAULT_QUORUM_PRESET;
  const p = QUORUM_PRESETS[id];
  return {
    preset: id,
    threshold: p.threshold,
    total: p.total,
    oracles: pool.slice(0, p.total),
  };
}

export const DEFAULT_NOSTRACLE_QUORUM = buildQuorumForPreset(DEFAULT_QUORUM_PRESET);

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
 * Build & sign a browser-native P2P Maker Order (`kind: 38384`) for the Nostr Order Book.
 * Setting `cancel: true` publishes a 0-liquidity replacement to clear the order from relays.
 */
export function buildP2pOrderEvent(
  nostrKey,
  {
    pair = "BTC-USD",
    currency = "USD",
    makerSide = "short",
    notional = 5,
    spotPrice = 60000,
    fundingRateBpsPerDay = 3,
    availableLiquiditySats = 0,
    arkPubkey = "",
    lpName = "P2P Peer",
    termSecs = 86_400,
    expirySecs = 900,
    oracleQuorum = DEFAULT_NOSTRACLE_QUORUM,
    cancel = false,
  }
) {
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = cancel ? now + 30 : now + Math.max(60, Number(expirySecs || 900));
  const takerSide = makerSide === "long" ? "short" : "long";
  const contentObj = {
    v: 1,
    makerType: "p2p",
    makerSide,
    takerSide,
    lpPubkey: nostrKey.pubHex,
    arkPubkey: arkPubkey || nostrKey.pubHex,
    lpName: lpName || "P2P Peer",
    network: "mutinynet",
    pair,
    currency,
    spotPrice: Number(spotPrice),
    spotUsd: Number(spotPrice),
    bidPrice: Number(spotPrice),
    askPrice: Number(spotPrice),
    bidUsd: Number(spotPrice),
    askUsd: Number(spotPrice),
    spreadBps: 0,
    fundingRateBpsPerDay: Number(fundingRateBpsPerDay),
    minNotionalUsd: Number(notional),
    maxNotionalUsd: Number(notional),
    exactNotional: Number(notional),
    termSecs: Math.max(3600, Number(termSecs || 86_400)),
    availableLiquiditySats: cancel ? 0 : Math.floor(Number(availableLiquiditySats || 0)),
    endpointUrl: "",
    transports: ["nostr-nip17"],
    oracleQuorum,
  };
  const unsigned = {
    pubkey: nostrKey.pubHex,
    created_at: now,
    kind: OFFER_KIND,
    tags: [
      ["d", `p2pfiat-offer-p2p-${pair}`],
      ["t", "p2pfiat-offer"],
      ["pair", pair],
      ["expiration", String(expiresAt)],
    ],
    content: JSON.stringify(contentObj),
  };
  const id = computeEventId(unsigned);
  const sig = hex.encode(schnorr.sign(hex.decode(id), hex.decode(nostrKey.privHex)));
  return { ...unsigned, id, sig };
}

export async function publishOfferEvent(signedEvent, relays = DEFAULT_RELAYS, timeoutMs = 4000) {
  const list = Array.isArray(relays) && relays.length > 0 ? relays : DEFAULT_RELAYS;
  const results = await Promise.all(
    list.map(
      (relayUrl) =>
        new Promise((resolve) => {
          let ws;
          let done = false;
          const finish = (ok) => {
            if (done) return;
            done = true;
            try { ws?.close(); } catch {}
            resolve({ relay: relayUrl, ok });
          };
          const timer = setTimeout(() => finish(false), timeoutMs);
          try {
            ws = new WebSocket(relayUrl);
            ws.onopen = () => ws.send(JSON.stringify(["EVENT", signedEvent]));
            ws.onmessage = (msg) => {
              try {
                const frame = JSON.parse(String(msg.data));
                if (frame[0] === "OK" && frame[1] === signedEvent.id) {
                  clearTimeout(timer);
                  finish(Boolean(frame[2]));
                }
              } catch {}
            };
            ws.onerror = () => { clearTimeout(timer); finish(false); };
            ws.onclose = () => { clearTimeout(timer); finish(false); };
          } catch {
            clearTimeout(timer);
            finish(false);
          }
        })
    )
  );
  return {
    accepted: results.filter((r) => r.ok).length,
    total: results.length,
  };
}

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
    const dTag = event.tags.find((t) => Array.isArray(t) && t[0] === "d")?.[1] || "";
    const offerKey = `${event.pubkey}:${dTag || pair}`;

    return {
      ...content,
      pair,
      currency,
      dTag,
      offerKey,
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
 * Status text while no LP can be selected. "Scanning" only until a relay has answered; after
 * that, say plainly that there is no live offer and when the most recent LP was last seen.
 */
export function noLiveOfferText({ answered = false, lastSeen = null, nowSecs = Math.floor(Date.now() / 1000) } = {}) {
  if (!answered) return "Scanning Nostr relays…";
  if (!lastSeen) return "No LP offers on Nostr relays";
  const mins = Math.max(0, Math.round((nowSecs - Number(lastSeen.createdAt)) / 60));
  const ago = mins < 1 ? "just now" : mins < 120 ? `${mins} min ago` : `${Math.round(mins / 60)} h ago`;
  return `No live LP offers on Nostr relays — ${lastSeen.lpName || "last LP"} last seen ${ago}`;
}

export class LocalOrderBook {
  constructor() {
    this.offers = new Map();
    this.verifications = new Map();
    // Every validly signed offer seen, expired or not: { lpName, createdAt } per LP pubkey.
    this.lastSeen = new Map();
    // True once at least one relay finished sending its stored offers (EOSE).
    this.relaysAnswered = false;
  }

  /** The most recently seen LP (from any signed offer, even an expired one), or null. */
  getLastSeenLp() {
    let best = null;
    for (const v of this.lastSeen.values()) if (!best || v.createdAt > best.createdAt) best = v;
    return best;
  }

  _noteSeen(offer) {
    if (!offer?.pubkey) return;
    const prev = this.lastSeen.get(offer.pubkey);
    if (!prev || offer.createdAt > prev.createdAt) {
      this.lastSeen.set(offer.pubkey, { lpName: offer.lpName || offer.pubkey.slice(0, 8), createdAt: offer.createdAt });
    }
  }

  ingest(event, nowSecs = Math.floor(Date.now() / 1000)) {
    const offer = verifyOfferEvent(event, nowSecs);
    if (!offer) {
      // Expired offers are not tradeable, but still tell when that LP was last online.
      const stale = verifyOfferEvent(event, 0);
      if (stale && stale.makerType !== "p2p") this._noteSeen(stale);
      return false;
    }
    if (offer.makerType !== "p2p") this._noteSeen(offer);
    const key = offer.offerKey || `${offer.pubkey}:${offer.dTag || offer.pair}`;
    const prev = this.offers.get(key);
    if (prev) {
      if (offer.createdAt < prev.createdAt) return false;
      if (offer.createdAt === prev.createdAt && offer.eventId === prev.eventId) return false;
    }
    if (offer.makerType === "p2p" && Number(offer.availableLiquiditySats || 0) <= 0) {
      this.offers.delete(key);
      return true;
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
          const arkPub = offer.arkPubkey && /^[0-9a-f]{64}$/i.test(offer.arkPubkey)
            ? offer.arkPubkey
            : offer.pubkey;
          const script = new DefaultVtxo.Script({
            pubKey: hex.decode(arkPub),
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
        } catch {}
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

  getOrderbookPrice({
    pair = null,
    nowSecs = Math.floor(Date.now() / 1000),
    verifiedOnly = false,
    maxOfferDeviation = 0.02,
  } = {}) {
    const ts = typeof arguments[0] === "number" ? arguments[0] : nowSecs;
    // Deduplicate by LP pubkey so an LP publishing multiple term tiers never double-counts
    // its verified liquidity or oracle weight.
    const seenPubs = new Set();
    const offers = [];
    for (const o of this.getOffers({ pair, nowSecs: ts })) {
      if (seenPubs.has(o.pubkey)) continue;
      seenPubs.add(o.pubkey);
      offers.push(o);
    }
    if (offers.length === 0) {
      return {
        medianMidUsd: null,
        shortMedianUsd: null,
        longMedianUsd: null,
        lpCount: 0,
        verifiedLpCount: 0,
        totalVerifiedSats: 0,
        spreadMinBps: null,
        isSybilResistant: false,
      };
    }

    // Outlier-resistant liquidity-weighted median per side (drops offers > maxOfferDeviation from raw median)
    const robustWeightedMedian = (items) => {
      if (!items.length) return null;
      const rawMed = weightedMedian(items);
      if (!Number.isFinite(rawMed) || rawMed <= 0) return null;
      const inliers = items.filter(
        (it) => Math.abs(it.value - rawMed) / rawMed <= maxOfferDeviation
      );
      return weightedMedian(inliers.length > 0 ? inliers : items);
    };

    // Split offers into Short (Stable) and Long (2x) books so APR/spread bias cancels out
    const computeBalancedMid = (pool, weightFn) => {
      const shortItems = [];
      const longItems = [];
      for (const o of pool) {
        const w = weightFn(o);
        if (!Number.isFinite(w) || w <= 0) continue;
        const spot = o.spotPrice ?? o.spotUsd;
        const bid = Number.isFinite(o.bidPrice ?? o.bidUsd) ? (o.bidPrice ?? o.bidUsd) : spot;
        const ask = Number.isFinite(o.askPrice ?? o.askUsd) ? (o.askPrice ?? o.askUsd) : spot;
        if (o.makerType === "p2p") {
          if (o.makerSide === "short") shortItems.push({ value: spot, weight: w });
          else longItems.push({ value: spot, weight: w });
        } else {
          // Two-sided LP quotes both short (bid) and long (ask)
          shortItems.push({ value: bid, weight: w });
          longItems.push({ value: ask, weight: w });
        }
      }
      const shortMed = robustWeightedMedian(shortItems);
      const longMed = robustWeightedMedian(longItems);
      const mid =
        shortMed !== null && longMed !== null
          ? (shortMed + longMed) / 2
          : shortMed ?? longMed;
      return { mid, shortMed, longMed };
    };

    const verifiedFunded = offers.filter((o) => o.pofVerified && o.verifiedLiquiditySats > 0);
    if (verifiedFunded.length > 0) {
      const totalVerifiedSats = verifiedFunded.reduce((s, o) => s + o.verifiedLiquiditySats, 0);
      const { mid, shortMed, longMed } = computeBalancedMid(
        verifiedFunded,
        (o) => o.verifiedLiquiditySats
      );
      return {
        medianMidUsd: mid !== null ? Math.round(mid) : null,
        shortMedianUsd: shortMed !== null ? Math.round(shortMed) : null,
        longMedianUsd: longMed !== null ? Math.round(longMed) : null,
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
        shortMedianUsd: null,
        longMedianUsd: null,
        lpCount: offers.length,
        verifiedLpCount: 0,
        totalVerifiedSats: 0,
        spreadMinBps: null,
        isSybilResistant: false,
      };
    }

    const { mid, shortMed, longMed } = computeBalancedMid(offers, () => 1);
    return {
      medianMidUsd: mid !== null ? Math.round(mid) : null,
      shortMedianUsd: shortMed !== null ? Math.round(shortMed) : null,
      longMedianUsd: longMed !== null ? Math.round(longMed) : null,
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
    const sockets = new Map();
    const reconnectTimers = new Map();
    let closed = false;
    const emitStatus = () => onStatus?.(Object.fromEntries(statuses));

    const connectRelay = (relayUrl) => {
      if (closed) return;
      const existing = sockets.get(relayUrl);
      if (existing && (existing.readyState === 0 || existing.readyState === 1)) return;
      statuses.set(relayUrl, "connecting");
      emitStatus();
      try {
        const ws = new WebSocket(relayUrl);
        sockets.set(relayUrl, ws);
        ws.onopen = () => {
          if (closed) {
            try { ws.close(); } catch {}
            return;
          }
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
              if (!this.relaysAnswered) {
                this.relaysAnswered = true;
                onUpdate?.(this.getOffers(), this.getOrderbookPrice());
              }
            }
          } catch {}
        };
        ws.onerror = () => {
          statuses.set(relayUrl, "error");
          emitStatus();
        };
        ws.onclose = () => {
          if (sockets.get(relayUrl) === ws) sockets.delete(relayUrl);
          if (statuses.get(relayUrl) !== "error") statuses.set(relayUrl, "closed");
          emitStatus();
          if (!closed && !reconnectTimers.has(relayUrl)) {
            const t = setTimeout(() => {
              reconnectTimers.delete(relayUrl);
              connectRelay(relayUrl);
            }, 5000);
            reconnectTimers.set(relayUrl, t);
          }
        };
      } catch {
        statuses.set(relayUrl, "error");
        emitStatus();
      }
    };

    for (const relayUrl of relays) connectRelay(relayUrl);

    const healthTimer = setInterval(() => {
      if (closed) return;
      for (const relayUrl of relays) {
        const ws = sockets.get(relayUrl);
        if (!ws || ws.readyState === 2 || ws.readyState === 3) connectRelay(relayUrl);
      }
    }, 25_000);

    const onVisibility = () => {
      if (!closed && document.visibilityState === "visible") {
        for (const relayUrl of relays) connectRelay(relayUrl);
      }
    };
    if (typeof document !== "undefined") {
      document.addEventListener("visibilitychange", onVisibility);
    }

    return {
      close: () => {
        closed = true;
        clearInterval(healthTimer);
        if (typeof document !== "undefined") {
          document.removeEventListener("visibilitychange", onVisibility);
        }
        for (const t of reconnectTimers.values()) clearTimeout(t);
        reconnectTimers.clear();
        for (const ws of sockets.values()) {
          try {
            if (ws.readyState === 1) ws.send(JSON.stringify(["CLOSE", subId]));
            ws.close();
          } catch {}
        }
        sockets.clear();
      },
    };
  }
}
