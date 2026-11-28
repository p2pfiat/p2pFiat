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

export const NOSTRACLE_POOL = [
  { name: "Nostracle-Demo", pubkey: "d048e2feb2d2edc0a07a3921b429676f8ea6160546b327b3f5efd7bbb395d580", feeSats: 100 },
  { name: "Nostracle-2", pubkey: "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5", feeSats: 150 },
  { name: "Nostracle-3", pubkey: "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9", feeSats: 200 },
  { name: "Nostracle-4", pubkey: "e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13", feeSats: 250 },
  { name: "Nostracle-5", pubkey: "2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4", feeSats: 300 },
  { name: "Nostracle-6", pubkey: "fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556", feeSats: 400 },
  { name: "Nostracle-7", pubkey: "5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc", feeSats: 500 },
].map((o) => ({ ...o, npub: pubkeyHexToNpub(o.pubkey) }));

export const QUORUM_PRESETS = {
  "2-of-3": {
    threshold: 2,
    total: 3,
    label: "2-of-3 (Light / Low cost)",
    note: "Tolerates 1 offline or 1 dishonest oracle. Lowest dispute zap cost.",
  },
  "3-of-5": {
    threshold: 3,
    total: 5,
    label: "3-of-5 (Balanced — Recommended)",
    note: "Tolerates 2 offline AND 2 dishonest oracles. Strong fee competition (cheapest 3 win).",
  },
  "4-of-7": {
    threshold: 4,
    total: 7,
    label: "4-of-7 (Max Security — Exp 17)",
    note: "Tolerates 3 offline AND 3 dishonest oracles. Strongest fee competition (cheapest 4 win); highest resilience for larger balances.",
  },
};

export function buildQuorumForPreset(presetId = "3-of-5") {
  const p = QUORUM_PRESETS[presetId] || QUORUM_PRESETS["3-of-5"];
  return {
    preset: presetId in QUORUM_PRESETS ? presetId : "3-of-5",
    threshold: p.threshold,
    total: p.total,
    oracles: NOSTRACLE_POOL.slice(0, p.total),
  };
}

export const DEFAULT_NOSTRACLE_QUORUM = buildQuorumForPreset("3-of-5");

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

export class LocalOrderBook {
  constructor() {
    this.offers = new Map();
    this.verifications = new Map();
  }

  ingest(event, nowSecs = Math.floor(Date.now() / 1000)) {
    const offer = verifyOfferEvent(event, nowSecs);
    if (!offer) return false;
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
