// Pure helpers for the opt-in client-side Auto-Rollover (no DOM, no wallet):
// kept separate so the decision logic can be unit-tested in Node.

export const AUTO_ROLL_FRACTION = 0.5;
export const AUTO_ROLL_RETRY_MS = 5 * 60_000;
export const AUTO_ROLL_MAX_DRIFT_PCT = 2.0;

export function autoRollTermSecs(p) {
  return Math.max(60, Number(p?.termSecs || 86_400));
}

/** Unix seconds at which the position becomes due for auto-roll (50% of the current term). */
export function autoRollDueAt(p, nowSecs = Math.floor(Date.now() / 1000)) {
  const startTs = Number(p?.lastRolledAt || p?.openedAt || nowSecs);
  return startTs + Math.floor(autoRollTermSecs(p) * AUTO_ROLL_FRACTION);
}

export function isAutoRollDue(p, nowSecs = Math.floor(Date.now() / 1000)) {
  return Boolean(p && p.status === "open" && p.autoRoll === true && nowSecs >= autoRollDueAt(p, nowSecs));
}

/** Spot for `currency` from an LP /health response (0 when absent). */
export function spotFromHealth(health, currency = "USD") {
  const cur = String(currency || "USD").toUpperCase();
  const v = Number(health?.spots?.[cur] ?? (cur === "EUR" ? health?.spotEur : cur === "USD" ? health?.spotUsd : 0));
  return Number.isFinite(v) && v > 0 ? v : 0;
}

// ── Independent price source for the ±2% guard ─────────────────────────────
// The guard compares the LP's roll quote with a "live" spot. If that spot came from the
// same LP's /health, the LP would be checked against itself. So the guard spot comes from
// sources the rolled LP does not control: other order-book LPs and public exchange feeds.
// The LP's own /health is used only when nothing else answers, and the UI says so.

export const GUARD_MAX_PEER_LPS = 3;
export const GUARD_SOURCE_TIMEOUT_MS = 5_000;

const normUrl = (u) => String(u || "").trim().replace(/\/+$/, "").toLowerCase();
const normKey = (k) => String(k || "").trim().toLowerCase();

/**
 * Other order-book LPs whose /health can serve as an independent spot: HTTP endpoint only,
 * one per pubkey, never the position's own LP (matched by pubkey or by URL).
 */
export function peerSpotTargets(offers, own = {}, max = GUARD_MAX_PEER_LPS) {
  if (!Array.isArray(offers)) return [];
  // The own LP may be known by pubkey, by URL, or both; an offer matching either one
  // also marks its other identifier as "own" (same LP under a second endpoint or key).
  const ownKeys = new Set([normKey(own.pubkey)].filter(Boolean));
  const ownUrls = new Set([normUrl(own.url)].filter(Boolean));
  for (let grew = true; grew; ) {
    grew = false;
    for (const o of offers) {
      const key = normKey(o?.pubkey);
      const url = normUrl(o?.endpointUrl);
      if ((key && ownKeys.has(key)) || (url && ownUrls.has(url))) {
        if (key && !ownKeys.has(key)) (ownKeys.add(key), (grew = true));
        if (url && !ownUrls.has(url)) (ownUrls.add(url), (grew = true));
      }
    }
  }
  const seenKeys = new Set();
  const seenUrls = new Set();
  const out = [];
  for (const o of offers) {
    if (out.length >= max) break;
    const key = normKey(o?.pubkey);
    const url = normUrl(o?.endpointUrl);
    if (!key || !url) continue;
    if (ownKeys.has(key) || ownUrls.has(url)) continue;
    if (seenKeys.has(key) || seenUrls.has(url)) continue;
    seenKeys.add(key);
    seenUrls.add(url);
    out.push({ url: o.endpointUrl, pubkey: o.pubkey, lpName: o.lpName || key.slice(0, 10) });
  }
  return out;
}

/** Public BTC spot feeds that answer browser requests (CORS checked 2026-11-28). */
export const PUBLIC_SPOT_FEEDS = [
  {
    name: "Coinbase",
    url: (cur) => `https://api.coinbase.com/v2/prices/BTC-${cur}/spot`,
    parse: (j) => Number(j?.data?.amount),
  },
  {
    name: "Kraken",
    url: (cur) => `https://api.kraken.com/0/public/Ticker?pair=XBT${cur}`,
    parse: (j, cur) => {
      const res = j?.result;
      if (!res || typeof res !== "object") return NaN;
      const entry = res[`XXBTZ${cur}`] || Object.values(res)[0];
      return Number(entry?.c?.[0]);
    },
  },
];

/** Parse a feed response into a positive spot, or 0 when unusable. */
export function parseFeedSpot(feed, json, currency = "USD") {
  try {
    const v = feed.parse(json, String(currency || "USD").toUpperCase());
    return Number.isFinite(v) && v > 0 ? v : 0;
  } catch {
    return 0;
  }
}

export function medianOf(values) {
  const xs = values.filter((v) => Number.isFinite(v) && v > 0).sort((a, b) => a - b);
  if (xs.length === 0) return 0;
  const mid = Math.floor(xs.length / 2);
  return xs.length % 2 ? xs[mid] : (xs[mid - 1] + xs[mid]) / 2;
}

/**
 * Pick the spot the guard compares the roll quote with.
 *  - `independent`: [{ name, spot }] from peer LPs and public feeds (failed ones may carry spot 0);
 *  - `selfSpot`: the position's own LP /health spot, used only when no independent source answered.
 * Returns { spot, selfOnly, sources, note } or null when there is no spot at all.
 */
export function chooseGuardSpot({ independent = [], selfSpot = 0 } = {}) {
  const ok = independent.filter((s) => Number.isFinite(s?.spot) && s.spot > 0);
  if (ok.length > 0) {
    const names = ok.map((s) => s.name);
    return {
      spot: medianOf(ok.map((s) => s.spot)),
      selfOnly: false,
      sources: names,
      note: `guard: median of ${names.join(", ")}`,
    };
  }
  if (Number.isFinite(selfSpot) && selfSpot > 0) {
    return { spot: selfSpot, selfOnly: true, sources: ["own LP"], note: "guard: LP self-quote only" };
  }
  return null;
}

/** NIP-17 relays an LP advertises in its current order-book offer (empty if none). */
export function lpRelaysFromOffers(offers, lpPubkey) {
  if (!lpPubkey || !Array.isArray(offers)) return [];
  const want = String(lpPubkey).toLowerCase();
  const o = offers.find((x) => x && typeof x.pubkey === "string" && x.pubkey.toLowerCase() === want);
  return Array.isArray(o?.nip17Relays) ? o.nip17Relays.filter((r) => typeof r === "string" && r) : [];
}

/** Turn a roll failure into a short, user-facing reason. */
export function describeAutoRollError(err) {
  const msg = String(err?.message || err || "unknown error");
  if (/deviates .*% from live spot/i.test(msg)) {
    return { kind: "spot", text: `price guard: ${msg.replace(/ — refusing to sign$/i, "")}` };
  }
  if (/mismatch|signature invalid|refusing/i.test(msg)) {
    return { kind: "verify", text: `LP proposal failed verification (${msg})` };
  }
  if (/timeout|timed out|relay|nostr|failed to fetch|networkerror|http 5\d\d|offline|ECONN/i.test(msg)) {
    return { kind: "unreachable", text: `LP unreachable (${msg})` };
  }
  return { kind: "lp", text: msg };
}

export function fmtShortDuration(secs) {
  const s = Math.max(0, Math.round(Number(secs) || 0));
  if (s < 60) return `${s}s`;
  const totalMin = Math.round(s / 60);
  if (totalMin < 60) return `${totalMin}m`;
  const h = Math.floor(totalMin / 60);
  const m = totalMin % 60;
  return m ? `${h}h ${m}m` : `${h}h`;
}

/**
 * One-line status for a position card with Auto-Roll on.
 * `status` is the last attempt record: { state: "blocked"|"rolling", text, at (ms) }.
 * `guard` is the last chooseGuardSpot() result for this position; when the guard fell back
 * to the LP's own quote, the line says so ("guard: LP self-quote only") and turns to a warning.
 */
export function autoRollStatusLine(p, status, nowMs = Date.now(), guard = null) {
  if (!p || p.status !== "open" || p.autoRoll !== true) return null;
  const selfOnly = guard?.selfOnly === true;
  const tail = selfOnly ? ` · ${guard.note}` : "";
  const infoTone = selfOnly ? "warn" : "info";
  const nowSecs = Math.floor(nowMs / 1000);
  const dueAt = autoRollDueAt(p, nowSecs);
  if (nowSecs < dueAt) {
    return {
      tone: infoTone,
      text: `↻ Auto-Roll scheduled in ${fmtShortDuration(dueAt - nowSecs)} (keep this tab open)${tail}`,
    };
  }
  if (status?.state === "rolling") return { tone: infoTone, text: `↻ Auto-Roll in progress…${tail}` };
  if (status?.state === "blocked") {
    const retryIn = Math.max(0, Math.ceil((status.at + AUTO_ROLL_RETRY_MS - nowMs) / 1000));
    return {
      tone: "warn",
      text: `⚠ Auto-Roll blocked: ${status.text}${retryIn > 0 ? ` · retry in ${fmtShortDuration(retryIn)}` : " · retrying now"}${tail}`,
    };
  }
  return { tone: infoTone, text: `↻ Auto-Roll due — will roll within a minute${tail}` };
}
