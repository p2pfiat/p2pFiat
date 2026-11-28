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
 */
export function autoRollStatusLine(p, status, nowMs = Date.now()) {
  if (!p || p.status !== "open" || p.autoRoll !== true) return null;
  const nowSecs = Math.floor(nowMs / 1000);
  const dueAt = autoRollDueAt(p, nowSecs);
  if (nowSecs < dueAt) {
    return { tone: "info", text: `↻ Auto-Roll scheduled in ${fmtShortDuration(dueAt - nowSecs)} (keep this tab open)` };
  }
  if (status?.state === "rolling") return { tone: "info", text: "↻ Auto-Roll in progress…" };
  if (status?.state === "blocked") {
    const retryIn = Math.max(0, Math.ceil((status.at + AUTO_ROLL_RETRY_MS - nowMs) / 1000));
    return {
      tone: "warn",
      text: `⚠ Auto-Roll blocked: ${status.text}${retryIn > 0 ? ` · retry in ${fmtShortDuration(retryIn)}` : " · retrying now"}`,
    };
  }
  return { tone: "info", text: "↻ Auto-Roll due — will roll within a minute" };
}
