// Sats the wallet pays to itself (a close payout, yield paid out on a roll) must not look
// like "received" sats to Auto-Stabilize, which locks every balance increase while the
// Stable receive panel is open. Pure and DOM-free so it can be unit-tested in Node.

export const OWN_PAYOUT_TTL_MS = 5 * 60_000;

/**
 * Tracks expected own payouts and tells how much of a balance increase they explain.
 *  - add(sats): record a payout the wallet just triggered (it may land in the balance later);
 *  - absorb(increaseSats): the part of a balance increase that is own payouts (consumed);
 * Entries expire after `ttlMs`, so a payout that never shows up cannot hide a later deposit.
 */
export function createOwnPayoutTracker({ ttlMs = OWN_PAYOUT_TTL_MS } = {}) {
  let pending = [];
  const prune = (now) => {
    pending = pending.filter((p) => p.sats > 0 && now - p.at < ttlMs);
  };
  return {
    add(sats, now = Date.now()) {
      const n = Math.floor(Number(sats) || 0);
      if (n > 0) pending.push({ sats: n, at: now });
    },
    absorb(increaseSats, now = Date.now()) {
      prune(now);
      let left = Math.max(0, Math.floor(Number(increaseSats) || 0));
      let absorbed = 0;
      for (const p of pending) {
        const take = Math.min(p.sats, left);
        p.sats -= take;
        left -= take;
        absorbed += take;
        if (left === 0) break;
      }
      prune(now);
      return absorbed;
    },
    pendingSats(now = Date.now()) {
      prune(now);
      return pending.reduce((s, p) => s + p.sats, 0);
    },
  };
}
