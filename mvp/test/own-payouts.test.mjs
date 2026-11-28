/**
 * Auto-Stabilize must not lock the wallet's own payouts (`web/src/own-payouts.js`).
 * Replays the bookkeeping main.js does: noteAvailable() moves the baseline by the part of a
 * balance increase that own payouts explain; only the rest counts as received.
 */
import assert from "node:assert/strict";
import { createOwnPayoutTracker, OWN_PAYOUT_TTL_MS } from "../web/src/own-payouts.js";

function simulate() {
  const own = createOwnPayoutTracker();
  let baseline = 0;
  let lastSeen = null;
  const note = (cur, now) => {
    if (lastSeen !== null && cur > lastSeen) baseline += own.absorb(cur - lastSeen, now);
    lastSeen = cur;
  };
  return {
    own,
    start(cur) { baseline = cur; lastSeen = cur; },
    received(cur, now = 0) { note(cur, now); return cur - baseline; },
  };
}

// The reported case: Receive panel open at 231 sats, a $10 position closes and pays 16,861 sats.
{
  const w = simulate();
  w.start(231);
  w.own.add(16_861, 0);
  assert.equal(w.received(231 + 16_861), 0, "a close payout is not received");
}

// A payout and a real deposit land together: only the deposit counts.
{
  const w = simulate();
  w.start(1_000);
  w.own.add(16_861, 0);
  assert.equal(w.received(1_000 + 16_861 + 5_000), 5_000);
}

// The payout lands in two steps, then a deposit follows.
{
  const w = simulate();
  w.start(0);
  w.own.add(10_000, 0);
  assert.equal(w.received(6_000), 0);
  assert.equal(w.received(10_000), 0);
  assert.equal(w.received(13_000), 3_000, "after the payout is fully absorbed, new sats count");
}

// A payout that never shows up expires and cannot hide a later deposit.
{
  const w = simulate();
  w.start(0);
  w.own.add(20_000, 0);
  assert.equal(w.own.pendingSats(OWN_PAYOUT_TTL_MS + 1), 0);
  assert.equal(w.received(20_000, OWN_PAYOUT_TTL_MS + 1), 20_000);
}

// Spending does not consume pending payouts; zero or missing payouts are ignored.
{
  const w = simulate();
  w.start(50_000);
  w.own.add(0, 0);
  w.own.add(undefined, 0);
  w.own.add(7_000, 0);
  assert.equal(w.received(40_000), -10_000);
  assert.equal(w.own.pendingSats(1), 7_000);
}

console.log("[PASS] own payouts (close/roll) are never counted as received by Auto-Stabilize");
