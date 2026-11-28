import { test } from "node:test";
import assert from "node:assert/strict";
import {
  AUTO_ROLL_RETRY_MS,
  autoRollDueAt,
  autoRollStatusLine,
  describeAutoRollError,
  isAutoRollDue,
  lpRelaysFromOffers,
  spotFromHealth,
} from "../web/src/autoroll.js";

const T0 = 1_800_000_000;
const pos = (extra = {}) => ({ positionId: "p1", status: "open", autoRoll: true, openedAt: T0, termSecs: 86_400, ...extra });

test("due exactly at 50% of the term, measured from the last roll", () => {
  assert.equal(autoRollDueAt(pos()), T0 + 43_200);
  assert.equal(isAutoRollDue(pos(), T0 + 43_199), false);
  assert.equal(isAutoRollDue(pos(), T0 + 43_200), true);
  assert.equal(isAutoRollDue(pos({ lastRolledAt: T0 + 50_000 }), T0 + 60_000), false);
  assert.equal(isAutoRollDue(pos({ autoRoll: false }), T0 + 90_000), false);
  assert.equal(isAutoRollDue(pos({ status: "closed" }), T0 + 90_000), false);
});

test("fresh spot is read per currency from LP health", () => {
  assert.equal(spotFromHealth({ spotUsd: 95_000, spotEur: 88_000 }, "USD"), 95_000);
  assert.equal(spotFromHealth({ spotUsd: 95_000, spotEur: 88_000 }, "eur"), 88_000);
  assert.equal(spotFromHealth({ spots: { USD: 1, EUR: 2 } }, "EUR"), 2);
  assert.equal(spotFromHealth({}, "USD"), 0);
  assert.equal(spotFromHealth(null, "USD"), 0);
});

test("LP NIP-17 relays come from that LP's order-book offer", () => {
  const offers = [
    { pubkey: "aa", nip17Relays: ["wss://a", "", 5] },
    { pubkey: "bb", nip17Relays: ["wss://b"] },
  ];
  assert.deepEqual(lpRelaysFromOffers(offers, "aa"), ["wss://a"]);
  assert.deepEqual(lpRelaysFromOffers(offers, "cc"), []);
  // hex pubkeys may arrive in mixed case
  assert.deepEqual(lpRelaysFromOffers(offers, "BB"), ["wss://b"]);
  assert.deepEqual(lpRelaysFromOffers([{ pubkey: "AA", nip17Relays: ["wss://x"] }], "aa"), ["wss://x"]);
  assert.deepEqual(lpRelaysFromOffers(null, "aa"), []);
});

test("roll errors map to user-facing reasons", () => {
  const drift = describeAutoRollError(
    new Error("LP roll spot 98000 deviates 3.16% from live spot 95000 — refusing to sign")
  );
  assert.equal(drift.kind, "spot");
  assert.match(drift.text, /deviates 3\.16%/);
  assert.doesNotMatch(drift.text, /refusing to sign/);
  assert.equal(describeAutoRollError(new Error("NIP-17 request timeout (roll/propose)")).kind, "unreachable");
  assert.equal(describeAutoRollError(new Error("LP roll proposal output 0 mismatch! Refusing to sign.")).kind, "verify");
  assert.equal(describeAutoRollError(new Error("position is closed")).kind, "lp");
});

test("status line: scheduled, due, blocked with retry countdown", () => {
  const nowBefore = (T0 + 40_000) * 1000;
  assert.match(autoRollStatusLine(pos(), null, nowBefore).text, /scheduled in 53m/);
  const nowDue = (T0 + 50_000) * 1000;
  assert.match(autoRollStatusLine(pos(), null, nowDue).text, /due/);
  const blocked = autoRollStatusLine(pos(), { state: "blocked", text: "LP unreachable (timeout)", at: nowDue - 60_000 }, nowDue);
  assert.equal(blocked.tone, "warn");
  assert.match(blocked.text, /Auto-Roll blocked: LP unreachable \(timeout\) · retry in 4m/);
  const stale = autoRollStatusLine(pos(), { state: "blocked", text: "x", at: nowDue - AUTO_ROLL_RETRY_MS }, nowDue);
  assert.match(stale.text, /retrying now/);
  assert.equal(autoRollStatusLine(pos({ autoRoll: false }), null, nowDue), null);
  // 11h 59m 50s rounds to 12h, never "11h 60m"
  assert.match(autoRollStatusLine(pos(), null, (T0 + 43_200 - 43_190) * 1000).text, /scheduled in 12h \(/);
});
