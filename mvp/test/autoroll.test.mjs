import { test } from "node:test";
import assert from "node:assert/strict";
import {
  AUTO_ROLL_RETRY_MS,
  autoRollDueAt,
  autoRollStatusLine,
  chooseGuardSpot,
  describeAutoRollError,
  isAutoRollDue,
  lpRelaysFromOffers,
  medianOf,
  parseFeedSpot,
  peerSpotTargets,
  PUBLIC_SPOT_FEEDS,
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

test("guard peers exclude the position's own LP by pubkey and by URL", () => {
  const offers = [
    { pubkey: "AA", endpointUrl: "https://lp-a.example/", lpName: "A" }, // own LP (case differs)
    { pubkey: "bb", endpointUrl: "https://lp-b.example", lpName: "B" },
    { pubkey: "bb", endpointUrl: "https://lp-b2.example", lpName: "B again" }, // same LP twice
    { pubkey: "cc", endpointUrl: "https://LP-A.example", lpName: "A under another key" }, // own URL
    { pubkey: "dd", nip17Relays: ["wss://r"], lpName: "nostr-only" }, // no /health URL
    { pubkey: "ee", endpointUrl: "https://lp-e.example", lpName: "E" },
    { pubkey: "ff", endpointUrl: "https://lp-f.example", lpName: "F" },
    { pubkey: "gg", endpointUrl: "https://lp-g.example", lpName: "G" },
  ];
  const peers = peerSpotTargets(offers, { pubkey: "aa", url: "https://lp-a.example" });
  assert.deepEqual(peers.map((t) => t.lpName), ["B", "E", "F"]); // capped at 3
  assert.ok(peers.every((t) => t.pubkey.toLowerCase() !== "aa"));
  // own LP known only by URL (no pubkey on the position): its second endpoint "B again" is excluded too
  assert.deepEqual(
    peerSpotTargets(offers, { url: "https://lp-b.example/" }, 10).map((t) => t.lpName),
    ["A", "E", "F", "G"] // "A under another key" shares lp-a's URL, so it is a duplicate of A
  );
  assert.deepEqual(peerSpotTargets(null, {}), []);
});

test("public feed responses parse to a spot, junk to 0", () => {
  const [coinbase, kraken] = PUBLIC_SPOT_FEEDS;
  assert.equal(parseFeedSpot(coinbase, { data: { amount: "95123.45" } }, "USD"), 95_123.45);
  assert.equal(parseFeedSpot(kraken, { result: { XXBTZEUR: { c: ["88000.1", "0.1"] } } }, "eur"), 88_000.1);
  assert.equal(parseFeedSpot(kraken, { result: { XBTUSD: { c: ["95000", "1"] } } }, "USD"), 95_000);
  assert.equal(parseFeedSpot(coinbase, { errors: [{ id: "not_found" }] }, "USD"), 0);
  assert.equal(parseFeedSpot(kraken, { error: ["EQuery:Unknown asset pair"], result: {} }, "USD"), 0);
  assert.equal(parseFeedSpot(kraken, null, "USD"), 0);
  assert.match(coinbase.url("EUR"), /BTC-EUR\/spot$/);
  assert.match(kraken.url("USD"), /pair=XBTUSD$/);
});

test("guard spot is the median of independent sources; self-quote only as a last resort", () => {
  assert.equal(medianOf([3, 1, 2]), 2);
  assert.equal(medianOf([4, 1, 0, NaN, 2, 3]), 2.5);
  assert.equal(medianOf([]), 0);

  // a single LP lying about the price cannot move the median of three sources
  const g = chooseGuardSpot({
    independent: [
      { name: "LP B", spot: 120_000 },
      { name: "Coinbase", spot: 95_000 },
      { name: "Kraken", spot: 95_100 },
      { name: "LP C", spot: 0 }, // answered without a spot for this currency
    ],
    selfSpot: 50_000,
  });
  assert.equal(g.spot, 95_100);
  assert.equal(g.selfOnly, false);
  assert.deepEqual(g.sources, ["LP B", "Coinbase", "Kraken"]);
  assert.doesNotMatch(g.note, /self/);

  const self = chooseGuardSpot({ independent: [{ name: "Coinbase", spot: 0 }], selfSpot: 95_000 });
  assert.deepEqual(self, { spot: 95_000, selfOnly: true, sources: ["own LP"], note: "guard: LP self-quote only" });
  assert.equal(chooseGuardSpot({ independent: [], selfSpot: 0 }), null);
  assert.equal(chooseGuardSpot(), null);
});

test("status line says when the guard fell back to the LP's self-quote", () => {
  const selfGuard = chooseGuardSpot({ selfSpot: 95_000 });
  const indep = chooseGuardSpot({ independent: [{ name: "Coinbase", spot: 95_000 }] });
  const nowBefore = (T0 + 40_000) * 1000;
  const sched = autoRollStatusLine(pos(), null, nowBefore, selfGuard);
  assert.equal(sched.tone, "warn");
  assert.match(sched.text, /scheduled in 53m .* · guard: LP self-quote only$/);
  const ok = autoRollStatusLine(pos(), null, nowBefore, indep);
  assert.equal(ok.tone, "info");
  assert.doesNotMatch(ok.text, /guard/);
  const nowDue = (T0 + 50_000) * 1000;
  const blocked = autoRollStatusLine(pos(), { state: "blocked", text: "x", at: nowDue }, nowDue, selfGuard);
  assert.match(blocked.text, /Auto-Roll blocked: x · retry in 5m · guard: LP self-quote only$/);
});
