/**
 * When no LP offer is live, the wallet says so (and when an LP was last seen) instead of
 * "Scanning Nostr relays…" forever (`web/src/offerbook.js`).
 */
import assert from "node:assert/strict";
import { randomEvenKey } from "../src/crypto.mjs";
import { createSignedOfferEvent } from "../src/offerbook.mjs";
import { LocalOrderBook, noLiveOfferText } from "../web/src/offerbook.js";

const now = Math.floor(Date.now() / 1000);
const lp = randomEvenKey();
const offer = (lpName) => ({
  lpName,
  lpPubkey: lp.pubHex,
  pair: "BTC-USD",
  currency: "USD",
  spotPrice: 95_000,
  spreadBps: 1,
  fundingRateBpsPerDay: 3,
  availableLiquiditySats: 400_000,
  termSecs: 86_400,
});

// before any relay answered
assert.equal(noLiveOfferText({ answered: false }), "Scanning Nostr relays…");
assert.equal(noLiveOfferText({ answered: true }), "No LP offers on Nostr relays");

// an offer published 21 minutes ago with the LP's 2-minute expiry: not tradeable, but seen
const book = new LocalOrderBook();
const stale = createSignedOfferEvent(lp, offer("LP-Home"), { createdAt: now - 21 * 60, ttlSecs: 120 });
assert.equal(book.ingest(stale, now), false, "expired offer is not tradeable");
assert.equal(book.getOffers().length, 0);
assert.deepEqual(book.getLastSeenLp(), { lpName: "LP-Home", createdAt: now - 21 * 60 });
assert.equal(
  noLiveOfferText({ answered: true, lastSeen: book.getLastSeenLp(), nowSecs: now }),
  "No live LP offers on Nostr relays — LP-Home last seen 21 min ago"
);
assert.match(noLiveOfferText({ answered: true, lastSeen: { lpName: "X", createdAt: now - 5 * 3600 }, nowSecs: now }), /last seen 5 h ago$/);

// a tampered expired offer does not count as "seen"
const forged = { ...stale, content: stale.content.replace("LP-Home", "LP-Evil") };
const book2 = new LocalOrderBook();
book2.ingest(forged, now);
assert.equal(book2.getLastSeenLp(), null, "signature still checked for last-seen");

// a live offer is tradeable and also updates last-seen
const live = createSignedOfferEvent(lp, offer("LP-Home"), { createdAt: now - 10 });
assert.equal(book.ingest(live, now), true);
assert.equal(book.getOffers().length, 1);
assert.equal(book.getLastSeenLp().createdAt, now - 10);

console.log("[PASS] no live LP offers: clear status with last-seen LP; signatures still checked");
