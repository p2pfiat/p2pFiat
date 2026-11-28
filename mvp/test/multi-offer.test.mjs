/**
 * Unit tests for multi-offer LP tiers (e.g. 24h @ 3 bps/day + 1h @ 0.27 bps/day ~1% APR)
 * and per-LP oracle deduplication in both Node and browser LocalOrderBook.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomEvenKey } from "../src/crypto.mjs";
import { parseOfferTiers } from "../src/lp.mjs";
import {
  createSignedOfferEvent,
  LocalOrderBook as NodeOrderBook,
} from "../src/offerbook.mjs";
import { LocalOrderBook as WebOrderBook } from "../web/src/offerbook.js";

test("parseOfferTiers parses LP_EXTRA_OFFERS and deduplicates by termSecs", () => {
  const tiers = parseOfferTiers("3600:0.27, 86400:99, invalid, 1800:0.5:2", {
    termSecs: 86_400,
    fundingRateBpsPerDay: 3,
    spreadBps: 1,
  });
  assert.deepEqual(tiers, [
    { termSecs: 86_400, fundingRateBpsPerDay: 3, spreadBps: 1 },
    { termSecs: 3600, fundingRateBpsPerDay: 0.27, spreadBps: 1 },
    { termSecs: 1800, fundingRateBpsPerDay: 0.5, spreadBps: 2 },
  ]);
});

test("LocalOrderBook keeps multiple term offers per LP without double-counting oracle weight", () => {
  const lpKey = randomEvenKey();
  const now = 1_800_000_000;
  const ev24h = createSignedOfferEvent(
    lpKey,
    {
      lpName: "LP-Home",
      pair: "BTC-USD",
      currency: "USD",
      dTag: "p2pfiat:v1:BTC-USD:arkade-mutinynet",
      spotPrice: 60_000,
      spreadBps: 1,
      fundingRateBpsPerDay: 3,
      availableLiquiditySats: 200_000,
      termSecs: 86_400,
    },
    { createdAt: now, ttlSecs: 300 }
  );
  const ev1h = createSignedOfferEvent(
    lpKey,
    {
      lpName: "LP-Home",
      pair: "BTC-USD",
      currency: "USD",
      dTag: "p2pfiat:v1:BTC-USD:arkade-mutinynet:3600s",
      spotPrice: 60_000,
      spreadBps: 1,
      fundingRateBpsPerDay: 0.27,
      availableLiquiditySats: 200_000,
      termSecs: 3600,
    },
    { createdAt: now, ttlSecs: 300 }
  );

  for (const Book of [NodeOrderBook, WebOrderBook]) {
    const ob = new Book();
    assert.equal(ob.ingest(ev24h, now), true);
    assert.equal(ob.ingest(ev1h, now), true);
    ob.setVerification(lpKey.pubHex, {
      verifiedLiquiditySats: 200_000,
      maxVtxoSats: 150_000,
      vtxoCount: 2,
    });

    const offers = ob.getOffers({ pair: "BTC-USD", nowSecs: now });
    assert.equal(offers.length, 2, "both 24h and 1h offers must coexist for the same LP");
    assert.notEqual(offers[0].offerKey, offers[1].offerKey);
    assert.deepEqual(
      offers.map((o) => [o.termSecs, o.fundingRateBpsPerDay]),
      [
        [86_400, 3],
        [3600, 0.27],
      ]
    );

    const price = ob.getOrderbookPrice({ pair: "BTC-USD", nowSecs: now });
    assert.equal(price.lpCount, 1, "same LP must only be counted once in oracle price");
    assert.equal(price.verifiedLpCount, 1);
    assert.equal(price.totalVerifiedSats, 200_000, "verified liquidity must not be double-counted");
  }
});
