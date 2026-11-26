/**
 * Verification suite for p2pFiat Nostr Offer Book Protocol v1 (`kind: 38384`).
 *
 * Part A (offline):
 *   - Signs 3 competing LP offers (5, 12, 25 bps spreads; spots 96400, 96500, 96600)
 *   - Verifies tampered content, spoofed lpPubkey, and expired events are rejected
 *   - Verifies LocalOrderBook ranks lowest spread+funding #1, replaces older events
 *     from the same LP, and computes decentralized median mid-price ($96,500)
 *
 * Part B (live public Nostr relays):
 *   - Publishes 2 signed LP offers under a unique test `#t` tag to DEFAULT_RELAYS
 *   - Subscribes from a fresh LocalOrderBook, verifies both arrive from live relays,
 *     verifies signatures, confirms best LP ranking & oracle median price
 */

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {
  DefaultVtxo,
  RestArkProvider,
  RestIndexerProvider,
  toXOnly,
} from "@arkade-os/sdk";
import { hex } from "@scure/base";
import { keyFromHex, randomEvenKey, schnorrSign } from "../src/crypto.mjs";
import {
  DEFAULT_RELAYS,
  OFFER_KIND,
  LocalOrderBook,
  computeEventId,
  createSignedOfferEvent,
  verifyOfferEvent,
  publishOfferToRelays,
} from "../src/offerbook.mjs";

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function runOfflineTests() {
  console.log("=== Part A: Offline Offer Book Verification & Security ===");
  const lpA = randomEvenKey();
  const lpB = randomEvenKey();
  const lpC = randomEvenKey();
  const baseTime = Math.floor(Date.now() / 1000);

  const evtA = createSignedOfferEvent(
    lpA,
    {
      lpName: "Alpha-5bps",
      spotUsd: 96_400,
      bidUsd: 96_352,
      askUsd: 96_448,
      spreadBps: 5,
      fundingRateBpsPerDay: 4, // +4 bps/day yield to stable user -> net cost = 1 bps
      availableLiquiditySats: 50_000,
      endpointUrl: "http://127.0.0.1:4001",
    },
    { createdAt: baseTime, ttlSecs: 120 }
  );
  const evtB = createSignedOfferEvent(
    lpB,
    {
      lpName: "Beta-12bps",
      spotUsd: 96_500,
      bidUsd: 96_384,
      askUsd: 96_616,
      spreadBps: 12,
      fundingRateBpsPerDay: 2, // +2 bps/day yield -> net cost = 10 bps
      availableLiquiditySats: 80_000,
      endpointUrl: "http://127.0.0.1:4002",
    },
    { createdAt: baseTime, ttlSecs: 120 }
  );
  const evtC = createSignedOfferEvent(
    lpC,
    {
      lpName: "Gamma-25bps",
      spotUsd: 96_600,
      bidUsd: 96_359,
      askUsd: 96_842,
      spreadBps: 25,
      fundingRateBpsPerDay: -3, // negative funding (backwardation) -> net cost = 28 bps
      availableLiquiditySats: 120_000,
      endpointUrl: "http://127.0.0.1:4003",
    },
    { createdAt: baseTime, ttlSecs: 120 }
  );

  // 1. Valid offers pass
  assert.ok(verifyOfferEvent(evtA, baseTime));
  assert.ok(verifyOfferEvent(evtB, baseTime));
  assert.ok(verifyOfferEvent(evtC, baseTime));

  // 2. Tampered content / bad sig rejected
  const tampered = structuredClone(evtA);
  tampered.content = tampered.content.replace("Alpha-5bps", "Evil-Spoof");
  assert.equal(verifyOfferEvent(tampered, baseTime), null, "tampered content must fail");

  const badSig = structuredClone(evtA);
  badSig.sig = "00".repeat(64);
  assert.equal(verifyOfferEvent(badSig, baseTime), null, "zero sig must fail");

  // 3. Mismatched lpPubkey !== event.pubkey rejected even with valid signature from lpA
  const spoofPayload = {
    version: "p2pfiat-offer/v1",
    lpName: "Spoof",
    lpPubkey: lpB.pubHex,
    spotUsd: 96_500,
    spreadBps: 1,
    fundingRateBpsPerDay: 1,
    availableLiquiditySats: 10_000,
  };
  const spoofEvt = {
    pubkey: lpA.pubHex,
    created_at: baseTime,
    kind: OFFER_KIND,
    tags: [["d", "p2pfiat:v1:BTC-USD:arkade-mutinynet"], ["expiration", String(baseTime + 120)]],
    content: JSON.stringify(spoofPayload),
  };
  spoofEvt.id = computeEventId(spoofEvt);
  spoofEvt.sig = hex.encode(schnorrSign(lpA, hex.decode(spoofEvt.id)));
  assert.equal(verifyOfferEvent(spoofEvt, baseTime), null, "mismatched lpPubkey must fail");

  const expired = createSignedOfferEvent(
    lpA,
    { lpName: "Expired", spotUsd: 96_500, availableLiquiditySats: 10_000 },
    { createdAt: baseTime - 200, ttlSecs: 60 }
  );
  assert.equal(verifyOfferEvent(expired, baseTime), null, "expired offer must fail");

  // 4. LocalOrderBook ingestion, ranking & median price oracle
  const book = new LocalOrderBook();
  assert.equal(book.ingest(evtC, baseTime), true);
  assert.equal(book.ingest(evtB, baseTime), true);
  assert.equal(book.ingest(evtA, baseTime), true);
  // Older event from lpA must be ignored
  const olderA = createSignedOfferEvent(
    lpA,
    { lpName: "Alpha-Old", spotUsd: 90_000, spreadBps: 1, availableLiquiditySats: 50_000 },
    { createdAt: baseTime - 10, ttlSecs: 120 }
  );
  assert.equal(book.ingest(olderA, baseTime), false, "older created_at must be rejected");

  const ranked = book.getOffers({ notionalUsd: 5, nowSecs: baseTime });
  assert.equal(ranked.length, 3);
  assert.equal(ranked[0].lpName, "Alpha-5bps");
  assert.equal(ranked[1].lpName, "Beta-12bps");
  assert.equal(ranked[2].lpName, "Gamma-25bps");
  assert.equal(book.getBestOffer(5)?.lpName, "Alpha-5bps");

  const oracle = book.getOrderbookPrice(baseTime);
  assert.equal(oracle.lpCount, 3);
  assert.equal(oracle.spreadMinBps, 5);
  assert.equal(oracle.medianMidUsd, 96_500);
  console.log(
    `  PASS: 3 LPs ranked cleanly, tampered/expired rejected, orderbook oracle median = $${oracle.medianMidUsd}`
  );
}

async function runLiveRelayTests() {
  console.log("=== Part B: Live Public Nostr Relay Roundtrip ===");
  const testTag = `p2pfiat-test-${crypto.randomBytes(4).toString("hex")}`;
  const lpFast = randomEvenKey();
  const lpSlow = randomEvenKey();

  const evtFast = createSignedOfferEvent(
    lpFast,
    {
      lpName: "LiveTest-Tight-4bps",
      spotUsd: 97_000,
      bidUsd: 96_961,
      askUsd: 97_039,
      spreadBps: 4,
      fundingRateBpsPerDay: 6,
      availableLiquiditySats: 40_000,
      endpointUrl: "http://127.0.0.1:4501",
    },
    { ttlSecs: 180, extraTags: [["t", testTag]] }
  );
  const evtSlow = createSignedOfferEvent(
    lpSlow,
    {
      lpName: "LiveTest-Wide-20bps",
      spotUsd: 97_200,
      bidUsd: 97_006,
      askUsd: 97_394,
      spreadBps: 20,
      fundingRateBpsPerDay: 10,
      availableLiquiditySats: 60_000,
      endpointUrl: "http://127.0.0.1:4502",
    },
    { ttlSecs: 180, extraTags: [["t", testTag]] }
  );

  const [pub1, pub2] = await Promise.all([
    publishOfferToRelays(evtFast, DEFAULT_RELAYS, 5500),
    publishOfferToRelays(evtSlow, DEFAULT_RELAYS, 5500),
  ]);
  console.log(`  Published evtFast to ${pub1.okRelays.length}/${DEFAULT_RELAYS.length} relays: ${pub1.okRelays.join(", ")}`);
  console.log(`  Published evtSlow to ${pub2.okRelays.length}/${DEFAULT_RELAYS.length} relays: ${pub2.okRelays.join(", ")}`);
  assert.ok(pub1.okRelays.length >= 1, "at least 1 public relay must accept evtFast");
  assert.ok(pub2.okRelays.length >= 1, "at least 1 public relay must accept evtSlow");

  // Subscribe on a fresh LocalOrderBook to the relays that accepted both events
  const activeRelays = pub1.okRelays.filter((r) => pub2.okRelays.includes(r));
  const subRelays = activeRelays.length > 0 ? activeRelays : DEFAULT_RELAYS;

  const book = new LocalOrderBook();
  const sub = book.subscribeRelays(subRelays, { tag: testTag });
  try {
    const deadline = Date.now() + 8000;
    while (Date.now() < deadline && book.getOffers().length < 2) {
      await sleep(250);
    }
    const offers = book.getOffers();
    const oracle = book.getOrderbookPrice();
    assert.equal(offers.length, 2, `expected 2 verified offers from relays, got ${offers.length}`);
    assert.equal(book.getBestOffer()?.lpName, "LiveTest-Tight-4bps");
    assert.equal(oracle.lpCount, 2);
    assert.equal(oracle.medianMidUsd, 97_100);
    console.log(
      `  PASS: received ${offers.length} live Nostr offers from [${subRelays.join(", ")}], best=${book.getBestOffer().lpName}, oracleMedian=$${oracle.medianMidUsd}`
    );
  } finally {
    sub.close();
  }
}

async function runLiveArkadePofTests() {
  console.log("=== Part C: Live Arkade Mutinynet Proof-of-Funds & Sybil Resistance ===");
  const arkUrl = "https://mutinynet.arkade.sh";
  const arkProvider = new RestArkProvider(arkUrl);
  const indexerProvider = new RestIndexerProvider(arkUrl);
  const info = await arkProvider.getInfo();
  const serverXOnly = toXOnly(hex.decode(info.signerPubkey));
  const exitDelaySecs = BigInt(info.unilateralExitDelay);

  const alphaKey = keyFromHex(
    JSON.parse(fs.readFileSync(path.resolve(import.meta.dirname, "../data/lp-alpha/lp.json"), "utf8")).lpKeyHex
  );
  const betaKey = keyFromHex(
    JSON.parse(fs.readFileSync(path.resolve(import.meta.dirname, "../data/lp-beta/lp.json"), "utf8")).lpKeyHex
  );
  const sybilKey = randomEvenKey();

  const evtAlpha = createSignedOfferEvent(alphaKey, {
    lpName: "LP-Alpha",
    spotUsd: 96_500,
    bidUsd: 96_404,
    askUsd: 96_596,
    spreadBps: 10,
    fundingRateBpsPerDay: 10,
    availableLiquiditySats: 15_000,
    endpointUrl: "http://127.0.0.1:3456",
  });
  const evtBeta = createSignedOfferEvent(betaKey, {
    lpName: "LP-Beta",
    spotUsd: 96_500,
    bidUsd: 96_452,
    askUsd: 96_548,
    spreadBps: 5,
    fundingRateBpsPerDay: 6,
    availableLiquiditySats: 15_000,
    endpointUrl: "http://127.0.0.1:3458",
  });
  // Malicious unfunded Sybil LP claiming 0 bps spread, 999M sats, and a fake $10,000 BTC price!
  const evtSybil = createSignedOfferEvent(sybilKey, {
    lpName: "Evil-Sybil-0bps",
    spotUsd: 10_000,
    bidUsd: 10_000,
    askUsd: 10_000,
    spreadBps: 0,
    fundingRateBpsPerDay: 0,
    availableLiquiditySats: 999_999_999,
    endpointUrl: "http://evil.invalid",
  });

  const book = new LocalOrderBook();
  book.ingest(evtAlpha);
  book.ingest(evtBeta);
  book.ingest(evtSybil);

  const verifiedCount = await book.verifyOffersOnArkade({
    indexerProvider,
    serverXOnly,
    exitDelaySecs,
    DefaultVtxo,
    force: true,
  });
  assert.equal(verifiedCount, 3, "all 3 offers must be checked against live Arkade indexer");

  const offers = book.getOffers({ notionalUsd: 2 });
  const alphaOffer = offers.find((o) => o.pubkey === alphaKey.pubHex);
  const betaOffer = offers.find((o) => o.pubkey === betaKey.pubHex);
  const sybilOffer = offers.find((o) => o.pubkey === sybilKey.pubHex);

  assert.ok(alphaOffer.pofVerified && alphaOffer.verifiedLiquiditySats > 0, "LP-Alpha must verify funded on Arkade");
  assert.ok(betaOffer.pofVerified && betaOffer.verifiedLiquiditySats > 0, "LP-Beta must verify funded on Arkade");
  assert.equal(sybilOffer.pofVerified, true);
  assert.equal(sybilOffer.verifiedLiquiditySats, 0, "Sybil LP must verify as 0 sats on Arkade");
  assert.equal(sybilOffer.canFill, false, "Sybil LP must be marked canFill=false");

  // Best LP must be LP-Beta (cheapest FUNDED LP), NOT Evil-Sybil-0bps!
  const best = book.getBestOffer(2);
  assert.equal(best.lpName, "LP-Beta", `expected LP-Beta as best, got ${best.lpName}`);

  // Oracle price must be liquidity-weighted and completely immune to the $10,000 Sybil LP!
  const oracle = book.getOrderbookPrice();
  assert.equal(oracle.isSybilResistant, true);
  assert.equal(oracle.verifiedLpCount, 2);
  assert.ok(oracle.totalVerifiedSats > 0);
  assert.equal(oracle.medianMidUsd, 96_500, `Sybil distorted oracle price: ${oracle.medianMidUsd}`);

  console.log(
    `  PASS: live Arkade PoF verified LP-Alpha (${alphaOffer.verifiedLiquiditySats} sats), LP-Beta (${betaOffer.verifiedLiquiditySats} sats), caught Evil-Sybil (0 sats)! Best=${best.lpName}, Sybil-resistant Oracle=$${oracle.medianMidUsd}`
  );
}

await runOfflineTests();
await runLiveRelayTests();
await runLiveArkadePofTests();
console.log("=== ALL OFFER BOOK TESTS PASSED ===");
process.exit(0);
