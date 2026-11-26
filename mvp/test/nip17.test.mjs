/**
 * Verification suite for NIP-44 v2 + NIP-17 / NIP-59 serverless P2P trade negotiation.
 *
 * Part A (offline crypto & security):
 *   - NIP-44 v2 encrypt/decrypt roundtrip on small JSON + 12KB Arkade PSBT payload
 *   - Tampered MAC and wrong conversation key are rejected
 *   - NIP-17 Gift Wrap / Unwrap roundtrip + NIP-59 impersonation check
 *
 * Part B (live public Nostr relay serverless LP roundtrip):
 *   - Starts a 100% serverless LP (`enableHttp: false`, zero HTTP ports!) on public Nostr relays
 *   - Connects a User `Nip17Peer` over the live Nostr relay
 *   - Calls `health` and `quote` ($5 USD) purely via encrypted kind-1059 Gift Wraps
 *   - Verifies live BTC/USD quote and collateral calculation return cleanly
 */

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomEvenKey } from "../src/crypto.mjs";
import {
  getConversationKey,
  nip44Encrypt,
  nip44Decrypt,
  wrapGift,
  unwrapGift,
  Nip17Peer,
} from "../src/nip17.mjs";
import { createLpServer } from "../src/lp.mjs";

async function runOfflineCryptoTests() {
  console.log("=== Part A: NIP-44 v2 & NIP-17 Gift Wrap Crypto Verification ===");
  const alice = randomEvenKey();
  const bob = randomEvenKey();
  const mallory = randomEvenKey();

  // 1. Symmetric ECDH conversation key
  const ckAB = getConversationKey(alice.privBytes, bob.pubHex);
  const ckBA = getConversationKey(bob.privBytes, alice.pubHex);
  assert.deepEqual(ckAB, ckBA, "ECDH conversation key must be symmetric");

  // 2. Roundtrip small + 12KB PSBT-sized payload
  const small = JSON.stringify({ method: "quote", notionalUsd: 5 });
  const ctSmall = nip44Encrypt(small, ckAB);
  assert.equal(nip44Decrypt(ctSmall, ckBA), small);

  const largePsbt = "A".repeat(12_345);
  const ctLarge = nip44Encrypt(largePsbt, ckAB);
  assert.equal(nip44Decrypt(ctLarge, ckBA), largePsbt);

  // 3. Wrong key and tampered ciphertext/MAC rejected
  const ckAM = getConversationKey(alice.privBytes, mallory.pubHex);
  assert.throws(() => nip44Decrypt(ctSmall, ckAM), /MAC|invalid/i);
  const tampered = ctSmall.slice(0, -4) + "AAAA";
  assert.throws(() => nip44Decrypt(tampered, ckBA), /MAC|invalid/i);

  // 4. NIP-17 Gift Wrap roundtrip (ephemeral outer key hides Alice's pubkey!)
  const wrap = wrapGift(alice, bob.pubHex, small);
  assert.equal(wrap.kind, 1059);
  assert.notEqual(wrap.pubkey, alice.pubHex, "outer gift wrap must use ephemeral random key");
  const unwrapped = unwrapGift(bob, wrap);
  assert.equal(unwrapped.senderPubkey, alice.pubHex);
  assert.equal(unwrapped.content, small);
  assert.throws(() => unwrapGift(mallory, wrap), /MAC|invalid/i);

  console.log("  PASS: NIP-44 v2 (small + 12KB PSBT), tampered MAC rejection, and NIP-17 Gift Wrap verified");
}

async function runLiveServerlessLpTest() {
  console.log("=== Part B: Live Serverless NIP-17 P2P LP Roundtrip (Zero HTTP Ports!) ===");
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "p2pfiat-nip17-"));
  const relays = ["wss://relay.primal.net", "wss://nos.lol"];

  // Start a 100% serverless LP: enableHttp = false!
  const lp = await createLpServer({
    enableHttp: false,
    dataDir: tmpDir,
    lpName: "Serverless-NIP17-LP",
    spreadBps: 4,
    fundingRateBpsPerDay: 5,
    relays,
  });
  assert.equal(lp.url, null, "HTTP must be completely disabled");
  assert.ok(lp.nip17Connected >= 1, "LP must connect to at least 1 Nostr relay for NIP-17");
  console.log(`  Serverless LP listening via NIP-17 on ${lp.nip17Connected}/${relays.length} relays (pubkey=${lp.lpKey.pubHex.slice(0, 12)}…)`);

  const userKey = randomEvenKey();
  const userPeer = new Nip17Peer(userKey, relays);
  try {
    const userConn = await userPeer.connect();
    assert.ok(userConn >= 1, "User must connect to at least 1 Nostr relay");

    const health = await userPeer.request(lp.lpKey.pubHex, "health", {}, 15_000);
    assert.equal(health.ok, true);
    assert.equal(health.lpName, "Serverless-NIP17-LP");
    assert.deepEqual(health.transports, ["nostr-nip17"]);
    console.log(`  NIP-17 health OK: spot=$${health.spotUsd}, transports=${JSON.stringify(health.transports)}`);

    const quote = await userPeer.request(lp.lpKey.pubHex, "quote", { notionalUsd: 5 }, 15_000);
    assert.equal(quote.notionalUsd, 5);
    assert.equal(quote.lpPubkey, lp.lpKey.pubHex);
    assert.equal(quote.spreadBps, 4);
    assert.equal(quote.fundingRateBpsPerDay, 5);
    assert.ok(quote.userCollateralSats > 0 && quote.totalCollateralSats === quote.userCollateralSats * 2);
    console.log(
      `  NIP-17 quote OK: $5 USD @ $${quote.spotUsd} -> collateral=${quote.userCollateralSats} sats (quoteId=${quote.quoteId})`
    );
  } finally {
    userPeer.close();
    await lp.close();
  }
}

await runOfflineCryptoTests();
await runLiveServerlessLpTest();
console.log("=== ALL NIP-17 P2P TESTS PASSED ===");
process.exit(0);
