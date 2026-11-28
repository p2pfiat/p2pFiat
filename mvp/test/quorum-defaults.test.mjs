/**
 * Guards the default Nostracle quorums of the LP (`src/offerbook.mjs`) and the web wallet
 * (`web/src/offerbook.js`): no oracle key may have a publicly known private key
 * (small scalars 1..1000, e.g. 1·G, 2·G, 3·G), and both sides use the same Nostracles.
 */
import assert from "node:assert/strict";
import { schnorr } from "@noble/curves/secp256k1.js";
import { hex } from "@scure/base";
import { DEFAULT_NOSTRACLE_QUORUM as lpDefault } from "../src/offerbook.mjs";
import { NOSTRACLE_POOL, DEFAULT_NOSTRACLE_QUORUM as webDefault } from "../web/src/offerbook.js";

const smallScalarKeys = new Set(
  Array.from({ length: 1000 }, (_, i) => {
    const sk = new Uint8Array(32);
    sk[30] = (i + 1) >> 8;
    sk[31] = (i + 1) & 0xff;
    return hex.encode(schnorr.getPublicKey(sk));
  })
);

for (const [name, oracles] of [
  ["LP DEFAULT_NOSTRACLE_QUORUM", lpDefault.oracles],
  ["web NOSTRACLE_POOL", NOSTRACLE_POOL],
  ["web DEFAULT_NOSTRACLE_QUORUM", webDefault.oracles],
]) {
  for (const o of oracles) {
    assert.ok(!smallScalarKeys.has(o.pubkey.toLowerCase()), `${name}: ${o.name} has a publicly known private key`);
  }
}

assert.equal(lpDefault.threshold, 2);
assert.equal(webDefault.threshold, 2);
assert.deepEqual(
  lpDefault.oracles.map((o) => o.pubkey),
  webDefault.oracles.map((o) => o.pubkey),
  "LP and web wallet default to the same Nostracles"
);
console.log("[PASS] default quorums: no small-scalar keys, LP and web wallet agree (2-of-3)");
