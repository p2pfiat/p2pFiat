/**
 * Cryptographic verification test for Leaf 3: BIP-342 `k-of-n` Nostracle
 * On-Demand Dispute / Anytime Exit & Early Liquidation.
 */
import assert from "node:assert/strict";
import { schnorr } from "@noble/curves/secp256k1.js";
import { hex } from "@scure/base";
import { randomEvenKey, schnorrSign } from "../src/crypto.mjs";
import {
  buildDlcContractScript,
  buildWatchtowerBountyScript,
  buildOnDemandDisputeTx,
  assembleDisputeWitness,
} from "../src/contract.mjs";

const userKey = randomEvenKey();
const lpKey = randomEvenKey();
const serverKey = randomEvenKey();
const wtKey = randomEvenKey();

// Build a 3-of-5 Nostracle quorum
const oracles = Array.from({ length: 5 }, (_, i) => ({
  name: `Nostracle-${i + 1}`,
  key: randomEvenKey(),
}));
const quorum = {
  threshold: 3,
  oracles: oracles.map((o) => ({ name: o.name, pubkey: o.key.pubHex })),
};

const exitDelaySecs = 2048n;
const { vtxoScript, disputeClosure } = buildDlcContractScript(
  userKey.pubXOnly,
  lpKey.pubXOnly,
  serverKey.pubXOnly,
  exitDelaySecs,
  quorum
);

assert.ok(disputeClosure, "3rd leaf (disputeClosure) must be present");
assert.equal(disputeClosure.threshold, 3);
assert.equal(disputeClosure.oraclePubsHex.length, 5);

const { pkScript: bountyPkScript } = buildWatchtowerBountyScript({
  amount_sats: 600,
  vout: 2,
  primary_pubkey: wtKey.pubHex,
  backup_pubkeys: [],
  backup_csv: 4,
});

// Scenario 1: Anytime Mid-Term Exit (Day 5 of a 30-day $100 Stable USD contract at $60k -> $72k)
const openedAt = 1_795_000_000;
const day5 = openedAt + 5 * 86_400;
const midExit = buildOnDemandDisputeTx({
  vtxoTxid: "aa".repeat(32),
  vtxoVout: 0,
  totalCollateralSats: 333_334, // $200 total at $60k ($100 user + $100 LP)
  notionalUsd: 100,
  openedAt,
  disputeTimestamp: day5,
  fundingRateBpsPerDay: 3, // +0.03%/d -> +$0.15 over 5 days
  spotPriceAtDispute: 72_000,
  side: "short",
  contractScript: vtxoScript,
  disputeClosure,
  userPubXOnly: userKey.pubXOnly,
  lpPubXOnly: lpKey.pubXOnly,
  bountyPkScript,
  bountyAmtSats: 600n,
});

// User should receive ~$100.15 at $72k (~139,097 sats)
const userUsd = (midExit.userAmtSats / 1e8) * 72_000;
assert.ok(Math.abs(userUsd - 100.15) < 0.05, `expected ~$100.15, got $${userUsd.toFixed(2)}`);

// Non-contiguous 3-of-5 oracles (#1, #3, #5) sign the BIP-342 sighash
const sigs3 = {};
for (const idx of [0, 2, 4]) {
  const sig = schnorrSign(oracles[idx].key, midExit.sighash);
  assert.ok(
    schnorr.verify(sig, midExit.sighash, oracles[idx].key.pubXOnly),
    `oracle ${idx + 1} BIP-340 sig must verify`
  );
  sigs3[oracles[idx].key.pubHex] = hex.encode(sig);
}

const assembled = assembleDisputeWitness(midExit, disputeClosure, sigs3);
assert.equal(assembled.signedCount, 3);
assert.equal(assembled.witnessStack.length, 5 + 2); // 5 oracle slots + script + controlBlock
assert.ok(assembled.rawSignedHex.length > 400, "finalized witness tx hex must be non-empty");
console.log(
  `[PASS] 3-of-5 Anytime Mid-Term Exit (Day 5): user=$${userUsd.toFixed(2)} (${midExit.userAmtSats} sats), rawTx=${assembled.rawSignedHex.length / 2} bytes`
);

// Scenario 2: Reject insufficient quorum (only 2-of-5 signatures)
const sigs2 = {
  [oracles[0].key.pubHex]: sigs3[oracles[0].key.pubHex],
  [oracles[2].key.pubHex]: sigs3[oracles[2].key.pubHex],
};
assert.throws(
  () => assembleDisputeWitness(midExit, disputeClosure, sigs2),
  /Insufficient Nostracle signatures/,
  "must reject < threshold signatures"
);
console.log("[PASS] Rejected insufficient 2-of-5 signatures");

// Scenario 3: Early Liquidation (BTC drops 55% from $60k to $27k mid-term)
const liqExit = buildOnDemandDisputeTx({
  vtxoTxid: "bb".repeat(32),
  vtxoVout: 0,
  totalCollateralSats: 333_334,
  notionalUsd: 100,
  openedAt,
  disputeTimestamp: day5,
  fundingRateBpsPerDay: 3,
  spotPriceAtDispute: 27_000, // -55% crash
  side: "short",
  contractScript: vtxoScript,
  disputeClosure,
  userPubXOnly: userKey.pubXOnly,
  lpPubXOnly: lpKey.pubXOnly,
  bountyPkScript,
  bountyAmtSats: 600n,
});
// Stable user gets full distributable collateral minus dust (333334 - 600 - 350 = 332384 sats)
assert.equal(liqExit.userAmtSats, 333_334 - 600 - 350);
assert.equal(liqExit.lpAmtSats, 350);
console.log(
  `[PASS] Early Liquidation (-55% BTC crash): Stable user gets 100% of distributable pool (${liqExit.userAmtSats} sats)`
);
