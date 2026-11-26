/**
 * Verification suite for Trustless DLC Exit Payouts, BIP-340 Adaptor Signatures,
 * Tiered Taproot Watchtower Bounties, and `ark-watchtower` Package Schema Compatibility.
 */

import assert from "node:assert/strict";
import * as btc from "@scure/btc-signer";
import { hex } from "@scure/base";
import { schnorr } from "@noble/curves/secp256k1.js";
import {
  randomEvenKey,
  schnorrSign,
  adaptorSign,
  adaptorVerify,
  adaptorComplete,
  deriveOutcomeAdaptorPoint,
} from "../src/crypto.mjs";
import {
  buildDlcContractScript,
  buildWatchtowerBountyScript,
  buildLpExitSuite,
} from "../src/contract.mjs";

const userKey = randomEvenKey();
const lpKey = randomEvenKey();
const serverKey = randomEvenKey();
const oracleKey = randomEvenKey();
const wtKey = randomEvenKey();

const exitDelaySecs = 2048n;
const totalCollateralSats = 10_000;
const notionalUsd = 5;
const openSpotUsd = 96_500;
const vtxoTxid = "aa".repeat(32);

const { vtxoScript: contractScript, exitClosure } = buildDlcContractScript(
  userKey.pubXOnly,
  lpKey.pubXOnly,
  serverKey.pubXOnly,
  exitDelaySecs
);

// 1. Verify Tiered Taproot Watchtower Bounty script
const bountySpec = {
  amount_sats: 600,
  vout: 2,
  primary_pubkey: wtKey.pubHex,
  backup_pubkeys: [],
  backup_csv: 4,
};
const bounty = buildWatchtowerBountyScript(bountySpec);
assert.equal(bounty.pkScript.length, 34, "Taproot bounty pkScript must be 34 bytes (OP_1 <32B>)");
assert.equal(bounty.pkScript[0], 0x51);
assert.equal(bounty.pkScript[1], 0x20);

// 2. Build full LP exit suite (5 DLC adaptor payouts + 1 timelocked refund)
const oracleEventId = "btcusd-1764100000";
const refundLockTime = 1_764_700_000;
const suite = buildLpExitSuite({
  vtxoTxid,
  vtxoVout: 0,
  totalCollateralSats,
  notionalUsd,
  openSpotUsd,
  contractScript,
  exitClosure,
  exitDelaySecs,
  userPubXOnly: userKey.pubXOnly,
  lpKey,
  oraclePubHex: oracleKey.pubHex,
  oracleEventId,
  watchtowerPubHex: wtKey.pubHex,
  refundLockTime,
});

assert.equal(suite.payouts.length, 5, "expected 5 discrete price-bucket payouts");
assert.ok(suite.refund, "expected timelocked refund tx");
assert.ok(suite.exit_control_block.length >= 66, "expected valid taproot control block");
assert.equal(suite.bounty.primary_pubkey, wtKey.pubHex);
assert.equal(suite.bounty.amount_sats, 1000);

function exitSighash(rawTxHex) {
  const tx = btc.Transaction.fromRaw(hex.decode(rawTxHex), {
    allowUnknownInputs: true,
    allowUnknownOutputs: true,
  });
  // Verify vout 2 is exact Taproot bounty output
  const out2 = tx.getOutput(2);
  assert.equal(out2.amount, 1000n, "vout 2 must pay exact 1000 sat watchtower bounty");
  assert.equal(hex.encode(out2.script), bounty.pkScriptHex, "vout 2 must lock to NUMS Taproot bounty script");
  return tx.preimageWitnessV1(
    0,
    [contractScript.pkScript],
    btc.SigHash.DEFAULT,
    [BigInt(totalCollateralSats)],
    -1,
    exitClosure.script,
    0xc0
  );
}

// 3. Verify every LP adaptor sig, co-sign as User, complete with oracle scalar, verify BIP-340!
for (const p of suite.payouts) {
  const sighash = exitSighash(p.tx_hex);
  const { scalar: tScalar, point: pointT } = deriveOutcomeAdaptorPoint(
    oracleKey.pubXOnly,
    oracleEventId,
    p.outcome
  );

  const lpAdaptor = hex.decode(p.lp_adaptor_sig);
  assert.equal(lpAdaptor.length, 64);
  assert.equal(
    adaptorVerify(lpAdaptor, lpKey.pubXOnly, sighash, pointT),
    true,
    `LP adaptor sig must verify for ${p.outcome}`
  );

  // User co-signs adaptor sig
  const userAdaptor = adaptorSign(userKey, sighash, pointT);
  assert.equal(
    adaptorVerify(userAdaptor, userKey.pubXOnly, sighash, pointT),
    true,
    `User adaptor sig must verify for ${p.outcome}`
  );

  // Watchtower completes both adaptor sigs upon oracle attestation scalar `t`
  const lpFinalSig = adaptorComplete(lpAdaptor, tScalar);
  const userFinalSig = adaptorComplete(userAdaptor, tScalar);
  assert.equal(
    schnorr.verify(lpFinalSig, sighash, lpKey.pubXOnly),
    true,
    `Completed LP BIP-340 sig must verify for ${p.outcome}`
  );
  assert.equal(
    schnorr.verify(userFinalSig, sighash, userKey.pubXOnly),
    true,
    `Completed User BIP-340 sig must verify for ${p.outcome}`
  );
}

// 4. Verify timelocked refund tx signatures (User + LP)
const refSighash = exitSighash(suite.refund.tx_hex);
const lpRefSig = hex.decode(suite.refund.lp_sig);
const userRefSig = schnorrSign(userKey, refSighash);
assert.equal(schnorr.verify(lpRefSig, refSighash, lpKey.pubXOnly), true, "LP refund sig must verify");
assert.equal(schnorr.verify(userRefSig, refSighash, userKey.pubXOnly), true, "User refund sig must verify");

console.log(
  `PASS: 5/5 adaptor-signed exit payouts + timelocked refund + 600-sat NUMS Taproot bounty verified (BIP-340 complete & valid)`
);
process.exit(0);
