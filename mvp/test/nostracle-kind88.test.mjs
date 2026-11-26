/**
 * Verification test for real `nostracle` (kormir 1.1.2) `kind: 88` announcement
 * binary parsing, BIP-340 verification, 20-bit binary prefix adaptor signing,
 * and `sum_attestation_scalars` completion (`ark-watchtower` compatible).
 */

import assert from "node:assert/strict";
import * as btc from "@scure/btc-signer";
import { hex, base64 } from "@scure/base";
import { schnorr } from "@noble/curves/secp256k1.js";
import {
  N,
  randomEvenKey,
  schnorrSign,
  adaptorSign,
  adaptorVerify,
  adaptorComplete,
  taggedHash,
  bytesToBigInt,
} from "../src/crypto.mjs";
import { buildDlcContractScript, buildLpExitSuite } from "../src/contract.mjs";
import {
  parseKormirAnnouncement,
  computeKormirOutcomePoint,
  priceToBinaryPrefix,
} from "../src/nostracle-client.mjs";

const enc = new TextEncoder();

function u16be(n) {
  return Uint8Array.from([(n >> 8) & 0xff, n & 0xff]);
}
function u32be(n) {
  return Uint8Array.from([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}
function concat(...arrs) {
  const out = new Uint8Array(arrs.reduce((s, a) => s + a.length, 0));
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

/** Encode a kormir-compatible `OracleAnnouncement` binary blob (without top-level type prefix). */
function encodeKormirAnnouncement(oracleKey, nonces, maturityEpoch, unit, numDigits, eventId) {
  const unitBytes = enc.encode(unit);
  const eventIdBytes = enc.encode(eventId);
  // DigitDecompositionEventDescriptor payload: u16 base(2), u8 is_signed(0), u16 unit_len + unit, i32 precision(0), u16 nb_digits
  const descPayload = concat(
    u16be(2),
    Uint8Array.from([0]),
    u16be(unitBytes.length),
    unitBytes,
    u32be(0),
    u16be(numDigits)
  );
  // BigSize type 55306 (0xfd d8 0a) + BigSize len + payload
  const descTlv = concat(Uint8Array.from([0xfd, 0xd8, 0x0a]), Uint8Array.from([descPayload.length]), descPayload);
  const oracleEvent = concat(
    u16be(nonces.length),
    ...nonces.map((n) => n.pubXOnly),
    u32be(maturityEpoch),
    descTlv,
    u16be(eventIdBytes.length),
    eventIdBytes
  );
  const annHash = taggedHash("DLC/oracle/announcement/v0", oracleEvent);
  const annSig = schnorrSign(oracleKey, annHash);
  return base64.encode(concat(annSig, oracleKey.pubXOnly, oracleEvent));
}

/** Sign a 20-bit price exactly like `kormir` (`nostracle`) does: s_i = (k_i + e_i * d_O) mod n. */
function kormirSignPrice(oracleKey, nonces, priceInt) {
  const bits = priceInt.toString(2).padStart(nonces.length, "0");
  const scalars = [];
  for (let i = 0; i < bits.length; i++) {
    const msg = taggedHash("DLC/oracle/attestation/v0", enc.encode(bits[i]));
    const e = bytesToBigInt(taggedHash("BIP0340/challenge", nonces[i].pubXOnly, oracleKey.pubXOnly, msg)) % N;
    scalars.push((nonces[i].d + e * oracleKey.d) % N);
  }
  return { bits, scalars };
}

// 1. Generate real 20-nonce kormir announcement & parse it with parseKormirAnnouncement
const oracleKey = randomEvenKey();
const nonces = Array.from({ length: 20 }, () => randomEvenKey());
const eventId = "btcusd-1764100000";
const annB64 = encodeKormirAnnouncement(oracleKey, nonces, 1_764_100_000, "USD", 20, eventId);

const parsed = parseKormirAnnouncement(annB64);
assert.equal(parsed.oraclePubkeyHex, oracleKey.pubHex);
assert.equal(parsed.noncesHex.length, 20);
assert.equal(parsed.unit, "USD");
assert.equal(parsed.numDigits, 20);
assert.equal(parsed.eventId, eventId);
assert.equal(parsed.maturityEpoch, 1_764_100_000);

// 2. Build full DLC exit suite bound to real kind:88 nonces
const userKey = randomEvenKey();
const lpKey = randomEvenKey();
const serverKey = randomEvenKey();
const wtKey = randomEvenKey();
const exitDelaySecs = 2048n;
const openSpot = 59_000;
const totalCollateralSats = 10_000;

const { vtxoScript: contractScript, exitClosure } = buildDlcContractScript(
  userKey.pubXOnly,
  lpKey.pubXOnly,
  serverKey.pubXOnly,
  exitDelaySecs
);

const suite = buildLpExitSuite({
  vtxoTxid: "bb".repeat(32),
  vtxoVout: 0,
  totalCollateralSats,
  notionalUsd: 5,
  openSpotUsd: openSpot,
  contractScript,
  exitClosure,
  exitDelaySecs,
  userPubXOnly: userKey.pubXOnly,
  lpKey,
  oraclePubHex: oracleKey.pubHex,
  oracleEventId: eventId,
  announcement: parsed,
  watchtowerPubHex: wtKey.pubHex,
  refundLockTime: 1_764_700_000,
});

assert.equal(suite.usesRealKind88Nonces, true);
assert.equal(suite.announcementNoncesHex.length, 10);
assert.equal(suite.payouts.length, 5);

// 3. Oracle attests price = 59,000 USD -> matches the 0%-bucket 10-bit prefix!
const targetPrefix = priceToBinaryPrefix(openSpot, 20, 10);
const matchingPayout = suite.payouts.find((p) => p.outcome === targetPrefix);
assert.ok(matchingPayout, `expected payout bucket for prefix ${targetPrefix}`);

const tx = btc.Transaction.fromRaw(hex.decode(matchingPayout.tx_hex), {
  allowUnknownInputs: true,
  allowUnknownOutputs: true,
});
const sighash = tx.preimageWitnessV1(
  0,
  [contractScript.pkScript],
  btc.SigHash.DEFAULT,
  [BigInt(totalCollateralSats)],
  -1,
  exitClosure.script,
  0xc0
);

const pointT = computeKormirOutcomePoint(oracleKey.pubXOnly, parsed.noncesHex, targetPrefix);
const lpAdaptor = hex.decode(matchingPayout.lp_adaptor_sig);
assert.equal(adaptorVerify(lpAdaptor, lpKey.pubXOnly, sighash, pointT), true);

const userAdaptor = adaptorSign(userKey, sighash, pointT);
assert.equal(adaptorVerify(userAdaptor, userKey.pubXOnly, sighash, pointT), true);

// 4. Sum the first 10 real kormir attestation scalars (exact same math as `ark-watchtower`)
const { scalars } = kormirSignPrice(oracleKey, nonces, openSpot);
let sumScalar = 0n;
for (let i = 0; i < targetPrefix.length; i++) {
  sumScalar = (sumScalar + scalars[i]) % N;
}

const lpFinalSig = adaptorComplete(lpAdaptor, sumScalar);
const userFinalSig = adaptorComplete(userAdaptor, sumScalar);
assert.equal(schnorr.verify(lpFinalSig, sighash, lpKey.pubXOnly), true, "LP completed sig must verify!");
assert.equal(schnorr.verify(userFinalSig, sighash, userKey.pubXOnly), true, "User completed sig must verify!");

console.log(
  `PASS: real kormir kind:88 announcement parsed (20 nonces), 10-bit prefix ${targetPrefix} (${openSpot} USD) adaptor sigs completed by summed oracle scalars -> valid BIP-340 sigs!`
);
process.exit(0);
