/**
 * Web wallet dispute witness (`web/src/dispute-witness.js`), used by
 * `BrowserP2pFiatWallet.forceDisputeExit`.
 */
import assert from "node:assert/strict";
import * as btc from "@scure/btc-signer";
import { hex } from "@scure/base";
import { CSVMultisigTapscript } from "@arkade-os/sdk";
import { randomEvenKey, schnorrSign } from "../src/crypto.mjs";
import {
  buildDlcContractScript,
  buildOnDemandDisputeTx,
  assembleDisputeWitness,
} from "../src/contract.mjs";
import { parseDisputeLeaf, buildDisputeWitnessSigs } from "../web/src/dispute-witness.js";

const csvLeaf = (keys) =>
  CSVMultisigTapscript.encode({
    timelock: { type: "seconds", value: 2048n },
    pubkeys: keys.map((k) => k.pubXOnly),
  }).script;

// 1. A CSVMultisig leaf whose bytes contain 0xba (inside a pubkey) is still CSVMultisig.
let keys;
do {
  keys = [0, 1, 2].map(() => randomEvenKey());
} while (!csvLeaf(keys).includes(0xba));
const leaf = csvLeaf(keys);
const parsed = parseDisputeLeaf(leaf);
assert.equal(parsed.kind, "csvmultisig", "0xba inside a pubkey must not mean OP_CHECKSIGADD");
assert.deepEqual(parsed.pubkeysHex, keys.map((k) => k.pubHex.toLowerCase()));

// 2. Witness: one sig per leaf key, reverse order, first key's sig on top of the stack.
const msg = new Uint8Array(32).fill(7);
const sigs = new Map(keys.map((k) => [k.pubHex.toLowerCase(), schnorrSign(k, msg)]));
const { sigs: stack } = buildDisputeWitnessSigs(leaf, sigs);
assert.equal(stack.length, 3);
assert.deepEqual(stack, [...keys].reverse().map((k) => sigs.get(k.pubHex.toLowerCase())));

// 3. A missing leaf signer is an error, not an empty push.
const partial = new Map(sigs);
partial.delete(keys[1].pubHex.toLowerCase());
assert.throws(
  () => buildDisputeWitnessSigs(leaf, partial),
  new RegExp(`missing ${keys[1].pubHex.slice(0, 8)}`, "i")
);

// 4. Legacy OP_CHECKSIGADD leaf keeps n slots with empty pushes for non-signers.
const legacy = btc.Script.encode([
  (1 << 22) | 4, "CHECKSEQUENCEVERIFY", "DROP",
  keys[0].pubXOnly, "CHECKSIG",
  keys[1].pubXOnly, "CHECKSIGADD",
  keys[2].pubXOnly, "CHECKSIGADD",
  2, "GREATERTHANOREQUAL",
]);
const legacyOut = buildDisputeWitnessSigs(legacy, partial);
assert.equal(legacyOut.kind, "checksigadd");
assert.equal(legacyOut.sigs.length, 3);
assert.equal(legacyOut.sigs[1].length, 0, "non-signer slot is empty");

// 5. Same witness as the Node builder for a real 3-of-5 contract's manifest (primary) leaf.
const oracles = Array.from({ length: 5 }, () => randomEvenKey());
const quorum = { threshold: 3, oracles: oracles.map((o) => ({ pubkey: o.pubHex })) };
const [user, lp, server] = [randomEvenKey(), randomEvenKey(), randomEvenKey()];
const { vtxoScript, disputeClosure } = buildDlcContractScript(
  user.pubXOnly, lp.pubXOnly, server.pubXOnly, 2048n, quorum
);
const dtx = buildOnDemandDisputeTx({
  vtxoTxid: "cc".repeat(32),
  totalCollateralSats: 333_334,
  notionalUsd: 100,
  openedAt: 1_795_000_000,
  disputeTimestamp: 1_795_000_000 + 86_400,
  spotPriceAtDispute: 60_000,
  contractScript: vtxoScript,
  disputeClosure,
  userPubXOnly: user.pubXOnly,
  lpPubXOnly: lp.pubXOnly,
});
// All 5 oracles answer; only the leaf's 3 are used.
const all = new Map(oracles.map((o) => [o.pubHex.toLowerCase(), schnorrSign(o, dtx.sighash)]));
const web = buildDisputeWitnessSigs(dtx.leafScript, all);
const node = assembleDisputeWitness(dtx, disputeClosure, Object.fromEntries(
  [...all].map(([pk, s]) => [pk, hex.encode(s)])
));
assert.deepEqual(web.sigs, node.witnessStack.slice(0, 3), "web and Node witnesses must match");

console.log("[PASS] web dispute witness: 0xba-safe parse, order, missing signer, legacy, matches Node");
