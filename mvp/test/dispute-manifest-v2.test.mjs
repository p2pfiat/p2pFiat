/**
 * Contract Manifest v2 (p2pfiat/p2pFiat#20): commit to every k-of-n dispute leaf so any
 * k online Nostracles can sign a dispute. Shared code: web/src/dispute-manifest.js.
 */
import assert from "node:assert/strict";
import { hex } from "@scure/base";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomEvenKey, schnorrSign, tapLeafHash } from "../src/crypto.mjs";
import {
  buildDlcContractScript,
  buildOnDemandDisputeTx,
  assembleDisputeWitness,
  computeDisputeManifestHash,
  disputeLeafHashHex,
  disputeLeavesFromTapTree,
  selectFallbackLeaf,
} from "../src/contract.mjs";

const enc = new TextEncoder();

// --- 1. v1 hash is byte-for-byte the pre-v2 implementation ---
function v1Reference(m) {
  const canonical = [
    m.contract_id, m.vtxo_outpoint.toLowerCase(), m.currency.toUpperCase(), m.side,
    String(m.total_collateral_sats), String(Math.round(m.notional_fiat * 100)), String(m.opened_at),
    String(Math.round(m.funding_rate_bps_per_day * 100)), m.user_pubkey_hex, m.lp_pubkey_hex,
    m.vtxo_pk_script_hex, m.dispute_script_hex, m.user_payout_script_hex, m.lp_payout_script_hex,
  ].join("|");
  const t = sha256(enc.encode("p2pfiat/dispute-manifest/v1"));
  const body = enc.encode(canonical);
  const pre = new Uint8Array(64 + body.length);
  pre.set(t, 0);
  pre.set(t, 32);
  pre.set(body, 64);
  return sha256(pre);
}

// Fixed cross-language vector (also asserted in watchtower/src/dispute.rs and nostracle).
const VECTOR = {
  contract_id: "pos-vector-1",
  vtxo_outpoint: "aa".repeat(32) + ":0",
  currency: "USD",
  side: "short",
  total_collateral_sats: 333334,
  notional_fiat: 100,
  opened_at: 1795000000,
  funding_rate_bps_per_day: 3,
  user_pubkey_hex: "11".repeat(32),
  lp_pubkey_hex: "22".repeat(32),
  vtxo_pk_script_hex: "5120" + "33".repeat(32),
  dispute_script_hex: "51",
  user_payout_script_hex: "5120" + "44".repeat(32),
  lp_payout_script_hex: "5120" + "55".repeat(32),
};
const VECTOR_V2 = {
  ...VECTOR,
  manifest_version: 2,
  // deliberately unsorted: the hash sorts
  dispute_leaf_hashes_hex: ["bb".repeat(32), "aa".repeat(32), "CC".repeat(32)],
};

assert.deepEqual(computeDisputeManifestHash(VECTOR), v1Reference(VECTOR), "v1 hash must not change");
const v2Hex = hex.encode(computeDisputeManifestHash(VECTOR_V2));
assert.notEqual(v2Hex, hex.encode(computeDisputeManifestHash(VECTOR)), "v2 must not collide with v1");
assert.equal(
  v2Hex,
  hex.encode(
    computeDisputeManifestHash({
      ...VECTOR_V2,
      dispute_leaf_hashes_hex: ["cc".repeat(32), "bb".repeat(32), "aa".repeat(32)],
      dispute_script_hex: "52", // ignored by v2
    })
  ),
  "v2 hash is independent of leaf order and of dispute_script_hex"
);
console.log(`[VECTOR] manifest v2 hash = ${v2Hex}`);
assert.equal(v2Hex, "362770732e8595c4c6c159e5aa17b142188bbd8e1ed09f7fde9547b801005116");

// --- 2. leaf hash matches the Node tapLeafHash ---
const someScript = hex.decode("20" + "77".repeat(32) + "ac");
assert.equal(disputeLeafHashHex(someScript), hex.encode(tapLeafHash(someScript)));

// --- 3. leaves read from a real 3-of-5 contract taptree ---
const oracles = Array.from({ length: 5 }, () => randomEvenKey());
const quorum = { threshold: 3, oracles: oracles.map((o) => ({ pubkey: o.pubHex })) };
const [user, lp, server] = [randomEvenKey(), randomEvenKey(), randomEvenKey()];
const { vtxoScript, disputeClosure } = buildDlcContractScript(
  user.pubXOnly, lp.pubXOnly, server.pubXOnly, 2048n, quorum
);
const leaves = disputeLeavesFromTapTree({
  tapTreeHex: hex.encode(vtxoScript.encode()),
  pkScriptHex: hex.encode(vtxoScript.pkScript),
  oracleQuorum: quorum,
});
assert.equal(leaves.length, 10, "settle and exit leaves are not dispute leaves");
assert.deepEqual(leaves.map((l) => l.leafHashHex).sort(), disputeClosure.leafHashesHex);
assert.deepEqual(
  [...disputeClosure.leafHashesHex].sort(),
  disputeClosure.leafHashesHex,
  "closure leaf hashes are sorted"
);
assert.throws(
  () =>
    disputeLeavesFromTapTree({
      tapTreeHex: hex.encode(vtxoScript.encode()),
      pkScriptHex: "5120" + "00".repeat(32),
      oracleQuorum: quorum,
    }),
  /does not match the contract's pkScript/
);

// --- 4. round-2 leaf choice and a full spend through the chosen leaf ---
const pub = (i) => oracles[i].pubHex.toLowerCase();
const fallback = selectFallbackLeaf(leaves, [pub(0), pub(2), pub(4), pub(3)].slice(0, 3));
assert.deepEqual(fallback.pubkeysHex, [pub(0), pub(2), pub(4)]);
assert.equal(selectFallbackLeaf(leaves, [pub(0), pub(2)]), null, "2 signers form no 3-of-5 leaf");

const dtx = buildOnDemandDisputeTx({
  vtxoTxid: "dd".repeat(32),
  totalCollateralSats: 333_334,
  notionalUsd: 100,
  openedAt: 1_795_000_000,
  disputeTimestamp: 1_795_000_000 + 86_400,
  spotPriceAtDispute: 60_000,
  contractScript: vtxoScript,
  disputeClosure,
  userPubXOnly: user.pubXOnly,
  lpPubXOnly: lp.pubXOnly,
  signerPubsHex: fallback.pubkeysHex,
});
assert.equal(dtx.leafScriptHex, fallback.scriptHex);
assert.equal(dtx.controlBlockHex, fallback.controlBlockHex, "taptree-derived control block matches");
const sigs = Object.fromEntries(
  [0, 2, 4].map((i) => [pub(i), hex.encode(schnorrSign(oracles[i], dtx.sighash))])
);
assert.equal(assembleDisputeWitness(dtx, disputeClosure, sigs).signedCount, 3);

console.log("[PASS] manifest v2: v1 unchanged, order-independent v2 hash, taptree leaves, fallback leaf spend");
