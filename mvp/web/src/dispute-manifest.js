// Contract Manifest hashing and k-of-n dispute leaf discovery, shared by the web wallet,
// the Node LP daemon (via mvp/src/contract.mjs) and the Node tests. No browser-only imports.
//
// v1 (`p2pfiat/dispute-manifest/v1`) commits to ONE dispute leaf script, so only that leaf's
// k oracles can sign a dispute. v2 (`p2pfiat/dispute-manifest/v2`) commits to the BIP-341 leaf
// hashes of EVERY k-of-n subset leaf, so any k online oracles can. Spec: p2pfiat/p2pFiat#20;
// oracle side: p2pfiat/nostracle#7; watchtower side: watchtower/src/dispute.rs.
import { VtxoScript } from "@arkade-os/sdk";
import * as btc from "@scure/btc-signer";
import { hex } from "@scure/base";
import { sha256 } from "@noble/hashes/sha2.js";
import { parseDisputeLeaf } from "./dispute-witness.js";

export const MANIFEST_TAG_V1 = "p2pfiat/dispute-manifest/v1";
export const MANIFEST_TAG_V2 = "p2pfiat/dispute-manifest/v2";

const enc = new TextEncoder();

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

function taggedHash(tag, ...parts) {
  const t = sha256(enc.encode(tag));
  return sha256(concat(t, t, ...parts));
}

function compactSize(n) {
  if (n < 0xfd) return new Uint8Array([n]);
  if (n <= 0xffff) return new Uint8Array([0xfd, n & 0xff, n >> 8]);
  throw new Error("leaf script too long");
}

/** BIP-341 TapLeaf hash (leaf version 0xc0) of a script, as lowercase hex. */
export function disputeLeafHashHex(script) {
  return hex.encode(taggedHash("TapLeaf", new Uint8Array([0xc0]), compactSize(script.length), script));
}

/** Sorted lowercase leaf hashes, the v2 manifest's commitment. */
export function disputeLeafHashesHex(scripts) {
  return scripts.map((s) => disputeLeafHashHex(s)).sort();
}

/**
 * Deterministic BIP-340 tagged hash of a Contract Manifest. `manifest_version: 2` commits to
 * `dispute_leaf_hashes_hex` (sorted, comma-joined) in place of `dispute_script_hex`; anything
 * else is v1. Matches nostracle `compute_manifest_hash` and the watchtower's.
 */
export function computeDisputeManifestHash(m) {
  const v2 = Number(m.manifest_version) === 2;
  const disputeField = v2
    ? [...(m.dispute_leaf_hashes_hex || [])].map((h) => String(h).trim().toLowerCase()).sort().join(",")
    : String(m.dispute_script_hex).trim().toLowerCase();
  const canonical = [
    String(m.contract_id).trim(),
    String(m.vtxo_outpoint).trim().toLowerCase(),
    String(m.currency).trim().toUpperCase(),
    String(m.side || "short").trim().toLowerCase(),
    String(Number(m.total_collateral_sats)),
    String(Math.round(Number(m.notional_fiat) * 100)),
    String(Number(m.opened_at)),
    String(Math.round(Number(m.funding_rate_bps_per_day) * 100)),
    String(m.user_pubkey_hex).trim().toLowerCase(),
    String(m.lp_pubkey_hex).trim().toLowerCase(),
    String(m.vtxo_pk_script_hex).trim().toLowerCase(),
    disputeField,
    String(m.user_payout_script_hex).trim().toLowerCase(),
    String(m.lp_payout_script_hex).trim().toLowerCase(),
  ].join("|");
  return taggedHash(v2 ? MANIFEST_TAG_V2 : MANIFEST_TAG_V1, enc.encode(canonical));
}

/**
 * Read the contract's real dispute leaves from its encoded taptree: every CSVMultisig leaf
 * whose keys are all quorum oracles and that has exactly `threshold` keys. The tree must
 * produce `pkScriptHex`, so a stored tree that does not match the contract is refused.
 * Returns `[{ scriptHex, script, pubkeysHex, controlBlockHex, leafHashHex }]` in tree order.
 */
export function disputeLeavesFromTapTree({ tapTreeHex, pkScriptHex, oracleQuorum }) {
  const vtxoScript = VtxoScript.decode(hex.decode(tapTreeHex));
  if (hex.encode(vtxoScript.pkScript) !== String(pkScriptHex).toLowerCase()) {
    throw new Error("Stored contract taptree does not match the contract's pkScript");
  }
  const quorum = new Set((oracleQuorum?.oracles || []).map((o) => String(o.pubkey).toLowerCase()));
  const k = Number(oracleQuorum?.threshold);
  const leaves = [];
  // `.scripts` holds the raw leaf scripts (`.leaves` are [controlBlock, script||version] pairs)
  for (const script of vtxoScript.scripts) {
    let parsed;
    try {
      parsed = parseDisputeLeaf(script);
    } catch {
      continue; // settle / exit / other leaves
    }
    if (parsed.pubkeysHex.length !== k || !parsed.pubkeysHex.every((pk) => quorum.has(pk))) continue;
    const [ctrl] = vtxoScript.findLeaf(hex.encode(script));
    leaves.push({
      script,
      scriptHex: hex.encode(script),
      pubkeysHex: parsed.pubkeysHex,
      controlBlockHex: hex.encode(btc.TaprootControlBlock.encode(ctrl)),
      leafHashHex: disputeLeafHashHex(script),
    });
  }
  return leaves;
}

/**
 * Round-2 leaf choice: the first leaf whose k oracles all signed in round 1.
 * Any k signers always form a leaf when every k-subset is committed.
 */
export function selectFallbackLeaf(leaves, signedPubkeysHex) {
  const signed = new Set([...signedPubkeysHex].map((p) => String(p).toLowerCase()));
  return leaves.find((l) => l.pubkeysHex.every((pk) => signed.has(pk))) || null;
}
