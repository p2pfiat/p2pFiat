// Tapscript witness assembly for the k-of-n Nostracle dispute leaf.
// Kept free of browser-only imports so the Node test suite can exercise it.
import * as btc from "@scure/btc-signer";
import { hex } from "@scure/base";

/**
 * Parse a dispute leaf script into its kind and its oracle x-only pubkeys, in script order.
 *  - "checksigadd": legacy `<csv> CSV DROP <pk_1> CHECKSIG <pk_2> CHECKSIGADD ... <k> GREATERTHANOREQUAL`
 *  - "csvmultisig": arkd-native `<csv> CSV DROP <pk_1> CHECKSIGVERIFY ... <pk_k> CHECKSIG`
 * Opcodes are read from the decoded script, never by searching raw bytes: a pubkey
 * can contain the byte 0xba (OP_CHECKSIGADD), which made byte search misclassify
 * about a third of 3-key CSVMultisig leaves.
 */
const SIG_OPS = new Set(["CHECKSIG", "CHECKSIGVERIFY", "CHECKSIGADD"]);

export function parseDisputeLeaf(disputeScript) {
  const ops = btc.Script.decode(disputeScript);
  const unrecognised = () => new Error("Unrecognised dispute leaf script");
  if (ops[1] !== "CHECKSEQUENCEVERIFY" || ops[2] !== "DROP") throw unrecognised();
  // Every 32-byte push must be a key consumed by the signature opcode right after it,
  // and every signature opcode must consume such a key.
  const pubkeysHex = [];
  const sigOps = [];
  for (let i = 3; i < ops.length; i++) {
    const op = ops[i];
    if (op instanceof Uint8Array && op.length === 32) {
      if (!SIG_OPS.has(ops[i + 1])) throw unrecognised();
      pubkeysHex.push(hex.encode(op));
      sigOps.push(ops[++i]);
    } else if (SIG_OPS.has(op)) {
      throw unrecognised();
    }
  }
  if (pubkeysHex.length < 2) throw new Error("Dispute leaf has fewer than 2 oracle keys");
  const last = ops.length - 1;
  if (sigOps.includes("CHECKSIGADD")) {
    // <pk_1> CHECKSIG <pk_i> CHECKSIGADD ... <k> GREATERTHANOREQUAL
    if (sigOps[0] !== "CHECKSIG" || sigOps.slice(1).some((op) => op !== "CHECKSIGADD")) throw unrecognised();
    if (ops[last] !== "GREATERTHANOREQUAL" || last !== 3 + 2 * pubkeysHex.length + 1) throw unrecognised();
    return { kind: "checksigadd", pubkeysHex };
  }
  // <pk_1> CHECKSIGVERIFY ... <pk_k> CHECKSIG, nothing after
  if (sigOps.slice(0, -1).some((op) => op !== "CHECKSIGVERIFY") || sigOps.at(-1) !== "CHECKSIG") throw unrecognised();
  if (last !== 3 + 2 * pubkeysHex.length - 1) throw unrecognised();
  return { kind: "csvmultisig", pubkeysHex };
}

/**
 * Build the signature part of the dispute witness (everything before script + control block).
 * `sigsByPubkeyHex` maps lowercase x-only oracle pubkey hex to a verified 64-byte signature.
 * The first key in the script is checked first, so its signature goes on top of the stack
 * (pushed last).
 *  - checksigadd: one slot per key, empty for oracles that did not sign.
 *  - csvmultisig: exactly one signature per leaf key, no empty slots (an empty sig fails
 *    CHECKSIGVERIFY); throws naming the leaf oracles that did not sign.
 */
export function buildDisputeWitnessSigs(disputeScript, sigsByPubkeyHex) {
  const { kind, pubkeysHex } = parseDisputeLeaf(disputeScript);
  if (kind === "csvmultisig") {
    const missing = pubkeysHex.filter((pk) => !sigsByPubkeyHex.get(pk));
    if (missing.length) {
      throw new Error(
        `Dispute leaf needs all ${pubkeysHex.length} of its oracles to sign; missing ${missing
          .map((pk) => pk.slice(0, 8))
          .join(", ")}`
      );
    }
  }
  const stack = [];
  for (let i = pubkeysHex.length - 1; i >= 0; i--) {
    stack.push(sigsByPubkeyHex.get(pubkeysHex[i]) || new Uint8Array(0));
  }
  return { kind, pubkeysHex, sigs: stack };
}
