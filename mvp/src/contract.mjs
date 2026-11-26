//! Arkade DLC contract Tapscript builder, VTXO unroll chain extractor, and
//! keyless `ark-watchtower` package exporter.

import {
  VtxoScript,
  MultisigTapscript,
  CSVMultisigTapscript,
  DefaultVtxo,
  Transaction,
} from "@arkade-os/sdk";
import * as btc from "@scure/btc-signer";
import { hex, base64 } from "@scure/base";
import {
  schnorrSign,
  adaptorSign,
  deriveOutcomeAdaptorPoint,
  computeUsdPayoutSats,
} from "./crypto.mjs";
import {
  computeKormirOutcomePoint,
  priceToBinaryPrefix,
} from "./nostracle-client.mjs";

/** Unspendable BIP-341 NUMS internal key (matches `ark-watchtower/src/bounty.rs`). */
export const NUMS_INTERNAL_KEY_HEX =
  "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

/**
 * Compile a tiered Taproot watchtower bounty output script matching `ark-watchtower/src/bounty.rs`:
 * - Internal key: NUMS point `H` (key-path unspendable)
 * - Primary leaf: `<primary_pubkey> OP_CHECKSIG`
 * - Backup leaves (optional): `<backup_csv> OP_CSV OP_DROP <backup_pubkey> OP_CHECKSIG`
 */
export function buildWatchtowerBountyScript(bountySpec) {
  const numsXOnly = hex.decode(NUMS_INTERNAL_KEY_HEX);
  const primaryLeaf = btc.Script.encode([hex.decode(bountySpec.primary_pubkey), "CHECKSIG"]);
  const backupPubs = bountySpec.backup_pubkeys || [];
  const backupCsv = Number(bountySpec.backup_csv || 4);

  let tree;
  if (backupPubs.length === 0) {
    tree = { script: primaryLeaf };
  } else {
    const leaves = [
      { script: primaryLeaf },
      ...backupPubs.map((pk) => ({
        script: btc.Script.encode([backupCsv, "CHECKSEQUENCEVERIFY", "DROP", hex.decode(pk), "CHECKSIG"]),
      })),
    ];
    // Balanced binary tree matching rust-bitcoin TaprootBuilder insertion order
    tree = leaves.reduce((acc, leaf) => [acc, leaf]);
  }
  const p2tr = btc.p2tr(numsXOnly, tree, btc.TEST_NETWORK, true);
  return {
    pkScript: p2tr.script,
    pkScriptHex: hex.encode(p2tr.script),
    address: p2tr.address,
  };
}

/**
 * Build a BIP-342 Tapscript `k-of-n` Nostracle On-Demand Dispute Leaf:
 *   `<exitDelaySecs> OP_CHECKSEQUENCEVERIFY OP_DROP`
 *   `<oracle_1> OP_CHECKSIG <oracle_2> OP_CHECKSIGADD ... <oracle_n> OP_CHECKSIGADD <k> OP_GREATERTHANOREQUAL`
 *
 * Allows either party (or a Watchtower) to close a long-term (7d/30d/90d) contract
 * at ANY time if the counterparty goes offline or BTC drops >= 50%, with zero
 * cherry-picking risk because the quorum signs the live spot price at exit time `T`.
 */
export function buildNostracleDisputeLeaf(oraclePubsHex, threshold, exitDelaySecs) {
  if (!Array.isArray(oraclePubsHex) || oraclePubsHex.length < 2) {
    throw new Error("Dispute quorum requires at least 2 oracles");
  }
  const k = Number(threshold);
  if (!Number.isInteger(k) || k < 2 || k > oraclePubsHex.length) {
    throw new Error(`Invalid quorum threshold ${k} for ${oraclePubsHex.length} oracles`);
  }
  const csvVal = (1 << 22) | Number(BigInt(exitDelaySecs) / 512n);
  const ops = [csvVal, "CHECKSEQUENCEVERIFY", "DROP"];
  oraclePubsHex.forEach((pubHex, idx) => {
    ops.push(hex.decode(pubHex.trim()));
    ops.push(idx === 0 ? "CHECKSIG" : "CHECKSIGADD");
  });
  ops.push(k, "GREATERTHANOREQUAL");
  const script = btc.Script.encode(ops);
  return {
    script,
    scriptHex: hex.encode(script),
    oraclePubsHex: oraclePubsHex.map((p) => p.trim().toLowerCase()),
    threshold: k,
    csvSequence: csvVal,
  };
}

/**
 * Build a Design 1 Arkade DLC VtxoScript compatible with live `mutinynet.arkade.sh`
 * (time-based `CSV(unilateralExitDelay)` on the exit leaf, plus optional 3rd leaf
 * for `k-of-n` Nostracle On-Demand Dispute / Anytime Exit).
 */
export function buildDlcContractScript(
  userPubXOnly,
  lpPubXOnly,
  serverXOnly,
  exitDelaySecs,
  oracleQuorum = null
) {
  const settleClosure = MultisigTapscript.encode({
    pubkeys: [userPubXOnly, lpPubXOnly, serverXOnly],
  });
  const exitClosure = CSVMultisigTapscript.encode({
    timelock: { type: "seconds", value: BigInt(exitDelaySecs) },
    pubkeys: [userPubXOnly, lpPubXOnly],
  });
  let disputeClosure = null;
  const leaves = [settleClosure.script, exitClosure.script];
  if (oracleQuorum?.oracles?.length >= 2 && Number(oracleQuorum.threshold) >= 2) {
    disputeClosure = buildNostracleDisputeLeaf(
      oracleQuorum.oracles.map((o) => o.pubkey),
      oracleQuorum.threshold,
      exitDelaySecs
    );
    leaves.push(disputeClosure.script);
  }
  const vtxoScript = new VtxoScript(leaves);
  return { vtxoScript, settleClosure, exitClosure, disputeClosure };
}

/** Build a standard DefaultVtxo script for receiving Arkade payouts. */
export function buildDefaultArkScript(pubXOnly, serverXOnly, exitDelaySecs) {
  return new DefaultVtxo.Script({
    pubKey: pubXOnly,
    serverPubKey: serverXOnly,
    csvTimelock: { type: "seconds", value: BigInt(exitDelaySecs) },
  });
}

/**
 * Extract ordered raw signed Bitcoin transaction hexes (`root -> leaf`) from
 * `RestIndexerProvider.getVtxoChain` + `getVirtualTxs`, handling both
 * `tapKeySig`-only TREE PSBTs and tapscript CHECKPOINT/ARK PSBTs.
 */
export async function extractUnrollTxs(indexerProvider, txid, vout) {
  let chain = [];
  for (let i = 0; i < 15; i++) {
    const resp = await indexerProvider.getVtxoChain({ txid, vout });
    if (resp.txs?.length) {
      chain = resp.txs;
      break;
    }
    if (resp.chain?.length) {
      chain = resp.chain;
      break;
    }
    await new Promise((r) => setTimeout(r, 1_500));
  }
  if (!chain.length) throw new Error(`Empty VTXO chain for ${txid}:${vout}`);

  const nonCommit = chain.filter((c) => !String(c.type).toLowerCase().includes("commitment") && c.type !== 1);
  const vtxResp = await indexerProvider.getVirtualTxs(nonCommit.map((c) => c.txid));

  const rawByTxid = new Map();
  const txObjByTxid = new Map();
  for (const psbtB64 of vtxResp.txs) {
    const t = Transaction.fromPSBT(base64.decode(psbtB64), { allowUnknownInputs: true, allowUnknownOutputs: true });
    let hasTapKeyOnly = false;
    for (let i = 0; i < t.inputsLength; i++) {
      const inp = t.getInput(i);
      if (!inp.finalScriptWitness && inp.tapKeySig && !inp.witnessUtxo) {
        t.updateInput(i, { finalScriptWitness: [inp.tapKeySig] });
        hasTapKeyOnly = true;
      }
    }
    const rawHex = hasTapKeyOnly
      ? hex.encode(t.toBytes(true, true))
      : (t.isFinal || t.finalize(), hex.encode(t.extract()));
    rawByTxid.set(t.id, rawHex);
    txObjByTxid.set(t.id, t);
  }

  const ordered = [];
  const visited = new Set();
  function visit(id) {
    if (visited.has(id) || !txObjByTxid.has(id)) return;
    visited.add(id);
    const t = txObjByTxid.get(id);
    for (let i = 0; i < t.inputsLength; i++) {
      const prev = hex.encode(t.getInput(i).txid);
      if (txObjByTxid.has(prev)) visit(prev);
    }
    ordered.push(id);
  }
  for (const c of nonCommit) visit(c.txid);
  return ordered.map((id) => rawByTxid.get(id));
}

/**
 * Build a pre-signed timelocked onchain exit/refund transaction with a tiered
 * Taproot bounty output, ready to export as a keyless `ark-watchtower` package.
 */
export function buildOnchainExitTx({
  vtxoTxid,
  vtxoVout,
  vtxoAmountSats,
  contractScript,
  exitClosure,
  exitDelaySecs,
  userPubXOnly,
  lpPubXOnly,
  userAmtSats,
  lpAmtSats,
  bountyPkScript,
  bountyAmtSats,
  lockTime = 0,
}) {
  const csvSequence = (1 << 22) | Number(BigInt(exitDelaySecs) / 512n);
  const uDest = btc.p2tr(userPubXOnly, undefined, btc.TEST_NETWORK).script;
  const lDest = btc.p2tr(lpPubXOnly, undefined, btc.TEST_NETWORK).script;

  const exitTx = new btc.Transaction({ version: 2, lockTime });
  exitTx.addInput({ txid: vtxoTxid, index: vtxoVout, sequence: csvSequence });
  exitTx.addOutput({ script: uDest, amount: BigInt(userAmtSats) });
  exitTx.addOutput({ script: lDest, amount: BigInt(lpAmtSats) });
  exitTx.addOutput({ script: bountyPkScript, amount: BigInt(bountyAmtSats) });

  const sighash = exitTx.preimageWitnessV1(
    0,
    [contractScript.pkScript],
    btc.SigHash.DEFAULT,
    [BigInt(vtxoAmountSats)],
    -1,
    exitClosure.script,
    0xc0
  );
  const [exitCtrlObj] = contractScript.findLeaf(hex.encode(exitClosure.script));
  const exitCtrlBytes = btc.TaprootControlBlock.encode(exitCtrlObj);

  return {
    txHex: hex.encode(exitTx.toBytes(true, false)),
    sighash,
    exitCtrlHex: hex.encode(exitCtrlBytes),
    signWith: (key) => hex.encode(schnorrSign(key, sighash)),
    adaptorSignWith: (key, pointT) => hex.encode(adaptorSign(key, sighash, pointT)),
  };
}

/**
 * Build a complete `ark-watchtower`-compatible pre-signed exit suite (5 discrete
 * DLC outcome buckets + 1 timelocked refund tx), signed by `lpKey`.
 * The User independently verifies every output and attaches their matching adaptor/refund sigs.
 */
export function buildLpExitSuite({
  vtxoTxid,
  vtxoVout = 0,
  totalCollateralSats,
  notionalUsd,
  openSpotUsd,
  side = "short",
  contractScript,
  exitClosure,
  exitDelaySecs,
  userPubXOnly,
  lpKey,
  oraclePubHex,
  oracleEventId,
  announcement = null,
  watchtowerPubHex,
  refundLockTime,
  includeAdaptorPayouts = true,
  disputeSpec = null,
}) {
  const total = BigInt(totalCollateralSats);
  const dust = 350n;
  // Reserve a Taproot bounty >= 1000 sats (matches default Watchtower min_bounty_sats) when collateral allows
  const bountyAmt = total >= 4_000n ? 1_000n : total >= 2_500n ? 600n : 0n;
  const distributable = total - bountyAmt;
  const bountySpec = {
    amount_sats: Number(bountyAmt > 0n ? bountyAmt : 1_000n),
    vout: 2,
    primary_pubkey: watchtowerPubHex || lpKey.pubHex,
    backup_pubkeys: [],
    backup_csv: 4,
  };
  const { pkScript: bountyPkScript } = buildWatchtowerBountyScript(bountySpec);
  const effectiveOracleHex = announcement?.oraclePubkeyHex || oraclePubHex;
  const effectiveEventId = announcement?.eventId || oracleEventId;
  const oraclePubXOnly = hex.decode(effectiveOracleHex);
  const usesRealKind88 = Boolean(includeAdaptorPayouts && announcement?.noncesHex?.length >= 10);
  const prefixLen = 10;
  const numDigits = announcement?.numDigits || 20;

  const multipliers = includeAdaptorPayouts
    ? [
        { label: "spot-20pct", mult: 0.8 },
        { label: "spot-10pct", mult: 0.9 },
        { label: "spot-0pct", mult: 1.0 },
        { label: "spot+10pct", mult: 1.1 },
        { label: "spot+20pct", mult: 1.2 },
      ]
    : [];

  let exitCtrlHex = "";
  const payouts = [];
  const seenPrefixes = new Set();
  for (const { label, mult } of multipliers) {
    const settleSpot = Math.max(1, Math.round(openSpotUsd * mult));
    const fiatAmt = computeUsdPayoutSats(notionalUsd, settleSpot, distributable, dust);
    // "short" = Stable USD/EUR (user gets fixed fiat value); "long" = 2x Long BTC (user gets residual)
    const userAmt = side === "long" ? distributable - fiatAmt : fiatAmt;
    const lpAmt = distributable - userAmt;
    if (bountyAmt === 0n) continue;
    const outcome = usesRealKind88
      ? priceToBinaryPrefix(settleSpot, numDigits, prefixLen)
      : label;
    if (usesRealKind88 && seenPrefixes.has(outcome)) continue;
    seenPrefixes.add(outcome);

    const built = buildOnchainExitTx({
      vtxoTxid,
      vtxoVout,
      vtxoAmountSats: total,
      contractScript,
      exitClosure,
      exitDelaySecs,
      userPubXOnly,
      lpPubXOnly: lpKey.pubXOnly,
      userAmtSats: userAmt,
      lpAmtSats: lpAmt,
      bountyPkScript,
      bountyAmtSats: bountyAmt,
      lockTime: 0,
    });
    exitCtrlHex = built.exitCtrlHex;
    const pointT = usesRealKind88
      ? computeKormirOutcomePoint(oraclePubXOnly, announcement.noncesHex, outcome)
      : deriveOutcomeAdaptorPoint(oraclePubXOnly, effectiveEventId, outcome).point;
    payouts.push({
      outcome,
      settleSpotUsd: settleSpot,
      userAmtSats: Number(userAmt),
      lpAmtSats: Number(lpAmt),
      tx_hex: built.txHex,
      lp_adaptor_sig: built.adaptorSignWith(lpKey, pointT),
      user_adaptor_sig: "",
      precompleted: false,
    });
  }

  // Timelocked refund tx (returns initial 50/50 split minus bounty if all oracles disappear)
  let refund = null;
  if (bountyAmt > 0n) {
    const halfUser = distributable / 2n;
    const halfLp = distributable - halfUser;
    const refBuilt = buildOnchainExitTx({
      vtxoTxid,
      vtxoVout,
      vtxoAmountSats: total,
      contractScript,
      exitClosure,
      exitDelaySecs,
      userPubXOnly,
      lpPubXOnly: lpKey.pubXOnly,
      userAmtSats: halfUser,
      lpAmtSats: halfLp,
      bountyPkScript,
      bountyAmtSats: bountyAmt,
      lockTime: refundLockTime,
    });
    exitCtrlHex = refBuilt.exitCtrlHex;
    refund = {
      tx_hex: refBuilt.txHex,
      refund_height: refundLockTime,
      user_sig: "",
      lp_sig: refBuilt.signWith(lpKey),
    };
  }

  return {
    oracle_pubkey: effectiveOracleHex,
    oracle_event_id: effectiveEventId,
    usesRealKind88Nonces: usesRealKind88,
    announcementNoncesHex: usesRealKind88 ? announcement.noncesHex.slice(0, prefixLen) : null,
    announcementNumDigits: usesRealKind88 ? numDigits : null,
    exit_control_block: exitCtrlHex,
    exit_csv: 0,
    exit_csv_seconds: Number(exitDelaySecs),
    bounty: bountySpec,
    payouts,
    refund,
    dispute: disputeSpec,
  };
}

/**
 * Build an On-Demand Dispute payout transaction spent via Leaf 3 (`k-of-n` Nostracle
 * BIP-342 threshold Tapscript). Computes pro-rata yield/funding up to `disputeTimestamp`
 * and handles both mid-term anytime exits and early liquidation (>= 50% BTC drop).
 */
export function buildOnDemandDisputeTx({
  vtxoTxid,
  vtxoVout = 0,
  totalCollateralSats,
  notionalUsd,
  openedAt,
  disputeTimestamp,
  fundingRateBpsPerDay = 3,
  spotPriceAtDispute,
  side = "short",
  contractScript,
  disputeClosure,
  userPubXOnly,
  lpPubXOnly,
  bountyPkScript = null,
  bountyAmtSats = 0n,
}) {
  const total = BigInt(totalCollateralSats);
  const bounty = BigInt(bountyAmtSats || 0n);
  const dust = 350n;
  const distributable = total - bounty;
  if (distributable < dust * 2n) {
    throw new Error("Insufficient collateral after watchtower bounty");
  }

  const elapsedSecs = Math.max(0, Number(disputeTimestamp) - Number(openedAt));
  const accruedFiat =
    Number(notionalUsd) * (Number(fundingRateBpsPerDay) / 10_000) * (elapsedSecs / 86_400);

  let userAmt;
  let lpAmt;
  if (side === "long") {
    const lpTargetFiat = Math.max(0.01, Number(notionalUsd) - accruedFiat);
    lpAmt = computeUsdPayoutSats(lpTargetFiat, spotPriceAtDispute, distributable, dust);
    userAmt = distributable - lpAmt;
  } else {
    const userTargetFiat = Math.max(0.01, Number(notionalUsd) + accruedFiat);
    userAmt = computeUsdPayoutSats(userTargetFiat, spotPriceAtDispute, distributable, dust);
    lpAmt = distributable - userAmt;
  }

  const uDest = btc.p2tr(userPubXOnly, undefined, btc.TEST_NETWORK).script;
  const lDest = btc.p2tr(lpPubXOnly, undefined, btc.TEST_NETWORK).script;

  const tx = new btc.Transaction({ version: 2, lockTime: 0 });
  tx.addInput({ txid: vtxoTxid, index: vtxoVout, sequence: disputeClosure.csvSequence });
  tx.addOutput({ script: uDest, amount: userAmt });
  tx.addOutput({ script: lDest, amount: lpAmt });
  if (bounty > 0n && bountyPkScript) {
    tx.addOutput({ script: bountyPkScript, amount: bounty });
  }

  const sighash = tx.preimageWitnessV1(
    0,
    [contractScript.pkScript],
    btc.SigHash.DEFAULT,
    [total],
    -1,
    disputeClosure.script,
    0xc0
  );
  const [ctrlObj] = contractScript.findLeaf(disputeClosure.scriptHex);
  const ctrlBytes = btc.TaprootControlBlock.encode(ctrlObj);

  return {
    tx,
    txHex: hex.encode(tx.toBytes(true, false)),
    sighash,
    sighashHex: hex.encode(sighash),
    controlBlock: ctrlBytes,
    controlBlockHex: hex.encode(ctrlBytes),
    userAmtSats: Number(userAmt),
    lpAmtSats: Number(lpAmt),
    bountyAmtSats: Number(bounty),
    accruedFiat,
  };
}

/**
 * Assemble the final BIP-342 Tapscript witness for the `k-of-n` Nostracle Dispute Leaf.
 * `sigsByPubkeyHex` maps each signing oracle's x-only pubkey (64-hex) to its 64-byte Schnorr sig (128-hex).
 * Enforces `validCount >= threshold` and pushes signatures in reverse key order as required by OP_CHECKSIGADD.
 */
export function assembleDisputeWitness(disputeTx, disputeClosure, sigsByPubkeyHex) {
  const pubs = disputeClosure.oraclePubsHex;
  const witnessSigs = [];
  let validCount = 0;

  // BIP-342 OP_CHECKSIG / OP_CHECKSIGADD consumes stack items in reverse order of pubkeys in the script
  for (let i = pubs.length - 1; i >= 0; i--) {
    const pk = pubs[i];
    const sigHex = sigsByPubkeyHex[pk];
    if (sigHex) {
      const sigBytes = hex.decode(sigHex);
      if (sigBytes.length !== 64) {
        throw new Error(`Invalid Schnorr signature length for oracle ${pk.slice(0, 8)}`);
      }
      witnessSigs.push(sigBytes);
      validCount++;
    } else {
      witnessSigs.push(new Uint8Array(0)); // empty push fails OP_CHECKSIG(ADD) cleanly with 0
    }
  }

  if (validCount < disputeClosure.threshold) {
    throw new Error(
      `Insufficient Nostracle signatures: got ${validCount}, need at least ${disputeClosure.threshold}-of-${pubs.length}`
    );
  }

  const finalWitness = [...witnessSigs, disputeClosure.script, disputeTx.controlBlock];
  const finalized = btc.Transaction.fromRaw(hex.decode(disputeTx.txHex), {
    allowUnknownInputs: true,
    allowUnknownOutputs: true,
  });
  finalized.updateInput(0, { finalScriptWitness: finalWitness });
  const rawSignedHex = hex.encode(finalized.toBytes(true, true));
  return {
    rawSignedHex,
    witnessStack: finalWitness,
    signedCount: validCount,
    threshold: disputeClosure.threshold,
    totalOracles: pubs.length,
  };
}
