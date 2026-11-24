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
import { schnorrSign } from "./crypto.mjs";

/**
 * Build a Design 1 Arkade DLC VtxoScript compatible with live `mutinynet.arkade.sh`
 * (time-based `CSV(unilateralExitDelay)` on the exit leaf).
 */
export function buildDlcContractScript(userPubXOnly, lpPubXOnly, serverXOnly, exitDelaySecs) {
  const settleClosure = MultisigTapscript.encode({
    pubkeys: [userPubXOnly, lpPubXOnly, serverXOnly],
  });
  const exitClosure = CSVMultisigTapscript.encode({
    timelock: { type: "seconds", value: BigInt(exitDelaySecs) },
    pubkeys: [userPubXOnly, lpPubXOnly],
  });
  const vtxoScript = new VtxoScript([settleClosure.script, exitClosure.script]);
  return { vtxoScript, settleClosure, exitClosure };
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
  };
}
