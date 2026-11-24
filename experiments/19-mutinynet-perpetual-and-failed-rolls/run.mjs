/**
 * Experiment 19: Perpetual DLC terms (funding payment at roll, ±25% liquidation
 * floor, collaborative early close) + Failed roll recovery (quorum member
 * dropout mid-signing -> fallback quorum succeeds) LIVE on `https://mutinynet.arkade.sh`.
 *
 * Scenarios:
 * A. Failed roll: quorum {N0, N1, N2} attempts roll, N2 drops out (bad/missing sig)
 *    -> rejected by mutinynet.arkade.sh; VTXO #1 stays untouched & spendable.
 * B. Fallback roll + funding payment: quorum {N0, N1, N3} rolls VTXO #1 (4,000 sats)
 *    into VTXO #2 (3,500 sats) while paying a 500-sat funding/carry output to User.
 * C. Liquidation at ±25% band: oracle attests $72,000 (below $75,000 floor) ->
 *    rolled VTXO #2 settles via liquidation prefix (User 3,100 sats, LP 400 sats).
 * D. Collaborative early close: user comes online on VTXO #3 (4,000 sats) and
 *    closes immediately via the 3-of-3 user settle leaf without oracle or quorum.
 */

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import {
  Wallet,
  SingleKey,
  Ramps,
  RestArkProvider,
  RestIndexerProvider,
  EsploraProvider,
  InMemoryWalletRepository,
  InMemoryContractRepository,
  VtxoScript,
  MultisigTapscript,
  CSVMultisigTapscript,
  CLTVMultisigTapscript,
  DefaultVtxo,
  buildOffchainTx,
  combineTapscriptSigs,
  Transaction,
  toXOnly,
} from "@arkade-os/sdk";
import * as btc from "@scure/btc-signer";
import { hex, base64 } from "@scure/base";
import { schnorr } from "@noble/curves/secp256k1.js";

const ARK_URL = "https://mutinynet.arkade.sh";
const ESPLORA_URL = "https://mutinynet.com/api";
const BOARD_AMOUNT = 10_000n;
const CONTRACT_AMOUNT = 4_000;
const FUNDING_PAYMENT = 500n; // above Arkade dust (330 sats)
const ROLLED_AMOUNT = BigInt(CONTRACT_AMOUNT) - FUNDING_PAYMENT; // 3,500 sats
const NUM_DIGITS = 20;

const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const G = schnorr.Point.BASE;

function sha256(...parts) {
  const h = crypto.createHash("sha256");
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
}

function taggedHash(tag, ...parts) {
  const th = sha256(Buffer.from(tag, "utf8"));
  return sha256(th, th, ...parts);
}

function bytesToBigInt(b) {
  return BigInt("0x" + hex.encode(b));
}

function bigIntToBytes32(n) {
  const mod = ((n % N) + N) % N;
  return hex.decode(mod.toString(16).padStart(64, "0"));
}

function pointToXOnly(pt) {
  const { x } = pt.toAffine();
  return hex.decode(x.toString(16).padStart(64, "0"));
}

function hasEvenY(pt) {
  return (pt.toAffine().y & 1n) === 0n;
}

function randomEvenKey() {
  while (true) {
    const priv = crypto.randomBytes(32);
    let d = bytesToBigInt(priv);
    if (d <= 0n || d >= N) continue;
    let pt = G.multiply(d);
    if (!hasEvenY(pt)) {
      d = N - d;
      pt = G.multiply(d);
    }
    return { d, privBytes: bigIntToBytes32(d), pubXOnly: pointToXOnly(pt), point: pt };
  }
}

class NumericOracle {
  constructor(numDigits) {
    this.key = randomEvenKey();
    this.nonces = Array.from({ length: numDigits }, () => randomEvenKey());
  }
  digitChallenge(i, bitStr) {
    const m = taggedHash("DLC/oracle/attestation/v0", Buffer.from(bitStr, "utf8"));
    return bytesToBigInt(taggedHash("BIP0340/challenge", this.nonces[i].pubXOnly, this.key.pubXOnly, m)) % N;
  }
  prefixAnticipationPoint(prefixBits) {
    let acc = null;
    for (let i = 0; i < prefixBits.length; i++) {
      const e = this.digitChallenge(i, prefixBits[i]);
      const si = this.nonces[i].point.add(this.key.point.multiply(e));
      acc = acc ? acc.add(si) : si;
    }
    return acc;
  }
  attestPrice(priceInt) {
    const bits = priceInt.toString(2).padStart(this.nonces.length, "0");
    const scalars = [];
    for (let i = 0; i < bits.length; i++) {
      const e = this.digitChallenge(i, bits[i]);
      scalars.push((this.nonces[i].d + e * this.key.d) % N);
    }
    return { bits, scalars };
  }
}

function sumPrefixScalars(scalars, prefixLen) {
  let acc = 0n;
  for (let i = 0; i < prefixLen; i++) acc = (acc + scalars[i]) % N;
  return acc;
}

function schnorrSign(signer, msg32) {
  while (true) {
    const k = bytesToBigInt(crypto.randomBytes(32));
    if (k <= 0n || k >= N) continue;
    const R = G.multiply(k);
    if (!hasEvenY(R)) continue;
    const rx = pointToXOnly(R);
    const e = bytesToBigInt(taggedHash("BIP0340/challenge", rx, signer.pubXOnly, msg32)) % N;
    const s = (k + e * signer.d) % N;
    const sig = new Uint8Array(64);
    sig.set(rx, 0);
    sig.set(bigIntToBytes32(s), 32);
    return sig;
  }
}

function adaptorSign(signer, msg32, T) {
  while (true) {
    const k = bytesToBigInt(crypto.randomBytes(32));
    if (k <= 0n || k >= N) continue;
    const R = G.multiply(k).add(T);
    if (!hasEvenY(R)) continue;
    const rx = pointToXOnly(R);
    const e = bytesToBigInt(taggedHash("BIP0340/challenge", rx, signer.pubXOnly, msg32)) % N;
    const sPrime = (k + e * signer.d) % N;
    return { rx, sPrime };
  }
}

function completeAdaptor(ad, oracleScalar) {
  const s = (ad.sPrime + oracleScalar) % N;
  const sig = new Uint8Array(64);
  sig.set(ad.rx, 0);
  sig.set(bigIntToBytes32(s), 32);
  return sig;
}

function encodeVarBytes(b) {
  if (b.length < 0xfd) return Uint8Array.from([b.length, ...b]);
  if (b.length <= 0xffff) return Uint8Array.from([0xfd, b.length & 0xff, (b.length >> 8) & 0xff, ...b]);
  throw new Error("script too long");
}

function tapLeafHash(leafScript) {
  return taggedHash("TapLeaf", new Uint8Array([0xc0]), encodeVarBytes(leafScript));
}

function tapscriptSighash(psbtTx, inputIdx, prevScript, prevAmount, leafScript) {
  return psbtTx.preimageWitnessV1(inputIdx, [prevScript], btc.SigHash.DEFAULT, [prevAmount], -1, leafScript, 0xc0);
}

function attachTapscriptSigs(psbtTx, leafHash, entries) {
  const inp = psbtTx.getInput(0);
  const existing = inp.tapScriptSig ? [...inp.tapScriptSig] : [];
  for (const [pubXOnly, sig] of entries) {
    existing.push([{ pubKey: pubXOnly, leafHash }, sig]);
  }
  psbtTx.updateInput(0, { tapScriptSig: existing });
}

function subsetsOf3(n = 5) {
  const out = [];
  for (let i = 0; i < n; i++)
    for (let j = i + 1; j < n; j++)
      for (let k = j + 1; k < n; k++) out.push([i, j, k]);
  return out;
}

function buildDesign3Script(userPub, lpPub, nostracles, serverXOnly, exitDelaySecs, rollCltv) {
  const userSettle = MultisigTapscript.encode({ pubkeys: [userPub, lpPub, serverXOnly] });
  const userExit = CSVMultisigTapscript.encode({
    timelock: { type: "seconds", value: exitDelaySecs },
    pubkeys: [userPub, lpPub],
  });
  const quorumSettle = new Map();
  const quorumExit = new Map();
  const scripts = [userSettle.script, userExit.script];

  for (const combo of subsetsOf3(nostracles.length)) {
    const qPubs = combo.map((idx) => nostracles[idx].pubXOnly);
    const qs = CLTVMultisigTapscript.encode({
      absoluteTimelock: rollCltv,
      pubkeys: [...qPubs, lpPub, serverXOnly],
    });
    const qe = CSVMultisigTapscript.encode({
      timelock: { type: "seconds", value: exitDelaySecs * 2n },
      pubkeys: [...qPubs, lpPub],
    });
    quorumSettle.set(combo.join(","), qs);
    quorumExit.set(combo.join(","), qe);
    scripts.push(qs.script, qe.script);
  }
  return { vtxoScript: new VtxoScript(scripts), userSettle, userExit, quorumSettle, quorumExit };
}

async function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function waitForVtxo(indexerProvider, pkHex, expectedTxid) {
  for (let i = 0; i < 20; i++) {
    const res = await indexerProvider.getVtxos({ scripts: [pkHex], spendableOnly: true });
    const found = res.vtxos?.find((v) => !expectedTxid || v.txid === expectedTxid);
    if (found) return found;
    await sleep(1_500);
  }
  throw new Error(`VTXO not indexed for ${pkHex}`);
}

async function main() {
  console.log("=== Experiment 19: Perpetual Terms + Failed Roll Recovery on Live Arkade Mutinynet ===");
  const arkProvider = new RestArkProvider(ARK_URL);
  const indexerProvider = new RestIndexerProvider(ARK_URL);
  const onchainProvider = new EsploraProvider(ESPLORA_URL);

  const info = await arkProvider.getInfo();
  const serverXOnly = toXOnly(hex.decode(info.signerPubkey));
  const exitDelaySecs = BigInt(info.unilateralExitDelay);
  const checkpointTapscript = CSVMultisigTapscript.decode(hex.decode(info.checkpointTapscript));
  console.log(`Connected to ${ARK_URL} (network=${info.network}, exitDelay=${exitDelaySecs}s)`);

  // Board 10,000 sats from our Mutinynet L1 wallet into a clean ephemeral funder wallet.
  const wtKeyPath = path.resolve(import.meta.dirname, "../../watchtower/data/mutinynet-wt.key");
  const l1Priv = hex.decode(fs.readFileSync(wtKeyPath, "utf8").trim());
  const wallet = await Wallet.create({
    identity: SingleKey.fromRandomBytes(),
    arkProvider,
    indexerProvider,
    onchainProvider,
    settlementConfig: false,
    storage: {
      walletRepository: new InMemoryWalletRepository(),
      contractRepository: new InMemoryContractRepository(),
    },
  });

  const boardingAddr = await wallet.getBoardingAddress();
  const p2tr = btc.p2tr(toXOnly(schnorr.getPublicKey(l1Priv)), undefined, btc.TEST_NETWORK);
  const utxos = await (await fetch(`${ESPLORA_URL}/address/${p2tr.address}/utxo`)).json();
  const confirmed = utxos.filter((u) => u.status?.confirmed).sort((a, b) => b.value - a.value);
  const fee = 500n;
  const selected = [];
  let totalIn = 0n;
  for (const u of confirmed) {
    selected.push(u);
    totalIn += BigInt(u.value);
    if (totalIn >= BOARD_AMOUNT + fee + 600n) break;
  }
  if (totalIn < BOARD_AMOUNT + fee) throw new Error(`Insufficient L1 funds at ${p2tr.address}: ${totalIn}`);

  const btx = new btc.Transaction();
  for (const u of selected) {
    btx.addInput({
      txid: u.txid,
      index: u.vout,
      witnessUtxo: { script: p2tr.script, amount: BigInt(u.value) },
      tapInternalKey: p2tr.tapInternalKey,
    });
  }
  btx.addOutputAddress(boardingAddr, BOARD_AMOUNT, btc.TEST_NETWORK);
  if (totalIn - BOARD_AMOUNT - fee > 546n) {
    btx.addOutputAddress(p2tr.address, totalIn - BOARD_AMOUNT - fee, btc.TEST_NETWORK);
  }
  btx.sign(l1Priv);
  btx.finalize();
  const bRes = await fetch(`${ESPLORA_URL}/tx`, { method: "POST", body: hex.encode(btx.extract()) });
  if (!bRes.ok) throw new Error(`Boarding tx failed: ${await bRes.text()}`);
  const boardingTxid = (await bRes.text()).trim();
  console.log(`\n[Setup] L1 boarding tx (${BOARD_AMOUNT} sats): https://mutinynet.com/tx/${boardingTxid}`);
  while (true) {
    const st = await (await fetch(`${ESPLORA_URL}/tx/${boardingTxid}/status`)).json();
    if (st.confirmed) break;
    await sleep(10_000);
  }
  const commitTxid = await new Ramps(wallet).onboard(info.fees);
  console.log(`  Onboarded batch commitment tx: https://mutinynet.com/tx/${commitTxid}`);
  await sleep(3_000);

  const user = randomEvenKey();
  const lp = randomEvenKey();
  const nostracles = Array.from({ length: 5 }, () => randomEvenKey());
  const oracle = new NumericOracle(NUM_DIGITS);
  const maturedCltv = BigInt(Math.floor(Date.now() / 1000) - 3600);

  const userArkScript = new DefaultVtxo.Script({
    pubKey: user.pubXOnly,
    serverPubKey: serverXOnly,
    csvTimelock: { type: "seconds", value: exitDelaySecs },
  });
  const lpArkScript = new DefaultVtxo.Script({
    pubKey: lp.pubXOnly,
    serverPubKey: serverXOnly,
    csvTimelock: { type: "seconds", value: exitDelaySecs },
  });

  // =========================================================================
  // SCENARIO A: Failed roll (quorum member N2 drops out mid-signing)
  // =========================================================================
  console.log("\n[Scenario A] Opening VTXO #1 (4,000 sats) & simulating N2 dropout mid-roll...");
  const c1 = buildDesign3Script(user.pubXOnly, lp.pubXOnly, nostracles, serverXOnly, exitDelaySecs, maturedCltv);
  const c1PkHex = hex.encode(c1.vtxoScript.pkScript);
  const open1Txid = await wallet.send({
    address: c1.vtxoScript.address("tark", serverXOnly).encode(),
    amount: CONTRACT_AMOUNT,
  });
  const vtxo1 = await waitForVtxo(indexerProvider, c1PkHex, open1Txid);
  console.log(`  Opened VTXO #1: ${vtxo1.txid}:${vtxo1.vout} (${vtxo1.value} sats)`);

  // Attempt roll with {N0, N1, N2} + LP, but N2 drops out (only N0, N1, LP sign -> missing N2 sig!).
  const c2 = buildDesign3Script(user.pubXOnly, lp.pubXOnly, nostracles, serverXOnly, exitDelaySecs, maturedCltv - 60n);
  const c2PkHex = hex.encode(c2.vtxoScript.pkScript);
  const badClosure = c1.quorumSettle.get("0,1,2");
  const badLeaf = c1.vtxoScript.findLeaf(hex.encode(badClosure.script));
  const badLeafHash = tapLeafHash(badClosure.script);

  const { arkTx: failArkTx, checkpoints: failCks } = buildOffchainTx(
    [
      {
        txid: vtxo1.txid,
        vout: vtxo1.vout,
        value: Number(vtxo1.value),
        tapLeafScript: badLeaf,
        tapTree: c1.vtxoScript.encode(),
      },
    ],
    [
      { script: c2.vtxoScript.pkScript, amount: ROLLED_AMOUNT },
      { script: userArkScript.pkScript, amount: FUNDING_PAYMENT },
    ],
    checkpointTapscript
  );
  const failCkOut0 = failCks[0].getOutput(0);
  const failArkHash = tapscriptSighash(failArkTx, 0, failCkOut0.script, failCkOut0.amount, badClosure.script);
  // N2 dropped out: only N0, N1, LP signed!
  attachTapscriptSigs(
    failArkTx,
    badLeafHash,
    [nostracles[0], nostracles[1], lp].map((s) => [s.pubXOnly, schnorrSign(s, failArkHash)])
  );

  let failedAsExpected = false;
  try {
    await arkProvider.submitTx(base64.encode(failArkTx.toPSBT()), [base64.encode(failCks[0].toPSBT())]);
  } catch (err) {
    failedAsExpected = true;
    console.log(`  Dropout roll REJECTED as expected by mutinynet.arkade.sh: ${err.message}`);
  }
  if (!failedAsExpected) throw new Error("Incomplete quorum roll should have been rejected!");

  // Verify VTXO #1 is still intact and spendable on live indexer!
  const stillLive = await waitForVtxo(indexerProvider, c1PkHex, vtxo1.txid);
  console.log(`  Verified VTXO #1 still intact & spendable after failed roll: ${stillLive.txid}:${stillLive.vout}`);

  // =========================================================================
  // SCENARIO B: Fallback quorum {N0, N1, N3} rolls VTXO #1 -> VTXO #2 + 500-sat funding payment
  // =========================================================================
  console.log("\n[Scenario B] Fallback quorum {N0, N1, N3} rolls VTXO #1 -> VTXO #2 (3,500) + funding payment (500 to User)...");
  const fbClosure = c1.quorumSettle.get("0,1,3");
  const fbLeaf = c1.vtxoScript.findLeaf(hex.encode(fbClosure.script));
  const fbLeafHash = tapLeafHash(fbClosure.script);
  const fbSigners = [nostracles[0], nostracles[1], nostracles[3], lp];

  const { arkTx: rollArkTx, checkpoints: rollCks } = buildOffchainTx(
    [
      {
        txid: vtxo1.txid,
        vout: vtxo1.vout,
        value: Number(vtxo1.value),
        tapLeafScript: fbLeaf,
        tapTree: c1.vtxoScript.encode(),
      },
    ],
    [
      { script: c2.vtxoScript.pkScript, amount: ROLLED_AMOUNT },
      { script: userArkScript.pkScript, amount: FUNDING_PAYMENT },
    ],
    checkpointTapscript
  );
  const rollCk = rollCks[0];
  const rollCkHash = tapscriptSighash(rollCk, 0, c1.vtxoScript.pkScript, BigInt(vtxo1.value), fbClosure.script);
  const rollCkOut0 = rollCk.getOutput(0);
  const rollArkHash = tapscriptSighash(rollArkTx, 0, rollCkOut0.script, rollCkOut0.amount, fbClosure.script);

  attachTapscriptSigs(rollArkTx, fbLeafHash, fbSigners.map((s) => [s.pubXOnly, schnorrSign(s, rollArkHash)]));
  const rollSub = await arkProvider.submitTx(base64.encode(rollArkTx.toPSBT()), [base64.encode(rollCk.toPSBT())]);
  const serverRollCk = Transaction.fromPSBT(base64.decode(rollSub.signedCheckpointTxs[0]));
  attachTapscriptSigs(rollCk, fbLeafHash, fbSigners.map((s) => [s.pubXOnly, schnorrSign(s, rollCkHash)]));
  const finalRollCk = combineTapscriptSigs(rollCk, serverRollCk);
  await arkProvider.finalizeTx(rollSub.arkTxid, [base64.encode(finalRollCk.toPSBT())]);

  const vtxo2 = await waitForVtxo(indexerProvider, c2PkHex, rollSub.arkTxid);
  const fundingVtxo = await waitForVtxo(indexerProvider, hex.encode(userArkScript.pkScript), rollSub.arkTxid);
  console.log(`  Fallback roll ACCEPTED! arkTxid = ${rollSub.arkTxid}`);
  console.log(`  Rolled VTXO #2  : ${vtxo2.txid}:${vtxo2.vout} (${vtxo2.value} sats)`);
  console.log(`  Funding payment : ${fundingVtxo.txid}:${fundingVtxo.vout} (${fundingVtxo.value} sats -> User)`);

  // =========================================================================
  // SCENARIO C: Automatic liquidation at ±25% band boundary ($72,000 <= $75,000 floor)
  // =========================================================================
  console.log("\n[Scenario C] Automatic liquidation on rolled VTXO #2 at $72,000 (below $75,000 floor)...");
  // 20-bit binary of $72,000 = 00010001100101000000; 7-bit prefix "0001000" covers [$65,536..$73,727] (liquidation band!)
  const liqPrefix = "0001000";
  const liqT = oracle.prefixAnticipationPoint(liqPrefix);
  const liqClosure = c2.quorumSettle.get("0,1,3");
  const liqLeaf = c2.vtxoScript.findLeaf(hex.encode(liqClosure.script));
  const liqLeafHash = tapLeafHash(liqClosure.script);

  const { arkTx: liqArkTx, checkpoints: liqCks } = buildOffchainTx(
    [
      {
        txid: vtxo2.txid,
        vout: vtxo2.vout,
        value: Number(vtxo2.value),
        tapLeafScript: liqLeaf,
        tapTree: c2.vtxoScript.encode(),
      },
    ],
    [
      { script: userArkScript.pkScript, amount: 3_100n },
      { script: lpArkScript.pkScript, amount: 400n },
    ],
    checkpointTapscript
  );
  const liqCk = liqCks[0];
  const liqCkHash = tapscriptSighash(liqCk, 0, c2.vtxoScript.pkScript, BigInt(vtxo2.value), liqClosure.script);
  const liqCkOut0 = liqCk.getOutput(0);
  const liqArkHash = tapscriptSighash(liqArkTx, 0, liqCkOut0.script, liqCkOut0.amount, liqClosure.script);

  const liqArkAd = fbSigners.map((s) => [s.pubXOnly, adaptorSign(s, liqArkHash, liqT)]);
  const liqCkAd = fbSigners.map((s) => [s.pubXOnly, adaptorSign(s, liqCkHash, liqT)]);

  const liqAtt = oracle.attestPrice(72_000);
  if (!liqAtt.bits.startsWith(liqPrefix)) throw new Error("Prefix mismatch");
  const liqScalar = sumPrefixScalars(liqAtt.scalars, liqPrefix.length);

  attachTapscriptSigs(liqArkTx, liqLeafHash, liqArkAd.map(([pub, ad]) => [pub, completeAdaptor(ad, liqScalar)]));
  const liqSub = await arkProvider.submitTx(base64.encode(liqArkTx.toPSBT()), [base64.encode(liqCk.toPSBT())]);
  const serverLiqCk = Transaction.fromPSBT(base64.decode(liqSub.signedCheckpointTxs[0]));
  attachTapscriptSigs(liqCk, liqLeafHash, liqCkAd.map(([pub, ad]) => [pub, completeAdaptor(ad, liqScalar)]));
  const finalLiqCk = combineTapscriptSigs(liqCk, serverLiqCk);
  await arkProvider.finalizeTx(liqSub.arkTxid, [base64.encode(finalLiqCk.toPSBT())]);
  console.log(`  Liquidation settled! arkTxid = ${liqSub.arkTxid} (User 3,100 sats, LP 400 sats)`);

  // =========================================================================
  // SCENARIO D: Collaborative early close (user online, no oracle or quorum needed)
  // =========================================================================
  console.log("\n[Scenario D] Opening VTXO #3 (4,000 sats) & executing collaborative early close (User + LP + Server)...");
  const c3 = buildDesign3Script(user.pubXOnly, lp.pubXOnly, nostracles, serverXOnly, exitDelaySecs, maturedCltv - 120n);
  const c3PkHex = hex.encode(c3.vtxoScript.pkScript);
  const open3Txid = await wallet.send({
    address: c3.vtxoScript.address("tark", serverXOnly).encode(),
    amount: CONTRACT_AMOUNT,
  });
  const vtxo3 = await waitForVtxo(indexerProvider, c3PkHex, open3Txid);
  console.log(`  Opened VTXO #3: ${vtxo3.txid}:${vtxo3.vout} (${vtxo3.value} sats)`);

  const uCloseLeaf = c3.vtxoScript.findLeaf(hex.encode(c3.userSettle.script));
  const uCloseLeafHash = tapLeafHash(c3.userSettle.script);
  const { arkTx: closeArkTx, checkpoints: closeCks } = buildOffchainTx(
    [
      {
        txid: vtxo3.txid,
        vout: vtxo3.vout,
        value: Number(vtxo3.value),
        tapLeafScript: uCloseLeaf,
        tapTree: c3.vtxoScript.encode(),
      },
    ],
    [
      { script: userArkScript.pkScript, amount: 1_900n },
      { script: lpArkScript.pkScript, amount: 2_100n },
    ],
    checkpointTapscript
  );
  const closeCk = closeCks[0];
  const closeCkHash = tapscriptSighash(closeCk, 0, c3.vtxoScript.pkScript, BigInt(vtxo3.value), c3.userSettle.script);
  const closeCkOut0 = closeCk.getOutput(0);
  const closeArkHash = tapscriptSighash(closeArkTx, 0, closeCkOut0.script, closeCkOut0.amount, c3.userSettle.script);

  attachTapscriptSigs(closeArkTx, uCloseLeafHash, [user, lp].map((s) => [s.pubXOnly, schnorrSign(s, closeArkHash)]));
  const closeSub = await arkProvider.submitTx(base64.encode(closeArkTx.toPSBT()), [base64.encode(closeCk.toPSBT())]);
  const serverCloseCk = Transaction.fromPSBT(base64.decode(closeSub.signedCheckpointTxs[0]));
  attachTapscriptSigs(closeCk, uCloseLeafHash, [user, lp].map((s) => [s.pubXOnly, schnorrSign(s, closeCkHash)]));
  const finalCloseCk = combineTapscriptSigs(closeCk, serverCloseCk);
  await arkProvider.finalizeTx(closeSub.arkTxid, [base64.encode(finalCloseCk.toPSBT())]);
  console.log(`  Collaborative early close ACCEPTED! arkTxid = ${closeSub.arkTxid} (User 1,900 sats, LP 2,100 sats)`);

  await sleep(2_000);
  const uAll = (await indexerProvider.getVtxos({ scripts: [hex.encode(userArkScript.pkScript)], spendableOnly: true })).vtxos;
  const lAll = (await indexerProvider.getVtxos({ scripts: [hex.encode(lpArkScript.pkScript)], spendableOnly: true })).vtxos;
  const uTotal = uAll.reduce((s, v) => s + Number(v.value), 0);
  const lTotal = lAll.reduce((s, v) => s + Number(v.value), 0);
  console.log(`\nFinal live balances on mutinynet.arkade.sh:`);
  console.log(`  User total: ${uTotal} sats (expected 500 funding + 3,100 liquidation + 1,900 early close = 5,500)`);
  console.log(`  LP total  : ${lTotal} sats (expected 400 liquidation + 2,100 early close = 2,500)`);
  if (uTotal !== 5_500 || lTotal !== 2_500) throw new Error("Final payout totals mismatch!");

  console.log("\n=== EXPERIMENT 19 RESULT: SUCCESS ===");
  await wallet.dispose?.();
  process.exit(0);
}

main().catch((err) => {
  console.error("EXPERIMENT 19 FAILED:", err);
  process.exit(1);
});
