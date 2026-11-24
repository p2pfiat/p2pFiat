/**
 * Experiment 17: Live Design 3 (22-path Tapscript quorum rolling DLC + 20-bit
 * numeric DLC settlement) on the unmodified public Arkade Mutinynet operator
 * (`https://mutinynet.arkade.sh`).
 *
 * Proves on a live public Arkade server:
 * 1. Opening a 22-path Design 3 contract VTXO:
 *      - 1 user settle leaf (user + LP + server)
 *      - 1 user exit leaf (CSV 2048s + user + LP)
 *      - 10 quorum roll/settle leaves (3-of-5 nostracles + LP + server, CLTV)
 *      - 10 quorum exit leaves (CSV 4096s + 3-of-5 nostracles + LP)
 * 2. Wiping the user's private key completely (user offline).
 * 3. Quorum {N0, N1, N2} + LP rolling VTXO #1 into a fresh 22-path VTXO #2
 *    offchain on `mutinynet.arkade.sh` (via CLTVMultisigTapscript).
 * 4. Adaptor-signing a 20-bit numeric DLC (binary prefix decomposition) on
 *    rolled VTXO #2, attesting $91,420 (20 BIP-340 digit signatures), and
 *    settling the winning prefix offchain on live `mutinynet.arkade.sh`.
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
const CONTRACT_AMOUNT = 4_500;
const ATTESTED_PRICE = 91_420; // $91,420 (20-bit binary: 00010110010100011100)
const NUM_DIGITS = 20;

// secp256k1 curve order & generator
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

/** 20-bit numeric DLC oracle (kormir-compatible `DLC/oracle/attestation/v0` digit signatures). */
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

/** Generate all C(5,3) = 10 three-element subsets of [0,1,2,3,4]. */
function subsetsOf3(n = 5) {
  const out = [];
  for (let i = 0; i < n; i++)
    for (let j = i + 1; j < n; j++)
      for (let k = j + 1; k < n; k++) out.push([i, j, k]);
  return out;
}

/**
 * Build the 22-path Design 3 VtxoScript (matching Experiment 4 & 14, adapted to
 * Arkade Mutinynet's time-based unilateralExitDelay).
 */
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
    const key = combo.join(",");
    quorumSettle.set(key, qs);
    quorumExit.set(key, qe);
    scripts.push(qs.script, qe.script);
  }

  return {
    vtxoScript: new VtxoScript(scripts),
    userSettle,
    userExit,
    quorumSettle,
    quorumExit,
  };
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
  console.log("=== Experiment 17: Live 22-path Design 3 Quorum Roll + 20-bit Numeric DLC on Mutinynet ===");
  const arkProvider = new RestArkProvider(ARK_URL);
  const indexerProvider = new RestIndexerProvider(ARK_URL);
  const onchainProvider = new EsploraProvider(ESPLORA_URL);

  const info = await arkProvider.getInfo();
  const serverXOnly = toXOnly(hex.decode(info.signerPubkey));
  const exitDelaySecs = BigInt(info.unilateralExitDelay);
  const checkpointTapscript = CSVMultisigTapscript.decode(hex.decode(info.checkpointTapscript));
  console.log(`Connected to ${ARK_URL} (network=${info.network}, exitDelay=${exitDelaySecs}s)`);

  // Load our funded Mutinynet key (still has 5,000 settled Arkade sats from Experiment 16!).
  const keyPath = path.resolve(import.meta.dirname, "../../watchtower/data/mutinynet-wt.key");
  const funderHex = fs.readFileSync(keyPath, "utf8").trim();
  const wallet = await Wallet.create({
    identity: SingleKey.fromHex(funderHex),
    arkProvider,
    indexerProvider,
    onchainProvider,
    settlementConfig: false,
    storage: {
      walletRepository: new InMemoryWalletRepository(),
      contractRepository: new InMemoryContractRepository(),
    },
  });

  let bal = await wallet.getBalance();
  console.log(`Funder Arkade balance: available=${bal.available} sats`);
  if (BigInt(bal.available) < BigInt(CONTRACT_AMOUNT)) {
    const boardAmt = 6_000n;
    const boardingAddr = await wallet.getBoardingAddress();
    console.log(`  Boarding ${boardAmt} sats from Mutinynet L1 to ${boardingAddr}...`);
    const funderPriv = hex.decode(funderHex);
    const p2tr = btc.p2tr(toXOnly(schnorr.getPublicKey(funderPriv)), undefined, btc.TEST_NETWORK);
    const utxos = await (await fetch(`${ESPLORA_URL}/address/${p2tr.address}/utxo`)).json();
    const confirmed = utxos.filter((u) => u.status?.confirmed).sort((a, b) => b.value - a.value);
    const fee = 500n;
    const selected = [];
    let totalIn = 0n;
    for (const u of confirmed) {
      selected.push(u);
      totalIn += BigInt(u.value);
      if (totalIn >= boardAmt + fee + 600n) break;
    }
    if (totalIn < boardAmt + fee) throw new Error(`Insufficient L1 sats at ${p2tr.address}`);
    const tx = new btc.Transaction();
    for (const u of selected) {
      tx.addInput({
        txid: u.txid,
        index: u.vout,
        witnessUtxo: { script: p2tr.script, amount: BigInt(u.value) },
        tapInternalKey: p2tr.tapInternalKey,
      });
    }
    tx.addOutputAddress(boardingAddr, boardAmt, btc.TEST_NETWORK);
    if (totalIn - boardAmt - fee > 546n) tx.addOutputAddress(p2tr.address, totalIn - boardAmt - fee, btc.TEST_NETWORK);
    tx.sign(funderPriv);
    tx.finalize();
    const bRes = await fetch(`${ESPLORA_URL}/tx`, { method: "POST", body: hex.encode(tx.extract()) });
    if (!bRes.ok) throw new Error(`Boarding broadcast failed: ${await bRes.text()}`);
    const boardingTxid = (await bRes.text()).trim();
    console.log(`  L1 boarding tx: https://mutinynet.com/tx/${boardingTxid}`);
    while (true) {
      const st = await (await fetch(`${ESPLORA_URL}/tx/${boardingTxid}/status`)).json();
      if (st.confirmed) break;
      await sleep(10_000);
    }
    const onboardTxid = await new Ramps(wallet).onboard(info.fees);
    console.log(`  Onboarded batch commitment tx: https://mutinynet.com/tx/${onboardTxid}`);
    await sleep(3_000);
    bal = await wallet.getBalance();
    console.log(`  Arkade balance after onboard: available=${bal.available} sats`);
  }

  // Create User, LP, 5 independent nostracles (N0..N4), and a 20-bit numeric DLC oracle.
  const user = randomEvenKey();
  const lp = randomEvenKey();
  const nostracles = Array.from({ length: 5 }, () => randomEvenKey());
  const oracle = new NumericOracle(NUM_DIGITS);

  // Use a matured CLTV unix timestamp (1 hour in the past) so the live quorum roll executes immediately.
  const maturedCltv = BigInt(Math.floor(Date.now() / 1000) - 3600);

  // 1. Open 22-path Design 3 Contract VTXO #1 on live mutinynet.arkade.sh.
  console.log("\n[1/4] Opening 22-path Design 3 contract VTXO #1 on mutinynet.arkade.sh...");
  const c1 = buildDesign3Script(user.pubXOnly, lp.pubXOnly, nostracles, serverXOnly, exitDelaySecs, maturedCltv);
  console.log(`  Tapscript leaves: ${c1.vtxoScript.scripts.length} (expected 22)`);
  const c1Addr = c1.vtxoScript.address("tark", serverXOnly).encode();
  const c1PkHex = hex.encode(c1.vtxoScript.pkScript);
  const openTxid = await wallet.send({ address: c1Addr, amount: CONTRACT_AMOUNT });
  const vtxo1 = await waitForVtxo(indexerProvider, c1PkHex, openTxid);
  console.log(`  Opened VTXO #1: ${vtxo1.txid}:${vtxo1.vout} (${vtxo1.value} sats)`);

  // Wipe user's private key — user is now completely OFFLINE!
  user.privBytes.fill(0);
  user.d = 0n;
  console.log("  User private key WIPED (user offline for roll AND settlement).");

  // 2. Quorum {N0, N1, N2} + LP roll VTXO #1 -> fresh 22-path VTXO #2 on live mutinynet.arkade.sh!
  console.log("\n[2/4] Quorum {N0, N1, N2} + LP rolling VTXO #1 -> VTXO #2 via CLTVMultisigTapscript...");
  const rollCltv2 = maturedCltv - 60n; // distinct script for VTXO #2
  const c2 = buildDesign3Script(user.pubXOnly, lp.pubXOnly, nostracles, serverXOnly, exitDelaySecs, rollCltv2);
  const c2PkHex = hex.encode(c2.vtxoScript.pkScript);

  const rollQuorumIdx = [0, 1, 2];
  const rollClosure = c1.quorumSettle.get("0,1,2");
  const rollLeaf = c1.vtxoScript.findLeaf(hex.encode(rollClosure.script));
  const rollLeafHash = tapLeafHash(rollClosure.script);

  const { arkTx: rollArkTx, checkpoints: rollCks } = buildOffchainTx(
    [
      {
        txid: vtxo1.txid,
        vout: vtxo1.vout,
        value: Number(vtxo1.value),
        tapLeafScript: rollLeaf,
        tapTree: c1.vtxoScript.encode(),
      },
    ],
    [{ script: c2.vtxoScript.pkScript, amount: BigInt(CONTRACT_AMOUNT) }],
    checkpointTapscript
  );
  // buildOffchainTx automatically reads CLTVMultisigTapscript and sets lockTime + sequence!
  const rollCk = rollCks[0];
  console.log(`  Roll tx lockTime=${rollArkTx.lockTime}, ck lockTime=${rollCk.lockTime}`);

  const rollSigners = [...rollQuorumIdx.map((i) => nostracles[i]), lp];
  const rollCkHash = tapscriptSighash(rollCk, 0, c1.vtxoScript.pkScript, BigInt(vtxo1.value), rollClosure.script);
  const rollCkOut0 = rollCk.getOutput(0);
  const rollArkHash = tapscriptSighash(rollArkTx, 0, rollCkOut0.script, rollCkOut0.amount, rollClosure.script);

  attachTapscriptSigs(
    rollArkTx,
    rollLeafHash,
    rollSigners.map((s) => [s.pubXOnly, schnorrSign(s, rollArkHash)])
  );
  const rollSub = await arkProvider.submitTx(base64.encode(rollArkTx.toPSBT()), [base64.encode(rollCk.toPSBT())]);
  console.log(`  Roll submitTx ACCEPTED! rolled arkTxid = ${rollSub.arkTxid}`);

  const serverRollCk = Transaction.fromPSBT(base64.decode(rollSub.signedCheckpointTxs[0]));
  attachTapscriptSigs(
    rollCk,
    rollLeafHash,
    rollSigners.map((s) => [s.pubXOnly, schnorrSign(s, rollCkHash)])
  );
  const finalRollCk = combineTapscriptSigs(rollCk, serverRollCk);
  await arkProvider.finalizeTx(rollSub.arkTxid, [base64.encode(finalRollCk.toPSBT())]);
  console.log("  Roll finalizeTx ACCEPTED by mutinynet.arkade.sh!");

  const vtxo2 = await waitForVtxo(indexerProvider, c2PkHex, rollSub.arkTxid);
  console.log(`  Indexer confirmed rolled 22-path VTXO #2: ${vtxo2.txid}:${vtxo2.vout} (${vtxo2.value} sats)`);

  // 3. Different quorum {N1, N2, N4} + LP adaptor-sign 20-bit numeric DLC binary prefixes on VTXO #2!
  console.log("\n[3/4] Quorum {N1, N2, N4} + LP adaptor-signing 20-bit numeric DLC prefixes on VTXO #2...");
  const settleQuorumIdx = [1, 2, 4];
  const settleSigners = [...settleQuorumIdx.map((i) => nostracles[i]), lp];
  const settleClosure = c2.quorumSettle.get("1,2,4");
  const settleLeaf = c2.vtxoScript.findLeaf(hex.encode(settleClosure.script));
  const settleLeafHash = tapLeafHash(settleClosure.script);

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

  // Binary prefixes for 20-bit BTC/USD price buckets (12-bit prefixes = $256 wide buckets):
  // - 000101100101 -> [$91,392 .. $91,647] (matches $91,420 -> User 2,450 sats, LP 2,050 sats)
  // - 000111000000 -> [$114,688 .. $114,943] (higher BTC -> User 1,950 sats, LP 2,550 sats)
  const prefixPayouts = {
    "000101100101": [2_450n, 2_050n],
    "000111000000": [1_950n, 2_550n],
  };

  const preSigned = {};
  for (const [prefix, [uAmt, lAmt]] of Object.entries(prefixPayouts)) {
    const T = oracle.prefixAnticipationPoint(prefix);
    const { arkTx, checkpoints } = buildOffchainTx(
      [
        {
          txid: vtxo2.txid,
          vout: vtxo2.vout,
          value: Number(vtxo2.value),
          tapLeafScript: settleLeaf,
          tapTree: c2.vtxoScript.encode(),
        },
      ],
      [
        { script: userArkScript.pkScript, amount: uAmt },
        { script: lpArkScript.pkScript, amount: lAmt },
      ],
      checkpointTapscript
    );
    const ck = checkpoints[0];

    const ckHash = tapscriptSighash(ck, 0, c2.vtxoScript.pkScript, BigInt(vtxo2.value), settleClosure.script);
    const ckOut0 = ck.getOutput(0);
    const arkHash = tapscriptSighash(arkTx, 0, ckOut0.script, ckOut0.amount, settleClosure.script);

    preSigned[prefix] = {
      arkTx,
      ck,
      arkAdapters: settleSigners.map((s) => [s.pubXOnly, adaptorSign(s, arkHash, T)]),
      ckAdapters: settleSigners.map((s) => [s.pubXOnly, adaptorSign(s, ckHash, T)]),
    };
  }
  console.log(`  Adaptor-signed ${Object.keys(preSigned).length} 12-bit numeric prefixes across 4 signers (N1, N2, N4, LP).`);

  // 4. Oracle attests $91,420 (20 binary digits) -> settle matching prefix on live mutinynet.arkade.sh!
  console.log(`\n[4/4] Oracle attests $${ATTESTED_PRICE} (20 binary digits) -> settling rolled VTXO #2...`);
  const att = oracle.attestPrice(ATTESTED_PRICE);
  console.log(`  20-bit outcome: ${att.bits}`);
  const matchedPrefix = Object.keys(preSigned).find((p) => att.bits.startsWith(p));
  if (!matchedPrefix) throw new Error(`No prefix matched ${att.bits}`);
  const scalar = sumPrefixScalars(att.scalars, matchedPrefix.length);
  const win = preSigned[matchedPrefix];

  attachTapscriptSigs(
    win.arkTx,
    settleLeafHash,
    win.arkAdapters.map(([pub, ad]) => [pub, completeAdaptor(ad, scalar)])
  );
  const settleSub = await arkProvider.submitTx(base64.encode(win.arkTx.toPSBT()), [base64.encode(win.ck.toPSBT())]);
  console.log(`  Settle submitTx ACCEPTED! settlement arkTxid = ${settleSub.arkTxid}`);

  const serverSettleCk = Transaction.fromPSBT(base64.decode(settleSub.signedCheckpointTxs[0]));
  attachTapscriptSigs(
    win.ck,
    settleLeafHash,
    win.ckAdapters.map(([pub, ad]) => [pub, completeAdaptor(ad, scalar)])
  );
  const finalSettleCk = combineTapscriptSigs(win.ck, serverSettleCk);
  await arkProvider.finalizeTx(settleSub.arkTxid, [base64.encode(finalSettleCk.toPSBT())]);
  console.log("  Settle finalizeTx ACCEPTED by mutinynet.arkade.sh!");

  await sleep(2_000);
  const v1Spent = (await indexerProvider.getVtxos({ scripts: [c1PkHex], spentOnly: true })).vtxos.some(
    (v) => v.txid === vtxo1.txid && v.isSpent
  );
  const v2Spent = (await indexerProvider.getVtxos({ scripts: [c2PkHex], spentOnly: true })).vtxos.some(
    (v) => v.txid === vtxo2.txid && v.isSpent
  );
  const uVtxos = (await indexerProvider.getVtxos({ scripts: [hex.encode(userArkScript.pkScript)], spendableOnly: true })).vtxos;
  const lVtxos = (await indexerProvider.getVtxos({ scripts: [hex.encode(lpArkScript.pkScript)], spendableOnly: true })).vtxos;

  console.log(`  VTXO #1 spent (rolled) : ${v1Spent}`);
  console.log(`  VTXO #2 spent (settled): ${v2Spent}`);
  console.log(`  User payout VTXO       : ${uVtxos.map((v) => `${v.txid}:${v.vout} (${v.value} sats)`).join(", ")}`);
  console.log(`  LP payout VTXO         : ${lVtxos.map((v) => `${v.txid}:${v.vout} (${v.value} sats)`).join(", ")}`);

  if (!v1Spent || !v2Spent) throw new Error("Expected both VTXO #1 and VTXO #2 spent");
  if (uVtxos.reduce((s, v) => s + Number(v.value), 0) !== 2_450) throw new Error("User payout mismatch");
  if (lVtxos.reduce((s, v) => s + Number(v.value), 0) !== 2_050) throw new Error("LP payout mismatch");

  console.log("\n=== EXPERIMENT 17 RESULT: SUCCESS ===");
  console.log("22-path Design 3 quorum roll + 20-bit numeric DLC settled LIVE on mutinynet.arkade.sh!");
  await wallet.dispose?.();
  process.exit(0);
}

main().catch((err) => {
  console.error("EXPERIMENT 17 FAILED:", err);
  process.exit(1);
});
