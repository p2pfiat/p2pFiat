/**
 * Experiment 16: Live custom-Tapscript DLC on public Arkade Mutinynet
 * (`https://mutinynet.arkade.sh`).
 *
 * Proves on a live public Arkade server:
 * 1. Boarding real Mutinynet L1 sats into an Arkade VTXO via a live batch round.
 * 2. Opening a custom Tapscript DLC contract VTXO:
 *      - settle: 3-of-3 MultisigTapscript (user + LP + Arkade signer)
 *      - exit  : 2-of-2 CSVMultisigTapscript (user + LP after 20 blocks)
 * 3. Adaptor-signing both the offchain settlement `arkTx` AND `checkpointTx`
 *    for multiple outcomes, then WIPING the user's private key (user offline).
 * 4. Completing the adaptor signatures from a DLC oracle attestation and
 *    settling offchain via `submitTx` + `finalizeTx` on `mutinynet.arkade.sh`.
 * 5. Verifying via the live Arkade indexer that the contract VTXO is spent
 *    and that User (17,000 sats) and LP (8,000 sats) hold live settled VTXOs.
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
const CONTRACT_AMOUNT = 5_000;
const PAYOUTS = {
  "BTCUSD-up": [3_000n, 2_000n],
  "BTCUSD-down": [2_000n, 3_000n],
};

// secp256k1 curve parameters (for BIP-340 adaptor signatures)
const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
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
    return {
      d,
      privBytes: bigIntToBytes32(d),
      pubXOnly: pointToXOnly(pt),
      point: pt,
    };
  }
}

class TestOracle {
  constructor() {
    this.key = randomEvenKey();
    this.nonce = randomEvenKey();
  }
  anticipationPoint(outcome) {
    const m = sha256(Buffer.from(outcome, "utf8"));
    const e = bytesToBigInt(taggedHash("BIP0340/challenge", this.nonce.pubXOnly, this.key.pubXOnly, m)) % N;
    return this.nonce.point.add(this.key.point.multiply(e));
  }
  attest(outcome) {
    const m = sha256(Buffer.from(outcome, "utf8"));
    const e = bytesToBigInt(taggedHash("BIP0340/challenge", this.nonce.pubXOnly, this.key.pubXOnly, m)) % N;
    return (this.nonce.d + e * this.key.d) % N;
  }
}

function adaptorSign(signer, msg32, T) {
  while (true) {
    const kBytes = crypto.randomBytes(32);
    const k = bytesToBigInt(kBytes);
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

function tapscriptSighash(psbtTx, inputIdx, prevScript, prevAmount, leafScript) {
  return psbtTx.preimageWitnessV1(
    inputIdx,
    [prevScript],
    btc.SigHash.DEFAULT,
    [prevAmount],
    -1,
    leafScript,
    0xc0
  );
}

function encodeVarBytes(b) {
  if (b.length < 0xfd) return Uint8Array.from([b.length, ...b]);
  throw new Error("script too long");
}

function attachTapscriptSig(psbtTx, pubXOnly, leafHash, sig) {
  const inp = psbtTx.getInput(0);
  const existing = inp.tapScriptSig ? [...inp.tapScriptSig] : [];
  existing.push([{ pubKey: pubXOnly, leafHash }, sig]);
  psbtTx.updateInput(0, { tapScriptSig: existing });
}

async function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function waitForTxConfirmed(txid) {
  while (true) {
    const res = await fetch(`${ESPLORA_URL}/tx/${txid}/status`);
    if (res.ok) {
      const st = await res.json();
      if (st.confirmed) {
        console.log(`  tx ${txid} confirmed at block ${st.block_height}`);
        return st.block_height;
      }
    }
    console.log(`  tx ${txid} in mempool, waiting...`);
    await sleep(10_000);
  }
}

async function main() {
  console.log("=== Experiment 16: Live DLC on public Arkade Mutinynet ===");
  const arkProvider = new RestArkProvider(ARK_URL);
  const indexerProvider = new RestIndexerProvider(ARK_URL);
  const onchainProvider = new EsploraProvider(ESPLORA_URL);

  const info = await arkProvider.getInfo();
  console.log(`Connected to ${ARK_URL} (network=${info.network}, session=${info.sessionDuration}s)`);
  const serverXOnly = toXOnly(hex.decode(info.signerPubkey));
  const checkpointTapscript = CSVMultisigTapscript.decode(hex.decode(info.checkpointTapscript));

  // Load our funded Mutinynet key from Experiment 15.
  const keyPath = path.resolve(import.meta.dirname, "../../watchtower/data/mutinynet-wt.key");
  const funderHex = fs.readFileSync(keyPath, "utf8").trim();
  const funderPriv = hex.decode(funderHex);
  const funderIdentity = SingleKey.fromHex(funderHex);
  const wallet = await Wallet.create({
    identity: funderIdentity,
    arkProvider,
    indexerProvider,
    onchainProvider,
    settlementConfig: false,
    storage: {
      walletRepository: new InMemoryWalletRepository(),
      contractRepository: new InMemoryContractRepository(),
    },
  });

  // 1. Check if wallet already has >= 26,000 offchain sats; if not, board 30,000 sats from Mutinynet L1.
  let bal = await wallet.getBalance();
  console.log("Initial Arkade balance:", bal);

  if (BigInt(bal.available) < BigInt(CONTRACT_AMOUNT)) {
    const boardingAddr = await wallet.getBoardingAddress();
    console.log(`\n[1/5] Boarding ${BOARD_AMOUNT} sats to Arkade Mutinynet (${boardingAddr})...`);

    // Check if boarding address already has confirmed UTXOs.
    let boardingUtxos = await onchainProvider.getCoins(boardingAddr);
    const boardingSum = boardingUtxos.reduce((acc, u) => acc + BigInt(u.value), 0n);

    if (boardingSum < BOARD_AMOUNT) {
      const p2tr = btc.p2tr(toXOnly(schnorr.getPublicKey(funderPriv)), undefined, btc.TEST_NETWORK);
      const l1Addr = p2tr.address;
      const utxosRes = await fetch(`${ESPLORA_URL}/address/${l1Addr}/utxo`);
      const utxos = await utxosRes.json();
      const confirmed = utxos.filter((u) => u.status?.confirmed).sort((a, b) => b.value - a.value);
      if (!confirmed.length) throw new Error(`No confirmed L1 UTXO at ${l1Addr}`);

      // Spend enough UTXOs to cover BOARD_AMOUNT + 500 fee.
      const fee = 500n;
      const selected = [];
      let totalIn = 0n;
      for (const u of confirmed) {
        selected.push(u);
        totalIn += BigInt(u.value);
        if (totalIn >= BOARD_AMOUNT + fee + 600n) break;
      }
      if (totalIn < BOARD_AMOUNT + fee) {
        throw new Error(`Insufficient L1 funds at ${l1Addr}: have ${totalIn}, need ${BOARD_AMOUNT + fee}`);
      }

      const tx = new btc.Transaction();
      for (const u of selected) {
        tx.addInput({
          txid: u.txid,
          index: u.vout,
          witnessUtxo: { script: p2tr.script, amount: BigInt(u.value) },
          tapInternalKey: p2tr.tapInternalKey,
        });
      }
      tx.addOutputAddress(boardingAddr, BOARD_AMOUNT, btc.TEST_NETWORK);
      const change = totalIn - BOARD_AMOUNT - fee;
      if (change > 546n) {
        tx.addOutputAddress(l1Addr, change, btc.TEST_NETWORK);
      }
      tx.sign(funderPriv);
      tx.finalize();
      const rawHex = hex.encode(tx.extract());
      const bRes = await fetch(`${ESPLORA_URL}/tx`, { method: "POST", body: rawHex });
      if (!bRes.ok) throw new Error(`Broadcast boarding tx failed: ${await bRes.text()}`);
      const boardingTxid = (await bRes.text()).trim();
      console.log(`  L1 boarding tx: https://mutinynet.com/tx/${boardingTxid}`);
      await waitForTxConfirmed(boardingTxid);
    }

    console.log("  Joining live Arkade Mutinynet batch round via Ramps.onboard()...");
    const ramps = new Ramps(wallet);
    const onboardTxid = await ramps.onboard(info.fees, undefined, undefined, (ev) => {
      if (ev?.type) console.log(`  [batch event] ${ev.type}`);
    });
    console.log(`  Onboarded into Arkade batch! Commitment tx: https://mutinynet.com/tx/${onboardTxid}`);
    await sleep(3_000);
    bal = await wallet.getBalance();
    console.log("  Arkade balance after onboard:", bal);
  }

  // 2. Construct custom Design 1 DLC Tapscript VtxoScript (settle 3-of-3 + exit CSV 20 2-of-2).
  console.log("\n[2/5] Opening custom Tapscript DLC contract VTXO on mutinynet.arkade.sh...");
  const user = randomEvenKey();
  const lp = randomEvenKey();
  const oracle = new TestOracle();

  const settleClosure = MultisigTapscript.encode({
    pubkeys: [user.pubXOnly, lp.pubXOnly, serverXOnly],
  });
  const exitClosure = CSVMultisigTapscript.encode({
    timelock: { type: "seconds", value: BigInt(info.unilateralExitDelay) },
    pubkeys: [user.pubXOnly, lp.pubXOnly],
  });
  const contractScript = new VtxoScript([settleClosure.script, exitClosure.script]);
  const contractAddr = contractScript.address("tark", serverXOnly).encode();
  const contractPkHex = hex.encode(contractScript.pkScript);
  console.log(`  DLC contract Ark address: ${contractAddr}`);

  const fundTxid = await wallet.send({
    address: contractAddr,
    amount: CONTRACT_AMOUNT,
  });
  console.log(`  Funded DLC contract offchain! arkTxid = ${fundTxid}`);

  // Wait for live indexer to project our custom DLC VTXO.
  let contractVtxo = null;
  for (let i = 0; i < 20; i++) {
    const res = await indexerProvider.getVtxos({ scripts: [contractPkHex], spendableOnly: true });
    if (res.vtxos && res.vtxos.length > 0) {
      contractVtxo = res.vtxos[0];
      break;
    }
    await sleep(1_500);
  }
  if (!contractVtxo) throw new Error("Indexer did not project custom DLC VTXO");
  console.log(`  Indexer confirmed custom DLC VTXO: ${contractVtxo.txid}:${contractVtxo.vout} (${contractVtxo.value} sats)`);

  // Also verify getVtxoChain returns the live unroll branch for watchtower backup!
  const chainResp = await indexerProvider.getVtxoChain({ txid: contractVtxo.txid, vout: contractVtxo.vout });
  console.log(`  Live unroll branch length: ${chainResp.txs?.length ?? 0} chained txs`);

  // 3. Build offchain DLC payout txs + checkpoints and adaptor-sign them for BOTH outcomes.
  console.log("\n[3/5] Adaptor-signing offchain arkTx + checkpoint for both outcomes, then wiping user key...");
  const userArkScript = new DefaultVtxo.Script({
    pubKey: user.pubXOnly,
    serverPubKey: serverXOnly,
    csvTimelock: { type: "seconds", value: BigInt(info.unilateralExitDelay) },
  });
  const lpArkScript = new DefaultVtxo.Script({
    pubKey: lp.pubXOnly,
    serverPubKey: serverXOnly,
    csvTimelock: { type: "seconds", value: BigInt(info.unilateralExitDelay) },
  });

  const settleLeaf = contractScript.findLeaf(hex.encode(settleClosure.script));
  const settleLeafHash = taggedHash("TapLeaf", new Uint8Array([0xc0]), encodeVarBytes(settleClosure.script));
  const arkInput = {
    txid: contractVtxo.txid,
    vout: contractVtxo.vout,
    value: Number(contractVtxo.value),
    tapLeafScript: settleLeaf,
    tapTree: contractScript.encode(),
  };

  const preSigned = {};
  for (const [outcome, [uAmt, lAmt]] of Object.entries(PAYOUTS)) {
    const T = oracle.anticipationPoint(outcome);
    const { arkTx, checkpoints } = buildOffchainTx(
      [arkInput],
      [
        { script: userArkScript.pkScript, amount: uAmt },
        { script: lpArkScript.pkScript, amount: lAmt },
      ],
      checkpointTapscript
    );
    const ck = checkpoints[0];

    // Sighash for checkpoint input 0 (spends contract VTXO via settleClosure)
    const ckHash = tapscriptSighash(ck, 0, contractScript.pkScript, BigInt(contractVtxo.value), settleClosure.script);

    // Sighash for arkTx input 0 (spends checkpoint output 0 via settleClosure)
    const ckOut0 = ck.getOutput(0);
    const arkHash = tapscriptSighash(arkTx, 0, ckOut0.script, ckOut0.amount, settleClosure.script);

    preSigned[outcome] = {
      arkTx,
      ck,
      uArk: adaptorSign(user, arkHash, T),
      lArk: adaptorSign(lp, arkHash, T),
      uCk: adaptorSign(user, ckHash, T),
      lCk: adaptorSign(lp, ckHash, T),
    };
  }

  // Wipe user's private key completely — user is now OFFLINE!
  user.privBytes.fill(0);
  user.d = 0n;
  console.log("  User private key WIPED. User is offline.");

  // 4. Oracle attests "BTCUSD-up" -> LP completes adaptor signatures & settles offchain on live mutinynet.arkade.sh!
  console.log("\n[4/5] Oracle attests 'BTCUSD-up' -> LP settles offchain on live mutinynet.arkade.sh...");
  const winning = "BTCUSD-up";
  const attScalar = oracle.attest(winning);
  const p = preSigned[winning];

  attachTapscriptSig(p.arkTx, user.pubXOnly, settleLeafHash, completeAdaptor(p.uArk, attScalar));
  attachTapscriptSig(p.arkTx, lp.pubXOnly, settleLeafHash, completeAdaptor(p.lArk, attScalar));

  const arkB64 = base64.encode(p.arkTx.toPSBT());
  const ckUnsignedB64 = base64.encode(p.ck.toPSBT());

  const submitted = await arkProvider.submitTx(arkB64, [ckUnsignedB64]);
  console.log(`  submitTx ACCEPTED by mutinynet.arkade.sh! settlement arkTxid = ${submitted.arkTxid}`);

  // Combine server's checkpoint signature with completed user + LP checkpoint adaptor signatures.
  const serverCk = Transaction.fromPSBT(base64.decode(submitted.signedCheckpointTxs[0]));
  attachTapscriptSig(p.ck, user.pubXOnly, settleLeafHash, completeAdaptor(p.uCk, attScalar));
  attachTapscriptSig(p.ck, lp.pubXOnly, settleLeafHash, completeAdaptor(p.lCk, attScalar));
  const finalCk = combineTapscriptSigs(p.ck, serverCk);
  const finalCkB64 = base64.encode(finalCk.toPSBT());

  await arkProvider.finalizeTx(submitted.arkTxid, [finalCkB64]);
  console.log("  finalizeTx ACCEPTED by mutinynet.arkade.sh!");

  // 5. Verify final state on live Arkade Mutinynet indexer!
  console.log("\n[5/5] Verifying settled VTXOs on live mutinynet.arkade.sh indexer...");
  await sleep(2_000);
  const spentCheck = await indexerProvider.getVtxos({ scripts: [contractPkHex], spentOnly: true });
  const userVtxos = await indexerProvider.getVtxos({ scripts: [hex.encode(userArkScript.pkScript)], spendableOnly: true });
  const lpVtxos = await indexerProvider.getVtxos({ scripts: [hex.encode(lpArkScript.pkScript)], spendableOnly: true });

  console.log(`  Contract VTXO spent  : ${spentCheck.vtxos.some((v) => v.txid === contractVtxo.txid && v.isSpent)}`);
  console.log(`  User settled VTXO    : ${userVtxos.vtxos.map((v) => `${v.txid}:${v.vout} (${v.value} sats)`).join(", ")}`);
  console.log(`  LP settled VTXO      : ${lpVtxos.vtxos.map((v) => `${v.txid}:${v.vout} (${v.value} sats)`).join(", ")}`);

  if (!spentCheck.vtxos.some((v) => v.txid === contractVtxo.txid && v.isSpent)) {
    throw new Error("Contract VTXO not marked spent!");
  }
  if (userVtxos.vtxos.reduce((s, v) => s + Number(v.value), 0) !== Number(PAYOUTS[winning][0])) {
    throw new Error("User payout mismatch!");
  }
  if (lpVtxos.vtxos.reduce((s, v) => s + Number(v.value), 0) !== Number(PAYOUTS[winning][1])) {
    throw new Error("LP payout mismatch!");
  }

  console.log("\n=== EXPERIMENT 16 RESULT: SUCCESS ===");
  console.log("Custom Tapscript DLC opened and offline-settled via adaptor signatures on LIVE mutinynet.arkade.sh!");
  await wallet.dispose?.();
  process.exit(0);
}

main().catch((err) => {
  console.error("EXPERIMENT 16 FAILED:", err);
  process.exit(1);
});
