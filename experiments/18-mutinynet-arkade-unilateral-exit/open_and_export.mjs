/**
 * Experiment 18 (Part 1): Open a REAL custom Tapscript DLC VTXO on public
 * `https://mutinynet.arkade.sh`, extract its real VTXO unroll branch
 * (`getVtxoChain` + `getVirtualTxs`), pre-sign the onchain DLC exit payout
 * with a tiered Taproot bounty for `W1` (`ark-watchtower`), wipe all user
 * and LP keys, and export a standard keyless `WatchtowerPackage` JSON file.
 */

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
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
  Transaction,
  toXOnly,
} from "@arkade-os/sdk";
import * as btc from "@scure/btc-signer";
import { hex, base64 } from "@scure/base";
import { schnorr } from "@noble/curves/secp256k1.js";

const ARK_URL = "https://mutinynet.arkade.sh";
const ESPLORA_URL = "https://mutinynet.com/api";
const BOARD_AMOUNT = 10_000n;
const CONTRACT_AMOUNT = 10_000;
const BOUNTY_AMOUNT = 5_000;
const EXIT_TX_FEE = 500;
const BACKUP_CSV = 4;

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
  console.log("=== Experiment 18 (Part 1): Open live Arkade Mutinynet DLC VTXO & export WatchtowerPackage ===");
  const arkProvider = new RestArkProvider(ARK_URL);
  const indexerProvider = new RestIndexerProvider(ARK_URL);
  const onchainProvider = new EsploraProvider(ESPLORA_URL);

  const info = await arkProvider.getInfo();
  const serverXOnly = toXOnly(hex.decode(info.signerPubkey));
  const exitDelaySecs = BigInt(info.unilateralExitDelay);
  console.log(`Connected to ${ARK_URL} (network=${info.network}, unilateralExitDelay=${exitDelaySecs}s)`);

  const wtKeyPath = path.resolve(import.meta.dirname, "../../watchtower/data/mutinynet-wt.key");
  const wtExePath = path.resolve(import.meta.dirname, "../../watchtower/target/debug/ark-watchtower.exe");
  const funderHex = fs.readFileSync(wtKeyPath, "utf8").trim();
  const funderPriv = hex.decode(funderHex);
  const w1PubXOnly = hex.encode(toXOnly(schnorr.getPublicKey(funderPriv)));
  const w2 = randomEvenKey();
  const w2PubXOnly = hex.encode(w2.pubXOnly);

  // Compile exact tiered Taproot bounty script via our Rust `ark-watchtower bounty-script` CLI!
  const bountyJson = JSON.parse(
    execFileSync(wtExePath, [
      "bounty-script",
      "--primary",
      w1PubXOnly,
      "--backup",
      w2PubXOnly,
      "--backup-csv",
      String(BACKUP_CSV),
      "--amount",
      String(BOUNTY_AMOUNT),
      "--network",
      "signet",
    ]).toString("utf8")
  );
  const bountyPkScript = hex.decode(bountyJson.script_pubkey);
  console.log(`Compiled tiered Taproot bounty via ark-watchtower CLI: ${bountyJson.address}`);

  // Use a brand-new ephemeral funder identity so it has ZERO prior preconfirmed VTXOs
  // and produces a clean, minimal 3-hop Arkade unroll branch (TREE -> CHECKPOINT -> ARK).
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

  // 1. Ensure wallet has >= 10,000 settled Arkade sats (and wait for the batch commitment tx to confirm on L1!).
  let bal = await wallet.getBalance();
  console.log(`Initial Arkade balance: settled=${bal.settled}, available=${bal.available}`);
  if (BigInt(bal.available) < BigInt(CONTRACT_AMOUNT)) {
    const boardingAddr = await wallet.getBoardingAddress();
    const p2tr = btc.p2tr(toXOnly(schnorr.getPublicKey(funderPriv)), undefined, btc.TEST_NETWORK);
    const fee = 500n;
    let selected = [];
    let totalIn = 0n;
    while (true) {
      const utxos = await (await fetch(`${ESPLORA_URL}/address/${p2tr.address}/utxo`)).json();
      const confirmed = utxos.filter((u) => u.status?.confirmed).sort((a, b) => b.value - a.value);
      selected = confirmed;
      totalIn = selected.reduce((acc, u) => acc + BigInt(u.value), 0n);
      if (totalIn >= BOARD_AMOUNT + fee + 5_000n) break;
      console.log(`  Waiting for confirmed L1 funds >= ${BOARD_AMOUNT + fee + 5_000n} sats (currently ${totalIn})...`);
      await sleep(10_000);
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
    if (totalIn - BOARD_AMOUNT - fee > 546n) {
      tx.addOutputAddress(p2tr.address, totalIn - BOARD_AMOUNT - fee, btc.TEST_NETWORK);
    }
    tx.sign(funderPriv);
    tx.finalize();
    const bRes = await fetch(`${ESPLORA_URL}/tx`, { method: "POST", body: hex.encode(tx.extract()) });
    if (!bRes.ok) throw new Error(`Boarding broadcast failed: ${await bRes.text()}`);
    const boardingTxid = (await bRes.text()).trim();
    console.log(`\n[1/4] L1 boarding tx: https://mutinynet.com/tx/${boardingTxid}`);
    await waitForTxConfirmed(boardingTxid);

    console.log("  Joining live Arkade Mutinynet batch round via Ramps.onboard()...");
    const commitTxid = await new Ramps(wallet).onboard(info.fees);
    console.log(`  Batch commitment tx: https://mutinynet.com/tx/${commitTxid}`);
    console.log("  Waiting for batch commitment tx to confirm on Mutinynet L1 (TRUC v3 requirement)...");
    await waitForTxConfirmed(commitTxid);
    await sleep(3_000);
  }

  // 2. Open custom Tapscript DLC contract VTXO (10,000 sats) on mutinynet.arkade.sh
  //    using ONLY a single freshly-settled batch VTXO so the unroll branch stays minimal (3 hops)!
  console.log("\n[2/4] Opening 10,000-sat DLC contract VTXO on mutinynet.arkade.sh...");
  const spendableVtxos = await wallet.getVtxos();
  const singleSettled = spendableVtxos
    .filter((v) => Number(v.value) >= CONTRACT_AMOUNT)
    .sort((a, b) => Number(b.value) - Number(a.value))[0];
  if (!singleSettled) {
    throw new Error(
      `No single VTXO >= ${CONTRACT_AMOUNT} sats (found: ${spendableVtxos.map((v) => `${v.value}`).join(",")})`
    );
  }
  console.log(`  Funding from single settled VTXO: ${singleSettled.txid}:${singleSettled.vout} (${singleSettled.value} sats)`);

  const user = randomEvenKey();
  const lp = randomEvenKey();
  const settleClosure = MultisigTapscript.encode({ pubkeys: [user.pubXOnly, lp.pubXOnly, serverXOnly] });
  const exitClosure = CSVMultisigTapscript.encode({
    timelock: { type: "seconds", value: exitDelaySecs },
    pubkeys: [user.pubXOnly, lp.pubXOnly],
  });
  const contractScript = new VtxoScript([settleClosure.script, exitClosure.script]);
  const contractAddr = contractScript.address("tark", serverXOnly).encode();
  const contractPkHex = hex.encode(contractScript.pkScript);
  const openTxid = await wallet.send({
    address: contractAddr,
    amount: CONTRACT_AMOUNT,
    selectedVtxos: [singleSettled],
  });

  let vtxo = null;
  for (let i = 0; i < 20; i++) {
    const res = await indexerProvider.getVtxos({ scripts: [contractPkHex], spendableOnly: true });
    if (res.vtxos?.length) {
      vtxo = res.vtxos[0];
      break;
    }
    await sleep(1_500);
  }
  if (!vtxo) throw new Error("Contract VTXO not indexed");
  console.log(`  Live Arkade DLC VTXO: ${vtxo.txid}:${vtxo.vout} (${vtxo.value} sats)`);

  // 3. Extract the REAL Arkade VTXO unroll chain (`getVtxoChain` + `getVirtualTxs`)!
  console.log("\n[3/4] Fetching real VTXO unroll chain from mutinynet.arkade.sh indexer...");
  let chain = [];
  for (let i = 0; i < 15; i++) {
    const resp = await indexerProvider.getVtxoChain({ txid: vtxo.txid, vout: vtxo.vout });
    if (resp.txs?.length) {
      chain = resp.txs;
      break;
    }
    if (resp.chain?.length) {
      chain = resp.chain;
      break;
    }
    await sleep(1_500);
  }
  if (!chain.length) throw new Error("Empty VTXO chain from indexer");
  console.log("  Raw chain nodes:", chain.map((c) => `${c.txid.slice(0, 8)}..(${c.type})`).join(" -> "));

  // Filter out commitment tx (already confirmed on L1) and order root-to-leaf (parent before child).
  const nonCommit = chain.filter((c) => !String(c.type).toLowerCase().includes("commitment") && c.type !== 1);
  // getVtxoChain returns leaf-to-root or topological; fetch all virtual PSBTs and sort by parent->child dependency!
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
    let rawHex;
    if (hasTapKeyOnly) {
      rawHex = hex.encode(t.toBytes(true, true));
    } else {
      if (!t.isFinal) t.finalize();
      rawHex = hex.encode(t.extract());
    }
    rawByTxid.set(t.id, rawHex);
    txObjByTxid.set(t.id, t);
  }

  // Topological sort: if tx B spends tx A's txid, A must come before B.
  const orderedTxids = [];
  const visited = new Set();
  function visit(txid) {
    if (visited.has(txid) || !txObjByTxid.has(txid)) return;
    visited.add(txid);
    const t = txObjByTxid.get(txid);
    for (let i = 0; i < t.inputsLength; i++) {
      const prev = hex.encode(t.getInput(i).txid);
      if (txObjByTxid.has(prev)) visit(prev);
    }
    orderedTxids.push(txid);
  }
  for (const c of nonCommit) visit(c.txid);
  const unrollTxs = orderedTxids.map((id) => rawByTxid.get(id));
  console.log(`  Ordered unroll_txs (${unrollTxs.length} hops, root->leaf):`);
  orderedTxids.forEach((id, idx) => console.log(`    hop ${idx + 1}: ${id}`));

  // 4. Build & sign the onchain DLC exit payout tx spending `vtxo` with BIP-68 time-based CSV(2048s)
  //    and paying 5,000 sats to our tiered Taproot bounty!
  console.log("\n[4/4] Signing onchain DLC exit payout (CSV 2048s + 5,000 sat tiered bounty) & wiping keys...");
  const csvSequence = (1 << 22) | Number(exitDelaySecs / 512n); // BIP-68 time-based relative locktime
  const uDest = btc.p2tr(user.pubXOnly, undefined, btc.TEST_NETWORK).script;
  const lDest = btc.p2tr(lp.pubXOnly, undefined, btc.TEST_NETWORK).script;

  const exitTx = new btc.Transaction({ version: 2 });
  exitTx.addInput({
    txid: vtxo.txid,
    index: vtxo.vout,
    sequence: csvSequence,
  });
  exitTx.addOutput({ script: uDest, amount: 3_250n });
  exitTx.addOutput({ script: lDest, amount: 1_250n });
  exitTx.addOutput({ script: bountyPkScript, amount: BigInt(BOUNTY_AMOUNT) });

  const exitSighash = exitTx.preimageWitnessV1(
    0,
    [contractScript.pkScript],
    btc.SigHash.DEFAULT,
    [BigInt(CONTRACT_AMOUNT)],
    -1,
    exitClosure.script,
    0xc0
  );
  const uSig = schnorrSign(user, exitSighash);
  const lSig = schnorrSign(lp, exitSighash);

  // Extract raw control block for exitLeaf.
  const [exitCtrlObj] = contractScript.findLeaf(hex.encode(exitClosure.script));
  const exitCtrlBytes = btc.TaprootControlBlock.encode(exitCtrlObj);

  // Wipe user & LP private keys!
  user.privBytes.fill(0);
  user.d = 0n;
  lp.privBytes.fill(0);
  lp.d = 0n;

  const pkg = {
    id: `exp18-arkade-${Date.now()}`,
    vtxo_outpoint: `${vtxo.txid}:${vtxo.vout}`,
    vtxo_amount_sats: CONTRACT_AMOUNT,
    vtxo_pk_script: contractPkHex,
    ark_indexer_url: null, // Simulate operator offline so watchtower proceeds to unroll
    unroll_txs: unrollTxs,
    exit_script: hex.encode(exitClosure.script),
    exit_control_block: hex.encode(exitCtrlBytes),
    user_pubkey: hex.encode(user.pubXOnly),
    lp_pubkey: hex.encode(lp.pubXOnly),
    exit_csv: 0,
    exit_csv_seconds: Number(exitDelaySecs),
    bounty: {
      amount_sats: BOUNTY_AMOUNT,
      vout: 2,
      primary_pubkey: w1PubXOnly,
      backup_pubkeys: [w2PubXOnly],
      backup_csv: BACKUP_CSV,
    },
    oracle_pubkey: null,
    oracle_event_id: null,
    payouts: [
      {
        outcome: "BTCUSD-up",
        tx_hex: hex.encode(exitTx.toBytes(true, false)),
        user_adaptor_sig: hex.encode(uSig),
        lp_adaptor_sig: hex.encode(lSig),
        precompleted: true,
      },
    ],
    refund: null,
    trigger_height: 0,
  };

  const outDir = path.resolve(import.meta.dirname, "data");
  fs.mkdirSync(outDir, { recursive: true });
  const outPath = path.join(outDir, "package.json");
  fs.writeFileSync(outPath, JSON.stringify(pkg, null, 2));
  console.log(`\nExported keyless WatchtowerPackage to ${outPath}`);
  console.log("User and LP keys WIPED. Handing off to Rust `ark-watchtower`!");
  await wallet.dispose?.();
  process.exit(0);
}

main().catch((err) => {
  console.error("EXPERIMENT 18 PART 1 FAILED:", err);
  process.exit(1);
});
