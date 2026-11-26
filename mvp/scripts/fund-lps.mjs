/**
 * Funds and onboards both local LP daemons (LP-Alpha & LP-Beta) with 15,000
 * Mutinynet sats each from `watchtower/data/mutinynet-wt.key` into live Arkade.
 */

import fs from "node:fs";
import path from "node:path";
import {
  Wallet,
  SingleKey,
  Ramps,
  RestArkProvider,
  RestIndexerProvider,
  EsploraProvider,
  InMemoryWalletRepository,
  InMemoryContractRepository,
  toXOnly,
} from "@arkade-os/sdk";
import * as btc from "@scure/btc-signer";
import { hex } from "@scure/base";
import { schnorr } from "@noble/curves/secp256k1.js";

const ARK_URL = "https://mutinynet.arkade.sh";
const ESPLORA_URL = "https://mutinynet.com/api";
const PER_LP_SATS = 15_000n;

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function createLpWallet(keyHex, arkProvider, indexerProvider, onchainProvider) {
  return Wallet.create({
    identity: SingleKey.fromHex(keyHex),
    arkProvider,
    indexerProvider,
    onchainProvider,
    settlementConfig: false,
    storage: {
      walletRepository: new InMemoryWalletRepository(),
      contractRepository: new InMemoryContractRepository(),
    },
  });
}

async function onboardWithRetry(wallet, fees, label) {
  for (let attempt = 1; attempt <= 2; attempt++) {
    try {
      return await new Ramps(wallet).onboard(fees);
    } catch (err) {
      console.log(`  [${label}] onboard attempt ${attempt} failed (${err.message}), retrying...`);
      if (attempt === 2) throw err;
      await sleep(3_000);
    }
  }
}

async function main() {
  const alphaPath = path.resolve(import.meta.dirname, "../data/lp-alpha/lp.json");
  const betaPath = path.resolve(import.meta.dirname, "../data/lp-beta/lp.json");
  const wtKeyPath = path.resolve(import.meta.dirname, "../../watchtower/data/mutinynet-wt.key");

  const alphaKeyHex = JSON.parse(fs.readFileSync(alphaPath, "utf8")).lpKeyHex;
  const betaKeyHex = JSON.parse(fs.readFileSync(betaPath, "utf8")).lpKeyHex;

  const arkProvider = new RestArkProvider(ARK_URL);
  const indexerProvider = new RestIndexerProvider(ARK_URL);
  const onchainProvider = new EsploraProvider(ESPLORA_URL);
  const info = await arkProvider.getInfo();

  const [alphaWallet, betaWallet] = await Promise.all([
    createLpWallet(alphaKeyHex, arkProvider, indexerProvider, onchainProvider),
    createLpWallet(betaKeyHex, arkProvider, indexerProvider, onchainProvider),
  ]);

  const alphaBoard = await alphaWallet.getBoardingAddress();
  const betaBoard = await betaWallet.getBoardingAddress();
  console.log(`LP-Alpha boarding: ${alphaBoard}`);
  console.log(`LP-Beta  boarding: ${betaBoard}`);

  // Build & broadcast 1 L1 tx funding both LP boarding addresses from mutinynet-wt.key
  const l1Priv = hex.decode(fs.readFileSync(wtKeyPath, "utf8").trim());
  const p2tr = btc.p2tr(toXOnly(schnorr.getPublicKey(l1Priv)), undefined, btc.TEST_NETWORK);
  const utxos = await (await fetch(`${ESPLORA_URL}/address/${p2tr.address}/utxo`)).json();
  const confirmed = utxos.filter((u) => u.status?.confirmed).sort((a, b) => b.value - a.value);

  const fee = 500n;
  const selected = [];
  let totalIn = 0n;
  for (const u of confirmed) {
    selected.push(u);
    totalIn += BigInt(u.value);
    if (totalIn >= PER_LP_SATS * 2n + fee + 600n) break;
  }
  console.log(`Mutinynet L1 source available (selected UTXOs): ${totalIn} sats`);
  if (totalIn < PER_LP_SATS * 2n + fee) {
    throw new Error(`Insufficient confirmed L1 funds (${totalIn} sats)`);
  }

  const btx = new btc.Transaction();
  for (const u of selected) {
    btx.addInput({
      txid: u.txid,
      index: u.vout,
      witnessUtxo: { script: p2tr.script, amount: BigInt(u.value) },
      tapInternalKey: p2tr.tapInternalKey,
    });
  }
  btx.addOutputAddress(alphaBoard, PER_LP_SATS, btc.TEST_NETWORK);
  btx.addOutputAddress(betaBoard, PER_LP_SATS, btc.TEST_NETWORK);
  const change = totalIn - PER_LP_SATS * 2n - fee;
  if (change > 546n) btx.addOutputAddress(p2tr.address, change, btc.TEST_NETWORK);
  btx.sign(l1Priv);
  btx.finalize();

  const bRes = await fetch(`${ESPLORA_URL}/tx`, { method: "POST", body: hex.encode(btx.extract()) });
  if (!bRes.ok) throw new Error(`Broadcast failed: ${await bRes.text()}`);
  const txid = (await bRes.text()).trim();
  console.log(`Broadcasted funding tx: https://mutinynet.com/tx/${txid}`);

  console.log("Waiting for Mutinynet L1 confirmation...");
  while (true) {
    const st = await (await fetch(`${ESPLORA_URL}/tx/${txid}/status`)).json();
    if (st.confirmed) break;
    await sleep(10_000);
  }
  console.log("L1 confirmed! Onboarding both LPs into Arkade batch round...");

  const [alphaCommit, betaCommit] = await Promise.all([
    onboardWithRetry(alphaWallet, info.fees, "LP-Alpha"),
    onboardWithRetry(betaWallet, info.fees, "LP-Beta"),
  ]);
  console.log(`Onboarded! LP-Alpha batch=${alphaCommit}, LP-Beta batch=${betaCommit}`);

  await Promise.all([alphaWallet.dispose?.(), betaWallet.dispose?.()]);
  await sleep(2_000);

  const [hA, hB] = await Promise.all([
    fetch("http://127.0.0.1:3456/health").then((r) => r.json()),
    fetch("http://127.0.0.1:3458/health").then((r) => r.json()),
  ]);
  console.log(`LP-Alpha live Ark balance: available=${hA.arkBalance.available} sats`);
  console.log(`LP-Beta  live Ark balance: available=${hB.arkBalance.available} sats`);
}

main().catch((err) => {
  console.error("Funding failed:", err);
  process.exit(1);
});
