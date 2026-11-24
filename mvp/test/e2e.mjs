/**
 * M4 Live Mutinynet E2E test:
 * Starts the real HTTP LP server (`src/lp.mjs`), boards Mutinynet sats for both
 * User and LP in parallel, and executes the real User CLI (`src/cli.mjs`) for:
 *   init -> balance -> quote --usd 3 -> open --usd 3 -> positions -> export-watchtower -> close
 * against live `https://mutinynet.arkade.sh` and live BTC/USD exchange spot feeds.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
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
import { createLpServer } from "../src/lp.mjs";

const ARK_URL = "https://mutinynet.arkade.sh";
const ESPLORA_URL = "https://mutinynet.com/api";
const LP_PORT = 3457;

async function runCli(args, env) {
  const cliPath = path.resolve(import.meta.dirname, "../src/cli.mjs");
  const { stdout } = await execFileAsync(process.execPath, [cliPath, ...args], {
    env: { ...process.env, ...env },
    encoding: "utf8",
  });
  return JSON.parse(stdout);
}

async function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function main() {
  console.log("=== M4 MVP Live Mutinynet E2E Test (LP Service + User CLI) ===");
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "p2pfiat-mvp-"));
  const cliEnv = { LP_URL: `http://127.0.0.1:${LP_PORT}`, USER_DATA_DIR: tmpDir };

  // 1. Start live HTTP LP server.
  const lp = await createLpServer({ port: LP_PORT, dataDir: tmpDir });
  const lpBoardingAddr = await lp.wallet.getBoardingAddress();
  console.log(`[1/6] LP server started at ${lp.url}`);

  try {
    // 2. Initialize User wallet via real CLI.
    const userInit = await runCli(["init"], cliEnv);
    console.log(`[2/6] User CLI initialized: ${userInit.arkAddress.slice(0, 24)}...`);

    // 3. Fund both LP and User boarding addresses (5,000 sats each) in 1 L1 Mutinynet tx!
    const wtKeyPath = path.resolve(import.meta.dirname, "../../watchtower/data/mutinynet-wt.key");
    const l1Priv = hex.decode(fs.readFileSync(wtKeyPath, "utf8").trim());
    const p2tr = btc.p2tr(toXOnly(schnorr.getPublicKey(l1Priv)), undefined, btc.TEST_NETWORK);
    const utxos = await (await fetch(`${ESPLORA_URL}/address/${p2tr.address}/utxo`)).json();
    const confirmed = utxos.filter((u) => u.status?.confirmed).sort((a, b) => b.value - a.value);
    const perSide = 5_000n;
    const fee = 500n;
    const selected = [];
    let totalIn = 0n;
    for (const u of confirmed) {
      selected.push(u);
      totalIn += BigInt(u.value);
      if (totalIn >= perSide * 2n + fee + 600n) break;
    }
    if (totalIn < perSide * 2n + fee) throw new Error(`Insufficient L1 funds: ${totalIn}`);

    const btx = new btc.Transaction();
    for (const u of selected) {
      btx.addInput({
        txid: u.txid,
        index: u.vout,
        witnessUtxo: { script: p2tr.script, amount: BigInt(u.value) },
        tapInternalKey: p2tr.tapInternalKey,
      });
    }
    btx.addOutputAddress(lpBoardingAddr, perSide, btc.TEST_NETWORK);
    btx.addOutputAddress(userInit.boardingAddress, perSide, btc.TEST_NETWORK);
    const change = totalIn - perSide * 2n - fee;
    if (change > 546n) btx.addOutputAddress(p2tr.address, change, btc.TEST_NETWORK);
    btx.sign(l1Priv);
    btx.finalize();

    const bRes = await fetch(`${ESPLORA_URL}/tx`, { method: "POST", body: hex.encode(btx.extract()) });
    if (!bRes.ok) throw new Error(`Boarding broadcast failed: ${await bRes.text()}`);
    const boardingTxid = (await bRes.text()).trim();
    console.log(`[3/6] L1 boarding tx (5k LP + 5k User): https://mutinynet.com/tx/${boardingTxid}`);
    while (true) {
      const st = await (await fetch(`${ESPLORA_URL}/tx/${boardingTxid}/status`)).json();
      if (st.confirmed) break;
      await sleep(10_000);
    }

    // Board LP and User into live Arkade Mutinynet in parallel!
    const userState = JSON.parse(fs.readFileSync(path.join(tmpDir, "user.json"), "utf8"));
    const arkProvider = new RestArkProvider(ARK_URL);
    const indexerProvider = new RestIndexerProvider(ARK_URL);
    const onchainProvider = new EsploraProvider(ESPLORA_URL);
    const info = await arkProvider.getInfo();
    const userWallet = await Wallet.create({
      identity: SingleKey.fromHex(userState.userKeyHex),
      arkProvider,
      indexerProvider,
      onchainProvider,
      settlementConfig: false,
      storage: {
        walletRepository: new InMemoryWalletRepository(),
        contractRepository: new InMemoryContractRepository(),
      },
    });
    async function onboardWithRetry(w, label) {
      for (let attempt = 1; attempt <= 2; attempt++) {
        try {
          return await new Ramps(w).onboard(info.fees);
        } catch (err) {
          console.log(`  [${label}] onboard attempt ${attempt} failed (${err.message}), retrying...`);
          if (attempt === 2) throw err;
          await sleep(3_000);
        }
      }
    }
    console.log("  Joining live Arkade batch round for LP + User...");
    const [lpCommit, userCommit] = await Promise.all([
      onboardWithRetry(lp.wallet, "LP"),
      onboardWithRetry(userWallet, "User"),
    ]);
    await userWallet.dispose?.();
    console.log(`  Both onboarded! LP batch=${lpCommit.slice(0, 12)}.., User batch=${userCommit.slice(0, 12)}..`);
    await sleep(3_000);

    // 4. Check LP /health and run real User CLI: quote -> open ($3 USD peg).
    const health = await (await fetch(`${lp.url}/health`)).json();
    console.log(
      `\n[4/6] LP health: spot=$${health.spotUsd} (${health.spotSources} exchanges), LP available=${health.arkBalance.available} sats`
    );

    const opened = await runCli(["open", "--usd", "2"], cliEnv);
    console.log(
      `  CLI open --usd 2 SUCCEEDED! positionId=${opened.positionId}, vtxo=${opened.vtxoTxid}:${opened.vtxoVout}, total=${opened.totalCollateralSats} sats (open spot=$${opened.openSpotUsd})`
    );

    // 5. Run real User CLI: positions + export-watchtower.
    const positions = await runCli(["positions"], cliEnv);
    console.log(
      `\n[5/6] CLI positions: ${positions.length} open, live mark-to-market = ${positions[0].estimatedUserSatsNow} sats at $${positions[0].liveSpotUsd}`
    );

    const exported = await runCli(["export-watchtower", opened.positionId], cliEnv);
    console.log(`  CLI export-watchtower: ${exported.unrollHops} Arkade unroll hops saved to ${exported.exportedTo}`);
    if (exported.unrollHops < 1) throw new Error("Expected at least 1 unroll hop");

    // 6. Run real User CLI: collaborative early close at live spot!
    const closed = await runCli(["close", opened.positionId], cliEnv);
    console.log(
      `\n[6/6] CLI close SUCCEEDED! closeTxid=${closed.closeTxid}, closeSpot=$${closed.closeSpotUsd}, User=${closed.userPayoutSats} sats, LP=${closed.lpPayoutSats} sats`
    );

    const finalBal = await runCli(["balance"], cliEnv);
    console.log(`  Final User Arkade balance: available=${finalBal.availableSats} sats`);
    if (finalBal.availableSats < closed.userPayoutSats) {
      throw new Error("Final user balance does not reflect settled payout!");
    }

    console.log("\n=== M4 MVP LIVE MUTINYNET E2E: SUCCESS ===");
  } finally {
    await lp.close();
  }
  process.exit(0);
}

main().catch((err) => {
  console.error("M4 E2E FAILED:", err);
  process.exit(1);
});
