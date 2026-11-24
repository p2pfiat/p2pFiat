#!/usr/bin/env node
/**
 * p2pFiat M4 User Wallet CLI on live Arkade Mutinynet.
 *
 * Commands:
 *   init                     Generate user key & local position store
 *   balance                  Show live Arkade offchain & boarding balance
 *   quote --usd <amount>     Fetch a live BTC/USD peg quote from the LP
 *   open  --usd <amount>     Trustlessly open a 2-party USD-pegged DLC on Arkade
 *   positions                List local USD-pegged positions & live mark-to-market
 *   close <positionId>       Collaboratively close a position at live BTC/USD spot
 *   export-watchtower <id>   Export real Arkade unroll chain for `ark-watchtower`
 */

import path from "node:path";
import fs from "node:fs";
import {
  Wallet,
  SingleKey,
  RestArkProvider,
  RestIndexerProvider,
  EsploraProvider,
  InMemoryWalletRepository,
  InMemoryContractRepository,
  VtxoScript,
  Transaction,
  toXOnly,
} from "@arkade-os/sdk";
import { hex, base64 } from "@scure/base";
import {
  keyFromHex,
  randomEvenKey,
  schnorrSign,
  tapLeafHash,
  tapscriptSighash,
  attachTapscriptSig,
  fetchBtcUsdSpot,
  computeUsdPayoutSats,
} from "./crypto.mjs";
import { buildDefaultArkScript, extractUnrollTxs } from "./contract.mjs";
import { JsonStore } from "./store.mjs";

const ARK_URL = process.env.ARK_URL || "https://mutinynet.arkade.sh";
const ESPLORA_URL = process.env.ESPLORA_URL || "https://mutinynet.com/api";
const LP_URL = process.env.LP_URL || "http://127.0.0.1:3456";
const DATA_DIR = process.env.USER_DATA_DIR || path.resolve(import.meta.dirname, "../data");

async function postJson(url, body) {
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const j = await r.json();
  if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`);
  return j;
}

async function openUserContext() {
  const store = new JsonStore(path.join(DATA_DIR, "user.json"), { userKeyHex: null, positions: {} });
  const d = store.read();
  if (!d.userKeyHex) throw new Error("User wallet not initialized (run `node src/cli.mjs init`)");
  const userKey = keyFromHex(d.userKeyHex);
  const arkProvider = new RestArkProvider(ARK_URL);
  const indexerProvider = new RestIndexerProvider(ARK_URL);
  const onchainProvider = new EsploraProvider(ESPLORA_URL);
  const info = await arkProvider.getInfo();
  const serverXOnly = toXOnly(hex.decode(info.signerPubkey));
  const exitDelaySecs = BigInt(info.unilateralExitDelay);

  const wallet = await Wallet.create({
    identity: SingleKey.fromHex(userKey.privHex),
    arkProvider,
    indexerProvider,
    onchainProvider,
    settlementConfig: false,
    storage: {
      walletRepository: new InMemoryWalletRepository(),
      contractRepository: new InMemoryContractRepository(),
    },
  });
  const userArkScript = buildDefaultArkScript(userKey.pubXOnly, serverXOnly, exitDelaySecs);
  return { store, userKey, wallet, arkProvider, indexerProvider, info, serverXOnly, exitDelaySecs, userArkScript };
}

function getFlag(args, name) {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}

async function main() {
  const [cmd, ...args] = process.argv.slice(2);
  if (!cmd || cmd === "--help" || cmd === "-h") {
    console.log("Usage: node src/cli.mjs <init|balance|quote|open|positions|close|export-watchtower>");
    process.exit(0);
  }

  if (cmd === "init") {
    const store = new JsonStore(path.join(DATA_DIR, "user.json"), { userKeyHex: null, positions: {} });
    let d = store.read();
    if (!d.userKeyHex) {
      d.userKeyHex = randomEvenKey().privHex;
      store.write(d);
    }
    const ctx = await openUserContext();
    console.log(
      JSON.stringify(
        {
          pubkey: ctx.userKey.pubHex,
          arkAddress: await ctx.wallet.getAddress(),
          boardingAddress: await ctx.wallet.getBoardingAddress(),
        },
        null,
        2
      )
    );
    await ctx.wallet.dispose?.();
    process.exit(0);
  }

  const ctx = await openUserContext();
  try {
    if (cmd === "balance") {
      const bal = await ctx.wallet.getBalance();
      console.log(
        JSON.stringify(
          {
            arkAddress: await ctx.wallet.getAddress(),
            boardingAddress: await ctx.wallet.getBoardingAddress(),
            availableSats: bal.available,
            settledSats: bal.settled,
            preconfirmedSats: bal.preconfirmed,
          },
          null,
          2
        )
      );
    } else if (cmd === "quote") {
      const usd = Number(getFlag(args, "--usd") || 2);
      const q = await postJson(`${LP_URL}/quote`, { notionalUsd: usd });
      console.log(JSON.stringify(q, null, 2));
    } else if (cmd === "open") {
      const usd = Number(getFlag(args, "--usd") || 2);
      const q = await postJson(`${LP_URL}/quote`, { notionalUsd: usd });

      const vtxos = await ctx.wallet.getVtxos();
      const userVtxo = vtxos
        .filter((v) => Number(v.value) >= q.userCollateralSats)
        .sort((a, b) => Number(b.value) - Number(a.value))[0];
      if (!userVtxo) {
        throw new Error(`No spendable user VTXO >= ${q.userCollateralSats} sats`);
      }

      const defaultLeaf = ctx.userArkScript.forfeit();
      const defaultLeafScript = defaultLeaf[1].slice(0, -1);
      const defaultLeafHash = tapLeafHash(defaultLeafScript);

      const prop = await postJson(`${LP_URL}/open/propose`, {
        quoteId: q.quoteId,
        userPubHex: ctx.userKey.pubHex,
        userInput: {
          txid: userVtxo.txid,
          vout: userVtxo.vout,
          value: Number(userVtxo.value),
          tapTreeHex: hex.encode(ctx.userArkScript.encode()),
          leafScriptHex: hex.encode(defaultLeafScript),
        },
        userChangeScriptHex: hex.encode(ctx.userArkScript.pkScript),
      });

      // Verify output 0 pays the exact contract script & totalCollateralSats before signing!
      const arkTx = Transaction.fromPSBT(base64.decode(prop.arkTxB64));
      const userCk = Transaction.fromPSBT(base64.decode(prop.userCkB64));
      const out0 = arkTx.getOutput(0);
      if (hex.encode(out0.script) !== prop.contractPkScriptHex || out0.amount !== BigInt(q.totalCollateralSats)) {
        throw new Error("LP proposal output 0 mismatch! Refusing to sign.");
      }

      // Sign User's input 0 on arkTx (2-input tx) and input 0 on userCk.
      const prevScripts = [arkTx.getInput(0).witnessUtxo.script, arkTx.getInput(1).witnessUtxo.script];
      const prevAmounts = [arkTx.getInput(0).witnessUtxo.amount, arkTx.getInput(1).witnessUtxo.amount];
      const arkHash = tapscriptSighash(arkTx, 0, prevScripts, prevAmounts, defaultLeafScript);
      const ckHash = tapscriptSighash(userCk, 0, [ctx.userArkScript.pkScript], [BigInt(userVtxo.value)], defaultLeafScript);

      attachTapscriptSig(arkTx, 0, ctx.userKey.pubXOnly, defaultLeafHash, schnorrSign(ctx.userKey, arkHash));
      attachTapscriptSig(userCk, 0, ctx.userKey.pubXOnly, defaultLeafHash, schnorrSign(ctx.userKey, ckHash));

      const pos = await postJson(`${LP_URL}/open/finalize`, {
        positionId: prop.positionId,
        signedArkTxB64: base64.encode(arkTx.toPSBT()),
        signedUserCkB64: base64.encode(userCk.toPSBT()),
      });

      ctx.store.update((d) => {
        d.positions[pos.positionId] = pos;
      });
      console.log(JSON.stringify(pos, null, 2));
    } else if (cmd === "positions") {
      const spot = await fetchBtcUsdSpot();
      const list = Object.values(ctx.store.read().positions).map((p) => ({
        ...p,
        liveSpotUsd: spot.price,
        estimatedUserSatsNow:
          p.status === "open"
            ? Number(computeUsdPayoutSats(p.notionalUsd, spot.price, BigInt(p.totalCollateralSats)))
            : p.userPayoutSats,
      }));
      console.log(JSON.stringify(list, null, 2));
    } else if (cmd === "close") {
      const positionId = args[0];
      if (!positionId) throw new Error("Usage: close <positionId>");
      const pos = ctx.store.read().positions[positionId];
      if (!pos) throw new Error(`Unknown local position ${positionId}`);

      const prop = await postJson(`${LP_URL}/close/propose`, { positionId });
      const arkTx = Transaction.fromPSBT(base64.decode(prop.arkTxB64));
      const ck = Transaction.fromPSBT(base64.decode(prop.ckB64));
      const settleScript = hex.decode(pos.settleScriptHex);
      const settleLeafHash = tapLeafHash(settleScript);
      const contractPkScript = hex.decode(pos.contractPkScriptHex);

      // Verify output 0 pays User's Ark script!
      if (hex.encode(arkTx.getOutput(0).script) !== hex.encode(ctx.userArkScript.pkScript)) {
        throw new Error("LP close proposal output 0 does not pay User! Refusing to sign.");
      }

      const ckHash = tapscriptSighash(ck, 0, [contractPkScript], [BigInt(pos.totalCollateralSats)], settleScript);
      const arkHash = tapscriptSighash(arkTx, 0, [ck.getOutput(0).script], [ck.getOutput(0).amount], settleScript);
      attachTapscriptSig(arkTx, 0, ctx.userKey.pubXOnly, settleLeafHash, schnorrSign(ctx.userKey, arkHash));
      attachTapscriptSig(ck, 0, ctx.userKey.pubXOnly, settleLeafHash, schnorrSign(ctx.userKey, ckHash));

      const closed = await postJson(`${LP_URL}/close/finalize`, {
        positionId,
        signedArkTxB64: base64.encode(arkTx.toPSBT()),
        signedCkB64: base64.encode(ck.toPSBT()),
      });
      ctx.store.update((d) => {
        d.positions[positionId] = closed;
      });
      console.log(JSON.stringify(closed, null, 2));
    } else if (cmd === "export-watchtower") {
      const positionId = args[0];
      if (!positionId) throw new Error("Usage: export-watchtower <positionId>");
      const pos = ctx.store.read().positions[positionId];
      if (!pos) throw new Error(`Unknown local position ${positionId}`);

      const unrollTxs = await extractUnrollTxs(ctx.indexerProvider, pos.vtxoTxid, pos.vtxoVout);
      const outPath = path.join(DATA_DIR, `watchtower-${positionId}.json`);
      const exportDoc = {
        positionId,
        vtxo_outpoint: `${pos.vtxoTxid}:${pos.vtxoVout}`,
        vtxo_amount_sats: pos.totalCollateralSats,
        vtxo_pk_script: pos.contractPkScriptHex,
        ark_indexer_url: ARK_URL,
        unroll_txs: unrollTxs,
        exit_script: pos.exitScriptHex,
        exit_csv_seconds: pos.exitDelaySecs,
        user_pubkey: pos.userPubHex,
        lp_pubkey: pos.lpPubHex,
      };
      fs.writeFileSync(outPath, JSON.stringify(exportDoc, null, 2));
      console.log(JSON.stringify({ exportedTo: outPath, unrollHops: unrollTxs.length }, null, 2));
    } else {
      throw new Error(`Unknown command: ${cmd}`);
    }
  } finally {
    await ctx.wallet.dispose?.();
  }
  process.exit(0);
}

main().catch((err) => {
  console.error("CLI ERROR:", err.message || err);
  process.exit(1);
});
