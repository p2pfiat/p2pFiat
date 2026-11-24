/**
 * p2pFiat M4 LP Service (HTTP) on live Arkade Mutinynet.
 *
 * Endpoints:
 *   GET  /health          - LP status, pubkey, live BTC/USD spot, Arkade balance
 *   POST /quote           - Request a BTC-collateralized USD-peg quote
 *   POST /open/propose    - Atomic 2-input Arkade funding tx proposal (User + LP -> DLC VTXO)
 *   POST /open/finalize   - Submit & finalize 2-party DLC funding tx on Arkade
 *   POST /close/propose   - Collaborative early close at live BTC/USD spot price
 *   POST /close/finalize  - Submit & finalize early close on Arkade
 *   GET  /positions       - List LP positions
 */

import http from "node:http";
import path from "node:path";
import crypto from "node:crypto";
import {
  Wallet,
  SingleKey,
  RestArkProvider,
  RestIndexerProvider,
  EsploraProvider,
  InMemoryWalletRepository,
  InMemoryContractRepository,
  VtxoScript,
  CSVMultisigTapscript,
  buildOffchainTx,
  combineTapscriptSigs,
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
import { buildDlcContractScript, buildDefaultArkScript } from "./contract.mjs";
import { JsonStore } from "./store.mjs";

const ARK_URL = process.env.ARK_URL || "https://mutinynet.arkade.sh";
const ESPLORA_URL = process.env.ESPLORA_URL || "https://mutinynet.com/api";
const DUST = 350n;

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let buf = "";
    req.on("data", (chunk) => (buf += chunk));
    req.on("end", () => {
      try {
        resolve(buf ? JSON.parse(buf) : {});
      } catch (e) {
        reject(new Error("Invalid JSON body"));
      }
    });
    req.on("error", reject);
  });
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj, null, 2);
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(body);
}

export async function createLpServer({
  port = 3456,
  dataDir = path.resolve(import.meta.dirname, "../data"),
  lpKeyHex,
} = {}) {
  const store = new JsonStore(path.join(dataDir, "lp.json"), {
    lpKeyHex: null,
    quotes: {},
    positions: {},
  });
  let state = store.read();
  if (!state.lpKeyHex) {
    state.lpKeyHex = lpKeyHex || randomEvenKey().privHex;
    store.write(state);
  }
  const lpKey = keyFromHex(lpKeyHex || state.lpKeyHex);

  const arkProvider = new RestArkProvider(ARK_URL);
  const indexerProvider = new RestIndexerProvider(ARK_URL);
  const onchainProvider = new EsploraProvider(ESPLORA_URL);
  const info = await arkProvider.getInfo();
  const serverXOnly = toXOnly(hex.decode(info.signerPubkey));
  const exitDelaySecs = BigInt(info.unilateralExitDelay);
  const checkpointTapscript = CSVMultisigTapscript.decode(hex.decode(info.checkpointTapscript));

  const wallet = await Wallet.create({
    identity: SingleKey.fromHex(lpKey.privHex),
    arkProvider,
    indexerProvider,
    onchainProvider,
    settlementConfig: false,
    storage: {
      walletRepository: new InMemoryWalletRepository(),
      contractRepository: new InMemoryContractRepository(),
    },
  });
  const lpArkScript = buildDefaultArkScript(lpKey.pubXOnly, serverXOnly, exitDelaySecs);
  const lpDefaultSettleLeaf = lpArkScript.forfeit();
  const lpDefaultLeafScript = lpDefaultSettleLeaf[1].slice(0, -1); // strip 0xc0 leaf version byte
  const lpDefaultLeafHash = tapLeafHash(lpDefaultLeafScript);

  // In-memory pending proposals (open/close) keyed by positionId
  const pendingOpen = new Map();
  const pendingClose = new Map();

  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, `http://127.0.0.1:${port}`);

      if (req.method === "GET" && url.pathname === "/health") {
        const spot = await fetchBtcUsdSpot();
        const bal = await wallet.getBalance();
        const arkAddress = await wallet.getAddress();
        return sendJson(res, 200, {
          ok: true,
          network: info.network,
          arkUrl: ARK_URL,
          lpPubkey: lpKey.pubHex,
          lpArkAddress: arkAddress,
          spotUsd: spot.price,
          spotSources: spot.sources,
          arkBalance: { available: bal.available, settled: bal.settled, preconfirmed: bal.preconfirmed },
          openPositions: Object.values(store.read().positions).filter((p) => p.status === "open").length,
        });
      }

      if (req.method === "GET" && url.pathname === "/positions") {
        return sendJson(res, 200, { positions: Object.values(store.read().positions) });
      }

      if (req.method === "POST" && url.pathname === "/quote") {
        const body = await readJsonBody(req);
        const notionalUsd = Number(body.notionalUsd);
        const termSecs = Number(body.termSecs || 86_400);
        if (!Number.isFinite(notionalUsd) || notionalUsd <= 0) {
          return sendJson(res, 400, { error: "notionalUsd must be > 0" });
        }
        const spot = await fetchBtcUsdSpot();
        const userCollateralSats = Math.max(1_000, Math.round((notionalUsd / spot.price) * 1e8));
        const lpCollateralSats = userCollateralSats; // 1:1 matching collateral (±50% / ±25% peg)
        const quote = {
          quoteId: `q-${crypto.randomBytes(6).toString("hex")}`,
          notionalUsd,
          spotUsd: spot.price,
          termSecs,
          fundingRateBpsPerDay: 10,
          userCollateralSats,
          lpCollateralSats,
          totalCollateralSats: userCollateralSats + lpCollateralSats,
          lpPubkey: lpKey.pubHex,
          expiresAt: Math.floor(Date.now() / 1000) + 120,
        };
        store.update((d) => {
          d.quotes[quote.quoteId] = quote;
        });
        return sendJson(res, 200, quote);
      }

      if (req.method === "POST" && url.pathname === "/open/propose") {
        const body = await readJsonBody(req);
        const d = store.read();
        const quote = d.quotes[body.quoteId];
        if (!quote) return sendJson(res, 404, { error: "unknown quoteId" });
        if (Math.floor(Date.now() / 1000) > quote.expiresAt) {
          return sendJson(res, 400, { error: "quote expired" });
        }

        const userPubXOnly = hex.decode(body.userPubHex);
        const { vtxoScript: contractScript, settleClosure, exitClosure } = buildDlcContractScript(
          userPubXOnly,
          lpKey.pubXOnly,
          serverXOnly,
          exitDelaySecs
        );

        // Select a spendable LP VTXO covering lpCollateralSats.
        const lpVtxos = await wallet.getVtxos();
        const lpVtxo = lpVtxos
          .filter((v) => Number(v.value) >= quote.lpCollateralSats)
          .sort((a, b) => Number(b.value) - Number(a.value))[0];
        if (!lpVtxo) {
          return sendJson(res, 503, { error: `LP lacks a VTXO >= ${quote.lpCollateralSats} sats` });
        }

        // Reconstruct User's input VtxoScript & tapLeafScript.
        const userVtxoScript = VtxoScript.decode(hex.decode(body.userInput.tapTreeHex));
        const userTapLeaf = userVtxoScript.findLeaf(body.userInput.leafScriptHex);
        const userArkInput = {
          txid: body.userInput.txid,
          vout: Number(body.userInput.vout),
          value: Number(body.userInput.value),
          tapLeafScript: userTapLeaf,
          tapTree: userVtxoScript.encode(),
        };
        const lpArkInput = {
          txid: lpVtxo.txid,
          vout: lpVtxo.vout,
          value: Number(lpVtxo.value),
          tapLeafScript: lpDefaultSettleLeaf,
          tapTree: lpArkScript.encode(),
        };

        const outputs = [
          { script: contractScript.pkScript, amount: BigInt(quote.totalCollateralSats) },
        ];
        const userChange = BigInt(userArkInput.value) - BigInt(quote.userCollateralSats);
        if (userChange < 0n) return sendJson(res, 400, { error: "userInput smaller than userCollateralSats" });
        if (userChange >= DUST) {
          outputs.push({ script: hex.decode(body.userChangeScriptHex), amount: userChange });
        }
        const lpChange = BigInt(lpArkInput.value) - BigInt(quote.lpCollateralSats);
        if (lpChange >= DUST) {
          outputs.push({ script: lpArkScript.pkScript, amount: lpChange });
        }

        const { arkTx, checkpoints } = buildOffchainTx([userArkInput, lpArkInput], outputs, checkpointTapscript);
        const [userCk, lpCk] = checkpoints;

        // LP signs input 1 on arkTx and input 0 on lpCk.
        const prevScripts = [userCk.getOutput(0).script, lpCk.getOutput(0).script];
        const prevAmounts = [userCk.getOutput(0).amount, lpCk.getOutput(0).amount];
        const lpArkHash = tapscriptSighash(arkTx, 1, prevScripts, prevAmounts, lpDefaultLeafScript);
        const lpCkHash = tapscriptSighash(lpCk, 0, [lpArkScript.pkScript], [BigInt(lpArkInput.value)], lpDefaultLeafScript);

        attachTapscriptSig(arkTx, 1, lpKey.pubXOnly, lpDefaultLeafHash, schnorrSign(lpKey, lpArkHash));
        const lpCkUnsignedB64 = base64.encode(lpCk.toPSBT());
        const lpCkSigned = Transaction.fromPSBT(base64.decode(lpCkUnsignedB64));
        attachTapscriptSig(lpCkSigned, 0, lpKey.pubXOnly, lpDefaultLeafHash, schnorrSign(lpKey, lpCkHash));

        const positionId = `pos-${crypto.randomBytes(6).toString("hex")}`;
        pendingOpen.set(positionId, {
          quote,
          userPubHex: body.userPubHex,
          contractScriptHex: hex.encode(contractScript.pkScript),
          contractTapTreeHex: hex.encode(contractScript.encode()),
          settleScriptHex: hex.encode(settleClosure.script),
          exitScriptHex: hex.encode(exitClosure.script),
          userCkUnsignedB64: base64.encode(userCk.toPSBT()),
          lpCkUnsignedB64,
          lpCkSigned,
        });

        return sendJson(res, 200, {
          positionId,
          contractAddress: contractScript.address("tark", serverXOnly).encode(),
          contractPkScriptHex: hex.encode(contractScript.pkScript),
          arkTxB64: base64.encode(arkTx.toPSBT()),
          userCkB64: base64.encode(userCk.toPSBT()),
        });
      }

      if (req.method === "POST" && url.pathname === "/open/finalize") {
        const body = await readJsonBody(req);
        const pend = pendingOpen.get(body.positionId);
        if (!pend) return sendJson(res, 404, { error: "unknown pending positionId" });

        const sub = await arkProvider.submitTx(body.signedArkTxB64, [
          pend.userCkUnsignedB64,
          pend.lpCkUnsignedB64,
        ]);

        const serverCk0 = Transaction.fromPSBT(base64.decode(sub.signedCheckpointTxs[0]));
        const serverCk1 = Transaction.fromPSBT(base64.decode(sub.signedCheckpointTxs[1]));
        const userCkSigned = Transaction.fromPSBT(base64.decode(body.signedUserCkB64));

        const finalCk0 = combineTapscriptSigs(userCkSigned, serverCk0);
        const finalCk1 = combineTapscriptSigs(pend.lpCkSigned, serverCk1);
        await arkProvider.finalizeTx(sub.arkTxid, [
          base64.encode(finalCk0.toPSBT()),
          base64.encode(finalCk1.toPSBT()),
        ]);

        pendingOpen.delete(body.positionId);
        const position = {
          positionId: body.positionId,
          status: "open",
          openedAt: Math.floor(Date.now() / 1000),
          vtxoTxid: sub.arkTxid,
          vtxoVout: 0,
          notionalUsd: pend.quote.notionalUsd,
          openSpotUsd: pend.quote.spotUsd,
          userCollateralSats: pend.quote.userCollateralSats,
          lpCollateralSats: pend.quote.lpCollateralSats,
          totalCollateralSats: pend.quote.totalCollateralSats,
          userPubHex: pend.userPubHex,
          lpPubHex: lpKey.pubHex,
          contractPkScriptHex: pend.contractScriptHex,
          contractTapTreeHex: pend.contractTapTreeHex,
          settleScriptHex: pend.settleScriptHex,
          exitScriptHex: pend.exitScriptHex,
          exitDelaySecs: Number(exitDelaySecs),
        };
        store.update((d) => {
          d.positions[position.positionId] = position;
        });
        return sendJson(res, 200, position);
      }

      if (req.method === "POST" && url.pathname === "/close/propose") {
        const body = await readJsonBody(req);
        const pos = store.read().positions[body.positionId];
        if (!pos) return sendJson(res, 404, { error: "unknown positionId" });
        if (pos.status !== "open") return sendJson(res, 400, { error: `position is ${pos.status}` });

        const spot = await fetchBtcUsdSpot(pos.openSpotUsd);
        const closeSpotUsd = body.overrideSpotUsd ? Number(body.overrideSpotUsd) : spot.price;
        const userPayout = computeUsdPayoutSats(
          pos.notionalUsd,
          closeSpotUsd,
          BigInt(pos.totalCollateralSats),
          DUST
        );
        const lpPayout = BigInt(pos.totalCollateralSats) - userPayout;

        const contractScript = VtxoScript.decode(hex.decode(pos.contractTapTreeHex));
        const settleScript = hex.decode(pos.settleScriptHex);
        const settleLeaf = contractScript.findLeaf(pos.settleScriptHex);
        const settleLeafHash = tapLeafHash(settleScript);
        const userArkScript = buildDefaultArkScript(hex.decode(pos.userPubHex), serverXOnly, exitDelaySecs);

        const { arkTx, checkpoints } = buildOffchainTx(
          [
            {
              txid: pos.vtxoTxid,
              vout: pos.vtxoVout,
              value: pos.totalCollateralSats,
              tapLeafScript: settleLeaf,
              tapTree: contractScript.encode(),
            },
          ],
          [
            { script: userArkScript.pkScript, amount: userPayout },
            { script: lpArkScript.pkScript, amount: lpPayout },
          ],
          checkpointTapscript
        );
        const ck = checkpoints[0];
        const ckHash = tapscriptSighash(ck, 0, [contractScript.pkScript], [BigInt(pos.totalCollateralSats)], settleScript);
        const arkHash = tapscriptSighash(arkTx, 0, [ck.getOutput(0).script], [ck.getOutput(0).amount], settleScript);

        attachTapscriptSig(arkTx, 0, lpKey.pubXOnly, settleLeafHash, schnorrSign(lpKey, arkHash));
        const ckUnsignedB64 = base64.encode(ck.toPSBT());
        const lpCkSig = schnorrSign(lpKey, ckHash);

        pendingClose.set(pos.positionId, {
          pos,
          closeSpotUsd,
          userPayoutSats: Number(userPayout),
          lpPayoutSats: Number(lpPayout),
          ckUnsignedB64,
          lpCkSig,
          settleLeafHash,
        });

        return sendJson(res, 200, {
          positionId: pos.positionId,
          closeSpotUsd,
          userPayoutSats: Number(userPayout),
          lpPayoutSats: Number(lpPayout),
          arkTxB64: base64.encode(arkTx.toPSBT()),
          ckB64: ckUnsignedB64,
        });
      }

      if (req.method === "POST" && url.pathname === "/close/finalize") {
        const body = await readJsonBody(req);
        const pend = pendingClose.get(body.positionId);
        if (!pend) return sendJson(res, 404, { error: "unknown pending close" });

        const sub = await arkProvider.submitTx(body.signedArkTxB64, [pend.ckUnsignedB64]);
        const serverCk = Transaction.fromPSBT(base64.decode(sub.signedCheckpointTxs[0]));
        const userCkSigned = Transaction.fromPSBT(base64.decode(body.signedCkB64));
        attachTapscriptSig(userCkSigned, 0, lpKey.pubXOnly, pend.settleLeafHash, pend.lpCkSig);
        const finalCk = combineTapscriptSigs(userCkSigned, serverCk);
        await arkProvider.finalizeTx(sub.arkTxid, [base64.encode(finalCk.toPSBT())]);

        pendingClose.delete(body.positionId);
        const closed = store.update((d) => {
          const p = d.positions[body.positionId];
          p.status = "closed";
          p.closedAt = Math.floor(Date.now() / 1000);
          p.closeSpotUsd = pend.closeSpotUsd;
          p.closeTxid = sub.arkTxid;
          p.userPayoutSats = pend.userPayoutSats;
          p.lpPayoutSats = pend.lpPayoutSats;
          return p;
        });
        return sendJson(res, 200, closed);
      }

      sendJson(res, 404, { error: "not found" });
    } catch (err) {
      sendJson(res, 500, { error: err?.message || String(err) });
    }
  });

  await new Promise((resolve) => server.listen(port, "127.0.0.1", resolve));
  return {
    server,
    port,
    url: `http://127.0.0.1:${port}`,
    lpKey,
    wallet,
    store,
    close: async () => {
      await wallet.dispose?.();
      await new Promise((resolve) => server.close(resolve));
    },
  };
}

// Run standalone if invoked directly (`node src/lp.mjs`)
if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(import.meta.filename)) {
  const port = Number(process.env.LP_PORT || 3456);
  const lp = await createLpServer({ port });
  console.log(`p2pFiat LP listening on ${lp.url}`);
  console.log(`  LP pubkey      : ${lp.lpKey.pubHex}`);
  console.log(`  LP Ark address : ${await lp.wallet.getAddress()}`);
  console.log(`  LP boarding    : ${await lp.wallet.getBoardingAddress()}`);
}
