/**
 * p2pFiat M4/M5 LP Service (HTTP + Serverless NIP-17 P2P) on live Arkade Mutinynet.
 *
 * Transports:
 *   - HTTP (optional, disable with `LP_NO_HTTP=1` or `enableHttp: false`)
 *   - NIP-17 encrypted Gift-Wrapped Nostr DMs (`kind: 1059`) over Nostr relays
 *
 * RPC Methods (identical over HTTP and NIP-17):
 *   health          (GET  /health)
 *   quote           (POST /quote)
 *   open/propose    (POST /open/propose)
 *   open/finalize   (POST /open/finalize)
 *   close/propose   (POST /close/propose)
 *   close/finalize  (POST /close/finalize)
 *   positions       (GET  /positions)
 *   offer           (GET  /offer)
 */

import http from "node:http";
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
  fetchBtcSpot,
  fetchBtcUsdSpot,
  computeFiatPayoutSats,
  computeUsdPayoutSats,
} from "./crypto.mjs";
import {
  buildDlcContractScript,
  buildDefaultArkScript,
  buildLpExitSuite,
  computeDisputeManifestHash,
} from "./contract.mjs";
import * as btc from "@scure/btc-signer";
import { JsonStore } from "./store.mjs";
import {
  DEFAULT_RELAYS,
  DEFAULT_NOSTRACLE_QUORUM,
  pubkeyHexToNpub,
  npubToPubkeyHex,
  createSignedOfferEvent,
  publishOfferToRelays,
} from "./offerbook.mjs";
import { Nip17Peer } from "./nip17.mjs";
import { fetchLatestNostracleAnnouncement } from "./nostracle-client.mjs";

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
      } catch {
        reject(new Error("Invalid JSON body"));
      }
    });
    req.on("error", reject);
  });
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj, null, 2);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  });
  res.end(body);
}

class RpcError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function parseNostracleQuorumEnv() {
  const raw = process.env.NOSTRACLE_NPUBS;
  if (!raw) return DEFAULT_NOSTRACLE_QUORUM;
  const items = raw.split(",").map((s) => s.trim()).filter(Boolean);
  if (items.length === 0) return DEFAULT_NOSTRACLE_QUORUM;
  const oracles = items.map((item, idx) => {
    const pubkey = item.startsWith("npub1") ? npubToPubkeyHex(item) : item;
    const npub = item.startsWith("npub1") ? item : pubkeyHexToNpub(item);
    return { name: `Nostracle-${idx + 1}`, pubkey, npub };
  });
  return { threshold: Math.min(2, oracles.length), oracles };
}

/**
 * Parse optional extra LP offer tiers (`LP_EXTRA_OFFERS`), comma-separated as
 * `<termSecs>:<fundingRateBpsPerDay>[:<spreadBps>]` (e.g. `3600:0.27` for a 1h ~1% APR tier).
 * Always starts with the primary tier and deduplicates by `termSecs`.
 */
export function parseOfferTiers(
  raw,
  { termSecs = 86_400, fundingRateBpsPerDay = 3, spreadBps = 1 } = {}
) {
  const primary = {
    termSecs: Math.max(60, Math.round(Number(termSecs) || 86_400)),
    fundingRateBpsPerDay: Number(fundingRateBpsPerDay),
    spreadBps: Math.max(0, Number(spreadBps)),
  };
  const tiers = [primary];
  const seenTerms = new Set([primary.termSecs]);
  const text = String(raw || "").trim();
  if (!text) return tiers;
  for (const part of text.split(",")) {
    const item = part.trim();
    if (!item) continue;
    const [tStr, fStr, sStr] = item.split(":").map((s) => s.trim());
    const t = Math.round(Number(tStr));
    const f = Number(fStr);
    const s = sStr !== undefined && sStr !== "" ? Number(sStr) : primary.spreadBps;
    if (!Number.isFinite(t) || t < 60) continue;
    if (!Number.isFinite(f)) continue;
    if (!Number.isFinite(s) || s < 0) continue;
    if (seenTerms.has(t)) continue;
    seenTerms.add(t);
    tiers.push({ termSecs: t, fundingRateBpsPerDay: f, spreadBps: s });
  }
  return tiers;
}

/**
 * Filter stored LP positions for the `positions` RPC so NIP-17 callers can query
 * only their own positions (staying well within NIP-44's 65 KB plaintext limit).
 */
export function filterPositionsQuery(positions, query = {}) {
  let list = Array.isArray(positions) ? [...positions] : [];
  const reqUser = String(query?.userPubHex || "").trim().toLowerCase();
  const reqId = String(query?.positionId || "").trim();
  const reqTxid = String(query?.vtxoTxid || "").trim().toLowerCase();
  const reqStatus = String(query?.status || "").trim().toLowerCase();
  if (reqUser) {
    list = list.filter((p) => String(p?.userPubHex || "").toLowerCase() === reqUser);
  }
  if (reqId) {
    list = list.filter((p) => p?.positionId === reqId);
  }
  if (reqTxid) {
    list = list.filter(
      (p) =>
        String(p?.vtxoTxid || "").toLowerCase() === reqTxid ||
        String(p?.prevVtxoTxid || "").toLowerCase() === reqTxid
    );
  }
  if (reqStatus) {
    list = list.filter((p) => String(p?.status || "").toLowerCase() === reqStatus);
  }
  list.sort((a, b) => Number(b?.openedAt || 0) - Number(a?.openedAt || 0));
  const limit = Number(query?.limit || 0);
  if (Number.isInteger(limit) && limit > 0) {
    list = list.slice(0, limit);
  }
  return list;
}

export async function createLpServer({
  port = 3456,
  enableHttp = true,
  dataDir = path.resolve(import.meta.dirname, "../data"),
  lpKeyHex,
  lpName = process.env.LP_NAME || "p2pFiat-LP",
  pairs = ["BTC-USD", "BTC-EUR"],
  spreadBps = Number(process.env.LP_SPREAD_BPS || 1),
  fundingRateBpsPerDay = Number(process.env.LP_FUNDING_BPS || 3),
  termSecs: defaultTermSecs = Number(process.env.LP_TERM_SECS || 86_400),
  offerTiers = parseOfferTiers(process.env.LP_EXTRA_OFFERS, {
    termSecs: Number(process.env.LP_TERM_SECS || 86_400),
    fundingRateBpsPerDay: Number(process.env.LP_FUNDING_BPS || 3),
    spreadBps: Number(process.env.LP_SPREAD_BPS || 1),
  }),
  oracleQuorum = parseNostracleQuorumEnv(),
  relays = [],
  publicUrl,
  publishIntervalMs = 45_000,
} = {}) {
  const tiers =
    Array.isArray(offerTiers) && offerTiers.length > 0
      ? offerTiers
      : [{ termSecs: defaultTermSecs, fundingRateBpsPerDay, spreadBps }];
  const findTierForTerm = (reqTermSecs) => {
    const n = Number(reqTermSecs);
    return tiers.find((t) => t.termSecs === n) || tiers[0];
  };
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

  const pendingOpen = new Map();
  const pendingRoll = new Map();
  const pendingClose = new Map();
  let latestOfferEvents = {};
  let actualPort = enableHttp ? port : 0;

  async function buildAndPublishOffer() {
    const [spotUsd, spotEur, bal] = await Promise.all([
      fetchBtcSpot("USD"),
      fetchBtcSpot("EUR"),
      wallet.getBalance(),
    ]);
    const spotsByCur = { USD: spotUsd.price, EUR: spotEur.price };
    const endpointUrl = enableHttp ? publicUrl || `http://127.0.0.1:${actualPort}` : "";
    const transports = [];
    if (enableHttp) transports.push("http");
    if (relays.length > 0) transports.push("nostr-nip17");

    const events = [];
    const okRelaySet = new Set();
    const failedRelays = [];
    const liveNip17Relays =
      nip17Peer?.getConnectedRelays?.().length > 0 ? nip17Peer.getConnectedRelays() : relays;

    for (const pair of pairs) {
      const currency = pair.includes("-") ? pair.split("-")[1].toUpperCase() : "USD";
      const spotPrice = spotsByCur[currency] || spotUsd.price;
      for (const tier of tiers) {
        const bidPrice = Math.round(spotPrice * (1 - tier.spreadBps / 10_000));
        const askPrice = Math.round(spotPrice * (1 + tier.spreadBps / 10_000));
        const dTag =
          tier.termSecs === 86_400
            ? `p2pfiat:v1:${pair}:arkade-mutinynet`
            : `p2pfiat:v1:${pair}:arkade-mutinynet:${tier.termSecs}s`;
        const event = createSignedOfferEvent(lpKey, {
          lpName,
          pair,
          currency,
          dTag,
          spotPrice,
          spotUsd: spotPrice,
          bidPrice,
          askPrice,
          bidUsd: bidPrice,
          askUsd: askPrice,
          spreadBps: tier.spreadBps,
          fundingRateBpsPerDay: tier.fundingRateBpsPerDay,
          minNotionalUsd: 1,
          maxNotionalUsd: 100,
          availableLiquiditySats: Number(bal.available || 0),
          termSecs: tier.termSecs,
          endpointUrl,
          transports,
          nip17Relays: liveNip17Relays,
          oracleQuorum,
        });
        if (!latestOfferEvents[pair] || tier.termSecs === tiers[0].termSecs) {
          latestOfferEvents[pair] = event;
        }
        latestOfferEvents[`${pair}:${tier.termSecs}`] = event;
        events.push(event);
        if (relays.length > 0) {
          const res = await publishOfferToRelays(event, relays);
          for (const r of res.okRelays) okRelaySet.add(r);
          failedRelays.push(...res.failedRelays);
        }
      }
    }
    return {
      event: events[0] || null,
      events,
      relayResult: { okRelays: [...okRelaySet], failedRelays },
    };
  }

  // Transport-agnostic LP RPC dispatcher (shared by HTTP and NIP-17 encrypted DMs)
  async function handleRpc(method, body = {}, senderPubkey = "") {
    if (method === "faucet") {
      const net = String(info.network || "mutinynet").toLowerCase();
      if (net === "bitcoin" || net === "mainnet") {
        throw new RpcError(403, "Faucet is strictly disabled on Bitcoin mainnet");
      }
      const arkAddress = String(body.arkAddress || "").trim();
      if (!arkAddress.startsWith("tark1")) {
        throw new RpcError(400, "Invalid Mutinynet Arkade address (expected tark1…)");
      }
      const claimKey = (senderPubkey || arkAddress).toLowerCase();
      const d = store.read();
      const prev = d.faucetClaims?.[claimKey];
      if (prev) {
        throw new RpcError(409, `Faucet already claimed for this identity (txid ${prev.txid})`);
      }
      const FAUCET_USD = 10;
      const MIN_LP_RESERVE_SATS = 20_000;
      const [spot, bal] = await Promise.all([fetchBtcSpot("USD"), wallet.getBalance()]);
      const effectiveSpot = spot.price * (1 - spreadBps / 10_000);
      // Compute exact sats needed for $10 Stable USD + 500-sat volatility/spread buffer, clamped to [5k, 35k].
      const rawNeeded = Math.ceil((FAUCET_USD / effectiveSpot) * 1e8) + 500;
      const faucetSats = Math.max(5_000, Math.min(35_000, rawNeeded));
      // Ensure LP has enough liquidity for both the faucet grant AND matching the user's $10 DLC open.
      if (Number(bal.available || 0) < faucetSats * 2 + MIN_LP_RESERVE_SATS) {
        throw new RpcError(503, "LP faucet reserve low — try again shortly");
      }
      const txid = await wallet.send({ address: arkAddress, amount: faucetSats });
      store.update((st) => {
        if (!st.faucetClaims) st.faucetClaims = {};
        st.faucetClaims[claimKey] = {
          txid,
          arkAddress,
          amountSats: faucetSats,
          targetUsd: FAUCET_USD,
          spotUsd: spot.price,
          claimedAt: Math.floor(Date.now() / 1000),
        };
      });
      console.log(
        `  LP faucet      : sent ${faucetSats} sats ($${FAUCET_USD} @ $${spot.price}) -> ${arkAddress.slice(0, 18)}… (${txid})`
      );
      return { ok: true, txid, amountSats: faucetSats, targetUsd: FAUCET_USD, spotUsd: spot.price, arkAddress };
    }

    if (method === "health") {
      const [spotUsd, spotEur, bal, arkAddress] = await Promise.all([
        fetchBtcSpot("USD"),
        fetchBtcSpot("EUR"),
        wallet.getBalance(),
        wallet.getAddress(),
      ]);
      return {
        ok: true,
        lpName,
        pairs,
        spreadBps,
        fundingRateBpsPerDay,
        offerTiers: tiers,
        oracleQuorum,
        relays,
        transports: [
          ...(enableHttp ? ["http"] : []),
          ...(relays.length > 0 ? ["nostr-nip17"] : []),
        ],
        network: info.network,
        arkUrl: ARK_URL,
        lpPubkey: lpKey.pubHex,
        lpArkAddress: arkAddress,
        spotUsd: spotUsd.price,
        spotEur: spotEur.price,
        spots: { USD: spotUsd.price, EUR: spotEur.price },
        spotSources: spotUsd.sources,
        arkBalance: { available: bal.available, settled: bal.settled, preconfirmed: bal.preconfirmed },
        openPositions: Object.values(store.read().positions).filter((p) => p.status === "open").length,
      };
    }

    if (method === "offer") {
      if (Object.keys(latestOfferEvents).length === 0) await buildAndPublishOffer();
      const pair = body.pair || "BTC-USD";
      return latestOfferEvents[pair] || Object.values(latestOfferEvents)[0];
    }

    if (method === "positions") {
      return { positions: filterPositionsQuery(Object.values(store.read().positions), body) };
    }

    if (method === "quote") {
      const currency = String(body.currency || "USD").toUpperCase();
      if (currency !== "USD" && currency !== "EUR") {
        throw new RpcError(400, `unsupported currency: ${currency}`);
      }
      const side = String(body.side || "short").toLowerCase() === "long" ? "long" : "short";
      const pair = `BTC-${currency}`;
      const notional = Number(body.notional ?? body.notionalUsd);
      const termSecs = Number(body.termSecs || tiers[0].termSecs);
      if (!Number.isFinite(notional) || notional <= 0) {
        throw new RpcError(400, "notional must be > 0");
      }
      const tier = findTierForTerm(termSecs);
      const spot = await fetchBtcSpot(currency);
      const effectiveSpot =
        side === "long"
          ? Math.round(spot.price * (1 + tier.spreadBps / 10_000))
          : Math.round(spot.price * (1 - tier.spreadBps / 10_000));
      const sideFundingBps = side === "long" ? -tier.fundingRateBpsPerDay : tier.fundingRateBpsPerDay;
      const userCollateralSats = Math.max(1_000, Math.round((notional / effectiveSpot) * 1e8));
      const lpCollateralSats = userCollateralSats;
      const quote = {
        quoteId: `q-${crypto.randomBytes(6).toString("hex")}`,
        lpName,
        side,
        leverage: side === "long" ? 2 : 1,
        liquidationPrice: side === "long" ? Math.round(effectiveSpot * 0.5) : 0,
        currency,
        pair,
        notional,
        notionalUsd: notional,
        spotPrice: spot.price,
        spotUsd: spot.price,
        effectiveSpotUsd: effectiveSpot,
        spreadBps: tier.spreadBps,
        termSecs,
        fundingRateBpsPerDay: sideFundingBps,
        userCollateralSats,
        lpCollateralSats,
        totalCollateralSats: userCollateralSats + lpCollateralSats,
        lpPubkey: lpKey.pubHex,
        oracleQuorum,
        expiresAt: Math.floor(Date.now() / 1000) + 120,
      };
      store.update((d) => {
        d.quotes[quote.quoteId] = quote;
      });
      return quote;
    }

    if (method === "open/propose") {
      const d = store.read();
      const quote = d.quotes[body.quoteId];
      if (!quote) throw new RpcError(404, "unknown quoteId");
      if (Math.floor(Date.now() / 1000) > quote.expiresAt) {
        throw new RpcError(400, "quote expired");
      }

      const userPubXOnly = hex.decode(body.userPubHex);
      const posQuorum = quote.oracleQuorum || oracleQuorum;
      const { vtxoScript: contractScript, settleClosure, exitClosure, disputeClosure } = buildDlcContractScript(
        userPubXOnly,
        lpKey.pubXOnly,
        serverXOnly,
        exitDelaySecs,
        posQuorum
      );
      const disputeControlBlockHex = disputeClosure
        ? hex.encode(
            btc.TaprootControlBlock.encode(
              contractScript.findLeaf(disputeClosure.scriptHex)[0]
            )
          )
        : null;

      const lpVtxos = await wallet.getVtxos();
      const lpVtxo = lpVtxos
        .filter((v) => Number(v.value) >= quote.lpCollateralSats)
        .sort((a, b) => Number(b.value) - Number(a.value))[0];
      if (!lpVtxo) {
        throw new RpcError(503, `LP lacks a VTXO >= ${quote.lpCollateralSats} sats`);
      }

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
      if (userChange < 0n) throw new RpcError(400, "userInput smaller than userCollateralSats");
      if (userChange >= DUST) {
        outputs.push({ script: hex.decode(body.userChangeScriptHex), amount: userChange });
      }
      const lpChange = BigInt(lpArkInput.value) - BigInt(quote.lpCollateralSats);
      if (lpChange >= DUST) {
        outputs.push({ script: lpArkScript.pkScript, amount: lpChange });
      }

      const { arkTx, checkpoints } = buildOffchainTx([userArkInput, lpArkInput], outputs, checkpointTapscript);
      const [userCk, lpCk] = checkpoints;

      const prevScripts = [userCk.getOutput(0).script, lpCk.getOutput(0).script];
      const prevAmounts = [userCk.getOutput(0).amount, lpCk.getOutput(0).amount];
      const lpArkHash = tapscriptSighash(arkTx, 1, prevScripts, prevAmounts, lpDefaultLeafScript);
      const lpCkHash = tapscriptSighash(lpCk, 0, [lpArkScript.pkScript], [BigInt(lpArkInput.value)], lpDefaultLeafScript);

      attachTapscriptSig(arkTx, 1, lpKey.pubXOnly, lpDefaultLeafHash, schnorrSign(lpKey, lpArkHash));
      const lpCkUnsignedB64 = base64.encode(lpCk.toPSBT());
      const lpCkSigned = Transaction.fromPSBT(base64.decode(lpCkUnsignedB64));
      attachTapscriptSig(lpCkSigned, 0, lpKey.pubXOnly, lpDefaultLeafHash, schnorrSign(lpKey, lpCkHash));

      const positionId = `pos-${crypto.randomBytes(6).toString("hex")}`;
      const openedAt = Math.floor(Date.now() / 1000);
      const primaryOracle = (quote.oracleQuorum || oracleQuorum)?.oracles?.[0];
      const cur = (quote.currency || "USD").toUpperCase();
      const maturityEpoch = openedAt + Number(quote.termSecs || 86_400);
      const oracleEventId = `btc${cur.toLowerCase()}-${maturityEpoch}`;
      const refundLockTime = openedAt + 7 * 86_400;
      const useLeanDisputeMode = Boolean(disputeClosure);
      let disputeManifest = null;
      if (useLeanDisputeMode) {
        const userPayoutScriptHex = hex.encode(
          btc.p2tr(userPubXOnly, undefined, btc.TEST_NETWORK).script
        );
        const lpPayoutScriptHex = hex.encode(
          btc.p2tr(lpKey.pubXOnly, undefined, btc.TEST_NETWORK).script
        );
        const manifestFields = {
          contract_id: positionId,
          vtxo_outpoint: `${arkTx.id}:0`,
          currency: cur,
          side: quote.side || "short",
          total_collateral_sats: Number(quote.totalCollateralSats),
          notional_fiat: Number(quote.notional ?? quote.notionalUsd),
          opened_at: openedAt,
          funding_rate_bps_per_day: Number(quote.fundingRateBpsPerDay),
          user_pubkey_hex: body.userPubHex.toLowerCase(),
          lp_pubkey_hex: lpKey.pubHex.toLowerCase(),
          vtxo_pk_script_hex: hex.encode(contractScript.pkScript),
          // v2: commit to every k-of-n subset leaf so any k online oracles can sign a
          // dispute (p2pfiat/p2pFiat#20). dispute_script_hex stays as the primary leaf.
          manifest_version: 2,
          dispute_script_hex: disputeClosure.scriptHex,
          dispute_leaf_hashes_hex: disputeClosure.leafHashesHex,
          user_payout_script_hex: userPayoutScriptHex,
          lp_payout_script_hex: lpPayoutScriptHex,
        };
        const mHash = computeDisputeManifestHash(manifestFields);
        disputeManifest = {
          ...manifestFields,
          lp_manifest_sig_hex: hex.encode(schnorrSign(lpKey, mHash)),
        };
      }
      const liveAnn =
        !useLeanDisputeMode && primaryOracle && relays.length > 0
          ? await fetchLatestNostracleAnnouncement({
              oraclePubkeyHex: primaryOracle.pubkey,
              unit: cur,
              relays,
              timeoutMs: 2500,
            }).catch(() => null)
          : null;
      const exitSuite = primaryOracle
        ? buildLpExitSuite({
            vtxoTxid: arkTx.id,
            vtxoVout: 0,
            totalCollateralSats: quote.totalCollateralSats,
            notionalUsd: quote.notional ?? quote.notionalUsd,
            openSpotUsd: quote.spotPrice ?? quote.spotUsd,
            side: quote.side || "short",
            contractScript,
            exitClosure,
            exitDelaySecs,
            userPubXOnly,
            lpKey,
            oraclePubHex: primaryOracle.pubkey,
            oracleEventId,
            announcement: liveAnn,
            watchtowerPubHex: body.watchtowerPubHex || lpKey.pubHex,
            refundLockTime,
            includeAdaptorPayouts: !useLeanDisputeMode,
            disputeSpec: useLeanDisputeMode
              ? {
                  script_hex: disputeClosure.scriptHex,
                  control_block_hex: disputeControlBlockHex,
                  csv_sequence: disputeClosure.csvSequence,
                  oracle_quorum: posQuorum,
                  leaves: disputeClosure.allLeaves.map((l) => ({
                    script_hex: l.scriptHex,
                    control_block_hex: hex.encode(
                      btc.TaprootControlBlock.encode(contractScript.findLeaf(l.scriptHex)[0])
                    ),
                  })),
                }
              : null,
          })
        : null;

      pendingOpen.set(positionId, {
        quote,
        openedAt,
        userPubHex: body.userPubHex,
        contractScriptHex: hex.encode(contractScript.pkScript),
        contractTapTreeHex: hex.encode(contractScript.encode()),
        settleScriptHex: hex.encode(settleClosure.script),
        exitScriptHex: hex.encode(exitClosure.script),
        disputeScriptHex: disputeClosure?.scriptHex || null,
        disputeControlBlockHex,
        disputeCsvSequence: disputeClosure?.csvSequence || null,
        disputeManifest,
        userCkUnsignedB64: base64.encode(userCk.toPSBT()),
        lpCkUnsignedB64,
        lpCkSigned,
        exitSuite,
      });

      return {
        positionId,
        openedAt,
        lpPubHex: lpKey.pubHex,
        contractAddress: contractScript.address("tark", serverXOnly).encode(),
        contractPkScriptHex: hex.encode(contractScript.pkScript),
        contractTapTreeHex: hex.encode(contractScript.encode()),
        settleScriptHex: hex.encode(settleClosure.script),
        exitScriptHex: hex.encode(exitClosure.script),
        disputeScriptHex: disputeClosure?.scriptHex || null,
        disputeControlBlockHex,
        disputeCsvSequence: disputeClosure?.csvSequence || null,
        exitDelaySecs: Number(exitDelaySecs),
        arkTxB64: base64.encode(arkTx.toPSBT()),
        userCkB64: base64.encode(userCk.toPSBT()),
        exitSuite,
        disputeManifest,
      };
    }

    if (method === "open/finalize") {
      const pend = pendingOpen.get(body.positionId);
      if (!pend) throw new RpcError(404, "unknown pending positionId");

      const sub = await arkProvider.submitTx(body.signedArkTxB64, [
        pend.userCkUnsignedB64,
        pend.lpCkUnsignedB64,
      ]);

      const serverCk0 = Transaction.fromPSBT(base64.decode(sub.signedCheckpointTxs[0]));
      const serverCk1 = Transaction.fromPSBT(base64.decode(sub.signedCheckpointTxs[1]));
      const userCkSigned = Transaction.fromPSBT(base64.decode(body.signedUserCkB64));

      const finalCk0 = combineTapscriptSigs(userCkSigned, serverCk0);
      const finalCk1 = combineTapscriptSigs(pend.lpCkSigned, serverCk1);

      const position = {
        positionId: body.positionId,
        status: "open",
        side: pend.quote.side || "short",
        leverage: pend.quote.leverage || (pend.quote.side === "long" ? 2 : 1),
        liquidationPrice: pend.quote.liquidationPrice || 0,
        currency: pend.quote.currency || "USD",
        pair: pend.quote.pair || `BTC-${pend.quote.currency || "USD"}`,
        openedAt: pend.openedAt || Math.floor(Date.now() / 1000),
        vtxoTxid: sub.arkTxid,
        vtxoVout: 0,
        notional: pend.quote.notional ?? pend.quote.notionalUsd,
        notionalUsd: pend.quote.notional ?? pend.quote.notionalUsd,
        openSpotPrice: pend.quote.spotPrice ?? pend.quote.spotUsd,
        openSpotUsd: pend.quote.spotPrice ?? pend.quote.spotUsd,
        spreadBps: pend.quote.spreadBps,
        termSecs: Number(pend.quote.termSecs || tiers[0].termSecs),
        fundingRateBpsPerDay: pend.quote.fundingRateBpsPerDay,
        oracleQuorum: pend.quote.oracleQuorum || oracleQuorum,
        userCollateralSats: pend.quote.userCollateralSats,
        lpCollateralSats: pend.quote.lpCollateralSats,
        totalCollateralSats: pend.quote.totalCollateralSats,
        userPubHex: pend.userPubHex,
        lpPubHex: lpKey.pubHex,
        contractPkScriptHex: pend.contractScriptHex,
        contractTapTreeHex: pend.contractTapTreeHex,
        settleScriptHex: pend.settleScriptHex,
        exitScriptHex: pend.exitScriptHex,
        disputeScriptHex: pend.disputeScriptHex,
        disputeControlBlockHex: pend.disputeControlBlockHex,
        disputeCsvSequence: pend.disputeCsvSequence,
        disputeManifest: pend.disputeManifest,
        exitDelaySecs: Number(exitDelaySecs),
      };
      // Persist immediately after submitTx succeeds so a transient finalizeTx error can never
      // orphan a live Arkade contract VTXO from lp.json.
      store.update((d) => {
        d.positions[position.positionId] = position;
      });
      const ckPayloads = [base64.encode(finalCk0.toPSBT()), base64.encode(finalCk1.toPSBT())];
      try {
        await arkProvider.finalizeTx(sub.arkTxid, ckPayloads);
      } catch (firstErr) {
        console.warn(`  LP open retry  : finalizeTx failed (${firstErr?.message || firstErr}), retrying once...`);
        await new Promise((r) => setTimeout(r, 1_000));
        await arkProvider.finalizeTx(sub.arkTxid, ckPayloads);
      }
      pendingOpen.delete(body.positionId);
      console.log(
        `  LP open        : ${position.positionId} (${position.currency} ${position.notional}, ${position.totalCollateralSats} sats, vtxo ${sub.arkTxid.slice(0, 14)}…)`
      );
      return position;
    }

    if (method === "roll/propose") {
      const pos = store.read().positions[body.positionId];
      if (!pos) throw new RpcError(404, "unknown positionId");
      if (pos.status !== "open") throw new RpcError(400, `position is ${pos.status}`);

      const cur = (pos.currency || "USD").toUpperCase();
      const side = pos.side === "long" ? "long" : "short";
      const notional = Number(pos.notional ?? pos.notionalUsd);
      const spot = await fetchBtcSpot(cur, pos.openSpotPrice ?? pos.openSpotUsd);
      const rollSpotUsd = body.overrideSpotUsd ? Number(body.overrideSpotUsd) : spot.price;
      const elapsedSecs = Math.max(0, Math.floor(Date.now() / 1000) - Number(pos.lastRolledAt || pos.openedAt || 0));
      const defaultSideFunding = side === "long" ? -fundingRateBpsPerDay : fundingRateBpsPerDay;
      const prevFundingBps = Number(pos.fundingRateBpsPerDay ?? defaultSideFunding);
      const prevCarriedInterestUsd = Number(pos.carriedInterestUsd || 0);
      const periodInterestUsd = notional * (prevFundingBps / 10_000) * (elapsedSecs / 86_400);
      const accruedInterestUsd = prevCarriedInterestUsd + periodInterestUsd;
      const total = BigInt(pos.totalCollateralSats);
      let userEquity;
      let lpEquity;
      if (side === "long") {
        lpEquity = computeFiatPayoutSats(
          Math.max(0.01, notional - accruedInterestUsd),
          rollSpotUsd,
          total,
          DUST
        );
        userEquity = total - lpEquity;
      } else {
        userEquity = computeFiatPayoutSats(
          Math.max(0.01, notional + accruedInterestUsd),
          rollSpotUsd,
          total,
          DUST
        );
        lpEquity = total - userEquity;
      }

      const targetPerSide = BigInt(Math.max(1_000, Math.round((notional / rollSpotUsd) * 1e8)));
      let newTotal = total;
      let userSurplus = 0n;
      let lpSurplus = 0n;
      if (userEquity >= targetPerSide && lpEquity >= targetPerSide) {
        const candidateUserSurplus = userEquity - targetPerSide;
        const candidateLpSurplus = lpEquity - targetPerSide;
        userSurplus = candidateUserSurplus >= DUST ? candidateUserSurplus : 0n;
        lpSurplus = candidateLpSurplus >= DUST ? candidateLpSurplus : 0n;
        newTotal = total - userSurplus - lpSurplus;
      }
      // If surplus is below Arkade dust (330 sats), carry the accrued yield forward so nothing is lost.
      const newCarriedInterestUsd = userSurplus >= DUST ? 0 : accruedInterestUsd;

      const contractScript = VtxoScript.decode(hex.decode(pos.contractTapTreeHex));
      const settleScript = hex.decode(pos.settleScriptHex);
      const settleLeaf = contractScript.findLeaf(pos.settleScriptHex);
      const settleLeafHash = tapLeafHash(settleScript);
      const userPubXOnly = hex.decode(pos.userPubHex);
      const userArkScript = buildDefaultArkScript(userPubXOnly, serverXOnly, exitDelaySecs);
      const { exitClosure } = buildDlcContractScript(
        userPubXOnly,
        lpKey.pubXOnly,
        serverXOnly,
        exitDelaySecs,
        pos.oracleQuorum || oracleQuorum
      );

      const outputs = [{ script: contractScript.pkScript, amount: newTotal }];
      if (userSurplus >= DUST) outputs.push({ script: userArkScript.pkScript, amount: userSurplus });
      if (lpSurplus >= DUST) outputs.push({ script: lpArkScript.pkScript, amount: lpSurplus });

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
        outputs,
        checkpointTapscript
      );
      const ck = checkpoints[0];
      const ckHash = tapscriptSighash(ck, 0, [contractScript.pkScript], [total], settleScript);
      const arkHash = tapscriptSighash(arkTx, 0, [ck.getOutput(0).script], [ck.getOutput(0).amount], settleScript);

      attachTapscriptSig(arkTx, 0, lpKey.pubXOnly, settleLeafHash, schnorrSign(lpKey, arkHash));
      const ckUnsignedB64 = base64.encode(ck.toPSBT());
      const lpCkSig = schnorrSign(lpKey, ckHash);

      const termSecs = Number(body.termSecs || pos.termSecs || tiers[0].termSecs);
      const rollTier = findTierForTerm(termSecs);
      const primaryOracle = (pos.oracleQuorum || oracleQuorum)?.oracles?.[0];
      const oracleEventId = `btc${cur.toLowerCase()}-${Math.floor(Date.now() / 1000) + termSecs}`;
      const refundLockTime = Math.floor(Date.now() / 1000) + 7 * 86_400;
      const exitSuite = primaryOracle
        ? buildLpExitSuite({
            vtxoTxid: arkTx.id,
            vtxoVout: 0,
            totalCollateralSats: Number(newTotal),
            notionalUsd: notional,
            openSpotUsd: rollSpotUsd,
            side,
            contractScript,
            exitClosure,
            exitDelaySecs,
            userPubXOnly,
            lpKey,
            oraclePubHex: primaryOracle.pubkey,
            oracleEventId,
            watchtowerPubHex: body.watchtowerPubHex || lpKey.pubHex,
            refundLockTime,
          })
        : null;

      pendingRoll.set(pos.positionId, {
        pos,
        rollSpotUsd,
        accruedInterestUsd,
        newCarriedInterestUsd,
        newTotalCollateralSats: Number(newTotal),
        userSurplusSats: Number(userSurplus),
        lpSurplusSats: Number(lpSurplus),
        termSecs,
        newFundingRateBpsPerDay: side === "long" ? -rollTier.fundingRateBpsPerDay : rollTier.fundingRateBpsPerDay,
        ckUnsignedB64,
        lpCkSig,
        settleLeafHash,
        exitSuite,
      });

      return {
        positionId: pos.positionId,
        rollSpotUsd,
        accruedInterestUsd,
        carriedInterestUsd: newCarriedInterestUsd,
        newTotalCollateralSats: Number(newTotal),
        userSurplusSats: Number(userSurplus),
        lpSurplusSats: Number(lpSurplus),
        termSecs,
        fundingRateBpsPerDay: rollTier.fundingRateBpsPerDay,
        arkTxB64: base64.encode(arkTx.toPSBT()),
        ckB64: ckUnsignedB64,
        exitSuite,
      };
    }

    if (method === "roll/finalize") {
      const pend = pendingRoll.get(body.positionId);
      if (!pend) throw new RpcError(404, "unknown pending roll");

      const sub = await arkProvider.submitTx(body.signedArkTxB64, [pend.ckUnsignedB64]);
      const serverCk = Transaction.fromPSBT(base64.decode(sub.signedCheckpointTxs[0]));
      const userCkSigned = Transaction.fromPSBT(base64.decode(body.signedCkB64));
      attachTapscriptSig(userCkSigned, 0, lpKey.pubXOnly, pend.settleLeafHash, pend.lpCkSig);
      const finalCk = combineTapscriptSigs(userCkSigned, serverCk);
      await arkProvider.finalizeTx(sub.arkTxid, [base64.encode(finalCk.toPSBT())]);

      pendingRoll.delete(body.positionId);
      return store.update((d) => {
        const p = d.positions[body.positionId];
        p.prevVtxoTxid = p.vtxoTxid;
        p.vtxoTxid = sub.arkTxid;
        p.vtxoVout = 0;
        p.openSpotUsd = pend.rollSpotUsd;
        p.openSpotPrice = pend.rollSpotUsd;
        p.totalCollateralSats = pend.newTotalCollateralSats;
        p.termSecs = pend.termSecs;
        p.fundingRateBpsPerDay = pend.newFundingRateBpsPerDay;
        p.lastRolledAt = Math.floor(Date.now() / 1000);
        p.rollCount = Number(p.rollCount || 0) + 1;
        p.lastRollInterestUsd = pend.accruedInterestUsd;
        p.carriedInterestUsd = pend.newCarriedInterestUsd;
        p.lastRollUserSurplusSats = pend.userSurplusSats;
        p.totalPaidInterestSats = Number(p.totalPaidInterestSats || 0) + Number(pend.userSurplusSats || 0);
        return p;
      });
    }

    if (method === "close/propose") {
      const pos = store.read().positions[body.positionId];
      if (!pos) throw new RpcError(404, "unknown positionId");
      if (pos.status !== "open") throw new RpcError(400, `position is ${pos.status}`);

      const cur = (pos.currency || "USD").toUpperCase();
      const side = pos.side === "long" ? "long" : "short";
      const notional = Number(pos.notional ?? pos.notionalUsd);
      const spot = await fetchBtcSpot(cur, pos.openSpotPrice ?? pos.openSpotUsd);
      const closeSpotUsd = body.overrideSpotUsd ? Number(body.overrideSpotUsd) : spot.price;
      const elapsedSecs = Math.max(0, Math.floor(Date.now() / 1000) - Number(pos.lastRolledAt || pos.openedAt || 0));
      const defaultSideFunding = side === "long" ? -fundingRateBpsPerDay : fundingRateBpsPerDay;
      const fundingBps = Number(pos.fundingRateBpsPerDay ?? defaultSideFunding);
      const prevCarriedInterestUsd = Number(pos.carriedInterestUsd || 0);
      const accruedInterestUsd =
        prevCarriedInterestUsd + notional * (fundingBps / 10_000) * (elapsedSecs / 86_400);
      let userPayout;
      let lpPayout;
      if (side === "long") {
        const lpEffectiveNotional = Math.max(0.01, notional - accruedInterestUsd);
        lpPayout = computeFiatPayoutSats(
          lpEffectiveNotional,
          closeSpotUsd,
          BigInt(pos.totalCollateralSats),
          DUST
        );
        userPayout = BigInt(pos.totalCollateralSats) - lpPayout;
      } else {
        const effectiveNotionalUsd = Math.max(0.01, notional + accruedInterestUsd);
        userPayout = computeFiatPayoutSats(
          effectiveNotionalUsd,
          closeSpotUsd,
          BigInt(pos.totalCollateralSats),
          DUST
        );
        lpPayout = BigInt(pos.totalCollateralSats) - userPayout;
      }

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
        accruedInterestUsd,
        userPayoutSats: Number(userPayout),
        lpPayoutSats: Number(lpPayout),
        ckUnsignedB64,
        lpCkSig,
        settleLeafHash,
      });

      return {
        positionId: pos.positionId,
        closeSpotUsd,
        accruedInterestUsd,
        userPayoutSats: Number(userPayout),
        lpPayoutSats: Number(lpPayout),
        arkTxB64: base64.encode(arkTx.toPSBT()),
        ckB64: ckUnsignedB64,
      };
    }

    if (method === "close/finalize") {
      const pend = pendingClose.get(body.positionId);
      if (!pend) throw new RpcError(404, "unknown pending close");

      const sub = await arkProvider.submitTx(body.signedArkTxB64, [pend.ckUnsignedB64]);
      const serverCk = Transaction.fromPSBT(base64.decode(sub.signedCheckpointTxs[0]));
      const userCkSigned = Transaction.fromPSBT(base64.decode(body.signedCkB64));
      attachTapscriptSig(userCkSigned, 0, lpKey.pubXOnly, pend.settleLeafHash, pend.lpCkSig);
      const finalCk = combineTapscriptSigs(userCkSigned, serverCk);
      await arkProvider.finalizeTx(sub.arkTxid, [base64.encode(finalCk.toPSBT())]);

      pendingClose.delete(body.positionId);
      return store.update((d) => {
        const p = d.positions[body.positionId];
        p.status = "closed";
        p.closedAt = Math.floor(Date.now() / 1000);
        p.closeSpotUsd = pend.closeSpotUsd;
        p.accruedInterestUsd = pend.accruedInterestUsd;
        p.closeTxid = sub.arkTxid;
        p.userPayoutSats = pend.userPayoutSats;
        p.lpPayoutSats = pend.lpPayoutSats;
        return p;
      });
    }

    throw new RpcError(404, `unknown method: ${method}`);
  }

  let server = null;
  if (enableHttp) {
    server = http.createServer(async (req, res) => {
      try {
        if (req.method === "OPTIONS") {
          res.writeHead(204, {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
          });
          return res.end();
        }
        const url = new URL(req.url, `http://127.0.0.1:${actualPort}`);
        const routeKey = `${req.method} ${url.pathname}`;
        const routeMap = {
          "GET /health": "health",
          "GET /offer": "offer",
          "GET /positions": "positions",
          "POST /quote": "quote",
          "POST /open/propose": "open/propose",
          "POST /open/finalize": "open/finalize",
          "POST /roll/propose": "roll/propose",
          "POST /roll/finalize": "roll/finalize",
          "POST /close/propose": "close/propose",
          "POST /close/finalize": "close/finalize",
        };
        const method = routeMap[routeKey];
        if (!method) return sendJson(res, 404, { error: "not found" });
        const body = req.method === "POST" ? await readJsonBody(req) : {};
        const result = await handleRpc(method, body);
        return sendJson(res, 200, result);
      } catch (err) {
        const status = err instanceof RpcError ? err.status : 500;
        sendJson(res, status, { error: err?.message || String(err) });
      }
    });
    await new Promise((resolve) => server.listen(port, "127.0.0.1", resolve));
    actualPort = server.address().port;
  }

  // Start NIP-17 encrypted P2P listener on Nostr relays whenever relays are configured
  let nip17Peer = null;
  let nip17Connected = 0;
  let publishTimer = null;
  let initialPublish = null;
  if (relays.length > 0) {
    nip17Peer = new Nip17Peer(lpKey, relays, {
      onRequest: (method, params, senderPubkey) => handleRpc(method, params, senderPubkey),
    });
    nip17Connected = await nip17Peer.connect();
    initialPublish = await buildAndPublishOffer().catch((err) => ({
      error: err?.message || String(err),
      relayResult: { okRelays: [], failedRelays: [] },
    }));
    publishTimer = setInterval(() => {
      buildAndPublishOffer().catch(() => {});
    }, publishIntervalMs);
    publishTimer.unref?.();
  }

  // Automatic L1 boarding -> Arkade onboarding: whenever confirmed sats arrive at the LP's
  // boarding address (e.g. funded via L1 Mutinynet/Bitcoin), onboard them into spendable Arkade VTXOs.
  let onboarding = false;
  async function onboardLpBoardingUtxos() {
    if (onboarding || settling || pendingOpen.size > 0 || pendingRoll.size > 0 || pendingClose.size > 0) return;
    onboarding = true;
    try {
      const bal = await wallet.getBalance();
      const confirmed = Number(bal?.boarding?.confirmed || 0);
      if (confirmed < 1_000) return;
      console.log(`  LP onboard     : boarding ${confirmed.toLocaleString()} confirmed L1 sats into Arkade...`);
      const txid = await new Ramps(wallet).onboard(info.fees);
      console.log(`  LP onboard     : boarded ${confirmed.toLocaleString()} sats into Arkade (${txid || "ok"})`);
      if (relays.length > 0) buildAndPublishOffer().catch(() => {});
    } catch (err) {
      console.warn(`  LP onboard     : skipped (${err?.message || err})`);
    } finally {
      onboarding = false;
    }
  }
  const onboardTimer = setInterval(() => {
    onboardLpBoardingUtxos().catch(() => {});
  }, 5 * 60 * 1000);
  onboardTimer.unref?.();
  const bootOnboardTimer = setTimeout(() => {
    onboardLpBoardingUtxos().catch(() => {});
  }, 10_000);
  bootOnboardTimer.unref?.();

  // Smart periodic VTXO compaction: only settle preconfirmed LP VTXOs when chain depth >= 6 hops
  // (avoids paying ~40 sat Arkade round fees on shallow 1-2 hop VTXOs while preventing deep chains).
  let settling = false;
  async function compactLpVtxos() {
    if (settling || onboarding || pendingOpen.size > 0 || pendingRoll.size > 0 || pendingClose.size > 0) return;
    settling = true;
    try {
      const vtxos = await wallet.getVtxos();
      const preconf = (vtxos || []).filter((v) => v?.virtualStatus?.state === "preconfirmed");
      if (preconf.length === 0) return;
      let maxHops = 0;
      for (const v of preconf.slice(0, 3)) {
        try {
          const resp = await indexerProvider.getVtxoChain({ txid: v.txid, vout: v.vout });
          const chain = resp?.txs?.length ? resp.txs : resp?.chain || [];
          const hops = chain.filter((c) => !String(c.type).toLowerCase().includes("commitment") && c.type !== 1).length;
          if (hops > maxHops) maxHops = hops;
        } catch {}
      }
      if (maxHops >= 6) {
        const txid = await wallet.settle();
        console.log(`  LP VTXO round  : compacted ${maxHops}-hop preconfirmed VTXOs into 1-hop round (${txid || "ok"})`);
      }
    } catch (err) {
      console.warn(`  LP VTXO round  : skipped (${err?.message || err})`);
    } finally {
      settling = false;
    }
  }
  const settleTimer = setInterval(() => {
    compactLpVtxos().catch(() => {});
  }, 30 * 60 * 1000);
  settleTimer.unref?.();
  const bootSettleTimer = setTimeout(() => {
    compactLpVtxos().catch(() => {});
  }, 20_000);
  bootSettleTimer.unref?.();

  return {
    server,
    port: actualPort,
    url: enableHttp ? `http://127.0.0.1:${actualPort}` : null,
    lpKey,
    lpName,
    wallet,
    store,
    nip17Peer,
    nip17Connected,
    initialPublish,
    publishOffer: buildAndPublishOffer,
    onboardLpBoardingUtxos,
    compactLpVtxos,
    handleRpc,
    close: async () => {
      if (publishTimer) clearInterval(publishTimer);
      clearInterval(onboardTimer);
      clearTimeout(bootOnboardTimer);
      clearInterval(settleTimer);
      clearTimeout(bootSettleTimer);
      nip17Peer?.close();
      await wallet.dispose?.();
      if (server) await new Promise((resolve) => server.close(resolve));
    },
  };
}

// Run standalone if invoked directly (`node src/lp.mjs`)
if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(import.meta.filename)) {
  // Never let transient upstream Esplora / network timeouts inside SDK background pollers
  // crash the 24/7 LP process (offchain Arkade RPCs only need the Arkade server + Nostr relays).
  process.on("unhandledRejection", (reason) => {
    console.warn(`  [LP unhandledRejection] ${reason?.message || reason}`);
  });
  process.on("uncaughtException", (err) => {
    console.warn(`  [LP uncaughtException] ${err?.message || err}`);
  });

  const enableHttp = process.env.LP_NO_HTTP !== "1" && process.env.LP_NO_HTTP !== "true";
  const port = Number(process.env.LP_PORT || 3456);
  const lpName = process.env.LP_NAME || "p2pFiat-LP";
  const spreadBps = Number(process.env.LP_SPREAD_BPS || 1);
  const fundingRateBpsPerDay = Number(process.env.LP_FUNDING_BPS || 3);
  const termSecs = Number(process.env.LP_TERM_SECS || 86_400);
  const offerTiers = parseOfferTiers(process.env.LP_EXTRA_OFFERS, {
    termSecs,
    fundingRateBpsPerDay,
    spreadBps,
  });
  const publicUrl = process.env.LP_PUBLIC_URL || undefined;
  const dataDir = process.env.LP_DATA_DIR ? path.resolve(process.env.LP_DATA_DIR) : undefined;
  const relays =
    process.env.NOSTR_RELAYS === "none"
      ? []
      : process.env.NOSTR_RELAYS
      ? process.env.NOSTR_RELAYS.split(",").map((s) => s.trim()).filter(Boolean)
      : DEFAULT_RELAYS;

  const lp = await createLpServer({
    port,
    enableHttp,
    dataDir,
    lpName,
    spreadBps,
    fundingRateBpsPerDay,
    termSecs,
    offerTiers,
    publicUrl,
    relays,
  });
  const tierSummary = offerTiers
    .map((t) => `${t.termSecs >= 86_400 ? `${Math.round(t.termSecs / 86_400)}d` : `${Math.round(t.termSecs / 3600)}h`}@${t.fundingRateBpsPerDay}bps/d`)
    .join(", ");
  console.log(
    `p2pFiat LP ready (${lp.lpName}, spread=${spreadBps}bps, tiers=[${tierSummary}])`
  );
  console.log(`  HTTP endpoint  : ${lp.url || "DISABLED (serverless NIP-17 P2P mode)"}`);
  console.log(`  LP pubkey      : ${lp.lpKey.pubHex}`);
  console.log(`  LP Ark address : ${await lp.wallet.getAddress()}`);
  console.log(`  LP boarding    : ${await lp.wallet.getBoardingAddress()}`);
  if (relays.length > 0) {
    const ok = lp.initialPublish?.relayResult?.okRelays || [];
    console.log(`  Nostr offer    : published to ${ok.length}/${relays.length} relays (${ok.join(", ") || "none"})`);
    console.log(`  NIP-17 P2P RPC : listening on ${lp.nip17Connected}/${relays.length} relays`);
  }
}
