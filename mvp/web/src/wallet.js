/**
 * Pure browser-native self-custody Arkade DLC wallet (no Node.js APIs).
 * Runs 100% client-side with `@arkade-os/sdk`, `@scure/btc-signer`, and `@noble/curves`.
 */

import {
  Wallet,
  SingleKey,
  Ramps,
  RestArkProvider,
  RestIndexerProvider,
  EsploraProvider,
  DefaultVtxo,
  VtxoScript,
  Transaction,
  toXOnly,
} from "@arkade-os/sdk";
import * as btc from "@scure/btc-signer";
import { hex, base64 } from "@scure/base";
import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";

export const ARK_URL = "https://mutinynet.arkade.sh";
export const ESPLORA_URL = "https://mutinynet.com/api";

const LS_KEY = "p2pfiat_user_privkey_hex";
const LS_POSITIONS = "p2pfiat_user_positions";
const LS_LP_URL = "p2pfiat_lp_url";

const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const G = schnorr.Point.BASE;
const enc = new TextEncoder();

function concatBytes(...arrays) {
  const len = arrays.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(len);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

function taggedHash(tag, ...parts) {
  const th = nobleSha256(enc.encode(tag));
  return nobleSha256(concatBytes(th, th, ...parts));
}

function bytesToBigInt(b) {
  return BigInt("0x" + hex.encode(b));
}

function bigIntToBytes32(n) {
  const mod = ((n % N) + N) % N;
  return hex.decode(mod.toString(16).padStart(64, "0"));
}

function pointToXOnly(pt) {
  return hex.decode(pt.toAffine().x.toString(16).padStart(64, "0"));
}

function hasEvenY(pt) {
  return (pt.toAffine().y & 1n) === 0n;
}

export function keyFromHex(privHex) {
  let d = bytesToBigInt(hex.decode(privHex.trim()));
  let pt = G.multiply(d);
  if (!hasEvenY(pt)) {
    d = N - d;
    pt = G.multiply(d);
  }
  const pubXOnly = pointToXOnly(pt);
  return {
    d,
    privHex: hex.encode(bigIntToBytes32(d)),
    pubXOnly,
    pubHex: hex.encode(pubXOnly),
  };
}

export function randomEvenKeyHex() {
  while (true) {
    const priv = new Uint8Array(32);
    crypto.getRandomValues(priv);
    const d = bytesToBigInt(priv);
    if (d <= 0n || d >= N) continue;
    return keyFromHex(hex.encode(priv)).privHex;
  }
}

function schnorrSign(signer, msg32) {
  while (true) {
    const kBytes = new Uint8Array(32);
    crypto.getRandomValues(kBytes);
    const k = bytesToBigInt(kBytes);
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

function encodeVarBytes(b) {
  if (b.length < 0xfd) return Uint8Array.from([b.length, ...b]);
  if (b.length <= 0xffff) return Uint8Array.from([0xfd, b.length & 0xff, (b.length >> 8) & 0xff, ...b]);
  throw new Error("script too long");
}

function tapLeafHash(leafScript) {
  return taggedHash("TapLeaf", new Uint8Array([0xc0]), encodeVarBytes(leafScript));
}

function tapscriptSighash(psbtTx, inputIdx, prevScripts, prevAmounts, leafScript) {
  return psbtTx.preimageWitnessV1(inputIdx, prevScripts, btc.SigHash.DEFAULT, prevAmounts, -1, leafScript, 0xc0);
}

function attachTapscriptSig(psbtTx, inputIdx, pubXOnly, leafHash, sig) {
  const inp = psbtTx.getInput(inputIdx);
  const existing = inp.tapScriptSig ? [...inp.tapScriptSig] : [];
  existing.push([{ pubKey: pubXOnly, leafHash }, sig]);
  psbtTx.updateInput(inputIdx, { tapScriptSig: existing });
}

export function getLpUrl() {
  return localStorage.getItem(LS_LP_URL) || "http://127.0.0.1:3456";
}

export function setLpUrl(url) {
  localStorage.setItem(LS_LP_URL, url.trim().replace(/\/+$/, ""));
}

export function loadPositions() {
  try {
    return JSON.parse(localStorage.getItem(LS_POSITIONS) || "{}");
  } catch {
    return {};
  }
}

export function savePositions(map) {
  localStorage.setItem(LS_POSITIONS, JSON.stringify(map));
}

export function getOrCreatePrivKeyHex() {
  let k = localStorage.getItem(LS_KEY);
  if (!k) {
    k = randomEvenKeyHex();
    localStorage.setItem(LS_KEY, k);
  }
  return k;
}

export function importPrivKeyHex(privHex) {
  const normalized = keyFromHex(privHex).privHex;
  localStorage.setItem(LS_KEY, normalized);
  return normalized;
}

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

export class BrowserP2pFiatWallet {
  static async create() {
    const privHex = getOrCreatePrivKeyHex();
    const userKey = keyFromHex(privHex);
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
    });
    const userArkScript = new DefaultVtxo.Script({
      pubKey: userKey.pubXOnly,
      serverPubKey: serverXOnly,
      csvTimelock: { type: "seconds", value: exitDelaySecs },
    });
    return new BrowserP2pFiatWallet({
      userKey,
      wallet,
      arkProvider,
      indexerProvider,
      info,
      serverXOnly,
      exitDelaySecs,
      userArkScript,
    });
  }

  constructor(deps) {
    Object.assign(this, deps);
  }

  async getAddresses() {
    return {
      arkAddress: await this.wallet.getAddress(),
      boardingAddress: await this.wallet.getBoardingAddress(),
    };
  }

  async getBalance() {
    return this.wallet.getBalance();
  }

  async onboard(onEvent) {
    return new Ramps(this.wallet).onboard(this.info.fees, undefined, undefined, onEvent);
  }

  async fetchLpHealth() {
    const r = await fetch(`${getLpUrl()}/health`);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  }

  async requestQuote(notionalUsd) {
    return postJson(`${getLpUrl()}/quote`, { notionalUsd });
  }

  async openPosition(notionalUsd) {
    const q = await this.requestQuote(notionalUsd);
    const vtxos = await this.wallet.getVtxos();
    const userVtxo = vtxos
      .filter((v) => Number(v.value) >= q.userCollateralSats)
      .sort((a, b) => Number(b.value) - Number(a.value))[0];
    if (!userVtxo) {
      throw new Error(`Need a spendable Arkade VTXO >= ${q.userCollateralSats} sats`);
    }

    const defaultLeaf = this.userArkScript.forfeit();
    const defaultLeafScript = defaultLeaf[1].slice(0, -1);
    const defaultLeafHash = tapLeafHash(defaultLeafScript);

    const prop = await postJson(`${getLpUrl()}/open/propose`, {
      quoteId: q.quoteId,
      userPubHex: this.userKey.pubHex,
      userInput: {
        txid: userVtxo.txid,
        vout: userVtxo.vout,
        value: Number(userVtxo.value),
        tapTreeHex: hex.encode(this.userArkScript.encode()),
        leafScriptHex: hex.encode(defaultLeafScript),
      },
      userChangeScriptHex: hex.encode(this.userArkScript.pkScript),
    });

    const arkTx = Transaction.fromPSBT(base64.decode(prop.arkTxB64));
    const userCk = Transaction.fromPSBT(base64.decode(prop.userCkB64));
    const out0 = arkTx.getOutput(0);
    if (hex.encode(out0.script) !== prop.contractPkScriptHex || out0.amount !== BigInt(q.totalCollateralSats)) {
      throw new Error("LP proposal output 0 mismatch! Refusing to sign.");
    }

    const prevScripts = [arkTx.getInput(0).witnessUtxo.script, arkTx.getInput(1).witnessUtxo.script];
    const prevAmounts = [arkTx.getInput(0).witnessUtxo.amount, arkTx.getInput(1).witnessUtxo.amount];
    const arkHash = tapscriptSighash(arkTx, 0, prevScripts, prevAmounts, defaultLeafScript);
    const ckHash = tapscriptSighash(
      userCk,
      0,
      [this.userArkScript.pkScript],
      [BigInt(userVtxo.value)],
      defaultLeafScript
    );

    attachTapscriptSig(arkTx, 0, this.userKey.pubXOnly, defaultLeafHash, schnorrSign(this.userKey, arkHash));
    attachTapscriptSig(userCk, 0, this.userKey.pubXOnly, defaultLeafHash, schnorrSign(this.userKey, ckHash));

    const pos = await postJson(`${getLpUrl()}/open/finalize`, {
      positionId: prop.positionId,
      signedArkTxB64: base64.encode(arkTx.toPSBT()),
      signedUserCkB64: base64.encode(userCk.toPSBT()),
    });

    const map = loadPositions();
    map[pos.positionId] = pos;
    savePositions(map);
    return pos;
  }

  async closePosition(positionId) {
    const map = loadPositions();
    const pos = map[positionId];
    if (!pos) throw new Error("Unknown position");

    const prop = await postJson(`${getLpUrl()}/close/propose`, { positionId });
    const arkTx = Transaction.fromPSBT(base64.decode(prop.arkTxB64));
    const ck = Transaction.fromPSBT(base64.decode(prop.ckB64));
    const settleScript = hex.decode(pos.settleScriptHex);
    const settleLeafHash = tapLeafHash(settleScript);
    const contractPkScript = hex.decode(pos.contractPkScriptHex);

    if (hex.encode(arkTx.getOutput(0).script) !== hex.encode(this.userArkScript.pkScript)) {
      throw new Error("LP close proposal output 0 does not pay User!");
    }

    const ckHash = tapscriptSighash(ck, 0, [contractPkScript], [BigInt(pos.totalCollateralSats)], settleScript);
    const arkHash = tapscriptSighash(arkTx, 0, [ck.getOutput(0).script], [ck.getOutput(0).amount], settleScript);
    attachTapscriptSig(arkTx, 0, this.userKey.pubXOnly, settleLeafHash, schnorrSign(this.userKey, arkHash));
    attachTapscriptSig(ck, 0, this.userKey.pubXOnly, settleLeafHash, schnorrSign(this.userKey, ckHash));

    const closed = await postJson(`${getLpUrl()}/close/finalize`, {
      positionId,
      signedArkTxB64: base64.encode(arkTx.toPSBT()),
      signedCkB64: base64.encode(ck.toPSBT()),
    });
    map[positionId] = closed;
    savePositions(map);
    return closed;
  }

  async exportWatchtowerPackage(positionId) {
    const pos = loadPositions()[positionId];
    if (!pos) throw new Error("Unknown position");
    const resp = await this.indexerProvider.getVtxoChain({ txid: pos.vtxoTxid, vout: pos.vtxoVout });
    const chain = resp.txs?.length ? resp.txs : resp.chain || [];
    const nonCommit = chain.filter((c) => !String(c.type).toLowerCase().includes("commitment") && c.type !== 1);
    const vtxResp = await this.indexerProvider.getVirtualTxs(nonCommit.map((c) => c.txid));

    const rawByTxid = new Map();
    const txObjByTxid = new Map();
    for (const psbtB64 of vtxResp.txs) {
      const t = Transaction.fromPSBT(base64.decode(psbtB64), { allowUnknownInputs: true, allowUnknownOutputs: true });
      let tapKeyOnly = false;
      for (let i = 0; i < t.inputsLength; i++) {
        const inp = t.getInput(i);
        if (!inp.finalScriptWitness && inp.tapKeySig && !inp.witnessUtxo) {
          t.updateInput(i, { finalScriptWitness: [inp.tapKeySig] });
          tapKeyOnly = true;
        }
      }
      const rawHex = tapKeyOnly
        ? hex.encode(t.toBytes(true, true))
        : (t.isFinal || t.finalize(), hex.encode(t.extract()));
      rawByTxid.set(t.id, rawHex);
      txObjByTxid.set(t.id, t);
    }

    const ordered = [];
    const visited = new Set();
    const visit = (id) => {
      if (visited.has(id) || !txObjByTxid.has(id)) return;
      visited.add(id);
      const t = txObjByTxid.get(id);
      for (let i = 0; i < t.inputsLength; i++) {
        const prev = hex.encode(t.getInput(i).txid);
        if (txObjByTxid.has(prev)) visit(prev);
      }
      ordered.push(id);
    };
    for (const c of nonCommit) visit(c.txid);

    return {
      positionId,
      vtxo_outpoint: `${pos.vtxoTxid}:${pos.vtxoVout}`,
      vtxo_amount_sats: pos.totalCollateralSats,
      vtxo_pk_script: pos.contractPkScriptHex,
      ark_indexer_url: ARK_URL,
      unroll_txs: ordered.map((id) => rawByTxid.get(id)),
      exit_script: pos.exitScriptHex,
      exit_csv_seconds: pos.exitDelaySecs,
      user_pubkey: pos.userPubHex,
      lp_pubkey: pos.lpPubHex,
    };
  }
}
