//! Cryptographic helpers (secp256k1 even keys, BIP-340 Schnorr, adaptor sigs)
//! and live BTC/USD median spot price feed (Kraken, Coinbase, Bitstamp).

import crypto from "node:crypto";
import { hex } from "@scure/base";
import { schnorr } from "@noble/curves/secp256k1.js";
import * as btc from "@scure/btc-signer";

export const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
export const G = schnorr.Point.BASE;

export function sha256(...parts) {
  const h = crypto.createHash("sha256");
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
}

export function taggedHash(tag, ...parts) {
  const th = sha256(Buffer.from(tag, "utf8"));
  return sha256(th, th, ...parts);
}

export function bytesToBigInt(b) {
  return BigInt("0x" + hex.encode(b));
}

export function bigIntToBytes32(n) {
  const mod = ((n % N) + N) % N;
  return hex.decode(mod.toString(16).padStart(64, "0"));
}

export function pointToXOnly(pt) {
  const { x } = pt.toAffine();
  return hex.decode(x.toString(16).padStart(64, "0"));
}

export function hasEvenY(pt) {
  return (pt.toAffine().y & 1n) === 0n;
}

export function keyFromHex(privHex) {
  let d = bytesToBigInt(hex.decode(privHex.trim()));
  let pt = G.multiply(d);
  if (!hasEvenY(pt)) {
    d = N - d;
    pt = G.multiply(d);
  }
  return { d, privHex: hex.encode(bigIntToBytes32(d)), privBytes: bigIntToBytes32(d), pubXOnly: pointToXOnly(pt), pubHex: hex.encode(pointToXOnly(pt)), point: pt };
}

export function randomEvenKey() {
  while (true) {
    const priv = crypto.randomBytes(32);
    let d = bytesToBigInt(priv);
    if (d <= 0n || d >= N) continue;
    return keyFromHex(hex.encode(priv));
  }
}

export function schnorrSign(signer, msg32) {
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

export function encodeVarBytes(b) {
  if (b.length < 0xfd) return Uint8Array.from([b.length, ...b]);
  if (b.length <= 0xffff) return Uint8Array.from([0xfd, b.length & 0xff, (b.length >> 8) & 0xff, ...b]);
  throw new Error("script too long");
}

export function tapLeafHash(leafScript) {
  return taggedHash("TapLeaf", new Uint8Array([0xc0]), encodeVarBytes(leafScript));
}

export function tapscriptSighash(psbtTx, inputIdx, prevScripts, prevAmounts, leafScript) {
  return psbtTx.preimageWitnessV1(inputIdx, prevScripts, btc.SigHash.DEFAULT, prevAmounts, -1, leafScript, 0xc0);
}

export function attachTapscriptSig(psbtTx, inputIdx, pubXOnly, leafHash, sig) {
  const inp = psbtTx.getInput(inputIdx);
  const existing = inp.tapScriptSig ? [...inp.tapScriptSig] : [];
  existing.push([{ pubKey: pubXOnly, leafHash }, sig]);
  psbtTx.updateInput(inputIdx, { tapScriptSig: existing });
}

/**
 * Fetch live BTC/USD median spot price from Kraken, Coinbase, and Bitstamp.
 * Falls back to `fallbackUsd` if offline or fewer than 1 exchange responds.
 */
export async function fetchBtcUsdSpot(fallbackUsd = 95_000) {
  const fetchers = [
    async () => {
      const r = await fetch("https://api.kraken.com/0/public/Ticker?pair=XBTUSD", { signal: AbortSignal.timeout(4000) });
      const j = await r.json();
      return Number(j.result.XXBTZUSD.c[0]);
    },
    async () => {
      const r = await fetch("https://api.coinbase.com/v2/prices/BTC-USD/spot", { signal: AbortSignal.timeout(4000) });
      const j = await r.json();
      return Number(j.data.amount);
    },
    async () => {
      const r = await fetch("https://www.bitstamp.net/api/v2/ticker/btcusd/", { signal: AbortSignal.timeout(4000) });
      const j = await r.json();
      return Number(j.last);
    },
  ];
  const results = await Promise.allSettled(fetchers.map((fn) => fn()));
  const prices = results
    .filter((r) => r.status === "fulfilled" && Number.isFinite(r.value) && r.value > 1000)
    .map((r) => r.value)
    .sort((a, b) => a - b);

  if (prices.length === 0) return { price: fallbackUsd, sources: 0 };
  const mid = Math.floor(prices.length / 2);
  const median = prices.length % 2 === 1 ? prices[mid] : (prices[mid - 1] + prices[mid]) / 2;
  return { price: Math.round(median), sources: prices.length };
}

/** Compute USD-pegged user payout in satoshis, clamped to `[dust, totalCollateral - dust]`. */
export function computeUsdPayoutSats(notionalUsd, spotUsd, totalCollateralSats, dustSats = 350n) {
  const raw = BigInt(Math.round((notionalUsd / spotUsd) * 1e8));
  const min = dustSats;
  const max = totalCollateralSats - dustSats;
  if (raw < min) return min;
  if (raw > max) return max;
  return raw;
}
