/**
 * Pure ESM NIP-44 v2 (ChaCha20 + HMAC-SHA256 + HKDF-SHA256 + secp256k1 ECDH)
 * and NIP-59 / NIP-17 Gift-Wrapped encrypted P2P RPC over Nostr relays.
 *
 * Zero extra npm dependencies — works identically in Node.js 24+ and browsers.
 */

import { secp256k1, schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hmac } from "@noble/hashes/hmac.js";
import { extract as hkdfExtract, expand as hkdfExpand } from "@noble/hashes/hkdf.js";
import { hex, base64 } from "@scure/base";
import { computeEventId, DEFAULT_RELAYS } from "./offerbook.mjs";
import { randomEvenKey, schnorrSign } from "./crypto.mjs";

export const KIND_DM_RUMOR = 14;
export const KIND_SEAL = 13;
export const KIND_GIFT_WRAP = 1059;

const enc = new TextEncoder();
const dec = new TextDecoder();
const NIP44_SALT = enc.encode("nip44-v2");

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

function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function randomBytes(n) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

// --- RFC 8439 ChaCha20 (counter = 0 for NIP-44 v2) ---
function rotl32(v, c) {
  return ((v << c) | (v >>> (32 - c))) >>> 0;
}

function quarterRound(s, a, b, c, d) {
  s[a] = (s[a] + s[b]) >>> 0; s[d] = rotl32(s[d] ^ s[a], 16);
  s[c] = (s[c] + s[d]) >>> 0; s[b] = rotl32(s[b] ^ s[c], 12);
  s[a] = (s[a] + s[b]) >>> 0; s[d] = rotl32(s[d] ^ s[a], 8);
  s[c] = (s[c] + s[d]) >>> 0; s[b] = rotl32(s[b] ^ s[c], 7);
}

function chacha20Block(key32, counter, nonce12) {
  const dvKey = new DataView(key32.buffer, key32.byteOffset, 32);
  const dvNonce = new DataView(nonce12.buffer, nonce12.byteOffset, 12);
  const state = new Uint32Array([
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
    dvKey.getUint32(0, true), dvKey.getUint32(4, true), dvKey.getUint32(8, true), dvKey.getUint32(12, true),
    dvKey.getUint32(16, true), dvKey.getUint32(20, true), dvKey.getUint32(24, true), dvKey.getUint32(28, true),
    counter >>> 0,
    dvNonce.getUint32(0, true), dvNonce.getUint32(4, true), dvNonce.getUint32(8, true),
  ]);
  const w = new Uint32Array(state);
  for (let i = 0; i < 10; i++) {
    quarterRound(w, 0, 4, 8, 12);
    quarterRound(w, 1, 5, 9, 13);
    quarterRound(w, 2, 6, 10, 14);
    quarterRound(w, 3, 7, 11, 15);
    quarterRound(w, 0, 5, 10, 15);
    quarterRound(w, 1, 6, 11, 12);
    quarterRound(w, 2, 7, 8, 13);
    quarterRound(w, 3, 4, 9, 14);
  }
  const out = new Uint8Array(64);
  const dvOut = new DataView(out.buffer);
  for (let i = 0; i < 16; i++) {
    dvOut.setUint32(i * 4, (w[i] + state[i]) >>> 0, true);
  }
  return out;
}

function chacha20(key32, nonce12, data) {
  const out = new Uint8Array(data.length);
  for (let block = 0, off = 0; off < data.length; block++, off += 64) {
    const ks = chacha20Block(key32, block, nonce12);
    const end = Math.min(64, data.length - off);
    for (let i = 0; i < end; i++) out[off + i] = data[off + i] ^ ks[i];
  }
  return out;
}

// --- NIP-44 v2 padding & key derivation ---
function calcPaddedLen(unpaddedLen) {
  if (unpaddedLen < 1 || unpaddedLen > 65535) {
    throw new Error(`NIP-44 invalid plaintext length: ${unpaddedLen}`);
  }
  if (unpaddedLen <= 32) return 32;
  const nextPower = 1 << (Math.floor(Math.log2(unpaddedLen - 1)) + 1);
  const chunk = nextPower <= 256 ? 32 : nextPower / 8;
  return chunk * (Math.floor((unpaddedLen - 1) / chunk) + 1);
}

function padPlaintext(plaintext) {
  const bytes = enc.encode(plaintext);
  const paddedLen = calcPaddedLen(bytes.length);
  const out = new Uint8Array(2 + paddedLen);
  out[0] = (bytes.length >> 8) & 0xff;
  out[1] = bytes.length & 0xff;
  out.set(bytes, 2);
  return out;
}

function unpadPlaintext(padded) {
  if (padded.length < 34) throw new Error("NIP-44 padded buffer too short");
  const unpaddedLen = (padded[0] << 8) | padded[1];
  if (unpaddedLen < 1 || 2 + unpaddedLen > padded.length || padded.length !== 2 + calcPaddedLen(unpaddedLen)) {
    throw new Error("NIP-44 invalid padding");
  }
  return dec.decode(padded.subarray(2, 2 + unpaddedLen));
}

export function getConversationKey(privBytes, peerPubXOnlyHex) {
  const peerCompressed = concatBytes(new Uint8Array([0x02]), hex.decode(peerPubXOnlyHex));
  const shared = secp256k1.getSharedSecret(privBytes, peerCompressed, true);
  const sharedX = shared.subarray(1, 33);
  return hkdfExtract(sha256, sharedX, NIP44_SALT);
}

function getMessageKeys(conversationKey, nonce32) {
  const keys = hkdfExpand(sha256, conversationKey, nonce32, 76);
  return {
    chachaKey: keys.subarray(0, 32),
    chachaNonce: keys.subarray(32, 44),
    hmacKey: keys.subarray(44, 76),
  };
}

export function nip44Encrypt(plaintext, conversationKey, nonce32 = randomBytes(32)) {
  const { chachaKey, chachaNonce, hmacKey } = getMessageKeys(conversationKey, nonce32);
  const padded = padPlaintext(plaintext);
  const ciphertext = chacha20(chachaKey, chachaNonce, padded);
  const mac = hmac(sha256, hmacKey, concatBytes(nonce32, ciphertext));
  return base64.encode(concatBytes(new Uint8Array([0x02]), nonce32, ciphertext, mac));
}

export function nip44Decrypt(payloadB64, conversationKey) {
  if (!payloadB64 || payloadB64[0] === "#") throw new Error("NIP-44 unsupported version");
  const raw = base64.decode(payloadB64);
  if (raw.length < 99 || raw[0] !== 0x02) throw new Error("NIP-44 invalid payload");
  const nonce32 = raw.subarray(1, 33);
  const ciphertext = raw.subarray(33, raw.length - 32);
  const mac = raw.subarray(raw.length - 32);
  const { chachaKey, chachaNonce, hmacKey } = getMessageKeys(conversationKey, nonce32);
  const expectedMac = hmac(sha256, hmacKey, concatBytes(nonce32, ciphertext));
  if (!equalBytes(mac, expectedMac)) throw new Error("NIP-44 invalid MAC");
  const padded = chacha20(chachaKey, chachaNonce, ciphertext);
  return unpadPlaintext(padded);
}

function jitteredTimestamp(nowSecs, maxPastSecs = 180) {
  const r = new Uint32Array(1);
  crypto.getRandomValues(r);
  return nowSecs - (r[0] % (maxPastSecs + 1));
}

function verifyNostrSig(ev) {
  if (!ev || typeof ev !== "object") return false;
  if (computeEventId(ev) !== ev.id) return false;
  return schnorr.verify(hex.decode(ev.sig), hex.decode(ev.id), hex.decode(ev.pubkey));
}

/**
 * NIP-17 / NIP-59 Gift Wrap: wraps `contentStr` in a kind-14 rumor -> kind-13 seal -> kind-1059 gift wrap.
 */
export function wrapGift(senderKey, recipientPubHex, contentStr, extraRumorTags = []) {
  const now = Math.floor(Date.now() / 1000);
  const rumor = {
    pubkey: senderKey.pubHex,
    created_at: now,
    kind: KIND_DM_RUMOR,
    tags: [["p", recipientPubHex], ...extraRumorTags],
    content: contentStr,
  };
  rumor.id = computeEventId(rumor);

  const sealConvKey = getConversationKey(senderKey.privBytes, recipientPubHex);
  const seal = {
    pubkey: senderKey.pubHex,
    created_at: jitteredTimestamp(now, 120),
    kind: KIND_SEAL,
    tags: [],
    content: nip44Encrypt(JSON.stringify(rumor), sealConvKey),
  };
  seal.id = computeEventId(seal);
  seal.sig = hex.encode(schnorrSign(senderKey, hex.decode(seal.id)));

  const ephemeral = randomEvenKey();
  const wrapConvKey = getConversationKey(ephemeral.privBytes, recipientPubHex);
  const wrap = {
    pubkey: ephemeral.pubHex,
    created_at: jitteredTimestamp(now, 120),
    kind: KIND_GIFT_WRAP,
    tags: [["p", recipientPubHex]],
    content: nip44Encrypt(JSON.stringify(seal), wrapConvKey),
  };
  wrap.id = computeEventId(wrap);
  wrap.sig = hex.encode(schnorrSign(ephemeral, hex.decode(wrap.id)));
  return wrap;
}

/**
 * Unwrap & cryptographically verify a NIP-17 / NIP-59 kind-1059 Gift Wrap.
 */
export function unwrapGift(recipientKey, wrapEvent) {
  if (!wrapEvent || wrapEvent.kind !== KIND_GIFT_WRAP) {
    throw new Error("Not a kind-1059 gift wrap");
  }
  if (!verifyNostrSig(wrapEvent)) throw new Error("Invalid gift wrap signature");

  const wrapConvKey = getConversationKey(recipientKey.privBytes, wrapEvent.pubkey);
  const seal = JSON.parse(nip44Decrypt(wrapEvent.content, wrapConvKey));
  if (!seal || seal.kind !== KIND_SEAL) throw new Error("Invalid inner seal kind");
  if (!verifyNostrSig(seal)) throw new Error("Invalid seal signature");

  const sealConvKey = getConversationKey(recipientKey.privBytes, seal.pubkey);
  const rumor = JSON.parse(nip44Decrypt(seal.content, sealConvKey));
  if (!rumor || rumor.kind !== KIND_DM_RUMOR) throw new Error("Invalid rumor kind");
  if (rumor.pubkey !== seal.pubkey) {
    throw new Error("NIP-59 impersonation detected: rumor.pubkey !== seal.pubkey");
  }
  return {
    senderPubkey: seal.pubkey,
    rumor,
    content: rumor.content,
    wrapId: wrapEvent.id,
  };
}

/**
 * Persistent multi-relay NIP-17 encrypted RPC peer (used by both LP listeners and User wallets).
 */
export class Nip17Peer {
  constructor(myKey, relays = DEFAULT_RELAYS, { onRequest } = {}) {
    this.myKey = myKey;
    this.relays = [...relays];
    this.onRequest = onRequest || null;
    this.sockets = new Map();
    this.seenWrapIds = new Set();
    this.pendingReqs = new Map();
    this.subId = `nip17-${hex.encode(randomBytes(4))}`;
    this.closed = false;
    this._healthTimer = null;
  }

  _startHealthCheck() {
    if (this._healthTimer) return;
    this._healthTimer = setInterval(() => {
      if (this.closed) return;
      for (const relayUrl of this.relays) {
        const ws = this.sockets.get(relayUrl);
        if (!ws || ws.readyState === 2 || ws.readyState === 3) {
          this.sockets.delete(relayUrl);
          this._connectSingle(relayUrl, 5000);
        }
      }
    }, 30_000);
  }

  _connectSingle(relayUrl, timeoutMs = 5000) {
    // NIP-59 randomizes outer kind:1059 `created_at` up to 48 hours in the past (used by nostr-sdk).
    const since = Math.floor(Date.now() / 1000) - 172_800 - 600;
    const filter = { kinds: [KIND_GIFT_WRAP], "#p": [this.myKey.pubHex], since };
    return new Promise((resolve) => {
      let settled = false;
      const finish = (ok) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(ok);
      };
      const timer = setTimeout(() => finish(false), timeoutMs);
      try {
        const ws = new WebSocket(relayUrl);
        this.sockets.set(relayUrl, ws);
        ws.onopen = () => {
          ws.send(JSON.stringify(["REQ", this.subId, filter]));
          finish(true);
        };
        ws.onmessage = (msg) => this._handleMessage(msg.data);
        ws.onerror = () => finish(false);
        ws.onclose = () => {
          this.sockets.delete(relayUrl);
          finish(false);
          if (!this.closed) {
            setTimeout(() => {
              if (!this.closed && !this.sockets.has(relayUrl)) {
                this._connectSingle(relayUrl, 5000);
              }
            }, 5000);
          }
        };
      } catch {
        finish(false);
      }
    });
  }

  async connect(timeoutMs = 5000) {
    if (this.relays.length === 0) return 0;
    this._startHealthCheck();
    const attempts = this.relays.map((relayUrl) => this._connectSingle(relayUrl, timeoutMs));
    const res = await Promise.all(attempts);
    return res.filter(Boolean).length;
  }

  async _handleMessage(rawData) {
    let frame;
    try {
      frame = JSON.parse(String(rawData));
    } catch {
      return;
    }
    if (!Array.isArray(frame) || frame[0] !== "EVENT" || !frame[2]) return;
    const wrap = frame[2];
    if (this.seenWrapIds.has(wrap.id)) return;
    this.seenWrapIds.add(wrap.id);

    let unwrapped;
    try {
      unwrapped = unwrapGift(this.myKey, wrap);
    } catch {
      return;
    }

    let msg;
    try {
      msg = JSON.parse(unwrapped.content);
    } catch {
      return;
    }

    if (msg?.type === "p2pfiat-rpc-res" && msg.reqId && this.pendingReqs.has(msg.reqId)) {
      const pend = this.pendingReqs.get(msg.reqId);
      if (pend.expectedPeer && pend.expectedPeer !== unwrapped.senderPubkey) return;
      this.pendingReqs.delete(msg.reqId);
      clearTimeout(pend.timer);
      if (msg.ok) pend.resolve(msg.result);
      else pend.reject(new Error(msg.error || "NIP-17 RPC error"));
      return;
    }

    if (msg?.type === "p2pfiat-rpc-req" && msg.reqId && msg.method && this.onRequest) {
      let reply;
      try {
        const result = await this.onRequest(msg.method, msg.params || {}, unwrapped.senderPubkey);
        reply = { type: "p2pfiat-rpc-res", reqId: msg.reqId, ok: true, result };
      } catch (err) {
        reply = {
          type: "p2pfiat-rpc-res",
          reqId: msg.reqId,
          ok: false,
          error: err?.message || String(err),
        };
      }
      await this.sendWrapped(unwrapped.senderPubkey, JSON.stringify(reply));
    }
  }

  async sendWrapped(recipientPubHex, contentStr) {
    const wrap = wrapGift(this.myKey, recipientPubHex, contentStr);
    const frame = JSON.stringify(["EVENT", wrap]);
    let sent = 0;
    for (const ws of this.sockets.values()) {
      if (ws.readyState === 1) {
        try {
          ws.send(frame);
          sent++;
        } catch {}
      }
    }
    if (sent === 0) throw new Error("No open Nostr relays for NIP-17 send");
    return wrap.id;
  }

  async request(recipientPubHex, method, params = {}, timeoutMs = 15_000) {
    if (this.sockets.size === 0) {
      const connected = await this.connect();
      if (connected === 0) throw new Error("Could not connect to any Nostr relay for NIP-17 RPC");
    }
    const reqId = `r-${hex.encode(randomBytes(6))}`;
    const payload = JSON.stringify({ type: "p2pfiat-rpc-req", reqId, method, params });

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pendingReqs.delete(reqId);
        reject(new Error(`NIP-17 RPC timeout for ${method}`));
      }, timeoutMs);
      this.pendingReqs.set(reqId, { resolve, reject, timer, expectedPeer: recipientPubHex });
      this.sendWrapped(recipientPubHex, payload).catch((err) => {
        clearTimeout(timer);
        this.pendingReqs.delete(reqId);
        reject(err);
      });
    });
  }

  close() {
    this.closed = true;
    for (const pend of this.pendingReqs.values()) {
      clearTimeout(pend.timer);
      pend.reject(new Error("Nip17Peer closed"));
    }
    this.pendingReqs.clear();
    for (const ws of this.sockets.values()) {
      try {
        if (ws.readyState === 1) ws.send(JSON.stringify(["CLOSE", this.subId]));
        ws.close();
      } catch {}
    }
    this.sockets.clear();
  }
}
