/**
 * Browser-native Unified Backup Key (`nsec1...`) & Nostr Account management.
 *
 * Every wallet user automatically gets a single `nsec1...` master backup key on first launch
 * (or can restore an existing `nsec1...` / 64-char hex key).
 * - Nostr identity = the `nsec1...` key itself (`npub1...` for NIP-17 DMs & optional profile).
 * - Arkade / Bitcoin spending key = deterministically derived via HKDF-SHA256 with domain
 *   separation (`salt = "p2pfiat/v1"`, `info = "arkade-spending-key"`), so 1 single backup
 *   string restores the entire wallet offline without any server or relay dependency, while
 *   keeping the Bitcoin/Arkade public key unlinkable to the Nostr `npub`.
 */

import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { extract as hkdfExtract, expand as hkdfExpand } from "@noble/hashes/hkdf.js";
import { hex, bech32 } from "@scure/base";
import { computeEventId, DEFAULT_RELAYS, pubkeyHexToNpub, publishOfferEvent } from "./offerbook.js";
import { getConversationKey, nip44Decrypt } from "./nip17.js";

const LS_NOSTR_PRIVKEY = "p2pfiat_nostr_privkey_hex";
const LS_AUTH_MODE = "p2pfiat_auth_mode";
const LS_NIP07_PUBKEY = "p2pfiat_nip07_pubkey";
const LS_WALLET_SEED = "p2pfiat_wallet_seed_hex";
const WALLET_SEED_D_TAG = "p2pfiat-wallet-seed-v1";
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const G = schnorr.Point.BASE;
const enc = new TextEncoder();
const ARKADE_HKDF_SALT = enc.encode("p2pfiat/v1");
const ARKADE_HKDF_INFO = enc.encode("arkade-spending-key");
const VAULT_HKDF_INFO = enc.encode("btc-l1-vault");
const RPC_TRANSPORT_HKDF_INFO = enc.encode("nostr-rpc-transport");

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

export function privkeyHexToNsec(privHex) {
  return bech32.encode("nsec", bech32.toWords(hex.decode(privHex.trim())));
}

function deriveSecp256k1KeyFromNsec(privHex, infoBytes) {
  const ikm = hex.decode(String(privHex).trim().toLowerCase());
  if (ikm.length !== 32) throw new Error("Expected 32-byte secret key for HKDF derivation");
  const prk = hkdfExtract(sha256, ikm, ARKADE_HKDF_SALT);
  for (let counter = 0; counter < 16; counter++) {
    const info =
      counter === 0 ? infoBytes : new Uint8Array([...infoBytes, counter]);
    const okm = hkdfExpand(sha256, prk, info, 32);
    let d = bytesToBigInt(okm);
    if (d <= 0n || d >= N) continue;
    const pt = G.multiply(d);
    if (!hasEvenY(pt)) d = N - d;
    return hex.encode(bigIntToBytes32(d));
  }
  throw new Error("HKDF derivation failed to produce a valid secp256k1 scalar");
}

/**
 * Deterministically derive an even-Y secp256k1 Arkade spending private key (64-char hex)
 * from the master Nostr secret key using HKDF-SHA256 with explicit domain separation.
 */
export function deriveArkadePrivKeyHexFromNsec(privHex) {
  return deriveSecp256k1KeyFromNsec(privHex, ARKADE_HKDF_INFO);
}

/**
 * Deterministically derive an independent single-key Bitcoin L1 Vault private key (P2TR)
 * from the master seed / `nsec` — 0 timelock, pure onchain self-custody.
 */
export function deriveVaultPrivKeyHexFromNsec(privHex) {
  return deriveSecp256k1KeyFromNsec(privHex, VAULT_HKDF_INFO);
}

/**
 * Deterministically derive a dedicated NIP-17 RPC transport key from a 32-byte wallet seed
 * (used in NIP-07 Extension mode so background LP/Watchtower/Nostracle RPC needs zero popups).
 */
export function deriveRpcTransportKeyFromSeed(seedHex) {
  return deriveSecp256k1KeyFromNsec(seedHex, RPC_TRANSPORT_HKDF_INFO);
}

export function hasNip07Extension() {
  return Boolean(typeof window !== "undefined" && window.nostr?.getPublicKey);
}

/**
 * Returns true only if the user has already logged in (via NIP-07 Extension, nsec restore,
 * or explicitly created a local wallet). Never auto-generates a ghost key.
 */
export function hasStoredAccount() {
  if (getAuthMode() === "nip07") return true;
  if (localStorage.getItem(LS_NOSTR_PRIVKEY)) return true;
  if (localStorage.getItem("p2pfiat_user_privkey_hex")) return true;
  return false;
}

/**
 * Clear active wallet session keys and cached account data from this browser (explicit Log out).
 */
export function clearAllWalletAuth() {
  localStorage.removeItem(LS_AUTH_MODE);
  localStorage.removeItem(LS_NIP07_PUBKEY);
  localStorage.removeItem(LS_WALLET_SEED);
  localStorage.removeItem(LS_NOSTR_PRIVKEY);
  localStorage.removeItem("p2pfiat_user_privkey_hex");
  localStorage.removeItem("p2pfiat_user_positions");
}

export function getAuthMode() {
  const mode = localStorage.getItem(LS_AUTH_MODE);
  const pub = localStorage.getItem(LS_NIP07_PUBKEY);
  const seed = localStorage.getItem(LS_WALLET_SEED);
  if (mode === "nip07" && pub && /^[0-9a-f]{64}$/i.test(pub) && seed && /^[0-9a-f]{64}$/i.test(seed)) {
    return "nip07";
  }
  return "local";
}

/**
 * Return the active wallet identity:
 * - `"nip07"`: user logged in with a NIP-07 browser extension (`window.nostr`), with their
 *   portable 32-byte `walletSeedHex` decrypted from Nostr `kind: 30078` (`p2pfiat-wallet-seed-v1`).
 * - `"local"`: zero-friction guest mode or `nsec1...` restore (works with zero Nostr extension).
 */
export function getActiveIdentity() {
  if (getAuthMode() === "nip07") {
    const pubHex = localStorage.getItem(LS_NIP07_PUBKEY).trim().toLowerCase();
    const walletSeedHex = localStorage.getItem(LS_WALLET_SEED).trim().toLowerCase();
    const rpcKey = parseNostrSecretKey(deriveRpcTransportKeyFromSeed(walletSeedHex));
    return {
      mode: "nip07",
      pubHex,
      npub: pubkeyHexToNpub(pubHex),
      nsec: null,
      walletSeedHex,
      rpcKey,
    };
  }
  const acct = getOrCreateNostrAccount();
  const customSeed = localStorage.getItem(LS_WALLET_SEED);
  const walletSeedHex =
    customSeed && /^[0-9a-f]{64}$/i.test(customSeed) ? customSeed.toLowerCase() : acct.privHex;
  return {
    mode: "local",
    ...acct,
    walletSeedHex,
    rpcKey: acct,
  };
}

/**
 * Fetch the latest NIP-44 encrypted portable wallet seed (`kind: 30078`, `d: "p2pfiat-wallet-seed-v1"`)
 * for `pubkeyHex` from Nostr relays.
 */
export async function fetchEncryptedWalletSeed(pubkeyHex, relays = DEFAULT_RELAYS, timeoutMs = 4000) {
  const list = Array.isArray(relays) && relays.length > 0 ? relays : DEFAULT_RELAYS;
  let latest = null;
  await Promise.all(
    list.map(
      (relayUrl) =>
        new Promise((resolve) => {
          let ws;
          let done = false;
          const finish = () => {
            if (done) return;
            done = true;
            try { ws?.close(); } catch {}
            resolve();
          };
          const timer = setTimeout(finish, timeoutMs);
          try {
            ws = new WebSocket(relayUrl);
            const subId = `seed-${Math.random().toString(16).slice(2, 10)}`;
            ws.onopen = () => {
              ws.send(
                JSON.stringify([
                  "REQ",
                  subId,
                  { kinds: [30078], authors: [pubkeyHex], "#d": [WALLET_SEED_D_TAG], limit: 1 },
                ])
              );
            };
            ws.onmessage = (msg) => {
              try {
                const frame = JSON.parse(String(msg.data));
                if (
                  frame[0] === "EVENT" &&
                  frame[2]?.kind === 30078 &&
                  frame[2].pubkey === pubkeyHex
                ) {
                  if (!latest || frame[2].created_at > latest.created_at) {
                    latest = frame[2];
                  }
                } else if (frame[0] === "EOSE") {
                  clearTimeout(timer);
                  finish();
                }
              } catch {}
            };
            ws.onerror = () => { clearTimeout(timer); finish(); };
            ws.onclose = () => { clearTimeout(timer); finish(); };
          } catch {
            clearTimeout(timer);
            finish();
          }
        })
    )
  );
  return latest;
}

/**
 * Login with a NIP-07 Nostr browser extension (`window.nostr` — Alby, nos2x, etc.).
 * - Your `nsec` NEVER leaves the extension.
 * - Restores or creates a NIP-44 encrypted 32-byte `walletSeedHex` in `kind: 30078`
 *   (`d: "p2pfiat-wallet-seed-v1"`) so your Arkade Spending key, Bitcoin L1 Vault, and
 *   open DLC positions travel seamlessly across any browser/device.
 */
export async function loginWithNip07Extension(relays = DEFAULT_RELAYS) {
  if (!hasNip07Extension()) {
    throw new Error("No Nostr extension found (install Alby or nos2x, or continue without an extension)");
  }
  if (!window.nostr?.nip44?.encrypt || !window.nostr?.nip44?.decrypt) {
    throw new Error("Your Nostr extension does not support NIP-44 encryption (update Alby/nos2x)");
  }
  if (!window.nostr?.signEvent) {
    throw new Error("Your Nostr extension does not support signEvent");
  }

  const pubHex = String(await window.nostr.getPublicKey()).trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(pubHex)) {
    throw new Error("Extension returned an invalid public key");
  }

  const existing = await fetchEncryptedWalletSeed(pubHex, relays);
  let walletSeedHex = null;
  let createdNew = false;

  if (existing?.content) {
    const plaintext = await window.nostr.nip44.decrypt(pubHex, existing.content);
    const parsed = JSON.parse(plaintext);
    if (!parsed?.walletSeedHex || !/^[0-9a-f]{64}$/i.test(parsed.walletSeedHex)) {
      throw new Error("Encrypted Nostr wallet seed is malformed");
    }
    walletSeedHex = parsed.walletSeedHex.toLowerCase();
  } else {
    walletSeedHex = generateRandomNostrKey().privHex;
    createdNew = true;
    const plaintext = JSON.stringify({
      v: 1,
      walletSeedHex,
      createdAt: Math.floor(Date.now() / 1000),
    });
    const encrypted = await window.nostr.nip44.encrypt(pubHex, plaintext);
    const unsigned = {
      pubkey: pubHex,
      created_at: Math.floor(Date.now() / 1000),
      kind: 30078,
      tags: [["d", WALLET_SEED_D_TAG]],
      content: encrypted,
    };
    const signed = await window.nostr.signEvent(unsigned);
    const pubRes = await publishOfferEvent(signed, relays);
    if (!pubRes?.accepted) {
      throw new Error("Could not publish encrypted wallet seed to any Nostr relay — check your relay connection");
    }
  }

  localStorage.setItem(LS_AUTH_MODE, "nip07");
  localStorage.setItem(LS_NIP07_PUBKEY, pubHex);
  localStorage.setItem(LS_WALLET_SEED, walletSeedHex);
  return {
    pubHex,
    npub: pubkeyHexToNpub(pubHex),
    walletSeedHex,
    createdNew,
  };
}

/**
 * Disconnect NIP-07 Extension session and return to local/guest wallet mode.
 */
export function logoutNip07Extension() {
  localStorage.removeItem(LS_AUTH_MODE);
  localStorage.removeItem(LS_NIP07_PUBKEY);
  localStorage.removeItem(LS_WALLET_SEED);
}

/**
 * When restoring an `nsec1...` directly (without an extension), check if that `npub`
 * previously created a portable NIP-44 encrypted wallet seed (`p2pfiat-wallet-seed-v1`)
 * via NIP-07 Extension — if so, decrypt and use that exact seed so funds are 100% portable
 * between Extension and `nsec` devices!
 */
export async function tryDecryptCloudWalletSeedWithNsec(nsecAccount, relays = DEFAULT_RELAYS) {
  try {
    const existing = await fetchEncryptedWalletSeed(nsecAccount.pubHex, relays, 3500);
    if (!existing?.content) return null;
    const convKey = getConversationKey(hex.decode(nsecAccount.privHex), nsecAccount.pubHex);
    const parsed = JSON.parse(nip44Decrypt(existing.content, convKey));
    if (parsed?.walletSeedHex && /^[0-9a-f]{64}$/i.test(parsed.walletSeedHex)) {
      const seed = parsed.walletSeedHex.toLowerCase();
      localStorage.setItem(LS_WALLET_SEED, seed);
      return seed;
    }
  } catch {}
  localStorage.removeItem(LS_WALLET_SEED);
  return null;
}

/**
 * Decode either a NIP-19 `nsec1...` string or a 64-char hex private key into a normalized
 * even-Y secp256k1 keypair object compatible with `Nip17Peer` and BIP-340 signing.
 */
export function parseNostrSecretKey(input) {
  const raw = String(input || "").trim();
  if (!raw) throw new Error("Empty Nostr secret key");

  let privBytes;
  if (raw.toLowerCase().startsWith("nsec1")) {
    const decoded = bech32.decode(raw.toLowerCase());
    if (decoded.prefix !== "nsec") {
      throw new Error(`Expected nsec1... prefix, got ${decoded.prefix}`);
    }
    privBytes = new Uint8Array(bech32.fromWords(decoded.words));
    if (privBytes.length !== 32) {
      throw new Error(`Invalid nsec payload length (${privBytes.length} bytes)`);
    }
  } else if (/^[0-9a-fA-F]{64}$/.test(raw)) {
    privBytes = hex.decode(raw.toLowerCase());
  } else {
    throw new Error("Enter a valid nsec1... key or 64-char hex private key");
  }

  let d = bytesToBigInt(privBytes);
  if (d <= 0n || d >= N) throw new Error("Private key out of secp256k1 range");

  let pt = G.multiply(d);
  // Preserve the exact secret scalar for Nostr (BIP-340 / NIP-01 derives x-only pubkey directly),
  // while exposing `d` normalized for even-Y signing helpers used by Nip17Peer.
  const rawPrivHex = hex.encode(privBytes);
  const pubXOnly = pointToXOnly(pt);
  const pubHex = hex.encode(pubXOnly);
  const evenD = hasEvenY(pt) ? d : N - d;

  return {
    d: evenD,
    privHex: rawPrivHex,
    evenPrivHex: hex.encode(bigIntToBytes32(evenD)),
    pubXOnly,
    pubHex,
    npub: pubkeyHexToNpub(pubHex),
    nsec: privkeyHexToNsec(rawPrivHex),
  };
}

export function generateRandomNostrKey() {
  while (true) {
    const priv = new Uint8Array(32);
    crypto.getRandomValues(priv);
    const d = bytesToBigInt(priv);
    if (d <= 0n || d >= N) continue;
    let pt = G.multiply(d);
    if (!hasEvenY(pt)) {
      const evenBytes = bigIntToBytes32(N - d);
      return parseNostrSecretKey(hex.encode(evenBytes));
    }
    return parseNostrSecretKey(hex.encode(priv));
  }
}

export function getOrCreateNostrAccount() {
  const stored = localStorage.getItem(LS_NOSTR_PRIVKEY);
  if (stored) {
    try {
      return parseNostrSecretKey(stored);
    } catch {
      // Fall through to fresh key generation if corrupted
    }
  }
  const fresh = generateRandomNostrKey();
  localStorage.setItem(LS_NOSTR_PRIVKEY, fresh.privHex);
  return fresh;
}

export function importNostrAccount(nsecOrHex) {
  const parsed = parseNostrSecretKey(nsecOrHex);
  localStorage.setItem(LS_NOSTR_PRIVKEY, parsed.privHex);
  return parsed;
}

export function resetNostrAccount() {
  const fresh = generateRandomNostrKey();
  localStorage.setItem(LS_NOSTR_PRIVKEY, fresh.privHex);
  return fresh;
}

/**
 * Fetch the latest NIP-01 `kind: 0` metadata profile for `pubkeyHex` across relays.
 */
export async function fetchNostrProfile(pubkeyHex, relays = DEFAULT_RELAYS, timeoutMs = 3500) {
  const list = Array.isArray(relays) && relays.length > 0 ? relays : DEFAULT_RELAYS;
  let latestEvent = null;

  await Promise.all(
    list.map(
      (relayUrl) =>
        new Promise((resolve) => {
          let ws;
          let done = false;
          const finish = () => {
            if (done) return;
            done = true;
            try {
              ws?.close();
            } catch { }
            resolve();
          };
          const timer = setTimeout(finish, timeoutMs);
          try {
            ws = new WebSocket(relayUrl);
            const subId = `prof-${Math.random().toString(16).slice(2, 10)}`;
            ws.onopen = () => {
              ws.send(
                JSON.stringify([
                  "REQ",
                  subId,
                  { kinds: [0], authors: [pubkeyHex], limit: 1 },
                ])
              );
            };
            ws.onmessage = (msg) => {
              try {
                const frame = JSON.parse(String(msg.data));
                if (frame[0] === "EVENT" && frame[2]?.kind === 0 && frame[2].pubkey === pubkeyHex) {
                  const ev = frame[2];
                  if (!latestEvent || ev.created_at > latestEvent.created_at) {
                    latestEvent = ev;
                  }
                } else if (frame[0] === "EOSE") {
                  clearTimeout(timer);
                  finish();
                }
              } catch { }
            };
            ws.onerror = () => {
              clearTimeout(timer);
              finish();
            };
            ws.onclose = () => {
              clearTimeout(timer);
              finish();
            };
          } catch {
            clearTimeout(timer);
            finish();
          }
        })
    )
  );

  if (!latestEvent) return null;
  try {
    const meta = JSON.parse(latestEvent.content || "{}");
    return {
      name: meta.display_name || meta.name || "",
      username: meta.name || "",
      nip05: meta.nip05 || "",
      picture: meta.picture || "",
      about: meta.about || "",
      updatedAt: latestEvent.created_at,
    };
  } catch {
    return null;
  }
}

/**
 * Sign and publish a NIP-01 `kind: 0` metadata profile event to relays.
 */
export async function publishNostrProfile(nostrAccount, profile, relays = DEFAULT_RELAYS, timeoutMs = 4000) {
  const list = Array.isArray(relays) && relays.length > 0 ? relays : DEFAULT_RELAYS;
  const contentObj = {
    name: String(profile.name || "").trim(),
    display_name: String(profile.name || "").trim(),
    about: String(profile.about || "p2pFiat self-custody Arkade wallet user").trim(),
  };
  if (profile.picture) contentObj.picture = String(profile.picture).trim();
  if (profile.nip05) contentObj.nip05 = String(profile.nip05).trim();

  const unsigned = {
    pubkey: nostrAccount.pubHex,
    created_at: Math.floor(Date.now() / 1000),
    kind: 0,
    tags: [],
    content: JSON.stringify(contentObj),
  };
  let signedEvent;
  if (nostrAccount.mode === "nip07" || !nostrAccount.privHex) {
    if (!window?.nostr?.signEvent) {
      throw new Error("Nostr extension required to sign profile update");
    }
    signedEvent = await window.nostr.signEvent(unsigned);
  } else {
    const id = computeEventId(unsigned);
    const sigBytes = schnorr.sign(hex.decode(id), hex.decode(nostrAccount.privHex));
    signedEvent = { ...unsigned, id, sig: hex.encode(sigBytes) };
  }
  const id = signedEvent.id;

  const results = await Promise.all(
    list.map(
      (relayUrl) =>
        new Promise((resolve) => {
          let ws;
          let done = false;
          const finish = (ok) => {
            if (done) return;
            done = true;
            try {
              ws?.close();
            } catch { }
            resolve({ relay: relayUrl, ok });
          };
          const timer = setTimeout(() => finish(false), timeoutMs);
          try {
            ws = new WebSocket(relayUrl);
            ws.onopen = () => {
              ws.send(JSON.stringify(["EVENT", signedEvent]));
            };
            ws.onmessage = (msg) => {
              try {
                const frame = JSON.parse(String(msg.data));
                if (frame[0] === "OK" && frame[1] === id) {
                  clearTimeout(timer);
                  finish(Boolean(frame[2]));
                }
              } catch { }
            };
            ws.onerror = () => {
              clearTimeout(timer);
              finish(false);
            };
            ws.onclose = () => {
              clearTimeout(timer);
              finish(false);
            };
          } catch {
            clearTimeout(timer);
            finish(false);
          }
        })
    )
  );

  const accepted = results.filter((r) => r.ok).length;
  return { event: signedEvent, accepted, total: results.length };
}
