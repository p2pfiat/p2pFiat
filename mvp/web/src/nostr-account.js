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
import { computeEventId, DEFAULT_RELAYS, pubkeyHexToNpub } from "./offerbook.js";

const LS_NOSTR_PRIVKEY = "p2pfiat_nostr_privkey_hex";
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const G = schnorr.Point.BASE;
const enc = new TextEncoder();
const ARKADE_HKDF_SALT = enc.encode("p2pfiat/v1");
const ARKADE_HKDF_INFO = enc.encode("arkade-spending-key");
const VAULT_HKDF_INFO = enc.encode("btc-l1-vault");

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
 * from the same master `nsec` backup string — 0 timelock, pure onchain self-custody.
 */
export function deriveVaultPrivKeyHexFromNsec(privHex) {
  return deriveSecp256k1KeyFromNsec(privHex, VAULT_HKDF_INFO);
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
  const id = computeEventId(unsigned);
  const sigBytes = schnorr.sign(hex.decode(id), hex.decode(nostrAccount.privHex));
  const signedEvent = { ...unsigned, id, sig: hex.encode(sigBytes) };

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
