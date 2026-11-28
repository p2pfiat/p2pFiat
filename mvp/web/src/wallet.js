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
  buildOffchainTx,
  MultisigTapscript,
  CSVMultisigTapscript,
  InMemoryWalletRepository,
  InMemoryContractRepository,
} from "@arkade-os/sdk";
import {
  ArkadeSwaps,
  decodeInvoice,
  getInvoiceSatoshis,
} from "@arkade-os/boltz-swap";
import * as btc from "@scure/btc-signer";
import { hex, base64, bech32 } from "@scure/base";
import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";

import {
  DEFAULT_RELAYS,
  LEGACY_RELAYS,
  withLegacyReadRelays,
  computeEventId,
  buildQuorumForPreset,
  DEFAULT_QUORUM_PRESET,
  isQuorumPresetAvailable,
  buildP2pOrderEvent,
  publishOfferEvent,
} from "./offerbook.js";
import {
  Nip17Peer,
  getConversationKey,
  nip44Encrypt,
  nip44Decrypt,
} from "./nip17.js";
import { computeKormirOutcomePoint } from "./nostracle-client.js";
import {
  buildDisputeWitnessSigs,
  hasLegacyDisputeLeaf,
  LEGACY_POSITION_TEXT,
  parseDisputeLeaf,
} from "./dispute-witness.js";
import {
  computeDisputeManifestHash,
  disputeLeafHashesHex,
  disputeLeavesFromTapTree,
  selectFallbackLeaf,
} from "./dispute-manifest.js";
import {
  getOrCreateNostrAccount,
  getActiveIdentity,
  importNostrAccount,
  resetNostrAccount,
  logoutNip07Extension,
  tryDecryptCloudWalletSeedWithNsec,
  deriveArkadePrivKeyHexFromNsec,
  deriveVaultPrivKeyHexFromNsec,
} from "./nostr-account.js";

export const ARK_URL = "https://mutinynet.arkade.sh";
export const ESPLORA_URL = "https://mutinynet.com/api";
const LEGACY_DEV_WATCHTOWER_PUBKEY =
  "08d19fed75e500fa6763db118b951a906c3ad7dfa98ace6d1c2c5bebde6e282d";
export const DEFAULT_WATCHTOWER_PUBKEY =
  "beb4bc21ac4e61d62dbcec51dbd8cfd7d45cd941cfb36258011eafe1b5fc8ffe";
export const DEFAULT_FAUCET_LP_PUBKEY =
  "577fcbd37606362e3c77273287a57c98c325de77e577fc77271c8e7c9ba504cd";

const LS_KEY = "p2pfiat_user_privkey_hex";
const LS_POSITIONS = "p2pfiat_user_positions";
const LS_LP_URL = "p2pfiat_lp_url";
const LS_RELAYS = "p2pfiat_nostr_relays";
const LS_WT_PUBKEY = "p2pfiat_watchtower_pubkey";
const LS_QUORUM_PRESET = "p2pfiat_quorum_preset";
const LS_CUSTOM_NOSTRACLES = "p2pfiat_custom_nostracles";

const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const G = schnorr.Point.BASE;
const enc = new TextEncoder();
const NUMS_INTERNAL_KEY_HEX =
  "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

function kCombinations(items, k) {
  const out = [];
  const rec = (start, cur) => {
    if (cur.length === k) {
      out.push([...cur]);
      return;
    }
    for (let i = start; i <= items.length - (k - cur.length); i++) {
      cur.push(items[i]);
      rec(i + 1, cur);
      cur.pop();
    }
  };
  rec(0, []);
  return out;
}

function buildNostracleDisputeLeaf(oraclePubsHex, threshold, exitDelaySecs) {
  if (!Array.isArray(oraclePubsHex) || oraclePubsHex.length < 2) return null;
  const k = Number(threshold);
  if (!Number.isInteger(k) || k < 2 || k > oraclePubsHex.length) return null;
  const normalized = oraclePubsHex.map((p) => p.trim().toLowerCase());
  const csvVal = (1 << 22) | Number(BigInt(exitDelaySecs) / 512n);
  const subsets = kCombinations(normalized, k);
  const allLeaves = subsets.map((subsetPubs) => {
    const encoded = CSVMultisigTapscript.encode({
      timelock: { type: "seconds", value: BigInt(exitDelaySecs) },
      pubkeys: subsetPubs.map((p) => hex.decode(p)),
    });
    return {
      script: encoded.script,
      scriptHex: hex.encode(encoded.script),
      oraclePubsHex: subsetPubs,
    };
  });
  const primary = allLeaves[0];
  return {
    script: primary.script,
    scriptHex: primary.scriptHex,
    oraclePubsHex: primary.oraclePubsHex,
    allOraclePubsHex: normalized,
    allLeaves,
    leafHashesHex: disputeLeafHashesHex(allLeaves.map((l) => l.script)),
    threshold: k,
    csvSequence: csvVal,
  };
}

function buildWatchtowerBountyScript(bountySpec) {
  const numsXOnly = hex.decode(NUMS_INTERNAL_KEY_HEX);
  const primaryLeaf = btc.Script.encode([hex.decode(bountySpec.primary_pubkey), "CHECKSIG"]);
  const backupPubs = bountySpec.backup_pubkeys || [];
  const backupCsv = Number(bountySpec.backup_csv || 4);
  let tree;
  if (backupPubs.length === 0) {
    tree = { script: primaryLeaf };
  } else {
    const leaves = [
      { script: primaryLeaf },
      ...backupPubs.map((pk) => ({
        script: btc.Script.encode([backupCsv, "CHECKSEQUENCEVERIFY", "DROP", hex.decode(pk), "CHECKSIG"]),
      })),
    ];
    tree = leaves.reduce((acc, leaf) => [acc, leaf]);
  }
  const p2tr = btc.p2tr(numsXOnly, tree, btc.TEST_NETWORK, true);
  return { pkScript: p2tr.script, pkScriptHex: hex.encode(p2tr.script) };
}

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

function adaptorSign(signer, msg32, adaptorPointT) {
  while (true) {
    const kBytes = new Uint8Array(32);
    crypto.getRandomValues(kBytes);
    const k = bytesToBigInt(kBytes);
    if (k <= 0n || k >= N) continue;
    const R = G.multiply(k).add(adaptorPointT);
    if (!hasEvenY(R)) continue;
    const rx = pointToXOnly(R);
    const e = bytesToBigInt(taggedHash("BIP0340/challenge", rx, signer.pubXOnly, msg32)) % N;
    const sPrime = (k + e * signer.d) % N;
    if (sPrime === 0n) continue;
    const sig = new Uint8Array(64);
    sig.set(rx, 0);
    sig.set(bigIntToBytes32(sPrime), 32);
    return sig;
  }
}

function deriveOutcomeAdaptorPoint(oraclePubXOnly, eventId, outcomeLabel) {
  const h = taggedHash(
    "p2pfiat/dlc-outcome",
    oraclePubXOnly,
    enc.encode(String(eventId)),
    enc.encode(String(outcomeLabel))
  );
  const scalar = (bytesToBigInt(h) % (N - 1n)) + 1n;
  return { scalar, point: G.multiply(scalar) };
}

function exitTxSighash(rawTxHex, contractPkScript, totalCollateralSats, exitScript) {
  const tx = btc.Transaction.fromRaw(hex.decode(rawTxHex), { allowUnknownInputs: true, allowUnknownOutputs: true });
  return tx.preimageWitnessV1(
    0,
    [contractPkScript],
    btc.SigHash.DEFAULT,
    [BigInt(totalCollateralSats)],
    -1,
    exitScript,
    0xc0
  );
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

function combineTapscriptSigs(baseTx, otherTx) {
  const out = Transaction.fromPSBT(baseTx.toPSBT());
  for (let i = 0; i < out.inputsLength; i++) {
    const a = out.getInput(i).tapScriptSig || [];
    const b = otherTx.getInput(i).tapScriptSig || [];
    const seen = new Set(a.map(([k]) => `${hex.encode(k.pubKey)}:${hex.encode(k.leafHash)}`));
    const merged = [...a];
    for (const entry of b) {
      const id = `${hex.encode(entry[0].pubKey)}:${hex.encode(entry[0].leafHash)}`;
      if (!seen.has(id)) {
        merged.push(entry);
        seen.add(id);
      }
    }
    if (merged.length) out.updateInput(i, { tapScriptSig: merged });
  }
  return out;
}

function isLocalDevHost() {
  try {
    const host = String(globalThis?.location?.hostname || "").toLowerCase();
    return host === "localhost" || host === "127.0.0.1" || host === "[::1]";
  } catch {
    return false;
  }
}

export function getLpUrl() {
  const saved = (localStorage.getItem(LS_LP_URL) || "").trim();
  if (saved) return saved;
  // Only fall back to a local dev LP when the web app itself runs on localhost;
  // on public HTTPS origins (e.g. p2pfiat.github.io) fetching 127.0.0.1 triggers
  // Chrome's scary "Access other apps and services on this device" (PNA) prompt.
  return isLocalDevHost() ? "http://127.0.0.1:3456" : "";
}

export function setLpUrl(url) {
  const clean = String(url || "").trim().replace(/\/+$/, "");
  if (!clean) {
    localStorage.removeItem(LS_LP_URL);
    return;
  }
  localStorage.setItem(LS_LP_URL, clean);
}

export function getNostrRelays() {
  const raw = localStorage.getItem(LS_RELAYS);
  if (!raw) return [...DEFAULT_RELAYS];
  const parsed = raw
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.startsWith("wss://") || s.startsWith("ws://"));
  if (parsed.length === 0) return [...DEFAULT_RELAYS];
  // Auto-upgrade any saved list containing retired legacy relays (damus/nos.lol/oxtr/bitcoiner.social)
  // to the verified DEFAULT_RELAYS while preserving any custom user-added relays.
  const legacySet = new Set(LEGACY_RELAYS);
  if (parsed.some((r) => legacySet.has(r))) {
    return [...new Set([...DEFAULT_RELAYS, ...parsed.filter((r) => !legacySet.has(r))])];
  }
  return parsed;
}

export function setNostrRelays(relaysOrStr) {
  const list = Array.isArray(relaysOrStr)
    ? relaysOrStr
    : String(relaysOrStr || "")
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.startsWith("wss://") || s.startsWith("ws://"));
  if (list.length === 0) throw new Error("Provide at least one wss:// relay URL");
  localStorage.setItem(LS_RELAYS, list.join(","));
  return list;
}

let discoveredWatchtowers = [];

export function setDiscoveredWatchtowers(list) {
  discoveredWatchtowers = Array.isArray(list) ? list.filter((w) => /^[0-9a-f]{64}$/i.test(w?.pubkey || "")) : [];
}

export function getBackupWatchtowerPubkeys() {
  return discoveredWatchtowers.slice(1).map((w) => w.pubkey.toLowerCase());
}

export function getWatchtowerPubkey() {
  const stored = localStorage.getItem(LS_WT_PUBKEY);
  if (stored === null || stored === LEGACY_DEV_WATCHTOWER_PUBKEY) {
    return discoveredWatchtowers[0]?.pubkey || DEFAULT_WATCHTOWER_PUBKEY;
  }
  return stored;
}

export function setWatchtowerPubkey(val) {
  const cleaned = String(val || "").trim();
  if (!cleaned) {
    localStorage.setItem(LS_WT_PUBKEY, "");
    return "";
  }
  if (!/^[0-9a-fA-F]{64}$/.test(cleaned)) {
    throw new Error("Watchtower pubkey must be 64-char hex x-only pubkey");
  }
  const lower = cleaned.toLowerCase();
  localStorage.setItem(LS_WT_PUBKEY, lower);
  return lower;
}

/** The saved quorum preset, or 2-of-3 when none is saved or too few Nostracles are live for it. */
export function getQuorumPreset() {
  const saved = localStorage.getItem(LS_QUORUM_PRESET) || DEFAULT_QUORUM_PRESET;
  return isQuorumPresetAvailable(saved) ? saved : DEFAULT_QUORUM_PRESET;
}

export function setQuorumPreset(preset) {
  const chosen = isQuorumPresetAvailable(preset) ? preset : DEFAULT_QUORUM_PRESET;
  localStorage.setItem(LS_QUORUM_PRESET, chosen);
  return chosen;
}

export function getCustomNostracles() {
  try {
    const arr = JSON.parse(localStorage.getItem(LS_CUSTOM_NOSTRACLES) || "[]");
    return Array.isArray(arr) ? arr : [];
  } catch {
    return [];
  }
}

export function addCustomNostracle(npubOrHex, name = "") {
  const raw = String(npubOrHex || "").trim();
  if (!raw) throw new Error("Enter a Nostracle npub1… or 64-char hex pubkey");
  let pubHex = "";
  if (raw.toLowerCase().startsWith("npub1")) {
    const dec = bech32.decode(raw.toLowerCase());
    if (dec.prefix !== "npub") throw new Error("Expected npub1… prefix");
    const bytes = new Uint8Array(bech32.fromWords(dec.words));
    if (bytes.length !== 32) throw new Error("Invalid npub length");
    pubHex = hex.encode(bytes);
  } else if (/^[0-9a-fA-F]{64}$/.test(raw)) {
    pubHex = raw.toLowerCase();
  } else {
    throw new Error("Invalid Nostracle key (expected npub1… or 64-char hex)");
  }
  const npub = bech32.encode("npub", bech32.toWords(hex.decode(pubHex)));
  const list = getCustomNostracles().filter((o) => o.pubkey !== pubHex);
  const entry = {
    name: String(name || "").trim() || `Custom-${pubHex.slice(0, 6)}`,
    pubkey: pubHex,
    npub,
    custom: true,
  };
  list.unshift(entry);
  localStorage.setItem(LS_CUSTOM_NOSTRACLES, JSON.stringify(list));
  return entry;
}

export function removeCustomNostracle(pubHex) {
  const target = String(pubHex || "").trim().toLowerCase();
  const next = getCustomNostracles().filter((o) => o.pubkey !== target);
  localStorage.setItem(LS_CUSTOM_NOSTRACLES, JSON.stringify(next));
  return next;
}

const POSITIONS_BACKUP_D_TAG = "p2pfiat-positions-backup-v1";
let _posBackupTimer = null;

export function loadPositions() {
  try {
    return JSON.parse(localStorage.getItem(LS_POSITIONS) || "{}");
  } catch {
    return {};
  }
}

export function savePositions(map, { skipNostrBackup = false } = {}) {
  localStorage.setItem(LS_POSITIONS, JSON.stringify(map));
  if (!skipNostrBackup) {
    if (_posBackupTimer) clearTimeout(_posBackupTimer);
    _posBackupTimer = setTimeout(() => {
      _posBackupTimer = null;
      backupPositionsToNostr(map).catch(() => {});
    }, 1500);
  }
}

/**
 * Encrypt open & recent DLC position metadata to self using NIP-44 v2 (`nsec1...` -> `npub1...`)
 * and publish as a replaceable NIP-78 `kind: 30078` event so restoring `nsec1...` on a new
 * device recovers all open DLC contracts (including Leaf 2 dispute scripts & oracle quorum).
 */
export async function backupPositionsToNostr(map = loadPositions()) {
  const identity = getActiveIdentity();
  const acct = identity?.rpcKey;
  if (!acct?.privHex || !acct?.pubHex) return null;
  const entries = Object.values(map || {});
  const open = entries.filter((p) => p?.status === "open");
  const closed = entries
    .filter((p) => p?.status !== "open")
    .sort((a, b) => (b.closedAt || b.openedAt || 0) - (a.closedAt || a.openedAt || 0))
    .slice(0, 15);
  const compact = {};
  for (const p of [...open, ...closed]) {
    if (!p?.positionId) continue;
    compact[p.positionId] = p;
  }
  const plaintext = JSON.stringify({ v: 1, updatedAt: Math.floor(Date.now() / 1000), positions: compact });
  if (plaintext.length > 60_000) return null;
  const convKey = getConversationKey(hex.decode(acct.privHex), acct.pubHex);
  const encrypted = nip44Encrypt(plaintext, convKey);
  const unsigned = {
    pubkey: acct.pubHex,
    created_at: Math.floor(Date.now() / 1000),
    kind: 30078,
    tags: [["d", POSITIONS_BACKUP_D_TAG]],
    content: encrypted,
  };
  const id = computeEventId(unsigned);
  const sig = hex.encode(schnorr.sign(hex.decode(id), hex.decode(acct.privHex)));
  return publishOfferEvent({ ...unsigned, id, sig }, getNostrRelays());
}

/**
 * Fetch and decrypt the latest NIP-44 self-encrypted DLC position backup from Nostr relays,
 * merging any missing or newer positions into `localStorage`.
 */
export async function restorePositionsFromNostr(timeoutMs = 4000) {
  const identity = getActiveIdentity();
  const acct = identity?.rpcKey;
  if (!acct?.privHex || !acct?.pubHex) return { restoredCount: 0, totalCount: 0 };
  const relays = getNostrRelays();
  const readRelays = withLegacyReadRelays(relays);
  let latest = null;
  await Promise.all(
    readRelays.map(
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
            const subId = `pbk-${Math.random().toString(16).slice(2, 8)}`;
            ws.onopen = () => {
              ws.send(
                JSON.stringify([
                  "REQ",
                  subId,
                  { kinds: [30078], authors: [acct.pubHex], "#d": [POSITIONS_BACKUP_D_TAG], limit: 1 },
                ])
              );
            };
            ws.onmessage = (msg) => {
              try {
                const frame = JSON.parse(String(msg.data));
                if (frame[0] === "EVENT" && frame[2]) {
                  const ev = frame[2];
                  if (ev.kind !== 30078 || ev.pubkey !== acct.pubHex) return;
                  if (computeEventId(ev) !== ev.id) return;
                  if (!schnorr.verify(hex.decode(ev.sig), hex.decode(ev.id), hex.decode(ev.pubkey))) return;
                  if (!latest || ev.created_at > latest.created_at) latest = ev;
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
  if (!latest?.content) return { restoredCount: 0, totalCount: Object.keys(loadPositions()).length };

  const convKey = getConversationKey(hex.decode(acct.privHex), acct.pubHex);
  const parsed = JSON.parse(nip44Decrypt(latest.content, convKey));
  // Best-effort republish the already-signed positions backup event to the current relay set
  // so backups fetched from retired legacy relays self-migrate to the new defaults.
  if (latest.id && latest.sig) {
    publishOfferEvent(latest, relays).catch(() => {});
  }
  const remoteMap = parsed?.positions || {};
  const localMap = loadPositions();
  let restoredCount = 0;
  for (const [id, remotePos] of Object.entries(remoteMap)) {
    const localPos = localMap[id];
    if (!localPos) {
      localMap[id] = remotePos;
      restoredCount++;
    } else if (localPos.status === "open" && remotePos.status === "closed") {
      localMap[id] = remotePos;
      restoredCount++;
    } else if ((remotePos.rollCount || 0) > (localPos.rollCount || 0)) {
      localMap[id] = remotePos;
      restoredCount++;
    }
  }
  if (restoredCount > 0) savePositions(localMap, { skipNostrBackup: true });
  return { restoredCount, totalCount: Object.keys(localMap).length };
}

export function getOrCreatePrivKeyHex(nostrAccount = null) {
  let k = localStorage.getItem(LS_KEY);
  if (!k) {
    const acct = nostrAccount || getOrCreateNostrAccount();
    k = deriveArkadePrivKeyHexFromNsec(acct.privHex);
    localStorage.setItem(LS_KEY, k);
  }
  return k;
}

export function importPrivKeyHex(privHex) {
  const normalized = keyFromHex(privHex).privHex;
  localStorage.setItem(LS_KEY, normalized);
  return normalized;
}

/**
 * Restore the entire wallet (both Nostr identity and derived Arkade/Vault keys)
 * from a single `nsec1...` (or 64-char hex) backup string.
 * Also checks Nostr relays for a NIP-44 encrypted portable wallet seed (`p2pfiat-wallet-seed-v1`)
 * in case the wallet was originally created via a NIP-07 browser extension.
 */
export async function restoreFromBackupKey(nsecOrHex) {
  logoutNip07Extension();
  localStorage.removeItem(LS_POSITIONS);
  const nostrAccount = importNostrAccount(nsecOrHex);
  const cloudSeed = await tryDecryptCloudWalletSeedWithNsec(nostrAccount, getNostrRelays());
  const effectiveSeed = cloudSeed || nostrAccount.privHex;
  const derivedArkHex = deriveArkadePrivKeyHexFromNsec(effectiveSeed);
  localStorage.setItem(LS_KEY, derivedArkHex);
  return { nostrAccount, arkPrivHex: derivedArkHex, restoredCloudSeed: Boolean(cloudSeed) };
}

/**
 * Create a brand-new Nostr identity (`nsec1...`) and deterministically derive its
 * unified Arkade Spending & Bitcoin L1 Vault keys (for users without an existing Nostr account).
 */
export function createFreshNostrWallet() {
  logoutNip07Extension();
  localStorage.removeItem(LS_POSITIONS);
  const nostrAccount = resetNostrAccount();
  const derivedArkHex = deriveArkadePrivKeyHexFromNsec(nostrAccount.privHex);
  localStorage.setItem(LS_KEY, derivedArkHex);
  return { nostrAccount, arkPrivHex: derivedArkHex };
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
    const identity = getActiveIdentity();
    const seedHex = identity.walletSeedHex;
    const derivedArkHex = deriveArkadePrivKeyHexFromNsec(seedHex);
    const privHex =
      identity.mode === "nip07" ? derivedArkHex : getOrCreatePrivKeyHex(identity);
    const isLegacySeparateKey =
      identity.mode !== "nip07" && privHex.toLowerCase() !== derivedArkHex.toLowerCase();
    const userKey = keyFromHex(privHex);
    const vaultKey = keyFromHex(deriveVaultPrivKeyHexFromNsec(seedHex));
    const nostrKey = identity.rpcKey;
    const vaultPayment = btc.p2tr(vaultKey.pubXOnly, undefined, btc.TEST_NETWORK);
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
    const userArkScript = new DefaultVtxo.Script({
      pubKey: userKey.pubXOnly,
      serverPubKey: serverXOnly,
      csvTimelock: { type: "seconds", value: exitDelaySecs },
    });
    return new BrowserP2pFiatWallet({
      userKey,
      vaultKey,
      vaultPayment,
      nostrKey,
      authIdentity: identity,
      isLegacySeparateKey,
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
      vaultAddress: this.vaultPayment.address,
    };
  }

  async getVaultBalance() {
    const address = this.vaultPayment.address;
    try {
      const r = await fetch(`${ESPLORA_URL}/address/${address}/utxo`);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const utxos = await r.json();
      let confirmed = 0;
      let unconfirmed = 0;
      for (const u of utxos) {
        const val = Number(u.value || 0);
        if (u.status?.confirmed) confirmed += val;
        else unconfirmed += val;
      }
      return { address, confirmed, unconfirmed, total: confirmed + unconfirmed, utxos };
    } catch {
      return { address, confirmed: 0, unconfirmed: 0, total: 0, utxos: [] };
    }
  }

  /**
   * Spend directly from the single-key P2TR Bitcoin L1 Vault (0 timelock, no Arkade server needed).
   * Pass `amountSats = null` (or `'max'`) to sweep the full vault balance minus fee.
   */
  async sendFromVault(destAddress, amountSats = null, feeRateSatVb = 2) {
    const vb = await this.getVaultBalance();
    const utxos = (vb.utxos || []).slice().sort((a, b) => Number(b.value) - Number(a.value));
    if (utxos.length === 0) throw new Error("Bitcoin Vault (L1) is empty");

    const DUST = 546;
    const isMax = amountSats === null || amountSats === "max";
    const target = isMax ? 0 : Math.floor(Number(amountSats));
    if (!isMax && (!Number.isFinite(target) || target < DUST)) {
      throw new Error(`Amount must be at least ${DUST} sats`);
    }

    const selected = [];
    let totalIn = 0;
    let fee = 0;
    for (const u of utxos) {
      selected.push(u);
      totalIn += Number(u.value);
      const estVbytes = Math.ceil(11 + selected.length * 58 + (isMax ? 43 : 86));
      fee = Math.max(200, estVbytes * feeRateSatVb);
      if (!isMax && totalIn >= target + fee) break;
    }

    const sendAmt = isMax ? totalIn - fee : target;
    if (sendAmt < DUST) {
      throw new Error(`Vault balance (${totalIn} sats) too small after ~${fee} sat L1 fee`);
    }
    if (!isMax && totalIn < target + fee) {
      throw new Error(`Insufficient Vault balance (${totalIn} sats < ${target + fee} sats incl. fee)`);
    }

    const tx = new btc.Transaction();
    for (const u of selected) {
      tx.addInput({
        txid: u.txid,
        index: Number(u.vout),
        witnessUtxo: {
          script: this.vaultPayment.script,
          amount: BigInt(u.value),
        },
        tapInternalKey: this.vaultKey.pubXOnly,
      });
    }
    tx.addOutputAddress(destAddress.trim(), BigInt(sendAmt), btc.TEST_NETWORK);
    const change = totalIn - sendAmt - fee;
    if (!isMax && change >= DUST) {
      tx.addOutputAddress(this.vaultPayment.address, BigInt(change), btc.TEST_NETWORK);
    }

    tx.sign(hex.decode(this.vaultKey.privHex));
    tx.finalize();
    const rawHex = hex.encode(tx.extract());

    const res = await fetch(`${ESPLORA_URL}/tx`, {
      method: "POST",
      headers: { "Content-Type": "text/plain" },
      body: rawHex,
    });
    const text = await res.text();
    if (!res.ok) throw new Error(`Broadcast failed: ${text || res.status}`);
    return { txid: text.trim(), amountSats: sendAmt, feeSats: fee };
  }

  /** Move a chosen amount (or 'max') from Bitcoin L1 Vault into Arkade Spending (auto-onboards after 1 conf). */
  async moveVaultToArkade(amountSats = null) {
    const boardingAddr = await this.wallet.getBoardingAddress();
    return this.sendFromVault(boardingAddr, amountSats);
  }

  /** Move a chosen amount from Arkade Spending into the pure L1 Bitcoin Vault (0 timelock). */
  async moveArkadeToVault(amountSats, onEvent) {
    return this.offboardToL1(this.vaultPayment.address, amountSats, onEvent);
  }

  async getBalance() {
    return this.wallet.getBalance();
  }

  async onboard(onEvent) {
    return new Ramps(this.wallet).onboard(this.info.fees, undefined, undefined, onEvent);
  }

  /** Settle preconfirmed Arkade VTXOs into the next Arkade Round (compacts deep unroll chains to 1 hop). */
  async settleVtxos(onEvent) {
    return this.wallet.settle(undefined, onEvent);
  }

  /**
   * Request a one-time 20,000-sat instant Arkade onboarding grant on Mutinynet from LP-Home
   * straight to this wallet's `tark1…` Arkade address (~2s arrival, strictly Mutinynet only).
   */
  async requestMutinynetFaucet(lpPubHex = DEFAULT_FAUCET_LP_PUBKEY) {
    const net = String(this.info?.network || "mutinynet").toLowerCase();
    if (net === "bitcoin" || net === "mainnet") {
      return { skipped: true, reason: "mainnet" };
    }
    const arkAddress = await this.wallet.getAddress();
    const peer = this.getNip17Peer();
    if (peer.sockets.size === 0) {
      const ok = await peer.connect(6_000);
      if (ok === 0) throw new Error("Could not connect to Nostr relays for faucet request");
    }
    const res = await peer.request(lpPubHex, "faucet", { arkAddress }, 25_000);
    return { ...res, arkAddress, lpPubHex };
  }

  /** Instant offchain Arkade payment to a `tark1...` / `ark1...` address. */
  async sendArk(address, amountSats) {
    const sats = Math.floor(Number(amountSats));
    if (!Number.isFinite(sats) || sats <= 0) throw new Error("Amount must be > 0 sats");
    return this.wallet.send({ address: address.trim(), amount: sats });
  }

  /** Collaborative offboard from Arkade to a Mutinynet L1 `tb1...` address. */
  async offboardToL1(destinationAddress, amountSats, onEvent) {
    const sats = BigInt(Math.floor(Number(amountSats)));
    if (sats <= 0n) throw new Error("Amount must be > 0 sats");
    return new Ramps(this.wallet).offboard(
      destinationAddress.trim(),
      this.info.fees,
      sats,
      onEvent
    );
  }

  async getTransactionHistory() {
    try {
      return (await this.wallet.getTransactionHistory()) || [];
    } catch {
      return [];
    }
  }

  /** Lazily initialize Boltz Lightning swaps (VHTLC directly on Arkade). */
  async getSwaps(onSwapCompleted) {
    if (!this._swapsPromise) {
      this._swapsPromise = ArkadeSwaps.create({ wallet: this.wallet })
        .then((swaps) => {
          this.swaps = swaps;
          const mgr = swaps.getSwapManager?.();
          if (mgr && onSwapCompleted) {
            mgr.onSwapCompleted((swap) => onSwapCompleted(swap));
          }
          return swaps;
        })
        .catch((err) => {
          this._swapsPromise = null;
          throw err;
        });
    }
    return this._swapsPromise;
  }

  async getLightningInfo() {
    try {
      const swaps = await this.getSwaps();
      const [fees, limits] = await Promise.all([swaps.getFees(), swaps.getLimits()]);
      return { available: true, fees, limits };
    } catch (err) {
      return { available: false, error: err?.message || "Boltz swap service unavailable" };
    }
  }

  decodeLightningInvoice(invoice) {
    const clean = String(invoice || "").trim().replace(/^lightning:/i, "");
    const decoded = decodeInvoice(clean);
    const amountSats = getInvoiceSatoshis(clean);
    return { clean, decoded, amountSats };
  }

  /** Create a BOLT11 Lightning invoice that auto-claims directly into Arkade Available BTC. */
  async createLightningInvoice(amountSats, description = "p2pFiat wallet deposit") {
    const sats = Math.floor(Number(amountSats));
    if (!Number.isFinite(sats) || sats <= 0) throw new Error("Amount must be > 0 sats");
    const swaps = await this.getSwaps();
    return swaps.createLightningInvoice({ amount: sats, description });
  }

  /** Pay a BOLT11 Lightning invoice directly from Arkade Available BTC via Boltz VHTLC. */
  async payLightningInvoice(invoice) {
    const clean = String(invoice || "").trim().replace(/^lightning:/i, "");
    if (!clean) throw new Error("Empty Lightning invoice");
    const swaps = await this.getSwaps();
    return swaps.sendLightningPayment({ invoice: clean });
  }

  async verifyOrderBook(orderBook, opts = {}) {
    return orderBook.verifyOffersOnArkade({
      indexerProvider: this.indexerProvider,
      serverXOnly: this.serverXOnly,
      exitDelaySecs: this.exitDelaySecs,
      DefaultVtxo,
      ...opts,
    });
  }

  setNostrAccount(nostrKey) {
    this.nostrKey = nostrKey;
    this.nip17Peer?.close();
    this.nip17Peer = null;
  }

  getNip17Peer() {
    const relays = getNostrRelays();
    if (
      !this.nip17Peer ||
      this.nip17Peer.relays.join(",") !== relays.join(",") ||
      this.nip17Peer.myKey?.pubHex !== this.nostrKey?.pubHex
    ) {
      this.nip17Peer?.close();
      this.nip17Peer = new Nip17Peer(this.nostrKey, relays, {
        onRequest: (method, params, senderPubkey) =>
          this._handleP2pMakerRpc(method, params, senderPubkey),
      });
    }
    return this.nip17Peer;
  }

  /**
   * Publish a live P2P Maker Order (`kind: 38384`) from this browser wallet and
   * listen over NIP-17 for a peer Taker to match it directly (0% LP spread).
   */
  async postP2pOrder({
    side = "short",
    currency = "USD",
    notional = 5,
    spotPrice = 60000,
    fundingRateBpsPerDay = 3,
    termSecs = 86_400,
    expirySecs = 900,
    displayName = "",
    onOrderFilled = null,
  }) {
    const cur = String(currency || "USD").toUpperCase();
    const pair = `BTC-${cur}`;
    const makerSide = side === "long" ? "long" : "short";
    const requiredSats = Math.max(1_000, Math.round((Number(notional) / Number(spotPrice)) * 1e8));
    const vtxos = await this.wallet.getVtxos();
    const spendable = vtxos.filter((v) => Number(v.value) >= requiredSats);
    const totalAvail = vtxos.reduce((s, v) => s + Number(v.value || 0), 0);
    if (spendable.length === 0) {
      throw new Error(`Need a spendable Arkade VTXO >= ${requiredSats.toLocaleString()} sats to post this order`);
    }

    const quorum = buildQuorumForPreset(getQuorumPreset());
    const lpName = displayName ? `${displayName} (P2P)` : "P2P Peer";
    const event = buildP2pOrderEvent(this.nostrKey, {
      pair,
      currency: cur,
      makerSide,
      notional: Number(notional),
      spotPrice: Number(spotPrice),
      fundingRateBpsPerDay: Number(fundingRateBpsPerDay),
      availableLiquiditySats: totalAvail,
      arkPubkey: this.userKey.pubHex,
      lpName,
      termSecs: Number(termSecs || 86_400),
      expirySecs,
      oracleQuorum: quorum,
    });

    const peer = this.getNip17Peer();
    await peer.connect();
    const pub = await publishOfferEvent(event, getNostrRelays());
    if (pub.accepted === 0) {
      throw new Error("No Nostr relay accepted the P2P order event");
    }

    this._p2pQuotes = new Map();
    this._p2pPendingOpens = new Map();
    this.activeP2pOrder = {
      pair,
      currency: cur,
      makerSide,
      takerSide: makerSide === "long" ? "short" : "long",
      notional: Number(notional),
      spotPrice: Number(spotPrice),
      makerFundingBps: Number(fundingRateBpsPerDay),
      takerFundingBps: -Number(fundingRateBpsPerDay),
      termSecs: Number(termSecs || 86_400),
      lpName,
      oracleQuorum: quorum,
      expiresAt: Math.floor(Date.now() / 1000) + Number(expirySecs),
      eventId: event.id,
      onOrderFilled,
    };
    return { order: this.activeP2pOrder, event, ...pub };
  }

  async cancelP2pOrder() {
    const ord = this.activeP2pOrder;
    this.activeP2pOrder = null;
    this._p2pQuotes?.clear();
    this._p2pPendingOpens?.clear();
    if (!ord) return null;
    const cancelEv = buildP2pOrderEvent(this.nostrKey, {
      pair: ord.pair,
      currency: ord.currency,
      makerSide: ord.makerSide,
      notional: ord.notional,
      spotPrice: ord.spotPrice,
      fundingRateBpsPerDay: ord.makerFundingBps,
      availableLiquiditySats: 0,
      arkPubkey: this.userKey.pubHex,
      lpName: ord.lpName,
      cancel: true,
    });
    const res = await publishOfferEvent(cancelEv, getNostrRelays());
    return { event: cancelEv, ...res };
  }

  async _handleP2pMakerRpc(method, params = {}, senderPubkey = "") {
    const ord = this.activeP2pOrder;
    if (!ord || Math.floor(Date.now() / 1000) > ord.expiresAt) {
      throw new Error("No active P2P order");
    }

    if (method === "health") {
      const bal = await this.getBalance();
      return {
        ok: true,
        lpName: ord.lpName,
        makerType: "p2p",
        pairs: [ord.pair],
        spreadBps: 0,
        fundingRateBpsPerDay: ord.takerFundingBps,
        oracleQuorum: ord.oracleQuorum,
        spotUsd: ord.currency === "USD" ? ord.spotPrice : undefined,
        spotEur: ord.currency === "EUR" ? ord.spotPrice : undefined,
        arkBalance: { available: bal.available || 0 },
      };
    }

    if (method === "quote") {
      const reqSide = String(params.side || ord.takerSide).toLowerCase() === "long" ? "long" : "short";
      if (reqSide !== ord.takerSide) {
        throw new Error(`This P2P order matches ${ord.takerSide === "long" ? "2x Long BTC" : `Stable ${ord.currency}`} only`);
      }
      const notional = ord.notional;
      const collatSats = Math.max(1_000, Math.round((notional / ord.spotPrice) * 1e8));
      const quoteId = `p2pq-${hex.encode(crypto.getRandomValues(new Uint8Array(6)))}`;
      const quote = {
        quoteId,
        lpName: ord.lpName,
        makerType: "p2p",
        side: ord.takerSide,
        leverage: ord.takerSide === "long" ? 2 : 1,
        liquidationPrice: ord.takerSide === "long" ? Math.round(ord.spotPrice * 0.5) : 0,
        currency: ord.currency,
        pair: ord.pair,
        notional,
        notionalUsd: notional,
        spotPrice: ord.spotPrice,
        spotUsd: ord.spotPrice,
        effectiveSpotUsd: ord.spotPrice,
        spreadBps: 0,
        termSecs: ord.termSecs || 86_400,
        fundingRateBpsPerDay: ord.takerFundingBps,
        userCollateralSats: collatSats,
        lpCollateralSats: collatSats,
        totalCollateralSats: collatSats * 2,
        lpPubkey: this.nostrKey.pubHex,
        oracleQuorum: ord.oracleQuorum,
        expiresAt: Math.min(ord.expiresAt, Math.floor(Date.now() / 1000) + 120),
      };
      this._p2pQuotes.set(quoteId, quote);
      return quote;
    }

    if (method === "open/propose") {
      const quote = this._p2pQuotes.get(params.quoteId);
      if (!quote) throw new Error("Unknown or expired P2P quoteId");
      if (Math.floor(Date.now() / 1000) > quote.expiresAt) throw new Error("P2P quote expired");

      const takerPubXOnly = hex.decode(params.userPubHex);
      const settleClosure = MultisigTapscript.encode({
        pubkeys: [takerPubXOnly, this.userKey.pubXOnly, this.serverXOnly],
      });
      const exitClosure = CSVMultisigTapscript.encode({
        timelock: { type: "seconds", value: BigInt(this.exitDelaySecs) },
        pubkeys: [takerPubXOnly, this.userKey.pubXOnly],
      });
      const posQuorum = quote.oracleQuorum || ord.oracleQuorum;
      const disputeClosure =
        posQuorum?.oracles?.length >= 2 && Number(posQuorum.threshold) >= 2
          ? buildNostracleDisputeLeaf(
              posQuorum.oracles.map((o) => o.pubkey),
              posQuorum.threshold,
              this.exitDelaySecs
            )
          : null;
      const contractLeaves = [settleClosure.script, exitClosure.script];
      if (disputeClosure?.allLeaves?.length) {
        for (const leaf of disputeClosure.allLeaves) contractLeaves.push(leaf.script);
      } else if (disputeClosure) {
        contractLeaves.push(disputeClosure.script);
      }
      const contractScript = new VtxoScript(contractLeaves);
      const disputeControlBlockHex = disputeClosure
        ? hex.encode(
            btc.TaprootControlBlock.encode(
              contractScript.findLeaf(disputeClosure.scriptHex)[0]
            )
          )
        : null;

      const myVtxos = await this.wallet.getVtxos();
      const myVtxo = myVtxos
        .filter((v) => Number(v.value) >= quote.lpCollateralSats)
        .sort((a, b) => Number(b.value) - Number(a.value))[0];
      if (!myVtxo) throw new Error("Maker lacks sufficient spendable Arkade VTXO");

      const takerVtxoScript = VtxoScript.decode(hex.decode(params.userInput.tapTreeHex));
      const takerTapLeaf = takerVtxoScript.findLeaf(params.userInput.leafScriptHex);
      const takerArkInput = {
        txid: params.userInput.txid,
        vout: Number(params.userInput.vout),
        value: Number(params.userInput.value),
        tapLeafScript: takerTapLeaf,
        tapTree: takerVtxoScript.encode(),
      };
      const myDefaultLeaf = this.userArkScript.forfeit();
      const myDefaultLeafScript = myDefaultLeaf[1].slice(0, -1);
      const myDefaultLeafHash = tapLeafHash(myDefaultLeafScript);
      const makerArkInput = {
        txid: myVtxo.txid,
        vout: myVtxo.vout,
        value: Number(myVtxo.value),
        tapLeafScript: myDefaultLeaf,
        tapTree: this.userArkScript.encode(),
      };

      const DUST = 330n;
      const outputs = [{ script: contractScript.pkScript, amount: BigInt(quote.totalCollateralSats) }];
      const takerChange = BigInt(takerArkInput.value) - BigInt(quote.userCollateralSats);
      if (takerChange < 0n) throw new Error("Taker input smaller than collateral");
      if (takerChange >= DUST) {
        outputs.push({ script: hex.decode(params.userChangeScriptHex), amount: takerChange });
      }
      const makerChange = BigInt(makerArkInput.value) - BigInt(quote.lpCollateralSats);
      if (makerChange >= DUST) {
        outputs.push({ script: this.userArkScript.pkScript, amount: makerChange });
      }

      const checkpointTapscript = CSVMultisigTapscript.decode(hex.decode(this.info.checkpointTapscript));
      const { arkTx, checkpoints } = buildOffchainTx([takerArkInput, makerArkInput], outputs, checkpointTapscript);
      const [takerCk, makerCk] = checkpoints;

      const prevScripts = [takerCk.getOutput(0).script, makerCk.getOutput(0).script];
      const prevAmounts = [takerCk.getOutput(0).amount, makerCk.getOutput(0).amount];
      const makerArkHash = tapscriptSighash(arkTx, 1, prevScripts, prevAmounts, myDefaultLeafScript);
      const makerCkHash = tapscriptSighash(
        makerCk,
        0,
        [this.userArkScript.pkScript],
        [BigInt(makerArkInput.value)],
        myDefaultLeafScript
      );

      attachTapscriptSig(arkTx, 1, this.userKey.pubXOnly, myDefaultLeafHash, schnorrSign(this.userKey, makerArkHash));
      const makerCkUnsignedB64 = base64.encode(makerCk.toPSBT());
      const makerCkSigned = Transaction.fromPSBT(base64.decode(makerCkUnsignedB64));
      attachTapscriptSig(makerCkSigned, 0, this.userKey.pubXOnly, myDefaultLeafHash, schnorrSign(this.userKey, makerCkHash));

      const positionId = `p2p-${hex.encode(crypto.getRandomValues(new Uint8Array(6)))}`;
      const openedAt = Math.floor(Date.now() / 1000);
      const takerCkUnsignedB64 = base64.encode(takerCk.toPSBT());

      // Build 2-party signed Contract Manifest + lean Leaf 2 Watchtower exitSuite for P2P matches
      let disputeManifest = null;
      let exitSuite = null;
      if (disputeClosure) {
        const userPayoutScriptHex = hex.encode(
          btc.p2tr(takerPubXOnly, undefined, btc.TEST_NETWORK).script
        );
        const lpPayoutScriptHex = hex.encode(
          btc.p2tr(this.userKey.pubXOnly, undefined, btc.TEST_NETWORK).script
        );
        const manifestFields = {
          contract_id: positionId,
          vtxo_outpoint: `${arkTx.id}:0`,
          currency: (quote.currency || "USD").toUpperCase(),
          side: quote.side || "short",
          total_collateral_sats: Number(quote.totalCollateralSats),
          notional_fiat: Number(quote.notional ?? quote.notionalUsd),
          opened_at: openedAt,
          funding_rate_bps_per_day: Number(quote.fundingRateBpsPerDay),
          user_pubkey_hex: params.userPubHex.toLowerCase(),
          lp_pubkey_hex: this.userKey.pubHex.toLowerCase(),
          vtxo_pk_script_hex: hex.encode(contractScript.pkScript),
          // v2: commit to every k-of-n subset leaf (p2pfiat/p2pFiat#20)
          manifest_version: disputeClosure.allLeaves ? 2 : 1,
          dispute_script_hex: disputeClosure.scriptHex,
          ...(disputeClosure.allLeaves ? { dispute_leaf_hashes_hex: disputeClosure.leafHashesHex } : {}),
          user_payout_script_hex: userPayoutScriptHex,
          lp_payout_script_hex: lpPayoutScriptHex,
        };
        const mHash = computeDisputeManifestHash(manifestFields);
        disputeManifest = {
          ...manifestFields,
          lp_manifest_sig_hex: hex.encode(schnorrSign(this.userKey, mHash)),
        };

        const total = BigInt(quote.totalCollateralSats);
        const bountyAmt = total >= 4_000n ? 1_000n : total >= 2_500n ? 600n : 0n;
        const distributable = total - bountyAmt;
        const primaryWt = params.watchtowerPubHex || getWatchtowerPubkey() || this.userKey.pubHex;
        const bountySpec = {
          amount_sats: Number(bountyAmt > 0n ? bountyAmt : 1_000n),
          vout: 2,
          primary_pubkey: primaryWt,
          backup_pubkeys: [],
          backup_csv: 4,
        };
        const bountyScript = buildWatchtowerBountyScript(bountySpec);
        const [exitCtrlObj] = contractScript.findLeaf(hex.encode(exitClosure.script));
        const exitCtrlHex = hex.encode(btc.TaprootControlBlock.encode(exitCtrlObj));
        const csvSequence = (1 << 22) | Number(BigInt(this.exitDelaySecs) / 512n);
        const refundLockTime = openedAt + 7 * 86_400;
        const halfAmt = distributable / 2n;
        const refundTx = new btc.Transaction({ version: 2, lockTime: refundLockTime });
        refundTx.addInput({ txid: arkTx.id, index: 0, sequence: csvSequence });
        refundTx.addOutput({ script: hex.decode(userPayoutScriptHex), amount: halfAmt });
        refundTx.addOutput({ script: hex.decode(lpPayoutScriptHex), amount: distributable - halfAmt });
        if (bountyAmt > 0n) {
          refundTx.addOutput({ script: bountyScript.pkScript, amount: bountyAmt });
        }
        const refundTxHex = hex.encode(refundTx.toBytes(true, false));
        const refundHash = exitTxSighash(
          refundTxHex,
          contractScript.pkScript,
          Number(total),
          exitClosure.script
        );
        const primaryOracle = posQuorum?.oracles?.[0];
        exitSuite = {
          oracle_pubkey: primaryOracle?.pubkey || null,
          oracle_event_id: `btc${(quote.currency || "USD").toLowerCase()}-${openedAt + Number(quote.termSecs || 86_400)}`,
          exit_control_block: exitCtrlHex,
          exit_csv: 0,
          exit_csv_seconds: Number(this.exitDelaySecs),
          bounty: bountySpec,
          payouts: [],
          refund: {
            tx_hex: refundTxHex,
            refund_height: refundLockTime,
            user_sig: null,
            lp_sig: hex.encode(schnorrSign(this.userKey, refundHash)),
          },
          dispute: {
            script_hex: disputeClosure.scriptHex,
            control_block_hex: disputeControlBlockHex,
            csv_sequence: disputeClosure.csvSequence,
            oracle_quorum: posQuorum,
            leaves: (disputeClosure.allLeaves || []).map((l) => ({
              script_hex: l.scriptHex,
              control_block_hex: hex.encode(
                btc.TaprootControlBlock.encode(contractScript.findLeaf(l.scriptHex)[0])
              ),
            })),
          },
        };
      }

      this._p2pPendingOpens.set(positionId, {
        quote,
        ord,
        openedAt,
        senderPubkey,
        takerPubHex: params.userPubHex,
        contractPkScriptHex: hex.encode(contractScript.pkScript),
        contractTapTreeHex: hex.encode(contractScript.encode()),
        settleScriptHex: hex.encode(settleClosure.script),
        exitScriptHex: hex.encode(exitClosure.script),
        disputeScriptHex: disputeClosure?.scriptHex || null,
        disputeControlBlockHex,
        disputeCsvSequence: disputeClosure?.csvSequence || null,
        disputeManifest,
        exitSuite,
        takerCkUnsignedB64,
        makerCkUnsignedB64,
        makerCkSignedB64: base64.encode(makerCkSigned.toPSBT()),
      });

      return {
        positionId,
        quote,
        contractPkScriptHex: hex.encode(contractScript.pkScript),
        contractTapTreeHex: hex.encode(contractScript.encode()),
        settleScriptHex: hex.encode(settleClosure.script),
        exitScriptHex: hex.encode(exitClosure.script),
        arkTxB64: base64.encode(arkTx.toPSBT()),
        userCkB64: takerCkUnsignedB64,
        exitSuite,
        disputeManifest,
      };
    }

    if (method === "open/finalize") {
      const pend = this._p2pPendingOpens.get(params.positionId);
      if (!pend) throw new Error("Unknown pending P2P open");

      const sub = await this.arkProvider.submitTx(params.signedArkTxB64, [
        pend.takerCkUnsignedB64,
        pend.makerCkUnsignedB64,
      ]);
      const finalCk0 = combineTapscriptSigs(
        Transaction.fromPSBT(base64.decode(params.signedUserCkB64)),
        Transaction.fromPSBT(base64.decode(sub.signedCheckpointTxs[0]))
      );
      const finalCk1 = combineTapscriptSigs(
        Transaction.fromPSBT(base64.decode(pend.makerCkSignedB64)),
        Transaction.fromPSBT(base64.decode(sub.signedCheckpointTxs[1]))
      );
      await this.arkProvider.finalizeTx(sub.arkTxid, [
        base64.encode(finalCk0.toPSBT()),
        base64.encode(finalCk1.toPSBT()),
      ]);

      this._p2pPendingOpens.delete(params.positionId);
      let completedManifest = pend.disputeManifest;
      if (completedManifest && params.userManifestSigHex) {
        const mHash = computeDisputeManifestHash(completedManifest);
        const takerOk = schnorr.verify(
          hex.decode(params.userManifestSigHex),
          mHash,
          hex.decode(completedManifest.user_pubkey_hex)
        );
        if (takerOk) {
          completedManifest = {
            ...completedManifest,
            user_manifest_sig_hex: params.userManifestSigHex,
          };
        }
      }
      const nowSecs = pend.openedAt || Math.floor(Date.now() / 1000);
      const takerPos = {
        positionId: params.positionId,
        status: "open",
        side: pend.quote.side,
        leverage: pend.quote.leverage,
        liquidationPrice: pend.quote.liquidationPrice,
        currency: pend.quote.currency,
        pair: pend.quote.pair,
        openedAt: nowSecs,
        vtxoTxid: sub.arkTxid,
        vtxoVout: 0,
        notional: pend.quote.notional,
        notionalUsd: pend.quote.notional,
        openSpotPrice: pend.quote.spotPrice,
        openSpotUsd: pend.quote.spotPrice,
        spreadBps: 0,
        fundingRateBpsPerDay: pend.quote.fundingRateBpsPerDay,
        oracleQuorum: pend.quote.oracleQuorum,
        userCollateralSats: pend.quote.userCollateralSats,
        lpCollateralSats: pend.quote.lpCollateralSats,
        totalCollateralSats: pend.quote.totalCollateralSats,
        userPubHex: pend.takerPubHex,
        lpPubHex: this.userKey.pubHex,
        contractPkScriptHex: pend.contractPkScriptHex,
        contractTapTreeHex: pend.contractTapTreeHex,
        settleScriptHex: pend.settleScriptHex,
        exitScriptHex: pend.exitScriptHex,
        disputeScriptHex: pend.disputeScriptHex,
        disputeControlBlockHex: pend.disputeControlBlockHex,
        disputeCsvSequence: pend.disputeCsvSequence,
        disputeManifest: completedManifest,
        exitDelaySecs: Number(this.exitDelaySecs),
      };

      // Save Maker's mirror position locally (including Leaf 2 disputeManifest & exitSuite)
      const makerExitSuite = pend.exitSuite
        ? {
            ...pend.exitSuite,
            refund: pend.exitSuite.refund
              ? { ...pend.exitSuite.refund, user_sig: params.userRefundSigHex || pend.exitSuite.refund.user_sig }
              : null,
          }
        : null;
      const makerPos = {
        ...takerPos,
        exitSuite: makerExitSuite,
        side: pend.ord.makerSide,
        leverage: pend.ord.makerSide === "long" ? 2 : 1,
        liquidationPrice: pend.ord.makerSide === "long" ? Math.round(pend.quote.spotPrice * 0.5) : 0,
        fundingRateBpsPerDay: pend.ord.makerFundingBps,
        lpName: "P2P Match",
        lpPubkey: pend.senderPubkey,
        lpUrl: "",
        lpTransport: "nostr-nip17",
      };
      const map = loadPositions();
      map[makerPos.positionId] = makerPos;
      savePositions(map);

      // Auto-register Maker's mirror position with Watchtower if configured
      const makerWt = getWatchtowerPubkey();
      if (makerWt && makerPos.disputeManifest?.user_manifest_sig_hex) {
        this.registerWithWatchtower(makerPos.positionId, makerWt).catch(() => {});
      }

      const cb = pend.ord.onOrderFilled;
      await this.cancelP2pOrder().catch(() => {});
      cb?.(makerPos);
      return takerPos;
    }

    throw new Error(`Unsupported P2P method: ${method}`);
  }

  _normalizeTarget(targetOrUrl) {
    if (typeof targetOrUrl === "string") {
      return { url: targetOrUrl, pubkey: null, preferNip17: false, relays: [] };
    }
    if (targetOrUrl && typeof targetOrUrl === "object") {
      const termSecs = Number(targetOrUrl.termSecs || targetOrUrl.offer?.termSecs || 0);
      return {
        url: targetOrUrl.url || "",
        pubkey: targetOrUrl.pubkey || null,
        preferNip17: Boolean(targetOrUrl.preferNip17),
        lpName: targetOrUrl.lpName || "",
        relays: Array.isArray(targetOrUrl.relays) ? targetOrUrl.relays : [],
        ...(Number.isFinite(termSecs) && termSecs > 0 ? { termSecs } : {}),
      };
    }
    return { url: getLpUrl(), pubkey: null, preferNip17: false, relays: [] };
  }

  async callLp(targetOrUrl, method, params = {}) {
    const t = this._normalizeTarget(targetOrUrl);
    const useNip17First = t.preferNip17 || (!t.url && Boolean(t.pubkey));
    if (useNip17First) {
      if (!t.pubkey) throw new Error("Missing LP pubkey for NIP-17 P2P transport");
      const peer = this.getNip17Peer();
      if (t.relays?.length) await peer.ensureRelays(t.relays);
      return peer.request(t.pubkey, method, params);
    }
    if (!t.url) {
      throw new Error("No LP connected yet (waiting for Nostr orderbook offers)");
    }
    try {
      if (method === "health" || method === "offer" || method === "positions") {
        const r = await fetch(`${t.url}/${method}`);
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return await r.json();
      }
      return await postJson(`${t.url}/${method}`, params);
    } catch (httpErr) {
      if (t.pubkey) {
        return this.getNip17Peer().request(t.pubkey, method, params);
      }
      throw httpErr;
    }
  }

  async fetchLpHealth(target = getLpUrl()) {
    return this.callLp(target, "health");
  }

  async requestQuote(notional, target = getLpUrl(), currency = "USD", side = "short") {
    const t = this._normalizeTarget(target);
    return this.callLp(t, "quote", {
      currency: String(currency || "USD").toUpperCase(),
      side: side === "long" ? "long" : "short",
      notional,
      notionalUsd: notional,
      ...(t.termSecs ? { termSecs: t.termSecs } : {}),
    });
  }

  async openPosition(notional, target = getLpUrl(), lpName = "", currency = "USD", side = "short") {
    const cur = String(currency || "USD").toUpperCase();
    const posSide = side === "long" ? "long" : "short";
    const t = this._normalizeTarget(target);
    const q = await this.requestQuote(notional, t, cur, posSide);
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

    const prop = await this.callLp(t, "open/propose", {
      quoteId: q.quoteId,
      userPubHex: this.userKey.pubHex,
      watchtowerPubHex: getWatchtowerPubkey() || undefined,
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

    // Pre-verify & co-sign LP/Maker's Contract Manifest + refund sig before finalize
    // so P2P Makers also receive the complete 2-party signed manifest & refund tx.
    let preSignedManifest = null;
    if (prop.disputeManifest?.lp_manifest_sig_hex) {
      const mHash = computeDisputeManifestHash(prop.disputeManifest);
      const lpOk = schnorr.verify(
        hex.decode(prop.disputeManifest.lp_manifest_sig_hex),
        mHash,
        hex.decode(prop.disputeManifest.lp_pubkey_hex)
      );
      if (!lpOk) throw new Error("LP/Maker dispute manifest signature invalid! Refusing position.");
      preSignedManifest = {
        ...prop.disputeManifest,
        user_manifest_sig_hex: hex.encode(schnorrSign(this.userKey, mHash)),
      };
    }
    let preSignedRefundSigHex = null;
    if (prop.exitSuite?.refund?.tx_hex && prop.exitScriptHex) {
      const refHash = exitTxSighash(
        prop.exitSuite.refund.tx_hex,
        hex.decode(prop.contractPkScriptHex),
        q.totalCollateralSats,
        hex.decode(prop.exitScriptHex)
      );
      preSignedRefundSigHex = hex.encode(schnorrSign(this.userKey, refHash));
    }

    const pos = await this.callLp(t, "open/finalize", {
      positionId: prop.positionId,
      signedArkTxB64: base64.encode(arkTx.toPSBT()),
      signedUserCkB64: base64.encode(userCk.toPSBT()),
      userManifestSigHex: preSignedManifest?.user_manifest_sig_hex || undefined,
      userRefundSigHex: preSignedRefundSigHex || undefined,
    });
    pos.lpUrl = t.url || "";
    pos.lpPubkey = t.pubkey || q.lpPubkey || pos.lpPubHex || null;
    pos.lpName = lpName || t.lpName || q.lpName || "LP";
    pos.lpTransport = !t.url || t.preferNip17 ? "nostr-nip17" : "http";

    // Co-sign pre-built DLC exit payouts (adaptor sigs) + timelocked refund tx locally
    if (prop.exitSuite) {
      const contractPkScript = hex.decode(pos.contractPkScriptHex);
      const exitScript = hex.decode(pos.exitScriptHex);
      const oraclePubXOnly = hex.decode(prop.exitSuite.oracle_pubkey);
      const signedPayouts = (prop.exitSuite.payouts || []).map((p) => {
        const sighash = exitTxSighash(p.tx_hex, contractPkScript, pos.totalCollateralSats, exitScript);
        const pointT =
          prop.exitSuite.usesRealKind88Nonces && prop.exitSuite.announcementNoncesHex?.length
            ? computeKormirOutcomePoint(oraclePubXOnly, prop.exitSuite.announcementNoncesHex, p.outcome)
            : deriveOutcomeAdaptorPoint(oraclePubXOnly, prop.exitSuite.oracle_event_id, p.outcome).point;
        return {
          ...p,
          user_adaptor_sig: hex.encode(adaptorSign(this.userKey, sighash, pointT)),
        };
      });
      let signedRefund = prop.exitSuite.refund;
      if (signedRefund) {
        const refHash = exitTxSighash(
          signedRefund.tx_hex,
          contractPkScript,
          pos.totalCollateralSats,
          exitScript
        );
        signedRefund = {
          ...signedRefund,
          user_sig: hex.encode(schnorrSign(this.userKey, refHash)),
        };
      }
      pos.exitSuite = {
        ...prop.exitSuite,
        payouts: signedPayouts,
        refund: signedRefund,
      };
    }

    // Attach verified 2-party signed Contract Manifest (from pre-finalize or finalize response)
    if (preSignedManifest) {
      pos.disputeManifest = preSignedManifest;
    } else if (pos.disputeManifest?.lp_manifest_sig_hex) {
      const mHash = computeDisputeManifestHash(pos.disputeManifest);
      const lpOk = schnorr.verify(
        hex.decode(pos.disputeManifest.lp_manifest_sig_hex),
        mHash,
        hex.decode(pos.disputeManifest.lp_pubkey_hex)
      );
      if (!lpOk) throw new Error("LP dispute manifest signature invalid! Refusing position.");
      pos.disputeManifest = {
        ...pos.disputeManifest,
        user_manifest_sig_hex: hex.encode(schnorrSign(this.userKey, mHash)),
      };
    }

    const map = loadPositions();
    map[pos.positionId] = pos;
    savePositions(map);

    // Automatically register keyless Watchtower package via NIP-17 if configured in Settings
    const wtPub = getWatchtowerPubkey();
    if (wtPub) {
      try {
        await this.registerWithWatchtower(pos.positionId, wtPub);
        pos.watchtowerRegistered = true;
        pos.watchtowerPubkey = wtPub;
        map[pos.positionId] = pos;
        savePositions(map);
      } catch {
        pos.watchtowerRegistered = false;
      }
    }
    return pos;
  }

  async rollPosition(positionId, { expectedSpot = 0, maxSpotDriftPct = 2.0, relays = [] } = {}) {
    const map = loadPositions();
    const pos = map[positionId];
    if (!pos) throw new Error("Unknown position");
    if (hasLegacyDisputeLeaf(pos)) throw new Error(LEGACY_POSITION_TEXT);
    const target = {
      url: pos.lpUrl || (pos.lpTransport === "nostr-nip17" ? "" : getLpUrl()),
      pubkey: pos.lpPubkey || pos.lpPubHex || null,
      preferNip17: pos.lpTransport === "nostr-nip17",
      // LP's advertised NIP-17 relays (from its order-book offer), so a roll still reaches an LP
      // that listens on relays other than this wallet's defaults.
      relays: Array.isArray(relays) ? relays : [],
    };

    const prop = await this.callLp(target, "roll/propose", {
      positionId,
      watchtowerPubHex: getWatchtowerPubkey() || undefined,
    });
    const proposedSpot = Number(prop.rollSpotUsd || 0);
    if (expectedSpot > 0 && proposedSpot > 0) {
      const driftPct = (Math.abs(proposedSpot - expectedSpot) / expectedSpot) * 100;
      if (driftPct > maxSpotDriftPct) {
        throw new Error(
          `LP roll spot ${proposedSpot} deviates ${driftPct.toFixed(2)}% from live spot ${expectedSpot} — refusing to sign`
        );
      }
    }
    const arkTx = Transaction.fromPSBT(base64.decode(prop.arkTxB64));
    const ck = Transaction.fromPSBT(base64.decode(prop.ckB64));
    const settleScript = hex.decode(pos.settleScriptHex);
    const settleLeafHash = tapLeafHash(settleScript);
    const contractPkScript = hex.decode(pos.contractPkScriptHex);

    if (
      hex.encode(arkTx.getOutput(0).script) !== pos.contractPkScriptHex ||
      arkTx.getOutput(0).amount !== BigInt(prop.newTotalCollateralSats)
    ) {
      throw new Error("LP roll proposal output 0 mismatch! Refusing to sign.");
    }
    const expectedSurplus = BigInt(Math.max(0, Math.floor(Number(prop.userSurplusSats || 0))));
    if (expectedSurplus > 0n) {
      const out1 = arkTx.outputsLength > 1 ? arkTx.getOutput(1) : null;
      if (
        !out1 ||
        hex.encode(out1.script) !== hex.encode(this.userArkScript.pkScript) ||
        out1.amount !== expectedSurplus
      ) {
        throw new Error("LP roll proposal user surplus output mismatch! Refusing to sign.");
      }
    }

    const ckHash = tapscriptSighash(ck, 0, [contractPkScript], [BigInt(pos.totalCollateralSats)], settleScript);
    const arkHash = tapscriptSighash(arkTx, 0, [ck.getOutput(0).script], [ck.getOutput(0).amount], settleScript);
    attachTapscriptSig(arkTx, 0, this.userKey.pubXOnly, settleLeafHash, schnorrSign(this.userKey, arkHash));
    attachTapscriptSig(ck, 0, this.userKey.pubXOnly, settleLeafHash, schnorrSign(this.userKey, ckHash));

    const rolled = await this.callLp(target, "roll/finalize", {
      positionId,
      signedArkTxB64: base64.encode(arkTx.toPSBT()),
      signedCkB64: base64.encode(ck.toPSBT()),
    });
    rolled.lpUrl = pos.lpUrl || "";
    rolled.lpPubkey = target.pubkey;
    rolled.lpName = pos.lpName || "LP";
    rolled.lpTransport = pos.lpTransport || "http";
    rolled.autoRoll = Boolean(pos.autoRoll);

    // Co-sign fresh DLC exit payouts + refund tx for the rolled VTXO
    if (prop.exitSuite) {
      const exitScript = hex.decode(rolled.exitScriptHex);
      const oraclePubXOnly = hex.decode(prop.exitSuite.oracle_pubkey);
      const signedPayouts = (prop.exitSuite.payouts || []).map((p) => {
        const sighash = exitTxSighash(p.tx_hex, contractPkScript, rolled.totalCollateralSats, exitScript);
        const pointT =
          prop.exitSuite.usesRealKind88Nonces && prop.exitSuite.announcementNoncesHex?.length
            ? computeKormirOutcomePoint(oraclePubXOnly, prop.exitSuite.announcementNoncesHex, p.outcome)
            : deriveOutcomeAdaptorPoint(oraclePubXOnly, prop.exitSuite.oracle_event_id, p.outcome).point;
        return { ...p, user_adaptor_sig: hex.encode(adaptorSign(this.userKey, sighash, pointT)) };
      });
      let signedRefund = prop.exitSuite.refund;
      if (signedRefund) {
        const refHash = exitTxSighash(signedRefund.tx_hex, contractPkScript, rolled.totalCollateralSats, exitScript);
        signedRefund = { ...signedRefund, user_sig: hex.encode(schnorrSign(this.userKey, refHash)) };
      }
      rolled.exitSuite = { ...prop.exitSuite, payouts: signedPayouts, refund: signedRefund };
    }

    // Verify & co-sign fresh 2-party Contract Manifest if provided on roll
    const rollManifestSrc = prop.disputeManifest || rolled.disputeManifest;
    if (rollManifestSrc?.lp_manifest_sig_hex) {
      const mHash = computeDisputeManifestHash(rollManifestSrc);
      const lpOk = schnorr.verify(
        hex.decode(rollManifestSrc.lp_manifest_sig_hex),
        mHash,
        hex.decode(rollManifestSrc.lp_pubkey_hex)
      );
      if (!lpOk) throw new Error("LP rolled dispute manifest signature invalid! Refusing roll.");
      rolled.disputeManifest = {
        ...rollManifestSrc,
        user_manifest_sig_hex: hex.encode(schnorrSign(this.userKey, mHash)),
      };
    }

    map[positionId] = rolled;
    savePositions(map);

    // Automatically update keyless Watchtower package via NIP-17 after roll if configured
    const wtPub = getWatchtowerPubkey();
    if (wtPub) {
      try {
        await this.registerWithWatchtower(positionId, wtPub);
        rolled.watchtowerRegistered = true;
        rolled.watchtowerPubkey = wtPub;
        map[positionId] = rolled;
        savePositions(map);
      } catch {
        rolled.watchtowerRegistered = false;
      }
    }
    return rolled;
  }

  async closePosition(positionId) {
    const map = loadPositions();
    const pos = map[positionId];
    if (!pos) throw new Error("Unknown position");
    if (hasLegacyDisputeLeaf(pos)) throw new Error(LEGACY_POSITION_TEXT);
    const target = {
      url: pos.lpUrl || (pos.lpTransport === "nostr-nip17" ? "" : getLpUrl()),
      pubkey: pos.lpPubkey || pos.lpPubHex || null,
      preferNip17: pos.lpTransport === "nostr-nip17",
    };

    const prop = await this.callLp(target, "close/propose", { positionId });
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

    const closed = await this.callLp(target, "close/finalize", {
      positionId,
      signedArkTxB64: base64.encode(arkTx.toPSBT()),
      signedCkB64: base64.encode(ck.toPSBT()),
    });
    closed.lpUrl = pos.lpUrl || "";
    closed.lpPubkey = target.pubkey;
    closed.lpName = pos.lpName || "LP";
    closed.lpTransport = pos.lpTransport || "http";
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
    // Only traverse strict ancestors of the DLC VTXO to keep the unroll chain minimal.
    if (txObjByTxid.has(pos.vtxoTxid)) {
      visit(pos.vtxoTxid);
    } else {
      for (const c of nonCommit) visit(c.txid);
    }

    const suite = pos.exitSuite || {};
    return {
      id: positionId,
      vtxo_outpoint: `${pos.vtxoTxid}:${pos.vtxoVout}`,
      vtxo_amount_sats: pos.totalCollateralSats,
      vtxo_pk_script: pos.contractPkScriptHex,
      ark_indexer_url: ARK_URL,
      unroll_txs: ordered.map((id) => rawByTxid.get(id)),
      exit_script: pos.exitScriptHex,
      exit_control_block: suite.exit_control_block || "",
      user_pubkey: pos.userPubHex,
      lp_pubkey: pos.lpPubHex,
      exit_csv: suite.exit_csv ?? 0,
      exit_csv_seconds: suite.exit_csv_seconds ?? pos.exitDelaySecs,
      bounty: suite.bounty || null,
      oracle_pubkey: suite.oracle_pubkey || null,
      oracle_event_id: suite.oracle_event_id || null,
      payouts: (suite.payouts || []).map((p) => ({
        outcome: p.outcome,
        tx_hex: p.tx_hex,
        user_adaptor_sig: p.user_adaptor_sig,
        lp_adaptor_sig: p.lp_adaptor_sig,
        precompleted: Boolean(p.precompleted),
      })),
      refund: suite.refund || null,
      dispute: suite.dispute
        ? { ...suite.dispute, manifest: pos.disputeManifest || null }
        : pos.disputeScriptHex && pos.disputeControlBlockHex && pos.oracleQuorum
          ? {
              script_hex: pos.disputeScriptHex,
              control_block_hex: pos.disputeControlBlockHex,
              csv_sequence: Number(pos.disputeCsvSequence || 0),
              oracle_quorum: pos.oracleQuorum,
              leaves: this._disputeLeavesOf(pos).map((l) => ({
                script_hex: l.scriptHex,
                control_block_hex: l.controlBlockHex,
              })),
              manifest: pos.disputeManifest || null,
            }
          : null,
      trigger_height: 0,
    };
  }

  /**
   * Send a complete `WatchtowerPackage` directly to an `ark-watchtower` over NIP-17 Gift Wrap.
   */
  async registerWithWatchtower(positionId, watchtowerPubHex = getWatchtowerPubkey()) {
    const pkg = await this.exportWatchtowerPackage(positionId);
    const targetPub = watchtowerPubHex || pkg.bounty?.primary_pubkey;
    if (!targetPub) {
      throw new Error("Configure a Watchtower 64-hex pubkey in Settings first");
    }
    // NIP-17 double-encrypts (rumor -> base64 seal -> gift wrap), so NIP-44's 65,535-byte
    // ceiling limits the inner rumor payload to ~46 KB. Compact if a deep preconfirmed
    // Arkade VTXO chain pushes the package near that threshold.
    const NIP17_SAFE_LIMIT = 45_000;
    let payloadStr = JSON.stringify({ type: "register_package", package: pkg });
    if (payloadStr.length > NIP17_SAFE_LIMIT && pkg.unroll_txs.length > 1) {
      // Drop any ancestor tx already confirmed onchain (watchtower skips confirmed hops anyway).
      const unconfirmed = [];
      for (const rawHex of pkg.unroll_txs) {
        try {
          const txObj = Transaction.fromRaw(hex.decode(rawHex), { allowUnknownInputs: true, allowUnknownOutputs: true });
          const st = await this.esploraProvider.getTxStatus(txObj.id).catch(() => null);
          if (st?.confirmed) continue;
        } catch {}
        unconfirmed.push(rawHex);
      }
      if (unconfirmed.length > 0) {
        pkg.unroll_txs = unconfirmed;
        payloadStr = JSON.stringify({ type: "register_package", package: pkg });
      }
    }
    if (payloadStr.length > NIP17_SAFE_LIMIT && pkg.payouts.length > 3) {
      // Keep min, mid/spot, and max payout buckets + refund to stay under NIP-17 limit.
      const p = pkg.payouts;
      pkg.payouts = [p[0], p[Math.floor(p.length / 2)], p[p.length - 1]];
      payloadStr = JSON.stringify({ type: "register_package", package: pkg });
    }
    const peer = this.getNip17Peer();
    if (peer.sockets.size === 0) {
      const ok = await peer.connect();
      if (ok === 0) throw new Error("Could not connect to Nostr relays for watchtower NIP-17 send");
    }

    const sendPayloadTo = async (destPub) => {
      if (payloadStr.length <= NIP17_SAFE_LIMIT) {
        return peer.sendWrapped(destPub, payloadStr);
      }
      // Multi-part NIP-17 chunking for deep preconfirmed VTXO unroll chains (>45 KB).
      const pkgJson = JSON.stringify(pkg);
      const CHUNK_SIZE = 36_000;
      const totalChunks = Math.ceil(pkgJson.length / CHUNK_SIZE);
      let lastWrapId = null;
      for (let i = 0; i < totalChunks; i++) {
        const chunkMsg = JSON.stringify({
          type: "register_package_chunk",
          package_id: pkg.id,
          chunk_index: i,
          total_chunks: totalChunks,
          data: pkgJson.slice(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE),
        });
        lastWrapId = await peer.sendWrapped(destPub, chunkMsg);
      }
      return lastWrapId;
    };

    const wrapId = await sendPayloadTo(targetPub);
    // Also mirror the exit package to any curated backup watchtowers from NIP-51 `p2pfiat-watchtowers`.
    const backups = getBackupWatchtowerPubkeys().filter((pk) => pk !== targetPub.toLowerCase());
    if (backups.length > 0) {
      await Promise.allSettled(backups.map((bpk) => sendPayloadTo(bpk)));
    }
    const map = loadPositions();
    if (map[positionId]) {
      map[positionId].watchtowerRegistered = true;
      map[positionId].watchtowerPubkey = targetPub;
      savePositions(map);
    }
    return { wrapId, targetPub, unrollHops: pkg.unroll_txs.length, payouts: pkg.payouts.length };
  }

  /**
   * The contract's committed k-of-n dispute leaves with control blocks, read from the stored
   * taptree (checked against the contract pkScript). Empty when the position predates it.
   */
  _disputeLeavesOf(pos) {
    if (!pos?.contractTapTreeHex || !pos?.contractPkScriptHex || !pos?.oracleQuorum) return [];
    try {
      return disputeLeavesFromTapTree({
        tapTreeHex: pos.contractTapTreeHex,
        pkScriptHex: pos.contractPkScriptHex,
        oracleQuorum: pos.oracleQuorum,
      });
    } catch (err) {
      console.warn(`dispute leaves for ${pos.positionId}: ${err.message}`);
      return [];
    }
  }

  /**
   * Emergency On-Demand Mid-Term Dispute Exit via Leaf 2 (`k-of-n` Nostracle BIP-342 quorum).
   * Used if the LP goes offline mid-term or BTC drops >= 50% (early liquidation).
   *
   * 1. Builds the deterministic BIP-342 dispute payout tx at live spot + pro-rata yield/funding.
   * 2. Requests BIP-340 Schnorr signatures from all `n` Nostracles in parallel over NIP-17 RPC (`sign_dispute`).
   * 3. Verifies the signatures, assembles the witness for the manifest's dispute leaf
   *    (arkd-native `CSVMultisigTapscript`: all k leaf oracles must sign; legacy `OP_CHECKSIGADD`
   *    leaves still supported), and broadcasts
   *    onchain if the DLC VTXO is confirmed (or returns the signed raw tx for broadcast after unroll).
   */
  async forceDisputeExit(positionId, spotPrice = null) {
    const map = loadPositions();
    const pos = map[positionId];
    if (!pos) throw new Error("Unknown position");
    if (!pos.disputeScriptHex || !pos.disputeControlBlockHex || !pos.oracleQuorum?.oracles?.length) {
      throw new Error("This position was opened before Leaf 2 On-Demand Dispute was enabled");
    }

    const manifest = pos.disputeManifest;
    if (!manifest?.user_manifest_sig_hex || !manifest?.lp_manifest_sig_hex) {
      throw new Error("This position lacks a 2-party signed dispute manifest (re-open or roll to enable)");
    }

    // Always derive dispute tx fields from the 2-party signed manifest so BOTH Taker (User)
    // and Maker (LP) in a P2P match construct the exact same canonical dispute transaction.
    const side = String(manifest.side || pos.side || "short").toLowerCase() === "long" ? "long" : "short";
    const total = BigInt(manifest.total_collateral_sats);
    const dust = 350n;
    const notional = Number(manifest.notional_fiat);
    const openedAt = Number(manifest.opened_at);
    const disputeTimestamp = Math.floor(Date.now() / 1000);
    const fundingBps = Number(manifest.funding_rate_bps_per_day);
    const liveSpot = Number(spotPrice || pos.openSpotPrice || pos.openSpotUsd);
    if (!Number.isFinite(liveSpot) || liveSpot <= 0) {
      throw new Error("Live BTC spot price unavailable for dispute calculation");
    }

    const elapsedDays = Math.max(0, disputeTimestamp - openedAt) / 86_400;
    const accruedFiat = notional * (fundingBps / 10_000) * elapsedDays;
    // Leave 350 sats as Bitcoin L1 miner fee so the dispute tx passes mempool min-relay-fee directly.
    const minerFeeSats = total > dust * 2n + 350n ? 350n : 0n;
    const distributable = total - minerFeeSats;
    const clampSats = (targetFiat) => {
      const raw = BigInt(Math.round((Math.max(0.01, targetFiat) / liveSpot) * 1e8));
      const maxOut = distributable - dust;
      return raw < dust ? dust : raw > maxOut ? maxOut : raw;
    };
    const userAmt =
      side === "long"
        ? distributable - clampSats(Math.max(0.01, notional - accruedFiat))
        : clampSats(Math.max(0.01, notional + accruedFiat));
    const lpAmt = distributable - userAmt;

    const uDest = hex.decode(manifest.user_payout_script_hex);
    const lDest = hex.decode(manifest.lp_payout_script_hex);
    const csvSeq =
      Number(pos.disputeCsvSequence) ||
      ((1 << 22) | Math.floor(Number(pos.exitDelaySecs || 512) / 512));

    const [vtxoTxid, vtxoVoutStr] = String(manifest.vtxo_outpoint).split(":");
    const tx = new btc.Transaction({ version: 2, lockTime: 0 });
    tx.addInput({ txid: vtxoTxid, index: Number(vtxoVoutStr || 0), sequence: csvSeq });
    tx.addOutput({ script: uDest, amount: userAmt });
    tx.addOutput({ script: lDest, amount: lpAmt });

    const contractPkScript = hex.decode(manifest.vtxo_pk_script_hex);
    const leafSighash = (leafScript) =>
      tx.preimageWitnessV1(0, [contractPkScript], btc.SigHash.DEFAULT, [total], undefined, leafScript, 0xc0);

    const peer = this.getNip17Peer();
    if (peer.sockets.size === 0) {
      const ok = await peer.connect();
      if (ok === 0) throw new Error("Could not connect to Nostr relays for dispute RPC");
    }

    const isV2 = Number(manifest.manifest_version) === 2;
    const baseParams = {
      contract_id: manifest.contract_id,
      vtxo_outpoint: manifest.vtxo_outpoint,
      currency: manifest.currency,
      side: manifest.side,
      total_collateral_sats: manifest.total_collateral_sats,
      notional_fiat: manifest.notional_fiat,
      opened_at: manifest.opened_at,
      dispute_timestamp: disputeTimestamp,
      funding_rate_bps_per_day: manifest.funding_rate_bps_per_day,
      bounty_sats: 0,
      miner_fee_sats: Number(minerFeeSats),
      fee_paid_sats: 0,
      user_pubkey_hex: manifest.user_pubkey_hex,
      lp_pubkey_hex: manifest.lp_pubkey_hex,
      user_manifest_sig_hex: manifest.user_manifest_sig_hex,
      lp_manifest_sig_hex: manifest.lp_manifest_sig_hex,
      raw_tx_hex: hex.encode(tx.toBytes(true, false)),
      vtxo_pk_script_hex: manifest.vtxo_pk_script_hex,
      user_payout_script_hex: manifest.user_payout_script_hex,
      lp_payout_script_hex: manifest.lp_payout_script_hex,
      ...(isV2
        ? { manifest_version: 2, dispute_leaf_hashes_hex: manifest.dispute_leaf_hashes_hex }
        : {}),
    };

    const oracles = pos.oracleQuorum.oracles;
    const threshold = Number(pos.oracleQuorum.threshold || 2);
    const errors = [];

    // Ask `oraclePubs` to sign the (fixed) dispute tx for `leafScript`; returns verified sigs.
    const requestLeafSigs = async (leafScript, oraclePubs) => {
      const sighash = leafSighash(leafScript);
      const params = { ...baseParams, dispute_script_hex: hex.encode(leafScript), sighash_hex: hex.encode(sighash) };
      const sigs = new Map();
      await Promise.all(
        oraclePubs.map(async (pub) => {
          const o = oracles.find((x) => x.pubkey.toLowerCase() === pub) || { pubkey: pub };
          try {
            const res = await peer.request(o.pubkey, "sign_dispute", params, 20_000);
            if (!res?.signature_hex || res.signature_hex.length !== 128) {
              throw new Error("missing signature_hex");
            }
            const sigBytes = hex.decode(res.signature_hex);
            if (!schnorr.verify(sigBytes, sighash, hex.decode(o.pubkey))) {
              throw new Error("invalid BIP-340 signature");
            }
            sigs.set(pub, sigBytes);
          } catch (err) {
            errors.push(`${o.name || o.pubkey.slice(0, 8)}: ${err.message}`);
          }
        })
      );
      return sigs;
    };

    // Round 1: everyone signs the manifest's primary leaf. Each oracle that signs also locks
    // this exact tx, so in round 2 it will sign the same tx for another committed leaf.
    let leafScript = hex.decode(manifest.dispute_script_hex);
    let controlBlockHex = pos.disputeControlBlockHex;
    let sigsByOracle = await requestLeafSigs(
      leafScript,
      oracles.map((o) => o.pubkey.toLowerCase())
    );
    const round1Signers = [...sigsByOracle.keys()];
    const primaryKeys = parseDisputeLeaf(leafScript).pubkeysHex;
    const primaryComplete = primaryKeys.every((pk) => sigsByOracle.has(pk));

    // Round 2 (v2 only): some primary oracle did not sign, but k others did -> use their leaf.
    let usedFallbackLeaf = false;
    if (!primaryComplete && isV2 && round1Signers.length >= threshold) {
      const committed = new Set((manifest.dispute_leaf_hashes_hex || []).map((h) => h.toLowerCase()));
      const leaves = this._disputeLeavesOf(pos).filter((l) => committed.has(l.leafHashHex));
      const fallback = selectFallbackLeaf(leaves, round1Signers);
      if (fallback) {
        leafScript = fallback.script;
        controlBlockHex = fallback.controlBlockHex;
        sigsByOracle = await requestLeafSigs(leafScript, fallback.pubkeysHex);
        usedFallbackLeaf = true;
      }
    }

    if (sigsByOracle.size < threshold) {
      throw new Error(
        `Only ${sigsByOracle.size}/${threshold} Nostracles signed (${errors.join("; ")})`
      );
    }

    // Witness signatures follow the leaf script's own key order; every key of a CSVMultisig
    // leaf must sign (see dispute-witness.js).
    let witnessSigs;
    try {
      ({ sigs: witnessSigs } = buildDisputeWitnessSigs(leafScript, sigsByOracle));
    } catch (err) {
      throw new Error(`${err.message}${errors.length ? ` (${errors.join("; ")})` : ""}`);
    }
    const witnessStack = [...witnessSigs, leafScript, hex.decode(controlBlockHex)];
    tx.updateInput(0, { finalScriptWitness: witnessStack });
    const rawTxHex = hex.encode(tx.toBytes(true, true));

    let broadcastTxid = null;
    try {
      const st = await this.esploraProvider.getTxStatus(pos.vtxoTxid);
      if (st?.confirmed) {
        const res = await fetch(`${ESPLORA_URL}/tx`, { method: "POST", body: rawTxHex });
        if (res.ok) broadcastTxid = (await res.text()).trim();
      }
    } catch {}

    pos.lastDisputeTxHex = rawTxHex;
    if (broadcastTxid) pos.disputeBroadcastTxid = broadcastTxid;
    map[positionId] = pos;
    savePositions(map);

    return {
      signedCount: sigsByOracle.size,
      threshold,
      totalOracles: oracles.length,
      usedFallbackLeaf,
      disputeLeafHex: hex.encode(leafScript),
      userPayoutSats: Number(userAmt),
      lpPayoutSats: Number(lpAmt),
      spotPrice: liveSpot,
      rawTxHex,
      broadcastTxid,
    };
  }
}
