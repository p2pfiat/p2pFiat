/**
 * Real `nostracle` (kormir 1.1.2 / draft DLC oracle NIP kind 88) announcement parser,
 * BIP-340 verification, live Nostr relay fetcher, and kormir digit-decomposition
 * adaptor point math (`DLC/oracle/attestation/v0`).
 */

import { schnorr } from "@noble/curves/secp256k1.js";
import { hex, base64 } from "@scure/base";
import { N, taggedHash, bytesToBigInt } from "./crypto.mjs";
import { DEFAULT_RELAYS } from "./offerbook.mjs";

export const KIND_ORACLE_ANNOUNCEMENT = 88;
export const KIND_ORACLE_ATTESTATION = 89;

const enc = new TextEncoder();
const dec = new TextDecoder();

function readU16BE(buf, off) {
  return ((buf[off] << 8) | buf[off + 1]) >>> 0;
}

function readU32BE(buf, off) {
  return (
    ((buf[off] << 24) | (buf[off + 1] << 16) | (buf[off + 2] << 8) | buf[off + 3]) >>> 0
  );
}

function readBigSize(buf, off) {
  const first = buf[off];
  if (first < 0xfd) return { value: first, next: off + 1 };
  if (first === 0xfd) return { value: readU16BE(buf, off + 1), next: off + 3 };
  if (first === 0xfe) return { value: readU32BE(buf, off + 1), next: off + 5 };
  throw new Error("BigSize u64 not supported in announcement descriptor");
}

/**
 * Parse and cryptographically verify a kormir `OracleAnnouncement` from a Nostr `kind: 88`
 * event's base64 content.
 */
export function parseKormirAnnouncement(base64Content) {
  const bytes = base64.decode(String(base64Content || "").trim());
  if (bytes.length < 104) throw new Error("kormir announcement too short");

  const sig = bytes.subarray(0, 64);
  const oraclePubXOnly = bytes.subarray(64, 96);
  const oracleEventBytes = bytes.subarray(96);

  // Verify BIP-340 announcement signature over taggedHash("DLC/oracle/announcement/v0", oracleEventBytes)
  const annHash = taggedHash("DLC/oracle/announcement/v0", oracleEventBytes);
  const validSig = schnorr.verify(sig, annHash, oraclePubXOnly);
  if (!validSig) throw new Error("Invalid kormir announcement BIP-340 signature");

  let off = 96;
  const numNonces = readU16BE(bytes, off);
  off += 2;
  if (numNonces === 0 || off + numNonces * 32 + 4 > bytes.length) {
    throw new Error(`Invalid nonce count ${numNonces}`);
  }
  const noncesHex = [];
  for (let i = 0; i < numNonces; i++) {
    noncesHex.push(hex.encode(bytes.subarray(off, off + 32)));
    off += 32;
  }

  const maturityEpoch = readU32BE(bytes, off);
  off += 4;

  // EventDescriptor (Lightning TLV: BigSize type, BigSize len, payload)
  const descType = readBigSize(bytes, off);
  off = descType.next;
  const descLen = readBigSize(bytes, off);
  off = descLen.next;
  const descEnd = off + descLen.value;

  let unit = "USD";
  let numDigits = numNonces;
  let base = 2;
  let isSigned = false;
  if (descType.value === 55306 && descEnd <= bytes.length) {
    // DigitDecompositionEventDescriptor: u16 base, u8 is_signed, u16 unit_len + unit, i32 precision, u16 nb_digits
    let dOff = off;
    base = readU16BE(bytes, dOff);
    dOff += 2;
    isSigned = bytes[dOff] !== 0;
    dOff += 1;
    const unitLen = readU16BE(bytes, dOff);
    dOff += 2;
    unit = dec.decode(bytes.subarray(dOff, dOff + unitLen));
    dOff += unitLen;
    dOff += 4; // i32 precision
    numDigits = readU16BE(bytes, dOff);
  }
  off = descEnd;

  const eventIdLen = readU16BE(bytes, off);
  off += 2;
  const eventId = dec.decode(bytes.subarray(off, off + eventIdLen));

  return {
    announcementSigHex: hex.encode(sig),
    oraclePubkeyHex: hex.encode(oraclePubXOnly),
    noncesHex,
    maturityEpoch,
    base,
    isSigned,
    unit,
    numDigits,
    eventId,
  };
}

/**
 * Parse a kormir `OracleAttestation` from a Nostr `kind: 89` event's base64 content.
 * Returns `{ eventId, oraclePubkeyHex, signaturesHex, outcomes }`.
 */
export function parseKormirAttestation(base64Content) {
  const bytes = base64.decode(String(base64Content || "").trim());
  if (bytes.length < 38) throw new Error("kormir attestation too short");

  let off = 0;
  const eventIdLen = readU16BE(bytes, off);
  off += 2;
  const eventId = dec.decode(bytes.subarray(off, off + eventIdLen));
  off += eventIdLen;

  const oraclePubkeyHex = hex.encode(bytes.subarray(off, off + 32));
  off += 32;

  const numSigs = readU16BE(bytes, off);
  off += 2;
  const signaturesHex = [];
  for (let i = 0; i < numSigs; i++) {
    signaturesHex.push(hex.encode(bytes.subarray(off, off + 64)));
    off += 64;
  }

  const numOutcomes = readU16BE(bytes, off);
  off += 2;
  const outcomes = [];
  for (let i = 0; i < numOutcomes; i++) {
    const len = readU16BE(bytes, off);
    off += 2;
    outcomes.push(dec.decode(bytes.subarray(off, off + len)));
    off += len;
  }

  return { eventId, oraclePubkeyHex, signaturesHex, outcomes };
}

/**
 * Compute the exact kormir / DLC-spec adaptor point `T` for a binary outcome prefix
 * (e.g. `"0000111001"`) using the real `kind: 88` announcement nonces `R_0..R_{k-1}`:
 *
 *   T = sum_{i=0..prefix.length-1} ( R_i + H("BIP0340/challenge", R_i || P_O || H("DLC/oracle/attestation/v0", bit_i)) * P_O )
 *
 * Byte-for-byte compatible with `nostracle` (`kormir 1.1.2`) and `ark-watchtower` (`sum_attestation_scalars`).
 */
export function computeKormirOutcomePoint(oraclePubXOnly, noncesHex, binaryPrefix) {
  if (!binaryPrefix || binaryPrefix.length === 0) {
    throw new Error("binaryPrefix must be non-empty");
  }
  if (noncesHex.length < binaryPrefix.length) {
    throw new Error(`Not enough nonces (${noncesHex.length}) for prefix length ${binaryPrefix.length}`);
  }
  const P = schnorr.Point.fromBytes(Uint8Array.from([0x02, ...oraclePubXOnly]));
  let acc = null;
  for (let i = 0; i < binaryPrefix.length; i++) {
    const bitStr = binaryPrefix[i];
    const rBytes = hex.decode(noncesHex[i]);
    const Ri = schnorr.Point.fromBytes(Uint8Array.from([0x02, ...rBytes]));
    const msg = taggedHash("DLC/oracle/attestation/v0", enc.encode(bitStr));
    const e = bytesToBigInt(taggedHash("BIP0340/challenge", rBytes, oraclePubXOnly, msg)) % N;
    const Si = Ri.add(P.multiply(e));
    acc = acc ? acc.add(Si) : Si;
  }
  return acc;
}

/**
 * Convert an integer fiat price to a binary prefix of length `prefixLen` (out of `numDigits` bits).
 * E.g. for `numDigits = 20, prefixLen = 10`, each bucket spans `2^10 = 1024` fiat units.
 */
export function priceToBinaryPrefix(priceInt, numDigits = 20, prefixLen = 10) {
  const clamped = Math.max(0, Math.min((1 << numDigits) - 1, Math.round(priceInt)));
  return clamped.toString(2).padStart(numDigits, "0").slice(0, prefixLen);
}

/**
 * Fetch the nearest upcoming verified `kind: 88` announcement for `(oraclePubkeyHex, unit)` from Nostr relays.
 */
export async function fetchLatestNostracleAnnouncement({
  oraclePubkeyHex,
  unit = "USD",
  relays = DEFAULT_RELAYS,
  timeoutMs = 3000,
}) {
  if (!oraclePubkeyHex || !relays?.length) return null;
  const nowSecs = Math.floor(Date.now() / 1000);
  const found = [];

  await Promise.all(
    relays.map(
      (relayUrl) =>
        new Promise((resolve) => {
          let ws;
          let doneFlag = false;
          const finish = () => {
            if (doneFlag) return;
            doneFlag = true;
            clearTimeout(timer);
            try {
              ws?.close();
            } catch {}
            resolve();
          };
          const timer = setTimeout(finish, timeoutMs);
          try {
            ws = new WebSocket(relayUrl);
            ws.onopen = () => {
              ws.send(
                JSON.stringify([
                  "REQ",
                  "k88",
                  { kinds: [KIND_ORACLE_ANNOUNCEMENT], authors: [oraclePubkeyHex], limit: 30 },
                ])
              );
            };
            ws.onmessage = (msg) => {
              try {
                const frame = JSON.parse(String(msg.data));
                if (frame[0] === "EVENT" && frame[2]?.kind === KIND_ORACLE_ANNOUNCEMENT) {
                  const parsed = parseKormirAnnouncement(frame[2].content);
                  if (
                    parsed.oraclePubkeyHex === oraclePubkeyHex &&
                    parsed.unit.toUpperCase() === unit.toUpperCase() &&
                    parsed.maturityEpoch > nowSecs
                  ) {
                    found.push({ ...parsed, nostrEventId: frame[2].id });
                  }
                } else if (frame[0] === "EOSE") {
                  finish();
                }
              } catch {}
            };
            ws.onerror = finish;
          } catch {
            finish();
          }
        })
    )
  );

  if (found.length === 0) return null;
  // Pick the nearest future maturity (or closest to 24h)
  found.sort((a, b) => a.maturityEpoch - b.maturityEpoch);
  return found[0];
}
