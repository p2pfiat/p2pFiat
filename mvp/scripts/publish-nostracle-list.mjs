/**
 * Publish or update the official NIP-51 `kind: 30000` (`d: "p2pfiat-nostracles"`)
 * curated Nostracle directory to Nostr relays.
 *
 * Usage (PowerShell):
 *   $env:P2PFIAT_NSEC="nsec1..."
 *   node mvp/scripts/publish-nostracle-list.mjs npub1... npub1...
 *
 * Your secret key is read only from the environment variable and never written to disk.
 */
import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bech32, hex } from "@scure/base";

const RELAYS = [
  "wss://relay.damus.io",
  "wss://nos.lol",
  "wss://relay.primal.net",
  "wss://nostr.oxtr.dev",
  "wss://nostr.bitcoiner.social",
];
const LIST_D_TAG = "p2pfiat-nostracles";
const enc = new TextEncoder();

function decodeSecretKey(raw) {
  const s = String(raw || "").trim();
  if (s.toLowerCase().startsWith("nsec1")) {
    const dec = bech32.decode(s.toLowerCase());
    if (dec.prefix !== "nsec") throw new Error("Expected nsec1...");
    return new Uint8Array(bech32.fromWords(dec.words));
  }
  if (/^[0-9a-fA-F]{64}$/.test(s)) return hex.decode(s.toLowerCase());
  throw new Error("Set P2PFIAT_NSEC to a valid nsec1... or 64-char hex secret key");
}

function decodePubkeyHex(raw) {
  const s = String(raw || "").trim();
  if (s.toLowerCase().startsWith("npub1")) {
    const dec = bech32.decode(s.toLowerCase());
    if (dec.prefix !== "npub") throw new Error(`Invalid npub: ${s}`);
    return hex.encode(new Uint8Array(bech32.fromWords(dec.words)));
  }
  if (/^[0-9a-fA-F]{64}$/.test(s)) return s.toLowerCase();
  throw new Error(`Invalid oracle pubkey/npub: ${s}`);
}

const args = process.argv.slice(2);
if (args.length === 0) {
  console.error("Usage: P2PFIAT_NSEC=nsec1... node mvp/scripts/publish-nostracle-list.mjs <npub1|hex> [...]");
  process.exit(1);
}

const skBytes = decodeSecretKey(process.env.P2PFIAT_NSEC);
const pubHex = hex.encode(schnorr.getPublicKey(skBytes));
const oraclePubs = [...new Set(args.map(decodePubkeyHex))];

const tags = [
  ["d", LIST_D_TAG],
  ["title", "p2pFiat Curated Nostracle Directory"],
  ["description", "Verified DLC price oracles (NIP-88) for p2pFiat quorums"],
  ...oraclePubs.map((pk, i) => ["p", pk, "", `Nostracle-${i + 1}`]),
];

const unsigned = {
  pubkey: pubHex,
  created_at: Math.floor(Date.now() / 1000),
  kind: 30000,
  tags,
  content: "",
};
const serialized = JSON.stringify([0, unsigned.pubkey, unsigned.created_at, unsigned.kind, unsigned.tags, unsigned.content]);
const id = hex.encode(sha256(enc.encode(serialized)));
const sig = hex.encode(schnorr.sign(hex.decode(id), skBytes));
const event = { ...unsigned, id, sig };

console.log(`Publishing NIP-51 kind:30000 (${LIST_D_TAG}) with ${oraclePubs.length} oracle(s) as ${pubHex.slice(0, 12)}…`);

const results = await Promise.all(
  RELAYS.map(
    (url) =>
      new Promise((resolve) => {
        let ws;
        let done = false;
        const finish = (ok, reason = "") => {
          if (done) return;
          done = true;
          try { ws?.close(); } catch {}
          resolve({ url, ok, reason });
        };
        const timer = setTimeout(() => finish(false, "timeout"), 5000);
        try {
          ws = new WebSocket(url);
          ws.onopen = () => ws.send(JSON.stringify(["EVENT", event]));
          ws.onmessage = (msg) => {
            try {
              const frame = JSON.parse(String(msg.data));
              if (frame[0] === "OK" && frame[1] === id) {
                clearTimeout(timer);
                finish(Boolean(frame[2]), frame[3] || "");
              }
            } catch {}
          };
          ws.onerror = () => { clearTimeout(timer); finish(false, "error"); };
          ws.onclose = () => { clearTimeout(timer); finish(false, "closed"); };
        } catch (e) {
          clearTimeout(timer);
          finish(false, e.message);
        }
      })
  )
);

for (const r of results) {
  console.log(`  ${r.ok ? "OK  " : "FAIL"} ${r.url}${r.reason ? ` (${r.reason})` : ""}`);
}
