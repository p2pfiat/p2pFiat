/**
 * Discover active DLC / Nostracle oracles across Nostr relays (`kind: 88` & `kind: 89`).
 * Usage:
 *   node mvp/scripts/discover-nostracles.mjs
 */
import { bech32, hex } from "@scure/base";
import { DEFAULT_RELAYS } from "../src/offerbook.mjs";

const RELAYS = DEFAULT_RELAYS;

function hexToNpub(pubHex) {
  return bech32.encode("npub", bech32.toWords(hex.decode(pubHex)));
}

async function scanRelays(timeoutMs = 5000) {
  const byPub = new Map();
  const seenIds = new Set();

  await Promise.all(
    RELAYS.map(
      (url) =>
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
            ws = new WebSocket(url);
            const subId = `disc-${Math.random().toString(16).slice(2, 8)}`;
            ws.onopen = () => {
              ws.send(JSON.stringify(["REQ", subId, { kinds: [88, 89], limit: 200 }]));
            };
            ws.onmessage = (msg) => {
              try {
                const frame = JSON.parse(String(msg.data));
                if (frame[0] === "EVENT" && frame[2]) {
                  const ev = frame[2];
                  if (seenIds.has(ev.id)) return;
                  seenIds.add(ev.id);
                  const pk = ev.pubkey;
                  if (!/^[0-9a-f]{64}$/.test(pk)) return;
                  let rec = byPub.get(pk);
                  if (!rec) {
                    rec = {
                      pubkey: pk,
                      npub: hexToNpub(pk),
                      announcements: 0,
                      attestations: 0,
                      feeSats: null,
                      firstSeen: ev.created_at,
                      lastSeen: ev.created_at,
                    };
                    byPub.set(pk, rec);
                  }
                  if (ev.kind === 88) {
                    rec.announcements++;
                    const feeTag = (ev.tags || []).find((t) => Array.isArray(t) && t[0] === "fee_sats");
                    if (feeTag && Number.isFinite(Number(feeTag[1]))) {
                      rec.feeSats = Number(feeTag[1]);
                    }
                  } else if (ev.kind === 89) {
                    rec.attestations++;
                  }
                  if (ev.created_at < rec.firstSeen) rec.firstSeen = ev.created_at;
                  if (ev.created_at > rec.lastSeen) rec.lastSeen = ev.created_at;
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

  return [...byPub.values()].sort(
    (a, b) => b.announcements + b.attestations - (a.announcements + a.attestations)
  );
}

const found = await scanRelays();
console.log(`\nDiscovered ${found.length} unique DLC/Nostracle oracle pubkey(s) on ${RELAYS.length} relays:\n`);
for (const o of found) {
  const feeTxt = o.feeSats !== null ? `${o.feeSats} sats` : "n/a";
  console.log(`- ${o.npub}`);
  console.log(`  hex:   ${o.pubkey}`);
  console.log(`  stats: ${o.announcements} kind:88 ann, ${o.attestations} kind:89 att, fee=${feeTxt}`);
  console.log(`  feed:  https://yakihonne.com/profile/${o.npub}\n`);
}
