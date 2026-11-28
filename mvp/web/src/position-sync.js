// Pure helpers for recovering finalized LP positions whose `open/finalize` reply
// was missed (e.g. NIP-17 relay timeout) without overwriting local position state.

const HEX_64 = /^[0-9a-f]{64}$/i;

/**
 * Merge open positions returned by an LP's `positions` RPC into the wallet's local map.
 * - Strictly enforces `p.userPubHex === userPubHex` (per-account isolation).
 * - Only adds missing `open` positions with a valid 64-hex `vtxoTxid` and positive collateral.
 * - Never overwrites an already-stored local position (preserving local `exitSuite`, `autoRoll`, etc.).
 */
export function mergeRecoveredLpPositions(localMap, remotePositions, { userPubHex, target = {} } = {}) {
  const myPub = String(userPubHex || "").trim().toLowerCase();
  const merged = { ...(localMap || {}) };
  const recoveredIds = [];
  if (!myPub || !Array.isArray(remotePositions)) {
    return { merged, recoveredCount: 0, recoveredIds };
  }

  const lpUrl = target.url || "";
  const lpPubkey = target.pubkey || null;
  const lpName = target.lpName || "LP";
  const lpTransport = !lpUrl || target.preferNip17 ? "nostr-nip17" : "http";

  for (const p of remotePositions) {
    if (!p || typeof p !== "object") continue;
    if (!p.positionId || typeof p.positionId !== "string") continue;
    if (String(p.status || "").toLowerCase() !== "open") continue;
    if (String(p.userPubHex || "").trim().toLowerCase() !== myPub) continue;
    if (!HEX_64.test(String(p.vtxoTxid || ""))) continue;
    if (!Number.isFinite(Number(p.totalCollateralSats)) || Number(p.totalCollateralSats) <= 0) continue;
    if (merged[p.positionId]) continue;

    merged[p.positionId] = {
      ...p,
      lpUrl,
      lpPubkey: lpPubkey || p.lpPubHex || null,
      lpName: p.lpName || lpName,
      lpTransport,
    };
    recoveredIds.push(p.positionId);
  }

  return { merged, recoveredCount: recoveredIds.length, recoveredIds };
}
