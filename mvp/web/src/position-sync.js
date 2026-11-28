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

/**
 * Build a local `status: "pending"` position checkpoint BEFORE sending `open/finalize`
 * so the user's browser already holds `vtxoTxid` (`arkTx.id`), contract scripts, and
 * the 2-party signed `disputeManifest` even if the LP reply times out or the tab closes.
 */
export function buildPendingPosition({
  prop,
  quote,
  arkTxId,
  userPubHex,
  target = {},
  lpName = "",
  preSignedManifest = null,
  nowSecs = Math.floor(Date.now() / 1000),
}) {
  const lpUrl = target.url || "";
  const lpPubkey = target.pubkey || quote?.lpPubkey || prop?.lpPubHex || null;
  const lpTransport = !lpUrl || target.preferNip17 ? "nostr-nip17" : "http";
  return {
    positionId: prop.positionId,
    status: "pending",
    pendingSince: nowSecs,
    side: quote.side || "short",
    leverage: quote.leverage || (quote.side === "long" ? 2 : 1),
    liquidationPrice: quote.liquidationPrice || 0,
    currency: quote.currency || "USD",
    pair: quote.pair || `BTC-${quote.currency || "USD"}`,
    openedAt: prop.openedAt || nowSecs,
    vtxoTxid: arkTxId,
    vtxoVout: 0,
    notional: quote.notional ?? quote.notionalUsd,
    notionalUsd: quote.notional ?? quote.notionalUsd,
    openSpotPrice: quote.spotPrice ?? quote.spotUsd,
    openSpotUsd: quote.spotPrice ?? quote.spotUsd,
    spreadBps: quote.spreadBps,
    termSecs: Number(quote.termSecs || 86_400),
    fundingRateBpsPerDay: quote.fundingRateBpsPerDay,
    oracleQuorum: quote.oracleQuorum || null,
    userCollateralSats: quote.userCollateralSats,
    lpCollateralSats: quote.lpCollateralSats,
    totalCollateralSats: quote.totalCollateralSats,
    userPubHex,
    lpPubHex: prop.lpPubHex || lpPubkey,
    contractPkScriptHex: prop.contractPkScriptHex,
    contractTapTreeHex: prop.contractTapTreeHex || null,
    settleScriptHex: prop.settleScriptHex || null,
    exitScriptHex: prop.exitScriptHex || null,
    disputeScriptHex: prop.disputeScriptHex || null,
    disputeControlBlockHex: prop.disputeControlBlockHex || null,
    disputeCsvSequence: prop.disputeCsvSequence || null,
    disputeManifest: preSignedManifest || prop.disputeManifest || null,
    exitDelaySecs: prop.exitDelaySecs ? Number(prop.exitDelaySecs) : undefined,
    lpUrl,
    lpPubkey,
    lpName: lpName || target.lpName || quote.lpName || "LP",
    lpTransport,
  };
}

/**
 * Reconcile a `status: "pending"` position against the Arkade indexer (100% LP-independent):
 * - If `vtxoExistsOnArkade` is true, promote to `status: "open"` (clearing `pendingSince`).
 * - If not found on Arkade and older than `maxPendingAgeSecs`, drop the stale pending entry.
 * - Otherwise keep it pending for a later check.
 */
export function reconcilePendingPosition(
  pendingPos,
  { vtxoExistsOnArkade, nowSecs = Math.floor(Date.now() / 1000), maxPendingAgeSecs = 600 } = {}
) {
  if (!pendingPos || pendingPos.status !== "pending") {
    return { action: "noop", position: pendingPos };
  }
  if (vtxoExistsOnArkade) {
    const promoted = { ...pendingPos, status: "open" };
    delete promoted.pendingSince;
    return { action: "promote", position: promoted };
  }
  const ageSecs = nowSecs - Number(pendingPos.pendingSince || pendingPos.openedAt || nowSecs);
  if (ageSecs > maxPendingAgeSecs) {
    return { action: "drop", position: null };
  }
  return { action: "keep-pending", position: pendingPos };
}
