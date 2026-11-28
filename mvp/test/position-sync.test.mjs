/**
 * Unit tests for LP `positions` RPC filtering (`filterPositionsQuery`) and
 * browser wallet recovery merge (`mergeRecoveredLpPositions`).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { filterPositionsQuery } from "../src/lp.mjs";
import {
  mergeRecoveredLpPositions,
  buildPendingPosition,
  reconcilePendingPosition,
} from "../web/src/position-sync.js";

const USER_A = "aa".repeat(32);
const USER_B = "bb".repeat(32);
const LP_PUB = "cc".repeat(32);
const TX_1 = "11".repeat(32);
const TX_2 = "22".repeat(32);
const TX_3 = "33".repeat(32);

test("filterPositionsQuery filters by userPubHex, positionId, vtxoTxid, status, and limit", () => {
  const all = [
    { positionId: "pos-1", userPubHex: USER_A, status: "open", vtxoTxid: TX_1, openedAt: 100 },
    { positionId: "pos-2", userPubHex: USER_A, status: "closed", vtxoTxid: TX_2, openedAt: 200 },
    { positionId: "pos-3", userPubHex: USER_B, status: "open", vtxoTxid: TX_3, openedAt: 300 },
  ];

  assert.deepEqual(
    filterPositionsQuery(all, { userPubHex: USER_A.toUpperCase(), status: "open" }).map((p) => p.positionId),
    ["pos-1"]
  );
  assert.deepEqual(
    filterPositionsQuery(all, { userPubHex: USER_A }).map((p) => p.positionId),
    ["pos-2", "pos-1"]
  );
  assert.deepEqual(
    filterPositionsQuery(all, { positionId: "pos-3" }).map((p) => p.positionId),
    ["pos-3"]
  );
  assert.deepEqual(
    filterPositionsQuery(all, { vtxoTxid: TX_1.toUpperCase() }).map((p) => p.positionId),
    ["pos-1"]
  );
  assert.deepEqual(
    filterPositionsQuery(all, { limit: 1 }).map((p) => p.positionId),
    ["pos-3"]
  );
});

test("mergeRecoveredLpPositions enforces account isolation, preserves local state, and recovers missing open positions", () => {
  const local = {
    "pos-existing": {
      positionId: "pos-existing",
      status: "open",
      userPubHex: USER_A,
      vtxoTxid: TX_1,
      totalCollateralSats: 20_000,
      autoRoll: true,
      exitSuite: { localOnly: true },
    },
  };
  const remote = [
    // Already exists locally -> must NOT overwrite local autoRoll/exitSuite
    {
      positionId: "pos-existing",
      status: "open",
      userPubHex: USER_A,
      vtxoTxid: TX_1,
      totalCollateralSats: 20_000,
    },
    // Missing open position for USER_A -> MUST be recovered
    {
      positionId: "pos-missing",
      status: "open",
      userPubHex: USER_A,
      vtxoTxid: TX_2,
      totalCollateralSats: 13_460,
      notionalUsd: 4,
    },
    // Different user -> MUST be rejected (strict account isolation)
    {
      positionId: "pos-other-user",
      status: "open",
      userPubHex: USER_B,
      vtxoTxid: TX_3,
      totalCollateralSats: 50_000,
    },
    // Closed position -> ignored
    {
      positionId: "pos-closed",
      status: "closed",
      userPubHex: USER_A,
      vtxoTxid: TX_3,
      totalCollateralSats: 10_000,
    },
    // Malformed txid -> rejected
    {
      positionId: "pos-bad-tx",
      status: "open",
      userPubHex: USER_A,
      vtxoTxid: "not-hex",
      totalCollateralSats: 10_000,
    },
  ];

  const { merged, recoveredCount, recoveredIds } = mergeRecoveredLpPositions(local, remote, {
    userPubHex: USER_A,
    target: { url: "", pubkey: LP_PUB, lpName: "LP-Home", preferNip17: true },
  });

  assert.equal(recoveredCount, 1);
  assert.deepEqual(recoveredIds, ["pos-missing"]);
  assert.equal(merged["pos-existing"].autoRoll, true, "existing local autoRoll must be preserved");
  assert.deepEqual(merged["pos-existing"].exitSuite, { localOnly: true });
  assert.equal(merged["pos-missing"].lpPubkey, LP_PUB);
  assert.equal(merged["pos-missing"].lpName, "LP-Home");
  assert.equal(merged["pos-missing"].lpTransport, "nostr-nip17");
  assert.equal(merged["pos-other-user"], undefined, "other user's position must never be merged");
  assert.equal(merged["pos-closed"], undefined);
  assert.equal(merged["pos-bad-tx"], undefined);
});

test("buildPendingPosition & reconcilePendingPosition promote confirmed Arkade VTXOs without LP and drop stale ones", () => {
  const now = 1_800_000_000;
  const pending = buildPendingPosition({
    prop: {
      positionId: "pos-pending-1",
      openedAt: now,
      lpPubHex: LP_PUB,
      contractPkScriptHex: "5120" + "dd".repeat(32),
      settleScriptHex: "aa",
      exitScriptHex: "bb",
    },
    quote: {
      side: "short",
      currency: "USD",
      pair: "BTC-USD",
      notional: 4,
      spotPrice: 60_000,
      spreadBps: 1,
      termSecs: 3600,
      fundingRateBpsPerDay: 0.27,
      userCollateralSats: 6730,
      lpCollateralSats: 6730,
      totalCollateralSats: 13460,
    },
    arkTxId: TX_2,
    userPubHex: USER_A,
    target: { url: "", pubkey: LP_PUB, lpName: "LP-Home", preferNip17: true },
    nowSecs: now,
  });

  assert.equal(pending.status, "pending");
  assert.equal(pending.vtxoTxid, TX_2);
  assert.equal(pending.termSecs, 3600);

  // 1. Not yet on Arkade and within window -> keep-pending
  const wait = reconcilePendingPosition(pending, { vtxoExistsOnArkade: false, nowSecs: now + 60 });
  assert.equal(wait.action, "keep-pending");
  assert.equal(wait.position.status, "pending");

  // 2. Confirmed on Arkade indexer -> promote to open (LP-independent!)
  const promoted = reconcilePendingPosition(pending, { vtxoExistsOnArkade: true, nowSecs: now + 15 });
  assert.equal(promoted.action, "promote");
  assert.equal(promoted.position.status, "open");
  assert.equal("pendingSince" in promoted.position, false);
  assert.equal(promoted.position.vtxoTxid, TX_2);

  // 3. Not on Arkade after >10 min -> drop stale pending record
  const dropped = reconcilePendingPosition(pending, { vtxoExistsOnArkade: false, nowSecs: now + 601 });
  assert.equal(dropped.action, "drop");
  assert.equal(dropped.position, null);
});
