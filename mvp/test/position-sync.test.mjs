/**
 * Unit tests for LP `positions` RPC filtering (`filterPositionsQuery`) and
 * browser wallet recovery merge (`mergeRecoveredLpPositions`).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { filterPositionsQuery } from "../src/lp.mjs";
import { mergeRecoveredLpPositions } from "../web/src/position-sync.js";

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
