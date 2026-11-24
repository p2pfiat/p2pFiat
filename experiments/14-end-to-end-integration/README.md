# Experiment 14: end-to-end integration on regtest

**Question:** do all components tested separately in experiments 1–13 — the 4-of-7 threshold oracle over real `strfry` Nostr relays, a real 20-bit numeric DLC, a 22-path Tapscript rolling DLC on a live `arkd` server, and a keyless watchtower with a tiered onchain exit bounty — work together end-to-end?

**Result: yes.** Both full lifecycles (offchain settlement and operator-gone onchain watchtower exit) passed in 5 of 5 repeat runs on regtest.

## What ran together

| Layer | Configuration |
|---|---|
| Nostr relays | 3 real `strfry` Docker containers (pinned by image digest) |
| Threshold oracle | 7 members running 4-of-7 Feldman VSS DKG over `strfry` with NIP-44 encrypted shares, 1 per-event key + 20 digit nonces per slot, attesting with 2 of 7 members offline |
| Numeric DLC | `$1,000` notional, `2,000,000` sats collateral, `$100,000` open price, `±25%` band (`$75,000`–`$125,000`), `10,000` sat payout steps → **527 binary prefixes** |
| Ark contract | Live `arkd` regtest (`fee16a7b`), 22 Tapscript paths (user settle/exit + 10 quorum roll/settle + 10 quorum exit), user private key wiped after opening |
| Batch roll | Two different 3-of-5 nostracle quorums (`{0,1,2}` and `{1,2,4}`) + LP rolled both `2,000,000` sat positions on `arkd`, adaptor-signing all 527 prefixes (offchain + onchain exit with bounty) before forfeiting the old coin |
| Watchtower bounty | Tiered P2TR output (`5,000` sats): primary `W1` immediate `OP_CHECKSIG`, backups `W2`/`W3` after 4-block CSV |

## Results

Both `2,000,000` sat numeric DLCs rolled in ~10 seconds total (including signing all 527 binary prefixes for offchain settlement, checkpoint, and onchain exit).

| Journey | Scenario | Result |
|---|---|---|
| **Journey A (offchain)** | Offline user; quorum `{0,1,2}` rolls on `arkd`; 5 of 7 nostracles attest `$91,420` over 3 `strfry` relays (members 6 & 7 offline); outside client verifies all 20 BIP-340 digit signatures and submits matching prefix (`[91392..91647]`) to `arkd` | Wrong prefix rejected by `arkd`; matching prefix settled offchain on `arkd` with exact dollar-pegged payout (`user = 1,090,000` sats, `LP = 910,000` sats) |
| **Journey B (onchain watchtower)** | Offline user; quorum `{1,2,4}` rolls on `arkd`; all user, LP and quorum keys wiped; `arkd` stopped; 5 of 7 nostracles attest `$114,800` over 3 `strfry` relays (members 1 & 3 offline); keyless watchtower `W1` unrolls rolled coin, waits 25-block CSV, settles matching prefix (`[114688..115199]`) on Bitcoin Core regtest, and sweeps bounty | Unrolled in 1 hop (`600` sats CPFP), exact onchain payout (`user = 867,250` sats, `LP = 1,127,250` sats after split fee+bounty), unauthorized miner bounty theft rejected, `W1` net profit **`+4,000` sats** |

## Practical findings

1. **Per-event share isolation:** Each oracle event slot must store its own `(keyShare, nonceShare[20])` map per session so overlapping or pre-generated event slots never clobber one another.
2. **Rolled coins unroll in fewer hops:** A fresh batch-rolled VTXO sits directly under the new batch commitment tree and unrolled in just **1 hop** (`600` sats CPFP) instead of 3 hops for an offchain-sent VTXO, increasing watchtower net profit from `+2,800` to `+4,000` sats.
3. **527 numeric prefixes sign comfortably inside an Ark batch:** Adaptor-signing all 527 prefixes across 4 signers (offchain tx, checkpoint tx, and onchain exit tx with bounty) completed cleanly inside `arkd`'s `onBatchFinalization` window.

## What this does not show

- Public Nostr relays, public Arkade testnet/mainnet operators, or independently operated nostracles.
- The full two-phase anti-bias DKG, locked slots and disk journal of experiments 10–12 (this test uses standard Feldman VSS DKG to focus on the end-to-end integration with `arkd`, numeric DLCs and watchtower exits).
- Perpetual funding payments, liquidation, dynamic mempool fee spikes, or chain reorgs.

## Run it

Start Nigiri and `arkd`'s `docker-compose.regtest.yml` at commit `fee16a7b`. Copy this test along with the tests from `../01-offline-settlement`, `../02-failure-paths`, `../04-guardian-rolling-dlc` and `../13-watchtower-bounty` into `arkd`'s `internal/test/e2e`, then run:

```sh
go test -v -count 5 -timeout 900s -run TestP2pFiatEndToEnd ./internal/test/e2e
```

The test starts 3 ephemeral `strfry` containers and stops/restarts `arkd` on each run.
