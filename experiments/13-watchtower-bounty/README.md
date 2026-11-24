# Experiment 13: keyless watchtower with tiered onchain exit bounty

**Question:** can a keyless watchtower (e.g. a nostracle or third party holding no user or LP private keys, only saved exit data and its own BTC fee wallet) unroll an orphaned Ark contract coin, pay real CPFP fees, finalize the DLC payout or refund, and profit from an onchain bounty — without allowing miners or competing watchtowers to snipe it?

**Result: yes.** All 5 subtests passed in 5 of 5 repeat runs on `arkd` regtest. Every watchtower exited purely from saved data after `arkd` was stopped, paid real CPFP and sweep fees from its own onchain P2TR wallet, and ended strictly profitable (`+2,800` sats net per exit).

## Tiered bounty output design

Each pre-signed onchain exit transaction (both DLC payouts and the timelocked refund) includes a third output paying `5,000` sats (split equally between user and LP) to a P2TR bounty script with an unspendable NUMS internal key:

| Leaf | Script | Purpose |
|---|---|---|
| Primary (`W1`) | `<W1> OP_CHECKSIG` | Assigned primary watchtower claims immediately (0-block delay) |
| Backup (`W2`, `W3`) | `<4> OP_CSV OP_DROP <Wi> OP_CHECKSIG` | Any backup watchtower can step in if `W1` is offline, but cannot front-run `W1` in the mempool |

Because the internal key is unspendable and every leaf requires a registered watchtower signature, **miners and unauthorized mempool snipers cannot steal the bounty**. Because backup leaves carry a 4-block CSV delay, **backup watchtowers cannot snipe the primary watchtower** during its exclusive claim window.

## Setup

- `arkd` commit `fee16a7b` on Nigiri regtest (Bitcoin Core v30, TRUC / v3 package relay with 0-sat P2A anchors).
- Contract coin: `25,000` sats (`user + LP + operator` offchain settle; `user + LP` after 20-block CSV exit).
- Exit payout tx: `500` sats miner fee + `5,000` sats bounty output (split `2,750` sats per party).
- Watchtowers (`W1`, `W2`, `W3`) each start with their own independent funded onchain P2TR wallet (`1,000,000` sats) and reuse their change UTXO across every unroll hop (`600` sats CPFP per hop, `400` sats bounty sweep fee).
- Both user and LP private keys are wiped immediately after opening; `arkd` is stopped before any unroll begins.

## Results

| Scenario | Result |
|---|---|
| Stale exit guard (contract already settled offchain) | Watchtower sees coin is spent on indexer and skips unroll |
| Profitability guard (fee spike: 3 × 3,000 + 400 = 9,400 > 5,000 bounty) | Watchtower refuses to unroll at a loss |
| Primary watchtower (`W1`) unrolls and settles DLC payout | Unrolled in 3 hops (`1,800` sats CPFP), swept bounty (`400` sats fee), net profit **`+2,800` sats** |
| Unauthorized miner / sniper tries to steal bounty | Rejected by Bitcoin Core (`mempool-script-verify-flag-failed`) |
| Backup watchtower (`W2`) tries to snipe `W1` before CSV(4) | Rejected by Bitcoin Core (`non-BIP68-final`) |
| `W1` offline: backup watchtower (`W2`) unrolls and claims after CSV(4) | Early claim rejected (`non-BIP68-final`); confirmed after 4 blocks, net profit **`+2,800` sats** |
| Operator and oracle both gone: `W1` executes onchain refund | Rejected before `nLockTime`; confirmed at `nLockTime`, total `W1` net profit across 2 exits **`+5,600` sats** |

## Practical findings

1. **TRUC (v3) confirmation rule:** Bitcoin Core v30 rejects a v3 VTXO unroll transaction if it spends an *unconfirmed* v2 commitment transaction or if the watchtower's CPFP child spends an unconfirmed v2 fee UTXO (`TRUC-violation`). A watchtower wallet must keep confirmed UTXOs (or v3 change outputs) ready for CPFP bumping.
2. **Zero-sat P2A anchors:** `arkd` uses 0-sat ephemeral P2A outputs, so watchtower accounting is exact: `netProfit = bounty - (hops × cpfpFee) - sweepFee`.
3. **Indexer projection lag:** Right after opening a contract, the watchtower must retry `GetVtxoChain` until the indexer projects the new VTXO before considering the exit package safely saved.
4. **Fixed bounty vs. extreme fee spikes:** If onchain fees spike above `bounty / (hops + 1)`, rational watchtowers will not exit at a loss (confirmed by the profitability guard). Setting the bounty high enough for a target fee environment — or allowing the user/LP to top up fees directly — remains a parameter choice.

## What this does not show

- Dynamic mempool fee estimation, RBF fee bumping, or chain reorgs under real mainnet congestion.
- A malicious backup watchtower racing `W1` during the 3-hop unroll *before* the payout tx is broadcast (both would spend CPFP, though only `W1` could claim immediately).
- Stale exit of an already-settled contract *after* the operator has disappeared (covered as an open limit in [ark-architecture.md](../../docs/ark-architecture.md)).

## Run it

Start Nigiri and `arkd`'s `docker-compose.regtest.yml` at commit `fee16a7b`. Copy this test along with `../01-offline-settlement/p2pfiat_offline_settlement_test.go` and `../02-failure-paths/p2pfiat_failure_paths_test.go` into `arkd`'s `internal/test/e2e`, then run:

```sh
go test -v -count 5 -timeout 900s -run TestP2pFiatWatchtowerBounty ./internal/test/e2e
```

The test stops and restarts the `arkd` container on each run.
