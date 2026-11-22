# Experiment 4: rolling DLC with a nostracle quorum

**Question:** can 3 of 5 nostracles roll a DLC for an offline user on arkd, so that no single party, including the operator, can take the funds?

**Result: yes on regtest, with one trust assumption left: 3 nostracles colluding with the LP can take the collateral after the timelock.** All 11 scenarios passed in 5 of 5 runs, covering 20 batch rolls. One of those scenarios is that successful theft, which shows the remaining trust.

## Setup

- arkd commit `fee16a7b`, built from source, on Nigiri regtest, ARM64 Ubuntu 24.04 in WSL. No emulator is used.
- The five nostracles are simulated in the test process. Nostr messaging and payments are not used.
- One throwaway oracle key signs two outcomes. The 20,000 sat position pays 14,000/6,000 or 8,000/12,000 sats.

## Contract

Each coin has 22 script paths:

| Path | Signers | Lock |
|---|---|---|
| User settle | user + LP + operator | None |
| User exit | user + LP | 20-block delay |
| Quorum roll or settle (10 paths) | 3 of 5 nostracles + LP + operator | Absolute timelock at the end of the term |
| Quorum exit (10 paths) | 3 of 5 nostracles + LP | 25-block delay |

**arkd refuses a script path that combines an absolute and a relative timelock.** The quorum exit therefore uses a relative delay longer than the maximum term of 12 blocks. A coin cannot be onchain before it exists, so the quorum cannot claim it before the term ends.

## How a roll works

1. Nostracles check the mandate, the timelock and whether the user answered the liveness challenge.
2. A quorum joins an Ark batch for a new coin with the same keys and a new term.
3. When the batch reveals the new coin, the quorum and LP sign its offchain and exit payouts.
4. **Only then** do they sign the forfeit of the old coin.

## Results

| Scenario | Result |
|---|---|
| Quorum rolls for an offline user, using two different quorums | Works |
| Settle from the oracle attestation after two rolls | User 14,000, LP 6,000 sats |
| Operator, LP and user gone after a roll | Onchain exit: user 7,500, LP 11,500 sats after fees |
| User answers the liveness challenge | Nostracles refuse to roll |
| Replayed old liveness answer | Does not count as alive |
| Roll that changes the payout script, value or maximum term | Nostracles refuse |
| Quorum spends or rolls before the timelock | Rejected by arkd: `FORFEIT_CLOSURE_LOCKED` |
| User and LP spend before the timelock | Works |
| 2 nostracles + LP after the timelock | Rejected: `missing 1 signatures` |
| Quorum exit before its delay | Rejected by Bitcoin: `non-BIP68-final` |
| Exit of an old, already rolled coin | Operator spends it with the forfeit, and the old payout fails |
| **3 nostracles + LP after the timelock** | **They take all 20,000 sats** |

## What each party can do

- **Operator alone:** refuse service and sweep an expired coin. It cannot spend a live contract coin.
- **LP alone:** refuse to roll. It cannot take the user's funds.
- **Up to 2 nostracles:** nothing alone. Two of them refusing still leaves a quorum of 3.
- **3 nostracles + LP:** take the collateral once the timelock passes.

## Limits of the design

- **The liveness test is policy, not a consensus rule.** Bitcoin and arkd only enforce the timelock and signatures. Mandate checks protect the user only while a majority of nostracles is honest.
- **The timelock does not give the user a unilateral escape.** The user's paths also need the LP, so a user who sees a colluding quorum and LP cannot move the coin alone.
- **Stale-exit protection depends on an online operator.** If the operator is gone, nobody broadcasts the forfeit, so an old coin could also exit. That loss should fall on the operator's liquidity rather than the user, but this was not tested.
- **Nostracles must be independent.** One party running three of them defeats the design.

## What this does not show

- Real nostr messaging, phone behavior, zaps or independently operated nostracles.
- A numeric DLC or a 3-of-5 oracle price. The number of pre-signed payouts may be much larger.
- A batch that fails halfway through a roll, or a nostracle dropping out during signing.
- Delivering the new payout signatures to the user.
- Funding payments, liquidation, operator censorship, real fees, reorgs or public-network behavior.

## Run it

Start Nigiri and arkd's `docker-compose.regtest.yml` at commit `fee16a7b`. Copy this test and the tests in `../01-offline-settlement` and `../02-failure-paths` into arkd's `internal/test/e2e`, then run:

```sh
go test -v -count 5 -timeout 1500s -run TestP2pFiatGuardian ./internal/test/e2e
```

The test stops and restarts the `arkd` container.
