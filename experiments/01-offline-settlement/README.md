# Experiment 1: offline settlement on arkd

**Question:** can the LP complete a pre-signed payout on arkd while the user is offline, including the checkpoint?

**Result: yes, while the operator cooperates.** The test passed 10 of 10 runs on regtest (40 of 40 subtests).

## Setup

- arkd commit `fee16a7b`, built from source, on Nigiri regtest (Bitcoin Core 30.0), ARM64 Ubuntu 24.04 in WSL.
- The contract coin has two paths: user + LP + operator, and user + LP after a 20-block delay.
- A throwaway local key acts as the oracle. Nostracle is not used.

## What the test does

1. Funds a 10,000 sat contract coin.
2. The user adaptor-signs the ark transaction and checkpoint for two outcomes: 7,000/3,000 and 4,000/6,000 sats.
3. The user's key is wiped.
4. The oracle attests the first outcome, and the LP completes the user's signatures and submits the payout in one step.

| Check | Result |
|---|---|
| LP submits without the user's signature | Rejected: `missing 1 signatures` |
| LP uses the attestation on the wrong outcome | Signature invalid, rejected by arkd |
| LP settles the attested outcome with the user offline | Accepted: user 7,000 sats, LP 3,000 sats |
| Second payout after settlement, even with a valid attestation | Rejected: `VTXO_ALREADY_SPENT` |

## What this does not show

- **Operator refusal.** The operator must cosign. If it refuses, this path does not settle. Experiment 2 covers this.
- **Onchain finality.** The payout is a preconfirmed offchain transaction. It was not settled into a batch or exited onchain.
- **Coin expiry.** The user's payout coin must still be refreshed or exited before it expires, so the user cannot stay offline indefinitely.
- **Double-spend protection.** The operator enforced the single payout. A colluding operator and LP were not tested.
- **Emergency exit.** The exit path needs both user and LP, so either can block it. Its payout logic is still undesigned.
- **Production oracle.** The attestation is BIP340-style, not nostracle's kormir format.

## Run it

Start Nigiri and arkd's `docker-compose.regtest.yml`, copy the test into arkd's `internal/test/e2e`, then run:

```sh
go test -v -count 10 -run TestP2pFiatOfflineSettlement ./internal/test/e2e
```
