# Experiment 2: failure paths on arkd

**Question:** with the operator, LP or oracle gone, can each party recover the correct amount, and which exit leaf achieves this?

**Result: yes, if someone acts before the coin expires and the exit data was saved in advance.** Both tests and all 7 subtests passed in 5 of 5 repeat runs on regtest. If nobody acts before expiry, the exit is no longer possible.

## The exit leaf that works

The contract coin has three paths:

| Path | Script | Used for |
|---|---|---|
| Settle | user + LP + operator | Normal offchain payout |
| Refund | user + LP + operator, after a locktime | Offchain refund if the oracle is gone |
| Exit | user + LP, after a 20-block delay | Onchain payout or refund if the operator is gone |

A plain user + LP exit leaf lets either party block the exit. **Signing the onchain payouts when the contract opens removes that block:**

- Both parties adaptor-sign one onchain payout per outcome, spending the exit leaf.
- Both parties sign one onchain refund with a future `nLockTime`.
- Either party can then complete a payout with the oracle's attestation, or broadcast the refund after the locktime, without the other party's key.

## Results

Both parties' keys are wiped after opening, so every recovery uses only pre-signed data. In the operator-gone cases, arkd is actually stopped. Amounts are from a 20,000 sat contract, and onchain payouts take 500 sats of fee from each side.

| Failure | Recovery | Result |
|---|---|---|
| LP gone | User settles offchain | User 14,000, LP 6,000 |
| Oracle gone | Offchain refund, rejected before its locktime | User 10,000, LP 10,000 |
| Operator and LP gone | User exits onchain with the attestation | User 13,500, LP 5,500 |
| Operator and user gone | LP exits onchain with the attestation | User 7,500, LP 11,500 |
| Operator and oracle gone | Onchain refund, rejected before its locktime | User 9,500, LP 9,500 |
| Exit before the 20-block delay | None | Rejected by Bitcoin: `non-BIP68-final` |
| Attestation used on the wrong outcome | None | Rejected by Bitcoin: invalid signature |
| **Nobody acts before expiry** | **None** | **Operator sweeps the coin. Exit fails: `bad-txns-inputs-missingorspent`** |

## Design rules this implies

1. **Expiry is the hard deadline.** Someone must settle, renew or start the exit before the coin expires.
2. **Save the exit data at opening.** The exit transactions came from the operator's indexer. They must be stored before the operator disappears.
3. **Store them with more than one party.** The exit needs no private key once signatures are complete, so a watchtower could broadcast it. This was not tested.
4. **Set the refund locktime before coin expiry.** An onchain refund after expiry worked here only because the coin had already been unrolled.
5. **Keep BTC available for exit fees.** The exit took 3 transactions, each fee-bumped from a separate wallet. The test paid a fixed 10,000 sats per bump, so it does not measure the real cost, but small balances may not be worth exiting.

## What this does not show

- **A malicious operator.** The operator was stopped, not adversarial. Censorship, and collusion with the LP or user, were not tested.
- **Stale exits with the operator online.** Unrolling a contract that was already settled offchain was not tested.
- **Both parties offline through expiry.** The test shows the coin is swept. Recovery of a swept coin through the operator was not tested.
- **Real fee conditions, reorgs or mainnet timings.** Regtest uses a 40-block expiry and instant mining.
- **A production oracle.** A throwaway key is used, not nostracle's kormir format.

## Run it

Start Nigiri and arkd's `docker-compose.regtest.yml` at commit `fee16a7b`. Copy this test and the one in `../01-offline-settlement` into arkd's `internal/test/e2e`, then run:

```sh
go test -v -count 5 -timeout 1500s -run TestP2pFiatFailure ./internal/test/e2e
```

The test stops and restarts the `arkd` container.
