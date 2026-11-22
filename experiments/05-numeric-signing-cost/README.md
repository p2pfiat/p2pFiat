# Experiment 5: numeric 3-of-5 signing cost

**Question:** what does a numeric 3-of-5 DLC cost to sign at every roll, and are frequent rolls practical?

**Result: a daily roll works for one position, but not at scale with independent 3-of-5 attestations.** At the reference settings each signer needs about **140,000 adaptor signatures per position per roll**, 40 times a single oracle. An 8-core signer could handle roughly 1,000 to 1,500 positions per day.

## Setup

- Uses nostracle's event shape: 20 binary digits of a whole-dollar price, with one BIP340 signature per digit and the DLC attestation tag. The oracle is reimplemented in the test.
- Uses the 22-path contract coin from experiment 4 and real exit, ark and checkpoint transactions. No arkd server is needed.
- Position: $1,000 stable balance, 2,000,000 sats collateral, opened at $100,000 per BTC.
- Measured on an 8-core ARM64 Windows PC in WSL. **No phone was measured.**

## How 3-of-5 multiplies the cost

Independent nostracles will not attest the identical price, so the contract has to accept small differences:

- Each of the 10 possible 3-of-5 groups needs its own signatures.
- In each group, the first nostracle's price sets the payout. The other two only need to be within the tolerance.
- Each of those two usually needs 2 digit prefixes to cover the tolerance, giving about 4 combinations.

That gives about **10 × 4 = 40 times** the single-oracle count. Tolerance size barely changes the total.

## Reference roll

Settings: payouts rounded to 1,000 sats ($1), price band of ±25%, $256 tolerance, exit payouts only.

| Measure | Result |
|---|---|
| Distinct payouts | 534 |
| Adaptor signatures per signer | 140,140 |
| Data each signer produces | 8.8 MB |
| Stored for all 4 signers | 35.3 MB |
| Time to sign | 3.7 to 5.9 s |
| Time to verify one other signer | 17.5 to 25.3 s |
| Time to verify all 3 other signers | About 53 to 76 s, extrapolated |

Timing comes from 4 real signing runs on 8 cores. The per-day capacity follows from about 56 to 82 seconds per position per signer.

## What changes the cost

Stored data per position per roll for all 4 signers, exit payouts only. The full table is in [results.csv](results.csv).

| Price band | Rounding | Largest rounding error | Single oracle | 3-of-5 |
|---|---|---|---|---|
| Whole domain | 1,000 sats | $0.50 | 3.4 MB | 143.6 MB |
| ±50% | 1,000 sats | $0.50 | 2.0 MB | 80.3 MB |
| **±25%** | **1,000 sats** | **$0.50** | **0.9 MB** | **35.3 MB** |
| ±10% | 1,000 sats | $0.50 | 0.3 MB | 13.6 MB |
| ±25% | 100 sats | $0.05 | 4.4 MB | 176.1 MB |
| ±25% | 10,000 sats | $5.00 | 0.1 MB | 5.9 MB |

Pre-signing the offchain path as well as the exit triples these figures. Offchain settlement can instead be signed after the attestation while the quorum and LP are online, with the pre-signed exit as the fallback.

## Checks

All checks passed in 4 of 4 runs:

- All 1,048,576 prices map to the exact expected payout.
- 1,000 random 3-of-5 settlements per run, with price differences inside the tolerance, passed Bitcoin's script engine.
- Two attestations cannot complete a payout.
- An attestation of a different price cannot complete a payout.
- Nostracles too far apart have no valid payout.

## What this means

- **One position can roll daily.** The work is small for servers.
- **Independent 3-of-5 attestations do not scale.** 1,000 positions would need about 35 GB of current signatures and most of an 8-core machine per signer.
- **A phone should not verify a full roll.** It could fetch only the 4 signatures it needs after settlement, but that fallback is not built.
- **The first nostracle in a group has limited price power.** It can move the settlement price by up to about twice the tolerance, about 0.5% at $256.

**The most promising fix is a threshold oracle.** If the nostracles agree on one price and produce one threshold signature per digit, the contract costs about the same as a single oracle: 3,496 signatures and 0.9 MB at the reference settings. This needs distributed key generation and a price agreement step. It was not built or tested.

## What this does not show

- Real nostracle attestations, nostr transport or independently operated nostracles.
- Phone CPU, battery or bandwidth.
- Batch verification, which may reduce the verification time.
- A threshold oracle, funding payments or liquidation.
- A numeric payout settled through a live arkd server.

## Run it

Copy this test into arkd's `internal/test/p2pfiatcost` directory at commit `fee16a7b`, then run:

```sh
P2PFIAT_OUT=results.csv go test -v -count 1 -timeout 560s -run TestP2pFiatNumericCost ./internal/test/p2pfiatcost
```
