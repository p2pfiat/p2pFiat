# Experiment 3: covenant lifecycle on Arkade

**Question:** can a position be opened, renewed with `OP_TUNNEL` and settled at an oracle price, and what could the operator do alone?

**Result: the lifecycle works without either owner signing, but anyone holding the emulator key can take the whole coin.** All 9 scenarios passed in 5 of 5 runs on regtest. One of those scenarios is the successful theft, which is the expected result of the trust model and the main finding.

## Setup

- Emulator commit `30a59c7` with its pinned arkd `v0.9.25` images, on Nigiri regtest, ARM64 Ubuntu 24.04 in WSL. This is a different arkd version from experiments 1 and 2.
- The emulator runs in plain Docker, not in an AWS Nitro enclave.
- The user and LP provide public keys only. Their private keys are discarded at creation.
- The position holds 20,000 sats of collateral for a $5.00 stable balance.

The contract coin has three paths:

| Path | Signers | Enforced by the emulator |
|---|---|---|
| Renew | operator + emulator | `OP_TUNNEL`: same script and value, in a new batch |
| Settle | operator + emulator | Oracle signature at maturity, then `user = min(collateral, notional / price)` and `LP = collateral - user` |
| Exit | user + LP, after a delay | Nothing. Bitcoin only checks the two signatures |

## Results

| Scenario | Result |
|---|---|
| Keeper renews the coin twice with no owner signature | Works, same script and 20,000 sats |
| Settle after renewal at $40,000 per BTC | User 12,500, LP 7,500 sats |
| Renewal to a new owner or lower value | Rejected by `OP_TUNNEL` |
| Forged oracle signature or changed price | Rejected by the signature check |
| Wrong timestamp, wrong payout or wrong recipient | Rejected by the script |
| Second settlement | Rejected: `VTXO_ALREADY_SPENT` |
| Two contracts sharing one payout | Rejected by the single-input check |
| Emulator down | Settlement unavailable, then works after restart |
| **Emulator key used directly on an owner-free path** | **Attacker receives all 20,000 sats** |
| Emulator key used on a path that also needs an owner | Rejected: `missing 1 signatures` |

## What the operator could do alone

- **With the emulator key, it can steal the coin.** The test skipped the emulator service and signed a payment to an attacker with the tweaked emulator key. Unmodified arkd cosigned it without running the covenant.
- **Without the emulator running, it can halt the contract.** Renewal and settlement both depend on the emulator, so a coin that cannot be renewed will eventually expire.
- **An owner signature blocks the theft, but removes the benefit.** A renewal that needs the owner's signature brings back the liveness problem this design is meant to solve.

Design 2 therefore depends on the security of the emulator key and its enclave. It does not remove operator trust.

## Open problems

- **The exit is unsolved.** The exit leaf needs both user and LP, so either can block it. The fix from experiment 2, pre-signed payouts, commits to one coin and would stop working at each renewal. This follows from the design and was not run.
- **The keeper is a dependency.** The renewal script is pinned to one keeper key, so if that keeper disappears, nobody else can renew. This was not run.
- **There is no refund path if the oracle never signs.** This contract would then need the exit leaf.

## What this does not show

- Nitro enclave protections, attestation, or a real key compromise. The key used is the published regtest key.
- The theft through the settle leaf. It has the same owner-free structure, but only the renew leaf was attacked.
- A position whose price falls far enough to use all the collateral.
- Renewal near real expiry timings, onchain exit, or mainnet behavior.
- nostracle. The oracle is a throwaway key signing `ticker || price || timestamp`, a format nostracle does not publish yet.

## Run it

Start Nigiri and the emulator's `docker-compose.regtest.yml` at commit `30a59c7`, copy this test into the emulator's `test` directory, then run:

```sh
go test -v -count 5 -timeout 500s -run TestP2pFiatCovenant ./test/
```

The test stops and restarts the `emulator` container.
