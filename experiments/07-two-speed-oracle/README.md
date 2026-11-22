# Experiment 7: 4-of-7 two-speed oracle

**Question:** can a 4-of-7 threshold oracle stay available with 3 members offline, without the key-leak risk of a plain 4-vote quorum?

**Result: yes, as long as any network split heals before the slow path signs.** The oracle attests with up to 3 of 7 members offline. Up to 2 malicious members could not leak a key in any tested attack on a healed split. **A split that outlasts the slow path, combined with 1 malicious member, can still leak the key for that event.**

All 11 scenarios passed in 5 of 5 runs. Testing also found a new attack on the first version of the slow path, which led to the grace period below.

This is a research prototype and has not had a cryptographic review. Key generation, attestations and contract signatures use real cryptography. **The network and voting are a simulation with authenticated messages**, with no nostr transport.

## Protocol

1. **Keys.** Seven members hold a long-term group key. Each event gets its own key and 20 digit nonces from a distributed key generation, and the long-term key certifies them.
2. **Reports.** Members exchange prices for 30 seconds and take the median. A member refuses a median over 1% from its own price.
3. **Vote.** Each member votes once. A member that sees two votes from one member ignores that member.
4. **Fast path.** With 5 matching votes, a member signs immediately.
5. **Slow path.** After 600 seconds, a member with 4 matching votes waits a further **60-second grace period**. It signs only if the 4 votes are still valid.
6. **Attestation.** Any 4 signatures produce one normal BIP340 signature per digit.

## Availability

All 128 online and offline patterns behaved as designed:

| Each oracle offline | Fast path, about 31 s | Slow path, about 660 s | No attestation |
|---|---|---|---|
| 1% | 99.997% | 0.003% | 0.000% |
| 5% | 99.624% | 0.356% | 0.019% |
| 10% | 97.431% | 2.296% | 0.273% |
| 20% | 85.197% | 11.469% | 3.334% |
| 30% | 64.707% | 22.689% | 12.604% |

These figures assume independent failures. A shared hosting, relay or price feed outage would make them worse.

## Attacks

| Scenario | Result |
|---|---|
| Any 4 of 7 members sign (all 35 groups) | Identical valid attestation |
| Any 3 members sign (all 35 groups) | Invalid |
| 2 or 3 members report extreme prices | Price stays within honest reports |
| 3 members stay silent | Slow path still attests |
| 4 members stay silent | No attestation |
| **1 member double-votes one second before the timeout, no grace period** | **Key leaks, even after the split healed** |
| Same attack with the grace period | Blocked |
| 20,000 randomized attacks per run, with jitter and 1 or 2 malicious members | 0 leaks |
| 20 settlements through fast and slow paths | Passed Bitcoin's script engine |

Scripted leak search over every split and 64 vote timings:

| Malicious members | Split heals before signing | Split outlasts the slow path |
|---|---|---|
| 0 | 0 leaks | 0 leaks |
| 1 | 0 leaks | **Leak possible** |
| 2 | 0 leaks | **Leak possible** |
| 3 | **Leak possible** | **Leak possible** |

## What a leak would do

- A leak exposes **one event key**. The test confirmed that the long-term key and other events stayed safe.
- For that event, the attacker can forge **any price**. **Every contract settling on that event is exposed**, so per-event keys limit the damage but do not remove it.
- Staggering contracts across events would reduce how many positions depend on one key. This is not built.

## Cost

The contract still sees one oracle, so the roll cost matches experiment 6: 3,496 adaptor signatures per signer at the reference settings.

| Step | Result |
|---|---|
| Event setup, 22 key generations, all 7 members in one process | 0.5 to 1.7 s |
| Traffic sent per member per event | 8.4 KB |
| Attestation by 4 members | 8 to 18 ms |

## What remains trusted

- **4 colluding members control the oracle.**
- **The grace period assumes honest messages arrive in time.** A split lasting beyond about 660 seconds removes the protection.
- **Honest members must keep their vote and signing state.** Crash recovery is not built.
- **3 malicious members** can leak an event key, even after a short split.

## What this does not show

- Real nostr transport, relay behavior or real network delays.
- Independently operated nostracles.
- A proof of the protocol. The attack search is broad, but not exhaustive across all attacker strategies.
- Key rotation, member replacement or crash recovery.
- Changes to nostracle itself, or a payout through a live arkd server.

## Run it

Copy this test and the tests in `../05-numeric-signing-cost` and `../06-threshold-oracle` into arkd's `internal/test/p2pfiatcost` directory at commit `fee16a7b`, then run:

```sh
go test -v -count 5 -timeout 1400s -run TestP2pFiatTwoSpeedOracle ./internal/test/p2pfiatcost
```
