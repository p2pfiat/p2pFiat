# Experiment 11: limit restart bias

**Question:** can a malicious nostracle still reject a key it has seen by forcing a restart? In experiment 10, with only 5 members online, one member could see the key, refuse to vote and cause a fresh attempt with a new key.

**Result: not while at most 2 of 7 members are malicious and honest members keep their lock.** Once a dealer set is certified, its event slot cannot restart. An attacker can still **delay or block that slot**, but it cannot swap the key. When enough members return, the slot finishes with the same key the attacker saw.

All 13 checks passed in 5 of 5 runs: 11 live scenarios and 2 calculations.

This is a research prototype and has not had a cryptographic review. **Seven processes and three strfry relays ran on one machine**, with shortened timers. Nothing was published to public relays.

## Protocol

This builds on the two-phase key generation of experiment 10, with three new rules.

1. **At least 5 dealers.** A proposal with fewer dealers cannot be voted on or certified. Experiment 10 allowed 4.
2. **A certified slot is locked.** A member that holds the 5-vote certificate refuses to help restart that slot. If finishing is blocked, members resume the same attempt when another member returns.
3. **A restart needs 5 signed abandon messages.** Before certification nobody can know the key, so a failed attempt can still be replaced. Abandon messages name one slot and one attempt, so they cannot be reused elsewhere.

**Why 5 dealers matter.** To know the key, an attacker needs the reveal of every honest certified dealer. With 5 dealers and at most 2 attackers, at least 3 honest members have revealed and locked. Only 4 members remain who could sign an abandon message, one short of the 5 needed. With 4 dealers, only 2 honest members would have locked, which leaves 5 possible signers.

An exhaustive count over all attacker sets of up to 2 and all dealer sets found **210 restart paths with 4 dealers and none with 5 or more**, in 1,856 cases.

## Results

| Scenario | Result |
|---|---|
| All 7 online | Key created, attested on the fast path |
| 2 offline during setup | Key created with 5 dealers, attested |
| **1 member aborts after seeing the key** | **No restart, then finished with the same key when a member returned** |
| **2 members abort after seeing the key** | **No restart, then finished with the same key when 2 members returned** |
| Attacker blocks and no fifth voter returns | Slot stays unfinished, and no replacement key exists |
| Silent leader | Nothing revealed, restarted with 5 abandon messages, attested |
| Split with a two-faced leader | Nothing certified, restarted, attested |
| Leader proposes only 4 dealers | Refused, restarted, attested |
| 1 bad dealer with only 5 members online | Attempt fails, retry with a sixth member succeeds |
| Abandon messages from another slot | Do not count |
| Another slot is blocked | A prepared event still attests |

### What a restart was worth

| Restarts the attacker can force | Chance to force one key bit before | With locked slots |
|---|---|---|
| 0 | 50.0% | 50.0% |
| 1 | 75.0% | 50.0% |
| 2 | 87.5% | 50.0% |
| 3 | 93.8% | 50.0% |
| 5 | 98.4% | 50.0% |

These figures are calculated. They show what each extra restart would give an attacker, and they assume locked slots hold.

## What remains open

- **An attacker can still block a slot.** With exactly 5 members online, one attacker can stop that slot from finishing until another member returns. **The product must not replace a blocked slot with a new key, or the bias returns.** Each event date needs a fixed slot and a defined fallback, such as the fixed-term DLC. Neither is built.
- **The lock is held in memory.** A member that crashes and forgets its lock could sign an abandon message. The lock must be stored durably before it reveals. Crash recovery is not built.
- **3 malicious members break the guarantees.** They could collect an abandon quorum, defeat certification or learn the key.
- **Raising the minimum to 5 dealers costs availability.** With 5 members online, a single bad dealer now fails the attempt until a sixth good member is available.
- **Earlier limits remain.** Share recovery, automatic retries and leader rotation, key rotation and member replacement are not built. The long-term key setup was only run with all 7 members honest.

## What this does not show

- Public relays, internet latency, or independently operated members.
- A second relay implementation.
- Production timers for setup. Attempts used a limit of 16 seconds.
- Changes to nostracle itself, or a payout through a live arkd server.
- A proof or cryptographic audit. The restart rule is supported by an exhaustive count, not a formal proof.

## Run it

Docker is required. Copy this test and the tests in `../05-numeric-signing-cost`, `../06-threshold-oracle`, `../07-two-speed-oracle`, `../08-nostr-oracle`, `../09-fault-tolerant-setup` and `../10-stronger-key-generation` into arkd's `internal/test/p2pfiatcost` directory at commit `fee16a7b`, then run:

```sh
go test -v -count 5 -timeout 3500s -run '^TestP2pFiatRestartBias$' ./internal/test/p2pfiatcost
```
