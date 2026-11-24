# Experiment 12: durable slot locks and crash recovery

**Question:** can a nostracle that crashes, restarts or loses its disk be made to break the oracle's promises? In experiment 11 the slot lock was held in memory, so a member that crashed after revealing could forget it and sign a restart. A restarted member could also compute a different value for a step it had already published, such as a second price.

**Result: no tested crash produced a second value, a second key or a forbidden restart.** A guard writes every outgoing message to a checksummed journal on disk before any relay can see it. A restarted member republishes exactly what it had sent and cannot send anything else for that step. When a disk is lost or rolled back, the member finds its own unknown messages on the relays and refuses to sign a restart, or stops publishing for that event.

All 27 checks passed in 5 of 5 runs: 3 journal and guard checks and 24 live scenarios, with no retries. Before that, 380 stepwise trials ran, including 180 targeted kills and 100 seeded random kills. None found a conflicting message on the relays.

This is a research prototype and has not had a cryptographic review. **Seven processes and three strfry relays ran on one machine**, with shortened timers. Members were killed with SIGKILL, which does not simulate power loss. Nothing was published to public relays.

## Protocol

The protocol logic of experiments 10 and 11 is unchanged. A guard sits between each member's logic and the relays:

1. **Journal before release.** Every outgoing event is signed, appended to a journal and flushed to disk before it is handed to the relays. Each record carries a SHA-256 checksum. A torn final record is dropped, because it was never released. Damage before the final record stops the member, because its history can no longer be trusted.
2. **One value per protocol step.** A restarted member republishes the stored event for a step unchanged, so its ID and content stay the same. If it computes anything different for that step, such as a second price vote or a second deal, the guard blocks it.
3. **A signature share must match the stored vote.** A member can only publish a signature share for the price it voted for in that event.
4. **The lock reaches the disk first.** The slot lock is flushed before a member reveals, votes to open dealers, or publishes an opening share. A locked member never signs a restart of that slot.
5. **Signing a restart gives up the attempt.** After signing an abandon message for an attempt, a member can no longer vote, reveal or vote to open in it. Experiment 11's rule did not have this, so a member could sign a restart and still reveal.
6. **Lost or rolled-back disks are detected on the relays.** A restarted member holds its output for 1 second while it reads the relays. A message signed with its own key that its journal does not know means its disk lost history. The member then stops publishing for that event. Before signing a restart, a member also reads the attempt from the relays. If it finds its own unknown messages, or a 5-vote certificate, it locks the slot and refuses.

The journal also stores the member's secret deal and its key shares, so a member that restarts after setup can still attest.

## Results

### Main test

| Scenario | Result |
|---|---|
| Journal with a torn final record | Record dropped, later records survive |
| Journal damaged before its final record | Refused as corrupt |
| Guard unit checks | Second vote, second price, share without a vote, reveal after abandon and abandon of a locked slot are all blocked |
| Kill before journal, after journal or after send of a deal (3 kill points) | The member restarts and finishes with the same key as the others, with at least 5 dealers |
| Kill at the same 3 points of a dealer vote, reveal or open vote (9 kill points) | The member restarts, stays a dealer with its one deal, and finishes with the same key |
| Kill at the same 3 points of a price vote or signature share (6 kill points) | The member restarts and sees the attestation; an outside client verifies it |
| Restart with a different price | The new price is blocked; one attested price |
| All 7 members restart after setup | All attest from their journals |
| Lock survives a restart | Restarted members refuse a restart and finish with the key the attacker saw |
| **Control:** 4 members lose their disks, no relay audit | **A restart certificate is formed:** this is the attack durable state must stop |
| 4 members lose their disks, with the relay audit | All 4 refuse; no restart certificate |
| Member's disk rolled back to before its signature share | Member quarantines itself for that event; no conflicting message |

On the relays, no member published two values for one step in any scenario.

### Stepwise checks

These ran before the final confirmation. Each trial used a fresh cluster, and after every trial the relays were scanned for two values from one member for one step, including after failed trials.

| Step | Trials | Ok | Skipped | Failed |
|---|---|---|---|---|
| 1. Experiment 11 members, no guard, no kills | 20 | 19 | 0 | 1 (machine went to sleep during the trial) |
| 2. Guard and journal, no kills | 20 | 20 | 0 | 0 |
| 4. Each of the 18 kill points, 10 times | 180 | 180 | 0 | 0 |
| 5. Each recovery scenario, 10 times | 60 | 60 | 0 | 0 |
| 6. Seeded random kills: any member, any of its messages | 100 | 79 | 21 | 0 |

In step 6 each trial picked a member, setup or attestation, the message number at which to kill, and one of the 3 kill points. In 21 setup trials the chosen member sent fewer messages than the chosen number, so nothing was killed and the trial passed. The 79 real kills hit all 7 members, including the leader 13 times. **No trial in any step found a conflicting message on the relays.**

## What went wrong while testing

The first batches failed in ways that turned out to come from the test machine, not the protocol:

- **WSL stopped responding twice** and had to be force-restarted. The relay ports stopped accepting connections and Docker stopped responding.
- **The arkd regtest stack crash-looped after a restart** and used more than a full CPU core. Experiment 12 does not need it, so it was stopped.
- **The PC went to sleep** during a run, and the timer-based protocol cannot survive that.
- **All scenarios shared one cluster,** so one failure spoiled the rest. Each scenario now gets a fresh cluster.

With the arkd stack stopped and the PC kept awake, steps 2 to 6 had no failures.

Two harness issues were fixed without weakening any safety assertion. An attacker that withholds its own open vote still counts it locally, so the test now checks that the **honest** members did not finish. A member that misses a reveal at the open-vote deadline skips its open vote. This is behaviour from experiment 10, not a crash effect, so a kill point on that vote may never be reached. The test now accepts this only when the member reports it, logs it and retries on a fresh cluster. Any other missed kill point still fails.

## What remains open

- **SIGKILL is not power loss.** The journal calls fsync, but this only shows that a killed process loses nothing it flushed. Lost writes in the disk or file-system cache are not tested.
- **Secrets are stored in plain text** in a 0600 journal. A production member needs encryption at rest or a hardware key.
- **The disk-loss audit trusts the relays to show history.** If every relay a member reads hides its earlier messages, a member with a lost disk could still sign a restart. More independent relays make this harder but not impossible.
- **Quarantine costs availability.** A member whose disk was rolled back stops publishing for that event. With 2 such members and 2 offline, the event cannot attest.
- **A late reveal costs an open vote.** A member that has not seen every reveal at the open-vote deadline skips its open vote and does not retry. With only 5 members online, this can stall the slot.
- **Earlier limits remain.** Blocked slots still need fixed date slots and a fallback. 3 malicious members break the guarantees. Share recovery, automatic retries, key rotation and member replacement are not built.

## What this does not show

- Power loss, disk failure or a second file system.
- Public relays, internet latency, or independently operated members.
- Production timers for setup. Attempts used a limit of 16 seconds.
- Changes to nostracle itself, or a payout through a live arkd server.
- A proof or cryptographic audit.

## Run it

Docker is required. Copy both test files in this directory and the tests in `../05-numeric-signing-cost`, `../06-threshold-oracle`, `../07-two-speed-oracle`, `../08-nostr-oracle`, `../09-fault-tolerant-setup`, `../10-stronger-key-generation` and `../11-restart-bias` into arkd's `internal/test/p2pfiatcost` directory at commit `fee16a7b`, then run:

```sh
go test -v -count 5 -timeout 7000s -run '^TestP2pFiatCrashRecovery$' ./internal/test/p2pfiatcost
```

The stepwise checks use the same directory. Set `P2PFIAT_LADDER_STEP` to 1, 2, 4, 5 or 6, `P2PFIAT_LADDER_N` to the number of trials, and for step 6 optionally `P2PFIAT_LADDER_SEED` (default 12):

```sh
P2PFIAT_LADDER_STEP=4 P2PFIAT_LADDER_N=10 go test -v -timeout 14300s -run '^TestP2pFiatCrashLadder$' ./internal/test/p2pfiatcost
```

Stop unrelated containers and keep the machine awake during a run: both caused failures here.
