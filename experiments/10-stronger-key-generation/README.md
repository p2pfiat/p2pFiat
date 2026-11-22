# Experiment 10: stronger key generation

**Question:** can the 4-of-7 oracle stop a malicious leader or dealer from steering the key? In experiment 9, public key parts were visible before the dealer set was fixed, so an attacker could choose the set that gave it a key it preferred.

**Result: mostly yes.** A leader can no longer choose a key from the visible parts, and a dealer cannot change or withdraw its contribution once the set is certified. **One bias remains:** when only 5 members are online, a single malicious member can see the key, refuse to vote and force a restart.

All 26 checks passed in 5 of 5 runs: 24 live scenarios and 2 calculations.

This is a research prototype and has not had a cryptographic review. **Seven processes and three strfry relays ran on one machine**, with shortened timers. Nothing was published to public relays.

## Protocol

The design follows the two-phase key generation of Gennaro, Jarecki, Krawczyk and Rabin, with a voting rule added for nostr.

1. **Deal.** Each member publishes hiding Pedersen commitments, with a NIP-44 encrypted share and blinding share for every other member.
2. **Complain and answer.** As in experiment 9, a bad share leads to a public complaint, and the dealer must answer it.
3. **Certify the dealers.** A leader proposes the dealer set, and 5 matching votes fix it. The key is already determined, but nobody can compute it yet.
4. **Reveal.** Each certified dealer publishes its public key parts. Members check them against their own shares and can publish proof of a false reveal.
5. **Vote on what to open.** Members vote on the exact reveals to use and the exact dealers to open. **5 matching votes are required, and at least 3 dealers must stay unopened.**
6. **Open.** Members publish their shares only for the dealers in that certified list. Any 4 valid shares rebuild the dealer's original contribution.
7. **Announce.** Members derive the keys and sign the event announcement with the long-term key.

The opening vote matters. Without it, a relay outage could make every member believe that all other dealers had withheld. They would then publish their shares for all of them, which would expose the key.

## Results

| Scenario | Result |
|---|---|
| All 7 online | Key created, nobody opened, attested on the fast path |
| 2 offline during setup | Key created, attested |
| 3 offline during setup | Nothing certified |
| 2 members miss setup, catch up, then help sign | Attested on the slow path |
| Bad share, false complaints, silent dealer, two deals | Handled as in experiment 9 |
| Silent leader, leader with an invalid set, split with a two-faced leader | No bad key, and the next attempt succeeds |
| **Dealer withholds its reveal** | **Opened, key keeps its original contribution** |
| **Dealer reveals a different key part** | **Opened, key keeps its original contribution** |
| **Dealer reveals two key parts** | **Opened, key keeps its original contribution** |
| 2 dealers withhold together | Both opened, key unchanged |
| False evidence against an honest dealer | Rejected, nobody opened |
| 2 false votes to open an honest dealer | Nobody opened |
| **All relays down during reveal** | **No member published a share, and the next attempt succeeded** |
| 2 dealers withhold and refuse to open, with 2 members offline | No key, setup stays unfinished |
| Opening would leave fewer than 3 dealers secret | Honest members refuse |
| 2 members abort after seeing the key, all 7 online | Key still created |
| **1 member aborts after seeing the key, 5 online** | **Attempt fails, so the attacker can reject that key** |
| 3 members down with a prepared event | New setup fails, the prepared event attests |

### Key bias

A simulated leader controlling 2 dealers tried to force one chosen bit of the key, in 2,000 trials per run.

| What the leader can see | Forced the bit |
|---|---|
| Public key parts, as in experiment 9 | 93.3% to 94.1% |
| Hiding commitments, as in this experiment | 49.0% to 51.2% |

An unbiased bit would be 50%. This calculation shows the effect of hiding the key parts from the leader. It is not a proof.

### A test failure

The first 5-run batches failed in 2 of 5 runs and then 1 of 5 runs. An honest dealer was left out of a retry after a split. The cause was the test harness: members kept connections for all earlier events, and these reconnected together when the split healed. That delayed one deal past the proposal deadline.

The protocol stayed safe, but this shows a real operational risk: **a slow honest dealer is excluded.** The harness now closes finished connections, and the final 5 runs passed.

## What remains open

- **Restart bias.** With no spare voter online, a malicious member can see the key and block the attempt. Each restart gives it another key to accept or reject. Limits on retries, and penalties for members that repeatedly stop voting, are not built.
- **3 malicious members break the guarantees.** They can defeat the 5-vote rule, and the 3 unopened dealers could then all be theirs.
- **A delayed honest dealer can be opened.** If 5 members vote that its reveal is missing, its contribution becomes public. The key stays secret while at least one unopened dealer is honest.
- **Setup can stall.** Opening needs 4 valid shares. Two malicious members and two offline members can leave too few, so the attempt fails.
- **A bad share to an offline member still goes unnoticed until it returns.** Share recovery is not built.
- **Retries and the event buffer are driven by the test.** Automatic leader rotation and buffer management are not built.
- **The long-term key setup was only run with all 7 honest members.**
- **Crash recovery, key rotation and permanent member replacement are not built.**

## What this does not show

- Public relays, internet latency, or independently operated members.
- A second relay implementation.
- Production timers for setup. Attempts used a limit of 16 seconds.
- Changes to nostracle itself, or a payout through a live arkd server.
- A proof or cryptographic audit of this protocol or its added voting rule.

## Run it

Docker is required. Copy this test and the tests in `../05-numeric-signing-cost`, `../06-threshold-oracle`, `../07-two-speed-oracle`, `../08-nostr-oracle` and `../09-fault-tolerant-setup` into arkd's `internal/test/p2pfiatcost` directory at commit `fee16a7b`, then run:

```sh
go test -v -count 5 -timeout 3500s -run '^TestP2pFiatStrongerKeygen$' ./internal/test/p2pfiatcost
```
