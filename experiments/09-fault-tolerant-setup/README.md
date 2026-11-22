# Experiment 9: fault-tolerant event setup

**Question:** can the 4-of-7 oracle set up new events when some nostracles are offline or malicious? In experiment 8, a single missing or bad member stopped setup.

**Result: yes, with up to 2 of 7 members offline or faulty.** Bad dealers are excluded, members that missed setup catch up from the relays, and events prepared in advance still attest when 3 members are down. **With 3 members down, no new event can be set up.** This is deliberate: requiring 5 votes stops a split from creating two conflicting key sets.

All 17 checks passed in 5 of 5 runs: 16 live scenarios and one availability calculation.

This is a research prototype and has not had a cryptographic review. **Seven processes and three strfry relays ran on one machine**, with shortened timers. Nothing was published to public relays.

## Protocol

1. **Deal.** Each member publishes commitments and proofs, with a NIP-44 encrypted share for every other member.
2. **Complain.** A member that receives a bad share publishes a signed complaint.
3. **Answer.** The dealer publishes the correct share for that complainer. Anyone can check it against the commitments. A dealer that does not answer is excluded.
4. **Propose.** A leader proposes the exact set of dealers, which must have at least 4 members.
5. **Certify.** Each member votes once. A member refuses a proposal with an invalid deal, an open complaint or a missing share of its own. **5 matching votes finalize the set.**
6. **Announce.** Only after certification, members sign the event announcement with the long-term key.
7. **Catch up.** A member that was offline reads the deals and votes from the relays and derives its share.

Each attempt is a fresh key generation. If an attempt fails, the next one starts clean with another leader.

## Availability

| Each oracle offline | Experiment 8: all 7 needed | Now: at least 5 needed | 3 independent attempts |
|---|---|---|---|
| 1% | 93.2% | 99.997% | Over 99.9999% |
| 5% | 69.8% | 99.624% | Over 99.9999% |
| 10% | 47.8% | 97.431% | 99.998% |
| 20% | 21.0% | 85.197% | 99.676% |
| 30% | 8.2% | 64.707% | 95.604% |

These figures are calculated and assume independent failures. Real outages are often shared and last longer than one attempt, which is why events should be prepared in advance.

## Results

| Scenario | Result |
|---|---|
| All 7 online | Certified, attested on the fast path |
| 2 offline during setup | Certified with 5 dealers, attested |
| 3 offline during setup | **4 members voted, nothing certified** |
| 2 members miss setup, catch up, then help sign with only 4 online | Attested on the slow path |
| Bad share, no answer | Dealer excluded |
| Bad share, dealer answers | Dealer stays, share repaired |
| False complaints against every dealer | All dealers answered, none excluded |
| Dealer sends nothing | Excluded |
| Dealer sends two different deals | Excluded |
| Leader stays silent | Attempt fails, next leader succeeds |
| Leader includes a dealer with an open complaint | All honest members refused |
| Leader sends two proposals | At most one key set among honest members |
| **Split with a two-faced leader** | **Each side voted for a different key set, and neither was certified** |
| Leader shrinks the dealer set to 4 | Accepted, key valid (see below) |
| 3 members down with 2 events prepared | New setup fails, both prepared events attest |
| Bad share sent to an offline member | That member cannot sign this event (see below) |

In the split scenario, each side held 4 votes. A 4-vote rule would have created two valid key sets, so setup uses only the 5-vote rule. Setup can wait, unlike attestation, so it does not need a slow path.

## What remains open

- **A malicious leader or dealer can influence the key.** A leader can choose which dealers count, and a dealer can wait to see others' commitments first. This can bias the key, although it does not reveal it. A stronger key generation should replace this before production.
- **A bad share to an offline member goes unnoticed until it returns.** That member then cannot sign that event, which quietly reduces how many members can be offline at attestation. Share recovery is not built.
- **3 malicious members can break certification.** Two sets of 5 votes can then overlap only in malicious members, which could produce two valid key sets for one attempt.
- **Retries and the event buffer are driven by the test.** Automatic leader rotation, buffer management and assigning key sets to dates are not built.
- **The long-term key setup was only run with all 7 honest members.**
- **Crash recovery, key rotation and permanent member replacement are not built.**

## What this does not show

- Public relays, internet latency, or independently operated members.
- A second relay implementation.
- Production timers for setup. Attempts used a limit of 11 seconds.
- Changes to nostracle itself, or a payout through a live arkd server.
- A proof or cryptographic audit of the protocol.

## Run it

Docker is required. Copy this test and the tests in `../05-numeric-signing-cost`, `../06-threshold-oracle`, `../07-two-speed-oracle` and `../08-nostr-oracle` into arkd's `internal/test/p2pfiatcost` directory at commit `fee16a7b`, then run:

```sh
go test -v -count 5 -timeout 3400s -run '^TestP2pFiatFaultTolerantSetup$' ./internal/test/p2pfiatcost
```
