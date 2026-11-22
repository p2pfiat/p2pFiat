# Experiment 8: 4-of-7 oracle over nostr relays

**Question:** does the 4-of-7 two-speed oracle from experiment 7 still work when its members are separate processes that communicate only through real nostr relay software?

**Result: yes, on local relays.** Seven processes generated keys, agreed on a price and produced valid attestations through three strfry relays. The oracle survived 3 members offline and full relay outages. **The known long-split attack also works over real relays:** 1 malicious member recovered an event key.

All 17 scenarios passed in 5 of 5 runs. The production timers passed in 1 run.

This is a research prototype and has not had a cryptographic review. **All relays and members ran on one machine.** Nothing was published to public relays, and the members were not independently operated.

## Setup

| Part | What ran |
|---|---|
| Members | 7 separate OS processes |
| Relays | 3 strfry containers, pinned by image digest |
| Messages | Signed nostr events, kind 9871, verified by each member |
| Key shares | NIP-44 encrypted to each recipient |
| Delivery | Published to every reachable relay, forwarded by members, and resent after reconnecting |
| Faults | A TCP proxy per member and relay for splits and latency; `docker kill` for relay outages |
| Result check | An outside client read the attestation from the relays and verified it as BIP340 |

The protocol is the one from experiment 7: 5 votes sign immediately, and 4 votes sign after the slow timeout plus a grace period.

## Results

Most scenarios used shortened timers: 3 s for reports, 20 s for the slow path and 6 s of grace.

| Scenario | Result |
|---|---|
| All 7 online, or 2 offline | Fast path, 3.3 to 8.5 s |
| 3 offline | Slow path, 26.2 to 26.3 s |
| 4 offline | No attestation |
| 150 to 400 ms of latency per proxy hop | Fast path, 4.2 to 4.4 s |
| 2 members report extreme prices | Fast path, price within honest reports |
| 3 members report extreme prices, or stay silent | Slow path, price within honest reports |
| 1 member sends a bad partial signature | Rejected, attestation still valid |
| 1 member sends a bad key share | Setup aborts and names the dealer |
| 1 dealer sends two different deals | Setup aborts and names the dealer |
| Forged, altered or replayed events | Ignored |
| 1 or 2 of 3 relays killed before the vote | Fast path |
| All 3 relays down across the vote deadline | Attested 0.8 to 1.0 s after they returned |
| **Last-second double vote, split heals in time** | **No honest member signed, no leak** |
| **Split outlasts the slow path, 1 malicious member** | **Event key recovered** |

With production timers:

| Members online | Attested after |
|---|---|
| 7 | 30.2 s |
| 4 | 660.2 s |

The busiest member sent 32.4 KB of original events per event, covering setup, voting and signing, before multiplying by the 3 relays. Forwarding other members' events adds more traffic, which was not measured.

## What testing found

- **Sequential publishing broke voting under latency.** Waiting for each relay's reply delayed reports past the deadline, so no attestation was produced. Members now publish concurrently.
- **go-nostr v0.40.1 cannot use WebSocket compression under Go 1.27.** Relay compression is off in this test. A real client needs a newer library or a fix.
- **go-nostr's tag lookup matches by prefix.** Members compare the session tag exactly, so a session whose name extends another's cannot be replayed into it.

## What remains open

- **Key setup needs all 7 members online.** One member can stop setup by sending a bad share. It is identified, but replacing it is not built, so events need to be set up well in advance.
- **The long-split leak remains.** A relay or network operator who can keep members apart for about 660 seconds, working with 1 malicious member, can expose an event key.
- **Relays can see the protocol.** Votes, prices and timing are public to them. Only key shares are encrypted.
- **Crash recovery and key rotation are not built.** A restarted member would lose its vote state, which could cause a double vote.

## What this does not show

- Public relays, internet latency, rate limits or relay retention.
- Independently operated members or relays.
- A second relay implementation. All three relays run strfry.
- A relay that actively lies, beyond dropping connections and the event checks above.
- Changes to nostracle itself, or a payout through a live arkd server.
- A proof or cryptographic audit of the protocol.

## Run it

Docker is required. Copy this test and the tests in `../05-numeric-signing-cost`, `../06-threshold-oracle` and `../07-two-speed-oracle` into arkd's `internal/test/p2pfiatcost` directory at commit `fee16a7b`, then run:

```sh
go test -v -count 5 -timeout 3000s -run '^TestP2pFiatNostrOracle$' ./internal/test/p2pfiatcost
```

For the production timers, which take about 12 minutes:

```sh
P2PFIAT_FULL_TIMING=1 go test -v -count 1 -timeout 1000s -run '^TestP2pFiatNostrOracle$' ./internal/test/p2pfiatcost
```
