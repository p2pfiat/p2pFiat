# Experiment 6: threshold oracle

**Question:** can 3 of 5 nostracles act as one DLC oracle, and does that remove the 40-times signing cost from experiment 5?

**Result: yes, the cost drops 40 times, but the simple protocol has a serious flaw that needs a price certificate.** Without one, a network split and 2 malicious members can reveal the whole group key. With 5 members the certificate prevents this, but 2 members can then halt attestations. **7 members with a 5-vote certificate is the better design**, based on quorum arithmetic that was not run with 7 live members.

All 19 scenarios passed in 5 of 5 runs. Two of them are successful key-leak attacks that show why the certificate is needed.

This is a research prototype and has not had a cryptographic review. All members run in one process, with no nostr transport.

## Protocol

1. **Key generation.** Five members run a distributed key generation with share verification and proofs of knowledge. No member ever holds the group key.
2. **Nonce generation.** Each event runs one more distributed generation per price digit, 20 in total, and announces the group nonces.
3. **Price agreement.** Members exchange signed reports in 3 synchronous rounds and take the median. Each member refuses a median more than 1% from its own price.
4. **Price certificate.** Each member votes once for the agreed price. A member signs only when it holds 4 votes for the same price.
5. **Attestation.** Any 3 members produce partial signatures, which combine into one normal BIP340 signature per digit.

The DLC contract sees one oracle with one public key.

## Cost

Same reference position as experiment 5: $1,000, payouts rounded to $1, ±25% price band, exit payouts only.

| Per position, per roll | Independent 3-of-5 | Threshold 3-of-5 |
|---|---|---|
| Adaptor signatures per signer | 140,140 | **3,496** |
| Data per signer | 8.8 MB | **225 KB** |
| Stored for all 4 signers | 35.3 MB | **0.9 MB** |
| Sign, 8 cores | 3.7 to 5.9 s | **0.13 to 0.28 s** |
| Verify 3 other signers, 8 cores | About 53 to 76 s | **About 2.0 to 4.4 s** |
| Positions per day, per 8-core signer | About 1,000 to 1,500 | **About 19,000 to 40,000** |

Oracle overhead is small:

| Step | Result |
|---|---|
| Key setup, once | 0.02 to 0.05 s |
| Event setup, all 5 members in one process | 0.25 to 0.69 s |
| Traffic sent per member per event | 5.7 KB |
| Price agreement | 0.08 to 0.31 s, excluding network delay |
| Attestation by 3 members | 0.03 to 0.11 s |

## Results

| Scenario | Result |
|---|---|
| All 10 groups of 3 members | Identical valid attestation |
| 40 random settlements with certificates | Passed Bitcoin's script engine |
| 2 members try to attest | Invalid signature |
| Member submits a bad partial signature | Identified |
| Dealer sends a bad share or a rogue key | Excluded |
| 3 of 5 dealers fail | Key generation aborts |
| 2 members report extreme prices | Median stays within honest reports |
| 2 members equivocate or reveal reports late | Honest members still agree |
| 3 members offline | No attestation |
| Honest member sees a price over 1% away | Refuses to sign |
| **3 members sign two prices** | **Whole group key is revealed** |
| **Network split + 2 malicious members, no certificate** | **Whole group key is revealed** |
| Same split with a 4-vote certificate | Two certificates are impossible, in all 8 splits |

## The flaw and the fix

A DLC oracle reveals its key if it signs two values with one nonce. In a threshold group, honest members can trigger this by accident:

1. A network delay makes honest member A choose one price and honest member B another.
2. Two malicious members sign both prices.
3. They combine with A for the first attestation and with B for the second.
4. The two attestations reveal the group key, which breaks every open contract using it.

The certificate prevents this without relying on network timing, because two 4-of-5 vote sets must share at least one honest member, and that member votes only once.

| Members | Vote quorum | Safe from a split with 2 malicious | Still attests if those 2 stop |
|---|---|---|---|
| 5 | 3 | No | Yes |
| 5 | 4 | **Yes** | **No** |
| 7 | 4 | No | Yes |
| **7** | **5** | **Yes** | **Yes** |

The 7-member row is arithmetic over the voting rule. The key generation and signing test used 5 members.

## What remains trusted

- **3 colluding members control the oracle.** They can attest any price, or reveal the key.
- **A key leak affects every open contract.** With independent oracles, one leak affects only that oracle. A leaked group key would need emergency rotation, which is not built.
- **Honest members must keep their vote and nonce state.** Losing it could cause a double vote or nonce reuse.
- **Price agreement assumes synchronous rounds.** If timing fails, the certificate keeps the key safe, but the event may produce no attestation, and contracts would use the refund path.

## What this does not show

- Real nostr transport, relays, delays or independently operated nostracles.
- A live 7-member group.
- Key rotation, member replacement, backups or crash recovery.
- Changes to nostracle itself, which still signs alone with kormir.
- A threshold-attested payout through a live arkd server.
- A formal security proof or cryptographic audit.

## Run it

Copy this test and the test in `../05-numeric-signing-cost` into arkd's `internal/test/p2pfiatcost` directory at commit `fee16a7b`, then run:

```sh
go test -v -count 5 -timeout 560s -run TestP2pFiatThresholdOracle ./internal/test/p2pfiatcost
```
