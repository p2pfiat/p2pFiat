# p2pFiat on Ark: architecture note

Status: draft, 2026-11-20

## Why 10101 struggled

10101 put DLCs inside Lightning channels. Every state change, including a
contract rollover, a channel update, or a counterparty force close, needed the
user's wallet to be online and responsive. iOS kills background processes
aggressively, so phones missed rollovers and channels force-closed. The
cryptography worked. The liveness model did not fit a phone.

## What Ark changes

Ark (implementation: [bark](https://gitlab.com/ark-bitcoin/bark), server
`captaind`) gives users off-chain VTXOs that the server co-signs.
Relevant properties, checked against bark `master` (Nov 2026):

- **No channels.** There is no channel state to keep alive and no per-peer
  liquidity to manage.
- **Delegated refresh.** VTXOs expire (default `vtxo_lifetime` = 30 days).
  bark supports *delegated / non-interactive round participation*
  (`RoundFlowState::NonInteractivePending`, `Redelegating`): the user signs
  ahead and the server refreshes the VTXO in a later round without the user
  being online. This addresses the problem that broke 10101.
- **Lightning interop** comes through the server (HTLC VTXO policies), so a stable
  balance can still pay Lightning invoices.

## The gap: contract VTXOs

bark's `VtxoPolicy` is a closed enum:

```
Pubkey | ServerHtlcSend | ServerHtlcRecv   (+ server-internal: Checkpoint, Expiry, HarkLeaf, ...)
```

There is no policy for a two-party contract, such as a DLC, a 2-of-2 with
timeout, or a 2-of-3 escrow. A fully collateralised stable position needs one. So:

> **The user does not need liveness, but the contract VTXO must be refreshable
> by delegation.** The always-online parties are the LP (counterparty)
> and the Ark server. The phone pre-signs everything at open time.

### Candidate design: DLC VTXO policy

```
Taproot output, internal key = MuSig(user, LP)   (cooperative close / roll)
  leaf A: CETs pre-signed by user as adaptor signatures on oracle
          attestation points -> LP completes once the oracle attests
  leaf B: refund to both after timeout (oracle never attests)
  + the usual Ark exit delta / server sweep after expiry
```

Open questions to work through with the Second team:

1. Can a delegated refresh carry a 2-party VTXO? The forfeit signatures need
   both keys. The user can pre-sign forfeits for N future rounds if round
   parameters are predictable enough.
2. Should contracts be shorter than `vtxo_lifetime` (e.g. weekly DLCs that
   settle into plain VTXOs) so that no contract VTXO ever needs a refresh?
   This is probably the simplest first version.
3. Settlement as an arkoor (out-of-round) spend that the server co-signs.

## The oracle's role

In a DLC the oracle **does not hold a key in the contract**. It publishes
nonces in advance (announcement) and later a Schnorr signature on the outcome
(attestation). The oracle cannot see which contracts use it, cannot spend
funds, and is not a custodian. That is better than a 2-of-3 escrow where the
oracle is the "third key", both for trust and for the operator's regulatory
position. Threshold use (k-of-n oracles) is supported by the DLC specs.

Oracle events are published on nostr as NIP-88 kind 88 (announcement) and
kind 89 (attestation). That is what
[nostracle](https://github.com/p2pfiat/nostracle) does. Revenue: zaps and
paid "premium" event series. The oracle is useful on its own, independent of
Ark progress.

## Roadmap

| Milestone | Deliverable | Depends on |
|---|---|---|
| M1 | **nostracle**: BTC/USD and BTC/EUR DLC oracle on nostr (NIP-88), multi-exchange median | nothing |
| M2 | Short-dated DLC between two bark wallets on signet, settling into plain VTXOs | M1, a contract VTXO policy in bark (fork or upstream) |
| M3 | LP / dealer service: quotes, hedging, rolls contracts while the user is offline | M2 |
| M4 | Mobile wallet (bark-ffi) with a "stable balance" toggle | M3 |
| later | p2p order book (nostr) instead of a single LP; k-of-n oracles | M3 |
