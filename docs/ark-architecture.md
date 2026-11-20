# p2pFiat on Ark: architecture note

Status: draft, 2026-11-20

## Why 10101 struggled

10101 put DLCs inside Lightning channels. Every state change, including a
contract rollover, a channel update, or a counterparty force close, needed the
user's wallet to be online and responsive. iOS kills background processes
aggressively, so phones missed rollovers and channels force-closed. The
cryptography worked. The liveness model did not fit a phone.

## What Ark changes

On Ark, users hold off-chain VTXOs that an always-online operator co-signs. There
are no channels, no per-peer liquidity, and Lightning interop goes through the
operator. VTXOs expire and must be renewed. Both implementations let a phone hand
that renewal to someone else, which addresses the problem that broke 10101.

A fully collateralised stable position needs a **contract VTXO** jointly owned by
the user and a liquidity provider (LP), with an oracle-conditioned payout and a
refund path. The question is which implementation can express that.

## bark vs arkd

Both checked against `master` on 2026-11-20:
[bark](https://gitlab.com/ark-bitcoin/bark) `1ab6ccb` by Second, and
[arkd](https://github.com/arkade-os/arkd) `fee16a7` by Ark Labs (Arkade). Both are MIT licensed.

| | **bark** (Second) | **arkd** (Ark Labs / Arkade) |
|---|---|---|
| Language | Rust | Go server; TypeScript SDK (browser, React Native, Node); Go client-lib |
| VTXO scripts | **Closed set**: `VtxoPolicy = Pubkey \| ServerHtlcSend \| ServerHtlcRecv` (+ server-internal types) | **Custom tapscript trees** built from closures: `Multisig`, `CLTVMultisig`, `CSVMultisig`, `ConditionMultisig`, `ConditionCSVMultisig` |
| Two-party VTXO | Only by hiding a MuSig2 key inside `Pubkey`. The exit path then also needs both keys: no unilateral refund. | Native: an N-of-N leaf with the operator key, plus separate timeout and exit leaves |
| Timeout / refund path | No | Yes (`CLTVMultisig` for collaborative timeouts, `CSVMultisig` for exits) |
| Hash or other conditions | HTLCs only, built in | `ConditionMultisig`: arbitrary condition script (no sig/timelock opcodes) + keys |
| Delegated renewal | Yes, built in, but for single-owner `Pubkey` VTXOs | Yes, via **intent delegation**: an extra `user + delegate + operator` leaf; forfeits pre-signed `SIGHASH_ALL\|ANYONECANPAY` |
| Default VTXO lifetime | 30 days (`vtxo_lifetime`) | ~7 days (`vtxo_tree_expiry` = 604672 s) |
| Off-chain spend | arkoor, operator co-signs | virtual tx + checkpoint tx per input; operator co-signs every non-CSV path |
| Experimental extras | — | "Arkade Script": operator-emulated introspection (experimental) |
| Maturity | signet; mobile via bark-ffi (uniffi) | Mutinynet examples; a single operator; self-hosting documented for regtest only |

**Conclusion:** arkd can express a DLC VTXO today without forking the server. bark
would need a new `VtxoPolicy` variant, which is upstream work. Choose arkd for M2,
and keep the design implementation-neutral, because only the script tree differs.

## DLC VTXO on arkd

Parties: user **U**, liquidity provider **L**, operator **S**, oracle **O** (nostracle, which never appears in the script).

```
Taproot (key path disabled)
  leaf settle   : Multisig(U, L, S)
                  CETs pre-signed by U and L as adaptor signatures on O's
                  attestation points; L completes one once O attests, S co-signs
  leaf delegate : Multisig(U, L, S)  - same leaf: L is also U's renewal delegate
                  (U pre-signs renewal intents + forfeits, ALL|ANYONECANPAY)
  leaf refund   : CLTVMultisig(U, L, S) after maturity + grace
                  pre-signed refund split, used if O never attests
  leaf exit     : CSVMultisig(U, L) after exit delay
                  unilateral on-chain exit; the DLC then settles on-chain
```

Why this removes the phone from the critical path:

- **L and S are always online.** U signs everything at open time: the CETs, the refund, and the renewal intents.
- **Renewal** (every ~7 days) is submitted by L as delegate. The forfeit
  signature locks the inputs and outputs, so L can only renew into the same contract script.
- **Settlement** at maturity: O attests, L completes the matching CET, S
  co-signs. U only needs to come online to spend the resulting plain VTXO.

Open questions:

1. **Roll vs renew.** Renewal keeps the *same* contract alive across VTXO
   expiries. Rolling into a *new* contract (new strike) needs U to sign new CETs,
   so U comes online once per contract term. Proposal: 30–90 day contracts,
   renewed weekly by delegation, rolled when the app is opened.
2. **Pre-signed intents.** Intents are bounded by `valid_at` / `expire_at`.
   Confirm that U can pre-sign a chain of ~13 renewals (90 days / 7) at open time,
   or whether each renewal's intent depends on the previous batch.
3. **CET count.** Numeric DLCs with digit decomposition keep the number of CETs
   manageable. Measure how many co-signatures S needs per contract.
4. **Oracle horizon.** nostracle must announce events at contract maturity,
   i.e. 30–90 days ahead rather than 48 h. This is a config change.
5. **bark path.** Ask Second whether a contract policy (or generic tapscript
   VTXOs) is on their roadmap. bark's 30-day lifetime and Rust stack are attractive.

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
| M2 | DLC VTXO between two Arkade wallets on Mutinynet/regtest: open, renew by delegation, settle on oracle attestation | M1, arkd custom scripts |
| M3 | LP / dealer service: quotes, hedging, acts as renewal delegate | M2 |
| M4 | Mobile wallet (Arkade TS SDK in React Native) with a "stable balance" toggle | M3 |
| later | p2p order book (nostr) instead of a single LP; k-of-n oracles; bark backend if it gains contract VTXOs | M3 |

## Sources

- bark source: `lib/src/vtxo/policy/mod.rs`, `bark/src/round/mod.rs`, `server/src/config.rs`
- arkd source: `pkg/ark-lib/script/closure.go`, `pkg/ark-lib/script/vtxo_script.go`, `docs/settings.md`
- [Arkade: intent delegation](https://docs.arkadeos.com/arkd/components/intent-delegation)
- [Arkade: VTXO lifecycle and liveness](https://docs.arkadeos.com/learn/core-concepts/vtxo-lifecycle-and-liveness.md)
- [Arkade: contracts deep dive](https://docs.arkadeos.com/contracts/deep-dive.md)
