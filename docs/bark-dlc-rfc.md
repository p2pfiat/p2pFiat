# RFC: Trustless 2-Party DLC VTXOs on Bark (`DlcVtxoPolicy` + 2-Input Arkoor Co-Funding)

> **Context:** [p2pFiat](https://github.com/p2pfiat/p2pFiat) is a working, self-custody synthetic USD/EUR and 2× Long BTC protocol currently running live on Mutinynet ([Web Wallet PWA](https://p2pfiat.github.io/), [Rust DLC Oracles `nostracle`](https://github.com/p2pfiat/nostracle), and a [keyless Rust TRUC CPFP `ark-watchtower`](https://github.com/p2pfiat/p2pFiat/tree/main/watchtower)).
>
> We want to build p2pFiat natively on **Bark** and are happy to contribute the implementation as MRs once we align on the preferred design.

---

## Why This Fits Bark's Current `master` Cleanly

Bark's `master` already has `lib/src/vtxo/policy/clause.rs` (`TapScriptClause`, `DelayedSignClause`) and `Policy` in `lib/src/vtxo/policy/mod.rs`. That means **most of the Taproot machinery needed for non-custodial DLC VTXOs is already in place**.

We only need two focused additions (plus one small export helper):

---

## 1. `VtxoPolicy::Dlc` (2-Party Shared VTXO Policy)

A DLC position (`Stable USD/EUR` or `2× Long BTC`) is a 2-party VTXO funded jointly by a **User** and a **Liquidity Provider (LP)** (or P2P counterparty):

- **Key-path (Collaborative / Arkoor — Happy Path):**
  - `MuSig2(User, LP, Server)` — identical to Bark's standard key-path spend, enabling instant offchain close, partial spend, or rollover at live spot.
- **Script-path Leaf 1 (Unilateral DLC Exit / Refund):**
  - `DelayedSignClause { pubkey: MuSig2(User, LP), block_delta: exit_delta }` (already exists in `clause.rs`!) — or an explicit `DelayedMultisigClause` (`CSV + <User> OP_CHECKSIG <LP> OP_CHECKSIGADD 2 OP_EQUAL`) if explicit 2-of-2 witness is preferred over MuSig2 adaptor signing.
  - Both parties pre-sign BIP-340 adaptor-signature CETs (locked to Nostracle `kind: 88` nonces) plus a timelocked refund transaction and a tiered NUMS P2TR Watchtower bounty output.
- **Script-path Leaf 2 (Optional — On-Demand BIP-342 `k-of-n` Oracle Dispute Clause):**
  - New `TapScriptClause` implementation (`ThresholdOracleClause`):
    ```
    <exit_delta> OP_CHECKSEQUENCEVERIFY OP_DROP
    <O_1> OP_CHECKSIG <O_2> OP_CHECKSIGADD ... <O_n> OP_CHECKSIGADD <k> OP_GREATERTHANOREQUAL
    ```
  - Allows mid-term exit on 7d/30d/90d contracts or early -50% liquidation if a counterparty goes offline, with zero cherry-picking risk because the `k-of-n` Nostracle quorum signs the live spot price at exit time `T`.

```rust
pub struct DlcVtxoPolicy {
    /// Combined 2-of-2 user + counterparty key (or explicit pair)
    pub user_pubkey: PublicKey,
    pub counterparty_pubkey: PublicKey,
    /// Optional k-of-n BIP-342 oracle dispute quorum (for long-term / anytime exit)
    pub dispute_oracles: Option<ThresholdOracleConfig>,
}
```

---

## 2. Atomic 2-Input Multi-Party `arkoor` Co-Funding & Settlement

Related to issue [#1388](https://gitlab.com/ark-bitcoin/bark/-/issues/1388) (*Third-party HTLCs*):

- **Open (Co-Funding):** Combine a User-owned VTXO + an LP-owned VTXO as 2 inputs to a single atomic `arkoor` transaction creating 1 shared `DlcVtxoPolicy` output (plus optional change outputs). Neither party can steal the other's collateral if funding aborts mid-way.
- **Close / Rollover:** Spend the shared `DlcVtxoPolicy` VTXO via collaborative key-path (`MuSig2(User, LP, Server)`) into separate User + LP `Pubkey` VTXOs (or directly into a new rolled `DlcVtxoPolicy` VTXO) in one atomic `arkoor`.

---

## 3. Exportable Unroll Chain for Keyless Watchtowers

Expose a read-only helper on `Bark` / `Vtxo` to export the signed VTXO unroll transaction branch (raw TRUC/v3 transactions + P2A anchors) so an independent **keyless Watchtower** (holding zero User/LP private keys) can monitor and CPFP-unroll the DLC VTXO onchain for a tiered bounty if the counterparty disappears.

---

## Questions for the Bark Maintainers

1. For Leaf 1 of `DlcVtxoPolicy`, do you prefer reusing `DelayedSignClause` with a `MuSig2(User, LP)` key, or adding an explicit `DelayedMultisigClause` (`OP_CHECKSIGADD`)?
2. Should `DlcVtxoPolicy` be a dedicated `VtxoPolicy` variant or generalized alongside [#1388](https://gitlab.com/ark-bitcoin/bark/-/issues/1388) (third-party multi-party policies)?
3. Is `bark-wasm-ffi` on track for browser wallets, or should we target native Rust (`bark-client`) first?

We're ready to open a Draft MR implementing `DlcVtxoPolicy` + `ThresholdOracleClause` + regtest tests as soon as we align on #1 and #2.

