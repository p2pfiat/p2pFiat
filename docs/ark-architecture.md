# p2pFiat on Ark: architecture note

Status: audited draft, 2026-11-21. Nothing below has been prototyped.

## Summary

- **No reviewed design gives all four at once:** a phone that stays offline, no trust in the Ark operator, rolling positions, and working software today.
- **The previous version of this note was wrong.** It said a phone could sign once and an LP could renew a DLC weekly. Pre-signed DLC transactions commit to the exact coin they spend, and renewal replaces that coin.
- **Two designs are worth testing:**
  1. **Fixed-term DLC.** It keeps the operator out of the payout logic. The phone must come online once per term to roll. If it doesn't, the position settles to BTC at maturity and the user loses the hedge, not the funds.
  2. **Arkade Script vault.** It can renew without the phone and settle from an oracle price. The operator's enclave enforces the contract, so this adds operator trust.
- **Recommendation:** prototype the fixed-term DLC first, and run the three tests under [Next steps](#next-steps) before committing to either design.

## What must hold

| # | Requirement | Why |
|---|---|---|
| R1 | The phone can be offline when something time-critical happens | This is the problem attributed to 10101 |
| R2 | The operator cannot take or redirect funds | Self-custody |
| R3 | The LP cannot take the user's funds, and vice versa | Two-party contract |
| R4 | Funds remain recoverable if the operator, LP or oracle disappears | Failure handling |
| R5 | Positions can continue past one coin lifetime | A stable balance is long-lived |
| R6 | It works on software available today | Buildable |

## Why pre-signed DLCs and renewal conflict

A DLC pre-signs one payout transaction (CET) per price outcome. Each signature commits to the outpoint it spends, including with `SIGHASH_ALL|ANYONECANPAY`. Ark renewal forfeits the old coin and creates a new one in a new batch. The new txid depends on the batch, so it cannot be known when the contract opens.

After a renewal, **every CET and refund signature is invalid**, and the user must sign again. Avoiding this requires one of:

- a contract that ends before the coin must renew;
- a signature that doesn't commit to the outpoint (APO, not active on Bitcoin);
- a covenant (CTV or TEMPLATEHASH, not active on Bitcoin);
- an off-chain script engine, such as Arkade's emulator, which adds trust in its operator.

## bark and Arkade today

Reviewed at bark `1ab6ccb`, Second docs `7ecd7e2`, arkd `fee16a7`, emulator `30a59c7`, compiler `4075d82` and ts-sdk `bd6057c`.

| | **bark** (Second) | **Arkade** (Ark Labs) |
|---|---|---|
| Networks | Mainnet and signet servers | Mainnet, Mutinynet and signet operators |
| Client SDKs | Rust, Swift, Kotlin, Dart, Go, React Native, WASM | TypeScript (browser, React Native, Node), Go client library |
| Coin lifetime | 28 days on Second's server (`vtxo_lifetime` default comment: 30) | arkd default about 7 days; the public operator's batch expiry was not confirmed |
| Coin scripts | Fixed set: `Pubkey`, HTLC variants, server-internal types | Custom tapscript: multisig, CLTV, CSV and hash-style conditions |
| Script engine beyond Bitcoin Script | None | Arkade Script: introspection, arithmetic, `OP_CHECKSIGFROMSTACK`, run by the operator's emulator |
| Oracle support | None documented | Signed price checks, oracle outputs, option and escrow templates |
| Delegated renewal for a normal coin | Yes, but the wallet **signs the forfeit when next opened**. Today it relies on the server's signature only; co-signers are not built | Yes: a presigned request and forfeit for specific coins. The SDK re-delegates each new coin **while the wallet runs** |
| Renewal without any owner | No | Yes, for covenant coins using `OP_TUNNEL` (`renewProgramContractOutputs`) |
| Status of the programmable layer | Not applicable | Emulator README: "Alpha — available on testnet". A mainnet emulator endpoint also responds (v0.0.9) |

**bark** has no contract coin type. A DLC would need a new `VtxoPolicy` and server support. A MuSig key inside `Pubkey` would make the exit path need both parties, and bark's signing code does not support that nesting.

**Arkade** can express a two-party script today. Its `StabilityVault` example targets this exact use case, but **it does not work yet**: all functions except the exit are commented out, because "settlement currently hits unsupported runtime bindings". Its design document also says the exit path enforces the same settlement math, while the code lets the seeker alone spend the whole output after the delay.

### The exit-path limit

Bitcoin cannot run Arkade Script, so after a unilateral exit the contract math no longer applies. The exit leaf must be one of:

- **One party alone**, as in `StabilityVault` and the option templates. That party can claim the other's collateral after the delay unless another spend happens first.
- **N-of-N**, as in the escrow template. If one party disappears, the funds are stuck.
- **N-of-N plus pre-signed payouts.** This is safe, but it brings back the outpoint problem.

Any design has to choose one explicitly. This is the main unresolved risk for R3 and R4.

## Methods compared

Yes = meets it; Partly = with a stated limit; No = does not.

| Method | R1 phone offline | R2 no operator trust | R3 no LP trust | R5 rolls | R6 today | Assessment |
|---|---|---|---|---|---|---|
| On-chain DLC | Partly: until roll | Yes | Yes | No: new on-chain contract | Yes | Sound, too costly for small balances |
| DLC in Lightning channel (10101) | No | Yes | Yes | Yes, interactive | Yes | The failure this project avoids |
| DLC factory | No: must watch before settlement | Yes | Yes | Yes, with both parties | Design | Good on-chain design; a VTXO renewal would break its signatures |
| Ticketed DLC | Partly | Yes | Yes | No | Library | One-shot, multi-player |
| **Fixed-term DLC on an Ark coin** | Partly: online once per term | Partly: operator must cosign; exit needs design | Yes, if exit is solved | Partly: user signs each roll | Unproven on arkd; needs new policy on bark | **Prototype first** |
| DLC renewed by re-signing | No | Partly | Yes | Yes | Unproven | Same liveness problem as 10101 |
| **Arkade Script vault** | Yes | **No: relies on operator enclave** | Partly: exit leaf | Yes | Partly: alpha, reference vault disabled | **Second track** |
| CTV, TEMPLATEHASH, APO or CSFS | Yes | Yes | Yes | Yes | No: not active | Best long-term, not buildable now |
| Witness encryption (VweTS) | Same as DLC | Yes | Yes | Same as DLC | Research | Improves multi-oracle efficiency, not liveness |
| Cashu or Fedimint | Yes | No: mint or federation custody | Partly | Yes | Yes | Custodial trust |
| Trusted LP balance (Stablesats style) | Yes | Yes | No | Yes | Yes | Simple, not trustless |

## Design 1: fixed-term DLC

The contract ends well before the coin must renew.

```
Open:      U and L fund a contract coin and pre-sign payouts for that exact coin
Maturity:  oracle attests -> L completes the matching payout -> operator cosigns
Roll:      when U next opens the app, settle and open a new contract
Missed:    position settles to plain BTC at the oracle price; U loses the hedge
```

**The main benefit is a safer failure.** Missing a roll ends the hedge at a fair price, and does not force a channel closure. The user must still open the wallet before the resulting coin expires, as with any Ark wallet.

Limits:

- The dollar value is protected only until maturity. An absent user then holds BTC.
- A term must fit inside one coin lifetime, with margin for settlement and exit.
- Arkade's offchain spend has a step where the wallet signs after the operator. Whether U can pre-sign it is **unverified** (test 1).

## Design 2: Arkade Script vault

A covenant checks a signed oracle price and enforces the payout, and `OP_TUNNEL` lets a keeper renew the coin without its owners. This is the only reviewed design that meets R1 and R5 today.

The cost is trust. Covenant paths are signed by the operator's server and emulator keys, inside an AWS Nitro enclave. Arkade's docs state that a compromised key could sign a spend the script would refuse, and that paths also requiring the owner's signature stay protected. A renewal path has no owner signature, so **it has no such protection**.

## The oracle

A DLC oracle holds no key in the contract and cannot see who uses it. [nostracle](https://github.com/p2pfiat/nostracle) works for Design 1 as built.

Design 2 needs a different signed message: Arkade's examples verify `sha256(ticker || price || time)` with `OP_CHECKSIGFROMSTACK`. nostracle would need to publish this format too. These signatures would be visible when used, which affects the paid-attestation model.

## Next steps

Run on regtest before building a product:

1. **Offline settlement (Design 1):** can L complete a pre-signed payout on arkd while U is offline, including the checkpoint?
2. **Failure paths:** with the operator, LP or oracle gone, can each party recover the correct amount? Which exit leaf achieves this?
3. **Covenant lifecycle (Design 2):** open, renew with `OP_TUNNEL`, and settle an oracle-priced position, measuring what the operator could do alone.

Questions for the teams:

- **Second:** are contract coins or custom scripts planned for bark?
- **Ark Labs:** what is the mainnet status of the emulator, the public batch expiry, and the plan for `StabilityVault`?

| Milestone | Deliverable | Depends on |
|---|---|---|
| M1 | nostracle oracle | Built; not deployed |
| M2 | Regtest tests 1–3, then choose a design | M1 |
| M3 | Chosen contract on a test network | M2 |
| M4 | LP service: quotes, hedging, rolls | M3 |
| M5 | Mobile wallet with a stable balance | M4 |

## Scope of this audit

**Read in full:** Second's protocol pages on VTXOs, lifetime, forfeits, rounds, exits and payments. Arkade's pages on trust, renewal, transactions, settlement, oracle overview, signed messages, vault overview, exit, options, escrow and network resources. The stability design and vault source. Delegation and renewal code in the SDK and bark.

**Keyword-searched, not read line by line:** the remaining Second pages (83 total) and Arkade pages (74 total).

**Not done:** a formal security review, running any contract, or an exhaustive literature review. The 10101 failure reason comes from the project's history and was not independently researched.

## Sources

- [Second docs](https://gitlab.com/ark-bitcoin/docs): `learn/vtxo`, `learn/lifetime`, `learn/forfeits`, `learn/rounds`, `learn/exit`
- bark source: `lib/src/vtxo/policy/mod.rs`, `bark/src/round/mod.rs`, `server/src/config.rs`
- [Arkade security and trust model](https://docs.arkadeos.com/learn/concepts/security-and-trust-model), [emulator](https://docs.arkadeos.com/learn/concepts/emulator), [expiry and renewal](https://docs.arkadeos.com/learn/concepts/expiry-and-renewal), [vault exit](https://docs.arkadeos.com/vaults/exit), [options](https://docs.arkadeos.com/vaults/reference/options)
- [Arkade emulator](https://github.com/arkade-os/emulator), [`StabilityVault`](https://github.com/arkade-os/compiler/tree/master/examples/stability), [ts-sdk](https://github.com/arkade-os/ts-sdk)
- [DLC factories](https://conduition.io/scriptless/dlc-factory/), [ticketed DLCs](https://conduition.io/scriptless/ticketed-dlc/)
- [CTV and DLCs](https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2022-January/019808.html), [modern oracle designs survey](https://arxiv.org/pdf/2602.09822)
