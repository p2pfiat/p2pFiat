# p2pFiat on Ark: architecture note

Status: audited draft, updated 2026-11-24 with six regtest experiments on `arkd` (including a keyless watchtower exit bounty and a full end-to-end integration with a 4-of-7 threshold oracle over local `strfry` nostr relays), a signing-cost measurement and seven threshold oracle prototypes. Nothing has run on a public network, and no product has been built.

## Summary

- **No reviewed design gives all four at once:** a phone that stays offline, no trust in the Ark operator, rolling positions, and working software today.
- **The previous version of this note was wrong.** It said a phone could sign once and an LP could renew a DLC weekly. Pre-signed DLC transactions commit to the exact coin they spend, and renewal replaces that coin.
- **Three designs were tested:**
  1. **Fixed-term DLC.** It keeps the operator out of the payout logic. The phone must come online once per term to roll. If it doesn't, the LP can settle the position to BTC at maturity, so the user loses the hedge, not the funds. **If nobody settles or exits before the coin expires, the operator can sweep it.**
  2. **Arkade Script vault.** It renewed and settled from an oracle price with no owner signature. **In our test, the emulator key alone was enough to take the whole coin**, so this design depends on the operator's enclave.
  3. **Nostracle quorum rolling DLC.** Any 3 of 5 nostracles can roll the DLC for an offline user, after a timelock and on terms the user fixed at opening. The operator cannot spend a live coin alone. **3 nostracles colluding with the LP can take the collateral.**
- **Regtest results:** all four tests passed. See [Regtest results](#regtest-results) for what they do and do not show.
- **Signing cost:** with independent 3-of-5 attestations, each signer needs about 140,000 adaptor signatures per position per roll. That works for one position but does not scale. See [Signing cost](#signing-cost).
- **Threshold oracle:** a prototype cuts that cost 40 times by making the nostracles act as one oracle. It needs a price certificate, because a network split and 2 malicious members could otherwise reveal the group key. See [Threshold oracle](#threshold-oracle).
- **4-of-7 two-speed oracle:** a simulated group attested with up to 3 of 7 members offline. Up to 2 malicious members could not leak a key in any tested attack on a split that healed in time. **A split lasting past about 660 seconds, plus 1 malicious member, can still leak one event key.** See [4-of-7 two-speed oracle](#4-of-7-two-speed-oracle).
- **Over nostr relays:** seven separate processes ran that oracle through three local strfry relays and survived 3 members offline and full relay outages. The long-split attack also worked there. Public relays and independent operators are untested. See [Over nostr relays](#over-nostr-relays).
- **Event setup:** setting up a new event now works with up to 2 of 7 members offline or faulty. With 3 down, no new event can be set up, but events prepared earlier still attest. See [Fault-tolerant event setup](#fault-tolerant-event-setup).
- **Key generation:** a two-phase key generation stops a leader from choosing a favourable key and stops a dealer from changing its contribution. See [Stronger key generation](#stronger-key-generation).
- **Restart bias:** a certified event slot can no longer restart, so up to 2 malicious members cannot swap a key they have seen. They can still delay or block that slot, and a blocked slot must never get a replacement key. See [Locked event slots](#locked-event-slots).
- **Crash recovery:** each member writes every message and its slot lock to a journal on disk before publishing. In 380 stepwise trials and a final 5-run test, no killed or restarted member published a second value, and a member with a lost disk refused to sign a restart. Power loss is not tested. See [Crash recovery](#crash-recovery).
- **Watchtower exit bounty:** a keyless watchtower holding only saved exit data and its own BTC fee wallet unrolled orphaned `arkd` contracts, paid real CPFP fees, settled DLC payouts or refunds, and profited (`+2,800` sats net per exit) via a tiered P2TR bounty output (`W1` immediate, backup watchtowers after 4-block CSV). Miners and early backup snipers were rejected by Bitcoin Core in 5 of 5 runs. See [Regtest results](#regtest-results).
- **End-to-end integration:** a live 4-of-7 threshold oracle over 3 local `strfry` nostr relays (with 2 members offline) attested real 20-bit numeric prices (`$91,420` and `$114,800`) to settle two rolled `2,000,000`-sat (`$1,000`) numeric DLCs (527 binary prefixes each) on a live `arkd` — both offchain and via a keyless watchtower onchain exit (`+4,000` sats net profit) after `arkd` was stopped. Passed 5 of 5 runs. See [Regtest results](#regtest-results).
- **Recommendation:** make the nostracle quorum rolling DLC the primary candidate for rolling swaps. Use a 4-of-7 threshold oracle with two-speed voting, per-event keys, two-phase key generation, locked event slots and a journal on disk for each member, subject to a cryptographic review. The fixed-term DLC is its fallback when no quorum is available. Keep the Arkade Script vault as a second track.

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
- an off-chain script engine, such as Arkade's emulator, which adds trust in its operator;
- a quorum that re-signs for an absent user at each renewal, which adds trust in that quorum (Design 3).

## bark and Arkade today

Reviewed at bark `1ab6ccb`, Second docs `7ecd7e2`, arkd `fee16a7`, emulator `30a59c7`, compiler `4075d82` and ts-sdk `bd6057c`. The covenant test ran on arkd `v0.9.25`, the version pinned by the emulator.

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
| Unilateral exit tooling | Built into wallet for supported policies; custom contract exits not yet supported | Keyless exit packages (`arkade-unilateral-exit` / `@arkade-os/sdk`) for standard wallets; multi-party DLC exits still require custom orchestration (storing exit branch at opening, CPFP bumping, watchtower) |

**bark** has no contract coin type, so it cannot host a trustless p2pFiat contract today. See [Can bark be used?](#can-bark-be-used).

**Arkade** can express a two-party script today. Its `StabilityVault` example targets this exact use case, but **it does not work yet**: all functions except the exit are commented out, because "settlement currently hits unsupported runtime bindings". Its design document also says the exit path enforces the same settlement math, while the code lets the seeker alone spend the whole output after the delay.

### Can bark be used?

**Not for a trustless contract today, but bark is not ruled out.** It needs a contract coin type in both the client and the server.

Why it does not work today:

- **No contract coin.** A bark coin has one owner key or a fixed Lightning HTLC form. A DLC needs a coin held jointly by user and LP, with payout and refund paths.
- **A combined key is not enough.** Putting a user+LP MuSig key in `Pubkey` makes the emergency exit need both parties, so either one can block it. bark's signing code also does not support that nested signing.
- **Delegated refresh does not fill the gap.** It is built for single-owner coins, and the wallet still signs a forfeit when next opened.

What would make it usable:

| Route | What it needs | Result |
|---|---|---|
| **Fixed-term DLC on bark** | A new `VtxoPolicy` with server validation, signing, exit and recovery support, upstream or in a fork | Design 1, with terms inside the 28-day coin lifetime on Second's server |
| **Generic custom scripts in bark** | A larger protocol change by Second | Could support DLCs and other contracts |
| **Trusted LP balance on plain bark coins** | No bark changes: the hedge lives with the LP, outside Ark | Works with bark as it is, but the user trusts the LP, so it misses R3 |
| **Covenants on Bitcoin** | A soft fork | Could remove the renewal problem, but is not available |

A fork has a practical cost: users could only use a server running that fork, and it would carry changes to security-critical server code. Upstream support from Second is the better route.

bark remains attractive for its mainnet server, native mobile SDKs, longer coin lifetime (28 days vs ~7 days default on arkd) and focus on reliable on-chain exits. Second has indicated they are working on catching up on script/contract support and want to make on-chain contract exits solid.

Minimum requirements for bark to host p2pFiat (no off-chain VM or covenants needed — pure Bitcoin Tapscript + pre-signed DLCs):

1. **Contract `VtxoPolicy` (or generic Tapscript policy):**
   - **Collaborative spend paths (off-chain):** `user + LP + server` (optionally with CLTV for refund), and for Design 3 rolling swaps, `M-of-N quorum + LP + server` paths with CLTV.
   - **Unilateral exit paths (on-chain):** `user + LP` after a CSV delay (and for Design 3, `quorum + LP` after a longer CSV delay), so parties can pre-sign adaptor payouts and refunds on the exact VTXO outpoint at opening.
2. **Hard on-chain exit tooling for custom leaves:**
   - Export/save the full exit transaction branch at contract opening.
   - Reliable unroll + CPFP fee-bumping that can finish by broadcasting a **pre-signed transaction** spending the custom exit leaf — ideally executable by a watchtower without private keys.

If Second adds these, Design 1 (and Design 3) can move to bark: the oracle, LP logic and contract terms stay the same, while the coin script and signing flow change.

### The exit-path limit

Bitcoin cannot run Arkade Script, so after a unilateral exit the contract math no longer applies. The exit leaf must be one of:

- **One party alone**, as in `StabilityVault` and the option templates. That party can claim the other's collateral after the delay unless another spend happens first.
- **N-of-N**, as in the escrow template. If one party disappears, the funds are stuck.
- **N-of-N plus pre-signed payouts.** Either party can exit alone with the correct amount. It brings back the outpoint problem, so it only fits a coin that is not renewed.

**Design 1 uses the third option, which worked on regtest (test 2).** Design 3 keeps this option across rolls, because its quorum signs the new coin's payouts before giving up the old coin (test 4). Design 2 renews with no signer, so pre-signed payouts would stop working at each renewal. Its exit remains the main unresolved risk for R3 and R4.

## Methods compared

Yes = meets it; Partly = with a stated limit; No = does not.

| Method | R1 phone offline | R2 no operator trust | R3 no LP trust | R5 rolls | R6 today | Assessment |
|---|---|---|---|---|---|---|
| On-chain DLC | Partly: until roll | Yes | Yes | No: new on-chain contract | Yes | Sound, too costly for small balances |
| DLC in Lightning channel (10101) | No | Yes | Yes | Yes, interactive | Yes | The failure this project avoids |
| DLC factory | No: must watch before settlement | Yes | Yes | Yes, with both parties | Design | Good on-chain design; a VTXO renewal would break its signatures |
| Ticketed DLC | Partly | Yes | Yes | No | Library | One-shot, multi-player |
| **Fixed-term DLC on an Ark coin** | Partly: online once per term, and someone must act before expiry | Partly: operator must cosign and can sweep after expiry | Yes on regtest, with pre-signed exits | Partly: user signs each roll | Partly: passed on arkd regtest; needs new policy on bark | **Build next** |
| DLC renewed by re-signing | No | Partly | Yes | Yes | Unproven | Same liveness problem as 10101 |
| **Arkade Script vault** | Yes, while a keeper renews | **No: emulator key can take the coin** | Partly: exit unsolved | Yes | Partly: custom contract passed on regtest; alpha, reference vault disabled | **Second track** |
| **Nostracle quorum rolling DLC** | Yes, while a quorum is online | Partly: operator must cosign and can refuse, but cannot spend a live coin alone | Partly: 3 of 5 nostracles + LP can take the collateral | Yes | Partly: passed on arkd regtest with simulated nostracles; threshold oracle is an unreviewed prototype | **Primary candidate** |
| CTV, TEMPLATEHASH, APO or CSFS | Yes | Yes | Yes | Yes | No: not active | Best long-term, not buildable now |
| Witness encryption (VweTS) | Same as DLC | Yes | Yes | Same as DLC | Research | Improves multi-oracle efficiency, not liveness |
| Cashu or Fedimint | Yes | No: mint or federation custody | Partly | Yes | Yes | Custodial trust |
| Trusted LP balance (Stablesats style) | Yes | Yes | No | Yes | Yes | Simple, not trustless |

## Design 1: fixed-term DLC

The contract ends well before the coin must renew.

```
Open:      U and L fund a contract coin and adaptor-sign offchain and exit payouts for that exact coin
Maturity:  oracle attests -> either party completes the matching payout -> operator cosigns
Failure:   if the operator is gone, either party exits onchain with the same attestation
Roll:      when U next opens the app, settle and open a new contract
Missed:    position settles to plain BTC at the oracle price; U loses the hedge
```

**The main benefit is a safer failure.** Missing a roll ends the hedge at a fair price, and does not force a channel closure. **Coin expiry remains a hard deadline:** someone must settle or start the exit before the contract coin expires, and the user must refresh or exit the payout coin before it expires. A watchtower is probably needed for a phone that may stay offline.

Limits:

- The dollar value is protected only until maturity. An absent user then holds BTC.
- A term must fit inside one coin lifetime, with margin for settlement and exit.
- The refund locktime must fall before coin expiry.
- Exit data comes from the operator, so it must be saved when the contract opens.
- An exit needs separate BTC for fees. It took 3 transactions in our test, so small balances may not be worth exiting.

## Design 2: Arkade Script vault

A covenant checks a signed oracle price and enforces the payout, and `OP_TUNNEL` lets a keeper renew the coin without its owners. This is the only reviewed design that meets R1 and R5 today, and it ran on regtest (test 3).

The cost is trust. Covenant paths are signed by the operator's server and emulator keys, inside an AWS Nitro enclave. Arkade's docs state that a compromised key could sign a spend the script would refuse, and that paths also requiring the owner's signature stay protected. A renewal path has no owner signature, so **it has no such protection**.

Test 3 confirmed this. Using the emulator key directly, the test paid a whole coin to an attacker, and unmodified arkd cosigned without running the covenant. The same attack failed on a path that also needed an owner signature, but requiring that signature for renewal brings back the liveness problem.

Other limits from the test:

- If the emulator is down, the contract cannot renew or settle.
- The tested renewal script is pinned to one keeper, so a missing keeper stops renewal.
- The contract has no refund path if the oracle never signs.

## Design 3: nostracle quorum rolling DLC

The contract is the Design 1 DLC with extra script paths for 3 of 5 independent nostracles. It keeps a position rolling for an absent user without an owner-free covenant.

```
Open:      U signs a mandate: payout keys, maximum term, absence limit
Challenge: before each roll, nostracles send U a fresh liveness challenge
Answered:  U signs the roll with L and the operator
Missed:    after the timelock, 3 of 5 nostracles sign the roll with L and the operator
Roll:      the quorum and L sign the new coin's payouts, then forfeit the old coin
Failure:   if the operator is gone, the quorum's latest exit payout still works
```

Each coin has 22 script paths: user settle, user exit, and 10 quorum settle and 10 quorum exit paths. arkd refuses a path that combines absolute and relative timelocks, so the quorum exit uses a relative delay longer than the maximum term. The quorum therefore cannot claim the coin before the term ends.

What each party can do:

| Party | Can do | Cannot do |
|---|---|---|
| Operator | Refuse service; sweep an expired coin | Spend a live contract coin |
| LP | Refuse to roll | Take the user's funds alone |
| Up to 2 nostracles | Nothing alone | Sign or block a roll |
| **3 nostracles + LP** | **Take the collateral after the timelock** | |

Limits:

- **The liveness test and mandate are policy.** Bitcoin and arkd enforce only signatures and timelocks, so these protect the user only while a majority of nostracles is honest.
- **The timelock gives no unilateral escape.** The user's paths also need the LP, so a user cannot move the coin away from a colluding quorum and LP.
- **Nostracles must be independent.** One party running three of them defeats the design.
- **Stale-exit protection needs an online operator.** Without one, an old coin could also exit. That loss should fall on the operator's liquidity rather than the user, but this was not tested.
- **Independent 3-of-5 attestations are expensive.** See [Signing cost](#signing-cost). A [threshold oracle](#threshold-oracle) removes that cost, but adds a shared group key.

## The oracle

In Design 1, a DLC oracle holds no key in the contract and cannot see who uses it. In Design 3, nostracles also hold quorum keys and see the contracts they roll. That adds a revenue stream per roll, but removes the oracle's privacy from those contracts. With a [threshold oracle](#threshold-oracle), the group also shares one oracle key. [nostracle](https://github.com/p2pfiat/nostracle) is built for Design 1, but **it has not been connected to a contract yet**. The regtest tests used a throwaway oracle key and two outcomes, and test 4 simulated the five nostracles.

Design 2 needs a different signed message: Arkade's examples verify `sha256(ticker || price || time)` with `OP_CHECKSIGFROMSTACK`. nostracle would need to publish this format too. These signatures would be visible when used, which affects the paid-attestation model.

## Regtest results

| Test | Question | Result | Runs |
|---|---|---|---|
| [1. Offline settlement](../experiments/01-offline-settlement/README.md) (Design 1) | Can L complete a pre-signed payout on arkd while U is offline, including the checkpoint? | **Yes**, while the operator cooperates | 10 of 10 |
| [2. Failure paths](../experiments/02-failure-paths/README.md) (Design 1) | With the operator, LP or oracle gone, can each party recover the correct amount? | **Yes**, if someone acts before expiry and the exit data was saved. After expiry, the operator sweeps the coin and the exit fails | 5 of 5 |
| [3. Covenant lifecycle](../experiments/03-covenant-lifecycle/README.md) (Design 2) | Can a position renew and settle at an oracle price, and what can the operator do alone? | **Lifecycle works with no owner signature**, but the emulator key alone can take the coin | 5 of 5 |
| [4. Nostracle quorum rolling DLC](../experiments/04-guardian-rolling-dlc/README.md) (Design 3) | Can 3 of 5 nostracles roll for an offline user, with no single party able to take the funds? | **Yes**, but 3 nostracles colluding with the LP can take the collateral after the timelock | 5 of 5 |
| [13. Watchtower exit bounty](../experiments/13-watchtower-bounty/README.md) (generic) | Can a keyless watchtower unroll an orphaned contract, pay CPFP fees and profit from a snipe-resistant bounty? | **Yes**: tiered P2TR bounty (`W1` immediate, backups after 4-block CSV) rejected miners and early snipers, netting `+2,800` sats per exit | 5 of 5 |
| [14. End-to-end integration](../experiments/14-end-to-end-integration/README.md) (Design 3 + bounty) | Do the 4-of-7 `strfry` threshold oracle, 20-bit numeric DLC, `arkd` quorum roll and keyless watchtower bounty work together? | **Yes**: 527-prefix `$1,000` positions rolled in 7.5–11.7 s and settled both offchain on `arkd` (`$91,420`) and onchain via keyless watchtower after `arkd` stopped (`$114,800`, `+4,000` sats net profit) | 5 of 5 |
| [15. Live Mutinynet + public Nostr](../experiments/15-mutinynet-watchtower/README.md) (Rust `ark-watchtower`) | Does the standalone Rust watchtower execute a keyless DLC exit over public Nostr relays and live Mutinynet TRUC v3 `/txs/package`? | **Yes**: received NIP-17 package, verified external oracle kind-88/89 (`$97,123`), unrolled 0-fee v3 P2A tx via `/txs/package`, settled DLC payout after CSV(4), and swept tiered bounty for **`+4,000` sats** real onchain profit | 1 of 1 |
| [16. Live Arkade Mutinynet DLC](../experiments/16-mutinynet-arkade-dlc/README.md) (Design 1 on `mutinynet.arkade.sh`) | Does the unmodified public Arkade Mutinynet operator accept a custom Tapscript DLC VTXO and offline adaptor-signed settlement (`arkTx` + `checkpointTx`)? | **Yes** (with time-based `CSV(2048s)` — operator rejects block-based CSV): boarded `10,000` sats, opened `5,000` sat DLC VTXO, wiped user key, settled `3,000`/`2,000` sats offchain via `submitTx` + `finalizeTx` | 1 of 1 |
| [17. Live Arkade Mutinynet Design 3](../experiments/17-mutinynet-quorum-rolling-dlc/README.md) (22-path quorum roll + 20-bit numeric DLC) | Does unmodified `mutinynet.arkade.sh` accept a 22-leaf Design 3 VTXO, let quorum `{0,1,2}` roll via `CLTV` for an offline user, and let quorum `{1,2,4}` settle a 20-bit numeric DLC? | **Yes**: opened 22-leaf `4,500` sat VTXO, wiped user key, rolled via `CLTVMultisigTapscript`, and settled `$91,420` (12-bit binary prefix) offchain (`2,450`/`2,050` sats) | 1 of 1 |
| [18. Live Arkade unilateral exit by `ark-watchtower`](../experiments/18-mutinynet-arkade-unilateral-exit/README.md) (real VTXO tree → Rust watchtower) | Can standalone Rust `ark-watchtower` unroll a real 3-hop `mutinynet.arkade.sh` VTXO tree onchain, wait out real BIP-68 `CSV(2048s)`, broadcast the DLC exit payout, and sweep the tiered bounty? | **Yes**: unrolled `TREE → CHECKPOINT → ARK` in 90s (`1,800` sats CPFP), waited `CSV(2048s)` via Esplora MTP, settled DLC exit onchain, and swept `5,000` sat bounty (`470` sat dynamic fee) for **`+2,730` sats** real profit | 1 of 1 |
| [19. Perpetual terms + failed rolls](../experiments/19-mutinynet-perpetual-and-failed-rolls/README.md) (live `mutinynet.arkade.sh`) | Can a 22-path Design 3 DLC recover from a mid-roll quorum dropout, pay funding at roll, liquidate at ±25% (`$72,000`), and allow collaborative early close? | **Yes**: dropout roll rejected cleanly with VTXO #1 intact; fallback `{0,1,3}` rolled + paid `500` sat funding; `$72,000` liquidation prefix settled `3,100`/`400`; user+LP early close settled `1,900`/`2,100` without oracle or quorum | 1 of 1 |

What the tests changed:

- **Design 1 is feasible on arkd.** U can pre-sign the checkpoint, which was the main open question.
- **The Design 1 exit leaf is user + LP after a delay, with payouts and a refund pre-signed at opening.** Either party can then exit without the other.
- **Design 2 trades custody risk for liveness.** It avoids the phone's liveness problem by trusting the emulator key.
- **Design 3 moves that trust from one operator to a quorum.** It keeps rolling for an offline user, and its exit payouts survive each roll.

What the tests do not show:

- A malicious operator beyond the emulator-key attack, including censorship or collusion with one party.
- A stale exit of a contract settled offchain. Test 4 covers a stale exit of a rolled coin with the operator online.
- Recovery of a swept coin, or a working watchtower.
- A numeric DLC settled through a live arkd server, real nostracle attestations, Nitro enclave protections, real fee conditions, reorgs or public-network behavior.
- Public nostr relays, independently operated nostracles, a batch that fails during a roll, funding payments or liquidation.
- Combining the full anti-bias DKG, locked slots and disk journal of experiments 10–12 into the live `arkd` integration (experiment 14 used Feldman VSS DKG).

## Signing cost

[Experiment 5](../experiments/05-numeric-signing-cost/README.md) measured a numeric 3-of-5 roll, using nostracle's 20-digit event shape with a reimplemented oracle. The position is $1,000 with 2,000,000 sats of collateral, payouts rounded to $1, a ±25% price band, a $256 tolerance, and pre-signed exit payouts only.

| Per position, per roll | Single oracle | Independent 3-of-5 |
|---|---|---|
| Adaptor signatures per signer | 3,496 | 140,140 |
| Stored for all 4 signers | 0.9 MB | 35.3 MB |
| Time to sign, 8 cores | Under 1 s, estimated | 3.7 to 5.9 s |
| Time to verify 3 other signers, 8 cores | Not run | About 53 to 76 s, extrapolated |

The 40-times increase comes from the 10 possible oracle groups and about 4 digit combinations per group, needed because independent oracles will not report the identical price.

- **One position can roll daily.** An 8-core signer could handle roughly 1,000 to 1,500 positions per day, so this does not scale to a product.
- **Contract terms reduce the cost, but do not fix it.** A ±10% band needs 13.6 MB. Rounding to $10 at ±25%, with up to $5 of error, needs 5.9 MB.
- **A phone should not verify a full roll.** It should fetch only the signatures it needs at settlement. This is not built, and no phone was measured.
- **The first oracle in a group has limited price power.** It can move the settlement price by up to about twice the tolerance, about 0.5% at $256.
- **A threshold oracle removes the multiplier.** See [Threshold oracle](#threshold-oracle).

## Threshold oracle

[Experiment 6](../experiments/06-threshold-oracle/README.md) built a research prototype in which nostracles generate a shared key and per-digit nonces, agree on one price, and produce one normal BIP340 signature per digit. The contract sees a single oracle. All members ran in one process, without nostr transport or a cryptographic review.

| Per position, per roll | Independent 3-of-5 | Threshold 3-of-5 |
|---|---|---|
| Adaptor signatures per signer | 140,140 | 3,496 |
| Stored for all 4 signers | 35.3 MB | 0.9 MB |
| Sign and verify 3 other signers, 8 cores | About 56 to 82 s | About 2 to 5 s |
| Positions per day, per 8-core signer | About 1,000 to 1,500 | About 19,000 to 40,000 |

**The simple protocol is unsafe.** Signing two prices with one nonce reveals the key. If a network split makes two honest members choose different prices, 2 malicious members can combine with each and produce both attestations. Test 6 demonstrated this key leak.

**A price certificate prevents it.** Each member votes once and signs only with enough votes for one price:

| Members | Votes needed | Safe from a split with 2 malicious | Still attests if those 2 stop |
|---|---|---|---|
| 5 | 3 | No | Yes |
| 5 | 4 | Yes | No |
| 7 | 4 | No | Yes |
| **7** | **5** | **Yes** | **Yes** |

Experiment 6 tested the certificate with 5 members. The 7-member rows are arithmetic over a single vote quorum. Experiment 7 ran 7 simulated members with two quorums.

### 4-of-7 two-speed oracle

[Experiment 7](../experiments/07-two-speed-oracle/README.md) tested whether 4 of 7 members can keep attesting with 3 offline, without the key-leak risk of a plain 4-vote quorum. All 11 scenarios passed in 5 of 5 runs. Key generation, attestations and contract signatures used real cryptography. **The network and voting were a simulation with authenticated messages**, with no nostr transport.

- **Fast path:** with 5 matching votes, a member signs immediately, about 31 seconds after the event.
- **Slow path:** after 600 seconds, a member with 4 matching votes waits a further 60 seconds and signs only if those votes are still valid.
- **Per-event keys:** each event gets its own key and digit nonces, certified by the long-term group key.

| Each oracle offline | Fast path | Slow path | No attestation |
|---|---|---|---|
| 1% | 99.997% | 0.003% | 0.000% |
| 5% | 99.624% | 0.356% | 0.019% |
| 10% | 97.431% | 2.296% | 0.273% |
| 20% | 85.197% | 11.469% | 3.334% |
| 30% | 64.707% | 22.689% | 12.604% |

These figures assume independent failures. A shared hosting, relay or price feed outage would make them worse.

The grace period exists because testing broke the first version: 1 malicious member double-voted one second before the timeout and leaked the event key, even after the split had healed.

| Malicious members | Split heals before signing | Split outlasts the slow path |
|---|---|---|
| 0 | 0 leaks | 0 leaks |
| 1 or 2 | 0 leaks | **Leak possible** |
| 3 | **Leak possible** | **Leak possible** |

The healed-split result covers 43,008 scripted attack runs with 0 to 2 malicious members, of which 18,432 had 1 or 2, plus 20,000 randomized attacks per test run. This is a broad search, not a proof.

The contract still sees one oracle, so the roll cost stays at 3,496 adaptor signatures per signer. Event setup took 0.5 to 1.7 seconds in one process and sent 8.4 KB per member.

### Over nostr relays

[Experiment 8](../experiments/08-nostr-oracle/README.md) ran the same protocol with 7 separate processes that communicated only through signed nostr events on 3 strfry relays. Key shares were NIP-44 encrypted, and an outside client verified each attestation from the relays. All 17 scenarios passed in 5 of 5 runs, and the production timers passed in 1 run. **Everything ran on one machine**, and nothing was published to public relays.

| Scenario | Result |
|---|---|
| All 7 online, production timers | Attested after 30.2 s |
| 3 offline, production timers | Attested after 660.2 s |
| 4 offline | No attestation |
| 1 or 2 of 3 relays killed | Fast path |
| All 3 relays down across the vote deadline | Attested about 1 s after they returned |
| Bad key share or conflicting key deal | Setup aborts and names the dealer |
| Last-second double vote, split heals in time | No honest member signed, no leak |
| **Split outlasts the slow path, 1 malicious member** | **Event key recovered** |

Other scenarios used shortened timers. The test also showed that:

- **Members must publish concurrently.** Waiting for each relay's reply made reports miss the vote deadline under latency.
- **The nostr client needs an update.** go-nostr v0.40.1 cannot use WebSocket compression under Go 1.27, so compression was off in this test.
- **Key setup needed all 7 members online in this experiment.** One member could stop it with a bad share. [Experiment 9](#fault-tolerant-event-setup) removes this limit for event keys.
- **Relays can see prices, votes and timing.** Only key shares are encrypted.

### Fault-tolerant event setup

[Experiment 9](../experiments/09-fault-tolerant-setup/README.md) changed event setup so that it no longer needs all 7 members. Members deal key shares, publicly resolve complaints, and vote on a leader's proposed set of at least 4 dealers. **5 matching votes finalize the set.** Members that missed setup catch up from the relays. All 17 checks passed in 5 of 5 runs, on one machine with 3 local strfry relays and shortened setup timers.

| Each oracle offline | All 7 needed | At least 5 needed | 3 independent attempts |
|---|---|---|---|
| 1% | 93.2% | 99.997% | Over 99.9999% |
| 5% | 69.8% | 99.624% | Over 99.9999% |
| 10% | 47.8% | 97.431% | 99.998% |
| 20% | 21.0% | 85.197% | 99.676% |
| 30% | 8.2% | 64.707% | 95.604% |

These figures are calculated and assume independent failures. Real outages are often shared and can outlast several attempts, so events should be prepared in advance.

| Scenario | Result |
|---|---|
| 2 offline during setup | Certified with 5 dealers, attested |
| 3 offline during setup | 4 members voted, nothing certified |
| 2 members miss setup, then help sign with only 4 online | Attested on the slow path |
| Bad, missing or conflicting deal | Dealer excluded |
| False complaints against every dealer | All answered, none excluded |
| Leader stays silent | Attempt fails, next leader succeeds |
| **Split with a two-faced leader** | **Each side reached 4 votes for a different key set, neither certified** |
| 3 members down with 2 events prepared | New setup fails, both prepared events attest |

Setup deliberately has no 4-vote path. In the split test, a 4-vote rule would have created two valid key sets. Setup can wait, unlike attestation.

The test also left these limits open:

- **A malicious leader or dealer can bias the key,** although it cannot learn it. [Experiment 10](#stronger-key-generation) addresses this.
- **A bad share sent to an offline member goes unnoticed until it returns.** That member then cannot sign that event, because share recovery is not built.
- **3 malicious members can break certification** and could produce two valid key sets for one attempt.
- **Retries, leader rotation and the event buffer were driven by the test.** They are not built as a service.
- **The long-term key setup was only run with all 7 members honest.**

### Stronger key generation

[Experiment 10](../experiments/10-stronger-key-generation/README.md) replaced the event key generation with the two-phase design of Gennaro, Jarecki, Krawczyk and Rabin, plus a voting rule for nostr. Dealers first publish hiding commitments, and 5 members certify the dealer set. Only then do dealers reveal their public key parts. A dealer that withholds or lies is opened from its shares, so its original contribution stays in the key. All 26 checks passed in 5 of 5 runs, on one machine with 3 local strfry relays and shortened setup timers.

Opening is guarded: members publish shares only for the exact dealers that 5 members voted to open, and at least 3 dealers must stay unopened. Without this rule, a relay outage could make members publish enough shares to expose the key.

| Scenario | Result |
|---|---|
| Leader with 2 dealers tries to force one key bit (simulated) | 93.3% to 94.1% with visible key parts, 49.0% to 51.2% with hidden parts |
| Dealer withholds, changes or duplicates its reveal | Opened, original contribution kept |
| 2 dealers withhold together | Both opened, key unchanged |
| False evidence or 2 false open votes | No honest dealer opened |
| All relays down during reveal | No shares published, next attempt succeeds |
| Opening would leave fewer than 3 dealers secret | Honest members refuse |
| 2 members abort after seeing the key, all 7 online | Key still created |
| **1 member aborts after seeing the key, 5 online** | **Attempt fails, so the attacker can reject that key** |

The test also left these limits open:

- **Restart bias remained in this experiment.** With no spare voter online, a malicious member could reject keys by forcing new attempts. [Experiment 11](#locked-event-slots) addresses this.
- **3 malicious members break the guarantees** and could learn the key.
- **A slow honest dealer can be excluded or opened.** Exclusion happened in early test runs when a harness fault overloaded the relays after a split. Opening one dealer does not expose the key while an unopened dealer is honest.
- **Setup can stall** if too few members publish shares for an opened dealer.

### Locked event slots

[Experiment 11](../experiments/11-restart-bias/README.md) stopped a member from rejecting a key by forcing a restart. All 13 checks passed in 5 of 5 runs, on one machine with 3 local strfry relays and shortened setup timers. It adds three rules:

- **At least 5 dealers** must be certified, up from 4.
- **A certified slot is locked.** Members holding the 5-vote certificate refuse to restart it. A blocked slot resumes when another member returns and finishes with the same key.
- **A restart needs 5 signed abandon messages** for that slot and attempt. This is only possible before the key can be known.

To know the key, an attacker needs the reveal of every honest certified dealer. With 5 dealers and at most 2 attackers, at least 3 honest members have locked, which leaves only 4 possible abandon signers. An exhaustive count of 1,856 attacker and dealer combinations found 210 restart paths with 4 dealers and none with 5 or more.

| Scenario | Result |
|---|---|
| 1 or 2 members abort after seeing the key | No restart, then finished with the same key when members returned |
| Attacker blocks and no fifth voter returns | Slot stays unfinished, and no replacement key exists |
| Silent leader, or split with a two-faced leader | Nothing revealed, restarted, attested |
| Leader proposes only 4 dealers | Refused, restarted, attested |
| 1 bad dealer with only 5 members online | Attempt fails, retry with a sixth member succeeds |
| Abandon messages from another slot | Do not count |
| Another slot is blocked | A prepared event still attests |

The test also left these limits open:

- **An attacker can still block a slot.** The product must not replace a blocked slot with a new key, or the bias returns. Each event date needs a fixed slot and a defined fallback, such as the fixed-term DLC. Neither is built.
- **The lock was held in memory.** A crashed member could forget it and sign a restart. [Experiment 12](#crash-recovery) stores it on disk.
- **3 malicious members break the guarantees.**
- **The 5-dealer minimum costs availability.** With 5 members online, one bad dealer fails the attempt until a sixth good member is available.

### Crash recovery

[Experiment 12](../experiments/12-crash-recovery/README.md) tested whether a member that crashes, restarts or loses its disk can break the oracle's promises. All 27 checks passed in 5 of 5 runs, on one machine with 3 local strfry relays and shortened setup timers. A guard between each member's protocol logic and the relays adds these rules:

- **Journal before release.** Every outgoing message is signed, written to a checksummed journal and flushed to disk before any relay sees it. A restart republishes the same message.
- **One value per protocol step.** A restarted member that computes a different deal, vote or price for a step it already published is blocked. A signature share must match the member's stored price vote.
- **The lock reaches the disk first,** before a member reveals or votes to open dealers.
- **Signing a restart gives up the attempt.** A member that signed an abandon message can no longer vote or reveal in that attempt. Experiment 11's rule allowed this.
- **Lost disks show up on the relays.** A restarted member that finds its own unknown messages stops publishing for that event. Before signing a restart, it reads the attempt from the relays and refuses if it finds its own messages or a 5-vote certificate.

Members were killed with SIGKILL before the journal write, after it and after sending, at each setup and attestation message. Before the final test, a stepwise series checked each layer apart, with a fresh cluster per trial and a relay scan for conflicting messages after every trial:

| Step | Trials | Result |
|---|---|---|
| Guard and journal, no kills | 20 | 20 ok |
| Each of the 18 kill points, 10 times | 180 | 180 ok |
| Each recovery scenario, 10 times | 60 | 60 ok |
| Seeded random kills: any member, any of its messages | 100 | 79 kills ok, 21 never reached a kill |

No trial found a member publishing two values for one step. In the control, 4 members that lost their disks formed a restart certificate when they did not check the relays. With the check, all 4 refused.

The first test batches failed on the test machine, not in the protocol: WSL stopped responding twice, a crash-looping arkd regtest stack loaded the CPU, and the PC went to sleep during a run. With those removed, no step failed.

The test also left these limits open:

- **SIGKILL is not power loss.** Writes lost in a disk or file-system cache are not tested.
- **Secrets are stored in plain text** in a 0600 journal. A production member needs encryption at rest or a hardware key.
- **The disk-loss check trusts the relays to show history.** If every relay a member reads hides its earlier messages, it could still sign a restart.
- **Quarantine costs availability.** A member whose disk was rolled back stops publishing for that event.
- **A late reveal costs an open vote.** A member that has not seen every reveal by the open-vote deadline skips its open vote and does not retry. With only 5 members online, this can stall the slot.

### What remains trusted

- **4 colluding members control a 4-of-7 oracle.** They can attest any price.
- **3 malicious members can leak an event key,** even after a short split. With a split past about 660 seconds, 1 is enough.
- **A leaked event key exposes every contract settling on that event,** because the attacker can forge any price for it. The long-term key and other events stayed safe in the test. Staggering contracts across events would limit this, but is not built.
- **Members must keep vote and nonce state.** Losing it could cause a double vote or nonce reuse. Crash recovery and key rotation are not built.

## Next steps

Before building a product on Design 3:

1. **Harden the 4-of-7 oracle:** independently run members on public relays, fixed date slots with a fallback for blocked slots, encrypted member storage and power-loss tests, an open-vote retry, share recovery, automatic setup retries with an event buffer, long-split protection, staggered events, member replacement and key rotation.
2. **Connect real nostracles:** liveness challenges, mandates and attestations over nostr.
3. **Test failed rolls:** a batch failure or a nostracle dropping out during signing.
4. **Add perpetual terms:** funding payments, closing at any time, and liquidation.
5. **Test adversarial cases:** operator censorship, collusion and stale exits without an operator.
6. **Harden watchtower fee handling:** Experiment 13 proved the tiered onchain bounty on regtest; dynamic mempool fee estimation, RBF and extreme fee-spike handling remain to be built.
7. **Get a cryptographic review** of the threshold oracle and contract.
8. **Repeat the lifecycle on a test network.**

Questions for the teams:

- **Second:** feedback received — they are catching up on script support and want to make on-chain contract exits solid; follow up with the minimum bark requirements above (`VtxoPolicy` + hard exit tooling for pre-signed spends).
- **Ark Labs:** what is the mainnet status of the emulator, the public batch expiry, and the plan for `StabilityVault`?

| Milestone | Deliverable | Depends on |
|---|---|---|
| M1 | nostracle oracle | Built (`p2pfiat/nostracle`); not yet deployed 24/7 |
| M2 | Regtest tests 1–14, then choose a design | **Done** — Design 3 with threshold oracle + watchtower bounty |
| M3 | Chosen contract on a test network (Mutinynet) | **Done** — Experiments 15–19 + standalone Rust `watchtower/` verified live on `mutinynet.arkade.sh` |
| M4 | LP service + User CLI (`mvp/`): quotes, atomic 2-party funding, early close | **MVP Done** — verified live on `mutinynet.arkade.sh` (`mvp/test/e2e.mjs`); hedging & quorum rolls next |
| M5 | Mobile wallet with a stable balance | M4 |

## Scope of this audit

**Read in full:** Second's protocol pages on VTXOs, lifetime, forfeits, rounds, exits and payments. Arkade's pages on trust, renewal, transactions, settlement, oracle overview, signed messages, vault overview, exit, options, escrow and network resources. The stability design and vault source. Delegation and renewal code in the SDK and bark.

**Keyword-searched, not read line by line:** the remaining Second pages (83 total) and Arkade pages (74 total).

**Run:** the four regtest experiments listed under [Regtest results](#regtest-results), the measurement under [Signing cost](#signing-cost), and the seven prototypes under [Threshold oracle](#threshold-oracle).

**Not done:** a formal security review, running a contract on a public network, or an exhaustive literature review. The 10101 failure reason comes from the project's history and was not independently researched.

## Sources

- [Second docs](https://gitlab.com/ark-bitcoin/docs): `learn/vtxo`, `learn/lifetime`, `learn/forfeits`, `learn/rounds`, `learn/exit`
- bark source: `lib/src/vtxo/policy/mod.rs`, `bark/src/round/mod.rs`, `server/src/config.rs`
- [Arkade security and trust model](https://docs.arkadeos.com/learn/concepts/security-and-trust-model), [emulator](https://docs.arkadeos.com/learn/concepts/emulator), [expiry and renewal](https://docs.arkadeos.com/learn/concepts/expiry-and-renewal), [vault exit](https://docs.arkadeos.com/vaults/exit), [options](https://docs.arkadeos.com/vaults/reference/options)
- [Arkade emulator](https://github.com/arkade-os/emulator), [`StabilityVault`](https://github.com/arkade-os/compiler/tree/master/examples/stability), [ts-sdk](https://github.com/arkade-os/ts-sdk)
- [DLC factories](https://conduition.io/scriptless/dlc-factory/), [ticketed DLCs](https://conduition.io/scriptless/ticketed-dlc/)
- [CTV and DLCs](https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2022-January/019808.html), [modern oracle designs survey](https://arxiv.org/pdf/2602.09822)
