# Pay-on-Dispute Oracle Incentive Model (`nostracle` + `ark-watchtower`)

How blind DLC price oracles (`nostracle`) get sustainably paid **only when long and short disagree** (or a counterparty disappears), while keeping normal collaborative trading at **0 sats oracle overhead**.

---

## 1. Happy Path vs. Dispute Path

| Scenario | Frequency | Oracle Cost | Settlement Mechanism |
| :--- | :--- | :--- | :--- |
| **Collaborative Close / Rollover** | ~99% | **0 sats** | User + LP co-sign offchain Arkade tx (HTTP or NIP-17) at live spot. Oracles are never queried or paid. |
| **Dispute / Unilateral Exit** | ~1% | **`M × zap_sats`** (paid from Watchtower bounty) | `ark-watchtower` unrolls VTXO onchain, zaps `M`-of-`N` paid Nostracles (`kind: 9734` → Lightning → `kind: 9735`), receives private `kind: 89` attestations via NIP-17 Gift Wrap, decrypts the adaptor exit tx, and sweeps its tiered Taproot bounty. |

---

## 2. Why Blindness Prevents Extortion

- Each `nostracle` publishes its `kind: 88` **announcement** (pre-committed Schnorr nonces $R_i$) publicly in advance, with **zero knowledge** of which contracts reference it or how much BTC is locked.
- Under `[pricing]` in `nostracle`, the `kind: 89` **attestation** is kept private and sold via flat-rate NIP-57 Lightning Zaps (e.g. `attestation_sats = 100–500 sats`).
- Because the oracle is blind to contract size and counterparty identities, it cannot extort a percentage of locked funds or collude with one side.

---

## 3. Watchtower Profitability Invariant

A rational keyless watchtower only pays oracle zap fees and onchain CPFP/sweep fees when:

$$\text{bounty\_sats} \ge \text{onchain\_fee\_sats} + (M \times \text{oracle\_zap\_sats}) + \text{min\_profit\_sats}$$

Implemented directly in `ark_watchtower::nostr_io::estimate_dispute_economics(...)`:
- Example with 2-of-3 quorum (`M = 2`), `oracle_zap_sats = 250 sats`, `onchain_fee_sats = 1,200 sats`, `bounty_sats = 4,000 sats`:
  - Total watchtower cost = `1,200 + 500 = 1,700 sats`
  - Watchtower net profit = **`+2,300 sats`**
  - Each Nostracle in the quorum earns **`+250 sats`** instantly via Lightning Zap
  - User & LP paid **0 sats** on every happy-path trade and still get guaranteed trustless settlement on disputes.

---

## 4. Wire Flow (`ark-watchtower` ↔ `nostracle`)

1. `nostracle` publishes `kind: 88` announcement (public) and `kind: 0` profile with `lud16` + `kind: 10002` relay list.
2. On unilateral exit, `ark-watchtower` checks `fetch_external_attestations`:
   - If the oracle published a public `kind: 89` attestation, it is used directly.
   - If not public, the watchtower builds a NIP-57 `Kind::ZapRequest` (`build_attestation_zap_request`) targeting `(oracle_pk, announcement_id)` and pays the LUD-16 invoice.
3. `nostracle` verifies the `kind: 9735` zap receipt and delivers `OracleBuyerMessage::Attestation` containing the signed `kind: 89` event inside a **NIP-17 Gift Wrap (`kind: 1059`)** addressed to the watchtower's pubkey.
4. `ark-watchtower` unwraps the NIP-17 Gift Wrap in `fetch_external_attestations`, verifies `gift.sender == oracle_pk` and `att_ev.pubkey == oracle_pk`, cryptographically validates the `kind: 89` Schnorr signatures against the `kind: 88` announcement (`verify_attestation`), and completes the adaptor-signature exit.

---

## 5. Security Rule: Preventing Lowball / Bait-and-Switch Sybil Attacks

An adversarial operator could spin up multiple Nostracles advertising `fee_sats = 1` to get selected into quorums, then coordinate an attack (price manipulation or ransom) once large contracts depend on them.

Therefore, **quorum selection** and **dispute fee competition** MUST remain strictly separated:
1. **Quorum Selection (at contract opening):** NEVER rank or admit oracles by lowest `fee_sats`. Select the `N` oracle identities strictly by **reputation, track-record age, historical accuracy, and operator independence** (`fee_sats` may only act as a sanity cap).
2. **Dispute Execution (inside an already-trusted quorum):** Once the trusted `M`-of-`N` set is fixed, the watchtower uses `select_cheapest_quorum(...)` to zap the cheapest `M` distinct oracles. Any oracle that breaks its signed `fee_sats` commitment on `kind: 88` leaves cryptographic proof of bait-and-switch and is slashed in future reputation scores.
