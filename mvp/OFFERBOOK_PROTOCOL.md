# p2pFiat Nostr Offer Book Protocol (v1)

An open, permissionless, cryptographically verifiable P2P Offer Book over **Nostr** (`kind: 38384`).
Any self-custodial wallet or institutional Liquidity Provider (LP) can publish signed quotes; any wallet can subscribe to Nostr relays, verify every quote locally, build its own orderbook, and route trades to the best LP — with zero central coordinator.

---

## 1. Event Kind & Replaceability

- **Nostr Kind:** `38384` (NIP-33 Parameterized Replaceable Event, ephemeral/short-lived via NIP-40 `expiration`).
- Because `kind: 38384` is parameterized-replaceable on `(pubkey, kind, d-tag)`, a relay only stores the **latest** quote per LP + pair + rail, preventing unbounded historical quote spam.
- Relays SHOULD drop events whose NIP-40 `expiration` timestamp has passed; clients MUST reject expired events regardless of relay behavior.

---

## 2. Required Tags

```json
[
  ["d", "p2pfiat:v1:BTC-USD:arkade-mutinynet"],
  ["t", "p2pfiat-offer"],
  ["pair", "BTC-USD"],
  ["rail", "arkade-mutinynet"],
  ["side", "lp-long"],
  ["expiration", "1764028920"]
]
```

| Tag | Purpose |
| :--- | :--- |
| `d` | NIP-33 replaceable key (`p2pfiat:v1:<PAIR>:<RAIL>`) so each LP maintains one active offer slot per pair/rail. |
| `t` | Topic filter (`p2pfiat-offer` by default; test suites may append/use isolated tags). |
| `pair` | Quoted asset pair (`BTC-USD`). |
| `rail` | Settlement rail (`arkade-mutinynet`, `arkade-mainnet`, etc.). |
| `side` | LP contract role (`lp-long` = LP matches user USD-peg hedge / takes BTC upside+downside). |
| `expiration` | Unix timestamp (seconds) after which the quote MUST be ignored (typically `created_at + 120`). |

---

## 3. Content Schema (JSON)

`event.content` is a JSON-encoded object:

```json
{
  "version": "p2pfiat-offer/v1",
  "lpName": "Alpha-LP",
  "lpPubkey": "<64-char-xonly-hex>",
  "pair": "BTC-USD",
  "rail": "arkade-mutinynet",
  "spotUsd": 96500,
  "bidUsd": 96403,
  "askUsd": 96597,
  "spreadBps": 10,
  "fundingRateBpsPerDay": 10,
  "minNotionalUsd": 1,
  "maxNotionalUsd": 50,
  "availableLiquiditySats": 48000,
  "termSecs": 86400,
  "endpointUrl": "http://127.0.0.1:3456",
  "oracleMode": "spot-median-v1",
  "proofMode": "arkade-default-vtxo",
  "updatedAt": 1764028800
}
```

### Field Notes
- `lpPubkey` **MUST** match `event.pubkey` (64-char lowercase x-only secp256k1 hex). Prevents an LP from impersonating another pubkey inside the JSON payload.
- `spotUsd`: LP's current reference BTC/USD spot price.
- `bidUsd` / `askUsd`: implied two-way quote around `spotUsd` given `spreadBps` (`bid = round(spot * (1 - spreadBps / 10000))`, `ask = round(spot * (1 + spreadBps / 10000))`).
- `spreadBps`: execution spread charged by the LP (non-negative bps).
- `fundingRateBpsPerDay`: **signed** daily interest rate from the USD-stable user's perspective (`> 0` = user **earns** yield in contango/bull markets, e.g. `+3 bps/day ≈ +10.95% APR`; `< 0` = user pays funding in backwardation).
- `endpointUrl`: Optional HTTP/HTTPS negotiation endpoint (`POST /quote`, `POST /open/propose`, `POST /open/finalize`, `POST /close/propose`, `POST /close/finalize`). May be empty (`""`) for serverless P2P LPs.
- `transports`: Array of supported negotiation transports, e.g. `["http", "nostr-nip17"]` or `["nostr-nip17"]` (serverless P2P over Nostr Gift-Wrapped DMs).

### NIP-17 Encrypted P2P Negotiation (`transport: "nostr-nip17"`)
When an LP has no public HTTP server (or the wallet prefers private P2P transport), all trade RPC calls (`health`, `quote`, `open/propose`, `open/finalize`, `roll/propose`, `roll/finalize`, `close/propose`, `close/finalize`) are sent as JSON inside a **NIP-17 / NIP-59 Gift Wrap** (`kind: 14` rumor → `kind: 13` seal → `kind: 1059` ephemeral gift wrap, NIP-44 v2 ChaCha20 + HMAC-SHA256):
- Request: `{ "type": "p2pfiat-rpc-req", "reqId": "r-...", "method": "quote", "params": { "notionalUsd": 5 } }`
- Response: `{ "type": "p2pfiat-rpc-res", "reqId": "r-...", "ok": true, "result": { ... } }`

### Atomic Rollover Primitive (`roll/propose` + `roll/finalize`)
Extends an active DLC position in a **single atomic Arkade transaction** (zero gap in price hedge, zero L1 fees):
1. `roll/propose { positionId, termSecs?, watchtowerPubHex?, overrideSpotUsd? }` settles accrued interest + mark-to-market at live spot, spends the old DLC VTXO (`settleLeaf`) directly into a fresh DLC VTXO re-centered at `rollSpotUsd` (returning any surplus above dust to User/LP Arkade addresses), and attaches a freshly adaptor-signed `exitSuite`.
2. User verifies output 0 + surplus outputs, co-signs the Arkade rollover tx + checkpoint + fresh `exitSuite`, and calls `roll/finalize { positionId, signedArkTxB64, signedCkB64 }`.

---

## 4. Client Verification & Local Ranking

Before admitting an event into its `LocalOrderBook`, every client **MUST** verify:
1. `event.kind === 38384` and `typeof event.content === "string"`.
2. Canonical NIP-01 `id === sha256(utf8(JSON.stringify([0, pubkey, created_at, kind, tags, content])))`.
3. Valid BIP-340 Schnorr signature (`schnorr.verify(sig, id, pubkey)`).
4. Valid NIP-40 `["expiration", "<ts>"]` tag with `Number(ts) > nowSecs`.
5. `content.lpPubkey === event.pubkey` and finite positive `spotUsd`, `availableLiquiditySats`, non-negative `spreadBps`, `fundingRateBpsPerDay`.
6. Monotonicity: if an offer for `event.pubkey` already exists, ignore events with `created_at <= existing.createdAt`.

### Best-Offer Selection
For a requested `notionalUsd`:
1. Filter active verified offers where `minNotionalUsd <= notionalUsd <= maxNotionalUsd` and `availableLiquiditySats >= requiredLpSats`.
2. Rank ascending by total cost score: `spreadBps + fundingRateBpsPerDay` (tie-breaker: higher `availableLiquiditySats`, then newer `createdAt`).

---

## 5. Arkade VTXO Proof-of-Funds (v1.1)

Because `event.sig` is a BIP-340 Schnorr signature by `event.pubkey === content.lpPubkey`, every offer already proves live control of the LP's secp256k1 key.

Under `proofMode: "arkade-default-vtxo"` (default for Arkade rails), any client can cryptographically verify the LP's real spendable liquidity with **zero trust in the LP's self-reported number**:

1. Deterministically derive the LP's standard Arkade VTXO script:
   `DefaultVtxo.Script(event.pubkey, arkServerXOnlyPubkey, unilateralExitDelay)`
2. Query the Arkade Indexer:
   `getVtxos({ scripts: [hex(pkScript)], spendableOnly: true })`
3. Compute:
   - `verifiedLiquiditySats = sum(v.value)` (total spendable VTXOs)
   - `maxVtxoSats = max(v.value)` (largest single spendable VTXO available for atomic 2-input funding)

### PoF-Aware Ranking
When selecting the best LP for a requested `notionalUsd` (`requiredSats`):
1. Verified LPs with `maxVtxoSats >= requiredSats` always rank above unfunded or unverified LPs.
2. Within the same fundability tier, rank ascending by `spreadBps + fundingRateBpsPerDay`, tie-breaking by higher `verifiedLiquiditySats`.

---

## 6. Orderbook as a Sybil-Resistant Price Oracle Input

Every verified offer in `LocalOrderBook` is cryptographically bound to real spendable Arkade VTXO collateral (`verifiedLiquiditySats`).
Computing the **liquidity-weighted median** mid-price across all PoF-verified funded LPs:

```text
midUsd_i = (bidUsd_i + askUsd_i) / 2   (or spotUsd_i)
weight_i = verifiedLiquiditySats_i     (0 for unfunded / Sybil LPs)
orderbookMedianUsd = weightedMedian({ midUsd_i, weight_i })
```

Unfunded Sybil LPs posting fake `0 bps` spreads or manipulated prices receive **`weight = 0`** — they can neither hijack rank #1 nor distort `orderbookMedianUsd`. This makes the live orderbook a credible, Sybil-resistant price feed input for threshold DLC oracles (`nostracle`).
