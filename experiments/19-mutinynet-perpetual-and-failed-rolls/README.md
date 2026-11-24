# Experiment 19: perpetual DLC terms and failed roll recovery on live Arkade Mutinynet

**Question:** on the unmodified public Arkade Mutinynet operator (`https://mutinynet.arkade.sh`), can a 22-path Design 3 DLC recover cleanly when a quorum member drops out mid-roll, settle a funding/carry payment during the fallback roll, liquidate automatically at the ±25% band floor, and allow a collaborative early close when the user comes back online?

**Result: yes.** All 4 scenarios passed on the first run on live `https://mutinynet.arkade.sh`, with exact satoshi-level balances verified on the live indexer (`User = 5,500` sats, `LP = 2,500` sats).

## Live Mutinynet & Arkade transactions

| Scenario | Transaction / ID | Result |
|---|---|---|
| Setup boarding + batch | [`7c0c017d...794a`](https://mutinynet.com/tx/7c0c017d0c9361376bc2924e74b7d1a3ba3a2c64ccd9bf53d81774947989794a) → [`9ff0bb52...9ebf`](https://mutinynet.com/tx/9ff0bb52163cfceaf41d990faffe8db54ff2ee4e079bb3cc2f493564145e9ebf) | `10,000` settled sats boarded into live Arkade Mutinynet |
| **A. Failed roll (`N2` drops out)** | VTXO #1 `13539239...7879:0` (`4,000` sats) | Incomplete quorum `{N0, N1}` + LP rejected by `mutinynet.arkade.sh` (`INVALID_SIGNATURE (18): missing 1 signatures`); VTXO #1 remained intact and spendable |
| **B. Fallback roll + funding payment** | `2a7a8aeba14cb76a0330545da75e20f707cc1c18c1426b7fab6b61259397bd3b` | Fallback quorum `{N0, N1, N3}` + LP rolled VTXO #1 → VTXO #2 (`3,500` sats, `:0`) + **`500`-sat funding payment** directly to User (`:1`) |
| **C. Automatic ±25% liquidation (`$72,000`)** | `bf7fa5e24eb8ba0cbc85d6c4a0f64116124580eb9b1ae533729b4748f43eab4c` | 7-bit liquidation prefix `0001000` (`[$65,536..$73,727]`) settled rolled VTXO #2 offchain: **User `3,100` sats**, **LP `400` sats** |
| **D. Collaborative early close** | VTXO #3 `9ef3a89a...3699:0` → `718aaecc761523123ef78f5f64a8c9153aa1f164519fec529e8173a9707a3c0d` | User + LP closed immediately via 3-of-3 user settle leaf (no oracle, no quorum, no waiting for maturity): **User `1,900` sats**, **LP `2,100` sats** |

**Final verified live indexer balances:**
- **User:** `500` (funding) + `3,100` (liquidation) + `1,900` (early close) = **`5,500` sats**
- **LP:** `400` (liquidation) + `2,100` (early close) = **`2,500` sats**

## Run it

```sh
cd experiments/19-mutinynet-perpetual-and-failed-rolls
npm install
node run.mjs
```
