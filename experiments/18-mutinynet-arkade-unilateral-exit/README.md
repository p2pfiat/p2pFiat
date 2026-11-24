# Experiment 18: live unilateral exit of a real Arkade Mutinynet DLC VTXO by `ark-watchtower`

**Question:** can our standalone Rust [`ark-watchtower`](../../watchtower/README.md) take a keyless exit package exported from a **live `https://mutinynet.arkade.sh` DLC VTXO**, unroll the entire 3-hop Arkade virtual transaction tree (`TREE → CHECKPOINT → ARK`) on live Mutinynet via TRUC v3 CPFP + 0-sat P2A anchors, wait out the operator's real BIP-68 time-based `CSV(2048s)` (~34 minutes), broadcast the finalized DLC exit payout, and sweep the tiered Taproot bounty at a real onchain profit — with zero user or LP private keys?

**Result: yes.** Every single transaction confirmed cleanly on live Mutinynet with zero errors or rejections, netting **`+2,730` sats** real onchain profit (`5,000` bounty − `1,800` CPFP − `470` dynamic sweep fee).

## Live Mutinynet & Arkade transactions

| Stage | Transaction | Details |
|---|---|---|
| Boarding L1 tx | [`687633d4...6c74`](https://mutinynet.com/tx/687633d4788874eea984b68fd9f61d66e1153af48c5cb68d5d335b7453276c74) | `10,000` sats boarded from `W1` to an ephemeral funder (block `3,618,332`) |
| Arkade batch commitment tx | [`35d84efc...67d5`](https://mutinynet.com/tx/35d84efc701cdcdd3358728c43f002965a4afe535eef126b09984cbf290867d5) | Live 60s Arkade batch round confirmed on L1 (block `3,618,333`) |
| Unroll hop 1/3 (`TREE`) | [`4eb1c1aa...76f9`](https://mutinynet.com/tx/4eb1c1aaffdf5d3f15697b0445d89977184384fb480609f30dc4ac4334d176f9) + CPFP [`e2597a10...dc99`](https://mutinynet.com/tx/e2597a10a82611d5f0008b6dff35a4d2c9091a5928fa49a5702d9178d7a4dc99) | TRUC v3 1p1c package (`600` sats CPFP) |
| Unroll hop 2/3 (`CHECKPOINT`) | [`dc16e8c9...bf66`](https://mutinynet.com/tx/dc16e8c9827858ed8b8c678d9baeb4731a39278af20fa842b965148d50eabf66) + CPFP [`e0f2510c...e363`](https://mutinynet.com/tx/e0f2510c015f34c05bef6447498c48e09c4a80a749b0ae3687aa40c9156ee363) | TRUC v3 1p1c package (`600` sats CPFP) |
| Unroll hop 3/3 (`ARK` DLC VTXO) | [`f690232d...9206`](https://mutinynet.com/tx/f690232d0b16d82cc6e1025e38910b2bef1f8441e5faf3035161ce2f41569206) + CPFP [`0560c0a4...f992`](https://mutinynet.com/tx/0560c0a4f85a4adb6806798e709df9965c028e0c40cb2e2c7edbe6fd81aff992) | TRUC v3 1p1c package (`600` sats CPFP); confirmed onchain at `20:05:03Z` |
| Finalized DLC exit payout | [`23b29ead...1a31`](https://mutinynet.com/tx/23b29ead46541d643935bbbac6abb269e9e49d6bbd48b63dca57e3be57721a31) | Broadcast automatically by `ark-watchtower` at `20:42:10Z` once MTP passed `CSV(2048s)`; pays User `3,250`, LP `1,250`, Tiered Bounty `5,000` (`500` sat fee) |
| Primary `W1` bounty sweep | [`b98cc499...7d2b`](https://mutinynet.com/tx/b98cc499f1b5d0b1d330af16654bc5f52e8cbeadeef00b0df008af2b11877d2b) | Swept immediately via primary leaf (`<W1> OP_CHECKSIG`) at `20:42:52Z` (`470` sat dynamic fee from Mutinynet Esplora `/fee-estimates`) |

**Exact watchtower accounting (`ark-watchtower info`):**
- Total CPFP fees spent (3 hops): `1,800` sats
- Total sweep fee spent (dynamic Esplora estimate): `470` sats
- Total bounty earned: `5,000` sats
- **Net onchain profit:** **`+2,730` sats**

## Practical findings from the real Arkade tree unroll

1. **Always fund DLC contracts from a single settled batch VTXO:** An earlier attempt that mixed a preconfirmed change VTXO with a freshly settled VTXO produced a 13-hop unroll chain across 3 batches (which would have exceeded the `5,000`-sat bounty). Funding from a single settled VTXO kept the chain to **3 hops** (`TREE → CHECKPOINT → ARK`).
2. **PSBT extraction across Arkade tx types:** `getVirtualTxs` returns `TREE` PSBTs with only `tapKeySig` (no `witnessUtxo`), while `CHECKPOINT` and `ARK` PSBTs carry `witnessUtxo` + `tapScriptSig` + `tapLeafScript`. Key-spend `TREE` PSBTs serialize cleanly by placing `[tapKeySig]` into `finalScriptWitness`.
3. **BIP-68 time-based CSV via Esplora MTP worked on the first attempt:** `ark-watchtower` waited ~37 minutes until Mutinynet's block `mediantime` cleared `vtxo_block_time + 2048s`, then broadcast the exit payout with zero `non-BIP68-final` rejections.

## Run it

```sh
# 1. Open a live DLC VTXO on mutinynet.arkade.sh and export the 3-hop keyless package
cd experiments/18-mutinynet-arkade-unilateral-exit
npm install
node open_and_export.mjs

# 2. Register and run the standalone Rust watchtower
cd ../..
cargo run --manifest-path watchtower/Cargo.toml -- --config watchtower/data/mutinynet-exp18.toml register experiments/18-mutinynet-arkade-unilateral-exit/data/package.json
cargo run --manifest-path watchtower/Cargo.toml -- --config watchtower/data/mutinynet-exp18.toml run
```
