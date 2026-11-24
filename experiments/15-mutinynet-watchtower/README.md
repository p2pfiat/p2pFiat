# Experiment 15: live Mutinynet (Signet) + public Nostr relays watchtower exit

**Question:** does the standalone Rust [`ark-watchtower`](../../watchtower/README.md) complete a full keyless DLC exit on a **public** Bitcoin test network (Mutinynet) and **public** Nostr relays — receiving the exit package via NIP-17 DM, fetching & verifying an independent external oracle's kind-88/89 attestation, unrolling a 0-fee v3 (TRUC) virtual transaction with a 0-sat P2A anchor via Esplora `/txs/package`, finalizing the adaptor-signed DLC payout after CSV, and sweeping the tiered Taproot bounty at a net profit?

**Result: yes.** All 6 stages completed end-to-end on the first run on live Mutinynet (blocks `3,618,010`–`3,618,017`) and public Nostr relays (`wss://nos.lol`, `wss://relay.damus.io`, `wss://relay.primal.net`), netting **`+4,000` sats** onchain (`74,500` → `78,500` sats).

## Public network preflight

| Endpoint | Verified behavior |
|---|---|
| `https://mutinynet.arkade.sh/v1/info` | Live (`network = "mutinynet"`, `sessionDuration = 60s`, `unilateralExitDelay = 2048s`, `dust = 330` sats, `txFeeRate = 0`) |
| `https://mutinynet.arkade.sh/v1/indexer/vtxos?scripts=...&spentOnly=true` | Live (`200 OK`, matches `HttpArkIndexer` stale-exit guard schema) |
| `https://mutinynet.com/api/txs/package` | Live, backed directly by Bitcoin Core `submitpackage` RPC (supports TRUC v3 1p1c + 0-sat P2A anchors) |
| `https://mutinynet.com/api/fee-estimates` | Live (`~2.02 sat/vB` for 1–2 blocks) |

## Live Mutinynet transactions

| Stage | Transaction | Details |
|---|---|---|
| 1. Setup commitment tx | [`deea5967...28a5`](https://mutinynet.com/tx/deea5967276d015848c1e0ff50b0aada333fefe4e0b35f0638de52b4651f28a5) | Splits `100,000` sat faucet UTXO into `25,000` sat commitment output + `74,500` sat confirmed `W1` fee UTXO |
| 2. Public Nostr relays | `btcusd-mutinynet-1795540563 = $97,123` | Independent external oracle published kind-88 & kind-89 (2 relay acks); user sent NIP-17 `RegisterPackage` DM (2 relay acks); `W1` unwrapped DM and verified external attestation |
| 3. Unroll VTXO tx (v3 TRUC, 0-sat fee, 0-sat P2A anchor) | [`7c66a3cd...4fb9`](https://mutinynet.com/tx/7c66a3cd57618c6464b17052a0184e2011a55edda5c16136669e5ef0e92c4fb9) | Broadcast as 1p1c package via `https://mutinynet.com/api/txs/package`, confirmed to `4/4` blocks (`exit_csv = 4`) |
| 4. CPFP child tx (v3 TRUC, `600` sat fee) | [`e638b3fc...b297`](https://mutinynet.com/tx/e638b3fc8434701941a22f208756d01f078004572719511411fe91faa794b297) | Spends VTXO's 0-sat P2A anchor (`OP_1 <0x4e73>`) + `W1`'s confirmed P2TR UTXO |
| 5. Finalized DLC exit payout | [`812b3eea...2e4a`](https://mutinynet.com/tx/812b3eeab40cc3911e9def7482c1dd9260a9277aebe25fe46e4d0a440ac42e4a) | Adaptor signatures completed by keyless `W1` from 10-bit numeric prefix; pays User `14,250`, LP `5,250`, tiered bounty `5,000` sats (`500` sat fee) |
| 6. Primary `W1` bounty sweep (`400` sat fee) | [`76750c13...76e2`](https://mutinynet.com/tx/76750c13141be4b6512b25b92726693e556b9c72708ec8ade1fb690a149676e2) | Immediate primary leaf spend (`<W1> OP_CHECKSIG`), sweeping `4,600` sats to `W1` |

**Exact onchain accounting (`W1`):**
- Balance before exit: `74,500` sats
- CPFP fee spent: `-600` sats
- Bounty swept (net of `400` sat sweep fee): `+4,600` sats
- Balance after exit: **`78,500` sats** (**`+4,000` sats** net profit)

## What this does not show

- Opening and offchain-settling a VTXO directly through the public `https://mutinynet.arkade.sh` operator (this test simulated the confirmed commitment output on Mutinynet L1 to exercise the full `ark-watchtower` onchain + public Nostr path; live Arkade Mutinynet VTXO opening/settlement is next).
- Backup watchtower (`W2`) failover on Mutinynet or fee-spike RBF under mainnet congestion.

## Run it

1. Configure `watchtower/data/mutinynet.toml` (network = `"signet"`, `esplora_url = "https://mutinynet.com/api"`).
2. Run `cargo run --manifest-path watchtower/Cargo.toml -- --config watchtower/data/mutinynet.toml init` and fund the printed `tb1p...` address with at least `35,000` Mutinynet sats from [faucet.mutinynet.com](https://faucet.mutinynet.com).
3. Run:

```sh
cargo run --manifest-path watchtower/Cargo.toml --example mutinynet_e2e
```
