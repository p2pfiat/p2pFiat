# ark-watchtower

Keyless Ark watchtower with tiered onchain exit bounties, implementing
[Experiment 13](../experiments/13-watchtower-bounty/README.md).

Designed to run **independently** from any DLC price oracle (such as
[nostracle](https://github.com/p2pfiat/nostracle) or a 4-of-7 threshold oracle):
it holds **zero user or LP private keys**, reads kind-88/89 DLC attestations
from Nostr relays for any oracle pubkey, and funds TRUC (v3) CPFP exits from
its own onchain P2TR wallet.

## Tiered bounty output design

Each pre-signed exit transaction (DLC payout or timelocked refund) pays a
bounty to a P2TR script with an unspendable BIP-341 NUMS internal key:

| Leaf | Script | Purpose |
|---|---|---|
| Primary (`W1`) | `<W1> OP_CHECKSIG` | Assigned primary watchtower claims immediately (0-block delay) |
| Backup (`W2`, `W3`) | `<4> OP_CSV OP_DROP <Wi> OP_CHECKSIG` | Backup watchtowers can step in if `W1` is offline, but cannot snipe `W1` in the mempool |

## What it does on each tick

1. **NIP-17 package intake:** unwraps incoming `WatchtowerRequest::RegisterPackage` DMs, validates the bounty script and transactions, persists to `watchtower.json`, and replies with `WatchtowerReply::Registered` or `Rejected`.
2. **External oracle attestation sync:** fetches and verifies kind-88/89 DLC oracle events from Nostr relays for watched contracts (supports both single `nostracle` and threshold oracles).
3. **Stale-exit guard:** queries the Ark indexer (if reachable) and skips contracts already settled offchain.
4. **Profitability guard:** counts remaining unconfirmed unroll hops and refuses to unroll at a loss when estimated CPFP + sweep fees exceed the bounty minus `min_profit_sats`.
5. **TRUC (v3) CPFP unrolling:** spends each virtual tx's 0-sat P2A anchor (`OP_1 <0x4e73>`) using a **confirmed** P2TR wallet UTXO via 1p1c package relay (`/txs/package`).
6. **Exit finalization:** once the VTXO confirms and satisfies `exit_csv`, completes the matching BIP-340 adaptor signatures from the oracle attestation — or broadcasts the pre-signed timelocked refund at `refund_height` if the oracle is absent.
7. **Bounty sweep:** sweeps the bounty output immediately (`Primary`) or after `backup_csv` confirmations (`Backup`) and tracks net profit in `watchtower.json`.

## Usage

```sh
cp config.example.toml config.toml
cargo run -- init                                # generate watchtower.key + print P2TR funding address
cargo run -- info                                # show pubkey, P2TR address, and profit summary
cargo run -- register path/to/package.json       # register an exit package locally
cargo run -- list                                # list watched contracts and states
cargo run -- run                                 # run watchtower loop (Nostr + Esplora + Ark indexer)
cargo run -- run --once                          # single tick and exit
cargo run -- bounty-script --primary <hex> --backup <hex> --backup-csv 4 --amount 5000
```

Fund the P2TR address printed by `init` with **confirmed** UTXOs before running
(Bitcoin Core v30 TRUC rules reject v3 CPFP children that spend unconfirmed v2
UTXOs).
