# p2pFiat M4 MVP: LP Service + User Wallet CLI on Arkade Mutinynet

A working end-to-end prototype of a trustless BTC-collateralized USD-pegged
position on the live public Arkade Mutinynet server (`https://mutinynet.arkade.sh`):

- **LP Service (`src/lp.mjs`):** quotes live BTC/USD spot (median of Kraken, Coinbase, Bitstamp), co-funds 2-party custom Tapscript DLC VTXOs atomically (2-input `buildOffchainTx` — zero custody), and executes collaborative early closes at live spot.
- **User CLI (`src/cli.mjs`):** `init`, `balance`, `quote`, `open --usd <amt>`, `positions`, `close <id>`, and `export-watchtower <id>` (extracts the real Arkade unroll chain for [`ark-watchtower`](../watchtower/README.md)).

## Quick start

```sh
cd mvp
npm install

# Terminal 1: start LP daemon
node src/lp.mjs

# Terminal 2: User CLI
node src/cli.mjs init
node src/cli.mjs balance
node src/cli.mjs quote --usd 3
node src/cli.mjs open --usd 3
node src/cli.mjs positions
node src/cli.mjs export-watchtower <positionId>
node src/cli.mjs close <positionId>
```

## Live Mutinynet E2E test

```sh
node test/e2e.mjs
```

Starts the LP server on an ephemeral local port, boards Mutinynet sats for both
User and LP, runs the real User CLI commands (`quote` → `open` → `positions` →
`export-watchtower` → `close`) against live `https://mutinynet.arkade.sh`, and
verifies exact USD-pegged settlement balances on the live indexer.
