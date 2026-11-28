# p2pFiat MVP — LP Service, DLC Engine, Order Book & CLI (`mvp/`)

Core protocol implementation for trustless, BTC-collateralized synthetic USD/EUR and 2× Long BTC positions on the live Arkade Mutinynet server (`https://mutinynet.arkade.sh`).

## Modules

| File | Purpose |
|---|---|
| [`src/lp.mjs`](src/lp.mjs) | Liquidity Provider daemon supporting USD, EUR, 1× Short (Stable Fiat), and 2× Long BTC. Runs over HTTP + NIP-17 or pure serverless NIP-17 (`LP_NO_HTTP=1`). Includes honest rollover yield accounting (`carriedInterestUsd` for sub-dust `< 330 sats` payouts). |
| [`src/contract.mjs`](src/contract.mjs) | Arkade DLC Tapscript builder (Leaf 0: 3-of-3 collab, Leaf 1: CSV + 2-of-2 adaptor CET / refund + tiered Watchtower bounty, Leaf 2: BIP-342 `k-of-n` Nostracle On-Demand Dispute Leaf), VTXO unroll chain extractor, and keyless `ark-watchtower` package exporter. |
| [`src/nip17.mjs`](src/nip17.mjs) | Zero-dependency NIP-44 v2 + NIP-59/17 Gift-Wrapped encrypted RPC peer with 5s auto-reconnect and 30s WebSocket health checks. |
| [`src/offerbook.mjs`](src/offerbook.mjs) | Serverless Nostr `kind: 30078` order book publisher & scanner across 5 default relays (`relay.primal.net`, `relay.snort.social`, `relay.noswhere.com`, `relay.satlantis.io`, `relay.nostr.net`). See [`OFFERBOOK_PROTOCOL.md`](OFFERBOOK_PROTOCOL.md). |
| [`src/nostracle-client.mjs`](src/nostracle-client.mjs) | Kormir `kind: 88` announcement parser and `DLC/oracle/attestation/v0` adaptor point math. |
| [`src/cli.mjs`](src/cli.mjs) | Reference User CLI (`init`, `balance`, `quote`, `open`, `positions`, `export-watchtower`, `close`). |
| [`web/`](web/) | Browser-native Self-Custody Web Wallet PWA. See [`web/README.md`](web/README.md). |
| [`scripts/`](scripts/) | Utility scripts (`discover-nostracles.mjs`, `publish-nostracle-list.mjs` for NIP-51 `kind: 30000` oracle curation). |

## Quick Start

```bash
cd mvp
npm install

# LP-Alpha (HTTP + NIP-17, 10 bps spread, +2 bps/day yield)
LP_PORT=3456 LP_NAME=LP-Alpha LP_SPREAD_BPS=10 LP_FUNDING_BPS=2 LP_DATA_DIR=data/lp-alpha node src/lp.mjs

# LP-Beta (Serverless NIP-17 only, 5 bps spread, +3.5 bps/day yield)
LP_NO_HTTP=1 LP_NAME=LP-Beta LP_SPREAD_BPS=5 LP_FUNDING_BPS=3.5 LP_DATA_DIR=data/lp-beta node src/lp.mjs

# User CLI
node src/cli.mjs init
node src/cli.mjs balance
node src/cli.mjs quote --usd 3
node src/cli.mjs open --usd 3
node src/cli.mjs positions
node src/cli.mjs export-watchtower <positionId>
node src/cli.mjs close <positionId>
```

## Tests

```bash
# Unit & compatibility tests (no Mutinynet funds required)
node --test test/nip17.test.mjs test/offerbook.test.mjs test/nostracle-kind88.test.mjs test/ondemand-dispute.test.mjs test/watchtower-compat.test.mjs

# Live Mutinynet E2E test (boards real Mutinynet sats)
node test/e2e.mjs
```
