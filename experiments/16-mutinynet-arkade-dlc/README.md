# Experiment 16: live custom-Tapscript DLC on public Arkade Mutinynet

**Question:** does the public Arkade Mutinynet operator (`https://mutinynet.arkade.sh`) accept our custom Design 1 Tapscript DLC contract (`settle: user + LP + signer`, `exit: CSV + user + LP`), and can an LP complete pre-signed BIP-340 adaptor signatures (both `arkTx` and `checkpointTx`) to settle offchain while the user's private key is wiped?

**Result: yes.** We boarded real Mutinynet L1 sats into a live Arkade batch round, opened a custom Tapscript DLC VTXO, wiped the user's private key, and settled the DLC offchain via `submitTx` + `finalizeTx` on `https://mutinynet.arkade.sh`.

## Live Mutinynet & Arkade transactions

| Stage | ID / Link | Details |
|---|---|---|
| 1. L1 boarding tx | [`b9fac364...4d20`](https://mutinynet.com/tx/b9fac364ee7025e139d8899db3c921cac51b2e2a5203c9de287bb775ed5e4d20) | `10,000` sats sent to Arkade boarding address (`tb1p34um...rcf2`), confirmed at block `3,618,103` |
| 2. Arkade batch commitment tx | [`cb7ec0fd...d192`](https://mutinynet.com/tx/cb7ec0fda1b03b6a8c695b9525847f2e3fcf21727a6a371585843b06df48d192) | Joined live 60s batch round via `Ramps.onboard()`, producing `10,000` settled offchain sats |
| 3. Custom DLC contract VTXO | `16b6b5c29fa5613f552af02629ab0402dfb045633495f6dc92eb96e7c05085e0:0` | `5,000` sats funded to custom Tapscript `VtxoScript` (`settle` 3-of-3 + `exit` `CSV(2048s)` 2-of-2) |
| 4. Offline adaptor DLC settlement | `f8f6cc635022c2b6ea00bf1658b3e2c6e3b051b6b9f7d0e12e6a3c3f6115a276` | User key wiped; oracle attested `BTCUSD-up`; LP completed adaptor sigs for `arkTx` + `checkpointTx`; `submitTx` and `finalizeTx` accepted by `mutinynet.arkade.sh` |
| 5. Settled payouts (live indexer) | `f8f6cc63...a276:0` (`3,000` sats), `f8f6cc63...a276:1` (`2,000` sats) | Contract VTXO marked `isSpent: true`; User (`3,000` sats) and LP (`2,000` sats) hold live spendable VTXOs |

## Practical findings from the live public operator

1. **Time-based CSV enforced on custom exit leaves:** Unlike local `arkd` regtest (where block-based `CSV(20)` worked), the live public `mutinynet.arkade.sh` operator rejects block-based CSV closures with:
   `INVALID_VTXO_SCRIPT (10): invalid exit closure, CSV block type not allowed`.
   Custom DLC exit leaves must match the operator's `unilateralExitDelay` type (`seconds`, `>= 2048n` on Mutinynet).
2. **No emulator or Arkade Script needed:** Standard Bitcoin Tapscript (`MultisigTapscript` + `CSVMultisigTapscript`) + BIP-340 adaptor signatures worked out of the box on the unmodified public Arkade operator via `@arkade-os/sdk` v0.5.13.
3. **Node.js SDK storage:** Outside browsers, `Wallet.create` requires explicit `InMemoryWalletRepository` + `InMemoryContractRepository` and explicit `arkProvider` / `indexerProvider` / `onchainProvider` instances (passing `arkServerUrl` alone defaults to mainnet).

## Run it

```sh
cd experiments/16-mutinynet-arkade-dlc
npm install
node run.mjs
```

Requires a funded Mutinynet P2TR key at `watchtower/data/mutinynet-wt.key` (at least `11,000` sats on Mutinynet L1, or `>= 5,000` sats already boarded on `mutinynet.arkade.sh`).
