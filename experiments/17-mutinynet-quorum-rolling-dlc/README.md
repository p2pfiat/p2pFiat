# Experiment 17: live 22-path Design 3 quorum rolling DLC + 20-bit numeric DLC on public Arkade Mutinynet

**Question:** does the unmodified public Arkade Mutinynet operator (`https://mutinynet.arkade.sh`) accept our full **22-path Design 3 Tapscript** (user settle/exit + 10 × 3-of-5 quorum `CLTV` settle/roll + 10 × 3-of-5 quorum `CSV` exit), let one 3-of-5 quorum roll the position offchain while the user is offline, and let a *different* 3-of-5 quorum settle the rolled VTXO using a **20-bit numeric DLC** binary prefix attestation?

**Result: yes.** All 4 stages succeeded live on `https://mutinynet.arkade.sh`.

## 22-path Design 3 Tapscript (adapted for Mutinynet time-based CSV)

| Leaves | Count | Script | Purpose |
|---|---|---|---|
| User settle | 1 | `<U> <L> <server> 3-of-3` | Cooperative offchain roll/settle while user is online |
| User exit | 1 | `CSV(2048s) <U> <L> 2-of-2` | Unilateral onchain exit (matches operator's `unilateralExitDelay`) |
| Quorum roll/settle | 10 (`C(5,3)`) | `CLTV <Ni> <Nj> <Nk> <L> <server> 5-of-5` | Any 3 of 5 nostracles + LP roll or settle offchain for an offline user |
| Quorum exit | 10 (`C(5,3)`) | `CSV(4096s) <Ni> <Nj> <Nk> <L> 4-of-4` | Unilateral onchain exit by any 3 of 5 nostracles + LP if operator disappears |

## Live Mutinynet & Arkade transactions

| Stage | ID / Link | Details |
|---|---|---|
| Boarding L1 tx | [`64937fd7...f376`](https://mutinynet.com/tx/64937fd7a43a4ba4840d94bbeb98a4ea2885717a3c6fdf270151a0996845f376) | `6,000` sats sent to Arkade boarding address |
| Batch commitment tx | [`864c2b0d...e608`](https://mutinynet.com/tx/864c2b0dcab937c317aace777d1d84e32c88b9b26326a5843fe9863e6f61e608) | Joined live 60s Arkade Mutinynet batch round (`6,500` available sats) |
| 1. Open 22-path VTXO #1 | `05cf2e83fd0bffd18a9972c3a9dec0ffb97d31c0c0e22dba74387ef7b0ea0403:0` | `4,500` sats locked in 22-leaf Tapscript; **user private key wiped immediately** |
| 2. Quorum `{N0,N1,N2}` roll → VTXO #2 | `0b23b81650af8e196e3288eaf8dd1d5c1bb01eae9a86452e7fac8d7ec98d36be:0` | Rolled offchain via `CLTVMultisigTapscript` (`submitTx` + `finalizeTx` accepted by `mutinynet.arkade.sh`) |
| 3. Quorum `{N1,N2,N4}` 20-bit numeric DLC settlement | `64d58194b39542877322b39f15a9086971d1a81d638d252ae98c5142c7e58f6c` | Attested `$91,420` (`00010110010100011100`), summed 12-bit prefix scalars, completed 4 adaptor sigs on `arkTx` + `checkpointTx` |
| 4. Final live indexer state | `:0` (`2,450` sats), `:1` (`2,050` sats) | VTXO #1 spent (`true`), VTXO #2 spent (`true`), User = `2,450` sats, LP = `2,050` sats |

## Practical findings

1. **22-leaf Taproot tree + 5-of-5 `CLTVMultisigTapscript` works unmodified on public `mutinynet.arkade.sh`:** No Arkade Script, no emulator, and no server changes were needed.
2. **Automatic CLTV handling in `@arkade-os/sdk`:** `buildOffchainTx` inspects `CLTVMultisigTapscript` on the input leaf and automatically sets the required `nLockTime` and non-final `nSequence` on both `arkTx` and `checkpointTx`.
3. **Cross-quorum continuity:** Quorum `{N0, N1, N2}` rolled the position while the user was offline, and a different quorum `{N1, N2, N4}` settled the rolled coin via 20-bit numeric adaptor signatures.

## Run it

```sh
cd experiments/17-mutinynet-quorum-rolling-dlc
npm install
node run.mjs
```
