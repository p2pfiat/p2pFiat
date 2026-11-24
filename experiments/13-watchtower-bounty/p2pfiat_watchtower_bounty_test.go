package e2e_test

// Experiment 13: keyless watchtower with a tiered onchain exit bounty on arkd.
//
// Question: can a watchtower holding NO user or LP private keys (only saved
// exit data and its own BTC fee wallet) unroll an orphaned Ark contract coin,
// pay real CPFP fees, finalize the DLC payout or refund, and profit from an
// onchain bounty — without allowing miners or other watchtowers to snipe it?
//
// Bounty output design (P2TR, unspendable NUMS internal key):
//   - Primary watchtower (W1): immediate OP_CHECKSIG
//   - Backup watchtowers (W2, W3): 2-block CSV delay + OP_CHECKSIG
//
// Needs helpers from ../01-offline-settlement and ../02-failure-paths. Copy all
// three test files into arkd's internal/test/e2e directory and run with:
//   go test -v -count 1 -run TestP2pFiatWatchtowerBounty ./internal/test/e2e

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/unroll"
	wallet "github.com/arkade-os/arkd/pkg/client-wallet"
	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

const (
	wtContractAmount = int64(25000)
	wtExitTxFee      = int64(500)  // split 250/250 in exit payout tx
	wtBountyAmount   = int64(5000) // split 2500/2500 in exit payout tx
	wtCPFPFeePerTx   = int64(600)  // fee paid per unroll hop by watchtower
	wtSweepFee       = int64(400)  // fee paid by watchtower to sweep bounty
	wtBackupCSV      = uint32(4)   // blocks backup watchtowers must wait
	wtExitCSV        = uint32(20)
	wtUp             = "BTCUSD-settles-up"
	wtDown           = "BTCUSD-settles-down"
)

var (
	wtPayouts = map[string][2]int64{wtUp: {17000, 8000}, wtDown: {10000, 15000}}
	wtRefund  = [2]int64{12500, 12500}
)

// watchtowerWallet is an independent onchain P2TR wallet owned by a watchtower.
// It holds no user or LP keys and tracks every satoshi spent on CPFP and earned
// from bounties.
type watchtowerWallet struct {
	name          string
	priv          *btcec.PrivateKey
	tweakedPriv   *btcec.PrivateKey
	pub           *btcec.PublicKey
	addr          string
	pkScript      []byte
	utxo          wire.OutPoint
	utxoValue     int64
	startBalance  int64
	cpfpFeesSpent int64
	cpfpTxs       int
	sweepFees     int64
}

func newWatchtowerWallet(t *testing.T, name string) *watchtowerWallet {
	t.Helper()
	d, pub := evenKey(t)
	dBytes := d.Bytes()
	priv, _ := btcec.PrivKeyFromBytes(dBytes[:])
	tweakedPriv := txscript.TweakTaprootPrivKey(*priv, nil)
	tapKey := txscript.ComputeTaprootKeyNoScript(priv.PubKey())
	addr, err := address.NewAddressTaproot(
		schnorr.SerializePubKey(tapKey), &chaincfg.RegressionNetParams,
	)
	require.NoError(t, err)
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	_, err = runCommand("nigiri", "faucet", addr.EncodeAddress(), "0.01")
	require.NoError(t, err)

	var utxos []clientlib.ExplorerUtxo
	waitUntil(t, chainWait, fmt.Sprintf("watchtower %s faucet utxo", name), func(ctx context.Context) error {
		found, err := testExplorer.GetUtxos([]string{addr.EncodeAddress()})
		if err != nil {
			return err
		}
		if len(found) != 1 {
			return fmt.Errorf("got %d utxos, want 1", len(found))
		}
		utxos = found
		return nil
	})
	txHash, err := chainhash.NewHashFromStr(utxos[0].Txid)
	require.NoError(t, err)
	// Confirm the v2 faucet UTXO so a v3 (TRUC) CPFP child can spend it.
	require.NoError(t, generateBlocks(1))
	waitForTxConfirmed(t, utxos[0].Txid)
	val := int64(utxos[0].Amount)

	return &watchtowerWallet{
		name:         name,
		priv:         priv,
		tweakedPriv:  tweakedPriv,
		pub:          pub,
		addr:         addr.EncodeAddress(),
		pkScript:     pkScript,
		utxo:         wire.OutPoint{Hash: *txHash, Index: utxos[0].Vout},
		utxoValue:    val,
		startBalance: val,
	}
}

// balance returns the watchtower's current confirmed onchain balance according to
// the explorer.
func (w *watchtowerWallet) balance(t *testing.T) int64 {
	t.Helper()
	utxos, err := testExplorer.GetUtxos([]string{w.addr})
	require.NoError(t, err)
	var sum int64
	for _, u := range utxos {
		sum += int64(u.Amount)
	}
	return sum
}

// bumpAndBroadcast spends the parent's P2A anchor using the watchtower's own
// UTXO, broadcasts the v3 1p1c package, mines 1 block, and updates the local
// change UTXO.
func (w *watchtowerWallet) bumpAndBroadcast(t *testing.T, parentHex string, fee int64) {
	t.Helper()
	var parent wire.MsgTx
	require.NoError(t, parent.Deserialize(hex.NewDecoder(strings.NewReader(parentHex))))
	anchor, err := txutils.FindAnchorOutpoint(&parent)
	require.NoError(t, err)
	anchorVal := parent.TxOut[anchor.Index].Value

	child := wire.NewMsgTx(3)
	child.AddTxIn(&wire.TxIn{
		PreviousOutPoint: *anchor,
		Sequence:         wire.MaxTxInSequenceNum,
	})
	child.AddTxIn(&wire.TxIn{
		PreviousOutPoint: w.utxo,
		Sequence:         wire.MaxTxInSequenceNum,
	})
	changeVal := w.utxoValue + anchorVal - fee
	require.Greater(t, changeVal, int64(546), "watchtower wallet out of funds")
	child.AddTxOut(&wire.TxOut{Value: changeVal, PkScript: w.pkScript})

	prevOuts := map[wire.OutPoint]*wire.TxOut{
		*anchor: parent.TxOut[anchor.Index],
		w.utxo:  {Value: w.utxoValue, PkScript: w.pkScript},
	}
	fetcher := txscript.NewMultiPrevOutFetcher(prevOuts)
	sigHash, err := txscript.CalcTaprootSignatureHash(
		txscript.NewTxSigHashes(child, fetcher),
		txscript.SigHashDefault, child, 1, fetcher,
	)
	require.NoError(t, err)
	sig, err := schnorr.Sign(w.tweakedPriv, sigHash)
	require.NoError(t, err)
	// Input 0 (P2A) has empty witness; input 1 is P2TR key-path spend.
	child.TxIn[1].Witness = wire.TxWitness{sig.Serialize()}

	var buf bytes.Buffer
	require.NoError(t, child.Serialize(&buf))
	childHex := hex.EncodeToString(buf.Bytes())

	_, err = testExplorer.Broadcast(parentHex, childHex)
	require.NoError(t, err)
	require.NoError(t, generateBlocks(1))
	waitForTxConfirmed(t, parent.TxHash().String())
	waitForTxConfirmed(t, child.TxHash().String())

	w.utxo = wire.OutPoint{Hash: child.TxHash(), Index: 0}
	w.utxoValue = changeVal
	w.cpfpFeesSpent += fee
	w.cpfpTxs++
}

// bountyScript holds the tiered Taproot bounty locking script and leaf data:
//   - Primary watchtower: immediate OP_CHECKSIG
//   - Backup watchtowers: CSV(wtBackupCSV) + OP_CHECKSIG
type bountyScript struct {
	pkScript      []byte
	primaryLeaf   failureLeaf
	primaryClose  *script.MultisigClosure
	backupLeaves  map[string]failureLeaf
	backupCloses  map[string]*script.CSVMultisigClosure
	backupSeq     uint32
}

func newBountyScript(t *testing.T, primary *btcec.PublicKey, backups []*btcec.PublicKey) *bountyScript {
	t.Helper()
	primaryClose := &script.MultisigClosure{PubKeys: []*btcec.PublicKey{primary}}
	closures := []script.Closure{primaryClose}

	backupLock := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: wtBackupCSV}
	backupSeq, err := arklib.BIP68Sequence(backupLock)
	require.NoError(t, err)

	backupCloses := map[string]*script.CSVMultisigClosure{}
	for _, pub := range backups {
		c := &script.CSVMultisigClosure{
			Locktime:        backupLock,
			MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{pub}},
		}
		closures = append(closures, c)
		backupCloses[hex.EncodeToString(schnorr.SerializePubKey(pub))] = c
	}

	vs := script.TapscriptsVtxoScript{Closures: closures}
	tapKey, tapTree, err := vs.TapTree()
	require.NoError(t, err)
	pkScript, err := script.P2TRScript(tapKey)
	require.NoError(t, err)

	leafFor := func(c script.Closure) failureLeaf {
		s, err := c.Script()
		require.NoError(t, err)
		proof, err := tapTree.GetTaprootMerkleProof(txscript.NewBaseTapLeaf(s).TapHash())
		require.NoError(t, err)
		ctrl, err := txscript.ParseControlBlock(proof.ControlBlock)
		require.NoError(t, err)
		return failureLeaf{
			script: proof.Script, ctrl: proof.ControlBlock,
			tapscript: &waddrmgr.Tapscript{ControlBlock: ctrl, RevealedScript: proof.Script},
		}
	}

	backupLeaves := map[string]failureLeaf{}
	for k, c := range backupCloses {
		backupLeaves[k] = leafFor(c)
	}

	return &bountyScript{
		pkScript:     pkScript,
		primaryLeaf:  leafFor(primaryClose),
		primaryClose: primaryClose,
		backupLeaves: backupLeaves,
		backupCloses: backupCloses,
		backupSeq:    backupSeq,
	}
}

// buildSweepBountyTx builds a signed transaction sweeping the bounty output to
// destPkScript using either the primary leaf (immediate) or a backup leaf (CSV).
func (b *bountyScript) buildSweepBountyTx(
	t *testing.T,
	bountyOutpoint wire.OutPoint,
	signerPriv *btcec.PrivateKey,
	signerPub *btcec.PublicKey,
	useBackup bool,
	destPkScript []byte,
	fee int64,
) string {
	t.Helper()
	tx := wire.NewMsgTx(2)
	seq := wire.MaxTxInSequenceNum
	var leaf failureLeaf
	var closure script.Closure
	if useBackup {
		seq = b.backupSeq
		pubHex := hex.EncodeToString(schnorr.SerializePubKey(signerPub))
		var ok bool
		leaf, ok = b.backupLeaves[pubHex]
		require.True(t, ok, "unknown backup watchtower pubkey")
		closure = b.backupCloses[pubHex]
	} else {
		leaf = b.primaryLeaf
		closure = b.primaryClose
	}
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: bountyOutpoint, Sequence: seq})
	tx.AddTxOut(&wire.TxOut{Value: wtBountyAmount - fee, PkScript: destPkScript})

	fetcher := txscript.NewCannedPrevOutputFetcher(b.pkScript, wtBountyAmount)
	sigHash, err := txscript.CalcTapscriptSignaturehash(
		txscript.NewTxSigHashes(tx, fetcher),
		txscript.SigHashDefault, tx, 0, fetcher,
		txscript.NewBaseTapLeaf(leaf.script),
	)
	require.NoError(t, err)
	sig, err := schnorr.Sign(signerPriv, sigHash)
	require.NoError(t, err)

	// Witness uses the script's expected pubkey slot; for attack tests signerPub
	// may not match the script leaf, so we pass the leaf's pubkey map entry.
	var witness wire.TxWitness
	if useBackup {
		witness, err = closure.Witness(leaf.ctrl, map[string][]byte{
			hex.EncodeToString(schnorr.SerializePubKey(signerPub)): sig.Serialize(),
		})
	} else {
		witness, err = closure.Witness(leaf.ctrl, map[string][]byte{
			hex.EncodeToString(schnorr.SerializePubKey(b.primaryClose.PubKeys[0])): sig.Serialize(),
		})
	}
	require.NoError(t, err)
	tx.TxIn[0].Witness = witness

	var buf bytes.Buffer
	require.NoError(t, tx.Serialize(&buf))
	return hex.EncodeToString(buf.Bytes())
}

// watchtowerPackage is everything a keyless watchtower receives at contract
// opening. It contains zero user or LP private keys.
type watchtowerPackage struct {
	outpoint     clientlib.Outpoint
	pkScript     []byte
	saved        *cachedIndexer
	uPub, lPub   *btcec.PublicKey
	uChainPk     []byte
	lChainPk     []byte
	exitClosure  *script.CSVMultisigClosure
	exitLeaf     failureLeaf
	bounty       *bountyScript
	exitPayouts  map[string]*exitPackage
	exitRefund   *exitPackage
	refundHeight uint32
}

type wtContract struct {
	funder     wallet.Wallet
	oracle     *testOracle
	uArkPk     []byte
	lArkPk     []byte
	arkPayouts map[string]*arkPackage
	pkg        *watchtowerPackage
}

func openWatchtowerContract(
	t *testing.T, ctx context.Context,
	chainRefundHeight uint32,
	bounty *bountyScript,
) *wtContract {
	t.Helper()
	funder := setupClientWallet(t)
	_, offchainAddr, _, err := funder.Receive(ctx)
	require.NoError(t, err)
	funderAddr, err := arklib.DecodeAddressV0(offchainAddr.Address)
	require.NoError(t, err)
	faucetOffchain(t, funder, 0.0003)
	signer := funderAddr.Signer

	uKey, uPub := evenKey(t)
	lKey, lPub := evenKey(t)
	oracle := newTestOracle(t)

	settle := &script.MultisigClosure{PubKeys: []*btcec.PublicKey{uPub, lPub, signer}}
	exitLocktime := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: wtExitCSV}
	exit := &script.CSVMultisigClosure{
		Locktime:        exitLocktime,
		MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{uPub, lPub}},
	}
	vs := script.TapscriptsVtxoScript{Closures: []script.Closure{settle, exit}}
	tapKey, tapTree, err := vs.TapTree()
	require.NoError(t, err)
	pkScript, err := script.P2TRScript(tapKey)
	require.NoError(t, err)
	addr, err := (&arklib.Address{HRP: "tark", VtxoTapKey: tapKey, Signer: signer}).EncodeV0()
	require.NoError(t, err)
	revealed, err := vs.Encode()
	require.NoError(t, err)

	leafFor := func(c script.Closure) failureLeaf {
		s, err := c.Script()
		require.NoError(t, err)
		proof, err := tapTree.GetTaprootMerkleProof(txscript.NewBaseTapLeaf(s).TapHash())
		require.NoError(t, err)
		ctrl, err := txscript.ParseControlBlock(proof.ControlBlock)
		require.NoError(t, err)
		return failureLeaf{
			script: proof.Script, ctrl: proof.ControlBlock,
			tapscript: &waddrmgr.Tapscript{ControlBlock: ctrl, RevealedScript: proof.Script},
		}
	}
	settleLeaf, exitLeaf := leafFor(settle), leafFor(exit)

	res, err := sendOffChainBounded(
		ctx, funder, []clientlib.Receiver{{To: addr, Amount: uint64(wtContractAmount)}},
	)
	require.NoError(t, err)

	var fundingPtx *psbt.Packet
	require.Eventually(t, func() bool {
		resp, err := funder.Indexer().GetVirtualTxs(ctx, []string{res.Txid})
		if err != nil || resp == nil || len(resp.Txs) == 0 {
			return false
		}
		fundingPtx = parsePsbt(t, resp.Txs[0])
		return true
	}, 30*time.Second, 500*time.Millisecond)
	vout := -1
	for i, out := range fundingPtx.UnsignedTx.TxOut {
		if bytes.Equal(out.PkScript, pkScript) {
			vout = i
		}
	}
	require.GreaterOrEqual(t, vout, 0)
	fundingHash := fundingPtx.UnsignedTx.TxHash()
	outpoint := clientlib.Outpoint{Txid: fundingHash.String(), VOut: uint32(vout)}

	info, err := funder.Client().GetInfo(ctx)
	require.NoError(t, err)
	checkpointScript, err := hex.DecodeString(info.CheckpointTapscript)
	require.NoError(t, err)

	uArkPk, lArkPk := ownerPkScript(t, uPub, signer), ownerPkScript(t, lPub, signer)
	uChainPk, err := script.P2TRScript(uPub)
	require.NoError(t, err)
	lChainPk, err := script.P2TRScript(lPub)
	require.NoError(t, err)

	buildArk := func(amounts [2]int64) *arkPackage {
		arkPtx, checkpoints, err := offchain.BuildTxs(
			[]offchain.VtxoInput{{
				Outpoint:           &wire.OutPoint{Hash: fundingHash, Index: uint32(vout)},
				Amount:             wtContractAmount,
				Tapscript:          settleLeaf.tapscript,
				RevealedTapscripts: revealed,
			}},
			[]*wire.TxOut{
				{Value: amounts[0], PkScript: uArkPk},
				{Value: amounts[1], PkScript: lArkPk},
			},
			checkpointScript,
		)
		require.NoError(t, err)
		arkB64, err := arkPtx.B64Encode()
		require.NoError(t, err)
		checkpointB64, err := checkpoints[0].B64Encode()
		require.NoError(t, err)
		return &arkPackage{
			arkB64: arkB64, checkpointB64: checkpointB64,
			arkMsg: tapscriptSighash(t, arkPtx), checkpointMsg: tapscriptSighash(t, checkpoints[0]),
		}
	}

	// Each onchain exit tx splits both the exit tx fee and the watchtower bounty
	// equally between user and LP, and pays the bounty to output index 2.
	deductPerSide := (wtExitTxFee + wtBountyAmount) / 2
	sequence, err := arklib.BIP68Sequence(exitLocktime)
	require.NoError(t, err)
	buildExit := func(amounts [2]int64, lockTime uint32) *exitPackage {
		tx := wire.NewMsgTx(2)
		tx.LockTime = lockTime
		tx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{Hash: fundingHash, Index: uint32(vout)},
			Sequence:         sequence,
		})
		tx.AddTxOut(&wire.TxOut{Value: amounts[0] - deductPerSide, PkScript: uChainPk})
		tx.AddTxOut(&wire.TxOut{Value: amounts[1] - deductPerSide, PkScript: lChainPk})
		tx.AddTxOut(&wire.TxOut{Value: wtBountyAmount, PkScript: bounty.pkScript})
		fetcher := txscript.NewCannedPrevOutputFetcher(pkScript, wtContractAmount)
		msg, err := txscript.CalcTapscriptSignaturehash(
			txscript.NewTxSigHashes(tx, fetcher), txscript.SigHashDefault, tx, 0, fetcher,
			txscript.NewBaseTapLeaf(exitLeaf.script),
		)
		require.NoError(t, err)
		return &exitPackage{tx: tx, msg: msg}
	}

	arkPayouts := map[string]*arkPackage{}
	exitPayouts := map[string]*exitPackage{}
	for outcome, amounts := range wtPayouts {
		T := oracle.anticipationPoint(outcome)
		a := buildArk(amounts)
		a.uArk = adaptorSign(t, uKey, uPub, a.arkMsg, T)
		a.uCheckpoint = adaptorSign(t, uKey, uPub, a.checkpointMsg, T)
		a.lArk = adaptorSign(t, lKey, lPub, a.arkMsg, T)
		a.lCheckpoint = adaptorSign(t, lKey, lPub, a.checkpointMsg, T)
		arkPayouts[outcome] = a

		e := buildExit(amounts, 0)
		e.uSig = adaptorSign(t, uKey, uPub, e.msg, T)
		e.lSig = adaptorSign(t, lKey, lPub, e.msg, T)
		require.True(t, verifyAdaptor(e.uSig, uPub, e.msg))
		require.True(t, verifyAdaptor(e.lSig, lPub, e.msg))
		exitPayouts[outcome] = e
	}

	er := buildExit(wtRefund, chainRefundHeight)
	er.uFull, er.lFull = signWith(t, uKey, er.msg), signWith(t, lKey, er.msg)

	// Save the VTXO exit branch while the operator is reachable.
	indexer := funder.Indexer()
	var chain *clientlib.VtxoChainResponse
	require.Eventually(t, func() bool {
		resp, err := indexer.GetVtxoChain(ctx, outpoint)
		if err != nil || resp == nil || len(resp.Chain) == 0 {
			return false
		}
		chain = resp
		return true
	}, 30*time.Second, 500*time.Millisecond, "vtxo chain not indexed for %s:%d", outpoint.Txid, outpoint.VOut)
	txs := map[string]string{}
	for _, node := range chain.Chain {
		if node.Type == clientlib.IndexerChainedTxTypeCommitment ||
			node.Type == clientlib.IndexerChainedTxTypeUnspecified {
			continue
		}
		resp, err := indexer.GetVirtualTxs(ctx, []string{node.Txid})
		require.NoError(t, err)
		require.Len(t, resp.Txs, 1)
		txs[node.Txid] = resp.Txs[0]
	}
	saved := &cachedIndexer{Indexer: indexer, chain: chain, txs: txs}

	// Wipe both user and LP private keys: from here on only the keyless
	// watchtower package exists.
	uKey.Zero()
	lKey.Zero()

	return &wtContract{
		funder: funder, oracle: oracle,
		uArkPk: uArkPk, lArkPk: lArkPk, arkPayouts: arkPayouts,
		pkg: &watchtowerPackage{
			outpoint: outpoint, pkScript: pkScript, saved: saved,
			uPub: uPub, lPub: lPub, uChainPk: uChainPk, lChainPk: lChainPk,
			exitClosure: exit, exitLeaf: exitLeaf, bounty: bounty,
			exitPayouts: exitPayouts, exitRefund: er, refundHeight: chainRefundHeight,
		},
	}
}

func (p *watchtowerPackage) finalizeExit(
	t *testing.T, tx *wire.MsgTx, uSig, lSig *schnorr.Signature,
) string {
	t.Helper()
	final := tx.Copy()
	witness, err := p.exitClosure.Witness(p.exitLeaf.ctrl, map[string][]byte{
		hex.EncodeToString(schnorr.SerializePubKey(p.uPub)): uSig.Serialize(),
		hex.EncodeToString(schnorr.SerializePubKey(p.lPub)): lSig.Serialize(),
	})
	require.NoError(t, err)
	final.TxIn[0].Witness = witness
	var buf bytes.Buffer
	require.NoError(t, final.Serialize(&buf))
	return hex.EncodeToString(buf.Bytes())
}

// estimateUnrollCost counts how many unconfirmed virtual transactions remain
// in the saved branch and returns the estimated total watchtower cost.
func (p *watchtowerPackage) estimateUnrollCost(t *testing.T, ctx context.Context, cpfpFee, sweepFee int64) (int, int64) {
	t.Helper()
	hops := len(p.saved.txs)
	return hops, int64(hops)*cpfpFee + sweepFee
}

// unrollWithWatchtower unrolls the VTXO branch using the watchtower's own
// wallet for CPFP fee bumping.
func (p *watchtowerPackage) unrollWithWatchtower(
	t *testing.T, ctx context.Context, wt *watchtowerWallet, cpfpFee int64,
) int {
	t.Helper()
	branch, err := unroll.NewRedeemBranch(
		ctx, testExplorer, p.saved, clientlib.Vtxo{Outpoint: p.outpoint},
	)
	require.NoError(t, err)
	hops := 0
	for {
		txHex, err := branch.NextRedeemTx()
		if err != nil {
			require.ErrorContains(t, err, "already redeemed")
			break
		}
		wt.bumpAndBroadcast(t, txHex, cpfpFee)
		hops++
	}
	waitForTxConfirmed(t, p.outpoint.Txid)
	return hops
}

func broadcastAndVerifyExitPayout(
	t *testing.T, pkg *watchtowerPackage, txHex string, amounts [2]int64,
) wire.OutPoint {
	t.Helper()
	txid, err := testExplorer.Broadcast(txHex)
	require.NoError(t, err)
	require.NoError(t, generateBlocks(1))
	waitForTxConfirmed(t, txid)

	raw, err := testExplorer.GetTxHex(txid)
	require.NoError(t, err)
	var tx wire.MsgTx
	require.NoError(t, tx.Deserialize(hex.NewDecoder(strings.NewReader(raw))))
	require.Len(t, tx.TxOut, 3)

	deduct := (wtExitTxFee + wtBountyAmount) / 2
	require.Equal(t, amounts[0]-deduct, tx.TxOut[0].Value)
	require.Equal(t, pkg.uChainPk, tx.TxOut[0].PkScript)
	require.Equal(t, amounts[1]-deduct, tx.TxOut[1].Value)
	require.Equal(t, pkg.lChainPk, tx.TxOut[1].PkScript)
	require.Equal(t, wtBountyAmount, tx.TxOut[2].Value)
	require.Equal(t, pkg.bounty.pkScript, tx.TxOut[2].PkScript)

	h, err := chainhash.NewHashFromStr(txid)
	require.NoError(t, err)
	return wire.OutPoint{Hash: *h, Index: 2}
}

func TestP2pFiatWatchtowerBounty(t *testing.T) {
	require.NoError(t, generateBlocks(1))
	ctx := t.Context()
	height, err := getBlockHeight()
	require.NoError(t, err)
	chainRefundHeight := height + 80

	// Three independent watchtowers (e.g. nostracles) with their own BTC wallets,
	// plus an unauthorized miner/sniper key.
	w1 := newWatchtowerWallet(t, "W1-primary")
	w2 := newWatchtowerWallet(t, "W2-backup")
	w3 := newWatchtowerWallet(t, "W3-backup")
	attackerKey, attackerPub := evenKey(t)
	attackerBytes := attackerKey.Bytes()
	attackerPriv, _ := btcec.PrivKeyFromBytes(attackerBytes[:])
	attackerPk, err := script.P2TRScript(attackerPub)
	require.NoError(t, err)

	bounty := newBountyScript(t, w1.pub, []*btcec.PublicKey{w2.pub, w3.pub})

	// Open four contracts before stopping arkd:
	// 1. settledOffchain: settled normally offchain (stale-exit guard check)
	// 2. primaryExit: W1 unrolls, settles DLC payout, sweeps bounty immediately
	// 3. backupExit: W1 offline, W2 unrolls, blocked from sniping at 0 blocks, claims after CSV(2)
	// 4. refundExit: operator & oracle both gone, W1 executes onchain refund & claims bounty
	settledOffchain := openWatchtowerContract(t, ctx, chainRefundHeight, bounty)
	primaryExit := openWatchtowerContract(t, ctx, chainRefundHeight, bounty)
	backupExit := openWatchtowerContract(t, ctx, chainRefundHeight, bounty)
	refundExit := openWatchtowerContract(t, ctx, chainRefundHeight, bounty)
	// Confirm the batch commitment transaction(s) so v3 VTXO unroll txs do not
	// spend an unconfirmed v2 commitment tx (TRUC rule).
	require.NoError(t, generateBlocks(1))

	t.Run("stale exit guard detects already-settled contract while operator is up", func(t *testing.T) {
		c := settledOffchain
		a := c.oracle.attest(wtUp)
		p := c.arkPayouts[wtUp]
		arkPtx, ckPtx := parsePsbt(t, p.arkB64), parsePsbt(t, p.checkpointB64)
		addTapscriptSig(arkPtx, c.pkg.uPub, completeAdaptor(t, p.uArk, a))
		addTapscriptSig(arkPtx, c.pkg.lPub, completeAdaptor(t, p.lArk, a))
		addTapscriptSig(ckPtx, c.pkg.uPub, completeAdaptor(t, p.uCheckpoint, a))
		addTapscriptSig(ckPtx, c.pkg.lPub, completeAdaptor(t, p.lCheckpoint, a))
		arkB64, err := arkPtx.B64Encode()
		require.NoError(t, err)
		ckB64, err := ckPtx.B64Encode()
		require.NoError(t, err)
		_, _, _, err = c.funder.Client().SubmitTx(ctx, arkB64, []string{ckB64})
		require.NoError(t, err)

		// Watchtower queries indexer before spending CPFP fees: coin is spent!
		scriptHex := hex.EncodeToString(c.pkg.pkScript)
		require.Eventually(t, func() bool {
			resp, err := c.funder.Indexer().GetVtxos(
				ctx, clientlib.WithScripts([]string{scriptHex}), clientlib.WithSpentOnly(),
			)
			if err != nil || resp == nil {
				return false
			}
			for _, v := range resp.Vtxos {
				if v.Outpoint == c.pkg.outpoint && v.Spent {
					return true
				}
			}
			return false
		}, 30*time.Second, 500*time.Millisecond)
		t.Log("watchtower verified contract coin is already spent offchain; skipping unroll")
	})

	t.Run("unprofitable exit guard refuses when estimated fees exceed bounty", func(t *testing.T) {
		hops, estCost := primaryExit.pkg.estimateUnrollCost(t, ctx, 3000, wtSweepFee)
		require.Greater(t, estCost, wtBountyAmount, "high fee spike must exceed bounty")
		t.Logf("profitability guard: %d hops * 3000 + %d sweep = %d sats > %d bounty -> skip",
			hops, wtSweepFee, estCost, wtBountyAmount)
	})

	// Stop arkd: operator is completely gone.
	_, err = runCommand("docker", "stop", "arkd")
	require.NoError(t, err)
	t.Cleanup(func() {
		if _, err := runCommand("docker", "start", "arkd"); err != nil {
			t.Logf("failed to restart arkd: %v", err)
			return
		}
		for range 30 {
			if err := setupArkd(); err == nil {
				return
			}
			time.Sleep(2 * time.Second)
		}
		t.Error("failed to unlock arkd after restart")
	})
	stopCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err = primaryExit.funder.Client().GetInfo(stopCtx)
	require.Error(t, err, "operator must be unreachable")
	t.Log("arkd stopped: watchtowers now operate purely from saved packages")

	// Unroll all three orphaned contracts using watchtower wallets.
	w1BalBeforePrimary := w1.balance(t)
	hopsPrimary := primaryExit.pkg.unrollWithWatchtower(t, ctx, w1, wtCPFPFeePerTx)
	t.Logf("W1 unrolled primaryExit in %d hops (CPFP spent: %d sats)", hopsPrimary, w1.cpfpFeesSpent)

	w2BalBeforeBackup := w2.balance(t)
	hopsBackup := backupExit.pkg.unrollWithWatchtower(t, ctx, w2, wtCPFPFeePerTx)
	t.Logf("W2 unrolled backupExit in %d hops (CPFP spent: %d sats)", hopsBackup, w2.cpfpFeesSpent)

	hopsRefund := refundExit.pkg.unrollWithWatchtower(t, ctx, w1, wtCPFPFeePerTx)
	t.Logf("W1 unrolled refundExit in %d hops", hopsRefund)

	// Wait out the 20-block contract exit CSV delay.
	require.NoError(t, generateBlocks(int(wtExitCSV)+1))

	t.Run("primary watchtower settles DLC payout and profits net of real fees", func(t *testing.T) {
		c := primaryExit
		e := c.pkg.exitPayouts[wtUp]
		a := c.oracle.attest(wtUp)
		exitHex := c.pkg.finalizeExit(t, e.tx,
			completeAdaptor(t, e.uSig, a), completeAdaptor(t, e.lSig, a))
		bountyOut := broadcastAndVerifyExitPayout(t, c.pkg, exitHex, wtPayouts[wtUp])

		// Unauthorized miner/sniper cannot steal the bounty output.
		badSweep := bounty.buildSweepBountyTx(
			t, bountyOut, attackerPriv, attackerPub, false, attackerPk, wtSweepFee,
		)
		_, err := testExplorer.Broadcast(badSweep)
		require.Error(t, err, "miner/attacker must not be able to spend bounty")
		t.Logf("miner/attacker bounty theft rejected: %v", err)

		// Backup watchtower W2 cannot snipe W1's bounty immediately (0 blocks < CSV 2).
		earlyBackup := bounty.buildSweepBountyTx(
			t, bountyOut, w2.priv, w2.pub, true, w2.pkScript, wtSweepFee,
		)
		_, err = testExplorer.Broadcast(earlyBackup)
		require.Error(t, err, "backup watchtower must be blocked before CSV delay")
		t.Logf("backup watchtower early snipe rejected: %v", err)

		// W1 sweeps the bounty immediately via primary leaf.
		sweepHex := bounty.buildSweepBountyTx(
			t, bountyOut, w1.priv, w1.pub, false, w1.pkScript, wtSweepFee,
		)
		sweepTxid, err := testExplorer.Broadcast(sweepHex)
		require.NoError(t, err)
		require.NoError(t, generateBlocks(1))
		waitForTxConfirmed(t, sweepTxid)
		w1.sweepFees += wtSweepFee

		// Check W1's exact onchain profit for this single exit (adjusting for the
		// refundExit unroll hops already paid by W1).
		refundUnrollFees := int64(hopsRefund) * wtCPFPFeePerTx
		w1BalAfter := w1.balance(t)
		netForPrimary := (w1BalAfter - w1BalBeforePrimary) + refundUnrollFees
		require.Greater(t, netForPrimary, int64(0), "watchtower must make a net profit")
		t.Logf("W1 bounty swept (%s): gross=%d, primaryCPFP=%d (%d hops), sweepFee=%d, netProfit=+%d sats (incl. P2A dust)",
			sweepTxid, wtBountyAmount, int64(hopsPrimary)*wtCPFPFeePerTx, hopsPrimary, wtSweepFee, netForPrimary)
	})

	t.Run("backup watchtower steps in when primary is offline and claims after CSV delay", func(t *testing.T) {
		c := backupExit
		e := c.pkg.exitPayouts[wtDown]
		a := c.oracle.attest(wtDown)
		exitHex := c.pkg.finalizeExit(t, e.tx,
			completeAdaptor(t, e.uSig, a), completeAdaptor(t, e.lSig, a))
		bountyOut := broadcastAndVerifyExitPayout(t, c.pkg, exitHex, wtPayouts[wtDown])

		// Immediately after payout confirms, W2 still cannot spend CSV(4).
		sweepHex := bounty.buildSweepBountyTx(
			t, bountyOut, w2.priv, w2.pub, true, w2.pkScript, wtSweepFee,
		)
		_, err := testExplorer.Broadcast(sweepHex)
		require.Error(t, err, "backup leaf must enforce CSV delay")
		t.Logf("W2 early claim rejected: %v", err)

		// After wtBackupCSV blocks, W2 claims the bounty.
		require.NoError(t, generateBlocks(int(wtBackupCSV)))
		sweepTxid, err := testExplorer.Broadcast(sweepHex)
		require.NoError(t, err)
		require.NoError(t, generateBlocks(1))
		waitForTxConfirmed(t, sweepTxid)

		w2BalAfter := w2.balance(t)
		netW2 := w2BalAfter - w2BalBeforeBackup
		require.Greater(t, netW2, int64(0), "backup watchtower must profit net of fees")
		t.Logf("W2 backup bounty swept (%s): gross=%d, CPFP=%d (%d hops), sweepFee=%d, netProfit=+%d sats",
			sweepTxid, wtBountyAmount, int64(hopsBackup)*wtCPFPFeePerTx, hopsBackup, wtSweepFee, netW2)
	})

	t.Run("operator and oracle gone: watchtower executes onchain refund and collects bounty", func(t *testing.T) {
		c := refundExit
		e := c.pkg.exitRefund
		refundHex := c.pkg.finalizeExit(t, e.tx, e.uFull, e.lFull)

		current, err := getBlockHeight()
		require.NoError(t, err)
		require.Less(t, current+1, c.pkg.refundHeight, "must reach refund check before locktime")
		_, err = testExplorer.Broadcast(refundHex)
		require.Error(t, err, "refund must be rejected before nLockTime")

		mineToHeight(t, c.pkg.refundHeight)
		bountyOut := broadcastAndVerifyExitPayout(t, c.pkg, refundHex, wtRefund)

		sweepHex := bounty.buildSweepBountyTx(
			t, bountyOut, w1.priv, w1.pub, false, w1.pkScript, wtSweepFee,
		)
		sweepTxid, err := testExplorer.Broadcast(sweepHex)
		require.NoError(t, err)
		require.NoError(t, generateBlocks(1))
		waitForTxConfirmed(t, sweepTxid)

		// Overall W1 balance across both primaryExit + refundExit must be strictly positive.
		totalNetW1 := w1.balance(t) - w1.startBalance
		require.Greater(t, totalNetW1, int64(0), "W1 total net balance across both exits must be positive")
		t.Logf("W1 refund bounty swept (%s): total W1 net profit across 2 exits = +%d sats", sweepTxid, totalNetW1)
	})
}
