package e2e_test

// Experiment 2 (docs/ark-architecture.md, "Next steps"): with the operator, LP
// or oracle gone, can each party recover the correct amount, and which exit leaf
// achieves this?
//
// Each contract is opened once. Both parties then wipe their keys, so every
// recovery below can only use data pre-signed at opening.
//
// Needs the helpers in ../01-offline-settlement. Copy both test files into
// arkd's internal/test/e2e directory and run with:
//   go test -v -count 1 -run TestP2pFiatFailure ./internal/test/e2e

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
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/unroll"
	wallet "github.com/arkade-os/arkd/pkg/client-wallet"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

const (
	failureAmount  = int64(20000)
	failureExitFee = int64(1000) // split equally in onchain payouts
	failureUp      = "BTCUSD-settles-up"
	failureDown    = "BTCUSD-settles-down"
)

var failurePayouts = map[string][2]int64{failureUp: {14000, 6000}, failureDown: {8000, 12000}}

var failureRefund = [2]int64{10000, 10000}

type failureLeaf struct {
	script    []byte
	ctrl      []byte
	tapscript *waddrmgr.Tapscript
}

type arkPackage struct {
	arkB64, checkpointB64                       string
	arkMsg, checkpointMsg                       []byte
	uArk, uCheckpoint, lArk, lCheckpoint        *adaptorSig
	uArkFull, uCheckpointFull, lArkFull, lCkFull *schnorr.Signature
}

type exitPackage struct {
	tx         *wire.MsgTx
	msg        []byte
	uSig, lSig *adaptorSig
	uFull      *schnorr.Signature
	lFull      *schnorr.Signature
}

type failureContract struct {
	funder       wallet.Wallet
	oracle       *testOracle
	uPub, lPub   *btcec.PublicKey
	pkScript     []byte
	outpoint     clientlib.Outpoint
	exitClosure  *script.CSVMultisigClosure
	exitLeaf     failureLeaf
	uArkPk       []byte
	lArkPk       []byte
	uChainPk     []byte
	lChainPk     []byte
	arkPayouts   map[string]*arkPackage
	exitPayouts  map[string]*exitPackage
	arkRefund    *arkPackage
	exitRefund   *exitPackage
	refundHeight uint32
}

func signWith(t *testing.T, d btcec.ModNScalar, msg []byte) *schnorr.Signature {
	t.Helper()
	b := d.Bytes()
	priv, _ := btcec.PrivKeyFromBytes(b[:])
	sig, err := schnorr.Sign(priv, msg)
	require.NoError(t, err)
	return sig
}

func openFailureContract(
	t *testing.T, ctx context.Context, arkRefundHeight, chainRefundHeight uint32,
) *failureContract {
	t.Helper()
	funder := setupClientWallet(t)
	_, offchainAddr, _, err := funder.Receive(ctx)
	require.NoError(t, err)
	funderAddr, err := arklib.DecodeAddressV0(offchainAddr.Address)
	require.NoError(t, err)
	faucetOffchain(t, funder, 0.00021)
	signer := funderAddr.Signer

	uKey, uPub := evenKey(t)
	lKey, lPub := evenKey(t)
	oracle := newTestOracle(t)

	settle := &script.MultisigClosure{PubKeys: []*btcec.PublicKey{uPub, lPub, signer}}
	refund := &script.CLTVMultisigClosure{
		Locktime:        arklib.AbsoluteLocktime(arkRefundHeight),
		MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{uPub, lPub, signer}},
	}
	exitLocktime := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 20}
	exit := &script.CSVMultisigClosure{
		Locktime:        exitLocktime,
		MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{uPub, lPub}},
	}
	vs := script.TapscriptsVtxoScript{Closures: []script.Closure{settle, refund, exit}}
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
	settleLeaf, refundLeaf, exitLeaf := leafFor(settle), leafFor(refund), leafFor(exit)

	res, err := sendOffChainBounded(
		ctx, funder, []clientlib.Receiver{{To: addr, Amount: uint64(failureAmount)}},
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

	info, err := funder.Client().GetInfo(ctx)
	require.NoError(t, err)
	checkpointScript, err := hex.DecodeString(info.CheckpointTapscript)
	require.NoError(t, err)

	uArkPk, lArkPk := ownerPkScript(t, uPub, signer), ownerPkScript(t, lPub, signer)
	uChainPk, err := script.P2TRScript(uPub)
	require.NoError(t, err)
	lChainPk, err := script.P2TRScript(lPub)
	require.NoError(t, err)

	buildArk := func(leaf failureLeaf, amounts [2]int64) *arkPackage {
		arkPtx, checkpoints, err := offchain.BuildTxs(
			[]offchain.VtxoInput{{
				Outpoint:           &wire.OutPoint{Hash: fundingHash, Index: uint32(vout)},
				Amount:             failureAmount,
				Tapscript:          leaf.tapscript,
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

	sequence, err := arklib.BIP68Sequence(exitLocktime)
	require.NoError(t, err)
	buildExit := func(amounts [2]int64, lockTime uint32) *exitPackage {
		tx := wire.NewMsgTx(2)
		tx.LockTime = lockTime
		tx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: wire.OutPoint{Hash: fundingHash, Index: uint32(vout)},
			Sequence:         sequence,
		})
		tx.AddTxOut(&wire.TxOut{Value: amounts[0] - failureExitFee/2, PkScript: uChainPk})
		tx.AddTxOut(&wire.TxOut{Value: amounts[1] - failureExitFee/2, PkScript: lChainPk})
		fetcher := txscript.NewCannedPrevOutputFetcher(pkScript, failureAmount)
		msg, err := txscript.CalcTapscriptSignaturehash(
			txscript.NewTxSigHashes(tx, fetcher), txscript.SigHashDefault, tx, 0, fetcher,
			txscript.NewBaseTapLeaf(exitLeaf.script),
		)
		require.NoError(t, err)
		return &exitPackage{tx: tx, msg: msg}
	}

	c := &failureContract{
		funder: funder, oracle: oracle, uPub: uPub, lPub: lPub, pkScript: pkScript,
		outpoint:    clientlib.Outpoint{Txid: fundingHash.String(), VOut: uint32(vout)},
		exitClosure: exit, exitLeaf: exitLeaf,
		uArkPk: uArkPk, lArkPk: lArkPk, uChainPk: uChainPk, lChainPk: lChainPk,
		arkPayouts: map[string]*arkPackage{}, exitPayouts: map[string]*exitPackage{},
		refundHeight: chainRefundHeight,
	}

	// Both parties adaptor-sign every outcome on both the Ark path and the exit leaf.
	for outcome, amounts := range failurePayouts {
		T := oracle.anticipationPoint(outcome)
		a := buildArk(settleLeaf, amounts)
		a.uArk = adaptorSign(t, uKey, uPub, a.arkMsg, T)
		a.uCheckpoint = adaptorSign(t, uKey, uPub, a.checkpointMsg, T)
		a.lArk = adaptorSign(t, lKey, lPub, a.arkMsg, T)
		a.lCheckpoint = adaptorSign(t, lKey, lPub, a.checkpointMsg, T)
		require.True(t, verifyAdaptor(a.uArk, uPub, a.arkMsg))
		require.True(t, verifyAdaptor(a.lArk, lPub, a.arkMsg))
		c.arkPayouts[outcome] = a

		e := buildExit(amounts, 0)
		e.uSig = adaptorSign(t, uKey, uPub, e.msg, T)
		e.lSig = adaptorSign(t, lKey, lPub, e.msg, T)
		require.True(t, verifyAdaptor(e.uSig, uPub, e.msg))
		require.True(t, verifyAdaptor(e.lSig, lPub, e.msg))
		c.exitPayouts[outcome] = e
	}

	// Refunds need no oracle, only a locktime.
	r := buildArk(refundLeaf, failureRefund)
	r.uArkFull, r.uCheckpointFull = signWith(t, uKey, r.arkMsg), signWith(t, uKey, r.checkpointMsg)
	r.lArkFull, r.lCkFull = signWith(t, lKey, r.arkMsg), signWith(t, lKey, r.checkpointMsg)
	c.arkRefund = r
	er := buildExit(failureRefund, chainRefundHeight)
	er.uFull, er.lFull = signWith(t, uKey, er.msg), signWith(t, lKey, er.msg)
	c.exitRefund = er

	// Both parties are now gone unless they hold the pre-signed data above.
	uKey.Zero()
	lKey.Zero()
	return c
}

func (c *failureContract) submitArk(
	t *testing.T, ctx context.Context, p *arkPackage,
	uArk, uCheckpoint, lArk, lCheckpoint *schnorr.Signature,
) (string, error) {
	t.Helper()
	arkPtx, checkpointPtx := parsePsbt(t, p.arkB64), parsePsbt(t, p.checkpointB64)
	addTapscriptSig(arkPtx, c.uPub, uArk)
	addTapscriptSig(arkPtx, c.lPub, lArk)
	addTapscriptSig(checkpointPtx, c.uPub, uCheckpoint)
	addTapscriptSig(checkpointPtx, c.lPub, lCheckpoint)
	arkB64, err := arkPtx.B64Encode()
	require.NoError(t, err)
	checkpointB64, err := checkpointPtx.B64Encode()
	require.NoError(t, err)
	txid, _, _, err := c.funder.Client().SubmitTx(ctx, arkB64, []string{checkpointB64})
	return txid, err
}

func (c *failureContract) requireArkPayout(
	t *testing.T, ctx context.Context, txid string, amounts [2]int64,
) {
	t.Helper()
	for i, pk := range [][]byte{c.uArkPk, c.lArkPk} {
		scriptHex := hex.EncodeToString(pk)
		require.Eventually(t, func() bool {
			resp, err := c.funder.Indexer().GetVtxos(ctx, clientlib.WithScripts([]string{scriptHex}))
			if err != nil || resp == nil {
				return false
			}
			for _, v := range resp.Vtxos {
				if v.Txid == txid && int64(v.Amount) == amounts[i] && !v.Spent {
					return true
				}
			}
			return false
		}, 30*time.Second, 500*time.Millisecond, "payout %d not found", i)
	}
	t.Logf("ark payout %s: user %d, LP %d sats", txid, amounts[0], amounts[1])
}

func (c *failureContract) finalizeExit(
	t *testing.T, tx *wire.MsgTx, uSig, lSig *schnorr.Signature,
) string {
	t.Helper()
	final := tx.Copy()
	witness, err := c.exitClosure.Witness(c.exitLeaf.ctrl, map[string][]byte{
		hex.EncodeToString(schnorr.SerializePubKey(c.uPub)): uSig.Serialize(),
		hex.EncodeToString(schnorr.SerializePubKey(c.lPub)): lSig.Serialize(),
	})
	require.NoError(t, err)
	final.TxIn[0].Witness = witness
	var buf bytes.Buffer
	require.NoError(t, final.Serialize(&buf))
	return hex.EncodeToString(buf.Bytes())
}

func (c *failureContract) requireChainPayout(t *testing.T, txHex string, amounts [2]int64) {
	t.Helper()
	txid, err := testExplorer.Broadcast(txHex)
	require.NoError(t, err)
	require.NoError(t, generateBlocks(1))
	waitForTxConfirmed(t, txid)
	raw, err := testExplorer.GetTxHex(txid)
	require.NoError(t, err)
	var tx wire.MsgTx
	require.NoError(t, tx.Deserialize(hex.NewDecoder(strings.NewReader(raw))))
	require.Len(t, tx.TxOut, 2)
	require.Equal(t, amounts[0]-failureExitFee/2, tx.TxOut[0].Value)
	require.Equal(t, c.uChainPk, tx.TxOut[0].PkScript)
	require.Equal(t, amounts[1]-failureExitFee/2, tx.TxOut[1].Value)
	require.Equal(t, c.lChainPk, tx.TxOut[1].PkScript)
	t.Logf("onchain payout %s: user %d, LP %d sats after fees", txid, tx.TxOut[0].Value, tx.TxOut[1].Value)
}

// cachedIndexer serves a coin's exit data after the operator has disappeared.
type cachedIndexer struct {
	clientlib.Indexer
	chain *clientlib.VtxoChainResponse
	txs   map[string]string
}

func (i *cachedIndexer) GetVtxoChain(
	context.Context, clientlib.Outpoint, ...clientlib.PageOption,
) (*clientlib.VtxoChainResponse, error) {
	return i.chain, nil
}

func (i *cachedIndexer) GetVirtualTxs(
	_ context.Context, txids []string, _ ...clientlib.PageOption,
) (*clientlib.VirtualTxsResponse, error) {
	out := make([]string, 0, len(txids))
	for _, txid := range txids {
		tx, ok := i.txs[txid]
		if !ok {
			return nil, fmt.Errorf("exit data for %s was not saved", txid)
		}
		out = append(out, tx)
	}
	return &clientlib.VirtualTxsResponse{Txs: out}, nil
}

func (c *failureContract) saveExitData(t *testing.T, ctx context.Context) *cachedIndexer {
	t.Helper()
	indexer := c.funder.Indexer()
	chain, err := indexer.GetVtxoChain(ctx, c.outpoint)
	require.NoError(t, err)
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
	return &cachedIndexer{Indexer: indexer, chain: chain, txs: txs}
}

func (c *failureContract) unrollFromSavedData(
	t *testing.T, ctx context.Context, saved *cachedIndexer,
) {
	t.Helper()
	branch, err := unroll.NewRedeemBranch(
		ctx, testExplorer, saved, clientlib.Vtxo{Outpoint: c.outpoint},
	)
	require.NoError(t, err)
	broadcast := 0
	for {
		tx, err := branch.NextRedeemTx()
		if err != nil {
			require.ErrorContains(t, err, "already redeemed")
			break
		}
		bumpAndBroadcastTx(t, tx, testExplorer)
		broadcast++
	}
	waitForTxConfirmed(t, c.outpoint.Txid)
	t.Logf("contract coin onchain after %d transactions", broadcast)
}

func mineToHeight(t *testing.T, height uint32) {
	t.Helper()
	current, err := getBlockHeight()
	require.NoError(t, err)
	if current < height {
		require.NoError(t, generateBlocks(int(height-current)))
	}
}

// TestP2pFiatFailure1Expiry: nobody acts before the batch expires.
func TestP2pFiatFailure1Expiry(t *testing.T) {
	require.NoError(t, generateBlocks(1))
	ctx := t.Context()
	height, err := getBlockHeight()
	require.NoError(t, err)
	c := openFailureContract(t, ctx, height+5, height+60)
	saved := c.saveExitData(t, ctx)

	require.NoError(t, generateBlocks(50))
	scriptHex := hex.EncodeToString(c.pkScript)
	waitUntil(t, sweepWait, "contract coin to be swept", func(ctx context.Context) error {
		resp, err := c.funder.Indexer().GetVtxos(
			ctx, clientlib.WithScripts([]string{scriptHex}), clientlib.WithRecoverableOnly(),
		)
		if err != nil {
			return err
		}
		if resp == nil || len(resp.Vtxos) == 0 || !resp.Vtxos[0].Swept {
			return fmt.Errorf("not swept yet")
		}
		return nil
	})
	t.Log("operator swept the expired contract coin")

	branch, err := unroll.NewRedeemBranch(
		ctx, testExplorer, saved, clientlib.Vtxo{Outpoint: c.outpoint},
	)
	require.NoError(t, err)
	txHex, err := branch.NextRedeemTx()
	require.NoError(t, err)
	var parent wire.MsgTx
	require.NoError(t, parent.Deserialize(hex.NewDecoder(strings.NewReader(txHex))))
	child := bumpAnchorTx(t, &parent, testExplorer)
	_, err = testExplorer.Broadcast(txHex, child)
	require.Error(t, err, "exit must be impossible once the batch output is swept")
	t.Logf("exit after expiry rejected: %v", err)
}

// TestP2pFiatFailure2Paths covers one failure per contract.
func TestP2pFiatFailure2Paths(t *testing.T) {
	require.NoError(t, generateBlocks(1))
	ctx := t.Context()
	height, err := getBlockHeight()
	require.NoError(t, err)
	arkRefundHeight, chainRefundHeight := height+5, height+60

	lpGoneArk := openFailureContract(t, ctx, arkRefundHeight, chainRefundHeight)
	oracleGoneArk := openFailureContract(t, ctx, arkRefundHeight, chainRefundHeight)
	userExit := openFailureContract(t, ctx, arkRefundHeight, chainRefundHeight)
	lpExit := openFailureContract(t, ctx, arkRefundHeight, chainRefundHeight)
	refundExit := openFailureContract(t, ctx, arkRefundHeight, chainRefundHeight)

	t.Run("operator up, LP gone: user settles", func(t *testing.T) {
		c := lpGoneArk
		attestation := c.oracle.attest(failureUp)
		p := c.arkPayouts[failureUp]
		txid, err := c.submitArk(t, ctx, p,
			completeAdaptor(t, p.uArk, attestation),
			completeAdaptor(t, p.uCheckpoint, attestation),
			completeAdaptor(t, p.lArk, attestation),
			completeAdaptor(t, p.lCheckpoint, attestation),
		)
		require.NoError(t, err)
		c.requireArkPayout(t, ctx, txid, failurePayouts[failureUp])
	})

	t.Run("operator up, oracle gone: refund only after locktime", func(t *testing.T) {
		c := oracleGoneArk
		r := c.arkRefund
		_, err := c.submitArk(t, ctx, r, r.uArkFull, r.uCheckpointFull, r.lArkFull, r.lCkFull)
		require.Error(t, err, "refund must be rejected before its locktime")
		t.Logf("early refund rejected: %v", err)

		mineToHeight(t, arkRefundHeight+1)
		var txid string
		require.Eventually(t, func() bool {
			var err error
			txid, err = c.submitArk(t, ctx, r, r.uArkFull, r.uCheckpointFull, r.lArkFull, r.lCkFull)
			return err == nil
		}, 30*time.Second, time.Second, "refund not accepted after locktime")
		c.requireArkPayout(t, ctx, txid, failureRefund)
	})

	// Exit data must be saved while the operator is still reachable.
	savedUser := userExit.saveExitData(t, ctx)
	savedLP := lpExit.saveExitData(t, ctx)
	savedRefund := refundExit.saveExitData(t, ctx)

	_, err = runCommand("docker", "stop", "arkd")
	require.NoError(t, err)
	t.Cleanup(func() {
		if _, err := runCommand("docker", "start", "arkd"); err != nil {
			t.Logf("failed to restart arkd: %v", err)
			return
		}
		// The admin API can reset connections for a while after a restart.
		var err error
		for range 30 {
			if err = setupArkd(); err == nil {
				return
			}
			time.Sleep(2 * time.Second)
		}
		t.Errorf("failed to unlock arkd: %v", err)
	})
	stopCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err = userExit.funder.Client().GetInfo(stopCtx)
	require.Error(t, err, "operator must be unreachable")
	t.Log("operator stopped")

	userExit.unrollFromSavedData(t, ctx, savedUser)
	lpExit.unrollFromSavedData(t, ctx, savedLP)
	refundExit.unrollFromSavedData(t, ctx, savedRefund)

	t.Run("exit delay is enforced", func(t *testing.T) {
		e := userExit.exitPayouts[failureUp]
		a := userExit.oracle.attest(failureUp)
		hexTx := userExit.finalizeExit(t, e.tx,
			completeAdaptor(t, e.uSig, a), completeAdaptor(t, e.lSig, a))
		_, err := testExplorer.Broadcast(hexTx)
		require.Error(t, err)
		t.Logf("early exit rejected: %v", err)
	})

	require.NoError(t, generateBlocks(21))

	t.Run("operator and LP gone: wrong outcome fails", func(t *testing.T) {
		c := userExit
		e := c.exitPayouts[failureDown]
		a := c.oracle.attest(failureUp)
		uSig, lSig := completeAdaptor(t, e.uSig, a), completeAdaptor(t, e.lSig, a)
		require.False(t, uSig.Verify(e.msg, c.uPub))
		_, err := testExplorer.Broadcast(c.finalizeExit(t, e.tx, uSig, lSig))
		require.Error(t, err)
		t.Logf("wrong outcome rejected: %v", err)
	})

	t.Run("operator and LP gone: user claims correct amount", func(t *testing.T) {
		c := userExit
		e := c.exitPayouts[failureUp]
		a := c.oracle.attest(failureUp)
		c.requireChainPayout(t, c.finalizeExit(t, e.tx,
			completeAdaptor(t, e.uSig, a), completeAdaptor(t, e.lSig, a)), failurePayouts[failureUp])
	})

	t.Run("operator and user gone: LP claims correct amount", func(t *testing.T) {
		c := lpExit
		e := c.exitPayouts[failureDown]
		a := c.oracle.attest(failureDown)
		c.requireChainPayout(t, c.finalizeExit(t, e.tx,
			completeAdaptor(t, e.uSig, a), completeAdaptor(t, e.lSig, a)), failurePayouts[failureDown])
	})

	t.Run("operator and oracle gone: onchain refund after locktime", func(t *testing.T) {
		c := refundExit
		e := c.exitRefund
		hexTx := c.finalizeExit(t, e.tx, e.uFull, e.lFull)
		current, err := getBlockHeight()
		require.NoError(t, err)
		require.Less(t, current+1, c.refundHeight, "test must reach this point before the locktime")
		_, err = testExplorer.Broadcast(hexTx)
		require.Error(t, err)
		t.Logf("early onchain refund rejected: %v", err)

		mineToHeight(t, c.refundHeight)
		c.requireChainPayout(t, hexTx, failureRefund)
	})
}
