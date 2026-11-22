package e2e_test

// Experiment 4: a rolling DLC where 3 of 5 nostracles can roll for an absent
// user, only after a timelock, on terms fixed by a signed mandate.
//
// The nostracles are simulated in this process. Nostr transport, payments and a
// multi-oracle price are not part of this test.
//
// Needs the helpers in ../01-offline-settlement and ../02-failure-paths. Copy
// all three test files into arkd's internal/test/e2e directory and run with:
//   go test -v -count 1 -run TestP2pFiatGuardian ./internal/test/e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	batchsession "github.com/arkade-os/arkd/pkg/client-lib/batch-session"
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
	guardianAmount  = int64(20000)
	guardianExitFee = int64(1000)
	guardianMaxTerm = uint32(12)
	guardianDelay   = uint32(20)
	// arkd refuses an exit leaf that combines CLTV and CSV. A relative delay
	// longer than the longest term gives the same bound: the coin cannot be
	// onchain before it exists, so the quorum cannot claim it before the term ends.
	guardianQuorumDelay = uint32(25)
	guardianUp      = "BTCUSD-settles-up"
	guardianDown    = "BTCUSD-settles-down"
)

var guardianPayouts = map[string][2]int64{guardianUp: {14000, 6000}, guardianDown: {8000, 12000}}

var (
	errUserAlive = errors.New("user answered the liveness challenge")
	errMandate   = errors.New("roll violates the signed mandate")
	errTooEarly  = errors.New("timelock has not passed")
)

type guardianParty struct {
	d   btcec.ModNScalar
	pub *btcec.PublicKey
}

func newGuardianParty(t *testing.T) guardianParty {
	t.Helper()
	d, pub := evenKey(t)
	return guardianParty{d: d, pub: pub}
}

type guardianQuorum [3]int

func allGuardianQuorums() []guardianQuorum {
	var out []guardianQuorum
	for a := 0; a < 5; a++ {
		for b := a + 1; b < 5; b++ {
			for c := b + 1; c < 5; c++ {
				out = append(out, guardianQuorum{a, b, c})
			}
		}
	}
	return out
}

// guardianMandate holds the terms fixed when the user opens the contract.
type guardianMandate struct {
	user, lp   guardianParty
	nostracles [5]guardianParty
	signer     *btcec.PublicKey
	checkpoint []byte
}

func (m *guardianMandate) signers(q guardianQuorum) []guardianParty {
	return []guardianParty{m.nostracles[q[0]], m.nostracles[q[1]], m.nostracles[q[2]], m.lp}
}

type guardianCoin struct {
	term        uint32
	vs          script.TapscriptsVtxoScript
	pkScript    []byte
	addr        string
	revealed    []string
	userLeaf    failureLeaf
	quorumLeaf  map[guardianQuorum]failureLeaf
	exitLeaf    map[guardianQuorum]failureLeaf
	exitClosure map[guardianQuorum]*script.CSVMultisigClosure
}

func (m *guardianMandate) coin(t *testing.T, term uint32) *guardianCoin {
	t.Helper()
	exitDelay := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: guardianDelay}
	userSettle := &script.MultisigClosure{
		PubKeys: []*btcec.PublicKey{m.user.pub, m.lp.pub, m.signer},
	}
	closures := []script.Closure{
		userSettle,
		&script.CSVMultisigClosure{
			Locktime:        exitDelay,
			MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{m.user.pub, m.lp.pub}},
		},
	}
	quorumDelay := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: guardianQuorumDelay}

	settleClosures := map[guardianQuorum]script.Closure{}
	exitClosures := map[guardianQuorum]*script.CSVMultisigClosure{}
	for _, q := range allGuardianQuorums() {
		keys := []*btcec.PublicKey{
			m.nostracles[q[0]].pub, m.nostracles[q[1]].pub, m.nostracles[q[2]].pub, m.lp.pub,
		}
		settle := &script.CLTVMultisigClosure{
			Locktime:        arklib.AbsoluteLocktime(term),
			MultisigClosure: script.MultisigClosure{PubKeys: append(slices.Clone(keys), m.signer)},
		}
		exit := &script.CSVMultisigClosure{
			Locktime:        quorumDelay,
			MultisigClosure: script.MultisigClosure{PubKeys: keys},
		}
		settleClosures[q], exitClosures[q] = settle, exit
		closures = append(closures, settle, exit)
	}

	vs := script.TapscriptsVtxoScript{Closures: closures}
	tapKey, tapTree, err := vs.TapTree()
	require.NoError(t, err)
	pkScript, err := script.P2TRScript(tapKey)
	require.NoError(t, err)
	addr, err := (&arklib.Address{HRP: "tark", VtxoTapKey: tapKey, Signer: m.signer}).EncodeV0()
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
	coin := &guardianCoin{
		term: term, vs: vs, pkScript: pkScript, addr: addr, revealed: revealed,
		userLeaf: leafFor(userSettle), quorumLeaf: map[guardianQuorum]failureLeaf{},
		exitLeaf: map[guardianQuorum]failureLeaf{}, exitClosure: exitClosures,
	}
	for _, q := range allGuardianQuorums() {
		coin.quorumLeaf[q] = leafFor(settleClosures[q])
		coin.exitLeaf[q] = leafFor(exitClosures[q])
	}
	return coin
}

func guardianChallenge(pkScript []byte, epoch uint32) []byte {
	h := sha256.New()
	h.Write([]byte("p2pfiat/liveness"))
	h.Write(pkScript)
	_ = binary.Write(h, binary.LittleEndian, epoch)
	return h.Sum(nil)
}

type guardianRollRequest struct {
	current   *guardianCoin
	nextPk    []byte
	nextTerm  uint32
	nextValue int64
	height    uint32
	epoch     uint32
	heartbeat *schnorr.Signature
}

// approveRoll is the check each honest nostracle runs before it signs.
func (m *guardianMandate) approveRoll(t *testing.T, r guardianRollRequest) error {
	t.Helper()
	if r.height < r.current.term {
		return errTooEarly
	}
	if r.heartbeat != nil &&
		r.heartbeat.Verify(guardianChallenge(r.current.pkScript, r.epoch), m.user.pub) {
		return errUserAlive
	}
	if guardianMaxTerm >= guardianQuorumDelay {
		return errMandate
	}
	if r.nextTerm <= r.height || r.nextTerm > r.height+guardianMaxTerm {
		return errMandate
	}
	if r.nextValue != guardianAmount || !bytes.Equal(r.nextPk, m.coin(t, r.nextTerm).pkScript) {
		return errMandate
	}
	return nil
}

type guardianExitPayout struct {
	tx   *wire.MsgTx
	msg  []byte
	sigs []*adaptorSig
}

type guardianArkPayout struct {
	arkB64, checkpointB64 string
	arkMsg, checkpointMsg []byte
	arkSigs, cpSigs       []*adaptorSig
}

type guardianOpenCoin struct {
	m        *guardianMandate
	coin     *guardianCoin
	funder   wallet.Wallet
	outpoint wire.OutPoint
	oracle   *testOracle
	quorum   guardianQuorum
	exits    map[string]*guardianExitPayout
	arks     map[string]*guardianArkPayout
}

func (o *guardianOpenCoin) clientOutpoint() clientlib.Outpoint {
	return clientlib.Outpoint{Txid: o.outpoint.Hash.String(), VOut: o.outpoint.Index}
}

func (m *guardianMandate) outputs(t *testing.T, amounts [2]int64) []*wire.TxOut {
	t.Helper()
	return []*wire.TxOut{
		{Value: amounts[0], PkScript: ownerPkScript(t, m.user.pub, m.signer)},
		{Value: amounts[1], PkScript: ownerPkScript(t, m.lp.pub, m.signer)},
	}
}

func (o *guardianOpenCoin) buildArk(
	t *testing.T, leaf failureLeaf, outputs []*wire.TxOut,
) (*psbt.Packet, *psbt.Packet) {
	t.Helper()
	ark, checkpoints, err := offchain.BuildTxs([]offchain.VtxoInput{{
		Outpoint: &o.outpoint, Amount: guardianAmount,
		Tapscript: leaf.tapscript, RevealedTapscripts: o.coin.revealed,
	}}, outputs, o.m.checkpoint)
	require.NoError(t, err)
	require.Len(t, checkpoints, 1)
	return ark, checkpoints[0]
}

func (o *guardianOpenCoin) buildExit(
	t *testing.T, q guardianQuorum, amounts [2]int64, delay uint32,
) (*wire.MsgTx, []byte) {
	t.Helper()
	sequence, err := arklib.BIP68Sequence(
		arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: delay},
	)
	require.NoError(t, err)
	uPk, err := script.P2TRScript(o.m.user.pub)
	require.NoError(t, err)
	lPk, err := script.P2TRScript(o.m.lp.pub)
	require.NoError(t, err)
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: o.outpoint, Sequence: sequence})
	tx.AddTxOut(&wire.TxOut{Value: amounts[0] - guardianExitFee/2, PkScript: uPk})
	tx.AddTxOut(&wire.TxOut{Value: amounts[1] - guardianExitFee/2, PkScript: lPk})
	fetcher := txscript.NewCannedPrevOutputFetcher(o.coin.pkScript, guardianAmount)
	msg, err := txscript.CalcTapscriptSignaturehash(
		txscript.NewTxSigHashes(tx, fetcher), txscript.SigHashDefault, tx, 0, fetcher,
		txscript.NewBaseTapLeaf(o.coin.exitLeaf[q].script),
	)
	require.NoError(t, err)
	return tx, msg
}

// signPayouts adaptor-signs every outcome for this exact coin.
func (o *guardianOpenCoin) signPayouts(t *testing.T, q guardianQuorum) {
	t.Helper()
	o.quorum, o.oracle = q, newTestOracle(t)
	o.exits, o.arks = map[string]*guardianExitPayout{}, map[string]*guardianArkPayout{}
	signers := o.m.signers(q)
	adaptAll := func(msg []byte, T *btcec.PublicKey) []*adaptorSig {
		sigs := make([]*adaptorSig, 0, len(signers))
		for _, s := range signers {
			a := adaptorSign(t, s.d, s.pub, msg, T)
			require.True(t, verifyAdaptor(a, s.pub, msg))
			sigs = append(sigs, a)
		}
		return sigs
	}
	for outcome, amounts := range guardianPayouts {
		T := o.oracle.anticipationPoint(outcome)
		tx, msg := o.buildExit(t, q, amounts, guardianQuorumDelay)
		o.exits[outcome] = &guardianExitPayout{tx: tx, msg: msg, sigs: adaptAll(msg, T)}

		ark, checkpoint := o.buildArk(t, o.coin.quorumLeaf[q], o.m.outputs(t, amounts))
		arkMsg, cpMsg := tapscriptSighash(t, ark), tapscriptSighash(t, checkpoint)
		arkB64, err := ark.B64Encode()
		require.NoError(t, err)
		cpB64, err := checkpoint.B64Encode()
		require.NoError(t, err)
		o.arks[outcome] = &guardianArkPayout{
			arkB64: arkB64, checkpointB64: cpB64, arkMsg: arkMsg, checkpointMsg: cpMsg,
			arkSigs: adaptAll(arkMsg, T), cpSigs: adaptAll(cpMsg, T),
		}
	}
}

func (o *guardianOpenCoin) finalizeExit(
	t *testing.T, q guardianQuorum, tx *wire.MsgTx, sigs []*schnorr.Signature,
) string {
	t.Helper()
	closure := o.coin.exitClosure[q]
	args := map[string][]byte{}
	for i, s := range o.m.signers(q) {
		args[hex.EncodeToString(schnorr.SerializePubKey(s.pub))] = sigs[i].Serialize()
	}
	witness, err := closure.Witness(o.coin.exitLeaf[q].ctrl, args)
	require.NoError(t, err)
	final := tx.Copy()
	final.TxIn[0].Witness = witness
	var buf bytes.Buffer
	require.NoError(t, final.Serialize(&buf))
	return hex.EncodeToString(buf.Bytes())
}

func (o *guardianOpenCoin) completedExit(t *testing.T, outcome string) string {
	t.Helper()
	p := o.exits[outcome]
	secret := o.oracle.attest(outcome)
	sigs := make([]*schnorr.Signature, 0, len(p.sigs))
	for i, s := range o.m.signers(o.quorum) {
		sig := completeAdaptor(t, p.sigs[i], secret)
		require.True(t, sig.Verify(p.msg, s.pub))
		sigs = append(sigs, sig)
	}
	return o.finalizeExit(t, o.quorum, p.tx, sigs)
}

func (o *guardianOpenCoin) submitSigned(
	t *testing.T, ctx context.Context, ark, checkpoint *psbt.Packet, signers []guardianParty,
) (string, error) {
	t.Helper()
	arkMsg, cpMsg := tapscriptSighash(t, ark), tapscriptSighash(t, checkpoint)
	for _, s := range signers {
		addTapscriptSig(ark, s.pub, signWith(t, s.d, arkMsg))
		addTapscriptSig(checkpoint, s.pub, signWith(t, s.d, cpMsg))
	}
	arkB64, err := ark.B64Encode()
	require.NoError(t, err)
	cpB64, err := checkpoint.B64Encode()
	require.NoError(t, err)
	txid, _, _, err := o.funder.Client().SubmitTx(ctx, arkB64, []string{cpB64})
	return txid, err
}

func guardianWaitVtxo(
	t *testing.T, ctx context.Context, funder wallet.Wallet, outpoint clientlib.Outpoint,
) {
	t.Helper()
	require.Eventually(t, func() bool {
		resp, err := funder.Indexer().GetVtxos(ctx, clientlib.WithOutpoints([]clientlib.Outpoint{outpoint}))
		return err == nil && resp != nil && len(resp.Vtxos) == 1 && !resp.Vtxos[0].Spent
	}, 30*time.Second, 200*time.Millisecond, "coin %s not indexed", outpoint)
}

func (m *guardianMandate) open(t *testing.T, ctx context.Context, term uint32) *guardianOpenCoin {
	t.Helper()
	funder := setupClientWallet(t)
	faucetOffchain(t, funder, 0.00021)
	coin := m.coin(t, term)
	res, err := sendOffChainBounded(
		ctx, funder, []clientlib.Receiver{{To: coin.addr, Amount: uint64(guardianAmount)}},
	)
	require.NoError(t, err)
	var ptx *psbt.Packet
	require.Eventually(t, func() bool {
		resp, err := funder.Indexer().GetVirtualTxs(ctx, []string{res.Txid})
		if err != nil || resp == nil || len(resp.Txs) == 0 {
			return false
		}
		ptx = parsePsbt(t, resp.Txs[0])
		return true
	}, 30*time.Second, 200*time.Millisecond)
	vout := slices.IndexFunc(ptx.UnsignedTx.TxOut, func(out *wire.TxOut) bool {
		return bytes.Equal(out.PkScript, coin.pkScript)
	})
	require.GreaterOrEqual(t, vout, 0)
	o := &guardianOpenCoin{
		m: m, coin: coin, funder: funder,
		outpoint: wire.OutPoint{Hash: ptx.UnsignedTx.TxHash(), Index: uint32(vout)},
	}
	guardianWaitVtxo(t, ctx, funder, o.clientOutpoint())
	o.signPayouts(t, guardianQuorum{0, 1, 2})
	return o
}

func guardianSignInput(
	t *testing.T, ptx *psbt.Packet, index int, leafScript []byte, signers []guardianParty,
) {
	t.Helper()
	prevouts := map[wire.OutPoint]*wire.TxOut{}
	for i, in := range ptx.UnsignedTx.TxIn {
		prevouts[in.PreviousOutPoint] = ptx.Inputs[i].WitnessUtxo
	}
	fetcher := txscript.NewMultiPrevOutFetcher(prevouts)
	leaf := txscript.NewBaseTapLeaf(leafScript)
	msg, err := txscript.CalcTapscriptSignaturehash(
		txscript.NewTxSigHashes(ptx.UnsignedTx, fetcher), ptx.Inputs[index].SighashType,
		ptx.UnsignedTx, index, fetcher, leaf,
	)
	require.NoError(t, err)
	hash := leaf.TapHash()
	for _, s := range signers {
		ptx.Inputs[index].TaprootScriptSpendSig = append(
			ptx.Inputs[index].TaprootScriptSpendSig, &psbt.TaprootScriptSpendSig{
				XOnlyPubKey: schnorr.SerializePubKey(s.pub),
				LeafHash:    hash.CloneBytes(),
				Signature:   signWith(t, s.d, msg).Serialize(),
				SigHash:     ptx.Inputs[index].SighashType,
			},
		)
	}
}

func (o *guardianOpenCoin) registerRoll(
	t *testing.T, ctx context.Context, q guardianQuorum, nextPk []byte, cosigners []string,
) (string, string, error) {
	t.Helper()
	message, err := intent.RegisterMessage{
		BaseMessage:         intent.BaseMessage{Type: intent.IntentMessageTypeRegister},
		CosignersPublicKeys: cosigners,
	}.Encode()
	require.NoError(t, err)
	proof, err := intent.New(message, []intent.Input{{
		OutPoint:    &o.outpoint,
		Sequence:    wire.MaxTxInSequenceNum - 1,
		WitnessUtxo: &wire.TxOut{Value: guardianAmount, PkScript: o.coin.pkScript},
	}}, []*wire.TxOut{{Value: guardianAmount, PkScript: nextPk}})
	require.NoError(t, err)
	leaf := o.coin.quorumLeaf[q]
	tapLeaf := &psbt.TaprootTapLeafScript{
		ControlBlock: leaf.ctrl, Script: leaf.script, LeafVersion: txscript.BaseLeafVersion,
	}
	proof.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{tapLeaf}
	proof.Inputs[1].TaprootLeafScript = []*psbt.TaprootTapLeafScript{tapLeaf}
	proof.UnsignedTx.LockTime = o.coin.term
	proof.UnsignedTx.TxIn[0].Sequence = wire.MaxTxInSequenceNum - 1
	require.NoError(t, txutils.SetArkPsbtField(
		&proof.Packet, 1, txutils.VtxoTaprootTreeField, txutils.TapTree(o.coin.revealed),
	))
	signers := o.m.signers(q)
	guardianSignInput(t, &proof.Packet, 0, leaf.script, signers)
	guardianSignInput(t, &proof.Packet, 1, leaf.script, signers)
	encoded, err := proof.B64Encode()
	require.NoError(t, err)
	intentID, err := o.funder.Client().RegisterIntent(ctx, encoded, message)
	return intentID, message, err
}

// roll moves the position into a new coin. The quorum signs the new coin's
// payouts before it signs the forfeit of the old coin.
func (o *guardianOpenCoin) roll(
	t *testing.T, ctx context.Context, q guardianQuorum, nextTerm uint32,
) *guardianOpenCoin {
	t.Helper()
	next := o.m.coin(t, nextTerm)
	height, err := getBlockHeight()
	require.NoError(t, err)
	require.NoError(t, o.m.approveRoll(t, guardianRollRequest{
		current: o.coin, nextPk: next.pkScript, nextTerm: nextTerm,
		nextValue: guardianAmount, height: height, epoch: 1,
	}))

	sessions := make([]tree.SignerSession, 3)
	cosigners := make([]string, 3)
	for i := range sessions {
		sessions[i], err = tree.NewVtxoTreeSigner()
		require.NoError(t, err)
		cosigners[i] = sessions[i].GetPublicKey()
	}
	intentID, _, err := o.registerRoll(t, ctx, q, next.pkScript, cosigners)
	require.NoError(t, err)

	client := o.funder.Client()
	config, err := o.funder.GetConfigData(ctx)
	require.NoError(t, err)
	forfeitAddr, err := arklib.DecodeBitcoinAddress(config.ForfeitAddress, nil)
	require.NoError(t, err)
	forfeitPk, err := txscript.PayToAddrScript(forfeitAddr)
	require.NoError(t, err)

	rolled := &guardianOpenCoin{m: o.m, coin: next, funder: o.funder}
	var batchExpiry arklib.RelativeLocktime
	var batchID string
	handler := &customBatchEventsHandler{
		onBatchStarted: func(
			ctx context.Context, event clientlib.BatchStartedEvent,
		) (bool, time.Duration, error) {
			hash := sha256.Sum256([]byte(intentID))
			if !slices.Contains(event.HashedIntentIds, hex.EncodeToString(hash[:])) {
				return true, -1, nil
			}
			if err := client.ConfirmRegistration(ctx, intentID); err != nil {
				return false, -1, err
			}
			batchID = event.Id
			batchExpiry = getBatchExpiryLocktime(uint32(event.BatchExpiry))
			return false, time.Duration(event.BatchExpiry) * time.Second, nil
		},
		onBatchFailed: func(_ context.Context, event clientlib.BatchFailedEvent) error {
			if event.Id == batchID {
				return fmt.Errorf("batch failed: %s", event.Reason)
			}
			return nil
		},
		onTreeSigningStarted: func(
			ctx context.Context, event clientlib.TreeSigningStartedEvent, vtxoTree *tree.TxTree,
		) (bool, error) {
			if !slices.Contains(event.CosignersPubkeys, cosigners[0]) {
				return true, nil
			}
			sweep := script.CSVMultisigClosure{
				MultisigClosure: script.MultisigClosure{
					PubKeys: []*btcec.PublicKey{config.ForfeitPubKey},
				},
				Locktime: batchExpiry,
			}
			sweepScript, err := sweep.Script()
			if err != nil {
				return false, err
			}
			commitment, err := psbt.NewFromRawBytes(strings.NewReader(event.UnsignedCommitmentTx), true)
			if err != nil {
				return false, err
			}
			root := txscript.AssembleTaprootScriptTree(txscript.NewBaseTapLeaf(sweepScript)).
				RootNode.TapHash()
			for _, session := range sessions {
				if err := session.Init(root.CloneBytes(), commitment.UnsignedTx.TxOut[0].Value, vtxoTree); err != nil {
					return false, err
				}
				nonces, err := session.GetNonces()
				if err != nil {
					return false, err
				}
				if err := client.SubmitTreeNonces(ctx, event.Id, session.GetPublicKey(), nonces); err != nil {
					return false, err
				}
			}
			return false, nil
		},
		onTreeNoncesAggregated: func(
			ctx context.Context, event clientlib.TreeNoncesAggregatedEvent,
		) (bool, error) {
			for _, session := range sessions {
				session.SetAggregatedNonces(event.Nonces)
				sigs, err := session.Sign()
				if err != nil {
					return false, err
				}
				if err := client.SubmitTreeSignatures(ctx, event.Id, session.GetPublicKey(), sigs); err != nil {
					return false, err
				}
			}
			return true, nil
		},
		onBatchFinalization: func(
			ctx context.Context, _ clientlib.BatchFinalizationEvent,
			vtxoTree, connectorTree *tree.TxTree,
		) ([]string, error) {
			found := false
			for _, leaf := range vtxoTree.Leaves() {
				for vout, out := range leaf.UnsignedTx.TxOut {
					if out.Value == guardianAmount && bytes.Equal(out.PkScript, next.pkScript) {
						rolled.outpoint = wire.OutPoint{Hash: leaf.UnsignedTx.TxHash(), Index: uint32(vout)}
						found = true
					}
				}
			}
			if !found {
				return nil, fmt.Errorf("new contract coin not in the batch")
			}
			// New payouts first. Only then is the old coin given up.
			rolled.signPayouts(t, q)

			connector := connectorTree.Leaves()[0]
			forfeit, err := tree.BuildForfeitTxWithOutput(
				[]*wire.OutPoint{&o.outpoint},
				[]uint32{wire.MaxTxInSequenceNum - 1},
				[]*wire.TxOut{{Value: guardianAmount, PkScript: o.coin.pkScript}},
				&wire.TxOut{
					Value:    guardianAmount + connector.UnsignedTx.TxOut[0].Value,
					PkScript: forfeitPk,
				},
				o.coin.term,
			)
			if err != nil {
				return nil, err
			}
			forfeit.UnsignedTx.TxIn = append(forfeit.UnsignedTx.TxIn, &wire.TxIn{
				PreviousOutPoint: wire.OutPoint{Hash: connector.UnsignedTx.TxHash(), Index: 0},
				Sequence:         wire.MaxTxInSequenceNum,
			})
			forfeit.Inputs = append(forfeit.Inputs, psbt.PInput{
				WitnessUtxo: connector.UnsignedTx.TxOut[0],
			})
			leaf := o.coin.quorumLeaf[q]
			forfeit.Inputs[0].SighashType = txscript.SigHashDefault
			forfeit.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
				ControlBlock: leaf.ctrl, Script: leaf.script, LeafVersion: txscript.BaseLeafVersion,
			}}
			guardianSignInput(t, forfeit, 0, leaf.script, o.m.signers(q))
			encoded, err := forfeit.B64Encode()
			if err != nil {
				return nil, err
			}
			if err := client.SubmitSignedForfeitTxs(ctx, []string{encoded}, ""); err != nil {
				return nil, err
			}
			return []string{encoded}, nil
		},
	}

	res, err := joinBatchBounded(ctx, batchsession.JoinBatchArgs{
		BaseArgs: batchsession.BaseArgs{
			Vtxos: []clientlib.Vtxo{{
				Outpoint: o.clientOutpoint(), Script: hex.EncodeToString(o.coin.pkScript),
				Amount: uint64(guardianAmount), Tapscripts: o.coin.revealed,
			}},
			Outputs: []clientlib.Receiver{{To: next.addr, Amount: uint64(guardianAmount)}},
			SignTx:  o.funder.SignTransaction,
		},
		TreeSigners: sessions, IntentId: intentID, Client: client, ServerParams: *config,
	}, batchsession.WithHandler(handler))
	require.NoError(t, err)
	require.NotEmpty(t, res.CommitmentTxid)
	guardianWaitVtxo(t, ctx, o.funder, rolled.clientOutpoint())
	t.Logf("quorum %v rolled coin into batch %s, term %d", q, res.CommitmentTxid, nextTerm)
	return rolled
}

func guardianSaveExit(
	t *testing.T, ctx context.Context, o *guardianOpenCoin,
) *cachedIndexer {
	t.Helper()
	indexer := o.funder.Indexer()
	chain, err := indexer.GetVtxoChain(ctx, o.clientOutpoint())
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

func guardianUnroll(
	t *testing.T, ctx context.Context, o *guardianOpenCoin, saved *cachedIndexer,
) {
	t.Helper()
	branch, err := unroll.NewRedeemBranch(
		ctx, testExplorer, saved, clientlib.Vtxo{Outpoint: o.clientOutpoint()},
	)
	require.NoError(t, err)
	for range 20 {
		tx, err := branch.NextRedeemTx()
		if err != nil {
			// The operator may broadcast a spent ancestor's checkpoint itself.
			var pending unroll.ErrPendingConfirmation
			if errors.As(err, &pending) {
				require.NoError(t, generateBlocks(1))
				waitForTxConfirmed(t, pending.Txid)
				continue
			}
			require.ErrorContains(t, err, "already redeemed")
			break
		}
		bumpAndBroadcastTx(t, tx, testExplorer)
	}
	waitForTxConfirmed(t, o.outpoint.Hash.String())
}

func TestP2pFiatGuardianRoll(t *testing.T) {
	require.NoError(t, generateBlocks(1))
	ctx := t.Context()

	setup := setupClientWallet(t)
	_, offchainAddr, _, err := setup.Receive(ctx)
	require.NoError(t, err)
	addr, err := arklib.DecodeAddressV0(offchainAddr.Address)
	require.NoError(t, err)
	info, err := setup.Client().GetInfo(ctx)
	require.NoError(t, err)
	checkpoint, err := hex.DecodeString(info.CheckpointTapscript)
	require.NoError(t, err)

	m := &guardianMandate{
		user: newGuardianParty(t), lp: newGuardianParty(t),
		signer: addr.Signer, checkpoint: checkpoint,
	}
	for i := range m.nostracles {
		m.nostracles[i] = newGuardianParty(t)
	}

	height, err := getBlockHeight()
	require.NoError(t, err)
	term := height + 10

	lifecycle := m.open(t, ctx, term)
	exitCoin := m.open(t, ctx, term)
	staleCoin := m.open(t, ctx, term)
	theftCoin := m.open(t, ctx, term)
	userCoin := m.open(t, ctx, term)
	lockedCoin := m.open(t, ctx, term)
	q012 := guardianQuorum{0, 1, 2}
	q134 := guardianQuorum{1, 3, 4}

	t.Run("nostracle policy", func(t *testing.T) {
		now, err := getBlockHeight()
		require.NoError(t, err)
		afterTerm := term + 1
		next := m.coin(t, afterTerm+6)
		base := guardianRollRequest{
			current: lifecycle.coin, nextPk: next.pkScript, nextTerm: afterTerm + 6,
			nextValue: guardianAmount, height: afterTerm, epoch: 7,
		}
		require.NoError(t, m.approveRoll(t, base), "absent user")

		alive := base
		alive.heartbeat = signWith(t, m.user.d, guardianChallenge(lifecycle.coin.pkScript, 7))
		require.ErrorIs(t, m.approveRoll(t, alive), errUserAlive)

		replay := base
		replay.heartbeat = signWith(t, m.user.d, guardianChallenge(lifecycle.coin.pkScript, 6))
		require.NoError(t, m.approveRoll(t, replay), "an old answer must not count as alive")

		early := base
		early.height = now
		require.ErrorIs(t, m.approveRoll(t, early), errTooEarly)

		redirected := base
		redirected.nextPk = ownerPkScript(t, m.lp.pub, m.signer)
		require.ErrorIs(t, m.approveRoll(t, redirected), errMandate)

		lower := base
		lower.nextValue = guardianAmount - 1
		require.ErrorIs(t, m.approveRoll(t, lower), errMandate)

		long := base
		long.nextTerm = afterTerm + guardianMaxTerm + 1
		long.nextPk = m.coin(t, long.nextTerm).pkScript
		require.ErrorIs(t, m.approveRoll(t, long), errMandate)
	})

	t.Run("quorum cannot spend before timelock", func(t *testing.T) {
		ark, cp := lockedCoin.buildArk(
			t, lockedCoin.coin.quorumLeaf[q012], m.outputs(t, [2]int64{1000, 19000}),
		)
		_, err := lockedCoin.submitSigned(t, ctx, ark, cp, m.signers(q012))
		require.ErrorContains(t, err, "FORFEIT_CLOSURE_LOCKED")
		t.Logf("offchain spend rejected: %v", err)

		session, err := tree.NewVtxoTreeSigner()
		require.NoError(t, err)
		_, _, err = lockedCoin.registerRoll(
			t, ctx, q012, m.coin(t, term+6).pkScript, []string{session.GetPublicKey()},
		)
		require.ErrorContains(t, err, "FORFEIT_CLOSURE_LOCKED")
		t.Logf("early roll rejected: %v", err)
	})

	t.Run("user can act first before timelock", func(t *testing.T) {
		ark, cp := userCoin.buildArk(
			t, userCoin.coin.userLeaf, m.outputs(t, guardianPayouts[guardianUp]),
		)
		txid, err := userCoin.submitSigned(t, ctx, ark, cp, []guardianParty{m.user, m.lp})
		require.NoError(t, err)
		t.Logf("user and LP spent before the timelock: %s", txid)
	})

	mineToHeight(t, term)
	require.NoError(t, generateBlocks(1))
	require.Eventually(t, func() bool {
		tip, err := testExplorer.GetBlockHeight()
		return err == nil && tip >= int64(term)
	}, 20*time.Second, 200*time.Millisecond)

	t.Run("two nostracles and LP cannot spend after timelock", func(t *testing.T) {
		ark, cp := theftCoin.buildArk(
			t, theftCoin.coin.quorumLeaf[q012], m.outputs(t, [2]int64{1000, 19000}),
		)
		_, err := theftCoin.submitSigned(
			t, ctx, ark, cp, []guardianParty{m.nostracles[0], m.nostracles[1], m.lp},
		)
		require.ErrorContains(t, err, "missing")
		t.Logf("rejected: %v", err)
	})

	t.Run("three nostracles and LP can take the collateral", func(t *testing.T) {
		attacker := ownerPkScript(t, m.lp.pub, m.signer)
		ark, cp := theftCoin.buildArk(t, theftCoin.coin.quorumLeaf[q012], []*wire.TxOut{
			{Value: guardianAmount, PkScript: attacker},
		})
		txid, err := theftCoin.submitSigned(t, ctx, ark, cp, m.signers(q012))
		require.NoError(t, err)
		t.Logf("colluding quorum and LP took %d sats in %s", guardianAmount, txid)
	})

	// Save the old coin's exit data before it is rolled.
	savedStale := guardianSaveExit(t, ctx, staleCoin)

	var rolledLifecycle, rolledExit *guardianOpenCoin
	t.Run("quorum rolls for an offline user", func(t *testing.T) {
		now, err := getBlockHeight()
		require.NoError(t, err)
		firstTerm := now + 8
		rolledLifecycle = lifecycle.roll(t, ctx, q012, firstTerm)
		rolledExit = exitCoin.roll(t, ctx, q012, firstTerm)
		_ = staleCoin.roll(t, ctx, q012, firstTerm)

		mineToHeight(t, firstTerm)
		require.NoError(t, generateBlocks(1))
		now, err = getBlockHeight()
		require.NoError(t, err)
		rolledLifecycle = rolledLifecycle.roll(t, ctx, q134, now+4)
	})
	require.NotNil(t, rolledLifecycle)
	require.NotNil(t, rolledExit)

	t.Run("settles from attestation after two rolls", func(t *testing.T) {
		o := rolledLifecycle
		mineToHeight(t, o.coin.term)
		require.NoError(t, generateBlocks(1))
		p := o.arks[guardianUp]
		secret := o.oracle.attest(guardianUp)
		ark, cp := parsePsbt(t, p.arkB64), parsePsbt(t, p.checkpointB64)
		for i, s := range m.signers(o.quorum) {
			arkSig := completeAdaptor(t, p.arkSigs[i], secret)
			cpSig := completeAdaptor(t, p.cpSigs[i], secret)
			require.True(t, arkSig.Verify(p.arkMsg, s.pub))
			require.True(t, cpSig.Verify(p.checkpointMsg, s.pub))
			addTapscriptSig(ark, s.pub, arkSig)
			addTapscriptSig(cp, s.pub, cpSig)
		}
		arkB64, err := ark.B64Encode()
		require.NoError(t, err)
		cpB64, err := cp.B64Encode()
		require.NoError(t, err)
		var txid string
		require.Eventually(t, func() bool {
			var err error
			txid, _, _, err = o.funder.Client().SubmitTx(ctx, arkB64, []string{cpB64})
			return err == nil
		}, 20*time.Second, time.Second, "settlement failed")
		amounts := guardianPayouts[guardianUp]
		for i, pk := range [][]byte{
			ownerPkScript(t, m.user.pub, m.signer), ownerPkScript(t, m.lp.pub, m.signer),
		} {
			scriptHex := hex.EncodeToString(pk)
			require.Eventually(t, func() bool {
				resp, err := o.funder.Indexer().GetVtxos(ctx, clientlib.WithScripts([]string{scriptHex}))
				if err != nil || resp == nil {
					return false
				}
				return slices.ContainsFunc(resp.Vtxos, func(v clientlib.Vtxo) bool {
					return v.Txid == txid && int64(v.Amount) == amounts[i]
				})
			}, 20*time.Second, 200*time.Millisecond, "payout %d not found", i)
		}
		t.Logf("settled %s: user %d, LP %d sats", txid, amounts[0], amounts[1])
	})

	savedExit := guardianSaveExit(t, ctx, rolledExit)
	staleForfeited := false

	t.Run("operator punishes a stale exit of a rolled coin", func(t *testing.T) {
		guardianUnroll(t, ctx, staleCoin, savedStale)
		staleTxid := staleCoin.outpoint.Hash.String()
		// arkd must confirm its connector branch before it can broadcast the forfeit.
		spent := false
		for range 15 {
			outspends, err := testExplorer.GetTxOutspends(staleTxid)
			require.NoError(t, err)
			if int(staleCoin.outpoint.Index) < len(outspends) && outspends[staleCoin.outpoint.Index].Spent {
				spent = true
				break
			}
			require.NoError(t, generateBlocks(1))
			time.Sleep(2 * time.Second)
		}
		require.True(t, spent, "operator did not spend the stale coin")
		outspends, err := testExplorer.GetTxOutspends(staleTxid)
		require.NoError(t, err)
		spender := outspends[staleCoin.outpoint.Index].SpentBy
		require.NoError(t, generateBlocks(1))
		waitForTxConfirmed(t, spender)

		raw, err := testExplorer.GetTxHex(spender)
		require.NoError(t, err)
		var tx wire.MsgTx
		require.NoError(t, tx.Deserialize(hex.NewDecoder(strings.NewReader(raw))))
		config, err := staleCoin.funder.GetConfigData(ctx)
		require.NoError(t, err)
		forfeitAddr, err := arklib.DecodeBitcoinAddress(config.ForfeitAddress, nil)
		require.NoError(t, err)
		forfeitPk, err := txscript.PayToAddrScript(forfeitAddr)
		require.NoError(t, err)
		require.Equal(t, forfeitPk, tx.TxOut[0].PkScript, "spender must be the forfeit tx")
		staleForfeited = true
		t.Logf("operator spent the stale coin with forfeit %s", spender)
	})

	_, err = runCommand("docker", "stop", "arkd")
	require.NoError(t, err)
	t.Cleanup(func() {
		if _, err := runCommand("docker", "start", "arkd"); err != nil {
			t.Errorf("failed to restart arkd: %v", err)
			return
		}
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
	_, err = setup.Client().GetInfo(stopCtx)
	require.Error(t, err, "operator must be unreachable")

	guardianUnroll(t, ctx, rolledExit, savedExit)
	require.NoError(t, generateBlocks(int(guardianQuorumDelay)-2))

	t.Run("quorum exit enforces its delay", func(t *testing.T) {
		_, err := testExplorer.Broadcast(rolledExit.completedExit(t, guardianDown))
		require.ErrorContains(t, err, "non-BIP68-final")
		t.Logf("early exit rejected: %v", err)
	})

	require.NoError(t, generateBlocks(2))

	t.Run("stale payout cannot be used", func(t *testing.T) {
		require.True(t, staleForfeited, "the stale coin must be onchain and forfeited first")
		_, err := testExplorer.Broadcast(staleCoin.completedExit(t, guardianDown))
		require.ErrorContains(t, err, "missingorspent")
		t.Logf("stale payout rejected: %v", err)
	})

	t.Run("operator, LP and user gone: rolled coin exits correctly", func(t *testing.T) {
		o := rolledExit
		txid, err := testExplorer.Broadcast(o.completedExit(t, guardianDown))
		require.NoError(t, err)
		require.NoError(t, generateBlocks(1))
		waitForTxConfirmed(t, txid)
		raw, err := testExplorer.GetTxHex(txid)
		require.NoError(t, err)
		var tx wire.MsgTx
		require.NoError(t, tx.Deserialize(hex.NewDecoder(strings.NewReader(raw))))
		amounts := guardianPayouts[guardianDown]
		require.Equal(t, amounts[0]-guardianExitFee/2, tx.TxOut[0].Value)
		require.Equal(t, amounts[1]-guardianExitFee/2, tx.TxOut[1].Value)
		t.Logf("onchain exit %s: user %d, LP %d sats after fees", txid, tx.TxOut[0].Value, tx.TxOut[1].Value)
	})
}
