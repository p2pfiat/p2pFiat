package e2e_test

// Experiment 1 (docs/ark-architecture.md, "Next steps"): can the LP complete a
// pre-signed payout on arkd while the user is offline, including the checkpoint?
//
// The user adaptor-signs the ark tx and checkpoint of every outcome, then their
// key is wiped. Only the oracle's attestation can complete those signatures.
//
// Copy into arkd's internal/test/e2e directory and run with:
//   go test -v -count 1 -run TestP2pFiatOfflineSettlement ./internal/test/e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

func bip340Challenge(rx, px, msg []byte) btcec.ModNScalar {
	tag := sha256.Sum256([]byte("BIP0340/challenge"))
	h := sha256.New()
	h.Write(tag[:])
	h.Write(tag[:])
	h.Write(rx)
	h.Write(px)
	h.Write(msg)
	var e btcec.ModNScalar
	e.SetByteSlice(h.Sum(nil))
	return e
}

func evenKey(t *testing.T) (btcec.ModNScalar, *btcec.PublicKey) {
	t.Helper()
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	d := priv.Key
	if priv.PubKey().SerializeCompressed()[0] == 0x03 {
		d.Negate()
	}
	pub, err := schnorr.ParsePubKey(schnorr.SerializePubKey(priv.PubKey()))
	require.NoError(t, err)
	return d, pub
}

// testOracle is a throwaway DLC-style oracle with one announced nonce.
type testOracle struct {
	x, k   btcec.ModNScalar
	P, R   *btcec.PublicKey
	px, rx []byte
}

func newTestOracle(t *testing.T) *testOracle {
	t.Helper()
	x, P := evenKey(t)
	k, R := evenKey(t)
	return &testOracle{
		x: x, k: k, P: P, R: R,
		px: schnorr.SerializePubKey(P), rx: schnorr.SerializePubKey(R),
	}
}

func outcomeHash(outcome string) []byte {
	h := sha256.Sum256([]byte(outcome))
	return h[:]
}

// anticipationPoint uses only public announcement data.
func (o *testOracle) anticipationPoint(outcome string) *btcec.PublicKey {
	e := bip340Challenge(o.rx, o.px, outcomeHash(outcome))
	var r, p, eP, sum btcec.JacobianPoint
	o.R.AsJacobian(&r)
	o.P.AsJacobian(&p)
	btcec.ScalarMultNonConst(&e, &p, &eP)
	btcec.AddNonConst(&r, &eP, &sum)
	sum.ToAffine()
	return btcec.NewPublicKey(&sum.X, &sum.Y)
}

func (o *testOracle) attest(outcome string) btcec.ModNScalar {
	e := bip340Challenge(o.rx, o.px, outcomeHash(outcome))
	var s btcec.ModNScalar
	s.Set(&e)
	s.Mul(&o.x)
	s.Add(&o.k)
	return s
}

type adaptorSig struct {
	nonce *btcec.PublicKey // kG, before adding the adaptor point
	rx    []byte           // x of kG + T, which has even y
	s     btcec.ModNScalar
}

func adaptorSign(
	t *testing.T, d btcec.ModNScalar, pub *btcec.PublicKey, msg []byte, adaptor *btcec.PublicKey,
) *adaptorSig {
	t.Helper()
	px := schnorr.SerializePubKey(pub)
	var T btcec.JacobianPoint
	adaptor.AsJacobian(&T)
	for {
		k, err := btcec.NewPrivateKey()
		require.NoError(t, err)
		var kG, sum btcec.JacobianPoint
		btcec.ScalarBaseMultNonConst(&k.Key, &kG)
		btcec.AddNonConst(&kG, &T, &sum)
		sum.ToAffine()
		if sum.Y.IsOdd() {
			continue
		}
		rx := sum.X.Bytes()
		e := bip340Challenge(rx[:], px, msg)
		var s btcec.ModNScalar
		s.Set(&e)
		s.Mul(&d)
		s.Add(&k.Key)
		return &adaptorSig{nonce: k.PubKey(), rx: append([]byte{}, rx[:]...), s: s}
	}
}

// verifyAdaptor lets the LP check the user's commitment before relying on it.
func verifyAdaptor(a *adaptorSig, pub *btcec.PublicKey, msg []byte) bool {
	e := bip340Challenge(a.rx, schnorr.SerializePubKey(pub), msg)
	var sG, p, eP, n, want btcec.JacobianPoint
	btcec.ScalarBaseMultNonConst(&a.s, &sG)
	pub.AsJacobian(&p)
	btcec.ScalarMultNonConst(&e, &p, &eP)
	a.nonce.AsJacobian(&n)
	btcec.AddNonConst(&n, &eP, &want)
	sG.ToAffine()
	want.ToAffine()
	return sG.X.Equals(&want.X) && sG.Y.Equals(&want.Y)
}

func completeAdaptor(t *testing.T, a *adaptorSig, secret btcec.ModNScalar) *schnorr.Signature {
	t.Helper()
	s := a.s
	s.Add(&secret)
	b := s.Bytes()
	sig, err := schnorr.ParseSignature(append(append([]byte{}, a.rx...), b[:]...))
	require.NoError(t, err)
	return sig
}

func tapscriptSighash(t *testing.T, ptx *psbt.Packet) []byte {
	t.Helper()
	in := ptx.Inputs[0]
	require.NotEmpty(t, in.TaprootLeafScript)
	fetcher := txscript.NewMultiPrevOutFetcher(map[wire.OutPoint]*wire.TxOut{
		ptx.UnsignedTx.TxIn[0].PreviousOutPoint: in.WitnessUtxo,
	})
	msg, err := txscript.CalcTapscriptSignaturehash(
		txscript.NewTxSigHashes(ptx.UnsignedTx, fetcher), in.SighashType, ptx.UnsignedTx, 0,
		fetcher, txscript.NewBaseTapLeaf(in.TaprootLeafScript[0].Script),
	)
	require.NoError(t, err)
	return msg
}

func addTapscriptSig(ptx *psbt.Packet, pub *btcec.PublicKey, sig *schnorr.Signature) {
	in := &ptx.Inputs[0]
	leaf := txscript.NewBaseTapLeaf(in.TaprootLeafScript[0].Script).TapHash()
	in.TaprootScriptSpendSig = append(in.TaprootScriptSpendSig, &psbt.TaprootScriptSpendSig{
		XOnlyPubKey: schnorr.SerializePubKey(pub),
		LeafHash:    leaf.CloneBytes(),
		Signature:   sig.Serialize(),
		SigHash:     in.SighashType,
	})
}

func parsePsbt(t *testing.T, b64 string) *psbt.Packet {
	t.Helper()
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(b64), true)
	require.NoError(t, err)
	return ptx
}

func ownerPkScript(t *testing.T, owner, signer *btcec.PublicKey) []byte {
	t.Helper()
	vs := script.TapscriptsVtxoScript{Closures: []script.Closure{
		&script.MultisigClosure{PubKeys: []*btcec.PublicKey{owner, signer}},
		&script.CSVMultisigClosure{
			MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{owner}},
			Locktime:        arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 20},
		},
	}}
	key, _, err := vs.TapTree()
	require.NoError(t, err)
	pk, err := script.P2TRScript(key)
	require.NoError(t, err)
	return pk
}

type presignedPayout struct {
	arkB64, checkpointB64 string
	arkMsg, checkpointMsg []byte
	arkSig, checkpointSig *adaptorSig
}

func TestP2pFiatOfflineSettlement(t *testing.T) {
	require.NoError(t, generateBlocks(1))
	ctx := t.Context()

	const (
		contractAmount = int64(10000)
		outcomeUp      = "BTCUSD-settles-up"
		outcomeDown    = "BTCUSD-settles-down"
	)
	payouts := map[string][2]int64{outcomeUp: {7000, 3000}, outcomeDown: {4000, 6000}}

	funder := setupClientWallet(t)
	arkClient := funder.Client()
	indexer := funder.Indexer()
	_, offchainAddr, _, err := funder.Receive(ctx)
	require.NoError(t, err)
	funderAddr, err := arklib.DecodeAddressV0(offchainAddr.Address)
	require.NoError(t, err)
	faucetOffchain(t, funder, 0.00021)
	serverKey := funderAddr.Signer

	uKey, uPub := evenKey(t)
	lKey, lPub := evenKey(t)
	oracle := newTestOracle(t)

	// Contract coin: user + LP + operator, with a user + LP timelocked exit.
	contract := script.TapscriptsVtxoScript{Closures: []script.Closure{
		&script.MultisigClosure{PubKeys: []*btcec.PublicKey{uPub, lPub, serverKey}},
		&script.CSVMultisigClosure{
			MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{uPub, lPub}},
			Locktime:        arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 20},
		},
	}}
	tapKey, tapTree, err := contract.TapTree()
	require.NoError(t, err)
	contractAddr, err := (&arklib.Address{
		HRP: "tark", VtxoTapKey: tapKey, Signer: serverKey,
	}).EncodeV0()
	require.NoError(t, err)
	contractPk, err := script.P2TRScript(tapKey)
	require.NoError(t, err)

	res, err := sendOffChainBounded(
		ctx, funder, []clientlib.Receiver{{To: contractAddr, Amount: uint64(contractAmount)}},
	)
	require.NoError(t, err)

	var fundingPtx *psbt.Packet
	require.Eventually(t, func() bool {
		resp, err := indexer.GetVirtualTxs(ctx, []string{res.Txid})
		if err != nil || resp == nil || len(resp.Txs) == 0 {
			return false
		}
		fundingPtx = parsePsbt(t, resp.Txs[0])
		return true
	}, 30*time.Second, 500*time.Millisecond)

	vout := -1
	for i, out := range fundingPtx.UnsignedTx.TxOut {
		if string(out.PkScript) == string(contractPk) {
			vout = i
		}
	}
	require.GreaterOrEqual(t, vout, 0)

	leafScript, err := contract.ForfeitClosures()[0].Script()
	require.NoError(t, err)
	proof, err := tapTree.GetTaprootMerkleProof(txscript.NewBaseTapLeaf(leafScript).TapHash())
	require.NoError(t, err)
	ctrl, err := txscript.ParseControlBlock(proof.ControlBlock)
	require.NoError(t, err)
	revealed, err := contract.Encode()
	require.NoError(t, err)
	info, err := arkClient.GetInfo(ctx)
	require.NoError(t, err)
	checkpointScript, err := hex.DecodeString(info.CheckpointTapscript)
	require.NoError(t, err)

	uPayoutPk := ownerPkScript(t, uPub, serverKey)
	lPayoutPk := ownerPkScript(t, lPub, serverKey)

	// The user comes online once and adaptor-signs every outcome.
	presigned := map[string]*presignedPayout{}
	for outcome, amounts := range payouts {
		arkPtx, checkpoints, err := offchain.BuildTxs(
			[]offchain.VtxoInput{{
				Outpoint:           &wire.OutPoint{Hash: fundingPtx.UnsignedTx.TxHash(), Index: uint32(vout)},
				Amount:             contractAmount,
				Tapscript:          &waddrmgr.Tapscript{ControlBlock: ctrl, RevealedScript: proof.Script},
				RevealedTapscripts: revealed,
			}},
			[]*wire.TxOut{
				{Value: amounts[0], PkScript: uPayoutPk},
				{Value: amounts[1], PkScript: lPayoutPk},
			},
			checkpointScript,
		)
		require.NoError(t, err)
		require.Len(t, checkpoints, 1)
		arkB64, err := arkPtx.B64Encode()
		require.NoError(t, err)
		checkpointB64, err := checkpoints[0].B64Encode()
		require.NoError(t, err)

		T := oracle.anticipationPoint(outcome)
		arkMsg := tapscriptSighash(t, arkPtx)
		checkpointMsg := tapscriptSighash(t, checkpoints[0])
		p := &presignedPayout{
			arkB64: arkB64, checkpointB64: checkpointB64,
			arkMsg: arkMsg, checkpointMsg: checkpointMsg,
			arkSig:        adaptorSign(t, uKey, uPub, arkMsg, T),
			checkpointSig: adaptorSign(t, uKey, uPub, checkpointMsg, T),
		}
		require.True(t, verifyAdaptor(p.arkSig, uPub, arkMsg))
		require.True(t, verifyAdaptor(p.checkpointSig, uPub, checkpointMsg))
		presigned[outcome] = p
	}

	// The user goes offline: their key no longer exists in this test.
	uKey.Zero()

	lSign := func(msg []byte) *schnorr.Signature {
		keyBytes := lKey.Bytes()
		priv, _ := btcec.PrivKeyFromBytes(keyBytes[:])
		sig, err := schnorr.Sign(priv, msg)
		require.NoError(t, err)
		return sig
	}
	submit := func(p *presignedPayout, uArk, uCheckpoint *schnorr.Signature) (string, error) {
		arkPtx, checkpointPtx := parsePsbt(t, p.arkB64), parsePsbt(t, p.checkpointB64)
		if uArk != nil {
			addTapscriptSig(arkPtx, uPub, uArk)
			addTapscriptSig(checkpointPtx, uPub, uCheckpoint)
		}
		addTapscriptSig(arkPtx, lPub, lSign(p.arkMsg))
		addTapscriptSig(checkpointPtx, lPub, lSign(p.checkpointMsg))
		arkB64, err := arkPtx.B64Encode()
		require.NoError(t, err)
		checkpointB64, err := checkpointPtx.B64Encode()
		require.NoError(t, err)
		txid, _, _, err := arkClient.SubmitTx(ctx, arkB64, []string{checkpointB64})
		return txid, err
	}

	attestationUp := oracle.attest(outcomeUp)
	attestationSig, err := schnorr.ParseSignature(append(
		append([]byte{}, oracle.rx...), func() []byte { b := attestationUp.Bytes(); return b[:] }()...,
	))
	require.NoError(t, err)
	require.True(t, attestationSig.Verify(outcomeHash(outcomeUp), oracle.P))

	t.Run("LP alone is rejected", func(t *testing.T) {
		_, err := submit(presigned[outcomeDown], nil, nil)
		require.Error(t, err)
		t.Logf("server rejected: %v", err)
	})

	t.Run("wrong outcome cannot be completed", func(t *testing.T) {
		p := presigned[outcomeDown]
		arkSig := completeAdaptor(t, p.arkSig, attestationUp)
		checkpointSig := completeAdaptor(t, p.checkpointSig, attestationUp)
		require.False(t, arkSig.Verify(p.arkMsg, uPub))
		require.False(t, checkpointSig.Verify(p.checkpointMsg, uPub))
		_, err := submit(p, arkSig, checkpointSig)
		require.Error(t, err)
		t.Logf("server rejected: %v", err)
	})

	var settledTxid string
	t.Run("LP settles attested outcome while user is offline", func(t *testing.T) {
		p := presigned[outcomeUp]
		arkSig := completeAdaptor(t, p.arkSig, attestationUp)
		checkpointSig := completeAdaptor(t, p.checkpointSig, attestationUp)
		require.True(t, arkSig.Verify(p.arkMsg, uPub))
		require.True(t, checkpointSig.Verify(p.checkpointMsg, uPub))

		settledTxid, err = submit(p, arkSig, checkpointSig)
		require.NoError(t, err)
		t.Logf("settled ark txid: %s", settledTxid)

		for _, want := range []struct {
			name   string
			pk     []byte
			amount uint64
		}{{"user", uPayoutPk, 7000}, {"LP", lPayoutPk, 3000}} {
			scriptHex := hex.EncodeToString(want.pk)
			require.Eventually(t, func() bool {
				resp, err := indexer.GetVtxos(ctx, clientlib.WithScripts([]string{scriptHex}))
				if err != nil || resp == nil {
					return false
				}
				for _, v := range resp.Vtxos {
					if v.Txid == settledTxid && v.Amount == want.amount && !v.Spent {
						t.Logf("%s received %d sats in %s:%d", want.name, v.Amount, v.Txid, v.VOut)
						return true
					}
				}
				return false
			}, 30*time.Second, 500*time.Millisecond, "%s payout not found", want.name)
		}

		resp, err := indexer.GetVtxos(ctx, clientlib.WithScripts([]string{hex.EncodeToString(contractPk)}))
		require.NoError(t, err)
		require.Len(t, resp.Vtxos, 1)
		require.True(t, resp.Vtxos[0].Spent, "contract coin must be spent")
	})

	t.Run("second payout is rejected after settlement", func(t *testing.T) {
		p := presigned[outcomeDown]
		attestationDown := oracle.attest(outcomeDown) // simulates an equivocating oracle
		arkSig := completeAdaptor(t, p.arkSig, attestationDown)
		checkpointSig := completeAdaptor(t, p.checkpointSig, attestationDown)
		require.True(t, arkSig.Verify(p.arkMsg, uPub))
		_, err := submit(p, arkSig, checkpointSig)
		require.Error(t, err)
		t.Logf("server rejected: %v", err)
	})
}
