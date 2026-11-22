package test

// Experiment 3 (docs/ark-architecture.md, "Next steps"): open, renew with
// OP_TUNNEL, and settle an oracle-priced position, measuring what the operator
// could do alone.
//
// The user and LP only ever contribute public keys. Their private keys are
// discarded at creation, so renewal and settlement cannot use an owner signature.
//
// Copy into the emulator repository's test directory and run with:
//   go test -v -count 1 -run TestP2pFiatCovenant ./test/

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math/big"
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
	batchsessionhandler "github.com/arkade-os/arkd/pkg/client-lib/batch-session/handler"
	mempoolexplorer "github.com/arkade-os/arkd/pkg/client-lib/explorer"
	clientwallet "github.com/arkade-os/arkd/pkg/client-wallet"
	"github.com/arkade-os/emulator/pkg/arkade"
	emulatorclient "github.com/arkade-os/emulator/pkg/client"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

const (
	covCollateral = int64(20_000)  // sats locked by user and LP
	covNotional   = int64(500)     // the user's stable balance, in USD cents
	covSatsPerBTC = int64(100_000_000)
	covMaturity   = int64(1_900_000_000)
	covPrice      = int64(4_000_000) // USD cents per BTC at maturity
	covExitDelay  = uint32(512)

	// Published regtest key from the emulator's docker-compose.regtest.yml.
	// Used here to model a compromised emulator key.
	covRegtestEmulatorKey = "5646b2e23bbb82491fb4ef262079ff17594d5e873fc6bcea5f1453edbe1029b1"
)

var covTicker = []byte("BTCUSD")

func covOracleMessage(price, ts int64) []byte {
	msg := append([]byte{}, covTicker...)
	msg = binary.LittleEndian.AppendUint64(msg, uint64(price))
	msg = binary.LittleEndian.AppendUint64(msg, uint64(ts))
	return msg
}

func covOracleWitness(t *testing.T, key *btcec.PrivateKey, price, ts int64) wire.TxWitness {
	t.Helper()
	digest := sha256.Sum256(covOracleMessage(price, ts))
	sig, err := schnorr.Sign(key, digest[:])
	require.NoError(t, err)
	return wire.TxWitness{sig.Serialize(), bnBytes(big.NewInt(price)), bnBytes(big.NewInt(ts))}
}

// covSettleScript enforces the payout from a signed price at exactly maturity.
// Witness stack: [signature, price, timestamp].
func covSettleScript(t *testing.T, oracle *btcec.PublicKey, uPk, lPk []byte) []byte {
	t.Helper()
	s, err := txscript.NewScriptBuilder().
		// One input only, so two contracts cannot share one set of payouts.
		AddOp(arkade.OP_INSPECTNUMINPUTS).AddInt64(1).AddOp(arkade.OP_NUMEQUALVERIFY).
		// The attestation must be for the agreed maturity.
		AddOp(arkade.OP_DUP).AddInt64(covMaturity).AddOp(arkade.OP_NUMEQUALVERIFY).
		// Rebuild ticker || price || timestamp with fixed-width fields.
		AddInt64(8).AddOp(arkade.OP_NUM2BIN).
		AddOp(arkade.OP_OVER).AddInt64(8).AddOp(arkade.OP_NUM2BIN).
		AddOp(arkade.OP_SWAP).AddOp(arkade.OP_CAT).
		AddData(covTicker).AddOp(arkade.OP_SWAP).AddOp(arkade.OP_CAT).
		AddOp(arkade.OP_SHA256).
		// Verify the oracle signature.
		AddOp(arkade.OP_ROT).AddOp(arkade.OP_SWAP).
		AddData(schnorr.SerializePubKey(oracle)).
		AddOp(arkade.OP_CHECKSIGFROMSTACK).AddOp(arkade.OP_VERIFY).
		// user payout = min(collateral, notional * 1e8 / price)
		AddOp(arkade.OP_DUP).AddInt64(0).AddOp(arkade.OP_GREATERTHAN).AddOp(arkade.OP_VERIFY).
		AddInt64(covNotional * covSatsPerBTC).AddOp(arkade.OP_SWAP).AddOp(arkade.OP_DIV).
		AddInt64(covCollateral).AddOp(arkade.OP_MIN).
		AddOp(arkade.OP_DUP).AddInt64(0).AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddOp(arkade.OP_NUMEQUALVERIFY).
		// LP payout = collateral - user payout
		AddInt64(covCollateral).AddOp(arkade.OP_SWAP).AddOp(arkade.OP_SUB).
		AddInt64(1).AddOp(arkade.OP_INSPECTOUTPUTVALUE).AddOp(arkade.OP_NUMEQUALVERIFY).
		// Output 0 pays the user and output 1 pays the LP.
		AddInt64(0).AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddInt64(1).AddOp(arkade.OP_EQUALVERIFY).AddData(uPk[2:]).AddOp(arkade.OP_EQUALVERIFY).
		AddInt64(1).AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddInt64(1).AddOp(arkade.OP_EQUALVERIFY).AddData(lPk[2:]).AddOp(arkade.OP_EQUAL).
		Script()
	require.NoError(t, err)
	return s
}

// covRenewScript is arkade's reference delegate covenant, pinned to one keeper.
func covRenewScript(t *testing.T, keeperCosigner string) []byte {
	t.Helper()
	s, err := txscript.NewScriptBuilder().
		AddOp(arkade.OP_PUSHEXPIRY).AddInt64(1024).AddOp(arkade.OP_SUB).
		AddOp(arkade.OP_CHECKTIME).AddOp(txscript.OP_VERIFY).
		AddData([]byte("type")).AddOp(arkade.OP_INSPECTINTENTMESSAGE).AddOp(txscript.OP_VERIFY).
		AddData([]byte(intent.IntentMessageTypeRegister)).AddOp(arkade.OP_EQUALVERIFY).
		AddData([]byte("onchain_output_indexes")).AddOp(arkade.OP_INSPECTINTENTMESSAGE).
		AddOp(txscript.OP_VERIFY).AddData([]byte("[]")).AddOp(arkade.OP_EQUALVERIFY).
		AddData([]byte("cosigners_public_keys.0")).AddOp(arkade.OP_INSPECTINTENTMESSAGE).
		AddOp(txscript.OP_VERIFY).AddData([]byte(keeperCosigner)).AddOp(arkade.OP_EQUALVERIFY).
		AddData([]byte("cosigners_public_keys.1")).AddOp(arkade.OP_INSPECTINTENTMESSAGE).
		AddOp(txscript.OP_NOT).AddOp(txscript.OP_VERIFY).AddOp(txscript.OP_DROP).
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).AddOp(arkade.OP_1SUB).
		AddInt64(arkade.TunnelScriptPubKey | arkade.TunnelValue | arkade.TunnelAssets).
		AddInt64(0).AddOp(arkade.OP_TUNNEL).
		Script()
	require.NoError(t, err)
	return s
}

type covEnv struct {
	alice       clientwallet.Wallet
	identity    clientlib.Identity
	client      clientlib.Client
	emulator    emulatorclient.TransportClient
	emulatorPub *btcec.PublicKey
	indexer     clientlib.Indexer
	explorer    clientlib.Explorer
	signer      *btcec.PublicKey
	checkpoint  []byte
}

type covContract struct {
	vs           script.TapscriptsVtxoScript
	tapKey       *btcec.PublicKey
	pkScript     []byte
	revealed     []string
	renewArkade  []byte
	settleArkade []byte
	renewLeaf    []byte
	settleLeaf   []byte
	uPk, lPk     []byte
	cosigner     *btcec.PrivateKey
}

func covP2TRKey(t *testing.T) (*btcec.PublicKey, []byte) {
	t.Helper()
	key, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	pub, err := schnorr.ParsePubKey(schnorr.SerializePubKey(key.PubKey()))
	require.NoError(t, err)
	pk, err := script.P2TRScript(pub)
	require.NoError(t, err)
	key.Zero() // the owner never signs anything in this experiment
	return pub, pk
}

func (e *covEnv) newContract(t *testing.T, oracle *btcec.PublicKey) *covContract {
	t.Helper()
	uPub, uPk := covP2TRKey(t)
	lPub, lPk := covP2TRKey(t)
	cosigner, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	session := tree.NewTreeSignerSession(cosigner)

	renewArkade := covRenewScript(t, session.GetPublicKey())
	settleArkade := covSettleScript(t, oracle, uPk, lPk)
	emulatorKey := func(s []byte) *btcec.PublicKey {
		return arkade.ComputeArkadeScriptPublicKey(e.emulatorPub, arkade.ArkadeScriptHash(s))
	}
	renew := &script.MultisigClosure{PubKeys: []*btcec.PublicKey{e.signer, emulatorKey(renewArkade)}}
	settle := &script.MultisigClosure{PubKeys: []*btcec.PublicKey{e.signer, emulatorKey(settleArkade)}}
	exit := &script.CSVMultisigClosure{
		MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{uPub, lPub}},
		Locktime:        arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: covExitDelay},
	}
	// The renewal leaf is first: the batch handler forfeits through closure 0.
	vs := script.TapscriptsVtxoScript{Closures: []script.Closure{renew, settle, exit}}
	tapKey, _, err := vs.TapTree()
	require.NoError(t, err)
	pkScript, err := script.P2TRScript(tapKey)
	require.NoError(t, err)
	revealed, err := vs.Encode()
	require.NoError(t, err)
	renewLeaf, err := renew.Script()
	require.NoError(t, err)
	settleLeaf, err := settle.Script()
	require.NoError(t, err)
	return &covContract{
		vs: vs, tapKey: tapKey, pkScript: pkScript, revealed: revealed,
		renewArkade: renewArkade, settleArkade: settleArkade,
		renewLeaf: renewLeaf, settleLeaf: settleLeaf, uPk: uPk, lPk: lPk, cosigner: cosigner,
	}
}

// fundScript sends the collateral to a VTXO script and returns its funding tx and vout.
func (e *covEnv) fundScript(
	t *testing.T, ctx context.Context, vs script.TapscriptsVtxoScript,
) (*wire.MsgTx, uint32) {
	t.Helper()
	tapKey, _, err := vs.TapTree()
	require.NoError(t, err)
	addr, err := (&arklib.Address{HRP: "tark", VtxoTapKey: tapKey, Signer: e.signer}).EncodeV0()
	require.NoError(t, err)
	// The wallet may still be syncing the change of its previous payment.
	var txid string
	var sendErr error
	require.Eventually(t, func() bool {
		res, err := e.alice.SendOffChain(ctx, []clientlib.Receiver{
			{To: addr, Amount: uint64(covCollateral)},
		})
		sendErr = err
		if err != nil {
			return false
		}
		txid = res.Txid
		return true
	}, 30*time.Second, time.Second, "funding failed")
	require.NoError(t, sendErr)

	var ptx *psbt.Packet
	require.Eventually(t, func() bool {
		txs, err := e.indexer.GetVirtualTxs(ctx, []string{txid})
		if err != nil || txs == nil || len(txs.Txs) != 1 {
			return false
		}
		ptx = parseCovPsbt(t, txs.Txs[0])
		return true
	}, 20*time.Second, 200*time.Millisecond, "funding tx not indexed")
	vout, out := findTaprootOutput(t, ptx.UnsignedTx, tapKey)
	require.Equal(t, covCollateral, out.Value)

	// Spending before arkd has stored the coin fails for an unrelated reason.
	outpoint := clientlib.Outpoint{Txid: txid, VOut: vout}
	require.Eventually(t, func() bool {
		resp, err := e.indexer.GetVtxos(ctx, clientlib.WithOutpoints([]clientlib.Outpoint{outpoint}))
		return err == nil && resp != nil && len(resp.Vtxos) == 1 && !resp.Vtxos[0].Spent
	}, 20*time.Second, 200*time.Millisecond, "funded coin not indexed")
	return ptx.UnsignedTx, vout
}

func parseCovPsbt(t *testing.T, b64 string) *psbt.Packet {
	t.Helper()
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(b64), true)
	require.NoError(t, err)
	return ptx
}

func (c *covContract) renewIntent(
	t *testing.T, input offchain.VtxoInput, parent *wire.MsgTx, outputs []*wire.TxOut, cosigner string,
) (*psbt.Packet, string) {
	t.Helper()
	message, err := intent.RegisterMessage{
		BaseMessage:          intent.BaseMessage{Type: intent.IntentMessageTypeRegister},
		OnchainOutputIndexes: []int{},
		CosignersPublicKeys:  []string{cosigner},
	}.Encode()
	require.NoError(t, err)
	proof, err := intent.New(message, []intent.Input{{
		OutPoint:    input.Outpoint,
		Sequence:    wire.MaxTxInSequenceNum,
		WitnessUtxo: &wire.TxOut{Value: covCollateral, PkScript: c.pkScript},
	}}, outputs)
	require.NoError(t, err)
	ctrl, err := input.Tapscript.ControlBlock.ToBytes()
	require.NoError(t, err)
	leaf := []*psbt.TaprootTapLeafScript{{
		LeafVersion: txscript.BaseLeafVersion, ControlBlock: ctrl, Script: c.renewLeaf,
	}}
	taptree, err := txutils.VtxoTaprootTreeField.Encode(c.revealed)
	require.NoError(t, err)
	for i := range 2 {
		proof.Inputs[i].TaprootLeafScript = leaf
		proof.Inputs[i].Unknowns = append(proof.Inputs[i].Unknowns, taptree)
	}
	ptx := &proof.Packet
	addEmulatorPacket(t, ptx, []arkade.EmulatorEntry{{Vin: 1, Script: c.renewArkade}})
	require.NoError(t, txutils.SetArkPsbtField(ptx, 1, arkade.PrevArkTxField, *parent))
	return ptx, message
}

// renew moves the coin into a new batch through the covenant only.
func (e *covEnv) renew(
	t *testing.T, ctx context.Context, c *covContract, parent *wire.MsgTx, vout uint32,
) (*wire.MsgTx, uint32) {
	t.Helper()
	input := vtxoInputFromScriptOutput(t, parent, vout, c.vs, c.renewLeaf)
	session := tree.NewTreeSignerSession(c.cosigner)
	ptx, message := c.renewIntent(t, input, parent,
		[]*wire.TxOut{{Value: covCollateral, PkScript: c.pkScript}}, session.GetPublicKey())
	encoded, err := ptx.B64Encode()
	require.NoError(t, err)
	approved, err := e.emulator.SubmitIntent(ctx, emulatorclient.Intent{Proof: encoded, Message: message})
	require.NoError(t, err)
	signed := emulatorclient.Intent{Proof: approved, Message: message}
	intentID, err := e.client.RegisterIntent(ctx, signed.Proof, signed.Message)
	require.NoError(t, err)

	vtxo := clientlib.Vtxo{
		Outpoint:   clientlib.Outpoint{Txid: input.Outpoint.Hash.String(), VOut: input.Outpoint.Index},
		Script:     hex.EncodeToString(c.renewLeaf),
		Amount:     uint64(covCollateral),
		Tapscripts: c.revealed,
	}
	handler := &capturingBatchEventsHandler{delegateBatchEventsHandler: &delegateBatchEventsHandler{
		intentId: intentID, intent: signed, vtxosToForfeit: []clientlib.Vtxo{vtxo},
		signerSession: session, emulatorClient: e.emulator, wallet: e.identity,
		client: e.client, explorer: e.explorer,
	}}
	topics := getEventStreamTopics([]clientlib.Outpoint{vtxo.Outpoint}, []tree.SignerSession{session})
	stream, stop, err := e.client.GetEventStream(ctx, topics)
	require.NoError(t, err)
	defer stop()
	commitment, _, _, _, _, err := batchsessionhandler.JoinBatchSession(ctx, stream, handler)
	require.NoError(t, err)
	require.NotEmpty(t, commitment)

	outpoint := findLeafOutpoint(t, handler.vtxoTree, c.pkScript, covCollateral)
	var leafTx *wire.MsgTx
	for _, leaf := range handler.vtxoTree.Leaves() {
		if leaf.UnsignedTx.TxID() == outpoint.Txid {
			leafTx = leaf.UnsignedTx
		}
	}
	require.NotNil(t, leafTx)
	require.Eventually(t, func() bool {
		resp, err := e.indexer.GetVtxos(ctx, clientlib.WithOutpoints([]clientlib.Outpoint{outpoint}))
		return err == nil && resp != nil && len(resp.Vtxos) == 1 &&
			!resp.Vtxos[0].Preconfirmed && !resp.Vtxos[0].Spent
	}, 15*time.Second, 200*time.Millisecond, "renewed coin not found")
	t.Logf("renewed in batch %s, same script and %d sats", commitment, covCollateral)
	return leafTx, outpoint.VOut
}

func (e *covEnv) submitSettle(
	t *testing.T, ctx context.Context, c *covContract, input offchain.VtxoInput,
	outputs []*wire.TxOut, witness wire.TxWitness,
) (string, error) {
	t.Helper()
	ptx, checkpoints, err := offchain.BuildTxs([]offchain.VtxoInput{input}, outputs, e.checkpoint)
	require.NoError(t, err)
	addEmulatorPacket(t, ptx, []arkade.EmulatorEntry{{Vin: 0, Script: c.settleArkade, Witness: witness}})
	encoded, err := ptx.B64Encode()
	require.NoError(t, err)
	_, _, err = e.emulator.SubmitTx(ctx, encoded, encodeCheckpoints(t, checkpoints))
	return ptx.UnsignedTx.TxID(), err
}

func (e *covEnv) requireVtxo(
	t *testing.T, ctx context.Context, pkScript []byte, txid string, amount int64, who string,
) {
	t.Helper()
	scriptHex := hex.EncodeToString(pkScript)
	require.Eventually(t, func() bool {
		resp, err := e.indexer.GetVtxos(ctx, clientlib.WithScripts([]string{scriptHex}))
		if err != nil || resp == nil {
			return false
		}
		for _, v := range resp.Vtxos {
			if v.Txid == txid && int64(v.Amount) == amount {
				return true
			}
		}
		return false
	}, 20*time.Second, 200*time.Millisecond, "%s payout not found", who)
	t.Logf("%s received %d sats in %s", who, amount, txid)
}

func covSignInput(t *testing.T, ptx *psbt.Packet, key *btcec.PrivateKey) {
	t.Helper()
	in := &ptx.Inputs[0]
	leaf := txscript.NewBaseTapLeaf(in.TaprootLeafScript[0].Script)
	fetcher := txscript.NewMultiPrevOutFetcher(map[wire.OutPoint]*wire.TxOut{
		ptx.UnsignedTx.TxIn[0].PreviousOutPoint: in.WitnessUtxo,
	})
	msg, err := txscript.CalcTapscriptSignaturehash(
		txscript.NewTxSigHashes(ptx.UnsignedTx, fetcher), in.SighashType, ptx.UnsignedTx, 0, fetcher, leaf,
	)
	require.NoError(t, err)
	sig, err := schnorr.Sign(key, msg)
	require.NoError(t, err)
	hash := leaf.TapHash()
	in.TaprootScriptSpendSig = append(in.TaprootScriptSpendSig, &psbt.TaprootScriptSpendSig{
		XOnlyPubKey: schnorr.SerializePubKey(key.PubKey()),
		LeafHash:    hash.CloneBytes(),
		Signature:   sig.Serialize(),
		SigHash:     in.SighashType,
	})
}

// stealWithEmulatorKey bypasses the emulator service and asks arkd to cosign
// a spend that pays the whole coin to an attacker.
func (e *covEnv) stealWithEmulatorKey(
	t *testing.T, ctx context.Context, input offchain.VtxoInput, arkadeScript, attacker []byte,
) (string, error) {
	t.Helper()
	raw, err := hex.DecodeString(covRegtestEmulatorKey)
	require.NoError(t, err)
	emulatorPriv, _ := btcec.PrivKeyFromBytes(raw)
	require.Equal(t, schnorr.SerializePubKey(e.emulatorPub), schnorr.SerializePubKey(emulatorPriv.PubKey()))
	tweaked := arkade.ComputeArkadeScriptPrivateKey(emulatorPriv, arkade.ArkadeScriptHash(arkadeScript))

	ptx, checkpoints, err := offchain.BuildTxs(
		[]offchain.VtxoInput{input},
		[]*wire.TxOut{{Value: covCollateral, PkScript: attacker}},
		e.checkpoint,
	)
	require.NoError(t, err)
	covSignInput(t, ptx, tweaked)
	covSignInput(t, checkpoints[0], tweaked)
	encoded, err := ptx.B64Encode()
	require.NoError(t, err)
	txid, _, _, err := e.client.SubmitTx(ctx, encoded, encodeCheckpoints(t, checkpoints))
	return txid, err
}

func TestP2pFiatCovenant(t *testing.T) {
	ctx := t.Context()
	alice, identity, _, client := setupArkSDKwithPublicKey(t)
	t.Cleanup(func() { client.Close() })
	emulator, emulatorPub, conn := setupEmulatorClient(t, ctx)
	t.Cleanup(func() { _ = conn.Close() })
	aliceAddr := fundAndSettleAlice(t, ctx, alice, 300_000)
	explorer, err := mempoolexplorer.NewExplorer("http://localhost:3000", arklib.BitcoinRegTest)
	require.NoError(t, err)
	info, err := client.GetInfo(ctx)
	require.NoError(t, err)
	checkpoint, err := hex.DecodeString(info.CheckpointTapscript)
	require.NoError(t, err)
	env := &covEnv{
		alice: alice, identity: identity, client: client, emulator: emulator,
		emulatorPub: emulatorPub, indexer: setupIndexer(t), explorer: explorer,
		signer: aliceAddr.Signer, checkpoint: checkpoint,
	}

	oracleKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	oraclePub := oracleKey.PubKey()
	wantUser := covNotional * covSatsPerBTC / covPrice
	wantLP := covCollateral - wantUser
	require.Equal(t, int64(12_500), wantUser)

	c := env.newContract(t, oraclePub)
	payouts := func(u, l int64) []*wire.TxOut {
		return []*wire.TxOut{{Value: u, PkScript: c.uPk}, {Value: l, PkScript: c.lPk}}
	}
	parent, vout := env.fundScript(t, ctx, c.vs)

	t.Run("covenant refuses a renewal that changes the coin", func(t *testing.T) {
		input := vtxoInputFromScriptOutput(t, parent, vout, c.vs, c.renewLeaf)
		session := tree.NewTreeSignerSession(c.cosigner)
		for name, out := range map[string]*wire.TxOut{
			"new owner":   {Value: covCollateral, PkScript: randomP2TRScript(t)},
			"lower value": {Value: covCollateral - 1, PkScript: c.pkScript},
		} {
			ptx, message := c.renewIntent(t, input, parent, []*wire.TxOut{out}, session.GetPublicKey())
			encoded, err := ptx.B64Encode()
			require.NoError(t, err)
			_, err = emulator.SubmitIntent(ctx, emulatorclient.Intent{Proof: encoded, Message: message})
			require.ErrorContains(t, err, "opcode=OP_TUNNEL", name)
			t.Logf("%s rejected: %v", name, err)
		}
	})

	t.Run("keeper renews twice without owners", func(t *testing.T) {
		for range 2 {
			parent, vout = env.renew(t, ctx, c, parent, vout)
		}
	})

	settleInput := vtxoInputFromScriptOutput(t, parent, vout, c.vs, c.settleLeaf)
	goodWitness := covOracleWitness(t, oracleKey, covPrice, covMaturity)

	t.Run("covenant refuses invalid settlements", func(t *testing.T) {
		wrongOracle, err := btcec.NewPrivateKey()
		require.NoError(t, err)
		lowerPrice := covPrice * 3 / 4 // pays the user more, within the collateral
		lowerUser := covNotional * covSatsPerBTC / lowerPrice
		attacker := randomP2TRScript(t)
		swapped := append(wire.TxWitness{}, goodWitness...)
		swapped[1] = bnBytes(big.NewInt(lowerPrice))
		cases := []struct {
			name    string
			reason  string
			outputs []*wire.TxOut
			witness wire.TxWitness
		}{
			{"forged oracle", "opcode=OP_CHECKSIGFROMSTACK", payouts(lowerUser, covCollateral-lowerUser),
				covOracleWitness(t, wrongOracle, lowerPrice, covMaturity)},
			{"changed price", "opcode=OP_CHECKSIGFROMSTACK", payouts(lowerUser, covCollateral-lowerUser), swapped},
			{"wrong timestamp", "opcode=OP_NUMEQUALVERIFY", payouts(wantUser, wantLP),
				covOracleWitness(t, oracleKey, covPrice, covMaturity+1)},
			{"user overpaid", "opcode=OP_NUMEQUALVERIFY", payouts(wantUser+1, wantLP-1), goodWitness},
			{"LP overpaid", "opcode=OP_NUMEQUALVERIFY", payouts(wantUser-1, wantLP+1), goodWitness},
			{"wrong recipient", "opcode=OP_EQUALVERIFY", []*wire.TxOut{
				{Value: wantUser, PkScript: attacker}, {Value: wantLP, PkScript: c.lPk},
			}, goodWitness},
		}
		for _, tc := range cases {
			_, err := env.submitSettle(t, ctx, c, settleInput, tc.outputs, tc.witness)
			require.ErrorContains(t, err, tc.reason, tc.name)
			t.Logf("%s rejected: %v", tc.name, err)
		}
	})

	t.Run("anyone settles the oracle price after renewal", func(t *testing.T) {
		txid, err := env.submitSettle(t, ctx, c, settleInput, payouts(wantUser, wantLP), goodWitness)
		require.NoError(t, err)
		env.requireVtxo(t, ctx, c.uPk, txid, wantUser, "user")
		env.requireVtxo(t, ctx, c.lPk, txid, wantLP, "LP")
	})

	t.Run("settled coin cannot be settled again", func(t *testing.T) {
		_, err := env.submitSettle(t, ctx, c, settleInput, []*wire.TxOut{
			{Value: wantUser, PkScript: c.uPk}, {Value: wantLP, PkScript: c.lPk},
			{Value: 0, PkScript: randomP2TRScript(t)},
		}, goodWitness)
		require.ErrorContains(t, err, "VTXO_ALREADY_SPENT")
		t.Logf("second settlement rejected: %v", err)
	})

	t.Run("two contracts cannot share one payout", func(t *testing.T) {
		parentA, voutA := env.fundScript(t, ctx, c.vs)
		parentB, voutB := env.fundScript(t, ctx, c.vs)
		inA := vtxoInputFromScriptOutput(t, parentA, voutA, c.vs, c.settleLeaf)
		inB := vtxoInputFromScriptOutput(t, parentB, voutB, c.vs, c.settleLeaf)
		ptx, checkpoints, err := offchain.BuildTxs([]offchain.VtxoInput{inA, inB}, []*wire.TxOut{
			{Value: wantUser, PkScript: c.uPk}, {Value: wantLP, PkScript: c.lPk},
			{Value: covCollateral, PkScript: randomP2TRScript(t)},
		}, checkpoint)
		require.NoError(t, err)
		addEmulatorPacket(t, ptx, []arkade.EmulatorEntry{
			{Vin: 0, Script: c.settleArkade, Witness: goodWitness},
			{Vin: 1, Script: c.settleArkade, Witness: goodWitness},
		})
		encoded, err := ptx.B64Encode()
		require.NoError(t, err)
		_, _, err = emulator.SubmitTx(ctx, encoded, encodeCheckpoints(t, checkpoints))
		require.ErrorContains(t, err, "opcode=OP_NUMEQUALVERIFY")
		t.Logf("shared payout rejected: %v", err)
	})

	t.Run("emulator down blocks settlement until it returns", func(t *testing.T) {
		d := env.newContract(t, oraclePub)
		parentD, voutD := env.fundScript(t, ctx, d.vs)
		inD := vtxoInputFromScriptOutput(t, parentD, voutD, d.vs, d.settleLeaf)
		out := []*wire.TxOut{{Value: wantUser, PkScript: d.uPk}, {Value: wantLP, PkScript: d.lPk}}

		_, err := runCommand("docker", "stop", "emulator")
		require.NoError(t, err)
		restarted := false
		restart := func() {
			if !restarted {
				_, _ = runCommand("docker", "start", "emulator")
				restarted = true
			}
		}
		t.Cleanup(restart)
		downCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		_, err = env.submitSettle(t, downCtx, d, inD, out, goodWitness)
		require.Error(t, err)
		t.Log("settlement unavailable while emulator is down")
		restart()

		var txid string
		require.Eventually(t, func() bool {
			var err error
			txid, err = env.submitSettle(t, ctx, d, inD, out, goodWitness)
			return err == nil
		}, 45*time.Second, time.Second, "settlement did not recover")
		env.requireVtxo(t, ctx, d.uPk, txid, wantUser, "user")
	})

	attacker := randomP2TRScript(t)

	t.Run("compromised emulator key drains an owner-free leaf", func(t *testing.T) {
		v := env.newContract(t, oraclePub)
		parentV, voutV := env.fundScript(t, ctx, v.vs)
		input := vtxoInputFromScriptOutput(t, parentV, voutV, v.vs, v.renewLeaf)
		txid, err := env.stealWithEmulatorKey(t, ctx, input, v.renewArkade, attacker)
		require.NoError(t, err, "expected arkd to cosign without running the covenant")
		env.requireVtxo(t, ctx, attacker, txid, covCollateral, "attacker")
	})

	t.Run("compromised emulator key cannot spend an owner-signed leaf", func(t *testing.T) {
		ownerPub, _ := covP2TRKey(t)
		arkadeScript, err := txscript.NewScriptBuilder().AddOp(arkade.OP_1).Script()
		require.NoError(t, err)
		tweaked := arkade.ComputeArkadeScriptPublicKey(emulatorPub, arkade.ArkadeScriptHash(arkadeScript))
		leaf := &script.MultisigClosure{PubKeys: []*btcec.PublicKey{ownerPub, env.signer, tweaked}}
		vs := script.TapscriptsVtxoScript{Closures: []script.Closure{
			leaf,
			&script.CSVMultisigClosure{
				MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{ownerPub}},
				Locktime:        arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: covExitDelay},
			},
		}}
		parentO, voutO := env.fundScript(t, ctx, vs)
		leafScript, err := leaf.Script()
		require.NoError(t, err)
		input := vtxoInputFromScriptOutput(t, parentO, voutO, vs, leafScript)
		_, err = env.stealWithEmulatorKey(t, ctx, input, arkadeScript, randomP2TRScript(t))
		require.ErrorContains(t, err, "missing 1 signatures")
		t.Logf("attack rejected: %v", err)
	})
}
