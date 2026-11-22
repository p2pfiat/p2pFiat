package p2pfiatcost

// Experiment 5: what does a numeric 3-of-5 DLC cost to sign at every roll?
//
// Uses nostracle's event shape: 20 binary digits of a whole-dollar price, one
// BIP340 signature per digit, hashed with the DLC attestation tag. The oracle is
// reimplemented here, so this does not consume real nostracle attestations.
//
// Copy into arkd's internal/test/p2pfiatcost directory and run with:
//   go test -v -count 1 -timeout 1500s -run TestP2pFiatNumericCost ./internal/test/p2pfiatcost
//
// No arkd server is needed.

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"math/bits"
	"math/rand/v2"
	"os"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

const (
	numDigits      = 20
	maxPrice       = uint32(1<<numDigits - 1)
	notionalUSD    = int64(1000)
	openPriceUSD   = int64(100_000)
	collateralSats = int64(2_000_000)
	exitFeeSats    = int64(1000)
	quorumDelay    = uint32(25)
	adaptorBytes   = 66 // 33-byte nonce, 32-byte scalar, 1 parity byte
	signersPerRoll = 4  // 3 nostracles + LP
)

type scenario struct {
	rounding int64
	tol      uint32 // power of two, whole dollars
	bandPct  int64  // 0 = whole price domain
	k, n     int
}

func (s scenario) band() (uint32, uint32) {
	if s.bandPct == 0 {
		return 1, maxPrice
	}
	return uint32(openPriceUSD * (100 - s.bandPct) / 100), uint32(openPriceUSD * (100 + s.bandPct) / 100)
}

func (s scenario) payout(price uint32) int64 {
	lo, hi := s.band()
	p := min(max(price, lo), hi)
	u := min(notionalUSD*100_000_000/int64(p), collateralSats)
	u = (u + s.rounding/2) / s.rounding * s.rounding
	return min(u, collateralSats)
}

type prefix struct {
	val  uint32
	bits uint8
}

func (p prefix) interval() (uint32, uint32) {
	shift := numDigits - uint(p.bits)
	lo := p.val << shift
	return lo, lo + (1 << shift) - 1
}

func (p prefix) contains(v uint32) bool {
	lo, hi := p.interval()
	return v >= lo && v <= hi
}

func cover(a, b uint32) []prefix {
	var out []prefix
	for x := uint64(a); x <= uint64(b); {
		k := uint(numDigits)
		if x != 0 {
			k = min(k, uint(bits.TrailingZeros64(x)))
		}
		for x+(1<<k)-1 > uint64(b) {
			k--
		}
		out = append(out, prefix{val: uint32(x >> k), bits: uint8(numDigits - k)})
		x += 1 << k
	}
	return out
}

type primaryRange struct {
	prefix prefix
	lo, hi uint32
	payout int64
}

func (s scenario) primaries() ([]primaryRange, int) {
	var out []primaryRange
	payouts := 0
	start := uint32(0)
	current := s.payout(0)
	flush := func(end uint32, u int64) {
		payouts++
		for _, p := range cover(start, end) {
			lo, hi := p.interval()
			out = append(out, primaryRange{prefix: p, lo: lo, hi: hi, payout: u})
		}
	}
	for p := uint32(1); p <= maxPrice; p++ {
		if u := s.payout(p); u != current {
			flush(p-1, current)
			start, current = p, u
		}
	}
	flush(maxPrice, current)
	return out, payouts
}

func (s scenario) secondary(lo, hi uint32) []prefix {
	e := uint(bits.TrailingZeros32(s.tol))
	a := uint32(0)
	if lo > s.tol {
		a = (lo - s.tol) >> e << e
	}
	bTop := min(uint64(hi)+uint64(s.tol), uint64(maxPrice))
	b := uint32(min((bTop>>e+1)<<e-1, uint64(maxPrice)))
	return cover(a, b)
}

func subsets(n, k int) [][]int {
	var out [][]int
	var walk func(start int, cur []int)
	walk = func(start int, cur []int) {
		if len(cur) == k {
			out = append(out, append([]int{}, cur...))
			return
		}
		for i := start; i < n; i++ {
			walk(i+1, append(cur, i))
		}
	}
	walk(0, nil)
	return out
}

func (s scenario) tuplesPerSubset(primaries []primaryRange) int64 {
	var total int64
	for _, p := range primaries {
		c := int64(1)
		if s.k > 1 {
			w := int64(len(s.secondary(p.lo, p.hi)))
			for range s.k - 1 {
				c *= w
			}
		}
		total += c
	}
	return total
}

func taggedChallenge(rx, px, msg []byte) btcec.ModNScalar {
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

func attestationMsg(bit byte) []byte {
	tag := sha256.Sum256([]byte("DLC/oracle/attestation/v0"))
	h := sha256.New()
	h.Write(tag[:])
	h.Write(tag[:])
	h.Write([]byte{bit})
	return h.Sum(nil)
}

func evenKey(t testing.TB) (btcec.ModNScalar, *btcec.PublicKey) {
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

type oracle struct {
	x      btcec.ModNScalar
	nonces [numDigits]btcec.ModNScalar
	digit  [numDigits][2]btcec.JacobianPoint
	mu     sync.Mutex
	cache  map[prefix]btcec.JacobianPoint
}

func newOracle(t testing.TB) *oracle {
	t.Helper()
	o := &oracle{cache: map[prefix]btcec.JacobianPoint{}}
	x, pub := evenKey(t)
	o.x = x
	px := schnorr.SerializePubKey(pub)
	var P btcec.JacobianPoint
	pub.AsJacobian(&P)
	for i := range numDigits {
		k, R := evenKey(t)
		o.nonces[i] = k
		rx := schnorr.SerializePubKey(R)
		var Rj btcec.JacobianPoint
		R.AsJacobian(&Rj)
		for b := range 2 {
			e := taggedChallenge(rx, px, attestationMsg(byte('0'+b)))
			var eP btcec.JacobianPoint
			btcec.ScalarMultNonConst(&e, &P, &eP)
			btcec.AddNonConst(&Rj, &eP, &o.digit[i][b])
			o.digit[i][b].ToAffine()
		}
	}
	return o
}

func (o *oracle) point(p prefix) btcec.JacobianPoint {
	o.mu.Lock()
	defer o.mu.Unlock()
	if c, ok := o.cache[p]; ok {
		return c
	}
	var sum btcec.JacobianPoint
	for i := range int(p.bits) {
		bit := (p.val >> (uint(p.bits) - 1 - uint(i))) & 1
		var next btcec.JacobianPoint
		btcec.AddNonConst(&sum, &o.digit[i][bit], &next)
		sum = next
	}
	sum.ToAffine()
	o.cache[p] = sum
	return sum
}

// attestPrefix returns the sum of the digit signatures covering this prefix.
func (o *oracle) attestPrefix(t testing.TB, price uint32, p prefix) btcec.ModNScalar {
	t.Helper()
	pub := new(btcec.JacobianPoint)
	btcec.ScalarBaseMultNonConst(&o.x, pub)
	pub.ToAffine()
	px := pub.X.Bytes()
	var sum btcec.ModNScalar
	for i := range int(p.bits) {
		var R btcec.JacobianPoint
		btcec.ScalarBaseMultNonConst(&o.nonces[i], &R)
		R.ToAffine()
		rx := R.X.Bytes()
		bit := byte('0' + (price>>(numDigits-1-uint(i)))&1)
		e := taggedChallenge(rx[:], px[:], attestationMsg(bit))
		var s btcec.ModNScalar
		s.Set(&e)
		s.Mul(&o.x)
		s.Add(&o.nonces[i])
		sum.Add(&s)
	}
	return sum
}

type adaptor struct {
	nonce btcec.JacobianPoint
	rx    [32]byte
	s     btcec.ModNScalar
	flip  bool
}

func adaptorSign(
	d btcec.ModNScalar, px, msg []byte, T *btcec.JacobianPoint,
) (*adaptor, error) {
	key, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, err
	}
	k := key.Key
	var kG, K btcec.JacobianPoint
	btcec.ScalarBaseMultNonConst(&k, &kG)
	btcec.AddNonConst(&kG, T, &K)
	K.ToAffine()
	flip := K.Y.IsOdd()
	if flip {
		k.Negate()
		kG.Y.Negate(1)
		kG.Y.Normalize()
	}
	rx := K.X.Bytes()
	e := taggedChallenge(rx[:], px, msg)
	var s btcec.ModNScalar
	s.Set(&e)
	s.Mul(&d)
	s.Add(&k)
	return &adaptor{nonce: kG, rx: *rx, s: s, flip: flip}, nil
}

func (a *adaptor) verify(P *btcec.JacobianPoint, px, msg []byte) bool {
	e := taggedChallenge(a.rx[:], px, msg)
	var sG, eP, want btcec.JacobianPoint
	btcec.ScalarBaseMultNonConst(&a.s, &sG)
	btcec.ScalarMultNonConst(&e, P, &eP)
	btcec.AddNonConst(&a.nonce, &eP, &want)
	sG.ToAffine()
	want.ToAffine()
	return sG.X.Equals(&want.X) && sG.Y.Equals(&want.Y)
}

func (a *adaptor) complete(t testing.TB, secret btcec.ModNScalar) *schnorr.Signature {
	t.Helper()
	sec := secret
	if a.flip {
		sec.Negate()
	}
	s := a.s
	s.Add(&sec)
	b := s.Bytes()
	sig, err := schnorr.ParseSignature(append(append([]byte{}, a.rx[:]...), b[:]...))
	require.NoError(t, err)
	return sig
}

type party struct {
	d   btcec.ModNScalar
	pub *btcec.PublicKey
	px  []byte
	j   btcec.JacobianPoint
}

func newParty(t testing.TB) *party {
	t.Helper()
	d, pub := evenKey(t)
	p := &party{d: d, pub: pub, px: schnorr.SerializePubKey(pub)}
	pub.AsJacobian(&p.j)
	return p
}

// contract is the Design 3 coin from experiment 4.
type contract struct {
	user, lp, operator *party
	nostracles         [5]*party
	pkScript           []byte
	revealed           []string
	settleLeaf         []byte
	settleTap          *waddrmgr.Tapscript
	exitClosure        *script.CSVMultisigClosure
	exitScript         []byte
	exitCtrl           []byte
	checkpoint         []byte
	outpoint           wire.OutPoint
	uPk, lPk           []byte
	uChainPk, lChainPk []byte
}

func newContract(t testing.TB) *contract {
	t.Helper()
	c := &contract{user: newParty(t), lp: newParty(t), operator: newParty(t)}
	for i := range c.nostracles {
		c.nostracles[i] = newParty(t)
	}
	term := arklib.AbsoluteLocktime(1000)
	closures := []script.Closure{
		&script.MultisigClosure{PubKeys: []*btcec.PublicKey{c.user.pub, c.lp.pub, c.operator.pub}},
		&script.CSVMultisigClosure{
			Locktime:        arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 20},
			MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{c.user.pub, c.lp.pub}},
		},
	}
	var settle *script.CLTVMultisigClosure
	for i, q := range subsets(5, 3) {
		keys := []*btcec.PublicKey{
			c.nostracles[q[0]].pub, c.nostracles[q[1]].pub, c.nostracles[q[2]].pub, c.lp.pub,
		}
		s := &script.CLTVMultisigClosure{
			Locktime: term,
			MultisigClosure: script.MultisigClosure{
				PubKeys: append(append([]*btcec.PublicKey{}, keys...), c.operator.pub),
			},
		}
		e := &script.CSVMultisigClosure{
			Locktime:        arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: quorumDelay},
			MultisigClosure: script.MultisigClosure{PubKeys: keys},
		}
		if i == 0 {
			settle, c.exitClosure = s, e
		}
		closures = append(closures, s, e)
	}
	vs := script.TapscriptsVtxoScript{Closures: closures}
	tapKey, tree, err := vs.TapTree()
	require.NoError(t, err)
	c.pkScript, err = script.P2TRScript(tapKey)
	require.NoError(t, err)
	c.revealed, err = vs.Encode()
	require.NoError(t, err)

	c.settleLeaf, err = settle.Script()
	require.NoError(t, err)
	proof, err := tree.GetTaprootMerkleProof(txscript.NewBaseTapLeaf(c.settleLeaf).TapHash())
	require.NoError(t, err)
	ctrl, err := txscript.ParseControlBlock(proof.ControlBlock)
	require.NoError(t, err)
	c.settleTap = &waddrmgr.Tapscript{ControlBlock: ctrl, RevealedScript: proof.Script}

	c.exitScript, err = c.exitClosure.Script()
	require.NoError(t, err)
	exitProof, err := tree.GetTaprootMerkleProof(txscript.NewBaseTapLeaf(c.exitScript).TapHash())
	require.NoError(t, err)
	c.exitCtrl = exitProof.ControlBlock

	checkpointClosure := &script.CSVMultisigClosure{
		Locktime:        arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 10},
		MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{c.operator.pub}},
	}
	c.checkpoint, err = checkpointClosure.Script()
	require.NoError(t, err)
	c.outpoint = wire.OutPoint{Hash: sha256.Sum256([]byte("p2pfiat-contract")), Index: 0}
	c.uPk, err = script.P2TRScript(c.user.pub)
	require.NoError(t, err)
	c.lPk, err = script.P2TRScript(c.lp.pub)
	require.NoError(t, err)
	c.uChainPk, c.lChainPk = c.uPk, c.lPk
	return c
}

func (c *contract) signers() []*party {
	return []*party{c.nostracles[0], c.nostracles[1], c.nostracles[2], c.lp}
}

type payoutTxs struct {
	exit                   *wire.MsgTx
	exitMsg, arkMsg, cpMsg []byte
}

func psbtSighash(t testing.TB, ptx *psbt.Packet) []byte {
	t.Helper()
	in := ptx.Inputs[0]
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

func (c *contract) payoutTxs(t testing.TB, u int64) *payoutTxs {
	t.Helper()
	l := collateralSats - u
	seq, err := arklib.BIP68Sequence(
		arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: quorumDelay},
	)
	require.NoError(t, err)
	exit := wire.NewMsgTx(2)
	exit.AddTxIn(&wire.TxIn{PreviousOutPoint: c.outpoint, Sequence: seq})
	uChain := max(u-exitFeeSats/2, 0)
	lChain := collateralSats - exitFeeSats - uChain
	if uChain > 0 {
		exit.AddTxOut(&wire.TxOut{Value: uChain, PkScript: c.uChainPk})
	}
	if lChain > 0 {
		exit.AddTxOut(&wire.TxOut{Value: lChain, PkScript: c.lChainPk})
	}
	fetcher := txscript.NewCannedPrevOutputFetcher(c.pkScript, collateralSats)
	exitMsg, err := txscript.CalcTapscriptSignaturehash(
		txscript.NewTxSigHashes(exit, fetcher), txscript.SigHashDefault, exit, 0, fetcher,
		txscript.NewBaseTapLeaf(c.exitScript),
	)
	require.NoError(t, err)

	var outs []*wire.TxOut
	if u > 0 {
		outs = append(outs, &wire.TxOut{Value: u, PkScript: c.uPk})
	}
	if l > 0 {
		outs = append(outs, &wire.TxOut{Value: l, PkScript: c.lPk})
	}
	ark, checkpoints, err := offchain.BuildTxs([]offchain.VtxoInput{{
		Outpoint: &c.outpoint, Amount: collateralSats,
		Tapscript: c.settleTap, RevealedTapscripts: c.revealed,
	}}, outs, c.checkpoint)
	require.NoError(t, err)
	return &payoutTxs{
		exit: exit, exitMsg: exitMsg,
		arkMsg: psbtSighash(t, ark), cpMsg: psbtSighash(t, checkpoints[0]),
	}
}

func (c *contract) spendExit(t testing.TB, p *payoutTxs, sigs []*schnorr.Signature) error {
	t.Helper()
	args := map[string][]byte{}
	for i, s := range c.signers() {
		args[hex.EncodeToString(s.px)] = sigs[i].Serialize()
	}
	witness, err := c.exitClosure.Witness(c.exitCtrl, args)
	require.NoError(t, err)
	tx := p.exit.Copy()
	tx.TxIn[0].Witness = witness
	fetcher := txscript.NewCannedPrevOutputFetcher(c.pkScript, collateralSats)
	vm, err := txscript.NewEngine(
		c.pkScript, tx, 0, txscript.StandardVerifyFlags, nil,
		txscript.NewTxSigHashes(tx, fetcher), collateralSats, fetcher,
	)
	if err != nil {
		return err
	}
	return vm.Execute()
}

type opRates struct {
	sign1, verify1, signAll, verifyAll float64
}

func measureRates(t *testing.T, c *contract, o *oracle) opRates {
	t.Helper()
	const samples = 4000
	msg := sha256.Sum256([]byte("rate"))
	T := o.point(prefix{val: 1, bits: 8})
	s := c.lp
	a, err := adaptorSign(s.d, s.px, msg[:], &T)
	require.NoError(t, err)

	start := time.Now()
	for range samples {
		_, err := adaptorSign(s.d, s.px, msg[:], &T)
		require.NoError(t, err)
	}
	sign1 := samples / time.Since(start).Seconds()
	start = time.Now()
	for range samples {
		require.True(t, a.verify(&s.j, s.px, msg[:]))
	}
	verify1 := samples / time.Since(start).Seconds()

	parallel := func(fn func()) float64 {
		workers := runtime.GOMAXPROCS(0)
		var wg sync.WaitGroup
		start := time.Now()
		for range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range samples {
					fn()
				}
			}()
		}
		wg.Wait()
		return float64(samples*workers) / time.Since(start).Seconds()
	}
	signAll := parallel(func() { _, _ = adaptorSign(s.d, s.px, msg[:], &T) })
	verifyAll := parallel(func() { a.verify(&s.j, s.px, msg[:]) })
	return opRates{sign1, verify1, signAll, verifyAll}
}

func human(b float64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", b/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", b/(1<<20))
	default:
		return fmt.Sprintf("%.0f KB", b/(1<<10))
	}
}

func findPrimary(primaries []primaryRange, price uint32) *primaryRange {
	i := sort.Search(len(primaries), func(i int) bool { return primaries[i].hi >= price })
	if i == len(primaries) || !primaries[i].prefix.contains(price) {
		return nil
	}
	return &primaries[i]
}

func findSecondary(s scenario, p *primaryRange, price uint32) *prefix {
	for _, c := range s.secondary(p.lo, p.hi) {
		if c.contains(price) {
			return &c
		}
	}
	return nil
}

func TestP2pFiatNumericCost(t *testing.T) {
	c := newContract(t)
	oracles := [5]*oracle{}
	for i := range oracles {
		oracles[i] = newOracle(t)
	}
	rates := measureRates(t, c, oracles[0])
	t.Logf("cores=%d sign=%.0f/s verify=%.0f/s (1 core), sign=%.0f/s verify=%.0f/s (all cores)",
		runtime.GOMAXPROCS(0), rates.sign1, rates.verify1, rates.signAll, rates.verifyAll)

	var rows [][]string
	rows = append(rows, []string{
		"oracles", "band_pct", "rounding_sats", "tolerance_usd", "payouts", "tuples",
		"exit_adaptors_per_signer", "exit_data_per_signer_bytes", "exit_stored_bytes",
		"exit_sign_s", "exit_verify_others_s", "all_paths_adaptors_per_signer",
		"all_paths_stored_bytes", "all_paths_sign_s",
	})
	var grid []scenario
	for _, band := range []int64{0, 50, 25, 10} {
		for _, rounding := range []int64{100, 1000, 10000} {
			grid = append(grid, scenario{rounding: rounding, tol: 1, bandPct: band, k: 1, n: 1})
			for _, tol := range []uint32{64, 256, 1024} {
				grid = append(grid, scenario{rounding: rounding, tol: tol, bandPct: band, k: 3, n: 5})
			}
		}
	}
	for _, s := range grid {
		primaries, payouts := s.primaries()
		tuples := s.tuplesPerSubset(primaries) * int64(len(subsets(s.n, s.k)))
		exitData := float64(tuples * adaptorBytes)
		tol := strconv.Itoa(int(s.tol))
		name := fmt.Sprintf("%d-of-%d", s.k, s.n)
		if s.k == 1 {
			tol = "n/a"
		}
		rows = append(rows, []string{
			name, strconv.FormatInt(s.bandPct, 10), strconv.FormatInt(s.rounding, 10), tol,
			strconv.Itoa(payouts), strconv.FormatInt(tuples, 10), strconv.FormatInt(tuples, 10),
			fmt.Sprintf("%.0f", exitData), fmt.Sprintf("%.0f", exitData*signersPerRoll),
			fmt.Sprintf("%.2f", float64(tuples)/rates.signAll),
			fmt.Sprintf("%.2f", 3*float64(tuples)/rates.verifyAll),
			strconv.FormatInt(tuples*3, 10), fmt.Sprintf("%.0f", exitData*3*signersPerRoll),
			fmt.Sprintf("%.2f", 3*float64(tuples)/rates.signAll),
		})
		t.Logf("%s band=%d%% round=%d tol=%s: payouts=%d tuples=%d exit stored=%s sign=%.1fs",
			name, s.bandPct, s.rounding, tol, payouts, tuples,
			human(exitData*signersPerRoll), float64(tuples)/rates.signAll)
	}
	if path := os.Getenv("P2PFIAT_OUT"); path != "" {
		f, err := os.Create(path)
		require.NoError(t, err)
		w := csv.NewWriter(f)
		require.NoError(t, w.WriteAll(rows))
		require.NoError(t, f.Close())
	}

	rec := scenario{rounding: 1000, tol: 256, bandPct: 25, k: 3, n: 5}
	primaries, payouts := rec.primaries()
	t.Logf("reference: band=%d%% rounding=%d tolerance=%d payouts=%d primary prefixes=%d",
		rec.bandPct, rec.rounding, rec.tol, payouts, len(primaries))

	txCache := map[int64]*payoutTxs{}
	for _, p := range primaries {
		if _, ok := txCache[p.payout]; !ok {
			txCache[p.payout] = c.payoutTxs(t, p.payout)
		}
	}

	t.Run("every price maps to its exact payout", func(t *testing.T) {
		for price := uint32(0); price <= maxPrice; price++ {
			p := findPrimary(primaries, price)
			require.NotNil(t, p, "price %d not covered", price)
			require.Equal(t, rec.payout(price), p.payout, "price %d", price)
			if price == maxPrice {
				break
			}
		}
	})

	quorums := subsets(5, 3)
	settle := func(t *testing.T, q []int, prices [3]uint32) (*payoutTxs, []*adaptor, btcec.ModNScalar, *primaryRange) {
		t.Helper()
		p := findPrimary(primaries, prices[0])
		require.NotNil(t, p)
		sec1 := findSecondary(rec, p, prices[1])
		sec2 := findSecondary(rec, p, prices[2])
		require.NotNil(t, sec1)
		require.NotNil(t, sec2)
		pts := []btcec.JacobianPoint{
			oracles[q[0]].point(p.prefix), oracles[q[1]].point(*sec1), oracles[q[2]].point(*sec2),
		}
		var T, next btcec.JacobianPoint
		btcec.AddNonConst(&pts[0], &pts[1], &next)
		btcec.AddNonConst(&next, &pts[2], &T)
		T.ToAffine()
		txs := txCache[p.payout]
		ads := make([]*adaptor, 0, 4)
		for _, s := range c.signers() {
			a, err := adaptorSign(s.d, s.px, txs.exitMsg, &T)
			require.NoError(t, err)
			require.True(t, a.verify(&s.j, s.px, txs.exitMsg))
			ads = append(ads, a)
		}
		var secret btcec.ModNScalar
		for i, pre := range []prefix{p.prefix, *sec1, *sec2} {
			part := oracles[q[i]].attestPrefix(t, prices[i], pre)
			secret.Add(&part)
		}
		return txs, ads, secret, p
	}

	const trials = 1000
	t.Run("random 3-of-5 attestations settle through Bitcoin script", func(t *testing.T) {
		lo, hi := rec.band()
		for i := range trials {
			q := quorums[rand.IntN(len(quorums))]
			var base uint32
			switch i % 4 {
			case 0:
				base = rand.Uint32N(maxPrice + 1)
			case 1, 2:
				base = lo + rand.Uint32N(hi-lo+1)
			default:
				base = []uint32{0, 1, lo, hi, maxPrice}[rand.IntN(5)]
			}
			noise := func() uint32 {
				d := int64(base) + int64(rand.IntN(2*int(rec.tol)+1)) - int64(rec.tol)
				return uint32(min(max(d, 0), int64(maxPrice)))
			}
			prices := [3]uint32{base, noise(), noise()}
			txs, ads, secret, p := settle(t, q, prices)
			require.Equal(t, rec.payout(base), p.payout)
			sigs := make([]*schnorr.Signature, 0, 4)
			for j, a := range ads {
				sig := a.complete(t, secret)
				require.True(t, sig.Verify(txs.exitMsg, c.signers()[j].pub))
				sigs = append(sigs, sig)
			}
			require.NoError(t, c.spendExit(t, txs, sigs))
		}
		t.Logf("%d random settlements passed the Bitcoin script engine", trials)
	})

	t.Run("two attestations cannot complete a payout", func(t *testing.T) {
		q := quorums[0]
		price := uint32(openPriceUSD)
		txs, ads, _, p := settle(t, q, [3]uint32{price, price, price})
		sec := findSecondary(rec, p, price)
		var partial btcec.ModNScalar
		a := oracles[q[0]].attestPrefix(t, price, p.prefix)
		b := oracles[q[1]].attestPrefix(t, price, *sec)
		partial.Add(&a)
		partial.Add(&b)
		sig := ads[0].complete(t, partial)
		require.False(t, sig.Verify(txs.exitMsg, c.signers()[0].pub))
	})

	t.Run("a different price cannot complete the payout", func(t *testing.T) {
		q := quorums[0]
		price := uint32(openPriceUSD)
		txs, ads, _, p := settle(t, q, [3]uint32{price, price, price})
		sec := findSecondary(rec, p, price)
		other := p.hi + 1
		var wrong btcec.ModNScalar
		x := oracles[q[0]].attestPrefix(t, other, p.prefix)
		y := oracles[q[1]].attestPrefix(t, price, *sec)
		z := oracles[q[2]].attestPrefix(t, price, *sec)
		wrong.Add(&x)
		wrong.Add(&y)
		wrong.Add(&z)
		sig := ads[0].complete(t, wrong)
		require.False(t, sig.Verify(txs.exitMsg, c.signers()[0].pub))
	})

	t.Run("nostracles too far apart have no payout", func(t *testing.T) {
		for range 2000 {
			base := uint32(75_000 + rand.IntN(50_000))
			p := findPrimary(primaries, base)
			require.NotNil(t, p)
			far := uint64(p.hi) + 2*uint64(rec.tol)
			require.Nil(t, findSecondary(rec, p, uint32(far)))
		}
	})

	t.Run("full reference roll with real signatures", func(t *testing.T) {
		type job struct {
			msg []byte
			T   btcec.JacobianPoint
		}
		var jobs []job
		for _, q := range quorums {
			for i := range primaries {
				p := &primaries[i]
				msg := txCache[p.payout].exitMsg
				P := oracles[q[0]].point(p.prefix)
				secs := rec.secondary(p.lo, p.hi)
				for _, a := range secs {
					A := oracles[q[1]].point(a)
					for _, b := range secs {
						B := oracles[q[2]].point(b)
						var sum, T btcec.JacobianPoint
						btcec.AddNonConst(&P, &A, &sum)
						btcec.AddNonConst(&sum, &B, &T)
						T.ToAffine()
						jobs = append(jobs, job{msg: msg, T: T})
					}
				}
			}
		}
		want := rec.tuplesPerSubset(primaries) * int64(len(quorums))
		require.Equal(t, want, int64(len(jobs)))

		s := c.lp
		out := make([]*adaptor, len(jobs))
		var next atomic.Int64
		run := func(fn func(i int)) time.Duration {
			next.Store(0)
			var wg sync.WaitGroup
			start := time.Now()
			for range runtime.GOMAXPROCS(0) {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						i := int(next.Add(1) - 1)
						if i >= len(jobs) {
							return
						}
						fn(i)
					}
				}()
			}
			wg.Wait()
			return time.Since(start)
		}
		signTime := run(func(i int) {
			a, err := adaptorSign(s.d, s.px, jobs[i].msg, &jobs[i].T)
			if err == nil {
				out[i] = a
			}
		})
		var bad atomic.Int64
		verifyTime := run(func(i int) {
			if out[i] == nil || !out[i].verify(&s.j, s.px, jobs[i].msg) {
				bad.Add(1)
			}
		})
		require.Zero(t, bad.Load())
		t.Logf("real roll: %d adaptors, sign %.2fs, verify one signer %.2fs, data per signer %s",
			len(jobs), signTime.Seconds(), verifyTime.Seconds(),
			human(float64(len(jobs))*adaptorBytes))
	})
}
