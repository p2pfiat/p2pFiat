package p2pfiatcost

// Experiment 6: can 3 of 5 nostracles act as one DLC oracle?
//
// Key and per-digit nonces come from a distributed key generation. The group
// agrees on one price, and any 3 members produce a normal BIP340 signature per
// digit, so the DLC contract sees a single oracle.
//
// This is a research prototype and has not had a cryptographic review. All five
// members run in this process, with no nostr transport.
//
// Needs ../05-numeric-signing-cost. Copy both test files into arkd's
// internal/test/p2pfiatcost directory and run with:
//   go test -v -count 1 -timeout 1500s -run TestP2pFiatThresholdOracle ./internal/test/p2pfiatcost

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/stretchr/testify/require"
)

const (
	thrT            = 3
	thrN            = 5
	thrFaulty       = 2
	thrMaxDeviation = 0.01
	// One dealer's traffic per DKG: 3 commitments, a proof, and 4 private shares.
	thrDealerBytes = 3*33 + 33 + 32 + 4*32
)

var thrIDs = []int{1, 2, 3, 4, 5}

func thrRandom(t testing.TB) btcec.ModNScalar {
	t.Helper()
	k, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return k.Key
}

func thrScalar(v int) btcec.ModNScalar {
	var s btcec.ModNScalar
	s.SetInt(uint32(v))
	return s
}

func thrMulG(s *btcec.ModNScalar) btcec.JacobianPoint {
	var p btcec.JacobianPoint
	btcec.ScalarBaseMultNonConst(s, &p)
	p.ToAffine()
	return p
}

func thrAdd(a, b *btcec.JacobianPoint) btcec.JacobianPoint {
	var p btcec.JacobianPoint
	btcec.AddNonConst(a, b, &p)
	p.ToAffine()
	return p
}

func thrMul(s *btcec.ModNScalar, a *btcec.JacobianPoint) btcec.JacobianPoint {
	var p btcec.JacobianPoint
	btcec.ScalarMultNonConst(s, a, &p)
	p.ToAffine()
	return p
}

func thrEqual(a, b *btcec.JacobianPoint) bool {
	return a.X.Equals(&b.X) && a.Y.Equals(&b.Y)
}

func thrSer(p *btcec.JacobianPoint) []byte {
	return btcec.NewPublicKey(&p.X, &p.Y).SerializeCompressed()
}

func thrNegate(p *btcec.JacobianPoint) {
	p.Y.Negate(1)
	p.Y.Normalize()
}

type thrDealer struct {
	id      int
	commits []btcec.JacobianPoint
	proofR  btcec.JacobianPoint
	proofZ  btcec.ModNScalar
	shares  map[int]btcec.ModNScalar
}

func thrProofChallenge(ctx string, id int, c0, r *btcec.JacobianPoint) btcec.ModNScalar {
	h := sha256.New()
	h.Write([]byte("p2pfiat/dkg/proof"))
	h.Write([]byte(ctx))
	_ = binary.Write(h, binary.LittleEndian, uint32(id))
	h.Write(thrSer(c0))
	h.Write(thrSer(r))
	var e btcec.ModNScalar
	e.SetByteSlice(h.Sum(nil))
	return e
}

func thrNewDealer(t testing.TB, ctx string, id int) *thrDealer {
	t.Helper()
	coeffs := make([]btcec.ModNScalar, thrT)
	d := &thrDealer{id: id, shares: map[int]btcec.ModNScalar{}}
	for i := range coeffs {
		coeffs[i] = thrRandom(t)
		d.commits = append(d.commits, thrMulG(&coeffs[i]))
	}
	for _, j := range thrIDs {
		x := thrScalar(j)
		share := coeffs[thrT-1]
		for k := thrT - 2; k >= 0; k-- {
			share.Mul(&x)
			share.Add(&coeffs[k])
		}
		d.shares[j] = share
	}
	r := thrRandom(t)
	d.proofR = thrMulG(&r)
	e := thrProofChallenge(ctx, id, &d.commits[0], &d.proofR)
	e.Mul(&coeffs[0])
	e.Add(&r)
	d.proofZ = e
	return d
}

func thrEvalCommit(commits []btcec.JacobianPoint, j int) btcec.JacobianPoint {
	x := thrScalar(j)
	res := commits[len(commits)-1]
	for k := len(commits) - 2; k >= 0; k-- {
		res = thrMul(&x, &res)
		res = thrAdd(&res, &commits[k])
	}
	return res
}

// thrKey is one shared secret: the signing key or one digit's nonce.
type thrKey struct {
	group     btcec.JacobianPoint
	shares    map[int]btcec.ModNScalar
	verify    map[int]btcec.JacobianPoint
	qualified []int
	excluded  map[int]string
}

func thrDKG(t testing.TB, ctx string, tamper map[int]func(*thrDealer)) (*thrKey, error) {
	t.Helper()
	dealers := map[int]*thrDealer{}
	for _, id := range thrIDs {
		d := thrNewDealer(t, ctx, id)
		if fn := tamper[id]; fn != nil {
			fn(d)
		}
		dealers[id] = d
	}
	excluded := map[int]string{}
	evals := map[[2]int]btcec.JacobianPoint{}
	for _, id := range thrIDs {
		d := dealers[id]
		e := thrProofChallenge(ctx, id, &d.commits[0], &d.proofR)
		lhs := thrMulG(&d.proofZ)
		ec := thrMul(&e, &d.commits[0])
		rhs := thrAdd(&d.proofR, &ec)
		if !thrEqual(&lhs, &rhs) {
			excluded[id] = "invalid proof of knowledge"
			continue
		}
		for _, j := range thrIDs {
			want := thrEvalCommit(d.commits, j)
			evals[[2]int{id, j}] = want
			share := d.shares[j]
			got := thrMulG(&share)
			if !thrEqual(&got, &want) {
				excluded[id] = fmt.Sprintf("invalid share for member %d", j)
				break
			}
		}
	}
	var qualified []int
	for _, id := range thrIDs {
		if _, bad := excluded[id]; !bad {
			qualified = append(qualified, id)
		}
	}
	if len(qualified) < thrT {
		return nil, fmt.Errorf("only %d qualified members", len(qualified))
	}

	k := &thrKey{
		shares: map[int]btcec.ModNScalar{}, verify: map[int]btcec.JacobianPoint{},
		qualified: qualified, excluded: excluded,
	}
	var group btcec.JacobianPoint
	for n, id := range qualified {
		if n == 0 {
			group = dealers[id].commits[0]
		} else {
			group = thrAdd(&group, &dealers[id].commits[0])
		}
	}
	flip := group.Y.IsOdd()
	if flip {
		thrNegate(&group)
	}
	k.group = group
	for _, j := range qualified {
		var share btcec.ModNScalar
		var v btcec.JacobianPoint
		for n, id := range qualified {
			s := dealers[id].shares[j]
			share.Add(&s)
			e := evals[[2]int{id, j}]
			if n == 0 {
				v = e
			} else {
				v = thrAdd(&v, &e)
			}
		}
		if flip {
			share.Negate()
			thrNegate(&v)
		}
		k.shares[j], k.verify[j] = share, v
	}
	return k, nil
}

func thrLagrange(j int, set []int) btcec.ModNScalar {
	out := thrScalar(1)
	js := thrScalar(j)
	for _, m := range set {
		if m == j {
			continue
		}
		ms := thrScalar(m)
		diff := js
		diff.Negate()
		diff.Add(&ms)
		diff.InverseNonConst()
		out.Mul(&ms)
		out.Mul(&diff)
	}
	return out
}

type thrEvent struct {
	key    *thrKey
	nonces [numDigits]*thrKey
	rx     [numDigits][]byte
	px     []byte
	ora    *oracle
}

func thrNewEvent(t testing.TB, key *thrKey, id string) *thrEvent {
	t.Helper()
	e := &thrEvent{key: key, ora: &oracle{cache: map[prefix]btcec.JacobianPoint{}}}
	e.px = thrSer(&key.group)[1:]
	for i := range numDigits {
		nonce, err := thrDKG(t, fmt.Sprintf("%s/digit/%d", id, i), nil)
		require.NoError(t, err)
		e.nonces[i] = nonce
		e.rx[i] = thrSer(&nonce.group)[1:]
		for b := range 2 {
			c := taggedChallenge(e.rx[i], e.px, attestationMsg(byte('0'+b)))
			cP := thrMul(&c, &key.group)
			e.ora.digit[i][b] = thrAdd(&nonce.group, &cP)
		}
	}
	return e
}

func thrBit(price uint32, i int) byte {
	return byte('0' + (price>>(numDigits-1-uint(i)))&1)
}

func (e *thrEvent) partial(j int, price uint32) [numDigits]btcec.ModNScalar {
	var out [numDigits]btcec.ModNScalar
	x := e.key.shares[j]
	for i := range numDigits {
		c := taggedChallenge(e.rx[i], e.px, attestationMsg(thrBit(price, i)))
		c.Mul(&x)
		k := e.nonces[i].shares[j]
		c.Add(&k)
		out[i] = c
	}
	return out
}

// checkPartial returns the first bad digit, or -1. It identifies a cheating member.
func (e *thrEvent) checkPartial(j int, price uint32, p [numDigits]btcec.ModNScalar) int {
	vx := e.key.verify[j]
	for i := range numDigits {
		c := taggedChallenge(e.rx[i], e.px, attestationMsg(thrBit(price, i)))
		lhs := thrMulG(&p[i])
		cX := thrMul(&c, &vx)
		vk := e.nonces[i].verify[j]
		rhs := thrAdd(&vk, &cX)
		if !thrEqual(&lhs, &rhs) {
			return i
		}
	}
	return -1
}

func (e *thrEvent) aggregate(
	set []int, parts map[int][numDigits]btcec.ModNScalar,
) [numDigits]btcec.ModNScalar {
	var out [numDigits]btcec.ModNScalar
	for _, j := range set {
		l := thrLagrange(j, set)
		p := parts[j]
		for i := range numDigits {
			v := p[i]
			v.Mul(&l)
			out[i].Add(&v)
		}
	}
	return out
}

func (e *thrEvent) validSignature(price uint32, i int, s *btcec.ModNScalar) bool {
	b := s.Bytes()
	sig, err := schnorr.ParseSignature(append(append([]byte{}, e.rx[i]...), b[:]...))
	if err != nil {
		return false
	}
	pub, err := schnorr.ParsePubKey(e.px)
	if err != nil {
		return false
	}
	return sig.Verify(attestationMsg(thrBit(price, i)), pub)
}

func (e *thrEvent) allValid(price uint32, sigs [numDigits]btcec.ModNScalar) bool {
	for i := range numDigits {
		if !e.validSignature(price, i, &sigs[i]) {
			return false
		}
	}
	return true
}

func thrPrefixSecret(sigs [numDigits]btcec.ModNScalar, p prefix) btcec.ModNScalar {
	var out btcec.ModNScalar
	for i := range int(p.bits) {
		out.Add(&sigs[i])
	}
	return out
}

// Price agreement: Dolev-Strong broadcast with f+1 = 3 synchronous rounds.

type thrChain struct {
	value   uint32
	signers []int
	sigs    []*schnorr.Signature
}

type thrLate struct {
	round, to int
	value     uint32
	by        []int
}

type thrBehavior struct {
	offline bool
	send    func(to int) (uint32, bool)
	late    []thrLate
}

type thrNetwork struct {
	event string
	keys  map[int]*party
}

func (n *thrNetwork) statement(sender int, value uint32) []byte {
	h := sha256.New()
	h.Write([]byte("p2pfiat/price-report"))
	h.Write([]byte(n.event))
	_ = binary.Write(h, binary.LittleEndian, uint32(sender))
	_ = binary.Write(h, binary.LittleEndian, value)
	return h.Sum(nil)
}

func (n *thrNetwork) sign(t testing.TB, id, sender int, value uint32) *schnorr.Signature {
	t.Helper()
	b := n.keys[id].d.Bytes()
	priv, _ := btcec.PrivKeyFromBytes(b[:])
	sig, err := schnorr.Sign(priv, n.statement(sender, value))
	require.NoError(t, err)
	return sig
}

func (n *thrNetwork) validChain(sender, round int, c *thrChain) bool {
	if len(c.signers) != round || c.signers[0] != sender {
		return false
	}
	msg := n.statement(sender, c.value)
	seen := map[int]bool{}
	for i, id := range c.signers {
		if seen[id] || !c.sigs[i].Verify(msg, n.keys[id].pub) {
			return false
		}
		seen[id] = true
	}
	return true
}

// broadcast returns what each honest member accepts from one sender.
func (n *thrNetwork) broadcast(
	t testing.TB, sender int, honest []int, b thrBehavior,
) map[int]*uint32 {
	t.Helper()
	rounds := thrFaulty + 1
	inbox := make([]map[int][]*thrChain, rounds+2)
	for r := range inbox {
		inbox[r] = map[int][]*thrChain{}
	}
	if !b.offline {
		for _, to := range thrIDs {
			if to == sender {
				continue
			}
			if v, ok := b.send(to); ok {
				inbox[1][to] = append(inbox[1][to], &thrChain{
					value: v, signers: []int{sender},
					sigs: []*schnorr.Signature{n.sign(t, sender, sender, v)},
				})
			}
		}
		for _, l := range b.late {
			c := &thrChain{value: l.value}
			for _, id := range l.by {
				c.signers = append(c.signers, id)
				c.sigs = append(c.sigs, n.sign(t, id, sender, l.value))
			}
			inbox[l.round][l.to] = append(inbox[l.round][l.to], c)
		}
	}
	extracted := map[int][]uint32{}
	if slices.Contains(honest, sender) && !b.offline {
		v, _ := b.send(sender)
		extracted[sender] = []uint32{v}
	}
	for r := 1; r <= rounds; r++ {
		for _, j := range honest {
			for _, c := range inbox[r][j] {
				if !n.validChain(sender, r, c) || slices.Contains(extracted[j], c.value) ||
					len(extracted[j]) >= 2 {
					continue
				}
				extracted[j] = append(extracted[j], c.value)
				if r == rounds || slices.Contains(c.signers, j) {
					continue
				}
				next := &thrChain{
					value:   c.value,
					signers: append(slices.Clone(c.signers), j),
					sigs:    append(slices.Clone(c.sigs), n.sign(t, j, sender, c.value)),
				}
				for _, to := range thrIDs {
					if to != j {
						inbox[r+1][to] = append(inbox[r+1][to], next)
					}
				}
			}
		}
	}
	out := map[int]*uint32{}
	for _, j := range honest {
		if len(extracted[j]) == 1 {
			v := extracted[j][0]
			out[j] = &v
		} else {
			out[j] = nil
		}
	}
	return out
}

// agree returns the price each honest member will sign, if any.
func (n *thrNetwork) agree(
	t testing.TB, own map[int]uint32, faulty map[int]thrBehavior,
) map[int]*uint32 {
	t.Helper()
	honest := make([]int, 0, len(own))
	for _, id := range thrIDs {
		if _, ok := own[id]; ok {
			honest = append(honest, id)
		}
	}
	values := map[int][]uint32{}
	for _, sender := range thrIDs {
		b, bad := faulty[sender]
		if !bad {
			v := own[sender]
			b = thrBehavior{send: func(int) (uint32, bool) { return v, true }}
		}
		for j, got := range n.broadcast(t, sender, honest, b) {
			if got != nil {
				values[j] = append(values[j], *got)
			}
		}
	}
	out := map[int]*uint32{}
	for _, j := range honest {
		vs := values[j]
		if len(vs) < thrT {
			out[j] = nil
			continue
		}
		slices.Sort(vs)
		m := vs[(len(vs)-1)/2]
		diff := float64(int64(m)-int64(own[j])) / float64(own[j])
		if diff < -thrMaxDeviation || diff > thrMaxDeviation {
			out[j] = nil
			continue
		}
		out[j] = &m
	}
	return out
}

func thrNetworkFor(t testing.TB, event string) *thrNetwork {
	t.Helper()
	n := &thrNetwork{event: event, keys: map[int]*party{}}
	for _, id := range thrIDs {
		n.keys[id] = newParty(t)
	}
	return n
}

// A price certificate stops a network split from producing two attestations.
// Each member votes once, and signs only with thrVoteQuorum votes for one price.
const thrVoteQuorum = 4

type thrVote struct {
	voter int
	price uint32
	sig   *schnorr.Signature
}

func (n *thrNetwork) voteHash(price uint32) []byte {
	h := sha256.New()
	h.Write([]byte("p2pfiat/price-vote"))
	h.Write([]byte(n.event))
	_ = binary.Write(h, binary.LittleEndian, price)
	return h.Sum(nil)
}

func (n *thrNetwork) vote(t testing.TB, voter int, price uint32) thrVote {
	t.Helper()
	b := n.keys[voter].d.Bytes()
	priv, _ := btcec.PrivKeyFromBytes(b[:])
	sig, err := schnorr.Sign(priv, n.voteHash(price))
	require.NoError(t, err)
	return thrVote{voter: voter, price: price, sig: sig}
}

func (n *thrNetwork) certified(votes []thrVote, price uint32, quorum int) bool {
	msg := n.voteHash(price)
	seen := map[int]bool{}
	for _, v := range votes {
		if v.price == price && !seen[v.voter] && v.sig.Verify(msg, n.keys[v.voter].pub) {
			seen[v.voter] = true
		}
	}
	return len(seen) >= quorum
}

func thrRecoverKey(
	e *thrEvent, a, b uint32, sa, sb [numDigits]btcec.ModNScalar,
) btcec.JacobianPoint {
	last := numDigits - 1
	ca := taggedChallenge(e.rx[last], e.px, attestationMsg(thrBit(a, last)))
	cb := taggedChallenge(e.rx[last], e.px, attestationMsg(thrBit(b, last)))
	ds := sa[last]
	nb := sb[last]
	nb.Negate()
	ds.Add(&nb)
	dc := ca
	nc := cb
	nc.Negate()
	dc.Add(&nc)
	dc.InverseNonConst()
	ds.Mul(&dc)
	return thrMulG(&ds)
}

func thrRequireSame(t *testing.T, got map[int]*uint32, ids []int) uint32 {
	t.Helper()
	require.NotNil(t, got[ids[0]])
	v := *got[ids[0]]
	for _, id := range ids {
		require.NotNil(t, got[id], "member %d did not decide", id)
		require.Equal(t, v, *got[id], "members disagree")
	}
	return v
}

func TestP2pFiatThresholdOracle(t *testing.T) {
	start := time.Now()
	key, err := thrDKG(t, "group-key", nil)
	require.NoError(t, err)
	keyTime := time.Since(start)
	require.False(t, key.group.Y.IsOdd())
	require.Len(t, key.qualified, thrN)

	start = time.Now()
	event := thrNewEvent(t, key, "timing-event")
	eventTime := time.Since(start)
	t.Logf("key setup %.3fs; event setup (20 nonce DKGs, all 5 members in one process) %.3fs",
		keyTime.Seconds(), eventTime.Seconds())
	t.Logf("traffic sent per member per event: %.1f KB", float64(thrDealerBytes*numDigits)/1024)

	price := uint32(100_123)
	parts := map[int][numDigits]btcec.ModNScalar{}
	for _, id := range thrIDs {
		parts[id] = event.partial(id, price)
		require.Equal(t, -1, event.checkPartial(id, price, parts[id]))
	}

	t.Run("any 3 of 5 produce the same valid attestation", func(t *testing.T) {
		var first [numDigits]btcec.ModNScalar
		for n, q := range subsets(thrN, thrT) {
			set := []int{q[0] + 1, q[1] + 1, q[2] + 1}
			sigs := event.aggregate(set, parts)
			require.True(t, event.allValid(price, sigs), "group %v", set)
			if n == 0 {
				first = sigs
				continue
			}
			for i := range numDigits {
				require.True(t, first[i].Equals(&sigs[i]), "group %v digit %d", set, i)
			}
		}
	})

	t.Run("two members cannot attest", func(t *testing.T) {
		sigs := event.aggregate([]int{1, 2}, parts)
		require.False(t, event.validSignature(price, 0, &sigs[0]))
	})

	t.Run("invalid partial signature identifies the member", func(t *testing.T) {
		bad := parts[2]
		one := thrScalar(1)
		bad[7].Add(&one)
		require.Equal(t, 7, event.checkPartial(2, price, bad))
		wrong := map[int][numDigits]btcec.ModNScalar{1: parts[1], 2: bad, 3: parts[3]}
		sigs := event.aggregate([]int{1, 2, 3}, wrong)
		require.False(t, event.allValid(price, sigs))
	})

	t.Run("bad DKG share excludes the dealer", func(t *testing.T) {
		k, err := thrDKG(t, "bad-share", map[int]func(*thrDealer){2: func(d *thrDealer) {
			s := d.shares[4]
			one := thrScalar(1)
			s.Add(&one)
			d.shares[4] = s
		}})
		require.NoError(t, err)
		require.Equal(t, []int{1, 3, 4, 5}, k.qualified)
		require.Contains(t, k.excluded[2], "invalid share")
	})

	t.Run("rogue key without proof is excluded", func(t *testing.T) {
		honest := thrNewDealer(t, "rogue", 1)
		k, err := thrDKG(t, "rogue", map[int]func(*thrDealer){3: func(d *thrDealer) {
			target := thrRandom(t)
			tp := thrMulG(&target)
			neg := honest.commits[0]
			thrNegate(&neg)
			d.commits[0] = thrAdd(&tp, &neg)
		}})
		require.NoError(t, err)
		require.Contains(t, k.excluded[3], "invalid proof")
	})

	t.Run("three failed dealers abort key generation", func(t *testing.T) {
		corrupt := func(d *thrDealer) {
			s := d.shares[1]
			one := thrScalar(1)
			s.Add(&one)
			d.shares[1] = s
		}
		_, err := thrDKG(t, "abort", map[int]func(*thrDealer){2: corrupt, 3: corrupt, 4: corrupt})
		require.ErrorContains(t, err, "qualified")
	})

	honestPrices := func() map[int]uint32 {
		return map[int]uint32{1: 100_000, 2: 100_040, 3: 99_960, 4: 100_020, 5: 99_980}
	}

	t.Run("agreement with all members honest", func(t *testing.T) {
		n := thrNetworkFor(t, "agree-honest")
		got := n.agree(t, honestPrices(), nil)
		require.Equal(t, uint32(100_000), thrRequireSame(t, got, thrIDs))
	})

	t.Run("two members lying cannot move the price outside honest reports", func(t *testing.T) {
		for _, extreme := range []uint32{1, maxPrice} {
			own := honestPrices()
			delete(own, 4)
			delete(own, 5)
			send := func(int) (uint32, bool) { return extreme, true }
			n := thrNetworkFor(t, fmt.Sprintf("agree-liars-%d", extreme))
			got := n.agree(t, own, map[int]thrBehavior{4: {send: send}, 5: {send: send}})
			v := thrRequireSame(t, got, []int{1, 2, 3})
			require.GreaterOrEqual(t, v, uint32(99_960))
			require.LessOrEqual(t, v, uint32(100_040))
		}
	})

	t.Run("two members offline still attest", func(t *testing.T) {
		own := honestPrices()
		delete(own, 2)
		delete(own, 4)
		n := thrNetworkFor(t, "agree-offline")
		got := n.agree(t, own, map[int]thrBehavior{2: {offline: true}, 4: {offline: true}})
		thrRequireSame(t, got, []int{1, 3, 5})
	})

	t.Run("three members offline produce no attestation", func(t *testing.T) {
		own := map[int]uint32{1: 100_000, 2: 100_010}
		n := thrNetworkFor(t, "agree-three-offline")
		got := n.agree(t, own, map[int]thrBehavior{
			3: {offline: true}, 4: {offline: true}, 5: {offline: true},
		})
		require.Nil(t, got[1])
		require.Nil(t, got[2])
	})

	t.Run("equivocating and late reports cannot split honest members", func(t *testing.T) {
		own := honestPrices()
		delete(own, 4)
		delete(own, 5)
		n := thrNetworkFor(t, "agree-equivocate")
		got := n.agree(t, own, map[int]thrBehavior{
			4: {send: func(to int) (uint32, bool) {
				if to%2 == 0 {
					return 100_500, true
				}
				return 99_500, true
			}},
			5: {
				send: func(int) (uint32, bool) { return 0, false },
				late: []thrLate{{round: 2, to: 1, value: 100_700, by: []int{5, 4}}},
			},
		})
		thrRequireSame(t, got, []int{1, 2, 3})
	})

	t.Run("honest member refuses a price far from its own", func(t *testing.T) {
		own := map[int]uint32{1: 100_000, 2: 100_000, 3: 120_000}
		send := func(int) (uint32, bool) { return 100_000, true }
		n := thrNetworkFor(t, "agree-refuse")
		got := n.agree(t, own, map[int]thrBehavior{4: {send: send}, 5: {send: send}})
		require.Nil(t, got[3])
		require.NotNil(t, got[1])
	})

	t.Run("three members signing two prices leak the group key", func(t *testing.T) {
		e := thrNewEvent(t, key, "equivocation")
		set := []int{1, 2, 3}
		a, b := uint32(100_000), uint32(100_001) // differ in the last digit
		pa, pb := map[int][numDigits]btcec.ModNScalar{}, map[int][numDigits]btcec.ModNScalar{}
		for _, id := range set {
			pa[id], pb[id] = e.partial(id, a), e.partial(id, b)
		}
		sa, sb := e.aggregate(set, pa), e.aggregate(set, pb)
		require.True(t, e.allValid(a, sa))
		require.True(t, e.allValid(b, sb))
		last := numDigits - 1
		ca := taggedChallenge(e.rx[last], e.px, attestationMsg(thrBit(a, last)))
		cb := taggedChallenge(e.rx[last], e.px, attestationMsg(thrBit(b, last)))
		ds := sa[last]
		nb := sb[last]
		nb.Negate()
		ds.Add(&nb)
		dc := ca
		nc := cb
		nc.Negate()
		dc.Add(&nc)
		dc.InverseNonConst()
		ds.Mul(&dc)
		recovered := thrMulG(&ds)
		require.True(t, thrEqual(&recovered, &key.group), "equivocation must reveal the key")
		t.Log("two attestations for one event revealed the whole group key")
	})

	t.Run("network split plus two malicious members leaks the key without a certificate", func(t *testing.T) {
		e := thrNewEvent(t, key, "split-attack")
		a, b := uint32(100_000), uint32(100_001)
		// Honest members 1 and 2 reached different prices. Members 4 and 5 are malicious.
		pa := map[int][numDigits]btcec.ModNScalar{
			1: e.partial(1, a), 4: e.partial(4, a), 5: e.partial(5, a),
		}
		pb := map[int][numDigits]btcec.ModNScalar{
			2: e.partial(2, b), 4: e.partial(4, b), 5: e.partial(5, b),
		}
		sa, sb := e.aggregate([]int{1, 4, 5}, pa), e.aggregate([]int{2, 4, 5}, pb)
		require.True(t, e.allValid(a, sa))
		require.True(t, e.allValid(b, sb))
		recovered := thrRecoverKey(e, a, b, sa, sb)
		require.True(t, thrEqual(&recovered, &key.group))
		t.Log("2 malicious members and a split between honest members revealed the group key")
	})

	t.Run("price certificate blocks every split", func(t *testing.T) {
		n := thrNetworkFor(t, "certificate-split")
		a, b := uint32(100_000), uint32(100_001)
		var weak bool
		for mask := range 8 {
			votes := []thrVote{
				n.vote(t, 4, a), n.vote(t, 4, b), n.vote(t, 5, a), n.vote(t, 5, b),
			}
			for i, honest := range []int{1, 2, 3} {
				price := a
				if mask>>i&1 == 1 {
					price = b
				}
				votes = append(votes, n.vote(t, honest, price))
			}
			require.False(t,
				n.certified(votes, a, thrVoteQuorum) && n.certified(votes, b, thrVoteQuorum),
				"two certificates for split %03b", mask)
			weak = weak || (n.certified(votes, a, 3) && n.certified(votes, b, 3))
		}
		require.True(t, weak, "a quorum of 3 must be shown to be unsafe")
	})

	t.Run("quorum sizes for two malicious members", func(t *testing.T) {
		for _, c := range []struct {
			n, f, q    int
			safe, live bool
		}{
			{5, 2, 3, false, true},
			{5, 2, 4, true, false},
			{7, 2, 4, false, true},
			{7, 2, 5, true, true},
		} {
			h := c.n - c.f
			safe := true
			for honestA := 0; honestA <= h; honestA++ {
				if honestA+c.f >= c.q && h-honestA+c.f >= c.q {
					safe = false
				}
			}
			require.Equal(t, c.safe, safe, "n=%d q=%d safety", c.n, c.q)
			require.Equal(t, c.live, h >= c.q, "n=%d q=%d liveness", c.n, c.q)
			t.Logf("n=%d, 2 malicious, vote quorum %d: split-safe=%v, still attests if they stop=%v",
				c.n, c.q, safe, h >= c.q)
		}
	})

	t.Run("certificate needs four of five members", func(t *testing.T) {
		n := thrNetworkFor(t, "certificate-liveness")
		e := thrNewEvent(t, key, "certificate-liveness")
		p := uint32(100_000)
		votes := []thrVote{n.vote(t, 1, p), n.vote(t, 2, p), n.vote(t, 3, p)}
		require.False(t, n.certified(votes, p, thrVoteQuorum), "3 votes must not certify")
		votes = append(votes, n.vote(t, 5, p))
		require.True(t, n.certified(votes, p, thrVoteQuorum), "4 votes must certify")
		set := []int{1, 3, 5}
		tp := map[int][numDigits]btcec.ModNScalar{}
		for _, m := range set {
			tp[m] = e.partial(m, p)
		}
		require.True(t, e.allValid(p, e.aggregate(set, tp)))
	})

	rec := scenario{rounding: 1000, tol: 1, bandPct: 25, k: 1, n: 1}
	primaries, payouts := rec.primaries()
	c := newContract(t)
	txCache := map[int64]*payoutTxs{}
	for _, p := range primaries {
		if _, ok := txCache[p.payout]; !ok {
			txCache[p.payout] = c.payoutTxs(t, p.payout)
		}
	}

	const trials = 40
	t.Run("threshold attestations settle through Bitcoin script", func(t *testing.T) {
		lo, hi := rec.band()
		for trial := range trials {
			id := fmt.Sprintf("settle-%d", trial)
			e := thrNewEvent(t, key, id)
			base := lo + 1000 + rand.Uint32N(hi-lo-2000)
			own := map[int]uint32{}
			for _, m := range thrIDs {
				own[m] = uint32(int64(base) + int64(rand.IntN(101)) - 50)
			}
			n := thrNetworkFor(t, id)
			decided := thrRequireSame(t, n.agree(t, own, nil), thrIDs)
			voters := append([]int{}, thrIDs...)
			rand.Shuffle(len(voters), func(i, j int) { voters[i], voters[j] = voters[j], voters[i] })
			votes := make([]thrVote, 0, thrVoteQuorum)
			for _, m := range voters[:thrVoteQuorum] {
				votes = append(votes, n.vote(t, m, decided))
			}
			require.True(t, n.certified(votes, decided, thrVoteQuorum))
			p := findPrimary(primaries, decided)
			require.NotNil(t, p)
			require.Equal(t, rec.payout(decided), p.payout)
			T := e.ora.point(p.prefix)
			txs := txCache[p.payout]
			ads := make([]*adaptor, 0, signersPerRoll)
			for _, s := range c.signers() {
				a, err := adaptorSign(s.d, s.px, txs.exitMsg, &T)
				require.NoError(t, err)
				require.True(t, a.verify(&s.j, s.px, txs.exitMsg))
				ads = append(ads, a)
			}
			// Any 3 of the members holding the certificate can sign.
			set := append([]int{}, voters[:thrT]...)
			slices.Sort(set)
			tp := map[int][numDigits]btcec.ModNScalar{}
			for _, m := range set {
				tp[m] = e.partial(m, decided)
				require.Equal(t, -1, e.checkPartial(m, decided, tp[m]))
			}
			sigs := e.aggregate(set, tp)
			require.True(t, e.allValid(decided, sigs))
			secret := thrPrefixSecret(sigs, p.prefix)
			final := make([]*schnorr.Signature, 0, signersPerRoll)
			for i, a := range ads {
				sig := a.complete(t, secret)
				require.True(t, sig.Verify(txs.exitMsg, c.signers()[i].pub))
				final = append(final, sig)
			}
			require.NoError(t, c.spendExit(t, txs, final))
		}
		t.Logf("%d threshold settlements passed the Bitcoin script engine", trials)
	})

	t.Run("cost of a full roll", func(t *testing.T) {
		start := time.Now()
		agreeNet := thrNetworkFor(t, "timing-agree")
		own := honestPrices()
		decided := thrRequireSame(t, agreeNet.agree(t, own, nil), thrIDs)
		agreeTime := time.Since(start)
		start = time.Now()
		tp := map[int][numDigits]btcec.ModNScalar{}
		set := []int{1, 3, 5}
		for _, m := range set {
			tp[m] = event.partial(m, decided)
			require.Equal(t, -1, event.checkPartial(m, decided, tp[m]))
		}
		sigs := event.aggregate(set, tp)
		require.True(t, event.allValid(decided, sigs))
		attestTime := time.Since(start)

		type job struct {
			msg []byte
			T   btcec.JacobianPoint
		}
		jobs := make([]job, 0, len(primaries))
		for i := range primaries {
			jobs = append(jobs, job{
				msg: txCache[primaries[i].payout].exitMsg, T: event.ora.point(primaries[i].prefix),
			})
		}
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
			if a, err := adaptorSign(s.d, s.px, jobs[i].msg, &jobs[i].T); err == nil {
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
		perPosition := signTime.Seconds() + 3*verifyTime.Seconds()
		t.Logf("agreement %.3fs; attestation by 3 members %.3fs", agreeTime.Seconds(), attestTime.Seconds())
		t.Logf("roll: payouts=%d adaptors=%d sign=%.3fs verify_one=%.3fs data_per_signer=%s stored=%s",
			payouts, len(jobs), signTime.Seconds(), verifyTime.Seconds(),
			human(float64(len(jobs))*adaptorBytes), human(float64(len(jobs))*adaptorBytes*signersPerRoll))
		t.Logf("per position per signer %.3fs, capacity %.0f positions per day on %d cores",
			perPosition, 86400/perPosition, runtime.GOMAXPROCS(0))
	})
}
