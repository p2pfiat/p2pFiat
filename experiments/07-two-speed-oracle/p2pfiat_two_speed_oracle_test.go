package p2pfiatcost

// Experiment 7: a 4-of-7 threshold oracle with two-speed price voting.
//
// Members sign after 5 matching votes, or after 4 matching votes once a long
// timeout has passed. Each event has its own key, certified by a long-term group
// key, so a key leak is limited to one event.
//
// Network behaviour is a discrete-event simulation with authenticated messages.
// Attestations, key generation and contract signatures use real cryptography.
// This is a research prototype and has not had a cryptographic review.
//
// Needs ../05-numeric-signing-cost and ../06-threshold-oracle. Copy all three
// test files into arkd's internal/test/p2pfiatcost directory and run with:
//   go test -v -count 1 -timeout 1500s -run TestP2pFiatTwoSpeedOracle ./internal/test/p2pfiatcost

import (
	"container/heap"
	"crypto/sha256"
	"fmt"
	"math"
	"math/bits"
	"math/rand/v2"
	"slices"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/stretchr/testify/require"
)

const (
	gN              = 7
	gT              = 4
	gFastVotes      = 5
	gSlowVotes      = 4
	gReportDeadline = 30
	gSlowTimeout    = 600
	gGrace          = 60 // a slow certificate must stay valid this long before signing
	gShortSplit     = 300
	gLongSplit      = 900
	gMaxDeviation   = 0.01
	gPriceA         = uint32(100_000)
	gPriceB         = uint32(100_501) // differs from A in the last digit
	// One dealer's traffic per DKG: 4 commitments, a proof, and 6 private shares.
	gDealerBytes = 4*33 + 33 + 32 + 6*32
	gDKGsPerEvent = numDigits + 2 // digit nonces, event key, certificate nonce
)

var gIDs = []int{1, 2, 3, 4, 5, 6, 7}

func gNewDealer(t testing.TB, ctx string, id int) *thrDealer {
	t.Helper()
	coeffs := make([]btcec.ModNScalar, gT)
	d := &thrDealer{id: id, shares: map[int]btcec.ModNScalar{}}
	for i := range coeffs {
		coeffs[i] = thrRandom(t)
		d.commits = append(d.commits, thrMulG(&coeffs[i]))
	}
	for _, j := range gIDs {
		x := thrScalar(j)
		share := coeffs[gT-1]
		for k := gT - 2; k >= 0; k-- {
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

func gDKG(t testing.TB, ctx string) *thrKey {
	t.Helper()
	dealers := map[int]*thrDealer{}
	evals := map[[2]int]btcec.JacobianPoint{}
	for _, id := range gIDs {
		d := gNewDealer(t, ctx, id)
		dealers[id] = d
		e := thrProofChallenge(ctx, id, &d.commits[0], &d.proofR)
		lhs := thrMulG(&d.proofZ)
		ec := thrMul(&e, &d.commits[0])
		rhs := thrAdd(&d.proofR, &ec)
		require.True(t, thrEqual(&lhs, &rhs))
		for _, j := range gIDs {
			want := thrEvalCommit(d.commits, j)
			share := d.shares[j]
			got := thrMulG(&share)
			require.True(t, thrEqual(&got, &want))
			evals[[2]int{id, j}] = want
		}
	}
	k := &thrKey{
		shares: map[int]btcec.ModNScalar{}, verify: map[int]btcec.JacobianPoint{},
		qualified: slices.Clone(gIDs), excluded: map[int]string{},
	}
	group := dealers[1].commits[0]
	for _, id := range gIDs[1:] {
		group = thrAdd(&group, &dealers[id].commits[0])
	}
	flip := group.Y.IsOdd()
	if flip {
		thrNegate(&group)
	}
	k.group = group
	for _, j := range gIDs {
		var share btcec.ModNScalar
		v := evals[[2]int{1, j}]
		for n, id := range gIDs {
			s := dealers[id].shares[j]
			share.Add(&s)
			if n > 0 {
				e := evals[[2]int{id, j}]
				v = thrAdd(&v, &e)
			}
		}
		if flip {
			share.Negate()
			thrNegate(&v)
		}
		k.shares[j], k.verify[j] = share, v
	}
	return k
}

// gEvent has its own signing key, certified by the long-term group key.
type gEvent struct {
	*thrEvent
	certMsg []byte
	cert    *schnorr.Signature
}

func gNewEvent(t testing.TB, longTerm *thrKey, id string) *gEvent {
	t.Helper()
	key := gDKG(t, id+"/key")
	e := &thrEvent{key: key, ora: &oracle{cache: map[prefix]btcec.JacobianPoint{}}}
	e.px = thrSer(&key.group)[1:]
	h := sha256.New()
	h.Write([]byte("p2pfiat/event-announcement"))
	h.Write([]byte(id))
	h.Write(e.px)
	for i := range numDigits {
		nonce := gDKG(t, fmt.Sprintf("%s/digit/%d", id, i))
		e.nonces[i] = nonce
		e.rx[i] = thrSer(&nonce.group)[1:]
		h.Write(e.rx[i])
		for b := range 2 {
			c := taggedChallenge(e.rx[i], e.px, attestationMsg(byte('0'+b)))
			cP := thrMul(&c, &key.group)
			e.ora.digit[i][b] = thrAdd(&nonce.group, &cP)
		}
	}
	msg := h.Sum(nil)

	certNonce := gDKG(t, id+"/cert")
	rx := thrSer(&certNonce.group)[1:]
	longPx := thrSer(&longTerm.group)[1:]
	c := taggedChallenge(rx, longPx, msg)
	set := []int{1, 2, 3, 4}
	var s btcec.ModNScalar
	for _, j := range set {
		part := c
		x := longTerm.shares[j]
		part.Mul(&x)
		k := certNonce.shares[j]
		part.Add(&k)
		l := thrLagrange(j, set)
		part.Mul(&l)
		s.Add(&part)
	}
	b := s.Bytes()
	cert, err := schnorr.ParseSignature(append(append([]byte{}, rx...), b[:]...))
	require.NoError(t, err)
	return &gEvent{thrEvent: e, certMsg: msg, cert: cert}
}

func gAttest(e *gEvent, set []int, price uint32) [numDigits]btcec.ModNScalar {
	parts := map[int][numDigits]btcec.ModNScalar{}
	for _, j := range set {
		parts[j] = e.partial(j, price)
	}
	return e.aggregate(set, parts)
}

// Network simulation.

const (
	gReport byte = iota
	gVote
)

type gMsg struct {
	kind  byte
	from  int
	price uint32
}

type gItem struct {
	at, seq, to, tick int
	msg               gMsg
}

type gQueue []gItem

func (q gQueue) Len() int { return len(q) }
func (q gQueue) Less(i, j int) bool {
	if q[i].at != q[j].at {
		return q[i].at < q[j].at
	}
	return q[i].seq < q[j].seq
}
func (q gQueue) Swap(i, j int) { q[i], q[j] = q[j], q[i] }
func (q *gQueue) Push(x any)   { *q = append(*q, x.(gItem)) }
func (q *gQueue) Pop() any {
	old := *q
	n := len(old)
	x := old[n-1]
	*q = old[:n-1]
	return x
}

type gMember struct {
	id        int
	own       uint32
	reports   map[int]uint32
	reportBad map[int]bool
	votes     map[int]uint32
	voteBad   map[int]bool
	seen      map[gMsg]bool
	voted     bool
	vote      uint32
	signed    bool
	certAt    int
}

type gSim struct {
	own       map[int]uint32 // honest, online members
	malicious map[int]string // "split", "extreme-low", "extreme-high" or "silent"
	sides     map[int]int
	healAt    int
	voteAt    [2]int // when "split" members send their vote to each side
	noGrace   bool   // the unsafe rule: sign as soon as the slow certificate exists
	scripted  []gScriptedVote
	maxJitter int // extra random delay on each honest message, in seconds
}

// gScriptedVote is one vote a malicious member sends to one honest member.
type gScriptedVote struct {
	from, to, at int
	price        uint32
}

type gSignature struct {
	member, at int
}

type gResult struct {
	signed map[uint32][]gSignature
}

func gRun(s gSim) *gResult {
	r := &gResult{signed: map[uint32][]gSignature{}}
	members := map[int]*gMember{}
	for id, p := range s.own {
		members[id] = &gMember{
			id: id, own: p, reports: map[int]uint32{id: p}, reportBad: map[int]bool{},
			votes: map[int]uint32{}, voteBad: map[int]bool{}, seen: map[gMsg]bool{}, certAt: -1,
		}
	}
	q := &gQueue{}
	seq := 0
	push := func(at, to, tick int, m gMsg) {
		seq++
		heap.Push(q, gItem{at: at, seq: seq, to: to, tick: tick, msg: m})
	}
	send := func(now, via, to int, m gMsg) {
		_, viaHonest := s.own[via]
		delay := 1
		if s.maxJitter > 0 {
			delay += rand.IntN(s.maxJitter + 1)
		}
		at := now + delay
		if now < s.healAt && viaHonest && s.sides[via] != s.sides[to] {
			at = s.healAt + delay
		}
		push(at, to, 0, m)
	}
	flood := func(now int, via *gMember, m gMsg) {
		for _, id := range gIDs {
			if id != via.id && members[id] != nil {
				send(now, via.id, id, m)
			}
		}
	}
	evaluate := func(m *gMember, now int) {
		if !m.voted || m.signed {
			return
		}
		count := 0
		for voter, p := range m.votes {
			if !m.voteBad[voter] && p == m.vote {
				count++
			}
		}
		sign := count >= gFastVotes
		if !sign && now >= gSlowTimeout && count >= gSlowVotes {
			switch {
			case s.noGrace:
				sign = true
			case m.certAt < 0:
				m.certAt = now
				push(now+gGrace, m.id, 3, gMsg{})
			case now >= m.certAt+gGrace:
				sign = true
			}
		} else if !sign {
			m.certAt = -1
		}
		if sign {
			m.signed = true
			r.signed[m.vote] = append(r.signed[m.vote], gSignature{member: m.id, at: now})
		}
	}
	for id := range members {
		push(gReportDeadline, id, 1, gMsg{})
		push(gSlowTimeout, id, 2, gMsg{})
		m := gMsg{kind: gReport, from: id, price: s.own[id]}
		members[id].seen[m] = true
		flood(0, members[id], m)
	}
	for id, mode := range s.malicious {
		if mode == "silent" {
			continue
		}
		for h := range members {
			price := gPriceA
			switch mode {
			case "split", "scripted":
				if s.sides[h] == 1 {
					price = gPriceB
				}
			case "extreme-low":
				price = 1
			case "extreme-high":
				price = maxPrice
			}
			push(1, h, 0, gMsg{kind: gReport, from: id, price: price})
			if mode == "scripted" {
				push(1, h, 0, gMsg{kind: gReport, from: id, price: price})
				continue
			}
			voteTime := gReportDeadline + 1
			if mode == "split" && s.voteAt[s.sides[h]] > 0 {
				voteTime = s.voteAt[s.sides[h]]
			}
			push(voteTime, h, 0, gMsg{kind: gVote, from: id, price: price})
		}
	}
	for _, v := range s.scripted {
		if members[v.to] != nil {
			push(v.at, v.to, 0, gMsg{kind: gVote, from: v.from, price: v.price})
		}
	}
	for q.Len() > 0 {
		it := heap.Pop(q).(gItem)
		m := members[it.to]
		switch it.tick {
		case 1:
			var values []uint32
			for from, p := range m.reports {
				if !m.reportBad[from] {
					values = append(values, p)
				}
			}
			if len(values) < gT {
				continue
			}
			slices.Sort(values)
			median := values[(len(values)-1)/2]
			if math.Abs(float64(int64(median)-int64(m.own)))/float64(m.own) > gMaxDeviation {
				continue
			}
			m.voted, m.vote = true, median
			m.votes[m.id] = median
			v := gMsg{kind: gVote, from: m.id, price: median}
			m.seen[v] = true
			flood(it.at, m, v)
			evaluate(m, it.at)
			continue
		case 2, 3:
			evaluate(m, it.at)
			continue
		}
		if m.seen[it.msg] {
			continue
		}
		m.seen[it.msg] = true
		switch it.msg.kind {
		case gReport:
			if old, ok := m.reports[it.msg.from]; ok && old != it.msg.price {
				m.reportBad[it.msg.from] = true
			} else {
				m.reports[it.msg.from] = it.msg.price
			}
		case gVote:
			if old, ok := m.votes[it.msg.from]; ok && old != it.msg.price {
				m.voteBad[it.msg.from] = true
			} else {
				m.votes[it.msg.from] = it.msg.price
			}
		}
		flood(it.at, m, it.msg)
		evaluate(m, it.at)
	}
	return r
}

// attestation returns the price honest members alone can attest.
func (r *gResult) attestation() (uint32, int, []int, bool) {
	for price, sigs := range r.signed {
		if len(sigs) < gT {
			continue
		}
		ordered := slices.Clone(sigs)
		slices.SortFunc(ordered, func(a, b gSignature) int { return a.at - b.at })
		set := make([]int, 0, gT)
		for _, s := range ordered[:gT] {
			set = append(set, s.member)
		}
		slices.Sort(set)
		return price, ordered[gT-1].at, set, true
	}
	return 0, 0, nil, false
}

// leaks reports whether malicious members can complete two different prices.
func (r *gResult) leaks(malicious int) bool {
	complete := 0
	for _, sigs := range r.signed {
		if len(sigs)+malicious >= gT {
			complete++
		}
	}
	return complete >= 2
}

func gHonestPrices(ids []int) map[int]uint32 {
	out := map[int]uint32{}
	for _, id := range ids {
		out[id] = 100_000 + uint32(id)*10
	}
	return out
}

func gRecoverScalar(
	e *thrEvent, a, b uint32, sa, sb [numDigits]btcec.ModNScalar,
) btcec.ModNScalar {
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
	return ds
}

func TestP2pFiatTwoSpeedOracle(t *testing.T) {
	start := time.Now()
	longTerm := gDKG(t, "long-term")
	keyTime := time.Since(start)
	start = time.Now()
	event := gNewEvent(t, longTerm, "timing-event")
	eventTime := time.Since(start)
	t.Logf("long-term key %.3fs; event setup (%d DKGs, all 7 members in one process) %.3fs; traffic per member per event %.1f KB",
		keyTime.Seconds(), gDKGsPerEvent, eventTime.Seconds(),
		float64(gDealerBytes*gDKGsPerEvent)/1024)

	t.Run("event key is certified by the long-term key", func(t *testing.T) {
		pub, err := schnorr.ParsePubKey(thrSer(&longTerm.group)[1:])
		require.NoError(t, err)
		require.True(t, event.cert.Verify(event.certMsg, pub))
		wrong := sha256.Sum256([]byte("different announcement"))
		require.False(t, event.cert.Verify(wrong[:], pub))
	})

	t.Run("any 4 of 7 attest and 3 cannot", func(t *testing.T) {
		price := uint32(100_123)
		var first [numDigits]btcec.ModNScalar
		groups := subsets(gN, gT)
		require.Len(t, groups, 35)
		for n, g := range groups {
			set := []int{g[0] + 1, g[1] + 1, g[2] + 1, g[3] + 1}
			sigs := gAttest(event, set, price)
			require.True(t, event.allValid(price, sigs), "group %v", set)
			if n == 0 {
				first = sigs
				continue
			}
			for i := range numDigits {
				require.True(t, first[i].Equals(&sigs[i]))
			}
		}
		for _, g := range subsets(gN, 3) {
			set := []int{g[0] + 1, g[1] + 1, g[2] + 1}
			sigs := gAttest(event, set, price)
			require.False(t, event.validSignature(price, 0, &sigs[0]), "group %v", set)
		}
	})

	t.Run("all 128 offline patterns", func(t *testing.T) {
		counts := map[string]int{}
		patterns := map[int]string{}
		for mask := range 1 << gN {
			var online []int
			for i, id := range gIDs {
				if mask>>i&1 == 1 {
					online = append(online, id)
				}
			}
			res := gRun(gSim{own: gHonestPrices(online)})
			_, at, _, ok := res.attestation()
			path := "none"
			switch {
			case ok && at < gSlowTimeout:
				path = "fast"
			case ok:
				path = "slow"
			}
			want := "none"
			if len(online) >= gFastVotes {
				want = "fast"
			} else if len(online) == gSlowVotes {
				want = "slow"
			}
			require.Equal(t, want, path, "online=%v", online)
			require.False(t, res.leaks(0))
			counts[path]++
			patterns[mask] = path
		}
		for _, q := range []float64{0.01, 0.05, 0.10, 0.20, 0.30} {
			p := map[string]float64{}
			for mask, path := range patterns {
				on := bits.OnesCount(uint(mask))
				p[path] += math.Pow(1-q, float64(on)) * math.Pow(q, float64(gN-on))
			}
			t.Logf("offline %.0f%%: fast %.3f%%, slow %.3f%%, none %.3f%%",
				q*100, p["fast"]*100, p["slow"]*100, p["none"]*100)
		}
		t.Logf("patterns: fast=%d slow=%d none=%d", counts["fast"], counts["slow"], counts["none"])
	})

	t.Run("malicious members cannot move the price or stop 4 honest members", func(t *testing.T) {
		for _, c := range []struct {
			name     string
			bad      []int
			mode     string
			wantPath string
		}{
			{"2 report low", []int{6, 7}, "extreme-low", "fast"},
			{"2 report high", []int{6, 7}, "extreme-high", "fast"},
			{"3 report low", []int{5, 6, 7}, "extreme-low", "slow"},
			{"3 report high", []int{5, 6, 7}, "extreme-high", "slow"},
			{"3 stay silent", []int{5, 6, 7}, "silent", "slow"},
		} {
			var honest []int
			for _, id := range gIDs {
				if !slices.Contains(c.bad, id) {
					honest = append(honest, id)
				}
			}
			own := gHonestPrices(honest)
			mal := map[int]string{}
			for _, id := range c.bad {
				mal[id] = c.mode
			}
			res := gRun(gSim{own: own, malicious: mal})
			price, at, _, ok := res.attestation()
			require.True(t, ok, c.name)
			require.GreaterOrEqual(t, price, own[honest[0]], c.name)
			require.LessOrEqual(t, price, own[honest[len(honest)-1]], c.name)
			if c.wantPath == "fast" {
				require.Less(t, at, gSlowTimeout, c.name)
			} else {
				require.GreaterOrEqual(t, at, gSlowTimeout, c.name)
			}
			t.Logf("%s: attested %d at %ds", c.name, price, at)
		}
	})

	t.Run("four silent members stop attestation", func(t *testing.T) {
		res := gRun(gSim{
			own:       gHonestPrices([]int{1, 2, 3}),
			malicious: map[int]string{4: "silent", 5: "silent", 6: "silent", 7: "silent"},
		})
		_, _, _, ok := res.attestation()
		require.False(t, ok)
	})

	t.Run("last-second double vote beats the slow path without a grace period", func(t *testing.T) {
		sides := map[int]int{1: 0, 2: 0, 3: 0, 4: 1, 5: 1, 6: 1}
		own := map[int]uint32{1: gPriceA, 2: gPriceA, 3: gPriceA, 4: gPriceB, 5: gPriceB, 6: gPriceB}
		sim := gSim{
			own: own, malicious: map[int]string{7: "split"}, sides: sides,
			healAt: gShortSplit, voteAt: [2]int{gSlowTimeout - 1, gSlowTimeout - 1},
		}
		unsafe := sim
		unsafe.noGrace = true
		require.True(t, gRun(unsafe).leaks(1), "one member must break the rule without a grace period")
		require.False(t, gRun(sim).leaks(1), "the grace period must stop it")
		t.Log("1 malicious member leaked the key after a healed split without a grace period")
	})

	type gridKey struct{ f, healAt int }
	grid := map[gridKey]int{}
	total := map[gridKey]int{}
	t.Run("every network split and vote timing", func(t *testing.T) {
		times := []int{gReportDeadline + 1, gShortSplit - 1, gSlowTimeout - 1, gSlowTimeout,
			gSlowTimeout + 1, gSlowTimeout + gGrace - 1, gSlowTimeout + gGrace, gSlowTimeout + gGrace + 1}
		heals := []int{gShortSplit, gSlowTimeout, gSlowTimeout + gGrace - 10, gLongSplit}
		for f := 0; f <= 3; f++ {
			honest := gIDs[:gN-f]
			mal := map[int]string{}
			for _, id := range gIDs[gN-f:] {
				mal[id] = "split"
			}
			for _, heal := range heals {
				for mask := range 1 << len(honest) {
					sides := map[int]int{}
					own := map[int]uint32{}
					for i, id := range honest {
						sides[id] = mask >> i & 1
						own[id] = gPriceA
						if sides[id] == 1 {
							own[id] = gPriceB
						}
					}
					for _, t0 := range times {
						for _, t1 := range times {
							res := gRun(gSim{
								own: own, malicious: mal, sides: sides, healAt: heal,
								voteAt: [2]int{t0, t1},
							})
							total[gridKey{f, heal}]++
							if res.leaks(f) {
								grid[gridKey{f, heal}]++
							}
						}
					}
				}
				t.Logf("%d malicious, split heals at %ds: %d of %d attack runs can leak",
					f, heal, grid[gridKey{f, heal}], total[gridKey{f, heal}])
			}
		}
		for _, heal := range heals {
			require.Zero(t, grid[gridKey{0, heal}], "no malicious members, heal %d", heal)
		}
		for _, heal := range heals[:3] {
			require.Zero(t, grid[gridKey{1, heal}], "1 malicious, heal %d", heal)
			require.Zero(t, grid[gridKey{2, heal}], "2 malicious, heal %d", heal)
		}
		require.Positive(t, grid[gridKey{1, gLongSplit}])
		require.Positive(t, grid[gridKey{2, gLongSplit}])
		require.Positive(t, grid[gridKey{3, gShortSplit}])
	})

	t.Run("randomized attackers with jitter cannot leak after a healed split", func(t *testing.T) {
		const runs = 20000
		leaks, attested := 0, 0
		for range runs {
			f := 1 + rand.IntN(2)
			perm := slices.Clone(gIDs)
			rand.Shuffle(len(perm), func(i, j int) { perm[i], perm[j] = perm[j], perm[i] })
			honest, bad := perm[:gN-f], perm[gN-f:]
			sides := map[int]int{}
			own := map[int]uint32{}
			for _, id := range honest {
				sides[id] = rand.IntN(2)
				own[id] = gPriceA
				if sides[id] == 1 {
					own[id] = gPriceB
				}
			}
			mal := map[int]string{}
			var votes []gScriptedVote
			for _, b := range bad {
				mal[b] = "scripted"
				for _, h := range honest {
					for range rand.IntN(3) { // none, one, or two votes to this member
						price := gPriceA
						if rand.IntN(2) == 1 {
							price = gPriceB
						}
						votes = append(votes, gScriptedVote{
							from: b, to: h, at: gReportDeadline + 1 + rand.IntN(700), price: price,
						})
					}
				}
			}
			res := gRun(gSim{
				own: own, malicious: mal, sides: sides,
				healAt: 1 + rand.IntN(gSlowTimeout+gGrace-10), scripted: votes, maxJitter: 5,
			})
			if res.leaks(f) {
				leaks++
			}
			if _, _, _, ok := res.attestation(); ok {
				attested++
			}
		}
		require.Zero(t, leaks)
		t.Logf("%d randomized attacks: 0 leaks, honest members attested in %d", runs, attested)
	})

	t.Run("a long split leak is limited to one event", func(t *testing.T) {
		leaked := gNewEvent(t, longTerm, "leaked-event")
		other := gNewEvent(t, longTerm, "other-event")
		sides := map[int]int{1: 0, 2: 0, 3: 0, 4: 1, 5: 1, 6: 1}
		own := map[int]uint32{1: gPriceA, 2: gPriceA, 3: gPriceA, 4: gPriceB, 5: gPriceB, 6: gPriceB}
		res := gRun(gSim{own: own, malicious: map[int]string{7: "split"}, sides: sides, healAt: gLongSplit})
		require.True(t, res.leaks(1))
		require.Len(t, res.signed[gPriceA], 3)
		require.Len(t, res.signed[gPriceB], 3)
		for _, s := range append(slices.Clone(res.signed[gPriceA]), res.signed[gPriceB]...) {
			require.GreaterOrEqual(t, s.at, gSlowTimeout, "the leak must use the slow path")
		}

		sa := gAttest(leaked, []int{1, 2, 3, 7}, gPriceA)
		sb := gAttest(leaked, []int{4, 5, 6, 7}, gPriceB)
		require.True(t, leaked.allValid(gPriceA, sa))
		require.True(t, leaked.allValid(gPriceB, sb))
		x := gRecoverScalar(leaked.thrEvent, gPriceA, gPriceB, sa, sb)
		xG := thrMulG(&x)
		require.True(t, thrEqual(&xG, &leaked.key.group), "must recover the event key")
		require.False(t, thrEqual(&xG, &longTerm.group), "long-term key must be different")
		require.False(t, thrEqual(&xG, &other.key.group), "other event key must be different")

		// With that key and the attestation, any price for the leaked event can be forged.
		forged := uint32(1)
		var fs [numDigits]btcec.ModNScalar
		for i := range numDigits {
			ca := taggedChallenge(leaked.rx[i], leaked.px, attestationMsg(thrBit(gPriceA, i)))
			ca.Mul(&x)
			ca.Negate()
			k := sa[i]
			k.Add(&ca)
			cf := taggedChallenge(leaked.rx[i], leaked.px, attestationMsg(thrBit(forged, i)))
			cf.Mul(&x)
			cf.Add(&k)
			fs[i] = cf
		}
		require.True(t, leaked.allValid(forged, fs), "leaked event can be forged")
		require.False(t, other.allValid(forged, fs), "other event must not accept the forgery")
		t.Log("the leak exposed one event key; the long-term key and other events stayed safe")
	})

	rec := scenario{rounding: 1000, tol: 1, bandPct: 25, k: 1, n: 1}
	primaries, payouts := rec.primaries()
	require.Len(t, primaries, 3496)
	c := newContract(t)
	txCache := map[int64]*payoutTxs{}
	for _, p := range primaries {
		if _, ok := txCache[p.payout]; !ok {
			txCache[p.payout] = c.payoutTxs(t, p.payout)
		}
	}

	const trials = 20
	t.Run("fast and slow attestations settle through Bitcoin script", func(t *testing.T) {
		lo, hi := rec.band()
		for trial := range trials {
			e := gNewEvent(t, longTerm, fmt.Sprintf("settle-%d", trial))
			online := slices.Clone(gIDs)
			rand.Shuffle(len(online), func(i, j int) { online[i], online[j] = online[j], online[i] })
			wantSlow := trial%2 == 1
			if wantSlow {
				online = online[:gSlowVotes]
			} else {
				online = online[:gFastVotes+rand.IntN(gN-gFastVotes+1)]
			}
			base := lo + 1000 + rand.Uint32N(hi-lo-2000)
			own := map[int]uint32{}
			for _, id := range online {
				own[id] = uint32(int64(base) + int64(rand.IntN(101)) - 50)
			}
			price, at, set, ok := gRun(gSim{own: own}).attestation()
			require.True(t, ok)
			require.Equal(t, wantSlow, at >= gSlowTimeout)
			p := findPrimary(primaries, price)
			require.NotNil(t, p)
			require.Equal(t, rec.payout(price), p.payout)
			T := e.ora.point(p.prefix)
			txs := txCache[p.payout]
			ads := make([]*adaptor, 0, signersPerRoll)
			for _, s := range c.signers() {
				a, err := adaptorSign(s.d, s.px, txs.exitMsg, &T)
				require.NoError(t, err)
				require.True(t, a.verify(&s.j, s.px, txs.exitMsg))
				ads = append(ads, a)
			}
			sigs := gAttest(e, set, price)
			require.True(t, e.allValid(price, sigs))
			secret := thrPrefixSecret(sigs, p.prefix)
			final := make([]*schnorr.Signature, 0, signersPerRoll)
			for i, a := range ads {
				sig := a.complete(t, secret)
				require.True(t, sig.Verify(txs.exitMsg, c.signers()[i].pub))
				final = append(final, sig)
			}
			require.NoError(t, c.spendExit(t, txs, final))
		}
		t.Logf("%d settlements (%d payouts in the contract) passed the Bitcoin script engine", trials, payouts)
	})

	t.Run("attestation cost", func(t *testing.T) {
		start := time.Now()
		sigs := gAttest(event, []int{2, 3, 5, 7}, 100_123)
		require.True(t, event.allValid(100_123, sigs))
		t.Logf("attestation by 4 members %.3fs", time.Since(start).Seconds())
	})
}
