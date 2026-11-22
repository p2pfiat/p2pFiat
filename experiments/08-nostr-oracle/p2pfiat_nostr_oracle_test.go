package p2pfiatcost

// Experiment 8: the 4-of-7 two-speed oracle over real nostr relays.
//
// Seven separate OS processes run key generation, price voting and threshold
// signing. They communicate only through signed nostr events on three local
// strfry relays. Private key shares are NIP-44 encrypted. A TCP proxy between
// each member and each relay creates network splits and latency, and relays
// are killed with docker. This is a research prototype and has not had a
// cryptographic review.
//
// Needs the test files of experiments 5, 6 and 7. Copy all four into arkd's
// internal/test/p2pfiatcost directory and run:
//   go test -v -count 5 -timeout 3000s -run 'TestP2pFiatNostrOracle' ./internal/test/p2pfiatcost
// Set P2PFIAT_FULL_TIMING=1 to run the 30 s / 600 s / 60 s production timers.

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip44"
	"github.com/stretchr/testify/require"
)

const (
	nsImage     = "ghcr.io/hoytech/strfry@sha256:36f1886d185a88ca57c66ebe52e6e9e8428dac2486eea0a5d50ff934f18b60c3"
	nsKind      = 9871
	nsRelays    = 3
	nsBasePort  = 17771
	nsEnv       = "P2PFIAT_NOSTR_MEMBER"
	nsLine      = "P2PFIAT:"
	nsInstLong  = 0
	nsInstKey   = 1
	nsInstDigit = 2
	nsInstCert  = nsInstDigit + numDigits
	nsInstances = nsInstCert + 1
)

type nsTiming struct{ ReportMs, SlowMs, GraceMs, StopMs int64 }

type nsConfig struct {
	Session  string
	ID       int
	SK       string
	Roster   map[int]string
	Relays   []string
	Own      uint32
	Behavior string
	VoteAtMs int64
	Timing   nsTiming
}

type nsWire struct {
	Type    string         `json:"type"`
	Commits [][]string     `json:"commits,omitempty"`
	R       []string       `json:"r,omitempty"`
	Z       []string       `json:"z,omitempty"`
	Shares  map[int]string `json:"shares,omitempty"`
	Hash    string         `json:"hash,omitempty"`
	Price   uint32         `json:"price,omitempty"`
	S       []string       `json:"s,omitempty"`
}

type nsOutput struct {
	Status      string
	Error       string
	LongPx      string
	EventPx     string
	Rx          []string
	CertMsg     string
	Cert        string
	SetupMs     int64
	BytesSent   int64
	Voted       bool
	Vote        uint32
	Signed      bool
	SignedAtMs  int64
	Attested    bool
	AttestPrice uint32
	AttestAtMs  int64
	LeakedKey   string
}

type nsMsg struct {
	from int
	w    nsWire
	id   string
}

// nsAccept applies every check a member makes before trusting a relay's event.
func nsAccept(evt *nostr.Event, session string, byPub map[string]int) (nsMsg, bool) {
	if evt == nil || evt.Kind != nsKind || len(evt.ID) != 64 {
		return nsMsg{}, false
	}
	from, ok := byPub[evt.PubKey]
	inSession := false
	for _, tag := range evt.Tags {
		if len(tag) == 2 && tag[0] == "t" && tag[1] == session {
			inSession = true
		}
	}
	if !ok || !inSession || !evt.CheckID() {
		return nsMsg{}, false
	}
	if valid, err := evt.CheckSignature(); err != nil || !valid {
		return nsMsg{}, false
	}
	var w nsWire
	if json.Unmarshal([]byte(evt.Content), &w) != nil {
		return nsMsg{}, false
	}
	return nsMsg{from: from, w: w, id: evt.ID}, true
}

// Nostr transport.

type nsNode struct {
	cfg       nsConfig
	pub       string
	byPub     map[string]int
	ctx       context.Context
	mu        sync.Mutex
	seen      map[string]bool
	inbox     []nsMsg
	outbox    [nsRelays][]*nostr.Event
	wake      chan struct{}
	noForward atomic.Bool
	sent      atomic.Int64
}

func nsNewNode(ctx context.Context, cfg nsConfig) (*nsNode, error) {
	pub, err := nostr.GetPublicKey(cfg.SK)
	if err != nil {
		return nil, err
	}
	n := &nsNode{
		cfg: cfg, pub: pub, ctx: ctx, byPub: map[string]int{},
		seen: map[string]bool{}, wake: make(chan struct{}, 1),
	}
	for id, p := range cfg.Roster {
		n.byPub[p] = id
	}
	for i := range cfg.Relays {
		go n.relayLoop(i)
	}
	return n, nil
}

func (n *nsNode) send(w nsWire, relays ...int) error {
	body, err := json.Marshal(w)
	if err != nil {
		return err
	}
	evt := &nostr.Event{
		PubKey: n.pub, CreatedAt: nostr.Now(), Kind: nsKind,
		Tags: nostr.Tags{{"t", n.cfg.Session}}, Content: string(body),
	}
	if err := evt.Sign(n.cfg.SK); err != nil {
		return err
	}
	n.sent.Add(int64(len(evt.String())))
	if len(relays) == 0 {
		relays = []int{0, 1, 2}
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, r := range relays {
		n.outbox[r] = append(n.outbox[r], evt)
	}
	return nil
}

func (n *nsNode) receive(evt *nostr.Event) {
	m, ok := nsAccept(evt, n.cfg.Session, n.byPub)
	if !ok {
		n.debugf("rejected event %s", evt.ID)
		return
	}
	n.mu.Lock()
	if n.seen[evt.ID] {
		n.mu.Unlock()
		return
	}
	n.seen[evt.ID] = true
	n.inbox = append(n.inbox, m)
	if !n.noForward.Load() {
		for r := range n.outbox {
			n.outbox[r] = append(n.outbox[r], evt)
		}
	}
	n.mu.Unlock()
	select {
	case n.wake <- struct{}{}:
	default:
	}
}

func (n *nsNode) take(wait time.Duration) []nsMsg {
	select {
	case <-n.wake:
	case <-time.After(wait):
	case <-n.ctx.Done():
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	out := n.inbox
	n.inbox = nil
	return out
}

func (n *nsNode) debugf(format string, args ...any) {
	if os.Getenv("P2PFIAT_NOSTR_DEBUG") != "" {
		fmt.Fprintf(os.Stderr, "DBG member %d: "+format+"\n", append([]any{n.cfg.ID}, args...)...)
	}
}

func (n *nsNode) relayLoop(idx int) {
	var pubMu sync.Mutex
	acked, inflight := map[string]bool{}, map[string]bool{}
	authors := make([]string, 0, len(n.cfg.Roster))
	for _, p := range n.cfg.Roster {
		authors = append(authors, p)
	}
	retry := func() {
		select {
		case <-n.ctx.Done():
		case <-time.After(200 * time.Millisecond):
		}
	}
	for n.ctx.Err() == nil {
		r := nostr.NewRelay(n.ctx, n.cfg.Relays[idx])
		dial, cancel := context.WithTimeout(n.ctx, 2*time.Second)
		err := r.Connect(dial)
		cancel()
		if err != nil {
			n.debugf("relay %d connect: %v", idx, err)
			retry()
			continue
		}
		sub, err := r.Subscribe(n.ctx, nostr.Filters{{
			Kinds: []int{nsKind}, Authors: authors,
			Tags: nostr.TagMap{"t": {n.cfg.Session}}, Limit: 500,
		}})
		if err != nil {
			n.debugf("relay %d subscribe: %v", idx, err)
			_ = r.Close()
			retry()
			continue
		}
		go func() {
			for {
				select {
				case evt, ok := <-sub.Events:
					if !ok {
						return
					}
					n.receive(evt)
				case <-sub.Context.Done():
					return
				}
			}
		}()
		for n.ctx.Err() == nil && r.IsConnected() {
			n.mu.Lock()
			pending := slices.Clone(n.outbox[idx])
			n.mu.Unlock()
			for _, evt := range pending {
				pubMu.Lock()
				skip := acked[evt.ID] || inflight[evt.ID]
				if !skip {
					inflight[evt.ID] = true
				}
				pubMu.Unlock()
				if skip {
					continue
				}
				// Publish concurrently: waiting for each OK in turn delays votes under latency.
				go func() {
					pub, cancel := context.WithTimeout(n.ctx, 4*time.Second)
					defer cancel()
					err := r.Publish(pub, *evt)
					pubMu.Lock()
					delete(inflight, evt.ID)
					if err == nil {
						acked[evt.ID] = true
					}
					pubMu.Unlock()
					if err != nil {
						n.debugf("relay %d publish: %v", idx, err)
					}
				}()
			}
			select {
			case <-n.ctx.Done():
			case <-time.After(50 * time.Millisecond):
			}
		}
		n.debugf("relay %d disconnected: %v", idx, r.ConnectionError)
		_ = r.Close()
	}
}

// Encoding.

func nsScalarHex(s *btcec.ModNScalar) string {
	b := s.Bytes()
	return hex.EncodeToString(b[:])
}

func nsParseScalar(v string) (btcec.ModNScalar, error) {
	var s btcec.ModNScalar
	b, err := hex.DecodeString(v)
	if err != nil || len(b) != 32 {
		return s, errors.New("bad scalar")
	}
	if s.SetByteSlice(b) {
		return s, errors.New("scalar overflow")
	}
	return s, nil
}

func nsPointHex(p *btcec.JacobianPoint) string { return hex.EncodeToString(thrSer(p)) }

func nsParsePoint(v string) (btcec.JacobianPoint, error) {
	var p btcec.JacobianPoint
	b, err := hex.DecodeString(v)
	if err != nil {
		return p, err
	}
	pub, err := btcec.ParsePubKey(b)
	if err != nil {
		return p, err
	}
	pub.AsJacobian(&p)
	p.ToAffine()
	return p, nil
}

func nsParseDigits(v []string) ([numDigits]btcec.ModNScalar, error) {
	var out [numDigits]btcec.ModNScalar
	if len(v) != numDigits {
		return out, errors.New("wrong digit count")
	}
	for i := range out {
		s, err := nsParseScalar(v[i])
		if err != nil {
			return out, err
		}
		out[i] = s
	}
	return out, nil
}

func nsDigitsHex(v [numDigits]btcec.ModNScalar) []string {
	out := make([]string, numDigits)
	for i := range v {
		out[i] = nsScalarHex(&v[i])
	}
	return out
}

// Distributed key generation over nostr.

func (n *nsNode) deal(t testing.TB, corrupt bool) (nsWire, error) {
	w := nsWire{Type: "deal", Shares: map[int]string{}}
	plain := map[int][]string{}
	for inst := range nsInstances {
		ctx := fmt.Sprintf("%s/%d", n.cfg.Session, inst)
		d := gNewDealer(t, ctx, n.cfg.ID)
		c := make([]string, len(d.commits))
		for i := range d.commits {
			c[i] = nsPointHex(&d.commits[i])
		}
		w.Commits = append(w.Commits, c)
		w.R = append(w.R, nsPointHex(&d.proofR))
		w.Z = append(w.Z, nsScalarHex(&d.proofZ))
		for _, j := range gIDs {
			s := d.shares[j]
			if corrupt && j == 1 {
				one := thrScalar(1)
				s.Add(&one)
			}
			plain[j] = append(plain[j], nsScalarHex(&s))
		}
	}
	for _, j := range gIDs {
		body, err := json.Marshal(plain[j])
		if err != nil {
			return w, err
		}
		key, err := nip44.GenerateConversationKey(n.cfg.Roster[j], n.cfg.SK)
		if err != nil {
			return w, err
		}
		if w.Shares[j], err = nip44.Encrypt(string(body), key); err != nil {
			return w, err
		}
	}
	return w, nil
}

func (n *nsNode) finishDKG(deals map[int]nsMsg) ([nsInstances]*thrKey, error) {
	var keys [nsInstances]*thrKey
	mine := map[int][]string{}
	for _, d := range gIDs {
		w := deals[d].w
		if len(w.Commits) != nsInstances || len(w.R) != nsInstances || len(w.Z) != nsInstances {
			return keys, fmt.Errorf("dealer %d: malformed deal", d)
		}
		key, err := nip44.GenerateConversationKey(n.cfg.Roster[d], n.cfg.SK)
		if err != nil {
			return keys, err
		}
		plain, err := nip44.Decrypt(w.Shares[n.cfg.ID], key)
		if err != nil {
			return keys, fmt.Errorf("dealer %d: share does not decrypt", d)
		}
		var v []string
		if json.Unmarshal([]byte(plain), &v) != nil || len(v) != nsInstances {
			return keys, fmt.Errorf("dealer %d: malformed share", d)
		}
		mine[d] = v
	}
	for inst := range nsInstances {
		ctx := fmt.Sprintf("%s/%d", n.cfg.Session, inst)
		sum := make([]btcec.JacobianPoint, gT)
		var share btcec.ModNScalar
		for dn, d := range gIDs {
			w := deals[d].w
			if len(w.Commits[inst]) != gT {
				return keys, fmt.Errorf("dealer %d: wrong commitment count", d)
			}
			commits := make([]btcec.JacobianPoint, gT)
			for k := range commits {
				p, err := nsParsePoint(w.Commits[inst][k])
				if err != nil {
					return keys, fmt.Errorf("dealer %d: bad commitment", d)
				}
				commits[k] = p
				if dn == 0 {
					sum[k] = p
				} else {
					sum[k] = thrAdd(&sum[k], &p)
				}
			}
			r, err := nsParsePoint(w.R[inst])
			if err != nil {
				return keys, fmt.Errorf("dealer %d: bad proof", d)
			}
			z, err := nsParseScalar(w.Z[inst])
			if err != nil {
				return keys, fmt.Errorf("dealer %d: bad proof", d)
			}
			e := thrProofChallenge(ctx, d, &commits[0], &r)
			lhs := thrMulG(&z)
			ec := thrMul(&e, &commits[0])
			rhs := thrAdd(&r, &ec)
			if !thrEqual(&lhs, &rhs) {
				return keys, fmt.Errorf("dealer %d: invalid proof of knowledge", d)
			}
			own, err := nsParseScalar(mine[d][inst])
			if err != nil {
				return keys, fmt.Errorf("dealer %d: bad share", d)
			}
			got := thrMulG(&own)
			want := thrEvalCommit(commits, n.cfg.ID)
			if !thrEqual(&got, &want) {
				return keys, fmt.Errorf("dealer %d: invalid share", d)
			}
			share.Add(&own)
		}
		group := sum[0]
		flip := group.Y.IsOdd()
		if flip {
			thrNegate(&group)
			share.Negate()
		}
		k := &thrKey{
			group: group, shares: map[int]btcec.ModNScalar{n.cfg.ID: share},
			verify: map[int]btcec.JacobianPoint{}, qualified: slices.Clone(gIDs),
			excluded: map[int]string{},
		}
		for _, j := range gIDs {
			v := thrEvalCommit(sum, j)
			if flip {
				thrNegate(&v)
			}
			k.verify[j] = v
		}
		keys[inst] = k
	}
	return keys, nil
}

type nsState struct {
	event *thrEvent
}

func (n *nsNode) setup(t testing.TB, out *nsOutput) (*nsState, error) {
	deal, err := n.deal(t, n.cfg.Behavior == "bad-share")
	if err != nil {
		return nil, err
	}
	if n.cfg.Behavior == "equivocate-deal" {
		other, err := n.deal(t, false)
		if err != nil {
			return nil, err
		}
		if err := n.send(deal, 0); err != nil {
			return nil, err
		}
		if err := n.send(other, 1, 2); err != nil {
			return nil, err
		}
	} else if err := n.send(deal); err != nil {
		return nil, err
	}

	deals := map[int]nsMsg{}
	hashes := map[int]string{}
	certParts := map[int]btcec.ModNScalar{}
	var keys [nsInstances]*thrKey
	var event *thrEvent
	var certMsg, c []byte
	var certC btcec.ModNScalar
	var rx []byte
	dkgDone, certSent := false, false
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		for _, m := range n.take(100 * time.Millisecond) {
			switch m.w.Type {
			case "abort":
				return nil, fmt.Errorf("member %d aborted setup: %s", m.from, m.w.Hash)
			case "deal":
				if old, ok := deals[m.from]; ok && old.id != m.id {
					_ = n.send(nsWire{Type: "abort", Hash: "two deals"})
					return nil, fmt.Errorf("dealer %d equivocated", m.from)
				}
				deals[m.from] = m
			case "transcript":
				if _, ok := hashes[m.from]; !ok {
					hashes[m.from] = m.w.Hash
				}
			case "certpart":
				if !dkgDone || len(m.w.S) != 1 {
					if len(m.w.S) == 1 {
						n.mu.Lock()
						n.inbox = append(n.inbox, m)
						n.mu.Unlock()
					}
					continue
				}
				s, err := nsParseScalar(m.w.S[0])
				if err != nil {
					continue
				}
				// s*G must equal the member's nonce share plus c times its key share.
				lhs := thrMulG(&s)
				vk := keys[nsInstCert].verify[m.from]
				vx := keys[nsInstLong].verify[m.from]
				cx := thrMul(&certC, &vx)
				rhs := thrAdd(&vk, &cx)
				if thrEqual(&lhs, &rhs) {
					certParts[m.from] = s
				}
			}
		}
		if !dkgDone && len(deals) == gN {
			if keys, err = n.finishDKG(deals); err != nil {
				_ = n.send(nsWire{Type: "abort", Hash: err.Error()})
				return nil, err
			}
			h := sha256.New()
			for _, id := range gIDs {
				h.Write([]byte(deals[id].id))
			}
			if err := n.send(nsWire{Type: "transcript", Hash: hex.EncodeToString(h.Sum(nil))}); err != nil {
				return nil, err
			}
			event = &thrEvent{key: keys[nsInstKey], ora: &oracle{cache: map[prefix]btcec.JacobianPoint{}}}
			event.px = thrSer(&event.key.group)[1:]
			a := sha256.New()
			a.Write([]byte("p2pfiat/event-announcement"))
			a.Write([]byte(n.cfg.Session))
			a.Write(event.px)
			for i := range numDigits {
				event.nonces[i] = keys[nsInstDigit+i]
				event.rx[i] = thrSer(&event.nonces[i].group)[1:]
				a.Write(event.rx[i])
			}
			certMsg = a.Sum(nil)
			rx = thrSer(&keys[nsInstCert].group)[1:]
			c = thrSer(&keys[nsInstLong].group)[1:]
			certC = taggedChallenge(rx, c, certMsg)
			dkgDone = true
		}
		if dkgDone && !certSent && len(hashes) == gN {
			for _, id := range gIDs {
				if hashes[id] != hashes[gIDs[0]] {
					_ = n.send(nsWire{Type: "abort", Hash: "transcript mismatch"})
					return nil, errors.New("transcript mismatch")
				}
			}
			s := certC
			x := keys[nsInstLong].shares[n.cfg.ID]
			s.Mul(&x)
			k := keys[nsInstCert].shares[n.cfg.ID]
			s.Add(&k)
			if err := n.send(nsWire{Type: "certpart", S: []string{nsScalarHex(&s)}}); err != nil {
				return nil, err
			}
			certSent = true
		}
		if certSent && len(certParts) >= gT {
			var set []int
			for _, id := range gIDs {
				if _, ok := certParts[id]; ok && len(set) < gT {
					set = append(set, id)
				}
			}
			var total btcec.ModNScalar
			for _, j := range set {
				v := certParts[j]
				l := thrLagrange(j, set)
				v.Mul(&l)
				total.Add(&v)
			}
			b := total.Bytes()
			raw := append(append([]byte{}, rx...), b[:]...)
			sig, err := schnorr.ParseSignature(raw)
			if err != nil {
				return nil, err
			}
			pub, err := schnorr.ParsePubKey(c)
			if err != nil || !sig.Verify(certMsg, pub) {
				return nil, errors.New("event certificate does not verify")
			}
			out.LongPx, out.EventPx = hex.EncodeToString(c), hex.EncodeToString(event.px)
			for i := range numDigits {
				out.Rx = append(out.Rx, hex.EncodeToString(event.rx[i]))
			}
			out.CertMsg, out.Cert = hex.EncodeToString(certMsg), hex.EncodeToString(raw)
			return &nsState{event: event}, nil
		}
	}
	return nil, fmt.Errorf("setup timed out: deals=%d transcripts=%d certparts=%d dkg=%v certSent=%v",
		len(deals), len(hashes), len(certParts), dkgDone, certSent)
}

// Two-speed attestation over nostr.

func (n *nsNode) attest(st *nsState, goAt time.Time, out *nsOutput) error {
	tm, id, b := n.cfg.Timing, n.cfg.ID, n.cfg.Behavior
	reports, votes := map[int]uint32{}, map[int]uint32{}
	reportBad, voteBad := map[int]bool{}, map[int]bool{}
	partials := map[uint32]map[int][numDigits]btcec.ModNScalar{}
	done := map[uint32][numDigits]btcec.ModNScalar{}
	certAt := int64(-1)
	honest := b == "" || b == "bad-partial" || b == "bad-share" || b == "equivocate-deal"
	if b == "split" {
		n.noForward.Store(true)
	}
	sentReport, sentVote := false, false
	for {
		msgs := n.take(50 * time.Millisecond)
		now := time.Since(goAt).Milliseconds()
		if now >= tm.StopMs || n.ctx.Err() != nil {
			return nil
		}
		if out.Attested && now >= out.AttestAtMs+2000 {
			return nil
		}
		for _, m := range msgs {
			switch m.w.Type {
			case "report":
				if old, ok := reports[m.from]; ok && old != m.w.Price {
					reportBad[m.from] = true
				} else {
					reports[m.from] = m.w.Price
				}
			case "vote":
				if old, ok := votes[m.from]; ok && old != m.w.Price {
					voteBad[m.from] = true
				} else {
					votes[m.from] = m.w.Price
				}
			case "partial":
				p, err := nsParseDigits(m.w.S)
				if err != nil || st.event.checkPartial(m.from, m.w.Price, p) != -1 {
					continue
				}
				if partials[m.w.Price] == nil {
					partials[m.w.Price] = map[int][numDigits]btcec.ModNScalar{}
				}
				partials[m.w.Price][m.from] = p
			}
		}

		switch b {
		case "silent":
			continue
		case "extreme-low", "extreme-high":
			price := uint32(1)
			if b == "extreme-high" {
				price = uint32(maxPrice)
			}
			if !sentReport {
				sentReport = true
				if err := n.send(nsWire{Type: "report", Price: price}); err != nil {
					return err
				}
			}
			if !sentVote && now >= tm.ReportMs {
				sentVote = true
				if err := n.send(nsWire{Type: "vote", Price: price}); err != nil {
					return err
				}
			}
			continue
		case "split":
			if !sentReport {
				sentReport = true
				if err := n.send(nsWire{Type: "report", Price: gPriceA}, 0); err != nil {
					return err
				}
				if err := n.send(nsWire{Type: "report", Price: gPriceB}, 1); err != nil {
					return err
				}
			}
			if !sentVote && now >= n.cfg.VoteAtMs {
				sentVote = true
				if err := n.send(nsWire{Type: "vote", Price: gPriceA}, 0); err != nil {
					return err
				}
				if err := n.send(nsWire{Type: "vote", Price: gPriceB}, 1); err != nil {
					return err
				}
			}
			for _, price := range []uint32{gPriceA, gPriceB} {
				if _, ok := done[price]; ok || len(partials[price]) < gT-1 {
					continue
				}
				parts := partials[price]
				parts[id] = st.event.partial(id, price)
				var set []int
				for _, j := range gIDs {
					if _, ok := parts[j]; ok && len(set) < gT {
						set = append(set, j)
					}
				}
				if !slices.Contains(set, id) {
					set[gT-1] = id
					slices.Sort(set)
				}
				sigs := st.event.aggregate(set, parts)
				if st.event.allValid(price, sigs) {
					done[price] = sigs
				}
			}
			if len(done) == 2 {
				x := gRecoverScalar(st.event, gPriceA, gPriceB, done[gPriceA], done[gPriceB])
				out.LeakedKey = nsScalarHex(&x)
				return nil
			}
			continue
		}

		if honest && !sentReport {
			sentReport = true
			reports[id] = n.cfg.Own
			if err := n.send(nsWire{Type: "report", Price: n.cfg.Own}); err != nil {
				return err
			}
		}
		if honest && !sentVote && now >= tm.ReportMs {
			sentVote = true
			var values []uint32
			for from, p := range reports {
				if !reportBad[from] {
					values = append(values, p)
				}
			}
			if len(values) >= gT {
				slices.Sort(values)
				median := values[(len(values)-1)/2]
				gap := float64(int64(median) - int64(n.cfg.Own))
				if gap < 0 {
					gap = -gap
				}
				if gap/float64(n.cfg.Own) <= gMaxDeviation {
					out.Voted, out.Vote = true, median
					votes[id] = median
					if err := n.send(nsWire{Type: "vote", Price: median}); err != nil {
						return err
					}
				}
			}
		}
		if out.Voted && !out.Signed {
			count := 0
			for voter, p := range votes {
				if !voteBad[voter] && p == out.Vote {
					count++
				}
			}
			sign := count >= gFastVotes
			if !sign && now >= tm.SlowMs && count >= gSlowVotes {
				if certAt < 0 {
					certAt = now
				} else if now >= certAt+tm.GraceMs {
					sign = true
				}
			} else if !sign {
				certAt = -1
			}
			if sign {
				out.Signed, out.SignedAtMs = true, now
				p := st.event.partial(id, out.Vote)
				if b == "bad-partial" {
					junk := thrScalar(7)
					p[3].Add(&junk)
				}
				if err := n.send(nsWire{Type: "partial", Price: out.Vote, S: nsDigitsHex(p)}); err != nil {
					return err
				}
				if b != "bad-partial" {
					if partials[out.Vote] == nil {
						partials[out.Vote] = map[int][numDigits]btcec.ModNScalar{}
					}
					partials[out.Vote][id] = p
				}
			}
		}
		if !out.Attested {
			for price, parts := range partials {
				if len(parts) < gT {
					continue
				}
				var set []int
				for _, j := range gIDs {
					if _, ok := parts[j]; ok && len(set) < gT {
						set = append(set, j)
					}
				}
				sigs := st.event.aggregate(set, parts)
				if !st.event.allValid(price, sigs) {
					return errors.New("verified partials produced an invalid attestation")
				}
				out.Attested, out.AttestPrice, out.AttestAtMs = true, price, now
				if err := n.send(nsWire{Type: "attestation", Price: price, S: nsDigitsHex(sigs)}); err != nil {
					return err
				}
				break
			}
		}
	}
}

// TestP2pFiatNostrMember is the entry point of one member process.
func TestP2pFiatNostrMember(t *testing.T) {
	raw := os.Getenv(nsEnv)
	if raw == "" {
		t.Skip("started only as a member process by TestP2pFiatNostrOracle")
	}
	var cfg nsConfig
	require.NoError(t, json.Unmarshal([]byte(raw), &cfg))
	emit := func(o *nsOutput) {
		body, _ := json.Marshal(o)
		fmt.Fprintf(os.Stdout, "\n%s%s\n", nsLine, body)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := &nsOutput{Status: "ready"}
	n, err := nsNewNode(ctx, cfg)
	require.NoError(t, err)
	start := time.Now()
	st, err := n.setup(t, out)
	if err != nil {
		time.Sleep(1500 * time.Millisecond) // let the abort reach the other members
		emit(&nsOutput{Status: "failed", Error: err.Error()})
		return
	}
	out.SetupMs = time.Since(start).Milliseconds()
	out.BytesSent = n.sent.Load()
	emit(out)

	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return
	}
	ms, err := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "go ")), 10, 64)
	require.NoError(t, err)
	goAt := time.UnixMilli(ms)
	time.Sleep(time.Until(goAt))
	out.Status = "done"
	if err := n.attest(st, goAt, out); err != nil {
		out.Status, out.Error = "failed", err.Error()
	}
	time.Sleep(300 * time.Millisecond)
	out.BytesSent = n.sent.Load()
	emit(out)
}

// Test harness: real relays, member processes and a controllable network.

func nsDocker(args ...string) (string, error) {
	out, err := exec.Command("docker", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func nsContainer(i int) string { return fmt.Sprintf("p2pfiat-strfry-%d", i) }

func nsWaitRelay(t testing.TB, i int) {
	t.Helper()
	url := fmt.Sprintf("ws://127.0.0.1:%d", nsBasePort+i)
	for range 100 {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		r, err := nostr.RelayConnect(ctx, url)
		cancel()
		if err == nil {
			_ = r.Close()
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	require.Fail(t, "relay did not start", url)
}

func nsStartRelays(t *testing.T) {
	t.Helper()
	// Compression is off because go-nostr v0.40.1's flate writer fails under Go 1.27.
	script := `sed -e 's/bind = "127.0.0.1"/bind = "0.0.0.0"/' -e '/compression {/,/}/ s/enabled = true/enabled = false/' /app/strfry.conf > /tmp/s.conf && exec /app/strfry --config /tmp/s.conf relay`
	for i := range nsRelays {
		_, _ = nsDocker("rm", "-f", nsContainer(i))
		out, err := nsDocker("run", "-d", "--name", nsContainer(i),
			"-p", fmt.Sprintf("127.0.0.1:%d:7777", nsBasePort+i),
			"--entrypoint", "sh", nsImage, "-c", script)
		require.NoError(t, err, out)
		nsWaitRelay(t, i)
	}
	t.Cleanup(func() {
		for i := range nsRelays {
			_, _ = nsDocker("rm", "-f", nsContainer(i))
		}
	})
}

type nsProxy struct {
	target    string
	ln        net.Listener
	mu        sync.Mutex
	blocked   bool
	conns     map[net.Conn]struct{}
	latencyMs atomic.Int64
	jitterMs  atomic.Int64
}

func nsNewProxy(t testing.TB, target string) *nsProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	p := &nsProxy{target: target, ln: ln, conns: map[net.Conn]struct{}{}}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.serve(c)
		}
	}()
	return p
}

func (p *nsProxy) track(c net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.blocked {
		_ = c.Close()
		return false
	}
	p.conns[c] = struct{}{}
	return true
}

func (p *nsProxy) serve(c net.Conn) {
	if !p.track(c) {
		return
	}
	u, err := net.DialTimeout("tcp", p.target, time.Second)
	if err != nil {
		_ = c.Close()
		return
	}
	if !p.track(u) {
		_ = c.Close()
		return
	}
	pipe := func(dst, src net.Conn) {
		defer dst.Close()
		defer src.Close()
		buf := make([]byte, 64*1024)
		for {
			m, err := src.Read(buf)
			if m > 0 {
				d := p.latencyMs.Load()
				if j := p.jitterMs.Load(); j > 0 {
					d += rand.Int64N(j + 1)
				}
				if d > 0 {
					time.Sleep(time.Duration(d) * time.Millisecond)
				}
				if _, werr := dst.Write(buf[:m]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}
	go pipe(u, c)
	pipe(c, u)
}

func (p *nsProxy) setBlocked(v bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.blocked = v
	if v {
		for c := range p.conns {
			_ = c.Close()
		}
		p.conns = map[net.Conn]struct{}{}
	}
}

type nsScenario struct {
	name     string
	own      map[int]uint32
	offline  []int
	behavior map[int]string
	sides    map[int]int
	healMs   int64
	voteAtMs int64
	latency  int64
	jitter   int64
	timing   nsTiming
	during   func(goAt time.Time)
}

type nsRun struct {
	aborted bool
	reason  string
	outs    map[int]*nsOutput
	attests []*nostr.Event
	session string
	ready   *nsOutput
}

var nsDefaultTiming = nsTiming{ReportMs: 3000, SlowMs: 20000, GraceMs: 6000, StopMs: 34000}

func nsExecute(t *testing.T, s nsScenario) *nsRun {
	t.Helper()
	if s.timing == (nsTiming{}) {
		s.timing = nsDefaultTiming
	}
	session := fmt.Sprintf("p2pfiat-exp8-%d-%d", time.Now().UnixNano(), rand.Uint32())
	sks, roster := map[int]string{}, map[int]string{}
	for _, id := range gIDs {
		sks[id] = nostr.GeneratePrivateKey()
		pub, err := nostr.GetPublicKey(sks[id])
		require.NoError(t, err)
		roster[id] = pub
	}
	proxies := map[[2]int]*nsProxy{}
	for _, id := range gIDs {
		for r := range nsRelays {
			p := nsNewProxy(t, fmt.Sprintf("127.0.0.1:%d", nsBasePort+r))
			p.latencyMs.Store(s.latency)
			p.jitterMs.Store(s.jitter)
			proxies[[2]int{id, r}] = p
		}
	}
	defer func() {
		for _, p := range proxies {
			_ = p.ln.Close()
			p.setBlocked(true)
		}
	}()

	type proc struct {
		cmd   *exec.Cmd
		stdin io.WriteCloser
	}
	procs := map[int]*proc{}
	type line struct {
		id  int
		out *nsOutput
	}
	lines := make(chan line, 64)
	defer func() {
		for _, p := range procs {
			_ = p.cmd.Process.Kill()
			_ = p.cmd.Wait()
		}
	}()
	for _, id := range gIDs {
		var urls []string
		for r := range nsRelays {
			urls = append(urls, "ws://"+proxies[[2]int{id, r}].ln.Addr().String())
		}
		own := uint32(100_000 + id*10)
		if v, ok := s.own[id]; ok {
			own = v
		}
		body, err := json.Marshal(nsConfig{
			Session: session, ID: id, SK: sks[id], Roster: roster, Relays: urls, Own: own,
			Behavior: s.behavior[id], VoteAtMs: s.voteAtMs, Timing: s.timing,
		})
		require.NoError(t, err)
		cmd := exec.Command(os.Args[0], "-test.run", "^TestP2pFiatNostrMember$", "-test.timeout", "0")
		cmd.Env = append(os.Environ(), nsEnv+"="+string(body))
		if os.Getenv("P2PFIAT_NOSTR_DEBUG") != "" {
			cmd.Stderr = os.Stderr
		}
		stdin, err := cmd.StdinPipe()
		require.NoError(t, err)
		stdout, err := cmd.StdoutPipe()
		require.NoError(t, err)
		require.NoError(t, cmd.Start())
		procs[id] = &proc{cmd: cmd, stdin: stdin}
		go func(id int) {
			sc := bufio.NewScanner(stdout)
			sc.Buffer(make([]byte, 1<<16), 1<<20)
			for sc.Scan() {
				text, ok := strings.CutPrefix(sc.Text(), nsLine)
				if !ok {
					continue
				}
				o := &nsOutput{}
				if json.Unmarshal([]byte(text), o) == nil {
					lines <- line{id: id, out: o}
				}
			}
		}(id)
	}

	run := &nsRun{outs: map[int]*nsOutput{}, session: session}
	ready := map[int]*nsOutput{}
	timeout := time.After(100 * time.Second)
	for len(ready) < gN {
		select {
		case l := <-lines:
			if l.out.Status == "failed" {
				run.aborted, run.reason = true, l.out.Error
				return run
			}
			ready[l.id] = l.out
		case <-timeout:
			require.Fail(t, "setup timed out", s.name)
		}
	}
	run.ready = ready[1]
	for _, id := range gIDs {
		o := ready[id]
		require.Equal(t, run.ready.EventPx, o.EventPx, "members must agree on the event key")
		require.Equal(t, run.ready.LongPx, o.LongPx, "members must agree on the long-term key")
		require.Equal(t, run.ready.Rx, o.Rx, "members must agree on the nonces")
	}
	certRaw, err := hex.DecodeString(run.ready.Cert)
	require.NoError(t, err)
	cert, err := schnorr.ParseSignature(certRaw)
	require.NoError(t, err)
	longRaw, _ := hex.DecodeString(run.ready.LongPx)
	longPub, err := schnorr.ParsePubKey(longRaw)
	require.NoError(t, err)
	msg, _ := hex.DecodeString(run.ready.CertMsg)
	require.True(t, cert.Verify(msg, longPub), "event certificate must verify")

	alive := map[int]bool{}
	for _, id := range gIDs {
		alive[id] = true
	}
	for _, id := range s.offline {
		require.NoError(t, procs[id].cmd.Process.Kill())
		_ = procs[id].cmd.Wait()
		delete(procs, id)
		delete(alive, id)
	}
	for id, side := range s.sides {
		for r := range nsRelays {
			if r != side {
				proxies[[2]int{id, r}].setBlocked(true)
			}
		}
	}
	goAt := time.Now().Add(time.Second)
	for id := range alive {
		_, err := io.WriteString(procs[id].stdin, fmt.Sprintf("go %d\n", goAt.UnixMilli()))
		require.NoError(t, err)
	}
	if s.healMs > 0 {
		time.AfterFunc(time.Until(goAt.Add(time.Duration(s.healMs)*time.Millisecond)), func() {
			for _, p := range proxies {
				p.setBlocked(false)
			}
		})
	}
	duringDone := make(chan struct{})
	if s.during != nil {
		go func() {
			defer close(duringDone)
			s.during(goAt)
		}()
	} else {
		close(duringDone)
	}
	finish := time.After(time.Until(goAt) + time.Duration(s.timing.StopMs+15000)*time.Millisecond)
	for len(run.outs) < len(alive) {
		select {
		case l := <-lines:
			run.outs[l.id] = l.out
			require.NotEqual(t, "failed", l.out.Status, "member %d: %s", l.id, l.out.Error)
		case <-finish:
			require.Fail(t, "members did not finish", s.name)
		}
	}
	<-duringDone
	run.attests = nsFetchAttestations(t, session, roster)
	return run
}

// nsFetchAttestations reads the result as an outside client, straight from the relays.
func nsFetchAttestations(t *testing.T, session string, roster map[int]string) []*nostr.Event {
	t.Helper()
	byPub := map[string]int{}
	for id, p := range roster {
		byPub[p] = id
	}
	seen := map[string]*nostr.Event{}
	for i := range nsRelays {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		r, err := nostr.RelayConnect(ctx, fmt.Sprintf("ws://127.0.0.1:%d", nsBasePort+i))
		if err == nil {
			events, qerr := r.QuerySync(ctx, nostr.Filter{
				Kinds: []int{nsKind}, Tags: nostr.TagMap{"t": {session}}, Limit: 500,
			})
			if qerr == nil {
				for _, e := range events {
					if m, ok := nsAccept(e, session, byPub); ok && m.w.Type == "attestation" {
						seen[e.ID] = e
					}
				}
			}
			_ = r.Close()
		}
		cancel()
	}
	out := make([]*nostr.Event, 0, len(seen))
	for _, e := range seen {
		out = append(out, e)
	}
	return out
}

// nsPublicEvent rebuilds only the public values an outside client has.
func nsPublicEvent(t *testing.T, o *nsOutput) *thrEvent {
	t.Helper()
	e := &thrEvent{}
	var err error
	e.px, err = hex.DecodeString(o.EventPx)
	require.NoError(t, err)
	require.Len(t, o.Rx, numDigits)
	for i := range numDigits {
		e.rx[i], err = hex.DecodeString(o.Rx[i])
		require.NoError(t, err)
	}
	return e
}

// nsRequireAttested checks one price, valid under the announced event key.
func nsRequireAttested(t *testing.T, run *nsRun, wantPath string) (uint32, int64) {
	t.Helper()
	require.False(t, run.aborted, run.reason)
	require.NotEmpty(t, run.attests, "an outside client must find the attestation on a relay")
	pub := nsPublicEvent(t, run.ready)
	var price uint32
	for n, e := range run.attests {
		var w nsWire
		require.NoError(t, json.Unmarshal([]byte(e.Content), &w))
		sigs, err := nsParseDigits(w.S)
		require.NoError(t, err)
		require.True(t, pub.allValid(w.Price, sigs), "attestation must be valid BIP340")
		if n == 0 {
			price = w.Price
		}
		require.Equal(t, price, w.Price, "all attestations must carry one price")
	}
	var first int64 = -1
	for _, o := range run.outs {
		if o.Attested && (first < 0 || o.AttestAtMs < first) {
			first = o.AttestAtMs
		}
	}
	require.GreaterOrEqual(t, first, int64(0))
	return price, first
}

func nsRequirePath(t *testing.T, at int64, timing nsTiming, path string) {
	t.Helper()
	if timing == (nsTiming{}) {
		timing = nsDefaultTiming
	}
	if path == "fast" {
		require.Less(t, at, timing.SlowMs, "must use the fast path")
	} else {
		require.GreaterOrEqual(t, at, timing.SlowMs+timing.GraceMs, "must use the slow path")
	}
}

func nsSignedPrices(run *nsRun) map[uint32]int {
	out := map[uint32]int{}
	for _, o := range run.outs {
		if o.Signed {
			out[o.Vote]++
		}
	}
	return out
}

func nsKillRelay(t *testing.T, i int) {
	out, err := nsDocker("kill", nsContainer(i))
	if err != nil {
		t.Errorf("kill relay %d: %v %s", i, err, out)
	}
}

// nsKillBeforeVote kills relays and fails the test unless they are down before members vote.
func nsKillBeforeVote(t *testing.T, goAt time.Time, relays ...int) {
	time.Sleep(time.Until(goAt.Add(time.Second)))
	var wg sync.WaitGroup
	for _, i := range relays {
		wg.Add(1)
		go func() {
			defer wg.Done()
			nsKillRelay(t, i)
		}()
	}
	wg.Wait()
	if down := time.Since(goAt).Milliseconds(); down >= nsDefaultTiming.ReportMs {
		t.Errorf("relays were only down at %d ms, after the vote deadline", down)
	}
}

func nsStartRelay(t *testing.T, i int) {
	out, err := nsDocker("start", nsContainer(i))
	if err != nil {
		t.Errorf("restart relay %d: %v %s", i, err, out)
	}
}

func TestP2pFiatNostrOracle(t *testing.T) {
	if os.Getenv(nsEnv) != "" {
		t.Skip("member process")
	}
	nsStartRelays(t)

	if os.Getenv("P2PFIAT_FULL_TIMING") == "1" {
		timing := nsTiming{ReportMs: 30000, SlowMs: 600000, GraceMs: 60000, StopMs: 690000}
		t.Run("production timers with 3 members offline", func(t *testing.T) {
			run := nsExecute(t, nsScenario{offline: []int{5, 6, 7}, timing: timing, name: "full"})
			_, at := nsRequireAttested(t, run, "slow")
			nsRequirePath(t, at, timing, "slow")
			t.Logf("attested %.1f s after the event", float64(at)/1000)
		})
		t.Run("production timers with all members online", func(t *testing.T) {
			run := nsExecute(t, nsScenario{timing: timing, name: "full-fast"})
			_, at := nsRequireAttested(t, run, "fast")
			nsRequirePath(t, at, timing, "fast")
			t.Logf("attested %.1f s after the event", float64(at)/1000)
		})
		return
	}

	t.Run("relay events that fail verification are ignored", func(t *testing.T) {
		sk, other := nostr.GeneratePrivateKey(), nostr.GeneratePrivateKey()
		pub, _ := nostr.GetPublicKey(sk)
		otherPub, _ := nostr.GetPublicKey(other)
		byPub := map[string]int{pub: 1}
		build := func(key, session string) *nostr.Event {
			p, _ := nostr.GetPublicKey(key)
			e := &nostr.Event{
				PubKey: p, CreatedAt: nostr.Now(), Kind: nsKind,
				Tags: nostr.Tags{{"t", session}}, Content: `{"type":"vote","price":100000}`,
			}
			require.NoError(t, e.Sign(key))
			return e
		}
		_, ok := nsAccept(build(sk, "s"), "s", byPub)
		require.True(t, ok)
		_, ok = nsAccept(build(other, "s"), "s", byPub)
		require.False(t, ok, "unknown author")
		_, ok = nsAccept(build(sk, "older-session"), "s", byPub)
		require.False(t, ok, "replay from another session")
		_, ok = nsAccept(build(sk, "s-longer"), "s", byPub)
		require.False(t, ok, "session that only shares a prefix")
		changed := build(sk, "s")
		changed.Content = `{"type":"vote","price":1}`
		_, ok = nsAccept(changed, "s", byPub)
		require.False(t, ok, "changed content")
		resigned := build(sk, "s")
		resigned.Content = `{"type":"vote","price":1}`
		resigned.ID = resigned.GetID()
		_, ok = nsAccept(resigned, "s", byPub)
		require.False(t, ok, "signature from before the change")
		stolen := build(other, "s")
		stolen.PubKey = pub
		stolen.ID = stolen.GetID()
		_, ok = nsAccept(stolen, "s", byPub)
		require.False(t, ok, "another key claiming to be a member")
		require.NotEqual(t, pub, otherPub)
	})

	for _, c := range []struct {
		name    string
		offline []int
		path    string
	}{
		{"all 7 online", nil, "fast"},
		{"2 offline", []int{6, 7}, "fast"},
		{"3 offline", []int{5, 6, 7}, "slow"},
	} {
		t.Run(c.name, func(t *testing.T) {
			run := nsExecute(t, nsScenario{name: c.name, offline: c.offline})
			price, at := nsRequireAttested(t, run, c.path)
			nsRequirePath(t, at, nsTiming{}, c.path)
			var setup int64
			var sent int64
			for _, o := range run.outs {
				setup = max(setup, o.SetupMs)
				sent = max(sent, o.BytesSent)
			}
			t.Logf("%s: price %d attested %.2f s after the event, largest member sent %.1f KB of original events",
				c.name, price, float64(at)/1000, float64(sent)/1024)
		})
	}

	t.Run("4 offline stops attestation", func(t *testing.T) {
		run := nsExecute(t, nsScenario{name: "4 offline", offline: []int{4, 5, 6, 7}})
		require.False(t, run.aborted, run.reason)
		require.Len(t, run.outs, 3)
		require.Empty(t, run.attests)
		require.Empty(t, nsSignedPrices(run))
	})

	t.Run("network latency of 150 to 400 ms per hop", func(t *testing.T) {
		run := nsExecute(t, nsScenario{name: "latency", latency: 150, jitter: 250})
		_, at := nsRequireAttested(t, run, "fast")
		nsRequirePath(t, at, nsTiming{}, "fast")
		t.Logf("attested %.2f s after the event", float64(at)/1000)
	})

	for _, c := range []struct {
		name string
		bad  map[int]string
		path string
	}{
		{"2 report extreme prices", map[int]string{6: "extreme-low", 7: "extreme-high"}, "fast"},
		{"3 report extreme prices", map[int]string{5: "extreme-high", 6: "extreme-high", 7: "extreme-high"}, "slow"},
		{"3 stay silent", map[int]string{5: "silent", 6: "silent", 7: "silent"}, "slow"},
	} {
		t.Run(c.name, func(t *testing.T) {
			run := nsExecute(t, nsScenario{name: c.name, behavior: c.bad})
			price, at := nsRequireAttested(t, run, c.path)
			nsRequirePath(t, at, nsTiming{}, c.path)
			var low, high uint32 = 1 << 31, 0
			for _, id := range gIDs {
				if _, bad := c.bad[id]; !bad {
					v := uint32(100_000 + id*10)
					low, high = min(low, v), max(high, v)
				}
			}
			require.GreaterOrEqual(t, price, low)
			require.LessOrEqual(t, price, high)
			t.Logf("%s: attested %d at %.2f s", c.name, price, float64(at)/1000)
		})
	}

	t.Run("a bad partial signature is rejected", func(t *testing.T) {
		run := nsExecute(t, nsScenario{name: "bad partial", behavior: map[int]string{1: "bad-partial"}})
		_, at := nsRequireAttested(t, run, "fast")
		nsRequirePath(t, at, nsTiming{}, "fast")
	})

	t.Run("a bad key share aborts setup", func(t *testing.T) {
		run := nsExecute(t, nsScenario{name: "bad share", behavior: map[int]string{7: "bad-share"}})
		require.True(t, run.aborted)
		require.Regexp(t, `dealer 7: invalid share|aborted setup: dealer 7: invalid share`, run.reason)
		t.Logf("setup aborted: %s", run.reason)
	})

	t.Run("a dealer sending two deals aborts setup", func(t *testing.T) {
		run := nsExecute(t, nsScenario{name: "two deals", behavior: map[int]string{7: "equivocate-deal"}})
		require.True(t, run.aborted)
		require.Regexp(t, `dealer 7 equivocated|two deals|transcript mismatch`, run.reason)
		t.Logf("setup aborted: %s", run.reason)
	})

	splitSides := map[int]int{1: 0, 2: 0, 3: 0, 4: 1, 5: 1, 6: 1}
	splitOwn := map[int]uint32{1: gPriceA, 2: gPriceA, 3: gPriceA, 4: gPriceB, 5: gPriceB, 6: gPriceB}

	t.Run("last-second double vote fails when the split heals in time", func(t *testing.T) {
		run := nsExecute(t, nsScenario{
			name: "healed split", own: splitOwn, sides: splitSides,
			behavior: map[int]string{7: "split"},
			voteAtMs: nsDefaultTiming.SlowMs - 1000, healMs: nsDefaultTiming.SlowMs + 2000,
		})
		require.False(t, run.aborted, run.reason)
		require.Empty(t, run.outs[7].LeakedKey, "the grace period must stop the leak")
		for price, count := range nsSignedPrices(run) {
			t.Logf("price %d signed by %d honest members", price, count)
		}
		require.Empty(t, nsSignedPrices(run), "no honest member may sign after seeing the double vote")
	})

	t.Run("a split outlasting the slow path leaks the event key", func(t *testing.T) {
		timing := nsDefaultTiming
		timing.StopMs = 40000
		run := nsExecute(t, nsScenario{
			name: "long split", own: splitOwn, sides: splitSides, timing: timing,
			behavior: map[int]string{7: "split"},
			voteAtMs: timing.ReportMs + 200, healMs: 36000,
		})
		require.False(t, run.aborted, run.reason)
		require.NotEmpty(t, run.outs[7].LeakedKey, "expected the documented long-split leak")
		x, err := nsParseScalar(run.outs[7].LeakedKey)
		require.NoError(t, err)
		xG := thrMulG(&x)
		require.Equal(t, run.ready.EventPx, hex.EncodeToString(thrSer(&xG)[1:]), "must be the event key")
		require.NotEqual(t, run.ready.LongPx, run.ready.EventPx)
		t.Log("1 malicious member recovered the event key through real relays; the long-term key is different")
	})

	t.Run("one relay killed during the event", func(t *testing.T) {
		run := nsExecute(t, nsScenario{name: "one relay", during: func(goAt time.Time) {
			nsKillBeforeVote(t, goAt, 0)
		}})
		nsStartRelay(t, 0)
		nsWaitRelay(t, 0)
		_, at := nsRequireAttested(t, run, "fast")
		nsRequirePath(t, at, nsTiming{}, "fast")
	})

	t.Run("two relays killed during the event", func(t *testing.T) {
		run := nsExecute(t, nsScenario{name: "two relays", during: func(goAt time.Time) {
			nsKillBeforeVote(t, goAt, 0, 1)
		}})
		nsStartRelay(t, 0)
		nsStartRelay(t, 1)
		nsWaitRelay(t, 0)
		nsWaitRelay(t, 1)
		_, at := nsRequireAttested(t, run, "fast")
		nsRequirePath(t, at, nsTiming{}, "fast")
	})

	t.Run("all relays down across the vote deadline", func(t *testing.T) {
		const restartMs = 7500
		run := nsExecute(t, nsScenario{name: "all relays", during: func(goAt time.Time) {
			nsKillBeforeVote(t, goAt, 0, 1, 2)
			time.Sleep(time.Until(goAt.Add(restartMs * time.Millisecond)))
			for i := range nsRelays {
				nsStartRelay(t, i)
			}
			for i := range nsRelays {
				nsWaitRelay(t, i)
			}
		}})
		price, at := nsRequireAttested(t, run, "fast")
		nsRequirePath(t, at, nsTiming{}, "fast")
		require.GreaterOrEqual(t, at, int64(restartMs), "the attestation must come after the outage")
		t.Logf("attested %d at %.2f s, after all relays were down across the vote deadline until 7.5 s", price, float64(at)/1000)
	})
}
