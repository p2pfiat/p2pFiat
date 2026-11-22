package p2pfiatcost

// Experiment 9: fault-tolerant event setup for the 4-of-7 nostr oracle.
//
// Experiment 8 needed all 7 members online to set up each event. Here a bad or
// missing dealer is excluded. Members complain about bad shares, dealers answer
// in public, a rotating leader proposes the final dealer set, and 5 members must
// certify it. A member that was offline catches up from the relays. Each attempt
// is a fresh key generation, so a failed attempt leaves no state to reconcile.
//
// Seven OS processes communicate through three local strfry relays. This is a
// research prototype and has not had a cryptographic review.
//
// Needs the test files of experiments 5 to 8. Copy all five into arkd's
// internal/test/p2pfiatcost directory and run:
//   go test -v -count 5 -timeout 3400s -run '^TestP2pFiatFaultTolerantSetup$' ./internal/test/p2pfiatcost

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/bits"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
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
	fsEnv            = "P2PFIAT_SETUP_MEMBER"
	fsLine           = "P2PFIATS:"
	fsCertVotes      = 5
	fsInstKey        = 0
	fsInstDigit      = 1
	fsInstCert       = fsInstDigit + numDigits
	fsEventInstances = fsInstCert + 1
	fsDealMs         = 2000
	fsProposeMs      = 4500
	fsFailMs         = 11000
	fsCatchupMs      = 15000
)

type fsCmd struct {
	Op       string
	Label    string
	Leader   int
	GoMs     int64
	Behavior string
	Own      uint32
}

type fsOutput struct {
	Op         string
	Label      string
	Error      string
	Certified  bool
	HasShare   bool
	Transcript string
	Qual       []int
	LongPx     string
	EventPx    string
	Rx         []string
	CertMsg    string
	Cert       string
	Attested   bool
	AttestAtMs int64
	Price      uint32
	// Evidence that an attack really reached this member.
	VotedFor     string
	SawProposals int
	Complaints   int
	Answers      int
}

type fsDealRec struct {
	from    int
	id      string
	w       nsWire
	commits [][]btcec.JacobianPoint
	valid   bool
	checked bool
	mine    []btcec.ModNScalar
}

// fsCheckDeal verifies a deal's public part: commitments and proofs of knowledge.
func fsCheckDeal(session string, m nsMsg, instances int) *fsDealRec {
	rec := &fsDealRec{from: m.from, id: m.id, w: m.w}
	w := m.w
	if len(w.Commits) != instances || len(w.R) != instances || len(w.Z) != instances {
		return rec
	}
	for inst := range instances {
		if len(w.Commits[inst]) != gT {
			return rec
		}
		commits := make([]btcec.JacobianPoint, gT)
		for k := range commits {
			p, err := nsParsePoint(w.Commits[inst][k])
			if err != nil {
				return rec
			}
			commits[k] = p
		}
		r, err := nsParsePoint(w.R[inst])
		if err != nil {
			return rec
		}
		z, err := nsParseScalar(w.Z[inst])
		if err != nil {
			return rec
		}
		e := thrProofChallenge(fmt.Sprintf("%s/%d", session, inst), m.from, &commits[0], &r)
		lhs := thrMulG(&z)
		ec := thrMul(&e, &commits[0])
		rhs := thrAdd(&r, &ec)
		if !thrEqual(&lhs, &rhs) {
			return rec
		}
		rec.commits = append(rec.commits, commits)
	}
	rec.valid = true
	return rec
}

func fsCheckShares(rec *fsDealRec, id int, shares []btcec.ModNScalar) bool {
	if !rec.valid || len(shares) != len(rec.commits) {
		return false
	}
	for inst := range shares {
		got := thrMulG(&shares[inst])
		want := thrEvalCommit(rec.commits[inst], id)
		if !thrEqual(&got, &want) {
			return false
		}
	}
	return true
}

func fsParseScalars(v []string) ([]btcec.ModNScalar, error) {
	out := make([]btcec.ModNScalar, len(v))
	for i := range v {
		s, err := nsParseScalar(v[i])
		if err != nil {
			return nil, err
		}
		out[i] = s
	}
	return out, nil
}

func fsTranscript(session string, ids []string, dealerOf func(string) int) string {
	ordered := slices.Clone(ids)
	slices.SortFunc(ordered, func(a, b string) int { return dealerOf(a) - dealerOf(b) })
	h := sha256.New()
	h.Write([]byte("p2pfiat/setup-transcript"))
	h.Write([]byte(session))
	for _, id := range ordered {
		fmt.Fprintf(h, "|%d:%s", dealerOf(id), id)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// fsSetup is one member's run of one setup attempt.
type fsSetup struct {
	t         testing.TB
	n         *nsNode
	id        int
	instances int
	leader    int
	behavior  string
	passive   bool
	long      *thrKey

	deals      map[string]*fsDealRec
	byDealer   map[int][]string
	complaints map[string]map[int]bool
	complained map[string]bool
	answered   map[string]bool
	reveals    map[string]map[int][]btcec.ModNScalar
	pending    []nsMsg
	proposals  [][]string
	votes      map[int]string
	badVoters  map[int]bool
	certParts  []nsMsg
	trueShares map[int][]string
	voted      bool
	proposed   bool
}

func (s *fsSetup) ingest(m nsMsg) {
	switch m.w.Type {
	case "fs-deal":
		if _, ok := s.deals[m.id]; !ok {
			s.deals[m.id] = fsCheckDeal(s.n.cfg.Session, m, s.instances)
			s.byDealer[m.from] = append(s.byDealer[m.from], m.id)
		}
	case "fs-complaint":
		if s.complaints[m.w.Hash] == nil {
			s.complaints[m.w.Hash] = map[int]bool{}
		}
		s.complaints[m.w.Hash][m.from] = true
	case "fs-reveal":
		s.pending = append(s.pending, m)
	case "fs-proposal":
		if m.from == s.leader {
			s.proposals = append(s.proposals, m.w.S)
		}
	case "fs-vote":
		if old, ok := s.votes[m.from]; ok && old != m.w.Hash {
			s.badVoters[m.from] = true
		} else {
			s.votes[m.from] = m.w.Hash
		}
	case "fs-certpart":
		s.certParts = append(s.certParts, m)
	}
}

func (s *fsSetup) resolveReveals() {
	var keep []nsMsg
	for _, m := range s.pending {
		rec := s.deals[m.w.Hash]
		if rec == nil {
			keep = append(keep, m)
			continue
		}
		if rec.from != m.from {
			continue
		}
		shares, err := fsParseScalars(m.w.S)
		if err != nil || !fsCheckShares(rec, int(m.w.Price), shares) {
			continue
		}
		if s.reveals[rec.id] == nil {
			s.reveals[rec.id] = map[int][]btcec.ModNScalar{}
		}
		s.reveals[rec.id][int(m.w.Price)] = shares
	}
	s.pending = keep
}

// myShares returns this member's share of a deal, from its ciphertext or a public answer.
func (s *fsSetup) myShares(rec *fsDealRec) []btcec.ModNScalar {
	if !rec.valid {
		return nil
	}
	if !rec.checked {
		rec.checked = true
		func() {
			key, err := nip44.GenerateConversationKey(s.n.cfg.Roster[rec.from], s.n.cfg.SK)
			if err != nil {
				return
			}
			plain, err := nip44.Decrypt(rec.w.Shares[s.id], key)
			if err != nil {
				return
			}
			var v []string
			if json.Unmarshal([]byte(plain), &v) != nil {
				return
			}
			shares, err := fsParseScalars(v)
			if err == nil && fsCheckShares(rec, s.id, shares) {
				rec.mine = shares
			}
		}()
	}
	if rec.mine != nil {
		return rec.mine
	}
	return s.reveals[rec.id][s.id]
}

func (s *fsSetup) unresolved(rec *fsDealRec) bool {
	for complainer := range s.complaints[rec.id] {
		if s.reveals[rec.id][complainer] == nil {
			return true
		}
	}
	return false
}

func (s *fsSetup) dealerOf(id string) int {
	if rec := s.deals[id]; rec != nil {
		return rec.from
	}
	return 0
}

func (s *fsSetup) qualified() []string {
	var out []string
	for _, d := range gIDs {
		ids := s.byDealer[d]
		if len(ids) != 1 {
			continue
		}
		rec := s.deals[ids[0]]
		if rec.valid && !s.unresolved(rec) {
			out = append(out, rec.id)
		}
	}
	return out
}

func (s *fsSetup) acceptable(ids []string) bool {
	if len(ids) < gT {
		return false
	}
	dealers := map[int]bool{}
	for _, id := range ids {
		rec := s.deals[id]
		if rec == nil || !rec.valid || dealers[rec.from] || s.unresolved(rec) || s.myShares(rec) == nil {
			return false
		}
		dealers[rec.from] = true
	}
	return true
}

func (s *fsSetup) deal() error {
	corrupt := 0
	switch s.behavior {
	case "bad-share", "bad-share-answer":
		corrupt = 1
	case "bad-share-offline":
		corrupt = 6
	case "silent-dealer":
		return nil
	}
	first, shares, err := fsMakeDeal(s.t, s.n, s.instances, corrupt)
	if err != nil {
		return err
	}
	s.trueShares = shares
	if s.behavior == "two-deals" {
		second, _, err := fsMakeDeal(s.t, s.n, s.instances, 0)
		if err != nil {
			return err
		}
		if err := s.n.send(first, 0); err != nil {
			return err
		}
		return s.n.send(second, 1, 2)
	}
	return s.n.send(first)
}

func fsMakeDeal(t testing.TB, n *nsNode, instances, corrupt int) (nsWire, map[int][]string, error) {
	w := nsWire{Type: "fs-deal", Shares: map[int]string{}}
	plain, honest := map[int][]string{}, map[int][]string{}
	for inst := range instances {
		d := gNewDealer(t, fmt.Sprintf("%s/%d", n.cfg.Session, inst), n.cfg.ID)
		c := make([]string, len(d.commits))
		for i := range d.commits {
			c[i] = nsPointHex(&d.commits[i])
		}
		w.Commits = append(w.Commits, c)
		w.R = append(w.R, nsPointHex(&d.proofR))
		w.Z = append(w.Z, nsScalarHex(&d.proofZ))
		for _, j := range gIDs {
			v := d.shares[j]
			honest[j] = append(honest[j], nsScalarHex(&v))
			if j == corrupt {
				one := thrScalar(1)
				v.Add(&one)
			}
			plain[j] = append(plain[j], nsScalarHex(&v))
		}
	}
	for _, j := range gIDs {
		body, err := json.Marshal(plain[j])
		if err != nil {
			return w, nil, err
		}
		key, err := nip44.GenerateConversationKey(n.cfg.Roster[j], n.cfg.SK)
		if err != nil {
			return w, nil, err
		}
		if w.Shares[j], err = nip44.Encrypt(string(body), key); err != nil {
			return w, nil, err
		}
	}
	return w, honest, nil
}

func (s *fsSetup) complain() error {
	for id, rec := range s.deals {
		if s.complained[id] || rec.from == s.id {
			continue
		}
		bad := rec.valid && s.myShares(rec) == nil
		if s.behavior == "false-complaint" && rec.valid {
			bad = true
		}
		s.complained[id] = true
		if bad {
			if err := s.n.send(nsWire{Type: "fs-complaint", Hash: id}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *fsSetup) answer() error {
	if s.behavior == "bad-share" || s.behavior == "bad-share-offline" || s.trueShares == nil {
		return nil
	}
	for id, who := range s.complaints {
		rec := s.deals[id]
		if rec == nil || rec.from != s.id {
			continue
		}
		for complainer := range who {
			key := fmt.Sprintf("%s/%d", id, complainer)
			if s.answered[key] {
				continue
			}
			s.answered[key] = true
			err := s.n.send(nsWire{
				Type: "fs-reveal", Hash: id, Price: uint32(complainer), S: s.trueShares[complainer],
			})
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *fsSetup) propose() error {
	s.proposed = true
	ids := s.qualified()
	switch s.behavior {
	case "leader-silent":
		return nil
	case "leader-include":
		ids = nil
		for _, d := range gIDs {
			if l := s.byDealer[d]; len(l) > 0 && s.deals[l[0]].valid {
				ids = append(ids, l[0])
			}
		}
	case "leader-exclude":
		if len(ids) > gT {
			ids = ids[:gT]
		}
	case "leader-two":
		if len(ids) <= gT {
			return nil
		}
		other := ids[:len(ids)-1]
		s.voted = true
		for relay, set := range [][]string{ids, other} {
			if err := s.n.send(nsWire{Type: "fs-proposal", S: set}, relay); err != nil {
				return err
			}
			h := fsTranscript(s.n.cfg.Session, set, s.dealerOf)
			if err := s.n.send(nsWire{Type: "fs-vote", Hash: h}, relay); err != nil {
				return err
			}
		}
		return nil
	}
	if len(ids) < gT {
		return nil
	}
	return s.n.send(nsWire{Type: "fs-proposal", S: ids})
}

func (s *fsSetup) tryVote() error {
	for _, ids := range s.proposals {
		if !s.acceptable(ids) {
			continue
		}
		s.voted = true
		h := fsTranscript(s.n.cfg.Session, ids, s.dealerOf)
		s.votes[s.id] = h
		return s.n.send(nsWire{Type: "fs-vote", Hash: h})
	}
	return nil
}

func (s *fsSetup) certified() (string, []string) {
	count := map[string]int{}
	for voter, h := range s.votes {
		if !s.badVoters[voter] {
			count[h]++
		}
	}
	for h, c := range count {
		if c < fsCertVotes {
			continue
		}
		for _, ids := range s.proposals {
			known := true
			for _, id := range ids {
				known = known && s.deals[id] != nil && s.deals[id].valid
			}
			if known && fsTranscript(s.n.cfg.Session, ids, s.dealerOf) == h {
				return h, ids
			}
		}
	}
	return "", nil
}

// finalize derives the group keys from exactly the certified deals.
func (s *fsSetup) finalize(ids []string) ([]*thrKey, []int, bool) {
	recs := make([]*fsDealRec, 0, len(ids))
	qual := make([]int, 0, len(ids))
	hasShare := true
	for _, id := range ids {
		rec := s.deals[id]
		recs = append(recs, rec)
		qual = append(qual, rec.from)
		hasShare = hasShare && s.myShares(rec) != nil
	}
	slices.Sort(qual)
	keys := make([]*thrKey, s.instances)
	for inst := range s.instances {
		sum := slices.Clone(recs[0].commits[inst])
		for _, rec := range recs[1:] {
			for k := range sum {
				sum[k] = thrAdd(&sum[k], &rec.commits[inst][k])
			}
		}
		var share btcec.ModNScalar
		if hasShare {
			for _, rec := range recs {
				v := s.myShares(rec)[inst]
				share.Add(&v)
			}
		}
		group := sum[0]
		flip := group.Y.IsOdd()
		if flip {
			thrNegate(&group)
			share.Negate()
		}
		k := &thrKey{
			group: group, shares: map[int]btcec.ModNScalar{}, verify: map[int]btcec.JacobianPoint{},
			qualified: slices.Clone(qual), excluded: map[int]string{},
		}
		if hasShare {
			k.shares[s.id] = share
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
	return keys, qual, hasShare
}

type fsResult struct {
	out   *fsOutput
	keys  []*thrKey
	event *thrEvent
}

func (s *fsSetup) run(goAt time.Time, limitMs int64) (*fsResult, error) {
	out := &fsOutput{}
	if !s.passive {
		time.Sleep(time.Until(goAt))
		if err := s.deal(); err != nil {
			return nil, err
		}
	}
	var keys []*thrKey
	var event *thrEvent
	var certMsg, rx, longPx []byte
	var certC btcec.ModNScalar
	var transcript string
	certSent := false
	good := map[int]btcec.ModNScalar{}
	for {
		msgs := s.n.take(50 * time.Millisecond)
		now := time.Since(goAt).Milliseconds()
		if now >= limitMs {
			return &fsResult{out: out}, nil
		}
		for _, m := range msgs {
			s.ingest(m)
		}
		s.resolveReveals()
		if !s.passive {
			if now >= fsDealMs {
				if err := s.complain(); err != nil {
					return nil, err
				}
			}
			if err := s.answer(); err != nil {
				return nil, err
			}
			if s.id == s.leader && !s.proposed && now >= fsProposeMs {
				if err := s.propose(); err != nil {
					return nil, err
				}
			}
			if !s.voted && now >= fsProposeMs {
				if err := s.tryVote(); err != nil {
					return nil, err
				}
			}
		}
		if keys == nil {
			h, ids := s.certified()
			if h == "" {
				continue
			}
			var qual []int
			keys, qual, out.HasShare = s.finalize(ids)
			transcript = h
			out.Certified, out.Transcript, out.Qual = true, h, qual
			if s.instances == 1 {
				out.LongPx = hex.EncodeToString(thrSer(&keys[0].group)[1:])
				return &fsResult{out: out, keys: keys}, nil
			}
			event = &thrEvent{key: keys[fsInstKey], ora: &oracle{cache: map[prefix]btcec.JacobianPoint{}}}
			event.px = thrSer(&event.key.group)[1:]
			a := sha256.New()
			a.Write([]byte("p2pfiat/event-announcement"))
			a.Write([]byte(s.n.cfg.Session))
			a.Write([]byte(transcript))
			a.Write(event.px)
			for i := range numDigits {
				event.nonces[i] = keys[fsInstDigit+i]
				event.rx[i] = thrSer(&event.nonces[i].group)[1:]
				a.Write(event.rx[i])
				out.Rx = append(out.Rx, hex.EncodeToString(event.rx[i]))
			}
			certMsg = a.Sum(nil)
			rx = thrSer(&keys[fsInstCert].group)[1:]
			longPx = thrSer(&s.long.group)[1:]
			certC = taggedChallenge(rx, longPx, certMsg)
			out.LongPx, out.EventPx = hex.EncodeToString(longPx), hex.EncodeToString(event.px)
			out.CertMsg = hex.EncodeToString(certMsg)
		}
		// A member signs the announcement once, and only after the transcript is certified.
		if !certSent && !s.passive && out.HasShare {
			certSent = true
			v := certC
			x := s.long.shares[s.id]
			v.Mul(&x)
			k := keys[fsInstCert].shares[s.id]
			v.Add(&k)
			err := s.n.send(nsWire{Type: "fs-certpart", Hash: transcript, S: []string{nsScalarHex(&v)}})
			if err != nil {
				return nil, err
			}
		}
		for _, m := range s.certParts {
			if m.w.Hash != transcript || len(m.w.S) != 1 {
				continue
			}
			v, err := nsParseScalar(m.w.S[0])
			if err != nil {
				continue
			}
			lhs := thrMulG(&v)
			vk := keys[fsInstCert].verify[m.from]
			vx := s.long.verify[m.from]
			cx := thrMul(&certC, &vx)
			rhs := thrAdd(&vk, &cx)
			if thrEqual(&lhs, &rhs) {
				good[m.from] = v
			}
		}
		s.certParts = nil
		if len(good) < gT {
			continue
		}
		var set []int
		for _, id := range gIDs {
			if _, ok := good[id]; ok && len(set) < gT {
				set = append(set, id)
			}
		}
		var total btcec.ModNScalar
		for _, j := range set {
			v := good[j]
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
		pub, err := schnorr.ParsePubKey(longPx)
		if err != nil || !sig.Verify(certMsg, pub) {
			return nil, errors.New("announcement certificate does not verify")
		}
		out.Cert = hex.EncodeToString(raw)
		return &fsResult{out: out, keys: keys, event: event}, nil
	}
}

// TestP2pFiatSetupMember is the entry point of one member process.
func TestP2pFiatSetupMember(t *testing.T) {
	raw := os.Getenv(fsEnv)
	if raw == "" {
		t.Skip("started only as a member process by TestP2pFiatFaultTolerantSetup")
	}
	var cfg nsConfig
	require.NoError(t, json.Unmarshal([]byte(raw), &cfg))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	emit := func(o *fsOutput) {
		body, _ := json.Marshal(o)
		fmt.Fprintf(os.Stdout, "\n%s%s\n", fsLine, body)
	}
	nodes := map[string]*nsNode{}
	events := map[string]*thrEvent{}
	node := func(label string) (*nsNode, error) {
		if n := nodes[label]; n != nil {
			return n, nil
		}
		c := cfg
		c.Session = cfg.Session + "/" + label
		c.Behavior = ""
		n, err := nsNewNode(ctx, c)
		if err == nil {
			nodes[label] = n
		}
		return n, err
	}
	var long *thrKey
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<16), 1<<20)
	for sc.Scan() {
		var cmd fsCmd
		require.NoError(t, json.Unmarshal(sc.Bytes(), &cmd))
		if cmd.Op == "exit" {
			return
		}
		out := &fsOutput{}
		err := func() error {
			n, err := node(cmd.Label)
			if err != nil {
				return err
			}
			if cmd.Op == "attest" {
				event := events[cmd.Label]
				if event == nil {
					return errors.New("no key share for this event")
				}
				n.cfg.Own, n.cfg.Behavior, n.cfg.Timing = cmd.Own, "", nsDefaultTiming
				a := &nsOutput{}
				if err := n.attest(&nsState{event: event}, time.UnixMilli(cmd.GoMs), a); err != nil {
					return err
				}
				out.Attested, out.AttestAtMs, out.Price = a.Attested, a.AttestAtMs, a.AttestPrice
				return nil
			}
			instances := fsEventInstances
			if cmd.Op == "genesis" {
				instances = 1
			}
			s := &fsSetup{
				t: t, n: n, id: cfg.ID, instances: instances, leader: cmd.Leader,
				behavior: cmd.Behavior, passive: cmd.Op == "catchup", long: long,
				deals: map[string]*fsDealRec{}, byDealer: map[int][]string{},
				complaints: map[string]map[int]bool{}, complained: map[string]bool{},
				answered: map[string]bool{}, reveals: map[string]map[int][]btcec.ModNScalar{},
				votes: map[int]string{}, badVoters: map[int]bool{},
			}
			if s.behavior == "leader-two" {
				n.noForward.Store(true)
			}
			limit := int64(fsFailMs)
			if s.passive {
				limit = fsCatchupMs
			}
			res, err := s.run(time.UnixMilli(cmd.GoMs), limit)
			if err != nil {
				return err
			}
			out = res.out
			out.VotedFor, out.SawProposals = s.votes[s.id], len(s.proposals)
			for _, who := range s.complaints {
				out.Complaints += len(who)
			}
			for _, who := range s.reveals {
				out.Answers += len(who)
			}
			if cmd.Op == "genesis" && res.keys != nil {
				long = res.keys[0]
			}
			if res.event != nil && res.out.HasShare {
				events[cmd.Label] = res.event
			}
			return nil
		}()
		if err != nil {
			out.Error = err.Error()
		}
		out.Op, out.Label = cmd.Op, cmd.Label
		emit(out)
	}
}

// Harness.

type fsCluster struct {
	t       *testing.T
	session string
	roster  map[int]string
	stdin   map[int]io.WriteCloser
	procs   map[int]*exec.Cmd
	lines   chan fsMemberLine
	proxies map[[2]int]*nsProxy
	longPx  string
	labels  atomic.Int64
}

type fsMemberLine struct {
	id  int
	out *fsOutput
}

func fsStart(t *testing.T) *fsCluster {
	t.Helper()
	c := &fsCluster{
		t: t, session: fmt.Sprintf("p2pfiat-exp9-%d", time.Now().UnixNano()),
		roster: map[int]string{}, stdin: map[int]io.WriteCloser{}, procs: map[int]*exec.Cmd{},
		lines: make(chan fsMemberLine, 128), proxies: map[[2]int]*nsProxy{},
	}
	sks := map[int]string{}
	for _, id := range gIDs {
		sks[id] = nostr.GeneratePrivateKey()
		pub, err := nostr.GetPublicKey(sks[id])
		require.NoError(t, err)
		c.roster[id] = pub
		for r := range nsRelays {
			c.proxies[[2]int{id, r}] = nsNewProxy(t, fmt.Sprintf("127.0.0.1:%d", nsBasePort+r))
		}
	}
	t.Cleanup(func() {
		for _, p := range c.procs {
			_ = p.Process.Kill()
			_ = p.Wait()
		}
		for _, p := range c.proxies {
			_ = p.ln.Close()
			p.setBlocked(true)
		}
	})
	for _, id := range gIDs {
		var urls []string
		for r := range nsRelays {
			urls = append(urls, "ws://"+c.proxies[[2]int{id, r}].ln.Addr().String())
		}
		body, err := json.Marshal(nsConfig{Session: c.session, ID: id, SK: sks[id], Roster: c.roster, Relays: urls})
		require.NoError(t, err)
		cmd := exec.Command(os.Args[0], "-test.run", "^TestP2pFiatSetupMember$", "-test.timeout", "0")
		cmd.Env = append(os.Environ(), fsEnv+"="+string(body))
		stdin, err := cmd.StdinPipe()
		require.NoError(t, err)
		stdout, err := cmd.StdoutPipe()
		require.NoError(t, err)
		require.NoError(t, cmd.Start())
		c.stdin[id], c.procs[id] = stdin, cmd
		go func(id int) {
			sc := bufio.NewScanner(stdout)
			sc.Buffer(make([]byte, 1<<16), 1<<20)
			for sc.Scan() {
				text, ok := strings.CutPrefix(sc.Text(), fsLine)
				if !ok {
					continue
				}
				o := &fsOutput{}
				if json.Unmarshal([]byte(text), o) == nil {
					c.lines <- fsMemberLine{id: id, out: o}
				}
			}
		}(id)
	}
	genesis := c.run(t, "genesis", "genesis", 1, gIDs, nil, 30*time.Second)
	for _, id := range gIDs {
		require.True(t, genesis[id].Certified, "genesis must certify")
		require.Equal(t, genesis[1].LongPx, genesis[id].LongPx)
	}
	c.longPx = genesis[1].LongPx
	return c
}

func (c *fsCluster) label() string {
	return "event-" + strconv.FormatInt(c.labels.Add(1), 10)
}

func (c *fsCluster) run(
	t *testing.T, op, label string, leader int, ids []int, behavior map[int]string, wait time.Duration,
) map[int]*fsOutput {
	t.Helper()
	goMs := time.Now().Add(time.Second).UnixMilli()
	for _, id := range ids {
		body, err := json.Marshal(fsCmd{
			Op: op, Label: label, Leader: leader, GoMs: goMs, Behavior: behavior[id],
			Own: uint32(100_000 + id*10),
		})
		require.NoError(t, err)
		_, err = c.stdin[id].Write(append(body, '\n'))
		require.NoError(t, err)
	}
	out := map[int]*fsOutput{}
	limit := time.After(wait)
	for len(out) < len(ids) {
		select {
		case l := <-c.lines:
			if l.out.Label != label || l.out.Op != op {
				continue
			}
			require.Empty(t, l.out.Error, "member %d", l.id)
			out[l.id] = l.out
		case <-limit:
			require.Fail(t, "members did not answer", "%s %s: %d of %d", op, label, len(out), len(ids))
		}
	}
	return out
}

func (c *fsCluster) setup(
	t *testing.T, leader int, ids []int, behavior map[int]string,
) (string, map[int]*fsOutput) {
	t.Helper()
	label := c.label()
	return label, c.run(t, "setup", label, leader, ids, behavior, 30*time.Second)
}

// requireCertified checks one transcript, one key set and a valid long-term certificate.
func (c *fsCluster) requireCertified(t *testing.T, outs map[int]*fsOutput, want []int) *fsOutput {
	t.Helper()
	var pub *fsOutput
	for id, o := range outs {
		require.True(t, o.Certified, "member %d must certify", id)
		if pub == nil {
			pub = o
		}
		require.Equal(t, pub.Transcript, o.Transcript, "one transcript")
		require.Equal(t, pub.EventPx, o.EventPx, "one event key")
		require.Equal(t, pub.Rx, o.Rx, "one nonce set")
		require.Equal(t, pub.Qual, o.Qual, "one dealer set")
		require.Equal(t, c.longPx, o.LongPx, "same long-term key")
	}
	require.NotNil(t, pub)
	if want != nil {
		require.Equal(t, want, pub.Qual)
	}
	var withCert *fsOutput
	for _, o := range outs {
		if o.Cert != "" {
			withCert = o
			break
		}
	}
	require.NotNil(t, withCert, "the announcement must be certified")
	raw, err := hex.DecodeString(withCert.Cert)
	require.NoError(t, err)
	sig, err := schnorr.ParseSignature(raw)
	require.NoError(t, err)
	lp, _ := hex.DecodeString(c.longPx)
	key, err := schnorr.ParsePubKey(lp)
	require.NoError(t, err)
	msg, _ := hex.DecodeString(withCert.CertMsg)
	require.True(t, sig.Verify(msg, key), "the long-term key must certify the announcement")
	return pub
}

func fsNotCertified(t *testing.T, outs map[int]*fsOutput) {
	t.Helper()
	for id, o := range outs {
		require.False(t, o.Certified, "member %d must not certify", id)
	}
}

func (c *fsCluster) requireAttests(
	t *testing.T, label string, pub *fsOutput, ids []int, path string,
) int64 {
	t.Helper()
	outs := c.run(t, "attest", label, 0, ids, nil, 50*time.Second)
	first := int64(-1)
	for _, o := range outs {
		if o.Attested && (first < 0 || o.AttestAtMs < first) {
			first = o.AttestAtMs
		}
	}
	require.GreaterOrEqual(t, first, int64(0), "members must attest")
	nsRequirePath(t, first, nsDefaultTiming, path)
	events := nsFetchAttestations(t, c.session+"/"+label, c.roster)
	require.NotEmpty(t, events, "an outside client must find the attestation")
	public := nsPublicEvent(t, &nsOutput{EventPx: pub.EventPx, Rx: pub.Rx})
	var price uint32
	for n, e := range events {
		var w nsWire
		require.NoError(t, json.Unmarshal([]byte(e.Content), &w))
		sigs, err := nsParseDigits(w.S)
		require.NoError(t, err)
		require.True(t, public.allValid(w.Price, sigs), "attestation must verify")
		if n == 0 {
			price = w.Price
		}
		require.Equal(t, price, w.Price)
	}
	return first
}

func fsOnly(ids ...int) []int { return ids }

func fsWithout(out ...int) []int {
	var ids []int
	for _, id := range gIDs {
		if !slices.Contains(out, id) {
			ids = append(ids, id)
		}
	}
	return ids
}

func TestP2pFiatFaultTolerantSetup(t *testing.T) {
	if os.Getenv(fsEnv) != "" || os.Getenv(nsEnv) != "" {
		t.Skip("member process")
	}

	t.Run("setup availability per attempt", func(t *testing.T) {
		for _, q := range []float64{0.01, 0.05, 0.10, 0.20, 0.30} {
			var five float64
			for mask := range 1 << gN {
				on := bits.OnesCount(uint(mask))
				if on >= fsCertVotes {
					five += math.Pow(1-q, float64(on)) * math.Pow(q, float64(gN-on))
				}
			}
			all := math.Pow(1-q, gN)
			require.Greater(t, five, all)
			t.Logf("offline %.0f%%: all 7 %.1f%%, at least 5 %.3f%%, 3 independent attempts %.4f%%",
				q*100, all*100, five*100, (1-math.Pow(1-five, 3))*100)
		}
	})

	nsStartRelays(t)
	c := fsStart(t)

	t.Run("all 7 online", func(t *testing.T) {
		label, outs := c.setup(t, 1, gIDs, nil)
		pub := c.requireCertified(t, outs, gIDs)
		at := c.requireAttests(t, label, pub, gIDs, "fast")
		t.Logf("attested %.2f s after the event", float64(at)/1000)
	})

	t.Run("2 offline during setup", func(t *testing.T) {
		online := fsWithout(6, 7)
		label, outs := c.setup(t, 1, online, nil)
		pub := c.requireCertified(t, outs, online)
		c.requireAttests(t, label, pub, online, "fast")
	})

	t.Run("3 offline stops new setup safely", func(t *testing.T) {
		_, outs := c.setup(t, 1, fsWithout(5, 6, 7), nil)
		fsNotCertified(t, outs)
		for id, o := range outs {
			require.NotEmpty(t, o.VotedFor, "member %d must vote, so only the 5-vote rule stops it", id)
			require.Equal(t, outs[1].VotedFor, o.VotedFor)
		}
	})

	t.Run("members that missed setup catch up and sign", func(t *testing.T) {
		label, outs := c.setup(t, 1, fsWithout(6, 7), nil)
		pub := c.requireCertified(t, outs, fsWithout(6, 7))
		late := c.run(t, "catchup", label, 1, fsOnly(6, 7), nil, 25*time.Second)
		for id, o := range late {
			require.True(t, o.Certified, "member %d", id)
			require.True(t, o.HasShare, "member %d", id)
			require.Equal(t, pub.EventPx, o.EventPx)
		}
		// Only 4 members are online, and 2 of them missed setup.
		c.requireAttests(t, label, pub, fsOnly(4, 5, 6, 7), "slow")
	})

	t.Run("a bad share with no answer excludes the dealer", func(t *testing.T) {
		label, outs := c.setup(t, 1, gIDs, map[int]string{7: "bad-share"})
		pub := c.requireCertified(t, outs, fsWithout(7))
		require.True(t, outs[1].HasShare)
		require.GreaterOrEqual(t, outs[1].Complaints, 1, "member 1 must have complained")
		require.Zero(t, outs[1].Answers, "the dealer must not have answered")
		c.requireAttests(t, label, pub, gIDs, "fast")
	})

	t.Run("a dealer that answers a complaint stays in", func(t *testing.T) {
		label, outs := c.setup(t, 1, gIDs, map[int]string{7: "bad-share-answer"})
		pub := c.requireCertified(t, outs, gIDs)
		require.True(t, outs[1].HasShare, "the public answer must repair the share")
		require.GreaterOrEqual(t, outs[1].Answers, 1, "the share must come from the public answer")
		c.requireAttests(t, label, pub, fsOnly(1, 2, 3, 4, 5), "fast")
	})

	t.Run("a false complaint cannot exclude honest dealers", func(t *testing.T) {
		label, outs := c.setup(t, 1, gIDs, map[int]string{7: "false-complaint"})
		pub := c.requireCertified(t, outs, gIDs)
		require.GreaterOrEqual(t, outs[1].Complaints, gN-1, "member 7 must complain about every dealer")
		require.GreaterOrEqual(t, outs[1].Answers, gN-1, "every honest dealer must answer")
		c.requireAttests(t, label, pub, gIDs, "fast")
	})

	t.Run("a dealer that sends nothing is excluded", func(t *testing.T) {
		label, outs := c.setup(t, 1, gIDs, map[int]string{7: "silent-dealer"})
		pub := c.requireCertified(t, outs, fsWithout(7))
		c.requireAttests(t, label, pub, gIDs, "fast")
	})

	t.Run("a dealer that sends two deals is excluded", func(t *testing.T) {
		label, outs := c.setup(t, 1, gIDs, map[int]string{7: "two-deals"})
		pub := c.requireCertified(t, outs, fsWithout(7))
		c.requireAttests(t, label, pub, gIDs, "fast")
	})

	t.Run("a silent leader only costs one attempt", func(t *testing.T) {
		_, first := c.setup(t, 7, gIDs, map[int]string{7: "leader-silent"})
		fsNotCertified(t, first)
		label, second := c.setup(t, 1, gIDs, nil)
		pub := c.requireCertified(t, second, gIDs)
		c.requireAttests(t, label, pub, gIDs, "fast")
	})

	t.Run("a leader cannot include a dealer with an open complaint", func(t *testing.T) {
		_, outs := c.setup(t, 7, gIDs, map[int]string{6: "bad-share", 7: "leader-include"})
		fsNotCertified(t, outs)
		for _, id := range fsOnly(1, 2, 3, 4, 5) {
			require.GreaterOrEqual(t, outs[id].SawProposals, 1, "member %d must see the proposal", id)
			require.Empty(t, outs[id].VotedFor, "member %d must refuse it", id)
		}
	})

	t.Run("a leader sending two proposals cannot create two keys", func(t *testing.T) {
		_, outs := c.setup(t, 7, gIDs, map[int]string{7: "leader-two"})
		seen := map[string]bool{}
		for id, o := range outs {
			if id != 7 && o.Certified {
				seen[o.Transcript] = true
			}
		}
		require.LessOrEqual(t, len(seen), 1, "honest members must not finish with two transcripts")
		t.Logf("%d certified transcript among honest members", len(seen))
	})

	t.Run("a split with a two-faced leader certifies nothing", func(t *testing.T) {
		sides := map[int]int{1: 0, 2: 0, 3: 0, 4: 1, 5: 1, 6: 1}
		cut := time.AfterFunc(time.Second+3500*time.Millisecond, func() {
			for id, side := range sides {
				for r := range nsRelays {
					if r != side {
						c.proxies[[2]int{id, r}].setBlocked(true)
					}
				}
			}
		})
		defer cut.Stop()
		_, outs := c.setup(t, 7, gIDs, map[int]string{7: "leader-two"})
		for _, p := range c.proxies {
			p.setBlocked(false)
		}
		for id, side := range sides {
			require.False(t, outs[id].Certified, "member %d must not certify in a split", id)
			require.NotEmpty(t, outs[id].VotedFor, "member %d must vote", id)
			require.Equal(t, outs[fsOnly(1, 4)[side]].VotedFor, outs[id].VotedFor, "one vote per side")
		}
		require.NotEqual(t, outs[1].VotedFor, outs[4].VotedFor,
			"the sides must vote for conflicting key sets, so a 4-vote rule would have created two keys")
		label, retry := c.setup(t, 1, gIDs, nil)
		pub := c.requireCertified(t, retry, gIDs)
		c.requireAttests(t, label, pub, gIDs, "fast")
	})

	t.Run("a leader can shrink the dealer set to 4", func(t *testing.T) {
		label, outs := c.setup(t, 7, gIDs, map[int]string{7: "leader-exclude"})
		pub := c.requireCertified(t, outs, fsOnly(1, 2, 3, 4))
		c.requireAttests(t, label, pub, gIDs, "fast")
		t.Log("a malicious leader chose the dealer set, which gives it some influence over the key")
	})

	t.Run("buffered events still attest when new setup is impossible", func(t *testing.T) {
		labelA, outsA := c.setup(t, 1, gIDs, nil)
		pubA := c.requireCertified(t, outsA, gIDs)
		labelB, outsB := c.setup(t, 2, gIDs, nil)
		pubB := c.requireCertified(t, outsB, gIDs)
		online := fsWithout(5, 6, 7)
		_, failed := c.setup(t, 1, online, nil)
		fsNotCertified(t, failed)
		c.requireAttests(t, labelA, pubA, online, "slow")
		c.requireAttests(t, labelB, pubB, online, "slow")
	})

	t.Run("a bad share to an offline member leaves it unable to sign", func(t *testing.T) {
		online := fsWithout(6)
		label, outs := c.setup(t, 1, online, map[int]string{7: "bad-share-offline"})
		pub := c.requireCertified(t, outs, online)
		late := c.run(t, "catchup", label, 1, fsOnly(6), nil, 25*time.Second)
		require.True(t, late[6].Certified, "member 6 still learns the public keys")
		require.False(t, late[6].HasShare, "documented gap: no share recovery")
		c.requireAttests(t, label, pub, online, "fast")
		t.Log("member 6 cannot sign this event: share recovery is not built")
	})
}
