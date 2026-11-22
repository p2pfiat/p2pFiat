package p2pfiatcost

// Experiment 10: stronger key generation for the 4-of-7 nostr oracle.
//
// In experiment 9 the public key parts were visible before the dealer set was
// fixed, so a leader or dealer could steer the key. This follows the two-phase
// design of Gennaro, Jarecki, Krawczyk and Rabin:
//
//  1. Dealers publish hiding Pedersen commitments. Five members certify the set.
//  2. Only then do dealers reveal their public key parts. A dealer that withholds
//     or lies is opened from its shares, so backing out cannot change the key.
//
// Opening is itself guarded. Members open only the exact dealer set that 5 members
// voted for, and at least 3 dealers must stay unopened. A relay outage therefore
// cannot make honest members publish enough shares to expose the key.
//
// Seven OS processes communicate through three local strfry relays. This is a
// research prototype and has not had a cryptographic review.
//
// Needs the test files of experiments 5 to 9. Copy all six into arkd's
// internal/test/p2pfiatcost directory and run:
//   go test -v -count 5 -timeout 3500s -run '^TestP2pFiatStrongerKeygen$' ./internal/test/p2pfiatcost

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	pdEnv         = "P2PFIAT_PEDERSEN_MEMBER"
	pdLine        = "P2PFIATP:"
	pdMinUnopened = 3
	pdDealMs      = 2000
	pdProposeMs   = 4500
	pdRevealMs    = 5500
	pdEvidenceMs  = 7000
	pdOpenVoteMs  = 8500
	pdFailMs      = 16000
	pdCatchupMs   = 14000
)

// pdH is a second generator with no known discrete log relative to G.
var pdH = func() btcec.JacobianPoint {
	for ctr := 0; ; ctr++ {
		h := sha256.Sum256([]byte(fmt.Sprintf("p2pfiat/pedersen-h/%d", ctr)))
		pub, err := btcec.ParsePubKey(append([]byte{2}, h[:]...))
		if err != nil {
			continue
		}
		var p btcec.JacobianPoint
		pub.AsJacobian(&p)
		return p
	}
}()

func pdCommit(a, b *btcec.ModNScalar) btcec.JacobianPoint {
	x := thrMulG(a)
	y := thrMul(b, &pdH)
	return thrAdd(&x, &y)
}

func pdEval(c []btcec.ModNScalar, j int) btcec.ModNScalar {
	x := thrScalar(j)
	v := c[len(c)-1]
	for k := len(c) - 2; k >= 0; k-- {
		v.Mul(&x)
		v.Add(&c[k])
	}
	return v
}

// pdInterpolate recovers polynomial coefficients from exactly gT points.
func pdInterpolate(points map[int]btcec.ModNScalar) []btcec.ModNScalar {
	var xs []int
	for x := range points {
		xs = append(xs, x)
	}
	slices.Sort(xs)
	xs = xs[:gT]
	out := make([]btcec.ModNScalar, gT)
	for _, xi := range xs {
		basis := []btcec.ModNScalar{thrScalar(1)}
		denom := thrScalar(1)
		for _, xj := range xs {
			if xj == xi {
				continue
			}
			neg := thrScalar(xj)
			neg.Negate()
			next := make([]btcec.ModNScalar, len(basis)+1)
			for k := range basis {
				v := basis[k]
				next[k+1].Add(&v)
				v.Mul(&neg)
				next[k].Add(&v)
			}
			basis = next
			d := thrScalar(xi)
			d.Add(&neg)
			denom.Mul(&d)
		}
		denom.InverseNonConst()
		y := points[xi]
		y.Mul(&denom)
		for k := range basis {
			v := basis[k]
			v.Mul(&y)
			out[k].Add(&v)
		}
	}
	return out
}

type pdCmd struct {
	Op       string
	Label    string
	Leader   int
	GoMs     int64
	Behavior string
	Own      uint32
}

type pdOutput struct {
	Op            string
	Label         string
	Error         string
	Certified     bool
	Final         bool
	HasShare      bool
	Transcript    string
	Qual          []int
	Opened        []int
	LongPx        string
	EventPx       string
	Rx            []string
	CertMsg       string
	Cert          string
	Attested      bool
	AttestAtMs    int64
	Price         uint32
	VotedFor      string
	SawProposals  int
	Complaints    int
	Answers       int
	OpenVoted     bool
	OpenShares    int
	BadEvidence   int
	RevealsSeen   int
	TrueA0        string
	Contributions map[int]string
}

type pdDeal struct {
	from    int
	id      string
	w       nsWire
	commits [][]btcec.JacobianPoint
	valid   bool
	checked bool
	mine    []btcec.ModNScalar
}

type pdReveal struct {
	id      string
	from    int
	deal    string
	commits [][]btcec.JacobianPoint
}

type pdOpenVote struct {
	hash    string
	opened  []string
	reveals []string
}

func pdCheckDeal(m nsMsg, instances int) *pdDeal {
	rec := &pdDeal{from: m.from, id: m.id, w: m.w}
	if len(m.w.Commits) != instances {
		return rec
	}
	c, ok := pdParseCommits(m.w.Commits, instances)
	if !ok {
		return rec
	}
	rec.commits, rec.valid = c, true
	return rec
}

func pdParseCommits(raw [][]string, instances int) ([][]btcec.JacobianPoint, bool) {
	if len(raw) != instances {
		return nil, false
	}
	out := make([][]btcec.JacobianPoint, instances)
	for inst := range raw {
		if len(raw[inst]) != gT {
			return nil, false
		}
		for _, v := range raw[inst] {
			p, err := nsParsePoint(v)
			if err != nil {
				return nil, false
			}
			out[inst] = append(out[inst], p)
		}
	}
	return out, true
}

// pdCheckPair verifies a (share, blind) pair against the Pedersen commitments.
func pdCheckPair(rec *pdDeal, j int, pair []btcec.ModNScalar) bool {
	n := len(rec.commits)
	if !rec.valid || len(pair) != 2*n {
		return false
	}
	for inst := range n {
		got := pdCommit(&pair[inst], &pair[n+inst])
		want := thrEvalCommit(rec.commits[inst], j)
		if !thrEqual(&got, &want) {
			return false
		}
	}
	return true
}

func pdMatchesReveal(commits [][]btcec.JacobianPoint, j int, pair []btcec.ModNScalar) bool {
	for inst := range commits {
		got := thrMulG(&pair[inst])
		want := thrEvalCommit(commits[inst], j)
		if !thrEqual(&got, &want) {
			return false
		}
	}
	return true
}

func pdHex(v []btcec.ModNScalar) []string {
	out := make([]string, len(v))
	for i := range v {
		out[i] = nsScalarHex(&v[i])
	}
	return out
}

func pdOpenHash(transcript string, opened, reveals []string) string {
	h := sha256.New()
	h.Write([]byte("p2pfiat/open-vote"))
	h.Write([]byte(transcript))
	for _, v := range opened {
		h.Write([]byte("|o:" + v))
	}
	for _, v := range reveals {
		h.Write([]byte("|r:" + v))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// pdSetup is one member's run of one setup attempt.
type pdSetup struct {
	t         testing.TB
	n         *nsNode
	id        int
	instances int
	leader    int
	behavior  string
	passive   bool
	long      *thrKey

	deals       map[string]*pdDeal
	byDealer    map[int][]string
	complaints  map[string]map[int]bool
	complained  map[string]bool
	answered    map[string]bool
	answers     map[string]map[int][]btcec.ModNScalar
	pending     []nsMsg
	proposals   [][]string
	votes       map[int]string
	badVoters   map[int]bool
	certParts   []nsMsg
	truePairs   map[int][]string
	coeffs      [][]btcec.ModNScalar
	ownDeal     string
	voted       bool
	proposed    bool
	transcript  string
	qualIDs     []string
	revealed    bool
	reveals     map[string]map[string]*pdReveal
	revealByID  map[string]*pdReveal
	evidence    []nsMsg
	sentProof   map[string]bool
	proven      map[string]bool
	badEvidence map[string]bool
	openVotes   map[int]pdOpenVote
	badOpeners  map[int]bool
	openVoted   bool
	opening     []string
	openReveals []string
	openDecided bool
	openSent    bool
	openMsgs    []nsMsg
	opens       map[string]map[int][]btcec.ModNScalar
}

func (s *pdSetup) ingest(m nsMsg) {
	switch m.w.Type {
	case "pd-deal":
		if _, ok := s.deals[m.id]; !ok {
			s.deals[m.id] = pdCheckDeal(m, s.instances)
			s.byDealer[m.from] = append(s.byDealer[m.from], m.id)
		}
	case "pd-complaint":
		if s.complaints[m.w.Hash] == nil {
			s.complaints[m.w.Hash] = map[int]bool{}
		}
		s.complaints[m.w.Hash][m.from] = true
	case "pd-answer":
		s.pending = append(s.pending, m)
	case "pd-proposal":
		if m.from == s.leader {
			s.proposals = append(s.proposals, m.w.S)
		}
	case "pd-vote":
		if old, ok := s.votes[m.from]; ok && old != m.w.Hash {
			s.badVoters[m.from] = true
		} else {
			s.votes[m.from] = m.w.Hash
		}
	case "pd-reveal":
		if s.revealByID[m.id] != nil {
			return
		}
		c, ok := pdParseCommits(m.w.Commits, s.instances)
		if !ok {
			return
		}
		r := &pdReveal{id: m.id, from: m.from, deal: m.w.Hash, commits: c}
		s.revealByID[m.id] = r
		if s.reveals[m.w.Hash] == nil {
			s.reveals[m.w.Hash] = map[string]*pdReveal{}
		}
		s.reveals[m.w.Hash][m.id] = r
	case "pd-evidence":
		s.evidence = append(s.evidence, m)
	case "pd-openvote":
		h := pdOpenHash(m.w.Hash, m.w.S, m.w.R)
		if old, ok := s.openVotes[m.from]; ok && old.hash != h {
			s.badOpeners[m.from] = true
		} else if m.w.Hash == s.transcript || s.transcript == "" {
			s.openVotes[m.from] = pdOpenVote{hash: h, opened: m.w.S, reveals: m.w.R}
		}
	case "pd-open":
		s.openMsgs = append(s.openMsgs, m)
	case "pd-certpart":
		s.certParts = append(s.certParts, m)
	}
}

func (s *pdSetup) resolveAnswers() {
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
		pair, err := fsParseScalars(m.w.S)
		if err != nil || !pdCheckPair(rec, int(m.w.Price), pair) {
			continue
		}
		if s.answers[rec.id] == nil {
			s.answers[rec.id] = map[int][]btcec.ModNScalar{}
		}
		s.answers[rec.id][int(m.w.Price)] = pair
	}
	s.pending = keep
}

func (s *pdSetup) myPair(rec *pdDeal) []btcec.ModNScalar {
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
			pair, err := fsParseScalars(v)
			if err == nil && pdCheckPair(rec, s.id, pair) {
				rec.mine = pair
			}
		}()
	}
	if rec.mine != nil {
		return rec.mine
	}
	return s.answers[rec.id][s.id]
}

func (s *pdSetup) unresolved(rec *pdDeal) bool {
	for complainer := range s.complaints[rec.id] {
		if s.answers[rec.id][complainer] == nil {
			return true
		}
	}
	return false
}

func (s *pdSetup) dealerOf(id string) int {
	if rec := s.deals[id]; rec != nil {
		return rec.from
	}
	return 0
}

func (s *pdSetup) qualified() []string {
	var out []string
	for _, d := range gIDs {
		ids := s.byDealer[d]
		if len(ids) != 1 {
			continue
		}
		if rec := s.deals[ids[0]]; rec.valid && !s.unresolved(rec) {
			out = append(out, rec.id)
		}
	}
	return out
}

func (s *pdSetup) acceptable(ids []string) bool {
	if len(ids) < gT {
		return false
	}
	dealers := map[int]bool{}
	for _, id := range ids {
		rec := s.deals[id]
		if rec == nil || !rec.valid || dealers[rec.from] || s.unresolved(rec) || s.myPair(rec) == nil {
			return false
		}
		dealers[rec.from] = true
	}
	return true
}

func pdMakeDeal(t testing.TB, n *nsNode, instances, corrupt int) (
	nsWire, map[int][]string, [][]btcec.ModNScalar, error,
) {
	w := nsWire{Type: "pd-deal", Shares: map[int]string{}}
	coeffs := make([][]btcec.ModNScalar, instances)
	blinds := make([][]btcec.ModNScalar, instances)
	for inst := range instances {
		var line []string
		for range gT {
			a, b := thrRandom(t), thrRandom(t)
			coeffs[inst] = append(coeffs[inst], a)
			blinds[inst] = append(blinds[inst], b)
			c := pdCommit(&a, &b)
			line = append(line, nsPointHex(&c))
		}
		w.Commits = append(w.Commits, line)
	}
	honest := map[int][]string{}
	for _, j := range gIDs {
		pair := make([]btcec.ModNScalar, 2*instances)
		for inst := range instances {
			pair[inst] = pdEval(coeffs[inst], j)
			pair[instances+inst] = pdEval(blinds[inst], j)
		}
		honest[j] = pdHex(pair)
		if j == corrupt {
			one := thrScalar(1)
			pair[0].Add(&one)
		}
		body, err := json.Marshal(pdHex(pair))
		if err != nil {
			return w, nil, nil, err
		}
		key, err := nip44.GenerateConversationKey(n.cfg.Roster[j], n.cfg.SK)
		if err != nil {
			return w, nil, nil, err
		}
		if w.Shares[j], err = nip44.Encrypt(string(body), key); err != nil {
			return w, nil, nil, err
		}
	}
	return w, honest, coeffs, nil
}

func (s *pdSetup) deal() error {
	corrupt := 0
	switch s.behavior {
	case "bad-share", "bad-share-answer":
		corrupt = 1
	case "silent-dealer":
		return nil
	}
	first, pairs, coeffs, err := pdMakeDeal(s.t, s.n, s.instances, corrupt)
	if err != nil {
		return err
	}
	s.truePairs, s.coeffs = pairs, coeffs
	if s.behavior == "two-deals" {
		second, _, _, err := pdMakeDeal(s.t, s.n, s.instances, 0)
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

func (s *pdSetup) complain() error {
	for id, rec := range s.deals {
		if s.complained[id] || rec.from == s.id {
			continue
		}
		bad := rec.valid && s.myPair(rec) == nil
		if s.behavior == "false-complaint" && rec.valid {
			bad = true
		}
		s.complained[id] = true
		if bad {
			if err := s.n.send(nsWire{Type: "pd-complaint", Hash: id}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *pdSetup) answer() error {
	if s.behavior == "bad-share" || s.truePairs == nil {
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
				Type: "pd-answer", Hash: id, Price: uint32(complainer), S: s.truePairs[complainer],
			})
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *pdSetup) propose() error {
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
			if err := s.n.send(nsWire{Type: "pd-proposal", S: set}, relay); err != nil {
				return err
			}
			h := fsTranscript(s.n.cfg.Session, set, s.dealerOf)
			if err := s.n.send(nsWire{Type: "pd-vote", Hash: h}, relay); err != nil {
				return err
			}
		}
		return nil
	}
	if len(ids) < gT {
		return nil
	}
	return s.n.send(nsWire{Type: "pd-proposal", S: ids})
}

func (s *pdSetup) tryVote() error {
	for _, ids := range s.proposals {
		if !s.acceptable(ids) {
			continue
		}
		s.voted = true
		h := fsTranscript(s.n.cfg.Session, ids, s.dealerOf)
		s.votes[s.id] = h
		return s.n.send(nsWire{Type: "pd-vote", Hash: h})
	}
	return nil
}

func (s *pdSetup) certified() (string, []string) {
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

// reveal publishes this dealer's public key parts, after the dealer set is fixed.
func (s *pdSetup) reveal() error {
	s.revealed = true
	var own string
	for _, id := range s.qualIDs {
		if s.deals[id].from == s.id {
			own = id
		}
	}
	s.ownDeal = own
	if own == "" || s.coeffs == nil {
		return nil
	}
	switch s.behavior {
	case "withhold", "withhold-noopen":
		return nil
	}
	build := func(shift bool) nsWire {
		w := nsWire{Type: "pd-reveal", Hash: own}
		for inst := range s.coeffs {
			var line []string
			for k := range s.coeffs[inst] {
				v := s.coeffs[inst][k]
				if shift && k == 0 {
					one := thrScalar(1)
					v.Add(&one)
				}
				p := thrMulG(&v)
				line = append(line, nsPointHex(&p))
			}
			w.Commits = append(w.Commits, line)
		}
		return w
	}
	switch s.behavior {
	case "wrong-reveal":
		return s.n.send(build(true))
	case "two-reveals":
		if err := s.n.send(build(false), 0); err != nil {
			return err
		}
		return s.n.send(build(true), 1, 2)
	}
	return s.n.send(build(false))
}

func (s *pdSetup) sendEvidence() error {
	for _, id := range s.qualIDs {
		rec := s.deals[id]
		if rec.from == s.id {
			continue
		}
		pair := s.myPair(rec)
		for rid, r := range s.reveals[id] {
			if s.sentProof[rid] || pair == nil {
				continue
			}
			send := slices.Clone(pair)
			switch {
			case s.behavior == "false-evidence":
				one := thrScalar(1)
				send[0].Add(&one)
			case pdMatchesReveal(r.commits, s.id, pair):
				continue
			}
			s.sentProof[rid] = true
			if err := s.n.send(nsWire{Type: "pd-evidence", Hash: rid, S: pdHex(send)}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *pdSetup) resolveEvidence() {
	var keep []nsMsg
	for _, m := range s.evidence {
		r := s.revealByID[m.w.Hash]
		if r == nil {
			keep = append(keep, m)
			continue
		}
		rec := s.deals[r.deal]
		if rec == nil {
			keep = append(keep, m)
			continue
		}
		pair, err := fsParseScalars(m.w.S)
		if err != nil || !pdCheckPair(rec, m.from, pair) || pdMatchesReveal(r.commits, m.from, pair) {
			s.badEvidence[m.id] = true
			continue
		}
		s.proven[r.deal] = true
	}
	s.evidence = keep
}

// badDealers lists certified dealers whose public parts cannot be trusted as revealed.
func (s *pdSetup) badDealers() []string {
	var bad []string
	for _, id := range s.qualIDs {
		rs := s.reveals[id]
		isBad := len(rs) != 1 || s.proven[id]
		if !isBad {
			rec := s.deals[id]
			if pair := s.myPair(rec); pair != nil {
				for _, r := range rs {
					isBad = !pdMatchesReveal(r.commits, s.id, pair)
				}
			}
		}
		if isBad {
			bad = append(bad, id)
		}
	}
	slices.Sort(bad)
	return bad
}

func (s *pdSetup) sendOpenVote() error {
	s.openVoted = true
	if s.behavior == "abort-after-reveal" {
		return nil
	}
	bad := s.badDealers()
	if s.behavior == "false-openvote" {
		bad = nil
		for _, id := range s.qualIDs {
			if s.deals[id].from != s.id {
				bad = []string{id}
				break
			}
		}
	}
	// Never help open so many dealers that fewer than 3 stay secret.
	if len(s.qualIDs)-len(bad) < pdMinUnopened {
		return nil
	}
	var reveals []string
	for _, id := range s.qualIDs {
		if slices.Contains(bad, id) {
			continue
		}
		if len(s.reveals[id]) != 1 {
			return nil
		}
		for rid := range s.reveals[id] {
			reveals = append(reveals, rid)
		}
	}
	slices.Sort(reveals)
	s.openVotes[s.id] = pdOpenVote{
		hash: pdOpenHash(s.transcript, bad, reveals), opened: bad, reveals: reveals,
	}
	return s.n.send(nsWire{Type: "pd-openvote", Hash: s.transcript, S: bad, R: reveals})
}

func (s *pdSetup) decideOpen() bool {
	count := map[string]int{}
	var pick *pdOpenVote
	for voter, v := range s.openVotes {
		if s.badOpeners[voter] {
			continue
		}
		count[v.hash]++
		if count[v.hash] >= fsCertVotes {
			copied := v
			pick = &copied
		}
	}
	if pick == nil || len(s.qualIDs)-len(pick.opened) < pdMinUnopened {
		return false
	}
	if pdOpenHash(s.transcript, pick.opened, pick.reveals) != pick.hash {
		return false
	}
	covered := map[string]bool{}
	for _, id := range pick.opened {
		if !slices.Contains(s.qualIDs, id) || covered[id] {
			return false
		}
		covered[id] = true
	}
	for _, rid := range pick.reveals {
		r := s.revealByID[rid]
		if r == nil || !slices.Contains(s.qualIDs, r.deal) || covered[r.deal] {
			return false
		}
		if rec := s.deals[r.deal]; rec == nil || rec.from != r.from {
			return false
		}
		covered[r.deal] = true
	}
	if len(covered) != len(s.qualIDs) {
		return false
	}
	s.opening, s.openReveals, s.openDecided = pick.opened, pick.reveals, true
	return true
}

func (s *pdSetup) resolveOpens() {
	var keep []nsMsg
	for _, m := range s.openMsgs {
		rec := s.deals[m.w.Hash]
		if rec == nil {
			keep = append(keep, m)
			continue
		}
		pair, err := fsParseScalars(m.w.S)
		if err != nil || !pdCheckPair(rec, m.from, pair) {
			continue
		}
		if s.opens[rec.id] == nil {
			s.opens[rec.id] = map[int][]btcec.ModNScalar{}
		}
		s.opens[rec.id][m.from] = pair
	}
	s.openMsgs = keep
}

// publicParts returns every certified dealer's public polynomial, or nil while opening.
func (s *pdSetup) publicParts() map[string][][]btcec.JacobianPoint {
	parts := map[string][][]btcec.JacobianPoint{}
	for _, rid := range s.openReveals {
		r := s.revealByID[rid]
		parts[r.deal] = r.commits
	}
	for _, id := range s.opening {
		if len(s.opens[id]) < gT {
			return nil
		}
		commits := make([][]btcec.JacobianPoint, s.instances)
		for inst := range s.instances {
			points := map[int]btcec.ModNScalar{}
			for j, pair := range s.opens[id] {
				points[j] = pair[inst]
			}
			for _, c := range pdInterpolate(points) {
				commits[inst] = append(commits[inst], thrMulG(&c))
			}
		}
		parts[id] = commits
	}
	return parts
}

func (s *pdSetup) finalize(parts map[string][][]btcec.JacobianPoint) ([]*thrKey, []int, bool) {
	qual := make([]int, 0, len(s.qualIDs))
	hasShare := true
	for _, id := range s.qualIDs {
		rec := s.deals[id]
		qual = append(qual, rec.from)
		pair := s.myPair(rec)
		hasShare = hasShare && pair != nil && pdMatchesReveal(parts[id], s.id, pair)
	}
	slices.Sort(qual)
	keys := make([]*thrKey, s.instances)
	for inst := range s.instances {
		var sum []btcec.JacobianPoint
		var share btcec.ModNScalar
		for _, id := range s.qualIDs {
			if sum == nil {
				sum = slices.Clone(parts[id][inst])
			} else {
				for k := range sum {
					sum[k] = thrAdd(&sum[k], &parts[id][inst][k])
				}
			}
			if hasShare {
				v := s.myPair(s.deals[id])[inst]
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

type pdResult struct {
	out   *pdOutput
	keys  []*thrKey
	event *thrEvent
}

func (s *pdSetup) step(now int64) error {
	if s.passive {
		return nil
	}
	if now >= pdDealMs {
		if err := s.complain(); err != nil {
			return err
		}
	}
	if err := s.answer(); err != nil {
		return err
	}
	if s.id == s.leader && !s.proposed && now >= pdProposeMs {
		if err := s.propose(); err != nil {
			return err
		}
	}
	if !s.voted && now >= pdProposeMs {
		if err := s.tryVote(); err != nil {
			return err
		}
	}
	if s.transcript == "" {
		return nil
	}
	if !s.revealed && now >= pdRevealMs {
		if err := s.reveal(); err != nil {
			return err
		}
	}
	if now >= pdEvidenceMs {
		if err := s.sendEvidence(); err != nil {
			return err
		}
	}
	if !s.openVoted && now >= pdOpenVoteMs {
		if err := s.sendOpenVote(); err != nil {
			return err
		}
	}
	// Publish shares only for the exact dealer set that 5 members voted to open.
	if s.openDecided && !s.openSent {
		s.openSent = true
		if s.behavior == "withhold-noopen" {
			return nil
		}
		for _, id := range s.opening {
			rec := s.deals[id]
			if rec.from == s.id {
				continue
			}
			if pair := s.myPair(rec); pair != nil {
				if err := s.n.send(nsWire{Type: "pd-open", Hash: id, S: pdHex(pair)}); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (s *pdSetup) evidenceOut(out *pdOutput) {
	out.VotedFor, out.SawProposals, out.OpenVoted = s.votes[s.id], len(s.proposals), s.openVoted
	out.BadEvidence, out.RevealsSeen = len(s.badEvidence), len(s.reveals)
	for _, who := range s.complaints {
		out.Complaints += len(who)
	}
	for _, who := range s.answers {
		out.Answers += len(who)
	}
	for _, who := range s.opens {
		out.OpenShares += len(who)
	}
	if s.coeffs != nil {
		p := thrMulG(&s.coeffs[fsInstKey][0])
		out.TrueA0 = nsPointHex(&p)
	}
}

func (s *pdSetup) run(goAt time.Time, limitMs int64) (*pdResult, error) {
	out := &pdOutput{}
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
	certSent := false
	good := map[int]btcec.ModNScalar{}
	for {
		msgs := s.n.take(50 * time.Millisecond)
		now := time.Since(goAt).Milliseconds()
		if now >= limitMs {
			s.evidenceOut(out)
			return &pdResult{out: out}, nil
		}
		for _, m := range msgs {
			s.ingest(m)
		}
		s.resolveAnswers()
		s.resolveEvidence()
		s.resolveOpens()
		if s.transcript == "" {
			if h, ids := s.certified(); h != "" {
				s.transcript, s.qualIDs = h, ids
				out.Certified, out.Transcript = true, h
				for v, o := range s.openVotes {
					if pdOpenHash(h, o.opened, o.reveals) != o.hash {
						delete(s.openVotes, v)
					}
				}
			}
		}
		if s.transcript != "" && !s.openDecided {
			s.decideOpen()
		}
		if err := s.step(now); err != nil {
			return nil, err
		}
		if keys == nil {
			if !s.openDecided {
				continue
			}
			parts := s.publicParts()
			if parts == nil {
				continue
			}
			var qual []int
			keys, qual, out.HasShare = s.finalize(parts)
			out.Final, out.Qual = true, qual
			out.Contributions = map[int]string{}
			for _, id := range s.qualIDs {
				out.Contributions[s.deals[id].from] = nsPointHex(&parts[id][fsInstKey][0])
			}
			for _, id := range s.opening {
				out.Opened = append(out.Opened, s.deals[id].from)
			}
			slices.Sort(out.Opened)
			if s.instances == 1 {
				out.LongPx = hex.EncodeToString(thrSer(&keys[0].group)[1:])
				s.evidenceOut(out)
				return &pdResult{out: out, keys: keys}, nil
			}
			event = &thrEvent{key: keys[fsInstKey], ora: &oracle{cache: map[prefix]btcec.JacobianPoint{}}}
			event.px = thrSer(&event.key.group)[1:]
			a := sha256.New()
			a.Write([]byte("p2pfiat/event-announcement"))
			a.Write([]byte(s.n.cfg.Session))
			a.Write([]byte(s.transcript))
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
		if !certSent && !s.passive && out.HasShare {
			certSent = true
			v := certC
			x := s.long.shares[s.id]
			v.Mul(&x)
			k := keys[fsInstCert].shares[s.id]
			v.Add(&k)
			err := s.n.send(nsWire{Type: "pd-certpart", Hash: s.transcript, S: []string{nsScalarHex(&v)}})
			if err != nil {
				return nil, err
			}
		}
		for _, m := range s.certParts {
			if m.w.Hash != s.transcript || len(m.w.S) != 1 {
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
		s.evidenceOut(out)
		return &pdResult{out: out, keys: keys, event: event}, nil
	}
}

// TestP2pFiatKeygenMember is the entry point of one member process.
func TestP2pFiatKeygenMember(t *testing.T) {
	raw := os.Getenv(pdEnv)
	if raw == "" {
		t.Skip("started only as a member process by TestP2pFiatStrongerKeygen")
	}
	var cfg nsConfig
	require.NoError(t, json.Unmarshal([]byte(raw), &cfg))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	emit := func(o *pdOutput) {
		body, _ := json.Marshal(o)
		fmt.Fprintf(os.Stdout, "\n%s%s\n", pdLine, body)
	}
	nodes := map[string]*nsNode{}
	closers := map[string]context.CancelFunc{}
	events := map[string]*thrEvent{}
	// Keep one event's connections open. Otherwise every finished event reconnects
	// and replays its history after a relay outage, which delays the next setup.
	node := func(label string) (*nsNode, error) {
		for old, stop := range closers {
			if old != label {
				stop()
				delete(closers, old)
				delete(nodes, old)
			}
		}
		if n := nodes[label]; n != nil {
			return n, nil
		}
		c := cfg
		c.Session = cfg.Session + "/" + label
		c.Behavior = ""
		nodeCtx, stop := context.WithCancel(ctx)
		n, err := nsNewNode(nodeCtx, c)
		if err != nil {
			stop()
			return nil, err
		}
		nodes[label], closers[label] = n, stop
		return n, nil
	}
	var long *thrKey
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<16), 1<<20)
	for sc.Scan() {
		var cmd pdCmd
		require.NoError(t, json.Unmarshal(sc.Bytes(), &cmd))
		if cmd.Op == "exit" {
			return
		}
		out := &pdOutput{}
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
			s := &pdSetup{
				t: t, n: n, id: cfg.ID, instances: instances, leader: cmd.Leader,
				behavior: cmd.Behavior, passive: cmd.Op == "catchup", long: long,
				deals: map[string]*pdDeal{}, byDealer: map[int][]string{},
				complaints: map[string]map[int]bool{}, complained: map[string]bool{},
				answered: map[string]bool{}, answers: map[string]map[int][]btcec.ModNScalar{},
				votes: map[int]string{}, badVoters: map[int]bool{},
				reveals: map[string]map[string]*pdReveal{}, revealByID: map[string]*pdReveal{},
				sentProof: map[string]bool{}, proven: map[string]bool{}, badEvidence: map[string]bool{},
				openVotes: map[int]pdOpenVote{}, badOpeners: map[int]bool{},
				opens: map[string]map[int][]btcec.ModNScalar{},
			}
			if s.behavior == "leader-two" || s.behavior == "two-reveals" {
				n.noForward.Store(true)
			}
			limit := int64(pdFailMs)
			if s.passive {
				limit = pdCatchupMs
			}
			res, err := s.run(time.UnixMilli(cmd.GoMs), limit)
			if err != nil {
				return err
			}
			out = res.out
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

type pdCluster struct {
	t       *testing.T
	session string
	roster  map[int]string
	stdin   map[int]io.WriteCloser
	procs   map[int]*exec.Cmd
	lines   chan pdMemberLine
	proxies map[[2]int]*nsProxy
	longPx  string
	labels  atomic.Int64
}

type pdMemberLine struct {
	id  int
	out *pdOutput
}

func pdStart(t *testing.T) *pdCluster {
	t.Helper()
	c := &pdCluster{
		t: t, session: fmt.Sprintf("p2pfiat-exp10-%d", time.Now().UnixNano()),
		roster: map[int]string{}, stdin: map[int]io.WriteCloser{}, procs: map[int]*exec.Cmd{},
		lines: make(chan pdMemberLine, 128), proxies: map[[2]int]*nsProxy{},
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
		cmd := exec.Command(os.Args[0], "-test.run", "^TestP2pFiatKeygenMember$", "-test.timeout", "0")
		cmd.Env = append(os.Environ(), pdEnv+"="+string(body))
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
				text, ok := strings.CutPrefix(sc.Text(), pdLine)
				if !ok {
					continue
				}
				o := &pdOutput{}
				if json.Unmarshal([]byte(text), o) == nil {
					c.lines <- pdMemberLine{id: id, out: o}
				}
			}
		}(id)
	}
	genesis := c.run(t, "genesis", "genesis", 1, gIDs, nil, 35*time.Second)
	for _, id := range gIDs {
		require.True(t, genesis[id].Final, "genesis must finish")
		require.Equal(t, genesis[1].LongPx, genesis[id].LongPx)
	}
	c.longPx = genesis[1].LongPx
	return c
}

func (c *pdCluster) label() string {
	return "event-" + strconv.FormatInt(c.labels.Add(1), 10)
}

func (c *pdCluster) run(
	t *testing.T, op, label string, leader int, ids []int, behavior map[int]string, wait time.Duration,
) map[int]*pdOutput {
	t.Helper()
	goMs := time.Now().Add(time.Second).UnixMilli()
	for _, id := range ids {
		body, err := json.Marshal(pdCmd{
			Op: op, Label: label, Leader: leader, GoMs: goMs, Behavior: behavior[id],
			Own: uint32(100_000 + id*10),
		})
		require.NoError(t, err)
		_, err = c.stdin[id].Write(append(body, '\n'))
		require.NoError(t, err)
	}
	out := map[int]*pdOutput{}
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

func (c *pdCluster) setup(
	t *testing.T, leader int, ids []int, behavior map[int]string,
) (string, map[int]*pdOutput) {
	t.Helper()
	label := c.label()
	return label, c.run(t, "setup", label, leader, ids, behavior, 35*time.Second)
}

// requireFinal checks one key set, one set of contributions and a valid certificate.
func (c *pdCluster) requireFinal(t *testing.T, outs map[int]*pdOutput, want []int) *pdOutput {
	t.Helper()
	var pub *pdOutput
	for id, o := range outs {
		require.True(t, o.Final, "member %d must finish", id)
		if pub == nil {
			pub = o
		}
		require.Equal(t, pub.Transcript, o.Transcript, "one transcript")
		require.Equal(t, pub.EventPx, o.EventPx, "one event key")
		require.Equal(t, pub.Rx, o.Rx, "one nonce set")
		require.Equal(t, pub.Qual, o.Qual, "one dealer set")
		require.Equal(t, pub.Opened, o.Opened, "one opened set")
		require.Equal(t, pub.Contributions, o.Contributions, "one set of contributions")
		require.Equal(t, c.longPx, o.LongPx, "same long-term key")
	}
	require.NotNil(t, pub)
	if want != nil {
		require.Equal(t, want, pub.Qual)
	}
	var withCert *pdOutput
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

func pdNotFinal(t *testing.T, outs map[int]*pdOutput) {
	t.Helper()
	for id, o := range outs {
		require.False(t, o.Final, "member %d must not finish", id)
	}
}

func (c *pdCluster) requireAttests(
	t *testing.T, label string, pub *pdOutput, ids []int, path string,
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

// requireOriginal proves the key used the contribution the dealer committed to.
func pdRequireOriginal(t *testing.T, pub *pdOutput, outs map[int]*pdOutput, dealers ...int) {
	t.Helper()
	require.Equal(t, dealers, pub.Opened, "exactly these dealers must be opened")
	for _, d := range dealers {
		require.NotEmpty(t, outs[d].TrueA0)
		require.Equal(t, outs[d].TrueA0, pub.Contributions[d], "dealer %d cannot change its contribution", d)
	}
}

// pdBiasTrial measures how often a leader controlling 2 dealers forces one key bit.
func pdBiasTrial(t *testing.T) (feldman, pedersen bool) {
	bit := func(p *btcec.JacobianPoint) bool { return thrSer(p)[32]&1 == 0 }
	var honest, honestBlind btcec.ModNScalar
	for range gN - 2 {
		a, b := thrRandom(t), thrRandom(t)
		honest.Add(&a)
		honestBlind.Add(&b)
	}
	a6, b6, a7, b7 := thrRandom(t), thrRandom(t), thrRandom(t), thrRandom(t)
	for _, mask := range []int{0, 1, 2, 3} {
		key, blind := honest, honestBlind
		if mask&1 != 0 {
			key.Add(&a6)
			blind.Add(&b6)
		}
		if mask&2 != 0 {
			key.Add(&a7)
			blind.Add(&b7)
		}
		p := thrMulG(&key)
		feldman = feldman || bit(&p)
	}
	// With hiding commitments the leader only sees a blinded sum, so it picks by that.
	for _, mask := range []int{0, 1, 2, 3} {
		key, blind := honest, honestBlind
		if mask&1 != 0 {
			key.Add(&a6)
			blind.Add(&b6)
		}
		if mask&2 != 0 {
			key.Add(&a7)
			blind.Add(&b7)
		}
		visible := pdCommit(&key, &blind)
		if bit(&visible) || mask == 3 {
			p := thrMulG(&key)
			return feldman, bit(&p)
		}
	}
	return feldman, false
}

func TestP2pFiatStrongerKeygen(t *testing.T) {
	if os.Getenv(pdEnv) != "" || os.Getenv(fsEnv) != "" || os.Getenv(nsEnv) != "" {
		t.Skip("member process")
	}

	t.Run("hiding commitments remove the leader's key bias", func(t *testing.T) {
		const trials = 2000
		var f, p int
		for range trials {
			a, b := pdBiasTrial(t)
			if a {
				f++
			}
			if b {
				p++
			}
		}
		fr, pr := float64(f)/trials, float64(p)/trials
		require.Greater(t, fr, 0.91, "the control attack must work on visible key parts")
		require.InDelta(t, 0.5, pr, 0.05, "hidden key parts must leave the bit unbiased")
		t.Logf("leader forces one key bit: visible parts %.1f%%, hidden parts %.1f%% (%d trials)",
			fr*100, pr*100, trials)
	})

	t.Run("opening recovers the committed polynomial", func(t *testing.T) {
		coeffs := make([]btcec.ModNScalar, gT)
		for i := range coeffs {
			coeffs[i] = thrRandom(t)
		}
		points := map[int]btcec.ModNScalar{}
		for _, j := range fsOnly(2, 3, 5, 7) {
			points[j] = pdEval(coeffs, j)
		}
		got := pdInterpolate(points)
		for i := range coeffs {
			require.True(t, got[i].Equals(&coeffs[i]))
		}
	})

	nsStartRelays(t)
	c := pdStart(t)

	t.Run("all 7 online", func(t *testing.T) {
		label, outs := c.setup(t, 1, gIDs, nil)
		pub := c.requireFinal(t, outs, gIDs)
		require.Empty(t, pub.Opened, "no honest dealer may be opened")
		for _, o := range outs {
			require.Zero(t, o.OpenShares)
		}
		at := c.requireAttests(t, label, pub, gIDs, "fast")
		t.Logf("attested %.2f s after the event", float64(at)/1000)
	})

	t.Run("2 offline during setup", func(t *testing.T) {
		online := fsWithout(6, 7)
		label, outs := c.setup(t, 1, online, nil)
		pub := c.requireFinal(t, outs, online)
		require.Empty(t, pub.Opened)
		c.requireAttests(t, label, pub, online, "fast")
	})

	t.Run("3 offline stops new setup safely", func(t *testing.T) {
		_, outs := c.setup(t, 1, fsWithout(5, 6, 7), nil)
		pdNotFinal(t, outs)
		for id, o := range outs {
			require.False(t, o.Certified, "member %d", id)
			require.NotEmpty(t, o.VotedFor, "member %d must vote, so only the 5-vote rule stops it", id)
		}
	})

	t.Run("members that missed setup catch up and sign", func(t *testing.T) {
		label, outs := c.setup(t, 1, fsWithout(6, 7), nil)
		pub := c.requireFinal(t, outs, fsWithout(6, 7))
		late := c.run(t, "catchup", label, 1, fsOnly(6, 7), nil, 25*time.Second)
		for id, o := range late {
			require.True(t, o.Final, "member %d", id)
			require.True(t, o.HasShare, "member %d", id)
			require.Equal(t, pub.EventPx, o.EventPx)
		}
		c.requireAttests(t, label, pub, fsOnly(4, 5, 6, 7), "slow")
	})

	t.Run("a bad share with no answer excludes the dealer", func(t *testing.T) {
		label, outs := c.setup(t, 1, gIDs, map[int]string{7: "bad-share"})
		pub := c.requireFinal(t, outs, fsWithout(7))
		require.GreaterOrEqual(t, outs[1].Complaints, 1)
		require.Zero(t, outs[1].Answers)
		c.requireAttests(t, label, pub, gIDs, "fast")
	})

	t.Run("a dealer that answers a complaint stays in", func(t *testing.T) {
		label, outs := c.setup(t, 1, gIDs, map[int]string{7: "bad-share-answer"})
		pub := c.requireFinal(t, outs, gIDs)
		require.True(t, outs[1].HasShare)
		require.GreaterOrEqual(t, outs[1].Answers, 1)
		c.requireAttests(t, label, pub, fsOnly(1, 2, 3, 4, 5), "fast")
	})

	t.Run("a false complaint cannot exclude honest dealers", func(t *testing.T) {
		label, outs := c.setup(t, 1, gIDs, map[int]string{7: "false-complaint"})
		pub := c.requireFinal(t, outs, gIDs)
		require.GreaterOrEqual(t, outs[1].Complaints, gN-1)
		require.GreaterOrEqual(t, outs[1].Answers, gN-1)
		c.requireAttests(t, label, pub, gIDs, "fast")
	})

	t.Run("silent and two-deal dealers are excluded", func(t *testing.T) {
		label, outs := c.setup(t, 1, gIDs, map[int]string{6: "silent-dealer", 7: "two-deals"})
		pub := c.requireFinal(t, outs, fsWithout(6, 7))
		c.requireAttests(t, label, pub, gIDs, "fast")
	})

	t.Run("a silent leader only costs one attempt", func(t *testing.T) {
		_, first := c.setup(t, 7, gIDs, map[int]string{7: "leader-silent"})
		pdNotFinal(t, first)
		label, second := c.setup(t, 1, gIDs, nil)
		pub := c.requireFinal(t, second, gIDs)
		c.requireAttests(t, label, pub, gIDs, "fast")
	})

	t.Run("a leader cannot include a dealer with an open complaint", func(t *testing.T) {
		_, outs := c.setup(t, 7, gIDs, map[int]string{6: "bad-share", 7: "leader-include"})
		pdNotFinal(t, outs)
		for _, id := range fsOnly(1, 2, 3, 4, 5) {
			require.GreaterOrEqual(t, outs[id].SawProposals, 1, "member %d must see the proposal", id)
			require.Empty(t, outs[id].VotedFor, "member %d must refuse it", id)
		}
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
		require.NotEqual(t, outs[1].VotedFor, outs[4].VotedFor)
		label, retry := c.setup(t, 1, gIDs, nil)
		pub := c.requireFinal(t, retry, gIDs)
		c.requireAttests(t, label, pub, gIDs, "fast")
	})

	t.Run("a dealer that withholds its reveal cannot change the key", func(t *testing.T) {
		label, outs := c.setup(t, 1, gIDs, map[int]string{7: "withhold"})
		pub := c.requireFinal(t, outs, gIDs)
		pdRequireOriginal(t, pub, outs, 7)
		c.requireAttests(t, label, pub, fsWithout(7), "fast")
	})

	t.Run("a dealer that reveals a different key part is opened", func(t *testing.T) {
		label, outs := c.setup(t, 1, gIDs, map[int]string{7: "wrong-reveal"})
		pub := c.requireFinal(t, outs, gIDs)
		pdRequireOriginal(t, pub, outs, 7)
		c.requireAttests(t, label, pub, fsWithout(7), "fast")
	})

	t.Run("a dealer that reveals two key parts is opened", func(t *testing.T) {
		label, outs := c.setup(t, 1, gIDs, map[int]string{7: "two-reveals"})
		pub := c.requireFinal(t, outs, gIDs)
		pdRequireOriginal(t, pub, outs, 7)
		c.requireAttests(t, label, pub, fsWithout(7), "fast")
	})

	t.Run("2 dealers withholding together cannot change the key", func(t *testing.T) {
		label, outs := c.setup(t, 1, gIDs, map[int]string{6: "withhold", 7: "withhold"})
		pub := c.requireFinal(t, outs, gIDs)
		pdRequireOriginal(t, pub, outs, 6, 7)
		c.requireAttests(t, label, pub, fsWithout(6, 7), "fast")
	})

	t.Run("false evidence cannot open an honest dealer", func(t *testing.T) {
		label, outs := c.setup(t, 1, gIDs, map[int]string{7: "false-evidence"})
		pub := c.requireFinal(t, outs, gIDs)
		require.Empty(t, pub.Opened)
		require.Positive(t, outs[1].BadEvidence, "the false evidence must have arrived")
		require.Zero(t, outs[1].OpenShares)
		c.requireAttests(t, label, pub, gIDs, "fast")
	})

	t.Run("2 false open votes cannot open an honest dealer", func(t *testing.T) {
		label, outs := c.setup(t, 1, gIDs, map[int]string{6: "false-openvote", 7: "false-openvote"})
		pub := c.requireFinal(t, outs, gIDs)
		require.Empty(t, pub.Opened)
		for _, id := range fsWithout(6, 7) {
			require.Zero(t, outs[id].OpenShares, "member %d", id)
		}
		c.requireAttests(t, label, pub, fsWithout(6, 7), "fast")
	})

	t.Run("a relay blackout during reveal exposes no shares", func(t *testing.T) {
		block := func(v bool) {
			for _, p := range c.proxies {
				p.setBlocked(v)
			}
		}
		cut := time.AfterFunc(time.Second+5200*time.Millisecond, func() { block(true) })
		heal := time.AfterFunc(time.Second+10500*time.Millisecond, func() { block(false) })
		defer cut.Stop()
		defer heal.Stop()
		_, outs := c.setup(t, 1, gIDs, nil)
		block(false)
		for id, o := range outs {
			require.True(t, o.Certified, "member %d must have certified before the blackout", id)
			require.True(t, o.OpenVoted, "member %d must have reached the open vote", id)
			require.False(t, o.Final, "member %d", id)
			require.Zero(t, o.OpenShares, "member %d: no share of any dealer may be published", id)
		}
		label, retry := c.setup(t, 1, gIDs, nil)
		pub := c.requireFinal(t, retry, gIDs)
		c.requireAttests(t, label, pub, gIDs, "fast")
	})

	t.Run("too few shareholders leaves setup unfinished", func(t *testing.T) {
		_, outs := c.setup(t, 1, fsWithout(6, 7), map[int]string{
			4: "withhold-noopen", 5: "withhold-noopen",
		})
		for _, id := range fsOnly(1, 2, 3) {
			require.True(t, outs[id].Certified, "member %d", id)
			require.False(t, outs[id].Final, "member %d", id)
			require.Equal(t, 6, outs[id].OpenShares, "3 honest members open 2 dealers")
		}
	})

	t.Run("opening never leaves fewer than 3 dealers secret", func(t *testing.T) {
		_, outs := c.setup(t, 7, gIDs, map[int]string{
			7: "leader-exclude", 3: "withhold", 4: "withhold",
		})
		for _, id := range fsOnly(1, 2, 5, 6) {
			require.True(t, outs[id].Certified, "member %d", id)
			require.False(t, outs[id].Final, "member %d", id)
			require.Zero(t, outs[id].OpenShares, "member %d must refuse to open", id)
		}
	})

	t.Run("with all 7 online, 2 members cannot abort after seeing the key", func(t *testing.T) {
		label, outs := c.setup(t, 1, gIDs, map[int]string{6: "abort-after-reveal", 7: "abort-after-reveal"})
		pub := c.requireFinal(t, outs, gIDs)
		require.Empty(t, pub.Opened)
		require.Equal(t, gN, outs[7].RevealsSeen, "the attacker must have seen every key part")
		c.requireAttests(t, label, pub, fsWithout(6, 7), "fast")
	})

	t.Run("documented gap: with 5 online, 1 member can abort after seeing the key", func(t *testing.T) {
		online := fsWithout(6, 7)
		_, outs := c.setup(t, 1, online, map[int]string{5: "abort-after-reveal"})
		require.Equal(t, len(online), outs[5].RevealsSeen, "the attacker must have seen every key part")
		for _, id := range online {
			require.True(t, outs[id].Certified, "member %d", id)
			require.False(t, outs[id].Final, "member %d", id)
			require.Zero(t, outs[id].OpenShares, "member %d", id)
		}
		t.Log("restart bias remains: a member can reject a key it has seen when no spare voter is online")
	})

	t.Run("a leader shrinking the set to 4 still works", func(t *testing.T) {
		label, outs := c.setup(t, 7, gIDs, map[int]string{7: "leader-exclude"})
		pub := c.requireFinal(t, outs, fsOnly(1, 2, 3, 4))
		c.requireAttests(t, label, pub, gIDs, "fast")
	})

	t.Run("buffered events still attest when new setup is impossible", func(t *testing.T) {
		labelA, outsA := c.setup(t, 1, gIDs, nil)
		pubA := c.requireFinal(t, outsA, gIDs)
		online := fsWithout(5, 6, 7)
		_, failed := c.setup(t, 1, online, nil)
		pdNotFinal(t, failed)
		c.requireAttests(t, labelA, pubA, online, "slow")
	})
}
