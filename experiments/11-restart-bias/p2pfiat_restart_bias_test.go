package p2pfiatcost

// Experiment 11: limit restart bias in the 4-of-7 nostr oracle.
//
// In experiment 10 a member could see the revealed key, refuse to vote and force
// a fresh attempt, so it could reject keys it disliked. Here each event slot locks
// to its certified dealer set:
//
//   - A certified slot is never restarted. If finishing is blocked, members resume
//     the same attempt when another member returns, which yields the same key.
//   - Before certification nobody can know the key, so a restart stays allowed. It
//     needs 5 signed abandon messages, and a member that holds a certificate refuses.
//   - At least 5 dealers must be certified. With at most 2 malicious members, at
//     least 3 honest dealers must then reveal before anyone can know the key, which
//     leaves at most 4 members able to sign an abandon message.
//
// Seven OS processes communicate through three local strfry relays. This is a
// research prototype and has not had a cryptographic review.
//
// Needs the test files of experiments 5 to 10. Copy all seven into arkd's
// internal/test/p2pfiatcost directory and run:
//   go test -v -count 5 -timeout 3500s -run '^TestP2pFiatRestartBias$' ./internal/test/p2pfiatcost

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/nbd-wtf/go-nostr"
	"github.com/stretchr/testify/require"
)

const (
	rbEnv        = "P2PFIAT_RESTART_MEMBER"
	rbLine       = "P2PFIATR:"
	rbMinDealers = 5
	rbAbandonMs  = 3000
	rbResumeMs   = 13000
	rbReplayMs   = 1500
)

type rbCmd struct {
	Op       string
	Slot     string
	Attempt  int
	Leader   int
	GoMs     int64
	Behavior string
	Own      uint32
}

type rbOutput struct {
	pdOutput
	Slot         string
	Attempt      int
	Refused      bool
	AbandonCount int
	AbandonCert  bool
	SeenKeyPx    string
}

// rbPrior is what a member remembers about an attempt it took part in.
type rbPrior struct {
	coeffs    [][]btcec.ModNScalar
	revealed  bool
	openVoted bool
}

func rbLabel(slot string, attempt int) string { return fmt.Sprintf("%s-a%d", slot, attempt) }

func rbNewSetup(t testing.TB, n *nsNode, id, instances, leader int, behavior string, long *thrKey) *pdSetup {
	return &pdSetup{
		t: t, n: n, id: id, instances: instances, leader: leader, behavior: behavior, long: long,
		deals: map[string]*pdDeal{}, byDealer: map[int][]string{},
		complaints: map[string]map[int]bool{}, complained: map[string]bool{},
		answered: map[string]bool{}, answers: map[string]map[int][]btcec.ModNScalar{},
		votes: map[int]string{}, badVoters: map[int]bool{},
		reveals: map[string]map[string]*pdReveal{}, revealByID: map[string]*pdReveal{},
		sentProof: map[string]bool{}, proven: map[string]bool{}, badEvidence: map[string]bool{},
		openVotes: map[int]pdOpenVote{}, badOpeners: map[int]bool{},
		opens: map[string]map[int][]btcec.ModNScalar{},
	}
}

// rbSeenKey is the key anyone can compute once every certified dealer has revealed.
func rbSeenKey(s *pdSetup) string {
	if s.transcript == "" {
		return ""
	}
	var sum *btcec.JacobianPoint
	for _, id := range s.qualIDs {
		if len(s.reveals[id]) != 1 {
			return ""
		}
		for _, r := range s.reveals[id] {
			p := r.commits[fsInstKey][0]
			if sum == nil {
				sum = &p
			} else {
				next := thrAdd(sum, &p)
				sum = &next
			}
		}
	}
	return hex.EncodeToString(thrSer(sum)[1:])
}

// rbRun runs one attempt. With resume set it replays the relays and finishes a certified attempt.
func rbRun(s *pdSetup, resume bool, goAt time.Time, limitMs int64) (*pdResult, error) {
	out := &pdOutput{}
	time.Sleep(time.Until(goAt))
	if resume {
		// Shift the clock so that reveal, evidence and open vote follow the replay.
		shift := int64(pdRevealMs - rbReplayMs)
		goAt = goAt.Add(-time.Duration(shift) * time.Millisecond)
		limitMs += shift
		s.proposed, s.voted, s.complained = true, true, map[string]bool{}
	} else if err := s.deal(); err != nil {
		return nil, err
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
		// A dealer set below the minimum can never be voted on or certified.
		s.proposals = slices.DeleteFunc(s.proposals, func(ids []string) bool { return len(ids) < rbMinDealers })
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
		if !certSent && out.HasShare {
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

// rbCollectAbandons publishes this member's abandon message if asked and counts signers.
func rbCollectAbandons(n *nsNode, hash string, send bool, goAt time.Time) (int, error) {
	time.Sleep(time.Until(goAt))
	if send {
		if err := n.send(nsWire{Type: "rb-abandon", Hash: hash}); err != nil {
			return 0, err
		}
	}
	signers := map[int]bool{}
	for time.Since(goAt).Milliseconds() < rbAbandonMs {
		for _, m := range n.take(50 * time.Millisecond) {
			if m.w.Type == "rb-abandon" && m.w.Hash == hash {
				signers[m.from] = true
			}
		}
	}
	return len(signers), nil
}

// TestP2pFiatRestartMember is the entry point of one member process.
func TestP2pFiatRestartMember(t *testing.T) {
	raw := os.Getenv(rbEnv)
	if raw == "" {
		t.Skip("started only as a member process by TestP2pFiatRestartBias")
	}
	var cfg nsConfig
	require.NoError(t, json.Unmarshal([]byte(raw), &cfg))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	emit := func(o *rbOutput) {
		body, _ := json.Marshal(o)
		fmt.Fprintf(os.Stdout, "\n%s%s\n", rbLine, body)
	}
	var current *nsNode
	var currentLabel string
	var stop context.CancelFunc
	node := func(label string, fresh bool) (*nsNode, error) {
		if current != nil && currentLabel == label && !fresh {
			return current, nil
		}
		if stop != nil {
			stop()
		}
		c := cfg
		c.Session = cfg.Session + "/" + label
		c.Behavior = ""
		nodeCtx, cancelNode := context.WithCancel(ctx)
		n, err := nsNewNode(nodeCtx, c)
		if err != nil {
			cancelNode()
			current, stop = nil, nil
			return nil, err
		}
		current, currentLabel, stop = n, label, cancelNode
		return n, nil
	}
	events := map[string]*thrEvent{}
	priors := map[string]*rbPrior{}
	locked := map[string]bool{}
	abandoned := map[string]bool{}
	var long *thrKey
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<16), 1<<20)
	for sc.Scan() {
		var cmd rbCmd
		require.NoError(t, json.Unmarshal(sc.Bytes(), &cmd))
		if cmd.Op == "exit" {
			return
		}
		out := &rbOutput{}
		label := rbLabel(cmd.Slot, cmd.Attempt)
		err := func() error {
			switch cmd.Op {
			case "attest":
				event := events[label]
				if event == nil {
					return errors.New("no key share for this event")
				}
				n, err := node(label, false)
				if err != nil {
					return err
				}
				n.cfg.Own, n.cfg.Behavior, n.cfg.Timing = cmd.Own, "", nsDefaultTiming
				a := &nsOutput{}
				if err := n.attest(&nsState{event: event}, time.UnixMilli(cmd.GoMs), a); err != nil {
					return err
				}
				out.Attested, out.AttestAtMs, out.Price = a.Attested, a.AttestAtMs, a.AttestPrice
				return nil
			case "abandon":
				// A member holding a certificate never helps restart its slot.
				send := !locked[cmd.Slot] || cmd.Behavior == "abandon-anyway"
				out.Refused = !send
				n, err := node(cmd.Slot+"-ctl", true)
				if err != nil {
					return err
				}
				hash := fmt.Sprintf("%s/%d", cmd.Slot, cmd.Attempt)
				count, err := rbCollectAbandons(n, hash, send, time.UnixMilli(cmd.GoMs))
				if err != nil {
					return err
				}
				out.AbandonCount, out.AbandonCert = count, count >= fsCertVotes
				if out.AbandonCert {
					abandoned[hash] = true
				}
				return nil
			}
			resume := cmd.Op == "resume"
			if !resume && cmd.Attempt > 0 &&
				(locked[cmd.Slot] || !abandoned[fmt.Sprintf("%s/%d", cmd.Slot, cmd.Attempt-1)]) {
				out.Refused = true
				return nil
			}
			if !resume && cmd.Attempt == 0 && locked[cmd.Slot] {
				out.Refused = true
				return nil
			}
			n, err := node(label, resume)
			if err != nil {
				return err
			}
			instances := fsEventInstances
			if cmd.Op == "genesis" {
				instances = 1
			}
			s := rbNewSetup(t, n, cfg.ID, instances, cmd.Leader, cmd.Behavior, long)
			if s.behavior == "leader-two" {
				n.noForward.Store(true)
			}
			limit := int64(pdFailMs)
			if resume {
				limit = rbResumeMs
				if p := priors[label]; p != nil {
					s.coeffs, s.revealed, s.openVoted = p.coeffs, p.revealed, p.openVoted
				}
			}
			res, err := rbRun(s, resume, time.UnixMilli(cmd.GoMs), limit)
			if err != nil {
				return err
			}
			_, voted := s.openVotes[s.id]
			priors[label] = &rbPrior{coeffs: s.coeffs, revealed: s.revealed, openVoted: voted}
			if s.transcript != "" {
				locked[cmd.Slot] = true
			}
			out.pdOutput = *res.out
			out.SeenKeyPx = rbSeenKey(s)
			if cmd.Op == "genesis" && res.keys != nil {
				long = res.keys[0]
			}
			if res.event != nil && res.out.HasShare {
				events[label] = res.event
			}
			return nil
		}()
		if err != nil {
			out.Error = err.Error()
		}
		out.Op, out.Label, out.Slot, out.Attempt = cmd.Op, label, cmd.Slot, cmd.Attempt
		emit(out)
	}
}

// Harness.

type rbCluster struct {
	session string
	roster  map[int]string
	stdin   map[int]io.WriteCloser
	procs   map[int]*exec.Cmd
	lines   chan rbMemberLine
	proxies map[[2]int]*nsProxy
	longPx  string
	slots   int
}

type rbMemberLine struct {
	id  int
	out *rbOutput
}

func rbStart(t *testing.T) *rbCluster {
	t.Helper()
	c := &rbCluster{
		session: fmt.Sprintf("p2pfiat-exp11-%d", time.Now().UnixNano()),
		roster:  map[int]string{}, stdin: map[int]io.WriteCloser{}, procs: map[int]*exec.Cmd{},
		lines: make(chan rbMemberLine, 128), proxies: map[[2]int]*nsProxy{},
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
		cmd := exec.Command(os.Args[0], "-test.run", "^TestP2pFiatRestartMember$", "-test.timeout", "0")
		cmd.Env = append(os.Environ(), rbEnv+"="+string(body))
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
				text, ok := strings.CutPrefix(sc.Text(), rbLine)
				if !ok {
					continue
				}
				o := &rbOutput{}
				if json.Unmarshal([]byte(text), o) == nil {
					c.lines <- rbMemberLine{id: id, out: o}
				}
			}
		}(id)
	}
	genesis := c.run(t, "genesis", "genesis", 0, 1, gIDs, nil)
	for _, id := range gIDs {
		require.True(t, genesis[id].Final, "genesis must finish")
		require.Equal(t, genesis[1].LongPx, genesis[id].LongPx)
	}
	c.longPx = genesis[1].LongPx
	return c
}

func (c *rbCluster) slot() string {
	c.slots++
	return fmt.Sprintf("slot-%d", c.slots)
}

func (c *rbCluster) run(
	t *testing.T, op, slot string, attempt, leader int, ids []int, behavior map[int]string,
) map[int]*rbOutput {
	t.Helper()
	goMs := time.Now().Add(time.Second).UnixMilli()
	for _, id := range ids {
		body, err := json.Marshal(rbCmd{
			Op: op, Slot: slot, Attempt: attempt, Leader: leader, GoMs: goMs, Behavior: behavior[id],
			Own: uint32(100_000 + id*10),
		})
		require.NoError(t, err)
		_, err = c.stdin[id].Write(append(body, '\n'))
		require.NoError(t, err)
	}
	out := map[int]*rbOutput{}
	limit := time.After(55 * time.Second)
	for len(out) < len(ids) {
		select {
		case l := <-c.lines:
			if l.out.Slot != slot || l.out.Attempt != attempt || l.out.Op != op {
				continue
			}
			require.Empty(t, l.out.Error, "member %d", l.id)
			out[l.id] = l.out
		case <-limit:
			require.Fail(t, "members did not answer", "%s %s: %d of %d", op, slot, len(out), len(ids))
		}
	}
	return out
}

func (c *rbCluster) requireFinal(t *testing.T, outs map[int]*rbOutput, want []int) *rbOutput {
	t.Helper()
	plain := map[int]*pdOutput{}
	var first *rbOutput
	for id, o := range outs {
		plain[id] = &o.pdOutput
		if first == nil {
			first = o
		}
	}
	(&pdCluster{longPx: c.longPx}).requireFinal(t, plain, want)
	return first
}

func (c *rbCluster) requireAttests(
	t *testing.T, slot string, attempt int, pub *rbOutput, ids []int, path string,
) {
	t.Helper()
	outs := c.run(t, "attest", slot, attempt, 0, ids, nil)
	first := int64(-1)
	for _, o := range outs {
		if o.Attested && (first < 0 || o.AttestAtMs < first) {
			first = o.AttestAtMs
		}
	}
	require.GreaterOrEqual(t, first, int64(0), "members must attest")
	nsRequirePath(t, first, nsDefaultTiming, path)
	events := nsFetchAttestations(t, c.session+"/"+rbLabel(slot, attempt), c.roster)
	require.NotEmpty(t, events, "an outside client must find the attestation")
	public := nsPublicEvent(t, &nsOutput{EventPx: pub.EventPx, Rx: pub.Rx})
	for _, e := range events {
		var w nsWire
		require.NoError(t, json.Unmarshal([]byte(e.Content), &w))
		sigs, err := nsParseDigits(w.S)
		require.NoError(t, err)
		require.True(t, public.allValid(w.Price, sigs), "attestation must verify")
	}
}

// rbRequireNoRestart proves that a certified slot cannot collect an abandon quorum or start again.
func (c *rbCluster) rbRequireNoRestart(t *testing.T, slot string, locked []int, attackers ...int) {
	t.Helper()
	behavior := map[int]string{}
	for _, id := range attackers {
		behavior[id] = "abandon-anyway"
	}
	outs := c.run(t, "abandon", slot, 0, 0, gIDs, behavior)
	for _, id := range locked {
		if !slices.Contains(attackers, id) {
			require.True(t, outs[id].Refused, "member %d holds a certificate and must refuse", id)
		}
	}
	for id, o := range outs {
		require.False(t, o.AbandonCert, "member %d must not see an abandon quorum", id)
		require.Less(t, o.AbandonCount, fsCertVotes, "member %d", id)
	}
	require.Positive(t, outs[attackers[0]].AbandonCount, "the attacker's abandon message must have been sent")
	again := c.run(t, "attempt", slot, 1, 1, gIDs, nil)
	for id, o := range again {
		require.True(t, o.Refused, "member %d must refuse a second attempt", id)
		require.False(t, o.Final, "member %d", id)
	}
}

func (c *rbCluster) requireAbandoned(t *testing.T, slot string, ids []int) {
	t.Helper()
	outs := c.run(t, "abandon", slot, 0, 0, ids, nil)
	for id, o := range outs {
		require.False(t, o.Refused, "member %d", id)
		require.True(t, o.AbandonCert, "member %d must see 5 abandon messages", id)
	}
}

func TestP2pFiatRestartBias(t *testing.T) {
	if os.Getenv(rbEnv) != "" || os.Getenv(pdEnv) != "" || os.Getenv(fsEnv) != "" || os.Getenv(nsEnv) != "" {
		t.Skip("member process")
	}

	t.Run("5 dealers make an abandon quorum impossible once the key is known", func(t *testing.T) {
		// For every attacker set of up to 2 and every certified dealer set, assume all honest
		// dealers revealed. Can 5 members that did not reveal still sign an abandon message?
		holes := map[int]int{}
		cases := 0
		for bad := range 1 << gN {
			if bits.OnesCount(uint(bad)) > 2 {
				continue
			}
			for qual := range 1 << gN {
				q := bits.OnesCount(uint(qual))
				if q < gT {
					continue
				}
				cases++
				revealers := qual &^ bad
				if gN-bits.OnesCount(uint(revealers)) >= fsCertVotes {
					holes[q]++
				}
			}
		}
		require.Positive(t, holes[4], "control: with 4 dealers the restart must remain possible")
		for q := rbMinDealers; q <= gN; q++ {
			require.Zero(t, holes[q], "%d dealers", q)
		}
		t.Logf("checked %d cases: %d restart paths with 4 dealers, 0 with 5 or more", cases, holes[4])
	})

	t.Run("what a restart was worth to an attacker", func(t *testing.T) {
		for _, r := range []int{0, 1, 2, 3, 5} {
			odds := 1 - 1/float64(int(1)<<(r+1))
			t.Logf("force one key bit with %d restarts: %.1f%% before, 50.0%% with locked slots", r, odds*100)
		}
	})

	nsStartRelays(t)
	c := rbStart(t)

	t.Run("all 7 online", func(t *testing.T) {
		slot := c.slot()
		outs := c.run(t, "attempt", slot, 0, 1, gIDs, nil)
		pub := c.requireFinal(t, outs, gIDs)
		require.Empty(t, pub.Opened)
		c.requireAttests(t, slot, 0, pub, gIDs, "fast")
	})

	t.Run("2 offline during setup", func(t *testing.T) {
		slot, online := c.slot(), fsWithout(6, 7)
		outs := c.run(t, "attempt", slot, 0, 1, online, nil)
		pub := c.requireFinal(t, outs, online)
		c.requireAttests(t, slot, 0, pub, online, "fast")
	})

	t.Run("1 member aborting after the reveal gets the same key", func(t *testing.T) {
		slot, online := c.slot(), fsWithout(6, 7)
		outs := c.run(t, "attempt", slot, 0, 1, online, map[int]string{5: "abort-after-reveal"})
		seen := outs[5].SeenKeyPx
		require.NotEmpty(t, seen, "the attacker must have seen the key")
		for _, id := range online {
			require.True(t, outs[id].Certified, "member %d", id)
			require.False(t, outs[id].Final, "member %d", id)
		}
		c.rbRequireNoRestart(t, slot, online, 5, 7)
		voters := fsOnly(1, 2, 3, 4, 6)
		done := c.run(t, "resume", slot, 0, 1, voters, nil)
		pub := c.requireFinal(t, done, online)
		for id, o := range done {
			require.Equal(t, seen, o.EventPx, "member %d must finish with the key the attacker saw", id)
		}
		c.requireAttests(t, slot, 0, pub, voters, "fast")
	})

	t.Run("2 members aborting after the reveal get the same key", func(t *testing.T) {
		slot, online := c.slot(), fsWithout(6, 7)
		outs := c.run(t, "attempt", slot, 0, 1, online, map[int]string{
			4: "abort-after-reveal", 5: "abort-after-reveal",
		})
		seen := outs[5].SeenKeyPx
		require.NotEmpty(t, seen)
		for _, id := range online {
			require.False(t, outs[id].Final, "member %d", id)
		}
		c.rbRequireNoRestart(t, slot, online, 4, 5)
		voters := fsOnly(1, 2, 3, 6, 7)
		done := c.run(t, "resume", slot, 0, 1, voters, nil)
		pub := c.requireFinal(t, done, online)
		for id, o := range done {
			require.Equal(t, seen, o.EventPx, "member %d", id)
		}
		c.requireAttests(t, slot, 0, pub, voters, "fast")
	})

	t.Run("a blocked slot stays unfinished without a replacement key", func(t *testing.T) {
		slot, online := c.slot(), fsWithout(6, 7)
		outs := c.run(t, "attempt", slot, 0, 1, online, map[int]string{5: "abort-after-reveal"})
		require.NotEmpty(t, outs[5].SeenKeyPx)
		c.rbRequireNoRestart(t, slot, online, 5)
		// Without a fifth voter the same key still cannot finish, and no other key exists.
		again := c.run(t, "resume", slot, 0, 1, fsOnly(1, 2, 3, 4), nil)
		for id, o := range again {
			require.False(t, o.Final, "member %d", id)
			require.Equal(t, outs[5].SeenKeyPx, o.SeenKeyPx, "member %d", id)
		}
	})

	t.Run("a silent leader can still be restarted", func(t *testing.T) {
		slot := c.slot()
		first := c.run(t, "attempt", slot, 0, 7, gIDs, map[int]string{7: "leader-silent"})
		for id, o := range first {
			require.False(t, o.Certified, "member %d", id)
			require.Zero(t, o.RevealsSeen, "member %d: nothing may be revealed", id)
		}
		c.requireAbandoned(t, slot, gIDs)
		outs := c.run(t, "attempt", slot, 1, 1, gIDs, nil)
		pub := c.requireFinal(t, outs, gIDs)
		c.requireAttests(t, slot, 1, pub, gIDs, "fast")
	})

	t.Run("a split with a two-faced leader can be restarted", func(t *testing.T) {
		slot := c.slot()
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
		first := c.run(t, "attempt", slot, 0, 7, gIDs, map[int]string{7: "leader-two"})
		for _, p := range c.proxies {
			p.setBlocked(false)
		}
		for id, side := range sides {
			require.False(t, first[id].Certified, "member %d", id)
			require.NotEmpty(t, first[id].VotedFor, "member %d must vote", id)
			require.Equal(t, first[fsOnly(1, 4)[side]].VotedFor, first[id].VotedFor)
			require.Zero(t, first[id].RevealsSeen, "member %d", id)
		}
		require.NotEqual(t, first[1].VotedFor, first[4].VotedFor)
		c.requireAbandoned(t, slot, gIDs)
		outs := c.run(t, "attempt", slot, 1, 1, gIDs, nil)
		pub := c.requireFinal(t, outs, gIDs)
		c.requireAttests(t, slot, 1, pub, gIDs, "fast")
	})

	t.Run("a leader cannot certify only 4 dealers", func(t *testing.T) {
		slot := c.slot()
		first := c.run(t, "attempt", slot, 0, 7, gIDs, map[int]string{7: "leader-exclude"})
		for id, o := range first {
			require.False(t, o.Certified, "member %d", id)
			require.Empty(t, o.VotedFor, "member %d must refuse", id)
			require.Zero(t, o.RevealsSeen, "member %d", id)
		}
		c.requireAbandoned(t, slot, gIDs)
		outs := c.run(t, "attempt", slot, 1, 1, gIDs, nil)
		pub := c.requireFinal(t, outs, gIDs)
		c.requireAttests(t, slot, 1, pub, gIDs, "fast")
	})

	t.Run("1 bad dealer with 5 online costs an attempt", func(t *testing.T) {
		slot, online := c.slot(), fsWithout(6, 7)
		first := c.run(t, "attempt", slot, 0, 1, online, map[int]string{5: "bad-share"})
		for id, o := range first {
			require.False(t, o.Certified, "member %d: only 4 good dealers remain", id)
			require.Zero(t, o.RevealsSeen, "member %d", id)
		}
		retry := fsOnly(1, 2, 3, 4, 6)
		c.requireAbandoned(t, slot, retry)
		outs := c.run(t, "attempt", slot, 1, 1, retry, nil)
		pub := c.requireFinal(t, outs, retry)
		c.requireAttests(t, slot, 1, pub, retry, "fast")
	})

	t.Run("an abandon quorum from another slot does not count", func(t *testing.T) {
		a, b := c.slot(), c.slot()
		first := c.run(t, "attempt", a, 0, 7, gIDs, map[int]string{7: "leader-silent"})
		for id, o := range first {
			require.False(t, o.Certified, "member %d", id)
		}
		c.requireAbandoned(t, a, gIDs)
		outs := c.run(t, "attempt", b, 1, 1, gIDs, nil)
		for id, o := range outs {
			require.True(t, o.Refused, "member %d must refuse", id)
		}
	})

	t.Run("a prepared event attests while another slot is blocked", func(t *testing.T) {
		ready := c.slot()
		outs := c.run(t, "attempt", ready, 0, 1, gIDs, nil)
		pub := c.requireFinal(t, outs, gIDs)
		blocked, online := c.slot(), fsWithout(6, 7)
		stuck := c.run(t, "attempt", blocked, 0, 1, online, map[int]string{5: "abort-after-reveal"})
		for id, o := range stuck {
			require.False(t, o.Final, "member %d", id)
		}
		c.requireAttests(t, ready, 0, pub, fsOnly(1, 2, 3, 4), "slow")
	})
}
