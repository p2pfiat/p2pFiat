package p2pfiatcost

// Experiment 12: durable slot locks and crash recovery for the 4-of-7 nostr oracle.
//
// Experiment 11 kept its locks in memory. Here a guard sits between each member's
// protocol logic and the relays:
//
//   - Every outgoing event is signed, appended to a checksummed journal and flushed
//     to disk before any relay can see it. A restart republishes the same event.
//   - A member can publish only one value per protocol step. A restarted member
//     that computes something different is blocked, so it cannot sign two prices.
//   - The slot lock is flushed before a member reveals, and a member that signed a
//     restart for an attempt can no longer vote or reveal in that attempt.
//   - A member whose disk was lost or rolled back sees its own unknown events on the
//     relays and stops publishing for that event.
//
// Members are killed with SIGKILL at exact points. This does not simulate power loss.
// This is a research prototype and has not had a cryptographic review.
//
// Needs the test files of experiments 5 to 11. Copy all eight into arkd's
// internal/test/p2pfiatcost directory and run:
//   go test -v -count 5 -timeout 7000s -run '^TestP2pFiatCrashRecovery$' ./internal/test/p2pfiatcost

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/nbd-wtf/go-nostr"
	"github.com/stretchr/testify/require"
)

const (
	rcEnv     = "P2PFIAT_CRASH_MEMBER"
	rcDirEnv  = "P2PFIAT_CRASH_DIR"
	rcLine    = "P2PFIATC:"
	rcHoldMs  = 1000
	rcLogName = "journal.log"
)

// Journal.

type rcRecord struct {
	Kind  string          `json:"kind"`
	Label string          `json:"label,omitempty"`
	Key   string          `json:"key,omitempty"`
	Event *nostr.Event    `json:"event,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
}

type rcSecret struct {
	Pairs  map[int][]string `json:"pairs"`
	Coeffs [][]string       `json:"coeffs"`
}

type rcKeySnap struct {
	Group  string         `json:"group"`
	Share  string         `json:"share,omitempty"`
	Verify map[int]string `json:"verify"`
	Qual   []int          `json:"qual"`
}

type rcJournal struct {
	mu         sync.Mutex
	f          *os.File
	ids        map[string]bool
	byKey      map[string]*nostr.Event
	perLabel   map[string][]*nostr.Event
	secrets    map[string]*rcSecret
	keys       map[string][]rcKeySnap
	locked     map[string]bool
	abandoned  map[string]bool
	quarantine map[string]bool
	records    int
}

func rcFrame(body []byte) []byte {
	h := sha256.Sum256(body)
	return append(append([]byte(hex.EncodeToString(h[:8])+" "), body...), '\n')
}

// rcOpenJournal replays the log. A torn final record was never released, so it is
// dropped. Damage anywhere else means the history cannot be trusted.
func rcOpenJournal(path string) (*rcJournal, error) {
	j := &rcJournal{
		ids: map[string]bool{}, byKey: map[string]*nostr.Event{}, perLabel: map[string][]*nostr.Event{},
		secrets: map[string]*rcSecret{}, keys: map[string][]rcKeySnap{}, locked: map[string]bool{},
		abandoned: map[string]bool{}, quarantine: map[string]bool{},
	}
	raw, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	good := 0
	for good < len(raw) {
		end := bytes.IndexByte(raw[good:], '\n')
		var rec rcRecord
		ok := end > 17
		if ok {
			line := raw[good : good+end]
			body := line[17:]
			h := sha256.Sum256(body)
			ok = string(line[:16]) == hex.EncodeToString(h[:8]) && line[16] == ' ' &&
				json.Unmarshal(body, &rec) == nil
		}
		if !ok {
			if end >= 0 && good+end+1 < len(raw) {
				return nil, errors.New("journal is corrupt before its final record")
			}
			break
		}
		j.apply(&rec)
		good += end + 1
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	created := errors.Is(func() error { _, e := os.Stat(path); return e }(), os.ErrNotExist)
	j.f, err = os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := j.f.Truncate(int64(good)); err != nil {
		return nil, err
	}
	if _, err := j.f.Seek(int64(good), io.SeekStart); err != nil {
		return nil, err
	}
	if err := j.f.Sync(); err != nil {
		return nil, err
	}
	if created {
		d, err := os.Open(filepath.Dir(path))
		if err != nil {
			return nil, err
		}
		defer d.Close()
		if err := d.Sync(); err != nil {
			return nil, err
		}
	}
	return j, nil
}

func (j *rcJournal) apply(r *rcRecord) {
	j.records++
	switch r.Kind {
	case "event":
		j.ids[r.Event.ID] = true
		j.byKey[r.Label+"|"+r.Key] = r.Event
		j.perLabel[r.Label] = append(j.perLabel[r.Label], r.Event)
		if strings.HasPrefix(r.Key, "rb-abandon/") {
			j.abandoned[strings.TrimPrefix(r.Key, "rb-abandon/")] = true
		}
	case "secret":
		s := &rcSecret{}
		if json.Unmarshal(r.Data, s) == nil {
			j.secrets[r.Label] = s
		}
	case "keys":
		var k []rcKeySnap
		if json.Unmarshal(r.Data, &k) == nil {
			j.keys[r.Label] = k
		}
	case "lock":
		j.locked[r.Label] = true
	case "quarantine":
		j.quarantine[r.Label] = true
	}
}

// append writes and flushes a record before the caller may act on it.
func (j *rcJournal) append(r *rcRecord) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if _, err := j.f.Write(rcFrame(body)); err != nil {
		return err
	}
	if err := j.f.Sync(); err != nil {
		return err
	}
	j.apply(r)
	return nil
}

func (j *rcJournal) has(label, key string) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.byKey[label+"|"+key] != nil
}

func (j *rcJournal) hasType(label, kind string) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	for k := range j.byKey {
		if strings.HasPrefix(k, label+"|"+kind) {
			return true
		}
	}
	return false
}

func (j *rcJournal) lock(slot string) error {
	j.mu.Lock()
	done := j.locked[slot]
	j.mu.Unlock()
	if done {
		return nil
	}
	return j.append(&rcRecord{Kind: "lock", Label: slot})
}

// rcKey names the protocol step of a message. Each step may carry only one value.
func rcKey(w *nsWire) string {
	switch w.Type {
	case "pd-complaint", "pd-reveal", "pd-evidence", "pd-open", "pd-certpart", "rb-abandon":
		return w.Type + "/" + w.Hash
	case "pd-answer":
		return fmt.Sprintf("%s/%s/%d", w.Type, w.Hash, w.Price)
	}
	return w.Type
}

// decide returns "send", "dup" or "block" for an outgoing event.
func (j *rcJournal) decide(label, slot string, attempt int, w *nsWire, evt *nostr.Event) string {
	j.mu.Lock()
	defer j.mu.Unlock()
	if old := j.byKey[label+"|"+rcKey(w)]; old != nil {
		if old.Content == evt.Content {
			return "dup"
		}
		return "block"
	}
	switch w.Type {
	case "pd-vote", "pd-reveal", "pd-openvote":
		// Signing a restart gives up this attempt. Otherwise the count behind the lock fails.
		if j.abandoned[fmt.Sprintf("%s/%d", slot, attempt)] {
			return "block"
		}
	case "rb-abandon":
		if at := strings.LastIndex(w.Hash, "/"); at < 0 || j.locked[w.Hash[:at]] {
			return "block"
		}
	case "partial":
		vote := j.byKey[label+"|vote"]
		if vote == nil {
			return "block"
		}
		var v nsWire
		if json.Unmarshal([]byte(vote.Content), &v) != nil || v.Price != w.Price {
			return "block"
		}
	}
	return "send"
}

func rcSnap(k *thrKey, id int) rcKeySnap {
	s := rcKeySnap{Group: nsPointHex(&k.group), Verify: map[int]string{}, Qual: k.qualified}
	if v, ok := k.shares[id]; ok {
		s.Share = nsScalarHex(&v)
	}
	for j, p := range k.verify {
		s.Verify[j] = nsPointHex(&p)
	}
	return s
}

func rcRestoreKey(s rcKeySnap, id int) (*thrKey, error) {
	group, err := nsParsePoint(s.Group)
	if err != nil {
		return nil, err
	}
	k := &thrKey{
		group: group, shares: map[int]btcec.ModNScalar{}, verify: map[int]btcec.JacobianPoint{},
		qualified: s.Qual, excluded: map[int]string{},
	}
	if s.Share != "" {
		v, err := nsParseScalar(s.Share)
		if err != nil {
			return nil, err
		}
		k.shares[id] = v
	}
	for j, h := range s.Verify {
		p, err := nsParsePoint(h)
		if err != nil {
			return nil, err
		}
		k.verify[j] = p
	}
	return k, nil
}

func rcRestoreEvent(snaps []rcKeySnap, id int) (*thrEvent, error) {
	if len(snaps) != fsEventInstances {
		return nil, errors.New("incomplete key snapshot")
	}
	keys := make([]*thrKey, len(snaps))
	for i := range snaps {
		k, err := rcRestoreKey(snaps[i], id)
		if err != nil {
			return nil, err
		}
		keys[i] = k
	}
	e := &thrEvent{key: keys[fsInstKey], ora: &oracle{cache: map[prefix]btcec.JacobianPoint{}}}
	e.px = thrSer(&e.key.group)[1:]
	for i := range numDigits {
		e.nonces[i] = keys[fsInstDigit+i]
		e.rx[i] = thrSer(&e.nonces[i].group)[1:]
	}
	return e, nil
}

// Guard between protocol logic and the relays.

type rcGate struct {
	j        *rcJournal
	logic    *nsNode
	net      *nsNode
	id       int
	label    string
	slot     string
	attempt  int
	drop     string
	sent     int
	crash    atomic.Value
	blocked  atomic.Int64
	isolated atomic.Bool
	opened   time.Time
	stop     context.CancelFunc
}

func rcDie() {
	p, _ := os.FindProcess(os.Getpid())
	_ = p.Kill()
	select {}
}

func rcOpenGate(ctx context.Context, cfg nsConfig, j *rcJournal, label, slot string, attempt int) (*rcGate, error) {
	c := cfg
	c.Session, c.Behavior = cfg.Session+"/"+label, ""
	gctx, stop := context.WithCancel(ctx)
	inner := c
	inner.Relays = nil
	logic, err := nsNewNode(gctx, inner)
	if err != nil {
		stop()
		return nil, err
	}
	net, err := nsNewNode(gctx, c)
	if err != nil {
		stop()
		return nil, err
	}
	g := &rcGate{
		j: j, logic: logic, net: net, id: cfg.ID, label: label, slot: slot, attempt: attempt,
		opened: time.Now(), stop: stop,
	}
	g.crash.Store("")
	j.mu.Lock()
	g.isolated.Store(j.quarantine[label])
	replay := append([]*nostr.Event{}, j.perLabel[label]...)
	j.mu.Unlock()
	// Republish what the journal holds. Event IDs are unchanged, so this cannot equivocate.
	for _, e := range replay {
		net.receive(e)
	}
	go g.pump(gctx)
	return g, nil
}

func (g *rcGate) pump(ctx context.Context) {
	for ctx.Err() == nil {
		for _, m := range g.net.take(15 * time.Millisecond) {
			g.j.mu.Lock()
			known := g.j.ids[m.id]
			g.j.mu.Unlock()
			if m.from == g.id && !known && !g.isolated.Load() {
				// The relays hold a message from this key that the journal does not know.
				g.isolated.Store(true)
				_ = g.j.append(&rcRecord{Kind: "quarantine", Label: g.label})
			}
			g.logic.mu.Lock()
			g.logic.inbox = append(g.logic.inbox, m)
			g.logic.mu.Unlock()
			select {
			case g.logic.wake <- struct{}{}:
			default:
			}
		}
		// Hold output until the relays had time to show this member's own history.
		if time.Since(g.opened) < rcHoldMs*time.Millisecond {
			continue
		}
		g.logic.mu.Lock()
		var out []*nostr.Event
		seen := map[string]bool{}
		for r := range g.logic.outbox {
			for _, e := range g.logic.outbox[r] {
				if !seen[e.ID] {
					seen[e.ID] = true
					out = append(out, e)
				}
			}
			g.logic.outbox[r] = nil
		}
		g.logic.mu.Unlock()
		for _, e := range out {
			g.release(e)
		}
	}
}

func (g *rcGate) crashAt(point, kind string) bool {
	c := g.crash.Load().(string)
	if c == point+":"+kind {
		return true
	}
	// "nth:K:point" kills at the K-th message this member tries to publish, whatever it is.
	var k int
	var p string
	if n, _ := fmt.Sscanf(c, "nth:%d:%s", &k, &p); n == 2 {
		return p == point && g.sent == k
	}
	return false
}

func (g *rcGate) release(e *nostr.Event) {
	var w nsWire
	if json.Unmarshal([]byte(e.Content), &w) != nil {
		return
	}
	if g.isolated.Load() {
		g.blocked.Add(1)
		return
	}
	if g.drop != "" && w.Type == g.drop {
		return
	}
	g.sent++
	if g.crashAt("before-journal", w.Type) {
		rcDie()
	}
	switch g.j.decide(g.label, g.slot, g.attempt, &w, e) {
	case "dup":
		return
	case "block":
		g.blocked.Add(1)
		return
	}
	// The lock must be on disk before this member helps make the key computable.
	if w.Type == "pd-reveal" || w.Type == "pd-openvote" || w.Type == "pd-open" {
		if g.j.lock(g.slot) != nil {
			g.blocked.Add(1)
			return
		}
	}
	if g.j.append(&rcRecord{Kind: "event", Label: g.label, Key: rcKey(&w), Event: e}) != nil {
		g.blocked.Add(1)
		return
	}
	if g.crashAt("after-journal", w.Type) {
		rcDie()
	}
	g.net.receive(e)
	if g.crashAt("after-send", w.Type) {
		time.Sleep(400 * time.Millisecond)
		rcDie()
	}
}

// Member process.

type rcCmd struct {
	Op      string
	Slot    string
	Attempt int
	Leader  int
	GoMs    int64
	Drop    string
	Crash   string
	NoAudit bool
	Own     uint32
}

type rcOutput struct {
	rbOutput
	Blocked     int64
	Quarantined bool
	// SkippedOpenVote: the open-vote deadline passed while a reveal was still missing.
	SkippedOpenVote bool
}

// rcAudit reads an attempt from the relays before this member may sign a restart.
func rcAudit(ctx context.Context, cfg nsConfig, j *rcJournal, label string) (bool, error) {
	c := cfg
	c.Session, c.Behavior = cfg.Session+"/"+label, ""
	actx, cancel := context.WithCancel(ctx)
	defer cancel()
	n, err := nsNewNode(actx, c)
	if err != nil {
		return false, err
	}
	n.noForward.Store(true)
	votes := map[int]string{}
	foreign := false
	for start := time.Now(); time.Since(start) < 1200*time.Millisecond; {
		for _, m := range n.take(50 * time.Millisecond) {
			j.mu.Lock()
			known := j.ids[m.id]
			j.mu.Unlock()
			foreign = foreign || (m.from == cfg.ID && !known)
			if m.w.Type == "pd-vote" {
				votes[m.from] = m.w.Hash
			}
		}
	}
	count := map[string]int{}
	for _, h := range votes {
		count[h]++
		if count[h] >= fsCertVotes {
			return true, nil
		}
	}
	return foreign, nil
}

func TestP2pFiatCrashMember(t *testing.T) {
	raw := os.Getenv(rcEnv)
	if raw == "" {
		t.Skip("started only as a member process by TestP2pFiatCrashRecovery")
	}
	var cfg nsConfig
	require.NoError(t, json.Unmarshal([]byte(raw), &cfg))
	j, err := rcOpenJournal(filepath.Join(os.Getenv(rcDirEnv), rcLogName))
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var long *thrKey
	if snaps := j.keys[rbLabel("genesis", 0)]; len(snaps) == 1 {
		long, err = rcRestoreKey(snaps[0], cfg.ID)
		require.NoError(t, err)
	}
	var gate *rcGate
	open := func(label, slot string, attempt int, fresh bool) (*rcGate, error) {
		if gate != nil && gate.label == label && !fresh {
			return gate, nil
		}
		if gate != nil {
			gate.stop()
		}
		g, err := rcOpenGate(ctx, cfg, j, label, slot, attempt)
		if err != nil {
			gate = nil
			return nil, err
		}
		gate = g
		return g, nil
	}
	emit := func(o *rcOutput) {
		body, _ := json.Marshal(o)
		fmt.Fprintf(os.Stdout, "\n%s%s\n", rcLine, body)
	}
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<16), 1<<20)
	for sc.Scan() {
		var cmd rcCmd
		require.NoError(t, json.Unmarshal(sc.Bytes(), &cmd))
		if cmd.Op == "exit" {
			return
		}
		out := &rcOutput{}
		label := rbLabel(cmd.Slot, cmd.Attempt)
		err := func() error {
			switch cmd.Op {
			case "attest":
				if len(j.keys[label]) == 0 {
					return errors.New("no key share for this event")
				}
				event, err := rcRestoreEvent(j.keys[label], cfg.ID)
				if err != nil {
					return err
				}
				g, err := open(label, cmd.Slot, cmd.Attempt, true)
				if err != nil {
					return err
				}
				g.crash.Store(cmd.Crash)
				g.logic.cfg.Own, g.logic.cfg.Behavior, g.logic.cfg.Timing = cmd.Own, "", nsDefaultTiming
				a := &nsOutput{}
				if err := g.logic.attest(&nsState{event: event}, time.UnixMilli(cmd.GoMs), a); err != nil {
					return err
				}
				// Give the guard time to process the last output before reporting.
				time.Sleep(200 * time.Millisecond)
				out.Attested, out.AttestAtMs, out.Price = a.Attested, a.AttestAtMs, a.AttestPrice
				out.Blocked, out.Quarantined = g.blocked.Load(), g.isolated.Load()
				return nil
			case "abandon":
				refuse := j.locked[cmd.Slot]
				if !refuse && !cmd.NoAudit {
					seen, err := rcAudit(ctx, cfg, j, label)
					if err != nil {
						return err
					}
					if seen {
						if err := j.lock(cmd.Slot); err != nil {
							return err
						}
						refuse = true
					}
				}
				out.Refused = refuse && cmd.Drop != "abandon-anyway"
				g, err := open(cmd.Slot+"-ctl", cmd.Slot, cmd.Attempt, true)
				if err != nil {
					return err
				}
				if cmd.Drop == "abandon-anyway" {
					// An attacker ignores the guard and signs directly.
					g.drop = ""
					if err := g.net.send(nsWire{Type: "rb-abandon", Hash: fmt.Sprintf("%s/%d", cmd.Slot, cmd.Attempt)}); err != nil {
						return err
					}
				}
				hash := fmt.Sprintf("%s/%d", cmd.Slot, cmd.Attempt)
				send := !refuse && cmd.Drop != "abandon-anyway"
				goAt := time.UnixMilli(cmd.GoMs).Add(1500 * time.Millisecond)
				count, err := rbCollectAbandons(g.logic, hash, send, goAt)
				if err != nil {
					return err
				}
				out.AbandonCount, out.AbandonCert = count, count >= fsCertVotes
				out.Blocked = g.blocked.Load()
				return nil
			}
			resume := cmd.Op == "resume"
			g, err := open(label, cmd.Slot, cmd.Attempt, true)
			if err != nil {
				return err
			}
			g.crash.Store(cmd.Crash)
			g.drop = cmd.Drop
			instances := fsEventInstances
			if cmd.Op == "genesis" {
				instances = 1
			}
			// The guard owns dealing: the secret reaches the disk before the deal can leave.
			s := rbNewSetup(t, g.logic, cfg.ID, instances, cmd.Leader, "silent-dealer", long)
			goAt := time.UnixMilli(cmd.GoMs)
			time.Sleep(time.Until(goAt))
			if sec := j.secrets[label]; sec != nil {
				s.truePairs = sec.Pairs
				for _, line := range sec.Coeffs {
					c, err := fsParseScalars(line)
					if err != nil {
						return err
					}
					s.coeffs = append(s.coeffs, c)
				}
			} else if !resume {
				w, pairs, coeffs, err := pdMakeDeal(t, g.logic, instances, 0)
				if err != nil {
					return err
				}
				sec := rcSecret{Pairs: pairs}
				for _, line := range coeffs {
					sec.Coeffs = append(sec.Coeffs, pdHex(line))
				}
				body, err := json.Marshal(sec)
				if err != nil {
					return err
				}
				if err := j.append(&rcRecord{Kind: "secret", Label: label, Data: body}); err != nil {
					return err
				}
				s.truePairs, s.coeffs = pairs, coeffs
				if err := g.logic.send(w); err != nil {
					return err
				}
			}
			s.voted = j.has(label, "pd-vote")
			s.proposed = j.has(label, "pd-proposal")
			s.revealed = j.hasType(label, "pd-reveal/")
			s.openVoted = j.has(label, "pd-openvote")
			limit := int64(pdFailMs)
			if resume {
				limit = rbResumeMs
			}
			res, err := rbRun(s, resume, goAt, limit)
			if err != nil {
				return err
			}
			if s.transcript != "" {
				if err := j.lock(cmd.Slot); err != nil {
					return err
				}
			}
			// Let the guard drain the certificate share before this member moves on.
			time.Sleep(300 * time.Millisecond)
			out.pdOutput = *res.out
			_, ownOpenVote := s.openVotes[cfg.ID]
			out.SkippedOpenVote = s.openVoted && !ownOpenVote
			out.SeenKeyPx = rbSeenKey(s)
			out.Blocked, out.Quarantined = g.blocked.Load(), g.isolated.Load()
			if res.keys != nil && res.out.HasShare {
				snaps := make([]rcKeySnap, len(res.keys))
				for i, k := range res.keys {
					snaps[i] = rcSnap(k, cfg.ID)
				}
				body, err := json.Marshal(snaps)
				if err != nil {
					return err
				}
				if err := j.append(&rcRecord{Kind: "keys", Label: label, Data: body}); err != nil {
					return err
				}
			}
			if cmd.Op == "genesis" && res.keys != nil {
				long = res.keys[0]
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

type rcProc struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	exited chan struct{}
}

type rcMemberLine struct {
	id  int
	out *rcOutput
}

type rcCluster struct {
	session string
	sks     map[int]string
	roster  map[int]string
	dir     string
	procs   map[int]*rcProc
	lines   chan rcMemberLine
	done    chan struct{}
	proxies map[[2]int]*nsProxy
	longPx  string
	slots   int
}

func (c *rcCluster) journal(id int) string {
	return filepath.Join(c.dir, fmt.Sprint(id), rcLogName)
}

func (c *rcCluster) spawn(t *testing.T, id int) {
	t.Helper()
	var urls []string
	for r := range nsRelays {
		urls = append(urls, "ws://"+c.proxies[[2]int{id, r}].ln.Addr().String())
	}
	body, err := json.Marshal(nsConfig{Session: c.session, ID: id, SK: c.sks[id], Roster: c.roster, Relays: urls})
	require.NoError(t, err)
	cmd := exec.Command(os.Args[0], "-test.run", "^TestP2pFiatCrashMember$", "-test.timeout", "0")
	cmd.Env = append(os.Environ(), rcEnv+"="+string(body), rcDirEnv+"="+filepath.Dir(c.journal(id)))
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	p := &rcProc{cmd: cmd, stdin: stdin, exited: make(chan struct{})}
	c.procs[id] = p
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 1<<16), 1<<20)
		for sc.Scan() {
			text, ok := strings.CutPrefix(sc.Text(), rcLine)
			if !ok {
				continue
			}
			o := &rcOutput{}
			if json.Unmarshal([]byte(text), o) == nil {
				select {
				case c.lines <- rcMemberLine{id: id, out: o}:
				case <-c.done:
				}
			}
		}
		_ = cmd.Wait()
		close(p.exited)
	}()
}

func (c *rcCluster) kill(t *testing.T, id int) {
	t.Helper()
	p := c.procs[id]
	_ = p.cmd.Process.Kill()
	select {
	case <-p.exited:
	case <-time.After(5 * time.Second):
		require.Fail(t, "member did not exit", "member %d", id)
	}
}

func rcDocker(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func rcStartRelays(t *testing.T) {
	t.Helper()
	// Compression is off because go-nostr v0.40.1's flate writer fails under Go 1.27.
	script := `sed -e 's/bind = "127.0.0.1"/bind = "0.0.0.0"/' -e '/compression {/,/}/ s/enabled = true/enabled = false/' /app/strfry.conf > /tmp/s.conf && exec /app/strfry --config /tmp/s.conf relay`
	for i := range nsRelays {
		_, _ = rcDocker("rm", "-f", nsContainer(i))
		out, err := rcDocker("run", "-d", "--name", nsContainer(i),
			"-p", fmt.Sprintf("127.0.0.1:%d:7777", nsBasePort+i),
			"--entrypoint", "sh", nsImage, "-c", script)
		require.NoError(t, err, out)
		nsWaitRelay(t, i)
	}
	t.Cleanup(func() {
		for i := range nsRelays {
			_, _ = rcDocker("rm", "-f", nsContainer(i))
		}
	})
}

func rcStart(t *testing.T) *rcCluster {
	t.Helper()
	c := &rcCluster{
		session: fmt.Sprintf("p2pfiat-exp12-%d", time.Now().UnixNano()),
		sks:     map[int]string{}, roster: map[int]string{}, dir: t.TempDir(), procs: map[int]*rcProc{},
		lines: make(chan rcMemberLine, 256), done: make(chan struct{}), proxies: map[[2]int]*nsProxy{},
	}
	rcLatest = c
	for i := range nsRelays {
		nsWaitRelay(t, i)
	}
	for _, id := range gIDs {
		c.sks[id] = nostr.GeneratePrivateKey()
		pub, err := nostr.GetPublicKey(c.sks[id])
		require.NoError(t, err)
		c.roster[id] = pub
		for r := range nsRelays {
			c.proxies[[2]int{id, r}] = nsNewProxy(t, fmt.Sprintf("127.0.0.1:%d", nsBasePort+r))
		}
	}
	t.Cleanup(func() {
		close(c.done)
		for _, p := range c.procs {
			_ = p.cmd.Process.Kill()
			select {
			case <-p.exited:
			case <-time.After(3 * time.Second):
			}
		}
		for _, p := range c.proxies {
			_ = p.ln.Close()
			p.setBlocked(true)
		}
	})
	for _, id := range gIDs {
		c.spawn(t, id)
	}
	genesis := c.collect(t, "genesis", "genesis", 0, gIDs, c.send(t, rcCmd{Op: "genesis", Slot: "genesis", Leader: 1}, gIDs))
	for _, id := range gIDs {
		require.True(t, genesis[id].Final, "genesis must finish")
		require.Equal(t, genesis[1].LongPx, genesis[id].LongPx)
	}
	c.longPx = genesis[1].LongPx
	return c
}

func (c *rcCluster) slot() string {
	c.slots++
	return fmt.Sprintf("slot-%d", c.slots)
}

func (c *rcCluster) write(t *testing.T, id int, cmd rcCmd) {
	t.Helper()
	cmd.Own = cmd.Own + uint32(100_000+id*10)
	body, err := json.Marshal(cmd)
	require.NoError(t, err)
	_, err = c.procs[id].stdin.Write(append(body, '\n'))
	require.NoError(t, err)
}

func (c *rcCluster) send(t *testing.T, cmd rcCmd, ids []int) int64 {
	t.Helper()
	cmd.GoMs = time.Now().Add(time.Second).UnixMilli()
	for _, id := range ids {
		c.write(t, id, cmd)
	}
	return cmd.GoMs
}

func (c *rcCluster) collect(t *testing.T, op, slot string, attempt int, ids []int, _ int64) map[int]*rcOutput {
	t.Helper()
	return c.collectFrom(t, op, slot, attempt, ids, map[int]*rcOutput{})
}

func (c *rcCluster) collectFrom(
	t *testing.T, op, slot string, attempt int, ids []int, out map[int]*rcOutput,
) map[int]*rcOutput {
	t.Helper()
	limit := time.After(60 * time.Second)
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

func (c *rcCluster) run(t *testing.T, cmd rcCmd, ids []int) map[int]*rcOutput {
	t.Helper()
	return c.collect(t, cmd.Op, cmd.Slot, cmd.Attempt, ids, c.send(t, cmd, ids))
}

func (c *rcCluster) stopAll() {
	for _, p := range c.procs {
		_ = p.cmd.Process.Kill()
	}
}

// runCrash kills one member at an exact point and restarts it with the same deadline.
// It returns nil only if the member proved it never reached the step: it skipped its
// open vote because a reveal was late. Any other missed crash point fails the test.
func (c *rcCluster) runCrash(
	t *testing.T, cmd rcCmd, ids []int, victim int, crash string, ownShift uint32, beforeRestart func(),
) map[int]*rcOutput {
	t.Helper()
	outs, killed := c.runCrashMaybe(t, cmd, ids, victim, crash, ownShift, beforeRestart)
	if killed {
		return outs
	}
	require.True(t, outs[victim].SkippedOpenVote, "the crash point was not reached: %s", crash)
	t.Logf("rc-retry: member %d skipped its open vote at %s", victim, crash)
	return nil
}

// runCrashMaybe is runCrash without a verdict: killed is false if the member finished
// without reaching the kill point, and the outputs then include its own answer.
func (c *rcCluster) runCrashMaybe(
	t *testing.T, cmd rcCmd, ids []int, victim int, crash string, ownShift uint32, beforeRestart func(),
) (map[int]*rcOutput, bool) {
	t.Helper()
	cmd.GoMs = time.Now().Add(time.Second).UnixMilli()
	for _, id := range ids {
		m := cmd
		if id == victim {
			m.Crash = crash
		}
		c.write(t, id, m)
	}
	p := c.procs[victim]
	early := map[int]*rcOutput{}
	limit := time.After(30 * time.Second)
	for waiting := true; waiting; {
		select {
		case <-p.exited:
			waiting = false
		case l := <-c.lines:
			if l.out.Slot != cmd.Slot || l.out.Attempt != cmd.Attempt || l.out.Op != cmd.Op {
				continue
			}
			require.Empty(t, l.out.Error, "member %d", l.id)
			early[l.id] = l.out
			if l.id == victim {
				return c.collectFrom(t, cmd.Op, cmd.Slot, cmd.Attempt, ids, early), false
			}
		case <-limit:
			require.Fail(t, "the crash point was not reached", crash)
		}
	}
	require.False(t, p.cmd.ProcessState.Success(), "member %d must have been killed", victim)
	if beforeRestart != nil {
		beforeRestart()
	}
	c.spawn(t, victim)
	again := cmd
	again.Own = ownShift
	c.write(t, victim, again)
	return c.collectFrom(t, cmd.Op, cmd.Slot, cmd.Attempt, ids, early), true
}

func (c *rcCluster) requireFinal(t *testing.T, outs map[int]*rcOutput, want []int) *rcOutput {
	t.Helper()
	plain := map[int]*pdOutput{}
	var first *rcOutput
	for id, o := range outs {
		plain[id] = &o.pdOutput
		if first == nil {
			first = o
		}
	}
	(&pdCluster{longPx: c.longPx}).requireFinal(t, plain, want)
	return first
}

func (c *rcCluster) requireOutsideAttestation(t *testing.T, slot string, pub *rcOutput) {
	t.Helper()
	events := nsFetchAttestations(t, c.session+"/"+rbLabel(slot, 0), c.roster)
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
		require.Equal(t, price, w.Price, "one attested price")
	}
}

// requireNoConflict reads the relays and checks that no member published two values for one step.
func (c *rcCluster) requireNoConflict(t *testing.T, label string) int {
	t.Helper()
	session := c.session + "/" + label
	byPub := map[string]int{}
	for id, p := range c.roster {
		byPub[p] = id
	}
	seen := map[string]bool{}
	values := map[string]map[string]bool{}
	for i := range nsRelays {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		r, err := nostr.RelayConnect(ctx, fmt.Sprintf("ws://127.0.0.1:%d", nsBasePort+i))
		require.NoError(t, err)
		events, err := r.QuerySync(ctx, nostr.Filter{
			Kinds: []int{nsKind}, Tags: nostr.TagMap{"t": {session}}, Limit: 500,
		})
		require.NoError(t, err)
		for _, e := range events {
			m, ok := nsAccept(e, session, byPub)
			if !ok || seen[e.ID] {
				continue
			}
			seen[e.ID] = true
			key := fmt.Sprintf("%d|%s", m.from, rcKey(&m.w))
			if values[key] == nil {
				values[key] = map[string]bool{}
			}
			values[key][e.Content] = true
		}
		_ = r.Close()
		cancel()
	}
	require.NotEmpty(t, seen, "the relays must hold this event's messages")
	for key, v := range values {
		require.Len(t, v, 1, "%s published two different values", key)
	}
	return len(seen)
}

func TestP2pFiatCrashRecovery(t *testing.T) {
	for _, e := range []string{rcEnv, rbEnv, pdEnv, fsEnv, nsEnv} {
		if os.Getenv(e) != "" {
			t.Skip("member process")
		}
	}

	t.Run("journal drops a torn final record", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), rcLogName)
		j, err := rcOpenJournal(path)
		require.NoError(t, err)
		for _, slot := range []string{"a", "b", "c"} {
			require.NoError(t, j.append(&rcRecord{Kind: "lock", Label: slot}))
		}
		require.NoError(t, j.f.Close())
		raw, err := os.ReadFile(path)
		require.NoError(t, err)
		for cut := 1; cut < 30; cut += 7 {
			require.NoError(t, os.WriteFile(path, raw[:len(raw)-cut], 0o600))
			j, err = rcOpenJournal(path)
			require.NoError(t, err)
			require.Equal(t, 2, j.records)
			require.True(t, j.locked["b"])
			require.False(t, j.locked["c"])
			require.NoError(t, j.append(&rcRecord{Kind: "lock", Label: "c"}))
			require.NoError(t, j.f.Close())
			j, err = rcOpenJournal(path)
			require.NoError(t, err)
			require.True(t, j.locked["c"], "a record after the repair must survive")
			require.NoError(t, j.f.Close())
		}
	})

	t.Run("journal refuses damage before its final record", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), rcLogName)
		j, err := rcOpenJournal(path)
		require.NoError(t, err)
		for _, slot := range []string{"a", "b", "c"} {
			require.NoError(t, j.append(&rcRecord{Kind: "lock", Label: slot}))
		}
		require.NoError(t, j.f.Close())
		raw, err := os.ReadFile(path)
		require.NoError(t, err)
		raw[25] ^= 1
		require.NoError(t, os.WriteFile(path, raw, 0o600))
		_, err = rcOpenJournal(path)
		require.ErrorContains(t, err, "corrupt")
	})

	t.Run("the guard blocks every conflicting step", func(t *testing.T) {
		sk := nostr.GeneratePrivateKey()
		event := func(w nsWire) (*nsWire, *nostr.Event) {
			body, err := json.Marshal(w)
			require.NoError(t, err)
			e := &nostr.Event{CreatedAt: nostr.Now(), Kind: nsKind, Content: string(body)}
			require.NoError(t, e.Sign(sk))
			return &w, e
		}
		j, err := rcOpenJournal(filepath.Join(t.TempDir(), rcLogName))
		require.NoError(t, err)
		store := func(label string, w *nsWire, e *nostr.Event) {
			require.NoError(t, j.append(&rcRecord{Kind: "event", Label: label, Key: rcKey(w), Event: e}))
		}
		w, e := event(nsWire{Type: "vote", Price: 100})
		require.Equal(t, "send", j.decide("s-a0", "s", 0, w, e))
		store("s-a0", w, e)
		same, sameE := event(nsWire{Type: "vote", Price: 100})
		require.Equal(t, "dup", j.decide("s-a0", "s", 0, same, sameE), "the same vote is a duplicate")
		other, otherE := event(nsWire{Type: "vote", Price: 101})
		require.Equal(t, "block", j.decide("s-a0", "s", 0, other, otherE), "a second vote value")
		p1, p1E := event(nsWire{Type: "partial", Price: 100})
		require.Equal(t, "send", j.decide("s-a0", "s", 0, p1, p1E))
		p2, p2E := event(nsWire{Type: "partial", Price: 101})
		require.Equal(t, "block", j.decide("s-a0", "s", 0, p2, p2E), "signing a price it did not vote for")
		p3, p3E := event(nsWire{Type: "partial", Price: 100})
		require.Equal(t, "block", j.decide("other-a0", "other", 0, p3, p3E), "signing without a stored vote")

		ab, abE := event(nsWire{Type: "rb-abandon", Hash: "t/0"})
		require.Equal(t, "send", j.decide("t-ctl", "t", 0, ab, abE))
		store("t-ctl", ab, abE)
		for _, kind := range []string{"pd-vote", "pd-reveal", "pd-openvote"} {
			late, lateE := event(nsWire{Type: kind, Hash: "x"})
			require.Equal(t, "block", j.decide("t-a0", "t", 0, late, lateE), "%s after signing a restart", kind)
		}
		require.NoError(t, j.lock("u"))
		lockedW, lockedE := event(nsWire{Type: "rb-abandon", Hash: "u/0"})
		require.Equal(t, "block", j.decide("u-ctl", "u", 0, lockedW, lockedE), "abandon of a locked slot")
		require.NoError(t, j.f.Close())
	})

	rcStartRelays(t)

	for _, kind := range []string{"pd-deal", "pd-vote", "pd-reveal", "pd-openvote"} {
		for _, point := range []string{"before-journal", "after-journal", "after-send"} {
			t.Run(fmt.Sprintf("setup survives a kill %s of %s", point, kind), func(t *testing.T) {
				var c *rcCluster
				var slot string
				var outs map[int]*rcOutput
				for try := 0; try < 3 && outs == nil; try++ {
					if c != nil {
						c.stopAll()
					}
					c = rcStart(t)
					slot = c.slot()
					cmd := rcCmd{Op: "attempt", Slot: slot, Leader: 1}
					outs = c.runCrash(t, cmd, gIDs, 3, point+":"+kind, 0, nil)
				}
				require.NotNil(t, outs, "the crash point was never reached")
				pub := c.requireFinal(t, outs, nil)
				require.GreaterOrEqual(t, len(pub.Qual), rbMinDealers)
				require.True(t, outs[3].Final, "the restarted member must finish")
				if kind != "pd-deal" {
					require.Contains(t, pub.Qual, 3, "the restarted dealer must keep its one deal")
				}
				c.requireNoConflict(t, rbLabel(slot, 0))
			})
		}
	}

	for _, kind := range []string{"vote", "partial"} {
		for _, point := range []string{"before-journal", "after-journal", "after-send"} {
			t.Run(fmt.Sprintf("attestation survives a kill %s of %s", point, kind), func(t *testing.T) {
				c := rcStart(t)
				slot := c.slot()
				setup := c.run(t, rcCmd{Op: "attempt", Slot: slot, Leader: 1}, gIDs)
				pub := c.requireFinal(t, setup, gIDs)
				outs := c.runCrash(t, rcCmd{Op: "attest", Slot: slot}, gIDs, 3, point+":"+kind, 0, nil)
				attested := 0
				for _, o := range outs {
					if o.Attested {
						attested++
					}
				}
				require.Positive(t, attested)
				require.True(t, outs[3].Attested, "the restarted member must see the attestation")
				c.requireOutsideAttestation(t, slot, pub)
				c.requireNoConflict(t, rbLabel(slot, 0))
			})
		}
	}

	for _, sc := range rcRecoveryScenarios {
		t.Run(sc.name, sc.run)
	}
}

type rcScenario struct {
	name string
	run  func(*testing.T)
}

// rcLostDisk certifies a slot, lets member 5 see the key, then wipes the journals of
// members 1 to 4 and asks them to sign a restart. Their journals are restored afterwards.
func rcLostDisk(t *testing.T, audit bool) map[int]*rcOutput {
	c := rcStart(t)
	slot, online := c.slot(), fsWithout(6, 7)
	goMs := c.send(t, rcCmd{Op: "attempt", Slot: slot, Leader: 1}, fsOnly(1, 2, 3, 4))
	c.write(t, 5, rcCmd{Op: "attempt", Slot: slot, Leader: 1, GoMs: goMs, Drop: "pd-openvote"})
	outs := c.collect(t, "attempt", slot, 0, online, goMs)
	require.NotEmpty(t, outs[5].SeenKeyPx)
	saved := map[int][]byte{}
	for _, id := range fsOnly(1, 2, 3, 4) {
		c.kill(t, id)
		raw, err := os.ReadFile(c.journal(id))
		require.NoError(t, err)
		saved[id] = raw
		require.NoError(t, os.Remove(c.journal(id)))
		c.spawn(t, id)
	}
	goMs = c.send(t, rcCmd{Op: "abandon", Slot: slot, NoAudit: !audit}, fsOnly(1, 2, 3, 4))
	c.write(t, 5, rcCmd{Op: "abandon", Slot: slot, GoMs: goMs, Drop: "abandon-anyway"})
	ab := c.collect(t, "abandon", slot, 0, online, goMs)
	for id, raw := range saved {
		c.kill(t, id)
		require.NoError(t, os.WriteFile(c.journal(id), raw, 0o600))
		c.spawn(t, id)
	}
	return ab
}

// rcRecoveryScenarios are shared by TestP2pFiatCrashRecovery and the ladder's step 5.
var rcRecoveryScenarios = []rcScenario{
	{"a restart with a new price cannot sign a second value", func(t *testing.T) {
		c := rcStart(t)
		slot := c.slot()
		setup := c.run(t, rcCmd{Op: "attempt", Slot: slot, Leader: 1}, gIDs)
		pub := c.requireFinal(t, setup, gIDs)
		outs := c.runCrash(t, rcCmd{Op: "attest", Slot: slot}, gIDs, 3, "after-send:partial", 700, nil)
		require.Positive(t, outs[3].Blocked, "the guard must have blocked the new price")
		c.requireOutsideAttestation(t, slot, pub)
		c.requireNoConflict(t, rbLabel(slot, 0))
	}},
	{"all 7 members restart and attest from disk", func(t *testing.T) {
		c := rcStart(t)
		slot := c.slot()
		setup := c.run(t, rcCmd{Op: "attempt", Slot: slot, Leader: 1}, gIDs)
		pub := c.requireFinal(t, setup, gIDs)
		for _, id := range gIDs {
			c.kill(t, id)
			c.spawn(t, id)
		}
		outs := c.run(t, rcCmd{Op: "attest", Slot: slot}, gIDs)
		for id, o := range outs {
			require.True(t, o.Attested, "member %d", id)
		}
		c.requireOutsideAttestation(t, slot, pub)
		c.requireNoConflict(t, rbLabel(slot, 0))
	}},
	{"a lock survives a restart and the slot finishes with the same key", func(t *testing.T) {
		c := rcStart(t)
		slot, online := c.slot(), fsWithout(6, 7)
		var outs map[int]*rcOutput
		func() {
			goMs := c.send(t, rcCmd{Op: "attempt", Slot: slot, Leader: 1}, fsOnly(1, 2, 3, 4))
			c.write(t, 5, rcCmd{Op: "attempt", Slot: slot, Leader: 1, GoMs: goMs, Drop: "pd-openvote"})
			outs = c.collect(t, "attempt", slot, 0, online, goMs)
		}()
		seen := outs[5].SeenKeyPx
		require.NotEmpty(t, seen, "the attacker must have seen the key")
		// Member 5 counts its own withheld open vote, so only its private view can finish.
		for _, id := range fsOnly(1, 2, 3, 4) {
			require.False(t, outs[id].Final, "honest member %d", id)
		}
		for _, id := range fsOnly(1, 2, 3, 4) {
			c.kill(t, id)
			c.spawn(t, id)
		}
		goMs := c.send(t, rcCmd{Op: "abandon", Slot: slot}, fsOnly(1, 2, 3, 4, 6))
		c.write(t, 5, rcCmd{Op: "abandon", Slot: slot, GoMs: goMs, Drop: "abandon-anyway"})
		c.write(t, 7, rcCmd{Op: "abandon", Slot: slot, GoMs: goMs, Drop: "abandon-anyway"})
		ab := c.collect(t, "abandon", slot, 0, gIDs, goMs)
		for _, id := range fsOnly(1, 2, 3, 4, 6) {
			require.True(t, ab[id].Refused, "member %d must refuse after its restart", id)
		}
		for id, o := range ab {
			require.False(t, o.AbandonCert, "member %d", id)
		}
		require.Positive(t, ab[5].AbandonCount, "the attacker's abandon messages must have been sent")
		voters := fsOnly(1, 2, 3, 4, 6)
		done := c.run(t, rcCmd{Op: "resume", Slot: slot, Leader: 1}, voters)
		pub := c.requireFinal(t, done, online)
		for id, o := range done {
			require.Equal(t, seen, o.EventPx, "member %d must finish with the key the attacker saw", id)
		}
		att := c.run(t, rcCmd{Op: "attest", Slot: slot}, voters)
		require.True(t, att[1].Attested)
		c.requireOutsideAttestation(t, slot, pub)
	}},
	{"control: without the audit, lost disks allow a restart", func(t *testing.T) {
		ab := rcLostDisk(t, false)
		for _, id := range fsOnly(1, 2, 3, 4) {
			require.False(t, ab[id].Refused, "member %d forgot its lock", id)
		}
		require.True(t, ab[1].AbandonCert, "this is the attack that durable state must stop")
	}},
	{"after a lost disk the relay audit refuses a restart", func(t *testing.T) {
		ab := rcLostDisk(t, true)
		for _, id := range fsOnly(1, 2, 3, 4) {
			require.True(t, ab[id].Refused, "member %d must see its own history", id)
		}
		for id, o := range ab {
			require.False(t, o.AbandonCert, "member %d", id)
		}
	}},
	{"a rolled-back disk stops publishing for that event", func(t *testing.T) {
		c := rcStart(t)
		slot := c.slot()
		setup := c.run(t, rcCmd{Op: "attempt", Slot: slot, Leader: 1}, gIDs)
		pub := c.requireFinal(t, setup, gIDs)
		old, err := os.ReadFile(c.journal(3))
		require.NoError(t, err)
		outs := c.runCrash(t, rcCmd{Op: "attest", Slot: slot}, gIDs, 3, "after-send:partial", 700, func() {
			require.NoError(t, os.WriteFile(c.journal(3), old, 0o600))
		})
		require.True(t, outs[3].Quarantined, "member 3 must notice its unknown history")
		require.Positive(t, outs[3].Blocked, "member 3 must have tried and been stopped")
		c.requireOutsideAttestation(t, slot, pub)
		c.requireNoConflict(t, rbLabel(slot, 0))
	}},
}
