package p2pfiatcost

// Stepwise diagnostics for experiment 12. Each trial uses a clean cluster and is
// classified separately from the pass or fail of the Go test:
//
//   - ok:       every member finished and agreed
//   - skipped:  the member never reached the kill point (it skipped a late open vote)
//   - progress: a member did not finish in time, with no conflicting output
//   - safety:   members disagreed, or a member published two values for one step
//
// The relays are scanned for conflicting messages after every trial, including failed
// ones. Select a step with P2PFIAT_LADDER_STEP and a trial count with P2PFIAT_LADDER_N:
//
//	1: no guard, no kills (experiment 11 members)
//	2: guard and journal, no kills
//	4: one kill at each of the 18 kill points, N times each
//	5: the six recovery scenarios of the main test, N times each
//	6: N seeded random kills (P2PFIAT_LADDER_SEED): any member, any of its messages

import (
	"context"
	"fmt"
	"math/rand/v2"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/stretchr/testify/require"
)

const (
	rcLadderEnv     = "P2PFIAT_LADDER_STEP"
	rcLadderNEnv    = "P2PFIAT_LADDER_N"
	rcLadderSeedEnv = "P2PFIAT_LADDER_SEED"
)

// rcLatest lets the ladder scan the relays even when a cluster failed during its setup.
var rcLatest *rcCluster

type rcTrialState struct {
	stage   string
	note    string
	skipped bool
	plain   *rbCluster
	// failOnly: the scenario's own assertions mix progress and protection checks, so a
	// failure is reported as "failed" for manual reading instead of being classified.
	failOnly bool
}

type rcTrial struct {
	name string
	run  func(*testing.T, *rcTrialState)
}

type rcFlow struct {
	longPx  string
	slot    func() string
	attempt func(*testing.T, string) map[int]*rbOutput
	attest  func(*testing.T, string) map[int]*rbOutput
}

func rcPlain(in map[int]*rcOutput) map[int]*rbOutput {
	out := map[int]*rbOutput{}
	for id, o := range in {
		out[id] = &o.rbOutput
	}
	return out
}

func rcGuardFlow(t *testing.T) *rcFlow {
	c := rcStart(t)
	return &rcFlow{
		longPx: c.longPx,
		slot:   c.slot,
		attempt: func(t *testing.T, slot string) map[int]*rbOutput {
			return rcPlain(c.run(t, rcCmd{Op: "attempt", Slot: slot, Leader: 1}, gIDs))
		},
		attest: func(t *testing.T, slot string) map[int]*rbOutput {
			return rcPlain(c.run(t, rcCmd{Op: "attest", Slot: slot}, gIDs))
		},
	}
}

func rcPlainFlow(c *rbCluster) *rcFlow {
	return &rcFlow{
		longPx: c.longPx,
		slot:   c.slot,
		attempt: func(t *testing.T, slot string) map[int]*rbOutput {
			return c.run(t, "attempt", slot, 0, 1, gIDs, nil)
		},
		attest: func(t *testing.T, slot string) map[int]*rbOutput {
			return c.run(t, "attest", slot, 0, 0, gIDs, nil)
		},
	}
}

// rcCheckSetup returns the agreed output, or nil after recording a progress or safety failure.
func rcCheckSetup(t *testing.T, longPx string, outs map[int]*rbOutput, st *rcTrialState) *rbOutput {
	t.Helper()
	plain := map[int]*pdOutput{}
	finals := 0
	var first *rbOutput
	for id, o := range outs {
		plain[id] = &o.pdOutput
		if !o.Final {
			continue
		}
		finals++
		if first == nil {
			first = o
		} else if o.EventPx != first.EventPx || o.Transcript != first.Transcript {
			st.note = fmt.Sprintf("member %d finished with a different key or transcript", id)
			t.Errorf("safety: %s", st.note)
			return nil
		}
	}
	if finals != len(gIDs) {
		t.Errorf("progress: %d of %d members finished setup", finals, len(gIDs))
		return nil
	}
	(&pdCluster{longPx: longPx}).requireFinal(t, plain, nil)
	return first
}

// rcCheckAttest returns how many members saw the attestation, recording a safety failure
// if two members saw different prices.
func rcCheckAttest(t *testing.T, att map[int]*rbOutput, st *rcTrialState) int {
	t.Helper()
	attested := 0
	price := ""
	for id, o := range att {
		if !o.Attested {
			continue
		}
		attested++
		p := fmt.Sprint(o.Price)
		if price == "" {
			price = p
		} else if p != price {
			st.note = fmt.Sprintf("member %d attested a different price", id)
			t.Errorf("safety: %s", st.note)
		}
	}
	return attested
}

func rcFlowTrial(t *testing.T, f *rcFlow, st *rcTrialState) {
	st.stage = "setup"
	slot := f.slot()
	if rcCheckSetup(t, f.longPx, f.attempt(t, slot), st) == nil {
		return
	}
	st.stage = "attest"
	if n := rcCheckAttest(t, f.attest(t, slot), st); n != len(gIDs) && st.note == "" {
		t.Errorf("progress: %d of %d members saw the attestation", n, len(gIDs))
	}
}

// rcKillTrial is one kill scenario of the main test, with failures classified.
func rcKillTrial(t *testing.T, kind, point string, st *rcTrialState) {
	st.stage = "genesis"
	c := rcStart(t)
	crash := point + ":" + kind
	slot := c.slot()
	if strings.HasPrefix(kind, "pd-") {
		st.stage = "setup"
		outs := c.runCrash(t, rcCmd{Op: "attempt", Slot: slot, Leader: 1}, gIDs, 3, crash, 0, nil)
		if outs == nil {
			st.skipped = true
			return
		}
		pub := rcCheckSetup(t, c.longPx, rcPlain(outs), st)
		if pub == nil {
			return
		}
		require.GreaterOrEqual(t, len(pub.Qual), rbMinDealers)
		if kind != "pd-deal" {
			require.Contains(t, pub.Qual, 3, "the restarted dealer must keep its one deal")
		}
		return
	}
	st.stage = "setup"
	setup := c.run(t, rcCmd{Op: "attempt", Slot: slot, Leader: 1}, gIDs)
	if rcCheckSetup(t, c.longPx, rcPlain(setup), st) == nil {
		return
	}
	st.stage = "attest"
	outs := c.runCrash(t, rcCmd{Op: "attest", Slot: slot}, gIDs, 3, crash, 0, nil)
	require.NotNil(t, outs, "the crash point was not reached")
	if n := rcCheckAttest(t, rcPlain(outs), st); n == 0 || !outs[3].Attested {
		if st.note == "" {
			t.Errorf("progress: %d members saw the attestation, restarted member: %v", n, outs[3].Attested)
		}
		return
	}
	c.requireOutsideAttestation(t, slot, setup[1])
}

// rcRandomTrial kills one member at its k-th outgoing message. If the member sends fewer
// messages, nothing is killed and the trial is reported as skipped when it otherwise passes.
func rcRandomTrial(t *testing.T, victim int, attest bool, k int, point string, st *rcTrialState) {
	st.stage = "genesis"
	c := rcStart(t)
	crash := fmt.Sprintf("nth:%d:%s", k, point)
	slot := c.slot()
	if !attest {
		st.stage = "setup"
		outs, killed := c.runCrashMaybe(t, rcCmd{Op: "attempt", Slot: slot, Leader: 1}, gIDs, victim, crash, 0, nil)
		st.skipped = !killed
		if pub := rcCheckSetup(t, c.longPx, rcPlain(outs), st); pub != nil {
			require.GreaterOrEqual(t, len(pub.Qual), rbMinDealers)
		}
		return
	}
	st.stage = "setup"
	setup := c.run(t, rcCmd{Op: "attempt", Slot: slot, Leader: 1}, gIDs)
	if rcCheckSetup(t, c.longPx, rcPlain(setup), st) == nil {
		return
	}
	st.stage = "attest"
	outs, killed := c.runCrashMaybe(t, rcCmd{Op: "attest", Slot: slot}, gIDs, victim, crash, 0, nil)
	st.skipped = !killed
	if n := rcCheckAttest(t, rcPlain(outs), st); n == 0 || !outs[victim].Attested {
		if st.note == "" {
			t.Errorf("progress: %d members saw the attestation, member %d: %v", n, victim, outs[victim].Attested)
		}
		return
	}
	c.requireOutsideAttestation(t, slot, setup[1])
}

// rcSafetyScan reads each label from every relay and reports two values for one step.
func rcSafetyScan(session string, roster map[int]string, labels []string) (int, []string) {
	byPub := map[string]int{}
	for id, p := range roster {
		byPub[p] = id
	}
	var problems []string
	total := 0
	for _, label := range labels {
		full := session + "/" + label
		seen := map[string]bool{}
		values := map[string]map[string]bool{}
		for i := range nsRelays {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			r, err := nostr.RelayConnect(ctx, fmt.Sprintf("ws://127.0.0.1:%d", nsBasePort+i))
			if err != nil {
				cancel()
				problems = append(problems, fmt.Sprintf("unread: relay %d: %v", i, err))
				continue
			}
			events, err := r.QuerySync(ctx, nostr.Filter{
				Kinds: []int{nsKind}, Tags: nostr.TagMap{"t": {full}}, Limit: 500,
			})
			_ = r.Close()
			cancel()
			if err != nil {
				problems = append(problems, fmt.Sprintf("unread: relay %d: %v", i, err))
				continue
			}
			if len(events) >= 500 {
				problems = append(problems, fmt.Sprintf("unread: relay %d hit the query limit for %s", i, label))
			}
			for _, e := range events {
				m, ok := nsAccept(e, full, byPub)
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
		}
		total += len(seen)
		for key, v := range values {
			if len(v) > 1 {
				problems = append(problems, fmt.Sprintf("conflict: %s %s has %d values", label, key, len(v)))
			}
		}
	}
	return total, problems
}

func rcLadderTrials(step string, n int) []rcTrial {
	var trials []rcTrial
	switch step {
	case "1":
		for i := 1; i <= n; i++ {
			trials = append(trials, rcTrial{fmt.Sprintf("plain_%d", i), func(t *testing.T, st *rcTrialState) {
				st.stage = "genesis"
				st.plain = rbStart(t)
				rcFlowTrial(t, rcPlainFlow(st.plain), st)
			}})
		}
	case "2":
		for i := 1; i <= n; i++ {
			trials = append(trials, rcTrial{fmt.Sprintf("guard_%d", i), func(t *testing.T, st *rcTrialState) {
				st.stage = "genesis"
				rcFlowTrial(t, rcGuardFlow(t), st)
			}})
		}
	case "4":
		for _, kind := range []string{"pd-deal", "pd-vote", "pd-reveal", "pd-openvote", "vote", "partial"} {
			for _, point := range []string{"before-journal", "after-journal", "after-send"} {
				for i := 1; i <= n; i++ {
					trials = append(trials, rcTrial{
						fmt.Sprintf("%s:%s_%d", point, kind, i),
						func(t *testing.T, st *rcTrialState) { rcKillTrial(t, kind, point, st) },
					})
				}
			}
		}
	case "6":
		seed, err := strconv.ParseUint(os.Getenv(rcLadderSeedEnv), 10, 64)
		if err != nil {
			seed = 12
		}
		points := []string{"before-journal", "after-journal", "after-send"}
		for i := 1; i <= n; i++ {
			r := rand.New(rand.NewPCG(seed, uint64(i)))
			victim := gIDs[r.IntN(len(gIDs))]
			attest := r.IntN(3) == 0
			k := 1 + r.IntN(8)
			phase := "setup"
			if attest {
				k, phase = 1+r.IntN(4), "attest"
			}
			point := points[r.IntN(len(points))]
			trials = append(trials, rcTrial{
				fmt.Sprintf("seed%d_%d_member%d_%s_message%d_%s", seed, i, victim, phase, k, point),
				func(t *testing.T, st *rcTrialState) { rcRandomTrial(t, victim, attest, k, point, st) },
			})
		}
	case "5":
		for _, sc := range rcRecoveryScenarios {
			for i := 1; i <= n; i++ {
				trials = append(trials, rcTrial{
					fmt.Sprintf("%s_%d", strings.NewReplacer(" ", "_", ":", "", ",", "").Replace(sc.name), i),
					func(t *testing.T, st *rcTrialState) {
						st.stage = "scenario"
						st.failOnly = true
						sc.run(t)
					},
				})
			}
		}
	}
	return trials
}

func TestP2pFiatCrashLadder(t *testing.T) {
	step := os.Getenv(rcLadderEnv)
	if step == "" {
		t.Skip("set " + rcLadderEnv + " to run a diagnostic step")
	}
	for _, e := range []string{rcEnv, rbEnv, pdEnv, fsEnv, nsEnv} {
		if os.Getenv(e) != "" {
			t.Skip("member process")
		}
	}
	n, err := strconv.Atoi(os.Getenv(rcLadderNEnv))
	if err != nil || n <= 0 {
		n = 20
	}
	trials := rcLadderTrials(step, n)
	require.NotEmpty(t, trials, "unknown step %q", step)
	rcStartRelays(t)
	counts := map[string]int{}
	for i, trial := range trials {
		rcLatest = nil
		st := &rcTrialState{stage: "start"}
		begin := time.Now()
		passed := t.Run(trial.name, func(t *testing.T) { trial.run(t, st) })
		var session string
		var roster map[int]string
		slots := 0
		if rcLatest != nil {
			session, roster, slots = rcLatest.session, rcLatest.roster, rcLatest.slots
		} else if st.plain != nil {
			session, roster, slots = st.plain.session, st.plain.roster, st.plain.slots
		}
		scanned, problems := 0, []string(nil)
		if session != "" {
			labels := []string{rbLabel("genesis", 0)}
			for s := 1; s <= slots; s++ {
				labels = append(labels, rbLabel(fmt.Sprintf("slot-%d", s), 0))
			}
			scanned, problems = rcSafetyScan(session, roster, labels)
		}
		conflict, unread := false, false
		for _, p := range problems {
			fmt.Printf("ladder-problem: step=%s trial=%d %s\n", step, i+1, p)
			if strings.HasPrefix(p, "conflict") {
				conflict = true
			} else {
				unread = true
			}
		}
		result := "ok"
		switch {
		case st.note != "" || conflict:
			result = "safety"
		case !passed && st.failOnly:
			result = "failed"
		case !passed:
			result = "progress"
		case unread || session == "":
			result = "unchecked"
		case st.skipped:
			result = "skipped"
		}
		counts[result]++
		fmt.Printf("ladder: step=%s trial=%d name=%s result=%s stage=%s events=%d seconds=%.1f\n",
			step, i+1, trial.name, result, st.stage, scanned, time.Since(begin).Seconds())
	}
	fmt.Printf("ladder-summary: step=%s trials=%d ok=%d skipped=%d progress=%d failed=%d safety=%d unchecked=%d\n",
		step, len(trials), counts["ok"], counts["skipped"], counts["progress"], counts["failed"], counts["safety"],
		counts["unchecked"])
}
