package e2e_test

// Experiment 14: full end-to-end integration of p2pFiat on regtest.
//
// Connects every component tested separately in experiments 1-13:
//   1. Live 4-of-7 threshold oracle over 3 real strfry Nostr relays (NIP-44
//      encrypted DKG shares, 20-digit BIP-340 attestations, 2 members offline).
//   2. Real numeric DLC ($1,000 stable position, 2,000,000 sats collateral,
//      +/-25% band [$75k..$125k], $10 payout rounding, binary prefix cover).
//   3. Live arkd regtest server with 22-path Tapscript VTXOs and real Ark batch
//      rolls by a 3-of-5 nostracle quorum for an offline user.
//   4. Keyless watchtower with a tiered P2TR onchain exit bounty (W1 immediate,
//      W2/W3 after 4-block CSV) unrolling a rolled numeric DLC after arkd stops.
//
// Needs helpers from ../01-offline-settlement, ../02-failure-paths,
// ../04-guardian-rolling-dlc and ../13-watchtower-bounty. Copy all five test
// files into arkd's internal/test/e2e directory and run with:
//   go test -v -count 1 -timeout 600s -run TestP2pFiatEndToEnd ./internal/test/e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/bits"
	"os/exec"
	"slices"
	"sort"
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
	batchsession "github.com/arkade-os/arkd/pkg/client-lib/batch-session"
	wallet "github.com/arkade-os/arkd/pkg/client-wallet"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip44"
	"github.com/stretchr/testify/require"
)

const (
	e2eStrfryImage  = "ghcr.io/hoytech/strfry@sha256:36f1886d185a88ca57c66ebe52e6e9e8428dac2486eea0a5d50ff934f18b60c3"
	e2eNostrKind    = 9871
	e2eNumRelays    = 3
	e2eBasePort     = 17881
	e2eOracleT      = 4
	e2eOracleN      = 7
	e2eNumDigits    = 20
	e2eMaxPrice     = uint32(1<<e2eNumDigits - 1)
	e2eNotionalUSD  = int64(1000)
	e2eOpenPriceUSD = int64(100_000)
	e2eCollateral   = int64(2_000_000)
	e2eRoundingSats = int64(100) // ~$0.10 at $100k, rounded to $10 bands via step
	e2eBandPct      = int64(25)  // [$75,000 .. $125,000]
	e2ePayoutStep   = int64(10_000) // ~100 satoshi-buckets (~$10 USD steps -> ~160 prefixes)
)

// -----------------------------------------------------------------------------
// Part 1: Numeric DLC prefix decomposition (from Experiment 5)
// -----------------------------------------------------------------------------

type e2ePrefix struct {
	val  uint32
	bits uint8
}

func (p e2ePrefix) interval() (uint32, uint32) {
	shift := e2eNumDigits - uint(p.bits)
	lo := p.val << shift
	return lo, lo + (1 << shift) - 1
}

func (p e2ePrefix) contains(v uint32) bool {
	lo, hi := p.interval()
	return v >= lo && v <= hi
}

func e2eCover(a, b uint32) []e2ePrefix {
	var out []e2ePrefix
	for x := uint64(a); x <= uint64(b); {
		k := uint(e2eNumDigits)
		if x != 0 {
			k = min(k, uint(bits.TrailingZeros64(x)))
		}
		for x+(1<<k)-1 > uint64(b) {
			k--
		}
		out = append(out, e2ePrefix{val: uint32(x >> k), bits: uint8(e2eNumDigits - k)})
		x += 1 << k
	}
	return out
}

func e2ePayoutForPrice(price uint32) [2]int64 {
	lo := uint32(e2eOpenPriceUSD * (100 - e2eBandPct) / 100)
	hi := uint32(e2eOpenPriceUSD * (100 + e2eBandPct) / 100)
	p := min(max(price, lo), hi)
	u := min(e2eNotionalUSD*100_000_000/int64(p), e2eCollateral)
	u = (u + e2ePayoutStep/2) / e2ePayoutStep * e2ePayoutStep
	u = min(max(u, 10_000), e2eCollateral-10_000)
	return [2]int64{u, e2eCollateral - u}
}

type e2eNumericRange struct {
	prefix  e2ePrefix
	lo, hi  uint32
	amounts [2]int64
}

func e2eBuildNumericRanges() []e2eNumericRange {
	var out []e2eNumericRange
	start := uint32(0)
	cur := e2ePayoutForPrice(0)
	flush := func(end uint32, amt [2]int64) {
		for _, p := range e2eCover(start, end) {
			lo, hi := p.interval()
			out = append(out, e2eNumericRange{prefix: p, lo: lo, hi: hi, amounts: amt})
		}
	}
	for p := uint32(1); p <= e2eMaxPrice; p++ {
		if amt := e2ePayoutForPrice(p); amt != cur {
			flush(p-1, cur)
			start, cur = p, amt
		}
	}
	flush(e2eMaxPrice, cur)
	return out
}

func e2eAttestationMsg(bit byte) []byte {
	tag := sha256.Sum256([]byte("DLC/oracle/attestation/v0"))
	h := sha256.New()
	h.Write(tag[:])
	h.Write(tag[:])
	h.Write([]byte{bit})
	return h.Sum(nil)
}

// -----------------------------------------------------------------------------
// Part 2: Live 4-of-7 Threshold Oracle over 3 real strfry Nostr relays
// -----------------------------------------------------------------------------

type e2eRelayCluster struct {
	urls       []string
	containers []string
}

func startStrfryCluster(t *testing.T) *e2eRelayCluster {
	t.Helper()
	cl := &e2eRelayCluster{}
	// Bind to 0.0.0.0 inside container and disable compression (go-nostr v0.40.1 / Go 1.27).
	startScript := `sed -e 's/bind = "127.0.0.1"/bind = "0.0.0.0"/' -e '/compression {/,/}/ s/enabled = true/enabled = false/' /app/strfry.conf > /tmp/s.conf && exec /app/strfry --config /tmp/s.conf relay`
	for i := range e2eNumRelays {
		port := e2eBasePort + i
		name := fmt.Sprintf("p2pfiat-e2e-strfry-%d-%d", port, time.Now().UnixNano()%100000)
		cmd := exec.Command(
			"docker", "run", "-d", "--rm", "--name", name,
			"-p", fmt.Sprintf("127.0.0.1:%d:7777", port),
			"--entrypoint", "sh", e2eStrfryImage, "-c", startScript,
		)
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "start strfry %s: %s", name, string(out))
		cl.containers = append(cl.containers, name)
		cl.urls = append(cl.urls, fmt.Sprintf("ws://127.0.0.1:%d", port))
	}
	t.Cleanup(func() {
		for _, name := range cl.containers {
			_ = exec.Command("docker", "rm", "-f", name).Run()
		}
	})
	for _, u := range cl.urls {
		require.Eventually(t, func() bool {
			cctx, cancel := context.WithTimeout(context.Background(), time.Second)
			r, err := nostr.RelayConnect(cctx, u)
			cancel()
			if err != nil {
				return false
			}
			_ = r.Close()
			return true
		}, 20*time.Second, 200*time.Millisecond, "strfry %s not ready", u)
	}
	return cl
}

func (c *e2eRelayCluster) connect(t *testing.T, ctx context.Context) []*nostr.Relay {
	t.Helper()
	relays := make([]*nostr.Relay, 0, len(c.urls))
	for _, u := range c.urls {
		r, err := nostr.RelayConnect(ctx, u)
		require.NoError(t, err, "connect %s", u)
		relays = append(relays, r)
	}
	return relays
}

func e2ePublishAll(t *testing.T, ctx context.Context, relays []*nostr.Relay, evt nostr.Event) {
	t.Helper()
	published := 0
	for _, r := range relays {
		if err := r.Publish(ctx, evt); err == nil {
			published++
		}
	}
	require.Greater(t, published, 0, "event failed to publish to any strfry relay")
}

func e2eQuerySession(
	t *testing.T, ctx context.Context, relays []*nostr.Relay, session string, wantType string, wantCount int,
) []*nostr.Event {
	t.Helper()
	var result []*nostr.Event
	require.Eventually(t, func() bool {
		seen := map[string]*nostr.Event{}
		for _, r := range relays {
			evts, err := r.QuerySync(ctx, nostr.Filter{
				Kinds: []int{e2eNostrKind},
				Tags:  nostr.TagMap{"t": []string{session}},
			})
			if err != nil {
				continue
			}
			for _, ev := range evts {
				if !ev.CheckID() {
					continue
				}
				ok, err := ev.CheckSignature()
				if err != nil || !ok {
					continue
				}
				var w e2eOracleWire
				if json.Unmarshal([]byte(ev.Content), &w) != nil || w.Type != wantType {
					continue
				}
				seen[ev.ID] = ev
			}
		}
		if len(seen) < wantCount {
			return false
		}
		result = make([]*nostr.Event, 0, len(seen))
		for _, ev := range seen {
			result = append(result, ev)
		}
		sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
		return true
	}, 20*time.Second, 150*time.Millisecond, "waiting for %d %s events in session %s", wantCount, wantType, session)
	return result
}

type e2eOracleWire struct {
	Type    string         `json:"type"`
	From    int            `json:"from"`
	Commits [][]string     `json:"commits,omitempty"` // [21][4] compressed points
	Shares  map[int]string `json:"shares,omitempty"`  // recipientID -> NIP-44 ciphertext of 21 scalars
	EventPx string         `json:"event_px,omitempty"`
	Rx      []string       `json:"rx,omitempty"`
	Price   uint32         `json:"price,omitempty"`
	Partial []string       `json:"partial,omitempty"` // 20 partial sig scalars
}

type e2eEventShares struct {
	keyShare   btcec.ModNScalar
	nonceShare [e2eNumDigits]btcec.ModNScalar
}

type e2eOracleMember struct {
	id      int
	nostrSK string
	nostrPK string
	events  map[string]*e2eEventShares
}

type e2eOracleAnnouncement struct {
	session  string
	eventPub *btcec.PublicKey
	eventPx  []byte
	rx       [e2eNumDigits][]byte
	digit    [e2eNumDigits][2]btcec.JacobianPoint
}

func (a *e2eOracleAnnouncement) anticipationPoint(p e2ePrefix) *btcec.PublicKey {
	var sum btcec.JacobianPoint
	for i := range int(p.bits) {
		bit := (p.val >> (uint(p.bits) - 1 - uint(i))) & 1
		var next btcec.JacobianPoint
		btcec.AddNonConst(&sum, &a.digit[i][bit], &next)
		sum = next
	}
	sum.ToAffine()
	return btcec.NewPublicKey(&sum.X, &sum.Y)
}

func e2eScalarInt(v int) btcec.ModNScalar {
	var s btcec.ModNScalar
	s.SetInt(uint32(v))
	return s
}

func e2eMulG(s *btcec.ModNScalar) btcec.JacobianPoint {
	var p btcec.JacobianPoint
	btcec.ScalarBaseMultNonConst(s, &p)
	p.ToAffine()
	return p
}

func e2eAdd(a, b *btcec.JacobianPoint) btcec.JacobianPoint {
	var p btcec.JacobianPoint
	btcec.AddNonConst(a, b, &p)
	p.ToAffine()
	return p
}

func e2eMul(s *btcec.ModNScalar, a *btcec.JacobianPoint) btcec.JacobianPoint {
	var p btcec.JacobianPoint
	btcec.ScalarMultNonConst(s, a, &p)
	p.ToAffine()
	return p
}

func e2eLagrange(ids []int, id int) btcec.ModNScalar {
	num := e2eScalarInt(1)
	den := e2eScalarInt(1)
	xi := e2eScalarInt(id)
	for _, j := range ids {
		if j == id {
			continue
		}
		xj := e2eScalarInt(j)
		num.Mul(&xj)
		var diff btcec.ModNScalar
		diff.Set(&xj)
		negXi := xi
		negXi.Negate()
		diff.Add(&negXi)
		den.Mul(&diff)
	}
	den.InverseNonConst()
	num.Mul(&den)
	return num
}

type e2eThresholdOracle struct {
	cluster *e2eRelayCluster
	members [e2eOracleN]*e2eOracleMember
}

func newE2EThresholdOracle(t *testing.T, cluster *e2eRelayCluster) *e2eThresholdOracle {
	t.Helper()
	o := &e2eThresholdOracle{cluster: cluster}
	for i := range e2eOracleN {
		sk := nostr.GeneratePrivateKey()
		pk, err := nostr.GetPublicKey(sk)
		require.NoError(t, err)
		o.members[i] = &e2eOracleMember{
			id: i + 1, nostrSK: sk, nostrPK: pk,
			events: map[string]*e2eEventShares{},
		}
	}
	return o
}

// setupEvent runs a 4-of-7 Feldman VSS DKG for 1 event key + 20 digit nonces
// over the 3 real strfry Nostr relays with NIP-44 encrypted shares.
func (o *e2eThresholdOracle) setupEvent(
	t *testing.T, ctx context.Context, session string,
) *e2eOracleAnnouncement {
	t.Helper()
	relays := o.cluster.connect(t, ctx)
	defer func() {
		for _, r := range relays {
			_ = r.Close()
		}
	}()

	const instances = 1 + e2eNumDigits // 0 = event key, 1..20 = digit nonces
	// 1. Each of the 7 members deals commitments + NIP-44 encrypted shares.
	for _, m := range o.members {
		commits := make([][]string, instances)
		perRecipient := make([][instances][32]byte, e2eOracleN)
		for inst := range instances {
			coeffs := make([]btcec.ModNScalar, e2eOracleT)
			commits[inst] = make([]string, e2eOracleT)
			for c := range e2eOracleT {
				k, err := btcec.NewPrivateKey()
				require.NoError(t, err)
				coeffs[c] = k.Key
				pt := e2eMulG(&coeffs[c])
				commits[inst][c] = hex.EncodeToString(btcec.NewPublicKey(&pt.X, &pt.Y).SerializeCompressed())
			}
			for rIdx, rec := range o.members {
				x := e2eScalarInt(rec.id)
				var share, xp btcec.ModNScalar
				xp.SetInt(1)
				for c := range e2eOracleT {
					var term btcec.ModNScalar
					term.Set(&coeffs[c])
					term.Mul(&xp)
					share.Add(&term)
					xp.Mul(&x)
				}
				perRecipient[rIdx][inst] = share.Bytes()
			}
		}

		encShares := map[int]string{}
		for rIdx, rec := range o.members {
			var raw bytes.Buffer
			for inst := range instances {
				raw.Write(perRecipient[rIdx][inst][:])
			}
			convKey, err := nip44.GenerateConversationKey(rec.nostrPK, m.nostrSK)
			require.NoError(t, err)
			ct, err := nip44.Encrypt(hex.EncodeToString(raw.Bytes()), convKey)
			require.NoError(t, err)
			encShares[rec.id] = ct
		}

		payload, err := json.Marshal(e2eOracleWire{
			Type: "deal", From: m.id, Commits: commits, Shares: encShares,
		})
		require.NoError(t, err)
		evt := nostr.Event{
			PubKey:    m.nostrPK,
			CreatedAt: nostr.Now(),
			Kind:      e2eNostrKind,
			Tags:      nostr.Tags{{"t", session}},
			Content:   string(payload),
		}
		require.NoError(t, evt.Sign(m.nostrSK))
		e2ePublishAll(t, ctx, relays, evt)
	}

	// 2. All 7 members fetch deals from strfry, verify Feldman VSS + decrypt NIP-44 shares.
	dealEvts := e2eQuerySession(t, ctx, relays, session, "deal", e2eOracleN)
	byID := map[int]e2eOracleWire{}
	byPK := map[int]string{}
	for _, ev := range dealEvts {
		var w e2eOracleWire
		require.NoError(t, json.Unmarshal([]byte(ev.Content), &w))
		byID[w.From] = w
		byPK[w.From] = ev.PubKey
	}
	require.Len(t, byID, e2eOracleN)

	// Sum C_0 across all 7 dealers to get public P and R_0..R_19.
	var groupPts [instances]btcec.JacobianPoint
	for inst := range instances {
		for id := 1; id <= e2eOracleN; id++ {
			cb, err := hex.DecodeString(byID[id].Commits[inst][0])
			require.NoError(t, err)
			pk, err := btcec.ParsePubKey(cb)
			require.NoError(t, err)
			var jp btcec.JacobianPoint
			pk.AsJacobian(&jp)
			if id == 1 {
				groupPts[inst] = jp
			} else {
				groupPts[inst] = e2eAdd(&groupPts[inst], &jp)
			}
		}
	}

	var oddParity [instances]bool
	for inst := range instances {
		if groupPts[inst].Y.IsOdd() {
			oddParity[inst] = true
			groupPts[inst].Y.Negate(1)
			groupPts[inst].Y.Normalize()
		}
	}

	// Each member decrypts its 7 incoming shares, verifies Feldman VSS, sums them,
	// and negates for even-Y BIP-340 parity.
	for _, m := range o.members {
		var total [instances]btcec.ModNScalar
		x := e2eScalarInt(m.id)
		for dealerID := 1; dealerID <= e2eOracleN; dealerID++ {
			w := byID[dealerID]
			convKey, err := nip44.GenerateConversationKey(byPK[dealerID], m.nostrSK)
			require.NoError(t, err)
			plainHex, err := nip44.Decrypt(w.Shares[m.id], convKey)
			require.NoError(t, err)
			raw, err := hex.DecodeString(plainHex)
			require.NoError(t, err)
			require.Len(t, raw, instances*32)
			for inst := range instances {
				var s btcec.ModNScalar
				s.SetByteSlice(raw[inst*32 : (inst+1)*32])
				// Verify s*G == sum C_k * x^k
				lhs := e2eMulG(&s)
				var rhs btcec.JacobianPoint
				var xp btcec.ModNScalar
				xp.SetInt(1)
				for c := range e2eOracleT {
					cb, err := hex.DecodeString(w.Commits[inst][c])
					require.NoError(t, err)
					pk, err := btcec.ParsePubKey(cb)
					require.NoError(t, err)
					var cp btcec.JacobianPoint
					pk.AsJacobian(&cp)
					term := e2eMul(&xp, &cp)
					if c == 0 {
						rhs = term
					} else {
						rhs = e2eAdd(&rhs, &term)
					}
					xp.Mul(&x)
				}
				require.True(t, lhs.X.Equals(&rhs.X) && lhs.Y.Equals(&rhs.Y), "VSS check failed")
				total[inst].Add(&s)
			}
		}
		for inst := range instances {
			if oddParity[inst] {
				total[inst].Negate()
			}
		}
		es := &e2eEventShares{keyShare: total[0]}
		for d := range e2eNumDigits {
			es.nonceShare[d] = total[1+d]
		}
		m.events[session] = es
	}

	eventPxBytes := groupPts[0].X.Bytes()
	eventPub, err := schnorr.ParsePubKey(eventPxBytes[:])
	require.NoError(t, err)
	ann := &e2eOracleAnnouncement{
		session:  session,
		eventPub: eventPub,
		eventPx:  append([]byte{}, eventPxBytes[:]...),
	}
	rxHex := make([]string, e2eNumDigits)
	for d := range e2eNumDigits {
		rxb := groupPts[1+d].X.Bytes()
		ann.rx[d] = append([]byte{}, rxb[:]...)
		rxHex[d] = hex.EncodeToString(ann.rx[d])
		for b := range 2 {
			e := bip340Challenge(ann.rx[d], ann.eventPx, e2eAttestationMsg(byte('0'+b)))
			eP := e2eMul(&e, &groupPts[0])
			ann.digit[d][b] = e2eAdd(&groupPts[1+d], &eP)
		}
	}

	// Publish public announcement event to strfry so outside clients can read it.
	annPayload, err := json.Marshal(e2eOracleWire{
		Type: "announce", From: 1, EventPx: hex.EncodeToString(ann.eventPx), Rx: rxHex,
	})
	require.NoError(t, err)
	annEvt := nostr.Event{
		PubKey:    o.members[0].nostrPK,
		CreatedAt: nostr.Now(),
		Kind:      e2eNostrKind,
		Tags:      nostr.Tags{{"t", session}},
		Content:   string(annPayload),
	}
	require.NoError(t, annEvt.Sign(o.members[0].nostrSK))
	e2ePublishAll(t, ctx, relays, annEvt)
	return ann
}

// attestPrice has the given online members (e.g. 5 of 7, with 2 offline) vote
// and publish 20 threshold partial signatures on the 3 strfry relays, then has
// an independent outside client read and verify all 20 BIP-340 digit signatures
// purely from the strfry relays.
func (o *e2eThresholdOracle) attestPrice(
	t *testing.T, ctx context.Context, ann *e2eOracleAnnouncement,
	onlineIDs []int, price uint32,
) (uint32, [e2eNumDigits]btcec.ModNScalar) {
	t.Helper()
	require.GreaterOrEqual(t, len(onlineIDs), e2eOracleT)
	relays := o.cluster.connect(t, ctx)
	defer func() {
		for _, r := range relays {
			_ = r.Close()
		}
	}()

	// 1. Online members publish price votes on strfry.
	for _, id := range onlineIDs {
		m := o.members[id-1]
		payload, err := json.Marshal(e2eOracleWire{Type: "vote", From: m.id, Price: price})
		require.NoError(t, err)
		evt := nostr.Event{
			PubKey: m.nostrPK, CreatedAt: nostr.Now(), Kind: e2eNostrKind,
			Tags: nostr.Tags{{"t", ann.session}}, Content: string(payload),
		}
		require.NoError(t, evt.Sign(m.nostrSK))
		e2ePublishAll(t, ctx, relays, evt)
	}
	// Verify >= 5 matching votes (fast path) are visible on strfry.
	voteEvts := e2eQuerySession(t, ctx, relays, ann.session, "vote", len(onlineIDs))
	require.GreaterOrEqual(t, len(voteEvts), 5, "fast path requires >= 5 votes")

	// 2. Online members publish 20 raw partial shares (k_i + e_i * x_i) on strfry.
	for _, id := range onlineIDs {
		m := o.members[id-1]
		es := m.events[ann.session]
		require.NotNil(t, es, "missing event shares for session %s", ann.session)
		partials := make([]string, e2eNumDigits)
		for d := range e2eNumDigits {
			bit := byte('0' + (price>>(e2eNumDigits-1-uint(d)))&1)
			e := bip340Challenge(ann.rx[d], ann.eventPx, e2eAttestationMsg(bit))
			var s btcec.ModNScalar
			s.Set(&e)
			s.Mul(&es.keyShare)
			s.Add(&es.nonceShare[d])
			sb := s.Bytes()
			partials[d] = hex.EncodeToString(sb[:])
		}
		payload, err := json.Marshal(e2eOracleWire{
			Type: "sig", From: m.id, Price: price, Partial: partials,
		})
		require.NoError(t, err)
		evt := nostr.Event{
			PubKey: m.nostrPK, CreatedAt: nostr.Now(), Kind: e2eNostrKind,
			Tags: nostr.Tags{{"t", ann.session}}, Content: string(payload),
		}
		require.NoError(t, evt.Sign(m.nostrSK))
		e2ePublishAll(t, ctx, relays, evt)
	}

	// 3. Outside client (zero secrets) reads partial sigs from strfry, combines
	//    the first 4 via Lagrange interpolation, and verifies all 20 BIP-340 sigs.
	sigEvts := e2eQuerySession(t, ctx, relays, ann.session, "sig", e2eOracleT)
	signerIDs := make([]int, 0, e2eOracleT)
	partialsByID := map[int][e2eNumDigits]btcec.ModNScalar{}
	var attestedPrice uint32
	for _, ev := range sigEvts {
		var w e2eOracleWire
		require.NoError(t, json.Unmarshal([]byte(ev.Content), &w))
		if _, dup := partialsByID[w.From]; dup {
			continue
		}
		attestedPrice = w.Price
		var arr [e2eNumDigits]btcec.ModNScalar
		for d := range e2eNumDigits {
			b, err := hex.DecodeString(w.Partial[d])
			require.NoError(t, err)
			arr[d].SetByteSlice(b)
		}
		partialsByID[w.From] = arr
		signerIDs = append(signerIDs, w.From)
		if len(signerIDs) == e2eOracleT {
			break
		}
	}
	require.Len(t, signerIDs, e2eOracleT)

	var combined [e2eNumDigits]btcec.ModNScalar
	for d := range e2eNumDigits {
		for _, id := range signerIDs {
			lam := e2eLagrange(signerIDs, id)
			term := partialsByID[id][d]
			term.Mul(&lam)
			combined[d].Add(&term)
		}
		sb := combined[d].Bytes()
		sigBytes := append(append([]byte{}, ann.rx[d]...), sb[:]...)
		sig, err := schnorr.ParseSignature(sigBytes)
		require.NoError(t, err)
		bit := byte('0' + (attestedPrice>>(e2eNumDigits-1-uint(d)))&1)
		require.True(t, sig.Verify(e2eAttestationMsg(bit), ann.eventPub),
			"BIP-340 verification failed for digit %d", d)
	}
	return attestedPrice, combined
}

func e2ePrefixSecret(p e2ePrefix, digitSigs [e2eNumDigits]btcec.ModNScalar) btcec.ModNScalar {
	var sum btcec.ModNScalar
	for i := range int(p.bits) {
		sum.Add(&digitSigs[i])
	}
	return sum
}

// -----------------------------------------------------------------------------
// Part 3: Numeric Rolling DLC on arkd + Keyless Watchtower Bounty
// -----------------------------------------------------------------------------

type e2eNumericCoin struct {
	m        *guardianMandate
	coin     *guardianCoin
	funder   wallet.Wallet
	outpoint wire.OutPoint
	quorum   guardianQuorum
	bounty   *bountyScript
	ranges   []e2eNumericRange
	arks     []*guardianArkPayout
	exits    []*guardianExitPayout
}

func (o *e2eNumericCoin) clientOutpoint() clientlib.Outpoint {
	return clientlib.Outpoint{Txid: o.outpoint.Hash.String(), VOut: o.outpoint.Index}
}

func (o *e2eNumericCoin) signNumericPayouts(
	t *testing.T, q guardianQuorum, ann *e2eOracleAnnouncement, bounty *bountyScript, ranges []e2eNumericRange,
) {
	t.Helper()
	o.quorum = q
	o.bounty = bounty
	o.ranges = ranges
	o.arks = make([]*guardianArkPayout, len(ranges))
	o.exits = make([]*guardianExitPayout, len(ranges))

	signers := o.m.signers(q)
	uArkPk := ownerPkScript(t, o.m.user.pub, o.m.signer)
	lArkPk := ownerPkScript(t, o.m.lp.pub, o.m.signer)
	uChainPk, err := script.P2TRScript(o.m.user.pub)
	require.NoError(t, err)
	lChainPk, err := script.P2TRScript(o.m.lp.pub)
	require.NoError(t, err)

	seq, err := arklib.BIP68Sequence(arklib.RelativeLocktime{
		Type: arklib.LocktimeTypeBlock, Value: guardianQuorumDelay,
	})
	require.NoError(t, err)
	deductPerSide := (wtExitTxFee + wtBountyAmount) / 2
	fetcher := txscript.NewCannedPrevOutputFetcher(o.coin.pkScript, e2eCollateral)
	exitLeaf := o.coin.exitLeaf[q]
	qLeaf := o.coin.quorumLeaf[q]

	adaptAll := func(msg []byte, T *btcec.PublicKey) []*adaptorSig {
		sigs := make([]*adaptorSig, len(signers))
		for i, s := range signers {
			sigs[i] = adaptorSign(t, s.d, s.pub, msg, T)
		}
		return sigs
	}

	for idx, r := range ranges {
		T := ann.anticipationPoint(r.prefix)

		// 1. Offchain Ark settlement tx + checkpoint tx
		arkPtx, checkpoints, err := offchain.BuildTxs(
			[]offchain.VtxoInput{{
				Outpoint:           &o.outpoint,
				Amount:             e2eCollateral,
				Tapscript:          qLeaf.tapscript,
				RevealedTapscripts: o.coin.revealed,
			}},
			[]*wire.TxOut{
				{Value: r.amounts[0], PkScript: uArkPk},
				{Value: r.amounts[1], PkScript: lArkPk},
			},
			o.m.checkpoint,
		)
		require.NoError(t, err)
		arkPtx.UnsignedTx.LockTime = o.coin.term
		arkPtx.UnsignedTx.TxIn[0].Sequence = wire.MaxTxInSequenceNum - 1
		arkMsg := tapscriptSighash(t, arkPtx)
		cpMsg := tapscriptSighash(t, checkpoints[0])
		arkB64, err := arkPtx.B64Encode()
		require.NoError(t, err)
		cpB64, err := checkpoints[0].B64Encode()
		require.NoError(t, err)
		o.arks[idx] = &guardianArkPayout{
			arkB64: arkB64, checkpointB64: cpB64, arkMsg: arkMsg, checkpointMsg: cpMsg,
			arkSigs: adaptAll(arkMsg, T), cpSigs: adaptAll(cpMsg, T),
		}

		// 2. Onchain exit payout tx WITH tiered P2TR watchtower bounty output
		tx := wire.NewMsgTx(2)
		tx.AddTxIn(&wire.TxIn{PreviousOutPoint: o.outpoint, Sequence: seq})
		tx.AddTxOut(&wire.TxOut{Value: r.amounts[0] - deductPerSide, PkScript: uChainPk})
		tx.AddTxOut(&wire.TxOut{Value: r.amounts[1] - deductPerSide, PkScript: lChainPk})
		tx.AddTxOut(&wire.TxOut{Value: wtBountyAmount, PkScript: bounty.pkScript})
		exitMsg, err := txscript.CalcTapscriptSignaturehash(
			txscript.NewTxSigHashes(tx, fetcher), txscript.SigHashDefault, tx, 0, fetcher,
			txscript.NewBaseTapLeaf(exitLeaf.script),
		)
		require.NoError(t, err)
		o.exits[idx] = &guardianExitPayout{tx: tx, msg: exitMsg, sigs: adaptAll(exitMsg, T)}
	}
}

func openE2ENumericCoin(
	t *testing.T, ctx context.Context, m *guardianMandate, term uint32,
	ann *e2eOracleAnnouncement, bounty *bountyScript, ranges []e2eNumericRange,
) *e2eNumericCoin {
	t.Helper()
	funder := setupClientWallet(t)
	faucetOffchain(t, funder, 0.021)
	coin := m.coin(t, term)
	res, err := sendOffChainBounded(
		ctx, funder, []clientlib.Receiver{{To: coin.addr, Amount: uint64(e2eCollateral)}},
	)
	require.NoError(t, err)
	var ptx *psbt.Packet
	require.Eventually(t, func() bool {
		resp, err := funder.Indexer().GetVirtualTxs(ctx, []string{res.Txid})
		if err != nil || resp == nil || len(resp.Txs) == 0 {
			return false
		}
		ptx = parsePsbt(t, resp.Txs[0])
		return true
	}, 30*time.Second, 200*time.Millisecond)
	vout := slices.IndexFunc(ptx.UnsignedTx.TxOut, func(out *wire.TxOut) bool {
		return bytes.Equal(out.PkScript, coin.pkScript)
	})
	require.GreaterOrEqual(t, vout, 0)
	o := &e2eNumericCoin{
		m: m, coin: coin, funder: funder,
		outpoint: wire.OutPoint{Hash: ptx.UnsignedTx.TxHash(), Index: uint32(vout)},
	}
	guardianWaitVtxo(t, ctx, funder, o.clientOutpoint())
	o.signNumericPayouts(t, guardianQuorum{0, 1, 2}, ann, bounty, ranges)
	return o
}

// rollNumeric moves the 2,000,000 sat numeric DLC into a new coin in a real
// arkd batch. The quorum signs ALL numeric prefixes (offchain + onchain exit
// with bounty) for the new coin BEFORE signing the forfeit of the old coin.
func (o *e2eNumericCoin) rollNumeric(
	t *testing.T, ctx context.Context, q guardianQuorum, nextTerm uint32,
	nextAnn *e2eOracleAnnouncement, bounty *bountyScript, ranges []e2eNumericRange,
) *e2eNumericCoin {
	t.Helper()
	next := o.m.coin(t, nextTerm)
	sessions := make([]tree.SignerSession, 3)
	cosigners := make([]string, 3)
	var err error
	for i := range sessions {
		sessions[i], err = tree.NewVtxoTreeSigner()
		require.NoError(t, err)
		cosigners[i] = sessions[i].GetPublicKey()
	}

	// Register intent spending old coin via quorum leaf.
	message, err := intent.RegisterMessage{
		BaseMessage:         intent.BaseMessage{Type: intent.IntentMessageTypeRegister},
		CosignersPublicKeys: cosigners,
	}.Encode()
	require.NoError(t, err)
	proof, err := intent.New(message, []intent.Input{{
		OutPoint:    &o.outpoint,
		Sequence:    wire.MaxTxInSequenceNum - 1,
		WitnessUtxo: &wire.TxOut{Value: e2eCollateral, PkScript: o.coin.pkScript},
	}}, []*wire.TxOut{{Value: e2eCollateral, PkScript: next.pkScript}})
	require.NoError(t, err)
	leaf := o.coin.quorumLeaf[q]
	tapLeaf := &psbt.TaprootTapLeafScript{
		ControlBlock: leaf.ctrl, Script: leaf.script, LeafVersion: txscript.BaseLeafVersion,
	}
	proof.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{tapLeaf}
	proof.Inputs[1].TaprootLeafScript = []*psbt.TaprootTapLeafScript{tapLeaf}
	proof.UnsignedTx.LockTime = o.coin.term
	proof.UnsignedTx.TxIn[0].Sequence = wire.MaxTxInSequenceNum - 1
	require.NoError(t, txutils.SetArkPsbtField(
		&proof.Packet, 1, txutils.VtxoTaprootTreeField, txutils.TapTree(o.coin.revealed),
	))
	signers := o.m.signers(q)
	guardianSignInput(t, &proof.Packet, 0, leaf.script, signers)
	guardianSignInput(t, &proof.Packet, 1, leaf.script, signers)
	encoded, err := proof.B64Encode()
	require.NoError(t, err)
	client := o.funder.Client()
	intentID, err := client.RegisterIntent(ctx, encoded, message)
	require.NoError(t, err)

	config, err := o.funder.GetConfigData(ctx)
	require.NoError(t, err)
	forfeitAddr, err := arklib.DecodeBitcoinAddress(config.ForfeitAddress, nil)
	require.NoError(t, err)
	forfeitPk, err := txscript.PayToAddrScript(forfeitAddr)
	require.NoError(t, err)

	rolled := &e2eNumericCoin{m: o.m, coin: next, funder: o.funder}
	var batchExpiry arklib.RelativeLocktime
	var batchID string
	handler := &customBatchEventsHandler{
		onBatchStarted: func(ctx context.Context, event clientlib.BatchStartedEvent) (bool, time.Duration, error) {
			hash := sha256.Sum256([]byte(intentID))
			if !slices.Contains(event.HashedIntentIds, hex.EncodeToString(hash[:])) {
				return true, -1, nil
			}
			if err := client.ConfirmRegistration(ctx, intentID); err != nil {
				return false, -1, err
			}
			batchID = event.Id
			batchExpiry = getBatchExpiryLocktime(uint32(event.BatchExpiry))
			return false, time.Duration(event.BatchExpiry) * time.Second, nil
		},
		onBatchFailed: func(_ context.Context, event clientlib.BatchFailedEvent) error {
			if event.Id == batchID {
				return fmt.Errorf("batch failed: %s", event.Reason)
			}
			return nil
		},
		onTreeSigningStarted: func(ctx context.Context, event clientlib.TreeSigningStartedEvent, vtxoTree *tree.TxTree) (bool, error) {
			if !slices.Contains(event.CosignersPubkeys, cosigners[0]) {
				return true, nil
			}
			sweep := script.CSVMultisigClosure{
				MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{config.ForfeitPubKey}},
				Locktime:        batchExpiry,
			}
			sweepScript, err := sweep.Script()
			if err != nil {
				return false, err
			}
			commitment, err := psbt.NewFromRawBytes(strings.NewReader(event.UnsignedCommitmentTx), true)
			if err != nil {
				return false, err
			}
			root := txscript.AssembleTaprootScriptTree(txscript.NewBaseTapLeaf(sweepScript)).RootNode.TapHash()
			for _, session := range sessions {
				if err := session.Init(root.CloneBytes(), commitment.UnsignedTx.TxOut[0].Value, vtxoTree); err != nil {
					return false, err
				}
				nonces, err := session.GetNonces()
				if err != nil {
					return false, err
				}
				if err := client.SubmitTreeNonces(ctx, event.Id, session.GetPublicKey(), nonces); err != nil {
					return false, err
				}
			}
			return false, nil
		},
		onTreeNoncesAggregated: func(ctx context.Context, event clientlib.TreeNoncesAggregatedEvent) (bool, error) {
			for _, session := range sessions {
				session.SetAggregatedNonces(event.Nonces)
				sigs, err := session.Sign()
				if err != nil {
					return false, err
				}
				if err := client.SubmitTreeSignatures(ctx, event.Id, session.GetPublicKey(), sigs); err != nil {
					return false, err
				}
			}
			return true, nil
		},
		onBatchFinalization: func(ctx context.Context, _ clientlib.BatchFinalizationEvent, vtxoTree, connectorTree *tree.TxTree) ([]string, error) {
			found := false
			for _, l := range vtxoTree.Leaves() {
				for vout, out := range l.UnsignedTx.TxOut {
					if out.Value == e2eCollateral && bytes.Equal(out.PkScript, next.pkScript) {
						rolled.outpoint = wire.OutPoint{Hash: l.UnsignedTx.TxHash(), Index: uint32(vout)}
						found = true
					}
				}
			}
			if !found {
				return nil, fmt.Errorf("new numeric contract coin not in batch")
			}
			// Critical safety rule: sign ALL new numeric DLC payouts BEFORE forfeiting the old coin.
			rolled.signNumericPayouts(t, q, nextAnn, bounty, ranges)

			connector := connectorTree.Leaves()[0]
			forfeit, err := tree.BuildForfeitTxWithOutput(
				[]*wire.OutPoint{&o.outpoint},
				[]uint32{wire.MaxTxInSequenceNum - 1},
				[]*wire.TxOut{{Value: e2eCollateral, PkScript: o.coin.pkScript}},
				&wire.TxOut{Value: e2eCollateral + connector.UnsignedTx.TxOut[0].Value, PkScript: forfeitPk},
				o.coin.term,
			)
			if err != nil {
				return nil, err
			}
			forfeit.UnsignedTx.TxIn = append(forfeit.UnsignedTx.TxIn, &wire.TxIn{
				PreviousOutPoint: wire.OutPoint{Hash: connector.UnsignedTx.TxHash(), Index: 0},
				Sequence:         wire.MaxTxInSequenceNum,
			})
			forfeit.Inputs = append(forfeit.Inputs, psbt.PInput{WitnessUtxo: connector.UnsignedTx.TxOut[0]})
			forfeit.Inputs[0].SighashType = txscript.SigHashDefault
			forfeit.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
				ControlBlock: leaf.ctrl, Script: leaf.script, LeafVersion: txscript.BaseLeafVersion,
			}}
			if err := txutils.SetArkPsbtField(
				forfeit, 0, txutils.VtxoTaprootTreeField, txutils.TapTree(o.coin.revealed),
			); err != nil {
				return nil, err
			}
			guardianSignInput(t, forfeit, 0, leaf.script, signers)
			b64, err := forfeit.B64Encode()
			if err != nil {
				return nil, err
			}
			if err := client.SubmitSignedForfeitTxs(ctx, []string{b64}, ""); err != nil {
				return nil, err
			}
			return []string{b64}, nil
		},
	}

	_, err = joinBatchBounded(ctx, batchsession.JoinBatchArgs{
		BaseArgs: batchsession.BaseArgs{
			Vtxos: []clientlib.Vtxo{{
				Outpoint: o.clientOutpoint(), Script: hex.EncodeToString(o.coin.pkScript),
				Amount: uint64(e2eCollateral), Tapscripts: o.coin.revealed,
			}},
			Outputs: []clientlib.Receiver{{To: next.addr, Amount: uint64(e2eCollateral)}},
			SignTx:  o.funder.SignTransaction,
		},
		TreeSigners: sessions, IntentId: intentID, Client: client, ServerParams: *config,
	}, batchsession.WithHandler(handler))
	require.NoError(t, err)
	guardianWaitVtxo(t, ctx, o.funder, rolled.clientOutpoint())
	return rolled
}

func (o *e2eNumericCoin) saveExitBranch(t *testing.T, ctx context.Context) *cachedIndexer {
	t.Helper()
	indexer := o.funder.Indexer()
	var chain *clientlib.VtxoChainResponse
	require.Eventually(t, func() bool {
		resp, err := indexer.GetVtxoChain(ctx, o.clientOutpoint())
		if err != nil || resp == nil || len(resp.Chain) == 0 {
			return false
		}
		chain = resp
		return true
	}, 30*time.Second, 500*time.Millisecond, "vtxo chain not indexed")
	txs := map[string]string{}
	for _, node := range chain.Chain {
		if node.Type == clientlib.IndexerChainedTxTypeCommitment ||
			node.Type == clientlib.IndexerChainedTxTypeUnspecified {
			continue
		}
		resp, err := indexer.GetVirtualTxs(ctx, []string{node.Txid})
		require.NoError(t, err)
		require.Len(t, resp.Txs, 1)
		txs[node.Txid] = resp.Txs[0]
	}
	return &cachedIndexer{Indexer: indexer, chain: chain, txs: txs}
}

func (o *e2eNumericCoin) findRange(t *testing.T, price uint32) int {
	t.Helper()
	for i, r := range o.ranges {
		if r.prefix.contains(price) {
			return i
		}
	}
	t.Fatalf("no prefix covering price %d", price)
	return -1
}

// -----------------------------------------------------------------------------
// Part 4: The Full End-to-End Integration Test
// -----------------------------------------------------------------------------

func TestP2pFiatEndToEnd(t *testing.T) {
	require.NoError(t, generateBlocks(1))
	ctx := t.Context()

	// 1. Start 3 real strfry Nostr relays and a 4-of-7 threshold oracle.
	cluster := startStrfryCluster(t)
	oracle := newE2EThresholdOracle(t, cluster)
	ranges := e2eBuildNumericRanges()
	t.Logf("numeric DLC: $%d notional, %d sats collateral, +/-%d%% band -> %d binary prefixes",
		e2eNotionalUSD, e2eCollateral, e2eBandPct, len(ranges))

	// 2. Run 4-of-7 DKG over strfry for two event slots (Journey A offchain, Journey B onchain).
	annA := oracle.setupEvent(t, ctx, fmt.Sprintf("e2e-slot-A-%d", time.Now().UnixNano()))
	annB := oracle.setupEvent(t, ctx, fmt.Sprintf("e2e-slot-B-%d", time.Now().UnixNano()))
	t.Logf("4-of-7 DKG over 3 strfry relays succeeded for both event slots (EventPx A=%x...)", annA.eventPx[:8])

	// 3. Setup watchtowers (W1 primary, W2/W3 backup) + unauthorized miner key.
	w1 := newWatchtowerWallet(t, "E2E-W1-primary")
	w2 := newWatchtowerWallet(t, "E2E-W2-backup")
	w3 := newWatchtowerWallet(t, "E2E-W3-backup")
	bounty := newBountyScript(t, w1.pub, []*btcec.PublicKey{w2.pub, w3.pub})

	attackerKey, attackerPub := evenKey(t)
	attackerBytes := attackerKey.Bytes()
	attackerPriv, _ := btcec.PrivKeyFromBytes(attackerBytes[:])
	attackerPk, err := script.P2TRScript(attackerPub)
	require.NoError(t, err)

	// 4. Setup mandate (user + LP + 5 nostracles) and arkd parameters.
	probe := setupClientWallet(t)
	_, offAddr, _, err := probe.Receive(ctx)
	require.NoError(t, err)
	decoded, err := arklib.DecodeAddressV0(offAddr.Address)
	require.NoError(t, err)
	info, err := probe.Client().GetInfo(ctx)
	require.NoError(t, err)
	cpScript, err := hex.DecodeString(info.CheckpointTapscript)
	require.NoError(t, err)

	m := &guardianMandate{
		user:       newGuardianParty(t),
		lp:         newGuardianParty(t),
		signer:     decoded.Signer,
		checkpoint: cpScript,
	}
	for i := range m.nostracles {
		m.nostracles[i] = newGuardianParty(t)
	}
	// User goes completely offline after opening!
	m.user.d.Zero()

	height, err := getBlockHeight()
	require.NoError(t, err)
	term1 := height + 4

	// Open both 2,000,000 sat numeric DLC contracts on arkd.
	coinA1 := openE2ENumericCoin(t, ctx, m, term1, annA, bounty, ranges)
	coinB1 := openE2ENumericCoin(t, ctx, m, term1, annB, bounty, ranges)

	// Mine past Term 1 so the quorum timelock opens.
	mineToHeight(t, term1+1)
	term2 := term1 + 1 + guardianMaxTerm

	// Roll both contracts in live arkd batches using two different 3-of-5 quorums!
	t0 := time.Now()
	coinA2 := coinA1.rollNumeric(t, ctx, guardianQuorum{0, 1, 2}, term2, annA, bounty, ranges)
	coinB2 := coinB1.rollNumeric(t, ctx, guardianQuorum{1, 2, 4}, term2, annB, bounty, ranges)
	t.Logf("rolled both 2,000,000-sat numeric DLCs on live arkd (%d prefixes signed each) in %v",
		len(ranges), time.Since(t0).Round(time.Millisecond))

	// Confirm the batch commitment tx(s) so v3 unroll txs satisfy TRUC rules.
	require.NoError(t, generateBlocks(1))

	// -------------------------------------------------------------------------
	// Journey A: 4-of-7 threshold oracle attests $91,420 over strfry (2 offline)
	//            -> numeric offchain settlement on live arkd
	// -------------------------------------------------------------------------
	t.Run("Journey A: 4-of-7 nostr oracle settles rolled numeric DLC offchain on arkd", func(t *testing.T) {
		const targetPrice = uint32(91_420)
		// Members 6 and 7 are offline; 5 of 7 attest on the fast path over strfry.
		attestedPrice, digitSigs := oracle.attestPrice(t, ctx, annA, []int{1, 2, 3, 4, 5}, targetPrice)
		require.Equal(t, targetPrice, attestedPrice)

		matchIdx := coinA2.findRange(t, attestedPrice)
		wrongIdx := (matchIdx + 1) % len(coinA2.ranges)
		secret := e2ePrefixSecret(coinA2.ranges[matchIdx].prefix, digitSigs)

		// Advance past term2 so quorum settle leaf is unlocked on arkd.
		mineToHeight(t, term2+1)

		submitIdx := func(idx int, sec btcec.ModNScalar) (string, error) {
			p := coinA2.arks[idx]
			arkPtx, cpPtx := parsePsbt(t, p.arkB64), parsePsbt(t, p.checkpointB64)
			for i, s := range m.signers(coinA2.quorum) {
				addTapscriptSig(arkPtx, s.pub, completeAdaptor(t, p.arkSigs[i], sec))
				addTapscriptSig(cpPtx, s.pub, completeAdaptor(t, p.cpSigs[i], sec))
			}
			aB64, err := arkPtx.B64Encode()
			require.NoError(t, err)
			cB64, err := cpPtx.B64Encode()
			require.NoError(t, err)
			txid, _, _, err := coinA2.funder.Client().SubmitTx(ctx, aB64, []string{cB64})
			return txid, err
		}

		// Wrong price prefix must be rejected by arkd.
		_, err := submitIdx(wrongIdx, secret)
		require.Error(t, err, "arkd must reject wrong numeric prefix")
		t.Logf("wrong prefix rejected by arkd: %v", err)

		// Matching prefix settles cleanly on arkd!
		txid, err := submitIdx(matchIdx, secret)
		require.NoError(t, err)
		wantAmounts := coinA2.ranges[matchIdx].amounts
		uArkPk := ownerPkScript(t, m.user.pub, m.signer)
		lArkPk := ownerPkScript(t, m.lp.pub, m.signer)
		for i, pk := range [][]byte{uArkPk, lArkPk} {
			scriptHex := hex.EncodeToString(pk)
			require.Eventually(t, func() bool {
				resp, err := coinA2.funder.Indexer().GetVtxos(ctx, clientlib.WithScripts([]string{scriptHex}))
				if err != nil || resp == nil {
					return false
				}
				for _, v := range resp.Vtxos {
					if v.Txid == txid && int64(v.Amount) == wantAmounts[i] && !v.Spent {
						return true
					}
				}
				return false
			}, 30*time.Second, 500*time.Millisecond)
		}
		t.Logf("Journey A settled offchain (%s) at $%d (prefix [%d..%d]): user=%d sats, LP=%d sats",
			txid, attestedPrice, coinA2.ranges[matchIdx].lo, coinA2.ranges[matchIdx].hi,
			wantAmounts[0], wantAmounts[1])
	})

	// -------------------------------------------------------------------------
	// Journey B: arkd dies -> 4-of-7 nostr oracle attests $114,800 (2 offline)
	//            -> keyless watchtower unrolls rolled numeric DLC & profits
	// -------------------------------------------------------------------------
	savedB2 := coinB2.saveExitBranch(t, ctx)

	// Wipe all remaining quorum & LP keys: watchtower has ZERO contract keys!
	m.lp.d.Zero()
	for i := range m.nostracles {
		m.nostracles[i].d.Zero()
	}

	// Stop arkd completely.
	_, err = runCommand("docker", "stop", "arkd")
	require.NoError(t, err)
	t.Cleanup(func() {
		if _, err := runCommand("docker", "start", "arkd"); err != nil {
			t.Logf("failed to restart arkd: %v", err)
			return
		}
		for range 30 {
			if err := setupArkd(); err == nil {
				return
			}
			time.Sleep(2 * time.Second)
		}
		t.Error("failed to unlock arkd after restart")
	})

	t.Run("Journey B: arkd gone, keyless watchtower unrolls rolled numeric DLC and collects bounty", func(t *testing.T) {
		const targetPrice = uint32(114_800)
		// Different subset of 5 online members (1 and 3 offline) attests over strfry!
		attestedPrice, digitSigs := oracle.attestPrice(t, ctx, annB, []int{2, 4, 5, 6, 7}, targetPrice)
		require.Equal(t, targetPrice, attestedPrice)

		// Watchtower W1 unrolls coinB2 purely from saved data using its own BTC wallet.
		w1BalBefore := w1.balance(t)
		pkg := &watchtowerPackage{
			outpoint: coinB2.clientOutpoint(),
			saved:    savedB2,
		}
		hops := pkg.unrollWithWatchtower(t, ctx, w1, wtCPFPFeePerTx)
		t.Logf("W1 unrolled rolled numeric DLC in %d hops (CPFP=%d sats)", hops, int64(hops)*wtCPFPFeePerTx)

		// Wait out the quorum CSV exit delay (25 blocks).
		require.NoError(t, generateBlocks(int(guardianQuorumDelay)+1))

		// Complete the matching numeric prefix exit payout with the strfry attestation.
		matchIdx := coinB2.findRange(t, attestedPrice)
		secret := e2ePrefixSecret(coinB2.ranges[matchIdx].prefix, digitSigs)
		ep := coinB2.exits[matchIdx]
		sigs := make([]*schnorr.Signature, len(ep.sigs))
		for i, s := range m.signers(coinB2.quorum) {
			sigs[i] = completeAdaptor(t, ep.sigs[i], secret)
			require.True(t, sigs[i].Verify(ep.msg, s.pub))
		}

		// Finalize quorum exit witness and broadcast on Bitcoin regtest.
		closure := coinB2.coin.exitClosure[coinB2.quorum]
		args := map[string][]byte{}
		for i, s := range m.signers(coinB2.quorum) {
			args[hex.EncodeToString(schnorr.SerializePubKey(s.pub))] = sigs[i].Serialize()
		}
		witness, err := closure.Witness(coinB2.coin.exitLeaf[coinB2.quorum].ctrl, args)
		require.NoError(t, err)
		finalTx := ep.tx.Copy()
		finalTx.TxIn[0].Witness = witness
		var buf bytes.Buffer
		require.NoError(t, finalTx.Serialize(&buf))
		exitTxHex := hex.EncodeToString(buf.Bytes())

		exitTxid, err := testExplorer.Broadcast(exitTxHex)
		require.NoError(t, err)
		require.NoError(t, generateBlocks(1))
		waitForTxConfirmed(t, exitTxid)

		// Verify exact onchain dollar-pegged payout + bounty output.
		raw, err := testExplorer.GetTxHex(exitTxid)
		require.NoError(t, err)
		var confirmed wire.MsgTx
		require.NoError(t, confirmed.Deserialize(hex.NewDecoder(strings.NewReader(raw))))
		require.Len(t, confirmed.TxOut, 3)
		wantAmounts := coinB2.ranges[matchIdx].amounts
		deduct := (wtExitTxFee + wtBountyAmount) / 2
		require.Equal(t, wantAmounts[0]-deduct, confirmed.TxOut[0].Value)
		require.Equal(t, wantAmounts[1]-deduct, confirmed.TxOut[1].Value)
		require.Equal(t, wtBountyAmount, confirmed.TxOut[2].Value)
		require.Equal(t, bounty.pkScript, confirmed.TxOut[2].PkScript)

		// Unauthorized miner cannot steal the bounty.
		exitHash, err := chainhash.NewHashFromStr(exitTxid)
		require.NoError(t, err)
		bountyOut := wire.OutPoint{Hash: *exitHash, Index: 2}
		badSweep := bounty.buildSweepBountyTx(t, bountyOut, attackerPriv, attackerPub, false, attackerPk, wtSweepFee)
		_, err = testExplorer.Broadcast(badSweep)
		require.Error(t, err, "miner must not steal watchtower bounty")

		// W1 sweeps the bounty immediately and finishes strictly profitable!
		sweepHex := bounty.buildSweepBountyTx(t, bountyOut, w1.priv, w1.pub, false, w1.pkScript, wtSweepFee)
		sweepTxid, err := testExplorer.Broadcast(sweepHex)
		require.NoError(t, err)
		require.NoError(t, generateBlocks(1))
		waitForTxConfirmed(t, sweepTxid)

		netProfit := w1.balance(t) - w1BalBefore
		require.Greater(t, netProfit, int64(0), "watchtower must profit net of all fees")
		t.Logf("Journey B settled onchain (%s) at $%d (prefix [%d..%d]): user=%d sats, LP=%d sats, W1 netProfit=+%d sats (sweep %s)",
			exitTxid, attestedPrice, coinB2.ranges[matchIdx].lo, coinB2.ranges[matchIdx].hi,
			confirmed.TxOut[0].Value, confirmed.TxOut[1].Value, netProfit, sweepTxid)
	})
}
