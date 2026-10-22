package daemon

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/matfax/tunsel/internal/config"
	"github.com/matfax/tunsel/internal/health"
	"github.com/matfax/tunsel/internal/learn"
	"github.com/matfax/tunsel/internal/nft"
	"github.com/matfax/tunsel/internal/status"
)

const learnYAML = cfgYAML + `
exclude: [198.18.0.3/32]
static_pref: [{ prefix: 203.0.113.0/24, tunnel: wg-a }]
learning:
  enabled: %t
`

func parseLearning(t *testing.T, enabled bool) *config.Config {
	t.Helper()
	c, err := config.Parse([]byte(fmt.Sprintf(learnYAML, "tunsel", enabled)))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type fixedSource []learn.Candidate

func (s fixedSource) Candidates(context.Context) ([]learn.Candidate, error) { return s, nil }

// tcpProbes answers the learning probes (TCP) with a fixed RTT per tunnel
// and destination; health probes (ICMP) go to fakeProbes.
type tcpProbes struct {
	*fakeProbes
	rtt map[string]map[netip.Addr]time.Duration
}

func (p tcpProbes) Probe(ctx context.Context, pr health.Probe) (time.Duration, error) {
	if pr.Kind != config.ProbeTCP {
		return p.fakeProbes.Probe(ctx, pr)
	}
	if d := p.rtt[pr.Iface][pr.Target]; d > 0 {
		return d, nil
	}
	return 0, context.DeadlineExceeded
}

var a = netip.MustParseAddr

func learnHarness(t *testing.T) (*harness, context.Context) {
	h := newHarness(t)
	h.d.cfg = parseLearning(t, true)
	h.d.opts.Health.Prober = tcpProbes{h.probes, map[string]map[netip.Addr]time.Duration{
		"wg-a": {a("198.18.0.1"): 10 * time.Millisecond, a("198.18.0.2"): 50 * time.Millisecond},
		"wg-b": {a("198.18.0.1"): 40 * time.Millisecond, a("198.18.0.2"): 20 * time.Millisecond},
	}}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := h.d.activate(ctx, h.d.cfg, nil); err != nil {
		t.Fatal(err)
	}
	return h, ctx
}

var cands = fixedSource{
	{Addr: a("198.18.0.1"), Score: 3},
	{Addr: a("198.18.0.2"), Score: 2},
	{Addr: a("10.0.0.1"), Score: 9},    // private
	{Addr: a("198.18.0.3"), Score: 9},  // excluded
	{Addr: a("203.0.113.5"), Score: 9}, // static preference in effect
}

// A round measures the eligible destinations, installs the faster tunnel
// where it beats the default, and the next round skips what it measured.
func TestLearningRound(t *testing.T) {
	h, ctx := learnHarness(t)
	cfg := h.d.cfg
	h.d.learnRound(ctx, cfg, cands)

	adds := h.tables.adds()
	if len(adds) != 1 || len(adds[0]) != 1 || adds[0][0] != (nft.Learned{Addr: a("198.18.0.1"), Tunnel: "wg-a", Timeout: time.Hour}) {
		t.Fatalf("added: %+v", adds)
	}
	r := h.d.report(status.Request{Learned: true})
	l := r.Learning
	if l == nil || l.Seen != 5 || l.Measured != 2 || l.Learned != 1 || l.Kept != 1 || l.LastError != "" || len(l.Entries) != 2 {
		t.Fatalf("report: %+v", l)
	}
	for _, e := range l.Entries {
		switch e.Addr {
		case a("198.18.0.1"):
			if e.Tunnel != "wg-a" || e.Baseline != "wg-b" || e.RTT["wg-a"].D() != 10*time.Millisecond {
				t.Errorf("learned entry: %+v", e)
			}
		case a("198.18.0.2"):
			if e.Tunnel != "" || e.Outcome != learn.Baseline {
				t.Errorf("kept entry: %+v", e)
			}
		}
	}

	h.d.learnRound(ctx, cfg, cands)
	if r := h.d.report(status.Request{}); r.Learning.Measured != 0 || len(h.tables.adds()) != 1 || r.Learning.Entries != nil {
		t.Errorf("second round re-measured: %+v", r.Learning)
	}

	// A table replacement carries the learned destination over.
	if err := h.d.activate(ctx, parseLearning(t, true), cfg); err != nil {
		t.Fatal(err)
	}
	if ls := h.tables.last().Learned; len(ls) != 1 || ls[0].Addr != a("198.18.0.1") || ls[0].Timeout > time.Hour || ls[0].Timeout < 59*time.Minute {
		t.Errorf("after reload: %+v", ls)
	}
}

// A failed tunnel loses its learned destinations; they are measured again.
func TestLearningTunnelFails(t *testing.T) {
	h, ctx := learnHarness(t)
	h.d.learnRound(ctx, h.d.cfg, cands)

	h.probes.set("192.0.2.1", true) // wg-a's health target
	waitFor(t, "wg-a unhealthy", func() bool {
		select {
		case ev := <-h.d.events:
			h.d.onEvent(ev)
		default:
		}
		return h.d.report(status.Request{}).Tunnels[0].State == health.Unhealthy
	})
	if ls := h.tables.last().Learned; len(ls) != 0 {
		t.Errorf("learned entries of a failed tunnel installed: %+v", ls)
	}
	h.d.mu.Lock()
	trained := h.d.learner.Trained(a("198.18.0.1"))
	kept := h.d.learner.Trained(a("198.18.0.2"))
	h.d.mu.Unlock()
	if trained || !kept {
		t.Errorf("records after failure: learned %v, kept %v", trained, kept)
	}
	// With one healthy tunnel there is nothing to choose.
	h.d.learnRound(ctx, h.d.cfg, cands)
	if r := h.d.report(status.Request{}); r.Learning.Measured != 0 {
		t.Errorf("measured with one tunnel: %+v", r.Learning)
	}
}

// Entries a previous run installed are adopted; a failed nft add keeps
// nothing learned; disabling learning forgets everything.
func TestLearningAdoptFailDisable(t *testing.T) {
	h := newHarness(t)
	h.d.cfg = parseLearning(t, true)
	h.tables.installed = []nft.Learned{{Addr: a("198.18.0.9"), Tunnel: "wg-a", Timeout: 30 * time.Minute}}
	h.d.adoptInstalledLearned()
	h.d.opts.Health.Prober = tcpProbes{h.probes, map[string]map[netip.Addr]time.Duration{
		"wg-a": {a("198.18.0.1"): 10 * time.Millisecond}, "wg-b": {a("198.18.0.1"): 40 * time.Millisecond},
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := h.d.activate(ctx, h.d.cfg, nil); err != nil {
		t.Fatal(err)
	}
	if ls := h.tables.last().Learned; len(ls) != 1 || ls[0].Addr != a("198.18.0.9") {
		t.Errorf("adopted: %+v", ls)
	}

	h.tables.failAdd = true
	h.d.learnRound(ctx, h.d.cfg, cands[:1])
	if r := h.d.report(status.Request{}); r.Learning.Learned != 1 || r.Learning.LastError == "" {
		t.Errorf("after a failed add: %+v", r.Learning)
	}

	if err := h.d.activate(ctx, parseLearning(t, false), h.d.cfg); err != nil {
		t.Fatal(err)
	}
	r := h.d.report(status.Request{})
	if ls := h.tables.last().Learned; len(ls) != 0 || r.Learning != nil || len(h.d.learner.Records()) != 0 {
		t.Errorf("after disabling: %+v, %+v", ls, r.Learning)
	}
}

// An address nft rejects does not keep the rest of the round out.
func TestLearningAddRetries(t *testing.T) {
	h, ctx := learnHarness(t)
	h.d.opts.Health.Prober.(tcpProbes).rtt["wg-a"][a("198.18.0.4")] = 10 * time.Millisecond
	h.d.opts.Health.Prober.(tcpProbes).rtt["wg-b"][a("198.18.0.4")] = 40 * time.Millisecond
	h.tables.rejectAdd = a("198.18.0.1")
	h.d.learnRound(ctx, h.d.cfg, append(cands, learn.Candidate{Addr: a("198.18.0.4"), Score: 1}))
	h.d.mu.Lock()
	ok, failed := h.d.learner.Trained(a("198.18.0.4")), h.d.learner.Trained(a("198.18.0.1"))
	h.d.mu.Unlock()
	if !ok || failed {
		t.Errorf("trained: 198.18.0.4 %v, rejected 198.18.0.1 %v", ok, failed)
	}
	if r := h.d.report(status.Request{}); r.Learning.Learned != 1 || r.Learning.LastError == "" {
		t.Errorf("report: %+v", r.Learning)
	}
}

// A destination still in use is measured again from two refreshes before
// its record expires: the same tunnel is renewed in place, a baseline
// that became faster removes it. One no longer in use just expires.
func TestLearningRenewal(t *testing.T) {
	h, ctx := learnHarness(t)
	start := time.Now()
	now := start
	h.d.opts.Now = func() time.Time { return now }
	rtt := h.d.opts.Health.Prober.(tcpProbes).rtt
	round := func(at time.Duration, src fixedSource) *status.Learning {
		t.Helper()
		now = start.Add(at)
		h.d.learnRound(ctx, h.d.cfg, src)
		return h.d.report(status.Request{Learned: true}).Learning
	}
	expiry := func(addr string) time.Time {
		for _, e := range h.d.report(status.Request{Learned: true}).Learning.Entries {
			if e.Addr == a(addr) {
				return e.Expires
			}
		}
		return time.Time{}
	}

	round(0, cands)
	if l := round(49*time.Minute, cands); l.Measured != 0 {
		t.Fatalf("measured before the renewal window: %+v", l)
	}
	// Due at 50 min (1 h TTL, 10 min ahead at the default 5 min refresh).
	l := round(51*time.Minute, cands)
	if l.Measured != 2 || l.Renewals != 2 || l.Learned != 1 {
		t.Fatalf("renewal round: %+v", l)
	}
	adds, removes := h.tables.adds(), h.tables.removes()
	last := len(adds) - 1
	if len(adds) != 2 || len(adds[last]) != 1 || adds[last][0] != (nft.Learned{Addr: a("198.18.0.1"), Tunnel: "wg-a", Timeout: time.Hour}) ||
		len(removes[last]) != 1 || removes[last][0].Addr != a("198.18.0.1") || removes[last][0].Tunnel != "wg-a" {
		t.Fatalf("renewal update: add %+v, remove %+v", adds, removes)
	}
	if got := expiry("198.18.0.1"); !got.Equal(start.Add(51*time.Minute + time.Hour)) {
		t.Errorf("renewed expiry: %s", got.Sub(start))
	}

	// The baseline overtook it: the element goes, the destination stays
	// on the default.
	rtt["wg-b"][a("198.18.0.1")] = 5 * time.Millisecond
	l = round(51*time.Minute+51*time.Minute, cands)
	adds, removes = h.tables.adds(), h.tables.removes()
	last = len(adds) - 1
	if l.Learned != 0 || len(adds[last]) != 0 || len(removes[last]) != 1 || removes[last][0].Tunnel != "wg-a" {
		t.Errorf("baseline took over: %+v, add %+v, remove %+v", l, adds[last], removes[last])
	}

	// No longer in conntrack: not measured, and gone once expired.
	l = round(4*time.Hour, nil)
	if l.Measured != 0 || l.Learned != 0 || l.Kept != 0 {
		t.Errorf("unused destinations kept: %+v", l)
	}
}

// The loop runs a round at start and stops with its context.
func TestLearningLoop(t *testing.T) {
	h, ctx := learnHarness(t)
	h.d.opts.LearnSource = func(*config.Config) learn.Source { return cands }
	h.d.restartLearning(ctx)
	waitFor(t, "first round", func() bool { return len(h.tables.adds()) == 1 })
	h.d.stopLearning()
	h.d.mu.Lock()
	stopped := h.d.learnStop == nil
	h.d.mu.Unlock()
	if !stopped {
		t.Error("learning still running")
	}
}
