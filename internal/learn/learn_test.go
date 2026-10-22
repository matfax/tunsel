package learn

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/matfax/tunsel/internal/config"
	"github.com/matfax/tunsel/internal/flows"
	"github.com/matfax/tunsel/internal/health"
)

var addr = netip.MustParseAddr

func TestConntrack(t *testing.T) {
	c := &Conntrack{Mask: 0xf, Marks: map[uint32]bool{1: true, 2: true}, Dump: func() ([]flows.Entry, error) {
		return []flows.Entry{
			{Mark: 0x11, Dst: addr("198.18.0.1"), BytesOut: 10, BytesIn: 90},
			{Mark: 0x2, Dst: addr("198.18.0.1"), BytesOut: 5},
			{Mark: 0x2, Dst: addr("198.18.0.2"), BytesIn: 1},
			{Mark: 0, Dst: addr("198.18.0.3"), BytesIn: 1000}, // not steered
		}, nil
	}}
	cs, err := c.Candidates(context.Background())
	if err != nil || len(cs) != 2 {
		t.Fatalf("%+v %v", cs, err)
	}
	for _, x := range cs {
		if x.Addr == addr("198.18.0.1") && (x.Score != 105 || x.Hits != 2) {
			t.Errorf("aggregate: %+v", x)
		}
	}
	c.Dump = func() ([]flows.Entry, error) { return nil, errors.New("no ctnetlink") }
	if _, err := c.Candidates(context.Background()); err == nil {
		t.Error("dump error swallowed")
	}
}

func params() *config.Learning {
	return &config.Learning{
		MinGain:  config.MinGain{Abs: config.Duration(5 * time.Millisecond), Rel: 0.15},
		TTL:      config.Duration(time.Hour),
		FlapDamp: config.FlapDamping{Window: config.Duration(30 * time.Minute), MaxSwitches: 2},
	}
}

func all(string) bool { return true }

func ms(n int) time.Duration { return time.Duration(n) * time.Millisecond }

func TestDecide(t *testing.T) {
	l := New()
	now := time.Now()
	c := Candidate{Addr: addr("198.18.0.1")}
	for _, tc := range []struct {
		rtt     map[string]time.Duration
		outcome string
		tunnel  string
	}{
		{map[string]time.Duration{"wg-a": ms(20), "wg-b": ms(40)}, Learned, "wg-a"},
		{map[string]time.Duration{"wg-a": ms(40), "wg-b": ms(20)}, Baseline, ""},
		{map[string]time.Duration{"wg-a": ms(20), "wg-b": ms(20)}, Baseline, ""}, // a tie keeps the baseline
		{map[string]time.Duration{"wg-a": ms(36), "wg-b": ms(40)}, NoGain, ""},   // 4 ms < 5 ms
		{map[string]time.Duration{"wg-a": ms(190), "wg-b": ms(200)}, NoGain, ""}, // 5% < 15%
		{map[string]time.Duration{"wg-a": ms(150), "wg-b": ms(200)}, Learned, "wg-a"},
		{map[string]time.Duration{"wg-a": ms(300)}, Learned, "wg-a"}, // the baseline did not answer
		{map[string]time.Duration{}, NoAnswer, ""},
	} {
		r := l.Decide(c, tc.rtt, "wg-b", "", all, params(), now)
		if r.Outcome != tc.outcome || r.Tunnel != tc.tunnel || !r.Expires.Equal(now.Add(time.Hour)) {
			t.Errorf("%v: %s %q, want %s %q", tc.rtt, r.Outcome, r.Tunnel, tc.outcome, tc.tunnel)
		}
	}
}

// On renewal, the current tunnel is kept unless another beats it by
// min_gain; the baseline taking over removes the learned tunnel.
func TestDecideRenewal(t *testing.T) {
	l := New()
	now := time.Now()
	c := Candidate{Addr: addr("198.18.0.1")}
	for _, tc := range []struct {
		rtt     map[string]time.Duration
		outcome string
		tunnel  string
	}{
		{map[string]time.Duration{"wg-a": ms(20), "wg-b": ms(40), "wg-c": ms(60)}, Learned, "wg-a"},
		{map[string]time.Duration{"wg-a": ms(20), "wg-b": ms(18), "wg-c": ms(60)}, Learned, "wg-a"}, // baseline faster, by too little
		{map[string]time.Duration{"wg-a": ms(20), "wg-b": ms(20), "wg-c": ms(20)}, Learned, "wg-a"}, // ties keep it
		{map[string]time.Duration{"wg-a": ms(40), "wg-b": ms(20), "wg-c": ms(60)}, Baseline, ""},
		{map[string]time.Duration{"wg-a": ms(40), "wg-b": ms(60), "wg-c": ms(20)}, Learned, "wg-c"},
		{map[string]time.Duration{"wg-a": ms(40), "wg-b": ms(38), "wg-c": ms(37)}, Learned, "wg-a"},
		{map[string]time.Duration{"wg-b": ms(40), "wg-c": ms(39)}, NoGain, ""}, // wg-a silent; wg-c not enough over the baseline
		{map[string]time.Duration{}, NoAnswer, ""},
	} {
		r := l.Decide(c, tc.rtt, "wg-b", "wg-a", all, params(), now)
		if r.Outcome != tc.outcome || r.Tunnel != tc.tunnel {
			t.Errorf("%v: %s %q, want %s %q", tc.rtt, r.Outcome, r.Tunnel, tc.outcome, tc.tunnel)
		}
	}
}

// After max_switches changes within the window, a destination keeps its
// tunnel, also against a return to the baseline.
func TestDamping(t *testing.T) {
	l := New()
	p := params()
	c := Candidate{Addr: addr("198.18.0.1")}
	now := time.Now()
	fastA := map[string]time.Duration{"wg-a": ms(10), "wg-b": ms(50), "wg-c": ms(50)}
	fastC := map[string]time.Duration{"wg-a": ms(50), "wg-b": ms(50), "wg-c": ms(10)}
	fastB := map[string]time.Duration{"wg-a": ms(50), "wg-b": ms(10), "wg-c": ms(50)}
	step := func(rtt map[string]time.Duration) *Record {
		r := l.Decide(c, rtt, "wg-b", l.Current(c.Addr), all, p, now)
		l.Store(r)
		now = now.Add(time.Minute)
		return r
	}
	for i, want := range []struct {
		rtt             map[string]time.Duration
		outcome, tunnel string
	}{
		{fastA, Learned, "wg-a"},
		{fastC, Learned, "wg-c"}, // change 1
		{fastA, Learned, "wg-a"}, // change 2
		{fastC, Damped, "wg-a"},
		{fastB, Damped, "wg-a"},
	} {
		if r := step(want.rtt); r.Outcome != want.outcome || r.Tunnel != want.tunnel {
			t.Errorf("step %d: %s %q, want %s %q", i, r.Outcome, r.Tunnel, want.outcome, want.tunnel)
		}
	}
	// Once the changes left the window, it moves again.
	now = now.Add(31 * time.Minute)
	if r := step(fastB); r.Outcome != Baseline {
		t.Errorf("after the window: %s %q", r.Outcome, r.Tunnel)
	}
}

func TestSelectAndPrune(t *testing.T) {
	l := New()
	now := time.Now()
	cands := []Candidate{
		{Addr: addr("198.18.0.1"), Score: 10},
		{Addr: addr("198.18.0.2"), Score: 30},
		{Addr: addr("198.18.0.3"), Score: 20},
		{Addr: addr("198.18.0.4"), Score: 20, Hits: 5},
		{Addr: addr("10.0.0.1"), Score: 99},
	}
	eligible := func(a netip.Addr) bool { return !a.IsPrivate() }
	l.Store(&Record{Addr: addr("198.18.0.2"), Baseline: "wg-b", Decided: now, Expires: now.Add(time.Minute)})
	got := l.Select(cands, 2, eligible, now, 0)
	if len(got) != 2 || got[0].Addr != addr("198.18.0.4") || got[1].Addr != addr("198.18.0.3") {
		t.Errorf("select: %+v", got)
	}
	// Due for renewal ahead of its expiry, the record no longer keeps the
	// destination out.
	if got := l.Select(cands, 1, eligible, now.Add(45*time.Second), 20*time.Second); len(got) != 1 || got[0].Addr != addr("198.18.0.2") {
		t.Errorf("select in the renewal window: %+v", got)
	}
	if !l.Fresh(addr("198.18.0.2"), now.Add(39*time.Second), 20*time.Second) || l.Fresh(addr("198.18.0.2"), now.Add(41*time.Second), 20*time.Second) {
		t.Error("Fresh")
	}

	l.Prune(now.Add(time.Minute+Grace/2), time.Hour)
	if !l.Trained(addr("198.18.0.2")) {
		t.Error("pruned within the grace period")
	}
	l.Prune(now.Add(time.Minute+2*Grace), time.Hour)
	if l.Trained(addr("198.18.0.2")) {
		t.Error("not pruned after expiry")
	}
	if got := l.Select(cands, 5, eligible, now.Add(time.Hour), 0); len(got) != 4 || got[0].Addr != addr("198.18.0.2") {
		t.Errorf("select after expiry: %+v", got)
	}

	l.Store(&Record{Addr: addr("198.18.0.1"), Tunnel: "wg-a", Decided: now, Expires: now.Add(time.Hour)})
	l.Store(&Record{Addr: addr("198.18.0.3"), Tunnel: "wg-b", Decided: now.Add(time.Second), Expires: now.Add(time.Hour)})
	l.Drop(func(r *Record) bool { return r.Tunnel == "wg-a" })
	if rs := l.Records(); len(rs) != 1 || rs[0].Addr != addr("198.18.0.3") {
		t.Errorf("records after drop: %+v", rs)
	}
}

func TestRenewBefore(t *testing.T) {
	p := params()
	p.Candidates.Refresh = config.Duration(5 * time.Minute)
	if got := RenewBefore(p); got != 10*time.Minute {
		t.Errorf("default: %s", got)
	}
	p.Candidates.Refresh = config.Duration(45 * time.Minute)
	if got := RenewBefore(p); got != 30*time.Minute {
		t.Errorf("capped at half the TTL: %s", got)
	}
}

// fakeProber answers with a fixed RTT per tunnel and sample, or not at all.
type fakeProber struct {
	mu   sync.Mutex
	rtts map[string][]time.Duration // per interface, one per sample; 0 = no answer
	n    map[string]int
	seen []health.Probe
}

func (f *fakeProber) Probe(ctx context.Context, p health.Probe) (time.Duration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, p)
	i := f.n[p.Iface]
	f.n[p.Iface]++
	if d := f.rtts[p.Iface][i]; d > 0 {
		return d, nil
	}
	return 0, context.DeadlineExceeded
}

func TestMeasure(t *testing.T) {
	f := &fakeProber{n: map[string]int{}, rtts: map[string][]time.Duration{
		"wg-a": {ms(30), ms(10), ms(20)},
		"wg-b": {ms(50), 0, ms(70)},
		"wg-c": {0, 0, 0},
	}}
	tunnels := []config.Tunnel{{Name: "wg-a", Mark: 1}, {Name: "wg-b", Mark: 2}, {Name: "wg-c", Mark: 3}}
	got := Measure(context.Background(), f, addr("198.18.0.1"), tunnels, config.LearnProbe{Port: 443, Samples: 3, Timeout: config.Duration(time.Second)})
	if len(got) != 2 || got["wg-a"] != ms(20) || got["wg-b"] != ms(60) {
		t.Errorf("medians: %v", got)
	}
	if p := f.seen[0]; len(f.seen) != 9 || p.Kind != config.ProbeTCP || p.Port != 443 || p.Target != addr("198.18.0.1") || p.Mark == 0 {
		t.Errorf("probes: %d, first %+v", len(f.seen), p)
	}
}
