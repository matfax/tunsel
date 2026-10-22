package learn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/matfax/tunsel/internal/config"
	"github.com/matfax/tunsel/internal/flows"
	"github.com/matfax/tunsel/internal/health"
)

var addr = netip.MustParseAddr

// fakeLog serves a query log like AdGuard Home: newest first, pages of
// limit entries older than older_than.
type fakeLog struct {
	mu      sync.Mutex
	entries []map[string]any // newest first
	pages   int
}

func (f *fakeLog) add(at time.Time, client, name string, answers ...string) {
	var ans []map[string]any
	for _, a := range answers {
		typ := "A"
		if addr(a).Is6() {
			typ = "AAAA"
		}
		ans = append(ans, map[string]any{"type": typ, "value": a, "ttl": 60})
	}
	ans = append(ans, map[string]any{"type": "HTTPS", "value": map[string]any{"hints": "x"}})
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries = append([]map[string]any{{
		"time": at.Format(time.RFC3339Nano), "client": client,
		"question": map[string]any{"name": name + ".", "type": "A"}, "answer": ans,
	}}, f.entries...)
}

func (f *fakeLog) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if u, p, ok := r.BasicAuth(); !ok || u != "admin" || p != "secret" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if r.URL.Path != "/control/querylog" {
		http.NotFound(w, r)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pages++
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	var page []map[string]any
	for _, e := range f.entries {
		if o := r.URL.Query().Get("older_than"); o != "" && !parseTime(e["time"]).Before(parseTime(o)) {
			continue
		}
		if len(page) == limit {
			break
		}
		page = append(page, e)
	}
	oldest := ""
	if len(page) > 0 {
		oldest = page[len(page)-1]["time"].(string)
	}
	json.NewEncoder(w).Encode(map[string]any{"data": page, "oldest": oldest})
}

func parseTime(v any) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, v.(string))
	return t
}

func TestAdGuard(t *testing.T) {
	log := &fakeLog{}
	srv := httptest.NewServer(log)
	defer srv.Close()
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	a := &AdGuard{URL: srv.URL + "/", Username: "admin", Password: "secret", Lookback: time.Minute, Now: func() time.Time { return now }}

	log.add(now.Add(-2*time.Minute), "10.0.0.2", "old.example", "198.18.0.9") // before the lookback
	log.add(now.Add(-30*time.Second), "10.0.0.2", "a.example", "198.18.0.1", "2001:db8::1")
	log.add(now.Add(-20*time.Second), "10.0.0.3", "a.example", "198.18.0.1")
	log.add(now.Add(-10*time.Second), "127.0.0.1", "router.example", "198.18.0.2") // the router's own
	cs, err := a.Candidates(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[netip.Addr]Candidate{}
	for _, c := range cs {
		got[c.Addr] = c
	}
	if len(got) != 2 || got[addr("198.18.0.1")].Hits != 2 || got[addr("198.18.0.1")].Name != "a.example" || got[addr("2001:db8::1")].Hits != 1 {
		t.Errorf("first poll: %+v", cs)
	}

	// The next poll counts only newer entries, across pages.
	for i := range adguardPage + 10 {
		log.add(now.Add(time.Duration(i+1)*time.Millisecond), "10.0.0.2", "b.example", fmt.Sprintf("198.18.%d.%d", 1+i/250, i%250))
	}
	log.pages = 0
	cs, err = a.Candidates(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != adguardPage+10 || log.pages != 2 {
		t.Errorf("second poll: %d candidates in %d pages", len(cs), log.pages)
	}
	if cs, err := a.Candidates(context.Background()); err != nil || len(cs) != 0 {
		t.Errorf("third poll: %v %v", cs, err)
	}

	a.LocalClients = true
	a.cursor = time.Time{}
	log.mu.Lock()
	log.entries = log.entries[len(log.entries)-4:]
	log.mu.Unlock()
	if cs, _ := a.Candidates(context.Background()); len(cs) != 3 {
		t.Errorf("with local clients: %+v", cs)
	}

	a.Password = "wrong"
	if _, err := a.Candidates(context.Background()); err == nil || err.Error() != "adguard: 403 Forbidden: Forbidden" {
		t.Errorf("bad password: %v", err)
	}
}

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
		r := l.Decide(c, tc.rtt, "wg-b", all, params(), now)
		if r.Outcome != tc.outcome || r.Tunnel != tc.tunnel || !r.Expires.Equal(now.Add(time.Hour)) {
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
		r := l.Decide(c, rtt, "wg-b", all, p, now)
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
	got := l.Select(cands, 2, eligible)
	if len(got) != 2 || got[0].Addr != addr("198.18.0.4") || got[1].Addr != addr("198.18.0.3") {
		t.Errorf("select: %+v", got)
	}

	l.Prune(now.Add(time.Minute+Grace/2), time.Hour)
	if !l.Trained(addr("198.18.0.2")) {
		t.Error("pruned within the grace period")
	}
	l.Prune(now.Add(time.Minute+2*Grace), time.Hour)
	if l.Trained(addr("198.18.0.2")) {
		t.Error("not pruned after expiry")
	}
	if got := l.Select(cands, 5, eligible); len(got) != 4 || got[0].Addr != addr("198.18.0.2") {
		t.Errorf("select after expiry: %+v", got)
	}

	l.Store(&Record{Addr: addr("198.18.0.1"), Tunnel: "wg-a", Decided: now, Expires: now.Add(time.Hour)})
	l.Store(&Record{Addr: addr("198.18.0.3"), Tunnel: "wg-b", Decided: now.Add(time.Second), Expires: now.Add(time.Hour)})
	l.Drop(func(r *Record) bool { return r.Tunnel == "wg-a" })
	if rs := l.Records(); len(rs) != 1 || rs[0].Addr != addr("198.18.0.3") {
		t.Errorf("records after drop: %+v", rs)
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
