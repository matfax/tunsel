package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/matfax/tunsel/internal/config"
	"github.com/matfax/tunsel/internal/flows"
	"github.com/matfax/tunsel/internal/health"
	"github.com/matfax/tunsel/internal/nft"
	"github.com/matfax/tunsel/internal/status"
)

type fakeTables struct {
	mu        sync.Mutex
	applied   []*nft.Ruleset
	failTable string
	v4, v6    string // installed defaults (chain names)
	counters  map[string]nft.Counter
	added     [][]nft.Learned // UpdateLearned calls: additions
	removed   [][]nft.Learned // and removals
	installed []nft.Learned   // Learned answers
	failAdd   bool
	rejectAdd netip.Addr // fails any batch containing it
}

func (f *fakeTables) Apply(rs *nft.Ruleset, _ ...string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if rs.Table == f.failTable {
		return errors.New("rejected")
	}
	f.applied = append(f.applied, rs)
	return nil
}
func (f *fakeTables) Exists(string) (bool, error) { return true, nil }
func (f *fakeTables) Delete(string) error         { return nil }
func (f *fakeTables) Defaults(string) (string, string, error) {
	return f.v4, f.v6, nil
}
func (f *fakeTables) Counters(string) (map[string]nft.Counter, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.counters, nil
}
func (f *fakeTables) UpdateLearned(_ string, remove, ls []nft.Learned) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failAdd {
		return errors.New("no such table")
	}
	for _, l := range append(append([]nft.Learned{}, remove...), ls...) {
		if l.Addr == f.rejectAdd {
			return errors.New("file exists")
		}
	}
	f.added = append(f.added, ls)
	f.removed = append(f.removed, remove)
	return nil
}
func (f *fakeTables) Learned(string, []string) ([]nft.Learned, error) {
	return f.installed, nil
}
func (f *fakeTables) removes() [][]nft.Learned {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]nft.Learned(nil), f.removed...)
}
func (f *fakeTables) adds() [][]nft.Learned {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]nft.Learned(nil), f.added...)
}
func (f *fakeTables) last() *nft.Ruleset {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.applied[len(f.applied)-1]
}

// fakeProbes answers probes unless the target is marked down.
type fakeProbes struct {
	mu   sync.Mutex
	down map[netip.Addr]bool
}

func (f *fakeProbes) Probe(ctx context.Context, p health.Probe) (time.Duration, error) {
	f.mu.Lock()
	down := f.down[p.Target]
	f.mu.Unlock()
	if down {
		<-ctx.Done()
		return 0, ctx.Err()
	}
	return time.Millisecond, nil
}

func (f *fakeProbes) set(addr string, down bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.down[netip.MustParseAddr(addr)] = down
}

const cfgYAML = `
nft: { table: %s, mark_mask: 0xf }
tunnels:
  - { name: wg-a, mark: 0x1, health: { targets: [192.0.2.1], interval: 20ms, timeout: 10ms, fail_after: 1, recover_after: 1 } }
  - { name: wg-b, mark: 0x2, health: { targets: [198.51.100.1], interval: 20ms, timeout: 10ms, fail_after: 1, recover_after: 1 } }
default_order: [wg-b, wg-a]
ingress: { interfaces: [lan0] }
`

func parse(t *testing.T, table string) *config.Config {
	t.Helper()
	c, err := config.Parse([]byte(fmt.Sprintf(cfgYAML, table)))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type harness struct {
	d       *Daemon
	tables  *fakeTables
	probes  *fakeProbes
	mu      sync.Mutex
	flushed []uint32
}

func newHarness(t *testing.T) *harness {
	h := &harness{tables: &fakeTables{}, probes: &fakeProbes{down: map[netip.Addr]bool{}}}
	h.d = New(parse(t, "tunsel"), Options{
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		NFT: h.tables,
		Health: health.Env{
			Prober: h.probes,
			Link:   func(string) (string, error) { return "up", nil },
			Route: func(_ netip.Addr, mark uint32) (string, error) {
				return map[uint32]string{1: "wg-a", 2: "wg-b"}[mark], nil
			},
		},
		FlushConntrack: func(mark, _ uint32) error {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.flushed = append(h.flushed, mark)
			return nil
		},
	})
	return h
}

func (h *harness) flushes() []uint32 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]uint32(nil), h.flushed...)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

// A transition queued by a monitor generation that a reload stops must
// still be acted on: logged, applied and flushed.
func TestReloadKeepsQueuedTransition(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := h.d.activate(ctx, h.d.cfg, nil); err != nil {
		t.Fatal(err)
	}
	if got := h.tables.last().Default4; got != "wg-b" {
		t.Fatalf("default: %s", got)
	}

	h.probes.set("198.51.100.1", true)
	waitFor(t, "queued event", func() bool { return len(h.d.events) > 0 })
	// Reload before the event is handled; the event is now stale.
	if err := h.d.activate(ctx, parse(t, "tunsel"), h.d.cfg); err != nil {
		t.Fatal(err)
	}
	if got := h.tables.last().Default4; got != "wg-a" {
		t.Errorf("default after reload: %s, want wg-a", got)
	}
	if f := h.flushes(); len(f) != 1 || f[0] != 0x2 {
		t.Errorf("flushes: %v, want [0x2]", f)
	}
}

// A reload whose ruleset nft rejects must leave the previous
// configuration and its monitors in charge.
func TestReloadApplyFailureKeepsOldConfig(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := h.d.activate(ctx, h.d.cfg, nil); err != nil {
		t.Fatal(err)
	}
	old := h.d.cfg
	h.tables.failTable = "bad"
	if err := h.d.activate(ctx, parse(t, "bad"), old); err == nil {
		t.Fatal("want error")
	}
	if h.d.cfg != old {
		t.Fatal("failed reload replaced the configuration")
	}
	// The resumed monitors still drive failover.
	h.probes.set("198.51.100.1", true)
	waitFor(t, "failover after failed reload", func() bool {
		select {
		case ev := <-h.d.events:
			h.d.onEvent(ev)
		default:
		}
		return h.tables.last().Default4 == "wg-a"
	})
}

// A restart with every tunnel down keeps the defaults of the installed
// table instead of leaving traffic unmarked.
func TestRestartKeepsInstalledDefaults(t *testing.T) {
	h := newHarness(t)
	h.tables.v4, h.tables.v6 = "to_wg_a", "to_wg_a"
	h.probes.set("192.0.2.1", true)
	h.probes.set("198.51.100.1", true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.d.adoptInstalledDefaults()
	if err := h.d.activate(ctx, h.d.cfg, nil); err != nil {
		t.Fatal(err)
	}
	if rs := h.tables.last(); rs.Default4 != "wg-a" || rs.Default6 != "wg-a" {
		t.Errorf("defaults: %q %q, want wg-a", rs.Default4, rs.Default6)
	}
	if f := h.flushes(); len(f) != 2 {
		t.Errorf("flushes on start with both down: %v", f)
	}
}

// The report combines health, latency, nft counters and conntrack flows.
func TestReport(t *testing.T) {
	h := newHarness(t)
	h.tables.counters = map[string]nft.Counter{
		nft.CounterNew: {Packets: 10}, nft.CounterLocal: {Packets: 1}, nft.CounterExcluded: {Packets: 2},
		nft.DefaultCounter("wg-b"): {Packets: 4}, nft.StaticCounter("wg-a"): {Packets: 2},
		nft.RestoreCounter("wg-b"): {Packets: 30, Bytes: 4000},
	}
	dumps := 0
	h.d.flows.Dump = func() ([]flows.Entry, error) {
		dumps++
		return []flows.Entry{{Mark: 0x2, Dst: netip.MustParseAddr("203.0.113.9")}, {Mark: 0}}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := h.d.activate(ctx, h.d.cfg, nil); err != nil {
		t.Fatal(err)
	}

	r := h.d.report(status.Request{})
	if r.Connections != (status.Connections{New: 10, Local: 1, Excluded: 2, Unmarked: 1}) {
		t.Errorf("connections: %+v", r.Connections)
	}
	a, b := r.Tunnels[0], r.Tunnels[1]
	if a.Static != 2 || b.Default != 4 || b.Upstream.Bytes != 4000 {
		t.Errorf("tunnel counters: %+v / %+v", a, b)
	}
	if len(a.Latency) != 1 || a.Latency[0].Last.D() != time.Millisecond || a.History != nil {
		t.Errorf("latency: %+v, history %v", a.Latency, a.History)
	}
	if r.Flows != nil || dumps != 0 {
		t.Error("flows dumped without being requested")
	}

	r = h.d.report(status.Request{Flows: true, History: true})
	if r.Flows == nil || r.Flows.Tunnels["wg-b"].Flows != 1 || r.Flows.Other != 1 {
		t.Errorf("flows: %+v", r.Flows)
	}
	if len(r.Tunnels[0].History) != 1 || len(r.Tunnels[0].History[0].Samples) == 0 {
		t.Errorf("history: %+v", r.Tunnels[0].History)
	}

	h.d.flows.Dump = func() ([]flows.Entry, error) { return nil, errors.New("no ctnetlink") }
	h.d.flows.MaxAge = 0
	if r := h.d.report(status.Request{Flows: true}); r.Flows != nil || len(r.Warnings) != 1 {
		t.Errorf("dump error: flows %+v, warnings %v", r.Flows, r.Warnings)
	}
}
