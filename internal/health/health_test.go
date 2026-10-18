package health

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/matfax/tunsel/internal/config"
)

func TestTracker(t *testing.T) {
	pass, fail, down := Round{Passed: true}, Round{}, Round{Down: true}
	steps := []struct {
		r    Round
		want State
	}{
		{fail, Unhealthy}, // first round decides directly
		{pass, Unhealthy},
		{fail, Unhealthy}, // resets the pass streak
		{pass, Unhealthy},
		{pass, Unhealthy},
		{pass, Healthy}, // recover_after = 3
		{fail, Healthy},
		{pass, Healthy}, // resets the fail streak
		{fail, Healthy},
		{fail, Unhealthy}, // fail_after = 2
		{pass, Unhealthy},
		{pass, Unhealthy},
		{pass, Healthy},
		{down, Unhealthy}, // link down bypasses fail_after
	}
	tr := Tracker{FailAfter: 2, RecoverAfter: 3}
	for i, s := range steps {
		tr.Observe(s.r)
		if tr.State != s.want {
			t.Fatalf("step %d: got %s, want %s", i, tr.State, s.want)
		}
	}
	tr = Tracker{FailAfter: 2, RecoverAfter: 3}
	if !tr.Observe(pass) || tr.State != Healthy {
		t.Fatal("first passing round should become healthy")
	}
}

type fakeProber struct {
	mu   sync.Mutex
	down map[netip.Addr]bool
	seen []Probe
}

func (f *fakeProber) Probe(ctx context.Context, p Probe) error {
	f.mu.Lock()
	f.seen = append(f.seen, p)
	down := f.down[p.Target]
	f.mu.Unlock()
	if down {
		<-ctx.Done()
		return ctx.Err()
	}
	return nil
}

func tunnel() config.Tunnel {
	return config.Tunnel{Name: "wg-a", Mark: 0x1, Health: config.Health{
		Targets:  []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")},
		Interval: config.Duration(20 * time.Millisecond), Timeout: config.Duration(10 * time.Millisecond),
		MinOK: 2, FailAfter: 2, RecoverAfter: 2,
	}}
}

func TestMonitorRound(t *testing.T) {
	fp := &fakeProber{down: map[netip.Addr]bool{}}
	link, route := "up", "wg-a"
	m := NewMonitor(tunnel(), Env{
		Prober: fp,
		Link:   func(string) (string, error) { return link, nil },
		Route:  func(netip.Addr, uint32) (string, error) { return route, nil },
	})
	ctx := context.Background()

	if !m.RunRound(ctx) || m.State() != Healthy {
		t.Fatalf("want healthy, got %s", m.State())
	}
	if len(fp.seen) != 2 || fp.seen[0].Mark != 0x1 || fp.seen[0].Iface != "wg-a" {
		t.Fatalf("probes: %+v", fp.seen)
	}

	fp.down[netip.MustParseAddr("2001:db8::1")] = true // below min_ok = 2
	m.RunRound(ctx)
	if s := m.Snapshot(); s.State != Healthy || s.OK != 1 || s.Fails != 1 || len(s.Errors) != 1 {
		t.Fatalf("after one failed round: %+v", s)
	}
	if !m.RunRound(ctx) || m.State() != Unhealthy {
		t.Fatal("want unhealthy after fail_after rounds")
	}

	delete(fp.down, netip.MustParseAddr("2001:db8::1"))
	m.RunRound(ctx)
	m.RunRound(ctx)
	if m.State() != Healthy {
		t.Fatal("want recovered")
	}

	link = "down"
	n := len(fp.seen)
	if !m.RunRound(ctx) || m.State() != Unhealthy || len(fp.seen) != n {
		t.Fatal("link down: want immediate unhealthy without probing")
	}
	if s := m.Snapshot(); s.Link != "down" {
		t.Fatalf("link: %s", s.Link)
	}

	// Link up but the marked route leaves via another interface.
	link, route = "up", "eth0"
	m.RunRound(ctx)
	m.RunRound(ctx)
	if s := m.Snapshot(); s.State != Unhealthy || len(fp.seen) != n || !strings.Contains(s.Errors[0], "leaves via eth0") {
		t.Fatalf("route check: %+v", s)
	}
	route = "wg-a"
	m.RunRound(ctx)
	m.RunRound(ctx)
	if m.State() != Healthy {
		t.Fatal("want recovered once the route is back")
	}
}

func TestMonitorRunAndAdopt(t *testing.T) {
	fp := &fakeProber{down: map[netip.Addr]bool{}}
	env := Env{
		Prober: fp,
		Link:   func(string) (string, error) { return "up", nil },
		Route:  func(netip.Addr, uint32) (string, error) { return "wg-a", nil },
	}
	m := NewMonitor(tunnel(), env)
	m.RunRound(context.Background())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := make(chan Event)
	go m.Run(ctx, 7, events)

	fp.mu.Lock()
	fp.down[netip.MustParseAddr("192.0.2.1")] = true
	fp.mu.Unlock()
	select {
	case ev := <-events:
		if ev.State != Unhealthy || ev.Gen != 7 || ev.Tunnel != "wg-a" {
			t.Fatalf("event: %+v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event")
	}
	cancel()

	n := NewMonitor(tunnel(), env)
	n.Adopt(m)
	if n.State() != Unhealthy || n.Snapshot().Since.IsZero() {
		t.Fatalf("adopt: %+v", n.Snapshot())
	}
}

func TestStateText(t *testing.T) {
	for _, s := range []State{Unknown, Healthy, Unhealthy} {
		b, _ := s.MarshalText()
		var got State
		if err := got.UnmarshalText(b); err != nil || got != s {
			t.Errorf("%s: %v %v", s, got, err)
		}
	}
	var s State
	if err := s.UnmarshalText([]byte("x")); err == nil {
		t.Error("want error")
	}
}
