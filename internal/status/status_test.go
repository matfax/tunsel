package status

import (
	"context"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/matfax/tunsel/internal/flows"
	"github.com/matfax/tunsel/internal/health"
	"github.com/matfax/tunsel/internal/nft"
)

func TestParseRequest(t *testing.T) {
	for in, want := range map[string]Request{
		"status\n":               {},
		"status flows\n":         {Flows: true},
		"status history flows\n": {Flows: true, History: true},
	} {
		if got, err := parseRequest(in); err != nil || got != want {
			t.Errorf("%q: %+v, %v", in, got, err)
		}
		if got, _ := parseRequest(want.String()); got != want {
			t.Errorf("String() does not round-trip: %q", want.String())
		}
	}
	for _, bad := range []string{"", "stats\n", "status bogus\n"} {
		if _, err := parseRequest(bad); err == nil {
			t.Errorf("%q: expected error", bad)
		}
	}
}

func sample() Report {
	target := netip.MustParseAddr("192.0.2.1")
	return Report{
		Version: "test", Table: "tunsel", StartedAt: time.Now(), Default4: "wg-a",
		Connections: Connections{New: 5, Excluded: 1},
		Tunnels: []Tunnel{{
			Name: "wg-a", Mark: 1, Static: 3, Default: 1,
			Upstream: nft.Counter{Packets: 9, Bytes: 3 << 20},
			Snapshot: health.Snapshot{State: health.Healthy, Link: "up", Latency: []health.Latency{
				{Target: target, Last: health.Millis(12 * time.Millisecond), Avg: health.Millis(10 * time.Millisecond), Samples: 2},
			}},
		}},
	}
}

func TestServeFetch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sock := filepath.Join(t.TempDir(), "s.sock")
	var got []Request
	err := Serve(ctx, sock, func(req Request) Report {
		got = append(got, req)
		r := sample()
		if req.Flows {
			r.Flows = &Flows{Tunnels: map[string]flows.Group{"wg-a": {Flows: 2}}}
		}
		return r
	})
	if err != nil {
		t.Fatal(err)
	}
	r, err := Fetch(sock, Request{})
	if err != nil || r.Flows != nil || r.Tunnels[0].Latency[0].Avg.D() != 10*time.Millisecond {
		t.Fatalf("%+v, %v", r, err)
	}
	r, err = Fetch(sock, Request{Flows: true})
	if err != nil || r.Flows.Tunnels["wg-a"].Flows != 2 {
		t.Fatalf("flows: %+v, %v", r, err)
	}
	if len(got) != 2 || got[1] != (Request{Flows: true}) {
		t.Errorf("requests: %+v", got)
	}
}

func TestRender(t *testing.T) {
	r := sample()
	r.Flows = &Flows{Tunnels: map[string]flows.Group{"wg-a": {Flows: 2, Destinations: 1}}}
	r.Tunnels[0].History = []health.History{{Target: netip.MustParseAddr("192.0.2.1"), Samples: []health.Sample{
		{OK: true, RTT: health.Millis(time.Millisecond)}, {}, {OK: true, RTT: health.Millis(8 * time.Millisecond)},
	}}}
	var b strings.Builder
	r.Render(&b)
	out := b.String()
	for _, want := range []string{
		"new connections: 5 (excluded 1, local 0, unmarked 0)",
		"12.0ms", "10.0ms",
		"3.0 MiB, 9 pkts",
		"▁·█ (max 8.0ms)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

// Sections without data are left out instead of rendering empty tables.
func TestRenderSparse(t *testing.T) {
	r := Report{
		Version: "test", Table: "tunsel", StartedAt: time.Now(),
		Apply:    Apply{At: time.Now(), Error: "nft: rejected"},
		Warnings: []string{"counters: no table"},
		Tunnels:  []Tunnel{{Name: "wg-a", Mark: 1}},
	}
	var b strings.Builder
	r.Render(&b)
	out := b.String()
	for _, want := range []string{"default: ipv4 none (unmarked)", "last apply FAILED", "warning: counters: no table", "exclude: none"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	for _, unwanted := range []string{"flows at", "RTT history"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("output has %q without data:\n%s", unwanted, out)
		}
	}
}
