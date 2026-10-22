package engine

import (
	"fmt"
	"math"
	"net/netip"
	"strings"
	"testing"

	"github.com/matfax/tunsel/internal/config"
	"github.com/matfax/tunsel/internal/ranges"
)

const cfgYAML = `
nft: { mark_mask: 0xf }
tunnels:
  - { name: wg-a, mark: 0x1, health: { targets: [192.0.2.1] } }
  - { name: wg-b, mark: 0x2, families: [ipv4], health: { targets: [198.51.100.1] } }
  - { name: wg-c, mark: 0x3, health: { targets: [203.0.113.1] } }
default_order: [wg-b, wg-a]
ingress: { interfaces: [lan0] }
exclude: [10.0.0.0/8, 10.1.0.0/16, fe80::/10]
static_pref:
  - { prefix: 203.0.113.0/24, tunnel: wg-a }
  - { prefix: 203.0.113.128/25, tunnel: wg-c }
  - { prefix: 2001:db8:100::/48, tunnel: wg-c }
`

func healthy(names ...string) func(string) bool {
	return func(n string) bool {
		for _, x := range names {
			if x == n {
				return true
			}
		}
		return false
	}
}

func str[V comparable](rs []ranges.Range[V]) string {
	var p []string
	for _, r := range rs {
		p = append(p, fmt.Sprintf("%s-%s=%v", r.From, r.To, r.Value))
	}
	return strings.Join(p, " ")
}

func TestBuild(t *testing.T) {
	cfg, err := config.Parse([]byte(cfgYAML))
	if err != nil {
		t.Fatal(err)
	}

	rs, d := Build(cfg, healthy("wg-a", "wg-b", "wg-c"), Defaults{})
	if d != (Defaults{V4: "wg-b", V6: "wg-a"}) {
		t.Errorf("defaults: %+v (wg-b carries no IPv6)", d)
	}
	if got := str(rs.Exclude4); got != "10.0.0.0-10.255.255.255={}" {
		t.Errorf("exclude4: %s", got)
	}
	if got := str(rs.Static4); got != "203.0.113.0-203.0.113.127=wg-a 203.0.113.128-203.0.113.255=wg-c" {
		t.Errorf("static4: %s", got)
	}
	if len(rs.Tunnels) != 3 || rs.Mask != 0xf || rs.Ingress[0] != "lan0" {
		t.Errorf("ruleset: %+v", rs)
	}

	// wg-c down: its more specific static falls back to the covering wg-a one.
	rs, _ = Build(cfg, healthy("wg-a", "wg-b"), d)
	if got := str(rs.Static4); got != "203.0.113.0-203.0.113.255=wg-a" {
		t.Errorf("static4 without wg-c: %s", got)
	}
	if len(rs.Static6) != 0 {
		t.Errorf("static6 without wg-c: %s", str(rs.Static6))
	}

	// wg-b down: IPv4 default moves to wg-a.
	_, d2 := Build(cfg, healthy("wg-a"), d)
	if d2 != (Defaults{V4: "wg-a", V6: "wg-a"}) {
		t.Errorf("defaults without wg-b: %+v", d2)
	}

	// nothing healthy: keep the last defaults (fail closed).
	rs, d3 := Build(cfg, healthy(), d2)
	if d3 != d2 || rs.Default4 != "wg-a" || len(rs.Static4) != 0 {
		t.Errorf("nothing healthy: %+v %+v", d3, rs)
	}

	// nothing healthy at startup: no default at all.
	if _, d4 := Build(cfg, healthy(), Defaults{}); d4 != (Defaults{}) {
		t.Errorf("cold start: %+v", d4)
	}

	// previous default no longer in the config is not kept.
	if _, d5 := Build(cfg, healthy(), Defaults{V4: "gone"}); d5.V4 != "" {
		t.Errorf("stale previous default kept: %+v", d5)
	}
}

func TestCover(t *testing.T) {
	cfg, err := config.Parse([]byte(cfgYAML))
	if err != nil {
		t.Fatal(err)
	}
	rs, _ := Build(cfg, healthy("wg-a", "wg-b", "wg-c"), Defaults{})
	c := Cover(cfg, rs)
	// wg-c's /25 is carved out of wg-a's /24.
	if got := c.Static["wg-a"]; got != (RangeStats{Prefixes: 1, Ranges: 1, IPv4: 128}) {
		t.Errorf("wg-a: %+v", got)
	}
	if got := c.Static["wg-c"]; got != (RangeStats{Prefixes: 2, Ranges: 2, IPv4: 128, IPv6: 1 << 16}) {
		t.Errorf("wg-c: %+v", got)
	}
	if got, ok := c.Static["wg-b"]; !ok || got != (RangeStats{}) {
		t.Errorf("wg-b: %+v %v", got, ok)
	}
	// 10.1.0.0/16 merges into 10.0.0.0/8.
	if got := c.Exclude; got != (RangeStats{Prefixes: 3, Ranges: 2, IPv4: 1 << 24, IPv6: 1 << 54}) {
		t.Errorf("exclude: %+v", got)
	}

	rs, _ = Build(cfg, healthy("wg-a", "wg-b"), Defaults{})
	c = Cover(cfg, rs)
	if a, cc := c.Static["wg-a"], c.Static["wg-c"]; a.IPv4 != 256 || cc != (RangeStats{Prefixes: 2}) {
		t.Errorf("wg-c down: wg-a %+v, wg-c %+v", a, cc)
	}

	var s RangeStats
	s.add(netip.MustParseAddr("::"), netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"))
	if s.IPv6 != math.MaxUint64 {
		t.Errorf("::/0 should saturate: %d", s.IPv6)
	}
}

// Route mirrors the ruleset: the most specific static preference of a
// healthy tunnel, else the default of the family.
func TestRoute(t *testing.T) {
	cfg, err := config.Parse([]byte(cfgYAML))
	if err != nil {
		t.Fatal(err)
	}
	d := Defaults{V4: "wg-b", V6: "wg-a"}
	for _, tc := range []struct {
		addr    string
		healthy []string
		tunnel  string
		static  bool
	}{
		{"203.0.113.200", []string{"wg-a", "wg-c"}, "wg-c", true},
		{"203.0.113.200", []string{"wg-a"}, "wg-a", true},
		{"203.0.113.200", nil, "wg-b", false},
		{"198.18.0.1", []string{"wg-a", "wg-c"}, "wg-b", false},
		{"2001:db8:100::1", []string{"wg-c"}, "wg-c", true},
		{"2001:db8:200::1", []string{"wg-c"}, "wg-a", false},
	} {
		tun, static := Route(cfg, healthy(tc.healthy...), d, netip.MustParseAddr(tc.addr))
		if tun != tc.tunnel || static != tc.static {
			t.Errorf("%s with %v healthy: %s %v, want %s %v", tc.addr, tc.healthy, tun, static, tc.tunnel, tc.static)
		}
	}
	if !Excluded(cfg, netip.MustParseAddr("10.1.2.3")) || Excluded(cfg, netip.MustParseAddr("198.18.0.1")) {
		t.Error("Excluded")
	}
}
