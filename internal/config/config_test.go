package config

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestExampleConfig(t *testing.T) {
	c, err := Load("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if c.NFT.MarkMask != 0xf || len(c.Tunnels) != 2 {
		t.Fatalf("unexpected config: %+v", c.NFT)
	}
	a := c.Tunnel("wg-a")
	if a.Mark != 0x1 || !a.IPv4 || !a.IPv6 {
		t.Errorf("wg-a: %+v", a)
	}
	if a.Health.Interval.D() != 10*time.Second || a.Health.ProbeKind != ProbeICMP {
		t.Errorf("wg-a health: %+v", a.Health)
	}
	if got := a.Health.Targets[0]; got != netip.MustParseAddr("192.0.2.1") {
		t.Errorf("target: %s", got)
	}
	if c.Learning.MinGain.Rel != 0.15 {
		t.Errorf("min_gain.rel: %v", c.Learning.MinGain.Rel)
	}
	if !*c.Conntrack.FlushOnUnhealthy {
		t.Error("flush_on_unhealthy should default to true")
	}
}

const base = `
nft: { table: tunsel, mark_mask: 0xf }
tunnels:
  - name: wg-a
    mark: 0x1
    health: { targets: [192.0.2.1], probe: "tcp:443" }
  - name: wg-b
    mark: 0x2
    families: [ipv4]
    health: { targets: [198.51.100.1] }
default_order: [wg-b, wg-a]
ingress: { interfaces: [lan0] }
`

var oneTunnel = strings.Replace(strings.Replace(base, `  - name: wg-b
    mark: 0x2
    families: [ipv4]
    health: { targets: [198.51.100.1] }
`, "", 1), "[wg-b, wg-a]", "[wg-a]", 1)

// Learning is accepted with two tunnels.
func TestLearningConfig(t *testing.T) {
	if _, err := Parse([]byte(oneTunnel)); err != nil {
		t.Fatalf("one tunnel without learning: %v", err)
	}
	c, err := Parse([]byte(base + "learning: { enabled: true }\n"))
	if err != nil {
		t.Fatal(err)
	}
	if l := c.Learning; !l.Enabled || l.Candidates.Source != "conntrack" || l.Candidates.Refresh.D() != 5*time.Minute {
		t.Errorf("learning: %+v", l)
	}
}

func TestDefaults(t *testing.T) {
	c, err := Parse([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	h := c.Tunnel("wg-b").Health
	if h.Interval.D() != 10*time.Second || h.Timeout.D() != 2*time.Second || h.MinOK != 1 || h.FailAfter != 3 || h.RecoverAfter != 3 {
		t.Errorf("health defaults: %+v", h)
	}
	if a := c.Tunnel("wg-a").Health; a.ProbeKind != ProbeTCP || a.ProbePort != 443 {
		t.Errorf("tcp probe: %+v", a)
	}
	if b := c.Tunnel("wg-b"); !b.IPv4 || b.IPv6 {
		t.Errorf("families: %+v", b)
	}
	if c.Status.Socket != DefaultSocket {
		t.Errorf("socket: %s", c.Status.Socket)
	}
	l := c.Learning
	if l.Candidates.Source != "conntrack" || l.Candidates.TopN != 100 || l.Probe.Port != 443 || l.Probe.Samples != 3 ||
		l.MinGain.Rel != 0.15 || l.TTL.D() != time.Hour || l.FlapDamp.MaxSwitches != 2 {
		t.Errorf("learning defaults: %+v", l)
	}
}

func TestInvalid(t *testing.T) {
	cases := []struct {
		name, edit, want string
	}{
		{"unknown key", base + "bogus: 1\n", "field bogus not found"},
		{"mark outside mask", strings.Replace(base, "mark: 0x2", "mark: 0x10", 1), "outside mark_mask"},
		{"duplicate mark", strings.Replace(base, "mark: 0x2", "mark: 0x1", 1), "already used"},
		{"unknown default", strings.Replace(base, "[wg-b, wg-a]", "[wg-c]", 1), `unknown tunnel "wg-c"`},
		{"host bits", base + "exclude: [10.0.0.1/8]\n", "host bits set"},
		{"static family", base + "static_pref: [{ prefix: 2001:db8::/32, tunnel: wg-b }]\n", "does not carry"},
		{"static unknown", base + "static_pref: [{ prefix: 203.0.113.0/24, tunnel: nope }]\n", "unknown tunnel"},
		{"target family", strings.Replace(base, "[198.51.100.1]", "[2001:db8::1]", 1), "does not carry its family"},
		{"timeout", strings.Replace(base, `probe: "tcp:443"`, "interval: 1s, timeout: 1s", 1), "must be shorter"},
		{"min_ok", strings.Replace(base, `probe: "tcp:443"`, "min_ok: 2", 1), "min_ok"},
		{"probe", strings.Replace(base, `"tcp:443"`, "udp", 1), "expected icmp or tcp"},
		{"ingress tunnel", strings.Replace(base, "[lan0]", "[wg-a]", 1), "is a tunnel"},
		{"chain name collision", strings.Replace(base, "name: wg-b", "name: wg.a", 1), "same nft chain"},
		{"learning one tunnel", oneTunnel + "learning: { enabled: true }\n", "needs at least two tunnels"},
		{"learning source", base + "learning: { candidates: { source: dns } }\n", `source "dns": expected conntrack`},
		{"learning top_n", base + "learning: { candidates: { top_n: -1 } }\n", "top_n: must be at least 1"},
		{"learning ttl", base + "learning: { ttl: -1h }\n", "learning.ttl: must be positive"},
		{"learning percent", base + "learning: { min_gain: { rel: 15 } }\n", `invalid percentage "15"`},
		{"duration", strings.Replace(base, `probe: "tcp:443"`, "interval: soon", 1), "invalid duration"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.edit))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestParsePrefix(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.10":    "192.0.2.10/32",
		"2001:db8::1":   "2001:db8::1/128",
		"10.0.0.0/8":    "10.0.0.0/8",
		"2001:db8::/32": "2001:db8::/32",
	} {
		p, err := ParsePrefix(in)
		if err != nil || p.String() != want {
			t.Errorf("%s: got %v, %v", in, p, err)
		}
	}
	for _, bad := range []string{"10.0.0.1/8", "x", "::ffff:10.0.0.0/104", "fe80::1%eth0"} {
		if _, err := ParsePrefix(bad); err == nil {
			t.Errorf("%s: expected error", bad)
		}
	}
}
