// Package config loads and validates the tunsel configuration file.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/matfax/tunsel/internal/nft"
)

type Config struct {
	NFT          NFT          `yaml:"nft"`
	Tunnels      []Tunnel     `yaml:"tunnels"`
	DefaultOrder []string     `yaml:"default_order"`
	Ingress      Ingress      `yaml:"ingress"`
	Exclude      []Prefix     `yaml:"exclude"`
	StaticPref   []StaticPref `yaml:"static_pref"`
	Conntrack    Conntrack    `yaml:"conntrack"`
	Learning     Learning     `yaml:"learning"`
	Log          Log          `yaml:"log"`
	Status       Status       `yaml:"status"`
	Metrics      Metrics      `yaml:"metrics"`
}

type NFT struct {
	Table         string `yaml:"table"`
	MarkMask      uint32 `yaml:"mark_mask"`
	CleanupOnExit bool   `yaml:"cleanup_on_exit"`
}

type Tunnel struct {
	Name string `yaml:"name"`
	Mark uint32 `yaml:"mark"`
	// Families the tunnel carries; default both. A family the tunnel
	// does not carry is never steered into it.
	Families []string `yaml:"families"`
	Health   Health   `yaml:"health"`

	IPv4, IPv6 bool `yaml:"-"`
}

// Carries reports whether the tunnel carries traffic of addr's family.
func (t *Tunnel) Carries(addr netip.Addr) bool {
	if addr.Is4() {
		return t.IPv4
	}
	return t.IPv6
}

type Health struct {
	Targets      []netip.Addr `yaml:"targets"`
	Probe        string       `yaml:"probe"`
	Interval     Duration     `yaml:"interval"`
	Timeout      Duration     `yaml:"timeout"`
	MinOK        int          `yaml:"min_ok"`
	FailAfter    int          `yaml:"fail_after"`
	RecoverAfter int          `yaml:"recover_after"`

	ProbeKind ProbeKind `yaml:"-"`
	ProbePort uint16    `yaml:"-"`
}

type ProbeKind int

const (
	ProbeICMP ProbeKind = iota
	ProbeTCP
)

type Ingress struct {
	Interfaces         []string `yaml:"interfaces"`
	IncludeLocalOutput bool     `yaml:"include_local_output"`
}

type StaticPref struct {
	Prefix Prefix `yaml:"prefix"`
	Tunnel string `yaml:"tunnel"`
}

type Conntrack struct {
	// Delete conntrack entries of a tunnel when it becomes unhealthy, so
	// that long-lived flows (UDP, QUIC) are re-decided instead of staying
	// pinned to a dead tunnel. Default true.
	FlushOnUnhealthy *bool `yaml:"flush_on_unhealthy"`
}

type Learning struct {
	Enabled    bool        `yaml:"enabled"`
	Candidates Candidates  `yaml:"candidates"`
	Probe      LearnProbe  `yaml:"probe"`
	MinGain    MinGain     `yaml:"min_gain"`
	TTL        Duration    `yaml:"ttl"`
	FlapDamp   FlapDamping `yaml:"flap_damping"`
}

type Candidates struct {
	Source  string   `yaml:"source"`
	TopN    int      `yaml:"top_n"`
	Refresh Duration `yaml:"refresh"`
}

type LearnProbe struct {
	Port    uint16   `yaml:"port"`
	Samples int      `yaml:"samples"`
	Timeout Duration `yaml:"timeout"`
}

type MinGain struct {
	Abs Duration `yaml:"abs"`
	Rel Percent  `yaml:"rel"`
}

type FlapDamping struct {
	Window      Duration `yaml:"window"`
	MaxSwitches int      `yaml:"max_switches"`
}

type Log struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

type Status struct {
	Socket string `yaml:"socket"`
}

type Metrics struct {
	Listen string `yaml:"listen"`
}

const DefaultSocket = "/run/tunsel/tunsel.sock"

// Duration is a time.Duration written as a Go duration string ("10s").
type Duration time.Duration

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: invalid duration %q", n.Line, n.Value)
	}
	*d = Duration(v)
	return nil
}

func (d Duration) D() time.Duration { return time.Duration(d) }

// Percent is a fraction written as "15%".
type Percent float64

func (p *Percent) UnmarshalYAML(n *yaml.Node) error {
	s, ok := strings.CutSuffix(strings.TrimSpace(n.Value), "%")
	v, err := strconv.ParseFloat(s, 64)
	if !ok || err != nil || v < 0 {
		return fmt.Errorf("line %d: invalid percentage %q", n.Line, n.Value)
	}
	*p = Percent(v / 100)
	return nil
}

// Prefix is a CIDR prefix; a bare address means a host prefix.
type Prefix struct{ netip.Prefix }

func (p *Prefix) UnmarshalYAML(n *yaml.Node) error {
	v, err := ParsePrefix(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	p.Prefix = v
	return nil
}

func ParsePrefix(s string) (netip.Prefix, error) {
	if !strings.Contains(s, "/") {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("invalid prefix %q", s)
		}
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid prefix %q", s)
	}
	if p.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("invalid prefix %q: use plain IPv4 notation", s)
	}
	if p != p.Masked() {
		return netip.Prefix{}, fmt.Errorf("prefix %q has host bits set (did you mean %s?)", s, p.Masked())
	}
	return p, nil
}

// Load reads, parses and validates a configuration file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse parses and validates configuration data. Unknown keys are errors.
func Parse(data []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	c.setDefaults()
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) setDefaults() {
	if c.NFT.Table == "" {
		c.NFT.Table = "tunsel"
	}
	for i := range c.Tunnels {
		t := &c.Tunnels[i]
		if len(t.Families) == 0 {
			t.Families = []string{"ipv4", "ipv6"}
		}
		h := &t.Health
		if h.Probe == "" {
			h.Probe = "icmp"
		}
		if h.Interval == 0 {
			h.Interval = Duration(10 * time.Second)
		}
		if h.Timeout == 0 {
			h.Timeout = Duration(2 * time.Second)
		}
		if h.MinOK == 0 {
			h.MinOK = 1
		}
		if h.FailAfter == 0 {
			h.FailAfter = 3
		}
		if h.RecoverAfter == 0 {
			h.RecoverAfter = 3
		}
	}
	if c.Conntrack.FlushOnUnhealthy == nil {
		t := true
		c.Conntrack.FlushOnUnhealthy = &t
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Log.Format == "" {
		c.Log.Format = "text"
	}
	if c.Status.Socket == "" {
		c.Status.Socket = DefaultSocket
	}
}

// Linux IFNAMSIZ is 16 including the terminating NUL.
var ifnameRE = regexp.MustCompile(`^[^/\s:]{1,15}$`)

var tableRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

func (c *Config) validate() error {
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if !tableRE.MatchString(c.NFT.Table) {
		fail("nft.table %q: must match %s", c.NFT.Table, tableRE)
	}
	if c.NFT.MarkMask == 0 {
		fail("nft.mark_mask: must be non-zero")
	}

	if len(c.Tunnels) == 0 {
		fail("tunnels: at least one tunnel is required")
	}
	byName := map[string]*Tunnel{}
	marks := map[uint32]string{}
	chains := map[string]string{}
	for i := range c.Tunnels {
		t := &c.Tunnels[i]
		where := fmt.Sprintf("tunnels[%d] (%s)", i, t.Name)
		if !ifnameRE.MatchString(t.Name) {
			fail("%s: name must be a valid interface name (1-15 chars, no '/', ':' or whitespace)", where)
		} else if _, dup := byName[t.Name]; dup {
			fail("%s: duplicate tunnel name", where)
		} else if other, dup := chains[nft.ChainName(t.Name)]; dup {
			fail("%s: name maps to the same nft chain (%s) as %s; rename one", where, nft.ChainName(t.Name), other)
		}
		chains[nft.ChainName(t.Name)] = t.Name
		byName[t.Name] = t

		switch {
		case t.Mark == 0:
			fail("%s: mark must be non-zero", where)
		case t.Mark&^c.NFT.MarkMask != 0:
			fail("%s: mark %#x has bits outside mark_mask %#x", where, t.Mark, c.NFT.MarkMask)
		default:
			if other, dup := marks[t.Mark]; dup {
				fail("%s: mark %#x already used by %s", where, t.Mark, other)
			}
			marks[t.Mark] = t.Name
		}

		for _, f := range t.Families {
			switch f {
			case "ipv4":
				t.IPv4 = true
			case "ipv6":
				t.IPv6 = true
			default:
				fail("%s: unknown family %q (ipv4 | ipv6)", where, f)
			}
		}

		h := &t.Health
		if len(h.Targets) == 0 {
			fail("%s: health.targets: at least one target is required", where)
		}
		for j, a := range h.Targets {
			a = a.Unmap()
			h.Targets[j] = a
			if a.Zone() != "" || !a.IsValid() {
				fail("%s: health.targets: invalid address %s", where, a)
			} else if !t.Carries(a) {
				fail("%s: health target %s: tunnel does not carry its family", where, a)
			}
		}
		switch {
		case h.Probe == "icmp":
			h.ProbeKind = ProbeICMP
		case strings.HasPrefix(h.Probe, "tcp:"):
			port, err := strconv.ParseUint(strings.TrimPrefix(h.Probe, "tcp:"), 10, 16)
			if err != nil || port == 0 {
				fail("%s: health.probe %q: invalid port", where, h.Probe)
			}
			h.ProbeKind, h.ProbePort = ProbeTCP, uint16(port)
		default:
			fail("%s: health.probe %q: expected icmp or tcp:<port>", where, h.Probe)
		}
		if h.Interval.D() <= 0 || h.Timeout.D() <= 0 {
			fail("%s: health.interval and health.timeout must be positive", where)
		} else if h.Timeout >= h.Interval {
			fail("%s: health.timeout (%s) must be shorter than health.interval (%s)", where, h.Timeout.D(), h.Interval.D())
		}
		if h.MinOK < 1 || h.MinOK > len(h.Targets) {
			fail("%s: health.min_ok must be between 1 and the number of targets (%d)", where, len(h.Targets))
		}
		if h.FailAfter < 1 || h.RecoverAfter < 1 {
			fail("%s: health.fail_after and health.recover_after must be at least 1", where)
		}
	}

	if len(c.DefaultOrder) == 0 {
		fail("default_order: at least one tunnel is required")
	}
	seen := map[string]bool{}
	for _, n := range c.DefaultOrder {
		if byName[n] == nil {
			fail("default_order: unknown tunnel %q", n)
		} else if seen[n] {
			fail("default_order: tunnel %q listed twice", n)
		}
		seen[n] = true
	}

	if len(c.Ingress.Interfaces) == 0 && !c.Ingress.IncludeLocalOutput {
		fail("ingress: no interfaces and include_local_output is false; nothing would be steered")
	}
	for _, n := range c.Ingress.Interfaces {
		if !ifnameRE.MatchString(n) {
			fail("ingress.interfaces: invalid interface name %q", n)
		} else if byName[n] != nil {
			fail("ingress.interfaces: %q is a tunnel", n)
		}
	}

	staticSeen := map[netip.Prefix]bool{}
	for i, s := range c.StaticPref {
		t := byName[s.Tunnel]
		switch {
		case !s.Prefix.IsValid():
			fail("static_pref[%d]: prefix is required", i)
		case t == nil:
			fail("static_pref[%d] (%s): unknown tunnel %q", i, s.Prefix, s.Tunnel)
		case !t.Carries(s.Prefix.Addr()):
			fail("static_pref[%d] (%s): tunnel %s does not carry this family", i, s.Prefix, s.Tunnel)
		case staticSeen[s.Prefix.Prefix]:
			fail("static_pref[%d]: prefix %s listed twice", i, s.Prefix)
		}
		staticSeen[s.Prefix.Prefix] = true
	}

	if c.Learning.Enabled {
		fail("learning.enabled: per-destination learning (phase 2) is not implemented in this version")
	}
	if c.Metrics.Listen != "" {
		fail("metrics.listen: the metrics endpoint is not implemented in this version; leave it empty")
	}

	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		fail("log.level %q: expected debug | info | warn | error", c.Log.Level)
	}
	switch c.Log.Format {
	case "text", "json":
	default:
		fail("log.format %q: expected text | json", c.Log.Format)
	}
	if !filepath.IsAbs(c.Status.Socket) {
		fail("status.socket %q: must be an absolute path", c.Status.Socket)
	}

	return errors.Join(errs...)
}

// Tunnel returns the tunnel with the given name, or nil.
func (c *Config) Tunnel(name string) *Tunnel {
	for i := range c.Tunnels {
		if c.Tunnels[i].Name == name {
			return &c.Tunnels[i]
		}
	}
	return nil
}
