// Package config loads and validates the tunsel configuration file.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
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
	// Source is conntrack (the busiest current flows) or adguard (the
	// addresses AdGuard Home resolved since the last refresh).
	Source  string   `yaml:"source"`
	TopN    int      `yaml:"top_n"`
	Refresh Duration `yaml:"refresh"`
	AdGuard AdGuard  `yaml:"adguard"`
}

// AdGuard is the AdGuard Home instance whose query log supplies the
// candidates of source adguard.
type AdGuard struct {
	URL      string `yaml:"url"` // e.g. http://127.0.0.1:3000
	Username string `yaml:"username"`
	Password string `yaml:"password"`
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
	v, err := parseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*d = v
	return nil
}

func parseDuration(s string) (Duration, error) {
	v, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	return Duration(v), nil
}

func (d Duration) D() time.Duration { return time.Duration(d) }

// Percent is a fraction written as "15%".
type Percent float64

func (p *Percent) UnmarshalYAML(n *yaml.Node) error {
	v, err := parsePercent(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*p = v
	return nil
}

func parsePercent(s string) (Percent, error) {
	num, ok := strings.CutSuffix(strings.TrimSpace(s), "%")
	v, err := strconv.ParseFloat(num, 64)
	if !ok || err != nil || v < 0 {
		return 0, fmt.Errorf("invalid percentage %q", s)
	}
	return Percent(v / 100), nil
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

// Load reads, parses and validates a configuration file: YAML if its name
// ends in .yaml or .yml, UCI otherwise (/etc/config/tunsel on OpenWrt).
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	switch filepath.Ext(path) {
	case ".yaml", ".yml":
		return Parse(data)
	}
	return ParseUCI(data)
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
	c.Learning.setDefaults()
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

// setDefaults fills in the learning parameters (design §7). As elsewhere,
// zero means the default. AdGuard is polled more often than conntrack: it
// reports addresses before their first connection.
func (l *Learning) setDefaults() {
	setDefault(&l.Candidates.Source, "conntrack")
	setDefault(&l.Candidates.TopN, 100)
	if l.Candidates.Source == "adguard" {
		setDefault(&l.Candidates.Refresh, Duration(time.Minute))
	} else {
		setDefault(&l.Candidates.Refresh, Duration(5*time.Minute))
	}
	setDefault(&l.Probe.Port, 443)
	setDefault(&l.Probe.Samples, 3)
	setDefault(&l.Probe.Timeout, Duration(2*time.Second))
	setDefault(&l.MinGain.Abs, Duration(5*time.Millisecond))
	setDefault(&l.MinGain.Rel, 0.15)
	setDefault(&l.TTL, Duration(time.Hour))
	setDefault(&l.FlapDamp.Window, Duration(30*time.Minute))
	setDefault(&l.FlapDamp.MaxSwitches, 2)
}

func setDefault[T comparable](dst *T, v T) {
	var zero T
	if *dst == zero {
		*dst = v
	}
}

// Linux IFNAMSIZ is 16 including the terminating NUL.
var ifnameRE = regexp.MustCompile(`^[^/\s:]{1,15}$`)

var tableRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

// errList collects validation failures so all of them are reported at once.
type errList []error

func (e *errList) fail(format string, a ...any) { *e = append(*e, fmt.Errorf(format, a...)) }

func (c *Config) validate() error {
	var errs errList

	if !tableRE.MatchString(c.NFT.Table) {
		errs.fail("nft.table %q: must match %s", c.NFT.Table, tableRE)
	}
	if c.NFT.MarkMask == 0 {
		errs.fail("nft.mark_mask: must be non-zero")
	}

	byName := c.validateTunnels(&errs)
	c.validateDefaultOrder(&errs, byName)
	c.validateIngress(&errs, byName)
	c.validateStaticPref(&errs, byName)
	c.validateLearning(&errs)
	c.validateMisc(&errs)

	return errors.Join(errs...)
}

// validateTunnels checks every tunnel and returns them by name.
func (c *Config) validateTunnels(errs *errList) map[string]*Tunnel {
	if len(c.Tunnels) == 0 {
		errs.fail("tunnels: at least one tunnel is required")
	}
	byName := map[string]*Tunnel{}
	marks := map[uint32]string{}
	chains := map[string]string{}
	for i := range c.Tunnels {
		t := &c.Tunnels[i]
		where := fmt.Sprintf("tunnels[%d] (%s)", i, t.Name)
		if !ifnameRE.MatchString(t.Name) {
			errs.fail("%s: name must be a valid interface name (1-15 chars, no '/', ':' or whitespace)", where)
		} else if _, dup := byName[t.Name]; dup {
			errs.fail("%s: duplicate tunnel name", where)
		} else if other, dup := chains[nft.ChainName(t.Name)]; dup {
			errs.fail("%s: name maps to the same nft chain (%s) as %s; rename one", where, nft.ChainName(t.Name), other)
		}
		chains[nft.ChainName(t.Name)] = t.Name
		byName[t.Name] = t

		c.validateMark(errs, where, t, marks)
		validateFamilies(errs, where, t)
		validateHealth(errs, where, t)
	}
	return byName
}

func (c *Config) validateMark(errs *errList, where string, t *Tunnel, marks map[uint32]string) {
	switch {
	case t.Mark == 0:
		errs.fail("%s: mark must be non-zero", where)
	case t.Mark&^c.NFT.MarkMask != 0:
		errs.fail("%s: mark %#x has bits outside mark_mask %#x", where, t.Mark, c.NFT.MarkMask)
	default:
		if other, dup := marks[t.Mark]; dup {
			errs.fail("%s: mark %#x already used by %s", where, t.Mark, other)
		}
		marks[t.Mark] = t.Name
	}
}

func validateFamilies(errs *errList, where string, t *Tunnel) {
	for _, f := range t.Families {
		switch f {
		case "ipv4":
			t.IPv4 = true
		case "ipv6":
			t.IPv6 = true
		default:
			errs.fail("%s: unknown family %q (ipv4 | ipv6)", where, f)
		}
	}
}

func validateHealth(errs *errList, where string, t *Tunnel) {
	h := &t.Health
	if len(h.Targets) == 0 {
		errs.fail("%s: health.targets: at least one target is required", where)
	}
	for j, a := range h.Targets {
		a = a.Unmap()
		h.Targets[j] = a
		if a.Zone() != "" || !a.IsValid() {
			errs.fail("%s: health.targets: invalid address %s", where, a)
		} else if !t.Carries(a) {
			errs.fail("%s: health target %s: tunnel does not carry its family", where, a)
		}
	}
	parseProbe(errs, where, h)
	if h.Interval.D() <= 0 || h.Timeout.D() <= 0 {
		errs.fail("%s: health.interval and health.timeout must be positive", where)
	} else if h.Timeout >= h.Interval {
		errs.fail("%s: health.timeout (%s) must be shorter than health.interval (%s)", where, h.Timeout.D(), h.Interval.D())
	}
	if h.MinOK < 1 || h.MinOK > len(h.Targets) {
		errs.fail("%s: health.min_ok must be between 1 and the number of targets (%d)", where, len(h.Targets))
	}
	if h.FailAfter < 1 || h.RecoverAfter < 1 {
		errs.fail("%s: health.fail_after and health.recover_after must be at least 1", where)
	}
}

func parseProbe(errs *errList, where string, h *Health) {
	switch {
	case h.Probe == "icmp":
		h.ProbeKind = ProbeICMP
	case strings.HasPrefix(h.Probe, "tcp:"):
		port, err := strconv.ParseUint(strings.TrimPrefix(h.Probe, "tcp:"), 10, 16)
		if err != nil || port == 0 {
			errs.fail("%s: health.probe %q: invalid port", where, h.Probe)
		}
		h.ProbeKind, h.ProbePort = ProbeTCP, uint16(port)
	default:
		errs.fail("%s: health.probe %q: expected icmp or tcp:<port>", where, h.Probe)
	}
}

func (c *Config) validateDefaultOrder(errs *errList, byName map[string]*Tunnel) {
	if len(c.DefaultOrder) == 0 {
		errs.fail("default_order: at least one tunnel is required")
	}
	seen := map[string]bool{}
	for _, n := range c.DefaultOrder {
		if byName[n] == nil {
			errs.fail("default_order: unknown tunnel %q", n)
		} else if seen[n] {
			errs.fail("default_order: tunnel %q listed twice", n)
		}
		seen[n] = true
	}
}

func (c *Config) validateIngress(errs *errList, byName map[string]*Tunnel) {
	if len(c.Ingress.Interfaces) == 0 && !c.Ingress.IncludeLocalOutput {
		errs.fail("ingress: no interfaces and include_local_output is false; nothing would be steered")
	}
	for _, n := range c.Ingress.Interfaces {
		if !ifnameRE.MatchString(n) {
			errs.fail("ingress.interfaces: invalid interface name %q", n)
		} else if byName[n] != nil {
			errs.fail("ingress.interfaces: %q is a tunnel", n)
		}
	}
}

func (c *Config) validateStaticPref(errs *errList, byName map[string]*Tunnel) {
	staticSeen := map[netip.Prefix]bool{}
	for i, s := range c.StaticPref {
		t := byName[s.Tunnel]
		switch {
		case !s.Prefix.IsValid():
			errs.fail("static_pref[%d]: prefix is required", i)
		case t == nil:
			errs.fail("static_pref[%d] (%s): unknown tunnel %q", i, s.Prefix, s.Tunnel)
		case !t.Carries(s.Prefix.Addr()):
			errs.fail("static_pref[%d] (%s): tunnel %s does not carry this family", i, s.Prefix, s.Tunnel)
		case staticSeen[s.Prefix.Prefix]:
			errs.fail("static_pref[%d]: prefix %s listed twice", i, s.Prefix)
		}
		staticSeen[s.Prefix.Prefix] = true
	}
}

// validateLearning checks the learning parameters, also while learning is
// off, so that a typo shows up when it is saved rather than when learning
// is switched on.
func (c *Config) validateLearning(errs *errList) {
	l := &c.Learning
	if l.Enabled && len(c.Tunnels) < 2 {
		errs.fail("learning.enabled: needs at least two tunnels to choose from")
	}
	switch l.Candidates.Source {
	case "conntrack":
	case "adguard":
		validateAdGuard(errs, l.Candidates.AdGuard)
	default:
		errs.fail("learning.candidates.source %q: expected conntrack | adguard", l.Candidates.Source)
	}
	if l.Candidates.TopN < 1 {
		errs.fail("learning.candidates.top_n: must be at least 1")
	}
	if l.Probe.Samples < 1 {
		errs.fail("learning.probe.samples: must be at least 1")
	}
	if l.FlapDamp.MaxSwitches < 1 {
		errs.fail("learning.flap_damping.max_switches: must be at least 1")
	}
	for _, d := range []struct {
		name string
		v    Duration
	}{
		{"candidates.refresh", l.Candidates.Refresh},
		{"probe.timeout", l.Probe.Timeout},
		{"ttl", l.TTL},
		{"flap_damping.window", l.FlapDamp.Window},
	} {
		if d.v <= 0 {
			errs.fail("learning.%s: must be positive", d.name)
		}
	}
	if l.MinGain.Abs < 0 {
		errs.fail("learning.min_gain.abs: must not be negative")
	}
}

func validateAdGuard(errs *errList, a AdGuard) {
	u, err := url.Parse(a.URL)
	switch {
	case a.URL == "":
		errs.fail("learning.candidates.adguard.url: required for source adguard (e.g. http://127.0.0.1:3000)")
	case err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "":
		errs.fail("learning.candidates.adguard.url %q: expected http(s)://host[:port][/path]", a.URL)
	case u.User != nil:
		errs.fail("learning.candidates.adguard.url: put the credentials in username and password")
	}
	if a.Password != "" && a.Username == "" {
		errs.fail("learning.candidates.adguard: password without username")
	}
}

// validateMisc checks the unimplemented features, logging and the status socket.
func (c *Config) validateMisc(errs *errList) {
	if c.Metrics.Listen != "" {
		errs.fail("metrics.listen: the metrics endpoint is not implemented in this version; leave it empty")
	}

	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		errs.fail("log.level %q: expected debug | info | warn | error", c.Log.Level)
	}
	switch c.Log.Format {
	case "text", "json":
	default:
		errs.fail("log.format %q: expected text | json", c.Log.Format)
	}
	if !filepath.IsAbs(c.Status.Socket) {
		errs.fail("status.socket %q: must be an absolute path", c.Status.Socket)
	}
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
