package config

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// The UCI form of the configuration (/etc/config/tunsel on OpenWrt) is flat:
// one "tunsel" section with the global options and one "tunnel" section per
// tunnel, with the health options folded in and the tunnel's static
// preferences as a "prefer" list. The learning options are flat options
// of the main section, "learning" for the switch and "learn_*" for the
// rest. Metrics have no UCI options until they are implemented.
//
//	config tunsel 'main'
//		option enabled '1'          # read by the init script only
//		option mark_mask '0xf'
//		list default_order 'wg-a'
//		list ingress 'br-lan'
//		list exclude '10.0.0.0/8'
//		option learn_ttl '1h'
//
//	config tunnel 'wg_a'            # section names cannot hold '-'
//		option iface 'wg-a'
//		option mark '0x1'
//		list target '192.0.2.1'
//		list prefer '203.0.113.0/24'

// uciSection is one "config <type> [name]" block.
type uciSection struct {
	typ, name string
	line      int
	opts      []uciOption
}

type uciOption struct {
	name   string
	values []string
	list   bool
	line   int
}

// ParseUCI parses and validates configuration data in UCI format. Unknown
// section types and options are errors.
func ParseUCI(data []byte) (*Config, error) {
	secs, err := parseUCI(string(data))
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	c, err := fromUCI(secs)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	c.setDefaults()
	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// parseUCI splits UCI text into sections. As in libuci, a repeated option
// replaces the earlier value and a repeated list appends to it.
func parseUCI(data string) ([]uciSection, error) {
	var secs []uciSection
	for i, raw := range strings.Split(data, "\n") {
		line := i + 1
		toks, err := uciTokens(raw)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		if len(toks) == 0 {
			continue
		}
		switch toks[0] {
		case "package":
			continue
		case "config":
			if len(toks) < 2 || len(toks) > 3 {
				return nil, fmt.Errorf("line %d: expected config <type> [<name>]", line)
			}
			s := uciSection{typ: toks[1], line: line}
			if len(toks) == 3 {
				s.name = toks[2]
			}
			secs = append(secs, s)
		case "option", "list":
			if len(toks) != 3 {
				return nil, fmt.Errorf("line %d: expected %s <name> <value>", line, toks[0])
			}
			if len(secs) == 0 {
				return nil, fmt.Errorf("line %d: %s outside a config section", line, toks[0])
			}
			s := &secs[len(secs)-1]
			s.add(uciOption{name: toks[1], values: []string{toks[2]}, list: toks[0] == "list", line: line})
		default:
			return nil, fmt.Errorf("line %d: unexpected %q", line, toks[0])
		}
	}
	return secs, nil
}

func (s *uciSection) add(o uciOption) {
	for i := range s.opts {
		if s.opts[i].name != o.name {
			continue
		}
		if o.list && s.opts[i].list {
			s.opts[i].values = append(s.opts[i].values, o.values...)
			s.opts[i].line = o.line
		} else {
			s.opts[i] = o
		}
		return
	}
	s.opts = append(s.opts, o)
}

// uciTokens splits one line into words: 'single quoted' (literal),
// "double quoted" or bare (backslash escapes), up to a '#' comment.
func uciTokens(line string) ([]string, error) {
	var (
		toks []string
		cur  strings.Builder
		in   bool // inside a word
	)
	end := func() {
		if in {
			toks = append(toks, cur.String())
			cur.Reset()
			in = false
		}
	}
	for i := 0; i < len(line); i++ {
		switch ch := line[i]; {
		case ch == ' ' || ch == '\t' || ch == '\r':
			end()
			continue
		case ch == '#' && !in:
			return toks, nil
		case ch == '\'' || ch == '"':
			next, err := quoted(line, i, &cur)
			if err != nil {
				return nil, err
			}
			i = next
		case ch == '\\' && i+1 < len(line):
			i++
			cur.WriteByte(line[i])
		default:
			cur.WriteByte(ch)
		}
		in = true
	}
	end()
	return toks, nil
}

// quoted appends the quoted string starting at line[i] to cur and returns
// the index of its closing quote. Backslash escapes apply in double quotes
// only.
func quoted(line string, i int, cur *strings.Builder) (int, error) {
	q := line[i]
	for i++; i < len(line) && line[i] != q; i++ {
		if q == '"' && line[i] == '\\' && i+1 < len(line) {
			i++
		}
		cur.WriteByte(line[i])
	}
	if i == len(line) {
		if q == '"' {
			return 0, errors.New("unterminated double quote")
		}
		return 0, errors.New("unterminated single quote")
	}
	return i, nil
}

// uciReader converts the options of one section, collecting errors.
type uciReader struct {
	errs *errList
	sec  *uciSection
}

func (r uciReader) fail(o uciOption, format string, a ...any) {
	r.errs.fail("line %d: option %s: %s", o.line, o.name, fmt.Sprintf(format, a...))
}

// scalar returns the value of a non-list option.
func (r uciReader) scalar(o uciOption) (string, bool) {
	if o.list {
		r.fail(o, "is not a list")
		return "", false
	}
	return o.values[0], o.values[0] != ""
}

func (r uciReader) setString(o uciOption, dst *string) {
	if v, ok := r.scalar(o); ok {
		*dst = v
	}
}

func (r uciReader) setUint32(o uciOption, dst *uint32) {
	if v, ok := r.scalar(o); ok {
		n, err := strconv.ParseUint(v, 0, 32)
		if err != nil {
			r.fail(o, "invalid number %q", v)
		}
		*dst = uint32(n)
	}
}

func (r uciReader) setUint16(o uciOption, dst *uint16) {
	if v, ok := r.scalar(o); ok {
		n, err := strconv.ParseUint(v, 10, 16)
		if err != nil {
			r.fail(o, "invalid number %q", v)
		}
		*dst = uint16(n)
	}
}

func (r uciReader) setInt(o uciOption, dst *int) {
	if v, ok := r.scalar(o); ok {
		n, err := strconv.Atoi(v)
		if err != nil {
			r.fail(o, "invalid number %q", v)
		}
		*dst = n
	}
}

func (r uciReader) setBool(o uciOption, dst *bool) {
	v, ok := r.scalar(o)
	if !ok {
		return
	}
	switch v {
	case "1", "yes", "on", "true", "enabled":
		*dst = true
	case "0", "no", "off", "false", "disabled":
		*dst = false
	default:
		r.fail(o, "invalid boolean %q", v)
	}
}

func (r uciReader) setDuration(o uciOption, dst *Duration) {
	if v, ok := r.scalar(o); ok {
		d, err := parseDuration(v)
		if err != nil {
			r.fail(o, "%v", err)
		}
		*dst = d
	}
}

func (r uciReader) setPercent(o uciOption, dst *Percent) {
	if v, ok := r.scalar(o); ok {
		p, err := parsePercent(v)
		if err != nil {
			r.fail(o, "%v", err)
		}
		*dst = p
	}
}

// list returns the non-empty values of an option; a single "option" is
// accepted where a list is expected.
func (r uciReader) list(o uciOption) []string {
	var vs []string
	for _, v := range o.values {
		if v != "" {
			vs = append(vs, v)
		}
	}
	return vs
}

func (r uciReader) addrs(o uciOption) []netip.Addr {
	var as []netip.Addr
	for _, v := range r.list(o) {
		a, err := netip.ParseAddr(v)
		if err != nil {
			r.fail(o, "invalid address %q", v)
			continue
		}
		as = append(as, a)
	}
	return as
}

func (r uciReader) prefixes(o uciOption) []Prefix {
	var ps []Prefix
	for _, v := range r.list(o) {
		p, err := ParsePrefix(v)
		if err != nil {
			r.fail(o, "%v", err)
			continue
		}
		ps = append(ps, Prefix{p})
	}
	return ps
}

func fromUCI(secs []uciSection) (*Config, error) {
	var (
		c    Config
		errs errList
		main *uciSection
	)
	for i := range secs {
		s := &secs[i]
		switch s.typ {
		case "tunsel":
			if main != nil {
				errs.fail("line %d: second tunsel section (the first is on line %d)", s.line, main.line)
				continue
			}
			main = s
			c.globalsFromUCI(uciReader{&errs, s})
		case "tunnel":
			c.tunnelFromUCI(uciReader{&errs, s})
		default:
			errs.fail("line %d: unknown section type %q (tunsel | tunnel)", s.line, s.typ)
		}
	}
	return &c, errors.Join(errs...)
}

func (c *Config) globalsFromUCI(r uciReader) {
	for _, o := range r.sec.opts {
		switch o.name {
		case "enabled":
			var b bool
			r.setBool(o, &b)
		case "table":
			r.setString(o, &c.NFT.Table)
		case "mark_mask":
			r.setUint32(o, &c.NFT.MarkMask)
		case "cleanup_on_exit":
			r.setBool(o, &c.NFT.CleanupOnExit)
		case "default_order":
			c.DefaultOrder = r.list(o)
		case "ingress":
			c.Ingress.Interfaces = r.list(o)
		case "include_local_output":
			r.setBool(o, &c.Ingress.IncludeLocalOutput)
		case "exclude":
			c.Exclude = r.prefixes(o)
		case "flush_on_unhealthy":
			var b bool
			r.setBool(o, &b)
			c.Conntrack.FlushOnUnhealthy = &b
		case "log_level":
			r.setString(o, &c.Log.Level)
		case "log_format":
			r.setString(o, &c.Log.Format)
		case "socket":
			r.setString(o, &c.Status.Socket)
		default:
			if !r.learning(o, &c.Learning) {
				r.errs.fail("line %d: unknown option %q in tunsel section", o.line, o.name)
			}
		}
	}
}

func (c *Config) tunnelFromUCI(r uciReader) {
	var (
		t      Tunnel
		prefer []Prefix
	)
	for _, o := range r.sec.opts {
		switch o.name {
		case "iface":
			r.setString(o, &t.Name)
		case "mark":
			r.setUint32(o, &t.Mark)
		case "family":
			t.Families = r.list(o)
		case "prefer":
			prefer = r.prefixes(o)
		default:
			if !r.health(o, &t.Health) {
				r.errs.fail("line %d: unknown option %q in tunnel section", o.line, o.name)
			}
		}
	}
	if t.Name == "" {
		r.errs.fail("line %d: tunnel section %s: option iface is required", r.sec.line, r.sec.name)
		return
	}
	c.Tunnels = append(c.Tunnels, t)
	for _, p := range prefer {
		c.StaticPref = append(c.StaticPref, StaticPref{Prefix: p, Tunnel: t.Name})
	}
}

// health sets the health option o and reports whether o is one.
func (r uciReader) health(o uciOption, h *Health) bool {
	switch o.name {
	case "target":
		h.Targets = append(h.Targets, r.addrs(o)...)
	case "probe":
		r.setString(o, &h.Probe)
	case "interval":
		r.setDuration(o, &h.Interval)
	case "timeout":
		r.setDuration(o, &h.Timeout)
	case "min_ok":
		r.setInt(o, &h.MinOK)
	case "fail_after":
		r.setInt(o, &h.FailAfter)
	case "recover_after":
		r.setInt(o, &h.RecoverAfter)
	default:
		return false
	}
	return true
}

// learning sets the learning option o and reports whether o is one.
func (r uciReader) learning(o uciOption, l *Learning) bool {
	switch o.name {
	case "learning":
		r.setBool(o, &l.Enabled)
	case "learn_source":
		r.setString(o, &l.Candidates.Source)
	case "learn_top_n":
		r.setInt(o, &l.Candidates.TopN)
	case "learn_refresh":
		r.setDuration(o, &l.Candidates.Refresh)
	case "learn_port":
		r.setUint16(o, &l.Probe.Port)
	case "learn_samples":
		r.setInt(o, &l.Probe.Samples)
	case "learn_timeout":
		r.setDuration(o, &l.Probe.Timeout)
	case "learn_min_gain_abs":
		r.setDuration(o, &l.MinGain.Abs)
	case "learn_min_gain_rel":
		r.setPercent(o, &l.MinGain.Rel)
	case "learn_ttl":
		r.setDuration(o, &l.TTL)
	case "learn_damp_window":
		r.setDuration(o, &l.FlapDamp.Window)
	case "learn_damp_max_switches":
		r.setInt(o, &l.FlapDamp.MaxSwitches)
	default:
		return false
	}
	return true
}
