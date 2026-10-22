package config

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The UCI file shipped with the OpenWrt package and the YAML example
// describe the same configuration.
func TestUCIMatchesYAMLExample(t *testing.T) {
	y, err := Load("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	u, err := Load("../../packaging/openwrt/tunsel.config")
	if err != nil {
		t.Fatal(err)
	}
	// Metrics have no UCI options yet.
	y.Metrics = Metrics{}
	if !reflect.DeepEqual(y, u) {
		t.Errorf("configs differ\nyaml: %+v\nuci:  %+v", y, u)
	}
}

const uciBase = `
package tunsel

config tunsel 'main'
	option mark_mask '0xf'
	list default_order 'wg-b'
	list default_order wg-a
	list ingress 'lan0'

config tunnel
	option iface 'wg-a'
	option mark '0x1'
	list target '192.0.2.1'
	option probe 'tcp:443'

config tunnel 'wg_b'
	option iface "wg-b"
	option mark 2
	option family 'ipv4'
	list target '198.51.100.1'
`

func TestUCIDefaults(t *testing.T) {
	c, err := ParseUCI([]byte(uciBase))
	if err != nil {
		t.Fatal(err)
	}
	if c.NFT.Table != "tunsel" || c.NFT.MarkMask != 0xf {
		t.Errorf("nft: %+v", c.NFT)
	}
	if !reflect.DeepEqual(c.DefaultOrder, []string{"wg-b", "wg-a"}) {
		t.Errorf("default_order: %v", c.DefaultOrder)
	}
	if a := c.Tunnel("wg-a").Health; a.ProbeKind != ProbeTCP || a.ProbePort != 443 || a.FailAfter != 3 {
		t.Errorf("wg-a health: %+v", a)
	}
	// A single "option" is accepted where a list is expected.
	if b := c.Tunnel("wg-b"); b.Mark != 2 || !b.IPv4 || b.IPv6 {
		t.Errorf("wg-b: %+v", b)
	}
	if !*c.Conntrack.FlushOnUnhealthy {
		t.Error("flush_on_unhealthy should default to true")
	}
}

func TestUCITokens(t *testing.T) {
	for in, want := range map[string][]string{
		`option a 'b c'`:            {"option", "a", "b c"},
		`option a "b \"c\""`:        {"option", "a", `b "c"`},
		`option a b\ c`:             {"option", "a", "b c"},
		`option a 'x'"y"z`:          {"option", "a", "xyz"},
		`option a '#' # comment`:    {"option", "a", "#"},
		"\toption a ''\r":           {"option", "a", ""},
		`# only a comment`:          nil,
		`option a 'it''s'`:          {"option", "a", "its"},
		`list exclude '10.0.0.0/8'`: {"list", "exclude", "10.0.0.0/8"},
		`option a "x\\y"`:           {"option", "a", `x\y`},
		`option a 'x\y'`:            {"option", "a", `x\y`}, // no escapes in single quotes
		`option a b\`:               {"option", "a", `b\`},  // trailing backslash is literal
		`option a b#c`:              {"option", "a", "b#c"}, // '#' inside a word
		`option a "#"#c`:            {"option", "a", "##c"}, // a word continues past a quote
		"option\ta\t'b'":            {"option", "a", "b"},
	} {
		got, err := uciTokens(in)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("%q: got %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{`option a 'b`, `option a "b`} {
		if _, err := uciTokens(bad); err == nil {
			t.Errorf("%q: expected error", bad)
		}
	}
}

func TestUCIHealthOptions(t *testing.T) {
	c, err := ParseUCI([]byte(uciBase + `
	list target '198.51.100.2'
	option probe 'tcp:8443'
	option interval '30s'
	option timeout '5s'
	option min_ok '2'
	option fail_after '4'
	option recover_after '6'
`))
	if err != nil {
		t.Fatal(err)
	}
	h := c.Tunnel("wg-b").Health
	want := Health{
		Targets: []netip.Addr{netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("198.51.100.2")},
		Probe:   "tcp:8443", Interval: Duration(30 * time.Second), Timeout: Duration(5 * time.Second),
		MinOK: 2, FailAfter: 4, RecoverAfter: 6, ProbeKind: ProbeTCP, ProbePort: 8443,
	}
	if !reflect.DeepEqual(h, want) {
		t.Errorf("health:\n got %+v\nwant %+v", h, want)
	}
}

func TestUCILearningOptions(t *testing.T) {
	c, err := ParseUCI([]byte(strings.Replace(uciBase, "list ingress 'lan0'", `list ingress 'lan0'
	option learning '0'
	option learn_source 'conntrack'
	option learn_top_n '50'
	option learn_refresh '10m'
	option learn_port '8443'
	option learn_samples '5'
	option learn_timeout '1s'
	option learn_min_gain_abs '10ms'
	option learn_min_gain_rel '20%'
	option learn_ttl '2h'
	option learn_damp_window '1h'
	option learn_damp_max_switches '3'`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	want := Learning{
		Candidates: Candidates{Source: "conntrack", TopN: 50, Refresh: Duration(10 * time.Minute)},
		Probe:      LearnProbe{Port: 8443, Samples: 5, Timeout: Duration(time.Second)},
		MinGain:    MinGain{Abs: Duration(10 * time.Millisecond), Rel: 0.2},
		TTL:        Duration(2 * time.Hour),
		FlapDamp:   FlapDamping{Window: Duration(time.Hour), MaxSwitches: 3},
	}
	if !reflect.DeepEqual(c.Learning, want) {
		t.Errorf("learning:\n got %+v\nwant %+v", c.Learning, want)
	}
}

func TestUCIRepeatedOptions(t *testing.T) {
	c, err := ParseUCI([]byte(uciBase + "\toption mark 3\n\tlist target '198.51.100.2'\n"))
	if err != nil {
		t.Fatal(err)
	}
	b := c.Tunnel("wg-b")
	if b.Mark != 3 || len(b.Health.Targets) != 2 {
		t.Errorf("an option replaces, a list appends: %+v", b)
	}
}

func TestUCIInvalid(t *testing.T) {
	cases := []struct {
		name, edit, want string
	}{
		{"unknown option", uciBase + "\toption bogus 1\n", `line 21: unknown option "bogus" in tunnel section`},
		{"unknown section", uciBase + "config other\n", `unknown section type "other"`},
		{"second main", uciBase + "config tunsel\n", "second tunsel section"},
		{"no iface", uciBase + "config tunnel 'x'\n\toption mark 4\n", "option iface is required"},
		{"list for scalar", uciBase + "\tlist mark 3\n", "option mark: is not a list"},
		{"number", uciBase + "\toption min_ok one\n", `invalid number "one"`},
		{"bool", strings.Replace(uciBase, "option mark_mask '0xf'", "option mark_mask '0xf'\n\toption cleanup_on_exit maybe", 1), `invalid boolean "maybe"`},
		{"duration", uciBase + "\toption interval soon\n", `invalid duration "soon"`},
		{"percent", strings.Replace(uciBase, "list ingress 'lan0'", "list ingress 'lan0'\n\toption learn_min_gain_rel 15", 1), `invalid percentage "15"`},
		{"port", strings.Replace(uciBase, "list ingress 'lan0'", "list ingress 'lan0'\n\toption learn_port 70000", 1), `invalid number "70000"`},
		{"learning in tunnel", uciBase + "\toption learn_ttl 1h\n", `unknown option "learn_ttl" in tunnel section`},
		{"address", uciBase + "\tlist target nowhere\n", `invalid address "nowhere"`},
		{"prefix", uciBase + "\tlist prefer '10.0.0.1/8'\n", "host bits set"},
		{"outside section", "option a b\n", "outside a config section"},
		{"garbage", uciBase + "frobnicate\n", `unexpected "frobnicate"`},
		// Validation is shared with YAML.
		{"validation", uciBase + "\tlist prefer '2001:db8::/32'\n", "does not carry"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseUCI([]byte(tc.edit))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}
