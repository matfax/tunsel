package nft

import (
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/google/nftables"

	"github.com/matfax/tunsel/internal/ranges"
)

// netns creates a throwaway network namespace and returns a Manager bound
// to it plus a helper that runs a command inside it.
func netns(t *testing.T) (*Manager, func(args ...string) string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root (network namespaces)")
	}
	name := "tunsel-test-" + strings.ReplaceAll(t.Name(), "/", "-")
	if out, err := exec.Command("ip", "netns", "add", name).CombinedOutput(); err != nil {
		t.Skipf("cannot create netns: %v: %s", err, out)
	}
	t.Cleanup(func() { exec.Command("ip", "netns", "del", name).Run() })
	f, err := os.Open("/run/netns/" + name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	run := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("ip", append([]string{"netns", "exec", name}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %v: %s", args, err, out)
		}
		return string(out)
	}
	return &Manager{Opts: []nftables.ConnOption{nftables.WithNetNSFd(int(f.Fd()))}}, run
}

func rng[V comparable](from, to string, v V) ranges.Range[V] {
	return ranges.Range[V]{From: netip.MustParseAddr(from), To: netip.MustParseAddr(to), Value: v}
}

func sample() *Ruleset {
	return &Ruleset{
		Table:   "tunsel",
		Mask:    0xf,
		Ingress: []string{"lan0", "lan1"},
		Tunnels: []Tunnel{{"wg-a", 0x1}, {"wg-b", 0x2}},
		Exclude4: []ranges.Range[struct{}]{
			rng("10.0.0.0", "10.255.255.255", struct{}{}),
			rng("192.168.0.0", "192.168.255.255", struct{}{}),
		},
		Exclude6: []ranges.Range[struct{}]{rng("fc00::", "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", struct{}{})},
		Static4: []ranges.Range[string]{
			rng("203.0.113.0", "203.0.113.127", "wg-a"),
			rng("203.0.113.128", "203.0.113.255", "wg-b"),
		},
		Static6:  []ranges.Range[string]{rng("2001:db8:100::", "2001:db8:100:ffff:ffff:ffff:ffff:ffff", "wg-a")},
		Default4: "wg-b",
		Default6: "wg-a",
	}
}

const want = `table inet tunsel {
	set ingress {
		type ifname
		elements = { "lan0",
			     "lan1" }
	}

	set exclude4 {
		type ipv4_addr
		flags interval
		elements = { 10.0.0.0/8, 192.168.0.0/16 }
	}

	set exclude6 {
		type ipv6_addr
		flags interval
		elements = { fc00::/7 }
	}

	map static4 {
		type ipv4_addr : verdict
		flags interval
		elements = { 203.0.113.0/25 : goto to_wg_a, 203.0.113.128/25 : goto to_wg_b }
	}

	map static6 {
		type ipv6_addr : verdict
		flags interval
		elements = { 2001:db8:100::/48 : goto to_wg_a }
	}

	chain to_wg_a {
		meta mark set meta mark & 0xfffffff1 | 0x00000001
		ct mark set ct mark & 0xfffffff1 | 0x00000001
	}

	chain to_wg_b {
		meta mark set meta mark & 0xfffffff2 | 0x00000002
		ct mark set ct mark & 0xfffffff2 | 0x00000002
	}

	chain pick4 {
		goto to_wg_b
	}

	chain pick6 {
		goto to_wg_a
	}

	chain decide {
		fib daddr type local return
		fib daddr type broadcast return
		fib daddr type multicast return
		ip daddr @exclude4 return
		ip6 daddr @exclude6 return
		ip daddr vmap @static4
		ip6 daddr vmap @static6
		meta nfproto ipv4 goto pick4
		meta nfproto ipv6 goto pick6
	}

	chain steer {
		ct state new goto decide
		ct mark & 0x0000000f == 0x00000001 goto to_wg_a
		ct mark & 0x0000000f == 0x00000002 goto to_wg_b
	}

	chain prerouting {
		type filter hook prerouting priority mangle; policy accept;
		iifname @ingress jump steer
	}

	chain output {
		type route hook output priority mangle; policy accept;
		meta mark & 0x0000000f != 0x00000000 return
		jump steer
	}
}
`

func TestApply(t *testing.T) {
	m, run := netns(t)
	rs := sample()
	rs.LocalOutput = true
	if err := m.Apply(rs); err != nil {
		t.Fatal(err)
	}
	got := run("nft", "list", "table", "inet", "tunsel")
	if got != want {
		t.Errorf("ruleset mismatch:\n--- got\n%s\n--- want\n%s", got, want)
	}

	// Re-apply is an atomic replace, also when switching defaults and
	// dropping the output chain.
	rs.LocalOutput = false
	rs.Default4, rs.Default6 = "", ""
	rs.Static4 = nil
	if err := m.Apply(rs); err != nil {
		t.Fatal(err)
	}
	got = run("nft", "list", "table", "inet", "tunsel")
	for _, gone := range []string{"chain output", "goto to_wg_b\n\t}\n\n\tchain pick6", "203.0.113"} {
		if strings.Contains(got, gone) {
			t.Errorf("still contains %q:\n%s", gone, got)
		}
	}
}

func TestDefaults(t *testing.T) {
	m, _ := netns(t)
	if v4, v6, err := m.Defaults("tunsel"); err != nil || v4 != "" || v6 != "" {
		t.Fatalf("no table: %q %q %v", v4, v6, err)
	}
	rs := sample()
	rs.Default6 = ""
	if err := m.Apply(rs); err != nil {
		t.Fatal(err)
	}
	if v4, v6, err := m.Defaults("tunsel"); err != nil || v4 != "to_wg_b" || v6 != "" {
		t.Fatalf("got %q %q %v", v4, v6, err)
	}
}

func TestEdgeIntervals(t *testing.T) {
	m, run := netns(t)
	rs := sample()
	rs.Exclude4 = []ranges.Range[struct{}]{
		rng("0.0.0.0", "0.255.255.255", struct{}{}),
		rng("255.255.255.255", "255.255.255.255", struct{}{}),
	}
	rs.Exclude6 = []ranges.Range[struct{}]{rng("ff00::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", struct{}{})}
	if err := m.Apply(rs); err != nil {
		t.Fatal(err)
	}
	got := run("nft", "list", "set", "inet", "tunsel", "exclude4")
	if !strings.Contains(got, "0.0.0.0/8, 255.255.255.255") {
		t.Errorf("exclude4:\n%s", got)
	}
	if got := run("nft", "list", "set", "inet", "tunsel", "exclude6"); !strings.Contains(got, "ff00::/8") {
		t.Errorf("exclude6:\n%s", got)
	}
}

func TestRenameAndDelete(t *testing.T) {
	m, run := netns(t)
	if err := m.Apply(sample()); err != nil {
		t.Fatal(err)
	}
	rs := sample()
	rs.Table = "tunsel2"
	if err := m.Apply(rs, "tunsel"); err != nil {
		t.Fatal(err)
	}
	if got := run("nft", "list", "tables"); got != "table inet tunsel2\n" {
		t.Errorf("tables after rename: %q", got)
	}
	if err := m.Delete("tunsel2"); err != nil {
		t.Fatal(err)
	}
	if err := m.Delete("tunsel2"); err != nil {
		t.Errorf("deleting a missing table: %v", err)
	}
	if ok, _ := m.Exists("tunsel2"); ok {
		t.Error("table still exists")
	}
}

// Large sets exceed one netlink attribute (16-bit length) and the default
// socket send buffer; all elements must still arrive.
func TestLargeSets(t *testing.T) {
	m, _ := netns(t)
	rs := sample()
	const n = 20000
	rs.Static4, rs.Exclude4 = nil, nil
	for i := 0; i < n; i++ {
		// disjoint, non-adjacent /31s
		a := netip.AddrFrom4([4]byte{100, byte(i >> 8), byte(i), 0})
		b := netip.AddrFrom4([4]byte{100, byte(i >> 8), byte(i), 1})
		rs.Static4 = append(rs.Static4, ranges.Range[string]{From: a, To: b, Value: []string{"wg-a", "wg-b"}[i%2]})
		rs.Exclude4 = append(rs.Exclude4, ranges.Range[struct{}]{From: netip.AddrFrom4([4]byte{11, byte(i >> 8), byte(i), 0}), To: netip.AddrFrom4([4]byte{11, byte(i >> 8), byte(i), 0})})
	}
	if err := m.Apply(rs); err != nil {
		t.Fatal(err)
	}
	c, err := nftables.New(m.Opts...)
	if err != nil {
		t.Fatal(err)
	}
	tbl := &nftables.Table{Family: nftables.TableFamilyINet, Name: rs.Table}
	for _, name := range []string{"static4", "exclude4"} {
		set, err := c.GetSetByName(tbl, name)
		if err != nil {
			t.Fatal(err)
		}
		elems, err := c.GetSetElements(set)
		if err != nil {
			t.Fatal(err)
		}
		// start + end per range, plus the leading zero end element
		if want := 2*n + 1; len(elems) != want {
			t.Errorf("%s: %d elements, want %d", name, len(elems), want)
		}
	}
}

func TestCheck(t *testing.T) {
	rs := sample()
	rs.Tunnels = append(rs.Tunnels, Tunnel{"wg.a", 0x3})
	if err := rs.check(); err == nil || !strings.Contains(err.Error(), "same chain name") {
		t.Errorf("chain name collision: %v", err)
	}
	rs = sample()
	rs.Default4 = "nope"
	if err := rs.check(); err == nil {
		t.Error("unknown default accepted")
	}
}
