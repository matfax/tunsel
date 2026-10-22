//go:build integration

// End-to-end test in network namespaces (needs root):
//
//	                        ┌────────┐ wg-a ── pa  (provider A)
//	lan (10.99.0.2) ── lan0 │ router │ wg-b ── pb  (provider B)
//	                        └────────┘ wan0 ── wan (host default route)
//
// The "tunnels" are veth pairs. pa, pb and wan all answer for every test
// destination; nft counters in each show which path carried a flow. The
// router has policy routing per tunnel, its main default via wan0, and
// masquerades on all three.
package integration

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/matfax/tunsel/internal/status"
)

const (
	nsLAN, nsRtr, nsA, nsB, nsWAN = "ts-lan", "ts-rtr", "ts-pa", "ts-pb", "ts-wan"

	dstDefault = "198.18.0.1"
	dstLearn   = "198.18.0.2" // provider B does not answer TCP 443 for it
	dstStatic  = "203.0.113.10"
	dstV6      = "2001:db8::1"
	dstExclude = "10.0.0.5"
)

func sh(t *testing.T, ns string, cmd string) string {
	t.Helper()
	out, err := exec.Command("ip", "netns", "exec", ns, "sh", "-ec", cmd).CombinedOutput()
	if err != nil {
		t.Fatalf("[%s] %s: %v\n%s", ns, cmd, err, out)
	}
	return string(out)
}

func try(ns, cmd string) error {
	return exec.Command("ip", "netns", "exec", ns, "sh", "-ec", cmd).Run()
}

// hasIPv6 is false on hosts booted with ipv6.disable=1; the IPv6 parts
// of the test are skipped there.
var hasIPv6 = func() bool { _, err := os.Stat("/proc/sys/net/ipv6"); return err == nil }()

// v6 drops lines mentioning IPv6 from a script when IPv6 is unavailable.
func v6(script string) string {
	if hasIPv6 {
		return script
	}
	var keep []string
	for _, l := range strings.Split(script, "\n") {
		if !strings.Contains(l, "-6 ") && !strings.Contains(l, "ipv6") && !strings.Contains(l, "nodad") && !strings.Contains(l, "ip6 ") {
			keep = append(keep, l)
		}
	}
	return strings.Join(keep, "\n")
}

func topology(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	for _, ns := range []string{nsLAN, nsRtr, nsA, nsB, nsWAN} {
		exec.Command("ip", "netns", "del", ns).Run()
		if out, err := exec.Command("ip", "netns", "add", ns).CombinedOutput(); err != nil {
			t.Fatalf("netns add %s: %v %s", ns, err, out)
		}
		ns := ns
		t.Cleanup(func() { exec.Command("ip", "netns", "del", ns).Run() })
		sh(t, ns, v6("ip link set lo up\nsysctl -qw net.ipv6.conf.all.accept_dad=0 net.ipv6.conf.default.accept_dad=0"))
	}

	sh(t, nsRtr, v6(`
		ip link add lan0 type veth peer name eth0 netns `+nsLAN+`
		ip link add wg-a type veth peer name uplink netns `+nsA+`
		ip link add wg-b type veth peer name uplink netns `+nsB+`
		ip link add wan0 type veth peer name uplink netns `+nsWAN+`
		sysctl -qw net.ipv4.ip_forward=1
		sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
		ip addr add 10.99.0.1/24 dev lan0
		ip addr add 10.98.1.1/30 dev wg-a
		ip addr add 10.98.2.1/30 dev wg-b
		ip addr add 10.98.3.1/30 dev wan0
		ip addr add fd99::1/64 dev lan0 nodad
		ip addr add fd98:1::1/64 dev wg-a nodad
		ip addr add fd98:2::1/64 dev wg-b nodad
		ip addr add fd98:3::1/64 dev wan0 nodad
		for i in lan0 wg-a wg-b wan0; do ip link set $i up; sysctl -qw net.ipv4.conf.$i.rp_filter=0; done
		ip route add default via 10.98.3.2 dev wan0
		ip -6 route add default via fd98:3::2 dev wan0
		ip route add default via 10.98.1.2 dev wg-a table 101
		ip -6 route add default via fd98:1::2 dev wg-a table 101
		ip route add default via 10.98.2.2 dev wg-b table 102
		ip -6 route add default via fd98:2::2 dev wg-b table 102
		ip rule add fwmark 0x1/0xf lookup 101 prio 100
		ip rule add fwmark 0x2/0xf lookup 102 prio 101
		ip -6 rule add fwmark 0x1/0xf lookup 101 prio 100
		ip -6 rule add fwmark 0x2/0xf lookup 102 prio 101
		sysctl -qw net.ipv6.conf.all.forwarding=1
		nft add table ip nat
		nft add chain ip nat post '{ type nat hook postrouting priority srcnat; }'
		nft add rule ip nat post oifname '{ "wg-a", "wg-b", "wan0" }' masquerade
		nft add table ip6 nat
		nft add chain ip6 nat post '{ type nat hook postrouting priority srcnat; }'
		nft add rule ip6 nat post oifname '{ "wg-a", "wg-b", "wan0" }' masquerade
	`))
	sh(t, nsLAN, v6(`
		ip addr add 10.99.0.2/24 dev eth0; ip link set eth0 up
		ip addr add fd99::2/64 dev eth0 nodad
		ip route add default via 10.99.0.1
		ip -6 route add default via fd99::1
	`))
	for i, ns := range []string{nsA, nsB, nsWAN} {
		n := i + 1
		sh(t, ns, v6(fmt.Sprintf(`
			ip addr add 10.98.%[1]d.2/30 dev uplink; ip link set uplink up
			ip addr add fd98:%[1]d::2/64 dev uplink nodad
			ip route add 10.99.0.0/24 via 10.98.%[1]d.1
			ip -6 route add fd99::/64 via fd98:%[1]d::1
			for a in 192.0.2.1 198.51.100.1 %[2]s %[3]s %[5]s %[6]s; do ip addr add $a/32 dev lo; done
			ip addr add %[4]s/128 dev lo nodad
			nft -f - <<'EOF'
			table inet c {
				counter traffic {}
				chain pre {
					type filter hook prerouting priority -300;
					ip daddr { 198.18.0.0/15, 203.0.113.0/24, 10.0.0.0/8 } icmp type echo-request counter name traffic
					ip6 daddr 2001:db8::/32 icmpv6 type echo-request counter name traffic
				}
				chain in { type filter hook input priority 0; }
			}
EOF
		`, n, dstDefault, dstStatic, dstV6, dstExclude, dstLearn)))
	}
}

var packetsRE = regexp.MustCompile(`packets (\d+)`)

func counter(t *testing.T, ns string) int {
	t.Helper()
	m := packetsRE.FindStringSubmatch(sh(t, ns, "nft list counter inet c traffic"))
	n, _ := strconv.Atoi(m[1])
	return n
}

// via sends pings and returns which path carried them: wg-a, wg-b or wan.
func via(t *testing.T, ns, cmd string) string {
	t.Helper()
	paths := []struct{ name, ns string }{{"wg-a", nsA}, {"wg-b", nsB}, {"wan", nsWAN}}
	before := make([]int, len(paths))
	for i, p := range paths {
		before[i] = counter(t, p.ns)
	}
	sh(t, ns, cmd)
	var hit []string
	for i, p := range paths {
		if d := counter(t, p.ns) - before[i]; d > 0 {
			hit = append(hit, fmt.Sprintf("%s(%d)", p.name, d))
		}
	}
	if len(hit) == 1 {
		return strings.SplitN(hit[0], "(", 2)[0]
	}
	return "[" + strings.Join(hit, " ") + "]"
}

func ping(dst string) string { return "ping -n -q -c 2 -i 0.2 -W 1 " + dst }

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

const configTmpl = `
nft: { table: tunsel, mark_mask: 0xf, cleanup_on_exit: true }
tunnels:
  - name: wg-a
    mark: 0x1
    health: { targets: [192.0.2.1], interval: 300ms, timeout: 200ms, fail_after: 2, recover_after: 2 }
  - name: wg-b
    mark: 0x2
    health: { targets: [198.51.100.1], interval: 300ms, timeout: 200ms, fail_after: 2, recover_after: 2 }
default_order: [%s]
ingress: { interfaces: [lan0], include_local_output: true }
exclude: [10.0.0.0/8]
static_pref: [{ prefix: 203.0.113.0/24, tunnel: wg-a }]
log: { level: debug }
status: { socket: %s }
`

type daemon struct {
	cmd    *exec.Cmd
	bin    string
	tmpl   string // with %s for default_order and the socket
	cfg    string
	socket string
	log    *bytes.Buffer
}

func start(t *testing.T, bin string) *daemon {
	return startWith(t, bin, configTmpl)
}

func startWith(t *testing.T, bin, tmpl string) *daemon {
	dir := t.TempDir()
	d := &daemon{bin: bin, tmpl: tmpl, cfg: filepath.Join(dir, "config.yaml"), socket: filepath.Join(dir, "run", "tunsel.sock"), log: &bytes.Buffer{}}
	d.write(t, "wg-b, wg-a")
	d.run(t)
	return d
}

func (d *daemon) run(t *testing.T) {
	d.cmd = exec.Command("ip", "netns", "exec", nsRtr, d.bin, "run", "-config", d.cfg)
	d.cmd.Stdout, d.cmd.Stderr = d.log, d.log
	if err := d.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	cmd := d.cmd
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		if t.Failed() && cmd == d.cmd {
			t.Logf("daemon log:\n%s", d.log)
		}
	})
}

func (d *daemon) write(t *testing.T, order string) {
	if err := os.WriteFile(d.cfg, []byte(fmt.Sprintf(d.tmpl, order, d.socket)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (d *daemon) state(tunnel string) string {
	r, err := status.Fetch(d.socket, status.Request{})
	if err != nil {
		return err.Error()
	}
	for _, x := range r.Tunnels {
		if x.Name == tunnel {
			return x.State.String()
		}
	}
	return "absent"
}

func (d *daemon) report(t *testing.T) *status.Report {
	t.Helper()
	r, err := status.Fetch(d.socket, status.Request{})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestEndToEnd(t *testing.T) {
	topology(t)
	bin := filepath.Join(t.TempDir(), "tunsel")
	if out, err := exec.Command("go", "build", "-o", bin, "../../cmd/tunsel").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	d := start(t, bin)
	eventually(t, "both tunnels healthy", func() bool { return d.state("wg-a") == "healthy" && d.state("wg-b") == "healthy" })
	if r := d.report(t); r.Default4 != "wg-b" || r.Default6 != "wg-b" {
		t.Fatalf("defaults: %s / %s", r.Default4, r.Default6)
	}

	t.Run("steering", func(t *testing.T) {
		// Pings succeeding also shows replies are not marked back into a tunnel.
		if got := via(t, nsLAN, ping(dstDefault)); got != "wg-b" {
			t.Errorf("default destination via %s, want wg-b", got)
		}
		if got := via(t, nsLAN, ping(dstStatic)); got != "wg-a" {
			t.Errorf("static destination via %s, want wg-a", got)
		}
		if !hasIPv6 {
			t.Log("IPv6 disabled on this host; skipping the IPv6 check")
		} else if got := via(t, nsLAN, ping("-6 "+dstV6)); got != "wg-b" {
			t.Errorf("IPv6 destination via %s, want wg-b", got)
		}
		if got := via(t, nsRtr, ping(dstDefault)); got != "wg-b" {
			t.Errorf("local output via %s, want wg-b", got)
		}
	})

	t.Run("exclude", func(t *testing.T) {
		if got := via(t, nsLAN, ping(dstExclude)); got != "wan" {
			t.Errorf("excluded destination via %s, want wan (host routing)", got)
		}
		ct := sh(t, nsRtr, "conntrack -L -d "+dstExclude+" 2>/dev/null")
		if !strings.Contains(ct, "mark=0 ") {
			t.Errorf("excluded destination got marked:\n%s", ct)
		}
	})

	t.Run("statistics", func(t *testing.T) {
		r, err := status.Fetch(d.socket, status.Request{Flows: true, History: true})
		if err != nil {
			t.Fatal(err)
		}
		a, b := r.Tunnels[0], r.Tunnels[1]
		// The pings above: static via wg-a, default via wg-b from the LAN
		// and from the router, one excluded.
		if a.Static < 1 || b.Default < 2 || r.Connections.Excluded < 1 || r.Connections.New < a.Static+b.Default+r.Connections.Excluded {
			t.Errorf("connections: %+v, wg-a static %d, wg-b default %d", r.Connections, a.Static, b.Default)
		}
		if b.Upstream.Packets == 0 {
			t.Errorf("no upstream packets restored into wg-b: %+v", b.Upstream)
		}
		// The ping flows are still in conntrack.
		if r.Flows == nil {
			t.Fatalf("no flows: %v", r.Warnings)
		}
		top := map[string]bool{}
		for _, x := range r.Flows.Tunnels["wg-a"].Top {
			top[x.Addr.String()] = true
		}
		if !top[dstStatic] || r.Flows.Tunnels["wg-b"].Flows == 0 || r.Flows.Other == 0 {
			t.Errorf("flows: %+v", r.Flows)
		}
		for _, tun := range r.Tunnels {
			if l := tun.Latency; len(l) != 1 || l[0].Avg == 0 || l[0].Loss != 0 || len(tun.History) != 1 {
				t.Errorf("%s latency: %+v, history %d", tun.Name, l, len(tun.History))
			}
		}
		if a.Ranges.IPv4 != 256 || r.Exclude.IPv4 != 1<<24 {
			t.Errorf("ranges: wg-a %+v, exclude %+v", a.Ranges, r.Exclude)
		}
	})

	t.Run("failover with conntrack flush", func(t *testing.T) {
		before := d.report(t)
		// A long-running flow pinned to wg-b.
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		flow := exec.CommandContext(ctx, "ip", "netns", "exec", nsLAN, "ping", "-n", "-q", "-i", "0.1", dstDefault)
		if err := flow.Start(); err != nil {
			t.Fatal(err)
		}
		defer flow.Wait()
		eventually(t, "flow on wg-b", func() bool { return counter(t, nsB) > 0 })

		sh(t, nsB, "nft add rule inet c in ip daddr 198.51.100.1 drop")
		eventually(t, "wg-b unhealthy", func() bool { return d.state("wg-b") == "unhealthy" })
		if r := d.report(t); r.Default4 != "wg-a" {
			t.Fatalf("default after wg-b failed: %s", r.Default4)
		}
		// The established flow moves too, because its conntrack entry was flushed.
		a := counter(t, nsA)
		eventually(t, "running flow moved to wg-a", func() bool { return counter(t, nsA) > a+3 })
		if got := via(t, nsLAN, ping(dstDefault)); got != "wg-a" {
			t.Errorf("new connection via %s, want wg-a", got)
		}
		cancel()

		if l := d.report(t).Tunnels[1].Latency[0]; l.Loss == 0 {
			t.Errorf("wg-b probes lost but not reported: %+v", l)
		}

		sh(t, nsB, "nft flush chain inet c in")
		eventually(t, "wg-b recovered", func() bool { return d.state("wg-b") == "healthy" })
		if got := via(t, nsLAN, ping(dstDefault)); got != "wg-b" {
			t.Errorf("after recovery via %s, want wg-b", got)
		}
		// Failover and recovery replaced the table twice; the counters carry on.
		after := d.report(t)
		if after.Tunnels[0].Static < before.Tunnels[0].Static || after.Connections.Excluded < before.Connections.Excluded {
			t.Errorf("counters lost on table replacement: before %+v / %d, after %+v / %d",
				before.Connections, before.Tunnels[0].Static, after.Connections, after.Tunnels[0].Static)
		}
	})

	t.Run("link down", func(t *testing.T) {
		sh(t, nsRtr, "ip link set wg-a down")
		eventually(t, "wg-a unhealthy", func() bool { return d.state("wg-a") == "unhealthy" })
		// The static preference is dropped while wg-a is down.
		if got := via(t, nsLAN, ping(dstStatic)); got != "wg-b" {
			t.Errorf("static destination via %s with wg-a down, want wg-b", got)
		}
		// Linux removed the device's routes, so the probe (bound to wg-a)
		// would pass while marked traffic falls through to main.
		sh(t, nsRtr, "ip link set wg-a up")
		time.Sleep(time.Second)
		if s := d.state("wg-a"); s != "unhealthy" {
			t.Fatalf("wg-a %s with its policy route missing", s)
		}
		if r := d.report(t); !strings.Contains(strings.Join(r.Tunnels[0].Errors, " "), "leaves via wan0") {
			t.Errorf("route check error not reported: %v", r.Tunnels[0].Errors)
		}
		// Restore what the interface manager would: the routes and, since
		// they are dropped on link down too, the IPv6 addresses.
		sh(t, nsRtr, v6("ip route add default via 10.98.1.2 dev wg-a table 101\nip -6 addr replace fd98:1::1/64 dev wg-a nodad\nip -6 route add default via fd98:1::2 dev wg-a table 101"))
		eventually(t, "wg-a recovered", func() bool { return d.state("wg-a") == "healthy" })
		if got := via(t, nsLAN, ping(dstStatic)); got != "wg-a" {
			t.Errorf("static destination via %s after recovery, want wg-a", got)
		}
	})

	t.Run("reload", func(t *testing.T) {
		os.WriteFile(d.cfg, []byte("not: [valid"), 0o600)
		d.cmd.Process.Signal(syscall.SIGHUP)
		eventually(t, "invalid reload logged", func() bool { return strings.Contains(d.log.String(), "reload failed") })
		if got := via(t, nsLAN, ping(dstDefault)); got != "wg-b" {
			t.Errorf("after invalid reload via %s, want wg-b", got)
		}

		d.write(t, "wg-a, wg-b")
		d.cmd.Process.Signal(syscall.SIGHUP)
		eventually(t, "default switched to wg-a", func() bool { return d.report(t).Default4 == "wg-a" })
		if got := via(t, nsLAN, ping(dstDefault)); got != "wg-a" {
			t.Errorf("after reload via %s, want wg-a", got)
		}
		if r := d.report(t); r.Tunnels[1].State.String() != "healthy" {
			t.Errorf("health state lost on reload: %+v", r.Tunnels[1])
		}
	})

	t.Run("clean shutdown", func(t *testing.T) {
		d.cmd.Process.Signal(syscall.SIGTERM)
		if err := d.cmd.Wait(); err != nil {
			t.Fatalf("exit: %v", err)
		}
		if out := sh(t, nsRtr, "nft list tables"); strings.Contains(out, "tunsel") {
			t.Errorf("table left behind with cleanup_on_exit: %s", out)
		}
	})
}

const learnTmpl = `
nft: { table: tunsel, mark_mask: 0xf }
tunnels:
  - name: wg-a
    mark: 0x1
    health: { targets: [192.0.2.1], interval: 300ms, timeout: 200ms, fail_after: 2, recover_after: 2 }
  - name: wg-b
    mark: 0x2
    health: { targets: [198.51.100.1], interval: 300ms, timeout: 200ms, fail_after: 2, recover_after: 2 }
default_order: [%s]
ingress: { interfaces: [lan0] }
learning:
  enabled: true
  candidates: { refresh: 1s }
  probe: { timeout: 500ms }
  ttl: 6s # renewed from 2s before expiry while the flow is in conntrack
log: { level: debug }
status: { socket: %s }
`

// Learning from conntrack: of two destinations the LAN talks to via the
// default wg-b, one only wg-a answers on TCP 443; it is learned for wg-a
// and its next connection goes there. The other, which both answer alike,
// stays on the default. While in use, the learned entry is renewed before
// it expires; a restart keeps it.
func TestLearning(t *testing.T) {
	topology(t)
	bin := filepath.Join(t.TempDir(), "tunsel")
	if out, err := exec.Command("go", "build", "-o", bin, "../../cmd/tunsel").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	sh(t, nsB, "nft add rule inet c in ip daddr "+dstLearn+" tcp dport 443 drop")

	d := startWith(t, bin, learnTmpl)
	eventually(t, "both tunnels healthy", func() bool { return d.state("wg-a") == "healthy" && d.state("wg-b") == "healthy" })
	learned := func() map[string]string {
		r, err := status.Fetch(d.socket, status.Request{Learned: true})
		if err != nil || r.Learning == nil {
			return nil
		}
		out := map[string]string{}
		for _, e := range r.Learning.Entries {
			out[e.Addr.String()] = e.Outcome + ":" + e.Tunnel
		}
		return out
	}

	// The flows that make both destinations candidates, via the default.
	for _, dst := range []string{dstLearn, dstDefault} {
		if got := via(t, nsLAN, ping(dst)); got != "wg-b" {
			t.Fatalf("%s via %s before learning, want wg-b", dst, got)
		}
	}
	eventually(t, "both destinations measured", func() bool { return len(learned()) == 2 })
	if got := learned(); got[dstLearn] != "learned:wg-a" || !strings.HasPrefix(got[dstDefault], "baseline:") && !strings.HasPrefix(got[dstDefault], "no gain:") {
		t.Fatalf("measured: %v", got)
	}
	// A new ping is a new connection (another ICMP id).
	if got := via(t, nsLAN, ping(dstLearn)); got != "wg-a" {
		t.Errorf("learned destination via %s, want wg-a", got)
	}
	if got := via(t, nsLAN, ping(dstDefault)); got != "wg-b" {
		t.Errorf("default destination via %s, want wg-b", got)
	}
	if r := d.report(t); r.Tunnels[0].Learned < 1 || r.Learning.Learned != 1 || r.Learning.LastError != "" {
		t.Errorf("report: wg-a learned %d, %+v", r.Tunnels[0].Learned, r.Learning)
	}
	if !strings.Contains(sh(t, nsRtr, "nft list map inet tunsel learned4"), dstLearn+" timeout 6s") {
		t.Error("learned element missing")
	}

	// Renewed in place: still there after its first lifetime, and new
	// connections never fell back to the default meanwhile.
	first := expires(t, d, dstLearn)
	for end := time.Now().Add(8 * time.Second); time.Now().Before(end); time.Sleep(time.Second) {
		if got := via(t, nsLAN, "ping -n -q -c 1 -W 1 "+dstLearn); got != "wg-a" {
			t.Fatalf("learned destination via %s while being renewed", got)
		}
	}
	if again := expires(t, d, dstLearn); !again.After(first.Add(time.Second)) {
		t.Errorf("not renewed: expiry %s, first %s", again, first)
	}
	if r := d.report(t); r.Learning.Renewals == 0 && !strings.Contains(d.log.String(), "msg=renewed") {
		t.Errorf("no renewal reported: %+v", r.Learning)
	}

	// A restart adopts the installed entry instead of forgetting it.
	d.cmd.Process.Signal(syscall.SIGTERM)
	if err := d.cmd.Wait(); err != nil {
		t.Fatalf("exit: %v", err)
	}
	d.run(t)
	eventually(t, "daemon back", func() bool { return d.state("wg-a") == "healthy" && d.state("wg-b") == "healthy" })
	if got := learned(); got[dstLearn] != "learned:wg-a" {
		t.Errorf("after restart: %v", got)
	}
	if got := via(t, nsLAN, ping(dstLearn)); got != "wg-a" {
		t.Errorf("learned destination via %s after restart, want wg-a", got)
	}
	if !strings.Contains(d.log.String(), "adopted learned destinations") {
		t.Error("adoption not logged")
	}
}

func expires(t *testing.T, d *daemon, addr string) time.Time {
	t.Helper()
	r, err := status.Fetch(d.socket, status.Request{Learned: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range r.Learning.Entries {
		if e.Addr.String() == addr {
			return e.Expires
		}
	}
	t.Fatalf("%s not measured", addr)
	return time.Time{}
}
