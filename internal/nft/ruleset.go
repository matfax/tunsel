// Package nft builds and installs the tool-owned nftables table.
//
// Every write to a packet or conntrack mark goes through a per-tunnel chain
// that uses only constant operands ((mark & ^mask) ^ value), so the tool
// coexists with other mark users on any kernel. Maps hold verdicts (goto
// that chain) rather than mark values.
//
//	table inet tunsel {
//	  set ingress   { type ifname; }
//	  set exclude4  { type ipv4_addr; flags interval; }
//	  set exclude6  { type ipv6_addr; flags interval; }
//	  map static4   { type ipv4_addr : verdict; flags interval; }
//	  map static6   { type ipv6_addr : verdict; flags interval; }
//
//	  chain to_<tunnel> {   # one per tunnel
//	    meta mark set meta mark & ~mask | <mark>
//	    ct mark set ct mark & ~mask | <mark>
//	  }
//	  chain pick4 { goto to_<default v4 tunnel> }
//	  chain pick6 { goto to_<default v6 tunnel> }
//
//	  chain decide {
//	    fib daddr type { local, broadcast, multicast } return
//	    ip  daddr @exclude4 return
//	    ip6 daddr @exclude6 return
//	    ip  daddr vmap @static4
//	    ip6 daddr vmap @static6
//	    meta nfproto ipv4 goto pick4
//	    meta nfproto ipv6 goto pick6
//	  }
//	  chain steer {
//	    ct state new goto decide
//	    ct mark & mask == <mark> goto to_<tunnel>   # restore, one per tunnel
//	  }
//	  chain prerouting {   # filter hook prerouting priority mangle
//	    iifname @ingress jump steer   # replies arriving on tunnels are never touched
//	  }
//	  chain output {       # route hook output priority mangle; optional
//	    meta mark & mask != 0 return  # pre-marked, e.g. the tool's own probes (SO_MARK)
//	    jump steer
//	  }
//	}
package nft

import (
	"fmt"
	"net/netip"
	"regexp"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"

	"github.com/matfax/tunsel/internal/ranges"
)

// Ruleset is the complete desired content of the table.
type Ruleset struct {
	Table       string
	Mask        uint32
	Ingress     []string
	LocalOutput bool
	Tunnels     []Tunnel

	Exclude4, Exclude6 []ranges.Range[struct{}]
	// Static ranges map to a tunnel name.
	Static4, Static6 []ranges.Range[string]
	// Default tunnel per family; "" leaves the family unmarked.
	Default4, Default6 string
}

type Tunnel struct {
	Name string
	Mark uint32
}

// ChainName returns the name of the chain that applies a tunnel's mark.
func ChainName(tunnel string) string {
	return "to_" + unsafeChars.ReplaceAllString(tunnel, "_")
}

var unsafeChars = regexp.MustCompile(`[^A-Za-z0-9_]`)

// Manager applies rulesets. Opts are passed to every nftables connection
// (e.g. nftables.WithNetNSFd in tests).
type Manager struct {
	Opts []nftables.ConnOption
}

// Apply atomically replaces the table (and any table named in alsoDelete)
// with rs. Conntrack marks of existing connections are unaffected.
func (m *Manager) Apply(rs *Ruleset, alsoDelete ...string) error {
	if err := rs.check(); err != nil {
		return err
	}
	c, err := nftables.New(append([]nftables.ConnOption{nftables.WithSockOptions(largeBuffers)}, m.Opts...)...)
	if err != nil {
		return err
	}
	existing, err := c.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return fmt.Errorf("list tables: %w", err)
	}
	for _, t := range existing {
		if t.Name == rs.Table || contains(alsoDelete, t.Name) {
			c.DelTable(t)
		}
	}
	if err := build(c, rs); err != nil {
		return err
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("nft transaction: %w", err)
	}
	return nil
}

// Exists reports whether the table is present.
func (m *Manager) Exists(table string) (bool, error) {
	c, err := nftables.New(m.Opts...)
	if err != nil {
		return false, err
	}
	ts, err := c.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return false, err
	}
	for _, t := range ts {
		if t.Name == table {
			return true, nil
		}
	}
	return false, nil
}

// Defaults returns the chains that the installed table's pick4 and pick6
// chains jump to ("" if the table or the rule is absent).
func (m *Manager) Defaults(table string) (v4, v6 string, err error) {
	ok, err := m.Exists(table)
	if err != nil || !ok {
		return "", "", err
	}
	c, err := nftables.New(m.Opts...)
	if err != nil {
		return "", "", err
	}
	t := &nftables.Table{Family: nftables.TableFamilyINet, Name: table}
	target := func(chain string) (string, error) {
		rules, err := c.GetRules(t, &nftables.Chain{Table: t, Name: chain})
		if err != nil || len(rules) == 0 {
			return "", err
		}
		for _, e := range rules[0].Exprs {
			if v, ok := e.(*expr.Verdict); ok && v.Kind == expr.VerdictGoto {
				return v.Chain, nil
			}
		}
		return "", nil
	}
	if v4, err = target("pick4"); err != nil {
		return "", "", err
	}
	v6, err = target("pick6")
	return v4, v6, err
}

// Delete removes the table if it exists.
func (m *Manager) Delete(table string) error {
	ok, err := m.Exists(table)
	if err != nil || !ok {
		return err
	}
	c, err := nftables.New(m.Opts...)
	if err != nil {
		return err
	}
	c.DelTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: table})
	return c.Flush()
}

func (rs *Ruleset) check() error {
	names := map[string]string{}
	known := map[string]bool{}
	for _, t := range rs.Tunnels {
		cn := ChainName(t.Name)
		if other, dup := names[cn]; dup {
			return fmt.Errorf("tunnels %q and %q map to the same chain name %s", other, t.Name, cn)
		}
		names[cn] = t.Name
		known[t.Name] = true
		if t.Mark == 0 || t.Mark&^rs.Mask != 0 {
			return fmt.Errorf("tunnel %s: invalid mark %#x for mask %#x", t.Name, t.Mark, rs.Mask)
		}
	}
	for _, d := range []string{rs.Default4, rs.Default6} {
		if d != "" && !known[d] {
			return fmt.Errorf("default tunnel %q unknown", d)
		}
	}
	for _, r := range append(append([]ranges.Range[string]{}, rs.Static4...), rs.Static6...) {
		if !known[r.Value] {
			return fmt.Errorf("static range %s-%s: unknown tunnel %q", r.From, r.To, r.Value)
		}
	}
	return nil
}

func build(c *nftables.Conn, rs *Ruleset) error {
	b := &builder{c: c, rs: rs, t: c.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: rs.Table})}
	// Tunnel chains come first: map elements and rules jump to them.
	b.tunnelChains()
	s, err := b.addSets()
	if err != nil {
		return err
	}
	steer := b.steerChain(b.decideChain(s))
	b.hookChains(s.ingress, steer)
	return nil
}

// builder adds the objects of one ruleset to a batch, in dependency order.
type builder struct {
	c  *nftables.Conn
	t  *nftables.Table
	rs *Ruleset
}

type sets struct {
	ingress, exclude4, exclude6, static4, static6 *nftables.Set
}

func (b *builder) chain(name string) *nftables.Chain {
	return b.c.AddChain(&nftables.Chain{Table: b.t, Name: name})
}

func (b *builder) rule(ch *nftables.Chain, es ...expr.Any) {
	b.c.AddRule(&nftables.Rule{Table: b.t, Chain: ch, Exprs: es})
}

func (b *builder) tunnelChains() {
	notMask := ne32(^b.rs.Mask)
	for _, tun := range b.rs.Tunnels {
		ch := b.chain(ChainName(tun.Name))
		b.rule(ch,
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: notMask, Xor: ne32(tun.Mark)},
			&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 1})
		b.rule(ch,
			&expr.Ct{Key: expr.CtKeyMARK, Register: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: notMask, Xor: ne32(tun.Mark)},
			&expr.Ct{Key: expr.CtKeyMARK, SourceRegister: true, Register: 1})
	}
}

func (b *builder) addSets() (sets, error) {
	t, rs := b.t, b.rs
	s := sets{
		ingress:  &nftables.Set{Table: t, Name: "ingress", KeyType: nftables.TypeIFName, KeyByteOrder: binaryutil.NativeEndian},
		exclude4: &nftables.Set{Table: t, Name: "exclude4", KeyType: nftables.TypeIPAddr, Interval: true},
		exclude6: &nftables.Set{Table: t, Name: "exclude6", KeyType: nftables.TypeIP6Addr, Interval: true},
		static4:  &nftables.Set{Table: t, Name: "static4", KeyType: nftables.TypeIPAddr, DataType: nftables.TypeVerdict, IsMap: true, Interval: true},
		static6:  &nftables.Set{Table: t, Name: "static6", KeyType: nftables.TypeIP6Addr, DataType: nftables.TypeVerdict, IsMap: true, Interval: true},
	}
	var ifs []nftables.SetElement
	for _, n := range rs.Ingress {
		ifs = append(ifs, nftables.SetElement{Key: ifname(n)})
	}
	for _, e := range []struct {
		set   *nftables.Set
		elems []nftables.SetElement
	}{
		{s.ingress, ifs},
		{s.exclude4, intervals(rs.Exclude4, nil)},
		{s.exclude6, intervals(rs.Exclude6, nil)},
		{s.static4, intervals(rs.Static4, gotoTunnel)},
		{s.static6, intervals(rs.Static6, gotoTunnel)},
	} {
		if err := addSet(b.c, e.set, e.elems); err != nil {
			return sets{}, fmt.Errorf("set %s: %w", e.set.Name, err)
		}
	}
	return s, nil
}

// decideChain adds the chain that picks a tunnel for a new connection.
func (b *builder) decideChain(s sets) *nftables.Chain {
	pick4, pick6 := b.chain("pick4"), b.chain("pick6")
	if b.rs.Default4 != "" {
		b.rule(pick4, gotoTunnel(b.rs.Default4))
	}
	if b.rs.Default6 != "" {
		b.rule(pick6, gotoTunnel(b.rs.Default6))
	}

	decide := b.chain("decide")
	for _, typ := range []uint32{unix.RTN_LOCAL, unix.RTN_BROADCAST, unix.RTN_MULTICAST} {
		b.rule(decide,
			&expr.Fib{Register: 1, FlagDADDR: true, ResultADDRTYPE: true},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ne32(typ)},
			&expr.Verdict{Kind: expr.VerdictReturn})
	}
	b.rule(decide, append(daddr(unix.NFPROTO_IPV4),
		&expr.Lookup{SourceRegister: 1, SetName: s.exclude4.Name, SetID: s.exclude4.ID},
		&expr.Verdict{Kind: expr.VerdictReturn})...)
	b.rule(decide, append(daddr(unix.NFPROTO_IPV6),
		&expr.Lookup{SourceRegister: 1, SetName: s.exclude6.Name, SetID: s.exclude6.ID},
		&expr.Verdict{Kind: expr.VerdictReturn})...)
	b.rule(decide, append(daddr(unix.NFPROTO_IPV4),
		&expr.Lookup{SourceRegister: 1, DestRegister: 0, IsDestRegSet: true, SetName: s.static4.Name, SetID: s.static4.ID})...)
	b.rule(decide, append(daddr(unix.NFPROTO_IPV6),
		&expr.Lookup{SourceRegister: 1, DestRegister: 0, IsDestRegSet: true, SetName: s.static6.Name, SetID: s.static6.ID})...)
	b.rule(decide, append(nfproto(unix.NFPROTO_IPV4), &expr.Verdict{Kind: expr.VerdictGoto, Chain: pick4.Name})...)
	b.rule(decide, append(nfproto(unix.NFPROTO_IPV6), &expr.Verdict{Kind: expr.VerdictGoto, Chain: pick6.Name})...)
	return decide
}

// steerChain adds the chain that sends new connections to decide and
// existing ones back to the tunnel their conntrack mark names.
func (b *builder) steerChain(decide *nftables.Chain) *nftables.Chain {
	steer := b.chain("steer")
	b.rule(steer,
		&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: ne32(expr.CtStateBitNEW), Xor: ne32(0)},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: ne32(0)},
		&expr.Verdict{Kind: expr.VerdictGoto, Chain: decide.Name})
	for _, tun := range b.rs.Tunnels {
		b.rule(steer,
			&expr.Ct{Key: expr.CtKeyMARK, Register: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: ne32(b.rs.Mask), Xor: ne32(0)},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ne32(tun.Mark)},
			gotoTunnel(tun.Name))
	}
	return steer
}

// hookChains adds the base chains that jump to steer.
func (b *builder) hookChains(ingress *nftables.Set, steer *nftables.Chain) {
	pre := b.c.AddChain(&nftables.Chain{
		Table: b.t, Name: "prerouting", Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityMangle,
		Policy: policy(nftables.ChainPolicyAccept),
	})
	if len(b.rs.Ingress) > 0 {
		b.rule(pre,
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Lookup{SourceRegister: 1, SetName: ingress.Name, SetID: ingress.ID},
			&expr.Verdict{Kind: expr.VerdictJump, Chain: steer.Name})
	}

	if b.rs.LocalOutput {
		out := b.c.AddChain(&nftables.Chain{
			Table: b.t, Name: "output", Type: nftables.ChainTypeRoute,
			Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityMangle,
			Policy: policy(nftables.ChainPolicyAccept),
		})
		b.rule(out,
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: ne32(b.rs.Mask), Xor: ne32(0)},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: ne32(0)},
			&expr.Verdict{Kind: expr.VerdictReturn})
		b.rule(out, &expr.Verdict{Kind: expr.VerdictJump, Chain: steer.Name})
	}
}

// elemChunk bounds the elements per netlink message: all elements of one
// message share an attribute whose length field is 16 bits.
const elemChunk = 256

// addSet adds a set and its elements, split over several messages of the
// same transaction.
func addSet(c *nftables.Conn, s *nftables.Set, elems []nftables.SetElement) error {
	first := elems[:min(len(elems), elemChunk)]
	if err := c.AddSet(s, first); err != nil {
		return err
	}
	for rest := elems[len(first):]; len(rest) > 0; {
		n := min(len(rest), elemChunk)
		if err := c.SetAddElements(s, rest[:n]); err != nil {
			return err
		}
		rest = rest[n:]
	}
	return nil
}

// largeBuffers lets one transaction carry tens of thousands of elements:
// the whole batch goes out in a single sendmsg, and every message is
// acknowledged (without echoing the request, NETLINK_CAP_ACK).
// SO_*BUFFORCE (CAP_NET_ADMIN) is not capped by net.core.[rw]mem_max.
func largeBuffers(conn *netlink.Conn) error {
	const size = 16 << 20
	if err := conn.SetOption(netlink.CapAcknowledge, true); err != nil {
		return err
	}
	rc, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var forced bool
	rc.Control(func(fd uintptr) {
		forced = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, size) == nil &&
			unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, size) == nil
	})
	if !forced {
		conn.SetWriteBuffer(size)
		conn.SetReadBuffer(size)
	}
	return nil
}

func gotoTunnel(name string) *expr.Verdict {
	return &expr.Verdict{Kind: expr.VerdictGoto, Chain: ChainName(name)}
}

func nfproto(p byte) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{p}},
	}
}

// daddr loads the destination address of the given family into register 1.
func daddr(p byte) []expr.Any {
	off, n := uint32(16), uint32(4)
	if p == unix.NFPROTO_IPV6 {
		off, n = 24, 16
	}
	return append(nfproto(p),
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: off, Len: n})
}

// intervals encodes ranges the way nft(8) does: an interval-end element at
// the zero address if the first range does not start there, a start element
// per range, and an end element at the address after each range unless it
// reaches the end of the address space.
func intervals[V comparable](rs []ranges.Range[V], verdict func(V) *expr.Verdict) []nftables.SetElement {
	var out []nftables.SetElement
	if len(rs) == 0 {
		return out
	}
	if first := rs[0].From; first != zeroLike(first) {
		out = append(out, nftables.SetElement{Key: zeroLike(first).AsSlice(), IntervalEnd: true})
	}
	for _, r := range rs {
		e := nftables.SetElement{Key: r.From.AsSlice()}
		if verdict != nil {
			e.VerdictData = verdict(r.Value)
		}
		out = append(out, e)
		if next := r.To.Next(); next.IsValid() {
			out = append(out, nftables.SetElement{Key: next.AsSlice(), IntervalEnd: true})
		}
	}
	return out
}

func zeroLike(a netip.Addr) netip.Addr {
	if a.Is4() {
		return netip.IPv4Unspecified()
	}
	return netip.IPv6Unspecified()
}

func ifname(n string) []byte {
	b := make([]byte, unix.IFNAMSIZ)
	copy(b, n)
	return b
}

func ne32(v uint32) []byte { return binaryutil.NativeEndian.PutUint32(v) }

func policy(p nftables.ChainPolicy) *nftables.ChainPolicy { return &p }

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
