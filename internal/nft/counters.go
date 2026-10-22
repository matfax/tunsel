package nft

import (
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// Counter names. New connections are counted once in CounterNew and once
// in the counter of the decision taken; one that matches none (no default
// for its family) stays unmarked.
const (
	CounterNew      = "new"      // new connections entering decide
	CounterLocal    = "local"    // to a local, broadcast or multicast address
	CounterExcluded = "excluded" // to an excluded address
)

// StaticCounter counts new connections steered by a static preference.
func StaticCounter(tunnel string) string { return "static_" + safeName(tunnel) }

// LearnedCounter counts new connections steered by a learned destination.
func LearnedCounter(tunnel string) string { return "learned_" + safeName(tunnel) }

// DefaultCounter counts new connections steered as the family's default.
func DefaultCounter(tunnel string) string { return "default_" + safeName(tunnel) }

// RestoreCounter counts packets of established connections, in the
// upstream direction, sent back into their tunnel. Flows offloaded to a
// flowtable bypass the hook and are not counted.
func RestoreCounter(tunnel string) string { return "restore_" + safeName(tunnel) }

type Counter struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// counters adds every named counter of the ruleset, starting from seed.
func (b *builder) counters(seed map[string]Counter) {
	names := []string{CounterNew, CounterLocal, CounterExcluded}
	for _, t := range b.rs.Tunnels {
		names = append(names, StaticCounter(t.Name), LearnedCounter(t.Name), DefaultCounter(t.Name), RestoreCounter(t.Name))
	}
	for _, n := range names {
		v := seed[n]
		b.c.AddObj(&nftables.NamedObj{
			Table: b.t, Name: n, Type: nftables.ObjTypeCounter,
			Obj: &expr.Counter{Packets: v.Packets, Bytes: v.Bytes},
		})
	}
}

// count references a named counter.
func count(name string) *expr.Objref {
	return &expr.Objref{Type: unix.NFT_OBJECT_COUNTER, Name: name}
}

// readCounters returns the named counters of a table by name.
func readCounters(c *nftables.Conn, t *nftables.Table) (map[string]Counter, error) {
	objs, err := c.GetNamedObjects(t)
	if err != nil {
		return nil, err
	}
	out := map[string]Counter{}
	for _, o := range objs {
		n, ok := o.(*nftables.NamedObj)
		if !ok || n.Type != nftables.ObjTypeCounter {
			continue
		}
		if v, ok := n.Obj.(*expr.Counter); ok {
			out[n.Name] = Counter{Packets: v.Packets, Bytes: v.Bytes}
		}
	}
	return out, nil
}

// Counters returns the named counters of the installed table by name, or
// nil if the table is absent.
func (m *Manager) Counters(table string) (map[string]Counter, error) {
	ok, err := m.Exists(table)
	if err != nil || !ok {
		return nil, err
	}
	c, err := nftables.New(m.Opts...)
	if err != nil {
		return nil, err
	}
	return readCounters(c, &nftables.Table{Family: nftables.TableFamilyINet, Name: table})
}
