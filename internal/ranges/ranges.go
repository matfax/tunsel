// Package ranges flattens possibly nested CIDR prefixes into the disjoint
// address ranges that nftables interval sets and maps require.
package ranges

import (
	"net/netip"
	"sort"
)

type Entry[V comparable] struct {
	Prefix netip.Prefix
	Value  V
}

// Range is an inclusive address range.
type Range[V comparable] struct {
	From, To netip.Addr
	Value    V
}

// Build returns disjoint, sorted ranges covering all prefixes. Where
// prefixes nest, the more specific one wins; for identical prefixes the
// later entry wins. Adjacent ranges with equal values are merged. All
// entries must be of the same address family.
func Build[V comparable](entries []Entry[V]) []Range[V] {
	es := make([]Entry[V], 0, len(entries))
	for _, e := range entries {
		es = append(es, Entry[V]{e.Prefix.Masked(), e.Value})
	}
	sort.SliceStable(es, func(i, j int) bool {
		a, b := es[i].Prefix, es[j].Prefix
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c < 0
		}
		return a.Bits() < b.Bits()
	})

	type open struct {
		last  netip.Addr
		value V
	}
	var (
		out   []Range[V]
		stack []open
		pos   netip.Addr // next address not yet emitted
		done  bool       // pos ran past the end of the address space
	)
	emit := func(from, to netip.Addr, v V) {
		if n := len(out); n > 0 && out[n-1].Value == v && out[n-1].To.Next() == from {
			out[n-1].To = to
			return
		}
		out = append(out, Range[V]{from, to, v})
	}
	// closeTop emits the rest of the innermost open prefix and pops it.
	closeTop := func() {
		top := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if !done && pos.Compare(top.last) <= 0 {
			emit(pos, top.last, top.value)
			pos = top.last.Next()
			done = !pos.IsValid()
		}
	}

	for _, e := range es {
		first, last := e.Prefix.Addr(), lastAddr(e.Prefix)
		for len(stack) > 0 && stack[len(stack)-1].last.Compare(first) < 0 {
			closeTop()
		}
		// Prefixes either nest or are disjoint, so a remaining top contains e.
		if len(stack) > 0 && !done && pos.Compare(first) < 0 {
			emit(pos, first.Prev(), stack[len(stack)-1].value)
		}
		pos, done = first, false
		stack = append(stack, open{last, e.Value})
	}
	for len(stack) > 0 {
		closeTop()
	}
	return out
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}
