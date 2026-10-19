package engine

import (
	"encoding/binary"
	"math"
	"math/big"
	"net/netip"

	"github.com/matfax/tunsel/internal/config"
	"github.com/matfax/tunsel/internal/nft"
	"github.com/matfax/tunsel/internal/ranges"
)

// RangeStats describes a group of prefixes and the address space they
// cover in the installed ruleset, after nested prefixes were flattened and
// those of unhealthy tunnels dropped.
type RangeStats struct {
	Prefixes int    `json:"prefixes"` // configured
	Ranges   int    `json:"ranges"`   // disjoint ranges in effect
	IPv4     uint64 `json:"ipv4_addresses"`
	IPv6     uint64 `json:"ipv6_64s"` // /64 networks touched; saturates
}

type Coverage struct {
	Static  map[string]RangeStats `json:"static"` // by tunnel
	Exclude RangeStats            `json:"exclude"`
}

// Cover returns what the static preferences and exclusions of cfg cover in
// rs, the ruleset built from it.
func Cover(cfg *config.Config, rs *nft.Ruleset) Coverage {
	c := Coverage{Static: map[string]RangeStats{}}
	for _, t := range cfg.Tunnels {
		c.Static[t.Name] = RangeStats{}
	}
	for _, s := range cfg.StaticPref {
		st := c.Static[s.Tunnel]
		st.Prefixes++
		c.Static[s.Tunnel] = st
	}
	for _, group := range [][]ranges.Range[string]{rs.Static4, rs.Static6} {
		for _, r := range group {
			st := c.Static[r.Value]
			st.add(r.From, r.To)
			c.Static[r.Value] = st
		}
	}
	c.Exclude.Prefixes = len(cfg.Exclude)
	for _, group := range [][]ranges.Range[struct{}]{rs.Exclude4, rs.Exclude6} {
		for _, r := range group {
			c.Exclude.add(r.From, r.To)
		}
	}
	return c
}

func (s *RangeStats) add(from, to netip.Addr) {
	s.Ranges++
	if from.Is4() {
		f, t := from.As4(), to.As4()
		s.IPv4 += uint64(binary.BigEndian.Uint32(t[:])) - uint64(binary.BigEndian.Uint32(f[:])) + 1
		return
	}
	// /64 networks from the one holding from to the one holding to.
	f, t := from.As16(), to.As16()
	n := new(big.Int).Sub(new(big.Int).SetBytes(t[:8]), new(big.Int).SetBytes(f[:8]))
	n.Add(n, big.NewInt(1))
	n.Add(n, new(big.Int).SetUint64(s.IPv6))
	if n.IsUint64() {
		s.IPv6 = n.Uint64()
	} else {
		s.IPv6 = math.MaxUint64
	}
}
