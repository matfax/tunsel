// Package engine derives the effective nftables ruleset from the
// configuration and the current tunnel health (design §4.3, §5).
package engine

import (
	"github.com/matfax/tunsel/internal/config"
	"github.com/matfax/tunsel/internal/nft"
	"github.com/matfax/tunsel/internal/ranges"
)

// Defaults is the default tunnel per family; "" means none.
type Defaults struct {
	V4, V6 string
}

// Build returns the ruleset for cfg given which tunnels are healthy.
//
//   - Static preferences of unhealthy tunnels are dropped, so those
//     destinations fall back to a covering static prefix or the default.
//   - The default per family is the first healthy tunnel in default_order
//     that carries the family. If none is healthy, prev is kept as long as
//     that tunnel still exists and carries the family; traffic then fails
//     closed via the host firewall instead of leaking to host routing.
func Build(cfg *config.Config, healthy func(tunnel string) bool, prev Defaults) (*nft.Ruleset, Defaults) {
	rs := &nft.Ruleset{
		Table:       cfg.NFT.Table,
		Mask:        cfg.NFT.MarkMask,
		Ingress:     cfg.Ingress.Interfaces,
		LocalOutput: cfg.Ingress.IncludeLocalOutput,
	}
	for _, t := range cfg.Tunnels {
		rs.Tunnels = append(rs.Tunnels, nft.Tunnel{Name: t.Name, Mark: t.Mark})
	}

	var ex4, ex6 []ranges.Entry[struct{}]
	for _, p := range cfg.Exclude {
		e := ranges.Entry[struct{}]{Prefix: p.Prefix}
		if p.Addr().Is4() {
			ex4 = append(ex4, e)
		} else {
			ex6 = append(ex6, e)
		}
	}
	rs.Exclude4, rs.Exclude6 = ranges.Build(ex4), ranges.Build(ex6)

	var st4, st6 []ranges.Entry[string]
	for _, s := range cfg.StaticPref {
		if !healthy(s.Tunnel) {
			continue
		}
		e := ranges.Entry[string]{Prefix: s.Prefix.Prefix, Value: s.Tunnel}
		if s.Prefix.Addr().Is4() {
			st4 = append(st4, e)
		} else {
			st6 = append(st6, e)
		}
	}
	rs.Static4, rs.Static6 = ranges.Build(st4), ranges.Build(st6)

	pick := func(carries func(*config.Tunnel) bool, prev string) string {
		for _, name := range cfg.DefaultOrder {
			if t := cfg.Tunnel(name); carries(t) && healthy(name) {
				return name
			}
		}
		if t := cfg.Tunnel(prev); t != nil && carries(t) {
			return prev
		}
		return ""
	}
	d := Defaults{
		V4: pick(func(t *config.Tunnel) bool { return t.IPv4 }, prev.V4),
		V6: pick(func(t *config.Tunnel) bool { return t.IPv6 }, prev.V6),
	}
	rs.Default4, rs.Default6 = d.V4, d.V6
	return rs, d
}
