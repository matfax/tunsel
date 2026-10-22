// Package learn picks the fastest tunnel per destination (design §7):
// candidates from conntrack, TCP handshake times through every healthy
// tunnel, and a decision per destination that lives for a TTL.
package learn

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/matfax/tunsel/internal/flows"
)

// Candidate is a destination a source has seen, with how much it was
// used: bytes and flows.
type Candidate struct {
	Addr  netip.Addr
	Score uint64
	Hits  int
}

// Source reports the candidates in use right now.
type Source interface {
	Candidates(ctx context.Context) ([]Candidate, error)
}

// Conntrack ranks the destinations of steered flows (those carrying a
// tunnel's mark) by bytes in both directions, then by flows.
type Conntrack struct {
	Dump  func() ([]flows.Entry, error)
	Mask  uint32
	Marks map[uint32]bool
}

func (c *Conntrack) Candidates(context.Context) ([]Candidate, error) {
	es, err := c.Dump()
	if err != nil {
		return nil, fmt.Errorf("conntrack: %w", err)
	}
	by := map[netip.Addr]*Candidate{}
	for _, e := range es {
		if !c.Marks[e.Mark&c.Mask] {
			continue
		}
		cd := by[e.Dst]
		if cd == nil {
			cd = &Candidate{Addr: e.Dst}
			by[e.Dst] = cd
		}
		cd.Score += e.BytesOut + e.BytesIn
		cd.Hits++
	}
	out := make([]Candidate, 0, len(by))
	for _, cd := range by {
		out = append(out, *cd)
	}
	return out, nil
}
