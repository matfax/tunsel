// Package flows attributes the current conntrack entries to tunnels by
// their conntrack mark.
package flows

import (
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/ti-mo/conntrack"
)

// TopN is the number of destinations listed per tunnel.
const TopN = 10

// Entry is the part of a conntrack entry that is aggregated.
type Entry struct {
	Mark              uint32
	Dst               netip.Addr
	BytesOut, BytesIn uint64 // original and reply direction
}

// Group aggregates the entries of one tunnel. Byte counts stay zero unless
// conntrack accounting is enabled (net.netfilter.nf_conntrack_acct=1, the
// OpenWrt default).
type Group struct {
	Flows        int    `json:"flows"`
	Destinations int    `json:"destinations"` // distinct destination addresses
	BytesOut     uint64 `json:"bytes_out"`
	BytesIn      uint64 `json:"bytes_in"`
	Top          []Dest `json:"top,omitempty"` // by bytes, then flows
}

type Dest struct {
	Addr  netip.Addr `json:"addr"`
	Flows int        `json:"flows"`
	Bytes uint64     `json:"bytes"`
}

type Snapshot struct {
	At      time.Time        `json:"at"`
	Tunnels map[string]Group `json:"tunnels"`
	// Other counts the entries carrying no tunnel's mark: excluded and
	// local destinations, and traffic that was never steered.
	Other int `json:"other"`
}

// Aggregate groups entries by the tunnel whose mark they carry.
func Aggregate(entries []Entry, mask uint32, tunnels map[uint32]string) Snapshot {
	s := Snapshot{Tunnels: map[string]Group{}}
	dests := map[string]map[netip.Addr]*Dest{}
	for _, name := range tunnels {
		s.Tunnels[name] = Group{}
		dests[name] = map[netip.Addr]*Dest{}
	}
	for _, e := range entries {
		name, ok := tunnels[e.Mark&mask]
		if !ok {
			s.Other++
			continue
		}
		g := s.Tunnels[name]
		g.Flows++
		g.BytesOut += e.BytesOut
		g.BytesIn += e.BytesIn
		s.Tunnels[name] = g
		d := dests[name][e.Dst]
		if d == nil {
			d = &Dest{Addr: e.Dst}
			dests[name][e.Dst] = d
		}
		d.Flows++
		d.Bytes += e.BytesOut + e.BytesIn
	}
	for name, ds := range dests {
		g := s.Tunnels[name]
		g.Destinations = len(ds)
		g.Top = top(ds)
		s.Tunnels[name] = g
	}
	return s
}

func top(ds map[netip.Addr]*Dest) []Dest {
	all := make([]Dest, 0, len(ds))
	for _, d := range ds {
		all = append(all, *d)
	}
	sort.Slice(all, func(i, j int) bool {
		a, b := all[i], all[j]
		if a.Bytes != b.Bytes {
			return a.Bytes > b.Bytes
		}
		if a.Flows != b.Flows {
			return a.Flows > b.Flows
		}
		return a.Addr.Less(b.Addr)
	})
	return all[:min(len(all), TopN)]
}

// Dump reads the conntrack table over netlink.
func Dump() ([]Entry, error) {
	c, err := conntrack.Dial(nil)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	fs, err := c.Dump(nil)
	if err != nil {
		return nil, err
	}
	es := make([]Entry, 0, len(fs))
	for _, f := range fs {
		es = append(es, Entry{
			Mark:     f.Mark,
			Dst:      f.TupleOrig.IP.DestinationAddress.Unmap(),
			BytesOut: f.CountersOrig.Bytes,
			BytesIn:  f.CountersReply.Bytes,
		})
	}
	return es, nil
}

// Cache rate-limits dumps: a snapshot younger than MaxAge is reused, so a
// status page polling every few seconds dumps the table at most that often.
type Cache struct {
	MaxAge time.Duration
	Dump   func() ([]Entry, error)

	mu   sync.Mutex
	snap Snapshot
	key  cacheKey
}

type cacheKey struct {
	mask    uint32
	tunnels string
}

// Get returns a snapshot for mask and tunnels (by mark), dumping conntrack
// if the cached one is older than MaxAge or was taken for another config.
func (c *Cache) Get(mask uint32, tunnels map[uint32]string) (Snapshot, error) {
	key := cacheKey{mask: mask, tunnels: keyOf(tunnels)}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.snap.At.IsZero() && c.key == key && time.Since(c.snap.At) < c.MaxAge {
		return c.snap, nil
	}
	es, err := c.Dump()
	if err != nil {
		return Snapshot{}, err
	}
	c.snap, c.key = Aggregate(es, mask, tunnels), key
	c.snap.At = time.Now()
	return c.snap, nil
}

func keyOf(tunnels map[uint32]string) string {
	marks := make([]uint32, 0, len(tunnels))
	for m := range tunnels {
		marks = append(marks, m)
	}
	sort.Slice(marks, func(i, j int) bool { return marks[i] < marks[j] })
	var k []byte
	for _, m := range marks {
		k = append(k, byte(m), byte(m>>8), byte(m>>16), byte(m>>24))
		k = append(k, tunnels[m]...)
		k = append(k, 0)
	}
	return string(k)
}
