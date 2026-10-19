package flows

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

var (
	dstA = netip.MustParseAddr("203.0.113.1")
	dstB = netip.MustParseAddr("198.51.100.7")
)

func TestAggregate(t *testing.T) {
	tunnels := map[uint32]string{0x1: "wg-a", 0x2: "wg-b", 0x3: "wg-c"}
	s := Aggregate([]Entry{
		{Mark: 0x1, Dst: dstA, BytesOut: 100, BytesIn: 900},
		{Mark: 0x1, Dst: dstA, BytesOut: 10, BytesIn: 10},
		{Mark: 0x11, Dst: dstB, BytesOut: 5}, // other bits outside the mask
		{Mark: 0x2, Dst: dstB},
		{Mark: 0x0, Dst: dstB}, // unmarked
		{Mark: 0x8, Dst: dstB}, // no tunnel has this mark
	}, 0xf, tunnels)

	a := s.Tunnels["wg-a"]
	if a.Flows != 3 || a.Destinations != 2 || a.BytesOut != 115 || a.BytesIn != 910 {
		t.Errorf("wg-a: %+v", a)
	}
	if len(a.Top) != 2 || a.Top[0] != (Dest{Addr: dstA, Flows: 2, Bytes: 1020}) {
		t.Errorf("wg-a top: %+v", a.Top)
	}
	if b := s.Tunnels["wg-b"]; b.Flows != 1 || b.Destinations != 1 {
		t.Errorf("wg-b: %+v", b)
	}
	if c, ok := s.Tunnels["wg-c"]; !ok || c.Flows != 0 || len(c.Top) != 0 {
		t.Errorf("idle tunnel should be listed empty: %+v %v", c, ok)
	}
	if s.Other != 2 {
		t.Errorf("other: %d", s.Other)
	}
}

func TestTopIsLimited(t *testing.T) {
	var es []Entry
	for i := range TopN + 5 {
		es = append(es, Entry{Mark: 1, Dst: netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}), BytesIn: uint64(i)})
	}
	g := Aggregate(es, 0xf, map[uint32]string{1: "wg-a"}).Tunnels["wg-a"]
	if len(g.Top) != TopN || g.Top[0].Bytes != TopN+4 || g.Destinations != TopN+5 {
		t.Errorf("top: %d entries, first %+v, %d destinations", len(g.Top), g.Top[0], g.Destinations)
	}
}

func TestCache(t *testing.T) {
	dumps := 0
	var fail error
	c := &Cache{MaxAge: time.Hour, Dump: func() ([]Entry, error) {
		dumps++
		return []Entry{{Mark: 1, Dst: dstA}}, fail
	}}
	tunnels := map[uint32]string{1: "wg-a"}
	for range 3 {
		if s, err := c.Get(0xf, tunnels); err != nil || s.Tunnels["wg-a"].Flows != 1 || s.At.IsZero() {
			t.Fatalf("%+v %v", s, err)
		}
	}
	if dumps != 1 {
		t.Errorf("dumped %d times, want 1", dumps)
	}
	// Another configuration is not served from the cache.
	if s, _ := c.Get(0xf, map[uint32]string{1: "wg-x"}); s.Tunnels["wg-x"].Flows != 1 || dumps != 2 {
		t.Errorf("config change: %+v, %d dumps", s, dumps)
	}
	c.MaxAge = 0
	fail = errors.New("netlink")
	if _, err := c.Get(0xf, tunnels); err == nil {
		t.Error("dump error not returned")
	}
}

func TestKeyOf(t *testing.T) {
	a := keyOf(map[uint32]string{1: "a", 2: "b"})
	if b := keyOf(map[uint32]string{2: "b", 1: "a"}); a != b {
		t.Error("key depends on map order")
	}
	if c := keyOf(map[uint32]string{1: "b", 2: "a"}); a == c {
		t.Errorf("swapped names share a key: %q", c)
	}
}
