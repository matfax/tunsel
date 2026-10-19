package health

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"
	"time"
)

func ms(n float64) Millis { return Millis(n * float64(time.Millisecond)) }

func TestSummarize(t *testing.T) {
	target := netip.MustParseAddr("192.0.2.1")
	ss := []Sample{
		{OK: true, RTT: ms(10)},
		{OK: false},
		{OK: true, RTT: ms(30)},
		{OK: true, RTT: ms(20)},
	}
	got := summarize(target, ss)
	want := Latency{Target: target, Last: ms(20), Min: ms(10), Avg: ms(20), Max: ms(30), Jitter: ms(15), Loss: 25, Samples: 4}
	if got != want {
		t.Errorf("got %+v\nwant %+v", got, want)
	}

	got = summarize(target, append(ss, Sample{}))
	if got.Last != 0 || got.Loss != 40 {
		t.Errorf("last probe lost: %+v", got)
	}
	if got := summarize(target, []Sample{{}, {}}); got.Avg != 0 || got.Loss != 100 {
		t.Errorf("all lost: %+v", got)
	}
	if got := summarize(target, nil); got.Samples != 0 || got.Loss != 0 {
		t.Errorf("empty: %+v", got)
	}
}

func TestRing(t *testing.T) {
	var r ring
	for i := range HistoryLen + 5 {
		r.add(Sample{RTT: Millis(i)})
	}
	ss := r.samples()
	if len(ss) != HistoryLen || ss[0].RTT != 5 || ss[len(ss)-1].RTT != HistoryLen+4 {
		t.Fatalf("len %d, first %v, last %v", len(ss), ss[0].RTT, ss[len(ss)-1].RTT)
	}
}

func TestMillisJSON(t *testing.T) {
	b, err := json.Marshal(Latency{Avg: Millis(12345678 * time.Nanosecond)})
	if err != nil {
		t.Fatal(err)
	}
	var l Latency
	if err := json.Unmarshal(b, &l); err != nil || l.Avg != ms(12.35) {
		t.Errorf("%s → %+v, %v", b, l, err)
	}
}

func TestMonitorLatency(t *testing.T) {
	a, b := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")
	fp := &fakeProber{
		down: map[netip.Addr]bool{},
		rtt:  map[netip.Addr]time.Duration{a: 5 * time.Millisecond, b: 7 * time.Millisecond},
	}
	link := "up"
	env := Env{
		Prober: fp,
		Link:   func(string) (string, error) { return link, nil },
		Route:  func(netip.Addr, uint32) (string, error) { return "wg-a", nil },
	}
	m := NewMonitor(tunnel(), env)
	ctx := context.Background()
	m.RunRound(ctx)
	fp.down[b] = true
	m.RunRound(ctx)
	link = "down" // not probed: lost for both
	m.RunRound(ctx)

	l := m.Snapshot().Latency
	if len(l) != 2 || l[0].Target != a || l[0].Avg != ms(5) || l[0].Last != 0 || l[0].Samples != 3 {
		t.Fatalf("a: %+v", l)
	}
	if l[1].Avg != ms(7) || l[1].Loss != 66.7 {
		t.Fatalf("b: %+v", l[1])
	}
	h := m.History()
	if len(h) != 2 || len(h[1].Samples) != 3 || !h[1].Samples[0].OK || h[1].Samples[1].OK {
		t.Fatalf("history: %+v", h)
	}

	n := NewMonitor(tunnel(), env)
	n.Adopt(m)
	if got := n.History(); len(got[0].Samples) != 3 {
		t.Fatalf("adopt keeps history: %+v", got)
	}
}
