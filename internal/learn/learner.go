package learn

import (
	"context"
	"net/netip"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/matfax/tunsel/internal/config"
	"github.com/matfax/tunsel/internal/health"
)

// Outcomes of a measurement.
const (
	Learned  = "learned"   // a faster tunnel than the baseline; installed in nft
	Baseline = "baseline"  // the baseline was fastest
	NoGain   = "no gain"   // faster, but below min_gain
	NoAnswer = "no answer" // no tunnel completed a handshake
	Damped   = "damped"    // too many changes within flap_damping.window
)

// Grace keeps a record beyond its expiry, so a destination is measured
// again only once the kernel has expired its nft element too.
const Grace = 2 * time.Second

// Record is the result of measuring one destination. Every outcome is kept
// until Expires, so a destination is not measured again before then.
type Record struct {
	Addr netip.Addr `json:"addr"`
	Name string     `json:"name,omitempty"`
	// Tunnel is the learned tunnel; "" leaves the destination to its
	// baseline (the static preference or default it takes without one).
	Tunnel   string                   `json:"tunnel,omitempty"`
	Baseline string                   `json:"baseline"`
	Outcome  string                   `json:"outcome"`
	RTT      map[string]health.Millis `json:"rtt_ms,omitempty"` // median per tunnel that answered
	Decided  time.Time                `json:"decided"`
	Expires  time.Time                `json:"expires"`
}

// track remembers a destination's effective tunnel across expiries, for
// flap damping.
type track struct {
	tunnel  string
	seen    time.Time
	changes []time.Time
}

// Learner holds the records and the damping history. It is not safe for
// concurrent use.
type Learner struct {
	records map[netip.Addr]*Record
	tracks  map[netip.Addr]*track
}

func New() *Learner {
	return &Learner{records: map[netip.Addr]*Record{}, tracks: map[netip.Addr]*track{}}
}

// Prune forgets records past their expiry (plus Grace) and damping
// history older than window.
func (l *Learner) Prune(now time.Time, window time.Duration) {
	for a, r := range l.records {
		if now.After(r.Expires.Add(Grace)) {
			delete(l.records, a)
		}
	}
	for a, t := range l.tracks {
		if now.Sub(t.seen) > window {
			delete(l.tracks, a)
		}
	}
}

// Drop forgets the records for which drop returns true, so their
// destinations are measured again at the next refresh.
func (l *Learner) Drop(drop func(*Record) bool) {
	for a, r := range l.records {
		if drop(r) {
			delete(l.records, a)
		}
	}
}

// Trained reports whether addr has a record.
func (l *Learner) Trained(addr netip.Addr) bool { return l.records[addr] != nil }

// Records returns the records, most recent decision first.
func (l *Learner) Records() []Record {
	out := make([]Record, 0, len(l.records))
	for _, r := range l.records {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Decided.Equal(out[j].Decided) {
			return out[i].Decided.After(out[j].Decided)
		}
		return out[i].Addr.Less(out[j].Addr)
	})
	return out
}

// Select returns up to n candidates, the most used first, that have no
// record and that eligible accepts. Untrained destinations get every slot.
func (l *Learner) Select(cands []Candidate, n int, eligible func(netip.Addr) bool) []Candidate {
	var out []Candidate
	for _, c := range cands {
		if c.Addr.IsValid() && !l.Trained(c.Addr) && eligible(c.Addr) {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		if a.Hits != b.Hits {
			return a.Hits > b.Hits
		}
		return a.Addr.Less(b.Addr)
	})
	return out[:min(len(out), n)]
}

// Decide turns the medians of one destination into a record. baseline is
// the tunnel it takes without a learned entry; healthy reports which
// tunnels may still be learned.
func (l *Learner) Decide(c Candidate, rtt map[string]time.Duration, baseline string, healthy func(string) bool, p *config.Learning, now time.Time) *Record {
	r := &Record{
		Addr: c.Addr, Name: c.Name, Baseline: baseline, RTT: map[string]health.Millis{},
		Decided: now, Expires: now.Add(p.TTL.D()),
	}
	var names []string
	for n, d := range rtt {
		r.RTT[n] = health.Millis(d)
		names = append(names, n)
	}
	if len(names) == 0 {
		r.Outcome = NoAnswer
		return r
	}
	// The fastest; ties go to the baseline, then by name.
	slices.Sort(names)
	win := names[0]
	for _, n := range names {
		if rtt[n] < rtt[win] || (rtt[n] == rtt[win] && n == baseline) {
			win = n
		}
	}
	switch base, ok := rtt[baseline]; {
	case win == baseline:
		r.Outcome = Baseline
	case ok && (base-rtt[win] < p.MinGain.Abs.D() || float64(base-rtt[win]) < float64(base)*float64(p.MinGain.Rel)):
		r.Outcome = NoGain
	default:
		r.Tunnel, r.Outcome = win, Learned
	}

	// Damping: once a destination changed tunnels max_switches times within
	// the window, it stays on the one it has.
	eff := r.Tunnel
	if eff == "" {
		eff = baseline
	}
	if t := l.tracks[c.Addr]; t != nil && t.tunnel != eff && healthy(t.tunnel) &&
		l.changes(t, now, p.FlapDamp.Window.D()) >= p.FlapDamp.MaxSwitches {
		r.Outcome, r.Tunnel = Damped, ""
		if t.tunnel != baseline {
			r.Tunnel = t.tunnel
		}
	}
	return r
}

func (l *Learner) changes(t *track, now time.Time, window time.Duration) int {
	n := 0
	for _, at := range t.changes {
		if now.Sub(at) <= window {
			n++
		}
	}
	return n
}

// Store keeps r and records its effective tunnel for damping.
func (l *Learner) Store(r *Record) {
	l.records[r.Addr] = r
	eff := r.Tunnel
	if eff == "" {
		eff = r.Baseline
	}
	t := l.tracks[r.Addr]
	switch {
	case t == nil:
		l.tracks[r.Addr] = &track{tunnel: eff, seen: r.Decided}
		return
	case t.tunnel != eff:
		t.changes = append(t.changes, r.Decided)
		t.tunnel = eff
	}
	t.seen = r.Decided
}

// Measure times TCP handshakes to addr:p.Port through each tunnel,
// p.Samples times, all tunnels of a sample at once, and returns the
// median per tunnel that answered at least once.
func Measure(ctx context.Context, prober health.Prober, addr netip.Addr, tunnels []config.Tunnel, p config.LearnProbe) map[string]time.Duration {
	got := make([][]time.Duration, len(tunnels))
	for range p.Samples {
		var wg sync.WaitGroup
		for i, t := range tunnels {
			wg.Add(1)
			go func() {
				defer wg.Done()
				pctx, cancel := context.WithTimeout(ctx, p.Timeout.D())
				defer cancel()
				d, err := prober.Probe(pctx, health.Probe{Iface: t.Name, Mark: t.Mark, Target: addr, Kind: config.ProbeTCP, Port: p.Port})
				if err == nil {
					got[i] = append(got[i], d)
				}
			}()
		}
		wg.Wait()
		if ctx.Err() != nil {
			return nil
		}
	}
	out := map[string]time.Duration{}
	for i, ds := range got {
		if len(ds) > 0 {
			out[tunnels[i].Name] = median(ds)
		}
	}
	return out
}

func median(ds []time.Duration) time.Duration {
	s := slices.Clone(ds)
	slices.Sort(s)
	if n := len(s); n%2 == 0 {
		return (s[n/2-1] + s[n/2]) / 2
	}
	return s[len(s)/2]
}
