package health

import (
	"encoding/json"
	"math"
	"net/netip"
	"time"
)

// HistoryLen is the number of probes kept per target: an hour at the
// default interval of 10 s.
const HistoryLen = 360

// Millis is a duration that is written to JSON as fractional milliseconds.
type Millis time.Duration

func (m Millis) MarshalJSON() ([]byte, error) {
	return json.Marshal(math.Round(float64(m)/1e4) / 100)
}

func (m *Millis) UnmarshalJSON(b []byte) error {
	var ms float64
	if err := json.Unmarshal(b, &ms); err != nil {
		return err
	}
	*m = Millis(ms * 1e6)
	return nil
}

func (m Millis) D() time.Duration { return time.Duration(m) }

// Sample is one probe of one target. RTT is omitted for a probe that got
// no answer, including rounds skipped because the tunnel was down.
type Sample struct {
	At  time.Time `json:"at"`
	RTT Millis    `json:"rtt_ms,omitempty"`
	OK  bool      `json:"ok"`
}

// Latency summarizes the kept samples of one target. The RTT fields are
// omitted while no probe in the window was answered; Last is omitted when
// the most recent probe got no answer.
type Latency struct {
	Target  netip.Addr `json:"target"`
	Last    Millis     `json:"last_ms,omitempty"`
	Min     Millis     `json:"min_ms,omitempty"`
	Avg     Millis     `json:"avg_ms,omitempty"`
	Max     Millis     `json:"max_ms,omitempty"`
	Jitter  Millis     `json:"jitter_ms,omitempty"` // mean change between consecutive answers
	Loss    float64    `json:"loss_pct"`
	Samples int        `json:"samples"`
}

// History is the kept samples of one target, oldest first.
type History struct {
	Target  netip.Addr `json:"target"`
	Samples []Sample   `json:"samples"`
}

// ring keeps the last HistoryLen samples.
type ring struct {
	buf  []Sample
	next int
}

func (r *ring) add(s Sample) {
	if len(r.buf) < HistoryLen {
		r.buf = append(r.buf, s)
		return
	}
	r.buf[r.next] = s
	r.next = (r.next + 1) % HistoryLen
}

// samples returns a copy of the kept samples, oldest first.
func (r *ring) samples() []Sample {
	out := make([]Sample, 0, len(r.buf))
	out = append(out, r.buf[r.next:]...)
	return append(out, r.buf[:r.next]...)
}

func summarize(target netip.Addr, ss []Sample) Latency {
	l := Latency{Target: target, Samples: len(ss)}
	if len(ss) == 0 {
		return l
	}
	if last := ss[len(ss)-1]; last.OK {
		l.Last = last.RTT
	}
	var (
		ok        int
		sum, jsum time.Duration
		prev      *Sample
		jn        int
	)
	for i := range ss {
		s := &ss[i]
		if !s.OK {
			continue
		}
		d := s.RTT.D()
		if ok == 0 || d < l.Min.D() {
			l.Min = s.RTT
		}
		if d > l.Max.D() {
			l.Max = s.RTT
		}
		sum += d
		ok++
		if prev != nil {
			jsum += (d - prev.RTT.D()).Abs()
			jn++
		}
		prev = s
	}
	l.Loss = math.Round(float64(len(ss)-ok)/float64(len(ss))*1000) / 10
	if ok > 0 {
		l.Avg = Millis(sum / time.Duration(ok))
	}
	if jn > 0 {
		l.Jitter = Millis(jsum / time.Duration(jn))
	}
	return l
}
