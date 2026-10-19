package health

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/matfax/tunsel/internal/config"
)

// Event reports a health state change of one tunnel.
type Event struct {
	Tunnel string
	State  State
	// Gen identifies the monitor generation, so the daemon can discard
	// events from monitors replaced by a reload.
	Gen uint64
}

// Snapshot is the externally visible state of a monitor.
type Snapshot struct {
	State     State     `json:"state"`
	Since     time.Time `json:"since"`
	LastRound time.Time `json:"last_round"`
	Link      string    `json:"link"` // up | down | missing
	OK        int       `json:"ok"`
	Total     int       `json:"total"`
	Passes    int       `json:"passes"`
	Fails     int       `json:"fails"`
	Errors    []string  `json:"errors,omitempty"`
	// Latency per health target over the kept history.
	Latency []Latency `json:"latency,omitempty"`
}

// LinkState reports the administrative state of an interface.
type LinkState func(name string) (string, error)

func SysLinkState(name string) (string, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return "missing", err
	}
	if ifi.Flags&net.FlagUp == 0 {
		return "down", nil
	}
	return "up", nil
}

// Env is how a monitor reaches the system; zero fields use the real one.
type Env struct {
	Prober Prober
	Link   LinkState
	Route  RouteCheck
}

type Monitor struct {
	tun config.Tunnel
	env Env

	mu      sync.Mutex
	tracker Tracker
	snap    Snapshot
	history []ring // per health target, in config order
}

func NewMonitor(t config.Tunnel, env Env) *Monitor {
	if env.Prober == nil {
		env.Prober = SocketProber{}
	}
	if env.Link == nil {
		env.Link = SysLinkState
	}
	if env.Route == nil {
		env.Route = SysRouteCheck
	}
	return &Monitor{
		tun: t, env: env,
		tracker: Tracker{FailAfter: t.Health.FailAfter, RecoverAfter: t.Health.RecoverAfter},
		history: make([]ring, len(t.Health.Targets)),
	}
}

// Adopt takes over the health state of a monitor from a previous
// configuration, so a reload does not reset an unchanged tunnel.
func (m *Monitor) Adopt(old *Monitor) {
	old.mu.Lock()
	defer old.mu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tracker.State = old.tracker.State
	m.tracker.passes, m.tracker.fails = old.tracker.passes, old.tracker.fails
	m.snap = old.snap
	// The daemon adopts only unchanged tunnels, so the targets match.
	for i := range min(len(old.history), len(m.history)) {
		m.history[i].buf = append([]Sample(nil), old.history[i].buf...)
		m.history[i].next = old.history[i].next
	}
}

func (m *Monitor) Tunnel() config.Tunnel { return m.tun }

func (m *Monitor) State() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tracker.State
}

func (m *Monitor) Snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.snap
	s.State = m.tracker.State
	s.Passes, s.Fails = m.tracker.Streak()
	s.Errors = append([]string(nil), s.Errors...)
	for i, t := range m.tun.Health.Targets {
		s.Latency = append(s.Latency, summarize(t, m.history[i].samples()))
	}
	return s
}

// History returns the kept samples per health target.
func (m *Monitor) History() []History {
	m.mu.Lock()
	defer m.mu.Unlock()
	var hs []History
	for i, t := range m.tun.Health.Targets {
		hs = append(hs, History{Target: t, Samples: m.history[i].samples()})
	}
	return hs
}

// RunRound performs one probe round and reports whether the state changed.
func (m *Monitor) RunRound(ctx context.Context) (changed bool) {
	h := m.tun.Health
	link, _ := m.env.Link(m.tun.Name)
	var (
		ok      int
		errs    []string
		results = make([]error, len(h.Targets))
		rtts    = make([]time.Duration, len(h.Targets))
	)
	down := link != "up"
	if down {
		errs = append(errs, "interface "+link)
	} else if err := m.checkRoutes(); err != nil {
		down = true
		errs = append(errs, err.Error())
	}
	if !down {
		ctx, cancel := context.WithTimeout(ctx, h.Timeout.D())
		defer cancel()
		var wg sync.WaitGroup
		for i, target := range h.Targets {
			wg.Add(1)
			go func() {
				defer wg.Done()
				rtts[i], results[i] = m.env.Prober.Probe(ctx, Probe{
					Iface: m.tun.Name, Mark: m.tun.Mark, Target: target,
					Kind: h.ProbeKind, Port: h.ProbePort,
				})
			}()
		}
		wg.Wait()
		for i, err := range results {
			if err == nil {
				ok++
			} else {
				errs = append(errs, fmt.Sprintf("%s: %v", h.Targets[i], err))
			}
		}
	}

	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	changed = m.tracker.Observe(Round{Passed: ok >= h.MinOK, Down: down})
	if changed || m.snap.Since.IsZero() {
		m.snap.Since = now
	}
	m.snap.LastRound, m.snap.Link = now, link
	m.snap.OK, m.snap.Total, m.snap.Errors = ok, len(h.Targets), errs
	// A round skipped because the tunnel is down counts as lost for every
	// target.
	for i := range h.Targets {
		s := Sample{At: now}
		if !down && results[i] == nil {
			s.RTT, s.OK = Millis(rtts[i]), true
		}
		m.history[i].add(s)
	}
	return changed
}

// checkRoutes verifies, once per family among the targets, that traffic
// carrying the tunnel's mark is routed out of the tunnel.
func (m *Monitor) checkRoutes() error {
	var done4, done6 bool
	for _, t := range m.tun.Health.Targets {
		if (t.Is4() && done4) || (t.Is6() && done6) {
			continue
		}
		done4, done6 = done4 || t.Is4(), done6 || t.Is6()
		iface, err := m.env.Route(t, m.tun.Mark)
		if err != nil {
			return fmt.Errorf("route to %s with mark %#x: %v", t, m.tun.Mark, err)
		}
		if iface != m.tun.Name {
			return fmt.Errorf("route to %s with mark %#x leaves via %s, not %s (policy table missing its route?)", t, m.tun.Mark, iface, m.tun.Name)
		}
	}
	return nil
}

// Run probes every interval until ctx is done, sending an event on each
// state change. The caller runs the first round itself.
func (m *Monitor) Run(ctx context.Context, gen uint64, events chan<- Event) {
	t := time.NewTicker(m.tun.Health.Interval.D())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if m.RunRound(ctx) && ctx.Err() == nil {
			select {
			case events <- Event{Tunnel: m.tun.Name, State: m.State(), Gen: gen}:
			case <-ctx.Done():
				return
			}
		}
	}
}
