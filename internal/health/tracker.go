// Package health probes tunnels and turns probe rounds into a health state
// with hysteresis.
package health

import "fmt"

type State int

const (
	Unknown State = iota
	Healthy
	Unhealthy
)

func (s State) String() string {
	switch s {
	case Healthy:
		return "healthy"
	case Unhealthy:
		return "unhealthy"
	}
	return "unknown"
}

func (s State) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

func (s *State) UnmarshalText(b []byte) error {
	switch string(b) {
	case "healthy":
		*s = Healthy
	case "unhealthy":
		*s = Unhealthy
	case "unknown":
		*s = Unknown
	default:
		return fmt.Errorf("unknown state %q", b)
	}
	return nil
}

// Round is the outcome of one probe round.
type Round struct {
	Passed bool
	// Down means the interface is missing or administratively down; it
	// makes the tunnel unhealthy immediately, bypassing fail_after.
	Down bool
}

// Tracker applies hysteresis to probe rounds. The first round sets the
// state directly, so a restart does not wait recover_after rounds.
type Tracker struct {
	FailAfter, RecoverAfter int

	State         State
	passes, fails int
}

// Observe records a round and reports whether the state changed.
func (t *Tracker) Observe(r Round) bool {
	prev := t.State
	if r.Passed && !r.Down {
		t.passes++
		t.fails = 0
	} else {
		t.fails++
		t.passes = 0
	}
	switch t.State {
	case Unknown:
		if r.Passed && !r.Down {
			t.State = Healthy
		} else {
			t.State = Unhealthy
		}
	case Healthy:
		if r.Down || t.fails >= t.FailAfter {
			t.State = Unhealthy
		}
	case Unhealthy:
		if t.passes >= t.RecoverAfter {
			t.State = Healthy
		}
	}
	return t.State != prev
}

// Streak returns the current run lengths of passed and failed rounds.
func (t *Tracker) Streak() (passes, fails int) { return t.passes, t.fails }
