// Package status serves the daemon's state over a unix socket and renders
// it for `tunsel status`.
package status

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/matfax/tunsel/internal/health"
)

type Report struct {
	Version   string         `json:"version"`
	Config    string         `json:"config"`
	Table     string         `json:"table"`
	StartedAt time.Time      `json:"started_at"`
	Tunnels   []Tunnel       `json:"tunnels"`
	Default4  string         `json:"default_ipv4"`
	Default6  string         `json:"default_ipv6"`
	Sizes     map[string]int `json:"sizes"` // ranges per set/map
	Apply     Apply          `json:"last_apply"`
}

type Tunnel struct {
	Name string `json:"name"`
	Mark uint32 `json:"mark"`
	health.Snapshot
}

type Apply struct {
	At    time.Time `json:"at"`
	Error string    `json:"error,omitempty"`
}

// Serve accepts connections on a unix socket at path and writes the
// current report to each, until ctx is done.
func Serve(ctx context.Context, path string, report func() Report) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		l.Close()
		return err
	}
	go func() {
		<-ctx.Done()
		l.Close()
	}()
	go func() {
		defer os.Remove(path)
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.SetDeadline(time.Now().Add(2 * time.Second))
			json.NewEncoder(c).Encode(report())
			c.Close()
		}
	}()
	return nil
}

// Fetch reads a report from the daemon.
func Fetch(path string) (*Report, error) {
	c, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("daemon not reachable at %s: %w", path, err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	var r Report
	if err := json.NewDecoder(c).Decode(&r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (r *Report) Render(w io.Writer) {
	fmt.Fprintf(w, "tunsel %s, table inet %s, up %s\n", r.Version, r.Table, time.Since(r.StartedAt).Round(time.Second))
	fmt.Fprintf(w, "default: ipv4 %s, ipv6 %s\n", orNone(r.Default4), orNone(r.Default6))
	if r.Apply.Error != "" {
		fmt.Fprintf(w, "last apply FAILED at %s: %s\n", r.Apply.At.Format(time.RFC3339), r.Apply.Error)
	}
	fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TUNNEL\tMARK\tSTATE\tSINCE\tLINK\tLAST ROUND\tSTREAK")
	for _, t := range r.Tunnels {
		streak := fmt.Sprintf("%d ok", t.Passes)
		if t.Fails > 0 {
			streak = fmt.Sprintf("%d failed", t.Fails)
		}
		fmt.Fprintf(tw, "%s\t%#x\t%s\t%s ago\t%s\t%d/%d answered\t%s\n",
			t.Name, t.Mark, t.State, time.Since(t.Since).Round(time.Second), t.Link, t.OK, t.Total, streak)
	}
	tw.Flush()
	for _, t := range r.Tunnels {
		for _, e := range t.Errors {
			fmt.Fprintf(w, "  %s: %s\n", t.Name, e)
		}
	}
	var sizes []string
	for _, k := range []string{"exclude4", "exclude6", "static4", "static6"} {
		sizes = append(sizes, fmt.Sprintf("%s %d", k, r.Sizes[k]))
	}
	fmt.Fprintf(w, "\nranges: %s\n", strings.Join(sizes, ", "))
}

func orNone(s string) string {
	if s == "" {
		return "none (unmarked)"
	}
	return s
}
