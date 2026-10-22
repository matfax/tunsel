// Package status serves the daemon's state over a unix socket and renders
// it for `tunsel status`.
package status

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/matfax/tunsel/internal/engine"
	"github.com/matfax/tunsel/internal/flows"
	"github.com/matfax/tunsel/internal/health"
	"github.com/matfax/tunsel/internal/learn"
	"github.com/matfax/tunsel/internal/nft"
)

type Report struct {
	Version   string    `json:"version"`
	Config    string    `json:"config"`
	Table     string    `json:"table"`
	StartedAt time.Time `json:"started_at"`
	Tunnels   []Tunnel  `json:"tunnels"`
	Default4  string    `json:"default_ipv4"`
	Default6  string    `json:"default_ipv6"`
	Apply     Apply     `json:"last_apply"`
	// New connections by decision, counted since the table was first
	// installed (nft counters, kept across table replacements).
	Connections Connections       `json:"connections"`
	Exclude     engine.RangeStats `json:"exclude"`
	// Only while learning is enabled.
	Learning *Learning `json:"learning,omitempty"`
	// Only on request.
	Flows *Flows `json:"flows,omitempty"`
	// Counters or flows that could not be read.
	Warnings []string `json:"warnings,omitempty"`
}

type Tunnel struct {
	Name string `json:"name"`
	Mark uint32 `json:"mark"`
	health.Snapshot
	// New connections steered here by a static preference, a learned
	// destination or as default.
	Static  uint64 `json:"connections_static"`
	Learned uint64 `json:"connections_learned"`
	Default uint64 `json:"connections_default"`
	// Upstream packets of established connections sent into the tunnel.
	// Flows offloaded to a flowtable are not counted.
	Upstream nft.Counter `json:"upstream"`
	// Static preferences in effect for this tunnel.
	Ranges engine.RangeStats `json:"static_ranges"`
	// Only on request.
	History []health.History `json:"history,omitempty"`
}

type Connections struct {
	New      uint64 `json:"new"`
	Local    uint64 `json:"local"`
	Excluded uint64 `json:"excluded"`
	// No static preference and no default for the family.
	Unmarked uint64 `json:"unmarked"`
}

// Learning summarizes per-destination learning (design §7).
type Learning struct {
	Source    string    `json:"source"`
	Refresh   string    `json:"refresh"`
	LastRound time.Time `json:"last_round"`
	LastError string    `json:"last_error,omitempty"`
	// Of the last round: candidates the source reported, those measured
	// (eligible and new or due for renewal, at most top_n), and of these
	// the renewals.
	Seen     int `json:"seen"`
	Measured int `json:"measured"`
	Renewals int `json:"renewals"`
	// Live records: with a learned tunnel in nft, and without one (the
	// baseline was fastest, the gain too small, no answer or damped).
	Learned int `json:"learned"`
	Kept    int `json:"kept"`
	// Only on request, most recent first.
	Entries []learn.Record `json:"entries,omitempty"`
}

// Flows is the current conntrack table attributed to tunnels.
type Flows struct {
	At      time.Time              `json:"at"`
	Tunnels map[string]flows.Group `json:"tunnels"`
	Other   int                    `json:"other"`
}

type Apply struct {
	At    time.Time `json:"at"`
	Error string    `json:"error,omitempty"`
}

// Request selects the optional parts of a report. On the socket it is one
// line: "status", optionally followed by "flows", "history" and/or
// "learned".
type Request struct {
	Flows   bool
	History bool
	Learned bool
}

func (r Request) String() string {
	s := "status"
	if r.Flows {
		s += " flows"
	}
	if r.History {
		s += " history"
	}
	if r.Learned {
		s += " learned"
	}
	return s
}

func parseRequest(line string) (Request, error) {
	words := strings.Fields(line)
	if len(words) == 0 || words[0] != "status" {
		return Request{}, fmt.Errorf("unknown request %q", line)
	}
	var r Request
	for _, w := range words[1:] {
		switch w {
		case "flows":
			r.Flows = true
		case "history":
			r.History = true
		case "learned":
			r.Learned = true
		default:
			return Request{}, fmt.Errorf("unknown option %q", w)
		}
	}
	return r, nil
}

// Serve accepts connections on a unix socket at path and answers each
// request with a report, until ctx is done.
func Serve(ctx context.Context, path string, report func(Request) Report) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
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
			// A conntrack dump can take a moment on a busy router.
			c.SetDeadline(time.Now().Add(10 * time.Second))
			answer(c, report)
			c.Close()
		}
	}()
	return nil
}

func answer(c net.Conn, report func(Request) Report) {
	line, err := bufio.NewReader(io.LimitReader(c, 256)).ReadString('\n')
	if err != nil {
		return
	}
	req, err := parseRequest(line)
	if err != nil {
		json.NewEncoder(c).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(c).Encode(report(req))
}

// Fetch reads a report from the daemon.
func Fetch(path string, req Request) (*Report, error) {
	c, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("daemon not reachable at %s: %w", path, err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := fmt.Fprintln(c, req); err != nil {
		return nil, err
	}
	var raw json.RawMessage
	if err := json.NewDecoder(c).Decode(&raw); err != nil {
		return nil, err
	}
	var e struct{ Error string }
	if json.Unmarshal(raw, &e) == nil && e.Error != "" {
		return nil, errors.New(e.Error)
	}
	var r Report
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Render writes the report as text: a header, then one section each for
// health, latency, traffic and, when requested, flows, learned
// destinations and RTT history.
func (r *Report) Render(w io.Writer) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	r.renderHeader(w)
	r.renderHealth(w, tw)
	r.renderLatency(w, tw)
	r.renderTraffic(w, tw)
	r.renderFlows(w, tw)
	r.renderLearned(w, tw)
	r.renderHistory(w)
}

func (r *Report) renderHeader(w io.Writer) {
	fmt.Fprintf(w, "tunsel %s, table inet %s, up %s\n", r.Version, r.Table, time.Since(r.StartedAt).Round(time.Second))
	fmt.Fprintf(w, "default: ipv4 %s, ipv6 %s\n", orNone(r.Default4), orNone(r.Default6))
	if r.Apply.Error != "" {
		fmt.Fprintf(w, "last apply FAILED at %s: %s\n", r.Apply.At.Format(time.RFC3339), r.Apply.Error)
	}
	for _, warn := range r.Warnings {
		fmt.Fprintf(w, "warning: %s\n", warn)
	}
	c := r.Connections
	fmt.Fprintf(w, "new connections: %d (excluded %d, local %d, unmarked %d)\n", c.New, c.Excluded, c.Local, c.Unmarked)
	if l := r.Learning; l != nil {
		last := "no round yet"
		if !l.LastRound.IsZero() {
			last = fmt.Sprintf("last round %s ago: %d seen, %d measured (%d renewals)", time.Since(l.LastRound).Round(time.Second), l.Seen, l.Measured, l.Renewals)
		}
		fmt.Fprintf(w, "learning: %s every %s, %s; %d destinations learned, %d kept on their baseline\n", l.Source, l.Refresh, last, l.Learned, l.Kept)
		if l.LastError != "" {
			fmt.Fprintf(w, "learning FAILED: %s\n", l.LastError)
		}
	}
}

func (r *Report) renderHealth(w io.Writer, tw *tabwriter.Writer) {
	fmt.Fprintln(w)
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
}

func (r *Report) renderLatency(w io.Writer, tw *tabwriter.Writer) {
	fmt.Fprintln(w)
	fmt.Fprintln(tw, "TUNNEL\tTARGET\tLAST\tAVG\tMIN\tMAX\tJITTER\tLOSS")
	for _, t := range r.Tunnels {
		for _, l := range t.Latency {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%.1f%% of %d\n", t.Name, l.Target,
				millis(l.Last), millis(l.Avg), millis(l.Min), millis(l.Max), millis(l.Jitter), l.Loss, l.Samples)
		}
	}
	tw.Flush()
}

func (r *Report) renderTraffic(w io.Writer, tw *tabwriter.Writer) {
	fmt.Fprintln(w)
	fmt.Fprintln(tw, "TUNNEL\tSTATIC\tLEARNED\tDEFAULT\tUPSTREAM\tSTATIC RANGES")
	for _, t := range r.Tunnels {
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%s, %d pkts\t%s\n", t.Name, t.Static, t.Learned, t.Default,
			fmtBytes(t.Upstream.Bytes), t.Upstream.Packets, fmtRanges(t.Ranges))
	}
	tw.Flush()
	fmt.Fprintf(w, "exclude: %s\n", fmtRanges(r.Exclude))
}

func (r *Report) renderFlows(w io.Writer, tw *tabwriter.Writer) {
	f := r.Flows
	if f == nil {
		return
	}
	fmt.Fprintf(w, "\nflows at %s (%d entries without a tunnel mark)\n", f.At.Format(time.TimeOnly), f.Other)
	fmt.Fprintln(tw, "TUNNEL\tFLOWS\tDESTINATIONS\tOUT\tIN\tTOP DESTINATIONS")
	for _, t := range r.Tunnels {
		g := f.Tunnels[t.Name]
		var top []string
		for _, d := range g.Top[:min(len(g.Top), 3)] {
			top = append(top, fmt.Sprintf("%s (%s)", d.Addr, fmtBytes(d.Bytes)))
		}
		fmt.Fprintf(tw, "%s\t%d\t%d\t%s\t%s\t%s\n", t.Name, g.Flows, g.Destinations,
			fmtBytes(g.BytesOut), fmtBytes(g.BytesIn), strings.Join(top, ", "))
	}
	tw.Flush()
}

// LearnedShown bounds the learned destinations listed as text; -json has
// all of them.
const LearnedShown = 50

func (r *Report) renderLearned(w io.Writer, tw *tabwriter.Writer) {
	if r.Learning == nil || r.Learning.Entries == nil {
		return
	}
	es := r.Learning.Entries
	fmt.Fprintf(w, "\nlearned destinations, most recent first (%d of %d)\n", min(len(es), LearnedShown), len(es))
	fmt.Fprintln(tw, "DESTINATION\tTUNNEL\tBASELINE\tOUTCOME\tHANDSHAKE\tEXPIRES IN")
	for _, e := range es[:min(len(es), LearnedShown)] {
		names := make([]string, 0, len(e.RTT))
		for n := range e.RTT {
			names = append(names, n)
		}
		sort.Strings(names)
		var rtts []string
		for _, n := range names {
			rtts = append(rtts, n+" "+millis(e.RTT[n]))
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", e.Addr, orDash(e.Tunnel), orDash(e.Baseline), e.Outcome,
			orDash(strings.Join(rtts, ", ")), time.Until(e.Expires).Round(time.Second))
	}
	tw.Flush()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func (r *Report) renderHistory(w io.Writer) {
	if !hasHistory(r) {
		return
	}
	fmt.Fprintln(w, "\nRTT history, oldest first (· = lost)")
	for _, t := range r.Tunnels {
		for _, h := range t.History {
			fmt.Fprintf(w, "  %s %s %s\n", t.Name, h.Target, sparkline(h.Samples))
		}
	}
}

func hasHistory(r *Report) bool {
	for _, t := range r.Tunnels {
		if len(t.History) > 0 {
			return true
		}
	}
	return false
}

// sparkline draws one character per sample, scaled to the largest RTT.
func sparkline(ss []health.Sample) string {
	const bars = "▁▂▃▄▅▆▇█"
	levels := []rune(bars)
	var hi health.Millis
	for _, s := range ss {
		hi = max(hi, s.RTT)
	}
	var b strings.Builder
	for _, s := range ss {
		if !s.OK {
			b.WriteRune('·')
			continue
		}
		i := 0
		if hi > 0 {
			i = int(int64(s.RTT) * int64(len(levels)-1) / int64(hi))
		}
		b.WriteRune(levels[i])
	}
	if hi > 0 {
		fmt.Fprintf(&b, " (max %s)", millis(hi))
	}
	return b.String()
}

func millis(m health.Millis) string {
	if m == 0 {
		return "-"
	}
	if m < health.Millis(time.Millisecond) {
		return fmt.Sprintf("%.2fms", float64(m)/float64(time.Millisecond))
	}
	return fmt.Sprintf("%.1fms", float64(m)/float64(time.Millisecond))
}

func fmtBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func fmtRanges(s engine.RangeStats) string {
	if s.Prefixes == 0 {
		return "none"
	}
	out := fmt.Sprintf("%d prefixes, %d ranges in effect", s.Prefixes, s.Ranges)
	var parts []string
	if s.IPv4 > 0 {
		parts = append(parts, fmt.Sprintf("%d IPv4 addresses", s.IPv4))
	}
	if s.IPv6 > 0 {
		parts = append(parts, fmt.Sprintf("%d IPv6 /64s", s.IPv6))
	}
	if len(parts) > 0 {
		out += " (" + strings.Join(parts, ", ") + ")"
	}
	return out
}

func orNone(s string) string {
	if s == "" {
		return "none (unmarked)"
	}
	return s
}
