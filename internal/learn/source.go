// Package learn picks the fastest tunnel per destination (design §7):
// candidates from a source, TCP handshake times through every healthy
// tunnel, and a decision per destination that lives for a TTL.
package learn

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/matfax/tunsel/internal/flows"
)

// Candidate is a destination a source has seen, with how much it was
// used: bytes and flows for conntrack, queries for AdGuard.
type Candidate struct {
	Addr  netip.Addr
	Name  string // the queried name, if the source knows it
	Score uint64
	Hits  int
}

// Source reports candidates; each call returns what it has seen since the
// previous one (AdGuard) or right now (conntrack).
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

// AdGuard reads the query log of AdGuard Home (GET /control/querylog) and
// counts, per address, the A and AAAA answers since the previous call. The
// first call looks back Lookback.
type AdGuard struct {
	URL, Username, Password string
	Lookback                time.Duration
	// Clients on loopback are the router itself; their queries only count
	// when the router's own traffic is steered.
	LocalClients bool
	Client       *http.Client
	Now          func() time.Time

	cursor time.Time // newest entry counted
}

// adguardPage and adguardMax bound one poll to 10000 log entries; a router
// resolving more than that per refresh needs a shorter refresh.
const (
	adguardPage = 500
	adguardMax  = 20
)

type queryLog struct {
	Data   []queryEntry `json:"data"`
	Oldest string       `json:"oldest"`
}

type queryEntry struct {
	Time     time.Time `json:"time"`
	Client   string    `json:"client"`
	Question struct {
		Name string `json:"name"`
	} `json:"question"`
	Answer []struct {
		Type  string          `json:"type"`
		Value json.RawMessage `json:"value"` // a string for A and AAAA
	} `json:"answer"`
}

func (a *AdGuard) Candidates(ctx context.Context) ([]Candidate, error) {
	now := time.Now
	if a.Now != nil {
		now = a.Now
	}
	if a.cursor.IsZero() {
		a.cursor = now().Add(-a.Lookback)
	}
	by := map[netip.Addr]*Candidate{}
	newest := a.cursor
	older := ""
	for range adguardMax {
		page, err := a.fetch(ctx, older)
		if err != nil {
			return nil, err
		}
		done := len(page.Data) < adguardPage || page.Oldest == ""
		// Entries come newest first.
		for _, e := range page.Data {
			if !e.Time.After(a.cursor) {
				done = true
				break
			}
			if e.Time.After(newest) {
				newest = e.Time
			}
			a.count(by, e)
		}
		if done {
			break
		}
		older = page.Oldest
	}
	a.cursor = newest
	out := make([]Candidate, 0, len(by))
	for _, cd := range by {
		out = append(out, *cd)
	}
	return out, nil
}

func (a *AdGuard) count(by map[netip.Addr]*Candidate, e queryEntry) {
	if c, err := netip.ParseAddr(e.Client); err == nil && c.IsLoopback() && !a.LocalClients {
		return
	}
	for _, ans := range e.Answer {
		if ans.Type != "A" && ans.Type != "AAAA" {
			continue
		}
		var v string
		if json.Unmarshal(ans.Value, &v) != nil {
			continue
		}
		addr, err := netip.ParseAddr(v)
		if err != nil {
			continue
		}
		addr = addr.Unmap()
		cd := by[addr]
		if cd == nil {
			cd = &Candidate{Addr: addr, Name: strings.TrimSuffix(e.Question.Name, ".")}
			by[addr] = cd
		}
		cd.Score++
		cd.Hits++
	}
}

func (a *AdGuard) fetch(ctx context.Context, older string) (*queryLog, error) {
	q := url.Values{"limit": {strconv.Itoa(adguardPage)}}
	if older != "" {
		q.Set("older_than", older)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(a.URL, "/")+"/control/querylog?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	if a.Username != "" {
		req.SetBasicAuth(a.Username, a.Password)
	}
	c := a.Client
	if c == nil {
		c = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("adguard: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return nil, fmt.Errorf("adguard: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	var page queryLog
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		return nil, fmt.Errorf("adguard: query log: %w", err)
	}
	return &page, nil
}
