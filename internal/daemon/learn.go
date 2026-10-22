package daemon

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/matfax/tunsel/internal/config"
	"github.com/matfax/tunsel/internal/engine"
	"github.com/matfax/tunsel/internal/health"
	"github.com/matfax/tunsel/internal/learn"
	"github.com/matfax/tunsel/internal/nft"
)

// learnWorkers bounds the destinations measured at once; each runs its
// samples through all tunnels in parallel.
const learnWorkers = 16

// restartLearning stops the learning loop and, if the current
// configuration enables learning, starts one for it.
func (d *Daemon) restartLearning(ctx context.Context) {
	d.stopLearning()
	d.mu.Lock()
	defer d.mu.Unlock()
	cfg := d.cfg
	if !cfg.Learning.Enabled {
		return
	}
	src := d.sourceLocked(cfg)
	lctx, stop := context.WithCancel(ctx)
	d.learnStop = stop
	d.learnDone.Add(1)
	go func() {
		defer d.learnDone.Done()
		d.learnLoop(lctx, cfg, src)
	}()
}

func (d *Daemon) stopLearning() {
	d.mu.Lock()
	stop := d.learnStop
	d.learnStop = nil
	d.mu.Unlock()
	if stop != nil {
		stop()
		d.learnDone.Wait()
	}
}

// sourceLocked returns the candidate source for cfg: the conntrack
// entries carrying a tunnel's mark.
func (d *Daemon) sourceLocked(cfg *config.Config) learn.Source {
	if d.opts.LearnSource != nil {
		return d.opts.LearnSource(cfg)
	}
	marks := map[uint32]bool{}
	for _, t := range cfg.Tunnels {
		marks[t.Mark] = true
	}
	return &learn.Conntrack{Dump: d.opts.DumpFlows, Mask: cfg.NFT.MarkMask, Marks: marks}
}

func (d *Daemon) learnLoop(ctx context.Context, cfg *config.Config, src learn.Source) {
	t := time.NewTicker(cfg.Learning.Candidates.Refresh.D())
	defer t.Stop()
	for {
		d.learnRound(ctx, cfg, src)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

type learnJob struct {
	cand    learn.Candidate
	tunnels []config.Tunnel
	rtt     map[string]time.Duration
}

// learnRound reads the candidates, measures the untrained ones without
// holding the lock, and installs the results. Results for a configuration
// replaced in the meantime are discarded.
func (d *Daemon) learnRound(ctx context.Context, cfg *config.Config, src learn.Source) {
	cands, err := src.Candidates(ctx)
	if ctx.Err() != nil {
		return
	}
	jobs := d.planRound(cfg, cands, err)
	if len(jobs) == 0 {
		return
	}
	prober := d.opts.Health.Prober
	if prober == nil {
		prober = health.SocketProber{}
	}
	sem := make(chan struct{}, learnWorkers)
	var wg sync.WaitGroup
	for _, j := range jobs {
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			j.rtt = learn.Measure(ctx, prober, j.cand.Addr, j.tunnels, cfg.Learning.Probe)
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cfg == cfg {
		d.commitLocked(cfg, jobs, d.opts.Now())
	}
}

// planRound records the round and picks the destinations to measure: new
// ones and those whose record is due for renewal.
func (d *Daemon) planRound(cfg *config.Config, cands []learn.Candidate, err error) []*learnJob {
	now := d.opts.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cfg != cfg {
		return nil
	}
	st := &d.learnStat
	st.LastRound, st.Seen, st.Measured, st.Renewals, st.LastError = now, len(cands), 0, 0, ""
	if err != nil {
		st.LastError = err.Error()
		d.log.Warn("learning: reading candidates failed", "source", cfg.Learning.Candidates.Source, "err", err)
		return nil
	}
	d.learner.Prune(now, cfg.Learning.FlapDamp.Window.D())
	healthy := d.healthyLocked()
	var jobs []*learnJob
	eligible := func(a netip.Addr) bool { return d.eligibleLocked(cfg, healthy, a) }
	for _, c := range d.learner.Select(cands, cfg.Learning.Candidates.TopN, eligible, now, learn.RenewBefore(&cfg.Learning)) {
		jobs = append(jobs, &learnJob{cand: c, tunnels: carriers(cfg, healthy, c.Addr)})
		if d.learner.Trained(c.Addr) {
			st.Renewals++
		}
	}
	st.Measured = len(jobs)
	return jobs
}

// commitLocked decides each measured destination against its baseline
// and current tunnel as of now, updates nft and keeps every record. A
// renewed destination's element is replaced in the same transaction, so
// it stays steered throughout.
func (d *Daemon) commitLocked(cfg *config.Config, jobs []*learnJob, now time.Time) {
	healthy := d.healthyLocked()
	renew := learn.RenewBefore(&cfg.Learning)
	var recs []*learn.Record
	var changes []learnChange
	for _, j := range jobs {
		addr := j.cand.Addr
		// Health may have changed while measuring.
		baseline, static := engine.Route(cfg, healthy, d.defaults, addr)
		if static || d.learner.Fresh(addr, now, renew) {
			continue
		}
		rtt := map[string]time.Duration{}
		for n, v := range j.rtt {
			if healthy(n) {
				rtt[n] = v
			}
		}
		current := d.learner.Current(addr)
		r := d.learner.Decide(j.cand, rtt, baseline, current, healthy, &cfg.Learning, now)
		var ch learnChange
		if current != "" {
			ch.remove = &nft.Learned{Addr: addr, Tunnel: current}
		}
		if r.Tunnel != "" {
			ch.add = &nft.Learned{Addr: addr, Tunnel: r.Tunnel, Timeout: cfg.Learning.TTL.D()}
		}
		if ch.remove != nil || ch.add != nil {
			changes = append(changes, ch)
		}
		recs = append(recs, r)
	}
	if failed := d.updateLearnedLocked(cfg, changes); len(failed) > 0 {
		// Keep the previous records; measured again next round.
		kept := recs[:0]
		for _, r := range recs {
			if !failed[r.Addr] {
				kept = append(kept, r)
			}
		}
		recs = kept
	}
	for _, r := range recs {
		was := d.learner.Current(r.Addr)
		d.learner.Store(r)
		switch {
		case r.Tunnel != "" && r.Tunnel == was:
			d.log.Debug("renewed", "addr", r.Addr, "tunnel", r.Tunnel, "baseline", r.Baseline, "rtt", fmtRTT(r.RTT))
		case r.Tunnel != "":
			d.log.Info("learned", "addr", r.Addr, "tunnel", r.Tunnel, "was", was, "baseline", r.Baseline, "outcome", r.Outcome, "rtt", fmtRTT(r.RTT))
		case was != "":
			d.log.Info("unlearned", "addr", r.Addr, "was", was, "baseline", r.Baseline, "outcome", r.Outcome, "rtt", fmtRTT(r.RTT))
		default:
			d.log.Debug("measured", "addr", r.Addr, "baseline", r.Baseline, "outcome", r.Outcome, "rtt", fmtRTT(r.RTT))
		}
	}
}

// learnChange replaces, adds or removes the element of one destination.
type learnChange struct {
	remove, add *nft.Learned
}

// updateLearnedLocked applies changes and returns the addresses that
// failed. One element nft rejects (an address with a stale element for
// another tunnel) fails the whole transaction, so a failed batch is
// retried one destination at a time.
func (d *Daemon) updateLearnedLocked(cfg *config.Config, changes []learnChange) map[netip.Addr]bool {
	if len(changes) == 0 {
		return nil
	}
	apply := func(cs []learnChange) error {
		var remove, add []nft.Learned
		for _, c := range cs {
			if c.remove != nil {
				remove = append(remove, *c.remove)
			}
			if c.add != nil {
				add = append(add, *c.add)
			}
		}
		return d.opts.NFT.UpdateLearned(cfg.NFT.Table, remove, add)
	}
	err := apply(changes)
	if err == nil {
		return nil
	}
	addr := func(c learnChange) netip.Addr {
		if c.add != nil {
			return c.add.Addr
		}
		return c.remove.Addr
	}
	failed := map[netip.Addr]bool{}
	if len(changes) > 1 {
		err = nil
		for _, c := range changes {
			if e := apply([]learnChange{c}); e != nil {
				failed[addr(c)], err = true, e
			}
		}
	} else {
		failed[addr(changes[0])] = true
	}
	if err != nil {
		d.learnStat.LastError = fmt.Sprintf("nft: %d of %d learned destinations not updated: %v", len(failed), len(changes), err)
		d.log.Error("learning: nft update failed", "failed", len(failed), "of", len(changes), "err", err)
	}
	return failed
}

func (d *Daemon) healthyLocked() func(string) bool {
	states := d.states
	return func(n string) bool { return states[n] == health.Healthy }
}

// eligibleLocked reports whether learning may pick a tunnel for addr: a
// public address that is not excluded, not covered by a static preference
// in effect, and carried by at least two healthy tunnels.
func (d *Daemon) eligibleLocked(cfg *config.Config, healthy func(string) bool, addr netip.Addr) bool {
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || engine.Excluded(cfg, addr) {
		return false
	}
	if _, static := engine.Route(cfg, healthy, d.defaults, addr); static {
		return false
	}
	return len(carriers(cfg, healthy, addr)) >= 2
}

// carriers returns the healthy tunnels that carry addr's family.
func carriers(cfg *config.Config, healthy func(string) bool, addr netip.Addr) []config.Tunnel {
	var out []config.Tunnel
	for _, t := range cfg.Tunnels {
		if healthy(t.Name) && t.Carries(addr) {
			out = append(out, t)
		}
	}
	return out
}

func fmtRTT(rtt map[string]health.Millis) string {
	var parts []string
	for n, v := range rtt {
		parts = append(parts, fmt.Sprintf("%s=%s", n, v.D().Round(100*time.Microsecond)))
	}
	sort.Strings(parts)
	return strings.Join(parts, " ")
}
