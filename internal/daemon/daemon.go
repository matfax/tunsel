// Package daemon ties configuration, health monitors and the nftables
// table together.
package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"reflect"
	"sync"
	"syscall"
	"time"

	"github.com/ti-mo/conntrack"

	"github.com/matfax/tunsel/internal/config"
	"github.com/matfax/tunsel/internal/engine"
	"github.com/matfax/tunsel/internal/health"
	"github.com/matfax/tunsel/internal/nft"
	"github.com/matfax/tunsel/internal/status"
)

// ReconcileInterval is how often the daemon checks that its table still
// exists (e.g. after another tool flushed the whole ruleset).
const ReconcileInterval = 15 * time.Second

type Options struct {
	ConfigPath string
	Version    string
	Log        *slog.Logger
	LogLevel   *slog.LevelVar

	// Overridable for tests.
	NFT    Tables
	Health health.Env
	// FlushConntrack deletes conntrack entries whose mark matches
	// mark/mask. Defaults to netlink.
	FlushConntrack func(mark, mask uint32) error
}

// Tables is the nftables side; *nft.Manager in production.
type Tables interface {
	Apply(rs *nft.Ruleset, alsoDelete ...string) error
	Exists(table string) (bool, error)
	Delete(table string) error
	Defaults(table string) (v4, v6 string, err error)
}

type Daemon struct {
	opts    Options
	log     *slog.Logger
	started time.Time

	// running tracks the monitor goroutines of the current generation.
	running sync.WaitGroup

	mu       sync.Mutex
	cfg      *config.Config
	monitors map[string]*health.Monitor
	gen      uint64
	stop     context.CancelFunc // stops the current monitor generation
	// State as of the last successful apply.
	defaults engine.Defaults
	states   map[string]health.State
	applied  *nft.Ruleset
	apply    status.Apply

	events chan health.Event
}

func New(cfg *config.Config, opts Options) *Daemon {
	if opts.NFT == nil {
		opts.NFT = &nft.Manager{}
	}
	if opts.FlushConntrack == nil {
		opts.FlushConntrack = flushConntrack
	}
	return &Daemon{opts: opts, log: opts.Log, cfg: cfg, events: make(chan health.Event, 16)}
}

// Run runs until ctx is done or SIGINT/SIGTERM. SIGHUP reloads the
// configuration file.
func (d *Daemon) Run(ctx context.Context) error {
	d.started = time.Now()
	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	d.adoptInstalledDefaults()
	// The first health round runs before nft is touched, so a restart keeps
	// the previous table until a fresh decision is available.
	if err := d.activate(ctx, d.cfg, nil); err != nil {
		return err
	}
	if err := status.Serve(ctx, d.cfg.Status.Socket, d.report); err != nil {
		return fmt.Errorf("status socket: %w", err)
	}
	d.log.Info("started", "version", d.opts.Version, "table", d.cfg.NFT.Table, "tunnels", len(d.cfg.Tunnels))

	reconcile := time.NewTicker(ReconcileInterval)
	defer reconcile.Stop()
	for {
		select {
		case <-ctx.Done():
			return d.shutdown()
		case <-hup:
			d.reload(ctx)
		case ev := <-d.events:
			d.onEvent(ev)
		case <-reconcile.C:
			d.reconcile()
		}
	}
}

// adoptInstalledDefaults reads the defaults of a table left by a previous
// run, so that a restart with every tunnel down keeps them (fail closed)
// instead of leaving traffic unmarked.
func (d *Daemon) adoptInstalledDefaults() {
	v4, v6, err := d.opts.NFT.Defaults(d.cfg.NFT.Table)
	if err != nil {
		d.log.Warn("reading installed defaults", "err", err)
		return
	}
	byChain := map[string]string{}
	for _, t := range d.cfg.Tunnels {
		byChain[nft.ChainName(t.Name)] = t.Name
	}
	d.defaults = engine.Defaults{V4: byChain[v4], V6: byChain[v6]}
}

// activate switches to cfg (old is the configuration being replaced, nil
// at start). The current monitors are stopped first, so the state that
// unchanged tunnels adopt cannot change underneath. New tunnels get a
// first round, then the ruleset is applied. cfg only takes effect if nft
// accepts it; otherwise the previous generation is resumed.
func (d *Daemon) activate(ctx context.Context, cfg, old *config.Config) error {
	d.mu.Lock()
	prev, stop := d.monitors, d.stop
	d.mu.Unlock()
	if stop != nil {
		stop()
		d.running.Wait()
	}

	monitors := map[string]*health.Monitor{}
	var fresh []*health.Monitor
	for _, t := range cfg.Tunnels {
		m := health.NewMonitor(t, d.opts.Health)
		if o := prev[t.Name]; o != nil && reflect.DeepEqual(o.Tunnel(), t) {
			m.Adopt(o)
		} else {
			fresh = append(fresh, m)
		}
		monitors[t.Name] = m
	}
	var wg sync.WaitGroup
	for _, m := range fresh {
		wg.Add(1)
		go func() { defer wg.Done(); m.RunRound(ctx) }()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}

	var alsoDelete []string
	if old != nil && old.NFT.Table != cfg.NFT.Table {
		alsoDelete = append(alsoDelete, old.NFT.Table)
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	err := d.applyLocked(cfg, monitors, alsoDelete...)
	if err != nil && prev != nil {
		// Keep running on the previous configuration; re-apply it to pick
		// up transitions that happened while its monitors were stopped.
		d.startLocked(ctx, prev)
		d.applyLocked(d.cfg, d.monitors)
		return err
	}
	if err == nil {
		d.startLocked(ctx, monitors)
	}
	return err
}

// startLocked starts a new monitor generation. d.mu must be held.
func (d *Daemon) startLocked(ctx context.Context, monitors map[string]*health.Monitor) {
	d.gen++
	gen := d.gen
	mctx, stop := context.WithCancel(ctx)
	d.stop = stop
	for _, m := range monitors {
		d.running.Add(1)
		go func() {
			defer d.running.Done()
			m.Run(mctx, gen, d.events)
		}()
	}
}

func (d *Daemon) reload(ctx context.Context) {
	cfg, err := config.Load(d.opts.ConfigPath)
	if err != nil {
		d.log.Error("reload failed; keeping current configuration", "err", err)
		return
	}
	d.mu.Lock()
	old := d.cfg
	d.mu.Unlock()
	if err := d.activate(ctx, cfg, old); err != nil {
		d.log.Error("reload failed; keeping current configuration", "err", err)
		return
	}
	if cfg.Status.Socket != old.Status.Socket || cfg.Log.Format != old.Log.Format {
		d.log.Warn("status.socket and log.format changes take effect after a restart")
	}
	if d.opts.LogLevel != nil {
		d.opts.LogLevel.Set(parseLevel(cfg.Log.Level))
	}
	d.log.Info("configuration reloaded")
}

func (d *Daemon) onEvent(ev health.Event) {
	d.mu.Lock()
	defer d.mu.Unlock()
	// Events of a stopped generation are covered by the state comparison
	// in applyLocked once the next generation applies.
	if ev.Gen != d.gen {
		return
	}
	d.applyLocked(d.cfg, d.monitors)
}

// applyLocked computes and installs the ruleset for cfg and monitors and,
// on success, makes them current. Health transitions since the last
// successful apply are logged, and tunnels that became unhealthy get their
// conntrack entries flushed once the ruleset no longer selects them.
// d.mu must be held.
func (d *Daemon) applyLocked(cfg *config.Config, monitors map[string]*health.Monitor, alsoDelete ...string) error {
	states := map[string]health.State{}
	for name, m := range monitors {
		states[name] = m.State()
	}
	rs, defs := engine.Build(cfg, func(n string) bool { return states[n] == health.Healthy }, d.defaults)
	if err := d.opts.NFT.Apply(rs, alsoDelete...); err != nil {
		d.apply = status.Apply{At: time.Now(), Error: err.Error()}
		d.log.Error("nft apply failed", "err", err)
		return err
	}

	for _, t := range cfg.Tunnels {
		before, known := d.states[t.Name]
		now := states[t.Name]
		if known && before == now {
			continue
		}
		d.log.Info("health", "tunnel", t.Name, "state", now.String(), "detail", monitors[t.Name].Snapshot().Errors)
		if now == health.Unhealthy {
			d.flush(cfg, t)
		}
	}
	for _, c := range []struct{ family, old, new string }{{"ipv4", d.defaults.V4, defs.V4}, {"ipv6", d.defaults.V6, defs.V6}} {
		if c.old != c.new {
			d.log.Info("default switched", "family", c.family, "from", c.old, "to", c.new)
		}
	}
	d.cfg, d.monitors, d.states = cfg, monitors, states
	d.defaults, d.applied = defs, rs
	d.apply = status.Apply{At: time.Now()}
	return nil
}

// flush deletes the conntrack entries of a tunnel, so their next packet is
// decided anew.
func (d *Daemon) flush(cfg *config.Config, t config.Tunnel) {
	if !*cfg.Conntrack.FlushOnUnhealthy {
		return
	}
	if err := d.opts.FlushConntrack(t.Mark, cfg.NFT.MarkMask); err != nil {
		d.log.Error("conntrack flush failed", "tunnel", t.Name, "err", err)
		return
	}
	d.log.Info("flushed conntrack entries", "tunnel", t.Name, "mark", fmt.Sprintf("%#x", t.Mark))
}

func (d *Daemon) reconcile() {
	d.mu.Lock()
	defer d.mu.Unlock()
	ok, err := d.opts.NFT.Exists(d.cfg.NFT.Table)
	if err != nil {
		d.log.Error("reconcile: list tables", "err", err)
		return
	}
	if !ok || d.apply.Error != "" {
		d.log.Warn("reconcile: re-applying table", "missing", !ok)
		d.applyLocked(d.cfg, d.monitors)
	}
}

func (d *Daemon) shutdown() error {
	d.mu.Lock()
	stop := d.stop
	d.mu.Unlock()
	if stop != nil {
		stop()
		d.running.Wait()
	}
	if d.cfg.NFT.CleanupOnExit {
		if err := d.opts.NFT.Delete(d.cfg.NFT.Table); err != nil {
			d.log.Error("cleanup: delete table", "err", err)
			return err
		}
		d.log.Info("removed table on exit", "table", d.cfg.NFT.Table)
	}
	d.log.Info("stopped")
	return nil
}

func (d *Daemon) report() status.Report {
	d.mu.Lock()
	defer d.mu.Unlock()
	r := status.Report{
		Version: d.opts.Version, Config: d.opts.ConfigPath, Table: d.cfg.NFT.Table,
		StartedAt: d.started, Default4: d.defaults.V4, Default6: d.defaults.V6,
		Apply: d.apply, Sizes: map[string]int{},
	}
	for _, t := range d.cfg.Tunnels {
		var snap health.Snapshot
		if m := d.monitors[t.Name]; m != nil {
			snap = m.Snapshot()
		}
		r.Tunnels = append(r.Tunnels, status.Tunnel{Name: t.Name, Mark: t.Mark, Snapshot: snap})
	}
	if rs := d.applied; rs != nil {
		r.Sizes["exclude4"], r.Sizes["exclude6"] = len(rs.Exclude4), len(rs.Exclude6)
		r.Sizes["static4"], r.Sizes["static6"] = len(rs.Static4), len(rs.Static6)
	}
	return r
}

func flushConntrack(mark, mask uint32) error {
	c, err := conntrack.Dial(nil)
	if err != nil {
		return err
	}
	defer c.Close()
	return c.FlushFilter(conntrack.NewFilter().Mark(mark).MarkMask(mask))
}

func parseLevel(s string) slog.Level {
	var l slog.Level
	l.UnmarshalText([]byte(s))
	return l
}

// NewLogger builds the logger described by the log section.
func NewLogger(c config.Log) (*slog.Logger, *slog.LevelVar) {
	lv := new(slog.LevelVar)
	lv.Set(parseLevel(c.Level))
	o := &slog.HandlerOptions{Level: lv}
	if c.Format == "json" {
		return slog.New(slog.NewJSONHandler(os.Stderr, o)), lv
	}
	return slog.New(slog.NewTextHandler(os.Stderr, o)), lv
}
