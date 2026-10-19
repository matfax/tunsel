// Command tunsel steers new connections between VPN tunnels by health.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/matfax/tunsel/internal/config"
	"github.com/matfax/tunsel/internal/daemon"
	"github.com/matfax/tunsel/internal/status"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const defaultConfig = "/etc/tunsel/config.yaml"

const usage = `usage: tunsel <command> [flags]

commands:
  run      run the daemon (-config path)
  check    validate a configuration file (-config path)
  status   show daemon state (-socket path, -json, -flows, -history)
  version  print the version

A configuration file whose name ends in .yaml or .yml is YAML; any other
name is read as UCI (e.g. /etc/config/tunsel on OpenWrt).
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "run":
		err = run(args)
	case "check":
		err = check(args)
	case "status":
		err = showStatus(args)
	case "version":
		fmt.Println(version)
	case "-h", "-help", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "tunsel:", err)
		os.Exit(1)
	}
}

func configFlag(fs *flag.FlagSet) *string {
	return fs.String("config", defaultConfig, "configuration file")
}

func run(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	path := configFlag(fs)
	fs.Parse(args)
	// An invalid config refuses to start and leaves any existing table alone.
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	log, level := daemon.NewLogger(cfg.Log)
	d := daemon.New(cfg, daemon.Options{ConfigPath: *path, Version: version, Log: log, LogLevel: level})
	return d.Run(context.Background())
}

func check(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	path := configFlag(fs)
	fs.Parse(args)
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	fmt.Printf("%s: ok (%d tunnels, %d exclude, %d static_pref)\n", *path, len(cfg.Tunnels), len(cfg.Exclude), len(cfg.StaticPref))
	return nil
}

func showStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	socket := fs.String("socket", config.DefaultSocket, "status socket")
	asJSON := fs.Bool("json", false, "print JSON")
	var req status.Request
	fs.BoolVar(&req.Flows, "flows", false, "include the conntrack flows per tunnel")
	fs.BoolVar(&req.History, "history", false, "include the RTT history per health target")
	fs.Parse(args)
	r, err := status.Fetch(*socket, req)
	if err != nil {
		return err
	}
	if *asJSON {
		e := json.NewEncoder(os.Stdout)
		e.SetIndent("", "  ")
		return e.Encode(r)
	}
	r.Render(os.Stdout)
	return nil
}
