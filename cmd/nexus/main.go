// Command nexus is the Nexara Nexus hub: web UI, API, auth and storage.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/phabioo/nexara/internal/buildinfo"
	"github.com/phabioo/nexara/internal/config"
	"github.com/phabioo/nexara/internal/hub/store"
)

// Exit codes.
const (
	exitOK           = 0
	exitFailure      = 1
	exitUsageOrStub  = 2 // bad usage, or a command that is not implemented yet
	notImplementedMs = "not implemented yet"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

const usage = `Usage: nexus <command> [flags]

Commands:
  serve --config <file>          run the hub
  dev --demo [--addr <addr>]     run the hub with simulated agents (development)
  setup code                     print a new one-time setup code (run locally on the hub)
  user reset                     reset the operator account (run locally on the hub)
  uninstall                      remove the hub from this device
  version                        print version information
`

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsageOrStub
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "serve":
		return cmdServe(rest, stderr)
	case "dev":
		return cmdDev(rest, stderr)
	case "setup":
		return cmdSub("setup", []string{"code"}, rest, stderr)
	case "user":
		return cmdSub("user", []string{"reset"}, rest, stderr)
	case "uninstall":
		fmt.Fprintf(stderr, "nexus uninstall: %s\n", notImplementedMs)
		return exitUsageOrStub
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, buildinfo.String("nexus"))
		return exitOK
	case "help", "--help", "-h":
		fmt.Fprint(stdout, usage)
		return exitOK
	default:
		fmt.Fprintf(stderr, "nexus: unknown command %q\n\n%s", cmd, usage)
		return exitUsageOrStub
	}
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("nexus "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

// parse returns (exit code, true) when the caller should return immediately.
func parse(fs *flag.FlagSet, args []string) (int, bool) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK, true
		}
		return exitUsageOrStub, true
	}
	return 0, false
}

func cmdServe(args []string, stderr io.Writer) int {
	fs := newFlagSet("serve", stderr)
	cfgPath := fs.String("config", config.DefaultHubConfigPath, "path to nexus.yaml")
	if code, done := parse(fs, args); done {
		return code
	}
	log := slog.New(slog.NewTextHandler(stderr, nil))

	cfg, err := config.LoadHub(*cfgPath)
	if err != nil {
		log.Error("cannot load configuration", "err", err)
		return exitFailure
	}
	st, err := store.Open(cfg.Storage.Database)
	if err != nil {
		log.Error("cannot open database", "path", cfg.Storage.Database, "err", err)
		return exitFailure
	}
	defer st.Close()
	version, err := st.SchemaVersion(context.Background())
	if err != nil {
		log.Error("cannot read schema version", "err", err)
		return exitFailure
	}
	log.Info("nexus ready", "version", buildinfo.Version, "hub", cfg.Hub.Name,
		"database", cfg.Storage.Database, "schema_version", version)
	log.Info("HTTP server is not implemented yet, exiting")
	return exitOK
}

func cmdDev(args []string, stderr io.Writer) int {
	fs := newFlagSet("dev", stderr)
	demo := fs.Bool("demo", false, "run with simulated agents and the design's sample data")
	fs.String("addr", "127.0.0.1:8080", "listen address")
	if code, done := parse(fs, args); done {
		return code
	}
	if !*demo {
		fmt.Fprintln(stderr, "nexus dev: --demo is required")
		return exitUsageOrStub
	}
	fmt.Fprintf(stderr, "nexus dev --demo: %s\n", notImplementedMs)
	return exitUsageOrStub
}

// cmdSub handles commands that only have fixed sub-commands (setup code, user reset).
func cmdSub(name string, subs []string, args []string, stderr io.Writer) int {
	if len(args) == 0 || args[0] != subs[0] {
		fmt.Fprintf(stderr, "Usage: nexus %s %s\n", name, subs[0])
		return exitUsageOrStub
	}
	fmt.Fprintf(stderr, "nexus %s %s: %s\n", name, subs[0], notImplementedMs)
	return exitUsageOrStub
}
