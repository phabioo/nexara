// Command nexus is the Nexara Nexus hub: web UI, API, auth and storage.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/phabioo/nexara/internal/buildinfo"
)

// Exit codes.
const (
	exitOK          = 0
	exitFailure     = 1
	exitUsageOrStub = 2 // bad usage
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := runContext(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

const usage = `Usage: nexus <command> [flags]

Commands:
  serve --config <file>               run the hub [--admin-socket <path>]
  dev --demo [--addr <addr>] [--seed] run the hub with simulated agents (development)
  setup code                          print a new one-time setup code (run locally on the hub)
  user reset                          reset the operator account (run locally on the hub)
  user unlock                         clear login lockouts (run locally on the hub)
  uninstall [--purge] [--yes]         remove the hub package (--purge also deletes data, CA and keys)
  version                             print version information
`

// run executes a command that does not wait for a signal (tests, version, help).
func run(args []string, stdout, stderr io.Writer) int {
	return runContext(context.Background(), args, os.Stdin, stdout, stderr)
}

// runContext executes one command; serve and dev run until ctx is cancelled.
func runContext(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsageOrStub
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "serve":
		return cmdServe(ctx, rest, stderr)
	case "dev":
		return cmdDev(ctx, rest, stdout, stderr)
	case "setup":
		return cmdSetup(rest, stdout, stderr)
	case "user":
		return cmdUser(rest, stdin, stdout, stderr)
	case "uninstall":
		return cmdUninstall(ctx, rest, stdin, stdout, stderr)
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
