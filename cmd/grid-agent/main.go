// Command grid-agent is the Nexara Grid Agent that runs on every managed device.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/phabioo/nexara/internal/buildinfo"
	"github.com/phabioo/nexara/internal/config"
)

// Exit codes.
const (
	exitOK          = 0
	exitUsageOrStub = 2 // bad usage, or a command that is not implemented yet
)

const notImplemented = "not implemented yet"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

const usage = `Usage: grid-agent <command> [flags]

Commands:
  run --config <file>               run the agent (normally started by systemd)
  enroll --hub <addr> --token <t>   pair this device with a hub using a one-time token
  version                           print version information
`

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsageOrStub
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "run":
		fs := newFlagSet("run", stderr)
		fs.String("config", config.DefaultAgentConfigPath, "path to agent.yaml")
		return stub(fs, rest, "run", stderr)
	case "enroll":
		fs := newFlagSet("enroll", stderr)
		hub := fs.String("hub", "", "hub address, e.g. frpi5.local:8443")
		token := fs.String("token", "", "one-time enrollment token")
		if code, done := parse(fs, rest); done {
			return code
		}
		if *hub == "" || *token == "" {
			fmt.Fprintln(stderr, "grid-agent enroll: --hub and --token are required")
			return exitUsageOrStub
		}
		fmt.Fprintf(stderr, "grid-agent enroll: %s\n", notImplemented)
		return exitUsageOrStub
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, buildinfo.String("grid-agent"))
		return exitOK
	case "help", "--help", "-h":
		fmt.Fprint(stdout, usage)
		return exitOK
	default:
		fmt.Fprintf(stderr, "grid-agent: unknown command %q\n\n%s", cmd, usage)
		return exitUsageOrStub
	}
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("grid-agent "+name, flag.ContinueOnError)
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

func stub(fs *flag.FlagSet, args []string, name string, stderr io.Writer) int {
	if code, done := parse(fs, args); done {
		return code
	}
	fmt.Fprintf(stderr, "grid-agent %s: %s\n", name, notImplemented)
	return exitUsageOrStub
}
