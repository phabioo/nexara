// Command grid-agent is the Nexara Grid Agent that runs on every managed device.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/phabioo/nexara/internal/buildinfo"
)

// Exit codes.
const (
	exitOK          = 0
	exitUsageOrStub = 2 // bad usage
)

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
		return runAgent(rest, stderr)
	case "enroll":
		return runEnroll(rest, stdout, stderr)
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
