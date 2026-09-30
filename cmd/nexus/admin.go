package main

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/phabioo/nexara/internal/hub/app"
	"github.com/phabioo/nexara/internal/hub/setup"
)

// adminCall is replaced in tests.
var adminCall = app.CallAdmin

// cmdSetup implements `nexus setup code`.
func cmdSetup(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "code" {
		fmt.Fprintln(stderr, "Usage: nexus setup code [--admin-socket <path>]")
		return exitUsageOrStub
	}
	fs := newFlagSet("setup code", stderr)
	socket := fs.String("admin-socket", app.DefaultAdminSocket, "admin Unix socket of the running hub")
	if code, done := parse(fs, args[1:]); done {
		return code
	}
	resp, err := adminCall(*socket, setup.CmdSetupCode)
	if err != nil {
		fmt.Fprintf(stderr, "nexus setup code: %v\n", err)
		return exitFailure
	}
	fmt.Fprintln(stdout, resp.Message)
	return exitOK
}

// cmdUser implements `nexus user reset`.
func cmdUser(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "reset" {
		fmt.Fprintln(stderr, "Usage: nexus user reset [--yes] [--admin-socket <path>]")
		return exitUsageOrStub
	}
	fs := newFlagSet("user reset", stderr)
	socket := fs.String("admin-socket", app.DefaultAdminSocket, "admin Unix socket of the running hub")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	if code, done := parse(fs, args[1:]); done {
		return code
	}
	if !*yes && !confirm(stdin, stdout, "This deletes the operator account and returns the hub to setup mode. Continue? [y/N] ") {
		fmt.Fprintln(stderr, "nexus user reset: cancelled")
		return exitFailure
	}
	resp, err := adminCall(*socket, setup.CmdUserReset)
	if err != nil {
		fmt.Fprintf(stderr, "nexus user reset: %v\n", err)
		return exitFailure
	}
	fmt.Fprintln(stdout, resp.Message)
	return exitOK
}

// confirm asks a yes/no question; anything but y/yes (or no input) is a no.
func confirm(in io.Reader, out io.Writer, question string) bool {
	fmt.Fprint(out, question)
	line, _ := bufio.NewReader(in).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	return false
}
