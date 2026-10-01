package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// ErrNotRoot is returned by Uninstall when it does not run as root.
var ErrNotRoot = errors.New("nexus uninstall must run as root (try: sudo nexus uninstall)")

// ErrNotPackaged is returned when the hub was not installed from the .deb.
var ErrNotPackaged = errors.New("nexus was not installed from the Debian package, so there is nothing to uninstall automatically")

// ErrCancelled is returned when the operator declines the confirmation.
var ErrCancelled = errors.New("cancelled")

// packageName is the Debian package that ships the hub and its own agent.
const packageName = "nexus"

// CommandRunner runs one external command, writing its output to out. It is
// the seam that keeps Uninstall testable without a real apt.
type CommandRunner func(ctx context.Context, out io.Writer, name string, args ...string) error

// ExecRunner is the production CommandRunner. Commands never read stdin and
// run non-interactively.
func ExecRunner(ctx context.Context, out io.Writer, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout, cmd.Stderr = out, out
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	return cmd.Run()
}

// UninstallOptions configure Uninstall. Only Out is optional-ish: a nil Run
// uses ExecRunner and a nil Geteuid uses os.Geteuid.
type UninstallOptions struct {
	// Purge also deletes configuration, database, CA and keys.
	Purge bool
	// Confirm is asked once, with the warning text, before anything changes.
	// Nil means "yes" (--yes).
	Confirm func(question string) bool
	Out     io.Writer

	Run     CommandRunner
	Geteuid func() int
}

// Uninstall removes the hub package: it stops and disables the services, then
// runs `apt-get remove` (or `purge`). Remote hosts enrolled through the hub are
// not touched.
func Uninstall(ctx context.Context, o UninstallOptions) error {
	run := o.Run
	if run == nil {
		run = ExecRunner
	}
	geteuid := o.Geteuid
	if geteuid == nil {
		geteuid = os.Geteuid
	}
	out := o.Out
	if out == nil {
		out = io.Discard
	}

	if geteuid() != 0 {
		return ErrNotRoot
	}

	var status bytes.Buffer
	if err := run(ctx, &status, "dpkg-query", "-W", "-f=${Status}", packageName); err != nil ||
		!strings.Contains(status.String(), "install ok installed") {
		return ErrNotPackaged
	}

	if o.Confirm != nil && !o.Confirm(uninstallWarning(o.Purge)) {
		return ErrCancelled
	}

	// The agent talks to the hub, so it stops first. A unit that is not loaded
	// (agent never enabled) is not an error.
	for _, unit := range []string{"grid-agent.service", "nexus.service"} {
		fmt.Fprintf(out, "Stopping %s ...\n", unit)
		var buf bytes.Buffer
		if err := run(ctx, &buf, "systemctl", "disable", "--now", unit); err != nil {
			fmt.Fprintf(out, "  (%s: %s)\n", unit, firstLine(buf.String(), err))
		}
	}

	verb := "remove"
	if o.Purge {
		verb = "purge"
	}
	fmt.Fprintf(out, "Running apt-get %s %s ...\n", verb, packageName)
	if err := run(ctx, out, "apt-get", verb, "-y", packageName); err != nil {
		return fmt.Errorf("apt-get %s %s failed: %w", verb, packageName, err)
	}

	if o.Purge {
		fmt.Fprintln(out, "Nexara Nexus was removed together with its configuration, database, CA and keys.")
	} else {
		fmt.Fprintln(out, "Nexara Nexus was removed. Configuration and data are kept in /etc/nexus, /etc/grid-agent and /var/lib/nexus.")
		fmt.Fprintln(out, "Delete them as well with: sudo nexus uninstall --purge (or: sudo apt-get purge nexus)")
	}
	fmt.Fprintln(out, "Hosts enrolled through the hub keep their Grid Agent; remove it there with: sudo systemctl disable --now grid-agent")
	return nil
}

func uninstallWarning(purge bool) string {
	if purge {
		return "This removes Nexara Nexus AND DELETES ALL ITS DATA: configuration, database, certificate authority and keys.\n" +
			"Agents on other hosts can no longer connect and a reinstall starts with a new CA. This cannot be undone. Continue? [y/N] "
	}
	return "This stops and removes Nexara Nexus from this device. Configuration and data are kept. Continue? [y/N] "
}

// firstLine returns the first non-empty line of s, or err's text.
func firstLine(s string, err error) string {
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			return l
		}
	}
	return err.Error()
}
