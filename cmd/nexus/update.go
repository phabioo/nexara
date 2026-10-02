package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/phabioo/nexara/internal/hub/app"
	"github.com/phabioo/nexara/internal/hub/update"
)

// Replaced in tests.
var (
	updateApply = update.Apply
	geteuid     = os.Geteuid
)

// cmdUpdateApply implements `nexus update-apply`, the root helper that
// nexus-update.service runs when the hub drops an install request (decision
// #50). It is not meant to be typed by hand, except for --allow-downgrade and
// --no-rollback, which only an operator on the console may choose.
func cmdUpdateApply(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("update-apply", stderr)
	dataDir := fs.String("data-dir", update.DefaultDataDir, "hub data directory (holds updates/request.json)")
	stateDir := fs.String("state-dir", update.DefaultStateDir, "root-owned directory for rollback material")
	socket := fs.String("admin-socket", app.DefaultAdminSocket, "admin socket of the hub, used for the health check")
	noRollback := fs.Bool("no-rollback", false, "update even if no verified copy of the running version exists to fall back to")
	downgrade := fs.Bool("allow-downgrade", false, "install a version that is not newer than the running one")
	health := fs.Duration("health-timeout", 60*time.Second, "how long the new hub may take to report its version")
	if code, done := parse(fs, args); done {
		return code
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "nexus update-apply: unexpected argument %q\n", fs.Arg(0))
		return exitUsageOrStub
	}
	if geteuid() != 0 {
		fmt.Fprintln(stderr, "nexus update-apply: must run as root (it installs the package); it is started by nexus-update.service")
		return exitFailure
	}
	res, err := updateApply(ctx, update.ApplyOptions{
		DataDir: *dataDir, StateDir: *stateDir,
		NoRollback: *noRollback, AllowDowngrade: *downgrade,
		Health: update.AdminHealth(*socket), HealthTimeout: *health,
		Log: stdout,
	})
	switch {
	case errors.Is(err, update.ErrNoRequest):
		fmt.Fprintln(stdout, "nexus update-apply: no update request pending")
		return exitOK
	case err != nil:
		fmt.Fprintf(stderr, "nexus update-apply: %v\n", err)
		return exitFailure
	}
	if res.Status != update.StatusOK {
		fmt.Fprintf(stderr, "nexus update-apply: %s: %s\n", res.Status, res.Message)
		return exitFailure
	}
	fmt.Fprintf(stdout, "nexus update-apply: %s\n", res.Message)
	return exitOK
}
