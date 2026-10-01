package main

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/phabioo/nexara/internal/hub/app"
)

// uninstall is replaced in tests.
var uninstall = app.Uninstall

// cmdUninstall implements `nexus uninstall [--purge] [--yes]`.
func cmdUninstall(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := newFlagSet("uninstall", stderr)
	purge := fs.Bool("purge", false, "also delete configuration, database, CA and keys (cannot be undone)")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	if code, done := parse(fs, args); done {
		return code
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "nexus uninstall: unexpected argument %q\n", fs.Arg(0))
		return exitUsageOrStub
	}
	opts := app.UninstallOptions{Purge: *purge, Out: stdout}
	if !*yes {
		opts.Confirm = func(q string) bool { return confirm(stdin, stdout, q) }
	}
	if err := uninstall(ctx, opts); err != nil {
		fmt.Fprintf(stderr, "nexus uninstall: %v\n", err)
		if errors.Is(err, app.ErrNotPackaged) {
			fmt.Fprintln(stderr, "If you installed manually, stop the service and delete the binaries, /etc/nexus and /var/lib/nexus yourself.")
		}
		return exitFailure
	}
	return exitOK
}
