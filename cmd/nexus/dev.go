package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/phabioo/nexara/internal/hub/app"
	"github.com/phabioo/nexara/internal/hub/demo"
)

// cmdDev implements `nexus dev --demo`: simulated agents, plain HTTP on
// loopback, temporary data.
func cmdDev(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("dev", stderr)
	isDemo := fs.Bool("demo", false, "run with simulated agents and the design's sample data")
	addr := fs.String("addr", "127.0.0.1:8080", "listen address (loopback only)")
	seed := fs.Bool("seed", false, "create the demo operator ("+app.DevOperator+" / "+app.DevPassphrase+") and skip the setup wizard")
	large := fs.Bool("demo-large", false, "give the demo host pi5-media a real install's size (about 900 packages, 31 units, 5 mounts) to test scrolling and paging")
	if code, done := parse(fs, args); done {
		return code
	}
	if !*isDemo {
		fmt.Fprintln(stderr, "nexus dev: --demo is required")
		return exitUsageOrStub
	}
	if _, err := app.LoopbackAddr(*addr); err != nil {
		fmt.Fprintf(stderr, "nexus dev: %v\n", err)
		return exitUsageOrStub
	}
	log := slog.New(slog.NewTextHandler(stderr, nil))
	err := app.RunDev(ctx, app.DevOptions{Addr: *addr, Seed: *seed, Console: stdout, Logger: log, Demo: demo.Options{Large: *large}})
	if err != nil && !(ctx.Err() != nil && errors.Is(err, context.Canceled)) {
		// A signal during startup is a stop request, not a failure.
		log.Error(err.Error())
		return exitFailure
	}
	return exitOK
}
