package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/phabioo/nexara/internal/hub/app"
)

// cmdDev implements `nexus dev --demo`: simulated agents, plain HTTP on
// loopback, temporary data.
func cmdDev(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("dev", stderr)
	demo := fs.Bool("demo", false, "run with simulated agents and the design's sample data")
	addr := fs.String("addr", "127.0.0.1:8080", "listen address (loopback only)")
	seed := fs.Bool("seed", false, "create the demo operator ("+app.DevOperator+" / "+app.DevPassphrase+") and skip the setup wizard")
	if code, done := parse(fs, args); done {
		return code
	}
	if !*demo {
		fmt.Fprintln(stderr, "nexus dev: --demo is required")
		return exitUsageOrStub
	}
	if _, err := app.LoopbackAddr(*addr); err != nil {
		fmt.Fprintf(stderr, "nexus dev: %v\n", err)
		return exitUsageOrStub
	}
	log := slog.New(slog.NewTextHandler(stderr, nil))
	err := app.RunDev(ctx, app.DevOptions{Addr: *addr, Seed: *seed, Console: stdout, Logger: log})
	if err != nil && !(ctx.Err() != nil && errors.Is(err, context.Canceled)) {
		// A signal during startup is a stop request, not a failure.
		log.Error(err.Error())
		return exitFailure
	}
	return exitOK
}
