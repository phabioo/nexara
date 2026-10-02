package main

import (
	"context"
	"errors"
	"io"
	"log/slog"

	"github.com/phabioo/nexara/internal/config"
	"github.com/phabioo/nexara/internal/hub/app"
)

// cmdServe implements `nexus serve`: the production hub, TLS on hub.listen.
func cmdServe(ctx context.Context, args []string, stderr io.Writer) int {
	fs := newFlagSet("serve", stderr)
	cfgPath := fs.String("config", config.DefaultHubConfigPath, "path to nexus.yaml")
	adminSocket := fs.String("admin-socket", app.DefaultAdminSocket, "Unix socket for `nexus setup code` and `nexus user reset` (empty disables it)")
	if code, done := parse(fs, args); done {
		return code
	}
	log := slog.New(slog.NewTextHandler(stderr, nil))
	err := app.Serve(ctx, app.ServeOptions{ConfigPath: *cfgPath, AdminSocket: *adminSocket, Logger: log})
	if errors.Is(err, app.ErrRestart) {
		return exitRestart
	}
	if err != nil && !(ctx.Err() != nil && errors.Is(err, context.Canceled)) {
		// A signal during startup is a stop request, not a failure.
		log.Error(err.Error())
		return exitFailure
	}
	return exitOK
}
