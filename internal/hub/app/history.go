package app

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/phabioo/nexara/internal/config"
	"github.com/phabioo/nexara/internal/hub/demo"
	"github.com/phabioo/nexara/internal/hub/history"
	"github.com/phabioo/nexara/internal/hub/store"
)

// newHistory creates the metrics history service: it listens to the grid's
// live samples, writes minute/hour buckets, enforces retention and prunes the
// audit log. nexus.yaml's storage.history values are the defaults; the
// settings table overrides the hour retention (history.retention_days).
// Start it with svc.Run(runCtx) as a background task and wait for Run before
// closing the store: Run flushes the open minute on shutdown.
func newHistory(st *store.Store, hub history.Subscriber, cfg config.HubConfig, now func() time.Time, log *slog.Logger) *history.Service {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return history.New(history.Options{
		Store:                st,
		Hub:                  hub,
		Logger:               log.With("component", "history"),
		Now:                  now,
		MinuteRetention:      cfg.MinuteRetention(),
		DefaultRetentionDays: cfg.Storage.History.HourDays,
		Location:             cfg.Location(),
	})
}

// newDevHistory is newHistory for `nexus dev --demo`: it first fills the
// temporary database with synthetic history of the demo hosts (unless skip is
// set, which tests use to stay fast), so the History view has data at once.
func newDevHistory(ctx context.Context, st *store.Store, hub *demo.Hub, cfg config.HubConfig, now func() time.Time, log *slog.Logger, skipBackfill bool) (*history.Service, error) {
	if !skipBackfill {
		if err := hub.BackfillHistory(ctx, st, now()); err != nil && ctx.Err() == nil {
			// A stop request during the backfill is not a failure: the hub
			// shuts down right after starting, as it does without a backfill.
			return nil, fmt.Errorf("cannot create the demo history: %w", err)
		}
	}
	return newHistory(st, hub, cfg, now, log), nil
}
