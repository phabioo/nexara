package app

import (
	"context"
	"errors"

	"github.com/phabioo/nexara/internal/hub/grid"
)

// onlineSource is the part of grid.Hub waitOnline needs.
type onlineSource interface {
	Host(id grid.HostID) (grid.HostInfo, bool)
	Subscribe(ctx context.Context) <-chan grid.Event
}

var errSubscriptionClosed = errors.New("app: event subscription closed while waiting for the agent")

// waitOnline returns the enroll.Options.WaitOnline hook: it blocks until the
// host's agent is connected or ctx ends. It subscribes before looking at the
// current state, so a connection that happens in between is not missed.
func waitOnline(src onlineSource) func(ctx context.Context, id grid.HostID) error {
	return func(ctx context.Context, id grid.HostID) error {
		sctx, cancel := context.WithCancel(ctx)
		defer cancel()
		events := src.Subscribe(sctx)
		if h, ok := src.Host(id); ok && h.Online {
			return nil
		}
		for {
			select {
			case ev, ok := <-events:
				if !ok {
					// The hub closed the subscription: it is shutting down.
					if err := ctx.Err(); err != nil {
						return err
					}
					return errSubscriptionClosed
				}
				if ev.Kind == grid.EventHostOnline && ev.Host == id {
					return nil
				}
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}
