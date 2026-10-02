package app

import (
	"context"
	"time"

	"github.com/phabioo/nexara/internal/hub/grid"
)

// Certificate lifetimes and renewal (decision #47), in one place:
//
//   - Server certificate (browsers and agents share it): issued for one year
//     with every name and IP of the device; certManager.Run re-issues it every
//     DefaultCertCheckInterval when it is within 30 days of expiry (pki.RenewBefore,
//     EnsureServerCert) or when the names, IPs or agent address change. The
//     listener reloads the files on the next handshake, no restart.
//   - Agent certificates: one year; renewed over the agent's mTLS WebSocket within
//     30 days of expiry (grid.Grid: on connect, by the agent's own check and by
//     the sweep below). The protocol and the grace window are documented in
//     internal/hub/grid/renew.go.
//   - CA: five years (decision #45); replacing it is out of scope for v0.2.

// agentCertSweeper is the part of the grid the daily sweep needs.
type agentCertSweeper interface {
	CheckRenewals(ctx context.Context)
}

var _ agentCertSweeper = (*grid.Grid)(nil)

// runAgentCertRenewals asks every connected agent whose certificate is within
// the renewal window to renew, once per interval until ctx ends. It catches
// agents that stay connected for months (the on-connect check never fires for
// them) and logs agents whose certificate is about to expire.
func runAgentCertRenewals(ctx context.Context, g agentCertSweeper, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultCertCheckInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			g.CheckRenewals(ctx)
		}
	}
}
