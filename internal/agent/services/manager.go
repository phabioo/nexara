// Package services defines the agent's service management capability
// (systemd on Linux; Windows services and launchd later).
package services

import (
	"context"

	"github.com/phabioo/nexara/internal/protocol"
)

// Manager lists and restarts system services.
type Manager interface {
	// List returns service units and a summary of listening ports.
	List(ctx context.Context) (protocol.Services, error)
	// Restart restarts one unit. The implementation validates the unit name
	// against a fixed pattern and refuses anything else (never passes it to a
	// shell). It returns once the restart job finished or failed.
	Restart(ctx context.Context, unit string) error
}
