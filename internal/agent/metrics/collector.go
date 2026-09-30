// Package metrics defines the agent's monitoring capability. Platform specific
// implementations live in build-tagged files next to this one.
package metrics

import (
	"context"

	"github.com/phabioo/nexara/internal/protocol"
)

// Collector samples system metrics.
type Collector interface {
	// Collect returns one sample (Timestamp set, UTC). CPU percentages need
	// two measurements, so the first call after creation may report 0 for CPU.
	// Missing optional values (no temperature sensor) are left zero/nil, not
	// reported as errors; an error means the sample as a whole failed.
	Collect(ctx context.Context) (protocol.Metrics, error)
}
