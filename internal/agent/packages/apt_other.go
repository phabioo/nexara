//go:build !linux

package packages

import (
	"context"

	"github.com/phabioo/nexara/internal/protocol"
)

// NewApt returns a Manager that reports ErrNotSupported; apt exists on Linux only.
func NewApt() Manager { return unsupported{} }

type unsupported struct{}

func (unsupported) List(context.Context) (protocol.Packages, error) {
	return protocol.Packages{}, ErrNotSupported
}

func (unsupported) Search(context.Context, string) ([]protocol.Package, error) {
	return nil, ErrNotSupported
}

func (unsupported) Run(_ context.Context, job protocol.JobStart, _ func(protocol.JobOutput)) protocol.JobDone {
	return protocol.JobDone{JobID: job.JobID, ExitCode: -1, Error: ErrNotSupported.Error()}
}
