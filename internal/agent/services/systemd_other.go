//go:build !linux

package services

import (
	"context"

	"github.com/phabioo/nexara/internal/protocol"
)

type unsupported struct{}

// New returns a Manager that reports that services are not supported here.
func New() Manager { return unsupported{} }

func (unsupported) List(context.Context) (protocol.Services, error) {
	return protocol.Services{}, ErrNotSupported
}

func (unsupported) Restart(context.Context, string) error { return ErrNotSupported }
