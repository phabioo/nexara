// Package packages defines the agent's package management capability (apt
// first; dnf, pacman, winget, brew later behind the same interface).
package packages

import (
	"context"

	"github.com/phabioo/nexara/internal/protocol"
)

// Manager lists packages and runs package jobs.
type Manager interface {
	// List returns installed and available packages and the reboot-required flag.
	List(ctx context.Context) (protocol.Packages, error)

	// Run executes one job to completion and returns its result. Output lines
	// are passed to out as they appear (out is called from one goroutine at a
	// time and must not block for long). The implementation validates the job
	// kind and package name against fixed patterns, waits for the dpkg lock
	// (reporting it as protocol.StreamStatus output), runs commands with
	// argument lists and no shell, and aborts the command when ctx is
	// cancelled, returning a JobDone with OK=false. JobDone.JobID is always
	// copied from the request.
	Run(ctx context.Context, job protocol.JobStart, out func(protocol.JobOutput)) protocol.JobDone
}
