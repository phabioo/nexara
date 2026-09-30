// Package buildinfo holds version information injected at build time.
//
// Set the variables with -ldflags (the release workflow and scripts/ do this):
//
//	go build -ldflags "\
//	  -X github.com/phabioo/nexara/internal/buildinfo.Version=0.1.0 \
//	  -X github.com/phabioo/nexara/internal/buildinfo.Commit=$(git rev-parse --short HEAD)" ./cmd/nexus
//
// Without ldflags the values are "dev" and "unknown".
package buildinfo

import (
	"fmt"

	"github.com/phabioo/nexara/internal/protocol"
)

// Injected via -ldflags -X; see the package documentation.
var (
	Version = "dev"
	Commit  = "unknown"
)

// String formats the output of the `version` subcommand, e.g.
// "nexus 0.1.0 (commit abc1234, protocol 1)".
func String(binary string) string {
	return fmt.Sprintf("%s %s (commit %s, protocol %d)", binary, Version, Commit, protocol.ProtocolVersion)
}
