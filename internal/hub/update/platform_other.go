//go:build !linux

package update

import "io/fs"

// The root helper only runs on Linux (apt); these stubs keep the package
// buildable elsewhere.

func fileUID(fs.FileInfo) (uint32, bool) { return 0, false }

func lockFile(string) (func(), error) { return func() {}, nil }
