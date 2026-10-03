//go:build !unix

package update

// openFlags: the root helper only runs on Linux; other platforms build and test.
const openFlags = 0
