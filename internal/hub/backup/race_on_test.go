//go:build race

package backup

// The race detector makes the large tests an order of magnitude slower, so
// they run with smaller data there (the plain `go test` run uses full size).
const raceEnabled = true
