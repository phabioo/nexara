//go:build !linux

package shell

// NewSpawner is not supported outside Linux yet (Windows ConPTY follows in v1.0).
func NewSpawner(user string) (Spawner, error) {
	return nil, ErrNotSupported
}
