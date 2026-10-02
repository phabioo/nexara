package update

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// fileUID returns the owner of a file.
func fileUID(fi fs.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}

// lockFile takes an exclusive lock so two helpers never install at once. The
// lock is released when the returned function runs or the process ends.
func lockFile(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if err == syscall.EWOULDBLOCK {
			return nil, fmt.Errorf("%w: another update-apply is running", ErrBusy)
		}
		return nil, err
	}
	return func() { f.Close() }, nil
}
