//go:build linux

package packages

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/phabioo/nexara/internal/protocol"
)

// killGrace is how long a cancelled command gets after SIGTERM before its
// whole process group receives SIGKILL.
const killGrace = 10 * time.Second

// NewApt returns the apt manager backed by the real system.
func NewApt() Manager {
	return newApt(execRunner{}, fcntlProber{}, osFiles{}, realClock{})
}

// execRunner runs commands with exec.CommandContext, without a shell, in their
// own process group so cancellation reaches dpkg and other children too.
type execRunner struct{}

func (execRunner) Run(ctx context.Context, c Command, onLine func(protocol.JobStream, string)) (int, error) {
	cmd := exec.CommandContext(ctx, c.Path, c.Args...)
	cmd.Env = c.Env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	finished := make(chan struct{})
	defer close(finished)
	cmd.Cancel = func() error {
		pid := cmd.Process.Pid
		err := syscall.Kill(-pid, syscall.SIGTERM)
		go func() {
			t := time.NewTimer(killGrace)
			defer t.Stop()
			select {
			case <-t.C:
				_ = syscall.Kill(-pid, syscall.SIGKILL)
			case <-finished:
			}
		}()
		return err
	}
	cmd.WaitDelay = killGrace + 2*time.Second

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return -1, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return -1, err
	}
	if err := cmd.Start(); err != nil {
		return -1, err
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_ = scanLines(stdout, maxLineBytes, func(l string) { onLine(protocol.StreamStdout, l) })
	}()
	go func() {
		defer wg.Done()
		_ = scanLines(stderr, maxLineBytes, func(l string) { onLine(protocol.StreamStderr, l) })
	}()
	wg.Wait() // all reads must finish before Wait closes the pipes

	werr := cmd.Wait()
	if ctx.Err() != nil {
		return -1, ctx.Err()
	}
	var ee *exec.ExitError
	if errors.As(werr, &ee) {
		return ee.ExitCode(), nil
	}
	if werr != nil {
		return -1, werr
	}
	return 0, nil
}

// fcntlProber probes a lock file with a non-blocking POSIX write-lock attempt
// (the mechanism dpkg and apt use) and releases it immediately.
type fcntlProber struct{}

func (fcntlProber) Locked(path string) (bool, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer f.Close()

	fl := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: 0, Start: 0, Len: 0}
	err = syscall.FcntlFlock(f.Fd(), syscall.F_SETLK, &fl)
	if err != nil {
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EACCES) {
			return true, nil
		}
		return false, err
	}
	fl.Type = syscall.F_UNLCK
	_ = syscall.FcntlFlock(f.Fd(), syscall.F_SETLK, &fl)
	return false, nil
}
