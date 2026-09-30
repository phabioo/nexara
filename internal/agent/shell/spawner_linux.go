//go:build linux

package shell

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
)

const (
	defaultPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	defaultLang = "C.UTF-8"
	reapTimeout = 3 * time.Second
)

type linuxSpawner struct {
	username string
	uid, gid uint32
	groups   []uint32
	home     string
	shell    string
	// credential is true when the agent runs as a different user (root) and
	// must switch to the target user; false when it already is that user.
	credential bool
	lang       string
}

// NewSpawner prepares shell sessions for the given user. It refuses root.
func NewSpawner(username string) (Spawner, error) {
	return newSpawner(username, "")
}

// newSpawner is NewSpawner with an optional shell override (used by tests).
func newSpawner(username, shellOverride string) (*linuxSpawner, error) {
	if username == "" || username == "root" {
		return nil, ErrRootRefused
	}
	u, err := user.Lookup(username)
	if err != nil {
		return nil, fmt.Errorf("shell: look up user %q: %w", username, err)
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("shell: bad uid %q: %w", u.Uid, err)
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("shell: bad gid %q: %w", u.Gid, err)
	}
	if uid == 0 {
		return nil, ErrRootRefused
	}
	var groups []uint32
	gids, err := u.GroupIds()
	if err != nil {
		return nil, fmt.Errorf("shell: groups of %q: %w", username, err)
	}
	for _, g := range gids {
		n, err := strconv.ParseUint(g, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("shell: bad group id %q: %w", g, err)
		}
		groups = append(groups, uint32(n))
	}

	s := &linuxSpawner{
		username: username,
		uid:      uint32(uid),
		gid:      uint32(gid),
		groups:   groups,
		home:     u.HomeDir,
		lang:     readLang(),
	}
	if os.Geteuid() != int(uid) {
		if os.Geteuid() != 0 {
			return nil, fmt.Errorf("shell: agent (uid %d) is not root and cannot switch to user %q", os.Geteuid(), username)
		}
		s.credential = true
	}
	s.shell = shellOverride
	if s.shell == "" {
		s.shell = loginShell(username)
	}
	return s, nil
}

func readLang() string {
	f, err := os.Open("/etc/default/locale")
	if err != nil {
		return defaultLang
	}
	defer f.Close()
	if v := parseLang(f); v != "" {
		return v
	}
	return defaultLang
}

func loginShell(username string) string {
	var candidates []string
	if f, err := os.Open("/etc/passwd"); err == nil {
		if sh := passwdShell(f, username); sh != "" {
			candidates = append(candidates, sh)
		}
		f.Close()
	}
	candidates = append(candidates, "/bin/bash", "/bin/sh")
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0 {
			return c
		}
	}
	return "/bin/sh"
}

func (s *linuxSpawner) env() []string {
	return []string{
		"HOME=" + s.home,
		"USER=" + s.username,
		"LOGNAME=" + s.username,
		"SHELL=" + s.shell,
		"PATH=" + defaultPath,
		"TERM=xterm-256color",
		"LANG=" + s.lang,
	}
}

// Open starts a login shell on a new PTY.
func (s *linuxSpawner) Open(cols, rows int) (Session, error) {
	if err := ValidateSize(cols, rows); err != nil {
		return nil, err
	}
	cmd := &exec.Cmd{
		Path: s.shell,
		// A leading dash in argv[0] makes the shell a login shell.
		Args: []string{"-" + filepath.Base(s.shell)},
		Dir:  s.home,
		Env:  s.env(),
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	if s.credential {
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: s.uid, Gid: s.gid, Groups: s.groups}
	}
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
	if err != nil {
		return nil, fmt.Errorf("shell: start %s: %w", s.shell, err)
	}
	sess := &session{ptmx: ptmx, cmd: cmd, done: make(chan struct{})}
	go func() {
		_ = cmd.Wait()
		close(sess.done)
	}()
	return sess, nil
}

type session struct {
	ptmx *os.File
	cmd  *exec.Cmd
	done chan struct{} // closed when the process has been reaped

	closeOnce sync.Once
}

func (s *session) Read(p []byte) (int, error) {
	n, err := s.ptmx.Read(p)
	if err != nil && (errors.Is(err, syscall.EIO) || errors.Is(err, os.ErrClosed)) {
		// EIO is how Linux reports that the slave side is gone.
		err = io.EOF
	}
	return n, err
}

func (s *session) Write(p []byte) (int, error) {
	return s.ptmx.Write(p)
}

func (s *session) Resize(cols, rows int) error {
	if err := ValidateSize(cols, rows); err != nil {
		return err
	}
	return pty.Setsize(s.ptmx, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
}

// Close hangs up the shell's process group, closes the PTY and reaps the
// process, killing it if it ignores SIGHUP. It is idempotent.
func (s *session) Close() error {
	s.closeOnce.Do(func() {
		pgid := s.cmd.Process.Pid // Setsid makes the shell its own group leader
		_ = syscall.Kill(-pgid, syscall.SIGHUP)
		_ = s.ptmx.Close()
		select {
		case <-s.done:
		case <-time.After(reapTimeout):
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
			<-s.done
		}
	})
	<-s.done
	return nil
}
