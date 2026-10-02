package update

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"syscall"
	"time"
)

// Command is one external program run by the helper. No shell is involved.
type Command struct {
	Name string
	Args []string
	Env  []string // added to the fixed environment
}

func (c Command) String() string {
	return c.Name + " " + fmt.Sprint(c.Args)
}

// Runner runs a Command and streams its combined output to out. It is the
// seam that keeps apt-get out of tests.
type Runner interface {
	Run(ctx context.Context, c Command, out io.Writer) error
}

// ExecRunner runs commands with os/exec.
type ExecRunner struct{}

// Fixed search path and environment: the helper runs as root and must not be
// steered by the caller's PATH.
var (
	toolDirs = []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"}
	baseEnv  = []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG=C.UTF-8",
		"DEBIAN_FRONTEND=noninteractive",
		"APT_LISTCHANGES_FRONTEND=none",
	}
)

// Run implements Runner. On cancellation the program gets SIGTERM first so
// dpkg can stop cleanly.
func (ExecRunner) Run(ctx context.Context, c Command, out io.Writer) error {
	path, err := lookTool(c.Name)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, path, c.Args...)
	cmd.Env = append(append([]string(nil), baseEnv...), c.Env...)
	cmd.Stdout, cmd.Stderr = out, out
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 30 * time.Second
	return cmd.Run()
}

// lookTool resolves a bare tool name in the fixed directories; an absolute
// path is used as given.
func lookTool(name string) (string, error) {
	if filepath.IsAbs(name) {
		return name, nil
	}
	for _, d := range toolDirs {
		p := filepath.Join(d, name)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s not found in %v", name, toolDirs)
}

// exitCode returns the exit status of a failed command, or -1.
func exitCode(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

// tailBuffer keeps the last max bytes written to it.
type tailBuffer struct {
	max int
	buf []byte
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	if len(t.buf) > 2*t.max {
		t.buf = append([]byte(nil), t.buf[len(t.buf)-t.max:]...)
	}
	return len(p), nil
}

// String returns the last max bytes with dpkg's progress counter
// ("(Reading database ... 35%") and carriage returns removed.
func (t *tailBuffer) String() string {
	b := compactProgress(t.buf)
	if len(b) > t.max {
		b = b[len(b)-t.max:]
		// Do not start in the middle of a line or a UTF-8 sequence.
		if i := bytes.IndexByte(b, '\n'); i >= 0 && i < len(b)-1 {
			b = b[i+1:]
		}
	}
	return string(bytes.ToValidUTF8(b, nil))
}

var progressLine = regexp.MustCompile(`^\(Reading database \.\.\.( \d+%| )?$`)

// compactProgress turns "\r" into line breaks and drops dpkg's database
// progress lines, which would fill the tail with noise.
func compactProgress(b []byte) []byte {
	lines := bytes.Split(bytes.ReplaceAll(b, []byte("\r"), []byte("\n")), []byte("\n"))
	out := lines[:0]
	for _, l := range lines {
		if progressLine.Match(l) {
			continue
		}
		out = append(out, l)
	}
	return bytes.Join(out, []byte("\n"))
}
