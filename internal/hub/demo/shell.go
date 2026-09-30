package demo

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/protocol"
)

// OpenShell implements grid.Hub with a scripted fake terminal.
func (h *Hub) OpenShell(_ context.Context, _ grid.Actor, id grid.HostID, cols, rows int) (grid.ShellSession, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	hst, err := h.usable(id, protocol.CapShell)
	if err != nil {
		return nil, err
	}
	s := &fakeShell{
		host: hst.info.Name, addr: hst.info.Address, kernel: hst.info.Kernel,
		cols: cols, rows: rows,
		status: func() (uint64, [3]float64, float64) {
			h.mu.Lock()
			defer h.mu.Unlock()
			if hst.metrics == nil {
				return 0, [3]float64{}, 0
			}
			return hst.metrics.UptimeSeconds, hst.metrics.Load, *hst.metrics.TempC
		},
		clock: func() string { return h.now().Format("15:04:05") },
	}
	s.cond = sync.NewCond(&s.mu)
	s.prompt()
	return s, nil
}

// fakeShell implements grid.ShellSession. Output is buffered until Read.
type fakeShell struct {
	host, addr, kernel string
	status             func() (uint64, [3]float64, float64)
	clock              func() string

	mu     sync.Mutex
	cond   *sync.Cond
	out    []byte
	line   []byte
	esc    int  // 0 none, 1 after ESC, 2 inside CSI
	closed bool // Close called
	exited bool // shell exited: EOF after the buffer drains
	cols   int
	rows   int
}

func (s *fakeShell) printf(format string, a ...any) {
	s.out = append(s.out, fmt.Sprintf(format, a...)...)
}

func (s *fakeShell) prompt() { s.printf("pi@%s:~ $ ", s.host) }

// Read implements io.Reader; it blocks until output is available.
func (s *fakeShell) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.out) == 0 {
		if s.closed || s.exited {
			return 0, io.EOF
		}
		s.cond.Wait()
	}
	n := copy(p, s.out)
	s.out = s.out[n:]
	return n, nil
}

// Write implements io.Writer: the keyboard input of the terminal.
func (s *fakeShell) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.exited {
		return 0, io.ErrClosedPipe
	}
	for _, b := range p {
		s.key(b)
		if s.exited {
			break
		}
	}
	s.cond.Broadcast()
	return len(p), nil
}

// key handles one input byte. Callers hold s.mu.
func (s *fakeShell) key(b byte) {
	switch s.esc {
	case 1:
		if b == '[' || b == 'O' {
			s.esc = 2
		} else {
			s.esc = 0
		}
		return
	case 2:
		if b >= 0x40 && b <= 0x7e {
			s.esc = 0
		}
		return
	}
	switch {
	case b == 0x1b:
		s.esc = 1
	case b == '\r' || b == '\n':
		s.printf("\r\n")
		cmd := strings.TrimSpace(string(s.line))
		s.line = s.line[:0]
		s.run(cmd)
		if !s.exited {
			s.prompt()
		}
	case b == 0x7f || b == 0x08:
		if len(s.line) > 0 {
			s.line = s.line[:len(s.line)-1]
			s.printf("\b \b")
		}
	case b == 0x03:
		s.line = s.line[:0]
		s.printf("^C\r\n")
		s.prompt()
	case b >= 0x20:
		s.line = append(s.line, b)
		s.out = append(s.out, b)
	}
}

func (s *fakeShell) run(cmd string) {
	up, load, temp := s.status()
	switch cmd {
	case "":
	case "help":
		s.printf("Available: help, uptime, hostname, whoami, ls, vcgencmd measure_temp, clear, exit\r\n")
	case "uptime":
		d, hr, m := up/86400, up%86400/3600, up%3600/60
		s.printf(" %s up %d days, %2d:%02d,  1 user,  load average: %.2f, %.2f, %.2f\r\n", s.clock(), d, hr, m, load[0], load[1], load[2])
	case "vcgencmd measure_temp":
		s.printf("temp=%.1f'C\r\n", temp)
	case "hostname":
		s.printf("%s\r\n", s.host)
	case "whoami":
		s.printf("pi\r\n")
	case "ls":
		s.printf("Desktop  Documents  Downloads  media  scripts\r\n")
	case "clear":
		s.printf("\x1b[2J\x1b[H")
	case "exit", "logout":
		s.printf("logout\r\n")
		s.exited = true
	default:
		name := cmd
		if i := strings.IndexByte(name, ' '); i >= 0 {
			name = name[:i]
		}
		s.printf("bash: %s: command not found\r\n", name)
	}
}

// Resize implements grid.ShellSession.
func (s *fakeShell) Resize(cols, rows int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return io.ErrClosedPipe
	}
	s.cols, s.rows = cols, rows
	return nil
}

// Close implements io.Closer.
func (s *fakeShell) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.cond.Broadcast()
	return nil
}
