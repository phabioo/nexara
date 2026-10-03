package grid

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/protocol"
)

// shellLimits bound the output buffered for a browser that reads slowly.
type shellLimits struct {
	// soft is the buffered size above which the stall timer runs; the session
	// is dropped if the buffer stays above it for stall.
	soft  int
	stall time.Duration
	// hard is the buffered size at which the session is dropped immediately.
	hard int
}

func defaultShellLimits() shellLimits {
	return shellLimits{soft: 256 << 10, stall: 30 * time.Second, hard: 4 << 20}
}

// shellSession implements ShellSession on top of the agent connection.
type shellSession struct {
	g      *Grid
	c      *agentConn
	id     string
	host   string // host name, for audit
	user   string // operator ID, for audit
	opened time.Time

	mu          sync.Mutex
	chunks      [][]byte
	size        int
	stallTimer  *time.Timer
	remoteEnded bool // the agent ended the session or disconnected: Read drains, then io.EOF
	localClosed bool // Close was called or the session was dropped: Read fails at once
	notify      chan struct{}

	finishOnce sync.Once
}

var _ ShellSession = (*shellSession)(nil)

// OpenShell implements Hub.
func (g *Grid) OpenShell(ctx context.Context, actor Actor, id HostID, cols, rows int) (ShellSession, error) {
	st, c, err := g.connFor(id, protocol.CapShell)
	if err != nil {
		return nil, err
	}
	if cols <= 0 {
		cols = 80
	}
	if rows <= 0 {
		rows = 24
	}
	cols, rows = min(cols, 1000), min(rows, 1000)

	s := &shellSession{
		g: g, c: c, id: store.NewID(), host: st.name, user: actor.Operator,
		opened: g.now(), notify: make(chan struct{}, 1),
	}
	if err := g.registerShell(st, c, s); err != nil {
		return nil, err
	}
	env, err := c.request(ctx, protocol.TypeShellOpen, protocol.ShellOpen{SessionID: s.id, Cols: cols, Rows: rows}, g.to.shellOpen)
	if err == nil {
		err = resultErr(env, "shell open")
	}
	if err != nil {
		c.removeShell(s.id)
		g.audit(store.AuditEntry{User: actor.Operator, Host: st.name, Action: "shell.open", Detail: err.Error(), Result: store.AuditError})
		return nil, err
	}
	g.audit(store.AuditEntry{User: actor.Operator, Host: st.name, Action: "shell.open", Detail: "session " + s.id, Result: store.AuditOK})
	return s, nil
}

// registerShell adds the session to the connection under g.mu with the
// capability checked again: SetCapability switches the shell off under the same
// lock and then ends the registered sessions, so a session either sees the
// switch here or is ended by it (security review C-05).
func (g *Grid) registerShell(st *hostState, c *agentConn, s *shellSession) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	switch {
	case st.conn != c || !st.online:
		return ErrHostOffline
	case !st.capEnabled(protocol.CapShell):
		return ErrCapabilityDisabled
	case !c.addShell(s):
		return ErrHostOffline
	}
	return nil
}

func (s *shellSession) signal() {
	select {
	case s.notify <- struct{}{}:
	default:
	}
}

// deliver queues terminal output from the agent. It never blocks the read loop.
func (s *shellSession) deliver(data []byte) {
	if len(data) == 0 {
		return
	}
	lim := s.g.shellLim
	s.mu.Lock()
	if s.localClosed || s.remoteEnded {
		s.mu.Unlock()
		return
	}
	s.chunks = append(s.chunks, data)
	s.size += len(data)
	drop := ""
	switch {
	case s.size > lim.hard:
		drop = "output buffer full"
	case s.size > lim.soft && s.stallTimer == nil:
		s.stallTimer = time.AfterFunc(lim.stall, func() { s.endLocal("browser not reading") })
	}
	s.mu.Unlock()
	s.signal()
	if drop != "" {
		go s.endLocal(drop)
	}
}

// Read implements io.Reader. It returns io.EOF after the agent ended the
// session (or disconnected) and all buffered output was read, and
// io.ErrClosedPipe after the session was closed or dropped on the hub side.
func (s *shellSession) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		s.mu.Lock()
		switch {
		case s.localClosed:
			s.mu.Unlock()
			return 0, io.ErrClosedPipe
		case len(s.chunks) > 0:
			n := copy(p, s.chunks[0])
			if n == len(s.chunks[0]) {
				s.chunks[0] = nil
				s.chunks = s.chunks[1:]
			} else {
				s.chunks[0] = s.chunks[0][n:]
			}
			s.size -= n
			if s.size <= s.g.shellLim.soft && s.stallTimer != nil {
				s.stallTimer.Stop()
				s.stallTimer = nil
			}
			s.mu.Unlock()
			return n, nil
		case s.remoteEnded:
			s.mu.Unlock()
			return 0, io.EOF
		}
		s.mu.Unlock()
		<-s.notify
	}
}

func (s *shellSession) closedForWrite() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.localClosed || s.remoteEnded
}

// Write implements io.Writer: keyboard input, split into chunks of at most protocol.MaxShellChunk.
func (s *shellSession) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		if s.closedForWrite() {
			return written, io.ErrClosedPipe
		}
		n := min(len(p), protocol.MaxShellChunk)
		if err := s.c.send(protocol.TypeShellData, "", protocol.ShellData{SessionID: s.id, Data: p[:n]}); err != nil {
			return written, fmt.Errorf("grid: shell write: %w", err)
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

// Resize implements ShellSession.
func (s *shellSession) Resize(cols, rows int) error {
	if cols <= 0 || rows <= 0 || cols > 1000 || rows > 1000 {
		return fmt.Errorf("%w: terminal size %dx%d", ErrInvalidArgument, cols, rows)
	}
	if s.closedForWrite() {
		return io.ErrClosedPipe
	}
	return s.c.send(protocol.TypeShellResize, "", protocol.ShellResize{SessionID: s.id, Cols: cols, Rows: rows})
}

// Close implements io.Closer and ends the remote shell. It is idempotent.
func (s *shellSession) Close() error {
	s.endLocal("closed by user")
	return nil
}

// endLocal ends the session on the hub's initiative.
func (s *shellSession) endLocal(reason string) {
	s.mu.Lock()
	already, remote := s.localClosed, s.remoteEnded
	s.localClosed = true
	s.chunks, s.size = nil, 0
	if s.stallTimer != nil {
		s.stallTimer.Stop()
		s.stallTimer = nil
	}
	s.mu.Unlock()
	s.signal()
	if !already && !remote {
		_ = s.c.send(protocol.TypeShellClose, "", protocol.ShellClose{SessionID: s.id, Reason: reason})
	}
	s.finish(reason)
}

// remoteClosed ends the session because the agent closed it or disconnected.
func (s *shellSession) remoteClosed(reason string) {
	s.mu.Lock()
	s.remoteEnded = true
	if s.stallTimer != nil {
		s.stallTimer.Stop()
		s.stallTimer = nil
	}
	s.mu.Unlock()
	s.signal()
	s.finish(reason)
}

// finish unregisters the session and writes the audit entry, once.
func (s *shellSession) finish(reason string) {
	s.finishOnce.Do(func() {
		s.c.removeShell(s.id)
		dur := s.g.now().Sub(s.opened).Round(time.Second)
		detail := fmt.Sprintf("session %s, duration %s", s.id, dur)
		if reason != "" {
			detail += ", " + reason
		}
		s.g.audit(store.AuditEntry{User: s.user, Host: s.host, Action: "shell.close", Detail: detail, Result: store.AuditOK})
	})
}
