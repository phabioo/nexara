package shell

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
)

// Terminal size limits accepted by Open and Resize.
const (
	MinSize = 1
	MaxSize = 1000
)

// MaxSessions is the number of concurrent shell sessions one agent allows.
const MaxSessions = 8

var (
	// ErrNotSupported is returned on platforms without a shell implementation.
	ErrNotSupported = errors.New("shell: not supported on this platform")
	// ErrInvalidSize is returned for terminal dimensions outside 1..1000.
	ErrInvalidSize = errors.New("shell: invalid terminal size")
	// ErrTooManySessions is returned when the session limit is reached.
	ErrTooManySessions = errors.New("shell: too many concurrent sessions")
	// ErrSessionExists is returned when a session ID is already in use.
	ErrSessionExists = errors.New("shell: session id already in use")
	// ErrNoSession is returned for an unknown session ID.
	ErrNoSession = errors.New("shell: no such session")
	// ErrRootRefused is returned when the configured shell user is root.
	ErrRootRefused = errors.New("shell: refusing to run the shell as root")
)

// ValidateSize checks terminal dimensions.
func ValidateSize(cols, rows int) error {
	if cols < MinSize || cols > MaxSize || rows < MinSize || rows > MaxSize {
		return fmt.Errorf("%w: %dx%d (allowed %d..%d)", ErrInvalidSize, cols, rows, MinSize, MaxSize)
	}
	return nil
}

var simpleLang = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,64}$`)

// parseLang extracts LANG from the content of /etc/default/locale. Only plain
// values are accepted; anything else yields "" so the caller uses its default.
func parseLang(content io.Reader) string {
	sc := bufio.NewScanner(content)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		v, ok := strings.CutPrefix(line, "LANG=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"'`)
		if simpleLang.MatchString(v) {
			return v
		}
		return ""
	}
	return ""
}

// passwdShell returns the login shell of the named user from /etc/passwd
// content, or "" when not found.
func passwdShell(passwd io.Reader, name string) string {
	sc := bufio.NewScanner(passwd)
	for sc.Scan() {
		f := strings.Split(sc.Text(), ":")
		if len(f) >= 7 && f[0] == name {
			return strings.TrimSpace(f[6])
		}
	}
	return ""
}

// Sessions is a registry of running shell sessions, limited to MaxSessions.
type Sessions struct {
	spawner Spawner
	max     int

	mu       sync.Mutex
	sessions map[string]Session
	pending  int // opens in progress, counted against the limit
}

// NewSessions returns a registry that opens sessions through spawner.
func NewSessions(spawner Spawner) *Sessions {
	return &Sessions{spawner: spawner, max: MaxSessions, sessions: make(map[string]Session)}
}

// Open starts a session registered under id. The caller must Close(id) when
// the session ends (for example on EOF), which frees its slot.
func (s *Sessions) Open(id string, cols, rows int) (Session, error) {
	if err := ValidateSize(cols, rows); err != nil {
		return nil, err
	}
	s.mu.Lock()
	if _, ok := s.sessions[id]; ok {
		s.mu.Unlock()
		return nil, ErrSessionExists
	}
	if len(s.sessions)+s.pending >= s.max {
		s.mu.Unlock()
		return nil, ErrTooManySessions
	}
	s.pending++
	s.mu.Unlock()

	sess, err := s.spawner.Open(cols, rows)

	s.mu.Lock()
	s.pending--
	if err == nil {
		if _, dup := s.sessions[id]; dup {
			err = ErrSessionExists
		} else {
			s.sessions[id] = sess
		}
	}
	s.mu.Unlock()
	if err != nil {
		if sess != nil {
			_ = sess.Close()
		}
		return nil, err
	}
	return sess, nil
}

// Get returns the session registered under id.
func (s *Sessions) Get(id string) (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	return sess, ok
}

// Len returns the number of registered sessions.
func (s *Sessions) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

// Close closes and removes the session registered under id.
func (s *Sessions) Close(id string) error {
	s.mu.Lock()
	sess, ok := s.sessions[id]
	delete(s.sessions, id)
	s.mu.Unlock()
	if !ok {
		return ErrNoSession
	}
	return sess.Close()
}

// CloseAll closes every session; used on agent shutdown.
func (s *Sessions) CloseAll() {
	s.mu.Lock()
	all := s.sessions
	s.sessions = make(map[string]Session)
	s.mu.Unlock()
	var wg sync.WaitGroup
	for _, sess := range all {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = sess.Close()
		}()
	}
	wg.Wait()
}
