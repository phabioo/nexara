package setup

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"os"
	"sync"
	"time"
)

const (
	// SessionCookie is the name of the setup session cookie.
	SessionCookie = "nexus_setup"
	// SessionIdle is the inactivity timeout of a setup session.
	SessionIdle = 30 * time.Minute
)

// UserCounter is the part of the store the setup mode needs.
type UserCounter interface {
	CountUsers(ctx context.Context) (int, error)
}

// Mode reports whether the hub is in setup mode (no operator exists yet).
type Mode struct {
	users UserCounter

	mu     sync.Mutex
	cached bool
	active bool
}

// NewMode creates a Mode backed by the given user counter.
func NewMode(users UserCounter) *Mode { return &Mode{users: users} }

// Active reports whether no operator exists. While it is true the HTTP server
// serves only the wizard and keeps the agent endpoint (/grid) closed. The
// result is cached until Invalidate. A store error counts as active without
// caching (fail closed).
func (m *Mode) Active(ctx context.Context) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cached {
		return m.active
	}
	n, err := m.users.CountUsers(ctx)
	if err != nil {
		return true
	}
	m.active = n == 0
	m.cached = true
	return m.active
}

// Invalidate drops the cached value; call after creating or resetting users.
func (m *Mode) Invalidate() {
	m.mu.Lock()
	m.cached = false
	m.mu.Unlock()
}

// SessionOptions configures Sessions.
type SessionOptions struct {
	// Now is the clock; defaults to time.Now.
	Now func() time.Time
	// Idle overrides SessionIdle.
	Idle time.Duration
	// InsecureCookie drops the Secure cookie flag (plain-HTTP demo mode only).
	InsecureCookie bool
	// Wizard is passed to every new wizard.
	Wizard WizardOptions
	// UploadDir is where backup files uploaded for the restore are kept until
	// they are restored (the hub's backup directory, not a RAM-backed
	// /tmp). Empty means os.TempDir().
	UploadDir string
}

// Session is the single active setup session.
type Session struct {
	hash     [sha256.Size]byte
	lastSeen time.Time
	// Wizard holds the collected, not yet persisted setup data.
	Wizard *Wizard

	umu    sync.Mutex
	upload *Upload // pending backup of the restore path, see restore.go
}

// Sessions holds at most one setup session; a new unlock replaces the old one.
type Sessions struct {
	now    func() time.Time
	idle   time.Duration
	secure bool
	wizard WizardOptions
	upDir  string
	limits *RestoreLimits

	mu  sync.Mutex
	cur *Session
}

// NewSessions creates an empty session holder.
func NewSessions(o SessionOptions) *Sessions {
	s := &Sessions{now: o.Now, idle: o.Idle, secure: !o.InsecureCookie, wizard: o.Wizard, upDir: o.UploadDir}
	if s.now == nil {
		s.now = time.Now
	}
	s.limits = NewRestoreLimits(s.now)
	if s.upDir == "" {
		s.upDir = os.TempDir()
	}
	if s.idle <= 0 {
		s.idle = SessionIdle
	}
	return s
}

// Unlock starts a new session after a correct setup code, replacing any
// existing one, and returns the opaque cookie token.
func (s *Sessions) Unlock() (string, *Session, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	sess := &Session{
		hash:     sha256.Sum256([]byte(token)),
		lastSeen: s.now(),
		Wizard:   NewWizard(s.wizard),
	}
	s.mu.Lock()
	old := s.cur
	s.cur = sess
	s.mu.Unlock()
	if old != nil {
		old.DropUpload()
	}
	return token, sess, nil
}

// Lookup returns the session for a token and refreshes its idle timer. It
// returns false for unknown tokens and sessions idle longer than the timeout.
func (s *Sessions) Lookup(token string) (*Session, bool) {
	if token == "" {
		return nil, false
	}
	h := sha256.Sum256([]byte(token))
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur == nil {
		return nil, false
	}
	if subtle.ConstantTimeCompare(h[:], s.cur.hash[:]) != 1 {
		return nil, false
	}
	now := s.now()
	if now.Sub(s.cur.lastSeen) >= s.idle {
		s.cur.DropUpload()
		s.cur = nil
		return nil, false
	}
	s.cur.lastSeen = now
	return s.cur, true
}

// FromRequest looks up the session named by the request's cookie.
func (s *Sessions) FromRequest(r *http.Request) (*Session, bool) {
	c, err := r.Cookie(SessionCookie)
	if err != nil {
		return nil, false
	}
	return s.Lookup(c.Value)
}

// Clear ends the active session (after commit or on explicit cancel).
func (s *Sessions) Clear() {
	s.mu.Lock()
	old := s.cur
	s.cur = nil
	s.mu.Unlock()
	if old != nil {
		old.DropUpload()
	}
}

// UploadDir is the directory for uploaded backup files.
func (s *Sessions) UploadDir() string { return s.upDir }

// RestoreLimits returns the attempt limits of the restore path.
func (s *Sessions) RestoreLimits() *RestoreLimits { return s.limits }

// Cookie builds the session cookie for a token. It is a browser-session cookie
// (no Max-Age); the server enforces the idle timeout.
func (s *Sessions) Cookie(token string) *http.Cookie {
	return &http.Cookie{
		Name: SessionCookie, Value: token, Path: "/",
		HttpOnly: true, Secure: s.secure, SameSite: http.SameSiteStrictMode,
	}
}

// ClearCookie builds a cookie that removes the session cookie.
func (s *Sessions) ClearCookie() *http.Cookie {
	c := s.Cookie("")
	c.MaxAge = -1
	return c
}
