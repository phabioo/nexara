package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/phabioo/nexara/internal/hub/store"
)

// Session lifetime rules (decision #29).
const (
	// AbsoluteLifetime is the maximum age of a session, persistent or not.
	AbsoluteLifetime = 30 * 24 * time.Hour
	// TouchInterval is the minimum time between two last_seen updates.
	TouchInterval = time.Minute

	// SessionCookieName is the base name of the cookie carrying the raw
	// session ID. Use Cookies.SessionName for the name on the wire.
	SessionCookieName = "nexus_session"

	maxSessionIDLen = 128 // raw IDs are 43 characters; anything longer is garbage
	maxIPLen        = 64
	maxUserAgentLen = 256
)

// Manager creates, validates and revokes browser sessions in the store. Only
// the SHA-256 of the session ID is stored, so a database leak does not yield
// usable cookies.
type Manager struct {
	store *store.Store
	idle  time.Duration
	now   func() time.Time
	rev   *revocations
}

// NewManager returns a Manager. idle is the idle timeout (config
// security.session_idle_hours); now may be nil for time.Now.
func NewManager(st *store.Store, idle time.Duration, now func() time.Time) *Manager {
	if now == nil {
		now = time.Now
	}
	return &Manager{store: st, idle: idle, now: now, rev: newRevocations()}
}

// HashSessionID returns the hex SHA-256 under which a raw session ID is stored.
func HashSessionID(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func randomToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("auth: read random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// Create starts a session for user and returns the raw ID (for the cookie)
// and the stored session (for the cookie's lifetime and the CSRF token).
// persistent is the "keep me signed in" choice; it only affects the cookie.
func (m *Manager) Create(ctx context.Context, user store.User, persistent bool, ip, userAgent string) (string, store.Session, error) {
	raw, err := randomToken()
	if err != nil {
		return "", store.Session{}, err
	}
	now := m.now().UTC()
	sess := store.Session{
		IDHash:     HashSessionID(raw),
		UserID:     user.ID,
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(AbsoluteLifetime),
		Persistent: persistent,
		IP:         truncate(ip, maxIPLen),
		UserAgent:  truncate(userAgent, maxUserAgentLen),
	}
	if err := m.store.CreateSession(ctx, sess); err != nil {
		return "", store.Session{}, fmt.Errorf("auth: create session: %w", err)
	}
	return raw, sess, nil
}

// Validate resolves a raw session ID to its user and session. It returns
// ErrSessionExpired for unknown, malformed, idle-expired (last_seen + idle
// timeout) and absolutely expired (30 days after creation) sessions, and
// removes expired ones. last_seen is refreshed at most once per TouchInterval
// to keep writes low; the returned session reflects the refreshed value.
func (m *Manager) Validate(ctx context.Context, raw string) (store.User, store.Session, error) {
	if raw == "" || len(raw) > maxSessionIDLen {
		return store.User{}, store.Session{}, ErrSessionExpired
	}
	return m.validate(ctx, HashSessionID(raw), true)
}

// CheckHash is Validate for a session that is already known by its stored
// hash (open SSE and shell streams re-check their session on every
// heartbeat). It does not refresh last_seen: a stream that only keeps
// beating must not keep an idle session alive, or the 12 h idle timeout
// would never fire for an open browser tab.
func (m *Manager) CheckHash(ctx context.Context, idHash string) error {
	_, _, err := m.validate(ctx, idHash, false)
	return err
}

func (m *Manager) validate(ctx context.Context, hash string, touch bool) (store.User, store.Session, error) {
	sess, err := m.store.GetSession(ctx, hash)
	if errors.Is(err, store.ErrNotFound) {
		return store.User{}, store.Session{}, ErrSessionExpired
	}
	if err != nil {
		return store.User{}, store.Session{}, err
	}
	now := m.now().UTC()
	if !now.Before(sess.ExpiresAt) || !now.Before(sess.CreatedAt.Add(AbsoluteLifetime)) ||
		!now.Before(sess.LastSeenAt.Add(m.idle)) {
		_ = m.store.DeleteSession(ctx, hash)
		return store.User{}, store.Session{}, ErrSessionExpired
	}
	user, err := m.store.GetUserByID(ctx, sess.UserID)
	if errors.Is(err, store.ErrNotFound) {
		_ = m.store.DeleteSession(ctx, hash)
		return store.User{}, store.Session{}, ErrSessionExpired
	}
	if err != nil {
		return store.User{}, store.Session{}, err
	}
	if touch && now.Sub(sess.LastSeenAt) >= TouchInterval {
		if err := m.store.TouchSession(ctx, hash, now); err != nil && !errors.Is(err, store.ErrNotFound) {
			return store.User{}, store.Session{}, err
		}
		sess.LastSeenAt = now
	}
	return user, sess, nil
}

// Revoked returns a channel that is closed the next time any session is
// ended on purpose (logout, Delete, DeleteAllForUser, ResetOperators).
// Long-lived streams take the channel first, then check their own session
// (CheckHash), then wait on it: a revocation between the check and the wait
// is never lost. Expiry by time is not signalled; streams find it with their
// periodic CheckHash.
func (m *Manager) Revoked() <-chan struct{} { return m.rev.wait() }

// Delete ends the session with the given raw ID (logout). Unknown IDs are not an error.
func (m *Manager) Delete(ctx context.Context, raw string) error {
	if raw == "" || len(raw) > maxSessionIDLen {
		return nil
	}
	err := m.store.DeleteSession(ctx, HashSessionID(raw))
	m.rev.notify()
	return err
}

// DeleteAllForUser ends every session of a user ("sign out everywhere",
// password change, 2FA reset) and returns how many there were.
func (m *Manager) DeleteAllForUser(ctx context.Context, userID int64) (int64, error) {
	n, err := m.store.DeleteUserSessions(ctx, userID)
	m.rev.notify()
	return n, err
}

// Cleanup removes expired sessions and returns how many were removed.
func (m *Manager) Cleanup(ctx context.Context) (int64, error) {
	return m.store.DeleteExpiredSessions(ctx, m.now().UTC(), m.idle)
}

// RunCleanup calls Cleanup every interval until ctx is done. Errors are
// passed to onErr (may be nil).
func (m *Manager) RunCleanup(ctx context.Context, interval time.Duration, onErr func(error)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := m.Cleanup(ctx); err != nil && onErr != nil && ctx.Err() == nil {
				onErr(err)
			}
		}
	}
}

// hostPrefix makes the browser enforce Secure, Path=/ and no Domain, and
// refuse a cookie of that name set over plain HTTP by another service on the
// same host (cookie tossing, security review S-17).
const hostPrefix = "__Host-"

// CookieName is the one place that decides how a cookie is named on the
// wire: with the __Host- prefix when secure (TLS), plain otherwise. The
// plain-HTTP demo cannot use the prefix because browsers reject it without
// Secure. A prefixed cookie must be set with Path=/ and without Domain.
func CookieName(base string, secure bool) string {
	if secure {
		return hostPrefix + base
	}
	return base
}

// Cookies builds the session and pre-session CSRF cookies.
type Cookies struct {
	secure bool
	now    func() time.Time
}

// CookieOption configures NewCookies.
type CookieOption func(*Cookies)

// WithSecure sets the Secure attribute. The default is true and must stay
// true in production. Dev mode (`nexus dev --demo`, plain HTTP on 127.0.0.1)
// can leave it on as well: browsers treat http://localhost and
// http://127.0.0.1 as secure contexts and accept Secure cookies there.
// Pass false only for tools that do not (e.g. curl-based scripts over HTTP).
func WithSecure(secure bool) CookieOption { return func(c *Cookies) { c.secure = secure } }

// WithCookieClock overrides the clock (tests).
func WithCookieClock(now func() time.Time) CookieOption { return func(c *Cookies) { c.now = now } }

// NewCookies returns a cookie builder (Secure by default).
func NewCookies(opts ...CookieOption) *Cookies {
	c := &Cookies{secure: true, now: time.Now}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Secure reports whether cookies carry the Secure flag and the __Host- prefix.
func (c *Cookies) Secure() bool { return c.secure }

// Name returns the wire name of the cookie with the given base name.
func (c *Cookies) Name(base string) string { return CookieName(base, c.secure) }

// SessionName is the wire name of the session cookie.
func (c *Cookies) SessionName() string { return c.Name(SessionCookieName) }

// CSRFName is the wire name of the pre-session double-submit cookie.
func (c *Cookies) CSRFName() string { return c.Name(CSRFCookieName) }

// Session returns the session cookie: HttpOnly, SameSite=Strict, Path=/.
// A persistent session gets Max-Age equal to its remaining absolute
// lifetime (a fixed end, survives browser restarts); otherwise no
// Max-Age/Expires is set and the browser drops the cookie when it closes.
// The server enforces idle and absolute limits either way.
func (c *Cookies) Session(raw string, sess store.Session) *http.Cookie {
	ck := &http.Cookie{
		Name:     c.SessionName(),
		Value:    raw,
		Path:     "/",
		HttpOnly: true,
		Secure:   c.secure,
		SameSite: http.SameSiteStrictMode,
	}
	if sess.Persistent {
		remaining := int(sess.ExpiresAt.Sub(c.now()) / time.Second)
		if remaining < 1 {
			remaining = 1
		}
		ck.MaxAge = remaining
	}
	return ck
}

// ClearSession returns a cookie that deletes the session cookie.
func (c *Cookies) ClearSession() *http.Cookie {
	return &http.Cookie{
		Name: c.SessionName(), Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: c.secure, SameSite: http.SameSiteStrictMode,
	}
}

// CSRF returns the double-submit cookie for pre-session forms (browser-session cookie).
func (c *Cookies) CSRF(token string) *http.Cookie {
	return &http.Cookie{
		Name: c.CSRFName(), Value: token, Path: "/",
		HttpOnly: true, Secure: c.secure, SameSite: http.SameSiteStrictMode,
	}
}

// ClearCSRF returns a cookie that deletes the double-submit cookie.
func (c *Cookies) ClearCSRF() *http.Cookie {
	return &http.Cookie{
		Name: c.CSRFName(), Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: c.secure, SameSite: http.SameSiteStrictMode,
	}
}
