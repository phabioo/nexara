package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/phabioo/nexara/internal/config"
	"github.com/phabioo/nexara/internal/hub/store"
)

// Config wires a Service. Use ConfigFromHub for the values of nexus.yaml.
type Config struct {
	Store       *store.Store
	SecretKey   []byte        // from LoadOrCreateSecretKey
	IdleTimeout time.Duration // session idle timeout (12 h by default)

	// RateAttempts failures within RateWindow block an IP or an account.
	RateAttempts int
	RateWindow   time.Duration

	HashParams    HashParams // zero value means DefaultHashParams
	CookieOptions []CookieOption
	Now           func() time.Time // nil means time.Now

	// OnAuditError is called when an audit entry cannot be written (may be nil).
	// The package itself never logs.
	OnAuditError func(error)
}

// ConfigFromHub fills a Config from the hub configuration.
func ConfigFromHub(c config.HubConfig, st *store.Store, secretKey []byte) Config {
	return Config{
		Store:        st,
		SecretKey:    secretKey,
		IdleTimeout:  c.SessionIdleTimeout(),
		RateAttempts: c.Security.LoginRateLimit.Attempts,
		RateWindow:   c.LoginRateWindow(),
	}
}

// Service is the auth facade used by the HTTP layer.
type Service struct {
	store      *store.Store
	key        []byte
	params     HashParams
	now        func() time.Time
	sessions   *Manager
	cookies    *Cookies
	limiter    *rateLimiter
	totp       *TOTPVerifier
	onAuditErr func(error)

	chMu       sync.Mutex
	challenges map[string]*challenge

	// hashSem bounds concurrent argon2 computations; every one allocates
	// Memory KiB, which matters on a Pi.
	hashSem   chan struct{}
	dummyOnce sync.Once
	dummyHash string

	// deleteAllUsers is what ResetOperators calls; see ResetOperators.
	deleteAllUsers func(ctx context.Context) (int64, error)
}

// NewService validates cfg and returns a Service.
func NewService(cfg Config) (*Service, error) {
	if cfg.Store == nil {
		return nil, errors.New("auth: store is required")
	}
	if len(cfg.SecretKey) != SecretKeyLen {
		return nil, errors.New("auth: secret key must be 32 bytes")
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 12 * time.Hour
	}
	if cfg.RateAttempts < 1 {
		cfg.RateAttempts = 5
	}
	if cfg.RateWindow <= 0 {
		cfg.RateWindow = 15 * time.Minute
	}
	if cfg.HashParams == (HashParams{}) {
		cfg.HashParams = DefaultHashParams
	}
	if err := cfg.HashParams.validate(); err != nil {
		return nil, err
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	key := append([]byte(nil), cfg.SecretKey...)
	s := &Service{
		store:      cfg.Store,
		key:        key,
		params:     cfg.HashParams,
		now:        cfg.Now,
		sessions:   NewManager(cfg.Store, cfg.IdleTimeout, cfg.Now),
		cookies:    NewCookies(append([]CookieOption{WithCookieClock(cfg.Now)}, cfg.CookieOptions...)...),
		limiter:    newRateLimiter(cfg.Now, cfg.RateAttempts, cfg.RateWindow),
		totp:       NewTOTPVerifier(),
		onAuditErr: cfg.OnAuditError,
		challenges: map[string]*challenge{},
		hashSem:    make(chan struct{}, 2),
	}
	// The store has no bulk user delete yet; use it as soon as it grows one.
	if d, ok := any(cfg.Store).(interface {
		DeleteAllUsers(ctx context.Context) (int64, error)
	}); ok {
		s.deleteAllUsers = d.DeleteAllUsers
	}
	return s, nil
}

// Sessions returns the session manager.
func (s *Service) Sessions() *Manager { return s.sessions }

// Cookies returns the cookie builder (uses the service clock and Secure setting).
func (s *Service) Cookies() *Cookies { return s.cookies }

// HashPassphrase applies the passphrase policy and hashes with the service's
// argon2 parameters. Use it for the setup wizard and password changes.
func (s *Service) HashPassphrase(ctx context.Context, pass string) (string, error) {
	if err := ValidatePassphrase(pass); err != nil {
		return "", err
	}
	if err := s.acquireHash(ctx); err != nil {
		return "", err
	}
	defer s.releaseHash()
	return HashPassword(pass, s.params)
}

// SealTOTPSecret encrypts a TOTP secret for users.totp_secret_enc.
func (s *Service) SealTOTPSecret(secret string) ([]byte, error) {
	return Seal(s.key, []byte(secret), AADTOTP)
}

// ConfirmTOTP checks the first code during 2FA enrollment (no replay state).
func (s *Service) ConfirmTOTP(secret, code string) bool {
	_, ok := MatchTOTP(secret, code, s.now())
	return ok
}

// TOTPReset clears replay state for a user whose 2FA was changed.
func (s *Service) TOTPReset(userID int64) { s.totp.Forget(userID) }

func (s *Service) acquireHash(ctx context.Context) error {
	select {
	case s.hashSem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Service) releaseHash() { <-s.hashSem }

func (s *Service) verifyPassword(ctx context.Context, pass, encoded string) (bool, error) {
	if err := s.acquireHash(ctx); err != nil {
		return false, err
	}
	defer s.releaseHash()
	return VerifyPassword(pass, encoded)
}

// burnPasswordHash spends the same time as a real verification, so an
// unknown operator ID cannot be told apart from a wrong passphrase by timing.
func (s *Service) burnPasswordHash(ctx context.Context, pass string) error {
	s.dummyOnce.Do(func() {
		s.dummyHash, _ = HashPassword("nexus-timing-equalizer", s.params)
	})
	_, err := s.verifyPassword(ctx, pass, s.dummyHash)
	return err
}

// --- audit -------------------------------------------------------------------

// Audit actions written by this package.
const (
	ActionLogin       = "login"
	ActionLoginLocked = "login.locked"
	ActionSecondFact  = "login.2fa"
	ActionLogout      = "logout"
	ActionUserReset   = "user.reset"
)

const maxAuditUserLen = 64

// cleanText makes attacker-controlled text safe for the audit log: control
// characters become '?', and it is cut to n characters.
func cleanText(s string, n int) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "?")
	}
	var b strings.Builder
	count := 0
	for _, r := range s {
		if count == n {
			break
		}
		if !unicode.IsPrint(r) {
			r = '?'
		}
		b.WriteRune(r)
		count++
	}
	return b.String()
}

// audit writes one entry. user is the operator ID (or the attempted ID),
// detail must never contain secrets; callers pass fixed reason codes and the IP only.
func (s *Service) audit(ctx context.Context, user, action, result, detail string) {
	_, err := s.store.AppendAudit(ctx, store.AuditEntry{
		Time:   s.now().UTC(),
		User:   cleanText(user, maxAuditUserLen),
		Action: action,
		Detail: cleanText(detail, 200),
		Result: result,
	})
	if err != nil && s.onAuditErr != nil {
		s.onAuditErr(fmt.Errorf("auth: write audit entry %q: %w", action, err))
	}
}

// --- operator reset ----------------------------------------------------------

// ResetOperators deletes all users (their sessions cascade), which returns
// the hub to setup mode. It backs `sudo nexus user reset` and is audited as
// "system". In-memory challenges and replay state are dropped too. It
// returns the number of users removed.
//
// It needs a bulk delete in the store (DeleteAllUsers); until the store has
// one this returns an error.
func (s *Service) ResetOperators(ctx context.Context) (int64, error) {
	if s.deleteAllUsers == nil {
		return 0, errors.New("auth: store does not support deleting users (DeleteAllUsers missing)")
	}
	n, err := s.deleteAllUsers(ctx)
	if err != nil {
		s.audit(ctx, "system", ActionUserReset, store.AuditError, "reset failed")
		return 0, fmt.Errorf("auth: reset operators: %w", err)
	}
	s.chMu.Lock()
	clear(s.challenges)
	s.chMu.Unlock()
	s.totp.Reset()
	s.audit(ctx, "system", ActionUserReset, store.AuditOK, fmt.Sprintf("operators removed: %d", n))
	return n, nil
}
