package auth

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/store"
)

// Fast argon2 parameters for tests.
var testParams = HashParams{Memory: 64, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16}

const (
	testPass  = "correct horse battery staple"
	testPass2 = "another long passphrase 42!"
	testIP    = "192.0.2.10"
	testUA    = "TestAgent/1.0"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type testEnv struct {
	t     *testing.T
	ctx   context.Context
	clock *fakeClock
	store *store.Store
	key   []byte
	svc   *Service
}

func newEnv(t *testing.T, mutate ...func(*Config)) *testEnv {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "nexus.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	clock := newFakeClock()
	key := make([]byte, SecretKeyLen)
	for i := range key {
		key[i] = byte(i + 1)
	}
	cfg := Config{
		Store:        st,
		SecretKey:    key,
		IdleTimeout:  12 * time.Hour,
		RateAttempts: 5,
		RateWindow:   15 * time.Minute,
		HashParams:   testParams,
		Now:          clock.Now,
	}
	for _, m := range mutate {
		m(&cfg)
	}
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return &testEnv{t: t, ctx: context.Background(), clock: clock, store: st, key: key, svc: svc}
}

// addUser creates an operator without TOTP.
func (e *testEnv) addUser(operatorID, pass string) store.User {
	e.t.Helper()
	hash, err := HashPassword(pass, testParams)
	if err != nil {
		e.t.Fatal(err)
	}
	u, err := e.store.CreateUser(e.ctx, store.User{OperatorID: operatorID, PassHash: hash})
	if err != nil {
		e.t.Fatal(err)
	}
	return u
}

// addTOTPUser creates an operator with TOTP enabled and returns the base32 secret.
func (e *testEnv) addTOTPUser(operatorID, pass string) (store.User, string) {
	e.t.Helper()
	u := e.addUser(operatorID, pass)
	enr, err := NewTOTP(operatorID)
	if err != nil {
		e.t.Fatal(err)
	}
	sealed, err := e.svc.SealTOTPSecret(enr.Secret)
	if err != nil {
		e.t.Fatal(err)
	}
	if err := e.store.SetTOTP(e.ctx, u.ID, sealed, true); err != nil {
		e.t.Fatal(err)
	}
	u, err = e.store.GetUserByID(e.ctx, u.ID)
	if err != nil {
		e.t.Fatal(err)
	}
	return u, enr.Secret
}

func (e *testEnv) auditEntries() []store.AuditEntry {
	e.t.Helper()
	list, err := e.store.ListAudit(e.ctx, 1000)
	if err != nil {
		e.t.Fatal(err)
	}
	return list
}

func (e *testEnv) auditCount(action, result string) int {
	n := 0
	for _, a := range e.auditEntries() {
		if a.Action == action && a.Result == result {
			n++
		}
	}
	return n
}

// codeAt returns the valid TOTP code for secret at time t.
func codeAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	code, err := generateTestCode(secret, at)
	if err != nil {
		t.Fatal(err)
	}
	return code
}
