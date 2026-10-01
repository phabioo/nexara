package app

import (
	"bytes"
	"context"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/auth"
	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/hub/store"
)

// cheapParams keeps argon2 fast in tests.
var cheapParams = auth.HashParams{Memory: 64, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16}

const (
	testOperator = "frank"
	testPass     = "correct horse battery staple"
)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func testLogger() (*slog.Logger, *syncBuffer) {
	buf := &syncBuffer{}
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})), buf
}

func openStore(t *testing.T, dir string) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(dir, "nexus.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func testKey() []byte {
	key := make([]byte, auth.SecretKeyLen)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return key
}

func newAuth(t *testing.T, st *store.Store) *auth.Service {
	t.Helper()
	svc, err := auth.NewService(auth.Config{
		Store: st, SecretKey: testKey(), IdleTimeout: 12 * time.Hour,
		RateAttempts: 5, RateWindow: 15 * time.Minute, HashParams: cheapParams,
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func createOperator(t *testing.T, st *store.Store, id, pass string) {
	t.Helper()
	hash, err := auth.HashPassword(pass, cheapParams)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateUser(context.Background(), store.User{OperatorID: id, PassHash: hash}); err != nil {
		t.Fatal(err)
	}
}

func contextWithCancel(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return ctx, cancel
}

func grid0() grid.Actor { return grid.Actor{Operator: testOperator, IP: "192.0.2.7"} }

func emptyOpts() grid.EnrollOptions { return grid.EnrollOptions{} }
