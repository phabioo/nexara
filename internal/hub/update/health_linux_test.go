package update

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/buildinfo"
	"github.com/phabioo/nexara/internal/hub/setup"
)

func TestAdminHealthAgainstTheAdminSocket(t *testing.T) {
	old := buildinfo.Version
	buildinfo.Version = "0.2.0-rc1"
	t.Cleanup(func() { buildinfo.Version = old })

	// Unix socket paths are short; t.TempDir can be too long.
	dir, err := os.MkdirTemp("", "nx")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "a.sock")

	health := AdminHealth(sock)
	if _, err := health(context.Background()); err == nil {
		t.Fatal("health succeeded without a hub")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- setup.ServeAdmin(ctx, sock, setup.AdminHandlers{}) }()
	t.Cleanup(func() { cancel(); <-done })

	var v string
	for i := 0; i < 200; i++ {
		if v, err = health(context.Background()); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil || v != "0.2.0-rc1" {
		t.Fatalf("health = %q, %v", v, err)
	}
	if _, err := health(cancelled()); err == nil {
		t.Fatal("health ignored a cancelled context")
	}
}

func cancelled() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}
