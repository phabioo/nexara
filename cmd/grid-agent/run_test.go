package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	agentenroll "github.com/phabioo/nexara/internal/agent/enroll"
	"github.com/phabioo/nexara/internal/config"
)

func TestLoadAgentTLSNotEnrolled(t *testing.T) {
	dir := t.TempDir()
	cfg := config.DefaultAgent()
	cfg.TLS = config.AgentTLSSection{
		CA:   filepath.Join(dir, "ca.pem"),
		Cert: filepath.Join(dir, "agent.pem"),
		Key:  filepath.Join(dir, "agent.key"),
	}
	if _, err := loadAgentTLS(cfg); !errors.Is(err, errNotEnrolled) {
		t.Fatalf("err = %v, want errNotEnrolled", err)
	}
}

// --- self-link -----------------------------------------------------------------

type selfLinkEnv struct {
	dir       string
	cfgPath   string
	tokenFile string
	cfg       config.AgentConfig
}

func newSelfLinkEnv(t *testing.T, withToken bool) *selfLinkEnv {
	t.Helper()
	dir := t.TempDir()
	e := &selfLinkEnv{dir: dir, cfgPath: filepath.Join(dir, "agent.yaml"), tokenFile: filepath.Join(dir, "self-enroll.token")}
	e.cfg = config.DefaultAgent()
	e.cfg.Hub.URL = "wss://127.0.0.1:8443/grid/connect" // placeholder written by the installer
	e.cfg.Shell.User = "pi"
	e.cfg.TLS = config.AgentTLSSection{
		CA: filepath.Join(dir, "state", "ca.pem"), Cert: filepath.Join(dir, "state", "agent.pem"), Key: filepath.Join(dir, "state", "agent.key"),
	}
	e.cfg.Enroll.TokenFile = e.tokenFile
	if err := config.SaveAgent(e.cfgPath, e.cfg); err != nil {
		t.Fatal(err)
	}
	if withToken {
		e.writeToken(t)
	}
	return e
}

func (e *selfLinkEnv) writeToken(t *testing.T) {
	t.Helper()
	if err := os.WriteFile(e.tokenFile, []byte(`{"token":"GRID-XXXX-YYYY"}`), 0o600); err != nil {
		t.Fatal(err)
	}
}

// enrollWrites mimics agent/enroll.EnrollFromTokenFile: it writes the
// certificate files and a new agent.yaml and deletes the token file.
func (e *selfLinkEnv) enrollWrites(t *testing.T) error {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(e.cfg.TLS.Cert), 0o700); err != nil {
		return err
	}
	for _, p := range []string{e.cfg.TLS.CA, e.cfg.TLS.Cert, e.cfg.TLS.Key} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			return err
		}
	}
	enrolled := e.cfg
	enrolled.Enroll = config.AgentEnrollSection{}
	enrolled.Hub.URL = "wss://frpi5.local:8443/grid/connect"
	if err := config.SaveAgent(e.cfgPath, enrolled); err != nil {
		return err
	}
	return os.Remove(e.tokenFile)
}

func (e *selfLinkEnv) run(t *testing.T, ctx context.Context, d selfLinkDeps) (config.AgentConfig, error) {
	t.Helper()
	log := slog.New(slog.DiscardHandler)
	return ensureEnrolled(ctx, log, e.cfgPath, e.cfg, d)
}

func TestEnsureEnrolledLeavesOtherSetupsAlone(t *testing.T) {
	never := selfLinkDeps{
		enroll: func(context.Context, string, string, string, string) error { t.Error("enroll called"); return nil },
		remove: func(string) error { t.Error("remove called"); return nil },
		poll:   time.Millisecond,
	}
	t.Run("certificates present", func(t *testing.T) {
		e := newSelfLinkEnv(t, true)
		if err := e.enrollWrites(t); err != nil {
			t.Fatal(err)
		}
		e.writeToken(t) // a leftover token must not trigger a second enrollment
		got, err := e.run(t, context.Background(), never)
		if err != nil || got.Hub.URL != e.cfg.Hub.URL {
			t.Fatalf("got %+v, %v", got.Hub, err)
		}
	})
	t.Run("no token file configured", func(t *testing.T) {
		e := newSelfLinkEnv(t, false)
		e.cfg.Enroll = config.AgentEnrollSection{}
		if _, err := e.run(t, context.Background(), never); err != nil {
			t.Fatal(err) // loadAgentTLS reports the missing certificate afterwards
		}
	})
}

func TestEnsureEnrolledEnrollsFromTheTokenFile(t *testing.T) {
	e := newSelfLinkEnv(t, true)
	var calls int
	got, err := e.run(t, context.Background(), selfLinkDeps{
		enroll: func(_ context.Context, cfgPath, stateDir, tokenFile, shellUser string) error {
			calls++
			if cfgPath != e.cfgPath || stateDir != filepath.Dir(e.cfg.TLS.Cert) || tokenFile != e.tokenFile || shellUser != "pi" {
				t.Errorf("enroll(%q, %q, %q, %q)", cfgPath, stateDir, tokenFile, shellUser)
			}
			return e.enrollWrites(t)
		},
		remove: func(string) error { t.Error("remove called"); return nil },
		poll:   time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Errorf("enroll calls = %d", calls)
	}
	// The configuration the enrollment wrote is what runs.
	if got.Hub.URL != "wss://frpi5.local:8443/grid/connect" || got.Enroll.TokenFile != "" {
		t.Errorf("returned config = %+v", got)
	}
}

func TestEnsureEnrolledRetriesUntilTheHubIsOpen(t *testing.T) {
	e := newSelfLinkEnv(t, true)
	var calls int
	_, err := e.run(t, context.Background(), selfLinkDeps{
		enroll: func(context.Context, string, string, string, string) error {
			calls++
			if calls < 3 {
				return errors.New("enroll: the hub answered with status 503") // setup mode, or not up yet
			}
			return e.enrollWrites(t)
		},
		remove: func(string) error { t.Error("a transient failure must keep the token"); return nil },
		poll:   time.Millisecond,
	})
	if err != nil || calls != 3 {
		t.Fatalf("err = %v, calls = %d, want success on the third try", err, calls)
	}
}

func TestEnsureEnrolledWaitsForTheTokenFile(t *testing.T) {
	e := newSelfLinkEnv(t, false) // the wizard has not finished yet
	sleeps := 0
	enrolled := false
	_, err := e.run(t, context.Background(), selfLinkDeps{
		enroll: func(context.Context, string, string, string, string) error {
			if sleeps != 2 {
				t.Errorf("enrolled after %d waits, want exactly when the file appeared (2)", sleeps)
			}
			enrolled = true
			return e.enrollWrites(t)
		},
		remove: func(string) error { t.Error("remove called"); return nil },
		poll:   5 * time.Second,
		sleep: func(_ context.Context, d time.Duration) error {
			if d != 5*time.Second {
				t.Errorf("waited %v", d)
			}
			sleeps++
			if sleeps == 2 {
				e.writeToken(t) // the hub's setup wizard writes the token
			}
			return nil
		},
	})
	if err != nil || !enrolled {
		t.Fatalf("err = %v, enrolled = %v", err, enrolled)
	}
}

func TestEnsureEnrolledDropsARejectedToken(t *testing.T) {
	e := newSelfLinkEnv(t, true)
	var removed []string
	enrollCalls := 0
	_, err := e.run(t, context.Background(), selfLinkDeps{
		enroll: func(context.Context, string, string, string, string) error {
			enrollCalls++
			if enrollCalls == 1 {
				return agentenroll.ErrTokenRejected
			}
			return e.enrollWrites(t)
		},
		remove: func(p string) error {
			removed = append(removed, p)
			return os.Remove(p)
		},
		poll: time.Millisecond,
		// The hub writes a fresh token while the agent waits.
		sleep: func(context.Context, time.Duration) error { e.writeToken(t); return nil },
	})
	if err != nil || enrollCalls != 2 {
		t.Fatalf("err = %v, enroll calls = %d", err, enrollCalls)
	}
	if len(removed) != 1 || removed[0] != e.tokenFile {
		t.Errorf("removed = %v, want the rejected token file", removed)
	}
}

func TestEnsureEnrolledStopsWithTheContext(t *testing.T) {
	e := newSelfLinkEnv(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	_, err := e.run(t, ctx, selfLinkDeps{
		enroll: func(context.Context, string, string, string, string) error { t.Error("enroll called"); return nil },
		remove: func(string) error { return nil },
		poll:   time.Hour,
		sleep:  func(ctx context.Context, _ time.Duration) error { cancel(); return ctx.Err() },
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}

	// The real timer honors the context as well.
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	if err := sleepCtx(ctx2, time.Hour); !errors.Is(err, context.Canceled) {
		t.Errorf("sleepCtx = %v", err)
	}
	if err := sleepCtx(context.Background(), time.Millisecond); err != nil {
		t.Errorf("sleepCtx = %v", err)
	}
}

func TestRunWaitsForSelfLinkAndExitsCleanlyOnCancel(t *testing.T) {
	// Through the command: an unenrolled agent with a token_file does not fail
	// at startup (systemd would restart-loop it), it waits for the hub.
	e := newSelfLinkEnv(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	var errBuf bytes.Buffer
	go func() { done <- runAgentContext(ctx, e.cfgPath, &errBuf) }()
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("exit code %d, stderr %q", code, errBuf.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("grid-agent run did not stop with the context")
	}
}
