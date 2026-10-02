package app

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/phabioo/nexara/internal/config"
	"github.com/phabioo/nexara/internal/hub/auth"
	"github.com/phabioo/nexara/internal/hub/demo"
	"github.com/phabioo/nexara/internal/hub/httpserver"
	"github.com/phabioo/nexara/internal/hub/setup"
	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/hub/views"
	"github.com/phabioo/nexara/internal/pki"
	"github.com/phabioo/nexara/web"
)

// Credentials of the operator that `nexus dev --demo --seed` creates. They are
// fixed and public on purpose: the demo store is temporary, empty of real
// data, simulated agents cannot touch a real device, and the listener is
// restricted to loopback.
const (
	DevOperator   = "demo"
	DevPassphrase = "nexara-demo-passphrase"
)

// DevSSHPublicKey is the sample key the demo shows in the Add-host dialog.
const DevSSHPublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK3v0demoKeyNotReal9Qx nexus@frpi5"

// DevOptions configure RunDev.
type DevOptions struct {
	// Addr is the listen address; it must be a loopback address (LoopbackAddr).
	Addr string
	// Seed creates the demo operator and skips the setup wizard.
	Seed bool
	// Console receives the human-readable hints (setup code, credentials, URL).
	Console io.Writer
	Logger  *slog.Logger

	// Listener, if set, is used instead of Addr (tests); it must be loopback.
	Listener net.Listener
	// Ready is called once the server accepts connections.
	Ready func(DevReady)

	// Overrides for tests.
	Now        func() time.Time
	HashParams auth.HashParams
	Demo       demo.Options
	// SkipHistoryBackfill leaves the demo history empty (tests).
	SkipHistoryBackfill bool
}

// DevReady describes a running dev hub.
type DevReady struct {
	Addr      net.Addr
	SetupMode bool
	// SetupCode is the initial setup code (XXXX-XXXX) in setup mode.
	SetupCode string
}

// RunDev runs the hub with simulated agents (decision #25) over plain HTTP on
// loopback (decision #34) until ctx is cancelled. The store lives in a
// temporary directory that is removed on exit.
func RunDev(ctx context.Context, o DevOptions) error {
	log := o.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	// Settings › Diagnostics shows the recent log of the dev hub.
	logRing := NewLogRing(LogRingSize)
	log = slog.New(logRing.Tee(log.Handler()))
	console := o.Console
	if console == nil {
		console = io.Discard
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}

	ln := o.Listener
	if ln == nil {
		addr, err := LoopbackAddr(o.Addr)
		if err != nil {
			return err
		}
		if ln, err = net.Listen("tcp", addr); err != nil {
			return fmt.Errorf("cannot listen on %s: %w", addr, err)
		}
	}
	defer ln.Close()

	dir, err := os.MkdirTemp("", "nexus-dev-*")
	if err != nil {
		return fmt.Errorf("cannot create a temporary directory: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			log.Warn("removing the temporary directory failed", "dir", dir, "err", err)
		}
	}()
	st, err := store.Open(filepath.Join(dir, "nexus.db"))
	if err != nil {
		return err
	}
	defer st.Close()
	key, err := auth.LoadOrCreateSecretKey(filepath.Join(dir, secretKeyFile))
	if err != nil {
		return err
	}

	const secure = false // plain HTTP on loopback
	cfg := config.DefaultHub()
	authSvc, err := auth.NewService(authConfig(cfg, st, key, secure, o.HashParams, now, log))
	if err != nil {
		return err
	}

	codes, mode, sessions := newSetupParts(st, log, now, secure, func(code string, expires time.Time) {
		fmt.Fprintf(console, "Setup code: %s (valid until %s)\n", setup.FormatCode(code), expires.Local().Format("15:04"))
	})

	if o.Seed {
		hash, err := authSvc.HashPassphrase(ctx, DevPassphrase)
		if err != nil {
			return err
		}
		if _, err := st.CreateUser(ctx, store.User{OperatorID: DevOperator, PassHash: hash}); err != nil {
			return fmt.Errorf("cannot create the demo operator: %w", err)
		}
		mode.Invalidate()
	}
	setupMode := mode.Active(ctx)
	var setupCode string
	if setupMode {
		code, _, err := codes.Rotate()
		if err != nil {
			return err
		}
		setupCode = setup.FormatCode(code)
	}

	// An ephemeral CA (removed with the temporary directory) makes the Trust
	// step with its QR code and downloads visible in the demo.
	tlsDir := filepath.Join(dir, "tls")
	if err := os.MkdirAll(tlsDir, 0o700); err != nil {
		return fmt.Errorf("cannot create the demo CA directory: %w", err)
	}
	ca, err := pki.LoadOrCreateCA(tlsDir, defaultAgentHost())
	if err != nil {
		return fmt.Errorf("cannot create the demo CA: %w", err)
	}

	hub := demo.New(o.Demo)
	defer hub.Close()
	hist, err := newDevHistory(ctx, st, hub, cfg, now, log, o.SkipHistoryBackfill)
	if err != nil {
		return err
	}

	// The commit works in the demo as well; there is no nexus.yaml to write
	// and no own agent to link.
	cm := &committer{
		st: st, auth: authSvc, codes: codes, sessions: sessions, mode: mode, log: log,
	}

	renderer, err := views.New(web.Templates, views.Options{})
	if err != nil {
		return fmt.Errorf("cannot load templates: %w", err)
	}
	capHub := newDevCapHub(hub, st, log, now)
	seedDevLog(logRing, now())
	services, err := devSettingsServices(devSettingsArgs{
		Dir: dir, TLSDir: tlsDir, Store: st, CA: ca, History: hist, Hub: capHub, Logs: logRing,
		Now: now, Log: log, SeedBackup: !o.SkipHistoryBackfill,
	})
	if err != nil {
		return err
	}
	srv, err := httpserver.New(httpserver.Options{
		Auth:         authSvc,
		Setup:        httpserver.SetupDeps{Codes: codes, Sessions: sessions, Mode: mode, Commit: cm.Commit, CA: ca},
		Hub:          capHub,
		Enroller:     hub,
		Renderer:     renderer,
		Static:       web.Static,
		SSHPublicKey: func() string { return DevSSHPublicKey },
		// Backup, updates, certificates and capabilities of the demo: dev_settings.go.
		Services:      services,
		Logger:        log.With("component", "http"),
		SecureCookies: secure,
		Now:           now,
	})
	if err != nil {
		return err
	}

	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	var wg sync.WaitGroup
	for _, fn := range []func(){
		func() { hub.Start(runCtx) },
		func() { codes.Run(runCtx) },
		func() { hist.Run(runCtx) },
	} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fn()
		}()
	}

	url := "http://" + ln.Addr().String()
	fmt.Fprintf(console, "Nexara Nexus dev mode (simulated hosts, temporary data): %s\n", url)
	if o.Seed {
		fmt.Fprintf(console, "Sign in as %s with passphrase %s (development only)\n", DevOperator, DevPassphrase)
	} else {
		fmt.Fprintf(console, "Open %s and enter the setup code above to start the setup wizard.\n", url)
	}
	log.Info("nexus dev listening", "addr", ln.Addr().String(), "seed", o.Seed, "setup_mode", setupMode)
	if o.Ready != nil {
		o.Ready(DevReady{Addr: ln.Addr(), SetupMode: setupMode, SetupCode: setupCode})
	}

	serveErr := srv.Serve(ctx, ln, nil)
	stop()
	wg.Wait()
	return serveErr
}
