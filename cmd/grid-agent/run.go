package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/phabioo/nexara/internal/agent/metrics"
	"github.com/phabioo/nexara/internal/agent/packages"
	"github.com/phabioo/nexara/internal/agent/runtime"
	"github.com/phabioo/nexara/internal/agent/services"
	"github.com/phabioo/nexara/internal/agent/shell"
	"github.com/phabioo/nexara/internal/buildinfo"
	"github.com/phabioo/nexara/internal/config"
	"github.com/phabioo/nexara/internal/pki"
	"github.com/phabioo/nexara/internal/protocol"
)

const exitRuntime = 1

// errNotEnrolled means the certificate material is missing.
var errNotEnrolled = errors.New("not enrolled: certificate files are missing; run `grid-agent enroll --hub <addr> --token <token>` first")

// runAgent implements `grid-agent run`.
func runAgent(args []string, stderr io.Writer) int {
	flags := newFlagSet("run", stderr)
	cfgPath := flags.String("config", config.DefaultAgentConfigPath, "path to agent.yaml")
	if code, done := parse(flags, args); done {
		return code
	}

	log := slog.New(slog.NewTextHandler(stderr, nil))

	cfg, err := config.LoadAgent(*cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "grid-agent run: %v\n", err)
		return exitRuntime
	}
	tlsCfg, err := loadAgentTLS(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "grid-agent run: %v\n", err)
		return exitRuntime
	}

	binary, err := os.Executable()
	if err != nil {
		log.Warn("cannot determine own binary path, self-update disabled", "error", err)
		binary = ""
	}

	opts := runtime.Options{
		Config:     cfg,
		TLS:        tlsCfg,
		Facts:      metrics.Facts,
		Logger:     log,
		BinaryPath: binary,
	}
	caps := &opts.Config.Capabilities
	if caps.Monitoring {
		opts.Metrics = metrics.New()
	}
	if caps.Services {
		opts.Services = services.New()
	}
	if caps.Packages {
		opts.Packages = packages.NewApt()
	}
	if caps.Shell {
		spawner, err := shell.NewSpawner(cfg.Shell.User)
		if err != nil {
			log.Warn("shell capability disabled", "error", err)
			caps.Shell = false
		} else {
			opts.Shell = shell.NewSessions(spawner)
		}
	}
	for _, name := range []string{protocol.CapPower, protocol.CapDocker} {
		if cfg.Capabilities.Has(name) {
			log.Warn("capability is not implemented in this version, disabled", "capability", name)
		}
	}
	caps.Power, caps.Docker = false, false

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Info("grid-agent starting", "version", buildinfo.Version, "hub", cfg.Hub.URL, "capabilities", opts.Config.Capabilities.Enabled())
	if err := runtime.New(opts).Run(ctx); err != nil {
		fmt.Fprintf(stderr, "grid-agent run: %v\n", err)
		return exitRuntime
	}
	return exitOK
}

// loadAgentTLS builds the mTLS client configuration from the configured files.
func loadAgentTLS(cfg config.AgentConfig) (*tls.Config, error) {
	for _, p := range []string{cfg.TLS.CA, cfg.TLS.Cert, cfg.TLS.Key} {
		if _, err := os.Stat(p); errors.Is(err, fs.ErrNotExist) {
			return nil, errNotEnrolled
		}
	}
	caPEM, err := os.ReadFile(cfg.TLS.CA)
	if err != nil {
		return nil, fmt.Errorf("read CA certificate: %w", err)
	}
	tlsCfg, err := pki.AgentTLSConfig(caPEM, cfg.TLS.Cert, cfg.TLS.Key)
	if err != nil {
		return nil, err
	}
	return tlsCfg, nil
}
