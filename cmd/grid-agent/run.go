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
	"path/filepath"
	"syscall"
	"time"

	agentenroll "github.com/phabioo/nexara/internal/agent/enroll"
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runAgentContext(ctx, *cfgPath, stderr)
}

// runAgentContext runs the agent until ctx is cancelled.
func runAgentContext(ctx context.Context, cfgPath string, stderr io.Writer) int {
	log := slog.New(slog.NewTextHandler(stderr, nil))

	cfg, err := config.LoadAgent(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "grid-agent run: %v\n", err)
		return exitRuntime
	}
	// Self-link on the hub device: no certificate yet, but a token file the
	// hub's setup wizard writes.
	cfg, err = ensureEnrolled(ctx, log, cfgPath, cfg, selfLinkDeps{
		enroll: agentenroll.EnrollFromTokenFile, remove: os.Remove, poll: selfLinkPoll,
	})
	if errors.Is(err, context.Canceled) {
		return exitOK // stopped while waiting for the hub
	}
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

// selfLinkPoll is how often the agent looks for the self-link token file and
// retries enrollment while the hub is not ready.
const selfLinkPoll = 5 * time.Second

// selfLinkDeps are the side effects of ensureEnrolled (replaced in tests).
type selfLinkDeps struct {
	enroll func(ctx context.Context, cfgPath, stateDir, tokenFile, shellUser string) error
	remove func(path string) error
	poll   time.Duration
	// sleep waits for d or until ctx ends (nil uses a timer).
	sleep func(ctx context.Context, d time.Duration) error
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// certsPresent reports whether all three certificate files exist.
func certsPresent(cfg config.AgentConfig) bool {
	for _, p := range []string{cfg.TLS.CA, cfg.TLS.Cert, cfg.TLS.Key} {
		if _, err := os.Stat(p); err != nil {
			return false
		}
	}
	return true
}

// ensureEnrolled implements the self-link of the hub's own agent (decision
// #38). An agent that already has its certificate, or has no enroll.token_file
// configured, is returned unchanged (a missing certificate is then reported by
// loadAgentTLS). Otherwise it waits for the token file, which the hub writes
// when the setup wizard finishes, enrolls with it and returns the configuration
// the enrollment wrote. It keeps retrying while the hub is not reachable or
// not open yet, and drops a token file the hub rejects (expired or used).
// It only returns an error when ctx ends.
func ensureEnrolled(ctx context.Context, log *slog.Logger, cfgPath string, cfg config.AgentConfig, d selfLinkDeps) (config.AgentConfig, error) {
	tokenFile := cfg.Enroll.TokenFile
	if certsPresent(cfg) || tokenFile == "" {
		return cfg, nil
	}
	if d.sleep == nil {
		d.sleep = sleepCtx
	}
	stateDir := filepath.Dir(cfg.TLS.Cert)
	log.Info("not enrolled yet, waiting for the hub's self-link token", "token_file", tokenFile)

	var lastErr string
	for {
		if _, err := os.Stat(tokenFile); err == nil {
			err := d.enroll(ctx, cfgPath, stateDir, tokenFile, cfg.Shell.User)
			if err == nil {
				log.Info("enrolled with the hub")
				return config.LoadAgent(cfgPath)
			}
			if errors.Is(err, agentenroll.ErrTokenRejected) {
				log.Warn("the hub rejected the self-link token, removing it and waiting for a new one")
				if rerr := d.remove(tokenFile); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
					log.Warn("cannot remove the rejected token file", "err", rerr)
				}
			} else if msg := err.Error(); msg != lastErr {
				// Log a repeating failure once, not every poll.
				lastErr = msg
				log.Warn("self-link enrollment failed, will retry", "err", msg)
			}
		}
		if err := d.sleep(ctx, d.poll); err != nil {
			return cfg, err
		}
	}
}
