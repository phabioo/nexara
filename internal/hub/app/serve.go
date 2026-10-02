// Package app wires the hub together: configuration, store, PKI, auth,
// setup mode, grid, enrollment and the HTTP server. cmd/nexus only parses
// flags and calls Serve (production) or RunDev (`nexus dev --demo`).
package app

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/phabioo/nexara/internal/buildinfo"
	"github.com/phabioo/nexara/internal/config"
	"github.com/phabioo/nexara/internal/hub/auth"
	"github.com/phabioo/nexara/internal/hub/enroll"
	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/hub/httpserver"
	"github.com/phabioo/nexara/internal/hub/setup"
	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/hub/views"
	"github.com/phabioo/nexara/internal/pki"
	"github.com/phabioo/nexara/web"
)

const (
	secretKeyFile = "secret.key"

	// agentDrainTimeout bounds how long shutdown waits for agent connections
	// to finish their last database writes before the store is closed.
	agentDrainTimeout = 5 * time.Second

	housekeepingInterval = time.Hour
)

// ServeOptions configure Serve. Only ConfigPath is required.
type ServeOptions struct {
	// ConfigPath is nexus.yaml.
	ConfigPath string
	// AdminSocket is the path of the admin Unix socket; empty disables it.
	AdminSocket string
	Logger      *slog.Logger

	// Listener, if set, is used instead of listening on hub.listen (tests).
	Listener net.Listener
	// Ready is called once the hub accepts connections.
	Ready func(Ready)

	// Overrides for tests; zero values use the real ones.
	Now            func() time.Time
	HashParams     auth.HashParams
	CertCheckEvery time.Duration
	LocalNames     func() []string
	LocalIPs       func() []net.IP
}

// Ready describes a running hub.
type Ready struct {
	Addr          net.Addr
	CAFingerprint string // colon separated, as shown to operators
	SetupMode     bool
}

// Serve runs the hub until ctx is cancelled and then shuts down in order: the
// HTTP server (streams end first), the agent connections, background loops,
// and finally the database. It returns nil on a clean shutdown.
func Serve(ctx context.Context, o ServeOptions) error {
	log := o.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}

	cfg, err := config.LoadHub(o.ConfigPath)
	if err != nil {
		return fmt.Errorf("cannot load configuration: %w", err)
	}
	dataDir := filepath.Dir(cfg.Storage.Database)
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return fmt.Errorf("cannot create data directory: %w", err)
	}
	st, err := store.Open(cfg.Storage.Database)
	if err != nil {
		return fmt.Errorf("cannot open database %s: %w", cfg.Storage.Database, err)
	}
	defer func() {
		if err := st.Close(); err != nil {
			log.Warn("closing the database failed", "err", err)
		}
	}()

	key, err := auth.LoadOrCreateSecretKey(filepath.Join(dataDir, secretKeyFile))
	if err != nil {
		return err
	}
	// A new CA is name-constrained (decision #45); the configured agent host is
	// part of the permitted names. The wizard sets it only after the CA exists,
	// so a later public DNS name is not covered (pki.CA.Permits tells).
	caHost, _ := resolveAgentAddress(cfg.Hub.AgentAddress, defaultAgentHost(), 0)
	ca, err := pki.LoadOrCreateCA(cfg.TLS.Dir, caHost)
	if err != nil {
		return err
	}
	certs := newCertManager(ca, cfg.TLS.Dir, log, now)
	if o.LocalNames != nil {
		certs.localNames = o.LocalNames
	}
	if o.LocalIPs != nil {
		certs.localIPs = o.LocalIPs
	}

	ln := o.Listener
	if ln == nil {
		if ln, err = net.Listen("tcp", cfg.Hub.Listen); err != nil {
			return fmt.Errorf("cannot listen on %s: %w", cfg.Hub.Listen, err)
		}
	}
	defer ln.Close() // no-op after a clean Serve; covers early error returns
	listenPort, err := portOf(ln.Addr())
	if err != nil {
		return err
	}

	agentHost, agentPort := resolveAgentAddress(cfg.Hub.AgentAddress, defaultAgentHost(), listenPort)
	certs.SetAgentHost(agentHost)
	if _, err := certs.Ensure(); err != nil {
		return fmt.Errorf("cannot issue the server certificate: %w", err)
	}

	authSvc, err := auth.NewService(authConfig(cfg, st, key, true, o.HashParams, now, log))
	if err != nil {
		return err
	}
	codes, mode, sessions := newSetupParts(st, log, now, true)
	codes.SetAudit(setupAudit(st, log))
	setupMode := mode.Active(ctx)
	if setupMode {
		if _, _, err := codes.Rotate(); err != nil {
			return fmt.Errorf("cannot create a setup code: %w", err)
		}
	}

	g, err := grid.NewGrid(grid.Options{
		Store: st, Logger: log.With("component", "grid"), Now: now,
		OfflineAfter: cfg.HostOfflineAfter(), HubVersion: buildinfo.Version, CA: ca,
	})
	if err != nil {
		return err
	}
	defer g.Close()

	newEnroll := func(host string, port int) (*enroll.Service, error) {
		return enroll.New(enroll.Options{
			Store: st, CA: ca, ServerCertFile: filepath.Join(cfg.TLS.Dir, pki.ServerCertFile),
			HubAddress: host, Port: port, DataDir: dataDir,
			Logger: log.With("component", "enroll"), Now: now,
			OnEnrolled: func(ctx context.Context, h store.Host) {
				if err := g.Register(ctx, h); err != nil {
					log.Error("registering an enrolled host failed", "host", h.Name, "err", err)
				}
			},
			WaitOnline: waitOnline(g),
			// Replacing a host is only allowed while it is offline (decision #46).
			HostOnline: func(id grid.HostID) bool { h, ok := g.Host(id); return ok && h.Online },
		})
	}
	enrollSvc, err := newEnroll(agentHost, agentPort)
	if err != nil {
		return fmt.Errorf("cannot start enrollment (hub.agent_address %q): %w", cfg.Hub.AgentAddress, err)
	}
	enrollers := newEnrollHolder(enrollSvc)

	rt := &hubRuntime{certs: certs, enrollers: enrollers, newEnroll: newEnroll, listenPort: listenPort, dataDir: dataDir}
	cm := &committer{
		st: st, auth: authSvc, codes: codes, sessions: sessions, mode: mode, log: log,
		configPath: o.ConfigPath, listenPort: listenPort,
		applyHub: rt.applyHub, selfLink: rt.writeSelfLink, permits: ca.Permits,
	}

	renderer, err := views.New(web.Templates, views.Options{})
	if err != nil {
		return fmt.Errorf("cannot load templates: %w", err)
	}

	// Agent connections are hijacked WebSockets that http.Server.Shutdown does
	// not wait for; track them so the database outlives their last writes.
	var agents sync.WaitGroup
	agentMux := http.NewServeMux()
	agentMux.Handle("/grid/connect", g.AgentHandler())
	agentMux.Handle("/grid/agent/{os}/{arch}", g.AgentDownloadHandler())
	agentHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agents.Add(1)
		defer agents.Done()
		agentMux.ServeHTTP(w, r)
	})

	srv, err := httpserver.New(httpserver.Options{
		Auth:          authSvc,
		Setup:         httpserver.SetupDeps{Codes: codes, Sessions: sessions, Mode: mode, Commit: cm.Commit, CA: ca},
		Hub:           g,
		Enroller:      enrollers,
		Renderer:      renderer,
		Static:        web.Static,
		AgentHandler:  agentHandler,
		EnrollHandler: enrollers,
		SSHPublicKey:  func() string { return enrollers.Service().PublicKey() },
		Logger:        log.With("component", "http"),
		SecureCookies: true,
		Now:           now,
	})
	if err != nil {
		return err
	}

	tlsCfg, err := pki.ServerTLSConfig(ca, filepath.Join(cfg.TLS.Dir, pki.ServerCertFile),
		filepath.Join(cfg.TLS.Dir, pki.ServerKeyFile), g.IsRevoked)
	if err != nil {
		return err
	}
	// WebSockets need the HTTP/1.1 upgrade.
	tlsCfg.NextProtos = []string{"http/1.1"}

	// --- run ---
	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	var wg sync.WaitGroup
	bg := func(fn func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fn()
		}()
	}

	bg(func() { codes.Run(runCtx) })
	bg(func() { certs.Run(runCtx, orDefault(o.CertCheckEvery, DefaultCertCheckInterval)) })
	bg(func() { runAgentCertRenewals(runCtx, g, orDefault(o.CertCheckEvery, DefaultCertCheckInterval)) })
	bg(func() { housekeeping(runCtx, st, authSvc, now, log) })
	backups := newBackupService(cfg, o.ConfigPath, st, log, now)
	bg(func() { runBackupScheduler(runCtx, backups, cfg, log, now) })
	if o.AdminSocket != "" {
		limits, _ := any(authSvc).(loginLimits) // ClearLoginLimits; nil until the auth service has it
		backend := adminBackend{
			codes: codes, mode: mode, sessions: sessions, auth: authSvc, limits: limits, now: now,
			audit: func(ctx context.Context, e store.AuditEntry) { appendAudit(ctx, st, log, e) },
		}
		bg(func() {
			if err := setup.ServeAdmin(runCtx, o.AdminSocket, backend.handlers()); err != nil && runCtx.Err() == nil {
				// The hub works without it; only `sudo nexus setup code` and
				// `user reset` are unavailable.
				log.Error("admin socket is not available", "path", o.AdminSocket, "err", err)
			}
		})
	}

	fp := pki.DisplayFingerprint(ca.Cert)
	log.Info("nexus listening", "addr", ln.Addr().String(), "version", buildinfo.Version,
		"hub", cfg.Hub.Name, "agent_address", net.JoinHostPort(agentHost, fmt.Sprint(agentPort)), "setup_mode", setupMode)
	log.Info("CA fingerprint", "sha256", fp)
	if o.Ready != nil {
		o.Ready(Ready{Addr: ln.Addr(), CAFingerprint: fp, SetupMode: setupMode})
	}

	serveErr := srv.Serve(ctx, ln, tlsCfg)

	// --- shutdown ---
	g.Close()
	waitTimeout(&agents, agentDrainTimeout)
	stop()
	wg.Wait()
	if serveErr != nil {
		return serveErr
	}
	log.Info("nexus stopped")
	return nil
}

// hubRuntime holds the parts of the running hub that the setup commit has to
// update when the operator chooses the agent address.
type hubRuntime struct {
	certs      *certManager
	enrollers  *enrollHolder
	newEnroll  func(host string, port int) (*enroll.Service, error)
	listenPort int
	dataDir    string
}

// applyHub puts the new hub settings into effect without a restart: the server
// certificate gets the agent address as a name, and enrollment URLs and
// install scripts use it.
func (h *hubRuntime) applyHub(cfg config.HubConfig) error {
	host, port := resolveAgentAddress(cfg.Hub.AgentAddress, defaultAgentHost(), h.listenPort)
	h.certs.SetAgentHost(host)
	if _, err := h.certs.Ensure(); err != nil {
		return err
	}
	svc, err := h.newEnroll(host, port)
	if err != nil {
		return err
	}
	h.enrollers.Replace(svc)
	return nil
}

// writeSelfLink writes the token the hub's own agent enrolls with
// (<data dir>/self-enroll.token, mode 0640).
func (h *hubRuntime) writeSelfLink(ctx context.Context, caps []string) error {
	return h.enrollers.Service().WriteSelfLinkToken(ctx, filepath.Join(h.dataDir, SelfEnrollTokenFile), caps)
}

// authConfig builds the auth.Config shared by serve and dev. secure is the
// single source for the Secure flag of the session cookies.
func authConfig(cfg config.HubConfig, st *store.Store, key []byte, secure bool, hp auth.HashParams, now func() time.Time, log *slog.Logger) auth.Config {
	c := auth.ConfigFromHub(cfg, st, key)
	c.HashParams = hp
	c.Now = now
	c.CookieOptions = []auth.CookieOption{auth.WithSecure(secure)}
	c.OnAuditError = func(err error) { log.Error("audit write failed", "err", err) }
	return c
}

// newSetupParts creates the setup-mode objects. The setup code is announced
// through the logger (journal); this is the one deliberate place where a
// secret is logged (see setup.CodeOptions.Announce). secure is the single
// source for the setup cookie's Secure flag.
func newSetupParts(users setup.UserCounter, log *slog.Logger, now func() time.Time, secure bool, extraAnnounce ...func(code string, expires time.Time)) (*setup.Codes, *setup.Mode, *setup.Sessions) {
	codes := setup.NewCodes(setup.CodeOptions{
		Now: now,
		Announce: func(code string, expires time.Time) {
			log.Info("setup code", "code", setup.FormatCode(code), "valid_until", expires.Local().Format(time.RFC3339))
			for _, fn := range extraAnnounce {
				fn(code, expires)
			}
		},
	})
	sessions := setup.NewSessions(setup.SessionOptions{
		Now:            now,
		InsecureCookie: !secure,
		Wizard:         setup.WizardOptions{CheckPassphrase: checkWizardPassphrase},
	})
	return codes, setup.NewMode(users), sessions
}

// appendAudit writes an audit entry; a failure is logged, never fatal.
func appendAudit(ctx context.Context, st *store.Store, log *slog.Logger, e store.AuditEntry) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := st.AppendAudit(ctx, e); err != nil {
		log.Error("audit write failed", "action", e.Action, "err", err)
	}
}

// Audit actions of the setup unlock.
const (
	ActionSetupUnlock    = "setup.unlock"
	ActionSetupWrongCode = "setup.wrong_code"
	ActionSetupLockedIP  = "setup.locked"
	ActionSetupLockedAll = "setup.locked_global"
	setupAuditActor      = "setup"
)

// setupAudit turns setup-code events into audit entries. The entered code is
// never part of an event.
func setupAudit(st *store.Store, log *slog.Logger) func(setup.CodeEvent) {
	return func(ev setup.CodeEvent) {
		e := store.AuditEntry{User: setupAuditActor, Time: ev.Time, Detail: "ip: " + ev.IP, Result: store.AuditDenied}
		switch ev.Kind {
		case setup.EventUnlocked:
			e.Action, e.Result = ActionSetupUnlock, store.AuditOK
		case setup.EventWrongCode:
			e.Action = ActionSetupWrongCode
		case setup.EventIPLocked:
			e.Action = ActionSetupLockedIP
			e.Detail += "; locked for 15 minutes"
		case setup.EventAllLocked:
			e.Action = ActionSetupLockedAll
			e.Detail += "; all clients locked for 15 minutes"
		default:
			return
		}
		appendAudit(context.Background(), st, log, e)
	}
}

// housekeeping removes expired sessions and enrollment tokens hourly.
func housekeeping(ctx context.Context, st *store.Store, a *auth.Service, now func() time.Time, log *slog.Logger) {
	t := time.NewTicker(housekeepingInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := a.Sessions().Cleanup(ctx); err != nil && ctx.Err() == nil {
				log.Warn("session cleanup failed", "err", err)
			}
			if _, err := st.DeleteExpiredEnrollTokens(ctx, now()); err != nil && ctx.Err() == nil {
				log.Warn("enrollment token cleanup failed", "err", err)
			}
		}
	}
}

// defaultAgentHost is the address agents use until the setup wizard sets one:
// <hostname>.local (mDNS), which the server certificate always covers.
func defaultAgentHost() string {
	h, err := os.Hostname()
	if err != nil {
		return "localhost"
	}
	h = strings.ToLower(strings.TrimSpace(h))
	if i := strings.IndexByte(h, '.'); i > 0 {
		h = h[:i]
	}
	if !shortHostRe.MatchString(h) {
		return "localhost"
	}
	return h + ".local"
}

// portOf returns the TCP port of a listener address.
func portOf(a net.Addr) (int, error) {
	_, p, err := net.SplitHostPort(a.String())
	if err != nil {
		return 0, fmt.Errorf("cannot determine the listen port from %q", a)
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		return 0, fmt.Errorf("cannot determine the listen port from %q", a)
	}
	return n, nil
}

func orDefault(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}

// waitTimeout waits for wg for at most d.
func waitTimeout(wg *sync.WaitGroup, d time.Duration) {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(d):
	}
}

var shortHostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
