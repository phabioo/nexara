// Package httpserver is the hub's HTTP layer: the security middleware chain
// (headers, client IP, setup gate, authentication, CSRF, panic recovery and
// request logging), route registration, the SSE endpoint and the Nexara Shell
// WebSocket. Pages live in one file per view (view_*.go) so they can be filled
// in independently; this package provides the infrastructure they build on.
//
// Everything the server needs is injected through Options; nothing here reads
// configuration or touches the network on its own.
package httpserver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/phabioo/nexara/internal/hub/auth"
	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/hub/setup"
	"github.com/phabioo/nexara/internal/hub/views"
)

// Timeouts. There is deliberately no global WriteTimeout: SSE and WebSocket
// responses live for hours.
const (
	readHeaderTimeout = 10 * time.Second
	idleTimeout       = 120 * time.Second
	shutdownTimeout   = 10 * time.Second
	maxHeaderBytes    = 64 << 10
)

// SetupDeps bundles the first-run setup pieces (package setup).
type SetupDeps struct {
	Codes    *setup.Codes
	Sessions *setup.Sessions // creates the wizard on Unlock
	Mode     *setup.Mode
	// Commit persists a completed wizard (see SetupCommitFunc). It is nil only
	// in tests; views reach it through Server.commitSetup.
	Commit SetupCommitFunc
	// CA is the hub's certificate authority for the Trust step (QR code,
	// downloads, fingerprint). Nil hides those parts (*pki.CA implements it).
	CA TrustAnchor
}

// Options are the injected dependencies of a Server.
type Options struct {
	Auth     *auth.Service
	Setup    SetupDeps
	Hub      grid.Hub
	Enroller grid.Enroller
	// Renderer is used by the view handlers (wave 3); nil is allowed while the
	// views are stubs.
	Renderer *views.Renderer
	// Static is served under /static/ (web.Static, rooted at web/static).
	Static fs.FS
	// AgentHandler serves /grid/connect and /grid/agent/ (mTLS side, owned by
	// the grid package). EnrollHandler serves /grid/enroll, /grid/install.sh and
	// /grid/download/. Both do their own authentication; nil leaves the paths unmounted.
	AgentHandler  http.Handler
	EnrollHandler http.Handler

	Logger *slog.Logger
	// SSHPublicKey returns the hub's SSH public key (authorized_keys format)
	// shown in the Add-host dialog. Nil means no key is available (empty string).
	SSHPublicKey func() string

	// SecureCookies sets the Secure attribute on the cookies this package sets
	// itself (the login challenge cookie). It must equal the auth.Service and
	// setup.Sessions cookie setting (New rejects a mismatch); false only for
	// the plain-HTTP dev mode.
	SecureCookies bool
	// Now is the clock; defaults to time.Now.
	Now func() time.Time
}

// Server is the hub's HTTP server.
type Server struct {
	auth     *auth.Service
	setup    SetupDeps
	hub      grid.Hub
	enroller grid.Enroller
	renderer *views.Renderer
	static   fs.FS
	agent    http.Handler
	enroll   http.Handler
	log      *slog.Logger
	secure   bool
	now      func() time.Time
	sshKey   func() string

	// sse is the registry view files add their event renderers to.
	sse *EventRegistry

	// Intervals, shortened in tests.
	sseHeartbeat time.Duration
	shellPing    time.Duration

	// streamsDone is closed when the server shuts down so SSE and WebSocket
	// handlers end (http.Server.Shutdown does not cancel running requests).
	streamsDone chan struct{}
	stopStreams sync.Once

	handler http.Handler
}

// New validates the options and builds the server.
func New(o Options) (*Server, error) {
	switch {
	case o.Auth == nil:
		return nil, errors.New("httpserver: Options.Auth is required")
	case o.Hub == nil:
		return nil, errors.New("httpserver: Options.Hub is required")
	case o.Setup.Mode == nil || o.Setup.Sessions == nil || o.Setup.Codes == nil:
		return nil, errors.New("httpserver: Options.Setup (Mode, Sessions, Codes) is required")
	case o.Static == nil:
		return nil, errors.New("httpserver: Options.Static is required")
	}
	// One source for the Secure cookie flag: a mismatch would silently break
	// sign-in (Secure cookies are dropped on plain HTTP) or weaken it.
	if authSecure, setupSecure := o.Auth.Cookies().ClearSession().Secure, o.Setup.Sessions.Cookie("").Secure; authSecure != o.SecureCookies || setupSecure != o.SecureCookies {
		return nil, fmt.Errorf("httpserver: cookie Secure setting differs (Options.SecureCookies=%v, auth=%v, setup=%v)",
			o.SecureCookies, authSecure, setupSecure)
	}
	s := &Server{
		auth: o.Auth, setup: o.Setup, hub: o.Hub, enroller: o.Enroller,
		renderer: o.Renderer, static: o.Static,
		agent: o.AgentHandler, enroll: o.EnrollHandler,
		log: o.Logger, secure: o.SecureCookies, now: o.Now, sshKey: o.SSHPublicKey,
		sse:          newEventRegistry(),
		sseHeartbeat: 15 * time.Second,
		shellPing:    30 * time.Second,
		streamsDone:  make(chan struct{}),
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.now == nil {
		s.now = time.Now
	}
	mux := http.NewServeMux()
	s.routes(mux)
	s.handler = s.chain(mux)
	return s, nil
}

// Handler returns the complete handler including all middleware.
func (s *Server) Handler() http.Handler { return s.handler }

// Serve serves on ln until ctx is cancelled, then shuts down gracefully:
// streams are ended, in-flight requests get shutdownTimeout to finish. With a
// non-nil tlsConfig the listener is wrapped in TLS (the config carries the
// server certificate and the mTLS client-CA settings for /grid/connect).
func (s *Server) Serve(ctx context.Context, ln net.Listener, tlsConfig *tls.Config) error {
	srv := &http.Server{
		Handler:           s.handler,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		TLSConfig:         tlsConfig,
		Protocols:         http1Only(),
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
	errc := make(chan error, 1)
	go func() {
		if tlsConfig != nil {
			errc <- srv.ServeTLS(ln, "", "")
		} else {
			errc <- srv.Serve(ln)
		}
	}()
	select {
	case err := <-errc:
		s.stopStreams.Do(func() { close(s.streamsDone) })
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("httpserver: serve: %w", err)
	case <-ctx.Done():
	}
	s.stopStreams.Do(func() { close(s.streamsDone) })
	shCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shCtx); err != nil {
		_ = srv.Close()
		return fmt.Errorf("httpserver: shutdown: %w", err)
	}
	return nil
}

// http1Only restricts the server to HTTP/1.1: the agent and shell WebSockets
// use the HTTP/1.1 upgrade, which HTTP/2 does not offer.
func http1Only() *http.Protocols {
	var p http.Protocols
	p.SetHTTP1(true)
	return &p
}
