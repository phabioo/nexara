// Package runtime is the Grid Agent's main loop: it keeps one WebSocket to the
// hub alive, answers the hub's requests with the enabled capabilities and
// streams metrics. It executes only the fixed set of protocol messages; there
// is no way to run an arbitrary command through it.
package runtime

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/phabioo/nexara/internal/agent/metrics"
	"github.com/phabioo/nexara/internal/agent/packages"
	"github.com/phabioo/nexara/internal/agent/services"
	"github.com/phabioo/nexara/internal/agent/shell"
	"github.com/phabioo/nexara/internal/buildinfo"
	"github.com/phabioo/nexara/internal/config"
	"github.com/phabioo/nexara/internal/protocol"
)

// Timing and size constants of the connection loop.
const (
	minBackoff   = time.Second
	maxBackoff   = 30 * time.Second
	stableAfter  = 60 * time.Second // a connection this old resets the backoff
	ackTimeout   = 10 * time.Second
	dialTimeout  = 15 * time.Second
	writeTimeout = 10 * time.Second
	// limitedModeTimeout bounds how long a connection the hub refused with
	// update_required is kept open to receive agent.update.
	limitedModeTimeout = 30 * time.Second

	bufferWindow    = 10 * time.Minute // metrics kept while disconnected
	outQueue        = 256
	maxParallel     = 8 // concurrently running slow requests (lists, restarts)
	shellInputQueue = 64
	readLimit       = protocol.MaxMessageSize + 4096
)

// DialFunc opens the WebSocket to the hub.
type DialFunc func(ctx context.Context, url string) (*websocket.Conn, error)

// Options configures an Agent. Zero values of the optional fields select the
// production behaviour.
type Options struct {
	Config config.AgentConfig
	// TLS is the mTLS client configuration (pki.AgentTLSConfig). Used by the
	// default Dial and the default HTTPClient.
	TLS *tls.Config

	// Capability implementations. A nil implementation behaves like a disabled
	// capability.
	Metrics  metrics.Collector
	Facts    func() metrics.HostFacts
	Services services.Manager
	Packages packages.Manager
	Shell    *shell.Sessions

	Logger *slog.Logger

	// Now is the clock for connection age; default time.Now.
	Now func() time.Time
	// Sleep waits d or until ctx ends (returns ctx.Err() then). Default: timer.
	Sleep func(ctx context.Context, d time.Duration) error
	// Jitter randomizes a backoff delay. Default: +-20 %.
	Jitter func(d time.Duration) time.Duration
	// Dial opens the WebSocket. Default: coder/websocket over TLS.
	Dial DialFunc
	// HTTPClient downloads agent updates. Default: a client using TLS.
	HTTPClient *http.Client
	// MetricsInterval overrides Config.MetricsInterval() (tests).
	MetricsInterval time.Duration

	// BinaryPath is the running executable (os.Executable) that agent.update replaces.
	BinaryPath string
	// Exit terminates the process after a successful update; default os.Exit.
	Exit func(code int)
}

// Agent is the Grid Agent runtime. Create it with New and call Run once.
type Agent struct {
	opts   Options
	cfg    config.AgentConfig
	log    *slog.Logger
	now    func() time.Time
	sleep  func(ctx context.Context, d time.Duration) error
	jitter func(d time.Duration) time.Duration
	dial   DialFunc
	http   *http.Client
	exit   func(code int)

	ring     *ring
	interval time.Duration

	stop       context.CancelFunc // cancels Run; set by Run
	restarting atomic.Bool        // a verified update was installed
	updating   atomic.Bool
	bg         sync.WaitGroup // background work outliving a connection (updates)
}

// New builds an Agent, filling in defaults for unset options.
func New(opts Options) *Agent {
	a := &Agent{opts: opts, cfg: opts.Config}
	a.log = opts.Logger
	if a.log == nil {
		a.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	a.now = opts.Now
	if a.now == nil {
		a.now = time.Now
	}
	a.sleep = opts.Sleep
	if a.sleep == nil {
		a.sleep = sleepCtx
	}
	a.jitter = opts.Jitter
	if a.jitter == nil {
		a.jitter = defaultJitter
	}
	a.exit = opts.Exit
	if a.exit == nil {
		a.exit = os.Exit
	}
	a.http = opts.HTTPClient
	if a.http == nil {
		a.http = &http.Client{Transport: &http.Transport{
			TLSClientConfig:     tlsClone(opts.TLS),
			TLSHandshakeTimeout: 15 * time.Second,
		}}
	}
	a.dial = opts.Dial
	if a.dial == nil {
		client := &http.Client{Transport: &http.Transport{
			TLSClientConfig:     tlsClone(opts.TLS),
			TLSHandshakeTimeout: 15 * time.Second,
		}}
		a.dial = func(ctx context.Context, url string) (*websocket.Conn, error) {
			c, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPClient: client})
			return c, err
		}
	}
	a.interval = opts.MetricsInterval
	if a.interval <= 0 {
		a.interval = a.cfg.MetricsInterval()
	}
	if a.interval <= 0 {
		a.interval = 2 * time.Second
	}
	a.ring = newRing(int(bufferWindow / a.interval))
	return a
}

func tlsClone(c *tls.Config) *tls.Config {
	if c == nil {
		return nil
	}
	c = c.Clone()
	c.NextProtos = []string{"http/1.1"} // WebSocket needs HTTP/1.1
	return c
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func defaultJitter(d time.Duration) time.Duration {
	return time.Duration(float64(d) * (0.8 + 0.4*rand.Float64()))
}

// has reports whether a capability is enabled in the config and implemented.
func (a *Agent) has(capability string) bool {
	if !a.cfg.Capabilities.Has(capability) {
		return false
	}
	switch capability {
	case protocol.CapMonitoring:
		return a.opts.Metrics != nil
	case protocol.CapServices:
		return a.opts.Services != nil
	case protocol.CapPackages:
		return a.opts.Packages != nil
	case protocol.CapShell:
		return a.opts.Shell != nil
	}
	return false
}

// Run connects to the hub and serves it until ctx is cancelled. It returns nil
// after a graceful shutdown. After a successful agent.update it shuts down the
// same way and then calls Options.Exit(0) so the service manager starts the new
// binary.
func (a *Agent) Run(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	a.stop = cancel

	var sampler sync.WaitGroup
	if a.has(protocol.CapMonitoring) {
		sampler.Add(1)
		go func() {
			defer sampler.Done()
			a.sampleLoop(runCtx)
		}()
	}

	backoff := minBackoff
	for runCtx.Err() == nil {
		stable, err := a.connectOnce(runCtx)
		if runCtx.Err() != nil {
			break
		}
		if stable {
			backoff = minBackoff
		}
		if err != nil {
			a.log.Warn("hub connection ended", "error", err, "retry_in", backoff.String())
		}
		if a.sleep(runCtx, a.jitter(backoff)) != nil {
			break
		}
		backoff = min(backoff*2, maxBackoff)
	}

	cancel()
	sampler.Wait()
	a.bg.Wait()
	if a.restarting.Load() {
		a.log.Info("agent updated, exiting so the service manager starts the new version")
		a.exit(0)
	}
	return nil
}

func (a *Agent) connectOnce(ctx context.Context) (stable bool, err error) {
	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	conn, err := a.dial(dctx, a.cfg.Hub.URL)
	cancel()
	if err != nil {
		return false, fmt.Errorf("dial hub: %w", err)
	}
	conn.SetReadLimit(readLimit)
	return a.serve(ctx, conn)
}

func (a *Agent) hello() protocol.Hello {
	h := protocol.Hello{
		AgentVersion:    buildinfo.Version,
		ProtocolVersion: protocol.ProtocolVersion,
		Capabilities:    a.cfg.Capabilities.Enabled(),
	}
	if h.Capabilities == nil {
		h.Capabilities = []string{}
	}
	if a.opts.Facts != nil {
		f := a.opts.Facts()
		h.Hostname, h.OS, h.Arch, h.Kernel, h.Model, h.MAC = f.Hostname, f.OS, f.Arch, f.Kernel, f.Model, f.MAC
	}
	return h
}

var errRejected = errors.New("hub rejected this agent")

// serve runs one connection from hello to disconnect.
func (a *Agent) serve(runCtx context.Context, conn *websocket.Conn) (stable bool, err error) {
	s := newSession(a, conn)
	watch := make(chan struct{})
	go func() {
		defer close(watch)
		select {
		case <-runCtx.Done():
			// Graceful shutdown: stop all work, then say goodbye properly.
			s.shutdown()
			_ = conn.Close(websocket.StatusNormalClosure, "agent shutting down")
		case <-s.ctx.Done():
			_ = conn.CloseNow()
		}
	}()
	defer func() {
		s.teardown()
		<-watch
	}()

	ack, err := s.handshake()
	if err != nil {
		return false, err
	}
	if !ack.Accepted {
		a.log.Warn("hub did not accept this agent", "reason", ack.Reason)
		if !ack.UpdateRequired {
			return false, fmt.Errorf("%w: %s", errRejected, ack.Reason)
		}
		a.log.Warn("agent update required: this agent is too old for the hub and waits for agent.update",
			"target_version", ack.TargetVersion, "agent_version", buildinfo.Version)
		s.limited = true
	}

	connectedAt := a.now()
	s.start()
	err = s.readLoop()
	stable = ack.Accepted && a.now().Sub(connectedAt) >= stableAfter
	if err == nil || errors.Is(err, context.Canceled) {
		err = errors.New("connection closed")
	}
	return stable, err
}
