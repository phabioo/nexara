package grid

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/protocol"
)

// agentConn is one live WebSocket to an agent.
type agentConn struct {
	ws     *websocket.Conn
	ctx    context.Context
	cancel context.CancelFunc
	wto    time.Duration

	closeOnce sync.Once
	last      atomic.Int64 // unix nanos of the last sign of life (message or pong)

	mu      sync.Mutex
	closed  bool
	pending map[string]chan protocol.Envelope
	shells  map[string]*shellSession
}

func newAgentConn(ctx context.Context, ws *websocket.Conn, writeTimeout time.Duration) *agentConn {
	cctx, cancel := context.WithCancel(ctx)
	c := &agentConn{
		ws: ws, ctx: cctx, cancel: cancel, wto: writeTimeout,
		pending: map[string]chan protocol.Envelope{},
		shells:  map[string]*shellSession{},
	}
	c.touch()
	return c
}

func (c *agentConn) touch() { c.last.Store(time.Now().UnixNano()) }

func (c *agentConn) idleFor() time.Duration { return time.Since(time.Unix(0, c.last.Load())) }

// close tears the connection down without waiting for the peer.
func (c *agentConn) close() {
	c.closeOnce.Do(func() {
		c.cancel()
		_ = c.ws.CloseNow()
	})
}

func (c *agentConn) send(typ, id string, data any) error {
	b, err := protocol.Encode(typ, id, data)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(c.ctx, c.wto)
	defer cancel()
	return c.ws.Write(ctx, websocket.MessageText, b)
}

// deliver hands an answer to the request waiting for env.ID; it reports whether somebody was waiting.
func (c *agentConn) deliver(env protocol.Envelope) bool {
	if env.ID == "" {
		return false
	}
	c.mu.Lock()
	ch, ok := c.pending[env.ID]
	delete(c.pending, env.ID)
	c.mu.Unlock()
	if ok {
		ch <- env // buffered, one answer per request
	}
	return ok
}

// request sends a message with a fresh correlation ID and waits for the
// answer. An "error" answer is returned as an error.
func (c *agentConn) request(ctx context.Context, typ string, data any, timeout time.Duration) (protocol.Envelope, error) {
	id := store.NewID()
	ch := make(chan protocol.Envelope, 1)
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return protocol.Envelope{}, ErrHostOffline
	}
	c.pending[id] = ch
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
	}()

	if err := c.send(typ, id, data); err != nil {
		if c.ctx.Err() != nil {
			return protocol.Envelope{}, ErrHostOffline
		}
		return protocol.Envelope{}, fmt.Errorf("grid: send %s: %w", typ, err)
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case env := <-ch:
		if env.Type == protocol.TypeError {
			e, err := protocol.DecodeData[protocol.Error](env)
			if err != nil {
				return env, fmt.Errorf("grid: %s failed on the agent", typ)
			}
			return env, mapAgentError(e)
		}
		return env, nil
	case <-timer.C:
		return protocol.Envelope{}, fmt.Errorf("grid: no answer to %s within %s: %w", typ, timeout, context.DeadlineExceeded)
	case <-ctx.Done():
		return protocol.Envelope{}, ctx.Err()
	case <-c.ctx.Done():
		return protocol.Envelope{}, ErrHostOffline
	}
}

func mapAgentError(e protocol.Error) error {
	switch e.Code {
	case protocol.CodeCapabilityDisabled:
		return fmt.Errorf("%w: %s", ErrCapabilityDisabled, e.Message)
	case protocol.CodeInvalidArgument:
		return fmt.Errorf("%w: %s", ErrInvalidArgument, e.Message)
	case protocol.CodeUnsupported:
		return fmt.Errorf("%w: %s", ErrUnsupported, e.Message)
	}
	return e
}

// resultErr turns a "result" answer into an error (nil when ok).
func resultErr(env protocol.Envelope, what string) error {
	if env.Type != protocol.TypeResult {
		return fmt.Errorf("grid: unexpected %q answer to %s", env.Type, what)
	}
	res, err := protocol.DecodeData[protocol.Result](env)
	if err != nil {
		return fmt.Errorf("grid: bad answer to %s: %w", what, err)
	}
	if !res.OK {
		if res.Error == "" {
			return fmt.Errorf("grid: %s rejected by the agent", what)
		}
		return fmt.Errorf("grid: %s rejected by the agent: %s", what, res.Error)
	}
	return nil
}

// addShell registers a session; false if the connection is already closed.
func (c *agentConn) addShell(s *shellSession) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false
	}
	c.shells[s.id] = s
	return true
}

func (c *agentConn) removeShell(id string) {
	c.mu.Lock()
	delete(c.shells, id)
	c.mu.Unlock()
}

func (c *agentConn) shell(id string) *shellSession {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.shells[id]
}

// markClosed refuses new requests and sessions and returns the open sessions.
func (c *agentConn) markClosed() []*shellSession {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	out := make([]*shellSession, 0, len(c.shells))
	for _, s := range c.shells {
		out = append(out, s)
	}
	return out
}

// AgentHandler serves GET /grid/connect: the agent WebSocket. The agent is
// identified from its verified client certificate.
func (g *Grid) AgentHandler() http.Handler {
	return http.HandlerFunc(g.serveAgent)
}

func (g *Grid) serveAgent(w http.ResponseWriter, r *http.Request) {
	st, err := g.authenticate(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ws, err := websocket.Accept(w, r, nil)
	if err != nil {
		return // Accept has answered the request
	}
	ws.SetReadLimit(protocol.MaxMessageSize)
	c := newAgentConn(g.ctx, ws, g.to.write)
	defer c.close()

	hello, ok := g.handshake(st, c)
	if !ok {
		return
	}
	g.accept(st, c, hello)
	go g.watchdog(c)
	go g.pinger(st, c)
	g.readLoop(st, c)
	g.connClosed(st, c)
}

// handshake reads the hello and answers it. ok is true when the agent was accepted (ack sent).
func (g *Grid) handshake(st *hostState, c *agentConn) (hello protocol.Hello, ok bool) {
	hctx, cancel := context.WithTimeout(c.ctx, g.to.hello)
	typ, data, err := c.ws.Read(hctx)
	cancel()
	if err != nil {
		return hello, false
	}
	env, err := protocol.Decode(data)
	if err != nil || typ != websocket.MessageText || env.Type != protocol.TypeHello {
		_ = c.ws.Close(websocket.StatusPolicyViolation, "expected hello")
		return hello, false
	}
	hello, herr := protocol.DecodeData[protocol.Hello](env)
	if !env.Compatible() || herr != nil || !protocol.Compatible(hello.ProtocolVersion) {
		g.rejectIncompatible(st, c, env, hello, herr)
		return hello, false
	}
	if err := c.send(protocol.TypeHelloAck, env.ID, protocol.HelloAck{Accepted: true}); err != nil {
		return hello, false
	}
	return hello, true
}

func (g *Grid) rejectIncompatible(st *hostState, c *agentConn, env protocol.Envelope, hello protocol.Hello, herr error) {
	reason := fmt.Sprintf("protocol version %d is not supported, hub speaks %d", env.V, protocol.ProtocolVersion)
	if herr != nil {
		reason = "malformed hello"
	}
	_ = c.send(protocol.TypeHelloAck, env.ID, protocol.HelloAck{
		Accepted: false, Reason: reason, UpdateRequired: true, TargetVersion: g.opts.HubVersion,
	})
	g.log.Info("agent rejected", "host", st.name, "agent_version", hello.AgentVersion, "reason", reason)

	g.mu.Lock()
	st.updateRequired = true
	if hello.AgentVersion != "" {
		st.host.AgentVersion = hello.AgentVersion
	}
	if hello.OS != "" && hello.Arch != "" {
		st.host.OS, st.host.Arch = hello.OS, hello.Arch
	}
	status := g.statusLocked(st)
	push := false
	if herr == nil && hello.OS != "" && hello.Arch != "" && time.Since(st.lastAutoUpdate) >= autoUpdateBackoff {
		if _, ok := g.opts.AgentBinary(hello.OS, hello.Arch); ok {
			st.lastAutoUpdate = time.Now()
			push = true
		}
	}
	g.mu.Unlock()
	g.saveStatus(st.id, status)
	if push {
		g.pushUpdateOnRejected(st, c, hello)
	}
	_ = c.ws.Close(websocket.StatusPolicyViolation, "update required")
}

// pushUpdateOnRejected sends agent.update on the connection of a rejected
// agent (which stays open for a short window for exactly this) and waits for
// its result. There is no read loop yet, so it reads the answer itself.
func (g *Grid) pushUpdateOnRejected(st *hostState, c *agentConn, hello protocol.Hello) {
	bin, ok := g.opts.AgentBinary(hello.OS, hello.Arch)
	if !ok {
		return
	}
	msg := protocol.AgentUpdate{Version: g.opts.HubVersion, SHA256: bin.SHA256, Path: "/grid/agent/" + bin.OS + "/" + bin.Arch}
	id := store.NewID()
	err := c.send(protocol.TypeAgentUpdate, id, msg)
	if err == nil {
		ctx, cancel := context.WithTimeout(c.ctx, g.to.update)
		defer cancel()
		for {
			_, data, rerr := c.ws.Read(ctx)
			if rerr != nil {
				err = fmt.Errorf("grid: no answer to agent.update: %w", rerr)
				break
			}
			env, derr := protocol.Decode(data)
			if derr != nil || env.ID != id {
				continue
			}
			err = resultErr(env, "agent update")
			break
		}
	}
	g.audit(store.AuditEntry{User: SystemActor.Operator, Host: st.name, Action: "agent.update", Detail: msg.Version, Result: auditResult(err)})
	if err != nil {
		g.log.Warn("grid: update of rejected agent failed", "host", st.name, "err", err)
	}
}

func (g *Grid) statusLocked(st *hostState) store.HostStatus {
	return store.HostStatus{
		Address:      st.host.Address,
		OS:           st.host.OS,
		Arch:         st.host.Arch,
		AgentVersion: st.host.AgentVersion,
		MAC:          st.host.MAC,
		Capabilities: slices.Clone(st.host.Capabilities),
		LastSeenAt:   g.now(),
	}
}

func (g *Grid) saveStatus(id HostID, status store.HostStatus) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := g.opts.Store.UpdateHostStatus(ctx, string(id), status); err != nil && !errors.Is(err, store.ErrNotFound) {
		g.log.Warn("grid: saving host status failed", "host", string(id), "err", err)
	}
}

// accept installs c as the host's connection (replacing an older one), stores
// the host facts and emits host_online.
func (g *Grid) accept(st *hostState, c *agentConn, hello protocol.Hello) {
	g.mu.Lock()
	old := st.conn
	st.conn = c
	st.online = true
	st.updateRequired = false
	st.latency = 0
	st.lastSeen = g.now()
	st.model, st.kernel = hello.Model, hello.Kernel
	st.host.OS, st.host.Arch = hello.OS, hello.Arch
	st.host.AgentVersion = hello.AgentVersion
	st.host.MAC = hello.MAC
	st.host.Capabilities = slices.Clone(hello.Capabilities)
	status := g.statusLocked(st)
	g.emitLocked(Event{Kind: EventHostOnline, Host: st.id, Payload: st.infoLocked()})
	g.mu.Unlock()

	if old != nil {
		old.close()
	}
	g.saveStatus(st.id, status)
	g.log.Info("agent connected", "host", st.name, "version", hello.AgentVersion)
	go g.onConnect(st, hello)
}

// onConnect refreshes services and packages and pushes an update to an old agent.
func (g *Grid) onConnect(st *hostState, hello protocol.Hello) {
	if hasCap(hello.Capabilities, protocol.CapServices) {
		if err := g.RefreshServices(g.ctx, st.id); err != nil {
			g.log.Debug("grid: initial services refresh failed", "host", st.name, "err", err)
		}
	}
	if hasCap(hello.Capabilities, protocol.CapPackages) {
		if err := g.RefreshPackages(g.ctx, st.id); err != nil {
			g.log.Debug("grid: initial packages refresh failed", "host", st.name, "err", err)
		}
	}
	g.maybeAutoUpdate(st.id, hello)
}

func (g *Grid) readLoop(st *hostState, c *agentConn) {
	for {
		typ, data, err := c.ws.Read(c.ctx)
		if err != nil {
			return
		}
		c.touch()
		if typ != websocket.MessageText {
			_ = c.send(protocol.TypeError, "", protocol.Error{Code: protocol.CodeBadRequest, Message: "binary frames are not supported"})
			continue
		}
		env, err := protocol.Decode(data)
		if err != nil {
			_ = c.send(protocol.TypeError, "", protocol.Error{Code: protocol.CodeBadRequest, Message: "malformed message"})
			continue
		}
		g.dispatch(st, c, env)
	}
}

// dispatch must not block on agent answers: it runs on the read loop.
func (g *Grid) dispatch(st *hostState, c *agentConn, env protocol.Envelope) {
	switch env.Type {
	case protocol.TypeMetrics:
		g.onMetrics(st, c, env)
	case protocol.TypeServices, protocol.TypePackages, protocol.TypeResult, protocol.TypeError:
		if !c.deliver(env) {
			g.log.Debug("grid: unmatched answer", "host", st.name, "type", env.Type)
		}
	case protocol.TypeJobOutput:
		g.onJobOutput(st, env)
	case protocol.TypeJobDone:
		g.onJobDone(st, c, env)
	case protocol.TypeShellData:
		if d, err := protocol.DecodeData[protocol.ShellData](env); err == nil {
			if s := c.shell(d.SessionID); s != nil {
				s.deliver(d.Data)
			}
		}
	case protocol.TypeShellClose:
		if d, err := protocol.DecodeData[protocol.ShellClose](env); err == nil {
			if s := c.shell(d.SessionID); s != nil {
				s.remoteClosed("closed by agent")
			}
		}
	default:
		code, msg := protocol.CodeUnknownType, "unknown message type"
		if protocol.KnownType(env.Type) {
			code, msg = protocol.CodeBadRequest, "message not expected from an agent"
		}
		_ = c.send(protocol.TypeError, env.ID, protocol.Error{Code: code, Message: msg})
	}
}

func (g *Grid) onMetrics(st *hostState, c *agentConn, env protocol.Envelope) {
	m, err := protocol.DecodeData[protocol.Metrics](env)
	if err != nil {
		_ = c.send(protocol.TypeError, env.ID, protocol.Error{Code: protocol.CodeBadRequest, Message: "malformed metrics"})
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if st.conn != c {
		return // replaced connection
	}
	st.metrics = cloneMetrics(&m)
	st.history = append(st.history, m.CPUPercent)
	if over := len(st.history) - g.opts.HistoryLen; over > 0 {
		st.history = slices.Delete(st.history, 0, over)
	}
	st.lastSeen = g.now()
	g.emitLocked(Event{Kind: EventMetrics, Host: st.id, Payload: *cloneMetrics(&m)})
}

// watchdog closes a connection that has been silent for OfflineAfter.
func (g *Grid) watchdog(c *agentConn) {
	iv := max(g.opts.OfflineAfter/4, 5*time.Millisecond)
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
			if c.idleFor() > g.opts.OfflineAfter {
				c.close()
				return
			}
		}
	}
}

// pinger measures the round trip time with WebSocket pings; a missing pong ends the connection.
func (g *Grid) pinger(st *hostState, c *agentConn) {
	t := time.NewTicker(g.opts.PingInterval)
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
		}
		start := time.Now()
		ctx, cancel := context.WithTimeout(c.ctx, max(g.opts.PingInterval, g.opts.OfflineAfter))
		err := c.ws.Ping(ctx)
		cancel()
		if err != nil {
			c.close()
			return
		}
		c.touch()
		lat := max(time.Since(start), time.Microsecond)
		g.mu.Lock()
		if st.conn == c {
			st.latency = lat
		}
		g.mu.Unlock()
	}
}

// connClosed cleans up after a connection ended: host offline (if c was the
// current connection), running and queued jobs failed, shell sessions ended.
func (g *Grid) connClosed(st *hostState, c *agentConn) {
	c.close()
	shells := c.markClosed()

	var entries []store.AuditEntry
	var touch time.Time
	g.mu.Lock()
	current := st.conn == c
	if current {
		st.conn = nil
		st.online = false
		st.latency = 0
		st.lastSeen = g.now()
		touch = st.lastSeen
		g.emitLocked(Event{Kind: EventHostOffline, Host: st.id, Payload: st.infoLocked()})
	}
	for _, rec := range slices.Clone(st.queue) {
		if current || rec.conn == c {
			if e, ok := g.finishLocked(st, rec, jobOutcome{state: JobFailed, err: "agent disconnected"}); ok {
				entries = append(entries, e)
			}
		}
	}
	g.mu.Unlock()

	for _, e := range entries {
		g.audit(e)
	}
	for _, s := range shells {
		s.remoteClosed("agent disconnected")
	}
	if current {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := g.opts.Store.TouchHost(ctx, string(st.id), touch); err != nil && !errors.Is(err, store.ErrNotFound) {
			g.log.Warn("grid: touch host failed", "host", st.name, "err", err)
		}
		cancel()
		g.log.Info("agent disconnected", "host", st.name)
	}
}
