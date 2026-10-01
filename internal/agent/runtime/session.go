package runtime

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/phabioo/nexara/internal/agent/shell"
	"github.com/phabioo/nexara/internal/protocol"
)

// session is the state of one hub connection. Everything it starts ends with
// the connection: jobs are cancelled, shells closed, goroutines joined.
type session struct {
	a    *Agent
	conn *websocket.Conn

	// ctx ends when the connection is over (or the agent shuts down).
	ctx    context.Context
	cancel context.CancelFunc

	out chan []byte    // the single writer goroutine drains this
	sem chan struct{}  // bounds concurrently running slow requests
	wg  sync.WaitGroup // all goroutines of this session

	// limited: the hub refused us with update_required; only agent.update is served.
	limited bool

	jobMu sync.Mutex
	job   *runningJob

	shMu   sync.Mutex
	shells map[string]*shellState
}

type runningJob struct {
	id     string
	cancel context.CancelFunc
}

type shellState struct {
	sess  shell.Session
	input chan []byte
	done  chan struct{} // closed when the session ends
}

func newSession(a *Agent, conn *websocket.Conn) *session {
	ctx, cancel := context.WithCancel(context.Background())
	return &session{
		a: a, conn: conn, ctx: ctx, cancel: cancel,
		out:    make(chan []byte, outQueue),
		sem:    make(chan struct{}, maxParallel),
		shells: make(map[string]*shellState),
	}
}

// shutdown stops all work of the session but leaves the socket to the caller.
func (s *session) shutdown() {
	s.cancel()
	if s.a.opts.Shell != nil {
		s.a.opts.Shell.CloseAll()
	}
}

// teardown ends the session and waits for its goroutines.
func (s *session) teardown() {
	s.shutdown()
	s.wg.Wait()
}

// spawn runs fn as part of the session; a panic is logged instead of killing the agent.
func (s *session) spawn(fn func()) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				s.a.log.Error("recovered from panic", "panic", fmt.Sprint(r))
			}
		}()
		fn()
	}()
}

func (s *session) handshake() (protocol.HelloAck, error) {
	ctx, cancel := context.WithTimeout(context.Background(), ackTimeout)
	defer cancel()
	b, err := protocol.Encode(protocol.TypeHello, "hello", s.a.hello())
	if err != nil {
		return protocol.HelloAck{}, err
	}
	if err := s.conn.Write(ctx, websocket.MessageText, b); err != nil {
		return protocol.HelloAck{}, fmt.Errorf("send hello: %w", err)
	}
	// Waiting for the ack follows the session, so a shutdown during the
	// handshake ends it at once instead of after ackTimeout (the reader holds
	// the lock Close needs for its close handshake).
	rctx, rcancel := context.WithTimeout(s.ctx, ackTimeout)
	defer rcancel()
	for {
		_, data, err := s.conn.Read(rctx)
		if err != nil {
			return protocol.HelloAck{}, fmt.Errorf("wait for hello.ack: %w", err)
		}
		env, err := protocol.Decode(data)
		if err != nil || env.Type != protocol.TypeHelloAck {
			continue
		}
		ack, err := protocol.DecodeData[protocol.HelloAck](env)
		if err != nil {
			return protocol.HelloAck{}, err
		}
		return ack, nil
	}
}

// start launches the writer and the metrics pump.
func (s *session) start() {
	s.spawn(s.writeLoop)
	if !s.limited && s.a.has(protocol.CapMonitoring) {
		s.spawn(s.metricsPump)
	}
}

// writeLoop is the only goroutine writing to the socket.
func (s *session) writeLoop() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case b := <-s.out:
			// Not derived from s.ctx: coder/websocket tears the connection down
			// when a write's context is cancelled, so a shutdown racing an
			// in-flight write would skip the normal close handshake.
			ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
			err := s.conn.Write(ctx, websocket.MessageText, b)
			cancel()
			if err != nil {
				s.cancel() // the watcher closes the socket, the reader then fails
				return
			}
		}
	}
}

// readLoop reads and dispatches frames until the connection fails. coder/websocket
// answers pings and handles close frames while a Read is pending.
func (s *session) readLoop() error {
	ctx := context.Background()
	if s.limited {
		c, cancel := context.WithTimeout(ctx, limitedModeTimeout)
		defer cancel()
		ctx = c
	}
	for {
		_, data, err := s.conn.Read(ctx)
		if err != nil {
			return err
		}
		env, err := protocol.Decode(data)
		if err != nil {
			s.a.log.Warn("dropping malformed frame", "error", err)
			continue
		}
		s.dispatch(env)
	}
}

// send queues one message for the writer. It blocks only while the bounded
// queue is full and returns an error once the session is over.
func (s *session) send(msgType, id string, data any) error {
	b, err := protocol.Encode(msgType, id, data)
	if err != nil {
		s.a.log.Error("encode message", "type", msgType, "error", err)
		return err
	}
	select {
	case s.out <- b:
		return nil
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}

func (s *session) result(id string, err error) {
	r := protocol.Result{OK: err == nil}
	if err != nil {
		r.Error = safeMessage(err)
	}
	_ = s.send(protocol.TypeResult, id, r)
}

func (s *session) resultMsg(id, msg string) {
	_ = s.send(protocol.TypeResult, id, protocol.Result{Error: msg})
}

func (s *session) fail(id, code, msg string) {
	_ = s.send(protocol.TypeError, id, protocol.Error{Code: code, Message: msg})
}

// safeMessage reduces an error to one short line for the hub. Details stay in
// the agent's log.
func safeMessage(err error) string {
	msg := err.Error()
	if i := strings.IndexAny(msg, "\r\n"); i >= 0 {
		msg = msg[:i]
	}
	if r := []rune(msg); len(r) > 200 {
		msg = string(r[:200]) + "..."
	}
	return msg
}

// need answers with capability_disabled and returns false if the capability is off.
func (s *session) need(env protocol.Envelope, capability string) bool {
	if s.a.has(capability) {
		return true
	}
	if env.ID != "" {
		s.fail(env.ID, protocol.CodeCapabilityDisabled, capability+" is disabled on this agent")
	}
	return false
}

func (s *session) dispatch(env protocol.Envelope) {
	if s.limited && env.Type != protocol.TypeAgentUpdate {
		return
	}
	switch env.Type {
	case protocol.TypeServicesList:
		if s.need(env, protocol.CapServices) {
			s.async(env, s.servicesList)
		}
	case protocol.TypeServiceRestart:
		if s.need(env, protocol.CapServices) {
			s.async(env, s.serviceRestart)
		}
	case protocol.TypePackagesList:
		if s.need(env, protocol.CapPackages) {
			s.async(env, s.packagesList)
		}
	case protocol.TypePackagesSearch:
		if s.need(env, protocol.CapPackages) {
			s.async(env, s.packagesSearch)
		}
	case protocol.TypeJobStart:
		if s.need(env, protocol.CapPackages) {
			s.jobStart(env)
		}
	case protocol.TypeJobCancel:
		if s.need(env, protocol.CapPackages) {
			s.jobCancel(env)
		}
	case protocol.TypeShellOpen:
		if s.need(env, protocol.CapShell) {
			s.shellOpen(env)
		}
	case protocol.TypeShellData:
		if s.need(env, protocol.CapShell) {
			s.shellData(env)
		}
	case protocol.TypeShellResize:
		if s.need(env, protocol.CapShell) {
			s.shellResize(env)
		}
	case protocol.TypeShellClose:
		if s.need(env, protocol.CapShell) {
			s.shellCloseFromHub(env)
		}
	case protocol.TypeAgentUpdate:
		s.agentUpdate(env)
	case protocol.TypeResult, protocol.TypeError, protocol.TypeHelloAck:
		// Answers to nothing we asked; never answer them (no error ping-pong).
	default:
		s.fail(env.ID, protocol.CodeUnknownType, "unknown message type "+quoteShort(env.Type))
	}
}

func quoteShort(t string) string {
	if len(t) > 40 {
		t = t[:40] + "..."
	}
	return fmt.Sprintf("%q", t)
}

// async runs a slow handler off the reader goroutine, bounded by sem.
func (s *session) async(env protocol.Envelope, fn func(protocol.Envelope)) {
	select {
	case s.sem <- struct{}{}:
	default:
		s.fail(env.ID, protocol.CodeBusy, "too many concurrent requests")
		return
	}
	s.spawn(func() {
		defer func() { <-s.sem }()
		fn(env)
	})
}

func decode[T any](s *session, env protocol.Envelope) (T, bool) {
	v, err := protocol.DecodeData[T](env)
	if err != nil {
		s.fail(env.ID, protocol.CodeBadRequest, safeMessage(err))
		return v, false
	}
	return v, true
}

// ---- services ----

func (s *session) servicesList(env protocol.Envelope) {
	res, err := s.a.opts.Services.List(s.ctx)
	if err != nil {
		s.a.log.Warn("services.list failed", "error", err)
		s.result(env.ID, err)
		return
	}
	if res.Units == nil {
		res.Units = []protocol.ServiceUnit{}
	}
	_ = s.send(protocol.TypeServices, env.ID, res)
}

func (s *session) serviceRestart(env protocol.Envelope) {
	req, ok := decode[protocol.ServiceRestart](s, env)
	if !ok {
		return
	}
	err := s.a.opts.Services.Restart(s.ctx, req.Unit)
	if err != nil {
		s.a.log.Warn("service.restart failed", "unit", req.Unit, "error", err)
	}
	s.result(env.ID, err)
}

// ---- packages ----

func (s *session) packagesList(env protocol.Envelope) {
	res, err := s.a.opts.Packages.List(s.ctx)
	if err != nil {
		s.a.log.Warn("packages.list failed", "error", err)
		s.result(env.ID, err)
		return
	}
	if res.Items == nil {
		res.Items = []protocol.Package{}
	}
	_ = s.send(protocol.TypePackages, env.ID, res)
}

func (s *session) packagesSearch(env protocol.Envelope) {
	req, ok := decode[protocol.PackagesSearch](s, env)
	if !ok {
		return
	}
	items, err := s.a.opts.Packages.Search(s.ctx, req.Query)
	if err != nil {
		s.a.log.Warn("packages.search failed", "error", err)
		s.result(env.ID, err)
		return
	}
	if items == nil {
		items = []protocol.Package{}
	}
	if len(items) > protocol.MaxSearchResults {
		items = items[:protocol.MaxSearchResults]
	}
	_ = s.send(protocol.TypePackages, env.ID, protocol.Packages{Items: items})
}

// ---- jobs ----

func (s *session) jobStart(env protocol.Envelope) {
	req, ok := decode[protocol.JobStart](s, env)
	if !ok {
		return
	}
	switch {
	case req.JobID == "":
		s.resultMsg(env.ID, "job_id is required")
		return
	case !req.Kind.Valid():
		s.resultMsg(env.ID, "unknown job kind")
		return
	case req.Kind.NeedsPackage() && req.Package == "":
		s.resultMsg(env.ID, "package is required for this job kind")
		return
	}

	s.jobMu.Lock()
	if s.job != nil {
		s.jobMu.Unlock()
		s.resultMsg(env.ID, "a job is already running")
		return
	}
	jctx, cancel := context.WithCancel(s.ctx)
	s.job = &runningJob{id: req.JobID, cancel: cancel}
	s.jobMu.Unlock()

	// The accept result is queued before the job can produce output.
	if err := s.send(protocol.TypeResult, env.ID, protocol.Result{OK: true}); err != nil {
		s.clearJob()
		cancel()
		return
	}
	s.spawn(func() { s.runJob(jctx, cancel, req) })
}

func (s *session) clearJob() {
	s.jobMu.Lock()
	s.job = nil
	s.jobMu.Unlock()
}

func (s *session) runJob(ctx context.Context, cancel context.CancelFunc, req protocol.JobStart) {
	defer cancel()
	var done protocol.JobDone
	func() {
		defer func() {
			if r := recover(); r != nil {
				s.a.log.Error("job panicked", "job", req.JobID, "panic", fmt.Sprint(r))
				done = protocol.JobDone{OK: false, ExitCode: -1, Error: "internal error"}
			}
		}()
		done = s.a.opts.Packages.Run(ctx, req, func(o protocol.JobOutput) {
			o.JobID = req.JobID
			_ = s.send(protocol.TypeJobOutput, "", o)
		})
	}()
	done.JobID = req.JobID
	// Free the slot first: the hub may send the next job right after job.done.
	s.clearJob()
	if s.ctx.Err() != nil {
		return // disconnected: the hub fails the job itself
	}
	_ = s.send(protocol.TypeJobDone, "", done)
}

func (s *session) jobCancel(env protocol.Envelope) {
	req, ok := decode[protocol.JobCancel](s, env)
	if !ok {
		return
	}
	s.jobMu.Lock()
	j := s.job
	s.jobMu.Unlock()
	if j == nil || j.id != req.JobID {
		s.resultMsg(env.ID, "no such running job")
		return
	}
	// Answer first so the result precedes the job's job.done on the wire.
	s.result(env.ID, nil)
	j.cancel()
}

// ---- shell ----

func shellErrMessage(err error) string {
	switch {
	case errors.Is(err, shell.ErrTooManySessions):
		return "too many open shells"
	case errors.Is(err, shell.ErrSessionExists):
		return "session id already in use"
	case errors.Is(err, shell.ErrInvalidSize):
		return "invalid terminal size"
	case errors.Is(err, shell.ErrRootRefused):
		return "shell is not available for this user"
	case errors.Is(err, shell.ErrNotSupported):
		return "shell is not supported on this platform"
	}
	return "could not open shell"
}

func (s *session) shellOpen(env protocol.Envelope) {
	req, ok := decode[protocol.ShellOpen](s, env)
	if !ok {
		return
	}
	if req.SessionID == "" {
		s.resultMsg(env.ID, "session_id is required")
		return
	}
	sess, err := s.a.opts.Shell.Open(req.SessionID, req.Cols, req.Rows)
	if err != nil {
		s.a.log.Warn("shell.open failed", "error", err)
		s.resultMsg(env.ID, shellErrMessage(err))
		return
	}
	st := &shellState{sess: sess, input: make(chan []byte, shellInputQueue), done: make(chan struct{})}
	s.shMu.Lock()
	s.shells[req.SessionID] = st
	s.shMu.Unlock()

	if err := s.send(protocol.TypeResult, env.ID, protocol.Result{OK: true}); err != nil {
		s.endShell(req.SessionID, "")
		return
	}
	id := req.SessionID
	s.spawn(func() { s.shellPump(id, st) })
	s.spawn(func() { s.shellInput(st) })
}

// endShell removes the session, frees its slot and, if reason is not empty,
// tells the hub. It reports whether this call ended the session (false means
// someone else already did).
func (s *session) endShell(id, reason string) bool {
	s.shMu.Lock()
	st, ok := s.shells[id]
	delete(s.shells, id)
	s.shMu.Unlock()
	if !ok {
		return false
	}
	close(st.done)
	_ = s.a.opts.Shell.Close(id) // closes the PTY and frees the slot
	if reason != "" {
		_ = s.send(protocol.TypeShellClose, "", protocol.ShellClose{SessionID: id, Reason: reason})
	}
	return true
}

// shellPump forwards terminal output to the hub until the shell exits.
func (s *session) shellPump(id string, st *shellState) {
	buf := make([]byte, protocol.MaxShellChunk)
	for {
		n, err := st.sess.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			if s.send(protocol.TypeShellData, "", protocol.ShellData{SessionID: id, Data: chunk}) != nil {
				return
			}
		}
		if err != nil {
			// Reports only if the shell ended on its own; a close from the hub or
			// a teardown has already removed the session.
			s.endShell(id, "shell exited")
			return
		}
	}
}

// shellInput writes keyboard input to the PTY so a slow PTY never blocks the reader.
func (s *session) shellInput(st *shellState) {
	for {
		select {
		case b := <-st.input:
			if _, err := st.sess.Write(b); err != nil {
				return // the pump sees the shell end and reports it
			}
		case <-st.done:
			return
		case <-s.ctx.Done():
			return
		}
	}
}

func (s *session) shellGet(id string) (*shellState, bool) {
	s.shMu.Lock()
	defer s.shMu.Unlock()
	st, ok := s.shells[id]
	return st, ok
}

// ackIfRequest answers a message that is normally unsolicited only when the hub
// sent an ID.
func (s *session) ackIfRequest(env protocol.Envelope, err error) {
	if env.ID != "" {
		s.result(env.ID, err)
	}
}

func (s *session) shellData(env protocol.Envelope) {
	req, ok := decode[protocol.ShellData](s, env)
	if !ok {
		return
	}
	st, ok := s.shellGet(req.SessionID)
	if !ok {
		s.ackIfRequest(env, shell.ErrNoSession)
		return
	}
	select {
	case st.input <- req.Data:
		s.ackIfRequest(env, nil)
	default:
		s.a.log.Warn("shell input queue full, closing session")
		s.endShell(req.SessionID, "input overflow")
	}
}

func (s *session) shellResize(env protocol.Envelope) {
	req, ok := decode[protocol.ShellResize](s, env)
	if !ok {
		return
	}
	if err := shell.ValidateSize(req.Cols, req.Rows); err != nil {
		s.ackIfRequest(env, err)
		return
	}
	st, ok := s.shellGet(req.SessionID)
	if !ok {
		s.ackIfRequest(env, shell.ErrNoSession)
		return
	}
	s.ackIfRequest(env, st.sess.Resize(req.Cols, req.Rows))
}

func (s *session) shellCloseFromHub(env protocol.Envelope) {
	req, ok := decode[protocol.ShellClose](s, env)
	if !ok {
		return
	}
	if !s.endShell(req.SessionID, "") {
		s.ackIfRequest(env, shell.ErrNoSession)
		return
	}
	s.ackIfRequest(env, nil)
}

// ---- metrics ----

func (a *Agent) sampleLoop(ctx context.Context) {
	t := time.NewTicker(a.interval)
	defer t.Stop()
	failing := false
	for {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		m, err := a.opts.Metrics.Collect(cctx)
		cancel()
		switch {
		case err != nil:
			if !failing {
				a.log.Warn("metrics collection failed", "error", err)
			}
			failing = true
		default:
			failing = false
			if m.Timestamp.IsZero() {
				m.Timestamp = a.now().UTC()
			}
			a.ring.push(m)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// metricsPump sends buffered samples oldest first, then live ones. A sample
// leaves the ring only after it was queued for the writer.
func (s *session) metricsPump() {
	r := s.a.ring
	for {
		for {
			smp, ok := r.peek()
			if !ok {
				break
			}
			if err := s.send(protocol.TypeMetrics, "", smp.m); err != nil {
				return
			}
			r.ack(smp.seq)
		}
		select {
		case <-r.notify:
		case <-s.ctx.Done():
			return
		}
	}
}
