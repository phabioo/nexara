package httpserver

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/phabioo/nexara/internal/hub/auth"
	"github.com/phabioo/nexara/internal/hub/grid"
)

// Terminal size bounds and defaults.
const (
	minCols, maxCols, defCols = 10, 500, 80
	minRows, maxRows, defRows = 5, 200, 24

	shellReadLimit = 64 << 10
	shellBufSize   = 32 << 10
	shellPingWait  = 10 * time.Second

	// shellReasonSessionEnded is the close reason (with code 1008) shell.js
	// recognizes as "sign in again".
	shellReasonSessionEnded = "session ended"
)

// resizeMessage is the only text frame the browser sends.
type resizeMessage struct {
	Type string `json:"type"`
	Cols int    `json:"cols"`
	Rows int    `json:"rows"`
}

func (s *Server) routeShellWS(mux *http.ServeMux) {
	mux.HandleFunc("GET /hosts/{host}/shell/ws", s.handleShellWS)
}

// handleShellWS bridges a browser terminal (xterm.js) to a host shell. Checks
// before the upgrade: session (middleware), host, the session's CSRF token in
// ?csrf= (browsers cannot set headers on a WebSocket) and an exact Origin
// match. Binary frames carry terminal bytes both ways; text frames carry
// {"type":"resize","cols":N,"rows":M}. The grid audits opening the shell.
func (s *Server) handleShellWS(w http.ResponseWriter, r *http.Request) {
	host, ok := s.requireHost(w, r)
	if !ok {
		return
	}
	sess, ok := SessionFrom(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	q := r.URL.Query()
	tok := q.Get("csrf")
	if !s.auth.CheckCSRF(sess, tok) {
		s.log.Warn("shell websocket rejected", "reason", "csrf", "path", logPath(r), "ip", ClientIP(r))
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if !originMatches(r) {
		s.log.Warn("shell websocket rejected", "reason", "origin", "path", logPath(r), "ip", ClientIP(r))
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	cols := clampInt(q.Get("cols"), defCols, minCols, maxCols)
	rows := clampInt(q.Get("rows"), defRows, minRows, maxRows)

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// The exact Origin check above replaced the library's; nothing more to allow.
		OriginPatterns: nil,
	})
	if err != nil {
		return // Accept already answered
	}
	conn.SetReadLimit(shellReadLimit)

	ctx, cancel := contextWithDone(r.Context(), s.streamsDone)
	defer cancel()

	shell, err := s.hub.OpenShell(ctx, ActorFrom(r), host.ID, cols, rows)
	if err != nil {
		code, reason := shellOpenFailure(err)
		if code == websocket.StatusInternalError {
			s.log.Error("open shell failed", "host", host.Name, "err", err)
		}
		_ = conn.Close(code, reason)
		return
	}
	actor := ActorFrom(r)
	guard, ok := s.guardFor(r)
	if !ok { // the session ended while the shell was being opened
		_ = shell.Close()
		s.auth.AuditShellSessionEnded(context.Background(), actor.Operator, host.Name, actor.IP)
		_ = conn.Close(websocket.StatusPolicyViolation, shellReasonSessionEnded)
		return
	}
	s.proxyShell(ctx, conn, shell, guard, func(ctx context.Context) {
		s.auth.AuditShellSessionEnded(ctx, actor.Operator, host.Name, actor.IP)
	})
}

// shellOpenFailure maps an OpenShell error to a WebSocket close code and a
// short reason (at most 123 bytes; never internal details).
func shellOpenFailure(err error) (websocket.StatusCode, string) {
	switch {
	case errors.Is(err, grid.ErrHostOffline):
		return websocket.StatusTryAgainLater, "host offline"
	case errors.Is(err, grid.ErrCapabilityDisabled):
		return websocket.StatusPolicyViolation, "shell disabled on this host"
	case errors.Is(err, grid.ErrHostNotFound):
		return websocket.StatusPolicyViolation, "unknown host"
	default:
		return websocket.StatusInternalError, "could not open shell"
	}
}

// proxyShell copies data until either side ends, then closes both. stopping
// (server shutdown) ends it too, and so does the end of the operator's
// session (guard): the socket is then closed with 1008 and the reason
// "session ended", which shell.js turns into a redirect to /login, and
// onSessionEnded writes the audit entry. The first side to end decides the
// close code; the shell session is always closed.
//
// Socket I/O runs on its own context (io), which is cancelled only after the
// close handshake: cancelling a context during a read or write makes the
// WebSocket library drop the connection without a close frame.
func (s *Server) proxyShell(stopping context.Context, conn *websocket.Conn, shell grid.ShellSession, guard *sessionGuard, onSessionEnded func(context.Context)) {
	sockCtx, stopIO := context.WithCancel(context.Background())
	defer stopIO()
	var (
		once sync.Once
		wg   sync.WaitGroup
	)
	finish := func(code websocket.StatusCode, why string) {
		once.Do(func() {
			_ = shell.Close() // unblocks the shell -> browser reader
			_ = conn.Close(code, why)
		})
	}

	// shell -> browser
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, shellBufSize)
		for {
			n, err := shell.Read(buf)
			if n > 0 {
				if werr := conn.Write(sockCtx, websocket.MessageBinary, buf[:n]); werr != nil {
					finish(websocket.StatusNormalClosure, "")
					return
				}
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					finish(websocket.StatusNormalClosure, "shell exited")
				} else {
					finish(websocket.StatusInternalError, "shell connection lost")
				}
				return
			}
		}
	}()

	sessionEnded := func() {
		onSessionEnded(sockCtx)
		finish(websocket.StatusPolicyViolation, shellReasonSessionEnded)
	}

	// keep-alive, session check and shutdown watcher
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(s.shellPing)
		defer t.Stop()
		revoked := guard.revoked()
		for {
			select {
			case <-sockCtx.Done():
				return
			case <-stopping.Done():
				finish(websocket.StatusGoingAway, "server shutting down")
				return
			case <-revoked:
				revoked = guard.revoked() // re-arm before looking
				if !guard.alive(sockCtx) {
					sessionEnded()
					return
				}
			case <-t.C:
				if !guard.alive(sockCtx) {
					sessionEnded()
					return
				}
				pctx, pcancel := context.WithTimeout(sockCtx, shellPingWait)
				err := conn.Ping(pctx)
				pcancel()
				if err != nil {
					finish(websocket.StatusGoingAway, "ping timeout")
					return
				}
			}
		}
	}()

	// browser -> shell (this goroutine; it also services pings and close frames)
	for {
		typ, data, err := conn.Read(sockCtx)
		if err != nil {
			finish(websocket.StatusNormalClosure, "")
			break
		}
		if typ == websocket.MessageBinary {
			if _, err := shell.Write(data); err != nil {
				finish(websocket.StatusInternalError, "shell write failed")
				break
			}
			continue
		}
		var msg resizeMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			finish(websocket.StatusInvalidFramePayloadData, "invalid control message")
			break
		}
		if msg.Type == "resize" {
			cols := clampValue(msg.Cols, minCols, maxCols)
			rows := clampValue(msg.Rows, minRows, maxRows)
			if err := shell.Resize(cols, rows); err != nil {
				s.log.Debug("shell resize failed", "err", err)
			}
		}
	}
	finish(websocket.StatusNormalClosure, "") // no-op if a reason was already set
	stopIO()
	wg.Wait()
}

// originMatches requires an Origin header whose scheme and host equal this
// request's (https when TLS is terminated here). A missing Origin is rejected:
// browsers always send one on WebSocket handshakes.
func originMatches(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return strings.EqualFold(u.Scheme, scheme) && strings.EqualFold(u.Host, r.Host)
}

func clampInt(raw string, def, lo, hi int) int {
	n, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return clampValue(n, lo, hi)
}

func clampValue(n, lo, hi int) int { return min(max(n, lo), hi) }

// constantTimeEqual is kept for callers comparing opaque tokens.
func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

var _ = auth.CSRFHeader
