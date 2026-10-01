package httpserver

import (
	"context"
	"errors"
	"net/http"

	"github.com/phabioo/nexara/internal/hub/auth"
)

// sessionGuard lets a long-lived handler (event stream, shell WebSocket)
// notice that the session it was opened with has ended: signed out, expired
// (12 h idle, 30 d absolute), cut by "sign out everywhere" or removed by an
// operator reset (security review S-01). The authentication middleware only
// looks at a session when a request starts, so without this an open stream
// would outlive its session indefinitely.
//
// Two triggers: the auth manager's revocation signal (immediate for logout
// and resets) and a periodic alive() call on the handler's own heartbeat
// (the only way to see time-based expiry).
type sessionGuard struct {
	s    *Server
	hash string
	// first is the revocation channel taken before the initial check in
	// guardFor; the first revoked() call hands it out.
	first <-chan struct{}
}

// guardFor returns the guard for the session of an authenticated request.
// It arms the revocation signal and then checks the session once more, so a
// logout between the middleware's check and the stream's start is not lost.
// ok is false when there is no session or it has ended meanwhile.
func (s *Server) guardFor(r *http.Request) (*sessionGuard, bool) {
	sess, ok := SessionFrom(r)
	if !ok {
		return nil, false
	}
	g := &sessionGuard{s: s, hash: sess.IDHash}
	g.first = s.auth.Sessions().Revoked()
	if !g.alive(r.Context()) {
		return nil, false
	}
	return g, true
}

// revoked returns the channel of the next revocation. Take it before calling
// alive, so a revocation in between is not lost.
func (g *sessionGuard) revoked() <-chan struct{} {
	if ch := g.first; ch != nil {
		g.first = nil
		return ch
	}
	return g.s.auth.Sessions().Revoked()
}

// alive reports whether the session is still valid. It does not refresh the
// session's last-seen time (see auth.Manager.CheckHash). A failing store does
// not end the stream: the browser would only reconnect into the same fault.
func (g *sessionGuard) alive(ctx context.Context) bool {
	err := g.s.auth.Sessions().CheckHash(ctx, g.hash)
	switch {
	case err == nil:
		return true
	case errors.Is(err, auth.ErrSessionExpired):
		return false
	case ctx.Err() != nil:
		return true // the stream is ending anyway
	default:
		g.s.log.Error("stream session check failed", "err", err)
		return true
	}
}
