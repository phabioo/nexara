package httpserver

import (
	"context"
	"net/http"

	"github.com/phabioo/nexara/internal/hub/auth"
	"github.com/phabioo/nexara/internal/hub/grid"
)

// ensureCSRFCookie returns the pre-session double-submit token for forms
// rendered before a session exists (login, TOTP step, setup wizard), creating
// and setting the cookie if the browser has none. Render the returned value
// into the form's hidden csrf_token field.
func (s *Server) ensureCSRFCookie(w http.ResponseWriter, r *http.Request) (string, error) {
	if c, err := r.Cookie(s.auth.Cookies().CSRFName()); err == nil && validPreSessionToken(c.Value) {
		return c.Value, nil
	}
	tok, err := auth.NewPreSessionCSRF()
	if err != nil {
		return "", err
	}
	http.SetCookie(w, s.auth.Cookies().CSRF(tok))
	return tok, nil
}

// validPreSessionToken accepts only what NewPreSessionCSRF produces (43
// base64url characters), so a garbage cookie gets replaced.
func validPreSessionToken(v string) bool {
	if len(v) != 43 {
		return false
	}
	for _, c := range []byte(v) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// hostByName looks a host up by its unique short name (the URL segment).
func (s *Server) hostByName(name string) (grid.HostInfo, bool) {
	for _, h := range s.hub.Hosts() {
		if h.Name == name {
			return h, true
		}
	}
	return grid.HostInfo{}, false
}

// requireHost resolves the {host} path value. On an unknown host it writes
// the 404 page and returns ok=false; the caller just returns.
func (s *Server) requireHost(w http.ResponseWriter, r *http.Request) (grid.HostInfo, bool) {
	h, ok := s.hostByName(r.PathValue("host"))
	if !ok {
		s.notFound(w, r)
		return grid.HostInfo{}, false
	}
	return h, true
}

// defaultHost is the host GET / shows: the first online host, else the first host.
func (s *Server) defaultHost() (grid.HostInfo, bool) {
	hosts := s.hub.Hosts()
	for _, h := range hosts {
		if h.Online {
			return h, true
		}
	}
	if len(hosts) > 0 {
		return hosts[0], true
	}
	return grid.HostInfo{}, false
}

// operatorName is the signed-in operator's ID ("" on public routes).
func operatorName(r *http.Request) string {
	if u, ok := UserFrom(r); ok {
		return u.OperatorID
	}
	return ""
}

// sshPublicKey is the hub's SSH public key for the Add-host dialog; empty if
// the server was built without one (demo mode shows a sample).
func (s *Server) sshPublicKey() string {
	if s.sshKey == nil {
		return ""
	}
	return s.sshKey()
}

// contextWithDone derives a context that is also cancelled when done closes
// (used to end streams on server shutdown).
func contextWithDone(parent context.Context, done <-chan struct{}) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	go func() {
		select {
		case <-done:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}
