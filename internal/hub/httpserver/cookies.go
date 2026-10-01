package httpserver

import (
	"net/http"

	"github.com/phabioo/nexara/internal/hub/auth"
	"github.com/phabioo/nexara/internal/hub/setup"
)

// Cookie names and attributes of the pre-session cookies (security review
// S-17). Over TLS every cookie carries the __Host- prefix (auth.CookieName),
// which makes the browser refuse a same-named cookie set by another service
// on the same host; the plain-HTTP demo cannot use the prefix.

// loginChallengeBase is the base name of the cookie that carries the TOTP
// challenge ID between the two sign-in steps.
const loginChallengeBase = "nexus_login"

func (s *Server) loginChallengeName() string { return auth.CookieName(loginChallengeBase, s.secure) }

// loginChallengePath: a __Host- cookie must have Path=/; in plain-HTTP mode
// the cookie stays scoped to the login forms.
func (s *Server) loginChallengePath() string {
	if s.secure {
		return "/"
	}
	return "/login"
}

// setupCookieShim gives the setup session cookie (named and built by package
// setup, which does not know about the prefix) its __Host- name on the wire
// without touching that package:
//
//   - requests: a __Host-nexus_setup cookie is presented to the handlers as
//     nexus_setup; a plain nexus_setup cookie is dropped, so it cannot be
//     planted by another service (that is the point of the prefix);
//   - responses: Set-Cookie for nexus_setup is rewritten to __Host-nexus_setup
//     (Secure, Path=/, no Domain).
//
// It applies to the setup paths only, the only place the cookie is used, and
// only when cookies are secure. Once setup.SessionOptions has a cookie-name
// option this shim can go.
func (s *Server) setupCookieShim(next http.Handler) http.Handler {
	if !s.secure {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isSetupPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		shimRequestCookies(r)
		next.ServeHTTP(&setupCookieWriter{ResponseWriter: w}, r)
	})
}

func shimRequestCookies(r *http.Request) {
	cookies := r.Cookies()
	if len(cookies) == 0 {
		return
	}
	r.Header.Del("Cookie")
	prefixed := auth.CookieName(setup.SessionCookie, true)
	for _, c := range cookies {
		switch c.Name {
		case setup.SessionCookie:
			continue // unprefixed: could have been set by anyone on the host
		case prefixed:
			c.Name = setup.SessionCookie
		}
		r.AddCookie(c)
	}
}

// setupCookieWriter renames the setup cookie in Set-Cookie headers just
// before the header is written.
type setupCookieWriter struct {
	http.ResponseWriter
	done bool
}

func (w *setupCookieWriter) rewrite() {
	if w.done {
		return
	}
	w.done = true
	h := w.Header()
	vals := h.Values("Set-Cookie")
	if len(vals) == 0 {
		return
	}
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		c, err := http.ParseSetCookie(v)
		if err != nil || c.Name != setup.SessionCookie {
			out = append(out, v)
			continue
		}
		c.Name = auth.CookieName(setup.SessionCookie, true)
		c.Path, c.Domain, c.Secure = "/", "", true
		out = append(out, c.String())
	}
	h["Set-Cookie"] = out
}

func (w *setupCookieWriter) WriteHeader(code int) {
	if code >= 200 || code == http.StatusSwitchingProtocols {
		w.rewrite()
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *setupCookieWriter) Write(b []byte) (int, error) {
	w.rewrite()
	return w.ResponseWriter.Write(b)
}

func (w *setupCookieWriter) Flush() {
	w.rewrite()
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap serves http.ResponseController.
func (w *setupCookieWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
