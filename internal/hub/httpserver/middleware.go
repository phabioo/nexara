package httpserver

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/phabioo/nexara/internal/hub/auth"
	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/hub/store"
)

// Content-Security-Policy: no inline scripts or styles, no third parties.
const contentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'"

const maxFormBody = 1 << 20

type ctxKey int

const (
	ctxClientIP ctxKey = iota
	ctxUser
	ctxSession
)

// ClientIP returns the peer address of the request (no proxy headers are trusted).
func ClientIP(r *http.Request) string {
	if ip, ok := r.Context().Value(ctxClientIP).(string); ok {
		return ip
	}
	return remoteHost(r)
}

// UserFrom returns the signed-in operator; ok is false on public routes.
func UserFrom(r *http.Request) (store.User, bool) {
	u, ok := r.Context().Value(ctxUser).(store.User)
	return u, ok
}

// SessionFrom returns the validated session; ok is false on public routes.
func SessionFrom(r *http.Request) (store.Session, bool) {
	s, ok := r.Context().Value(ctxSession).(store.Session)
	return s, ok
}

// withUserSession returns the request context with the user and session of a
// sign-in that happened during this very request (the cookie only arrives
// with the next one).
func withUserSession(r *http.Request, res auth.LoginResult) context.Context {
	ctx := context.WithValue(r.Context(), ctxUser, res.User)
	return context.WithValue(ctx, ctxSession, res.Session)
}

// ActorFrom builds the audit actor (operator and IP) for grid calls.
func ActorFrom(r *http.Request) grid.Actor {
	a := grid.Actor{IP: ClientIP(r)}
	if u, ok := UserFrom(r); ok {
		a.Operator = u.OperatorID
	}
	return a
}

func remoteHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// chain wraps the mux. Order, outermost first: recovery and logging (so a
// panic anywhere still yields a 500 that carries the security headers),
// security headers, client IP, setup cookie names, body limits, setup gate,
// authentication, CSRF.
func (s *Server) chain(h http.Handler) http.Handler {
	h = s.csrf(h)
	h = s.authenticate(h)
	h = s.setupGate(h)
	h = s.bodyLimits(h)
	h = s.setupCookieShim(h)
	h = s.clientIP(h)
	h = s.securityHeaders(h)
	h = s.recoverAndLog(h)
	return h
}

// --- path classes --------------------------------------------------------------

func isStaticPath(p string) bool {
	return strings.HasPrefix(p, "/static/") || p == "/manifest.webmanifest" || p == "/favicon.svg"
}

func isSetupPath(p string) bool { return p == "/setup" || strings.HasPrefix(p, "/setup/") }

func isGridPath(p string) bool { return strings.HasPrefix(p, "/grid/") }

// isLoginPath covers the pre-session login forms.
func isLoginPath(p string) bool { return p == "/login" || p == "/login/verify" }

func isPublicPath(p string) bool {
	return isStaticPath(p) || isLoginPath(p) || isSetupPath(p) || isGridPath(p)
}

// usesDoubleSubmit reports whether state-changing requests on p come before
// a session exists (login, TOTP step, setup wizard).
func usesDoubleSubmit(p string) bool { return isLoginPath(p) || isSetupPath(p) }

func isStreamPath(p string) bool {
	return p == "/events" || strings.HasSuffix(p, "/shell/ws")
}

func isSafeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// --- 1. security headers -------------------------------------------------------

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if r.TLS != nil {
			// Only on TLS responses: browsers ignore it on plain HTTP, and the demo must stay reachable. No
			// includeSubDomains: other services on the host are not ours to pin.
			h.Set("Strict-Transport-Security", "max-age=15552000")
		}
		switch {
		case strings.HasPrefix(r.URL.Path, "/static/") && r.URL.Query().Get("v") != "":
			// Versioned asset URL: the version changes with the content.
			h.Set("Cache-Control", "public, max-age=31536000, immutable")
		case isStaticPath(r.URL.Path):
			h.Set("Cache-Control", "no-cache")
		default:
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// --- 2. client IP --------------------------------------------------------------

func (s *Server) clientIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), ctxClientIP, remoteHost(r))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// --- 3. setup gate -------------------------------------------------------------

func (s *Server) setupGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if s.setup.Mode.Active(r.Context()) {
			switch {
			case isSetupPath(p), isStaticPath(p):
				next.ServeHTTP(w, r)
			case isGridPath(p), p == "/events":
				// The agent endpoint stays closed until an operator exists.
				http.Error(w, "Setup required", http.StatusServiceUnavailable)
			default:
				redirectTo(w, r, "/setup")
			}
			return
		}
		if isSetupPath(p) {
			redirectTo(w, r, "/")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// redirectTo sends the browser to loc: a 303 for navigations, HX-Redirect with
// 401 for HTMX requests (a swapped-in login page would be wrong).
func redirectTo(w http.ResponseWriter, r *http.Request, loc string) {
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", loc)
		http.Error(w, "Redirecting", http.StatusUnauthorized)
		return
	}
	http.Redirect(w, r, loc, http.StatusSeeOther)
}

// --- 4. authentication ---------------------------------------------------------

func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		c, err := r.Cookie(s.auth.Cookies().SessionName())
		if err != nil {
			s.unauthenticated(w, r, false)
			return
		}
		user, sess, err := s.auth.Sessions().Validate(r.Context(), c.Value)
		switch {
		case errors.Is(err, auth.ErrSessionExpired):
			s.unauthenticated(w, r, true)
			return
		case err != nil:
			s.log.Error("session validation failed", "err", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		if s.auth.EnrollmentPending(user) && !enrollmentAllowed(r) {
			s.enrollmentRequired(w, r)
			return
		}
		ctx := context.WithValue(r.Context(), ctxUser, user)
		ctx = context.WithValue(ctx, ctxSession, sess)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// enrollmentAllowed lists what a session of an operator without two-factor
// login may reach (decision #51): the enrollment page and its POST, and
// logout. Static assets, the login pages and /grid/* never get here (public
// paths). Everything else, views, SSE, the shell WebSocket and every POST, is
// refused by enrollmentRequired.
func enrollmentAllowed(r *http.Request) bool {
	switch r.URL.Path {
	case totpEnrollPath:
		return r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodPost
	case "/logout":
		return r.Method == http.MethodPost
	}
	return false
}

// enrollmentRequired answers a request of an enrollment-pending session that
// is not allowed: a page navigation (also htmx boost) is sent to the
// enrollment page; streams and everything that changes state get 403, since
// a redirect would be followed silently by script clients.
func (s *Server) enrollmentRequired(w http.ResponseWriter, r *http.Request) {
	if isSafeMethod(r.Method) && !isStreamPath(r.URL.Path) {
		redirectTo(w, r, totpEnrollPath)
		return
	}
	http.Error(w, "Two-factor login must be set up first", http.StatusForbidden)
}

func (s *Server) unauthenticated(w http.ResponseWriter, r *http.Request, clearCookie bool) {
	if clearCookie {
		http.SetCookie(w, s.auth.Cookies().ClearSession())
	}
	if isStreamPath(r.URL.Path) {
		// EventSource and WebSocket clients cannot use a redirect to a login page.
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	redirectTo(w, r, "/login")
}

// --- 5. CSRF -------------------------------------------------------------------

func (s *Server) csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if isSafeMethod(r.Method) || isGridPath(p) {
			// /grid/* authenticates with mTLS or a one-time token itself.
			next.ServeHTTP(w, r)
			return
		}
		if isRestoreUpload(p) {
			// A multipart upload far beyond maxFormBody: the handler checks the
			// double-submit token in the first part before it reads anything else.
			next.ServeHTTP(w, r)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, bodyCap(p))
		submitted := r.Header.Get(auth.CSRFHeader)
		if submitted == "" && p != uploadPathUpdate { // a big upload is never parsed for a token: the header or nothing
			// Only the body is consulted; a token in the URL would end up in logs.
			submitted = r.PostFormValue(auth.CSRFFormField)
		}
		ok := false
		switch {
		case usesDoubleSubmit(p):
			if c, err := r.Cookie(s.auth.Cookies().CSRFName()); err == nil {
				ok = auth.CheckDoubleSubmit(c.Value, submitted)
			}
		default:
			if sess, has := SessionFrom(r); has {
				ok = s.auth.CheckCSRF(sess, submitted)
			}
		}
		if !ok {
			// No token values in the log, and no audit entry (forged requests must not flood the audit log).
			s.log.Warn("csrf check failed", "method", r.Method, "path", logPath(r), "ip", ClientIP(r))
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- 6. recovery and logging ---------------------------------------------------

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
	wrote  bool
}

func (w *statusRecorder) WriteHeader(code int) {
	if !w.wrote && code >= 200 {
		w.status, w.wrote = code, true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusRecorder) Write(b []byte) (int, error) {
	if !w.wrote {
		w.status, w.wrote = http.StatusOK, true
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

func (w *statusRecorder) Flush() {
	if !w.wrote {
		w.status, w.wrote = http.StatusOK, true
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack lets the WebSocket upgrade through.
func (w *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	conn, rw, err := h.Hijack()
	if err == nil {
		w.status, w.wrote = http.StatusSwitchingProtocols, true
	}
	return conn, rw, err
}

// Unwrap serves http.ResponseController.
func (w *statusRecorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func logPath(r *http.Request) string {
	p := r.URL.Path // never the query: it can carry the WebSocket CSRF token
	if len(p) > 200 {
		p = p[:200]
	}
	return p
}

func (s *Server) recoverAndLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler { //nolint:errorlint // sentinel panic value
					panic(v)
				}
				s.log.Error("panic in handler", "method", r.Method, "path", logPath(r), "panic", v, "stack", string(debug.Stack()))
				if !rec.wrote {
					http.Error(rec, "Internal Server Error", http.StatusInternalServerError)
				}
			}
			status := rec.status
			if status == 0 {
				status = http.StatusOK
			}
			level := s.requestLevel(r, status)
			s.log.Log(r.Context(), level, "http request",
				"method", r.Method, "path", logPath(r), "status", status,
				"duration_ms", time.Since(start).Milliseconds(), "bytes", rec.bytes, "ip", remoteHost(r))
		}()
		next.ServeHTTP(rec, r)
	})
}
