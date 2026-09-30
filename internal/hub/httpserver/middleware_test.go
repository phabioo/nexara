package httpserver

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/phabioo/nexara/internal/hub/auth"
)

const wantCSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; " +
	"connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'"

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	e := newEnv(t)
	cookie, _ := e.signIn()
	tests := []struct {
		name, method, path string
		opts               []reqOpt
		cache              string
	}{
		{"login page", "GET", "/login", nil, "no-store"},
		{"redirect to login", "GET", "/", nil, "no-store"},
		{"signed-in stub", "GET", "/", []reqOpt{withCookies(cookie)}, "no-store"},
		{"not found", "GET", "/nope", []reqOpt{withCookies(cookie)}, "no-store"},
		{"csrf rejection", "POST", "/logout", []reqOpt{withCookies(cookie)}, "no-store"},
		{"static versioned", "GET", "/static/css/a.css?v=abc", nil, "public, max-age=31536000, immutable"},
		{"static unversioned", "GET", "/static/css/a.css", nil, "no-cache"},
		{"manifest", "GET", "/manifest.webmanifest", nil, "no-cache"},
		{"favicon", "GET", "/favicon.svg", nil, "no-cache"},
		{"grid", "GET", "/grid/connect", nil, "no-store"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := e.do(e.srv.Handler(), tc.method, tc.path, tc.opts...)
			h := rec.Header()
			want := map[string]string{
				"Content-Security-Policy":    wantCSP,
				"X-Content-Type-Options":     "nosniff",
				"Referrer-Policy":            "no-referrer",
				"X-Frame-Options":            "DENY",
				"Cross-Origin-Opener-Policy": "same-origin",
				"Permissions-Policy":         "camera=(), microphone=(), geolocation=()",
				"Cache-Control":              tc.cache,
			}
			for k, v := range want {
				if got := h.Get(k); got != v {
					t.Errorf("%s = %q, want %q", k, got, v)
				}
			}
		})
	}
}

func TestClientIPIgnoresForwardingHeaders(t *testing.T) {
	e := newEnv(t)
	var got string
	h := e.srv.clientIP(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got = ClientIP(r) }))
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.0.2.77:5555"
	r.Header.Set("X-Forwarded-For", "203.0.113.9")
	r.Header.Set("X-Real-IP", "203.0.113.10")
	r.Header.Set("Forwarded", "for=203.0.113.11")
	h.ServeHTTP(httptest.NewRecorder(), r)
	if got != "192.0.2.77" {
		t.Errorf("ClientIP = %q, want 192.0.2.77", got)
	}
}

func TestSetupGate(t *testing.T) {
	e := newEnv(t)
	e.setSetupMode(true)
	cookie, _ := e.signIn() // a stale cookie must not matter

	tests := []struct {
		name, path string
		opts       []reqOpt
		status     int
		location   string
		hxRedirect string
	}{
		{"root redirects", "/", nil, 303, "/setup", ""},
		{"login redirects", "/login", nil, 303, "/setup", ""},
		{"host page redirects", "/hosts/alpha", []reqOpt{withCookies(cookie)}, 303, "/setup", ""},
		{"htmx request", "/", []reqOpt{withHeader("HX-Request", "true")}, 401, "", "/setup"},
		{"setup served", "/setup", nil, 200, "", ""},
		{"setup step without session goes to unlock", "/setup/trust", nil, 303, "/setup", ""},
		{"static served", "/static/css/a.css", nil, 200, "", ""},
		{"manifest served", "/manifest.webmanifest", nil, 200, "", ""},
		{"favicon served", "/favicon.svg", nil, 200, "", ""},
		{"agent endpoint closed", "/grid/connect", nil, 503, "", ""},
		{"enroll endpoint closed", "/grid/enroll", nil, 503, "", ""},
		{"install script closed", "/grid/install.sh", nil, 503, "", ""},
		{"events closed", "/events", []reqOpt{withCookies(cookie)}, 503, "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := e.get(tc.path, tc.opts...)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d", rec.Code, tc.status)
			}
			if got := rec.Header().Get("Location"); got != tc.location {
				t.Errorf("Location = %q, want %q", got, tc.location)
			}
			if got := rec.Header().Get("HX-Redirect"); got != tc.hxRedirect {
				t.Errorf("HX-Redirect = %q, want %q", got, tc.hxRedirect)
			}
		})
	}

	t.Run("setup POST passes the gate", func(t *testing.T) {
		rec := e.post("/grid/enroll")
		if rec.Code != 503 {
			t.Errorf("POST /grid/enroll during setup = %d, want 503", rec.Code)
		}
	})

	t.Run("opens after setup", func(t *testing.T) {
		e.setSetupMode(false)
		if rec := e.get("/setup"); rec.Code != 303 || rec.Header().Get("Location") != "/" {
			t.Errorf("/setup after setup: %d %q, want 303 to /", rec.Code, rec.Header().Get("Location"))
		}
		if rec := e.get("/setup/unlock"); rec.Code != 303 {
			t.Errorf("/setup/unlock after setup = %d, want 303", rec.Code)
		}
		if rec := e.get("/grid/connect"); rec.Code != 200 || rec.Body.String() != "agent-ok" {
			t.Errorf("/grid/connect after setup = %d %q", rec.Code, rec.Body.String())
		}
		if rec := e.get("/login"); rec.Code != 200 {
			t.Errorf("/login after setup = %d", rec.Code)
		}
	})
}

func TestAuthentication(t *testing.T) {
	e := newEnv(t)
	cookie, _ := e.signIn()

	t.Run("redirect to login", func(t *testing.T) {
		rec := e.get("/")
		if rec.Code != 303 || rec.Header().Get("Location") != "/login" {
			t.Errorf("got %d %q", rec.Code, rec.Header().Get("Location"))
		}
	})
	t.Run("htmx gets HX-Redirect and 401", func(t *testing.T) {
		rec := e.get("/hosts/alpha", withHeader("HX-Request", "true"))
		if rec.Code != 401 || rec.Header().Get("HX-Redirect") != "/login" {
			t.Errorf("got %d %q", rec.Code, rec.Header().Get("HX-Redirect"))
		}
	})
	t.Run("streams get plain 401", func(t *testing.T) {
		for _, p := range []string{"/events", "/hosts/alpha/shell/ws"} {
			rec := e.get(p)
			if rec.Code != 401 || rec.Header().Get("Location") != "" {
				t.Errorf("%s: %d location %q", p, rec.Code, rec.Header().Get("Location"))
			}
		}
	})
	t.Run("garbage cookie is rejected and cleared", func(t *testing.T) {
		rec := e.get("/", withCookies(&http.Cookie{Name: auth.SessionCookieName, Value: "garbage"}))
		if rec.Code != 303 {
			t.Fatalf("status %d", rec.Code)
		}
		c := findCookie(rec, auth.SessionCookieName)
		if c == nil || c.MaxAge >= 0 {
			t.Errorf("session cookie not cleared: %+v", c)
		}
	})
	t.Run("valid session reaches handler", func(t *testing.T) {
		if rec := e.get("/", withCookies(cookie)); rec.Code != 501 {
			t.Errorf("status %d, want 501 stub", rec.Code)
		}
	})
	t.Run("public routes need no session", func(t *testing.T) {
		for path, want := range map[string]int{
			"/login": 200, "/static/css/a.css": 200, "/manifest.webmanifest": 200, "/favicon.svg": 200,
			"/grid/connect": 200, "/grid/agent/x": 200, "/grid/install.sh": 200, "/grid/download/agent": 200,
		} {
			if rec := e.get(path); rec.Code != want {
				t.Errorf("%s = %d, want %d", path, rec.Code, want)
			}
		}
	})
	t.Run("user and session in context", func(t *testing.T) {
		var op string
		var haveSess bool
		var ip string
		mux := http.NewServeMux()
		mux.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
			u, _ := UserFrom(r)
			_, haveSess = SessionFrom(r)
			op, ip = u.OperatorID, ActorFrom(r).IP
			if a := ActorFrom(r); a.Operator != testOperator {
				t.Errorf("actor operator = %q", a.Operator)
			}
		})
		e.do(e.srv.chain(mux), "GET", "/probe", withCookies(cookie))
		if op != testOperator || !haveSess || ip != "192.0.2.10" {
			t.Errorf("op=%q session=%v ip=%q", op, haveSess, ip)
		}
	})
}

func TestCSRF(t *testing.T) {
	e := newEnv(t)
	cookie, token := e.signIn()
	otherCookie, otherToken := e.signIn()
	_ = otherCookie

	hits := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
		hits++
		// The form must still be readable after the middleware consumed the body.
		if r.PostFormValue("name") != "" {
			w.Header().Set("X-Name", r.PostFormValue("name"))
		}
	})
	h := e.srv.chain(mux)

	tests := []struct {
		name   string
		method string
		path   string
		opts   []reqOpt
		status int
	}{
		{"GET needs no token", "GET", "/probe", []reqOpt{withCookies(cookie)}, 200},
		{"POST with header", "POST", "/probe", []reqOpt{withCookies(cookie), withHeader(auth.CSRFHeader, token)}, 200},
		{"POST with form field", "POST", "/probe", []reqOpt{withCookies(cookie), withForm(url.Values{auth.CSRFFormField: {token}, "name": {"x"}})}, 200},
		{"POST without token", "POST", "/probe", []reqOpt{withCookies(cookie)}, 403},
		{"POST wrong token", "POST", "/probe", []reqOpt{withCookies(cookie), withHeader(auth.CSRFHeader, "nope")}, 403},
		{"POST other session's token", "POST", "/probe", []reqOpt{withCookies(cookie), withHeader(auth.CSRFHeader, otherToken)}, 403},
		{"token in query only", "POST", "/probe?csrf_token=" + token, []reqOpt{withCookies(cookie)}, 403},
		{"DELETE without token", "DELETE", "/probe", []reqOpt{withCookies(cookie)}, 403},
		{"PUT with header", "PUT", "/probe", []reqOpt{withCookies(cookie), withHeader(auth.CSRFHeader, token)}, 200},
		{"no session", "POST", "/probe", []reqOpt{withHeader(auth.CSRFHeader, token)}, 303},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := hits
			rec := e.do(h, tc.method, tc.path, tc.opts...)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d", rec.Code, tc.status)
			}
			if (tc.status == 200) != (hits == before+1) {
				t.Errorf("handler called = %v for status %d", hits == before+1, tc.status)
			}
		})
	}

	t.Run("form value survives", func(t *testing.T) {
		rec := e.do(h, "POST", "/probe", withCookies(cookie), withForm(url.Values{auth.CSRFFormField: {token}, "name": {"x"}}))
		if rec.Header().Get("X-Name") != "x" {
			t.Errorf("form value lost: %q", rec.Header().Get("X-Name"))
		}
	})
	t.Run("csrf rejection logs no token", func(t *testing.T) {
		e.do(h, "POST", "/probe", withCookies(cookie), withHeader(auth.CSRFHeader, "secret-wrong-token"))
		out := e.logs.String()
		if !strings.Contains(out, "csrf check failed") {
			t.Error("no csrf log line")
		}
		if strings.Contains(out, "secret-wrong-token") || strings.Contains(out, token) {
			t.Error("log contains token values")
		}
	})
	t.Run("grid is exempt", func(t *testing.T) {
		if rec := e.post("/grid/enroll"); rec.Code != 200 || rec.Body.String() != "enroll-ok" {
			t.Errorf("POST /grid/enroll = %d %q", rec.Code, rec.Body.String())
		}
	})
	t.Run("csrf rejection writes no audit entry", func(t *testing.T) {
		list, err := e.st.ListAudit(t.Context(), 100)
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range list {
			if strings.Contains(a.Action, "csrf") {
				t.Errorf("unexpected audit entry %q", a.Action)
			}
		}
	})
}

func TestPreSessionCSRFDoubleSubmit(t *testing.T) {
	e := newEnv(t)
	getRec := e.get("/login")
	csrf := findCookie(getRec, auth.CSRFCookieName)
	assertCookieAttrs(t, csrf)
	bad := url.Values{fieldOperator: {"nobody"}, fieldPass: {"wrong"}}

	t.Run("matching pair passes the check", func(t *testing.T) {
		v := url.Values{fieldOperator: {"nobody"}, fieldPass: {"wrong"}, auth.CSRFFormField: {csrf.Value}}
		rec := e.post("/login", withCookies(csrf), withForm(v))
		if rec.Code != 401 {
			t.Errorf("status = %d, want 401 (reached auth)", rec.Code)
		}
	})
	t.Run("header variant", func(t *testing.T) {
		rec := e.post("/login", withCookies(csrf), withHeader(auth.CSRFHeader, csrf.Value), withForm(bad))
		if rec.Code != 401 {
			t.Errorf("status = %d, want 401", rec.Code)
		}
	})
	t.Run("missing cookie", func(t *testing.T) {
		v := url.Values{auth.CSRFFormField: {csrf.Value}}
		if rec := e.post("/login", withForm(v)); rec.Code != 403 {
			t.Errorf("status = %d, want 403", rec.Code)
		}
	})
	t.Run("missing field", func(t *testing.T) {
		if rec := e.post("/login", withCookies(csrf), withForm(bad)); rec.Code != 403 {
			t.Errorf("status = %d, want 403", rec.Code)
		}
	})
	t.Run("mismatch", func(t *testing.T) {
		v := url.Values{auth.CSRFFormField: {"other"}}
		if rec := e.post("/login", withCookies(csrf), withForm(v)); rec.Code != 403 {
			t.Errorf("status = %d, want 403", rec.Code)
		}
	})
	t.Run("verify step", func(t *testing.T) {
		v := url.Values{auth.CSRFFormField: {"other"}}
		if rec := e.post("/login/verify", withCookies(csrf), withForm(v)); rec.Code != 403 {
			t.Errorf("status = %d, want 403", rec.Code)
		}
	})
	t.Run("session token does not satisfy login form", func(t *testing.T) {
		cookie, token := e.signIn()
		v := url.Values{auth.CSRFFormField: {token}}
		if rec := e.post("/login", withCookies(cookie, csrf), withForm(v)); rec.Code != 403 {
			t.Errorf("status = %d, want 403", rec.Code)
		}
	})
	t.Run("setup forms use double submit", func(t *testing.T) {
		e.setSetupMode(true)
		defer e.setSetupMode(false)
		if rec := e.post("/setup", withForm(url.Values{"code": {"X"}})); rec.Code != 403 {
			t.Errorf("no token: %d, want 403", rec.Code)
		}
		v := url.Values{auth.CSRFFormField: {csrf.Value}}
		if rec := e.post("/setup", withCookies(csrf), withForm(v)); rec.Code != 400 {
			t.Errorf("with token: %d, want 400 (passes CSRF, the unlock form rejects the malformed code)", rec.Code)
		}
	})
}

func TestPanicRecovery(t *testing.T) {
	e := newEnv(t)
	cookie, _ := e.signIn()
	mux := http.NewServeMux()
	mux.HandleFunc("/probe", func(http.ResponseWriter, *http.Request) { panic("boom") })
	h := e.srv.chain(mux)
	rec := e.do(h, "GET", "/probe?secret=hunter2", withCookies(cookie))
	if rec.Code != 500 {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if rec.Header().Get("Content-Security-Policy") != wantCSP {
		t.Error("500 response lacks security headers")
	}
	if strings.Contains(rec.Body.String(), "boom") {
		t.Error("panic value leaked to the client")
	}
	out := e.logs.String()
	if !strings.Contains(out, "panic in handler") || !strings.Contains(out, "boom") {
		t.Errorf("panic not logged: %s", out)
	}
	if strings.Contains(out, "hunter2") || strings.Contains(out, cookie.Value) {
		t.Error("log leaks query or cookie")
	}
}

func TestRequestLogging(t *testing.T) {
	e := newEnv(t)
	cookie, _ := e.signIn()
	e.get("/hosts/alpha?token=abc123", withCookies(cookie))
	out := e.logs.String()
	for _, want := range []string{"http request", "method=GET", "path=/hosts/alpha", "status=501", "duration_ms="} {
		if !strings.Contains(out, want) {
			t.Errorf("log missing %q in %s", want, out)
		}
	}
	if strings.Contains(out, "abc123") || strings.Contains(out, cookie.Value) {
		t.Error("log contains query or cookie value")
	}
}

func TestStaticRoutes(t *testing.T) {
	e := newEnv(t)
	t.Run("file", func(t *testing.T) {
		rec := e.get("/static/css/a.css")
		if rec.Code != 200 || rec.Body.String() != "body{}" {
			t.Errorf("%d %q", rec.Code, rec.Body.String())
		}
	})
	t.Run("no directory listing", func(t *testing.T) {
		for _, p := range []string{"/static/", "/static/css/"} {
			if rec := e.get(p); rec.Code != 404 {
				t.Errorf("%s = %d, want 404", p, rec.Code)
			}
		}
	})
	t.Run("manifest type", func(t *testing.T) {
		rec := e.get("/manifest.webmanifest")
		if rec.Code != 200 || rec.Header().Get("Content-Type") != "application/manifest+json" {
			t.Errorf("%d %q", rec.Code, rec.Header().Get("Content-Type"))
		}
	})
	t.Run("favicon type", func(t *testing.T) {
		rec := e.get("/favicon.svg")
		if rec.Code != 200 || rec.Header().Get("Content-Type") != "image/svg+xml" {
			t.Errorf("%d %q", rec.Code, rec.Header().Get("Content-Type"))
		}
	})
	t.Run("static write method", func(t *testing.T) {
		if rec := e.post("/static/css/a.css"); rec.Code == 200 {
			t.Errorf("POST to static = %d", rec.Code)
		}
	})
	t.Run("path traversal does not escape", func(t *testing.T) {
		rec := e.get("/static/../hosts/alpha")
		if rec.Code == 501 {
			t.Error("traversal reached a protected handler without a session")
		}
	})
}
