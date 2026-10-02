package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/phabioo/nexara/internal/hub/auth"
	"github.com/phabioo/nexara/internal/hub/store"
)

// pendingEnv is the login environment (real templates) with a session of an
// operator who has no two-factor login yet.
type pendingEnv struct {
	*env
	cookie *http.Cookie
	csrf   string
	sess   store.Session
}

func newPendingEnv(t *testing.T) *pendingEnv {
	t.Helper()
	e := newLoginEnv(t)
	c, csrf, sess := e.signInPending()
	return &pendingEnv{env: e, cookie: c, csrf: csrf, sess: sess}
}

func (p *pendingEnv) secret(t *testing.T) string {
	t.Helper()
	u, err := p.st.GetUserByOperatorID(context.Background(), testOperator)
	if err != nil {
		t.Fatal(err)
	}
	return p.svc.PendingTOTPSecret(u, p.sess)
}

func (p *pendingEnv) enroll(code string, opts ...reqOpt) *httptest.ResponseRecorder {
	opts = append([]reqOpt{withCookies(p.cookie), withForm(url.Values{auth.CSRFFormField: {p.csrf}, fieldCode: {code}})}, opts...)
	return p.post(totpEnrollPath, opts...)
}

// TestEnrollmentGate is the matrix of route classes for an enrollment-pending
// session: only the enrollment page, its POST, logout and static files get
// through (decision #51).
func TestEnrollmentGate(t *testing.T) {
	p := newPendingEnv(t)
	hx := withHeader("HX-Request", "true")
	csrf := withHeader(auth.CSRFHeader, p.csrf)
	tests := []struct {
		name     string
		method   string
		path     string
		opts     []reqOpt
		wantCode int
		wantLoc  string // Location or HX-Redirect
	}{
		// What is allowed.
		{"enrollment page", "GET", totpEnrollPath, nil, 200, ""},
		{"static asset", "GET", "/static/css/a.css", nil, 200, ""},
		{"manifest", "GET", "/manifest.webmanifest", nil, 200, ""},
		{"favicon", "GET", "/favicon.svg", nil, 200, ""},
		{"login page", "GET", "/login", nil, 303, "/"}, // a valid session: on to the app, which sends it to the enrollment page
		{"agent endpoint is not a browser route", "GET", "/grid/connect", nil, 200, ""},

		// Pages: sent to the enrollment page.
		{"overview", "GET", "/", nil, 303, totpEnrollPath},
		{"host overview", "GET", "/hosts/alpha", nil, 303, totpEnrollPath},
		{"packages", "GET", "/hosts/alpha/packages", nil, 303, totpEnrollPath},
		{"shell page", "GET", "/hosts/alpha/shell", nil, 303, totpEnrollPath},
		{"history", "GET", "/history", nil, 303, totpEnrollPath},
		{"settings", "GET", "/settings", nil, 303, totpEnrollPath},
		{"audit view", "GET", "/settings/audit", nil, 303, totpEnrollPath},
		{"unknown path", "GET", "/nothing-here", nil, 303, totpEnrollPath},
		{"htmx navigation", "GET", "/hosts/alpha/packages", []reqOpt{hx}, 401, totpEnrollPath},
		{"HEAD", "HEAD", "/", nil, 303, totpEnrollPath},

		// Streams and everything that changes state: 403.
		{"SSE", "GET", "/events", nil, 403, ""},
		{"shell WebSocket", "GET", "/hosts/alpha/shell/ws", nil, 403, ""},
		{"POST action", "POST", "/hosts/alpha/services/ssh/restart", []reqOpt{csrf}, 403, ""},
		{"POST add host", "POST", "/hosts/new/ssh", []reqOpt{csrf}, 403, ""},
		{"POST with htmx", "POST", "/hosts/alpha/packages/upgrade", []reqOpt{hx, csrf}, 403, ""},
		{"DELETE", "DELETE", "/hosts/alpha", []reqOpt{csrf}, 403, ""},
		{"GET logout is not allowed", "GET", "/logout", nil, 303, totpEnrollPath},
		{"POST settings", "POST", "/settings", []reqOpt{csrf}, 403, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := append([]reqOpt{withCookies(p.cookie)}, tc.opts...)
			rec := p.do(p.srv.Handler(), tc.method, tc.path, opts...)
			if rec.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d\n%s", rec.Code, tc.wantCode, rec.Body.String())
			}
			loc := rec.Header().Get("Location")
			if loc == "" {
				loc = rec.Header().Get("HX-Redirect")
			}
			if loc != tc.wantLoc {
				t.Errorf("redirect = %q, want %q", loc, tc.wantLoc)
			}
		})
	}

	t.Run("logout works and ends the session", func(t *testing.T) {
		q := newPendingEnv(t)
		rec := q.post("/logout", withCookies(q.cookie), withForm(url.Values{auth.CSRFFormField: {q.csrf}}))
		if rec.Code != 303 || rec.Header().Get("Location") != "/login" {
			t.Fatalf("got %d %q", rec.Code, rec.Header().Get("Location"))
		}
		if _, _, err := q.svc.Sessions().Validate(context.Background(), q.cookie.Value); err == nil {
			t.Error("the session must be gone after logout")
		}
	})

	t.Run("an operator with two-factor login is not gated", func(t *testing.T) {
		e := newLoginEnv(t)
		c, _ := e.signIn()
		for _, path := range []string{"/", "/hosts/alpha/packages"} {
			if rec := e.get(path, withCookies(c)); rec.Code != 200 {
				t.Errorf("GET %s = %d, want 200", path, rec.Code)
			}
		}
		if rec := e.get(totpEnrollPath, withCookies(c)); rec.Code != 303 || rec.Header().Get("Location") != "/" {
			t.Errorf("enrollment page for an enrolled operator: %d %q, want a redirect home", rec.Code, rec.Header().Get("Location"))
		}
	})

	t.Run("without a session it is the sign-in", func(t *testing.T) {
		rec := p.get(totpEnrollPath)
		if rec.Code != 303 || rec.Header().Get("Location") != "/login" {
			t.Errorf("got %d %q", rec.Code, rec.Header().Get("Location"))
		}
	})
}

func TestEnrollmentPageContent(t *testing.T) {
	p := newPendingEnv(t)
	rec := p.get(totpEnrollPath, withCookies(p.cookie))
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	secret := p.secret(t)
	body := rec.Body.String()
	mustContain(t, body, "Two-factor login", `<svg class="qr"`, setupGroup(secret, 4), `name="code"`, `inputmode="numeric"`,
		`action="/account/totp"`, `value="`+p.csrf+`"`, "sudo nexus user reset", "Sign out")
	mustNotContain(t, body, secret, "Skip", "Continue without")
	// The app shell with hosts and navigation must not be there.
	mustNotContain(t, body, "alpha", "Beta Pi", `class="sidebar`)
	// Reload shows the same key.
	if again := p.get(totpEnrollPath, withCookies(p.cookie)).Body.String(); !strings.Contains(again, setupGroup(secret, 4)) {
		t.Error("the key changed on reload")
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q", rec.Header().Get("Cache-Control"))
	}
}

func TestEnrollmentFlow(t *testing.T) {
	t.Run("csrf is required", func(t *testing.T) {
		p := newPendingEnv(t)
		secret := p.secret(t)
		for name, form := range map[string]url.Values{
			"no token":    {fieldCode: {codeFor(secret)}},
			"wrong token": {auth.CSRFFormField: {"x" + p.csrf}, fieldCode: {codeFor(secret)}},
		} {
			rec := p.post(totpEnrollPath, withCookies(p.cookie), withForm(form))
			if rec.Code != 403 {
				t.Errorf("%s: status %d, want 403", name, rec.Code)
			}
		}
		if u, _ := p.st.GetUserByOperatorID(context.Background(), testOperator); u.TOTPEnabled {
			t.Fatal("a forged request enrolled the operator")
		}
	})

	t.Run("malformed and wrong codes", func(t *testing.T) {
		p := newPendingEnv(t)
		secret := p.secret(t)
		for name, tc := range map[string]struct {
			code string
			want int
		}{
			"empty":   {"", 400},
			"letters": {"abcdef", 400},
			"short":   {"12345", 400},
			"wrong":   {wrongCodeFor(secret), 422},
		} {
			rec := p.enroll(tc.code)
			if rec.Code != tc.want {
				t.Errorf("%s: status %d, want %d", name, rec.Code, tc.want)
			}
			if findCookie(rec, sessionCookieName) != nil {
				t.Errorf("%s: session cookie set on failure", name)
			}
			mustContain(t, rec.Body.String(), `role="alert"`, setupGroup(secret, 4))
		}
		if u, _ := p.st.GetUserByOperatorID(context.Background(), testOperator); u.TOTPEnabled {
			t.Fatal("a wrong code enrolled the operator")
		}
		// The session is still the pending one.
		if rec := p.get("/", withCookies(p.cookie)); rec.Code != 303 {
			t.Errorf("GET / = %d", rec.Code)
		}
	})

	t.Run("success rotates the session and ends the old ones", func(t *testing.T) {
		p := newPendingEnv(t)
		secret := p.secret(t)
		other, _, _ := p.signInPending() // another session of the same operator
		code := codeFor(secret)
		rec := p.enroll(code)
		if rec.Code != 200 {
			t.Fatalf("status %d\n%s", rec.Code, rec.Body.String())
		}
		mustContain(t, rec.Body.String(), "Access granted", "Two-factor login is on", `http-equiv="refresh"`, `href="/"`)
		fresh := findCookie(rec, sessionCookieName)
		assertCookieAttrs(t, fresh)
		if fresh.Value == "" || fresh.Value == p.cookie.Value {
			t.Fatalf("the session ID must change, got %q", fresh.Value)
		}
		for name, c := range map[string]*http.Cookie{"enrolling session": p.cookie, "other session": other} {
			if rec := p.get("/", withCookies(c)); rec.Code != 303 || rec.Header().Get("Location") != "/login" {
				t.Errorf("%s still works: %d %q", name, rec.Code, rec.Header().Get("Location"))
			}
		}
		if rec := p.get("/", withCookies(fresh)); rec.Code != 200 {
			t.Errorf("the new session must open the app, got %d", rec.Code)
		}
		if rec := p.get(totpEnrollPath, withCookies(fresh)); rec.Code != 303 || rec.Header().Get("Location") != "/" {
			t.Errorf("enrollment page after success: %d %q", rec.Code, rec.Header().Get("Location"))
		}

		u, err := p.st.GetUserByOperatorID(context.Background(), testOperator)
		if err != nil || !u.TOTPEnabled {
			t.Fatalf("user = %+v, %v", u, err)
		}
		if opened, err := p.svc.OpenTOTPSecret(u.ID, u.TOTPSecretEnc); err != nil || opened != secret {
			t.Errorf("stored secret %q, %v", opened, err)
		}
		found := false
		entries, _ := p.st.ListAudit(context.Background(), 100)
		for _, a := range entries {
			if a.Action == auth.ActionTOTPEnroll && a.Result == store.AuditOK && a.User == testOperator {
				found = true
			}
			if strings.Contains(a.Detail, secret) || strings.Contains(a.Detail, code) {
				t.Errorf("audit entry leaks a secret: %+v", a)
			}
		}
		if !found {
			t.Error("no user.totp_enroll audit entry")
		}
	})

	t.Run("the enrollment code cannot be replayed at sign-in", func(t *testing.T) {
		p := newPendingEnv(t)
		secret := p.secret(t)
		code := codeFor(secret)
		if rec := p.enroll(code); rec.Code != 200 {
			t.Fatalf("status %d", rec.Code)
		}
		j, token := loginForm(t, p.env)
		rec := p.post("/login", withJar(j), withForm(creds(token, testOperator, testPass)))
		if rec.Code != 200 {
			t.Fatalf("passphrase step: %d", rec.Code)
		}
		j.absorb(rec)
		rec = p.post("/login/verify", withJar(j), withForm(url.Values{auth.CSRFFormField: {token}, fieldCode: {code}}))
		if rec.Code != 401 || findCookie(rec, sessionCookieName) != nil {
			t.Fatalf("replayed code: status %d, session cookie %v", rec.Code, findCookie(rec, sessionCookieName) != nil)
		}
		// The next time step signs in.
		p.clock.Advance(31 * time.Second)
		next, err := totp.GenerateCode(secret, p.clock.Now())
		if err != nil {
			t.Fatal(err)
		}
		rec = p.post("/login/verify", withJar(j), withForm(url.Values{auth.CSRFFormField: {token}, fieldCode: {next}}))
		if rec.Code != 200 || findCookie(rec, sessionCookieName) == nil {
			t.Fatalf("next code: status %d", rec.Code)
		}
	})

	t.Run("wrong codes are rate limited", func(t *testing.T) {
		p := newPendingEnv(t)
		secret := p.secret(t)
		bad := wrongCodeFor(secret)
		for i := 0; i < 5; i++ {
			if rec := p.enroll(bad); rec.Code != 422 {
				t.Fatalf("attempt %d: status %d", i+1, rec.Code)
			}
		}
		rec := p.enroll(codeFor(secret))
		if rec.Code != 429 || rec.Header().Get("Retry-After") == "" {
			t.Fatalf("status %d, Retry-After %q; want 429 even for the right code", rec.Code, rec.Header().Get("Retry-After"))
		}
		mustContain(t, rec.Body.String(), "Too many failed attempts")
	})

	t.Run("sign out instead", func(t *testing.T) {
		p := newPendingEnv(t)
		rec := p.get(totpEnrollPath, withCookies(p.cookie))
		mustContain(t, rec.Body.String(), `formaction="/logout"`)
	})
}

// TestDemoPasswordOnly: the seeded demo operator reaches the app without an
// authenticator, and only because the auth service was built that way (it
// refuses Secure cookies, so a TLS hub cannot).
func TestDemoPasswordOnly(t *testing.T) {
	e := newEnvSecure(t, false)
	svc, err := auth.NewService(auth.Config{
		Store: e.st, SecretKey: func() []byte {
			k := make([]byte, auth.SecretKeyLen)
			for i := range k {
				k[i] = byte(i + 1)
			}
			return k
		}(),
		IdleTimeout: 12 * time.Hour, HashParams: testParams, Now: e.clock.Now,
		CookieOptions:    []auth.CookieOption{auth.WithSecure(false)},
		DemoPasswordOnly: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	e.srv.auth = svc
	res, err := svc.Login(context.Background(), testOperator, testPass, "192.0.2.10", "test", false)
	if err != nil {
		t.Fatal(err)
	}
	c := &http.Cookie{Name: svc.Cookies().SessionName(), Value: res.SessionID}
	for _, path := range []string{"/", "/hosts/alpha/packages", "/settings"} {
		if rec := e.get(path, withCookies(c)); rec.Header().Get("Location") == totpEnrollPath || rec.Code == 403 {
			t.Errorf("GET %s = %d %q: the demo operator must not be gated", path, rec.Code, rec.Header().Get("Location"))
		}
	}
	if rec := e.post("/settings", withCookies(c), withForm(url.Values{auth.CSRFFormField: {svc.CSRFToken(res.Session)}})); rec.Code == 403 {
		t.Error("POST by the demo operator was refused with 403")
	}

	if _, err := auth.NewService(auth.Config{
		Store: e.st, SecretKey: make([]byte, auth.SecretKeyLen), DemoPasswordOnly: true,
	}); err == nil {
		t.Error("DemoPasswordOnly with the default (Secure) cookies must be refused")
	}
}
