package httpserver

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/phabioo/nexara/internal/hub/auth"
	"github.com/phabioo/nexara/internal/hub/views"
	"github.com/phabioo/nexara/web"
)

// newLoginEnv is newEnv with the real templates, so the login page renders.
func newLoginEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t)
	r, err := views.New(web.Templates, views.Options{})
	if err != nil {
		t.Fatal(err)
	}
	e.srv.renderer = r
	return e
}

func mustContain(t *testing.T, body string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(body, w) {
			t.Errorf("body lacks %q", w)
		}
	}
}

func mustNotContain(t *testing.T, body string, unwanted ...string) {
	t.Helper()
	for _, w := range unwanted {
		if strings.Contains(body, w) {
			t.Errorf("body contains %q", w)
		}
	}
}

// loginForm fetches the login page and returns a jar holding the CSRF cookie and the token.
func loginForm(t *testing.T, e *env) (jar, string) {
	t.Helper()
	j := jar{}
	rec := e.get("/login")
	if rec.Code != 200 {
		t.Fatalf("GET /login = %d", rec.Code)
	}
	j.absorb(rec)
	c := j[csrfCookieName]
	if c == nil {
		t.Fatal("no csrf cookie on the login page")
	}
	return j, c.Value
}

func creds(token, op, pass string, extra ...string) url.Values {
	v := url.Values{auth.CSRFFormField: {token}, fieldOperator: {op}, fieldPass: {pass}}
	for i := 0; i+1 < len(extra); i += 2 {
		v.Set(extra[i], extra[i+1])
	}
	return v
}

func TestLoginPageSetsCSRFCookie(t *testing.T) {
	e := newLoginEnv(t)
	rec := e.get("/login")
	c := findCookie(rec, csrfCookieName)
	assertCookieAttrs(t, c)
	if len(c.Value) != 43 {
		t.Errorf("token length %d", len(c.Value))
	}
	// An existing valid cookie is reused, not rotated.
	rec2 := e.get("/login", withCookies(c))
	if findCookie(rec2, csrfCookieName) != nil {
		t.Error("valid csrf cookie was replaced")
	}
	// A garbage cookie is replaced.
	rec3 := e.get("/login", withCookies(&http.Cookie{Name: csrfCookieName, Value: "x"}))
	if findCookie(rec3, csrfCookieName) == nil {
		t.Error("garbage csrf cookie was kept")
	}
}

func TestLoginRedirectsWhenSignedIn(t *testing.T) {
	e := newLoginEnv(t)
	cookie, _ := e.signIn()
	rec := e.get("/login", withCookies(cookie))
	if rec.Code != 303 || rec.Header().Get("Location") != "/" {
		t.Errorf("got %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestLoginWithoutTOTP(t *testing.T) {
	e := newLoginEnv(t)

	t.Run("success, browser-session cookie", func(t *testing.T) {
		j, token := loginForm(t, e)
		rec := e.post("/login", withJar(j), withForm(creds(token, testOperator, testPass)))
		if rec.Code != 303 || rec.Header().Get("Location") != "/" {
			t.Fatalf("got %d %q", rec.Code, rec.Header().Get("Location"))
		}
		sc := findCookie(rec, sessionCookieName)
		assertCookieAttrs(t, sc)
		if sc.MaxAge != 0 || sc.Path != "/" || sc.Value == "" {
			t.Errorf("session cookie: maxage=%d path=%q value-empty=%v", sc.MaxAge, sc.Path, sc.Value == "")
		}
		if c := findCookie(rec, csrfCookieName); c == nil || c.MaxAge >= 0 {
			t.Errorf("csrf cookie not cleared: %+v", c)
		}
		if _, _, err := e.svc.Sessions().Validate(context.Background(), sc.Value); err != nil {
			t.Errorf("session not valid: %v", err)
		}
		// The operator has no two-factor login: the session opens the enrollment page only (decision #51).
		if rec := e.get("/", withCookies(sc)); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != totpEnrollPath {
			t.Errorf("GET / with new session = %d %q, want a redirect to %s", rec.Code, rec.Header().Get("Location"), totpEnrollPath)
		}
	})

	t.Run("keep me signed in gives a persistent cookie", func(t *testing.T) {
		j, token := loginForm(t, e)
		rec := e.post("/login", withJar(j), withForm(creds(token, testOperator, testPass, fieldKeep, "on")))
		sc := findCookie(rec, sessionCookieName)
		assertCookieAttrs(t, sc)
		if sc.MaxAge <= 0 {
			t.Errorf("persistent cookie has Max-Age %d", sc.MaxAge)
		}
	})

	t.Run("wrong passphrase", func(t *testing.T) {
		j, token := loginForm(t, e)
		rec := e.post("/login", withJar(j), withForm(creds(token, testOperator, "nope")))
		if rec.Code != 401 {
			t.Fatalf("status %d", rec.Code)
		}
		if findCookie(rec, sessionCookieName) != nil {
			t.Error("session cookie set on failure")
		}
		if !strings.Contains(rec.Body.String(), "Invalid operator ID or passphrase.") {
			t.Errorf("body %q", rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "nope") {
			t.Error("passphrase echoed")
		}
	})

	t.Run("unknown operator looks identical", func(t *testing.T) {
		j, token := loginForm(t, e)
		a := e.post("/login", withJar(j), withForm(creds(token, "ghost", "nope")))
		b := e.post("/login", withJar(j), withForm(creds(token, testOperator, "nope")))
		// The page echoes the operator ID; apart from that nothing may differ.
		bodyA := strings.ReplaceAll(a.Body.String(), `value="ghost"`, `value="OP"`)
		bodyB := strings.ReplaceAll(b.Body.String(), `value="`+testOperator+`"`, `value="OP"`)
		if a.Code != b.Code || bodyA != bodyB {
			t.Errorf("responses differ: %d vs %d (bodies equal: %v)", a.Code, b.Code, bodyA == bodyB)
		}
	})
}

func TestLoginRateLimit(t *testing.T) {
	e := newLoginEnv(t)
	j, token := loginForm(t, e)
	var last int
	for i := 0; i < 8; i++ {
		rec := e.post("/login", withJar(j), withForm(creds(token, testOperator, "wrong")))
		last = rec.Code
		if last == http.StatusTooManyRequests {
			if rec.Header().Get("Retry-After") == "" {
				t.Error("429 without Retry-After")
			}
			if !strings.Contains(rec.Body.String(), "Too many failed attempts") {
				t.Errorf("body %q", rec.Body.String())
			}
			return
		}
	}
	t.Fatalf("no 429 after repeated failures, last status %d", last)
}

func TestLoginWithTOTP(t *testing.T) {
	e := newLoginEnv(t)
	secret := e.addTOTP()

	j, token := loginForm(t, e)
	rec := e.post("/login", withJar(j), withForm(creds(token, testOperator, testPass, fieldKeep, "on")))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Step 2 of 2") {
		t.Fatalf("step one: %d %q", rec.Code, rec.Body.String())
	}
	if findCookie(rec, sessionCookieName) != nil {
		t.Fatal("session issued before the second factor")
	}
	ch := findCookie(rec, challengeCookieName)
	assertCookieAttrs(t, ch)
	if ch.Path != "/" || ch.MaxAge <= 0 || ch.MaxAge > int(auth.ChallengeTTL.Seconds()) || ch.Value == "" {
		t.Errorf("challenge cookie: path=%q maxage=%d", ch.Path, ch.MaxAge)
	}
	j.absorb(rec)

	t.Run("wrong code keeps the challenge", func(t *testing.T) {
		v := url.Values{auth.CSRFFormField: {token}, fieldCode: {wrongCodeFor(secret)}}
		rec := e.post("/login/verify", withJar(j), withForm(v))
		if rec.Code != 401 || !strings.Contains(rec.Body.String(), "Invalid authentication code.") {
			t.Fatalf("%d %q", rec.Code, rec.Body.String())
		}
		if findCookie(rec, sessionCookieName) != nil {
			t.Error("session on wrong code")
		}
		if c := findCookie(rec, challengeCookieName); c != nil && c.MaxAge < 0 {
			t.Error("challenge dropped after one wrong code")
		}
	})

	t.Run("right code signs in and keeps the persistent choice", func(t *testing.T) {
		v := url.Values{auth.CSRFFormField: {token}, fieldCode: {codeFor(secret)}}
		rec := e.post("/login/verify", withJar(j), withForm(v))
		if rec.Code != 200 {
			t.Fatalf("%d %q", rec.Code, rec.Body.String())
		}
		// "Access granted" continues to the app on its own, without script.
		mustContain(t, rec.Body.String(), "Access granted", "Welcome back, <b>"+testOperator+"</b>",
			`<meta http-equiv="refresh" content="2;url=/">`, `href="/"`, "Enter Nexus")
		mustNotContain(t, rec.Body.String(), "<form", "<script>")
		sc := findCookie(rec, sessionCookieName)
		assertCookieAttrs(t, sc)
		if sc.MaxAge <= 0 {
			t.Errorf("persistent choice lost: Max-Age %d", sc.MaxAge)
		}
		if rec := e.get("/", withCookies(sc)); rec.Code != http.StatusOK {
			t.Errorf("GET / with the new session = %d", rec.Code)
		}
		if c := findCookie(rec, challengeCookieName); c == nil || c.MaxAge >= 0 {
			t.Errorf("challenge cookie not cleared: %+v", c)
		}
	})
}

func TestLoginVerifyWithoutChallenge(t *testing.T) {
	e := newLoginEnv(t)
	e.addTOTP()
	j, token := loginForm(t, e)
	v := url.Values{auth.CSRFFormField: {token}, fieldCode: {"123456"}}
	rec := e.post("/login/verify", withJar(j), withForm(v))
	if rec.Code != 401 || !strings.Contains(rec.Body.String(), "Sign-in timed out") {
		t.Errorf("%d %q", rec.Code, rec.Body.String())
	}
	if c := findCookie(rec, challengeCookieName); c == nil || c.MaxAge >= 0 {
		t.Errorf("challenge cookie not cleared: %+v", c)
	}
}

func TestLogout(t *testing.T) {
	e := newLoginEnv(t)

	t.Run("needs csrf", func(t *testing.T) {
		cookie, _ := e.signIn()
		if rec := e.post("/logout", withCookies(cookie)); rec.Code != 403 {
			t.Fatalf("status %d", rec.Code)
		}
		if _, _, err := e.svc.Sessions().Validate(context.Background(), cookie.Value); err != nil {
			t.Errorf("session was deleted by a forged logout: %v", err)
		}
	})

	t.Run("the sign-out form of the app shell works without JavaScript", func(t *testing.T) {
		cookie, token := e.signIn()
		// The form posts the token as a field; it is the same token the page renders.
		page := e.get("/", withCookies(cookie)).Body.String()
		mustContain(t, page, `<form class="signout" method="post" action="/logout">`, `name="csrf_token" value="`+token+`"`)
		rec := e.post("/logout", withCookies(cookie), withForm(url.Values{auth.CSRFFormField: {token}}))
		if rec.Code != 303 || rec.Header().Get("Location") != "/login" {
			t.Fatalf("%d %q", rec.Code, rec.Header().Get("Location"))
		}
		if _, _, err := e.svc.Sessions().Validate(context.Background(), cookie.Value); err == nil {
			t.Error("session still valid after logout")
		}
	})

	t.Run("clears cookie and deletes session", func(t *testing.T) {
		cookie, token := e.signIn()
		rec := e.post("/logout", withCookies(cookie), withHeader(auth.CSRFHeader, token))
		if rec.Code != 303 || rec.Header().Get("Location") != "/login" {
			t.Fatalf("%d %q", rec.Code, rec.Header().Get("Location"))
		}
		sc := findCookie(rec, sessionCookieName)
		assertCookieAttrs(t, sc)
		if sc.MaxAge >= 0 || sc.Value != "" {
			t.Errorf("cookie not cleared: %+v", sc)
		}
		if _, _, err := e.svc.Sessions().Validate(context.Background(), cookie.Value); err == nil {
			t.Error("session still valid after logout")
		}
		list, err := e.st.ListAudit(context.Background(), 100)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, a := range list {
			if a.Action == auth.ActionLogout {
				found = true
			}
		}
		if !found {
			t.Error("logout not audited")
		}
	})
}

func TestLoginPageContent(t *testing.T) {
	e := newLoginEnv(t)
	rec := e.get("/login")
	if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("%d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	body := rec.Body.String()
	csrf := findCookie(rec, csrfCookieName)
	mustContain(t, body,
		`<title>Sign in · Nexara Nexus</title>`,
		`action="/login"`, `method="post"`,
		`name="csrf_token" value="`+csrf.Value+`"`,
		`name="operator_id"`, `name="passphrase"`, `type="password"`, `name="keep_signed_in"`,
		`data-toggle-password="l-pass"`,
		"Authenticate", "Restricted", "Sessions end after 12 hours without activity.",
		"Keep me signed in on this device", "sudo nexus user reset",
		"LOCKED", "Awaiting operator credentials", "auth-login",
	)
	// Checked by default, like the design.
	if !strings.Contains(body, `value="on" checked`) {
		t.Error("keep-signed-in box is not checked by default")
	}
	// Hidden until v0.2 (decision #28); nothing else from later versions.
	mustNotContain(t, body, "Restore", "restore", "Backup", "<script>", " onclick=", "style=")
	if strings.Contains(body, `class="form-error"`) {
		t.Error("error row on a fresh page")
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") {
		t.Errorf("CSP %q", csp)
	}
}

func TestLoginAfterSetupShowsHubOnline(t *testing.T) {
	e := newLoginEnv(t)
	tests := []struct {
		target string
		want   bool
	}{
		{"/login?setup=done", true},
		{"/login?setup=other", false},
		{"/login", false},
	}
	for _, tc := range tests {
		t.Run(tc.target, func(t *testing.T) {
			rec := e.get(tc.target)
			body := rec.Body.String()
			if rec.Code != 200 || strings.Contains(body, `class="toast"`) != tc.want {
				t.Fatalf("status %d, toast present %v, want %v", rec.Code, strings.Contains(body, `class="toast"`), tc.want)
			}
			if tc.want {
				mustContain(t, body, "Hub online", "Setup complete | sign in", `id="toasts"`)
			}
		})
	}
}

func TestLoginErrorStates(t *testing.T) {
	tests := []struct {
		name     string
		form     func(token string) url.Values
		status   int
		wantText string
		wantLog  string
		checked  bool
	}{
		{"wrong passphrase", func(tk string) url.Values { return creds(tk, testOperator, "hunter2-not-it") },
			401, "Invalid operator ID or passphrase.", "Sign-in rejected", false},
		{"unknown operator", func(tk string) url.Values { return creds(tk, "ghost", "hunter2-not-it", fieldKeep, "on") },
			401, "Invalid operator ID or passphrase.", "Sign-in rejected", true},
		{"missing passphrase", func(tk string) url.Values { return creds(tk, testOperator, "") },
			400, "Enter your operator ID and passphrase.", "Sign-in rejected", false},
		{"missing operator", func(tk string) url.Values { return creds(tk, "  ", "whatever") },
			400, "Enter your operator ID and passphrase.", "Sign-in rejected", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newLoginEnv(t)
			j, token := loginForm(t, e)
			form := tc.form(token)
			rec := e.post("/login", withJar(j), withForm(form))
			if rec.Code != tc.status {
				t.Fatalf("status %d, want %d", rec.Code, tc.status)
			}
			body := rec.Body.String()
			mustContain(t, body, `<div class="form-error" role="alert">`, tc.wantText, tc.wantLog, `name="csrf_token" value="`)
			if got := strings.Contains(body, `value="on" checked`); got != tc.checked {
				t.Errorf("keep-signed-in checked = %v, want %v", got, tc.checked)
			}
			if pass := form.Get(fieldPass); pass != "" {
				mustNotContain(t, body, pass)
			}
			if op := strings.TrimSpace(form.Get(fieldOperator)); op != "" {
				mustContain(t, body, `value="`+op+`"`)
			}
			if findCookie(rec, sessionCookieName) != nil {
				t.Error("session cookie on failure")
			}
			// The re-rendered form carries a token that still works.
			if c := findCookie(rec, csrfCookieName); c != nil && !strings.Contains(body, c.Value) {
				t.Error("new csrf cookie not in the form")
			}
		})
	}
}

func TestLoginErrorEscapesOperator(t *testing.T) {
	e := newLoginEnv(t)
	j, token := loginForm(t, e)
	evil := `"><script>alert(1)</script>`
	rec := e.post("/login", withJar(j), withForm(creds(token, evil, "nope")))
	body := rec.Body.String()
	mustNotContain(t, body, "<script>alert(1)")
	mustContain(t, body, "&lt;script&gt;alert(1)&lt;/script&gt;")
}

func TestLoginRateLimitedPage(t *testing.T) {
	e := newLoginEnv(t)
	j, token := loginForm(t, e)
	for i := 0; i < 8; i++ {
		rec := e.post("/login", withJar(j), withForm(creds(token, testOperator, "wrong")))
		if rec.Code != http.StatusTooManyRequests {
			continue
		}
		mustContain(t, rec.Body.String(), "Too many failed attempts. Try again in ", `role="alert"`, "Sign-in rejected")
		if !strings.Contains(rec.Body.String(), "minute") {
			t.Error("remaining time missing")
		}
		return
	}
	t.Fatal("never rate limited")
}

func TestLoginTOTPStep(t *testing.T) {
	e := newLoginEnv(t)
	secret := e.addTOTP()
	j, token := loginForm(t, e)

	rec := e.post("/login", withJar(j), withForm(creds(token, testOperator, testPass)))
	body := rec.Body.String()
	mustContain(t, body,
		"Step 2 of 2", `action="/login/verify"`, `name="code"`, `autocomplete="one-time-code"`, `inputmode="numeric"`,
		`name="operator_id" value="`+testOperator+`"`, "<b>"+testOperator+"</b>",
		"Authentication code", `href="/login"`, "Back", "Verify",
		"Lost your authenticator?", "sudo nexus user reset",
		"Passphrase accepted · waiting for second factor",
	)
	mustNotContain(t, body, `name="passphrase"`, testPass, "Access granted")
	j.absorb(rec)

	tests := []struct {
		name   string
		code   string
		status int
		want   string
	}{
		{"not digits", "abcdef", 400, "Enter the 6-digit code."},
		{"too short", "123", 400, "Enter the 6-digit code."},
		{"empty", "", 400, "Enter the 6-digit code."},
		{"wrong", wrongCodeFor(secret), 401, "Invalid authentication code."},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := url.Values{auth.CSRFFormField: {token}, fieldOperator: {testOperator}, fieldCode: {tc.code}}
			rec := e.post("/login/verify", withJar(j), withForm(v))
			if rec.Code != tc.status {
				t.Fatalf("status %d, want %d", rec.Code, tc.status)
			}
			body := rec.Body.String()
			// Stays on the second step with the operator still named.
			mustContain(t, body, tc.want, `role="alert"`, "Step 2 of 2", "<b>"+testOperator+"</b>")
			if findCookie(rec, sessionCookieName) != nil {
				t.Error("session cookie on a bad code")
			}
		})
	}

	t.Run("a spaced code is accepted", func(t *testing.T) {
		c := codeFor(secret)
		v := url.Values{auth.CSRFFormField: {token}, fieldOperator: {testOperator}, fieldCode: {c[:3] + " " + c[3:]}}
		rec := e.post("/login/verify", withJar(j), withForm(v))
		if rec.Code != 200 {
			t.Fatalf("status %d", rec.Code)
		}
		mustContain(t, rec.Body.String(), "Access granted", "Operator "+testOperator+" authenticated")
	})
}

func TestLoginTOTPOperatorDisplayIsEscapedAndShort(t *testing.T) {
	e := newLoginEnv(t)
	e.addTOTP()
	j, token := loginForm(t, e)
	rec := e.post("/login", withJar(j), withForm(creds(token, testOperator, testPass)))
	j.absorb(rec)
	long := strings.Repeat("a", 200) + "<i>"
	v := url.Values{auth.CSRFFormField: {token}, fieldOperator: {long}, fieldCode: {"000000"}}
	rec = e.post("/login/verify", withJar(j), withForm(v))
	body := rec.Body.String()
	mustNotContain(t, body, strings.Repeat("a", 65), "<i>")
	mustContain(t, body, strings.Repeat("a", 64))
}

func TestLoginBackDropsChallenge(t *testing.T) {
	e := newLoginEnv(t)
	e.addTOTP()
	j, token := loginForm(t, e)
	rec := e.post("/login", withJar(j), withForm(creds(token, testOperator, testPass)))
	j.absorb(rec)
	if j[challengeCookieName] == nil {
		t.Fatal("no challenge cookie")
	}
	rec = e.get("/login", withJar(j))
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if c := findCookie(rec, challengeCookieName); c == nil || c.MaxAge >= 0 {
		t.Errorf("challenge cookie not cleared: %+v", c)
	}
	mustContain(t, rec.Body.String(), `name="passphrase"`)
	mustNotContain(t, rec.Body.String(), "Step 2 of 2")
}

func TestLoginVerifyNeedsCSRF(t *testing.T) {
	e := newLoginEnv(t)
	e.addTOTP()
	j, _ := loginForm(t, e)
	v := url.Values{fieldCode: {"123456"}}
	if rec := e.post("/login/verify", withJar(j), withForm(v)); rec.Code != 403 {
		t.Errorf("status %d", rec.Code)
	}
}

func TestLoginViewFor(t *testing.T) {
	s := &Server{}
	tests := []struct {
		name    string
		p       loginPage
		step    string
		log     string
		refresh int
	}{
		{"fresh", loginPage{}, loginStepCreds, "Awaiting operator credentials", 0},
		{"error", loginPage{Error: "x"}, loginStepCreds, "Sign-in rejected", 0},
		{"totp", loginPage{SecondFactor: true}, loginStepTOTP, "Passphrase accepted · waiting for second factor", 0},
		{"totp error", loginPage{SecondFactor: true, Error: "x"}, loginStepTOTP, "Second factor rejected", 0},
		{"granted", loginPage{Granted: true, Operator: "frank"}, loginStepGranted, "Operator frank authenticated", grantedDelaySeconds},
		{"after setup", loginPage{SetupDone: true}, loginStepCreds, "Setup complete · awaiting operator credentials", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := s.loginViewFor(tc.p)
			if v.Step != tc.step || v.Log != tc.log || v.RefreshSeconds != tc.refresh {
				t.Errorf("got step=%q log=%q refresh=%d", v.Step, v.Log, v.RefreshSeconds)
			}
			if v.Variant != "auth-login" || len(v.Segments) != 1 || v.Segments[0].Text != "LOCKED" {
				t.Errorf("layout: %+v", v.AuthLayout)
			}
		})
	}
}

func TestLogoutWithoutSession(t *testing.T) {
	e := newLoginEnv(t)
	j, token := loginForm(t, e)
	v := url.Values{auth.CSRFFormField: {token}}
	rec := e.post("/logout", withJar(j), withForm(v))
	if rec.Code != 303 || rec.Header().Get("Location") != "/login" {
		t.Errorf("%d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestLoginRedirectsWhenSignedInRendered(t *testing.T) {
	e := newLoginEnv(t)
	cookie, _ := e.signIn()
	rec := e.get("/login", withCookies(cookie))
	if rec.Code != 303 || rec.Header().Get("Location") != "/" || strings.Contains(rec.Body.String(), "Authenticate") {
		t.Errorf("%d %q", rec.Code, rec.Header().Get("Location"))
	}
}
