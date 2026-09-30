package httpserver

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/phabioo/nexara/internal/hub/auth"
)

// loginForm fetches the login page and returns a jar holding the CSRF cookie and the token.
func loginForm(t *testing.T, e *env) (jar, string) {
	t.Helper()
	j := jar{}
	rec := e.get("/login")
	if rec.Code != 200 {
		t.Fatalf("GET /login = %d", rec.Code)
	}
	j.absorb(rec)
	c := j[auth.CSRFCookieName]
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
	e := newEnv(t)
	rec := e.get("/login")
	c := findCookie(rec, auth.CSRFCookieName)
	assertCookieAttrs(t, c)
	if len(c.Value) != 43 {
		t.Errorf("token length %d", len(c.Value))
	}
	// An existing valid cookie is reused, not rotated.
	rec2 := e.get("/login", withCookies(c))
	if findCookie(rec2, auth.CSRFCookieName) != nil {
		t.Error("valid csrf cookie was replaced")
	}
	// A garbage cookie is replaced.
	rec3 := e.get("/login", withCookies(&http.Cookie{Name: auth.CSRFCookieName, Value: "x"}))
	if findCookie(rec3, auth.CSRFCookieName) == nil {
		t.Error("garbage csrf cookie was kept")
	}
}

func TestLoginRedirectsWhenSignedIn(t *testing.T) {
	e := newEnv(t)
	cookie, _ := e.signIn()
	rec := e.get("/login", withCookies(cookie))
	if rec.Code != 303 || rec.Header().Get("Location") != "/" {
		t.Errorf("got %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestLoginWithoutTOTP(t *testing.T) {
	e := newEnv(t)

	t.Run("success, browser-session cookie", func(t *testing.T) {
		j, token := loginForm(t, e)
		rec := e.post("/login", withJar(j), withForm(creds(token, testOperator, testPass)))
		if rec.Code != 303 || rec.Header().Get("Location") != "/" {
			t.Fatalf("got %d %q", rec.Code, rec.Header().Get("Location"))
		}
		sc := findCookie(rec, auth.SessionCookieName)
		assertCookieAttrs(t, sc)
		if sc.MaxAge != 0 || sc.Path != "/" || sc.Value == "" {
			t.Errorf("session cookie: maxage=%d path=%q value-empty=%v", sc.MaxAge, sc.Path, sc.Value == "")
		}
		if c := findCookie(rec, auth.CSRFCookieName); c == nil || c.MaxAge >= 0 {
			t.Errorf("csrf cookie not cleared: %+v", c)
		}
		if _, _, err := e.svc.Sessions().Validate(context.Background(), sc.Value); err != nil {
			t.Errorf("session not valid: %v", err)
		}
		// The new cookie opens the app.
		if rec := e.get("/", withCookies(sc)); rec.Code != 501 {
			t.Errorf("GET / with new session = %d", rec.Code)
		}
	})

	t.Run("keep me signed in gives a persistent cookie", func(t *testing.T) {
		j, token := loginForm(t, e)
		rec := e.post("/login", withJar(j), withForm(creds(token, testOperator, testPass, fieldKeep, "on")))
		sc := findCookie(rec, auth.SessionCookieName)
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
		if findCookie(rec, auth.SessionCookieName) != nil {
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
		if a.Code != b.Code || a.Body.String() != b.Body.String() {
			t.Errorf("responses differ: %d %q vs %d %q", a.Code, a.Body.String(), b.Code, b.Body.String())
		}
	})
}

func TestLoginRateLimit(t *testing.T) {
	e := newEnv(t)
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
	e := newEnv(t)
	secret := e.addTOTP()

	j, token := loginForm(t, e)
	rec := e.post("/login", withJar(j), withForm(creds(token, testOperator, testPass, fieldKeep, "on")))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Two-factor") {
		t.Fatalf("step one: %d %q", rec.Code, rec.Body.String())
	}
	if findCookie(rec, auth.SessionCookieName) != nil {
		t.Fatal("session issued before the second factor")
	}
	ch := findCookie(rec, loginChallengeCookie)
	assertCookieAttrs(t, ch)
	if ch.Path != "/login" || ch.MaxAge <= 0 || ch.MaxAge > int(auth.ChallengeTTL.Seconds()) || ch.Value == "" {
		t.Errorf("challenge cookie: path=%q maxage=%d", ch.Path, ch.MaxAge)
	}
	j.absorb(rec)

	t.Run("wrong code keeps the challenge", func(t *testing.T) {
		v := url.Values{auth.CSRFFormField: {token}, fieldCode: {wrongCodeFor(secret)}}
		rec := e.post("/login/verify", withJar(j), withForm(v))
		if rec.Code != 401 || !strings.Contains(rec.Body.String(), "Invalid authentication code.") {
			t.Fatalf("%d %q", rec.Code, rec.Body.String())
		}
		if findCookie(rec, auth.SessionCookieName) != nil {
			t.Error("session on wrong code")
		}
		if c := findCookie(rec, loginChallengeCookie); c != nil && c.MaxAge < 0 {
			t.Error("challenge dropped after one wrong code")
		}
	})

	t.Run("right code signs in and keeps the persistent choice", func(t *testing.T) {
		v := url.Values{auth.CSRFFormField: {token}, fieldCode: {codeFor(secret)}}
		rec := e.post("/login/verify", withJar(j), withForm(v))
		if rec.Code != 303 || rec.Header().Get("Location") != "/" {
			t.Fatalf("%d %q", rec.Code, rec.Body.String())
		}
		sc := findCookie(rec, auth.SessionCookieName)
		assertCookieAttrs(t, sc)
		if sc.MaxAge <= 0 {
			t.Errorf("persistent choice lost: Max-Age %d", sc.MaxAge)
		}
		if c := findCookie(rec, loginChallengeCookie); c == nil || c.MaxAge >= 0 {
			t.Errorf("challenge cookie not cleared: %+v", c)
		}
	})
}

func TestLoginVerifyWithoutChallenge(t *testing.T) {
	e := newEnv(t)
	e.addTOTP()
	j, token := loginForm(t, e)
	v := url.Values{auth.CSRFFormField: {token}, fieldCode: {"123456"}}
	rec := e.post("/login/verify", withJar(j), withForm(v))
	if rec.Code != 401 || !strings.Contains(rec.Body.String(), "Sign-in timed out") {
		t.Errorf("%d %q", rec.Code, rec.Body.String())
	}
	if c := findCookie(rec, loginChallengeCookie); c == nil || c.MaxAge >= 0 {
		t.Errorf("challenge cookie not cleared: %+v", c)
	}
}

func TestLogout(t *testing.T) {
	e := newEnv(t)

	t.Run("needs csrf", func(t *testing.T) {
		cookie, _ := e.signIn()
		if rec := e.post("/logout", withCookies(cookie)); rec.Code != 403 {
			t.Fatalf("status %d", rec.Code)
		}
		if _, _, err := e.svc.Sessions().Validate(context.Background(), cookie.Value); err != nil {
			t.Errorf("session was deleted by a forged logout: %v", err)
		}
	})

	t.Run("clears cookie and deletes session", func(t *testing.T) {
		cookie, token := e.signIn()
		rec := e.post("/logout", withCookies(cookie), withHeader(auth.CSRFHeader, token))
		if rec.Code != 303 || rec.Header().Get("Location") != "/login" {
			t.Fatalf("%d %q", rec.Code, rec.Header().Get("Location"))
		}
		sc := findCookie(rec, auth.SessionCookieName)
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
