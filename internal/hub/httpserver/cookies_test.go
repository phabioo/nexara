package httpserver

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/phabioo/nexara/internal/hub/auth"
	"github.com/phabioo/nexara/internal/hub/setup"
)

// S-17: with TLS every cookie is __Host- prefixed (Secure, Path=/, no Domain);
// the plain-HTTP demo keeps the plain names.
func TestCookieNamesPerMode(t *testing.T) {
	tests := []struct {
		name                     string
		secure                   bool
		csrf, session, challenge string
		challengePath            string
	}{
		{"tls", true, "__Host-nexus_csrf", "__Host-nexus_session", "__Host-nexus_login", "/"},
		{"plain http demo", false, "nexus_csrf", "nexus_session", "nexus_login", "/login"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signIn := func(e *env) (*httptest.ResponseRecorder, *http.Cookie) {
				t.Helper()
				csrf := findCookie(e.get("/login"), tc.csrf)
				if csrf == nil || csrf.Secure != tc.secure || csrf.Path != "/" || csrf.Domain != "" || !csrf.HttpOnly {
					t.Fatalf("csrf cookie = %+v, want name %q", csrf, tc.csrf)
				}
				v := url.Values{fieldOperator: {testOperator}, fieldPass: {testPass}, auth.CSRFFormField: {csrf.Value}}
				return e.post("/login", withCookies(csrf), withForm(v)), csrf
			}

			// Without TOTP: the session cookie.
			rec, _ := signIn(newEnvSecure(t, tc.secure))
			sc := findCookie(rec, tc.session)
			if sc == nil || sc.Secure != tc.secure || sc.Path != "/" || sc.Domain != "" || !sc.HttpOnly {
				t.Fatalf("session cookie = %+v, want name %q", sc, tc.session)
			}
			if cleared := findCookie(rec, tc.csrf); cleared == nil || cleared.MaxAge >= 0 {
				t.Errorf("csrf cookie not cleared under its own name: %+v", cleared)
			}

			// With TOTP: the challenge cookie.
			e := newEnvSecure(t, tc.secure)
			e.addTOTP()
			rec, _ = signIn(e)
			ch := findCookie(rec, tc.challenge)
			if ch == nil || ch.Path != tc.challengePath || ch.Secure != tc.secure || ch.Domain != "" || !ch.HttpOnly {
				t.Fatalf("challenge cookie = %+v, want name %q path %q", ch, tc.challenge, tc.challengePath)
			}
		})
	}
}

// Plain-named cookies are not accepted in TLS mode: another service on the
// same host could have planted them.
func TestTLSModeIgnoresUnprefixedCookies(t *testing.T) {
	e := newEnv(t)
	cookie, _ := e.signIn()

	t.Run("session", func(t *testing.T) {
		plain := &http.Cookie{Name: auth.SessionCookieName, Value: cookie.Value}
		if rec := e.get("/events/ping", withCookies(plain)); rec.Code != http.StatusSeeOther {
			t.Errorf("plain session cookie accepted: %d", rec.Code)
		}
		if rec := e.get("/events/ping", withCookies(cookie)); rec.Code != http.StatusNoContent {
			t.Errorf("prefixed session cookie = %d", rec.Code)
		}
	})
	t.Run("pre-session csrf cookie", func(t *testing.T) {
		tok := findCookie(e.get("/login"), csrfCookieName).Value
		v := url.Values{fieldOperator: {"nobody"}, fieldPass: {"x"}, auth.CSRFFormField: {tok}}
		plain := &http.Cookie{Name: auth.CSRFCookieName, Value: tok}
		if rec := e.post("/login", withCookies(plain), withForm(v)); rec.Code != http.StatusForbidden {
			t.Errorf("plain csrf cookie accepted: %d", rec.Code)
		}
		prefixed := &http.Cookie{Name: csrfCookieName, Value: tok}
		if rec := e.post("/login", withCookies(prefixed), withForm(v)); rec.Code != http.StatusUnauthorized {
			t.Errorf("prefixed csrf cookie = %d, want 401 (reached auth)", rec.Code)
		}
	})
	t.Run("login challenge", func(t *testing.T) {
		e := newEnv(t)
		e.addTOTP()
		tok := findCookie(e.get("/login"), csrfCookieName)
		v := url.Values{fieldOperator: {testOperator}, fieldPass: {testPass}, auth.CSRFFormField: {tok.Value}}
		ch := findCookie(e.post("/login", withCookies(tok), withForm(v)), challengeCookieName)
		if ch == nil {
			t.Fatal("no challenge cookie")
		}
		verify := url.Values{fieldCode: {"123456"}, auth.CSRFFormField: {tok.Value}}
		rec := e.post("/login/verify", withCookies(tok, &http.Cookie{Name: loginChallengeBase, Value: ch.Value}), withForm(verify))
		if !strings.Contains(rec.Body.String(), "Sign-in timed out") {
			t.Errorf("plain challenge cookie treated as the challenge: %d %q", rec.Code, rec.Body.String())
		}
	})
}

func TestSetupCookieShim(t *testing.T) {
	prefixed := auth.CookieName(setup.SessionCookie, true)

	t.Run("request cookies", func(t *testing.T) {
		tests := []struct {
			name   string
			header string
			want   string // the Cookie header the handlers see
		}{
			{"prefixed is presented under the logical name", prefixed + "=tok; other=1", "other=1; " + setup.SessionCookie + "=tok"},
			{"plain setup cookie is dropped", setup.SessionCookie + "=planted; other=1", "other=1"},
			{"plain is dropped, prefixed wins", setup.SessionCookie + "=planted; " + prefixed + "=real", setup.SessionCookie + "=real"},
			{"unrelated cookies untouched", "a=1; b=2", "a=1; b=2"},
			{"no cookies", "", ""},
		}
		for _, tc := range tests {
			r := httptest.NewRequest("GET", "/setup", nil)
			if tc.header != "" {
				r.Header.Set("Cookie", tc.header)
			}
			shimRequestCookies(r)
			got := r.Header.Get("Cookie")
			// Order of the rebuilt header is not part of the contract.
			if !sameCookieSet(got, tc.want) {
				t.Errorf("%s: Cookie = %q, want %q", tc.name, got, tc.want)
			}
		}
	})

	t.Run("response cookies", func(t *testing.T) {
		e := newSetupEnv(t)
		h := e.srv.Handler()
		// Unlock through the full chain: the cookie leaves under the prefixed name.
		b := e.browser(t)
		rec := b.post("/setup/unlock", url.Values{"code": {setup.FormatCode(e.code)}})
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("unlock = %d", rec.Code)
		}
		if findCookie(rec, setup.SessionCookie) != nil {
			t.Error("unprefixed setup cookie leaked")
		}
		c := findCookie(rec, prefixed)
		if c == nil || !c.Secure || !c.HttpOnly || c.Path != "/" || c.Domain != "" || c.SameSite != http.SameSiteStrictMode {
			t.Fatalf("setup cookie = %+v", c)
		}
		// The session works under the prefixed name ...
		if rec := e.do(h, "GET", "/setup/trust", withCookies(c)); rec.Code != http.StatusOK {
			t.Errorf("prefixed setup cookie not accepted: %d", rec.Code)
		}
		// ... and a plain-named cookie with the same token does not.
		plain := &http.Cookie{Name: setup.SessionCookie, Value: c.Value}
		if rec := e.do(h, "GET", "/setup/trust", withCookies(plain)); rec.Code == http.StatusOK {
			t.Errorf("plain setup cookie accepted: %d", rec.Code)
		}
	})

	t.Run("plain mode does nothing", func(t *testing.T) {
		e := newEnvSecure(t, false)
		var seen string
		h := e.srv.setupCookieShim(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen = r.Header.Get("Cookie")
			http.SetCookie(w, &http.Cookie{Name: setup.SessionCookie, Value: "v", Path: "/"})
		}))
		rec := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/setup", nil)
		r.Header.Set("Cookie", setup.SessionCookie+"=tok")
		h.ServeHTTP(rec, r)
		if seen != setup.SessionCookie+"=tok" || findCookie(rec, setup.SessionCookie) == nil {
			t.Errorf("plain mode altered cookies: seen %q, response %v", seen, rec.Result().Cookies())
		}
	})

	t.Run("clearing keeps the attributes", func(t *testing.T) {
		e := newEnv(t)
		h := e.srv.setupCookieShim(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.SetCookie(w, e.srv.setup.Sessions.ClearCookie())
			http.SetCookie(w, &http.Cookie{Name: "other", Value: "1", Path: "/x"})
			w.WriteHeader(http.StatusNoContent)
		}))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/setup", nil))
		c := findCookie(rec, prefixed)
		if c == nil || c.MaxAge >= 0 || !c.Secure || c.Path != "/" {
			t.Errorf("clear cookie = %+v", c)
		}
		if o := findCookie(rec, "other"); o == nil || o.Path != "/x" {
			t.Errorf("unrelated cookie changed: %+v", o)
		}
	})
}

func sameCookieSet(a, b string) bool {
	split := func(s string) map[string]bool {
		m := map[string]bool{}
		for _, p := range strings.Split(s, ";") {
			if p = strings.TrimSpace(p); p != "" {
				m[p] = true
			}
		}
		return m
	}
	ma, mb := split(a), split(b)
	if len(ma) != len(mb) {
		return false
	}
	for k := range ma {
		if !mb[k] {
			return false
		}
	}
	return true
}
