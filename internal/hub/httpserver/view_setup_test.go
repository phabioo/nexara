package httpserver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/phabioo/nexara/internal/hub/auth"
	"github.com/phabioo/nexara/internal/hub/setup"
	"github.com/phabioo/nexara/internal/hub/views"
	"github.com/phabioo/nexara/web"
)

const setupTestPass = "correct horse battery 7!"

// setupClock is an adjustable clock shared by the code, session and server clocks.
type setupClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *setupClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *setupClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// setupEnv is a server in setup mode with real templates, a fake clock and a
// recording commit hook.
type setupEnv struct {
	*env
	clock *setupClock
	code  string // the current setup code, normalized

	mu        sync.Mutex
	committed []setup.Result
	commitFn  func(res setup.Result) (SetupOutcome, error)
}

func newSetupEnv(t *testing.T) *setupEnv {
	t.Helper()
	e := newEnv(t)
	r, err := views.New(web.Templates, views.Options{})
	if err != nil {
		t.Fatal(err)
	}
	e.srv.renderer = r
	clock := &setupClock{t: time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)}
	e.srv.now = clock.Now
	e.srv.setup.Codes = setup.NewCodes(setup.CodeOptions{Now: clock.Now})
	e.srv.setup.Sessions = setup.NewSessions(setup.SessionOptions{Now: clock.Now})
	e.setSetupMode(true)
	code, _, err := e.srv.setup.Codes.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	se := &setupEnv{env: e, clock: clock, code: code}
	e.srv.setup.Commit = func(_ context.Context, res setup.Result, _ string) (SetupOutcome, error) {
		se.mu.Lock()
		defer se.mu.Unlock()
		se.committed = append(se.committed, res)
		if se.commitFn != nil {
			return se.commitFn(res)
		}
		return SetupOutcome{OperatorID: res.OperatorID}, nil
	}
	return se
}

// setupBrowser is a cookie jar plus the helpers to drive the wizard.
type setupBrowser struct {
	t  *testing.T
	e  *setupEnv
	j  jar
	ho string // Host header
}

func (e *setupEnv) browser(t *testing.T) *setupBrowser {
	return &setupBrowser{t: t, e: e, j: jar{}}
}

func (b *setupBrowser) do(method, target string, form url.Values, extra ...reqOpt) *httptest.ResponseRecorder {
	b.t.Helper()
	opts := []reqOpt{withJar(b.j)}
	if b.ho != "" {
		host := b.ho
		opts = append(opts, func(r *http.Request) { r.Host = host })
	}
	if form != nil {
		opts = append(opts, withForm(form))
	}
	opts = append(opts, extra...)
	rec := b.e.do(b.e.srv.Handler(), method, target, opts...)
	b.j.absorb(rec)
	return rec
}

func (b *setupBrowser) get(target string) *httptest.ResponseRecorder {
	b.t.Helper()
	return b.do(http.MethodGet, target, nil)
}

// post submits a form with the double-submit token of the jar (fetching a page
// first if the browser has none yet).
func (b *setupBrowser) post(target string, v url.Values) *httptest.ResponseRecorder {
	b.t.Helper()
	if b.j[csrfCookieName] == nil {
		b.get("/setup")
	}
	if v == nil {
		v = url.Values{}
	}
	if v.Get(auth.CSRFFormField) == "" {
		v.Set(auth.CSRFFormField, b.j[csrfCookieName].Value)
	}
	return b.do(http.MethodPost, target, v)
}

func (b *setupBrowser) unlock() {
	b.t.Helper()
	rec := b.post("/setup/unlock", url.Values{"code": {setup.FormatCode(b.e.code)}})
	if rec.Code != 303 || rec.Header().Get("Location") != "/setup/trust" {
		b.t.Fatalf("unlock: %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func (b *setupBrowser) token() string { return b.j[setupCookieName].Value }

func wantRedirect(t *testing.T, rec *httptest.ResponseRecorder, loc string) {
	t.Helper()
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != loc {
		t.Fatalf("got %d %q, want 303 %q", rec.Code, rec.Header().Get("Location"), loc)
	}
}

func wantBody(t *testing.T, rec *httptest.ResponseRecorder, want ...string) {
	t.Helper()
	body := rec.Body.String()
	for _, w := range want {
		if !strings.Contains(body, w) {
			t.Errorf("body lacks %q", w)
		}
	}
}

func wantNoBody(t *testing.T, rec *httptest.ResponseRecorder, bad ...string) {
	t.Helper()
	body := rec.Body.String()
	for _, w := range bad {
		if strings.Contains(body, w) {
			t.Errorf("body contains %q", w)
		}
	}
}

// walkTo completes the wizard up to (not including) the given step.
func (b *setupBrowser) walkTo(step setup.Step) {
	b.t.Helper()
	b.unlock()
	type stage struct {
		path string
		form url.Values
	}
	stages := []stage{
		{"/setup/trust", nil},
		{"/setup/operator", url.Values{"id": {"Fabio"}, "passphrase": {setupTestPass}, "confirm": {setupTestPass}}},
		{"/setup/two-factor", url.Values{"skip": {"1"}}},
		{"/setup/hub", url.Values{"name": {"frpi5"}, "timezone": {"Europe/Berlin"}, "agent_host": {"frpi5.local"}, "https_port": {"8443"}, "retention": {"365"}}},
		{"/setup/self-link", url.Values{"self_link": {"1"}, "capabilities": {"monitoring", "shell"}}},
	}
	for i := 0; i < int(step)-1; i++ {
		rec := b.post(stages[i].path, stages[i].form)
		if rec.Code != 303 {
			b.t.Fatalf("%s: %d\n%s", stages[i].path, rec.Code, rec.Body.String())
		}
	}
}

// --- tests ---------------------------------------------------------------------

func TestSetupUnlockPage(t *testing.T) {
	e := newSetupEnv(t)
	for _, path := range []string{"/setup", "/setup/unlock"} {
		t.Run(path, func(t *testing.T) {
			rec := e.browser(t).get(path)
			if rec.Code != 200 {
				t.Fatalf("status %d", rec.Code)
			}
			wantBody(t, rec, "Claim this hub", "STEP 1/7", "Printed by the installer", "XXXX-XXXX", "5 attempts",
				`name="csrf_token"`, `action="/setup/unlock"`, "sudo nexus setup code")
			// Decision #28: the restore link stays hidden in v0.1.
			wantNoBody(t, rec, "Restore", "backup")
			// The real code must never be on the page.
			wantNoBody(t, rec, e.code, setup.FormatCode(e.code))
			if c := findCookie(rec, csrfCookieName); c == nil {
				t.Error("no CSRF cookie")
			} else {
				assertCookieAttrs(t, c)
			}
			if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") {
				t.Errorf("csp = %q", csp)
			}
		})
	}
}

func TestSetupRouting(t *testing.T) {
	e := newSetupEnv(t)
	tests := []struct {
		name, method, path string
		wantCode           int
		wantLoc            string
	}{
		{"unknown step", "GET", "/setup/bogus", 404, ""},
		{"step without session", "GET", "/setup/trust", 303, "/setup"},
		{"ready without session", "GET", "/setup/ready", 303, "/setup"},
		{"other pages are gated", "GET", "/", 303, "/setup"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := e.browser(t).do(tt.method, tt.path, nil)
			if rec.Code != tt.wantCode || rec.Header().Get("Location") != tt.wantLoc {
				t.Errorf("got %d %q", rec.Code, rec.Header().Get("Location"))
			}
		})
	}

	t.Run("setup is closed once an operator exists", func(t *testing.T) {
		e := newSetupEnv(t)
		e.setSetupMode(false)
		wantRedirect(t, e.browser(t).get("/setup"), "/")
		wantRedirect(t, e.browser(t).get("/setup/operator"), "/")
	})
}

func TestSetupUnlockPost(t *testing.T) {
	t.Run("correct code starts a session", func(t *testing.T) {
		for _, form := range []string{"{code}", "{code-lower}", " {code} "} {
			e := newSetupEnv(t)
			b := e.browser(t)
			code := setup.FormatCode(e.code)
			v := strings.NewReplacer("{code}", code, "{code-lower}", strings.ToLower(code)).Replace(form)
			rec := b.post("/setup/unlock", url.Values{"code": {v}})
			wantRedirect(t, rec, "/setup/trust")
			c := findCookie(rec, setupCookieName)
			assertCookieAttrs(t, c)
			if c.MaxAge != 0 || c.Path != "/" {
				t.Errorf("cookie = %+v", c)
			}
			wantRedirect(t, b.get("/setup"), "/setup/trust") // GET /setup continues where it stopped
		}
	})

	t.Run("malformed input does not use an attempt", func(t *testing.T) {
		e := newSetupEnv(t)
		b := e.browser(t)
		for _, v := range []string{"", "ABC", "AAAA-AAAAA", "AAAA-AA!A"} {
			rec := b.post("/setup/unlock", url.Values{"code": {v}})
			if rec.Code != 400 {
				t.Errorf("%q: status %d", v, rec.Code)
			}
			wantBody(t, rec, "Enter the 8-character setup code")
		}
		if left := e.srv.setup.Codes.AttemptsLeft(); left != setup.MaxAttempts {
			t.Errorf("attempts left = %d", left)
		}
	})

	t.Run("wrong codes count down and lock", func(t *testing.T) {
		e := newSetupEnv(t)
		b := e.browser(t)
		wrong := "AAAA-AAAA"
		if e.code == "AAAAAAAA" {
			wrong = "BBBB-BBBB"
		}
		for i, want := range []string{"4 attempts left", "3 attempts left", "2 attempts left", "1 attempt left"} {
			rec := b.post("/setup/unlock", url.Values{"code": {wrong}})
			if rec.Code != 401 {
				t.Fatalf("try %d: status %d", i+1, rec.Code)
			}
			wantBody(t, rec, "Code invalid or expired. "+want+".", strconv.Itoa(setup.MaxAttempts-i-1)+" of 5 attempts left")
			if findCookie(rec, setupCookieName) != nil {
				t.Error("session cookie set after a wrong code")
			}
		}
		rec := b.post("/setup/unlock", url.Values{"code": {wrong}})
		if rec.Code != 429 {
			t.Fatalf("5th wrong code: status %d", rec.Code)
		}
		if ra := rec.Header().Get("Retry-After"); ra != "900" {
			t.Errorf("Retry-After = %q", ra)
		}
		wantBody(t, rec, "Input locked for 15 minutes", "About 15 minutes left")
		wantNoBody(t, rec, `id="f-code"`)

		// The correct code does not help during the lock, and the page shows it.
		e.clock.Add(5 * time.Minute)
		rec = b.post("/setup/unlock", url.Values{"code": {setup.FormatCode(e.code)}})
		if rec.Code != 429 || rec.Header().Get("Retry-After") != "600" {
			t.Errorf("during lock: %d, Retry-After %q", rec.Code, rec.Header().Get("Retry-After"))
		}
		rec = b.get("/setup")
		wantBody(t, rec, "Input locked for 15 minutes", "About 10 minutes left", ` disabled`)
		wantNoBody(t, rec, `id="f-code"`)

		// After the lock a fresh code is generated and the field is back.
		e.clock.Add(11 * time.Minute)
		rec = b.get("/setup")
		wantBody(t, rec, `id="f-code"`, "5 attempts")
		wantNoBody(t, rec, "Input locked")
	})

	t.Run("an expired code is rejected", func(t *testing.T) {
		e := newSetupEnv(t)
		old := setup.FormatCode(e.code)
		e.clock.Add(setup.CodeValidity + time.Second)
		// Verify rotates the expired code first, so the old one is wrong now.
		rec := e.browser(t).post("/setup/unlock", url.Values{"code": {old}})
		if rec.Code != 401 {
			t.Errorf("status %d", rec.Code)
		}
	})
}

func TestSetupCSRF(t *testing.T) {
	e := newSetupEnv(t)
	good := func(b *setupBrowser) url.Values {
		return url.Values{auth.CSRFFormField: {b.j[csrfCookieName].Value}}
	}
	for _, path := range []string{"/setup/unlock", "/setup/trust", "/setup/operator", "/setup/two-factor", "/setup/hub", "/setup/self-link", "/setup/ready"} {
		t.Run(path, func(t *testing.T) {
			b := e.browser(t)
			b.get("/setup")
			cases := map[string]url.Values{
				"no token":    {},
				"wrong token": {auth.CSRFFormField: {flipFirst(good(b).Get(auth.CSRFFormField))}},
			}
			for name, v := range cases {
				if rec := b.do(http.MethodPost, path, v); rec.Code != 403 {
					t.Errorf("%s: status %d", name, rec.Code)
				}
			}
			// Without the cookie the matching token is worthless.
			tok := good(b)
			rec := e.do(e.srv.Handler(), http.MethodPost, path, withForm(tok))
			if rec.Code != 403 {
				t.Errorf("no cookie: status %d", rec.Code)
			}
		})
	}
}

func TestSetupSessionExpiry(t *testing.T) {
	e := newSetupEnv(t)
	b := e.browser(t)
	b.unlock()
	wantRedirect(t, b.post("/setup/trust", nil), "/setup/operator")

	e.clock.Add(setup.SessionIdle + time.Minute)
	t.Run("GET goes back to Unlock", func(t *testing.T) {
		wantRedirect(t, b.get("/setup/operator"), "/setup")
	})
	t.Run("POST shows Unlock with a message", func(t *testing.T) {
		rec := b.post("/setup/operator", url.Values{"id": {"x"}})
		if rec.Code != 401 {
			t.Errorf("status %d", rec.Code)
		}
		wantBody(t, rec, "Claim this hub", "The setup session expired", `id="f-code"`)
	})
	t.Run("commit does not run", func(t *testing.T) {
		rec := b.post("/setup/ready", nil)
		if rec.Code != 401 || len(e.committed) != 0 {
			t.Errorf("status %d, commits %d", rec.Code, len(e.committed))
		}
	})
}

func TestSetupOutOfOrder(t *testing.T) {
	e := newSetupEnv(t)
	b := e.browser(t)
	b.unlock()
	tests := []struct{ method, path, wantLoc string }{
		{"GET", "/setup/operator", "/setup/trust"},
		{"GET", "/setup/ready", "/setup/trust"},
		{"POST", "/setup/operator", "/setup/trust"},
		{"POST", "/setup/hub", "/setup/trust"},
		{"POST", "/setup/ready", "/setup/trust"},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			var rec *httptest.ResponseRecorder
			if tt.method == "GET" {
				rec = b.get(tt.path)
			} else {
				rec = b.post(tt.path, url.Values{"id": {"fabio"}, "passphrase": {setupTestPass}, "confirm": {setupTestPass}})
			}
			wantRedirect(t, rec, tt.wantLoc)
		})
	}
	if len(e.committed) != 0 {
		t.Error("committed out of order")
	}
	// Completing Trust opens exactly the next step.
	wantRedirect(t, b.post("/setup/trust", nil), "/setup/operator")
	wantRedirect(t, b.get("/setup/hub"), "/setup/operator")
	if rec := b.get("/setup/operator"); rec.Code != 200 {
		t.Errorf("operator: %d", rec.Code)
	}
}

func TestSetupOperatorStep(t *testing.T) {
	tests := []struct {
		name string
		form url.Values
		want []string // messages expected on the re-rendered page
	}{
		{"short id", url.Values{"id": {"ab"}, "passphrase": {setupTestPass}, "confirm": {setupTestPass}}, []string{"Use 3 to 32 characters."}},
		{"bad characters", url.Values{"id": {"fa bio"}, "passphrase": {setupTestPass}, "confirm": {setupTestPass}}, []string{"Use only letters, digits, dot, dash and underscore."}},
		{"short passphrase", url.Values{"id": {"fabio"}, "passphrase": {"short"}, "confirm": {"short"}}, []string{"Use at least 12 characters."}},
		{"mismatch", url.Values{"id": {"fabio"}, "passphrase": {setupTestPass}, "confirm": {"other"}}, []string{"The passphrases do not match."}},
		{"everything wrong", url.Values{"id": {""}, "passphrase": {""}, "confirm": {"x"}}, []string{"Use 3 to 32 characters.", "Use at least 12 characters.", "The passphrases do not match."}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newSetupEnv(t)
			b := e.browser(t)
			b.walkTo(setup.StepOperator)
			rec := b.post("/setup/operator", tt.form)
			if rec.Code != 422 {
				t.Fatalf("status %d", rec.Code)
			}
			wantBody(t, rec, append(tt.want, `role="alert"`, `aria-invalid="true"`, "Create operator")...)
			// Nothing secret comes back.
			wantNoBody(t, rec, setupTestPass, "correct horse")
			// The wizard did not advance.
			wantRedirect(t, b.get("/setup/two-factor"), "/setup/operator")
		})
	}

	t.Run("valid input advances and is pre-filled when coming back", func(t *testing.T) {
		e := newSetupEnv(t)
		b := e.browser(t)
		b.walkTo(setup.StepOperator)
		wantRedirect(t, b.post("/setup/operator", url.Values{"id": {"Fabio"}, "passphrase": {setupTestPass}, "confirm": {setupTestPass}}), "/setup/two-factor")
		rec := b.get("/setup/operator")
		wantBody(t, rec, `value="fabio"`)
		wantNoBody(t, rec, setupTestPass)
	})

	t.Run("the form keeps the typed id on errors", func(t *testing.T) {
		e := newSetupEnv(t)
		b := e.browser(t)
		b.walkTo(setup.StepOperator)
		rec := b.post("/setup/operator", url.Values{"id": {"  Fab io "}, "passphrase": {"x"}, "confirm": {"y"}})
		wantBody(t, rec, `value="Fab io"`)
	})
}

func TestSetupTrustStepWithoutCA(t *testing.T) {
	e := newSetupEnv(t)
	b := e.browser(t)
	b.unlock()
	rec := b.get("/setup/trust")
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	wantBody(t, rec, "Trust this hub", "not available in this mode", "Skip for now", `href="/setup/unlock"`)
	wantNoBody(t, rec, "<svg class=\"qr\"", "nexara-ca.crt")
	for _, p := range []string{"/setup/trust/nexara-ca.crt", "/setup/trust/nexara-ca.mobileconfig"} {
		if rec := b.get(p); rec.Code != 404 {
			t.Errorf("%s: status %d", p, rec.Code)
		}
	}
}

func totpStep(t *testing.T, b *setupBrowser) (secret string) {
	t.Helper()
	return setupTOTPSecret(b.token())
}

func TestSetupTwoFactorStep(t *testing.T) {
	t.Run("page shows QR code and manual key", func(t *testing.T) {
		e := newSetupEnv(t)
		b := e.browser(t)
		b.walkTo(setup.StepTwoFactor)
		rec := b.get("/setup/two-factor")
		secret := totpStep(t, b)
		wantBody(t, rec, "Two-factor login", `<svg class="qr"`, setupGroup(secret, 4), `inputmode="numeric"`, "Skip for now", "Required from v0.2.")
		wantNoBody(t, rec, secret) // the ungrouped secret is only inside the QR path as modules, never as text
		// Reloading shows the same secret.
		if rec2 := b.get("/setup/two-factor"); !strings.Contains(rec2.Body.String(), setupGroup(secret, 4)) {
			t.Error("secret changed on reload")
		}
		// A different session gets a different secret.
		b2 := e.browser(t)
		b2.walkTo(setup.StepTwoFactor)
		if setupTOTPSecret(b2.token()) == secret {
			t.Error("two sessions share a secret")
		}
	})

	t.Run("code validation", func(t *testing.T) {
		e := newSetupEnv(t)
		b := e.browser(t)
		b.walkTo(setup.StepTwoFactor)
		secret := totpStep(t, b)
		good, err := totp.GenerateCode(secret, time.Now())
		if err != nil {
			t.Fatal(err)
		}

		for name, code := range map[string]string{"empty": "", "wrong": wrongCodeFor(secret), "letters": "abcdef"} {
			rec := b.post("/setup/two-factor", url.Values{"totp": {code}})
			if rec.Code != 422 {
				t.Errorf("%s: status %d", name, rec.Code)
			}
			wantBody(t, rec, `role="alert"`)
		}
		wantRedirect(t, b.get("/setup/hub"), "/setup/two-factor")

		wantRedirect(t, b.post("/setup/two-factor", url.Values{"totp": {good}}), "/setup/hub")
		// The hub step's status line reflects the choice.
		wantBody(t, b.get("/setup/hub"), "Two-factor login enabled")
		se := e.committedAfter(t, b)
		if se.TOTPSecret != secret || se.TOTPSkipped {
			t.Errorf("result = %+v", se)
		}
	})

	t.Run("skip", func(t *testing.T) {
		e := newSetupEnv(t)
		b := e.browser(t)
		b.walkTo(setup.StepTwoFactor)
		wantRedirect(t, b.post("/setup/two-factor", url.Values{"skip": {"1"}, "totp": {"123456"}}), "/setup/hub")
		wantBody(t, b.get("/setup/hub"), "Two-factor login skipped")
		res := e.committedAfter(t, b)
		if !res.TOTPSkipped || res.TOTPSecret != "" {
			t.Errorf("result = %+v", res)
		}
	})
}

// committedAfter finishes the wizard and returns the committed Result.
func (e *setupEnv) committedAfter(t *testing.T, b *setupBrowser) setup.Result {
	t.Helper()
	for _, step := range []struct {
		path string
		form url.Values
	}{
		{"/setup/hub", url.Values{"name": {"frpi5"}, "timezone": {"UTC"}, "agent_host": {"frpi5.local"}, "https_port": {"8443"}, "retention": {"90"}}},
		{"/setup/self-link", url.Values{}},
		{"/setup/ready", nil},
	} {
		if rec := b.post(step.path, step.form); rec.Code != 303 {
			t.Fatalf("%s: %d\n%s", step.path, rec.Code, rec.Body.String())
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.committed) != 1 {
		t.Fatalf("commits = %d", len(e.committed))
	}
	return e.committed[0]
}

func TestSetupHubStep(t *testing.T) {
	valid := func() url.Values {
		return url.Values{"name": {"frpi5"}, "timezone": {"Europe/Berlin"}, "agent_host": {"frpi5.local"}, "https_port": {"8443"}, "retention": {"365"}}
	}
	with := func(k, v string) url.Values { f := valid(); f.Set(k, v); return f }
	tests := []struct {
		name string
		form url.Values
		want string // message, empty = accepted
	}{
		{"valid", valid(), ""},
		{"name with space", with("name", "my hub"), "Use 1 to 63 letters, digits, dots, dashes or underscores"},
		{"name with umlaut", with("name", "hübner"), "Use 1 to 63 letters"},
		{"empty name", with("name", ""), "Use 1 to 63 letters"},
		{"leading dash", with("name", "-hub"), "starting with a letter or digit"},
		{"unknown zone", with("timezone", "Mars/Base"), "Unknown time zone."},
		{"local zone", with("timezone", "Local"), "Choose a time zone."},
		{"host with port", with("agent_host", "frpi5:8443"), "Enter a host name or IP address."},
		{"port text", with("https_port", "abc"), "Enter a port between 1 and 65535."},
		{"port zero", with("https_port", "0"), "Enter a port between 1 and 65535."},
		{"port too big", with("https_port", "70000"), "Enter a port between 1 and 65535."},
		{"retention unknown", with("retention", "7"), "Choose one of the offered periods."},
		{"retention missing", with("retention", ""), "Choose one of the offered periods."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newSetupEnv(t)
			b := e.browser(t)
			b.walkTo(setup.StepHub)
			rec := b.post("/setup/hub", tt.form)
			if tt.want == "" {
				wantRedirect(t, rec, "/setup/self-link")
				return
			}
			if rec.Code != 422 {
				t.Fatalf("status %d", rec.Code)
			}
			wantBody(t, rec, tt.want, "Hub settings")
			// What was typed is still in the form.
			wantBody(t, rec, `value="`+tt.form.Get("name")+`"`)
		})
	}

	t.Run("defaults come from the address the hub was reached on", func(t *testing.T) {
		e := newSetupEnv(t)
		b := e.browser(t)
		b.ho = "frpi5.local:8443"
		b.walkTo(setup.StepHub)
		rec := b.get("/setup/hub")
		wantBody(t, rec, `name="agent_host"`, `value="frpi5.local"`, `value="8443"`)
		wantBody(t, rec, `value="365" checked`)
	})

	t.Run("saved values come back", func(t *testing.T) {
		e := newSetupEnv(t)
		b := e.browser(t)
		b.walkTo(setup.StepHub)
		wantRedirect(t, b.post("/setup/hub", with("retention", "30")), "/setup/self-link")
		rec := b.get("/setup/hub")
		wantBody(t, rec, `value="30" checked`, `value="Europe/Berlin"`)
		wantNoBody(t, rec, `value="365" checked`)
	})
}

func TestSetupSelfLinkStep(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		e := newSetupEnv(t)
		b := e.browser(t)
		b.walkTo(setup.StepSelfLink)
		rec := b.get("/setup/self-link")
		wantBody(t, rec, "Manage this Pi", "Monitoring", "Packages", "Shell", "Power", "Docker",
			`name="self_link" value="1" checked`, `value="monitoring" checked`, `value="power" checked`)
		wantNoBody(t, rec, `value="docker" checked`)
		wantNoBody(t, rec, `value="services"`) // part of Monitoring
	})

	t.Run("choices are stored; monitoring includes services", func(t *testing.T) {
		e := newSetupEnv(t)
		b := e.browser(t)
		b.walkTo(setup.StepSelfLink)
		wantRedirect(t, b.post("/setup/self-link", url.Values{"self_link": {"1"}, "capabilities": {"monitoring", "docker"}}), "/setup/ready")
		rec := b.get("/setup/ready")
		wantBody(t, rec, "Yes · Monitoring, Docker")
		res := func() setup.Result {
			rec := b.post("/setup/ready", nil)
			wantRedirect(t, rec, "/login?setup=done")
			e.mu.Lock()
			defer e.mu.Unlock()
			return e.committed[0]
		}()
		got := strings.Join(res.SelfLink.Capabilities, ",")
		if !res.SelfLink.Enabled || got != "monitoring,services,docker" {
			t.Errorf("self-link = %+v", res.SelfLink)
		}
	})

	t.Run("switched off", func(t *testing.T) {
		e := newSetupEnv(t)
		b := e.browser(t)
		b.walkTo(setup.StepSelfLink)
		wantRedirect(t, b.post("/setup/self-link", url.Values{"capabilities": {"shell"}}), "/setup/ready")
		wantBody(t, b.get("/setup/ready"), `<b>No</b>`)
		rec := b.get("/setup/self-link")
		wantNoBody(t, rec, `name="self_link" value="1" checked`)
	})

	t.Run("unknown capability", func(t *testing.T) {
		e := newSetupEnv(t)
		b := e.browser(t)
		b.walkTo(setup.StepSelfLink)
		rec := b.post("/setup/self-link", url.Values{"self_link": {"1"}, "capabilities": {"shell", "root"}})
		if rec.Code != 422 {
			t.Fatalf("status %d", rec.Code)
		}
		wantBody(t, rec, "Unknown capability: root")
	})
}

func TestSetupReadyAndCommit(t *testing.T) {
	ready := func(t *testing.T, fn func(setup.Result) (SetupOutcome, error)) (*setupEnv, *setupBrowser) {
		e := newSetupEnv(t)
		e.commitFn = fn
		b := e.browser(t)
		b.walkTo(setup.StepReady)
		return e, b
	}

	t.Run("page summarizes without secrets", func(t *testing.T) {
		_, b := ready(t, nil)
		rec := b.get("/setup/ready")
		if rec.Code != 200 {
			t.Fatalf("status %d", rec.Code)
		}
		wantBody(t, rec, "Ready to finish", "STEP 7/7", "Finish setup", "Source", "New installation", "fabio", "Skipped (required from v0.2)",
			"frpi5 · frpi5.local:8443", "Minutes 7 days · hours 1 year", "Yes · Monitoring, Shell", "Not installed yet", `action="/setup/ready"`)
		wantNoBody(t, rec, setupTestPass, "Enter Nexus")
	})

	tests := []struct {
		name     string
		hook     func(setup.Result) (SetupOutcome, error)
		wantCode int
		wantLoc  string
		wantBody []string
		noBody   []string
	}{
		{"success", nil, 303, "/login?setup=done", nil, nil},
		{"already done elsewhere", func(setup.Result) (SetupOutcome, error) { return SetupOutcome{}, ErrSetupDone }, 303, "/login", nil, nil},
		{"session lost", func(setup.Result) (SetupOutcome, error) { return SetupOutcome{}, ErrNoSetupSession }, 401, "", []string{"The setup session expired", `id="f-code"`}, nil},
		{"validation error", func(setup.Result) (SetupOutcome, error) {
			return SetupOutcome{}, setup.ValidationError{"passphrase": "That passphrase is too common.", "hub": "hub.agent_address is invalid"}
		}, 422, "", []string{"That passphrase is too common.", "hub.agent_address is invalid", "Finish setup", `role="alert"`}, nil},
		{"not ready", func(setup.Result) (SetupOutcome, error) { return SetupOutcome{}, setup.ErrNotReady }, 303, "/setup/ready", nil, nil},
		{"internal error", func(setup.Result) (SetupOutcome, error) { return SetupOutcome{}, errors.New("disk full: /secret/path") }, 500, "", []string{"Internal Server Error"}, []string{"disk full", "/secret/path"}},
		{"warnings are shown once", func(res setup.Result) (SetupOutcome, error) {
			return SetupOutcome{OperatorID: res.OperatorID, Warnings: []string{"The hub's own agent could not be linked automatically; add it with an enrollment code."}}, nil
		}, 200, "", []string{"Setup complete", "Hub online", "could not be linked automatically", `href="/login"`, "Enter Nexus"}, []string{"Finish setup", setupTestPass}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, b := ready(t, tt.hook)
			rec := b.post("/setup/ready", nil)
			if rec.Code != tt.wantCode || rec.Header().Get("Location") != tt.wantLoc {
				t.Fatalf("got %d %q\n%s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
			}
			wantBody(t, rec, tt.wantBody...)
			wantNoBody(t, rec, tt.noBody...)
			if len(e.committed) != 1 {
				t.Fatalf("commits = %d", len(e.committed))
			}
			r := e.committed[0]
			if r.OperatorID != "fabio" || r.Passphrase != setupTestPass || r.Hub.Name != "frpi5" || r.Hub.RetentionDays != 365 || !r.TOTPSkipped {
				t.Errorf("result = %+v", r)
			}
			// The setup cookie is gone exactly when the commit succeeded.
			cleared := findCookie(rec, setupCookieName)
			wantCleared := tt.wantCode == 200 || tt.wantLoc == "/login?setup=done"
			if wantCleared != (cleared != nil && cleared.MaxAge < 0) {
				t.Errorf("setup cookie cleared = %v, want %v", cleared != nil, wantCleared)
			}
			// No secrets or codes in any URL.
			if loc := rec.Header().Get("Location"); strings.Contains(loc, setupTestPass) || strings.Contains(loc, e.code) {
				t.Errorf("secret in redirect %q", loc)
			}
		})
	}

	t.Run("commit hook missing", func(t *testing.T) {
		e, b := ready(t, nil)
		e.srv.setup.Commit = nil
		rec := b.post("/setup/ready", nil)
		if rec.Code != 500 {
			t.Errorf("status %d", rec.Code)
		}
	})

	t.Run("a failed commit can be retried", func(t *testing.T) {
		calls := 0
		_, b := ready(t, func(res setup.Result) (SetupOutcome, error) {
			calls++
			if calls == 1 {
				return SetupOutcome{}, errors.New("transient")
			}
			return SetupOutcome{OperatorID: res.OperatorID}, nil
		})
		if rec := b.post("/setup/ready", nil); rec.Code != 500 {
			t.Fatalf("first: %d", rec.Code)
		}
		wantRedirect(t, b.post("/setup/ready", nil), "/login?setup=done")
	})
}

func TestSetupBackLinks(t *testing.T) {
	e := newSetupEnv(t)
	b := e.browser(t)
	b.unlock()

	t.Run("Trust goes back to Unlock, which continues without a code", func(t *testing.T) {
		wantBody(t, b.get("/setup/trust"), `href="/setup/unlock"`)
		rec := b.get("/setup/unlock")
		wantBody(t, rec, "Claim this hub", "<span>Continue</span>")
		wantRedirect(t, b.post("/setup/unlock", url.Values{"code": {""}}), "/setup/trust")
	})

	t.Run("later steps link to the previous step", func(t *testing.T) {
		b.walkTo(setup.StepReady)
		for path, back := range map[string]string{
			"/setup/operator":   "/setup/trust",
			"/setup/two-factor": "/setup/operator",
			"/setup/hub":        "/setup/two-factor",
			"/setup/self-link":  "/setup/hub",
			"/setup/ready":      "/setup/self-link",
		} {
			rec := b.get(path)
			if rec.Code != 200 {
				t.Fatalf("%s: %d", path, rec.Code)
			}
			wantBody(t, rec, `class="btn-card btn-card-grey" href="`+back+`"`)
		}
		wantNoBody(t, b.get("/setup/trust"), "Restore")
	})
}

func TestSetupStatusAndStepList(t *testing.T) {
	e := newSetupEnv(t)
	b := e.browser(t)
	b.walkTo(setup.StepHub)
	rec := b.get("/setup/hub")
	wantBody(t, rec, "STEP 5/7", "SETUP", "5/7", `aria-current="step"`, "Self-link", "Two-factor", "setup_gate_", "SETUP MODE · LAN ONLY")
	if n := strings.Count(rec.Body.String(), `class="step-item done"`); n != 4 {
		t.Errorf("done steps = %d, want 4", n)
	}
}

func TestSetupNoRendererFallback(t *testing.T) {
	e := newSetupEnv(t)
	e.srv.renderer = nil
	rec := e.browser(t).get("/setup")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Claim this hub") {
		t.Errorf("got %d %q", rec.Code, rec.Body.String())
	}
}

func TestSetupHelpers(t *testing.T) {
	t.Run("address defaults", func(t *testing.T) {
		tests := []struct{ host, wantHost, wantPort string }{
			{"frpi5.local:8443", "frpi5.local", "8443"},
			{"192.0.2.5:9000", "192.0.2.5", "9000"},
			{"[2001:db8::1]:8443", "2001:db8::1", "8443"},
			{"frpi5.local", "frpi5.local", "8443"},
			{"frpi5.local:notaport", "frpi5.local", "8443"},
			{"frpi5.local:0", "frpi5.local", "8443"},
		}
		for _, tt := range tests {
			r := httptest.NewRequest("GET", "/setup", nil)
			r.Host = tt.host
			if h, p := setupAddressDefaults(r); h != tt.wantHost || p != tt.wantPort {
				t.Errorf("%q: got %q %q", tt.host, h, p)
			}
		}
	})
	t.Run("zone from link", func(t *testing.T) {
		tests := map[string]string{
			"/usr/share/zoneinfo/Europe/Berlin":         "Europe/Berlin",
			"../usr/share/zoneinfo/UTC":                 "UTC",
			"/var/db/timezone/zoneinfo/America/Chicago": "America/Chicago",
			"/etc/whatever":                             "",
		}
		for in, want := range tests {
			if got := setupZoneFromLink(in); got != want {
				t.Errorf("%q: got %q, want %q", in, got, want)
			}
		}
	})
	t.Run("group", func(t *testing.T) {
		tests := []struct {
			in   string
			n    int
			want string
		}{{"ABCDEFGHIJ", 4, "ABCD EFGH IJ"}, {"", 4, ""}, {"ABCD", 4, "ABCD"}}
		for _, tt := range tests {
			if got := setupGroup(tt.in, tt.n); got != tt.want {
				t.Errorf("%q: got %q", tt.in, got)
			}
		}
	})
	t.Run("code shape", func(t *testing.T) {
		tests := map[string]bool{"7KQ2-M9XD": true, "7kq2m9xd": true, " 7KQ2 M9XD ": true, "7KQ2-M9X": false, "": false, "7KQ2-M9X!": false, "7KQ2-M9XDD": false}
		for in, want := range tests {
			if got := setupWellFormedCode(in); got != want {
				t.Errorf("%q: got %v", in, got)
			}
		}
	})
	t.Run("lock left", func(t *testing.T) {
		tests := map[time.Duration]string{
			-time.Second: "a moment", 0: "a moment", time.Second: "1 minute", time.Minute: "1 minute",
			time.Minute + time.Second: "2 minutes", 15 * time.Minute: "15 minutes",
		}
		for in, want := range tests {
			if got := setupLockLeft(in); got != want {
				t.Errorf("%v: got %q, want %q", in, got, want)
			}
		}
	})
	t.Run("totp secret", func(t *testing.T) {
		a, b := setupTOTPSecret("token-a"), setupTOTPSecret("token-b")
		if a == b || a != setupTOTPSecret("token-a") {
			t.Error("secret must be deterministic per token and differ between tokens")
		}
		if len(a) != 32 || strings.ToUpper(a) != a {
			t.Errorf("secret %q is not 32 base32 characters", a)
		}
		u := setupOTPAuthURL(a, "fab io")
		for _, want := range []string{"otpauth://totp/Nexara%20Nexus:fab%20io?", "secret=" + a, "issuer=Nexara+Nexus"} {
			if !strings.Contains(u, want) {
				t.Errorf("%q lacks %q", u, want)
			}
		}
	})
	t.Run("short hostname matches the hub name pattern", func(t *testing.T) {
		if h := setupShortHostname(); h == "" || len(h) > 63 {
			t.Errorf("hostname %q", h)
		}
	})
}

// TestSetupOperatorMessages pins the message for every cause on the Operator
// step, including the injected passphrase policy (the wiring passes the auth
// rules). Each cause must produce exactly its own message, never another's.
func TestSetupOperatorMessages(t *testing.T) {
	policy := func(p string) error {
		switch {
		case len([]rune(p)) > 40:
			return errors.New("Use at most 40 characters.")
		case strings.Contains(p, "password"):
			return errors.New("That passphrase is too common.")
		}
		return nil
	}
	long := strings.Repeat("x", 41)
	all := []string{
		"Use 3 to 32 characters.",
		"Use only letters, digits, dot, dash and underscore.",
		"Use at least 12 characters.",
		"Use at most 40 characters.",
		"That passphrase is too common.",
		"The passphrases do not match.",
	}
	form := func(id, pass, confirm string) url.Values {
		return url.Values{"id": {id}, "passphrase": {pass}, "confirm": {confirm}}
	}
	tests := []struct {
		name string
		form url.Values
		want []string // exactly these messages, in this order
	}{
		{"too short", form("fabio", "short", "short"), []string{"Use at least 12 characters."}},
		{"eleven characters", form("fabio", "elevenchars", "elevenchars"), []string{"Use at least 12 characters."}},
		{"twelve characters are fine", form("fabio", "twelve chars", "twelve chars"), nil},
		{"long but repeat differs", form("fabio", setupTestPass, setupTestPass+"x"), []string{"The passphrases do not match."}},
		{"repeat empty", form("fabio", setupTestPass, ""), []string{"The passphrases do not match."}},
		{"policy: too common", form("fabio", "my password is long", "my password is long"), []string{"That passphrase is too common."}},
		{"policy: too long", form("fabio", long, long), []string{"Use at most 40 characters."}},
		{"id too short", form("ab", setupTestPass, setupTestPass), []string{"Use 3 to 32 characters."}},
		{"id too long", form(strings.Repeat("a", 33), setupTestPass, setupTestPass), []string{"Use 3 to 32 characters."}},
		{"id with space", form("fa bio", setupTestPass, setupTestPass), []string{"Use only letters, digits, dot, dash and underscore."}},
		{"id with umlaut", form("fäbio", setupTestPass, setupTestPass), []string{"Use only letters, digits, dot, dash and underscore."}},
		{"id empty", form("", setupTestPass, setupTestPass), []string{"Use 3 to 32 characters."}},
		{"id and passphrase wrong", form("x", "short", "short"), []string{"Use 3 to 32 characters.", "Use at least 12 characters."}},
		{"three problems", form("x y", "short", "other"), []string{"Use only letters, digits, dot, dash and underscore.", "Use at least 12 characters.", "The passphrases do not match."}},
		{"long passphrase is accepted with the matching repeat", form("fabio", setupTestPass, setupTestPass), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newSetupEnv(t)
			e.srv.setup.Sessions = setup.NewSessions(setup.SessionOptions{
				Now: e.clock.Now, Wizard: setup.WizardOptions{CheckPassphrase: policy},
			})
			b := e.browser(t)
			b.walkTo(setup.StepOperator)
			rec := b.post("/setup/operator", tt.form)
			if tt.want == nil {
				wantRedirect(t, rec, "/setup/two-factor")
				return
			}
			if rec.Code != 422 {
				t.Fatalf("status %d", rec.Code)
			}
			body := rec.Body.String()
			var got []string
			for _, m := range all {
				if strings.Contains(body, m) {
					got = append(got, m)
				}
			}
			// Compare as sets, and check the order of the rows in the page.
			if len(got) != len(tt.want) {
				t.Fatalf("messages = %q, want %q", got, tt.want)
			}
			last := -1
			for _, w := range tt.want {
				i := strings.Index(body, w)
				if i < 0 || i < last {
					t.Fatalf("message %q missing or out of order (messages = %q)", w, got)
				}
				last = i
			}
			if strings.Contains(body, "auth:") || strings.Contains(body, "does not meet the policy") {
				t.Error("internal error text reaches the form")
			}
			if n := strings.Count(body, `role="alert"`); n != len(tt.want) {
				t.Errorf("error rows = %d, want %d", n, len(tt.want))
			}
		})
	}
}

// flipFirst changes the first character, so the result never equals the input (a fixed replacement
// would equal it for one token in 64).
func flipFirst(tok string) string {
	if strings.HasPrefix(tok, "x") {
		return "y" + tok[1:]
	}
	return "x" + tok[1:]
}
