package httpserver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/auth"
	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/hub/store"
)

func TestSettingsPage(t *testing.T) {
	s := newSettingsEnv(t)
	_, _ = s.st.AppendAudit(context.Background(), store.AuditEntry{User: testOperator, Action: "login", Result: store.AuditOK})
	rec := s.get("/settings", s.opts(false, false)...)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	contains(t, body,
		// shell
		`data-view="settings"`, `aria-current="page"`, "<title>Settings · Nexara Nexus</title>",
		// 1 operators
		">Operators<", "1 operator", "Operator ID", ">frank<", ">Owner<", ">Enabled<", "Last sign-in", "192.0.2.10", "Change passphrase",
		// 2 security
		">Security<", "Require two-factor login", ">Required<", "Lock sign-in after 5 failed attempts", "15 min", "Session timeout", ">12 h<",
		// 3 updates
		">Updates<", "v0.1.0 · linux/arm64", "1/2 on v0.1.0", "auto-update on", "Check GitHub for new releases", ">Off<", "Check now",
		"Upload update file", "Manual updates",
		// 4 backup
		">Backup<", "Nightly 03:00 · keeps 7 · before updates", "No backup yet", "Back up now", "Download backup", "Nightly at",
		// 5 hosts
		"Hosts &amp; capabilities", "Nexara Grid · 2 hosts", "alpha", "192.0.2.21", "Beta Pi", "Shell", "Packages",
		// 6 certificates
		">Certificates<", "Nexara CA", "SHA-256", "Hub certificate", "auto-renew", "frpi5 · frpi5.local · 192.168.10.21",
		"Agent certificates", "Download CA certificate", `href="/grid/ca.crt"`,
		// 7 diagnostics
		">Diagnostics<", "Hub log", "Agent logs come with a later version",
		// 8 audit
		">Audit log<", "Operator frank signed in", "View all", `href="/settings/audit"`,
	)
	// Views of later versions stay hidden (decision #31), and the fixed settings have no controls (#51, #52).
	lacks(t, body, "Power", "Docker", "Wake", ">24 h<", ">4 h<", "ZgotmplZ")
	if n := strings.Count(body, `class="set-row set-check"`); n != 2 {
		t.Errorf("%d fixed check rows, want 2", n)
	}
}

func TestSettingsPageRequiresSignIn(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{"/settings", "/settings/passphrase", "/settings/logs/hub", "/settings/backup/download"} {
		if rec := e.get(p); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
			t.Errorf("GET %s signed out: %d %q", p, rec.Code, rec.Header().Get("Location"))
		}
	}
	for _, p := range []string{"/settings/passphrase", "/settings/updates/config", "/settings/updates/upload", "/settings/backup/run",
		"/settings/hosts/alpha/capabilities/shell", "/settings/certs/alpha/renew"} {
		if rec := e.post(p); rec.Code == http.StatusOK || rec.Code == http.StatusNoContent {
			t.Errorf("POST %s signed out: %d", p, rec.Code)
		}
	}
}

func TestSettingsPageHidesCardsWithoutServices(t *testing.T) {
	s := newSettingsEnv(t)
	s.srv.svc = Services{}
	rec := s.get("/settings", s.opts(false, false)...)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	body := rec.Body.String()
	contains(t, body, ">Operators<", ">Security<", "Hosts &amp; capabilities", ">Certificates<", ">Diagnostics<", "not available")
	lacks(t, body, ">Updates<", ">Backup<", ">Audit log<", `hx-get="/settings/logs/hub"`)
	// No capability service: the chips are shown but cannot be pressed.
	if strings.Contains(body, "/capabilities/") {
		t.Error("capability switches rendered without a controller")
	}
	if strings.Contains(body, "/renew") {
		t.Error("renew buttons rendered without a renewer")
	}
}

func TestSettingsPageWithoutHosts(t *testing.T) {
	s := newSettingsEnv(t)
	s.hub.fakeHub.mu.Lock()
	s.hub.fakeHub.hosts = nil
	s.hub.fakeHub.mu.Unlock()
	rec := s.get("/settings", s.opts(false, false)...)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	contains(t, rec.Body.String(), "Nexara Grid · 0 hosts", `data-host=""`, "0/0 on v0.1.0")
}

func TestSettingsPageIsBoostable(t *testing.T) {
	// A boosted navigation gets the whole page: htmx takes #main and the shell regions out of it.
	s := newSettingsEnv(t)
	rec := s.get("/settings", s.opts(false, true, withHeader("HX-Boosted", "true"))...)
	contains(t, rec.Body.String(), `id="main"`, `id="nx-tabs"`, `id="set-operators"`)
}

// --- change passphrase ---------------------------------------------------------

func passphraseForm(current, next, confirm string) url.Values {
	return url.Values{"current": {current}, "passphrase": {next}, "confirm": {confirm}}
}

func TestPassphraseDialog(t *testing.T) {
	s := newSettingsEnv(t)
	rec := s.hxGet("/settings/passphrase")
	contains(t, rec.Body.String(), `hx-post="/settings/passphrase"`, `name="current"`, `name="passphrase"`, `name="confirm"`,
		`autocomplete="current-password"`, `autocomplete="new-password"`, "All other sessions are signed out", "data-modal-close")
}

func TestPassphraseChange(t *testing.T) {
	const newPass = "a much longer passphrase 42"
	s := newSettingsEnv(t)
	// A second session of the same operator (another browser).
	other, otherCSRF := s.signIn()
	rec := s.hxPost("/settings/passphrase", passphraseForm(testPass, newPass, newPass))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("HX-Redirect"); got != "/settings" {
		t.Errorf("HX-Redirect = %q, want a full load of /settings (the CSRF token of the new session)", got)
	}
	fresh := findCookie(rec, sessionCookieName)
	assertCookieAttrs(t, fresh)
	if fresh.Value == s.cookie.Value {
		t.Error("the session ID was not rotated")
	}

	// The old cookie and the other browser's session are gone, the new cookie works.
	for name, c := range map[string]*http.Cookie{"this browser before": s.cookie, "other browser": other} {
		if r := s.get("/settings", withCookies(c)); r.Code != http.StatusSeeOther {
			t.Errorf("%s still signed in: %d", name, r.Code)
		}
	}
	_ = otherCSRF
	if r := s.get("/settings", withCookies(fresh)); r.Code != http.StatusOK {
		t.Errorf("new session: %d", r.Code)
	}
	// The passphrase itself changed, with argon2id.
	u, err := s.st.GetUserByOperatorID(context.Background(), testOperator)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(u.PassHash, "$argon2id$") {
		t.Errorf("hash %q is not argon2id", u.PassHash)
	}
	if _, err := s.svc.Login(context.Background(), testOperator, testPass, "192.0.2.10", "t", false); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("old passphrase still works: %v", err)
	}
	if _, err := s.svc.Login(context.Background(), testOperator, newPass, "192.0.2.10", "t", false); !passAccepted(err) {
		t.Errorf("new passphrase does not work: %v", err)
	}
	// Audited without the passphrases.
	au := s.auditFor("user.passphrase")
	if len(au) != 1 || au[0].User != testOperator || au[0].Result != store.AuditOK || !strings.Contains(au[0].Detail, "other sessions ended: 2") {
		t.Fatalf("audit = %+v", au)
	}
	for _, e := range []store.AuditEntry{au[0]} {
		if strings.Contains(e.Detail, newPass) || strings.Contains(e.Detail, testPass) {
			t.Error("a passphrase reached the audit log")
		}
	}
	if logs := s.logs.String(); strings.Contains(logs, newPass) || strings.Contains(logs, testPass) {
		t.Error("a passphrase reached the log")
	}
}

func TestPassphraseChangeKeepsPersistentSession(t *testing.T) {
	s := newSettingsEnv(t)
	u, err := s.st.GetUserByOperatorID(context.Background(), testOperator)
	if err != nil {
		t.Fatal(err)
	}
	raw, sess, err := s.svc.Sessions().Create(context.Background(), u, true, "192.0.2.10", "t")
	if err != nil {
		t.Fatal(err)
	}
	s.cookie = &http.Cookie{Name: sessionCookieName, Value: raw}
	s.csrf = s.svc.CSRFToken(sess)
	rec := s.hxPost("/settings/passphrase", passphraseForm(testPass, "another long passphrase", "another long passphrase"))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status %d", rec.Code)
	}
	if c := findCookie(rec, sessionCookieName); c == nil || c.MaxAge <= 0 {
		t.Errorf("a persistent session lost its lifetime: %+v", c)
	}
}

func TestPassphraseChangeErrors(t *testing.T) {
	long := "a much longer passphrase 42"
	tests := []struct {
		name   string
		form   url.Values
		status int
		want   string
	}{
		{"empty", passphraseForm("", "", ""), 422, "Enter your current and your new passphrase."},
		{"wrong current", passphraseForm("not the passphrase", long, long), 422, "The current passphrase is not correct."},
		{"mismatch", passphraseForm(testPass, long, long+"x"), 422, "The new passphrases do not match."},
		{"too short", passphraseForm(testPass, "short", "short"), 422, "needs at least 12 characters"},
		{"unchanged", passphraseForm(testPass, testPass, testPass), 422, "differs from the current one"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newSettingsEnv(t)
			rec := s.hxPost("/settings/passphrase", tc.form)
			if rec.Code != tc.status {
				t.Fatalf("status %d, want %d", rec.Code, tc.status)
			}
			body := rec.Body.String()
			contains(t, body, tc.want, `hx-post="/settings/passphrase"`, `role="alert"`)
			lacks(t, body, long, testPass, "not the passphrase")
			// Nothing changed: same passphrase, same session.
			if r := s.get("/settings", withCookies(s.cookie)); r.Code != http.StatusOK {
				t.Errorf("session ended by a rejected change: %d", r.Code)
			}
			if _, err := s.svc.Login(context.Background(), testOperator, testPass, "192.0.2.10", "t", false); !passAccepted(err) {
				t.Errorf("passphrase changed by a rejected request: %v", err)
			}
			if len(s.auditFor("user.passphrase"))-boolInt(tc.name == "wrong current") != 0 {
				t.Errorf("audit = %+v", s.auditFor("user.passphrase"))
			}
		})
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func TestPassphraseChangeLocksAfterWrongEntries(t *testing.T) {
	s := newSettingsEnv(t)
	long := "a much longer passphrase 42"
	for i := 0; i < 5; i++ {
		if rec := s.hxPost("/settings/passphrase", passphraseForm("wrong"+strings.Repeat("x", i), long, long)); rec.Code != 422 {
			t.Fatalf("attempt %d: %d", i, rec.Code)
		}
	}
	// The right current passphrase is refused as well while locked.
	rec := s.hxPost("/settings/passphrase", passphraseForm(testPass, long, long))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d, want 429", rec.Code)
	}
	contains(t, rec.Body.String(), "Too many wrong entries", "15 minutes")
	if _, err := s.svc.Login(context.Background(), testOperator, testPass, "192.0.2.10", "t", false); !passAccepted(err) {
		t.Errorf("a locked change must not change the passphrase: %v", err)
	}
	if got := len(s.auditFor("user.passphrase")); got != 5 {
		t.Errorf("%d audit entries for 5 wrong entries", got)
	}
}

func TestAttemptLimiter(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	l := &attemptLimiter{max: 2, window: 10 * time.Minute}
	if _, b := l.blocked(1, now); b {
		t.Fatal("blocked before any failure")
	}
	l.fail(1, now)
	l.fail(1, now.Add(time.Minute))
	if wait, b := l.blocked(1, now.Add(2*time.Minute)); !b || wait != 8*time.Minute {
		t.Errorf("blocked = %v, wait %v; want blocked for 8m", b, wait)
	}
	if _, b := l.blocked(2, now.Add(2*time.Minute)); b {
		t.Error("another operator is blocked")
	}
	if _, b := l.blocked(1, now.Add(10*time.Minute)); b {
		t.Error("still blocked after the oldest failure left the window")
	}
	l.fail(1, now.Add(11*time.Minute))
	l.reset(1)
	if _, b := l.blocked(1, now.Add(11*time.Minute)); b {
		t.Error("blocked after a reset")
	}
	for in, want := range map[time.Duration]string{time.Second: "1 minute", 61 * time.Second: "2 minutes", 15 * time.Minute: "15 minutes"} {
		if got := waitText(in); got != want {
			t.Errorf("waitText(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestPassphraseRejectsMissingCSRF(t *testing.T) {
	s := newSettingsEnv(t)
	rec := s.post("/settings/passphrase", s.opts(false, true, withForm(passphraseForm(testPass, "a much longer passphrase 42", "a much longer passphrase 42")))...)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rec.Code)
	}
	if _, err := s.svc.Login(context.Background(), testOperator, testPass, "192.0.2.10", "t", false); !passAccepted(err) {
		t.Errorf("passphrase changed without a CSRF token: %v", err)
	}
}

// --- hosts and capabilities ----------------------------------------------------

func TestHostCapabilityChips(t *testing.T) {
	s := newSettingsEnv(t)
	body := s.get("/settings", s.opts(false, false)...).Body.String()
	// alpha offers both and has both on: two switches. beta offers no packages: that chip is unavailable.
	contains(t, body,
		`hx-post="/settings/hosts/alpha/capabilities/shell"`, `hx-post="/settings/hosts/alpha/capabilities/packages"`,
		`hx-post="/settings/hosts/beta/capabilities/shell"`,
		"Not offered by this agent: Packages", "agent.yaml", `title="Not offered by this agent"`,
		`hx-get="/settings/hosts/beta/remove"`, "Hub &#43; agent")
	lacks(t, body, `/settings/hosts/beta/capabilities/packages`, `/settings/hosts/alpha/remove`)
}

func TestHostCapabilityToggle(t *testing.T) {
	s := newSettingsEnv(t)
	rec := s.hxPost("/settings/hosts/alpha/capabilities/shell", url.Values{"enabled": {"false"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	// The answer is the host row, with the shell chip off and a switch back on, and a toast.
	contains(t, body, `id="set-host-a1"`, `name="enabled" value="true"`, `id="toasts"`, "Saved", "alpha | Shell off")
	if calls := s.caps.recorded(); len(calls) != 1 || calls[0] != "a1/shell/off" {
		t.Errorf("calls = %v", calls)
	}
	if s.caps.actor.Operator != testOperator || s.caps.actor.IP == "" {
		t.Errorf("actor = %+v", s.caps.actor)
	}
	if i := strings.Index(body, `hx-post="/settings/hosts/alpha/capabilities/shell"`); i < 0 || !strings.Contains(body[i:i+700], `aria-pressed="false"`) {
		t.Errorf("the shell chip is not shown off:\n%s", body)
	}

	// Back on.
	rec = s.hxPost("/settings/hosts/alpha/capabilities/shell", url.Values{"enabled": {"true"}})
	contains(t, rec.Body.String(), "alpha | Shell on", `name="enabled" value="false"`)
}

func TestHostCapabilityErrors(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		form   url.Values
		csrf   bool
		err    error
		noCaps bool
		status int
		want   string
	}{
		{"no csrf", "/settings/hosts/alpha/capabilities/shell", url.Values{"enabled": {"false"}}, false, nil, false, 403, ""},
		{"unknown host", "/settings/hosts/nope/capabilities/shell", url.Values{"enabled": {"false"}}, true, nil, false, 404, ""},
		{"power stays hidden", "/settings/hosts/alpha/capabilities/power", url.Values{"enabled": {"false"}}, true, nil, false, 404, "cannot be switched"},
		{"docker stays hidden", "/settings/hosts/alpha/capabilities/docker", url.Values{"enabled": {"true"}}, true, nil, false, 404, "cannot be switched"},
		{"monitoring is not a switch", "/settings/hosts/alpha/capabilities/monitoring", url.Values{"enabled": {"false"}}, true, nil, false, 404, "cannot be switched"},
		{"no value", "/settings/hosts/alpha/capabilities/shell", url.Values{}, true, nil, false, 400, "switch it on or off"},
		{"bad value", "/settings/hosts/alpha/capabilities/shell", url.Values{"enabled": {"maybe"}}, true, nil, false, 400, "switch it on or off"},
		{"not offered by the agent", "/settings/hosts/beta/capabilities/packages", url.Values{"enabled": {"true"}}, true, grid.ErrUnsupported, false, 422, "The agent on beta does not offer Packages."},
		{"host vanished", "/settings/hosts/alpha/capabilities/shell", url.Values{"enabled": {"false"}}, true, grid.ErrHostNotFound, false, 404, "Host not found"},
		{"store failure is not echoed", "/settings/hosts/alpha/capabilities/shell", url.Values{"enabled": {"false"}}, true, errors.New("database secret path"), false, 500, "Something went wrong"},
		{"no controller", "/settings/hosts/alpha/capabilities/shell", url.Values{"enabled": {"false"}}, true, nil, true, 404, "cannot be changed"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newSettingsEnv(t)
			s.caps.err = tc.err
			if tc.noCaps {
				s.srv.svc.Caps = nil
			}
			opts := s.opts(tc.csrf, true, withForm(tc.form))
			rec := s.post(tc.path, opts...)
			if rec.Code != tc.status {
				t.Fatalf("status %d, want %d: %s", rec.Code, tc.status, rec.Body.String())
			}
			if tc.want != "" {
				contains(t, rec.Body.String(), tc.want)
				lacks(t, rec.Body.String(), "database secret path")
				if rec.Header().Get("HX-Retarget") != "#toasts" {
					t.Errorf("error is not a toast: %v", rec.Header())
				}
			}
		})
	}
}

func TestSettingsRemoveHost(t *testing.T) {
	s := newSettingsEnv(t)
	dialog := s.hxGet("/settings/hosts/beta/remove")
	if dialog.Code != http.StatusOK {
		t.Fatalf("dialog status %d", dialog.Code)
	}
	// The overview's dialog, posting to Settings so the browser stays here.
	contains(t, dialog.Body.String(), "Remove host", `hx-post="/settings/hosts/beta/remove"`, "Beta Pi")
	if rec := s.hxGet("/settings/hosts/nope/remove"); rec.Code != 404 {
		t.Errorf("unknown host dialog: %d", rec.Code)
	}

	rec := s.hxPost("/settings/hosts/beta/remove", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	hl := rec.Header().Get("HX-Location")
	contains(t, hl, `"path":"/settings"`, `"target":"#main"`, "#nx-tabs")
	if got := s.hub.removed; len(got) != 1 || got[0] != "b2" {
		t.Errorf("removed = %v", got)
	}
	// A plain form post is redirected.
	s = newSettingsEnv(t)
	rec = s.post("/settings/hosts/beta/remove", s.opts(true, false)...)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/settings" {
		t.Errorf("plain post: %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

// C-08: the hub's own host (alpha in this env) cannot be removed, whatever the route or the request style.
func TestSettingsRefusesRemovingTheHubsOwnHost(t *testing.T) {
	s := newSettingsEnv(t)
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"dialog":     s.hxGet("/settings/hosts/alpha/remove"),
		"htmx post":  s.hxPost("/settings/hosts/alpha/remove", nil),
		"plain post": s.post("/settings/hosts/alpha/remove", s.opts(true, false)...),
	} {
		if rec.Code != http.StatusConflict {
			t.Errorf("%s: status %d, want 409", name, rec.Code)
		}
		if name != "plain post" {
			contains(t, rec.Body.String(), "Not removed", "device the hub runs on")
		}
		if strings.Contains(rec.Body.String(), `hx-post="/settings/hosts/alpha/remove"`) {
			t.Errorf("%s offers the removal", name)
		}
	}
	if len(s.hub.removed) != 0 {
		t.Errorf("the hub's own host was removed: %v", s.hub.removed)
	}
}

func TestSettingsRemoveHostErrors(t *testing.T) {
	s := newSettingsEnv(t)
	if rec := s.post("/settings/hosts/beta/remove", s.opts(false, true)...); rec.Code != 403 {
		t.Errorf("no csrf: %d", rec.Code)
	}
	if rec := s.hxPost("/settings/hosts/nope/remove", nil); rec.Code != 404 {
		t.Errorf("unknown host: %d", rec.Code)
	}
	s.hub.rmErr = errors.New("revocation list is not writable")
	rec := s.hxPost("/settings/hosts/beta/remove", nil)
	if rec.Code != 500 {
		t.Fatalf("status %d", rec.Code)
	}
	lacks(t, rec.Body.String(), "revocation list")
	contains(t, rec.Body.String(), "Not removed")
}

// --- certificates --------------------------------------------------------------

func TestCertificatesCard(t *testing.T) {
	s := newSettingsEnv(t)
	body := s.get("/settings", s.opts(false, false)...).Body.String()
	// alpha is online and valid, beta is offline and due within 30 days: it counts as valid but due.
	contains(t, body, "2 valid · 1 due for renewal", `hx-post="/settings/certs/alpha/renew"`, "offline")
	lacks(t, body, `/settings/certs/beta/renew`)
}

func TestCertificateRenew(t *testing.T) {
	s := newSettingsEnv(t)
	rec := s.hxPost("/settings/certs/alpha/renew", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	contains(t, rec.Body.String(), `id="set-certs"`, "Renewing", "alpha | new certificate requested")
	if len(s.certs.calls) != 1 || s.certs.calls[0] != "a1" {
		t.Errorf("calls = %v", s.certs.calls)
	}
}

func TestCertificateRenewErrors(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		err      error
		noRenew  bool
		noCSRF   bool
		status   int
		want     string
		wantCall bool
	}{
		{name: "no csrf", path: "/settings/certs/alpha/renew", noCSRF: true, status: 403},
		{name: "unknown host", path: "/settings/certs/nope/renew", status: 404},
		{name: "no renewer", path: "/settings/certs/alpha/renew", noRenew: true, status: 404, want: "cannot be renewed"},
		{name: "offline", path: "/settings/certs/alpha/renew", err: grid.ErrHostOffline, status: 409, want: "alpha is offline", wantCall: true},
		{name: "already running", path: "/settings/certs/alpha/renew", err: grid.ErrRenewInProgress, status: 409, want: "already running", wantCall: true},
		{name: "old agent", path: "/settings/certs/alpha/renew", err: grid.ErrUnsupported, status: 422, want: "Update the agent first", wantCall: true},
		{name: "timeout", path: "/settings/certs/alpha/renew", err: context.DeadlineExceeded, status: 504, want: "did not answer", wantCall: true},
		{name: "unexpected", path: "/settings/certs/alpha/renew", err: errors.New("ca key is locked"), status: 500, want: "Something went wrong", wantCall: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newSettingsEnv(t)
			s.certs.err = tc.err
			if tc.noRenew {
				s.srv.svc.Certs = nil
			}
			rec := s.post(tc.path, s.opts(!tc.noCSRF, true)...)
			if rec.Code != tc.status {
				t.Fatalf("status %d, want %d: %s", rec.Code, tc.status, rec.Body.String())
			}
			contains(t, rec.Body.String(), tc.want)
			lacks(t, rec.Body.String(), "ca key is locked")
			if got := len(s.certs.calls) > 0; got != tc.wantCall {
				t.Errorf("RenewCert called = %v, want %v", got, tc.wantCall)
			}
		})
	}
}

// --- diagnostics ---------------------------------------------------------------

func TestHubLogDialog(t *testing.T) {
	s := newSettingsEnv(t)
	body := s.hxGet("/settings/logs/hub").Body.String()
	contains(t, body, "Hub log", `role="log"`, "4 of 4", "debug detail", "agent connected host=alpha", "audit write failed",
		"is-warn", "is-error", "is-info", "is-debug", `hx-get="/settings/logs/hub?level=warn"`, "Refresh")
	// Record text is escaped, never markup.
	contains(t, body, "certificate &lt;b&gt;expires&lt;/b&gt; soon")
	lacks(t, body, "<b>expires</b>")
	// Newest first.
	if a, b := strings.Index(body, "audit write failed"), strings.Index(body, "debug detail"); a < 0 || b < 0 || a > b {
		t.Errorf("not newest first: error at %d, debug at %d", a, b)
	}
	for level, want := range map[string]struct {
		count   string
		present []string
		absent  []string
	}{
		"warn":  {"2 of 2", []string{"audit write failed", "expires"}, []string{"agent connected", "debug detail"}},
		"error": {"1 of 1", []string{"audit write failed"}, []string{"expires", "agent connected"}},
		"bogus": {"4 of 4", []string{"debug detail"}, nil},
	} {
		body := s.hxGet("/settings/logs/hub?level=" + level).Body.String()
		contains(t, body, want.count)
		contains(t, body, want.present...)
		lacks(t, body, want.absent...)
	}
}

func TestHubLogDialogIsBounded(t *testing.T) {
	s := newSettingsEnv(t)
	var recs []LogRecord
	for i := 0; i < 1000; i++ {
		recs = append(recs, LogRecord{Time: time.Now(), Level: 0, Text: "line"})
	}
	s.srv.svc.Logs = stgLogs{recs: recs}
	body := s.hxGet("/settings/logs/hub").Body.String()
	contains(t, body, "300 of 1000")
	if n := strings.Count(body, `class="log-line `); n != 300 {
		t.Errorf("%d lines rendered, want 300", n)
	}
	s.srv.svc.Logs = stgLogs{}
	contains(t, s.hxGet("/settings/logs/hub").Body.String(), "Nothing logged at this level.", "0 of 0")
	s.srv.svc.Logs = nil
	if rec := s.hxGet("/settings/logs/hub"); rec.Code != 404 {
		t.Errorf("without a log source: %d", rec.Code)
	}
}

// --- audit card ----------------------------------------------------------------

func TestAuditCardShowsTheNewestThree(t *testing.T) {
	s := newSettingsEnv(t)
	ctx := context.Background()
	base := time.Now().Add(time.Hour) // after the sign-in of the test itself
	for i, e := range []store.AuditEntry{
		{User: "frank", Action: "login", Result: store.AuditOK},
		{User: "frank", Host: "alpha", Action: "shell.open", Detail: "session x", Result: store.AuditOK},
		{User: "frank", Action: "backup.create", Result: store.AuditOK},
		{User: "frank", Host: "alpha", Action: "host.capabilities", Detail: "shell off", Result: store.AuditOK},
		{User: "mallory", Action: "login", Result: store.AuditError},
	} {
		e.Time = base.Add(time.Duration(i) * time.Minute)
		if _, err := s.st.AppendAudit(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	body := s.get("/settings", s.opts(false, false)...).Body.String()
	contains(t, body, "Last 3 entries", "Sign-in failed for mallory", "Capability on alpha: shell off", "Backup created", `class="set-row set-audit-row is-bad"`)
	lacks(t, body, "Shell opened by")
}

// passAccepted reports whether Login accepted the passphrase: the test
// operator has two-factor login, so a right passphrase asks for the code.
func passAccepted(err error) bool {
	return err == nil || errors.Is(err, auth.ErrSecondFactorRequired)
}
