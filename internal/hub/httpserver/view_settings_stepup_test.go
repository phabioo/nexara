package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/auth"
	"github.com/phabioo/nexara/internal/hub/backup"
	"github.com/phabioo/nexara/internal/hub/update"
)

// stepAction is one of the three actions behind the step-up.
type stepAction struct {
	name string
	// setup prepares the state the action needs and returns the form without the step-up fields.
	setup func(t *testing.T, s *settingsEnv) url.Values
	path  string
	// dialog marks the dialog the error answer shows again.
	dialog string
	// done reports whether the action took effect.
	done func(t *testing.T, s *settingsEnv) bool
}

func stepActions() []stepAction {
	return []stepAction{
		{
			name: "download", path: "/settings/backup/download", dialog: `hx-post="/settings/backup/download"`,
			setup: func(t *testing.T, s *settingsEnv) url.Values {
				return url.Values{"passphrase": {bkPass}, "confirm": {bkPass}}
			},
			// Step 1 hands out a grant when it took effect.
			done: func(t *testing.T, s *settingsEnv) bool { return false },
		},
		{
			name: "restore", path: "/settings/backup/restore", dialog: `hx-post="/settings/backup/restore"`,
			setup: func(t *testing.T, s *settingsEnv) url.Values {
				info, err := s.bk.CreateLocal(context.Background(), backup.ReasonManual)
				if err != nil {
					t.Fatal(err)
				}
				return url.Values{"name": {info.Name}}
			},
			done: func(t *testing.T, s *settingsEnv) bool { return s.restarts > 0 },
		},
		{
			name: "install", path: "/settings/updates/install", dialog: `hx-post="/settings/updates/install"`,
			setup: func(t *testing.T, s *settingsEnv) url.Values {
				if rec := s.upload(t, true, s.bundle("0.2.0", 100).files()...); rec.Code != 200 {
					t.Fatal(rec.Body.String())
				}
				return url.Values{"version": {"0.2.0"}}
			},
			done: func(t *testing.T, s *settingsEnv) bool {
				_, err := os.Stat(filepath.Join(s.updDir, update.RequestFile))
				return err == nil
			},
		},
	}
}

// secretFree fails when a step-up secret came back in the answer.
func secretFree(t *testing.T, body string, secrets ...string) {
	t.Helper()
	for _, sec := range secrets {
		lacks(t, body, sec)
	}
}

func TestStepUpFailures(t *testing.T) {
	for _, act := range stepActions() {
		t.Run(act.name, func(t *testing.T) {
			s := newSettingsEnv(t)
			form := act.setup(t, s)
			post := func(f url.Values) *httptest.ResponseRecorder { return s.hxPost(act.path, f) }
			with := func(pass, code string) url.Values {
				f := s.stepUp(form)
				if pass != "-" {
					f.Set(fieldStepUpPass, pass)
				}
				if code != "-" {
					f.Set(fieldStepUpCode, code)
				}
				return f
			}
			wrongCode := func() string {
				good := s.stepUp(nil).Get(fieldStepUpCode)
				if good == "000000" {
					return "111111"
				}
				return "000000"
			}

			for _, tc := range []struct {
				name string
				form func() url.Values
				want string
			}{
				{"wrong passphrase", func() url.Values { return with("not the passphrase", "-") }, "The passphrase is not correct."},
				{"wrong code", func() url.Values { return with("-", wrongCode()) }, "The code is not correct"},
				{"missing passphrase", func() url.Values { return with("", "-") }, "Enter your passphrase and the 6-digit code."},
				{"missing code", func() url.Values { return with("-", "") }, "Enter the 6-digit code from your authenticator."},
				{"malformed code", func() url.Values { return with("-", "12ab56") }, "Enter the 6-digit code from your authenticator."},
				{"no step-up at all", func() url.Values { return form }, "Enter your passphrase and the 6-digit code."},
			} {
				rec := post(tc.form())
				wantStatus := http.StatusUnprocessableEntity
				body := rec.Body.String()
				if rec.Code != wantStatus {
					t.Errorf("%s: status %d, want %d\n%s", tc.name, rec.Code, wantStatus, abbreviate(body))
					continue
				}
				// The dialog stays, with the message in its error row and both fields empty again.
				contains(t, body, tc.want, `role="alert"`, act.dialog, `name="stepup_passphrase"`, `name="stepup_code"`,
					"Confirm with your passphrase and a code from your authenticator.", ">Passphrase</label>", ">6-digit code</label>")
				secretFree(t, body, testPass, "not the passphrase")
				if act.done(t, s) {
					t.Errorf("%s: the action ran", tc.name)
				}
				if strings.Contains(body, `name="download_grant"`) {
					t.Errorf("%s: a grant was issued", tc.name)
				}
			}
			// Incomplete forms did not use up attempts or the one-time code: a valid step-up still passes.
			if rec := post(s.stepUp(form)); rec.Code != http.StatusOK {
				t.Errorf("valid step-up after the failures: %d %s", rec.Code, abbreviate(rec.Body.String()))
			}
			if got := s.auditFor(auth.ActionReauth); len(got) == 0 {
				t.Error("no reauth audit entries")
			}
			for _, e := range s.auditFor(auth.ActionReauth) {
				if strings.Contains(e.Detail, testPass) || strings.Contains(e.Detail, "not the passphrase") {
					t.Errorf("secret in audit: %q", e.Detail)
				}
			}
		})
	}
}

func TestStepUpRateLimited(t *testing.T) {
	for _, act := range stepActions() {
		t.Run(act.name, func(t *testing.T) {
			s := newSettingsEnv(t)
			form := act.setup(t, s)
			bad := s.stepUp(form)
			bad.Set(fieldStepUpPass, "wrong wrong wrong")
			for i := 0; i < 5; i++ {
				if rec := s.hxPost(act.path, bad); rec.Code != http.StatusUnprocessableEntity {
					t.Fatalf("attempt %d: %d", i+1, rec.Code)
				}
			}
			// Even a correct entry is refused while the block lasts.
			rec := s.hxPost(act.path, s.stepUp(form))
			if rec.Code != http.StatusTooManyRequests {
				t.Fatalf("blocked: %d %s", rec.Code, abbreviate(rec.Body.String()))
			}
			if ra := rec.Header().Get("Retry-After"); ra == "" || ra == "0" {
				t.Errorf("Retry-After = %q", ra)
			}
			contains(t, rec.Body.String(), "Too many wrong entries. Try again in", "minute", act.dialog)
			if act.done(t, s) {
				t.Error("the action ran while blocked")
			}
			// Later it works again.
			s.clock.Advance(16 * time.Minute)
			if rec := s.hxPost(act.path, s.stepUp(form)); rec.Code == http.StatusTooManyRequests || rec.Code == http.StatusUnprocessableEntity {
				t.Errorf("after the block: %d %s", rec.Code, abbreviate(rec.Body.String()))
			}
		})
	}
}

func TestStepUpBusy(t *testing.T) {
	for _, act := range stepActions() {
		t.Run(act.name, func(t *testing.T) {
			s := newSettingsEnv(t)
			form := act.setup(t, s)
			done, err := s.env.svc.BeginOperatorAction(s.ensureTOTP().ID)
			if err != nil {
				t.Fatal(err)
			}
			rec := s.hxPost(act.path, s.stepUp(form))
			done()
			if rec.Code != http.StatusTooManyRequests {
				t.Fatalf("busy: %d %s", rec.Code, abbreviate(rec.Body.String()))
			}
			if rec.Header().Get("Retry-After") == "" {
				t.Error("no Retry-After")
			}
			contains(t, rec.Body.String(), "Another check is running.")
			if act.done(t, s) {
				t.Error("the action ran while busy")
			}
		})
	}
}

func TestStepUpCSRF(t *testing.T) {
	for _, act := range stepActions() {
		t.Run(act.name, func(t *testing.T) {
			s := newSettingsEnv(t)
			form := act.setup(t, s)
			rec := s.post(act.path, s.opts(false, true, withForm(s.stepUp(form)))...)
			if rec.Code != http.StatusForbidden {
				t.Errorf("without the CSRF token: %d", rec.Code)
			}
			if act.done(t, s) {
				t.Error("the action ran without a CSRF token")
			}
			// Signed out: sent to sign in, nothing happens.
			if rec := s.post(act.path, withForm(s.stepUp(form))); rec.Code != http.StatusSeeOther {
				t.Errorf("signed out: %d", rec.Code)
			}
		})
	}
}

func TestStepUpDialogsAskForBoth(t *testing.T) {
	s := newSettingsEnv(t)
	info, err := s.bk.CreateLocal(context.Background(), backup.ReasonManual)
	if err != nil {
		t.Fatal(err)
	}
	if rec := s.upload(t, true, s.bundle("0.2.0", 100).files()...); rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	for _, path := range []string{"/settings/backup/download", "/settings/backup/restore?name=" + info.Name, "/settings/updates/install?version=0.2.0"} {
		rec := s.hxGet(path)
		if rec.Code != 200 {
			t.Fatalf("%s: %d", path, rec.Code)
		}
		contains(t, rec.Body.String(), "Confirm with your passphrase and a code from your authenticator.",
			`name="stepup_passphrase"`, `type="password"`, `autocomplete="current-password"`,
			`name="stepup_code"`, `inputmode="numeric"`, `autocomplete="one-time-code"`)
	}
}

// TestStepUpTheSameRequest: a successful step-up leaves nothing behind that a later request could use.
func TestStepUpTheSameRequest(t *testing.T) {
	s := newSettingsEnv(t)
	info, err := s.bk.CreateLocal(context.Background(), backup.ReasonManual)
	if err != nil {
		t.Fatal(err)
	}
	if rec := s.hxPost("/settings/backup/restore", s.stepUp(url.Values{"name": {info.Name}})); rec.Code != 200 {
		t.Fatalf("restore: %d %s", rec.Code, rec.Body.String())
	}
	if s.restarts != 1 {
		t.Fatalf("restarts = %d", s.restarts)
	}
	rec := s.hxPost("/settings/backup/restore", url.Values{"name": {info.Name}})
	if rec.Code != http.StatusUnprocessableEntity || s.restarts != 1 {
		t.Errorf("second restore without a step-up: %d, restarts %d", rec.Code, s.restarts)
	}
	// A used code does not work twice.
	f := s.stepUp(url.Values{"name": {info.Name}})
	if rec := s.hxPost("/settings/backup/restore", f); rec.Code != 200 {
		t.Fatalf("fresh step-up: %d %s", rec.Code, abbreviate(rec.Body.String()))
	}
	if rec := s.hxPost("/settings/backup/restore", f); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("replayed code: %d", rec.Code)
	} else {
		contains(t, rec.Body.String(), "already used")
	}
}

// --- the grant of the download's second step -------------------------------------------------------------------

func TestBackupDownloadGrant(t *testing.T) {
	fetch := func(s *settingsEnv, cookie *http.Cookie, csrf, grant string) *httptest.ResponseRecorder {
		f := url.Values{"passphrase": {bkPass}, "csrf_token": {csrf}}
		if grant != "" {
			f.Set(fieldDownloadGrant, grant)
		}
		return s.post("/settings/backup/download", withCookies(cookie), withForm(f))
	}
	noBackup := func(t *testing.T, s *settingsEnv) {
		t.Helper()
		if _, err := os.Stat(s.lay.BackupDir); err == nil {
			if infos, _ := s.bk.List(context.Background()); len(infos) != 0 {
				t.Errorf("a refused download left a backup: %v", infos)
			}
		}
	}

	t.Run("single use", func(t *testing.T) {
		s := newSettingsEnv(t)
		g := s.downloadGrant(t)
		if rec := fetch(s, s.cookie, s.csrf, g); rec.Code != 200 || !strings.HasPrefix(rec.Body.String(), "NXBKUP") {
			t.Fatalf("first use: %d", rec.Code)
		}
		rec := fetch(s, s.cookie, s.csrf, g)
		if rec.Code != http.StatusForbidden || strings.HasPrefix(rec.Body.String(), "NXBKUP") {
			t.Errorf("second use: %d", rec.Code)
		}
		contains(t, rec.Body.String(), "no longer valid")
	})

	t.Run("without or with a wrong grant", func(t *testing.T) {
		s := newSettingsEnv(t)
		for name, g := range map[string]string{"none": "", "wrong": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"} {
			if rec := fetch(s, s.cookie, s.csrf, g); rec.Code != http.StatusForbidden {
				t.Errorf("%s: %d", name, rec.Code)
			}
		}
		noBackup(t, s)
		// A wrong try burns the open grant: the dialog has to be started again.
		g := s.downloadGrant(t)
		fetch(s, s.cookie, s.csrf, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
		if rec := fetch(s, s.cookie, s.csrf, g); rec.Code != http.StatusForbidden {
			t.Errorf("grant after a wrong try: %d", rec.Code)
		}
	})

	t.Run("another session", func(t *testing.T) {
		s := newSettingsEnv(t)
		g := s.downloadGrant(t)
		u := s.ensureTOTP()
		raw, sess, err := s.env.svc.Sessions().Create(context.Background(), u, false, "192.0.2.11", "other")
		if err != nil {
			t.Fatal(err)
		}
		other := &http.Cookie{Name: sessionCookieName, Value: raw}
		if rec := fetch(s, other, s.env.svc.CSRFToken(sess), g); rec.Code != http.StatusForbidden {
			t.Errorf("grant of another session: %d", rec.Code)
		}
		noBackup(t, s)
		// The owner's grant was not touched by that.
		if rec := fetch(s, s.cookie, s.csrf, g); rec.Code != 200 {
			t.Errorf("owner after the foreign try: %d", rec.Code)
		}
	})

	t.Run("expiry", func(t *testing.T) {
		s := newSettingsEnv(t)
		g := s.downloadGrant(t)
		s.srv.now = func() time.Time { return time.Now().Add(downloadGrantTTL + time.Second) }
		if rec := fetch(s, s.cookie, s.csrf, g); rec.Code != http.StatusForbidden {
			t.Errorf("expired grant: %d", rec.Code)
		}
		noBackup(t, s)
	})

	t.Run("a newer grant replaces the older one", func(t *testing.T) {
		s := newSettingsEnv(t)
		old := s.downloadGrant(t)
		fresh := s.downloadGrant(t)
		if rec := fetch(s, s.cookie, s.csrf, old); rec.Code != http.StatusForbidden {
			t.Errorf("old grant: %d", rec.Code)
		}
		// The failed try consumed the open slot, so the fresh one is gone as well: start over.
		if rec := fetch(s, s.cookie, s.csrf, fresh); rec.Code != http.StatusForbidden {
			t.Errorf("fresh grant after a wrong try: %d", rec.Code)
		}
	})

	t.Run("the htmx header does not skip the step-up", func(t *testing.T) {
		s := newSettingsEnv(t)
		rec := s.hxPost("/settings/backup/download", url.Values{"passphrase": {bkPass}, "confirm": {bkPass}})
		if rec.Code != http.StatusUnprocessableEntity || strings.Contains(rec.Body.String(), "download_grant") {
			t.Errorf("step 1 without a step-up: %d", rec.Code)
		}
	})
}

func TestGrantStore(t *testing.T) {
	t0 := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	g := &grantStore{m: map[string]grant{}}
	a, err := g.issue(t0, "sess-a")
	if err != nil || len(a) < 40 {
		t.Fatalf("issue: %q %v", a, err)
	}
	b, _ := g.issue(t0, "sess-b")
	if a == b {
		t.Error("two grants are equal")
	}
	for _, tc := range []struct {
		name    string
		session string
		token   string
		at      time.Time
		want    bool
	}{
		{"other session", "sess-c", a, t0, false},
		{"other sessions token", "sess-a", b, t0, false},
		{"empty", "sess-a", "", t0, false},
	} {
		if got := g.redeem(tc.at, tc.session, tc.token); got != tc.want {
			t.Errorf("%s: %v", tc.name, got)
		}
	}
	// Any redeem of sess-a (even the wrong ones above) consumed its slot; issue again for the timing cases.
	for _, tc := range []struct {
		name string
		at   time.Duration
		want bool
	}{
		{"just in time", downloadGrantTTL - time.Second, true},
		{"at the limit", downloadGrantTTL, false},
		{"late", downloadGrantTTL + time.Minute, false},
	} {
		tok, _ := g.issue(t0, "sess-t")
		if got := g.redeem(t0.Add(tc.at), "sess-t", tok); got != tc.want {
			t.Errorf("%s: %v", tc.name, got)
		}
		if g.redeem(t0, "sess-t", tok) {
			t.Errorf("%s: redeemed twice", tc.name)
		}
	}
	// Expired grants of other sessions are dropped on the next issue.
	g.issue(t0, "sess-x")
	g.issue(t0.Add(time.Hour), "sess-y")
	g.mu.Lock()
	n := len(g.m)
	g.mu.Unlock()
	if n != 1 {
		t.Errorf("%d grants kept, want 1", n)
	}
}

// --- demo: passphrase only, and only with DemoPasswordOnly ------------------------------------------------------

// goDemo turns the environment into the --seed demo: an operator without TOTP and an auth service in
// DemoPasswordOnly mode.
func goDemo(t *testing.T, s *settingsEnv) {
	t.Helper()
	ctx := context.Background()
	u := s.ensureTOTP()
	if err := s.st.SetTOTP(ctx, u.ID, nil, false); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, auth.SecretKeyLen)
	for i := range key {
		key[i] = byte(i + 1)
	}
	demo, err := auth.NewService(auth.Config{
		Store: s.st, SecretKey: key, IdleTimeout: 12 * time.Hour, RateAttempts: 5, RateWindow: 15 * time.Minute,
		HashParams: testParams, Now: s.clock.Now, CookieOptions: []auth.CookieOption{auth.WithSecure(false)}, DemoPasswordOnly: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	s.srv.auth = demo
	u, _ = s.st.GetUserByOperatorID(ctx, testOperator)
	raw, sess, err := demo.Sessions().Create(ctx, u, false, "192.0.2.10", "demo")
	if err != nil {
		t.Fatal(err)
	}
	s.cookie, s.csrf = &http.Cookie{Name: demo.Cookies().SessionName(), Value: raw}, demo.CSRFToken(sess)
}

func TestStepUpDemoPassphraseOnly(t *testing.T) {
	for _, act := range stepActions() {
		t.Run(act.name, func(t *testing.T) {
			s := newSettingsEnv(t)
			form := act.setup(t, s)
			goDemo(t, s)

			pass := func(p string) url.Values {
				f := url.Values{}
				for k, v := range form {
					f[k] = v
				}
				f.Set(fieldStepUpPass, p)
				return f
			}
			// A wrong passphrase still fails.
			if rec := s.hxPost(act.path, pass("wrong wrong wrong")); rec.Code != http.StatusUnprocessableEntity {
				t.Errorf("wrong passphrase: %d", rec.Code)
			} else {
				contains(t, rec.Body.String(), "The passphrase is not correct.")
				lacks(t, rec.Body.String(), `name="stepup_code"`)
			}
			// The right one is enough, without any code.
			rec := s.hxPost(act.path, pass(testPass))
			if rec.Code != http.StatusOK {
				t.Fatalf("passphrase only: %d %s", rec.Code, abbreviate(rec.Body.String()))
			}
			if act.name != "download" && !act.done(t, s) {
				t.Error("the action did not run")
			}
		})
	}

	t.Run("dialog without the code field", func(t *testing.T) {
		s := newSettingsEnv(t)
		goDemo(t, s)
		rec := s.hxGet("/settings/backup/download")
		contains(t, rec.Body.String(), `name="stepup_passphrase"`)
		lacks(t, rec.Body.String(), `name="stepup_code"`)
	})

	t.Run("an operator with TOTP still needs the code", func(t *testing.T) {
		s := newSettingsEnv(t) // production auth, TOTP enrolled
		info, _ := s.bk.CreateLocal(context.Background(), backup.ReasonManual)
		f := url.Values{"name": {info.Name}, fieldStepUpPass: {testPass}}
		if rec := s.hxPost("/settings/backup/restore", f); rec.Code != http.StatusUnprocessableEntity || s.restarts != 0 {
			t.Errorf("passphrase only with TOTP: %d, restarts %d", rec.Code, s.restarts)
		}
	})
}

// A production hub (no DemoPasswordOnly) refuses an operator without TOTP: the service answers ErrNoSecondFactor and
// the handler maps it to 403. (Such a session cannot reach the settings routes in a real hub; it is enrollment
// pending, so the check is made on the handler's helper directly.)
func TestStepUpNoSecondFactorProduction(t *testing.T) {
	s := newSettingsEnv(t)
	u := s.ensureTOTP()
	u.TOTPEnabled = false
	r := httptest.NewRequest(http.MethodPost, "/settings/backup/restore", strings.NewReader(url.Values{fieldStepUpPass: {testPass}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(context.WithValue(r.Context(), ctxUser, u))
	w := httptest.NewRecorder()
	status, msg := s.srv.stepUp(w, r)
	if status != http.StatusForbidden || !strings.Contains(msg, "not set up") {
		t.Errorf("status %d, %q", status, msg)
	}
	// The attempt was given back: it does not count towards the block.
	for i := 0; i < 5; i++ {
		r2 := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(url.Values{fieldStepUpPass: {testPass}}.Encode()))
		r2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r2 = r2.WithContext(context.WithValue(r2.Context(), ctxUser, u))
		if st, _ := s.srv.stepUp(httptest.NewRecorder(), r2); st != http.StatusForbidden {
			t.Fatalf("attempt %d: %d", i+2, st)
		}
	}
}

// --- restore: the store was closed but the swap failed ------------------------------------------------------------

func TestRestoreStoreClosed(t *testing.T) {
	// A directory with a file in it where the restore wants to move nexus.yaml aside makes the swap fail.
	breakSwap := func(t *testing.T, s *settingsEnv) {
		t.Helper()
		bak := s.lay.ConfigPath + backup.BeforeRestoreSuffix
		if err := os.MkdirAll(bak, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(bak, "x"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("database closed: the hub restarts", func(t *testing.T) {
		s := newSettingsEnv(t)
		closed := 0
		s.useBeforeSwap(func() error { closed++; return nil })
		info, err := s.bk.CreateLocal(context.Background(), backup.ReasonManual)
		if err != nil {
			t.Fatal(err)
		}
		breakSwap(t, s)
		rec := s.hxPost("/settings/backup/restore", s.stepUp(url.Values{"name": {info.Name}}))
		if closed != 1 {
			t.Fatalf("BeforeSwap ran %d times", closed)
		}
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status %d: %s", rec.Code, abbreviate(rec.Body.String()))
		}
		contains(t, rec.Body.String(), "Hub restarting…", "could not be completed", "restarts now", `hx-get="/settings/restart?boot=`+processBoot+`&amp;failed=1"`)
		lacks(t, rec.Body.String(), "Nothing was changed", "Restarting the hub with the restored data")
		if s.restarts != 1 {
			t.Errorf("Restart called %d times, want once", s.restarts)
		}

		// The poll keeps telling the same story, and the finished dialog does not claim restored data.
		poll := s.hxGet("/settings/restart?boot=" + processBoot + "&failed=1").Body.String()
		contains(t, poll, "Hub restarting…", "could not be completed")
		done := s.hxGet("/settings/restart?boot=" + strings.Repeat("0", len(processBoot)) + "&failed=1").Body.String()
		contains(t, done, "Hub restarted", "did not go through")
		lacks(t, done, "restored data")
	})

	t.Run("database still open: nothing changed, no restart", func(t *testing.T) {
		s := newSettingsEnv(t)
		info, err := s.bk.CreateLocal(context.Background(), backup.ReasonManual)
		if err != nil {
			t.Fatal(err)
		}
		breakSwap(t, s)
		rec := s.hxPost("/settings/backup/restore", s.stepUp(url.Values{"name": {info.Name}}))
		if rec.Code < 400 {
			t.Fatalf("status %d", rec.Code)
		}
		contains(t, rec.Body.String(), "Nothing was changed.")
		if s.restarts != 0 {
			t.Errorf("Restart called %d times", s.restarts)
		}
	})

	t.Run("a closed database without a restart service", func(t *testing.T) {
		// The route is not offered without one, so there is nothing to restart.
		s := newSettingsEnv(t)
		s.srv.svc.Restart = nil
		if rec := s.hxPost("/settings/backup/restore", s.stepUp(url.Values{"name": {"x"}})); rec.Code != 404 {
			t.Errorf("status %d", rec.Code)
		}
	})
}

func TestRestoreSuccessMentionsBeforeRestoreCopies(t *testing.T) {
	s := newSettingsEnv(t)
	info, err := s.bk.CreateLocal(context.Background(), backup.ReasonManual)
	if err != nil {
		t.Fatal(err)
	}
	rec := s.hxPost("/settings/backup/restore", s.stepUp(url.Values{"name": {info.Name}}))
	contains(t, rec.Body.String(), "*.before-restore", "previous keys")
	done := s.hxGet("/settings/restart?boot=" + strings.Repeat("0", len(processBoot))).Body.String()
	contains(t, done, "*.before-restore", "previous keys")
}
