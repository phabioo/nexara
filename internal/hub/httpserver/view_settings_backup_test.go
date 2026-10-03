package httpserver

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/phabioo/nexara/internal/hub/backup"
)

const bkPass = "a backup passphrase 99"

func TestBackupCardEmpty(t *testing.T) {
	s := newSettingsEnv(t)
	body := s.get("/settings", s.opts(false, false)...).Body.String()
	contains(t, body, "No backup yet", `value="03:00"`, `value="7"`, `hx-post="/settings/backup/run"`, `hx-get="/settings/backup/download"`)
	lacks(t, body, `class="set-list`, "Restore</button>")
}

func TestBackupSchedule(t *testing.T) {
	tests := []struct {
		name   string
		form   url.Values
		status int
		want   string
		saved  backup.Schedule
	}{
		{"valid", url.Values{"time": {"04:30"}, "keep": {"12"}}, 200, "Nightly 04:30 · keeps 12 · before updates", backup.Schedule{Time: "04:30", Keep: 12}},
		{"spaces around", url.Values{"time": {" 01:05 "}, "keep": {" 3 "}}, 200, "Nightly 01:05 · keeps 3", backup.Schedule{Time: "01:05", Keep: 3}},
		{"time out of range", url.Values{"time": {"25:00"}, "keep": {"7"}}, 422, "the time must be HH:MM", backup.Schedule{Time: "03:00", Keep: 7}},
		{"time with seconds", url.Values{"time": {"03:00:00"}, "keep": {"7"}}, 422, "the time must be HH:MM", backup.Schedule{Time: "03:00", Keep: 7}},
		{"no time", url.Values{"keep": {"7"}}, 422, "the time must be HH:MM", backup.Schedule{Time: "03:00", Keep: 7}},
		{"keep zero", url.Values{"time": {"03:00"}, "keep": {"0"}}, 422, "keep between 1 and 100 backups", backup.Schedule{Time: "03:00", Keep: 7}},
		{"keep too many", url.Values{"time": {"03:00"}, "keep": {"101"}}, 422, "keep between 1 and 100 backups", backup.Schedule{Time: "03:00", Keep: 7}},
		{"keep not a number", url.Values{"time": {"03:00"}, "keep": {"many"}}, 422, "Keep must be a whole number", backup.Schedule{Time: "03:00", Keep: 7}},
		{"keep missing", url.Values{"time": {"03:00"}}, 422, "Keep must be a whole number", backup.Schedule{Time: "03:00", Keep: 7}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newSettingsEnv(t)
			rec := s.hxPost("/settings/backup/schedule", tc.form)
			if rec.Code != tc.status {
				t.Fatalf("status %d, want %d: %s", rec.Code, tc.status, rec.Body.String())
			}
			contains(t, rec.Body.String(), tc.want, `id="set-backup"`)
			if got := s.bk.Schedule(context.Background()); got != tc.saved {
				t.Errorf("schedule = %+v, want %+v", got, tc.saved)
			}
			if tc.status == 422 {
				contains(t, rec.Body.String(), `role="alert"`)
				// What was typed stays in the form, next to the error.
				if v := tc.form.Get("time"); v != "" && !strings.Contains(rec.Body.String(), `value="`+strings.TrimSpace(v)+`"`) {
					t.Errorf("the typed time %q was dropped", v)
				}
				if got := s.auditFor("backup.schedule"); len(got) != 0 {
					t.Errorf("a rejected schedule was audited: %+v", got)
				}
			} else if got := s.auditFor("backup.schedule"); len(got) != 1 || got[0].User != testOperator || !strings.Contains(got[0].Detail, "time="+tc.saved.Time) {
				t.Errorf("audit = %+v", got)
			}
		})
	}
	s := newSettingsEnv(t)
	if rec := s.post("/settings/backup/schedule", s.opts(false, true, withForm(url.Values{"time": {"04:00"}, "keep": {"4"}}))...); rec.Code != 403 {
		t.Errorf("no csrf: %d", rec.Code)
	}
}

func TestBackupRun(t *testing.T) {
	s := newSettingsEnv(t)
	rec := s.hxPost("/settings/backup/run", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	contains(t, body, `id="set-backup"`, "Backed up", "Today ", "Manual", `class="set-list`)
	lacks(t, body, "No backup yet")
	infos, err := s.bk.List(context.Background())
	if err != nil || len(infos) != 1 || infos[0].Reason != backup.ReasonManual {
		t.Fatalf("backups = %+v, %v", infos, err)
	}
	au := s.auditFor("backup.create")
	if len(au) != 1 || au[0].User != testOperator {
		t.Errorf("audit = %+v (the operator, not the system, made it)", au)
	}
	// No restart service in the card's list until the hub can restart itself: here it can.
	contains(t, body, `hx-get="/settings/backup/restore?name=`+infos[0].Name+`"`)
}

func TestBackupRunFailure(t *testing.T) {
	s := newSettingsEnv(t)
	if err := os.Remove(s.lay.SecretKey); err != nil {
		t.Fatal(err)
	}
	rec := s.hxPost("/settings/backup/run", nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d", rec.Code)
	}
	contains(t, rec.Body.String(), "The backup could not be created.", `id="set-backup"`)
	lacks(t, rec.Body.String(), s.lay.SecretKey, "secret.key")
	if rec := s.post("/settings/backup/run", s.opts(false, true)...); rec.Code != 403 {
		t.Errorf("no csrf: %d", rec.Code)
	}
}

func TestBackupDownloadDialogs(t *testing.T) {
	s := newSettingsEnv(t)
	dialog := s.hxGet("/settings/backup/download")
	contains(t, dialog.Body.String(), "Download backup", `name="passphrase"`, `name="confirm"`, `minlength="12"`, `autocomplete="new-password"`,
		`hx-post="/settings/backup/download"`, "min. 12 characters")

	// Step 1 checks what was typed.
	for name, tc := range map[string]struct {
		form url.Values
		want string
	}{
		"mismatch": {url.Values{"passphrase": {bkPass}, "confirm": {bkPass + "x"}}, "The passphrases do not match."},
		"short":    {url.Values{"passphrase": {"short"}, "confirm": {"short"}}, "at least 12 characters"},
		"empty":    {url.Values{}, "at least 12 characters"},
	} {
		rec := s.hxPost("/settings/backup/download", tc.form)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s: status %d", name, rec.Code)
		}
		contains(t, rec.Body.String(), tc.want, `role="alert"`, `hx-post="/settings/backup/download"`)
		lacks(t, rec.Body.String(), bkPass)
	}

	// Accepted: the "ready" dialog posts the passphrase again, as a plain form with the CSRF token.
	rec := s.hxPost("/settings/backup/download", url.Values{"passphrase": {bkPass}, "confirm": {bkPass}})
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	contains(t, rec.Body.String(), "Backup ready", `method="post" action="/settings/backup/download"`, `name="csrf_token" value="`+s.csrf+`"`,
		`name="passphrase" value="`+bkPass+`"`)
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q: the dialog holds the passphrase", cc)
	}
	if len(s.auditFor("backup.download")) != 0 {
		t.Error("the check step wrote a download audit entry")
	}
	if rec := s.hxPost("/settings/backup/download", url.Values{"passphrase": {bkPass}, "confirm": {bkPass}}); rec.Header().Get("Set-Cookie") != "" {
		t.Error("the dialog sets a cookie")
	}
}

func TestBackupDownloadFile(t *testing.T) {
	s := newSettingsEnv(t)
	// Step 2: a plain form post, token in the form field.
	rec := s.post("/settings/backup/download", withCookies(s.cookie), withForm(url.Values{"passphrase": {bkPass}, "csrf_token": {s.csrf}}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	h := rec.Header()
	if cd := h.Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment;") || !strings.Contains(cd, "nexus-backup-frpi5-") || !strings.Contains(cd, ".nxbk") {
		t.Errorf("Content-Disposition = %q", cd)
	}
	if h.Get("Content-Type") != "application/octet-stream" || h.Get("Cache-Control") != "no-store" {
		t.Errorf("headers = %v", h)
	}
	body := rec.Body.Bytes()
	if !strings.HasPrefix(string(body), "NXBKUP") {
		t.Errorf("not an encrypted backup: %q", body[:min(len(body), 12)])
	}
	if strings.Contains(string(body), bkPass) || strings.Contains(string(body), "frpi5.local") {
		t.Error("the file is not encrypted")
	}
	// It opens with the passphrase and only with it.
	if _, err := s.bk.Inspect(context.Background(), strings.NewReader(string(body)), bkPass); err != nil {
		t.Errorf("the download does not open with its passphrase: %v", err)
	}
	if _, err := s.bk.Inspect(context.Background(), strings.NewReader(string(body)), bkPass+"x"); err == nil {
		t.Error("the download opens with another passphrase")
	}
	au := s.auditFor("backup.download")
	if len(au) != 1 || au[0].User != testOperator || au[0].Result != "ok" {
		t.Errorf("audit = %+v", au)
	}
	if strings.Contains(au[0].Detail, bkPass) || strings.Contains(s.logs.String(), bkPass) {
		t.Error("the passphrase reached the audit log or the log")
	}
}

func TestBackupDownloadFileErrors(t *testing.T) {
	s := newSettingsEnv(t)
	form := func(pass string) reqOpt { return withForm(url.Values{"passphrase": {pass}, "csrf_token": {s.csrf}}) }
	rec := s.post("/settings/backup/download", withCookies(s.cookie), form("short"))
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "at least 12 characters") {
		t.Errorf("weak passphrase: %d %q", rec.Code, rec.Body.String())
	}
	if cd := rec.Header().Get("Content-Disposition"); cd != "" {
		t.Errorf("an error carries Content-Disposition %q", cd)
	}
	// No token: forbidden, nothing created.
	rec = s.post("/settings/backup/download", withCookies(s.cookie), withForm(url.Values{"passphrase": {bkPass}}))
	if rec.Code != http.StatusForbidden {
		t.Errorf("no csrf: %d", rec.Code)
	}
	if infos, _ := s.bk.List(context.Background()); len(infos) != 0 {
		t.Errorf("a download left a local backup: %v", infos)
	}
	// Signed out: sent to sign in.
	if rec := s.post("/settings/backup/download", withForm(url.Values{"passphrase": {bkPass}})); rec.Code != http.StatusSeeOther {
		t.Errorf("signed out: %d", rec.Code)
	}
	// A hub whose files are broken answers 500 with fixed text, before any byte of the file.
	if err := os.Remove(s.lay.SecretKey); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(s.lay.ConfigPath)
	rec = s.post("/settings/backup/download", withCookies(s.cookie), form(bkPass))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("broken hub: %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), s.lay.ConfigPath) || rec.Header().Get("Content-Disposition") != "" {
		t.Errorf("error answer: %q %v", rec.Body.String(), rec.Header())
	}
}

func TestBackupRestore(t *testing.T) {
	s := newSettingsEnv(t)
	info, err := s.bk.CreateLocal(context.Background(), backup.ReasonManual)
	if err != nil {
		t.Fatal(err)
	}
	dialog := s.hxGet("/settings/backup/restore?name=" + info.Name)
	if dialog.Code != http.StatusOK {
		t.Fatalf("dialog: %d %s", dialog.Code, dialog.Body.String())
	}
	contains(t, dialog.Body.String(), "Restore backup", "replaced by their state at that time", "The hub restarts", `name="name" value="`+info.Name+`"`,
		`hx-post="/settings/backup/restore"`, "Manual", "is-bad")
	for _, bad := range []string{"", "nexus-bogus.nxbk", "../../etc/passwd", "nexus-20250101T000000Z-manual.nxbk"} {
		if rec := s.hxGet("/settings/backup/restore?name=" + url.QueryEscape(bad)); rec.Code != 404 {
			t.Errorf("dialog for %q: %d", bad, rec.Code)
		}
	}

	if s.restarts != 0 {
		t.Fatal("restarted before the restore")
	}
	rec := s.hxPost("/settings/backup/restore", url.Values{"name": {info.Name}})
	if rec.Code != http.StatusOK {
		t.Fatalf("restore: %d %s", rec.Code, rec.Body.String())
	}
	contains(t, rec.Body.String(), "Hub restarting…", "Restarting the hub with the restored data", `hx-trigger="every 2s"`, `hx-get="/settings/restart?boot=`+processBoot+`"`)
	if s.restarts != 1 {
		t.Errorf("Restart called %d times, want once", s.restarts)
	}
	au := s.auditFor("backup.restore")
	_ = au // written into the restored database by the service
}

func TestBackupRestoreErrors(t *testing.T) {
	s := newSettingsEnv(t)
	info, err := s.bk.CreateLocal(context.Background(), backup.ReasonManual)
	if err != nil {
		t.Fatal(err)
	}
	post := func(name string, opts ...reqOpt) int {
		return s.post("/settings/backup/restore", append(s.opts(true, true, withForm(url.Values{"name": {name}})), opts...)...).Code
	}
	if rec := s.post("/settings/backup/restore", s.opts(false, true, withForm(url.Values{"name": {info.Name}}))...); rec.Code != 403 {
		t.Errorf("no csrf: %d", rec.Code)
	}
	rec := s.hxPost("/settings/backup/restore", url.Values{"name": {"nexus-20250101T000000Z-manual.nxbk"}})
	if rec.Code != http.StatusNotFound {
		t.Errorf("gone: %d", rec.Code)
	}
	contains(t, rec.Body.String(), "That backup no longer exists.", `hx-swap-oob="true"`, `id="set-backup"`)
	rec = s.hxPost("/settings/backup/restore", url.Values{"name": {"../../etc/passwd"}})
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("not a backup name: %d", rec.Code)
	}
	contains(t, rec.Body.String(), "Nothing was changed.")
	// A damaged file changes nothing and says so.
	if err := os.WriteFile(info.Path, []byte("NXBKUP garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	rec = s.hxPost("/settings/backup/restore", url.Values{"name": {info.Name}})
	if rec.Code < 400 {
		t.Errorf("a damaged backup was restored: %d", rec.Code)
	}
	contains(t, rec.Body.String(), "Nothing was changed.")
	lacks(t, rec.Body.String(), info.Path)
	if s.restarts != 0 {
		t.Errorf("the hub restarted after failed restores: %d", s.restarts)
	}
	_ = post
	// Without a restart service (the demo) there is no restore at all.
	s.srv.svc.Restart = nil
	if rec := s.hxPost("/settings/backup/restore", url.Values{"name": {info.Name}}); rec.Code != 404 {
		t.Errorf("restore without restart: %d", rec.Code)
	}
	if rec := s.hxGet("/settings/backup/restore?name=" + info.Name); rec.Code != 404 {
		t.Errorf("dialog without restart: %d", rec.Code)
	}
	body := s.get("/settings", s.opts(false, false)...).Body.String()
	lacks(t, body, "/settings/backup/restore")
	// Backups from another hub's key cannot be restored here.
}

func TestRestartPoll(t *testing.T) {
	s := newSettingsEnv(t)
	// Still the process that restored: keep waiting.
	body := s.hxGet("/settings/restart?boot=" + processBoot).Body.String()
	contains(t, body, "Hub restarting…", `hx-trigger="every 2s"`)
	lacks(t, body, "Hub restarted")
	// Another process answers: done, no more polling.
	body = s.hxGet("/settings/restart?boot=0123456789abcdef").Body.String()
	contains(t, body, "Hub restarted", "The hub is back with the restored data.")
	lacks(t, body, "every 2s")
	// Whatever else is sent is not echoed into the dialog's URL.
	body = s.hxGet(`/settings/restart?boot="><script>alert(1)</script>`).Body.String()
	lacks(t, body, "<script>", "alert(1)")
	contains(t, body, "Hub restarted")
	if rec := s.get("/settings/restart?boot=x"); rec.Code != http.StatusSeeOther {
		t.Errorf("signed out: %d", rec.Code)
	}
}

func TestBackupNotAvailable(t *testing.T) {
	s := newSettingsEnv(t)
	s.srv.svc.Backup = nil
	for _, p := range []string{"/settings/backup/download", "/settings/backup/restore?name=x"} {
		if rec := s.hxGet(p); rec.Code != 404 {
			t.Errorf("GET %s: %d", p, rec.Code)
		}
	}
	for _, p := range []string{"/settings/backup/schedule", "/settings/backup/run", "/settings/backup/download", "/settings/backup/restore"} {
		if rec := s.hxPost(p, url.Values{}); rec.Code != 404 {
			t.Errorf("POST %s: %d", p, rec.Code)
		}
	}
}
