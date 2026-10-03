package httpserver

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/update"
)

func (s *settingsEnv) setCheck(on bool) {
	s.postForm("/settings/updates/config", url.Values{"check_github": {map[bool]string{true: "true", false: "false"}[on]}})
}

func (s *settingsEnv) postForm(path string, form url.Values) int {
	return s.hxPost(path, form).Code
}

func TestUpdatesConfig(t *testing.T) {
	s := newSettingsEnv(t)
	rec := s.hxPost("/settings/updates/config", url.Values{"check_github": {"true"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	// The card comes back with the switch on, the channel chips and the next toggle posting "false".
	contains(t, rec.Body.String(), `id="set-updates"`, `aria-checked="true"`, ">On<", `name="check_github" value="false"`,
		`name="channel" value="rc"`, ">Stable<", ">RC<")
	cfg, _ := s.upd.Config(context.Background())
	if !cfg.CheckGitHub || cfg.Channel != update.ChannelStable {
		t.Fatalf("config = %+v", cfg)
	}
	rec = s.hxPost("/settings/updates/config", url.Values{"channel": {"rc"}})
	if cfg, _ = s.upd.Config(context.Background()); cfg.Channel != update.ChannelRC || !cfg.CheckGitHub {
		t.Fatalf("config after channel = %+v", cfg)
	}
	if i := strings.Index(rec.Body.String(), `name="channel" value="rc"`); i < 0 || !strings.Contains(rec.Body.String()[i:i+300], `aria-pressed="true"`) {
		t.Error("the rc chip is not pressed")
	}
	s.setCheck(false)
	body := s.hxGet("/settings/updates/status").Body.String()
	lacks(t, body, `name="channel"`)
	acts := s.auditActions()
	if n := strings.Count(strings.Join(acts, ","), "update.settings:ok"); n != 3 {
		t.Errorf("%d settings audit entries, want 3: %v", n, acts)
	}
	for _, tc := range []struct {
		name string
		form url.Values
	}{
		{"bad switch", url.Values{"check_github": {"yes"}}},
		{"bad channel", url.Values{"channel": {"nightly"}}},
	} {
		if rec := s.hxPost("/settings/updates/config", tc.form); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d", tc.name, rec.Code)
		}
	}
	if rec := s.post("/settings/updates/config", s.opts(false, true, withForm(url.Values{"check_github": {"true"}}))...); rec.Code != 403 {
		t.Errorf("no csrf: %d", rec.Code)
	}
}

func TestUpdatesCheck(t *testing.T) {
	s := newSettingsEnv(t)
	// Off by default (decision #53): no outbound call, a clear message.
	rec := s.hxPost("/settings/updates/check", nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("check while off: %d", rec.Code)
	}
	contains(t, rec.Body.String(), "Turn on the GitHub check first.", `id="set-updates"`)

	s.setCheck(true)
	rec = s.hxPost("/settings/updates/check", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("check: %d %s", rec.Code, rec.Body.String())
	}
	contains(t, rec.Body.String(), "Up to date", "Checked just now", "Up to date")

	// A newer release shows up with a download button.
	s.gh.publish("0.2.0", s.bundle("0.2.0", 10))
	s.clockForward()
	rec = s.hxPost("/settings/updates/check", nil)
	contains(t, rec.Body.String(), "Update found", "Update available · v0.2.0", "v0.2.0 is available", `hx-post="/settings/updates/stage"`)
	lacks(t, rec.Body.String(), "Install now")
}

// clockForward lets the next manual check go to GitHub: the service answers from its cache within 30 seconds.
func (s *settingsEnv) clockForward() { s.updClock.Advance(time.Minute) }

func TestUpdatesCheckFailure(t *testing.T) {
	s := newSettingsEnv(t)
	s.setCheck(true)
	s.gh.status = http.StatusInternalServerError
	rec := s.hxPost("/settings/updates/check", nil)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	contains(t, rec.Body.String(), "GitHub could not be reached or answered with an error.", "Last check failed")
	lacks(t, rec.Body.String(), "127.0.0.1")
}

func TestUpdatesStageFromGitHub(t *testing.T) {
	s := newSettingsEnv(t)
	if rec := s.hxPost("/settings/updates/stage", nil); rec.Code != http.StatusConflict {
		t.Errorf("stage while the check is off: %d", rec.Code)
	}
	s.setCheck(true)
	if rec := s.hxPost("/settings/updates/stage", nil); rec.Code != http.StatusConflict {
		t.Errorf("stage without a newer release: %d %s", rec.Code, rec.Body.String())
	} else {
		contains(t, rec.Body.String(), "There is no newer release.")
	}
	s.gh.publish("0.2.0", s.bundle("0.2.0", 2048))
	s.updClock.Advance(7 * time.Hour) // the hub asks GitHub again every 6 hours
	rec := s.hxPost("/settings/updates/stage", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	contains(t, rec.Body.String(), "Downloaded", "v0.2.0 ready to install", "downloaded", `hx-get="/settings/updates/install?version=0.2.0"`, "Install now")
	// A tampered download is refused.
	s.gh.releases = nil
	s.updClock.Advance(7 * time.Hour)
	bad := s.bundle("0.3.0", 100)
	bad.deb = append(bad.deb, 'x')
	s.gh.publish("0.3.0", bad)
	rec = s.hxPost("/settings/updates/stage", nil)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("tampered download: %d %s", rec.Code, rec.Body.String())
	}
	contains(t, rec.Body.String(), "does not match its checksum")
}

func TestUpdatesUpload(t *testing.T) {
	good := func(s *settingsEnv) stgBundle { return s.bundle("0.2.0", 4096) }
	tests := []struct {
		name   string
		files  func(s *settingsEnv) []stgFile
		csrf   bool
		status int
		want   string
	}{
		{"deb, sums, signature", func(s *settingsEnv) []stgFile { return good(s).files() }, true, 200, "v0.2.0 ready to install"},
		{"signature first", func(s *settingsEnv) []stgFile {
			b := good(s)
			return []stgFile{{update.SigFile, b.sigb}, {update.SumsFile, b.sums}, {b.debName, b.deb}}
		}, true, 200, "v0.2.0 ready to install"},
		{"deb last, uppercase names first as a file dialog sorts them", func(s *settingsEnv) []stgFile {
			b := good(s)
			return []stgFile{{update.SumsFile, b.sums}, {update.SigFile, b.sigb}, {b.debName, b.deb}}
		}, true, 200, "uploaded"},
		{"path in the file name is ignored", func(s *settingsEnv) []stgFile {
			b := good(s)
			return []stgFile{{`C:\Downloads\` + b.debName, b.deb}, {"../" + update.SumsFile, b.sums}, {update.SigFile, b.sigb}}
		}, true, 200, "v0.2.0 ready to install"},
		{"a tar of the three", func(s *settingsEnv) []stgFile {
			b := good(s)
			return []stgFile{{"nexus-update.tar", tarOf(t, b)}}
		}, true, 200, "v0.2.0 ready to install"},
		{"nothing chosen", func(s *settingsEnv) []stgFile { return nil }, true, 422, "This is not an update bundle."},
		{"signature missing", func(s *settingsEnv) []stgFile { b := good(s); return b.files()[:2] }, true, 422, "This is not an update bundle."},
		{"package missing", func(s *settingsEnv) []stgFile { b := good(s); return b.files()[1:] }, true, 422, "This is not an update bundle."},
		{"two packages", func(s *settingsEnv) []stgFile {
			b := good(s)
			return append(b.files(), stgFile{"nexus_0.2.1_arm64.deb", b.deb})
		}, true, 422, "This is not an update bundle."},
		{"unexpected file", func(s *settingsEnv) []stgFile {
			return append(good(s).files(), stgFile{"install.sh", []byte("#!/bin/sh")})
		}, true, 422, "This is not an update bundle."},
		{"signature of another key", func(s *settingsEnv) []stgFile {
			b := good(s)
			b.sigb = bytes.Repeat([]byte{1}, 64)
			return b.files()
		}, true, 422, "The signature does not match."},
		{"package changed after signing", func(s *settingsEnv) []stgFile {
			b := good(s)
			b.deb = append(b.deb, 0)
			return b.files()
		}, true, 422, "does not match its checksum"},
		{"other architecture", func(s *settingsEnv) []stgFile {
			b := s.bundle("0.2.0", 100)
			b.debName = update.DebName("0.2.0", "amd64")
			return b.files()
		}, true, 422, "another processor architecture"},
		{"older version", func(s *settingsEnv) []stgFile {
			b := s.bundle("0.0.5", 100)
			return b.files()
		}, true, 422, "older than the running version"},
		{"same version", func(s *settingsEnv) []stgFile { return s.bundle("0.1.0", 100).files() }, true, 409, "already installed"},
		{"file named like nothing", func(s *settingsEnv) []stgFile { return []stgFile{{"readme.txt", []byte("hi")}} }, true, 422, "This is not an update bundle."},
		{"no csrf token", func(s *settingsEnv) []stgFile { return good(s).files() }, false, 403, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newSettingsEnv(t)
			rec := s.upload(t, tc.csrf, tc.files(s)...)
			if rec.Code != tc.status {
				t.Fatalf("status %d, want %d: %s", rec.Code, tc.status, abbreviate(rec.Body.String()))
			}
			if tc.want != "" {
				contains(t, rec.Body.String(), tc.want, `id="set-updates"`)
			}
			st, _ := s.upd.Status(context.Background())
			if tc.status == 200 && len(st.Staged) != 1 {
				t.Errorf("staged = %+v", st.Staged)
			}
			if tc.status != 200 && len(st.Staged) != 0 {
				t.Errorf("a refused upload was staged: %+v", st.Staged)
			}
			if tc.status == 200 {
				if got := s.auditFor("update.stage"); len(got) != 1 || got[0].User != testOperator {
					t.Errorf("audit = %+v", got)
				}
			}
		})
	}
}

func tarOf(t *testing.T, b stgBundle) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range b.files() {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write(f.data)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestUpdatesUploadIsNotCappedLikeAForm(t *testing.T) {
	// A package is far larger than the 1 MiB of a form body; the upload path (and only it) takes it.
	s := newSettingsEnv(t)
	b := s.bundle("0.2.0", maxFormBody*3)
	rec := s.upload(t, true, b.files()...)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, abbreviate(rec.Body.String()))
	}
	contains(t, rec.Body.String(), "v0.2.0 ready to install")
	st, _ := s.upd.Status(context.Background())
	if len(st.Staged) != 1 || st.Staged[0].Size != int64(maxFormBody*3) {
		t.Errorf("staged = %+v", st.Staged)
	}
	// Every other path keeps the form cap.
	big := bytes.Repeat([]byte("a"), maxFormBody+10)
	rec = s.post("/settings/backup/schedule", s.opts(true, true, func(r *http.Request) {
		r.Body = nopCloser{bytes.NewBuffer(big)}
		r.ContentLength = int64(len(big))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	})...)
	if rec.Code < 400 {
		t.Errorf("an oversized form was accepted: %d", rec.Code)
	}
}

func TestUpdatesUploadLimits(t *testing.T) {
	s := newSettingsEnv(t)
	if bodyCap(uploadPathUpdate) != update.MaxBundleBytes || bodyCap("/settings/backup/schedule") != maxFormBody || bodyCap("/login") != maxFormBody {
		t.Fatal("bodyCap does not single out the upload path")
	}
	s.srv.bodyTimeout = 30 * time.Second
	if got := s.srv.bodyDeadline(uploadPathUpdate); got != 10*time.Minute {
		t.Errorf("upload deadline %v, want 10 min", got)
	}
	if got := s.srv.bodyDeadline("/login"); got != 30*time.Second {
		t.Errorf("form deadline %v", got)
	}
	// A body that is not multipart at all.
	rec := s.post(uploadPathUpdate, s.opts(true, true, withForm(url.Values{"a": {"b"}}))...)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("not multipart: %d", rec.Code)
	}
	contains(t, rec.Body.String(), "Choose the update files first.")
}

func TestUpdatesInstall(t *testing.T) {
	s := newSettingsEnv(t)
	if rec := s.upload(t, true, s.bundle("0.2.0", 100).files()...); rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	dialog := s.hxGet("/settings/updates/install?version=0.2.0")
	if dialog.Code != http.StatusOK {
		t.Fatalf("dialog: %d %s", dialog.Code, dialog.Body.String())
	}
	contains(t, dialog.Body.String(), "Install update", "v0.2.0", "over v0.1.0", "restarts", "A backup is taken first", `name="version" value="0.2.0"`,
		`hx-post="/settings/updates/install"`, "data-modal-close")
	lacks(t, dialog.Body.String(), "older version than the one running")
	if rec := s.hxGet("/settings/updates/install?version=9.9.9"); rec.Code != 404 {
		t.Errorf("dialog for an unstaged version: %d", rec.Code)
	}

	rec := s.hxPost("/settings/updates/install", s.stepUp(url.Values{"version": {"0.2.0"}}))
	if rec.Code != http.StatusOK {
		t.Fatalf("install: %d %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	// The dialog closes (empty main part), the card arrives out of band with the progress, polling itself.
	contains(t, body, `hx-swap-oob="true"`, `id="set-updates"`, "Installing v0.2.0", "Waiting for the update helper", "Cancel request",
		`hx-get="/settings/updates/status"`, `hx-trigger="every 3s"`, "Update queued")
	if strings.Index(body, `id="set-updates"`) == 0 {
		t.Error("the answer starts with the card: the dialog would not close")
	}
	b, err := os.ReadFile(filepath.Join(s.updDir, update.RequestFile))
	if err != nil {
		t.Fatalf("no request for the helper: %v", err)
	}
	var req update.Request
	if err := json.Unmarshal(b, &req); err != nil || req.Version != "0.2.0" || req.RequestedBy != testOperator {
		t.Errorf("request = %+v, %v", req, err)
	}
	if got := s.auditFor("update.request"); len(got) != 1 || got[0].User != testOperator {
		t.Errorf("audit = %+v", got)
	}
	// While it runs: no second install, no upload; the status poll shows the phase.
	rec = s.hxPost("/settings/updates/install", s.stepUp(url.Values{"version": {"0.2.0"}}))
	if rec.Code != http.StatusConflict {
		t.Errorf("second install: %d", rec.Code)
	}
	contains(t, rec.Body.String(), "Another update step is in progress")
	status := s.hxGet("/settings/updates/status").Body.String()
	contains(t, status, `hx-trigger="every 3s"`, "Installing v0.2.0")
	if !strings.Contains(status, `<button type="button" class="btn-tool is-hot" hx-get="/settings/updates/install?version=0.2.0" hx-target="#modal-root" hx-swap="innerHTML" disabled>`) {
		t.Errorf("Install now is not disabled while an update runs:\n%s", status)
	}
}

func TestUpdatesInstallErrors(t *testing.T) {
	s := newSettingsEnv(t)
	if rec := s.hxPost("/settings/updates/install", s.stepUp(url.Values{"version": {"0.2.0"}})); rec.Code != 404 {
		t.Errorf("not staged: %d", rec.Code)
	} else {
		contains(t, rec.Body.String(), "That version is no longer staged.")
	}
	if rec := s.hxPost("/settings/updates/install", s.stepUp(url.Values{"version": {"../../etc"}})); rec.Code != 404 {
		t.Errorf("path-like version: %d", rec.Code)
	}
	if rec := s.post("/settings/updates/install", s.opts(false, true, withForm(url.Values{"version": {"0.2.0"}}))...); rec.Code != 403 {
		t.Errorf("no csrf: %d", rec.Code)
	}
}

func TestUpdatesInstallWithoutHelper(t *testing.T) {
	// A hub without the update helper (a manual install) can stage a bundle but not install it.
	s := newSettingsEnv(t, func(o *update.Options) { o.HelperWatches = false })
	if rec := s.upload(t, true, s.bundle("0.2.0", 100).files()...); rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	body := s.get("/settings", s.opts(false, false)...).Body.String()
	contains(t, body, "no update helper")
	if !strings.Contains(body, `hx-swap="innerHTML" disabled>Install now`) {
		t.Error("Install now is not disabled without a helper")
	}
	rec := s.hxPost("/settings/updates/install", s.stepUp(url.Values{"version": {"0.2.0"}}))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status %d", rec.Code)
	}
	contains(t, rec.Body.String(), "no update helper")
	if _, err := os.Stat(filepath.Join(s.updDir, update.RequestFile)); err == nil {
		t.Error("a request was written without a helper")
	}
}

func TestUpdatesCancel(t *testing.T) {
	s := newSettingsEnv(t)
	if rec := s.hxPost("/settings/updates/cancel", nil); rec.Code != http.StatusConflict {
		t.Errorf("nothing to cancel: %d", rec.Code)
	}
	s.upload(t, true, s.bundle("0.2.0", 100).files()...)
	s.hxPost("/settings/updates/install", s.stepUp(url.Values{"version": {"0.2.0"}}))
	rec := s.hxPost("/settings/updates/cancel", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	contains(t, rec.Body.String(), "Cancelled", "v0.2.0 ready to install")
	lacks(t, rec.Body.String(), "Cancel request", "every 3s")
	if _, err := os.Stat(filepath.Join(s.updDir, update.RequestFile)); err == nil {
		t.Error("the request is still there")
	}
}

func TestUpdatesProgressAndResult(t *testing.T) {
	now := time.Now().UTC()
	// The helper claims the request (applying.json) and moves through its phases.
	phases := map[string]struct{ run, done int }{
		update.PhaseVerify: {1, 1}, update.PhaseBackup: {2, 2}, update.PhaseInstall: {3, 3}, update.PhaseHealth: {4, 4},
	}
	for phase, want := range phases {
		t.Run(phase, func(t *testing.T) {
			s := newSettingsEnv(t)
			s.upload(t, true, s.bundle("0.2.0", 100).files()...)
			ap := update.Applying{Request: update.Request{Version: "0.2.0", Arch: "arm64", Deb: update.DebName("0.2.0", "arm64"), SHA256: strings.Repeat("a", 64),
				RequestedBy: testOperator, RequestedAt: now}, Phase: phase, StartedAt: now}
			writeJSON(t, filepath.Join(s.updDir, update.ApplyingFile), ap)
			body := s.hxGet("/settings/updates/status").Body.String()
			contains(t, body, "Installing v0.2.0", `hx-trigger="every 3s"`, "The hub restarts during this")
			if got := strings.Count(body, `class="step-row run"`); got != 1 {
				t.Errorf("%d running steps", got)
			}
			if got := strings.Count(body, `class="step-row done"`); got != want.done {
				t.Errorf("%d done steps, want %d", got, want.done)
			}
			lacks(t, body, "Cancel request")
		})
	}
	t.Run("rollback", func(t *testing.T) {
		s := newSettingsEnv(t)
		s.upload(t, true, s.bundle("0.2.0", 100).files()...)
		writeJSON(t, filepath.Join(s.updDir, update.ApplyingFile), update.Applying{Request: update.Request{Version: "0.2.0"}, Phase: update.PhaseRollback, StartedAt: now})
		body := s.hxGet("/settings/updates/status").Body.String()
		contains(t, body, "Restoring the previous version", `class="step-row bad"`)
	})
	t.Run("a stalled update stops polling", func(t *testing.T) {
		s := newSettingsEnv(t)
		s.upload(t, true, s.bundle("0.2.0", 100).files()...)
		writeJSON(t, filepath.Join(s.updDir, update.RequestFile), update.Request{Version: "0.2.0", RequestedAt: now.Add(-2 * time.Hour)})
		body := s.hxGet("/settings/updates/status").Body.String()
		contains(t, body, "Nothing has happened for 30 minutes")
		lacks(t, body, "every 3s")
	})
}

func TestUpdatesLastResult(t *testing.T) {
	now := time.Now().UTC()
	tests := []struct {
		name string
		res  update.Result
		want []string
		bad  bool
		tag  string
	}{
		{"ok", update.Result{Status: update.StatusOK, Version: "0.2.0", PreviousVersion: "0.1.0", Message: "installed"},
			[]string{"Updated to v0.2.0", "Previous version v0.1.0", "set-result is-ok"}, false, ""},
		{"rolled back", update.Result{Status: update.StatusRolledBack, Version: "0.2.0", PreviousVersion: "0.1.0", Message: "the new hub did not become healthy", LogTail: "apt: boom\nline two"},
			[]string{"Rolled back to v0.1.0", "did not become healthy", "The previous version was restored.", "set-result is-bad", "Helper log", "apt: boom"}, true, "Last update failed"},
		{"error", update.Result{Status: update.StatusError, Version: "0.2.0", Phase: update.PhaseVerify, Message: "signature check failed"},
			[]string{"Update failed", "signature check failed (step: verify)", "set-result is-bad"}, true, "Last update failed"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newSettingsEnv(t)
			tc.res.RequestedBy, tc.res.StartedAt, tc.res.FinishedAt = testOperator, now.Add(-time.Minute), now
			writeJSON(t, filepath.Join(s.updDir, update.ResultFile), tc.res)
			// The hub reports the helper's result once (this is what Run does every few seconds).
			if _, err := s.upd.Reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			body := s.get("/settings", s.opts(false, false)...).Body.String()
			contains(t, body, tc.want...)
			if tc.tag != "" {
				contains(t, body, tc.tag)
			}
			if got := s.auditFor("update.apply"); len(got) != 1 {
				t.Errorf("audit = %+v", got)
			}
		})
	}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestUpdatesNotAvailable(t *testing.T) {
	s := newSettingsEnv(t)
	s.srv.svc.Updates = nil
	for _, p := range []string{"/settings/updates/status", "/settings/updates/install?version=0.2.0"} {
		if rec := s.hxGet(p); rec.Code != 404 {
			t.Errorf("GET %s: %d", p, rec.Code)
		}
	}
	for _, p := range []string{"/settings/updates/config", "/settings/updates/check", "/settings/updates/stage", "/settings/updates/install", "/settings/updates/cancel"} {
		if rec := s.hxPost(p, url.Values{}); rec.Code != 404 {
			t.Errorf("POST %s: %d", p, rec.Code)
		}
	}
	if rec := s.upload(t, true, s.bundle("0.2.0", 10).files()...); rec.Code != 404 {
		t.Errorf("upload: %d", rec.Code)
	}
}

func TestUpdateProblemMapping(t *testing.T) {
	tests := []struct {
		err    error
		status int
		want   string
		known  bool
	}{
		{&http.MaxBytesError{Limit: 1}, 413, "larger than the hub accepts", true},
		{fmtErr("%w: x", update.ErrTooLarge), 413, "larger than the hub accepts", true},
		{update.ErrBadSignature, 422, "signature does not match", true},
		{update.ErrChecksum, 422, "checksum", true},
		{update.ErrBadBundle, 422, "not an update bundle", true},
		{update.ErrWrongArch, 422, "architecture", true},
		{update.ErrDowngrade, 422, "older than the running version", true},
		{update.ErrAlreadyInstalled, 409, "already installed", true},
		{update.ErrDevBuild, 422, "development build", true},
		{update.ErrCheckDisabled, 409, "Turn on the GitHub check", true},
		{update.ErrBusy, 409, "in progress", true},
		{update.ErrNotStaged, 404, "no longer staged", true},
		{update.ErrUnsupported, 422, "no update helper", true},
		{update.ErrNoUpdate, 409, "no newer release", true},
		{update.ErrNoRequest, 409, "no pending request", true},
		{context.DeadlineExceeded, 504, "too long", true},
		{fmtErr("disk /var/lib/nexus is full"), 500, "fallback text", false},
	}
	for _, tc := range tests {
		status, msg, known := updateProblem(tc.err, 500, "fallback text")
		if status != tc.status || !strings.Contains(msg, tc.want) || known != tc.known {
			t.Errorf("%v: %d %q %v, want %d %q %v", tc.err, status, msg, known, tc.status, tc.want, tc.known)
		}
		if strings.Contains(msg, "/var/lib") {
			t.Errorf("%v: the message leaks the cause: %q", tc.err, msg)
		}
	}
}

func fmtErr(format string, a ...any) error { return fmt.Errorf(format, a...) }
