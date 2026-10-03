package httpserver

import (
	"bytes"
	"context"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/config"
	"github.com/phabioo/nexara/internal/hub/auth"
	"github.com/phabioo/nexara/internal/hub/backup"
	"github.com/phabioo/nexara/internal/hub/setup"
	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/pki"
)

const restorePass = "a long backup passphrase"

var restoreKDF = backup.KDFParams{Time: 1, MemoryKiB: 64, Threads: 1}

// hubFiles lays out the files of one hub below root, like the backup tests do.
func hubFiles(root string) backup.Layout {
	return backup.Layout{
		ConfigPath: filepath.Join(root, "etc", "nexus.yaml"),
		Database:   filepath.Join(root, "var", "nexus.db"),
		TLSDir:     filepath.Join(root, "var", "pki"),
		SecretKey:  filepath.Join(root, "var", "secret.key"),
		SSHKey:     filepath.Join(root, "var", "ssh", "id_ed25519"),
		BackupDir:  filepath.Join(root, "var", "backups"),
	}
}

// makeBackup builds a real hub (database with one operator, config, CA, secret
// key) and returns a passphrase backup of it, the way Settings downloads one.
func makeBackup(t *testing.T) []byte {
	t.Helper()
	lay := hubFiles(t.TempDir())
	for _, d := range []string{filepath.Dir(lay.ConfigPath), filepath.Dir(lay.Database)} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.DefaultHub()
	cfg.Hub.Name = "old-hub"
	cfg.Hub.AgentAddress = "frpi5.local"
	cfg.Storage.Database = lay.Database
	cfg.TLS.Dir = lay.TLSDir
	if err := config.SaveHub(lay.ConfigPath, cfg); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(lay.Database)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if _, err := st.CreateUser(context.Background(), store.User{OperatorID: "alice", PassHash: "hash"}); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.LoadOrCreateSecretKey(lay.SecretKey); err != nil {
		t.Fatal(err)
	}
	if _, err := pki.LoadOrCreateCA(lay.TLSDir, "frpi5.local"); err != nil {
		t.Fatal(err)
	}
	svc := backup.New(backup.Options{
		Layout: lay, Snapshot: st.Snapshot, HubName: "old-hub", HubVersion: "0.2.0-test", KDF: restoreKDF,
		Now: func() time.Time { return time.Date(2026, 9, 30, 3, 0, 0, 0, time.UTC) },
	})
	var buf bytes.Buffer
	if err := svc.WriteDownload(context.Background(), &buf, restorePass); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// restoreEnv is a setup-mode server whose hub can restore backups into a
// fresh file tree.
type restoreEnv struct {
	*setupEnv
	lay      backup.Layout
	svc      *backup.Service
	file     []byte
	restarts chan struct{}

	mu       sync.Mutex
	audits   []store.AuditEntry
	restores int
}

func newRestoreEnv(t *testing.T, mutate ...func(*backup.Options)) *restoreEnv {
	t.Helper()
	e := &restoreEnv{setupEnv: newSetupEnv(t), restarts: make(chan struct{}, 4), file: makeBackup(t)}
	e.lay = hubFiles(t.TempDir())
	opts := backup.Options{
		Layout: e.lay, KDF: restoreKDF,
		// As in the hub: failures are audited into the (setup mode) database.
		Audit: func(ctx context.Context, en store.AuditEntry) { _, _ = e.st.AppendAudit(ctx, en) },
		AuditRestore: func(_ context.Context, _ string, en store.AuditEntry) error {
			e.mu.Lock()
			defer e.mu.Unlock()
			e.audits = append(e.audits, en)
			return nil
		},
	}
	for _, m := range mutate {
		m(&opts)
	}
	e.svc = backup.New(opts)
	e.srv.svc = Services{Backup: e.svc, Store: e.st, Restart: func() { e.restarts <- struct{}{} }}
	// Uploads go to the hub's backup directory; the clock is the shared fake one.
	e.srv.setup.Sessions = setup.NewSessions(setup.SessionOptions{Now: e.clock.Now, UploadDir: e.lay.BackupDir})
	return e
}

// renewCode issues a fresh setup code (the fake clock may have run past the old one).
func (e *restoreEnv) renewCode(t *testing.T) {
	t.Helper()
	code, _, err := e.srv.setup.Codes.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	e.code = code
}

func (e *restoreEnv) uploadFiles() []string {
	ents, _ := os.ReadDir(e.lay.BackupDir)
	var names []string
	for _, f := range ents {
		if strings.HasPrefix(f.Name(), ".upload-") {
			names = append(names, f.Name())
		}
	}
	return names
}

func (e *restoreEnv) restoreAudits() []store.AuditEntry {
	list, _ := e.st.ListAudit(context.Background(), 100)
	var out []store.AuditEntry
	for _, a := range list {
		if a.Action == backup.ActionRestore {
			out = append(out, a)
		}
	}
	return out
}

type mpPart struct {
	name, filename string
	data           []byte
}

func restoreMultipart(t *testing.T, parts ...mpPart) (body []byte, contentType string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for _, p := range parts {
		h := textproto.MIMEHeader{}
		disp := fmt.Sprintf(`form-data; name=%q`, p.name)
		if p.filename != "" {
			disp += fmt.Sprintf(`; filename=%q`, p.filename)
			h.Set("Content-Type", "application/octet-stream")
		}
		h.Set("Content-Disposition", disp)
		pw, err := w.CreatePart(h)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = pw.Write(p.data)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), w.FormDataContentType()
}

// uploadAs posts the upload form: token first, then passphrase and file.
func (b *setupBrowser) uploadAs(file []byte, pass string, extra ...reqOpt) *httptest.ResponseRecorder {
	b.t.Helper()
	if b.j[csrfCookieName] == nil {
		b.get("/setup")
	}
	return b.uploadParts(
		mpPart{name: auth.CSRFFormField, data: []byte(b.j[csrfCookieName].Value)},
		mpPart{name: fieldBackupPassphrase, data: []byte(pass)},
		mpPart{name: fieldBackupFile, filename: "nexus-backup.nxbk", data: file},
	)
}

func (b *setupBrowser) uploadParts(parts ...mpPart) *httptest.ResponseRecorder {
	b.t.Helper()
	body, ct := restoreMultipart(b.t, parts...)
	return b.do(http.MethodPost, setupRestoreUpload, nil, func(r *http.Request) {
		r.Body = readerCloser{bytes.NewReader(body)}
		r.ContentLength = int64(len(body))
		r.Header.Set("Content-Type", ct)
	})
}

type readerCloser struct{ *bytes.Reader }

func (readerCloser) Close() error { return nil }

// unlockForRestore walks the Unlock form with the restore button.
func (b *setupBrowser) unlockForRestore() {
	b.t.Helper()
	rec := b.post("/setup/unlock", map[string][]string{"code": {setup.FormatCode(b.e.code)}, "restore": {"1"}})
	wantRedirect(b.t, rec, setupRestorePath)
}

func TestSetupRestoreHiddenWithoutBackupService(t *testing.T) {
	e := newSetupEnv(t) // Services.Backup is nil, like the demo
	b := e.browser(t)
	rec := b.get("/setup")
	wantBody(t, rec, "Claim this hub")
	wantNoBody(t, rec, "Restore from a backup instead", `name="restore"`)
	b.unlock()
	for _, tc := range []struct{ method, path string }{
		{"GET", setupRestorePath}, {"POST", setupRestoreUpload}, {"POST", setupRestoreConfirm}, {"POST", setupRestoreCancel},
	} {
		rec := b.do(tc.method, tc.path, nil)
		if rec.Code != 404 && rec.Code != 403 { // the upload has no token here: either way nothing happens
			t.Errorf("%s %s = %d, want 404", tc.method, tc.path, rec.Code)
		}
	}
	// A forged restore flag on the unlock form is ignored.
	b2 := e.browser(t)
	wantRedirect(t, b2.post("/setup/unlock", map[string][]string{"code": {setup.FormatCode(e.code)}, "restore": {"1"}}), "/setup/trust")
}

func TestSetupRestoreOnTheUnlockStep(t *testing.T) {
	e := newRestoreEnv(t)
	b := e.browser(t)
	rec := b.get("/setup")
	body := rec.Body.String()
	wantBody(t, rec, "Restore from a backup instead", `name="restore"`)
	// Enter in the code field must still unlock: the Unlock button comes first in the DOM.
	if iu, ir := strings.Index(body, "<span>Unlock</span>"), strings.Index(body, `name="restore"`); iu < 0 || ir < iu {
		t.Errorf("Unlock button at %d, restore button at %d: the restore button must come after", iu, ir)
	}
}

// TestSetupRestoreGate: the setup code gates everything.
func TestSetupRestoreGate(t *testing.T) {
	e := newRestoreEnv(t)

	t.Run("no route works without a verified code", func(t *testing.T) {
		b := e.browser(t)
		b.get("/setup") // csrf cookie only
		wantRedirect(t, b.get(setupRestorePath), "/setup")
		for _, path := range []string{setupRestoreConfirm, setupRestoreCancel} {
			rec := b.post(path, nil)
			if rec.Code != 401 {
				t.Errorf("POST %s = %d, want 401", path, rec.Code)
			}
			wantBody(t, rec, "The setup session expired", `id="f-code"`)
		}
		rec := b.uploadAs(e.file, restorePass)
		if rec.Code != 401 {
			t.Errorf("upload = %d, want 401", rec.Code)
		}
		if files := e.uploadFiles(); len(files) != 0 {
			t.Errorf("an unauthenticated upload left %v behind", files)
		}
		if _, err := os.Stat(e.lay.Database); err == nil {
			t.Error("a database appeared")
		}
	})

	t.Run("a wrong code does not open the restore page", func(t *testing.T) {
		b := e.browser(t)
		rec := b.post("/setup/unlock", map[string][]string{"code": {"AAAA-AAAA"}, "restore": {"1"}})
		if rec.Code != 401 || b.j[setupCookieName] != nil {
			t.Fatalf("status %d, setup cookie %v", rec.Code, b.j[setupCookieName] != nil)
		}
		wantRedirect(t, b.get(setupRestorePath), "/setup")
	})

	t.Run("restore without a code is refused", func(t *testing.T) {
		b := e.browser(t)
		rec := b.post("/setup/unlock", map[string][]string{"restore": {"1"}})
		if rec.Code != 400 || b.j[setupCookieName] != nil {
			t.Fatalf("status %d, setup cookie %v", rec.Code, b.j[setupCookieName] != nil)
		}
	})

	t.Run("the right code with the restore button lands on the restore page", func(t *testing.T) {
		b := e.browser(t)
		b.unlockForRestore()
		rec := b.get(setupRestorePath)
		if rec.Code != 200 {
			t.Fatalf("status %d", rec.Code)
		}
		wantBody(t, rec, "Restore from backup", `enctype="multipart/form-data"`, `action="/setup/restore/upload"`, `name="backup"`,
			`name="passphrase"`, "Check backup")
		body := rec.Body.String()
		if i, j := strings.Index(body, `name="csrf_token"`), strings.Index(body, `name="backup"`); i < 0 || j < i {
			t.Error("the csrf_token field must come before the file field (the handler checks it first)")
		}
	})

	t.Run("a returning operator with a session gets there with the button alone", func(t *testing.T) {
		b := e.browser(t)
		b.unlock()
		wantRedirect(t, b.post("/setup/unlock", map[string][]string{"restore": {"1"}}), setupRestorePath)
	})

	t.Run("not in setup mode", func(t *testing.T) {
		b := e.browser(t)
		b.unlockForRestore()
		e.setSetupMode(false)
		defer e.setSetupMode(true)
		wantRedirect(t, b.get(setupRestorePath), "/")
	})
}

func TestSetupRestoreUploadRejections(t *testing.T) {
	e := newRestoreEnv(t)
	newBrowser := func() *setupBrowser {
		// Every case starts with a fresh attempt budget and a valid code.
		e.clock.Add(setup.RestoreWindow + time.Second)
		e.renewCode(t)
		b := e.browser(t)
		b.unlockForRestore()
		return b
	}
	tooBig := append([]byte(nil), e.file...)
	truncated := e.file[:len(e.file)-200]

	tests := []struct {
		name     string
		do       func(b *setupBrowser) *httptest.ResponseRecorder
		wantCode int
		wantBody string
	}{
		{"wrong passphrase", func(b *setupBrowser) *httptest.ResponseRecorder { return b.uploadAs(e.file, "not the passphrase") },
			422, "Wrong passphrase, or the file is damaged."},
		{"not a backup file", func(b *setupBrowser) *httptest.ResponseRecorder {
			return b.uploadAs([]byte("this is just some text, not a backup at all"), restorePass)
		}, 422, "not a Nexara backup file"},
		{"truncated file", func(b *setupBrowser) *httptest.ResponseRecorder { return b.uploadAs(truncated, restorePass) },
			422, "damaged"},
		{"no file", func(b *setupBrowser) *httptest.ResponseRecorder {
			return b.uploadParts(mpPart{name: auth.CSRFFormField, data: []byte(b.j[csrfCookieName].Value)}, mpPart{name: fieldBackupPassphrase, data: []byte(restorePass)})
		}, 400, "Choose a backup file"},
		{"empty file", func(b *setupBrowser) *httptest.ResponseRecorder { return b.uploadAs(nil, restorePass) },
			400, "Choose a backup file"},
		{"no passphrase", func(b *setupBrowser) *httptest.ResponseRecorder { return b.uploadAs(tooBig, "") },
			400, "Enter the passphrase"},
		{"two files", func(b *setupBrowser) *httptest.ResponseRecorder {
			return b.uploadParts(
				mpPart{name: auth.CSRFFormField, data: []byte(b.j[csrfCookieName].Value)},
				mpPart{name: fieldBackupPassphrase, data: []byte(restorePass)},
				mpPart{name: fieldBackupFile, filename: "a", data: e.file},
				mpPart{name: fieldBackupFile, filename: "b", data: e.file})
		}, 400, "one backup file only"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := newBrowser()
			rec := tc.do(b)
			if rec.Code != tc.wantCode {
				t.Fatalf("status %d, want %d\n%s", rec.Code, tc.wantCode, rec.Body.String())
			}
			wantBody(t, rec, tc.wantBody, `role="alert"`, "Restore from backup")
			wantNoBody(t, rec, restorePass, "not the passphrase")
			if files := e.uploadFiles(); len(files) != 0 {
				t.Errorf("temp files left behind: %v", files)
			}
			// Nothing pending, nothing changed.
			sess, ok := e.srv.setup.Sessions.Lookup(b.token())
			if !ok {
				t.Fatal("setup session lost")
			}
			if _, has := sess.Upload(); has {
				t.Error("a rejected upload is pending")
			}
			wantBody(t, b.get(setupRestorePath), `name="backup"`)
			if _, err := os.Stat(e.lay.Database); err == nil {
				t.Error("a database appeared")
			}
		})
	}

	t.Run("a refused check is audited without secrets", func(t *testing.T) {
		b := newBrowser()
		b.uploadAs(e.file, "not the passphrase 2")
		var found bool
		for _, a := range e.restoreAudits() {
			if a.Result == store.AuditDenied && a.User == "setup" {
				found = true
				if strings.Contains(a.Detail, "passphrase 2") || !strings.Contains(a.Detail, "ip=") {
					t.Errorf("audit detail %q", a.Detail)
				}
			}
		}
		if !found {
			t.Error("no audit entry for the refused check")
		}
	})
}

func TestSetupRestoreUploadCSRF(t *testing.T) {
	e := newRestoreEnv(t)
	b := e.browser(t)
	b.unlockForRestore()
	tok := []byte(b.j[csrfCookieName].Value)
	file := mpPart{name: fieldBackupFile, filename: "x.nxbk", data: e.file}
	pass := mpPart{name: fieldBackupPassphrase, data: []byte(restorePass)}
	tests := []struct {
		name  string
		parts []mpPart
	}{
		{"no token", []mpPart{pass, file}},
		{"wrong token", []mpPart{{name: auth.CSRFFormField, data: []byte("x" + string(tok))}, pass, file}},
		{"empty token", []mpPart{{name: auth.CSRFFormField}, pass, file}},
		{"token after the file", []mpPart{pass, file, {name: auth.CSRFFormField, data: tok}}},
		{"token under another name", []mpPart{{name: "csrf", data: tok}, pass, file}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := b.uploadParts(tc.parts...)
			if rec.Code != 403 {
				t.Fatalf("status %d, want 403", rec.Code)
			}
			if files := e.uploadFiles(); len(files) != 0 {
				t.Errorf("the file was written before the token was checked: %v", files)
			}
		})
	}
	t.Run("a header token is not enough", func(t *testing.T) {
		body, ct := restoreMultipart(t, pass, file)
		rec := b.do(http.MethodPost, setupRestoreUpload, nil, func(r *http.Request) {
			r.Body = readerCloser{bytes.NewReader(body)}
			r.ContentLength = int64(len(body))
			r.Header.Set("Content-Type", ct)
			r.Header.Set(auth.CSRFHeader, string(tok))
		})
		if rec.Code != 403 {
			t.Fatalf("status %d, want 403", rec.Code)
		}
	})
	t.Run("rejected tokens do not use up attempts", func(t *testing.T) {
		for i := 0; i < 2*setup.RestorePerIPAttempts; i++ {
			b.uploadParts(pass, file)
		}
		if rec := b.uploadAs(e.file, restorePass); rec.Code != 303 {
			t.Fatalf("a valid upload after forged ones: status %d", rec.Code)
		}
	})
	t.Run("other form posts still need the token", func(t *testing.T) {
		for _, path := range []string{setupRestoreConfirm, setupRestoreCancel} {
			rec := b.do(http.MethodPost, path, nil)
			if rec.Code != 403 {
				t.Errorf("POST %s without a token = %d, want 403", path, rec.Code)
			}
		}
	})
}

func TestSetupRestoreUploadLimit(t *testing.T) {
	old := maxRestoreUpload
	maxRestoreUpload = 2 << 10
	defer func() { maxRestoreUpload = old }()

	e := newRestoreEnv(t)
	b := e.browser(t)
	b.unlockForRestore()
	rec := b.uploadAs(bytes.Repeat([]byte("x"), 8<<10), restorePass)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d, want 413\n%s", rec.Code, rec.Body.String())
	}
	wantBody(t, rec, "larger than")
	if files := e.uploadFiles(); len(files) != 0 {
		t.Errorf("the oversized upload left %v behind", files)
	}
}

func TestSetupRestoreSuccess(t *testing.T) {
	e := newRestoreEnv(t)
	b := e.browser(t)
	b.unlockForRestore()

	// Upload and check: PRG to the preview.
	wantRedirect(t, b.uploadAs(e.file, restorePass), setupRestorePath)
	if files := e.uploadFiles(); len(files) != 1 {
		t.Fatalf("the checked backup must be kept in the upload dir, got %v", files)
	} else if fi, err := os.Stat(filepath.Join(e.lay.BackupDir, files[0])); err != nil || fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("upload file mode %v, %v: must be private", fi.Mode(), err)
	}
	if _, err := os.Stat(e.lay.Database); err == nil {
		t.Fatal("checking must not change anything")
	}

	rec := b.get(setupRestorePath)
	wantBody(t, rec, "Restore this backup?", "old-hub", "0.2.0-test", "2026-09-30 03:00 UTC", "Database schema", "nexus-backup.nxbk",
		`action="/setup/restore/confirm"`, `action="/setup/restore/cancel"`, "Restore and restart")
	wantNoBody(t, rec, restorePass)
	if len(e.restarts) != 0 {
		t.Fatal("the hub restarted before the confirmation")
	}

	oldSession, oldCSRF := b.j[setupCookieName], b.j[csrfCookieName]

	// Confirm. The response is complete before the hub is asked to restart.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rec = b.do(http.MethodPost, setupRestoreConfirm, map[string][]string{
		auth.CSRFFormField: {b.j[csrfCookieName].Value},
	}, func(r *http.Request) { *r = *r.WithContext(ctx) })
	if rec.Code != 200 {
		t.Fatalf("status %d\n%s", rec.Code, rec.Body.String())
	}
	wantBody(t, rec, "Restored", "Nexus restarts", `data-restore-auto`, "/static/js/restore.js", `href="/login"`)
	wantNoBody(t, rec, restorePass)
	if len(e.restarts) != 0 {
		t.Fatal("Restart ran before the handler returned")
	}
	cancel() // what net/http does when the handler has returned
	select {
	case <-e.restarts:
	case <-time.After(5 * time.Second):
		t.Fatal("Restart was not called after the response")
	}
	select {
	case <-e.restarts:
		t.Fatal("Restart was called twice")
	case <-time.After(50 * time.Millisecond):
	}

	// The restored files are in place.
	cfg, err := config.LoadHub(e.lay.ConfigPath)
	if err != nil || cfg.Hub.Name != "old-hub" {
		t.Fatalf("restored config: %+v, %v", cfg.Hub, err)
	}
	if cfg.Storage.Database != e.lay.Database {
		t.Errorf("config points at %s", cfg.Storage.Database)
	}
	restored, err := store.Open(e.lay.Database)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if n, _ := restored.CountUsers(context.Background()); n != 1 {
		t.Errorf("restored database has %d operators, want 1", n)
	}
	for _, p := range []string{e.lay.SecretKey, filepath.Join(e.lay.TLSDir, "ca.pem")} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("restored file missing: %v", err)
		}
	}
	// The audit entry goes through the backup package, with the setup actor.
	e.mu.Lock()
	audits := append([]store.AuditEntry(nil), e.audits...)
	e.mu.Unlock()
	if len(audits) != 1 || audits[0].User != "setup" || audits[0].Action != backup.ActionRestore || audits[0].Result != store.AuditOK {
		t.Errorf("restore audit entries: %+v", audits)
	}

	// The setup is over: cookie cleared, session and code gone, upload deleted.
	if c := findCookie(rec, setupCookieName); c == nil || c.MaxAge >= 0 {
		t.Errorf("setup cookie not cleared: %+v", c)
	}
	if _, _, ok := e.srv.setup.Codes.Current(); ok {
		t.Error("the setup code is still valid")
	}
	if files := e.uploadFiles(); len(files) != 0 {
		t.Errorf("upload file left behind: %v", files)
	}
	rec = e.post(setupRestoreConfirm, withCookies(oldSession, oldCSRF), withForm(map[string][]string{auth.CSRFFormField: {oldCSRF.Value}}))
	if rec.Code != 401 {
		t.Errorf("a second confirm with the old session = %d, want 401", rec.Code)
	}
	if len(e.restarts) != 0 {
		t.Error("a second confirm restarted again")
	}
}

func TestSetupRestoreConfirmErrors(t *testing.T) {
	t.Run("a backup from a newer Nexus changes nothing", func(t *testing.T) {
		e := newRestoreEnv(t, func(o *backup.Options) { o.LatestSchema = func() int { return 0 } })
		b := e.browser(t)
		b.unlockForRestore()
		wantRedirect(t, b.uploadAs(e.file, restorePass), setupRestorePath)
		rec := b.post(setupRestoreConfirm, nil)
		if rec.Code != 422 {
			t.Fatalf("status %d\n%s", rec.Code, rec.Body.String())
		}
		wantBody(t, rec, "newer Nexus", "Nothing was changed", `role="alert"`)
		if _, err := os.Stat(e.lay.Database); err == nil {
			t.Error("a database appeared")
		}
		if _, err := os.Stat(e.lay.ConfigPath); err == nil {
			t.Error("a config appeared")
		}
		if files := e.uploadFiles(); len(files) != 0 {
			t.Errorf("upload file left behind: %v", files)
		}
		if len(e.restarts) != 0 {
			t.Error("a failed restore restarted the hub")
		}
		if _, _, ok := e.srv.setup.Codes.Current(); !ok {
			t.Error("a failed restore must leave the setup code alone")
		}
		// The wizard is still there.
		wantBody(t, b.get(setupRestorePath), `name="backup"`)
		if audits := e.restoreAudits(); len(audits) == 0 || audits[0].Result != store.AuditError {
			t.Errorf("failed restore not audited: %+v", audits)
		}
	})

	t.Run("confirm without a checked upload goes back to the upload form", func(t *testing.T) {
		e := newRestoreEnv(t)
		b := e.browser(t)
		b.unlockForRestore()
		wantRedirect(t, b.post(setupRestoreConfirm, nil), setupRestorePath)
		if len(e.restarts) != 0 {
			t.Error("restart without a restore")
		}
	})

	t.Run("cancel throws the upload away", func(t *testing.T) {
		e := newRestoreEnv(t)
		b := e.browser(t)
		b.unlockForRestore()
		wantRedirect(t, b.uploadAs(e.file, restorePass), setupRestorePath)
		wantRedirect(t, b.post(setupRestoreCancel, nil), setupRestorePath)
		if files := e.uploadFiles(); len(files) != 0 {
			t.Errorf("upload file left behind: %v", files)
		}
		wantBody(t, b.get(setupRestorePath), `name="backup"`)
		wantRedirect(t, b.post(setupRestoreConfirm, nil), setupRestorePath)
	})

	t.Run("a new upload replaces the pending one", func(t *testing.T) {
		e := newRestoreEnv(t)
		b := e.browser(t)
		b.unlockForRestore()
		wantRedirect(t, b.uploadAs(e.file, restorePass), setupRestorePath)
		wantRedirect(t, b.uploadAs(e.file, restorePass), setupRestorePath)
		if files := e.uploadFiles(); len(files) != 1 {
			t.Errorf("want exactly one pending file, got %v", files)
		}
	})

	t.Run("only one check or restore at a time", func(t *testing.T) {
		e := newRestoreEnv(t)
		b := e.browser(t)
		b.unlockForRestore()
		release, ok := e.srv.setup.Sessions.RestoreLimits().Begin()
		if !ok {
			t.Fatal("slot not free")
		}
		defer release()
		rec := b.uploadAs(e.file, restorePass)
		if rec.Code != 503 || rec.Header().Get("Retry-After") == "" {
			t.Fatalf("upload while busy: %d", rec.Code)
		}
		wantRedirect(t, b.post(setupRestoreCancel, nil), setupRestorePath) // cancel needs no slot
		if rec := b.post(setupRestoreConfirm, nil); rec.Code != 503 {
			t.Fatalf("confirm while busy: %d", rec.Code)
		}
	})
}

func TestSetupRestoreRateLimit(t *testing.T) {
	e := newRestoreEnv(t)
	attempt := func(b *setupBrowser) *httptest.ResponseRecorder { return b.uploadAs(e.file, "wrong passphrase!") }
	browserAt := func(ip string) *setupBrowser {
		e.renewCode(t)
		b := e.browser(t)
		b.ra = ip + ":40000"
		b.unlockForRestore()
		return b
	}

	t.Run("per address", func(t *testing.T) {
		b := browserAt("192.0.2.50")
		for i := 0; i < setup.RestorePerIPAttempts; i++ {
			if rec := attempt(b); rec.Code != 422 {
				t.Fatalf("attempt %d: %d", i+1, rec.Code)
			}
		}
		rec := attempt(b)
		if rec.Code != 429 || rec.Header().Get("Retry-After") == "" {
			t.Fatalf("status %d, Retry-After %q", rec.Code, rec.Header().Get("Retry-After"))
		}
		wantBody(t, rec, "Too many restore attempts")
		// Even the right passphrase is refused while blocked, and no file was touched.
		if rec := b.uploadAs(e.file, restorePass); rec.Code != 429 {
			t.Fatalf("right passphrase while blocked: %d", rec.Code)
		}
		if files := e.uploadFiles(); len(files) != 0 {
			t.Errorf("blocked attempts left %v", files)
		}
		// Another address is unaffected; this one recovers after the window.
		if rec := attempt(browserAt("192.0.2.51")); rec.Code != 422 {
			t.Errorf("other address: %d", rec.Code)
		}
		e.clock.Add(setup.RestoreWindow + time.Second)
		if rec := attempt(browserAt("192.0.2.50")); rec.Code != 422 {
			t.Errorf("after the window: %d", rec.Code)
		}
	})

	t.Run("all addresses together", func(t *testing.T) {
		e.clock.Add(2 * setup.RestoreWindow)
		var last *httptest.ResponseRecorder
		for i := 0; i < setup.RestoreGlobalAttempts; i++ {
			b := browserAt(fmt.Sprintf("198.51.100.%d", 10+i/setup.RestorePerIPAttempts))
			last = attempt(b)
			if last.Code != 422 {
				t.Fatalf("attempt %d: %d", i+1, last.Code)
			}
		}
		rec := attempt(browserAt("203.0.113.9"))
		if rec.Code != 429 {
			t.Fatalf("one more from a new address: %d, want 429", rec.Code)
		}
		e.clock.Add(setup.RestoreWindow + time.Second)
		if rec := attempt(browserAt("203.0.113.9")); rec.Code != 422 {
			t.Errorf("after the window: %d", rec.Code)
		}
	})

	t.Run("blocked attempts are audited", func(t *testing.T) {
		var n int
		for _, a := range e.restoreAudits() {
			if strings.Contains(a.Detail, "rate_limited") {
				n++
			}
		}
		if n == 0 {
			t.Error("no audit entry for the rate limit")
		}
	})
}

func TestRestoreErrorMessage(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantText   string
		notText    string
	}{
		{"wrong passphrase", backup.ErrAuth, 422, "Wrong passphrase, or the file is damaged.", ""},
		{"wrapped sentinel", fmt.Errorf("x: %w", backup.ErrCorrupt), 422, "damaged or has been modified", ""},
		{"not a backup", backup.ErrNotBackup, 422, "not a Nexara backup file", ""},
		{"too new", fmt.Errorf("%w (backup schema 9, this Nexus supports up to 2)", backup.ErrTooNew), 422, "newer Nexus", "schema 9"},
		{"newer format", backup.ErrUnsupportedFormat, 422, "newer Nexus", ""},
		{"local backup", backup.ErrWrongKeyKind, 422, "automatic backup", ""},
		{"interrupted", context.Canceled, 503, "interrupted", ""},
		{"worded for the screen", fmt.Errorf("backup: the backup does not contain nexus.yaml"), 422, "The backup does not contain nexus.yaml.", ""},
		{"paths stay out of the page", fmt.Errorf("backup: cannot prepare /var/lib/nexus/nexus.db: permission denied"), 500, "could not be checked", "/var/lib"},
		{"unknown", fmt.Errorf("disk on fire"), 500, "could not be checked", "disk on fire"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg, status := restoreErrorMessage(tc.err)
			if status != tc.wantStatus || !strings.Contains(msg, tc.wantText) || (tc.notText != "" && strings.Contains(msg, tc.notText)) {
				t.Errorf("restoreErrorMessage = %q, %d; want %q (not %q), %d", msg, status, tc.wantText, tc.notText, tc.wantStatus)
			}
		})
	}
}

func TestDisplayFileName(t *testing.T) {
	tests := map[string]string{
		"nexus-backup.nxbk":                "nexus-backup.nxbk",
		`C:\Users\me\Downloads\b.nxbk`:     "b.nxbk",
		"../../etc/passwd":                 "passwd",
		"":                                 "backup.nxbk",
		".":                                "backup.nxbk",
		"a\x00b\nc.nxbk":                   "abc.nxbk",
		strings.Repeat("x", 200) + ".nxbk": strings.Repeat("x", 80),
	}
	for in, want := range tests {
		if got := displayFileName(in); got != want {
			t.Errorf("displayFileName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSetupByteSize(t *testing.T) {
	tests := map[int64]string{0: "0 bytes", 900: "900 bytes", 2048: "2 KB", 1 << 20: "1.0 MB", 3 << 19: "1.5 MB", 40 << 20: "40 MB"}
	for in, want := range tests {
		if got := setupByteSize(in); got != want {
			t.Errorf("setupByteSize(%d) = %q, want %q", in, got, want)
		}
	}
}

// Security review A-09/B-03: the wizard's earlier entries and the restore entry
// (with the client address) are handed to the restored database; a failed
// restore is audited once, by the backup service, with the address.
func TestSetupRestoreAuditReachesTheRestoredDatabase(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := newRestoreEnv(t)
		for _, en := range []store.AuditEntry{
			{Time: time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC), User: "setup", Action: "setup.wrong_code", Result: store.AuditDenied, Detail: "ip=203.0.113.9"},
			{Time: time.Date(2026, 10, 3, 9, 1, 0, 0, time.UTC), User: "setup", Action: "setup.unlock", Result: store.AuditOK, Detail: "ip=203.0.113.9"},
			{Time: time.Date(2026, 10, 3, 9, 2, 0, 0, time.UTC), User: "alice", Action: "login", Result: store.AuditOK},
		} {
			if _, err := e.st.AppendAudit(context.Background(), en); err != nil {
				t.Fatal(err)
			}
		}
		// A key the hub had before: it is kept as *.before-restore, and the page says so (B-07).
		if err := os.MkdirAll(filepath.Dir(e.lay.SecretKey), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(e.lay.SecretKey, bytes.Repeat([]byte("k"), 32), 0o600); err != nil {
			t.Fatal(err)
		}
		b := e.browser(t)
		b.ra = "203.0.113.9:4711"
		b.unlockForRestore()
		wantRedirect(t, b.uploadAs(e.file, restorePass), setupRestorePath)
		rec := b.post(setupRestoreConfirm, nil)
		if rec.Code != 200 {
			t.Fatalf("confirm: %d\n%s", rec.Code, rec.Body.String())
		}
		wantBody(t, rec, "kept next to the new ones as *.before-restore")
		if _, err := os.Stat(e.lay.SecretKey + backup.BeforeRestoreSuffix); err != nil {
			t.Errorf("the old key was not kept: %v", err)
		}
		e.mu.Lock()
		got := append([]store.AuditEntry(nil), e.audits...)
		e.mu.Unlock()
		if len(got) != 3 {
			t.Fatalf("entries for the restored database: %+v", got)
		}
		if got[0].Action != "setup.wrong_code" || got[1].Action != "setup.unlock" {
			t.Errorf("carried entries (oldest first): %+v", got[:2])
		}
		last := got[2]
		if last.Action != backup.ActionRestore || last.Result != store.AuditOK || !strings.Contains(last.Detail, "ip=203.0.113.9") {
			t.Errorf("restore entry: %+v", last)
		}
	})

	t.Run("failure is audited once with the address", func(t *testing.T) {
		e := newRestoreEnv(t, func(o *backup.Options) { o.LatestSchema = func() int { return 0 } })
		b := e.browser(t)
		b.ra = "203.0.113.9:4711"
		b.unlockForRestore()
		wantRedirect(t, b.uploadAs(e.file, restorePass), setupRestorePath)
		if rec := b.post(setupRestoreConfirm, nil); rec.Code != 422 {
			t.Fatalf("confirm: %d", rec.Code)
		}
		audits := e.restoreAudits()
		if len(audits) != 1 || audits[0].Result != store.AuditError || !strings.Contains(audits[0].Detail, "ip=203.0.113.9") {
			t.Errorf("audit entries of the failed restore: %+v", audits)
		}
	})
}
