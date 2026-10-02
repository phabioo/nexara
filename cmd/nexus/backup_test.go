package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phabioo/nexara/internal/config"
	"github.com/phabioo/nexara/internal/hub/app"
	"github.com/phabioo/nexara/internal/hub/auth"
	"github.com/phabioo/nexara/internal/hub/backup"
	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/pki"
)

// The real dropToNexus would take the test process's root away (when a nexus
// user exists on the machine), so tests run without it.
func init() { dropPrivileges = func() error { return nil } }

const cliPass = "correct horse battery staple"

type cliHub struct {
	cfgPath string
	data    string
	db      string
}

// newCLIHub lays out a minimal hub (config, database with one operator,
// secret key, CA) below a temp dir.
func newCLIHub(t *testing.T) cliHub {
	t.Helper()
	root := t.TempDir()
	h := cliHub{cfgPath: filepath.Join(root, "etc", "nexus.yaml"), data: filepath.Join(root, "var"), db: filepath.Join(root, "var", "nexus.db")}
	for _, d := range []string{filepath.Dir(h.cfgPath), h.data} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.DefaultHub()
	cfg.Storage.Database = h.db
	cfg.TLS.Dir = filepath.Join(h.data, "pki")
	if err := config.SaveHub(h.cfgPath, cfg); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(h.db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateUser(context.Background(), store.User{OperatorID: "alice", PassHash: "h"}); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.LoadOrCreateSecretKey(filepath.Join(h.data, "secret.key")); err != nil {
		t.Fatal(err)
	}
	if _, err := pki.LoadOrCreateCA(cfg.TLS.Dir, "localhost"); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h cliHub) backupFiles(t *testing.T) []string {
	t.Helper()
	m, _ := filepath.Glob(filepath.Join(h.data, "backups", "*.nxbk"))
	return m
}

func notRunning(t *testing.T, running bool) {
	t.Helper()
	orig := hubRunning
	hubRunning = func(string) bool { return running }
	t.Cleanup(func() { hubRunning = orig })
}

func userExists(t *testing.T, db, id string) bool {
	t.Helper()
	st, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_, err = st.GetUserByOperatorID(context.Background(), id)
	return err == nil
}

func TestBackupCreateAndList(t *testing.T) {
	h := newCLIHub(t)
	code, out, errOut := runCtxArgs(context.Background(), "", "backup", "create", "--config", h.cfgPath, "--reason", "pre-update")
	if code != 0 || !strings.Contains(out, "Backup created") || !strings.Contains(out, "pre-update") {
		t.Fatalf("code %d stdout %q stderr %q", code, out, errOut)
	}
	files := h.backupFiles(t)
	if len(files) != 1 || !strings.Contains(files[0], "-pre-update.nxbk") {
		t.Fatalf("files = %v", files)
	}
	if fi, _ := os.Stat(files[0]); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(filepath.Dir(files[0])); fi.Mode().Perm() != 0o700 {
		t.Errorf("dir mode %v", fi.Mode().Perm())
	}
	// The CLI did not run migrations or leave journal files behind that a
	// different user could not use: the database is as before.
	code, out, _ = runCtxArgs(context.Background(), "", "backup", "list", "--config", h.cfgPath)
	if code != 0 || !strings.Contains(out, filepath.Base(files[0])) || !strings.Contains(out, "pre-update") {
		t.Errorf("list: %d %q", code, out)
	}

	// --keep prunes (names differ by reason; give each its own second).
	for i := 0; i < 3; i++ {
		if code, _, e := runCtxArgs(context.Background(), "", "backup", "create", "--config", h.cfgPath, "--reason", "manual", "--keep", "2"); code != 0 {
			t.Fatalf("create %d: %s", i, e)
		}
	}
	if n := len(h.backupFiles(t)); n != 2 {
		t.Errorf("--keep 2 left %d files", n)
	}
}

func TestBackupCreateErrors(t *testing.T) {
	h := newCLIHub(t)
	tests := []struct {
		name string
		args []string
		code int
		msg  string
	}{
		{"bad reason", []string{"create", "--config", h.cfgPath, "--reason", "Bad Reason"}, 1, "invalid reason"},
		{"missing config", []string{"create", "--config", filepath.Join(t.TempDir(), "none.yaml")}, 1, "configuration"},
		{"extra argument", []string{"create", "--config", h.cfgPath, "stray"}, 2, "Usage"},
		{"no subcommand", []string{}, 2, "Usage"},
		{"unknown subcommand", []string{"frobnicate"}, 2, "unknown command"},
		{"bad flag", []string{"create", "--bogus"}, 2, "not defined"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, _, errOut := runCtxArgs(context.Background(), "", append([]string{"backup"}, tc.args...)...)
			if code != tc.code || !strings.Contains(errOut, tc.msg) {
				t.Fatalf("code %d stderr %q", code, errOut)
			}
		})
	}
}

func TestBackupRestoreLocal(t *testing.T) {
	h := newCLIHub(t)
	runCtxArgs(context.Background(), "", "backup", "create", "--config", h.cfgPath)
	files := h.backupFiles(t)
	if len(files) != 1 {
		t.Fatal("no backup")
	}
	// Change the live state after the backup.
	st, _ := store.Open(h.db)
	_, _ = st.CreateUser(context.Background(), store.User{OperatorID: "mallory", PassHash: "x"})
	_ = st.Close()

	t.Run("refused while the service runs", func(t *testing.T) {
		notRunning(t, true)
		code, _, errOut := runCtxArgs(context.Background(), "", "backup", "restore", files[0], "--config", h.cfgPath, "--yes")
		if code != 1 || !strings.Contains(errOut, "systemctl stop nexus") {
			t.Fatalf("code %d %q", code, errOut)
		}
		if !userExists(t, h.db, "mallory") {
			t.Error("database was changed")
		}
	})
	t.Run("declined", func(t *testing.T) {
		notRunning(t, false)
		code, _, errOut := runCtxArgs(context.Background(), "n\n", "backup", "restore", files[0], "--config", h.cfgPath)
		if code != 1 || !strings.Contains(errOut, "cancelled") || !userExists(t, h.db, "mallory") {
			t.Fatalf("code %d %q", code, errOut)
		}
	})
	t.Run("confirmed", func(t *testing.T) {
		notRunning(t, false)
		code, out, errOut := runCtxArgs(context.Background(), "y\n", "backup", "restore", "--config", h.cfgPath, files[0])
		if code != 0 || !strings.Contains(out, "Restored") || !strings.Contains(out, "systemctl start nexus") {
			t.Fatalf("code %d stdout %q stderr %q", code, out, errOut)
		}
		if userExists(t, h.db, "mallory") || !userExists(t, h.db, "alice") {
			t.Error("database was not restored")
		}
		if _, err := os.Stat(h.db + ".before-restore"); err != nil {
			t.Errorf("one step back is missing: %v", err)
		}
	})
}

func TestBackupPassphraseFileFlow(t *testing.T) {
	h := newCLIHub(t)
	svc, _, err := app.OpenBackupService(h.cfgPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := svc.WriteDownload(context.Background(), &buf, cliPass); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "disaster.nxbk")
	passFile := filepath.Join(dir, "pass")
	badPass := filepath.Join(dir, "bad")
	for p, c := range map[string][]byte{file: buf.Bytes(), passFile: []byte(cliPass + "\n"), badPass: []byte("not the passphrase\n")} {
		if err := os.WriteFile(p, c, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	notRunning(t, false)

	code, out, errOut := runCtxArgs(context.Background(), "", "backup", "inspect", file, "--config", h.cfgPath, "--passphrase-file", passFile)
	if code != 0 || !strings.Contains(out, "checksums match") || !strings.Contains(out, "nexus.db") {
		t.Fatalf("inspect: %d %q %q", code, out, errOut)
	}
	code, _, errOut = runCtxArgs(context.Background(), "", "backup", "inspect", "--config", h.cfgPath, "--passphrase-file", badPass, file)
	if code != 1 || !strings.Contains(errOut, "wrong passphrase") {
		t.Fatalf("wrong passphrase: %d %q", code, errOut)
	}

	st, _ := store.Open(h.db)
	_, _ = st.CreateUser(context.Background(), store.User{OperatorID: "mallory", PassHash: "x"})
	_ = st.Close()

	// Wrong passphrase on restore: nothing changes.
	code, _, errOut = runCtxArgs(context.Background(), "", "backup", "restore", file, "--config", h.cfgPath, "--passphrase-file", badPass, "--yes")
	if code != 1 || !userExists(t, h.db, "mallory") {
		t.Fatalf("restore with a wrong passphrase: %d %q", code, errOut)
	}
	// Passphrase and confirmation both come from stdin.
	code, out, errOut = runCtxArgs(context.Background(), cliPass+"\ny\n", "backup", "restore", file, "--config", h.cfgPath)
	if code != 0 || !strings.Contains(out, "Backup passphrase:") || !strings.Contains(out, "Restored") {
		t.Fatalf("restore: %d %q %q", code, out, errOut)
	}
	if userExists(t, h.db, "mallory") {
		t.Error("database was not restored")
	}
	// The restore left a backup.restore entry in the restored database.
	st, _ = store.Open(h.db)
	defer st.Close()
	entries, _ := st.ListAudit(context.Background(), 20)
	found := false
	for _, e := range entries {
		if e.Action == backup.ActionRestore && e.User == "cli" && e.Result == store.AuditOK {
			found = true
		}
	}
	if !found {
		t.Errorf("no backup.restore audit entry: %+v", entries)
	}
}

func TestBackupListEmptyAndHelp(t *testing.T) {
	h := newCLIHub(t)
	code, out, _ := runCtxArgs(context.Background(), "", "backup", "list", "--config", h.cfgPath)
	if code != 0 || !strings.Contains(out, "No local backups") {
		t.Errorf("%d %q", code, out)
	}
	if code, out, _ := runCtxArgs(context.Background(), "", "backup", "help"); code != 0 || !strings.Contains(out, "restore <file>") {
		t.Errorf("help: %d %q", code, out)
	}
	if code, out, _ := runCtxArgs(context.Background(), "", "help"); code != 0 || !strings.Contains(out, "backup") {
		t.Errorf("main usage lacks backup: %q", out)
	}
	for _, args := range [][]string{{"inspect"}, {"restore"}, {"restore", "a", "b"}} {
		if code, _, _ := runCtxArgs(context.Background(), "", append([]string{"backup"}, args...)...); code != 2 {
			t.Errorf("%v: code %d, want 2", args, code)
		}
	}
}

// Every subcommand that touches hub files gives up root first, and stops when
// it cannot.
func TestBackupDropsPrivilegesFirst(t *testing.T) {
	h := newCLIHub(t)
	notRunning(t, false)
	svc, _, err := app.OpenBackupService(h.cfgPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	info, err := svc.CreateLocal(context.Background(), "manual")
	if err != nil {
		t.Fatal(err)
	}
	before := len(h.backupFiles(t))

	orig := dropPrivileges
	t.Cleanup(func() { dropPrivileges = orig })

	for _, args := range [][]string{
		{"create"}, {"list"}, {"inspect", info.Path}, {"restore", info.Path, "--yes"},
	} {
		calls := 0
		dropPrivileges = func() error { calls++; return nil }
		runCtxArgs(context.Background(), "", append([]string{"backup", args[0]}, append(args[1:], "--config", h.cfgPath)...)...)
		if calls != 1 {
			t.Errorf("%v: privileges dropped %d times, want 1", args, calls)
		}
	}

	dropPrivileges = func() error { return errors.New("cannot switch to the nexus user: boom") }
	for _, args := range [][]string{{"create"}, {"list"}, {"inspect", info.Path}, {"restore", info.Path, "--yes"}} {
		code, _, errOut := runCtxArgs(context.Background(), "", append([]string{"backup", args[0]}, append(args[1:], "--config", h.cfgPath)...)...)
		if code != 1 || !strings.Contains(errOut, "boom") {
			t.Errorf("%v: code %d stderr %q", args, code, errOut)
		}
	}
	if n := len(h.backupFiles(t)); n != before+1 { // only the first loop's create added one
		t.Errorf("backup files = %d, want %d: a failed privilege drop must not create or touch anything", n, before+1)
	}
}
