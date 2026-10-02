package backup

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/config"
	"github.com/phabioo/nexara/internal/hub/auth"
	"github.com/phabioo/nexara/internal/hub/store"
)

var bg = context.Background()

// newTarget returns a hub layout under a fresh root with nothing in it: the
// replacement device after an SD-card failure.
func newTarget(t *testing.T) *testHub {
	t.Helper()
	root := t.TempDir()
	h := &testHub{t: t, root: root, clock: &fakeClock{t: t0}, set: &memSettings{}}
	h.lay = Layout{
		ConfigPath: filepath.Join(root, "etc", "nexus.yaml"),
		Database:   filepath.Join(root, "var", "nexus.db"),
		TLSDir:     filepath.Join(root, "var", "pki"),
		SecretKey:  filepath.Join(root, "var", "secret.key"),
		SSHKey:     filepath.Join(root, "var", "ssh", "id_ed25519"),
		BackupDir:  filepath.Join(root, "var", "backups"),
	}
	h.svc = New(Options{Layout: h.lay, KDF: testKDF, Now: h.clock.Now,
		AuditRestore: func(_ context.Context, db string, _ store.AuditEntry) error {
			h.restoreAudits = append(h.restoreAudits, db)
			return nil
		}})
	return h
}

var liveFiles = []func(Layout) string{
	func(l Layout) string { return l.ConfigPath },
	func(l Layout) string { return l.SecretKey },
	func(l Layout) string { return l.SSHKey },
	func(l Layout) string { return filepath.Join(l.TLSDir, "ca.pem") },
	func(l Layout) string { return filepath.Join(l.TLSDir, "ca.key") },
	func(l Layout) string { return filepath.Join(l.TLSDir, "server.pem") },
	func(l Layout) string { return filepath.Join(l.TLSDir, "server.key") },
}

func TestRoundTripPassphraseOnNewDevice(t *testing.T) {
	src := newHub(t)
	data := downloadBytes(t, src, testPass)
	wantUsers, wantAudit := dbContent(t, src.lay.Database)
	if len(wantUsers) == 0 || len(wantAudit) == 0 {
		t.Fatal("fixture database is empty")
	}

	dst := newTarget(t)
	res, err := dst.svc.Restore(bg, bytes.NewReader(data), testPass)
	if err != nil {
		t.Fatal(err)
	}
	if !res.RestartRequired || res.Manifest.HubName != "frpi5" || res.Manifest.Reason != ReasonDownload || res.Manifest.HubVersion != "0.2.0-test" {
		t.Errorf("result = %+v", res)
	}
	if len(res.Replaced) != 0 {
		t.Errorf("nothing existed, but Replaced = %v", res.Replaced)
	}
	if !res.ConfigAdjusted {
		t.Error("the backup came from other paths; the config must be adjusted")
	}

	for _, f := range liveFiles[1:] { // the config legitimately changes (paths)
		a, err1 := os.ReadFile(f(src.lay))
		b, err2 := os.ReadFile(f(dst.lay))
		if err1 != nil || err2 != nil || !bytes.Equal(a, b) {
			t.Errorf("%s differs after restore (%v, %v)", filepath.Base(f(src.lay)), err1, err2)
		}
	}
	cfg, err := config.LoadHub(dst.lay.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Storage.Database != dst.lay.Database || cfg.TLS.Dir != dst.lay.TLSDir || cfg.Hub.Name != "frpi5" || cfg.Hub.AgentAddress != "frpi5.local" {
		t.Errorf("restored config = %+v", cfg)
	}
	gotUsers, gotAudit := dbContent(t, dst.lay.Database)
	if fmt.Sprint(gotUsers) != fmt.Sprint(wantUsers) || fmt.Sprint(gotAudit) != fmt.Sprint(wantAudit) {
		t.Errorf("database differs:\n users %v vs %v\n audit %v vs %v", gotUsers, wantUsers, gotAudit, wantAudit)
	}
	if len(dst.restoreAudits) != 1 || dst.restoreAudits[0] != dst.lay.Database {
		t.Errorf("restore audit hook calls = %v", dst.restoreAudits)
	}
	assertNoLeftovers(t, dst)
	if runtime.GOOS != "windows" {
		for p, want := range map[string]os.FileMode{
			dst.lay.Database: 0o600, dst.lay.SecretKey: 0o600, dst.lay.SSHKey: 0o600,
			filepath.Join(dst.lay.TLSDir, "ca.key"): 0o600, filepath.Join(dst.lay.TLSDir, "ca.pem"): 0o644,
			dst.lay.ConfigPath: 0o640,
		} {
			if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != want {
				t.Errorf("%s mode = %v, %v; want %v", p, fi.Mode().Perm(), err, want)
			}
		}
	}
}

// assertNoLeftovers fails when staging or .restore-new files remain.
func assertNoLeftovers(t *testing.T, h *testHub) {
	t.Helper()
	for p := range fileState(t, h.root, true) {
		if strings.Contains(p, restoreNewSuffix) || strings.Contains(p, ".staging-") || strings.Contains(p, ".restore-") {
			t.Errorf("left over: %s", p)
		}
	}
}

func TestRoundTripLocalOnSameDevice(t *testing.T) {
	h := newHub(t)
	ctx := WithActor(bg, "cli")
	info, err := h.svc.CreateLocal(ctx, ReasonPreUpdate)
	if err != nil {
		t.Fatal(err)
	}
	if info.Reason != ReasonPreUpdate || !info.Readable || info.HubVersion != "0.2.0-test" || info.Size == 0 {
		t.Errorf("info = %+v", info)
	}
	wantCfg, _ := os.ReadFile(h.lay.ConfigPath)
	wantSecret, _ := os.ReadFile(h.lay.SecretKey)
	wantUsers, wantAudit := dbContent(t, h.lay.Database)
	before := fileState(t, h.root, false)
	must(t, h.st.Close())

	// The device drifts away from the backup afterwards.
	must(t, os.WriteFile(h.lay.ConfigPath, []byte("garbage"), 0o640))
	must(t, os.Remove(filepath.Join(h.lay.TLSDir, "server.key")))
	st, err := store.Open(h.lay.Database)
	must(t, err)
	if _, err := st.CreateUser(bg, store.User{OperatorID: "mallory", PassHash: "x"}); err != nil {
		t.Fatal(err)
	}
	must(t, st.Close())

	res, err := h.svc.RestoreLocal(bg, info.Name)
	if err != nil {
		t.Fatal(err)
	}
	if res.ConfigAdjusted {
		t.Error("same layout: the config must not be adjusted")
	}
	if got, _ := os.ReadFile(h.lay.ConfigPath); !bytes.Equal(got, wantCfg) {
		t.Errorf("config not restored:\n%s", got)
	}
	if got, _ := os.ReadFile(h.lay.SecretKey); !bytes.Equal(got, wantSecret) {
		t.Error("secret.key differs")
	}
	gotUsers, gotAudit := dbContent(t, h.lay.Database)
	if fmt.Sprint(gotUsers) != fmt.Sprint(wantUsers) {
		t.Errorf("users after restore = %v, want %v (mallory must be gone)", gotUsers, wantUsers)
	}
	// The audit list also holds the entries written by the content check above;
	// compare the prefix that existed at backup time.
	if len(gotAudit) < len(wantAudit) || fmt.Sprint(gotAudit[:len(wantAudit)]) != fmt.Sprint(wantAudit) {
		t.Errorf("audit after restore = %v", gotAudit)
	}
	for _, f := range liveFiles {
		if _, err := os.Stat(f(h.lay)); err != nil {
			t.Errorf("%v", err)
		}
	}
	// One step back: the replaced files are kept next to the new ones.
	if b, _ := os.ReadFile(h.lay.ConfigPath + BeforeRestoreSuffix); string(b) != "garbage" {
		t.Errorf("config.before-restore = %q", b)
	}
	if _, err := os.Stat(h.lay.Database + BeforeRestoreSuffix); err != nil {
		t.Errorf("database not kept: %v", err)
	}
	if len(res.Replaced) < 3 {
		t.Errorf("Replaced = %v", res.Replaced)
	}
	// server.key did not exist before the restore: nothing to keep.
	if _, err := os.Stat(filepath.Join(h.lay.TLSDir, "server.key"+BeforeRestoreSuffix)); err == nil {
		t.Error("kept a file that did not exist")
	}
	assertNoLeftovers(t, h)
	_ = before
}

func TestRestoreRemovesStaleJournalFiles(t *testing.T) {
	h := newHub(t)
	data := downloadBytes(t, h, testPass)
	must(t, os.WriteFile(h.lay.Database+"-wal", []byte("stale wal"), 0o600))
	must(t, os.WriteFile(h.lay.Database+"-shm", []byte("stale shm"), 0o600))
	if _, err := h.svc.Restore(bg, bytes.NewReader(data), testPass); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(h.lay.Database + s); err == nil {
			t.Errorf("stale %s next to the restored database", s)
		}
		if b, _ := os.ReadFile(h.lay.Database + s + BeforeRestoreSuffix); !strings.HasPrefix(string(b), "stale") {
			t.Errorf("stale %s not kept: %q", s, b)
		}
	}
}

// padFixture grows the hub's database so the backup spans several chunks.
func padFixture(t *testing.T, h *testHub) {
	t.Helper()
	for i := 0; i < 1500; i++ {
		_, err := h.st.AppendAudit(bg, store.AuditEntry{User: "alice", Action: "login", Result: store.AuditOK,
			Detail: strings.Repeat(fmt.Sprintf("entry %d ", i), 40)})
		must(t, err)
	}
}

func TestRestoreFailsLeaveNothingChanged(t *testing.T) {
	h := newHub(t)
	padFixture(t, h) // several chunks: the chunk-swap case needs three
	good := downloadBytes(t, h, testPass)
	// Make the live state differ from the backup, so a partial restore would show.
	must(t, os.WriteFile(h.lay.SecretKey+".marker", []byte("m"), 0o600))
	before := fileState(t, h.root, true)

	ct := chunkSize + tagSize
	if len(good) < headerSize+4*ct {
		t.Fatalf("fixture backup too small (%d bytes) for the chunk swap case", len(good))
	}
	flip := func(b []byte, at int) []byte { b = bytes.Clone(b); b[at] ^= 1; return b }
	tests := []struct {
		name string
		data []byte
		pass string
		want error
	}{
		{"wrong passphrase", good, "this is wrong, really", ErrAuth},
		{"bit flip in first chunk", flip(good, headerSize+5), testPass, ErrAuth},
		{"bit flip in a later chunk", flip(good, headerSize+ct+5), testPass, ErrCorrupt},
		{"bit flip in the last chunk", flip(good, len(good)-3), testPass, ErrCorrupt},
		{"truncated mid chunk", good[:len(good)-1], testPass, ErrCorrupt},
		{"truncated at a chunk boundary", good[:headerSize+2*ct], testPass, ErrCorrupt},
		{"truncated to the first chunk", good[:headerSize+ct], testPass, ErrAuth},
		{"appended data", append(bytes.Clone(good), 1, 2, 3), testPass, ErrCorrupt},
		{"chunks swapped", func() []byte {
			b := bytes.Clone(good)
			a, c := b[headerSize+ct:headerSize+2*ct], b[headerSize+2*ct:headerSize+3*ct]
			x, y := bytes.Clone(a), bytes.Clone(c)
			copy(b[headerSize+ct:], y)
			copy(b[headerSize+2*ct:], x)
			return b
		}(), testPass, ErrCorrupt},
		{"not a backup", []byte("hello hello hello hello hello hello hello hello"), testPass, ErrNotBackup},
		{"empty", nil, testPass, ErrNotBackup},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := h.svc.Restore(bg, bytes.NewReader(tc.data), tc.pass)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			sameState(t, before, fileState(t, h.root, true))
		})
	}
}

func TestRestoreRefusals(t *testing.T) {
	h := newHub(t)
	good := downloadBytes(t, h, testPass)
	before := fileState(t, h.root, true)

	tests := []struct {
		name   string
		data   []byte
		latest func() int
		want   string
	}{
		{"schema newer than this binary", good, func() int { return store.LatestSchemaVersion() - 1 }, "newer Nexus"},
		{"archive format newer", rebuild(t, good, func(_ string, m *Manifest) { m.Format = ArchiveVersion + 1 }), nil, "newer than this Nexus understands"},
		{"manifest schema does not match the database", rebuild(t, good, func(_ string, m *Manifest) { m.SchemaVersion = 1 + store.LatestSchemaVersion() }), nil, "newer Nexus"},
		{"manifest schema claims older than database", rebuild(t, good, func(_ string, m *Manifest) {
			if store.LatestSchemaVersion() < 2 {
				m.SchemaVersion = 0
			} else {
				m.SchemaVersion = 1
			}
		}), nil, ""},
		{"database damaged", rebuild(t, good, func(stage string, m *Manifest) {
			must(t, os.WriteFile(filepath.Join(stage, "nexus.db"), bytes.Repeat([]byte("junk"), 3000), 0o600))
			rehash(t, stage, m)
		}), nil, "database"},
		{"config unusable", rebuild(t, good, func(stage string, m *Manifest) {
			must(t, os.WriteFile(filepath.Join(stage, "nexus.yaml"), []byte("hub: [not, a, mapping"), 0o600))
			rehash(t, stage, m)
		}), nil, "configuration"},
		{"config with unknown keys (newer version)", rebuild(t, good, func(stage string, m *Manifest) {
			b, _ := os.ReadFile(filepath.Join(stage, "nexus.yaml"))
			must(t, os.WriteFile(filepath.Join(stage, "nexus.yaml"), append(b, "future_feature: true\n"...), 0o600))
			rehash(t, stage, m)
		}), nil, "configuration"},
		{"CA key does not match", rebuild(t, good, func(stage string, m *Manifest) {
			other := newHub(t)
			b, _ := os.ReadFile(filepath.Join(other.lay.TLSDir, "ca.key"))
			must(t, os.WriteFile(filepath.Join(stage, "tls", "ca.key"), b, 0o600))
			rehash(t, stage, m)
		}), nil, "CA"},
		{"secret key wrong size", rebuild(t, good, func(stage string, m *Manifest) {
			must(t, os.WriteFile(filepath.Join(stage, "secret.key"), []byte("short"), 0o600))
			rehash(t, stage, m)
		}), nil, "secret.key"},
		{"required member missing", rebuild(t, good, func(_ string, m *Manifest) {
			var keep []FileEntry
			for _, f := range m.Files {
				if f.Name != "secret.key" {
					keep = append(keep, f)
				}
			}
			m.Files = keep
		}), nil, "does not contain secret.key"},
		{"checksum mismatch", rebuild(t, good, func(_ string, m *Manifest) { m.Files[1].SHA256 = strings.Repeat("0", 64) }), nil, "checksum"},
		{"unknown member in manifest", rebuild(t, good, func(stage string, m *Manifest) {
			must(t, os.WriteFile(filepath.Join(stage, "admin.sock"), []byte("x"), 0o600))
			m.Files = append(m.Files, FileEntry{Name: "admin.sock"})
			rehash(t, stage, m)
		}), nil, "unknown file"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc := h.svc
			if tc.latest != nil {
				o := h.svc.o
				o.LatestSchema = tc.latest
				svc = New(o)
			}
			_, err := svc.Restore(bg, bytes.NewReader(tc.data), testPass)
			if err == nil {
				t.Fatal("restore succeeded")
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
			sameState(t, before, fileState(t, h.root, true))
		})
	}

	t.Run("schema too new is ErrTooNew", func(t *testing.T) {
		o := h.svc.o
		o.LatestSchema = func() int { return store.LatestSchemaVersion() - 1 }
		_, err := New(o).Restore(bg, bytes.NewReader(good), testPass)
		if !errors.Is(err, ErrTooNew) {
			t.Fatalf("err = %v, want ErrTooNew", err)
		}
	})
	t.Run("format newer is ErrUnsupportedFormat", func(t *testing.T) {
		data := rebuild(t, good, func(_ string, m *Manifest) { m.Format = 99 })
		if _, err := h.svc.Restore(bg, bytes.NewReader(data), testPass); !errors.Is(err, ErrUnsupportedFormat) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestRestoreRejectsForeignTarMembers(t *testing.T) {
	h := newHub(t)
	good := downloadBytes(t, h, testPass)
	before := fileState(t, h.root, true)

	build := func(extra func(tw *tar.Writer)) []byte {
		stage := t.TempDir()
		dec, err := Decrypt(bytes.NewReader(good), PassphraseKey(testPass, testKDF))
		must(t, err)
		m, err := readArchive(dec, readExtract, stage)
		must(t, err)
		var buf bytes.Buffer
		enc, err := Encrypt(&buf, PassphraseKey(testPass, testKDF))
		must(t, err)
		tw := tar.NewWriter(enc)
		mb := mustJSON(t, m)
		must(t, tw.WriteHeader(&tar.Header{Name: nameManifest, Size: int64(len(mb)), Mode: 0o600, Typeflag: tar.TypeReg}))
		_, _ = tw.Write(mb)
		extra(tw)
		for _, f := range m.Files {
			b, _ := os.ReadFile(filepath.Join(stage, filepath.FromSlash(f.Name)))
			must(t, tw.WriteHeader(&tar.Header{Name: f.Name, Size: int64(len(b)), Mode: 0o600, Typeflag: tar.TypeReg}))
			_, _ = tw.Write(b)
		}
		must(t, tw.Close())
		must(t, enc.Close())
		return buf.Bytes()
	}
	tests := map[string]func(tw *tar.Writer){
		"path traversal member": func(tw *tar.Writer) {
			must(t, tw.WriteHeader(&tar.Header{Name: "../../etc/cron.d/evil", Size: 1, Mode: 0o600, Typeflag: tar.TypeReg}))
			_, _ = tw.Write([]byte("x"))
		},
		"symlink member": func(tw *tar.Writer) {
			must(t, tw.WriteHeader(&tar.Header{Name: "nexus.db", Linkname: "/etc/shadow", Typeflag: tar.TypeSymlink}))
		},
		"admin socket": func(tw *tar.Writer) {
			must(t, tw.WriteHeader(&tar.Header{Name: "admin.sock", Size: 1, Mode: 0o600, Typeflag: tar.TypeReg}))
			_, _ = tw.Write([]byte("x"))
		},
	}
	for name, extra := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := h.svc.Restore(bg, bytes.NewReader(build(extra)), testPass)
			if err == nil {
				t.Fatal("restore succeeded")
			}
			sameState(t, before, fileState(t, h.root, true))
		})
	}
}

func TestInterruptedSwapRollsBack(t *testing.T) {
	h := newHub(t)
	data := downloadBytes(t, h, testPass)
	// Different content in the live files so that a half swap is visible.
	must(t, os.WriteFile(h.lay.ConfigPath, []byte("# live config\n"), 0o640))
	must(t, os.WriteFile(h.lay.Database+"-wal", []byte("wal"), 0o600))
	must(t, h.st.Close())
	before := fileState(t, h.root, true)

	succeeded := false
	for n := 1; n <= 60 && !succeeded; n++ {
		calls := 0
		o := h.svc.o
		svc := New(o)
		svc.rename = func(oldp, newp string) error {
			calls++
			if calls == n {
				return errors.New("injected rename failure")
			}
			return os.Rename(oldp, newp)
		}
		_, err := svc.Restore(bg, bytes.NewReader(data), testPass)
		if err == nil {
			succeeded = true
			if calls >= n {
				t.Fatalf("n=%d: restore succeeded although rename #%d was meant to fail", n, n)
			}
			break
		}
		if !strings.Contains(err.Error(), "injected") {
			t.Fatalf("n=%d: err = %v", n, err)
		}
		sameState(t, before, fileState(t, h.root, true))
		if t.Failed() {
			t.Fatalf("state changed after a failure at rename #%d", n)
		}
	}
	if !succeeded {
		t.Fatal("the restore never succeeded; the loop bound is too small")
	}
	// After the successful run (no injection) the live config is replaced.
	if b, _ := os.ReadFile(h.lay.ConfigPath); strings.Contains(string(b), "live config") {
		t.Error("restore did not replace the config")
	}
}

func TestInterruptedPrepareLeavesOriginal(t *testing.T) {
	h := newHub(t)
	data := downloadBytes(t, h, testPass)
	must(t, h.st.Close())
	// A directory where the staged copy of the secret key would go: copying fails.
	must(t, os.MkdirAll(filepath.Join(h.lay.SecretKey+restoreNewSuffix, "x"), 0o700))
	before := fileState(t, h.root, true)
	if _, err := h.svc.Restore(bg, bytes.NewReader(data), testPass); err == nil {
		t.Fatal("restore succeeded")
	}
	after := fileState(t, h.root, true)
	sameState(t, before, after)
}

func TestRestoreCancelledBeforeSwap(t *testing.T) {
	h := newHub(t)
	data := downloadBytes(t, h, testPass)
	must(t, h.st.Close())
	before := fileState(t, h.root, true)
	ctx, cancel := context.WithCancel(bg)
	cancel()
	if _, err := h.svc.Restore(ctx, bytes.NewReader(data), testPass); err == nil {
		t.Fatal("restore succeeded with a cancelled context")
	}
	sameState(t, before, fileState(t, h.root, true))
}

func TestInspect(t *testing.T) {
	h := newHub(t)
	data := downloadBytes(t, h, testPass)
	m, err := h.svc.Inspect(bg, bytes.NewReader(data), testPass)
	if err != nil {
		t.Fatal(err)
	}
	if m.Format != ArchiveVersion || m.HubName != "frpi5" || m.SchemaVersion != store.LatestSchemaVersion() || m.CreatedAt.IsZero() {
		t.Errorf("manifest = %+v", m)
	}
	names := map[string]bool{}
	for _, f := range m.Files {
		names[f.Name] = true
		if len(f.SHA256) != 64 || f.Size <= 0 {
			t.Errorf("bad entry %+v", f)
		}
	}
	for _, mem := range members {
		if !names[mem.name] {
			t.Errorf("%s missing from the backup", mem.name)
		}
	}
	if _, err := h.svc.Inspect(bg, bytes.NewReader(data), "not the passphrase"); !errors.Is(err, ErrAuth) {
		t.Errorf("wrong passphrase: %v", err)
	}
	if _, err := h.svc.Inspect(bg, bytes.NewReader(data[:len(data)-1]), testPass); !errors.Is(err, ErrCorrupt) {
		t.Errorf("truncated: %v", err)
	}
	// File based, local backup needs no passphrase.
	info, err := h.svc.CreateLocal(bg, ReasonManual)
	must(t, err)
	if m, err := h.svc.InspectFile(bg, info.Path, ""); err != nil || m.Reason != ReasonManual {
		t.Errorf("InspectFile(local) = %+v, %v", m, err)
	}
	dl := filepath.Join(t.TempDir(), "dl.nxbk")
	must(t, os.WriteFile(dl, data, 0o600))
	if _, err := h.svc.InspectFile(bg, dl, ""); !errors.Is(err, ErrPassphraseRequired) {
		t.Errorf("InspectFile without passphrase: %v", err)
	}
	if m, err := h.svc.InspectFile(bg, dl, testPass); err != nil || m.Reason != ReasonDownload {
		t.Errorf("InspectFile = %+v, %v", m, err)
	}
}

func TestWriteDownloadPolicyAndEarlyFailure(t *testing.T) {
	tests := []struct {
		name string
		pass string
		prep func(h *testHub)
		want string
	}{
		{"too short", "short", nil, "policy"},
		{"eleven characters", "elevenchars", nil, "policy"},
		{"empty", "", nil, "policy"},
		{"snapshot fails", testPass, func(h *testHub) {
			o := h.svc.o
			o.Snapshot = func(context.Context, string) error { return errors.New("disk full") }
			h.svc = New(o)
		}, "disk full"},
		{"required file missing", testPass, func(h *testHub) { must(t, os.Remove(h.lay.SecretKey)) }, "secret.key"},
		{"ca key missing", testPass, func(h *testHub) { must(t, os.Remove(filepath.Join(h.lay.TLSDir, "ca.key"))) }, "ca.key"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHub(t)
			if tc.prep != nil {
				tc.prep(h)
			}
			var buf bytes.Buffer
			err := h.svc.WriteDownload(bg, &buf, tc.pass)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if buf.Len() != 0 {
				t.Errorf("%d bytes were written before the failure", buf.Len())
			}
			assertNoLeftovers(t, h)
		})
	}
	h := newHub(t)
	if err := h.svc.WriteDownload(bg, &bytes.Buffer{}, "short"); !errors.Is(err, auth.ErrWeakPassphrase) {
		t.Errorf("err = %v, want ErrWeakPassphrase", err)
	}
}

func TestAuditEntries(t *testing.T) {
	h := newHub(t)
	ctx := WithActor(bg, "alice")
	info, err := h.svc.CreateLocal(ctx, ReasonPreUpdate)
	must(t, err)
	var buf bytes.Buffer
	must(t, h.svc.WriteDownload(ctx, &buf, testPass))
	if err := h.svc.WriteDownload(ctx, &buf, "short"); err == nil {
		t.Fatal("weak passphrase accepted")
	}
	_, err = h.svc.CreateLocal(bg, "Bad Reason!")
	if err == nil {
		t.Fatal("invalid reason accepted")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.audits) != 3 {
		t.Fatalf("audit entries = %+v", h.audits)
	}
	c, d, f := h.audits[0], h.audits[1], h.audits[2]
	if c.Action != ActionCreate || c.User != "alice" || c.Result != store.AuditOK || !strings.Contains(c.Detail, "pre-update") || !strings.Contains(c.Detail, info.Name) {
		t.Errorf("create entry = %+v", c)
	}
	if d.Action != ActionDownload || d.Result != store.AuditOK {
		t.Errorf("download entry = %+v", d)
	}
	if f.Action != ActionDownload || f.Result != store.AuditError {
		t.Errorf("failed download entry = %+v", f)
	}
	for _, e := range h.audits {
		if strings.Contains(e.Detail, testPass) || strings.Contains(e.Detail, "short") && e.Action == ActionCreate {
			t.Errorf("secret in audit detail: %q", e.Detail)
		}
	}
}

func TestLocalBackupFilesAndList(t *testing.T) {
	h := newHub(t)
	var names []string
	for _, reason := range []string{ReasonNightly, ReasonManual, ReasonPreUpdate} {
		h.clock.Add(time.Hour)
		in, err := h.svc.CreateLocal(bg, reason)
		must(t, err)
		names = append(names, in.Name)
	}
	// Same second, same reason: a second file, not an overwrite.
	a, err := h.svc.CreateLocal(bg, ReasonPreUpdate)
	must(t, err)
	b, err := h.svc.CreateLocal(bg, ReasonPreUpdate)
	must(t, err)
	if a.Name == b.Name {
		t.Fatalf("both backups are named %s", a.Name)
	}
	// Junk in the directory is ignored.
	must(t, os.WriteFile(filepath.Join(h.lay.BackupDir, "notes.txt"), []byte("x"), 0o600))
	must(t, os.WriteFile(filepath.Join(h.lay.BackupDir, "nexus-20200101T000000Z-nightly.nxbk.tmp"), []byte("x"), 0o600))

	list, err := h.svc.List(bg)
	must(t, err)
	if len(list) != 5 {
		t.Fatalf("list = %+v", list)
	}
	if list[0].Name != b.Name && list[0].Name != a.Name {
		t.Errorf("newest first expected, got %s", list[0].Name)
	}
	for i := 1; i < len(list); i++ {
		if list[i].CreatedAt.After(list[i-1].CreatedAt) {
			t.Errorf("not sorted newest first: %v", list)
		}
	}
	for _, in := range list {
		if !in.Readable || in.HubVersion != "0.2.0-test" || in.Size <= 0 || in.CreatedAt.Location() != time.UTC {
			t.Errorf("info = %+v", in)
		}
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(h.lay.BackupDir); fi.Mode().Perm() != 0o700 {
			t.Errorf("backup dir mode %v", fi.Mode().Perm())
		}
		for _, in := range list {
			if fi, _ := os.Stat(in.Path); fi.Mode().Perm() != 0o600 {
				t.Errorf("%s mode %v", in.Name, fi.Mode().Perm())
			}
		}
	}

	// A backup made with another hub's secret.key is listed but unreadable.
	other := newHub(t)
	in, err := other.svc.CreateLocal(bg, ReasonNightly)
	must(t, err)
	b2, _ := os.ReadFile(in.Path)
	foreign := "nexus-20260101T000000Z-nightly.nxbk"
	must(t, os.WriteFile(filepath.Join(h.lay.BackupDir, foreign), b2, 0o600))
	list, err = h.svc.List(bg)
	must(t, err)
	found := false
	for _, in := range list {
		if in.Name == foreign {
			found = true
			if in.Readable || in.HubVersion != "" {
				t.Errorf("foreign backup = %+v", in)
			}
		}
	}
	if !found {
		t.Error("foreign backup not listed")
	}
	if _, err := h.svc.RestoreLocal(bg, foreign); !errors.Is(err, ErrAuth) {
		t.Errorf("restoring a foreign local backup: %v", err)
	}
	if _, err := h.svc.RestoreLocal(bg, "../../etc/passwd"); err == nil {
		t.Error("path in name accepted")
	}
	if list, err := newTarget(t).svc.List(bg); err != nil || len(list) != 0 {
		t.Errorf("List without a backup dir = %v, %v", list, err)
	}
}

func TestRetention(t *testing.T) {
	h := newHub(t)
	for i := 0; i < 10; i++ {
		h.clock.Add(time.Hour)
		_, err := h.svc.CreateLocal(bg, ReasonNightly)
		must(t, err)
	}
	removed, err := h.svc.Prune(bg, 7)
	must(t, err)
	if len(removed) != 3 {
		t.Fatalf("removed %v", removed)
	}
	list, _ := h.svc.List(bg)
	if len(list) != 7 {
		t.Fatalf("%d left", len(list))
	}
	// The newest seven survive.
	if want := t0.Add(10 * time.Hour); !list[0].CreatedAt.Equal(want) {
		t.Errorf("newest = %v, want %v", list[0].CreatedAt, want)
	}
	if want := t0.Add(4 * time.Hour); !list[6].CreatedAt.Equal(want) {
		t.Errorf("oldest = %v, want %v", list[6].CreatedAt, want)
	}
	if removed, err := h.svc.Prune(bg, 7); err != nil || len(removed) != 0 {
		t.Errorf("second prune = %v, %v", removed, err)
	}
	if removed, err := h.svc.Prune(bg, 0); err != nil || len(removed) != 0 {
		t.Errorf("keep 0 must delete nothing: %v, %v", removed, err)
	}

	// CreateAndPrune follows backup.keep, default 7.
	h.clock.Add(time.Hour)
	if _, err := h.svc.CreateAndPrune(bg, ReasonNightly); err != nil {
		t.Fatal(err)
	}
	if list, _ := h.svc.List(bg); len(list) != 7 {
		t.Errorf("default keep: %d left, want 7", len(list))
	}
	must(t, h.svc.SetSchedule(bg, Schedule{Time: "04:30", Keep: 3}))
	h.clock.Add(time.Hour)
	if _, err := h.svc.CreateAndPrune(bg, ReasonNightly); err != nil {
		t.Fatal(err)
	}
	if list, _ := h.svc.List(bg); len(list) != 3 {
		t.Errorf("keep 3: %d left", len(list))
	}
}

func TestStaleStagingIsCleaned(t *testing.T) {
	h := newHub(t)
	must(t, os.MkdirAll(h.lay.BackupDir, 0o700))
	oldDir := filepath.Join(h.lay.BackupDir, ".staging-old")
	newDir := filepath.Join(h.lay.BackupDir, ".staging-new")
	oldTmp := filepath.Join(h.lay.BackupDir, "nexus-20200101T000000Z-nightly.nxbk.tmp")
	for _, p := range []string{oldDir, newDir} {
		must(t, os.MkdirAll(p, 0o700))
	}
	must(t, os.WriteFile(oldTmp, []byte("x"), 0o600))
	old := h.clock.Now().Add(-2 * time.Hour)
	for _, p := range []string{oldDir, oldTmp} {
		must(t, os.Chtimes(p, old, old))
	}
	// The fake clock is in the past relative to real file times: use the
	// service clock as "now" and file times relative to it.
	must(t, os.Chtimes(newDir, h.clock.Now(), h.clock.Now()))
	_, err := h.svc.CreateLocal(bg, ReasonManual)
	must(t, err)
	for _, p := range []string{oldDir, oldTmp} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s was not removed", p)
		}
	}
	if _, err := os.Stat(newDir); err != nil {
		t.Errorf("a fresh staging directory (another running backup) was removed")
	}
}

func TestScheduleSettings(t *testing.T) {
	tests := []struct {
		name string
		set  map[string]string
		want Schedule
	}{
		{"defaults", nil, Schedule{"03:00", 7}},
		{"custom", map[string]string{SettingTime: "04:15", SettingKeep: "14"}, Schedule{"04:15", 14}},
		{"invalid time", map[string]string{SettingTime: "25:00", SettingKeep: "5"}, Schedule{"03:00", 5}},
		{"invalid keep", map[string]string{SettingTime: "01:00", SettingKeep: "0"}, Schedule{"01:00", 7}},
		{"garbage keep", map[string]string{SettingKeep: "many"}, Schedule{"03:00", 7}},
		{"too many", map[string]string{SettingKeep: "100000"}, Schedule{"03:00", 7}},
		{"whitespace", map[string]string{SettingTime: " 02:00 "}, Schedule{"02:00", 7}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc := New(Options{Settings: &memSettings{m: tc.set}})
			if got := svc.Schedule(bg); got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
	if got := New(Options{}).Schedule(bg); got != (Schedule{"03:00", 7}) {
		t.Errorf("no settings store: %+v", got)
	}

	svc := New(Options{Settings: &memSettings{}})
	for _, bad := range []Schedule{{"3:00", 7}, {"24:00", 7}, {"03:60", 7}, {"03:00", 0}, {"03:00", 101}, {"", 7}} {
		if err := svc.SetSchedule(bg, bad); err == nil {
			t.Errorf("SetSchedule(%+v) accepted", bad)
		}
	}
	must(t, svc.SetSchedule(bg, Schedule{"23:59", 30}))
	if got := svc.Schedule(bg); got != (Schedule{"23:59", 30}) {
		t.Errorf("after set: %+v", got)
	}
}

func TestDownloadName(t *testing.T) {
	h := newHub(t)
	if got, want := h.svc.DownloadName(), "nexus-backup-frpi5-20261002-010000.nxbk"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBackupContainsOnlyWhitelistedFiles(t *testing.T) {
	h := newHub(t)
	// Runtime state next to the data must not travel with the backup.
	must(t, os.WriteFile(filepath.Join(filepath.Dir(h.lay.Database), "self-enroll.token"), []byte("tok"), 0o640))
	must(t, os.WriteFile(filepath.Join(filepath.Dir(h.lay.Database), "admin.sock"), []byte("sock"), 0o600))
	data := downloadBytes(t, h, testPass)
	m, err := h.svc.Inspect(bg, bytes.NewReader(data), testPass)
	must(t, err)
	for _, f := range m.Files {
		if _, ok := memberByName(f.Name); !ok {
			t.Errorf("unexpected member %s", f.Name)
		}
	}
	dec, _ := Decrypt(bytes.NewReader(data), PassphraseKey(testPass, testKDF))
	tr := tar.NewReader(dec)
	n := 0
	for {
		hd, err := tr.Next()
		if err != nil {
			break
		}
		n++
		if strings.Contains(hd.Name, "token") || strings.Contains(hd.Name, "sock") || strings.Contains(hd.Name, "backups") {
			t.Errorf("runtime state in archive: %s", hd.Name)
		}
	}
	if n != len(m.Files)+1 {
		t.Errorf("%d tar members, manifest lists %d files", n, len(m.Files))
	}
}

func TestWriteDownloadStopsWhenContextEnds(t *testing.T) {
	h := newHub(t)
	ctx, cancel := context.WithCancel(bg)
	cancel()
	var buf bytes.Buffer
	if err := h.svc.WriteDownload(ctx, &buf, testPass); err == nil {
		t.Fatal("download with a cancelled context succeeded")
	}
	assertNoLeftovers(t, h)
}
