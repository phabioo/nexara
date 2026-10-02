package backup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/phabioo/nexara/internal/config"
	"github.com/phabioo/nexara/internal/hub/auth"
	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/pki"
)

// Cheap argon2id parameters for tests; production uses DefaultKDF.
var testKDF = KDFParams{Time: 1, MemoryKiB: 64, Threads: 1}

const testPass = "correct horse battery staple"

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type memSettings struct {
	mu sync.Mutex
	m  map[string]string
}

func (s *memSettings) Get(_ context.Context, k string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[k]
	return v, ok, nil
}

func (s *memSettings) Set(_ context.Context, k, v string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string]string{}
	}
	s.m[k] = v
	return nil
}

// testHub is a complete hub file layout with a real database.
type testHub struct {
	t      *testing.T
	root   string
	lay    Layout
	st     *store.Store
	svc    *Service
	clock  *fakeClock
	set    *memSettings
	mu     sync.Mutex
	audits []store.AuditEntry
	// auditedRestore collects AuditRestore calls (db path).
	restoreAudits []string
}

var t0 = time.Date(2026, 10, 2, 1, 0, 0, 0, time.UTC)

func newHub(t *testing.T) *testHub {
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
	for _, d := range []string{filepath.Dir(h.lay.ConfigPath), filepath.Dir(h.lay.Database)} {
		must(t, os.MkdirAll(d, 0o750))
	}
	cfg := config.DefaultHub()
	cfg.Hub.Name = "frpi5"
	cfg.Hub.AgentAddress = "frpi5.local"
	cfg.Storage.Database = h.lay.Database
	cfg.TLS.Dir = h.lay.TLSDir
	must(t, config.SaveHub(h.lay.ConfigPath, cfg))

	var err error
	h.st, err = store.Open(h.lay.Database)
	must(t, err)
	t.Cleanup(func() { _ = h.st.Close() })
	ctx := context.Background()
	if _, err := h.st.CreateUser(ctx, store.User{OperatorID: "alice", PassHash: "hash"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.st.AppendAudit(ctx, store.AuditEntry{User: "alice", Action: "login", Result: store.AuditOK, Time: t0}); err != nil {
		t.Fatal(err)
	}

	_, err = auth.LoadOrCreateSecretKey(h.lay.SecretKey)
	must(t, err)
	ca, err := pki.LoadOrCreateCA(h.lay.TLSDir, "frpi5.local")
	must(t, err)
	_, err = pki.EnsureServerCert(ca, h.lay.TLSDir, []string{"frpi5.local"}, nil, time.Now())
	must(t, err)
	writeSSHKey(t, h.lay.SSHKey)

	h.svc = New(Options{
		Layout:   h.lay,
		Snapshot: h.st.Snapshot,
		Settings: h.set,
		Audit: func(_ context.Context, e store.AuditEntry) {
			h.mu.Lock()
			h.audits = append(h.audits, e)
			h.mu.Unlock()
		},
		AuditRestore: func(_ context.Context, db string, _ store.AuditEntry) error {
			h.mu.Lock()
			h.restoreAudits = append(h.restoreAudits, db)
			h.mu.Unlock()
			return nil
		},
		HubName: "frpi5", HubVersion: "0.2.0-test",
		KDF: testKDF, Now: h.clock.Now,
	})
	return h
}

func writeSSHKey(t *testing.T, path string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	must(t, err)
	blk, err := ssh.MarshalPrivateKey(priv, "nexus@test")
	must(t, err)
	must(t, os.MkdirAll(filepath.Dir(path), 0o700))
	must(t, os.WriteFile(path, pem.EncodeToMemory(blk), 0o600))
}

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// fileState maps relative path to content for every file below dir. The
// backups directory is skipped unless withBackups is set.
func fileState(t *testing.T, dir string, withBackups bool) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		if d.IsDir() {
			if !withBackups && d.Name() == BackupDirName {
				return filepath.SkipDir
			}
			out[rel+"/"] = ""
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		out[rel] = string(b)
		return nil
	})
	must(t, err)
	return out
}

func sameState(t *testing.T, a, b map[string]string) {
	t.Helper()
	var keys []string
	for k := range a {
		keys = append(keys, k)
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		av, aok := a[k]
		bv, bok := b[k]
		if aok != bok {
			t.Errorf("%s: present before=%v after=%v", k, aok, bok)
		} else if av != bv {
			t.Errorf("%s: content differs", k)
		}
	}
}

// dbContent returns a comparable dump of users and audit entries.
func dbContent(t *testing.T, path string) (users []string, audits []string) {
	t.Helper()
	st, err := store.Open(path)
	must(t, err)
	defer st.Close()
	ctx := context.Background()
	for _, id := range []string{"alice", "bob", "carol", "mallory"} {
		if u, err := st.GetUserByOperatorID(ctx, id); err == nil {
			users = append(users, u.OperatorID+":"+u.PassHash)
		}
	}
	es, err := st.ListAudit(ctx, 100)
	must(t, err)
	for _, e := range es {
		audits = append(audits, e.User+"/"+e.Action+"/"+e.Detail)
	}
	return users, audits
}

// downloadBytes makes a passphrase backup of h.
func downloadBytes(t *testing.T, h *testHub, pass string) []byte {
	t.Helper()
	var buf bytes.Buffer
	must(t, h.svc.WriteDownload(context.Background(), &buf, pass))
	return buf.Bytes()
}

// rebuild decrypts a passphrase backup, lets mutate change the staged files
// and the manifest, and encrypts the result again (valid envelope, valid
// hashes unless mutate breaks them on purpose).
func rebuild(t *testing.T, data []byte, mutate func(stage string, m *Manifest)) []byte {
	t.Helper()
	stage := t.TempDir()
	dec, err := Decrypt(bytes.NewReader(data), PassphraseKey(testPass, testKDF))
	must(t, err)
	m, err := readArchive(dec, readExtract, stage)
	must(t, err)
	mutate(stage, &m)
	var buf bytes.Buffer
	enc, err := Encrypt(&buf, PassphraseKey(testPass, testKDF))
	must(t, err)
	must(t, writeArchive(enc, stage, m))
	must(t, enc.Close())
	return buf.Bytes()
}

// rehash recomputes size and hash of every manifest file from stage.
func rehash(t *testing.T, stage string, m *Manifest) {
	t.Helper()
	for i, f := range m.Files {
		size, sum, err := hashFile(filepath.Join(stage, filepath.FromSlash(f.Name)))
		must(t, err)
		m.Files[i].Size, m.Files[i].SHA256 = size, sum
	}
}

type countingWriter struct{ n int64 }

func (c *countingWriter) Write(p []byte) (int, error) { c.n += int64(len(p)); return len(p), nil }

var _ io.Writer = (*countingWriter)(nil)

func mustJSON(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	must(t, err)
	return b
}
