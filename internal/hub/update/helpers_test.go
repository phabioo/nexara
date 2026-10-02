package update

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/store"
)

// testBundle is a signed release as the CI would publish it, with a fake .deb.
type testBundle struct {
	version string
	arch    string
	debName string
	deb     []byte
	sums    []byte
	sig     []byte
}

type keyPair struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newKey(t testing.TB) keyPair {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return keyPair{pub, priv}
}

func sumLine(name string, data []byte) string {
	d := sha256.Sum256(data)
	return hex.EncodeToString(d[:]) + "  " + name + "\n"
}

// makeBundle builds the three release files. SHA256SUMS also lists unrelated
// assets, like the real one.
func makeBundle(t testing.TB, k keyPair, version, arch string) testBundle {
	t.Helper()
	name := DebName(version, arch)
	deb := []byte("!<arch>\nfake nexus package " + version + " " + arch + "\n")
	sums := []byte(sumLine("install.sh", []byte("#!/bin/sh\n")) + sumLine(name, deb))
	return testBundle{version: version, arch: arch, debName: name, deb: deb, sums: sums, sig: ed25519.Sign(k.priv, sums)}
}

func (b testBundle) input() StageInput {
	return StageInput{DebName: b.debName, Deb: bytes.NewReader(b.deb), Sums: bytes.NewReader(b.sums), Sig: bytes.NewReader(b.sig)}
}

// writeStaged puts the bundle into dir/<version>/ the way the hub does.
func (b testBundle) writeStaged(t testing.TB, updatesDir string) string {
	t.Helper()
	dir := filepath.Join(updatesDir, b.version)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	b.writeFiles(t, dir, 0o600)
	return dir
}

func (b testBundle) writeFiles(t testing.TB, dir string, mode os.FileMode) {
	t.Helper()
	for name, data := range map[string][]byte{b.debName: b.deb, SumsFile: b.sums, SigFile: b.sig} {
		if err := os.WriteFile(filepath.Join(dir, name), data, mode); err != nil {
			t.Fatal(err)
		}
	}
}

type tarEntry struct {
	name     string
	data     []byte
	typeflag byte
	link     string
}

func makeTar(t testing.TB, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		flag := e.typeflag
		if flag == 0 {
			flag = tar.TypeReg
		}
		hdr := &tar.Header{Name: e.name, Typeflag: flag, Mode: 0o644, Linkname: e.link}
		if flag == tar.TypeReg {
			hdr.Size = int64(len(e.data))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if flag == tar.TypeReg {
			if _, err := tw.Write(e.data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func (b testBundle) tarEntries() []tarEntry {
	return []tarEntry{{name: b.debName, data: b.deb}, {name: SumsFile, data: b.sums}, {name: SigFile, data: b.sig}}
}

// fakeClock is a settable clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock { return &fakeClock{t: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// auditLog collects audit entries.
type auditLog struct {
	mu      sync.Mutex
	entries []store.AuditEntry
}

func (a *auditLog) add(_ context.Context, e store.AuditEntry) {
	a.mu.Lock()
	a.entries = append(a.entries, e)
	a.mu.Unlock()
}

func (a *auditLog) all() []store.AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]store.AuditEntry(nil), a.entries...)
}

func (a *auditLog) actions() []string {
	var out []string
	for _, e := range a.all() {
		out = append(out, e.Action+":"+e.Result)
	}
	return out
}

// svcEnv is a Service with a temp directory, a test key and a clock.
type svcEnv struct {
	svc      *Service
	dir      string
	key      keyPair
	clock    *fakeClock
	audit    *auditLog
	settings *MemorySettings
}

func newSvcEnv(t testing.TB, mod func(*Options)) *svcEnv {
	t.Helper()
	e := &svcEnv{key: newKey(t), clock: newClock(), audit: &auditLog{}, settings: NewMemorySettings()}
	e.dir = filepath.Join(t.TempDir(), "updates")
	o := Options{
		Dir: e.dir, Settings: e.settings, Audit: e.audit.add, Now: e.clock.Now,
		CurrentVersion: "0.1.0", Arch: "arm64", HelperWatches: true, Key: e.key.pub,
	}
	if mod != nil {
		mod(&o)
	}
	svc, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
	return e
}

func (e *svcEnv) set(t testing.TB, key, val string) {
	t.Helper()
	if err := e.settings.Set(context.Background(), key, val); err != nil {
		t.Fatal(err)
	}
}

func lowerMaxDeb(t *testing.T, n int64) {
	t.Helper()
	old := maxDeb
	maxDeb = n
	t.Cleanup(func() { maxDeb = old })
}

func listNames(t testing.TB, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}

func readAll(t testing.TB, r io.Reader) string {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func contains(s string, subs ...string) bool {
	for _, x := range subs {
		if !strings.Contains(s, x) {
			return false
		}
	}
	return true
}
