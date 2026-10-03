package httpserver

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/config"
	"github.com/phabioo/nexara/internal/hub/auth"
	"github.com/phabioo/nexara/internal/hub/backup"
	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/hub/update"
	"github.com/phabioo/nexara/internal/hub/views"
	"github.com/phabioo/nexara/internal/pki"
	"github.com/phabioo/nexara/internal/protocol"
	"github.com/phabioo/nexara/web"
)

// stgHub is the shared fake hub plus the removal of hosts, which Settings uses.
type stgHub struct {
	*fakeHub
	mu      sync.Mutex
	removed []grid.HostID
	rmErr   error
}

func (h *stgHub) RemoveHost(_ context.Context, _ grid.Actor, id grid.HostID) error {
	h.mu.Lock()
	h.removed = append(h.removed, id)
	err := h.rmErr
	h.mu.Unlock()
	if err != nil {
		return err
	}
	h.fakeHub.mu.Lock()
	defer h.fakeHub.mu.Unlock()
	h.fakeHub.hosts = slices.DeleteFunc(h.fakeHub.hosts, func(x grid.HostInfo) bool { return x.ID == id })
	return nil
}

// stgCaps is a CapabilityController that changes the fake hub like the grid does.
type stgCaps struct {
	hub   *fakeHub
	mu    sync.Mutex
	calls []string
	actor grid.Actor
	err   error
}

func (c *stgCaps) SetCapability(_ context.Context, actor grid.Actor, id grid.HostID, capability string, enabled bool) error {
	c.mu.Lock()
	c.calls = append(c.calls, string(id)+"/"+capability+"/"+map[bool]string{true: "on", false: "off"}[enabled])
	c.actor = actor
	err := c.err
	c.mu.Unlock()
	if err != nil {
		return err
	}
	c.hub.mu.Lock()
	defer c.hub.mu.Unlock()
	for i, h := range c.hub.hosts {
		if h.ID != id {
			continue
		}
		on, off := h.Capabilities, h.DisabledCapabilities
		if !slices.Contains(on, capability) && !slices.Contains(off, capability) {
			return grid.ErrUnsupported
		}
		on = slices.DeleteFunc(slices.Clone(on), func(x string) bool { return x == capability })
		off = slices.DeleteFunc(slices.Clone(off), func(x string) bool { return x == capability })
		if enabled {
			on = append(on, capability)
		} else {
			off = append(off, capability)
		}
		c.hub.hosts[i].Capabilities, c.hub.hosts[i].DisabledCapabilities = on, off
		return nil
	}
	return grid.ErrHostNotFound
}

func (c *stgCaps) recorded() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.calls)
}

// stgCerts is a CertRenewer.
type stgCerts struct {
	mu    sync.Mutex
	calls []grid.HostID
	err   error
}

func (c *stgCerts) RenewCert(_ context.Context, _ grid.Actor, id grid.HostID) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, id)
	return c.err
}

// stgLogs is a LogSource.
type stgLogs struct{ recs []LogRecord }

func (l stgLogs) Records() []LogRecord { return l.recs }

// stgGitHub serves the two GitHub endpoints the update check uses.
type stgGitHub struct {
	srv      *httptest.Server
	releases []map[string]any
	files    map[string]map[string][]byte // tag -> asset -> content
	status   int                          // answer of the API when not 0
}

func newStgGitHub(t *testing.T) *stgGitHub {
	g := &stgGitHub{files: map[string]map[string][]byte{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/phabioo/nexara/releases", func(w http.ResponseWriter, r *http.Request) {
		if g.status != 0 {
			http.Error(w, "no", g.status)
			return
		}
		_ = json.NewEncoder(w).Encode(g.releases)
	})
	mux.HandleFunc("/phabioo/nexara/releases/download/", func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/phabioo/nexara/releases/download/")
		tag, asset, _ := strings.Cut(rest, "/")
		data, ok := g.files[tag][asset]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(data)
	})
	g.srv = httptest.NewTLSServer(mux)
	t.Cleanup(g.srv.Close)
	return g
}

// publish adds a release with the bundle's files.
func (g *stgGitHub) publish(version string, b stgBundle) {
	var assets []map[string]any
	for _, n := range []string{b.debName, update.SumsFile, update.SigFile} {
		assets = append(assets, map[string]any{"name": n})
	}
	g.releases = append(g.releases, map[string]any{
		"tag_name": "v" + version, "draft": false, "prerelease": false, "body": "notes",
		"published_at": "2026-10-01T10:00:00Z", "assets": assets,
	})
	g.files["v"+version] = map[string][]byte{b.debName: b.deb, update.SumsFile: b.sums, update.SigFile: b.sigb}
}

// settingsEnv is the test environment of Settings: real update and backup services in temporary directories, fakes
// for the grid.
type settingsEnv struct {
	*env
	hub      *stgHub
	caps     *stgCaps
	certs    *stgCerts
	upd      *update.Service
	gh       *stgGitHub
	updClock *offsetClock
	updDir   string
	updKey   ed25519.PrivateKey
	bk       *backup.Service
	lay      backup.Layout
	restarts int
	cookie   *http.Cookie
	csrf     string
}

func newSettingsEnv(t *testing.T, mods ...func(*update.Options)) *settingsEnv {
	t.Helper()
	e := newEnv(t)
	r, err := views.New(web.Templates, views.Options{})
	if err != nil {
		t.Fatal(err)
	}
	e.srv.renderer = r
	se := &settingsEnv{env: e}
	se.hub = &stgHub{fakeHub: e.hub}
	e.srv.hub = se.hub
	now := time.Now()
	e.hub.mu.Lock()
	e.hub.hosts[0].AgentVersion = "0.1.0"
	e.hub.hosts[0].Capabilities = []string{protocol.CapMonitoring, protocol.CapServices, protocol.CapShell, protocol.CapPackages}
	e.hub.hosts[0].CertNotAfter = now.Add(200 * 24 * time.Hour)
	e.hub.hosts[1].AgentVersion = "0.0.9"
	e.hub.hosts[1].Capabilities = []string{protocol.CapMonitoring, protocol.CapShell}
	e.hub.hosts[1].CertNotAfter = now.Add(10 * 24 * time.Hour)
	e.hub.mu.Unlock()
	se.caps = &stgCaps{hub: e.hub}
	se.certs = &stgCerts{}

	ca, err := pki.LoadOrCreateCA(t.TempDir(), "frpi5.local", "frpi5")
	if err != nil {
		t.Fatal(err)
	}
	tlsDir := t.TempDir()
	if _, err := pki.EnsureServerCert(ca, tlsDir, []string{"frpi5", "frpi5.local"}, []net.IP{net.ParseIP("192.168.10.21")}, now); err != nil {
		t.Fatal(err)
	}
	pem, err := os.ReadFile(filepath.Join(tlsDir, pki.ServerCertFile))
	if err != nil {
		t.Fatal(err)
	}
	server, err := pki.ParseCertPEM(pem)
	if err != nil {
		t.Fatal(err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	se.updKey = priv
	se.updDir = filepath.Join(t.TempDir(), "updates")
	audit := func(ctx context.Context, a store.AuditEntry) { _, _ = e.st.AppendAudit(ctx, a) }
	se.gh = newStgGitHub(t)
	se.updClock = &offsetClock{}
	uo := update.Options{
		Dir: se.updDir, Settings: update.NewMemorySettings(), Audit: audit, Now: se.updClock.Now,
		CurrentVersion: "0.1.0", Arch: "arm64", HelperWatches: true, Key: pub,
		HTTPClient: se.gh.srv.Client(), APIBase: se.gh.srv.URL, DownloadBase: se.gh.srv.URL, AllowedHosts: []string{"127.0.0.1"},
	}
	for _, m := range mods {
		m(&uo)
	}
	se.upd, err = update.New(uo)
	if err != nil {
		t.Fatal(err)
	}

	se.lay = stgBackupLayout(t, e.st)
	se.bk = backup.New(backup.Options{
		Layout: se.lay, Snapshot: e.st.Snapshot, Settings: update.NewMemorySettings(), Audit: audit,
		HubName: "frpi5", HubVersion: "0.1.0", KDF: backup.KDFParams{Time: 1, MemoryKiB: 64, Threads: 1},
		AuditRestore: func(context.Context, string, store.AuditEntry) error { return nil },
	})
	e.srv.svc = Services{
		Updates: se.upd, Backup: se.bk, Certs: se.certs, Caps: se.caps, Store: e.st, CA: ca,
		Restart:    func() { se.restarts++ },
		ServerCert: func() (*x509.Certificate, error) { return server, nil },
		// Newest first, as a LogSource returns them.
		Logs: stgLogs{recs: []LogRecord{
			{Time: now, Level: 8, Text: "audit write failed"},
			{Time: now.Add(-1 * time.Minute), Level: 4, Text: "certificate <b>expires</b> soon"},
			{Time: now.Add(-2 * time.Minute), Level: 0, Text: "agent connected host=alpha"},
			{Time: now.Add(-3 * time.Minute), Level: -4, Text: "debug detail"},
		}},
		HubHost: func(h grid.HostInfo) bool { return h.Name == "alpha" },
	}
	se.cookie, se.csrf = e.signIn()
	return se
}

// stgBackupLayout creates the files a backup holds, in a temporary directory, with the database at the path of the
// store.
func stgBackupLayout(t *testing.T, st *store.Store) backup.Layout {
	t.Helper()
	root := t.TempDir()
	lay := backup.Layout{
		ConfigPath: filepath.Join(root, "etc", "nexus.yaml"),
		Database:   filepath.Join(root, "var", "nexus.db"),
		TLSDir:     filepath.Join(root, "var", "pki"),
		SecretKey:  filepath.Join(root, "var", "secret.key"),
		SSHKey:     filepath.Join(root, "var", "ssh", "id_ed25519"),
		BackupDir:  filepath.Join(root, "var", "backups"),
	}
	for _, d := range []string{filepath.Dir(lay.ConfigPath), filepath.Dir(lay.Database)} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.DefaultHub()
	cfg.Hub.Name = "frpi5"
	cfg.Hub.AgentAddress = "frpi5.local"
	cfg.Storage.Database = lay.Database
	cfg.TLS.Dir = lay.TLSDir
	if err := config.SaveHub(lay.ConfigPath, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.LoadOrCreateSecretKey(lay.SecretKey); err != nil {
		t.Fatal(err)
	}
	if _, err := pki.LoadOrCreateCA(lay.TLSDir, "frpi5.local"); err != nil {
		t.Fatal(err)
	}
	_ = st
	return lay
}

// opts returns the options of an authenticated request; csrf adds the token header, htmx the HX-Request header.
func (s *settingsEnv) opts(csrf, hx bool, more ...reqOpt) []reqOpt {
	o := []reqOpt{withCookies(s.cookie)}
	if csrf {
		o = append(o, withHeader("X-CSRF-Token", s.csrf))
	}
	if hx {
		o = append(o, htmx())
	}
	return append(o, more...)
}

func (s *settingsEnv) hxGet(path string) *httptest.ResponseRecorder {
	return s.get(path, s.opts(false, true)...)
}

// hxPost posts a form the way htmx does (token header, HX-Request).
func (s *settingsEnv) hxPost(path string, form url.Values) *httptest.ResponseRecorder {
	return s.post(path, s.opts(true, true, withForm(form))...)
}

// stgBundle is a signed release as CI publishes it, with a fake package.
type stgBundle struct {
	debName         string
	deb, sums, sigb []byte
}

func (s *settingsEnv) bundle(version string, debSize int) stgBundle {
	name := update.DebName(version, "arm64")
	deb := bytes.Repeat([]byte("x"), debSize)
	sum := sha256.Sum256(deb)
	sums := []byte(hex.EncodeToString(sum[:]) + "  " + name + "\n")
	return stgBundle{debName: name, deb: deb, sums: sums, sigb: ed25519.Sign(s.updKey, sums)}
}

type stgFile struct {
	name string
	data []byte
}

// multipartBody builds an upload body from the files in order.
func multipartBody(t *testing.T, files ...stgFile) (body *bytes.Buffer, contentType string) {
	t.Helper()
	body = &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	for _, f := range files {
		w, err := mw.CreateFormFile("files", f.name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write(f.data)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	return body, mw.FormDataContentType()
}

func (s *settingsEnv) upload(t *testing.T, csrf bool, files ...stgFile) *httptest.ResponseRecorder {
	t.Helper()
	body, ct := multipartBody(t, files...)
	return s.post(uploadPathUpdate, s.opts(csrf, true, func(r *http.Request) {
		r.Body = nopCloser{body}
		r.ContentLength = int64(body.Len())
		r.Header.Set("Content-Type", ct)
	})...)
}

type nopCloser struct{ *bytes.Buffer }

func (nopCloser) Close() error { return nil }

func (b stgBundle) files() []stgFile {
	return []stgFile{{b.debName, b.deb}, {update.SumsFile, b.sums}, {update.SigFile, b.sigb}}
}

func contains(t *testing.T, body string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(body, w) {
			t.Errorf("body lacks %q\n%s", w, abbreviate(body))
		}
	}
}

func lacks(t *testing.T, body string, unwanted ...string) {
	t.Helper()
	for _, w := range unwanted {
		if strings.Contains(body, w) {
			t.Errorf("body contains %q", w)
		}
	}
}

func abbreviate(s string) string {
	if len(s) > 3000 {
		return s[:3000] + "…"
	}
	return s
}

// auditActions returns the actions in the audit log, oldest first.
func (s *settingsEnv) auditActions() []string {
	entries, _ := s.st.ListAudit(context.Background(), 1000)
	var out []string
	for i := len(entries) - 1; i >= 0; i-- {
		out = append(out, entries[i].Action+":"+entries[i].Result)
	}
	return out
}

func (s *settingsEnv) auditFor(action string) []store.AuditEntry {
	entries, _ := s.st.ListAudit(context.Background(), 1000)
	var out []store.AuditEntry
	for _, e := range entries {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}
