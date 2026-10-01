package enroll

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/config"
	hubenroll "github.com/phabioo/nexara/internal/hub/enroll"
	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/pki"
	"github.com/phabioo/nexara/internal/protocol"
)

// testHub runs the real enrollment handler behind a real pki-issued TLS listener.
type testHub struct {
	svc  *hubenroll.Service
	st   *store.Store
	ca   *pki.CA
	port int
}

func startHub(t *testing.T) *testHub {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "nexus.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	pkiDir := filepath.Join(dir, "pki")
	ca, err := pki.LoadOrCreateCA(pkiDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pki.EnsureServerCert(ca, pkiDir, []string{"localhost"}, []net.IP{net.IPv4(127, 0, 0, 1)}, time.Now()); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	svc, err := hubenroll.New(hubenroll.Options{
		Store: st, CA: ca, ServerCertFile: filepath.Join(pkiDir, pki.ServerCertFile),
		HubAddress: "localhost", Port: port, DataDir: dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg, err := pki.ServerTLSConfig(ca, filepath.Join(pkiDir, pki.ServerCertFile), filepath.Join(pkiDir, pki.ServerKeyFile), nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: svc.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(tls.NewListener(ln, tlsCfg)) }()
	t.Cleanup(func() { _ = srv.Close() })
	return &testHub{svc: svc, st: st, ca: ca, port: port}
}

func (h *testHub) url() string { return "https://localhost:" + strconv.Itoa(h.port) }

func (h *testHub) code(t *testing.T, caps []string) string {
	t.Helper()
	c, err := h.svc.NewEnrollCode(context.Background(), grid.Actor{Operator: "1"}, grid.EnrollOptions{Capabilities: caps})
	if err != nil {
		t.Fatal(err)
	}
	return c.Code
}

func (h *testHub) options(t *testing.T, token string) Options {
	dir := t.TempDir()
	return Options{
		Hub: h.url(), Token: token, CAFingerprint: pki.DisplayFingerprint(h.ca.Cert),
		ConfigPath: filepath.Join(dir, "etc", "grid-agent", "agent.yaml"),
		StateDir:   filepath.Join(dir, "var", "grid-agent"),
		ShellUser:  "pi",
	}
}

func TestEnrollEndToEnd(t *testing.T) {
	hub := startHub(t)
	code := hub.code(t, nil)
	o := hub.options(t, code)
	if err := Enroll(context.Background(), o); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.LoadAgent(o.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Hub.URL != "wss://localhost:"+strconv.Itoa(hub.port)+"/grid/connect" {
		t.Fatalf("hub url %q", cfg.Hub.URL)
	}
	if cfg.Shell.User != "pi" {
		t.Fatalf("shell user %q", cfg.Shell.User)
	}
	if cfg.Capabilities != config.DefaultAgent().Capabilities {
		t.Fatalf("nil capabilities must keep the defaults, got %+v", cfg.Capabilities)
	}
	if cfg.TLS.CA != filepath.Join(o.StateDir, "ca.pem") || cfg.TLS.Cert != filepath.Join(o.StateDir, "agent.pem") || cfg.TLS.Key != filepath.Join(o.StateDir, "agent.key") {
		t.Fatalf("tls paths %+v", cfg.TLS)
	}
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(cfg.TLS.Key); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("key file: %v %v", fi, err)
		}
		if fi, err := os.Stat(o.ConfigPath); err != nil || fi.Mode().Perm() != 0o640 {
			t.Fatalf("config file: %v %v", fi, err)
		}
	}
	// key, certificate and CA belong together and the certificate carries the host ID.
	if _, err := tls.LoadX509KeyPair(cfg.TLS.Cert, cfg.TLS.Key); err != nil {
		t.Fatal(err)
	}
	caPEM, _ := os.ReadFile(cfg.TLS.CA)
	if fp, err := pki.FingerprintFromPEM(caPEM); err != nil || fp != hub.ca.Fingerprint() {
		t.Fatalf("ca.pem: %v", err)
	}
	certPEM, _ := os.ReadFile(cfg.TLS.Cert)
	cert, _ := pki.ParseCertPEM(certPEM)
	hosts, err := hub.st.ListHosts(context.Background())
	if err != nil || len(hosts) != 1 || hosts[0].ID != cert.Subject.CommonName || hosts[0].CertFingerprint != pki.Fingerprint(cert) {
		t.Fatalf("hosts %+v %v", hosts, err)
	}
	if hosts[0].OS != runtime.GOOS || hosts[0].Arch != runtime.GOARCH {
		t.Fatalf("hello not applied: %+v", hosts[0])
	}
	// The agent can use its files for the real mTLS configuration.
	if _, err := pki.AgentTLSConfig(caPEM, cfg.TLS.Cert, cfg.TLS.Key); err != nil {
		t.Fatal(err)
	}

	// The same host name again (clone, re-install) is refused, not taken over
	// (decision #46), and says why in words the operator can act on.
	o2 := hub.options(t, hub.code(t, nil))
	o2.ConfigPath, o2.StateDir = filepath.Join(t.TempDir(), "agent.yaml"), filepath.Join(t.TempDir(), "state")
	err = Enroll(context.Background(), o2)
	if err == nil || !strings.Contains(err.Error(), "already has a host with this name") {
		t.Fatalf("second enrollment of the same host name: %v", err)
	}
	if _, statErr := os.Stat(o2.StateDir); statErr == nil {
		t.Fatal("state written for a refused enrollment")
	}
	hosts2, _ := hub.st.ListHosts(context.Background())
	if len(hosts2) != 1 || hosts2[0].ID != hosts[0].ID || hosts2[0].CertFingerprint != hosts[0].CertFingerprint {
		t.Fatalf("host changed: %+v", hosts2)
	}
}

func TestEnrollCapabilitySemantics(t *testing.T) {
	tests := []struct {
		name string
		caps []string
		want config.Capabilities
	}{
		{"nil keeps defaults", nil, config.DefaultAgent().Capabilities},
		{"exactly these", []string{"monitoring", "shell", "docker"}, config.Capabilities{Monitoring: true, Shell: true, Docker: true}},
		{"empty means all off", []string{}, config.Capabilities{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hub := startHub(t)
			o := hub.options(t, hub.code(t, tt.caps))
			if err := Enroll(context.Background(), o); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.LoadAgent(o.ConfigPath)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Capabilities != tt.want {
				t.Fatalf("capabilities %+v, want %+v", cfg.Capabilities, tt.want)
			}
		})
	}
}

func TestEnrollRejectsWrongPin(t *testing.T) {
	hub := startHub(t)
	other, err := pki.LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	code := hub.code(t, nil)
	o := hub.options(t, code)
	o.CAFingerprint = other.Fingerprint()
	err = Enroll(context.Background(), o)
	if err == nil {
		t.Fatal("enrolled against an unpinned CA")
	}
	if strings.Contains(err.Error(), code) {
		t.Fatalf("token in error: %v", err)
	}
	if _, statErr := os.Stat(o.ConfigPath); statErr == nil {
		t.Fatal("config written")
	}
	// The code was not sent (the TLS handshake failed first), so it still works.
	o.CAFingerprint = hub.ca.Fingerprint()
	if err := Enroll(context.Background(), o); err != nil {
		t.Fatalf("code unusable after a failed pin check: %v", err)
	}
}

func TestEnrollRejectedToken(t *testing.T) {
	hub := startHub(t)
	for _, token := range []string{"GRID-AAAA-BBBB-CCCC-DDDD", "grid-aaaa-bbbb-cccc-dddd"} {
		o := hub.options(t, token)
		err := Enroll(context.Background(), o)
		if !errors.Is(err, ErrTokenRejected) {
			t.Fatalf("got %v", err)
		}
		if strings.Contains(err.Error(), token) {
			t.Fatalf("token in error: %v", err)
		}
		if _, statErr := os.Stat(o.StateDir); statErr == nil {
			t.Fatal("state dir created for a failed enrollment")
		}
	}
}

func TestEnrollMalformedCodeNeverReachesTheNetwork(t *testing.T) {
	hub := startHub(t)
	for _, token := range []string{"1234", "GRID-AAAA-BBBB", "GRID-AAAA-BBBB-CCCC-DDD0", "GRID-AAAA-BBBB-CCCC-DDDD-EEEE"} {
		o := hub.options(t, token)
		err := Enroll(context.Background(), o)
		if err == nil || errors.Is(err, ErrTokenRejected) || !strings.Contains(err.Error(), "malformed") {
			t.Fatalf("%q: %v", token, err)
		}
		if strings.Contains(err.Error(), token) {
			t.Fatalf("token in error: %v", err)
		}
	}
}

func TestNormalizeCode(t *testing.T) {
	tests := []struct {
		in, want string
		ok       bool
	}{
		{"GRID-ABCD-EFGH-JKMN-PQRS", "GRID-ABCD-EFGH-JKMN-PQRS", true},
		{"  grid-abcd-efgh-jkmn-pqrs\n", "GRID-ABCD-EFGH-JKMN-PQRS", true},
		{"GRID-ABCD-EFGH", "", false},
		{"GRID-ABCD-EFGH-JKMN-PQR1", "", false},
		{"", "", false},
		{"GRID-ABCD-EFGH-JKMN-PQRS GRID-ABCD-EFGH-JKMN-PQRS", "", false},
	}
	for _, tt := range tests {
		got, err := NormalizeCode(tt.in)
		if (err == nil) != tt.ok || got != tt.want {
			t.Errorf("NormalizeCode(%q) = %q, %v", tt.in, got, err)
		}
	}
}

// S-19: the code can come from a file instead of the command line. The file
// must be private: a world-readable code file is refused.
func TestReadTokenFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	const code = "GRID-ABCD-EFGH-JKMN-PQRS"
	tests := []struct {
		name    string
		path    string
		want    string
		wantErr string
		unixAll bool // the check only exists on Unix
	}{
		{"private file", write("ok", code+"\n", 0o600), code, "", false},
		{"lower case and spaces", write("lower", " grid-abcd-efgh-jkmn-pqrs \n", 0o600), code, "", false},
		{"group readable", write("group", code, 0o640), "", "must not be accessible", true},
		{"world readable", write("world", code, 0o644), "", "must not be accessible", true},
		{"malformed content", write("bad", "hello", 0o600), "", "malformed", false},
		{"empty", write("empty", "", 0o600), "", "malformed", false},
		{"too large", write("big", strings.Repeat("A", maxTokenFile+1), 0o600), "", "too large", false},
		{"missing", filepath.Join(dir, "missing"), "", "open token file", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.unixAll && runtime.GOOS == "windows" {
				t.Skip("file modes are not enforced on Windows")
			}
			got, err := ReadTokenFile(tt.path)
			if tt.wantErr == "" {
				if err != nil || got != tt.want {
					t.Fatalf("got %q, %v", got, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %v, want %q", err, tt.wantErr)
			}
			if got != "" {
				t.Fatalf("returned %q together with an error", got)
			}
		})
	}
}

func TestEnrollConflictMessages(t *testing.T) {
	tests := []struct{ body, want string }{
		{`{"error":"host exists"}`, "already has a host with this name"},
		{`{"error":"host is revoked"}`, "revoked"},
		{`garbage`, "revoked"},
	}
	for _, tt := range tests {
		if err := conflictError(strings.NewReader(tt.body)); !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s -> %v, want %q", tt.body, err, tt.want)
		}
	}
}

func TestEnrollValidatesInputBeforeNetwork(t *testing.T) {
	base := Options{Hub: "https://localhost:1", Token: "GRID-AAAA-BBBB-CCCC-DDDD", CAFingerprint: strings.Repeat("ab", 32), ConfigPath: "x", StateDir: "y", ShellUser: "pi"}
	tests := []struct {
		name string
		mod  func(*Options)
	}{
		{"empty shell user", func(o *Options) { o.ShellUser = "" }},
		{"root shell user", func(o *Options) { o.ShellUser = "root" }},
		{"shell user with slash", func(o *Options) { o.ShellUser = "a/b" }},
		{"shell user with space", func(o *Options) { o.ShellUser = "a b" }},
		{"empty token", func(o *Options) { o.Token = "" }},
		{"empty hub", func(o *Options) { o.Hub = "" }},
		{"http hub", func(o *Options) { o.Hub = "http://localhost:1" }},
		{"hub with credentials", func(o *Options) { o.Hub = "https://u:p@localhost:1" }},
		{"bad fingerprint", func(o *Options) { o.CAFingerprint = "abc" }},
		{"no paths", func(o *Options) { o.ConfigPath, o.StateDir = "", "" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := base
			tt.mod(&o)
			start := time.Now()
			if err := Enroll(context.Background(), o); err == nil {
				t.Fatal("expected error")
			}
			if time.Since(start) > 2*time.Second {
				t.Fatal("tried the network")
			}
		})
	}
}

func TestHubBase(t *testing.T) {
	tests := []struct {
		in, want string
		ok       bool
	}{
		{"https://frpi5.local:8443", "https://frpi5.local:8443", true},
		{"frpi5.local:8443", "https://frpi5.local:8443", true},
		{"https://frpi5.local:8443/", "https://frpi5.local:8443", true},
		{"https://frpi5.local:8443/some/path?x=1", "https://frpi5.local:8443", true},
		{"http://frpi5.local", "", false},
		{"ftp://x", "", false},
		{"", "", false},
		{"https://", "", false},
	}
	for _, tt := range tests {
		got, err := hubBase(tt.in)
		if (err == nil) != tt.ok || got != tt.want {
			t.Errorf("hubBase(%q) = %q, %v", tt.in, got, err)
		}
	}
}

func TestInstallChecksTheHubAnswer(t *testing.T) {
	ca, err := pki.LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	other, err := pki.LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, csrPEM, err := pki.NewAgentKeyAndCSR("pi")
	if err != nil {
		t.Fatal(err)
	}
	certPEM, _, err := pki.SignAgentCSR(ca, csrPEM, "abcdef0123456789", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	otherKey, _, _ := pki.NewAgentKeyAndCSR("x")
	good := protocol.EnrollResponse{HostID: "abcdef0123456789", CertPEM: string(certPEM), CAPEM: string(ca.CertPEM()), HubURL: "wss://h:1/grid/connect"}
	newOpts := func() Options {
		d := t.TempDir()
		return Options{ConfigPath: filepath.Join(d, "agent.yaml"), StateDir: filepath.Join(d, "state"), ShellUser: "pi"}
	}

	if err := install(newOpts(), ca.Fingerprint(), keyPEM, good); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		mod  func(*protocol.EnrollResponse)
		key  []byte
		fp   string
	}{
		{"CA differs from the pin", func(r *protocol.EnrollResponse) { r.CAPEM = string(other.CertPEM()) }, keyPEM, ca.Fingerprint()},
		{"pin differs", func(*protocol.EnrollResponse) {}, keyPEM, other.Fingerprint()},
		{"certificate for another key", func(*protocol.EnrollResponse) {}, otherKey, ca.Fingerprint()},
		{"no host id", func(r *protocol.EnrollResponse) { r.HostID = "" }, keyPEM, ca.Fingerprint()},
		{"hub url not wss", func(r *protocol.EnrollResponse) { r.HubURL = "http://h/x" }, keyPEM, ca.Fingerprint()},
		{"garbage CA", func(r *protocol.EnrollResponse) { r.CAPEM = "nope" }, keyPEM, ca.Fingerprint()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := good
			tt.mod(&r)
			o := newOpts()
			if err := install(o, tt.fp, tt.key, r); err == nil {
				t.Fatal("accepted")
			}
			if _, err := os.Stat(o.ConfigPath); err == nil {
				t.Fatal("config written for a rejected answer")
			}
		})
	}
}

func TestEnrollFromTokenFile(t *testing.T) {
	hub := startHub(t)
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "self-enroll.token")
	if err := hub.svc.WriteSelfLinkToken(context.Background(), tokenFile, []string{"monitoring", "shell"}); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "etc", "agent.yaml")
	stateDir := filepath.Join(dir, "state")
	if err := EnrollFromTokenFile(context.Background(), cfgPath, stateDir, tokenFile, "pi"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(tokenFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("token file still there: %v", err)
	}
	cfg, err := config.LoadAgent(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if (cfg.Capabilities != config.Capabilities{Monitoring: true, Shell: true}) || cfg.Shell.User != "pi" {
		t.Fatalf("config %+v", cfg)
	}
}

func TestEnrollFromTokenFileFailures(t *testing.T) {
	hub := startHub(t)
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cfg := filepath.Join(dir, "agent.yaml")
	state := filepath.Join(dir, "state")

	if err := EnrollFromTokenFile(context.Background(), cfg, state, filepath.Join(dir, "missing"), "pi"); err == nil {
		t.Fatal("missing file accepted")
	}
	bad := write("bad.token", "not json")
	if err := EnrollFromTokenFile(context.Background(), cfg, state, bad, "pi"); err == nil {
		t.Fatal("bad json accepted")
	}
	huge := write("huge.token", strings.Repeat("a", maxTokenFile+1))
	if err := EnrollFromTokenFile(context.Background(), cfg, state, huge, "pi"); err == nil {
		t.Fatal("huge file accepted")
	}
	// Enrollment failure keeps the file (nothing was consumed) and never writes a config.
	stale := write("stale.token", `{"token":"GRID-AAAA-BBBB-CCCC-DDDD","ca_fingerprint":"`+hub.ca.Fingerprint()+`","hub":"`+hub.url()+`"}`)
	if err := EnrollFromTokenFile(context.Background(), cfg, state, stale, "pi"); !errors.Is(err, ErrTokenRejected) {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(stale); err != nil {
		t.Fatal("token file removed after a failed enrollment")
	}
	if _, err := os.Stat(cfg); err == nil {
		t.Fatal("config written")
	}
	// root is refused even with a good token, and the token stays unused.
	good := filepath.Join(dir, "good.token")
	if err := hub.svc.WriteSelfLinkToken(context.Background(), good, nil); err != nil {
		t.Fatal(err)
	}
	if err := EnrollFromTokenFile(context.Background(), cfg, state, good, "root"); err == nil {
		t.Fatal("root accepted as shell user")
	}
	if err := EnrollFromTokenFile(context.Background(), cfg, state, good, "pi"); err != nil {
		t.Fatalf("token was consumed by a refused attempt: %v", err)
	}
}
