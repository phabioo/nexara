package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/auth"
	"github.com/phabioo/nexara/internal/hub/setup"
	"github.com/phabioo/nexara/internal/pki"
)

const waitLimit = 15 * time.Second

type hubProc struct {
	t      *testing.T
	dir    string
	cfg    string
	socket string
	logs   *syncBuffer
	cancel context.CancelFunc
	done   chan error
	ready  Ready
	client *http.Client
	base   string
}

// writeHubConfig writes a nexus.yaml whose paths live in dir.
func writeHubConfig(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "nexus.yaml")
	yaml := "hub:\n  name: smoke\n  listen: \"127.0.0.1:8443\"\n" +
		"tls:\n  mode: self\n  dir: \"" + filepath.ToSlash(filepath.Join(dir, "pki")) + "\"\n" +
		"storage:\n  database: \"" + filepath.ToSlash(filepath.Join(dir, "data", "nexus.db")) + "\"\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// startHub runs Serve on 127.0.0.1:0 in the background and waits until it is ready.
func startHub(t *testing.T, dir string) *hubProc {
	t.Helper()
	log, logs := testLogger()
	h := &hubProc{t: t, dir: dir, cfg: writeHubConfig(t, dir), logs: logs, done: make(chan error, 1)}
	h.socket = filepath.Join(shortTempDir(t), "admin.sock")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	ready := make(chan Ready, 1)
	go func() {
		h.done <- Serve(ctx, ServeOptions{
			ConfigPath: h.cfg, AdminSocket: h.socket, Logger: log, Listener: ln,
			HashParams: cheapParams, Ready: func(r Ready) { ready <- r },
		})
	}()
	select {
	case h.ready = <-ready:
	case err := <-h.done:
		t.Fatalf("Serve returned before it was ready: %v", err)
	case <-time.After(waitLimit):
		t.Fatal("hub did not become ready")
	}
	t.Cleanup(func() { h.stop() })

	caPEM, err := os.ReadFile(filepath.Join(dir, "pki", pki.CACertFile))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("CA PEM")
	}
	jar, _ := cookiejar.New(nil)
	h.client = &http.Client{
		Jar:           jar,
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost"},
			// Offer h2 so a server that negotiates it would be caught.
			ForceAttemptHTTP2: true,
		},
	}
	h.base = "https://" + h.ready.Addr.String()
	return h
}

// stop cancels the hub and returns Serve's result (nil if stopped before).
func (h *hubProc) stop() error {
	h.cancel()
	select {
	case err := <-h.done:
		h.done <- err // keep it readable for further calls
		return err
	case <-time.After(waitLimit):
		h.t.Error("Serve did not return after the context was cancelled")
		return context.DeadlineExceeded
	}
}

func (h *hubProc) get(path string) *http.Response {
	h.t.Helper()
	resp, err := h.client.Get(h.base + path)
	if err != nil {
		h.t.Fatal(err)
	}
	t := h.t
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestServeSetupMode(t *testing.T) {
	dir := t.TempDir()
	h := startHub(t, dir)
	if !h.ready.SetupMode || !strings.Contains(h.ready.CAFingerprint, ":") {
		t.Errorf("ready = %+v", h.ready)
	}

	// Only the wizard is served; everything else redirects to it, and the agent endpoint is closed.
	for _, p := range []string{"/", "/login", "/hosts/x/shell"} {
		resp := h.get(p)
		if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/setup" {
			t.Errorf("GET %s = %d -> %q, want 303 -> /setup", p, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
	for _, p := range []string{"/grid/connect", "/grid/install.sh"} {
		if resp := h.get(p); resp.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("GET %s = %d, want 503 while no operator exists", p, resp.StatusCode)
		}
	}
	if resp := h.get("/static/css/nexus.css"); resp.StatusCode != http.StatusOK {
		t.Errorf("static asset = %d", resp.StatusCode)
	}

	// The code is in the journal (the log) and `nexus setup code` replaces it.
	logs := h.logs.String()
	for _, want := range []string{"setup code", "code=", "CA fingerprint", h.ready.CAFingerprint} {
		if !strings.Contains(logs, want) {
			t.Errorf("log does not contain %q:\n%s", want, logs)
		}
	}
	resp, err := CallAdmin(h.socket, setup.CmdSetupCode)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Code) != 9 || !strings.Contains(h.logs.String(), "code="+resp.Code) {
		t.Errorf("admin code %q not announced in the log", resp.Code)
	}

	// TLS: 1.3 only, HTTP/1.1 even when the client offers h2.
	raw := func(cfg *tls.Config) (*tls.Conn, error) {
		cfg.InsecureSkipVerify = true
		return tls.Dial("tcp", h.ready.Addr.String(), cfg)
	}
	conn, err := raw(&tls.Config{NextProtos: []string{"h2", "http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := conn.ConnectionState().NegotiatedProtocol; got != "http/1.1" {
		t.Errorf("negotiated %q, want http/1.1", got)
	}
	if got := conn.ConnectionState().Version; got != tls.VersionTLS13 {
		t.Errorf("TLS version %x", got)
	}
	conn.Close()
	if c, err := raw(&tls.Config{MaxVersion: tls.VersionTLS12}); err == nil {
		c.Close()
		t.Error("TLS 1.2 accepted")
	}

	if err := h.stop(); err != nil {
		t.Fatalf("Serve = %v, want nil on a clean shutdown", err)
	}
	if _, err := os.Stat(h.socket); !os.IsNotExist(err) {
		t.Errorf("admin socket left behind: %v", err)
	}
	for _, f := range []string{filepath.Join("pki", pki.CACertFile), filepath.Join("pki", pki.ServerCertFile), filepath.Join("data", "secret.key"), filepath.Join("data", "nexus.db")} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("%s not created: %v", f, err)
		}
	}
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(filepath.Join(dir, "data", "secret.key")); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("secret.key mode = %v %v", fi.Mode().Perm(), err)
		}
	}
}

func TestServeWithOperatorSignsIn(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0o750); err != nil {
		t.Fatal(err)
	}
	st := openStore(t, filepath.Join(dir, "data"))
	createOperator(t, st, testOperator, testPass)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	h := startHub(t, dir)
	if h.ready.SetupMode {
		t.Fatal("hub with an operator must not be in setup mode")
	}
	if strings.Contains(h.logs.String(), "setup code") {
		t.Error("a setup code was announced although an operator exists")
	}
	if _, err := CallAdmin(h.socket, setup.CmdSetupCode); err == nil {
		t.Error("`setup code` must be refused while an operator exists")
	}

	if resp := h.get("/login"); resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /login = %d", resp.StatusCode)
	}
	if resp := h.get("/"); resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
		t.Errorf("anonymous GET / = %d -> %q, want 303 -> /login", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp := h.get("/grid/connect"); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("/grid/connect without a client certificate = %d, want 401", resp.StatusCode)
	}
	if resp := h.get("/grid/install.sh"); resp.StatusCode != http.StatusOK {
		t.Errorf("/grid/install.sh = %d, want 200 once an operator exists", resp.StatusCode)
	}

	// Sign in with the double-submit CSRF token.
	u, _ := url.Parse(h.base)
	var csrf string
	for _, c := range h.client.Jar.Cookies(u) {
		if c.Name == auth.CSRFCookieName {
			csrf = c.Value
		}
	}
	if csrf == "" {
		t.Fatal("no CSRF cookie after GET /login")
	}
	form := url.Values{"csrf_token": {csrf}, "operator_id": {testOperator}, "passphrase": {testPass}}
	resp, err := h.client.PostForm(h.base+"/login", form)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		t.Fatalf("POST /login = %d -> %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	var session *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == auth.SessionCookieName {
			session = c
		}
	}
	if session == nil || !session.Secure || !session.HttpOnly || session.SameSite != http.SameSiteStrictMode {
		t.Errorf("session cookie = %+v, want Secure HttpOnly SameSite=Strict", session)
	}
	if resp := h.get("/"); resp.StatusCode == http.StatusSeeOther || resp.StatusCode == http.StatusUnauthorized {
		t.Errorf("signed-in GET / = %d, want an authenticated answer", resp.StatusCode)
	}

	// An open event stream must not hold up the shutdown.
	stream := h.get("/events")
	if stream.StatusCode != http.StatusOK || !strings.HasPrefix(stream.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("/events = %d %q", stream.StatusCode, stream.Header.Get("Content-Type"))
	}
	if err := h.stop(); err != nil {
		t.Fatalf("Serve = %v", err)
	}
	if _, err := io.ReadAll(stream.Body); err != nil && !strings.Contains(err.Error(), "EOF") && !strings.Contains(err.Error(), "closed") && !strings.Contains(err.Error(), "reset") {
		t.Logf("stream ended with %v", err)
	}
}

func TestServeRestartKeepsIdentity(t *testing.T) {
	dir := t.TempDir()
	first := startHub(t, dir)
	key1, err := os.ReadFile(filepath.Join(dir, "data", "secret.key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := first.stop(); err != nil {
		t.Fatal(err)
	}

	second := startHub(t, dir)
	key2, _ := os.ReadFile(filepath.Join(dir, "data", "secret.key"))
	if first.ready.CAFingerprint != second.ready.CAFingerprint {
		t.Error("the CA changed across a restart; agents would no longer trust the hub")
	}
	if string(key1) != string(key2) {
		t.Error("secret.key changed across a restart; sealed TOTP secrets would be lost")
	}
	if err := second.stop(); err != nil {
		t.Fatal(err)
	}
}

func TestServeStartupErrors(t *testing.T) {
	log, _ := testLogger()
	dir := t.TempDir()

	err := Serve(context.Background(), ServeOptions{ConfigPath: filepath.Join(dir, "missing.yaml"), Logger: log})
	if err == nil || !strings.Contains(err.Error(), "cannot load configuration") {
		t.Errorf("missing config: %v", err)
	}

	// hub.listen is taken.
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	cfg := writeHubConfig(t, dir)
	data, _ := os.ReadFile(cfg)
	data = []byte(strings.Replace(string(data), "127.0.0.1:8443", busy.Addr().String(), 1))
	if err := os.WriteFile(cfg, data, 0o600); err != nil {
		t.Fatal(err)
	}
	err = Serve(context.Background(), ServeOptions{ConfigPath: cfg, Logger: log})
	if err == nil || !strings.Contains(err.Error(), "cannot listen") {
		t.Errorf("busy port: %v", err)
	}
}
