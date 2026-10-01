package app

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/auth"
	"github.com/phabioo/nexara/internal/hub/demo"
)

type devProc struct {
	t       *testing.T
	ready   DevReady
	console *syncBuffer
	cancel  context.CancelFunc
	done    chan error
	client  *http.Client
	base    string
	tmp     string
}

func startDev(t *testing.T, seed bool) *devProc {
	t.Helper()
	// RunDev creates its temporary directory under TMPDIR/TMP; point it at a
	// directory we can inspect afterwards.
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	t.Setenv("TMP", tmp)
	t.Setenv("TEMP", tmp)

	log, _ := testLogger()
	d := &devProc{t: t, console: &syncBuffer{}, done: make(chan error, 1), tmp: tmp}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	d.cancel = cancel
	ready := make(chan DevReady, 1)
	go func() {
		d.done <- RunDev(ctx, DevOptions{
			Seed: seed, Console: d.console, Logger: log, Listener: ln, HashParams: cheapParams,
			Ready: func(r DevReady) { ready <- r },
			Demo:  demo.Options{TimeScale: 0.001},
		})
	}()
	select {
	case d.ready = <-ready:
	case err := <-d.done:
		t.Fatalf("RunDev returned before it was ready: %v", err)
	case <-time.After(waitLimit):
		t.Fatal("dev hub did not become ready")
	}
	t.Cleanup(func() { d.stop() })
	jar, _ := cookiejar.New(nil)
	d.client = &http.Client{
		Jar: jar, Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	d.base = "http://" + d.ready.Addr.String()
	return d
}

func (d *devProc) stop() error {
	d.cancel()
	select {
	case err := <-d.done:
		d.done <- err
		return err
	case <-time.After(waitLimit):
		d.t.Error("RunDev did not return after the context was cancelled")
		return context.DeadlineExceeded
	}
}

func (d *devProc) get(path string) *http.Response {
	d.t.Helper()
	resp, err := d.client.Get(d.base + path)
	if err != nil {
		d.t.Fatal(err)
	}
	d.t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestDevSeeded(t *testing.T) {
	d := startDev(t, true)
	if d.ready.SetupMode || d.ready.SetupCode != "" {
		t.Errorf("seeded dev hub must skip the setup: %+v", d.ready)
	}
	for _, want := range []string{d.base, DevOperator, DevPassphrase} {
		if !strings.Contains(d.console.String(), want) {
			t.Errorf("console does not say %q:\n%s", want, d.console.String())
		}
	}

	if resp := d.get("/login"); resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /login = %d", resp.StatusCode)
	}
	if resp := d.get("/"); resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
		t.Errorf("anonymous GET / = %d -> %q", resp.StatusCode, resp.Header.Get("Location"))
	}

	u, _ := url.Parse(d.base)
	var csrf string
	for _, c := range d.client.Jar.Cookies(u) {
		if c.Name == auth.CSRFCookieName {
			csrf = c.Value
		}
	}
	resp, err := d.client.PostForm(d.base+"/login", url.Values{
		"csrf_token": {csrf}, "operator_id": {DevOperator}, "passphrase": {DevPassphrase},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		t.Fatalf("POST /login = %d -> %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	// Plain HTTP: a Secure cookie would never come back, so the flag must be off.
	var session *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == auth.SessionCookieName {
			session = c
		}
	}
	if session == nil || session.Secure || !session.HttpOnly || session.SameSite != http.SameSiteStrictMode {
		t.Errorf("session cookie = %+v, want HttpOnly SameSite=Strict without Secure", session)
	}
	if resp := d.get("/"); resp.StatusCode == http.StatusSeeOther || resp.StatusCode == http.StatusUnauthorized {
		t.Errorf("signed-in GET / = %d, want an authenticated answer", resp.StatusCode)
	}

	// The event stream is served (the views subscribe to the simulated hosts).
	stream := d.get("/events")
	if stream.StatusCode != http.StatusOK {
		t.Errorf("/events = %d", stream.StatusCode)
	}

	if err := d.stop(); err != nil {
		t.Fatalf("RunDev = %v, want nil on a clean shutdown", err)
	}
	if entries, err := os.ReadDir(d.tmp); err != nil || len(entries) != 0 {
		t.Errorf("temporary data left behind: %v %v", entries, err)
	}
}

func TestDevWithoutSeedStartsSetup(t *testing.T) {
	d := startDev(t, false)
	if !d.ready.SetupMode || len(d.ready.SetupCode) != 9 || d.ready.SetupCode[4] != '-' {
		t.Fatalf("ready = %+v", d.ready)
	}
	if !strings.Contains(d.console.String(), "Setup code: "+d.ready.SetupCode) {
		t.Errorf("the setup code is not on the console:\n%s", d.console.String())
	}
	if strings.Contains(d.console.String(), DevPassphrase) {
		t.Error("demo credentials printed although no operator was created")
	}
	for _, p := range []string{"/", "/login"} {
		if resp := d.get(p); resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/setup" {
			t.Errorf("GET %s = %d -> %q, want 303 -> /setup", p, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
	if err := d.stop(); err != nil {
		t.Fatalf("RunDev = %v", err)
	}
}

// The demo gets an ephemeral CA so the Trust step (QR code, downloads) is visible.
func TestDevSetupServesTheCA(t *testing.T) {
	d := startDev(t, false)
	resp := d.get("/setup/trust/nexara-ca.crt")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(string(body), "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("GET CA = %d %.40q", resp.StatusCode, body)
	}
	if strings.Contains(string(body), "PRIVATE KEY") {
		t.Fatal("the CA key is served")
	}
	if err := d.stop(); err != nil {
		t.Fatalf("RunDev = %v", err)
	}
	if entries, err := os.ReadDir(d.tmp); err != nil || len(entries) != 0 {
		t.Errorf("temporary data left behind: %v %v", entries, err)
	}
}

func TestRunDevRejectsNonLoopback(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	t.Setenv("TMP", tmp)
	for _, addr := range []string{"0.0.0.0:0", ":0", "192.0.2.1:8080", "frpi5.local:8080"} {
		err := RunDev(context.Background(), DevOptions{Addr: addr})
		if err == nil || !strings.Contains(err.Error(), "loopback") {
			t.Errorf("RunDev(%q) = %v, want a loopback error", addr, err)
		}
	}
	if entries, _ := os.ReadDir(tmp); len(entries) != 0 {
		t.Errorf("a rejected start created %v", entries)
	}
}
