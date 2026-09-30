package httpserver

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/auth"
	"github.com/phabioo/nexara/internal/hub/setup"
)

var tlsState tls.ConnectionState

func TestNewValidatesOptions(t *testing.T) {
	e := newEnv(t)
	good := Options{
		Auth: e.svc, Hub: e.hub, Setup: e.srv.setup, Static: e.srv.static, SecureCookies: true,
	}
	if _, err := New(good); err != nil {
		t.Fatalf("valid options rejected: %v", err)
	}
	for name, mutate := range map[string]func(*Options){
		"auth":   func(o *Options) { o.Auth = nil },
		"hub":    func(o *Options) { o.Hub = nil },
		"mode":   func(o *Options) { o.Setup.Mode = nil },
		"static": func(o *Options) { o.Static = nil },
	} {
		o := good
		mutate(&o)
		if _, err := New(o); err == nil {
			t.Errorf("missing %s accepted", name)
		}
	}
}

func TestNewRejectsCookieSecureMismatch(t *testing.T) {
	e := newEnv(t)
	o := Options{Auth: e.svc, Hub: e.hub, Setup: e.srv.setup, Static: e.srv.static, SecureCookies: true}
	if _, err := New(o); err != nil {
		t.Fatalf("consistent options rejected: %v", err)
	}

	insecureAuth, err := auth.NewService(auth.Config{
		Store: e.st, SecretKey: make([]byte, auth.SecretKeyLen), HashParams: testParams,
		CookieOptions: []auth.CookieOption{auth.WithSecure(false)},
	})
	if err != nil {
		t.Fatal(err)
	}
	insecureSetup := SetupDeps{
		Codes: e.srv.setup.Codes, Mode: e.srv.setup.Mode,
		Sessions: setup.NewSessions(setup.SessionOptions{InsecureCookie: true}),
	}
	tests := []struct {
		name   string
		mutate func(*Options)
	}{
		{"option off, rest secure", func(o *Options) { o.SecureCookies = false }},
		{"auth insecure", func(o *Options) { o.Auth = insecureAuth }},
		{"setup sessions insecure", func(o *Options) { o.Setup = insecureSetup }},
	}
	for _, tt := range tests {
		o := o
		tt.mutate(&o)
		if _, err := New(o); err == nil || !strings.Contains(err.Error(), "Secure") {
			t.Errorf("%s: err = %v, want a Secure mismatch error", tt.name, err)
		}
	}

	// All three insecure (dev mode) is consistent.
	dev := Options{Auth: insecureAuth, Hub: e.hub, Setup: insecureSetup, Static: e.srv.static, SecureCookies: false}
	if _, err := New(dev); err != nil {
		t.Errorf("consistent insecure options rejected: %v", err)
	}
}

func TestServeIsHTTP1Only(t *testing.T) {
	p := http1Only()
	if !p.HTTP1() || p.HTTP2() || p.UnencryptedHTTP2() {
		t.Errorf("protocols = %v, want HTTP/1.1 only (WebSockets need the upgrade)", p)
	}
}

func TestSSHPublicKey(t *testing.T) {
	e := newEnv(t)
	if got := e.srv.sshPublicKey(); got != "" {
		t.Errorf("without a provider = %q, want empty", got)
	}
	o := Options{Auth: e.svc, Hub: e.hub, Setup: e.srv.setup, Static: e.srv.static, SecureCookies: true,
		SSHPublicKey: func() string { return "ssh-ed25519 AAAA test" }}
	s, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.sshPublicKey(); got != "ssh-ed25519 AAAA test" {
		t.Errorf("sshPublicKey = %q", got)
	}
}

func TestServeGracefulShutdownEndsStreams(t *testing.T) {
	e := newEnv(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.srv.Serve(ctx, ln, nil) }()

	cookie, _ := e.signIn()
	c := openStreamURL(t, "http://"+ln.Addr().String(), "/events", withCookies(cookie))
	waitFor(t, "subscription", func() bool { return e.hub.subscribers() == 1 })

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after cancel (stream kept it open)")
	}
	// The client sees the end of the stream.
	for {
		select {
		case _, ok := <-c.lines:
			if !ok {
				return
			}
		case <-time.After(3 * time.Second):
			t.Fatal("stream not closed")
		}
	}
}
