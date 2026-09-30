package httpserver

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"
)

var tlsState tls.ConnectionState

func TestNewValidatesOptions(t *testing.T) {
	e := newEnv(t)
	good := Options{
		Auth: e.svc, Hub: e.hub, Setup: e.srv.setup, Static: e.srv.static,
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
