package grid

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/agentbin"
	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/protocol"
)

const fakeSHA = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

var fakeAgentData = []byte("NEXARA-AGENT-BINARY")

func fakeBinaries(goos, arch string) (agentbin.Binary, bool) {
	if goos == "linux" && arch == "arm64" {
		return agentbin.Binary{OS: goos, Arch: arch, Version: "0.2.0", SHA256: fakeSHA, Data: fakeAgentData}, true
	}
	return agentbin.Binary{}, false
}

func withHubVersion(v string) func(*Options) {
	return func(o *Options) { o.HubVersion = v; o.AgentBinary = fakeBinaries }
}

// updateAgent records agent.update messages and answers them.
type updateAgent struct {
	t       *testing.T
	updates chan protocol.AgentUpdate
	reject  string
}

func newUpdateAgent(t *testing.T) *updateAgent {
	return &updateAgent{t: t, updates: make(chan protocol.AgentUpdate, 4)}
}

func (u *updateAgent) handle(a *fakeAgent, env protocol.Envelope) bool {
	if env.Type != protocol.TypeAgentUpdate {
		return false
	}
	msg, err := protocol.DecodeData[protocol.AgentUpdate](env)
	if err != nil {
		u.t.Errorf("agent.update: %v", err)
		return true
	}
	if u.reject != "" {
		a.result(env, false, u.reject)
		return true
	}
	a.result(env, true, "")
	u.updates <- msg
	return true
}

func TestOlderAgentIsUpdatedAutomatically(t *testing.T) {
	e := newEnv(t, withHubVersion("0.2.0"))
	ua := newUpdateAgent(t)
	e.addHost("alpha")
	e.connect("alpha", helloFor("0.1.0"), ua.handle)

	select {
	case msg := <-ua.updates:
		if msg.Version != "0.2.0" || msg.SHA256 != fakeSHA || msg.Path != "/grid/agent/linux/arm64" {
			t.Fatalf("agent.update = %+v", msg)
		}
	case <-timeAfterWait():
		t.Fatal("no agent.update in time")
	}
	au := e.waitAudit("agent.update")
	if au.User != "system" || au.Host != "alpha" || au.Result != store.AuditOK || au.Detail != "0.2.0" {
		t.Fatalf("audit = %+v", au)
	}
}

func TestNoAutomaticUpdateWhenNotNeeded(t *testing.T) {
	cases := []struct {
		name       string
		hub, agent string
		os, arch   string
	}{
		{"same version", "0.2.0", "0.2.0", "linux", "arm64"},
		{"newer agent", "0.2.0", "0.3.0", "linux", "arm64"},
		{"dev agent", "0.2.0", "dev", "linux", "arm64"},
		{"dev hub", "dev", "0.1.0", "linux", "arm64"},
		{"no binary for platform", "0.2.0", "0.1.0", "linux", "amd64"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, withHubVersion(c.hub))
			ua := newUpdateAgent(t)
			id := e.addHost("alpha", protocol.CapServices)
			hello := helloFor(c.agent, protocol.CapServices)
			hello.OS, hello.Arch = c.os, c.arch
			e.connect("alpha", hello, chain(answerRefresh, ua.handle))
			// The update decision follows the initial refresh on the same goroutine.
			eventually(t, func() bool { s, _ := e.g.Snapshot(id); return s.Services != nil })
			time.Sleep(100 * time.Millisecond)
			if len(ua.updates) != 0 {
				t.Fatalf("unexpected update: %+v", <-ua.updates)
			}
		})
	}
}

func TestUpdateAgentOnDemand(t *testing.T) {
	e := newEnv(t, withHubVersion("0.2.0"))
	ua := newUpdateAgent(t)
	id := e.addHost("alpha")
	e.connect("alpha", helloFor("0.2.0"), ua.handle)
	eventually(t, func() bool { i, _ := e.g.Host(id); return i.Online })
	ctx := context.Background()

	if err := e.g.UpdateAgent(ctx, Actor{Operator: "op1"}, id); err != nil {
		t.Fatal(err)
	}
	select {
	case msg := <-ua.updates:
		if msg.Version != "0.2.0" || msg.SHA256 != fakeSHA || msg.Path != "/grid/agent/linux/arm64" {
			t.Fatalf("agent.update = %+v", msg)
		}
	case <-timeAfterWait():
		t.Fatal("no agent.update")
	}
	if au := e.waitAudit("agent.update"); au.User != "op1" || au.Result != store.AuditOK {
		t.Fatalf("audit = %+v", au)
	}

	ua.reject = "disk full"
	if err := e.g.UpdateAgent(ctx, Actor{Operator: "op2"}, id); err == nil {
		t.Fatal("rejected update reported success")
	}
	eventually(t, func() bool {
		for _, a := range e.auditFor("agent.update") {
			if a.User == "op2" && a.Result == store.AuditError {
				return true
			}
		}
		return false
	})

	if err := e.g.UpdateAgent(ctx, Actor{}, "missing"); !errors.Is(err, ErrHostNotFound) {
		t.Errorf("unknown host: %v", err)
	}
	off := e.addHost("offline")
	if err := e.g.UpdateAgent(ctx, Actor{}, off); !errors.Is(err, ErrHostOffline) {
		t.Errorf("offline: %v", err)
	}
	win := e.addHost("winbox")
	hello := helloFor("0.1.0")
	hello.OS, hello.Arch = "windows", "amd64"
	e.connect("winbox", hello, nil)
	eventually(t, func() bool { i, _ := e.g.Host(win); return i.Online })
	if err := e.g.UpdateAgent(ctx, Actor{}, win); !errors.Is(err, ErrUnsupported) {
		t.Errorf("no binary: %v", err)
	}
}

func TestAgentDownloadHandler(t *testing.T) {
	e := newEnv(t, withHubVersion("0.2.0"))
	e.addHost("alpha")
	get := func(path, host string) (*http.Response, []byte) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, e.srv.URL+path, nil)
		if host != "" {
			req.Header.Set("X-Test-Host", host)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp, body
	}

	resp, body := get("/grid/agent/linux/arm64", "alpha")
	if resp.StatusCode != http.StatusOK || string(body) != string(fakeAgentData) {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("content type %q", ct)
	}
	if got := resp.Header.Get("X-Nexara-SHA256"); got != fakeSHA {
		t.Errorf("sha header %q", got)
	}
	if got := resp.Header.Get("Content-Length"); got != strconv.Itoa(len(fakeAgentData)) {
		t.Errorf("content length %q", got)
	}

	for _, tc := range []struct {
		name, path, host string
		want             int
	}{
		{"no identity", "/grid/agent/linux/arm64", "", http.StatusUnauthorized},
		{"unknown identity", "/grid/agent/linux/arm64", "nobody", http.StatusUnauthorized},
		{"no binary", "/grid/agent/linux/riscv64", "alpha", http.StatusNotFound},
		{"unknown os", "/grid/agent/plan9/arm64", "alpha", http.StatusNotFound},
	} {
		resp, body := get(tc.path, tc.host)
		if resp.StatusCode != tc.want {
			t.Errorf("%s: status %d, want %d", tc.name, resp.StatusCode, tc.want)
		}
		if tc.want == http.StatusUnauthorized && string(body) == string(fakeAgentData) {
			t.Errorf("%s: binary leaked", tc.name)
		}
	}
}
