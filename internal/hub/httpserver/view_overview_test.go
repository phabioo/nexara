package httpserver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/hub/views"
	"github.com/phabioo/nexara/internal/protocol"
	"github.com/phabioo/nexara/web"
)

// overviewHub records the service calls of the overview on top of the shared fake hub.
type overviewHub struct {
	*fakeHub
	mu        sync.Mutex
	restarted []string
	actors    []grid.Actor
	restartFn func(unit string) error
	refreshed chan grid.HostID
}

func (h *overviewHub) RestartService(_ context.Context, actor grid.Actor, id grid.HostID, unit string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.restarted = append(h.restarted, string(id)+"/"+unit)
	h.actors = append(h.actors, actor)
	if h.restartFn != nil {
		return h.restartFn(unit)
	}
	return nil
}

func (h *overviewHub) RefreshServices(_ context.Context, id grid.HostID) error {
	select {
	case h.refreshed <- id:
	default:
	}
	return nil
}

func (h *overviewHub) calls() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.restarted...)
}

const ovGiB = 1 << 30

func sampleOvMetrics() *protocol.Metrics {
	temp := 47.2
	return &protocol.Metrics{
		CPUPercent: 24, CPUPerCore: []float64{28, 20, 25, 0}, TempC: &temp, Load: [3]float64{0.42, 0.38, 0.35},
		MemTotal: 8 * ovGiB, MemUsed: 3_650_722_201, SwapTotal: 2 * ovGiB,
		Disks: []protocol.Disk{{Mount: "/", Total: 117_000_000_000, Used: 41_000_000_000}},
		Net:   protocol.NetRate{Iface: "eth0", RxBytesPerSec: 1.2e6, TxBytesPerSec: 8.6e6},
		TopProcesses: []protocol.Process{
			{PID: 1, Name: "plexmediaserver", CPU: 12.4, MemBytes: ovGiB / 4},
			{PID: 2, Name: "dockerd", CPU: 1.9, MemBytes: ovGiB / 10},
		},
	}
}

func sampleOvServices() *protocol.Services {
	return &protocol.Services{
		Units: []protocol.ServiceUnit{
			{Name: "ssh.service", ActiveState: "active"},
			{Name: "smbd.service", ActiveState: "failed"},
			{Name: "cron.service", ActiveState: "active"},
		},
		Ports: []protocol.ListeningPort{{Proto: "tcp", Port: 22}, {Proto: "tcp", Port: 445}, {Proto: "udp", Port: 5353}},
	}
}

func newOverviewEnv(t *testing.T) (*env, *overviewHub) {
	t.Helper()
	e := newEnv(t)
	r, err := views.New(web.Templates, views.Options{})
	if err != nil {
		t.Fatal(err)
	}
	e.srv.renderer = r
	oh := &overviewHub{fakeHub: e.hub, refreshed: make(chan grid.HostID, 8)}
	e.srv.hub = oh
	e.hub.mu.Lock()
	e.hub.hosts[0].Model = "Raspberry Pi 5 Model B Rev 1.0"
	e.hub.hosts[0].Capabilities = []string{protocol.CapMonitoring, protocol.CapServices, protocol.CapShell}
	e.hub.snaps["a1"] = grid.Snapshot{
		Host: e.hub.hosts[0], Metrics: sampleOvMetrics(), CPUHistory: []float64{10, 20, 30, 25},
		Services: sampleOvServices(),
	}
	e.hub.mu.Unlock()
	return e, oh
}

func ovHave(t *testing.T, body string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(body, w) {
			t.Errorf("body lacks %q", w)
		}
	}
}

func ovLack(t *testing.T, body string, unwanted ...string) {
	t.Helper()
	for _, w := range unwanted {
		if strings.Contains(body, w) {
			t.Errorf("body contains %q", w)
		}
	}
}

func TestOverviewPages(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		hosts  func(h *fakeHub)
		status int
		want   []string
		lack   []string
	}{
		{
			name: "default host is the first online host", path: "/", status: 200,
			want: []string{"Overview: alpha", `sse-connect="/events?host=alpha"`, "CPU · 4 Cores", "Memory &amp; storage", ">Services<",
				"Raspberry Pi 5 Model B Rev 1.0, 4 cores.", "Currently at 24% utilisation, SoC temperature 47.2 °C. Throttling starts at 80 °C.",
				"Core 0", "Core 3", "SoC temperature", "0.42 0.38 0.35", "3.4 / 8 GB", "41 / 117 GB", "NO DISK", "CPU · LAST 8 S",
				"Listening on 22, 445 and 5353/udp.", "2/3 running", "Restart failed units (1)", `hx-post="/hosts/alpha/services/restart"`,
				"Open shell", `href="/hosts/alpha/shell"`, "Connected to alpha", "plexmediaserver", "12.4%", "3.1%",
				`sse-swap="ov-cpu"`, `sse-swap="ov-mem"`, `sse-swap="ov-svc"`, `sse-swap="ov-load"`, "overview.js", "<polyline points="},
			lack: []string{"Wake", "WoL", "Shut down", "Reboot required", "History", "Alerts", "Containers"},
		},
		{
			name: "explicit online host", path: "/hosts/alpha", status: 200,
			want: []string{"Overview: alpha", `aria-current="page"`},
		},
		{
			name: "offline host shows the offline card without Wake-on-LAN", path: "/hosts/beta", status: 200,
			want: []string{"Beta Pi · Offline", "The Grid Agent is not connected.", "Last seen", "never", `sse-connect="/events?host=beta"`},
			lack: []string{"Wake", "WoL", "MAC address", "Memory &amp; storage", "Restart failed units"},
		},
		{
			name: "unknown host", path: "/hosts/nope", status: 404,
		},
		{
			name: "default falls back to the first host when none is online", path: "/", status: 200,
			hosts: func(h *fakeHub) { h.hosts[0].Online = false },
			want:  []string{"alpha · Offline"},
		},
		{
			name: "no hosts", path: "/", status: 200,
			hosts: func(h *fakeHub) { h.hosts = nil },
			want:  []string{"No hosts yet", `hx-get="/hosts/new"`},
			lack:  []string{"sse-connect"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e, _ := newOverviewEnv(t)
			if tc.hosts != nil {
				e.hub.mu.Lock()
				tc.hosts(e.hub)
				e.hub.mu.Unlock()
			}
			cookie, _ := e.signIn()
			rec := e.get(tc.path, withCookies(cookie))
			if rec.Code != tc.status {
				t.Fatalf("status %d, want %d", rec.Code, tc.status)
			}
			if tc.status == 200 {
				if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
					t.Errorf("content type %q", ct)
				}
			}
			ovHave(t, rec.Body.String(), tc.want...)
			ovLack(t, rec.Body.String(), tc.lack...)
		})
	}
}

func TestOverviewRequiresSession(t *testing.T) {
	e, _ := newOverviewEnv(t)
	for _, path := range []string{"/", "/hosts/alpha", "/hosts/nope"} {
		rec := e.get(path)
		if rec.Code != http.StatusSeeOther && rec.Code != http.StatusFound {
			t.Errorf("%s: status %d, want a redirect to /login", path, rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "/login" {
			t.Errorf("%s: Location %q", path, loc)
		}
	}
}

func TestOverviewWithoutData(t *testing.T) {
	tests := []struct {
		name  string
		setup func(h *fakeHub)
		want  []string
		lack  []string
	}{
		{
			name:  "no sample yet",
			setup: func(h *fakeHub) { h.snaps["a1"] = grid.Snapshot{} },
			want:  []string{"Waiting for the first sample from the agent.", "Waiting for the unit list from the agent.", ">CPU<"},
			lack:  []string{"Per core", "<polyline"},
		},
		{
			name: "capabilities switched off",
			setup: func(h *fakeHub) {
				h.hosts[0].Capabilities = []string{protocol.CapMonitoring}
			},
			want: []string{"Service monitoring is switched off for this host."},
			lack: []string{"Open shell", "Restart failed units"},
		},
		{
			name: "reboot required from the agent",
			setup: func(h *fakeHub) {
				h.hosts[0].RebootRequired = true
			},
			want: []string{"Reboot required", `class="btn-alert ov-reboot"`},
			lack: []string{"hx-post=\"/hosts/alpha/reboot", "Shut down"},
		},
		{
			name: "no failed units",
			setup: func(h *fakeHub) {
				s := h.snaps["a1"]
				s.Services = &protocol.Services{Units: []protocol.ServiceUnit{{Name: "ssh.service", ActiveState: "active"}}}
				h.snaps["a1"] = s
			},
			want: []string{"All units running", " disabled>", "1/1 running"},
			lack: []string{"Restart failed units"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e, _ := newOverviewEnv(t)
			e.hub.mu.Lock()
			tc.setup(e.hub)
			e.hub.mu.Unlock()
			cookie, _ := e.signIn()
			rec := e.get("/hosts/alpha", withCookies(cookie))
			if rec.Code != 200 {
				t.Fatalf("status %d", rec.Code)
			}
			ovHave(t, rec.Body.String(), tc.want...)
			ovLack(t, rec.Body.String(), tc.lack...)
		})
	}
}

func TestOverviewRefreshesServicesInBackground(t *testing.T) {
	e, oh := newOverviewEnv(t)
	cookie, _ := e.signIn()

	if rec := e.get("/hosts/alpha", withCookies(cookie)); rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	select {
	case id := <-oh.refreshed:
		if id != "a1" {
			t.Errorf("refreshed %q", id)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no services refresh after viewing an online host")
	}

	// An offline host is not asked.
	if rec := e.get("/hosts/beta", withCookies(cookie)); rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	select {
	case id := <-oh.refreshed:
		t.Errorf("refresh for offline host %q", id)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestServicesRestart(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		csrf      bool
		restartFn func(string) error
		mutate    func(h *fakeHub)
		status    int
		want      []string
		calls     []string
	}{
		{
			name: "success restarts the failed units", path: "/hosts/alpha/services/restart", csrf: true, status: 200,
			want:  []string{`hx-swap-oob="beforeend:#toasts"`, "Restored", "alpha | systemctl restart", `role="status"`},
			calls: []string{"a1/smbd.service"},
		},
		{
			name: "several failed units", path: "/hosts/alpha/services/restart", csrf: true, status: 200,
			mutate: func(h *fakeHub) {
				s := h.snaps["a1"]
				s.Services = &protocol.Services{Units: []protocol.ServiceUnit{
					{Name: "a.service", ActiveState: "failed"}, {Name: "b.service", ActiveState: "active"}, {Name: "c.service", ActiveState: "failed"}}}
				h.snaps["a1"] = s
			},
			want:  []string{"Restored"},
			calls: []string{"a1/a.service", "a1/c.service"},
		},
		{
			name: "nothing failed", path: "/hosts/alpha/services/restart", csrf: true, status: 200,
			mutate: func(h *fakeHub) {
				s := h.snaps["a1"]
				s.Services = &protocol.Services{Units: []protocol.ServiceUnit{{Name: "ssh.service", ActiveState: "active"}}}
				h.snaps["a1"] = s
			},
			want: []string{"Nothing to do"},
		},
		{
			name: "no csrf token", path: "/hosts/alpha/services/restart", csrf: false, status: 403,
		},
		{
			name: "offline host", path: "/hosts/beta/services/restart", csrf: true, status: 409,
			want: []string{"The host is offline."},
		},
		{
			name: "unknown host", path: "/hosts/nope/services/restart", csrf: true, status: 404,
		},
		{
			name: "host went offline meanwhile", path: "/hosts/alpha/services/restart", csrf: true, status: 409,
			restartFn: func(string) error { return grid.ErrHostOffline },
			want:      []string{"The host is offline."},
			calls:     []string{"a1/smbd.service"},
		},
		{
			name: "capability switched off", path: "/hosts/alpha/services/restart", csrf: true, status: 403,
			restartFn: func(string) error { return grid.ErrCapabilityDisabled },
			want:      []string{"This feature is switched off for the host."},
			calls:     []string{"a1/smbd.service"},
		},
		{
			name: "agent timeout", path: "/hosts/alpha/services/restart", csrf: true, status: 504,
			restartFn: func(string) error { return context.DeadlineExceeded },
			calls:     []string{"a1/smbd.service"},
		},
		{
			name: "unexpected error is not echoed", path: "/hosts/alpha/services/restart", csrf: true, status: 500,
			restartFn: func(string) error { return errors.New("secret detail from the agent") },
			want:      []string{"Something went wrong."},
			calls:     []string{"a1/smbd.service"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e, oh := newOverviewEnv(t)
			oh.restartFn = tc.restartFn
			if tc.mutate != nil {
				e.hub.mu.Lock()
				tc.mutate(e.hub)
				e.hub.mu.Unlock()
			}
			cookie, csrf := e.signIn()
			opts := []reqOpt{withCookies(cookie)}
			if tc.csrf {
				opts = append(opts, withHeader("X-CSRF-Token", csrf))
			}
			rec := e.post(tc.path, opts...)
			if rec.Code != tc.status {
				t.Fatalf("status %d, want %d (%q)", rec.Code, tc.status, rec.Body.String())
			}
			ovHave(t, rec.Body.String(), tc.want...)
			ovLack(t, rec.Body.String(), "secret detail")
			got := oh.calls()
			if strings.Join(got, ",") != strings.Join(tc.calls, ",") {
				t.Errorf("restarts %v, want %v", got, tc.calls)
			}
			if len(tc.calls) > 0 {
				oh.mu.Lock()
				actor := oh.actors[0]
				oh.mu.Unlock()
				if actor.Operator != testOperator || actor.IP == "" {
					t.Errorf("actor %+v", actor)
				}
			}
		})
	}
}

func TestServicesRestartCSRFFromForm(t *testing.T) {
	e, oh := newOverviewEnv(t)
	cookie, csrf := e.signIn()
	rec := e.post("/hosts/alpha/services/restart", withCookies(cookie), withForm(url.Values{"csrf_token": {csrf}}))
	if rec.Code != 200 || len(oh.calls()) != 1 {
		t.Fatalf("status %d, calls %v", rec.Code, oh.calls())
	}
	if rec := e.post("/hosts/alpha/services/restart", withCookies(cookie), withHeader("X-CSRF-Token", "wrong")); rec.Code != 403 {
		t.Errorf("wrong token: status %d", rec.Code)
	}
}

func TestServicesRestartRejectsGET(t *testing.T) {
	e, oh := newOverviewEnv(t)
	cookie, _ := e.signIn()
	if rec := e.get("/hosts/alpha/services/restart", withCookies(cookie)); rec.Code == 200 {
		t.Errorf("GET answered 200")
	}
	if len(oh.calls()) != 0 {
		t.Errorf("GET restarted units: %v", oh.calls())
	}
}

func TestOverviewSSERenderers(t *testing.T) {
	e, _ := newOverviewEnv(t)
	req := httptest.NewRequest("GET", "/events?host=alpha", nil)

	type got struct{ name, html string }
	run := func(ev grid.Event) []got {
		var out []got
		for _, fn := range e.srv.sse.renderers(ev.Kind) {
			if name, html, ok := fn(req, ev); ok {
				out = append(out, got{name, html})
			}
		}
		return out
	}
	byName := func(gs []got, name string) string {
		for _, g := range gs {
			if g.name == name {
				return g.html
			}
		}
		return ""
	}

	t.Run("metrics value", func(t *testing.T) {
		gs := run(grid.Event{Kind: grid.EventMetrics, Host: "a1", Payload: *sampleOvMetrics()})
		if len(gs) != 3 {
			t.Fatalf("%d events, want 3: %+v", len(gs), gs)
		}
		if h := byName(gs, "ov-load"); h != "0.42 0.38 0.35" {
			t.Errorf("load %q", h)
		}
		ovHave(t, byName(gs, "ov-cpu"), "Currently at 24% utilisation", "Core 2", "Top processes", "plexmediaserver", "data-ov-procs")
		ovHave(t, byName(gs, "ov-mem"), "3.4 / 8 GB", "CPU · LAST 8 S", "<polyline", "24%", `href="/hosts/alpha/shell"`)
		for _, g := range gs {
			if strings.HasPrefix(g.html, "\n") || strings.HasSuffix(g.html, "\n") {
				t.Errorf("%s not trimmed", g.name)
			}
		}
	})

	t.Run("metrics pointer", func(t *testing.T) {
		if gs := run(grid.Event{Kind: grid.EventMetrics, Host: "a1", Payload: sampleOvMetrics()}); len(gs) != 3 {
			t.Errorf("%d events, want 3", len(gs))
		}
	})

	t.Run("services", func(t *testing.T) {
		gs := run(grid.Event{Kind: grid.EventServices, Host: "a1", Payload: *sampleOvServices()})
		if len(gs) != 1 || gs[0].name != "ov-svc" {
			t.Fatalf("%+v", gs)
		}
		ovHave(t, gs[0].html, "2/3 running", "smbd", "failed", "Restart failed units (1)", `hx-post="/hosts/alpha/services/restart"`)
		ovLack(t, gs[0].html, "smbd.service")
	})

	t.Run("host state", func(t *testing.T) {
		for _, tc := range []struct {
			kind grid.EventKind
			want string
		}{{grid.EventHostOnline, "a1 online"}, {grid.EventHostOffline, "b2 offline"}} {
			id := grid.HostID(strings.Fields(tc.want)[0])
			gs := run(grid.Event{Kind: tc.kind, Host: id, Payload: grid.HostInfo{ID: id}})
			if len(gs) != 1 || gs[0].name != "ov-state" || gs[0].html != tc.want {
				t.Errorf("%s: %+v", tc.kind, gs)
			}
		}
	})

	t.Run("unusable payloads are skipped", func(t *testing.T) {
		for _, ev := range []grid.Event{
			{Kind: grid.EventMetrics, Host: "a1", Payload: "nope"},
			{Kind: grid.EventMetrics, Host: "a1", Payload: (*protocol.Metrics)(nil)},
			{Kind: grid.EventServices, Host: "a1", Payload: 42},
			{Kind: grid.EventServices, Host: "zz", Payload: *sampleOvServices()}, // unknown host
			{Kind: grid.EventHostOffline, Host: "b2"},                            // no HostInfo payload
		} {
			if gs := run(ev); len(gs) != 0 {
				t.Errorf("%+v rendered %+v", ev, gs)
			}
		}
	})

	t.Run("without a renderer nothing is rendered", func(t *testing.T) {
		e2, _ := newOverviewEnv(t)
		e2.srv.renderer = nil
		for _, fn := range e2.srv.sse.renderers(grid.EventMetrics) {
			if name, html, ok := fn(req, grid.Event{Kind: grid.EventMetrics, Host: "a1", Payload: *sampleOvMetrics()}); ok && name != "ov-load" {
				t.Errorf("%s rendered %q without a renderer", name, html)
			}
		}
	})
}

func TestOverviewEventStream(t *testing.T) {
	e, _ := newOverviewEnv(t)
	e.srv.sseHeartbeat = time.Hour
	ts := httptest.NewServer(e.srv.Handler())
	t.Cleanup(ts.Close)
	cookie, _ := e.signIn()

	c := openStream(t, ts, "/events?host=alpha", withCookies(cookie))
	waitFor(t, "subscription", func() bool { return e.hub.subscribers() == 1 })

	e.hub.emit(grid.Event{Kind: grid.EventMetrics, Host: "b2", Payload: *sampleOvMetrics()}) // other host: filtered
	e.hub.emit(grid.Event{Kind: grid.EventMetrics, Host: "a1", Payload: *sampleOvMetrics()})

	names := map[string][]string{}
	for range 3 {
		block := c.nextEvent(t)
		if !strings.HasPrefix(block[0], "event: ") {
			t.Fatalf("block %q", block)
		}
		names[strings.TrimPrefix(block[0], "event: ")] = block[1:]
	}
	for _, n := range []string{"ov-load", "ov-cpu", "ov-mem"} {
		if names[n] == nil {
			t.Errorf("event %s missing (got %v)", n, names)
		}
	}
	if got := strings.Join(names["ov-load"], ""); got != "data: 0.42 0.38 0.35" {
		t.Errorf("load block %q", got)
	}
	// Every line of a multi-line fragment carries its own data: field.
	for _, l := range names["ov-cpu"] {
		if !strings.HasPrefix(l, "data: ") {
			t.Errorf("line without data: %q", l)
		}
	}
}

func TestOverviewEscapesHostData(t *testing.T) {
	e, _ := newOverviewEnv(t)
	e.hub.mu.Lock()
	e.hub.hosts[0].DisplayName = `<script>alert(1)</script>`
	e.hub.hosts[0].Model = `<img src=x onerror=alert(1)>`
	s := e.hub.snaps["a1"]
	s.Services = &protocol.Services{Units: []protocol.ServiceUnit{{Name: `<b>x</b>.service`, ActiveState: "failed"}}}
	e.hub.snaps["a1"] = s
	e.hub.mu.Unlock()
	cookie, _ := e.signIn()
	body := e.get("/hosts/alpha", withCookies(cookie)).Body.String()
	ovLack(t, body, "<script>alert", "<img src=x", "<b>x</b>")
	ovHave(t, body, "&lt;script&gt;alert(1)&lt;/script&gt;", "&lt;img src=x onerror=alert(1)&gt;", "&lt;b&gt;x&lt;/b&gt;")
}
