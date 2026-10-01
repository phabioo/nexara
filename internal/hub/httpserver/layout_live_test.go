package httpserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/protocol"
)

// liveEvents renders an event with only the shared shell renderers registered, so the tests do not
// depend on any view.
func liveEvents(t *testing.T, e *env, ev grid.Event) (html string, ok bool) {
	t.Helper()
	reg := newEventRegistry()
	prev := e.srv.sse
	e.srv.sse = reg
	t.Cleanup(func() { e.srv.sse = prev })
	e.srv.registerLive()
	req := httptest.NewRequest("GET", "/events?host=alpha", nil)
	var out []string
	for _, fn := range reg.renderers(ev.Kind) {
		name, h, rendered := fn(req, ev)
		if !rendered {
			continue
		}
		if name != sseLive {
			t.Errorf("event name %q, want %q", name, sseLive)
		}
		out = append(out, h)
	}
	return strings.Join(out, "\n"), len(out) > 0
}

func TestLiveMetrics(t *testing.T) {
	temp := 47.26
	tests := []struct {
		name    string
		payload any
		want    []string
		lack    []string
		ok      bool
	}{
		{"value", protocol.Metrics{TempC: &temp, UptimeSeconds: 41*86400 + 6*3600},
			[]string{`hx-swap-oob="innerHTML:#pill-temp"`, "<span>47.3°</span>", `hx-swap-oob="innerHTML:#node-card-up"`, `41D 06H <span>UP</span>`}, nil, true},
		{"pointer", &protocol.Metrics{TempC: &temp}, []string{"#pill-temp"}, nil, true},
		{"no sensor", protocol.Metrics{UptimeSeconds: 3600}, []string{"#node-card-up", "00D 01H"}, []string{"#pill-temp"}, true},
		{"nil pointer", (*protocol.Metrics)(nil), nil, nil, false},
		{"wrong payload", "x", nil, nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newLoginEnv(t)
			html, ok := liveEvents(t, e, grid.Event{Kind: grid.EventMetrics, Host: "a1", Payload: tc.payload})
			if ok != tc.ok {
				t.Fatalf("rendered = %v, want %v", ok, tc.ok)
			}
			mustContain(t, html, tc.want...)
			mustNotContain(t, html, tc.lack...)
			mustNotContain(t, html, "ZgotmplZ", "<html", "\n\n")
		})
	}
}

func TestLivePackages(t *testing.T) {
	p := protocol.Packages{Items: []protocol.Package{
		{Name: "a", State: protocol.PackageInstalled}, {Name: "b", State: protocol.PackageUpdate}, {Name: "c", State: protocol.PackageAvailable},
	}}
	e := newLoginEnv(t)
	for _, payload := range []any{p, &p} {
		html, ok := liveEvents(t, e, grid.Event{Kind: grid.EventPackages, Host: "a1", Payload: payload})
		if !ok {
			t.Fatal("not rendered")
		}
		mustContain(t, html, `hx-swap-oob="innerHTML:#pill-pkg"`, "<span>1/2</span>")
	}
	if _, ok := liveEvents(t, e, grid.Event{Kind: grid.EventPackages, Host: "a1", Payload: 3}); ok {
		t.Error("a wrong payload was rendered")
	}
}

func TestLiveJob(t *testing.T) {
	running := grid.Job{ID: "job-9", Host: "a1", Kind: protocol.JobAptUpgrade, State: grid.JobRunning}
	done := running
	done.State = grid.JobDone
	tests := []struct {
		name   string
		ev     grid.Event
		jobs   []grid.Job // what the hub lists while the event is rendered
		want   []string
		lack   []string
		wantOK bool
	}{
		{"started shows the chip", grid.Event{Kind: grid.EventJobStarted, Host: "a1", Payload: running}, []grid.Job{running},
			[]string{`id="job-chip-slot"`, `hx-swap-oob="true"`, "JOB · apt upgrade · running", `hx-get="/hosts/alpha/jobs/job-9"`,
				`id="statusbar-log"`, "apt upgrade · running"}, nil, true},
		{"done empties the slot", grid.Event{Kind: grid.EventJobDone, Host: "a1", Payload: done}, []grid.Job{done},
			[]string{`id="job-chip-slot"`, "apt upgrade · done"}, []string{"hx-get", "btn-tool"}, true},
		{"next queued job takes over", grid.Event{Kind: grid.EventJobDone, Host: "a1", Payload: done},
			[]grid.Job{{ID: "job-10", Host: "a1", Kind: protocol.JobAptClean, State: grid.JobQueued}, done},
			[]string{"JOB · apt clean · queued", `hx-get="/hosts/alpha/jobs/job-10"`}, nil, true},
		{"unknown host", grid.Event{Kind: grid.EventJobDone, Host: "zz", Payload: done}, nil, nil, nil, false},
		{"wrong payload", grid.Event{Kind: grid.EventJobQueued, Host: "a1", Payload: "x"}, nil, nil, nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newLoginEnv(t)
			e.hub.jobs["a1"] = tc.jobs
			html, ok := liveEvents(t, e, tc.ev)
			if ok != tc.wantOK {
				t.Fatalf("rendered = %v, want %v", ok, tc.wantOK)
			}
			mustContain(t, html, tc.want...)
			mustNotContain(t, html, tc.lack...)
		})
	}
}

// Every app page has the event stream on <body> and the sink for the live values, whatever its view is.
func TestAppPagesCarryTheLiveShell(t *testing.T) {
	e := newLoginEnv(t)
	cookie, token := e.signIn()
	for _, path := range []string{"/", "/hosts/alpha", "/hosts/alpha/packages", "/hosts/alpha/shell"} {
		t.Run(path, func(t *testing.T) {
			rec := e.get(path, withCookies(cookie))
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d", rec.Code)
			}
			body := rec.Body.String()
			mustContain(t, body, `hx-ext="sse" sse-connect="/events?host=alpha`, `sse-swap="nx-live,pkg-job" hx-swap="none" data-oob-sink`,
				`id="job-chip-slot"`, `id="statusbar-log"`, `action="/logout"`, `name="csrf_token" value="`+token+`"`,
				`data-sheet-open="more-sheet"`, `frank`)
			if n := strings.Count(body, "sse-connect="); n != 1 {
				t.Errorf("%d event streams on the page, want 1", n)
			}
		})
	}
}

func TestEventsPing(t *testing.T) {
	e := newEnv(t)
	cookie, _ := e.signIn()
	if rec := e.get("/events/ping", withCookies(cookie)); rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
		t.Errorf("with session: %d %q", rec.Code, rec.Body.String())
	}
	// Without a session the middleware redirects to the login page, which is what nexus.js looks for.
	rec := e.get("/events/ping")
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Errorf("without session: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if rec := e.post("/events/ping", withCookies(cookie)); rec.Code == http.StatusNoContent {
		t.Error("POST must not be routed to the ping")
	}
}

// An EventSource stream of an expired session gets 401 (no redirect it could follow).
func TestEventsExpiredSession(t *testing.T) {
	e := newEnv(t)
	e.srv.sseHeartbeat = time.Hour
	if rec := e.get("/events?host=alpha"); rec.Code != http.StatusUnauthorized {
		t.Errorf("status %d, want 401", rec.Code)
	}
}
