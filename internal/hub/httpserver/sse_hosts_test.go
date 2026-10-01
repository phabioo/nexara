package httpserver

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/protocol"
)

func TestRenderHostsEvent(t *testing.T) {
	tests := []struct {
		name     string
		ev       grid.Event
		wantKind string
		wantHost string // "" = skipped
	}{
		{"added", grid.Event{Kind: grid.EventHostAdded, Host: "a1", Payload: grid.HostInfo{ID: "a1", Name: "alpha"}}, "added", "alpha"},
		{"online", grid.Event{Kind: grid.EventHostOnline, Host: "a1", Payload: grid.HostInfo{ID: "a1", Name: "alpha"}}, "online", "alpha"},
		{"offline", grid.Event{Kind: grid.EventHostOffline, Host: "b2", Payload: &grid.HostInfo{ID: "b2", Name: "beta"}}, "offline", "beta"},
		// A removed host is gone from the hub: its name has to come from the payload.
		{"removed", grid.Event{Kind: grid.EventHostRemoved, Host: "zz", Payload: grid.HostInfo{ID: "zz", Name: "gone"}}, "removed", "gone"},
		{"packages of a known host", grid.Event{Kind: grid.EventPackages, Host: "a1", Payload: protocol.Packages{}}, "packages", "alpha"},
		{"packages of an unknown host", grid.Event{Kind: grid.EventPackages, Host: "zz", Payload: protocol.Packages{}}, "", ""},
		{"no payload, unknown host", grid.Event{Kind: grid.EventHostOffline, Host: "zz"}, "", ""},
		{"other kinds are not host-list events", grid.Event{Kind: grid.EventMetrics, Host: "a1"}, "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := viewTestEnv(t)
			name, data, ok := e.srv.renderHostsEvent(nil, tc.ev)
			if ok != (tc.wantHost != "") {
				t.Fatalf("rendered = %v (%q)", ok, data)
			}
			if !ok {
				return
			}
			var got hostsEvent
			if err := json.Unmarshal([]byte(data), &got); err != nil {
				t.Fatalf("payload %q: %v", data, err)
			}
			if name != sseHosts || got.Kind != tc.wantKind || got.Host != tc.wantHost {
				t.Errorf("got %q %+v", name, got)
			}
			if strings.ContainsAny(data, "\r\n") {
				t.Errorf("payload spans lines: %q", data)
			}
		})
	}
}

// Every renderer of the app registers for the events it needs and nothing else; the host-list event is there
// for each of its kinds.
func TestHostsEventIsRegistered(t *testing.T) {
	e := viewTestEnv(t)
	for _, k := range []grid.EventKind{grid.EventHostAdded, grid.EventHostRemoved, grid.EventHostOnline, grid.EventHostOffline, grid.EventPackages} {
		found := false
		for _, r := range e.srv.sse.renderers(k) {
			if name, _, ok := r(nil, grid.Event{Kind: k, Host: "a1", Payload: grid.HostInfo{Name: "alpha"}}); ok && name == sseHosts {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: no %s renderer registered", k, sseHosts)
		}
	}
}

func TestEventID(t *testing.T) {
	e := viewTestEnv(t)
	tests := []struct {
		name  string
		event string
		ev    grid.Event
		want  string
	}{
		{"metrics of a known host", "ov-cpu", grid.Event{Kind: grid.EventMetrics, Host: "b2"}, "beta"},
		{"live pills", sseLive, grid.Event{Kind: grid.EventMetrics, Host: "a1"}, "alpha"},
		{"list reload", packagesEventChanged, grid.Event{Kind: grid.EventPackages, Host: "a1"}, "alpha"},
		{"host payload wins", "x", grid.Event{Kind: grid.EventHostRemoved, Host: "zz", Payload: grid.HostInfo{Name: "gone"}}, "gone"},
		{"unknown host", "x", grid.Event{Kind: grid.EventMetrics, Host: "zz"}, ""},
		{"job dialog is addressed by job id", packagesEventJob, grid.Event{Kind: grid.EventJobOutput, Host: "a1"}, ""},
		{"host list names its host in the payload", sseHosts, grid.Event{Kind: grid.EventHostOnline, Host: "a1"}, ""},
	}
	for _, tc := range tests {
		if got := e.srv.eventID(tc.event, tc.ev); got != tc.want {
			t.Errorf("%s: id %q, want %q", tc.name, got, tc.want)
		}
	}
}

// One stream serves every page and every host: the open stream of a page keeps running while the operator
// moves between hosts. Events of all hosts arrive, each naming its host in the SSE id, the host-agnostic ones
// with an empty id (which resets the id the browser remembers).
func TestUnfilteredStreamTagsEventsWithTheirHost(t *testing.T) {
	e := viewTestEnv(t)
	e.srv.sseHeartbeat = time.Hour
	ts := httptest.NewServer(e.srv.Handler())
	t.Cleanup(ts.Close)
	cookie, _ := e.signIn()

	c := openStream(t, ts, "/events", withCookies(cookie))
	waitFor(t, "subscription", func() bool { return e.hub.subscribers() == 1 })

	m := protocol.Metrics{Load: [3]float64{0.1, 0.2, 0.3}}
	e.hub.emit(grid.Event{Kind: grid.EventMetrics, Host: "a1", Payload: m})
	e.hub.emit(grid.Event{Kind: grid.EventMetrics, Host: "c3", Payload: m})
	e.hub.emit(grid.Event{Kind: grid.EventJobOutput, Host: "a1", Payload: grid.JobOutputEvent{JobID: "job-3", Line: grid.JobLine{Line: "x"}}})
	e.hub.emit(grid.Event{Kind: grid.EventHostOffline, Host: "b2", Payload: grid.HostInfo{ID: "b2", Name: "beta"}})

	type seen struct{ name, id, data string }
	var got []seen
	for len(got) < 14 {
		block := c.nextEvent(t)
		s := seen{}
		for _, l := range block {
			switch {
			case strings.HasPrefix(l, "event: "):
				s.name = strings.TrimPrefix(l, "event: ")
			case strings.HasPrefix(l, "id: "):
				s.id = strings.TrimPrefix(l, "id: ")
			case strings.HasPrefix(l, "data: "):
				s.data += strings.TrimPrefix(l, "data: ")
			}
		}
		got = append(got, s)
		if s.name == sseHosts {
			break
		}
	}
	ids := map[string]map[string]bool{} // event name -> ids seen
	for _, s := range got {
		if ids[s.name] == nil {
			ids[s.name] = map[string]bool{}
		}
		ids[s.name][s.id] = true
	}
	for _, name := range []string{"ov-load", "ov-cpu", "ov-mem", sseLive} {
		if !ids[name]["alpha"] || !ids[name]["gamma"] || len(ids[name]) != 2 {
			t.Errorf("%s: ids %v, want alpha and gamma (an unfiltered stream, every fragment tagged)", name, ids[name])
		}
	}
	if ids[packagesEventJob][""] != true || len(ids[packagesEventJob]) != 1 {
		t.Errorf("%s: ids %v, want only the empty one", packagesEventJob, ids[packagesEventJob])
	}
	last := got[len(got)-1]
	if last.name != sseHosts || last.id != "" || last.data != `{"kind":"offline","host":"beta"}` {
		t.Errorf("host list event = %+v", last)
	}
}
