package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/phabioo/nexara/internal/hub/grid"
)

// RemoveHost of the shared fake: the other tests never remove hosts.
func (h *fakeHub) RemoveHost(context.Context, grid.Actor, grid.HostID) error { return errFake }

// RemoveHost of the overview fake records the call and drops the host from the fake registry, like the
// real grid does.
func (h *overviewHub) RemoveHost(_ context.Context, actor grid.Actor, id grid.HostID) error {
	h.mu.Lock()
	h.removed = append(h.removed, string(id))
	h.actors = append(h.actors, actor)
	fn := h.removeFn
	h.mu.Unlock()
	if fn != nil {
		if err := fn(id); err != nil {
			return err
		}
	}
	h.fakeHub.mu.Lock()
	defer h.fakeHub.mu.Unlock()
	h.fakeHub.hosts = slices.DeleteFunc(h.fakeHub.hosts, func(x grid.HostInfo) bool { return x.ID == id })
	return nil
}

func (h *overviewHub) removals() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.removed)
}

func TestRemoveHostPost(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		csrf     bool
		htmx     bool
		removeFn func(grid.HostID) error
		hosts    func(h *fakeHub)
		status   int
		location string // Location (303) or the "path" of HX-Location (htmx)
		removed  []string
	}{
		{name: "online host, next tab", path: "/hosts/alpha/remove", csrf: true, status: 303, location: "/hosts/beta", removed: []string{"a1"}},
		{name: "last tab goes left", path: "/hosts/beta/remove", csrf: true, status: 303, location: "/hosts/alpha", removed: []string{"b2"}},
		{
			name: "only host leads to the empty state", path: "/hosts/alpha/remove", csrf: true, status: 303, location: "/", removed: []string{"a1"},
			hosts: func(h *fakeHub) { h.hosts = h.hosts[:1] },
		},
		{name: "htmx gets HX-Location, not a 303 the XHR would follow", path: "/hosts/beta/remove", csrf: true, htmx: true, status: 204, location: "/hosts/alpha", removed: []string{"b2"}},
		{name: "no csrf token", path: "/hosts/alpha/remove", csrf: false, status: 403},
		{name: "unknown host", path: "/hosts/nope/remove", csrf: true, status: 404},
		{
			name: "host vanished meanwhile", path: "/hosts/alpha/remove", csrf: true, status: 404, removed: []string{"a1"},
			removeFn: func(grid.HostID) error { return grid.ErrHostNotFound },
		},
		{
			name: "unexpected error is not echoed", path: "/hosts/alpha/remove", csrf: true, status: 500, removed: []string{"a1"},
			removeFn: func(grid.HostID) error { return errors.New("secret detail") },
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e, oh := newOverviewEnv(t)
			oh.removeFn = tc.removeFn
			if tc.hosts != nil {
				e.hub.mu.Lock()
				tc.hosts(e.hub)
				e.hub.mu.Unlock()
			}
			cookie, csrf := e.signIn()
			opts := []reqOpt{withCookies(cookie)}
			if tc.csrf {
				opts = append(opts, withHeader("X-CSRF-Token", csrf))
			}
			if tc.htmx {
				opts = append(opts, withHeader("HX-Request", "true"))
			}
			rec := e.post(tc.path, opts...)
			if rec.Code != tc.status {
				t.Fatalf("status %d, want %d (%q)", rec.Code, tc.status, rec.Body.String())
			}
			if tc.location != "" {
				got := rec.Header().Get("Location")
				if tc.htmx {
					if rec.Header().Get("Location") != "" || rec.Header().Get("HX-Redirect") != "" {
						t.Errorf("htmx answer carries Location %q / HX-Redirect %q, a page load is what it must avoid",
							rec.Header().Get("Location"), rec.Header().Get("HX-Redirect"))
					}
					var loc map[string]string
					if err := json.Unmarshal([]byte(rec.Header().Get("HX-Location")), &loc); err != nil {
						t.Fatalf("HX-Location %q: %v", rec.Header().Get("HX-Location"), err)
					}
					// Navigates like a boosted link: only #main and the shell regions change.
					if loc["target"] != "#main" || loc["select"] != "#main" || loc["swap"] != "outerHTML" ||
						!strings.Contains(loc["selectOOB"], "#nx-tabs") || !strings.Contains(loc["selectOOB"], "#nx-nav") {
						t.Errorf("HX-Location does not navigate like a boosted link: %v", loc)
					}
					got = loc["path"]
				}
				if got != tc.location {
					t.Errorf("redirect to %q, want %q", got, tc.location)
				}
			}
			ovLack(t, rec.Body.String(), "secret detail")
			if got := oh.removals(); !slices.Equal(got, tc.removed) {
				t.Errorf("removals %v, want %v", got, tc.removed)
			}
			if len(tc.removed) > 0 {
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

func TestRemoveHostRejectsGET(t *testing.T) {
	e, oh := newOverviewEnv(t)
	cookie, _ := e.signIn()
	// GET is the confirm dialog and must never remove anything.
	if rec := e.get("/hosts/alpha/remove", withCookies(cookie)); rec.Code != 200 {
		t.Fatalf("dialog status %d", rec.Code)
	}
	if len(oh.removals()) != 0 {
		t.Fatalf("GET removed hosts: %v", oh.removals())
	}
}

func TestRemoveHostRequiresSession(t *testing.T) {
	e, oh := newOverviewEnv(t)
	if rec := e.get("/hosts/alpha/remove"); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Errorf("GET without session: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if rec := e.post("/hosts/alpha/remove"); rec.Code == http.StatusSeeOther && rec.Header().Get("Location") == "/hosts/beta" {
		t.Error("POST without session removed the host")
	}
	if len(oh.removals()) != 0 {
		t.Fatalf("unauthenticated removal: %v", oh.removals())
	}
}

func TestRemoveConfirmDialog(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		hubOf  string // hub host name for the heuristic
		status int
		want   []string
		lack   []string
	}{
		{
			name: "online host", path: "/hosts/alpha/remove", hubOf: "frpi5", status: 200,
			want: []string{`role="dialog"`, "is-bad", "Remove alpha? Its agent loses access immediately. To add it again, link it as a new host.",
				`hx-post="/hosts/alpha/remove"`, "data-modal-close", "Remove host"},
			lack: []string{"hub&#39;s own agent", "hub's own agent"},
		},
		{
			name: "offline host uses the display name", path: "/hosts/beta/remove", hubOf: "frpi5", status: 200,
			want: []string{"Remove Beta Pi? Its agent loses access immediately.", `hx-post="/hosts/beta/remove"`},
		},
		{
			name: "hub's own host is flagged by name", path: "/hosts/alpha/remove", hubOf: "alpha", status: 200,
			want: []string{"This is the hub&#39;s own agent."},
		},
		{name: "unknown host", path: "/hosts/nope/remove", hubOf: "frpi5", status: 404},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			old := hubHostname
			hubHostname = func() string { return tc.hubOf }
			t.Cleanup(func() { hubHostname = old })
			e, _ := newOverviewEnv(t)
			cookie, _ := e.signIn()
			rec := e.get(tc.path, withCookies(cookie))
			if rec.Code != tc.status {
				t.Fatalf("status %d, want %d", rec.Code, tc.status)
			}
			ovHave(t, rec.Body.String(), tc.want...)
			ovLack(t, rec.Body.String(), tc.lack...)
		})
	}
}

func TestIsHubHost(t *testing.T) {
	old := hubHostname
	hubHostname = func() string { return "frpi5" }
	t.Cleanup(func() { hubHostname = old })
	tests := []struct {
		h    grid.HostInfo
		want bool
	}{
		{grid.HostInfo{Name: "frpi5", Address: "192.0.2.5"}, true},
		{grid.HostInfo{Name: "FRPI5"}, true},
		{grid.HostInfo{Name: "other", Address: "127.0.0.1"}, true},
		{grid.HostInfo{Name: "other", Address: "::1"}, true},
		{grid.HostInfo{Name: "other", Address: "localhost"}, true},
		{grid.HostInfo{Name: "other", Address: "192.0.2.9"}, false},
		{grid.HostInfo{Name: "pi5-media"}, false},
	}
	for _, tc := range tests {
		if got := isHubHost(tc.h); got != tc.want {
			t.Errorf("isHubHost(%+v) = %v, want %v", tc.h, got, tc.want)
		}
	}
}

func TestOverviewHasRemoveControls(t *testing.T) {
	e, _ := newOverviewEnv(t)
	cookie, _ := e.signIn()
	online := e.get("/hosts/alpha", withCookies(cookie)).Body.String()
	ovHave(t, online, `hx-get="/hosts/alpha/remove"`, "Remove host", `data-ov-host="alpha"`)
	offline := e.get("/hosts/beta", withCookies(cookie)).Body.String()
	ovHave(t, offline, `hx-get="/hosts/beta/remove"`, "Remove host", `data-ov-host="beta"`)
	e.hub.mu.Lock()
	e.hub.hosts = nil
	e.hub.mu.Unlock()
	empty := e.get("/", withCookies(cookie)).Body.String()
	ovLack(t, empty, "Remove host")
}

func TestNextHostURL(t *testing.T) {
	hosts := []grid.HostInfo{{ID: "a", Name: "a"}, {ID: "b", Name: "b c"}, {ID: "c", Name: "c"}}
	tests := []struct {
		id   grid.HostID
		want string
	}{
		{"a", "/hosts/b%20c"}, {"b", "/hosts/c"}, {"c", "/hosts/b%20c"}, {"zz", "/"},
	}
	for _, tc := range tests {
		if got := nextHostURL(hosts, tc.id); got != tc.want {
			t.Errorf("nextHostURL(%q) = %q, want %q", tc.id, got, tc.want)
		}
	}
	if got := nextHostURL(hosts[:1], "a"); got != "/" {
		t.Errorf("last host: %q", got)
	}
}
