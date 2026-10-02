package httpserver

import (
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/hub/views"
	"github.com/phabioo/nexara/internal/protocol"
)

func TestHostViewURL(t *testing.T) {
	tests := []struct {
		active, name, want string
	}{
		{"overview", "alpha", "/hosts/alpha"},
		{"packages", "alpha", "/hosts/alpha/packages"},
		{"shell", "alpha", "/hosts/alpha/shell"},
		{"", "alpha", "/hosts/alpha"},
		{"settings", "alpha", "/hosts/alpha"}, // a view that is not per host: the host's overview
		{"packages", "pi 4", "/hosts/pi%204/packages"},
		{"shell", "a/b", "/hosts/a%2Fb/shell"},
	}
	for _, tc := range tests {
		if got := hostViewURL(tc.active, tc.name); got != tc.want {
			t.Errorf("hostViewURL(%q, %q) = %q, want %q", tc.active, tc.name, got, tc.want)
		}
	}
}

// tabHosts is the host list of the tab tests: alpha online, beta offline (display name "Beta Pi"), gamma online.
func tabHosts() []grid.HostInfo {
	caps := []string{protocol.CapMonitoring, protocol.CapPackages, protocol.CapShell}
	return []grid.HostInfo{
		{ID: "a1", Name: "alpha", Address: "192.0.2.21", Online: true, Capabilities: caps},
		{ID: "b2", Name: "beta", DisplayName: "Beta Pi", Address: "192.0.2.22", Online: false, Capabilities: caps},
		{ID: "c3", Name: "gamma", Address: "192.0.2.23", Online: true, Capabilities: caps},
	}
}

// The tabs (and with them Q / E, which click the neighbouring tab) lead to the same view of the other host,
// whatever the number of hosts and their state.
func TestHostTabHrefsFollowTheActiveView(t *testing.T) {
	views3 := []struct{ active, suffix string }{
		{"overview", ""},
		{"packages", "/packages"},
		{"shell", "/shell"},
	}
	for _, v := range views3 {
		for n := 1; n <= 3; n++ {
			for _, current := range tabHosts()[:n] {
				name := fmt.Sprintf("%s with %d host(s), on %s", v.active, n, current.Name)
				t.Run(name, func(t *testing.T) {
					e := newEnv(t)
					hosts := tabHosts()[:n]
					e.hub.mu.Lock()
					e.hub.hosts = hosts
					e.hub.mu.Unlock()
					cookie, _ := e.signIn()
					var got views.Layout
					mux := http.NewServeMux()
					mux.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
						h, _ := e.srv.hostByName(current.Name)
						got = e.srv.layout(r, v.active, &h)
					})
					e.do(e.srv.chain(mux), "GET", "/probe", withCookies(cookie))

					if len(got.Hosts) != n {
						t.Fatalf("%d tabs, want %d", len(got.Hosts), n)
					}
					for i, tab := range got.Hosts {
						want := "/hosts/" + hosts[i].Name + v.suffix
						if tab.Href != want {
							t.Errorf("tab %d href = %q, want %q", i, tab.Href, want)
						}
						if tab.Active != (hosts[i].Name == current.Name) {
							t.Errorf("tab %d active = %v", i, tab.Active)
						}
						if tab.Offline != !hosts[i].Online {
							t.Errorf("tab %d offline = %v", i, tab.Offline)
						}
					}
					// The "+ Host" tab is a dialog, not a host view.
					if got.AddHostURL != "/hosts/new" {
						t.Errorf("AddHostURL = %q", got.AddHostURL)
					}
				})
			}
		}
	}
}

// A page that has no host on screen (the empty overview, nothing selected) sends its tabs to the host overviews.
func TestHostTabHrefsWithoutAHostGoToTheOverview(t *testing.T) {
	e := newEnv(t)
	e.hub.mu.Lock()
	e.hub.hosts = tabHosts()
	e.hub.mu.Unlock()
	cookie, _ := e.signIn()
	var got views.Layout
	mux := http.NewServeMux()
	mux.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) { got = e.srv.layout(r, "overview", nil) })
	e.do(e.srv.chain(mux), "GET", "/probe", withCookies(cookie))
	for i, tab := range got.Hosts {
		if want := "/hosts/" + tabHosts()[i].Name; tab.Href != want || tab.Active {
			t.Errorf("tab %d = %+v, want href %q, inactive", i, tab, want)
		}
	}
}

var tabHrefRe = regexp.MustCompile(`<a class="tab(?: on)?" href="([^"]+)"`)

// tabHrefs reads the hrefs of the host tabs out of a rendered page, in order.
func tabHrefs(body string) []string {
	if i := strings.Index(body, `<nav class="hosttabs"`); i >= 0 {
		body = body[i:]
		if j := strings.Index(body, "</nav>"); j >= 0 {
			body = body[:j]
		}
	}
	var out []string
	for _, m := range tabHrefRe.FindAllStringSubmatch(body, -1) {
		out = append(out, html.UnescapeString(m[1]))
	}
	return out
}

// switchEnv has distinct data per host so that a page of one host showing anything of another is noticed:
// alpha (everything on), beta (offline, last known packages), gamma (online, shell and packages switched off).
func switchEnv(t *testing.T) *env {
	t.Helper()
	e := viewTestEnv(t)
	all := []string{protocol.CapMonitoring, protocol.CapPackages, protocol.CapServices, protocol.CapShell}
	e.hub.mu.Lock()
	e.hub.hosts = []grid.HostInfo{
		{ID: "a1", Name: "alpha", Address: "192.0.2.21", Online: true, Capabilities: all},
		{ID: "b2", Name: "beta", DisplayName: "Beta Pi", Address: "192.0.2.22", Online: false, Capabilities: all, LastSeen: time.Now().Add(-time.Hour)},
		{ID: "c3", Name: "gamma", Address: "192.0.2.23", Online: true, Capabilities: []string{protocol.CapMonitoring}},
	}
	pkgs := func(name string) *protocol.Packages {
		return &protocol.Packages{Items: []protocol.Package{{Name: name, State: protocol.PackageUpdate, CandidateVersion: "2", InstalledVersion: "1"}}}
	}
	e.hub.snaps["a1"] = grid.Snapshot{Packages: pkgs("alpha-only-pkg")}
	e.hub.snaps["b2"] = grid.Snapshot{Packages: pkgs("beta-only-pkg")}
	e.hub.snaps["c3"] = grid.Snapshot{Packages: pkgs("gamma-only-pkg")}
	e.hub.mu.Unlock()
	return e
}

var portraitRe = regexp.MustCompile(`host-portrait-title t-display">([^<]*)<`)

// Following a tab of the current view lands on the proper state of that view for the other host: the offline
// card for a host that is away, the "switched off" card for a disabled capability, the live view otherwise.
// Nothing of the host we came from is in the answer, and the shell regions name the new host.
func TestFollowingATabShowsTheStateOfTheNewHost(t *testing.T) {
	boosted := []reqOpt{withHeader("HX-Request", "true"), withHeader("HX-Boosted", "true"), withHeader("HX-Target", "main")}
	otherPkgs := map[string][]string{"alpha": {"beta-only-pkg", "gamma-only-pkg"}, "beta": {"alpha-only-pkg", "gamma-only-pkg"}, "gamma": {"alpha-only-pkg", "beta-only-pkg"}}
	label := map[string]string{"alpha": "alpha", "beta": "Beta Pi", "gamma": "gamma"}

	type want struct {
		contain, absent []string
	}
	cases := []struct {
		view, suffix string
		perHost      map[string]want
	}{
		{"shell", "/shell", map[string]want{
			"alpha": {contain: []string{`data-state="ready"`, `data-ws="/hosts/alpha/shell/ws?csrf=`}},
			"beta":  {contain: []string{`data-state="offline"`, "Beta Pi · Offline", "Back to overview"}, absent: []string{"data-ws=", "data-shell-term", "data-key="}},
			"gamma": {contain: []string{`data-state="disabled"`, "Shell disabled", "Back to overview"}, absent: []string{"data-ws=", "data-shell-term", "· Offline"}},
		}},
		{"packages", "/packages", map[string]want{
			"alpha": {contain: []string{"alpha-only-pkg", "APT · alpha"}, absent: []string{"is offline", "switched off"}},
			"beta":  {contain: []string{"beta-only-pkg", "APT · Beta Pi", "Beta Pi is offline"}, absent: []string{"switched off"}},
			"gamma": {contain: []string{"APT · gamma", "Package management is switched off for gamma"}, absent: []string{"is offline"}},
		}},
		{"overview", "", map[string]want{
			"alpha": {contain: []string{"Overview: alpha"}, absent: []string{"ov-offline-card"}},
			"beta":  {contain: []string{"Beta Pi · Offline", "ov-offline-card"}, absent: []string{"ov-cpu"}},
			"gamma": {contain: []string{"Overview: gamma"}, absent: []string{"ov-offline-card"}},
		}},
	}
	for _, c := range cases {
		for _, from := range []string{"alpha", "beta", "gamma"} {
			t.Run(c.view+" from "+from, func(t *testing.T) {
				e := switchEnv(t)
				cookie, _ := e.signIn()
				page := e.get("/hosts/"+from+c.suffix, withCookies(cookie)).Body.String()
				hrefs := tabHrefs(page)
				if len(hrefs) != 3 {
					t.Fatalf("tabs %v", hrefs)
				}
				for _, href := range hrefs {
					to := strings.TrimSuffix(strings.TrimPrefix(href, "/hosts/"), c.suffix)
					if want := "/hosts/" + to + c.suffix; href != want || label[to] == "" {
						t.Fatalf("tab href %q does not keep the %s view", href, c.view)
					}
					rec := e.get(href, append([]reqOpt{withCookies(cookie)}, boosted...)...)
					if rec.Code != http.StatusOK {
						t.Fatalf("%s: status %d", href, rec.Code)
					}
					body := rec.Body.String()
					w := c.perHost[to]
					mustContain(t, body, append([]string{`data-host="` + to + `" data-view="` + c.view + `"`}, w.contain...)...)
					mustNotContain(t, body, w.absent...)
					if c.view == "packages" {
						mustNotContain(t, body, otherPkgs[to]...)
					}
					// The regions swapped out of band name the new host and keep the view.
					if m := portraitRe.FindStringSubmatch(body); m == nil || m[1] != label[to] {
						t.Errorf("%s: portrait %v, want %q", href, m, label[to])
					}
					for _, h := range tabHrefs(body) {
						if !strings.HasSuffix(h, c.suffix) {
							t.Errorf("%s: tab href %q left the view", href, h)
						}
					}
					mustContain(t, body, `href="/hosts/`+to+c.suffix+`" aria-current="page"`,
						`href="/hosts/`+to+`/shell"`, `href="/hosts/`+to+`/packages"`)
					wantCurrent := 3 // the tab, the sidebar link, the bottom-bar link
					if c.view == "packages" {
						wantCurrent++ // the "All" filter chip
					}
					if n := strings.Count(body, `aria-current="page"`); n != wantCurrent {
						t.Errorf("%s: %d items marked current, want %d", href, n, wantCurrent)
					}
				}
			})
		}
	}
}

// A host-bound fragment of a host the hub no longer knows has no host to tag it with. The browser could not tell
// it from the view on screen, so the stream drops it instead of sending it with an empty id.
func TestStreamDropsHostBoundEventsOfUnknownHosts(t *testing.T) {
	e := viewTestEnv(t)
	e.srv.sseHeartbeat = time.Hour
	ts := httptest.NewServer(e.srv.Handler())
	t.Cleanup(ts.Close)
	cookie, _ := e.signIn()
	c := openStream(t, ts, "/events", withCookies(cookie))
	waitFor(t, "subscription", func() bool { return e.hub.subscribers() == 1 })

	m := protocol.Metrics{Load: [3]float64{0.1, 0.2, 0.3}}
	e.hub.emit(grid.Event{Kind: grid.EventMetrics, Host: "gone", Payload: m}) // removed a moment ago
	e.hub.emit(grid.Event{Kind: grid.EventMetrics, Host: "a1", Payload: m})

	for i := 0; i < 4; i++ { // the fragments of one event: load, cpu, memory, live pills
		var name, id string
		for _, l := range c.nextEvent(t) {
			switch {
			case strings.HasPrefix(l, "event: "):
				name = strings.TrimPrefix(l, "event: ")
			case strings.HasPrefix(l, "id: "):
				id = strings.TrimPrefix(l, "id: ")
			}
		}
		if id != "alpha" {
			t.Fatalf("event %d (%s) has id %q: the first event on the stream must be the one of alpha", i, name, id)
		}
	}
}
