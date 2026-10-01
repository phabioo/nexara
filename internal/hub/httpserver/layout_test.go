package httpserver

import (
	"net/http"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/hub/views"
	"github.com/phabioo/nexara/internal/protocol"
)

func TestLayoutModel(t *testing.T) {
	e := newEnv(t)
	temp := 47.2
	e.hub.mu.Lock()
	e.hub.hosts = []grid.HostInfo{
		{ID: "a1", Name: "alpha", Address: "192.0.2.21", Online: true, Latency: 4 * time.Millisecond},
		{ID: "b2", Name: "beta", DisplayName: "Beta Pi", Address: "192.0.2.22", Online: false, RebootRequired: true},
		{ID: "c3", Name: "gamma", Address: "192.0.2.23", Online: true},
	}
	e.hub.snaps["a1"] = grid.Snapshot{
		Metrics: &protocol.Metrics{TempC: &temp, UptimeSeconds: 3*86400 + 5*3600 + 59},
		Packages: &protocol.Packages{Items: []protocol.Package{
			{Name: "a", State: protocol.PackageInstalled},
			{Name: "b", State: protocol.PackageInstalled},
			{Name: "c", State: protocol.PackageUpdate},
			{Name: "d", State: protocol.PackageAvailable},
		}},
	}
	e.hub.snaps["b2"] = grid.Snapshot{Packages: &protocol.Packages{
		Items:          []protocol.Package{{Name: "x", State: protocol.PackageUpdate}, {Name: "y", State: protocol.PackageUpdate}},
		RebootRequired: true,
	}}
	e.hub.jobs["a1"] = []grid.Job{{ID: "j2", Kind: protocol.JobAptUpgrade, State: grid.JobDone}, {ID: "j1", Kind: protocol.JobAptUpdate, State: grid.JobDone}}
	e.hub.mu.Unlock()

	cookie, token := e.signIn()
	var got, none views.Layout
	mux := http.NewServeMux()
	mux.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
		h, _ := e.srv.hostByName("alpha")
		got = e.srv.layout(r, "packages", &h)
		none = e.srv.layout(r, "overview", nil)
	})
	e.do(e.srv.chain(mux), "GET", "/probe", withCookies(cookie))

	if got.CSRF != token {
		t.Errorf("CSRF = %q, want the session token", got.CSRF)
	}
	if got.Operator != testOperator || none.Operator != testOperator {
		t.Errorf("Operator = %q / %q, want %q", got.Operator, none.Operator, testOperator)
	}
	if got.Online != 2 {
		t.Errorf("Online = %d, want 2", got.Online)
	}
	if got.NodeNo != "01" || got.HostName != "alpha" || got.HostIP != "192.0.2.21" {
		t.Errorf("host fields: %q %q %q", got.NodeNo, got.HostName, got.HostIP)
	}
	if got.Uptime != "03D 05H" || got.Temp != "47.2" || got.Latency != "4 ms" || got.Packages != "2/3" {
		t.Errorf("pill: uptime=%q temp=%q latency=%q packages=%q", got.Uptime, got.Temp, got.Latency, got.Packages)
	}
	if got.Log != "apt upgrade · done" {
		t.Errorf("Log = %q", got.Log)
	}
	if got.HostKey != "alpha" || none.HostKey != "" {
		t.Errorf("HostKey = %q / %q, want the short name of the host on screen", got.HostKey, none.HostKey)
	}
	if got.EventsURL != "/events" || none.EventsURL != "/events" {
		t.Errorf("EventsURL = %q / %q", got.EventsURL, none.EventsURL)
	}
	if got.Job != nil {
		t.Errorf("Job = %+v, want none (both jobs are done)", got.Job)
	}
	if got.AddHostURL != "/hosts/new" || got.ActiveNav != "packages" {
		t.Errorf("AddHostURL=%q ActiveNav=%q", got.AddHostURL, got.ActiveNav)
	}

	wantTabs := []views.HostTab{
		{Name: "alpha", Href: "/hosts/alpha", Active: true, Badge: 1},
		{Name: "Beta Pi", Href: "/hosts/beta", Offline: true, Reboot: true, Badge: 2},
		{Name: "gamma", Href: "/hosts/gamma"},
	}
	if len(got.Hosts) != len(wantTabs) {
		t.Fatalf("tabs = %+v", got.Hosts)
	}
	for i, w := range wantTabs {
		if got.Hosts[i] != w {
			t.Errorf("tab %d = %+v, want %+v", i, got.Hosts[i], w)
		}
	}

	nav := map[string]views.NavItem{}
	for _, n := range got.Nav {
		nav[n.Key] = n
	}
	if nav["packages"].Href != "/hosts/alpha/packages" || nav["packages"].Badge != 1 ||
		nav["shell"].Href != "/hosts/alpha/shell" || nav["overview"].Href != "/hosts/alpha" {
		t.Errorf("nav = %+v", got.Nav)
	}

	// Without a host: no host data, no active tab, nav falls back to the overview.
	if none.HostName != "" || none.NodeNo != "" || none.Packages != "" || none.Temp != "" || none.Uptime != "" {
		t.Errorf("host data without host: %+v", none)
	}
	for _, tab := range none.Hosts {
		if tab.Active {
			t.Error("tab active without host")
		}
	}
	if none.Online != 2 || len(none.Hosts) != 3 {
		t.Errorf("tabs still expected: online=%d tabs=%d", none.Online, len(none.Hosts))
	}
	for _, n := range none.Nav {
		if n.Href != "/" {
			t.Errorf("nav %s = %q without a host, want /", n.Key, n.Href)
		}
	}
	if none.Log != "" || none.Job != nil {
		t.Errorf("status bar without host: log=%q job=%+v", none.Log, none.Job)
	}
}

func TestLayoutStatusBar(t *testing.T) {
	running := grid.Job{ID: "j7", Kind: protocol.JobAptUpgrade, State: grid.JobRunning}
	tests := []struct {
		name     string
		host     string
		jobs     []grid.Job
		wantLog  string
		wantChip string // href of the chip, empty for none
	}{
		{"online without jobs", "alpha", nil, "Connected to alpha", ""},
		{"offline host", "beta", nil, "Beta Pi is offline", ""},
		{"running job", "alpha", []grid.Job{running}, "apt upgrade · running", "/hosts/alpha/jobs/j7"},
		{"finished job keeps the log, no chip", "alpha", []grid.Job{{ID: "j8", Kind: protocol.JobAptClean, State: grid.JobDone}}, "apt clean · done", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			h, _ := e.srv.hostByName(tc.host)
			e.hub.mu.Lock()
			e.hub.jobs[h.ID] = tc.jobs
			e.hub.mu.Unlock()
			cookie, _ := e.signIn()
			var got views.Layout
			mux := http.NewServeMux()
			mux.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) { got = e.srv.layout(r, "overview", &h) })
			e.do(e.srv.chain(mux), "GET", "/probe", withCookies(cookie))
			if got.Log != tc.wantLog {
				t.Errorf("Log = %q, want %q", got.Log, tc.wantLog)
			}
			switch {
			case tc.wantChip == "" && got.Job != nil:
				t.Errorf("Job = %+v, want none", got.Job)
			case tc.wantChip != "" && (got.Job == nil || got.Job.Href != tc.wantChip):
				t.Errorf("Job = %+v, want href %s", got.Job, tc.wantChip)
			}
		})
	}
}

func TestFormatUptimeAndPill(t *testing.T) {
	if got := formatUptime(41*86400 + 6*3600 + 10); got != "41D 06H" {
		t.Errorf("formatUptime = %q", got)
	}
	if got := formatUptime(0); got != "00D 00H" {
		t.Errorf("formatUptime(0) = %q", got)
	}
	if packagePill(nil) != "" {
		t.Error("pill for unknown packages must be empty")
	}
}

func TestHostHelpers(t *testing.T) {
	e := newEnv(t)
	if _, ok := e.srv.hostByName("alpha"); !ok {
		t.Error("alpha not found")
	}
	if _, ok := e.srv.hostByName("missing"); ok {
		t.Error("missing host found")
	}
	if h, ok := e.srv.defaultHost(); !ok || h.Name != "alpha" {
		t.Errorf("defaultHost = %+v", h)
	}
	e.hub.mu.Lock()
	e.hub.hosts[0].Online = false
	e.hub.hosts[1].Online = true
	e.hub.mu.Unlock()
	if h, _ := e.srv.defaultHost(); h.Name != "beta" {
		t.Errorf("defaultHost should prefer an online host, got %q", h.Name)
	}

	cookie, _ := e.signIn()
	if rec := e.get("/hosts/unknown/packages", withCookies(cookie)); rec.Code != 501 {
		// Stub handlers do not call requireHost yet; the 404 path is covered below.
		t.Logf("stub status %d", rec.Code)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /hosts/{host}", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := e.srv.requireHost(w, r); ok {
			w.WriteHeader(204)
		}
	})
	if rec := e.do(e.srv.chain(mux), "GET", "/hosts/unknown", withCookies(cookie)); rec.Code != 404 {
		t.Errorf("unknown host = %d, want 404", rec.Code)
	}
	if rec := e.do(e.srv.chain(mux), "GET", "/hosts/alpha", withCookies(cookie)); rec.Code != 204 {
		t.Errorf("known host = %d, want 204", rec.Code)
	}
}
