package httpserver

import (
	"context"
	"errors"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/auth"
	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/hub/views"
	"github.com/phabioo/nexara/internal/protocol"
	"github.com/phabioo/nexara/web"
)

// pkgHub wraps the shared fake hub with scriptable package and job calls.
type pkgHub struct {
	*fakeHub

	mu        sync.Mutex
	startErr  error
	started   []grid.JobSpec
	startedOn []grid.HostID
	actors    []grid.Actor
	cancelErr error
	canceled  []string
	found     []protocol.Package
	searchErr error
	queries   []string
	refreshed int
	onRefresh func()
}

func (h *pkgHub) StartJob(_ context.Context, actor grid.Actor, id grid.HostID, spec grid.JobSpec) (grid.Job, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.startErr != nil {
		return grid.Job{}, h.startErr
	}
	h.started = append(h.started, spec)
	h.startedOn = append(h.startedOn, id)
	h.actors = append(h.actors, actor)
	job := grid.Job{ID: "job-0001", Host: id, Kind: spec.Kind, Package: spec.Package, State: grid.JobRunning, RequestedBy: actor.Operator}
	h.fakeHub.mu.Lock()
	h.fakeHub.jobs[id] = append([]grid.Job{job}, h.fakeHub.jobs[id]...)
	h.fakeHub.mu.Unlock()
	return job, nil
}

func (h *pkgHub) CancelJob(_ context.Context, _ grid.Actor, jobID string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.canceled = append(h.canceled, jobID)
	return h.cancelErr
}

func (h *pkgHub) SearchPackages(_ context.Context, _ grid.HostID, q string) ([]protocol.Package, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.queries = append(h.queries, q)
	return h.found, h.searchErr
}

func (h *pkgHub) RefreshPackages(context.Context, grid.HostID) error {
	h.mu.Lock()
	h.refreshed++
	fn := h.onRefresh
	h.mu.Unlock()
	if fn != nil {
		fn()
	}
	return nil
}

func (h *pkgHub) calls() (started []grid.JobSpec, canceled, queries []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]grid.JobSpec(nil), h.started...), append([]string(nil), h.canceled...), append([]string(nil), h.queries...)
}

type pkgEnv struct {
	*env
	ph     *pkgHub
	cookie *http.Cookie
	csrf   string
}

func newPackagesEnv(t *testing.T) *pkgEnv {
	t.Helper()
	e := newEnv(t)
	rd, err := views.New(web.Templates, views.Options{})
	if err != nil {
		t.Fatal(err)
	}
	e.srv.renderer = rd
	for i := range e.hub.hosts {
		e.hub.hosts[i].Capabilities = []string{protocol.CapPackages}
	}
	e.hub.snaps["a1"] = grid.Snapshot{Packages: &protocol.Packages{Items: []protocol.Package{
		{Name: "curl", Summary: "URL client", InstalledVersion: "7.88", SizeBytes: 315_000, State: protocol.PackageInstalled},
		{Name: "openssh-server", Summary: "ssh server", InstalledVersion: "9.2u3", CandidateVersion: "9.2u4", SizeBytes: 1_400_000, State: protocol.PackageUpdate},
		{Name: "linux-image-rpi-v8", Summary: "kernel", InstalledVersion: "6.6.51", CandidateVersion: "6.6.62", SizeBytes: 78_000_000, State: protocol.PackageUpdate},
		{Name: "old-lib", Summary: "unused", InstalledVersion: "1.0", SizeBytes: 1_100_000, State: protocol.PackageOrphaned},
	}}}
	ph := &pkgHub{fakeHub: e.hub}
	e.srv.hub = ph
	cookie, csrf := e.signIn()
	return &pkgEnv{env: e, ph: ph, cookie: cookie, csrf: csrf}
}

func (p *pkgEnv) getAs(target string, opts ...reqOpt) *httptest.ResponseRecorder {
	return p.get(target, append([]reqOpt{withCookies(p.cookie)}, opts...)...)
}

// postAs posts a form as the signed-in operator with the CSRF header.
func (p *pkgEnv) postAs(target string, form url.Values, opts ...reqOpt) *httptest.ResponseRecorder {
	base := []reqOpt{withCookies(p.cookie), withHeader(auth.CSRFHeader, p.csrf)}
	if form != nil {
		base = append(base, withForm(form))
	}
	return p.post(target, append(base, opts...)...)
}

// noFiltered fails if html/template replaced a value it did not trust (ZgotmplZ), which silently
// drops attributes such as data-modal-close.
func noFiltered(t *testing.T, body string) {
	t.Helper()
	if strings.Contains(body, "ZgotmplZ") {
		t.Errorf("template output contains a filtered value (ZgotmplZ)")
	}
}

// pkgStreamReq is the request of an open event stream of the packages page.
func pkgStreamReq() *http.Request {
	return httptest.NewRequest("GET", "/events?host=alpha&view=packages", nil)
}

func htmx() reqOpt { return withHeader("HX-Request", "true") }

func TestPackagesPage(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		opts     []reqOpt
		setup    func(*pkgEnv)
		code     int
		contains []string
		absent   []string
		queries  []string
	}{
		{
			name: "default page", target: "/hosts/alpha/packages", code: 200,
			contains: []string{
				"<title>Packages", `sse-connect="/events?host=alpha&amp;view=packages"`, `sse-swap="pkg-job"`,
				"openssh-server", "linux-image-rpi-v8", "curl", "old-lib",
				"1.4 MB", "315 KB", "Sync sources", "System upgrade", "Clean up", "apt update", "apt upgrade", "autoremove &#43; clean",
				"2 updates available", "2 updates ready, including kernel and OpenSSH.", `aria-current="page"`, `name="filter" value="all"`,
				`hx-post="/hosts/alpha/packages/pkg-upgrade"`, `hx-get="/hosts/alpha/packages/confirm/pkg-remove"`,
				`hx-get="/hosts/alpha/packages/confirm/apt-upgrade"`, `hx-post="/hosts/alpha/packages/apt-update"`,
				"packages.js", "APT", "SEARCH",
			},
			absent: []string{"is offline", "A reboot is required"},
		},
		{
			name: "updates filter", target: "/hosts/alpha/packages?filter=updates", code: 200,
			contains: []string{"openssh-server", "linux-image-rpi-v8", `name="filter" value="updates"`},
			absent:   []string{">curl<", ">old-lib<"},
		},
		{
			name: "orphaned filter", target: "/hosts/alpha/packages?filter=orphaned", code: 200,
			contains: []string{"old-lib"}, absent: []string{">curl<", ">openssh-server<"},
		},
		{
			name: "search narrows the list and asks the repositories", target: "/hosts/alpha/packages?q=cur", code: 200,
			contains: []string{">curl<", `value="cur"`}, absent: []string{">openssh-server<"}, queries: []string{"cur"},
		},
		{
			name: "one character is not searched remotely", target: "/hosts/alpha/packages?q=c", code: 200,
			contains: []string{">curl<"}, queries: nil,
		},
		{
			name: "updates filter does not search remotely", target: "/hosts/alpha/packages?filter=updates&q=ssh", code: 200,
			contains: []string{">openssh-server<"}, queries: nil,
		},
		{
			name: "repository hits are listed", target: "/hosts/alpha/packages?q=tmux", code: 200,
			setup: func(p *pkgEnv) {
				p.ph.found = []protocol.Package{{Name: "tmux", Summary: "multiplexer", CandidateVersion: "3.3", SizeBytes: 470_000, State: protocol.PackageAvailable}}
			},
			contains: []string{">tmux<", "Available", `hx-post="/hosts/alpha/packages/pkg-install"`, ">Install<"}, queries: []string{"tmux"},
		},
		{
			name: "repository search failure is a note, not an error", target: "/hosts/alpha/packages?q=tmux", code: 200,
			setup:    func(p *pkgEnv) { p.ph.searchErr = grid.ErrHostOffline },
			contains: []string{"Repository search is unavailable: The host is offline."}, queries: []string{"tmux"},
		},
		{
			name: "search term is escaped", target: "/hosts/alpha/packages?q=" + url.QueryEscape(`"><script>x</script>`), code: 200,
			absent: []string{"<script>x"}, queries: []string{`"><script>x</script>`},
			contains: []string{"No package matches"},
		},
		{
			name: "long search term is cut", target: "/hosts/alpha/packages?q=" + strings.Repeat("a", 200), code: 200,
			queries: []string{strings.Repeat("a", 64)},
		},
		{
			name: "reboot required", target: "/hosts/alpha/packages", code: 200,
			setup: func(p *pkgEnv) {
				s := p.hub.snaps["a1"]
				s.Packages.RebootRequired = true
				p.hub.snaps["a1"] = s
			},
			contains: []string{"A reboot is required on alpha to finish the update."},
		},
		{
			name: "status bar log without jobs", target: "/hosts/alpha/packages", code: 200,
			contains: []string{`<span id="statusbar-log" role="status">Connected to alpha</span>`},
		},
		{
			name: "status bar log shows the last job", target: "/hosts/alpha/packages", code: 200,
			setup: func(p *pkgEnv) {
				p.hub.jobs["a1"] = []grid.Job{{ID: "job-8", Host: "a1", Kind: protocol.JobAptUpdate, State: grid.JobDone, OK: true}}
			},
			contains: []string{`<span id="statusbar-log" role="status">apt update · done</span>`},
			absent:   []string{"Connected to alpha"},
		},
		{
			name: "job chip while a job runs", target: "/hosts/alpha/packages", code: 200,
			setup: func(p *pkgEnv) {
				p.hub.jobs["a1"] = []grid.Job{{ID: "job-7", Host: "a1", Kind: protocol.JobAptUpgrade, State: grid.JobRunning}}
			},
			contains: []string{"JOB · apt upgrade · running", `hx-get="/hosts/alpha/jobs/job-7"`},
		},
		{
			name: "offline host", target: "/hosts/beta/packages", code: 200,
			contains: []string{"Beta Pi is offline.", "No package data yet."},
		},
		{
			name: "capability switched off", target: "/hosts/alpha/packages", code: 200,
			setup:    func(p *pkgEnv) { p.hub.hosts[0].Capabilities = nil },
			contains: []string{"Package management is switched off for alpha."},
		},
		{
			name: "unknown host", target: "/hosts/nope/packages", code: 404,
		},
		{
			name: "fragment for htmx", target: "/hosts/alpha/packages?filter=updates", opts: []reqOpt{htmx()}, code: 200,
			contains: []string{`name="filter" value="updates"`, `id="pkg-cards"`, `hx-swap-oob="true"`, "openssh-server"},
			absent:   []string{"<html", "<title>", `id="modal-root"`},
		},
		{
			name: "history restore gets the full page", target: "/hosts/alpha/packages", code: 200,
			opts:     []reqOpt{htmx(), withHeader("HX-History-Restore-Request", "true")},
			contains: []string{"<html", `id="modal-root"`},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newPackagesEnv(t)
			if tc.setup != nil {
				tc.setup(p)
			}
			rec := p.getAs(tc.target, tc.opts...)
			if rec.Code != tc.code {
				t.Fatalf("status %d, want %d: %s", rec.Code, tc.code, rec.Body.String())
			}
			body := rec.Body.String()
			for _, s := range tc.contains {
				if !strings.Contains(body, s) {
					t.Errorf("body lacks %q", s)
				}
			}
			for _, s := range tc.absent {
				if strings.Contains(body, s) {
					t.Errorf("body contains %q", s)
				}
			}
			noFiltered(t, body)
			_, _, queries := p.ph.calls()
			if strings.Join(queries, "|") != strings.Join(tc.queries, "|") {
				t.Errorf("SearchPackages queries %q, want %q", queries, tc.queries)
			}
			if tc.code == 200 {
				if got := rec.Header().Get("Vary"); !strings.Contains(got, "HX-Request") {
					t.Errorf("Vary = %q", got)
				}
			}
		})
	}
}

func TestPackagesPageRequiresLogin(t *testing.T) {
	p := newPackagesEnv(t)
	rec := p.get("/hosts/alpha/packages")
	if rec.Code != 303 || rec.Header().Get("Location") != "/login" {
		t.Errorf("got %d %q", rec.Code, rec.Header().Get("Location"))
	}
	rec = p.get("/hosts/alpha/packages", htmx())
	if rec.Code != 401 || rec.Header().Get("HX-Redirect") != "/login" {
		t.Errorf("htmx: got %d %q", rec.Code, rec.Header().Get("HX-Redirect"))
	}
}

func TestPackagesPageRefreshesMissingData(t *testing.T) {
	p := newPackagesEnv(t)
	delete(p.hub.snaps, "a1")
	p.ph.onRefresh = func() {
		p.hub.mu.Lock()
		p.hub.snaps["a1"] = grid.Snapshot{Packages: &protocol.Packages{Items: []protocol.Package{
			{Name: "fresh-pkg", State: protocol.PackageInstalled, InstalledVersion: "1"},
		}}}
		p.hub.mu.Unlock()
	}
	rec := p.getAs("/hosts/alpha/packages")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "fresh-pkg") {
		t.Fatalf("got %d, body lacks the refreshed list", rec.Code)
	}
	if p.ph.refreshed != 1 {
		t.Errorf("RefreshPackages called %d times", p.ph.refreshed)
	}

	// Offline hosts are not asked.
	p.ph.refreshed = 0
	if rec := p.getAs("/hosts/beta/packages"); rec.Code != 200 || p.ph.refreshed != 0 {
		t.Errorf("offline host: status %d, refreshes %d", rec.Code, p.ph.refreshed)
	}
}

func TestPackagesActions(t *testing.T) {
	tests := []struct {
		action string
		form   url.Values
		want   grid.JobSpec
	}{
		{"apt-update", nil, grid.JobSpec{Kind: protocol.JobAptUpdate}},
		{"apt-upgrade", nil, grid.JobSpec{Kind: protocol.JobAptUpgrade}},
		{"apt-clean", nil, grid.JobSpec{Kind: protocol.JobAptClean}},
		{"apt-update", url.Values{"package": {"ignored"}}, grid.JobSpec{Kind: protocol.JobAptUpdate}},
		{"pkg-install", url.Values{"package": {"htop"}}, grid.JobSpec{Kind: protocol.JobPkgInstall, Package: "htop"}},
		{"pkg-remove", url.Values{"package": {" curl "}}, grid.JobSpec{Kind: protocol.JobPkgRemove, Package: "curl"}},
		{"pkg-upgrade", url.Values{"package": {"openssh-server"}}, grid.JobSpec{Kind: protocol.JobPkgUpgrade, Package: "openssh-server"}},
	}
	for _, tc := range tests {
		t.Run(tc.action+"/"+tc.form.Encode(), func(t *testing.T) {
			p := newPackagesEnv(t)
			rec := p.postAs("/hosts/alpha/packages/"+tc.action, tc.form, htmx())
			if rec.Code != 200 {
				t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
			}
			started, _, _ := p.ph.calls()
			if len(started) != 1 || started[0] != tc.want {
				t.Fatalf("started = %+v, want %+v", started, tc.want)
			}
			if p.ph.startedOn[0] != "a1" || p.ph.actors[0].Operator != testOperator || p.ph.actors[0].IP == "" {
				t.Errorf("host %q actor %+v", p.ph.startedOn[0], p.ph.actors[0])
			}
			body := rec.Body.String()
			for _, s := range []string{
				`data-modal`, `id="job-head-job-0001"`, `id="job-term-job-0001"`, `id="job-lines-job-0001"`, `id="job-foot-job-0001"`,
				"Running", "Run in background", "Cancel job", `hx-post="/hosts/alpha/jobs/job-0001/cancel"`, "$ " + html.EscapeString(views.JobCommand(tc.want.Kind, tc.want.Package)),
			} {
				if !strings.Contains(body, s) {
					t.Errorf("dialog lacks %q", s)
				}
			}
			if strings.Contains(body, "<html") {
				t.Error("dialog must be a fragment")
			}
			noFiltered(t, body)
			if !strings.Contains(body, "data-modal-close><span>Run in background") {
				t.Error("Run in background must close the dialog")
			}
		})
	}
}

func TestPackagesActionErrors(t *testing.T) {
	tests := []struct {
		name   string
		target string
		form   url.Values
		err    error
		code   int
		msg    string
		called bool
	}{
		{"offline", "/hosts/alpha/packages/apt-update", nil, grid.ErrHostOffline, 409, "The host is offline.", true},
		{"busy", "/hosts/alpha/packages/apt-upgrade", nil, grid.ErrJobBusy, 409, "The same job is already queued or running.", true},
		{"capability off", "/hosts/alpha/packages/apt-clean", nil, grid.ErrCapabilityDisabled, 403, "switched off", true},
		{"invalid package", "/hosts/alpha/packages/pkg-install", url.Values{"package": {"Bad Name"}}, grid.ErrInvalidArgument, 400, "not valid", true},
		{"host vanished", "/hosts/alpha/packages/apt-update", nil, grid.ErrHostNotFound, 404, "Host not found.", true},
		{"agent timeout", "/hosts/alpha/packages/apt-update", nil, context.DeadlineExceeded, 504, "did not answer", true},
		{"unexpected", "/hosts/alpha/packages/apt-update", nil, errors.New("disk on fire: secret-detail"), 500, "Something went wrong.", true},
		{"package missing", "/hosts/alpha/packages/pkg-remove", nil, nil, 400, "not valid", false},
		{"package blank", "/hosts/alpha/packages/pkg-remove", url.Values{"package": {"   "}}, nil, 400, "not valid", false},
		{"package too long", "/hosts/alpha/packages/pkg-install", url.Values{"package": {strings.Repeat("a", 200)}}, nil, 400, "not valid", false},
		{"unknown action", "/hosts/alpha/packages/reboot", nil, nil, 404, "", false},
		{"kind spelling is not an action", "/hosts/alpha/packages/apt_update", nil, nil, 404, "", false},
		{"unknown host", "/hosts/nope/packages/apt-update", nil, nil, 404, "", false},
	}
	for _, tc := range tests {
		for _, hx := range []bool{false, true} {
			name := tc.name
			var opts []reqOpt
			if hx {
				name += " (htmx)"
				opts = append(opts, htmx())
			}
			t.Run(name, func(t *testing.T) {
				p := newPackagesEnv(t)
				p.ph.startErr = tc.err
				rec := p.postAs(tc.target, tc.form, opts...)
				if rec.Code != tc.code {
					t.Fatalf("status %d, want %d: %s", rec.Code, tc.code, rec.Body.String())
				}
				body := rec.Body.String()
				if !strings.Contains(body, tc.msg) {
					t.Errorf("body %q lacks %q", body, tc.msg)
				}
				if strings.Contains(body, "secret-detail") || strings.Contains(p.logs.String(), "secret-detail") != (tc.code == 500) {
					t.Errorf("cause leaked to the browser or missing from the log (code %d)", tc.code)
				}
				toast := rec.Header().Get("X-Nexus-Toast") == "1"
				if hx && tc.msg != "" {
					if !toast || rec.Header().Get("HX-Retarget") != "#toasts" || rec.Header().Get("HX-Reswap") != "innerHTML" ||
						!strings.Contains(body, `class="toast"`) {
						t.Errorf("htmx error must be a retargeted toast: headers %v", rec.Header())
					}
				}
				if !hx && (toast || rec.Header().Get("HX-Retarget") != "") {
					t.Error("plain requests get no htmx headers")
				}
				started, _, _ := p.ph.calls()
				if tc.err == nil && len(started) != 0 {
					t.Errorf("job started despite rejected request: %+v", started)
				}
			})
		}
	}
}

func TestPackagesActionCSRFAndAuth(t *testing.T) {
	p := newPackagesEnv(t)
	tests := []struct {
		name string
		opts []reqOpt
		code int
	}{
		{"no token", []reqOpt{withCookies(p.cookie)}, 403},
		{"wrong token", []reqOpt{withCookies(p.cookie), withHeader(auth.CSRFHeader, "nope")}, 403},
		{"no session", []reqOpt{withHeader(auth.CSRFHeader, p.csrf)}, 303},
		{"no session (htmx)", []reqOpt{withHeader(auth.CSRFHeader, p.csrf), htmx()}, 401},
	}
	for _, tc := range tests {
		for _, path := range []string{"/hosts/alpha/packages/apt-update", "/hosts/alpha/jobs/job-1/cancel"} {
			rec := p.post(path, tc.opts...)
			if rec.Code != tc.code {
				t.Errorf("%s %s: status %d, want %d", tc.name, path, rec.Code, tc.code)
			}
		}
	}
	started, canceled, _ := p.ph.calls()
	if len(started) != 0 || len(canceled) != 0 {
		t.Errorf("hub was called: %v %v", started, canceled)
	}
}

func TestPackagesConfirm(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		code     int
		contains []string
	}{
		{"remove", "/hosts/alpha/packages/confirm/pkg-remove?package=curl", 200, []string{
			"Remove package", "Remove curl from alpha?", `hx-post="/hosts/alpha/packages/pkg-remove"`, `name="package" value="curl"`,
			"is-bad", "Cancel", "data-modal-close", `type="submit"`, "Remove curl"}},
		{"upgrade all", "/hosts/alpha/packages/confirm/apt-upgrade", 200, []string{
			"Upgrade all", "Install 2 pending updates on alpha?", `hx-post="/hosts/alpha/packages/apt-upgrade"`, "is-hot"}},
		{"clean up", "/hosts/alpha/packages/confirm/apt-clean", 200, []string{
			"Clean up", "Remove 1 orphaned package and clear the package cache on alpha?", `hx-post="/hosts/alpha/packages/apt-clean"`, "is-bad"}},
		{"package name is escaped", "/hosts/alpha/packages/confirm/pkg-remove?package=" + url.QueryEscape(`<b>x</b>`), 200, []string{"&lt;b&gt;x&lt;/b&gt;"}},
		{"package required", "/hosts/alpha/packages/confirm/pkg-remove", 400, nil},
		{"no confirm for update", "/hosts/alpha/packages/confirm/apt-update", 404, nil},
		{"no confirm for install", "/hosts/alpha/packages/confirm/pkg-install?package=htop", 404, nil},
		{"unknown action", "/hosts/alpha/packages/confirm/reboot", 404, nil},
		{"unknown host", "/hosts/nope/packages/confirm/apt-clean", 404, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newPackagesEnv(t)
			rec := p.getAs(tc.target, htmx())
			if rec.Code != tc.code {
				t.Fatalf("status %d, want %d: %s", rec.Code, tc.code, rec.Body.String())
			}
			for _, s := range tc.contains {
				if !strings.Contains(rec.Body.String(), s) {
					t.Errorf("body lacks %q", s)
				}
			}
			if strings.Contains(rec.Body.String(), "<b>x</b>") {
				t.Error("package name not escaped")
			}
			noFiltered(t, rec.Body.String())
			if tc.code == 200 && !strings.Contains(rec.Body.String(), "data-modal-close><span>Cancel") {
				t.Error("Cancel must close the dialog")
			}
		})
	}
}

func TestJobDialog(t *testing.T) {
	setup := func(p *pkgEnv) {
		p.hub.jobs["a1"] = []grid.Job{
			{ID: "job-fin", Host: "a1", Kind: protocol.JobAptUpgrade, State: grid.JobDone, OK: true, RebootRequired: true,
				Output: []grid.JobLine{{Stream: protocol.StreamStdout, Line: "Setting up <b>x</b>"}}},
			{ID: "job-run", Host: "a1", Kind: protocol.JobPkgInstall, Package: "htop", State: grid.JobRunning,
				Output: []grid.JobLine{{Stream: protocol.StreamStatus, Line: "Waiting for dpkg lock (4 s)"}, {Stream: protocol.StreamStderr, Line: "E: boom"}}},
		}
		p.hub.jobs["b2"] = []grid.Job{{ID: "job-other", Host: "b2", Kind: protocol.JobAptUpdate, State: grid.JobRunning}}
	}
	tests := []struct {
		name     string
		target   string
		code     int
		contains []string
		absent   []string
	}{
		{"running", "/hosts/alpha/jobs/job-run", 200, []string{
			"$ apt install -y htop", "Running", "Cancel job", "Run in background", `hx-post="/hosts/alpha/jobs/job-run/cancel"`,
			`class="job-line is-wait"`, "Waiting for dpkg lock (4 s)", `class="job-line is-bad"`, "E: boom", `data-job-state="running"`, "is-busy"},
			[]string{"Reboot required"}},
		{"finished", "/hosts/alpha/jobs/job-fin", 200, []string{
			"Done", "Reboot required", `data-job-state="done"`, "Close", "Setting up &lt;b&gt;x&lt;/b&gt;"},
			[]string{"Cancel job", "Run in background", "<b>x</b>"}},
		{"unknown job", "/hosts/alpha/jobs/nope", 404, nil, nil},
		{"job of another host", "/hosts/alpha/jobs/job-other", 404, nil, nil},
		{"unknown host", "/hosts/nope/jobs/job-run", 404, nil, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newPackagesEnv(t)
			setup(p)
			rec := p.getAs(tc.target, htmx())
			if rec.Code != tc.code {
				t.Fatalf("status %d, want %d: %s", rec.Code, tc.code, rec.Body.String())
			}
			for _, s := range tc.contains {
				if !strings.Contains(rec.Body.String(), s) {
					t.Errorf("body lacks %q", s)
				}
			}
			for _, s := range tc.absent {
				if strings.Contains(rec.Body.String(), s) {
					t.Errorf("body contains %q", s)
				}
			}
			noFiltered(t, rec.Body.String())
		})
	}
}

func TestJobCancel(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		err      error
		code     int
		canceled []string
	}{
		{"running job", "/hosts/alpha/jobs/job-run/cancel", nil, 204, []string{"job-run"}},
		{"already finished", "/hosts/alpha/jobs/job-run/cancel", grid.ErrJobFinished, 409, []string{"job-run"}},
		{"gone in the grid", "/hosts/alpha/jobs/job-run/cancel", grid.ErrJobNotFound, 404, []string{"job-run"}},
		{"unknown job", "/hosts/alpha/jobs/nope/cancel", nil, 404, nil},
		{"job of another host", "/hosts/alpha/jobs/job-other/cancel", nil, 404, nil},
		{"unknown host", "/hosts/nope/jobs/job-run/cancel", nil, 404, nil},
	}
	for _, tc := range tests {
		for _, hx := range []bool{false, true} {
			t.Run(tc.name, func(t *testing.T) {
				p := newPackagesEnv(t)
				p.hub.jobs["a1"] = []grid.Job{{ID: "job-run", Host: "a1", Kind: protocol.JobAptUpgrade, State: grid.JobRunning}}
				p.hub.jobs["b2"] = []grid.Job{{ID: "job-other", Host: "b2", Kind: protocol.JobAptUpdate, State: grid.JobRunning}}
				p.ph.cancelErr = tc.err
				var opts []reqOpt
				if hx {
					opts = append(opts, htmx())
				}
				rec := p.postAs(tc.target, nil, opts...)
				if rec.Code != tc.code {
					t.Fatalf("status %d, want %d: %s", rec.Code, tc.code, rec.Body.String())
				}
				_, canceled, _ := p.ph.calls()
				if strings.Join(canceled, ",") != strings.Join(tc.canceled, ",") {
					t.Errorf("canceled = %v, want %v", canceled, tc.canceled)
				}
				if tc.code == 204 && rec.Body.Len() != 0 {
					t.Error("204 must not carry a body")
				}
			})
		}
	}
}

// --- event stream ----------------------------------------------------------------

func TestPackagesJobEvents(t *testing.T) {
	p := newPackagesEnv(t)
	running := grid.Job{ID: "job-9", Host: "a1", Kind: protocol.JobAptUpgrade, State: grid.JobRunning}
	p.hub.jobs["a1"] = []grid.Job{running}

	done := running
	done.State, done.OK, done.RebootRequired = grid.JobDone, true, true
	done.Output = []grid.JobLine{{Stream: protocol.StreamStdout, Line: "Setting up openssh-server"}}
	failed := running
	failed.State, failed.Error = grid.JobFailed, "apt-get exited with code 100"
	updated := done
	updated.Kind = protocol.JobAptUpdate
	cleaned := done
	cleaned.Kind = protocol.JobAptClean
	removed := done
	removed.Kind, removed.Package = protocol.JobPkgRemove, "curl"
	canceled := running
	canceled.State = grid.JobCanceled

	tests := []struct {
		name     string
		kind     grid.EventKind
		job      grid.Job
		active   []grid.Job // what the hub lists while the event is rendered
		contains []string
		absent   []string
	}{
		{"queued", grid.EventJobQueued, func() grid.Job { j := running; j.State = grid.JobQueued; return j }(), []grid.Job{running},
			[]string{`id="job-head-job-9"`, `hx-swap-oob="true"`, "Queued", `hx-swap-oob="afterbegin:.statusbar-log"`, "JOB · apt upgrade · running",
				`hx-get="/hosts/alpha/jobs/job-9"`, `id="statusbar-log"`, "apt upgrade · queued"},
			[]string{`id="job-term-job-9"`, "toast"}},
		{"started", grid.EventJobStarted, running, []grid.Job{running},
			[]string{`id="job-head-job-9"`, "Running", `id="job-foot-job-9"`, "Cancel job", `hx-swap-oob="delete:.statusbar-log > .btn-tool.is-hot"`, "JOB · apt upgrade · running", "apt upgrade · running"},
			[]string{`id="job-term-job-9"`, `class="toast"`}},
		{"done upgrade", grid.EventJobDone, done, nil,
			[]string{`id="job-head-job-9"`, `data-job-state="done"`, "Reboot required", `id="job-term-job-9"`, "Setting up openssh-server",
				`id="job-foot-job-9"`, "Close", `hx-swap-oob="delete:`, `id="toasts"`, "Updated", "alpha | apt upgrade", "apt upgrade · done"},
			[]string{"afterbegin", "Cancel job"}},
		{"done update", grid.EventJobDone, updated, nil, []string{"Synced", "alpha | apt update"}, nil},
		{"done clean", grid.EventJobDone, cleaned, nil, []string{"Cleaned", "alpha | autoremove &#43; clean"}, nil},
		{"done package job has no banner", grid.EventJobDone, removed, nil, []string{"remove curl · done"}, []string{`class="toast"`}},
		{"failed", grid.EventJobDone, failed, nil,
			[]string{`data-job-state="failed"`, "Failed", "Failed: apt-get exited with code 100", "tag-bad", "apt upgrade · failed"},
			[]string{`class="toast"`}},
		{"canceled", grid.EventJobDone, canceled, nil, []string{"Canceled", `data-job-state="canceled"`}, []string{`class="toast"`}},
		{"next queued job takes over the chip", grid.EventJobDone, done, []grid.Job{
			{ID: "job-10", Host: "a1", Kind: protocol.JobAptClean, State: grid.JobQueued}, done},
			[]string{"JOB · apt clean · queued", `hx-get="/hosts/alpha/jobs/job-10"`}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p.hub.jobs["a1"] = tc.active
			name, html, ok := p.srv.renderPackagesJob(pkgStreamReq(), grid.Event{Kind: tc.kind, Host: "a1", Payload: tc.job})
			if !ok || name != "pkg-job" {
				t.Fatalf("got %q ok=%v", name, ok)
			}
			for _, s := range tc.contains {
				if !strings.Contains(html, s) {
					t.Errorf("payload lacks %q\n%s", s, html)
				}
			}
			for _, s := range tc.absent {
				if strings.Contains(html, s) {
					t.Errorf("payload contains %q", s)
				}
			}
			noFiltered(t, html)
			// Every top-level element must be an out-of-band one: the sink swaps nothing else.
			if strings.Contains(html, "<html") || strings.Contains(html, "modal-backdrop") {
				t.Error("payload must not carry the dialog frame")
			}
		})
	}

	declines := []struct {
		name string
		ev   grid.Event
	}{
		{"wrong payload", grid.Event{Kind: grid.EventJobDone, Host: "a1", Payload: "x"}},
		{"unsafe job id", grid.Event{Kind: grid.EventJobDone, Host: "a1", Payload: grid.Job{ID: `a"b`}}},
		{"unknown host", grid.Event{Kind: grid.EventJobDone, Host: "zz", Payload: running}},
	}
	for _, tc := range declines {
		if _, _, ok := p.srv.renderPackagesJob(pkgStreamReq(), tc.ev); ok {
			t.Errorf("%s: event was rendered", tc.name)
		}
	}
}

func TestPackagesJobOutputEvent(t *testing.T) {
	p := newPackagesEnv(t)
	tests := []struct {
		name string
		out  grid.JobOutputEvent
		want []string
		ok   bool
	}{
		{"plain", grid.JobOutputEvent{JobID: "job-9", Line: grid.JobLine{Stream: protocol.StreamStdout, Line: "Reading package lists..."}},
			[]string{`hx-swap-oob="beforeend:#job-lines-job-9"`, `<div class="job-line">Reading package lists...</div>`}, true},
		{"dpkg lock wait", grid.JobOutputEvent{JobID: "job-9", Line: grid.JobLine{Stream: protocol.StreamStatus, Line: "waiting for dpkg lock (12s)"}},
			[]string{`class="job-line is-wait"`}, true},
		{"error", grid.JobOutputEvent{JobID: "job-9", Line: grid.JobLine{Stream: protocol.StreamStderr, Line: "E: nope"}},
			[]string{`class="job-line is-bad"`}, true},
		{"escaped", grid.JobOutputEvent{JobID: "job-9", Line: grid.JobLine{Line: "<script>alert(1)</script>"}},
			[]string{"&lt;script&gt;alert(1)&lt;/script&gt;"}, true},
		{"empty line keeps its height", grid.JobOutputEvent{JobID: "job-9"}, []string{"&nbsp;"}, true},
		{"unsafe id", grid.JobOutputEvent{JobID: `x"y`}, nil, false},
	}
	for _, tc := range tests {
		name, html, ok := p.srv.renderPackagesJobOutput(pkgStreamReq(), grid.Event{Kind: grid.EventJobOutput, Host: "a1", Payload: tc.out})
		if ok != tc.ok {
			t.Errorf("%s: ok = %v", tc.name, ok)
			continue
		}
		if !ok {
			continue
		}
		if name != "pkg-job" {
			t.Errorf("%s: event %q", tc.name, name)
		}
		for _, s := range tc.want {
			if !strings.Contains(html, s) {
				t.Errorf("%s: payload lacks %q: %s", tc.name, s, html)
			}
		}
		if strings.Contains(html, "<script>") {
			t.Errorf("%s: unescaped output", tc.name)
		}
	}
	if _, _, ok := p.srv.renderPackagesJobOutput(pkgStreamReq(), grid.Event{Kind: grid.EventJobOutput, Payload: 5}); ok {
		t.Error("wrong payload type rendered")
	}
}

func TestPackagesChangedEvent(t *testing.T) {
	p := newPackagesEnv(t)
	for _, k := range []grid.EventKind{grid.EventPackages, grid.EventHostOnline, grid.EventHostOffline, grid.EventJobQueued, grid.EventJobStarted, grid.EventJobDone} {
		found := false
		for _, r := range p.srv.sse.renderers(k) {
			if name, html, ok := r(pkgStreamReq(), grid.Event{Kind: k, Host: "a1"}); ok && name == "pkg-changed" && html == "" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: no pkg-changed renderer registered", k)
		}
	}
}

func TestPackagesEventsOnlyForPackagesStreams(t *testing.T) {
	p := newPackagesEnv(t)
	job := grid.Job{ID: "job-1", Host: "a1", Kind: protocol.JobAptUpdate, State: grid.JobRunning}
	events := []grid.Event{
		{Kind: grid.EventJobStarted, Host: "a1", Payload: job},
		{Kind: grid.EventJobOutput, Host: "a1", Payload: grid.JobOutputEvent{JobID: "job-1"}},
		{Kind: grid.EventPackages, Host: "a1"},
	}
	for _, r := range []*http.Request{nil, httptest.NewRequest("GET", "/events?host=alpha", nil), httptest.NewRequest("GET", "/events?view=overview", nil)} {
		for _, ev := range events {
			for _, render := range []EventRenderer{p.srv.renderPackagesJob, p.srv.renderPackagesJobOutput, p.srv.renderPackagesChanged} {
				if name, _, ok := render(r, ev); ok {
					t.Errorf("%s rendered %q for a foreign stream", ev.Kind, name)
				}
			}
		}
	}
}

func TestPackagesEventStream(t *testing.T) {
	p := newPackagesEnv(t)
	p.srv.sseHeartbeat = time.Hour
	ts := httptest.NewServer(p.srv.Handler())
	t.Cleanup(ts.Close)

	c := openStream(t, ts, "/events?host=alpha&view=packages", withCookies(p.cookie))
	waitFor(t, "subscription", func() bool { return p.hub.subscribers() == 1 })

	p.hub.jobs["a1"] = []grid.Job{{ID: "job-3", Host: "a1", Kind: protocol.JobAptUpdate, State: grid.JobRunning}}
	p.hub.emit(grid.Event{Kind: grid.EventJobOutput, Host: "b2", Payload: grid.JobOutputEvent{JobID: "job-x"}}) // other host
	p.hub.emit(grid.Event{Kind: grid.EventJobOutput, Host: "a1", Payload: grid.JobOutputEvent{JobID: "job-3", Line: grid.JobLine{Line: "Hit:1 http://x"}}})

	for {
		ev := c.nextEvent(t)
		if ev[0] != "event: pkg-job" {
			continue
		}
		if joined := strings.Join(ev, "\n"); !strings.Contains(joined, "job-lines-job-3") || strings.Contains(joined, "job-x") {
			t.Fatalf("event = %q", joined)
		}
		return
	}
}
