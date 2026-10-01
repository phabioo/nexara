package views

import (
	"html/template"
	"io/fs"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/phabioo/nexara/web"
)

type pageData struct {
	Layout
	Marker string
}

type authData struct {
	AuthLayout
	Steps SetupSteps
}

func sampleLayout() Layout {
	return Layout{
		Title:     "Overview",
		ActiveNav: "overview",
		CSRF:      "csrf-token-value",
		Operator:  "frank",
		EventsURL: "/events",
		HostKey:   "pi5-media",
		NodeNo:    "01",
		Uptime:    "41D 06H",
		HostName:  "pi5-media",
		HostIP:    "192.168.10.21",
		Online:    2,
		Packages:  "7/10",
		Temp:      "47.2",
		Latency:   "4 ms",
		Hosts: []HostTab{
			{Name: "pi5-media", Href: "/h/pi5-media", Active: true, Badge: 3},
			{Name: "pi3-dns", Href: "/h/pi3-dns", Badge: 2, Offline: true},
		},
		Nav:        DefaultNav(3),
		AddHostURL: "/hosts/add",
		Log:        "Connected to pi5-media",
		Job:        &JobChip{Label: "JOB · apt upgrade · 42%", Href: "/jobs/1"},
		Toast:      &Toast{Title: "Updated", Sub: "3 packages"},
	}
}

func newTestRenderer(t *testing.T) *Renderer {
	t.Helper()
	r, err := New(web.Templates, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

func render(t *testing.T, r *Renderer, page string, data any) string {
	t.Helper()
	rec := httptest.NewRecorder()
	if err := r.Render(rec, page, data); err != nil {
		t.Fatalf("Render(%s): %v", page, err)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
	return rec.Body.String()
}

func TestNewParsesAllTemplates(t *testing.T) {
	r := newTestRenderer(t)
	for _, name := range []string{"app", "auth", "topbar", "sidebar", "statusbar", "bottomnav", "hosttabs",
		"auth-topbar", "auth-statusbar", "lockup", "setup-steps", "setup-progress", "card-head", "tag", "checker",
		"objective", "btn-card", "tile", "tile-resource", "tab", "ticker", "toast", "toasts", "modal-open",
		"modal-close", "field", "form-error", "stat-chip", "corners"} {
		if r.base.Lookup(name) == nil {
			t.Errorf("template %q is not defined", name)
		}
	}
}

func TestRenderAppLayout(t *testing.T) {
	r := newTestRenderer(t)
	if err := r.AddPage("one", `{{define "content"}}<p id="page-one">ONE-MARKER {{.Marker}}</p>{{end}}`); err != nil {
		t.Fatal(err)
	}
	out := render(t, r, "one", pageData{Layout: sampleLayout(), Marker: "<b>x</b>"})
	for _, want := range []string{
		`<meta name="csrf-token" content="csrf-token-value">`,
		`<title>Overview · Nexara Nexus</title>`,
		`href="/static/css/nexus.css"`,
		`src="/static/js/nexus.js"`,
		`src="/static/js/vendor/htmx-2.0.11.min.js"`,
		`<div class="node-card-title t-display">Node 01</div>`,
		`41D 06H <span>UP</span>`,
		`<span>7/10</span>`,
		`<span>47.2°</span>`,
		`4 ms`,
		`class="nav-item on" href="/" aria-current="page"`,
		`class="nav-item hot" href="/packages"`,
		`<span class="nav-badge">3</span>`,
		`class="bnav-item on"`,
		`<span class="bnav-badge">3</span>`,
		`class="tab on" href="/h/pi5-media" aria-current="page"`,
		`<i class="offline-dot" title="Offline"></i>pi3-dns`,
		`data-host-step="-1"`,
		`hx-get="/hosts/add"`,
		`<span id="statusbar-log" role="status">Connected to pi5-media</span>`,
		`<span id="job-chip-slot" class="job-chip-slot"><button type="button" class="btn-tool is-hot" hx-get="/jobs/1"`,
		`JOB · apt upgrade · 42%`,
		`id="pill-pkg"`, `id="pill-temp"`, `<div id="node-card-up" class="node-card-up">41D 06H <span>UP</span></div>`,
		`hx-ext="sse"`, `sse-connect="/events"`, `sse-swap="nx-live,pkg-job,nx-hosts" hx-swap="none" data-oob-sink`,
		// navigation without page loads: regions, the main area's identity, boosted links
		`data-regions="#nx-micro-host,`, `id="nx-tabs"`, `id="nx-pill"`, `id="nx-node"`, `id="nx-nav"`, `id="nx-bnav"`, `id="nx-portrait"`,
		`id="nx-status-host"`, `id="topbar-latency"`, `<main class="main" id="main" tabindex="-1" hx-history-elt data-host="pi5-media" data-view="overview">`,
		`hx-boost="true" hx-target="#main" hx-select="#main" hx-swap="outerHTML" hx-sync="body:replace" hx-select-oob="#nx-micro-host,`,
		`id="nx-announce"`,
		// operator and sign out: sidebar block and More sheet, both POST /logout with the CSRF token
		`<b class="account-name" title="frank">frank</b>`,
		`<form class="signout" method="post" action="/logout">`, `<form class="sheet-signout" method="post" action="/logout">`,
		`name="csrf_token" value="csrf-token-value"`,
		`data-sheet-open="more-sheet"`, `id="more-sheet"`,
		`class="toast"`,
		`ONE-MARKER &lt;b&gt;x&lt;/b&gt;`,
		`<use href="/static/img/icons.svg#i-mark">`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q", want)
		}
	}
	// Phone navigation only carries the items of v0.1 (decision #31): the three views and the More sheet,
	// which holds the account only.
	for _, unwanted := range []string{"History", "Containers", "Alerts", "Settings"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("output contains %q, which belongs to a later version", unwanted)
		}
	}
	if n := strings.Count(out, `class="bnav-item`); n != 4 {
		t.Errorf("bottom nav has %d items, want 4 (Overview, Packages, Shell, More)", n)
	}
	if strings.Contains(out, "ZgotmplZ") {
		t.Error("output contains a filtered value (ZgotmplZ)")
	}
}

func TestRenderAppLayoutWithoutOperatorOrStream(t *testing.T) {
	r := newTestRenderer(t)
	if err := r.AddPage("quiet", `{{define "content"}}x{{end}}`); err != nil {
		t.Fatal(err)
	}
	l := sampleLayout()
	l.Operator, l.EventsURL = "", ""
	out := render(t, r, "quiet", pageData{Layout: l})
	for _, unwanted := range []string{"account", "/logout", "data-sheet-open", "more-sheet", "sse-connect", "data-oob-sink"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("output contains %q without an operator or an event stream", unwanted)
		}
	}
	if n := strings.Count(out, `class="bnav-item`); n != 3 {
		t.Errorf("bottom nav has %d items, want 3", n)
	}
}

func TestRenderConnectionLostAndNoOptionalParts(t *testing.T) {
	r := newTestRenderer(t)
	if err := r.AddPage("bare", `{{define "content"}}x{{end}}`); err != nil {
		t.Fatal(err)
	}
	l := Layout{CSRF: "t", NodeNo: "01", Nav: DefaultNav(0), ConnectionLost: true}
	out := render(t, r, "bare", pageData{Layout: l})
	if !strings.Contains(out, `class=" is-lost"`) {
		t.Error("connection lost body class missing")
	}
	for _, unwanted := range []string{"tab-add", "pill-pkg", "pill-temp", "nav-badge", "host-portrait-title", "JOB"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("optional part %q rendered without data", unwanted)
		}
	}
}

func TestPagesDoNotLeakBlocks(t *testing.T) {
	r := newTestRenderer(t)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(r.AddPage("alpha", `{{define "title"}}ALPHA-TITLE{{end}}{{define "content"}}ALPHA-CONTENT{{end}}{{define "modals"}}ALPHA-MODAL{{end}}`))
	must(r.AddPage("beta", `{{define "content"}}BETA-CONTENT{{end}}`))
	for i := 0; i < 2; i++ { // twice, order must not matter
		a := render(t, r, "alpha", pageData{Layout: sampleLayout()})
		b := render(t, r, "beta", pageData{Layout: sampleLayout()})
		for _, want := range []string{"ALPHA-TITLE", "ALPHA-CONTENT", "ALPHA-MODAL"} {
			if !strings.Contains(a, want) {
				t.Errorf("alpha lacks %s", want)
			}
		}
		if strings.Contains(b, "ALPHA") || !strings.Contains(b, "BETA-CONTENT") || !strings.Contains(b, "<title>Overview · Nexara Nexus</title>") {
			t.Errorf("beta leaked or lost blocks: %.300s", b)
		}
	}
	// Fragments come from the shared set and see no page blocks.
	rec := httptest.NewRecorder()
	if err := r.RenderPartial(rec, "tag", map[string]any{"Tone": "lime", "Text": "Live"}); err != nil {
		t.Fatal(err)
	}
	if got := rec.Body.String(); got != `<span class="tag tag-lime">Live</span>` {
		t.Errorf("tag = %q", got)
	}
}

func TestRenderAuthLayout(t *testing.T) {
	r := newTestRenderer(t)
	src := `{{define "layout"}}auth{{end}}
{{define "auth-top"}}{{template "ticker" (dict "Variant" "blue" "Text" "first run")}}{{end}}
{{define "content"}}<div class="auth-card">{{template "corners"}}{{template "card-head" (dict "Title" "Authenticate" "Variant" "hot")}}</div>
{{template "lockup" (dict "Md" true)}}{{template "lockup-sub" (dict "Tagline" "FIRST-RUN SETUP")}}
{{template "setup-steps" .Steps}}{{template "setup-progress" .Steps}}{{end}}`
	if err := r.AddPage("authdemo", src); err != nil {
		t.Fatal(err)
	}
	data := authData{
		AuthLayout: AuthLayout{
			Title: "Sign in", CSRF: "tok", Variant: "auth-setup",
			Segments:   []PillSegment{{Text: "SETUP"}, {Text: "2/7", Light: true}},
			MicroLines: []string{"[nexara nexus first run]", "setup mode active"},
			BuildLines: []string{"nexus build 0.1.0"},
			Log:        "Awaiting setup code", LiveText: "SETUP MODE · LAN ONLY",
		},
		Steps: NewSetupSteps([]string{"Unlock", "Trust", "Operator"}, 2),
	}
	out := render(t, r, "authdemo", data)
	for _, want := range []string{
		`<div class="auth auth-setup">`, `<meta name="csrf-token" content="tok">`,
		`<span>Nexus</span>`, `pill-light`, `<span>2/7</span>`, `[nexara nexus first run]<br>setup mode active`,
		`ticker ticker-blue`, `class="step-item done"`, `aria-current="step"`, `STEP 2/3 · TRUST`, `NEXT: OPERATOR`,
		`class="lockup lockup-md"`, `SETUP MODE · LAN ONLY`, `Awaiting setup code`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("auth output lacks %q", want)
		}
	}
	if strings.Contains(out, `class="sidebar"`) || strings.Contains(out, "bnav") {
		t.Error("auth layout must not render the app shell")
	}
}

func TestRenderFailsWithoutWriting(t *testing.T) {
	r := newTestRenderer(t)
	if err := r.AddPage("broken", `{{define "content"}}before{{icon "no-such-icon"}}after{{end}}`); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	if err := r.Render(rec, "broken", pageData{Layout: sampleLayout()}); err == nil {
		t.Fatal("want error")
	}
	if rec.Body.Len() != 0 {
		t.Errorf("half-written response: %.100s", rec.Body.String())
	}
	if err := r.Render(rec, "missing", nil); err == nil {
		t.Error("unknown page should fail")
	}
	if err := r.AddPage("badlayout", `{{define "layout"}}nope{{end}}`); err == nil {
		t.Error("unknown layout should fail")
	}
}

// TestComponents renders every component with realistic and with minimal parameters, so a missing
// key or a type error in a template shows up here.
func TestComponents(t *testing.T) {
	r := newTestRenderer(t)
	cases := []struct {
		name string
		data any
		want string
	}{
		{"card-head", map[string]any{"Title": "CPU · 4 Cores", "Variant": "hot", "Meta": "STEP 1/7"}, `card-head is-hot`},
		{"card-head", map[string]any{"Title": "Services"}, `class="card-head"`},
		{"checker", nil, `class="checker"`},
		{"objective", map[string]any{"Label": "Core 0", "Pct": 28, "BoxText": "28", "BoxUnit": "%", "Small": true}, `class="p-28"`},
		{"objective", map[string]any{"Label": "smbd", "Value": "failed", "Pct": 100, "Bad": true, "BoxIcon": "close", "Small": true}, `p-100 bad`},
		{"objective", map[string]any{"Label": "Sources read", "Value": "4/4", "Strong": true, "Pct": 50.4, "BoxIcon": "reboot"}, `<b>4/4</b>`},
		{"btn-card", map[string]any{"Label": "Show processes"}, `class="btn-card"><span>Show processes</span>`},
		{"btn-card", map[string]any{"Label": "Cancel", "Variant": "grey", "NoIcon": true, "Attrs": mustAttr(t, "data-modal-close")}, `btn-card-grey" data-modal-close><span>Cancel</span></button>`},
		{"btn-card", map[string]any{"Label": "Send", "Type": "submit", "Icon": "plus", "IconSize": 12}, `type="submit" class="btn-card"><span>Send</span><svg class="icon" width="12" height="12"`},
		{"btn-card", map[string]any{"Label": "Open", "Href": "/x", "Attrs": mustAttr(t, "hx-boost", "true")}, `href="/x" hx-boost="true"`},
		{"btn-card", map[string]any{"Label": "apt upgrade", "Variant": "light", "Attrs": template.HTMLAttr(`hx-post="/x"`)}, `btn-card btn-card-light" hx-post="/x"`},
		{"btn-card", map[string]any{"Label": "Enter", "Href": "/", "Icon": "arrow-right"}, `<a class="btn-card" href="/"`},
		{"tile", map[string]any{"Tone": "blue", "Glyph": "arrow-up", "Label": "Update", "Name": "libssl3", "Desc": "x", "Meta": "1 → 2", "Badge": "2.1 MB", "ActionLabel": "Update", "ActionClass": "btn-tool is-hot"}, `tile t-blue`},
		{"tile", map[string]any{"Tone": "grey", "Label": "Installed", "Name": "bash"}, `<span></span>`},
		{"tile-resource", map[string]any{"Tone": "blue", "Label": "RAM", "Value": "3.4 / 8 GB", "On": 7}, `<i class="cell on"></i><i class="cell on"></i><i class="cell on"></i><i class="cell on"></i><i class="cell on"></i><i class="cell on"></i><i class="cell on"></i><i class="cell"></i>`},
		{"tab", map[string]any{"Label": "All", "Count": 0, "Active": true, "Href": "/p?f=all"}, `<span class="tab-count">0</span>`},
		{"tab", map[string]any{"Label": "Password", "Active": false}, `aria-pressed="false"><span class="tab-label">Password</span>`},
		{"tab", map[string]any{"Label": "Updates", "Href": "/p", "Attrs": template.HTMLAttr(`hx-get="/p"`)}, `href="/p" hx-get="/p"`},
		{"tile", map[string]any{"Tone": "lime", "Label": "Update", "Name": "x", "ActionLabel": "Go", "ActionAttrs": template.HTMLAttr(`hx-post="/go"`)}, `class="btn-tool" hx-post="/go">Go</button>`},
		{"ticker", map[string]any{"Variant": "green", "Text": "nexara shell 1.0 (grid.session)"}, `ticker-green`},
		{"toast", &Toast{Title: "Updated", Sub: "done"}, `toast-title`},
		{"toasts", nil, `id="toasts"`},
		{"modal-open", map[string]any{"ID": "m-title", "Title": "Link new host", "Variant": "hot", "Size": "lg"}, `modal modal-lg`},
		{"modal-close", nil, `</div>`},
		{"field", map[string]any{"ID": "f-addr", "Label": "Address", "Placeholder": "pi4.local"}, `placeholder="pi4.local">`},
		{"field", map[string]any{"ID": "f-x", "Label": "X", "Attrs": mustAttr(t, "maxlength", "5")}, `maxlength="5">`},
		{"form-error", "Enter your operator ID.", `role="alert"`},
		{"stat-chip", map[string]any{"Label": "LOAD", "Value": "0.42"}, `stat-chip`},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		if err := r.RenderPartial(rec, tc.name, tc.data); err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("%s: output lacks %q:\n%s", tc.name, tc.want, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "ZgotmplZ") {
			t.Errorf("%s: html/template filtered a value (ZgotmplZ): %s", tc.name, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "no value") || strings.Contains(rec.Body.String(), "&lt;nil&gt;") {
			t.Errorf("%s: leaked a missing value: %s", tc.name, rec.Body.String())
		}
	}
}

var (
	reScript  = regexp.MustCompile(`(?is)<script\b[^>]*>`)
	reStyle   = regexp.MustCompile(`(?i)\sstyle\s*=`)
	reHandler = regexp.MustCompile(`(?i)\son[a-z]+\s*=`)
)

func checkCSPClean(t *testing.T, what, src string) {
	t.Helper()
	for _, tag := range reScript.FindAllString(src, -1) {
		if !strings.Contains(strings.ToLower(tag), "src=") {
			t.Errorf("%s: inline <script> %q", what, tag)
		}
	}
	if strings.Contains(strings.ToLower(src), "<style") {
		t.Errorf("%s: contains <style>", what)
	}
	if m := reStyle.FindString(src); m != "" {
		t.Errorf("%s: style attribute", what)
	}
	if m := reHandler.FindString(src); m != "" {
		t.Errorf("%s: inline event handler %q", what, m)
	}
	if strings.Contains(src, "hx-on") || strings.Contains(src, "javascript:") {
		t.Errorf("%s: hx-on or javascript: URL", what)
	}
}

func TestTemplatesAreCSPClean(t *testing.T) {
	err := fs.WalkDir(web.Templates, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".html") {
			return err
		}
		b, err := fs.ReadFile(web.Templates, p)
		if err != nil {
			return err
		}
		checkCSPClean(t, p, string(b))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	r := newTestRenderer(t)
	if err := r.AddPage("csp", `{{define "content"}}x{{end}}`); err != nil {
		t.Fatal(err)
	}
	checkCSPClean(t, "rendered app shell", render(t, r, "csp", pageData{Layout: sampleLayout()}))
}

func mustAttr(t *testing.T, args ...string) template.HTMLAttr {
	t.Helper()
	a, err := attr(args...)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestAttr(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    string
		wantErr bool
	}{
		{"bare", []string{"data-modal-close"}, `data-modal-close`, false},
		{"pair", []string{"hx-get", "/x"}, `hx-get="/x"`, false},
		{"pairs", []string{"hx-post", "/a", "hx-target", "#t"}, `hx-post="/a" hx-target="#t"`, false},
		{"value is escaped", []string{"title", `a"b<c&`}, `title="a&#34;b&lt;c&amp;"`, false},
		{"event handler", []string{"onclick", "x()"}, "", true},
		{"name with space", []string{"a b"}, "", true},
		{"name with quote", []string{`a"b`, "x"}, "", true},
		{"empty", nil, "", true},
		{"odd pair count", []string{"a", "b", "c"}, "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := attr(tc.args...)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if string(got) != tc.want {
				t.Errorf("attr = %q, want %q", got, tc.want)
			}
		})
	}
}

// Every shared template must render without html/template replacing a value it does not trust.
func TestSharedTemplatesRenderWithoutFilteredValues(t *testing.T) {
	r := newTestRenderer(t)
	if err := r.AddPage("plain", `{{define "content"}}{{template "btn-card" (dict "Label" "x")}}{{template "tab" (dict "Label" "y")}}{{template "field" (dict "ID" "z" "Label" "Z")}}{{end}}`); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]any{"plain": pageData{Layout: sampleLayout()}} {
		if out := render(t, r, name, data); strings.Contains(out, "ZgotmplZ") {
			t.Errorf("%s contains ZgotmplZ", name)
		}
	}
	auth := authData{AuthLayout: AuthLayout{Title: "x", Variant: "auth-login", Segments: []PillSegment{{Text: "LOCKED", Icon: "lock"}}}}
	if err := r.AddPage("plainauth", `{{define "layout"}}auth{{end}}{{define "content"}}{{template "btn-card" (dict "Label" "x")}}{{end}}`); err != nil {
		t.Fatal(err)
	}
	if out := render(t, r, "plainauth", auth); strings.Contains(out, "ZgotmplZ") {
		t.Error("auth layout contains ZgotmplZ")
	}
}
