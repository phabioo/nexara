package httpserver

import (
	"encoding/json"
	"html"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

// regionIDs is the list of shell regions boosted navigation swaps out of band (partials/components.html).
func regionIDs(t *testing.T, e *env) []string {
	t.Helper()
	list, err := e.srv.partialString("nx-regions", nil)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, id := range strings.Split(strings.TrimSpace(list), ",") {
		if !strings.HasPrefix(id, "#") || len(id) < 2 {
			t.Fatalf("region %q is not an id selector (list %q)", id, list)
		}
		ids = append(ids, id[1:])
	}
	if len(ids) == 0 {
		t.Fatal("no regions")
	}
	return ids
}

// Boosted navigation, the refresh after an event and history restore all fetch the URL with htmx and take #main
// and the shell regions out of the answer: the answer must always be the complete page, never a fragment, and it
// must be the same page a plain browser load gets (a reload of any URL renders everything).
func TestNavigationResponsesAreFullPages(t *testing.T) {
	headers := []struct {
		name string
		opts []reqOpt
	}{
		{"plain load", nil},
		{"boosted link", []reqOpt{withHeader("HX-Request", "true"), withHeader("HX-Boosted", "true"), withHeader("HX-Target", "main")}},
		{"refresh", []reqOpt{withHeader("HX-Request", "true"), withHeader("HX-Target", "main"), withHeader("X-Nx-Refresh", "1")}},
		{"history restore", []reqOpt{withHeader("HX-Request", "true"), withHeader("HX-History-Restore-Request", "true")}},
	}
	pages := []struct {
		path, host, view string
	}{
		{"/", "alpha", "overview"},
		{"/hosts/alpha", "alpha", "overview"},
		{"/hosts/beta", "beta", "overview"}, // offline
		{"/hosts/alpha/packages", "alpha", "packages"},
		{"/hosts/alpha/shell", "alpha", "shell"},
		{"/hosts/beta/shell", "beta", "shell"}, // offline
	}
	for _, pg := range pages {
		for _, h := range headers {
			t.Run(pg.path+" "+h.name, func(t *testing.T) {
				e := viewTestEnv(t)
				ids := regionIDs(t, e)
				cookie, _ := e.signIn()
				rec := e.get(pg.path, append([]reqOpt{withCookies(cookie)}, h.opts...)...)
				if rec.Code != http.StatusOK {
					t.Fatalf("status %d", rec.Code)
				}
				body := rec.Body.String()
				mustContain(t, body, "<!doctype html>", `<main class="main" id="main"`, "hx-history-elt", `tabindex="-1"`,
					`data-host="`+pg.host+`" data-view="`+pg.view+`"`, `id="modal-root"`, `id="nx-announce"`, `sse-connect="/events"`)
				for _, id := range ids {
					if n := strings.Count(body, `id="`+id+`"`); n != 1 {
						t.Errorf("region #%s appears %d times, want once", id, n)
					}
				}
				if n := strings.Count(body, `id="main"`); n != 1 {
					t.Errorf("#main appears %d times", n)
				}
				// The page scripts are part of every page: after in-app navigation nothing reloads them.
				mustContain(t, body, "js/nexus.js", "js/overview.js", "js/shell.js")
				for _, name := range []string{"js/nexus.js", "js/shell.js"} {
					if n := strings.Count(body, name); n != 1 {
						t.Errorf("%s is included %d times, want once", name, n)
					}
				}
				// pages/overview.html still lists overview.js in its own "scripts" block; the script ignores a
				// second load (window.__nxOverview), so twice is harmless but never more.
				if n := strings.Count(body, "js/overview.js"); n < 1 || n > 2 {
					t.Errorf("js/overview.js is included %d times", n)
				}
			})
		}
	}
}

// The shell regions exist on the empty-state page too: that is where a host that gets added shows up.
func TestRegionsOnThePageWithoutHosts(t *testing.T) {
	e := viewTestEnv(t)
	e.hub.mu.Lock()
	e.hub.hosts = nil
	e.hub.mu.Unlock()
	cookie, _ := e.signIn()
	body := e.get("/", withCookies(cookie)).Body.String()
	for _, id := range regionIDs(t, e) {
		if n := strings.Count(body, `id="`+id+`"`); n != 1 {
			t.Errorf("region #%s appears %d times, want once", id, n)
		}
	}
	mustContain(t, body, `data-host="" data-view="overview"`, `sse-connect="/events"`)
}

var boostAttrs = regexp.MustCompile(`<a [^>]*hx-boost="true"[^>]*>`)

// Every in-app link of the shell is boosted and carries the same swap: #main replaced, regions out of band.
func TestShellLinksAreBoosted(t *testing.T) {
	e := viewTestEnv(t)
	cookie, _ := e.signIn()
	regions, err := e.srv.partialString("nx-regions", nil)
	if err != nil {
		t.Fatal(err)
	}
	body := e.get("/hosts/alpha", withCookies(cookie)).Body.String()

	// Host tabs (3), the sidebar nav (5), the bottom nav (3), the More sheet (History, Settings) and
	// "Open shell" on the overview.
	links := boostAttrs.FindAllString(body, -1)
	if len(links) != 3+5+3+2+1 {
		t.Fatalf("%d boosted links, want 14:\n%s", len(links), strings.Join(links, "\n"))
	}
	for _, l := range links {
		mustContain(t, l, `hx-target="#main"`, `hx-select="#main"`, `hx-swap="outerHTML"`, `hx-sync="body:replace"`,
			`hx-select-oob="`+html.EscapeString(strings.TrimSpace(regions))+`"`)
		if strings.Contains(l, "hx-push-url") {
			t.Errorf("boosted links push their URL by default, found an explicit attribute: %s", l)
		}
	}
	mustContain(t, body, `data-regions="`+html.EscapeString(strings.TrimSpace(regions))+`"`)

	// Dialog openers, forms and the sign-out form stay plain: they are not navigation.
	for _, plain := range []string{`class="tab tab-add"`, `action="/logout"`} {
		i := strings.Index(body, plain)
		if i < 0 {
			t.Fatalf("%s missing", plain)
		}
		start := strings.LastIndex(body[:i], "<")
		end := i + strings.Index(body[i:], ">")
		if strings.Contains(body[start:end], "hx-boost") {
			t.Errorf("%s must not be boosted: %s", plain, body[start:end])
		}
	}
}

func TestShellPageCarriesItsLibraries(t *testing.T) {
	e := viewTestEnv(t)
	cookie, _ := e.signIn()
	body := e.get("/hosts/alpha/shell", withCookies(cookie)).Body.String()
	// shell.js loads xterm on first use, after in-app navigation: it needs the versioned URLs.
	mustContain(t, body, `data-xterm-css="/static/css/xterm-6.0.0.css`, `data-xterm-js="/static/js/vendor/xterm-6.0.0.js`,
		`data-xterm-fit="/static/js/vendor/xterm-addon-fit-0.11.0.js`)
	// The offline card has no terminal, no libraries and a boosted way back.
	body = e.get("/hosts/beta/shell", withCookies(cookie)).Body.String()
	mustNotContain(t, body, "data-xterm-js", "shell-host-state")
	mustContain(t, body, `data-state="offline"`, `hx-boost="true"`)
}

// Removing a host moves on like a click on a host tab: HX-Location with the boosted swap, never a page load.
func TestNavLocationHeader(t *testing.T) {
	e := viewTestEnv(t)
	var loc struct {
		Path, Target, Select, Swap, SelectOOB string
	}
	h := e.srv.navLocation("/hosts/b c")
	if err := json.Unmarshal([]byte(h), &loc); err != nil {
		t.Fatalf("%q: %v", h, err)
	}
	if loc.Path != "/hosts/b c" || loc.Target != "#main" || loc.Select != "#main" || loc.Swap != "outerHTML" {
		t.Errorf("location = %+v", loc)
	}
	for _, id := range regionIDs(t, e) {
		if !strings.Contains(loc.SelectOOB, "#"+id) {
			t.Errorf("selectOOB lacks #%s: %q", id, loc.SelectOOB)
		}
	}
	for _, c := range h {
		if c > 126 || c < 32 {
			t.Fatalf("header value has a character outside printable ASCII: %q", c)
		}
	}
}

// A page the host tabs show for the wrong host would make the refresh policy of nexus.js act on stale data:
// <main data-host> always names the host the page is about.
func TestMainNamesItsHost(t *testing.T) {
	e := viewTestEnv(t)
	cookie, _ := e.signIn()
	for path, want := range map[string]string{"/hosts/gamma": "gamma", "/hosts/beta/packages": "beta"} {
		body := e.get(path, withCookies(cookie)).Body.String()
		if !strings.Contains(body, `data-host="`+want+`"`) {
			t.Errorf("%s: <main> does not name %q", path, want)
		}
	}
}
