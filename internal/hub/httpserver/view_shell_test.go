package httpserver

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/hub/views"
	"github.com/phabioo/nexara/internal/protocol"
	"github.com/phabioo/nexara/web"
)

// viewTestEnv is newEnv with the real templates and three hosts: an online
// host with the shell capability, an offline one and an online one whose shell
// capability is switched off.
func viewTestEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t)
	r, err := views.New(web.Templates, views.Options{})
	if err != nil {
		t.Fatal(err)
	}
	e.srv.renderer = r
	e.hub.mu.Lock()
	e.hub.hosts = []grid.HostInfo{
		{ID: "a1", Name: "alpha", Address: "192.0.2.21", Online: true, Kernel: "6.6.51+rpt-rpi-2712",
			Capabilities: []string{protocol.CapMonitoring, protocol.CapShell}},
		{ID: "b2", Name: "beta", DisplayName: "Beta Pi", Address: "192.0.2.22", Online: false,
			Capabilities: []string{protocol.CapShell}},
		{ID: "c3", Name: "gamma", DisplayName: `<b>Gamma</b>`, Address: "192.0.2.23", Online: true,
			Capabilities: []string{protocol.CapMonitoring}},
	}
	e.hub.mu.Unlock()
	return e
}

func TestShellPageRequiresSession(t *testing.T) {
	e := viewTestEnv(t)
	rec := e.get("/hosts/alpha/shell")
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("got %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestShellPageUnknownHost(t *testing.T) {
	e := viewTestEnv(t)
	cookie, _ := e.signIn()
	if rec := e.get("/hosts/nope/shell", withCookies(cookie)); rec.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404", rec.Code)
	}
}

func TestShellPageStates(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		wantState string
		wantWS    bool
		contains  []string
		absent    []string
	}{
		{
			name: "online host opens the terminal", path: "/hosts/alpha/shell", wantState: "ready", wantWS: true,
			contains: []string{
				`data-state="ready"`, "PROTOCOL: GRID · mTLS", "nexara shell 1.0 (grid.session)",
				"v.6.6.51", "js/vendor/xterm-6.0.0.js", "js/vendor/xterm-addon-fit-0.11.0.js", "css/xterm-6.0.0.css",
				"js/shell.js", `data-key="esc"`, `data-key="ctrl"`, `data-text="|"`, "Nexara Shell: Session 1",
			},
			absent: []string{"SSH", "· Offline", "Shell disabled"},
		},
		{
			name: "offline host shows the offline card and never connects", path: "/hosts/beta/shell", wantState: "offline",
			contains: []string{`data-state="offline"`, "Beta Pi · Offline", "sse-connect=\"/events?host=beta\"", "Back to overview", "js/shell.js"},
			absent:   []string{"data-ws=", "xterm-6.0.0.js", "data-shell-term"},
		},
		{
			name: "shell capability off", path: "/hosts/gamma/shell", wantState: "disabled",
			contains: []string{`data-state="disabled"`, "Shell disabled", "&lt;b&gt;Gamma&lt;/b&gt;"},
			absent:   []string{"data-ws=", "xterm-6.0.0.js", "<b>Gamma</b>"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := viewTestEnv(t)
			cookie, csrf := e.signIn()
			rec := e.get(tc.path, withCookies(cookie))
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
			}
			body := rec.Body.String()
			if !strings.Contains(body, `data-state="`+tc.wantState+`"`) {
				t.Errorf("state %q missing", tc.wantState)
			}
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
			if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") {
				t.Errorf("CSP = %q", csp)
			}
			if strings.Contains(body, " style=") || strings.Contains(body, "<style") {
				t.Error("inline style in the page (blocked by the CSP)")
			}
			wantWS := `data-ws="/hosts/alpha/shell/ws?csrf=` + url.QueryEscape(csrf) + `"`
			if got := strings.Contains(body, wantWS); got != tc.wantWS {
				t.Errorf("WebSocket URL with the session's CSRF token present = %v, want %v", got, tc.wantWS)
			}
		})
	}
}

func TestShellPageWSURLIsAcceptedByTheSocket(t *testing.T) {
	e := viewTestEnv(t)
	cookie, csrf := e.signIn()
	rec := e.get("/hosts/alpha/shell", withCookies(cookie))
	const marker = `data-ws="`
	i := strings.Index(rec.Body.String(), marker)
	if i < 0 {
		t.Fatal("no data-ws")
	}
	raw := rec.Body.String()[i+len(marker):]
	raw = raw[:strings.IndexByte(raw, '"')]
	u, err := url.Parse(strings.ReplaceAll(raw, "&amp;", "&"))
	if err != nil {
		t.Fatal(err)
	}
	_, sess, err := e.svc.Sessions().Validate(context.Background(), cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	if tok := u.Query().Get("csrf"); tok != csrf || !e.svc.CheckCSRF(sess, tok) {
		t.Error("the token in the WebSocket URL is not the session's CSRF token")
	}
	if u.Path != "/hosts/alpha/shell/ws" {
		t.Errorf("path = %q", u.Path)
	}
}

func TestShellPageState(t *testing.T) {
	tests := []struct {
		name string
		host grid.HostInfo
		want string
	}{
		{"online with shell", grid.HostInfo{Online: true, Capabilities: []string{protocol.CapShell}}, views.ShellReady},
		{"offline wins over the capability", grid.HostInfo{Online: false, Capabilities: []string{protocol.CapShell}}, views.ShellOffline},
		{"online without shell", grid.HostInfo{Online: true, Capabilities: []string{protocol.CapPackages}}, views.ShellDisabled},
		{"online without capabilities", grid.HostInfo{Online: true}, views.ShellDisabled},
	}
	for _, tc := range tests {
		if got := shellPageState(tc.host); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestRenderShellHostState(t *testing.T) {
	tests := []struct {
		name   string
		ev     grid.Event
		wantOK bool
		want   string
	}{
		{"online", grid.Event{Kind: grid.EventHostOnline, Payload: grid.HostInfo{Name: "alpha"}}, true, `<i data-host="alpha" data-online="true"></i>`},
		{"offline", grid.Event{Kind: grid.EventHostOffline, Payload: grid.HostInfo{Name: "alpha", Online: true}}, true, `<i data-host="alpha" data-online="false"></i>`},
		{"name is escaped", grid.Event{Kind: grid.EventHostOnline, Payload: grid.HostInfo{Name: `a"b`}}, true, `data-host="a&#34;b"`},
		{"foreign payload", grid.Event{Kind: grid.EventHostOnline, Payload: 42}, false, ""},
	}
	for _, tc := range tests {
		name, html, ok := renderShellHostState(nil, tc.ev)
		if ok != tc.wantOK {
			t.Errorf("%s: ok = %v", tc.name, ok)
			continue
		}
		if !ok {
			continue
		}
		if name != shellStateEvent || !strings.Contains(html, tc.want) {
			t.Errorf("%s: %q %q", tc.name, name, html)
		}
	}
}

func TestShellHostStateReachesTheEventStream(t *testing.T) {
	e := viewTestEnv(t)
	got := map[grid.EventKind]bool{}
	for _, k := range []grid.EventKind{grid.EventHostOnline, grid.EventHostOffline} {
		got[k] = len(e.srv.sse.renderers(k)) > 0
	}
	if !got[grid.EventHostOnline] || !got[grid.EventHostOffline] {
		t.Errorf("renderers registered: %v", got)
	}
}

func TestShellWSURL(t *testing.T) {
	if got := shellWSURL("my host", "a+b/c="); got != "/hosts/my%20host/shell/ws?csrf=a%2Bb%2Fc%3D" {
		t.Errorf("got %q", got)
	}
}
