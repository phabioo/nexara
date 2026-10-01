package httpserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/auth"
	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/hub/views"
)

const addHostTestFP = "SHA256:ZmFrZUhvc3RLZXlGaW5nZXJwcmludDEyMzQ1Njc4OTA"

const addHostTestKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK3vTESTKEY nexus@frpi5"

// addHostFakeEnroller is a grid.Enroller the tests steer.
type addHostFakeEnroller struct {
	mu       sync.Mutex
	probes   []string // address:port of every ProbeSSH call
	probeKey grid.HostKeyInfo
	probeErr error
	linkReqs []grid.SSHLinkRequest
	linkFn   func(ctx context.Context, req grid.SSHLinkRequest, progress func(grid.LinkStep)) (grid.HostInfo, error)
	code     grid.EnrollCode
	codeErr  error
	codeN    int
}

func (f *addHostFakeEnroller) ProbeSSH(_ context.Context, _ grid.Actor, host string, port int) (grid.HostKeyInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.probes = append(f.probes, fmt.Sprintf("%s:%d", host, port))
	if f.probeErr != nil {
		return grid.HostKeyInfo{}, f.probeErr
	}
	return f.probeKey, nil
}

func (f *addHostFakeEnroller) probed() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.probes...)
}

func (f *addHostFakeEnroller) LinkViaSSH(ctx context.Context, _ grid.Actor, req grid.SSHLinkRequest, progress func(grid.LinkStep)) (grid.HostInfo, error) {
	f.mu.Lock()
	f.linkReqs = append(f.linkReqs, req)
	fn := f.linkFn
	f.mu.Unlock()
	if fn == nil {
		return grid.HostInfo{}, errors.New("no linkFn")
	}
	return fn(ctx, req, progress)
}

func (f *addHostFakeEnroller) NewEnrollCode(context.Context, grid.Actor, grid.EnrollOptions) (grid.EnrollCode, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.codeN++
	return f.code, f.codeErr
}

func (f *addHostFakeEnroller) requests() []grid.SSHLinkRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]grid.SSHLinkRequest(nil), f.linkReqs...)
}

// addHostClock is a settable clock.
type addHostClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *addHostClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *addHostClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type addHostEnv struct {
	*env
	enr    *addHostFakeEnroller
	clock  *addHostClock
	cookie *http.Cookie
	csrf   string
}

func newAddHostEnv(t *testing.T) *addHostEnv {
	t.Helper()
	e := viewTestEnv(t)
	enr := &addHostFakeEnroller{probeKey: grid.HostKeyInfo{Type: "ssh-ed25519", SHA256: addHostTestFP}, code: grid.EnrollCode{
		Code:    "GRID-ABCD-EFGH-JKMN-PQRS",
		Expires: time.Date(2026, 9, 30, 12, 15, 0, 0, time.UTC),
		Command: "curl -fsSL --insecure --pinnedpubkey sha256//PIN https://frpi5.local:8443/grid/install.sh | sudo sh -s -- GRID-ABCD-EFGH-JKMN-PQRS",
	}}
	clock := &addHostClock{t: time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)}
	e.srv.enroller = enr
	e.srv.now = clock.Now
	e.srv.sshKey = func() string { return addHostTestKey }
	cookie, csrf := e.signIn()
	return &addHostEnv{env: e, enr: enr, clock: clock, cookie: cookie, csrf: csrf}
}

func (a *addHostEnv) hx(method, target string, vals url.Values) *httptest.ResponseRecorder {
	a.t.Helper()
	opts := []reqOpt{withCookies(a.cookie), withHeader("HX-Request", "true"), withHeader(auth.CSRFHeader, a.csrf)}
	if vals != nil {
		opts = append(opts, withForm(vals))
	}
	return a.do(a.srv.Handler(), method, target, opts...)
}

// sshForm is the phase 1 form: target only, no credential.
func sshForm(extra ...string) url.Values {
	v := url.Values{"address": {"pi4.local"}, "port": {"22"}, "user": {"pi"}, "display_name": {"Pi4"}}
	for i := 0; i+1 < len(extra); i += 2 {
		v.Set(extra[i], extra[i+1])
	}
	return v
}

// confirmForm is the phase 2 form for a probe.
func confirmForm(probe string, extra ...string) url.Values {
	v := url.Values{"probe": {probe}, "auth": {"password"}, "password": {"hunter2-secret"}}
	for i := 0; i+1 < len(extra); i += 2 {
		v.Set(extra[i], extra[i+1])
	}
	return v
}

var probeIDRE = regexp.MustCompile(`name="probe" value="([0-9a-f]{32})"`)

// probe runs phase 1 and returns the probe id of the fingerprint pane.
func (a *addHostEnv) probe(vals url.Values) string {
	a.t.Helper()
	rec := a.hx(http.MethodPost, "/hosts/new", vals)
	if rec.Code != http.StatusOK {
		a.t.Fatalf("phase 1: status %d: %s", rec.Code, rec.Body.String())
	}
	m := probeIDRE.FindStringSubmatch(rec.Body.String())
	if m == nil {
		a.t.Fatalf("no probe in the fingerprint pane:\n%s", rec.Body.String())
	}
	return m[1]
}

// startLink runs both phases like an operator would and returns the response of phase 2.
func (a *addHostEnv) startLink(phase2 ...string) *httptest.ResponseRecorder {
	a.t.Helper()
	return a.hx(http.MethodPost, "/hosts/new/confirm", confirmForm(a.probe(sshForm()), phase2...))
}

var pollURLRE = regexp.MustCompile(`hx-get="(/hosts/new/(?:link|code)/[^"]+)"`)

func pollURL(t *testing.T, body string) string {
	t.Helper()
	m := pollURLRE.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no poll URL in %s", body)
	}
	return strings.ReplaceAll(m[1], "&amp;", "&")
}

// eventually polls get until the body contains want (2 s at most).
func (a *addHostEnv) eventually(target, want string) string {
	a.t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		rec := a.hx(http.MethodGet, target, nil)
		if strings.Contains(rec.Body.String(), want) {
			return rec.Body.String()
		}
		if time.Now().After(deadline) {
			a.t.Fatalf("%q never appeared at %s; last body:\n%s", want, target, rec.Body.String())
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// --- dialog ------------------------------------------------------------------------------

func TestAddHostRequiresSessionAndCSRF(t *testing.T) {
	a := newAddHostEnv(t)
	tests := []struct {
		name   string
		method string
		target string
		opts   []reqOpt
		want   int
	}{
		{"dialog without session", http.MethodGet, "/hosts/new", []reqOpt{withHeader("HX-Request", "true")}, http.StatusUnauthorized},
		{"submit without session", http.MethodPost, "/hosts/new", []reqOpt{withForm(sshForm())}, http.StatusSeeOther},
		{"submit without CSRF token", http.MethodPost, "/hosts/new", []reqOpt{withCookies(a.cookie), withForm(sshForm())}, http.StatusForbidden},
		{"submit with a wrong token", http.MethodPost, "/hosts/new", []reqOpt{withCookies(a.cookie), withHeader(auth.CSRFHeader, "nope"), withForm(sshForm())}, http.StatusForbidden},
		{"code without CSRF token", http.MethodPost, "/hosts/new/code", []reqOpt{withCookies(a.cookie)}, http.StatusForbidden},
		{"confirm without session", http.MethodPost, "/hosts/new/confirm", []reqOpt{withForm(confirmForm("x"))}, http.StatusSeeOther},
		{"confirm without CSRF token", http.MethodPost, "/hosts/new/confirm", []reqOpt{withCookies(a.cookie), withForm(confirmForm("x"))}, http.StatusForbidden},
	}
	for _, tc := range tests {
		rec := a.do(a.srv.Handler(), tc.method, tc.target, tc.opts...)
		if rec.Code != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, rec.Code, tc.want)
		}
	}
	if n := len(a.enr.requests()) + len(a.enr.probed()); n != 0 {
		t.Errorf("enroller called %d times without authorization", n)
	}
}

func TestAddHostDialog(t *testing.T) {
	a := newAddHostEnv(t)

	t.Run("plain navigation goes home", func(t *testing.T) {
		rec := a.get("/hosts/new", withCookies(a.cookie))
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
			t.Fatalf("got %d %q", rec.Code, rec.Header().Get("Location"))
		}
	})
	t.Run("htmx request renders the dialog", func(t *testing.T) {
		rec := a.hx(http.MethodGet, "/hosts/new", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
		body := rec.Body.String()
		for _, want := range []string{
			`id="addhost-title"`, "Link new host", "Via SSH", "Enrollment code", `name="address"`, `name="port"`, `value="22"`,
			`name="user"`, `value="pi"`, `name="display_name"`, `value="` + a.csrf + `"`, "Check host key", "Step 1 of 2",
			`hx-post="/hosts/new"`, `hx-post="/hosts/new/code"`,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("dialog lacks %q", want)
			}
		}
		// Phase 1 asks for no credential at all (S-04): the password is only
		// requested after the host key was shown and confirmed.
		for _, absent := range []string{`name="password"`, `type="password"`, `name="auth"`, addHostTestKey} {
			if strings.Contains(body, absent) {
				t.Errorf("phase 1 form contains %q", absent)
			}
		}
		if strings.Contains(body, "<html") {
			t.Error("dialog is a fragment, not a page")
		}
		if strings.Contains(body, " style=") || strings.Contains(body, "<script") {
			t.Error("inline style or script in the dialog")
		}
	})
	t.Run("without a hub key the option explains itself", func(t *testing.T) {
		probe := a.probe(sshForm())
		a.srv.sshKey = nil
		defer func() { a.srv.sshKey = func() string { return addHostTestKey } }()
		rec := a.hx(http.MethodPost, "/hosts/new/confirm", confirmForm(probe, "auth", "key"))
		if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "The hub has no SSH key available.") {
			t.Errorf("%d %s", rec.Code, rec.Body.String())
		}
	})
}

// --- validation ------------------------------------------------------------------------------

func TestValidateAddHost(t *testing.T) {
	ok := views.AddHostForm{Address: "pi4.local", Port: "22", User: "pi", Auth: views.AddHostAuthPassword}
	tests := []struct {
		name     string
		mod      func(*views.AddHostForm)
		password string
		hubKey   bool
		wantMsg  string
		check    func(*testing.T, grid.SSHLinkRequest)
	}{
		{"valid password", nil, "pw", true, "", func(t *testing.T, r grid.SSHLinkRequest) {
			if r.Address != "pi4.local" || r.Port != 22 || r.User != "pi" || r.Password.Reveal() != "pw" || r.UseHubKey {
				t.Errorf("%v", r)
			}
		}},
		{"valid ip, empty port means 22", func(f *views.AddHostForm) { f.Address = "192.168.10.30"; f.Port = "" }, "pw", true, "", func(t *testing.T, r grid.SSHLinkRequest) {
			if r.Port != 22 {
				t.Errorf("port %d", r.Port)
			}
		}},
		{"valid ipv6", func(f *views.AddHostForm) { f.Address = "fe80::1" }, "pw", true, "", nil},
		{"valid hub key", func(f *views.AddHostForm) { f.Auth = views.AddHostAuthKey }, "", true, "", func(t *testing.T, r grid.SSHLinkRequest) {
			if !r.UseHubKey || r.Password != "" {
				t.Errorf("%v", r)
			}
		}},
		{"hub key ignores a typed password", func(f *views.AddHostForm) { f.Auth = views.AddHostAuthKey }, "typed", true, "", func(t *testing.T, r grid.SSHLinkRequest) {
			if r.Password != "" {
				t.Error("password kept together with the hub key")
			}
		}},
		{"no address", func(f *views.AddHostForm) { f.Address = "" }, "pw", true, "Enter the IP address or hostname", nil},
		{"address with spaces", func(f *views.AddHostForm) { f.Address = "bad host" }, "pw", true, "valid IP address or host name", nil},
		{"address with a protocol", func(f *views.AddHostForm) { f.Address = "ssh://pi4" }, "pw", true, "valid IP address or host name", nil},
		{"address with double dots", func(f *views.AddHostForm) { f.Address = "a..b" }, "pw", true, "valid IP address or host name", nil},
		{"shell metacharacters", func(f *views.AddHostForm) { f.Address = "pi4;reboot" }, "pw", true, "valid IP address or host name", nil},
		{"port zero", func(f *views.AddHostForm) { f.Port = "0" }, "pw", true, "between 1 and 65535", nil},
		{"port too high", func(f *views.AddHostForm) { f.Port = "65536" }, "pw", true, "between 1 and 65535", nil},
		{"port not a number", func(f *views.AddHostForm) { f.Port = "ssh" }, "pw", true, "between 1 and 65535", nil},
		{"port negative", func(f *views.AddHostForm) { f.Port = "-1" }, "pw", true, "between 1 and 65535", nil},
		{"no user", func(f *views.AddHostForm) { f.User = "" }, "pw", true, "Enter a user with sudo rights.", nil},
		{"root", func(f *views.AddHostForm) { f.User = "root" }, "pw", true, "must not be root", nil},
		{"user with a space", func(f *views.AddHostForm) { f.User = "my user" }, "pw", true, "user name may contain", nil},
		{"name too long", func(f *views.AddHostForm) { f.DisplayName = strings.Repeat("x", 65) }, "pw", true, "Display name", nil},
		{"name with control character", func(f *views.AddHostForm) { f.DisplayName = "a\x07b" }, "pw", true, "Display name", nil},
		{"missing password", nil, "", true, "Enter the password for pi.", nil},
		{"hub key without a key", func(f *views.AddHostForm) { f.Auth = views.AddHostAuthKey }, "", false, "no SSH key available", nil},
		{"unknown auth", func(f *views.AddHostForm) { f.Auth = "kerberos" }, "pw", true, "Choose how to sign in", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			form := ok
			if tc.mod != nil {
				tc.mod(&form)
			}
			req, msg := validateAddHost(form, tc.password, tc.hubKey)
			if tc.wantMsg == "" {
				if msg != "" {
					t.Fatalf("unexpected error %q", msg)
				}
				if tc.check != nil {
					tc.check(t, req)
				}
				return
			}
			if !strings.Contains(msg, tc.wantMsg) {
				t.Fatalf("message %q lacks %q", msg, tc.wantMsg)
			}
			if req.Password != "" || req.Address != "" {
				t.Errorf("a rejected form produced a request: %v", req)
			}
		})
	}
}

func TestAddHostSubmitValidationErrors(t *testing.T) {
	a := newAddHostEnv(t)
	tests := []struct {
		name string
		form url.Values
		want string
	}{
		{"bad host", sshForm("address", "not a host"), "valid IP address or host name"},
		{"port out of range", sshForm("port", "70000"), "between 1 and 65535"},
		{"missing user", sshForm("user", ""), "Enter a user with sudo rights."},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// The status is the real one for HTMX too; nexus.js swaps the HTML fragment of an error response.
			rec := a.hx(http.MethodPost, "/hosts/new", tc.form)
			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("htmx status %d, want 422", rec.Code)
			}
			body := rec.Body.String()
			if !strings.Contains(body, `class="form-error"`) || !strings.Contains(body, tc.want) {
				t.Errorf("no error row with %q:\n%s", tc.want, body)
			}
			if strings.Contains(body, "hunter2-secret") {
				t.Error("the password was echoed back")
			}
			// the typed values stay in the form
			if !strings.Contains(body, `name="user"`) || !strings.Contains(body, `id="addhost-name" name="display_name"`) {
				t.Error("form lost")
			}
			// a plain request gets the same status
			rec = a.do(a.srv.Handler(), http.MethodPost, "/hosts/new",
				withCookies(a.cookie), withHeader(auth.CSRFHeader, a.csrf), withForm(tc.form))
			if rec.Code != http.StatusUnprocessableEntity {
				t.Errorf("plain status %d, want 422", rec.Code)
			}
		})
	}
	if n := len(a.enr.requests()) + len(a.enr.probed()); n != 0 {
		t.Errorf("enroller was called %d times for invalid input", n)
	}
	if strings.Contains(a.logs.String(), "hunter2-secret") {
		t.Error("the password reached the log")
	}
}

func TestAddHostFormKeepsFieldsButNeverThePassword(t *testing.T) {
	a := newAddHostEnv(t)
	// a password sent to phase 1 anyway is neither used nor echoed
	body := a.hx(http.MethodPost, "/hosts/new", sshForm("address", "bad host", "display_name", "My Pi", "password", "hunter2-secret")).Body.String()
	if !strings.Contains(body, `value="bad host"`) || !strings.Contains(body, `value="My Pi"`) {
		t.Error("typed values are not kept")
	}
	if strings.Contains(body, "hunter2-secret") {
		t.Error("password in the HTML")
	}
	if strings.Contains(body, `name="password"`) {
		t.Error("the phase 1 form has a password field")
	}
	// the password field of phase 2 carries no value attribute at all
	body = a.hx(http.MethodPost, "/hosts/new/confirm", confirmForm(a.probe(sshForm()), "password", "")).Body.String()
	m := regexp.MustCompile(`<input[^>]*name="password"[^>]*>`).FindString(body)
	if m == "" || strings.Contains(m, "value=") {
		t.Errorf("password input: %q", m)
	}
}

// --- SSH link -----------------------------------------------------------------------------------

func TestAddHostLinkProgress(t *testing.T) {
	a := newAddHostEnv(t)
	release := make(chan struct{})
	a.enr.linkFn = func(_ context.Context, req grid.SSHLinkRequest, progress func(grid.LinkStep)) (grid.HostInfo, error) {
		progress(grid.LinkStep{Step: grid.StepConnect, State: grid.LinkRunning})
		progress(grid.LinkStep{Step: grid.StepConnect, State: grid.LinkDone, Detail: "Connected as pi · Host key SHA256:abcDEF123"})
		<-release
		progress(grid.LinkStep{Step: grid.StepDetect, State: grid.LinkDone, Detail: "Debian 12 · arm64"})
		return grid.HostInfo{ID: "n1", Name: "pi4", DisplayName: "Pi4", Address: "pi4.local", Online: true}, nil
	}
	rec := a.startLink()
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"Linking…", "Pi4", "Connect via SSH", "Detect system", "Install Grid Agent", "Enroll &amp; issue certificate", "Agent online", "pi@pi4.local:22"} {
		if !strings.Contains(body, want) {
			t.Errorf("progress lacks %q", want)
		}
	}
	if strings.Contains(body, "hunter2-secret") {
		t.Fatal("password in the progress view")
	}
	poll := pollURL(t, body)

	// the host key fingerprint shows up (decision #41)
	body = a.eventually(poll, "SHA256:abcDEF123")
	if !strings.Contains(body, "Connected as pi") || strings.Contains(body, "Connected as pi · Host key") {
		t.Errorf("connect detail not split: %s", body)
	}
	if !strings.Contains(body, "Only the host key you confirmed was accepted") {
		t.Error("fingerprint hint missing")
	}
	// nothing changed since: no update, the pane stays
	poll = pollURL(t, body)
	if rec := a.hx(http.MethodGet, poll, nil); rec.Code != http.StatusNoContent {
		t.Errorf("unchanged poll = %d, want 204", rec.Code)
	}

	close(release)
	body = a.eventually(poll, "Open Pi4")
	for _, want := range []string{"Online", `href="/hosts/pi4"`, "Debian 12 · arm64"} {
		if !strings.Contains(body, want) {
			t.Errorf("finished view lacks %q", want)
		}
	}
	if strings.Contains(body, "hx-trigger") {
		t.Error("a finished attempt keeps polling")
	}

	reqs := a.enr.requests()
	if len(reqs) != 1 || reqs[0].Password.Reveal() != "hunter2-secret" || reqs[0].Address != "pi4.local" || reqs[0].User != "pi" || reqs[0].Port != 22 || reqs[0].DisplayName != "Pi4" || reqs[0].UseHubKey {
		t.Errorf("request = %v", reqs)
	}
	if reqs[0].HostKeySHA256 != addHostTestFP || reqs[0].ReplaceHostID != "" {
		t.Errorf("the confirmed host key did not reach the enroller: %+v", reqs[0])
	}
	if strings.Contains(a.logs.String(), "hunter2-secret") {
		t.Error("password in the log")
	}
}

func TestAddHostLinkWithHubKey(t *testing.T) {
	a := newAddHostEnv(t)
	done := make(chan struct{})
	a.enr.linkFn = func(_ context.Context, req grid.SSHLinkRequest, _ func(grid.LinkStep)) (grid.HostInfo, error) {
		defer close(done)
		return grid.HostInfo{Name: "pi4", Online: true}, nil
	}
	rec := a.startLink("auth", "key", "password", "ignored-typed-password")
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "form-error") {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	<-done
	reqs := a.enr.requests()
	if len(reqs) != 1 || !reqs[0].UseHubKey || reqs[0].Password != "" {
		t.Errorf("request = %v", reqs)
	}
}

func TestAddHostLinkFailures(t *testing.T) {
	tests := []struct {
		name string
		fn   func(progress func(grid.LinkStep)) error
		want []string
	}{
		{
			name: "connect fails",
			fn: func(p func(grid.LinkStep)) error {
				p(grid.LinkStep{Step: grid.StepConnect, State: grid.LinkRunning})
				p(grid.LinkStep{Step: grid.StepConnect, State: grid.LinkFailed, Detail: "Could not connect: connection refused"})
				return fmt.Errorf("%w at step connect: refused", grid.ErrLinkFailed)
			},
			want: []string{"Failed", "Could not connect: connection refused", "step-row fail", "failed at the step marked above", "Try again"},
		},
		{
			name: "host exists",
			fn:   func(func(grid.LinkStep)) error { return grid.ErrHostExists },
			want: []string{"Failed", "A host with this name already exists.", "unique host name", "Try again"},
		},
		{
			name: "host key changed after the confirmation",
			fn: func(p func(grid.LinkStep)) error {
				p(grid.LinkStep{Step: grid.StepConnect, State: grid.LinkFailed, Detail: "Host key changed since you confirmed it. Nothing was sent."})
				return fmt.Errorf("%w at step connect: %w", grid.ErrLinkFailed, grid.ErrHostKeyMismatch)
			},
			want: []string{"Failed", "Host key changed since you confirmed it", "The host key changed after you confirmed it", "Nothing was sent to the device"},
		},
		{
			name: "rejected input",
			fn:   func(func(grid.LinkStep)) error { return fmt.Errorf("%w: invalid user name", grid.ErrInvalidArgument) },
			want: []string{"The hub rejected the input"},
		},
		{
			name: "timeout",
			fn:   func(func(grid.LinkStep)) error { return fmt.Errorf("wait: %w", context.DeadlineExceeded) },
			want: []string{"took too long"},
		},
		{
			name: "unknown error stays generic",
			fn:   func(func(grid.LinkStep)) error { return errors.New("dial tcp 10.0.0.1: secret-internal-detail") },
			want: []string{"Something went wrong. Check the hub log."},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := newAddHostEnv(t)
			a.enr.linkFn = func(_ context.Context, _ grid.SSHLinkRequest, p func(grid.LinkStep)) (grid.HostInfo, error) {
				return grid.HostInfo{}, tc.fn(p)
			}
			rec := a.startLink()
			// A link that fails at once may already render the final state,
			// which carries no poll URL.
			body := rec.Body.String()
			if !strings.Contains(body, "Failed") {
				poll := pollURL(t, body)
				deadline := time.Now().Add(2 * time.Second)
				for !strings.Contains(body, "Failed") && time.Now().Before(deadline) {
					time.Sleep(time.Millisecond)
					body = a.hx(http.MethodGet, poll, nil).Body.String()
					if m := pollURLRE.FindStringSubmatch(body); m != nil {
						poll = strings.ReplaceAll(m[1], "&amp;", "&")
					}
				}
			}
			for _, want := range tc.want {
				if !strings.Contains(body, want) {
					t.Errorf("lacks %q in:\n%s", want, body)
				}
			}
			if strings.Contains(body, "secret-internal-detail") || strings.Contains(body, "hunter2-secret") {
				t.Error("internal detail or password leaked into the HTML")
			}
			// "Try again" returns the form prefilled, without the password
			m := regexp.MustCompile(`hx-get="(/hosts/new/pane\?retry=[^"]+)"`).FindStringSubmatch(body)
			if m == nil {
				t.Fatal("no retry link")
			}
			form := a.hx(http.MethodGet, strings.ReplaceAll(m[1], "&amp;", "&"), nil).Body.String()
			if !strings.Contains(form, `value="pi4.local"`) || strings.Contains(form, "hunter2-secret") {
				t.Errorf("retry form: %s", form)
			}
		})
	}
}

func TestAddHostLinkMapping(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{nil, ""},
		{grid.ErrHostExists, "already exists"},
		{&grid.HostExistsError{ID: "d4", Name: "delta"}, "A host named delta already exists"},
		{fmt.Errorf("%w at step connect: %w", grid.ErrLinkFailed, grid.ErrHostKeyMismatch), "host key changed after you confirmed it"},
		{fmt.Errorf("x: %w", grid.ErrInvalidArgument), "rejected the input"},
		{context.DeadlineExceeded, "took too long"},
		{context.Canceled, "canceled"},
		{fmt.Errorf("%w at step connect: boom", grid.ErrLinkFailed), "failed at the step marked above"},
		{errors.New("boom"), "Something went wrong"},
	}
	for _, tc := range tests {
		got := linkErrorMessage(tc.err)
		if !strings.Contains(got, tc.want) || (tc.err != nil && strings.Contains(got, "boom")) {
			t.Errorf("%v -> %q, want %q", tc.err, got, tc.want)
		}
	}
}

func TestAddHostTooManyLinks(t *testing.T) {
	a := newAddHostEnv(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	a.enr.linkFn = func(ctx context.Context, _ grid.SSHLinkRequest, _ func(grid.LinkStep)) (grid.HostInfo, error) {
		select {
		case <-release:
		case <-ctx.Done():
		}
		return grid.HostInfo{Name: "x", Online: true}, nil
	}
	for i := 0; i < maxRunningLinks; i++ {
		rec := a.hx(http.MethodPost, "/hosts/new/confirm", confirmForm(a.probe(sshForm("address", fmt.Sprintf("pi%d.local", i)))))
		if strings.Contains(rec.Body.String(), "form-error") {
			t.Fatalf("attempt %d refused: %s", i, rec.Body.String())
		}
	}
	probe := a.probe(sshForm())
	rec := a.hx(http.MethodPost, "/hosts/new/confirm", confirmForm(probe))
	if rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), "Another host is being linked right now") {
		t.Errorf("4th attempt: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), addHostTestFP) {
		t.Error("the refused confirmation does not show the fingerprint pane again")
	}
	// the refused attempt did not use up the confirmation
	rec = a.do(a.srv.Handler(), http.MethodPost, "/hosts/new/confirm",
		withCookies(a.cookie), withHeader(auth.CSRFHeader, a.csrf), withForm(confirmForm(probe)))
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("plain status %d, want 429", rec.Code)
	}
}

func TestAddHostAttemptsBelongToTheOperator(t *testing.T) {
	a := newAddHostEnv(t)
	done, release := make(chan struct{}), make(chan struct{})
	a.enr.linkFn = func(context.Context, grid.SSHLinkRequest, func(grid.LinkStep)) (grid.HostInfo, error) {
		defer close(done)
		<-release // finish only after the response (with its poll URL) is rendered
		return grid.HostInfo{Name: "pi4", Online: true}, nil
	}
	rec := a.startLink()
	poll := pollURL(t, rec.Body.String())
	close(release)
	<-done
	id := strings.TrimPrefix(strings.SplitN(poll, "?", 2)[0], "/hosts/new/link/")
	reg := a.srv.addHost
	if reg.get(id, testOperator) == nil {
		t.Fatal("own attempt not found")
	}
	if reg.get(id, "someone-else") != nil || reg.get("", testOperator) != nil || reg.get("unknown", testOperator) != nil {
		t.Error("attempt visible to the wrong operator or by a wrong id")
	}
	for _, p := range []string{"/hosts/new/link/unknown", "/hosts/new/code/unknown"} {
		if rec := a.hx(http.MethodGet, p, nil); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", p, rec.Code)
		}
	}
}

func TestSplitHostKey(t *testing.T) {
	tests := []struct{ in, text, fp string }{
		{"Connected as pi · Host key SHA256:abc", "Connected as pi", "SHA256:abc"},
		{"Connected as pi", "Connected as pi", ""},
		{"", "", ""},
		{"Host key only", "Host key only", ""},
	}
	for _, tc := range tests {
		if text, fp := splitHostKey(tc.in); text != tc.text || fp != tc.fp {
			t.Errorf("%q -> %q %q", tc.in, text, fp)
		}
	}
}

// --- enrollment code ------------------------------------------------------------------------

func TestAddHostCodeFlow(t *testing.T) {
	a := newAddHostEnv(t)
	rec := a.hx(http.MethodPost, "/hosts/new/code", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		"GRID-ABCD-EFGH-JKMN-PQRS", "valid 15 min · one use", "--pinnedpubkey sha256//PIN", `data-copy="#addhost-cmd"`,
		"Waiting for the agent to connect…", "New code", "For hosts without SSH", `aria-pressed="true"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("code pane lacks %q", want)
		}
	}
	if strings.Contains(body, "Simulate") {
		t.Error("mockup-only control rendered")
	}
	poll := pollURL(t, body)

	// nothing happened yet
	if rec := a.hx(http.MethodGet, poll, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("waiting poll = %d, want 204", rec.Code)
	}

	// the agent enrolls: a new host exists but is not online yet
	a.hub.mu.Lock()
	a.hub.hosts = append(a.hub.hosts, grid.HostInfo{ID: "d4", Name: "delta", DisplayName: "Delta", Address: "192.0.2.40", OS: "linux", Arch: "arm64", AgentVersion: "0.1.0"})
	a.hub.mu.Unlock()
	rec = a.hx(http.MethodGet, poll, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("joined poll = %d", rec.Code)
	}
	body = rec.Body.String()
	for _, want := range []string{"Delta", "Linking…", "Agent connected with code", "linux · arm64", "v0.1.0 from this hub", "step-row run"} {
		if !strings.Contains(body, want) {
			t.Errorf("joined view lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "GRID-ABCD-EFGH-JKMN-PQRS") {
		t.Error("the code is shown again after the agent used it")
	}
	poll = pollURL(t, body)
	if rec := a.hx(http.MethodGet, poll, nil); rec.Code != http.StatusNoContent {
		t.Errorf("unchanged joined poll = %d, want 204", rec.Code)
	}

	// it comes online
	a.hub.mu.Lock()
	a.hub.hosts[len(a.hub.hosts)-1].Online = true
	a.hub.mu.Unlock()
	rec = a.hx(http.MethodGet, poll, nil)
	body = rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "Open Delta") || !strings.Contains(body, `href="/hosts/delta"`) || strings.Contains(body, "hx-trigger") {
		t.Errorf("online view: %d %s", rec.Code, body)
	}
}

func TestAddHostCodeExpires(t *testing.T) {
	a := newAddHostEnv(t)
	body := a.hx(http.MethodPost, "/hosts/new/code", nil).Body.String()
	poll := pollURL(t, body)
	a.clock.Add(14 * time.Minute)
	if rec := a.hx(http.MethodGet, poll, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("before expiry = %d", rec.Code)
	}
	a.clock.Add(2 * time.Minute)
	rec := a.hx(http.MethodGet, poll, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "This code has expired. Create a new one.") || !strings.Contains(rec.Body.String(), "New code") {
		t.Errorf("expired view: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "GRID-ABCD-EFGH-JKMN-PQRS") {
		t.Error("expired code shown")
	}
}

func TestAddHostCodeErrors(t *testing.T) {
	a := newAddHostEnv(t)
	a.enr.codeErr = grid.ErrUnsupported
	rec := a.hx(http.MethodPost, "/hosts/new/code", nil)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "Could not create an enrollment code.") || strings.Contains(rec.Body.String(), "GRID-ABCD-EFGH-JKMN-PQRS") {
		t.Errorf("htmx: %d %s", rec.Code, rec.Body.String())
	}
	rec = a.do(a.srv.Handler(), http.MethodPost, "/hosts/new/code", withCookies(a.cookie), withHeader(auth.CSRFHeader, a.csrf))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("plain status %d, want 422 (ErrUnsupported)", rec.Code)
	}
}

func TestValidFor(t *testing.T) {
	for d, want := range map[time.Duration]string{15 * time.Minute: "15 min", 14*time.Minute + time.Second: "15 min", 30 * time.Second: "1 min", -time.Minute: "1 min"} {
		if got := validFor(d); got != want {
			t.Errorf("validFor(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestAddHostRoutesDoNotShadowHosts(t *testing.T) {
	a := newAddHostEnv(t)
	// /hosts/new is the dialog, not a host called "new"; the shell of a real host still works.
	if rec := a.get("/hosts/alpha/shell", withCookies(a.cookie)); rec.Code != http.StatusOK {
		t.Errorf("shell route = %d", rec.Code)
	}
}

// --- two-phase SSH link (S-04, decision #41) ----------------------------------------------------

func TestAddHostPhaseOneShowsTheFingerprintAndSendsNoCredential(t *testing.T) {
	a := newAddHostEnv(t)
	rec := a.hx(http.MethodPost, "/hosts/new", sshForm("port", "2222", "password", "typed-too-early"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Step 2 of 2", "pi@pi4.local:2222", "Verify this fingerprint on the device", "Host key (ssh-ed25519)", addHostTestFP,
		"ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub", `data-copy="#addhost-fp-cmd"`,
		`hx-post="/hosts/new/confirm"`, `name="probe"`, "Confirm &amp; link", "Cancel", `data-modal-close`,
		`name="password"`, addHostTestKey,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("fingerprint pane lacks %q", want)
		}
	}
	if strings.Contains(body, "typed-too-early") {
		t.Error("a password sent in phase 1 was echoed")
	}
	if got := a.enr.probed(); len(got) != 1 || got[0] != "pi4.local:2222" {
		t.Errorf("probes = %v", got)
	}
	if n := len(a.enr.requests()); n != 0 {
		t.Fatalf("the enroller was asked to link (%d) before the operator confirmed", n)
	}
	if strings.Contains(a.logs.String(), "typed-too-early") {
		t.Error("password in the log")
	}
}

func TestAddHostConfirmUsesTheServersFingerprint(t *testing.T) {
	a := newAddHostEnv(t)
	probe := a.probe(sshForm())
	done := make(chan struct{})
	a.enr.linkFn = func(context.Context, grid.SSHLinkRequest, func(grid.LinkStep)) (grid.HostInfo, error) {
		defer close(done)
		return grid.HostInfo{Name: "pi4", Online: true}, nil
	}
	// A fingerprint, address or user sent along with the confirmation is ignored.
	rec := a.hx(http.MethodPost, "/hosts/new/confirm", confirmForm(probe,
		"host_key", "SHA256:attackerChosen", "hostkey_sha256", "SHA256:attackerChosen", "address", "evil.example", "user", "root", "replace", "a1"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	<-done
	reqs := a.enr.requests()
	if len(reqs) != 1 || reqs[0].HostKeySHA256 != addHostTestFP || reqs[0].Address != "pi4.local" || reqs[0].User != "pi" || reqs[0].ReplaceHostID != "" {
		t.Fatalf("request = %+v", reqs)
	}
}

func TestAddHostProbeFailures(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"unreachable", fmt.Errorf("%w: dial tcp 10.9.9.9:22: secret-internal-detail", grid.ErrLinkFailed), "Could not read the SSH host key of pi4.local:22"},
		{"rejected", fmt.Errorf("%w: invalid address", grid.ErrInvalidArgument), "rejected the address or port"},
		{"unknown", errors.New("secret-internal-detail"), "Could not read the SSH host key"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newAddHostEnv(t)
			a.enr.probeErr = tt.err
			rec := a.hx(http.MethodPost, "/hosts/new", sshForm())
			body := rec.Body.String()
			if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(body, tt.want) {
				t.Fatalf("%d %s", rec.Code, body)
			}
			if strings.Contains(body, "secret-internal-detail") {
				t.Error("error detail leaked into the HTML")
			}
			if !strings.Contains(body, `value="pi4.local"`) || strings.Contains(body, "probe") {
				t.Error("the form is not shown again with the typed values")
			}
			if n := len(a.enr.requests()); n != 0 {
				t.Errorf("linked %d times after a failed probe", n)
			}
		})
	}
}

func TestAddHostProbeBinding(t *testing.T) {
	t.Run("another browser session cannot use the probe", func(t *testing.T) {
		a := newAddHostEnv(t)
		probe := a.probe(sshForm())
		cookie2, csrf2 := a.signIn() // same operator, different session
		rec := a.do(a.srv.Handler(), http.MethodPost, "/hosts/new/confirm",
			withCookies(cookie2), withHeader("HX-Request", "true"), withHeader(auth.CSRFHeader, csrf2), withForm(confirmForm(probe)))
		if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "host key check expired") {
			t.Fatalf("%d %s", rec.Code, rec.Body.String())
		}
		if n := len(a.enr.requests()); n != 0 {
			t.Fatalf("linked %d times with a probe of another session", n)
		}
		// the owner can still use it
		a.enr.linkFn = func(context.Context, grid.SSHLinkRequest, func(grid.LinkStep)) (grid.HostInfo, error) {
			return grid.HostInfo{Name: "pi4", Online: true}, nil
		}
		if rec := a.hx(http.MethodPost, "/hosts/new/confirm", confirmForm(probe)); rec.Code != http.StatusOK {
			t.Fatalf("owner: %d %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("the probe expires", func(t *testing.T) {
		a := newAddHostEnv(t)
		probe := a.probe(sshForm())
		a.clock.Add(probeTTL - time.Second)
		if rec := a.hx(http.MethodPost, "/hosts/new/confirm", confirmForm(probe, "password", "")); rec.Code != http.StatusUnprocessableEntity ||
			strings.Contains(rec.Body.String(), "expired") {
			t.Fatalf("just before the limit: %d %s", rec.Code, rec.Body.String())
		}
		a.clock.Add(2 * time.Second)
		rec := a.hx(http.MethodPost, "/hosts/new/confirm", confirmForm(probe))
		if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "host key check expired") {
			t.Fatalf("after the limit: %d %s", rec.Code, rec.Body.String())
		}
		if n := len(a.enr.requests()); n != 0 {
			t.Fatalf("linked %d times with an expired probe", n)
		}
	})
	t.Run("the probe is single use", func(t *testing.T) {
		a := newAddHostEnv(t)
		started := make(chan struct{}, 2)
		a.enr.linkFn = func(context.Context, grid.SSHLinkRequest, func(grid.LinkStep)) (grid.HostInfo, error) {
			started <- struct{}{}
			return grid.HostInfo{Name: "pi4", Online: true}, nil
		}
		probe := a.probe(sshForm())
		if rec := a.hx(http.MethodPost, "/hosts/new/confirm", confirmForm(probe)); rec.Code != http.StatusOK {
			t.Fatalf("first: %d", rec.Code)
		}
		<-started
		rec := a.hx(http.MethodPost, "/hosts/new/confirm", confirmForm(probe))
		if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "host key check expired") {
			t.Fatalf("second: %d %s", rec.Code, rec.Body.String())
		}
		if n := len(a.enr.requests()); n != 1 {
			t.Fatalf("%d link requests, want 1", n)
		}
	})
	t.Run("unknown and missing ids", func(t *testing.T) {
		a := newAddHostEnv(t)
		for _, id := range []string{"", "nope", strings.Repeat("0", 32)} {
			rec := a.hx(http.MethodPost, "/hosts/new/confirm", confirmForm(id))
			if rec.Code != http.StatusUnprocessableEntity {
				t.Errorf("id %q: %d", id, rec.Code)
			}
		}
		if n := len(a.enr.requests()); n != 0 {
			t.Fatalf("linked %d times", n)
		}
	})
}

func TestAddHostConfirmValidation(t *testing.T) {
	tests := []struct {
		name string
		form url.Values
		want string
	}{
		{"missing password", confirmForm("", "password", ""), "Enter the password for pi."},
		{"unknown authentication", confirmForm("", "auth", "kerberos"), "Choose how to sign in"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newAddHostEnv(t)
			probe := a.probe(sshForm())
			tt.form.Set("probe", probe)
			rec := a.hx(http.MethodPost, "/hosts/new/confirm", tt.form)
			body := rec.Body.String()
			if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(body, tt.want) {
				t.Fatalf("%d %s", rec.Code, body)
			}
			// the fingerprint stays visible and the confirmation usable
			if !strings.Contains(body, addHostTestFP) || !strings.Contains(body, probe) {
				t.Error("the fingerprint pane is gone after a validation error")
			}
			if n := len(a.enr.requests()); n != 0 {
				t.Errorf("linked %d times", n)
			}
		})
	}
}

func TestAddHostProbesAreBounded(t *testing.T) {
	reg := newLinkRegistry()
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	var first string
	for i := 0; i < maxProbes+10; i++ {
		p := reg.addProbe(&hostKeyProbe{operator: "o", session: "s"}, nil, now.Add(time.Duration(i)*time.Second))
		if i == 0 {
			first = p.id
		}
	}
	if len(reg.probes) != maxProbes {
		t.Fatalf("%d probes kept, want %d", len(reg.probes), maxProbes)
	}
	if reg.getProbe(first, "o", "s", now.Add(time.Minute)) != nil {
		t.Error("the oldest probe was kept")
	}
	// expired ones are dropped when a new one is added
	reg.addProbe(&hostKeyProbe{operator: "o", session: "s"}, nil, now.Add(time.Hour))
	if len(reg.probes) != 1 {
		t.Errorf("%d probes after expiry, want 1", len(reg.probes))
	}
}

func TestKeyFile(t *testing.T) {
	for in, want := range map[string]string{
		"ssh-ed25519":         "/etc/ssh/ssh_host_ed25519_key.pub",
		"ecdsa-sha2-nistp256": "/etc/ssh/ssh_host_ecdsa_key.pub",
		"ssh-rsa":             "/etc/ssh/ssh_host_rsa_key.pub",
		"":                    "/etc/ssh/ssh_host_ed25519_key.pub",
	} {
		if got := keyFile(in); got != want {
			t.Errorf("keyFile(%q) = %q, want %q", in, got, want)
		}
	}
}

// --- host exists and Replace (S-03, decision #46) ------------------------------------------------

func TestAddHostReplaceOffer(t *testing.T) {
	// "beta" (b2) is offline in the test hub, "alpha" (a1) is online.
	tests := []struct {
		name      string
		existing  grid.HostID
		wantName  string
		wantOffer bool
	}{
		{"offline host: Replace is offered", "b2", "Beta Pi", true},
		{"online host: no Replace", "a1", "alpha", false},
		{"unknown host: no Replace", "zz", "zz", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newAddHostEnv(t)
			a.enr.linkFn = func(_ context.Context, _ grid.SSHLinkRequest, p func(grid.LinkStep)) (grid.HostInfo, error) {
				p(grid.LinkStep{Step: grid.StepDetect, State: grid.LinkFailed, Detail: "A host named x already exists"})
				return grid.HostInfo{}, &grid.HostExistsError{ID: tt.existing, Name: "beta"}
			}
			body := a.startLink().Body.String()
			if !strings.Contains(body, "Failed") {
				body = a.eventually(pollURL(t, body), "Failed")
			}
			if !strings.Contains(body, "A host named beta already exists") || !strings.Contains(body, "Try again") {
				t.Fatalf("host exists view:\n%s", body)
			}
			hasOffer := strings.Contains(body, "<span>Replace ")
			if hasOffer != tt.wantOffer {
				t.Fatalf("Replace offered = %v, want %v:\n%s", hasOffer, tt.wantOffer, body)
			}
			if tt.wantOffer && !strings.Contains(body, "<span>Replace "+tt.wantName+"</span>") {
				t.Errorf("button does not name the host %q", tt.wantName)
			}
		})
	}
}

func TestAddHostReplaceFlow(t *testing.T) {
	a := newAddHostEnv(t)
	hostExists := &grid.HostExistsError{ID: "b2", Name: "beta"}
	a.enr.linkFn = func(_ context.Context, req grid.SSHLinkRequest, _ func(grid.LinkStep)) (grid.HostInfo, error) {
		if req.ReplaceHostID == "b2" {
			return grid.HostInfo{ID: "b2", Name: "beta", DisplayName: "Beta Pi", Online: true}, nil
		}
		return grid.HostInfo{}, hostExists
	}
	body := a.startLink().Body.String()
	if !strings.Contains(body, "Failed") {
		body = a.eventually(pollURL(t, body), "Failed")
	}
	m := regexp.MustCompile(`hx-get="(/hosts/new/pane\?retry=[^"]+&amp;replace=b2)"`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no Replace link:\n%s", body)
	}
	// Replace goes back to the form (no password is kept), marked with the host to replace.
	form := a.hx(http.MethodGet, strings.ReplaceAll(m[1], "&amp;", "&"), nil).Body.String()
	for _, want := range []string{`name="replace" value="b2"`, "Replacing <b>Beta Pi</b> (offline)", `value="pi4.local"`, "Check host key"} {
		if !strings.Contains(form, want) {
			t.Errorf("replace form lacks %q:\n%s", want, form)
		}
	}
	if strings.Contains(form, "hunter2-secret") {
		t.Error("password in the replace form")
	}

	// Phase 1 keeps the choice server-side; phase 2 hands it to the enroller.
	probeBody := a.hx(http.MethodPost, "/hosts/new", sshForm("replace", "b2")).Body.String()
	if !strings.Contains(probeBody, "Replacing <b>Beta Pi</b> (offline)") {
		t.Errorf("fingerprint pane does not say what is replaced:\n%s", probeBody)
	}
	probe := probeIDRE.FindStringSubmatch(probeBody)[1]
	rec := a.hx(http.MethodPost, "/hosts/new/confirm", confirmForm(probe, "replace", "a1"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	body = a.eventually(pollURL(t, rec.Body.String()), "Open Beta Pi")
	reqs := a.enr.requests()
	if last := reqs[len(reqs)-1]; last.ReplaceHostID != "b2" || last.HostKeySHA256 != addHostTestFP {
		t.Fatalf("request = %+v", last)
	}
	_ = body
}

func TestAddHostReplaceIsOnlyForOfflineHosts(t *testing.T) {
	a := newAddHostEnv(t)
	for _, id := range []string{"a1", "c3", "zz"} { // online, online, unknown
		rec := a.hx(http.MethodPost, "/hosts/new", sshForm("replace", id))
		if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "Only a host that is currently offline can be replaced.") {
			t.Errorf("replace %s: %d %s", id, rec.Code, rec.Body.String())
		}
	}
	if len(a.enr.probed()) != 0 {
		t.Error("probed although the replace request was refused")
	}
	// the retry link only works for the host the failed attempt ran into
	a.enr.linkFn = func(context.Context, grid.SSHLinkRequest, func(grid.LinkStep)) (grid.HostInfo, error) {
		return grid.HostInfo{}, &grid.HostExistsError{ID: "b2", Name: "beta"}
	}
	body := a.startLink().Body.String()
	if !strings.Contains(body, "Failed") {
		body = a.eventually(pollURL(t, body), "Failed")
	}
	retry := regexp.MustCompile(`/hosts/new/pane\?retry=([0-9a-f]+)`).FindStringSubmatch(body)[1]
	other := a.hx(http.MethodGet, "/hosts/new/pane?retry="+retry+"&replace=a1", nil).Body.String()
	if strings.Contains(other, "Replacing") || strings.Contains(other, `name="replace"`) {
		t.Errorf("replace link accepted for a host the attempt did not collide with:\n%s", other)
	}
}
