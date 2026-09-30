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

const addHostTestKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK3vTESTKEY nexus@frpi5"

// addHostFakeEnroller is a grid.Enroller the tests steer.
type addHostFakeEnroller struct {
	mu       sync.Mutex
	linkReqs []grid.SSHLinkRequest
	linkFn   func(ctx context.Context, req grid.SSHLinkRequest, progress func(grid.LinkStep)) (grid.HostInfo, error)
	code     grid.EnrollCode
	codeErr  error
	codeN    int
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
	enr := &addHostFakeEnroller{code: grid.EnrollCode{
		Code:    "GRID-ABCD-EFGH",
		Expires: time.Date(2026, 9, 30, 12, 15, 0, 0, time.UTC),
		Command: "curl -fsSL --insecure --pinnedpubkey sha256//PIN https://frpi5.local:8443/grid/install.sh | sudo sh -s -- GRID-ABCD-EFGH",
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

func sshForm(extra ...string) url.Values {
	v := url.Values{
		"address": {"pi4.local"}, "port": {"22"}, "user": {"pi"}, "display_name": {"Pi4"},
		"auth": {"password"}, "password": {"hunter2-secret"},
	}
	for i := 0; i+1 < len(extra); i += 2 {
		v.Set(extra[i], extra[i+1])
	}
	return v
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
	}
	for _, tc := range tests {
		rec := a.do(a.srv.Handler(), tc.method, tc.target, tc.opts...)
		if rec.Code != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, rec.Code, tc.want)
		}
	}
	if n := len(a.enr.requests()); n != 0 {
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
			`name="user"`, `value="pi"`, `name="display_name"`, `name="auth"`, `name="password"`, `type="password"`,
			addHostTestKey, `data-copy="#addhost-hubkey"`, `value="` + a.csrf + `"`, "Install agent &amp; link", "never stored",
			`hx-post="/hosts/new"`, `hx-post="/hosts/new/code"`,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("dialog lacks %q", want)
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
		a.srv.sshKey = nil
		defer func() { a.srv.sshKey = func() string { return addHostTestKey } }()
		body := a.hx(http.MethodGet, "/hosts/new", nil).Body.String()
		if !strings.Contains(body, "The hub has no SSH key available.") {
			t.Error("missing hint")
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
		{"missing password", sshForm("password", ""), "Enter the password for pi."},
		{"missing user", sshForm("user", ""), "Enter a user with sudo rights."},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// htmx: 200 so the fragment is swapped in.
			rec := a.hx(http.MethodPost, "/hosts/new", tc.form)
			if rec.Code != http.StatusOK {
				t.Fatalf("htmx status %d", rec.Code)
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
			// a plain request gets the real status
			rec = a.do(a.srv.Handler(), http.MethodPost, "/hosts/new",
				withCookies(a.cookie), withHeader(auth.CSRFHeader, a.csrf), withForm(tc.form))
			if rec.Code != http.StatusUnprocessableEntity {
				t.Errorf("plain status %d, want 422", rec.Code)
			}
		})
	}
	if n := len(a.enr.requests()); n != 0 {
		t.Errorf("enroller was called %d times for invalid input", n)
	}
	if strings.Contains(a.logs.String(), "hunter2-secret") {
		t.Error("the password reached the log")
	}
}

func TestAddHostFormKeepsFieldsButNeverThePassword(t *testing.T) {
	a := newAddHostEnv(t)
	body := a.hx(http.MethodPost, "/hosts/new", sshForm("address", "bad host", "display_name", "My Pi")).Body.String()
	if !strings.Contains(body, `value="bad host"`) || !strings.Contains(body, `value="My Pi"`) {
		t.Error("typed values are not kept")
	}
	if strings.Contains(body, "hunter2-secret") {
		t.Error("password in the HTML")
	}
	// the password field carries no value attribute at all
	if m := regexp.MustCompile(`<input[^>]*name="password"[^>]*>`).FindString(body); strings.Contains(m, "value=") {
		t.Errorf("password input has a value: %s", m)
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
	rec := a.hx(http.MethodPost, "/hosts/new", sshForm())
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
	if !strings.Contains(body, "accepted on first use") {
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
	rec := a.hx(http.MethodPost, "/hosts/new", sshForm("auth", "key", "password", "ignored-typed-password"))
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
			want: []string{"Failed", "A host with this name already exists. Choose another display name.", "Try again"},
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
			rec := a.hx(http.MethodPost, "/hosts/new", sshForm())
			poll := pollURL(t, rec.Body.String())
			deadline := time.Now().Add(2 * time.Second)
			var body string
			for !strings.Contains(body, "Failed") && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
				body = a.hx(http.MethodGet, poll, nil).Body.String()
				if m := pollURLRE.FindStringSubmatch(body); m != nil {
					poll = strings.ReplaceAll(m[1], "&amp;", "&")
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
		rec := a.hx(http.MethodPost, "/hosts/new", sshForm("address", fmt.Sprintf("pi%d.local", i)))
		if strings.Contains(rec.Body.String(), "form-error") {
			t.Fatalf("attempt %d refused: %s", i, rec.Body.String())
		}
	}
	rec := a.hx(http.MethodPost, "/hosts/new", sshForm())
	if !strings.Contains(rec.Body.String(), "Another host is being linked right now") {
		t.Errorf("4th attempt: %s", rec.Body.String())
	}
	rec = a.do(a.srv.Handler(), http.MethodPost, "/hosts/new",
		withCookies(a.cookie), withHeader(auth.CSRFHeader, a.csrf), withForm(sshForm()))
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("plain status %d, want 429", rec.Code)
	}
}

func TestAddHostAttemptsBelongToTheOperator(t *testing.T) {
	a := newAddHostEnv(t)
	done := make(chan struct{})
	a.enr.linkFn = func(context.Context, grid.SSHLinkRequest, func(grid.LinkStep)) (grid.HostInfo, error) {
		defer close(done)
		return grid.HostInfo{Name: "pi4", Online: true}, nil
	}
	rec := a.hx(http.MethodPost, "/hosts/new", sshForm())
	poll := pollURL(t, rec.Body.String())
	<-done
	id := strings.TrimPrefix(strings.SplitN(poll, "?", 2)[0], "/hosts/new/link/")
	reg := a.srv.links()
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
		"GRID-ABCD-EFGH", "valid 15 min · one use", "--pinnedpubkey sha256//PIN", `data-copy="#addhost-cmd"`,
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
	if strings.Contains(body, "GRID-ABCD-EFGH") {
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
	if strings.Contains(rec.Body.String(), "GRID-ABCD-EFGH") {
		t.Error("expired code shown")
	}
}

func TestAddHostCodeErrors(t *testing.T) {
	a := newAddHostEnv(t)
	a.enr.codeErr = grid.ErrUnsupported
	rec := a.hx(http.MethodPost, "/hosts/new/code", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Could not create an enrollment code.") || strings.Contains(rec.Body.String(), "GRID-ABCD-EFGH") {
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

func TestAddHostStatus(t *testing.T) {
	plain := httptest.NewRequest(http.MethodPost, "/hosts/new", nil)
	hx := httptest.NewRequest(http.MethodPost, "/hosts/new", nil)
	hx.Header.Set("HX-Request", "true")
	if addHostStatus(plain, 422) != 422 || addHostStatus(hx, 422) != 200 {
		t.Error("status mapping")
	}
}

func TestAddHostRoutesDoNotShadowHosts(t *testing.T) {
	a := newAddHostEnv(t)
	// /hosts/new is the dialog, not a host called "new"; the shell of a real host still works.
	if rec := a.get("/hosts/alpha/shell", withCookies(a.cookie)); rec.Code != http.StatusOK {
		t.Errorf("shell route = %d", rec.Code)
	}
}
