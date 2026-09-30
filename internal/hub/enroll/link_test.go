package enroll

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/hub/store"
)

const testPassword = "hunter2-Secret-PW!"

const osReleaseDebian = `PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
ID=debian
`

// fakeConn records every command with its stdin and answers like a Debian host.
type fakeConn struct {
	mu     sync.Mutex
	cmds   []string
	stdins [][]byte
	files  map[string][]byte
	tmpN   int
	closed bool

	// override runs first; a non-nil handled result short-circuits the default behaviour.
	override func(cmd string, stdin []byte) (out []byte, err error, handled bool)
	env      *testEnv
}

func (f *fakeConn) HostKeyFingerprint() string { return "SHA256:fakeHostKeyFingerprint" }

func (f *fakeConn) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakeConn) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

func (f *fakeConn) Run(_ context.Context, cmd string, stdin io.Reader) ([]byte, error) {
	var in []byte
	if stdin != nil {
		in, _ = io.ReadAll(stdin)
	}
	f.mu.Lock()
	f.cmds = append(f.cmds, cmd)
	f.stdins = append(f.stdins, in)
	override := f.override
	f.mu.Unlock()

	if override != nil {
		if out, err, handled := override(cmd, in); handled {
			return out, err
		}
	}
	switch {
	case cmd == "uname -s":
		return []byte("Linux\n"), nil
	case cmd == "uname -m":
		return []byte("aarch64\n"), nil
	case cmd == "cat /etc/os-release":
		return []byte(osReleaseDebian), nil
	case cmd == "mktemp":
		f.mu.Lock()
		defer f.mu.Unlock()
		f.tmpN++
		return []byte(fmt.Sprintf("/tmp/tmp.X%d\n", f.tmpN)), nil
	case strings.HasPrefix(cmd, "cat > "):
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.files == nil {
			f.files = map[string][]byte{}
		}
		f.files[strings.TrimPrefix(cmd, "cat > ")] = in
		return nil, nil
	case strings.Contains(cmd, "grid-agent enroll --hub"):
		fields := strings.Fields(cmd)
		for i, fl := range fields {
			if fl == "--token" && i+1 < len(fields) {
				w, _ := f.env.post(fields[i+1], "pi-kitchen", "192.168.10.23")
				if w.Code != 200 {
					return nil, &ExitError{Status: 1, Stderr: "enroll: rejected"}
				}
				return nil, nil
			}
		}
		return nil, &ExitError{Status: 2, Stderr: "no token"}
	}
	return nil, nil
}

func (f *fakeConn) commands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.cmds...)
}

type fakeDialer struct {
	conn       *fakeConn
	err        error
	calls      int
	cfg        SSHDialConfig
	pwAtDial   string
	signerUsed bool
}

func (d *fakeDialer) Dial(_ context.Context, cfg SSHDialConfig) (SSHConn, error) {
	d.calls++
	d.cfg = cfg
	d.pwAtDial = string(cfg.Password)
	d.signerUsed = cfg.Signer != nil
	if d.err != nil {
		return nil, d.err
	}
	return d.conn, nil
}

type linkResult struct {
	info  grid.HostInfo
	err   error
	steps []grid.LinkStep
	conn  *fakeConn
	dial  *fakeDialer
	env   *testEnv
}

func (r linkResult) summary() string {
	var parts []string
	for _, s := range r.steps {
		parts = append(parts, string(s.Step)+":"+string(s.State))
	}
	return strings.Join(parts, ",")
}

func (r linkResult) step(name grid.LinkStepName, state grid.LinkState) (grid.LinkStep, bool) {
	for _, s := range r.steps {
		if s.Step == name && s.State == state {
			return s, true
		}
	}
	return grid.LinkStep{}, false
}

func defaultRequest() grid.SSHLinkRequest {
	return grid.SSHLinkRequest{Address: "pi-kitchen.local", User: "pi", Password: grid.Secret(testPassword), DisplayName: "Kitchen"}
}

func runLink(t *testing.T, req grid.SSHLinkRequest, tweak func(*fakeConn, *fakeDialer), mods ...func(*Options)) linkResult {
	t.Helper()
	conn := &fakeConn{}
	dial := &fakeDialer{conn: conn}
	mods = append([]func(*Options){func(o *Options) { o.SSH = dial }}, mods...)
	e := newEnv(t, mods...)
	conn.env = e
	if tweak != nil {
		tweak(conn, dial)
	}
	var steps []grid.LinkStep
	info, err := e.svc.LinkViaSSH(context.Background(), grid.Actor{Operator: "1", IP: "192.0.2.1"}, req, func(s grid.LinkStep) { steps = append(steps, s) })
	return linkResult{info: info, err: err, steps: steps, conn: conn, dial: dial, env: e}
}

// assertNoSecret checks every place the password could leak to.
func assertNoSecret(t *testing.T, r linkResult, secret string) {
	t.Helper()
	for _, c := range r.conn.commands() {
		if strings.Contains(c, secret) {
			t.Errorf("password in command line: %q", c)
		}
	}
	for _, s := range r.steps {
		if strings.Contains(s.Detail, secret) {
			t.Errorf("password in progress detail: %+v", s)
		}
	}
	if r.err != nil && strings.Contains(r.err.Error(), secret) {
		t.Errorf("password in error: %v", r.err)
	}
	if strings.Contains(r.env.logs.String(), secret) {
		t.Errorf("password in log: %s", r.env.logs.String())
	}
	for _, a := range r.env.auditActions() {
		if strings.Contains(a.Detail, secret) || strings.Contains(a.Host, secret) || strings.Contains(a.Action, secret) {
			t.Errorf("password in audit: %+v", a)
		}
	}
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func TestLinkViaSSHWithPassword(t *testing.T) {
	var waitedFor grid.HostID
	var hadDeadline bool
	r := runLink(t, defaultRequest(), nil, func(o *Options) {
		o.WaitOnline = func(ctx context.Context, id grid.HostID) error {
			waitedFor = id
			_, hadDeadline = ctx.Deadline()
			return nil
		}
	})
	if r.err != nil {
		t.Fatal(r.err)
	}
	want := "connect:running,connect:done,detect:running,detect:done,install:running,install:done,enroll:running,enroll:done,online:running,online:done"
	if got := r.summary(); got != want {
		t.Fatalf("progress\n got %s\nwant %s", got, want)
	}
	if s, _ := r.step(grid.StepConnect, grid.LinkDone); s.Detail != "Connected as pi · Host key SHA256:fakeHostKeyFingerprint" {
		t.Fatalf("connect detail %q", s.Detail)
	}
	if s, _ := r.step(grid.StepDetect, grid.LinkDone); s.Detail != "Debian 12 · arm64" {
		t.Fatalf("detect detail %q", s.Detail)
	}

	// Result and stored host.
	if r.info.Name != "pi-kitchen" || r.info.DisplayName != "Kitchen" || r.info.Address != "pi-kitchen.local" ||
		r.info.OS != "linux" || r.info.Arch != "arm64" || !r.info.Online || r.info.ID == "" {
		t.Fatalf("info %+v", r.info)
	}
	if waitedFor != r.info.ID || !hadDeadline {
		t.Fatalf("WaitOnline(%q, deadline=%v)", waitedFor, hadDeadline)
	}
	h, err := r.env.st.GetHost(context.Background(), string(r.info.ID))
	if err != nil || h.DisplayName != "Kitchen" || h.Address != "pi-kitchen.local" {
		t.Fatalf("stored host %+v %v", h, err)
	}

	// Dial: password auth, 10 s timeout, port 22, and the secret wiped afterwards.
	if r.dial.cfg.Addr != "pi-kitchen.local:22" || r.dial.cfg.User != "pi" || r.dial.pwAtDial != testPassword ||
		r.dial.signerUsed || r.dial.cfg.Timeout != 10*time.Second {
		t.Fatalf("dial config %+v", r.dial.cfg)
	}
	if !allZero(r.dial.cfg.Password) {
		t.Fatal("password copy was not zeroed")
	}
	if !r.conn.isClosed() {
		t.Fatal("connection left open")
	}

	// Commands.
	cmds := r.conn.commands()
	joined := strings.Join(cmds, "\n")
	for _, want := range []string{
		"uname -s", "uname -m", "cat /etc/os-release", "mktemp",
		"sudo -S -p '' sh -c 'systemctl stop grid-agent >/dev/null 2>&1; install -m 0755 /tmp/tmp.X1 /usr/local/bin/grid-agent'",
		"sudo -S -p '' /usr/local/bin/grid-agent enroll --hub https://frpi5.local:8443 --token GRID-",
		"--ca-fingerprint " + r.env.ca.Fingerprint() + " --shell-user pi",
		"sudo -S -p '' sh -c 'install -m 0644 /tmp/tmp.X2 /etc/systemd/system/grid-agent.service && systemctl daemon-reload && systemctl enable --now grid-agent'",
		"rm -f /tmp/tmp.X1 /tmp/tmp.X2",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing command %q in:\n%s", want, joined)
		}
	}
	if !bytes.Equal(r.conn.files["/tmp/tmp.X1"], testBinary.Data) {
		t.Error("binary not uploaded")
	}
	if string(r.conn.files["/tmp/tmp.X2"]) != unitFile {
		t.Error("unit not uploaded")
	}
	// The password travels only as the first stdin line of each sudo call.
	sudoCalls := 0
	r.conn.mu.Lock()
	for i, c := range r.conn.cmds {
		if strings.HasPrefix(c, "sudo ") {
			sudoCalls++
			if string(r.conn.stdins[i]) != testPassword+"\n" {
				t.Errorf("sudo stdin for %q = %q", c, r.conn.stdins[i])
			}
		} else if bytes.Contains(r.conn.stdins[i], []byte(testPassword)) {
			t.Errorf("password sent on stdin of non-sudo command %q", c)
		}
	}
	r.conn.mu.Unlock()
	if sudoCalls != 3 {
		t.Errorf("%d sudo calls, want 3", sudoCalls)
	}
	assertNoSecret(t, r, testPassword)

	// Audit: host.link ok with address and user only.
	var found bool
	for _, a := range r.env.auditActions() {
		if a.Action == "host.link" {
			found = true
			if a.Result != store.AuditOK || a.User != "1" || a.Host != "pi-kitchen" || a.Detail != "pi@pi-kitchen.local:22 [password]" {
				t.Fatalf("audit %+v", a)
			}
		}
	}
	if !found {
		t.Fatal("no host.link audit entry")
	}
}

func TestLinkViaSSHWithHubKey(t *testing.T) {
	req := defaultRequest()
	req.Password, req.UseHubKey, req.Port = "", true, 2222
	r := runLink(t, req, nil)
	if r.err != nil {
		t.Fatal(r.err)
	}
	if !r.dial.signerUsed || r.dial.cfg.Password != nil || r.dial.cfg.Addr != "pi-kitchen.local:2222" {
		t.Fatalf("dial %+v", r.dial.cfg)
	}
	r.conn.mu.Lock()
	defer r.conn.mu.Unlock()
	n := 0
	for i, c := range r.conn.cmds {
		if strings.HasPrefix(c, "sudo ") {
			n++
			if !strings.HasPrefix(c, "sudo -n ") || strings.Contains(c, "-S") {
				t.Errorf("hub key must use sudo -n: %q", c)
			}
			if len(r.conn.stdins[i]) != 0 {
				t.Errorf("unexpected stdin for %q", c)
			}
		}
	}
	if n != 3 {
		t.Fatalf("%d sudo calls", n)
	}
	for _, a := range r.env.auditActions() {
		if a.Action == "host.link" && a.Detail != "pi@pi-kitchen.local:2222 [hub key]" {
			t.Fatalf("audit %+v", a)
		}
	}
}

func TestLinkViaSSHWithoutWaitOnline(t *testing.T) {
	r := runLink(t, defaultRequest(), nil)
	if r.err != nil {
		t.Fatal(r.err)
	}
	if _, ok := r.step(grid.StepOnline, grid.LinkDone); !ok {
		t.Fatalf("progress %s", r.summary())
	}
}

func TestLinkViaSSHFailures(t *testing.T) {
	sorry := func(cmd string) bool { return strings.HasPrefix(cmd, "sudo ") }
	tests := []struct {
		name      string
		step      grid.LinkStepName
		detailHas string
		tweak     func(*fakeConn, *fakeDialer)
		wait      func(context.Context, grid.HostID) error
		cleanup   bool // temp files exist on the host and must be removed
	}{
		{
			name: "connect refused", step: grid.StepConnect, detailHas: "Could not connect",
			tweak: func(_ *fakeConn, d *fakeDialer) {
				d.err = errors.New("dial tcp 10.0.0.9:22: connect: connection refused")
			},
		},
		{
			name: "auth failed echoing the password", step: grid.StepConnect, detailHas: "Could not connect",
			tweak: func(_ *fakeConn, d *fakeDialer) {
				d.err = errors.New("ssh: unable to authenticate (tried " + testPassword + ")")
			},
		},
		{
			name: "not linux", step: grid.StepDetect, detailHas: "Unsupported system",
			tweak: func(c *fakeConn, _ *fakeDialer) {
				c.override = func(cmd string, _ []byte) ([]byte, error, bool) {
					if cmd == "uname -s" {
						return []byte("Darwin\n"), nil, true
					}
					return nil, nil, false
				}
			},
		},
		{
			name: "unknown architecture", step: grid.StepDetect, detailHas: "Unsupported architecture",
			tweak: func(c *fakeConn, _ *fakeDialer) {
				c.override = func(cmd string, _ []byte) ([]byte, error, bool) {
					if cmd == "uname -m" {
						return []byte("mips\n"), nil, true
					}
					return nil, nil, false
				}
			},
		},
		{
			name: "no embedded binary", step: grid.StepDetect, detailHas: "no Grid Agent build for linux/amd64",
			tweak: func(c *fakeConn, _ *fakeDialer) {
				c.override = func(cmd string, _ []byte) ([]byte, error, bool) {
					if cmd == "uname -m" {
						return []byte("x86_64\n"), nil, true
					}
					return nil, nil, false
				}
			},
		},
		{
			name: "upload fails", step: grid.StepInstall, detailHas: "Upload failed", cleanup: true,
			tweak: func(c *fakeConn, _ *fakeDialer) {
				c.override = func(cmd string, _ []byte) ([]byte, error, bool) {
					if strings.HasPrefix(cmd, "cat > ") {
						return nil, &ExitError{Status: 1, Stderr: "No space left on device"}, true
					}
					return nil, nil, false
				}
			},
		},
		{
			name: "sudo password wrong, stderr echoes it", step: grid.StepInstall, detailHas: "Install failed", cleanup: true,
			tweak: func(c *fakeConn, _ *fakeDialer) {
				c.override = func(cmd string, _ []byte) ([]byte, error, bool) {
					if sorry(cmd) {
						return nil, &ExitError{Status: 1, Stderr: "sudo: 1 incorrect password attempt for " + testPassword}, true
					}
					return nil, nil, false
				}
			},
		},
		{
			name: "enroll command fails", step: grid.StepEnroll, detailHas: "Enrollment failed: enroll: cannot reach the hub", cleanup: true,
			tweak: func(c *fakeConn, _ *fakeDialer) {
				c.override = func(cmd string, _ []byte) ([]byte, error, bool) {
					if strings.Contains(cmd, "grid-agent enroll --hub") {
						return nil, &ExitError{Status: 1, Stderr: "enroll: cannot reach the hub"}, true
					}
					return nil, nil, false
				}
			},
		},
		{
			name: "agent never reports to the hub", step: grid.StepEnroll, detailHas: "did not report back", cleanup: true,
			tweak: func(c *fakeConn, _ *fakeDialer) {
				c.override = func(cmd string, _ []byte) ([]byte, error, bool) {
					if strings.Contains(cmd, "grid-agent enroll --hub") {
						return nil, nil, true // exits 0 but never contacted the hub
					}
					return nil, nil, false
				}
			},
		},
		{
			name: "unit installation fails", step: grid.StepEnroll, detailHas: "Starting the agent failed", cleanup: true,
			tweak: func(c *fakeConn, _ *fakeDialer) {
				c.override = func(cmd string, _ []byte) ([]byte, error, bool) {
					if strings.Contains(cmd, "systemctl enable --now") {
						return nil, &ExitError{Status: 1, Stderr: "Failed to enable unit"}, true
					}
					return nil, nil, false
				}
			},
		},
		{
			name: "agent does not come online", step: grid.StepOnline, detailHas: "did not come online within",
			wait: func(context.Context, grid.HostID) error { return context.DeadlineExceeded },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := runLink(t, defaultRequest(), tt.tweak, func(o *Options) {
				if tt.wait != nil {
					o.WaitOnline = tt.wait
				}
			})
			if !errors.Is(r.err, grid.ErrLinkFailed) {
				t.Fatalf("error %v", r.err)
			}
			if r.info.ID != "" {
				t.Fatalf("host info returned on failure: %+v", r.info)
			}
			last := r.steps[len(r.steps)-1]
			if last.Step != tt.step || last.State != grid.LinkFailed || !strings.Contains(last.Detail, tt.detailHas) {
				t.Fatalf("last step %+v, want failed %s containing %q\nall: %s", last, tt.step, tt.detailHas, r.summary())
			}
			// Earlier steps are done, and no later step started.
			seen := false
			for _, s := range r.steps {
				if seen {
					t.Fatalf("step %+v after the failure", s)
				}
				if s.Step == tt.step && s.State == grid.LinkFailed {
					seen = true
				}
			}
			assertNoSecret(t, r, testPassword)
			if r.dial.calls == 1 && r.dial.err == nil && !r.conn.isClosed() {
				t.Error("connection left open")
			}
			if tt.cleanup && !strings.Contains(strings.Join(r.conn.commands(), "\n"), "rm -f /tmp/tmp.X1") {
				t.Errorf("temp files not removed: %v", r.conn.commands())
			}
			var audited bool
			for _, a := range r.env.auditActions() {
				if a.Action == "host.link" {
					audited = true
					if a.Result != store.AuditError || a.Detail != "pi@pi-kitchen.local:22 [password] failed" {
						t.Fatalf("audit %+v", a)
					}
				}
			}
			if !audited {
				t.Fatal("failure not audited")
			}
		})
	}
}

func TestLinkViaSSHInvalidArguments(t *testing.T) {
	tests := []struct {
		name string
		mod  func(*grid.SSHLinkRequest)
	}{
		{"root user", func(r *grid.SSHLinkRequest) { r.User = "root" }},
		{"empty user", func(r *grid.SSHLinkRequest) { r.User = "" }},
		{"shell metacharacters in user", func(r *grid.SSHLinkRequest) { r.User = "pi;reboot" }},
		{"space in user", func(r *grid.SSHLinkRequest) { r.User = "pi user" }},
		{"bad address", func(r *grid.SSHLinkRequest) { r.Address = "x y" }},
		{"empty address", func(r *grid.SSHLinkRequest) { r.Address = "" }},
		{"port too big", func(r *grid.SSHLinkRequest) { r.Port = 70000 }},
		{"negative port", func(r *grid.SSHLinkRequest) { r.Port = -1 }},
		{"password and key", func(r *grid.SSHLinkRequest) { r.UseHubKey = true }},
		{"neither", func(r *grid.SSHLinkRequest) { r.Password = "" }},
		{"control char in name", func(r *grid.SSHLinkRequest) { r.DisplayName = "a\nb" }},
		{"long name", func(r *grid.SSHLinkRequest) { r.DisplayName = strings.Repeat("x", 65) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := defaultRequest()
			tt.mod(&req)
			r := runLink(t, req, nil)
			if !errors.Is(r.err, grid.ErrInvalidArgument) {
				t.Fatalf("error %v", r.err)
			}
			if r.dial.calls != 0 || len(r.steps) != 0 {
				t.Fatal("connected despite invalid request")
			}
		})
	}
}

func TestLinkViaSSHNilProgressAndCancel(t *testing.T) {
	conn := &fakeConn{}
	dial := &fakeDialer{conn: conn}
	e := newEnv(t, func(o *Options) { o.SSH = dial })
	conn.env = e
	if _, err := e.svc.LinkViaSSH(context.Background(), grid.Actor{}, defaultRequest(), nil); err != nil {
		t.Fatal(err)
	}
}

func TestDistroName(t *testing.T) {
	tests := []struct{ in, want string }{
		{osReleaseDebian, "Debian 12"},
		{"NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04 LTS\"\n", "Ubuntu 24.04"},
		{"PRETTY_NAME=\"Raspbian Something\"\n", "Raspbian Something"},
		{"", "Linux"},
		{"garbage", "Linux"},
	}
	for _, tt := range tests {
		if got := distroName(tt.in); got != tt.want {
			t.Errorf("distroName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestArchFromUname(t *testing.T) {
	tests := []struct {
		in, want string
		ok       bool
	}{
		{"aarch64\n", "arm64", true}, {"arm64", "arm64", true}, {"x86_64", "amd64", true},
		{"armv7l", "", false}, {"mips", "", false}, {"", "", false},
	}
	for _, tt := range tests {
		got, ok := archFromUname(tt.in)
		if got != tt.want || ok != tt.ok {
			t.Errorf("archFromUname(%q) = %q,%v", tt.in, got, ok)
		}
	}
}
