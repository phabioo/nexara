package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/phabioo/nexara/internal/config"
	"github.com/phabioo/nexara/internal/hub/auth"
	"github.com/phabioo/nexara/internal/hub/httpserver"
	"github.com/phabioo/nexara/internal/hub/setup"
	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/pki"
)

type commitEnv struct {
	t        *testing.T
	st       *store.Store
	auth     *auth.Service
	codes    *setup.Codes
	mode     *setup.Mode
	sessions *setup.Sessions
	logs     *syncBuffer
	cfgPath  string
	c        *committer

	applied   []config.HubConfig
	applyErr  error
	linked    [][]string
	linkErr   error
	setupCode string
}

func newCommitEnv(t *testing.T, withConfig bool) *commitEnv {
	t.Helper()
	dir := t.TempDir()
	st := openStore(t, dir)
	log, logs := testLogger()
	e := &commitEnv{t: t, st: st, auth: newAuth(t, st), logs: logs}
	e.codes = setup.NewCodes(setup.CodeOptions{})
	e.mode = setup.NewMode(st)
	e.sessions = setup.NewSessions(setup.SessionOptions{})
	code, _, err := e.codes.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	e.setupCode = code
	if !e.mode.Active(context.Background()) {
		t.Fatal("fresh store must be in setup mode")
	}
	e.c = &committer{
		st: st, auth: e.auth, codes: e.codes, sessions: e.sessions, mode: e.mode, log: log,
		listenPort: 8443,
		applyHub: func(c config.HubConfig) error {
			e.applied = append(e.applied, c)
			return e.applyErr
		},
		selfLink: func(_ context.Context, caps []string) error {
			e.linked = append(e.linked, caps)
			return e.linkErr
		},
	}
	if withConfig {
		e.cfgPath = filepath.Join(dir, "nexus.yaml")
		cfg := config.DefaultHub()
		cfg.Storage.Database = filepath.ToSlash(filepath.Join(dir, "nexus.db"))
		cfg.TLS.Dir = filepath.ToSlash(filepath.Join(dir, "pki"))
		if err := config.SaveHub(e.cfgPath, cfg); err != nil {
			t.Fatal(err)
		}
		e.c.configPath = e.cfgPath
	}
	return e
}

func goodResult() setup.Result {
	return setup.Result{
		OperatorID:  testOperator,
		Passphrase:  testPass,
		TOTPSkipped: true,
		Hub:         setup.HubInput{Name: "Home Hub", TimeZone: "Europe/Berlin", AgentHost: "frpi5.local", HTTPSPort: 8443, RetentionDays: 90},
		SelfLink:    setup.SelfLinkInput{Enabled: true, Capabilities: []string{"monitoring", "packages"}},
	}
}

func (e *commitEnv) users() int {
	e.t.Helper()
	n, err := e.st.CountUsers(context.Background())
	if err != nil {
		e.t.Fatal(err)
	}
	return n
}

func TestCommitSuccess(t *testing.T) {
	e := newCommitEnv(t, true)
	ctx := context.Background()

	// A setup session that must be cleared.
	token, _, err := e.sessions.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	out, err := e.c.Commit(ctx, goodResult(), "192.0.2.7")
	if err != nil {
		t.Fatal(err)
	}
	if out.OperatorID != testOperator || !out.SelfLink || len(out.Warnings) != 0 {
		t.Errorf("outcome = %+v", out)
	}

	// Operator: argon2id hash, no TOTP, can sign in.
	u, err := e.st.GetUserByOperatorID(ctx, testOperator)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(u.PassHash, "$argon2id$") || u.TOTPEnabled || u.TOTPSecretEnc != nil {
		t.Errorf("user = %+v", u)
	}
	if _, err := e.auth.Login(ctx, testOperator, testPass, "192.0.2.7", "test", false); err != nil {
		t.Errorf("new operator cannot sign in: %v", err)
	}

	// Setup mode closed everywhere.
	if e.mode.Active(ctx) {
		t.Error("setup mode still active")
	}
	if _, _, ok := e.codes.Current(); ok {
		t.Error("setup code still valid")
	}
	if e.codes.Verify(e.setupCode) == nil {
		t.Error("old setup code still verifies")
	}
	if _, ok := e.sessions.Lookup(token); ok {
		t.Error("setup session survived the commit")
	}

	// nexus.yaml carries the wizard's choices (name sanitized, port omitted when it is the listen port).
	cfg, err := config.LoadHub(e.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Hub.Name != "Home-Hub" || cfg.Hub.Timezone != "Europe/Berlin" || cfg.Hub.AgentAddress != "frpi5.local" ||
		cfg.Storage.History.HourDays != 90 || cfg.Hub.Listen != ":8443" {
		t.Errorf("config = %+v", cfg)
	}
	if len(e.applied) != 1 || e.applied[0].Hub.AgentAddress != "frpi5.local" {
		t.Errorf("applyHub calls = %+v", e.applied)
	}
	if len(e.linked) != 1 || strings.Join(e.linked[0], ",") != "monitoring,packages" {
		t.Errorf("self-link calls = %v", e.linked)
	}

	// Audit entry without secrets.
	entries, err := e.st.ListAudit(ctx, 20)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, a := range entries {
		if a.Action != ActionSetupCommit {
			continue
		}
		found = true
		if a.User != testOperator || a.Result != store.AuditOK || !strings.Contains(a.Detail, "192.0.2.7") {
			t.Errorf("audit = %+v", a)
		}
		if strings.Contains(a.Detail, testPass) {
			t.Error("passphrase in the audit detail")
		}
	}
	if !found {
		t.Errorf("no %s audit entry in %+v", ActionSetupCommit, entries)
	}
	if strings.Contains(e.logs.String(), testPass) {
		t.Error("passphrase in the log")
	}
}

func TestCommitSealsTOTP(t *testing.T) {
	e := newCommitEnv(t, false)
	ctx := context.Background()
	enr, err := auth.NewTOTP(testOperator)
	if err != nil {
		t.Fatal(err)
	}
	res := goodResult()
	res.TOTPSkipped, res.TOTPSecret = false, enr.Secret
	if _, err := e.c.Commit(ctx, res, "192.0.2.7"); err != nil {
		t.Fatal(err)
	}
	u, err := e.st.GetUserByOperatorID(ctx, testOperator)
	if err != nil {
		t.Fatal(err)
	}
	if !u.TOTPEnabled || len(u.TOTPSecretEnc) == 0 {
		t.Fatalf("totp not stored: %+v", u)
	}
	if strings.Contains(string(u.TOTPSecretEnc), enr.Secret) {
		t.Error("TOTP secret stored in clear")
	}
	plain, err := auth.Open(testKey(), u.TOTPSecretEnc, auth.AADTOTP)
	if err != nil || string(plain) != enr.Secret {
		t.Errorf("sealed secret does not open: %q %v", plain, err)
	}
	// Sign-in now asks for the second factor.
	if _, err := e.auth.Login(ctx, testOperator, testPass, "192.0.2.7", "test", false); !errors.Is(err, auth.ErrSecondFactorRequired) {
		t.Errorf("login err = %v, want ErrSecondFactorRequired", err)
	}
}

func TestCommitWithoutConfigPathAndSelfLink(t *testing.T) {
	// The demo wiring has neither nexus.yaml nor an own agent.
	e := newCommitEnv(t, false)
	e.c.applyHub, e.c.selfLink = nil, nil
	out, err := e.c.Commit(context.Background(), goodResult(), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if out.SelfLink || len(out.Warnings) != 0 || e.users() != 1 || e.mode.Active(context.Background()) {
		t.Errorf("outcome = %+v, users = %d", out, e.users())
	}
}

func TestCommitSelfLinkChoices(t *testing.T) {
	tests := []struct {
		name     string
		link     setup.SelfLinkInput
		wantCall bool
		wantCaps []string
	}{
		{"disabled", setup.SelfLinkInput{Enabled: false}, false, nil},
		{"enabled, chosen", setup.SelfLinkInput{Enabled: true, Capabilities: []string{"shell"}}, true, []string{"shell"}},
		// Nothing selected must not turn into "agent defaults" (nil).
		{"enabled, none chosen", setup.SelfLinkInput{Enabled: true}, true, []string{}},
	}
	for _, tt := range tests {
		e := newCommitEnv(t, false)
		res := goodResult()
		res.SelfLink = tt.link
		if _, err := e.c.Commit(context.Background(), res, "192.0.2.7"); err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		if (len(e.linked) == 1) != tt.wantCall {
			t.Errorf("%s: self-link calls = %v", tt.name, e.linked)
			continue
		}
		if tt.wantCall && (e.linked[0] == nil || strings.Join(e.linked[0], ",") != strings.Join(tt.wantCaps, ",")) {
			t.Errorf("%s: caps = %#v, want %#v", tt.name, e.linked[0], tt.wantCaps)
		}
	}
}

func TestCommitWarningsDoNotKeepSetupOpen(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*commitEnv)
		want   string
	}{
		{"self-link fails", func(e *commitEnv) { e.linkErr = errors.New("disk full") }, "own agent"},
		{"apply fails", func(e *commitEnv) { e.applyErr = errors.New("cert dir not writable") }, "restart"},
	}
	for _, tt := range tests {
		e := newCommitEnv(t, true)
		tt.mutate(e)
		out, err := e.c.Commit(context.Background(), goodResult(), "192.0.2.7")
		if err != nil {
			t.Fatalf("%s: commit failed although the operator could be created: %v", tt.name, err)
		}
		if len(out.Warnings) != 1 || !strings.Contains(out.Warnings[0], tt.want) {
			t.Errorf("%s: warnings = %v", tt.name, out.Warnings)
		}
		if strings.Contains(strings.Join(out.Warnings, " "), "disk full") || strings.Contains(strings.Join(out.Warnings, " "), "cert dir") {
			t.Errorf("%s: warning leaks the cause: %v", tt.name, out.Warnings)
		}
		if e.users() != 1 || e.mode.Active(context.Background()) {
			t.Errorf("%s: users=%d, setup mode still active", tt.name, e.users())
		}
		entries, _ := e.st.ListAudit(context.Background(), 10)
		var result string
		for _, a := range entries {
			if a.Action == ActionSetupCommit {
				result = a.Result
			}
		}
		if result != store.AuditError {
			t.Errorf("%s: audit result = %q, want %q so the problem is visible", tt.name, result, store.AuditError)
		}
	}
}

func TestCommitRejections(t *testing.T) {
	bad := func(mutate func(*setup.Result)) setup.Result {
		r := goodResult()
		mutate(&r)
		return r
	}
	tests := []struct {
		name string
		res  setup.Result
		key  string // expected field of the setup.ValidationError
		msg  string // expected message of that field, if set
	}{
		{"weak passphrase", bad(func(r *setup.Result) { r.Passphrase = "short" }), "passphrase", "Use at least 12 characters."},
		{"over-long passphrase", bad(func(r *setup.Result) { r.Passphrase = strings.Repeat("a", auth.MaxPassphraseLength+1) }), "passphrase", "Use at most 1024 characters."},
		{"retention out of range", bad(func(r *setup.Result) { r.Hub.RetentionDays = 0 }), "hub", ""},
		{"bad time zone", bad(func(r *setup.Result) { r.Hub.TimeZone = "Mars/Base" }), "hub", ""},
	}
	for _, tt := range tests {
		e := newCommitEnv(t, true)
		before, _ := os.ReadFile(e.cfgPath)
		_, err := e.c.Commit(context.Background(), tt.res, "192.0.2.7")
		var verr setup.ValidationError
		if !errors.As(err, &verr) || verr[tt.key] == "" {
			t.Errorf("%s: err = %v, want a ValidationError for %q", tt.name, err, tt.key)
		}
		if tt.msg != "" && verr[tt.key] != tt.msg {
			t.Errorf("%s: message = %q, want %q", tt.name, verr[tt.key], tt.msg)
		}
		after, _ := os.ReadFile(e.cfgPath)
		if string(before) != string(after) {
			t.Errorf("%s: nexus.yaml changed although the commit failed", tt.name)
		}
		if e.users() != 0 || !e.mode.Active(context.Background()) || len(e.linked) != 0 || len(e.applied) != 0 {
			t.Errorf("%s: side effects after a failed commit: users=%d linked=%v applied=%v", tt.name, e.users(), e.linked, e.applied)
		}
		if _, _, ok := e.codes.Current(); !ok {
			t.Errorf("%s: setup code invalidated by a failed commit", tt.name)
		}
	}
}

func TestCommitAlreadySetUp(t *testing.T) {
	e := newCommitEnv(t, true)
	createOperator(t, e.st, "someone", testPass)
	e.mode.Invalidate()
	before, _ := os.ReadFile(e.cfgPath)
	if _, err := e.c.Commit(context.Background(), goodResult(), "192.0.2.7"); !errors.Is(err, httpserver.ErrSetupDone) {
		t.Fatalf("err = %v, want ErrSetupDone", err)
	}
	if after, _ := os.ReadFile(e.cfgPath); string(before) != string(after) {
		t.Error("nexus.yaml written although an operator exists")
	}
	if e.users() != 1 {
		t.Errorf("users = %d", e.users())
	}
}

func TestCommitConcurrentCreatesOneOperator(t *testing.T) {
	e := newCommitEnv(t, false)
	var wg sync.WaitGroup
	errs := make([]error, 6)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := goodResult()
			res.OperatorID = "op" + string(rune('a'+i)) // different IDs: only the count check can stop them
			_, errs[i] = e.c.Commit(context.Background(), res, "192.0.2.7")
		}()
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case !errors.Is(err, httpserver.ErrSetupDone):
			t.Errorf("unexpected error: %v", err)
		}
	}
	if ok != 1 || e.users() != 1 {
		t.Errorf("successful commits = %d, users = %d, want 1 and 1", ok, e.users())
	}
}

func TestCommitKeepsUnrelatedConfig(t *testing.T) {
	e := newCommitEnv(t, true)
	cur, _ := config.LoadHub(e.cfgPath)
	cur.Security.SessionIdleHours = 6
	cur.Alerts.CPUTempC = 80
	if err := config.SaveHub(e.cfgPath, cur); err != nil {
		t.Fatal(err)
	}
	if _, err := e.c.Commit(context.Background(), goodResult(), "192.0.2.7"); err != nil {
		t.Fatal(err)
	}
	got, err := config.LoadHub(e.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if got.Security.SessionIdleHours != 6 || got.Alerts.CPUTempC != 80 || got.Storage.Database != cur.Storage.Database {
		t.Errorf("unrelated settings changed: %+v", got)
	}
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(e.cfgPath); err != nil || fi.Mode().Perm() != 0o640 {
			t.Errorf("nexus.yaml mode = %v %v, want 0640", fi.Mode().Perm(), err)
		}
	}
}

func TestHubConfigName(t *testing.T) {
	tests := []struct{ in, want string }{
		{"frpi5", "frpi5"},
		{"Home Hub", "Home-Hub"},
		{"  spaced  out  ", "spaced-out"},
		{"Büro-Pi", "B-ro-Pi"},
		{"--x--", "x"},
		{"a.b_c-d", "a.b_c-d"},
		{"", "nexus"},
		{"!!!", "nexus"},
		{strings.Repeat("a", 80), strings.Repeat("a", 63)},
		{strings.Repeat("a", 62) + " b", strings.Repeat("a", 62)},
	}
	for _, tt := range tests {
		got := hubConfigName(tt.in)
		if got != tt.want {
			t.Errorf("hubConfigName(%q) = %q, want %q", tt.in, got, tt.want)
		}
		cfg := config.DefaultHub()
		cfg.Hub.Name = got
		if err := cfg.Validate(); err != nil {
			t.Errorf("hubConfigName(%q) = %q is rejected by config: %v", tt.in, got, err)
		}
	}
}

func TestAgentAddressHelpers(t *testing.T) {
	addrTests := []struct {
		host         string
		port, listen int
		want         string
	}{
		{"frpi5.local", 8443, 8443, "frpi5.local"},
		{"frpi5.local", 9443, 8443, "frpi5.local:9443"},
		{"192.0.2.5", 8443, 8443, "192.0.2.5"},
		{" frpi5.local ", 8443, 8443, "frpi5.local"},
		{"fe80::1", 8443, 8443, "[fe80::1]:8443"},
	}
	for _, tt := range addrTests {
		if got := agentAddressFor(tt.host, tt.port, tt.listen); got != tt.want {
			t.Errorf("agentAddressFor(%q, %d, %d) = %q, want %q", tt.host, tt.port, tt.listen, got, tt.want)
		}
	}

	resolveTests := []struct {
		addr     string
		wantHost string
		wantPort int
	}{
		{"", "fallback.local", 8443},
		{"frpi5.local", "frpi5.local", 8443},
		{"frpi5.local:9443", "frpi5.local", 9443},
		{"192.0.2.5:9", "192.0.2.5", 9},
		{"[fe80::1]:9443", "fe80::1", 9443},
		{"[fe80::1]", "fe80::1", 8443},
		{"host:99999", "host:99999", 8443}, // invalid port: config validation rejects it elsewhere
	}
	for _, tt := range resolveTests {
		host, port := resolveAgentAddress(tt.addr, "fallback.local", 8443)
		if host != tt.wantHost || port != tt.wantPort {
			t.Errorf("resolveAgentAddress(%q) = %q, %d; want %q, %d", tt.addr, host, port, tt.wantHost, tt.wantPort)
		}
	}
}

func TestHubConfigFrom(t *testing.T) {
	cur := config.DefaultHub()
	cur.Security.SessionIdleHours = 7
	got := hubConfigFrom(cur, setup.HubInput{Name: "Pi Hub", TimeZone: "UTC", AgentHost: "hub.example", HTTPSPort: 9000, RetentionDays: 30}, 8443)
	if got.Hub.Name != "Pi-Hub" || got.Hub.AgentAddress != "hub.example:9000" || got.Storage.History.HourDays != 30 || got.Security.SessionIdleHours != 7 {
		t.Errorf("config = %+v", got)
	}
	if err := got.Validate(); err != nil {
		t.Errorf("result must validate: %v", err)
	}
}

func TestCommitAgentHostMustFitTheCA(t *testing.T) {
	ca, err := pki.LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		host string
		ok   bool
	}{
		{"frpi5.local", true},
		{"192.168.1.20", true},
		{"fd00::20", true},
		{"hub.example.com", false},
		{"8.8.8.8", false},
	}
	for _, tt := range tests {
		e := newCommitEnv(t, true)
		e.c.permits = ca.Permits
		res := goodResult()
		res.Hub.AgentHost = tt.host
		_, err := e.c.Commit(context.Background(), res, "192.0.2.7")
		var verr setup.ValidationError
		switch {
		case tt.ok && err != nil:
			t.Errorf("%s: unexpected error %v", tt.host, err)
		case !tt.ok && (!errors.As(err, &verr) || verr["hub"] != agentHostNotPermitted):
			t.Errorf("%s: err = %v, want the agent-host validation error", tt.host, err)
		case !tt.ok && e.users() != 0:
			t.Errorf("%s: operator created although the agent host was refused", tt.host)
		}
	}
}
