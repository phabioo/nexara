package packages

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/protocol"
)

// --- fakes -----------------------------------------------------------------

type fakeRunner struct {
	calls []Command
	// handler produces output and result for a call.
	handler func(ctx context.Context, c Command, emit func(protocol.JobStream, string)) (int, error)
}

func (f *fakeRunner) Run(ctx context.Context, c Command, emit func(protocol.JobStream, string)) (int, error) {
	f.calls = append(f.calls, c)
	if f.handler == nil {
		return 0, nil
	}
	return f.handler(ctx, c, emit)
}

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }
func (c *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.now = c.now.Add(d)
	return nil
}

// fakeLocks reports the given path as locked until the clock passes until.
type fakeLocks struct {
	clock *fakeClock
	path  string
	until time.Time
	err   error
}

func (l *fakeLocks) Locked(path string) (bool, error) {
	if l.err != nil {
		return false, l.err
	}
	return path == l.path && l.clock.now.Before(l.until), nil
}

type fakeFiles map[string]bool

func (f fakeFiles) Exists(p string) bool { return f[p] }

func newTestApt(r Runner, files fakeFiles) (*Apt, *fakeClock) {
	clk := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	return newApt(r, &fakeLocks{clock: clk}, files, clk), clk
}

// --- fixtures (Raspberry Pi OS bookworm, arm64) ------------------------------

var dpkgQueryFixture = []string{
	"base-files\t12+rpt1+deb12u1\t350\tii \tDebian base system miscellaneous files",
	"bash\t5.2.15-2+b2\t7490\tii \tGNU Bourne Again SHell",
	"libssl3:arm64\t3.0.11-1~deb12u1\t5142\tii \tSecure Sockets Layer toolkit - shared libraries",
	"raspberrypi-kernel\t1:1.20230405-1\t139561\tii \tRaspberry Pi bootloader",
	"old-lib\t1.0-1\t99\tii \tAuto installed leftover",
	"removed-pkg\t2.0-1\t10\trc \tRemoved but config files remain",
	"zsh\t5.9-4+b2\t\tii \tshell with lots of features",
	"half\t1.0\t5\tiU \tNot fully configured",
}

var upgradeSimFixture = []string{
	"NOTE: This is only a simulation!",
	"      apt-get needs root privileges for real execution.",
	"Reading package lists...",
	"Building dependency tree...",
	"Calculating upgrade...",
	"The following packages will be upgraded:",
	"  libssl3 raspberrypi-kernel",
	"2 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.",
	"Inst libssl3:arm64 [3.0.11-1~deb12u1] (3.0.11-1~deb12u2 Raspbian:12.2/stable-security [arm64])",
	"Inst raspberrypi-kernel [1:1.20230405-1] (1:1.20230405-1+rpt1 Raspberry Pi Foundation:stable [arm64])",
	"Inst brand-new-dep (2.0 Debian:stable [all])",
	"Conf libssl3:arm64 (3.0.11-1~deb12u2 Raspbian:12.2/stable-security [arm64])",
}

var autoremoveSimFixture = []string{
	"Reading package lists...",
	"The following packages will be REMOVED:",
	"  old-lib",
	"0 upgraded, 0 newly installed, 1 to remove and 0 not upgraded.",
	"Remv old-lib [1.0-1]",
}

func listRunner() *fakeRunner {
	return &fakeRunner{handler: func(_ context.Context, c Command, emit func(protocol.JobStream, string)) (int, error) {
		var lines []string
		switch {
		case c.Path == dpkgQueryPath:
			lines = dpkgQueryFixture
		case c.Path == aptGetPath && c.Args[len(c.Args)-1] == "upgrade":
			lines = upgradeSimFixture
		case c.Path == aptGetPath && c.Args[len(c.Args)-1] == "autoremove":
			lines = autoremoveSimFixture
		case c.Path == aptCachePath:
			lines = []string{
				"libssl3 - Secure Sockets Layer toolkit - shared libraries",
				"libssl-dev - Secure Sockets Layer toolkit - development files",
				"libssl-dev - duplicate",
				"zsh - shell with lots of features",
				"garbage line without a valid name!",
			}
		}
		for _, l := range lines {
			emit(protocol.StreamStdout, l)
		}
		return 0, nil
	}}
}

// --- validation --------------------------------------------------------------

func TestValidPackageName(t *testing.T) {
	long := "a" + strings.Repeat("b", 127)
	tests := []struct {
		in   string
		want bool
	}{
		{"bash", true},
		{"libstdc++6", true},
		{"g++-12", true},
		{"python3.11", true},
		{"libc6:armhf", true},
		{"0ad", true},
		{long, true},
		{long + "b", false},
		{"", false},
		{"a", false},
		{"-o", false},
		{"--help", false},
		{"-y", false},
		{"foo;rm", false},
		{"foo bar", false},
		{"foo\n", false},
		{"foo$(id)", false},
		{"../x", false},
		{"/etc/passwd", false},
		{"Foo", false},
		{"foo_bar", false},
		{"foo:", false},
		{"foo:ARM", false},
		{"foo:a:b", false},
		{".hidden", false},
		{"+plus", false},
	}
	for _, tt := range tests {
		if got := ValidPackageName(tt.in); got != tt.want {
			t.Errorf("ValidPackageName(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestValidSearchQuery(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"ssl", true},
		{"g++", true},
		{"python3.11", true},
		{"ab", true},
		{strings.Repeat("a", 64), true},
		{strings.Repeat("a", 65), false},
		{"a", false},
		{"", false},
		{"-o", false},
		{"--version", false},
		{"foo;rm", false},
		{"foo bar", false},
		{"a.*", false},
		{"Foo", false},
		{"../x", false},
		{"foo\n", false},
		{"libc6:armhf", false},
	}
	for _, tt := range tests {
		if got := ValidSearchQuery(tt.in); got != tt.want {
			t.Errorf("ValidSearchQuery(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

// --- parsing -----------------------------------------------------------------

func TestParseDpkgQuery(t *testing.T) {
	got := parseDpkgQuery(dpkgQueryFixture)
	var names []string
	for _, p := range got {
		names = append(names, p.name)
	}
	want := []string{"base-files", "bash", "libssl3:arm64", "raspberrypi-kernel", "old-lib", "zsh"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("names = %v, want %v", names, want)
	}
	if got[0].sizeBytes != 350*1024 || got[0].version != "12+rpt1+deb12u1" || got[0].summary != "Debian base system miscellaneous files" {
		t.Errorf("unexpected first row: %+v", got[0])
	}
	if got[3].version != "1:1.20230405-1" {
		t.Errorf("epoch version lost: %+v", got[3])
	}
	if got[5].sizeBytes != 0 {
		t.Errorf("empty installed size should be 0, got %d", got[5].sizeBytes)
	}
	if n := len(parseDpkgQuery([]string{"short", "a\tb", ""})); n != 0 {
		t.Errorf("malformed lines must be skipped, got %d rows", n)
	}
}

func TestParseInst(t *testing.T) {
	got := parseInst(upgradeSimFixture)
	want := map[string]string{
		"libssl3:arm64":      "3.0.11-1~deb12u2",
		"raspberrypi-kernel": "1:1.20230405-1+rpt1",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseInst = %v, want %v", got, want)
	}
}

func TestParseInstOddLines(t *testing.T) {
	got := parseInst([]string{
		"Inst foo [1.0] (1.1 Debian:12/stable [all]) []",
		"Inst bar [2:3.4~rc1+b1] (2:3.4~rc2-1 Debian:12/stable [amd64])",
		"  Inst indented [1] (2 x [all])",
		"Conf foo (1.1 Debian:12/stable [all])",
		"Inst",
	})
	want := map[string]string{"foo": "1.1", "bar": "2:3.4~rc2-1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseRemv(t *testing.T) {
	got := parseRemv(append(autoremoveSimFixture, "Remv libfoo:armhf [1.2-3] (x)", "Purg nope"))
	want := map[string]bool{"old-lib": true, "libfoo:armhf": true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseSearch(t *testing.T) {
	got := parseSearch([]string{
		"libssl3 - Secure Sockets Layer toolkit - shared libraries",
		"nosummary",
		"Bad Name - x",
	})
	want := []searchHit{
		{"libssl3", "Secure Sockets Layer toolkit - shared libraries"},
		{"nosummary", ""},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// --- List / classification ---------------------------------------------------

func TestList(t *testing.T) {
	r := listRunner()
	a, _ := newTestApt(r, fakeFiles{rebootRequired: true})
	res, err := a.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !res.RebootRequired {
		t.Error("RebootRequired = false")
	}
	type row struct {
		name  string
		state protocol.PackageState
		cand  string
	}
	var got []row
	for _, p := range res.Items {
		got = append(got, row{p.Name, p.State, p.CandidateVersion})
	}
	want := []row{
		{"libssl3:arm64", protocol.PackageUpdate, "3.0.11-1~deb12u2"},
		{"raspberrypi-kernel", protocol.PackageUpdate, "1:1.20230405-1+rpt1"},
		{"base-files", protocol.PackageInstalled, ""},
		{"bash", protocol.PackageInstalled, ""},
		{"zsh", protocol.PackageInstalled, ""},
		{"old-lib", protocol.PackageOrphaned, ""},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rows = %v\nwant   %v", got, want)
	}
	if res.Items[0].InstalledVersion != "3.0.11-1~deb12u1" || res.Items[0].SizeBytes != 5142*1024 {
		t.Errorf("row data: %+v", res.Items[0])
	}

	// The simulations must be read-only and unlocked, through fixed paths.
	wantCalls := []Command{
		{Path: dpkgQueryPath, Args: []string{"-W", "-f", `${binary:Package}\t${Version}\t${Installed-Size}\t${db:Status-Abbrev}\t${binary:Summary}\n`}, Env: aptEnv},
		{Path: aptGetPath, Args: []string{"-s", "-o", "Debug::NoLocking=1", "upgrade"}, Env: aptEnv},
		{Path: aptGetPath, Args: []string{"-s", "-o", "Debug::NoLocking=1", "autoremove"}, Env: aptEnv},
	}
	if !reflect.DeepEqual(r.calls, wantCalls) {
		t.Errorf("calls = %#v", r.calls)
	}
}

func TestListNoReboot(t *testing.T) {
	a, _ := newTestApt(listRunner(), fakeFiles{})
	res, err := a.List(context.Background())
	if err != nil || res.RebootRequired {
		t.Fatalf("err=%v reboot=%v", err, res.RebootRequired)
	}
}

func TestListErrors(t *testing.T) {
	r := &fakeRunner{handler: func(_ context.Context, c Command, emit func(protocol.JobStream, string)) (int, error) {
		emit(protocol.StreamStderr, "E: something broke")
		return 100, nil
	}}
	a, _ := newTestApt(r, fakeFiles{})
	_, err := a.List(context.Background())
	if err == nil || !strings.Contains(err.Error(), "E: something broke") {
		t.Fatalf("err = %v", err)
	}

	r.handler = func(context.Context, Command, func(protocol.JobStream, string)) (int, error) {
		return -1, errors.New("boom")
	}
	if _, err := a.List(context.Background()); err == nil {
		t.Fatal("expected start error")
	}
}

func TestClassifyPriorityAndSort(t *testing.T) {
	inst := []installedPkg{
		{name: "z-orphan"}, {name: "b-inst"}, {name: "a-upd"}, {name: "a-orphan"}, {name: "both"},
	}
	updates := map[string]string{"a-upd": "2", "both": "3"}
	orphans := map[string]bool{"z-orphan": true, "a-orphan": true, "both": true}
	var names []string
	for _, p := range classify(inst, updates, orphans) {
		names = append(names, p.Name)
	}
	want := []string{"a-upd", "both", "b-inst", "a-orphan", "z-orphan"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("order = %v, want %v", names, want)
	}
}

// --- Search ------------------------------------------------------------------

func TestSearch(t *testing.T) {
	r := listRunner()
	a, _ := newTestApt(r, fakeFiles{})
	res, err := a.Search(context.Background(), "ssl")
	if err != nil {
		t.Fatal(err)
	}
	type row struct {
		name  string
		state protocol.PackageState
	}
	var got []row
	for _, p := range res {
		got = append(got, row{p.Name, p.State})
	}
	want := []row{
		{"libssl-dev", protocol.PackageAvailable},
		{"libssl3", protocol.PackageUpdate},
		{"zsh", protocol.PackageInstalled},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	wantFirst := Command{Path: aptCachePath, Args: []string{"search", "--names-only", "--", "ssl"}, Env: aptEnv}
	if !reflect.DeepEqual(r.calls[0], wantFirst) {
		t.Errorf("first call = %#v", r.calls[0])
	}
}

func TestSearchEscapesAndRejects(t *testing.T) {
	r := listRunner()
	a, _ := newTestApt(r, fakeFiles{})
	if _, err := a.Search(context.Background(), "g++.x"); err != nil {
		t.Fatal(err)
	}
	if got := r.calls[0].Args[3]; got != `g\+\+\.x` {
		t.Errorf("pattern = %q", got)
	}
	r.calls = nil
	for _, q := range []string{"", "-o", "foo;rm", "a", "Foo"} {
		if _, err := a.Search(context.Background(), q); err == nil {
			t.Errorf("Search(%q) should fail", q)
		}
	}
	if len(r.calls) != 0 {
		t.Errorf("rejected queries must not run anything, got %v", r.calls)
	}
}

func TestSearchLimit(t *testing.T) {
	var hits []searchHit
	for i := 0; i < 120; i++ {
		hits = append(hits, searchHit{name: "pkg" + string(rune('a'+i/26)) + string(rune('a'+i%26))})
	}
	got := mergeSearch(hits, nil, nil)
	if len(got) != protocol.MaxSearchResults {
		t.Fatalf("len = %d", len(got))
	}
}

func TestSearchNoHitsSkipsSnapshot(t *testing.T) {
	r := &fakeRunner{}
	a, _ := newTestApt(r, fakeFiles{})
	res, err := a.Search(context.Background(), "zzzz")
	if err != nil || res == nil || len(res) != 0 {
		t.Fatalf("res=%v err=%v", res, err)
	}
	if len(r.calls) != 1 {
		t.Errorf("calls = %d, want 1", len(r.calls))
	}
}

// --- job arguments -----------------------------------------------------------

func TestJobArgs(t *testing.T) {
	base := []string{"-y", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"}
	with := func(rest ...string) []string { return append(append([]string{}, base...), rest...) }
	tests := []struct {
		name string
		job  protocol.JobStart
		want [][]string
	}{
		{"update", protocol.JobStart{Kind: protocol.JobAptUpdate}, [][]string{{"update"}}},
		{"upgrade", protocol.JobStart{Kind: protocol.JobAptUpgrade}, [][]string{with("upgrade")}},
		{"clean", protocol.JobStart{Kind: protocol.JobAptClean}, [][]string{with("autoremove"), {"clean"}}},
		{"install", protocol.JobStart{Kind: protocol.JobPkgInstall, Package: "htop"}, [][]string{with("install", "--", "htop")}},
		{"remove", protocol.JobStart{Kind: protocol.JobPkgRemove, Package: "libc6:armhf"}, [][]string{with("remove", "--", "libc6:armhf")}},
		{"pkg upgrade", protocol.JobStart{Kind: protocol.JobPkgUpgrade, Package: "bash"}, [][]string{with("install", "--only-upgrade", "--", "bash")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := jobArgs(tt.job)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %q\nwant %q", got, tt.want)
			}
		})
	}
}

func TestJobArgsRejects(t *testing.T) {
	bad := []protocol.JobStart{
		{Kind: "rm_rf"},
		{Kind: ""},
		{Kind: protocol.JobPkgInstall},
		{Kind: protocol.JobPkgInstall, Package: "-o"},
		{Kind: protocol.JobPkgRemove, Package: "foo;rm"},
		{Kind: protocol.JobPkgUpgrade, Package: "../x"},
		{Kind: protocol.JobPkgInstall, Package: "Foo"},
	}
	for _, j := range bad {
		if _, err := jobArgs(j); err == nil {
			t.Errorf("jobArgs(%+v) should fail", j)
		}
	}
}

// --- Run ---------------------------------------------------------------------

func collect() (*[]protocol.JobOutput, func(protocol.JobOutput)) {
	var lines []protocol.JobOutput
	return &lines, func(o protocol.JobOutput) { lines = append(lines, o) }
}

func TestRunSuccess(t *testing.T) {
	r := &fakeRunner{handler: func(_ context.Context, c Command, emit func(protocol.JobStream, string)) (int, error) {
		emit(protocol.StreamStdout, "Reading package lists...")
		emit(protocol.StreamStderr, "W: something")
		return 0, nil
	}}
	a, _ := newTestApt(r, fakeFiles{rebootRequired: true})
	lines, out := collect()
	done := a.Run(context.Background(), protocol.JobStart{JobID: "j1", Kind: protocol.JobAptClean}, out)
	want := protocol.JobDone{JobID: "j1", OK: true, RebootRequired: true}
	if done != want {
		t.Fatalf("done = %+v", done)
	}
	if len(r.calls) != 2 || r.calls[0].Path != aptGetPath || r.calls[1].Args[0] != "clean" {
		t.Fatalf("calls = %#v", r.calls)
	}
	if !reflect.DeepEqual(r.calls[0].Env, aptEnv) {
		t.Errorf("env = %v", r.calls[0].Env)
	}
	if len(*lines) != 4 || (*lines)[1] != (protocol.JobOutput{JobID: "j1", Stream: protocol.StreamStderr, Line: "W: something"}) {
		t.Errorf("lines = %+v", *lines)
	}
}

func TestRunExitCodePropagates(t *testing.T) {
	r := &fakeRunner{handler: func(context.Context, Command, func(protocol.JobStream, string)) (int, error) { return 100, nil }}
	a, _ := newTestApt(r, fakeFiles{})
	_, out := collect()
	done := a.Run(context.Background(), protocol.JobStart{JobID: "j2", Kind: protocol.JobAptClean}, out)
	if done.OK || done.ExitCode != 100 || done.JobID != "j2" || !strings.Contains(done.Error, "autoremove") {
		t.Fatalf("done = %+v", done)
	}
	if len(r.calls) != 1 {
		t.Errorf("clean must not run after failed autoremove, calls = %d", len(r.calls))
	}
}

func TestRunRejectsInvalid(t *testing.T) {
	r := &fakeRunner{}
	a, _ := newTestApt(r, fakeFiles{})
	_, out := collect()
	done := a.Run(context.Background(), protocol.JobStart{JobID: "j3", Kind: protocol.JobPkgInstall, Package: "-o"}, out)
	if done.OK || done.JobID != "j3" || done.Error == "" || done.ExitCode != -1 {
		t.Fatalf("done = %+v", done)
	}
	if len(r.calls) != 0 {
		t.Fatal("must not run anything")
	}
}

func TestRunStartError(t *testing.T) {
	r := &fakeRunner{handler: func(context.Context, Command, func(protocol.JobStream, string)) (int, error) {
		return -1, errors.New("fork/exec /usr/bin/apt-get: no such file or directory")
	}}
	a, _ := newTestApt(r, fakeFiles{})
	_, out := collect()
	done := a.Run(context.Background(), protocol.JobStart{JobID: "j4", Kind: protocol.JobAptUpdate}, out)
	if done.OK || !strings.Contains(done.Error, "no such file") {
		t.Fatalf("done = %+v", done)
	}
}

func TestRunCancelDuringCommand(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	r := &fakeRunner{handler: func(ctx context.Context, _ Command, emit func(protocol.JobStream, string)) (int, error) {
		emit(protocol.StreamStdout, "Get:1 ...")
		cancel()
		return -1, ctx.Err()
	}}
	a, _ := newTestApt(r, fakeFiles{rebootRequired: true})
	_, out := collect()
	done := a.Run(ctx, protocol.JobStart{JobID: "j5", Kind: protocol.JobAptUpgrade}, out)
	if done.OK || done.Error != "canceled" || done.JobID != "j5" || !done.RebootRequired {
		t.Fatalf("done = %+v", done)
	}
}

func TestRunCancelWhileWaitingForLock(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	clk := &fakeClock{now: time.Unix(0, 0)}
	locks := &fakeLocks{clock: clk, path: aptLockPaths[0], until: clk.now.Add(time.Hour)}
	r := &fakeRunner{}
	a := newApt(r, locks, fakeFiles{}, clk)
	calls := 0
	_, out := collect()
	wrapped := func(o protocol.JobOutput) {
		calls++
		cancel()
		out(o)
	}
	done := a.Run(ctx, protocol.JobStart{JobID: "j6", Kind: protocol.JobAptUpdate}, wrapped)
	if done.OK || done.Error != "canceled" {
		t.Fatalf("done = %+v", done)
	}
	if len(r.calls) != 0 || calls == 0 {
		t.Fatalf("runner calls = %d, status lines = %d", len(r.calls), calls)
	}
}

func TestRunWaitsForLock(t *testing.T) {
	clk := &fakeClock{now: time.Unix(0, 0)}
	locks := &fakeLocks{clock: clk, path: "/var/lib/dpkg/lock", until: clk.now.Add(40 * time.Second)}
	r := &fakeRunner{}
	a := newApt(r, locks, fakeFiles{}, clk)
	lines, out := collect()
	done := a.Run(context.Background(), protocol.JobStart{JobID: "j7", Kind: protocol.JobAptUpdate}, out)
	if !done.OK {
		t.Fatalf("done = %+v", done)
	}
	var got []string
	for _, l := range *lines {
		if l.Stream != protocol.StreamStatus || l.JobID != "j7" {
			t.Errorf("unexpected output %+v", l)
		}
		got = append(got, l.Line)
	}
	want := []string{
		"Waiting for dpkg lock … 0s",
		"Waiting for dpkg lock … 15s",
		"Waiting for dpkg lock … 30s",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("status lines = %q, want %q", got, want)
	}
	if len(r.calls) != 1 {
		t.Fatalf("calls = %d", len(r.calls))
	}
}

func TestRunLockTimeout(t *testing.T) {
	clk := &fakeClock{now: time.Unix(0, 0)}
	locks := &fakeLocks{clock: clk, path: "/var/lib/dpkg/lock-frontend", until: clk.now.Add(24 * time.Hour)}
	r := &fakeRunner{}
	a := newApt(r, locks, fakeFiles{}, clk)
	lines, out := collect()
	done := a.Run(context.Background(), protocol.JobStart{JobID: "j8", Kind: protocol.JobAptUpgrade}, out)
	if done.OK || done.ExitCode != -1 || !strings.Contains(done.Error, "10 minutes") || !strings.Contains(done.Error, "lock-frontend") {
		t.Fatalf("done = %+v", done)
	}
	if len(r.calls) != 0 {
		t.Fatal("must not run after lock timeout")
	}
	if clk.now.Sub(time.Unix(0, 0)) != lockWaitTimeout {
		t.Errorf("waited %v", clk.now.Sub(time.Unix(0, 0)))
	}
	// 0s, 15s, ... 585s = 40 reports
	if len(*lines) != 40 {
		t.Errorf("status lines = %d, want 40", len(*lines))
	}
}

func TestRunLockProbeError(t *testing.T) {
	clk := &fakeClock{now: time.Unix(0, 0)}
	locks := &fakeLocks{clock: clk, err: errors.New("permission denied")}
	a := newApt(&fakeRunner{}, locks, fakeFiles{}, clk)
	_, out := collect()
	done := a.Run(context.Background(), protocol.JobStart{JobID: "j9", Kind: protocol.JobAptUpdate}, out)
	if done.OK || !strings.Contains(done.Error, "permission denied") {
		t.Fatalf("done = %+v", done)
	}
}

// --- line splitting ----------------------------------------------------------

func scanAll(t *testing.T, in string, max int) []string {
	t.Helper()
	var got []string
	if err := scanLines(strings.NewReader(in), max, func(l string) { got = append(got, l) }); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestScanLines(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"lf", "a\nb\n", []string{"a", "b"}},
		{"no trailing newline", "a\nb", []string{"a", "b"}},
		{"crlf", "a\r\nb\r\n", []string{"a", "b"}},
		{"cr progress", "10%\r50%\r100%\n", []string{"10%", "50%", "100%"}},
		{"blank line kept", "a\n\nb\n", []string{"a", "", "b"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := scanAll(t, tt.in, maxLineBytes); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestScanLinesTruncation(t *testing.T) {
	exact := strings.Repeat("x", maxLineBytes)
	long := strings.Repeat("y", maxLineBytes*3)
	got := scanAll(t, exact+"\n"+long+"\nshort\n", maxLineBytes)
	if len(got) != 3 {
		t.Fatalf("lines = %d", len(got))
	}
	if got[0] != exact {
		t.Error("line of exactly max bytes must not be truncated")
	}
	if len(got[1]) != maxLineBytes || !strings.HasSuffix(got[1], truncatedSuffix) {
		t.Errorf("long line: len=%d suffix=%q", len(got[1]), got[1][len(got[1])-12:])
	}
	if got[2] != "short" {
		t.Errorf("line after truncation = %q", got[2])
	}
}

func TestScanLinesTruncationKeepsUTF8(t *testing.T) {
	in := strings.Repeat("ä", 100) // 2 bytes per rune
	got := scanAll(t, in+"\n", 51)
	if len(got) != 1 || len(got[0]) > 51 {
		t.Fatalf("got %q", got)
	}
	if !strings.HasSuffix(got[0], truncatedSuffix) || strings.ContainsRune(got[0], '�') {
		t.Errorf("bad cut: %q", got[0])
	}
}

func TestScanLinesInvalidUTF8(t *testing.T) {
	got := scanAll(t, "a\xffb\n", maxLineBytes)
	if len(got) != 1 || got[0] != "a�b" {
		t.Fatalf("got %q", got)
	}
}
