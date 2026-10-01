package views

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/protocol"
)

func testPackages() *protocol.Packages {
	return &protocol.Packages{Items: []protocol.Package{
		{Name: "curl", Summary: "URL client", InstalledVersion: "7.88", SizeBytes: 315_000, State: protocol.PackageInstalled},
		{Name: "openssh-server", Summary: "ssh", InstalledVersion: "9.2u3", CandidateVersion: "9.2u4", SizeBytes: 1_400_000, State: protocol.PackageUpdate},
		{Name: "linux-image-rpi-v8", Summary: "kernel", InstalledVersion: "6.6.51", CandidateVersion: "6.6.62", SizeBytes: 78_000_000, State: protocol.PackageUpdate},
		{Name: "old-kernel", Summary: "unused", InstalledVersion: "6.1", SizeBytes: 64_000_000, State: protocol.PackageOrphaned},
		{Name: "htop", Summary: "viewer", CandidateVersion: "3.2", SizeBytes: 432_000, State: protocol.PackageAvailable},
	}}
}

func baseInput() PackagesInput {
	return PackagesInput{
		HostLabel: "pi5", HostPath: "/hosts/pi5",
		Online: true, Capable: true, Data: testPackages(), Filter: "all", Count: "1/3",
	}
}

func tileNames(m PackagesModel) []string {
	var n []string
	for _, t := range m.Tiles {
		n = append(n, t.Name)
	}
	return n
}

func TestNormalizePackageFilter(t *testing.T) {
	for in, want := range map[string]string{
		"": "all", "all": "all", "updates": "updates", "installed": "installed",
		"available": "available", "orphaned": "orphaned", "bogus": "all", "UPDATES": "all",
	} {
		if got := NormalizePackageFilter(in); got != want {
			t.Errorf("NormalizePackageFilter(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLookupPackageAction(t *testing.T) {
	tests := []struct {
		name     string
		ok       bool
		kind     protocol.JobKind
		needsPkg bool
		needsAsk bool
	}{
		{"apt-update", true, protocol.JobAptUpdate, false, false},
		{"apt-upgrade", true, protocol.JobAptUpgrade, false, true},
		{"apt-clean", true, protocol.JobAptClean, false, true},
		{"pkg-install", true, protocol.JobPkgInstall, true, false},
		{"pkg-remove", true, protocol.JobPkgRemove, true, true},
		{"pkg-upgrade", true, protocol.JobPkgUpgrade, true, false},
		{"reboot", false, "", false, false},
		{"", false, "", false, false},
		{"apt_update", false, "", false, false},
	}
	for _, tc := range tests {
		a, ok := LookupPackageAction(tc.name)
		if ok != tc.ok || a.Kind != tc.kind || a.NeedsPkg != tc.needsPkg || a.NeedsAsk != tc.needsAsk {
			t.Errorf("%q: got %+v ok=%v", tc.name, a, ok)
		}
	}
}

func TestBuildPackagesFilters(t *testing.T) {
	tests := []struct {
		name   string
		filter string
		query  string
		found  []protocol.Package
		want   []string
	}{
		{"all: updates, orphaned, installed, available", "all", "", nil, []string{"openssh-server", "linux-image-rpi-v8", "old-kernel", "curl", "htop"}},
		{"updates", "updates", "", nil, []string{"openssh-server", "linux-image-rpi-v8"}},
		{"installed includes updates", "installed", "", nil, []string{"openssh-server", "linux-image-rpi-v8", "curl"}},
		{"available", "available", "", nil, []string{"htop"}},
		{"orphaned", "orphaned", "", nil, []string{"old-kernel"}},
		{"unknown filter is all", "nope", "", nil, []string{"openssh-server", "linux-image-rpi-v8", "old-kernel", "curl", "htop"}},
		{"query is case-insensitive", "all", "  CURL ", nil, []string{"curl"}},
		{"query with filter", "updates", "linux", nil, []string{"linux-image-rpi-v8"}},
		{"search hits are appended once", "all", "tm", []protocol.Package{
			{Name: "tmux", CandidateVersion: "3.3", State: protocol.PackageAvailable},
			{Name: "tmux", CandidateVersion: "3.3", State: protocol.PackageAvailable},
		}, []string{"tmux"}},
		{"search hit known locally is not duplicated", "all", "curl", []protocol.Package{
			{Name: "curl", State: protocol.PackageAvailable},
		}, []string{"curl"}},
		{"search hits obey the filter", "updates", "tm", []protocol.Package{
			{Name: "tmux", State: protocol.PackageAvailable},
		}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := baseInput()
			in.Filter, in.Query, in.Found = tc.filter, tc.query, tc.found
			got := tileNames(BuildPackages(in))
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("tiles = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestBuildPackagesTabs(t *testing.T) {
	in := baseInput()
	in.Filter, in.Query = "updates", "a b"
	m := BuildPackages(in)
	var got []string
	for _, f := range m.Filters {
		got = append(got, f.Label+"="+strconv.Itoa(f.Count))
	}
	if want := "All=5,Updates=2,Installed=3,Available=1,Orphaned=1"; strings.Join(got, ",") != want {
		t.Errorf("tabs = %v, want %s", got, want)
	}
	for _, f := range m.Filters {
		if f.Active != (f.Label == "Updates") {
			t.Errorf("tab %s active = %v", f.Label, f.Active)
		}
	}
	if href := m.Filters[1].Href; href != "/hosts/pi5/packages?filter=updates&q=a+b" {
		t.Errorf("href = %q", href)
	}
	if a := string(m.Filters[1].Attrs); !strings.Contains(a, `hx-get="/hosts/pi5/packages?filter=updates"`) || strings.Contains(a, "q=") {
		t.Errorf("attrs must not carry the search term (hx-include adds it): %s", a)
	}
	if m.Query != "a b" || m.Count != "1/3" {
		t.Errorf("model = %+v", m)
	}
}

func TestBuildPackagesTiles(t *testing.T) {
	m := BuildPackages(baseInput())
	byName := map[string]PackageTile{}
	for _, tl := range m.Tiles {
		byName[tl.Name] = tl
	}
	tests := []struct {
		name                                    string
		tone, label, meta, badge, action, class string
		wantAttrs                               []string
	}{
		{"openssh-server", "lime", "Update", "9.2u3 → 9.2u4", "1.4 MB", "Update", "btn-tool is-hot",
			[]string{`hx-post="/hosts/pi5/packages/pkg-upgrade"`, `hx-vals="{&#34;package&#34;:&#34;openssh-server&#34;}"`, `hx-target="#modal-root"`}},
		{"curl", "grey", "Installed", "7.88", "315 KB", "Remove", "btn-tool",
			[]string{`hx-get="/hosts/pi5/packages/confirm/pkg-remove"`}},
		{"old-kernel", "pink", "Orphaned", "6.1", "64 MB", "Remove", "btn-tool",
			[]string{`hx-get="/hosts/pi5/packages/confirm/pkg-remove"`}},
		{"htop", "blue", "Available", "3.2", "432 KB", "Install", "btn-tool",
			[]string{`hx-post="/hosts/pi5/packages/pkg-install"`}},
	}
	for _, tc := range tests {
		tl, ok := byName[tc.name]
		if !ok {
			t.Fatalf("no tile for %s", tc.name)
		}
		if tl.Tone != tc.tone || tl.Label != tc.label || tl.Meta != tc.meta || tl.Badge != tc.badge ||
			tl.ActionLabel != tc.action || tl.ActionClass != tc.class {
			t.Errorf("%s: got %+v", tc.name, tl)
		}
		for _, w := range tc.wantAttrs {
			if !strings.Contains(string(tl.ActionAttrs), w) {
				t.Errorf("%s: attrs %q lack %q", tc.name, tl.ActionAttrs, w)
			}
		}
		if strings.Contains(string(tl.ActionAttrs), "disabled") {
			t.Errorf("%s: enabled host must not disable the button", tc.name)
		}
	}
}

func TestBuildPackagesAttrEscaping(t *testing.T) {
	in := baseInput()
	in.Data = &protocol.Packages{Items: []protocol.Package{{Name: `x"><script>`, State: protocol.PackageInstalled}}}
	a := string(BuildPackages(in).Tiles[0].ActionAttrs)
	if strings.Contains(a, "<script>") || strings.Contains(a, `x"><`) {
		t.Errorf("unescaped package name in attrs: %s", a)
	}
}

func TestBuildPackagesDisabledAndNotices(t *testing.T) {
	tests := []struct {
		name       string
		mod        func(*PackagesInput)
		disabled   bool
		wantNotice string
	}{
		{"online", func(*PackagesInput) {}, false, ""},
		{"offline", func(in *PackagesInput) { in.Online = false }, true, "is offline"},
		{"capability off", func(in *PackagesInput) { in.Capable = false }, true, "switched off"},
		{"reboot", func(in *PackagesInput) { in.Reboot = true }, false, "A reboot is required on pi5"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := baseInput()
			tc.mod(&in)
			m := BuildPackages(in)
			if m.Disabled != tc.disabled {
				t.Errorf("Disabled = %v", m.Disabled)
			}
			for _, tl := range m.Tiles {
				if strings.Contains(string(tl.ActionAttrs), "disabled") != tc.disabled {
					t.Errorf("tile %s attrs %q", tl.Name, tl.ActionAttrs)
				}
			}
			for _, c := range []PackageCard{m.Sync, m.Clean} {
				if strings.Contains(string(c.ButtonAttrs), "disabled") != tc.disabled {
					t.Errorf("card %s attrs %q", c.Title, c.ButtonAttrs)
				}
			}
			joined := strings.Join(m.Notices, "|")
			if tc.wantNotice == "" && joined != "" || !strings.Contains(joined, tc.wantNotice) {
				t.Errorf("notices = %q, want %q", joined, tc.wantNotice)
			}
		})
	}
}

func TestBuildPackagesTicker(t *testing.T) {
	tests := []struct {
		name string
		data *protocol.Packages
		want string
	}{
		{"none", nil, "No package data yet"},
		{"up to date", &protocol.Packages{Items: []protocol.Package{{Name: "a", State: protocol.PackageInstalled}}}, "System up to date"},
		{"one", &protocol.Packages{Items: []protocol.Package{{Name: "a", State: protocol.PackageUpdate}}}, "1 update available"},
		{"two", testPackages(), "2 updates available"},
	}
	for _, tc := range tests {
		in := baseInput()
		in.Data = tc.data
		if got := BuildPackages(in).Ticker; got != tc.want {
			t.Errorf("%s: ticker %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestBuildPackagesEmptyMessage(t *testing.T) {
	tests := []struct {
		name        string
		data        *protocol.Packages
		filter, q   string
		want        string
		wantNoTiles bool
	}{
		{"no data", nil, "all", "", "No package data yet.", true},
		{"no match", testPackages(), "all", "zzz", "No package matches “zzz”.", true},
		{"no updates", &protocol.Packages{Items: []protocol.Package{{Name: "a", State: protocol.PackageInstalled}}}, "updates", "", "All packages are up to date.", true},
		{"no orphans", &protocol.Packages{Items: []protocol.Package{{Name: "a", State: protocol.PackageInstalled}}}, "orphaned", "", "No orphaned packages.", true},
		{"has tiles", testPackages(), "all", "", "", false},
	}
	for _, tc := range tests {
		in := baseInput()
		in.Data, in.Filter, in.Query = tc.data, tc.filter, tc.q
		m := BuildPackages(in)
		if m.Empty != tc.want || (len(m.Tiles) == 0) != tc.wantNoTiles {
			t.Errorf("%s: empty %q tiles %d", tc.name, m.Empty, len(m.Tiles))
		}
	}
}

func TestUpgradeText(t *testing.T) {
	up := func(names ...string) []protocol.Package {
		var out []protocol.Package
		for _, n := range names {
			out = append(out, protocol.Package{Name: n, State: protocol.PackageUpdate})
		}
		return out
	}
	tests := []struct {
		names []string
		want  string
	}{
		{[]string{"openssh-server", "linux-image-rpi-v8", "ffmpeg"}, "3 updates ready, including kernel and OpenSSH."},
		{[]string{"ffmpeg"}, "1 update ready, including ffmpeg."},
		{[]string{"a", "b", "c"}, "3 updates ready, including a and b."},
		{[]string{"linux-image-a", "linux-image-b", "x"}, "3 updates ready, including kernel and x."},
		{[]string{"openssh-server"}, "1 update ready, including OpenSSH."},
	}
	for _, tc := range tests {
		if got := upgradeText(up(tc.names...)); got != tc.want {
			t.Errorf("%v: %q, want %q", tc.names, got, tc.want)
		}
	}
}

func TestCards(t *testing.T) {
	m := BuildPackages(baseInput())
	if m.Upgrade.ObjValue != "0/2" || m.Upgrade.BoxText != "2" || m.Upgrade.Variant != "hot" || m.Upgrade.TagText != "Recommended" {
		t.Errorf("upgrade card: %+v", m.Upgrade)
	}
	if !strings.Contains(string(m.Upgrade.ButtonAttrs), `hx-get="/hosts/pi5/packages/confirm/apt-upgrade"`) {
		t.Errorf("upgrade attrs: %s", m.Upgrade.ButtonAttrs)
	}
	if m.Clean.ObjValue != "0/1" || m.Clean.BoxText != "64" || m.Clean.BoxUnit != "MB" {
		t.Errorf("clean card: %+v", m.Clean)
	}
	if !strings.Contains(string(m.Sync.ButtonAttrs), `hx-post="/hosts/pi5/packages/apt-update"`) {
		t.Errorf("sync attrs: %s", m.Sync.ButtonAttrs)
	}

	// Nothing to do: the upgrade button is inert, the orphan box shows zero.
	in := baseInput()
	in.Data = &protocol.Packages{Items: []protocol.Package{{Name: "a", State: protocol.PackageInstalled}}}
	m = BuildPackages(in)
	if !strings.Contains(string(m.Upgrade.ButtonAttrs), "disabled") || m.Upgrade.TagText != "Up to date" || m.Upgrade.Pct != 100 {
		t.Errorf("idle upgrade card: %+v", m.Upgrade)
	}
	if m.Clean.BoxText != "0" || m.Clean.BoxUnit != "MB" || m.Clean.Pct != 100 {
		t.Errorf("idle clean card: %+v", m.Clean)
	}
}

func TestSourcesRead(t *testing.T) {
	lines := func(ls ...string) []grid.JobLine {
		var out []grid.JobLine
		for _, l := range ls {
			out = append(out, grid.JobLine{Stream: protocol.StreamStdout, Line: l})
		}
		return out
	}
	done := grid.Job{Kind: protocol.JobAptUpdate, State: grid.JobDone, OK: true,
		Output: lines("Hit:1 http://a InRelease", "Get:2 http://b InRelease [1 kB]", "Ign:3 http://c", "Fetched 1 kB", "Reading package lists... Done")}
	tests := []struct {
		name  string
		jobs  []grid.Job
		n     int
		state string
		value string
	}{
		{"no job", nil, 0, "", "not synced"},
		{"other job", []grid.Job{{Kind: protocol.JobAptUpgrade, State: grid.JobDone, OK: true}}, 0, "", "not synced"},
		{"done", []grid.Job{done}, 3, "done", "3/3"},
		{"newest wins", []grid.Job{{Kind: protocol.JobAptUpdate, State: grid.JobRunning}, done}, 0, "running", "reading…"},
		{"failed", []grid.Job{{Kind: protocol.JobAptUpdate, State: grid.JobFailed}, done}, 0, "failed", "failed"},
		{"canceled is skipped", []grid.Job{{Kind: protocol.JobAptUpdate, State: grid.JobCanceled}, done}, 3, "done", "3/3"},
	}
	for _, tc := range tests {
		n, st := sourcesRead(tc.jobs)
		if n != tc.n || st != tc.state {
			t.Errorf("%s: sourcesRead = %d %q", tc.name, n, st)
		}
		in := baseInput()
		in.Jobs = tc.jobs
		if got := BuildPackages(in).Sync.ObjValue; got != tc.value {
			t.Errorf("%s: card value %q, want %q", tc.name, got, tc.value)
		}
	}
}

func TestFormatSI(t *testing.T) {
	for in, want := range map[int64]string{
		0: "0 B", 999: "999 B", 1_000: "1 KB", 22_000: "22 KB", 315_000: "315 KB", 1_400_000: "1.4 MB",
		9_600_000: "9.6 MB", 31_000_000: "31 MB", 78_000_000: "78 MB", 1_500_000_000: "1.5 GB",
	} {
		if got := formatSI(in); got != want {
			t.Errorf("formatSI(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestNewPackagesConfirm(t *testing.T) {
	tests := []struct {
		action   string
		pkg      string
		updates  int
		orphans  int
		ok       bool
		variant  string
		title    string
		contains string
	}{
		{"pkg-remove", "curl", 0, 0, true, "bad", "Remove package", "Remove curl from pi5"},
		{"apt-upgrade", "", 3, 0, true, "hot", "Upgrade all", "Install 3 pending updates on pi5"},
		{"apt-upgrade", "", 1, 0, true, "hot", "Upgrade all", "Install 1 pending update on pi5"},
		{"apt-clean", "", 0, 2, true, "bad", "Clean up", "Remove 2 orphaned packages"},
		{"apt-clean", "", 0, 0, true, "bad", "Clean up", "Remove orphaned packages and clear"},
		{"apt-update", "", 0, 0, false, "", "", ""},
		{"pkg-install", "htop", 0, 0, false, "", "", ""},
	}
	for _, tc := range tests {
		a, _ := LookupPackageAction(tc.action)
		c, ok := NewPackagesConfirm(a, "pi5", "/hosts/pi5", tc.pkg, tc.updates, tc.orphans)
		if ok != tc.ok {
			t.Errorf("%s: ok = %v", tc.action, ok)
			continue
		}
		if !ok {
			continue
		}
		if c.Variant != tc.variant || c.Title != tc.title || !strings.Contains(c.Text, tc.contains) ||
			c.PostURL != "/hosts/pi5/packages/"+tc.action || c.Package != tc.pkg {
			t.Errorf("%s: %+v", tc.action, c)
		}
	}
}

func TestJobLineClass(t *testing.T) {
	tests := []struct {
		stream protocol.JobStream
		line   string
		want   string
	}{
		{protocol.StreamStdout, "Reading package lists... Done", ""},
		{protocol.StreamStatus, "waiting for dpkg lock (12s)", "is-wait"},
		{protocol.StreamStdout, "Waiting for cache lock", "is-wait"},
		{protocol.StreamStderr, "W: A reboot is required", "is-wait"},
		{protocol.StreamStderr, "E: Unable to locate package x", "is-bad"},
		{protocol.StreamStdout, "Err:1 http://x InRelease", "is-bad"},
		{protocol.StreamStderr, "debconf: delaying package configuration", ""},
		{protocol.StreamStdout, "Error while reading", "is-bad"},
	}
	for _, tc := range tests {
		if got := JobLineClass(grid.JobLine{Stream: tc.stream, Line: tc.line}); got != tc.want {
			t.Errorf("%q: %q, want %q", tc.line, got, tc.want)
		}
	}
}

func TestNewJobView(t *testing.T) {
	tests := []struct {
		name      string
		job       grid.Job
		state     string
		label     string
		active    bool
		busy      bool
		pct       int
		bad       bool
		lastLine  string
		lastClass string
		cancel    bool
	}{
		{"queued", grid.Job{ID: "j1", Kind: protocol.JobAptUpdate, State: grid.JobQueued}, "queued", "Queued", true, false, 0, false, "", "", true},
		{"running", grid.Job{ID: "j1", Kind: protocol.JobAptUpgrade, State: grid.JobRunning,
			Output: []grid.JobLine{{Stream: protocol.StreamStatus, Line: "Waiting for dpkg lock"}}}, "running", "Running", true, true, 0, false, "Waiting for dpkg lock", "is-wait", true},
		{"done", grid.Job{ID: "j1", Kind: protocol.JobAptClean, State: grid.JobDone, OK: true, RebootRequired: true}, "done", "Done", false, false, 100, false, "", "", false},
		{"done but not ok", grid.Job{ID: "j1", Kind: protocol.JobAptClean, State: grid.JobDone, ExitCode: 100}, "failed", "Failed", false, false, 100, true, "Failed: exit code 100", "is-bad", false},
		{"failed", grid.Job{ID: "j1", Kind: protocol.JobPkgInstall, Package: "htop", State: grid.JobFailed, Error: "apt-get install exited with code 100"}, "failed", "Failed", false, false, 100, true, "Failed: apt-get install exited with code 100", "is-bad", false},
		{"canceled", grid.Job{ID: "j1", Kind: protocol.JobAptUpdate, State: grid.JobCanceled}, "canceled", "Canceled", false, false, 0, false, "Canceled.", "is-wait", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := NewJobView("pi5", "/hosts/pi5", tc.job)
			if v.StateKey != tc.state || v.StateLabel != tc.label || v.Active != tc.active || v.Busy != tc.busy ||
				v.Pct != tc.pct || v.Bad != tc.bad || v.Finished == tc.active {
				t.Errorf("view = %+v", v)
			}
			if tc.lastLine != "" {
				last := v.Lines[len(v.Lines)-1]
				if last.Text != tc.lastLine || last.Class != tc.lastClass {
					t.Errorf("last line = %+v", last)
				}
			}
			if hasCancel := v.CancelAttrs != ""; hasCancel != tc.cancel {
				t.Errorf("cancel attrs = %q", v.CancelAttrs)
			}
			if tc.cancel && !strings.Contains(string(v.CancelAttrs), `hx-post="/hosts/pi5/jobs/j1/cancel"`) {
				t.Errorf("cancel attrs = %q", v.CancelAttrs)
			}
			if v.OOB || !v.AsOOB().OOB {
				t.Error("AsOOB must return a flagged copy")
			}
		})
	}
	if v := NewJobView("pi5", "/hosts/pi5", grid.Job{ID: "j", Kind: protocol.JobAptUpgrade, State: grid.JobDone, OK: true, RebootRequired: true}); !v.RebootRequired {
		t.Error("reboot flag lost")
	}
	if v := NewJobView("pi5", "/hosts/pi5", grid.Job{ID: "j", Kind: protocol.JobAptUpgrade, State: grid.JobRunning, RebootRequired: true}); v.RebootRequired {
		t.Error("reboot flag shown before the job finished")
	}
}

func TestJobCommandAndShort(t *testing.T) {
	tests := []struct {
		kind       protocol.JobKind
		pkg        string
		cmd, short string
	}{
		{protocol.JobAptUpdate, "", "apt update", "apt update"},
		{protocol.JobAptUpgrade, "", "apt upgrade -y", "apt upgrade"},
		{protocol.JobAptClean, "", "apt autoremove -y && apt clean", "apt clean"},
		{protocol.JobPkgInstall, "htop", "apt install -y htop", "install htop"},
		{protocol.JobPkgRemove, "htop", "apt remove -y htop", "remove htop"},
		{protocol.JobPkgUpgrade, "htop", "apt install --only-upgrade -y htop", "upgrade htop"},
	}
	for _, tc := range tests {
		if got := JobCommand(tc.kind, tc.pkg); got != tc.cmd {
			t.Errorf("JobCommand(%s) = %q", tc.kind, got)
		}
		if got := JobShort(tc.kind, tc.pkg); got != tc.short {
			t.Errorf("JobShort(%s) = %q", tc.kind, got)
		}
	}
}

func TestJobChipFor(t *testing.T) {
	job := func(id string, st grid.JobState, k protocol.JobKind) grid.Job {
		return grid.Job{ID: id, State: st, Kind: k}
	}
	tests := []struct {
		name      string
		jobs      []grid.Job // newest first
		wantNil   bool
		wantLabel string
		wantHref  string
	}{
		{"none", nil, true, "", ""},
		{"only finished", []grid.Job{job("a", grid.JobDone, protocol.JobAptUpdate)}, true, "", ""},
		{"running", []grid.Job{job("a", grid.JobRunning, protocol.JobAptUpgrade)}, false, "JOB · apt upgrade · running", "/hosts/pi5/jobs/a"},
		{"running beats newer queued", []grid.Job{job("b", grid.JobQueued, protocol.JobAptClean), job("a", grid.JobRunning, protocol.JobAptUpgrade)}, false, "JOB · apt upgrade · running", "/hosts/pi5/jobs/a"},
		{"oldest queued when nothing runs", []grid.Job{job("c", grid.JobQueued, protocol.JobAptClean), job("b", grid.JobQueued, protocol.JobAptUpdate)}, false, "JOB · apt update · queued", "/hosts/pi5/jobs/b"},
	}
	for _, tc := range tests {
		got := JobChipFor("/hosts/pi5", tc.jobs)
		if (got == nil) != tc.wantNil {
			t.Errorf("%s: chip = %+v", tc.name, got)
			continue
		}
		if got != nil && (got.Label != tc.wantLabel || got.Href != tc.wantHref) {
			t.Errorf("%s: chip = %+v", tc.name, got)
		}
	}
}

func TestSafeDOMID(t *testing.T) {
	for in, want := range map[string]bool{
		"": false, "job-000001": true, "a1b2c3": true, "a_b": true, "a b": false, "a\"b": false, "a#b": false,
		"a.b": false, strings.Repeat("a", 64): true, strings.Repeat("a", 65): false,
	} {
		if got := SafeDOMID(in); got != want {
			t.Errorf("SafeDOMID(%q) = %v", in, got)
		}
	}
}

func manyPackages(n int) []protocol.Package {
	out := make([]protocol.Package, 0, n)
	for i := range n {
		out = append(out, protocol.Package{Name: fmt.Sprintf("pkg%03d", n-i), InstalledVersion: "1", State: protocol.PackageInstalled})
	}
	return out
}

func TestSortPackages(t *testing.T) {
	ps := []protocol.Package{
		{Name: "zlib", State: protocol.PackageInstalled},
		{Name: "Bash", State: protocol.PackageInstalled},
		{Name: "tmux", State: protocol.PackageAvailable},
		{Name: "xz", State: protocol.PackageOrphaned},
		{Name: "curl", State: protocol.PackageInstalled},
		{Name: "openssh", State: protocol.PackageUpdate},
		{Name: "apt", State: protocol.PackageUpdate},
		{Name: "acl", State: protocol.PackageOrphaned},
	}
	sortPackages(ps)
	var got []string
	for _, p := range ps {
		got = append(got, p.Name)
	}
	// updates keep the agent's order, everything else is alphabetical (case-insensitive)
	if want := "openssh,apt,acl,xz,Bash,curl,zlib,tmux"; strings.Join(got, ",") != want {
		t.Errorf("order = %s, want %s", strings.Join(got, ","), want)
	}
}

func TestBuildPackagesPaging(t *testing.T) {
	const total = 2*PackagesPageSize + 7
	tests := []struct {
		name       string
		offset     int
		query      string
		wantTiles  int
		wantFirst  string
		wantMore   string // "" = no sentinel
		wantRemain int
		wantEmpty  bool
	}{
		{"first page", 0, "", PackagesPageSize, "pkg001", "/hosts/pi5/packages?filter=all&offset=60", total - PackagesPageSize, false},
		{"second page", PackagesPageSize, "", PackagesPageSize, "pkg061", "/hosts/pi5/packages?filter=all&offset=120", 7, false},
		{"last page has no sentinel", 2 * PackagesPageSize, "", 7, "pkg121", "", 0, false},
		{"offset past the end", 500, "", 0, "", "", 0, false},
		{"negative offset is the first page", -5, "", PackagesPageSize, "pkg001", "/hosts/pi5/packages?filter=all&offset=60", total - PackagesPageSize, false},
		{"search covers all packages, not the page", 0, "g0", PackagesPageSize, "pkg001", "/hosts/pi5/packages?filter=all&q=g0&offset=60", 0, false},
		{"search without match", 0, "nope", 0, "", "", 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := baseInput()
			in.Data = &protocol.Packages{Items: manyPackages(total)}
			in.Offset, in.Query = tc.offset, tc.query
			m := BuildPackages(in)
			if len(m.Tiles) != tc.wantTiles {
				t.Fatalf("%d tiles, want %d", len(m.Tiles), tc.wantTiles)
			}
			if tc.wantFirst != "" && m.Tiles[0].Name != tc.wantFirst {
				t.Errorf("first tile %q, want %q", m.Tiles[0].Name, tc.wantFirst)
			}
			switch {
			case tc.wantMore == "" && m.More != nil:
				t.Errorf("unexpected sentinel %+v", m.More)
			case tc.wantMore != "" && (m.More == nil || m.More.URL != tc.wantMore):
				t.Errorf("sentinel %+v, want %s", m.More, tc.wantMore)
			}
			if tc.query == "" && tc.wantMore != "" && m.More.Remaining != tc.wantRemain {
				t.Errorf("remaining %d, want %d", m.More.Remaining, tc.wantRemain)
			}
			if (m.Empty != "") != tc.wantEmpty {
				t.Errorf("empty = %q", m.Empty)
			}
		})
	}

	t.Run("counts and total ignore the page", func(t *testing.T) {
		in := baseInput()
		in.Data = &protocol.Packages{Items: manyPackages(total)}
		m := BuildPackages(in)
		if m.Total != total || m.Filters[0].Count != total {
			t.Errorf("total %d, all-count %d, want %d", m.Total, m.Filters[0].Count, total)
		}
	})
}
