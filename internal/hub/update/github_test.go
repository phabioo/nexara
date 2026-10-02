package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeGitHub serves the two endpoints the hub uses and counts requests.
type fakeGitHub struct {
	t        *testing.T
	srv      *httptest.Server
	releases []map[string]any
	files    map[string]map[string][]byte // tag -> asset -> content
	api      atomic.Int32
	apiHook  func(w http.ResponseWriter, r *http.Request) bool
	dlHook   func(w http.ResponseWriter, r *http.Request) bool
	lastUA   atomic.Value
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	f := &fakeGitHub{t: t, files: map[string]map[string][]byte{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/phabioo/nexara/releases", func(w http.ResponseWriter, r *http.Request) {
		f.api.Add(1)
		f.lastUA.Store(r.Header.Get("User-Agent"))
		if f.apiHook != nil && f.apiHook(w, r) {
			return
		}
		_ = json.NewEncoder(w).Encode(f.releases)
	})
	mux.HandleFunc("/phabioo/nexara/releases/download/", func(w http.ResponseWriter, r *http.Request) {
		if f.dlHook != nil && f.dlHook(w, r) {
			return
		}
		rest := strings.TrimPrefix(r.URL.Path, "/phabioo/nexara/releases/download/")
		tag, asset, _ := strings.Cut(rest, "/")
		data, ok := f.files[tag][asset]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(data)
	})
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGitHub) options(o *Options) {
	o.HTTPClient = f.srv.Client()
	o.APIBase = f.srv.URL
	o.DownloadBase = f.srv.URL
	o.AllowedHosts = []string{"127.0.0.1"}
}

func rel(tag string, prerelease bool, assets ...string) map[string]any {
	var as []map[string]any
	for _, a := range assets {
		as = append(as, map[string]any{"name": a})
	}
	return map[string]any{
		"tag_name": tag, "prerelease": prerelease, "draft": false, "body": "notes for " + tag,
		"published_at": "2026-10-01T10:00:00Z", "assets": as,
	}
}

func allAssets(version, arch string) []string {
	return []string{DebName(version, arch), SumsFile, SigFile, "install.sh"}
}

func TestCheckChannelsAndSelection(t *testing.T) {
	draft := rel("v0.9.0", false, allAssets("0.9.0", "arm64")...)
	draft["draft"] = true
	tests := []struct {
		name     string
		channel  string
		current  string
		releases []map[string]any
		want     string // latest version, "" for none
		avail    bool
	}{
		{name: "stable picks highest release", channel: ChannelStable, current: "0.1.0", want: "0.3.0", avail: true, releases: []map[string]any{
			rel("v0.2.0", false, allAssets("0.2.0", "arm64")...),
			rel("v0.3.0", false, allAssets("0.3.0", "arm64")...),
			rel("v0.1.0", false, allAssets("0.1.0", "arm64")...),
		}},
		{name: "stable skips prereleases", channel: ChannelStable, current: "0.1.0", want: "0.2.0", avail: true, releases: []map[string]any{
			rel("v0.3.0-rc1", true, allAssets("0.3.0-rc1", "arm64")...),
			rel("v0.2.0", false, allAssets("0.2.0", "arm64")...),
		}},
		{name: "stable skips a prerelease tag not flagged as such", channel: ChannelStable, current: "0.1.0", want: "0.2.0", avail: true, releases: []map[string]any{
			rel("v0.3.0-rc1", false, allAssets("0.3.0-rc1", "arm64")...),
			rel("v0.2.0", false, allAssets("0.2.0", "arm64")...),
		}},
		{name: "rc includes prereleases", channel: ChannelRC, current: "0.1.0", want: "0.3.0-rc1", avail: true, releases: []map[string]any{
			rel("v0.3.0-rc1", true, allAssets("0.3.0-rc1", "arm64")...),
			rel("v0.2.0", false, allAssets("0.2.0", "arm64")...),
		}},
		{name: "rc prefers the release over its candidate", channel: ChannelRC, current: "0.1.0", want: "0.3.0", avail: true, releases: []map[string]any{
			rel("v0.3.0-rc2", true, allAssets("0.3.0-rc2", "arm64")...),
			rel("v0.3.0", false, allAssets("0.3.0", "arm64")...),
		}},
		{name: "drafts are ignored", channel: ChannelRC, current: "0.1.0", want: "0.2.0", avail: true, releases: []map[string]any{
			draft, rel("v0.2.0", false, allAssets("0.2.0", "arm64")...),
		}},
		{name: "release without the package for this arch is skipped", channel: ChannelStable, current: "0.1.0", want: "0.2.0", avail: true, releases: []map[string]any{
			rel("v0.3.0", false, allAssets("0.3.0", "amd64")...),
			rel("v0.2.0", false, allAssets("0.2.0", "arm64")...),
		}},
		{name: "release without signature is skipped", channel: ChannelStable, current: "0.1.0", want: "0.2.0", avail: true, releases: []map[string]any{
			rel("v0.3.0", false, DebName("0.3.0", "arm64"), SumsFile),
			rel("v0.2.0", false, allAssets("0.2.0", "arm64")...),
		}},
		{name: "same version is not an update", channel: ChannelStable, current: "0.2.0", want: "0.2.0", avail: false, releases: []map[string]any{
			rel("v0.2.0", false, allAssets("0.2.0", "arm64")...),
		}},
		{name: "older release is not an update", channel: ChannelStable, current: "0.5.0", want: "0.2.0", avail: false, releases: []map[string]any{
			rel("v0.2.0", false, allAssets("0.2.0", "arm64")...),
		}},
		{name: "development build never sees an update", channel: ChannelStable, current: "dev", want: "0.2.0", avail: false, releases: []map[string]any{
			rel("v0.2.0", false, allAssets("0.2.0", "arm64")...),
		}},
		{name: "odd tags are ignored", channel: ChannelStable, current: "0.1.0", want: "", releases: []map[string]any{
			rel("nightly", false, allAssets("0.2.0", "arm64")...),
			rel("v1.2", false, allAssets("1.2.0", "arm64")...),
			rel("v../../x", false),
		}},
		{name: "no releases", channel: ChannelStable, current: "0.1.0", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gh := newFakeGitHub(t)
			gh.releases = tt.releases
			e := newSvcEnv(t, func(o *Options) { gh.options(o); o.CurrentVersion = tt.current })
			e.set(t, SettingCheckGitHub, "true")
			e.set(t, SettingChannel, tt.channel)
			res, err := e.svc.CheckNow(context.Background(), "alice")
			if err != nil {
				t.Fatal(err)
			}
			got := ""
			if res.Latest != nil {
				got = res.Latest.Version
			}
			if got != tt.want || res.UpdateAvailable != tt.avail {
				t.Fatalf("latest = %q available = %v, want %q / %v", got, res.UpdateAvailable, tt.want, tt.avail)
			}
			if res.Latest != nil && (!strings.HasPrefix(res.Latest.URL, "https://github.com/phabioo/nexara/releases/tag/v") || res.Latest.Notes == "") {
				t.Fatalf("release = %+v", res.Latest)
			}
			if ua, _ := gh.lastUA.Load().(string); !strings.HasPrefix(ua, "nexara-nexus/") {
				t.Fatalf("User-Agent = %q", ua)
			}
			if a := e.audit.actions(); len(a) != 1 || a[0] != "update.check:ok" {
				t.Fatalf("audit = %v", a)
			}
		})
	}
}

func TestCheckOffByDefaultMakesNoRequest(t *testing.T) {
	gh := newFakeGitHub(t)
	gh.releases = []map[string]any{rel("v0.2.0", false, allAssets("0.2.0", "arm64")...)}
	e := newSvcEnv(t, gh.options)
	ctx := context.Background()

	if _, err := e.svc.CheckNow(ctx, "a"); !errors.Is(err, ErrCheckDisabled) {
		t.Fatalf("CheckNow err = %v, want ErrCheckDisabled", err)
	}
	if _, err := e.svc.StageRelease(ctx, "a"); !errors.Is(err, ErrCheckDisabled) {
		t.Fatalf("StageRelease err = %v, want ErrCheckDisabled", err)
	}
	e.svc.tick(ctx)
	e.clock.Advance(48 * time.Hour)
	e.svc.tick(ctx)
	if n := gh.api.Load(); n != 0 {
		t.Fatalf("%d requests to GitHub while the check is off", n)
	}
	st, err := e.svc.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Config.CheckGitHub || st.Check != nil {
		t.Fatalf("status = %+v", st)
	}
}

func TestCheckSchedule(t *testing.T) {
	gh := newFakeGitHub(t)
	gh.releases = []map[string]any{rel("v0.2.0", false, allAssets("0.2.0", "arm64")...)}
	e := newSvcEnv(t, gh.options)
	e.set(t, SettingCheckGitHub, "true")
	ctx := context.Background()

	steps := []struct {
		advance time.Duration
		manual  bool
		wantAPI int32
		what    string
	}{
		{0, false, 1, "first tick checks"},
		{time.Minute, false, 1, "no second check within 6 h"},
		{5 * time.Hour, false, 1, "still cached after 5 h 1 min"},
		{time.Hour, false, 2, "6 h later the next check runs"},
		{time.Minute, true, 3, "manual check now runs at any time"},
		{10 * time.Second, true, 3, "manual checks are throttled to one per 30 s"},
		{31 * time.Second, true, 4, "after 30 s manual works again"},
	}
	for _, s := range steps {
		e.clock.Advance(s.advance)
		if s.manual {
			if _, err := e.svc.CheckNow(ctx, "a"); err != nil {
				t.Fatal(err)
			}
		} else {
			e.svc.tick(ctx)
		}
		if got := gh.api.Load(); got != s.wantAPI {
			t.Fatalf("%s: API calls = %d, want %d", s.what, got, s.wantAPI)
		}
	}

	// A failed check is retried after an hour, not six, and keeps the last good answer.
	gh.apiHook = func(w http.ResponseWriter, _ *http.Request) bool { http.Error(w, "boom", 500); return true }
	e.clock.Advance(6 * time.Hour)
	e.svc.tick(ctx)
	st, _ := e.svc.Status(ctx)
	if st.Check == nil || st.Check.Error == "" || st.Check.Latest == nil || st.Check.Latest.Version != "0.2.0" {
		t.Fatalf("check after failure = %+v", st.Check)
	}
	before := gh.api.Load()
	e.clock.Advance(30 * time.Minute)
	e.svc.tick(ctx)
	if gh.api.Load() != before {
		t.Fatal("retried too early after a failure")
	}
	e.clock.Advance(31 * time.Minute)
	e.svc.tick(ctx)
	if gh.api.Load() != before+1 {
		t.Fatal("did not retry an hour after a failure")
	}
}

func TestCheckCacheSurvivesRestart(t *testing.T) {
	gh := newFakeGitHub(t)
	gh.releases = []map[string]any{rel("v0.2.0", false, allAssets("0.2.0", "arm64")...)}
	e := newSvcEnv(t, gh.options)
	e.set(t, SettingCheckGitHub, "true")
	if _, err := e.svc.CheckNow(context.Background(), "a"); err != nil {
		t.Fatal(err)
	}
	svc2, err := New(Options{Dir: e.dir, Settings: e.settings, Now: e.clock.Now, CurrentVersion: "0.1.0", Arch: "arm64",
		HTTPClient: gh.srv.Client(), APIBase: gh.srv.URL, DownloadBase: gh.srv.URL, AllowedHosts: []string{"127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	svc2.tick(context.Background())
	if n := gh.api.Load(); n != 1 {
		t.Fatalf("restart re-checked immediately (%d API calls)", n)
	}
	st, _ := svc2.Status(context.Background())
	if st.Check == nil || !st.Check.UpdateAvailable {
		t.Fatalf("status = %+v", st.Check)
	}
}

func TestCheckErrors(t *testing.T) {
	tests := []struct {
		name string
		hook func(w http.ResponseWriter, r *http.Request) bool
		want string
	}{
		{"server error", func(w http.ResponseWriter, _ *http.Request) bool { http.Error(w, "x", 502); return true }, "502"},
		{"rate limited", func(w http.ResponseWriter, _ *http.Request) bool { http.Error(w, "x", 403); return true }, "403"},
		{"not json", func(w http.ResponseWriter, _ *http.Request) bool { fmt.Fprint(w, "<html>"); return true }, "decoding"},
		{"oversized answer", func(w http.ResponseWriter, _ *http.Request) bool {
			fmt.Fprint(w, "["+strings.Repeat(" ", maxAPIBytes+10)+"]")
			return true
		}, "too large"},
		{"redirect to another host", func(w http.ResponseWriter, r *http.Request) bool {
			http.Redirect(w, r, "https://evil.example/repos", http.StatusFound)
			return true
		}, "evil.example"},
		{"redirect to plain http", func(w http.ResponseWriter, r *http.Request) bool {
			http.Redirect(w, r, "http://127.0.0.1/repos", http.StatusFound)
			return true
		}, "non-HTTPS"},
		{"redirect loop", func(w http.ResponseWriter, r *http.Request) bool {
			http.Redirect(w, r, r.URL.Path, http.StatusFound)
			return true
		}, "redirects"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gh := newFakeGitHub(t)
			gh.apiHook = tt.hook
			e := newSvcEnv(t, gh.options)
			e.set(t, SettingCheckGitHub, "true")
			_, err := e.svc.CheckNow(context.Background(), "a")
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tt.want)
			}
			st, _ := e.svc.Status(context.Background())
			if st.Check == nil || st.Check.Error == "" {
				t.Fatalf("the failure is not recorded: %+v", st.Check)
			}
			if a := e.audit.actions(); len(a) != 1 || a[0] != "update.check:error" {
				t.Fatalf("audit = %v", a)
			}
		})
	}
}

func TestRedirectToAllowedHostIsFollowed(t *testing.T) {
	gh := newFakeGitHub(t)
	gh.releases = []map[string]any{rel("v0.2.0", false, allAssets("0.2.0", "arm64")...)}
	hops := 0
	gh.apiHook = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Query().Get("hop") == "" {
			hops++
			http.Redirect(w, r, r.URL.Path+"?per_page=30&hop=1", http.StatusFound)
			return true
		}
		return false
	}
	e := newSvcEnv(t, gh.options)
	e.set(t, SettingCheckGitHub, "true")
	res, err := e.svc.CheckNow(context.Background(), "a")
	if err != nil || res.Latest == nil || hops != 1 {
		t.Fatalf("res = %+v err = %v hops = %d", res, err, hops)
	}
}

func TestProductionHostAllowList(t *testing.T) {
	g := newGitHubClient(Options{CurrentVersion: "0.1.0"}, defaultHTTPClient())
	tests := []struct {
		url string
		ok  bool
	}{
		{"https://api.github.com/repos/phabioo/nexara/releases", true},
		{"https://github.com/phabioo/nexara/releases/download/v0.2.0/x", true},
		{"https://objects.githubusercontent.com/x", true},
		{"https://release-assets.githubusercontent.com/x", true},
		{"http://github.com/x", false},
		{"https://githubusercontent.com/x", false},
		{"https://evil.githubusercontent.com/x", false},
		{"https://github.com.evil.example/x", false},
		{"https://example.com/x", false},
		{"https://127.0.0.1/x", false},
		{"ftp://github.com/x", false},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			u, _ := url.Parse(tt.url)
			if err := g.checkURL(u); (err == nil) != tt.ok {
				t.Fatalf("checkURL = %v, want ok=%v", err, tt.ok)
			}
		})
	}
}

// releaseFixture publishes a signed 0.2.0 bundle on the fake GitHub.
func releaseFixture(t *testing.T, gh *fakeGitHub, e *svcEnv, version string) testBundle {
	t.Helper()
	b := makeBundle(t, e.key, version, "arm64")
	tag := "v" + version
	gh.releases = []map[string]any{rel(tag, false, allAssets(version, "arm64")...)}
	gh.files[tag] = map[string][]byte{b.debName: b.deb, SumsFile: b.sums, SigFile: b.sig}
	return b
}

func TestStageReleaseFromGitHub(t *testing.T) {
	ctx := context.Background()
	gh := newFakeGitHub(t)
	e := newSvcEnv(t, gh.options)
	e.set(t, SettingCheckGitHub, "true")
	b := releaseFixture(t, gh, e, "0.2.0")

	st, err := e.svc.StageRelease(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if st.Version != "0.2.0" || st.Source != SourceGitHub || st.SHA256 == "" {
		t.Fatalf("staged = %+v", st)
	}
	got, err := os.ReadFile(filepath.Join(e.dir, "0.2.0", b.debName))
	if err != nil || string(got) != string(b.deb) {
		t.Fatalf("staged package: %v", err)
	}
	if a := e.audit.actions(); len(a) != 1 || a[0] != "update.stage:ok" {
		t.Fatalf("audit = %v", a)
	}
	status, _ := e.svc.Status(ctx)
	if len(status.Staged) != 1 || status.Staged[0].Source != SourceGitHub {
		t.Fatalf("status.Staged = %+v", status.Staged)
	}
}

func TestStageReleaseRefusals(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name  string
		setup func(gh *fakeGitHub, e *svcEnv, b *testBundle)
		cur   string
		want  error
		text  string
	}{
		{name: "no newer release", cur: "0.2.0", want: ErrNoUpdate},
		{name: "bad signature on GitHub", cur: "0.1.0", want: ErrBadSignature, setup: func(gh *fakeGitHub, _ *svcEnv, b *testBundle) {
			sig := append([]byte(nil), b.sig...)
			sig[0] ^= 0xff
			gh.files["v0.2.0"][SigFile] = sig
		}},
		{name: "tampered package on GitHub", cur: "0.1.0", want: ErrChecksum, setup: func(gh *fakeGitHub, _ *svcEnv, b *testBundle) {
			gh.files["v0.2.0"][b.debName] = []byte("evil")
		}},
		{name: "asset missing at download", cur: "0.1.0", text: "404", setup: func(gh *fakeGitHub, _ *svcEnv, b *testBundle) {
			delete(gh.files["v0.2.0"], b.debName)
		}},
		{name: "download redirects off GitHub", cur: "0.1.0", text: "evil.example", setup: func(gh *fakeGitHub, _ *svcEnv, _ *testBundle) {
			gh.dlHook = func(w http.ResponseWriter, r *http.Request) bool {
				http.Redirect(w, r, "https://evil.example/x", http.StatusFound)
				return true
			}
		}},
		{name: "oversized download", cur: "0.1.0", want: ErrTooLarge, setup: func(gh *fakeGitHub, _ *svcEnv, _ *testBundle) {
			lowerMaxDeb(t, 8)
		}},
		{name: "oversized sums download", cur: "0.1.0", want: ErrTooLarge, setup: func(gh *fakeGitHub, _ *svcEnv, _ *testBundle) {
			gh.files["v0.2.0"][SumsFile] = make([]byte, MaxSumsBytes+1)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gh := newFakeGitHub(t)
			e := newSvcEnv(t, func(o *Options) { gh.options(o); o.CurrentVersion = tt.cur })
			e.set(t, SettingCheckGitHub, "true")
			b := releaseFixture(t, gh, e, "0.2.0")
			if tt.setup != nil {
				tt.setup(gh, e, &b)
			}
			_, err := e.svc.StageRelease(ctx, "alice")
			if err == nil {
				t.Fatal("staged a bad release")
			}
			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			if tt.text != "" && !strings.Contains(err.Error(), tt.text) {
				t.Fatalf("err = %v, want text %q", err, tt.text)
			}
			if names := listNames(t, e.dir); strings.Join(names, ",") != "check.json" && len(names) != 0 {
				t.Fatalf("left behind: %v", names)
			}
		})
	}
}

func TestStageReleaseUsesTagNotAPIURLs(t *testing.T) {
	// The download URL is built from the validated tag; whatever URL fields
	// the API answer carries are never used.
	gh := newFakeGitHub(t)
	e := newSvcEnv(t, gh.options)
	e.set(t, SettingCheckGitHub, "true")
	releaseFixture(t, gh, e, "0.2.0")
	gh.releases[0]["assets"] = []map[string]any{
		{"name": DebName("0.2.0", "arm64"), "browser_download_url": "https://evil.example/deb"},
		{"name": SumsFile, "browser_download_url": "https://evil.example/sums"},
		{"name": SigFile, "browser_download_url": "https://evil.example/sig"},
	}
	gh.releases[0]["html_url"] = "https://evil.example/"
	if _, err := e.svc.StageRelease(context.Background(), "a"); err != nil {
		t.Fatal(err)
	}
	res, _ := e.svc.Status(context.Background())
	if res.Check == nil || res.Check.Latest == nil || strings.Contains(res.Check.Latest.URL, "evil") {
		t.Fatalf("check = %+v", res.Check)
	}
}
