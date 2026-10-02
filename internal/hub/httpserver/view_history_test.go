package httpserver

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/hub/history"
	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/hub/views"
	"github.com/phabioo/nexara/web"
)

// historyNow is the fixed clock of the history tests: 14:30:20 in Berlin (summer time).
var historyNow = time.Date(2026, 10, 2, 12, 30, 20, 0, time.UTC)

// historyRow is one bucket whose values depend on n, so charts have a shape.
func historyRow(host string, at time.Time, n, samples int) store.MetricRow {
	f := float64(n % 97)
	temp, tmax := 40+f/4, 45+f/4
	return store.MetricRow{
		HostID: host, Time: at, Samples: samples,
		CPUAvg: f, CPUMax: f + 3, MemUsedAvg: 1e9 + f*1e6, MemUsedMax: 1.1e9 + f*1e6, MemTotal: 8 << 30,
		TempAvg: &temp, TempMax: &tmax,
		NetRxAvg: f * 1e3, NetRxMax: f * 2e3, NetTxAvg: f * 1e2, NetTxMax: f * 3e2,
		Disks: []store.DiskUsage{
			{Mount: "/", Used: uint64(40e9 + f*1e6), Total: 117e9},
			{Mount: "/mnt/data", Used: uint64(2.9e12), Total: 4e12},
		},
	}
}

// seedHistory writes minute rows for the last `minutes` minutes (skipping gap, if set: [from, to) ago in
// minutes) and hour rows for the last `hours` hours.
func seedHistory(tb testing.TB, st *store.Store, host string, now time.Time, minutes, hours int, gapFrom, gapTo int) {
	tb.Helper()
	ctx := context.Background()
	var mins, hrs []store.MetricRow
	for i := 1; i <= minutes; i++ {
		if gapTo > 0 && i >= gapFrom && i < gapTo {
			continue
		}
		mins = append(mins, historyRow(host, now.Truncate(time.Minute).Add(-time.Duration(i)*time.Minute), i, 30))
	}
	for i := 1; i <= hours; i++ {
		hrs = append(hrs, historyRow(host, now.Truncate(time.Hour).Add(-time.Duration(i)*time.Hour), i, 1800))
	}
	if len(hrs) > 0 {
		if err := st.ReplaceMetrics(ctx, store.Metrics1h, hrs); err != nil {
			tb.Fatal(err)
		}
	}
	if len(mins) > 0 {
		if err := st.MergeMetrics1m(ctx, mins); err != nil {
			tb.Fatal(err)
		}
	}
}

func newHistoryEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t)
	r, err := views.New(web.Templates, views.Options{})
	if err != nil {
		t.Fatal(err)
	}
	e.srv.renderer = r
	loc, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Skipf("no time zone database: %v", err)
	}
	e.srv.svc.History = history.New(history.Options{Store: e.st, Now: func() time.Time { return historyNow }, Location: loc})
	e.srv.now = func() time.Time { return historyNow }
	// alpha (a1) is online with a day of minutes and 30 days of hours, a two hour hole in the minutes; beta
	// (b2) is offline with a few hours of old data; gamma (c3) has never reported.
	seedHistory(t, e.st, "a1", historyNow, 26*60, 31*24, 3*60, 5*60)
	seedHistory(t, e.st, "b2", historyNow.Add(-6*time.Hour), 120, 0, 0, 0)
	e.hub.mu.Lock()
	e.hub.hosts = append(e.hub.hosts, grid.HostInfo{ID: "c3", Name: "gamma", Address: "192.0.2.23", Online: true})
	e.hub.hosts[1].LastSeen = historyNow.Add(-5 * time.Hour)
	e.hub.mu.Unlock()
	return e
}

func TestHistoryPages(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		mod    func(e *env)
		status int
		want   []string
		lack   []string
	}{
		{
			name: "default host is the first online host", path: "/history", status: 200,
			want: []string{
				"History: alpha", "times in Europe/Berlin", `data-host="alpha" data-view="history"`, `sse-connect="/events"`,
				"CPU · 24H", "Memory · 24H", "SoC temperature · 24H", "Network · 24H", "Disk / · 24H", "Disk /mnt/data · 24H",
				`href="/hosts/alpha/history" aria-current="page"`, `href="/hosts/alpha/history?range=7d"`, `href="/hosts/alpha/history?range=30d"`,
				`viewBox="0 0 300 100"`, `class="hist-line"`, `class="hist-area"`, "GREEN ↓ RX · PURPLE ↑ TX", "MIN ", "AVG ", "MAX ", "NOW",
				// 24 h back from 14:30 Berlin time: the axis starts at the same clock time the day before
				"Thu 14:30", `hx-trigger="every 60s"`, `hx-get="/hosts/alpha/history"`, "8 GB total",
			},
			lack: []string{"Alerts", "Containers", "History is not available", "History starts collecting", "<script>", "style="},
		},
		{
			name: "explicit host and the host tabs keep the view", path: "/hosts/alpha/history", status: 200,
			want: []string{"History: alpha", `href="/hosts/beta/history"`, `href="/hosts/gamma/history"`},
		},
		{
			name: "seven days", path: "/hosts/alpha/history?range=7d", status: 200,
			want: []string{"CPU · 7D", "Memory · 7D", `href="/hosts/alpha/history?range=7d" aria-current="page"`, `hx-trigger="every 300s"`,
				`hx-get="/hosts/alpha/history?range=7d"`, "Fri 25 Sep"},
			lack: []string{"CPU · 24H"},
		},
		{
			name: "thirty days", path: "/hosts/alpha/history?range=30d", status: 200,
			want: []string{"CPU · 30D", `href="/hosts/alpha/history?range=30d" aria-current="page"`, "2 Sep"},
		},
		{
			name: "an unknown range is the default", path: "/hosts/alpha/history?range=1y", status: 200,
			want: []string{"CPU · 24H", `href="/hosts/alpha/history" aria-current="page"`},
		},
		{
			name: "an empty range is the default", path: "/hosts/alpha/history?range=", status: 200,
			want: []string{"CPU · 24H"},
		},
		{
			name: "a range with markup is just the default", path: "/hosts/alpha/history?range=%3Cscript%3E", status: 200,
			want: []string{"CPU · 24H"}, lack: []string{"<script>alert"},
		},
		{
			name: "unknown host", path: "/hosts/nope/history", status: 404,
		},
		{
			name: "offline host shows its history and the notice", path: "/hosts/beta/history?range=7d", status: 200,
			want: []string{"History: Beta Pi", "Beta Pi is offline.", "Last seen 5 h ago", `class="hist-line"`},
			lack: []string{"History starts collecting"},
		},
		{
			name: "host without data yet", path: "/hosts/gamma/history", status: 200,
			want: []string{"No history yet", "History starts collecting when the agent is online.", `data-state="empty"`},
			lack: []string{`class="hist-line"`, "hist-card"},
		},
		{
			name: "offline host without data", path: "/hosts/gamma/history", status: 200,
			mod: func(e *env) {
				e.hub.mu.Lock()
				e.hub.hosts[2].Online = false
				e.hub.mu.Unlock()
			},
			want: []string{"gamma is offline.", "History starts collecting when the agent is online."},
			lack: []string{"The charts show", "Last seen"},
		},
		{
			name: "no history service", path: "/hosts/alpha/history", status: 200,
			mod:  func(e *env) { e.srv.svc.History = nil },
			want: []string{"History is not available", `data-state="unavailable"`, "History: alpha", `href="/hosts/alpha/history?range=7d"`},
			lack: []string{`class="hist-line"`},
		},
		{
			name: "no hosts", path: "/history", status: 200,
			mod: func(e *env) {
				e.hub.mu.Lock()
				e.hub.hosts = nil
				e.hub.mu.Unlock()
			},
			want: []string{"No hosts yet", `hx-get="/hosts/new"`, `data-host="" data-view="history"`},
			lack: []string{"hist-card"},
		},
		{
			name: "default falls back to the first host when none is online", path: "/history", status: 200,
			mod: func(e *env) {
				e.hub.mu.Lock()
				for i := range e.hub.hosts {
					e.hub.hosts[i].Online = false
				}
				e.hub.mu.Unlock()
			},
			want: []string{"History: alpha", "alpha is offline."},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newHistoryEnv(t)
			if tc.mod != nil {
				tc.mod(e)
			}
			cookie, _ := e.signIn()
			rec := e.get(tc.path, withCookies(cookie))
			if rec.Code != tc.status {
				t.Fatalf("status %d, want %d", rec.Code, tc.status)
			}
			if tc.status != 200 {
				return
			}
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
				t.Errorf("content type %q", ct)
			}
			ovHave(t, rec.Body.String(), tc.want...)
			ovLack(t, rec.Body.String(), tc.lack...)
		})
	}
}

func TestHistoryRequiresSession(t *testing.T) {
	e := newHistoryEnv(t)
	for _, path := range []string{"/history", "/hosts/alpha/history", "/hosts/nope/history"} {
		rec := e.get(path)
		if rec.Code != http.StatusSeeOther && rec.Code != http.StatusFound {
			t.Errorf("%s: status %d, want a redirect to /login", path, rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "/login" {
			t.Errorf("%s: Location %q", path, loc)
		}
	}
}

// Only GET exists; the view has no state-changing request.
func TestHistoryRejectsOtherMethods(t *testing.T) {
	e := newHistoryEnv(t)
	cookie, csrf := e.signIn()
	rec := e.post("/hosts/alpha/history", withCookies(cookie), withHeader("X-CSRF-Token", csrf))
	if rec.Code != http.StatusMethodNotAllowed && rec.Code != http.StatusNotFound {
		t.Errorf("POST: status %d", rec.Code)
	}
}

// A gap in the data (the host was offline) is a break in the line, not a run of zeros.
func TestHistoryGapBreaksTheLine(t *testing.T) {
	e := newHistoryEnv(t)
	cookie, _ := e.signIn()
	body := e.get("/hosts/alpha/history", withCookies(cookie)).Body.String()
	m := regexp.MustCompile(`<path class="hist-line" d="([^"]+)"`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no line path in the page")
	}
	if got := strings.Count(m[1], "M"); got != 2 {
		t.Errorf("CPU line has %d sub-paths, want 2 (before and after the two hour hole): %.80s", got, m[1])
	}
}

// The axis is written in the hub's time zone: the same instants read differently in UTC.
func TestHistoryAxisUsesTheHubZone(t *testing.T) {
	e := newHistoryEnv(t)
	cookie, _ := e.signIn()
	berlinBody := e.get("/hosts/alpha/history", withCookies(cookie)).Body.String()
	e.srv.svc.History = history.New(history.Options{Store: e.st, Now: func() time.Time { return historyNow }, Location: time.UTC})
	utcBody := e.get("/hosts/alpha/history", withCookies(cookie)).Body.String()
	ovHave(t, berlinBody, "Thu 14:30", "times in Europe/Berlin")
	ovHave(t, utcBody, "Thu 12:30", "times in UTC")
	ovLack(t, utcBody, "Thu 14:30")
}

func TestHistoryFragment(t *testing.T) {
	e := newHistoryEnv(t)
	cookie, _ := e.signIn()

	poll := e.get("/hosts/alpha/history?range=7d", withCookies(cookie),
		withHeader("HX-Request", "true"), withHeader("HX-Target", "hist-charts"))
	if poll.Code != 200 {
		t.Fatalf("status %d", poll.Code)
	}
	body := poll.Body.String()
	ovHave(t, body, `id="hist-charts"`, `hx-trigger="every 300s"`, `hx-get="/hosts/alpha/history?range=7d"`, "CPU · 7D")
	// Only the charts: no shell, no heading, no range tabs.
	ovLack(t, body, "<html", "<main", `id="nx-tabs"`, "History: alpha", "tab-label")

	// A boosted navigation targets #main and gets the whole page.
	nav := e.get("/hosts/alpha/history?range=7d", withCookies(cookie),
		withHeader("HX-Request", "true"), withHeader("HX-Boosted", "true"), withHeader("HX-Target", "main"))
	ovHave(t, nav.Body.String(), "<html", `id="main"`, "History: alpha", `id="hist-charts"`)
}

// No inline style or script may reach the page: the CSP forbids both.
func TestHistoryPageIsCSPSafe(t *testing.T) {
	e := newHistoryEnv(t)
	cookie, _ := e.signIn()
	rec := e.get("/hosts/alpha/history", withCookies(cookie))
	body := rec.Body.String()
	for _, re := range []string{`\sstyle=`, `<style`, `\son[a-z]+=`, `javascript:`} {
		if regexp.MustCompile(re).MatchString(body) {
			t.Errorf("page matches %q", re)
		}
	}
	for _, f := range regexp.MustCompile(`<script[^>]*>`).FindAllString(body, -1) {
		if !strings.Contains(f, " src=") {
			t.Errorf("inline script %q", f)
		}
	}
}

// The mount name comes from the agent: markup in it must come out escaped.
func TestHistoryEscapesMountNames(t *testing.T) {
	e := newHistoryEnv(t)
	row := historyRow("a1", historyNow.Truncate(time.Minute).Add(-time.Minute), 1, 30)
	row.Disks = []store.DiskUsage{{Mount: `/mnt/<img src=x onerror=alert(1)>`, Used: 1, Total: 2}}
	if err := e.st.MergeMetrics1m(context.Background(), []store.MetricRow{row}); err != nil {
		t.Fatal(err)
	}
	cookie, _ := e.signIn()
	body := e.get("/hosts/alpha/history", withCookies(cookie)).Body.String()
	if strings.Contains(body, "<img src=x") {
		t.Error("mount name was not escaped")
	}
	ovHave(t, body, "&lt;img src=x onerror=alert(1)&gt;")
}

func TestZoneName(t *testing.T) {
	berlin, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Skip("no tz database")
	}
	tests := []struct {
		name string
		loc  *time.Location
		want string
	}{
		{"named zone", berlin, "Europe/Berlin"},
		{"utc", time.UTC, "UTC"},
		{"nil", nil, "UTC"},
		{"local shows the abbreviation", time.Local, func() string { a, _ := historyNow.In(time.Local).Zone(); return a }()},
	}
	for _, tc := range tests {
		if got := zoneName(tc.loc, historyNow); got != tc.want {
			t.Errorf("%s: zoneName = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestHistoryRange(t *testing.T) {
	tests := []struct{ query, want string }{
		{"", "24h"}, {"range=24h", "24h"}, {"range=7d", "7d"}, {"range=30d", "30d"},
		{"range=7D", "24h"}, {"range=bogus", "24h"}, {"range=7d&range=30d", "7d"},
	}
	for _, tc := range tests {
		r := httptest.NewRequest("GET", "/history?"+tc.query, nil)
		if got := historyRange(r).Key; got != tc.want {
			t.Errorf("?%s: range %q, want %q", tc.query, got, tc.want)
		}
	}
}

// --- a year of data -------------------------------------------------------------

// newHistoryBenchServer is a bare Server around a history service over a store with a year of hourly rows
// and a week of minute rows for one host, enough to call the handler directly.
func newHistoryBenchServer(tb testing.TB) *Server {
	tb.Helper()
	st, err := store.Open(filepath.Join(tb.TempDir(), "nexus.db"))
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = st.Close() })
	seedHistory(tb, st, "a1", historyNow, 7*24*60, 365*24, 0, 0)
	r, err := views.New(web.Templates, views.Options{})
	if err != nil {
		tb.Fatal(err)
	}
	hub := newFakeHub()
	hub.hosts = []grid.HostInfo{{ID: "a1", Name: "alpha", Address: "192.0.2.21", Online: true}}
	return &Server{
		hub: hub, renderer: r, log: slog.New(slog.DiscardHandler), now: func() time.Time { return historyNow },
		svc: Services{History: history.New(history.Options{Store: st, Now: func() time.Time { return historyNow }, Location: time.UTC})},
	}
}

func serveHistory(tb testing.TB, s *Server, rangeKey string) int {
	tb.Helper()
	r := httptest.NewRequest("GET", "/hosts/alpha/history?range="+rangeKey, nil)
	r.SetPathValue("host", "alpha")
	rec := httptest.NewRecorder()
	s.handleHistoryHost(rec, r)
	if rec.Code != 200 {
		tb.Fatalf("%s: status %d: %s", rangeKey, rec.Code, rec.Body.String())
	}
	return rec.Body.Len()
}

func TestHistoryYearOfData(t *testing.T) {
	if testing.Short() {
		t.Skip("seeds a year of hourly rows")
	}
	s := newHistoryBenchServer(t)
	for _, key := range []string{"24h", "7d", "30d"} {
		size := serveHistory(t, s, key)
		// ~300 points per series keep the page small: six charts, two paths each.
		if size > 150<<10 {
			t.Errorf("%s: page is %d bytes", key, size)
		}
		t.Logf("%s: %d bytes", key, size)
	}
}

func BenchmarkHistoryHandler(b *testing.B) {
	s := newHistoryBenchServer(b)
	for _, key := range []string{"24h", "7d", "30d"} {
		b.Run(key, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				serveHistory(b, s, key)
			}
		})
	}
}
