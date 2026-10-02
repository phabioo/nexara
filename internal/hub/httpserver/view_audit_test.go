package httpserver

import (
	"context"
	"encoding/csv"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/hub/views"
	"github.com/phabioo/nexara/web"
)

type auditEnv struct {
	*env
	cookie *http.Cookie
}

func newAuditEnv(t *testing.T) *auditEnv {
	t.Helper()
	e := newEnv(t)
	rd, err := views.New(web.Templates, views.Options{})
	if err != nil {
		t.Fatal(err)
	}
	e.srv.renderer = rd
	e.srv.svc.Store = e.st
	cookie, _ := e.signIn()
	return &auditEnv{env: e, cookie: cookie}
}

func (a *auditEnv) add(entries ...store.AuditEntry) {
	a.t.Helper()
	for _, en := range entries {
		if en.Time.IsZero() {
			en.Time = time.Now().Add(-time.Minute)
		}
		if _, err := a.st.AppendAudit(context.Background(), en); err != nil {
			a.t.Fatal(err)
		}
	}
}

func (a *auditEnv) getAs(target string, opts ...reqOpt) *httptest.ResponseRecorder {
	return a.get(target, append([]reqOpt{withCookies(a.cookie)}, opts...)...)
}

func TestAuditRequiresSignIn(t *testing.T) {
	a := newAuditEnv(t)
	for _, target := range []string{"/settings/audit", "/settings/audit.csv"} {
		rec := a.get(target)
		if rec.Code != http.StatusSeeOther && rec.Code != http.StatusUnauthorized && rec.Code != http.StatusFound {
			t.Errorf("%s: status %d, want a redirect or 401", target, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "Audit log") {
			t.Errorf("%s leaks the page without a session", target)
		}
	}
}

func TestAuditPage(t *testing.T) {
	a := newAuditEnv(t)
	a.add(
		store.AuditEntry{User: "fabio", Action: "login", Result: store.AuditOK, Detail: "ip=192.0.2.1"},
		store.AuditEntry{User: "fabio", Host: "alpha", Action: "job.apt_upgrade", Result: store.AuditOK},
		store.AuditEntry{User: "mallory", Action: "login", Result: store.AuditDenied, Detail: "ip=x reason=bad_password"},
		store.AuditEntry{User: "fabio", Host: "beta", Action: "job.pkg_install", Result: store.AuditError, Detail: `<script>alert(1)</script> failed`},
		store.AuditEntry{User: "fabio", Host: "alpha", Action: "shell.open", Result: store.AuditOK, Time: time.Now().Add(-40 * 24 * time.Hour)},
	)
	tests := []struct {
		name     string
		target   string
		opts     []reqOpt
		contains []string
		absent   []string
	}{
		{
			name: "default page: 7 days, newest first, sentences", target: "/settings/audit",
			contains: []string{"<title>Audit log", "Operator fabio signed in", "apt upgrade on alpha finished", "Sign-in refused for mallory (bad password)",
				"Installing &lt;script&gt;alert(1)&lt;/script&gt; on beta failed", "Back to settings", `href="/settings"`, `id="audit-filter"`,
				`name="range" value="7d" checked`, `aria-current="page"`, "Export CSV", "Error", "Denied", `<option value="alpha">alpha</option>`},
			absent: []string{"opened a shell on alpha", "<script>alert(1)</script>", "Clear filters"},
		},
		{
			name: "range all includes old entries", target: "/settings/audit?range=all",
			contains: []string{"Operator fabio opened a shell on alpha", `name="range" value="all" checked`, "Clear filters"},
		},
		{
			name: "host filter", target: "/settings/audit?host=beta",
			contains: []string{"on beta failed", `<option value="beta" selected>`}, absent: []string{"signed in", "apt upgrade"},
		},
		{
			name: "user filter", target: "/settings/audit?user=mallory",
			contains: []string{"Sign-in refused"}, absent: []string{"signed in", "apt upgrade"},
		},
		{
			name: "action group", target: "/settings/audit?group=packages",
			contains: []string{"apt upgrade on alpha finished", "on beta failed", `<option value="packages" selected>`}, absent: []string{"signed in", "Sign-in refused"},
		},
		{
			name: "result filter", target: "/settings/audit?result=denied",
			contains: []string{"Sign-in refused", `name="result" value="denied" checked`}, absent: []string{"apt upgrade", "signed in"},
		},
		{
			name: "search over detail, wildcard literal", target: "/settings/audit?q=ip%3D192",
			contains: []string{"Operator fabio signed in", `value="ip=192"`}, absent: []string{"Sign-in refused"},
		},
		{
			name: "percent matches nothing", target: "/settings/audit?q=%25",
			contains: []string{"No entries match these filters."}, absent: []string{"signed in"},
		},
		{
			name: "unknown filter values fall back", target: "/settings/audit?group=zzz&result=zzz&range=zzz",
			contains: []string{"Operator fabio signed in"},
		},
		{
			name: "fragment for the filter bar", target: "/settings/audit?host=alpha",
			opts:     []reqOpt{htmx(), withHeader("HX-Target", "audit-results")},
			contains: []string{"apt upgrade on alpha finished", "audit-meta"}, absent: []string{"<title>", "audit-filter", "signed in"},
		},
		{
			name: "boosted navigation gets the full page", target: "/settings/audit",
			opts:     []reqOpt{htmx(), withHeader("HX-Target", "main")},
			contains: []string{"<title>Audit log", `id="audit-filter"`},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := a.getAs(tc.target, tc.opts...)
			if rec.Code != 200 {
				t.Fatalf("status %d: %.200s", rec.Code, rec.Body.String())
			}
			body := rec.Body.String()
			for _, s := range tc.contains {
				if !strings.Contains(body, s) {
					t.Errorf("missing %q", s)
				}
			}
			for _, s := range tc.absent {
				if strings.Contains(body, s) {
					t.Errorf("unexpected %q", s)
				}
			}
		})
	}
}

func TestAuditPaging(t *testing.T) {
	a := newAuditEnv(t)
	var batch []store.AuditEntry
	for i := 0; i < 130; i++ {
		batch = append(batch, store.AuditEntry{User: "u", Action: "logout", Result: store.AuditOK, Detail: fmt.Sprintf("n%03d", i),
			Time: time.Now().Add(-time.Duration(i+1) * time.Minute)})
	}
	a.add(batch...)

	first := a.getAs("/settings/audit")
	body := first.Body.String()
	if got := strings.Count(body, `class="audit-row`); got != 100 {
		t.Fatalf("first page has %d rows, want 100", got)
	}
	i := strings.Index(body, `hx-get="/settings/audit?cursor=`)
	if i < 0 {
		t.Fatal("no Show more sentinel")
	}
	rest := body[i+len(`hx-get="`):]
	next := strings.ReplaceAll(rest[:strings.Index(rest, `"`)], "&amp;", "&")

	// A newer entry arrives meanwhile; the next page must continue exactly where the first ended.
	a.add(store.AuditEntry{User: "u", Action: "logout", Result: store.AuditOK, Detail: "late", Time: time.Now()})
	more := a.getAs(next, htmx())
	if more.Code != 200 {
		t.Fatalf("more: %d", more.Code)
	}
	mb := more.Body.String()
	if got := strings.Count(mb, `class="audit-row`); got != 31 { // 130 seeded + the sign-in of the test operator - 100 on the first page
		t.Errorf("second page has %d rows, want 31", got)
	}
	if strings.Contains(mb, "audit-more") || strings.Contains(mb, "<title>") {
		t.Errorf("second page should be rows only without a sentinel")
	}

	if rec := a.getAs("/settings/audit?cursor=garbage", htmx()); rec.Code != http.StatusBadRequest {
		t.Errorf("bad cursor: status %d, want 400", rec.Code)
	}
	if rec := a.getAs("/settings/audit?cursor=garbage"); rec.Code != http.StatusBadRequest {
		t.Errorf("bad cursor on the full page: status %d, want 400", rec.Code)
	}
}

func TestAuditCSV(t *testing.T) {
	a := newAuditEnv(t)
	a.add(
		store.AuditEntry{User: "fabio", Host: "alpha", Action: "shell.open", Result: store.AuditOK, Detail: `=HYPERLINK("http://x","y")`},
		store.AuditEntry{User: "+evil", Host: "@h", Action: "login", Result: store.AuditDenied, Detail: "-1+2, with \"quotes\"\nand newline"},
		store.AuditEntry{User: "fabio", Action: "logout", Result: store.AuditOK, Detail: "plain"},
		store.AuditEntry{User: "fabio", Action: "logout", Result: store.AuditOK, Detail: "old", Time: time.Now().Add(-90 * 24 * time.Hour)},
	)
	rec := a.getAs("/settings/audit.csv")
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("content type %q", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment; filename=") {
		t.Errorf("content disposition %q", cd)
	}
	recs, err := csv.NewReader(rec.Body).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 5 { // header + 3 seeded within 7 days + the sign-in of the test operator
		t.Fatalf("%d records: %v", len(recs), recs)
	}
	if strings.Join(recs[0], ",") != "time,operator,host,action,result,detail" {
		t.Errorf("header %v", recs[0])
	}
	for _, r := range recs[1:] {
		for _, cell := range r {
			if cell != "" && strings.ContainsRune("=+-@\t\r", rune(cell[0])) {
				t.Errorf("cell %q starts with a formula character", cell)
			}
		}
	}
	got := map[string][]string{}
	for _, r := range recs[1:] {
		got[r[5]] = r
	}
	if r := got[`'=HYPERLINK("http://x","y")`]; r == nil || r[1] != "fabio" {
		t.Errorf("formula cell not neutralized: %v", got)
	}
	if r := got["'-1+2, with \"quotes\"\nand newline"]; r == nil || r[1] != "'+evil" || r[2] != "'@h" {
		t.Errorf("injection cells not neutralized: %v", got)
	}

	// Filters apply; range=all brings the old entry.
	rec = a.getAs("/settings/audit.csv?range=all&q=old")
	recs, _ = csv.NewReader(rec.Body).ReadAll()
	if len(recs) != 2 || recs[1][5] != "old" {
		t.Errorf("filtered export: %v", recs)
	}
	// The export is audited.
	entries, _, _ := a.st.QueryAudit(context.Background(), store.AuditFilter{Actions: []string{"audit.export"}})
	if len(entries) != 2 || entries[0].User != testOperator {
		t.Errorf("export audit entries: %+v", entries)
	}
}

func TestCSVCell(t *testing.T) {
	tests := map[string]string{
		"": "", "plain": "plain", "=1": "'=1", "+1": "'+1", "-1": "'-1", "@x": "'@x", "\tx": "'\tx", "\rx": "'\rx",
		"a=b": "a=b", "2026-01-01T00:00:00Z": "2026-01-01T00:00:00Z", "'=x": "'=x",
	}
	for in, want := range tests {
		if got := csvCell(in); got != want {
			t.Errorf("csvCell(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAuditWithoutStore(t *testing.T) {
	a := newAuditEnv(t)
	a.srv.svc.Store = nil
	if rec := a.getAs("/settings/audit"); rec.Code != http.StatusNotImplemented {
		t.Errorf("status %d, want 501", rec.Code)
	}
	if rec := a.getAs("/settings/audit.csv"); rec.Code != http.StatusNotImplemented {
		t.Errorf("csv status %d, want 501", rec.Code)
	}
}
