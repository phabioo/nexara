package views

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/store"
)

func TestFormatAudit(t *testing.T) {
	tests := []struct {
		name string
		e    store.AuditEntry
		want string
	}{
		{"login ok", store.AuditEntry{User: "fabio", Action: "login", Result: "ok", Detail: "ip=192.0.2.1"}, "Operator fabio signed in"},
		{"login denied with reason", store.AuditEntry{User: "mallory", Action: "login", Result: "denied", Detail: "ip=192.0.2.9 reason=bad_password"}, "Sign-in refused for mallory (bad password)"},
		{"login error", store.AuditEntry{User: "fabio", Action: "login", Result: "error", Detail: "ip=x reason=stored_hash_unusable"}, "Sign-in failed for fabio (stored hash unusable)"},
		{"2fa denied", store.AuditEntry{User: "fabio", Action: "login.2fa", Result: "denied", Detail: "reason=bad_code"}, "Two-factor code refused for fabio (bad code)"},
		{"system actor", store.AuditEntry{User: "system", Action: "backup.create", Result: "ok"}, "Backup created"},
		{"apt upgrade ok", store.AuditEntry{User: "fabio", Host: "pi5-media", Action: "job.apt_upgrade", Result: "ok"}, "apt upgrade on pi5-media finished"},
		{"apt update failed", store.AuditEntry{Host: "pi3-dns", Action: "job.apt_update", Result: "error", Detail: "exit 100"}, "apt update on pi3-dns failed"},
		{"apt clean canceled", store.AuditEntry{Host: "pi3-dns", Action: "job.apt_clean", Result: "error", Detail: "canceled by fabio"}, "apt clean-up on pi3-dns canceled"},
		{"install ok", store.AuditEntry{Host: "pi3-dns", Action: "job.pkg_install", Result: "ok", Detail: "tmux"}, "Installed tmux on pi3-dns"},
		{"install failed", store.AuditEntry{Host: "pi3-dns", Action: "job.pkg_install", Result: "error", Detail: "tmux E: unable"}, "Installing tmux on pi3-dns failed"},
		{"remove canceled", store.AuditEntry{Host: "pi3-dns", Action: "job.pkg_remove", Result: "error", Detail: "tmux canceled"}, "Removing tmux from pi3-dns canceled"},
		{"unknown job kind falls back", store.AuditEntry{User: "fabio", Host: "h", Action: "job.mystery", Result: "ok"}, "job.mystery by Operator fabio on h"},
		{"shell open", store.AuditEntry{User: "fabio", Host: "pi5-media", Action: "shell.open", Result: "ok", Detail: "session ab"}, "Operator fabio opened a shell on pi5-media"},
		{"shell close without detail", store.AuditEntry{Host: "h", Action: "shell.close", Result: "ok"}, "Shell session on h closed"},
		{"shell close with detail", store.AuditEntry{Host: "h", Action: "shell.close", Result: "ok", Detail: "12 min"}, "Shell session on h closed (12 min)"},
		{"service restart", store.AuditEntry{User: "fabio", Host: "h", Action: "service.restart", Result: "ok", Detail: "ssh.service"}, "Operator fabio restarted ssh.service on h"},
		{"cert renew without detail", store.AuditEntry{Host: "h", Action: "cert.renew", Result: "ok"}, "Certificate of h"},
		{"hub-level host", store.AuditEntry{User: "fabio", Action: "service.restart", Result: "error", Detail: "x"}, "Restarting x on the hub failed"},
		{"generic fallback ok", store.AuditEntry{User: "fabio", Action: "settings.audit_retention", Result: "ok"}, "settings.audit_retention by Operator fabio"},
		{"generic fallback denied", store.AuditEntry{User: "fabio", Host: "h", Action: "x.y", Result: "denied"}, "x.y by Operator fabio on h refused"},
		{"markup stays text", store.AuditEntry{User: "<b>x</b>", Action: "logout", Result: "ok"}, "Operator <b>x</b> signed out"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := FormatAudit(tc.e); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAuditGroupsDoNotOverlap(t *testing.T) {
	actions := []string{"login", "login.locked", "login.2fa", "logout", "user.reset", "admin.user_reset", "admin.login_unlock",
		"admin.setup_code", "setup.commit", "setup.unlock", "setup.wrong_code", "setup.locked", "setup.locked_global",
		"host.remove", "host.link", "host.probe", "host.replace", "enroll.ok", "enroll.denied", "enroll.code", "agent.update",
		"job.apt_update", "shell.open", "shell.close", "shell.session_ended", "service.restart", "cert.renew",
		"backup.create", "backup.download", "backup.restore", "update.check", "update.stage", "update.request", "update.apply", "update.settings",
		"audit.prune", "audit.export"}
	for _, a := range actions {
		var in []string
		for _, g := range AuditGroups {
			match := false
			for _, x := range g.Actions {
				match = match || x == a
			}
			for _, p := range g.Prefixes {
				match = match || strings.HasPrefix(a, p)
			}
			if match {
				in = append(in, g.Key)
			}
		}
		want := 1
		if strings.HasPrefix(a, "audit.") {
			want = 0
		}
		if len(in) != want {
			t.Errorf("action %q is in groups %v, want %d", a, in, want)
		}
	}
}

func TestParseAuditQuery(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want AuditQuery
	}{
		{"defaults", "", AuditQuery{Range: "7d"}},
		{"all set", "host=h&user=u&group=shell&result=error&range=all&q=abc&cursor=1.2", AuditQuery{Host: "h", User: "u", Group: "shell", Result: "error", Range: "all", Q: "abc", Cursor: "1.2"}},
		{"unknown values fall back", "group=nope&result=bad&range=1y", AuditQuery{Range: "7d"}},
		{"control chars dropped, trimmed", "q=%20a%00b%0A%20", AuditQuery{Range: "7d", Q: "ab"}},
		{"long term cut", "q=" + strings.Repeat("x", 100), AuditQuery{Range: "7d", Q: strings.Repeat("x", 64)}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, _ := url.ParseQuery(tc.in)
			if got := ParseAuditQuery(v); got != tc.want {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestAuditQueryFilterAndValues(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	q := AuditQuery{Host: "h", Group: "packages", Result: "ok", Range: "24h", Q: "a b"}
	f := q.Filter(now, 50)
	if f.Host != "h" || f.Result != "ok" || f.Search != "a b" || f.Limit != 50 || !f.Since.Equal(now.Add(-24*time.Hour)) ||
		len(f.ActionPrefixes) != 1 || f.ActionPrefixes[0] != "job." {
		t.Errorf("filter = %+v", f)
	}
	if got := (AuditQuery{Range: "all"}).Filter(now, 1); !got.Since.IsZero() {
		t.Errorf("all has Since %v", got.Since)
	}
	if got := q.Values().Encode(); got != "group=packages&host=h&q=a+b&range=24h&result=ok" {
		t.Errorf("values = %q", got)
	}
	if got := (AuditQuery{Range: "7d"}).Values().Encode(); got != "" {
		t.Errorf("default values = %q", got)
	}
}

func TestBuildAudit(t *testing.T) {
	loc := time.FixedZone("T", 2*3600)
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC) // 14:00 local
	at := func(d time.Duration) time.Time { return now.Add(d) }
	entries := []store.AuditEntry{
		{ID: 5, Time: at(-time.Hour), User: "fabio", Action: "login", Result: "ok"},
		{ID: 4, Time: at(-2 * time.Hour), User: "fabio", Host: "pi5", Action: "job.apt_update", Result: "error"},
		{ID: 3, Time: at(-20 * time.Hour), User: "mallory", Action: "login", Result: "denied"},
		{ID: 2, Time: at(-72 * time.Hour), User: "fabio", Action: "logout", Result: "ok"},
	}
	m := BuildAudit(AuditInput{
		Query: AuditQuery{Range: "7d", Host: "gone"}, Entries: entries, Next: "9.9",
		Hosts: []string{"pi5"}, Users: []string{"fabio"}, Now: now, Loc: loc,
	})
	if len(m.Rows) != 4 || m.Shown != 4 {
		t.Fatalf("rows = %d", len(m.Rows))
	}
	wantDay := []string{"Today", "", "Yesterday", "Tue 29 Sep 2026"}
	for i, r := range m.Rows {
		if r.Day != wantDay[i] {
			t.Errorf("row %d day = %q, want %q", i, r.Day, wantDay[i])
		}
	}
	if m.Rows[0].Time != "13:00:00" || m.Rows[0].Host != "—" || m.Rows[0].Tag != "" {
		t.Errorf("row 0 = %+v", m.Rows[0])
	}
	if m.Rows[1].Tag != "Error" || m.Rows[2].Tag != "Denied" || m.Rows[1].Host != "pi5" {
		t.Errorf("tags = %q %q", m.Rows[1].Tag, m.Rows[2].Tag)
	}
	if m.More == nil || m.More.URL != "/settings/audit?cursor=9.9&host=gone" {
		t.Errorf("more = %+v", m.More)
	}
	if m.ExportURL != "/settings/audit.csv?host=gone" || !m.Filtered {
		t.Errorf("export = %q filtered = %v", m.ExportURL, m.Filtered)
	}
	if len(m.Hosts) != 3 || !m.Hosts[2].Selected || m.Hosts[2].Value != "gone" {
		t.Errorf("hosts = %+v", m.Hosts)
	}
	if len(m.Groups) != len(AuditGroups)+1 || !m.Groups[0].Selected {
		t.Errorf("groups = %+v", m.Groups)
	}

	empty := BuildAudit(AuditInput{Query: AuditQuery{Range: "7d"}, Now: now})
	if empty.Empty != "Nothing has been recorded yet." || empty.Filtered || empty.More != nil {
		t.Errorf("empty = %+v", empty)
	}
	empty = BuildAudit(AuditInput{Query: AuditQuery{Range: "7d", Q: "x"}, Now: now})
	if empty.Empty != "No entries match these filters." {
		t.Errorf("empty filtered = %q", empty.Empty)
	}
}
