package views

import (
	"crypto/x509"
	"log/slog"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/backup"
	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/hub/update"
	"github.com/phabioo/nexara/internal/protocol"
)

var settingsNow = time.Date(2026, 10, 2, 20, 45, 0, 0, time.UTC)

func TestSettingsWhen(t *testing.T) {
	tests := []struct {
		name string
		t    time.Time
		want string
	}{
		{"zero", time.Time{}, "never"},
		{"today", time.Date(2026, 10, 2, 20, 41, 0, 0, time.UTC), "Today 20:41"},
		{"today early", time.Date(2026, 10, 2, 0, 5, 0, 0, time.UTC), "Today 00:05"},
		{"yesterday", time.Date(2026, 10, 1, 3, 0, 0, 0, time.UTC), "Yesterday 03:00"},
		{"this year", time.Date(2026, 9, 30, 23, 59, 0, 0, time.UTC), "30 Sep 23:59"},
		{"another year", time.Date(2025, 12, 31, 12, 0, 0, 0, time.UTC), "31 Dec 2025 12:00"},
		{"shown in the zone of now", time.Date(2026, 10, 2, 22, 30, 0, 0, time.FixedZone("x", 3600)), "Today 21:30"},
	}
	for _, tc := range tests {
		if got := SettingsWhen(settingsNow, tc.t); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
	if got := SettingsDate(settingsNow, time.Date(2027, 9, 30, 1, 0, 0, 0, time.UTC)); got != "30 Sep 2027" {
		t.Errorf("SettingsDate = %q", got)
	}
	if got := SettingsDate(settingsNow, time.Time{}); got != "unknown" {
		t.Errorf("SettingsDate(zero) = %q", got)
	}
}

func TestNewSettingsOperators(t *testing.T) {
	tests := []struct {
		totp   bool
		ip     string
		want2f string
		wantIn string
	}{
		{true, "192.168.10.44", "Enabled", "Today 20:41 · 192.168.10.44"},
		{false, "", "Not set up", "Today 20:41"},
	}
	for _, tc := range tests {
		o := NewSettingsOperators(settingsNow, "fabio", tc.totp, time.Date(2026, 10, 2, 20, 41, 0, 0, time.UTC), tc.ip)
		if o.ID != "fabio" || o.Role != "Owner" || o.TwoFactor != tc.want2f || o.LastSignIn != tc.wantIn || o.PassphraseURL != "/settings/passphrase" {
			t.Errorf("%+v", o)
		}
	}
}

func hostURLFn(name string) string { return "/settings/hosts/" + name }

func TestNewSettingsHost(t *testing.T) {
	tests := []struct {
		name      string
		h         grid.HostInfo
		hub       bool
		canSwitch bool
		caps      map[string]string // key -> state
		next      map[string]string
		urls      bool
		hint      string
		role      string
		remove    bool
	}{
		{
			name: "both on", h: grid.HostInfo{ID: "a1", Name: "pi5", Capabilities: []string{protocol.CapMonitoring, protocol.CapShell, protocol.CapPackages}},
			canSwitch: true, caps: map[string]string{"shell": "on", "packages": "on"}, next: map[string]string{"shell": "false", "packages": "false"},
			urls: true, role: "Agent", remove: true,
		},
		{
			name: "shell switched off", h: grid.HostInfo{ID: "a1", Name: "pi5", Capabilities: []string{protocol.CapPackages}, DisabledCapabilities: []string{protocol.CapShell}},
			canSwitch: true, caps: map[string]string{"shell": "off", "packages": "on"}, next: map[string]string{"shell": "true", "packages": "false"},
			urls: true, role: "Agent", remove: true,
		},
		{
			name: "the agent has no packages", h: grid.HostInfo{ID: "a1", Name: "pi5", Capabilities: []string{protocol.CapShell}},
			canSwitch: true, caps: map[string]string{"shell": "on", "packages": "unavailable"}, next: map[string]string{"shell": "false"}, urls: true,
			hint: "Not offered by this agent: Packages", role: "Agent", remove: true,
		},
		{
			name: "no controller: nothing can be pressed", h: grid.HostInfo{ID: "a1", Name: "pi5", Capabilities: []string{protocol.CapShell, protocol.CapPackages}},
			canSwitch: false, caps: map[string]string{"shell": "on", "packages": "on"}, next: map[string]string{"shell": "false", "packages": "false"}, role: "Agent", remove: true,
		},
		{
			name: "the hub's own host cannot be removed here", h: grid.HostInfo{ID: "a1", Name: "frpi5", DisplayName: "Frpi5", Capabilities: []string{protocol.CapShell, protocol.CapPackages}},
			hub: true, canSwitch: true, caps: map[string]string{"shell": "on", "packages": "on"}, next: map[string]string{"shell": "false", "packages": "false"}, urls: true, role: "Hub + agent",
		},
		{
			name: "power and docker are never shown", h: grid.HostInfo{ID: "a1", Name: "x", Capabilities: []string{protocol.CapShell, protocol.CapPower, protocol.CapDocker}},
			canSwitch: true, caps: map[string]string{"shell": "on", "packages": "unavailable"}, next: map[string]string{"shell": "false"}, urls: true, hint: "Packages", role: "Agent", remove: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			row := NewSettingsHost(tc.h, tc.hub, tc.canSwitch, hostURLFn)
			if len(row.Caps) != 2 || row.Caps[0].Key != "shell" || row.Caps[1].Key != "packages" {
				t.Fatalf("caps = %+v", row.Caps)
			}
			for _, c := range row.Caps {
				if c.State != tc.caps[c.Key] {
					t.Errorf("%s state %q, want %q", c.Key, c.State, tc.caps[c.Key])
				}
				if c.Next != tc.next[c.Key] {
					t.Errorf("%s next %q, want %q", c.Key, c.Next, tc.next[c.Key])
				}
				if (c.PostURL != "") != (tc.urls && c.State != "unavailable") || (c.State == "unavailable" && c.PostURL != "") {
					t.Errorf("%s PostURL %q", c.Key, c.PostURL)
				}
				if c.PostURL != "" && c.PostURL != "/settings/hosts/"+tc.h.Name+"/capabilities/"+c.Key {
					t.Errorf("%s PostURL %q", c.Key, c.PostURL)
				}
			}
			if !strings.Contains(row.Hint, tc.hint) || (tc.hint == "") != (row.Hint == "") {
				t.Errorf("hint %q, want %q", row.Hint, tc.hint)
			}
			if row.Role != tc.role || (row.RemoveURL != "") != tc.remove || row.DomID != "set-host-a1" {
				t.Errorf("row = %+v", row)
			}
		})
	}
	if got := settingsDomID("a b/<x>"); got != "set-host-a-b--x-" {
		t.Errorf("settingsDomID = %q", got)
	}
}

func TestNewSettingsHosts(t *testing.T) {
	hosts := []grid.HostInfo{{ID: "a", Name: "one"}, {ID: "b", Name: "two"}}
	c := NewSettingsHosts(hosts, func(h grid.HostInfo) bool { return h.Name == "one" }, true, hostURLFn)
	if c.Tag != "Nexara Grid · 2 hosts" || len(c.Hosts) != 2 || c.Hosts[0].Role != "Hub + agent" || c.Hosts[1].Role != "Agent" {
		t.Errorf("%+v", c)
	}
	if c := NewSettingsHosts(hosts[:1], nil, true, hostURLFn); c.Tag != "Nexara Grid · 1 host" || c.Hosts[0].Role != "Agent" {
		t.Errorf("one host without a hub predicate: %+v", c)
	}
}

func certAt(notAfter time.Time, dns []string, ips ...string) *x509.Certificate {
	c := &x509.Certificate{NotAfter: notAfter, DNSNames: dns, Raw: []byte("raw certificate")}
	for _, ip := range ips {
		c.IPAddresses = append(c.IPAddresses, net.ParseIP(ip))
	}
	return c
}

func TestNewSettingsCerts(t *testing.T) {
	day := 24 * time.Hour
	ca := certAt(time.Date(2031, 10, 1, 0, 0, 0, 0, time.UTC), nil)
	server := certAt(time.Date(2027, 9, 30, 0, 0, 0, 0, time.UTC), []string{"frpi5", "frpi5.local"}, "192.168.10.21")
	tests := []struct {
		name   string
		hosts  []grid.HostInfo
		agents string
		states []string
		renew  []bool
	}{
		{"all valid", []grid.HostInfo{
			{Name: "a", Online: true, CertNotAfter: settingsNow.Add(200 * day)}, {Name: "b", Online: true, CertNotAfter: settingsNow.Add(100 * day)},
		}, "2 valid · renew 30 days before expiry", []string{"valid", "valid"}, []bool{true, true}},
		{"one due, one offline", []grid.HostInfo{
			{Name: "a", Online: true, CertNotAfter: settingsNow.Add(29 * day)}, {Name: "b", Online: false, CertNotAfter: settingsNow.Add(100 * day)},
		}, "2 valid · 1 due for renewal", []string{"due", "valid"}, []bool{true, false}},
		{"expired and unknown", []grid.HostInfo{
			{Name: "a", Online: true, CertNotAfter: settingsNow.Add(-day)}, {Name: "b", Online: true},
		}, "0 valid · renew 30 days before expiry · 1 expired · 1 unknown", []string{"expired", "unknown"}, []bool{true, true}},
		{"no hosts", nil, "0 valid · renew 30 days before expiry", nil, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := NewSettingsCerts(settingsNow, ca, server, tc.hosts, func(n string) string { return "/settings/certs/" + n + "/renew" })
			if c.Agents != tc.agents {
				t.Errorf("Agents = %q, want %q", c.Agents, tc.agents)
			}
			for i, h := range c.Hosts {
				if h.State != tc.states[i] {
					t.Errorf("%s state %q, want %q", h.Name, h.State, tc.states[i])
				}
				if (h.RenewURL != "") != tc.renew[i] {
					t.Errorf("%s RenewURL %q, online %v", h.Name, h.RenewURL, h.Online)
				}
			}
			if c.Hub != "until 30 Sep 2027 · auto-renew" || c.Names != "frpi5 · frpi5.local · 192.168.10.21" || c.DownloadURL != "/grid/ca.crt" {
				t.Errorf("%+v", c)
			}
			if !strings.HasPrefix(c.CA, "SHA-256 ") || !strings.HasSuffix(c.CA, " · until 2031") || !strings.Contains(c.CA, " … ") || len(c.CAFull) != 32*3-1 {
				t.Errorf("CA = %q (full %q)", c.CA, c.CAFull)
			}
		})
	}
	// Without certificates (the demo, a broken file) the rows say so and renewing is not offered.
	c := NewSettingsCerts(settingsNow, nil, nil, []grid.HostInfo{{Name: "a", Online: true, CertNotAfter: settingsNow.Add(100 * day)}}, nil)
	if c.CA != "not available" || c.Hub != "not available" || c.Names != "not available" || c.Hosts[0].RenewURL != "" {
		t.Errorf("%+v", c)
	}
}

func TestShortFingerprint(t *testing.T) {
	full := "4F:9A:12:C7:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:8E:C2"
	if got := shortFingerprint(full); got != "4F:9A:12:C7 … 8E:C2" {
		t.Errorf("%q", got)
	}
	if got := shortFingerprint("AA:BB"); got != "AA:BB" {
		t.Errorf("%q", got)
	}
}

// The actions the Settings view writes read as sentences, not as the generic fallback.
func TestAuditSentencesForSettingsActions(t *testing.T) {
	tests := []struct {
		e    store.AuditEntry
		want string
	}{
		{store.AuditEntry{User: "fabio", Action: "user.passphrase", Result: store.AuditOK}, "Operator fabio changed the passphrase"},
		{store.AuditEntry{User: "fabio", Action: "user.passphrase", Result: store.AuditDenied}, "Passphrase change refused for fabio"},
		{store.AuditEntry{User: "fabio", Action: "user.totp_enroll", Result: store.AuditOK}, "Operator fabio set up two-factor login"},
		{store.AuditEntry{User: "fabio", Host: "pi4", Action: "host.capabilities", Detail: "shell off", Result: store.AuditOK}, "Capability on pi4: shell off"},
		{store.AuditEntry{User: "fabio", Action: "backup.schedule", Detail: "time=03:00 keep=7", Result: store.AuditOK}, "Operator fabio changed the backup schedule (time=03:00 keep=7)"},
	}
	for _, tc := range tests {
		if got := FormatAudit(tc.e); got != tc.want {
			t.Errorf("%+v: %q, want %q", tc.e, got, tc.want)
		}
	}
}

func TestNewSettingsAudit(t *testing.T) {
	a := NewSettingsAudit(settingsNow, nil)
	if a.Tag != "No entries yet" || len(a.Rows) != 0 || a.AllURL != "/settings/audit" {
		t.Errorf("%+v", a)
	}
	a = NewSettingsAudit(settingsNow, []store.AuditEntry{
		{Time: time.Date(2026, 10, 2, 20, 41, 12, 0, time.UTC), User: "fabio", Action: "login", Result: store.AuditOK},
		{Time: time.Date(2026, 9, 30, 3, 0, 0, 0, time.UTC), Host: "pi5", Action: "backup.create", Result: store.AuditError},
	})
	if a.Tag != "Last 2 entries" || len(a.Rows) != 2 {
		t.Fatalf("%+v", a)
	}
	if r := a.Rows[0]; r.Time != "20:41:12" || r.Host != "–" || r.Text != "Operator fabio signed in" || r.Bad {
		t.Errorf("row 0 = %+v", r)
	}
	if r := a.Rows[1]; r.Time != "30 Sep" || r.Host != "pi5" || !r.Bad {
		t.Errorf("row 1 = %+v", r)
	}
	if got := NewSettingsAudit(settingsNow, []store.AuditEntry{{Action: "x", Result: "ok"}}).Tag; got != "Last 1 entry" {
		t.Errorf("tag = %q", got)
	}
}

func TestNewSettingsLogLine(t *testing.T) {
	tests := []struct {
		level slog.Level
		t     time.Time
		lvl   string
		class string
		clock string
	}{
		{slog.LevelError, settingsNow, "ERROR", "is-error", "20:45:00"},
		{slog.LevelWarn + 1, settingsNow, "WARN", "is-warn", "20:45:00"},
		{slog.LevelInfo, settingsNow, "INFO", "is-info", "20:45:00"},
		{slog.LevelDebug, settingsNow, "DEBUG", "is-debug", "20:45:00"},
		{slog.LevelInfo, settingsNow.Add(-48 * time.Hour), "INFO", "is-info", "30 Sep 20:45:00"},
	}
	for _, tc := range tests {
		l := NewSettingsLogLine(settingsNow, tc.t, tc.level, "text")
		if l.Level != tc.lvl || l.Class != tc.class || l.Time != tc.clock || l.Text != "text" {
			t.Errorf("%v: %+v", tc.level, l)
		}
	}
}

func TestNewSettingsBackup(t *testing.T) {
	infos := []backup.Info{
		{Name: "nexus-b.nxbk", CreatedAt: settingsNow.Add(-17*time.Hour - 45*time.Minute), Reason: backup.ReasonNightly, Size: 2_200_000, Readable: true},
		{Name: "nexus-a.nxbk", CreatedAt: settingsNow.Add(-40 * time.Hour), Reason: backup.ReasonPreUpdate, Size: 1_000, Readable: false},
		{Name: "nexus-c.nxbk", CreatedAt: settingsNow.Add(-50 * time.Hour), Reason: "odd", Size: 10, Readable: true},
	}
	b := NewSettingsBackup(settingsNow, backup.Schedule{Time: "03:00", Keep: 7}, infos, true)
	if b.Schedule != "Nightly 03:00 · keeps 7 · before updates" || b.Time != "03:00" || b.Keep != 7 || b.Last != "Today 03:00 · 2.1 MB" {
		t.Errorf("%+v", b)
	}
	want := []struct{ reason, restore string }{
		{"Nightly", "/settings/backup/restore?name=nexus-b.nxbk"}, {"Before update", ""}, {"Odd", "/settings/backup/restore?name=nexus-c.nxbk"},
	}
	for i, w := range want {
		if b.Backups[i].Reason != w.reason || b.Backups[i].RestoreURL != w.restore {
			t.Errorf("row %d = %+v", i, b.Backups[i])
		}
	}
	// An unreadable backup (made with another hub's key) is listed but never restorable.
	if b.Backups[1].Readable {
		t.Error("unreadable backup reported readable")
	}
	b = NewSettingsBackup(settingsNow, backup.Schedule{Time: "01:30", Keep: 1}, infos, false)
	for _, r := range b.Backups {
		if r.RestoreURL != "" {
			t.Errorf("restore offered without a restart service: %+v", r)
		}
	}
	if b := NewSettingsBackup(settingsNow, backup.Schedule{Time: "03:00", Keep: 7}, nil, true); b.Last != "No backup yet" || len(b.Backups) != 0 {
		t.Errorf("%+v", b)
	}
}

func TestNewBackupRestoreConfirm(t *testing.T) {
	c := NewBackupRestoreConfirm(settingsNow, backup.Info{Name: "n.nxbk", CreatedAt: settingsNow.Add(-time.Hour), Reason: backup.ReasonManual})
	if c.Name != "n.nxbk" || c.When != "Today 19:45" || c.Reason != "Manual" || c.PostURL != "/settings/backup/restore" {
		t.Errorf("%+v", c)
	}
	if got := RestartPollURL("abc"); got != "/settings/restart?boot=abc" {
		t.Errorf("RestartPollURL = %q", got)
	}
}

func updStatus(mod func(*update.Status)) update.Status {
	st := update.Status{Current: "0.1.0", Arch: "arm64", Supported: true, Config: update.Config{Channel: update.ChannelStable}}
	if mod != nil {
		mod(&st)
	}
	return st
}

func TestNewSettingsUpdatesTag(t *testing.T) {
	hosts := []grid.HostInfo{{AgentVersion: "0.1.0"}, {AgentVersion: "v0.1.0"}, {AgentVersion: "0.0.9"}}
	latest := &update.Release{Version: "0.2.0", PublishedAt: time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC), URL: "https://github.com/phabioo/nexara/releases/tag/v0.2.0"}
	tests := []struct {
		name string
		mod  func(*update.Status)
		tag  string
		tone string
	}{
		{"nothing known", nil, "Manual updates", "light"},
		{"up to date", func(s *update.Status) {
			s.Config.CheckGitHub = true
			s.Check = &update.CheckResult{CheckedAt: settingsNow.Add(-5 * time.Minute)}
		}, "Up to date", "lime"},
		{"update available", func(s *update.Status) {
			s.Config.CheckGitHub = true
			s.Check = &update.CheckResult{CheckedAt: settingsNow, Latest: latest, UpdateAvailable: true}
		}, "Update available · v0.2.0", "lime"},
		{"a failed check is not 'up to date'", func(s *update.Status) {
			s.Config.CheckGitHub = true
			s.Check = &update.CheckResult{CheckedAt: settingsNow, Error: "boom"}
		}, "Manual updates", "light"},
		{"staged wins over available", func(s *update.Status) {
			s.Config.CheckGitHub = true
			s.Check = &update.CheckResult{CheckedAt: settingsNow, Latest: latest, UpdateAvailable: true}
			s.Staged = []update.Staged{{Version: "0.2.0", Size: 48_000_000, StagedAt: settingsNow, Source: update.SourceUpload}}
		}, "v0.2.0 ready to install", "lime"},
		{"installing wins over everything", func(s *update.Status) {
			s.Staged = []update.Staged{{Version: "0.2.0"}}
			s.Installing = &update.Installing{Version: "0.2.0", Phase: update.PhaseBackup, Since: settingsNow}
		}, "Installing v0.2.0", "lime"},
		{"a stalled update does not claim to install", func(s *update.Status) {
			s.Installing = &update.Installing{Version: "0.2.0", Phase: update.PhaseQueued, Since: settingsNow, Stale: true}
		}, "Manual updates", "light"},
		{"last update failed", func(s *update.Status) {
			s.Last = &update.Result{Status: update.StatusError, Message: "x", FinishedAt: settingsNow}
		}, "Last update failed", "bad"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u := NewSettingsUpdates(settingsNow, updStatus(tc.mod), hosts)
			if u.Tag != tc.tag || u.TagTone != tc.tone {
				t.Errorf("tag %q (%s), want %q (%s)", u.Tag, u.TagTone, tc.tag, tc.tone)
			}
			if u.Hub != "v0.1.0 · linux/arm64" || u.Agents != "2/3 on v0.1.0 · auto-update on" {
				t.Errorf("hub %q, agents %q", u.Hub, u.Agents)
			}
		})
	}
}

func TestNewSettingsUpdatesDetails(t *testing.T) {
	// A development build: no numeric version, no auto-update.
	u := NewSettingsUpdates(settingsNow, updStatus(func(s *update.Status) { s.Current = "dev" }), []grid.HostInfo{{AgentVersion: "dev"}})
	if u.Hub != "dev · linux/arm64" || u.Agents != "1/1 on dev · auto-update off (development build)" {
		t.Errorf("%q / %q", u.Hub, u.Agents)
	}
	// The channel chips follow the switch.
	u = NewSettingsUpdates(settingsNow, updStatus(nil), nil)
	if u.CheckOn || len(u.Channels) != 0 {
		t.Errorf("channels while the check is off: %+v", u.Channels)
	}
	u = NewSettingsUpdates(settingsNow, updStatus(func(s *update.Status) { s.Config.CheckGitHub, s.Config.Channel = true, update.ChannelRC }), nil)
	if len(u.Channels) != 2 || u.Channels[0].On || !u.Channels[1].On || u.Channels[1].Value != "rc" {
		t.Errorf("channels = %+v", u.Channels)
	}
	// Check notes.
	u = NewSettingsUpdates(settingsNow, updStatus(func(s *update.Status) {
		s.Config.CheckGitHub = true
		s.Check = &update.CheckResult{CheckedAt: settingsNow.Add(-2 * time.Hour), Error: "GitHub answered 403"}
	}), nil)
	if u.CheckNote != "Last check failed: GitHub answered 403" || !u.CheckFailed {
		t.Errorf("note %q failed %v", u.CheckNote, u.CheckFailed)
	}
	u = NewSettingsUpdates(settingsNow, updStatus(func(s *update.Status) {
		s.Config.CheckGitHub = true
		s.Check = &update.CheckResult{CheckedAt: settingsNow.Add(-2 * time.Hour)}
	}), nil)
	if u.CheckNote != "Checked 2 h ago" {
		t.Errorf("note %q", u.CheckNote)
	}
	// A release that is already staged is not offered for download again.
	u = NewSettingsUpdates(settingsNow, updStatus(func(s *update.Status) {
		s.Config.CheckGitHub = true
		s.Check = &update.CheckResult{CheckedAt: settingsNow, UpdateAvailable: true, Latest: &update.Release{Version: "0.2.0"}}
		s.Staged = []update.Staged{{Version: "0.2.0", Size: 2_100_000, StagedAt: settingsNow, Source: update.SourceGitHub}}
	}), nil)
	if u.Latest == nil || !u.Latest.Staged || len(u.Staged) != 1 || u.Staged[0].Detail != "2 MB · downloaded Today 20:45" || u.Staged[0].InstallURL != "/settings/updates/install?version=0.2.0" {
		t.Errorf("latest %+v staged %+v", u.Latest, u.Staged)
	}
	// Busy and polling follow the helper.
	u = NewSettingsUpdates(settingsNow, updStatus(func(s *update.Status) {
		s.Installing = &update.Installing{Version: "0.2.0", Phase: update.PhaseQueued, Since: settingsNow}
	}), nil)
	if !u.Busy || !u.Poll || u.Installing.CancelURL == "" {
		t.Errorf("queued: busy %v poll %v cancel %q", u.Busy, u.Poll, u.Installing.CancelURL)
	}
	u = NewSettingsUpdates(settingsNow, updStatus(func(s *update.Status) {
		s.Installing = &update.Installing{Version: "0.2.0", Phase: update.PhaseInstall, Since: settingsNow}
	}), nil)
	if !u.Busy || !u.Poll || u.Installing.CancelURL != "" {
		t.Errorf("running: busy %v poll %v cancel %q", u.Busy, u.Poll, u.Installing.CancelURL)
	}
	u = NewSettingsUpdates(settingsNow, updStatus(func(s *update.Status) {
		s.Installing = &update.Installing{Version: "0.2.0", Phase: update.PhaseInstall, Since: settingsNow, Stale: true}
	}), nil)
	if u.Busy || u.Poll {
		t.Errorf("stalled: busy %v poll %v", u.Busy, u.Poll)
	}
	if u := NewSettingsUpdates(settingsNow, updStatus(func(s *update.Status) { s.Supported = false }), nil); u.CanInstall {
		t.Error("CanInstall without a helper")
	}
}

func TestInstallProgress(t *testing.T) {
	states := func(phase string) []string {
		var out []string
		for _, s := range installProgress(phase) {
			out = append(out, s.State)
		}
		return out
	}
	tests := []struct {
		phase string
		want  []string
	}{
		{update.PhaseQueued, []string{"run", "wait", "wait", "wait", "wait"}},
		{update.PhaseVerify, []string{"done", "run", "wait", "wait", "wait"}},
		{update.PhaseBackup, []string{"done", "done", "run", "wait", "wait"}},
		{update.PhaseInstall, []string{"done", "done", "done", "run", "wait"}},
		{update.PhaseHealth, []string{"done", "done", "done", "done", "run"}},
		{update.PhaseRollback, []string{"done", "done", "done", "done", "bad", "run"}},
		{"unknown phase", []string{"run", "wait", "wait", "wait", "wait"}},
	}
	for _, tc := range tests {
		if got := states(tc.phase); !slices.Equal(got, tc.want) {
			t.Errorf("%s: %v, want %v", tc.phase, got, tc.want)
		}
	}
}

func TestNewSettingsInstallConfirm(t *testing.T) {
	st := updStatus(func(s *update.Status) {
		s.Staged = []update.Staged{{Version: "0.2.0", Size: 48_000_000, StagedAt: settingsNow}, {Version: "0.0.5", Size: 10, StagedAt: settingsNow}}
	})
	c, ok := NewSettingsInstallConfirm(settingsNow, st, "0.2.0")
	if !ok || c.Version != "v0.2.0" || c.Version0 != "0.2.0" || c.Current != "v0.1.0" || c.PostURL != "/settings/updates/install" || c.Older || !strings.Contains(c.Detail, "MB") {
		t.Errorf("%+v %v", c, ok)
	}
	if c, ok := NewSettingsInstallConfirm(settingsNow, st, "0.0.5"); !ok || !c.Older {
		t.Errorf("older version: %+v %v", c, ok)
	}
	for _, v := range []string{"", "0.3.0", "../x"} {
		if _, ok := NewSettingsInstallConfirm(settingsNow, st, v); ok {
			t.Errorf("%q accepted", v)
		}
	}
}

func TestTailText(t *testing.T) {
	if got := tailText("  short  ", 100); got != "short" {
		t.Errorf("%q", got)
	}
	long := "first line\nsecond line\nthird line"
	if got := tailText(long, 20); got != "…\nthird line" {
		t.Errorf("%q", got)
	}
}
