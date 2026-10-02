package views

import (
	"crypto/x509"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/pki"
	"github.com/phabioo/nexara/internal/protocol"
)

// SettingsPage is the data of pages/settings.html: the cards of Settings in the
// order of the mockup (left column, then right column; one column on phones).
// A nil card pointer hides the card, because the service behind it is not
// available (tests, demo).
type SettingsPage struct {
	Layout
	Operators SettingsOperators
	Updates   *SettingsUpdates
	Backup    *SettingsBackup
	// HostCard, CertCard and DiagCard are not called Hosts, Certs and Diag: Layout already has a Hosts (the tabs).
	HostCard SettingsHosts
	CertCard SettingsCerts
	DiagCard SettingsDiag
	Audit    *SettingsAudit
}

// SettingsChoice is one chip of a choice (channel, log filter).
type SettingsChoice struct {
	Label string
	Value string
	On    bool
	URL   string // set for links (log filter)
}

// SettingsWhen renders a moment the way the mockup does: "Today 20:41",
// "Yesterday 03:00", "2 Oct 20:41", with the year for another year. t is shown
// in the time zone of now.
func SettingsWhen(now, t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	loc := now.Location()
	t = t.In(loc)
	ny, nm, nd := now.Date()
	yesterday := now.AddDate(0, 0, -1)
	yy, ym, yd := yesterday.Date()
	y, m, d := t.Date()
	clock := t.Format("15:04")
	switch {
	case y == ny && m == nm && d == nd:
		return "Today " + clock
	case y == yy && m == ym && d == yd:
		return "Yesterday " + clock
	case y == ny:
		return t.Format("2 Jan ") + clock
	}
	return t.Format("2 Jan 2006 ") + clock
}

// SettingsDate renders a calendar date: "30 Sep 2027".
func SettingsDate(now, t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	return t.In(now.Location()).Format("2 Jan 2006")
}

// SizeText renders a byte count: "2.1 MB".
func SizeText(n int64) string {
	s, err := formatBytes(n)
	if err != nil {
		return ""
	}
	return s
}

// VersionLabel prefixes a numeric version with "v": "0.2.0" -> "v0.2.0"; "dev" stays.
func VersionLabel(v string) string {
	v = strings.TrimSpace(v)
	if v != "" && v[0] >= '0' && v[0] <= '9' {
		return "v" + v
	}
	return v
}

func countText(n int, one, many string) string {
	return fmt.Sprintf("%d %s", n, plural(n, one, many))
}

// --- Operators ---

// SettingsOperators is the Operators card.
type SettingsOperators struct {
	ID            string
	Role          string
	TwoFactor     string
	TwoFactorOn   bool
	LastSignIn    string
	PassphraseURL string
}

// NewSettingsOperators builds the card for the signed-in operator. signedIn and
// ip come from the session the operator is using: it is the last sign-in.
func NewSettingsOperators(now time.Time, id string, totp bool, signedIn time.Time, ip string) SettingsOperators {
	o := SettingsOperators{ID: id, Role: "Owner", TwoFactor: "Not set up", TwoFactorOn: totp, PassphraseURL: "/settings/passphrase"}
	if totp {
		o.TwoFactor = "Enabled"
	}
	o.LastSignIn = SettingsWhen(now, signedIn)
	if ip != "" {
		o.LastSignIn += " · " + ip
	}
	return o
}

// PassphraseDialog is the data of the "Change passphrase" dialog.
type PassphraseDialog struct {
	PostURL string
	Error   string
}

// --- Hosts & capabilities ---

// Capabilities with a switch in v0.2 (decision #31: Power and Docker stay hidden).
var settingsSwitchable = []struct{ Key, Label string }{
	{protocol.CapShell, "Shell"},
	{protocol.CapPackages, "Packages"},
}

// SettingsCap is one capability chip of a host.
type SettingsCap struct {
	Key   string
	Label string
	// State is "on", "off" (offered but switched off in the hub) or
	// "unavailable" (the agent does not offer it).
	State   string
	Next    string // value of "enabled" the chip posts: "true" or "false"
	PostURL string // empty: read-only
}

// SettingsHost is one host row.
type SettingsHost struct {
	DomID     string
	Name      string
	Address   string
	Role      string
	Online    bool
	Caps      []SettingsCap
	Hint      string // why a chip is unavailable
	RemoveURL string // empty: not removable (the hub's own host)
}

// SettingsHosts is the Hosts & capabilities card.
type SettingsHosts struct {
	Tag   string
	Hosts []SettingsHost
}

func settingsDomID(id grid.HostID) string {
	var b strings.Builder
	for _, r := range string(id) {
		if r < unicode.MaxASCII && (unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_') {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	return "set-host-" + b.String()
}

// NewSettingsHost builds the row of one host. hubOwn marks the hub's own device; canSwitch is false when the
// hub cannot change capabilities (the chips are then read-only).
func NewSettingsHost(h grid.HostInfo, hubOwn, canSwitch bool, hostURL func(name string) string) SettingsHost {
	row := SettingsHost{DomID: settingsDomID(h.ID), Name: h.Name, Address: h.Address, Online: h.Online, Role: "Agent"}
	if h.DisplayName != "" {
		row.Name = h.DisplayName
	}
	if hubOwn {
		row.Role = "Hub + agent"
	} else {
		row.RemoveURL = hostURL(h.Name) + "/remove"
	}
	var missing []string
	for _, c := range settingsSwitchable {
		sc := SettingsCap{Key: c.Key, Label: c.Label}
		switch {
		case slices.Contains(h.Capabilities, c.Key):
			sc.State, sc.Next = "on", "false"
		case slices.Contains(h.DisabledCapabilities, c.Key):
			sc.State, sc.Next = "off", "true"
		default:
			sc.State = "unavailable"
			missing = append(missing, c.Label)
		}
		if canSwitch && sc.State != "unavailable" {
			sc.PostURL = hostURL(h.Name) + "/capabilities/" + c.Key
		}
		row.Caps = append(row.Caps, sc)
	}
	if len(missing) > 0 {
		row.Hint = "Not offered by this agent: " + strings.Join(missing, ", ") + ". Enable it in the agent's configuration (agent.yaml)."
	}
	return row
}

// NewSettingsHosts builds the card. settingsHostURL maps a host name to the URL of its settings actions.
func NewSettingsHosts(hosts []grid.HostInfo, isHub func(grid.HostInfo) bool, canSwitch bool, hostURL func(name string) string) SettingsHosts {
	out := SettingsHosts{Tag: "Nexara Grid · " + countText(len(hosts), "host", "hosts")}
	for _, h := range hosts {
		out.Hosts = append(out.Hosts, NewSettingsHost(h, isHub != nil && isHub(h), canSwitch, hostURL))
	}
	return out
}

// --- Certificates ---

// SettingsCertHost is the agent certificate of one host.
type SettingsCertHost struct {
	Name     string
	Until    string
	State    string // "valid", "due", "expired", "unknown"
	Online   bool
	RenewURL string // empty: cannot be renewed now (offline)
}

// SettingsCerts is the Certificates card.
type SettingsCerts struct {
	CA          string
	CAFull      string
	Hub         string
	Names       string
	Agents      string
	Hosts       []SettingsCertHost
	DownloadURL string
	OOB         bool // renders the card as an out-of-band swap
}

// shortFingerprint turns "4F:9A:12:C7:...:8E:C2" into "4F:9A:12:C7 … 8E:C2".
func shortFingerprint(full string) string {
	parts := strings.Split(full, ":")
	if len(parts) <= 6 {
		return full
	}
	return strings.Join(parts[:4], ":") + " … " + strings.Join(parts[len(parts)-2:], ":")
}

// certNames lists the DNS names, then the IP addresses of a certificate.
func certNames(c *x509.Certificate) []string {
	names := slices.Clone(c.DNSNames)
	for _, ip := range c.IPAddresses {
		names = append(names, ip.String())
	}
	return names
}

// NewSettingsCerts builds the card. ca and server may be nil; renewURL maps a host name to its renew action
// (nil: no renewing).
func NewSettingsCerts(now time.Time, ca, server *x509.Certificate, hosts []grid.HostInfo, renewURL func(name string) string) SettingsCerts {
	c := SettingsCerts{DownloadURL: "/grid/ca.crt", CA: "not available", Hub: "not available", Names: "not available"}
	if ca != nil {
		c.CAFull = pki.DisplayFingerprint(ca)
		c.CA = fmt.Sprintf("SHA-256 %s · until %d", shortFingerprint(c.CAFull), ca.NotAfter.In(now.Location()).Year())
	}
	if server != nil {
		c.Hub = "until " + SettingsDate(now, server.NotAfter) + " · auto-renew"
		if names := certNames(server); len(names) > 0 {
			c.Names = strings.Join(names, " · ")
		}
	}
	var valid, due, expired, unknown int
	for _, h := range hosts {
		row := SettingsCertHost{Name: h.Name, Online: h.Online}
		if h.DisplayName != "" {
			row.Name = h.DisplayName
		}
		switch {
		case h.CertNotAfter.IsZero():
			row.State, row.Until = "unknown", "unknown"
			unknown++
		case !h.CertNotAfter.After(now):
			row.State, row.Until = "expired", "expired "+SettingsDate(now, h.CertNotAfter)
			expired++
		case !now.Add(pki.RenewBefore).Before(h.CertNotAfter):
			row.State, row.Until = "due", "until "+SettingsDate(now, h.CertNotAfter)
			due++
			valid++
		default:
			row.State, row.Until = "valid", "until "+SettingsDate(now, h.CertNotAfter)
			valid++
		}
		if h.Online && renewURL != nil {
			row.RenewURL = renewURL(h.Name)
		}
		c.Hosts = append(c.Hosts, row)
	}
	c.Agents = fmt.Sprintf("%d valid · renew 30 days before expiry", valid)
	if due > 0 {
		c.Agents = fmt.Sprintf("%d valid · %d due for renewal", valid, due)
	}
	if expired > 0 {
		c.Agents += fmt.Sprintf(" · %d expired", expired)
	}
	if unknown > 0 {
		c.Agents += fmt.Sprintf(" · %d unknown", unknown)
	}
	return c
}

// --- Diagnostics ---

// SettingsDiag is the Diagnostics card.
type SettingsDiag struct {
	Text      string
	HubLogURL string // empty: no log source
}

// SettingsLogLine is one line of the log dialog.
type SettingsLogLine struct {
	Time  string
	Level string // "DEBUG", "INFO", "WARN", "ERROR"
	Class string // "is-debug", "is-info", "is-warn", "is-error"
	Text  string
}

// NewSettingsLogLine formats one log record. t is shown in the time zone of now; older days carry the date.
func NewSettingsLogLine(now, t time.Time, level slog.Level, text string) SettingsLogLine {
	t = t.In(now.Location())
	clock := t.Format("15:04:05")
	if y, m, d := t.Date(); y != now.Year() || m != now.Month() || d != now.Day() {
		clock = t.Format("2 Jan ") + clock
	}
	l := SettingsLogLine{Time: clock, Text: text}
	switch {
	case level >= slog.LevelError:
		l.Level, l.Class = "ERROR", "is-error"
	case level >= slog.LevelWarn:
		l.Level, l.Class = "WARN", "is-warn"
	case level >= slog.LevelInfo:
		l.Level, l.Class = "INFO", "is-info"
	default:
		l.Level, l.Class = "DEBUG", "is-debug"
	}
	return l
}

// SettingsLog is the data of the hub log dialog.
type SettingsLog struct {
	Lines   []SettingsLogLine
	Filters []SettingsChoice
	Shown   int
	Total   int // records that match the filter
	Limit   int
	Empty   string
}

// --- Audit log ---

// SettingsAuditRow is one line of the Audit log card.
type SettingsAuditRow struct {
	Time string
	Host string
	Text string
	Bad  bool
}

// SettingsAudit is the Audit log card: the newest entries and a link to all.
type SettingsAudit struct {
	Tag    string
	Rows   []SettingsAuditRow
	AllURL string
}

func auditClock(now, t time.Time) string {
	t = t.In(now.Location())
	if y, m, d := t.Date(); y == now.Year() && m == now.Month() && d == now.Day() {
		return t.Format("15:04:05")
	}
	return t.Format("2 Jan")
}

// AuditSentence phrases an audit entry for a person. Unknown actions show the action name.
func AuditSentence(e store.AuditEntry) string {
	who := e.User
	if who == "" {
		who = "system"
	}
	var s string
	switch e.Action {
	case "login":
		s = "Operator " + who + " signed in"
		if e.Result != store.AuditOK {
			s = "Sign-in failed for " + who
		}
	case "login.2fa":
		s = "Second factor for " + who
	case "login.locked":
		s = "Sign-in locked for " + who
	case "logout":
		s = "Operator " + who + " signed out"
	case "user.passphrase":
		s = "Operator " + who + " changed the passphrase"
	case "host.remove":
		s = "Host removed"
	case "host.capabilities":
		s = "Capability " + e.Detail
	case "backup.create":
		s = "Backup created"
	case "backup.download":
		s = "Backup downloaded"
	case "backup.restore":
		s = "Backup restored"
	case "update.check":
		s = "Update check"
	case "update.stage":
		s = "Update staged"
	case "update.request":
		s = "Update requested"
	case "update.apply":
		s = "Update applied"
	case "update.settings":
		s = "Update settings changed"
	case "cert.renew":
		s = "Certificate renewal requested"
	case "shell.open":
		s = "Shell opened by " + who
	case "shell.close":
		s = "Shell closed"
	default:
		s = e.Action
		if d := strings.TrimSpace(e.Detail); d != "" {
			if r := []rune(d); len(r) > 60 {
				d = string(r[:60]) + "…"
			}
			s += " · " + d
		}
	}
	switch e.Result {
	case store.AuditError:
		if e.Action != "login" {
			s += " (failed)"
		}
	case store.AuditDenied:
		s += " (denied)"
	}
	return s
}

// NewSettingsAudit builds the card from the newest entries (newest first).
func NewSettingsAudit(now time.Time, entries []store.AuditEntry) *SettingsAudit {
	a := &SettingsAudit{AllURL: "/settings/audit", Tag: "No entries yet"}
	if len(entries) > 0 {
		a.Tag = "Last " + countText(len(entries), "entry", "entries")
	}
	for _, e := range entries {
		host := e.Host
		if host == "" {
			host = "–"
		}
		a.Rows = append(a.Rows, SettingsAuditRow{
			Time: auditClock(now, e.Time), Host: host, Text: AuditSentence(e), Bad: e.Result != store.AuditOK,
		})
	}
	return a
}
