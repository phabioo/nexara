package views

import (
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/phabioo/nexara/internal/hub/store"
)

// Query limits and defaults of the audit log view.
const (
	AuditQueryMax = 64
	AuditPageSize = 100

	AuditRangeAll     = "all"
	auditDefaultRange = "7d"
)

// AuditGroup is an action group of the filter: exact action names and name prefixes.
type AuditGroup struct {
	Key      string
	Label    string
	Actions  []string
	Prefixes []string
}

// AuditGroups are the action groups, in display order. Every action the hub
// writes belongs to at most one group; actions without a group (for example
// "audit.prune") show up only in the unfiltered list.
var AuditGroups = []AuditGroup{
	{Key: "signin", Label: "Sign-in", Actions: []string{"login", "login.locked", "login.2fa", "logout", "user.reset", "admin.user_reset", "admin.login_unlock"}},
	{Key: "setup", Label: "Setup", Actions: []string{"admin.setup_code"}, Prefixes: []string{"setup."}},
	{Key: "hosts", Label: "Hosts", Actions: []string{"agent.update"}, Prefixes: []string{"host.", "enroll."}},
	{Key: "packages", Label: "Packages & jobs", Prefixes: []string{"job."}},
	{Key: "shell", Label: "Shell", Prefixes: []string{"shell."}},
	{Key: "services", Label: "Services", Prefixes: []string{"service."}},
	{Key: "certs", Label: "Certificates", Prefixes: []string{"cert."}},
	{Key: "backup", Label: "Backup", Prefixes: []string{"backup."}},
	{Key: "updates", Label: "Updates", Prefixes: []string{"update."}},
}

var auditRanges = []struct {
	Key, Label string
	D          time.Duration
}{
	{"24h", "24 h", 24 * time.Hour},
	{"7d", "7 d", 7 * 24 * time.Hour},
	{"30d", "30 d", 30 * 24 * time.Hour},
	{AuditRangeAll, "All", 0},
}

var auditResults = []struct{ Key, Label string }{
	{"", "All"},
	{store.AuditOK, "OK"},
	{store.AuditError, "Error"},
	{store.AuditDenied, "Denied"},
}

// AuditQuery is the normalized filter of the audit view (the URL query).
type AuditQuery struct {
	Host, User string
	Group      string // key of AuditGroups, "" = all
	Result     string // "", ok, error, denied
	Range      string // 24h, 7d, 30d, all
	Q          string // search term (detail)
	Cursor     string
}

func clampTerm(s string, max int) string {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > max {
		s = string([]rune(s)[:max])
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

// ParseAuditQuery normalizes the URL query: unknown values fall back to the defaults.
func ParseAuditQuery(v url.Values) AuditQuery {
	q := AuditQuery{
		Host:   clampTerm(v.Get("host"), 128),
		User:   clampTerm(v.Get("user"), 128),
		Q:      clampTerm(v.Get("q"), AuditQueryMax),
		Cursor: clampTerm(v.Get("cursor"), 48),
		Range:  auditDefaultRange,
	}
	if _, ok := LookupAuditGroup(v.Get("group")); ok {
		q.Group = v.Get("group")
	}
	switch r := v.Get("result"); r {
	case store.AuditOK, store.AuditError, store.AuditDenied:
		q.Result = r
	}
	for _, r := range auditRanges {
		if r.Key == v.Get("range") {
			q.Range = r.Key
		}
	}
	return q
}

// LookupAuditGroup returns the group with the given key.
func LookupAuditGroup(key string) (AuditGroup, bool) {
	for _, g := range AuditGroups {
		if g.Key == key {
			return g, true
		}
	}
	return AuditGroup{}, false
}

// Values encodes the filter without the cursor; defaults are left out.
func (q AuditQuery) Values() url.Values {
	v := url.Values{}
	set := func(k, s string) {
		if s != "" {
			v.Set(k, s)
		}
	}
	set("host", q.Host)
	set("user", q.User)
	set("group", q.Group)
	set("result", q.Result)
	if q.Range != auditDefaultRange {
		set("range", q.Range)
	}
	set("q", q.Q)
	return v
}

// Filter turns the query into a store filter. now anchors the time range.
func (q AuditQuery) Filter(now time.Time, limit int) store.AuditFilter {
	f := store.AuditFilter{Host: q.Host, User: q.User, Result: q.Result, Search: q.Q, Cursor: q.Cursor, Limit: limit}
	if g, ok := LookupAuditGroup(q.Group); ok {
		f.Actions, f.ActionPrefixes = g.Actions, g.Prefixes
	}
	for _, r := range auditRanges {
		if r.Key == q.Range && r.D > 0 {
			f.Since = now.Add(-r.D)
		}
	}
	return f
}

// auditURL is path plus the query string of v.
func auditURL(path string, v url.Values) string {
	if len(v) == 0 {
		return path
	}
	return path + "?" + v.Encode()
}

// AuditOption is one <option> or radio of the filter bar.
type AuditOption struct {
	Value, Label string
	Selected     bool
}

// AuditRow is one entry of the list.
type AuditRow struct {
	Day      string // set on the first row of a day: "Today", "Yesterday" or a date
	Time     string // 15:04:05
	FullTime string // RFC 3339 in the display zone
	Host     string // "—" when the entry belongs to no host
	Text     string // the sentence
	Result   string // ok, error, denied
	Tag      string // "Error" / "Denied"; empty for ok
	TagClass string
	Action   string
	User     string
	Detail   string
}

// AuditMore is the "Show more" button below a full page.
type AuditMore struct{ URL string }

// AuditModel feeds pages/audit.html and the audit-* partials.
type AuditModel struct {
	Q         AuditQuery
	Rows      []AuditRow
	Hosts     []AuditOption
	Users     []AuditOption
	Groups    []AuditOption
	Ranges    []AuditOption
	Results   []AuditOption
	More      *AuditMore
	Empty     string
	Filtered  bool
	ExportURL string
	ResetURL  string
	Shown     int
}

// AuditInput is what BuildAudit needs.
type AuditInput struct {
	Query   AuditQuery
	Entries []store.AuditEntry
	Next    string
	Hosts   []string
	Users   []string
	Now     time.Time
	Loc     *time.Location
}

// BuildAudit builds the view model for one page of entries.
func BuildAudit(in AuditInput) AuditModel {
	loc := in.Loc
	if loc == nil {
		loc = time.UTC
	}
	q := in.Query
	m := AuditModel{Q: q, ResetURL: "/settings/audit"}
	m.Filtered = q.Host != "" || q.User != "" || q.Group != "" || q.Result != "" || q.Q != "" || q.Range != auditDefaultRange
	base := q.Values()
	m.ExportURL = auditURL("/settings/audit.csv", base)

	lastDay := ""
	for _, e := range in.Entries {
		t := e.Time.In(loc)
		row := AuditRow{
			Time: t.Format("15:04:05"), FullTime: t.Format("2006-01-02 15:04:05 MST"),
			Host: e.Host, Text: FormatAudit(e), Result: e.Result, Action: e.Action, User: e.User, Detail: e.Detail,
		}
		if row.Host == "" {
			row.Host = "—"
		}
		switch e.Result {
		case store.AuditError:
			row.Tag, row.TagClass = "Error", "tag-bad"
		case store.AuditDenied:
			row.Tag, row.TagClass = "Denied", "tag-dark"
		}
		if day := auditDayLabel(t, in.Now.In(loc)); day != lastDay {
			row.Day, lastDay = day, day
		}
		m.Rows = append(m.Rows, row)
	}
	m.Shown = len(m.Rows)
	if in.Next != "" {
		v := q.Values()
		v.Set("cursor", in.Next)
		m.More = &AuditMore{URL: auditURL("/settings/audit", v)}
	}
	switch {
	case len(m.Rows) > 0:
	case m.Filtered:
		m.Empty = "No entries match these filters."
	default:
		m.Empty = "Nothing has been recorded yet."
	}

	m.Hosts = auditValueOptions("All hosts", q.Host, in.Hosts)
	m.Users = auditValueOptions("All operators", q.User, in.Users)
	m.Groups = append(m.Groups, AuditOption{Value: "", Label: "All actions", Selected: q.Group == ""})
	for _, g := range AuditGroups {
		m.Groups = append(m.Groups, AuditOption{Value: g.Key, Label: g.Label, Selected: g.Key == q.Group})
	}
	for _, r := range auditRanges {
		m.Ranges = append(m.Ranges, AuditOption{Value: r.Key, Label: r.Label, Selected: r.Key == q.Range})
	}
	for _, r := range auditResults {
		m.Results = append(m.Results, AuditOption{Value: r.Key, Label: r.Label, Selected: r.Key == q.Result})
	}
	return m
}

// auditValueOptions lists "all" plus the known values; a selected value that
// is not known (an old URL) stays selectable.
func auditValueOptions(all, selected string, values []string) []AuditOption {
	opts := []AuditOption{{Value: "", Label: all, Selected: selected == ""}}
	found := selected == ""
	for _, v := range values {
		opts = append(opts, AuditOption{Value: v, Label: v, Selected: v == selected})
		if v == selected {
			found = true
		}
	}
	if !found {
		opts = append(opts, AuditOption{Value: selected, Label: selected, Selected: true})
	}
	return opts
}

func auditDayLabel(t, now time.Time) string {
	y, m, d := t.Date()
	ny, nm, nd := now.Date()
	switch {
	case y == ny && m == nm && d == nd:
		return "Today"
	case t.AddDate(0, 0, 1).Format("2006-01-02") == now.Format("2006-01-02"):
		return "Yesterday"
	}
	return t.Format("Mon 02 Jan 2006")
}

// --- sentences -------------------------------------------------------------------

// detailKV reads "key=value" words of a detail string ("ip=192.0.2.1 reason=bad_code").
func detailKV(detail string) map[string]string {
	kv := map[string]string{}
	for _, w := range strings.Fields(detail) {
		if k, v, ok := strings.Cut(w, "="); ok && k != "" {
			kv[k] = v
		}
	}
	return kv
}

func auditWho(e store.AuditEntry) string {
	switch e.User {
	case "", "system":
		return "The hub"
	}
	return "Operator " + e.User
}

func auditHost(e store.AuditEntry) string {
	if e.Host == "" {
		return "the hub"
	}
	return e.Host
}

// by picks a sentence by result; missing results use the "ok" form.
type auditForms struct{ OK, Error, Denied string }

func (f auditForms) pick(result string) string {
	switch {
	case result == store.AuditError && f.Error != "":
		return f.Error
	case result == store.AuditDenied && f.Denied != "":
		return f.Denied
	}
	return f.OK
}

// auditSentence expands the placeholders {who} {user} {host} {detail} {pkg}.
func auditSentence(tpl string, e store.AuditEntry) string {
	pkg := ""
	if f := strings.Fields(e.Detail); len(f) > 0 {
		pkg = f[0]
	}
	user := e.User
	if user == "" {
		user = "unknown"
	}
	return strings.NewReplacer("{who}", auditWho(e), "{user}", user, "{host}", auditHost(e),
		"{detail}", e.Detail, "{pkg}", pkg).Replace(tpl)
}

// auditFormats is the table of sentences. Keys are action names; job.* are
// handled by jobSentence.
var auditFormats = map[string]auditForms{
	"login":               {OK: "{who} signed in", Denied: "Sign-in refused for {user}", Error: "Sign-in failed for {user}"},
	"login.locked":        {OK: "Sign-in locked for {user} after repeated failures", Denied: "Sign-in locked for {user} after repeated failures"},
	"login.2fa":           {OK: "{who} passed the two-factor check", Denied: "Two-factor code refused for {user}", Error: "Two-factor check failed for {user}"},
	"logout":              {OK: "{who} signed out"},
	"user.reset":          {OK: "All operators were removed (reset)", Error: "Operator reset failed"},
	"admin.setup_code":    {OK: "A new setup code was issued from the console", Error: "Issuing a setup code failed"},
	"admin.user_reset":    {OK: "Operators were reset from the console", Error: "Resetting operators from the console failed"},
	"admin.login_unlock":  {OK: "Sign-in locks were cleared from the console", Error: "Clearing sign-in locks failed"},
	"setup.commit":        {OK: "Setup finished: {detail}", Error: "Setup failed"},
	"setup.unlock":        {OK: "Setup wizard unlocked", Denied: "Setup wizard unlock refused"},
	"setup.wrong_code":    {OK: "Wrong setup code entered", Denied: "Wrong setup code entered"},
	"setup.locked":        {OK: "Setup locked for one address after wrong codes", Denied: "Setup locked for one address after wrong codes"},
	"setup.locked_global": {OK: "Setup locked after too many wrong codes", Denied: "Setup locked after too many wrong codes"},
	"shell.open":          {OK: "{who} opened a shell on {host}", Error: "Opening a shell on {host} failed", Denied: "Shell on {host} refused"},
	"shell.close":         {OK: "Shell session on {host} closed ({detail})"},
	"shell.session_ended": {OK: "Shell on {host} closed because the sign-in ended"},
	"service.restart":     {OK: "{who} restarted {detail} on {host}", Error: "Restarting {detail} on {host} failed", Denied: "Restarting {detail} on {host} refused"},
	"cert.renew":          {OK: "Certificate of {host}: {detail}", Error: "Certificate renewal for {host} failed", Denied: "Certificate renewal for {host} refused"},
	"host.remove":         {OK: "{who} removed host {host}", Error: "Removing host {host} failed", Denied: "Removing host {host} refused"},
	"host.link":           {OK: "{who} linked host {host}", Error: "Linking host {host} failed", Denied: "Linking host {host} refused"},
	"host.probe":          {OK: "{who} checked the SSH host key of {host}", Error: "Reaching {host} over SSH failed"},
	"host.replace":        {OK: "{who} replaced host {host}", Error: "Replacing host {host} failed", Denied: "Replacing host {host} refused"},
	"agent.update":        {OK: "Grid Agent on {host} updated to {detail}", Error: "Updating the Grid Agent on {host} failed", Denied: "Agent update on {host} refused"},
	"enroll.ok":           {OK: "Host {host} enrolled", Error: "Enrolling host {host} failed"},
	"enroll.denied":       {OK: "Enrollment refused", Denied: "Enrollment of {host} refused", Error: "Enrollment failed"},
	"enroll.code":         {OK: "{who} created an enrollment code", Error: "Creating an enrollment code failed"},
	"update.check":        {OK: "Checked for hub updates", Error: "Checking for hub updates failed"},
	"update.stage":        {OK: "{who} staged a hub update", Error: "Staging a hub update failed", Denied: "Staging a hub update refused"},
	"update.request":      {OK: "{who} requested a hub update", Error: "Requesting a hub update failed", Denied: "Hub update request refused"},
	"update.apply":        {OK: "Hub update applied", Error: "Applying the hub update failed"},
	"update.settings":     {OK: "{who} changed the update settings", Error: "Changing the update settings failed"},
	"backup.create":       {OK: "Backup created", Error: "Creating a backup failed"},
	"backup.download":     {OK: "{who} downloaded a backup", Error: "Backup download failed", Denied: "Backup download refused"},
	"backup.restore":      {OK: "{who} restored a backup", Error: "Restoring a backup failed", Denied: "Backup restore refused"},
	"audit.prune":         {OK: "Old audit entries were pruned", Error: "Pruning audit entries failed"},
	"audit.export":        {OK: "{who} exported the audit log", Error: "Audit export failed"},
}

var auditJobs = map[string]struct{ Name, Done, Doing string }{
	"apt_update":  {Name: "apt update"},
	"apt_upgrade": {Name: "apt upgrade"},
	"apt_clean":   {Name: "apt clean-up"},
	"pkg_install": {Done: "Installed {pkg} on {host}", Doing: "Installing {pkg} on {host}"},
	"pkg_remove":  {Done: "Removed {pkg} from {host}", Doing: "Removing {pkg} from {host}"},
	"pkg_upgrade": {Done: "Upgraded {pkg} on {host}", Doing: "Upgrading {pkg} on {host}"},
}

func jobSentence(kind string, e store.AuditEntry) string {
	j, ok := auditJobs[kind]
	if !ok {
		return ""
	}
	canceled := strings.Contains(e.Detail, "canceled")
	var s string
	switch {
	case j.Name != "":
		switch {
		case e.Result == store.AuditOK:
			s = j.Name + " on {host} finished"
		case canceled:
			s = j.Name + " on {host} canceled"
		default:
			s = j.Name + " on {host} failed"
		}
	case e.Result == store.AuditOK:
		s = j.Done
	case canceled:
		s = j.Doing + " canceled"
	default:
		s = j.Doing + " failed"
	}
	return auditSentence(s, e)
}

// FormatAudit returns the human-readable sentence of an entry. Unknown actions
// get a generic sentence; the raw fields stay available to the view.
func FormatAudit(e store.AuditEntry) string {
	if kind, ok := strings.CutPrefix(e.Action, "job."); ok {
		if s := jobSentence(kind, e); s != "" {
			return s
		}
	}
	if f, ok := auditFormats[e.Action]; ok {
		s := auditSentence(f.pick(e.Result), e)
		// A missing detail leaves an empty "()" or a trailing colon behind.
		s = strings.TrimRight(strings.TrimSpace(strings.ReplaceAll(s, " ()", "")), ":")
		if reason := detailKV(e.Detail)["reason"]; reason != "" && e.Result != store.AuditOK {
			s += " (" + strings.ReplaceAll(reason, "_", " ") + ")"
		}
		return s
	}
	s := fmt.Sprintf("%s by %s", e.Action, auditWho(e))
	if e.Host != "" {
		s += " on " + e.Host
	}
	switch e.Result {
	case store.AuditError:
		s += " failed"
	case store.AuditDenied:
		s += " refused"
	}
	return s
}
