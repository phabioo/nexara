package views

import (
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/protocol"
)

// Filter keys of the packages view, in display order.
const (
	PackageFilterAll       = "all"
	PackageFilterUpdates   = "updates"
	PackageFilterInstalled = "installed"
	PackageFilterAvailable = "available"
	PackageFilterOrphaned  = "orphaned"
)

var packageFilters = []struct{ Key, Label string }{
	{PackageFilterAll, "All"},
	{PackageFilterUpdates, "Updates"},
	{PackageFilterInstalled, "Installed"},
	{PackageFilterAvailable, "Available"},
	{PackageFilterOrphaned, "Orphaned"},
}

// NormalizePackageFilter returns key if it is a known filter, else "all".
func NormalizePackageFilter(key string) string {
	for _, f := range packageFilters {
		if f.Key == key {
			return key
		}
	}
	return PackageFilterAll
}

// PackageAction is one POST /hosts/{host}/packages/{action}. The action name is
// the job kind with "-" instead of "_".
type PackageAction struct {
	Name       string
	Kind       protocol.JobKind
	NeedsPkg   bool
	NeedsAsk   bool   // the UI asks for confirmation first
	AskVariant string // header of the confirm dialog: "bad" (destructive) or "hot"
}

var packageActions = []PackageAction{
	{Name: "apt-update", Kind: protocol.JobAptUpdate},
	{Name: "apt-upgrade", Kind: protocol.JobAptUpgrade, NeedsAsk: true, AskVariant: "hot"},
	{Name: "apt-clean", Kind: protocol.JobAptClean, NeedsAsk: true, AskVariant: "bad"},
	{Name: "pkg-install", Kind: protocol.JobPkgInstall, NeedsPkg: true},
	{Name: "pkg-remove", Kind: protocol.JobPkgRemove, NeedsPkg: true, NeedsAsk: true, AskVariant: "bad"},
	{Name: "pkg-upgrade", Kind: protocol.JobPkgUpgrade, NeedsPkg: true},
}

// LookupPackageAction resolves an action name of the URL.
func LookupPackageAction(name string) (PackageAction, bool) {
	for _, a := range packageActions {
		if a.Name == name {
			return a, true
		}
	}
	return PackageAction{}, false
}

// PackageFilterTab is one filter chip.
type PackageFilterTab struct {
	Label  string
	Count  int
	Active bool
	Href   string // plain link (works without JS), carries the search term
	Attrs  template.HTMLAttr
}

// PackageTile feeds the "tile" partial.
type PackageTile struct {
	Tone, Glyph, Label, Name, Desc, Meta, Badge string
	ActionLabel, ActionClass                    string
	ActionAttrs                                 template.HTMLAttr
}

// PackageCard is one of the three maintenance cards.
type PackageCard struct {
	Order    string // phone order class
	Title    string
	Variant  string // "" or "hot"
	TagTone  string
	TagText  string
	Text     string
	ObjLabel string
	ObjValue string
	Pct      int
	Bad      bool
	BoxIcon  string
	BoxText  string
	BoxUnit  string

	ButtonLabel   string
	ButtonVariant string
	ButtonAttrs   template.HTMLAttr
}

// PackagesPageSize is the number of tiles rendered per request; the rest follows through More.
const PackagesPageSize = 60

// PackagesMore describes the "show more" sentinel at the end of a page of tiles.
type PackagesMore struct {
	URL       string // GET answers with the next page of tiles (and the next sentinel)
	Remaining int    // tiles not rendered yet
}

// PackagesModel is the view model of the packages page and its HTMX fragments.
type PackagesModel struct {
	HostLabel string
	HostPath  string // "/hosts/alpha"
	Filter    string
	Query     string
	Count     string // "7/10", empty hides it

	Filters []PackageFilterTab
	Ticker  string
	Notices []string      // pink notices under the ticker (reboot required, offline)
	Note    string        // hint about the repository search
	Tiles   []PackageTile // one page of the filtered, searched and sorted list
	Total   int           // all tiles of the current filter and search, not only this page
	More    *PackagesMore // nil when this page reaches the end
	Empty   string        // shown instead of tiles

	Sync, Upgrade, Clean PackageCard
	Disabled             bool // host offline or packages switched off: actions are inert
}

// PackagesInput is everything BuildPackages needs; it has no side effects.
type PackagesInput struct {
	HostLabel string
	HostPath  string
	Online    bool
	Capable   bool // packages capability enabled
	Data      *protocol.Packages
	Reboot    bool
	Count     string
	Filter    string
	Query     string
	Found     []protocol.Package // repository search results for Query
	Offset    int                // first tile of the page (0 for the whole view, >0 for "show more")
	Note      string
	Jobs      []grid.Job // recent jobs of the host, newest first
}

// BuildPackages assembles the packages view model.
func BuildPackages(in PackagesInput) PackagesModel {
	filter := NormalizePackageFilter(in.Filter)
	q := strings.TrimSpace(in.Query)
	disabled := !in.Online || !in.Capable

	var items []protocol.Package
	if in.Data != nil {
		items = in.Data.Items
	}
	var nAll, nUpd, nInst, nAvail, nOrph int
	var orphBytes int64
	var updates []protocol.Package
	local := make(map[string]bool, len(items))
	for _, p := range items {
		local[p.Name] = true
		nAll++
		switch p.State {
		case protocol.PackageUpdate:
			nUpd++
			nInst++
			updates = append(updates, p)
		case protocol.PackageInstalled:
			nInst++
		case protocol.PackageAvailable:
			nAvail++
		case protocol.PackageOrphaned:
			nOrph++
			orphBytes += p.SizeBytes
		}
	}

	m := PackagesModel{
		HostLabel: in.HostLabel,
		HostPath:  in.HostPath,
		Filter:    filter,
		Query:     q,
		Count:     in.Count,
		Note:      in.Note,
		Disabled:  disabled,
	}

	counts := map[string]int{
		PackageFilterAll: nAll, PackageFilterUpdates: nUpd, PackageFilterInstalled: nInst,
		PackageFilterAvailable: nAvail, PackageFilterOrphaned: nOrph,
	}
	for _, f := range packageFilters {
		base := in.HostPath + "/packages?filter=" + f.Key
		href := base
		if q != "" {
			href += "&q=" + url.QueryEscape(q)
		}
		m.Filters = append(m.Filters, PackageFilterTab{
			Label: f.Label, Count: counts[f.Key], Active: f.Key == filter, Href: href,
			Attrs: attrs(
				"hx-get", base, "hx-target", "#pkg-results", "hx-swap", "innerHTML",
				"hx-include", "#pkg-q", "hx-push-url", "true"),
		})
	}

	switch {
	case in.Data == nil:
		m.Ticker = "No package data yet"
	case nUpd == 1:
		m.Ticker = "1 update available"
	case nUpd > 1:
		m.Ticker = fmt.Sprintf("%d updates available", nUpd)
	default:
		m.Ticker = "System up to date"
	}

	switch {
	case !in.Capable:
		m.Notices = append(m.Notices, fmt.Sprintf("Package management is switched off for %s.", in.HostLabel))
	case !in.Online:
		m.Notices = append(m.Notices, fmt.Sprintf("%s is offline. The list shows the last known state; actions are unavailable.", in.HostLabel))
	}
	if in.Reboot {
		m.Notices = append(m.Notices, fmt.Sprintf("A reboot is required on %s to finish the update.", in.HostLabel))
	}

	// Tiles: the host's list narrowed by the search term, plus repository hits
	// that are not in the list yet.
	var pool []protocol.Package
	lq := strings.ToLower(q)
	for _, p := range items {
		if lq == "" || strings.Contains(strings.ToLower(p.Name), lq) {
			pool = append(pool, p)
		}
	}
	for _, p := range in.Found {
		if !local[p.Name] {
			local[p.Name] = true
			pool = append(pool, p)
		}
	}
	var shown []protocol.Package
	for _, p := range pool {
		if packageMatchesFilter(p.State, filter) {
			shown = append(shown, p)
		}
	}
	sortPackages(shown)
	m.Total = len(shown)
	start := min(max(in.Offset, 0), len(shown))
	end := min(start+PackagesPageSize, len(shown))
	for _, p := range shown[start:end] {
		m.Tiles = append(m.Tiles, packageTile(p, in.HostPath, disabled))
	}
	if end < len(shown) {
		more := in.HostPath + "/packages?filter=" + filter
		if q != "" {
			more += "&q=" + url.QueryEscape(q)
		}
		m.More = &PackagesMore{URL: more + "&offset=" + strconv.Itoa(end), Remaining: len(shown) - end}
	}
	if len(shown) == 0 {
		m.Empty = emptyMessage(in.Data != nil, filter, q)
	}

	m.Sync = syncCard(in, disabled)
	m.Upgrade = upgradeCard(in, updates, disabled)
	m.Clean = cleanCard(in, nOrph, orphBytes, disabled)
	return m
}

func packageMatchesFilter(st protocol.PackageState, filter string) bool {
	switch filter {
	case PackageFilterUpdates:
		return st == protocol.PackageUpdate
	case PackageFilterInstalled:
		return st == protocol.PackageInstalled || st == protocol.PackageUpdate
	case PackageFilterAvailable:
		return st == protocol.PackageAvailable
	case PackageFilterOrphaned:
		return st == protocol.PackageOrphaned
	}
	return true
}

// sortPackages puts what needs attention first: updates, then orphaned packages, then installed ones,
// then packages that are only available. Updates keep the order the agent reported (it sorts by name
// already); the other groups are sorted alphabetically here.
func sortPackages(ps []protocol.Package) {
	sort.SliceStable(ps, func(i, j int) bool {
		if ri, rj := stateRank(ps[i].State), stateRank(ps[j].State); ri != rj {
			return ri < rj
		} else if ri == 0 {
			return false
		}
		li, lj := strings.ToLower(ps[i].Name), strings.ToLower(ps[j].Name)
		if li != lj {
			return li < lj
		}
		return ps[i].Name < ps[j].Name
	})
}

func stateRank(st protocol.PackageState) int {
	switch st {
	case protocol.PackageUpdate:
		return 0
	case protocol.PackageOrphaned:
		return 1
	case protocol.PackageInstalled:
		return 2
	}
	return 3
}

func emptyMessage(haveData bool, filter, q string) string {
	switch {
	case !haveData && q == "":
		return "No package data yet."
	case q != "":
		return fmt.Sprintf("No package matches “%s”.", q)
	case filter == PackageFilterUpdates:
		return "All packages are up to date."
	case filter == PackageFilterOrphaned:
		return "No orphaned packages."
	case filter == PackageFilterAvailable:
		return "Search by name to find packages to install."
	}
	return "No packages."
}

func packageTile(p protocol.Package, hostPath string, disabled bool) PackageTile {
	t := PackageTile{Name: p.Name, Desc: p.Summary, ActionClass: "btn-tool"}
	if p.SizeBytes > 0 {
		t.Badge = formatSI(p.SizeBytes)
	}
	var act string
	var ask bool
	switch p.State {
	case protocol.PackageUpdate:
		t.Tone, t.Glyph, t.Label = "lime", "arrow-up", "Update"
		t.Meta = p.InstalledVersion + " → " + p.CandidateVersion
		t.ActionLabel, t.ActionClass, act = "Update", "btn-tool is-hot", "pkg-upgrade"
	case protocol.PackageAvailable:
		t.Tone, t.Glyph, t.Label = "blue", "plus", "Available"
		t.Meta = p.CandidateVersion
		t.ActionLabel, act = "Install", "pkg-install"
	case protocol.PackageOrphaned:
		t.Tone, t.Glyph, t.Label = "pink", "close", "Orphaned"
		t.Meta = p.InstalledVersion
		t.ActionLabel, act, ask = "Remove", "pkg-remove", true
	default:
		t.Tone, t.Glyph, t.Label = "grey", "check", "Installed"
		t.Meta = p.InstalledVersion
		t.ActionLabel, act, ask = "Remove", "pkg-remove", true
	}
	vals := `{"package":` + jsonString(p.Name) + `}`
	if ask {
		t.ActionAttrs = attrs("hx-get", hostPath+"/packages/confirm/"+act, "hx-vals", vals,
			"hx-target", "#modal-root", "hx-swap", "innerHTML")
	} else {
		t.ActionAttrs = attrs("hx-post", hostPath+"/packages/"+act, "hx-vals", vals,
			"hx-target", "#modal-root", "hx-swap", "innerHTML")
	}
	if disabled {
		t.ActionAttrs += " disabled"
	}
	return t
}

func syncCard(in PackagesInput, disabled bool) PackageCard {
	c := PackageCard{
		Order: "phone-order-3", Title: "Sync sources", TagTone: "dark", TagText: "Standard",
		Text:     fmt.Sprintf("Re-read the package lists from all sources on %s.", in.HostLabel),
		ObjLabel: "Sources read", BoxIcon: "reboot",
		ButtonLabel: "apt update",
		ButtonAttrs: postAttrs(in.HostPath+"/packages/apt-update", disabled),
	}
	switch n, st := sourcesRead(in.Jobs); st {
	case "done":
		c.ObjValue, c.Pct, c.BoxText = fmt.Sprintf("%d/%d", n, n), 100, fmt.Sprint(n)
	case "running":
		c.ObjValue, c.BoxText = "reading…", "…"
	case "failed":
		c.ObjValue, c.Pct, c.Bad, c.BoxText = "failed", 100, true, "!"
	default:
		c.ObjValue, c.BoxText = "not synced", "–"
	}
	return c
}

func upgradeCard(in PackagesInput, updates []protocol.Package, disabled bool) PackageCard {
	n := len(updates)
	c := PackageCard{
		Order: "phone-order-1", Title: "System upgrade", Variant: "hot", TagTone: "lime", TagText: "Recommended",
		ObjLabel: "Updates installed", BoxIcon: "arrow-up", BoxText: fmt.Sprint(n),
		ButtonLabel: "apt upgrade", ButtonVariant: "light",
	}
	if n == 0 {
		c.TagTone, c.TagText = "dark", "Up to date"
		c.Text = "All packages are up to date."
		c.ObjValue, c.Pct = "0/0", 100
	} else {
		c.Text = upgradeText(updates)
		c.ObjValue = fmt.Sprintf("0/%d", n)
	}
	c.ButtonAttrs = attrs("hx-get", in.HostPath+"/packages/confirm/apt-upgrade",
		"hx-target", "#modal-root", "hx-swap", "innerHTML")
	if disabled || n == 0 {
		c.ButtonAttrs += " disabled"
	}
	return c
}

// upgradeText names the most interesting pending updates: the kernel and
// OpenSSH first, then whatever comes first in the list.
func upgradeText(updates []protocol.Package) string {
	n := len(updates)
	lead := fmt.Sprintf("%d updates ready", n)
	if n == 1 {
		lead = "1 update ready"
	}
	var picks []string
	has := func(s string) bool {
		for _, p := range picks {
			if p == s {
				return true
			}
		}
		return false
	}
	for _, p := range updates {
		if strings.HasPrefix(p.Name, "linux-image") && !has("kernel") {
			picks = append(picks, "kernel")
		}
	}
	for _, p := range updates {
		if p.Name == "openssh-server" && !has("OpenSSH") {
			picks = append(picks, "OpenSSH")
		}
	}
	for _, p := range updates {
		if len(picks) >= 2 {
			break
		}
		if !strings.HasPrefix(p.Name, "linux-image") && p.Name != "openssh-server" && !has(p.Name) {
			picks = append(picks, p.Name)
		}
	}
	if len(picks) > 2 {
		picks = picks[:2]
	}
	switch len(picks) {
	case 0:
		return lead + "."
	case 1:
		return lead + ", including " + picks[0] + "."
	}
	return lead + ", including " + picks[0] + " and " + picks[1] + "."
}

func cleanCard(in PackagesInput, orphans int, orphBytes int64, disabled bool) PackageCard {
	c := PackageCard{
		Order: "phone-order-3", Title: "Clean up", TagTone: "light", TagText: "Maintenance",
		Text:     "Remove orphaned packages and clear the package cache.",
		ObjLabel: "Orphans removed", ObjValue: fmt.Sprintf("0/%d", orphans),
		ButtonLabel: "autoremove + clean",
	}
	if orphans == 0 {
		c.Pct = 100
	}
	size := formatSI(orphBytes)
	c.BoxText, c.BoxUnit, _ = strings.Cut(size, " ")
	if orphBytes <= 0 {
		c.BoxText, c.BoxUnit = "0", "MB"
	}
	c.ButtonAttrs = attrs("hx-get", in.HostPath+"/packages/confirm/apt-clean",
		"hx-target", "#modal-root", "hx-swap", "innerHTML")
	if disabled {
		c.ButtonAttrs += " disabled"
	}
	return c
}

var reSourceLine = regexp.MustCompile(`^(Hit|Get|Ign):\d+ `)

// sourcesRead reports the outcome of the newest apt update job: how many
// sources it read ("done"), or "running", "failed"; "" if there is none.
func sourcesRead(jobs []grid.Job) (int, string) {
	for _, j := range jobs {
		if j.Kind != protocol.JobAptUpdate {
			continue
		}
		switch {
		case !j.State.Finished():
			return 0, "running"
		case j.State == grid.JobDone && j.OK:
			n := 0
			for _, l := range j.Output {
				if reSourceLine.MatchString(l.Line) {
					n++
				}
			}
			return n, "done"
		case j.State == grid.JobFailed:
			return 0, "failed"
		}
	}
	return 0, ""
}

// formatSI renders a package size with decimal units like apt does: 315 KB, 1.4 MB, 78 MB.
func formatSI(b int64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	f := float64(b)
	i := 0
	for f >= 1000 && i < len(units)-1 {
		f /= 1000
		i++
	}
	switch {
	case i == 0:
		return fmt.Sprintf("%d B", b)
	case f < 9.95:
		return strings.TrimSuffix(fmt.Sprintf("%.1f", f), ".0") + " " + units[i]
	}
	return fmt.Sprintf("%.0f %s", f, units[i])
}

func postAttrs(path string, disabled bool) template.HTMLAttr {
	a := attrs("hx-post", path, "hx-target", "#modal-root", "hx-swap", "innerHTML")
	if disabled {
		a += " disabled"
	}
	return a
}

// attrs builds an attribute string from name/value pairs; values are escaped.
// Names are literals of this package.
func attrs(kv ...string) template.HTMLAttr {
	var b strings.Builder
	for i := 0; i+1 < len(kv); i += 2 {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(kv[i] + `="` + html.EscapeString(kv[i+1]) + `"`)
	}
	return template.HTMLAttr(b.String()) //nolint:gosec // names are constants, values are escaped
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// --- confirm dialog ---------------------------------------------------------

// PackagesConfirm is the model of the confirm dialog.
type PackagesConfirm struct {
	Title     string
	Variant   string // "bad" or "hot"
	HostLabel string
	Text      string
	Label     string // confirm button
	Icon      string
	PostURL   string
	Package   string
}

// NewPackagesConfirm builds the confirm dialog of a confirmable action.
// updates and orphans are the current counts, used in the text.
func NewPackagesConfirm(a PackageAction, hostLabel, hostPath, pkg string, updates, orphans int) (PackagesConfirm, bool) {
	if !a.NeedsAsk {
		return PackagesConfirm{}, false
	}
	c := PackagesConfirm{
		Variant: a.AskVariant, HostLabel: hostLabel, PostURL: hostPath + "/packages/" + a.Name, Package: pkg, Icon: "close",
	}
	switch a.Kind {
	case protocol.JobPkgRemove:
		c.Title, c.Label = "Remove package", "Remove "+pkg
		c.Text = fmt.Sprintf("Remove %s from %s? Configuration files are kept. Dependent packages may stop working.", pkg, hostLabel)
	case protocol.JobAptUpgrade:
		c.Title, c.Label, c.Icon = "Upgrade all", "Upgrade all", "arrow-up"
		c.Text = fmt.Sprintf("Install all pending updates on %s? This can take several minutes and may require a reboot afterwards.", hostLabel)
		if updates > 0 {
			c.Text = fmt.Sprintf("Install %d pending %s on %s? This can take several minutes and may require a reboot afterwards.",
				updates, plural(updates, "update", "updates"), hostLabel)
		}
	case protocol.JobAptClean:
		c.Title, c.Label = "Clean up", "Autoremove + clean"
		c.Text = fmt.Sprintf("Remove orphaned packages and clear the package cache on %s? Configuration files are kept.", hostLabel)
		if orphans > 0 {
			c.Text = fmt.Sprintf("Remove %d orphaned %s and clear the package cache on %s? Configuration files are kept.",
				orphans, plural(orphans, "package", "packages"), hostLabel)
		}
	default:
		return PackagesConfirm{}, false
	}
	return c, true
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// --- jobs -------------------------------------------------------------------

// JobLineView is one rendered output line.
type JobLineView struct {
	Text  string
	Class string // "", "is-wait" (lime) or "is-bad" (pink)
}

// JobView is the model of the job dialog and of its live updates.
type JobView struct {
	ID        string
	HostLabel string
	Title     string // "apt upgrade -y"
	Command   string
	Short     string // "apt upgrade", for the chip and the log line

	StateKey   string // queued, running, done, failed, canceled
	StateLabel string
	StateTag   string // tag class
	Active     bool   // queued or running
	Finished   bool
	Pct        int
	Bad        bool
	Busy       bool // indeterminate progress (running)

	RebootRequired bool
	Lines          []JobLineView

	CancelAttrs template.HTMLAttr
	OOB         bool // render as out-of-band replacement
}

// AsOOB returns a copy whose regions carry hx-swap-oob.
func (v JobView) AsOOB() JobView { v.OOB = true; return v }

// JobCommand is the command line shown for a job kind.
func JobCommand(kind protocol.JobKind, pkg string) string {
	switch kind {
	case protocol.JobAptUpdate:
		return "apt update"
	case protocol.JobAptUpgrade:
		return "apt upgrade -y"
	case protocol.JobAptClean:
		return "apt autoremove -y && apt clean"
	case protocol.JobPkgInstall:
		return "apt install -y " + pkg
	case protocol.JobPkgRemove:
		return "apt remove -y " + pkg
	case protocol.JobPkgUpgrade:
		return "apt install --only-upgrade -y " + pkg
	}
	return string(kind)
}

// JobShort is the short name of a job for the chip.
func JobShort(kind protocol.JobKind, pkg string) string {
	switch kind {
	case protocol.JobAptUpdate:
		return "apt update"
	case protocol.JobAptUpgrade:
		return "apt upgrade"
	case protocol.JobAptClean:
		return "apt clean"
	case protocol.JobPkgInstall:
		return "install " + pkg
	case protocol.JobPkgRemove:
		return "remove " + pkg
	case protocol.JobPkgUpgrade:
		return "upgrade " + pkg
	}
	return string(kind)
}

// JobLineClass colors an output line: waiting for the dpkg lock and apt
// warnings lime, errors pink.
func JobLineClass(l grid.JobLine) string {
	t := strings.TrimSpace(l.Line)
	lower := strings.ToLower(t)
	switch {
	case strings.HasPrefix(t, "E:"), strings.HasPrefix(t, "Err:"), strings.HasPrefix(lower, "error"):
		return "is-bad"
	case l.Stream == protocol.StreamStatus, strings.HasPrefix(t, "W:"), strings.HasPrefix(lower, "waiting"):
		return "is-wait"
	}
	return ""
}

// NewJobLine renders one output line.
func NewJobLine(l grid.JobLine) JobLineView {
	return JobLineView{Text: l.Line, Class: JobLineClass(l)}
}

// NewJobView builds the dialog model of a job.
func NewJobView(hostLabel, hostPath string, j grid.Job) JobView {
	v := JobView{
		ID: j.ID, HostLabel: hostLabel,
		Title: JobCommand(j.Kind, j.Package), Command: JobCommand(j.Kind, j.Package),
		Short:    JobShort(j.Kind, j.Package),
		StateKey: string(j.State), Active: !j.State.Finished(), Finished: j.State.Finished(),
		RebootRequired: j.State.Finished() && j.RebootRequired,
	}
	switch j.State {
	case grid.JobQueued:
		v.StateLabel, v.StateTag = "Queued", "tag-light"
	case grid.JobRunning:
		v.StateLabel, v.StateTag, v.Busy = "Running", "tag-light", true
	case grid.JobDone:
		v.StateLabel, v.StateTag, v.Pct = "Done", "tag-lime", 100
		if !j.OK {
			v.StateKey, v.StateLabel, v.StateTag, v.Bad = string(grid.JobFailed), "Failed", "tag-bad", true
		}
	case grid.JobFailed:
		v.StateLabel, v.StateTag, v.Pct, v.Bad = "Failed", "tag-bad", 100, true
	case grid.JobCanceled:
		v.StateLabel, v.StateTag = "Canceled", "tag-light"
	default:
		v.StateLabel, v.StateTag = string(j.State), "tag-light"
	}
	for _, l := range j.Output {
		v.Lines = append(v.Lines, NewJobLine(l))
	}
	if v.Finished {
		switch {
		case j.State == grid.JobCanceled:
			v.Lines = append(v.Lines, JobLineView{Text: "Canceled.", Class: "is-wait"})
		case v.Bad:
			msg := j.Error
			if msg == "" {
				msg = fmt.Sprintf("exit code %d", j.ExitCode)
			}
			v.Lines = append(v.Lines, JobLineView{Text: "Failed: " + msg, Class: "is-bad"})
		}
	}
	if v.Active {
		v.CancelAttrs = attrs("hx-post", hostPath+"/jobs/"+url.PathEscape(j.ID)+"/cancel",
			"hx-target", "this", "hx-swap", "none")
	}
	return v
}

// JobChipFor returns the status-bar chip for the host's jobs (newest first):
// the running job, else the oldest queued one; nil if nothing is active.
func JobChipFor(hostPath string, jobs []grid.Job) *JobChip {
	var pick *grid.Job
	for i := range jobs {
		j := &jobs[i]
		switch {
		case j.State == grid.JobRunning:
			pick = j
		case j.State == grid.JobQueued && (pick == nil || pick.State != grid.JobRunning):
			pick = j // later in the slice means older
		}
		if pick != nil && pick.State == grid.JobRunning {
			break
		}
	}
	if pick == nil {
		return nil
	}
	return NewJobChip(hostPath, *pick)
}

// NewJobChip builds the chip of one active job.
func NewJobChip(hostPath string, j grid.Job) *JobChip {
	return &JobChip{
		Label: fmt.Sprintf("JOB · %s · %s", JobShort(j.Kind, j.Package), j.State),
		Href:  hostPath + "/jobs/" + url.PathEscape(j.ID),
	}
}

// SafeDOMID reports whether s can be used inside an element id, an event name
// and a selector without quoting.
func SafeDOMID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range []byte(s) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}
