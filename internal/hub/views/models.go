package views

// Layout is the view model of the app shell (layouts/app.html). Every page's data struct embeds it:
//
//	type overviewData struct {
//		views.Layout
//		Cores []Core
//	}
type Layout struct {
	Title     string // page title, rendered as "<Title> · Nexara Nexus"
	ActiveNav string // key of the active nav item
	CSRF      string // CSRF token for <meta name="csrf-token">

	NodeNo   string // "01", number of the selected host
	Uptime   string // "41D 06H"; empty hides the line
	HostName string // selected host, shown in the portrait card and the status bar
	HostIP   string

	Online   int    // hosts online
	Packages string // "7/10" up-to-date packages, empty hides the pill segment
	Temp     string // "47.2" (the degree sign is added), empty hides the segment
	Latency  string // "4 ms"

	Hosts      []HostTab
	Nav        []NavItem // only items of shipped versions (decision #31)
	AddHostURL string    // hx-get target of the dashed "+ Host" tab; empty hides it

	Log            string   // last action, left side of the status bar
	Job            *JobChip // running background job, left of the log line
	BodyClass      string
	ConnectionLost bool   // renders the reconnecting state from the start
	Toast          *Toast // server-rendered banner, hidden again by nexus.js
}

// HostTab is one entry of the host tab row.
type HostTab struct {
	Name    string
	Href    string
	Active  bool
	Badge   int // pending updates; 0 hides the count box
	Offline bool
	Reboot  bool
}

// NavItem is one entry of the sidebar, icon rail and bottom navigation.
type NavItem struct {
	Key    string
	Label  string
	Href   string
	Icon   string // icon name from the sprite
	Badge  int
	Active bool
}

// JobChip is the lime "JOB" button in the status bar that reopens the job dialog.
type JobChip struct {
	Label string // "JOB · apt upgrade · 42%"
	Href  string // hx-get target that returns the dialog
}

// Toast is the banner shown after an action.
type Toast struct {
	Title string // serif title, e.g. "Updated"
	Sub   string // small caps subtitle
}

// NavItems returns Nav with Active set from ActiveNav.
func (l Layout) NavItems() []NavItem {
	items := make([]NavItem, len(l.Nav))
	for i, it := range l.Nav {
		it.Active = it.Active || (l.ActiveNav != "" && it.Key == l.ActiveNav)
		items[i] = it
	}
	return items
}

// DefaultNav returns the navigation of v0.1: Overview, Packages, Shell. Views of later versions are
// added by the version that ships them (decision #31). packageUpdates is the badge of Packages.
func DefaultNav(packageUpdates int) []NavItem {
	return []NavItem{
		{Key: "overview", Label: "Overview", Href: "/", Icon: "overview"},
		{Key: "packages", Label: "Packages", Href: "/packages", Icon: "package", Badge: packageUpdates},
		{Key: "shell", Label: "Shell", Href: "/shell", Icon: "terminal"},
	}
}

// AuthLayout is the view model of the auth shell (layouts/auth.html) used by login and setup.
// Page data structs embed it and define `{{define "layout"}}auth{{end}}`.
type AuthLayout struct {
	Title     string
	CSRF      string
	BodyClass string
	Variant   string // "auth-login" or "auth-setup"

	PillLabel  string        // text of the lime segment, default "Nexus"
	Segments   []PillSegment // e.g. LOCKED, or SETUP + 1/7
	MicroLines []string      // tiny lines in the top bar; the first one also shows on phones
	BuildLines []string      // right-aligned build info

	Log      string // status bar log line
	LiveText string // e.g. "SECURE CHANNEL · TLS 1.3"
	Toast    *Toast
}

// PillSegment is a segment of the auth top bar pill.
type PillSegment struct {
	Text  string
	Icon  string
	Light bool // light grey instead of dark
}

// PillLabelOrDefault returns PillLabel or "Nexus".
func (a AuthLayout) PillLabelOrDefault() string {
	if a.PillLabel == "" {
		return "Nexus"
	}
	return a.PillLabel
}

// SetupStep is one step of the setup wizard.
type SetupStep struct {
	Num   int
	Label string
	State string // "done", "on" or "todo"
}

// SetupSteps feeds the "setup-steps" and "setup-progress" templates.
type SetupSteps struct {
	Items        []SetupStep
	Current      int // 1-based
	Total        int
	CurrentLabel string
	NextLabel    string // empty on the last step
}

// NewSetupSteps builds the step list for the wizard; current is 1-based.
func NewSetupSteps(labels []string, current int) SetupSteps {
	s := SetupSteps{Total: len(labels), Current: current}
	for i, l := range labels {
		n := i + 1
		st := "todo"
		switch {
		case n < current:
			st = "done"
		case n == current:
			st = "on"
			s.CurrentLabel = l
		case n == current+1:
			s.NextLabel = l
		}
		s.Items = append(s.Items, SetupStep{Num: n, Label: l, State: st})
	}
	return s
}
