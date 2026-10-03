package views

import (
	"strconv"
	"strings"
	"time"

	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/hub/update"
)

// SettingsRelease is a newer release found by the GitHub check.
type SettingsRelease struct {
	Version  string
	When     string
	PageURL  string // release page on GitHub, shown as text only
	Staged   bool   // already staged: "Install now" is offered instead
	StageURL string
}

// SettingsStaged is a verified bundle waiting for "Install now".
type SettingsStaged struct {
	Version    string
	Detail     string // "48.2 MB · uploaded Today 12:00"
	InstallURL string // GET: the confirm dialog
}

// SettingsStep is one line of the install progress.
type SettingsStep struct {
	Label string
	State string // "done", "run", "wait", "bad"
}

// SettingsInstall is an update the helper is working on.
type SettingsInstall struct {
	Version string
	Since   string
	Steps   []SettingsStep
	Stale   bool
	// CancelURL withdraws a request the helper has not claimed yet.
	CancelURL string
}

// SettingsLast is the outcome of the last update the helper reported.
type SettingsLast struct {
	Tone    string // "ok" or "bad"
	Title   string
	Message string
	When    string
	Log     string
	// NoRollback is set when the helper refused the update for lack of a saved
	// copy of the running version; the card then explains why and shows Command.
	NoRollback bool
	Why        string
	Steps      []string
	Command    string
}

// SettingsUpdates is the Updates card.
type SettingsUpdates struct {
	Tag      string
	TagTone  string // "lime", "light", "bad"
	Hub      string
	Agents   string
	CheckOn  bool
	Channels []SettingsChoice // shown while the check is on
	// CheckNote is the line under the toggle: when the check last ran, or why it failed.
	CheckNote   string
	CheckFailed bool
	Latest      *SettingsRelease
	Staged      []SettingsStaged
	Installing  *SettingsInstall
	Last        *SettingsLast
	// CanInstall is false when the update helper does not watch this hub (a development hub, a manual install).
	CanInstall bool
	Busy       bool // an update is in progress: no new install, no upload
	// Poll makes the card ask for its own state while the helper works.
	Poll bool
	// Err is the error row of a failed action.
	Err string
	// OOB renders the card as an out-of-band swap (the answer to a dialog).
	OOB bool
}

// installSteps in the order the helper reports its phases.
var installSteps = []struct{ Phase, Label string }{
	{update.PhaseQueued, "Waiting for the update helper"},
	{update.PhaseVerify, "Verifying the package"},
	{update.PhaseBackup, "Backing up the hub"},
	{update.PhaseInstall, "Installing the new version"},
	{update.PhaseHealth, "Waiting for the new hub"},
}

func installProgress(phase string) []SettingsStep {
	cur := 0
	for i, s := range installSteps {
		if s.Phase == phase {
			cur = i
		}
	}
	rollback := phase == update.PhaseRollback
	if rollback {
		cur = len(installSteps) - 1
	}
	steps := make([]SettingsStep, 0, len(installSteps)+1)
	for i, s := range installSteps {
		st := SettingsStep{Label: s.Label, State: "wait"}
		switch {
		case rollback && i == len(installSteps)-1:
			st.State = "bad"
		case i < cur:
			st.State = "done"
		case i == cur && !rollback:
			st.State = "run"
		}
		steps = append(steps, st)
	}
	if rollback {
		steps = append(steps, SettingsStep{Label: "Restoring the previous version", State: "run"})
	}
	return steps
}

func trimVersion(v string) string { return strings.TrimPrefix(strings.TrimSpace(v), "v") }

// NewSettingsUpdates builds the card from the update service's status and the host list (for the agent count).
func NewSettingsUpdates(now time.Time, st update.Status, hosts []grid.HostInfo) *SettingsUpdates {
	u := &SettingsUpdates{
		CheckOn:    st.Config.CheckGitHub,
		CanInstall: st.Supported,
		Hub:        VersionLabel(st.Current) + " · linux/" + st.Arch,
		TagTone:    "light",
		Tag:        "Manual updates",
	}

	// Agents: how many run the hub's version; the hub updates the others when they connect (decision #20).
	dev := !isNumericVersion(st.Current)
	onCurrent := 0
	for _, h := range hosts {
		if trimVersion(h.AgentVersion) == trimVersion(st.Current) {
			onCurrent++
		}
	}
	u.Agents = countFrac(onCurrent, len(hosts)) + " on " + VersionLabel(st.Current)
	if dev {
		u.Agents += " · auto-update off (development build)"
	} else {
		u.Agents += " · auto-update on"
	}

	if u.CheckOn {
		u.Channels = []SettingsChoice{
			{Label: "Stable", Value: update.ChannelStable, On: st.Config.Channel == update.ChannelStable},
			{Label: "RC", Value: update.ChannelRC, On: st.Config.Channel == update.ChannelRC},
		}
	}

	staged := map[string]bool{}
	for _, s := range st.Staged {
		staged[s.Version] = true
		src := "uploaded"
		if s.Source == update.SourceGitHub {
			src = "downloaded"
		}
		u.Staged = append(u.Staged, SettingsStaged{
			Version:    VersionLabel(s.Version),
			Detail:     SizeText(s.Size) + " · " + src + " " + SettingsWhen(now, s.StagedAt),
			InstallURL: "/settings/updates/install?version=" + s.Version,
		})
	}

	if c := st.Check; c != nil {
		switch {
		case c.Error != "":
			u.CheckNote, u.CheckFailed = "Last check failed: "+c.Error, true
		default:
			u.CheckNote = "Checked " + AgoText(now, c.CheckedAt)
		}
		if c.Latest != nil && c.UpdateAvailable {
			u.Latest = &SettingsRelease{
				Version: VersionLabel(c.Latest.Version), When: SettingsDate(now, c.Latest.PublishedAt),
				PageURL: c.Latest.URL, Staged: staged[c.Latest.Version], StageURL: "/settings/updates/stage",
			}
		}
	}

	if in := st.Installing; in != nil {
		u.Busy = !in.Stale
		u.Installing = &SettingsInstall{
			Version: VersionLabel(in.Version), Since: SettingsWhen(now, in.Since), Steps: installProgress(in.Phase), Stale: in.Stale,
		}
		if in.Phase == update.PhaseQueued {
			u.Installing.CancelURL = "/settings/updates/cancel"
		}
		u.Poll = !in.Stale
	}

	if r := st.Last; r != nil {
		l := &SettingsLast{When: SettingsWhen(now, r.FinishedAt), Message: r.Message}
		switch r.Status {
		case update.StatusOK:
			l.Tone, l.Title = "ok", "Updated to "+VersionLabel(r.Version)
			if r.PreviousVersion != "" {
				l.Message = "Previous version " + VersionLabel(r.PreviousVersion) + "."
			}
		case update.StatusRolledBack:
			l.Tone, l.Title = "bad", "Rolled back to "+VersionLabel(r.PreviousVersion)
			if r.PreviousVersion == "" {
				l.Title = "Update rolled back"
			}
			l.Message = r.Message + " The previous version was restored."
		default:
			l.Tone, l.Title = "bad", "Update failed"
			if r.Phase != "" {
				l.Message = strings.TrimSpace(r.Message + " (step: " + r.Phase + ")")
			}
			if strings.Contains(r.Message, update.MsgNoRollback) {
				noRollbackHint(l)
			}
		}
		l.Log = tailText(r.LogTail, 2000)
		u.Last = l
	}

	switch {
	case u.Installing != nil && !u.Installing.Stale:
		u.Tag, u.TagTone = "Installing "+u.Installing.Version, "lime"
	case len(u.Staged) > 0:
		u.Tag, u.TagTone = u.Staged[0].Version+" ready to install", "lime"
	case u.Latest != nil:
		u.Tag, u.TagTone = "Update available · "+u.Latest.Version, "lime"
	case st.Check != nil && st.Check.Error == "" && u.CheckOn:
		u.Tag, u.TagTone = "Up to date", "lime"
	case u.Last != nil && u.Last.Tone == "bad" && st.Check == nil:
		u.Tag, u.TagTone = "Last update failed", "bad"
	}
	return u
}

// noRollbackHint turns the helper's refusal for missing rollback material into
// an explanation and the one command that updates anyway (decision #50; owner
// decision: no relaxation, only a clear way out).
func noRollbackHint(l *SettingsLast) {
	l.Title, l.Message = "Update refused: no rollback copy", "Nothing was installed."
	l.NoRollback = true
	l.Why = "An update is only installed when this hub can go back to the version it runs now if the new one does not start. " +
		"That copy is saved after every update and by the installer; a package you installed by hand with apt or dpkg leaves none."
	l.Steps = []string{
		"1. On the hub, stop the update watcher: sudo systemctl stop nexus-update.path",
		"2. Request the update here again.",
		"3. Run this on the hub. It installs without a way back, so a failed update then needs a manual fix:",
	}
	l.Command = update.NoRollbackCommand
}

func isNumericVersion(v string) bool {
	v = trimVersion(v)
	return v != "" && v[0] >= '0' && v[0] <= '9'
}

func countFrac(n, total int) string { return strconv.Itoa(n) + "/" + strconv.Itoa(total) }

// tailText keeps the last n bytes of s at a line start.
func tailText(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	s = s[len(s)-n:]
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[i+1:]
	}
	return "…\n" + s
}

// SettingsInstallConfirm is the data of the "Install now" dialog.
type SettingsInstallConfirm struct {
	Version  string
	Current  string
	Detail   string
	PostURL  string
	Version0 string // plain version for the form
	Older    bool
	Error    string // step-up failure
	NoCode   bool
}

// NewSettingsInstallConfirm builds the confirm dialog of a staged version.
func NewSettingsInstallConfirm(now time.Time, st update.Status, version string) (SettingsInstallConfirm, bool) {
	for _, s := range st.Staged {
		if s.Version != version {
			continue
		}
		c := SettingsInstallConfirm{
			Version: VersionLabel(s.Version), Version0: s.Version, Current: VersionLabel(st.Current), PostURL: "/settings/updates/install",
			Detail: SizeText(s.Size) + " · " + SettingsWhen(now, s.StagedAt),
		}
		if cur, err := update.ParseVersion(st.Current); err == nil {
			if v, err := update.ParseVersion(s.Version); err == nil && v.Compare(cur) < 0 {
				c.Older = true
			}
		}
		return c, true
	}
	return SettingsInstallConfirm{}, false
}
