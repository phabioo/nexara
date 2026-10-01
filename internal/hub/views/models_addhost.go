package views

// Add-host dialog modes.
const (
	AddHostModeSSH  = "ssh"
	AddHostModeCode = "code"
)

// Authentication choices of the SSH form.
const (
	AddHostAuthPassword = "password"
	AddHostAuthKey      = "key"
)

// Link progress states (AddHostProgress.State).
const (
	LinkStateRunning = "running"
	LinkStateOnline  = "online"
	LinkStateFailed  = "failed"
)

// AddHostForm holds the values the SSH form shows again after an error. It has
// no password field on purpose: the password is never sent back to the browser.
type AddHostForm struct {
	Address     string
	Port        string
	User        string
	DisplayName string
	Auth        string // AddHostAuthPassword or AddHostAuthKey
}

// AddHostStep is one row of the progress list. State is "wait", "run", "done" or "fail".
type AddHostStep struct {
	Label       string
	Detail      string
	Fingerprint string // SHA256:... host key, shown below the row (decision #41)
	State       string
}

// AddHostProgress is the progress list of a running or finished link attempt.
type AddHostProgress struct {
	Target     string // tag left of the state, for example "pi4" or the code
	State      string // LinkStateRunning, LinkStateOnline or LinkStateFailed
	StateLabel string
	Steps      []AddHostStep
	PollURL    string // hx-get target while running; empty when finished
	PollEvery  string // hx-trigger interval, for example "1s"
	Error      string // failure message (failed state)
	OpenURL    string // link to the new host (online state)
	OpenLabel  string // host name for "Open pi4"
	Retry      bool   // offer "Try again" (failed state)
	RetryURL   string // hx-get target of "Try again": the form, prefilled
	HostKeyTip bool   // show the fingerprint hint
}

// AddHostCode is the enrollment-code pane.
type AddHostCode struct {
	Code     string
	Command  string
	ValidFor string // "15 min"
	PollURL  string // status poll while waiting
	Expired  bool
}

// AddHostDialog is the data of the add-host partials.
type AddHostDialog struct {
	CSRF     string
	Mode     string // AddHostModeSSH or AddHostCode
	Form     AddHostForm
	HubKey   string // the hub's SSH public key, empty if none
	Error    string // pink error row
	Code     *AddHostCode
	Progress *AddHostProgress
}

// IsSSH reports whether the SSH tab is active.
func (d AddHostDialog) IsSSH() bool { return d.Mode != AddHostModeCode }

// AuthKey reports whether the hub SSH key option is selected.
func (d AddHostDialog) AuthKey() bool { return d.Form.Auth == AddHostAuthKey }
