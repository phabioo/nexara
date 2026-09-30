package views

import "strings"

// Shell page states. Only ShellReady opens a WebSocket.
const (
	ShellReady    = "ready"    // online, shell capability on: the terminal connects
	ShellOffline  = "offline"  // the Grid Agent is not connected
	ShellDisabled = "disabled" // the shell capability is switched off for the host
)

// ShellKey is one button of the phone key bar. Name selects a special key
// (shell.js knows esc, tab, ctrl, alt, up, down, left, right); Text is sent
// literally.
type ShellKey struct {
	Label string
	Name  string
	Text  string
	Mod   bool // sticky modifier (Ctrl, Alt): applies to the next key
	Arrow bool // narrower button
}

// ShellKeys is the key bar of the mobile mockup: Esc, Tab, Ctrl, Alt, the four
// arrows and | ~ /.
func ShellKeys() []ShellKey {
	return []ShellKey{
		{Label: "Esc", Name: "esc"},
		{Label: "Tab", Name: "tab"},
		{Label: "Ctrl", Name: "ctrl", Mod: true},
		{Label: "Alt", Name: "alt", Mod: true},
		{Label: "↑", Name: "up", Arrow: true},
		{Label: "↓", Name: "down", Arrow: true},
		{Label: "←", Name: "left", Arrow: true},
		{Label: "→", Name: "right", Arrow: true},
		{Label: "|", Text: "|", Arrow: true},
		{Label: "~", Text: "~", Arrow: true},
		{Label: "/", Text: "/", Arrow: true},
	}
}

// ShellPage is the data of pages/shell.html.
type ShellPage struct {
	Layout

	State   string // ShellReady, ShellOffline or ShellDisabled
	Host    string // URL name of the host
	Label   string // display name
	Address string
	Version string // "v.6.6.51" (kernel), empty if unknown
	WSURL   string // WebSocket path incl. ?csrf=; empty unless State is ShellReady
	BackURL string // overview of the host
	Keys    []ShellKey
}

// KernelVersion shortens a kernel release for the terminal header:
// "6.6.51+rpt-rpi-2712" becomes "v.6.6.51". Empty input gives "".
func KernelVersion(kernel string) string {
	kernel = strings.TrimSpace(kernel)
	if kernel == "" {
		return ""
	}
	if i := strings.IndexAny(kernel, "+-_ "); i > 0 {
		kernel = kernel[:i]
	}
	return "v." + kernel
}
