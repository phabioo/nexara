package views

import "fmt"

// OverviewRemove is the data of the "Remove host" confirm dialog (partials/overview.html,
// "overview-remove"). It reuses the markup of the packages confirm dialog. The hub's own
// host never gets this dialog (decision #60).
type OverviewRemove struct {
	HostLabel string
	Text      string
	PostURL   string
}

// NewOverviewRemove builds the dialog for the host shown as hostLabel; hostPath is its URL ("/hosts/pi4").
func NewOverviewRemove(hostLabel, hostPath string) OverviewRemove {
	return OverviewRemove{
		HostLabel: hostLabel,
		PostURL:   hostPath + "/remove",
		Text: fmt.Sprintf("Remove %s? Its agent loses access immediately. To add it again, link it as a new host.",
			hostLabel),
	}
}
