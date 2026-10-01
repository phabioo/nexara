package views

import "fmt"

// OverviewRemove is the data of the "Remove host" confirm dialog (partials/overview.html,
// "overview-remove"). It reuses the markup of the packages confirm dialog.
type OverviewRemove struct {
	HostLabel string
	Text      string
	// HubNote is an extra warning shown when the host is the hub's own device; empty otherwise.
	HubNote string
	PostURL string
}

// NewOverviewRemove builds the dialog for the host shown as hostLabel; hostPath is its URL ("/hosts/pi4").
// isHub adds the warning that the hub's own agent is going away.
func NewOverviewRemove(hostLabel, hostPath string, isHub bool) OverviewRemove {
	r := OverviewRemove{
		HostLabel: hostLabel,
		PostURL:   hostPath + "/remove",
		Text: fmt.Sprintf("Remove %s? Its agent loses access immediately. To add it again, link it as a new host.",
			hostLabel),
	}
	if isHub {
		r.HubNote = "This is the hub's own agent. Nexara Nexus stops managing this device until you link it again."
	}
	return r
}
