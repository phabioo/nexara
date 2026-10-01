package views

import "testing"

func TestNewOverviewRemove(t *testing.T) {
	tests := []struct {
		name    string
		label   string
		isHub   bool
		text    string
		hubNote bool
	}{
		{"normal host", "PI4", false, "Remove PI4? Its agent loses access immediately. To add it again, link it as a new host.", false},
		{"hub's own host", "frpi5", true, "Remove frpi5? Its agent loses access immediately. To add it again, link it as a new host.", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := NewOverviewRemove(tc.label, "/hosts/x", tc.isHub)
			if r.Text != tc.text || r.PostURL != "/hosts/x/remove" || r.HostLabel != tc.label {
				t.Errorf("got %+v", r)
			}
			if (r.HubNote != "") != tc.hubNote {
				t.Errorf("HubNote = %q", r.HubNote)
			}
		})
	}
}
