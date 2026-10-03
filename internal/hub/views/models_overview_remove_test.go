package views

import "testing"

func TestNewOverviewRemove(t *testing.T) {
	r := NewOverviewRemove("PI4", "/hosts/x")
	if r.Text != "Remove PI4? Its agent loses access immediately. To add it again, link it as a new host." ||
		r.PostURL != "/hosts/x/remove" || r.HostLabel != "PI4" {
		t.Errorf("got %+v", r)
	}
}
