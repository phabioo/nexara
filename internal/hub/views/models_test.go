package views

import "testing"

func TestNavItemsActive(t *testing.T) {
	l := Layout{ActiveNav: "packages", Nav: DefaultNav(3)}
	items := l.NavItems()
	if len(items) != 5 {
		t.Fatalf("v0.2 nav has %d items, want 5 (Overview, Packages, Shell, History, Settings)", len(items))
	}
	for _, it := range items {
		if want := it.Key == "history" || it.Key == "settings"; it.More != want {
			t.Errorf("%s in the phone's More sheet = %v, want %v", it.Key, it.More, want)
		}
	}
	for _, it := range items {
		if want := it.Key == "packages"; it.Active != want {
			t.Errorf("%s active = %v, want %v", it.Key, it.Active, want)
		}
	}
	if items[1].Badge != 3 {
		t.Errorf("packages badge = %d", items[1].Badge)
	}
	if l.Nav[1].Active {
		t.Error("NavItems must not modify Nav")
	}
}

func TestNewSetupSteps(t *testing.T) {
	s := NewSetupSteps([]string{"Unlock", "Trust", "Operator"}, 2)
	states := []string{"done", "on", "todo"}
	for i, it := range s.Items {
		if it.State != states[i] || it.Num != i+1 {
			t.Errorf("step %d = %+v", i, it)
		}
	}
	if s.CurrentLabel != "Trust" || s.NextLabel != "Operator" || s.Total != 3 || s.Current != 2 {
		t.Errorf("summary = %+v", s)
	}
	if last := NewSetupSteps([]string{"A", "B"}, 2); last.NextLabel != "" {
		t.Errorf("last step has next label %q", last.NextLabel)
	}
}

func TestPillLabelOrDefault(t *testing.T) {
	if (AuthLayout{}).PillLabelOrDefault() != "Nexus" || (AuthLayout{PillLabel: "X"}).PillLabelOrDefault() != "X" {
		t.Error("PillLabelOrDefault")
	}
}
