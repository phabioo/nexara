package views

import "testing"

func TestShellKeys(t *testing.T) {
	keys := ShellKeys()
	var labels []string
	mods := 0
	for _, k := range keys {
		labels = append(labels, k.Label)
		if k.Mod {
			mods++
		}
		if (k.Name == "") == (k.Text == "") {
			t.Errorf("key %q needs exactly one of Name and Text", k.Label)
		}
	}
	want := []string{"Esc", "Tab", "Ctrl", "Alt", "↑", "↓", "←", "→", "|", "~", "/"}
	if len(labels) != len(want) {
		t.Fatalf("labels = %v, want %v", labels, want)
	}
	for i := range want {
		if labels[i] != want[i] {
			t.Errorf("key %d = %q, want %q", i, labels[i], want[i])
		}
	}
	if mods != 2 {
		t.Errorf("%d sticky modifiers, want 2 (Ctrl, Alt)", mods)
	}
}

func TestKernelVersion(t *testing.T) {
	tests := map[string]string{
		"6.6.51+rpt-rpi-2712": "v.6.6.51",
		"5.15.0-105-generic":  "v.5.15.0",
		"6.1":                 "v.6.1",
		"  6.8.0 ":            "v.6.8.0",
		"":                    "",
		"   ":                 "",
	}
	for in, want := range tests {
		if got := KernelVersion(in); got != want {
			t.Errorf("KernelVersion(%q) = %q, want %q", in, got, want)
		}
	}
}
