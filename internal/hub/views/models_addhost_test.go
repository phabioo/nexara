package views

import "testing"

func TestAddHostDialogMode(t *testing.T) {
	tests := []struct {
		name    string
		d       AddHostDialog
		ssh     bool
		authKey bool
	}{
		{"default is SSH", AddHostDialog{}, true, false},
		{"ssh", AddHostDialog{Mode: AddHostModeSSH}, true, false},
		{"code", AddHostDialog{Mode: AddHostModeCode}, false, false},
		{"hub key", AddHostDialog{Form: AddHostForm{Auth: AddHostAuthKey}}, true, true},
		{"password", AddHostDialog{Form: AddHostForm{Auth: AddHostAuthPassword}}, true, false},
	}
	for _, tc := range tests {
		if tc.d.IsSSH() != tc.ssh || tc.d.AuthKey() != tc.authKey {
			t.Errorf("%s: IsSSH=%v AuthKey=%v", tc.name, tc.d.IsSSH(), tc.d.AuthKey())
		}
	}
}
