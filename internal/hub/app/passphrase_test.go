package app

import (
	"strings"
	"testing"

	"github.com/phabioo/nexara/internal/hub/auth"
)

func TestCheckWizardPassphrase(t *testing.T) {
	tests := []struct {
		name string
		pass string
		want string // "" = accepted
	}{
		{"exactly the minimum", strings.Repeat("a", auth.MinPassphraseLength), ""},
		{"long enough with spaces and umlauts", "correct horse battery ä ö ü", ""},
		{"exactly the maximum", strings.Repeat("a", auth.MaxPassphraseLength), ""},
		{"one too short", strings.Repeat("a", auth.MinPassphraseLength-1), "Use at least 12 characters."},
		{"empty", "", "Use at least 12 characters."},
		{"one too long", strings.Repeat("a", auth.MaxPassphraseLength+1), "Use at most 1024 characters."},
		{"multi-byte runes count as one", strings.Repeat("ä", auth.MinPassphraseLength-1), "Use at least 12 characters."},
		{"not valid UTF-8", strings.Repeat("a", 20) + "\xff", "Use valid text characters only."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkWizardPassphrase(tt.pass)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("err = %v", err)
				}
				return
			}
			if err == nil || err.Error() != tt.want {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
			if strings.Contains(err.Error(), "auth:") {
				t.Errorf("internal error text reaches the form: %q", err)
			}
		})
	}
}
