package views

import (
	"regexp"
	"strings"
	"testing"
)

func TestQRSVG(t *testing.T) {
	tests := []struct {
		name    string
		content string
		level   QRLevel
		label   string
		wantErr bool
	}{
		{name: "url", content: "https://frpi5.local:8443/setup/trust/nexara-ca.crt", level: QRMedium, label: "CA"},
		{name: "otpauth low", content: "otpauth://totp/Nexara%20Nexus:fabio?secret=JBSWY3DPEHPK3PXP&issuer=Nexara%20Nexus", level: QRLow, label: "TOTP"},
		{name: "quartile", content: "hello", level: QRQuartile, label: "x"},
		{name: "high", content: "hello", level: QRHigh, label: "x"},
		{name: "label is escaped", content: "hello", level: QRMedium, label: `a"<b>&`},
		{name: "empty", content: "", wantErr: true},
		{name: "too long", content: strings.Repeat("a", qrMaxContent+1), wantErr: true},
	}
	viewBox := regexp.MustCompile(`viewBox="0 0 (\d+) (\d+)"`)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := QRSVG(tt.content, tt.level, tt.label)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			s := string(got)
			if !strings.HasPrefix(s, "<svg ") || !strings.HasSuffix(s, "</svg>") {
				t.Fatalf("not an svg element: %.80s", s)
			}
			m := viewBox.FindStringSubmatch(s)
			if m == nil || m[1] != m[2] {
				t.Fatalf("viewBox missing or not square: %v", m)
			}
			for _, bad := range []string{"<script", "style=", "data:", "javascript:"} {
				if strings.Contains(s, bad) {
					t.Errorf("output contains %q", bad)
				}
			}
			if regexp.MustCompile(`\son\w+=`).MatchString(s) {
				t.Error("event handler attribute in output")
			}
			if strings.Contains(tt.label, "<") && strings.Contains(s, "<b>") {
				t.Error("label not escaped")
			}
			if !strings.Contains(s, `role="img"`) || !strings.Contains(s, "aria-label=") {
				t.Error("accessible name missing")
			}
			if !strings.Contains(s, "<path") || !strings.Contains(s, " d=\"M") {
				t.Error("no module path")
			}
		})
	}
}

func TestQRSVGDeterministic(t *testing.T) {
	a, _ := QRSVG("same input", QRMedium, "l")
	b, _ := QRSVG("same input", QRMedium, "l")
	c, _ := QRSVG("other input", QRMedium, "l")
	if a != b {
		t.Error("same content produced different output")
	}
	if a == c {
		t.Error("different content produced identical output")
	}
}

// The three finder patterns are the one thing every QR code has: the top-left
// 7x7 block starts with a run of 7 dark modules on its first row.
func TestQRSVGHasFinderRun(t *testing.T) {
	got, err := QRSVG("finder", QRMedium, "l")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "M2 2h7v1h-7z") {
		t.Errorf("top-left finder run not found: %.200s", got)
	}
}
