package views

import (
	"html/template"
	"strings"
	"testing"
	"time"
)

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		in   any
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{int64(1023), "1023 B"},
		{1024, "1 KB"},
		{uint64(3650722202), "3.4 GB"},
		{uint64(8) << 30, "8 GB"},
		{uint64(117) << 30, "117 GB"},
		{uint64(4) << 40, "4 TB"},
		{float64(2.9 * 1099511627776), "2.9 TB"},
		{float64(1536), "1.5 KB"},
		{-5, "0 B"},
	}
	for _, tc := range tests {
		got, err := formatBytes(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("formatBytes(%v) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
	if _, err := formatBytes("x"); err == nil {
		t.Error("formatBytes(string) should fail")
	}
}

func TestFormatPercent(t *testing.T) {
	tests := []struct {
		in   any
		want string
	}{{24, "24%"}, {23.6, "24%"}, {0, "0%"}, {100.0, "100%"}, {float32(7.4), "7%"}}
	for _, tc := range tests {
		got, err := formatPercent(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("formatPercent(%v) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		in   any
		want string
	}{
		{int64(41*86400 + 6*3600 + 59), "41D 06H"},
		{time.Duration(41*24+6) * time.Hour, "41D 06H"},
		{3*3600 + 12*60, "03H 12M"},
		{750, "12M 30S"},
		{0, "00M 00S"},
		{-10, "00M 00S"},
	}
	for _, tc := range tests {
		got, err := formatDuration(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("formatDuration(%v) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
}

func TestSeq(t *testing.T) {
	if got := seq(3); len(got) != 3 || got[2] != 2 {
		t.Errorf("seq(3) = %v", got)
	}
	if seq(-1) != nil || seq(1<<20) != nil {
		t.Error("seq out of range should be empty")
	}
}

func TestPctClass(t *testing.T) {
	tests := []struct {
		in   any
		want string
	}{{0, "p-0"}, {39, "p-39"}, {39.6, "p-40"}, {150, "p-100"}, {-3, "p-0"}, {nil, "p-0"}, {"x", "p-0"}}
	for _, tc := range tests {
		if got := pctClass(tc.in); got != tc.want {
			t.Errorf("pctClass(%v) = %q; want %q", tc.in, got, tc.want)
		}
	}
}

func TestDictAndHas(t *testing.T) {
	m, err := dict("A", 1, "B", "x")
	if err != nil || m["A"] != 1 || m["B"] != "x" {
		t.Errorf("dict = %v, %v", m, err)
	}
	if _, err := dict("A"); err == nil {
		t.Error("odd dict should fail")
	}
	if _, err := dict(1, 2); err == nil {
		t.Error("non-string key should fail")
	}
	for v, want := range map[string]bool{"nil": false, "empty": false, "text": true, "zero": true} {
		var in any
		switch v {
		case "empty":
			in = ""
		case "text":
			in = "a"
		case "zero":
			in = 0
		}
		if got := has(in); got != want {
			t.Errorf("has(%s) = %v; want %v", v, got, want)
		}
	}
}

func TestIcon(t *testing.T) {
	r := &Renderer{opts: Options{StaticBase: "/static/"}}
	got, err := r.icon("eye", 36)
	if err != nil {
		t.Fatal(err)
	}
	want := template.HTML(`<svg class="icon" width="36" height="28" aria-hidden="true" focusable="false"><use href="/static/img/icons.svg#i-eye"></use></svg>`)
	if got != want {
		t.Errorf("icon = %s; want %s", got, want)
	}
	native, _ := r.icon("arrow-right")
	if !strings.Contains(string(native), `width="16" height="12"`) {
		t.Errorf("native size missing: %s", native)
	}
	inline := &Renderer{opts: Options{StaticBase: "/static/", InlineSprite: "<svg></svg>"}}
	got, _ = inline.icon("check", 12)
	if !strings.Contains(string(got), `href="#i-check"`) {
		t.Errorf("inline href missing: %s", got)
	}
	if _, err := r.icon("nope"); err == nil {
		t.Error("unknown icon should fail")
	}
}
