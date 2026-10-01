package views

import (
	"io/fs"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/phabioo/nexara/internal/protocol"
	"github.com/phabioo/nexara/web"
)

func renderPartial(t *testing.T, name string, data any) string {
	t.Helper()
	r, err := New(web.Templates, Options{})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	if err := r.RenderPartial(rec, name, data); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return rec.Body.String()
}

func TestServicesBodyRendering(t *testing.T) {
	svc := &protocol.Services{Units: []protocol.ServiceUnit{
		{Name: "cloud-init-main.service", ActiveState: "inactive"},
		{Name: "ssh.service", ActiveState: "active"},
		{Name: "fstrim.service", ActiveState: "failed"},
		{Name: "apt-daily.service", ActiveState: "activating"},
	}}
	body := renderPartial(t, "overview-svc-body", NewOverviewServices("pi", svc, true, "/restart"))

	order := []string{"fstrim", "ssh", "apt-daily", "cloud-init-main"}
	last := -1
	for _, name := range order {
		i := strings.Index(body, ">"+name+"<")
		if i < 0 || i < last {
			t.Fatalf("unit %q missing or out of order (failed, active, busy, inactive) at %d after %d:\n%s", name, i, last, body)
		}
		last = i
	}
	for _, want := range []string{
		`1/4 running`, // only the active unit counts as running
		`<div class="svc-list">`,
		`<div class="svc-dim">`,                      // the inactive unit is dimmed ...
		`<div class="bar"><i class="p-0"></i></div>`, // ... with an empty bar ...
		`<b>–</b>`,                                   // ... and no check mark
		`class="p-50"`,                               // the unit in transition shows a half bar
		`data-ov-restart`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("output lacks %q:\n%s", want, body)
		}
	}
	if n := strings.Count(body, `class="svc-dim"`); n != 1 {
		t.Errorf("%d dimmed rows, want 1", n)
	}
	// the restart button sits after the list, outside the scroll region
	if strings.Index(body, "data-ov-restart") < strings.Index(body, "</div>\n  <button") {
		t.Errorf("restart button is inside the list")
	}
}

func TestTickerRendering(t *testing.T) {
	tests := []struct {
		name  string
		text  string
		class string
	}{
		{"short text is fast", "system up to date", "ticker ticker-blue ticker-short"},
		{"login band", "restricted access · nexara grid", `class="ticker ticker-blue"`},
		{"long text is slow", "connection to hub lost · reconnecting in 3 s", "ticker ticker-blue ticker-long"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := renderPartial(t, "ticker", map[string]any{"Variant": "blue", "Text": tc.text})
			if !strings.Contains(body, tc.class) {
				t.Errorf("lacks %q: %s", tc.class, body)
			}
			// the keyframes slide by 1/20 of the run: the unit count is part of the contract
			if n := strings.Count(body, `class="ticker-unit"`); n != 20 {
				t.Errorf("%d units, want 20", n)
			}
			if !strings.Contains(body, `aria-hidden="true"`) {
				t.Errorf("ticker must stay hidden from assistive technology")
			}
		})
	}
}

// The ticker slides by exactly one unit: 1 of 20 identical units is 5 % of the run.
func TestTickerKeyframesMatchUnitCount(t *testing.T) {
	css, err := fs.ReadFile(web.Static, "css/nexus.css")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(css), "@keyframes ticker-scroll { to { transform: translateX(-5%); } }") {
		t.Errorf("nexus.css: ticker-scroll must translate by 5%% (one of 20 units)")
	}
}
