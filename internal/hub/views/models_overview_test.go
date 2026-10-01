package views

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/protocol"
)

func TestCPUCurve(t *testing.T) {
	tests := []struct {
		name     string
		in       []float64
		wantLine string
		wantArea string
	}{
		{"empty", nil, "", ""},
		{"one sample is drawn flat", []float64{50}, "0.0,53.0 300.0,53.0", "0,100 0.0,53.0 300.0,53.0 300,100"},
		{"two samples span the width", []float64{0, 100}, "0.0,97.1 300.0,8.0", "0,100 0.0,97.1 300.0,8.0 300,100"},
		{"three samples", []float64{10, 20, 30}, "0.0,89.0 150.0,80.0 300.0,71.0", "0,100 0.0,89.0 150.0,80.0 300.0,71.0 300,100"},
		{"clamped and NaN", []float64{-5, 250, math.NaN()}, "0.0,97.1 150.0,8.0 300.0,97.1", "0,100 0.0,97.1 150.0,8.0 300.0,97.1 300,100"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			line, area := CPUCurve(tc.in)
			if line != tc.wantLine || area != tc.wantArea {
				t.Errorf("got\n%q\n%q\nwant\n%q\n%q", line, area, tc.wantLine, tc.wantArea)
			}
		})
	}

	t.Run("point count follows the history", func(t *testing.T) {
		hist := make([]float64, 60)
		line, _ := CPUCurve(hist)
		if n := len(strings.Fields(line)); n != 60 {
			t.Errorf("%d points, want 60", n)
		}
		if !strings.HasSuffix(line, " 300.0,97.1") {
			t.Errorf("last point %q", line[len(line)-12:])
		}
	})
}

func f64(v float64) *float64 { return &v }

func TestNewOverviewCPU(t *testing.T) {
	tests := []struct {
		name  string
		model string
		m     *protocol.Metrics
		want  OverviewCPU
	}{
		{"no sample", "Pi", nil, OverviewCPU{}},
		{
			name: "raspberry pi with temperature", model: "Raspberry Pi 5 Model B Rev 1.0",
			m: &protocol.Metrics{CPUPercent: 23.6, CPUPerCore: []float64{28.4, 0, 100, 140}, TempC: f64(47.2),
				MemTotal: 1000, TopProcesses: []protocol.Process{{Name: "a", CPU: 12.44, MemBytes: 41}}},
			want: OverviewCPU{
				Ready:   true,
				Text:    "Raspberry Pi 5 Model B Rev 1.0, 4 cores. Currently at 24% utilisation, SoC temperature 47.2 °C. Throttling starts at 80 °C.",
				Cores:   []OverviewCore{{"Core 0", 28}, {"Core 1", 0}, {"Core 2", 100}, {"Core 3", 100}},
				HasTemp: true, TempPct: 56, TempInt: 47,
				Procs: []OverviewProc{{"a", "12.4%", "4.1%"}},
			},
		},
		{
			name: "hot, other board", model: "Some Board",
			m: &protocol.Metrics{CPUPercent: 5, CPUPerCore: []float64{5}, TempC: f64(82.6)},
			want: OverviewCPU{
				Ready: true, Text: "Some Board, 1 core. Currently at 5% utilisation, SoC temperature 82.6 °C.",
				Cores: []OverviewCore{{"Core 0", 5}}, HasTemp: true, TempPct: 97, TempInt: 83, TempHot: true,
			},
		},
		{
			name: "no model, no sensor", model: " ",
			m:    &protocol.Metrics{CPUPercent: 10, CPUPerCore: []float64{10, 10}},
			want: OverviewCPU{Ready: true, Text: "2 cores. Currently at 10% utilisation.", Cores: []OverviewCore{{"Core 0", 10}, {"Core 1", 10}}},
		},
		{
			name: "model only", model: "Board",
			m:    &protocol.Metrics{CPUPercent: 1},
			want: OverviewCPU{Ready: true, Text: "Board. Currently at 1% utilisation."},
		},
		{
			name: "process list is capped and memory unknown",
			m: &protocol.Metrics{CPUPerCore: []float64{1}, TopProcesses: []protocol.Process{
				{Name: "1"}, {Name: "2"}, {Name: "3"}, {Name: "4"}, {Name: "5"}, {Name: "6"}, {Name: "7"}, {Name: "8"}, {Name: "9"}}},
			want: OverviewCPU{Ready: true, Text: "1 core. Currently at 0% utilisation.", Cores: []OverviewCore{{"Core 0", 1}},
				Procs: []OverviewProc{{"1", "0.0%", "–"}, {"2", "0.0%", "–"}, {"3", "0.0%", "–"}, {"4", "0.0%", "–"},
					{"5", "0.0%", "–"}, {"6", "0.0%", "–"}, {"7", "0.0%", "–"}, {"8", "0.0%", "–"}}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := NewOverviewCPU(tc.model, tc.m)
			if got.Ready != tc.want.Ready || got.Text != tc.want.Text || got.HasTemp != tc.want.HasTemp ||
				got.TempPct != tc.want.TempPct || got.TempInt != tc.want.TempInt || got.TempHot != tc.want.TempHot {
				t.Errorf("got %+v\nwant %+v", got, tc.want)
			}
			if len(got.Cores) != len(tc.want.Cores) || len(got.Procs) != len(tc.want.Procs) {
				t.Fatalf("cores/procs: got %+v\nwant %+v", got, tc.want)
			}
			for i := range got.Cores {
				if got.Cores[i] != tc.want.Cores[i] {
					t.Errorf("core %d: %+v, want %+v", i, got.Cores[i], tc.want.Cores[i])
				}
			}
			for i := range got.Procs {
				if got.Procs[i] != tc.want.Procs[i] {
					t.Errorf("proc %d: %+v, want %+v", i, got.Procs[i], tc.want.Procs[i])
				}
			}
		})
	}
}

func TestCPUTitle(t *testing.T) {
	tests := []struct {
		m    *protocol.Metrics
		want string
	}{
		{nil, "CPU"},
		{&protocol.Metrics{}, "CPU"},
		{&protocol.Metrics{CPUPerCore: []float64{1}}, "CPU · 1 Core"},
		{&protocol.Metrics{CPUPerCore: []float64{1, 2, 3, 4}}, "CPU · 4 Cores"},
	}
	for _, tc := range tests {
		if got := CPUTitle(tc.m); got != tc.want {
			t.Errorf("CPUTitle = %q, want %q", got, tc.want)
		}
	}
}

func TestNewOverviewMem(t *testing.T) {
	const gib = 1 << 30
	m := &protocol.Metrics{
		CPUPercent: 24.4, MemTotal: 8 * gib, MemUsed: 3_650_722_201, SwapTotal: 2 * gib,
		Disks: []protocol.Disk{
			{Mount: "/", Total: 117_000_000_000, Used: 41_000_000_000},
			{Mount: "/mnt/data", Total: 4_000_000_000_000, Used: 2_900_000_000_000},
		},
		Net: protocol.NetRate{Iface: "eth0", RxBytesPerSec: 1.2e6, TxBytesPerSec: 8.64e6},
	}
	got := NewOverviewMem(m, make([]float64, 60), "/hosts/x/shell")
	if !got.Ready || got.Tag != "Healthy" || got.CPUNow != "24%" || got.ChartLabel != "CPU · LAST 120 S" || got.ShellHref != "/hosts/x/shell" {
		t.Errorf("header fields: %+v", got)
	}
	if want := "3.4 of 8 GB RAM in use. Network: ↓ 1.2 MB/s · ↑ 8.6 MB/s on eth0."; got.Text != want {
		t.Errorf("text %q, want %q", got.Text, want)
	}
	want := []OverviewTile{
		{Tone: "blue", Label: "RAM", Value: "3.4 / 8 GB", On: 7},
		{Tone: "purple", Label: "Swap", Value: "0 / 2 GB", On: 0},
		{Tone: "grey", Label: "Disk /", Value: "41 / 117 GB", On: 6},
		{Tone: "grey", Label: "Disk /mnt/data", Value: "2.9 / 4 TB", On: 12},
	}
	if len(got.Tiles) != len(want) {
		t.Fatalf("%d tiles: %+v", len(got.Tiles), got.Tiles)
	}
	for i := range want {
		if got.Tiles[i] != want[i] {
			t.Errorf("tile %d: %+v, want %+v", i, got.Tiles[i], want[i])
		}
	}

	t.Run("no sample", func(t *testing.T) {
		if g := NewOverviewMem(nil, nil, "/s"); g.Ready || g.ShellHref != "/s" {
			t.Errorf("%+v", g)
		}
	})
	t.Run("one disk leaves an empty slot", func(t *testing.T) {
		g := NewOverviewMem(&protocol.Metrics{MemTotal: gib, Disks: m.Disks[:1]}, nil, "")
		if len(g.Tiles) != 4 || !g.Tiles[3].Empty || g.Tiles[2].Empty {
			t.Errorf("%+v", g.Tiles)
		}
	})
	t.Run("full disk changes the tag", func(t *testing.T) {
		g := NewOverviewMem(&protocol.Metrics{MemTotal: gib, Disks: []protocol.Disk{{Mount: "/", Total: 100, Used: 95}}}, nil, "")
		if g.Tag != "Disk almost full" {
			t.Errorf("tag %q", g.Tag)
		}
	})
	t.Run("no interface name, no history", func(t *testing.T) {
		g := NewOverviewMem(&protocol.Metrics{MemTotal: gib, MemUsed: gib / 2}, nil, "")
		if !strings.HasSuffix(g.Text, "↑ 0.0 MB/s.") || g.CurveLine != "" || g.ChartLabel != "CPU · LAST 0 S" {
			t.Errorf("%+v", g)
		}
	})
}

func TestNewOverviewServices(t *testing.T) {
	svc := &protocol.Services{
		Units: []protocol.ServiceUnit{
			{Name: "ssh.service", ActiveState: "active"},
			{Name: "smbd.service", ActiveState: "failed"},
			{Name: "cron", ActiveState: "inactive"},
			{Name: "apt-daily.service", ActiveState: "activating"},
			{Name: "nmbd.service", ActiveState: "active"},
		},
		Ports: []protocol.ListeningPort{{Proto: "tcp", Port: 22}, {Proto: "tcp", Port: 22}, {Proto: "udp", Port: 5353}},
	}
	tests := []struct {
		name    string
		svc     *protocol.Services
		enabled bool
		check   func(t *testing.T, g OverviewServices)
	}{
		{"capability off", svc, false, func(t *testing.T, g OverviewServices) {
			if !g.Disabled || g.Ready || len(g.Units) != 0 {
				t.Errorf("%+v", g)
			}
		}},
		{"not fetched yet", nil, true, func(t *testing.T, g OverviewServices) {
			if g.Disabled || g.Ready {
				t.Errorf("%+v", g)
			}
		}},
		{"list", svc, true, func(t *testing.T, g OverviewServices) {
			if !g.Ready || g.Failed != 1 || g.Tag != "2/5 running" || g.RestartURL != "/r" {
				t.Errorf("%+v", g)
			}
			if g.Text != "systemd units on pi. Listening on 22 and 5353/udp." {
				t.Errorf("text %q", g.Text)
			}
			// failed first, then active (agent order kept), then units in transition, then inactive
			wantUnits := []OverviewUnit{
				{Name: "smbd", State: "failed", Bad: true},
				{Name: "ssh", State: "active"},
				{Name: "nmbd", State: "active"},
				{Name: "apt-daily", State: "activating", Busy: true},
				{Name: "cron", State: "inactive", Dim: true},
			}
			if len(g.Units) != len(wantUnits) {
				t.Fatalf("%d units, want %d", len(g.Units), len(wantUnits))
			}
			for i, u := range wantUnits {
				if g.Units[i] != u {
					t.Errorf("unit %d: %+v, want %+v", i, g.Units[i], u)
				}
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { tc.check(t, NewOverviewServices("pi", tc.svc, tc.enabled, "/r")) })
	}
}

func TestPortsText(t *testing.T) {
	tcp := func(p uint16) protocol.ListeningPort { return protocol.ListeningPort{Proto: "tcp", Port: p} }
	tests := []struct {
		name  string
		ports []protocol.ListeningPort
		want  string
	}{
		{"none", nil, "No listening ports reported."},
		{"one", []protocol.ListeningPort{tcp(22)}, "Listening on 22."},
		{"two", []protocol.ListeningPort{tcp(22), tcp(445)}, "Listening on 22 and 445."},
		{"design", []protocol.ListeningPort{tcp(22), tcp(445), tcp(32400), {Proto: "udp", Port: 5353}}, "Listening on 22, 445, 32400 and 5353/udp."},
		{"same port on tcp and udp", []protocol.ListeningPort{tcp(53), {Proto: "udp", Port: 53}}, "Listening on 53 and 53/udp."},
		{"duplicates", []protocol.ListeningPort{tcp(22), tcp(22)}, "Listening on 22."},
		{"many", []protocol.ListeningPort{tcp(1), tcp(2), tcp(3), tcp(4), tcp(5), tcp(6), tcp(7), tcp(8)}, "Listening on 1, 2, 3, 4, 5, 6 and 2 more."},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := PortsText(tc.ports); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestLoadText(t *testing.T) {
	if got := LoadText([3]float64{0.424, 0.385, 12}); got != "0.42 0.39 12.00" {
		t.Errorf("got %q", got)
	}
}

func TestAgoText(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		t    time.Time
		want string
	}{
		{"never", time.Time{}, "never"},
		{"seconds", now.Add(-20 * time.Second), "just now"},
		{"future", now.Add(time.Minute), "just now"},
		{"minutes", now.Add(-12*time.Minute - 5*time.Second), "12 min ago"},
		{"hours", now.Add(-3 * time.Hour), "3 h ago"},
		{"47 hours", now.Add(-47 * time.Hour), "47 h ago"},
		{"days", now.Add(-72 * time.Hour), "3 d ago"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := AgoText(now, tc.t); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestOverviewNumberHelpers(t *testing.T) {
	t.Run("pairText", func(t *testing.T) {
		const gib = 1 << 30
		tests := []struct {
			used, total uint64
			base        float64
			want        string
		}{
			{0, 0, 1024, "–"},
			{3_650_722_201, 8 * gib, 1024, "3.4 / 8 GB"},
			{0, 2 * gib, 1024, "0 / 2 GB"},
			{41_000_000_000, 117_000_000_000, 1000, "41 / 117 GB"},
			{2_900_000_000_000, 4_000_000_000_000, 1000, "2.9 / 4 TB"},
			{100 << 20, 107 << 20, 1024, "100 / 107 MB"},
			{512, 1000, 1024, "512 / 1000 B"},
		}
		for _, tc := range tests {
			if got := pairText(tc.used, tc.total, tc.base); got != tc.want {
				t.Errorf("pairText(%d,%d,%v) = %q, want %q", tc.used, tc.total, tc.base, got, tc.want)
			}
		}
	})
	t.Run("cells", func(t *testing.T) {
		tests := []struct {
			used, total uint64
			want        int
		}{{0, 10, 0}, {5, 0, 0}, {1, 1000, 1}, {425, 1000, 7}, {1, 2, 8}, {10, 10, 16}, {50, 10, 16}}
		for _, tc := range tests {
			if got := cells(tc.used, tc.total); got != tc.want {
				t.Errorf("cells(%d,%d) = %d, want %d", tc.used, tc.total, got, tc.want)
			}
		}
	})
	t.Run("rate", func(t *testing.T) {
		for in, want := range map[float64]string{0: "0.0", 1.25e6: "1.2", 8.6e6: "8.6", -5: "0.0", math.NaN(): "0.0"} {
			if got := rate(in); got != want && !(math.IsNaN(in) && got == "0.0") {
				t.Errorf("rate(%v) = %q, want %q", in, got, want)
			}
		}
	})
	t.Run("roundPct", func(t *testing.T) {
		for in, want := range map[float64]int{-3: 0, 0.4: 0, 0.5: 1, 99.6: 100, 250: 100} {
			if got := roundPct(in); got != want {
				t.Errorf("roundPct(%v) = %d, want %d", in, got, want)
			}
		}
		if roundPct(math.NaN()) != 0 {
			t.Error("NaN")
		}
	})
}
