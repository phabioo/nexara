package views

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/history"
)

func berlin(t *testing.T) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Skipf("no time zone database: %v", err)
	}
	return loc
}

// mkSeries builds a series on a grid of step from start; vals are the averages, NaN is a gap. Peaks are the
// averages plus peakAdd.
func mkSeries(metric history.Metric, start time.Time, step time.Duration, peakAdd float64, vals ...float64) history.Series {
	s := history.Series{Host: "h", Metric: metric, From: start, Step: step}
	for i, v := range vals {
		s.Points = append(s.Points, history.Point{Time: start.Add(time.Duration(i) * step), Avg: v, Max: v + peakAdd})
	}
	return s
}

func gapSeries(metric history.Metric, start time.Time, step time.Duration, n int) history.Series {
	vals := make([]float64, n)
	for i := range vals {
		vals[i] = nan
	}
	return mkSeries(metric, start, step, 0, vals...)
}

func TestHistoryAxisLabel(t *testing.T) {
	loc := berlin(t)
	tests := []struct {
		name string
		at   time.Time
		key  string
		loc  *time.Location
		want string
	}{
		{"24h summer time", time.Date(2026, 10, 24, 10, 0, 0, 0, time.UTC), "24h", loc, "Sat 12:00"},
		{"24h winter time", time.Date(2026, 12, 24, 10, 0, 0, 0, time.UTC), "24h", loc, "Thu 11:00"},
		// 2026-10-25 03:00 CEST falls back to 02:00 CET: the hour 02:xx exists twice, one hour apart.
		{"first 02:30 on the day the clocks go back", time.Date(2026, 10, 25, 0, 30, 0, 0, time.UTC), "24h", loc, "Sun 02:30"},
		{"second 02:30 on the day the clocks go back", time.Date(2026, 10, 25, 1, 30, 0, 0, time.UTC), "24h", loc, "Sun 02:30"},
		{"after the change", time.Date(2026, 10, 25, 2, 0, 0, 0, time.UTC), "24h", loc, "Sun 03:00"},
		// 2026-03-29 02:00 CET jumps to 03:00 CEST: there is no 02:xx.
		{"before the spring change", time.Date(2026, 3, 29, 0, 59, 0, 0, time.UTC), "24h", loc, "Sun 01:59"},
		{"after the spring change", time.Date(2026, 3, 29, 1, 0, 0, 0, time.UTC), "24h", loc, "Sun 03:00"},
		{"7d shows the date", time.Date(2026, 10, 25, 0, 30, 0, 0, time.UTC), "7d", loc, "Sun 25 Oct"},
		{"30d shows the short date", time.Date(2026, 10, 25, 0, 30, 0, 0, time.UTC), "30d", loc, "25 Oct"},
		{"the date follows the zone, not UTC", time.Date(2026, 10, 24, 22, 30, 0, 0, time.UTC), "30d", loc, "25 Oct"},
		{"no zone means UTC", time.Date(2026, 10, 24, 22, 30, 0, 0, time.UTC), "24h", nil, "Sat 22:30"},
		{"unknown range falls back to the clock", time.Date(2026, 10, 24, 22, 30, 0, 0, time.UTC), "", time.UTC, "Sat 22:30"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := HistoryAxisLabel(tc.at, tc.key, tc.loc); got != tc.want {
				t.Errorf("HistoryAxisLabel = %q, want %q", got, tc.want)
			}
		})
	}
}

// The middle label is the middle instant of the range, not the middle of the wall clock: on a day with a clock
// change the two differ by half an hour.
func TestHistoryChartsAxisAcrossDST(t *testing.T) {
	loc := berlin(t)
	tests := []struct {
		name   string
		start  time.Time
		x0, xm string
	}{
		{"autumn change inside the range", time.Date(2026, 10, 24, 11, 0, 0, 0, time.UTC), "Sat 13:00", "Sun 01:00"},
		{"spring change inside the range", time.Date(2026, 3, 28, 11, 0, 0, 0, time.UTC), "Sat 12:00", "Sun 00:00"},
		{"no change", time.Date(2026, 6, 10, 10, 0, 0, 0, time.UTC), "Wed 12:00", "Thu 00:00"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vals := make([]float64, 288)
			for i := range vals {
				vals[i] = 10
			}
			in := HistoryInput{
				Label: "alpha", Online: true, Loc: loc, Range: history.Ranges[0],
				CPU: mkSeries(history.MetricCPU, tc.start, 5*time.Minute, 0, vals...),
			}
			got := NewHistoryCharts(in)
			if got.State != HistoryOK || len(got.Charts) != 4 {
				t.Fatalf("state %q, %d charts", got.State, len(got.Charts))
			}
			c := got.Charts[0]
			if c.X0 != tc.x0 || c.XMid != tc.xm || c.X1 != "NOW" {
				t.Errorf("axis = %q / %q / %q, want %q / %q / NOW", c.X0, c.XMid, c.X1, tc.x0, tc.xm)
			}
		})
	}
}

func TestNewHistoryRanges(t *testing.T) {
	tests := []struct {
		active string
		hrefs  []string
		on     int
	}{
		{"24h", []string{"/hosts/a/history", "/hosts/a/history?range=7d", "/hosts/a/history?range=30d"}, 0},
		{"7d", []string{"/hosts/a/history", "/hosts/a/history?range=7d", "/hosts/a/history?range=30d"}, 1},
		{"30d", []string{"/hosts/a/history", "/hosts/a/history?range=7d", "/hosts/a/history?range=30d"}, 2},
	}
	for _, tc := range tests {
		t.Run(tc.active, func(t *testing.T) {
			tabs := NewHistoryRanges("/hosts/a/history", tc.active)
			if len(tabs) != 3 {
				t.Fatalf("%d tabs", len(tabs))
			}
			for i, tab := range tabs {
				if tab.Href != tc.hrefs[i] {
					t.Errorf("tab %d href %q, want %q", i, tab.Href, tc.hrefs[i])
				}
				if tab.Active != (i == tc.on) {
					t.Errorf("tab %d active = %v", i, tab.Active)
				}
			}
			if tabs[0].Label != "24 h" || tabs[1].Label != "7 days" || tabs[2].Label != "30 days" {
				t.Errorf("labels %q %q %q", tabs[0].Label, tabs[1].Label, tabs[2].Label)
			}
		})
	}
}

func TestNewHistoryChartsStates(t *testing.T) {
	start := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	step := 5 * time.Minute
	data := func() HistoryInput {
		return HistoryInput{
			Label: "alpha", Online: true, Loc: time.UTC, Range: history.Ranges[0],
			CPU: mkSeries(history.MetricCPU, start, step, 5, 10, 20, 30),
			Mem: func() history.Series {
				s := mkSeries(history.MetricMem, start, step, 0, 2<<30, 4<<30, 2<<30)
				s.Total = 8 << 30
				return s
			}(),
			Temp: mkSeries(history.MetricTemp, start, step, 1, 45, 50, 47.25),
			Rx:   mkSeries(history.MetricNetRx, start, step, 0, 1000, 2000, 3000),
			Tx:   mkSeries(history.MetricNetTx, start, step, 0, 100, 200, 300),
		}
	}
	empty := func() HistoryInput {
		in := data()
		in.CPU = gapSeries(history.MetricCPU, start, step, 3)
		in.Mem = gapSeries(history.MetricMem, start, step, 3)
		in.Temp = gapSeries(history.MetricTemp, start, step, 3)
		in.Rx = gapSeries(history.MetricNetRx, start, step, 3)
		in.Tx = gapSeries(history.MetricNetTx, start, step, 3)
		return in
	}
	tests := []struct {
		name  string
		in    func() HistoryInput
		state string
		check func(t *testing.T, h HistoryCharts)
	}{
		{
			name: "online host with data", in: data, state: HistoryOK,
			check: func(t *testing.T, h HistoryCharts) {
				if h.Notice != "" || len(h.Disks) != 0 {
					t.Errorf("notice %q disks %d", h.Notice, len(h.Disks))
				}
				keys := []string{"cpu", "mem", "temp", "net"}
				for i, c := range h.Charts {
					if c.Key != keys[i] {
						t.Errorf("chart %d key %q", i, c.Key)
					}
				}
				cpu := h.Charts[0]
				if cpu.Title != "CPU · 24H" || cpu.Now != "30" || cpu.Unit != "%" || cpu.Stats != "MIN 10 · AVG 20 · MAX 35" || cpu.Tone != "lime" {
					t.Errorf("cpu %+v", cpu)
				}
				if cpu.Line == "" || cpu.Area == "" || cpu.Empty != "" {
					t.Errorf("cpu plot %q %q %q", cpu.Line, cpu.Area, cpu.Empty)
				}
				mem := h.Charts[1]
				if mem.Now != "25" || mem.Unit != "%" || mem.Stats != "MIN 25 · AVG 33 · MAX 50" || mem.Note != "8 GB total" {
					t.Errorf("mem %+v", mem)
				}
				temp := h.Charts[2]
				if temp.Now != "47.2" && temp.Now != "47.3" { // 47.25 rounds either way
					t.Errorf("temp now %q", temp.Now)
				}
				if temp.Unit != "°C" || !strings.HasPrefix(temp.Stats, "MIN 45.0 · AVG 47.4 ·") {
					t.Errorf("temp %+v", temp)
				}
				net := h.Charts[3]
				if net.Unit != "KB/s ↓" || net.Now != "2.9" || net.Stats != "MIN 1.0 · AVG 2.0 · MAX 2.9" ||
					net.Stats2 != "↑ MIN 0.1 · AVG 0.2 · MAX 0.3" || net.Line2 == "" || net.Note != "GREEN ↓ RX · PURPLE ↑ TX" {
					t.Errorf("net %+v", net)
				}
			},
		},
		{
			name: "no history at all", in: empty, state: HistoryEmpty,
			check: func(t *testing.T, h HistoryCharts) {
				if h.Message != "History starts collecting when the agent is online." || len(h.Charts) != 0 {
					t.Errorf("message %q, %d charts", h.Message, len(h.Charts))
				}
			},
		},
		{
			name: "offline host keeps its history and gets a notice", state: HistoryOK,
			in: func() HistoryInput {
				in := data()
				in.Online, in.LastSeen = false, "3 h ago"
				return in
			},
			check: func(t *testing.T, h HistoryCharts) {
				want := "alpha is offline. The charts show the history collected while its agent was connected. Last seen 3 h ago."
				if h.Notice != want || len(h.Charts) != 4 {
					t.Errorf("notice %q, %d charts", h.Notice, len(h.Charts))
				}
			},
		},
		{
			name: "offline and never seen", state: HistoryEmpty,
			in: func() HistoryInput {
				in := empty()
				in.Online, in.LastSeen = false, "never"
				return in
			},
			check: func(t *testing.T, h HistoryCharts) {
				if h.Notice != "alpha is offline." {
					t.Errorf("notice %q", h.Notice)
				}
			},
		},
		{
			name: "host without a temperature sensor", state: HistoryOK,
			in: func() HistoryInput {
				in := data()
				in.Temp = gapSeries(history.MetricTemp, start, step, 3)
				return in
			},
			check: func(t *testing.T, h HistoryCharts) {
				temp := h.Charts[2]
				if temp.Empty != "No temperature sensor reported" || temp.Line != "" || temp.Now != "–" || temp.Stats != "" {
					t.Errorf("temp %+v", temp)
				}
				if h.Charts[0].Line == "" {
					t.Error("the other charts must still draw")
				}
			},
		},
		{
			name: "silent for longer than the lookback: no current value, history stays", state: HistoryOK,
			in: func() HistoryInput {
				in := data()
				in.CPU = mkSeries(history.MetricCPU, start, step, 0, 10, 20, nan, nan, nan)
				return in
			},
			check: func(t *testing.T, h HistoryCharts) {
				cpu := h.Charts[0]
				if cpu.Now != "–" || cpu.Unit != "" || cpu.Stats != "MIN 10 · AVG 15 · MAX 20" || cpu.Line == "" {
					t.Errorf("cpu %+v", cpu)
				}
			},
		},
		{
			name: "memory without a total cannot be shown", state: HistoryOK,
			in: func() HistoryInput {
				in := data()
				in.Mem.Total = 0
				return in
			},
			check: func(t *testing.T, h HistoryCharts) {
				if m := h.Charts[1]; m.Empty != "No data in this range" || m.Note != "" {
					t.Errorf("mem %+v", m)
				}
			},
		},
		{
			name: "disks", state: HistoryOK,
			in: func() HistoryInput {
				in := data()
				root := mkSeries(history.MetricDisk("/"), start, step, 0, 40e9, 40e9, 41e9)
				root.Total = 100e9
				data := mkSeries(history.MetricDisk("/mnt/data"), start, step, 0, nan, nan, nan)
				data.Total = 4e12
				in.Disks = []history.Series{root, data}
				return in
			},
			check: func(t *testing.T, h HistoryCharts) {
				if len(h.Disks) != 2 {
					t.Fatalf("%d disks", len(h.Disks))
				}
				root, data := h.Disks[0], h.Disks[1]
				if root.Title != "Disk / · 24H" || root.Now != "41" || root.Note != "38 GB of 93 GB" || root.Tone != "grey" {
					t.Errorf("root %+v", root)
				}
				if data.Title != "Disk /mnt/data · 24H" || data.Empty == "" || data.Note != "3.6 TB total" {
					t.Errorf("data %+v", data)
				}
			},
		},
		{
			name: "no more than twelve disks", state: HistoryOK,
			in: func() HistoryInput {
				in := data()
				for i := 0; i < 20; i++ {
					d := mkSeries(history.MetricDisk("/m"+string(rune('a'+i))), start, step, 0, 1, 1, 1)
					d.Total = 10
					in.Disks = append(in.Disks, d)
				}
				return in
			},
			check: func(t *testing.T, h HistoryCharts) {
				if len(h.Disks) != 12 {
					t.Errorf("%d disks", len(h.Disks))
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := NewHistoryCharts(tc.in())
			if h.State != tc.state {
				t.Fatalf("state %q, want %q", h.State, tc.state)
			}
			tc.check(t, h)
		})
	}
}

func TestNewHistoryChartsNetworkUnits(t *testing.T) {
	start := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name     string
		rx, tx   []float64
		wantUnit string
		wantNow  string
	}{
		{"bytes", []float64{100, 200}, []float64{10, 20}, "B/s ↓", "200"},
		{"kilobytes", []float64{1024, 2048}, []float64{10, 20}, "KB/s ↓", "2.0"},
		{"the upload decides the unit", []float64{1000, 2000}, []float64{5 << 20, 1 << 20}, "MB/s ↓", "0.0"},
		{"megabytes", []float64{1 << 20, 3 << 20}, []float64{0, 0}, "MB/s ↓", "3.0"},
		{"gigabytes", []float64{1 << 30, 2 << 30}, []float64{0, 0}, "GB/s ↓", "2.0"},
		{"all zero stays in bytes", []float64{0, 0}, []float64{0, 0}, "B/s ↓", "0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := HistoryInput{
				Online: true, Loc: time.UTC, Range: history.Ranges[0],
				CPU: mkSeries(history.MetricCPU, start, time.Minute, 0, 1, 2),
				Rx:  mkSeries(history.MetricNetRx, start, time.Minute, 0, tc.rx...),
				Tx:  mkSeries(history.MetricNetTx, start, time.Minute, 0, tc.tx...),
			}
			net := NewHistoryCharts(in).Charts[3]
			if net.Unit != tc.wantUnit || net.Now != tc.wantNow {
				t.Errorf("unit %q now %q, want %q %q", net.Unit, net.Now, tc.wantUnit, tc.wantNow)
			}
			if strings.Contains(net.Line+net.Line2+net.Area, "NaN") {
				t.Errorf("non-finite path: %q", net.Line)
			}
		})
	}
}

// A gap in the data is a break in the path, in the rendered card as well.
func TestNewHistoryChartsGapIsABreak(t *testing.T) {
	start := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	in := HistoryInput{
		Online: true, Loc: time.UTC, Range: history.Ranges[0],
		CPU: mkSeries(history.MetricCPU, start, 5*time.Minute, 0, 50, 50, nan, nan, 50, 50),
	}
	cpu := NewHistoryCharts(in).Charts[0]
	if got := strings.Count(cpu.Line, "M"); got != 2 {
		t.Errorf("%d sub-paths in %q, want 2 (a gap is a break, never a drop to zero)", got, cpu.Line)
	}
	if strings.Contains(cpu.Line, ",96") {
		t.Errorf("the line touches the baseline: %q", cpu.Line)
	}
}

func TestSeriesWithoutPointsDoesNotPanic(t *testing.T) {
	in := HistoryInput{Online: true, Range: history.Ranges[0], CPU: history.Series{}, Mem: history.Series{Total: math.NaN()}}
	if got := NewHistoryCharts(in); got.State != HistoryEmpty {
		t.Errorf("state %q", got.State)
	}
}
