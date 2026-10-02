package views

import (
	"math"
	"strings"
	"testing"
)

var nan = math.NaN()

func TestCoord(t *testing.T) {
	tests := []struct {
		in   float64
		want string
	}{
		{0, "0"}, {-0.04, "0"}, {1, "1"}, {1.25, "1.3"}, {1.24, "1.2"}, {299.96, "300"}, {96, "96"}, {12.5, "12.5"},
	}
	for _, tc := range tests {
		if got := coord(tc.in); got != tc.want {
			t.Errorf("coord(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestChartY(t *testing.T) {
	tests := []struct {
		name      string
		v, lo, hi float64
		want      float64
	}{
		{"bottom", 0, 0, 100, 96},
		{"top", 100, 0, 100, 8},
		{"middle", 50, 0, 100, 52},
		{"above is clamped", 150, 0, 100, 8},
		{"below is clamped", -5, 0, 100, 96},
		{"degenerate range falls back to a span of 1", 5, 0, 0, 8},
		{"offset range", 15, 10, 20, 52},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := chartY(tc.v, tc.lo, tc.hi); math.Abs(got-tc.want) > 1e-9 {
				t.Errorf("chartY(%v, %v, %v) = %v, want %v", tc.v, tc.lo, tc.hi, got, tc.want)
			}
		})
	}
}

func TestChartX(t *testing.T) {
	tests := []struct {
		name string
		i, n int
		want float64
	}{
		{"first", 0, 5, 0},
		{"last", 4, 5, 300},
		{"middle", 2, 5, 150},
		{"single point is centred", 0, 1, 150},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := chartX(tc.i, tc.n); math.Abs(got-tc.want) > 1e-9 {
				t.Errorf("chartX(%d, %d) = %v, want %v", tc.i, tc.n, got, tc.want)
			}
		})
	}
}

func TestChartPaths(t *testing.T) {
	tests := []struct {
		name     string
		vals     []float64
		lo, hi   float64
		wantLine string
		wantArea string
	}{
		{
			name: "no values", vals: []float64{nan, nan, nan}, lo: 0, hi: 100,
		},
		{
			name: "empty", vals: nil, lo: 0, hi: 100,
		},
		{
			name: "three points scale to the plot", vals: []float64{0, 50, 100}, lo: 0, hi: 100,
			wantLine: "M0,96 150,52 300,8",
			wantArea: "M0,100 0,96 150,52 300,8 300,100Z",
		},
		{
			name: "a gap breaks the line instead of dropping to zero", vals: []float64{100, 100, nan, nan, 0, 0}, lo: 0, hi: 100,
			// n=6: x step 60. Two runs: [0,60] at the top and [240,300] at the bottom.
			wantLine: "M0,8 60,8 M240,96 300,96",
			wantArea: "M0,100 0,8 60,8 60,100Z M240,100 240,96 300,96 300,100Z",
		},
		{
			name: "a single isolated point is a short flat stroke", vals: []float64{nan, 100, nan}, lo: 0, hi: 100,
			// n=3: x step 150, half 75: the stroke covers 75..225 around x=150.
			wantLine: "M75,8 225,8",
			wantArea: "M75,100 75,8 225,8 225,100Z",
		},
		{
			name: "an isolated point at the right edge is clamped", vals: []float64{nan, nan, 0}, lo: 0, hi: 100,
			wantLine: "M225,96 300,96",
			wantArea: "M225,100 225,96 300,96 300,100Z",
		},
		{
			name: "values outside the scale are clamped", vals: []float64{-10, 200}, lo: 0, hi: 100,
			wantLine: "M0,96 300,8",
			wantArea: "M0,100 0,96 300,8 300,100Z",
		},
		{
			name: "leading and trailing gaps", vals: []float64{nan, 0, 100, nan}, lo: 0, hi: 100,
			wantLine: "M100,96 200,8",
			wantArea: "M100,100 100,96 200,8 200,100Z",
		},
		{
			name: "custom scale", vals: []float64{0, 5, 10}, lo: 0, hi: 20,
			wantLine: "M0,96 150,74 300,52",
			wantArea: "M0,100 0,96 150,74 300,52 300,100Z",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			line, area := chartPaths(tc.vals, tc.lo, tc.hi)
			if line != tc.wantLine {
				t.Errorf("line = %q, want %q", line, tc.wantLine)
			}
			if area != tc.wantArea {
				t.Errorf("area = %q, want %q", area, tc.wantArea)
			}
			if strings.Contains(line, "NaN") || strings.Contains(area, "NaN") || strings.Contains(line, "Inf") {
				t.Errorf("non-finite coordinate in %q / %q", line, area)
			}
		})
	}
}

func TestSummarize(t *testing.T) {
	tests := []struct {
		name      string
		avg, peak []float64
		want      seriesStats
	}{
		{name: "nothing", avg: []float64{nan, nan}, want: seriesStats{}},
		{name: "empty", want: seriesStats{}},
		{name: "plain", avg: []float64{10, 20, 30}, want: seriesStats{Min: 10, Avg: 20, Max: 30, OK: true}},
		{name: "gaps are skipped", avg: []float64{nan, 10, nan, 30}, want: seriesStats{Min: 10, Avg: 20, Max: 30, OK: true}},
		{
			name: "max is the true peak", avg: []float64{10, 20}, peak: []float64{12, 90},
			want: seriesStats{Min: 10, Avg: 15, Max: 90, OK: true},
		},
		{
			name: "a missing peak falls back to the value", avg: []float64{10, 20}, peak: []float64{nan, 25},
			want: seriesStats{Min: 10, Avg: 15, Max: 25, OK: true},
		},
		{name: "a single value", avg: []float64{nan, 7}, want: seriesStats{Min: 7, Avg: 7, Max: 7, OK: true}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := summarize(tc.avg, tc.peak); got != tc.want {
				t.Errorf("summarize = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestLatest(t *testing.T) {
	tests := []struct {
		name   string
		vals   []float64
		within int
		want   float64
	}{
		{"newest point", []float64{1, 2, 3}, 2, 3},
		{"one back", []float64{1, 2, nan}, 2, 2},
		{"too old", []float64{1, nan, nan}, 2, math.NaN()},
		{"empty", nil, 2, math.NaN()},
		{"all gaps", []float64{nan, nan}, 2, math.NaN()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := latest(tc.vals, tc.within)
			if math.IsNaN(tc.want) != math.IsNaN(got) || (!math.IsNaN(got) && got != tc.want) {
				t.Errorf("latest = %v, want %v", got, tc.want)
			}
		})
	}
}
