package views

import (
	"math"
	"strconv"
	"strings"
)

// Chart geometry of the History view. Every chart is an SVG with viewBox "0 0 300 100" that is stretched over
// its card (preserveAspectRatio="none", strokes with vector-effect="non-scaling-stroke"), exactly like the
// mockup. The plot uses y = 8 (top) to y = 96 (bottom); y = 100 is the baseline the area is closed on.
const (
	chartWidth  = 300.0
	chartBase   = 100.0
	chartBottom = 96.0
	chartHeight = 88.0 // chartBottom - 8
)

// chartX is the x position of point i of n: the first point sits on the left edge, the last one on the right
// edge ("NOW").
func chartX(i, n int) float64 {
	if n < 2 {
		return chartWidth / 2
	}
	return float64(i) * chartWidth / float64(n-1)
}

// chartY maps v from [lo, hi] to the plot. Values outside the range are clamped.
func chartY(v, lo, hi float64) float64 {
	span := hi - lo
	if span <= 0 {
		span = 1
	}
	t := (v - lo) / span
	switch {
	case t < 0:
		t = 0
	case t > 1:
		t = 1
	}
	return chartBottom - t*chartHeight
}

// coord formats a coordinate with at most one decimal and no trailing zero.
func coord(f float64) string {
	f = math.Round(f*10) / 10
	if f == 0 {
		return "0" // no "-0"
	}
	return strconv.FormatFloat(f, 'f', -1, 64)
}

// chartPaths turns values into the path data of a line and of the area below it. NaN marks a gap (the agent was
// offline, the host has no sensor): the line breaks there, it never drops to zero. A run of a single point
// becomes a short flat stroke so an isolated sample stays visible. Both results are empty when no value exists.
func chartPaths(vals []float64, lo, hi float64) (line, area string) {
	n := len(vals)
	half := 4.0
	if n >= 2 {
		half = chartWidth / float64(n-1) / 2
	}
	var l, a strings.Builder
	for i := 0; i < n; {
		if math.IsNaN(vals[i]) {
			i++
			continue
		}
		j := i
		for j < n && !math.IsNaN(vals[j]) {
			j++
		}
		// run [i, j)
		var xs, ys []float64
		if j-i == 1 {
			x, y := chartX(i, n), chartY(vals[i], lo, hi)
			xs = []float64{math.Max(0, x-half), math.Min(chartWidth, x+half)}
			ys = []float64{y, y}
		} else {
			for k := i; k < j; k++ {
				xs = append(xs, chartX(k, n))
				ys = append(ys, chartY(vals[k], lo, hi))
			}
		}
		for k := range xs {
			p := coord(xs[k]) + "," + coord(ys[k])
			switch k {
			case 0:
				if l.Len() > 0 {
					l.WriteByte(' ')
				}
				l.WriteString("M" + p)
				if a.Len() > 0 {
					a.WriteByte(' ')
				}
				a.WriteString("M" + coord(xs[0]) + "," + coord(chartBase) + " " + p)
			default:
				l.WriteString(" " + p)
				a.WriteString(" " + p)
			}
		}
		a.WriteString(" " + coord(xs[len(xs)-1]) + "," + coord(chartBase) + "Z")
		i = j
	}
	return l.String(), a.String()
}

// seriesStats summarises a series: the smallest and mean of the plotted (average) values and the largest peak.
type seriesStats struct {
	Min, Avg, Max float64
	OK            bool
}

// summarize computes the stats of the points that carry data. avg are the plotted values, peak the per-bucket
// maxima (nil: use avg). min and avg describe the line; max is the true peak, which can be above the line when
// a bucket covers several samples.
func summarize(avg, peak []float64) seriesStats {
	var st seriesStats
	var sum float64
	n := 0
	for i, v := range avg {
		if math.IsNaN(v) {
			continue
		}
		p := v
		if peak != nil && i < len(peak) && !math.IsNaN(peak[i]) {
			p = peak[i]
		}
		if n == 0 {
			st.Min, st.Max = v, p
		}
		st.Min = math.Min(st.Min, v)
		st.Max = math.Max(st.Max, p)
		sum += v
		n++
	}
	if n > 0 {
		st.Avg = sum / float64(n)
		st.OK = true
	}
	return st
}

// latest returns the newest value if it is one of the last `within` points, else NaN: a host that stopped
// reporting some time ago has no "now".
func latest(vals []float64, within int) float64 {
	for i := len(vals) - 1; i >= 0 && i >= len(vals)-within; i-- {
		if !math.IsNaN(vals[i]) {
			return vals[i]
		}
	}
	return math.NaN()
}
