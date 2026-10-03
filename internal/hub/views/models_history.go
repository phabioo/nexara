package views

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/phabioo/nexara/internal/hub/history"
)

// View models of the History view (pages/history.html, partials/history.html). The builders are pure: they take
// history series plus a few strings and a time zone, so they are tested without a hub or a database.

// States of HistoryCharts.
const (
	HistoryOK          = "ok"          // charts
	HistoryEmpty       = "empty"       // the host has no data in the range yet
	HistoryUnavailable = "unavailable" // the hub runs without a history service
	HistoryNoHosts     = "nohosts"     // no host is linked (page level)
)

// historyLookback is how many of the newest points may still provide the big "now" value: a host that has been
// silent for longer has no current value.
const historyLookback = 2

// maxHistoryDisks bounds the disk charts of one host (a Pi with dozens of bind mounts stays readable).
const maxHistoryDisks = 12

// HistoryPage is the data of pages/history.html.
type HistoryPage struct {
	Layout

	State string // HistoryNoHosts, or "" when Charts decides
	Host  string // short name (URL segment)
	Label string // display name

	RangeKey string
	Ranges   []HistoryRangeTab
	Zone     string // "Europe/Berlin": time zone of the axis labels

	Charts HistoryCharts
}

// HistoryRangeTab is one of the range buttons (24 h / 7 days / 30 days).
type HistoryRangeTab struct {
	Label  string
	Active bool
	Href   string
}

// HistoryCharts is the live part of the view: the offline notice and the charts. It is the fragment the page
// refreshes by itself (partials/history.html, "history-charts").
type HistoryCharts struct {
	State   string
	Message string // text of the empty and unavailable states
	Notice  string // host offline
	Charts  []HistoryChart
	Disks   []HistoryChart

	PollURL   string // GET of the whole fragment
	PollEvery string // "60s"
}

// HistoryChart is one card.
type HistoryChart struct {
	Key   string // "cpu", "mem", "temp", "net", "disk-0"
	Tone  string // tile tone: lime, blue, pink, green, grey
	Title string // "CPU · 24H"

	Now, Unit string // big value and its unit; "–" without a current value
	Stats     string // "MIN 10 · AVG 34 · MAX 54"
	Stats2    string // second series (network upload), empty otherwise

	Line, Area string // path data of the main series
	Line2      string // path data of the second series
	Empty      string // text over the empty plot, empty when there is data

	X0, XMid, X1 string // time axis: start, middle, "NOW"
	Note         string // between start and middle (legend, capacity)
	Label        string // accessible description of the plot
}

// HistoryInput feeds NewHistoryCharts.
type HistoryInput struct {
	Label    string
	Online   bool
	LastSeen string // "12 min ago"; used in the offline notice
	Range    history.Range
	Loc      *time.Location

	CPU, Mem, Temp, Rx, Tx history.Series
	Disks                  []history.Series
}

// HistoryEmptyText is shown for a host without data in the range.
const HistoryEmptyText = "History starts collecting when the agent is online."

// NewHistoryRanges builds the range tabs; base is the page URL of the host without query.
func NewHistoryRanges(base, active string) []HistoryRangeTab {
	tabs := make([]HistoryRangeTab, 0, len(history.Ranges))
	for i, r := range history.Ranges {
		href := base
		if i > 0 {
			href += "?range=" + r.Key
		}
		tabs = append(tabs, HistoryRangeTab{Label: historyTabLabel(r), Active: r.Key == active, Href: href})
	}
	return tabs
}

func historyTabLabel(r history.Range) string {
	if r.Key == "24h" {
		return "24 h"
	}
	return r.Label // "7 days", "30 days"
}

// NewHistoryCharts builds the charts of a host from its series.
func NewHistoryCharts(in HistoryInput) HistoryCharts {
	out := HistoryCharts{State: HistoryOK}
	empty := !in.CPU.HasData() && !in.Mem.HasData() && !in.Rx.HasData() && !in.Tx.HasData() && !in.Temp.HasData()
	if !in.Online {
		out.Notice = in.Label + " is offline."
		if !empty {
			out.Notice += " The charts show the history collected while its agent was connected."
		}
		if in.LastSeen != "" && in.LastSeen != "never" {
			out.Notice += " Last seen " + in.LastSeen + "."
		}
	}
	if empty {
		out.State = HistoryEmpty
		out.Message = HistoryEmptyText
		return out
	}

	b := chartBuilder{in: in, tag: strings.ToUpper(in.Range.Key)}
	b.axis()
	out.Charts = []HistoryChart{b.cpu(), b.mem(), b.temp(), b.net()}
	for i, d := range in.Disks {
		if i >= maxHistoryDisks {
			break
		}
		out.Disks = append(out.Disks, b.disk(i, d))
	}
	return out
}

type chartBuilder struct {
	in         HistoryInput
	tag        string // "24H"
	x0, xm, x1 string
	haveAxis   bool
}

// axis computes the time labels from the first series that has a grid. Labels are formatted in the hub's time
// zone from instants, so a day with a clock change still labels the true start, middle and end.
func (b *chartBuilder) axis() {
	s := b.in.CPU
	if len(s.Points) == 0 {
		return
	}
	start := s.Points[0].Time
	end := s.Points[len(s.Points)-1].Time.Add(s.Step)
	b.x0 = HistoryAxisLabel(start, b.in.Range.Key, b.in.Loc)
	b.xm = HistoryAxisLabel(start.Add(end.Sub(start)/2), b.in.Range.Key, b.in.Loc)
	b.x1 = "NOW"
	b.haveAxis = true
}

// HistoryAxisLabel formats an instant for the time axis in loc: weekday and clock for the 24 h view, the date for
// the longer ranges.
func HistoryAxisLabel(t time.Time, rangeKey string, loc *time.Location) string {
	if loc == nil {
		loc = time.UTC
	}
	t = t.In(loc)
	switch rangeKey {
	case "7d":
		return t.Format("Mon 2 Jan")
	case "30d":
		return t.Format("2 Jan")
	}
	return t.Format("Mon 15:04")
}

// values returns the plotted values and peaks of a series after f (NaN stays NaN).
func values(s history.Series, f func(float64) float64) (avg, peak []float64) {
	avg = make([]float64, len(s.Points))
	peak = make([]float64, len(s.Points))
	for i, p := range s.Points {
		if !p.HasData() {
			avg[i], peak[i] = math.NaN(), math.NaN()
			continue
		}
		avg[i], peak[i] = f(p.Avg), f(p.Max)
	}
	return avg, peak
}

func identity(v float64) float64 { return v }

// ofTotal turns bytes into percent of total; without a total there is nothing to show.
func ofTotal(total float64) func(float64) float64 {
	if total <= 0 {
		return func(float64) float64 { return math.NaN() }
	}
	return func(v float64) float64 { return math.Min(100, math.Max(0, v/total*100)) }
}

func (b *chartBuilder) card(key, tone, name string) HistoryChart {
	c := HistoryChart{Key: key, Tone: tone, Title: name + " · " + b.tag, Now: "–"}
	if b.haveAxis {
		c.X0, c.XMid, c.X1 = b.x0, b.xm, b.x1
	}
	return c
}

// fill sets the plot and the numbers of a chart from percent-like values.
func (b *chartBuilder) fill(c *HistoryChart, avg, peak []float64, lo, hi float64, dec int, unit, emptyText string) {
	st := summarize(avg, peak)
	if !st.OK {
		c.Empty = emptyText
		c.Label = c.Title + ": no data"
		return
	}
	c.Line, c.Area = chartPaths(avg, lo, hi)
	c.Unit = unit
	f := func(v float64) string { return strconv.FormatFloat(v, 'f', dec, 64) }
	if now := latest(avg, historyLookback); !math.IsNaN(now) {
		c.Now = f(now)
	} else {
		c.Unit = ""
	}
	c.Stats = "MIN " + f(st.Min) + " · AVG " + f(st.Avg) + " · MAX " + f(st.Max)
	c.Label = fmt.Sprintf("%s: now %s %s, min %s, average %s, max %s", c.Title, c.Now, unit, f(st.Min), f(st.Avg), f(st.Max))
}

const noDataText = "No data in this range"

func (b *chartBuilder) cpu() HistoryChart {
	c := b.card("cpu", "lime", "CPU")
	avg, peak := values(b.in.CPU, func(v float64) float64 { return math.Min(100, math.Max(0, v)) })
	b.fill(&c, avg, peak, 0, 100, 0, "%", noDataText)
	return c
}

func (b *chartBuilder) mem() HistoryChart {
	c := b.card("mem", "blue", "Memory")
	avg, peak := values(b.in.Mem, ofTotal(b.in.Mem.Total))
	b.fill(&c, avg, peak, 0, 100, 0, "%", noDataText)
	if b.in.Mem.Total > 0 {
		c.Note = formatBytesText(b.in.Mem.Total) + " total"
	}
	return c
}

func (b *chartBuilder) temp() HistoryChart {
	c := b.card("temp", "pink", "SoC temperature")
	avg, peak := values(b.in.Temp, identity)
	hi := 90.0
	for _, v := range peak {
		if !math.IsNaN(v) && v > hi {
			hi = math.Ceil(v/10) * 10
		}
	}
	text := noDataText
	if !b.in.Temp.HasData() && (b.in.CPU.HasData() || b.in.Mem.HasData()) {
		text = "No temperature sensor reported"
	}
	b.fill(&c, avg, peak, 0, hi, 1, "°C", text)
	return c
}

// byteUnits scales network rates: the unit is chosen from the largest peak of the card, so both lines and
// all numbers share it.
var byteUnits = []struct {
	div  float64
	name string
	dec  int
}{{1, "B/s", 0}, {1 << 10, "KB/s", 1}, {1 << 20, "MB/s", 1}, {1 << 30, "GB/s", 1}}

func (b *chartBuilder) net() HistoryChart {
	c := b.card("net", "green", "Network")
	c.Note = "GREEN ↓ RX · PURPLE ↑ TX"

	peak := 0.0
	for _, s := range []history.Series{b.in.Rx, b.in.Tx} {
		for _, p := range s.Points {
			if p.HasData() && p.Max > peak {
				peak = p.Max
			}
		}
	}
	u := byteUnits[0]
	for _, cand := range byteUnits {
		if peak >= cand.div {
			u = cand
		}
	}
	scale := func(v float64) float64 { return v / u.div }
	rxAvg, rxPeak := values(b.in.Rx, scale)
	txAvg, txPeak := values(b.in.Tx, scale)
	rx, tx := summarize(rxAvg, rxPeak), summarize(txAvg, txPeak)
	if !rx.OK && !tx.OK {
		c.Empty = noDataText
		c.Note = ""
		c.Label = c.Title + ": no data"
		return c
	}
	hi := 1.0
	for _, v := range append(append([]float64{}, rxAvg...), txAvg...) {
		if !math.IsNaN(v) && v*1.15 > hi {
			hi = v * 1.15
		}
	}
	// A flat zero line must not stretch to an arbitrary scale: 1 unit is the floor.
	c.Line, c.Area = chartPaths(rxAvg, 0, hi)
	c.Line2, _ = chartPaths(txAvg, 0, hi)
	f := func(v float64) string { return strconv.FormatFloat(v, 'f', u.dec, 64) }
	stats := func(s seriesStats) string {
		return "MIN " + f(s.Min) + " · AVG " + f(s.Avg) + " · MAX " + f(s.Max)
	}
	c.Unit = u.name + " ↓"
	if now := latest(rxAvg, historyLookback); !math.IsNaN(now) {
		c.Now = f(now)
	} else {
		c.Unit = ""
	}
	if rx.OK {
		c.Stats = stats(rx)
	}
	if tx.OK {
		c.Stats2 = "↑ " + stats(tx)
	}
	c.Label = fmt.Sprintf("%s: download now %s %s; %s; upload %s", c.Title, c.Now, u.name, c.Stats, c.Stats2)
	return c
}

func (b *chartBuilder) disk(i int, s history.Series) HistoryChart {
	mount, _ := s.Metric.Mount()
	c := b.card("disk-"+strconv.Itoa(i), "grey", "Disk "+mount)
	avg, peak := values(s, ofTotal(s.Total))
	b.fill(&c, avg, peak, 0, 100, 0, "%", noDataText)
	if s.Total > 0 {
		used := math.NaN()
		for j := len(s.Points) - 1; j >= 0 && j >= len(s.Points)-historyLookback; j-- {
			if s.Points[j].HasData() {
				used = s.Points[j].Avg
				break
			}
		}
		if !math.IsNaN(used) {
			c.Note = formatBytesText(used) + " of " + formatBytesText(s.Total)
		} else {
			c.Note = formatBytesText(s.Total) + " total"
		}
	}
	return c
}

func formatBytesText(v float64) string {
	s, err := formatBytes(v)
	if err != nil {
		return ""
	}
	return s
}
