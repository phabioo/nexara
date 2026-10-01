package views

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/phabioo/nexara/internal/protocol"
)

// View models of the overview (pages/overview.html and partials/overview*.html). The builders are pure:
// they take protocol data plus a few strings, so they are tested without a hub.

const (
	// OverviewSampleInterval is the spacing of the CPU history samples (the agent's default metrics
	// interval); it only feeds the "LAST n S" label of the curve.
	OverviewSampleInterval = 2 * time.Second

	maxOverviewProcs = 8
	maxListedPorts   = 6
	// tempBarMax maps the SoC temperature to the bar: the full bar is 85 °C (the Pi's hard limit).
	tempBarMax = 85.0
	tempHot    = 70.0
	diskFull   = 0.9
	cellTotal  = 16
)

// OverviewPage is the data of pages/overview.html.
type OverviewPage struct {
	Layout

	// Empty is true while no host is linked.
	Empty bool

	Host           string // unique short name (URL segment)
	Label          string // display name
	RebootRequired bool   // informational chip; the reboot action itself ships with the Power view
	Load           string // "0.42 0.38 0.35"
	Offline        *OverviewOffline
	RemoveURL      string // GET opens the "Remove host" confirm dialog

	CPUTitle string
	CPU      OverviewCPU
	Mem      OverviewMem
	Svc      OverviewServices

	MicroNode string // "grid_node_01"
	MicroRes  string // "res_map_pi5-media"
}

// OverviewOffline is the "device offline" card.
type OverviewOffline struct {
	Title    string // "PI4 · Offline" (upper-cased by CSS)
	Tag      string
	Text     string
	LastSeen string // "12 min ago" or "never"
	// Host is the unique short name (URL segment); RemoveURL opens the "Remove host" confirm dialog.
	Host      string
	RemoveURL string
}

// OverviewCore is one per-core bar.
type OverviewCore struct {
	Label string
	Pct   int
}

// OverviewProc is one row of the top-process list.
type OverviewProc struct {
	Name string
	CPU  string // "12.4%"
	Mem  string // "4.1%"
}

// OverviewCPU feeds the body of the CPU card.
type OverviewCPU struct {
	Ready   bool // false until the first sample arrived
	Text    string
	Cores   []OverviewCore
	HasTemp bool
	TempPct int // bar width
	TempInt int // value box
	TempHot bool
	Procs   []OverviewProc
}

// OverviewTile is one resource tile (RAM, swap, disk); Empty renders the "NO DISK" placeholder.
type OverviewTile struct {
	Tone  string
	Label string
	Value string
	On    int
	Empty bool
}

// OverviewMem feeds the body of the Memory & storage card.
type OverviewMem struct {
	Ready      bool
	Tag        string
	CurveLine  string
	CurveArea  string
	ChartLabel string // "CPU · LAST 120 S"
	CPUNow     string // "24%"
	Text       string
	Tiles      []OverviewTile
	ShellHref  string // empty hides "Open shell"
}

// OverviewUnit is one service row. At most one of Bad, Busy and Dim is set: Bad is a failed unit (pink),
// Busy one that is starting or stopping (half bar), Dim an inactive one (empty bar, dimmed row).
type OverviewUnit struct {
	Name  string
	State string
	Bad   bool
	Busy  bool
	Dim   bool
}

// OverviewServices feeds the body of the Services card.
type OverviewServices struct {
	Ready      bool // false until the first services answer
	Disabled   bool // the services capability is switched off
	Tag        string
	Text       string
	Units      []OverviewUnit
	Failed     int
	RestartURL string
}

// NewOverviewCPU builds the CPU card. m may be nil (no sample yet).
func NewOverviewCPU(model string, m *protocol.Metrics) OverviewCPU {
	if m == nil {
		return OverviewCPU{}
	}
	c := OverviewCPU{Ready: true}
	for i, v := range m.CPUPerCore {
		c.Cores = append(c.Cores, OverviewCore{Label: "Core " + strconv.Itoa(i), Pct: roundPct(v)})
	}

	var text strings.Builder
	model = strings.TrimSpace(model)
	switch n := len(m.CPUPerCore); {
	case model != "" && n > 0:
		fmt.Fprintf(&text, "%s, %s. ", model, coresText(n))
	case model != "":
		text.WriteString(model + ". ")
	case n > 0:
		text.WriteString(capitalize(coresText(n)) + ". ")
	}
	fmt.Fprintf(&text, "Currently at %d%% utilisation", roundPct(m.CPUPercent))
	if m.TempC != nil {
		t := *m.TempC
		c.HasTemp = true
		c.TempPct = roundPct(100 * t / tempBarMax)
		c.TempInt = int(math.Round(t))
		c.TempHot = t >= tempHot
		fmt.Fprintf(&text, ", SoC temperature %.1f °C.", t)
		if strings.Contains(model, "Raspberry Pi") {
			text.WriteString(" Throttling starts at 80 °C.")
		}
	} else {
		text.WriteString(".")
	}
	c.Text = text.String()

	for i, p := range m.TopProcesses {
		if i == maxOverviewProcs {
			break
		}
		mem := "–"
		if m.MemTotal > 0 {
			mem = fmt.Sprintf("%.1f%%", 100*float64(p.MemBytes)/float64(m.MemTotal))
		}
		c.Procs = append(c.Procs, OverviewProc{Name: p.Name, CPU: fmt.Sprintf("%.1f%%", p.CPU), Mem: mem})
	}
	return c
}

// CPUTitle is the card header: "CPU · 4 Cores".
func CPUTitle(m *protocol.Metrics) string {
	if m == nil || len(m.CPUPerCore) == 0 {
		return "CPU"
	}
	n := len(m.CPUPerCore)
	if n == 1 {
		return "CPU · 1 Core"
	}
	return fmt.Sprintf("CPU · %d Cores", n)
}

// NewOverviewMem builds the Memory & storage card. history is the CPU ring buffer (oldest first);
// shellHref may be empty.
func NewOverviewMem(m *protocol.Metrics, history []float64, shellHref string) OverviewMem {
	if m == nil {
		return OverviewMem{ShellHref: shellHref}
	}
	line, area := CPUCurve(history)
	out := OverviewMem{
		Ready:      true,
		Tag:        "Healthy",
		CurveLine:  line,
		CurveArea:  area,
		CPUNow:     strconv.Itoa(roundPct(m.CPUPercent)) + "%",
		ChartLabel: fmt.Sprintf("CPU · LAST %d S", int(time.Duration(len(history))*OverviewSampleInterval/time.Second)),
		ShellHref:  shellHref,
	}

	div, unit := scaleBytes(float64(m.MemTotal), 1024)
	out.Text = fmt.Sprintf("%s of %s %s RAM in use. Network: ↓ %s MB/s · ↑ %s MB/s",
		trimNum(float64(m.MemUsed)/div), trimNum(float64(m.MemTotal)/div), unit,
		rate(m.Net.RxBytesPerSec), rate(m.Net.TxBytesPerSec))
	if m.Net.Iface != "" {
		out.Text += " on " + m.Net.Iface
	}
	out.Text += "."

	out.Tiles = append(out.Tiles,
		OverviewTile{Tone: "blue", Label: "RAM", Value: pairText(m.MemUsed, m.MemTotal, 1024), On: cells(m.MemUsed, m.MemTotal)},
		OverviewTile{Tone: "purple", Label: "Swap", Value: pairText(m.SwapUsed, m.SwapTotal, 1024), On: cells(m.SwapUsed, m.SwapTotal)},
	)
	for _, d := range m.Disks {
		out.Tiles = append(out.Tiles, OverviewTile{Tone: "grey", Label: "Disk " + d.Mount, Value: pairText(d.Used, d.Total, 1000), On: cells(d.Used, d.Total)})
		if d.Total > 0 && float64(d.Used)/float64(d.Total) > diskFull {
			out.Tag = "Disk almost full"
		}
	}
	for len(out.Tiles) < 4 {
		out.Tiles = append(out.Tiles, OverviewTile{Empty: true})
	}
	return out
}

// NewOverviewServices builds the Services card. svc may be nil (not fetched yet). enabled says whether the
// host has the services capability.
func NewOverviewServices(host string, svc *protocol.Services, enabled bool, restartURL string) OverviewServices {
	out := OverviewServices{RestartURL: restartURL}
	if !enabled {
		out.Disabled = true
		return out
	}
	if svc == nil {
		return out
	}
	out.Ready = true
	running := 0
	for _, u := range svc.Units {
		unit := OverviewUnit{Name: strings.TrimSuffix(u.Name, ".service"), State: u.ActiveState}
		switch u.ActiveState {
		case "failed":
			unit.Bad = true
			out.Failed++
		case "active":
			running++
		case "inactive":
			unit.Dim = true
		default:
			unit.Busy = true
		}
		out.Units = append(out.Units, unit)
	}
	// What matters first: failed, then running, then units in transition, then the inactive ones. The
	// agent already sorts by name, which the stable sort keeps inside each group.
	sort.SliceStable(out.Units, func(i, j int) bool { return unitRank(out.Units[i]) < unitRank(out.Units[j]) })
	out.Tag = fmt.Sprintf("%d/%d running", running, len(svc.Units))
	out.Text = fmt.Sprintf("systemd units on %s. %s", host, PortsText(svc.Ports))
	return out
}

func unitRank(u OverviewUnit) int {
	switch {
	case u.Bad:
		return 0
	case u.Dim:
		return 3
	case u.Busy:
		return 2
	}
	return 1
}

// PortsText renders the listening-ports sentence: "Listening on 22, 445, 32400 and 5353/udp."
func PortsText(ports []protocol.ListeningPort) string {
	seen := map[string]bool{}
	var items []string
	for _, p := range ports {
		s := strconv.Itoa(int(p.Port))
		if p.Proto == "udp" {
			s += "/udp"
		}
		if !seen[s] {
			seen[s] = true
			items = append(items, s)
		}
	}
	switch {
	case len(items) == 0:
		return "No listening ports reported."
	case len(items) > maxListedPorts:
		return "Listening on " + strings.Join(items[:maxListedPorts], ", ") + fmt.Sprintf(" and %d more.", len(items)-maxListedPorts)
	case len(items) == 1:
		return "Listening on " + items[0] + "."
	}
	return "Listening on " + strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1] + "."
}

// LoadText renders the load chip: "0.42 0.38 0.35".
func LoadText(load [3]float64) string {
	return fmt.Sprintf("%.2f %.2f %.2f", load[0], load[1], load[2])
}

// CPUCurve turns the CPU history (percent, oldest first) into the points of the SVG polyline and of the
// filled polygon below it. The viewBox is 300 x 100; 0 % sits at y=97.1 so a flat idle line stays visible.
// Empty history yields empty strings.
func CPUCurve(history []float64) (line, area string) {
	switch len(history) {
	case 0:
		return "", ""
	case 1:
		history = []float64{history[0], history[0]}
	}
	var b strings.Builder
	last := float64(len(history) - 1)
	for i, v := range history {
		if math.IsNaN(v) {
			v = 0
		}
		v = math.Max(1, math.Min(100, v))
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%.1f,%.1f", float64(i)*300/last, 98-v*0.9)
	}
	line = b.String()
	return line, "0,100 " + line + " 300,100"
}

// AgoText renders how long ago t was: "just now", "12 min ago", "3 h ago", "2 d ago"; "never" for the zero time.
func AgoText(now, t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d/time.Minute))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h ago", int(d/time.Hour))
	}
	return fmt.Sprintf("%d d ago", int(d/(24*time.Hour)))
}

func roundPct(v float64) int {
	if math.IsNaN(v) {
		return 0
	}
	return int(math.Round(math.Max(0, math.Min(100, v))))
}

func coresText(n int) string {
	if n == 1 {
		return "1 core"
	}
	return strconv.Itoa(n) + " cores"
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// scaleBytes picks the unit for total (base 1024 for memory, 1000 for disks, as drives are sold).
func scaleBytes(total, base float64) (div float64, unit string) {
	units := []string{"B", "KB", "MB", "GB", "TB", "PB"}
	div = 1
	i := 0
	for total/div >= base && i < len(units)-1 {
		div *= base
		i++
	}
	return div, units[i]
}

// trimNum prints one decimal below 10 and none above, without a trailing ".0".
func trimNum(f float64) string {
	if f >= 9.95 {
		return strconv.FormatFloat(math.Round(f), 'f', 0, 64)
	}
	return strings.TrimSuffix(strconv.FormatFloat(f, 'f', 1, 64), ".0")
}

// pairText renders "3.4 / 8 GB" with the unit of the total.
func pairText(used, total uint64, base float64) string {
	if total == 0 {
		return "–"
	}
	div, unit := scaleBytes(float64(total), base)
	return fmt.Sprintf("%s / %s %s", trimNum(float64(used)/div), trimNum(float64(total)/div), unit)
}

// cells is the number of filled pixel cells of 16; any use shows at least one.
func cells(used, total uint64) int {
	if total == 0 || used == 0 {
		return 0
	}
	n := int(math.Round(cellTotal * float64(used) / float64(total)))
	return max(1, min(cellTotal, n))
}

// rate renders bytes per second as megabytes per second with one decimal.
func rate(bps float64) string {
	if math.IsNaN(bps) || bps < 0 {
		bps = 0
	}
	return fmt.Sprintf("%.1f", bps/1e6)
}
