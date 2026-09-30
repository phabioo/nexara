package metrics

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	gnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"

	"github.com/phabioo/nexara/internal/protocol"
)

const topProcessCount = 8

// HostFacts are static host properties for the hello message.
type HostFacts struct {
	Hostname string
	OS       string
	Arch     string
	Kernel   string
	Model    string // may be empty
	MAC      string // primary interface, lower case, colon separated; may be empty
}

// gopsutilCollector keeps the previous CPU and network samples so every
// Collect call reports deltas since the one before.
type gopsutilCollector struct {
	mu sync.Mutex

	prevNetTime  time.Time
	prevNetIface string
	prevRx       uint64
	prevTx       uint64

	procs map[int32]*process.Process // retained so Percent(0) reports deltas
}

// New returns the Collector for this platform.
func New() Collector {
	c := &gopsutilCollector{procs: map[int32]*process.Process{}}
	// Prime the CPU delta state; the first real Collect then has a baseline.
	_, _ = cpu.Percent(0, true)
	return c
}

func (c *gopsutilCollector) Collect(ctx context.Context) (protocol.Metrics, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now().UTC()
	m := protocol.Metrics{Timestamp: now}

	perCore, err := cpu.PercentWithContext(ctx, 0, true)
	if err != nil {
		return m, fmt.Errorf("cpu: %w", err)
	}
	m.CPUPerCore = perCore
	if len(perCore) > 0 {
		// The total is the mean of the cores; it matches the delta based total
		// and avoids a second sampling window.
		var sum float64
		for _, p := range perCore {
			sum += p
		}
		m.CPUPercent = sum / float64(len(perCore))
	}

	m.TempC = readTemperature()

	if avg, err := load.AvgWithContext(ctx); err == nil {
		m.Load = [3]float64{avg.Load1, avg.Load5, avg.Load15}
	}

	vm, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil {
		return m, fmt.Errorf("memory: %w", err)
	}
	m.MemTotal, m.MemUsed = vm.Total, vm.Used
	if sw, err := mem.SwapMemoryWithContext(ctx); err == nil {
		m.SwapTotal, m.SwapUsed = sw.Total, sw.Used
	}

	m.Disks = collectDisks(ctx)
	m.Net = c.collectNet(ctx, now)

	if up, err := host.UptimeWithContext(ctx); err == nil {
		m.UptimeSeconds = up
	}
	m.TopProcesses = c.collectProcesses(ctx)
	return m, nil
}

func collectDisks(ctx context.Context) []protocol.Disk {
	parts, err := disk.PartitionsWithContext(ctx, true)
	if err != nil {
		return nil
	}
	in := make([]mount, 0, len(parts))
	for _, p := range parts {
		in = append(in, mount{Device: p.Device, Point: p.Mountpoint, FSType: p.Fstype})
	}
	var out []protocol.Disk
	for _, mt := range realMounts(in) {
		u, err := disk.UsageWithContext(ctx, mt.Point)
		if err != nil || u.Total == 0 {
			continue
		}
		out = append(out, protocol.Disk{Mount: mt.Point, Total: u.Total, Used: u.Used})
	}
	return out
}

func (c *gopsutilCollector) collectNet(ctx context.Context, now time.Time) protocol.NetRate {
	iface := primaryInterface()
	if iface == "" {
		return protocol.NetRate{}
	}
	counters, err := gnet.IOCountersWithContext(ctx, true)
	if err != nil {
		return protocol.NetRate{Iface: iface}
	}
	for _, s := range counters {
		if s.Name != iface {
			continue
		}
		out := protocol.NetRate{Iface: iface}
		if c.prevIfaceMatches(iface) {
			secs := now.Sub(c.prevNetTime).Seconds()
			out.RxBytesPerSec = rate(c.prevRx, s.BytesRecv, secs)
			out.TxBytesPerSec = rate(c.prevTx, s.BytesSent, secs)
		}
		c.prevNetTime, c.prevNetIface, c.prevRx, c.prevTx = now, iface, s.BytesRecv, s.BytesSent
		return out
	}
	return protocol.NetRate{Iface: iface}
}

func (c *gopsutilCollector) prevIfaceMatches(iface string) bool {
	return !c.prevNetTime.IsZero() && c.prevNetIface == iface
}

func (c *gopsutilCollector) collectProcesses(ctx context.Context) []protocol.Process {
	pids, err := process.PidsWithContext(ctx)
	if err != nil {
		return nil
	}
	seen := make(map[int32]*process.Process, len(pids))
	all := make([]protocol.Process, 0, len(pids))
	for _, pid := range pids {
		p, ok := c.procs[pid]
		if !ok {
			p = &process.Process{Pid: pid}
		}
		cpuPct, err := p.PercentWithContext(ctx, 0)
		if err != nil {
			continue // vanished or not readable
		}
		seen[pid] = p
		var rss uint64
		if mi, err := p.MemoryInfoWithContext(ctx); err == nil && mi != nil {
			rss = mi.RSS
		}
		all = append(all, protocol.Process{PID: pid, CPU: cpuPct, MemBytes: rss})
	}
	c.procs = seen

	top := topProcesses(all, topProcessCount)
	for i := range top {
		p := c.procs[top[i].PID]
		if name, err := p.NameWithContext(ctx); err == nil {
			top[i].Name = name
		}
		if user, err := p.UsernameWithContext(ctx); err == nil {
			top[i].User = user
		}
	}
	return top
}

// Facts gathers the static host properties for the hello message.
func Facts() HostFacts {
	f := HostFacts{OS: runtime.GOOS, Arch: runtime.GOARCH, Model: readModel()}
	f.Hostname, _ = os.Hostname()
	if kv, err := host.KernelVersion(); err == nil {
		f.Kernel = kv
	}
	if iface := primaryInterface(); iface != "" {
		if ni, err := net.InterfaceByName(iface); err == nil {
			f.MAC = formatMAC(ni.HardwareAddr.String())
		}
	}
	return f
}
