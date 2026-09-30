package demo

import (
	"sort"
	"time"

	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/protocol"
)

func clamp(v, lo, hi float64) float64 {
	return min(max(v, lo), hi)
}

// jitter returns a value in [-amp, amp]. Callers hold h.mu.
func (h *Hub) jitter(amp float64) float64 { return (h.rng.Float64()*2 - 1) * amp }

// sample builds a Metrics value from the host's current simulated state.
func (hst *host) sample(now time.Time) *protocol.Metrics {
	var total float64
	for _, c := range hst.cores {
		total += c
	}
	total /= float64(len(hst.cores))
	temp := hst.temp
	p := hst.prof
	uptime := p.uptimeBase + uint64(max(now.Sub(hst.since), 0)/time.Second)
	disks := append([]protocol.Disk(nil), p.disks...)
	procs := append([]protocol.Process(nil), hst.procs...)
	return &protocol.Metrics{
		Timestamp:     now.UTC(),
		CPUPercent:    total,
		CPUPerCore:    append([]float64(nil), hst.cores...),
		TempC:         &temp,
		Load:          hst.load,
		MemTotal:      p.memTotal,
		MemUsed:       uint64(hst.memUsed),
		SwapTotal:     p.swapTotal,
		SwapUsed:      p.swapUsed,
		Disks:         disks,
		Net:           protocol.NetRate{Iface: "eth0", RxBytesPerSec: hst.rx, TxBytesPerSec: hst.tx},
		UptimeSeconds: uptime,
		TopProcesses:  procs,
	}
}

// step advances every online host by one simulation tick and emits EventMetrics.
func (h *Hub) step() {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now().UTC()
	for _, hst := range h.hosts {
		if !hst.info.Online || hst.metrics == nil {
			continue
		}
		h.advance(hst, now)
		h.emit(grid.Event{Kind: grid.EventMetrics, Host: hst.info.ID, Payload: cloneMetrics(*hst.metrics)})
	}
}

// advance moves the simulated values one step; all values are pulled back
// towards the profile's base so they wander plausibly instead of drifting away.
func (h *Hub) advance(hst *host, now time.Time) {
	p := hst.prof
	var total float64
	for i := range hst.cores {
		hst.cores[i] = clamp(hst.cores[i]+(p.cpuBase[i]-hst.cores[i])*0.3+h.jitter(p.cpuAmp), 0, 100)
		total += hst.cores[i]
	}
	total /= float64(len(hst.cores))

	targetTemp := p.tempBase + (total-p.cpuAvg())*0.2
	hst.temp = clamp(hst.temp+(targetTemp-hst.temp)*0.3+h.jitter(0.15), 20, 85)

	hst.memUsed = clamp(0.8*hst.memUsed+0.2*(float64(p.memBase)+h.jitter(0.1*gib)), 0, float64(p.memTotal))
	hst.rx = max(0, 0.6*hst.rx+0.4*p.rx*(1+h.jitter(0.5)))
	hst.tx = max(0, 0.6*hst.tx+0.4*p.tx*(1+h.jitter(0.5)))

	ratio := 1.0
	if avg := p.cpuAvg(); avg > 0 {
		ratio = total / avg
	}
	hst.load[0] = clamp(0.7*hst.load[0]+0.3*p.load[0]*ratio+h.jitter(0.02), 0, 50)
	hst.load[1] = clamp(0.95*hst.load[1]+0.05*hst.load[0], 0, 50)
	hst.load[2] = clamp(0.98*hst.load[2]+0.02*hst.load[0], 0, 50)

	for i := range hst.procs {
		for _, base := range p.procs {
			if base.PID == hst.procs[i].PID {
				hst.procs[i].CPU = max(0, base.CPU*(1+h.jitter(0.3)))
			}
		}
	}

	sort.SliceStable(hst.procs, func(a, b int) bool { return hst.procs[a].CPU > hst.procs[b].CPU })

	hst.hist = append(hst.hist, total)
	if len(hst.hist) > historyLen {
		hst.hist = hst.hist[len(hst.hist)-historyLen:]
	}
	hst.info.LastSeen = now
	hst.metrics = hst.sample(now)
}
