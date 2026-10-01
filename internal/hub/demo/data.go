package demo

import (
	"fmt"
	"time"

	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/protocol"
)

func gbytes(f float64) uint64 { return uint64(f * (1 << 30)) }

const (
	gib = 1 << 30
	tib = 1 << 40
)

// profile holds the values one simulated host wanders around.
type profile struct {
	cpuBase    []float64
	cpuAmp     float64
	tempBase   float64
	memTotal   uint64
	memBase    uint64
	swapTotal  uint64
	swapUsed   uint64
	disks      []protocol.Disk
	rx, tx     float64 // bytes per second
	load       [3]float64
	uptimeBase uint64 // seconds at simulation start
	procs      []protocol.Process
	latency    time.Duration
}

func (p profile) cpuAvg() float64 {
	var s float64
	for _, c := range p.cpuBase {
		s += c
	}
	return s / float64(len(p.cpuBase))
}

// host is the simulated state of one device. Guarded by Hub.mu.
type host struct {
	info grid.HostInfo
	prof profile

	since time.Time // simulation start of this host (uptime = base + now-since)

	cores   []float64
	temp    float64
	memUsed float64
	rx, tx  float64
	load    [3]float64
	procs   []protocol.Process
	metrics *protocol.Metrics
	hist    []float64

	services *protocol.Services
	pkgs     []protocol.Package
	reboot   bool

	jobs         []*job // oldest first, bounded
	workerActive bool
	lockWaited   bool
}

func (hst *host) packages() protocol.Packages {
	return protocol.Packages{Items: append([]protocol.Package(nil), hst.pkgs...), RebootRequired: hst.reboot}
}

var defaultCaps = []string{protocol.CapMonitoring, protocol.CapPackages, protocol.CapServices, protocol.CapShell}

func pkg(name, summary, installed, candidate string, size int64, st protocol.PackageState) protocol.Package {
	return protocol.Package{Name: name, Summary: summary, InstalledVersion: installed, CandidateVersion: candidate, SizeBytes: size, State: st}
}

// designPackages is the package list of the design (12 rows, 3 updates, 2 orphans).
// upd says which of the update rows are pending on the host.
func designPackages(pi5 bool) []protocol.Package {
	avail := protocol.PackageAvailable
	inst := protocol.PackageInstalled
	upd := protocol.PackageUpdate
	orph := protocol.PackageOrphaned
	ffmpeg := pkg("ffmpeg", "Audio and video tools", "7:5.1.6-0+deb12u1", "7:5.1.7-0+deb12u1", 9_600_000, upd)
	nginx := pkg("nginx", "Web server and reverse proxy", "1.22.1-9", "", 1_600_000, inst)
	docker := pkg("docker.io", "Container runtime", "20.10.24+dfsg1-1", "", 31_000_000, inst)
	ether := pkg("etherwake", "Wake-on-LAN client", "1.09-4+b1", "", 22_000, inst)
	samba := pkg("samba", "SMB/CIFS file server", "2:4.17.12+dfsg-0+deb12u1", "", 3_100_000, inst)
	if !pi5 {
		// pi3-dns: two updates, the rest of the optional packages is only available.
		ffmpeg = pkg("ffmpeg", "Audio and video tools", "", "7:5.1.7-0+deb12u1", 9_600_000, avail)
		nginx = pkg("nginx", "Web server and reverse proxy", "", "1.22.1-9", 1_600_000, avail)
		docker = pkg("docker.io", "Container runtime", "", "20.10.24+dfsg1-1", 31_000_000, avail)
		ether = pkg("etherwake", "Wake-on-LAN client", "", "1.09-4+b1", 22_000, avail)
		samba = pkg("samba", "SMB/CIFS file server", "", "2:4.17.12+dfsg-0+deb12u1", 3_100_000, avail)
	}
	return []protocol.Package{
		pkg("openssh-server", "Secure shell server", "1:9.2p1-2+deb12u3", "1:9.2p1-2+deb12u4", 1_400_000, upd),
		pkg("linux-image-rpi-v8", "Raspberry Pi kernel (arm64)", "6.6.51-1+rpt3", "6.6.62-1+rpt1", 78_000_000, upd),
		ffmpeg,
		pkg("curl", "Command-line URL client", "7.88.1-10+deb12u8", "", 315_000, inst),
		pkg("htop", "Interactive process viewer", "3.2.2-2", "", 432_000, inst),
		nginx, docker, ether, samba,
		pkg("python3-pip", "Python package installer", "23.0.1+dfsg-1", "", 1_300_000, inst),
		pkg("linux-image-6.1.0-rpi7", "Old kernel, no longer needed", "6.1.63-1+rpt1", "", 64_000_000, orph),
		pkg("libjs-sphinxdoc", "Orphaned dependency", "5.3.0-4", "", 1_100_000, orph),
	}
}

// catalog holds packages that SearchPackages can find and pkg_install can add.
var catalog = []protocol.Package{
	pkg("neofetch", "Shows Linux System Information with Distribution Logo", "", "7.1.0-4", 90_000, protocol.PackageAvailable),
	pkg("btop", "Modern and colorful command line resource monitor", "", "1.2.13-1", 1_000_000, protocol.PackageAvailable),
	pkg("tmux", "Terminal multiplexer", "", "3.3a-3", 470_000, protocol.PackageAvailable),
	pkg("ncdu", "Ncurses disk usage viewer", "", "1.18-0.2", 90_000, protocol.PackageAvailable),
	pkg("git", "Fast, scalable, distributed revision control system", "", "1:2.39.5-0+deb12u1", 7_200_000, protocol.PackageAvailable),
	pkg("vim", "Vi IMproved - enhanced vi editor", "", "2:9.0.1378-2", 1_500_000, protocol.PackageAvailable),
	pkg("bat", "Cat clone with syntax highlighting", "", "0.22.1-4", 1_800_000, protocol.PackageAvailable),
	pkg("ripgrep", "Recursively search directories for a regex pattern", "", "13.0.0-4+b2", 1_700_000, protocol.PackageAvailable),
}

func unit(name, desc, active, sub string) protocol.ServiceUnit {
	return protocol.ServiceUnit{Name: name + ".service", Description: desc, ActiveState: active, SubState: sub}
}

const (
	hostPi5  grid.HostID = "a1c5e0d2b7f34961"
	hostPi3  grid.HostID = "b3d7f1a4c8e25072"
	hostPi4  grid.HostID = "c9e2a6b5d1f04783"
	pi5Model             = "Raspberry Pi 5 Model B Rev 1.0"
)

// seed creates the design's three hosts.
func (h *Hub) seed() {
	now := h.now().UTC()

	pi5 := &host{
		info: grid.HostInfo{
			ID: hostPi5, Name: "pi5-media", DisplayName: "pi5-media", Address: "192.168.10.21",
			OS: "linux", Arch: "arm64", AgentVersion: agentVersion, Model: pi5Model,
			Kernel: "6.6.51+rpt-rpi-2712", Capabilities: append([]string(nil), defaultCaps...),
		},
		prof: profile{
			cpuBase: []float64{28, 20, 25, 22}, cpuAmp: 4, tempBase: 47.2,
			memTotal: 8 * gib, memBase: gbytes(3.4), swapTotal: 2 * gib,
			disks: []protocol.Disk{
				{Mount: "/", Total: 117 * 1_000_000_000, Used: 41 * 1_000_000_000},
				{Mount: "/mnt/data", Total: 4 * 1_000_000_000_000, Used: 2_900_000_000_000},
			},
			rx: 1.2e6, tx: 8.6e6, load: [3]float64{0.42, 0.38, 0.35},
			uptimeBase: 41*86400 + 6*3600 + 2*60, latency: 4 * time.Millisecond,
			procs: []protocol.Process{
				{PID: 1423, Name: "plexmediaserver", User: "plex", CPU: 12.4, MemBytes: gbytes(0.041 * 8)},
				{PID: 911, Name: "dockerd", User: "root", CPU: 1.9, MemBytes: gbytes(0.033 * 8)},
				{PID: 3120, Name: "python3", User: "pi", CPU: 1.4, MemBytes: gbytes(0.012 * 8)},
				{PID: 874, Name: "containerd", User: "root", CPU: 0.8, MemBytes: gbytes(0.019 * 8)},
				{PID: 2210, Name: "sshd: pi", User: "pi", CPU: 0.4, MemBytes: gbytes(0.002 * 8)},
				{PID: 1102, Name: "smbd", User: "root", CPU: 0.3, MemBytes: gbytes(0.006 * 8)},
				{PID: 702, Name: "cron", User: "root", CPU: 0.1, MemBytes: gbytes(0.001 * 8)},
				{PID: 1, Name: "systemd", User: "root", CPU: 0.1, MemBytes: gbytes(0.003 * 8)},
			},
		},
		pkgs: designPackages(true),
		services: &protocol.Services{
			Units: []protocol.ServiceUnit{
				unit("ssh", "OpenBSD Secure Shell server", "active", "running"),
				unit("plexmediaserver", "Plex Media Server for Linux", "active", "running"),
				unit("docker", "Docker Application Container Engine", "active", "running"),
				unit("cron", "Regular background program processing daemon", "active", "running"),
				unit("smbd", "Samba SMB Daemon", "failed", "failed"),
				unit("avahi-daemon", "Avahi mDNS/DNS-SD Stack", "active", "running"),
			},
			Ports: []protocol.ListeningPort{
				{Proto: "tcp", Port: 22, Process: "sshd"},
				{Proto: "tcp", Port: 445, Process: "smbd"},
				{Proto: "tcp", Port: 32400, Process: "plexmediaserver"},
				{Proto: "udp", Port: 5353, Process: "avahi-daemon"},
			},
		},
	}

	pi3 := &host{
		info: grid.HostInfo{
			ID: hostPi3, Name: "pi3-dns", DisplayName: "pi3-dns", Address: "192.168.10.5",
			OS: "linux", Arch: "arm64", AgentVersion: agentVersion, Model: "Raspberry Pi 3 Model B Plus Rev 1.3",
			Kernel: "6.6.51+rpt-rpi-v8", Capabilities: append([]string(nil), defaultCaps...),
		},
		prof: profile{
			cpuBase: []float64{10, 8, 9, 7}, cpuAmp: 2, tempBase: 54.8,
			memTotal: 1 * gib, memBase: gbytes(0.31), swapTotal: gbytes(0.1), swapUsed: gbytes(0.1),
			disks: []protocol.Disk{{Mount: "/", Total: 29 * 1_000_000_000, Used: 6_200_000_000}},
			rx:    0.3e6, tx: 0.2e6, load: [3]float64{0.08, 0.11, 0.09},
			uptimeBase: 112*86400 + 3*3600 + 14*60, latency: 6 * time.Millisecond,
			procs: []protocol.Process{
				{PID: 812, Name: "technitium", User: "dns", CPU: 4.8, MemBytes: gbytes(0.226)},
				{PID: 301, Name: "systemd-journald", User: "root", CPU: 0.6, MemBytes: gbytes(0.014)},
				{PID: 1990, Name: "sshd: pi", User: "pi", CPU: 0.3, MemBytes: gbytes(0.009)},
				{PID: 640, Name: "ntpd", User: "ntp", CPU: 0.1, MemBytes: gbytes(0.005)},
				{PID: 588, Name: "cron", User: "root", CPU: 0.1, MemBytes: gbytes(0.004)},
				{PID: 1, Name: "systemd", User: "root", CPU: 0.1, MemBytes: gbytes(0.011)},
			},
		},
		pkgs: designPackages(false),
		services: &protocol.Services{
			Units: []protocol.ServiceUnit{
				unit("ssh", "OpenBSD Secure Shell server", "active", "running"),
				unit("technitium-dns", "Technitium DNS Server", "active", "running"),
				unit("cron", "Regular background program processing daemon", "active", "running"),
				unit("ntp", "Network Time Service", "active", "running"),
			},
			Ports: []protocol.ListeningPort{
				{Proto: "tcp", Port: 22, Process: "sshd"},
				{Proto: "tcp", Port: 53, Process: "technitium"},
				{Proto: "udp", Port: 53, Process: "technitium"},
				{Proto: "tcp", Port: 5380, Process: "technitium"},
			},
		},
	}

	// pi4 never connected: no hello data, no metrics.
	pi4 := &host{
		info: grid.HostInfo{
			ID: hostPi4, Name: "pi4", DisplayName: "pi4", Address: "192.168.10.30",
			OS: "linux", Arch: "arm64", Capabilities: append([]string(nil), defaultCaps...),
		},
	}

	if h.large {
		pi5.pkgs = largePackages()
		pi5.services.Units = largeUnits()
		pi5.prof.disks = largeDisks()
	}

	h.hosts = []*host{pi5, pi3, pi4}
	h.hostSeq = 3
	for _, hst := range []*host{pi5, pi3} {
		h.activate(hst, now)
	}
}

// genericProfile is used for hosts that enroll while the demo runs.
func genericProfile() profile {
	return profile{
		cpuBase: []float64{12, 9, 10, 8}, cpuAmp: 3, tempBase: 45,
		memTotal: 4 * gib, memBase: gbytes(0.6), swapTotal: 1 * gib,
		disks: []protocol.Disk{{Mount: "/", Total: 29 * 1_000_000_000, Used: 4_100_000_000}},
		rx:    0.2e6, tx: 0.1e6, load: [3]float64{0.2, 0.15, 0.1},
		uptimeBase: 120, latency: 5 * time.Millisecond,
		procs: []protocol.Process{
			{PID: 640, Name: "grid-agent", User: "root", CPU: 0.6, MemBytes: 18_000_000},
			{PID: 588, Name: "sshd: pi", User: "pi", CPU: 0.2, MemBytes: 9_000_000},
			{PID: 1, Name: "systemd", User: "root", CPU: 0.1, MemBytes: 11_000_000},
		},
	}
}

// activate makes hst an online host with initial metrics at the profile's base
// values (so the first screen shows the design's numbers). Callers hold h.mu
// (or own the host exclusively during seeding).
func (h *Hub) activate(hst *host, now time.Time) {
	if len(hst.prof.cpuBase) == 0 {
		hst.prof = genericProfile()
		hst.info.Model = "Raspberry Pi 4 Model B Rev 1.5"
		hst.info.Kernel = "6.6.51+rpt-rpi-v8"
		hst.info.AgentVersion = agentVersion
		hst.pkgs = []protocol.Package{
			pkg("curl", "Command-line URL client", "7.88.1-10+deb12u8", "", 315_000, protocol.PackageInstalled),
			pkg("htop", "Interactive process viewer", "3.2.2-2", "", 432_000, protocol.PackageInstalled),
		}
		hst.services = &protocol.Services{
			Units: []protocol.ServiceUnit{
				unit("ssh", "OpenBSD Secure Shell server", "active", "running"),
				unit("cron", "Regular background program processing daemon", "active", "running"),
			},
			Ports: []protocol.ListeningPort{{Proto: "tcp", Port: 22, Process: "sshd"}},
		}
	}
	p := hst.prof
	hst.since = now
	hst.cores = append([]float64(nil), p.cpuBase...)
	hst.temp = p.tempBase
	hst.memUsed = float64(p.memBase)
	hst.rx, hst.tx = p.rx, p.tx
	hst.load = p.load
	hst.procs = append([]protocol.Process(nil), p.procs...)
	hst.info.Online = true
	hst.info.LastSeen = now
	hst.info.Latency = p.latency

	// A plausible history that ends at the current value.
	avg := p.cpuAvg()
	hist := make([]float64, 0, historyLen)
	v := avg
	for i := 0; i < historyLen-1; i++ {
		v = clamp(avg+(v-avg)*0.8+(h.rng.Float64()-0.5)*8, 0, 100)
		hist = append(hist, v)
	}
	hst.hist = append(hist, avg)
	hst.metrics = hst.sample(now)
}

// Job and enroll files share these helpers.

func (h *Hub) newHostID() grid.HostID {
	return grid.HostID(fmt.Sprintf("%08x%08x", h.rng.Uint32(), h.rng.Uint32()))
}
