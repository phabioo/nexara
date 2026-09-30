package metrics

import (
	"sort"
	"strconv"
	"strings"

	"github.com/phabioo/nexara/internal/protocol"
)

// Pure parsing and filtering helpers. They take plain data so they can be
// tested with fixtures on every platform.

// thermalZone is one /sys/class/thermal/thermal_zone* entry.
type thermalZone struct {
	Type  string // contents of "type", trimmed
	Milli int64  // contents of "temp" in millidegrees Celsius
}

// pickTemperature returns the SoC temperature in degrees Celsius. It prefers
// the zone of type "cpu-thermal", else the first zone. Nil if there is none.
func pickTemperature(zones []thermalZone) *float64 {
	if len(zones) == 0 {
		return nil
	}
	z := zones[0]
	for _, c := range zones {
		if c.Type == "cpu-thermal" {
			z = c
			break
		}
	}
	v := float64(z.Milli) / 1000
	return &v
}

// parseDefaultRoute returns the interface of the default route from the
// contents of /proc/net/route. With several default routes the lowest metric
// wins. It returns "" if there is none.
func parseDefaultRoute(content string) string {
	best := ""
	bestMetric := int64(-1)
	for i, line := range strings.Split(content, "\n") {
		if i == 0 {
			continue // header
		}
		f := strings.Fields(line)
		if len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		flags, err := strconv.ParseInt(f[3], 16, 64)
		if err != nil || flags&0x1 == 0 { // RTF_UP
			continue
		}
		metric, err := strconv.ParseInt(f[6], 10, 64)
		if err != nil {
			continue
		}
		if bestMetric < 0 || metric < bestMetric {
			best, bestMetric = f[0], metric
		}
	}
	return best
}

// pseudoFSTypes are filesystem types that never represent real storage.
var pseudoFSTypes = map[string]bool{
	"tmpfs": true, "devtmpfs": true, "overlay": true, "squashfs": true,
	"proc": true, "sysfs": true, "cgroup": true, "cgroup2": true,
	"devpts": true, "mqueue": true, "debugfs": true, "tracefs": true,
	"securityfs": true, "pstore": true, "configfs": true, "fusectl": true,
	"autofs": true, "binfmt_misc": true, "bpf": true, "hugetlbfs": true,
	"rpc_pipefs": true, "nsfs": true, "ramfs": true, "efivarfs": true,
	"fuse.gvfsd-fuse": true, "fuse.lxcfs": true, "selinuxfs": true,
}

// mount is one mounted filesystem as reported by the OS.
type mount struct {
	Device string
	Point  string
	FSType string
}

// realMounts keeps real storage mounts: no pseudo filesystems, no snap loop
// devices, no mounts under /proc, /sys, /dev, /run, /snap, and one entry per
// device (bind mounts: the shortest mount point wins). Order is preserved by
// first appearance of the device.
func realMounts(in []mount) []mount {
	byDevice := map[string]int{}
	var out []mount
	for _, m := range in {
		if pseudoFSTypes[m.FSType] || m.Device == "" || m.Device == "none" {
			continue
		}
		if strings.HasPrefix(m.Device, "/dev/loop") || m.FSType == "squashfs" {
			continue
		}
		if hasPathPrefix(m.Point, "/proc", "/sys", "/dev", "/run", "/snap", "/var/lib/docker") {
			continue
		}
		if i, ok := byDevice[m.Device]; ok {
			if len(m.Point) < len(out[i].Point) {
				out[i].Point = m.Point
			}
			continue
		}
		byDevice[m.Device] = len(out)
		out = append(out, m)
	}
	return out
}

func hasPathPrefix(p string, prefixes ...string) bool {
	for _, pre := range prefixes {
		if p == pre || strings.HasPrefix(p, pre+"/") {
			return true
		}
	}
	return false
}

// rate converts a counter delta over elapsed seconds into a per second rate.
// A counter reset (cur < prev) or non-positive elapsed time yields 0.
func rate(prev, cur uint64, seconds float64) float64 {
	if cur < prev || seconds <= 0 {
		return 0
	}
	return float64(cur-prev) / seconds
}

// formatMAC normalizes a hardware address to lower case, colon separated.
func formatMAC(s string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), "-", ":"))
}

// topProcesses sorts by CPU descending (ties: higher memory, then lower PID)
// and returns at most n entries.
func topProcesses(items []protocol.Process, n int) []protocol.Process {
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if a.CPU != b.CPU {
			return a.CPU > b.CPU
		}
		if a.MemBytes != b.MemBytes {
			return a.MemBytes > b.MemBytes
		}
		return a.PID < b.PID
	})
	if len(items) > n {
		items = items[:n]
	}
	return items
}
