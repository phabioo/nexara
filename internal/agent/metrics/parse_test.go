package metrics

import (
	"reflect"
	"testing"

	"github.com/phabioo/nexara/internal/protocol"
)

func TestPickTemperature(t *testing.T) {
	tests := []struct {
		name  string
		zones []thermalZone
		want  *float64
	}{
		{"none", nil, nil},
		{"single", []thermalZone{{"x86_pkg_temp", 45500}}, ptr(45.5)},
		{"prefers cpu-thermal", []thermalZone{{"gpu", 40000}, {"cpu-thermal", 52123}}, ptr(52.123)},
		{"first when no cpu-thermal", []thermalZone{{"a", 30000}, {"b", 40000}}, ptr(30)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pickTemperature(tt.zones)
			if (got == nil) != (tt.want == nil) || (got != nil && *got != *tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func ptr(f float64) *float64 { return &f }

const routeFixture = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
wlan0	00000000	0100A8C0	0003	0	0	600	00000000	0	0	0
eth0	00000000	0100A8C0	0003	0	0	100	00000000	0	0	0
eth0	0000A8C0	00000000	0001	0	0	100	00FFFFFF	0	0	0
`

func TestParseDefaultRoute(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"lowest metric", routeFixture, "eth0"},
		{"empty", "", ""},
		{"header only", "Iface\tDestination\n", ""},
		{"no default", "Iface Destination Gateway Flags RefCnt Use Metric Mask\neth0 0000A8C0 00000000 0001 0 0 100 00FFFFFF 0 0 0\n", ""},
		{"down route ignored", "Iface Destination Gateway Flags RefCnt Use Metric Mask\neth0 00000000 0100A8C0 0002 0 0 1 00000000 0 0 0\n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseDefaultRoute(tt.in); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRealMounts(t *testing.T) {
	in := []mount{
		{"/dev/root", "/", "ext4"},
		{"tmpfs", "/run", "tmpfs"},
		{"devtmpfs", "/dev", "devtmpfs"},
		{"proc", "/proc", "proc"},
		{"/dev/loop3", "/snap/core/1", "squashfs"},
		{"/dev/loop4", "/mnt/img", "ext4"},
		{"overlay", "/var/lib/docker/overlay2/x/merged", "overlay"},
		{"/dev/mmcblk0p1", "/boot/firmware", "vfat"},
		{"/dev/root", "/var/lib/bind", "ext4"},
		{"/dev/sda1", "/srv/data", "ext4"},
		{"192.168.1.5:/export", "/mnt/nfs", "nfs4"},
		{"cgroup2", "/sys/fs/cgroup", "cgroup2"},
	}
	var got []string
	for _, m := range realMounts(in) {
		got = append(got, m.Point)
	}
	want := []string{"/", "/boot/firmware", "/srv/data", "/mnt/nfs"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestRealMountsDedupePrefersShortestMount(t *testing.T) {
	got := realMounts([]mount{{"/dev/sda1", "/mnt/a/b", "ext4"}, {"/dev/sda1", "/mnt/a", "ext4"}})
	if len(got) != 1 || got[0].Point != "/mnt/a" {
		t.Fatalf("got %v", got)
	}
}

func TestRate(t *testing.T) {
	tests := []struct {
		name      string
		prev, cur uint64
		secs      float64
		want      float64
	}{
		{"normal", 1000, 3000, 2, 1000},
		{"reset", 3000, 1000, 2, 0},
		{"zero time", 1, 2, 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rate(tt.prev, tt.cur, tt.secs); got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFormatMAC(t *testing.T) {
	tests := []struct{ in, want string }{
		{"DC:A6:32:0A:BB:CC", "dc:a6:32:0a:bb:cc"},
		{" DC-A6-32-0A-BB-CC\n", "dc:a6:32:0a:bb:cc"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := formatMAC(tt.in); got != tt.want {
			t.Errorf("formatMAC(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestTopProcesses(t *testing.T) {
	in := []protocol.Process{
		{PID: 5, CPU: 1}, {PID: 3, CPU: 9}, {PID: 4, CPU: 9, MemBytes: 10}, {PID: 2, CPU: 5},
	}
	got := topProcesses(in, 3)
	var pids []int32
	for _, p := range got {
		pids = append(pids, p.PID)
	}
	if want := []int32{4, 3, 2}; !reflect.DeepEqual(pids, want) {
		t.Fatalf("got %v, want %v", pids, want)
	}
	if n := len(topProcesses(in[:2], 8)); n != 2 {
		t.Fatalf("len %d", n)
	}
}
