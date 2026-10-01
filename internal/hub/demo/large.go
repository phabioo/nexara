package demo

import (
	"fmt"

	"github.com/phabioo/nexara/internal/protocol"
)

// The large data set (nexus dev --demo --demo-large) gives pi5-media the size of a real
// Raspberry Pi 5 install: about 900 packages, 31 systemd units with a failed and several
// inactive ones, and five mounts. It exists to test scrolling and paging; the default demo
// keeps the design's sample data (decision #25).

const largePackageTarget = 900

// largeUnits is the unit list of a real Pi: one failed, eight inactive oneshots, the rest active.
func largeUnits() []protocol.ServiceUnit {
	return []protocol.ServiceUnit{
		unit("fstrim", "Discard unused blocks on filesystems from /etc/fstab", "failed", "failed"),
		unit("NetworkManager-wait-online", "Network Manager Wait Online", "active", "exited"),
		unit("NetworkManager", "Network Manager", "active", "running"),
		unit("apparmor", "Load AppArmor profiles", "inactive", "dead"),
		unit("avahi-daemon", "Avahi mDNS/DNS-SD Stack", "active", "running"),
		unit("bluetooth", "Bluetooth service", "active", "running"),
		unit("cloud-config", "Apply the settings specified in cloud-config", "active", "exited"),
		unit("cloud-final", "Execute cloud user/final scripts", "active", "exited"),
		unit("cloud-init-local", "Initial cloud-init job (pre-networking)", "active", "exited"),
		unit("cloud-init-main", "Initial cloud-init job (metadata service crawler)", "inactive", "dead"),
		unit("cloud-init-network", "Initial cloud-init job (network)", "active", "exited"),
		unit("console-setup", "Set console font and keymap", "active", "exited"),
		unit("cron", "Regular background program processing daemon", "active", "running"),
		unit("e2scrub_reap", "Remove Stale Online ext4 Metadata Check Snapshots", "inactive", "dead"),
		unit("grid-agent", "Nexara Grid Agent", "active", "running"),
		unit("keyboard-setup", "Set the console keyboard layout", "active", "exited"),
		unit("netplan-ovs-cleanup", "OpenVSwitch configuration for cleanup", "inactive", "dead"),
		unit("nexus", "Nexara Nexus", "active", "running"),
		unit("nmbd", "Samba NMB Daemon", "active", "running"),
		unit("plexmediaserver", "Plex Media Server for Linux", "active", "running"),
		unit("regenerate_ssh_host_keys", "Regenerate SSH host keys", "inactive", "dead"),
		unit("rpi-eeprom-update", "Checks if the RPi EEPROM can be updated", "active", "exited"),
		unit("samba-ad-dc", "Samba AD Daemon", "inactive", "dead"),
		unit("smartmontools", "Self Monitoring and Reporting Technology (SMART) Daemon", "active", "running"),
		unit("smbd", "Samba SMB Daemon", "active", "running"),
		unit("ssh", "OpenBSD Secure Shell server", "active", "running"),
		unit("sshd-keygen", "Generate sshd host keys on first boot", "inactive", "dead"),
		unit("sshswitch", "Turn on SSH if /boot/ssh is present", "inactive", "dead"),
		unit("stash", "Stash media organizer", "active", "running"),
		unit("winbind", "Samba Winbind Daemon", "active", "running"),
		unit("wpa_supplicant", "WPA supplicant", "active", "running"),
	}
}

func largeDisks() []protocol.Disk {
	const gb, tb = 1_000_000_000, 1_000_000_000_000
	return []protocol.Disk{
		{Mount: "/", Total: 62 * gb, Used: 20 * gb},
		{Mount: "/boot/firmware", Total: 529_000_000, Used: 69_000_000},
		{Mount: "/mnt/media/stuff", Total: 3 * tb, Used: 2_950_000_000_000},
		{Mount: "/mnt/media/stuff2", Total: 3 * tb, Used: 2_900_000_000_000},
		{Mount: "/mnt/media/stuff3", Total: 5 * tb, Used: 4_900_000_000_000},
	}
}

var (
	largePrefixes = []string{"lib", "python3-", "libreoffice-", "gir1.2-", "fonts-", "perl-", "node-", "golang-", "lib", "lib", "xserver-", "gstreamer1.0-"}
	largeStems    = []string{"alsa", "apt", "avahi", "bluez", "cairo", "curl", "dbus", "ffi", "fftw3", "gcc", "gdbm", "glib", "gnutls", "gpm", "icu", "json", "krb5", "lzma", "mnl", "nettle", "ogg", "pam", "pcre", "png", "pulse", "sdl2", "sqlite3", "ssl3", "tiff", "udev", "usb", "vorbis", "xml2", "yaml", "zstd"}
	largeSummary  = []string{"shared library", "runtime files", "development files", "documentation", "command-line tools", "data files", "plugins", "helper utilities"}
)

// largePackages builds about largePackageTarget packages on top of the design rows: 16 updates, 8
// orphans, the rest installed, in the alphabetical order an agent reports them. The names are unique
// and the data is deterministic.
func largePackages() []protocol.Package {
	out := designPackages(true)
	seen := make(map[string]bool, largePackageTarget)
	for _, p := range out {
		seen[p.Name] = true
	}
	for i := 0; len(out) < largePackageTarget && i < 10*largePackageTarget; i++ {
		name := fmt.Sprintf("%s%s%d", largePrefixes[i%len(largePrefixes)], largeStems[(i*3)%len(largeStems)], 1+(i/420)%9)
		if i%3 == 0 {
			name += ":arm64"
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		summary := fmt.Sprintf("%s - %s", largeStems[(i*5)%len(largeStems)], largeSummary[i%len(largeSummary)])
		size := int64(20_000 + (i*7919)%40_000_000)
		inst := fmt.Sprintf("%d.%d.%d-%d", 1+i%4, i%12, i%30, 1+i%3)
		switch {
		case i%58 == 0:
			out = append(out, pkg(name, summary, inst, fmt.Sprintf("%d.%d.%d-%d", 1+i%4, i%12, i%30+1, 1+i%3), size, protocol.PackageUpdate))
		case i%101 == 0:
			out = append(out, pkg(name, summary+" (no longer needed)", inst, "", size, protocol.PackageOrphaned))
		default:
			out = append(out, pkg(name, summary, inst, "", size, protocol.PackageInstalled))
		}
	}
	return out
}
