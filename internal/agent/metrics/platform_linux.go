//go:build linux

package metrics

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// readTemperature reads the SoC temperature from the thermal zones.
func readTemperature() *float64 {
	dirs, _ := filepath.Glob("/sys/class/thermal/thermal_zone*")
	var zones []thermalZone
	for _, d := range dirs {
		raw, err := os.ReadFile(filepath.Join(d, "temp"))
		if err != nil {
			continue
		}
		milli, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
		if err != nil {
			continue
		}
		typ, _ := os.ReadFile(filepath.Join(d, "type"))
		zones = append(zones, thermalZone{Type: strings.TrimSpace(string(typ)), Milli: milli})
	}
	return pickTemperature(zones)
}

// primaryInterface is the default route interface.
func primaryInterface() string {
	raw, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	return parseDefaultRoute(string(raw))
}

// readModel returns the board model from the device tree (Raspberry Pi etc.).
func readModel() string {
	raw, err := os.ReadFile("/proc/device-tree/model")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(bytes.Trim(raw, "\x00")))
}
