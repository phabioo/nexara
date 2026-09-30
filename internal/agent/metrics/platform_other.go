//go:build !linux

package metrics

import "net"

// readTemperature: no portable sensor access outside Linux.
func readTemperature() *float64 { return nil }

func readModel() string { return "" }

// primaryInterface picks the first interface that is up, not loopback and has
// a hardware address. Good enough for the generic implementation.
func primaryInterface() string {
	ifs, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, i := range ifs {
		if i.Flags&net.FlagUp != 0 && i.Flags&net.FlagLoopback == 0 && len(i.HardwareAddr) > 0 {
			return i.Name
		}
	}
	return ""
}
