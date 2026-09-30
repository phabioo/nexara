package services

import (
	"sort"
	"strconv"
	"strings"

	"github.com/phabioo/nexara/internal/protocol"
)

// listener is one listening socket parsed from /proc/net/{tcp,tcp6,udp,udp6}.
type listener struct {
	Proto string // "tcp" or "udp"
	Port  uint16
	Inode uint64
}

// parseProcNet parses the content of one /proc/net/{tcp,tcp6,udp,udp6} file.
// For tcp only state 0A (LISTEN) counts, for udp state 07 (unconnected).
func parseProcNet(proto, content string) []listener {
	wantState := "0A"
	if proto == "udp" {
		wantState = "07"
	}
	var out []listener
	for i, line := range strings.Split(content, "\n") {
		if i == 0 {
			continue // header
		}
		f := strings.Fields(line)
		if len(f) < 10 || f[3] != wantState {
			continue
		}
		_, portHex, ok := strings.Cut(f[1], ":")
		if !ok {
			continue
		}
		port, err := strconv.ParseUint(portHex, 16, 16)
		if err != nil || port == 0 {
			continue
		}
		inode, err := strconv.ParseUint(f[9], 10, 64)
		if err != nil {
			continue
		}
		out = append(out, listener{Proto: proto, Port: uint16(port), Inode: inode})
	}
	return out
}

// parseSocketLink extracts the inode from a /proc/PID/fd link target such as
// "socket:[12345]".
func parseSocketLink(target string) (uint64, bool) {
	rest, ok := strings.CutPrefix(target, "socket:[")
	if !ok {
		return 0, false
	}
	rest, ok = strings.CutSuffix(rest, "]")
	if !ok {
		return 0, false
	}
	inode, err := strconv.ParseUint(rest, 10, 64)
	return inode, err == nil
}

// summarizePorts deduplicates by proto and port (IPv4 and IPv6 sockets, several
// workers) and attaches the owning process name by socket inode. The first
// known owner wins. Output is sorted by proto, then port.
func summarizePorts(ls []listener, owners map[uint64]string) []protocol.ListeningPort {
	type key struct {
		proto string
		port  uint16
	}
	idx := map[key]int{}
	out := []protocol.ListeningPort{}
	for _, l := range ls {
		k := key{l.Proto, l.Port}
		name := owners[l.Inode]
		if i, ok := idx[k]; ok {
			if out[i].Process == "" {
				out[i].Process = name
			}
			continue
		}
		idx[k] = len(out)
		out = append(out, protocol.ListeningPort{Proto: l.Proto, Port: l.Port, Process: name})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Proto != out[j].Proto {
			return out[i].Proto < out[j].Proto
		}
		return out[i].Port < out[j].Port
	})
	return out
}
