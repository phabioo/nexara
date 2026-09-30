package app

import (
	"errors"
	"fmt"
	"net"
	"strconv"
)

// LoopbackAddr validates the listen address of `nexus dev --demo` (decision
// #34: plain HTTP, loopback only) and returns the address to bind. The host
// must be an IPv4/IPv6 loopback address or "localhost" (bound as 127.0.0.1);
// an empty host, 0.0.0.0, [::] and every other address are rejected, because
// they would expose the unauthenticated demo on the network. Port 0 picks a
// free port.
func LoopbackAddr(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("invalid listen address %q (want host:port, e.g. 127.0.0.1:8080)", addr)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 0 || n > 65535 {
		return "", fmt.Errorf("invalid port %q in listen address", port)
	}
	if host == "localhost" {
		return net.JoinHostPort("127.0.0.1", port), nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", errors.New("dev mode serves plain HTTP and listens on loopback only; use 127.0.0.1, [::1] or localhost")
	}
	return net.JoinHostPort(ip.String(), port), nil
}
