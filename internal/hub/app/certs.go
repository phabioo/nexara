package app

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/phabioo/nexara/internal/pki"
)

// DefaultCertCheckInterval is how often the server certificate is checked for
// expiry and for changed host names or IP addresses.
const DefaultCertCheckInterval = 24 * time.Hour

// certManager keeps the hub's server certificate current (decision #19): it
// re-issues it when the names or IPs of the device change, when the agent
// address chosen in the setup wizard is not covered, and 30 days before
// expiry. The listener's TLS config reloads the files on the next handshake
// (pki.ServerTLSConfig), so no restart is needed.
type certManager struct {
	ca  *pki.CA
	dir string
	log *slog.Logger
	now func() time.Time

	localNames func() []string
	localIPs   func() []net.IP

	mu        sync.Mutex
	agentHost string // DNS name or IP from hub.agent_address; added to the SANs
}

func newCertManager(ca *pki.CA, dir string, log *slog.Logger, now func() time.Time) *certManager {
	return &certManager{ca: ca, dir: dir, log: log, now: now, localNames: pki.LocalNames, localIPs: pki.LocalIPs}
}

// SetAgentHost sets the extra name or IP the certificate must cover.
func (m *certManager) SetAgentHost(host string) {
	m.mu.Lock()
	m.agentHost = host
	m.mu.Unlock()
}

// Ensure issues a new certificate if needed and reports whether it did.
func (m *certManager) Ensure() (bool, error) {
	names := m.localNames()
	ips := m.localIPs()
	m.mu.Lock()
	extra := m.agentHost
	m.mu.Unlock()
	if extra != "" {
		if ip := net.ParseIP(extra); ip != nil {
			ips = append(append([]net.IP(nil), ips...), ip)
		} else {
			names = append(append([]string(nil), names...), extra)
		}
	}
	issued, err := pki.EnsureServerCert(m.ca, m.dir, names, ips, m.now())
	if err != nil {
		return false, err
	}
	if issued {
		m.log.Info("server certificate issued", "dir", m.dir, "names", len(names), "ips", len(ips))
	}
	return issued, nil
}

// Run checks the certificate every interval until ctx ends.
func (m *certManager) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultCertCheckInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := m.Ensure(); err != nil {
				m.log.Error("server certificate check failed", "err", err)
			}
		}
	}
}
