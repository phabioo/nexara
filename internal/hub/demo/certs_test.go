package demo

import (
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/pki"
)

// The demo shows what a healthy install looks like: agent certificates last a
// year and are renewed 30 days before they expire, so none shows less than that.
func TestHostsShowSensibleCertificateExpiry(t *testing.T) {
	h, _ := newHub(t, 0.001)

	h.mu.Lock()
	added := h.addHost("pi-new", "pi-new", "192.168.10.77", nil)
	h.mu.Unlock()

	hosts := h.Hosts()
	if len(hosts) != 4 {
		t.Fatalf("%d hosts, want the design's three plus the new one", len(hosts))
	}
	for _, info := range hosts {
		left := info.CertNotAfter.Sub(clockStart)
		if info.CertNotAfter.IsZero() {
			t.Errorf("%s: no certificate expiry", info.Name)
			continue
		}
		if left <= pki.RenewBefore || left > pki.LeafValidity {
			t.Errorf("%s: certificate expires in %v, want between the renewal window and a year", info.Name, left.Round(time.Hour))
		}
	}
	if got := added.info.CertNotAfter.Sub(clockStart); got != pki.LeafValidity {
		t.Errorf("a host enrolled now gets a certificate for %v, want %v", got, pki.LeafValidity)
	}
	if info, ok := h.Host(hosts[0].ID); !ok || info.CertNotAfter.IsZero() {
		t.Errorf("Host() lost the certificate expiry: %+v", info)
	}
}
