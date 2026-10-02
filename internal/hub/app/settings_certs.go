package app

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"

	"github.com/phabioo/nexara/internal/pki"
)

// loadServerCert reads the hub's current TLS certificate from the TLS directory
// (Settings › Certificates). The certificate is renewed in place by the cert
// manager, so the file is read on every call.
func loadServerCert(tlsDir string) (*x509.Certificate, error) {
	data, err := os.ReadFile(filepath.Join(tlsDir, pki.ServerCertFile))
	if err != nil {
		return nil, fmt.Errorf("read server certificate: %w", err)
	}
	return pki.ParseCertPEM(data)
}
