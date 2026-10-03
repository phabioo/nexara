package app

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/pki"
)

func TestLoadServerCert(t *testing.T) {
	dir := t.TempDir()
	if _, err := loadServerCert(dir); err == nil {
		t.Error("missing certificate: no error")
	}
	ca, err := pki.LoadOrCreateCA(dir, "frpi5.local")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pki.EnsureServerCert(ca, dir, []string{"frpi5", "frpi5.local"}, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	cert, err := loadServerCert(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.DNSNames) == 0 || cert.NotAfter.Before(time.Now()) {
		t.Errorf("certificate = %v until %v", cert.DNSNames, cert.NotAfter)
	}
	if err := os.WriteFile(filepath.Join(dir, pki.ServerCertFile), []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadServerCert(dir); err == nil {
		t.Error("garbage certificate: no error")
	}
}
