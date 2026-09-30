package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/phabioo/nexara/internal/config"
	"github.com/phabioo/nexara/internal/hub/enroll"
	"github.com/phabioo/nexara/internal/pki"
)

type rtEnv struct {
	rt  *hubRuntime
	ce  *certEnv
	dir string
}

func newRuntimeEnv(t *testing.T) *rtEnv {
	t.Helper()
	ce := newCertEnv(t)
	if _, err := ce.m.Ensure(); err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	st := openStore(t, dataDir)
	newEnroll := func(host string, port int) (*enroll.Service, error) {
		return enroll.New(enroll.Options{
			Store: st, CA: ce.ca, ServerCertFile: filepath.Join(ce.dir, pki.ServerCertFile),
			HubAddress: host, Port: port, DataDir: dataDir,
		})
	}
	svc, err := newEnroll("hub.local", 8443)
	if err != nil {
		t.Fatal(err)
	}
	return &rtEnv{
		rt: &hubRuntime{
			certs: ce.m, enrollers: newEnrollHolder(svc), newEnroll: newEnroll, listenPort: 8443, dataDir: dataDir,
		},
		ce: ce, dir: dataDir,
	}
}

func TestApplyHubSwitchesEnrollmentAndCertificate(t *testing.T) {
	e := newRuntimeEnv(t)
	ctx := context.Background()

	before, err := e.rt.enrollers.NewEnrollCode(ctx, grid0(), emptyOpts())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(before.Command, "https://hub.local:8443/grid/install.sh") {
		t.Fatalf("command = %q", before.Command)
	}

	cfg := config.DefaultHub()
	cfg.Hub.AgentAddress = "hub.example:9443"
	if err := e.rt.applyHub(cfg); err != nil {
		t.Fatal(err)
	}
	after, err := e.rt.enrollers.NewEnrollCode(ctx, grid0(), emptyOpts())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(after.Command, "https://hub.example:9443/grid/install.sh") {
		t.Errorf("enrollment still uses the old address: %q", after.Command)
	}
	// The pin in the one-liner follows the re-issued certificate.
	if pinOf(before.Command) == pinOf(after.Command) {
		t.Error("the pinned key did not change although the certificate was re-issued")
	}

	data, err := os.ReadFile(filepath.Join(e.ce.dir, pki.ServerCertFile))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := pki.ParseCertPEM(data)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(leaf.DNSNames, "hub.example") {
		t.Errorf("certificate names = %v", leaf.DNSNames)
	}

	// The HTTP handler of /grid/install.sh follows too.
	rec := httptest.NewRecorder()
	e.rt.enrollers.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/grid/install.sh", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "hub.example") {
		t.Errorf("install.sh: %d, mentions new host: %v", rec.Code, strings.Contains(rec.Body.String(), "hub.example"))
	}

	// An address the enrollment cannot use is an error and leaves the old service in place.
	cfg.Hub.AgentAddress = "bad host name"
	if err := e.rt.applyHub(cfg); err == nil {
		t.Error("invalid agent address accepted")
	}
	again, err := e.rt.enrollers.NewEnrollCode(ctx, grid0(), emptyOpts())
	if err != nil || !strings.Contains(again.Command, "hub.example:9443") {
		t.Errorf("service replaced despite the error: %v %q", err, again.Command)
	}
}

func TestWriteSelfLink(t *testing.T) {
	e := newRuntimeEnv(t)
	if err := e.rt.writeSelfLink(context.Background(), []string{"monitoring", "shell"}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(e.dir, SelfEnrollTokenFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var link struct {
		Token         string `json:"token"`
		CAFingerprint string `json:"ca_fingerprint"`
		Hub           string `json:"hub"`
	}
	if err := json.Unmarshal(data, &link); err != nil {
		t.Fatal(err)
	}
	if link.Token == "" || link.CAFingerprint != e.ce.ca.Fingerprint() || !strings.HasPrefix(link.Hub, "https://127.0.0.1:8443") {
		t.Errorf("self-link file = %+v", link)
	}
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o640 {
			t.Errorf("token file mode = %v %v, want 0640", fi.Mode().Perm(), err)
		}
	}
	// Invalid capabilities are refused (no file replaced).
	if err := e.rt.writeSelfLink(context.Background(), []string{"teleport"}); err == nil {
		t.Error("unknown capability accepted")
	}
}

func pinOf(command string) string {
	_, rest, _ := strings.Cut(command, "sha256//")
	pin, _, _ := strings.Cut(rest, " ")
	return pin
}
