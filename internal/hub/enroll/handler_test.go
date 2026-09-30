package enroll

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/pki"
)

func TestEnrollHappyPath(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	code := e.newCode(nil)

	w, resp := e.post(code, "Pi-Kitchen.fritz.box", "192.168.10.23")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if resp.HubURL != "wss://frpi5.local:8443/grid/connect" {
		t.Fatalf("hub_url %q", resp.HubURL)
	}
	if resp.Settings.Capabilities != nil {
		t.Fatalf("nil capabilities (defaults) expected, got %v", resp.Settings.Capabilities)
	}
	if !strings.Contains(w.Body.String(), `"capabilities":null`) {
		t.Fatalf("capabilities must be JSON null for agent defaults: %s", w.Body)
	}
	if resp.CAPEM != string(e.ca.CertPEM()) {
		t.Fatal("wrong CA in response")
	}

	cert, err := pki.ParseCertPEM([]byte(resp.CertPEM))
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != resp.HostID {
		t.Fatalf("CN %q, host id %q", cert.Subject.CommonName, resp.HostID)
	}
	h, err := e.st.GetHost(ctx, resp.HostID)
	if err != nil {
		t.Fatal(err)
	}
	if h.Name != "pi-kitchen" || h.Address != "192.168.10.23" || h.OS != "linux" || h.Arch != "arm64" ||
		h.MAC != "dc:a6:32:11:22:33" || h.AgentVersion != "0.1.0" {
		t.Fatalf("host %+v", h)
	}
	if h.CertFingerprint != pki.Fingerprint(cert) || h.CertSerial != pki.SerialHex(cert) || !h.CertNotAfter.Equal(cert.NotAfter.Truncate(time.Second)) {
		t.Fatalf("cert data not stored: %+v", h)
	}
	if got := strings.Join(h.Capabilities, ","); got != "monitoring,packages" {
		t.Fatalf("capabilities %q (agent defaults from hello expected)", got)
	}
	tok, err := e.st.GetEnrollToken(ctx, hashCode(code))
	if err != nil || tok.HostID != h.ID || tok.UsedAt.IsZero() {
		t.Fatalf("token %+v %v", tok, err)
	}
	if got := e.enrolledHosts(); len(got) != 1 || got[0].ID != h.ID {
		t.Fatalf("OnEnrolled calls: %+v", got)
	}

	var ok bool
	for _, a := range e.auditActions() {
		if a.Action == "enroll.ok" {
			ok = true
			if a.Result != store.AuditOK || a.Host != "pi-kitchen" {
				t.Fatalf("audit %+v", a)
			}
		}
		if strings.Contains(a.Detail, code) {
			t.Fatalf("code in audit: %+v", a)
		}
	}
	if !ok {
		t.Fatal("no enroll.ok audit entry")
	}
	if strings.Contains(e.logs.String(), code) {
		t.Fatal("code in log")
	}
}

func TestEnrollCapabilitiesFromToken(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	_, resp := e.post(e.newCode([]string{"monitoring", "shell"}), "pi-a", "192.0.2.5")
	if got := strings.Join(resp.Settings.Capabilities, ","); got != "monitoring,shell" {
		t.Fatalf("settings %q", got)
	}
	h, _ := e.st.GetHost(ctx, resp.HostID)
	if got := strings.Join(h.Capabilities, ","); got != "monitoring,shell" {
		t.Fatalf("host capabilities %q", got)
	}

	w, resp := e.post(e.newCode([]string{}), "pi-b", "192.0.2.6")
	if !strings.Contains(w.Body.String(), `"capabilities":[]`) {
		t.Fatalf("empty list must stay an empty array: %s", w.Body)
	}
	h, _ = e.st.GetHost(ctx, resp.HostID)
	if len(h.Capabilities) != 0 {
		t.Fatalf("all off expected, got %v", h.Capabilities)
	}
}

func TestEnrollReusesExistingHostName(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	_, first := e.post(e.newCode(nil), "pi-kitchen", "192.0.2.5")
	h1, _ := e.st.GetHost(ctx, first.HostID)
	if err := e.st.SetHostDisplayName(ctx, h1.ID, "Kitchen Pi"); err != nil {
		t.Fatal(err)
	}

	e.clock.Advance(time.Hour)
	w, second := e.post(e.newCode([]string{"monitoring"}), "PI-KITCHEN", "192.0.2.77")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if second.HostID != first.HostID {
		t.Fatalf("host re-created: %s vs %s", second.HostID, first.HostID)
	}
	hosts, _ := e.st.ListHosts(ctx)
	if len(hosts) != 1 {
		t.Fatalf("%d hosts", len(hosts))
	}
	h2 := hosts[0]
	if h2.DisplayName != "Kitchen Pi" {
		t.Fatalf("display name lost: %q", h2.DisplayName)
	}
	if h2.Address != "192.0.2.77" || len(h2.Capabilities) != 1 {
		t.Fatalf("host not refreshed: %+v", h2)
	}
	if h2.CertFingerprint == h1.CertFingerprint || h2.CertSerial == h1.CertSerial {
		t.Fatal("certificate was not replaced")
	}
	// The old certificate no longer maps to a host.
	if _, err := e.st.GetHostByFingerprint(ctx, h1.CertFingerprint); err == nil {
		t.Fatal("old certificate still valid")
	}
	if got, err := e.st.GetHostByFingerprint(ctx, h2.CertFingerprint); err != nil || got.ID != h1.ID {
		t.Fatalf("new certificate: %v", err)
	}
	if len(e.enrolledHosts()) != 2 {
		t.Fatal("OnEnrolled must fire for re-enrollment too")
	}
}

func TestEnrollRevokedHostIsRefused(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	_, first := e.post(e.newCode(nil), "pi-kitchen", "192.0.2.5")
	if err := e.st.RevokeHost(ctx, first.HostID); err != nil {
		t.Fatal(err)
	}
	w, _ := e.post(e.newCode(nil), "pi-kitchen", "192.0.2.5")
	if w.Code != http.StatusConflict {
		t.Fatalf("status %d", w.Code)
	}
	h, _ := e.st.GetHost(ctx, first.HostID)
	if !h.Revoked {
		t.Fatal("host was un-revoked")
	}
}

func TestEnrollInvalidTokensAreUniform(t *testing.T) {
	e := newEnv(t)
	used := e.newCode(nil)
	if w, _ := e.post(used, "pi-one", "192.0.2.5"); w.Code != http.StatusOK {
		t.Fatalf("first use failed: %d", w.Code)
	}
	expired := e.newCode(nil)
	e.clock.Advance(16 * time.Minute)

	var bodies []string
	for name, token := range map[string]string{
		"unknown": "GRID-AAAA-BBBB",
		"used":    used,
		"expired": expired,
		"empty":   "",
		"huge":    strings.Repeat("A", 500),
	} {
		w, _ := e.post(token, "pi-two", "192.0.2.9")
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s: status %d", name, w.Code)
		}
		bodies = append(bodies, w.Body.String())
	}
	for _, b := range bodies[1:] {
		if b != bodies[0] {
			t.Fatalf("responses differ: %q vs %q", b, bodies[0])
		}
	}
	denied := 0
	for _, a := range e.auditActions() {
		if a.Action == "enroll.denied" && a.Result == store.AuditDenied {
			denied++
		}
	}
	if denied != 5 {
		t.Fatalf("%d denied audit entries, want 5", denied)
	}
}

func TestEnrollTokenSingleUse(t *testing.T) {
	e := newEnv(t)
	code := e.newCode(nil)
	if w, _ := e.post(code, "pi-one", "192.0.2.5"); w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	if w, _ := e.post(code, "pi-one", "192.0.2.5"); w.Code != http.StatusUnauthorized {
		t.Fatalf("second use: status %d", w.Code)
	}
}

func TestEnrollRateLimitPerIP(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < enrollRate; i++ {
		if w, _ := e.post("GRID-WRNG-TOKN", "pi", "192.0.2.50"); w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status %d", i, w.Code)
		}
	}
	w, _ := e.post("GRID-WRNG-TOKN", "pi", "192.0.2.50")
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("status %d", w.Code)
	}
	// A valid code from the blocked address is refused as well (no oracle while limited) ...
	if w, _ := e.post(e.newCode(nil), "pi", "192.0.2.50"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d", w.Code)
	}
	// ... while other addresses are unaffected, and the block ends with the window.
	if w, _ := e.post(e.newCode(nil), "pi-ok", "192.0.2.51"); w.Code != http.StatusOK {
		t.Fatalf("other IP: status %d", w.Code)
	}
	e.clock.Advance(61 * time.Second)
	if w, _ := e.post(e.newCode(nil), "pi-later", "192.0.2.50"); w.Code != http.StatusOK {
		t.Fatalf("after window: status %d", w.Code)
	}
}

func TestEnrollRejectsOversizedAndMalformedBodies(t *testing.T) {
	e := newEnv(t)
	big := bytes.Repeat([]byte("a"), maxEnrollBody+10)
	body := append([]byte(`{"token":"`), big...)
	body = append(body, []byte(`"}`)...)
	if w, _ := e.postBody(body, "192.0.2.5"); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized: status %d", w.Code)
	}
	if w, _ := e.postBody([]byte(`{not json`), "192.0.2.5"); w.Code != http.StatusBadRequest {
		t.Fatalf("malformed: status %d", w.Code)
	}
}

func TestEnrollInvalidHelloDoesNotBurnToken(t *testing.T) {
	e := newEnv(t)
	code := e.newCode(nil)
	for _, host := range []string{"bad_name!", "", "-lead", strings.Repeat("a", 64), "a b"} {
		if w, _ := e.post(code, host, "192.0.2.5"); w.Code != http.StatusBadRequest {
			t.Errorf("host %q: status %d", host, w.Code)
		}
	}
	// bad OS / arch / CSR
	_, csr, _ := pki.NewAgentKeyAndCSR("pi")
	for _, tt := range []struct{ name, goos, arch, csr string }{
		{"os", "plan9", "arm64", string(csr)},
		{"arch", "linux", "mips", string(csr)},
		{"csr", "linux", "arm64", "not a csr"},
	} {
		w, _ := e.postRaw(helloRequest(code, "pi", tt.goos, tt.arch, tt.csr), "192.0.2.5")
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d", tt.name, w.Code)
		}
	}
	if w, _ := e.post(code, "pi", "192.0.2.5"); w.Code != http.StatusOK {
		t.Fatalf("code was burned by invalid requests: status %d", w.Code)
	}
}

func TestInstallScriptEndpoint(t *testing.T) {
	e := newEnv(t)
	r := httptest.NewRequest(http.MethodGet, "/grid/install.sh", nil)
	w := httptest.NewRecorder()
	e.svc.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/") {
		t.Fatalf("status %d type %q", w.Code, w.Header().Get("Content-Type"))
	}
	certPEM, _ := os.ReadFile(filepath.Join(e.dir, "pki", pki.ServerCertFile))
	cert, _ := pki.ParseCertPEM(certPEM)
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	body := w.Body.String()
	for _, want := range []string{
		"PIN='sha256//" + base64.StdEncoding.EncodeToString(sum[:]) + "'",
		"CA_FP='" + e.ca.Fingerprint() + "'",
		"HUB_ADDR='frpi5.local'", "HUB_PORT='8443'", "set -eu",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("script lacks %q", want)
		}
	}
}

func TestDownloadEndpoint(t *testing.T) {
	e := newEnv(t)
	get := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		e.svc.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		return w
	}
	if w := get("/grid/download/linux/arm64"); w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), testBinary.Data) {
		t.Fatalf("status %d", w.Code)
	}
	for _, p := range []string{"/grid/download/linux/amd64", "/grid/download/windows/arm64", "/grid/download/..%2f/x", "/grid/download/linux/arm64/extra", "/grid/download/LINUX/arm64"} {
		if w := get(p); w.Code != http.StatusNotFound {
			t.Errorf("%s: status %d", p, w.Code)
		}
	}
	// POST is not allowed on the script or download paths
	w := httptest.NewRecorder()
	e.svc.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/grid/install.sh", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status %d", w.Code)
	}
}
