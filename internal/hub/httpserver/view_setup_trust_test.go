package httpserver

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/phabioo/nexara/internal/hub/setup"
	"github.com/phabioo/nexara/internal/pki"
)

func withCA(t *testing.T, e *setupEnv) *pki.CA {
	t.Helper()
	ca, err := pki.LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	e.srv.setup.CA = ca
	return ca
}

func TestSetupTrustStep(t *testing.T) {
	e := newSetupEnv(t)
	ca := withCA(t, e)
	b := e.browser(t)
	b.ho = "frpi5.local:8443"
	b.unlock()

	t.Run("page", func(t *testing.T) {
		rec := b.get("/setup/trust")
		if rec.Code != 200 {
			t.Fatalf("status %d", rec.Code)
		}
		full := setupColonFingerprint(ca.Fingerprint())
		wantBody(t, rec, "Trust this hub", "STEP 2/7", `<svg class="qr"`, "Scan on your phone",
			"This computer (.crt)", "iPhone / iPad (profile)", "Android (.crt)", "Skip for now",
			`href="/setup/trust/nexara-ca.crt"`, `href="/setup/trust/nexara-ca.mobileconfig"`,
			"Must match the fingerprint the installer printed.")
		// The fingerprint is shown in full, byte by byte, so lines can break between bytes.
		body := strings.ReplaceAll(rec.Body.String(), "<wbr>", "")
		if !strings.Contains(body, "SHA-256 "+full) {
			t.Errorf("full fingerprint %s missing", full)
		}
		wantNoBody(t, rec, "data:image")
	})

	t.Run("unlock page shows the abbreviated fingerprint", func(t *testing.T) {
		rec := e.browser(t).get("/setup")
		wantBody(t, rec, "Cert  SHA-256 "+setupShortFingerprint(ca.Fingerprint()))
	})

	t.Run("a download makes Trust continuable and is noted in the summary", func(t *testing.T) {
		fresh := e.browser(t)
		fresh.ho = b.ho
		fresh.walkTo(setup.StepTrust)
		wantBody(t, fresh.get("/setup/trust"), "<span>Skip for now</span>")
		rec := fresh.get("/setup/trust/nexara-ca.crt")
		c := findCookie(rec, trustCookie)
		assertCookieAttrs(t, c)
		if c.Value != "1" || c.Path != "/setup" {
			t.Errorf("trust cookie = %+v", c)
		}
		wantBody(t, fresh.get("/setup/trust"), "<span>Continue</span>")
	})
}

func TestSetupTrustSummary(t *testing.T) {
	e := newSetupEnv(t)
	withCA(t, e)
	b := e.browser(t)
	b.walkTo(setup.StepReady)
	wantBody(t, b.get("/setup/ready"), "Not installed yet")
	b.get("/setup/trust/nexara-ca.mobileconfig")
	wantBody(t, b.get("/setup/ready"), "Nexara CA downloaded")
	wantBody(t, b.get("/setup/operator"), "Nexara CA downloaded on this device")
}

func TestSetupTrustDownloads(t *testing.T) {
	e := newSetupEnv(t)
	ca := withCA(t, e)

	t.Run("certificate", func(t *testing.T) {
		rec := e.browser(t).get("/setup/trust/nexara-ca.crt")
		if rec.Code != 200 {
			t.Fatalf("status %d", rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/x-x509-ca-cert" {
			t.Errorf("content type %q", ct)
		}
		if cd := rec.Header().Get("Content-Disposition"); cd != `attachment; filename="nexara-ca.crt"` {
			t.Errorf("content disposition %q", cd)
		}
		if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Error("nosniff missing")
		}
		fp, err := pki.FingerprintFromPEM(rec.Body.Bytes())
		if err != nil || fp != ca.Fingerprint() {
			t.Errorf("downloaded certificate does not match the CA: %v", err)
		}
		if strings.Contains(rec.Body.String(), "PRIVATE KEY") {
			t.Fatal("the private key must never be served")
		}
	})

	t.Run("iOS profile", func(t *testing.T) {
		rec := e.browser(t).get("/setup/trust/nexara-ca.mobileconfig")
		if rec.Code != 200 {
			t.Fatalf("status %d", rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/x-apple-aspen-config" {
			t.Errorf("content type %q", ct)
		}
		body := rec.Body.Bytes()
		// Well-formed XML ...
		dec := xml.NewDecoder(strings.NewReader(string(body)))
		dec.Strict = false
		dec.Entity = xml.HTMLEntity
		for {
			if _, err := dec.Token(); err != nil {
				if err != io.EOF {
					t.Fatalf("profile is not well-formed: %v", err)
				}
				break
			}
		}
		// ... carrying exactly the CA certificate as root payload.
		s := string(body)
		for _, want := range []string{"com.apple.security.root", "<key>PayloadType</key>\n\t<string>Configuration</string>", "<false/>"} {
			if !strings.Contains(s, want) {
				t.Errorf("profile lacks %q", want)
			}
		}
		m := regexp.MustCompile(`<data>([A-Za-z0-9+/=]+)</data>`).FindStringSubmatch(s)
		if m == nil {
			t.Fatal("no certificate data in the profile")
		}
		der, err := base64.StdEncoding.DecodeString(m[1])
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(ca.CertPEM())
		if string(der) != string(block.Bytes) {
			t.Error("profile carries a different certificate")
		}
		uuids := regexp.MustCompile(`<string>([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})</string>`).FindAllStringSubmatch(s, -1)
		if len(uuids) != 2 || uuids[0][1] == uuids[1][1] {
			t.Errorf("payload UUIDs = %v", uuids)
		}
		// Deterministic for one CA.
		again := e.browser(t).get("/setup/trust/nexara-ca.mobileconfig")
		if again.Body.String() != s {
			t.Error("profile differs between downloads")
		}
	})

	t.Run("files are public during setup, without a setup session", func(t *testing.T) {
		for _, p := range []string{"/setup/trust/nexara-ca.crt", "/setup/trust/nexara-ca.mobileconfig"} {
			if rec := e.browser(t).get(p); rec.Code != 200 {
				t.Errorf("%s: %d", p, rec.Code)
			}
		}
	})

	t.Run("the grid copies are closed while setup runs", func(t *testing.T) {
		for _, p := range []string{"/grid/ca.crt", "/grid/ca.mobileconfig"} {
			if rec := e.browser(t).get(p); rec.Code != 503 {
				t.Errorf("%s during setup: %d, want 503", p, rec.Code)
			}
		}
	})

	t.Run("after setup the grid copies are public and /setup is gone", func(t *testing.T) {
		e.setSetupMode(false)
		defer e.setSetupMode(true)
		for _, p := range []string{"/grid/ca.crt", "/grid/ca.mobileconfig"} {
			rec := e.browser(t).get(p) // no session cookie
			if rec.Code != 200 {
				t.Errorf("%s: %d", p, rec.Code)
			}
			if findCookie(rec, trustCookie) != nil {
				t.Errorf("%s sets the setup cookie", p)
			}
		}
		wantRedirect(t, e.browser(t).get("/setup/trust/nexara-ca.crt"), "/")
	})

	t.Run("POST is not allowed", func(t *testing.T) {
		rec := e.browser(t).post("/setup/trust/nexara-ca.crt", nil)
		if rec.Code == 200 {
			t.Error("POST served the certificate")
		}
	})
}

func TestSetupTrustQR(t *testing.T) {
	e := newSetupEnv(t)
	withCA(t, e)
	tests := []struct {
		name, host string
		tls        bool
		wantQR     bool
	}{
		{"plain host", "frpi5.local:8443", false, true},
		{"tls", "frpi5.local:8443", true, true},
		{"host with userinfo is not encoded", "evil@frpi5.local", false, false},
		{"host with slash is not encoded", "a/b", false, false},
		{"empty host", "", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/setup/trust", nil)
			r.Host = tt.host
			if tt.tls {
				r.TLS = &tls.ConnectionState{}
			}
			p := &setupPage{}
			e.srv.setupFillTrust(p, r)
			if !p.TrustAvailable {
				t.Fatal("trust not available")
			}
			if (p.TrustQR != "") != tt.wantQR {
				t.Errorf("QR present = %v, want %v", p.TrustQR != "", tt.wantQR)
			}
			if p.TrustQR != "" && !strings.HasPrefix(string(p.TrustQR), "<svg ") {
				t.Errorf("not an svg: %.60s", p.TrustQR)
			}
		})
	}
}

func TestSetupFingerprintFormats(t *testing.T) {
	const hex64 = "4f9a12c7aabbccddeeff00112233445566778899aabbccddeeff00112233" + "8ec2"
	tests := []struct{ in, colon, short string }{
		{hex64, "4F:9A:12:C7:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:8E:C2", "4F:9A:12:C7 … 8E:C2"},
		{"4F:9A:12:C7:AA:BB:CC:DD", "4F:9A:12:C7:AA:BB:CC:DD", "4F:9A:12:C7 … CC:DD"},
		{"4F:9A", "4F:9A", "4F:9A"},
		{"not hex", "NOT HEX", "NOT HEX"},
	}
	for _, tt := range tests {
		if got := setupColonFingerprint(tt.in); got != strings.ToUpper(tt.colon) && tt.in != "not hex" {
			t.Errorf("colon(%q) = %q", tt.in, got)
		}
		if got := setupShortFingerprint(tt.in); got != tt.short && tt.in != "not hex" {
			t.Errorf("short(%q) = %q, want %q", tt.in, got, tt.short)
		}
	}
}
