package httpserver

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/phabioo/nexara/internal/hub/views"
)

// TrustAnchor is the hub CA as far as the Trust step needs it. *pki.CA
// implements it.
type TrustAnchor interface {
	// CertPEM is the PEM encoded CA certificate.
	CertPEM() []byte
	// Fingerprint is the SHA-256 of the certificate as hex (any case, colons
	// allowed).
	Fingerprint() string
}

// trustAnchor returns the hub CA, or nil when this server was built without
// one (plain-HTTP dev mode).
//
// There is no dedicated field in Options yet, so it is looked up on the
// injected enroller handlers, which live next to the CA in the wiring. A
// SetupDeps.CA field would replace this body (see the report of the Setup view).
func (s *Server) trustAnchor() TrustAnchor {
	if a, ok := s.enroller.(TrustAnchor); ok && a != nil {
		return a
	}
	if a, ok := s.enroll.(TrustAnchor); ok && a != nil {
		return a
	}
	return nil
}

// trustCookie remembers that this browser downloaded the CA, so the Trust step
// offers "Continue" instead of "Skip for now" and the summary can say so.
const trustCookie = "nexus_setup_trust"

const (
	trustCertFile    = "nexara-ca.crt"
	trustProfileFile = "nexara-ca.mobileconfig"
)

func setupTrusted(r *http.Request) bool {
	c, err := r.Cookie(trustCookie)
	return err == nil && c.Value == "1"
}

// routesSetupTrust serves the CA certificate. During setup the files live under
// /setup/trust/ (the only paths the setup gate lets through); the /grid/ copies
// serve devices that are set up later, when /setup/ redirects away.
func (s *Server) routesSetupTrust(mux *http.ServeMux) {
	mux.HandleFunc("GET /setup/trust/"+trustCertFile, s.handleTrustCert(true))
	mux.HandleFunc("GET /setup/trust/"+trustProfileFile, s.handleTrustProfile(true))
	mux.HandleFunc("GET /grid/ca.crt", s.handleTrustCert(false))
	mux.HandleFunc("GET /grid/ca.mobileconfig", s.handleTrustProfile(false))
}

func (s *Server) markTrusted(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: trustCookie, Value: "1", Path: "/setup",
		HttpOnly: true, Secure: s.secure, SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) handleTrustCert(duringSetup bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a := s.trustAnchor()
		if a == nil {
			s.notFound(w, r)
			return
		}
		if duringSetup {
			s.markTrusted(w)
		}
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.Header().Set("Content-Disposition", `attachment; filename="`+trustCertFile+`"`)
		_, _ = w.Write(a.CertPEM())
	}
}

func (s *Server) handleTrustProfile(duringSetup bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a := s.trustAnchor()
		if a == nil {
			s.notFound(w, r)
			return
		}
		prof, err := trustMobileConfig(a)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		if duringSetup {
			s.markTrusted(w)
		}
		w.Header().Set("Content-Type", "application/x-apple-aspen-config")
		w.Header().Set("Content-Disposition", `attachment; filename="`+trustProfileFile+`"`)
		_, _ = w.Write(prof)
	}
}

// trustMobileConfig builds the unsigned iOS/iPadOS configuration profile that
// installs the CA as a root certificate. The payload UUIDs are derived from the
// CA fingerprint, so the same CA always yields the same profile and iOS treats
// a second download as an update, not a duplicate.
func trustMobileConfig(a TrustAnchor) ([]byte, error) {
	block, _ := pem.Decode(a.CertPEM())
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("httpserver: CA certificate is not PEM encoded")
	}
	fp := strings.ToUpper(strings.NewReplacer(":", "", " ", "").Replace(a.Fingerprint()))
	if len(fp) < 64 {
		return nil, fmt.Errorf("httpserver: CA fingerprint is too short")
	}
	uuid := func(h string) string {
		return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
	}
	certUUID, profUUID := uuid(fp[:32]), uuid(fp[32:64])
	der := base64.StdEncoding.EncodeToString(block.Bytes)

	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadCertificateFileName</key>
			<string>` + trustCertFile + `</string>
			<key>PayloadContent</key>
			<data>` + der + `</data>
			<key>PayloadDescription</key>
			<string>Adds the Nexara Nexus certificate authority</string>
			<key>PayloadDisplayName</key>
			<string>Nexara CA</string>
			<key>PayloadIdentifier</key>
			<string>nexara.nexus.ca.` + strings.ToLower(fp[:8]) + `.cert</string>
			<key>PayloadType</key>
			<string>com.apple.security.root</string>
			<key>PayloadUUID</key>
			<string>` + certUUID + `</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>PayloadDescription</key>
	<string>Trust the Nexara Nexus hub on this device</string>
	<key>PayloadDisplayName</key>
	<string>Nexara Nexus CA</string>
	<key>PayloadIdentifier</key>
	<string>nexara.nexus.ca.` + strings.ToLower(fp[:8]) + `</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>` + profUUID + `</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
`), nil
}

// setupFillTrust adds the CA facts to the Trust step.
func (s *Server) setupFillTrust(p *setupPage, r *http.Request) {
	a := s.trustAnchor()
	if a == nil {
		return
	}
	p.TrustAvailable = true
	p.Fingerprint = setupColonFingerprint(a.Fingerprint())
	p.FingerprintParts = strings.Split(p.Fingerprint, ":")
	// The QR code points a phone at the certificate on the address the
	// operator used to reach the hub.
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	u := url.URL{Scheme: scheme, Host: r.Host, Path: "/setup/trust/" + trustCertFile}
	if r.Host == "" || strings.ContainsAny(r.Host, " /\\@?#") {
		return
	}
	qr, err := views.QRSVG(u.String(), views.QRMedium, "QR code to download the CA certificate on a phone")
	if err != nil {
		s.log.Error("render trust QR code failed", "err", err)
		return
	}
	p.TrustQR = qr
}

// setupColonFingerprint renders hex as "4F:9A:12:...".
func setupColonFingerprint(fp string) string {
	fp = strings.ToUpper(strings.NewReplacer(":", "", " ", "").Replace(fp))
	if _, err := hex.DecodeString(fp); err != nil || len(fp)%2 != 0 {
		return fp
	}
	parts := make([]string, 0, len(fp)/2)
	for i := 0; i+1 < len(fp); i += 2 {
		parts = append(parts, fp[i:i+2])
	}
	return strings.Join(parts, ":")
}

// setupShortFingerprint is the installer-style abbreviation "4F:9A:12:C7 … 8E:C2".
func setupShortFingerprint(fp string) string {
	full := setupColonFingerprint(fp)
	parts := strings.Split(full, ":")
	if len(parts) < 8 {
		return full
	}
	return strings.Join(parts[:4], ":") + " … " + strings.Join(parts[len(parts)-2:], ":")
}
