package enroll

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/pki"
	"github.com/phabioo/nexara/internal/protocol"
)

const (
	maxEnrollBody = 64 << 10
	// enrollRate is the number of POST /grid/enroll attempts per client per
	// minute; a client is an IPv4 address or an IPv6 /64. enrollGlobalRate
	// caps all clients together (S-10).
	enrollRate       = 10
	enrollGlobalRate = 60
)

// Handler serves POST /grid/enroll, GET /grid/install.sh and
// GET /grid/download/{os}/{arch}. It is public (no session, no client
// certificate) and must be mounted at those exact paths.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /grid/enroll", s.handleEnroll)
	mux.HandleFunc("GET /grid/install.sh", s.handleInstallScript)
	mux.HandleFunc("GET /grid/download/{os}/{arch}", s.handleDownload)
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

var (
	hostNameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	osArchRE   = regexp.MustCompile(`^[a-z0-9]{1,16}$`)
)

var (
	knownOS   = map[string]bool{"linux": true, "windows": true, "darwin": true}
	knownArch = map[string]bool{"arm64": true, "amd64": true, "arm": true, "386": true}
)

// hostNameFrom turns a reported host name into the unique short host name:
// lower case, without domain. ok is false if the result is not a valid label.
func hostNameFrom(reported string) (string, bool) {
	name := strings.ToLower(strings.TrimSpace(reported))
	if i := strings.IndexByte(name, '.'); i > 0 {
		name = name[:i]
	}
	return name, hostNameRE.MatchString(name)
}

func (s *Service) handleEnroll(w http.ResponseWriter, r *http.Request) {
	ip := ipOf(r.RemoteAddr)
	now := s.now()
	if !s.limiter.allow(limitKey(ip), now) || !s.globalLimiter.allow("*", now) {
		w.Header().Set("Retry-After", "60")
		writeErr(w, http.StatusTooManyRequests, "too many attempts")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxEnrollBody)
	var req protocol.EnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeErr(w, http.StatusRequestEntityTooLarge, "request too large")
			return
		}
		writeErr(w, http.StatusBadRequest, "malformed request")
		return
	}
	ctx := r.Context()

	// The token is checked before anything else is parsed: an unauthenticated
	// request never reaches the CSR or the CA (S-10). The check only reads, so
	// a malformed request from a legitimate agent does not burn its one-time
	// code; the code is consumed once everything else is known to be valid.
	// Nothing of the presented code is ever logged or audited.
	if len(req.Token) > 128 || !codeRE.MatchString(normalizeCode(req.Token)) {
		s.deny(ctx, ip, "malformed or missing token")
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	tokenHash := hashCode(req.Token)
	if err := s.checkToken(ctx, tokenHash, now); err != nil {
		if errors.Is(err, store.ErrTokenInvalid) {
			s.deny(ctx, ip, "invalid, expired or used token")
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		s.log.Error("enroll: check token", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}

	name, ok := hostNameFrom(req.Hello.Hostname)
	if !ok || !knownOS[req.Hello.OS] || !knownArch[req.Hello.Arch] {
		writeErr(w, http.StatusBadRequest, "invalid host description")
		return
	}
	if err := checkCSR([]byte(req.CSRPEM)); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid certificate request")
		return
	}

	tokenCaps, err := s.st.ConsumeEnrollToken(ctx, tokenHash, now)
	if errors.Is(err, store.ErrTokenInvalid) { // used by a concurrent request
		s.deny(ctx, ip, "invalid, expired or used token")
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if err != nil {
		s.log.Error("enroll: consume token", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}

	host, err := s.registerHost(ctx, name, ip, tokenHash, req, tokenCaps)
	if err != nil {
		switch {
		case errors.Is(err, errHostRevoked):
			s.audit(ctx, "system", name, "enroll.denied", "host is revoked; remove it first (from "+ip+")", store.AuditDenied)
			writeErr(w, http.StatusConflict, "host is revoked")
		case errors.Is(err, grid.ErrHostExists):
			s.audit(ctx, "system", name, "enroll.denied", "a host with this name already exists (from "+ip+")", store.AuditDenied)
			writeErr(w, http.StatusConflict, "host exists")
		default:
			s.log.Error("enroll: register host", "host", name, "err", err)
			s.audit(ctx, "system", name, "enroll.ok", "failed while registering (from "+ip+")", store.AuditError)
			writeErr(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	_ = s.st.SetEnrollTokenHost(ctx, tokenHash, host.h.ID)

	s.audit(ctx, "system", host.h.Name, "enroll.ok", host.detail+" (from "+ip+")", store.AuditOK)
	if s.enrolled != nil {
		s.enrolled(ctx, host.h)
	}
	writeJSON(w, http.StatusOK, protocol.EnrollResponse{
		HostID:   host.h.ID,
		CertPEM:  string(host.certPEM),
		CAPEM:    string(s.ca.CertPEM()),
		HubURL:   s.connectURL(),
		Settings: protocol.AgentSettings{Capabilities: tokenCaps},
	})
}

// checkToken reports store.ErrTokenInvalid unless the token exists, is unused
// and has not expired. It does not consume the token.
func (s *Service) checkToken(ctx context.Context, tokenHash string, now time.Time) error {
	t, err := s.st.GetEnrollToken(ctx, tokenHash)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return store.ErrTokenInvalid
	case err != nil:
		return err
	case !t.UsedAt.IsZero() || !t.ExpiresAt.After(now):
		return store.ErrTokenInvalid
	}
	return nil
}

// checkCSR parses the request and verifies its self-signature without
// involving the CA. Only authenticated requests get here.
func checkCSR(csrPEM []byte) error {
	blk, _ := pem.Decode(csrPEM)
	if blk == nil || blk.Type != "CERTIFICATE REQUEST" {
		return errors.New("no certificate request")
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		return errors.New("malformed certificate request")
	}
	if err := csr.CheckSignature(); err != nil {
		return errors.New("bad signature")
	}
	if pub, ok := csr.PublicKey.(*ecdsa.PublicKey); !ok || pub.Curve != elliptic.P256() {
		return errors.New("key must be ECDSA P-256")
	}
	return nil
}

// limitKey maps a client address to its rate-limit bucket: the address itself
// for IPv4, the /64 for IPv6 (a single host can use any address in its /64).
func limitKey(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	addr = addr.Unmap()
	if addr.Is6() {
		if p, err := addr.Prefix(64); err == nil {
			return p.String()
		}
	}
	return addr.String()
}

func (s *Service) deny(ctx context.Context, ip, why string) {
	s.audit(ctx, "system", "", "enroll.denied", why+" (from "+ip+")", store.AuditDenied)
}

var errHostRevoked = errors.New("enroll: host is revoked")

type registered struct {
	h       store.Host
	certPEM []byte
	detail  string
}

// registerHost signs the CSR and creates the host row. A host name that is
// already taken is refused with grid.ErrHostExists (decision #46): cloned
// images and stolen codes must not take over an existing identity. The one
// exception is a replacement the operator granted explicitly for exactly this
// token and host (see replaceHost).
func (s *Service) registerHost(ctx context.Context, name, ip, tokenHash string, req protocol.EnrollRequest, tokenCaps []string) (registered, error) {
	now := s.now()
	caps := tokenCaps
	if caps == nil {
		caps = filterCaps(req.Hello.Capabilities)
	}
	mac := ""
	if hw, err := net.ParseMAC(req.Hello.MAC); err == nil {
		mac = strings.ToLower(hw.String())
	}
	version := truncate(req.Hello.AgentVersion, 64)

	existing, err := s.st.GetHostByName(ctx, name)
	switch {
	case err == nil:
		return s.existingHost(ctx, existing, tokenHash, ip, req, caps, mac, version, now)
	case !errors.Is(err, store.ErrNotFound):
		return registered{}, err
	}

	id := store.NewID()
	certPEM, cert, err := pki.SignAgentCSR(s.ca, []byte(req.CSRPEM), id, now)
	if err != nil {
		return registered{}, err
	}
	h, err := s.st.CreateHost(ctx, store.Host{
		ID: id, Name: name, DisplayName: name, Address: ip,
		OS: req.Hello.OS, Arch: req.Hello.Arch, AgentVersion: version,
		CertFingerprint: pki.Fingerprint(cert), CertSerial: pki.SerialHex(cert), CertNotAfter: cert.NotAfter,
		MAC: mac, Capabilities: caps, CreatedAt: now,
	})
	if errors.Is(err, store.ErrExists) { // lost a race with a concurrent enrollment of the same name
		return registered{}, &grid.HostExistsError{Name: name}
	}
	if err != nil {
		return registered{}, err
	}
	return registered{h: h, certPEM: certPEM, detail: "new host " + h.ID}, nil
}

// existingHost decides what happens when the reported name is taken.
func (s *Service) existingHost(ctx context.Context, h store.Host, tokenHash, ip string, req protocol.EnrollRequest, caps []string, mac, version string, now time.Time) (registered, error) {
	if h.Revoked {
		return registered{}, errHostRevoked
	}
	grant, ok := s.takeReplace(tokenHash, now)
	if !ok || grant.hostID != h.ID {
		return registered{}, &grid.HostExistsError{ID: grid.HostID(h.ID), Name: h.Name}
	}
	if s.hostOnline != nil && s.hostOnline(grid.HostID(h.ID)) {
		return registered{}, &grid.HostExistsError{ID: grid.HostID(h.ID), Name: h.Name}
	}
	return s.replaceHost(ctx, h, grant.actor, ip, req, caps, mac, version, now)
}

// replaceHost gives an existing host a new certificate (the device behind the
// name was re-installed or swapped). The row id and history stay; the old
// certificate stops working because the host is looked up by the fingerprint
// of its current certificate. Audited as host.replace.
func (s *Service) replaceHost(ctx context.Context, h store.Host, actor grid.Actor, ip string, req protocol.EnrollRequest, caps []string, mac, version string, now time.Time) (registered, error) {
	oldFP := h.CertFingerprint
	certPEM, cert, err := pki.SignAgentCSR(s.ca, []byte(req.CSRPEM), h.ID, now)
	if err != nil {
		return registered{}, err
	}
	if err := s.st.SetHostCert(ctx, h.ID, pki.Fingerprint(cert), pki.SerialHex(cert), cert.NotAfter); err != nil {
		return registered{}, err
	}
	if err := s.st.UpdateHostStatus(ctx, h.ID, store.HostStatus{
		Address: ip, OS: req.Hello.OS, Arch: req.Hello.Arch, AgentVersion: version,
		MAC: mac, Capabilities: caps, LastSeenAt: h.LastSeenAt,
	}); err != nil {
		return registered{}, err
	}
	nh, err := s.st.GetHost(ctx, h.ID)
	if err != nil {
		return registered{}, err
	}
	s.audit(ctx, actor.Operator, nh.Name, "host.replace",
		"replaced by a new agent from "+ip+"; old certificate "+shortFP(oldFP)+" revoked", store.AuditOK)
	return registered{h: nh, certPEM: certPEM, detail: "replaced host " + nh.ID}, nil
}

func shortFP(fp string) string {
	if len(fp) > 16 {
		return fp[:16]
	}
	if fp == "" {
		return "(none)"
	}
	return fp
}

func filterCaps(in []string) []string {
	known := map[string]bool{}
	for _, c := range protocol.Capabilities() {
		known[c] = true
	}
	out := []string{}
	seen := map[string]bool{}
	for _, c := range in {
		if known[c] && !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

func truncate(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > n {
		return s[:n]
	}
	return s
}

func (s *Service) handleInstallScript(w http.ResponseWriter, r *http.Request) {
	pin, err := s.pin()
	var script []byte
	if err == nil {
		script, err = renderInstallScript(s.addr, s.port, pin, s.ca.Fingerprint())
	}
	if err != nil {
		s.log.Error("enroll: render install script", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(script)
}

func (s *Service) handleDownload(w http.ResponseWriter, r *http.Request) {
	goos, goarch := r.PathValue("os"), r.PathValue("arch")
	if !osArchRE.MatchString(goos) || !osArchRE.MatchString(goarch) {
		http.NotFound(w, r)
		return
	}
	bin, ok := s.binary(goos, goarch)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(bin.Data)))
	w.Header().Set("Content-Disposition", `attachment; filename="grid-agent"`)
	w.Header().Set("X-Content-SHA256", bin.SHA256)
	_, _ = w.Write(bin.Data)
}

// ipLimiter is a sliding-window limiter per key.
type ipLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	hits   map[string][]time.Time
	calls  int
}

func newIPLimiter(limit int, window time.Duration) *ipLimiter {
	return &ipLimiter{limit: limit, window: window, hits: map[string][]time.Time{}}
}

func (l *ipLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls++
	if l.calls%256 == 0 { // drop idle keys
		for k, v := range l.hits {
			if len(v) == 0 || now.Sub(v[len(v)-1]) >= l.window {
				delete(l.hits, k)
			}
		}
	}
	cutoff := now.Add(-l.window)
	recent := l.hits[key][:0]
	for _, t := range l.hits[key] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	if len(recent) >= l.limit {
		l.hits[key] = recent
		return false
	}
	l.hits[key] = append(recent, now)
	return true
}
