package grid

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/pki"
	"github.com/phabioo/nexara/internal/protocol"
)

// Agent certificate renewal (decision #47).
//
// Agent certificates live one year. Within 30 days of expiry (pki.RenewBefore)
// they are renewed over the existing mTLS WebSocket, with no operator and no
// SSH:
//
//	agent                                   hub
//	  |  (own cert < 30 days left, or)        |  (cert_not_after < 30 days on
//	  |<------------- cert.renew -------------|   connect and in the daily check)
//	  |-- result{ok} ------------------------>|
//	  |  fresh P-256 key, CSR (CN = host id)  |
//	  |-- cert.csr --------------------------->|  validate, sign (pki.SignAgentRenewal),
//	  |<------------ cert.issued --------------|  remember as pending, audit
//	  |  stage cert.new/key.new, reconnect    |
//	  |== mTLS with the NEW certificate ======>|  first use: activate (DB swap), old one dies
//
// Both sides can start it. The agent knows its own expiry best and also covers
// a hub that was down at the 30 day mark; the hub covers agents that never
// look and gives the operator a "renew now". The signing path is the same.
//
// The database keeps the old fingerprint as the certificate of record until
// the new certificate has been used once. Until then both authenticate
// (IsRevoked, identifyTLS). Activation swaps fingerprint, serial and expiry in
// one compare-and-swap statement (store.ReplaceHostCert). A renewal that is
// never used simply expires after pendingCertTTL; the old certificate stayed
// valid throughout, so an interrupted renewal can never lock an agent out.
//
// The pending certificate is held in memory. If the hub restarts before the
// agent connects with the new certificate, the agent's first attempt with it
// fails, it falls back to the old one and asks again.

// pendingCertTTL is how long an issued certificate may wait for its first use.
const pendingCertTTL = 24 * time.Hour

// forceWindow is how long a hub-initiated renewal may be signed although the
// certificate is not within the renewal window (operator "renew now").
const forceWindow = 10 * time.Minute

// renewRetryAfter spaces the hub's automatic renewal requests per host.
const renewRetryAfter = time.Hour

// certWarnWithin is when a failing renewal is logged as an error.
const certWarnWithin = 7 * 24 * time.Hour

// notDueAuditEvery spaces the "certificate not due" audit entries per host: an
// agent that keeps asking would otherwise fill the audit log.
const notDueAuditEvery = time.Hour

// maxBadCSRs is how many refused certificate requests one connection may send
// before the hub closes it (the agent reconnects with its backoff).
const maxBadCSRs = 5

// maxCSRSize bounds a certificate request (a P-256 CSR is ~300 bytes).
const maxCSRSize = 8 << 10

// CertRenewer is what a view needs to offer "Renew certificate" for a host
// (v0.2 Settings > Certificates). *Grid implements it; Hub does not, because
// the demo hub has no certificates to renew.
type CertRenewer interface {
	RenewCert(ctx context.Context, actor Actor, id HostID) error
}

var _ CertRenewer = (*Grid)(nil)

// ErrRenewInProgress is returned when a renewal for the host is already running.
var ErrRenewInProgress = errors.New("grid: certificate renewal already in progress")

// pendingCert is an issued certificate waiting for its first use.
type pendingCert struct {
	host     HostID
	conn     *agentConn // the connection it was requested on
	serial   string
	notAfter time.Time
	expires  time.Time
}

// certDue reports whether the host's certificate is within the renewal window.
// An unknown expiry counts as due.
func certDue(h store.Host, now time.Time) bool {
	return h.CertNotAfter.IsZero() || !now.Add(pki.RenewBefore).Before(h.CertNotAfter)
}

func (g *Grid) peerCertificate(r *http.Request) *x509.Certificate {
	if g.opts.PeerCertificate != nil {
		return g.opts.PeerCertificate(r)
	}
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return r.TLS.PeerCertificates[0]
	}
	return nil
}

// livePendingLocked returns the pending certificate with the fingerprint if it
// has not expired; expired ones are dropped. g.mu must be held.
func (g *Grid) livePendingLocked(fp string) (*pendingCert, bool) {
	p, ok := g.pending[fp]
	if !ok {
		return nil, false
	}
	if !g.now().Before(p.expires) {
		g.removePendingLocked(fp)
		return nil, false
	}
	return p, true
}

// prunePendingLocked forgets expired pending certificates. g.mu must be held.
func (g *Grid) prunePendingLocked() {
	for fp := range g.pending {
		g.livePendingLocked(fp)
	}
}

func (g *Grid) removePendingLocked(fp string) {
	p, ok := g.pending[fp]
	if !ok {
		return
	}
	delete(g.pending, fp)
	if st, ok := g.hosts[p.host]; ok && st.pendingFP == fp {
		st.pendingFP = ""
	}
}

// dropPendingLocked forgets the host's pending certificate. g.mu must be held.
func (g *Grid) dropPendingLocked(st *hostState) {
	if st.pendingFP != "" {
		g.removePendingLocked(st.pendingFP)
	}
	st.pendingFP = ""
}

// hasLivePendingLocked reports whether the host has an issued, unused, unexpired certificate.
func (g *Grid) hasLivePendingLocked(st *hostState) bool {
	if st.pendingFP == "" {
		return false
	}
	_, ok := g.livePendingLocked(st.pendingFP)
	return ok
}

// RenewCert asks the connected agent to renew its certificate now (operator
// action; the UI of v0.2 offers it per host). The agent answers at once and
// then sends the certificate request over the same connection, which the hub
// signs even though the certificate is not within the renewal window yet.
// Audited as cert.renew. Errors: ErrHostNotFound, ErrHostOffline,
// ErrUnsupported (agent too old, or no CA), ErrRenewInProgress.
func (g *Grid) RenewCert(ctx context.Context, actor Actor, id HostID) error {
	st, c, err := g.connFor(id, "")
	if err != nil {
		return err
	}
	err = g.requestRenewal(ctx, st, c, true)
	if !errors.Is(err, ErrRenewInProgress) {
		g.audit(store.AuditEntry{User: actor.Operator, Host: st.name, Action: "cert.renew", Detail: "requested" + withIP(actor), Result: auditResult(err)})
	}
	return err
}

func withIP(a Actor) string {
	if a.IP == "" {
		return ""
	}
	return " from " + a.IP
}

// requestRenewal sends cert.renew and waits for the agent's answer.
func (g *Grid) requestRenewal(ctx context.Context, st *hostState, c *agentConn, force bool) error {
	if g.opts.CA == nil {
		return ErrUnsupported
	}
	g.mu.Lock()
	switch {
	case st.conn != c:
		g.mu.Unlock()
		return ErrHostOffline
	case st.renewUnsupported:
		g.mu.Unlock()
		return ErrUnsupported
	case st.renewBusy || g.hasLivePendingLocked(st):
		g.mu.Unlock()
		return ErrRenewInProgress
	}
	now := g.now()
	st.renewBusy = true
	st.renewRequested = now
	if force {
		st.forceUntil = now.Add(forceWindow)
	}
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		st.renewBusy = false
		g.mu.Unlock()
	}()

	env, err := c.request(ctx, protocol.TypeCertRenew, protocol.CertRenew{Force: force}, g.to.renew)
	if err == nil {
		err = resultErr(env, "certificate renewal")
	}
	var perr protocol.Error
	if errors.As(err, &perr) && perr.Code == protocol.CodeUnknownType {
		// An agent from before decision #47: the automatic agent update comes first.
		g.mu.Lock()
		st.renewUnsupported = true
		g.mu.Unlock()
		g.log.Info("grid: agent cannot renew its certificate yet, relying on the automatic agent update", "host", st.name)
		return ErrUnsupported
	}
	return err
}

// maybeRenewOnConnect starts a renewal for an agent whose certificate is due
// (maybeAutoUpdate ran before; see autoRenew).
func (g *Grid) maybeRenewOnConnect(st *hostState) { g.autoRenew(st) }

// autoRenew asks the host's agent to renew if its certificate is due and the
// last request is old enough. An agent older than the hub is updated first
// (decision #20) and renews after it came back with the new version: it may
// not know cert.renew at all. It logs loudly when expiry is near.
func (g *Grid) autoRenew(st *hostState) {
	if g.opts.CA == nil {
		return
	}
	now := g.now()
	g.mu.Lock()
	c := st.conn
	host := st.host
	pending := g.hasLivePendingLocked(st)
	recent := !st.renewRequested.IsZero() && now.Sub(st.renewRequested) < renewRetryAfter
	g.mu.Unlock()
	switch {
	case !certDue(host, now) || pending:
		return
	case c == nil:
		g.warnExpiring(st.name, host, now, nil, true)
		return
	case needsUpdate(host.AgentVersion, g.opts.HubVersion):
		g.warnExpiring(st.name, host, now, errors.New("the agent must be updated first"), false)
		return
	case recent:
		return
	}
	err := g.requestRenewal(g.ctx, st, c, false)
	if err != nil && !errors.Is(err, ErrRenewInProgress) {
		g.log.Warn("grid: certificate renewal request failed", "host", st.name, "err", err)
		g.warnExpiring(st.name, host, now, err, false)
	}
}

// warnExpiring logs an error when a certificate within 7 days of expiry has
// not been renewed: from there on only re-enrolling helps in the end.
func (g *Grid) warnExpiring(name string, h store.Host, now time.Time, cause error, offline bool) {
	if h.CertNotAfter.IsZero() || h.CertNotAfter.Sub(now) > certWarnWithin {
		return
	}
	left := h.CertNotAfter.Sub(now).Round(time.Hour)
	switch {
	case !now.Before(h.CertNotAfter):
		g.log.Error("grid: agent certificate has expired, re-enroll the host", "host", name, "expired", h.CertNotAfter)
	case offline:
		g.log.Error("grid: agent certificate expires soon and the host is offline, so it cannot be renewed", "host", name, "expires_in", left.String())
	default:
		g.log.Error("grid: agent certificate expires soon and renewal keeps failing", "host", name, "expires_in", left.String(), "err", cause)
	}
}

// CheckRenewals is the daily sweep: every online host whose certificate is
// within the renewal window is asked to renew (once per renewRetryAfter), and
// every certificate within 7 days of expiry that is still not renewed is
// logged as an error. Expired pending certificates are forgotten.
func (g *Grid) CheckRenewals(ctx context.Context) {
	g.mu.Lock()
	g.prunePendingLocked()
	sts := make([]*hostState, 0, len(g.order))
	for _, id := range g.order {
		sts = append(sts, g.hosts[id])
	}
	g.mu.Unlock()
	for _, st := range sts {
		if ctx.Err() != nil {
			return
		}
		g.autoRenew(st)
	}
}

// onCertCSR signs an agent's certificate request (agent->hub cert.csr).
func (g *Grid) onCertCSR(st *hostState, c *agentConn, env protocol.Envelope) {
	// fail answers with an error and counts it against the connection; a peer
	// that keeps sending requests the hub refuses is disconnected.
	fail := func(code, msg string) {
		_ = c.send(protocol.TypeError, env.ID, protocol.Error{Code: code, Message: msg})
		if int(c.badRequests.Add(1)) >= maxBadCSRs {
			g.log.Warn("grid: closing a connection after repeated refused certificate requests", "host", st.name)
			c.close()
		}
	}
	denied := func(result, detail string) {
		g.audit(store.AuditEntry{User: SystemActor.Operator, Host: st.name, Action: "cert.renew", Detail: detail, Result: result})
	}
	if g.opts.CA == nil {
		fail(protocol.CodeUnsupported, "this hub cannot renew agent certificates")
		return
	}
	req, err := protocol.DecodeData[protocol.CertCSR](env)
	if err != nil || req.CSRPEM == "" || len(req.CSRPEM) > maxCSRSize {
		fail(protocol.CodeBadRequest, "malformed certificate request")
		return
	}

	now := g.now()
	g.mu.Lock()
	if st.conn != c {
		g.mu.Unlock()
		return // a newer connection took over; this one is about to close
	}
	g.prunePendingLocked()
	if p, ok := g.livePendingLocked(st.pendingFP); ok && p.conn == c {
		// The agent asks twice on one connection (both sides started a renewal).
		// Signing again would invalidate the certificate it already received.
		g.mu.Unlock()
		fail(protocol.CodeBusy, "a certificate was already issued on this connection")
		return
	}
	forced := now.Before(st.forceUntil)
	if !forced && !certDue(st.host, now) {
		notAfter := st.host.CertNotAfter
		auditNow := st.lastNotDueAudit.IsZero() || now.Sub(st.lastNotDueAudit) >= notDueAuditEvery || now.Before(st.lastNotDueAudit)
		if auditNow {
			st.lastNotDueAudit = now
		}
		g.mu.Unlock()
		if auditNow {
			denied(store.AuditDenied, "certificate not due, expires "+notAfter.UTC().Format(time.RFC3339))
		}
		fail(protocol.CodeInvalidArgument, "certificate is not due for renewal")
		return
	}
	g.mu.Unlock()

	// Names come from the authenticated connection (the host ID), never from the CSR.
	certPEM, cert, err := pki.SignAgentRenewal(g.opts.CA, []byte(req.CSRPEM), string(st.id), c.peer, now)
	if err != nil {
		g.log.Warn("grid: certificate request refused", "host", st.name, "err", err)
		denied(store.AuditError, "certificate request refused")
		fail(protocol.CodeInvalidArgument, "certificate request refused")
		return
	}

	fp := pki.Fingerprint(cert)
	g.mu.Lock()
	if cur, ok := g.hosts[st.id]; !ok || cur != st || st.conn != c {
		g.mu.Unlock()
		return // removed or replaced while signing
	}
	g.dropPendingLocked(st) // a request from a new connection supersedes an unused one (agent crashed before staging)
	g.pending[fp] = &pendingCert{
		host: st.id, conn: c, serial: pki.SerialHex(cert), notAfter: cert.NotAfter, expires: now.Add(pendingCertTTL),
	}
	st.pendingFP = fp
	st.forceUntil = time.Time{}
	g.mu.Unlock()

	g.audit(store.AuditEntry{
		User: SystemActor.Operator, Host: st.name, Action: "cert.renew", Result: store.AuditOK,
		Detail: fmt.Sprintf("issued serial %s, expires %s", pki.SerialHex(cert), cert.NotAfter.UTC().Format("2006-01-02")),
	})
	g.log.Info("grid: agent certificate renewed", "host", st.name, "expires", cert.NotAfter.UTC().Format("2006-01-02"))
	if err := c.send(protocol.TypeCertIssued, env.ID, protocol.CertIssued{CertPEM: string(certPEM), NotAfter: cert.NotAfter.UTC()}); err != nil {
		g.log.Warn("grid: sending the renewed certificate failed", "host", st.name, "err", err)
	}
}

// activateRenewed runs when an agent's hello has been accepted, before the ack
// is sent: if it connected with a pending certificate, that certificate becomes
// the certificate of record and the old one stops working. It returns false if
// that failed; the agent is then not acknowledged and keeps its old pair.
func (g *Grid) activateRenewed(st *hostState, c *agentConn) bool {
	if c.peer == nil {
		return true
	}
	fp := pki.Fingerprint(c.peer)
	g.mu.Lock()
	p, ok := g.livePendingLocked(fp)
	if !ok || p.host != st.id {
		g.mu.Unlock()
		return true // the certificate of record, nothing to activate
	}
	oldFP := st.host.CertFingerprint
	g.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	err := g.opts.Store.ReplaceHostCert(ctx, string(st.id), oldFP, fp, p.serial, p.notAfter)
	cancel()
	if err != nil {
		g.log.Error("grid: activating the renewed agent certificate failed", "host", st.name, "err", err)
		g.audit(store.AuditEntry{User: SystemActor.Operator, Host: st.name, Action: "cert.renew", Detail: "activation failed", Result: store.AuditError})
		return false
	}
	g.mu.Lock()
	if cur, ok := g.hosts[st.id]; ok && cur == st {
		delete(g.byFP, oldFP)
		g.byFP[fp] = st.id
		st.host.CertFingerprint, st.host.CertSerial, st.host.CertNotAfter = fp, p.serial, p.notAfter
		g.removePendingLocked(fp)
	}
	g.mu.Unlock()
	g.audit(store.AuditEntry{
		User: SystemActor.Operator, Host: st.name, Action: "cert.renew", Result: store.AuditOK,
		Detail: fmt.Sprintf("activated serial %s, previous certificate retired", p.serial),
	})
	g.log.Info("grid: agent uses its renewed certificate", "host", st.name)
	return true
}
