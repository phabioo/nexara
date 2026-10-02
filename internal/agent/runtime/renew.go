package runtime

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/phabioo/nexara/internal/pki"
	"github.com/phabioo/nexara/internal/protocol"
)

// Certificate renewal (decision #47, protocol in internal/hub/grid/renew.go).
//
// The agent renews when its certificate has less than pki.RenewBefore (30
// days) left, checked on every connect and daily, or when the hub sends
// cert.renew. It creates a fresh P-256 key, sends only a CSR, and stages the
// answer next to the active pair (pki.AgentFiles). The active pair is not
// touched until the staged one has been accepted by the hub, so a failure at
// any point leaves an agent that still connects with its old certificate.
//
// After staging, the agent reconnects. While a staged pair exists, connection
// attempts alternate between the staged and the active pair: a success with
// the staged pair promotes it (the old pair stays as .prev); a staged pair
// that is rejected twice (hub restarted and forgot it, or it was never
// accepted) or is older than the hub's grace window is discarded and a new
// renewal starts.

const (
	// defaultRenewCheck is how often the certificate's expiry is checked.
	defaultRenewCheck = 24 * time.Hour
	// defaultRenewRetry is the pause after a failed renewal while it is still due.
	defaultRenewRetry = time.Hour
	// renewTimeout bounds the wait for the hub's answer to cert.csr.
	renewTimeout = 30 * time.Second
	// stagedMaxAge matches the hub's grace window for an unused certificate.
	stagedMaxAge = 24 * time.Hour
	// stagedRejectLimit is how many rejections of the staged pair (each followed
	// by a successful connection with the active pair) discard it.
	stagedRejectLimit = 2
	// renewWarnWithin is when a failing renewal is logged as an error.
	renewWarnWithin = 7 * 24 * time.Hour
)

// certKeeper decides which client certificate each connection attempt uses and
// moves a renewed pair into place once it has proven itself.
type certKeeper struct {
	files  pki.AgentFiles
	caFile string
	log    *slog.Logger
	now    func() time.Time
	nudge  func() // asks for a renewal check (a staged pair was discarded)

	mu           sync.Mutex
	hasStaged    bool
	tryStaged    bool // the next attempt uses the staged pair
	cur          bool // the running attempt uses the staged pair
	stagedFailed bool // the last attempt with the staged pair failed
	rejects      int
}

// newCertKeeper returns nil (renewal off) unless the agent has a usable
// certificate on disk; the first connect then fails with a clear error anyway.
func newCertKeeper(cert, key, caFile string, log *slog.Logger, now func() time.Time, nudge func()) *certKeeper {
	if cert == "" || key == "" {
		return nil
	}
	k := &certKeeper{files: pki.AgentFiles{Cert: cert, Key: key}, caFile: caFile, log: log, now: now, nudge: nudge}
	if msg, err := k.files.Recover(); err != nil {
		log.Error("agent certificate is unusable", "error", err)
		return nil
	} else if msg != "" {
		log.Warn(msg)
	}
	if _, err := k.files.LoadActive(); err != nil {
		return nil
	}
	k.mu.Lock()
	k.refreshStagedLocked()
	k.mu.Unlock()
	return k
}

// refreshStagedLocked validates a staged pair found on disk: it must load and
// be younger than the hub's grace window, otherwise it is dropped.
func (k *certKeeper) refreshStagedLocked() {
	if !k.files.HasStaged() {
		k.hasStaged = false
		return
	}
	mod, ok := k.files.StagedModTime()
	_, err := k.files.LoadStaged()
	if !ok || err != nil || k.now().Sub(mod) >= stagedMaxAge {
		k.log.Info("discarding a stale renewed certificate, the next check renews again")
		if derr := k.files.Discard(); derr != nil {
			k.log.Warn("cannot remove the stale renewed certificate", "error", derr)
		}
		k.hasStaged = false
		return
	}
	if !k.hasStaged {
		k.hasStaged, k.tryStaged = true, true
	}
}

// beginAttempt chooses the pair for the next connection attempt.
func (k *certKeeper) beginAttempt() {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.hasStaged {
		before := k.hasStaged
		k.refreshStagedLocked()
		if before && !k.hasStaged {
			k.nudgeLater()
		}
	}
	k.cur = k.hasStaged && k.tryStaged
}

// clientCert is the tls.Config.GetClientCertificate of the agent.
func (k *certKeeper) clientCert(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.cur && k.hasStaged {
		if pair, err := k.files.LoadStaged(); err == nil {
			return pair, nil
		}
		k.log.Warn("the renewed certificate cannot be loaded, falling back to the current one")
		_ = k.files.Discard()
		k.hasStaged, k.cur = false, false
		k.nudgeLater()
	}
	return k.files.LoadActive()
}

// accepted is called when the hub accepted the connection (hello.ack).
func (k *certKeeper) accepted() {
	k.mu.Lock()
	defer k.mu.Unlock()
	switch {
	case k.cur && k.hasStaged:
		if err := k.files.Promote(); err != nil {
			// Both pairs stay on disk; the next start completes or retries it.
			k.log.Error("the renewed certificate is accepted but could not be activated", "error", err)
			return
		}
		k.hasStaged, k.stagedFailed, k.rejects = false, false, 0
		k.log.Info("connected with the renewed certificate, it replaces the previous one")
	case k.hasStaged && k.stagedFailed:
		k.stagedFailed = false
		k.rejects++
		if k.rejects >= stagedRejectLimit {
			k.log.Warn("the hub does not accept the renewed certificate, discarding it and renewing again")
			_ = k.files.Discard()
			k.hasStaged, k.rejects = false, 0
			k.nudgeLater()
		}
	}
}

// endAttempt is called when a connection attempt ended; accepted says whether
// the hub had accepted it.
func (k *certKeeper) endAttempt(accepted bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.cur && k.hasStaged && !accepted {
		k.stagedFailed = true
	}
	k.tryStaged = k.hasStaged && !k.cur
	k.cur = false
}

// staged records a freshly staged pair: the next attempt tries it first.
func (k *certKeeper) staged() {
	k.mu.Lock()
	k.hasStaged, k.tryStaged, k.stagedFailed, k.rejects = true, true, false, 0
	k.mu.Unlock()
}

func (k *certKeeper) isStaged() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.hasStaged
}

// nudgeLater asks for a renewal check without holding up the caller.
func (k *certKeeper) nudgeLater() {
	if k.nudge != nil {
		go k.nudge()
	}
}

// activeLeaf returns the certificate in use.
func (k *certKeeper) activeLeaf() (*x509.Certificate, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	pair, err := k.files.LoadActive()
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(pair.Certificate[0])
}

// caCert reads the hub CA from the configured file.
func (k *certKeeper) caCert() (*x509.Certificate, error) {
	b, err := os.ReadFile(k.caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA certificate: %w", err)
	}
	return pki.ParseCertPEM(b)
}

// tlsConfig returns c with the keeper's certificate selection.
func (a *Agent) tlsConfig(c *tls.Config) *tls.Config {
	c = tlsClone(c)
	if c != nil && a.certs != nil {
		c.GetClientCertificate = a.certs.clientCert
		c.Certificates = nil
	}
	return c
}

// ---- session side ----

// renewLoop checks the certificate on connect and then periodically.
func (s *session) renewLoop() {
	a := s.a
	interval := a.opts.RenewCheckInterval
	if interval <= 0 {
		interval = defaultRenewCheck
	}
	retry := a.opts.RenewRetryInterval
	if retry <= 0 {
		retry = defaultRenewRetry
	}
	for {
		wait := interval
		if s.renewCert(false) == renewFailed {
			wait = retry
		}
		t := time.NewTimer(wait)
		select {
		case <-s.ctx.Done():
			t.Stop()
			return
		case <-a.renewNudge:
			t.Stop()
		case <-t.C:
		}
	}
}

type renewOutcome int

const (
	renewSkipped renewOutcome = iota // nothing to do
	renewDone                        // renewed pair staged, reconnecting
	renewFailed                      // try again later
)

// certRenewMsg handles the hub's cert.renew: answer first, then renew.
func (s *session) certRenewMsg(env protocol.Envelope) {
	if s.a.certs == nil {
		s.fail(env.ID, protocol.CodeUnsupported, "certificate renewal is not available on this agent")
		return
	}
	req, _ := protocol.DecodeData[protocol.CertRenew](env) // the payload is optional
	s.result(env.ID, nil)
	s.spawn(func() { s.renewCert(req.Force) })
}

// renewCert runs one renewal if it is due (or forced). Only one runs at a time.
func (s *session) renewCert(force bool) renewOutcome {
	a := s.a
	k := a.certs
	if k == nil || s.limited || s.noRenewal.Load() {
		return renewSkipped
	}
	// One renewal at a time. A trigger that arrives while another runs (own
	// check and cert.renew together) waits and then finds the renewed pair
	// staged, so the hub gets one request, not two.
	select {
	case a.renewSem <- struct{}{}:
	case <-s.ctx.Done():
		return renewSkipped
	}
	defer func() { <-a.renewSem }()
	if k.isStaged() {
		return renewSkipped // a renewed pair waits for its first use
	}
	leaf, err := k.activeLeaf()
	if err != nil {
		a.log.Warn("cannot read the agent certificate for renewal", "error", err)
		return renewFailed
	}
	if !force && !pki.NeedsRenewal(leaf, a.now()) {
		return renewSkipped
	}
	if err := s.requestCertificate(leaf); err != nil {
		left := leaf.NotAfter.Sub(a.now())
		if errors.Is(err, errRenewUnsupported) {
			s.noRenewal.Store(true)
			a.log.Info("the hub does not support certificate renewal (yet)", "expires_in", left.Round(time.Hour).String())
			return renewSkipped
		}
		if left <= renewWarnWithin {
			a.log.Error("agent certificate expires soon and renewal keeps failing; re-enroll the agent if it cannot be fixed",
				"expires_in", left.Round(time.Hour).String(), "error", err)
		} else {
			a.log.Warn("certificate renewal failed, will retry", "expires_in", left.Round(time.Hour).String(), "error", err)
		}
		if s.ctx.Err() != nil {
			return renewSkipped
		}
		return renewFailed
	}
	return renewDone
}

var errRenewUnsupported = errors.New("hub does not support certificate renewal")

// requestCertificate performs the cert.csr exchange and stages the result.
func (s *session) requestCertificate(leaf *x509.Certificate) error {
	a := s.a
	k := a.certs
	hostID := leaf.Subject.CommonName
	keyPEM, csrPEM, err := pki.NewAgentKeyAndCSR(hostID)
	if err != nil {
		return err
	}
	env, err := s.renewRPC(protocol.TypeCertCSR, protocol.CertCSR{CSRPEM: string(csrPEM)})
	if err != nil {
		return err
	}
	if env.Type == protocol.TypeError {
		e, derr := protocol.DecodeData[protocol.Error](env)
		if derr != nil {
			return errors.New("the hub refused the certificate request")
		}
		switch e.Code {
		case protocol.CodeUnknownType, protocol.CodeUnsupported:
			return errRenewUnsupported
		case protocol.CodeBusy:
			return errors.New("the hub already issued a certificate on this connection")
		}
		return fmt.Errorf("the hub refused the certificate request: %s", e.Message)
	}
	issued, err := protocol.DecodeData[protocol.CertIssued](env)
	if err != nil {
		return fmt.Errorf("malformed certificate from the hub: %w", err)
	}
	certPEM := []byte(issued.CertPEM)
	cert, err := pki.ParseCertPEM(certPEM)
	if err != nil {
		return fmt.Errorf("malformed certificate from the hub: %w", err)
	}
	ca, err := k.caCert()
	if err != nil {
		return err
	}
	switch {
	case cert.Subject.CommonName != hostID:
		return errors.New("the hub issued a certificate for another host")
	case cert.CheckSignatureFrom(ca) != nil:
		return errors.New("the new certificate is not signed by the hub CA")
	case !cert.NotAfter.After(leaf.NotAfter):
		return errors.New("the new certificate does not last longer than the current one")
	}
	if err := k.files.Stage(certPEM, keyPEM); err != nil { // also proves cert and key belong together
		return err
	}
	k.staged()
	a.log.Info("agent certificate renewed, reconnecting to use it", "expires", cert.NotAfter.UTC().Format("2006-01-02"))
	s.reconnect.Store(true)
	s.cancel()
	return nil
}

// renewRPC sends a request and waits for the hub's answer (cert.issued or error).
func (s *session) renewRPC(typ string, data any) (protocol.Envelope, error) {
	s.renewMu.Lock()
	s.renewSeq++
	id := fmt.Sprintf("renew-%d", s.renewSeq)
	ch := make(chan protocol.Envelope, 1)
	s.renewID, s.renewCh = id, ch
	s.renewMu.Unlock()
	defer func() {
		s.renewMu.Lock()
		s.renewID, s.renewCh = "", nil
		s.renewMu.Unlock()
	}()

	if err := s.send(typ, id, data); err != nil {
		return protocol.Envelope{}, err
	}
	timeout := s.a.opts.RenewTimeout
	if timeout <= 0 {
		timeout = renewTimeout
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case env := <-ch:
		return env, nil
	case <-t.C:
		return protocol.Envelope{}, errors.New("no answer from the hub")
	case <-s.ctx.Done():
		return protocol.Envelope{}, context.Canceled
	}
}

// deliverRenewal hands cert.issued / error answers to the waiting request.
func (s *session) deliverRenewal(env protocol.Envelope) {
	s.renewMu.Lock()
	ch := s.renewCh
	ok := ch != nil && env.ID == s.renewID
	if ok {
		s.renewCh = nil // one answer
	}
	s.renewMu.Unlock()
	if ok {
		ch <- env
	}
}
