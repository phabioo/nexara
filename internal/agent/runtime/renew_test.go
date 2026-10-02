package runtime

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/phabioo/nexara/internal/config"
	"github.com/phabioo/nexara/internal/pki"
	"github.com/phabioo/nexara/internal/protocol"
)

const (
	hostID = "a1c5e0d2b7f34961"
	day    = 24 * time.Hour
)

// renewFixture is an agent with real certificate files, a hub CA and a fake
// hub that signs with it. The fake clock decides what "near expiry" means.
type renewFixture struct {
	*harness
	ca       *pki.CA
	files    pki.AgentFiles
	oldCert  *x509.Certificate
	oldPair  pairBytes
	tlsCfg   *tls.Config
	caFile   string
	mu       sync.Mutex
	dialFPs  []string // fingerprint of the certificate each dial would have presented
	rejectFP string   // dials presenting this certificate fail (the hub does not know it)
}

type pairBytes struct{ cert, key []byte }

// newRenewFixture issues the agent's certificate so that it expires in notAfterIn on the fake clock.
func newRenewFixture(t *testing.T, notAfterIn time.Duration, mod func(*renewFixture)) *renewFixture {
	t.Helper()
	dir := t.TempDir()
	ca, err := pki.LoadOrCreateCA(filepath.Join(dir, "hub"))
	if err != nil {
		t.Fatal(err)
	}
	f := &renewFixture{ca: ca}
	f.harness = newHarness(t, func(c *config.AgentConfig) {
		c.Capabilities.Services, c.Capabilities.Packages, c.Capabilities.Shell = false, false, false
		c.TLS.Cert = filepath.Join(dir, "agent.pem")
		c.TLS.Key = filepath.Join(dir, "agent.key")
		c.TLS.CA = filepath.Join(dir, "ca.pem")
	})
	f.files = pki.AgentFiles{Cert: f.cfg.TLS.Cert, Key: f.cfg.TLS.Key}
	f.caFile = f.cfg.TLS.CA
	if err := os.WriteFile(f.caFile, ca.CertPEM(), 0o644); err != nil {
		t.Fatal(err)
	}
	f.oldPair = f.issue(notAfterIn)
	f.oldCert = mustParse(t, f.oldPair.cert)
	writeFiles(t, f.files, f.oldPair)
	if mod != nil {
		mod(f)
	}
	f.tlsCfg, err = pki.AgentTLSConfig(ca.CertPEM(), f.files.Cert, f.files.Key)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// issue creates a key and a certificate for the agent that expires in notAfterIn.
func (f *renewFixture) issue(notAfterIn time.Duration) pairBytes {
	f.t.Helper()
	key, csr, err := pki.NewAgentKeyAndCSR(hostID)
	if err != nil {
		f.t.Fatal(err)
	}
	cert, _, err := pki.SignAgentCSR(f.ca, csr, hostID, f.clock.Now().Add(notAfterIn-pki.LeafValidity))
	if err != nil {
		f.t.Fatal(err)
	}
	return pairBytes{cert: cert, key: key}
}

func mustParse(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	c, err := pki.ParseCertPEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func writeFiles(t *testing.T, f pki.AgentFiles, p pairBytes) {
	t.Helper()
	if err := os.WriteFile(f.Cert, p.cert, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.Key, p.key, 0o600); err != nil {
		t.Fatal(err)
	}
}

func fpOfFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	fp, err := pki.FingerprintFromPEM(b)
	if err != nil {
		t.Fatal(err)
	}
	return fp
}

// startAgent runs the agent. Every dial records which certificate the TLS
// layer would present, and fails when that is rejectFP.
func (f *renewFixture) startAgent(opt func(*Options)) {
	f.t.Helper()
	f.start(func(o *Options) {
		o.TLS = f.tlsCfg
		o.RenewRetryInterval = 10 * time.Millisecond
		o.RenewTimeout = 5 * time.Second
		o.Dial = func(ctx context.Context, url string) (*websocket.Conn, error) {
			pair, err := f.agent.certs.clientCert(nil)
			if err != nil {
				return nil, err
			}
			leaf, _ := x509.ParseCertificate(pair.Certificate[0])
			fp := pki.Fingerprint(leaf)
			f.mu.Lock()
			f.dialFPs = append(f.dialFPs, fp)
			reject := fp == f.rejectFP
			f.mu.Unlock()
			if reject {
				return nil, errors.New("tls: bad certificate")
			}
			return f.hub.dial(ctx, url)
		}
		if opt != nil {
			opt(o)
		}
	})
}

func (f *renewFixture) dials() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.dialFPs...)
}

// signCSR is the hub's part: sign the request the way the real hub does.
func (f *renewFixture) signCSR(req protocol.CertCSR, current *x509.Certificate) protocol.CertIssued {
	f.t.Helper()
	certPEM, cert, err := pki.SignAgentRenewal(f.ca, []byte(req.CSRPEM), hostID, current, f.clock.Now())
	if err != nil {
		f.t.Fatalf("the agent sent an unacceptable CSR: %v", err)
	}
	return protocol.CertIssued{CertPEM: string(certPEM), NotAfter: cert.NotAfter}
}

// expectCSR reads the agent's cert.csr.
func (f *renewFixture) expectCSR(c *hubConn) (protocol.Envelope, protocol.CertCSR) {
	f.t.Helper()
	env := c.recvType(protocol.TypeCertCSR)
	return env, mustData[protocol.CertCSR](f.t, env)
}

func TestRenewalOnConnectStagesPromotesAndStopsAsking(t *testing.T) {
	f := newRenewFixture(t, 25*day, nil)
	f.startAgent(nil)
	oldFP := pki.Fingerprint(f.oldCert)

	c1 := f.hub.next()
	c1.accept()
	env, req := f.expectCSR(c1)
	csrBlock := mustParse2(t, req.CSRPEM)
	if csrBlock.Subject.CommonName != hostID {
		t.Errorf("CSR common name = %q, want the host id", csrBlock.Subject.CommonName)
	}
	if strings.Contains(req.CSRPEM, "PRIVATE KEY") || strings.Contains(string(env.Data), "PRIVATE KEY") {
		t.Fatal("the private key left the agent")
	}
	if pubEqual(csrBlock.PublicKey, f.oldCert.PublicKey) {
		t.Error("the renewal reuses the old key")
	}
	issued := f.signCSR(req, f.oldCert)
	c1.send(protocol.TypeCertIssued, env.ID, issued)
	newCert := mustParse(t, []byte(issued.CertPEM))
	newFP := pki.Fingerprint(newCert)

	// The agent reconnects with the NEW certificate first and, once the hub took it, promotes it.
	c2 := f.hub.next()
	c2.accept()
	c2.sync()
	waitFor(t, "promotion of the renewed pair", func() bool { return fpOfFile(t, f.files.Cert) == newFP })
	if got := f.dials(); len(got) != 2 || got[0] != oldFP || got[1] != newFP {
		t.Errorf("certificates presented = %v, want old then new", got)
	}
	if got := fpOfFile(t, f.files.Cert+pki.PrevSuffix); got != oldFP {
		t.Errorf(".prev holds %s, want the old certificate", got)
	}
	if f.files.HasStaged() {
		t.Error("staged files remain after promotion")
	}
	if _, err := f.files.LoadActive(); err != nil {
		t.Errorf("active pair after promotion: %v", err)
	}
	// The new certificate lasts a year: nothing more to renew.
	c2.send("sync.ping", "again", nil)
	if env := c2.recv(); env.Type != protocol.TypeError || env.ID != "again" {
		t.Errorf("unexpected message after renewal: %s %s", env.Type, env.Data)
	}
	if !strings.Contains(f.logs.String(), "connected with the renewed certificate") {
		t.Errorf("no log line about the switch:\n%s", f.logs.String())
	}
}

func mustParse2(t *testing.T, csrPEM string) *x509.CertificateRequest {
	t.Helper()
	blk, _ := pemDecode(csrPEM)
	csr, err := x509.ParseCertificateRequest(blk)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

func TestNoRenewalWhenNotDue(t *testing.T) {
	f := newRenewFixture(t, 200*day, nil)
	f.startAgent(nil)
	c := f.hub.next()
	c.accept()
	// A hub that asks without force gets an ok, but the agent has nothing to do.
	env := c.rpc(protocol.TypeCertRenew, "r1", protocol.CertRenew{})
	if env.Type != protocol.TypeResult || !mustData[protocol.Result](t, env).OK {
		t.Fatalf("answer to cert.renew = %s %s", env.Type, env.Data)
	}
	c.sync()
	if f.files.HasStaged() {
		t.Error("renewed although the certificate is not due")
	}
}

func TestHubInitiatedRenewalForcesIt(t *testing.T) {
	f := newRenewFixture(t, 200*day, nil)
	f.startAgent(nil)
	c := f.hub.next()
	c.accept()
	c.send(protocol.TypeCertRenew, "r1", protocol.CertRenew{Force: true})
	res := c.recvType(protocol.TypeResult)
	if res.ID != "r1" || !mustData[protocol.Result](t, res).OK {
		t.Fatalf("result = %s", res.Data)
	}
	env, req := f.expectCSR(c)
	c.send(protocol.TypeCertIssued, env.ID, f.signCSR(req, f.oldCert))
	waitFor(t, "staged pair", func() bool { return f.files.HasStaged() })
}

func TestConcurrentTriggersSendOneRequest(t *testing.T) {
	f := newRenewFixture(t, 20*day, nil) // due: the agent starts its own renewal on connect
	f.startAgent(nil)
	c := f.hub.next()
	c.accept()
	// The hub asks twice while the agent's own request is outstanding.
	c.send(protocol.TypeCertRenew, "r1", protocol.CertRenew{Force: true})
	c.send(protocol.TypeCertRenew, "r2", protocol.CertRenew{Force: true})

	var csrs []protocol.Envelope
	results := 0
	var reqs []protocol.CertCSR
	for results < 2 || len(csrs) < 1 {
		env := c.recv()
		switch env.Type {
		case protocol.TypeResult:
			results++
		case protocol.TypeCertCSR:
			csrs = append(csrs, env)
			reqs = append(reqs, mustData[protocol.CertCSR](t, env))
		default:
			t.Fatalf("unexpected %s", env.Type)
		}
	}
	// Answer, then make sure no second request was queued behind the first.
	c.send(protocol.TypeCertIssued, csrs[0].ID, f.signCSR(reqs[0], f.oldCert))
	c2 := f.hub.next() // the agent reconnects to use the new certificate
	c2.accept()
	c2.sync()
	if len(csrs) != 1 {
		t.Fatalf("agent sent %d cert.csr, want 1", len(csrs))
	}
	waitFor(t, "promotion", func() bool { return !f.files.HasStaged() })
}

func TestRenewalFailuresKeepTheOldCertificate(t *testing.T) {
	good := func(f *renewFixture, req protocol.CertCSR) protocol.CertIssued { return f.signCSR(req, f.oldCert) }
	tests := []struct {
		name   string
		answer func(t *testing.T, f *renewFixture, c *hubConn, env protocol.Envelope, req protocol.CertCSR)
		log    string
	}{
		{"hub refuses", func(t *testing.T, f *renewFixture, c *hubConn, env protocol.Envelope, req protocol.CertCSR) {
			c.send(protocol.TypeError, env.ID, protocol.Error{Code: protocol.CodeInvalidArgument, Message: "certificate request refused"})
		}, "certificate request refused"},
		{"hub busy", func(t *testing.T, f *renewFixture, c *hubConn, env protocol.Envelope, req protocol.CertCSR) {
			c.send(protocol.TypeError, env.ID, protocol.Error{Code: protocol.CodeBusy, Message: "x"})
		}, "already issued"},
		{"certificate for another host", func(t *testing.T, f *renewFixture, c *hubConn, env protocol.Envelope, req protocol.CertCSR) {
			// The hub's CA signs the agent's key but with a different name.
			iss := good(f, req)
			other := signForName(t, f, req, "ffffffffffffffff")
			iss.CertPEM = other
			c.send(protocol.TypeCertIssued, env.ID, iss)
		}, "another host"},
		{"certificate from a foreign CA", func(t *testing.T, f *renewFixture, c *hubConn, env protocol.Envelope, req protocol.CertCSR) {
			foreign, err := pki.LoadOrCreateCA(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			certPEM, _, err := pki.SignAgentCSR(foreign, []byte(req.CSRPEM), hostID, f.clock.Now())
			if err != nil {
				t.Fatal(err)
			}
			c.send(protocol.TypeCertIssued, env.ID, protocol.CertIssued{CertPEM: string(certPEM)})
		}, "not signed by the hub CA"},
		{"certificate for another key", func(t *testing.T, f *renewFixture, c *hubConn, env protocol.Envelope, req protocol.CertCSR) {
			_, otherCSR, _ := pki.NewAgentKeyAndCSR(hostID)
			certPEM, _, err := pki.SignAgentCSR(f.ca, otherCSR, hostID, f.clock.Now())
			if err != nil {
				t.Fatal(err)
			}
			c.send(protocol.TypeCertIssued, env.ID, protocol.CertIssued{CertPEM: string(certPEM)})
		}, "does not match"},
		{"certificate that does not last longer", func(t *testing.T, f *renewFixture, c *hubConn, env protocol.Envelope, req protocol.CertCSR) {
			certPEM, _, err := pki.SignAgentCSR(f.ca, []byte(req.CSRPEM), hostID, f.clock.Now().Add(-360*day))
			if err != nil {
				t.Fatal(err)
			}
			c.send(protocol.TypeCertIssued, env.ID, protocol.CertIssued{CertPEM: string(certPEM)})
		}, "does not last longer"},
		{"garbage", func(t *testing.T, f *renewFixture, c *hubConn, env protocol.Envelope, req protocol.CertCSR) {
			c.send(protocol.TypeCertIssued, env.ID, protocol.CertIssued{CertPEM: "nope"})
		}, "malformed certificate"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newRenewFixture(t, 20*day, nil)
			f.startAgent(nil)
			c := f.hub.next()
			c.accept()
			env, req := f.expectCSR(c)
			tc.answer(t, f, c, env, req)
			// The agent asks again after its retry pause: it has not given up and is still connected.
			env2, _ := f.expectCSR(c)
			if env2.ID == env.ID {
				t.Error("retry reused the request id")
			}
			if f.files.HasStaged() {
				t.Error("a rejected certificate was staged")
			}
			if got := fpOfFile(t, f.files.Cert); got != pki.Fingerprint(f.oldCert) {
				t.Error("the active certificate changed")
			}
			if !strings.Contains(f.logs.String(), tc.log) {
				t.Errorf("log does not mention %q:\n%s", tc.log, f.logs.String())
			}
		})
	}
}

// signForName signs the agent's CSR key under another common name (what a
// confused hub could do).
func signForName(t *testing.T, f *renewFixture, req protocol.CertCSR, name string) string {
	t.Helper()
	certPEM, _, err := pki.SignAgentCSR(f.ca, []byte(req.CSRPEM), name, f.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	return string(certPEM)
}

func TestOldHubWithoutRenewalSupport(t *testing.T) {
	f := newRenewFixture(t, 3*day, nil) // within 7 days
	f.startAgent(nil)
	c := f.hub.next()
	c.accept()
	env, _ := f.expectCSR(c)
	// A hub from before decision #47 does not know the message.
	c.send(protocol.TypeError, env.ID, protocol.Error{Code: protocol.CodeUnknownType, Message: "unknown message type"})
	c.sync() // the connection is fine
	waitFor(t, "log line", func() bool { return strings.Contains(f.logs.String(), "does not support certificate renewal") })
	// And the agent does not ask again on this connection.
	time.Sleep(60 * time.Millisecond) // several retry intervals; nothing may arrive
	c.send("sync.ping", "again", nil)
	if env := c.recv(); env.Type != protocol.TypeError || env.ID != "again" {
		t.Errorf("got %s %s after the hub said it does not know cert.csr", env.Type, env.Data)
	}
}

func TestExpiringCertificateWithFailingRenewalIsLoggedLoudly(t *testing.T) {
	f := newRenewFixture(t, 3*day, nil)
	f.startAgent(nil)
	c := f.hub.next()
	c.accept()
	env, _ := f.expectCSR(c)
	c.send(protocol.TypeError, env.ID, protocol.Error{Code: protocol.CodeInternal, Message: "boom"})
	waitFor(t, "error log", func() bool {
		l := f.logs.String()
		return strings.Contains(l, "level=ERROR") && strings.Contains(l, "renewal keeps failing")
	})
}

func TestStagedPairStartupHandling(t *testing.T) {
	tests := []struct {
		name       string
		stage      func(t *testing.T, f *renewFixture, staged pairBytes)
		wantFirst  string // "new" or "old": certificate of the first dial
		wantStaged bool
	}{
		{"fresh staged pair is tried first", func(t *testing.T, f *renewFixture, staged pairBytes) {
			if err := f.files.Stage(staged.cert, staged.key); err != nil {
				t.Fatal(err)
			}
		}, "new", true},
		{"staged pair older than the hub's grace window is dropped", func(t *testing.T, f *renewFixture, staged pairBytes) {
			if err := f.files.Stage(staged.cert, staged.key); err != nil {
				t.Fatal(err)
			}
			old := f.clock.Now().Add(-stagedMaxAge - time.Hour)
			if err := os.Chtimes(f.files.Cert+pki.StagedSuffix, old, old); err != nil {
				t.Fatal(err)
			}
		}, "old", false},
		{"half-written staged pair (crash between key and cert) is dropped", func(t *testing.T, f *renewFixture, staged pairBytes) {
			if err := os.WriteFile(f.files.Key+pki.StagedSuffix, staged.key, 0o600); err != nil {
				t.Fatal(err)
			}
		}, "old", false},
		{"staged certificate that does not match its key is dropped", func(t *testing.T, f *renewFixture, staged pairBytes) {
			other := f.issue(365 * day)
			if err := os.WriteFile(f.files.Key+pki.StagedSuffix, other.key, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(f.files.Cert+pki.StagedSuffix, staged.cert, 0o600); err != nil {
				t.Fatal(err)
			}
		}, "old", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stagedFP string
			f := newRenewFixture(t, 20*day, func(f *renewFixture) {
				staged := f.issue(365 * day)
				stagedFP = pki.Fingerprint(mustParse(t, staged.cert))
				tc.stage(t, f, staged)
			})
			f.startAgent(nil)
			c := f.hub.next()
			c.accept()
			want := pki.Fingerprint(f.oldCert)
			if tc.wantFirst == "new" {
				want = stagedFP
			}
			if got := f.dials(); len(got) == 0 || got[0] != want {
				t.Fatalf("first dial presented %v, want the %s certificate", got, tc.wantFirst)
			}
			if tc.wantFirst == "new" {
				waitFor(t, "promotion", func() bool { return fpOfFile(t, f.files.Cert) == stagedFP })
				return
			}
			// A dropped staged pair means the renewal starts over.
			f.expectCSR(c)
		})
	}
}

func TestRejectedStagedPairIsDiscardedAndRenewalRestarts(t *testing.T) {
	var stagedFP string
	f := newRenewFixture(t, 20*day, func(f *renewFixture) {
		staged := f.issue(365 * day)
		stagedFP = pki.Fingerprint(mustParse(t, staged.cert))
		if err := f.files.Stage(staged.cert, staged.key); err != nil {
			t.Fatal(err)
		}
		f.rejectFP = stagedFP // e.g. the hub restarted and forgot the pending certificate
	})
	f.startAgent(nil)
	oldFP := pki.Fingerprint(f.oldCert)

	// Attempt 1 (staged) fails at TLS; attempt 2 (old) connects. The staged pair is not given up on yet.
	c1 := f.hub.next()
	c1.accept()
	f.hubEnsureNoCSR(c1)
	_ = c1.c.CloseNow()
	// Attempt 3 (staged) fails again, attempt 4 (old) connects: two rejections, the pair is dropped.
	c2 := f.hub.next()
	c2.accept()
	if got := f.dials(); len(got) != 4 || got[0] != stagedFP || got[1] != oldFP || got[2] != stagedFP || got[3] != oldFP {
		t.Fatalf("dial sequence = %v, want staged/old alternating", got)
	}
	// ...and a fresh renewal begins, because the old certificate is still due.
	env, req := f.expectCSR(c2)
	if f.files.HasStaged() {
		t.Error("the rejected pair was not discarded")
	}
	c2.send(protocol.TypeCertIssued, env.ID, f.signCSR(req, f.oldCert))
	waitFor(t, "new staged pair", func() bool { return f.files.HasStaged() })
}

// hubEnsureNoCSR checks that no cert.csr arrives while a staged pair exists.
func (f *renewFixture) hubEnsureNoCSR(c *hubConn) {
	f.t.Helper()
	c.send("sync.ping", "chk", nil)
	if env := c.recv(); env.Type != protocol.TypeError || env.ID != "chk" {
		f.t.Fatalf("unexpected message %s %s", env.Type, env.Data)
	}
}

func TestInterruptedPromotionRecoversAtStart(t *testing.T) {
	// A crash between the two renames of Promote: new key, old certificate, staged certificate.
	var newFP string
	f := newRenewFixture(t, 20*day, func(f *renewFixture) {
		staged := f.issue(365 * day)
		newFP = pki.Fingerprint(mustParse(t, staged.cert))
		if err := os.WriteFile(f.files.Key, staged.key, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f.files.Cert+pki.StagedSuffix, staged.cert, 0o600); err != nil {
			t.Fatal(err)
		}
	})
	f.startAgent(nil)
	c := f.hub.next()
	c.accept()
	c.sync()
	if got := f.dials(); len(got) != 1 || got[0] != newFP {
		t.Errorf("dial presented %v, want the completed renewed certificate", got)
	}
}

func TestRenewalIsOffWithoutCertificateFiles(t *testing.T) {
	h := newHarness(t, nil) // default paths do not exist
	h.start(func(o *Options) { o.TLS = &tls.Config{MinVersion: tls.VersionTLS13} })
	c := h.hub.next()
	c.accept()
	env := c.rpc(protocol.TypeCertRenew, "r1", protocol.CertRenew{Force: true})
	if env.Type != protocol.TypeError || mustData[protocol.Error](t, env).Code != protocol.CodeUnsupported {
		t.Errorf("cert.renew without certificate files = %s %s", env.Type, env.Data)
	}
}

func pemDecode(s string) ([]byte, []byte) {
	blk, rest := pem.Decode([]byte(s))
	if blk == nil {
		return nil, rest
	}
	return blk.Bytes, rest
}

func pubEqual(a, b any) bool {
	k, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && k.Equal(b)
}

func TestStagedPairNotAcknowledgedKeepsBothPairs(t *testing.T) {
	var stagedFP string
	f := newRenewFixture(t, 20*day, func(f *renewFixture) {
		staged := f.issue(365 * day)
		stagedFP = pki.Fingerprint(mustParse(t, staged.cert))
		if err := f.files.Stage(staged.cert, staged.key); err != nil {
			t.Fatal(err)
		}
	})
	f.startAgent(nil)
	oldFP := pki.Fingerprint(f.oldCert)

	// The hub could not activate the renewed certificate and refuses the hello.
	c1 := f.hub.next()
	c1.handshake(protocol.HelloAck{Accepted: false, Reason: "activating the renewed certificate failed, try again"})
	// The next attempt uses the old pair, which is still the active one, and works.
	c2 := f.hub.next()
	c2.accept()
	c2.sync()
	if got := f.dials(); len(got) != 2 || got[0] != stagedFP || got[1] != oldFP {
		t.Fatalf("dial sequence = %v, want staged then old", got)
	}
	if got := fpOfFile(t, f.files.Cert); got != oldFP {
		t.Error("the active certificate was replaced without an acknowledgement")
	}
	if !f.files.HasStaged() {
		t.Error("the staged pair was dropped after a single refusal")
	}
	// The third attempt tries the staged pair again; this time the hub takes it.
	_ = c2.c.CloseNow()
	c3 := f.hub.next()
	c3.accept()
	c3.sync()
	waitFor(t, "promotion", func() bool { return fpOfFile(t, f.files.Cert) == stagedFP })
}
