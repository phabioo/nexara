package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/phabioo/nexara/internal/agent/runtime"
	"github.com/phabioo/nexara/internal/config"
	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/pki"
	"github.com/phabioo/nexara/internal/protocol"
)

// hubClock is the hub's injected time. TLS verifies certificates against the
// real time, so the clock starts in the past (the agent certificate issued at
// enrollment then has 20 days left in real time) and is set to the real time to
// make the renewal due.
type hubClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *hubClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *hubClock) Set(t time.Time) {
	c.mu.Lock()
	c.t = t
	c.mu.Unlock()
}

func pollUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(waitLimit)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func certFP(t *testing.T, path string) string {
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

// TestAgentCertificateRenewalEndToEnd runs the real hub (TLS listener, CA,
// store, grid) and the real agent runtime: an agent whose certificate is 20
// days from expiry renews over its WebSocket, reconnects with the new
// certificate, the hub switches over on first use and the old certificate
// stops working.
func TestAgentCertificateRenewalEndToEnd(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0o750); err != nil {
		t.Fatal(err)
	}
	seed := openStore(t, filepath.Join(dir, "data"))
	createOperator(t, seed, testOperator, testPass)
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}

	realNow := time.Now().UTC().Truncate(time.Second)
	clk := &hubClock{t: realNow.Add(-(pki.LeafValidity - 20*24*time.Hour))}

	log, logs := testLogger()
	cfgPath := writeHubConfig(t, dir)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	ready := make(chan Ready, 1)
	go func() {
		done <- Serve(ctx, ServeOptions{
			ConfigPath: cfgPath, Logger: log, Listener: ln, Now: clk.Now,
			HashParams: cheapParams, Ready: func(r Ready) { ready <- r },
		})
	}()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("Serve returned before it was ready: %v", err)
	case <-time.After(waitLimit):
		t.Fatal("hub did not become ready")
	}
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(waitLimit):
			t.Error("Serve did not return")
		}
	})
	addr := ln.Addr().String()

	caPEM, err := os.ReadFile(filepath.Join(dir, "pki", pki.CACertFile))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)

	// --- enroll an agent (the hub's clock is in the past: 20 days of validity are left) ---
	st, err := store.Open(filepath.Join(dir, "data", "nexus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	const code = "GRID-ABCD-EFGH-JKMN-PQRS"
	sum := sha256.Sum256([]byte(code))
	if err := st.CreateEnrollToken(context.Background(), hex.EncodeToString(sum[:]), clk.Now().Add(15*time.Minute), nil); err != nil {
		t.Fatal(err)
	}
	keyPEM, csrPEM, err := pki.NewAgentKeyAndCSR("agent1")
	if err != nil {
		t.Fatal(err)
	}
	hello := protocol.Hello{AgentVersion: "dev", ProtocolVersion: protocol.ProtocolVersion, Hostname: "agent1", OS: "linux", Arch: "arm64"}
	body, _ := json.Marshal(protocol.EnrollRequest{Token: code, CSRPEM: string(csrPEM), Hello: hello})
	httpc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost"}}}
	resp, err := httpc.Post("https://"+addr+"/grid/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var enrolled protocol.EnrollResponse
	err = json.NewDecoder(resp.Body).Decode(&enrolled)
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("enroll: %d %v", resp.StatusCode, err)
	}

	agentDir := t.TempDir()
	certFile, keyFile, caFile := filepath.Join(agentDir, "agent.pem"), filepath.Join(agentDir, "agent.key"), filepath.Join(agentDir, "ca.pem")
	for path, data := range map[string][]byte{certFile: []byte(enrolled.CertPEM), keyFile: keyPEM, caFile: []byte(enrolled.CAPEM)} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	oldFP := certFP(t, certFile)
	oldCertPEM := append([]byte(nil), enrolled.CertPEM...)
	oldKeyPEM := append([]byte(nil), keyPEM...)
	host, err := st.GetHostByFingerprint(context.Background(), oldFP)
	if err != nil {
		t.Fatal(err)
	}
	if left := host.CertNotAfter.Sub(realNow); left < 19*24*time.Hour || left > 21*24*time.Hour {
		t.Fatalf("test setup: certificate has %v left, want about 20 days", left)
	}

	// The hub now sees the certificate as due.
	clk.Set(realNow)

	// --- run the real agent ---
	cfg := config.DefaultAgent()
	cfg.Hub.URL = "wss://" + addr + "/grid/connect"
	cfg.TLS.CA, cfg.TLS.Cert, cfg.TLS.Key = caFile, certFile, keyFile
	cfg.Capabilities = config.Capabilities{}
	tlsCfg, err := pki.AgentTLSConfig([]byte(enrolled.CAPEM), certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	agentLog, agentLogs := testLogger()
	agent := runtime.New(runtime.Options{Config: cfg, TLS: tlsCfg, Logger: agentLog})
	agentCtx, agentCancel := context.WithCancel(context.Background())
	agentDone := make(chan error, 1)
	go func() { agentDone <- agent.Run(agentCtx) }()
	stopAgent := func() {
		agentCancel()
		select {
		case <-agentDone:
		case <-time.After(waitLimit):
			t.Error("agent did not stop")
		}
	}
	t.Cleanup(stopAgent)

	// The agent renews, reconnects with the new certificate, the hub activates it.
	pollUntil(t, "the hub to switch to the renewed certificate", func() bool {
		h, err := st.GetHost(context.Background(), host.ID)
		return err == nil && h.CertFingerprint != oldFP
	})
	row, _ := st.GetHost(context.Background(), host.ID)
	pollUntil(t, "the agent to promote its renewed pair", func() bool { return certFP(t, certFile) == row.CertFingerprint })
	if got := certFP(t, certFile+pki.PrevSuffix); got != oldFP {
		t.Errorf("previous certificate kept as %s, want %s", got, oldFP)
	}
	if left := row.CertNotAfter.Sub(realNow); left < 364*24*time.Hour || left > 366*24*time.Hour {
		t.Errorf("renewed certificate lasts %v, want about a year", left)
	}
	if row.CertSerial == host.CertSerial || row.CertSerial == "" {
		t.Errorf("serial = %q, was %q", row.CertSerial, host.CertSerial)
	}

	// The old certificate no longer works; the new one does.
	oldPair, err := tls.X509KeyPair(oldCertPEM, oldKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	newPair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	dial := func(pair tls.Certificate) error {
		ctx, cancel := context.WithTimeout(context.Background(), waitLimit)
		defer cancel()
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost", Certificates: []tls.Certificate{pair}}}}
		ws, _, err := websocket.Dial(ctx, "wss://"+addr+"/grid/connect", &websocket.DialOptions{HTTPClient: c})
		if err != nil {
			return err
		}
		defer ws.CloseNow()
		b, _ := protocol.Encode(protocol.TypeHello, "h", hello)
		if err := ws.Write(ctx, websocket.MessageText, b); err != nil {
			return err
		}
		_, data, err := ws.Read(ctx)
		if err != nil {
			return err
		}
		env, err := protocol.Decode(data)
		if err != nil {
			return err
		}
		ack, err := protocol.DecodeData[protocol.HelloAck](env)
		if err != nil || !ack.Accepted {
			return fmt.Errorf("not accepted: %+v %v", ack, err)
		}
		return nil
	}
	if err := dial(oldPair); err == nil {
		t.Error("the old certificate still connects after the renewed one was used")
	}
	if err := dial(newPair); err != nil {
		t.Errorf("the renewed certificate does not connect: %v", err)
	}

	// Audit: issued and activated, nothing secret in it.
	entries, err := st.ListAudit(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	var issued, activated bool
	for _, e := range entries {
		if e.Action != "cert.renew" {
			continue
		}
		issued = issued || (e.Result == store.AuditOK && strings.Contains(e.Detail, "issued"))
		activated = activated || (e.Result == store.AuditOK && strings.Contains(e.Detail, "activated"))
		if strings.Contains(e.Detail, "PRIVATE") {
			t.Errorf("audit detail leaks key material: %q", e.Detail)
		}
	}
	if !issued || !activated {
		t.Errorf("audit entries cert.renew: issued=%v activated=%v in %+v", issued, activated, entries)
	}
	for _, l := range []string{logs.String(), agentLogs.String()} {
		if strings.Contains(l, "PRIVATE KEY") {
			t.Error("a log contains key material")
		}
	}
}

// fakeSweeper counts the daily sweeps.
type fakeSweeper struct{ n atomic.Int32 }

func (f *fakeSweeper) CheckRenewals(context.Context) { f.n.Add(1) }

func TestRunAgentCertRenewalsSweepsPeriodically(t *testing.T) {
	f := &fakeSweeper{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runAgentCertRenewals(ctx, f, 5*time.Millisecond)
		close(done)
	}()
	pollUntil(t, "two sweeps", func() bool { return f.n.Load() >= 2 })
	cancel()
	select {
	case <-done:
	case <-time.After(waitLimit):
		t.Fatal("the sweep loop did not stop")
	}
}
