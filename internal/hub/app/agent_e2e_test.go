package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	agentenroll "github.com/phabioo/nexara/internal/agent/enroll"
	"github.com/phabioo/nexara/internal/config"
	"github.com/phabioo/nexara/internal/hub/enroll"
	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/pki"
	"github.com/phabioo/nexara/internal/protocol"
)

// TestServeEnrollsAndAcceptsAnAgent drives the real wiring end to end: a
// one-time token is traded for a client certificate over the pinned HTTPS
// endpoint, OnEnrolled registers the host in the grid, and the agent then
// connects to /grid/connect with mTLS and is accepted. Shutting the hub down
// with the agent still connected must not hang.
func TestServeEnrollsAndAcceptsAnAgent(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0o750); err != nil {
		t.Fatal(err)
	}
	seed := openStore(t, filepath.Join(dir, "data"))
	createOperator(t, seed, testOperator, testPass)
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}
	h := startHub(t, dir)

	// A second handle on the same database plays the part of the UI creating a code.
	st, err := store.Open(filepath.Join(dir, "data", "nexus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	const code = "GRID-ABCD-EFGH-JKMN-PQRS"
	sum := sha256.Sum256([]byte(code))
	if err := st.CreateEnrollToken(context.Background(), hex.EncodeToString(sum[:]), time.Now().Add(15*time.Minute), nil); err != nil {
		t.Fatal(err)
	}

	keyPEM, csrPEM, err := pki.NewAgentKeyAndCSR("agent1")
	if err != nil {
		t.Fatal(err)
	}
	hello := protocol.Hello{
		AgentVersion: "dev", ProtocolVersion: protocol.ProtocolVersion, Hostname: "agent1",
		OS: "linux", Arch: "arm64", Capabilities: []string{protocol.CapMonitoring},
	}
	body, _ := json.Marshal(protocol.EnrollRequest{Token: code, CSRPEM: string(csrPEM), Hello: hello})
	resp, err := h.client.Post(h.base+"/grid/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /grid/enroll = %d", resp.StatusCode)
	}
	var enrolled protocol.EnrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&enrolled); err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(h.ready.Addr.String())
	if !strings.HasPrefix(enrolled.HubURL, "wss://") || !strings.HasSuffix(enrolled.HubURL, ":"+port+"/grid/connect") {
		t.Errorf("hub URL = %q, want wss://<agent address>:%s/grid/connect", enrolled.HubURL, port)
	}

	// Connect with the new certificate.
	pair, err := tls.X509KeyPair([]byte(enrolled.CertPEM), keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(enrolled.CAPEM)) {
		t.Fatal("CA PEM")
	}
	agentHTTP := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost", Certificates: []tls.Certificate{pair}},
	}}
	ctx, cancel := context.WithTimeout(context.Background(), waitLimit)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "wss://"+h.ready.Addr.String()+"/grid/connect", &websocket.DialOptions{HTTPClient: agentHTTP})
	if err != nil {
		t.Fatalf("agent cannot connect (enrolled host not registered in the grid?): %v", err)
	}
	defer ws.CloseNow()
	msg, err := protocol.Encode(protocol.TypeHello, "h1", hello)
	if err != nil {
		t.Fatal(err)
	}
	if err := ws.Write(ctx, websocket.MessageText, msg); err != nil {
		t.Fatal(err)
	}
	_, data, err := ws.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	env, err := protocol.Decode(data)
	if err != nil || env.Type != protocol.TypeHelloAck {
		t.Fatalf("answer = %+v %v", env, err)
	}
	if ack, err := protocol.DecodeData[protocol.HelloAck](env); err != nil || !ack.Accepted {
		t.Fatalf("hello.ack = %+v %v", ack, err)
	}

	// A certificate that is not from this hub's CA is refused.
	foreign, err := pki.LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fKey, fCSR, _ := pki.NewAgentKeyAndCSR("agent1")
	fCert, _, err := pki.SignAgentCSR(foreign, fCSR, "x", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	fPair, err := tls.X509KeyPair(fCert, fKey)
	if err != nil {
		t.Fatal(err)
	}
	bad := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost", Certificates: []tls.Certificate{fPair}},
	}}
	if r, err := bad.Get(h.base + "/grid/connect"); err == nil {
		r.Body.Close()
		if r.StatusCode != http.StatusUnauthorized {
			t.Errorf("foreign client certificate: status %d, want 401 or a handshake failure", r.StatusCode)
		}
	}

	// The agent is still connected; shutdown must finish anyway and close its socket.
	if err := h.stop(); err != nil {
		t.Fatalf("Serve = %v", err)
	}
	readCtx, readCancel := context.WithTimeout(context.Background(), waitLimit)
	defer readCancel()
	if _, _, err := ws.Read(readCtx); err == nil {
		t.Error("the agent connection survived the hub shutdown")
	}
}

// TestSelfLinkEndToEnd follows the hub's own agent: the token file the setup
// commit writes (decision #38) is traded for a certificate by the agent's
// EnrollFromTokenFile, and the agent then connects over mTLS.
func TestSelfLinkEndToEnd(t *testing.T) {
	if !validEnrollHostname(t) {
		t.Skip("the host name of this machine is not accepted by the hub (enrollment validates it)")
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0o750); err != nil {
		t.Fatal(err)
	}
	seed := openStore(t, filepath.Join(dir, "data"))
	createOperator(t, seed, testOperator, testPass)
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}
	h := startHub(t, dir)
	_, portStr, _ := net.SplitHostPort(h.ready.Addr.String())
	port, _ := strconv.Atoi(portStr)

	// What the commit does: a service with the hub's CA and store writes the token file.
	st, err := store.Open(filepath.Join(dir, "data", "nexus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ca, err := pki.LoadOrCreateCA(filepath.Join(dir, "pki"))
	if err != nil {
		t.Fatal(err)
	}
	svc, err := enroll.New(enroll.Options{
		Store: st, CA: ca, ServerCertFile: filepath.Join(dir, "pki", pki.ServerCertFile),
		HubAddress: "localhost", Port: port, DataDir: filepath.Join(dir, "data"),
	})
	if err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(dir, "data", SelfEnrollTokenFile)
	if err := svc.WriteSelfLinkToken(context.Background(), tokenFile, []string{protocol.CapMonitoring}); err != nil {
		t.Fatal(err)
	}

	agentDir := t.TempDir()
	cfgPath := filepath.Join(agentDir, "agent.yaml")
	ctx, cancel := context.WithTimeout(context.Background(), waitLimit)
	defer cancel()
	if err := agentenroll.EnrollFromTokenFile(ctx, cfgPath, agentDir, tokenFile, "pi"); err != nil {
		t.Fatalf("self-link enrollment: %v", err)
	}
	if _, err := os.Stat(tokenFile); !os.IsNotExist(err) {
		t.Errorf("token file not deleted after use: %v", err)
	}
	cfg, err := config.LoadAgent(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Capabilities.Monitoring || cfg.Capabilities.Shell || cfg.Capabilities.Packages {
		t.Errorf("capabilities = %+v, want only the chosen one", cfg.Capabilities)
	}

	caPEM, err := os.ReadFile(cfg.TLS.CA)
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg, err := pki.AgentTLSConfig(caPEM, cfg.TLS.Cert, cfg.TLS.Key)
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg.ServerName = "localhost"
	ws, _, err := websocket.Dial(ctx, "wss://"+h.ready.Addr.String()+"/grid/connect", &websocket.DialOptions{
		HTTPClient: &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}},
	})
	if err != nil {
		t.Fatalf("self-linked agent cannot connect: %v", err)
	}
	defer ws.CloseNow()
	hello := protocol.Hello{AgentVersion: "dev", ProtocolVersion: protocol.ProtocolVersion, Hostname: "x", OS: "linux", Arch: "arm64", Capabilities: cfg.Capabilities.Enabled()}
	msg, _ := protocol.Encode(protocol.TypeHello, "h1", hello)
	if err := ws.Write(ctx, websocket.MessageText, msg); err != nil {
		t.Fatal(err)
	}
	_, data, err := ws.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	env, err := protocol.Decode(data)
	if ack, aerr := protocol.DecodeData[protocol.HelloAck](env); err != nil || aerr != nil || !ack.Accepted {
		t.Fatalf("hello.ack = %+v %v %v", ack, err, aerr)
	}
}

// validEnrollHostname reports whether the hub will accept this machine's name
// (the enrollment takes it from the agent's facts).
func validEnrollHostname(t *testing.T) bool {
	t.Helper()
	name, err := os.Hostname()
	if err != nil {
		return false
	}
	name = strings.ToLower(strings.TrimSpace(name))
	if i := strings.IndexByte(name, '.'); i > 0 {
		name = name[:i]
	}
	return shortHostRe.MatchString(name)
}
