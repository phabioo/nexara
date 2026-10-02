package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/phabioo/nexara/internal/config"
	"github.com/phabioo/nexara/internal/hub/demo"
	"github.com/phabioo/nexara/internal/hub/history"
	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/pki"
	"github.com/phabioo/nexara/internal/protocol"
)

func TestNewHistoryUsesConfigDefaults(t *testing.T) {
	st := openStore(t, t.TempDir())
	cfg := config.DefaultHub()
	cfg.Storage.History.HourDays = 90
	svc := newHistory(st, nil, cfg, time.Now, nil)
	ctx := context.Background()
	if got := svc.RetentionDays(ctx); got != 90 {
		t.Fatalf("retention from nexus.yaml: %d, want 90", got)
	}
	if err := svc.SetRetentionDays(ctx, 30); err != nil {
		t.Fatal(err)
	}
	if got := svc.RetentionDays(ctx); got != 30 {
		t.Fatalf("retention after the setting: %d, want 30", got)
	}
}

func TestDevHistoryBackfill(t *testing.T) {
	st := openStore(t, t.TempDir())
	now := time.Date(2026, 10, 2, 14, 17, 42, 0, time.UTC)
	hub := demo.New(demo.Options{TimeScale: 0.001})
	defer hub.Close()

	svc, err := newDevHistory(context.Background(), st, hub, config.DefaultHub(), func() time.Time { return now }, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	hosts := hub.Hosts()
	if len(hosts) == 0 {
		t.Fatal("no demo hosts")
	}
	for _, h := range hosts {
		s, err := svc.SeriesRange(context.Background(), string(h.ID), history.MetricCPU, history.Ranges[1])
		if err != nil || !s.HasData() {
			t.Errorf("%s: no demo history (%v)", h.Name, err)
		}
	}
	// Skipping leaves the database empty.
	empty := openStore(t, t.TempDir())
	svc2, err := newDevHistory(context.Background(), empty, hub, config.DefaultHub(), func() time.Time { return now }, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := svc2.SeriesRange(context.Background(), string(hosts[0].ID), history.MetricCPU, history.Ranges[1]); s.HasData() {
		t.Error("history present although the backfill was skipped")
	}
}

// TestServeStoresHistoryAndFlushesOnShutdown connects a real (enrolled) agent,
// sends one live sample and stops the hub: the still open minute must be in
// the database afterwards.
func TestServeStoresHistoryAndFlushesOnShutdown(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0o750); err != nil {
		t.Fatal(err)
	}
	seed := openStore(t, filepath.Join(dir, "data"))
	createOperator(t, seed, testOperator, testPass)
	const code = "GRID-ABCD-EFGH-JKMN-PQRS"
	sum := sha256.Sum256([]byte(code))
	if err := seed.CreateEnrollToken(context.Background(), hex.EncodeToString(sum[:]), time.Now().Add(15*time.Minute), nil); err != nil {
		t.Fatal(err)
	}
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}
	h := startHub(t, dir)

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
	var enrolled protocol.EnrollResponse
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&enrolled) != nil {
		t.Fatalf("enrollment failed: %d", resp.StatusCode)
	}
	pair, err := tls.X509KeyPair([]byte(enrolled.CertPEM), keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(enrolled.CAPEM))
	agentHTTP := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost", Certificates: []tls.Certificate{pair}},
	}}
	ctx, cancel := context.WithTimeout(context.Background(), waitLimit)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "wss://"+h.ready.Addr.String()+"/grid/connect", &websocket.DialOptions{HTTPClient: agentHTTP})
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	send := func(id, typ string, data any) {
		t.Helper()
		msg, err := protocol.Encode(typ, id, data)
		if err != nil {
			t.Fatal(err)
		}
		if err := ws.Write(ctx, websocket.MessageText, msg); err != nil {
			t.Fatal(err)
		}
	}
	readType := func(want string) {
		t.Helper()
		for {
			_, data, err := ws.Read(ctx)
			if err != nil {
				t.Fatalf("waiting for %s: %v", want, err)
			}
			if env, err := protocol.Decode(data); err == nil && env.Type == want {
				return
			}
		}
	}
	send("h1", protocol.TypeHello, hello)
	readType(protocol.TypeHelloAck)

	cpu := 37.5
	send("", protocol.TypeMetrics, protocol.Metrics{
		Timestamp: time.Now().UTC(), CPUPercent: cpu, MemTotal: 1 << 30, MemUsed: 1 << 29,
		Disks: []protocol.Disk{{Mount: "/", Total: 100, Used: 10}},
	})
	// The hub answers an unknown message type with an error; it reads in order,
	// so the metrics message before it has been handled by then.
	send("sync", "no.such.type", struct{}{})
	readType(protocol.TypeError)

	if err := h.stop(); err != nil {
		t.Fatalf("Serve = %v", err)
	}
	st, err := store.Open(filepath.Join(dir, "data", "nexus.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	hosts, err := st.ListHosts(context.Background())
	if err != nil || len(hosts) != 1 {
		t.Fatalf("hosts %v %v", hosts, err)
	}
	now := time.Now()
	rows, err := st.ListMetrics(context.Background(), store.Metrics1m, hosts[0].ID, now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil || len(rows) != 1 || rows[0].CPUAvg != cpu || rows[0].Samples != 1 || len(rows[0].Disks) != 1 {
		t.Fatalf("the open minute was not stored at shutdown: %+v %v", rows, err)
	}
}

func TestDevHistoryBackfillStopRequestIsNoFailure(t *testing.T) {
	st := openStore(t, t.TempDir())
	hub := demo.New(demo.Options{TimeScale: 0.001})
	defer hub.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	svc, err := newDevHistory(ctx, st, hub, config.DefaultHub(), time.Now, nil, false)
	if err != nil || svc == nil {
		t.Fatalf("a cancelled context must not fail the start: %v", err)
	}
}
