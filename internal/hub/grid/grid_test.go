package grid

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/protocol"
)

func TestRegisterAndIsRevoked(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := e.g.Subscribe(ctx)

	id := e.addHost("alpha")
	ev := waitEvent(t, events, EventHostAdded)
	if ev.Host != id || ev.Payload.(HostInfo).Name != "alpha" {
		t.Fatalf("event %+v", ev)
	}
	if e.g.IsRevoked("fp-alpha") {
		t.Fatal("registered fingerprint reported revoked")
	}
	if !e.g.IsRevoked("fp-unknown") || !e.g.IsRevoked("") {
		t.Fatal("unknown fingerprint must count as revoked")
	}
	info, ok := e.g.Host(id)
	if !ok || info.Online || info.DisplayName != "ALPHA" {
		t.Fatalf("host = %+v, %v", info, ok)
	}
	if err := e.g.Register(ctx, store.Host{}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("empty host: %v", err)
	}

	e.g.Remove(id)
	waitEvent(t, events, EventHostRemoved)
	if _, ok := e.g.Host(id); ok || !e.g.IsRevoked("fp-alpha") {
		t.Fatal("removed host still known")
	}
}

func TestNewGridLoadsHostsWithoutRevoked(t *testing.T) {
	e := newEnv(t)
	base := time.Now().Add(-time.Hour)
	mk := func(name string, age time.Duration, revoked bool) {
		if _, err := e.st.CreateHost(context.Background(), store.Host{
			Name: name, CertFingerprint: "fp-" + name, CreatedAt: base.Add(age), Revoked: revoked,
		}); err != nil {
			t.Fatal(err)
		}
	}
	mk("second", time.Minute, false)
	mk("first", 0, false)
	mk("gone", 2*time.Minute, true)

	g, err := NewGrid(Options{Store: e.st})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	var names []string
	for _, h := range g.Hosts() {
		names = append(names, h.Name)
	}
	if !slices.Equal(names, []string{"first", "second"}) {
		t.Fatalf("hosts = %v", names)
	}
	if g.IsRevoked("fp-first") || !g.IsRevoked("fp-gone") {
		t.Fatal("revocation wrong")
	}
	if _, err := NewGrid(Options{}); err == nil {
		t.Fatal("NewGrid without store must fail")
	}
}

func TestHelloAckHappyPath(t *testing.T) {
	e := newEnv(t)
	id := e.addHost("alpha", protocol.CapMonitoring)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := e.g.Subscribe(ctx)

	a := e.connect("alpha", helloFor("0.1.0", protocol.CapMonitoring), nil)
	if !a.ack.Accepted || a.ack.UpdateRequired {
		t.Fatalf("ack = %+v", a.ack)
	}
	ev := waitEvent(t, events, EventHostOnline)
	if ev.Host != id {
		t.Fatalf("event host %s", ev.Host)
	}
	info, _ := e.g.Host(id)
	if !info.Online || info.AgentVersion != "0.1.0" || info.Kernel != "6.6.31" || info.Model != "Raspberry Pi 5" ||
		info.OS != "linux" || info.Arch != "arm64" || info.LastSeen.IsZero() ||
		!slices.Equal(info.Capabilities, []string{protocol.CapMonitoring}) {
		t.Fatalf("info = %+v", info)
	}
	eventually(t, func() bool {
		h, err := e.st.GetHost(context.Background(), string(id))
		return err == nil && h.AgentVersion == "0.1.0" && h.MAC == "aa:bb:cc:dd:ee:ff" && h.OS == "linux" && !h.LastSeenAt.IsZero()
	})
}

func TestIncompatibleAgentIsRejected(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.HubVersion = "0.2.0" })
	id := e.addHost("alpha")
	ctx := context.Background()
	ws, _, err := websocket.Dial(ctx, e.wsURL(), &websocket.DialOptions{HTTPHeader: http.Header{"X-Test-Host": {"alpha"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	hello, _ := json.Marshal(protocol.Hello{AgentVersion: "0.0.1", ProtocolVersion: 99, OS: "linux", Arch: "arm64"})
	raw, _ := json.Marshal(protocol.Envelope{V: 99, Type: protocol.TypeHello, ID: "h1", Data: hello})
	if err := ws.Write(ctx, websocket.MessageText, raw); err != nil {
		t.Fatal(err)
	}
	rctx, cancel := context.WithTimeout(ctx, waitFor)
	defer cancel()
	_, data, err := ws.Read(rctx)
	if err != nil {
		t.Fatal(err)
	}
	env, err := protocol.Decode(data)
	if err != nil || env.Type != protocol.TypeHelloAck || env.ID != "h1" {
		t.Fatalf("env = %+v, %v", env, err)
	}
	ack := decode[protocol.HelloAck](t, env)
	if ack.Accepted || !ack.UpdateRequired || ack.TargetVersion != "0.2.0" || ack.Reason == "" {
		t.Fatalf("ack = %+v", ack)
	}
	if _, _, err := ws.Read(rctx); err == nil {
		t.Fatal("connection stayed open")
	}
	info, _ := e.g.Host(id)
	if info.Online || !info.UpdateRequired || info.AgentVersion != "0.0.1" {
		t.Fatalf("info = %+v", info)
	}

	// A compatible agent clears the flag.
	e.connect("alpha", helloFor("0.2.0"), nil)
	eventually(t, func() bool { i, _ := e.g.Host(id); return i.Online && !i.UpdateRequired })
}

func TestNonHelloFirstMessageIsRejected(t *testing.T) {
	e := newEnv(t)
	e.addHost("alpha")
	ctx := context.Background()
	ws, _, err := websocket.Dial(ctx, e.wsURL(), &websocket.DialOptions{HTTPHeader: http.Header{"X-Test-Host": {"alpha"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	raw, _ := protocol.Encode(protocol.TypeMetrics, "", protocol.Metrics{})
	_ = ws.Write(ctx, websocket.MessageText, raw)
	rctx, cancel := context.WithTimeout(ctx, waitFor)
	defer cancel()
	if _, _, err := ws.Read(rctx); err == nil {
		t.Fatal("connection stayed open")
	}
}

func TestHelloTimeout(t *testing.T) {
	e := newEnv(t)
	e.addHost("alpha")
	e.g.to.hello = 100 * time.Millisecond
	ws, _, err := websocket.Dial(context.Background(), e.wsURL(), &websocket.DialOptions{HTTPHeader: http.Header{"X-Test-Host": {"alpha"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	rctx, cancel := context.WithTimeout(context.Background(), waitFor)
	defer cancel()
	if _, _, err := ws.Read(rctx); err == nil || rctx.Err() != nil {
		t.Fatalf("expected the hub to close the silent connection, err = %v", err)
	}
}

func TestUnknownOrRevokedAgentGets401(t *testing.T) {
	e := newEnv(t)
	for _, name := range []string{"", "nobody"} {
		hdr := http.Header{}
		if name != "" {
			hdr.Set("X-Test-Host", name)
		}
		_, resp, err := websocket.Dial(context.Background(), e.wsURL(), &websocket.DialOptions{HTTPHeader: hdr})
		if err == nil {
			t.Fatalf("%q connected", name)
		}
		if resp == nil || resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%q: response = %+v", name, resp)
		}
	}

	// Known in the store but not registered with the grid (e.g. revoked): also rejected.
	if _, err := e.st.CreateHost(context.Background(), store.Host{Name: "ghost", CertFingerprint: "fp-ghost"}); err != nil {
		t.Fatal(err)
	}
	_, resp, err := websocket.Dial(context.Background(), e.wsURL(), &websocket.DialOptions{HTTPHeader: http.Header{"X-Test-Host": {"ghost"}}})
	if err == nil || resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("ghost: %v %+v", err, resp)
	}
}

func TestDefaultIdentifyRequiresClientCertificate(t *testing.T) {
	st := newEnv(t).st
	g, err := NewGrid(Options{Store: st})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	rec := httptest.NewRecorder()
	g.AgentHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/grid/connect", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestNewConnectionReplacesOld(t *testing.T) {
	e := newEnv(t)
	id := e.addHost("alpha")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := e.g.Subscribe(ctx)

	a1 := e.connect("alpha", helloFor("0.1.0"), nil)
	waitEvent(t, events, EventHostOnline)
	a2 := e.connect("alpha", helloFor("0.1.1"), nil)
	waitEvent(t, events, EventHostOnline)
	a1.waitDone()

	// The replaced connection ending must not mark the host offline.
	time.Sleep(50 * time.Millisecond)
	info, _ := e.g.Host(id)
	if !info.Online || info.AgentVersion != "0.1.1" {
		t.Fatalf("info = %+v", info)
	}
	a2.send(protocol.TypeMetrics, "", protocol.Metrics{CPUPercent: 7})
	waitEvent(t, events, EventMetrics)

	a2.close()
	waitEvent(t, events, EventHostOffline)
	if info, _ := e.g.Host(id); info.Online {
		t.Fatal("still online after disconnect")
	}
	eventually(t, func() bool {
		h, _ := e.st.GetHost(context.Background(), string(id))
		return !h.LastSeenAt.IsZero()
	})
}

func TestOfflineAfterSilence(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.OfflineAfter = 150 * time.Millisecond })
	id := e.addHost("alpha")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := e.g.Subscribe(ctx)

	a := e.connect("alpha", helloFor("0.1.0"), nil)
	waitEvent(t, events, EventHostOnline)
	waitEvent(t, events, EventHostOffline)
	a.waitDone()
	info, _ := e.g.Host(id)
	if info.Online || info.LastSeen.IsZero() || info.Latency != 0 {
		t.Fatalf("info = %+v", info)
	}
	// host_offline is emitted once.
	time.Sleep(100 * time.Millisecond)
	for {
		select {
		case ev := <-events:
			if ev.Kind == EventHostOffline {
				t.Fatal("second host_offline event")
			}
			continue
		default:
		}
		break
	}
}

func TestMessagesKeepHostAlive(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.OfflineAfter = 500 * time.Millisecond })
	id := e.addHost("alpha")
	a := e.connect("alpha", helloFor("0.1.0"), nil)
	for range 30 {
		a.send(protocol.TypeMetrics, "", protocol.Metrics{CPUPercent: 1})
		time.Sleep(30 * time.Millisecond)
	}
	if info, _ := e.g.Host(id); !info.Online {
		t.Fatal("host went offline although metrics kept arriving")
	}
}

func TestDisconnectMakesHostOffline(t *testing.T) {
	e := newEnv(t)
	id := e.addHost("alpha")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := e.g.Subscribe(ctx)
	a := e.connect("alpha", helloFor("0.1.0"), nil)
	waitEvent(t, events, EventHostOnline)
	_ = a.ws.Close(websocket.StatusNormalClosure, "bye")
	ev := waitEvent(t, events, EventHostOffline)
	if ev.Payload.(HostInfo).Online {
		t.Fatal("offline payload says online")
	}
	if info, _ := e.g.Host(id); info.Online {
		t.Fatal("host still online")
	}
}

func TestLatencyFromPing(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.PingInterval = 20 * time.Millisecond })
	id := e.addHost("alpha")
	e.connect("alpha", helloFor("0.1.0"), nil)
	eventually(t, func() bool { i, _ := e.g.Host(id); return i.Latency > 0 })
}

func TestMetricsHistoryAndSnapshotCopies(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.HistoryLen = 3 })
	id := e.addHost("alpha")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := e.g.Subscribe(ctx)
	a := e.connect("alpha", helloFor("0.1.0"), nil)

	if snap, ok := e.g.Snapshot(id); !ok || snap.Metrics != nil || len(snap.CPUHistory) != 0 {
		t.Fatalf("fresh snapshot = %+v", snap)
	}
	temp := 51.5
	for i := 1; i <= 5; i++ {
		a.send(protocol.TypeMetrics, "", protocol.Metrics{
			CPUPercent: float64(i * 10), CPUPerCore: []float64{1, 2}, TempC: &temp,
			Disks: []protocol.Disk{{Mount: "/"}}, Timestamp: time.Unix(int64(i), 0).UTC(),
		})
	}
	var last Event
	for range 5 {
		last = waitEvent(t, events, EventMetrics)
	}
	if m := last.Payload.(protocol.Metrics); m.CPUPercent != 50 || last.Host != id {
		t.Fatalf("last event %+v", last)
	}
	snap, _ := e.g.Snapshot(id)
	if !slices.Equal(snap.CPUHistory, []float64{30, 40, 50}) || snap.Metrics == nil || snap.Metrics.CPUPercent != 50 {
		t.Fatalf("snapshot = %+v", snap)
	}
	if snap.Metrics.TempC == nil || *snap.Metrics.TempC != 51.5 {
		t.Fatalf("temp = %v", snap.Metrics.TempC)
	}

	// Mutating the returned copy must not touch the grid's state.
	snap.CPUHistory[0] = 99
	snap.Metrics.CPUPerCore[0] = 99
	*snap.Metrics.TempC = 99
	snap.Metrics.Disks[0].Mount = "x"
	again, _ := e.g.Snapshot(id)
	if again.CPUHistory[0] != 30 || again.Metrics.CPUPerCore[0] != 1 || *again.Metrics.TempC != 51.5 || again.Metrics.Disks[0].Mount != "/" {
		t.Fatalf("snapshot shares state: %+v", again)
	}
	if _, ok := e.g.Snapshot("nope"); ok {
		t.Fatal("snapshot of unknown host")
	}
}

func TestRefreshOnConnectAndOnDemand(t *testing.T) {
	e := newEnv(t)
	id := e.addHost("alpha", protocol.CapServices, protocol.CapPackages)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := e.g.Subscribe(ctx)
	e.connect("alpha", helloFor("0.1.0", protocol.CapServices, protocol.CapPackages), answerRefresh)

	sv := waitEvent(t, events, EventServices).Payload.(protocol.Services)
	pk := waitEvent(t, events, EventPackages).Payload.(protocol.Packages)
	if len(sv.Units) != 1 || sv.Units[0].Name != "ssh.service" || len(pk.Items) != 1 || !pk.RebootRequired {
		t.Fatalf("payloads %+v %+v", sv, pk)
	}
	snap, _ := e.g.Snapshot(id)
	if snap.Services == nil || snap.Packages == nil || !snap.Host.RebootRequired {
		t.Fatalf("snapshot = %+v", snap)
	}
	if err := e.g.RefreshServices(ctx, id); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, events, EventServices)
	if err := e.g.RefreshPackages(ctx, id); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, events, EventPackages)
}

func TestRefreshErrors(t *testing.T) {
	e := newEnv(t)
	offline := e.addHost("offline", protocol.CapServices, protocol.CapPackages)
	noCaps := e.addHost("nocaps", protocol.CapMonitoring)
	e.connect("nocaps", helloFor("0.1.0", protocol.CapMonitoring), nil)
	ctx := context.Background()

	for name, fn := range map[string]func(HostID) error{
		"services": func(id HostID) error { return e.g.RefreshServices(ctx, id) },
		"packages": func(id HostID) error { return e.g.RefreshPackages(ctx, id) },
		"search":   func(id HostID) error { _, err := e.g.SearchPackages(ctx, id, "htop"); return err },
		"restart":  func(id HostID) error { return e.g.RestartService(ctx, Actor{}, id, "ssh.service") },
	} {
		if err := fn("missing"); !errors.Is(err, ErrHostNotFound) {
			t.Errorf("%s unknown host: %v", name, err)
		}
		if err := fn(offline); !errors.Is(err, ErrHostOffline) {
			t.Errorf("%s offline: %v", name, err)
		}
		eventually(t, func() bool { i, _ := e.g.Host(noCaps); return i.Online })
		if err := fn(noCaps); !errors.Is(err, ErrCapabilityDisabled) {
			t.Errorf("%s capability: %v", name, err)
		}
	}
}

func TestRefreshTimeouts(t *testing.T) {
	e := newEnv(t)
	e.g.to.servicesList = 100 * time.Millisecond
	e.g.to.packagesList = 100 * time.Millisecond
	e.g.to.packagesSearch = 100 * time.Millisecond
	id := e.addHost("alpha", protocol.CapServices, protocol.CapPackages)
	swallow := func(_ *fakeAgent, env protocol.Envelope) bool {
		return env.Type == protocol.TypeServicesList || env.Type == protocol.TypePackagesList || env.Type == protocol.TypePackagesSearch
	}
	a := e.connect("alpha", helloFor("0.1.0", protocol.CapServices, protocol.CapPackages), swallow)
	ctx := context.Background()
	if err := e.g.RefreshServices(ctx, id); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("services: %v", err)
	}
	if err := e.g.RefreshPackages(ctx, id); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("packages: %v", err)
	}
	if _, err := e.g.SearchPackages(ctx, id, "htop"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("search: %v", err)
	}
	// The connection survives a timeout.
	a.send(protocol.TypeMetrics, "", protocol.Metrics{})
	if info, _ := e.g.Host(id); !info.Online {
		t.Fatal("host offline after timeouts")
	}
}

func TestRefreshHonoursContextCancel(t *testing.T) {
	e := newEnv(t)
	id := e.addHost("alpha", protocol.CapServices)
	e.connect("alpha", helloFor("0.1.0", protocol.CapServices), func(_ *fakeAgent, env protocol.Envelope) bool {
		return env.Type == protocol.TypeServicesList // never answered
	})
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	if err := e.g.RefreshServices(ctx, id); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
}

func TestSearchPackages(t *testing.T) {
	e := newEnv(t)
	id := e.addHost("alpha", protocol.CapPackages)
	var queries = make(chan string, 4)
	handler := func(a *fakeAgent, env protocol.Envelope) bool {
		switch env.Type {
		case protocol.TypePackagesList:
			a.send(protocol.TypePackages, env.ID, protocol.Packages{})
			return true
		case protocol.TypePackagesSearch:
			q := decode[protocol.PackagesSearch](t, env).Query
			queries <- q
			if q == "explode" {
				a.send(protocol.TypeError, env.ID, protocol.Error{Code: protocol.CodeInvalidArgument, Message: "no"})
				return true
			}
			a.send(protocol.TypePackages, env.ID, protocol.Packages{Items: []protocol.Package{
				{Name: q, State: protocol.PackageAvailable}, {Name: q + "-doc", State: protocol.PackageAvailable},
			}})
			return true
		}
		return false
	}
	e.connect("alpha", helloFor("0.1.0", protocol.CapPackages), handler)
	eventually(t, func() bool { s, _ := e.g.Snapshot(id); return s.Packages != nil })

	items, err := e.g.SearchPackages(context.Background(), id, "nginx")
	if err != nil || len(items) != 2 || items[0].Name != "nginx" || <-queries != "nginx" {
		t.Fatalf("items = %+v, %v", items, err)
	}
	if _, err := e.g.SearchPackages(context.Background(), id, "explode"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("agent error: %v", err)
	}
	<-queries
	for _, q := range []string{"", "a", "Nginx", "x y", "a;b", "-x", "a/b"} {
		if _, err := e.g.SearchPackages(context.Background(), id, q); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("query %q: %v", q, err)
		}
	}
	if len(queries) != 0 {
		t.Fatal("invalid queries reached the agent")
	}
}

func TestRestartService(t *testing.T) {
	e := newEnv(t)
	id := e.addHost("alpha", protocol.CapServices)
	restarts := make(chan string, 4)
	var fail bool
	handler := func(a *fakeAgent, env protocol.Envelope) bool {
		switch env.Type {
		case protocol.TypeServicesList:
			return answerRefresh(a, env)
		case protocol.TypeServiceRestart:
			restarts <- decode[protocol.ServiceRestart](t, env).Unit
			if fail {
				a.result(env, false, "unit not found")
			} else {
				a.result(env, true, "")
			}
			return true
		}
		return false
	}
	e.connect("alpha", helloFor("0.1.0", protocol.CapServices), handler)
	ctx := context.Background()
	events := e.g.Subscribe(ctx)
	eventually(t, func() bool { s, _ := e.g.Snapshot(id); return s.Services != nil })
	for len(events) > 0 {
		<-events
	}

	for _, bad := range []string{"", "ssh", "ssh.timer", ".service x", "a b.service", "../x.service", "a;b.service", "$(x).service"} {
		if err := e.g.RestartService(ctx, Actor{Operator: "op1"}, id, bad); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("unit %q: %v", bad, err)
		}
	}
	if len(restarts) != 0 {
		t.Fatal("invalid unit reached the agent")
	}

	for _, good := range []string{"ssh.service", "getty@tty1.service", "systemd-resolved.service"} {
		if err := e.g.RestartService(ctx, Actor{Operator: "op1"}, id, good); err != nil {
			t.Fatalf("%s: %v", good, err)
		}
		if got := <-restarts; got != good {
			t.Fatalf("agent got %q", got)
		}
		waitEvent(t, events, EventServices) // refreshed after the restart
	}
	a := e.waitAudit("service.restart")
	if a.User != "op1" || a.Host != "alpha" || a.Result != store.AuditOK || a.Detail == "" {
		t.Fatalf("audit = %+v", a)
	}

	fail = true
	err := e.g.RestartService(ctx, Actor{Operator: "op2"}, id, "nope.service")
	if err == nil || errors.Is(err, ErrInvalidArgument) || !strings.Contains(err.Error(), "unit not found") {
		t.Fatalf("agent rejection: %v", err)
	}
	eventually(t, func() bool {
		for _, a := range e.auditEntries() {
			if a.Action == "service.restart" && a.User == "op2" && a.Result == store.AuditError {
				return true
			}
		}
		return false
	})
}

func TestUnknownMessageTypeKeepsConnection(t *testing.T) {
	e := newEnv(t)
	id := e.addHost("alpha", protocol.CapServices)
	a := e.connect("alpha", helloFor("0.1.0", protocol.CapServices), answerRefresh)
	eventually(t, func() bool { s, _ := e.g.Snapshot(id); return s.Services != nil })

	raw, _ := json.Marshal(protocol.Envelope{V: 1, Type: "teleport", ID: "x1"})
	if err := a.ws.Write(context.Background(), websocket.MessageText, raw); err != nil {
		t.Fatal(err)
	}
	env := a.expect(protocol.TypeError)
	if perr := decode[protocol.Error](t, env); env.ID != "x1" || perr.Code != protocol.CodeUnknownType {
		t.Fatalf("reply = %+v %+v", env, perr)
	}
	// Hub-to-agent types are not valid from an agent either.
	a.send(protocol.TypeServicesList, "x2", nil)
	if perr := decode[protocol.Error](t, a.expect(protocol.TypeError)); perr.Code != protocol.CodeBadRequest {
		t.Fatalf("code = %s", perr.Code)
	}
	// Malformed JSON does not end the connection.
	_ = a.ws.Write(context.Background(), websocket.MessageText, []byte("{not json"))
	a.expect(protocol.TypeError)
	if err := e.g.RefreshServices(context.Background(), id); err != nil {
		t.Fatalf("connection broken: %v", err)
	}
}

func TestSlowSubscriberNeverBlocksGrid(t *testing.T) {
	e := newEnv(t)
	id := e.addHost("alpha", protocol.CapServices)
	a := e.connect("alpha", helloFor("0.1.0", protocol.CapServices), answerRefresh)

	slowCtx, slowCancel := context.WithCancel(context.Background())
	slow := e.g.Subscribe(slowCtx) // never read while the agent floods
	const n = subscriberBuffer*2 + 50
	for i := range n {
		a.send(protocol.TypeMetrics, "", protocol.Metrics{CPUPercent: float64(i % 100)})
	}
	// The grid still serves requests (the answer is read after all metrics above).
	if err := e.g.RefreshServices(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if len(slow) > subscriberBuffer {
		t.Fatalf("buffer grew to %d", len(slow))
	}
	// Later subscribers still get events.
	freshCtx, freshCancel := context.WithCancel(context.Background())
	defer freshCancel()
	fresh := e.g.Subscribe(freshCtx)
	a.send(protocol.TypeMetrics, "", protocol.Metrics{CPUPercent: 42})
	if m := waitEvent(t, fresh, EventMetrics).Payload.(protocol.Metrics); m.CPUPercent != 42 {
		t.Fatalf("metrics = %+v", m)
	}
	slowCancel()
	deadline := time.After(waitFor)
	for {
		select {
		case _, ok := <-slow:
			if !ok {
				return
			}
		case <-deadline:
			t.Fatal("subscription channel not closed after cancel")
		}
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		cmp  int
		ok   bool
	}{
		{"0.1.0", "0.1.0", 0, true},
		{"0.1.0", "0.2.0", -1, true},
		{"0.10.0", "0.9.0", 1, true},
		{"v1.2.3", "1.2.3", 0, true},
		{"1.2", "1.2.0", 0, true},
		{"1.0.0-rc1", "1.0.0", -1, true},
		{"1.0.0", "1.0.0-rc1", 1, true},
		{"1.0.0+build5", "1.0.0", 0, true},
		{"2.0.0", "1.99.99", 1, true},
		{"dev", "1.0.0", 0, false},
		{"", "1.0.0", 0, false},
		{"1.x.0", "1.0.0", 0, false},
		{"1.2.3.4", "1.0.0", 0, false},
	}
	for _, c := range cases {
		cmp, ok := compareVersions(c.a, c.b)
		if cmp != c.cmp || ok != c.ok {
			t.Errorf("compareVersions(%q, %q) = %d, %v; want %d, %v", c.a, c.b, cmp, ok, c.cmp, c.ok)
		}
	}
}

func TestNeedsUpdate(t *testing.T) {
	cases := []struct {
		agent, hub string
		want       bool
	}{
		{"0.1.0", "0.2.0", true},
		{"0.2.0", "0.2.0", false},
		{"0.3.0", "0.2.0", false},
		{"0.1.0", "dev", false},
		{"dev", "0.2.0", false},
		{"", "0.2.0", false},
		{"0.1.0", "", false},
		{"garbage", "0.2.0", false},
	}
	for _, c := range cases {
		if got := needsUpdate(c.agent, c.hub); got != c.want {
			t.Errorf("needsUpdate(%q, %q) = %v", c.agent, c.hub, got)
		}
	}
}

func TestRegisterKnownHostClosesConnectionWithoutHostAdded(t *testing.T) {
	e := newEnv(t)
	id := e.addHost("alpha")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := e.g.Subscribe(ctx)
	a := e.connect("alpha", helloFor("0.1.0"), nil)
	waitEvent(t, events, EventHostOnline)

	// Re-install: new certificate and display name in the store.
	if err := e.st.SetHostCert(ctx, string(id), "fp-alpha-new", "serial2", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := e.st.SetHostDisplayName(ctx, string(id), "Renamed"); err != nil {
		t.Fatal(err)
	}
	h, err := e.st.GetHost(ctx, string(id))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.g.Register(ctx, h); err != nil {
		t.Fatal(err)
	}
	a.waitDone()
	for {
		ev := nextEvent(t, events)
		if ev.Kind == EventHostAdded {
			t.Fatal("host_added emitted for a known host")
		}
		if ev.Kind == EventHostOffline {
			break
		}
	}
	info, _ := e.g.Host(id)
	if info.Online || info.DisplayName != "Renamed" {
		t.Fatalf("info = %+v", info)
	}
	if !e.g.IsRevoked("fp-alpha") || e.g.IsRevoked("fp-alpha-new") {
		t.Fatal("fingerprints not refreshed")
	}
}

func nextEvent(t *testing.T, ch <-chan Event) Event {
	t.Helper()
	select {
	case ev, ok := <-ch:
		if !ok {
			t.Fatal("event channel closed")
		}
		return ev
	case <-timeAfterWait():
		t.Fatal("no event in time")
	}
	return Event{}
}
