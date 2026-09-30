package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	goruntime "runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/phabioo/nexara/internal/agent/shell"
	"github.com/phabioo/nexara/internal/buildinfo"
	"github.com/phabioo/nexara/internal/config"
	"github.com/phabioo/nexara/internal/protocol"
)

func TestHelloAndAck(t *testing.T) {
	h := newHarness(t, func(c *config.AgentConfig) { c.Capabilities.Docker = false })
	h.start(nil)
	hello := h.hub.next().accept()

	if hello.AgentVersion != buildinfo.Version || hello.ProtocolVersion != protocol.ProtocolVersion {
		t.Errorf("versions: %+v", hello)
	}
	if hello.Hostname != "frpi5" || hello.OS != "linux" || hello.Arch != "arm64" || hello.Kernel != "6.6" || hello.Model != "Pi 5" || hello.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("facts: %+v", hello)
	}
	want := []string{protocol.CapPackages, protocol.CapServices, protocol.CapShell}
	if !slices.Equal(hello.Capabilities, want) {
		t.Errorf("capabilities = %v, want %v", hello.Capabilities, want)
	}
}

func TestNotAcceptedBacksOffThenReconnects(t *testing.T) {
	h := newHarness(t, nil)
	h.failDials.Store(2)
	h.start(nil)

	// Two failed dials (1s, 2s), then a refusal (4s).
	c1 := h.hub.next()
	c1.handshake(protocol.HelloAck{Accepted: false, Reason: "agent too old", UpdateRequired: false})

	// Accepted, dropped after a short time: backoff keeps growing (8s).
	c2 := h.hub.next()
	c2.accept()
	c2.sync()
	h.clock.Advance(30 * time.Second)
	_ = c2.c.CloseNow()

	// Accepted and stable for more than 60s: backoff resets (1s).
	c3 := h.hub.next()
	c3.accept()
	c3.sync()
	h.clock.Advance(61 * time.Second)
	_ = c3.c.CloseNow()

	c4 := h.hub.next()
	c4.accept()
	c4.sync()

	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, time.Second}
	if got := h.gotSleeps(); !slices.Equal(got, want) {
		t.Fatalf("sleeps = %v, want %v", got, want)
	}
	if !strings.Contains(h.logs.String(), "agent too old") {
		t.Errorf("rejection reason not logged:\n%s", h.logs.String())
	}
}

func TestBackoffCapsAtThirtySeconds(t *testing.T) {
	h := newHarness(t, nil)
	h.failDials.Store(8)
	h.start(nil)
	h.hub.next().accept()
	want := []time.Duration{1, 2, 4, 8, 16, 30, 30, 30}
	got := h.gotSleeps()
	for i, w := range want {
		if got[i] != w*time.Second {
			t.Fatalf("sleeps = %v", got)
		}
	}
}

func TestMetricsBufferedWhileDisconnectedAndFlushedInOrder(t *testing.T) {
	h := newHarness(t, func(c *config.AgentConfig) { c.Capabilities.Monitoring = true })
	h.gate = make(chan struct{})
	h.start(nil)

	c1 := h.hub.next()
	c1.accept()
	var last float64
	for range 3 {
		last = mustData[protocol.Metrics](t, c1.recvType(protocol.TypeMetrics)).CPUPercent
	}
	_ = c1.c.CloseNow()
	recvChan(t, h.entered, "agent entering backoff")

	// Samples keep being taken while the agent is offline.
	waitFor(t, "samples while offline", func() bool { return float64(h.metrics.n.Load()) >= last+6 })
	collected := float64(h.metrics.n.Load())
	close(h.gate)

	c2 := h.hub.next()
	c2.accept()
	prev := last
	for i := range 5 {
		v := mustData[protocol.Metrics](t, c2.recvType(protocol.TypeMetrics)).CPUPercent
		if v <= prev {
			t.Fatalf("sample %d = %v, not after %v", i, v, prev)
		}
		if i == 0 && v > collected {
			t.Fatalf("first sample after reconnect (%v) is newer than the ones buffered while offline (<= %v)", v, collected)
		}
		prev = v
	}
}

func TestRingDropsOldest(t *testing.T) {
	r := newRing(3)
	for i := 1; i <= 5; i++ {
		r.push(protocol.Metrics{CPUPercent: float64(i)})
	}
	var got []float64
	for {
		s, ok := r.peek()
		if !ok {
			break
		}
		got = append(got, s.m.CPUPercent)
		r.ack(s.seq)
	}
	if !slices.Equal(got, []float64{3, 4, 5}) {
		t.Fatalf("got %v", got)
	}
	// ack of a dropped sample must not remove a newer one.
	r.push(protocol.Metrics{CPUPercent: 9})
	r.ack(1)
	if r.len() != 1 {
		t.Fatalf("len = %d", r.len())
	}
}

func TestRequests(t *testing.T) {
	h := newHarness(t, nil)
	h.packages.run = func(context.Context, protocol.JobStart, func(protocol.JobOutput)) protocol.JobDone {
		return protocol.JobDone{OK: true}
	}
	h.start(nil)
	c := h.hub.next()
	c.accept()

	t.Run("services.list", func(t *testing.T) {
		env := c.rpc(protocol.TypeServicesList, "r1", nil)
		if env.Type != protocol.TypeServices {
			t.Fatalf("type %s", env.Type)
		}
		if got := mustData[protocol.Services](t, env); len(got.Units) != 1 || got.Units[0].Name != "ssh.service" {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("service.restart ok", func(t *testing.T) {
		env := c.rpc(protocol.TypeServiceRestart, "r2", protocol.ServiceRestart{Unit: "ssh.service"})
		if r := mustData[protocol.Result](t, env); env.Type != protocol.TypeResult || !r.OK {
			t.Fatalf("%s %+v", env.Type, r)
		}
		h.services.mu.Lock()
		defer h.services.mu.Unlock()
		if !slices.Equal(h.services.restarted, []string{"ssh.service"}) {
			t.Fatalf("restarted %v", h.services.restarted)
		}
	})
	t.Run("service.restart error is a safe result", func(t *testing.T) {
		h.services.mu.Lock()
		h.services.restartErr = errors.New("unit not found\nsecret detail on the second line")
		h.services.mu.Unlock()
		env := c.rpc(protocol.TypeServiceRestart, "r3", protocol.ServiceRestart{Unit: "nope.service"})
		r := mustData[protocol.Result](t, env)
		if env.Type != protocol.TypeResult || r.OK || r.Error != "unit not found" {
			t.Fatalf("%s %+v", env.Type, r)
		}
	})
	t.Run("packages.list", func(t *testing.T) {
		env := c.rpc(protocol.TypePackagesList, "r4", nil)
		got := mustData[protocol.Packages](t, env)
		if env.Type != protocol.TypePackages || len(got.Items) != 1 || !got.RebootRequired {
			t.Fatalf("%s %+v", env.Type, got)
		}
	})
	t.Run("packages.search", func(t *testing.T) {
		env := c.rpc(protocol.TypePackagesSearch, "r5", protocol.PackagesSearch{Query: "htop"})
		got := mustData[protocol.Packages](t, env)
		if env.Type != protocol.TypePackages || len(got.Items) != 1 || got.Items[0].Name != "htop" || got.RebootRequired {
			t.Fatalf("%s %+v", env.Type, got)
		}
	})
	t.Run("unknown type", func(t *testing.T) {
		env := c.rpc("frobnicate", "r6", nil)
		e := mustData[protocol.Error](t, env)
		if env.Type != protocol.TypeError || e.Code != protocol.CodeUnknownType {
			t.Fatalf("%s %+v", env.Type, e)
		}
	})
	t.Run("missing payload", func(t *testing.T) {
		env := c.rpc(protocol.TypeServiceRestart, "r7", nil)
		e := mustData[protocol.Error](t, env)
		if env.Type != protocol.TypeError || e.Code != protocol.CodeBadRequest {
			t.Fatalf("%s %+v", env.Type, e)
		}
	})
}

func TestCapabilityDisabled(t *testing.T) {
	h := newHarness(t, func(c *config.AgentConfig) {
		c.Capabilities.Services = false
		c.Capabilities.Packages = false
		c.Capabilities.Shell = false
	})
	h.start(nil)
	c := h.hub.next()
	hello := c.accept()
	if len(hello.Capabilities) != 0 {
		t.Fatalf("capabilities = %v", hello.Capabilities)
	}
	for _, typ := range []string{
		protocol.TypeServicesList, protocol.TypeServiceRestart, protocol.TypePackagesList, protocol.TypePackagesSearch,
		protocol.TypeJobStart, protocol.TypeJobCancel, protocol.TypeShellOpen, protocol.TypeShellData,
		protocol.TypeShellResize, protocol.TypeShellClose,
	} {
		env := c.rpc(typ, "x-"+typ, map[string]string{"unit": "a"})
		e := mustData[protocol.Error](t, env)
		if env.Type != protocol.TypeError || e.Code != protocol.CodeCapabilityDisabled {
			t.Errorf("%s: got %s %+v", typ, env.Type, e)
		}
	}
}

func TestJobLifecycle(t *testing.T) {
	h := newHarness(t, nil)
	release := make(chan struct{})
	started := make(chan string, 4)
	h.packages.run = func(ctx context.Context, job protocol.JobStart, out func(protocol.JobOutput)) protocol.JobDone {
		out(protocol.JobOutput{Stream: protocol.StreamStdout, Line: "one"})
		out(protocol.JobOutput{Stream: protocol.StreamStatus, Line: "two"})
		started <- job.JobID
		select {
		case <-release:
			return protocol.JobDone{OK: true, RebootRequired: true} // JobID deliberately unset
		case <-ctx.Done():
			return protocol.JobDone{OK: false, ExitCode: -1, Error: "cancelled"}
		}
	}
	h.start(nil)
	c := h.hub.next()
	c.accept()

	if r := mustData[protocol.Result](t, c.rpc(protocol.TypeJobStart, "a", protocol.JobStart{JobID: "J1", Kind: protocol.JobAptUpdate})); !r.OK {
		t.Fatalf("J1 rejected: %+v", r)
	}
	for _, line := range []string{"one", "two"} {
		o := mustData[protocol.JobOutput](t, c.recvType(protocol.TypeJobOutput))
		if o.JobID != "J1" || o.Line != line {
			t.Fatalf("output %+v", o)
		}
	}
	recvChan(t, started, "job running")

	// A second job while one runs is rejected.
	if r := mustData[protocol.Result](t, c.rpc(protocol.TypeJobStart, "b", protocol.JobStart{JobID: "J2", Kind: protocol.JobAptUpdate})); r.OK || r.Error == "" {
		t.Fatalf("J2 accepted: %+v", r)
	}
	// Cancelling an unknown job fails, the running one succeeds.
	if r := mustData[protocol.Result](t, c.rpc(protocol.TypeJobCancel, "c", protocol.JobCancel{JobID: "nope"})); r.OK {
		t.Fatalf("cancel of unknown job succeeded")
	}
	if r := mustData[protocol.Result](t, c.rpc(protocol.TypeJobCancel, "d", protocol.JobCancel{JobID: "J1"})); !r.OK {
		t.Fatalf("cancel failed: %+v", r)
	}
	done := mustData[protocol.JobDone](t, c.recvType(protocol.TypeJobDone))
	if done.JobID != "J1" || done.OK || done.Error != "cancelled" {
		t.Fatalf("done %+v", done)
	}

	// The slot is free again; a completing job yields exactly one job.done.
	close(release)
	if r := mustData[protocol.Result](t, c.rpc(protocol.TypeJobStart, "e", protocol.JobStart{JobID: "J3", Kind: protocol.JobPkgInstall, Package: "htop"})); !r.OK {
		t.Fatalf("J3 rejected: %+v", r)
	}
	c.recvType(protocol.TypeJobOutput)
	c.recvType(protocol.TypeJobOutput)
	done = mustData[protocol.JobDone](t, c.recvType(protocol.TypeJobDone))
	if done.JobID != "J3" || !done.OK || !done.RebootRequired {
		t.Fatalf("done %+v", done)
	}
	// Nothing else (in particular no second job.done) may follow.
	env := c.rpc("sync.ping", "z", nil)
	if env.Type != protocol.TypeError || env.ID != "z" {
		t.Fatalf("unexpected message after job.done: %s %s", env.Type, env.Data)
	}
}

func TestJobStartValidation(t *testing.T) {
	h := newHarness(t, nil)
	h.packages.run = func(context.Context, protocol.JobStart, func(protocol.JobOutput)) protocol.JobDone {
		t.Error("job must not run")
		return protocol.JobDone{}
	}
	h.start(nil)
	c := h.hub.next()
	c.accept()
	for _, js := range []protocol.JobStart{
		{JobID: "", Kind: protocol.JobAptUpdate},
		{JobID: "j", Kind: "rm_rf"},
		{JobID: "j", Kind: protocol.JobPkgInstall},
	} {
		if r := mustData[protocol.Result](t, c.rpc(protocol.TypeJobStart, "v", js)); r.OK {
			t.Errorf("%+v accepted", js)
		}
	}
}

func TestShellSessions(t *testing.T) {
	h := newHarness(t, nil)
	h.start(nil)
	c := h.hub.next()
	c.accept()

	open := func(id string, cols, rows int) protocol.Result {
		return mustData[protocol.Result](t, c.rpc(protocol.TypeShellOpen, "o-"+id, protocol.ShellOpen{SessionID: id, Cols: cols, Rows: rows}))
	}

	if r := open("s1", 0, 24); r.OK {
		t.Fatal("invalid size accepted")
	}
	if r := open("s1", 80, 24); !r.OK {
		t.Fatalf("open: %+v", r)
	}
	fs := recvChan(t, h.spawner.opened, "spawned session")
	if r := open("s1", 80, 24); r.OK {
		t.Fatal("duplicate session id accepted")
	}

	// hub -> agent
	c.send(protocol.TypeShellData, "", protocol.ShellData{SessionID: "s1", Data: []byte("ls\n")})
	if got := recvChan(t, fs.in, "shell input"); string(got) != "ls\n" {
		t.Fatalf("input %q", got)
	}
	c.send(protocol.TypeShellResize, "", protocol.ShellResize{SessionID: "s1", Cols: 100, Rows: 30})
	if got := recvChan(t, fs.resizes, "resize"); got != [2]int{100, 30} {
		t.Fatalf("resize %v", got)
	}

	// agent -> hub, chunked
	big := bytes.Repeat([]byte("x"), 70_000)
	fs.out <- big
	var total int
	for total < len(big) {
		d := mustData[protocol.ShellData](t, c.recvType(protocol.TypeShellData))
		if d.SessionID != "s1" || len(d.Data) == 0 || len(d.Data) > protocol.MaxShellChunk {
			t.Fatalf("chunk: session %q, %d bytes", d.SessionID, len(d.Data))
		}
		total += len(d.Data)
	}
	if total != len(big) {
		t.Fatalf("received %d bytes", total)
	}

	// Shell exits by itself: agent reports it and frees the slot.
	fs.exit()
	cl := mustData[protocol.ShellClose](t, c.recvType(protocol.TypeShellClose))
	if cl.SessionID != "s1" {
		t.Fatalf("close %+v", cl)
	}
	if n := h.sessions.Len(); n != 0 {
		t.Fatalf("slot not freed: %d sessions", n)
	}

	// Hub closes a session.
	if r := open("s1", 80, 24); !r.OK {
		t.Fatalf("reopen: %+v", r)
	}
	fs2 := recvChan(t, h.spawner.opened, "second session")
	c.send(protocol.TypeShellClose, "", protocol.ShellClose{SessionID: "s1"})
	recvChan(t, fs2.closed, "session closed")
	waitFor(t, "slot freed", func() bool { return h.sessions.Len() == 0 })

	// The session limit applies, and closing frees slots.
	for i := range shell.MaxSessions {
		if r := open("m"+string(rune('a'+i)), 80, 24); !r.OK {
			t.Fatalf("open %d: %+v", i, r)
		}
	}
	if r := open("over", 80, 24); r.OK {
		t.Fatal("limit not enforced")
	}
}

func TestGracefulShutdown(t *testing.T) {
	h := newHarness(t, nil)
	cancelled := make(chan struct{})
	h.packages.run = func(ctx context.Context, job protocol.JobStart, out func(protocol.JobOutput)) protocol.JobDone {
		<-ctx.Done()
		close(cancelled)
		return protocol.JobDone{OK: false}
	}
	h.start(nil)
	c := h.hub.next()
	c.accept()
	c.rpc(protocol.TypeJobStart, "j", protocol.JobStart{JobID: "J", Kind: protocol.JobAptUpdate})
	c.rpc(protocol.TypeShellOpen, "s", protocol.ShellOpen{SessionID: "s", Cols: 80, Rows: 24})
	fs := recvChan(t, h.spawner.opened, "session")

	h.cancel()
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	var err error
	for err == nil {
		_, _, err = c.c.Read(ctx)
	}
	if st := websocket.CloseStatus(err); st != websocket.StatusNormalClosure {
		t.Fatalf("close status %v (err %v)", st, err)
	}
	if err := h.stop(); err != nil {
		t.Fatalf("Run: %v", err)
	}
	recvChan(t, cancelled, "job cancelled")
	recvChan(t, fs.closed, "shell closed")
	if h.sessions.Len() != 0 {
		t.Fatal("sessions left")
	}
	select {
	case code := <-h.exits:
		t.Fatalf("Exit(%d) called on plain shutdown", code)
	default:
	}
}

// ---- self-update ----

type fakeHubHTTP struct {
	body   []byte
	status int
	reqs   chan string
}

func (f *fakeHubHTTP) RoundTrip(r *http.Request) (*http.Response, error) {
	f.reqs <- r.URL.String()
	status := f.status
	if status == 0 {
		status = http.StatusOK
	}
	return &http.Response{
		StatusCode: status, Status: http.StatusText(status), Body: io.NopCloser(bytes.NewReader(f.body)),
		Header: http.Header{}, Request: r,
	}, nil
}

func sum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func updateHarness(t *testing.T, transport *fakeHubHTTP) (*harness, string) {
	h := newHarness(t, nil)
	dir := t.TempDir()
	bin := filepath.Join(dir, "grid-agent")
	if err := os.WriteFile(bin, []byte("old-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.httpClient = &http.Client{Transport: transport}
	h.start(func(o *Options) { o.BinaryPath = bin })
	return h, bin
}

func dirEntries(t *testing.T, path string) int {
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

func TestAgentUpdateSuccess(t *testing.T) {
	newBin := []byte("new-binary-contents")
	tr := &fakeHubHTTP{body: newBin, reqs: make(chan string, 4)}
	h, bin := updateHarness(t, tr)
	c := h.hub.next()
	c.accept()

	env := c.rpc(protocol.TypeAgentUpdate, "u", protocol.AgentUpdate{Version: "9.9.9", SHA256: sum(newBin), Path: "/grid/agent/linux/arm64"})
	if r := mustData[protocol.Result](t, env); !r.OK {
		t.Fatalf("update rejected: %+v", r)
	}
	c.drain()
	if got := recvChan(t, tr.reqs, "download"); got != "https://hub.test:8443/grid/agent/linux/arm64" {
		t.Fatalf("downloaded %s", got)
	}
	select {
	case err := <-h.done:
		h.done <- err
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(testTimeout):
		t.Fatal("agent did not shut down after the update")
	}
	if code := recvChan(t, h.exits, "Exit"); code != 0 {
		t.Fatalf("Exit(%d)", code)
	}
	got, err := os.ReadFile(bin)
	if err != nil || !bytes.Equal(got, newBin) {
		t.Fatalf("binary = %q, %v", got, err)
	}
	if goruntime.GOOS != "windows" {
		if fi, _ := os.Stat(bin); fi.Mode().Perm() != 0o755 {
			t.Errorf("mode %v", fi.Mode())
		}
	}
	if n := dirEntries(t, bin); n != 1 {
		t.Errorf("%d files left in the binary directory", n)
	}
}

func TestAgentUpdateFailureKeepsOldBinary(t *testing.T) {
	good := []byte("new-binary-contents")
	tests := []struct {
		name   string
		status int
		sha    string
	}{
		{"wrong checksum", 0, sum([]byte("something else"))},
		{"http error", http.StatusNotFound, sum(good)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := &fakeHubHTTP{body: good, status: tt.status, reqs: make(chan string, 4)}
			h, bin := updateHarness(t, tr)
			c := h.hub.next()
			c.accept()
			env := c.rpc(protocol.TypeAgentUpdate, "u", protocol.AgentUpdate{Version: "9", SHA256: tt.sha, Path: "/grid/agent/linux/arm64"})
			if r := mustData[protocol.Result](t, env); !r.OK {
				t.Fatalf("update rejected: %+v", r)
			}
			recvChan(t, tr.reqs, "download")
			waitFor(t, "failure log", func() bool { return strings.Contains(h.logs.String(), "agent update failed") })

			c.sync() // still connected and serving
			c.drain()
			if got, _ := os.ReadFile(bin); string(got) != "old-binary" {
				t.Fatalf("binary replaced: %q", got)
			}
			if n := dirEntries(t, bin); n != 1 {
				t.Errorf("%d files left in the binary directory", n)
			}
			if err := h.stop(); err != nil {
				t.Fatal(err)
			}
			select {
			case code := <-h.exits:
				t.Fatalf("Exit(%d) after failed update", code)
			default:
			}
		})
	}
}

func TestAgentUpdateRejectsBadRequests(t *testing.T) {
	tr := &fakeHubHTTP{body: []byte("x"), reqs: make(chan string, 4)}
	h, _ := updateHarness(t, tr)
	c := h.hub.next()
	c.accept()
	for _, up := range []protocol.AgentUpdate{
		{Version: "1", SHA256: "abc", Path: "/grid/agent/linux/arm64"},
		{Version: "1", SHA256: sum([]byte("x")), Path: "/etc/passwd"},
		{Version: "1", SHA256: sum([]byte("x")), Path: "/grid/agent/../../etc/passwd"},
	} {
		if r := mustData[protocol.Result](t, c.rpc(protocol.TypeAgentUpdate, "u", up)); r.OK {
			t.Errorf("%+v accepted", up)
		}
	}
	select {
	case u := <-tr.reqs:
		t.Fatalf("unexpected download %s", u)
	default:
	}
}

func TestUpdateRequiredAcceptsOnlyUpdate(t *testing.T) {
	newBin := []byte("fresh")
	tr := &fakeHubHTTP{body: newBin, reqs: make(chan string, 4)}
	h, bin := updateHarness(t, tr)
	c := h.hub.next()
	c.handshake(protocol.HelloAck{Accepted: false, Reason: "too old", UpdateRequired: true, TargetVersion: "2.0.0"})

	// Regular requests are ignored while the agent is not accepted.
	c.send(protocol.TypeServicesList, "ignored", nil)
	env := c.rpc(protocol.TypeAgentUpdate, "u", protocol.AgentUpdate{Version: "2.0.0", SHA256: sum(newBin), Path: "/grid/agent/linux/arm64"})
	if r := mustData[protocol.Result](t, env); !r.OK {
		t.Fatalf("update rejected: %+v", r)
	}
	c.drain()
	if code := recvChan(t, h.exits, "Exit"); code != 0 {
		t.Fatalf("Exit(%d)", code)
	}
	if got, _ := os.ReadFile(bin); !bytes.Equal(got, newBin) {
		t.Fatalf("binary = %q", got)
	}
	if !strings.Contains(h.logs.String(), "update required") {
		t.Errorf("update_required not logged clearly:\n%s", h.logs.String())
	}
}

func TestHubOrigin(t *testing.T) {
	tests := []struct{ in, want string }{
		{"wss://frpi5.local:8443/grid/connect", "https://frpi5.local:8443"},
		{"wss://10.0.0.5/grid/connect", "https://10.0.0.5"},
	}
	for _, tt := range tests {
		if got, err := hubOrigin(tt.in); err != nil || got != tt.want {
			t.Errorf("hubOrigin(%q) = %q, %v", tt.in, got, err)
		}
	}
}

func TestSafeMessage(t *testing.T) {
	if got := safeMessage(errors.New("first\nsecond")); got != "first" {
		t.Errorf("got %q", got)
	}
	if got := safeMessage(errors.New(strings.Repeat("Ã©", 300))); len([]rune(got)) != 203 {
		t.Errorf("len %d", len([]rune(got)))
	}
}
