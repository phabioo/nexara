package demo

import (
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/protocol"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

var clockStart = time.Date(2026, 9, 30, 21, 14, 7, 0, time.UTC)

// newHub returns a hub with a fake clock and compressed delays. scale 0.001
// turns the 150 ms job line pacing into 150 µs.
func newHub(t *testing.T, scale float64) (*Hub, *fakeClock) {
	t.Helper()
	clk := &fakeClock{t: clockStart}
	h := New(Options{Now: clk.Now, Rand: rand.New(rand.NewPCG(1, 2)), TimeScale: scale})
	t.Cleanup(h.Close)
	return h, clk
}

func sub(t *testing.T, h *Hub) <-chan grid.Event {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return h.Subscribe(ctx)
}

// waitFor returns the first event satisfying pred, collecting all seen events.
func waitFor(t *testing.T, ch <-chan grid.Event, pred func(grid.Event) bool) (grid.Event, []grid.Event) {
	t.Helper()
	var seen []grid.Event
	timeout := time.After(10 * time.Second)
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				t.Fatalf("event channel closed; seen %d events", len(seen))
			}
			seen = append(seen, ev)
			if pred(ev) {
				return ev, seen
			}
		case <-timeout:
			t.Fatalf("timed out waiting for event; seen %d events", len(seen))
		}
	}
}

func kind(k grid.EventKind) func(grid.Event) bool {
	return func(e grid.Event) bool { return e.Kind == k }
}

func jobDone(id string) func(grid.Event) bool {
	return func(e grid.Event) bool {
		j, ok := e.Payload.(grid.Job)
		return e.Kind == grid.EventJobDone && ok && j.ID == id
	}
}

func byName(t *testing.T, h *Hub, name string) grid.HostInfo {
	t.Helper()
	for _, i := range h.Hosts() {
		if i.Name == name {
			return i
		}
	}
	t.Fatalf("host %q not found", name)
	return grid.HostInfo{}
}

func countState(p *protocol.Packages, st protocol.PackageState) int {
	n := 0
	for _, it := range p.Items {
		if it.State == st {
			n++
		}
	}
	return n
}

func TestInitialData(t *testing.T) {
	h, _ := newHub(t, 0.001)
	hosts := h.Hosts()
	if len(hosts) != 3 {
		t.Fatalf("hosts = %d, want 3", len(hosts))
	}
	pi5, pi3, pi4 := hosts[0], hosts[1], hosts[2]
	if pi5.Name != "pi5-media" || !pi5.Online || pi5.Address != "192.168.10.21" || pi5.Latency != 4*time.Millisecond {
		t.Errorf("pi5 = %+v", pi5)
	}
	if pi3.Name != "pi3-dns" || !pi3.Online {
		t.Errorf("pi3 = %+v", pi3)
	}
	if pi4.Name != "pi4" || pi4.Online || !pi4.LastSeen.IsZero() || pi4.Model != "" {
		t.Errorf("pi4 = %+v", pi4)
	}

	s, ok := h.Snapshot(pi5.ID)
	if !ok || s.Metrics == nil || s.Packages == nil || s.Services == nil {
		t.Fatalf("pi5 snapshot incomplete: %+v", s)
	}
	if n := len(s.Packages.Items); n != 12 {
		t.Errorf("packages = %d, want 12", n)
	}
	if n := countState(s.Packages, protocol.PackageUpdate); n != 3 {
		t.Errorf("updates = %d, want 3", n)
	}
	if n := countState(s.Packages, protocol.PackageOrphaned); n != 2 {
		t.Errorf("orphans = %d, want 2", n)
	}
	if n := countState(s.Packages, protocol.PackageInstalled); n != 7 {
		t.Errorf("installed = %d, want 7", n)
	}
	if n := countState(s.Packages, protocol.PackageAvailable); n != 0 {
		t.Errorf("available = %d, want 0", n)
	}
	if n := len(s.Services.Units); n != 6 {
		t.Errorf("services = %d, want 6", n)
	}
	failed := 0
	for _, u := range s.Services.Units {
		if u.ActiveState == "failed" {
			failed++
			if u.Name != "smbd.service" {
				t.Errorf("failed unit = %s", u.Name)
			}
		}
	}
	if failed != 1 {
		t.Errorf("failed units = %d, want 1", failed)
	}
	if got := s.Metrics.CPUPerCore; len(got) != 4 || got[0] != 28 || got[1] != 20 || got[2] != 25 || got[3] != 22 {
		t.Errorf("cores = %v", got)
	}
	if len(s.CPUHistory) != historyLen {
		t.Errorf("history = %d, want %d", len(s.CPUHistory), historyLen)
	}
	if s.Metrics.MemUsed != gbytes(3.4) || s.Metrics.MemTotal != 8*gib || len(s.Metrics.Disks) != 2 {
		t.Errorf("memory/disks = %+v", s.Metrics)
	}
	if up := s.Metrics.UptimeSeconds; up != 41*86400+6*3600+2*60 {
		t.Errorf("uptime = %d", up)
	}

	s3, _ := h.Snapshot(pi3.ID)
	if n := countState(s3.Packages, protocol.PackageUpdate); n != 2 {
		t.Errorf("pi3 updates = %d, want 2", n)
	}
	s4, ok := h.Snapshot(pi4.ID)
	if !ok || s4.Metrics != nil || s4.Services != nil || s4.Packages != nil {
		t.Errorf("pi4 snapshot = %+v", s4)
	}
	if _, ok := h.Snapshot("nope"); ok {
		t.Error("snapshot of unknown host")
	}
	if _, ok := h.Host("nope"); ok {
		t.Error("unknown host found")
	}
}

func TestSnapshotReturnsCopies(t *testing.T) {
	h, _ := newHub(t, 0.001)
	id := h.Hosts()[0].ID
	s, _ := h.Snapshot(id)
	s.Packages.Items[0].Name = "changed"
	s.Services.Units[0].Name = "changed"
	s.Metrics.CPUPerCore[0] = -1
	s.CPUHistory[0] = -1
	s.Host.Capabilities[0] = "changed"
	infos := h.Hosts()
	infos[0].Capabilities[0] = "changed"

	s2, _ := h.Snapshot(id)
	if s2.Packages.Items[0].Name == "changed" || s2.Services.Units[0].Name == "changed" ||
		s2.Metrics.CPUPerCore[0] == -1 || s2.CPUHistory[0] == -1 || s2.Host.Capabilities[0] == "changed" {
		t.Error("mutating a snapshot changed hub state")
	}
}

func TestMetricsTick(t *testing.T) {
	h, clk := newHub(t, 0.001)
	ch := sub(t, h)
	pi5 := byName(t, h, "pi5-media")
	before, _ := h.Snapshot(pi5.ID)

	clk.Advance(2 * time.Second)
	h.step()

	got := map[grid.HostID]protocol.Metrics{}
	for i := 0; i < 2; i++ {
		ev := <-ch
		if ev.Kind != grid.EventMetrics {
			t.Fatalf("event = %s", ev.Kind)
		}
		got[ev.Host] = ev.Payload.(protocol.Metrics)
	}
	if _, ok := got[byName(t, h, "pi4").ID]; ok {
		t.Error("offline host emitted metrics")
	}
	m := got[pi5.ID]
	if !m.Timestamp.Equal(clockStart.Add(2 * time.Second)) {
		t.Errorf("timestamp = %v", m.Timestamp)
	}
	if m.UptimeSeconds != before.Metrics.UptimeSeconds+2 {
		t.Errorf("uptime = %d, want %d", m.UptimeSeconds, before.Metrics.UptimeSeconds+2)
	}

	for i := 0; i < 200; i++ {
		clk.Advance(2 * time.Second)
		h.step()
		s, _ := h.Snapshot(pi5.ID)
		if len(s.CPUHistory) > historyLen {
			t.Fatalf("history grew to %d", len(s.CPUHistory))
		}
		mm := s.Metrics
		if mm.CPUPercent < 0 || mm.CPUPercent > 100 {
			t.Fatalf("cpu = %v", mm.CPUPercent)
		}
		if mm.CPUPercent > 60 || *mm.TempC < 35 || *mm.TempC > 60 {
			t.Fatalf("values left the plausible band: cpu %.1f temp %.1f", mm.CPUPercent, *mm.TempC)
		}
		if mm.MemUsed > mm.MemTotal {
			t.Fatalf("memory %d > %d", mm.MemUsed, mm.MemTotal)
		}
		for i := 1; i < len(mm.TopProcesses); i++ {
			if mm.TopProcesses[i].CPU > mm.TopProcesses[i-1].CPU {
				t.Fatalf("processes not sorted: %+v", mm.TopProcesses)
			}
		}
	}
	s, _ := h.Snapshot(pi5.ID)
	if len(s.CPUHistory) != historyLen {
		t.Errorf("history = %d", len(s.CPUHistory))
	}
	if !byName(t, h, "pi5-media").LastSeen.Equal(clk.Now()) {
		t.Error("LastSeen not updated")
	}
}

func TestStartRunsTicks(t *testing.T) {
	ticks := make(chan time.Time)
	h := New(Options{Ticks: ticks, Rand: rand.New(rand.NewPCG(3, 4))})
	ch := sub(t, h)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.Start(ctx); close(done) }()

	ticks <- time.Now()
	waitFor(t, ch, kind(grid.EventMetrics))
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return")
	}
}

func TestSubscribeCleanup(t *testing.T) {
	h, _ := newHub(t, 0.001)
	ctx, cancel := context.WithCancel(context.Background())
	ch := h.Subscribe(ctx)
	cancel()
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("unexpected event")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("channel not closed")
	}
	h.mu.Lock()
	n := len(h.subs)
	h.mu.Unlock()
	if n != 0 {
		t.Errorf("subscribers left: %d", n)
	}
}

func TestSubscribeBoundedBuffer(t *testing.T) {
	h, _ := newHub(t, 0.001)
	ch := sub(t, h)
	for i := 0; i < subscriberBuf+50; i++ {
		h.step() // nobody reads: must not block
	}
	if len(ch) != subscriberBuf {
		t.Errorf("buffered = %d, want %d", len(ch), subscriberBuf)
	}
}

func TestRestartService(t *testing.T) {
	h, _ := newHub(t, 0.001)
	ch := sub(t, h)
	pi5 := byName(t, h, "pi5-media").ID

	if err := h.RestartService(context.Background(), grid.Actor{}, pi5, "smbd"); err != nil {
		t.Fatal(err)
	}
	ev, _ := waitFor(t, ch, func(e grid.Event) bool {
		if e.Kind != grid.EventServices {
			return false
		}
		for _, u := range e.Payload.(protocol.Services).Units {
			if u.Name == "smbd.service" && u.ActiveState == "active" {
				return true
			}
		}
		return false
	})
	for _, u := range ev.Payload.(protocol.Services).Units {
		if u.Name == "smbd.service" && u.SubState != "running" {
			t.Errorf("smbd substate = %s", u.SubState)
		}
	}
	s, _ := h.Snapshot(pi5)
	for _, u := range s.Services.Units {
		if u.ActiveState != "active" {
			t.Errorf("%s is %s", u.Name, u.ActiveState)
		}
	}

	tests := []struct {
		name string
		id   grid.HostID
		unit string
		want error
	}{
		{"empty", pi5, "", grid.ErrInvalidArgument},
		{"shell chars", pi5, "ssh; rm -rf /", grid.ErrInvalidArgument},
		{"leading dash", pi5, "--now", grid.ErrInvalidArgument},
		{"unknown unit", pi5, "nosuch", grid.ErrInvalidArgument},
		{"offline", byName(t, h, "pi4").ID, "ssh", grid.ErrHostOffline},
		{"no host", "nope", "ssh", grid.ErrHostNotFound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := h.RestartService(context.Background(), grid.Actor{}, tc.id, tc.unit); !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
	if err := h.RestartService(context.Background(), grid.Actor{}, pi5, "ssh.service"); err != nil {
		t.Errorf("full unit name: %v", err)
	}
}

func TestRefreshAndUpdateAgent(t *testing.T) {
	h, _ := newHub(t, 0.001)
	ch := sub(t, h)
	pi5 := byName(t, h, "pi5-media").ID
	pi4 := byName(t, h, "pi4").ID
	ctx := context.Background()

	if err := h.RefreshServices(ctx, pi5); err != nil {
		t.Fatal(err)
	}
	if err := h.RefreshPackages(ctx, pi5); err != nil {
		t.Fatal(err)
	}
	waitFor(t, ch, kind(grid.EventServices))
	waitFor(t, ch, kind(grid.EventPackages))
	if err := h.RefreshServices(ctx, pi4); !errors.Is(err, grid.ErrHostOffline) {
		t.Errorf("err = %v", err)
	}
	if err := h.RefreshPackages(ctx, "x"); !errors.Is(err, grid.ErrHostNotFound) {
		t.Errorf("err = %v", err)
	}
	if err := h.UpdateAgent(ctx, grid.Actor{}, pi5); err != nil {
		t.Error(err)
	}
	if err := h.UpdateAgent(ctx, grid.Actor{}, pi4); !errors.Is(err, grid.ErrHostOffline) {
		t.Errorf("err = %v", err)
	}
	if err := h.UpdateAgent(ctx, grid.Actor{}, "x"); !errors.Is(err, grid.ErrHostNotFound) {
		t.Errorf("err = %v", err)
	}
}

func TestJobUpgradeLifecycle(t *testing.T) {
	h, clk := newHub(t, 0.001)
	ch := sub(t, h)
	pi5 := byName(t, h, "pi5-media").ID
	ctx := context.Background()
	actor := grid.Actor{Operator: "op1"}

	j, err := h.StartJob(ctx, actor, pi5, grid.JobSpec{Kind: protocol.JobAptUpgrade})
	if err != nil {
		t.Fatal(err)
	}
	if j.State != grid.JobRunning || j.RequestedBy != "op1" || !j.QueuedAt.Equal(clk.Now()) {
		t.Errorf("job = %+v", j)
	}
	done, seen := waitFor(t, ch, jobDone(j.ID))
	fin := done.Payload.(grid.Job)
	if fin.State != grid.JobDone || !fin.OK || !fin.RebootRequired || fin.FinishedAt.IsZero() {
		t.Errorf("finished = %+v", fin)
	}
	if seen[0].Kind != grid.EventJobQueued {
		t.Errorf("first event = %s", seen[0].Kind)
	}
	if st, ok := seen[1].Payload.(grid.Job); seen[1].Kind != grid.EventJobStarted || !ok || st.ID != j.ID || st.State != grid.JobRunning || st.StartedAt.IsZero() {
		t.Errorf("second event = %+v", seen[1])
	}

	var lines []grid.JobLine
	for _, e := range seen {
		if e.Kind == grid.EventJobOutput {
			lines = append(lines, e.Payload.(grid.JobOutputEvent).Line)
		}
	}
	if len(lines) != len(fin.Output) {
		t.Errorf("streamed %d lines, retained %d", len(lines), len(fin.Output))
	}
	text := ""
	for _, l := range lines {
		text += l.Line + "\n"
	}
	for _, want := range []string{"Reading package lists... Done", "Get:1 ", "Unpacking openssh-server (1:9.2p1-2+deb12u4) ...", "Setting up ffmpeg (7:5.1.7-0+deb12u1) ...", "linux-image-rpi-v8"} {
		if !strings.Contains(text, want) {
			t.Errorf("output lacks %q:\n%s", want, text)
		}
	}
	if lines[0].Stream != protocol.StreamStatus || !strings.Contains(lines[0].Line, "Waiting for dpkg lock") {
		t.Errorf("first line = %+v", lines[0])
	}

	s, _ := h.Snapshot(pi5)
	if n := countState(s.Packages, protocol.PackageUpdate); n != 0 {
		t.Errorf("updates left = %d", n)
	}
	if !s.Packages.RebootRequired || !s.Host.RebootRequired {
		t.Error("reboot not required after kernel update")
	}
	if len(s.Jobs) != 0 {
		t.Errorf("finished job in snapshot jobs: %+v", s.Jobs)
	}
	if jobs := h.Jobs(pi5); len(jobs) != 1 || jobs[0].ID != j.ID {
		t.Errorf("Jobs = %+v", jobs)
	}
}

func TestJobPackageChanges(t *testing.T) {
	h, _ := newHub(t, 0.001)
	ch := sub(t, h)
	pi5 := byName(t, h, "pi5-media").ID
	ctx := context.Background()

	run := func(spec grid.JobSpec) grid.Job {
		t.Helper()
		j, err := h.StartJob(ctx, grid.Actor{}, pi5, spec)
		if err != nil {
			t.Fatal(err)
		}
		ev, _ := waitFor(t, ch, jobDone(j.ID))
		return ev.Payload.(grid.Job)
	}
	pkgs := func() *protocol.Packages { s, _ := h.Snapshot(pi5); return s.Packages }

	if j := run(grid.JobSpec{Kind: protocol.JobAptClean}); !j.OK {
		t.Errorf("clean: %+v", j)
	}
	if p := pkgs(); len(p.Items) != 10 || countState(p, protocol.PackageOrphaned) != 0 {
		t.Errorf("after clean: %d items", len(p.Items))
	}

	if j := run(grid.JobSpec{Kind: protocol.JobPkgInstall, Package: "neofetch"}); !j.OK {
		t.Errorf("install: %+v", j)
	}
	p := pkgs()
	if len(p.Items) != 11 || p.Items[10].Name != "neofetch" || p.Items[10].State != protocol.PackageInstalled || p.Items[10].InstalledVersion == "" {
		t.Errorf("after install: %+v", p.Items)
	}

	if j := run(grid.JobSpec{Kind: protocol.JobPkgUpgrade, Package: "ffmpeg"}); !j.OK || j.RebootRequired {
		t.Errorf("upgrade ffmpeg: %+v", j)
	}
	p = pkgs()
	if countState(p, protocol.PackageUpdate) != 2 || p.RebootRequired {
		t.Errorf("after single upgrade: %d updates, reboot %v", countState(p, protocol.PackageUpdate), p.RebootRequired)
	}

	if j := run(grid.JobSpec{Kind: protocol.JobPkgRemove, Package: "neofetch"}); !j.OK {
		t.Errorf("remove: %+v", j)
	}
	if p := pkgs(); len(p.Items) != 10 {
		t.Errorf("after remove: %d items", len(p.Items))
	}

	run(grid.JobSpec{Kind: protocol.JobAptUpdate})
	if len(pkgs().Items) != 10 {
		t.Error("apt update changed the list")
	}
}

func TestStartJobValidation(t *testing.T) {
	h, _ := newHub(t, 0.001)
	pi5 := byName(t, h, "pi5-media").ID
	tests := []struct {
		name string
		id   grid.HostID
		spec grid.JobSpec
		want error
	}{
		{"bad kind", pi5, grid.JobSpec{Kind: "rm_rf"}, grid.ErrInvalidArgument},
		{"pkg kind without package", pi5, grid.JobSpec{Kind: protocol.JobPkgInstall}, grid.ErrInvalidArgument},
		{"apt kind with package", pi5, grid.JobSpec{Kind: protocol.JobAptUpdate, Package: "curl"}, grid.ErrInvalidArgument},
		{"bad package name", pi5, grid.JobSpec{Kind: protocol.JobPkgInstall, Package: "a;b"}, grid.ErrInvalidArgument},
		{"remove not installed", pi5, grid.JobSpec{Kind: protocol.JobPkgRemove, Package: "tmux"}, grid.ErrInvalidArgument},
		{"offline", byName(t, h, "pi4").ID, grid.JobSpec{Kind: protocol.JobAptUpdate}, grid.ErrHostOffline},
		{"unknown host", "nope", grid.JobSpec{Kind: protocol.JobAptUpdate}, grid.ErrHostNotFound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := h.StartJob(context.Background(), grid.Actor{}, tc.id, tc.spec); !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestJobQueueBusyAndCancel(t *testing.T) {
	// Real line pacing (150 ms) keeps the first job running while we queue and cancel.
	h, _ := newHub(t, 1)
	ch := sub(t, h)
	pi5 := byName(t, h, "pi5-media").ID
	ctx := context.Background()

	first, err := h.StartJob(ctx, grid.Actor{}, pi5, grid.JobSpec{Kind: protocol.JobAptUpgrade})
	if err != nil || first.State != grid.JobRunning {
		t.Fatalf("first = %+v, %v", first, err)
	}
	if _, err := h.StartJob(ctx, grid.Actor{}, pi5, grid.JobSpec{Kind: protocol.JobAptUpgrade}); !errors.Is(err, grid.ErrJobBusy) {
		t.Errorf("duplicate err = %v", err)
	}
	second, err := h.StartJob(ctx, grid.Actor{}, pi5, grid.JobSpec{Kind: protocol.JobAptClean})
	if err != nil || second.State != grid.JobQueued {
		t.Fatalf("second = %+v, %v", second, err)
	}
	third, err := h.StartJob(ctx, grid.Actor{}, pi5, grid.JobSpec{Kind: protocol.JobAptUpdate})
	if err != nil || third.State != grid.JobQueued {
		t.Fatalf("third = %+v, %v", third, err)
	}
	if s, _ := h.Snapshot(pi5); len(s.Jobs) != 3 || s.Jobs[0].ID != first.ID {
		t.Errorf("snapshot jobs = %+v", s.Jobs)
	}

	// Cancel the queued one: immediate.
	if err := h.CancelJob(ctx, grid.Actor{}, second.ID); err != nil {
		t.Fatal(err)
	}
	ev, _ := waitFor(t, ch, jobDone(second.ID))
	if st := ev.Payload.(grid.Job).State; st != grid.JobCanceled {
		t.Errorf("queued job state = %s", st)
	}
	if err := h.CancelJob(ctx, grid.Actor{}, second.ID); !errors.Is(err, grid.ErrJobFinished) {
		t.Errorf("err = %v", err)
	}

	// Cancel the running one: the next queued job (third) then runs.
	if err := h.CancelJob(ctx, grid.Actor{}, first.ID); err != nil {
		t.Fatal(err)
	}
	ev, _ = waitFor(t, ch, jobDone(first.ID))
	if j := ev.Payload.(grid.Job); j.State != grid.JobCanceled || j.OK || j.Error == "" {
		t.Errorf("running job after cancel = %+v", j)
	}
	// A queued job only announces itself as started once its predecessor ended.
	waitFor(t, ch, func(e grid.Event) bool {
		j, ok := e.Payload.(grid.Job)
		return e.Kind == grid.EventJobStarted && ok && j.ID == third.ID && j.State == grid.JobRunning
	})
	ev, _ = waitFor(t, ch, jobDone(third.ID))
	if j := ev.Payload.(grid.Job); j.State != grid.JobDone {
		t.Errorf("third = %+v", j)
	}
	// The canceled upgrade left the package list untouched.
	if s, _ := h.Snapshot(pi5); countState(s.Packages, protocol.PackageUpdate) != 3 {
		t.Error("canceled upgrade changed packages")
	}
	if err := h.CancelJob(ctx, grid.Actor{}, "job-999999"); !errors.Is(err, grid.ErrJobNotFound) {
		t.Errorf("err = %v", err)
	}
	jobs := h.Jobs(pi5)
	if len(jobs) != 3 || jobs[0].ID != third.ID {
		t.Errorf("Jobs order = %+v", jobs)
	}
	if h.Jobs("nope") != nil {
		t.Error("Jobs of unknown host not nil")
	}
}

func TestSearchPackages(t *testing.T) {
	h, _ := newHub(t, 0.001)
	pi5 := byName(t, h, "pi5-media").ID
	ctx := context.Background()

	res, err := h.SearchPackages(ctx, pi5, "  NEO ")
	if err != nil || len(res) != 1 || res[0].Name != "neofetch" || res[0].State != protocol.PackageAvailable {
		t.Errorf("neo = %+v, %v", res, err)
	}
	res, _ = h.SearchPackages(ctx, pi5, "ssh")
	if len(res) != 1 || res[0].Name != "openssh-server" || res[0].State != protocol.PackageUpdate {
		t.Errorf("ssh = %+v", res)
	}
	for _, n := range []string{"btop", "tmux", "ncdu"} {
		if res, _ := h.SearchPackages(ctx, pi5, n); len(res) != 1 || res[0].Name != n {
			t.Errorf("%s = %+v", n, res)
		}
	}
	if res, _ := h.SearchPackages(ctx, pi5, "zzzz"); len(res) != 0 {
		t.Errorf("zzzz = %+v", res)
	}
	for _, q := range []string{"", "   ", "a b", "x;y", strings.Repeat("a", 65)} {
		if _, err := h.SearchPackages(ctx, pi5, q); !errors.Is(err, grid.ErrInvalidArgument) {
			t.Errorf("query %q: err = %v", q, err)
		}
	}
	if _, err := h.SearchPackages(ctx, byName(t, h, "pi4").ID, "tmux"); !errors.Is(err, grid.ErrHostOffline) {
		t.Errorf("err = %v", err)
	}
	if _, err := h.SearchPackages(ctx, "nope", "tmux"); !errors.Is(err, grid.ErrHostNotFound) {
		t.Errorf("err = %v", err)
	}
}

// readUntil reads from the session until the output contains want.
func readUntil(t *testing.T, s grid.ShellSession, want string) string {
	t.Helper()
	var sb strings.Builder
	buf := make([]byte, 4096)
	for !strings.Contains(sb.String(), want) {
		n, err := s.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			t.Fatalf("read: %v; got %q, want %q", err, sb.String(), want)
		}
	}
	return sb.String()
}

func TestShell(t *testing.T) {
	h, _ := newHub(t, 0.001)
	pi5 := byName(t, h, "pi5-media").ID
	sh, err := h.OpenShell(context.Background(), grid.Actor{}, pi5, 120, 30)
	if err != nil {
		t.Fatal(err)
	}
	defer sh.Close()

	// Like a real agent: no banner, the first output is the prompt.
	if first := readUntil(t, sh, "pi@pi5-media:~ $ "); first != "pi@pi5-media:~ $ " {
		t.Errorf("first output = %q, want the prompt only", first)
	}
	if err := sh.Resize(80, 24); err != nil {
		t.Error(err)
	}

	send := func(in, want string) string {
		t.Helper()
		if _, err := sh.Write([]byte(in)); err != nil {
			t.Fatal(err)
		}
		return readUntil(t, sh, want)
	}
	if got := send("uptime\r", "load average: 0.42, 0.38, 0.35"); !strings.Contains(got, "uptime\r\n") || !strings.Contains(got, "21:14:07 up 41 days,  6:02") {
		t.Errorf("uptime = %q", got)
	}
	if got := send("vcgencmd measure_temp\n", "temp=47.2'C"); !strings.Contains(got, "vcgencmd measure_temp") {
		t.Errorf("temp = %q", got)
	}
	send("hostname\r", "pi5-media\r\n")
	send("whoami\r", "pi\r\n")
	send("ls\r", "Documents")
	send("help\r", "Available:")
	send("clear\r", "\x1b[2J")
	send("frobnicate --now\r", "bash: frobnicate: command not found")

	// Backspace: type "lx", erase "x", type "s" -> "ls" runs.
	if got := send("lx\x7fs", "lx\x08 \x08s"); !strings.Contains(got, "\x08 \x08") {
		t.Errorf("backspace echo = %q", got)
	}
	send("\r", "Documents")
	// Escape sequences (arrow keys) are swallowed, ctrl-c resets the line.
	send("\x1b[Aabc\x03", "^C")
	send("\r", "$ ")

	// Exit ends the session with EOF after the output drained.
	if _, err := sh.Write([]byte("exit\r")); err != nil {
		t.Fatal(err)
	}
	readUntil(t, sh, "logout")
	if _, err := sh.Read(make([]byte, 16)); err != io.EOF {
		t.Errorf("read after exit = %v, want EOF", err)
	}
	if _, err := sh.Write([]byte("x")); err == nil {
		t.Error("write after exit succeeded")
	}
}

func TestShellCloseAndErrors(t *testing.T) {
	h, _ := newHub(t, 0.001)
	sh, err := h.OpenShell(context.Background(), grid.Actor{}, byName(t, h, "pi3-dns").ID, 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	readUntil(t, sh, "pi@pi3-dns:~ $ ")
	done := make(chan error, 1)
	go func() { _, err := sh.Read(make([]byte, 8)); done <- err }()
	time.Sleep(10 * time.Millisecond) // let the reader block; correctness does not depend on it
	sh.Close()
	select {
	case err := <-done:
		if err != nil && err != io.EOF {
			t.Errorf("err = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not unblock Read")
	}
	if _, err := sh.Write([]byte("x")); err == nil {
		t.Error("write after close succeeded")
	}
	if _, err := h.OpenShell(context.Background(), grid.Actor{}, byName(t, h, "pi4").ID, 80, 24); !errors.Is(err, grid.ErrHostOffline) {
		t.Errorf("err = %v", err)
	}
	if _, err := h.OpenShell(context.Background(), grid.Actor{}, "nope", 80, 24); !errors.Is(err, grid.ErrHostNotFound) {
		t.Errorf("err = %v", err)
	}
}

var codeRe = regexp.MustCompile(`^GRID-[A-Z0-9]{4}-[A-Z0-9]{4}$`)

func TestEnrollCode(t *testing.T) {
	h, clk := newHub(t, 0.001)
	ch := sub(t, h)
	ec, err := h.NewEnrollCode(context.Background(), grid.Actor{}, grid.EnrollOptions{Capabilities: []string{protocol.CapMonitoring, protocol.CapShell}})
	if err != nil {
		t.Fatal(err)
	}
	if !codeRe.MatchString(ec.Code) {
		t.Errorf("code = %q", ec.Code)
	}
	if !ec.Expires.Equal(clk.Now().Add(15 * time.Minute)) {
		t.Errorf("expires = %v", ec.Expires)
	}
	cmdRe := regexp.MustCompile(`^curl -fsSL --insecure --pinnedpubkey sha256//[A-Za-z0-9+/]{43}= https://\S+/grid/install\.sh \| sudo sh -s -- ` + ec.Code + `$`)
	if !cmdRe.MatchString(ec.Command) {
		t.Errorf("command = %q", ec.Command)
	}

	ev, seen := waitFor(t, ch, kind(grid.EventHostAdded))
	info := ev.Payload.(grid.HostInfo)
	if info.Name != "pi-new" || !info.Online {
		t.Errorf("added = %+v", info)
	}
	if info.HasCapability(protocol.CapPackages) || !info.HasCapability(protocol.CapShell) {
		t.Errorf("capabilities = %v", info.Capabilities)
	}
	if ev2, _ := waitFor(t, ch, kind(grid.EventHostOnline)); ev2.Host != info.ID {
		t.Error("online event for another host")
	}
	_ = seen
	if len(h.Hosts()) != 4 {
		t.Errorf("hosts = %d", len(h.Hosts()))
	}
	if s, ok := h.Snapshot(info.ID); !ok || s.Metrics == nil {
		t.Error("new host has no metrics")
	}
}

func TestEnrollCodeSuperseded(t *testing.T) {
	h, _ := newHub(t, 0.001)
	ch := sub(t, h)
	a, _ := h.NewEnrollCode(context.Background(), grid.Actor{}, grid.EnrollOptions{})
	b, _ := h.NewEnrollCode(context.Background(), grid.Actor{}, grid.EnrollOptions{})
	if a.Code == b.Code {
		t.Error("codes equal")
	}
	waitFor(t, ch, kind(grid.EventHostAdded))
	time.Sleep(100 * time.Millisecond) // a second host would have appeared by now (8 ms scaled)
	if n := len(h.Hosts()); n != 4 {
		t.Errorf("hosts = %d, want exactly one new host", n)
	}
}

func sshReq(addr string) grid.SSHLinkRequest {
	return grid.SSHLinkRequest{Address: addr, User: "pi", Password: "s3cret-pw"}
}

func TestLinkViaSSH(t *testing.T) {
	h, _ := newHub(t, 0.001)
	ch := sub(t, h)
	var steps []grid.LinkStep
	info, err := h.LinkViaSSH(context.Background(), grid.Actor{}, grid.SSHLinkRequest{
		Address: "192.168.10.77", User: "pi", DisplayName: "Pi Zero", UseHubKey: true,
	}, func(s grid.LinkStep) { steps = append(steps, s) })
	if err != nil {
		t.Fatal(err)
	}
	if info.Name != "pi-zero" || info.DisplayName != "Pi Zero" || info.Address != "192.168.10.77" || !info.Online {
		t.Errorf("info = %+v", info)
	}
	want := grid.LinkSteps()
	if len(steps) != 10 {
		t.Fatalf("steps = %+v", steps)
	}
	for i, name := range want {
		if steps[2*i].Step != name || steps[2*i].State != grid.LinkRunning || steps[2*i+1].Step != name || steps[2*i+1].State != grid.LinkDone {
			t.Errorf("step %d = %+v / %+v", i, steps[2*i], steps[2*i+1])
		}
	}
	details := map[grid.LinkStepName]string{}
	for _, s := range steps {
		if s.State == grid.LinkDone {
			details[s.Step] = s.Detail
		}
	}
	if !regexp.MustCompile(`^Connected as pi · Host key SHA256:[A-Za-z0-9+/]{43}$`).MatchString(details[grid.StepConnect]) {
		t.Errorf("connect detail = %q", details[grid.StepConnect])
	}
	if details[grid.StepDetect] != "Debian 12 · arm64" || details[grid.StepInstall] != "v0.1.0 · systemd unit" ||
		details[grid.StepEnroll] != "mTLS · valid 1 year · SSH closed" || details[grid.StepOnline] != "first sync running" {
		t.Errorf("details = %v", details)
	}
	waitFor(t, ch, kind(grid.EventHostAdded))
	if _, ok := h.Host(info.ID); !ok {
		t.Error("host not registered")
	}

	// Without display name the address gives the name.
	info2, err := h.LinkViaSSH(context.Background(), grid.Actor{}, sshReq("pi-zero2.local"), nil)
	if err != nil || info2.Name != "pi-zero2" || info2.DisplayName != "pi-zero2.local" {
		t.Errorf("info2 = %+v, %v", info2, err)
	}
}

func TestLinkViaSSHErrors(t *testing.T) {
	h, _ := newHub(t, 0.001)
	ctx := context.Background()

	var steps []grid.LinkStep
	_, err := h.LinkViaSSH(ctx, grid.Actor{}, sshReq("FAIL.local"), func(s grid.LinkStep) { steps = append(steps, s) })
	if !errors.Is(err, grid.ErrLinkFailed) {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "s3cret") {
		t.Error("password in error")
	}
	if len(steps) != 2 || steps[0].State != grid.LinkRunning || steps[1].Step != grid.StepConnect || steps[1].State != grid.LinkFailed || steps[1].Detail == "" {
		t.Errorf("steps = %+v", steps)
	}
	if len(h.Hosts()) != 3 {
		t.Error("failed link added a host")
	}

	tests := []struct {
		name string
		req  grid.SSHLinkRequest
		want error
	}{
		{"no address", grid.SSHLinkRequest{User: "pi", Password: "x"}, grid.ErrInvalidArgument},
		{"no user", grid.SSHLinkRequest{Address: "a.local", Password: "x"}, grid.ErrInvalidArgument},
		{"no auth", grid.SSHLinkRequest{Address: "a.local", User: "pi"}, grid.ErrInvalidArgument},
		{"both auth", grid.SSHLinkRequest{Address: "a.local", User: "pi", Password: "x", UseHubKey: true}, grid.ErrInvalidArgument},
		{"bad port", grid.SSHLinkRequest{Address: "a.local", User: "pi", Password: "x", Port: 70000}, grid.ErrInvalidArgument},
		{"online duplicate by name", sshReq("pi5-media"), grid.ErrHostExists},
		{"online duplicate by address", sshReq("192.168.10.5"), grid.ErrHostExists},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := h.LinkViaSSH(ctx, grid.Actor{}, tc.req, nil); !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := h.LinkViaSSH(canceled, grid.Actor{}, sshReq("x.local"), nil); !errors.Is(err, grid.ErrLinkFailed) {
		t.Errorf("canceled err = %v", err)
	}
}

func TestLinkBringsOfflineHostOnline(t *testing.T) {
	h, _ := newHub(t, 0.001)
	ch := sub(t, h)
	info, err := h.LinkViaSSH(context.Background(), grid.Actor{}, sshReq("pi4.local"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if info.Name != "pi4" || !info.Online || info.Model == "" {
		t.Errorf("info = %+v", info)
	}
	waitFor(t, ch, kind(grid.EventHostOnline))
	if len(h.Hosts()) != 3 {
		t.Errorf("hosts = %d, want 3", len(h.Hosts()))
	}
	if s, _ := h.Snapshot(info.ID); s.Metrics == nil || s.Packages == nil {
		t.Error("revived host has no data")
	}
}

func TestInterfaceCompliance(t *testing.T) {
	var hub grid.Hub = New(Options{})
	var enr grid.Enroller = hub.(*Hub)
	_ = enr
	hub.(*Hub).Close()
}
