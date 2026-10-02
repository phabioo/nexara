package history

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/protocol"
)

const (
	hostA = "a1c5e0d2b7f34961"
	hostB = "b3d7f1a4c8e25072"
)

// t0 is a fixed "now": 12:30:20 on a fresh minute-aligned day.
var t0 = time.Date(2026, 10, 2, 12, 30, 20, 0, time.UTC)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Set(t time.Time) {
	c.mu.Lock()
	c.t = t
	c.mu.Unlock()
}

func (c *clock) Add(d time.Duration) { c.Set(c.Now().Add(d)) }

type env struct {
	t   *testing.T
	st  *store.Store
	clk *clock
	svc *Service
}

func newEnv(t *testing.T, mod ...func(*Options)) *env {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "nexus.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	clk := &clock{t: t0}
	o := Options{Store: st, Now: clk.Now}
	for _, m := range mod {
		m(&o)
	}
	return &env{t: t, st: st, clk: clk, svc: New(o)}
}

// sample builds a live sample at time at.
func sample(at time.Time, cpu float64) protocol.Metrics {
	temp := 40 + cpu/10
	return protocol.Metrics{
		Timestamp:  at,
		CPUPercent: cpu,
		TempC:      &temp,
		MemTotal:   8 << 30, MemUsed: 2 << 30,
		Disks: []protocol.Disk{{Mount: "/", Total: 100, Used: 40}, {Mount: "/mnt/data", Total: 1000, Used: 500}},
		Net:   protocol.NetRate{Iface: "eth0", RxBytesPerSec: cpu * 100, TxBytesPerSec: cpu * 10},
	}
}

func (e *env) minutes(host string, from, to time.Time) []store.MetricRow {
	e.t.Helper()
	rows, err := e.st.ListMetrics(context.Background(), store.Metrics1m, host, from, to)
	if err != nil {
		e.t.Fatal(err)
	}
	return rows
}

func (e *env) hours(host string, from, to time.Time) []store.MetricRow {
	e.t.Helper()
	rows, err := e.st.ListMetrics(context.Background(), store.Metrics1h, host, from, to)
	if err != nil {
		e.t.Fatal(err)
	}
	return rows
}

func (e *env) flush() {
	e.t.Helper()
	if err := e.svc.Flush(context.Background()); err != nil {
		e.t.Fatal(err)
	}
}

// fakeHub is a grid subscriber the test feeds by hand.
type fakeHub struct {
	ch chan grid.Event
}

func newFakeHub(buffer ...int) *fakeHub {
	n := 0
	if len(buffer) > 0 {
		n = buffer[0]
	}
	return &fakeHub{ch: make(chan grid.Event, n)}
}

// Subscribe returns the unbuffered channel itself: send returns only once the
// service's Run loop has received the event, which keeps the tests race-free.
func (f *fakeHub) Subscribe(context.Context) <-chan grid.Event { return f.ch }

func (f *fakeHub) send(ctx context.Context, ev grid.Event) {
	select {
	case f.ch <- ev:
	case <-ctx.Done():
	}
}
