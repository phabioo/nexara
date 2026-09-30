// Package demo implements grid.Hub and grid.Enroller with simulated hosts for
// `nexus dev --demo` (decision #25). The data set is the one of the design
// mockups: pi5-media, pi3-dns and the offline pi4. Nothing here talks to a
// network or a real agent, and nothing is audited.
package demo

import (
	"context"
	"fmt"
	"math/rand/v2"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/protocol"
)

// Compile-time contract checks.
var (
	_ grid.Hub      = (*Hub)(nil)
	_ grid.Enroller = (*Hub)(nil)
)

const (
	historyLen     = 60
	subscriberBuf  = 64
	maxJobHistory  = 30
	maxJobOutput   = 200
	defaultTick    = 2 * time.Second
	restartDelay   = 1500 * time.Millisecond
	jobLineDelay   = 150 * time.Millisecond
	enrollDelay    = 8 * time.Second
	linkStepDelay  = 800 * time.Millisecond
	enrollCodeTTL  = 15 * time.Minute
	agentVersion   = "0.1.0"
	demoHubAddress = "frpi5.local:8443"
)

// Options configure a demo Hub. The zero value is usable.
type Options struct {
	// Now is the clock; defaults to time.Now.
	Now func() time.Time
	// Tick is the simulation interval used by Start; defaults to 2 s.
	Tick time.Duration
	// Ticks, if set, replaces the internal ticker of Start (tests drive the
	// simulation with it).
	Ticks <-chan time.Time
	// Rand is the randomness source; defaults to a time-seeded generator. The
	// Hub owns it afterwards and serializes all access.
	Rand *rand.Rand
	// TimeScale multiplies every artificial delay (job line pacing, service
	// restart, enrollment, SSH steps). 0 means 1. Tests use a tiny value.
	TimeScale float64
}

// Hub is the simulated grid. Create it with New and run the simulation with Start.
type Hub struct {
	now   func() time.Time
	tick  time.Duration
	ticks <-chan time.Time
	scale float64

	ctx    context.Context
	cancel context.CancelFunc

	mu         sync.Mutex
	rng        *rand.Rand
	hosts      []*host
	subs       map[chan grid.Event]struct{}
	jobSeq     int
	hostSeq    int
	enrollGen  int
	enrollCode string
}

// New creates a hub with the design's sample data.
func New(o Options) *Hub {
	h := &Hub{
		now:   o.Now,
		tick:  o.Tick,
		ticks: o.Ticks,
		scale: o.TimeScale,
		rng:   o.Rand,
		subs:  make(map[chan grid.Event]struct{}),
	}
	if h.now == nil {
		h.now = time.Now
	}
	if h.tick <= 0 {
		h.tick = defaultTick
	}
	if h.scale <= 0 {
		h.scale = 1
	}
	if h.rng == nil {
		h.rng = rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), 0x6e657861))
	}
	h.ctx, h.cancel = context.WithCancel(context.Background())
	h.seed()
	return h
}

// Start runs the simulation until ctx ends; it blocks. Background work
// (running jobs, pending enrollments) stops when it returns.
func (h *Hub) Start(ctx context.Context) {
	defer h.cancel()
	ticks := h.ticks
	if ticks == nil {
		t := time.NewTicker(h.tick)
		defer t.Stop()
		ticks = t.C
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-h.ctx.Done():
			return
		case <-ticks:
			h.step()
		}
	}
}

// Close stops background work without Start having run.
func (h *Hub) Close() { h.cancel() }

// wait sleeps for the scaled duration; false if ctx ended first.
func (h *Hub) wait(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(time.Duration(float64(d) * h.scale))
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// emit delivers ev to all subscribers without blocking. Callers hold h.mu.
func (h *Hub) emit(ev grid.Event) {
	for ch := range h.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

// Subscribe implements grid.Hub.
func (h *Hub) Subscribe(ctx context.Context) <-chan grid.Event {
	ch := make(chan grid.Event, subscriberBuf)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	go func() {
		<-ctx.Done()
		h.mu.Lock()
		delete(h.subs, ch)
		close(ch)
		h.mu.Unlock()
	}()
	return ch
}

// Hosts implements grid.Hub.
func (h *Hub) Hosts() []grid.HostInfo {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]grid.HostInfo, len(h.hosts))
	for i, hst := range h.hosts {
		out[i] = cloneInfo(hst.info)
	}
	return out
}

// Host implements grid.Hub.
func (h *Hub) Host(id grid.HostID) (grid.HostInfo, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	hst := h.find(id)
	if hst == nil {
		return grid.HostInfo{}, false
	}
	return cloneInfo(hst.info), true
}

// Snapshot implements grid.Hub.
func (h *Hub) Snapshot(id grid.HostID) (grid.Snapshot, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	hst := h.find(id)
	if hst == nil {
		return grid.Snapshot{}, false
	}
	s := grid.Snapshot{Host: cloneInfo(hst.info)}
	if hst.metrics != nil {
		m := cloneMetrics(*hst.metrics)
		s.Metrics = &m
		s.CPUHistory = append([]float64(nil), hst.hist...)
	}
	if hst.services != nil {
		sv := cloneServices(*hst.services)
		s.Services = &sv
	}
	if hst.pkgs != nil {
		p := hst.packages()
		s.Packages = &p
	}
	for _, j := range hst.jobs {
		if !j.State.Finished() {
			s.Jobs = append(s.Jobs, j.copy())
		}
	}
	return s, true
}

// RefreshServices implements grid.Hub.
func (h *Hub) RefreshServices(_ context.Context, id grid.HostID) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	hst, err := h.usable(id, protocol.CapServices)
	if err != nil {
		return err
	}
	h.emit(grid.Event{Kind: grid.EventServices, Host: id, Payload: cloneServices(*hst.services)})
	return nil
}

// RefreshPackages implements grid.Hub.
func (h *Hub) RefreshPackages(_ context.Context, id grid.HostID) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	hst, err := h.usable(id, protocol.CapPackages)
	if err != nil {
		return err
	}
	h.emit(grid.Event{Kind: grid.EventPackages, Host: id, Payload: hst.packages()})
	return nil
}

var unitRe = regexp.MustCompile(`^[A-Za-z0-9:_.@][A-Za-z0-9:_.@\-]{0,127}$`)

// RestartService implements grid.Hub. The unit goes through "activating" and is
// active/running after about 1.5 s.
func (h *Hub) RestartService(_ context.Context, _ grid.Actor, id grid.HostID, unit string) error {
	if !unitRe.MatchString(unit) {
		return fmt.Errorf("%w: unit name %q", grid.ErrInvalidArgument, unit)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	hst, err := h.usable(id, protocol.CapServices)
	if err != nil {
		return err
	}
	want := strings.TrimSuffix(unit, ".service")
	idx := -1
	for i, u := range hst.services.Units {
		if strings.TrimSuffix(u.Name, ".service") == want {
			idx = i
		}
	}
	if idx < 0 {
		return fmt.Errorf("%w: unknown unit %q", grid.ErrInvalidArgument, unit)
	}
	name := hst.services.Units[idx].Name
	hst.services.Units[idx].ActiveState = "activating"
	hst.services.Units[idx].SubState = "start"
	h.emit(grid.Event{Kind: grid.EventServices, Host: id, Payload: cloneServices(*hst.services)})
	go func() {
		if !h.wait(h.ctx, restartDelay) {
			return
		}
		h.mu.Lock()
		defer h.mu.Unlock()
		for i := range hst.services.Units {
			if hst.services.Units[i].Name == name {
				hst.services.Units[i].ActiveState = "active"
				hst.services.Units[i].SubState = "running"
			}
		}
		h.emit(grid.Event{Kind: grid.EventServices, Host: id, Payload: cloneServices(*hst.services)})
	}()
	return nil
}

// UpdateAgent implements grid.Hub; the demo pretends the update worked.
func (h *Hub) UpdateAgent(_ context.Context, _ grid.Actor, id grid.HostID) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	hst := h.find(id)
	if hst == nil {
		return grid.ErrHostNotFound
	}
	if !hst.info.Online {
		return grid.ErrHostOffline
	}
	hst.info.AgentVersion = agentVersion
	hst.info.UpdateRequired = false
	return nil
}

// find returns the host with the given ID or nil. Callers hold h.mu.
func (h *Hub) find(id grid.HostID) *host {
	for _, hst := range h.hosts {
		if hst.info.ID == id {
			return hst
		}
	}
	return nil
}

// usable returns an online host with the capability enabled. Callers hold h.mu.
func (h *Hub) usable(id grid.HostID, capability string) (*host, error) {
	hst := h.find(id)
	switch {
	case hst == nil:
		return nil, grid.ErrHostNotFound
	case !hst.info.Online:
		return nil, grid.ErrHostOffline
	case !hst.info.HasCapability(capability):
		return nil, grid.ErrCapabilityDisabled
	}
	return hst, nil
}

func cloneInfo(i grid.HostInfo) grid.HostInfo {
	i.Capabilities = append([]string(nil), i.Capabilities...)
	return i
}

func cloneMetrics(m protocol.Metrics) protocol.Metrics {
	m.CPUPerCore = append([]float64(nil), m.CPUPerCore...)
	m.Disks = append([]protocol.Disk(nil), m.Disks...)
	m.TopProcesses = append([]protocol.Process(nil), m.TopProcesses...)
	if m.TempC != nil {
		t := *m.TempC
		m.TempC = &t
	}
	return m
}

func cloneServices(s protocol.Services) protocol.Services {
	s.Units = append([]protocol.ServiceUnit(nil), s.Units...)
	s.Ports = append([]protocol.ListeningPort(nil), s.Ports...)
	return s
}
