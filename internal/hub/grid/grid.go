package grid

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/phabioo/nexara/internal/hub/agentbin"
	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/pki"
	"github.com/phabioo/nexara/internal/protocol"
)

// Defaults used when the matching Options field is zero.
const (
	defaultOfflineAfter = 60 * time.Second // config alerts.host_offline_seconds default
	defaultHistoryLen   = 60
	defaultPingInterval = 10 * time.Second

	subscriberBuffer = 256
	maxOutputLines   = 500 // retained output lines per job
	maxFinishedJobs  = 20  // finished jobs kept per host
)

// Options configures a Grid.
type Options struct {
	Store  *store.Store     // required
	Logger *slog.Logger     // defaults to a discarding logger
	Now    func() time.Time // defaults to time.Now
	// OfflineAfter is how long the connection may stay silent before the host
	// counts as offline (config alerts.host_offline_seconds).
	OfflineAfter time.Duration
	// HistoryLen is the number of CPU samples kept per host (default 60).
	HistoryLen int
	// AgentBinary looks up the embedded agent binary for an os/arch; defaults to agentbin.Lookup.
	AgentBinary func(os, arch string) (agentbin.Binary, bool)
	// HubVersion is the version agents are updated to; "dev" (or empty) disables auto-update.
	HubVersion string

	// Identify authenticates an agent request and returns its host. The default
	// reads the verified mTLS client certificate; tests inject their own.
	Identify func(*http.Request) (store.Host, error)
	// PingInterval is the WebSocket ping period (default 10 s).
	PingInterval time.Duration

	// CA signs renewed agent certificates (decision #47). Without it the hub
	// answers certificate requests with "unsupported" and never asks agents to
	// renew.
	CA *pki.CA
	// PeerCertificate returns the client certificate an agent request was
	// authenticated with. The default reads the verified TLS connection; tests
	// inject their own.
	PeerCertificate func(*http.Request) *x509.Certificate
}

// timeouts of hub->agent requests; fields are replaced by tests.
type timeouts struct {
	hello, write, servicesList, packagesList, packagesSearch time.Duration
	serviceRestart, shellOpen, jobStart, jobCancel, update   time.Duration
	renew                                                    time.Duration
}

func defaultTimeouts() timeouts {
	return timeouts{
		hello:          10 * time.Second,
		write:          10 * time.Second,
		servicesList:   30 * time.Second,
		packagesList:   120 * time.Second,
		packagesSearch: 30 * time.Second,
		serviceRestart: 70 * time.Second,
		shellOpen:      10 * time.Second,
		jobStart:       15 * time.Second,
		jobCancel:      10 * time.Second,
		update:         10 * time.Second,
		renew:          10 * time.Second,
	}
}

// Grid is the hub side of the agent connections. It implements Hub.
type Grid struct {
	opts     Options
	log      *slog.Logger
	now      func() time.Time
	identify func(*http.Request) (store.Host, error)
	ctx      context.Context
	cancel   context.CancelFunc
	to       timeouts
	shellLim shellLimits

	// mu guards everything below and the fields of every hostState.
	mu    sync.Mutex
	hosts map[HostID]*hostState
	order []HostID
	byFP  map[string]HostID
	// capMu serializes SetCapability (capabilities.go).
	capMu sync.Mutex
	// pending holds renewed certificates that were issued but have not been
	// used yet, by fingerprint (renew.go).
	pending map[string]*pendingCert
	jobs    map[string]*hostState // job ID -> host, for queued, running and retained finished jobs
	jobSeq  uint64

	subMu sync.Mutex
	subs  map[*subscriber]struct{}
}

var _ Hub = (*Grid)(nil)

type subscriber struct{ ch chan Event }

// hostState is the registry entry of one host; guarded by Grid.mu.
type hostState struct {
	id   HostID
	name string // immutable copy of host.Name for logging and audit without the lock
	host store.Host

	model, kernel  string
	online         bool
	lastSeen       time.Time
	latency        time.Duration
	updateRequired bool
	rebootRequired bool

	conn           *agentConn
	lastAutoUpdate time.Time

	// capsOff are the capabilities the operator switched off in the hub (capabilities.go).
	capsOff []string

	// Certificate renewal (renew.go).
	pendingFP        string    // fingerprint of the issued, not yet used certificate
	renewBusy        bool      // a hub-initiated cert.renew request is in flight
	renewRequested   time.Time // last time the hub asked the agent to renew
	forceUntil       time.Time // an operator asked for a renewal; sign even if not due until then
	renewUnsupported bool      // the connected agent does not know cert.renew
	lastNotDueAudit  time.Time // last "certificate not due" audit entry (throttled per hour)

	metrics  *protocol.Metrics
	history  []float64
	services *protocol.Services
	packages *protocol.Packages

	queue    []*jobRec // running job first, then queued jobs
	finished []*jobRec // oldest first
}

// NewGrid loads the hosts (revoked ones excluded) from the store.
func NewGrid(opts Options) (*Grid, error) {
	if opts.Store == nil {
		return nil, errors.New("grid: store is required")
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.OfflineAfter <= 0 {
		opts.OfflineAfter = defaultOfflineAfter
	}
	if opts.HistoryLen <= 0 {
		opts.HistoryLen = defaultHistoryLen
	}
	if opts.AgentBinary == nil {
		opts.AgentBinary = agentbin.Lookup
	}
	if opts.HubVersion == "" {
		opts.HubVersion = "dev"
	}
	if opts.PingInterval <= 0 {
		opts.PingInterval = defaultPingInterval
	}
	ctx, cancel := context.WithCancel(context.Background())
	g := &Grid{
		opts:     opts,
		log:      opts.Logger,
		now:      func() time.Time { return opts.Now().UTC() },
		ctx:      ctx,
		cancel:   cancel,
		to:       defaultTimeouts(),
		shellLim: defaultShellLimits(),
		hosts:    map[HostID]*hostState{},
		byFP:     map[string]HostID{},
		pending:  map[string]*pendingCert{},
		jobs:     map[string]*hostState{},
		subs:     map[*subscriber]struct{}{},
	}
	g.identify = opts.Identify
	if g.identify == nil {
		g.identify = g.identifyTLS
	}
	hosts, err := opts.Store.ListHosts(ctx)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("grid: load hosts: %w", err)
	}
	for _, h := range hosts {
		if h.Revoked {
			continue
		}
		_, _ = g.addLocked(h)
	}
	if err := g.loadCapsOff(ctx); err != nil {
		cancel()
		return nil, err
	}
	return g, nil
}

// Close drops all agent connections and ends all subscriptions. The Grid must
// not be used afterwards.
func (g *Grid) Close() { g.cancel() }

func (g *Grid) addLocked(h store.Host) (*hostState, bool) {
	id := HostID(h.ID)
	h.Capabilities = slices.Clone(h.Capabilities)
	st, ok := g.hosts[id]
	if ok {
		delete(g.byFP, st.host.CertFingerprint)
		st.host = h
	} else {
		st = &hostState{id: id, name: h.Name, host: h, lastSeen: h.LastSeenAt}
		g.hosts[id] = st
		g.order = append(g.order, id)
		sort.SliceStable(g.order, func(i, j int) bool {
			a, b := g.hosts[g.order[i]].host, g.hosts[g.order[j]].host
			if !a.CreatedAt.Equal(b.CreatedAt) {
				return a.CreatedAt.Before(b.CreatedAt)
			}
			return a.Name < b.Name
		})
	}
	if h.CertFingerprint != "" {
		g.byFP[h.CertFingerprint] = id
	}
	return st, !ok
}

// Register announces a new or re-enrolled host (called by the enrollment
// package). EventHostAdded is emitted for new hosts only. For a known host
// (re-installed device, new certificate) the host facts are refreshed and a
// live connection is closed: it used the old certificate.
func (g *Grid) Register(_ context.Context, h store.Host) error {
	if h.ID == "" || h.Name == "" {
		return fmt.Errorf("%w: host needs id and name", ErrInvalidArgument)
	}
	if h.Revoked {
		return fmt.Errorf("%w: host is revoked", ErrInvalidArgument)
	}
	g.mu.Lock()
	st, isNew := g.addLocked(h)
	g.dropPendingLocked(st) // it was issued for the certificate that was just replaced
	old := st.conn
	if isNew {
		g.emitLocked(Event{Kind: EventHostAdded, Host: st.id, Payload: st.infoLocked()})
	}
	g.mu.Unlock()
	if old != nil {
		old.close()
	}
	return nil
}

// Remove drops a host from the registry (host removal or revocation): its
// connection is closed and EventHostRemoved is emitted. Unknown IDs are ignored.
func (g *Grid) Remove(id HostID) {
	g.mu.Lock()
	st, ok := g.hosts[id]
	if !ok {
		g.mu.Unlock()
		return
	}
	info := st.infoLocked()
	c := st.conn
	// Detach first: connClosed must not report a removed host as offline or
	// write its last-seen time.
	st.conn = nil
	st.online = false
	g.dropPendingLocked(st)
	delete(g.hosts, id)
	delete(g.byFP, st.host.CertFingerprint)
	g.order = slices.DeleteFunc(g.order, func(x HostID) bool { return x == id })
	for _, rec := range st.queue {
		delete(g.jobs, rec.ID)
	}
	for _, rec := range st.finished {
		delete(g.jobs, rec.ID)
	}
	g.emitLocked(Event{Kind: EventHostRemoved, Host: id, Payload: info})
	g.mu.Unlock()
	if c != nil {
		c.close()
	}
}

// RemoveHost implements Hub (decision #47): the host is revoked in the
// database first, so a handshake racing with the removal is refused by
// identifyTLS even before the registry entry is gone, then it leaves the
// registry (IsRevoked turns true for its certificate) and its live connection
// is closed. The row stays, revoked and with a freed name, for the audit trail.
func (g *Grid) RemoveHost(ctx context.Context, actor Actor, id HostID) error {
	g.mu.Lock()
	st, ok := g.hosts[id]
	var name string
	if ok {
		name = st.name
	}
	g.mu.Unlock()
	if !ok {
		return ErrHostNotFound
	}
	err := g.opts.Store.RetireHost(ctx, string(id))
	if err != nil {
		g.audit(store.AuditEntry{User: actor.Operator, Host: name, Action: "host.remove", Detail: auditDetailIP(actor), Result: store.AuditError})
		if errors.Is(err, store.ErrNotFound) {
			g.Remove(id) // registry and database disagree; the registry entry is stale
			return ErrHostNotFound
		}
		return fmt.Errorf("grid: remove host: %w", err)
	}
	g.Remove(id)
	_ = g.opts.Store.DeleteSetting(ctx, capsOffKey(id)) // best effort: a stale switch is harmless
	g.audit(store.AuditEntry{User: actor.Operator, Host: name, Action: "host.remove", Detail: auditDetailIP(actor), Result: store.AuditOK})
	g.log.Info("host removed", "host", name)
	return nil
}

func auditDetailIP(a Actor) string {
	if a.IP == "" {
		return ""
	}
	return "from " + a.IP
}

// IsRevoked reports whether a certificate fingerprint must be rejected in the
// TLS handshake. Unknown fingerprints count as revoked.
//
// A renewed certificate is accepted from the moment it is issued until it has
// been used once (activation) or 24 hours have passed, next to the old one.
func (g *Grid) IsRevoked(fingerprint string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, ok := g.byFP[fingerprint]; ok {
		return false
	}
	_, ok := g.livePendingLocked(fingerprint)
	return !ok
}

var errNotAuthenticated = errors.New("grid: agent not authenticated")

func (g *Grid) identifyTLS(r *http.Request) (store.Host, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return store.Host{}, errNotAuthenticated
	}
	fp := pki.Fingerprint(r.TLS.PeerCertificates[0])
	h, err := g.opts.Store.GetHostByFingerprint(r.Context(), fp)
	if errors.Is(err, store.ErrNotFound) {
		// Not the certificate of record: maybe a renewed one that has not been used yet.
		g.mu.Lock()
		p, ok := g.livePendingLocked(fp)
		g.mu.Unlock()
		if !ok {
			return store.Host{}, errNotAuthenticated
		}
		h, err = g.opts.Store.GetHost(r.Context(), string(p.host))
	}
	if err != nil {
		return store.Host{}, errNotAuthenticated
	}
	if h.Revoked {
		return store.Host{}, errNotAuthenticated
	}
	return h, nil
}

// authenticate identifies the agent behind r and returns its registry entry.
func (g *Grid) authenticate(r *http.Request) (*hostState, error) {
	h, err := g.identify(r)
	if err != nil {
		return nil, errNotAuthenticated
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	st, ok := g.hosts[HostID(h.ID)]
	if !ok {
		return nil, errNotAuthenticated
	}
	return st, nil
}

func hasCap(caps []string, name string) bool { return slices.Contains(caps, name) }

// infoLocked builds the HostInfo; g.mu must be held.
func (st *hostState) infoLocked() HostInfo {
	return HostInfo{
		ID:                   st.id,
		Name:                 st.host.Name,
		DisplayName:          st.host.DisplayName,
		Address:              st.host.Address,
		OS:                   st.host.OS,
		Arch:                 st.host.Arch,
		AgentVersion:         st.host.AgentVersion,
		Model:                st.model,
		Kernel:               st.kernel,
		Online:               st.online,
		LastSeen:             st.lastSeen.UTC(),
		Latency:              st.latency,
		Capabilities:         st.enabledCaps(),
		DisabledCapabilities: st.disabledCaps(),
		UpdateRequired:       st.updateRequired,
		RebootRequired:       st.rebootRequired,
		CertNotAfter:         st.host.CertNotAfter.UTC(),
	}
}

// Hosts implements Hub.
func (g *Grid) Hosts() []HostInfo {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]HostInfo, 0, len(g.order))
	for _, id := range g.order {
		out = append(out, g.hosts[id].infoLocked())
	}
	return out
}

// Host implements Hub.
func (g *Grid) Host(id HostID) (HostInfo, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	st, ok := g.hosts[id]
	if !ok {
		return HostInfo{}, false
	}
	return st.infoLocked(), true
}

// Snapshot implements Hub.
func (g *Grid) Snapshot(id HostID) (Snapshot, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	st, ok := g.hosts[id]
	if !ok {
		return Snapshot{}, false
	}
	snap := Snapshot{
		Host:       st.infoLocked(),
		Metrics:    cloneMetrics(st.metrics),
		CPUHistory: slices.Clone(st.history),
		Services:   cloneServices(st.services),
		Packages:   clonePackages(st.packages),
	}
	for _, rec := range st.queue {
		snap.Jobs = append(snap.Jobs, rec.snapshot())
	}
	return snap, true
}

// Subscribe implements Hub.
func (g *Grid) Subscribe(ctx context.Context) <-chan Event {
	s := &subscriber{ch: make(chan Event, subscriberBuffer)}
	g.subMu.Lock()
	g.subs[s] = struct{}{}
	g.subMu.Unlock()
	go func() {
		select {
		case <-ctx.Done():
		case <-g.ctx.Done():
		}
		g.subMu.Lock()
		delete(g.subs, s)
		close(s.ch)
		g.subMu.Unlock()
	}()
	return s.ch
}

// emitLocked delivers ev to all subscribers without ever blocking: a full
// subscriber buffer loses the event. It may be called with g.mu held (subMu is a leaf lock).
func (g *Grid) emitLocked(ev Event) {
	g.subMu.Lock()
	defer g.subMu.Unlock()
	for s := range g.subs {
		select {
		case s.ch <- ev:
		default:
		}
	}
}

func (g *Grid) audit(e store.AuditEntry) {
	if e.Time.IsZero() {
		e.Time = g.now()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := g.opts.Store.AppendAudit(ctx, e); err != nil {
		g.log.Warn("grid: audit write failed", "action", e.Action, "err", err)
	}
}

func auditResult(err error) string {
	if err != nil {
		return store.AuditError
	}
	return store.AuditOK
}

// connFor returns the live connection of a host after checking that the host
// exists, is online and has the capability (empty name = no capability needed).
func (g *Grid) connFor(id HostID, capability string) (*hostState, *agentConn, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	st, ok := g.hosts[id]
	if !ok {
		return nil, nil, ErrHostNotFound
	}
	if st.conn == nil || !st.online {
		return nil, nil, ErrHostOffline
	}
	if capability != "" && !st.capEnabled(capability) {
		return nil, nil, ErrCapabilityDisabled
	}
	return st, st.conn, nil
}

func cloneMetrics(m *protocol.Metrics) *protocol.Metrics {
	if m == nil {
		return nil
	}
	c := *m
	c.CPUPerCore = slices.Clone(m.CPUPerCore)
	if m.TempC != nil {
		v := *m.TempC
		c.TempC = &v
	}
	c.Disks = slices.Clone(m.Disks)
	c.TopProcesses = slices.Clone(m.TopProcesses)
	return &c
}

func cloneServices(s *protocol.Services) *protocol.Services {
	if s == nil {
		return nil
	}
	c := *s
	c.Units = slices.Clone(s.Units)
	c.Ports = slices.Clone(s.Ports)
	return &c
}

func clonePackages(p *protocol.Packages) *protocol.Packages {
	if p == nil {
		return nil
	}
	c := *p
	c.Items = slices.Clone(p.Items)
	return &c
}
