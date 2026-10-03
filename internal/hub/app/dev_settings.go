package app

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/phabioo/nexara/internal/config"
	"github.com/phabioo/nexara/internal/hub/backup"
	"github.com/phabioo/nexara/internal/hub/demo"
	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/hub/history"
	"github.com/phabioo/nexara/internal/hub/httpserver"
	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/hub/update"
	"github.com/phabioo/nexara/internal/pki"
	"github.com/phabioo/nexara/internal/protocol"
)

// The services behind Settings in the demo. Everything lives in the temporary directory of `nexus dev`, nothing
// reaches the network, and there is no root helper: updates can be staged but not installed, a backup cannot be
// restored (the demo cannot restart itself).

// devSettingsArgs are the pieces devSettingsServices builds on.
type devSettingsArgs struct {
	Dir        string // temporary directory of the dev hub
	TLSDir     string // holds the demo CA
	Store      *store.Store
	CA         *pki.CA
	History    *history.Service
	Hub        *devCapHub
	Logs       *LogRing
	Now        func() time.Time
	Log        *slog.Logger
	SeedBackup bool
}

func devSettingsServices(a devSettingsArgs) (httpserver.Services, error) {
	svc := httpserver.Services{History: a.History, Settings: a.Store.Settings(), Store: a.Store, CA: a.CA, Caps: a.Hub, Logs: a.Logs}

	// A server certificate for the names of the screenshots, signed by the demo CA.
	if _, err := pki.EnsureServerCert(a.CA, a.TLSDir, []string{"frpi5", "frpi5.local"}, []net.IP{net.ParseIP("192.168.10.21")}, a.Now()); err != nil {
		a.Log.Warn("demo server certificate", "err", err)
	} else {
		svc.ServerCert = func() (*x509.Certificate, error) { return loadServerCert(a.TLSDir) }
	}
	svc.HubHost = func(h grid.HostInfo) bool { return h.Name == "pi5-media" }
	svc.Certs = devCerts{hub: a.Hub, st: a.Store, log: a.Log, now: a.Now}

	cfg := config.DefaultHub()
	cfg.Storage.Database = filepath.Join(a.Dir, "nexus.db")
	cfg.TLS.Dir = a.TLSDir
	confPath := filepath.Join(a.Dir, "nexus.yaml")
	if err := config.SaveHub(confPath, cfg); err != nil {
		return svc, err
	}
	svc.Backup = newBackupService(cfg, confPath, a.Store, a.Log, a.Now)
	if a.SeedBackup {
		if _, err := svc.Backup.CreateLocal(context.Background(), backup.ReasonNightly); err != nil {
			a.Log.Warn("demo backup", "err", err)
		}
	}

	version := "0.2.0"
	if hosts := a.Hub.Hosts(); len(hosts) > 0 && hosts[0].AgentVersion != "" {
		version = hosts[0].AgentVersion
	}
	arch, err := update.HostArch()
	if err != nil {
		arch = "arm64"
	}
	upd, err := update.New(update.Options{
		Dir:      filepath.Join(a.Dir, update.UpdatesDirName),
		Settings: a.Store.Settings(),
		Audit:    func(ctx context.Context, e store.AuditEntry) { appendAudit(ctx, a.Store, a.Log, e) },
		Logger:   a.Log.With("component", "update"),
		Now:      a.Now, CurrentVersion: version, Arch: arch,
		HTTPClient: &http.Client{Transport: offlineTransport{}},
	})
	if err != nil {
		return svc, err
	}
	svc.Updates = upd
	return svc, nil
}

// offlineTransport makes the GitHub check fail visibly instead of leaving the machine.
type offlineTransport struct{}

func (offlineTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("the demo makes no outbound connections")
}

// devCerts stands in for the grid's certificate renewal: the demo agents have no certificates.
type devCerts struct {
	hub grid.Hub
	st  *store.Store
	log *slog.Logger
	now func() time.Time
}

func (d devCerts) RenewCert(ctx context.Context, actor grid.Actor, id grid.HostID) error {
	h, ok := d.hub.Host(id)
	switch {
	case !ok:
		return grid.ErrHostNotFound
	case !h.Online:
		return grid.ErrHostOffline
	}
	appendAudit(ctx, d.st, d.log, store.AuditEntry{Time: d.now().UTC(), User: actor.Operator, Host: h.Name, Action: "cert.renew", Detail: "requested (demo)", Result: store.AuditOK})
	return nil
}

// devCapHub is the demo hub with the hub-side capability switches of the real grid: a capability that is switched
// off disappears from HostInfo.Capabilities, shows up in DisabledCapabilities and is refused.
type devCapHub struct {
	*demo.Hub
	st  *store.Store
	log *slog.Logger
	now func() time.Time

	mu  sync.Mutex
	off map[grid.HostID][]string
}

var (
	_ grid.Hub                  = (*devCapHub)(nil)
	_ grid.CapabilityController = (*devCapHub)(nil)
)

func newDevCapHub(h *demo.Hub, st *store.Store, log *slog.Logger, now func() time.Time) *devCapHub {
	return &devCapHub{Hub: h, st: st, log: log, now: now, off: map[grid.HostID][]string{}}
}

func (d *devCapHub) apply(i grid.HostInfo) grid.HostInfo {
	d.mu.Lock()
	off := d.off[i.ID]
	d.mu.Unlock()
	if len(off) == 0 {
		return i
	}
	var on, disabled []string
	for _, c := range i.Capabilities {
		if slices.Contains(off, c) {
			disabled = append(disabled, c)
		} else {
			on = append(on, c)
		}
	}
	i.Capabilities, i.DisabledCapabilities = on, disabled
	return i
}

func (d *devCapHub) Hosts() []grid.HostInfo {
	hosts := d.Hub.Hosts()
	for i := range hosts {
		hosts[i] = d.apply(hosts[i])
	}
	return hosts
}

func (d *devCapHub) Host(id grid.HostID) (grid.HostInfo, bool) {
	i, ok := d.Hub.Host(id)
	return d.apply(i), ok
}

func (d *devCapHub) Snapshot(id grid.HostID) (grid.Snapshot, bool) {
	s, ok := d.Hub.Snapshot(id)
	s.Host = d.apply(s.Host)
	return s, ok
}

func (d *devCapHub) allowed(id grid.HostID, capability string) error {
	d.mu.Lock()
	off := slices.Contains(d.off[id], capability)
	d.mu.Unlock()
	if off {
		return grid.ErrCapabilityDisabled
	}
	return nil
}

func (d *devCapHub) RefreshPackages(ctx context.Context, id grid.HostID) error {
	if err := d.allowed(id, protocol.CapPackages); err != nil {
		return err
	}
	return d.Hub.RefreshPackages(ctx, id)
}

func (d *devCapHub) SearchPackages(ctx context.Context, id grid.HostID, q string) ([]protocol.Package, error) {
	if err := d.allowed(id, protocol.CapPackages); err != nil {
		return nil, err
	}
	return d.Hub.SearchPackages(ctx, id, q)
}

func (d *devCapHub) StartJob(ctx context.Context, actor grid.Actor, id grid.HostID, spec grid.JobSpec) (grid.Job, error) {
	if err := d.allowed(id, protocol.CapPackages); err != nil {
		return grid.Job{}, err
	}
	return d.Hub.StartJob(ctx, actor, id, spec)
}

func (d *devCapHub) OpenShell(ctx context.Context, actor grid.Actor, id grid.HostID, cols, rows int) (grid.ShellSession, error) {
	if err := d.allowed(id, protocol.CapShell); err != nil {
		return nil, err
	}
	return d.Hub.OpenShell(ctx, actor, id, cols, rows)
}

func (d *devCapHub) SetCapability(ctx context.Context, actor grid.Actor, id grid.HostID, capability string, enabled bool) error {
	if capability == protocol.CapMonitoring || !slices.Contains(protocol.Capabilities(), capability) {
		return grid.ErrInvalidArgument
	}
	info, ok := d.Hub.Host(id)
	if !ok {
		return grid.ErrHostNotFound
	}
	if !slices.Contains(info.Capabilities, capability) {
		return grid.ErrUnsupported
	}
	d.mu.Lock()
	off := slices.DeleteFunc(slices.Clone(d.off[id]), func(c string) bool { return c == capability })
	if !enabled {
		off = append(off, capability)
	}
	d.off[id] = off
	d.mu.Unlock()
	state := "off"
	if enabled {
		state = "on"
	}
	appendAudit(ctx, d.st, d.log, store.AuditEntry{Time: d.now().UTC(), User: actor.Operator, Host: info.Name,
		Action: "host.capabilities", Detail: capability + " " + state, Result: store.AuditOK})
	return nil
}

// seedDevLog fills the demo's hub log with a few records of each level, so the Diagnostics dialog shows its colours.
func seedDevLog(r *LogRing, now time.Time) {
	for i, rec := range []httpserver.LogRecord{
		{Level: slog.LevelInfo, Text: "agent connected component=grid host=pi5-media version=0.2.0"},
		{Level: slog.LevelInfo, Text: "agent connected component=grid host=pi3-dns version=0.2.0"},
		{Level: slog.LevelWarn, Text: "agent certificate expires soon component=grid host=pi3-dns days=253"},
		{Level: slog.LevelError, Text: "audit write failed action=login err=\"database is locked\" (sample line of the demo)"},
	} {
		rec.Time = now.Add(time.Duration(i-5) * time.Minute)
		r.add(rec)
	}
}
