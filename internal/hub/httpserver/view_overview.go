package httpserver

import (
	"bytes"
	"context"
	"errors"
	"html"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/hub/views"
	"github.com/phabioo/nexara/internal/protocol"
)

// Names of the SSE events of the overview. Each one is swapped into the element carrying the same
// sse-swap value in pages/overview.html.
const (
	sseOverviewLoad  = "ov-load"  // text of the LOAD chip
	sseOverviewCPU   = "ov-cpu"   // body of the CPU card
	sseOverviewMem   = "ov-mem"   // body of the Memory & storage card
	sseOverviewSvc   = "ov-svc"   // body of the Services card
	sseOverviewState = "ov-state" // a host went online or offline; overview.js reloads the page
)

// overviewServicesTimeout bounds the background services refresh started by a page view.
const overviewServicesTimeout = 10 * time.Second

// routesOverview registers the live overview: GET / shows the default host, GET /hosts/{host} a specific
// one, POST /hosts/{host}/services/restart restarts the failed units.
func (s *Server) routesOverview(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", s.handleOverviewDefault)
	mux.HandleFunc("GET /hosts/{host}", s.handleOverviewHost)
	mux.HandleFunc("POST /hosts/{host}/services/restart", s.handleServicesRestart)

	s.sse.Register(grid.EventMetrics, s.renderOverviewLoad)
	s.sse.Register(grid.EventMetrics, s.renderOverviewCPU)
	s.sse.Register(grid.EventMetrics, s.renderOverviewMem)
	s.sse.Register(grid.EventServices, s.renderOverviewServices)
	s.sse.Register(grid.EventHostOnline, s.renderOverviewState)
	s.sse.Register(grid.EventHostOffline, s.renderOverviewState)
}

func (s *Server) handleOverviewDefault(w http.ResponseWriter, r *http.Request) {
	h, ok := s.defaultHost()
	if !ok {
		s.renderOverview(w, r, nil)
		return
	}
	s.renderOverview(w, r, &h)
}

func (s *Server) handleOverviewHost(w http.ResponseWriter, r *http.Request) {
	h, ok := s.requireHost(w, r)
	if !ok {
		return
	}
	s.renderOverview(w, r, &h)
}

func (s *Server) renderOverview(w http.ResponseWriter, r *http.Request, h *grid.HostInfo) {
	if s.renderer == nil {
		s.notImplemented(w, r)
		return
	}
	page := views.OverviewPage{Layout: s.layout(r, "overview", h)}
	page.Title = "Overview"
	if h == nil {
		page.Empty = true
	} else {
		snap, _ := s.hub.Snapshot(h.ID)
		s.overviewFill(&page, *h, snap)
		if page.Log == "" && h.Online {
			page.Log = "Connected to " + h.Name
		}
		if h.Online {
			s.overviewRefreshServices(r, *h)
		}
	}
	if err := s.renderer.Render(w, "overview", page); err != nil {
		s.serverError(w, r, err)
	}
}

// overviewFill copies the host's state into the page model.
func (s *Server) overviewFill(p *views.OverviewPage, h grid.HostInfo, snap grid.Snapshot) {
	label := hostLabel(h)
	p.Host, p.Label = h.Name, label
	p.SSEURL = "/events?host=" + url.QueryEscape(h.Name)
	p.MicroNode = "grid_node_" + p.NodeNo
	p.MicroRes = "res_map_" + h.Name
	p.RebootRequired = h.RebootRequired || (snap.Packages != nil && snap.Packages.RebootRequired)

	if !h.Online {
		p.Offline = &views.OverviewOffline{
			Title:    label + " · Offline",
			Tag:      "Offline",
			Text:     "The Grid Agent is not connected. This view returns as soon as the agent reconnects.",
			LastSeen: views.AgoText(s.now(), h.LastSeen),
		}
		return
	}

	p.CPUTitle = views.CPUTitle(snap.Metrics)
	p.CPU = views.NewOverviewCPU(h.Model, snap.Metrics)
	p.Mem = views.NewOverviewMem(snap.Metrics, snap.CPUHistory, overviewShellHref(h))
	p.Svc = views.NewOverviewServices(h.Name, snap.Services, h.HasCapability(protocol.CapServices), overviewRestartURL(h))
	if snap.Metrics != nil {
		p.Load = views.LoadText(snap.Metrics.Load)
	} else {
		p.Load = "–"
	}
}

func overviewShellHref(h grid.HostInfo) string {
	if !h.HasCapability(protocol.CapShell) {
		return ""
	}
	return hostURL(h.Name) + "/shell"
}

func overviewRestartURL(h grid.HostInfo) string { return hostURL(h.Name) + "/services/restart" }

// overviewRefreshServices asks the agent for a fresh unit list; the answer arrives as EventServices and
// updates the open page. Units change state on their own (a crash), and the hub only fetches the list on
// connect and after a restart.
func (s *Server) overviewRefreshServices(r *http.Request, h grid.HostInfo) {
	if !h.HasCapability(protocol.CapServices) {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), overviewServicesTimeout)
	go func() {
		defer cancel()
		_ = s.hub.RefreshServices(ctx, h.ID)
	}()
}

// handleServicesRestart restarts every failed unit of the host. The hub audits each restart. The answer is a
// toast (out-of-band swap into #toasts); the refreshed unit list follows as EventServices.
func (s *Server) handleServicesRestart(w http.ResponseWriter, r *http.Request) {
	h, ok := s.requireHost(w, r)
	if !ok {
		return
	}
	if s.renderer == nil {
		s.notImplemented(w, r)
		return
	}
	if !h.Online {
		s.gridError(w, r, grid.ErrHostOffline)
		return
	}
	snap, _ := s.hub.Snapshot(h.ID)
	var failed []string
	if snap.Services != nil {
		for _, u := range snap.Services.Units {
			if u.ActiveState == "failed" {
				failed = append(failed, u.Name)
			}
		}
	}

	toast := views.Toast{Title: "Nothing to do", Sub: h.Name + " | all units running"}
	if len(failed) > 0 {
		actor := ActorFrom(r)
		for _, unit := range failed {
			if err := s.hub.RestartService(r.Context(), actor, h.ID, unit); err != nil {
				s.gridError(w, r, err)
				return
			}
		}
		toast = views.Toast{Title: "Restored", Sub: h.Name + " | systemctl restart"}
	}
	if err := s.renderer.RenderPartial(w, "overview-toast", toast); err != nil {
		s.serverError(w, r, err)
	}
}

// --- SSE renderers ----------------------------------------------------------------

// metricsOf extracts the sample from an event payload (value or pointer).
func overviewMetrics(ev grid.Event) (protocol.Metrics, bool) {
	switch m := ev.Payload.(type) {
	case protocol.Metrics:
		return m, true
	case *protocol.Metrics:
		if m != nil {
			return *m, true
		}
	}
	return protocol.Metrics{}, false
}

func overviewServices(ev grid.Event) (protocol.Services, bool) {
	switch v := ev.Payload.(type) {
	case protocol.Services:
		return v, true
	case *protocol.Services:
		if v != nil {
			return *v, true
		}
	}
	return protocol.Services{}, false
}

func (s *Server) renderOverviewLoad(_ *http.Request, ev grid.Event) (string, string, bool) {
	m, ok := overviewMetrics(ev)
	if !ok {
		return "", "", false
	}
	return sseOverviewLoad, html.EscapeString(views.LoadText(m.Load)), true
}

func (s *Server) renderOverviewCPU(_ *http.Request, ev grid.Event) (string, string, bool) {
	m, ok := overviewMetrics(ev)
	if !ok {
		return "", "", false
	}
	info, _ := s.hub.Host(ev.Host)
	out, err := s.overviewPartial("overview-cpu-body", views.NewOverviewCPU(info.Model, &m))
	if err != nil {
		s.log.Error("render overview cpu", "err", err)
		return "", "", false
	}
	return sseOverviewCPU, out, true
}

func (s *Server) renderOverviewMem(_ *http.Request, ev grid.Event) (string, string, bool) {
	m, ok := overviewMetrics(ev)
	if !ok {
		return "", "", false
	}
	info, _ := s.hub.Host(ev.Host)
	snap, _ := s.hub.Snapshot(ev.Host)
	out, err := s.overviewPartial("overview-mem-body", views.NewOverviewMem(&m, snap.CPUHistory, overviewShellHref(info)))
	if err != nil {
		s.log.Error("render overview memory", "err", err)
		return "", "", false
	}
	return sseOverviewMem, out, true
}

func (s *Server) renderOverviewServices(_ *http.Request, ev grid.Event) (string, string, bool) {
	sv, ok := overviewServices(ev)
	if !ok {
		return "", "", false
	}
	info, known := s.hub.Host(ev.Host)
	if !known {
		return "", "", false
	}
	out, err := s.overviewPartial("overview-svc-body", views.NewOverviewServices(info.Name, &sv, info.HasCapability(protocol.CapServices), overviewRestartURL(info)))
	if err != nil {
		s.log.Error("render overview services", "err", err)
		return "", "", false
	}
	return sseOverviewSvc, out, true
}

// renderOverviewState tells the open page that a host changed between online and offline. The payload is
// only a marker; overview.js reloads the page so tabs, pill and sidebar are rebuilt by the server.
func (s *Server) renderOverviewState(_ *http.Request, ev grid.Event) (string, string, bool) {
	switch ev.Payload.(type) {
	case grid.HostInfo, *grid.HostInfo:
	default:
		return "", "", false
	}
	state := "offline"
	if ev.Kind == grid.EventHostOnline {
		state = "online"
	}
	return sseOverviewState, html.EscapeString(string(ev.Host) + " " + state), true
}

// overviewPartial renders a partial into a string for an SSE payload.
func (s *Server) overviewPartial(name string, data any) (string, error) {
	if s.renderer == nil {
		return "", errors.New("no renderer")
	}
	w := &overviewBuf{}
	if err := s.renderer.RenderPartial(w, name, data); err != nil {
		return "", err
	}
	return strings.TrimSpace(w.buf.String()), nil
}

// overviewBuf is a minimal http.ResponseWriter that collects the body.
type overviewBuf struct {
	buf bytes.Buffer
	hdr http.Header
}

func (b *overviewBuf) Header() http.Header {
	if b.hdr == nil {
		b.hdr = http.Header{}
	}
	return b.hdr
}
func (b *overviewBuf) Write(p []byte) (int, error) { return b.buf.Write(p) }
func (b *overviewBuf) WriteHeader(int)             {}
