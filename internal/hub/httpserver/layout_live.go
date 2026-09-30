package httpserver

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/hub/views"
	"github.com/phabioo/nexara/internal/protocol"
)

// sseLive is the one SSE event of the app shell. Its payload is a set of tiny hx-swap-oob elements that
// update the parts of the shell every page shows: the temperature and packages pills, the sidebar
// uptime, the job chip and the log line. layouts/app.html carries the sink (sse-swap="nx-live") on
// every page with an event stream, so views do not need to know about any of this.
const sseLive = "nx-live"

// liveJob is the data of the "live-job" template.
type liveJob struct {
	Chip *views.JobChip
	Log  string
}

// registerLive adds the renderers of the shell's live values (called once from routeEvents).
func (s *Server) registerLive() {
	s.sse.Register(grid.EventMetrics, s.renderLiveMetrics)
	s.sse.Register(grid.EventPackages, s.renderLivePackages)
	for _, k := range []grid.EventKind{grid.EventJobQueued, grid.EventJobStarted, grid.EventJobDone} {
		s.sse.Register(k, s.renderLiveJob)
	}
}

// renderLiveMetrics updates the temperature pill and the uptime of the sidebar card. Fragments the page
// does not contain (a host without a sensor) are dropped client-side (nexus.js).
func (s *Server) renderLiveMetrics(_ *http.Request, ev grid.Event) (string, string, bool) {
	m, ok := eventMetrics(ev)
	if !ok {
		return "", "", false
	}
	var parts []string
	if m.TempC != nil {
		parts = append(parts, s.liveFragment("live-temp", fmt.Sprintf("%.1f", *m.TempC)))
	}
	parts = append(parts, s.liveFragment("live-uptime", formatUptime(m.UptimeSeconds)))
	return joinLive(parts)
}

// renderLivePackages updates the "up to date / installed" pill.
func (s *Server) renderLivePackages(_ *http.Request, ev grid.Event) (string, string, bool) {
	var p protocol.Packages
	switch v := ev.Payload.(type) {
	case protocol.Packages:
		p = v
	case *protocol.Packages:
		if v == nil {
			return "", "", false
		}
		p = *v
	default:
		return "", "", false
	}
	return joinLive([]string{s.liveFragment("live-pkg", packagePill(&p))})
}

// renderLiveJob updates the job chip and the log line of the status bar on every page.
func (s *Server) renderLiveJob(_ *http.Request, ev grid.Event) (string, string, bool) {
	j, ok := ev.Payload.(grid.Job)
	if !ok {
		return "", "", false
	}
	host, known := s.hub.Host(ev.Host)
	if !known {
		return "", "", false
	}
	d := liveJob{Chip: views.JobChipFor(hostURL(host.Name), s.hub.Jobs(ev.Host)), Log: jobLogLine(j)}
	return joinLive([]string{s.liveFragment("live-job", d)})
}

func joinLive(parts []string) (string, string, bool) {
	out := strings.Join(parts, "\n")
	return sseLive, out, strings.TrimSpace(out) != ""
}

// liveFragment renders one template of the shell partials; a failure yields an empty string (logged).
func (s *Server) liveFragment(name string, data any) string {
	out, err := s.partialString(name, data)
	if err != nil {
		s.log.Error("render live fragment", "name", name, "err", err)
		return ""
	}
	return strings.TrimSpace(out)
}

// eventMetrics extracts the sample from a metrics event (value or pointer payload).
func eventMetrics(ev grid.Event) (protocol.Metrics, bool) {
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

// partialString renders a named partial (an HTMX fragment) into a string, for SSE payloads and error
// bodies. Nothing is written anywhere on error.
func (s *Server) partialString(name string, data any) (string, error) {
	if s.renderer == nil {
		return "", errors.New("httpserver: no renderer configured")
	}
	buf := &fragmentBuffer{}
	if err := s.renderer.RenderPartial(buf, name, data); err != nil {
		return "", err
	}
	return buf.body.String(), nil
}

// fragmentBuffer is the http.ResponseWriter the renderer writes a fragment into.
type fragmentBuffer struct {
	hdr  http.Header
	body bytes.Buffer
}

func (b *fragmentBuffer) Header() http.Header {
	if b.hdr == nil {
		b.hdr = http.Header{}
	}
	return b.hdr
}
func (b *fragmentBuffer) Write(p []byte) (int, error) { return b.body.Write(p) }
func (b *fragmentBuffer) WriteHeader(int)             {}
