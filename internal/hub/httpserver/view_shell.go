package httpserver

import (
	"errors"
	"html"
	"net/http"
	"net/url"
	"strconv"

	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/hub/views"
	"github.com/phabioo/nexara/internal/protocol"
)

// shellStateEvent is the SSE event the offline state of the shell page waits
// for: it reports when a host goes online or offline so the page can reload.
const shellStateEvent = "shell-host-state"

// routesShell registers the Nexara Shell page. The WebSocket behind it
// (GET /hosts/{host}/shell/ws) is infrastructure and lives in shellws.go; the
// page passes the session's CSRF token as the ?csrf= query parameter.
func (s *Server) routesShell(mux *http.ServeMux) {
	mux.HandleFunc("GET /hosts/{host}/shell", s.handleShellPage)
	s.sse.Register(grid.EventHostOnline, renderShellHostState)
	s.sse.Register(grid.EventHostOffline, renderShellHostState)
}

// shellPageState decides what the page shows for a host: the terminal, the
// offline card (no connect attempt) or the "shell disabled" card.
func shellPageState(h grid.HostInfo) string {
	switch {
	case !h.Online:
		return views.ShellOffline
	case !h.HasCapability(protocol.CapShell):
		return views.ShellDisabled
	default:
		return views.ShellReady
	}
}

// shellWSURL is the WebSocket path for a host including the CSRF token the
// handshake requires (browsers cannot set headers on a WebSocket).
func shellWSURL(host, csrf string) string {
	return hostURL(host) + "/shell/ws?csrf=" + url.QueryEscape(csrf)
}

func (s *Server) handleShellPage(w http.ResponseWriter, r *http.Request) {
	host, ok := s.requireHost(w, r)
	if !ok {
		return
	}
	l := s.layout(r, "shell", &host)
	l.Title = "Shell"
	page := views.ShellPage{
		Layout:  l,
		State:   shellPageState(host),
		Host:    host.Name,
		Label:   hostLabel(host),
		Address: host.Address,
		Version: views.KernelVersion(host.Kernel),
		BackURL: hostURL(host.Name),
		Keys:    views.ShellKeys(),
	}
	switch page.State {
	case views.ShellReady:
		page.WSURL = shellWSURL(host.Name, l.CSRF)
	case views.ShellOffline:
		page.EventsURL = "/events?host=" + url.QueryEscape(host.Name)
	}
	if s.renderer == nil {
		s.serverError(w, r, errors.New("shell page: no renderer configured"))
		return
	}
	if err := s.renderer.Render(w, "shell", page); err != nil {
		s.serverError(w, r, err)
	}
}

// renderShellHostState tells an open shell page that a host changed state. The
// fragment is an invisible marker; shell.js compares it with the page state.
func renderShellHostState(_ *http.Request, ev grid.Event) (string, string, bool) {
	info, ok := ev.Payload.(grid.HostInfo)
	if !ok {
		return "", "", false
	}
	online := ev.Kind == grid.EventHostOnline
	return shellStateEvent,
		`<i data-host="` + html.EscapeString(info.Name) + `" data-online="` + strconv.FormatBool(online) + `"></i>`,
		true
}
