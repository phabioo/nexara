package httpserver

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/phabioo/nexara/internal/hub/grid"
)

// EventRenderer turns a hub event into one named SSE event carrying an HTML
// fragment. It returns ok=false to skip the event (nothing to show for this
// page). r is the request of the open /events stream (session context,
// query); it must not write to a response.
type EventRenderer func(r *http.Request, ev grid.Event) (event string, html string, ok bool)

// EventRegistry maps hub event kinds to renderers. Views register theirs from
// their routes<View> function via s.sse.Register; registration must happen
// before the server starts serving.
type EventRegistry struct {
	mu sync.RWMutex
	m  map[grid.EventKind][]EventRenderer
}

func newEventRegistry() *EventRegistry {
	return &EventRegistry{m: map[grid.EventKind][]EventRenderer{}}
}

// Register adds a renderer for an event kind. Several renderers per kind are
// allowed; each produces its own SSE event.
func (g *EventRegistry) Register(kind grid.EventKind, fn EventRenderer) {
	g.mu.Lock()
	g.m[kind] = append(g.m[kind], fn)
	g.mu.Unlock()
}

func (g *EventRegistry) renderers(kind grid.EventKind) []EventRenderer {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.m[kind]
}

// hostLevel events concern the host list shown on every page (tabs), so they
// are delivered regardless of the host filter.
func hostLevel(k grid.EventKind) bool {
	switch k {
	case grid.EventHostOnline, grid.EventHostOffline, grid.EventHostAdded, grid.EventHostRemoved:
		return true
	}
	return false
}

// hostAgnostic are the SSE events whose payload does not belong to the host on screen: the job dialog and
// its toasts are addressed by job id, and the host-list event names its host in the payload. Every other
// event is about one host and carries that host's short name as the SSE id, see eventID.
var hostAgnostic = map[string]bool{packagesEventJob: true, sseHosts: true}

// eventID is the SSE id field of an event: the short name of the host the fragment belongs to, or "" for
// host-agnostic events. The stream of a page is not filtered by host (the page keeps one connection while the
// operator switches hosts), so nexus.js compares this id with the host on screen (<main data-host>) and drops
// the events of other hosts before they reach the DOM. The field is always written, empty included: the
// browser would otherwise carry the id of the previous event over.
func (s *Server) eventID(name string, ev grid.Event) string {
	if hostAgnostic[name] {
		return ""
	}
	return s.eventHostName(ev)
}

// eventHostName is the short name of the host an event is about; "" if it cannot be told.
func (s *Server) eventHostName(ev grid.Event) string {
	switch info := ev.Payload.(type) {
	case grid.HostInfo:
		return info.Name
	case *grid.HostInfo:
		if info != nil {
			return info.Name
		}
	}
	if h, ok := s.hub.Host(ev.Host); ok {
		return h.Name
	}
	return ""
}

func (s *Server) routeEvents(mux *http.ServeMux) {
	mux.HandleFunc("GET /events", s.handleEvents)
	mux.HandleFunc("GET /events/ping", s.handleEventsPing)
	s.registerLive()
	s.registerHostEvents()
}

// handleEventsPing answers 204 for a valid session. nexus.js asks it after the event stream broke: an
// expired session shows up as a redirect to /login (the middleware), which EventSource cannot see by itself.
func (s *Server) handleEventsPing(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

// handleEvents streams hub events as server-sent events. The app pages open it without a filter; ?host=<name> limits
// the stream to one host (host-level events still pass). The session is
// required (middleware). The stream ends when the client disconnects, the
// server shuts down or the session ends (see sessionGuard).
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	var filter grid.HostID
	if name := r.URL.Query().Get("host"); name != "" {
		h, ok := s.hostByName(name)
		if !ok {
			s.notFound(w, r)
			return
		}
		filter = h.ID
	}
	guard, ok := s.guardFor(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	// A stream outlives any server write timeout.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})

	ctx, cancel := contextWithDone(r.Context(), s.streamsDone)
	defer cancel()
	events := s.hub.Subscribe(ctx)

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("retry: 2000\n\n"))
	flusher.Flush()

	tick := time.NewTicker(s.sseHeartbeat)
	defer tick.Stop()
	revoked := guard.revoked()
	for {
		select {
		case <-ctx.Done():
			return
		case <-revoked:
			// Re-arm first, then look: a revocation after the check is not lost.
			revoked = guard.revoked()
			if !guard.alive(ctx) {
				return
			}
		case <-tick.C:
			// The heartbeat also finds sessions that ended by time. The
			// client's reconnect then gets a 401 and nexus.js goes to /login.
			if !guard.alive(ctx) {
				return
			}
			if _, err := w.Write([]byte(": ping\n\n")); err != nil {
				return
			}
			flusher.Flush()
		case ev, open := <-events:
			if !open {
				return
			}
			if filter != "" && ev.Host != filter && !hostLevel(ev.Kind) {
				continue
			}
			wrote := false
			for _, render := range s.sse.renderers(ev.Kind) {
				name, html, ok := render(r, ev)
				if !ok {
					continue
				}
				if _, err := w.Write(formatSSE(name, s.eventID(name, ev), html)); err != nil {
					return
				}
				wrote = true
			}
			if wrote {
				flusher.Flush()
			}
		}
	}
}

// formatSSE encodes one event; every line of the payload gets its own data:
// field (a bare newline would end the event). CR, LF and NUL in the event name and the id are dropped.
func formatSSE(event, id, data string) []byte {
	clean := strings.NewReplacer("\r", "", "\n", "", "\x00", "")
	var b strings.Builder
	if event = clean.Replace(event); event != "" {
		b.WriteString("event: " + event + "\n")
	}
	b.WriteString("id: " + clean.Replace(id) + "\n")
	data = strings.ReplaceAll(data, "\r\n", "\n")
	data = strings.ReplaceAll(data, "\r", "\n")
	for _, line := range strings.Split(data, "\n") {
		b.WriteString("data: " + line + "\n")
	}
	b.WriteString("\n")
	return []byte(b.String())
}

// sseHosts is the event that tells every open page that the host list changed (a host was added, removed,
// went online or offline, or its package counts moved). The payload is JSON {"kind": ..., "host": ...};
// nexus.js refreshes the shell regions and, where the host on screen is concerned, the main area.
const sseHosts = "nx-hosts"

// hostsEvent is the payload of sseHosts.
type hostsEvent struct {
	Kind string `json:"kind"` // added, removed, online, offline, packages
	Host string `json:"host"` // short name
}

// registerHostEvents adds the renderer of the host-list event (called once from routeEvents).
func (s *Server) registerHostEvents() {
	for _, k := range []grid.EventKind{grid.EventHostAdded, grid.EventHostRemoved, grid.EventHostOnline,
		grid.EventHostOffline, grid.EventPackages} {
		s.sse.Register(k, s.renderHostsEvent)
	}
}

func (s *Server) renderHostsEvent(_ *http.Request, ev grid.Event) (string, string, bool) {
	var kind string
	switch ev.Kind {
	case grid.EventHostAdded:
		kind = "added"
	case grid.EventHostRemoved:
		kind = "removed"
	case grid.EventHostOnline:
		kind = "online"
	case grid.EventHostOffline:
		kind = "offline"
	case grid.EventPackages:
		kind = "packages"
	default:
		return "", "", false
	}
	// A removed host is unknown to the hub by now; its HostInfo travels in the payload.
	host := s.eventHostName(ev)
	if host == "" {
		return "", "", false
	}
	out, err := json.Marshal(hostsEvent{Kind: kind, Host: host})
	if err != nil {
		return "", "", false
	}
	return sseHosts, string(out), true
}
