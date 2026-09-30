package httpserver

import (
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

func (s *Server) routeEvents(mux *http.ServeMux) {
	mux.HandleFunc("GET /events", s.handleEvents)
	mux.HandleFunc("GET /events/ping", s.handleEventsPing)
	s.registerLive()
}

// handleEventsPing answers 204 for a valid session. nexus.js asks it after the event stream broke: an
// expired session shows up as a redirect to /login (the middleware), which EventSource cannot see by itself.
func (s *Server) handleEventsPing(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

// handleEvents streams hub events as server-sent events. ?host=<name> limits
// the stream to one host (host-level events still pass). The session is
// required (middleware). The stream ends when the client disconnects or the
// server shuts down.
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
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
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
				if _, err := w.Write(formatSSE(name, html)); err != nil {
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
// field (a bare newline would end the event). CR and LF in the event name are dropped.
func formatSSE(event, data string) []byte {
	var b strings.Builder
	if event = strings.NewReplacer("\r", "", "\n", "").Replace(event); event != "" {
		b.WriteString("event: " + event + "\n")
	}
	data = strings.ReplaceAll(data, "\r\n", "\n")
	data = strings.ReplaceAll(data, "\r", "\n")
	for _, line := range strings.Split(data, "\n") {
		b.WriteString("data: " + line + "\n")
	}
	b.WriteString("\n")
	return []byte(b.String())
}
