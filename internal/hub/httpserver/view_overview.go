package httpserver

import "net/http"

// routesOverview registers the live overview. GET / shows s.defaultHost();
// GET /hosts/{host} a specific one (use s.requireHost).
//
// TODO(wave 3): register the SSE renderers of this view here, e.g.
// s.sse.Register(grid.EventMetrics, s.renderMetricsFragment).
func (s *Server) routesOverview(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", s.notImplemented)
	mux.HandleFunc("GET /hosts/{host}", s.notImplemented)
}
