package httpserver

import "net/http"

// routesHistory registers the History view (wave 8): GET /history shows the
// default host, GET /hosts/{host}/history a specific one. Data comes from
// s.svc.History (history.Service.Series).
func (s *Server) routesHistory(mux *http.ServeMux) {
	mux.HandleFunc("GET /history", s.notImplemented)
	mux.HandleFunc("GET /hosts/{host}/history", s.notImplemented)
}
