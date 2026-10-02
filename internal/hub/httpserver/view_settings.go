package httpserver

import "net/http"

// routesSettings registers the Settings view (wave 8): the eight cards of the
// mockup. Sub-routes for card actions live under /settings/… .
func (s *Server) routesSettings(mux *http.ServeMux) {
	mux.HandleFunc("GET /settings", s.notImplemented)
}
