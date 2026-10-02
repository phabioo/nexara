package httpserver

import "net/http"

// routesAudit registers the full audit log (wave 8), linked from the Audit log
// card in Settings. It is part of the Settings section of the navigation.
func (s *Server) routesAudit(mux *http.ServeMux) {
	mux.HandleFunc("GET /settings/audit", s.notImplemented)
}
