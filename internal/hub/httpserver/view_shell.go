package httpserver

import "net/http"

// routesShell registers the Nexara Shell page. The WebSocket behind it
// (GET /hosts/{host}/shell/ws) is infrastructure and lives in shellws.go; the
// page must pass the session's CSRF token as the ?csrf= query parameter.
func (s *Server) routesShell(mux *http.ServeMux) {
	mux.HandleFunc("GET /hosts/{host}/shell", s.notImplemented)
}
