package httpserver

import "net/http"

// routesSetup registers the first-run wizard. The setup gate (middleware) lets
// only these paths through while no operator exists; POSTs use the double-submit
// CSRF token (see ensureCSRFCookie) and the setup session cookie of package setup.
//
// TODO(wave 3): after the final commit call s.setup.Mode.Invalidate() so the
// gate opens, and s.setup.Sessions.Clear().
func (s *Server) routesSetup(mux *http.ServeMux) {
	mux.HandleFunc("GET /setup", s.notImplemented)
	mux.HandleFunc("POST /setup", s.notImplemented)
	mux.HandleFunc("GET /setup/{step}", s.notImplemented)
	mux.HandleFunc("POST /setup/{step}", s.notImplemented)
}
