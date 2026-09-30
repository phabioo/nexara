package httpserver

import "net/http"

// routesAddHost registers the Add-host dialog and its submit. Enrollment goes
// through s.enroller (grid.Enroller). "new" is reserved: a host cannot be
// called that, because /hosts/new wins over /hosts/{host}.
func (s *Server) routesAddHost(mux *http.ServeMux) {
	mux.HandleFunc("GET /hosts/new", s.notImplemented)
	mux.HandleFunc("POST /hosts/new", s.notImplemented)
}
