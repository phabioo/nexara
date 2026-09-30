package httpserver

import "net/http"

// routesPackages registers the packages view and its actions (hx-post). Start
// jobs with s.hub.StartJob(ctx, ActorFrom(r), host.ID, spec); grid audits them.
//
// TODO(wave 3): register the SSE renderers for package and job events here.
func (s *Server) routesPackages(mux *http.ServeMux) {
	mux.HandleFunc("GET /hosts/{host}/packages", s.notImplemented)
	mux.HandleFunc("POST /hosts/{host}/packages/{action}", s.notImplemented)
}
