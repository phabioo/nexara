package httpserver

import (
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
)

// routes registers everything. View files add their routes through their own
// routes<View> function; nothing view-specific belongs in this file.
func (s *Server) routes(mux *http.ServeMux) {
	s.routeStatic(mux)
	s.routeGrid(mux)
	s.routeEvents(mux)
	s.routeShellWS(mux)

	s.routesLogin(mux)
	s.routesSetup(mux)
	s.routesOverview(mux)
	s.routesPackages(mux)
	s.routesShell(mux)
	s.routesAddHost(mux)

	mux.HandleFunc("/", s.notFound)
}

func (s *Server) routeStatic(mux *http.ServeMux) {
	files := http.FileServerFS(s.static)
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "" || strings.HasSuffix(r.URL.Path, "/") {
			s.notFound(w, r) // no directory listings
			return
		}
		files.ServeHTTP(w, r)
	})))
	mux.HandleFunc("GET /manifest.webmanifest", s.staticFile("img/manifest.webmanifest", "application/manifest+json"))
	mux.HandleFunc("GET /favicon.svg", s.staticFile("img/favicon.svg", "image/svg+xml"))
}

func (s *Server) staticFile(name, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := fs.ReadFile(s.static, name)
		if err != nil {
			s.notFound(w, r)
			return
		}
		w.Header().Set("Content-Type", contentType)
		_, _ = w.Write(data)
	}
}

// routeGrid mounts the handlers owned by the grid package. They authenticate
// themselves (mTLS for the agent, one-time token or code for enrollment).
func (s *Server) routeGrid(mux *http.ServeMux) {
	if s.agent != nil {
		mux.Handle("/grid/connect", s.agent)
		mux.Handle("/grid/agent/", s.agent)
	}
	if s.enroll != nil {
		mux.Handle("/grid/enroll", s.enroll)
		mux.Handle("/grid/install.sh", s.enroll)
		mux.Handle("/grid/download/", s.enroll)
	}
}

func (s *Server) requestLevel(r *http.Request, status int) slog.Level {
	switch {
	case status >= 500:
		return slog.LevelError
	case isStaticPath(r.URL.Path):
		return slog.LevelDebug
	default:
		return slog.LevelInfo
	}
}
