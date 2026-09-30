package httpserver

import "net/http"

// renderStub writes a plain-text page. It stands in for template rendering
// until the views of wave 3 exist; do not build on it.
func (s *Server) renderStub(w http.ResponseWriter, status int, text string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(text + "\n"))
}

// notFound is the 404 page (plain text for now).
func (s *Server) notFound(w http.ResponseWriter, _ *http.Request) {
	s.renderStub(w, http.StatusNotFound, "Not found")
}

// notImplemented is the body of every view stub.
func (s *Server) notImplemented(w http.ResponseWriter, _ *http.Request) {
	s.renderStub(w, http.StatusNotImplemented, "Not implemented")
}

// serverError logs err and answers 500 without details.
func (s *Server) serverError(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Error("request failed", "method", r.Method, "path", logPath(r), "err", err)
	s.renderStub(w, http.StatusInternalServerError, "Internal Server Error")
}
