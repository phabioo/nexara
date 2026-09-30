package httpserver

import (
	"context"
	"errors"
	"net/http"

	"github.com/phabioo/nexara/internal/hub/grid"
)

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

// gridStatus is the one mapping from errors of grid.Hub / grid.Enroller to an
// HTTP status. Views use it for every failed hub call so the same condition
// always yields the same status:
//
//	ErrHostNotFound, ErrJobNotFound        404
//	ErrInvalidArgument                     400
//	ErrCapabilityDisabled                  403  (switched off for this host)
//	ErrHostOffline, ErrJobBusy,
//	ErrJobFinished, ErrHostExists          409  (state conflict)
//	ErrUnsupported                         422
//	ErrLinkFailed                          502  (the remote host misbehaved)
//	context.DeadlineExceeded               504  (the agent did not answer)
//	anything else                          500
//
// nil maps to 200.
func gridStatus(err error) int {
	switch {
	case err == nil:
		return http.StatusOK
	case errors.Is(err, grid.ErrHostNotFound), errors.Is(err, grid.ErrJobNotFound):
		return http.StatusNotFound
	case errors.Is(err, grid.ErrInvalidArgument):
		return http.StatusBadRequest
	case errors.Is(err, grid.ErrCapabilityDisabled):
		return http.StatusForbidden
	case errors.Is(err, grid.ErrHostOffline), errors.Is(err, grid.ErrJobBusy),
		errors.Is(err, grid.ErrJobFinished), errors.Is(err, grid.ErrHostExists):
		return http.StatusConflict
	case errors.Is(err, grid.ErrUnsupported):
		return http.StatusUnprocessableEntity
	case errors.Is(err, grid.ErrLinkFailed):
		return http.StatusBadGateway
	case errors.Is(err, context.DeadlineExceeded):
		return http.StatusGatewayTimeout
	default:
		return http.StatusInternalServerError
	}
}

// gridMessage is the short, fixed, user-facing text for a failed hub call.
// It never echoes err (which may carry host output), so it is safe to render.
// Views that need a more specific text (for example the Add-host dialog, which
// shows the failing step) build their own.
func gridMessage(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, grid.ErrHostNotFound):
		return "Host not found."
	case errors.Is(err, grid.ErrJobNotFound):
		return "Job not found."
	case errors.Is(err, grid.ErrInvalidArgument):
		return "The request was not valid."
	case errors.Is(err, grid.ErrCapabilityDisabled):
		return "This feature is switched off for the host."
	case errors.Is(err, grid.ErrHostOffline):
		return "The host is offline."
	case errors.Is(err, grid.ErrJobBusy):
		return "The same job is already queued or running."
	case errors.Is(err, grid.ErrJobFinished):
		return "The job has already finished."
	case errors.Is(err, grid.ErrHostExists):
		return "A host with this name already exists."
	case errors.Is(err, grid.ErrUnsupported):
		return "Not supported on this host."
	case errors.Is(err, grid.ErrLinkFailed):
		return "Linking the host failed."
	case errors.Is(err, context.DeadlineExceeded):
		return "The host did not answer in time."
	default:
		return "Something went wrong."
	}
}

// gridError answers a failed hub call with gridStatus and gridMessage. Server
// errors (5xx other than a gateway timeout, which is routine) are logged with
// the cause; the cause is never sent to the browser.
func (s *Server) gridError(w http.ResponseWriter, r *http.Request, err error) {
	status := gridStatus(err)
	if status == http.StatusInternalServerError {
		s.log.Error("hub call failed", "method", r.Method, "path", logPath(r), "err", err)
	}
	s.renderStub(w, status, gridMessage(err))
}
