package httpserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/phabioo/nexara/internal/hub/grid"
)

func TestGridStatus(t *testing.T) {
	tests := []struct {
		err  error
		want int
	}{
		{nil, http.StatusOK},
		{grid.ErrHostNotFound, http.StatusNotFound},
		{grid.ErrJobNotFound, http.StatusNotFound},
		{grid.ErrInvalidArgument, http.StatusBadRequest},
		{grid.ErrCapabilityDisabled, http.StatusForbidden},
		{grid.ErrHostOffline, http.StatusConflict},
		{grid.ErrJobBusy, http.StatusConflict},
		{grid.ErrJobFinished, http.StatusConflict},
		{grid.ErrHostExists, http.StatusConflict},
		{grid.ErrUnsupported, http.StatusUnprocessableEntity},
		{grid.ErrLinkFailed, http.StatusBadGateway},
		{context.DeadlineExceeded, http.StatusGatewayTimeout},
		{errors.New("boom"), http.StatusInternalServerError},
		// Wrapped errors, as the hub returns them ("%w: detail").
		{fmt.Errorf("%w: unit name %q", grid.ErrInvalidArgument, "x"), http.StatusBadRequest},
		{fmt.Errorf("no answer within 30s: %w", context.DeadlineExceeded), http.StatusGatewayTimeout},
		{fmt.Errorf("%w at step connect: %w", grid.ErrLinkFailed, errors.New("refused")), http.StatusBadGateway},
	}
	for _, tt := range tests {
		if got := gridStatus(tt.err); got != tt.want {
			t.Errorf("gridStatus(%v) = %d, want %d", tt.err, got, tt.want)
		}
	}
}

func TestGridMessage(t *testing.T) {
	all := []error{
		grid.ErrHostNotFound, grid.ErrJobNotFound, grid.ErrInvalidArgument, grid.ErrCapabilityDisabled,
		grid.ErrHostOffline, grid.ErrJobBusy, grid.ErrJobFinished, grid.ErrHostExists, grid.ErrUnsupported,
		grid.ErrLinkFailed, context.DeadlineExceeded, errors.New("boom"),
	}
	seen := map[string]error{}
	for _, err := range all {
		msg := gridMessage(err)
		if msg == "" {
			t.Errorf("no message for %v", err)
		}
		if strings.Contains(msg, "grid:") || strings.Contains(msg, "boom") {
			t.Errorf("message for %v leaks internals: %q", err, msg)
		}
		// Every distinct condition has its own text (the fallback is the last entry).
		if prev, dup := seen[msg]; dup {
			t.Errorf("%v and %v share the message %q", prev, err, msg)
		}
		seen[msg] = err
	}
	if gridMessage(nil) != "" {
		t.Error("nil must have no message")
	}
	if got := gridMessage(fmt.Errorf("%w: ssh password hunter2 rejected", grid.ErrLinkFailed)); strings.Contains(got, "hunter2") {
		t.Errorf("message echoes error detail: %q", got)
	}
}

func TestGridError(t *testing.T) {
	e := newEnv(t)
	tests := []struct {
		err       error
		status    int
		logsCause bool
	}{
		{grid.ErrHostOffline, http.StatusConflict, false},
		{grid.ErrHostNotFound, http.StatusNotFound, false},
		{errors.New("database exploded"), http.StatusInternalServerError, true},
	}
	for _, tt := range tests {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/hosts/alpha/services/x/restart", nil)
		e.srv.gridError(rec, r, tt.err)
		if rec.Code != tt.status {
			t.Errorf("%v: status %d, want %d", tt.err, rec.Code, tt.status)
		}
		if body := rec.Body.String(); strings.Contains(body, "exploded") || strings.TrimSpace(body) != gridMessage(tt.err) {
			t.Errorf("%v: body %q", tt.err, body)
		}
		if got := strings.Contains(e.logs.String(), "database exploded"); got != tt.logsCause {
			t.Errorf("%v: cause logged = %v, want %v", tt.err, got, tt.logsCause)
		}
	}
}
