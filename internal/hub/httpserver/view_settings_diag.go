package httpserver

import (
	"log/slog"
	"net/http"

	"github.com/phabioo/nexara/internal/hub/views"
)

// logDialogLines is how many log lines the dialog shows at most.
const logDialogLines = 300

// routesSettingsDiag registers the Diagnostics card.
//
//	GET /settings/logs/hub?level=all|warn|error   the hub log in a dialog, newest first
//
// Only the hub's own log exists in v0.2. Showing an agent's log needs a new agent capability; the buttons for the
// hosts come with that version (decision #31).
func (s *Server) routesSettingsDiag(mux *http.ServeMux) {
	mux.HandleFunc("GET /settings/logs/hub", s.handleHubLog)
}

func (s *Server) diagCard() views.SettingsDiag {
	d := views.SettingsDiag{Text: "Log of the hub, newest first. Agent logs come with a later version."}
	if s.svc.Logs != nil {
		d.HubLogURL = "/settings/logs/hub"
	}
	return d
}

// logFilters are the level filters of the dialog, in display order.
var logFilters = []struct {
	Key, Label string
	Min        slog.Level
}{
	{"all", "All", slog.LevelDebug},
	{"warn", "Warnings", slog.LevelWarn},
	{"error", "Errors", slog.LevelError},
}

func (s *Server) handleHubLog(w http.ResponseWriter, r *http.Request) {
	if s.svc.Logs == nil {
		s.toastError(w, r, http.StatusNotFound, "Not available", "The hub log is not available here.")
		return
	}
	level := r.URL.Query().Get("level")
	min := slog.LevelDebug
	known := false
	for _, f := range logFilters {
		if f.Key == level {
			min, known = f.Min, true
		}
	}
	if !known {
		level = "all"
	}
	now := s.now()
	d := views.SettingsLog{Limit: logDialogLines}
	for _, rec := range s.svc.Logs.Records() {
		if rec.Level < min {
			continue
		}
		d.Total++
		if len(d.Lines) < logDialogLines {
			d.Lines = append(d.Lines, views.NewSettingsLogLine(now, rec.Time, rec.Level, rec.Text))
		}
	}
	d.Shown = len(d.Lines)
	d.Empty = "Nothing logged at this level."
	for _, f := range logFilters {
		d.Filters = append(d.Filters, views.SettingsChoice{Label: f.Label, Value: f.Key, On: f.Key == level, URL: "/settings/logs/hub?level=" + f.Key})
	}
	s.writeFragments(w, r, http.StatusOK, fragment{"settings-hub-log", d})
}
