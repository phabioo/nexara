package httpserver

import (
	"encoding/csv"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/hub/views"
)

// Limits of the audit view.
const (
	auditResultsTarget = "audit-results" // HX-Target of the filter bar
	auditCSVPage       = 500             // rows per query while streaming the export
	auditCSVMax        = 200_000         // rows of one export
)

// auditPage is the data of pages/audit.html.
type auditPage struct {
	views.Layout
	A views.AuditModel
}

// routesAudit registers the full audit log, linked from the Audit log card in
// Settings. It belongs to the Settings section of the navigation.
//
//	GET /settings/audit?host=&user=&group=&result=&range=&q=   page; fragment for the filter bar (HX-Target audit-results)
//	GET /settings/audit?...&cursor=C                           HTMX only: the next rows ("Show more")
//	GET /settings/audit.csv?...                                the current filter as CSV, streamed
func (s *Server) routesAudit(mux *http.ServeMux) {
	mux.HandleFunc("GET /settings/audit", s.handleAudit)
	mux.HandleFunc("GET /settings/audit.csv", s.handleAuditCSV)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	st := s.svc.Store
	if st == nil || s.renderer == nil {
		s.notImplemented(w, r)
		return
	}
	q := views.ParseAuditQuery(r.URL.Query())
	now := s.now()
	entries, next, err := st.QueryAudit(r.Context(), q.Filter(now, views.AuditPageSize))
	if errors.Is(err, store.ErrBadAuditCursor) {
		s.renderStub(w, http.StatusBadRequest, "Bad request")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	in := views.AuditInput{Query: q, Entries: entries, Next: next, Now: now, Loc: time.Local}

	w.Header().Add("Vary", "HX-Request, HX-Target")
	if isHTMXRequest(r) && (q.Cursor != "" || r.Header.Get("HX-Target") == auditResultsTarget) {
		name := "audit-results"
		if q.Cursor != "" {
			name = "audit-more"
		}
		if err := s.renderer.RenderPartial(w, name, views.BuildAudit(in)); err != nil {
			s.serverError(w, r, err)
		}
		return
	}
	// The facets feed the drop-downs, which only the full page has.
	if in.Hosts, in.Users, err = st.AuditFacets(r.Context(), 0); err != nil {
		s.serverError(w, r, err)
		return
	}
	l := s.layout(r, "settings", nil)
	l.Title = "Audit log"
	if err := s.renderer.Render(w, "audit", auditPage{Layout: l, A: views.BuildAudit(in)}); err != nil {
		s.serverError(w, r, err)
	}
}

// csvCell neutralizes spreadsheet formulas: a cell that starts with = + - @
// (or a tab or carriage return, which some programs strip first) gets a
// leading apostrophe.
func csvCell(v string) string {
	if v == "" {
		return v
	}
	switch v[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + v
	}
	return v
}

func (s *Server) handleAuditCSV(w http.ResponseWriter, r *http.Request) {
	st := s.svc.Store
	if st == nil {
		s.notImplemented(w, r)
		return
	}
	q := views.ParseAuditQuery(r.URL.Query())
	q.Cursor = ""
	now := s.now()
	f := q.Filter(now, auditCSVPage)

	// Read the first page before the headers go out, so a failure is still a real status.
	entries, next, err := st.QueryAudit(r.Context(), f)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/csv; charset=utf-8")
	h.Set("Content-Disposition", `attachment; filename="nexara-audit-`+now.UTC().Format("20060102-150405")+`.csv"`)
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"time", "operator", "host", "action", "result", "detail"})
	flusher, _ := w.(http.Flusher)
	written := 0
	for {
		for _, e := range entries {
			_ = cw.Write([]string{e.Time.UTC().Format(time.RFC3339), csvCell(e.User), csvCell(e.Host),
				csvCell(e.Action), csvCell(e.Result), csvCell(e.Detail)})
			written++
		}
		cw.Flush()
		if flusher != nil {
			flusher.Flush()
		}
		if next == "" || written >= auditCSVMax || cw.Error() != nil || r.Context().Err() != nil {
			break
		}
		f.Cursor = next
		if entries, next, err = st.QueryAudit(r.Context(), f); err != nil {
			s.log.Error("audit export", "err", err)
			return // the stream is cut; the client sees a truncated file
		}
	}
	s.exportAudited(r, written)
}

// exportAudited records the export in the audit log (best effort).
func (s *Server) exportAudited(r *http.Request, rows int) {
	if s.svc.Store == nil {
		return
	}
	_, err := s.svc.Store.AppendAudit(r.Context(), store.AuditEntry{
		User: operatorName(r), Action: "audit.export", Result: store.AuditOK, Detail: strconv.Itoa(rows) + " rows",
	})
	if err != nil {
		s.log.Warn("audit export entry failed", "err", err)
	}
}
