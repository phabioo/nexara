package httpserver

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/hub/views"
	"github.com/phabioo/nexara/internal/protocol"
)

// Limits of the packages view.
const (
	packagesQueryMax     = 64 // characters of the search term
	packageNameMax       = 128
	packagesSearchMin    = 2 // characters before the repositories are searched
	packagesSearchWait   = 10 * time.Second
	packagesRefreshWait  = 8 * time.Second
	packagesEventJob     = "pkg-job"     // SSE event: out-of-band updates of the job dialog and status bar
	packagesEventChanged = "pkg-changed" // SSE event: the list or the host state changed, reload the fragment
)

// packagesPage is the data of pages/packages.html.
type packagesPage struct {
	views.Layout
	P views.PackagesModel
}

// packagesJobEvent is the data of the "packages-job-state" partial.
type packagesJobEvent struct {
	Job   views.JobView
	Chip  *views.JobChip
	Log   string
	Toast *views.Toast
}

// routesPackages registers the packages view, its actions and the job dialog.
//
//	GET  /hosts/{host}/packages?filter=&q=        page; fragment for HTMX (filter, search, live refresh)
//	GET  /hosts/{host}/packages/confirm/{action}  confirm dialog (?package=)
//	POST /hosts/{host}/packages/{action}          start a job, answers with the job dialog
//	GET  /hosts/{host}/jobs/{job}                 job dialog (status-bar chip)
//	POST /hosts/{host}/jobs/{job}/cancel          cancel a queued or running job
//
// Actions are the job kinds with dashes: apt-update, apt-upgrade, apt-clean,
// pkg-install, pkg-remove, pkg-upgrade. The grid audits every job.
func (s *Server) routesPackages(mux *http.ServeMux) {
	mux.HandleFunc("GET /hosts/{host}/packages", s.handlePackages)
	mux.HandleFunc("GET /hosts/{host}/packages/confirm/{action}", s.handlePackagesConfirm)
	mux.HandleFunc("POST /hosts/{host}/packages/{action}", s.handlePackagesAction)
	mux.HandleFunc("GET /hosts/{host}/jobs/{job}", s.handleJobDialog)
	mux.HandleFunc("POST /hosts/{host}/jobs/{job}/cancel", s.handleJobCancel)

	for _, k := range []grid.EventKind{grid.EventJobQueued, grid.EventJobStarted, grid.EventJobDone} {
		s.sse.Register(k, s.renderPackagesJob)
	}
	s.sse.Register(grid.EventJobOutput, s.renderPackagesJobOutput)
	// Job events also move the maintenance cards (for example "sources read"), so they reload the fragment too.
	for _, k := range []grid.EventKind{grid.EventPackages, grid.EventHostOnline, grid.EventHostOffline,
		grid.EventJobQueued, grid.EventJobStarted, grid.EventJobDone} {
		s.sse.Register(k, s.renderPackagesChanged)
	}
}

// --- page --------------------------------------------------------------------

func (s *Server) handlePackages(w http.ResponseWriter, r *http.Request) {
	host, ok := s.requireHost(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	model, jobs := s.packagesModel(r, host, q.Get("filter"), q.Get("q"))

	w.Header().Add("Vary", "HX-Request")
	if isHTMXFragment(r) {
		s.packagesWrite(w, r, http.StatusOK, func(rd *views.Renderer, w http.ResponseWriter) error {
			return rd.RenderPartial(w, "packages-fragment", model)
		})
		return
	}
	l := s.layout(r, "packages", &host)
	l.Title = "Packages"
	if l.Log == "" {
		// s.layout only knows the last job; without one show the usual connection line.
		l.Log = "Connected to " + hostLabel(host)
	}
	l.Job = views.JobChipFor(hostURL(host.Name), jobs)
	s.packagesWrite(w, r, http.StatusOK, func(rd *views.Renderer, w http.ResponseWriter) error {
		return rd.Render(w, "packages", packagesPage{Layout: l, P: model})
	})
}

// isHTMXFragment reports whether the request wants a fragment: an HTMX request
// that is not the full-page fetch htmx does when restoring history.
func isHTMXFragment(r *http.Request) bool {
	return r.Header.Get("HX-Request") == "true" && r.Header.Get("HX-History-Restore-Request") != "true"
}

// packagesModel reads the host state and builds the view model. It also
// returns the host's jobs (newest first) for the status-bar chip.
func (s *Server) packagesModel(r *http.Request, host grid.HostInfo, filter, query string) (views.PackagesModel, []grid.Job) {
	capable := host.HasCapability(protocol.CapPackages)
	snap, _ := s.hub.Snapshot(host.ID)
	if snap.Packages == nil && host.Online && capable {
		// The first visit after the agent connected: ask for the list once.
		ctx, cancel := context.WithTimeout(r.Context(), packagesRefreshWait)
		if err := s.hub.RefreshPackages(ctx, host.ID); err != nil {
			s.log.Debug("packages refresh failed", "host", host.Name, "err", err)
		}
		cancel()
		snap, _ = s.hub.Snapshot(host.ID)
	}

	query = clampQuery(query)
	filter = views.NormalizePackageFilter(filter)
	var found []protocol.Package
	var note string
	if utf8.RuneCountInString(query) >= packagesSearchMin && host.Online && capable &&
		(filter == views.PackageFilterAll || filter == views.PackageFilterAvailable) {
		ctx, cancel := context.WithTimeout(r.Context(), packagesSearchWait)
		var err error
		found, err = s.hub.SearchPackages(ctx, host.ID, query)
		cancel()
		if err != nil {
			found = nil
			note = "Repository search is unavailable: " + gridMessage(err)
		}
	}

	jobs := s.hub.Jobs(host.ID)
	reboot := host.RebootRequired || (snap.Packages != nil && snap.Packages.RebootRequired)
	return views.BuildPackages(views.PackagesInput{
		HostLabel: hostLabel(host),
		HostPath:  hostURL(host.Name),
		HostName:  host.Name,
		Online:    host.Online,
		Capable:   capable,
		Data:      snap.Packages,
		Reboot:    reboot,
		Count:     packagePill(snap.Packages),
		Filter:    filter,
		Query:     query,
		Found:     found,
		Note:      note,
		Jobs:      jobs,
	}), jobs
}

// clampQuery trims the search term and cuts it to packagesQueryMax characters.
func clampQuery(q string) string {
	q = strings.TrimSpace(q)
	if utf8.RuneCountInString(q) > packagesQueryMax {
		q = string([]rune(q)[:packagesQueryMax])
	}
	return q
}

// --- actions -----------------------------------------------------------------

func (s *Server) handlePackagesConfirm(w http.ResponseWriter, r *http.Request) {
	host, ok := s.requireHost(w, r)
	if !ok {
		return
	}
	action, ok := views.LookupPackageAction(r.PathValue("action"))
	if !ok || !action.NeedsAsk {
		s.notFound(w, r)
		return
	}
	pkg := strings.TrimSpace(r.URL.Query().Get("package"))
	if action.NeedsPkg && (pkg == "" || len(pkg) > packageNameMax) {
		s.packagesError(w, r, grid.ErrInvalidArgument, "Not started")
		return
	}
	snap, _ := s.hub.Snapshot(host.ID)
	orphans := 0
	if snap.Packages != nil {
		for _, p := range snap.Packages.Items {
			if p.State == protocol.PackageOrphaned {
				orphans++
			}
		}
	}
	c, ok := views.NewPackagesConfirm(action, hostLabel(host), hostURL(host.Name), pkg, countUpdates(snap.Packages), orphans)
	if !ok {
		s.notFound(w, r)
		return
	}
	s.packagesWrite(w, r, http.StatusOK, func(rd *views.Renderer, w http.ResponseWriter) error {
		return rd.RenderPartial(w, "packages-confirm", c)
	})
}

func (s *Server) handlePackagesAction(w http.ResponseWriter, r *http.Request) {
	host, ok := s.requireHost(w, r)
	if !ok {
		return
	}
	action, ok := views.LookupPackageAction(r.PathValue("action"))
	if !ok {
		s.notFound(w, r)
		return
	}
	spec := grid.JobSpec{Kind: action.Kind}
	if action.NeedsPkg {
		spec.Package = strings.TrimSpace(r.PostFormValue("package"))
		if spec.Package == "" || len(spec.Package) > packageNameMax {
			s.packagesError(w, r, grid.ErrInvalidArgument, "Not started")
			return
		}
	}
	job, err := s.hub.StartJob(r.Context(), ActorFrom(r), host.ID, spec)
	if err != nil {
		s.packagesError(w, r, err, "Not started")
		return
	}
	s.writeJobDialog(w, r, host, job)
}

func (s *Server) handleJobDialog(w http.ResponseWriter, r *http.Request) {
	host, ok := s.requireHost(w, r)
	if !ok {
		return
	}
	job, ok := s.jobOf(host, r.PathValue("job"))
	if !ok {
		s.packagesError(w, r, grid.ErrJobNotFound, "Job not found")
		return
	}
	s.writeJobDialog(w, r, host, job)
}

func (s *Server) handleJobCancel(w http.ResponseWriter, r *http.Request) {
	host, ok := s.requireHost(w, r)
	if !ok {
		return
	}
	job, ok := s.jobOf(host, r.PathValue("job"))
	if !ok {
		s.packagesError(w, r, grid.ErrJobNotFound, "Not canceled")
		return
	}
	if err := s.hub.CancelJob(r.Context(), ActorFrom(r), job.ID); err != nil {
		s.packagesError(w, r, err, "Not canceled")
		return
	}
	// The new state arrives through the event stream.
	w.WriteHeader(http.StatusNoContent)
}

// jobOf finds a job of the host. Looking it up in the host's own list keeps a
// job of another host from being opened or canceled through this URL.
func (s *Server) jobOf(host grid.HostInfo, id string) (grid.Job, bool) {
	for _, j := range s.hub.Jobs(host.ID) {
		if j.ID == id {
			return j, true
		}
	}
	return grid.Job{}, false
}

// writeJobDialog renders the job dialog from the freshest state the hub has
// (events that fired before the dialog existed are not replayed).
func (s *Server) writeJobDialog(w http.ResponseWriter, r *http.Request, host grid.HostInfo, job grid.Job) {
	if fresh, ok := s.jobOf(host, job.ID); ok {
		job = fresh
	}
	if !views.SafeDOMID(job.ID) {
		s.serverError(w, r, errors.New("packages: job id is not safe for the DOM"))
		return
	}
	v := views.NewJobView(hostLabel(host), hostURL(host.Name), job)
	s.packagesWrite(w, r, http.StatusOK, func(rd *views.Renderer, w http.ResponseWriter) error {
		return rd.RenderPartial(w, "packages-job-dialog", v)
	})
}

// packagesError answers a failed call. HTMX requests get a toast fragment that
// packages.js lets htmx swap into #toasts despite the error status; everything
// else gets the plain mapping of gridError.
func (s *Server) packagesError(w http.ResponseWriter, r *http.Request, err error, title string) {
	if r.Header.Get("HX-Request") != "true" || s.renderer == nil {
		s.gridError(w, r, err)
		return
	}
	status := gridStatus(err)
	if status == http.StatusInternalServerError {
		s.log.Error("hub call failed", "method", r.Method, "path", logPath(r), "err", err)
	}
	body, rerr := s.packagesPartial("toast", views.Toast{Title: title, Sub: gridMessage(err)})
	if rerr != nil {
		s.gridError(w, r, err)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("HX-Retarget", "#toasts")
	h.Set("HX-Reswap", "innerHTML")
	h.Set("X-Nexus-Toast", "1")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

// --- rendering helpers -------------------------------------------------------

// bufResponse captures what a Renderer writes.
type bufResponse struct {
	h http.Header
	b bytes.Buffer
}

func (p *bufResponse) Header() http.Header         { return p.h }
func (p *bufResponse) Write(b []byte) (int, error) { return p.b.Write(b) }
func (p *bufResponse) WriteHeader(int)             {}

// packagesExec runs fn against the renderer and returns the HTML it wrote.
func (s *Server) packagesExec(fn func(*views.Renderer, http.ResponseWriter) error) (string, error) {
	if s.renderer == nil {
		return "", errors.New("packages: no renderer configured")
	}
	buf := &bufResponse{h: http.Header{}}
	if err := fn(s.renderer, buf); err != nil {
		return "", err
	}
	return buf.b.String(), nil
}

// packagesPartial renders one named partial to a string.
func (s *Server) packagesPartial(name string, data any) (string, error) {
	return s.packagesExec(func(rd *views.Renderer, w http.ResponseWriter) error {
		return rd.RenderPartial(w, name, data)
	})
}

// packagesWrite renders into a buffer first so a template error becomes a 500
// instead of half a page.
func (s *Server) packagesWrite(w http.ResponseWriter, r *http.Request, status int, fn func(*views.Renderer, http.ResponseWriter) error) {
	body, err := s.packagesExec(fn)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

// --- event stream --------------------------------------------------------------

// onPackagesStream reports whether the event stream belongs to the packages
// page (its URL carries view=packages); other pages do not get these events.
func onPackagesStream(r *http.Request) bool {
	return r != nil && r.URL.Query().Get("view") == "packages"
}

// renderPackagesJob turns job_queued, job_started and job_done into one "pkg-job"
// event whose payload is a set of hx-swap-oob elements: the dialog regions (if
// the dialog is open), the status-bar chip and log line and, after a
// maintenance job, the banner. Elements without a target are ignored by htmx.
func (s *Server) renderPackagesJob(r *http.Request, ev grid.Event) (string, string, bool) {
	j, ok := ev.Payload.(grid.Job)
	if !onPackagesStream(r) || !ok || !views.SafeDOMID(j.ID) {
		return "", "", false
	}
	host, ok := s.hub.Host(ev.Host)
	if !ok {
		return "", "", false
	}
	path := hostURL(host.Name)
	data := packagesJobEvent{
		Job:  views.NewJobView(hostLabel(host), path, j).AsOOB(),
		Chip: views.JobChipFor(path, s.hub.Jobs(ev.Host)),
		Log:  jobLogLine(j),
	}
	if j.State == grid.JobDone && j.OK {
		data.Toast = maintenanceToast(hostLabel(host), j.Kind)
	}
	html, err := s.packagesPartial("packages-job-state", data)
	if err != nil {
		s.log.Error("render job event", "err", err)
		return "", "", false
	}
	return packagesEventJob, html, true
}

func maintenanceToast(host string, kind protocol.JobKind) *views.Toast {
	switch kind {
	case protocol.JobAptUpdate:
		return &views.Toast{Title: "Synced", Sub: host + " | apt update"}
	case protocol.JobAptUpgrade:
		return &views.Toast{Title: "Updated", Sub: host + " | apt upgrade"}
	case protocol.JobAptClean:
		return &views.Toast{Title: "Cleaned", Sub: host + " | autoremove + clean"}
	}
	return nil
}

// renderPackagesJobOutput appends one output line to the open job dialog.
func (s *Server) renderPackagesJobOutput(r *http.Request, ev grid.Event) (string, string, bool) {
	out, ok := ev.Payload.(grid.JobOutputEvent)
	if !onPackagesStream(r) || !ok || !views.SafeDOMID(out.JobID) {
		return "", "", false
	}
	html, err := s.packagesPartial("packages-job-output", struct {
		ID   string
		Line views.JobLineView
	}{out.JobID, views.NewJobLine(out.Line)})
	if err != nil {
		s.log.Error("render job output", "err", err)
		return "", "", false
	}
	return packagesEventJob, html, true
}

// renderPackagesChanged tells the open packages page to reload its fragment;
// the page knows its own filter and search term.
func (s *Server) renderPackagesChanged(r *http.Request, _ grid.Event) (string, string, bool) {
	return packagesEventChanged, "", onPackagesStream(r)
}
