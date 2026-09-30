package httpserver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/hub/views"
)

// Form field names of the SSH form (partials/addhost.html uses the same).
const (
	addHostFieldAddress = "address"
	addHostFieldPort    = "port"
	addHostFieldUser    = "user"
	addHostFieldName    = "display_name"
	addHostFieldAuth    = "auth"
	addHostFieldPass    = "password"
)

var (
	addHostHostRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
	addHostUserRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,31}$`)
)

// routesAddHost registers the Add-host dialog and its steps. Enrollment goes
// through s.enroller (grid.Enroller). "new" is reserved: a host cannot be
// called that, because /hosts/new wins over /hosts/{host}.
//
//	GET  /hosts/new              the dialog (HTMX, into #modal-root)
//	GET  /hosts/new/pane         the SSH form again (tab switch, "Try again")
//	POST /hosts/new              validate and start linking over SSH
//	GET  /hosts/new/link/{id}    progress of a link attempt (polled)
//	POST /hosts/new/code         create an enrollment code
//	GET  /hosts/new/code/{id}    status of a code: waiting, joined, expired (polled)
func (s *Server) routesAddHost(mux *http.ServeMux) {
	mux.HandleFunc("GET /hosts/new", s.handleAddHostDialog)
	mux.HandleFunc("GET /hosts/new/pane", s.handleAddHostPane)
	mux.HandleFunc("POST /hosts/new", s.handleAddHostSubmit)
	mux.HandleFunc("GET /hosts/new/link/{id}", s.handleAddHostLink)
	mux.HandleFunc("POST /hosts/new/code", s.handleAddHostCode)
	mux.HandleFunc("GET /hosts/new/code/{id}", s.handleAddHostCodeStatus)
}

// addHostBase is the dialog data every response starts from.
func (s *Server) addHostBase(r *http.Request, mode string) views.AddHostDialog {
	d := views.AddHostDialog{
		Mode:   mode,
		Form:   views.AddHostForm{Port: "22", User: "pi", Auth: views.AddHostAuthPassword},
		HubKey: strings.TrimSpace(s.sshPublicKey()),
	}
	if sess, ok := SessionFrom(r); ok {
		d.CSRF = s.auth.CSRFToken(sess)
	}
	return d
}

// addHostStatus is the status for a failed step of the dialog. htmx does not
// swap 4xx responses, and the dialog must show its error row, so HTMX requests
// get 200 and the fragment carries the error.
func addHostStatus(r *http.Request, status int) int {
	if r.Header.Get("HX-Request") == "true" {
		return http.StatusOK
	}
	return status
}

// addHostBuffer collects a rendered fragment so the status can be chosen
// before anything is written.
type addHostBuffer struct {
	header http.Header
	body   bytes.Buffer
}

func (b *addHostBuffer) Header() http.Header         { return b.header }
func (b *addHostBuffer) Write(p []byte) (int, error) { return b.body.Write(p) }
func (b *addHostBuffer) WriteHeader(int)             {}

// renderAddHost writes the named add-host partial with the given status.
func (s *Server) renderAddHost(w http.ResponseWriter, r *http.Request, status int, name string, d views.AddHostDialog) {
	if s.renderer == nil {
		s.serverError(w, r, errors.New("add host: no renderer configured"))
		return
	}
	buf := &addHostBuffer{header: http.Header{}}
	if err := s.renderer.RenderPartial(buf, name, d); err != nil {
		s.serverError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.body.Bytes())
}

func (s *Server) handleAddHostDialog(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("HX-Request") != "true" {
		// The dialog only makes sense over a page; the "+ Host" tab opens it with HTMX.
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.renderAddHost(w, r, http.StatusOK, "addhost-dialog", s.addHostBase(r, views.AddHostModeSSH))
}

// handleAddHostPane returns the SSH form: for the tab switch, and prefilled
// for "Try again" (?retry=<attempt id>; the password is never kept).
func (s *Server) handleAddHostPane(w http.ResponseWriter, r *http.Request) {
	d := s.addHostBase(r, views.AddHostModeSSH)
	if a := s.links().get(r.URL.Query().Get("retry"), operatorName(r)); a != nil {
		d.Form = a.form
	}
	s.renderAddHost(w, r, http.StatusOK, "addhost-pane", d)
}

// --- SSH ------------------------------------------------------------------------------

// validateAddHost checks the submitted SSH form with the same rules as the
// enroller (internal/hub/enroll) so mistakes show up before any connection is
// made. The returned message is user facing and never contains the password.
func validateAddHost(form views.AddHostForm, password string, haveHubKey bool) (grid.SSHLinkRequest, string) {
	var req grid.SSHLinkRequest
	switch {
	case form.Address == "":
		return req, "Enter the IP address or hostname of the device."
	case !validAddHostAddress(form.Address):
		return req, "Enter a valid IP address or host name, without spaces or a protocol."
	}
	port := 22
	if form.Port != "" {
		n, err := strconv.Atoi(form.Port)
		if err != nil || n < 1 || n > 65535 {
			return req, "SSH port must be between 1 and 65535."
		}
		port = n
	}
	switch {
	case form.User == "":
		return req, "Enter a user with sudo rights."
	case form.User == "root":
		return req, "The shell runs as the SSH user, which must not be root. Use your normal sudo user."
	case !addHostUserRE.MatchString(form.User):
		return req, "The user name may contain letters, digits, dots, dashes and underscores."
	case len(form.DisplayName) > 64 || strings.IndexFunc(form.DisplayName, unicode.IsControl) >= 0:
		return req, "Display name: at most 64 characters, no control characters."
	}
	req = grid.SSHLinkRequest{Address: form.Address, Port: port, User: form.User, DisplayName: form.DisplayName}
	switch form.Auth {
	case views.AddHostAuthKey:
		if !haveHubKey {
			return grid.SSHLinkRequest{}, "The hub has no SSH key available. Sign in with a password instead."
		}
		req.UseHubKey = true
	case views.AddHostAuthPassword:
		if password == "" {
			return grid.SSHLinkRequest{}, "Enter the password for " + form.User + "."
		}
		req.Password = grid.Secret(password)
	default:
		return grid.SSHLinkRequest{}, "Choose how to sign in: password or hub SSH key."
	}
	return req, ""
}

func validAddHostAddress(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	return addHostHostRE.MatchString(s) && !strings.Contains(s, "..")
}

func (s *Server) handleAddHostSubmit(w http.ResponseWriter, r *http.Request) {
	form := views.AddHostForm{
		Address:     strings.TrimSpace(r.PostFormValue(addHostFieldAddress)),
		Port:        strings.TrimSpace(r.PostFormValue(addHostFieldPort)),
		User:        strings.TrimSpace(r.PostFormValue(addHostFieldUser)),
		DisplayName: strings.TrimSpace(r.PostFormValue(addHostFieldName)),
		Auth:        r.PostFormValue(addHostFieldAuth),
	}
	if form.Auth == "" {
		form.Auth = views.AddHostAuthPassword
	}
	if s.enroller == nil {
		s.serverError(w, r, errors.New("add host: no enroller configured"))
		return
	}
	d := s.addHostBase(r, views.AddHostModeSSH)
	d.Form = form
	// The password goes from the request straight into the request struct.
	req, msg := validateAddHost(form, r.PostFormValue(addHostFieldPass), d.HubKey != "")
	if msg != "" {
		d.Error = msg
		s.renderAddHost(w, r, addHostStatus(r, http.StatusUnprocessableEntity), "addhost-pane", d)
		return
	}
	a, err := s.links().start(s, r, req, form)
	if err != nil {
		d.Error = linkStartMessage(err)
		s.renderAddHost(w, r, addHostStatus(r, http.StatusTooManyRequests), "addhost-pane", d)
		return
	}
	d.Progress = a.progress(true)
	s.renderAddHost(w, r, http.StatusOK, "addhost-pane", d)
}

func (s *Server) handleAddHostLink(w http.ResponseWriter, r *http.Request) {
	a := s.links().get(r.PathValue("id"), operatorName(r))
	if a == nil {
		s.notFound(w, r)
		return
	}
	if seen, err := strconv.Atoi(r.URL.Query().Get("v")); err == nil && seen == a.currentVersion() {
		w.WriteHeader(http.StatusNoContent) // nothing new: htmx keeps the pane
		return
	}
	d := s.addHostBase(r, views.AddHostModeSSH)
	d.Progress = a.progress(true)
	s.renderAddHost(w, r, http.StatusOK, "addhost-pane", d)
}

// --- enrollment code -------------------------------------------------------------------

func (s *Server) handleAddHostCode(w http.ResponseWriter, r *http.Request) {
	if s.enroller == nil {
		s.serverError(w, r, errors.New("add host: no enroller configured"))
		return
	}
	d := s.addHostBase(r, views.AddHostModeCode)
	known := s.knownHostIDs()
	code, err := s.enroller.NewEnrollCode(r.Context(), ActorFrom(r), grid.EnrollOptions{})
	if err != nil {
		s.log.Warn("enrollment code failed", "err", err)
		d.Error = "Could not create an enrollment code. " + gridMessage(err)
		s.renderAddHost(w, r, addHostStatus(r, gridStatus(err)), "addhost-pane", d)
		return
	}
	id := s.links().addCode(operatorName(r), known, code.Expires, s.now())
	d.Code = &views.AddHostCode{
		Code:     code.Code,
		Command:  code.Command,
		ValidFor: validFor(code.Expires.Sub(s.now())),
		PollURL:  "/hosts/new/code/" + id + "?p=0",
	}
	s.renderAddHost(w, r, http.StatusOK, "addhost-pane", d)
}

// validFor renders the remaining validity as "15 min" (rounded up, at least 1).
func validFor(d time.Duration) string {
	mins := int((d + time.Minute - 1) / time.Minute)
	if mins < 1 {
		mins = 1
	}
	return fmt.Sprintf("%d min", mins)
}

func (s *Server) knownHostIDs() map[grid.HostID]bool {
	known := map[grid.HostID]bool{}
	for _, h := range s.hub.Hosts() {
		known[h.ID] = true
	}
	return known
}

// handleAddHostCodeStatus is polled while a code is waiting. It answers 204
// until something changes: a new host appeared (progress list), the host came
// online (done) or the code expired.
func (s *Server) handleAddHostCodeStatus(w http.ResponseWriter, r *http.Request) {
	c := s.links().getCode(r.PathValue("id"), operatorName(r))
	if c == nil {
		s.notFound(w, r)
		return
	}
	d := s.addHostBase(r, views.AddHostModeCode)
	phase, p := c.evaluate(s.hub.Hosts(), s.now())
	if seen, err := strconv.Atoi(r.URL.Query().Get("p")); err == nil && seen == phase {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	switch phase {
	case codePhaseExpired:
		d.Code = &views.AddHostCode{Expired: true}
	default:
		d.Progress = p
		if p.PollURL != "" {
			p.PollURL = "/hosts/new/code/" + c.id + "?p=" + strconv.Itoa(phase)
		}
	}
	s.renderAddHost(w, r, http.StatusOK, "addhost-pane", d)
}

// linkStartMessage explains why a link attempt could not start.
func linkStartMessage(err error) string {
	if errors.Is(err, errTooManyLinks) {
		return "Another host is being linked right now. Wait for it to finish and try again."
	}
	return "The link attempt could not be started."
}

// linkErrorMessage maps the error of Enroller.LinkViaSSH to the message under
// the progress list. It is fixed text: the failing step and its detail are
// shown in the list (the enroller already made those safe), and the cause
// itself may carry output of the remote host.
func linkErrorMessage(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, grid.ErrHostExists):
		return "A host with this name already exists. Choose another display name."
	case errors.Is(err, grid.ErrInvalidArgument):
		return "The hub rejected the input. Check address, port and user."
	case errors.Is(err, context.DeadlineExceeded):
		return "Linking took too long and was stopped."
	case errors.Is(err, context.Canceled):
		return "Linking was canceled."
	case errors.Is(err, grid.ErrLinkFailed):
		return "Linking failed at the step marked above. Nothing was kept on the hub; fix the cause and try again."
	default:
		return "Something went wrong. Check the hub log."
	}
}
