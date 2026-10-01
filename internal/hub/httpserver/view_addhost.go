package httpserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
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
	addHostFieldProbe   = "probe"   // id of the confirmed host key probe (phase 2)
	addHostFieldReplace = "replace" // id of the offline host to replace (phase 1, optional)
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
//	GET  /hosts/new/pane         the SSH form again (tab switch, "Try again", "Replace")
//	POST /hosts/new              phase 1: probe the host key, show its fingerprint
//	POST /hosts/new/confirm      phase 2: confirmed fingerprint + credentials, start linking
//	GET  /hosts/new/link/{id}    progress of a link attempt (polled)
//	POST /hosts/new/code         create an enrollment code
//	GET  /hosts/new/code/{id}    status of a code: waiting, joined, expired (polled)
func (s *Server) routesAddHost(mux *http.ServeMux) {
	mux.HandleFunc("GET /hosts/new", s.handleAddHostDialog)
	mux.HandleFunc("GET /hosts/new/pane", s.handleAddHostPane)
	mux.HandleFunc("POST /hosts/new", s.handleAddHostSubmit)
	mux.HandleFunc("POST /hosts/new/confirm", s.handleAddHostConfirm)
	mux.HandleFunc("GET /hosts/new/link/{id}", s.handleAddHostLink)
	mux.HandleFunc("POST /hosts/new/code", s.handleAddHostCode)
	mux.HandleFunc("GET /hosts/new/code/{id}", s.handleAddHostCodeStatus)
}

// addHostView is the data of the add-host partials: the shared dialog model
// plus the two-phase SSH link states (decision #41).
type addHostView struct {
	views.AddHostDialog
	// Confirm is set in phase 2: the host key the operator has to verify.
	Confirm *hostKeyConfirm
	// Replace is set on the phase 1 form when the operator chose to replace an offline host.
	Replace *replaceNotice
	// ReplaceOffer is set under a failed attempt whose host name exists and is offline.
	ReplaceOffer *replaceNotice
}

// hostKeyConfirm is the fingerprint pane.
type hostKeyConfirm struct {
	ProbeID     string
	Target      string // user@address:port
	KeyType     string // ssh-ed25519
	Fingerprint string // SHA256:...
	KeyFile     string // /etc/ssh/ssh_host_ed25519_key.pub
	Replace     *replaceNotice
}

// replaceNotice names the host an operator can replace.
type replaceNotice struct {
	ID   string
	Name string
	URL  string // GET target of the "Replace" button
}

// addHostBase is the dialog data every response starts from.
func (s *Server) addHostBase(r *http.Request, mode string) *addHostView {
	d := &addHostView{AddHostDialog: views.AddHostDialog{
		Mode:   mode,
		Form:   views.AddHostForm{Port: "22", User: "pi", Auth: views.AddHostAuthPassword},
		HubKey: strings.TrimSpace(s.sshPublicKey()),
	}}
	if sess, ok := SessionFrom(r); ok {
		d.CSRF = s.auth.CSRFToken(sess)
	}
	return d
}

// renderAddHost writes the named add-host partial with the given status.
func (s *Server) renderAddHost(w http.ResponseWriter, r *http.Request, status int, name string, d *addHostView) {
	if s.renderer == nil {
		s.serverError(w, r, errors.New("add host: no renderer configured"))
		return
	}
	body, err := s.partialString(name, d)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
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
// for "Try again" (?retry=<attempt id>; the password is never kept) and
// "Replace" (?retry=<attempt id>&replace=<host id>).
func (s *Server) handleAddHostPane(w http.ResponseWriter, r *http.Request) {
	d := s.addHostBase(r, views.AddHostModeSSH)
	if a := s.addHost.get(r.URL.Query().Get("retry"), operatorName(r)); a != nil {
		d.Form = a.form
		// "Replace <name>": only for the host the failed attempt ran into, and only while it is offline.
		if id := r.URL.Query().Get("replace"); id != "" && a.existsID() == grid.HostID(id) {
			d.Replace = s.replaceNotice(grid.HostID(id), a.id)
		}
	}
	s.renderAddHost(w, r, http.StatusOK, "addhost-pane", d)
}

// --- SSH ------------------------------------------------------------------------------

// validateAddHostTarget checks address, port, user and display name (phase 1)
// and returns the port. The message is user facing.
func validateAddHostTarget(form views.AddHostForm) (int, string) {
	switch {
	case form.Address == "":
		return 0, "Enter the IP address or hostname of the device."
	case !validAddHostAddress(form.Address):
		return 0, "Enter a valid IP address or host name, without spaces or a protocol."
	}
	port := 22
	if form.Port != "" {
		n, err := strconv.Atoi(form.Port)
		if err != nil || n < 1 || n > 65535 {
			return 0, "SSH port must be between 1 and 65535."
		}
		port = n
	}
	switch {
	case form.User == "":
		return 0, "Enter a user with sudo rights."
	case form.User == "root":
		return 0, "The shell runs as the SSH user, which must not be root. Use your normal sudo user."
	case !addHostUserRE.MatchString(form.User):
		return 0, "The user name may contain letters, digits, dots, dashes and underscores."
	case len(form.DisplayName) > 64 || strings.IndexFunc(form.DisplayName, unicode.IsControl) >= 0:
		return 0, "Display name: at most 64 characters, no control characters."
	}
	return port, ""
}

// validateAddHost checks the target and the chosen authentication (phase 2)
// with the same rules as the enroller (internal/hub/enroll) so mistakes show
// up before any connection is made. The returned message is user facing and
// never contains the password.
func validateAddHost(form views.AddHostForm, password string, haveHubKey bool) (grid.SSHLinkRequest, string) {
	port, msg := validateAddHostTarget(form)
	if msg != "" {
		return grid.SSHLinkRequest{}, msg
	}
	req := grid.SSHLinkRequest{Address: form.Address, Port: port, User: form.User, DisplayName: form.DisplayName}
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

// handleAddHostSubmit is phase 1: it validates address, port, user and name,
// asks the enroller for the host key (no authentication, no password) and shows
// the fingerprint for confirmation.
func (s *Server) handleAddHostSubmit(w http.ResponseWriter, r *http.Request) {
	form := views.AddHostForm{
		Address:     strings.TrimSpace(r.PostFormValue(addHostFieldAddress)),
		Port:        strings.TrimSpace(r.PostFormValue(addHostFieldPort)),
		User:        strings.TrimSpace(r.PostFormValue(addHostFieldUser)),
		DisplayName: strings.TrimSpace(r.PostFormValue(addHostFieldName)),
		Auth:        views.AddHostAuthPassword,
	}
	if s.enroller == nil {
		s.serverError(w, r, errors.New("add host: no enroller configured"))
		return
	}
	d := s.addHostBase(r, views.AddHostModeSSH)
	d.Form = form
	var replace *replaceNotice
	if id := strings.TrimSpace(r.PostFormValue(addHostFieldReplace)); id != "" {
		if replace = s.replaceNotice(grid.HostID(id), ""); replace == nil {
			d.Error = "Only a host that is currently offline can be replaced."
			s.renderAddHost(w, r, http.StatusUnprocessableEntity, "addhost-pane", d)
			return
		}
		d.Replace = replace
	}
	port, msg := validateAddHostTarget(form)
	if msg != "" {
		d.Error = msg
		s.renderAddHost(w, r, http.StatusUnprocessableEntity, "addhost-pane", d)
		return
	}
	info, err := s.enroller.ProbeSSH(r.Context(), ActorFrom(r), form.Address, port)
	if err != nil {
		s.log.Warn("ssh host key probe failed", "address", form.Address, "port", port, "err", err)
		d.Error = probeErrorMessage(err, form.Address, port)
		s.renderAddHost(w, r, http.StatusUnprocessableEntity, "addhost-pane", d)
		return
	}
	var sessHash string
	if sess, ok := SessionFrom(r); ok {
		sessHash = sess.IDHash
	}
	p := s.addHost.addProbe(&hostKeyProbe{
		operator: operatorName(r), session: sessHash, form: form, port: port, info: info,
	}, replace, s.now())
	d.Replace = nil
	d.Confirm = p.view()
	s.renderAddHost(w, r, http.StatusOK, "addhost-pane", d)
}

// handleAddHostConfirm is phase 2: the operator confirmed the fingerprint of
// the stored probe and now chooses the authentication. The fingerprint comes
// from the server-side probe, never from the form.
func (s *Server) handleAddHostConfirm(w http.ResponseWriter, r *http.Request) {
	if s.enroller == nil {
		s.serverError(w, r, errors.New("add host: no enroller configured"))
		return
	}
	d := s.addHostBase(r, views.AddHostModeSSH)
	var sessHash string
	if sess, ok := SessionFrom(r); ok {
		sessHash = sess.IDHash
	}
	probeID := r.PostFormValue(addHostFieldProbe)
	p := s.addHost.getProbe(probeID, operatorName(r), sessHash, s.now())
	if p == nil {
		d.Error = "The host key check expired. Check the host key again."
		s.renderAddHost(w, r, http.StatusUnprocessableEntity, "addhost-pane", d)
		return
	}
	form := p.form
	form.Auth = r.PostFormValue(addHostFieldAuth)
	if form.Auth == "" {
		form.Auth = views.AddHostAuthPassword
	}
	d.Form = form
	// The password goes from the request straight into the request struct.
	req, msg := validateAddHost(form, r.PostFormValue(addHostFieldPass), d.HubKey != "")
	if msg != "" {
		d.Confirm, d.Error = p.view(), msg
		s.renderAddHost(w, r, http.StatusUnprocessableEntity, "addhost-pane", d)
		return
	}
	req.HostKeySHA256 = p.info.SHA256
	req.ReplaceHostID = p.replaceID
	a, err := s.addHost.start(s, r, req, form, probeID)
	if err != nil {
		if errors.Is(err, errProbeGone) {
			d.Error = "The host key check expired. Check the host key again."
			s.renderAddHost(w, r, http.StatusUnprocessableEntity, "addhost-pane", d)
			return
		}
		d.Confirm, d.Error = p.view(), linkStartMessage(err)
		s.renderAddHost(w, r, http.StatusTooManyRequests, "addhost-pane", d)
		return
	}
	d.Form.Auth = form.Auth
	d.Progress = a.progress(true)
	d.ReplaceOffer = s.replaceOffer(a)
	s.renderAddHost(w, r, http.StatusOK, "addhost-pane", d)
}

// probeErrorMessage is the fixed text for a failed host key probe.
func probeErrorMessage(err error, addr string, port int) string {
	if errors.Is(err, grid.ErrInvalidArgument) {
		return "The hub rejected the address or port."
	}
	return "Could not read the SSH host key of " + net.JoinHostPort(addr, strconv.Itoa(port)) +
		". Check the address and port, and that SSH is running on the device."
}

// replaceNotice describes host id as a replacement target, or returns nil if
// it is unknown or online: only an offline host can be replaced (decision
// #46). attempt, if set, becomes part of the button's URL.
func (s *Server) replaceNotice(id grid.HostID, attempt string) *replaceNotice {
	h, ok := s.hub.Host(id)
	if !ok || h.Online {
		return nil
	}
	name := h.DisplayName
	if name == "" {
		name = h.Name
	}
	n := &replaceNotice{ID: string(h.ID), Name: name}
	if attempt != "" {
		n.URL = "/hosts/new/pane?retry=" + url.QueryEscape(attempt) + "&replace=" + url.QueryEscape(string(h.ID))
	}
	return n
}

// replaceOffer is the "Replace <name>" button under a failed attempt.
func (s *Server) replaceOffer(a *linkAttempt) *replaceNotice {
	if id := a.existsID(); id != "" {
		return s.replaceNotice(id, a.id)
	}
	return nil
}

func (s *Server) handleAddHostLink(w http.ResponseWriter, r *http.Request) {
	a := s.addHost.get(r.PathValue("id"), operatorName(r))
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
	d.ReplaceOffer = s.replaceOffer(a)
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
		s.renderAddHost(w, r, gridStatus(err), "addhost-pane", d)
		return
	}
	id := s.addHost.addCode(operatorName(r), known, code.Expires, s.now())
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
	c := s.addHost.getCode(r.PathValue("id"), operatorName(r))
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

// hostExistsMessage explains a name clash. The name comes from the hub's own
// host list, not from the remote device.
func hostExistsMessage(err error) string {
	name := ""
	var he *grid.HostExistsError
	if errors.As(err, &he) {
		name = he.Name
	}
	if name == "" {
		return "A host with this name already exists. Give the device a unique host name and try again."
	}
	return "A host named " + name + " already exists. Give this device a unique host name (for example with sudo hostnamectl set-hostname) and try again, or replace the existing host if it is offline."
}

// linkErrorMessage maps the error of Enroller.LinkViaSSH to the message under
// the progress list. It is fixed text: the failing step and its detail are
// shown in the list (the enroller already made those safe), and the cause
// itself may carry output of the remote host.
func linkErrorMessage(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, grid.ErrHostKeyMismatch):
		return "The host key changed after you confirmed it. Nothing was sent to the device. Make sure you reach the right device, then check the host key again."
	case errors.Is(err, grid.ErrHostExists):
		return hostExistsMessage(err)
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
