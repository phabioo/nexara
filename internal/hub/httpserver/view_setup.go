package httpserver

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/phabioo/nexara/internal/buildinfo"
	"github.com/phabioo/nexara/internal/hub/auth"
	"github.com/phabioo/nexara/internal/hub/setup"
	"github.com/phabioo/nexara/internal/hub/views"
	"github.com/phabioo/nexara/internal/protocol"
)

// Form field names of the wizard (the templates use the same strings; the
// error keys of setup.ValidationError are the names without "f-").
const (
	setupFieldCode       = "code"
	setupFieldID         = "id"
	setupFieldPass       = "passphrase"
	setupFieldConfirm    = "confirm"
	setupFieldTOTP       = "totp"
	setupFieldSkip       = "skip"
	setupFieldName       = "name"
	setupFieldTimeZone   = "timezone"
	setupFieldAgentHost  = "agent_host"
	setupFieldHTTPSPort  = "https_port"
	setupFieldRetention  = "retention"
	setupFieldSelfLink   = "self_link"
	setupFieldCapability = "capabilities"
)

// setupStepMeta is the copy of one wizard step (docs/design/mockups/setup.dc.html).
type setupStepMeta struct {
	Label, Title, Tag, Lead string
}

// setupMeta is indexed by setup.Step.
var setupMeta = [...]setupStepMeta{
	setup.StepUnlock: {"Unlock", "Claim this hub", "First run",
		"Nexus is running on this Pi and waits to be claimed. Enter the one-time setup code from the hub console so nobody else in the network can take over the installation."},
	setup.StepTrust: {"Trust", "Trust this hub", "Certificate",
		"Your browser warned you once because Nexus signs its own certificates. Install the Nexara CA on each device you use and the warning is gone for good, also after renewals."},
	setup.StepOperator: {"Operator", "Create operator", "Account",
		"Create the first operator account. It has full access to every host on the grid."},
	setup.StepTwoFactor: {"Two-factor", "Two-factor login", "Recommended",
		"Scan the code with an authenticator app and confirm it with the current 6-digit code."},
	setup.StepHub: {"Hub", "Hub settings", "Configuration",
		"How the hub is named and where Grid Agents reach it. These values are written to nexus.yaml."},
	setup.StepSelfLink: {"Self-link", "Manage this Pi", "Grid",
		"The hub can monitor and manage the Pi it runs on, just like any other host."},
	setup.StepReady: {"Ready", "Ready to finish", "Review",
		"Check the summary. Finishing closes setup mode and makes the setup code invalid; from then on you sign in with your operator account."},
}

// setupUnlockLeadShort is the phone copy of the Unlock lead.
const setupUnlockLeadShort = "Enter the one-time setup code the installer printed, so nobody else in the network can take over this hub."

const setupSessionExpired = "The setup session expired. Enter the setup code again."

// setupRetention are the selectable history periods, in display order.
var setupRetention = []struct {
	Days  int
	Label string
}{{30, "30 days"}, {90, "90 days"}, {365, "1 year"}}

// setupCapLabels are the capability chips of the Self-link step. "services" has
// no chip: it is part of Monitoring (the overview shows the services card).
var setupCapLabels = []struct{ Key, Label string }{
	{protocol.CapMonitoring, "Monitoring"},
	{protocol.CapPackages, "Packages"},
	{protocol.CapShell, "Shell"},
	{protocol.CapPower, "Power"},
	{protocol.CapDocker, "Docker"},
}

// setupDefaultCaps are on when the operator has not chosen yet.
var setupDefaultCaps = []string{protocol.CapMonitoring, protocol.CapPackages, protocol.CapShell, protocol.CapPower}

// setupPage is the data of pages/setup.html: one template for all steps.
type setupPage struct {
	views.AuthLayout
	Steps views.SetupSteps

	Key       string // step key, "unlock" ... "ready"
	No        int    // 1-based step number
	Total     int
	Title     string
	Tag       string
	Lead      string
	LeadShort string
	Host      string // short host name for the decor lines

	Errors    []string        // pink error rows
	Invalid   map[string]bool // field names to mark aria-invalid
	Back      string          // href of the Back button, empty hides it
	NextLabel string

	// Unlock
	Locked       bool
	LockLeft     string
	AttemptsText string
	HasSession   bool
	InstallLines setupInstallLines

	// Trust
	TrustAvailable   bool
	TrustQR          template.HTML
	Fingerprint      string   // colon separated, upper case
	FingerprintParts []string // the same, one entry per byte (the template can break lines between them)
	Trusted          bool

	// Operator
	OperatorID string

	// Two-factor
	TOTPQR  template.HTML
	TOTPKey string

	// Hub
	HubName   string
	TimeZone  string
	AgentHost string
	Port      string
	Retention int
	Choices   []setupRetentionChoice

	// Self-link
	SelfLink bool
	Caps     []setupCapChoice

	// Ready
	Summary  []setupSummaryRow
	Banner   string
	Done     bool
	Warnings []string
}

type setupInstallLines struct {
	Version     string
	URL         string
	Fingerprint string // abbreviated, empty when no CA is available
}

type setupRetentionChoice struct {
	Days  int
	Label string
	On    bool
}

type setupCapChoice struct {
	Key, Label string
	On         bool
}

type setupSummaryRow struct{ Label, Value string }

func (s *Server) routesSetup(mux *http.ServeMux) {
	mux.HandleFunc("GET /setup", s.handleSetupGet)
	mux.HandleFunc("POST /setup", s.handleSetupPost)
	mux.HandleFunc("GET /setup/{step}", s.handleSetupGet)
	mux.HandleFunc("POST /setup/{step}", s.handleSetupPost)
	s.routesSetupTrust(mux)
}

// --- helpers -------------------------------------------------------------------

func setupStepByKey(key string) (setup.Step, bool) {
	for st := setup.StepUnlock; st <= setup.StepReady; st++ {
		if st.String() == key {
			return st, true
		}
	}
	return 0, false
}

func setupPath(st setup.Step) string { return "/setup/" + st.String() }

// setupFirstIncomplete is the furthest step the wizard lets the operator reach.
func setupFirstIncomplete(w *setup.Wizard) setup.Step {
	for st := setup.StepTrust; st < setup.StepReady; st++ {
		if !w.Done(st) {
			return st
		}
	}
	return setup.StepReady
}

// setupStatusWriter delays the status line until the first body write, so the
// renderer can set the content type first and still answer with a non-200 code.
type setupStatusWriter struct {
	http.ResponseWriter
	code  int
	wrote bool
}

func (d *setupStatusWriter) Write(b []byte) (int, error) {
	if !d.wrote {
		d.wrote = true
		d.ResponseWriter.WriteHeader(d.code)
	}
	return d.ResponseWriter.Write(b)
}

// setupShortHostname is the machine's host name for the decor lines and as the
// default hub name. It always matches the hub-name pattern.
func setupShortHostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "nexus"
	}
	if i := strings.IndexByte(h, '.'); i > 0 {
		h = h[:i]
	}
	h = strings.ToLower(h)
	if h == "" || len(h) > 63 {
		return "nexus"
	}
	for i, r := range h {
		ok := r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || (i > 0 && (r == '-' || r == '_' || r == '.'))
		if !ok {
			return "nexus"
		}
	}
	return h
}

// setupDefaultTimeZone guesses the hub's zone: TZ, then the named local zone,
// then /etc/localtime, else UTC (the wizard refuses "Local").
func setupDefaultTimeZone() string {
	if tz := os.Getenv("TZ"); tz != "" {
		if _, err := time.LoadLocation(tz); err == nil && tz != "Local" {
			return tz
		}
	}
	if name := time.Local.String(); name != "Local" && name != "" {
		return name
	}
	if target, err := os.Readlink("/etc/localtime"); err == nil {
		if name := setupZoneFromLink(target); name != "" {
			if _, err := time.LoadLocation(name); err == nil {
				return name
			}
		}
	}
	return "UTC"
}

// setupZoneFromLink extracts "Europe/Berlin" from ".../zoneinfo/Europe/Berlin".
func setupZoneFromLink(target string) string {
	const marker = "zoneinfo/"
	i := strings.LastIndex(target, marker)
	if i < 0 {
		return ""
	}
	return target[i+len(marker):]
}

// setupAddressDefaults turns the Host header the operator reached the hub with
// into the defaults for "Address for agents" and "HTTPS port".
func setupAddressDefaults(r *http.Request) (host, port string) {
	host, port = r.Host, ""
	if h, p, err := net.SplitHostPort(r.Host); err == nil {
		host, port = h, p
	}
	host = strings.Trim(host, "[]")
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		port = "8443"
	}
	if host == "" {
		host = setupShortHostname() + ".local"
	}
	return host, port
}

// setupTOTPSecret derives the pending TOTP secret of a setup session from its
// cookie token. The token is 256 random bits only this browser and the server
// know, so the secret is unguessable, stays stable while the operator reloads
// the page, and needs no server-side state (the wizard stores the secret only
// after the first code was confirmed).
func setupTOTPSecret(token string) string {
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte("nexus:setup:totp:v1"))
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(mac.Sum(nil)[:20])
}

// setupGroup splits s into groups of n characters separated by spaces.
func setupGroup(s string, n int) string {
	var b strings.Builder
	for i := 0; i < len(s); i += n {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(s[i:min(i+n, len(s))])
	}
	return b.String()
}

func setupOTPAuthURL(secret, operator string) string {
	label := url.PathEscape(auth.TOTPIssuer + ":" + operator)
	q := url.Values{"secret": {secret}, "issuer": {auth.TOTPIssuer}}
	return "otpauth://totp/" + label + "?" + q.Encode()
}

func setupRetentionLabel(days int) string {
	for _, c := range setupRetention {
		if c.Days == days {
			return c.Label
		}
	}
	return strconv.Itoa(days) + " days"
}

func setupCapLabel(key string) string {
	for _, c := range setupCapLabels {
		if c.Key == key {
			return c.Label
		}
	}
	return key
}

// --- rendering -----------------------------------------------------------------

// setupBase fills the parts every step shares.
func (s *Server) setupBase(w http.ResponseWriter, r *http.Request, st setup.Step, log string) *setupPage {
	meta := setupMeta[st]
	labels := make([]string, len(setupMeta))
	for i, m := range setupMeta {
		labels[i] = m.Label
	}
	host := setupShortHostname()
	no := int(st) + 1
	p := &setupPage{
		Key: st.String(), No: no, Total: len(setupMeta),
		Title: meta.Title, Tag: meta.Tag, Lead: meta.Lead, Host: host,
		Steps: views.NewSetupSteps(labels, no),
		AuthLayout: views.AuthLayout{
			Title:    "Setup",
			Variant:  "auth-setup",
			LiveText: "SETUP MODE · LAN ONLY",
			Log:      log,
		},
	}
	p.Segments = []views.PillSegment{{Text: "SETUP"}, {Text: fmt.Sprintf("%d/%d", no, len(setupMeta)), Light: true}}
	p.MicroLines = []string{"[nexara nexus first run]", "hub not claimed · setup mode active", "grid nodes . . . . . . . [none]"}
	p.BuildLines = []string{"nexus build " + buildinfo.Version, "host " + host + " · " + runtime.GOOS + "/" + runtime.GOARCH}
	p.CSRF = s.setupCSRF(w, r)
	p.Invalid = map[string]bool{}
	p.NextLabel = "Continue"
	if st > setup.StepUnlock {
		p.Back = setupPath(st - 1)
	}
	return p
}

// setupCSRF returns the pre-session double-submit token for the form. A
// failure leaves it empty: the submit is then rejected and the operator reloads.
func (s *Server) setupCSRF(w http.ResponseWriter, r *http.Request) string {
	tok, err := s.ensureCSRFCookie(w, r)
	if err != nil {
		s.log.Error("create csrf token failed", "err", err)
		return ""
	}
	return tok
}

func setupTruthy(v string) bool {
	switch strings.ToLower(v) {
	case "on", "1", "true", "yes":
		return true
	}
	return false
}

// renderSetup writes the page with the given status.
func (s *Server) renderSetup(w http.ResponseWriter, r *http.Request, status int, p *setupPage) {
	if s.renderer == nil {
		s.renderStub(w, status, "Setup: "+p.Title)
		return
	}
	if err := s.renderer.Render(&setupStatusWriter{ResponseWriter: w, code: status}, "setup", p); err != nil {
		s.serverError(w, r, err)
	}
}

func (s *Server) setupRedirect(w http.ResponseWriter, r *http.Request, loc string) {
	redirectTo(w, r, loc)
}

// setupUnlockPage builds the Unlock step with its current lock state.
func (s *Server) setupUnlockPage(w http.ResponseWriter, r *http.Request, hasSession bool) *setupPage {
	log := "Setup mode active · waiting for setup code"
	if hasSession {
		log = "Hub claimed · setup code accepted"
	}
	p := s.setupBase(w, r, setup.StepUnlock, log)
	p.LeadShort = setupUnlockLeadShort
	p.HasSession = hasSession
	if hasSession {
		p.NextLabel = "Continue"
	} else {
		p.NextLabel = "Unlock"
	}
	if locked, until := s.setup.Codes.LockedFor(ClientIP(r)); locked {
		p.Locked = true
		p.LockLeft = setupLockLeft(until.Sub(s.now()))
		p.Log = "Setup locked after " + strconv.Itoa(setup.MaxAttempts) + " wrong codes"
	}
	left := s.setup.Codes.AttemptsLeftFor(ClientIP(r))
	if left >= setup.MaxAttempts {
		p.AttemptsText = fmt.Sprintf("%d attempts", setup.MaxAttempts)
	} else {
		p.AttemptsText = fmt.Sprintf("%d of %d attempts left", max(left, 0), setup.MaxAttempts)
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	p.InstallLines = setupInstallLines{Version: buildinfo.Version, URL: scheme + "://" + r.Host}
	if a := s.trustAnchor(); a != nil {
		p.InstallLines.Fingerprint = setupShortFingerprint(a.Fingerprint())
	}
	return p
}

// setupLockLeft renders the remaining lock time, rounded up to whole minutes.
func setupLockLeft(d time.Duration) string {
	if d <= 0 {
		return "a moment"
	}
	m := int((d + time.Minute - 1) / time.Minute)
	if m == 1 {
		return "1 minute"
	}
	return strconv.Itoa(m) + " minutes"
}

// setupStepPage builds the page of a step after Unlock from the wizard state.
func (s *Server) setupStepPage(w http.ResponseWriter, r *http.Request, sess *setup.Session, st setup.Step) *setupPage {
	wiz := sess.Wizard
	draft := wiz.Draft()
	trusted := setupTrusted(r)
	host, port := setupAddressDefaults(r)

	switch st {
	case setup.StepTrust:
		p := s.setupBase(w, r, st, "Hub claimed · setup code accepted")
		p.Trusted = trusted
		if trusted {
			p.NextLabel = "Continue"
		} else {
			p.NextLabel = "Skip for now"
		}
		s.setupFillTrust(p, r)
		return p

	case setup.StepOperator:
		log := "Trust step skipped · browser warning stays for now"
		if trusted {
			log = "Nexara CA downloaded on this device"
		}
		p := s.setupBase(w, r, st, log)
		p.OperatorID = draft.OperatorID
		return p

	case setup.StepTwoFactor:
		p := s.setupBase(w, r, st, "Operator "+draft.OperatorID+" created")
		token := setupSessionToken(r)
		secret := setupTOTPSecret(token)
		p.TOTPKey = setupGroup(secret, 4)
		if qr, err := views.QRSVG(setupOTPAuthURL(secret, draft.OperatorID), views.QRLow, "QR code for the authenticator app"); err == nil {
			p.TOTPQR = qr
		} else {
			s.log.Error("render TOTP QR code failed", "err", err)
		}
		return p

	case setup.StepHub:
		log := "Two-factor login skipped · required from v0.2"
		if draft.TOTPSecret != "" {
			log = "Two-factor login enabled"
		}
		p := s.setupBase(w, r, st, log)
		p.HubName, p.TimeZone, p.AgentHost, p.Port = setupShortHostname(), setupDefaultTimeZone(), host, port
		p.Retention = 365
		if wiz.Done(setup.StepHub) {
			h := draft.Hub
			p.HubName, p.TimeZone, p.AgentHost, p.Port, p.Retention = h.Name, h.TimeZone, h.AgentHost, strconv.Itoa(h.HTTPSPort), h.RetentionDays
		}
		setupFillRetention(p)
		return p

	case setup.StepSelfLink:
		p := s.setupBase(w, r, st, "Hub settings saved for this session")
		p.HubName = draft.Hub.Name
		p.SelfLink = true
		on := setupDefaultCaps
		if wiz.Done(setup.StepSelfLink) {
			p.SelfLink, on = draft.SelfLink.Enabled, draft.SelfLink.Capabilities
		}
		setupFillCaps(p, on)
		return p

	default: // Ready
		p := s.setupBase(w, r, st, "Review the summary · nothing is saved until you finish")
		p.NextLabel = "Finish setup"
		p.Banner = "Ready to go"
		if res, err := wiz.Result(); err == nil {
			p.Summary = setupSummary(res, trusted)
		}
		return p
	}
}

func setupFillRetention(p *setupPage) {
	p.Choices = p.Choices[:0]
	for _, c := range setupRetention {
		p.Choices = append(p.Choices, setupRetentionChoice{Days: c.Days, Label: c.Label, On: c.Days == p.Retention})
	}
}

func setupFillCaps(p *setupPage, on []string) {
	p.Caps = p.Caps[:0]
	for _, c := range setupCapLabels {
		p.Caps = append(p.Caps, setupCapChoice{Key: c.Key, Label: c.Label, On: slices.Contains(on, c.Key)})
	}
}

func setupSummary(res setup.Result, trusted bool) []setupSummaryRow {
	cert := "Not installed yet"
	if trusted {
		cert = "Nexara CA downloaded"
	}
	tfa := "Skipped (required from v0.2)"
	if res.TOTPSecret != "" {
		tfa = "Enabled"
	}
	self := "No"
	if res.SelfLink.Enabled {
		var names []string
		for _, c := range setupCapLabels {
			if slices.Contains(res.SelfLink.Capabilities, c.Key) {
				names = append(names, c.Label)
			}
		}
		self = "Yes"
		if len(names) > 0 {
			self += " · " + strings.Join(names, ", ")
		}
	}
	return []setupSummaryRow{
		{"Source", "New installation"},
		{"Operator", res.OperatorID},
		{"Certificate", cert},
		{"Two-factor", tfa},
		{"Hub", fmt.Sprintf("%s · %s", res.Hub.Name, net.JoinHostPort(res.Hub.AgentHost, strconv.Itoa(res.Hub.HTTPSPort)))},
		{"History", "Minutes 7 days · hours " + setupRetentionLabel(res.Hub.RetentionDays)},
		{"Self-managed", self},
	}
}

// setupSessionToken is the raw setup cookie value ("" without one).
func setupSessionToken(r *http.Request) string {
	if c, err := r.Cookie(setup.SessionCookie); err == nil {
		return c.Value
	}
	return ""
}

// setupErrorMessages turns validation errors into rows in a stable order and
// marks the offending fields.
func setupErrorMessages(p *setupPage, ve setup.ValidationError) {
	order := []string{setupFieldID, setupFieldPass, setupFieldConfirm, setupFieldTOTP, setupFieldName, setupFieldTimeZone,
		setupFieldAgentHost, setupFieldHTTPSPort, setupFieldRetention, setupFieldCapability}
	seen := map[string]bool{}
	add := func(k string) {
		if msg, ok := ve[k]; ok && !seen[k] {
			seen[k] = true
			p.Errors = append(p.Errors, msg)
			p.Invalid[k] = true
		}
	}
	for _, k := range order {
		add(k)
	}
	rest := make([]string, 0, len(ve))
	for k := range ve {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	slices.Sort(rest)
	for _, k := range rest {
		add(k)
	}
}

// --- handlers ------------------------------------------------------------------

func (s *Server) handleSetupGet(w http.ResponseWriter, r *http.Request) {
	sess, have := s.setup.Sessions.FromRequest(r)
	key := r.PathValue("step")
	if key == "" {
		if have {
			s.setupRedirect(w, r, setupPath(sess.Wizard.Current()))
			return
		}
		s.renderSetup(w, r, http.StatusOK, s.setupUnlockPage(w, r, false))
		return
	}
	st, ok := setupStepByKey(key)
	if !ok {
		s.notFound(w, r)
		return
	}
	if st == setup.StepUnlock {
		s.renderSetup(w, r, http.StatusOK, s.setupUnlockPage(w, r, have))
		return
	}
	if !have {
		s.setupRedirect(w, r, "/setup")
		return
	}
	if err := sess.Wizard.Goto(st); err != nil {
		s.setupRedirect(w, r, setupPath(setupFirstIncomplete(sess.Wizard)))
		return
	}
	s.renderSetup(w, r, http.StatusOK, s.setupStepPage(w, r, sess, st))
}

func (s *Server) handleSetupPost(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("step")
	if key == "" || key == setup.StepUnlock.String() {
		s.handleSetupUnlock(w, r)
		return
	}
	st, ok := setupStepByKey(key)
	if !ok {
		s.notFound(w, r)
		return
	}
	sess, have := s.setup.Sessions.FromRequest(r)
	if !have {
		p := s.setupUnlockPage(w, r, false)
		p.Errors = []string{setupSessionExpired}
		s.renderSetup(w, r, http.StatusUnauthorized, p)
		return
	}
	wiz := sess.Wizard
	if err := wiz.Goto(st); err != nil {
		s.setupRedirect(w, r, setupPath(setupFirstIncomplete(wiz)))
		return
	}

	var err error
	switch st {
	case setup.StepTrust:
		err = wiz.SubmitTrust()
	case setup.StepOperator:
		err = wiz.SubmitOperator(setup.OperatorInput{
			ID:         r.PostFormValue(setupFieldID),
			Passphrase: r.PostFormValue(setupFieldPass),
			Confirm:    r.PostFormValue(setupFieldConfirm),
		})
	case setup.StepTwoFactor:
		err = s.setupSubmitTwoFactor(r, wiz)
	case setup.StepHub:
		port, _ := strconv.Atoi(strings.TrimSpace(r.PostFormValue(setupFieldHTTPSPort)))
		days, _ := strconv.Atoi(r.PostFormValue(setupFieldRetention))
		err = wiz.SubmitHub(setup.HubInput{
			Name:          r.PostFormValue(setupFieldName),
			TimeZone:      r.PostFormValue(setupFieldTimeZone),
			AgentHost:     r.PostFormValue(setupFieldAgentHost),
			HTTPSPort:     port,
			RetentionDays: days,
		})
	case setup.StepSelfLink:
		err = wiz.SubmitSelfLink(setupSelfLinkInput(r))
	case setup.StepReady:
		s.setupFinish(w, r, sess)
		return
	}

	var ve setup.ValidationError
	switch {
	case err == nil:
		s.setupRedirect(w, r, setupPath(wiz.Current()))
	case errors.As(err, &ve):
		p := s.setupStepPage(w, r, sess, st)
		setupErrorMessages(p, ve)
		s.setupKeepInput(p, r, st)
		s.renderSetup(w, r, http.StatusUnprocessableEntity, p)
	case errors.Is(err, setup.ErrStepLocked):
		s.setupRedirect(w, r, setupPath(setupFirstIncomplete(wiz)))
	default:
		s.serverError(w, r, err)
	}
}

// setupKeepInput puts the submitted (non-secret) values back into the form.
func (s *Server) setupKeepInput(p *setupPage, r *http.Request, st setup.Step) {
	switch st {
	case setup.StepOperator:
		p.OperatorID = strings.TrimSpace(r.PostFormValue(setupFieldID))
	case setup.StepHub:
		p.HubName = r.PostFormValue(setupFieldName)
		p.TimeZone = r.PostFormValue(setupFieldTimeZone)
		p.AgentHost = r.PostFormValue(setupFieldAgentHost)
		p.Port = r.PostFormValue(setupFieldHTTPSPort)
		if days, err := strconv.Atoi(r.PostFormValue(setupFieldRetention)); err == nil {
			p.Retention = days
		}
		setupFillRetention(p)
	case setup.StepSelfLink:
		in := setupSelfLinkInput(r)
		p.SelfLink = in.Enabled
		setupFillCaps(p, in.Capabilities)
	}
}

func (s *Server) setupSubmitTwoFactor(r *http.Request, wiz *setup.Wizard) error {
	if setupTruthy(r.PostFormValue(setupFieldSkip)) {
		return wiz.SubmitTwoFactor(true, "")
	}
	secret := setupTOTPSecret(setupSessionToken(r))
	code := strings.TrimSpace(r.PostFormValue(setupFieldTOTP))
	if code == "" {
		return setup.ValidationError{setupFieldTOTP: "Enter the 6-digit code from your authenticator app."}
	}
	if !s.auth.ConfirmTOTP(secret, code) {
		return setup.ValidationError{setupFieldTOTP: "That code did not match. Check the clock of your phone and try again."}
	}
	return wiz.SubmitTwoFactor(false, secret)
}

// setupSelfLinkInput reads the Self-link form. Monitoring includes the
// services capability (the overview's services card).
func setupSelfLinkInput(r *http.Request) setup.SelfLinkInput {
	_ = r.ParseForm()
	in := setup.SelfLinkInput{Enabled: setupTruthy(r.PostFormValue(setupFieldSelfLink))}
	for _, c := range r.PostForm[setupFieldCapability] {
		in.Capabilities = append(in.Capabilities, c)
		if c == protocol.CapMonitoring {
			in.Capabilities = append(in.Capabilities, protocol.CapServices)
		}
	}
	return in
}

func (s *Server) handleSetupUnlock(w http.ResponseWriter, r *http.Request) {
	ip := ClientIP(r)
	sess, have := s.setup.Sessions.FromRequest(r)
	raw := strings.TrimSpace(r.PostFormValue(setupFieldCode))
	if raw == "" && have {
		// Back from Trust: the operator is unlocked already.
		s.setupRedirect(w, r, setupPath(sess.Wizard.Current()))
		return
	}
	fail := func(status int, msg string) {
		p := s.setupUnlockPage(w, r, have)
		p.Errors = []string{msg}
		if p.Locked {
			p.Errors = nil
		}
		s.renderSetup(w, r, status, p)
	}
	if !setupWellFormedCode(raw) {
		fail(http.StatusBadRequest, "Enter the 8-character setup code from the hub console.")
		return
	}
	err := s.setup.Codes.VerifyFrom(ip, raw)
	var ce *setup.CodeError
	switch {
	case err == nil:
	case errors.As(err, &ce) && ce.Locked:
		s.log.Warn("setup code locked", "ip", ip)
		secs := int((ce.Until.Sub(s.now()) + time.Second - 1) / time.Second)
		w.Header().Set("Retry-After", strconv.Itoa(max(secs, 1)))
		fail(http.StatusTooManyRequests, "")
		return
	case errors.As(err, &ce):
		s.log.Warn("wrong setup code", "ip", ip, "attempts_left", ce.Left)
		fail(http.StatusUnauthorized, ce.Error())
		return
	default:
		s.serverError(w, r, err)
		return
	}
	token, _, err := s.setup.Sessions.Unlock()
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.log.Info("setup unlocked", "ip", ip)
	http.SetCookie(w, s.setup.Sessions.Cookie(token))
	s.setupRedirect(w, r, setupPath(setup.StepTrust))
}

// setupWellFormedCode checks the shape only (8 characters of the code
// alphabet after normalizing), so typos do not cost one of the five attempts.
func setupWellFormedCode(input string) bool {
	c := setup.NormalizeCode(input)
	if len(c) != setup.CodeLength {
		return false
	}
	for _, r := range c {
		if !(r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

// setupFinish is the POST of the Ready step: the one place that commits.
func (s *Server) setupFinish(w http.ResponseWriter, r *http.Request, sess *setup.Session) {
	trusted := setupTrusted(r)
	res, _ := sess.Wizard.Result() // for the summary; commitSetup reads it again
	out, err := s.commitSetup(w, r)

	var ve setup.ValidationError
	switch {
	case err == nil:
		if len(out.Warnings) == 0 {
			s.setupRedirect(w, r, "/login?setup=done")
			return
		}
		// The operator exists but something needs attention: show it once.
		p := s.setupBase(w, r, setup.StepReady, "Setup finished with warnings")
		p.Title, p.Tag = "Setup complete", "Done"
		p.Lead = "Setup mode is now closed and the setup code is invalid. Sign in with your operator account from now on."
		p.Banner, p.Done, p.Warnings, p.Back = "Hub online", true, out.Warnings, ""
		p.Summary = setupSummary(res, trusted)
		s.renderSetup(w, r, http.StatusOK, p)
	case errors.Is(err, ErrSetupDone):
		s.setupRedirect(w, r, "/login")
	case errors.Is(err, ErrNoSetupSession):
		p := s.setupUnlockPage(w, r, false)
		p.Errors = []string{setupSessionExpired}
		s.renderSetup(w, r, http.StatusUnauthorized, p)
	case errors.Is(err, setup.ErrNotReady):
		s.setupRedirect(w, r, setupPath(setupFirstIncomplete(sess.Wizard)))
	case errors.As(err, &ve):
		p := s.setupStepPage(w, r, sess, setup.StepReady)
		setupErrorMessages(p, ve)
		s.renderSetup(w, r, http.StatusUnprocessableEntity, p)
	default:
		s.serverError(w, r, err)
	}
}
