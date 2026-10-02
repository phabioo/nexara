package httpserver

import (
	"bytes"
	"errors"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/phabioo/nexara/internal/buildinfo"
	"github.com/phabioo/nexara/internal/hub/auth"
	"github.com/phabioo/nexara/internal/hub/views"
)

// Login form field names (wave 3 templates must use these).
const (
	fieldOperator = "operator_id"
	fieldPass     = "passphrase"
	fieldKeep     = "keep_signed_in" // checkbox; any of on/1/true counts
	fieldCode     = "code"           // TOTP code
)

// loginPage is the state of one render of the login view.
type loginPage struct {
	Status       int
	Error        string // user-facing message, empty if none
	SecondFactor bool   // show the TOTP step instead of the credentials form
	Granted      bool   // show "Access granted" (after the second factor), then continue to the app
	Operator     string // prefill / display name; never the passphrase
	KeepSignedIn bool
	CSRF         string // double-submit token, also set as cookie
	SetupDone    bool   // arrived from the setup wizard (/login?setup=done): show the "Hub online" banner
}

// loginView is the data of pages/login.html.
type loginView struct {
	views.AuthLayout
	Step         string // "creds", "totp" or "granted"
	Error        string
	Operator     string
	KeepSignedIn bool
	// RefreshSeconds > 0 makes the page continue to "/" by itself.
	RefreshSeconds int
}

const (
	loginStepCreds   = "creds"
	loginStepTOTP    = "totp"
	loginStepGranted = "granted"

	// grantedDelaySeconds is how long "Access granted" shows before the
	// browser continues to the app on its own (meta refresh, no script).
	grantedDelaySeconds = 2

	maxOperatorDisplay = 64 // runes of an operator ID echoed on the TOTP step
)

func (s *Server) routesLogin(mux *http.ServeMux) {
	mux.HandleFunc("GET /login", s.handleLoginGet)
	mux.HandleFunc("POST /login", s.handleLoginPost)
	mux.HandleFunc("POST /login/verify", s.handleLoginVerify)
	mux.HandleFunc("POST /logout", s.handleLogout)
	s.routesTOTP(mux)
}

// renderLogin renders pages/login.html for the state in p. Without a
// renderer (tests that do not exercise the views) it falls back to plain text.
func (s *Server) renderLogin(w http.ResponseWriter, r *http.Request, p loginPage) {
	if p.Status == 0 {
		p.Status = http.StatusOK
	}
	if s.renderer == nil {
		s.renderStub(w, p.Status, "Sign in\n"+p.Error)
		return
	}
	v := s.loginViewFor(p)
	var buf loginBuffer
	if err := s.renderer.Render(&buf, "login", v); err != nil {
		s.serverError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(p.Status)
	_, _ = w.Write(buf.body.Bytes())
}

// loginViewFor builds the view model: step, copy, top-bar pill and status line.
func (s *Server) loginViewFor(p loginPage) loginView {
	v := loginView{
		AuthLayout: views.AuthLayout{
			Title:      "Sign in",
			CSRF:       p.CSRF,
			Variant:    "auth-login",
			Segments:   []views.PillSegment{{Text: "LOCKED", Icon: "lock"}},
			MicroLines: []string{"[nexara nexus standby]", "operator authentication required", "grid nodes . . . . . . . [locked]"},
			BuildLines: []string{"nexus build " + buildinfo.Version, runtime.Version() + " · " + runtime.GOOS + "/" + runtime.GOARCH},
			Log:        "Awaiting operator credentials",
			LiveText:   "SECURE CHANNEL · TLS 1.3",
		},
		Step:         loginStepCreds,
		Error:        p.Error,
		Operator:     p.Operator,
		KeepSignedIn: p.KeepSignedIn,
	}
	switch {
	case p.Granted:
		v.Step = loginStepGranted
		v.Log = "Operator " + p.Operator + " authenticated"
		v.RefreshSeconds = grantedDelaySeconds
	case p.SecondFactor:
		v.Step = loginStepTOTP
		v.Log = "Passphrase accepted · waiting for second factor"
		if p.Error != "" {
			v.Log = "Second factor rejected"
		}
	case p.Error != "":
		v.Log = "Sign-in rejected"
	case p.SetupDone:
		v.Log = "Setup complete · awaiting operator credentials"
	}
	if p.SetupDone && !p.SecondFactor && !p.Granted {
		v.Toast = &views.Toast{Title: "Hub online", Sub: "Setup complete | sign in"}
	}
	return v
}

// loginBuffer collects a rendered page so the status code can be chosen after
// a successful render (views.Renderer writes straight to its writer).
type loginBuffer struct {
	h    http.Header
	body bytes.Buffer
}

func (b *loginBuffer) Header() http.Header {
	if b.h == nil {
		b.h = http.Header{}
	}
	return b.h
}
func (b *loginBuffer) Write(p []byte) (int, error) { return b.body.Write(p) }
func (b *loginBuffer) WriteHeader(int)             {}

func (s *Server) handleLoginGet(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(s.auth.Cookies().SessionName()); err == nil {
		if _, _, err := s.auth.Sessions().Validate(r.Context(), c.Value); err == nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	}
	tok, err := s.ensureCSRFCookie(w, r)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	// Coming back from the TOTP step ("Back") abandons its challenge.
	if _, err := r.Cookie(s.loginChallengeName()); err == nil {
		http.SetCookie(w, s.clearChallengeCookie())
	}
	// The box is checked by default, as in the design.
	s.renderLogin(w, r, loginPage{CSRF: tok, KeepSignedIn: true, SetupDone: r.URL.Query().Get("setup") == "done"})
}

func (s *Server) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	operator := strings.TrimSpace(r.PostFormValue(fieldOperator))
	keep := truthy(r.PostFormValue(fieldKeep))
	pass := r.PostFormValue(fieldPass)
	if operator == "" || pass == "" {
		// Nothing to check and nothing to count against the rate limit.
		s.renderLogin(w, r, loginPage{
			Status: http.StatusBadRequest, Error: "Enter your operator ID and passphrase.",
			Operator: operator, KeepSignedIn: keep, CSRF: s.csrfFor(w, r),
		})
		return
	}
	res, err := s.auth.Login(r.Context(), operator, pass, ClientIP(r), r.UserAgent(), keep)
	switch {
	case err == nil:
		s.finishSignIn(w, r, res)
	case errors.Is(err, auth.ErrSecondFactorRequired):
		http.SetCookie(w, s.challengeCookie(res.Challenge, res.ChallengeExpires))
		s.renderLogin(w, r, loginPage{SecondFactor: true, Operator: operator, KeepSignedIn: keep, CSRF: s.csrfFor(w, r)})
	default:
		s.loginError(w, r, err, loginPage{Operator: operator, KeepSignedIn: keep})
	}
}

func (s *Server) handleLoginVerify(w http.ResponseWriter, r *http.Request) {
	var challenge string
	if c, err := r.Cookie(s.loginChallengeName()); err == nil {
		challenge = c.Value
	}
	code := strings.ReplaceAll(r.PostFormValue(fieldCode), " ", "")
	// Display only (the step says which operator it is for); never trusted.
	who := displayOperator(r.PostFormValue(fieldOperator))
	if !isSixDigits(code) {
		s.renderLogin(w, r, loginPage{
			Status: http.StatusBadRequest, Error: "Enter the 6-digit code.",
			SecondFactor: true, Operator: who, CSRF: s.csrfFor(w, r),
		})
		return
	}
	res, err := s.auth.VerifySecondFactor(r.Context(), challenge, code, ClientIP(r))
	switch {
	case err == nil:
		// The second factor is the step the design celebrates: show
		// "Access granted", then continue to the app.
		s.finishSignInGranted(w, r, res)
	case errors.Is(err, auth.ErrInvalidCode):
		// The challenge survives a wrong code (the service discards it after five).
		s.loginError(w, r, err, loginPage{SecondFactor: true, Operator: who})
	case errors.Is(err, auth.ErrRateLimited):
		s.loginError(w, r, err, loginPage{SecondFactor: true, Operator: who})
	default:
		// Invalid or expired challenge, or an internal error: start over.
		http.SetCookie(w, s.clearChallengeCookie())
		s.loginError(w, r, err, loginPage{})
	}
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(s.auth.Cookies().SessionName()); err == nil {
		if err := s.auth.Logout(r.Context(), c.Value, ClientIP(r)); err != nil {
			// Still drop the cookie; the session expires on its own.
			s.log.Error("logout failed", "err", err)
		}
	}
	http.SetCookie(w, s.auth.Cookies().ClearSession())
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// finishSignIn sets the session cookie, retires the pre-session cookies and redirects home.
func (s *Server) finishSignIn(w http.ResponseWriter, r *http.Request, res auth.LoginResult) {
	s.startSession(w, res)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// finishSignInGranted is finishSignIn for the TOTP path: it answers with the
// "Access granted" page, which continues to "/" after a moment.
func (s *Server) finishSignInGranted(w http.ResponseWriter, r *http.Request, res auth.LoginResult) {
	s.startSession(w, res)
	s.renderLogin(w, r, loginPage{Granted: true, Operator: res.User.OperatorID})
}

func (s *Server) startSession(w http.ResponseWriter, res auth.LoginResult) {
	ck := s.auth.Cookies()
	http.SetCookie(w, ck.Session(res.SessionID, res.Session))
	http.SetCookie(w, ck.ClearCSRF())
	http.SetCookie(w, s.clearChallengeCookie())
}

// displayOperator trims and shortens a posted operator ID for display.
func displayOperator(v string) string {
	v = strings.TrimSpace(v)
	if utf8.RuneCountInString(v) > maxOperatorDisplay {
		v = string([]rune(v)[:maxOperatorDisplay])
	}
	return v
}

func isSixDigits(v string) bool {
	if len(v) != 6 {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return false
		}
	}
	return true
}

// loginError maps an auth error to a status and the user-facing message.
func (s *Server) loginError(w http.ResponseWriter, r *http.Request, err error, p loginPage) {
	switch {
	case errors.Is(err, auth.ErrRateLimited):
		p.Status = http.StatusTooManyRequests
		secs := int((auth.RetryAfter(err) + time.Second - 1) / time.Second)
		if secs < 1 {
			secs = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(secs))
	case errors.Is(err, auth.ErrInvalidCredentials), errors.Is(err, auth.ErrInvalidCode), errors.Is(err, auth.ErrInvalidChallenge):
		p.Status = http.StatusUnauthorized
	default:
		s.log.Error("sign-in failed", "err", err)
		p.Status = http.StatusInternalServerError
	}
	p.Error = auth.UserMessage(err)
	p.CSRF = s.csrfFor(w, r)
	s.renderLogin(w, r, p)
}

// csrfFor returns the pre-session token for re-rendering a form; a failure to
// create one leaves it empty (the next submit is rejected and the user reloads).
func (s *Server) csrfFor(w http.ResponseWriter, r *http.Request) string {
	tok, err := s.ensureCSRFCookie(w, r)
	if err != nil {
		s.log.Error("create csrf token failed", "err", err)
		return ""
	}
	return tok
}

// challengeCookie carries the TOTP challenge ID between the two sign-in
// steps: HttpOnly, Strict, short-lived (naming and path: cookies.go).
func (s *Server) challengeCookie(id string, expires time.Time) *http.Cookie {
	maxAge := int(expires.Sub(s.now()) / time.Second)
	if maxAge < 1 {
		maxAge = 1
	}
	return &http.Cookie{
		Name: s.loginChallengeName(), Value: id, Path: s.loginChallengePath(), MaxAge: maxAge,
		HttpOnly: true, Secure: s.secure, SameSite: http.SameSiteStrictMode,
	}
}

func (s *Server) clearChallengeCookie() *http.Cookie {
	return &http.Cookie{
		Name: s.loginChallengeName(), Value: "", Path: s.loginChallengePath(), MaxAge: -1,
		HttpOnly: true, Secure: s.secure, SameSite: http.SameSiteStrictMode,
	}
}

func truthy(v string) bool {
	switch strings.ToLower(v) {
	case "on", "1", "true", "yes":
		return true
	}
	return false
}
