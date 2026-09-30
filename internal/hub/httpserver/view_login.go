package httpserver

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/phabioo/nexara/internal/hub/auth"
)

// Login form field names (wave 3 templates must use these).
const (
	fieldOperator = "operator_id"
	fieldPass     = "passphrase"
	fieldKeep     = "keep_signed_in" // checkbox; any of on/1/true counts
	fieldCode     = "code"           // TOTP code
)

// loginChallengeCookie carries the TOTP challenge ID between the two sign-in
// steps. HttpOnly, Strict, scoped to /login and /login/verify, short-lived.
const loginChallengeCookie = "nexus_login"

// loginPage is the data of the login view. Wave 3 replaces renderLogin with a
// template render of this struct (pages/login.html); the handlers stay.
type loginPage struct {
	Status       int
	Error        string // user-facing message, empty if none
	SecondFactor bool   // show the TOTP step instead of the credentials form
	Operator     string // prefill; never the passphrase
	KeepSignedIn bool
	CSRF         string // double-submit token, also set as cookie
}

func (s *Server) routesLogin(mux *http.ServeMux) {
	mux.HandleFunc("GET /login", s.handleLoginGet)
	mux.HandleFunc("POST /login", s.handleLoginPost)
	mux.HandleFunc("POST /login/verify", s.handleLoginVerify)
	mux.HandleFunc("POST /logout", s.handleLogout)
}

// renderLogin is a stub until wave 3 (templates).
func (s *Server) renderLogin(w http.ResponseWriter, r *http.Request, p loginPage) {
	if p.Status == 0 {
		p.Status = http.StatusOK
	}
	text := "Sign in"
	if p.SecondFactor {
		text = "Two-factor authentication"
	}
	if p.Error != "" {
		text += "\n" + p.Error
	}
	s.renderStub(w, p.Status, text)
}

func (s *Server) handleLoginGet(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(auth.SessionCookieName); err == nil {
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
	s.renderLogin(w, r, loginPage{CSRF: tok})
}

func (s *Server) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	operator := strings.TrimSpace(r.PostFormValue(fieldOperator))
	keep := truthy(r.PostFormValue(fieldKeep))
	res, err := s.auth.Login(r.Context(), operator, r.PostFormValue(fieldPass), ClientIP(r), r.UserAgent(), keep)
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
	if c, err := r.Cookie(loginChallengeCookie); err == nil {
		challenge = c.Value
	}
	code := strings.ReplaceAll(r.PostFormValue(fieldCode), " ", "")
	res, err := s.auth.VerifySecondFactor(r.Context(), challenge, code, ClientIP(r))
	switch {
	case err == nil:
		s.finishSignIn(w, r, res)
	case errors.Is(err, auth.ErrInvalidCode):
		// The challenge survives a wrong code (the service discards it after five).
		s.loginError(w, r, err, loginPage{SecondFactor: true})
	case errors.Is(err, auth.ErrRateLimited):
		s.loginError(w, r, err, loginPage{SecondFactor: true})
	default:
		// Invalid or expired challenge, or an internal error: start over.
		http.SetCookie(w, s.clearChallengeCookie())
		s.loginError(w, r, err, loginPage{})
	}
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(auth.SessionCookieName); err == nil {
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
	ck := s.auth.Cookies()
	http.SetCookie(w, ck.Session(res.SessionID, res.Session))
	http.SetCookie(w, ck.ClearCSRF())
	http.SetCookie(w, s.clearChallengeCookie())
	http.Redirect(w, r, "/", http.StatusSeeOther)
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

func (s *Server) challengeCookie(id string, expires time.Time) *http.Cookie {
	maxAge := int(expires.Sub(s.now()) / time.Second)
	if maxAge < 1 {
		maxAge = 1
	}
	return &http.Cookie{
		Name: loginChallengeCookie, Value: id, Path: "/login", MaxAge: maxAge,
		HttpOnly: true, Secure: s.secure, SameSite: http.SameSiteStrictMode,
	}
}

func (s *Server) clearChallengeCookie() *http.Cookie {
	return &http.Cookie{
		Name: loginChallengeCookie, Value: "", Path: "/login", MaxAge: -1,
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
