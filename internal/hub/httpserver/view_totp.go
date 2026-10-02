package httpserver

import (
	"errors"
	"html/template"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/phabioo/nexara/internal/buildinfo"
	"github.com/phabioo/nexara/internal/hub/auth"
	"github.com/phabioo/nexara/internal/hub/views"
)

// totpEnrollPath is the enrollment page of an operator who has no two-factor
// login yet (decision #51). Until it succeeds, this page, its POST and logout
// are all the session reaches (enrollmentAllowed in middleware.go).
const totpEnrollPath = "/account/totp"

// totpView is the data of pages/totp.html. The page uses the auth shell, not
// the app shell: a pending session must not see the hosts, the navigation or
// the live status bar, and the look stays the one of the sign-in and the
// setup wizard's two-factor step it continues.
type totpView struct {
	views.AuthLayout
	Step     string // "enroll" or "granted"
	Operator string
	QR       template.HTML
	Key      string // grouped for reading
	Error    string
	// RefreshSeconds > 0 continues to "/" by itself (granted).
	RefreshSeconds int
}

func (s *Server) routesTOTP(mux *http.ServeMux) {
	mux.HandleFunc("GET "+totpEnrollPath, s.handleTOTPGet)
	mux.HandleFunc("POST "+totpEnrollPath, s.handleTOTPPost)
}

func (s *Server) totpViewFor(r *http.Request, step, errMsg string) (totpView, bool) {
	user, _ := UserFrom(r)
	sess, _ := SessionFrom(r)
	v := totpView{
		AuthLayout: views.AuthLayout{
			Title:      "Two-factor login",
			CSRF:       s.auth.CSRFToken(sess),
			Variant:    "auth-login auth-totp",
			Segments:   []views.PillSegment{{Text: "2FA REQUIRED", Icon: "lock"}},
			MicroLines: []string{"[nexara nexus standby]", "second factor required", "grid nodes . . . . . . . [locked]"},
			BuildLines: []string{"nexus build " + buildinfo.Version, runtime.Version() + " · " + runtime.GOOS + "/" + runtime.GOARCH},
			Log:        "Passphrase accepted · set up two-factor login to continue",
			LiveText:   "SECURE CHANNEL · TLS 1.3",
		},
		Step:     step,
		Operator: user.OperatorID,
		Error:    errMsg,
	}
	if step == totpStepGranted {
		v.Segments = []views.PillSegment{{Text: "2FA ON", Icon: "lock"}}
		v.Log = "Two-factor login enabled for " + user.OperatorID
		v.RefreshSeconds = grantedDelaySeconds
		return v, true
	}
	if errMsg != "" {
		v.Log = "Code rejected"
	}
	secret := s.auth.PendingTOTPSecret(user, sess)
	v.Key = setupGroup(secret, 4)
	qr, err := views.QRSVG(setupOTPAuthURL(secret, user.OperatorID), views.QRLow, "QR code for the authenticator app")
	if err != nil {
		s.log.Error("render TOTP QR code failed", "err", err)
		return v, false
	}
	v.QR = qr
	return v, true
}

const (
	totpStepEnroll  = "enroll"
	totpStepGranted = "granted"
)

func (s *Server) renderTOTP(w http.ResponseWriter, r *http.Request, status int, step, errMsg string) {
	v, ok := s.totpViewFor(r, step, errMsg)
	if !ok {
		s.serverError(w, r, errors.New("totp enrollment page: QR code failed"))
		return
	}
	if s.renderer == nil {
		s.renderStub(w, status, "Two-factor login\n"+errMsg)
		return
	}
	if err := s.renderer.Render(&setupStatusWriter{ResponseWriter: w, code: status}, "totp", v); err != nil {
		s.serverError(w, r, err)
	}
}

func (s *Server) handleTOTPGet(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFrom(r)
	if user.TOTPEnabled {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.renderTOTP(w, r, http.StatusOK, totpStepEnroll, "")
}

func (s *Server) handleTOTPPost(w http.ResponseWriter, r *http.Request) {
	user, _ := UserFrom(r)
	sess, _ := SessionFrom(r)
	if user.TOTPEnabled {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	code := strings.ReplaceAll(r.PostFormValue(fieldCode), " ", "")
	if !isSixDigits(code) {
		s.renderTOTP(w, r, http.StatusBadRequest, totpStepEnroll, "Enter the 6-digit code.")
		return
	}
	res, err := s.auth.EnrollTOTP(r.Context(), user.ID, sess, code, ClientIP(r))
	switch {
	case err == nil:
		// A new session ID replaces the old one (and all others of the operator).
		http.SetCookie(w, s.auth.Cookies().Session(res.SessionID, res.Session))
		r = r.WithContext(withUserSession(r, res))
		s.renderTOTP(w, r, http.StatusOK, totpStepGranted, "")
	case errors.Is(err, auth.ErrAlreadyEnrolled):
		http.Redirect(w, r, "/", http.StatusSeeOther)
	case errors.Is(err, auth.ErrInvalidCode):
		s.renderTOTP(w, r, http.StatusUnprocessableEntity, totpStepEnroll, "That code did not match. Check the clock of your phone and try again.")
	case errors.Is(err, auth.ErrRateLimited):
		secs := int((auth.RetryAfter(err) + time.Second - 1) / time.Second)
		w.Header().Set("Retry-After", strconv.Itoa(max(secs, 1)))
		s.renderTOTP(w, r, http.StatusTooManyRequests, totpStepEnroll, auth.UserMessage(err))
	case errors.Is(err, auth.ErrSessionExpired):
		redirectTo(w, r, "/login")
	default:
		s.serverError(w, r, err)
	}
}
