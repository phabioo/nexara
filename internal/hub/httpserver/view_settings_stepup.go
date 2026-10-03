package httpserver

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/phabioo/nexara/internal/hub/auth"
)

// Step-up for the heaviest Settings actions (decision #58, security review B-06): backup download, restore and
// update install ask for the operator's passphrase and a current TOTP code again. The check runs in the very request
// that performs the action; nothing remembers "verified a minute ago".
const (
	fieldStepUpPass = "stepup_passphrase"
	fieldStepUpCode = "stepup_code"
	// fieldDownloadGrant carries the grant of the second step of the backup download.
	fieldDownloadGrant = "download_grant"

	// downloadGrantTTL is how long the "Backup ready" dialog may take until the file is fetched.
	downloadGrantTTL = 2 * time.Minute
)

// stepUp verifies the step-up fields of the request through auth.Service.Reauthenticate. It returns status 0 when the
// operator is confirmed. Otherwise it returns the HTTP status and a message that is safe to show in the dialog
// (Retry-After is already set where it applies). The secrets are never echoed or logged.
func (s *Server) stepUp(w http.ResponseWriter, r *http.Request) (status int, msg string) {
	user, ok := UserFrom(r)
	if !ok {
		return http.StatusForbidden, "Sign in again to continue."
	}
	if err := r.ParseForm(); err != nil {
		return http.StatusBadRequest, "The form could not be read."
	}
	pass := r.PostForm.Get(fieldStepUpPass)
	code := strings.ReplaceAll(r.PostForm.Get(fieldStepUpCode), " ", "")
	// Cheap checks first: a form that is incomplete must not use up an attempt or the one-time code.
	switch {
	case pass == "" && user.TOTPEnabled:
		return http.StatusUnprocessableEntity, "Enter your passphrase and the 6-digit code."
	case pass == "":
		return http.StatusUnprocessableEntity, "Enter your passphrase."
	case user.TOTPEnabled && !isSixDigits(code):
		return http.StatusUnprocessableEntity, "Enter the 6-digit code from your authenticator."
	}
	// Without TOTP only the demo (auth's DemoPasswordOnly) gets past this call; the service decides, not this layer.
	err := s.auth.Reauthenticate(r.Context(), user, pass, code, ClientIP(r))
	switch {
	case err == nil:
		return 0, ""
	case errors.Is(err, auth.ErrWrongPassphrase):
		return http.StatusUnprocessableEntity, "The passphrase is not correct."
	case errors.Is(err, auth.ErrInvalidCode):
		return http.StatusUnprocessableEntity, "The code is not correct or was already used. Wait for the next code and try again."
	case errors.Is(err, auth.ErrRateLimited):
		wait := auth.RetryAfter(err)
		w.Header().Set("Retry-After", strconv.Itoa(max(int((wait+time.Second-1)/time.Second), 1)))
		return http.StatusTooManyRequests, "Too many wrong entries. Try again in " + waitText(wait) + "."
	case errors.Is(err, auth.ErrBusy):
		w.Header().Set("Retry-After", "2")
		return http.StatusTooManyRequests, "Another check is running. Try again in a moment."
	case errors.Is(err, auth.ErrNoSecondFactor):
		return http.StatusForbidden, "Two-factor sign-in is not set up for this account, so this action is not available."
	}
	s.log.Error("settings: step-up check", "path", logPath(r), "err", err)
	return http.StatusInternalServerError, "The check could not be done. The hub log has the reason."
}

// stepUpNoCode tells the dialogs to leave out the code field: the operator has no authenticator, which only the demo
// (stepUp above) accepts.
func stepUpNoCode(r *http.Request) bool {
	u, ok := UserFrom(r)
	return ok && !u.TOTPEnabled
}

// downloadGrants holds the grants of the backup download's second step. The first step issues one after the step-up
// succeeded; the second step (a plain form post that fetches the file) must present it. A grant is
//   - random (256 bit) and kept only as a hash,
//   - bound to the session that got it (one open grant per session; a new one replaces the old),
//   - valid for downloadGrantTTL and
//   - redeemed once, whatever the outcome.
//
// It replaces trusting the echoed form alone: the second step cannot be reached without having passed the first.
// The state is in memory; a hub restart simply invalidates open dialogs. It is package level because the Server has
// no field for it and the key (the session hash) already isolates users from each other.
var downloadGrants = &grantStore{m: map[string]grant{}}

type grant struct {
	hash    [sha256.Size]byte
	expires time.Time
}

type grantStore struct {
	mu sync.Mutex
	m  map[string]grant // session ID hash -> grant
}

// issue returns a new grant for the session. Expired grants of other sessions are dropped on the way, which bounds
// the map by the number of live sessions.
func (g *grantStore) issue(now time.Time, sessionHash string) (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	g.mu.Lock()
	defer g.mu.Unlock()
	for k, v := range g.m {
		if !now.Before(v.expires) {
			delete(g.m, k)
		}
	}
	g.m[sessionHash] = grant{hash: sha256.Sum256([]byte(token)), expires: now.Add(downloadGrantTTL)}
	return token, nil
}

// redeem checks and consumes the session's grant.
func (g *grantStore) redeem(now time.Time, sessionHash, token string) bool {
	g.mu.Lock()
	v, ok := g.m[sessionHash]
	delete(g.m, sessionHash)
	g.mu.Unlock()
	if !ok || token == "" || !now.Before(v.expires) {
		return false
	}
	sum := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(sum[:], v.hash[:]) == 1
}
