package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"

	"github.com/phabioo/nexara/internal/hub/store"
)

// CSRF transport names.
const (
	// CSRFHeader is the request header HTMX sends the token in.
	CSRFHeader = "X-CSRF-Token"
	// CSRFFormField is the hidden form field name for plain form posts.
	CSRFFormField = "csrf_token"
	// CSRFCookieName is the base name of the pre-session double-submit cookie
	// (login, TOTP step); Cookies.CSRFName gives the name on the wire.
	CSRFCookieName = "nexus_csrf"

	maxCSRFTokenLen = 256
)

// csrfToken derives the token for a session: base64url(HMAC-SHA256(key,
// "csrf:" + idHash)). It is stable for the life of the session, unguessable
// without the secret key, and bound to that session only.
func csrfToken(key []byte, idHash string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("csrf:" + idHash))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// CSRFToken returns the token to embed in pages of the session (meta tag /
// hx-headers); the browser sends it back in CSRFHeader.
func (s *Service) CSRFToken(sess store.Session) string {
	return csrfToken(s.csrfKey, sess.IDHash)
}

// CheckCSRF verifies a submitted token against the session in constant time.
// Empty, oversized or other-session tokens fail.
func (s *Service) CheckCSRF(sess store.Session, token string) bool {
	if token == "" || len(token) > maxCSRFTokenLen || sess.IDHash == "" {
		return false
	}
	want := csrfToken(s.csrfKey, sess.IDHash)
	return subtle.ConstantTimeCompare([]byte(want), []byte(token)) == 1
}

// NewPreSessionCSRF returns a random token for the double-submit variant
// used before a session exists: set it as the CSRFCookieName cookie (see
// Cookies.CSRF) and render the same value into the form / header.
func NewPreSessionCSRF() (string, error) { return randomToken() }

// CheckDoubleSubmit compares the cookie value with the value submitted in
// the form field or header. Both must be present and equal.
func CheckDoubleSubmit(cookieValue, submitted string) bool {
	if cookieValue == "" || submitted == "" || len(cookieValue) > maxCSRFTokenLen || len(submitted) > maxCSRFTokenLen {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookieValue), []byte(submitted)) == 1
}
