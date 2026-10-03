// Package auth implements operator authentication for the Nexus hub:
// argon2id passphrases, encrypted TOTP secrets, sessions, two-step login,
// login rate limiting, CSRF tokens and the audit entries that go with them.
//
// Everything that depends on time takes an injectable clock (Config.Now) and
// the argon2 cost is injectable (HashParams), so tests run fast and
// deterministically. Nothing in this package logs; secrets (passphrases,
// TOTP codes and secrets, session IDs) never reach the audit log or errors.
package auth

import (
	"errors"
	"fmt"
	"time"
)

// Sentinel errors. Use errors.Is.
var (
	// ErrInvalidCredentials is returned for an unknown operator ID and for a
	// wrong passphrase alike, so callers cannot tell the two apart.
	ErrInvalidCredentials = errors.New("auth: invalid operator ID or passphrase")
	// ErrRateLimited means too many failed attempts; see RateLimitedError for the wait time.
	ErrRateLimited = errors.New("auth: too many failed attempts")
	// ErrSecondFactorRequired is returned by Login together with a populated
	// LoginResult (Challenge set) when the passphrase was correct but a TOTP
	// code is still needed. It is not a failure.
	ErrSecondFactorRequired = errors.New("auth: second factor required")
	// ErrInvalidCode means the TOTP code is wrong, malformed or was already used.
	ErrInvalidCode = errors.New("auth: invalid authentication code")
	// ErrInvalidChallenge means the second-factor challenge is unknown, expired,
	// already used or bound to another IP address. The user has to sign in again.
	ErrInvalidChallenge = errors.New("auth: sign-in challenge invalid or expired")
	// ErrSessionExpired means the session is unknown, malformed, idle for too
	// long or past its absolute lifetime.
	ErrSessionExpired = errors.New("auth: session expired")
	// ErrWeakPassphrase means the passphrase violates the length policy.
	ErrWeakPassphrase = errors.New("auth: passphrase does not meet the policy")
	// ErrAlreadyEnrolled means the operator already has two-factor login; enrollment must not replace it.
	ErrAlreadyEnrolled = errors.New("auth: two-factor login is already set up")
)

// RateLimitedError is the concrete error behind ErrRateLimited.
type RateLimitedError struct {
	// RetryAfter is how long the caller has to wait before the next attempt can succeed.
	RetryAfter time.Duration
}

func (e *RateLimitedError) Error() string {
	return fmt.Sprintf("%v (retry in %s)", ErrRateLimited, e.RetryAfter.Round(time.Second))
}

// Is makes errors.Is(err, ErrRateLimited) work.
func (e *RateLimitedError) Is(target error) bool { return target == ErrRateLimited }

// RetryAfter extracts the wait time from a rate-limit error (zero if err is none).
func RetryAfter(err error) time.Duration {
	var rl *RateLimitedError
	if errors.As(err, &rl) {
		return rl.RetryAfter
	}
	return 0
}

// UserMessage maps an error to the copy the login page shows. Unknown errors
// yield a generic message so internal details never reach the browser.
func UserMessage(err error) string {
	switch {
	case errors.Is(err, ErrInvalidCredentials):
		return "Invalid operator ID or passphrase."
	case errors.Is(err, ErrRateLimited):
		mins := int((RetryAfter(err) + time.Minute - 1) / time.Minute)
		if mins < 1 {
			mins = 1
		}
		if mins == 1 {
			return "Too many failed attempts. Try again in 1 minute."
		}
		return fmt.Sprintf("Too many failed attempts. Try again in %d minutes.", mins)
	case errors.Is(err, ErrInvalidCode):
		return "Invalid authentication code."
	case errors.Is(err, ErrInvalidChallenge):
		return "Sign-in timed out. Enter your credentials again."
	case errors.Is(err, ErrSessionExpired):
		return "Your session has expired. Sign in again."
	case errors.Is(err, ErrWeakPassphrase):
		return "Use a passphrase of at least 12 characters."
	default:
		return "Sign-in failed. Try again."
	}
}
