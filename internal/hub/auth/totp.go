package auth

import (
	"crypto/subtle"
	"sync"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TOTPIssuer is the issuer shown in authenticator apps.
const TOTPIssuer = "Nexara Nexus"

const (
	totpPeriod = 30 // seconds; the de-facto standard every authenticator app supports
	totpSkew   = 1  // accepted steps before and after the current one
	totpDigits = 6
)

// TOTPEnrollment is a freshly generated TOTP secret.
type TOTPEnrollment struct {
	Secret string // base32; encrypt with Seal(key, []byte(Secret), AADTOTP) before storing
	URL    string // otpauth:// URL for the QR code
}

// NewTOTP generates a TOTP secret (160 bit, SHA-1, 6 digits, 30 s, which is
// what all common authenticator apps support) for the operator.
func NewTOTP(operatorID string) (TOTPEnrollment, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      TOTPIssuer,
		AccountName: operatorID,
		Period:      totpPeriod,
		SecretSize:  20,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return TOTPEnrollment{}, err
	}
	return TOTPEnrollment{Secret: key.Secret(), URL: key.URL()}, nil
}

func totpOpts() totp.ValidateOpts {
	return totp.ValidateOpts{Period: totpPeriod, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
}

// normalizeCode strips spaces and dashes (authenticator apps group digits)
// and reports whether the result is exactly six ASCII digits.
func normalizeCode(code string) (string, bool) {
	out := make([]byte, 0, totpDigits)
	for i := 0; i < len(code); i++ {
		c := code[i]
		switch {
		case c == ' ' || c == '-':
		case c >= '0' && c <= '9':
			out = append(out, c)
		default:
			return "", false
		}
	}
	return string(out), len(out) == totpDigits
}

// MatchTOTP checks code against secret for the time steps now-1, now and
// now+1 and returns the matching time step (the newest one if several
// match). It has no replay protection; use TOTPVerifier for logins.
func MatchTOTP(secret, code string, now time.Time) (step int64, ok bool) {
	code, valid := normalizeCode(code)
	if !valid {
		return 0, false
	}
	cur := now.Unix() / totpPeriod
	// Check every candidate without early exit so timing does not reveal which step matched.
	for off := int64(totpSkew); off >= -totpSkew; off-- {
		s := cur + off
		want, err := totp.GenerateCodeCustom(secret, time.Unix(s*totpPeriod, 0), totpOpts())
		if err != nil {
			return 0, false // secret is not valid base32
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 && !ok {
			step, ok = s, true
		}
	}
	return step, ok
}

// TOTPVerifier validates codes and rejects replays: per user it remembers the
// last accepted time step in memory and only accepts strictly newer ones.
// Because a code is valid for three steps, using one makes it (and every
// older code) unusable, which is what stops an observed code from being
// replayed. The state is lost on restart; the window is at most 90 seconds.
type TOTPVerifier struct {
	mu   sync.Mutex
	last map[int64]int64 // user ID -> last accepted step
}

// NewTOTPVerifier returns an empty verifier.
func NewTOTPVerifier() *TOTPVerifier { return &TOTPVerifier{last: map[int64]int64{}} }

// VerifyTOTP reports whether code is valid for secret at now and has not been
// used before by this user. On success the step is recorded atomically, so
// of two concurrent requests with the same code only one succeeds.
func (v *TOTPVerifier) VerifyTOTP(userID int64, secret, code string, now time.Time) bool {
	step, ok := MatchTOTP(secret, code, now)
	if !ok {
		return false
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if last, seen := v.last[userID]; seen && step <= last {
		return false
	}
	v.last[userID] = step
	return true
}

// Reset drops the replay state of all users.
func (v *TOTPVerifier) Reset() {
	v.mu.Lock()
	clear(v.last)
	v.mu.Unlock()
}

// Forget drops the replay state of a user (after 2FA was reset or re-enrolled).
func (v *TOTPVerifier) Forget(userID int64) {
	v.mu.Lock()
	delete(v.last, userID)
	v.mu.Unlock()
}
