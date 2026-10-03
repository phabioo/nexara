package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"strconv"

	"github.com/phabioo/nexara/internal/hub/store"
)

// Two-factor login is mandatory (decision #51). An operator who has none
// (an installation that skipped it in v0.1) can sign in with the passphrase,
// but the session is "enrollment pending": the HTTP layer lets it reach
// nothing except the enrollment page, its POST and logout until EnrollTOTP
// succeeded. The pending state is not stored anywhere. It follows from the
// user row (no TOTP yet), so it cannot be lost, forged or left behind.

// EnrollmentPending reports whether u must set up two-factor login before
// anything else. It is false for every operator with TOTP, and for all
// operators when Config.DemoPasswordOnly is set (plain-HTTP dev demo only).
func (s *Service) EnrollmentPending(u store.User) bool {
	return !u.TOTPEnabled && !s.passwordOnly
}

// PendingTOTPSecret returns the TOTP secret (base32) the enrollment page of
// this session shows. It is derived from a key only the hub knows, the user
// and the session, so it is the same on every reload, needs no server-side
// state, differs between sessions, and cannot be computed from the database
// contents. It becomes the user's secret only when EnrollTOTP accepted a code
// for it.
func (s *Service) PendingTOTPSecret(u store.User, sess store.Session) string {
	mac := hmac.New(sha256.New, s.enrollKey)
	mac.Write([]byte("user=" + strconv.FormatInt(u.ID, 10) + ";session=" + sess.IDHash))
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(mac.Sum(nil)[:20])
}

// EnrollTOTP completes the enrollment of the session's operator: code must be
// the current code for PendingTOTPSecret. On success the secret is sealed
// (bound to the user ID) and stored, TOTP is enabled, every session of the
// operator ends (including this one, so a password thief's session does not
// survive the new factor) and a fresh session replaces them. The code counts
// as used: signing in with it right afterwards is a replay and fails.
//
// Errors: ErrInvalidCode (wrong or malformed code; counts towards the sign-in
// limits like a wrong login code), ErrRateLimited, ErrAlreadyEnrolled.
func (s *Service) EnrollTOTP(ctx context.Context, userID int64, sess store.Session, code, ip string) (LoginResult, error) {
	s.enrollMu.Lock() // two sessions of one operator must not enroll different secrets at once
	defer s.enrollMu.Unlock()

	user, err := s.store.GetUserByID(ctx, userID)
	if errors.Is(err, store.ErrNotFound) {
		return LoginResult{}, ErrSessionExpired
	}
	if err != nil {
		return LoginResult{}, fmt.Errorf("auth: look up operator: %w", err)
	}
	res, err := s.reserveAttempt(ctx, user.OperatorID, ip)
	if err != nil {
		return LoginResult{}, err
	}
	if user.TOTPEnabled {
		res.refund()
		return LoginResult{}, ErrAlreadyEnrolled
	}

	secret := s.PendingTOTPSecret(user, sess)
	if !s.totp.VerifyTOTP(user.ID, secret, code, s.now()) {
		s.audit(ctx, user.OperatorID, ActionTOTPEnroll, store.AuditDenied, "ip="+cleanText(ip, maxIPLen)+" reason=bad_code")
		return LoginResult{}, ErrInvalidCode
	}
	fail := func(reason string, err error) (LoginResult, error) {
		res.refund()           // the code was right; the failure is ours
		s.totp.Forget(user.ID) // the code was not used for anything: let the operator try the next one
		s.audit(ctx, user.OperatorID, ActionTOTPEnroll, store.AuditError, "ip="+cleanText(ip, maxIPLen)+" reason="+reason)
		return LoginResult{}, err
	}
	sealed, err := s.SealTOTPSecret(user.ID, secret)
	if err != nil {
		return fail("seal_failed", fmt.Errorf("auth: seal TOTP secret: %w", err))
	}
	if err := s.store.SetTOTP(ctx, user.ID, sealed, true); err != nil {
		return fail("store_failed", fmt.Errorf("auth: store TOTP secret: %w", err))
	}
	user.TOTPSecretEnc, user.TOTPEnabled = sealed, true

	if _, err := s.sessions.DeleteAllForUser(ctx, user.ID); err != nil {
		res.refund()
		return LoginResult{}, fmt.Errorf("auth: end old sessions: %w", err)
	}
	raw, fresh, err := s.sessions.Create(ctx, user, sess.Persistent, ip, sess.UserAgent)
	if err != nil {
		res.refund()
		return LoginResult{}, err
	}
	res.succeed()
	s.audit(ctx, user.OperatorID, ActionTOTPEnroll, store.AuditOK, "ip="+cleanText(ip, maxIPLen))
	return LoginResult{User: user, SessionID: raw, Session: fresh}, nil
}
