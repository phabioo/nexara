package auth

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"unicode/utf8"

	"github.com/phabioo/nexara/internal/hub/store"
)

// Sensitive actions of a signed-in operator (changing the passphrase, the
// later step-up for backups and updates) re-check the operator's secrets. An
// attacker with a stolen session must not be able to use them as a guessing
// oracle, so they share these rules:
//
//   - the passphrase check goes through the argon2 semaphore like a sign-in;
//   - every attempt is counted per operator before it is evaluated and given
//     back when it was right (the limit is the sign-in one: 5 per 15 min);
//   - one such action per operator is in flight at a time.

func opKey(userID int64) string { return limiterKey("op:", strconv.FormatInt(userID, 10)) }

// BeginOperatorAction claims the single in-flight slot of the operator for
// a sensitive action and returns the function that releases it. It returns
// ErrBusy while another one is running. A caller that holds the slot must
// not call Reauthenticate (which claims it itself).
func (s *Service) BeginOperatorAction(userID int64) (done func(), err error) {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	if _, busy := s.opBusy[userID]; busy {
		return nil, ErrBusy
	}
	s.opBusy[userID] = struct{}{}
	return func() {
		s.opMu.Lock()
		delete(s.opBusy, userID)
		s.opMu.Unlock()
	}, nil
}

// reserveOperator counts one attempt of the operator before it is evaluated.
// It returns the function that gives the count back (nothing was guessed),
// the function that ends a fully successful check (gives the count back and
// forgets the operator's earlier failures, like a successful sign-in), or a
// *RateLimitedError (the first blocked attempt of a block is audited under action).
func (s *Service) reserveOperator(ctx context.Context, user store.User, ip, action string) (refund, succeed func(), err error) {
	key := opKey(user.ID)
	s.opMu.Lock()
	blocked, retry, first := s.opLimit.check(key)
	at := s.now()
	if !blocked {
		s.opLimit.failAt(at, key)
	}
	s.opMu.Unlock()
	if blocked {
		if first {
			s.audit(ctx, user.OperatorID, action, store.AuditDenied,
				fmt.Sprintf("ip=%s reason=throttled retry_after=%ds", cleanText(ip, maxIPLen), int(retry.Seconds())))
		}
		return nil, nil, &RateLimitedError{RetryAfter: retry}
	}
	return func() { s.opLimit.unfail(key, at) }, func() { s.opLimit.reset(key) }, nil
}

// checkReservedPassphrase evaluates the passphrase for an attempt that was
// already counted. Errors other than ErrWrongPassphrase mean nothing was
// guessed; the caller refunds.
func (s *Service) checkReservedPassphrase(ctx context.Context, user store.User, passphrase string) error {
	if passphrase == "" || utf8.RuneCountInString(passphrase) > MaxPassphraseLength {
		return ErrWrongPassphrase
	}
	ok, err := s.verifyPassword(ctx, passphrase, user.PassHash)
	if err != nil {
		return fmt.Errorf("auth: verify passphrase: %w", err)
	}
	if !ok {
		return ErrWrongPassphrase
	}
	return nil
}

// CheckPassphrase verifies the current passphrase of a signed-in operator,
// for the passphrase change in Settings. user must be freshly loaded. It uses
// the argon2 semaphore and the per-operator attempt limit; action is the audit
// action under which a throttled attempt is recorded. Errors: ErrWrongPassphrase
// (counted; the caller audits it), *RateLimitedError (errors.Is ErrRateLimited),
// ErrBusy. The caller should hold BeginOperatorAction for the whole change.
func (s *Service) CheckPassphrase(ctx context.Context, user store.User, passphrase, ip, action string) error {
	refund, succeed, err := s.reserveOperator(ctx, user, ip, action)
	if err != nil {
		return err
	}
	if err := s.checkReservedPassphrase(ctx, user, passphrase); err != nil {
		if !errors.Is(err, ErrWrongPassphrase) {
			refund()
		}
		return err
	}
	succeed()
	return nil
}

// Reauthenticate is the step-up check before a sensitive action: it verifies
// the operator's passphrase (argon2 semaphore) and a current TOTP code (with
// the replay guard of the sign-in, so a code works once). The attempt is
// counted per operator before it is evaluated, shares the limit with
// CheckPassphrase and is given back on success; one step-up per operator is in
// flight at a time. Success and failure are audited as ActionReauth with
// fixed reason codes and the IP, never the secrets.
//
// user must be freshly loaded. Errors: ErrWrongPassphrase, ErrInvalidCode,
// ErrNoSecondFactor, a *RateLimitedError (errors.Is ErrRateLimited), ErrBusy.
// With Config.DemoPasswordOnly an operator without TOTP passes with the
// passphrase alone (code is ignored); the production hub has no such mode.
func (s *Service) Reauthenticate(ctx context.Context, user store.User, passphrase, code, ip string) error {
	done, err := s.BeginOperatorAction(user.ID)
	if err != nil {
		return err
	}
	defer done()

	refund, succeed, err := s.reserveOperator(ctx, user, ip, ActionReauth)
	if err != nil {
		return err
	}
	deny := func(reason string, err error) error {
		s.audit(ctx, user.OperatorID, ActionReauth, store.AuditDenied, "ip="+cleanText(ip, maxIPLen)+" reason="+reason)
		return err
	}

	if err := s.checkReservedPassphrase(ctx, user, passphrase); err != nil {
		if !errors.Is(err, ErrWrongPassphrase) {
			refund()
			return err
		}
		return deny("bad_passphrase", err)
	}

	if !user.TOTPEnabled || len(user.TOTPSecretEnc) == 0 {
		if s.passwordOnly {
			succeed()
			s.audit(ctx, user.OperatorID, ActionReauth, store.AuditOK, "ip="+cleanText(ip, maxIPLen)+" passphrase_only")
			return nil
		}
		refund()
		return deny("no_second_factor", ErrNoSecondFactor)
	}
	secret, err := s.OpenTOTPSecret(user.ID, user.TOTPSecretEnc)
	if err != nil {
		refund()
		s.audit(ctx, user.OperatorID, ActionReauth, store.AuditError, "ip="+cleanText(ip, maxIPLen)+" reason=totp_secret_unusable")
		return fmt.Errorf("auth: open TOTP secret: %w", err)
	}
	if !s.totp.VerifyTOTP(user.ID, secret, code, s.now()) {
		return deny("bad_code", ErrInvalidCode)
	}
	succeed()
	s.audit(ctx, user.OperatorID, ActionReauth, store.AuditOK, "ip="+cleanText(ip, maxIPLen))
	return nil
}
