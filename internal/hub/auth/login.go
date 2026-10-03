package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/phabioo/nexara/internal/hub/store"
)

const (
	// ChallengeTTL is how long the user has to enter the TOTP code after the passphrase.
	ChallengeTTL = 5 * time.Minute

	maxChallenges        = 1000
	maxChallengeFailures = 5 // wrong codes per challenge before it is discarded
)

// challenge is a pending second-factor step. It lives in memory only, is
// bound to the user and the client IP, expires after ChallengeTTL and is
// consumed by the first successful verification.
type challenge struct {
	userID     int64
	operatorID string
	ip         string
	userAgent  string
	persistent bool
	expires    time.Time
	failures   int
}

// LoginResult is the outcome of Login and VerifySecondFactor.
type LoginResult struct {
	User store.User

	// Set when a session was created: the raw ID for the cookie (see
	// Service.Cookies().Session) and the stored session.
	SessionID string
	Session   store.Session

	// Set together with ErrSecondFactorRequired: the challenge ID to send to
	// the TOTP step (hidden form field) and when it expires.
	Challenge        string
	ChallengeExpires time.Time
}

// Login is step one of the sign-in. It returns:
//   - a LoginResult with a session and nil if the account has no TOTP;
//   - a LoginResult with Challenge set and ErrSecondFactorRequired if the
//     passphrase is right and a TOTP code is still needed;
//   - ErrInvalidCredentials for an unknown operator ID or a wrong passphrase
//     (same error, same work: unknown IDs get a dummy argon2 verification);
//   - a *RateLimitedError (errors.Is ErrRateLimited) while the IP or the
//     account is blocked.
//
// persistent is the "keep me signed in" choice; it is carried through the
// second factor and never skips it (decision #29). The account's failure
// counter is reset only when the sign-in fully succeeds, so a password
// thief cannot reset it by repeating step one.
func (s *Service) Login(ctx context.Context, operatorID, passphrase, ip, userAgent string, persistent bool) (LoginResult, error) {
	operatorID = strings.TrimSpace(operatorID)
	// The attempt is counted before it is evaluated and given back when it
	// turns out right, so parallel guesses cannot outrun the limits (A-01).
	res, err := s.reserveAttempt(ctx, operatorID, ip)
	if err != nil {
		return LoginResult{}, err
	}

	// Cheap rejections that must not reach argon2: empty input and inputs
	// that can never be a valid passphrase.
	if operatorID == "" || passphrase == "" || utf8.RuneCountInString(passphrase) > MaxPassphraseLength {
		s.loginDenied(ctx, operatorID, ip, "invalid_input")
		return LoginResult{}, ErrInvalidCredentials
	}

	user, err := s.store.GetUserByOperatorID(ctx, operatorID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		if err := s.burnPasswordHash(ctx, passphrase); err != nil {
			res.refund() // nothing was evaluated
			return LoginResult{}, err
		}
		s.loginDenied(ctx, operatorID, ip, "unknown_user")
		return LoginResult{}, ErrInvalidCredentials
	case err != nil:
		res.refund()
		return LoginResult{}, fmt.Errorf("auth: look up operator: %w", err)
	}

	ok, err := s.verifyPassword(ctx, passphrase, user.PassHash)
	if err != nil {
		res.refund()
		if !errors.Is(err, ErrBusy) && ctx.Err() == nil {
			s.audit(ctx, user.OperatorID, ActionLogin, store.AuditError, "ip="+cleanText(ip, maxIPLen)+" reason=stored_hash_unusable")
		}
		return LoginResult{}, fmt.Errorf("auth: verify passphrase: %w", err)
	}
	if !ok {
		s.loginDenied(ctx, user.OperatorID, ip, "bad_passphrase")
		return LoginResult{}, ErrInvalidCredentials
	}

	s.rehashIfNeeded(ctx, user, passphrase)

	if user.TOTPEnabled {
		id, expires, err := s.newChallenge(user, ip, userAgent, persistent)
		if err != nil {
			res.refund()
			return LoginResult{}, err
		}
		// Step one of two: the right passphrase is not a failure, but it
		// does not reset the counters either (a thief repeating it must not).
		res.refund()
		return LoginResult{User: user, Challenge: id, ChallengeExpires: expires}, ErrSecondFactorRequired
	}
	return s.finishLogin(ctx, user, ip, userAgent, persistent, "", res)
}

// VerifySecondFactor is step two: it checks the TOTP code for a pending
// challenge and, on success, consumes the challenge and creates the session.
// Errors: ErrInvalidChallenge (unknown, expired, used, other IP: sign in
// again), ErrInvalidCode (wrong, malformed or replayed code: try again),
// ErrRateLimited. Wrong codes count towards the IP and account limits; after
// five wrong codes the challenge is discarded. Every attempt is counted
// (challenge and limits) before the code is evaluated, so parallel requests
// cannot get more evaluations than the limits allow.
func (s *Service) VerifySecondFactor(ctx context.Context, challengeID, code, ip string) (LoginResult, error) {
	ch, ok := s.reserveChallengeAttempt(challengeID)
	if !ok {
		return LoginResult{}, ErrInvalidChallenge
	}
	res, err := s.reserveAttempt(ctx, ch.operatorID, ip)
	if err != nil {
		s.releaseChallengeAttempt(challengeID)
		return LoginResult{}, err
	}
	if ch.ip != ip {
		s.dropChallenge(challengeID)
		res.refundAccount() // only the address that replayed the challenge pays
		s.audit(ctx, ch.operatorID, ActionSecondFact, store.AuditDenied, "ip="+cleanText(ip, maxIPLen)+" reason=challenge_ip_mismatch")
		return LoginResult{}, ErrInvalidChallenge
	}

	user, err := s.store.GetUserByID(ctx, ch.userID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && (!user.TOTPEnabled || len(user.TOTPSecretEnc) == 0)) {
		s.dropChallenge(challengeID)
		res.refund()
		return LoginResult{}, ErrInvalidChallenge
	}
	if err != nil {
		res.refund()
		s.releaseChallengeAttempt(challengeID)
		return LoginResult{}, fmt.Errorf("auth: look up operator: %w", err)
	}
	secret, err := s.OpenTOTPSecret(user.ID, user.TOTPSecretEnc)
	if err != nil {
		res.refund()
		s.releaseChallengeAttempt(challengeID)
		s.audit(ctx, user.OperatorID, ActionSecondFact, store.AuditError, "ip="+cleanText(ip, maxIPLen)+" reason=totp_secret_unusable")
		return LoginResult{}, fmt.Errorf("auth: open TOTP secret: %w", err)
	}

	if !s.totp.VerifyTOTP(user.ID, secret, code, s.now()) {
		s.challengeFailed(challengeID)
		s.audit(ctx, user.OperatorID, ActionSecondFact, store.AuditDenied, "ip="+cleanText(ip, maxIPLen)+" reason=bad_code")
		return LoginResult{}, ErrInvalidCode
	}
	// Consume: of two concurrent requests with the same challenge only one gets here with it.
	if _, ok := s.takeChallenge(challengeID); !ok {
		res.refund()
		return LoginResult{}, ErrInvalidChallenge
	}
	s.audit(ctx, user.OperatorID, ActionSecondFact, store.AuditOK, "ip="+cleanText(ip, maxIPLen))
	return s.finishLogin(ctx, user, ip, ch.userAgent, ch.persistent, "second_factor", res)
}

// Logout ends the session and audits it. Unknown sessions are ignored.
func (s *Service) Logout(ctx context.Context, rawSessionID, ip string) error {
	if rawSessionID == "" || len(rawSessionID) > maxSessionIDLen {
		return nil
	}
	hash := HashSessionID(rawSessionID)
	sess, err := s.store.GetSession(ctx, hash)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	err = s.store.DeleteSession(ctx, hash)
	s.sessions.rev.notify() // open streams of this session end now
	if err != nil {
		return err
	}
	name := ""
	if u, err := s.store.GetUserByID(ctx, sess.UserID); err == nil {
		name = u.OperatorID
	}
	s.audit(ctx, name, ActionLogout, store.AuditOK, "ip="+cleanText(ip, maxIPLen))
	return nil
}

// --- internals ---------------------------------------------------------------

func (s *Service) finishLogin(ctx context.Context, user store.User, ip, userAgent string, persistent bool, via string, res reservation) (LoginResult, error) {
	raw, sess, err := s.sessions.Create(ctx, user, persistent, ip, userAgent)
	if err != nil {
		res.refund()
		return LoginResult{}, err
	}
	res.succeed()
	detail := "ip=" + cleanText(ip, maxIPLen)
	if persistent {
		detail += " persistent"
	}
	if via != "" {
		detail += " via=" + via
	}
	s.audit(ctx, user.OperatorID, ActionLogin, store.AuditOK, detail)
	return LoginResult{User: user, SessionID: raw, Session: sess}, nil
}

// reserveAttempt counts one attempt against the IP, (account, IP) and
// account limits before it is evaluated. It returns a *RateLimitedError if
// one of them is blocked (nothing is counted then) and audits the first
// blocked attempt of each block.
func (s *Service) reserveAttempt(ctx context.Context, operatorID, ip string) (reservation, error) {
	res, blocked, retry, first := s.limiter.reserve(operatorID, ip)
	if !blocked {
		return res, nil
	}
	if first {
		s.audit(ctx, operatorID, ActionLoginLocked, store.AuditDenied,
			fmt.Sprintf("ip=%s retry_after=%ds", cleanText(ip, maxIPLen), int(retry.Seconds())))
	}
	return reservation{}, &RateLimitedError{RetryAfter: retry}
}

// loginDenied audits a failed attempt; its count is the reservation made
// before the attempt was evaluated.
func (s *Service) loginDenied(ctx context.Context, attempted, ip, reason string) {
	s.audit(ctx, attempted, ActionLogin, store.AuditDenied, "ip="+cleanText(ip, maxIPLen)+" reason="+reason)
}

// rehashIfNeeded upgrades the stored hash after a successful verification
// when the cost parameters changed. Best effort: a failure changes nothing.
func (s *Service) rehashIfNeeded(ctx context.Context, user store.User, passphrase string) {
	if !NeedsRehash(user.PassHash, s.params) {
		return
	}
	if err := s.acquireHash(ctx); err != nil {
		return
	}
	defer s.releaseHash()
	if enc, err := HashPassword(passphrase, s.params); err == nil {
		_ = s.store.UpdatePassword(ctx, user.ID, enc)
	}
}

func (s *Service) newChallenge(user store.User, ip, userAgent string, persistent bool) (string, time.Time, error) {
	id, err := randomToken()
	if err != nil {
		return "", time.Time{}, err
	}
	now := s.now()
	expires := now.Add(ChallengeTTL)
	s.chMu.Lock()
	defer s.chMu.Unlock()
	s.pruneChallengesLocked(now)
	if len(s.challenges) >= maxChallenges { // evict the one closest to expiry
		var oldest string
		for k, c := range s.challenges {
			if oldest == "" || c.expires.Before(s.challenges[oldest].expires) {
				oldest = k
			}
		}
		delete(s.challenges, oldest)
	}
	s.challenges[id] = &challenge{
		userID: user.ID, operatorID: user.OperatorID, ip: ip,
		userAgent: truncate(userAgent, maxUserAgentLen), persistent: persistent, expires: expires,
	}
	return id, expires, nil
}

func (s *Service) pruneChallengesLocked(now time.Time) {
	for k, c := range s.challenges {
		if !now.Before(c.expires) {
			delete(s.challenges, k)
		}
	}
}

// reserveChallengeAttempt counts one evaluation against a live challenge
// (under chMu, before the code is looked at) and returns a copy of it. Once
// maxChallengeFailures evaluations have been handed out, further requests are
// refused without being evaluated; challengeFailed removes the challenge when
// the last of them failed.
func (s *Service) reserveChallengeAttempt(id string) (challenge, bool) {
	s.chMu.Lock()
	defer s.chMu.Unlock()
	c, ok := s.challenges[id]
	if !ok {
		return challenge{}, false
	}
	if !s.now().Before(c.expires) {
		delete(s.challenges, id)
		return challenge{}, false
	}
	if c.failures >= maxChallengeFailures {
		return challenge{}, false
	}
	c.failures++
	return *c, true
}

// releaseChallengeAttempt gives back a reservation whose code was never evaluated.
func (s *Service) releaseChallengeAttempt(id string) {
	s.chMu.Lock()
	defer s.chMu.Unlock()
	if c, ok := s.challenges[id]; ok && c.failures > 0 {
		c.failures--
	}
}

func (s *Service) takeChallenge(id string) (challenge, bool) {
	s.chMu.Lock()
	defer s.chMu.Unlock()
	c, ok := s.challenges[id]
	if !ok || !s.now().Before(c.expires) {
		delete(s.challenges, id)
		return challenge{}, false
	}
	delete(s.challenges, id)
	return *c, true
}

func (s *Service) dropChallenge(id string) {
	s.chMu.Lock()
	delete(s.challenges, id)
	s.chMu.Unlock()
}

// challengeFailed discards the challenge once its last allowed evaluation failed.
func (s *Service) challengeFailed(id string) {
	s.chMu.Lock()
	defer s.chMu.Unlock()
	if c, ok := s.challenges[id]; ok && c.failures >= maxChallengeFailures {
		delete(s.challenges, id)
	}
}
