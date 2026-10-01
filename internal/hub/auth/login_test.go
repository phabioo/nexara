package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/store"
)

func TestLoginWithoutTOTP(t *testing.T) {
	e := newEnv(t)
	u := e.addUser("alice", testPass)

	res, err := e.svc.Login(e.ctx, "alice", testPass, testIP, testUA, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.SessionID == "" || res.Challenge != "" || res.User.ID != u.ID {
		t.Fatalf("result %+v", res)
	}
	if res.Session.Persistent {
		t.Fatal("session must not be persistent")
	}
	user, _, err := e.svc.Sessions().Validate(e.ctx, res.SessionID)
	if err != nil || user.ID != u.ID {
		t.Fatalf("session does not validate: %v", err)
	}

	t.Run("operator ID is case-insensitive and trimmed", func(t *testing.T) {
		if _, err := e.svc.Login(e.ctx, "  ALICE ", testPass, testIP, testUA, true); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("persistent choice is stored", func(t *testing.T) {
		res, err := e.svc.Login(e.ctx, "alice", testPass, testIP, testUA, true)
		if err != nil || !res.Session.Persistent {
			t.Fatalf("%+v, %v", res, err)
		}
	})
}

func TestLoginCredentialErrors(t *testing.T) {
	e := newEnv(t)
	e.addUser("alice", testPass)
	tests := []struct {
		name, id, pass string
	}{
		{"wrong passphrase", "alice", testPass + "x"},
		{"unknown user", "mallory", testPass},
		{"empty id", "", testPass},
		{"empty passphrase", "alice", ""},
		{"oversized passphrase", "alice", strings.Repeat("a", MaxPassphraseLength+1)},
		{"sql-ish id", "alice' OR '1'='1", testPass},
	}
	var msgs []string
	for i, tc := range tests {
		ip := fmt.Sprintf("192.0.2.%d", i+1) // distinct IPs so nothing rate-limits
		res, err := e.svc.Login(e.ctx, tc.id, tc.pass, ip, testUA, false)
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("%s: err = %v, want ErrInvalidCredentials", tc.name, err)
		}
		if res.SessionID != "" || res.Challenge != "" {
			t.Errorf("%s: result must be empty: %+v", tc.name, res)
		}
		msgs = append(msgs, UserMessage(err))
	}
	for _, m := range msgs {
		if m != msgs[0] {
			t.Fatalf("messages differ: %q vs %q", m, msgs[0])
		}
	}
}

func TestLoginUnknownUserDoesArgonWork(t *testing.T) {
	e := newEnv(t)
	e.addUser("alice", testPass)
	if _, err := e.svc.Login(e.ctx, "nobody", testPass, testIP, testUA, false); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatal(err)
	}
	if e.svc.dummyHash == "" {
		t.Fatal("a dummy hash must have been computed to equalize timing")
	}
	if _, err := parseHash(e.svc.dummyHash); err != nil {
		t.Fatalf("dummy hash malformed: %v", err)
	}
	if NeedsRehash(e.svc.dummyHash, e.svc.params) {
		t.Fatal("dummy hash must use the service parameters")
	}
}

func TestLoginRehashesOldParameters(t *testing.T) {
	e := newEnv(t)
	old := testParams
	old.Time = 2
	hash, _ := HashPassword(testPass, old)
	u, err := e.store.CreateUser(e.ctx, store.User{OperatorID: "alice", PassHash: hash})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Login(e.ctx, "alice", testPass, testIP, testUA, false); err != nil {
		t.Fatal(err)
	}
	got, _ := e.store.GetUserByID(e.ctx, u.ID)
	if got.PassHash == hash || NeedsRehash(got.PassHash, testParams) {
		t.Fatalf("hash was not upgraded: %s", got.PassHash)
	}
	if ok, _ := VerifyPassword(testPass, got.PassHash); !ok {
		t.Fatal("upgraded hash must still verify")
	}
}

func TestLoginWithTOTP(t *testing.T) {
	e := newEnv(t)
	u, secret := e.addTOTPUser("alice", testPass)

	res, err := e.svc.Login(e.ctx, "alice", testPass, testIP, testUA, true)
	if !errors.Is(err, ErrSecondFactorRequired) {
		t.Fatalf("err = %v, want ErrSecondFactorRequired", err)
	}
	if res.SessionID != "" || res.Challenge == "" || len(res.Challenge) != 43 {
		t.Fatalf("result %+v", res)
	}
	if want := e.clock.Now().Add(ChallengeTTL); !res.ChallengeExpires.Equal(want) {
		t.Fatalf("challenge expires %v, want %v", res.ChallengeExpires, want)
	}
	if n, _ := e.store.CountUsers(e.ctx); n != 1 {
		t.Fatal("setup broken")
	}
	// No session exists yet.
	if n, _ := e.store.DeleteUserSessions(e.ctx, u.ID); n != 0 {
		t.Fatalf("%d sessions exist before the second factor", n)
	}

	final, err := e.svc.VerifySecondFactor(e.ctx, res.Challenge, codeAt(t, secret, e.clock.Now()), testIP)
	if err != nil {
		t.Fatal(err)
	}
	if final.SessionID == "" || !final.Session.Persistent || final.User.ID != u.ID {
		t.Fatalf("final %+v (the keep-signed-in choice must survive the second step)", final)
	}
	if final.Session.UserAgent != testUA {
		t.Fatalf("user agent %q not carried over", final.Session.UserAgent)
	}
	if _, _, err := e.svc.Sessions().Validate(e.ctx, final.SessionID); err != nil {
		t.Fatal(err)
	}
}

func TestSecondFactorChallengeRules(t *testing.T) {
	type setup struct {
		e      *testEnv
		secret string
		chal   string
	}
	start := func(t *testing.T) setup {
		e := newEnv(t)
		_, secret := e.addTOTPUser("alice", testPass)
		res, err := e.svc.Login(e.ctx, "alice", testPass, testIP, testUA, false)
		if !errors.Is(err, ErrSecondFactorRequired) {
			t.Fatal(err)
		}
		return setup{e, secret, res.Challenge}
	}

	t.Run("expires after 5 minutes", func(t *testing.T) {
		s := start(t)
		s.e.clock.Advance(ChallengeTTL - time.Second)
		code := codeAt(t, s.secret, s.e.clock.Now())
		s.e.clock.Advance(time.Second)
		if _, err := s.e.svc.VerifySecondFactor(s.e.ctx, s.chal, code, testIP); !errors.Is(err, ErrInvalidChallenge) {
			t.Fatalf("err = %v, want ErrInvalidChallenge", err)
		}
	})
	t.Run("valid just before expiry", func(t *testing.T) {
		s := start(t)
		s.e.clock.Advance(ChallengeTTL - time.Second)
		if _, err := s.e.svc.VerifySecondFactor(s.e.ctx, s.chal, codeAt(t, s.secret, s.e.clock.Now()), testIP); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("single use", func(t *testing.T) {
		s := start(t)
		code := codeAt(t, s.secret, s.e.clock.Now())
		if _, err := s.e.svc.VerifySecondFactor(s.e.ctx, s.chal, code, testIP); err != nil {
			t.Fatal(err)
		}
		// Even with a fresh, never-used code the challenge is gone.
		s.e.clock.Advance(30 * time.Second)
		code2 := codeAt(t, s.secret, s.e.clock.Now())
		if _, err := s.e.svc.VerifySecondFactor(s.e.ctx, s.chal, code2, testIP); !errors.Is(err, ErrInvalidChallenge) {
			t.Fatalf("second use: err = %v, want ErrInvalidChallenge", err)
		}
	})
	t.Run("bound to the IP", func(t *testing.T) {
		s := start(t)
		code := codeAt(t, s.secret, s.e.clock.Now())
		if _, err := s.e.svc.VerifySecondFactor(s.e.ctx, s.chal, code, "198.51.100.7"); !errors.Is(err, ErrInvalidChallenge) {
			t.Fatalf("err = %v, want ErrInvalidChallenge", err)
		}
		// A mismatch burns the challenge: the right IP cannot use it afterwards.
		if _, err := s.e.svc.VerifySecondFactor(s.e.ctx, s.chal, code, testIP); !errors.Is(err, ErrInvalidChallenge) {
			t.Fatalf("after mismatch: err = %v, want ErrInvalidChallenge", err)
		}
	})
	t.Run("unknown challenge", func(t *testing.T) {
		s := start(t)
		for _, id := range []string{"", "nope", strings.Repeat("A", 43)} {
			if _, err := s.e.svc.VerifySecondFactor(s.e.ctx, id, "123456", testIP); !errors.Is(err, ErrInvalidChallenge) {
				t.Fatalf("id %q: err = %v", id, err)
			}
		}
	})
	t.Run("wrong code keeps the challenge, right code then works", func(t *testing.T) {
		s := start(t)
		bad := wrongCode(s.secret, s.e.clock.Now())
		if _, err := s.e.svc.VerifySecondFactor(s.e.ctx, s.chal, bad, testIP); !errors.Is(err, ErrInvalidCode) {
			t.Fatalf("err = %v, want ErrInvalidCode", err)
		}
		if _, err := s.e.svc.VerifySecondFactor(s.e.ctx, s.chal, codeAt(t, s.secret, s.e.clock.Now()), testIP); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("a used code cannot be replayed on a new challenge", func(t *testing.T) {
		s := start(t)
		code := codeAt(t, s.secret, s.e.clock.Now())
		if _, err := s.e.svc.VerifySecondFactor(s.e.ctx, s.chal, code, testIP); err != nil {
			t.Fatal(err)
		}
		res, err := s.e.svc.Login(s.e.ctx, "alice", testPass, testIP, testUA, false)
		if !errors.Is(err, ErrSecondFactorRequired) {
			t.Fatal(err)
		}
		if _, err := s.e.svc.VerifySecondFactor(s.e.ctx, res.Challenge, code, testIP); !errors.Is(err, ErrInvalidCode) {
			t.Fatalf("replay: err = %v, want ErrInvalidCode", err)
		}
	})
	t.Run("challenge is discarded after five wrong codes", func(t *testing.T) {
		s := start(t)
		bad := wrongCode(s.secret, s.e.clock.Now())
		for i := 0; i < maxChallengeFailures; i++ {
			if _, err := s.e.svc.VerifySecondFactor(s.e.ctx, s.chal, bad, testIP); !errors.Is(err, ErrInvalidCode) {
				t.Fatalf("attempt %d: %v", i, err)
			}
		}
		// Rate limit (5) and challenge limit (5) coincide; wait the window out so only the challenge rule is left.
		s.e.clock.Advance(16 * time.Minute)
		if _, err := s.e.svc.VerifySecondFactor(s.e.ctx, s.chal, "123456", testIP); !errors.Is(err, ErrInvalidChallenge) {
			t.Fatalf("err = %v, want ErrInvalidChallenge", err)
		}
	})
	t.Run("totp disabled in the meantime", func(t *testing.T) {
		s := start(t)
		u, _ := s.e.store.GetUserByOperatorID(s.e.ctx, "alice")
		if err := s.e.store.SetTOTP(s.e.ctx, u.ID, nil, false); err != nil {
			t.Fatal(err)
		}
		if _, err := s.e.svc.VerifySecondFactor(s.e.ctx, s.chal, "123456", testIP); !errors.Is(err, ErrInvalidChallenge) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("challenge cannot be used to skip the code", func(t *testing.T) {
		s := start(t)
		for _, code := range []string{"", "      ", "abcdef"} {
			if _, err := s.e.svc.VerifySecondFactor(s.e.ctx, s.chal, code, testIP); !errors.Is(err, ErrInvalidCode) {
				t.Fatalf("code %q: err = %v", code, err)
			}
		}
	})
	t.Run("concurrent use of one challenge yields one session", func(t *testing.T) {
		s := start(t)
		code := codeAt(t, s.secret, s.e.clock.Now())
		var wg sync.WaitGroup
		var mu sync.Mutex
		ok := 0
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := s.e.svc.VerifySecondFactor(s.e.ctx, s.chal, code, testIP); err == nil {
					mu.Lock()
					ok++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if ok != 1 {
			t.Fatalf("%d successful verifications, want 1", ok)
		}
	})
}

func TestChallengesAreBounded(t *testing.T) {
	e := newEnv(t)
	u, _ := e.addTOTPUser("alice", testPass)
	for i := 0; i < maxChallenges+50; i++ {
		if _, _, err := e.svc.newChallenge(u, testIP, testUA, false); err != nil {
			t.Fatal(err)
		}
	}
	e.svc.chMu.Lock()
	n := len(e.svc.challenges)
	e.svc.chMu.Unlock()
	if n > maxChallenges {
		t.Fatalf("%d challenges held", n)
	}
	e.clock.Advance(ChallengeTTL)
	if _, _, err := e.svc.newChallenge(u, testIP, testUA, false); err != nil {
		t.Fatal(err)
	}
	e.svc.chMu.Lock()
	n = len(e.svc.challenges)
	e.svc.chMu.Unlock()
	if n != 1 {
		t.Fatalf("expired challenges not pruned: %d", n)
	}
}

func TestRateLimitPerIP(t *testing.T) {
	e := newEnv(t)
	e.addUser("alice", testPass)
	e.addUser("bob", testPass2)

	// Five failures from one IP against different accounts block that IP.
	for i := 0; i < 5; i++ {
		_, err := e.svc.Login(e.ctx, fmt.Sprintf("user%d", i), "wrong", testIP, testUA, false)
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	_, err := e.svc.Login(e.ctx, "bob", testPass2, testIP, testUA, false)
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("err = %v, want ErrRateLimited even with correct credentials", err)
	}
	if got := RetryAfter(err); got <= 0 || got > 15*time.Minute {
		t.Fatalf("retry after %v", got)
	}
	if msg := UserMessage(err); !strings.Contains(msg, "Too many") || !strings.Contains(msg, "15 minutes") {
		t.Fatalf("message %q", msg)
	}
	// Another IP is unaffected.
	if _, err := e.svc.Login(e.ctx, "bob", testPass2, "192.0.2.99", testUA, false); err != nil {
		t.Fatalf("other IP: %v", err)
	}
	// After the window the IP may try again.
	e.clock.Advance(15 * time.Minute)
	if _, err := e.svc.Login(e.ctx, "bob", testPass2, testIP, testUA, false); err != nil {
		t.Fatalf("after window: %v", err)
	}
}

func TestRateLimitPerAccount(t *testing.T) {
	e := newEnv(t)
	e.addUser("alice", testPass)

	// The account-wide threshold is ten times the per-IP one: it only
	// slows a distributed guess (S-08).
	for i := 0; i < 50; i++ {
		ip := fmt.Sprintf("198.51.100.%d", i+1) // a different IP every time
		if _, err := e.svc.Login(e.ctx, "alice", "wrong", ip, testUA, false); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	// A new IP cannot even try: the account is locked, also for the right passphrase.
	_, err := e.svc.Login(e.ctx, "alice", testPass, "203.0.113.200", testUA, false)
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("err = %v, want ErrRateLimited", err)
	}
	// Case variants hit the same account counter.
	if _, err := e.svc.Login(e.ctx, "ALICE", testPass, "203.0.113.201", testUA, false); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("case variant: %v", err)
	}
	// Retry-after shrinks with time, and unlocks at the end of the window.
	e.clock.Advance(10 * time.Minute)
	_, err = e.svc.Login(e.ctx, "alice", testPass, "203.0.113.202", testUA, false)
	if d := RetryAfter(err); !errors.Is(err, ErrRateLimited) || d != 5*time.Minute {
		t.Fatalf("err = %v, retry %v; want 5m", err, d)
	}
	e.clock.Advance(5 * time.Minute)
	if _, err := e.svc.Login(e.ctx, "alice", testPass, "203.0.113.203", testUA, false); err != nil {
		t.Fatalf("after window: %v", err)
	}
}

func TestRateLimitUnknownAccountsAreLimitedToo(t *testing.T) {
	e := newEnv(t)
	// Same rules as for a real account (no enumeration): the pair limit ...
	for i := 0; i < 5; i++ {
		_, _ = e.svc.Login(e.ctx, "ghost", "x", testIP, testUA, false)
	}
	if _, err := e.svc.Login(e.ctx, "ghost", "x", testIP, testUA, false); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("unknown accounts must lock like real ones (no enumeration): %v", err)
	}
	// ... and the account-wide limit.
	for i := 0; i < 50; i++ {
		_, _ = e.svc.Login(e.ctx, "phantom", "x", fmt.Sprintf("198.51.100.%d", i+1), testUA, false)
	}
	if _, err := e.svc.Login(e.ctx, "phantom", "x", "203.0.113.99", testUA, false); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("unknown accounts must lock account-wide like real ones: %v", err)
	}
}

func TestRateLimitResetOnSuccess(t *testing.T) {
	e := newEnv(t)
	e.addUser("alice", testPass)
	n := 0
	fail := func() {
		t.Helper()
		n++
		ip := fmt.Sprintf("10.%d.%d.1", n/250, n%250)
		if _, err := e.svc.Login(e.ctx, "alice", "wrong", ip, testUA, false); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("failure %d: %v", n, err)
		}
	}
	for i := 0; i < 49; i++ {
		fail()
	}
	if _, err := e.svc.Login(e.ctx, "alice", testPass, "198.51.100.50", testUA, false); err != nil {
		t.Fatal(err)
	}
	// With the counter reset, 49 more failures are still not a lock-out.
	for i := 0; i < 49; i++ {
		fail()
	}
	if _, err := e.svc.Login(e.ctx, "alice", testPass, "198.51.100.60", testUA, false); err != nil {
		t.Fatalf("account locked although the counter was reset: %v", err)
	}
}

// S-08: guessing against the operator's ID must not lock the operator out.
func TestLockoutCannotLockOutTheOperator(t *testing.T) {
	e := newEnv(t)
	e.addUser("alice", testPass)
	const attacker, operator = "198.51.100.66", "192.0.2.10"

	for i := 0; i < 5; i++ {
		if _, err := e.svc.Login(e.ctx, "alice", "wrong", attacker, testUA, false); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	// The attacker's address is locked, even with the right passphrase ...
	if _, err := e.svc.Login(e.ctx, "alice", testPass, attacker, testUA, false); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("attacker: %v, want ErrRateLimited", err)
	}
	// ... but the operator on another address gets in.
	if _, err := e.svc.Login(e.ctx, "alice", testPass, operator, testUA, false); err != nil {
		t.Fatalf("operator locked out by someone else's failures: %v", err)
	}
}

func TestAccountWideLimitExemptsKnownIPs(t *testing.T) {
	const operator, stranger = "192.0.2.10", "203.0.113.77"
	signIn := func(e *testEnv) {
		t.Helper()
		if _, err := e.svc.Login(e.ctx, "alice", testPass, operator, testUA, false); err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		name  string
		setup func(e *testEnv) // before the flood
		want  bool             // operator gets in
	}{
		{"unknown address is held back", func(*testEnv) {}, false},
		{"address with a recent success is exempt", signIn, true},
		{"success 31 days ago no longer counts", func(e *testEnv) {
			signIn(e)
			e.clock.Advance(31 * 24 * time.Hour)
		}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.addUser("alice", testPass)
			tc.setup(e)
			for i := 0; i < 50; i++ { // from 50 different addresses: only the account-wide limit can react
				_, _ = e.svc.Login(e.ctx, "alice", "wrong", fmt.Sprintf("198.51.100.%d", i+1), testUA, false)
			}
			// A stranger never gets past the account-wide limit.
			if _, err := e.svc.Login(e.ctx, "alice", testPass, stranger, testUA, false); !errors.Is(err, ErrRateLimited) {
				t.Fatalf("stranger: %v, want ErrRateLimited", err)
			}
			_, err := e.svc.Login(e.ctx, "alice", testPass, operator, testUA, false)
			if got := err == nil; got != tc.want {
				t.Fatalf("operator signed in = %v (%v), want %v", got, err, tc.want)
			}
		})
	}
}

// The exemption is rebuilt from the audit log, so it survives a restart.
func TestKnownIPsSurviveRestart(t *testing.T) {
	e := newEnv(t)
	e.addUser("alice", testPass)
	if _, err := e.svc.Login(e.ctx, "alice", testPass, "192.0.2.10", testUA, false); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewService(Config{
		Store: e.store, SecretKey: e.key, RateAttempts: 5, RateWindow: 15 * time.Minute,
		HashParams: testParams, Now: e.clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		_, _ = restarted.Login(e.ctx, "alice", "wrong", fmt.Sprintf("198.51.100.%d", i+1), testUA, false)
	}
	if _, err := restarted.Login(e.ctx, "alice", testPass, "203.0.113.77", testUA, false); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("unknown address: %v, want ErrRateLimited", err)
	}
	if _, err := restarted.Login(e.ctx, "alice", testPass, "192.0.2.10", testUA, false); err != nil {
		t.Fatalf("known address locked out after restart: %v", err)
	}
}

func TestAccountRateAttemptsConfig(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.AccountRateAttempts = 7 })
	e.addUser("alice", testPass)
	for i := 0; i < 7; i++ {
		_, _ = e.svc.Login(e.ctx, "alice", "wrong", fmt.Sprintf("198.51.100.%d", i+1), testUA, false)
	}
	if _, err := e.svc.Login(e.ctx, "alice", testPass, "203.0.113.1", testUA, false); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("err = %v, want ErrRateLimited at the configured threshold", err)
	}
}

func TestClearLoginLimits(t *testing.T) {
	e := newEnv(t)
	e.addUser("alice", testPass)
	for i := 0; i < 5; i++ {
		_, _ = e.svc.Login(e.ctx, "alice", "wrong", testIP, testUA, false)
	}
	if _, err := e.svc.Login(e.ctx, "alice", testPass, testIP, testUA, false); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("not locked: %v", err)
	}
	e.svc.ClearLoginLimits()
	if _, err := e.svc.Login(e.ctx, "alice", testPass, testIP, testUA, false); err != nil {
		t.Fatalf("still locked after ClearLoginLimits: %v", err)
	}
}

func TestRateLimitTOTPFailuresCount(t *testing.T) {
	e := newEnv(t)
	_, secret := e.addTOTPUser("alice", testPass)
	bad := wrongCode(secret, e.clock.Now())

	// Each round: password OK (new challenge), wrong code. The password step
	// must not reset the account counter, so the 5th wrong code locks.
	for i := 0; i < 5; i++ {
		res, err := e.svc.Login(e.ctx, "alice", testPass, testIP, testUA, false)
		if !errors.Is(err, ErrSecondFactorRequired) {
			t.Fatalf("round %d login: %v", i, err)
		}
		if _, err := e.svc.VerifySecondFactor(e.ctx, res.Challenge, bad, testIP); !errors.Is(err, ErrInvalidCode) {
			t.Fatalf("round %d: %v", i, err)
		}
	}
	if _, err := e.svc.Login(e.ctx, "alice", testPass, testIP, testUA, false); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("err = %v, want ErrRateLimited after 5 wrong codes", err)
	}
	// Another IP is not locked (S-08): the operator can still get in.
	if _, err := e.svc.Login(e.ctx, "alice", testPass, "198.51.100.1", testUA, false); !errors.Is(err, ErrSecondFactorRequired) {
		t.Fatalf("other IP: %v", err)
	}
}

func TestRateLimitBlocksSecondFactorStep(t *testing.T) {
	e := newEnv(t)
	_, secret := e.addTOTPUser("alice", testPass)
	res, _ := e.svc.Login(e.ctx, "alice", testPass, testIP, testUA, false)
	// Lock the address through failures from the same IP (another operator ID, so the challenge survives).
	for i := 0; i < 5; i++ {
		_, _ = e.svc.Login(e.ctx, "bob", "wrong", testIP, testUA, false)
	}
	_, err := e.svc.VerifySecondFactor(e.ctx, res.Challenge, codeAt(t, secret, e.clock.Now()), testIP)
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("err = %v, want ErrRateLimited", err)
	}
}

func TestRateLimiterBoundedMemory(t *testing.T) {
	clock := newFakeClock()
	l := newRateLimiter(clock.Now, 5, 15*time.Minute)
	for i := 0; i < limiterMaxEntries+500; i++ {
		l.fail(limiterKey(limiterKeyAccount, fmt.Sprintf("user%d", i)))
	}
	if n := l.size(); n > limiterMaxEntries {
		t.Fatalf("%d entries, cap is %d", n, limiterMaxEntries)
	}
	clock.Advance(16 * time.Minute)
	l.check("ip:x") // triggers the sweep
	if n := l.size(); n != 0 {
		t.Fatalf("expired entries not pruned: %d", n)
	}

	// At most `max` timestamps per key.
	for i := 0; i < 50; i++ {
		l.fail("acct:x")
	}
	if n := len(l.entries["acct:x"].fails); n != 5 {
		t.Fatalf("%d timestamps kept", n)
	}
	// Overlong keys are cut.
	if k := limiterKey(limiterKeyAccount, strings.Repeat("a", 5000)); len(k) > limiterMaxKeyBytes+len(limiterKeyAccount) {
		t.Fatalf("key length %d", len(k))
	}
}

func TestRateLimiterSlidingWindow(t *testing.T) {
	clock := newFakeClock()
	l := newRateLimiter(clock.Now, 3, 10*time.Minute)
	l.fail("k")
	clock.Advance(4 * time.Minute)
	l.fail("k")
	clock.Advance(4 * time.Minute)
	l.fail("k") // t=8: three failures in the window, blocked
	blocked, retry, first := l.check("k")
	if !blocked || retry != 2*time.Minute || !first {
		t.Fatalf("blocked=%v retry=%v first=%v", blocked, retry, first)
	}
	if _, _, first := l.check("k"); first {
		t.Fatal("the same block must be reported as new only once")
	}
	clock.Advance(2 * time.Minute) // the oldest failure leaves the window
	if blocked, _, _ := l.check("k"); blocked {
		t.Fatal("block must lift when the oldest failure expires")
	}
	l.fail("k") // window still holds two old ones: blocked again at once
	if blocked, _, first := l.check("k"); !blocked || !first {
		t.Fatalf("re-block: blocked=%v first=%v", blocked, first)
	}
	l.reset("k")
	if blocked, _, _ := l.check("k"); blocked {
		t.Fatal("reset must unblock")
	}
}

func TestAuditEntries(t *testing.T) {
	e := newEnv(t)
	_, secret := e.addTOTPUser("alice", testPass)
	e.addUser("bob", testPass2)
	const secretPass = "super-secret-passphrase-value"

	// failed login (unknown), failed login (bad passphrase), ok login without TOTP, logout
	_, _ = e.svc.Login(e.ctx, "nobody", secretPass, "192.0.2.1", testUA, false)
	_, _ = e.svc.Login(e.ctx, "bob", secretPass, "192.0.2.2", testUA, false)
	bobRes, err := e.svc.Login(e.ctx, "bob", testPass2, "192.0.2.3", testUA, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Logout(e.ctx, bobRes.SessionID, "192.0.2.3"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.Sessions().Validate(e.ctx, bobRes.SessionID); !errors.Is(err, ErrSessionExpired) {
		t.Fatal("logout must end the session")
	}
	// TOTP path: bad code, good code
	res, _ := e.svc.Login(e.ctx, "alice", testPass, "192.0.2.4", testUA, false)
	bad := wrongCode(secret, e.clock.Now())
	_, _ = e.svc.VerifySecondFactor(e.ctx, res.Challenge, bad, "192.0.2.4")
	good := codeAt(t, secret, e.clock.Now())
	if _, err := e.svc.VerifySecondFactor(e.ctx, res.Challenge, good, "192.0.2.4"); err != nil {
		t.Fatal(err)
	}
	// Lock-out: 5 failures, then two blocked attempts -> one "locked" entry
	for i := 0; i < 5; i++ {
		_, _ = e.svc.Login(e.ctx, "carol", secretPass, "192.0.2.77", testUA, false)
	}
	_, _ = e.svc.Login(e.ctx, "carol", secretPass, "192.0.2.77", testUA, false)
	_, _ = e.svc.Login(e.ctx, "carol", secretPass, "192.0.2.77", testUA, false)

	checks := []struct {
		action, result string
		want           int
	}{
		{ActionLogin, store.AuditDenied, 2 + 5}, // nobody, bob wrong, 5x carol
		{ActionLogin, store.AuditOK, 2},         // bob, alice (after 2FA)
		{ActionSecondFact, store.AuditDenied, 1},
		{ActionSecondFact, store.AuditOK, 1},
		{ActionLoginLocked, store.AuditDenied, 1},
		{ActionLogout, store.AuditOK, 1},
	}
	for _, c := range checks {
		if got := e.auditCount(c.action, c.result); got != c.want {
			t.Errorf("audit %s/%s = %d, want %d", c.action, c.result, got, c.want)
		}
	}

	users := map[string]bool{}
	for _, a := range e.auditEntries() {
		users[a.User] = true
		for _, secretValue := range []string{secretPass, testPass, testPass2, bad, good, secret, res.Challenge, bobRes.SessionID} {
			if strings.Contains(a.User+a.Detail+a.Action+a.Host, secretValue) {
				t.Fatalf("audit entry leaks a secret (%q): %+v", secretValue, a)
			}
		}
		if a.Time.IsZero() {
			t.Fatalf("entry without time: %+v", a)
		}
	}
	for _, u := range []string{"nobody", "bob", "alice", "carol"} {
		if !users[u] {
			t.Errorf("no audit entry for %q (have %v)", u, users)
		}
	}
}

func TestAuditUserIsTruncatedAndCleaned(t *testing.T) {
	e := newEnv(t)
	long := strings.Repeat("x", 300) + "\n\x00injected"
	_, _ = e.svc.Login(e.ctx, long, "pw", testIP, testUA, false)
	_, _ = e.svc.Login(e.ctx, "line1\nline2\tx", "pw", "192.0.2.50", testUA, false)
	list := e.auditEntries()
	if len(list) != 2 {
		t.Fatalf("%d entries", len(list))
	}
	for _, a := range list {
		if n := len([]rune(a.User)); n > 64 {
			t.Errorf("user has %d characters", n)
		}
		if strings.ContainsAny(a.User, "\n\x00\t\r") || strings.ContainsAny(a.Detail, "\n\x00\t\r") {
			t.Errorf("control characters in %+v", a)
		}
	}
}

func TestLogoutUnknownSession(t *testing.T) {
	e := newEnv(t)
	if err := e.svc.Logout(e.ctx, "nope", testIP); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Logout(e.ctx, "", testIP); err != nil {
		t.Fatal(err)
	}
	if len(e.auditEntries()) != 0 {
		t.Fatal("logging out an unknown session must not be audited")
	}
}

func TestResetOperators(t *testing.T) {
	e := newEnv(t)
	_, secret := e.addTOTPUser("alice", testPass)
	res, _ := e.svc.Login(e.ctx, "alice", testPass, testIP, testUA, false)
	u2 := e.addUser("bob", testPass2)
	sessionRaw, _, err := e.svc.Sessions().Create(e.ctx, u2, false, testIP, testUA)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("fails cleanly without store support", func(t *testing.T) {
		e.svc.deleteAllUsers = nil
		if _, err := e.svc.ResetOperators(e.ctx); err == nil {
			t.Fatal("expected an error")
		}
	})
	t.Run("audited as system and clears in-memory state", func(t *testing.T) {
		called := 0
		e.svc.deleteAllUsers = func(context.Context) (int64, error) { called++; return 1, nil }
		n, err := e.svc.ResetOperators(e.ctx)
		if err != nil || n != 1 || called != 1 {
			t.Fatalf("n=%d err=%v called=%d", n, err, called)
		}
		if _, ok := e.svc.peekChallenge(res.Challenge); ok {
			t.Fatal("pending challenges must be dropped")
		}
		// replay state cleared: the code may be used again
		if !e.svc.totp.VerifyTOTP(1, secret, codeAt(t, secret, e.clock.Now()), e.clock.Now()) {
			t.Fatal("verifier state should be fresh")
		}
		list := e.auditEntries()
		last := list[0]
		if last.User != "system" || last.Action != ActionUserReset || last.Result != store.AuditOK {
			t.Fatalf("audit entry %+v", last)
		}
	})
	t.Run("failure is audited", func(t *testing.T) {
		e.svc.deleteAllUsers = func(context.Context) (int64, error) { return 0, errors.New("boom") }
		if _, err := e.svc.ResetOperators(e.ctx); err == nil {
			t.Fatal("expected an error")
		}
		if e.auditCount(ActionUserReset, store.AuditError) != 1 {
			t.Fatal("failed reset must be audited")
		}
	})
	t.Run("real store", func(t *testing.T) {
		svc2, err := NewService(Config{Store: e.store, SecretKey: e.key, HashParams: testParams, Now: e.clock.Now})
		if err != nil {
			t.Fatal(err)
		}
		if svc2.deleteAllUsers == nil {
			t.Fatal("store.Store must provide DeleteAllUsers")
		}
		if _, err := svc2.ResetOperators(e.ctx); err != nil {
			t.Fatal(err)
		}
		if n, _ := e.store.CountUsers(e.ctx); n != 0 {
			t.Fatalf("%d users left", n)
		}
		if _, _, err := e.svc.Sessions().Validate(e.ctx, sessionRaw); !errors.Is(err, ErrSessionExpired) {
			t.Fatal("sessions must be gone")
		}
	})
}

func TestAuditErrorCallback(t *testing.T) {
	var got []error
	e := newEnv(t, func(c *Config) { c.OnAuditError = func(err error) { got = append(got, err) } })
	e.addUser("alice", testPass)
	// An audit entry without a result is rejected by the store; emulate a broken store by closing it.
	if err := e.store.Close(); err != nil {
		t.Fatal(err)
	}
	e.svc.audit(e.ctx, "alice", ActionLogin, store.AuditOK, "")
	if len(got) != 1 {
		t.Fatalf("callback invoked %d times", len(got))
	}
}

func TestNewServiceValidation(t *testing.T) {
	e := newEnv(t)
	tests := []struct {
		name string
		cfg  Config
		ok   bool
	}{
		{"ok", Config{Store: e.store, SecretKey: e.key, HashParams: testParams}, true},
		{"defaults filled in", Config{Store: e.store, SecretKey: e.key, HashParams: testParams, RateAttempts: 0}, true},
		{"no store", Config{SecretKey: e.key}, false},
		{"short key", Config{Store: e.store, SecretKey: e.key[:16]}, false},
		{"bad params", Config{Store: e.store, SecretKey: e.key, HashParams: HashParams{Memory: 1, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16}}, false},
	}
	for _, tc := range tests {
		_, err := NewService(tc.cfg)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v", tc.name, err)
		}
	}
}

func TestHashPassphraseAppliesPolicy(t *testing.T) {
	e := newEnv(t)
	if _, err := e.svc.HashPassphrase(e.ctx, "short"); !errors.Is(err, ErrWeakPassphrase) {
		t.Fatalf("err = %v", err)
	}
	h, err := e.svc.HashPassphrase(e.ctx, testPass)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := VerifyPassword(testPass, h); !ok || NeedsRehash(h, testParams) {
		t.Fatal("hash must verify and use the service parameters")
	}
	ctx, cancel := context.WithCancel(e.ctx)
	cancel()
	e.svc.hashSem <- struct{}{}
	e.svc.hashSem <- struct{}{} // saturate the semaphore
	if _, err := e.svc.HashPassphrase(ctx, testPass); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestUserMessages(t *testing.T) {
	for _, err := range []error{
		ErrInvalidCredentials, ErrInvalidCode, ErrInvalidChallenge, ErrSessionExpired, ErrWeakPassphrase,
		&RateLimitedError{RetryAfter: time.Second}, &RateLimitedError{RetryAfter: 90 * time.Second}, errors.New("db exploded"),
	} {
		m := UserMessage(err)
		if m == "" || strings.Contains(m, "auth:") || strings.Contains(m, "exploded") {
			t.Errorf("message for %v: %q", err, m)
		}
	}
	if !errors.Is(&RateLimitedError{}, ErrRateLimited) {
		t.Fatal("RateLimitedError must match ErrRateLimited")
	}
	if !strings.Contains(UserMessage(&RateLimitedError{RetryAfter: time.Second}), "1 minute.") {
		t.Fatal("singular minute expected")
	}
	if !strings.Contains(UserMessage(&RateLimitedError{RetryAfter: 90 * time.Second}), "2 minutes") {
		t.Fatal("rounded up minutes expected")
	}
}
