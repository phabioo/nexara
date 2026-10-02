package auth

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/store"
)

func TestEnrollmentPending(t *testing.T) {
	e := newEnv(t)
	plain := e.addUser("plain", testPass)
	withTOTP, _ := e.addTOTPUser("secure", testPass)
	demo := newEnv(t, func(c *Config) { c.DemoPasswordOnly = true; c.CookieOptions = []CookieOption{WithSecure(false)} })
	demoUser := demo.addUser("demo", testPass)

	tests := []struct {
		name string
		svc  *Service
		user store.User
		want bool
	}{
		{"operator without TOTP", e.svc, plain, true},
		{"operator with TOTP", e.svc, withTOTP, false},
		{"demo password-only mode", demo.svc, demoUser, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.svc.EnrollmentPending(tc.user); got != tc.want {
				t.Errorf("EnrollmentPending = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDemoPasswordOnlyRefusesSecureCookies(t *testing.T) {
	e := newEnv(t)
	for _, tc := range []struct {
		name    string
		opts    []CookieOption
		wantErr bool
	}{
		{"default cookies are secure", nil, true},
		{"explicit secure", []CookieOption{WithSecure(true)}, true},
		{"plain HTTP", []CookieOption{WithSecure(false)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewService(Config{
				Store: e.store, SecretKey: e.key, HashParams: testParams,
				DemoPasswordOnly: true, CookieOptions: tc.opts,
			})
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestPendingTOTPSecret(t *testing.T) {
	e := newEnv(t)
	u := e.addUser("alice", testPass)
	other := e.addUser("bob", testPass)
	r1, _ := e.svc.Login(e.ctx, "alice", testPass, testIP, testUA, false)
	r2, _ := e.svc.Login(e.ctx, "alice", testPass, testIP, testUA, false)

	a := e.svc.PendingTOTPSecret(u, r1.Session)
	if a != e.svc.PendingTOTPSecret(u, r1.Session) {
		t.Error("the secret must be stable for one session")
	}
	if a == e.svc.PendingTOTPSecret(u, r2.Session) {
		t.Error("another session must get another secret")
	}
	if a == e.svc.PendingTOTPSecret(other, r1.Session) {
		t.Error("another user must get another secret")
	}
	if len(a) != 32 || strings.ToUpper(a) != a {
		t.Errorf("secret %q: want 32 base32 characters", a)
	}
	// Another hub (other secret key) derives another secret for the same session.
	e2 := newEnv(t, func(c *Config) { c.SecretKey = append([]byte(nil), c.SecretKey...); c.SecretKey[0] ^= 0xff })
	if a == e2.svc.PendingTOTPSecret(u, r1.Session) {
		t.Error("the secret must depend on secret.key")
	}
}

func TestEnrollTOTP(t *testing.T) {
	e := newEnv(t)
	u := e.addUser("alice", testPass)
	login := func() LoginResult {
		t.Helper()
		res, err := e.svc.Login(e.ctx, "alice", testPass, testIP, testUA, true)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	first := login()
	other := login() // a second session, e.g. a password thief's
	secret := e.svc.PendingTOTPSecret(u, first.Session)
	now := e.clock.Now()

	t.Run("wrong and malformed codes", func(t *testing.T) {
		// Two failures only: five from one address would block it (TestEnrollTOTPRateLimit).
		for _, code := range []string{"12345", "abcdef"} {
			if _, err := e.svc.EnrollTOTP(e.ctx, u.ID, first.Session, code, testIP); !errors.Is(err, ErrInvalidCode) {
				t.Errorf("code %q: err = %v, want ErrInvalidCode", code, err)
			}
		}
		got, _ := e.store.GetUserByID(e.ctx, u.ID)
		if got.TOTPEnabled || got.TOTPSecretEnc != nil {
			t.Fatal("a wrong code must change nothing")
		}
		if e.auditCount(ActionTOTPEnroll, "denied") == 0 {
			t.Error("wrong codes must be audited")
		}
	})

	t.Run("the secret of another session does not work", func(t *testing.T) {
		code := codeAt(t, e.svc.PendingTOTPSecret(u, other.Session), now)
		if _, err := e.svc.EnrollTOTP(e.ctx, u.ID, first.Session, code, testIP); !errors.Is(err, ErrInvalidCode) {
			t.Fatalf("err = %v, want ErrInvalidCode", err)
		}
	})

	code := codeAt(t, secret, now)
	res, err := e.svc.EnrollTOTP(e.ctx, u.ID, first.Session, code, testIP)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("success stores the sealed secret and rotates the session", func(t *testing.T) {
		got, _ := e.store.GetUserByID(e.ctx, u.ID)
		if !got.TOTPEnabled || len(got.TOTPSecretEnc) == 0 {
			t.Fatal("TOTP must be enabled")
		}
		opened, err := e.svc.OpenTOTPSecret(u.ID, got.TOTPSecretEnc)
		if err != nil || opened != secret {
			t.Fatalf("stored secret = %q, %v; want the pending one", opened, err)
		}
		if _, err := e.svc.OpenTOTPSecret(u.ID+1, got.TOTPSecretEnc); err == nil {
			t.Error("the sealed secret must be bound to the user ID")
		}
		if res.SessionID == "" || res.SessionID == first.SessionID || !res.Session.Persistent || !res.User.TOTPEnabled {
			t.Fatalf("result %+v", res)
		}
		for name, raw := range map[string]string{"enrolling session": first.SessionID, "other session": other.SessionID} {
			if _, _, err := e.svc.Sessions().Validate(e.ctx, raw); !errors.Is(err, ErrSessionExpired) {
				t.Errorf("%s must end, err = %v", name, err)
			}
		}
		if _, _, err := e.svc.Sessions().Validate(e.ctx, res.SessionID); err != nil {
			t.Errorf("the new session must be valid: %v", err)
		}
		if e.auditCount(ActionTOTPEnroll, "ok") != 1 {
			t.Error("success must be audited once")
		}
		for _, a := range e.auditEntries() {
			if strings.Contains(a.Detail, secret) || strings.Contains(a.Detail, code) {
				t.Fatalf("audit entry leaks a secret: %+v", a)
			}
		}
	})

	t.Run("the enrollment code cannot be replayed to sign in", func(t *testing.T) {
		r, err := e.svc.Login(e.ctx, "alice", testPass, testIP, testUA, false)
		if !errors.Is(err, ErrSecondFactorRequired) {
			t.Fatalf("login err = %v, want second factor", err)
		}
		if _, err := e.svc.VerifySecondFactor(e.ctx, r.Challenge, code, testIP); !errors.Is(err, ErrInvalidCode) {
			t.Fatalf("replayed code: err = %v, want ErrInvalidCode", err)
		}
		e.clock.Advance(time.Duration(totpPeriod) * time.Second)
		if _, err := e.svc.VerifySecondFactor(e.ctx, r.Challenge, codeAt(t, secret, e.clock.Now()), testIP); err != nil {
			t.Fatalf("next code must sign in: %v", err)
		}
	})

	t.Run("enrolling again is refused", func(t *testing.T) {
		e.clock.Advance(2 * time.Minute)
		code := codeAt(t, secret, e.clock.Now())
		if _, err := e.svc.EnrollTOTP(e.ctx, u.ID, first.Session, code, testIP); !errors.Is(err, ErrAlreadyEnrolled) {
			t.Fatalf("err = %v, want ErrAlreadyEnrolled", err)
		}
	})
}

func TestEnrollTOTPRateLimit(t *testing.T) {
	e := newEnv(t)
	u := e.addUser("alice", testPass)
	res, err := e.svc.Login(e.ctx, "alice", testPass, testIP, testUA, false)
	if err != nil {
		t.Fatal(err)
	}
	secret := e.svc.PendingTOTPSecret(u, res.Session)
	bad := "000000"
	if _, ok := MatchTOTP(secret, bad, e.clock.Now()); ok {
		bad = "000001"
	}
	for i := 0; i < 5; i++ {
		if _, err := e.svc.EnrollTOTP(e.ctx, u.ID, res.Session, bad, testIP); !errors.Is(err, ErrInvalidCode) {
			t.Fatalf("try %d: %v", i, err)
		}
	}
	// Even the right code is refused while blocked.
	_, err = e.svc.EnrollTOTP(e.ctx, u.ID, res.Session, codeAt(t, secret, e.clock.Now()), testIP)
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("err = %v, want ErrRateLimited", err)
	}
	got, _ := e.store.GetUserByID(e.ctx, u.ID)
	if got.TOTPEnabled {
		t.Fatal("a blocked attempt must not enroll")
	}
}
