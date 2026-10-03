package auth

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/store"
)

// burst runs n calls at the same moment and returns their errors.
func burst(n int, fn func(i int) error) []error {
	errs := make([]error, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = fn(i)
		}()
	}
	close(start)
	wg.Wait()
	return errs
}

func count(errs []error, target error) int {
	n := 0
	for _, err := range errs {
		if errors.Is(err, target) {
			n++
		}
	}
	return n
}

// A-01: sixty parallel wrong passphrases from one IP must not get more than
// the limit's worth of evaluations (before, the check came before the count
// and every request that arrived early passed it).
func TestParallelLoginGuessesAreLimited(t *testing.T) {
	e := newEnv(t)
	e.addUser("alice", testPass)
	errs := burst(60, func(i int) error {
		_, err := e.svc.Login(e.ctx, "alice", fmt.Sprintf("wrong passphrase %d", i), testIP, testUA, false)
		return err
	})
	evaluated := count(errs, ErrInvalidCredentials)
	if evaluated < 1 || evaluated > 5 {
		t.Fatalf("%d guesses evaluated, want 1-5", evaluated)
	}
	if got := e.auditCount(ActionLogin, store.AuditDenied); got != evaluated {
		t.Errorf("%d denied audit entries for %d evaluations", got, evaluated)
	}
	if limited, busy := count(errs, ErrRateLimited), count(errs, ErrBusy); evaluated+limited+busy != len(errs) {
		t.Errorf("evaluated %d + limited %d + busy %d != %d (other errors: %v)", evaluated, limited, busy, len(errs), errs)
	}
	// And the right passphrase is blocked from this address afterwards.
	if _, err := e.svc.Login(e.ctx, "alice", testPass, testIP, testUA, false); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("login after the burst: %v", err)
	}
}

func TestParallelUnknownUserGuessesAreLimited(t *testing.T) {
	e := newEnv(t)
	errs := burst(40, func(i int) error {
		_, err := e.svc.Login(e.ctx, fmt.Sprintf("ghost%d", i), "whatever passphrase", testIP, testUA, false)
		return err
	})
	if got := count(errs, ErrInvalidCredentials); got > 5 {
		t.Fatalf("%d attempts evaluated from one IP, want at most 5", got)
	}
}

// A-01: the per-challenge counter is taken under the lock before the code is
// looked at, so a parallel burst cannot read past the fifth failure.
func TestChallengeAttemptsAreReservedAtomically(t *testing.T) {
	e := newEnv(t)
	e.addTOTPUser("alice", testPass)
	res, err := e.svc.Login(e.ctx, "alice", testPass, testIP, testUA, false)
	if !errors.Is(err, ErrSecondFactorRequired) {
		t.Fatal(err)
	}
	var granted atomic.Int32
	burst(200, func(int) error {
		if _, ok := e.svc.reserveChallengeAttempt(res.Challenge); ok {
			granted.Add(1)
		}
		return nil
	})
	if granted.Load() != maxChallengeFailures {
		t.Fatalf("%d evaluations granted, want %d", granted.Load(), maxChallengeFailures)
	}
}

func TestParallelSecondFactorGuessesAreLimited(t *testing.T) {
	e := newEnv(t)
	_, secret := e.addTOTPUser("alice", testPass)
	res, _ := e.svc.Login(e.ctx, "alice", testPass, testIP, testUA, false)
	valid := map[string]bool{}
	for _, off := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		valid[codeAt(t, secret, e.clock.Now().Add(off))] = true
	}
	var wrong []string
	for i := 0; len(wrong) < 100; i++ {
		if c := fmt.Sprintf("%06d", 100000+i); !valid[c] {
			wrong = append(wrong, c)
		}
	}
	errs := burst(100, func(i int) error {
		_, err := e.svc.VerifySecondFactor(e.ctx, res.Challenge, wrong[i], testIP)
		return err
	})
	if got := count(errs, ErrInvalidCode); got < 1 || got > maxChallengeFailures {
		t.Fatalf("%d codes evaluated, want 1-%d", got, maxChallengeFailures)
	}
	// The challenge is gone: even the right code does not work any more.
	if _, err := e.svc.VerifySecondFactor(e.ctx, res.Challenge, codeAt(t, secret, e.clock.Now()), testIP); !errors.Is(err, ErrInvalidChallenge) && !errors.Is(err, ErrRateLimited) {
		t.Fatalf("right code on a burnt challenge: %v", err)
	}
}

func TestSecondFactorRateBlockReleasesTheChallengeAttempt(t *testing.T) {
	e := newEnv(t)
	e.addTOTPUser("alice", testPass)
	res, _ := e.svc.Login(e.ctx, "alice", testPass, testIP, testUA, false)
	for range 5 { // fill the address's counter with failures of another account
		e.svc.limiter.ip.fail(ipLimitKey(testIP))
	}
	for range 10 {
		if _, err := e.svc.VerifySecondFactor(e.ctx, res.Challenge, "000000", testIP); !errors.Is(err, ErrRateLimited) {
			t.Fatalf("err = %v", err)
		}
	}
	e.svc.chMu.Lock()
	failures := e.svc.challenges[res.Challenge].failures
	e.svc.chMu.Unlock()
	if failures != 0 {
		t.Fatalf("blocked requests used %d evaluations of the challenge", failures)
	}
}

func TestSuccessfulLoginsDoNotUseUpTheLimit(t *testing.T) {
	e := newEnv(t)
	e.addUser("alice", testPass)
	for i := range 20 {
		if _, err := e.svc.Login(e.ctx, "alice", testPass, testIP, testUA, false); err != nil {
			t.Fatalf("login %d: %v", i, err)
		}
	}
	// The first step of a two-step sign-in is given back as well.
	e.addTOTPUser("bob", testPass)
	for i := range 20 {
		if _, err := e.svc.Login(e.ctx, "bob", testPass, testIP, testUA, false); !errors.Is(err, ErrSecondFactorRequired) {
			t.Fatalf("bob step one %d: %v", i, err)
		}
	}
	if n := e.svc.limiter.ip.size(); n != 0 {
		t.Errorf("%d IP counters left after successful logins", n)
	}
}

func TestIPKey(t *testing.T) {
	tests := []struct{ in, want string }{
		{"192.0.2.10", "192.0.2.10"},
		{" 192.0.2.10 ", "192.0.2.10"},
		{"::ffff:192.0.2.10", "192.0.2.10"},
		{"2001:db8:1:2:3:4:5:6", "2001:db8:1:2::/64"},
		{"2001:DB8:1:2:ffff:ffff:ffff:ffff", "2001:db8:1:2::/64"},
		{"2001:db8:1:3::1", "2001:db8:1:3::/64"},
		{"fe80::1%eth0", "fe80::/64"},
		{"not an ip", "not an ip"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := ipKey(tt.in); got != tt.want {
			t.Errorf("ipKey(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// A-04: guesses from many addresses of one /64 share one counter.
func TestLoginLimitsKeyIPv6ByPrefix(t *testing.T) {
	e := newEnv(t)
	e.addUser("alice", testPass)
	for i := range 5 {
		ip := fmt.Sprintf("2001:db8:1:2::%x", i+1)
		if _, err := e.svc.Login(e.ctx, "alice", "wrong passphrase", ip, testUA, false); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("guess %d: %v", i, err)
		}
	}
	if _, err := e.svc.Login(e.ctx, "alice", "wrong passphrase", "2001:db8:1:2:aaaa::9", testUA, false); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("a sixth address of the same /64 was evaluated: %v", err)
	}
	if _, err := e.svc.Login(e.ctx, "alice", testPass, "2001:db8:1:3::1", testUA, false); err != nil {
		t.Fatalf("another /64 must stay unaffected: %v", err)
	}
}

// A-04: the wait queue for argon2 slots is bounded.
func TestAcquireHashQueueIsBounded(t *testing.T) {
	e := newEnv(t)
	for range cap(e.svc.hashSem) {
		e.svc.hashSem <- struct{}{}
	}
	ctx, cancel := context.WithCancel(e.ctx)
	var wg sync.WaitGroup
	for range maxHashWaiters {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = e.svc.acquireHash(ctx)
		}()
	}
	for e.svc.hashWaiters.Load() < maxHashWaiters {
		runtime.Gosched()
	}
	if err := e.svc.acquireHash(e.ctx); !errors.Is(err, ErrBusy) {
		t.Fatalf("waiter %d: %v, want ErrBusy", maxHashWaiters+1, err)
	}
	cancel()
	wg.Wait()
	if n := e.svc.hashWaiters.Load(); n != 0 {
		t.Errorf("%d waiters left", n)
	}
}

// A-04: unknown operator IDs share one argon2 slot, so the real operator keeps the other.
func TestUnknownUserHashesAreBounded(t *testing.T) {
	e := newEnv(t)
	e.svc.unknownSem <- struct{}{} // an unknown-user verification is running
	ctx, cancel := context.WithCancel(e.ctx)
	var wg sync.WaitGroup
	for range maxUnknownWaiters {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = e.svc.burnPasswordHash(ctx, "x")
		}()
	}
	for e.svc.unknownWaiters.Load() < maxUnknownWaiters {
		runtime.Gosched()
	}
	if err := e.svc.burnPasswordHash(e.ctx, "x"); !errors.Is(err, ErrBusy) {
		t.Fatalf("err = %v, want ErrBusy", err)
	}
	// A real operator is not affected by the unknown-user queue.
	e.addUser("alice", testPass)
	if _, err := e.svc.Login(e.ctx, "alice", testPass, testIP, testUA, false); err != nil {
		t.Fatalf("real login while unknown users queue: %v", err)
	}
	cancel()
	wg.Wait()
}

func TestBusyIsNotCounted(t *testing.T) {
	e := newEnv(t)
	e.addUser("alice", testPass)
	for range cap(e.svc.hashSem) {
		e.svc.hashSem <- struct{}{}
	}
	e.svc.hashWaiters.Store(maxHashWaiters)
	for range 20 {
		if _, err := e.svc.Login(e.ctx, "alice", testPass, testIP, testUA, false); !errors.Is(err, ErrBusy) {
			t.Fatalf("err = %v, want ErrBusy", err)
		}
	}
	e.svc.hashWaiters.Store(0)
	for range cap(e.svc.hashSem) {
		<-e.svc.hashSem
	}
	if _, err := e.svc.Login(e.ctx, "alice", testPass, testIP, testUA, false); err != nil {
		t.Fatalf("busy rejections were counted as failures: %v", err)
	}
}

// A-08: the idle timeout is fixed, whatever a caller passes.
func TestSessionIdleTimeoutIsPinned(t *testing.T) {
	for _, d := range []time.Duration{0, time.Minute, 720 * time.Hour} {
		e := newEnv(t, func(c *Config) { c.IdleTimeout = d })
		if e.svc.sessions.idle != 12*time.Hour {
			t.Errorf("IdleTimeout %v gave idle timeout %v", d, e.svc.sessions.idle)
		}
	}
}

// --- A-02 / step-up ---------------------------------------------------------

func auditDetails(e *testEnv, action, result string) []string {
	var out []string
	for _, a := range e.auditEntries() {
		if a.Action == action && a.Result == result {
			out = append(out, a.Detail)
		}
	}
	return out
}

func TestCheckPassphrase(t *testing.T) {
	e := newEnv(t)
	u := e.addUser("alice", testPass)
	for i := range 20 { // right passphrases never use up the limit
		if err := e.svc.CheckPassphrase(e.ctx, u, testPass, testIP, "user.passphrase"); err != nil {
			t.Fatalf("right passphrase %d: %v", i, err)
		}
	}
	for i := range 5 {
		if err := e.svc.CheckPassphrase(e.ctx, u, "wrong passphrase", testIP, "user.passphrase"); !errors.Is(err, ErrWrongPassphrase) {
			t.Fatalf("wrong %d: %v", i, err)
		}
	}
	for range 3 { // blocked, even with the right passphrase
		err := e.svc.CheckPassphrase(e.ctx, u, testPass, testIP, "user.passphrase")
		if !errors.Is(err, ErrRateLimited) || RetryAfter(err) <= 0 {
			t.Fatalf("blocked: %v", err)
		}
	}
	if d := auditDetails(e, "user.passphrase", store.AuditDenied); len(d) != 1 || !strings.Contains(d[0], "throttled") {
		t.Errorf("throttled audit entries = %q, want one", d)
	}
	e.clock.Advance(16 * time.Minute)
	if err := e.svc.CheckPassphrase(e.ctx, u, testPass, testIP, "user.passphrase"); err != nil {
		t.Fatalf("after the window: %v", err)
	}
}

// A-02: parallel guesses of the current passphrase.
func TestCheckPassphraseParallelGuessesAreLimited(t *testing.T) {
	e := newEnv(t)
	u := e.addUser("alice", testPass)
	errs := burst(100, func(i int) error {
		return e.svc.CheckPassphrase(e.ctx, u, fmt.Sprintf("wrong passphrase %d", i), testIP, "user.passphrase")
	})
	if got := count(errs, ErrWrongPassphrase); got < 1 || got > 5 {
		t.Fatalf("%d guesses evaluated, want 1-5", got)
	}
}

func TestBeginOperatorAction(t *testing.T) {
	e := newEnv(t)
	done, err := e.svc.BeginOperatorAction(1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.BeginOperatorAction(1); !errors.Is(err, ErrBusy) {
		t.Fatalf("second in-flight action: %v", err)
	}
	other, err := e.svc.BeginOperatorAction(2)
	if err != nil {
		t.Fatalf("another operator: %v", err)
	}
	other()
	done()
	again, err := e.svc.BeginOperatorAction(1)
	if err != nil {
		t.Fatalf("after release: %v", err)
	}
	again()
}

func TestReauthenticate(t *testing.T) {
	e := newEnv(t)
	u, secret := e.addTOTPUser("alice", testPass)
	code := func() string { return codeAt(t, secret, e.clock.Now()) }
	next := func() { e.clock.Advance(31 * time.Second) } // the replay guard wants a newer step

	t.Run("success is audited without secrets", func(t *testing.T) {
		c := code()
		if err := e.svc.Reauthenticate(e.ctx, u, testPass, c, testIP); err != nil {
			t.Fatal(err)
		}
		d := auditDetails(e, ActionReauth, store.AuditOK)
		if len(d) != 1 || !strings.Contains(d[0], "ip="+testIP) {
			t.Fatalf("audit = %q", d)
		}
		for _, a := range e.auditEntries() {
			if strings.Contains(a.Detail, testPass) || strings.Contains(a.Detail, c) || strings.Contains(a.Detail, secret) {
				t.Fatalf("secret in audit entry %+v", a)
			}
		}
	})
	t.Run("a code works once", func(t *testing.T) {
		if err := e.svc.Reauthenticate(e.ctx, u, testPass, code(), testIP); !errors.Is(err, ErrInvalidCode) {
			t.Fatalf("replayed code: %v", err)
		}
		next()
	})
	t.Run("wrong passphrase", func(t *testing.T) {
		before := e.auditCount(ActionReauth, store.AuditDenied)
		if err := e.svc.Reauthenticate(e.ctx, u, "wrong passphrase", code(), testIP); !errors.Is(err, ErrWrongPassphrase) {
			t.Fatalf("err = %v", err)
		}
		if e.auditCount(ActionReauth, store.AuditDenied) != before+1 {
			t.Error("not audited")
		}
		// The code was not spent on a wrong passphrase.
		if err := e.svc.Reauthenticate(e.ctx, u, testPass, code(), testIP); err != nil {
			t.Fatalf("right credentials after a wrong passphrase: %v", err)
		}
		next()
	})
	t.Run("wrong and malformed codes", func(t *testing.T) {
		for _, c := range []string{"", "12345", "abcdef"} {
			if err := e.svc.Reauthenticate(e.ctx, u, testPass, c, testIP); !errors.Is(err, ErrInvalidCode) {
				t.Errorf("code %q: %v", c, err)
			}
		}
	})
	t.Run("throttled, shared with the passphrase check", func(t *testing.T) {
		// The success above forgot the earlier failures; three malformed
		// codes are in the window, two wrong passphrases make five.
		for range 2 {
			if err := e.svc.Reauthenticate(e.ctx, u, "wrong passphrase", code(), testIP); !errors.Is(err, ErrWrongPassphrase) {
				t.Fatal(err)
			}
		}
		err := e.svc.Reauthenticate(e.ctx, u, testPass, code(), testIP)
		if !errors.Is(err, ErrRateLimited) {
			t.Fatalf("err = %v", err)
		}
		if err := e.svc.CheckPassphrase(e.ctx, u, testPass, testIP, "user.passphrase"); !errors.Is(err, ErrRateLimited) {
			t.Fatalf("the passphrase check must share the limit: %v", err)
		}
		if d := auditDetails(e, ActionReauth, store.AuditDenied); !slicesContain(d, "throttled") {
			t.Errorf("no throttled audit entry in %q", d)
		}
		e.clock.Advance(16 * time.Minute)
		if err := e.svc.Reauthenticate(e.ctx, u, testPass, code(), testIP); err != nil {
			t.Fatalf("after the window: %v", err)
		}
	})
}

func slicesContain(list []string, sub string) bool {
	for _, s := range list {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func TestReauthenticateWithoutSecondFactor(t *testing.T) {
	e := newEnv(t)
	u := e.addUser("alice", testPass)
	if err := e.svc.Reauthenticate(e.ctx, u, testPass, "123456", testIP); !errors.Is(err, ErrNoSecondFactor) {
		t.Fatalf("err = %v", err)
	}
	if err := e.svc.Reauthenticate(e.ctx, u, "wrong passphrase", "123456", testIP); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("err = %v", err)
	}
}

func TestReauthenticateIsOneAtATime(t *testing.T) {
	e := newEnv(t)
	u, secret := e.addTOTPUser("alice", testPass)
	done, err := e.svc.BeginOperatorAction(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Reauthenticate(e.ctx, u, testPass, codeAt(t, secret, e.clock.Now()), testIP); !errors.Is(err, ErrBusy) {
		t.Fatalf("err = %v, want ErrBusy", err)
	}
	done()
	if err := e.svc.Reauthenticate(e.ctx, u, testPass, codeAt(t, secret, e.clock.Now()), testIP); err != nil {
		t.Fatalf("after the other action ended: %v", err)
	}
}

func TestReauthenticateParallelGuessesAreLimited(t *testing.T) {
	e := newEnv(t)
	u, _ := e.addTOTPUser("alice", testPass)
	errs := burst(100, func(i int) error {
		return e.svc.Reauthenticate(e.ctx, u, testPass, fmt.Sprintf("%06d", 100000+i), testIP)
	})
	if got := count(errs, ErrInvalidCode); got > 5 {
		t.Fatalf("%d codes evaluated, want at most 5", got)
	}
}
