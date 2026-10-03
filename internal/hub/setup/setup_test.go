package setup

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time          { return c.t }
func (c *fakeClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

func newClock() *fakeClock { return &fakeClock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)} }

func TestCodeFormatAndAlphabet(t *testing.T) {
	c := NewCodes(CodeOptions{})
	for i := 0; i < 200; i++ {
		code, _, err := c.Rotate()
		if err != nil {
			t.Fatal(err)
		}
		if len(code) != CodeLength {
			t.Fatalf("len = %d", len(code))
		}
		for _, r := range code {
			if !strings.ContainsRune(codeAlphabet, r) || strings.ContainsRune("0O1IL", r) {
				t.Fatalf("bad char %q in %s", r, code)
			}
		}
		f := FormatCode(code)
		if len(f) != 9 || f[4] != '-' {
			t.Fatalf("format %q", f)
		}
	}
}

func TestNormalizeCode(t *testing.T) {
	for in, want := range map[string]string{
		"abcd-efgh":     "ABCDEFGH",
		" ab cd-EF gh ": "ABCDEFGH",
		"ABCDEFGH":      "ABCDEFGH",
		"":              "",
	} {
		if got := NormalizeCode(in); got != want {
			t.Errorf("NormalizeCode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCodeVerifyAndExpiry(t *testing.T) {
	clk := newClock()
	var announced []string
	c := NewCodes(CodeOptions{Now: clk.Now, Announce: func(code string, _ time.Time) { announced = append(announced, code) }})
	code, exp, _ := c.Rotate()
	if !exp.Equal(clk.t.Add(CodeValidity)) {
		t.Fatalf("expiry %v", exp)
	}
	clk.Advance(CodeValidity)
	err := c.Verify(code)
	var ce *CodeError
	if !errors.As(err, &ce) || ce.Left != MaxAttempts-1 {
		t.Fatalf("expired code: %v", err)
	}
	if !strings.HasPrefix(err.Error(), "Code invalid or expired.") {
		t.Fatalf("message %q", err)
	}
	// Expiry triggered an automatic rotation and announcement.
	if len(announced) != 2 || announced[0] != code {
		t.Fatalf("announced = %v", announced)
	}
	if err := c.Verify(announced[1]); err != nil {
		t.Fatalf("fresh code rejected: %v", err)
	}
}

func TestCodeFormatsAreAccepted(t *testing.T) {
	c := NewCodes(CodeOptions{})
	code, _, _ := c.Rotate()
	if err := c.Verify(strings.ToLower(FormatCode(code))); err != nil {
		t.Fatalf("valid code rejected: %v", err)
	}
}

// A-06: a correct code works once.
func TestCodeIsConsumedByUnlock(t *testing.T) {
	clk := newClock()
	var announced []string
	c := NewCodes(CodeOptions{Now: clk.Now, Announce: func(code string, _ time.Time) { announced = append(announced, code) }})
	code, _, _ := c.Rotate()
	if err := c.VerifyFrom("10.0.0.5", code); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := c.Current(); ok {
		t.Error("Current() still returns the consumed code")
	}
	for _, ip := range []string{"10.0.0.5", "10.0.0.6"} {
		err := c.VerifyFrom(ip, code)
		var ce *CodeError
		if !errors.As(err, &ce) {
			t.Fatalf("reused code from %s accepted: %v", ip, err)
		}
	}
	// It does not come back by itself ...
	clk.Advance(2 * CodeValidity)
	c.Tick()
	if len(announced) != 1 {
		t.Fatalf("a consumed code was rotated: %v", announced)
	}
	if c.Verify(code) == nil {
		t.Fatal("consumed code valid after the validity period")
	}
	// ... only `sudo nexus setup code` issues a new one.
	fresh, _, _ := c.Rotate()
	if err := c.Verify(fresh); err != nil {
		t.Fatalf("fresh code: %v", err)
	}
}

// Two clients entering the right code at once: one unlock only.
func TestCodeIsConsumedOnlyOnce(t *testing.T) {
	c := NewCodes(CodeOptions{})
	code, _, _ := c.Rotate()
	var wg sync.WaitGroup
	var ok atomic.Int32
	start := make(chan struct{})
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if c.VerifyFrom(fmt.Sprintf("10.0.0.%d", i), code) == nil {
				ok.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if ok.Load() != 1 {
		t.Fatalf("%d unlocks with one code", ok.Load())
	}
}

// A-04: IPv6 clients are counted per /64.
func TestIPv6ClientsShareTheirPrefix(t *testing.T) {
	c := NewCodes(CodeOptions{})
	code, _, _ := c.Rotate()
	for i := 1; i <= MaxAttempts; i++ {
		c.VerifyFrom(fmt.Sprintf("2001:db8:1:2::%x", i), "WRONGONE")
	}
	if ok, _ := c.LockedFor("2001:db8:1:2:ffff::1"); !ok {
		t.Fatal("the whole /64 should be locked after five wrong codes from it")
	}
	if err := c.VerifyFrom("2001:db8:1:2:abcd::1", code); !isLocked(err) {
		t.Fatalf("right code from the locked /64: %v", err)
	}
	if ok, _ := c.LockedFor("2001:db8:1:3::1"); ok {
		t.Fatal("another /64 must stay unlocked")
	}
	if got := c.AttemptsLeftFor("2001:db8:1:3::1"); got != MaxAttempts {
		t.Fatalf("attempts left of another /64 = %d", got)
	}
	if err := c.VerifyFrom("2001:db8:1:3::1", code); err != nil {
		t.Fatalf("another /64 with the right code: %v", err)
	}
	if len(c.perIP) != 0 {
		t.Fatalf("%d counters left", len(c.perIP))
	}
}

func TestIPKey(t *testing.T) {
	tests := []struct{ in, want string }{
		{"192.0.2.10", "192.0.2.10"},
		{"::ffff:192.0.2.10", "192.0.2.10"},
		{"2001:db8:1:2:3:4:5:6", "2001:db8:1:2::/64"},
		{"fe80::1%eth0", "fe80::/64"},
		{"", ""},
		{"garbage", "garbage"},
	}
	for _, tt := range tests {
		if got := ipKey(tt.in); got != tt.want {
			t.Errorf("ipKey(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestRotateInvalidatesOldCode(t *testing.T) {
	c := NewCodes(CodeOptions{})
	old, _, _ := c.Rotate()
	c.Rotate()
	if c.Verify(old) == nil {
		t.Fatal("old code still valid")
	}
}

func TestIPLockKeepsCodeValid(t *testing.T) {
	clk := newClock()
	var announced []string
	c := NewCodes(CodeOptions{Now: clk.Now, Announce: func(code string, _ time.Time) { announced = append(announced, code) }})
	code, _, _ := c.Rotate()

	for i := 1; i < MaxAttempts; i++ {
		err := c.VerifyFrom("10.0.0.5", "WRONGONE")
		var ce *CodeError
		if !errors.As(err, &ce) || ce.Locked || ce.Left != MaxAttempts-i {
			t.Fatalf("attempt %d: %v", i, err)
		}
		if got := c.AttemptsLeftFor("10.0.0.5"); got != MaxAttempts-i {
			t.Fatalf("AttemptsLeftFor = %d", got)
		}
	}
	if got := c.AttemptsLeftFor("10.0.0.6"); got != MaxAttempts {
		t.Fatalf("other IP attempts = %d", got)
	}
	if err := c.VerifyFrom("10.0.0.5", "WRONGONE"); !isLocked(err) {
		t.Fatalf("expected lock: %v", err)
	}
	// The locked client is refused even with the right code ...
	clk.Advance(LockDuration - time.Second)
	if err := c.VerifyFrom("10.0.0.5", code); !isLocked(err) {
		t.Fatalf("locked verify: %v", err)
	}
	if ok, _ := c.LockedFor("10.0.0.5"); !ok {
		t.Fatal("LockedFor false")
	}
	// ... while another client still unlocks with the printed code, which
	// was neither rotated nor invalidated.
	if ok, _ := c.LockedFor("10.0.0.6"); ok {
		t.Fatal("other IP locked")
	}
	if ok, _ := c.Locked(); ok {
		t.Fatal("one locked client must not lock everybody")
	}
	clk.Advance(2 * time.Second)
	if err := c.VerifyFrom("10.0.0.5", code); err != nil {
		t.Fatalf("after lock end: %v", err)
	}
	if len(announced) != 1 {
		t.Fatalf("code rotated by a lock: %v", announced)
	}
}

func TestGlobalCeiling(t *testing.T) {
	clk := newClock()
	var announced []string
	c := NewCodes(CodeOptions{Now: clk.Now, GlobalMaxAttempts: 6, Announce: func(code string, _ time.Time) { announced = append(announced, code) }})
	code, _, _ := c.Rotate()
	// Distinct IPs never hit the per-IP limit but exhaust the global ceiling.
	for i := 0; i < 5; i++ {
		if err := c.VerifyFrom(fmt.Sprintf("10.0.0.%d", i), "WRONGONE"); err == nil || isLocked(err) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if err := c.VerifyFrom("10.0.0.9", "WRONGONE"); !isLocked(err) {
		t.Fatalf("expected global lock: %v", err)
	}
	if err := c.VerifyFrom("10.0.0.77", code); !isLocked(err) {
		t.Fatalf("right code during global lock: %v", err)
	}
	if ok, _ := c.Locked(); !ok {
		t.Fatal("Locked() false")
	}
	clk.Advance(LockDuration + time.Second)
	if err := c.VerifyFrom("10.0.0.77", code); err != nil {
		t.Fatalf("code after global lock: %v", err)
	}
	if len(announced) != 1 {
		t.Fatalf("announced = %v", announced)
	}
}

func TestInvalidateClearsLocks(t *testing.T) {
	clk := newClock()
	c := NewCodes(CodeOptions{Now: clk.Now})
	c.Rotate()
	for i := 0; i < MaxAttempts; i++ {
		c.VerifyFrom("10.0.0.5", "WRONGONE")
	}
	c.Invalidate()
	if ok, _ := c.LockedFor("10.0.0.5"); ok {
		t.Fatal("lock survived Invalidate")
	}
	clk.Advance(2 * LockDuration)
	c.Tick()
	if _, _, ok := c.Current(); ok {
		t.Fatal("code resurrected after Invalidate")
	}
}

func TestCodeAuditEvents(t *testing.T) {
	clk := newClock()
	var kinds []string
	c := NewCodes(CodeOptions{Now: clk.Now, Audit: func(e CodeEvent) { kinds = append(kinds, e.Kind+"@"+e.IP) }})
	code, _, _ := c.Rotate()
	for i := 0; i < MaxAttempts; i++ {
		c.VerifyFrom("1.2.3.4", "WRONGONE")
	}
	c.VerifyFrom("5.6.7.8", code)
	want := []string{}
	for i := 1; i < MaxAttempts; i++ {
		want = append(want, EventWrongCode+"@1.2.3.4")
	}
	want = append(want, EventWrongCode+"@1.2.3.4", EventIPLocked+"@1.2.3.4", EventUnlocked+"@5.6.7.8")
	if !reflect.DeepEqual(kinds, want) {
		t.Fatalf("events = %v\nwant %v", kinds, want)
	}
}

func isLocked(err error) bool {
	var ce *CodeError
	return errors.As(err, &ce) && ce.Locked
}

func TestSuccessResetsFailures(t *testing.T) {
	c := NewCodes(CodeOptions{})
	code, _, _ := c.Rotate()
	c.Verify("AAAAAAAA")
	c.Verify("AAAAAAAA")
	if err := c.Verify(code); err != nil {
		t.Fatal(err)
	}
	if c.AttemptsLeft() != MaxAttempts {
		t.Fatalf("left = %d", c.AttemptsLeft())
	}
}

func TestRotateClearsLockAndRunRotates(t *testing.T) {
	c := NewCodes(CodeOptions{Validity: 50 * time.Millisecond})
	var n int
	ch := make(chan struct{}, 8)
	c.announce = func(string, time.Time) { n++; ch <- struct{}{} }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.Rotate()
	<-ch
	go c.Run(ctx)
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not rotate")
	}
}

func TestInvalidate(t *testing.T) {
	c := NewCodes(CodeOptions{})
	code, _, _ := c.Rotate()
	c.Invalidate()
	if c.Verify(code) == nil {
		t.Fatal("invalidated code accepted")
	}
}

func TestSessions(t *testing.T) {
	clk := newClock()
	s := NewSessions(SessionOptions{Now: clk.Now})
	tok, sess, err := s.Unlock()
	if err != nil || len(tok) != 43 || sess.Wizard == nil {
		t.Fatalf("unlock: %q %v", tok, err)
	}
	if _, ok := s.Lookup(tok); !ok {
		t.Fatal("lookup failed")
	}
	if _, ok := s.Lookup("nope"); ok {
		t.Fatal("bad token accepted")
	}
	// Activity keeps the session alive past the original idle window.
	clk.Advance(20 * time.Minute)
	if _, ok := s.Lookup(tok); !ok {
		t.Fatal("expired too early")
	}
	clk.Advance(20 * time.Minute)
	if _, ok := s.Lookup(tok); !ok {
		t.Fatal("idle timer not refreshed")
	}
	clk.Advance(SessionIdle)
	if _, ok := s.Lookup(tok); ok {
		t.Fatal("idle session still valid")
	}

	// Replacement.
	t1, _, _ := s.Unlock()
	t2, _, _ := s.Unlock()
	if _, ok := s.Lookup(t1); ok {
		t.Fatal("old session survived")
	}
	if _, ok := s.Lookup(t2); !ok {
		t.Fatal("new session missing")
	}
	s.Clear()
	if _, ok := s.Lookup(t2); ok {
		t.Fatal("session survived Clear")
	}
}

func TestSessionCookie(t *testing.T) {
	s := NewSessions(SessionOptions{})
	tok, _, _ := s.Unlock()
	c := s.Cookie(tok)
	if c.Name != "nexus_setup" || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
		t.Fatalf("cookie %+v", c)
	}
	if NewSessions(SessionOptions{InsecureCookie: true}).Cookie("x").Secure {
		t.Fatal("insecure option ignored")
	}
	r, _ := http.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: SessionCookie, Value: tok})
	if _, ok := s.FromRequest(r); !ok {
		t.Fatal("FromRequest failed")
	}
	if s.ClearCookie().MaxAge >= 0 {
		t.Fatal("ClearCookie MaxAge")
	}
}

type fakeCounter struct {
	n     int
	err   error
	calls int
}

func (f *fakeCounter) CountUsers(context.Context) (int, error) { f.calls++; return f.n, f.err }

func TestMode(t *testing.T) {
	fc := &fakeCounter{}
	m := NewMode(fc)
	ctx := context.Background()
	if !m.Active(ctx) || !m.Active(ctx) || fc.calls != 1 {
		t.Fatalf("cache: calls=%d", fc.calls)
	}
	fc.n = 1
	if !m.Active(ctx) {
		t.Fatal("cache should hold")
	}
	m.Invalidate()
	if m.Active(ctx) {
		t.Fatal("operator exists but active")
	}
	fc.err = errors.New("db")
	m.Invalidate()
	if !m.Active(ctx) {
		t.Fatal("error must fail closed")
	}
	fc.err = nil
	if m.Active(ctx) {
		t.Fatal("error result must not be cached")
	}
}

func TestAdminDispatchLoginUnlock(t *testing.T) {
	ctx := context.Background()
	if r := (AdminHandlers{}).dispatch(ctx, CmdLoginUnlock); r.OK {
		t.Error("unwired login-unlock succeeded")
	}
	h := AdminHandlers{LoginUnlock: func(context.Context) (string, error) { return "done", nil }}
	if r := h.dispatch(ctx, CmdLoginUnlock); !r.OK || r.Message != "done" {
		t.Errorf("response = %+v", r)
	}
	h.LoginUnlock = func(context.Context) (string, error) { return "", errors.New("nope") }
	if r := h.dispatch(ctx, CmdLoginUnlock); r.OK || r.Message != "nope" {
		t.Errorf("response = %+v", r)
	}
}
