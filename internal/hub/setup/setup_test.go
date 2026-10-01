package setup

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
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
	if err := c.Verify(strings.ToLower(FormatCode(code))); err != nil {
		t.Fatalf("valid code rejected: %v", err)
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
	if err := c.VerifyFrom("10.0.0.6", code); err != nil {
		t.Fatalf("other client with printed code: %v", err)
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
