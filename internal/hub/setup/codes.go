// Package setup implements the hub's first-run setup mode: one-time setup
// codes, the setup session, the in-memory wizard state and the local admin
// socket used by `nexus setup code` and `nexus user reset`.
package setup

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
)

const (
	// CodeLength is the number of characters of a setup code.
	CodeLength = 8
	// CodeValidity is how long a setup code is valid and the auto-rotation period.
	CodeValidity = 60 * time.Minute
	// MaxAttempts is the number of wrong codes before input is locked.
	MaxAttempts = 5
	// LockDuration is how long input stays locked after MaxAttempts failures.
	LockDuration = 15 * time.Minute

	// GlobalMaxAttempts is the number of wrong codes from all clients together
	// within one LockDuration window before input is locked for everybody. It
	// is far above MaxAttempts so one LAN client that guesses is locked out
	// alone and cannot keep the operator from the printed code.
	GlobalMaxAttempts = 50

	// maxTrackedIPs bounds the per-IP table; expired entries are pruned first.
	maxTrackedIPs = 4096

	// codeAlphabet omits 0, O, 1, I and L to avoid misreading from a console.
	codeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
)

// CodeError is returned by Codes.Verify for a wrong, expired or locked code.
type CodeError struct {
	// Left is the number of attempts remaining (0 when locked).
	Left int
	// Locked reports that input is locked until Until.
	Locked bool
	Until  time.Time
}

func (e *CodeError) Error() string {
	if e.Locked {
		return "Input locked for 15 minutes"
	}
	if e.Left == 1 {
		return "Code invalid or expired. 1 attempt left."
	}
	return fmt.Sprintf("Code invalid or expired. %d attempts left.", e.Left)
}

// CodeOptions configures Codes. Zero values use the documented defaults.
type CodeOptions struct {
	// Now is the clock; defaults to time.Now.
	Now func() time.Time
	// Announce is called for every newly generated code (service start,
	// auto-rotation, `nexus setup code`, lock expiry). The caller writes it to
	// the journal. This is the single deliberate exception to "never log
	// secrets": the code is how the operator learns it, it is one-time, short
	// lived and worthless once an operator exists.
	Announce func(code string, expires time.Time)
	// Audit receives unlock attempts (success, wrong code, lock). It runs
	// outside the internal mutex and must not block for long. Detail never
	// contains the entered code.
	Audit func(CodeEvent)
	// Validity, MaxAttempts, GlobalMaxAttempts and LockDuration override the
	// defaults (tests).
	Validity          time.Duration
	MaxAttempts       int
	GlobalMaxAttempts int
	LockDuration      time.Duration
}

// Kinds of CodeEvent.
const (
	EventUnlocked  = "unlocked"    // correct code
	EventWrongCode = "wrong"       // wrong or expired code
	EventIPLocked  = "ip-locked"   // this client reached MaxAttempts
	EventAllLocked = "global-lock" // all clients together reached GlobalMaxAttempts
)

// CodeEvent describes one unlock attempt for auditing.
type CodeEvent struct {
	Kind string
	IP   string
	Time time.Time
}

// ipState is the failure counter of one client address.
type ipState struct {
	failures    int
	lockedUntil time.Time
	last        time.Time
}

// Codes manages the current setup code, its expiry and the attempt lock.
type Codes struct {
	now      func() time.Time
	announce func(string, time.Time)
	validity time.Duration
	max      int
	globalMx int
	lockFor  time.Duration
	audit    func(CodeEvent)

	mu      sync.Mutex
	code    string // normalized; empty after Invalidate. A lock never clears it.
	expires time.Time
	perIP   map[string]*ipState
	// Global ceiling: failures from all clients within the current window, and
	// the lock that follows when it is exceeded.
	globalFails  int
	globalStart  time.Time
	globalLocked time.Time
	wake         chan struct{}
}

// NewCodes creates a Codes with no active code; call Rotate on service start.
func NewCodes(o CodeOptions) *Codes {
	c := &Codes{
		now: o.Now, announce: o.Announce, validity: o.Validity,
		max: o.MaxAttempts, globalMx: o.GlobalMaxAttempts, lockFor: o.LockDuration,
		audit: o.Audit, perIP: make(map[string]*ipState), wake: make(chan struct{}, 1),
	}
	if c.now == nil {
		c.now = time.Now
	}
	if c.validity <= 0 {
		c.validity = CodeValidity
	}
	if c.max <= 0 {
		c.max = MaxAttempts
	}
	if c.globalMx <= 0 {
		c.globalMx = GlobalMaxAttempts
	}
	if c.lockFor <= 0 {
		c.lockFor = LockDuration
	}
	return c
}

// NormalizeCode upper-cases the input and strips spaces and dashes.
func NormalizeCode(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		if r == ' ' || r == '-' || r == '\t' || r == '\n' || r == '\r' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// FormatCode renders a normalized code as XXXX-XXXX.
func FormatCode(code string) string {
	if len(code) != CodeLength {
		return code
	}
	return code[:CodeLength/2] + "-" + code[CodeLength/2:]
}

func generateCode() (string, error) {
	max := big.NewInt(int64(len(codeAlphabet)))
	b := make([]byte, CodeLength)
	for i := range b {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("setup: generate code: %w", err)
		}
		b[i] = codeAlphabet[n.Int64()]
	}
	return string(b), nil
}

// Rotate replaces the current code with a fresh one, clears all failure
// counters and locks, announces it and returns it (normalized) with its expiry. The old code
// is invalid afterwards.
func (c *Codes) Rotate() (string, time.Time, error) {
	c.mu.Lock()
	code, exp, err := c.rotateLocked()
	c.mu.Unlock()
	if err != nil {
		return "", time.Time{}, err
	}
	c.notify(code, exp)
	return code, exp, nil
}

func (c *Codes) rotateLocked() (string, time.Time, error) {
	code, err := generateCode()
	if err != nil {
		return "", time.Time{}, err
	}
	c.code = code
	c.expires = c.now().Add(c.validity)
	c.resetFailuresLocked()
	select {
	case c.wake <- struct{}{}:
	default:
	}
	return code, c.expires, nil
}

func (c *Codes) resetFailuresLocked() {
	c.perIP = make(map[string]*ipState)
	c.globalFails = 0
	c.globalStart = time.Time{}
	c.globalLocked = time.Time{}
}

func (c *Codes) notify(code string, exp time.Time) {
	if c.announce != nil {
		c.announce(code, exp)
	}
}

// Invalidate drops the current code (used when setup is committed).
func (c *Codes) Invalidate() {
	c.mu.Lock()
	c.code = ""
	c.expires = time.Time{}
	c.resetFailuresLocked() // no lock state may outlive the code
	c.mu.Unlock()
}

// Current returns the current code and expiry, ok=false while locked,
// invalidated or expired.
func (c *Codes) Current() (code string, expires time.Time, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.code == "" || !c.now().Before(c.expires) {
		return "", time.Time{}, false
	}
	return c.code, c.expires, true
}

// Tick rotates the code once it expired. Run calls it; tests call it directly.
// A lock never rotates the code: the printed code must stay valid while one
// client is locked out.
func (c *Codes) Tick() {
	c.mu.Lock()
	if c.code == "" || c.now().Before(c.expires) {
		c.mu.Unlock()
		return
	}
	code, exp, err := c.rotateLocked()
	c.mu.Unlock()
	if err == nil {
		c.notify(code, exp)
	}
}

// ipStateLocked returns the live counter of ip (creating it), dropping a
// counter whose lock has run out.
func (c *Codes) ipStateLocked(ip string, now time.Time) *ipState {
	st := c.perIP[ip]
	if st != nil && !st.lockedUntil.IsZero() && !now.Before(st.lockedUntil) {
		delete(c.perIP, ip)
		st = nil
	}
	if st == nil {
		if len(c.perIP) >= maxTrackedIPs {
			c.pruneLocked(now)
		}
		st = &ipState{}
		c.perIP[ip] = st
	}
	return st
}

// pruneLocked drops idle counters; if the table is still full the oldest
// unlocked ones go (a locked entry is what we must keep).
func (c *Codes) pruneLocked(now time.Time) {
	for ip, st := range c.perIP {
		if st.lockedUntil.IsZero() && now.Sub(st.last) >= c.lockFor ||
			!st.lockedUntil.IsZero() && !now.Before(st.lockedUntil) {
			delete(c.perIP, ip)
		}
	}
	for ip, st := range c.perIP {
		if len(c.perIP) < maxTrackedIPs {
			break
		}
		if st.lockedUntil.IsZero() {
			delete(c.perIP, ip)
		}
	}
}

// Locked reports whether input is locked for everybody (global ceiling).
func (c *Codes) Locked() (bool, time.Time) { return c.LockedFor("") }

// LockedFor reports whether input is locked for ip, either by its own failures
// or by the global ceiling, and until when.
func (c *Codes) LockedFor(ip string) (bool, time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lockedLocked(ip, c.now())
}

func (c *Codes) lockedLocked(ip string, now time.Time) (bool, time.Time) {
	var until time.Time
	if now.Before(c.globalLocked) {
		until = c.globalLocked
	}
	if st := c.perIP[ip]; st != nil && now.Before(st.lockedUntil) && st.lockedUntil.After(until) {
		until = st.lockedUntil
	}
	return !until.IsZero(), until
}

// AttemptsLeft returns the remaining attempts before the lock for an
// unspecified client.
func (c *Codes) AttemptsLeft() int { return c.AttemptsLeftFor("") }

// AttemptsLeftFor returns the remaining attempts of ip before its lock.
func (c *Codes) AttemptsLeftFor(ip string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.perIP[ip]
	if st == nil || (!st.lockedUntil.IsZero() && !c.now().Before(st.lockedUntil)) {
		return c.max
	}
	return c.max - st.failures
}

// Verify checks a code for an unspecified client; see VerifyFrom.
func (c *Codes) Verify(input string) error { return c.VerifyFrom("", input) }

// VerifyFrom checks a user-entered code from the client at ip. It returns nil
// on success and a *CodeError otherwise. After MaxAttempts failures from one
// ip that ip is locked for LockDuration; after GlobalMaxAttempts failures
// within one LockDuration window from all clients, everybody is. Locks never
// invalidate or rotate the code.
func (c *Codes) VerifyFrom(ip, input string) error {
	c.Tick() // pick up an expired code first

	c.mu.Lock()
	now := c.now()
	if locked, until := c.lockedLocked(ip, now); locked {
		c.mu.Unlock()
		return &CodeError{Locked: true, Until: until}
	}
	got := []byte(NormalizeCode(input))
	want := []byte(c.code)
	valid := c.code != "" && now.Before(c.expires) &&
		len(got) == len(want) && subtle.ConstantTimeCompare(got, want) == 1
	if valid {
		delete(c.perIP, ip)
		c.mu.Unlock()
		c.emit(EventUnlocked, ip, now)
		return nil
	}

	st := c.ipStateLocked(ip, now)
	st.failures++
	st.last = now
	if c.globalStart.IsZero() || !now.Before(c.globalStart.Add(c.lockFor)) {
		c.globalStart, c.globalFails = now, 0
	}
	c.globalFails++
	var events []string
	var err *CodeError
	switch {
	case c.globalFails >= c.globalMx:
		c.globalLocked = now.Add(c.lockFor)
		c.globalFails = 0
		c.globalStart = time.Time{}
		events = append(events, EventWrongCode, EventAllLocked)
		err = &CodeError{Locked: true, Until: c.globalLocked}
	case st.failures >= c.max:
		st.lockedUntil = now.Add(c.lockFor)
		events = append(events, EventWrongCode, EventIPLocked)
		err = &CodeError{Locked: true, Until: st.lockedUntil}
	default:
		events = append(events, EventWrongCode)
		err = &CodeError{Left: c.max - st.failures}
	}
	c.mu.Unlock()
	for _, k := range events {
		c.emit(k, ip, now)
	}
	return err
}

// SetAudit installs (or replaces) the audit hook of CodeOptions.Audit after
// construction, for callers that create Codes before the store is available.
func (c *Codes) SetAudit(fn func(CodeEvent)) {
	c.mu.Lock()
	c.audit = fn
	c.mu.Unlock()
}

func (c *Codes) emit(kind, ip string, at time.Time) {
	c.mu.Lock()
	fn := c.audit
	c.mu.Unlock()
	if fn != nil {
		fn(CodeEvent{Kind: kind, IP: ip, Time: at})
	}
}

// Run rotates the code automatically when it expires (every 60 minutes). It
// blocks until ctx is done.
func (c *Codes) Run(ctx context.Context) {
	for {
		c.mu.Lock()
		wait := c.expires.Sub(c.now())
		idle := c.code == ""
		c.mu.Unlock()

		if idle {
			wait = time.Hour // nothing scheduled; wake on Rotate
		}
		if wait < time.Second {
			wait = time.Second
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-c.wake:
			t.Stop()
		case <-t.C:
			c.Tick()
		}
	}
}
