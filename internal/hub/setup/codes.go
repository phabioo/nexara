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
	// Validity, MaxAttempts and LockDuration override the defaults (tests).
	Validity     time.Duration
	MaxAttempts  int
	LockDuration time.Duration
}

// Codes manages the current setup code, its expiry and the attempt lock.
type Codes struct {
	now      func() time.Time
	announce func(string, time.Time)
	validity time.Duration
	max      int
	lockFor  time.Duration

	mu          sync.Mutex
	code        string // normalized; empty while locked or invalidated
	expires     time.Time
	failures    int
	lockedUntil time.Time
	wake        chan struct{}
}

// NewCodes creates a Codes with no active code; call Rotate on service start.
func NewCodes(o CodeOptions) *Codes {
	c := &Codes{
		now: o.Now, announce: o.Announce, validity: o.Validity,
		max: o.MaxAttempts, lockFor: o.LockDuration, wake: make(chan struct{}, 1),
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

// Rotate replaces the current code with a fresh one, clears failures and any
// lock, announces it and returns it (normalized) with its expiry. The old code
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
	c.failures = 0
	c.lockedUntil = time.Time{}
	select {
	case c.wake <- struct{}{}:
	default:
	}
	return code, c.expires, nil
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

// Tick rotates the code if it expired or a lock ran out. Run calls it; tests
// call it directly.
func (c *Codes) Tick() {
	c.mu.Lock()
	now := c.now()
	due := false
	if !c.lockedUntil.IsZero() {
		due = !now.Before(c.lockedUntil)
	} else {
		due = c.code != "" && !now.Before(c.expires)
	}
	if !due {
		c.mu.Unlock()
		return
	}
	code, exp, err := c.rotateLocked()
	c.mu.Unlock()
	if err == nil {
		c.notify(code, exp)
	}
}

// Locked reports whether input is currently locked and until when.
func (c *Codes) Locked() (bool, time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lockedUntil.IsZero() || !c.now().Before(c.lockedUntil) {
		return false, time.Time{}
	}
	return true, c.lockedUntil
}

// AttemptsLeft returns the remaining attempts before the lock.
func (c *Codes) AttemptsLeft() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.max - c.failures
}

// Verify checks a user-entered code. It returns nil on success and a
// *CodeError otherwise. After MaxAttempts failures input is locked for
// LockDuration; when the lock ends a fresh code is generated.
func (c *Codes) Verify(input string) error {
	c.Tick() // pick up an expired lock or code first

	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if !c.lockedUntil.IsZero() && now.Before(c.lockedUntil) {
		return &CodeError{Locked: true, Until: c.lockedUntil}
	}
	got := []byte(NormalizeCode(input))
	want := []byte(c.code)
	valid := c.code != "" && now.Before(c.expires) &&
		len(got) == len(want) && subtle.ConstantTimeCompare(got, want) == 1
	if valid {
		c.failures = 0
		return nil
	}
	c.failures++
	if c.failures >= c.max {
		c.code = ""
		c.lockedUntil = now.Add(c.lockFor)
		select {
		case c.wake <- struct{}{}:
		default:
		}
		return &CodeError{Locked: true, Until: c.lockedUntil}
	}
	return &CodeError{Left: c.max - c.failures}
}

// Run rotates the code automatically when it expires (every 60 minutes) and
// generates a fresh one after a lock ends. It blocks until ctx is done.
func (c *Codes) Run(ctx context.Context) {
	for {
		c.mu.Lock()
		deadline := c.expires
		if !c.lockedUntil.IsZero() {
			deadline = c.lockedUntil
		}
		wait := deadline.Sub(c.now())
		idle := c.code == "" && c.lockedUntil.IsZero()
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
