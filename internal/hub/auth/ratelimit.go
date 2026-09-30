package auth

import (
	"strings"
	"sync"
	"time"
)

const (
	limiterMaxEntries  = 10000
	limiterPruneEvery  = time.Minute
	limiterKeyIP       = "ip:"
	limiterKeyAccount  = "acct:"
	limiterMaxKeyBytes = 200
)

// rateLimiter is an in-memory sliding-window failure limiter.
//
// Algorithm: per key (IP address or account) it keeps the timestamps of the
// last `max` failures. Failures older than `window` are dropped. A key is
// blocked while it holds `max` failures inside the window; the block lifts
// when the oldest of them leaves the window (retry-after = oldest + window -
// now). Blocked attempts do not extend the block, so an attacker cannot keep
// an account locked forever by hammering it, but every new failure after the
// block lifts re-blocks immediately because the window is still nearly full.
//
// Memory is bounded: each key stores at most `max` timestamps, expired keys
// are swept once a minute, and at limiterMaxEntries keys an arbitrary one is
// evicted to admit a new key. One IP can create at most `max` entries per
// window before it is blocked itself.
type rateLimiter struct {
	mu        sync.Mutex
	now       func() time.Time
	max       int
	window    time.Duration
	entries   map[string]*limiterEntry
	lastPrune time.Time
}

type limiterEntry struct {
	fails    []time.Time
	notified bool // the current block was already reported (audit once per block)
}

func newRateLimiter(now func() time.Time, max int, window time.Duration) *rateLimiter {
	return &rateLimiter{now: now, max: max, window: window, entries: map[string]*limiterEntry{}}
}

func limiterKey(prefix, id string) string {
	id = strings.ToLower(strings.TrimSpace(id))
	if len(id) > limiterMaxKeyBytes {
		id = id[:limiterMaxKeyBytes]
	}
	return prefix + id
}

// trim drops expired failures of e and the notified flag once the block is over.
func (l *rateLimiter) trim(e *limiterEntry, now time.Time) {
	cut := now.Add(-l.window)
	i := 0
	for i < len(e.fails) && !e.fails[i].After(cut) {
		i++
	}
	e.fails = e.fails[i:]
	if len(e.fails) < l.max {
		e.notified = false
	}
}

func (l *rateLimiter) prune(now time.Time) {
	if now.Sub(l.lastPrune) < limiterPruneEvery {
		return
	}
	l.lastPrune = now
	for k, e := range l.entries {
		l.trim(e, now)
		if len(e.fails) == 0 {
			delete(l.entries, k)
		}
	}
}

// check reports whether any of the keys is blocked, the longest remaining
// wait, and whether this is the first time this block is reported.
func (l *rateLimiter) check(keys ...string) (blocked bool, retry time.Duration, first bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.prune(now)
	for _, k := range keys {
		e := l.entries[k]
		if e == nil {
			continue
		}
		l.trim(e, now)
		if len(e.fails) < l.max {
			continue
		}
		blocked = true
		if wait := e.fails[0].Add(l.window).Sub(now); wait > retry {
			retry = wait
		}
		if !e.notified {
			e.notified = true
			first = true
		}
	}
	return blocked, retry, first
}

// fail records one failure for every key.
func (l *rateLimiter) fail(keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.prune(now)
	for _, k := range keys {
		e := l.entries[k]
		if e == nil {
			if len(l.entries) >= limiterMaxEntries {
				for victim := range l.entries {
					delete(l.entries, victim)
					break
				}
			}
			e = &limiterEntry{}
			l.entries[k] = e
		}
		l.trim(e, now)
		e.fails = append(e.fails, now)
		if len(e.fails) > l.max {
			e.fails = e.fails[len(e.fails)-l.max:]
		}
	}
}

// reset forgets the failures of a key (successful login).
func (l *rateLimiter) reset(key string) {
	l.mu.Lock()
	delete(l.entries, key)
	l.mu.Unlock()
}

func (l *rateLimiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}
