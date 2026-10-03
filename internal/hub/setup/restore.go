package setup

import (
	"os"
	"sync"
	"time"
)

// Restore from a backup is offered in the setup wizard after the setup code
// was verified (decision #55; the code gates everything, so none of this is
// reachable without a setup session). The package keeps the state the HTTP
// layer needs between the steps "upload and check" and "restore":
//
//   - Upload: the checked backup file on disk and the passphrase for it;
//   - RestoreLimits: the attempt limits and the single-flight guard. Every
//     check derives a key with argon2id (128 MiB on a Pi), so attempts are
//     limited per client address and for all clients together, independent of
//     the setup code's own lock.

// Restore limits.
const (
	// RestorePerIPAttempts is the number of checks one client address may
	// start per RestoreWindow.
	RestorePerIPAttempts = 5
	// RestoreGlobalAttempts is the same for all clients together.
	RestoreGlobalAttempts = 15
	// RestoreWindow is the sliding window of both limits.
	RestoreWindow = 15 * time.Minute

	maxLimiterKeys = 4096
)

// RestorePreview is what the operator confirms before the restore: the facts
// of the backup's manifest.
type RestorePreview struct {
	HubName       string
	HubVersion    string
	Reason        string
	CreatedAt     time.Time
	SchemaVersion int
	Files         int
}

// Upload is a backup file that was received, decrypted and verified. It lives
// in the setup session until it is restored, replaced or cancelled, and the
// session removes the file when it ends.
type Upload struct {
	Path       string // temporary file in the upload directory (0600)
	Name       string // file name as the browser sent it, for display only
	Size       int64
	Passphrase string // kept in memory only, for the restore itself
	Preview    RestorePreview
}

// SetUpload stores u as the session's pending upload and deletes the file of
// the previous one.
func (s *Session) SetUpload(u Upload) {
	s.umu.Lock()
	old := s.upload
	s.upload = &u
	s.umu.Unlock()
	removeUpload(old)
}

// Upload returns a copy of the pending upload.
func (s *Session) Upload() (Upload, bool) {
	s.umu.Lock()
	defer s.umu.Unlock()
	if s.upload == nil {
		return Upload{}, false
	}
	return *s.upload, true
}

// TakeUpload detaches the pending upload; the caller owns the file now and
// must remove it. Of two concurrent callers only one gets it.
func (s *Session) TakeUpload() (Upload, bool) {
	s.umu.Lock()
	defer s.umu.Unlock()
	if s.upload == nil {
		return Upload{}, false
	}
	u := *s.upload
	s.upload = nil
	return u, true
}

// DropUpload deletes the pending upload and its file.
func (s *Session) DropUpload() {
	s.umu.Lock()
	old := s.upload
	s.upload = nil
	s.umu.Unlock()
	removeUpload(old)
}

func removeUpload(u *Upload) {
	if u == nil || u.Path == "" {
		return
	}
	_ = os.Remove(u.Path)
}

// AttemptLimiter is a sliding-window limiter that counts every attempt, not
// only failures: the thing it protects is expensive in itself.
type AttemptLimiter struct {
	now    func() time.Time
	max    int
	window time.Duration

	mu   sync.Mutex
	hits map[string][]time.Time
}

// NewAttemptLimiter returns a limiter of max attempts per window and key.
func NewAttemptLimiter(now func() time.Time, max int, window time.Duration) *AttemptLimiter {
	if now == nil {
		now = time.Now
	}
	return &AttemptLimiter{now: now, max: max, window: window, hits: map[string][]time.Time{}}
}

// Allow records an attempt for key and reports whether it may proceed. When
// it may not, retry says how long until an attempt would be allowed; nothing
// is recorded then, so hammering does not extend the block.
func (l *AttemptLimiter) Allow(key string) (ok bool, retry time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	hits := l.trim(key, now)
	if len(hits) >= l.max {
		return false, hits[0].Add(l.window).Sub(now)
	}
	if _, known := l.hits[key]; !known && len(l.hits) >= maxLimiterKeys {
		for k := range l.hits { // sweep expired keys, then evict one if still full
			if len(l.trim(k, now)) == 0 {
				delete(l.hits, k)
			}
		}
		if len(l.hits) >= maxLimiterKeys {
			for k := range l.hits {
				delete(l.hits, k)
				break
			}
		}
	}
	l.hits[key] = append(hits, now)
	return true, 0
}

// refund takes back the attempt Allow recorded last for key.
func (l *AttemptLimiter) refund(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if h := l.hits[key]; len(h) > 0 {
		l.hits[key] = h[:len(h)-1]
	}
}

func (l *AttemptLimiter) trim(key string, now time.Time) []time.Time {
	h := l.hits[key]
	cut := now.Add(-l.window)
	i := 0
	for i < len(h) && !h[i].After(cut) {
		i++
	}
	h = h[i:]
	if len(h) == 0 {
		delete(l.hits, key)
		return nil
	}
	l.hits[key] = h
	return h
}

// RestoreLimits bundles the per-address and the global attempt limit of the
// setup restore and a guard that lets only one check or restore run at a time
// (each holds a 128 MiB key derivation and a copy of the backup).
type RestoreLimits struct {
	perIP  *AttemptLimiter
	global *AttemptLimiter
	busy   chan struct{}
}

// NewRestoreLimits returns the limits with the package defaults.
func NewRestoreLimits(now func() time.Time) *RestoreLimits {
	return &RestoreLimits{
		perIP:  NewAttemptLimiter(now, RestorePerIPAttempts, RestoreWindow),
		global: NewAttemptLimiter(now, RestoreGlobalAttempts, RestoreWindow),
		busy:   make(chan struct{}, 1),
	}
}

// Allow records one check from ip. It fails when this address or all clients
// together used up their attempts; retry is the longer wait.
func (r *RestoreLimits) Allow(ip string) (ok bool, retry time.Duration) {
	ok, retry = r.perIP.Allow(ip)
	if !ok {
		return false, retry
	}
	if gok, gretry := r.global.Allow("*"); !gok {
		r.perIP.refund(ip) // the address did nothing wrong
		return false, gretry
	}
	return true, 0
}

// Begin claims the single work slot. The returned function releases it.
func (r *RestoreLimits) Begin() (release func(), ok bool) {
	select {
	case r.busy <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-r.busy }) }, true
	default:
		return nil, false
	}
}
