package auth

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/phabioo/nexara/internal/hub/store"
)

const (
	limiterKeyPair = "pair:"

	// accountLimitFactor sets the account-wide threshold relative to the
	// per-IP one (Config.AccountRateAttempts overrides it).
	accountLimitFactor = 10

	// knownIPTTL is how long a successful sign-in keeps an IP exempt from the
	// account-wide limit.
	knownIPTTL = 30 * 24 * time.Hour

	maxKnownAccounts = 64
	maxKnownIPs      = 64 // per account
	auditHydrateRows = 10000
)

// loginLimits combines the three failure counters of the sign-in (security
// review S-08). A LAN attacker must not be able to lock the operator out by
// guessing against the operator's ID, so:
//
//   - per IP: 5 failures block that address (any account);
//   - per (account, IP): 5 failures block that address for that account;
//   - per account: a much higher threshold (RateAttempts * 10) that only
//     slows a distributed guess, and which never applies to an IP that signed
//     in successfully as that account during the last 30 days.
//
// The attacker's own address is blocked after five tries; the operator on
// another address (or a known one) keeps getting in.
type loginLimits struct {
	now  func() time.Time
	ip   *rateLimiter
	pair *rateLimiter
	acct *rateLimiter

	mu       sync.Mutex
	known    map[string]map[string]time.Time // account key -> IP -> last success
	loadOnce sync.Once
	load     func() map[string]map[string]time.Time // seeds known (the audit log); may be nil
}

func newLoginLimits(now func() time.Time, ipMax, acctMax int, window time.Duration) *loginLimits {
	return &loginLimits{
		now:   now,
		ip:    newRateLimiter(now, ipMax, window),
		pair:  newRateLimiter(now, ipMax, window),
		acct:  newRateLimiter(now, acctMax, window),
		known: map[string]map[string]time.Time{},
	}
}

func pairKey(account, ip string) string {
	// IP first: a very long attacker-chosen account ID is cut at the end of the key.
	return limiterKey(limiterKeyPair, strings.ToLower(strings.TrimSpace(ip))+"|"+strings.ToLower(strings.TrimSpace(account)))
}

// check reports whether this attempt is blocked, the longest wait and whether
// this is the first report of a block (audit once per block).
func (l *loginLimits) check(account, ip string) (blocked bool, retry time.Duration, first bool) {
	b, r, f := l.ip.check(limiterKey(limiterKeyIP, ip))
	blocked, retry, first = b, r, f
	b, r, f = l.pair.check(pairKey(account, ip))
	blocked, retry, first = blocked || b, max(retry, r), first || f
	if !l.isKnown(account, ip) {
		b, r, f = l.acct.check(limiterKey(limiterKeyAccount, account))
		blocked, retry, first = blocked || b, max(retry, r), first || f
	}
	return blocked, retry, first
}

// fail records a failed attempt in all three counters.
func (l *loginLimits) fail(account, ip string) {
	l.ip.fail(limiterKey(limiterKeyIP, ip))
	l.pair.fail(pairKey(account, ip))
	l.acct.fail(limiterKey(limiterKeyAccount, account))
}

// failIP records a failure that only concerns the address (a challenge replayed from another IP).
func (l *loginLimits) failIP(ip string) { l.ip.fail(limiterKey(limiterKeyIP, ip)) }

// succeed resets the account's counters and remembers the IP as known.
func (l *loginLimits) succeed(account, ip string) {
	l.pair.reset(pairKey(account, ip))
	l.acct.reset(limiterKey(limiterKeyAccount, account))
	l.remember(account, ip, l.now())
}

// clear forgets every failure counter (not the known IPs).
func (l *loginLimits) clear() {
	l.ip.clear()
	l.pair.clear()
	l.acct.clear()
}

func (l *loginLimits) remember(account, ip string, at time.Time) {
	acct := limiterKey(limiterKeyAccount, account)
	ip = strings.ToLower(strings.TrimSpace(ip))
	if ip == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	rememberLocked(l.known, acct, ip, at)
}

func rememberLocked(known map[string]map[string]time.Time, acct, ip string, at time.Time) {
	ips := known[acct]
	if ips == nil {
		if len(known) >= maxKnownAccounts { // attacker-chosen names never get here: only real sign-ins are remembered
			for victim := range known {
				delete(known, victim)
				break
			}
		}
		ips = map[string]time.Time{}
		known[acct] = ips
	}
	if len(ips) >= maxKnownIPs {
		if _, have := ips[ip]; !have {
			var oldest string
			for k, t := range ips {
				if oldest == "" || t.Before(ips[oldest]) {
					oldest = k
				}
			}
			delete(ips, oldest)
		}
	}
	if prev, ok := ips[ip]; !ok || at.After(prev) {
		ips[ip] = at
	}
}

func (l *loginLimits) isKnown(account, ip string) bool {
	l.loadOnce.Do(func() {
		if l.load == nil {
			return
		}
		seed := l.load()
		l.mu.Lock()
		for acct, ips := range seed {
			for addr, at := range ips {
				rememberLocked(l.known, acct, addr, at)
			}
		}
		l.mu.Unlock()
	})
	acct := limiterKey(limiterKeyAccount, account)
	ip = strings.ToLower(strings.TrimSpace(ip))
	l.mu.Lock()
	defer l.mu.Unlock()
	at, ok := l.known[acct][ip]
	if !ok {
		return false
	}
	if l.now().Sub(at) >= knownIPTTL {
		delete(l.known[acct], ip)
		return false
	}
	return true
}

// knownLoginsFromAudit reads the successful sign-ins of the last 30 days from
// the audit log, so the exemption survives a restart. Best effort: only the
// newest auditHydrateRows entries are looked at and an error yields no seed.
func (s *Service) knownLoginsFromAudit() map[string]map[string]time.Time {
	out := map[string]map[string]time.Time{}
	entries, err := s.store.ListAudit(context.Background(), auditHydrateRows)
	if err != nil {
		return out
	}
	cut := s.now().Add(-knownIPTTL)
	for _, e := range entries { // newest first
		if e.Action != ActionLogin || e.Result != store.AuditOK || !e.Time.After(cut) {
			continue
		}
		ip := auditField(e.Detail, "ip=")
		if ip == "" || e.User == "" {
			continue
		}
		rememberLocked(out, limiterKey(limiterKeyAccount, e.User), strings.ToLower(ip), e.Time)
	}
	return out
}

// auditField returns the value of a "key=value" token of an audit detail.
func auditField(detail, key string) string {
	for _, tok := range strings.Fields(detail) {
		if v, ok := strings.CutPrefix(tok, key); ok {
			return v
		}
	}
	return ""
}
