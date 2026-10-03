package auth

import (
	"context"
	"net/netip"
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

	// resMu makes "check all three, then count in all three" one step, so
	// parallel attempts cannot all pass the check before any is counted.
	resMu sync.Mutex

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

// ipKey is the address a per-IP counter is kept under. IPv4 addresses count
// as they are; an IPv6 address stands for its whole /64, because one host or
// network owns billions of addresses in it and would otherwise get a fresh
// counter for every guess (security review A-04). IPv4-mapped IPv6 addresses
// count as IPv4. Text that is no IP address is used as it is.
func ipKey(ip string) string {
	ip = strings.ToLower(strings.TrimSpace(ip))
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	a = a.WithZone("").Unmap()
	if a.Is6() {
		if p, err := a.Prefix(64); err == nil {
			return p.String()
		}
	}
	return a.String()
}

func ipLimitKey(ip string) string { return limiterKey(limiterKeyIP, ipKey(ip)) }

func pairKey(account, ip string) string {
	// IP first: a very long attacker-chosen account ID is cut at the end of the key.
	return limiterKey(limiterKeyPair, ipKey(ip)+"|"+strings.ToLower(strings.TrimSpace(account)))
}

// check reports whether this attempt is blocked, the longest wait and whether
// this is the first report of a block (audit once per block).
func (l *loginLimits) check(account, ip string) (blocked bool, retry time.Duration, first bool) {
	b, r, f := l.ip.check(ipLimitKey(ip))
	blocked, retry, first = b, r, f
	b, r, f = l.pair.check(pairKey(account, ip))
	blocked, retry, first = blocked || b, max(retry, r), first || f
	if !l.isKnown(account, ip) {
		b, r, f = l.acct.check(limiterKey(limiterKeyAccount, account))
		blocked, retry, first = blocked || b, max(retry, r), first || f
	}
	return blocked, retry, first
}

// reservation is one attempt that was counted before it was evaluated.
type reservation struct {
	l          *loginLimits
	account    string
	ip         string
	at         time.Time
	ipKey      string
	pairKey    string
	acctKey    string
	registered bool
}

// reserve checks the three limits and, if none is blocked, counts the
// attempt as a failure in all three at once, before the passphrase or code is
// evaluated. N parallel attempts therefore get at most the limit's worth of
// evaluations. The caller gives the count back with refund or succeed when
// the attempt was right (or never evaluated). When blocked, nothing is
// counted and the reservation is unusable.
func (l *loginLimits) reserve(account, ip string) (r reservation, blocked bool, retry time.Duration, first bool) {
	l.resMu.Lock()
	defer l.resMu.Unlock()
	blocked, retry, first = l.check(account, ip)
	if blocked {
		return reservation{}, true, retry, first
	}
	at := l.now()
	r = reservation{
		l: l, account: account, ip: ip, at: at,
		ipKey: ipLimitKey(ip), pairKey: pairKey(account, ip), acctKey: limiterKey(limiterKeyAccount, account),
		registered: true,
	}
	l.ip.failAt(at, r.ipKey)
	l.pair.failAt(at, r.pairKey)
	l.acct.failAt(at, r.acctKey)
	return r, false, 0, false
}

// refund takes the whole reservation back: the attempt was not a guess (the
// first step of a two-step sign-in, a request that never reached argon2).
func (r reservation) refund() {
	if !r.registered {
		return
	}
	r.l.ip.unfail(r.ipKey, r.at)
	r.l.pair.unfail(r.pairKey, r.at)
	r.l.acct.unfail(r.acctKey, r.at)
}

// refundAccount takes back the account and pair counts but keeps the
// address's: a challenge replayed from another IP says nothing about the
// account's secrets, but the address that tried it is suspect.
func (r reservation) refundAccount() {
	if !r.registered {
		return
	}
	r.l.pair.unfail(r.pairKey, r.at)
	r.l.acct.unfail(r.acctKey, r.at)
}

// succeed ends a fully successful sign-in: the IP count is given back, the
// account's counters are reset and the IP is remembered as known.
func (r reservation) succeed() {
	if !r.registered {
		return
	}
	r.l.ip.unfail(r.ipKey, r.at)
	r.l.pair.reset(r.pairKey)
	r.l.acct.reset(r.acctKey)
	r.l.remember(r.account, r.ip, r.l.now())
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
