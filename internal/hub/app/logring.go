package app

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/phabioo/nexara/internal/hub/httpserver"
)

// Settings › Diagnostics shows the hub's own log. The ring keeps the last
// records in memory next to the real log output (the journal); nothing is
// written anywhere else.
const (
	// LogRingSize is how many records the hub keeps for the Diagnostics card.
	LogRingSize = 1000
	// logRecordMax caps one retained line (message and attributes).
	logRecordMax = 600
)

// LogRing is a bounded in-memory copy of the hub's log. It implements
// httpserver.LogSource.
type LogRing struct {
	mu   sync.Mutex
	buf  []httpserver.LogRecord
	next int
	full bool
}

// NewLogRing returns a ring of size records (at least 1).
func NewLogRing(size int) *LogRing {
	return &LogRing{buf: make([]httpserver.LogRecord, max(size, 1))}
}

func (r *LogRing) add(rec httpserver.LogRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf[r.next] = rec
	r.next++
	if r.next == len(r.buf) {
		r.next, r.full = 0, true
	}
}

// Records implements httpserver.LogSource: newest first.
func (r *LogRing) Records() []httpserver.LogRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := r.next
	if r.full {
		n = len(r.buf)
	}
	out := make([]httpserver.LogRecord, 0, n)
	for i := 1; i <= n; i++ {
		out = append(out, r.buf[(r.next-i+len(r.buf))%len(r.buf)])
	}
	return out
}

// Tee returns a handler that passes every record to next and keeps a copy in
// the ring. The ring also keeps Info records when next would drop them, so the
// Diagnostics view is useful on a hub that logs at warn level.
func (r *LogRing) Tee(next slog.Handler) slog.Handler { return &ringHandler{ring: r, next: next} }

type ringHandler struct {
	ring   *LogRing
	next   slog.Handler
	prefix string   // group path for attribute keys, "a.b."
	attrs  []string // pre-formatted attributes from WithAttrs
}

func (h *ringHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return l >= slog.LevelInfo || h.next.Enabled(ctx, l)
}

func (h *ringHandler) Handle(ctx context.Context, rec slog.Record) error {
	if h.keep(rec) {
		parts := append([]string{rec.Message}, h.attrs...)
		rec.Attrs(func(a slog.Attr) bool {
			parts = appendAttr(parts, h.prefix, a)
			return true
		})
		h.ring.add(httpserver.LogRecord{Time: rec.Time, Level: rec.Level, Text: cleanLogText(strings.Join(parts, " "))})
	}
	if h.next.Enabled(ctx, rec.Level) {
		return h.next.Handle(ctx, rec)
	}
	return nil
}

// keep drops the request log of successful requests: it would push everything
// else out of the ring within minutes.
func (h *ringHandler) keep(rec slog.Record) bool {
	return !(rec.Message == "http request" && rec.Level < slog.LevelWarn)
}

func (h *ringHandler) WithAttrs(as []slog.Attr) slog.Handler {
	c := *h
	c.next = h.next.WithAttrs(as)
	c.attrs = append([]string(nil), h.attrs...)
	for _, a := range as {
		c.attrs = appendAttr(c.attrs, h.prefix, a)
	}
	return &c
}

func (h *ringHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	c := *h
	c.next = h.next.WithGroup(name)
	c.prefix = h.prefix + name + "."
	return &c
}

var secretKeyWords = []string{
	"pass", "pw", "secret", "token", "key", "cookie", "auth", "csrf", "code", "credential", "cert_pem",
	"otp", "sid", "session", "csr", "enroll", "private", "hash", "salt", "bearer",
}

// setupCodeRe matches the format of a setup code (8 characters of the code
// alphabet, optionally shown as XXXX-XXXX). It catches a code that ended up in
// the value of an attribute whose name gives nothing away.
var setupCodeRe = regexp.MustCompile(`\b[A-HJKMNP-Z2-9]{4}-?[A-HJKMNP-Z2-9]{4}\b`)

// secretKey matches attribute names whose value must not be kept. The hub does
// not log secrets (CLAUDE.md); this is the second line of defence.
func secretKey(k string) bool {
	k = strings.ToLower(k)
	for _, w := range secretKeyWords {
		if strings.Contains(k, w) {
			return true
		}
	}
	return false
}

func appendAttr(parts []string, prefix string, a slog.Attr) []string {
	a.Value = a.Value.Resolve()
	if a.Equal(slog.Attr{}) {
		return parts
	}
	if a.Value.Kind() == slog.KindGroup {
		p := prefix
		if a.Key != "" {
			p += a.Key + "."
		}
		for _, g := range a.Value.Group() {
			parts = appendAttr(parts, p, g)
		}
		return parts
	}
	key := prefix + a.Key
	if secretKey(key) {
		return append(parts, key+"=[redacted]")
	}
	v := setupCodeRe.ReplaceAllString(fmt.Sprint(a.Value.Any()), "[redacted]")
	if strings.ContainsAny(v, " \t\"=") {
		v = fmt.Sprintf("%q", v)
	}
	return append(parts, key+"="+v)
}

// cleanLogText strips control characters (log injection into the view) and
// caps the length.
func cleanLogText(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "?")
	}
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n == logRecordMax {
			b.WriteString("…")
			break
		}
		if !unicode.IsPrint(r) {
			r = ' '
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}
