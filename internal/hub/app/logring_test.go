package app

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func newRingLogger(size int, level slog.Level) (*slog.Logger, *LogRing, *bytes.Buffer) {
	var out bytes.Buffer
	ring := NewLogRing(size)
	h := slog.NewTextHandler(&out, &slog.HandlerOptions{Level: level})
	return slog.New(ring.Tee(h)), ring, &out
}

func TestLogRingIsBoundedAndNewestFirst(t *testing.T) {
	log, ring, _ := newRingLogger(3, slog.LevelInfo)
	if got := ring.Records(); len(got) != 0 {
		t.Fatalf("empty ring returned %v", got)
	}
	for i := 1; i <= 5; i++ {
		log.Info(fmt.Sprintf("line %d", i))
	}
	got := ring.Records()
	if len(got) != 3 {
		t.Fatalf("%d records, want 3", len(got))
	}
	for i, want := range []string{"line 5", "line 4", "line 3"} {
		if got[i].Text != want {
			t.Errorf("record %d = %q, want %q", i, got[i].Text, want)
		}
	}
	if NewLogRing(0).buf == nil || len(NewLogRing(-4).buf) != 1 {
		t.Error("a ring of size < 1 is not clamped to one record")
	}
}

func TestLogRingTeesAndKeepsInfoBelowTheOutputLevel(t *testing.T) {
	log, ring, out := newRingLogger(10, slog.LevelWarn)
	log.Debug("debug line")
	log.Info("info line")
	log.Warn("warn line")
	if s := out.String(); strings.Contains(s, "info line") || strings.Contains(s, "debug line") || !strings.Contains(s, "warn line") {
		t.Errorf("output changed by the ring: %q", s)
	}
	got := ring.Records()
	if len(got) != 2 || got[0].Text != "warn line" || got[0].Level != slog.LevelWarn || got[1].Text != "info line" {
		t.Fatalf("records = %+v", got)
	}
}

func TestLogRingText(t *testing.T) {
	tests := []struct {
		name string
		log  func(*slog.Logger)
		want string
		lack []string
	}{
		{"attributes", func(l *slog.Logger) { l.Info("agent connected", "host", "pi5", "version", "0.2.0") },
			"agent connected host=pi5 version=0.2.0", nil},
		{"quoting", func(l *slog.Logger) { l.Info("m", "err", "boom happened") }, `m err="boom happened"`, nil},
		{"with attrs and group", func(l *slog.Logger) { l.With("component", "grid").WithGroup("req").Info("m", "path", "/x") },
			"m component=grid req.path=/x", nil},
		{"group attribute", func(l *slog.Logger) { l.Info("m", slog.Group("a", slog.Int("n", 4))) }, "m a.n=4", nil},
		{"secrets are redacted", func(l *slog.Logger) {
			l.Info("login", "passphrase", "hunter2", "session_token", "abc", "Authorization", "Bearer x", "setup_code", "1234", "ok", "yes")
		}, "login passphrase=[redacted] session_token=[redacted] Authorization=[redacted] setup_code=[redacted] ok=yes",
			[]string{"hunter2", "abc", "Bearer", "1234"}},
		{"more secret key names", func(l *slog.Logger) {
			l.Info("m", "otp_value", "123456", "pw", "x1", "sid", "s1", "session", "s2", "csr", "c1", "enroll_id", "e1",
				"private", "p1", "hash", "h1", "salt", "s3", "bearer", "b1", "host", "pi5")
		}, "m otp_value=[redacted] pw=[redacted] sid=[redacted] session=[redacted] csr=[redacted] enroll_id=[redacted] private=[redacted] hash=[redacted] salt=[redacted] bearer=[redacted] host=pi5",
			[]string{"123456", "x1", "s1", "s2", "c1", "e1", "p1", "h1", "s3", "b1"}},
		{"setup code in an innocent attribute", func(l *slog.Logger) {
			l.Warn("setup", "detail", "wrong try for K7PQ2MXA", "input", "K7PQ-2MXA", "user", "fabio", "note", "database")
		}, `setup detail="wrong try for [redacted]" input=[redacted] user=fabio note=database`,
			[]string{"K7PQ2MXA", "K7PQ-2MXA"}},
		{"redaction applies to attributes added with With", func(l *slog.Logger) { l.With("api_key", "sekret").Info("m") },
			"m api_key=[redacted]", []string{"sekret"}},
		{"control characters cannot forge lines", func(l *slog.Logger) { l.Info("a\nb\x1b[31mred\r") }, "a b [31mred ", []string{"\n", "\x1b", "\r"}},
		{"long lines are cut", func(l *slog.Logger) { l.Info(strings.Repeat("x", 5000)) }, strings.Repeat("x", logRecordMax) + "…", nil},
		{"successful requests are not kept", func(l *slog.Logger) { l.Info("http request", "status", 200) }, "", nil},
		{"failed requests are", func(l *slog.Logger) { l.Warn("http request", "status", 500) }, "http request status=500", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			log, ring, _ := newRingLogger(10, slog.LevelDebug)
			tc.log(log)
			got := ring.Records()
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("kept %+v", got)
				}
				return
			}
			if len(got) != 1 || got[0].Text != tc.want {
				t.Fatalf("records = %+v, want %q", got, tc.want)
			}
			for _, bad := range tc.lack {
				if strings.Contains(got[0].Text, bad) {
					t.Errorf("text %q contains %q", got[0].Text, bad)
				}
			}
		})
	}
}

func TestLogRingConcurrent(t *testing.T) {
	log, ring, _ := newRingLogger(50, slog.LevelInfo)
	done := make(chan struct{})
	for g := 0; g < 4; g++ {
		go func() {
			for i := 0; i < 200; i++ {
				log.Info("x", "i", i)
				_ = ring.Records()
			}
			done <- struct{}{}
		}()
	}
	for g := 0; g < 4; g++ {
		<-done
	}
	if n := len(ring.Records()); n != 50 {
		t.Errorf("%d records, want 50", n)
	}
}
