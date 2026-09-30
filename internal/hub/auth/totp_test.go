package auth

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func generateTestCode(secret string, at time.Time) (string, error) {
	return totp.GenerateCodeCustom(secret, at, totpOpts())
}

// wrongCode returns a six-digit code that is invalid for secret at now (and
// its skew window), so tests never collide with a real code by chance.
func wrongCode(secret string, now time.Time) string {
	for i := 0; ; i++ {
		c := fmt.Sprintf("%06d", i)
		if _, ok := MatchTOTP(secret, c, now); !ok {
			return c
		}
	}
}

func TestNewTOTP(t *testing.T) {
	enr, err := NewTOTP("alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(enr.Secret) < 32 {
		t.Fatalf("secret too short: %q", enr.Secret)
	}
	u, err := url.Parse(enr.URL)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "otpauth" || u.Host != "totp" {
		t.Fatalf("bad URL %q", enr.URL)
	}
	q := u.Query()
	if q.Get("issuer") != "Nexara Nexus" || q.Get("secret") != enr.Secret || q.Get("digits") != "6" || q.Get("period") != "30" {
		t.Fatalf("bad query in %q", enr.URL)
	}
	if !strings.Contains(u.Path, "alice") {
		t.Fatalf("account missing in %q", u.Path)
	}
	other, _ := NewTOTP("alice")
	if other.Secret == enr.Secret {
		t.Fatal("secrets must be random")
	}
}

func TestMatchTOTP(t *testing.T) {
	enr, _ := NewTOTP("alice")
	now := time.Date(2026, 3, 1, 12, 0, 10, 0, time.UTC)
	cur := now.Unix() / 30
	at := func(step int64) string { return codeAt(t, enr.Secret, time.Unix(step*30, 0)) }

	tests := []struct {
		name string
		code string
		ok   bool
		step int64
	}{
		{"current", at(cur), true, cur},
		{"previous step", at(cur - 1), true, cur - 1},
		{"next step", at(cur + 1), true, cur + 1},
		{"two steps back", at(cur - 2), false, 0},
		{"two steps ahead", at(cur + 2), false, 0},
		{"with space", at(cur)[:3] + " " + at(cur)[3:], true, cur},
		{"with dash", at(cur)[:3] + "-" + at(cur)[3:], true, cur},
		{"five digits", at(cur)[:5], false, 0},
		{"seven digits", at(cur) + "1", false, 0},
		{"letters", "abcdef", false, 0},
		{"empty", "", false, 0},
		{"wrong", wrongCode(enr.Secret, now), false, 0},
	}
	for _, tc := range tests {
		step, ok := MatchTOTP(enr.Secret, tc.code, now)
		if ok != tc.ok || (ok && step != tc.step) {
			t.Errorf("%s: MatchTOTP = %d, %v; want %d, %v", tc.name, step, ok, tc.step, tc.ok)
		}
	}
	if _, ok := MatchTOTP("not base32!!", at(cur), now); ok {
		t.Error("invalid secret must not verify")
	}
}

func TestTOTPVerifierReplay(t *testing.T) {
	enr, _ := NewTOTP("alice")
	now := time.Date(2026, 3, 1, 12, 0, 10, 0, time.UTC)
	cur := now.Unix() / 30
	at := func(step int64) string { return codeAt(t, enr.Secret, time.Unix(step*30, 0)) }

	v := NewTOTPVerifier()
	if !v.VerifyTOTP(1, enr.Secret, at(cur), now) {
		t.Fatal("first use must succeed")
	}
	if v.VerifyTOTP(1, enr.Secret, at(cur), now) {
		t.Fatal("replay of the same code must fail")
	}
	if v.VerifyTOTP(1, enr.Secret, at(cur-1), now) {
		t.Fatal("an older step than the last accepted must fail")
	}
	if !v.VerifyTOTP(2, enr.Secret, at(cur), now) {
		t.Fatal("replay state is per user")
	}
	if !v.VerifyTOTP(1, enr.Secret, at(cur+1), now) {
		t.Fatal("a newer step is fine")
	}
	if v.VerifyTOTP(1, enr.Secret, wrongCode(enr.Secret, now), now) {
		t.Fatal("wrong code must fail")
	}
	v.Forget(1)
	if !v.VerifyTOTP(1, enr.Secret, at(cur), now) {
		t.Fatal("after Forget the user starts fresh")
	}
	v.Reset()
	if !v.VerifyTOTP(1, enr.Secret, at(cur), now) {
		t.Fatal("after Reset everyone starts fresh")
	}
}

func TestTOTPVerifierWrongCodeDoesNotBurnStep(t *testing.T) {
	enr, _ := NewTOTP("alice")
	now := time.Date(2026, 3, 1, 12, 0, 10, 0, time.UTC)
	v := NewTOTPVerifier()
	_ = v.VerifyTOTP(1, enr.Secret, "12345", now)
	if !v.VerifyTOTP(1, enr.Secret, codeAt(t, enr.Secret, now), now) {
		t.Fatal("a failed attempt must not consume the step")
	}
}
