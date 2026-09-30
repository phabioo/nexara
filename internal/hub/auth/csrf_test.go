package auth

import (
	"strings"
	"testing"
)

func TestCSRFSessionBound(t *testing.T) {
	e := newEnv(t)
	u := e.addUser("alice", testPass)
	_, s1, _ := e.svc.Sessions().Create(e.ctx, u, false, testIP, testUA)
	_, s2, _ := e.svc.Sessions().Create(e.ctx, u, false, testIP, testUA)

	tok1 := e.svc.CSRFToken(s1)
	tok2 := e.svc.CSRFToken(s2)
	if tok1 == "" || tok1 == tok2 {
		t.Fatalf("tokens %q %q must be non-empty and session specific", tok1, tok2)
	}
	if tok1 != e.svc.CSRFToken(s1) {
		t.Fatal("token must be stable within a session")
	}
	if strings.ContainsAny(tok1, "+/=") {
		t.Fatalf("token %q is not base64url", tok1)
	}

	cases := []struct {
		name  string
		check bool
	}{
		{"valid", e.svc.CheckCSRF(s1, tok1)},
		{"other session's token", e.svc.CheckCSRF(s1, tok2)},
		{"empty", e.svc.CheckCSRF(s1, "")},
		{"garbage", e.svc.CheckCSRF(s1, "garbage")},
		{"truncated", e.svc.CheckCSRF(s1, tok1[:len(tok1)-1])},
		{"extended", e.svc.CheckCSRF(s1, tok1+"A")},
		{"huge", e.svc.CheckCSRF(s1, strings.Repeat("A", 100000))},
		{"session hash as token", e.svc.CheckCSRF(s1, s1.IDHash)},
	}
	want := map[string]bool{"valid": true}
	for _, c := range cases {
		if c.check != want[c.name] {
			t.Errorf("%s: got %v, want %v", c.name, c.check, want[c.name])
		}
	}

	// A session without an ID hash never validates.
	s1.IDHash = ""
	if e.svc.CheckCSRF(s1, csrfToken(e.key, "")) {
		t.Fatal("empty session must not validate")
	}
}

func TestCSRFDependsOnSecretKey(t *testing.T) {
	a := newEnv(t)
	b := newEnv(t, func(c *Config) { c.SecretKey = append([]byte(nil), c.SecretKey...); c.SecretKey[0] ^= 0xff })
	ua, ub := a.addUser("alice", testPass), b.addUser("alice", testPass)
	_, sa, _ := a.svc.Sessions().Create(a.ctx, ua, false, testIP, testUA)
	_ = ub
	if b.svc.CheckCSRF(sa, a.svc.CSRFToken(sa)) {
		t.Fatal("a token made with another key must not validate")
	}
}

func TestPreSessionCSRF(t *testing.T) {
	tok, err := NewPreSessionCSRF()
	if err != nil || len(tok) != 43 {
		t.Fatalf("%q, %v", tok, err)
	}
	other, _ := NewPreSessionCSRF()
	if tok == other {
		t.Fatal("tokens must be random")
	}
	tests := []struct {
		name, cookie, submitted string
		want                    bool
	}{
		{"match", tok, tok, true},
		{"mismatch", tok, other, false},
		{"missing cookie", "", tok, false},
		{"missing submitted", tok, "", false},
		{"both empty", "", "", false},
		{"oversized", strings.Repeat("a", 1000), strings.Repeat("a", 1000), false},
	}
	for _, tc := range tests {
		if got := CheckDoubleSubmit(tc.cookie, tc.submitted); got != tc.want {
			t.Errorf("%s: got %v", tc.name, got)
		}
	}
	if CSRFHeader != "X-CSRF-Token" {
		t.Fatal("header name changed")
	}
}
