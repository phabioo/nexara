package auth

import "testing"

// S-17
func TestCookieName(t *testing.T) {
	tests := []struct {
		base   string
		secure bool
		want   string
	}{
		{SessionCookieName, true, "__Host-nexus_session"},
		{SessionCookieName, false, "nexus_session"},
		{CSRFCookieName, true, "__Host-nexus_csrf"},
		{CSRFCookieName, false, "nexus_csrf"},
		{"nexus_login", true, "__Host-nexus_login"},
	}
	for _, tc := range tests {
		if got := CookieName(tc.base, tc.secure); got != tc.want {
			t.Errorf("CookieName(%q, %v) = %q, want %q", tc.base, tc.secure, got, tc.want)
		}
	}
	if c := NewCookies(); c.SessionName() != "__Host-nexus_session" || c.CSRFName() != "__Host-nexus_csrf" || !c.Secure() {
		t.Errorf("default builder names: %q %q", c.SessionName(), c.CSRFName())
	}
	if c := NewCookies(WithSecure(false)); c.SessionName() != "nexus_session" || c.CSRFName() != "nexus_csrf" || c.Secure() {
		t.Errorf("plain builder names: %q %q", c.SessionName(), c.CSRFName())
	}
}

// A __Host- cookie is only accepted with Path=/ , Secure and no Domain.
func TestHostPrefixedCookiesMeetBrowserRules(t *testing.T) {
	e := newEnv(t)
	u := e.addUser("alice", testPass)
	raw, sess, _ := e.svc.Sessions().Create(e.ctx, u, true, testIP, testUA)
	cs := e.svc.Cookies()
	for name, ck := range map[string]struct {
		n, path, domain string
		secure          bool
	}{
		"session":       {cs.Session(raw, sess).Name, cs.Session(raw, sess).Path, cs.Session(raw, sess).Domain, cs.Session(raw, sess).Secure},
		"clear session": {cs.ClearSession().Name, cs.ClearSession().Path, cs.ClearSession().Domain, cs.ClearSession().Secure},
		"csrf":          {cs.CSRF("t").Name, cs.CSRF("t").Path, cs.CSRF("t").Domain, cs.CSRF("t").Secure},
		"clear csrf":    {cs.ClearCSRF().Name, cs.ClearCSRF().Path, cs.ClearCSRF().Domain, cs.ClearCSRF().Secure},
	} {
		if ck.n[:7] != "__Host-" || ck.path != "/" || ck.domain != "" || !ck.secure {
			t.Errorf("%s: %+v violates the __Host- rules", name, ck)
		}
	}
}
