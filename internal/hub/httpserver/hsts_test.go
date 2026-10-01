package httpserver

import (
	"crypto/tls"
	"net/http"
	"testing"
)

// S-11: HSTS on TLS responses only.
func TestStrictTransportSecurity(t *testing.T) {
	e := newEnv(t)
	cookie, _ := e.signIn()
	const want = "max-age=15552000"
	tests := []struct {
		name, method, path string
		tls                bool
		opts               []reqOpt
		want               string
	}{
		{"login page over TLS", "GET", "/login", true, nil, want},
		{"redirect over TLS", "GET", "/", true, nil, want},
		{"signed-in page over TLS", "GET", "/events/ping", true, []reqOpt{withCookies(cookie)}, want},
		{"static over TLS", "GET", "/static/css/a.css", true, nil, want},
		{"not found over TLS", "GET", "/nope", true, []reqOpt{withCookies(cookie)}, want},
		{"csrf rejection over TLS", "POST", "/logout", true, []reqOpt{withCookies(cookie)}, want},
		{"agent endpoint over TLS", "GET", "/grid/connect", true, nil, want},
		{"login page over plain HTTP", "GET", "/login", false, nil, ""},
		{"static over plain HTTP", "GET", "/static/css/a.css", false, nil, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := tc.opts
			if tc.tls {
				opts = append([]reqOpt{func(r *http.Request) { r.TLS = &tls.ConnectionState{} }}, opts...)
			}
			rec := e.do(e.srv.Handler(), tc.method, tc.path, opts...)
			if got := rec.Header().Get("Strict-Transport-Security"); got != tc.want {
				t.Errorf("Strict-Transport-Security = %q, want %q", got, tc.want)
			}
		})
	}
}
