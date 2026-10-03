package httpserver

import (
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/phabioo/nexara/internal/hub/update"
)

// bodyReadTimeout bounds how long a client may take to deliver a request
// body (security review S-02). The server has ReadHeaderTimeout but, by
// design, no ReadTimeout (streams live for hours), so without this a client
// could announce a body and then send nothing, holding the connection and its
// goroutine forever, before any authentication.
const bodyReadTimeout = 30 * time.Second

// uploadTimeoutFactor stretches the body deadline of the update upload: a release package is tens of megabytes
// and may come over WiFi.
const uploadTimeoutFactor = 20

// bodyCap is the largest request body a path accepts. Only the update upload takes a release package
// (view_settings_updates.go); the Settings handler sets the same cap itself, the CSRF middleware needs this one
// because it wraps the body before the handler runs.
func bodyCap(p string) int64 {
	if p == uploadPathUpdate {
		return update.MaxBundleBytes
	}
	return maxFormBody
}

// bodyDeadline is how long a client may take to deliver the body of a request to path p.
func (s *Server) bodyDeadline(p string) time.Duration {
	if p == uploadPathUpdate {
		return s.bodyTimeout * uploadTimeoutFactor
	}
	return s.bodyTimeout
}

// exemptFromBodyLimits reports the long-lived paths: the SSE stream, the shell
// WebSocket and the agent endpoints (WebSocket connection and its mTLS
// helpers). A read deadline on those would end the connection, because
// net/http cancels a request whose background read times out.
//
// The setup restore upload is exempt as well: it is a backup file of hundreds
// of megabytes at most, which neither fits maxFormBody nor the fixed deadline.
// Its handler sits behind the setup session, applies its own size cap and a
// rolling idle timeout, and checks the CSRF token before reading the file.
func exemptFromBodyLimits(p string) bool {
	return p == "/events" || strings.HasPrefix(p, "/events/") || strings.HasSuffix(p, "/shell/ws") ||
		p == "/grid/connect" || strings.HasPrefix(p, "/grid/agent/") ||
		isRestoreUpload(p)
}

// bodyLimits gives every request that has a body a read deadline and a size
// cap. The deadline starts when the handler chain starts (after the headers)
// and is lifted again when the body has been read completely or failed, so
// a slow handler or a long response is not cut short. Requests without a
// body are not touched.
func (s *Server) bodyLimits(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if exemptFromBodyLimits(r.URL.Path) || r.Body == nil || r.Body == http.NoBody {
			next.ServeHTTP(w, r)
			return
		}
		body := r.Body
		rc := http.NewResponseController(w)
		if err := rc.SetReadDeadline(time.Now().Add(s.bodyDeadline(r.URL.Path))); err == nil {
			body = &deadlineBody{ReadCloser: body, rc: rc}
		}
		r.Body = http.MaxBytesReader(w, body, bodyCap(r.URL.Path))
		next.ServeHTTP(w, r)
	})
}

// deadlineBody lifts the connection's read deadline once the body has been
// read completely, so the rest of the exchange (and the server's background
// read, which detects a client that went away) is not subject to it. A failed
// read leaves the deadline in place on purpose: net/http reads the rest of an
// unconsumed body before it replies, and that must fail at once instead of
// waiting for the stalled client again.
type deadlineBody struct {
	io.ReadCloser
	rc   *http.ResponseController
	done bool
}

func (b *deadlineBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF && !b.done {
		b.done = true
		_ = b.rc.SetReadDeadline(time.Time{})
	}
	return n, err
}
