package httpserver

import (
	"context"
	"errors"
	"net/http"

	"github.com/phabioo/nexara/internal/hub/setup"
)

// Errors of the setup commit. Match with errors.Is / errors.As.
var (
	// ErrSetupDone means an operator already exists (another browser finished
	// the wizard first). The view should redirect to /login.
	ErrSetupDone = errors.New("httpserver: setup is already complete")
	// ErrNoSetupSession means the request carries no valid setup session
	// (expired after 30 minutes idle, or never unlocked). The view should send
	// the browser back to the Unlock step.
	ErrNoSetupSession = errors.New("httpserver: no active setup session")
	// ErrSetupUnavailable means the server was built without a commit hook
	// (tests only).
	ErrSetupUnavailable = errors.New("httpserver: setup commit is not configured")
)

// SetupOutcome is what a successful commit reports.
type SetupOutcome struct {
	// OperatorID is the created operator (lower case).
	OperatorID string
	// SelfLink is true when the token for the hub's own Grid Agent was written.
	SelfLink bool
	// Warnings are non-fatal problems that happened after the operator was
	// created (for example "the self-link token could not be written"). The
	// hub is open for sign-in regardless; show them on the Ready page or as a
	// toast after the redirect. Texts are safe to display (no secrets).
	Warnings []string
}

// SetupCommitFunc persists a completed wizard. It is implemented by the
// wiring (package app) and reached through Server.commitSetup.
//
// Contract (for the Setup view):
//
//   - Call it once, from the POST of the final "Ready" step, with
//     Wizard.Result() of the request's setup session and the client IP (for the
//     audit entry). Use Server.commitSetup, which does exactly that.
//   - Before it returns successfully it has: created the operator (argon2id
//     hash, TOTP secret sealed when 2FA was set up), written the Hub step's
//     settings into nexus.yaml (name, time zone, agent address, history
//     retention), prepared the self-link token when chosen, written an audit
//     entry ("setup.commit"), and invalidated the setup code, the setup
//     session and the cached setup mode. The hub then serves the normal,
//     authenticated UI and opens the agent endpoint.
//   - On success the wizard is gone: do not render wizard state afterwards.
//     Redirect to /login (303); the operator signs in with the new account.
//   - On error nothing was created or changed visibly, and the wizard can be
//     resubmitted. A setup.ValidationError carries field messages to show on
//     the Ready step; ErrSetupDone means an operator exists (redirect to
//     /login); any other error is an internal failure (log it, answer 500).
//   - Warnings in the outcome are not errors: the operator exists.
type SetupCommitFunc func(ctx context.Context, res setup.Result, clientIP string) (SetupOutcome, error)

// commitSetup finishes the wizard of the request's setup session: it reads
// the collected Result, calls the commit hook and, on success, expires the
// setup cookie. Errors: ErrNoSetupSession, setup.ErrNotReady (wizard not
// complete), ErrSetupUnavailable, or whatever the hook returns (see
// SetupCommitFunc).
func (s *Server) commitSetup(w http.ResponseWriter, r *http.Request) (SetupOutcome, error) {
	if s.setup.Commit == nil {
		return SetupOutcome{}, ErrSetupUnavailable
	}
	sess, ok := s.setup.Sessions.FromRequest(r)
	if !ok {
		return SetupOutcome{}, ErrNoSetupSession
	}
	res, err := sess.Wizard.Result()
	if err != nil {
		return SetupOutcome{}, err
	}
	out, err := s.setup.Commit(r.Context(), res, ClientIP(r))
	if err != nil {
		return SetupOutcome{}, err
	}
	http.SetCookie(w, s.setup.Sessions.ClearCookie())
	return out, nil
}
