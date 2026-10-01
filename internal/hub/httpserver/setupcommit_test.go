package httpserver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/phabioo/nexara/internal/hub/setup"
)

// finishWizard walks a setup session through every step.
func finishWizard(t *testing.T, sess *setup.Session) {
	t.Helper()
	w := sess.Wizard
	steps := []error{
		w.SubmitTrust(),
		w.SubmitOperator(setup.OperatorInput{ID: "Frank", Passphrase: "correct horse battery staple", Confirm: "correct horse battery staple"}),
		w.SubmitTwoFactor(true, ""),
		w.SubmitHub(setup.HubInput{Name: "frpi5", TimeZone: "Europe/Berlin", AgentHost: "frpi5.local", HTTPSPort: 8443, RetentionDays: 365}),
		w.SubmitSelfLink(setup.SelfLinkInput{Enabled: true, Capabilities: []string{"monitoring", "shell"}}),
	}
	for i, err := range steps {
		if err != nil {
			t.Fatalf("wizard step %d: %v", i, err)
		}
	}
}

func TestCommitSetup(t *testing.T) {
	type call struct {
		res setup.Result
		ip  string
	}
	newServer := func(t *testing.T, commit SetupCommitFunc) (*env, *http.Cookie) {
		t.Helper()
		e := newEnv(t)
		e.srv.setup.Commit = commit
		token, sess, err := e.srv.setup.Sessions.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		finishWizard(t, sess)
		return e, &http.Cookie{Name: setup.SessionCookie, Value: token}
	}
	request := func(e *env, c *http.Cookie) (*httptest.ResponseRecorder, SetupOutcome, error) {
		r := httptest.NewRequest(http.MethodPost, "/setup/ready", nil)
		r.RemoteAddr = testPeerAddr
		if c != nil {
			r.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		out, err := e.srv.commitSetup(rec, r)
		return rec, out, err
	}

	t.Run("success passes the result and clears the setup cookie", func(t *testing.T) {
		var got call
		e, cookie := newServer(t, func(_ context.Context, res setup.Result, ip string) (SetupOutcome, error) {
			got = call{res, ip}
			return SetupOutcome{OperatorID: res.OperatorID, SelfLink: true, Warnings: []string{"w"}}, nil
		})
		rec, out, err := request(e, cookie)
		if err != nil {
			t.Fatal(err)
		}
		if got.ip != "192.0.2.10" || got.res.OperatorID != "frank" || got.res.Hub.Name != "frpi5" ||
			!got.res.SelfLink.Enabled || len(got.res.SelfLink.Capabilities) != 2 {
			t.Errorf("hook got %+v", got)
		}
		if out.OperatorID != "frank" || !out.SelfLink || len(out.Warnings) != 1 {
			t.Errorf("outcome = %+v", out)
		}
		c := findCookie(rec, setup.SessionCookie)
		if c == nil || c.MaxAge >= 0 {
			t.Errorf("setup cookie not cleared: %+v", c)
		}
	})

	t.Run("hook errors pass through and keep the cookie", func(t *testing.T) {
		for _, hookErr := range []error{
			ErrSetupDone,
			setup.ValidationError{"hub": "bad"},
			errors.New("disk full"),
		} {
			e, cookie := newServer(t, func(context.Context, setup.Result, string) (SetupOutcome, error) {
				return SetupOutcome{}, hookErr
			})
			rec, _, err := request(e, cookie)
			if err == nil || err.Error() != hookErr.Error() {
				t.Errorf("err = %v, want %v", err, hookErr)
			}
			if findCookie(rec, setup.SessionCookie) != nil {
				t.Errorf("%v: cookie touched although the commit failed", hookErr)
			}
		}
	})

	t.Run("no session", func(t *testing.T) {
		called := false
		e, _ := newServer(t, func(context.Context, setup.Result, string) (SetupOutcome, error) {
			called = true
			return SetupOutcome{}, nil
		})
		for name, c := range map[string]*http.Cookie{
			"no cookie":     nil,
			"unknown token": {Name: setup.SessionCookie, Value: "nope"},
		} {
			if _, _, err := request(e, c); !errors.Is(err, ErrNoSetupSession) {
				t.Errorf("%s: err = %v, want ErrNoSetupSession", name, err)
			}
		}
		if called {
			t.Error("hook called without a session")
		}
	})

	t.Run("wizard not complete", func(t *testing.T) {
		called := false
		e := newEnv(t)
		e.srv.setup.Commit = func(context.Context, setup.Result, string) (SetupOutcome, error) {
			called = true
			return SetupOutcome{}, nil
		}
		token, _, err := e.srv.setup.Sessions.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = request(e, &http.Cookie{Name: setup.SessionCookie, Value: token})
		if !errors.Is(err, setup.ErrNotReady) || called {
			t.Errorf("err = %v, called = %v", err, called)
		}
	})

	t.Run("no hook configured", func(t *testing.T) {
		e, cookie := newServer(t, nil)
		if _, _, err := request(e, cookie); !errors.Is(err, ErrSetupUnavailable) {
			t.Errorf("err = %v, want ErrSetupUnavailable", err)
		}
	})
}
