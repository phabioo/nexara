package setup

import (
	"context"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/buildinfo"
)

func TestAdminVersionIsReadOnlyAndNeedsNoHandler(t *testing.T) {
	old := buildinfo.Version
	buildinfo.Version = "9.8.7"
	t.Cleanup(func() { buildinfo.Version = old })

	// No handler is wired: version must still answer (the update helper polls
	// it right after a restart), and must not touch any of the handlers.
	touched := false
	h := AdminHandlers{
		SetupCode:   func(context.Context) (string, time.Time, error) { touched = true; return "", time.Time{}, nil },
		UserReset:   func(context.Context) (string, error) { touched = true; return "", nil },
		LoginUnlock: func(context.Context) (string, error) { touched = true; return "", nil },
	}
	for _, hh := range []AdminHandlers{{}, h} {
		resp := hh.dispatch(context.Background(), CmdVersion)
		if !resp.OK || resp.Version != "9.8.7" || resp.Message == "" || resp.Code != "" {
			t.Fatalf("response = %+v", resp)
		}
	}
	if touched {
		t.Fatal("version called a mutating handler")
	}
}
