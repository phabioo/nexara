package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"syscall"
	"time"

	"github.com/phabioo/nexara/internal/hub/auth"
	"github.com/phabioo/nexara/internal/hub/setup"
)

// DefaultAdminSocket is where the running hub listens for `nexus setup code`
// and `nexus user reset` (decision #35). The systemd unit provides
// /run/nexus through RuntimeDirectory=nexus.
const DefaultAdminSocket = "/run/nexus/admin.sock"

// adminBackend is what the admin commands operate on.
type adminBackend struct {
	codes    *setup.Codes
	mode     *setup.Mode
	sessions *setup.Sessions
	auth     *auth.Service
	now      func() time.Time
}

// handlers returns the admin socket handlers.
func (b adminBackend) handlers() setup.AdminHandlers {
	return setup.AdminHandlers{
		SetupCode: b.setupCode,
		UserReset: b.userReset,
	}
}

// setupCode rotates the setup code. It only makes sense while the hub is in
// setup mode; with an operator present the code would unlock nothing.
func (b adminBackend) setupCode(ctx context.Context) (string, time.Time, error) {
	if !b.mode.Active(ctx) {
		return "", time.Time{}, errors.New("an operator account already exists, so there is no setup code; run `sudo nexus user reset` to start over")
	}
	code, exp, err := b.codes.Rotate()
	if err != nil {
		return "", time.Time{}, err
	}
	return setup.FormatCode(code), exp, nil
}

// userReset deletes the operator accounts, which returns the hub to setup
// mode, and issues a fresh setup code so the operator can start the wizard.
func (b adminBackend) userReset(ctx context.Context) (string, error) {
	n, err := b.auth.ResetOperators(ctx)
	if err != nil {
		return "", err
	}
	b.mode.Invalidate()
	b.sessions.Clear()
	code, exp, err := b.codes.Rotate()
	if err != nil {
		return "", fmt.Errorf("operators were removed, but creating a setup code failed: %w", err)
	}
	what := fmt.Sprintf("Removed %d operator account(s).", n)
	if n == 0 {
		what = "There was no operator account."
	}
	return fmt.Sprintf("%s The hub is in setup mode again. Setup code: %s (valid until %s)",
		what, setup.FormatCode(code), exp.Local().Format("15:04")), nil
}

// CallAdmin sends one admin command (setup.CmdSetupCode, setup.CmdUserReset)
// to the running hub. Connection problems come back as messages that say what
// to do; a refusal by the hub is returned as an error carrying its message.
func CallAdmin(socket, cmd string) (setup.AdminResponse, error) {
	resp, err := setup.AdminCall(socket, cmd)
	if err != nil {
		return setup.AdminResponse{}, adminConnError(socket, err)
	}
	if !resp.OK {
		msg := resp.Message
		if msg == "" {
			msg = "the hub refused the command"
		}
		return resp, errors.New(msg)
	}
	return resp, nil
}

// adminConnError translates low-level socket errors.
func adminConnError(socket string, err error) error {
	switch {
	case errors.Is(err, fs.ErrPermission):
		return fmt.Errorf("permission denied on %s: run this command with sudo", socket)
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("the nexus admin socket %s does not exist: is the nexus service running? (sudo systemctl status nexus)", socket)
	case errors.Is(err, syscall.ECONNREFUSED):
		return fmt.Errorf("nothing is listening on %s: the nexus service is not running (sudo systemctl status nexus)", socket)
	}
	return fmt.Errorf("cannot talk to the nexus service on %s: %w", socket, err)
}
