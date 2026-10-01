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
	"github.com/phabioo/nexara/internal/hub/store"
)

// DefaultAdminSocket is where the running hub listens for `nexus setup code`,
// `nexus user reset` and `nexus user unlock` (decision #35). The systemd unit
// provides /run/nexus through RuntimeDirectory=nexus.
//
// Ownership: decision #35 says root:nexus, but the hub runs as the unprivileged
// nexus user and creates the socket itself, so it is owned nexus:nexus with
// mode 0660 and /run/nexus is 0750 (RuntimeDirectoryMode). root reaches it
// regardless of the mode; other users are kept out by the directory. Access
// control is therefore "root or the nexus user", the same people as decided.
const DefaultAdminSocket = "/run/nexus/admin.sock"

// Audit actions of the admin socket commands.
const (
	ActionAdminSetupCode   = "admin.setup_code"
	ActionAdminUserReset   = "admin.user_reset"
	ActionAdminLoginUnlock = "admin.login_unlock"

	// adminActor is the audit user of commands that arrive on the local socket.
	adminActor = "local-admin"
)

// loginLimits clears the login rate limiters; *auth.Service provides it.
type loginLimits interface{ ClearLoginLimits() }

// adminBackend is what the admin commands operate on.
type adminBackend struct {
	codes    *setup.Codes
	mode     *setup.Mode
	sessions *setup.Sessions
	auth     *auth.Service
	limits   loginLimits // nil when the auth service has no ClearLoginLimits
	audit    func(ctx context.Context, e store.AuditEntry)
	now      func() time.Time
}

// record writes an audit entry for an admin command (no-op without a writer).
func (b adminBackend) record(ctx context.Context, action, detail string, err error) {
	if b.audit == nil {
		return
	}
	res := store.AuditOK
	if err != nil {
		res = store.AuditError
	}
	b.audit(ctx, store.AuditEntry{User: adminActor, Action: action, Detail: detail, Result: res})
}

// handlers returns the admin socket handlers.
func (b adminBackend) handlers() setup.AdminHandlers {
	return setup.AdminHandlers{
		SetupCode:   b.setupCode,
		UserReset:   b.userReset,
		LoginUnlock: b.loginUnlock,
	}
}

// setupCode rotates the setup code. It only makes sense while the hub is in
// setup mode; with an operator present the code would unlock nothing.
func (b adminBackend) setupCode(ctx context.Context) (string, time.Time, error) {
	if !b.mode.Active(ctx) {
		err := errors.New("an operator account already exists, so there is no setup code; run `sudo nexus user reset` to start over")
		b.record(ctx, ActionAdminSetupCode, "refused: operator exists", err)
		return "", time.Time{}, err
	}
	code, exp, err := b.codes.Rotate()
	b.record(ctx, ActionAdminSetupCode, "new code issued", err)
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
		b.record(ctx, ActionAdminUserReset, "reset failed", err)
		return "", err
	}
	b.record(ctx, ActionAdminUserReset, fmt.Sprintf("removed %d operator(s)", n), nil)
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

// loginUnlock clears the login rate limits (locked-out accounts and IPs), for
// an operator who locked themselves out.
func (b adminBackend) loginUnlock(ctx context.Context) (string, error) {
	if b.limits == nil {
		err := errors.New("login limits cannot be cleared by this hub build")
		b.record(ctx, ActionAdminLoginUnlock, "unavailable", err)
		return "", err
	}
	b.limits.ClearLoginLimits()
	b.record(ctx, ActionAdminLoginUnlock, "login rate limits cleared", nil)
	return "Login rate limits cleared: locked accounts and addresses can try again.", nil
}

// CallAdmin sends one admin command (setup.CmdSetupCode, setup.CmdUserReset, setup.CmdLoginUnlock)
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
