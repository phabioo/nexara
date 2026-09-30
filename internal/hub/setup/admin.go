package setup

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

// Admin commands (decision #35).
const (
	CmdSetupCode = "setup-code"
	CmdUserReset = "user-reset"
)

const (
	adminMaxRequest  = 4 << 10
	adminMaxResponse = 64 << 10
	adminDeadline    = 10 * time.Second
)

// AdminRequest is one newline-delimited JSON request.
type AdminRequest struct {
	Cmd string `json:"cmd"`
}

// AdminResponse is one newline-delimited JSON response. Code and Expires are
// set for setup-code only.
type AdminResponse struct {
	OK      bool       `json:"ok"`
	Message string     `json:"message"`
	Code    string     `json:"code,omitempty"`
	Expires *time.Time `json:"expires,omitempty"`
}

// AdminHandlers implement the admin commands; the caller wires them to Codes
// and the auth/store layers.
type AdminHandlers struct {
	// SetupCode rotates the setup code and returns the new one (formatted
	// XXXX-XXXX) and its expiry.
	SetupCode func(ctx context.Context) (code string, expires time.Time, err error)
	// UserReset resets the operator account and returns a message for the CLI.
	UserReset func(ctx context.Context) (message string, err error)
}

func (h AdminHandlers) dispatch(ctx context.Context, cmd string) AdminResponse {
	switch cmd {
	case CmdSetupCode:
		if h.SetupCode == nil {
			return AdminResponse{Message: "setup-code is not available"}
		}
		code, exp, err := h.SetupCode(ctx)
		if err != nil {
			return AdminResponse{Message: err.Error()}
		}
		return AdminResponse{OK: true, Code: code, Expires: &exp,
			Message: fmt.Sprintf("New setup code: %s (valid until %s)", code, exp.Local().Format("15:04"))}
	case CmdUserReset:
		if h.UserReset == nil {
			return AdminResponse{Message: "user-reset is not available"}
		}
		msg, err := h.UserReset(ctx)
		if err != nil {
			return AdminResponse{Message: err.Error()}
		}
		return AdminResponse{OK: true, Message: msg}
	default:
		return AdminResponse{Message: "unknown command"}
	}
}

// ServeAdmin serves the admin socket at path until ctx is done. A stale socket
// file is removed first; on Linux the socket gets mode 0660 (group access is
// arranged by the service's user and umask).
func ServeAdmin(ctx context.Context, path string, h AdminHandlers) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("setup: remove stale admin socket: %w", err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("setup: listen admin socket: %w", err)
	}
	if err := chmodSocket(path); err != nil {
		ln.Close()
		return fmt.Errorf("setup: chmod admin socket: %w", err)
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("setup: accept admin connection: %w", err)
		}
		go serveAdminConn(ctx, conn, h)
	}
}

func serveAdminConn(ctx context.Context, conn net.Conn, h AdminHandlers) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(adminDeadline))
	line, err := bufio.NewReader(io.LimitReader(conn, adminMaxRequest)).ReadBytes('\n')
	var resp AdminResponse
	var req AdminRequest
	switch {
	case err != nil && len(line) == 0:
		resp = AdminResponse{Message: "bad request"}
	case json.Unmarshal(line, &req) != nil:
		resp = AdminResponse{Message: "bad request"}
	default:
		resp = h.dispatch(ctx, req.Cmd)
	}
	b, _ := json.Marshal(resp)
	conn.Write(append(b, '\n'))
}

// AdminCall sends one command to the admin socket and returns the response.
func AdminCall(path, cmd string) (AdminResponse, error) {
	conn, err := net.DialTimeout("unix", path, 5*time.Second)
	if err != nil {
		return AdminResponse{}, fmt.Errorf("connect to nexus admin socket: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(adminDeadline))
	b, _ := json.Marshal(AdminRequest{Cmd: cmd})
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return AdminResponse{}, err
	}
	line, err := bufio.NewReader(io.LimitReader(conn, adminMaxResponse)).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return AdminResponse{}, fmt.Errorf("read admin response: %w", err)
	}
	var resp AdminResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		return AdminResponse{}, fmt.Errorf("decode admin response: %w", err)
	}
	return resp, nil
}
