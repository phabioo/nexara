// Package shell defines the agent's Nexara Shell capability: an interactive
// PTY session running as the enrolled user (never root).
package shell

import "io"

// Session is one running interactive shell. Read returns terminal output and
// io.EOF once the shell process has exited; Write sends keyboard input; Close
// terminates the shell and releases the PTY.
type Session interface {
	io.ReadWriteCloser
	// Resize sets the PTY window size.
	Resize(cols, rows int) error
}

// Spawner starts shell sessions.
type Spawner interface {
	// Open starts a login shell for the configured user (agent.yaml shell.user)
	// on a new PTY of the given size.
	Open(cols, rows int) (Session, error)
}
