package enroll

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHDialer opens SSH connections. The real implementation uses
// golang.org/x/crypto/ssh; tests inject a fake.
type SSHDialer interface {
	Dial(ctx context.Context, cfg SSHDialConfig) (SSHConn, error)
}

// SSHConn is one open SSH connection.
type SSHConn interface {
	// HostKeyFingerprint is the server's host key as "SHA256:...".
	HostKeyFingerprint() string
	// Run executes cmd (passed to the remote shell) with stdin and returns the
	// command's stdout. A non-zero exit status is reported as *ExitError that
	// carries stderr. cmd must never contain secrets; pass them through stdin.
	Run(ctx context.Context, cmd string, stdin io.Reader) (stdout []byte, err error)
	Close() error
}

// SSHDialConfig describes one connection. Exactly one of Password and Signer is set.
type SSHDialConfig struct {
	Addr     string // host:port
	User     string
	Password []byte // not retained by the dialer beyond the connection attempt
	Signer   ssh.Signer
	Timeout  time.Duration
}

// ExitError is returned by SSHConn.Run for a command that ran but failed.
type ExitError struct {
	Status int
	Stderr string // trimmed and truncated
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("remote command exited with status %d", e.Status)
}

const maxOutput = 64 << 10

// limitedBuffer keeps at most maxOutput bytes and drops the rest.
type limitedBuffer struct{ bytes.Buffer }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := maxOutput - b.Len(); room > 0 {
		if len(p) > room {
			b.Buffer.Write(p[:room])
		} else {
			b.Buffer.Write(p)
		}
	}
	return len(p), nil
}

type realDialer struct{}

func (realDialer) Dial(ctx context.Context, cfg SSHDialConfig) (SSHConn, error) {
	var auth []ssh.AuthMethod
	switch {
	case cfg.Signer != nil:
		auth = append(auth, ssh.PublicKeys(cfg.Signer))
	case cfg.Password != nil:
		pw := cfg.Password
		auth = append(auth,
			ssh.PasswordCallback(func() (string, error) { return string(pw), nil }),
			ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = string(pw)
				}
				return answers, nil
			}))
	default:
		return nil, errors.New("enroll: no SSH credentials")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	conn := &realConn{}
	sc := &ssh.ClientConfig{
		User: cfg.User,
		Auth: auth,
		// Accepted on first use (decision #41); the fingerprint is shown in the
		// progress list. The connection is used once and then dropped.
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			conn.fingerprint = ssh.FingerprintSHA256(key)
			return nil
		},
		Timeout: timeout,
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(dctx, "tcp", cfg.Addr)
	if err != nil {
		return nil, err
	}
	_ = raw.SetDeadline(time.Now().Add(timeout)) // bounds the handshake
	c, chans, reqs, err := ssh.NewClientConn(raw, cfg.Addr, sc)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	_ = raw.SetDeadline(time.Time{})
	conn.client = ssh.NewClient(c, chans, reqs)
	return conn, nil
}

type realConn struct {
	client      *ssh.Client
	fingerprint string
}

func (c *realConn) HostKeyFingerprint() string { return c.fingerprint }

func (c *realConn) Close() error { return c.client.Close() }

func (c *realConn) Run(ctx context.Context, cmd string, stdin io.Reader) ([]byte, error) {
	sess, err := c.client.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	var stdout, stderr limitedBuffer
	sess.Stdout, sess.Stderr = &stdout, &stderr
	if stdin != nil {
		sess.Stdin = stdin
	}
	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()
	select {
	case <-ctx.Done():
		_ = sess.Close()
		<-done
		return nil, ctx.Err()
	case err := <-done:
		if err != nil {
			var ee *ssh.ExitError
			if errors.As(err, &ee) {
				return stdout.Bytes(), &ExitError{Status: ee.ExitStatus(), Stderr: cleanLine(stderr.String(), 200)}
			}
			return nil, err
		}
		return stdout.Bytes(), nil
	}
}

// cleanLine reduces remote output to one short printable line.
func cleanLine(s string, max int) string {
	s = strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\n' && r != '\t' || r == 0x7f {
			return -1
		}
		return r
	}, s)), " ")
	if len(s) > max {
		s = s[:max]
	}
	return s
}

// hubKey is the hub's own SSH identity (ed25519, <DataDir>/ssh/id_ed25519).
type hubKey struct {
	signer     ssh.Signer
	authorized string // authorized_keys line without trailing newline
}

func loadOrCreateHubKey(dir, hubAddress string) (*hubKey, error) {
	path := filepath.Join(dir, "id_ed25519")
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
	case errors.Is(err, os.ErrNotExist):
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("enroll: create %s: %w", dir, err)
		}
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("enroll: generate SSH key: %w", err)
		}
		blk, err := ssh.MarshalPrivateKey(priv, "nexus@"+hubAddress)
		if err != nil {
			return nil, errors.New("enroll: encode SSH key")
		}
		data = pem.EncodeToMemory(blk)
		if err := writeFileAtomic(path, data, 0o600); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("enroll: read %s: %w", path, err)
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("enroll: parse %s: %w", path, err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))) + " nexus@" + hubAddress
	return &hubKey{signer: signer, authorized: line}, nil
}
