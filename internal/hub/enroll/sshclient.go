package enroll

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/phabioo/nexara/internal/hub/grid"
)

// SSHDialer opens SSH connections. The real implementation uses
// golang.org/x/crypto/ssh; tests inject a fake.
type SSHDialer interface {
	// Probe is phase 1 of the link: connect, receive the host key and stop.
	// No authentication is attempted, so no credential can leak to an
	// unconfirmed host.
	Probe(ctx context.Context, addr string, timeout time.Duration) (grid.HostKeyInfo, error)
	// Dial connects and authenticates. It refuses any host key other than
	// cfg.HostKeySHA256 before a credential is sent (grid.ErrHostKeyMismatch).
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
	// HostKeySHA256 is the only host key ("SHA256:...") the dialer accepts.
	HostKeySHA256 string
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

// hostKeyAlgorithms is the fixed preference list of both phases. ed25519 comes
// first so the fingerprint shown to the operator is the one of
// /etc/ssh/ssh_host_ed25519_key.pub whenever the host has such a key; using the
// same list in probe and dial keeps the negotiated key type stable.
var hostKeyAlgorithms = []string{
	ssh.KeyAlgoED25519,
	ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256,
}

// errProbeDone aborts the handshake right after the host key was received.
var errProbeDone = errors.New("enroll: probe done")

var fingerprintRE = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)

func (realDialer) Probe(ctx context.Context, addr string, timeout time.Duration) (grid.HostKeyInfo, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	var got grid.HostKeyInfo
	sc := &ssh.ClientConfig{
		User:              "nexus-probe",
		HostKeyAlgorithms: hostKeyAlgorithms,
		// No Auth methods: the callback runs during key exchange, before the
		// client could authenticate, and ends the handshake.
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			got = grid.HostKeyInfo{Type: key.Type(), SHA256: ssh.FingerprintSHA256(key)}
			return errProbeDone
		},
		Timeout: timeout,
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(dctx, "tcp", addr)
	if err != nil {
		return grid.HostKeyInfo{}, err
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(timeout))
	// Closing the connection on cancellation unblocks a stuck handshake.
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()
	c, _, _, err := ssh.NewClientConn(raw, addr, sc)
	if err == nil { // cannot happen without Auth, but never leak a session
		_ = c.Close()
		return grid.HostKeyInfo{}, errors.New("enroll: unexpected SSH session during probe")
	}
	if got.SHA256 == "" {
		return grid.HostKeyInfo{}, err
	}
	return got, nil
}

func (realDialer) Dial(ctx context.Context, cfg SSHDialConfig) (SSHConn, error) {
	if !fingerprintRE.MatchString(cfg.HostKeySHA256) {
		return nil, errors.New("enroll: no confirmed host key fingerprint")
	}
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
	mismatch := false
	sc := &ssh.ClientConfig{
		User:              cfg.User,
		Auth:              auth,
		HostKeyAlgorithms: hostKeyAlgorithms,
		// Only the fingerprint the operator confirmed is accepted (decision
		// #41). The callback runs during key exchange, before any credential
		// is sent, so a changed key never sees the password.
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			conn.fingerprint = ssh.FingerprintSHA256(key)
			if subtle.ConstantTimeCompare([]byte(conn.fingerprint), []byte(cfg.HostKeySHA256)) != 1 {
				mismatch = true
				return grid.ErrHostKeyMismatch
			}
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
		if mismatch {
			return nil, grid.ErrHostKeyMismatch
		}
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
