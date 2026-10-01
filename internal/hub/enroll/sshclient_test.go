package enroll

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/phabioo/nexara/internal/hub/grid"
)

// sshTestServer is a minimal SSH server: password "pw" or one authorized key,
// exec requests answered by handler.
type sshTestServer struct {
	addr    string
	hostKey ssh.PublicKey
	// authAttempts counts authentication attempts of any method, "none" included.
	authAttempts atomic.Int32
}

func startSSHServer(t *testing.T, authorized ssh.PublicKey, handler func(cmd string, stdin []byte) (stdout, stderr string, status int)) *sshTestServer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	srv := &sshTestServer{hostKey: hostSigner.PublicKey()}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if c.User() == "pi" && string(pw) == "pw" {
				return nil, nil
			}
			return nil, errors.New("denied")
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if authorized != nil && string(key.Marshal()) == string(authorized.Marshal()) {
				return nil, nil
			}
			return nil, errors.New("denied")
		},
	}
	cfg.AuthLogCallback = func(ssh.ConnMetadata, string, error) { srv.authAttempts.Add(1) }
	cfg.AddHostKey(hostSigner)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSSH(nc, cfg, handler)
		}
	}()
	srv.addr = ln.Addr().String()
	return srv
}

func (s *sshTestServer) fingerprint() string { return ssh.FingerprintSHA256(s.hostKey) }

func serveSSH(nc net.Conn, cfg *ssh.ServerConfig, handler func(string, []byte) (string, string, int)) {
	defer nc.Close()
	conn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nch := range chans {
		if nch.ChannelType() != "session" {
			_ = nch.Reject(ssh.UnknownChannelType, "no")
			continue
		}
		ch, chReqs, err := nch.Accept()
		if err != nil {
			return
		}
		go func() {
			defer ch.Close()
			for req := range chReqs {
				if req.Type != "exec" {
					_ = req.Reply(false, nil)
					continue
				}
				var p struct{ Command string }
				if err := ssh.Unmarshal(req.Payload, &p); err != nil {
					_ = req.Reply(false, nil)
					continue
				}
				_ = req.Reply(true, nil)
				stdin, _ := io.ReadAll(ch)
				out, errOut, status := handler(p.Command, stdin)
				_, _ = io.WriteString(ch, out)
				_, _ = io.WriteString(ch.Stderr(), errOut)
				st := make([]byte, 4)
				binary.BigEndian.PutUint32(st, uint32(status))
				_, _ = ch.SendRequest("exit-status", false, st)
				return
			}
		}()
	}
	_ = conn.Wait()
}

func TestRealDialerPasswordAndRun(t *testing.T) {
	srv := startSSHServer(t, nil, func(cmd string, stdin []byte) (string, string, int) {
		switch cmd {
		case "echo":
			return "got:" + string(stdin), "", 0
		case "fail":
			return "partial", "permission denied\nsecond line", 3
		}
		return "", "unknown command", 127
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	c, err := realDialer{}.Dial(ctx, SSHDialConfig{Addr: srv.addr, User: "pi", Password: []byte("pw"), Timeout: 5 * time.Second, HostKeySHA256: srv.fingerprint()})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if want := ssh.FingerprintSHA256(srv.hostKey); c.HostKeyFingerprint() != want || !strings.HasPrefix(want, "SHA256:") {
		t.Fatalf("fingerprint %q, want %q", c.HostKeyFingerprint(), want)
	}
	out, err := c.Run(ctx, "echo", strings.NewReader("payload"))
	if err != nil || string(out) != "got:payload" {
		t.Fatalf("out %q err %v", out, err)
	}
	out, err = c.Run(ctx, "fail", nil)
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Status != 3 || ee.Stderr != "permission denied second line" || string(out) != "partial" {
		t.Fatalf("out %q err %#v", out, err)
	}
	// a second command on the same connection
	if _, err := c.Run(ctx, "echo", strings.NewReader("again")); err != nil {
		t.Fatal(err)
	}
}

func TestRealDialerWrongPasswordAndNoCredentials(t *testing.T) {
	srv := startSSHServer(t, nil, func(string, []byte) (string, string, int) { return "", "", 0 })
	ctx := context.Background()
	_, err := realDialer{}.Dial(ctx, SSHDialConfig{Addr: srv.addr, User: "pi", Password: []byte("wrong-password"), Timeout: 5 * time.Second, HostKeySHA256: srv.fingerprint()})
	if err == nil {
		t.Fatal("wrong password accepted")
	}
	if strings.Contains(err.Error(), "wrong-password") {
		t.Fatalf("password in error: %v", err)
	}
	if _, err := (realDialer{}).Dial(ctx, SSHDialConfig{Addr: srv.addr, User: "pi", HostKeySHA256: srv.fingerprint()}); err == nil {
		t.Fatal("dial without credentials succeeded")
	}
	if _, err := (realDialer{}).Dial(ctx, SSHDialConfig{Addr: "127.0.0.1:1", User: "pi", Password: []byte("pw"), Timeout: time.Second, HostKeySHA256: testHostKey}); err == nil {
		t.Fatal("dial to closed port succeeded")
	}
}

func TestRealDialerCancelRun(t *testing.T) {
	release := make(chan struct{})
	srv := startSSHServer(t, nil, func(string, []byte) (string, string, int) { <-release; return "", "", 0 })
	defer close(release)
	c, err := realDialer{}.Dial(context.Background(), SSHDialConfig{Addr: srv.addr, User: "pi", Password: []byte("pw"), Timeout: 5 * time.Second, HostKeySHA256: srv.fingerprint()})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := c.Run(ctx, "slow", nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
}

func TestHubKeyCreatedReusedAndUsable(t *testing.T) {
	e := newEnv(t)
	keyPath := filepath.Join(e.dir, "ssh", "id_ed25519")
	fi, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode %v", fi.Mode().Perm())
	}
	pub := e.svc.PublicKey()
	if !strings.HasPrefix(pub, "ssh-ed25519 ") || !strings.HasSuffix(pub, " nexus@frpi5.local") || strings.Contains(pub, "\n") {
		t.Fatalf("public key %q", pub)
	}
	priv, _ := os.ReadFile(keyPath)
	if strings.Contains(pub, string(priv[:20])) {
		t.Fatal("private key material in the public line")
	}

	// A second service on the same data dir reuses the key.
	svc2, err := New(Options{
		Store: e.st, CA: e.ca, ServerCertFile: filepath.Join(e.dir, "pki", "server.pem"),
		HubAddress: "frpi5.local", Port: 8443, DataDir: e.dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	if svc2.PublicKey() != pub {
		t.Fatal("hub key changed on restart")
	}

	// The key authenticates against a server that authorizes it.
	srv := startSSHServer(t, e.svc.hubKey.signer.PublicKey(), func(string, []byte) (string, string, int) { return "ok", "", 0 })
	c, err := realDialer{}.Dial(context.Background(), SSHDialConfig{Addr: srv.addr, User: "anyone", Signer: e.svc.hubKey.signer, Timeout: 5 * time.Second, HostKeySHA256: srv.fingerprint()})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if out, err := c.Run(context.Background(), "x", nil); err != nil || string(out) != "ok" {
		t.Fatalf("%q %v", out, err)
	}
}

func TestCleanLine(t *testing.T) {
	if got := cleanLine("a\x00b\r\nc\td  e\x1b[31m", 100); got != "ab c d e[31m" {
		t.Fatalf("%q", got)
	}
	if got := cleanLine(strings.Repeat("x", 500), 20); len(got) != 20 {
		t.Fatalf("len %d", len(got))
	}
}

func TestRealDialerProbeReceivesKeyWithoutAuthenticating(t *testing.T) {
	srv := startSSHServer(t, nil, func(string, []byte) (string, string, int) { return "", "", 0 })
	info, err := realDialer{}.Probe(context.Background(), srv.addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if info.Type != "ssh-ed25519" || info.SHA256 != srv.fingerprint() {
		t.Fatalf("probe returned %+v, want ssh-ed25519 %s", info, srv.fingerprint())
	}
	if n := srv.authAttempts.Load(); n != 0 {
		t.Fatalf("the probe attempted authentication %d times", n)
	}
}

func TestRealDialerProbeFailures(t *testing.T) {
	// A closed port.
	if _, err := (realDialer{}).Probe(context.Background(), "127.0.0.1:1", time.Second); err == nil {
		t.Fatal("probe of a closed port succeeded")
	}
	// Something that is not SSH: the connection is closed without a banner.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	if _, err := (realDialer{}).Probe(context.Background(), ln.Addr().String(), time.Second); err == nil {
		t.Fatal("probe of a non-SSH service succeeded")
	}
	// A canceled context ends a probe of a host that never answers.
	silent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := (realDialer{}).Probe(ctx, silent.Addr().String(), 5*time.Second); err == nil {
		t.Fatal("probe of a silent host succeeded")
	}
}

// oneCharOff changes the last character of a fingerprint. The last base64
// character of a SHA-256 fingerprint carries only 4 bits, so a fixed
// replacement would equal the original about once in 16 runs.
func oneCharOff(fp string) string {
	last := "A"
	if strings.HasSuffix(fp, "A") {
		last = "E"
	}
	return fp[:len(fp)-1] + last
}

func TestRealDialerPinsTheConfirmedHostKey(t *testing.T) {
	srv := startSSHServer(t, nil, func(string, []byte) (string, string, int) { return "", "", 0 })
	other := startSSHServer(t, nil, func(string, []byte) (string, string, int) { return "", "", 0 })
	tests := []struct {
		name    string
		pin     string
		wantErr error
	}{
		{"confirmed key", srv.fingerprint(), nil},
		{"another host's key", other.fingerprint(), grid.ErrHostKeyMismatch},
		{"one character off", oneCharOff(srv.fingerprint()), grid.ErrHostKeyMismatch},
		{"no fingerprint given", "", errors.New("any")},
		{"malformed fingerprint", "SHA256:short", errors.New("any")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := srv.authAttempts.Load()
			c, err := realDialer{}.Dial(context.Background(), SSHDialConfig{
				Addr: srv.addr, User: "pi", Password: []byte("pw"), Timeout: 5 * time.Second, HostKeySHA256: tt.pin,
			})
			if tt.wantErr == nil {
				if err != nil {
					t.Fatal(err)
				}
				c.Close()
				return
			}
			if err == nil {
				c.Close()
				t.Fatal("dial accepted a host key that was not confirmed")
			}
			if tt.pin != "" && tt.pin != "SHA256:short" && !errors.Is(err, grid.ErrHostKeyMismatch) {
				t.Fatalf("error %v, want ErrHostKeyMismatch", err)
			}
			if n := srv.authAttempts.Load() - before; n != 0 {
				t.Fatalf("the password was offered %d times to an unconfirmed host key", n)
			}
		})
	}
}
