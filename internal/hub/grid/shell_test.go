package grid

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/protocol"
)

type shellAgent struct {
	t      *testing.T
	opens  chan protocol.ShellOpen
	reject string
}

func newShellAgent(t *testing.T) *shellAgent {
	return &shellAgent{t: t, opens: make(chan protocol.ShellOpen, 8)}
}

func (s *shellAgent) handle(a *fakeAgent, env protocol.Envelope) bool {
	if env.Type != protocol.TypeShellOpen {
		return false
	}
	so, err := protocol.DecodeData[protocol.ShellOpen](env)
	if err != nil {
		s.t.Errorf("shell.open: %v", err)
		return true
	}
	if s.reject != "" {
		a.result(env, false, s.reject)
		return true
	}
	a.result(env, true, "")
	s.opens <- so
	return true
}

func (s *shellAgent) nextOpen() protocol.ShellOpen {
	s.t.Helper()
	select {
	case so := <-s.opens:
		return so
	case <-timeAfterWait():
		s.t.Fatal("no shell.open in time")
	}
	return protocol.ShellOpen{}
}

func (e *testEnv) shellHost(sa *shellAgent) (HostID, *fakeAgent) {
	id := e.addHost("alpha", protocol.CapShell)
	a := e.connect("alpha", helloFor("0.1.0", protocol.CapShell), sa.handle)
	eventually(e.t, func() bool { i, _ := e.g.Host(id); return i.Online })
	return id, a
}

func readN(t *testing.T, r io.Reader, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	done := make(chan error, 1)
	go func() { _, err := io.ReadFull(r, buf); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("read: %v", err)
		}
	case <-timeAfterWait():
		t.Fatal("read timed out")
	}
	return buf
}

func readAllWithin(t *testing.T, r io.Reader) ([]byte, error) {
	t.Helper()
	type res struct {
		b   []byte
		err error
	}
	done := make(chan res, 1)
	go func() { b, err := io.ReadAll(r); done <- res{b, err} }()
	select {
	case r := <-done:
		return r.b, r.err
	case <-timeAfterWait():
		t.Fatal("ReadAll did not return")
	}
	return nil, nil
}

func readErr(t *testing.T, r io.Reader) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { _, err := r.Read(make([]byte, 16)); done <- err }()
	select {
	case err := <-done:
		return err
	case <-timeAfterWait():
		t.Fatal("Read did not return")
	}
	return nil
}

func TestShellDataBothWaysResizeAndClose(t *testing.T) {
	e := newEnv(t)
	sa := newShellAgent(t)
	id, a := e.shellHost(sa)
	ctx := context.Background()

	sh, err := e.g.OpenShell(ctx, Actor{Operator: "op1", IP: "192.0.2.7"}, id, 100, 30)
	if err != nil {
		t.Fatal(err)
	}
	open := sa.nextOpen()
	if open.SessionID == "" || open.Cols != 100 || open.Rows != 30 {
		t.Fatalf("shell.open = %+v", open)
	}

	// agent -> browser, including partial reads of one chunk
	a.send(protocol.TypeShellData, "", protocol.ShellData{SessionID: open.SessionID, Data: []byte("hello\r\n")})
	if got := readN(t, sh, 7); string(got) != "hello\r\n" {
		t.Fatalf("read %q", got)
	}
	a.send(protocol.TypeShellData, "", protocol.ShellData{SessionID: open.SessionID, Data: []byte("abcdef")})
	if got := readN(t, sh, 4); string(got) != "abcd" {
		t.Fatalf("read %q", got)
	}
	if got := readN(t, sh, 2); string(got) != "ef" {
		t.Fatalf("read %q", got)
	}
	a.send(protocol.TypeShellData, "", protocol.ShellData{SessionID: "unknown-session", Data: []byte("x")}) // ignored

	// browser -> agent, small and chunked
	if n, err := sh.Write([]byte("ls\n")); err != nil || n != 3 {
		t.Fatalf("write = %d, %v", n, err)
	}
	if d := decode[protocol.ShellData](t, a.expect(protocol.TypeShellData)); d.SessionID != open.SessionID || string(d.Data) != "ls\n" {
		t.Fatalf("shell.data = %+v", d)
	}
	big := bytes.Repeat([]byte("0123456789"), 7000) // 70000 bytes
	if n, err := sh.Write(big); err != nil || n != len(big) {
		t.Fatalf("big write = %d, %v", n, err)
	}
	var got []byte
	for len(got) < len(big) {
		d := decode[protocol.ShellData](t, a.expect(protocol.TypeShellData))
		if len(d.Data) > protocol.MaxShellChunk || len(d.Data) == 0 || d.SessionID != open.SessionID {
			t.Fatalf("chunk of %d bytes for %s", len(d.Data), d.SessionID)
		}
		got = append(got, d.Data...)
	}
	if !bytes.Equal(got, big) {
		t.Fatal("chunks do not add up to the written data")
	}

	if err := sh.Resize(120, 40); err != nil {
		t.Fatal(err)
	}
	if r := decode[protocol.ShellResize](t, a.expect(protocol.TypeShellResize)); r.SessionID != open.SessionID || r.Cols != 120 || r.Rows != 40 {
		t.Fatalf("resize = %+v", r)
	}
	for _, sz := range [][2]int{{0, 10}, {10, 0}, {-1, 5}, {5000, 5}} {
		if err := sh.Resize(sz[0], sz[1]); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("resize %v: %v", sz, err)
		}
	}

	if err := sh.Close(); err != nil {
		t.Fatal(err)
	}
	if c := decode[protocol.ShellClose](t, a.expect(protocol.TypeShellClose)); c.SessionID != open.SessionID {
		t.Fatalf("shell.close = %+v", c)
	}
	if err := readErr(t, sh); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("read after close: %v", err)
	}
	if _, err := sh.Write([]byte("x")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("write after close: %v", err)
	}
	if err := sh.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}

	op := e.waitAudit("shell.open")
	cl := e.waitAudit("shell.close")
	if op.User != "op1" || op.Host != "alpha" || op.Result != store.AuditOK || !strings.Contains(op.Detail, open.SessionID) {
		t.Fatalf("open audit = %+v", op)
	}
	if cl.User != "op1" || cl.Host != "alpha" || !strings.Contains(cl.Detail, "duration") {
		t.Fatalf("close audit = %+v", cl)
	}
	for _, en := range e.auditEntries() {
		if strings.Contains(en.Detail, "hello") || strings.Contains(en.Detail, "0123456789") {
			t.Fatalf("typed or received data in audit: %+v", en)
		}
	}
	if n := len(e.auditFor("shell.close")); n != 1 {
		t.Fatalf("%d shell.close entries", n)
	}
}

func TestShellSessionsAreIndependent(t *testing.T) {
	e := newEnv(t)
	sa := newShellAgent(t)
	id, a := e.shellHost(sa)
	ctx := context.Background()
	s1, err := e.g.OpenShell(ctx, Actor{Operator: "op"}, id, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	o1 := sa.nextOpen()
	if o1.Cols != 80 || o1.Rows != 24 {
		t.Fatalf("default size = %dx%d", o1.Cols, o1.Rows)
	}
	s2, err := e.g.OpenShell(ctx, Actor{Operator: "op"}, id, 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	o2 := sa.nextOpen()
	if o1.SessionID == o2.SessionID {
		t.Fatal("session IDs collide")
	}
	a.send(protocol.TypeShellData, "", protocol.ShellData{SessionID: o2.SessionID, Data: []byte("two")})
	a.send(protocol.TypeShellData, "", protocol.ShellData{SessionID: o1.SessionID, Data: []byte("one")})
	if got := readN(t, s1, 3); string(got) != "one" {
		t.Fatalf("s1 read %q", got)
	}
	if got := readN(t, s2, 3); string(got) != "two" {
		t.Fatalf("s2 read %q", got)
	}
	// Closing one leaves the other open.
	_ = s1.Close()
	a.expect(protocol.TypeShellClose)
	a.send(protocol.TypeShellData, "", protocol.ShellData{SessionID: o2.SessionID, Data: []byte("still")})
	if got := readN(t, s2, 5); string(got) != "still" {
		t.Fatalf("s2 read %q", got)
	}
	_ = s2.Close()
}

func TestShellClosedByAgentDrainsThenEOF(t *testing.T) {
	e := newEnv(t)
	sa := newShellAgent(t)
	id, a := e.shellHost(sa)
	sh, err := e.g.OpenShell(context.Background(), Actor{Operator: "op1"}, id, 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	open := sa.nextOpen()
	a.send(protocol.TypeShellData, "", protocol.ShellData{SessionID: open.SessionID, Data: []byte("bye")})
	a.send(protocol.TypeShellClose, "", protocol.ShellClose{SessionID: open.SessionID, Reason: "exit 0"})

	data, err := readAllWithin(t, sh)
	if err != nil || string(data) != "bye" {
		t.Fatalf("ReadAll = %q, %v", data, err)
	}
	if err := readErr(t, sh); err != io.EOF {
		t.Fatalf("read after EOF: %v", err)
	}
	if _, err := sh.Write([]byte("x")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("write after agent close: %v", err)
	}
	cl := e.waitAudit("shell.close")
	if cl.User != "op1" || !strings.Contains(cl.Detail, "duration") {
		t.Fatalf("audit = %+v", cl)
	}
	// Closing afterwards is fine and writes no second audit entry.
	if err := sh.Close(); err != nil {
		t.Fatal(err)
	}
	if n := len(e.auditFor("shell.close")); n != 1 {
		t.Fatalf("%d shell.close entries", n)
	}
}

func TestShellEndsWhenAgentDisconnects(t *testing.T) {
	e := newEnv(t)
	sa := newShellAgent(t)
	id, a := e.shellHost(sa)
	sh, err := e.g.OpenShell(context.Background(), Actor{Operator: "op"}, id, 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	open := sa.nextOpen()
	a.send(protocol.TypeShellData, "", protocol.ShellData{SessionID: open.SessionID, Data: []byte("last words")})
	a.close()
	data, err := readAllWithin(t, sh)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if s := string(data); s != "last words" && s != "" {
		t.Fatalf("data = %q", s)
	}
	e.waitAudit("shell.close")
}

func TestOpenShellErrors(t *testing.T) {
	e := newEnv(t)
	sa := newShellAgent(t)
	id, _ := e.shellHost(sa)
	offline := e.addHost("offline", protocol.CapShell)
	noCap := e.addHost("nocap", protocol.CapMonitoring)
	e.connect("nocap", helloFor("0.1.0", protocol.CapMonitoring), nil)
	eventually(t, func() bool { i, _ := e.g.Host(noCap); return i.Online })
	ctx := context.Background()

	if _, err := e.g.OpenShell(ctx, Actor{}, "missing", 80, 24); !errors.Is(err, ErrHostNotFound) {
		t.Errorf("unknown: %v", err)
	}
	if _, err := e.g.OpenShell(ctx, Actor{}, offline, 80, 24); !errors.Is(err, ErrHostOffline) {
		t.Errorf("offline: %v", err)
	}
	if _, err := e.g.OpenShell(ctx, Actor{}, noCap, 80, 24); !errors.Is(err, ErrCapabilityDisabled) {
		t.Errorf("capability: %v", err)
	}

	sa.reject = "no pty available"
	if _, err := e.g.OpenShell(ctx, Actor{Operator: "op1"}, id, 80, 24); err == nil || !strings.Contains(err.Error(), "no pty available") {
		t.Errorf("rejected: %v", err)
	}
	eventually(t, func() bool {
		for _, a := range e.auditFor("shell.open") {
			if a.Result == store.AuditError && a.User == "op1" {
				return true
			}
		}
		return false
	})
}

func TestShellDroppedWhenBrowserStopsReading(t *testing.T) {
	e := newEnv(t)
	e.g.shellLim = shellLimits{soft: 100, stall: 50 * time.Millisecond, hard: 1 << 20}
	sa := newShellAgent(t)
	id, a := e.shellHost(sa)
	sh, err := e.g.OpenShell(context.Background(), Actor{Operator: "op"}, id, 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	open := sa.nextOpen()
	a.send(protocol.TypeShellData, "", protocol.ShellData{SessionID: open.SessionID, Data: bytes.Repeat([]byte("x"), 200)})
	c := decode[protocol.ShellClose](t, a.expect(protocol.TypeShellClose))
	if c.SessionID != open.SessionID || !strings.Contains(c.Reason, "not reading") {
		t.Fatalf("shell.close = %+v", c)
	}
	if err := readErr(t, sh); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("read after drop: %v", err)
	}
	e.waitAudit("shell.close")
}

func TestShellStallTimerIsCancelledByReading(t *testing.T) {
	e := newEnv(t)
	e.g.shellLim = shellLimits{soft: 100, stall: 300 * time.Millisecond, hard: 1 << 20}
	sa := newShellAgent(t)
	id, a := e.shellHost(sa)
	sh, err := e.g.OpenShell(context.Background(), Actor{Operator: "op"}, id, 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	open := sa.nextOpen()
	a.send(protocol.TypeShellData, "", protocol.ShellData{SessionID: open.SessionID, Data: bytes.Repeat([]byte("x"), 200)})
	readN(t, sh, 200) // drains the buffer below the soft limit: no drop
	time.Sleep(450 * time.Millisecond)
	a.send(protocol.TypeShellData, "", protocol.ShellData{SessionID: open.SessionID, Data: []byte("ok")})
	if got := readN(t, sh, 2); string(got) != "ok" {
		t.Fatalf("read %q", got)
	}
	_ = sh.Close()
}

func TestShellDroppedAtHardLimit(t *testing.T) {
	e := newEnv(t)
	e.g.shellLim = shellLimits{soft: 500, stall: time.Minute, hard: 1000}
	sa := newShellAgent(t)
	id, a := e.shellHost(sa)
	sh, err := e.g.OpenShell(context.Background(), Actor{Operator: "op"}, id, 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	open := sa.nextOpen()
	for range 3 {
		a.send(protocol.TypeShellData, "", protocol.ShellData{SessionID: open.SessionID, Data: bytes.Repeat([]byte("x"), 600)})
	}
	a.expect(protocol.TypeShellClose)
	if err := readErr(t, sh); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("read after drop: %v", err)
	}
}
