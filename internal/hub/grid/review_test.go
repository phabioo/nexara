package grid

import (
	"context"
	"crypto/x509"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/protocol"
)

// Regression tests for the v0.2 security review (docs/security-review-v0.2.md).

// C-01: "certificate not due" is audited once per host and hour.
func TestCSRNotDueAuditIsThrottled(t *testing.T) {
	e := newRenewEnv(t)
	id, old := e.enroll("pi5", 200*day)
	a := e.connect(old, nil)
	_, csr := freshCSR(t, string(id))

	count := func() int {
		n := 0
		for _, en := range e.audit("cert.renew") {
			if en.Result == store.AuditDenied {
				n++
			}
		}
		return n
	}
	for i := 0; i < maxBadCSRs-1; i++ {
		if env := a.csr("c"+string(rune('a'+i)), csr); env.Type != protocol.TypeError {
			t.Fatalf("answer = %s, want error", env.Type)
		}
	}
	if n := count(); n != 1 {
		t.Fatalf("%d audit entries after %d requests in one hour, want 1", n, maxBadCSRs-1)
	}

	// An hour later the next refusal is recorded again (on a fresh connection;
	// the first one used up its allowance).
	e.clk.Advance(notDueAuditEvery + time.Minute)
	b := e.connect(old, nil)
	b.csr("late", csr)
	if n := count(); n != 2 {
		t.Fatalf("%d audit entries after the hour, want 2", n)
	}
}

// C-01: a connection that keeps sending refused requests is closed.
func TestCSRRepeatedBadRequestsCloseTheConnection(t *testing.T) {
	e := newRenewEnv(t)
	id, old := e.enroll("pi5", 200*day)
	a := e.connect(old, nil)
	_, csr := freshCSR(t, string(id))
	for i := 0; i < maxBadCSRs; i++ {
		a.send(protocol.TypeCertCSR, "c"+string(rune('a'+i)), protocol.CertCSR{CSRPEM: string(csr)})
	}
	a.waitDone()
	eventually(t, func() bool { info, _ := e.g.Host(id); return !info.Online })
	if n := len(e.audit("cert.renew")); n != 1 {
		t.Errorf("%d audit entries for %d refused requests, want 1", n, maxBadCSRs)
	}
	// The host can reconnect normally.
	e.suppressAutoRenew(id)
	e.connect(old, nil)
}

// C-03: switching packages off cancels queued jobs and the running one.
func TestSwitchingPackagesOffCancelsQueuedAndRunningJobs(t *testing.T) {
	e := newEnv(t)
	ja := newJobAgent(t)
	ja.cancelEndsJob = true
	id, _ := e.jobHost(ja)
	ctx := context.Background()
	actor := Actor{Operator: "op"}

	run, err := e.g.StartJob(ctx, actor, id, JobSpec{Kind: protocol.JobAptUpgrade})
	if err != nil {
		t.Fatal(err)
	}
	ja.nextStart()
	q1, _ := e.g.StartJob(ctx, actor, id, JobSpec{Kind: protocol.JobAptUpdate})
	q2, _ := e.g.StartJob(ctx, actor, id, JobSpec{Kind: protocol.JobAptClean})

	if err := e.g.SetCapability(ctx, actor, id, protocol.CapPackages, false); err != nil {
		t.Fatal(err)
	}
	for _, j := range []Job{q1, q2} {
		got := e.job(id, j.ID)
		if got.State != JobCanceled || got.Error != "packages switched off" {
			t.Errorf("queued job %s = %s %q, want canceled by the switch", j.Kind, got.State, got.Error)
		}
	}
	select {
	case got := <-ja.cancels:
		if got != run.ID {
			t.Errorf("job.cancel for %s, want the running job %s", got, run.ID)
		}
	case <-timeAfterWait():
		t.Fatal("the running job was not told to stop")
	}
	eventually(t, func() bool { return e.job(id, run.ID).State == JobCanceled })
	eventually(t, func() bool {
		return len(e.auditFor("job.apt_upgrade")) == 1 && len(e.auditFor("job.apt_update")) == 1 && len(e.auditFor("job.apt_clean")) == 1
	})
	for _, action := range []string{"job.apt_upgrade", "job.apt_update", "job.apt_clean"} {
		au := e.auditFor(action)[0]
		if au.Result != store.AuditError || !strings.Contains(au.Detail, "packages switched off") {
			t.Errorf("audit %s = %+v", action, au)
		}
	}
	if len(ja.starts) != 0 {
		t.Error("a queued job reached the agent after the switch")
	}
	if snap, _ := e.g.Snapshot(id); len(snap.Jobs) != 0 {
		t.Errorf("jobs still active: %+v", snap.Jobs)
	}
}

// C-03: the queue never starts a job while packages are off, whatever got it there.
func TestPumpDoesNotStartJobsWhilePackagesAreOff(t *testing.T) {
	e := newEnv(t)
	ja := newJobAgent(t)
	id, agent := e.jobHost(ja)
	ctx := context.Background()
	run, _ := e.g.StartJob(ctx, Actor{Operator: "op"}, id, JobSpec{Kind: protocol.JobAptUpgrade})
	ja.nextStart()
	queued, _ := e.g.StartJob(ctx, Actor{Operator: "op"}, id, JobSpec{Kind: protocol.JobAptUpdate})

	e.g.mu.Lock()
	e.g.hosts[id].capsOff = []string{protocol.CapPackages} // bypasses SetCapability's cleanup
	e.g.mu.Unlock()
	agent.send(protocol.TypeJobDone, "", protocol.JobDone{JobID: run.ID, OK: true})
	eventually(t, func() bool { return e.job(id, run.ID).State == JobDone })

	if got := e.job(id, queued.ID); got.State != JobQueued {
		t.Fatalf("queued job = %s, want it to stay queued", got.State)
	}
	if len(ja.starts) != 0 {
		t.Error("job.start sent while packages are off")
	}
}

// C-05: a session cannot be registered once the capability is off.
func TestRegisterShellRechecksTheCapability(t *testing.T) {
	e := newEnv(t)
	sa := newShellAgent(t)
	id, _ := e.shellHost(sa)
	st, c, err := e.g.connFor(id, protocol.CapShell)
	if err != nil {
		t.Fatal(err)
	}
	// The switch lands between OpenShell's check and its registration.
	if err := e.g.SetCapability(context.Background(), Actor{Operator: "op"}, id, protocol.CapShell, false); err != nil {
		t.Fatal(err)
	}
	s := &shellSession{g: e.g, c: c, id: "s1", notify: make(chan struct{}, 1)}
	if err := e.g.registerShell(st, c, s); !errors.Is(err, ErrCapabilityDisabled) {
		t.Fatalf("registerShell with the shell off: %v", err)
	}
	if c.shell("s1") != nil {
		t.Error("session registered although the shell is off")
	}
}

// C-04: a handshake that outlives the host or its certificate is not accepted.
func TestAcceptRefusesRemovedHostAndRetiredCertificate(t *testing.T) {
	e := newEnv(t)
	id := e.addHost("alpha", protocol.CapMonitoring)
	e.g.mu.Lock()
	st := e.g.hosts[id]
	e.g.mu.Unlock()
	hello := helloFor("0.1.0", protocol.CapMonitoring)

	t.Run("retired certificate", func(t *testing.T) {
		c := &agentConn{peer: &x509.Certificate{Raw: []byte("some other certificate")}}
		if e.g.accept(st, c, hello) {
			t.Fatal("accepted a connection whose certificate is not of record")
		}
		if info, _ := e.g.Host(id); info.Online {
			t.Error("host online after a refused accept")
		}
	})
	t.Run("removed host", func(t *testing.T) {
		e.g.Remove(id)
		c := &agentConn{}
		if e.g.accept(st, c, hello) {
			t.Fatal("accepted a connection for a removed host")
		}
		e.g.mu.Lock()
		defer e.g.mu.Unlock()
		if st.conn != nil || st.online {
			t.Error("detached host state was installed")
		}
	})
}

// C-04 end to end: the certificate of a removed host no longer gets an ack.
func TestRemovedHostsCertificateIsNotAcknowledged(t *testing.T) {
	e := newRenewEnv(t)
	id, creds := e.enroll("pi5", 200*day)
	e.suppressAutoRenew(id)
	if err := e.g.RemoveHost(context.Background(), Actor{Operator: "op"}, id); err != nil {
		t.Fatal(err)
	}
	if _, err := e.tryConnect(creds, nil); err == nil {
		t.Fatal("a removed host was acknowledged")
	}
}

// C-06: unreadable capability switches stop the startup.
func TestNewGridFailsWhenSwitchesCannotBeRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hub.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec("DROP TABLE settings"); err != nil {
		t.Fatal(err)
	}
	g, err := NewGrid(Options{Store: st})
	if err == nil {
		g.Close()
		t.Fatal("NewGrid succeeded although the capability switches could not be read")
	}
	if !strings.Contains(err.Error(), "capability switches") {
		t.Errorf("err = %v", err)
	}
}
