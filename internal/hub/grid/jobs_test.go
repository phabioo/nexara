package grid

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/protocol"
)

// jobAgent scripts the agent side of the job protocol.
type jobAgent struct {
	t       *testing.T
	starts  chan protocol.JobStart
	cancels chan string

	reject        string // non-empty: job.start is rejected with this reason
	autoDone      bool   // finish every accepted job successfully at once
	cancelEndsJob bool   // job.cancel is answered and followed by job.done{ok:false}
	packageLists  atomic.Int32
}

func newJobAgent(t *testing.T) *jobAgent {
	return &jobAgent{t: t, starts: make(chan protocol.JobStart, 64), cancels: make(chan string, 8)}
}

func (j *jobAgent) handle(a *fakeAgent, env protocol.Envelope) bool {
	switch env.Type {
	case protocol.TypePackagesList:
		j.packageLists.Add(1)
		a.send(protocol.TypePackages, env.ID, protocol.Packages{})
		return true
	case protocol.TypeJobStart:
		js, err := protocol.DecodeData[protocol.JobStart](env)
		if err != nil {
			j.t.Errorf("job.start: %v", err)
			return true
		}
		if j.reject != "" {
			a.result(env, false, j.reject)
			return true
		}
		a.result(env, true, "")
		j.starts <- js
		if j.autoDone {
			a.send(protocol.TypeJobDone, "", protocol.JobDone{JobID: js.JobID, OK: true})
		}
		return true
	case protocol.TypeJobCancel:
		jc, err := protocol.DecodeData[protocol.JobCancel](env)
		if err != nil {
			j.t.Errorf("job.cancel: %v", err)
			return true
		}
		j.cancels <- jc.JobID
		a.result(env, true, "")
		if j.cancelEndsJob {
			a.send(protocol.TypeJobDone, "", protocol.JobDone{JobID: jc.JobID, OK: false, ExitCode: 130, Error: "canceled"})
		}
		return true
	}
	return false
}

func (j *jobAgent) nextStart() protocol.JobStart {
	j.t.Helper()
	select {
	case js := <-j.starts:
		return js
	case <-timeAfterWait():
		j.t.Fatal("no job.start in time")
	}
	return protocol.JobStart{}
}

func (e *testEnv) jobHost(ja *jobAgent) (HostID, *fakeAgent) {
	id := e.addHost("alpha", protocol.CapPackages)
	a := e.connect("alpha", helloFor("0.1.0", protocol.CapPackages), ja.handle)
	eventually(e.t, func() bool { i, _ := e.g.Host(id); return i.Online })
	return id, a
}

func (e *testEnv) job(id HostID, jobID string) Job {
	for _, j := range e.g.Jobs(id) {
		if j.ID == jobID {
			return j
		}
	}
	e.t.Fatalf("job %s not listed", jobID)
	return Job{}
}

func (e *testEnv) auditFor(action string) []store.AuditEntry {
	var out []store.AuditEntry
	for _, a := range e.auditEntries() {
		if a.Action == action {
			out = append(out, a)
		}
	}
	return out
}

func TestJobQueueRunsOneAtATimeInOrder(t *testing.T) {
	e := newEnv(t)
	ja := newJobAgent(t)
	id, a := e.jobHost(ja)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := e.g.Subscribe(ctx)
	op1, op2 := Actor{Operator: "op1"}, Actor{Operator: "op2"}

	jA, err := e.g.StartJob(ctx, op1, id, JobSpec{Kind: protocol.JobAptUpdate})
	if err != nil || jA.State != JobRunning || jA.Host != id || jA.RequestedBy != "op1" || jA.QueuedAt.IsZero() || jA.StartedAt.IsZero() {
		t.Fatalf("job A = %+v, %v", jA, err)
	}
	jB, err := e.g.StartJob(ctx, op2, id, JobSpec{Kind: protocol.JobPkgInstall, Package: "htop"})
	if err != nil || jB.State != JobQueued || !jB.StartedAt.IsZero() {
		t.Fatalf("job B = %+v, %v", jB, err)
	}
	jC, err := e.g.StartJob(ctx, op2, id, JobSpec{Kind: protocol.JobPkgInstall, Package: "curl"})
	if err != nil || jC.State != JobQueued {
		t.Fatalf("job C = %+v, %v", jC, err)
	}
	// Identical queued or running jobs are refused; a different package is fine.
	for _, spec := range []JobSpec{{Kind: protocol.JobAptUpdate}, {Kind: protocol.JobPkgInstall, Package: "htop"}} {
		if _, err := e.g.StartJob(ctx, op1, id, spec); !errors.Is(err, ErrJobBusy) {
			t.Fatalf("duplicate %+v: %v", spec, err)
		}
	}

	if js := ja.nextStart(); js.JobID != jA.ID || js.Kind != protocol.JobAptUpdate || js.Package != "" {
		t.Fatalf("first start = %+v", js)
	}
	// B and C cannot have started before A is done.
	snap, _ := e.g.Snapshot(id)
	if len(snap.Jobs) != 3 || snap.Jobs[0].ID != jA.ID || snap.Jobs[1].ID != jB.ID || snap.Jobs[2].ID != jC.ID ||
		snap.Jobs[0].State != JobRunning || snap.Jobs[1].State != JobQueued || snap.Jobs[2].State != JobQueued {
		t.Fatalf("snapshot jobs = %+v", snap.Jobs)
	}
	if list := e.g.Jobs(id); len(list) != 3 || list[0].ID != jC.ID || list[2].ID != jA.ID {
		t.Fatalf("Jobs must be newest first: %+v", list)
	}

	for _, l := range []protocol.JobOutput{
		{Stream: protocol.StreamStdout, Line: "Get:1 http://deb"},
		{Stream: protocol.StreamStderr, Line: "W: warning"},
		{Stream: protocol.StreamStatus, Line: "waiting for dpkg lock"},
	} {
		l.JobID = jA.ID
		a.send(protocol.TypeJobOutput, "", l)
	}
	for _, want := range []string{"Get:1 http://deb", "W: warning", "waiting for dpkg lock"} {
		ev := waitEvent(t, events, EventJobOutput)
		if out := ev.Payload.(JobOutputEvent); out.JobID != jA.ID || out.Line.Line != want {
			t.Fatalf("output event %+v, want %q", out, want)
		}
	}
	if got := e.job(id, jA.ID).Output; len(got) != 3 || got[1].Stream != protocol.StreamStderr {
		t.Fatalf("retained output = %+v", got)
	}

	a.send(protocol.TypeJobDone, "", protocol.JobDone{JobID: jA.ID, OK: true, RebootRequired: true})
	done := waitEvent(t, events, EventJobDone).Payload.(Job)
	if done.ID != jA.ID || done.State != JobDone || !done.OK || !done.RebootRequired || done.FinishedAt.IsZero() {
		t.Fatalf("job_done = %+v", done)
	}
	if info, _ := e.g.Host(id); !info.RebootRequired {
		t.Fatal("host reboot flag not set")
	}

	if js := ja.nextStart(); js.JobID != jB.ID || js.Kind != protocol.JobPkgInstall || js.Package != "htop" {
		t.Fatalf("second start = %+v", js)
	}
	a.send(protocol.TypeJobDone, "", protocol.JobDone{JobID: jB.ID, OK: false, ExitCode: 100, Error: "E: boom"})
	failed := waitEvent(t, events, EventJobDone).Payload.(Job)
	if failed.State != JobFailed || failed.OK || failed.ExitCode != 100 || failed.Error != "E: boom" {
		t.Fatalf("failed job = %+v", failed)
	}

	if js := ja.nextStart(); js.JobID != jC.ID || js.Package != "curl" {
		t.Fatalf("third start = %+v", js)
	}
	a.send(protocol.TypeJobDone, "", protocol.JobDone{JobID: jC.ID, OK: true})
	waitEvent(t, events, EventJobDone)

	// One audit entry per job with the requesting operator.
	eventually(t, func() bool {
		return len(e.auditFor("job.apt_update")) == 1 && len(e.auditFor("job.pkg_install")) == 2
	})
	au := e.auditFor("job.apt_update")[0]
	if au.User != "op1" || au.Host != "alpha" || au.Result != store.AuditOK {
		t.Fatalf("audit A = %+v", au)
	}
	var sawFail, sawOK bool
	for _, a := range e.auditFor("job.pkg_install") {
		if a.User != "op2" {
			t.Fatalf("audit user = %+v", a)
		}
		switch a.Result {
		case store.AuditError:
			sawFail = strings.HasPrefix(a.Detail, "htop")
		case store.AuditOK:
			sawOK = a.Detail == "curl"
		}
	}
	if !sawFail || !sawOK {
		t.Fatalf("pkg_install audit = %+v", e.auditFor("job.pkg_install"))
	}
	// The package list is refreshed once the queue ran empty (plus once on connect).
	eventually(t, func() bool { return ja.packageLists.Load() >= 2 })
	if n := len(e.g.Jobs(id)); n != 3 {
		t.Fatalf("%d jobs listed", n)
	}
	if snap, _ := e.g.Snapshot(id); len(snap.Jobs) != 0 {
		t.Fatalf("finished jobs in snapshot: %+v", snap.Jobs)
	}
}

func TestJobOutputKeepsLastLines(t *testing.T) {
	e := newEnv(t)
	ja := newJobAgent(t)
	id, a := e.jobHost(ja)
	j, err := e.g.StartJob(context.Background(), Actor{Operator: "op"}, id, JobSpec{Kind: protocol.JobAptUpgrade})
	if err != nil {
		t.Fatal(err)
	}
	ja.nextStart()
	for i := range maxOutputLines + 20 {
		a.send(protocol.TypeJobOutput, "", protocol.JobOutput{JobID: j.ID, Stream: protocol.StreamStdout, Line: fmt.Sprintf("l%d", i)})
	}
	a.send(protocol.TypeJobDone, "", protocol.JobDone{JobID: j.ID, OK: true})
	eventually(t, func() bool { return e.job(id, j.ID).State == JobDone })
	out := e.job(id, j.ID).Output
	if len(out) != maxOutputLines || out[0].Line != "l20" || out[len(out)-1].Line != fmt.Sprintf("l%d", maxOutputLines+19) {
		t.Fatalf("len %d, first %q, last %q", len(out), out[0].Line, out[len(out)-1].Line)
	}
}

func TestJobRejectedByAgentFailsAndQueueContinues(t *testing.T) {
	e := newEnv(t)
	ja := newJobAgent(t)
	ja.reject = "dpkg lock timeout"
	id, _ := e.jobHost(ja)
	ctx := context.Background()
	jA, _ := e.g.StartJob(ctx, Actor{Operator: "op"}, id, JobSpec{Kind: protocol.JobAptUpdate})
	jB, _ := e.g.StartJob(ctx, Actor{Operator: "op"}, id, JobSpec{Kind: protocol.JobAptClean})
	for _, j := range []Job{jA, jB} {
		eventually(t, func() bool { return e.job(id, j.ID).State == JobFailed })
		if got := e.job(id, j.ID).Error; !strings.Contains(got, "dpkg lock timeout") {
			t.Fatalf("error = %q", got)
		}
	}
	eventually(t, func() bool { return len(e.auditFor("job.apt_update")) == 1 && len(e.auditFor("job.apt_clean")) == 1 })
	if e.auditFor("job.apt_update")[0].Result != store.AuditError {
		t.Fatal("rejected job audited as ok")
	}
}

func TestCancelQueuedJobDoesNotContactAgent(t *testing.T) {
	e := newEnv(t)
	ja := newJobAgent(t)
	ja.cancelEndsJob = true
	id, _ := e.jobHost(ja)
	ctx := context.Background()
	events := e.g.Subscribe(ctx)
	jA, _ := e.g.StartJob(ctx, Actor{Operator: "op1"}, id, JobSpec{Kind: protocol.JobAptUpgrade})
	jB, _ := e.g.StartJob(ctx, Actor{Operator: "op1"}, id, JobSpec{Kind: protocol.JobPkgRemove, Package: "htop"})
	ja.nextStart()

	if err := e.g.CancelJob(ctx, Actor{Operator: "op2"}, jB.ID); err != nil {
		t.Fatal(err)
	}
	ev := waitEvent(t, events, EventJobDone)
	if got := ev.Payload.(Job); got.ID != jB.ID || got.State != JobCanceled || got.FinishedAt.IsZero() {
		t.Fatalf("job_done = %+v", got)
	}
	if err := e.g.CancelJob(ctx, Actor{}, jB.ID); !errors.Is(err, ErrJobFinished) {
		t.Fatalf("second cancel: %v", err)
	}
	if err := e.g.CancelJob(ctx, Actor{}, "no-such-job"); !errors.Is(err, ErrJobNotFound) {
		t.Fatalf("unknown job: %v", err)
	}

	// Cancelling the running job is the first job.cancel the agent sees: B's was handled locally.
	if err := e.g.CancelJob(ctx, Actor{Operator: "op2"}, jA.ID); err != nil {
		t.Fatal(err)
	}
	if got := <-ja.cancels; got != jA.ID {
		t.Fatalf("agent was asked to cancel %s, want %s", got, jA.ID)
	}
	eventually(t, func() bool { return e.job(id, jA.ID).State == JobCanceled })
	eventually(t, func() bool { return len(e.auditFor("job.pkg_remove")) == 1 && len(e.auditFor("job.apt_upgrade")) == 1 })
	if a := e.auditFor("job.pkg_remove")[0]; a.Result != store.AuditError || !strings.Contains(a.Detail, "canceled by op2") || !strings.HasPrefix(a.Detail, "htop") {
		t.Fatalf("audit = %+v", a)
	}
	if a := e.auditFor("job.apt_upgrade")[0]; a.Result != store.AuditError || !strings.Contains(a.Detail, "canceled by op2") {
		t.Fatalf("audit = %+v", a)
	}
}

func TestCancelRunningJobAlreadyGoneOnAgent(t *testing.T) {
	e := newEnv(t)
	ja := newJobAgent(t)
	id := e.addHost("alpha", protocol.CapPackages)
	a := e.connect("alpha", helloFor("0.1.0", protocol.CapPackages), func(a *fakeAgent, env protocol.Envelope) bool {
		if env.Type == protocol.TypeJobCancel {
			a.send(protocol.TypeError, env.ID, protocol.Error{Code: protocol.CodeNotFound, Message: "no such job"})
			return true
		}
		return ja.handle(a, env)
	})
	_ = a
	j, _ := e.g.StartJob(context.Background(), Actor{Operator: "op"}, id, JobSpec{Kind: protocol.JobAptClean})
	ja.nextStart()
	if err := e.g.CancelJob(context.Background(), Actor{}, j.ID); !errors.Is(err, ErrJobFinished) {
		t.Fatalf("cancel: %v", err)
	}
}

func TestAgentDisconnectFailsRunningAndQueuedJobs(t *testing.T) {
	e := newEnv(t)
	ja := newJobAgent(t)
	id, a := e.jobHost(ja)
	ctx := context.Background()
	events := e.g.Subscribe(ctx)
	jA, _ := e.g.StartJob(ctx, Actor{Operator: "op1"}, id, JobSpec{Kind: protocol.JobAptUpgrade})
	jB, _ := e.g.StartJob(ctx, Actor{Operator: "op1"}, id, JobSpec{Kind: protocol.JobAptClean})
	ja.nextStart()

	a.close()
	waitEvent(t, events, EventJobDone)
	waitEvent(t, events, EventJobDone)
	for _, j := range []Job{jA, jB} {
		got := e.job(id, j.ID)
		if got.State != JobFailed || got.Error != "agent disconnected" || got.OK {
			t.Fatalf("job = %+v", got)
		}
	}
	eventually(t, func() bool { return len(e.auditFor("job.apt_upgrade")) == 1 && len(e.auditFor("job.apt_clean")) == 1 })
	if _, err := e.g.StartJob(ctx, Actor{}, id, JobSpec{Kind: protocol.JobAptUpdate}); !errors.Is(err, ErrHostOffline) {
		t.Fatalf("start while offline: %v", err)
	}
}

func TestReplacedConnectionFailsItsJobAndQueueContinuesOnNewOne(t *testing.T) {
	e := newEnv(t)
	ja1 := newJobAgent(t)
	id, _ := e.jobHost(ja1)
	ctx := context.Background()
	jA, _ := e.g.StartJob(ctx, Actor{Operator: "op"}, id, JobSpec{Kind: protocol.JobAptUpgrade})
	ja1.nextStart()

	ja2 := newJobAgent(t)
	e.connect("alpha", helloFor("0.1.0", protocol.CapPackages), ja2.handle)
	eventually(t, func() bool { return e.job(id, jA.ID).State == JobFailed })
	if got := e.job(id, jA.ID).Error; got != "agent disconnected" {
		t.Fatalf("error = %q", got)
	}
	if info, _ := e.g.Host(id); !info.Online {
		t.Fatal("host must stay online on the new connection")
	}
	if _, err := e.g.StartJob(ctx, Actor{Operator: "op"}, id, JobSpec{Kind: protocol.JobAptUpgrade}); err != nil {
		t.Fatalf("start on new connection: %v", err)
	}
	ja2.nextStart()
}

func TestFinishedJobsAreBounded(t *testing.T) {
	e := newEnv(t)
	ja := newJobAgent(t)
	ja.autoDone = true
	id, _ := e.jobHost(ja)
	ctx := context.Background()
	var ids []string
	for i := range maxFinishedJobs + 5 {
		j, err := e.g.StartJob(ctx, Actor{Operator: "op"}, id, JobSpec{Kind: protocol.JobPkgInstall, Package: fmt.Sprintf("pkg%02d", i)})
		if err != nil {
			t.Fatalf("job %d: %v", i, err)
		}
		ids = append(ids, j.ID)
		eventually(t, func() bool { return e.job(id, j.ID).State == JobDone })
	}
	list := e.g.Jobs(id)
	if len(list) != maxFinishedJobs || list[0].Package != fmt.Sprintf("pkg%02d", maxFinishedJobs+4) || list[len(list)-1].Package != "pkg05" {
		t.Fatalf("%d jobs, first %q, last %q", len(list), list[0].Package, list[len(list)-1].Package)
	}
	if err := e.g.CancelJob(ctx, Actor{}, ids[0]); !errors.Is(err, ErrJobNotFound) {
		t.Fatalf("evicted job: %v", err)
	}
	if err := e.g.CancelJob(ctx, Actor{}, ids[len(ids)-1]); !errors.Is(err, ErrJobFinished) {
		t.Fatalf("retained job: %v", err)
	}
}

func TestStartJobValidationAndErrors(t *testing.T) {
	e := newEnv(t)
	ja := newJobAgent(t)
	id, _ := e.jobHost(ja)
	offline := e.addHost("offline", protocol.CapPackages)
	noCap := e.addHost("nocap", protocol.CapMonitoring)
	e.connect("nocap", helloFor("0.1.0", protocol.CapMonitoring), nil)
	eventually(t, func() bool { i, _ := e.g.Host(noCap); return i.Online })
	ctx := context.Background()

	invalid := []JobSpec{
		{Kind: "rm_rf"},
		{Kind: ""},
		{Kind: protocol.JobPkgInstall},
		{Kind: protocol.JobPkgInstall, Package: "Bad Name"},
		{Kind: protocol.JobPkgRemove, Package: "x"},
		{Kind: protocol.JobPkgUpgrade, Package: "a;b"},
		{Kind: protocol.JobPkgInstall, Package: "--purge"},
		{Kind: protocol.JobAptUpdate, Package: "htop"},
	}
	for _, spec := range invalid {
		if _, err := e.g.StartJob(ctx, Actor{}, id, spec); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%+v: %v", spec, err)
		}
	}
	if len(ja.starts) != 0 {
		t.Fatal("invalid job reached the agent")
	}
	ok := JobSpec{Kind: protocol.JobAptClean}
	if _, err := e.g.StartJob(ctx, Actor{}, "missing", ok); !errors.Is(err, ErrHostNotFound) {
		t.Errorf("unknown host: %v", err)
	}
	if _, err := e.g.StartJob(ctx, Actor{}, offline, ok); !errors.Is(err, ErrHostOffline) {
		t.Errorf("offline: %v", err)
	}
	if _, err := e.g.StartJob(ctx, Actor{}, noCap, ok); !errors.Is(err, ErrCapabilityDisabled) {
		t.Errorf("capability: %v", err)
	}
}

func TestJobStartedEventWhenQueuedJobRuns(t *testing.T) {
	e := newEnv(t)
	ja := newJobAgent(t)
	id, a := e.jobHost(ja)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := e.g.Subscribe(ctx)

	jA, _ := e.g.StartJob(ctx, Actor{Operator: "op"}, id, JobSpec{Kind: protocol.JobAptUpdate})
	jB, _ := e.g.StartJob(ctx, Actor{Operator: "op"}, id, JobSpec{Kind: protocol.JobAptClean})
	ev := waitEvent(t, events, EventJobStarted)
	if got := ev.Payload.(Job); got.ID != jA.ID || got.State != JobRunning || got.StartedAt.IsZero() || ev.Host != id {
		t.Fatalf("first job_started = %+v", ev)
	}
	ja.nextStart()
	a.send(protocol.TypeJobDone, "", protocol.JobDone{JobID: jA.ID, OK: true})
	ev = waitEvent(t, events, EventJobStarted)
	if got := ev.Payload.(Job); got.ID != jB.ID || got.State != JobRunning {
		t.Fatalf("second job_started = %+v", ev)
	}
}
