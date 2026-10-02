package grid

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/protocol"
)

// jobRec is a job plus the bookkeeping only the grid needs; guarded by Grid.mu.
type jobRec struct {
	Job
	conn            *agentConn // connection the job was started on
	cancelRequested bool
	cancelBy        string
	seq             uint64
}

func (r *jobRec) snapshot() Job {
	j := r.Job
	j.Output = slices.Clone(r.Output)
	return j
}

type jobOutcome struct {
	state  JobState
	ok     bool
	exit   int
	err    string
	reboot bool
}

// StartJob implements Hub.
func (g *Grid) StartJob(_ context.Context, actor Actor, id HostID, spec JobSpec) (Job, error) {
	if !spec.Kind.Valid() {
		return Job{}, fmt.Errorf("%w: unknown job kind %q", ErrInvalidArgument, spec.Kind)
	}
	if spec.Kind.NeedsPackage() {
		if !packageRe.MatchString(spec.Package) {
			return Job{}, fmt.Errorf("%w: package name", ErrInvalidArgument)
		}
	} else if spec.Package != "" {
		return Job{}, fmt.Errorf("%w: %s takes no package", ErrInvalidArgument, spec.Kind)
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	st, ok := g.hosts[id]
	if !ok {
		return Job{}, ErrHostNotFound
	}
	if st.conn == nil || !st.online {
		return Job{}, ErrHostOffline
	}
	if !st.capEnabled(protocol.CapPackages) {
		return Job{}, ErrCapabilityDisabled
	}
	for _, rec := range st.queue {
		if rec.Kind == spec.Kind && rec.Package == spec.Package {
			return Job{}, ErrJobBusy
		}
	}
	g.jobSeq++
	rec := &jobRec{seq: g.jobSeq, Job: Job{
		ID:          store.NewID(),
		Host:        id,
		Kind:        spec.Kind,
		Package:     spec.Package,
		State:       JobQueued,
		QueuedAt:    g.now(),
		RequestedBy: actor.Operator,
	}}
	st.queue = append(st.queue, rec)
	g.jobs[rec.ID] = st
	g.emitLocked(Event{Kind: EventJobQueued, Host: id, Payload: rec.snapshot()})
	g.pumpLocked(st)
	return rec.snapshot(), nil
}

// pumpLocked starts the head of the queue if nothing is running; g.mu must be held.
func (g *Grid) pumpLocked(st *hostState) {
	if st.conn == nil || !st.online || len(st.queue) == 0 {
		return
	}
	rec := st.queue[0]
	if rec.State != JobQueued {
		return
	}
	rec.State = JobRunning
	rec.StartedAt = g.now()
	rec.conn = st.conn
	g.emitLocked(Event{Kind: EventJobStarted, Host: st.id, Payload: rec.snapshot()})
	go g.startOnAgent(st, rec, rec.conn)
}

// startOnAgent sends job.start; the job then progresses through job.output / job.done.
func (g *Grid) startOnAgent(st *hostState, rec *jobRec, c *agentConn) {
	env, err := c.request(c.ctx, protocol.TypeJobStart, protocol.JobStart{JobID: rec.ID, Kind: rec.Kind, Package: rec.Package}, g.to.jobStart)
	if err == nil {
		err = resultErr(env, "job start")
	}
	if err == nil {
		return
	}
	msg := err.Error()
	if errors.Is(err, ErrHostOffline) {
		msg = "agent disconnected"
	}
	g.mu.Lock()
	entry, ok := g.finishLocked(st, rec, jobOutcome{state: JobFailed, err: msg})
	g.mu.Unlock()
	if ok {
		g.postJob(st, entry)
	}
}

// finishLocked moves a job to a terminal state, emits job_done, pumps the
// queue and returns the audit entry to write once g.mu is released. ok is false
// if the job was already finished. g.mu must be held.
func (g *Grid) finishLocked(st *hostState, rec *jobRec, o jobOutcome) (store.AuditEntry, bool) {
	if rec.State.Finished() {
		return store.AuditEntry{}, false
	}
	rec.State = o.state
	rec.FinishedAt = g.now()
	rec.OK = o.ok
	rec.ExitCode = o.exit
	rec.Error = o.err
	rec.RebootRequired = o.reboot
	if o.reboot {
		st.rebootRequired = true
	}
	if i := slices.Index(st.queue, rec); i >= 0 {
		st.queue = slices.Delete(st.queue, i, i+1)
	}
	st.finished = append(st.finished, rec)
	if len(st.finished) > maxFinishedJobs {
		delete(g.jobs, st.finished[0].ID)
		st.finished = slices.Delete(st.finished, 0, 1)
	}
	g.emitLocked(Event{Kind: EventJobDone, Host: st.id, Payload: rec.snapshot()})

	entry := store.AuditEntry{
		Time:   rec.FinishedAt,
		User:   rec.RequestedBy,
		Host:   st.name,
		Action: "job." + string(rec.Kind),
		Detail: rec.Package,
		Result: store.AuditOK,
	}
	if !o.ok {
		entry.Result = store.AuditError
		reason := o.err
		if o.state == JobCanceled {
			reason = "canceled"
			if rec.cancelBy != "" {
				reason += " by " + rec.cancelBy
			}
		}
		entry.Detail = strings.TrimSpace(rec.Package + " " + reason)
	}
	g.pumpLocked(st)
	return entry, true
}

// postJob writes the audit entry and, once the queue is empty, refreshes the package list.
func (g *Grid) postJob(st *hostState, entry store.AuditEntry) {
	g.audit(entry)
	g.mu.Lock()
	idle := len(st.queue) == 0 && st.online
	g.mu.Unlock()
	if idle {
		go func() {
			if err := g.RefreshPackages(g.ctx, st.id); err != nil {
				g.log.Debug("grid: packages refresh after job failed", "host", st.name, "err", err)
			}
		}()
	}
}

func (g *Grid) onJobOutput(st *hostState, env protocol.Envelope) {
	out, err := protocol.DecodeData[protocol.JobOutput](env)
	if err != nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	owner, ok := g.jobs[out.JobID]
	if !ok || owner != st {
		return
	}
	rec := findJob(st, out.JobID)
	if rec == nil || rec.State != JobRunning {
		return
	}
	line := JobLine{Stream: out.Stream, Line: out.Line}
	if len(rec.Output) >= maxOutputLines {
		copy(rec.Output, rec.Output[1:])
		rec.Output[len(rec.Output)-1] = line
	} else {
		rec.Output = append(rec.Output, line)
	}
	g.emitLocked(Event{Kind: EventJobOutput, Host: st.id, Payload: JobOutputEvent{JobID: rec.ID, Line: line}})
}

func (g *Grid) onJobDone(st *hostState, c *agentConn, env protocol.Envelope) {
	d, err := protocol.DecodeData[protocol.JobDone](env)
	if err != nil {
		return
	}
	g.mu.Lock()
	rec := findJob(st, d.JobID)
	if rec == nil || rec.conn != c {
		g.mu.Unlock()
		return
	}
	o := jobOutcome{state: JobDone, ok: d.OK, exit: d.ExitCode, err: d.Error, reboot: d.RebootRequired}
	if !d.OK {
		o.state = JobFailed
		if rec.cancelRequested {
			o.state = JobCanceled
		}
	}
	entry, ok := g.finishLocked(st, rec, o)
	g.mu.Unlock()
	if ok {
		g.postJob(st, entry)
	}
}

// findJob looks a queued or running job up; g.mu must be held.
func findJob(st *hostState, id string) *jobRec {
	for _, rec := range st.queue {
		if rec.ID == id {
			return rec
		}
	}
	return nil
}

// CancelJob implements Hub.
func (g *Grid) CancelJob(ctx context.Context, actor Actor, jobID string) error {
	g.mu.Lock()
	st, ok := g.jobs[jobID]
	if !ok {
		g.mu.Unlock()
		return ErrJobNotFound
	}
	rec := findJob(st, jobID)
	if rec == nil {
		g.mu.Unlock()
		return ErrJobFinished
	}
	rec.cancelBy = actor.Operator
	if rec.State == JobQueued {
		entry, _ := g.finishLocked(st, rec, jobOutcome{state: JobCanceled, err: "canceled"})
		g.mu.Unlock()
		g.audit(entry)
		return nil
	}
	rec.cancelRequested = true
	c := rec.conn
	g.mu.Unlock()

	env, err := c.request(ctx, protocol.TypeJobCancel, protocol.JobCancel{JobID: jobID}, g.to.jobCancel)
	if err == nil {
		err = resultErr(env, "job cancel")
	}
	var perr protocol.Error
	if errors.As(err, &perr) && perr.Code == protocol.CodeNotFound {
		return ErrJobFinished
	}
	return err
}

// Jobs implements Hub.
func (g *Grid) Jobs(id HostID) []Job {
	g.mu.Lock()
	defer g.mu.Unlock()
	st, ok := g.hosts[id]
	if !ok {
		return nil
	}
	all := make([]*jobRec, 0, len(st.queue)+len(st.finished))
	all = append(all, st.finished...)
	all = append(all, st.queue...)
	sort.Slice(all, func(i, j int) bool { return all[i].seq > all[j].seq })
	out := make([]Job, len(all))
	for i, rec := range all {
		out[i] = rec.snapshot()
	}
	return out
}
