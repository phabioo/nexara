package demo

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/protocol"
)

type job struct {
	grid.Job
	ctx       context.Context
	cancel    context.CancelFunc
	cancelReq bool
}

func (j *job) copy() grid.Job {
	c := j.Job
	c.Output = append([]grid.JobLine(nil), c.Output...)
	return c
}

var pkgNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9+.\-]{0,99}$`)

// StartJob implements grid.Hub. Jobs of a host run one at a time in FIFO order.
func (h *Hub) StartJob(_ context.Context, actor grid.Actor, id grid.HostID, spec grid.JobSpec) (grid.Job, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	hst, err := h.usable(id, protocol.CapPackages)
	if err != nil {
		return grid.Job{}, err
	}
	if !spec.Kind.Valid() {
		return grid.Job{}, fmt.Errorf("%w: job kind %q", grid.ErrInvalidArgument, spec.Kind)
	}
	if spec.Kind.NeedsPackage() != (spec.Package != "") || (spec.Package != "" && !pkgNameRe.MatchString(spec.Package)) {
		return grid.Job{}, fmt.Errorf("%w: package %q for %s", grid.ErrInvalidArgument, spec.Package, spec.Kind)
	}
	if spec.Kind == protocol.JobPkgRemove || spec.Kind == protocol.JobPkgUpgrade {
		if i := hst.pkgIndex(spec.Package); i < 0 || hst.pkgs[i].State == protocol.PackageAvailable {
			return grid.Job{}, fmt.Errorf("%w: %s is not installed", grid.ErrInvalidArgument, spec.Package)
		}
	}
	for _, j := range hst.jobs {
		if !j.State.Finished() && j.Kind == spec.Kind && j.Package == spec.Package {
			return grid.Job{}, grid.ErrJobBusy
		}
	}

	h.jobSeq++
	j := &job{Job: grid.Job{
		ID: fmt.Sprintf("job-%06d", h.jobSeq), Host: id, Kind: spec.Kind, Package: spec.Package,
		State: grid.JobQueued, QueuedAt: h.now().UTC(), RequestedBy: actor.Operator,
	}}
	hst.jobs = append(hst.jobs, j)
	hst.trimJobs()
	h.emit(grid.Event{Kind: grid.EventJobQueued, Host: id, Payload: j.copy()})
	if !hst.workerActive {
		hst.workerActive = true
		h.begin(j)
		go h.worker(hst, j)
	}
	return j.copy(), nil
}

// begin marks j running. Callers hold h.mu.
func (h *Hub) begin(j *job) {
	j.State = grid.JobRunning
	j.StartedAt = h.now().UTC()
	j.ctx, j.cancel = context.WithCancel(h.ctx)
	h.emit(grid.Event{Kind: grid.EventJobStarted, Host: j.Host, Payload: j.copy()})
}

// CancelJob implements grid.Hub.
func (h *Hub) CancelJob(_ context.Context, _ grid.Actor, jobID string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, hst := range h.hosts {
		for _, j := range hst.jobs {
			if j.ID != jobID {
				continue
			}
			switch {
			case j.State.Finished():
				return grid.ErrJobFinished
			case j.State == grid.JobQueued:
				j.State = grid.JobCanceled
				j.FinishedAt = h.now().UTC()
				j.Error = "canceled"
				h.emit(grid.Event{Kind: grid.EventJobDone, Host: hst.info.ID, Payload: j.copy()})
			default:
				j.cancelReq = true
				j.cancel()
			}
			return nil
		}
	}
	return grid.ErrJobNotFound
}

// Jobs implements grid.Hub (newest first).
func (h *Hub) Jobs(id grid.HostID) []grid.Job {
	h.mu.Lock()
	defer h.mu.Unlock()
	hst := h.find(id)
	if hst == nil {
		return nil
	}
	out := make([]grid.Job, 0, len(hst.jobs))
	for i := len(hst.jobs) - 1; i >= 0; i-- {
		out = append(out, hst.jobs[i].copy())
	}
	return out
}

func (hst *host) pkgIndex(name string) int {
	for i, p := range hst.pkgs {
		if p.Name == name {
			return i
		}
	}
	return -1
}

// trimJobs drops the oldest finished jobs beyond the history bound.
func (hst *host) trimJobs() {
	for len(hst.jobs) > maxJobHistory {
		if !hst.jobs[0].State.Finished() {
			return
		}
		hst.jobs = hst.jobs[1:]
	}
}

// worker runs first and then every queued job of the host.
func (h *Hub) worker(hst *host, j *job) {
	for {
		h.run(hst, j)
		h.mu.Lock()
		j = nil
		for _, c := range hst.jobs {
			if c.State == grid.JobQueued {
				j = c
				break
			}
		}
		if j == nil {
			hst.workerActive = false
			h.mu.Unlock()
			return
		}
		h.begin(j)
		h.mu.Unlock()
	}
}

type outLine struct {
	stream protocol.JobStream
	text   string
}

func out(text string) outLine { return outLine{protocol.StreamStdout, text} }

func fmtSize(b int64) string {
	switch {
	case b >= 10_000_000:
		return fmt.Sprintf("%d MB", (b+500_000)/1_000_000)
	case b >= 1_000_000:
		return fmt.Sprintf("%.1f MB", float64(b)/1e6)
	default:
		return fmt.Sprintf("%d KB", (b+500)/1000)
	}
}

func (h *Hub) run(hst *host, j *job) {
	h.mu.Lock()
	lines, apply := h.script(hst, j)
	h.mu.Unlock()

	for _, l := range lines {
		if j.ctx.Err() != nil {
			break
		}
		h.mu.Lock()
		jl := grid.JobLine{Stream: l.stream, Line: l.text}
		j.Output = append(j.Output, jl)
		if len(j.Output) > maxJobOutput {
			j.Output = j.Output[len(j.Output)-maxJobOutput:]
		}
		h.emit(grid.Event{Kind: grid.EventJobOutput, Host: hst.info.ID, Payload: grid.JobOutputEvent{JobID: j.ID, Line: jl}})
		h.mu.Unlock()
		if !h.wait(j.ctx, jobLineDelay) {
			break
		}
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	j.FinishedAt = h.now().UTC()
	if j.ctx.Err() != nil {
		j.State = grid.JobCanceled
		j.ExitCode = 130
		j.Error = "canceled"
	} else {
		j.State = grid.JobDone
		j.OK = true
		if apply != nil {
			j.RebootRequired = apply()
			h.emit(grid.Event{Kind: grid.EventPackages, Host: hst.info.ID, Payload: hst.packages()})
		}
	}
	j.cancel()
	h.emit(grid.Event{Kind: grid.EventJobDone, Host: hst.info.ID, Payload: j.copy()})
}

// script builds the output of j and the effect it has on the package list when
// it succeeds (returns whether a reboot is now required). Callers hold h.mu.
func (h *Hub) script(hst *host, j *job) ([]outLine, func() bool) {
	switch j.Kind {
	case protocol.JobAptUpdate:
		n := 0
		for _, p := range hst.pkgs {
			if p.State == protocol.PackageUpdate {
				n++
			}
		}
		return []outLine{
			out("Hit:1 http://deb.debian.org/debian bookworm InRelease"),
			out("Get:2 http://deb.debian.org/debian-security bookworm-security InRelease [48.0 kB]"),
			out("Get:3 http://archive.raspberrypi.com/debian bookworm InRelease [23.6 kB]"),
			out("Fetched 71.6 kB in 1s (72.1 kB/s)"),
			out("Reading package lists... Done"),
			out("Building dependency tree... Done"),
			out(fmt.Sprintf("%d packages can be upgraded. Run 'apt list --upgradable' to see them.", n)),
		}, nil

	case protocol.JobAptUpgrade, protocol.JobPkgUpgrade:
		var upd []protocol.Package
		for _, p := range hst.pkgs {
			if p.State == protocol.PackageUpdate && (j.Kind == protocol.JobAptUpgrade || p.Name == j.Package) {
				upd = append(upd, p)
			}
		}
		var ls []outLine
		if !hst.lockWaited {
			hst.lockWaited = true
			ls = append(ls,
				outLine{protocol.StreamStatus, "Waiting for dpkg lock (held by unattended-upgr, pid 1873)"},
				outLine{protocol.StreamStatus, "Lock released after 4 s"})
		}
		ls = append(ls, out("Reading package lists... Done"), out("Building dependency tree... Done"), out("Calculating upgrade... Done"))
		if len(upd) == 0 {
			return append(ls, out("0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.")), nil
		}
		names := make([]string, len(upd))
		for i, p := range upd {
			names[i] = p.Name
		}
		ls = append(ls, out("The following packages will be upgraded:"), out("  "+strings.Join(names, " ")))
		for i, p := range upd {
			ls = append(ls, out(fmt.Sprintf("Get:%d http://deb.debian.org/debian bookworm/main arm64 %s %s [%s]", i+1, p.Name, p.CandidateVersion, fmtSize(p.SizeBytes))))
		}
		for _, p := range upd {
			ls = append(ls, out(fmt.Sprintf("Unpacking %s (%s) ...", p.Name, p.CandidateVersion)))
		}
		for _, p := range upd {
			ls = append(ls, out(fmt.Sprintf("Setting up %s (%s) ...", p.Name, p.CandidateVersion)))
		}
		ls = append(ls, out("Processing triggers for man-db (2.11.2-2) ..."))
		kernel := false
		for _, p := range upd {
			kernel = kernel || strings.HasPrefix(p.Name, "linux-image")
		}
		if kernel {
			ls = append(ls, outLine{protocol.StreamStderr, "W: A reboot is required to finish the kernel update."})
		}
		return ls, func() bool {
			for _, u := range upd {
				if i := hst.pkgIndex(u.Name); i >= 0 {
					hst.pkgs[i].InstalledVersion = hst.pkgs[i].CandidateVersion
					hst.pkgs[i].CandidateVersion = ""
					hst.pkgs[i].State = protocol.PackageInstalled
				}
			}
			h.setReboot(hst, kernel)
			return kernel
		}

	case protocol.JobAptClean:
		var orph []protocol.Package
		for _, p := range hst.pkgs {
			if p.State == protocol.PackageOrphaned {
				orph = append(orph, p)
			}
		}
		names := make([]string, len(orph))
		for i, p := range orph {
			names[i] = p.Name
		}
		ls := []outLine{out("Reading package lists... Done"), out("Building dependency tree... Done")}
		if len(orph) > 0 {
			ls = append(ls, out("The following packages will be REMOVED:"), out("  "+strings.Join(names, " ")))
			for _, p := range orph {
				ls = append(ls, out(fmt.Sprintf("Removing %s (%s) ...", p.Name, p.InstalledVersion)))
			}
		} else {
			ls = append(ls, out("0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded."))
		}
		ls = append(ls, out("Cleaning package cache ..."))
		return ls, func() bool {
			kept := hst.pkgs[:0:0]
			for _, p := range hst.pkgs {
				if p.State != protocol.PackageOrphaned {
					kept = append(kept, p)
				}
			}
			hst.pkgs = kept
			return hst.reboot
		}

	case protocol.JobPkgInstall:
		ls := []outLine{out("Reading package lists... Done"), out("Building dependency tree... Done")}
		if i := hst.pkgIndex(j.Package); i >= 0 && hst.pkgs[i].State != protocol.PackageAvailable {
			return append(ls, out(j.Package+" is already the newest version ("+hst.pkgs[i].InstalledVersion+").")), nil
		}
		p := lookupCatalog(hst, j.Package)
		ls = append(ls,
			out("The following NEW packages will be installed:"), out("  "+p.Name),
			out(fmt.Sprintf("Get:1 http://deb.debian.org/debian bookworm/main arm64 %s %s [%s]", p.Name, p.CandidateVersion, fmtSize(p.SizeBytes))),
			out(fmt.Sprintf("Unpacking %s (%s) ...", p.Name, p.CandidateVersion)),
			out(fmt.Sprintf("Setting up %s (%s) ...", p.Name, p.CandidateVersion)))
		return ls, func() bool {
			p.InstalledVersion, p.CandidateVersion, p.State = p.CandidateVersion, "", protocol.PackageInstalled
			if i := hst.pkgIndex(p.Name); i >= 0 {
				hst.pkgs[i] = p
			} else {
				hst.pkgs = append(hst.pkgs, p)
			}
			return hst.reboot
		}

	default: // JobPkgRemove
		ver := ""
		if i := hst.pkgIndex(j.Package); i >= 0 {
			ver = hst.pkgs[i].InstalledVersion
		}
		return []outLine{
			out("Reading package lists... Done"), out("Building dependency tree... Done"),
			out("The following packages will be REMOVED:"), out("  " + j.Package),
			out(fmt.Sprintf("Removing %s (%s) ...", j.Package, ver)),
			out("Processing triggers for man-db (2.11.2-2) ..."),
		}, func() bool {
			if i := hst.pkgIndex(j.Package); i >= 0 {
				hst.pkgs = append(hst.pkgs[:i:i], hst.pkgs[i+1:]...)
			}
			return hst.reboot
		}
	}
}

// lookupCatalog returns the package to install: a listed "available" one, a
// catalog entry, or a generic stand-in for any other valid name.
func lookupCatalog(hst *host, name string) protocol.Package {
	if i := hst.pkgIndex(name); i >= 0 {
		return hst.pkgs[i]
	}
	for _, c := range catalog {
		if c.Name == name {
			return c
		}
	}
	return pkg(name, "Package "+name, "", "1.0-1", 500_000, protocol.PackageAvailable)
}

func (h *Hub) setReboot(hst *host, kernel bool) {
	if kernel {
		hst.reboot = true
	}
	hst.info.RebootRequired = hst.reboot
}

// SearchPackages implements grid.Hub.
func (h *Hub) SearchPackages(_ context.Context, id grid.HostID, query string) ([]protocol.Package, error) {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" || len(q) > 64 || !regexp.MustCompile(`^[a-z0-9+.\-_]+$`).MatchString(q) {
		return nil, fmt.Errorf("%w: search query %q", grid.ErrInvalidArgument, query)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	hst, err := h.usable(id, protocol.CapPackages)
	if err != nil {
		return nil, err
	}
	var res []protocol.Package
	for _, p := range hst.pkgs {
		if strings.Contains(p.Name, q) {
			res = append(res, p)
		}
	}
	for _, c := range catalog {
		if strings.Contains(c.Name, q) && hst.pkgIndex(c.Name) < 0 {
			res = append(res, c)
		}
	}
	if len(res) > protocol.MaxSearchResults {
		res = res[:protocol.MaxSearchResults]
	}
	return res, nil
}
