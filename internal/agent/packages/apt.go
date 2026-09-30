package packages

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/phabioo/nexara/internal/protocol"
)

// This file holds the platform independent part of the apt manager: input
// validation, argument lists, output parsing, lock waiting and job control.
// Everything that touches the system goes through the small interfaces below so
// tests can run with fakes; the real implementations live in apt_linux.go.

// ErrNotSupported is returned on platforms without an apt implementation.
var ErrNotSupported = errors.New("packages: apt is not supported on this platform")

// Fixed binaries and environment. Commands are never run through a shell.
const (
	aptGetPath     = "/usr/bin/apt-get"
	aptCachePath   = "/usr/bin/apt-cache"
	dpkgQueryPath  = "/usr/bin/dpkg-query"
	rebootRequired = "/var/run/reboot-required"
)

var aptEnv = []string{
	"DEBIAN_FRONTEND=noninteractive",
	"LC_ALL=C",
	"APT_LISTCHANGES_FRONTEND=none",
	"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
}

var aptLockPaths = []string{
	"/var/lib/dpkg/lock-frontend",
	"/var/lib/dpkg/lock",
	"/var/lib/apt/lists/lock",
	"/var/cache/apt/archives/lock",
}

// Timing and size limits.
const (
	lockWaitTimeout  = 10 * time.Minute
	lockPollInterval = time.Second
	lockReportEvery  = 15 * time.Second
	queryTimeout     = 2 * time.Minute
	maxLineBytes     = 4096
	truncatedSuffix  = " [truncated]"
)

var (
	pkgNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{1,127}(:[a-z0-9]+)?$`)
	queryRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{1,63}$`)

	instRe = regexp.MustCompile(`^Inst (\S+)(?: \[([^\]]+)\])? \((\S+)`)
	remvRe = regexp.MustCompile(`^Remv (\S+)`)
)

// ValidPackageName reports whether name is an acceptable package name
// (optionally with an ":arch" suffix).
func ValidPackageName(name string) bool { return pkgNameRe.MatchString(name) }

// ValidSearchQuery reports whether q is an acceptable search query.
func ValidSearchQuery(q string) bool { return queryRe.MatchString(q) }

// Command is one fixed command to execute (absolute path, argument list, env).
type Command struct {
	Path string
	Args []string
	Env  []string
}

// Runner executes a command to completion and delivers its output line by
// line. onLine may be called from several goroutines; the caller serializes.
// A non-zero exit status is reported through exitCode with a nil error; err is
// set when the command could not be started or ctx was cancelled (ctx.Err()).
type Runner interface {
	Run(ctx context.Context, cmd Command, onLine func(stream protocol.JobStream, line string)) (exitCode int, err error)
}

// LockProber reports whether another process holds the lock file at path.
// A missing file counts as not locked. The probe must not keep the lock.
type LockProber interface {
	Locked(path string) (bool, error)
}

// FileChecker reports whether a path exists.
type FileChecker interface {
	Exists(path string) bool
}

// Clock abstracts time so lock waiting can be tested.
type Clock interface {
	Now() time.Time
	// Sleep waits for d or until ctx is done (then it returns ctx.Err()).
	Sleep(ctx context.Context, d time.Duration) error
}

type osFiles struct{}

func (osFiles) Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

func (realClock) Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Apt implements Manager on top of apt-get, apt-cache and dpkg-query.
type Apt struct {
	runner Runner
	locks  LockProber
	files  FileChecker
	clock  Clock
}

var _ Manager = (*Apt)(nil)

func newApt(r Runner, l LockProber, f FileChecker, c Clock) *Apt {
	return &Apt{runner: r, locks: l, files: f, clock: c}
}

// --- listing ---------------------------------------------------------------

type installedPkg struct {
	name, version, summary string
	sizeBytes              int64
}

// List implements Manager.
func (a *Apt) List(ctx context.Context) (protocol.Packages, error) {
	installed, updates, err := a.snapshot(ctx)
	if err != nil {
		return protocol.Packages{}, err
	}
	out, err := a.capture(ctx, aptGetPath, "-s", "-o", "Debug::NoLocking=1", "autoremove")
	if err != nil {
		return protocol.Packages{}, err
	}
	orphans := parseRemv(out)
	return protocol.Packages{
		Items:          classify(installed, updates, orphans),
		RebootRequired: a.files.Exists(rebootRequired),
	}, nil
}

// snapshot returns the installed packages and the candidate versions of the
// packages a plain upgrade would upgrade.
func (a *Apt) snapshot(ctx context.Context) ([]installedPkg, map[string]string, error) {
	out, err := a.capture(ctx, dpkgQueryPath, "-W", "-f",
		`${binary:Package}\t${Version}\t${Installed-Size}\t${db:Status-Abbrev}\t${binary:Summary}\n`)
	if err != nil {
		return nil, nil, err
	}
	installed := parseDpkgQuery(out)
	sim, err := a.capture(ctx, aptGetPath, "-s", "-o", "Debug::NoLocking=1", "upgrade")
	if err != nil {
		return nil, nil, err
	}
	return installed, parseInst(sim), nil
}

// capture runs a read-only command and returns its stdout lines. A non-zero
// exit becomes an error carrying the last stderr line.
func (a *Apt) capture(ctx context.Context, path string, args ...string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	var (
		mu      sync.Mutex
		lines   []string
		lastErr string
	)
	code, err := a.runner.Run(ctx, Command{Path: path, Args: args, Env: aptEnv}, func(s protocol.JobStream, l string) {
		mu.Lock()
		defer mu.Unlock()
		switch s {
		case protocol.StreamStdout:
			lines = append(lines, l)
		case protocol.StreamStderr:
			if strings.TrimSpace(l) != "" {
				lastErr = l
			}
		}
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if code != 0 {
		return nil, fmt.Errorf("%s exited with code %d: %s", path, code, lastErr)
	}
	return lines, nil
}

// parseDpkgQuery parses lines of
// name TAB version TAB installed-size-KiB TAB status-abbrev TAB summary
// and keeps packages whose status is "installed".
func parseDpkgQuery(lines []string) []installedPkg {
	var res []installedPkg
	for _, l := range lines {
		f := strings.SplitN(l, "\t", 5)
		if len(f) < 4 {
			continue
		}
		st := f[3]
		if len(st) < 2 || st[1] != 'i' {
			continue
		}
		var kib int64
		if _, err := fmt.Sscanf(strings.TrimSpace(f[2]), "%d", &kib); err != nil || kib < 0 {
			kib = 0
		}
		p := installedPkg{name: f[0], version: f[1], sizeBytes: kib * 1024}
		if len(f) == 5 {
			p.summary = strings.TrimSpace(f[4])
		}
		res = append(res, p)
	}
	return res
}

// parseInst returns name -> candidate version for "Inst" lines of an apt
// simulation that replace an installed version (new installs are ignored).
func parseInst(lines []string) map[string]string {
	res := map[string]string{}
	for _, l := range lines {
		m := instRe.FindStringSubmatch(l)
		if m == nil || m[2] == "" {
			continue
		}
		res[m[1]] = m[3]
	}
	return res
}

// parseRemv returns the set of names on "Remv" lines of an apt simulation.
func parseRemv(lines []string) map[string]bool {
	res := map[string]bool{}
	for _, l := range lines {
		if m := remvRe.FindStringSubmatch(l); m != nil {
			res[m[1]] = true
		}
	}
	return res
}

func stripArch(name string) string {
	if i := strings.IndexByte(name, ':'); i >= 0 {
		return name[:i]
	}
	return name
}

func lookupCandidate(updates map[string]string, name string) (string, bool) {
	if v, ok := updates[name]; ok {
		return v, true
	}
	v, ok := updates[stripArch(name)]
	return v, ok
}

func lookupOrphan(orphans map[string]bool, name string) bool {
	return orphans[name] || orphans[stripArch(name)]
}

func stateRank(s protocol.PackageState) int {
	switch s {
	case protocol.PackageUpdate:
		return 0
	case protocol.PackageInstalled:
		return 1
	case protocol.PackageOrphaned:
		return 2
	}
	return 3
}

// classify builds the sorted package rows: updates first, then installed, then
// orphaned, each group by name.
func classify(installed []installedPkg, updates map[string]string, orphans map[string]bool) []protocol.Package {
	items := make([]protocol.Package, 0, len(installed))
	for _, p := range installed {
		row := protocol.Package{
			Name:             p.name,
			Summary:          p.summary,
			InstalledVersion: p.version,
			SizeBytes:        p.sizeBytes,
			State:            protocol.PackageInstalled,
		}
		if cand, ok := lookupCandidate(updates, p.name); ok {
			row.State = protocol.PackageUpdate
			row.CandidateVersion = cand
		} else if lookupOrphan(orphans, p.name) {
			row.State = protocol.PackageOrphaned
		}
		items = append(items, row)
	}
	sortPackages(items)
	return items
}

func sortPackages(items []protocol.Package) {
	sort.SliceStable(items, func(i, j int) bool {
		ri, rj := stateRank(items[i].State), stateRank(items[j].State)
		if ri != rj {
			return ri < rj
		}
		return items[i].Name < items[j].Name
	})
}

// --- search ----------------------------------------------------------------

// Search implements Manager.
func (a *Apt) Search(ctx context.Context, query string) ([]protocol.Package, error) {
	if !ValidSearchQuery(query) {
		return nil, fmt.Errorf("invalid search query %q", query)
	}
	lines, err := a.capture(ctx, aptCachePath, "search", "--names-only", "--", escapeQuery(query))
	if err != nil {
		return nil, err
	}
	found := parseSearch(lines)
	if len(found) == 0 {
		return []protocol.Package{}, nil
	}
	installed, updates, err := a.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	return mergeSearch(found, installed, updates), nil
}

// escapeQuery makes the two regex metacharacters allowed in queries literal
// (apt-cache search treats its argument as a regular expression).
func escapeQuery(q string) string {
	return strings.NewReplacer(".", `\.`, "+", `\+`).Replace(q)
}

type searchHit struct{ name, summary string }

// parseSearch parses "name - summary" lines of apt-cache search.
func parseSearch(lines []string) []searchHit {
	var res []searchHit
	for _, l := range lines {
		name, summary, _ := strings.Cut(l, " - ")
		name = strings.TrimSpace(name)
		if !ValidPackageName(name) {
			continue
		}
		res = append(res, searchHit{name: name, summary: strings.TrimSpace(summary)})
	}
	return res
}

func mergeSearch(hits []searchHit, installed []installedPkg, updates map[string]string) []protocol.Package {
	byName := make(map[string]installedPkg, len(installed))
	for _, p := range installed {
		byName[p.name] = p
		byName[stripArch(p.name)] = p
	}
	seen := map[string]bool{}
	var items []protocol.Package
	for _, h := range hits {
		if seen[h.name] {
			continue
		}
		seen[h.name] = true
		row := protocol.Package{Name: h.name, Summary: h.summary, State: protocol.PackageAvailable}
		if p, ok := byName[h.name]; ok {
			row.State = protocol.PackageInstalled
			row.InstalledVersion = p.version
			row.SizeBytes = p.sizeBytes
			if cand, ok := lookupCandidate(updates, p.name); ok {
				row.State = protocol.PackageUpdate
				row.CandidateVersion = cand
			}
		}
		items = append(items, row)
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	if len(items) > protocol.MaxSearchResults {
		items = items[:protocol.MaxSearchResults]
	}
	return items
}

// --- jobs ------------------------------------------------------------------

var aptGetBase = []string{
	"-y",
	"-o", "Dpkg::Options::=--force-confdef",
	"-o", "Dpkg::Options::=--force-confold",
}

func withBase(rest ...string) []string {
	return append(append([]string{}, aptGetBase...), rest...)
}

// jobArgs returns the apt-get argument lists (one per command, run in order)
// for a job. It validates the kind and the package name.
func jobArgs(job protocol.JobStart) ([][]string, error) {
	if !job.Kind.Valid() {
		return nil, fmt.Errorf("unknown job kind %q", job.Kind)
	}
	if job.Kind.NeedsPackage() && !ValidPackageName(job.Package) {
		return nil, fmt.Errorf("invalid package name %q", job.Package)
	}
	switch job.Kind {
	case protocol.JobAptUpdate:
		return [][]string{{"update"}}, nil
	case protocol.JobAptUpgrade:
		return [][]string{withBase("upgrade")}, nil
	case protocol.JobAptClean:
		return [][]string{withBase("autoremove"), {"clean"}}, nil
	case protocol.JobPkgInstall:
		return [][]string{withBase("install", "--", job.Package)}, nil
	case protocol.JobPkgRemove:
		return [][]string{withBase("remove", "--", job.Package)}, nil
	case protocol.JobPkgUpgrade:
		return [][]string{withBase("install", "--only-upgrade", "--", job.Package)}, nil
	}
	return nil, fmt.Errorf("unknown job kind %q", job.Kind)
}

// Run implements Manager.
func (a *Apt) Run(ctx context.Context, job protocol.JobStart, out func(protocol.JobOutput)) protocol.JobDone {
	done := protocol.JobDone{JobID: job.JobID}

	var mu sync.Mutex // one caller goroutine at a time, also across stdout/stderr
	emit := func(s protocol.JobStream, line string) {
		mu.Lock()
		defer mu.Unlock()
		out(protocol.JobOutput{JobID: job.JobID, Stream: s, Line: line})
	}
	finish := func(d protocol.JobDone) protocol.JobDone {
		d.RebootRequired = a.files.Exists(rebootRequired)
		return d
	}

	cmds, err := jobArgs(job)
	if err != nil {
		done.ExitCode = -1
		done.Error = err.Error()
		return finish(done)
	}

	for _, args := range cmds {
		if err := a.waitForLocks(ctx, func(l string) { emit(protocol.StreamStatus, l) }); err != nil {
			done.ExitCode = -1
			done.Error = errText(ctx, err)
			return finish(done)
		}
		code, err := a.runner.Run(ctx, Command{Path: aptGetPath, Args: args, Env: aptEnv}, emit)
		if ctx.Err() != nil {
			done.ExitCode = code
			if err != nil || code == 0 {
				done.ExitCode = -1
			}
			done.Error = "canceled"
			return finish(done)
		}
		if err != nil {
			done.ExitCode = -1
			done.Error = err.Error()
			return finish(done)
		}
		if code != 0 {
			done.ExitCode = code
			done.Error = fmt.Sprintf("apt-get %s exited with code %d", aptVerb(args), code)
			return finish(done)
		}
	}
	done.OK = true
	return finish(done)
}

// aptVerb returns the apt-get verb of an argument list for error text (never
// the package name, to keep messages short and stable).
func aptVerb(args []string) string {
	for _, a := range args {
		switch a {
		case "update", "upgrade", "autoremove", "clean", "install", "remove":
			return a
		}
	}
	return "command"
}

func errText(ctx context.Context, err error) string {
	if ctx.Err() != nil {
		return "canceled"
	}
	return err.Error()
}

// waitForLocks blocks while another process holds one of the apt/dpkg locks.
// It reports a status line every lockReportEvery and gives up after
// lockWaitTimeout.
func (a *Apt) waitForLocks(ctx context.Context, status func(string)) error {
	start := a.clock.Now()
	var nextReport time.Duration
	for {
		held, err := a.heldLock()
		if err != nil {
			return err
		}
		if held == "" {
			return nil
		}
		elapsed := a.clock.Now().Sub(start)
		if elapsed >= lockWaitTimeout {
			return fmt.Errorf("gave up after %d minutes waiting for the dpkg lock (%s is held by another process, e.g. unattended-upgrades)",
				int(lockWaitTimeout/time.Minute), held)
		}
		if elapsed >= nextReport {
			status(fmt.Sprintf("Waiting for dpkg lock … %ds", int(elapsed/time.Second)))
			nextReport = elapsed/lockReportEvery*lockReportEvery + lockReportEvery
		}
		if err := a.clock.Sleep(ctx, lockPollInterval); err != nil {
			return err
		}
	}
}

// heldLock returns the first lock path held by another process, or "".
func (a *Apt) heldLock() (string, error) {
	for _, p := range aptLockPaths {
		locked, err := a.locks.Locked(p)
		if err != nil {
			return "", fmt.Errorf("probing lock %s: %w", p, err)
		}
		if locked {
			return p, nil
		}
	}
	return "", nil
}

// --- output splitting ------------------------------------------------------

// scanLines splits r into lines (separators: \n, \r\n, \r) and passes each to
// emit. Lines longer than max bytes are cut at a rune boundary and end with
// truncatedSuffix, so emitted lines are never longer than max bytes.
func scanLines(r io.Reader, max int, emit func(string)) error {
	br := bufio.NewReaderSize(r, 32*1024)
	var (
		buf       []byte
		pendingCR bool
	)
	flush := func() {
		emit(finishLine(buf, max))
		buf = buf[:0]
	}
	for {
		b, err := br.ReadByte()
		if err != nil {
			if len(buf) > 0 {
				flush()
			}
			if err == io.EOF {
				return nil
			}
			return err
		}
		if pendingCR {
			pendingCR = false
			if b == '\n' {
				continue
			}
		}
		switch b {
		case '\n':
			flush()
		case '\r':
			flush()
			pendingCR = true
		default:
			if len(buf) <= max { // keep max+1 bytes to detect overflow
				buf = append(buf, b)
			}
		}
	}
}

func finishLine(buf []byte, max int) string {
	if len(buf) <= max {
		return strings.ToValidUTF8(string(buf), "�")
	}
	cut := max - len(truncatedSuffix)
	for cut > 0 && !utf8.RuneStart(buf[cut]) {
		cut--
	}
	return strings.ToValidUTF8(string(buf[:cut]), "�") + truncatedSuffix
}
