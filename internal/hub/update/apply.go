package update

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"time"

	"github.com/phabioo/nexara/internal/buildinfo"
)

// Helper timing.
const (
	defaultHealthTimeout = 60 * time.Second
	healthPoll           = time.Second
	backupTimeout        = 10 * time.Minute
	installTimeout       = 15 * time.Minute
	logTailBytes         = 8 << 10
)

// ApplyOptions configure Apply, the root helper behind `nexus update-apply`.
type ApplyOptions struct {
	// DataDir and StateDir default to the package locations. The helper never
	// reads them from nexus.yaml (see DefaultDataDir).
	DataDir  string
	StateDir string
	// NoRollback installs even though no verified copy of the running version
	// is available to fall back to.
	NoRollback bool
	// AllowDowngrade lets the helper install an older (or the same) version.
	// Only the operator can say so, on the command line: the hub's request
	// file is not trusted for it.
	AllowDowngrade bool

	CurrentVersion string // default buildinfo.Version
	Arch           string // default: this machine
	Key            ed25519.PublicKey
	Runner         Runner // default ExecRunner
	// Exe is the nexus binary that creates the pre-update backup; default is
	// this executable.
	Exe string
	// Health asks the hub for its version; required.
	Health        func(ctx context.Context) (string, error)
	HealthTimeout time.Duration
	Now           func() time.Time
	Sleep         func(ctx context.Context, d time.Duration)
	// CheckOwner decides whether a file in the updates directory is owned by
	// who may own it. The default accepts root and the nexus user.
	CheckOwner func(fs.FileInfo) error
	// Log receives progress lines (the journal).
	Log io.Writer
}

func (o ApplyOptions) withDefaults() (ApplyOptions, error) {
	if o.DataDir == "" {
		o.DataDir = DefaultDataDir
	}
	if o.StateDir == "" {
		o.StateDir = DefaultStateDir
	}
	if o.CurrentVersion == "" {
		o.CurrentVersion = buildinfo.Version
	}
	if o.Arch == "" {
		arch, err := HostArch()
		if err != nil {
			return o, err
		}
		o.Arch = arch
	}
	if o.Runner == nil {
		o.Runner = ExecRunner{}
	}
	if o.Exe == "" {
		exe, err := os.Executable()
		if err != nil {
			return o, fmt.Errorf("cannot locate the nexus binary: %w", err)
		}
		o.Exe = exe
	}
	if o.Health == nil {
		return o, errors.New("update: ApplyOptions.Health is required")
	}
	if o.HealthTimeout <= 0 {
		o.HealthTimeout = defaultHealthTimeout
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Sleep == nil {
		o.Sleep = func(ctx context.Context, d time.Duration) {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
			case <-t.C:
			}
		}
	}
	if o.CheckOwner == nil {
		check, err := nexusOwnerCheck()
		if err != nil {
			return o, err
		}
		o.CheckOwner = check
	}
	if o.Log == nil {
		o.Log = io.Discard
	}
	return o, nil
}

// nexusOwnerCheck accepts files owned by root or the nexus user: the only
// accounts that may have put something into the updates directory.
func nexusOwnerCheck() (func(fs.FileInfo) error, error) {
	u, err := user.Lookup("nexus")
	if err != nil {
		return nil, fmt.Errorf("the nexus user does not exist: %w", err)
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("bad uid %q for the nexus user", u.Uid)
	}
	return ownerOneOf(0, uint32(uid)), nil
}

func ownerOneOf(uids ...uint32) func(fs.FileInfo) error {
	return func(fi fs.FileInfo) error {
		got, ok := fileUID(fi)
		if !ok {
			return nil
		}
		for _, u := range uids {
			if got == u {
				return nil
			}
		}
		return fmt.Errorf("%s is owned by uid %d", fi.Name(), got)
	}
}

// Apply processes the pending install request. It never trusts the hub: the
// request is only a pointer; the staged files are copied into a root-owned
// work directory, their signature and checksum verified there, and apt
// installs that copy. It returns ErrNoRequest if nothing is pending. Every
// other outcome, including refusals, is written to updates/result.json and
// returned; the error is only for failures before a result can be written.
func Apply(ctx context.Context, o ApplyOptions) (Result, error) {
	o, err := o.withDefaults()
	if err != nil {
		return Result{}, err
	}
	if err := os.MkdirAll(o.StateDir, 0o755); err != nil {
		return Result{}, err
	}
	unlock, err := lockFile(filepath.Join(o.StateDir, "apply.lock"))
	if err != nil {
		return Result{}, err
	}
	defer unlock()

	root, err := openTrustedRoot(filepath.Join(o.DataDir, UpdatesDirName), o.CheckOwner)
	if err != nil {
		return Result{}, err
	}
	defer root.Close()

	// Claim the request: after the rename the path unit has nothing left to
	// trigger on, and the hub sees "installing" through applying.json.
	if err := root.Rename(RequestFile, ApplyingFile); err != nil {
		if isNotExist(err) {
			return Result{}, ErrNoRequest
		}
		return Result{}, fmt.Errorf("cannot claim the request: %w", err)
	}

	a := &applier{ApplyOptions: o, root: root, tail: &tailBuffer{max: logTailBytes}}
	a.work = filepath.Join(o.StateDir, "work")
	defer os.RemoveAll(a.work)

	res := a.processClaimed(ctx)
	if err := a.writeRoot(ResultFile, res, 0o644); err != nil {
		return res, fmt.Errorf("cannot write the result: %w", err)
	}
	_ = root.Remove(ApplyingFile)
	return res, nil
}

// MsgNoRollback starts the message of an update refused for lack of rollback
// material; the Settings card recognizes it. NoRollbackCommand is the one
// command that updates anyway, without a safety net.
const (
	MsgNoRollback     = "no rollback material for the running version"
	NoRollbackCommand = "sudo nexus update-apply --no-rollback"
)

type applier struct {
	ApplyOptions
	root  *os.Root
	work  string
	tail  *tailBuffer
	req   Request
	start time.Time
}

func (a *applier) logf(format string, args ...any) {
	line := fmt.Sprintf(format, args...) + "\n"
	io.WriteString(a.Log, line)
	io.WriteString(a.tail, line)
}

// openTrustedRoot opens the hub-owned updates directory. Everything below is
// reached through the returned os.Root, so a symlink swapped in by the hub
// user cannot lead the helper out of the directory.
func openTrustedRoot(path string, owner func(fs.FileInfo) error) (*os.Root, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		if isNotExist(err) {
			return nil, ErrNoRequest
		}
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("%s is not a directory (symlinks are refused)", path)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	// The path may have been swapped between Lstat and OpenRoot (OpenRoot
	// follows a final symlink): the opened directory must be the one seen.
	if err := sameDir(root, fi); err != nil {
		root.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := checkTrustedDir(root, owner); err != nil {
		root.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return root, nil
}

// sameDir fails unless root is the directory that fi (from Lstat) describes.
func sameDir(root *os.Root, fi fs.FileInfo) error {
	st, err := root.Stat(".")
	if err != nil {
		return err
	}
	if !os.SameFile(st, fi) {
		return errors.New("the directory was replaced while it was being opened")
	}
	return nil
}

// checkTrustedDir validates the opened directory itself (not its path).
func checkTrustedDir(root *os.Root, owner func(fs.FileInfo) error) error {
	fi, err := root.Stat(".")
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return errors.New("not a directory")
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("directory is writable by group or others (mode %v)", fi.Mode().Perm())
	}
	if owner != nil {
		return owner(fi)
	}
	return nil
}

// readRootFile reads a small regular file through root.
func readRootFile(root *os.Root, name string, max int64, owner func(fs.FileInfo) error) ([]byte, error) {
	f, err := openRootFile(root, name, max, owner)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readAllLimited(f, max)
}

// openRootFile opens a regular, non-symlink, size-limited, correctly owned
// file; the checks run on the opened file as well, against a swap in between.
func openRootFile(root *os.Root, name string, max int64, owner func(fs.FileInfo) error) (*os.File, error) {
	check := func(fi fs.FileInfo) error {
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("%s is not a regular file", name)
		}
		if fi.Size() > max {
			return fmt.Errorf("%w: %s", ErrTooLarge, name)
		}
		if owner != nil {
			return owner(fi)
		}
		return nil
	}
	fi, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if err := check(fi); err != nil {
		return nil, err
	}
	// os.Root follows symlinks that stay inside the root, whatever the flags
	// say, so the opened descriptor is compared with what Lstat showed.
	f, err := root.OpenFile(name, os.O_RDONLY|openFlags, 0)
	if err != nil {
		return nil, err
	}
	if err := verifyOpened(f, fi, name, check); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// verifyOpened checks the opened descriptor: it must be the file that Lstat
// described (not a link or FIFO swapped in since) and still pass the checks.
func verifyOpened(f *os.File, lstat fs.FileInfo, name string, check func(fs.FileInfo) error) error {
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(st, lstat) {
		return fmt.Errorf("%s was replaced while it was being opened", name)
	}
	return check(st)
}

func (a *applier) writeRoot(name string, v any, mode fs.FileMode) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := tempName()
	f, err := a.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = a.root.Rename(tmp, name)
	}
	if err != nil {
		_ = a.root.Remove(tmp)
	}
	return err
}

// processClaimed does the actual work and returns the result to record.
func (a *applier) processClaimed(ctx context.Context) (res Result) {
	a.start = a.Now()
	res = Result{Status: StatusError, PreviousVersion: a.CurrentVersion, StartedAt: a.start}
	defer func() {
		res.FinishedAt = a.Now()
		res.LogTail = a.tail.String()
	}()
	fail := func(phase string, err error) Result {
		res.Phase, res.Message = phase, err.Error()
		a.logf("update failed in phase %s: %v", phase, err)
		return res
	}

	raw, err := readRootFile(a.root, ApplyingFile, MaxRequestBytes, a.CheckOwner)
	if err != nil {
		return fail(PhaseVerify, fmt.Errorf("%w: cannot read the request: %v", ErrBadBundle, err))
	}
	var req Request
	if err := json.Unmarshal(raw, &req); err != nil {
		return fail(PhaseVerify, fmt.Errorf("%w: bad request file: %v", ErrBadBundle, err))
	}
	res.Version, res.RequestedBy = req.Version, req.RequestedBy
	if err := req.validate(); err != nil {
		return fail(PhaseVerify, err)
	}
	if req.Arch != a.Arch {
		return fail(PhaseVerify, fmt.Errorf("%w: request is for %s, this machine is %s", ErrWrongArch, req.Arch, a.Arch))
	}
	a.req = req
	a.logf("update %s -> %s requested by %q", a.CurrentVersion, req.Version, req.RequestedBy)

	// --- verify (everything from the hub is re-checked) ---
	a.phase(PhaseVerify)
	if err := os.RemoveAll(a.work); err != nil {
		return fail(PhaseVerify, err)
	}
	if err := os.MkdirAll(a.work, 0o755); err != nil {
		return fail(PhaseVerify, err)
	}
	staged, err := a.root.OpenRoot(req.Version)
	if err != nil {
		return fail(PhaseVerify, fmt.Errorf("%w: staged directory %s: %v", ErrNotStaged, req.Version, err))
	}
	defer staged.Close()
	if fi, err := a.root.Lstat(req.Version); err != nil || !fi.IsDir() {
		return fail(PhaseVerify, fmt.Errorf("%w: %s is not a directory", ErrNotStaged, req.Version))
	} else if err := sameDir(staged, fi); err != nil {
		return fail(PhaseVerify, fmt.Errorf("%w: %s: %v", ErrNotStaged, req.Version, err))
	}
	if err := checkTrustedDir(staged, a.CheckOwner); err != nil {
		return fail(PhaseVerify, fmt.Errorf("%w: staged directory: %v", ErrBadBundle, err))
	}
	nb, err := a.loadBundle(staged, a.CheckOwner, req.Deb, filepath.Join(a.work, "new"))
	if err != nil {
		return fail(PhaseVerify, err)
	}
	if nb.digest != req.SHA256 {
		return fail(PhaseVerify, fmt.Errorf("%w: the request names a different package than the signed sums", ErrChecksum))
	}
	if _, err := checkPolicy(req.Deb, a.Arch, a.CurrentVersion, a.AllowDowngrade); err != nil {
		return fail(PhaseVerify, err)
	}
	a.logf("package %s verified (signature and sha256 %s)", req.Deb, nb.digest[:12])

	var rb *loadedBundle
	if !a.NoRollback {
		var why string
		rb, why = a.prepareRollback()
		if rb == nil {
			return fail(PhaseVerify, fmt.Errorf(MsgNoRollback+" (%s); "+
				"to update without a safety net, stop nexus-update.path, request the update again and run `"+NoRollbackCommand+"`", why))
		}
		a.logf("rollback material for %s is ready", a.CurrentVersion)
	}

	// --- backup ---
	a.phase(PhaseBackup)
	if err := a.run(ctx, backupTimeout, Command{Name: a.Exe, Args: []string{"backup", "create", "--reason", "pre-update"}}); err != nil {
		hint := ""
		if exitCode(err) == 2 {
			hint = " (this nexus binary has no backup command)"
		}
		return fail(PhaseBackup, fmt.Errorf("the pre-update backup failed, nothing was changed%s: %w", hint, err))
	}

	// --- install; from here on a failure is rolled back ---
	a.phase(PhaseInstall)
	if err := a.run(ctx, installTimeout, aptInstall(nb.debPath, false)); err != nil {
		return a.rollback(ctx, res, PhaseInstall, fmt.Errorf("apt-get install failed: %w", err), rb)
	}
	a.phase(PhaseHealth)
	if err := a.waitHealthy(ctx, req.Version); err != nil {
		return a.rollback(ctx, res, PhaseHealth, err, rb)
	}

	res.Status = StatusOK
	res.Message = fmt.Sprintf("updated from %s to %s", a.CurrentVersion, req.Version)
	if err := a.saveInstalled(nb); err != nil {
		res.Message += "; the rollback copy of the new version could not be saved: " + err.Error()
		a.logf("saving rollback material failed: %v", err)
	}
	a.logf("%s", res.Message)
	return res
}

// phase records the current step where the hub can read it.
func (a *applier) phase(name string) {
	a.logf("phase %s", name)
	ap := Applying{Request: a.req, Phase: name, StartedAt: a.start}
	if err := a.writeRoot(ApplyingFile, ap, 0o644); err != nil {
		a.logf("cannot record phase %s: %v", name, err)
	}
}

// run executes a command, streaming its output to the journal and the tail.
func (a *applier) run(ctx context.Context, timeout time.Duration, c Command) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	a.logf("$ %s", c)
	return a.Runner.Run(ctx, c, io.MultiWriter(a.Log, a.tail))
}

// aptInstall is the apt-get call for a local package. Argument list, no
// shell. force-confold keeps local config files without asking; the lock
// timeout waits for a running unattended-upgrade.
func aptInstall(debPath string, downgrade bool) Command {
	args := []string{"install", "-y",
		"-o", "Dpkg::Options::=--force-confold",
		"-o", "DPkg::Lock::Timeout=300"}
	if downgrade {
		args = append(args, "--allow-downgrades")
	}
	return Command{Name: "apt-get", Args: append(args, debPath)}
}

// waitHealthy polls the hub until it reports version want or the timeout ends.
func (a *applier) waitHealthy(ctx context.Context, want string) error {
	deadline := a.Now().Add(a.HealthTimeout)
	last := "no answer"
	for {
		v, err := a.Health(ctx)
		switch {
		case err == nil && normalizeVersion(v) == normalizeVersion(want):
			a.logf("hub reports version %s", v)
			return nil
		case err == nil:
			last = "hub reports " + v
		default:
			last = err.Error()
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !a.Now().Before(deadline) {
			return fmt.Errorf("the hub did not report version %s within %s (%s)", want, a.HealthTimeout, last)
		}
		a.Sleep(ctx, healthPoll)
	}
}

// rollback reinstalls the previous package after a failed install or health
// check and reports what happened.
func (a *applier) rollback(ctx context.Context, res Result, phase string, cause error, rb *loadedBundle) Result {
	res.Phase = phase
	a.logf("update failed in phase %s: %v", phase, cause)
	if rb == nil {
		res.Message = fmt.Sprintf("%v; no rollback copy of %s was available, the system may need manual repair", cause, a.CurrentVersion)
		return res
	}
	a.phase(PhaseRollback)
	// The caller's context may be what cancelled us (SIGTERM); the rollback
	// still has to run.
	rctx := context.WithoutCancel(ctx)
	if err := a.run(rctx, installTimeout, aptInstall(rb.debPath, true)); err != nil {
		res.Message = fmt.Sprintf("%v; reinstalling %s failed too (%v): fix manually with `sudo apt install %s`",
			cause, a.CurrentVersion, err, rb.debPath)
		return res
	}
	if err := a.waitHealthy(rctx, a.CurrentVersion); err != nil {
		res.Message = fmt.Sprintf("%v; %s was reinstalled but is not healthy: %v", cause, a.CurrentVersion, err)
		return res
	}
	res.Status = StatusRolledBack
	res.Message = fmt.Sprintf("update to %s failed (%v); restored %s", a.req.Version, cause, a.CurrentVersion)
	a.logf("%s", res.Message)
	return res
}
