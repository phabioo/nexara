package update

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// fakeRunner records the commands and answers them through handler.
type fakeRunner struct {
	cmds    []Command
	handler func(n int, c Command, out *bytes.Buffer) error
}

func (f *fakeRunner) Run(_ context.Context, c Command, out io.Writer) error {
	f.cmds = append(f.cmds, c)
	var buf bytes.Buffer
	var err error
	if f.handler != nil {
		err = f.handler(len(f.cmds)-1, c, &buf)
	}
	_, _ = out.Write(buf.Bytes())
	return err
}

func (f *fakeRunner) names() []string {
	var out []string
	for _, c := range f.cmds {
		switch {
		case c.Name == "apt-get" && contains(strings.Join(c.Args, " "), "--allow-downgrades"):
			out = append(out, "apt-rollback")
		case c.Name == "apt-get":
			out = append(out, "apt")
		default:
			out = append(out, "backup")
		}
	}
	return out
}

type applyEnv struct {
	t        *testing.T
	dataDir  string
	stateDir string
	updates  string
	key      keyPair
	clock    *fakeClock
	runner   *fakeRunner
	log      bytes.Buffer

	// reported is what the fake hub answers on the admin socket.
	reported   string
	healthErr  error
	healthHits int
	// healthAfter makes the hub answer only after this many polls (0: at once).
	healthAfter int
}

func newApplyEnv(t *testing.T) *applyEnv {
	t.Helper()
	e := &applyEnv{t: t, key: newKey(t), clock: newClock(), runner: &fakeRunner{}, reported: "0.1.0"}
	root := t.TempDir()
	e.dataDir = filepath.Join(root, "data")
	e.stateDir = filepath.Join(root, "state")
	e.updates = filepath.Join(e.dataDir, UpdatesDirName)
	if err := os.MkdirAll(e.updates, 0o700); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *applyEnv) opts() ApplyOptions {
	return ApplyOptions{
		DataDir: e.dataDir, StateDir: e.stateDir,
		CurrentVersion: "0.1.0", Arch: "arm64", Key: e.key.pub,
		Runner: e.runner, Exe: "/usr/bin/nexus",
		Health: func(context.Context) (string, error) {
			e.healthHits++
			if e.healthErr != nil {
				return "", e.healthErr
			}
			if e.healthHits <= e.healthAfter {
				return "", errors.New("connection refused")
			}
			return e.reported, nil
		},
		HealthTimeout: 60 * time.Second,
		Now:           e.clock.Now,
		Sleep:         func(_ context.Context, d time.Duration) { e.clock.Advance(d) },
		CheckOwner:    func(fs.FileInfo) error { return nil },
		Log:           &e.log,
	}
}

// stage writes a signed bundle of version into the updates dir and a matching request.
func (e *applyEnv) stage(version string) testBundle {
	e.t.Helper()
	b := makeBundle(e.t, e.key, version, "arm64")
	b.writeStaged(e.t, e.updates)
	e.request(b)
	return b
}

func (e *applyEnv) request(b testBundle) {
	e.t.Helper()
	req := Request{Version: b.version, Arch: b.arch, Deb: b.debName, SHA256: debDigest(b), RequestedBy: "alice", RequestedAt: e.clock.Now()}
	if err := writeJSONAtomic(e.updates, RequestFile, req, 0o600); err != nil {
		e.t.Fatal(err)
	}
}

func debDigest(b testBundle) string {
	d, _ := parseSumsDigest(b.sums, b.debName)
	return d
}

// seedInstalled stores rollback material for version in the state dir.
func (e *applyEnv) seedInstalled(version string) {
	e.t.Helper()
	b := makeBundle(e.t, e.key, version, "arm64")
	dir := filepath.Join(e.stateDir, installedDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		e.t.Fatal(err)
	}
	b.writeFiles(e.t, dir, 0o644)
}

func (e *applyEnv) apply() (Result, error) {
	e.t.Helper()
	return Apply(context.Background(), e.opts())
}

func (e *applyEnv) result() Result {
	e.t.Helper()
	var r Result
	if err := readJSON(filepath.Join(e.updates, ResultFile), MaxResultBytes, &r); err != nil {
		e.t.Fatalf("result.json: %v", err)
	}
	return r
}

func (e *applyEnv) mustNotExist(name string) {
	e.t.Helper()
	if _, err := os.Lstat(filepath.Join(e.updates, name)); !os.IsNotExist(err) {
		e.t.Fatalf("%s should not exist (err %v)", name, err)
	}
}

// installsNew makes the fake apt install the new version: the hub then
// reports it. Rollback installs make it report the old one again.
func (e *applyEnv) aptHandler(newVersion string, failInstall bool) func(int, Command, *bytes.Buffer) error {
	return func(_ int, c Command, out *bytes.Buffer) error {
		if c.Name != "apt-get" {
			return nil
		}
		isRollback := contains(strings.Join(c.Args, " "), "--allow-downgrades")
		switch {
		case isRollback:
			e.reported = "0.1.0"
			out.WriteString("Selecting previously unselected package nexus.\nrollback done\n")
		case failInstall:
			out.WriteString("E: Sub-process /usr/bin/dpkg returned an error code (1)\n")
			return fmt.Errorf("exit status 100")
		default:
			e.reported = newVersion
			out.WriteString("Setting up nexus (" + newVersion + ") ...\n")
		}
		return nil
	}
}

func TestApplySuccess(t *testing.T) {
	e := newApplyEnv(t)
	e.seedInstalled("0.1.0")
	b := e.stage("0.2.0")
	var phases []string
	e.runner.handler = func(n int, c Command, out *bytes.Buffer) error {
		var ap Applying
		if err := readJSON(filepath.Join(e.updates, ApplyingFile), MaxRequestBytes, &ap); err != nil {
			t.Errorf("applying.json while running %v: %v", c.Name, err)
		}
		phases = append(phases, ap.Phase)
		if c.Name == "apt-get" {
			// The package apt installs is the root-owned copy, not the hub's file.
			last := c.Args[len(c.Args)-1]
			if !strings.HasPrefix(last, e.stateDir) || strings.HasPrefix(last, e.updates) {
				t.Errorf("apt installs %s", last)
			}
			if got, err := os.ReadFile(last); err != nil || !bytes.Equal(got, b.deb) {
				t.Errorf("work copy: %v", err)
			}
		}
		return e.aptHandler("0.2.0", false)(n, c, out)
	}
	e.healthAfter = 3

	res, err := e.apply()
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusOK || res.Version != "0.2.0" || res.PreviousVersion != "0.1.0" || res.RequestedBy != "alice" {
		t.Fatalf("result = %+v", res)
	}
	if got := strings.Join(e.runner.names(), ","); got != "backup,apt" {
		t.Fatalf("commands = %s", got)
	}
	backup := e.runner.cmds[0]
	if backup.Name != "/usr/bin/nexus" || strings.Join(backup.Args, " ") != "backup create --reason pre-update" {
		t.Fatalf("backup command = %+v", backup)
	}
	apt := e.runner.cmds[1]
	args := strings.Join(apt.Args, " ")
	if apt.Name != "apt-get" || !strings.HasPrefix(args, "install -y ") || strings.Contains(args, "--allow-downgrades") ||
		!strings.Contains(args, "Dpkg::Options::=--force-confold") {
		t.Fatalf("apt command = %+v", apt)
	}
	if strings.Join(phases, ",") != "backup,install" {
		t.Fatalf("phases = %v", phases)
	}
	if e.healthHits != 4 {
		t.Fatalf("health polls = %d, want 4 (3 refused, then the new version)", e.healthHits)
	}
	if !strings.Contains(res.LogTail, "Setting up nexus (0.2.0)") {
		t.Fatalf("log tail = %q", res.LogTail)
	}
	if on := e.result(); on.Status != StatusOK {
		t.Fatalf("result.json = %+v", on)
	}
	e.mustNotExist(ApplyingFile)
	e.mustNotExist(RequestFile)

	// The new package is now the rollback material for the next update.
	kept, err := os.ReadFile(filepath.Join(e.stateDir, installedDir, b.debName))
	if err != nil || !bytes.Equal(kept, b.deb) {
		t.Fatalf("installed copy: %v", err)
	}
	if _, err := os.Stat(filepath.Join(e.stateDir, installedOld)); !os.IsNotExist(err) {
		t.Fatal("installed.old left behind")
	}
	if _, err := os.Stat(filepath.Join(e.stateDir, "work")); !os.IsNotExist(err) {
		t.Fatal("work dir left behind")
	}
	// ... and the hub reports it.
	svc := newSvcEnv(t, func(o *Options) { o.Dir = e.updates; o.Key = e.key.pub })
	got, err := svc.svc.Reconcile(context.Background())
	if err != nil || got == nil || got.Status != StatusOK {
		t.Fatalf("hub Reconcile = %+v, %v", got, err)
	}
}

func TestApplyNoRequest(t *testing.T) {
	e := newApplyEnv(t)
	if _, err := e.apply(); !errors.Is(err, ErrNoRequest) {
		t.Fatalf("err = %v, want ErrNoRequest", err)
	}
	if len(e.runner.cmds) != 0 {
		t.Fatalf("ran %v", e.runner.cmds)
	}
	// An updates directory that does not exist yet is the same thing.
	e2 := newApplyEnv(t)
	_ = os.RemoveAll(e2.updates)
	if _, err := e2.apply(); !errors.Is(err, ErrNoRequest) {
		t.Fatalf("err = %v, want ErrNoRequest", err)
	}
}

func TestApplyRefusals(t *testing.T) {
	tests := []struct {
		name   string
		cur    string
		opts   func(o *ApplyOptions)
		setup  func(t *testing.T, e *applyEnv, b *testBundle)
		want   error  // errors cannot cross result.json: matched on message text
		text   string // expected substring of Result.Message
		phase  string
		failAt string
	}{
		{name: "bad signature", text: ErrBadSignature.Error(), phase: PhaseVerify, setup: func(t *testing.T, e *applyEnv, b *testBundle) {
			sig := ed25519.Sign(newKey(t).priv, b.sums)
			os.WriteFile(filepath.Join(e.updates, b.version, SigFile), sig, 0o600)
		}},
		{name: "sums tampered", text: ErrBadSignature.Error(), phase: PhaseVerify, setup: func(t *testing.T, e *applyEnv, b *testBundle) {
			os.WriteFile(filepath.Join(e.updates, b.version, SumsFile), append([]byte("\n"), b.sums...), 0o600)
		}},
		{name: "package tampered", text: ErrChecksum.Error(), phase: PhaseVerify, setup: func(t *testing.T, e *applyEnv, b *testBundle) {
			os.WriteFile(filepath.Join(e.updates, b.version, b.debName), []byte("evil"), 0o600)
		}},
		{name: "request names another checksum", text: "different package", phase: PhaseVerify, setup: func(t *testing.T, e *applyEnv, b *testBundle) {
			req := Request{Version: b.version, Arch: b.arch, Deb: b.debName, SHA256: strings.Repeat("ab", 32)}
			writeJSONAtomic(e.updates, RequestFile, req, 0o600)
		}},
		{name: "wrong arch in request", text: ErrWrongArch.Error(), phase: PhaseVerify, setup: func(t *testing.T, e *applyEnv, b *testBundle) {
			req := Request{Version: b.version, Arch: "amd64", Deb: DebName(b.version, "amd64"), SHA256: debDigest(*b)}
			writeJSONAtomic(e.updates, RequestFile, req, 0o600)
		}},
		{name: "downgrade", cur: "0.3.0", text: ErrDowngrade.Error(), phase: PhaseVerify},
		{name: "same version", cur: "0.2.0", text: ErrAlreadyInstalled.Error(), phase: PhaseVerify},
		{name: "development build", cur: "dev", text: ErrDevBuild.Error(), phase: PhaseVerify},
		{name: "request flag does not allow a downgrade", cur: "0.3.0", text: ErrDowngrade.Error(), phase: PhaseVerify, setup: func(t *testing.T, e *applyEnv, b *testBundle) {
			// A forged "allow_downgrade" in the hub-written file is ignored.
			raw := `{"version":"0.2.0","arch":"arm64","deb":"` + b.debName + `","sha256":"` + debDigest(*b) + `","allow_downgrade":true}`
			os.WriteFile(filepath.Join(e.updates, RequestFile), []byte(raw), 0o600)
		}},
		{name: "oversized package", text: ErrTooLarge.Error(), phase: PhaseVerify, setup: func(t *testing.T, e *applyEnv, b *testBundle) {
			lowerMaxDeb(t, 8)
		}},
		{name: "oversized sums", text: ErrTooLarge.Error(), phase: PhaseVerify, setup: func(t *testing.T, e *applyEnv, b *testBundle) {
			os.WriteFile(filepath.Join(e.updates, b.version, SumsFile), make([]byte, MaxSumsBytes+1), 0o600)
		}},
		{name: "oversized request", text: "cannot read the request", phase: PhaseVerify, setup: func(t *testing.T, e *applyEnv, b *testBundle) {
			os.WriteFile(filepath.Join(e.updates, RequestFile), bytes.Repeat([]byte(" "), MaxRequestBytes+1), 0o600)
		}},
		{name: "garbage request", text: "bad request file", phase: PhaseVerify, setup: func(t *testing.T, e *applyEnv, b *testBundle) {
			os.WriteFile(filepath.Join(e.updates, RequestFile), []byte("nope"), 0o600)
		}},
		{name: "version with path traversal", text: "bad version", phase: PhaseVerify, setup: func(t *testing.T, e *applyEnv, b *testBundle) {
			req := Request{Version: "../../etc", Arch: "arm64", Deb: "x", SHA256: debDigest(*b)}
			writeJSONAtomic(e.updates, RequestFile, req, 0o600)
		}},
		{name: "package name with path", text: "unexpected package name", phase: PhaseVerify, setup: func(t *testing.T, e *applyEnv, b *testBundle) {
			req := Request{Version: b.version, Arch: "arm64", Deb: "../" + b.debName, SHA256: debDigest(*b)}
			writeJSONAtomic(e.updates, RequestFile, req, 0o600)
		}},
		{name: "version not staged", text: ErrNotStaged.Error(), phase: PhaseVerify, setup: func(t *testing.T, e *applyEnv, b *testBundle) {
			os.RemoveAll(filepath.Join(e.updates, b.version))
		}},
		{name: "package missing from the staged directory", text: ErrBadBundle.Error(), phase: PhaseVerify, setup: func(t *testing.T, e *applyEnv, b *testBundle) {
			os.Remove(filepath.Join(e.updates, b.version, b.debName))
		}},
		{name: "no rollback material", text: "no rollback material", phase: PhaseVerify, setup: func(t *testing.T, e *applyEnv, b *testBundle) {
			os.RemoveAll(filepath.Join(e.stateDir, installedDir))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newApplyEnv(t)
			e.seedInstalled("0.1.0")
			b := e.stage("0.2.0")
			if tt.setup != nil {
				tt.setup(t, e, &b)
			}
			opts := e.opts()
			if tt.cur != "" {
				opts.CurrentVersion = tt.cur
			}
			res, err := Apply(context.Background(), opts)
			if err != nil {
				t.Fatal(err)
			}
			if res.Status != StatusError || res.Phase != tt.phase || !strings.Contains(res.Message, tt.text) {
				t.Fatalf("result = %+v, want error in %s containing %q", res, tt.phase, tt.text)
			}
			if len(e.runner.cmds) != 0 {
				t.Fatalf("a refused update ran %v", e.runner.cmds)
			}
			if got := e.result(); got.Status != StatusError {
				t.Fatalf("result.json = %+v", got)
			}
			e.mustNotExist(ApplyingFile)
			e.mustNotExist(RequestFile)
		})
	}
}

func TestApplyDowngradeNeedsTheOperatorFlag(t *testing.T) {
	e := newApplyEnv(t)
	e.seedInstalled("0.3.0")
	e.stage("0.2.0")
	e.runner.handler = e.aptHandler("0.2.0", false)
	e.reported = "0.3.0"
	opts := e.opts()
	opts.CurrentVersion = "0.3.0"
	opts.AllowDowngrade = true
	res, err := Apply(context.Background(), opts)
	if err != nil || res.Status != StatusOK {
		t.Fatalf("result = %+v, err %v", res, err)
	}
}

func TestApplyHostileRequestPointers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks")
	}
	tests := []struct {
		name  string
		setup func(t *testing.T, e *applyEnv, b testBundle)
		text  string
	}{
		{name: "package is a symlink", text: "not a regular file", setup: func(t *testing.T, e *applyEnv, b testBundle) {
			p := filepath.Join(e.updates, b.version, b.debName)
			target := filepath.Join(t.TempDir(), "other.deb")
			os.WriteFile(target, b.deb, 0o600)
			os.Remove(p)
			mustSymlink(t, target, p)
		}},
		{name: "sums is a symlink", text: "not a regular file", setup: func(t *testing.T, e *applyEnv, b testBundle) {
			p := filepath.Join(e.updates, b.version, SumsFile)
			os.Remove(p)
			mustSymlink(t, "/etc/passwd", p)
		}},
		{name: "signature is a symlink inside the directory", text: "not a regular file", setup: func(t *testing.T, e *applyEnv, b testBundle) {
			p := filepath.Join(e.updates, b.version, SigFile)
			os.Rename(p, p+".real")
			mustSymlink(t, SigFile+".real", p)
		}},
		{name: "staged directory is a symlink to a directory outside", text: "", setup: func(t *testing.T, e *applyEnv, b testBundle) {
			other := filepath.Join(t.TempDir(), "bundle")
			os.Rename(filepath.Join(e.updates, b.version), other)
			mustSymlink(t, other, filepath.Join(e.updates, b.version))
		}},
		{name: "staged directory is a symlink inside", text: "", setup: func(t *testing.T, e *applyEnv, b testBundle) {
			real := filepath.Join(e.updates, "real")
			os.Rename(filepath.Join(e.updates, b.version), real)
			mustSymlink(t, "real", filepath.Join(e.updates, b.version))
		}},
		{name: "request is a symlink", text: "cannot read the request", setup: func(t *testing.T, e *applyEnv, b testBundle) {
			p := filepath.Join(e.updates, RequestFile)
			os.Remove(p)
			mustSymlink(t, "/etc/passwd", p)
		}},
		{name: "staged directory is world-writable", text: "writable by group or others", setup: func(t *testing.T, e *applyEnv, b testBundle) {
			os.Chmod(filepath.Join(e.updates, b.version), 0o777)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newApplyEnv(t)
			e.seedInstalled("0.1.0")
			b := e.stage("0.2.0")
			tt.setup(t, e, b)
			res, err := e.apply()
			if err != nil {
				t.Fatal(err)
			}
			if res.Status != StatusError || !strings.Contains(res.Message, tt.text) {
				t.Fatalf("result = %+v, want error containing %q", res, tt.text)
			}
			if len(e.runner.cmds) != 0 {
				t.Fatalf("ran %v", e.runner.cmds)
			}
		})
	}

	t.Run("updates directory is a symlink", func(t *testing.T) {
		e := newApplyEnv(t)
		e.seedInstalled("0.1.0")
		e.stage("0.2.0")
		real := filepath.Join(t.TempDir(), "elsewhere")
		os.Rename(e.updates, real)
		mustSymlink(t, real, e.updates)
		if _, err := e.apply(); err == nil || !strings.Contains(err.Error(), "not a directory") {
			t.Fatalf("err = %v", err)
		}
		if len(e.runner.cmds) != 0 {
			t.Fatalf("ran %v", e.runner.cmds)
		}
		if _, err := os.Stat(filepath.Join(real, ResultFile)); !os.IsNotExist(err) {
			t.Fatal("the helper wrote through a symlinked updates directory")
		}
	})

	t.Run("updates directory is group-writable", func(t *testing.T) {
		e := newApplyEnv(t)
		e.stage("0.2.0")
		os.Chmod(e.updates, 0o770)
		if _, err := e.apply(); err == nil || !strings.Contains(err.Error(), "writable by group or others") {
			t.Fatalf("err = %v", err)
		}
	})
}

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

func TestApplyOwnerCheck(t *testing.T) {
	e := newApplyEnv(t)
	e.seedInstalled("0.1.0")
	e.stage("0.2.0")
	opts := e.opts()
	opts.CheckOwner = func(fi fs.FileInfo) error { return fmt.Errorf("%s: wrong owner", fi.Name()) }
	if _, err := Apply(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "wrong owner") {
		t.Fatalf("err = %v", err)
	}
	if len(e.runner.cmds) != 0 {
		t.Fatalf("ran %v", e.runner.cmds)
	}
}

func TestOwnerOneOf(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("file owners are checked on Linux only")
	}
	f := filepath.Join(t.TempDir(), "f")
	os.WriteFile(f, nil, 0o600)
	fi, _ := os.Stat(f)
	self := uint32(os.Getuid())
	if err := ownerOneOf(0, self)(fi); err != nil {
		t.Fatalf("own file refused: %v", err)
	}
	if err := ownerOneOf(self + 1)(fi); err == nil {
		t.Fatal("foreign owner accepted")
	}
}

func TestApplyRollback(t *testing.T) {
	tests := []struct {
		name       string
		seed       bool
		setup      func(e *applyEnv)
		handler    func(e *applyEnv) func(int, Command, *bytes.Buffer) error
		wantStatus string
		wantPhase  string
		wantCmds   string
		text       string
		wantKept   string // version in installed/ afterwards
	}{
		{
			name: "apt fails, previous version restored", seed: true,
			handler:    func(e *applyEnv) func(int, Command, *bytes.Buffer) error { return e.aptHandler("0.2.0", true) },
			wantStatus: StatusRolledBack, wantPhase: PhaseInstall, wantCmds: "backup,apt,apt-rollback",
			text: "restored 0.1.0", wantKept: "0.1.0",
		},
		{
			name: "new hub never reports the version", seed: true,
			handler: func(e *applyEnv) func(int, Command, *bytes.Buffer) error {
				inner := e.aptHandler("0.2.0", false)
				return func(n int, c Command, out *bytes.Buffer) error {
					err := inner(n, c, out)
					if c.Name == "apt-get" && !contains(strings.Join(c.Args, " "), "--allow-downgrades") {
						e.reported = "0.1.0" // old hub keeps answering
					}
					return err
				}
			},
			wantStatus: StatusRolledBack, wantPhase: PhaseHealth, wantCmds: "backup,apt,apt-rollback",
			text: "did not report version 0.2.0 within 1m0s", wantKept: "0.1.0",
		},
		{
			name: "new hub never answers", seed: true,
			setup: func(e *applyEnv) { e.healthAfter = 1000 },
			handler: func(e *applyEnv) func(int, Command, *bytes.Buffer) error {
				inner := e.aptHandler("0.2.0", false)
				return func(n int, c Command, out *bytes.Buffer) error {
					if c.Name == "apt-get" && contains(strings.Join(c.Args, " "), "--allow-downgrades") {
						e.healthAfter = 0 // the old hub comes back after the rollback
					}
					return inner(n, c, out)
				}
			},
			wantStatus: StatusRolledBack, wantPhase: PhaseHealth, wantCmds: "backup,apt,apt-rollback",
			text: "connection refused", wantKept: "0.1.0",
		},
		{
			name: "rollback apt fails too", seed: true,
			handler: func(e *applyEnv) func(int, Command, *bytes.Buffer) error {
				inner := e.aptHandler("0.2.0", true)
				return func(n int, c Command, out *bytes.Buffer) error {
					if c.Name == "apt-get" && contains(strings.Join(c.Args, " "), "--allow-downgrades") {
						return errors.New("exit status 100")
					}
					return inner(n, c, out)
				}
			},
			wantStatus: StatusError, wantPhase: PhaseInstall, wantCmds: "backup,apt,apt-rollback",
			text: "reinstalling 0.1.0 failed too", wantKept: "0.1.0",
		},
		{
			name: "rolled back hub is not healthy either", seed: true,
			handler: func(e *applyEnv) func(int, Command, *bytes.Buffer) error {
				inner := e.aptHandler("0.2.0", true)
				return func(n int, c Command, out *bytes.Buffer) error {
					err := inner(n, c, out)
					e.healthErr = errors.New("socket missing")
					return err
				}
			},
			wantStatus: StatusError, wantPhase: PhaseInstall, wantCmds: "backup,apt,apt-rollback",
			text: "is not healthy", wantKept: "0.1.0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newApplyEnv(t)
			if tt.seed {
				e.seedInstalled("0.1.0")
			}
			e.stage("0.2.0")
			if tt.setup != nil {
				tt.setup(e)
			}
			e.runner.handler = tt.handler(e)
			res, err := e.apply()
			if err != nil {
				t.Fatal(err)
			}
			if res.Status != tt.wantStatus || res.Phase != tt.wantPhase || !strings.Contains(res.Message, tt.text) {
				t.Fatalf("result = %+v", res)
			}
			if got := strings.Join(e.runner.names(), ","); got != tt.wantCmds {
				t.Fatalf("commands = %s, want %s", got, tt.wantCmds)
			}
			rb := e.runner.cmds[len(e.runner.cmds)-1]
			if !contains(strings.Join(rb.Args, " "), "--allow-downgrades", DebName("0.1.0", "arm64")) {
				t.Fatalf("rollback command = %+v", rb)
			}
			if res.LogTail == "" || !strings.Contains(res.LogTail, "update failed in phase") {
				t.Fatalf("log tail = %q", res.LogTail)
			}
			if got := e.result(); got.Status != tt.wantStatus {
				t.Fatalf("result.json = %+v", got)
			}
			// A failed update must not replace the rollback material.
			if _, err := os.Stat(filepath.Join(e.stateDir, installedDir, DebName(tt.wantKept, "arm64"))); err != nil {
				t.Fatalf("rollback material lost: %v", err)
			}
		})
	}
}

func TestApplyBackupFailureAbortsBeforeInstall(t *testing.T) {
	tests := []struct {
		name string
		err  error
		text string
	}{
		{"backup fails", errors.New("exit status 1"), "nothing was changed"},
		{"binary has no backup command", exitError(t, 2), "has no backup command"},
		{"binary cannot be started", errors.New("fork/exec /usr/bin/nexus: no such file or directory"), "nothing was changed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newApplyEnv(t)
			e.seedInstalled("0.1.0")
			e.stage("0.2.0")
			e.runner.handler = func(_ int, c Command, out *bytes.Buffer) error {
				if c.Name == "apt-get" {
					t.Error("apt-get ran although the backup failed")
				}
				out.WriteString("nexus: unknown command \"backup\"\n")
				return tt.err
			}
			res, err := e.apply()
			if err != nil {
				t.Fatal(err)
			}
			if res.Status != StatusError || res.Phase != PhaseBackup || !strings.Contains(res.Message, tt.text) {
				t.Fatalf("result = %+v", res)
			}
			if got := strings.Join(e.runner.names(), ","); got != "backup" {
				t.Fatalf("commands = %s", got)
			}
			if !strings.Contains(res.LogTail, "unknown command") {
				t.Fatalf("log tail = %q", res.LogTail)
			}
		})
	}
}

// exitError returns a real *exec.ExitError with the given code.
func exitError(t *testing.T, code int) error {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("needs sh")
	}
	return runShExit(code)
}

func TestApplyRollbackMaterial(t *testing.T) {
	t.Run("kept copy of another version is ignored", func(t *testing.T) {
		e := newApplyEnv(t)
		e.seedInstalled("0.0.9")
		e.stage("0.2.0")
		res, _ := e.apply()
		if res.Status != StatusError || !strings.Contains(res.Message, MsgNoRollback) || !strings.Contains(res.Message, NoRollbackCommand) {
			t.Fatalf("result = %+v", res)
		}
	})
	t.Run("kept copy with a bad signature is ignored", func(t *testing.T) {
		e := newApplyEnv(t)
		e.seedInstalled("0.1.0")
		os.WriteFile(filepath.Join(e.stateDir, installedDir, SigFile), make([]byte, 64), 0o644)
		e.stage("0.2.0")
		res, _ := e.apply()
		if res.Status != StatusError || !strings.Contains(res.Message, "kept copy is unusable") || len(e.runner.cmds) != 0 {
			t.Fatalf("result = %+v", res)
		}
	})
	t.Run("kept copy with a tampered package is ignored", func(t *testing.T) {
		e := newApplyEnv(t)
		e.seedInstalled("0.1.0")
		os.WriteFile(filepath.Join(e.stateDir, installedDir, DebName("0.1.0", "arm64")), []byte("evil"), 0o644)
		e.stage("0.2.0")
		res, _ := e.apply()
		if res.Status != StatusError || !strings.Contains(res.Message, ErrChecksum.Error()) {
			t.Fatalf("result = %+v", res)
		}
	})
	t.Run("a staged bundle of the running version serves as fallback", func(t *testing.T) {
		e := newApplyEnv(t)
		old := makeBundle(t, e.key, "0.1.0", "arm64")
		old.writeStaged(t, e.updates)
		e.stage("0.2.0")
		e.runner.handler = e.aptHandler("0.2.0", true)
		res, _ := e.apply()
		if res.Status != StatusRolledBack {
			t.Fatalf("result = %+v", res)
		}
	})
	t.Run("--no-rollback updates without material and cannot roll back", func(t *testing.T) {
		e := newApplyEnv(t)
		e.stage("0.2.0")
		e.runner.handler = e.aptHandler("0.2.0", true)
		opts := e.opts()
		opts.NoRollback = true
		res, err := Apply(context.Background(), opts)
		if err != nil {
			t.Fatal(err)
		}
		if res.Status != StatusError || res.Phase != PhaseInstall || !strings.Contains(res.Message, "no rollback copy") {
			t.Fatalf("result = %+v", res)
		}
		if got := strings.Join(e.runner.names(), ","); got != "backup,apt" {
			t.Fatalf("commands = %s", got)
		}
	})
	t.Run("--no-rollback success still saves material for next time", func(t *testing.T) {
		e := newApplyEnv(t)
		e.stage("0.2.0")
		e.runner.handler = e.aptHandler("0.2.0", false)
		opts := e.opts()
		opts.NoRollback = true
		res, _ := Apply(context.Background(), opts)
		if res.Status != StatusOK {
			t.Fatalf("result = %+v", res)
		}
		if _, err := os.Stat(filepath.Join(e.stateDir, installedDir, DebName("0.2.0", "arm64"))); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("second update uses the material the first one saved", func(t *testing.T) {
		e := newApplyEnv(t)
		e.seedInstalled("0.1.0")
		e.stage("0.2.0")
		e.runner.handler = e.aptHandler("0.2.0", false)
		if res, _ := e.apply(); res.Status != StatusOK {
			t.Fatalf("first result = %+v", res)
		}
		// Next release, now running 0.2.0; apt fails and the rollback goes to 0.2.0.
		e.stage("0.3.0")
		e.reported = "0.2.0"
		e.runner.cmds = nil
		e.runner.handler = func(n int, c Command, out *bytes.Buffer) error {
			if c.Name == "apt-get" && contains(strings.Join(c.Args, " "), "--allow-downgrades") {
				e.reported = "0.2.0"
				return nil
			}
			if c.Name == "apt-get" {
				return errors.New("exit status 100")
			}
			return nil
		}
		opts := e.opts()
		opts.CurrentVersion = "0.2.0"
		res, err := Apply(context.Background(), opts)
		if err != nil || res.Status != StatusRolledBack {
			t.Fatalf("result = %+v, err %v", res, err)
		}
		rb := e.runner.cmds[len(e.runner.cmds)-1]
		if !contains(strings.Join(rb.Args, " "), DebName("0.2.0", "arm64")) {
			t.Fatalf("rollback command = %+v", rb)
		}
	})
}

func TestApplyLogTailIsBounded(t *testing.T) {
	e := newApplyEnv(t)
	e.seedInstalled("0.1.0")
	e.stage("0.2.0")
	e.runner.handler = func(n int, c Command, out *bytes.Buffer) error {
		if c.Name == "apt-get" {
			for i := 0; i < 5000; i++ {
				fmt.Fprintf(out, "line %05d of a very chatty apt run\n", i)
			}
			e.reported = "0.2.0"
		}
		return nil
	}
	res, _ := e.apply()
	if res.Status != StatusOK {
		t.Fatalf("result = %+v", res)
	}
	if len(res.LogTail) > logTailBytes || !strings.Contains(res.LogTail, "line 04999") || strings.Contains(res.LogTail, "line 00000") {
		t.Fatalf("log tail has %d bytes, starts %q", len(res.LogTail), res.LogTail[:40])
	}
	if !strings.HasPrefix(res.LogTail, "line ") && !strings.HasPrefix(res.LogTail, "update") {
		t.Fatalf("log tail starts mid-line: %q", res.LogTail[:30])
	}
}

func TestApplyBusy(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("flock")
	}
	e := newApplyEnv(t)
	e.seedInstalled("0.1.0")
	e.stage("0.2.0")
	unlock, err := lockFile(filepath.Join(e.stateDir, "apply.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, err := e.apply(); !errors.Is(err, ErrBusy) {
		t.Fatalf("err = %v, want ErrBusy", err)
	}
	if _, err := os.Stat(filepath.Join(e.updates, RequestFile)); err != nil {
		t.Fatal("a helper that lost the lock consumed the request")
	}
}

func TestApplyHealthContextCancel(t *testing.T) {
	// A cancelled context ends the health wait; the rollback still runs.
	e := newApplyEnv(t)
	e.seedInstalled("0.1.0")
	e.stage("0.2.0")
	ctx, cancel := context.WithCancel(context.Background())
	e.runner.handler = func(n int, c Command, out *bytes.Buffer) error {
		if c.Name == "apt-get" && !contains(strings.Join(c.Args, " "), "--allow-downgrades") {
			cancel()
		}
		if c.Name == "apt-get" && contains(strings.Join(c.Args, " "), "--allow-downgrades") {
			e.reported = "0.1.0"
		}
		return nil
	}
	res, err := Apply(ctx, e.opts())
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusRolledBack {
		t.Fatalf("result = %+v", res)
	}
}
