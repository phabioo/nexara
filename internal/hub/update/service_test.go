package update

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func stageGood(t *testing.T, e *svcEnv, version string) testBundle {
	t.Helper()
	b := makeBundle(t, e.key, version, "arm64")
	if _, err := e.svc.StageFiles(context.Background(), "alice", b.input()); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRequestInstall(t *testing.T) {
	ctx := context.Background()
	t.Run("writes the request and reports installing", func(t *testing.T) {
		e := newSvcEnv(t, nil)
		b := stageGood(t, e, "0.2.0")
		if err := e.svc.RequestInstall(ctx, "alice", "0.2.0"); err != nil {
			t.Fatal(err)
		}
		var req Request
		if err := readJSON(filepath.Join(e.dir, RequestFile), MaxRequestBytes, &req); err != nil {
			t.Fatal(err)
		}
		if req.Version != "0.2.0" || req.Arch != "arm64" || req.Deb != b.debName || req.RequestedBy != "alice" ||
			req.SHA256 != strings.TrimSpace(strings.SplitN(string(b.sums[strings.Index(string(b.sums), "\n")+1:]), " ", 2)[0]) ||
			!req.RequestedAt.Equal(e.clock.Now()) {
			t.Fatalf("request = %+v", req)
		}
		if err := req.validate(); err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" {
			fi, _ := os.Stat(filepath.Join(e.dir, RequestFile))
			if fi.Mode().Perm() != 0o600 {
				t.Fatalf("request mode = %v", fi.Mode().Perm())
			}
		}
		// No temp files left; state is "installing".
		if got := listNames(t, e.dir); strings.Join(got, ",") != "0.2.0,request.json" {
			t.Fatalf("dir = %v", got)
		}
		st, _ := e.svc.Status(ctx)
		if st.Installing == nil || st.Installing.Phase != PhaseQueued || st.Installing.Version != "0.2.0" || st.Installing.Stale {
			t.Fatalf("installing = %+v", st.Installing)
		}
		if a := e.audit.actions(); len(a) != 2 || a[1] != "update.request:ok" {
			t.Fatalf("audit = %v", a)
		}
		// A second request while one is pending is refused.
		if err := e.svc.RequestInstall(ctx, "alice", "0.2.0"); !errors.Is(err, ErrBusy) {
			t.Fatalf("second request err = %v, want ErrBusy", err)
		}
	})

	t.Run("a stale request may be replaced", func(t *testing.T) {
		e := newSvcEnv(t, nil)
		stageGood(t, e, "0.2.0")
		if err := e.svc.RequestInstall(ctx, "alice", "0.2.0"); err != nil {
			t.Fatal(err)
		}
		e.clock.Advance(staleAfter + time.Minute)
		st, _ := e.svc.Status(ctx)
		if st.Installing == nil || !st.Installing.Stale {
			t.Fatalf("installing = %+v", st.Installing)
		}
		if err := e.svc.RequestInstall(ctx, "alice", "0.2.0"); err != nil {
			t.Fatalf("stale request not replaced: %v", err)
		}
	})

	tests := []struct {
		name  string
		setup func(t *testing.T, e *svcEnv)
		ver   string
		want  error
	}{
		{name: "not staged", ver: "0.2.0", want: ErrNotStaged},
		{name: "version with path", ver: "../0.2.0", want: ErrNotStaged},
		{name: "empty version", ver: "", want: ErrNotStaged},
		{name: "helper not watching", ver: "0.2.0", want: ErrUnsupported, setup: func(t *testing.T, e *svcEnv) {
			e.svc.o.HelperWatches = false
		}},
		{name: "package changed after staging", ver: "0.2.0", want: ErrChecksum, setup: func(t *testing.T, e *svcEnv) {
			p := filepath.Join(e.dir, "0.2.0", DebName("0.2.0", "arm64"))
			if err := os.WriteFile(p, []byte("evil"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "signature replaced after staging", ver: "0.2.0", want: ErrBadSignature, setup: func(t *testing.T, e *svcEnv) {
			if err := os.WriteFile(filepath.Join(e.dir, "0.2.0", SigFile), make([]byte, 64), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "became a downgrade", ver: "0.2.0", want: ErrDowngrade, setup: func(t *testing.T, e *svcEnv) {
			e.svc.o.CurrentVersion = "0.3.0"
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newSvcEnv(t, nil)
			stageGood(t, e, "0.2.0")
			if tt.name == "not staged" {
				e.svc.removeStaged()
			}
			if tt.setup != nil {
				tt.setup(t, e)
			}
			err := e.svc.RequestInstall(ctx, "alice", tt.ver)
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			if _, serr := os.Stat(filepath.Join(e.dir, RequestFile)); !os.IsNotExist(serr) {
				t.Fatal("a request file exists after a refusal")
			}
		})
	}
}

func TestCancelRequest(t *testing.T) {
	ctx := context.Background()
	e := newSvcEnv(t, nil)
	stageGood(t, e, "0.2.0")
	if ok, err := e.svc.CancelRequest(ctx, "a"); ok || err != nil {
		t.Fatalf("cancel without request = %v, %v", ok, err)
	}
	if err := e.svc.RequestInstall(ctx, "a", "0.2.0"); err != nil {
		t.Fatal(err)
	}
	if ok, err := e.svc.CancelRequest(ctx, "a"); !ok || err != nil {
		t.Fatalf("cancel = %v, %v", ok, err)
	}
	if st, _ := e.svc.Status(ctx); st.Installing != nil {
		t.Fatalf("installing = %+v", st.Installing)
	}
}

func TestStatusInstallingFromApplying(t *testing.T) {
	e := newSvcEnv(t, nil)
	ap := Applying{Request: Request{Version: "0.2.0", RequestedBy: "bob"}, Phase: PhaseInstall, StartedAt: e.clock.Now()}
	if err := writeJSONAtomic(e.dir, ApplyingFile, ap, 0o600); err != nil {
		t.Fatal(err)
	}
	st, _ := e.svc.Status(context.Background())
	if st.Installing == nil || st.Installing.Phase != PhaseInstall || st.Installing.RequestedBy != "bob" {
		t.Fatalf("installing = %+v", st.Installing)
	}
	if st.Current != "0.1.0" || st.Arch != "arm64" || !st.Supported {
		t.Fatalf("status = %+v", st)
	}
}

func TestReconcile(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name       string
		result     any    // marshalled to result.json; string is written verbatim
		wantStatus string // in last-result
		wantResult string // audit result
		wantStaged bool
	}{
		{name: "ok", result: Result{Status: StatusOK, Version: "0.2.0", PreviousVersion: "0.1.0", Message: "updated", RequestedBy: "alice"}, wantStatus: StatusOK, wantResult: "ok"},
		{name: "rolled back", result: Result{Status: StatusRolledBack, Version: "0.2.0", PreviousVersion: "0.1.0", Message: "health", RequestedBy: "alice"}, wantStatus: StatusRolledBack, wantResult: "error"},
		{name: "error", result: Result{Status: StatusError, Version: "0.2.0", Message: "bad signature"}, wantStatus: StatusError, wantResult: "error"},
		{name: "unknown status counts as error", result: Result{Status: "weird", Version: "0.2.0"}, wantStatus: StatusError, wantResult: "error"},
		{name: "corrupt file", result: "{not json", wantStatus: StatusError, wantResult: "error", wantStaged: true},
		{name: "version with path is not used for deletion", result: Result{Status: StatusOK, Version: "../x"}, wantStatus: StatusOK, wantResult: "ok", wantStaged: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newSvcEnv(t, nil)
			stageGood(t, e, "0.2.0")
			outside := filepath.Join(filepath.Dir(e.dir), "x")
			if err := os.MkdirAll(outside, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := writeJSONAtomic(e.dir, ApplyingFile, Applying{}, 0o600); err != nil {
				t.Fatal(err)
			}
			if s, ok := tt.result.(string); ok {
				if err := os.WriteFile(filepath.Join(e.dir, ResultFile), []byte(s), 0o600); err != nil {
					t.Fatal(err)
				}
			} else if err := writeJSONAtomic(e.dir, ResultFile, tt.result, 0o644); err != nil {
				t.Fatal(err)
			}

			res, err := e.svc.Reconcile(ctx)
			if err != nil || res == nil {
				t.Fatalf("Reconcile = %v, %v", res, err)
			}
			if res.Status != tt.wantStatus {
				t.Fatalf("status = %q, want %q", res.Status, tt.wantStatus)
			}
			a := e.audit.all()
			last := a[len(a)-1]
			if last.Action != ActionApply || last.Result != tt.wantResult {
				t.Fatalf("audit = %+v", last)
			}
			if r, ok := tt.result.(Result); ok && r.RequestedBy != "" && last.User != r.RequestedBy {
				t.Fatalf("audit user = %q", last.User)
			}
			if !strings.Contains(strings.Join(listNames(t, e.dir), ","), "last-result.json") {
				t.Fatalf("dir = %v", listNames(t, e.dir))
			}
			for _, gone := range []string{ResultFile, ApplyingFile} {
				if _, err := os.Stat(filepath.Join(e.dir, gone)); !os.IsNotExist(err) {
					t.Fatalf("%s still exists", gone)
				}
			}
			_, serr := os.Stat(filepath.Join(e.dir, "0.2.0"))
			if staged := serr == nil; staged != tt.wantStaged {
				t.Fatalf("staged dir exists = %v, want %v", staged, tt.wantStaged)
			}
			if _, err := os.Stat(outside); err != nil {
				t.Fatalf("Reconcile deleted outside the updates dir: %v", err)
			}
			// Reported once only.
			if again, err := e.svc.Reconcile(ctx); again != nil || err != nil {
				t.Fatalf("second Reconcile = %v, %v", again, err)
			}
			st, _ := e.svc.Status(ctx)
			if st.Last == nil || st.Last.Status != tt.wantStatus {
				t.Fatalf("status.Last = %+v", st.Last)
			}
		})
	}

	t.Run("no result is not an error", func(t *testing.T) {
		e := newSvcEnv(t, nil)
		if res, err := e.svc.Reconcile(ctx); res != nil || err != nil {
			t.Fatalf("Reconcile = %v, %v", res, err)
		}
	})

	t.Run("run picks up a result after the hub started", func(t *testing.T) {
		e := newSvcEnv(t, nil)
		e.svc.tick(ctx) // the new hub is up, the helper is still checking health
		if len(e.audit.all()) != 0 {
			t.Fatal("audit without a result")
		}
		if err := writeJSONAtomic(e.dir, ResultFile, Result{Status: StatusOK, Version: "0.2.0"}, 0o644); err != nil {
			t.Fatal(err)
		}
		e.svc.tick(ctx)
		if a := e.audit.actions(); len(a) != 1 || a[0] != "update.apply:ok" {
			t.Fatalf("audit = %v", a)
		}
	})
}

func TestConfig(t *testing.T) {
	ctx := context.Background()
	e := newSvcEnv(t, nil)
	c, err := e.svc.Config(ctx)
	if err != nil || c != (Config{Channel: ChannelStable}) {
		t.Fatalf("defaults = %+v, %v", c, err)
	}
	want := Config{CheckGitHub: true, Channel: ChannelRC, AllowDowngrade: true}
	if err := e.svc.SetConfig(ctx, "alice", want); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.svc.Config(ctx); got != want {
		t.Fatalf("config = %+v", got)
	}
	if err := e.svc.SetConfig(ctx, "alice", Config{Channel: "nightly"}); err == nil {
		t.Fatal("accepted an unknown channel")
	}
	if a := e.audit.actions(); len(a) != 2 || a[0] != "update.settings:ok" || a[1] != "update.settings:error" {
		t.Fatalf("audit = %v", a)
	}
	// Persisted JSON key names are what the Settings view will bind to.
	b, _ := json.Marshal(want)
	if string(b) != `{"check_github":true,"channel":"rc","allow_downgrade":true}` {
		t.Fatalf("json = %s", b)
	}
}

func TestCleanupRemovesOldTemp(t *testing.T) {
	e := newSvcEnv(t, nil)
	old := filepath.Join(e.dir, ".incoming-old")
	fresh := filepath.Join(e.dir, ".incoming-new")
	for _, p := range []string{old, fresh} {
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	past := e.clock.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}
	e.svc.cleanup()
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("old temp dir not removed")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Fatal("fresh temp dir removed")
	}
}
