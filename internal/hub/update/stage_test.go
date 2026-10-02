package update

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestStageFilesMatrix(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name    string
		current string
		allow   bool
		mutate  func(t *testing.T, e *svcEnv, b *testBundle)
		want    error // nil: staged
	}{
		{name: "good", current: "0.1.0"},
		{name: "good, prerelease to release", current: "0.2.0-rc1"},
		{name: "bad signature (other key)", current: "0.1.0", want: ErrBadSignature,
			mutate: func(t *testing.T, _ *svcEnv, b *testBundle) { b.sig = ed25519.Sign(newKey(t).priv, b.sums) }},
		{name: "bad signature (flipped bit)", current: "0.1.0", want: ErrBadSignature,
			mutate: func(_ *testing.T, _ *svcEnv, b *testBundle) { b.sig = append([]byte(nil), b.sig...); b.sig[3] ^= 1 }},
		{name: "short signature", current: "0.1.0", want: ErrBadSignature,
			mutate: func(_ *testing.T, _ *svcEnv, b *testBundle) { b.sig = b.sig[:10] }},
		{name: "empty signature", current: "0.1.0", want: ErrBadSignature,
			mutate: func(_ *testing.T, _ *svcEnv, b *testBundle) { b.sig = nil }},
		{name: "sums changed after signing", current: "0.1.0", want: ErrBadSignature,
			mutate: func(_ *testing.T, _ *svcEnv, b *testBundle) { b.sums = append([]byte("# x\n"), b.sums...) }},
		{name: "bad checksum (package changed)", current: "0.1.0", want: ErrChecksum,
			mutate: func(_ *testing.T, _ *svcEnv, b *testBundle) { b.deb = append(b.deb, 'x') }},
		{name: "package not listed in sums", current: "0.1.0", want: ErrBadBundle,
			mutate: func(t *testing.T, e *svcEnv, b *testBundle) {
				b.sums = []byte(sumLine("install.sh", []byte("x")))
				b.sig = ed25519.Sign(e.key.priv, b.sums)
			}},
		{name: "package renamed to a newer version", current: "0.1.0", want: ErrBadBundle,
			mutate: func(_ *testing.T, _ *svcEnv, b *testBundle) { b.debName = DebName("9.9.9", "arm64") }},
		{name: "wrong arch", current: "0.1.0", want: ErrWrongArch,
			mutate: func(_ *testing.T, e *svcEnv, b *testBundle) { *b = rebuildSigned(e, b, "0.2.0", "amd64") }},
		{name: "downgrade", current: "0.3.0", want: ErrDowngrade},
		{name: "same version", current: "0.2.0", want: ErrAlreadyInstalled},
		{name: "release to its own release candidate", current: "0.2.0", want: ErrDowngrade,
			mutate: func(_ *testing.T, e *svcEnv, b *testBundle) { *b = rebuildSigned(e, b, "0.2.0-rc1", "arm64") }},
		{name: "downgrade allowed by setting", current: "0.3.0", allow: true},
		{name: "development build", current: "dev", want: ErrDevBuild},
		{name: "not a nexus package name", current: "0.1.0", want: ErrBadBundle,
			mutate: func(_ *testing.T, _ *svcEnv, b *testBundle) { b.debName = "evil_0.2.0_arm64.deb" }},
		{name: "path in package name", current: "0.1.0", want: ErrBadBundle,
			mutate: func(_ *testing.T, _ *svcEnv, b *testBundle) { b.debName = "../nexus_0.2.0_arm64.deb" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newSvcEnv(t, func(o *Options) { o.CurrentVersion = tt.current })
			if tt.allow {
				e.set(t, SettingAllowDowngrade, "true")
			}
			b := makeBundle(t, e.key, "0.2.0", "arm64")
			if tt.mutate != nil {
				tt.mutate(t, e, &b)
			}
			got, err := e.svc.StageFiles(ctx, "alice", b.input())
			if tt.want != nil {
				if !errors.Is(err, tt.want) {
					t.Fatalf("err = %v, want %v", err, tt.want)
				}
				if names := listNames(t, e.dir); len(names) != 0 {
					t.Fatalf("a refused bundle left files behind: %v", names)
				}
				if a := e.audit.all(); len(a) != 1 || a[0].Action != ActionStage || a[0].Result != "error" || a[0].User != "alice" {
					t.Fatalf("audit = %+v", a)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Version != b.version || got.SHA256 == "" || got.Source != SourceUpload {
				t.Fatalf("staged = %+v", got)
			}
			if a := e.audit.actions(); len(a) != 1 || a[0] != "update.stage:ok" {
				t.Fatalf("audit = %v", a)
			}
		})
	}
}

// rebuild creates an unsigned-by-test-key bundle for another version; the
// caller must re-sign if it should verify.
func rebuild(old *testBundle, version, arch string) testBundle {
	b := *old
	b.version, b.arch, b.debName = version, arch, DebName(version, arch)
	b.sums = []byte(sumLine("install.sh", []byte("x")) + sumLine(b.debName, b.deb))
	return b
}

func rebuildSigned(e *svcEnv, old *testBundle, version, arch string) testBundle {
	b := rebuild(old, version, arch)
	b.sig = ed25519.Sign(e.key.priv, b.sums)
	return b
}

func TestStageFilesLayoutAndModes(t *testing.T) {
	e := newSvcEnv(t, nil)
	old := makeBundle(t, e.key, "0.1.5", "arm64")
	if _, err := e.svc.StageFiles(context.Background(), "a", old.input()); err != nil {
		t.Fatal(err)
	}
	b := makeBundle(t, e.key, "0.2.0", "arm64")
	st, err := e.svc.StageFiles(context.Background(), "a", b.input())
	if err != nil {
		t.Fatal(err)
	}
	if st.Size != int64(len(b.deb)) || st.Deb != b.debName {
		t.Fatalf("staged = %+v", st)
	}
	// Only the newest bundle stays; no temp directories.
	if got := listNames(t, e.dir); strings.Join(got, ",") != "0.2.0" {
		t.Fatalf("updates dir = %v", got)
	}
	if got := listNames(t, filepath.Join(e.dir, "0.2.0")); strings.Join(got, ",") != strings.Join([]string{"SHA256SUMS", "SHA256SUMS.sig", b.debName, "source"}, ",") {
		t.Fatalf("bundle dir = %v", got)
	}
	if runtime.GOOS == "windows" {
		return
	}
	fi, _ := os.Stat(filepath.Join(e.dir, "0.2.0"))
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("bundle dir mode = %v, want 0700", fi.Mode().Perm())
	}
	fi, _ = os.Stat(filepath.Join(e.dir, "0.2.0", b.debName))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("package mode = %v, want 0600", fi.Mode().Perm())
	}
}

func TestStageFilesLimits(t *testing.T) {
	ctx := context.Background()
	t.Run("oversized package", func(t *testing.T) {
		lowerMaxDeb(t, 16)
		e := newSvcEnv(t, nil)
		b := makeBundle(t, e.key, "0.2.0", "arm64")
		_, err := e.svc.StageFiles(ctx, "a", b.input())
		if !errors.Is(err, ErrTooLarge) {
			t.Fatalf("err = %v, want ErrTooLarge", err)
		}
		if names := listNames(t, e.dir); len(names) != 0 {
			t.Fatalf("left behind: %v", names)
		}
	})
	t.Run("oversized sums", func(t *testing.T) {
		e := newSvcEnv(t, nil)
		b := makeBundle(t, e.key, "0.2.0", "arm64")
		in := b.input()
		in.Sums = bytes.NewReader(bytes.Repeat([]byte("a"), MaxSumsBytes+1))
		if _, err := e.svc.StageFiles(ctx, "a", in); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("err = %v, want ErrTooLarge", err)
		}
	})
	t.Run("missing part", func(t *testing.T) {
		e := newSvcEnv(t, nil)
		b := makeBundle(t, e.key, "0.2.0", "arm64")
		in := b.input()
		in.Sig = nil
		if _, err := e.svc.StageFiles(ctx, "a", in); !errors.Is(err, ErrBadBundle) {
			t.Fatalf("err = %v, want ErrBadBundle", err)
		}
	})
	t.Run("refusal comes before the body is read", func(t *testing.T) {
		e := newSvcEnv(t, func(o *Options) { o.CurrentVersion = "0.9.0" })
		b := makeBundle(t, e.key, "0.2.0", "arm64")
		r := &countingReader{r: bytes.NewReader(b.deb)}
		in := b.input()
		in.Deb = r
		if _, err := e.svc.StageFiles(ctx, "a", in); !errors.Is(err, ErrDowngrade) {
			t.Fatalf("err = %v", err)
		}
		if r.n != 0 {
			t.Fatalf("read %d bytes of a refused package", r.n)
		}
	})
}

type countingReader struct {
	r interface{ Read([]byte) (int, error) }
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func TestStageTar(t *testing.T) {
	ctx := context.Background()
	mk := func(e *svcEnv) testBundle { return makeBundle(t, e.key, "0.2.0", "arm64") }
	tests := []struct {
		name    string
		entries func(b testBundle) []tarEntry
		raw     func(b testBundle) []byte
		want    error
	}{
		{name: "good", entries: testBundle.tarEntries},
		{name: "good with ./ prefix", entries: func(b testBundle) []tarEntry {
			es := b.tarEntries()
			for i := range es {
				es[i].name = "./" + es[i].name
			}
			return es
		}},
		{name: "any order", entries: func(b testBundle) []tarEntry {
			es := b.tarEntries()
			return []tarEntry{es[2], es[1], es[0]}
		}},
		{name: "missing signature", want: ErrBadBundle, entries: func(b testBundle) []tarEntry { return b.tarEntries()[:2] }},
		{name: "missing package", want: ErrBadBundle, entries: func(b testBundle) []tarEntry { return b.tarEntries()[1:] }},
		{name: "extra file", want: ErrBadBundle, entries: func(b testBundle) []tarEntry {
			return append(b.tarEntries(), tarEntry{name: "install.sh", data: []byte("x")})
		}},
		{name: "directory entry", want: ErrBadBundle, entries: func(b testBundle) []tarEntry {
			return append([]tarEntry{{name: "dir/", typeflag: 53}}, b.tarEntries()...)
		}},
		{name: "symlink entry", want: ErrBadBundle, entries: func(b testBundle) []tarEntry {
			return append([]tarEntry{{name: SumsFile, typeflag: 50, link: "/etc/passwd"}}, b.tarEntries()...)
		}},
		{name: "hard link entry", want: ErrBadBundle, entries: func(b testBundle) []tarEntry {
			return []tarEntry{{name: SumsFile, typeflag: 49, link: "/etc/passwd"}}
		}},
		{name: "path traversal", want: ErrBadBundle, entries: func(b testBundle) []tarEntry {
			return []tarEntry{{name: "../" + SumsFile, data: b.sums}}
		}},
		{name: "nested path", want: ErrBadBundle, entries: func(b testBundle) []tarEntry {
			return []tarEntry{{name: "x/" + SumsFile, data: b.sums}}
		}},
		{name: "absolute path", want: ErrBadBundle, entries: func(b testBundle) []tarEntry {
			return []tarEntry{{name: "/etc/" + SumsFile, data: b.sums}}
		}},
		{name: "duplicate entry", want: ErrBadBundle, entries: func(b testBundle) []tarEntry {
			return append(b.tarEntries(), tarEntry{name: SigFile, data: b.sig})
		}},
		{name: "two packages", want: ErrBadBundle, entries: func(b testBundle) []tarEntry {
			return append(b.tarEntries(), tarEntry{name: DebName("0.2.1", "arm64"), data: b.deb})
		}},
		{name: "wrong arch package", want: ErrWrongArch, entries: func(b testBundle) []tarEntry {
			es := b.tarEntries()
			es[0].name = DebName("0.2.0", "amd64")
			return es
		}},
		{name: "tampered package", want: ErrChecksum, entries: func(b testBundle) []tarEntry {
			es := b.tarEntries()
			es[0].data = append([]byte("x"), es[0].data...)
			return es
		}},
		{name: "bad signature", want: ErrBadSignature, entries: func(b testBundle) []tarEntry {
			es := b.tarEntries()
			es[2].data = bytes.Repeat([]byte{1}, 64)
			return es
		}},
		{name: "oversized sums", want: ErrTooLarge, entries: func(b testBundle) []tarEntry {
			return []tarEntry{{name: SumsFile, data: bytes.Repeat([]byte("a"), MaxSumsBytes+1)}}
		}},
		{name: "not a tar", want: ErrBadBundle, raw: func(testBundle) []byte { return bytes.Repeat([]byte("not a tar archive "), 100) }},
		{name: "empty", want: ErrBadBundle, raw: func(testBundle) []byte { return nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newSvcEnv(t, nil)
			b := mk(e)
			var data []byte
			if tt.raw != nil {
				data = tt.raw(b)
			} else {
				data = makeTar(t, tt.entries(b)...)
			}
			st, err := e.svc.StageTar(ctx, "alice", bytes.NewReader(data))
			if tt.want != nil {
				if !errors.Is(err, tt.want) {
					t.Fatalf("err = %v, want %v", err, tt.want)
				}
				if names := listNames(t, e.dir); len(names) != 0 {
					t.Fatalf("left behind: %v", names)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if st.Version != "0.2.0" || st.Source != SourceUpload {
				t.Fatalf("staged = %+v", st)
			}
			if got, err := os.ReadFile(filepath.Join(e.dir, "0.2.0", b.debName)); err != nil || !bytes.Equal(got, b.deb) {
				t.Fatalf("staged package differs: %v", err)
			}
		})
	}
}

func TestStageBusy(t *testing.T) {
	e := newSvcEnv(t, nil)
	e.svc.opMu.Lock()
	defer e.svc.opMu.Unlock()
	b := makeBundle(t, e.key, "0.2.0", "arm64")
	if _, err := e.svc.StageFiles(context.Background(), "a", b.input()); !errors.Is(err, ErrBusy) {
		t.Fatalf("err = %v, want ErrBusy", err)
	}
}
