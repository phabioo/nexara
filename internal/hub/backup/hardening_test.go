package backup

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/phabioo/nexara/internal/hub/store"
)

// Security review B-03: a failed restore leaves an audit entry, with the
// client address when the caller knows it.
func TestFailedRestoresAreAudited(t *testing.T) {
	h := newHub(t)
	good := downloadBytes(t, h, testPass)
	h.mu.Lock()
	h.audits = nil
	h.mu.Unlock()

	ctx := WithRemoteAddr(WithActor(bg, "setup"), "203.0.113.9")
	tests := []struct {
		name string
		run  func() error
	}{
		{"wrong passphrase", func() error { _, err := h.svc.Restore(ctx, bytes.NewReader(good), "wrong wrong wrong"); return err }},
		{"passphrase missing", func() error {
			_, err := h.svc.RestoreFrom(ctx, bytes.NewReader(good), "")
			return err
		}},
		{"missing file", func() error { _, err := h.svc.RestoreFile(ctx, h.root+"/nope.nxbk", ""); return err }},
		{"bad local name", func() error { _, err := h.svc.RestoreLocal(ctx, "../../etc/passwd"); return err }},
	}
	for i, tc := range tests {
		if err := tc.run(); err == nil {
			t.Fatalf("%s: restore succeeded", tc.name)
		}
		h.mu.Lock()
		got := append([]store.AuditEntry(nil), h.audits...)
		h.mu.Unlock()
		if len(got) != i+1 {
			t.Fatalf("%s: %d audit entries, want %d: %+v", tc.name, len(got), i+1, got)
		}
		e := got[i]
		if e.Action != ActionRestore || e.Result != store.AuditError || e.User != "setup" ||
			!strings.Contains(e.Detail, "ip=203.0.113.9") || strings.Contains(e.Detail, "wrong wrong") {
			t.Errorf("%s: entry %+v", tc.name, e)
		}
	}
}

// Security review A-09: what the setup wizard recorded before the restore, and
// the restore itself, go into the restored database, in that order.
func TestRestoreAuditGoesToTheRestoredDatabase(t *testing.T) {
	h := newHub(t)
	data := downloadBytes(t, h, testPass)
	tgt := newTarget(t)
	type rec struct {
		db string
		e  store.AuditEntry
	}
	var got []rec
	o := tgt.svc.o
	o.AuditRestore = func(_ context.Context, db string, e store.AuditEntry) error {
		got = append(got, rec{db, e})
		return nil
	}
	svc := New(o)
	carried := []store.AuditEntry{
		{ID: 7, User: "setup", Action: ActionRestore, Result: store.AuditDenied, Detail: "ip=203.0.113.9 reason=bad_upload"},
		{ID: 8, User: "setup", Action: ActionRestore, Result: store.AuditDenied, Detail: "ip=203.0.113.9 reason=rate_limited"},
	}
	ctx := WithCarriedAudit(WithRemoteAddr(WithActor(bg, "setup"), "203.0.113.9"), carried)
	if _, err := svc.Restore(ctx, bytes.NewReader(data), testPass); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("%d entries written, want 3: %+v", len(got), got)
	}
	for i, r := range got {
		if r.db != tgt.lay.Database {
			t.Errorf("entry %d went to %s", i, r.db)
		}
	}
	if got[0].e.Detail != carried[0].Detail || got[1].e.Detail != carried[1].Detail || got[0].e.ID != 0 {
		t.Errorf("carried entries: %+v %+v", got[0].e, got[1].e)
	}
	if last := got[2].e; last.Result != store.AuditOK || last.User != "setup" || !strings.Contains(last.Detail, "ip=203.0.113.9") {
		t.Errorf("restore entry: %+v", last)
	}
}

// Security review B-07: the hub closes its database right before the swap.
func TestBeforeSwapHook(t *testing.T) {
	t.Run("runs after staging, before the first rename", func(t *testing.T) {
		h := newHub(t)
		data := downloadBytes(t, h, testPass)
		must(t, os.WriteFile(h.lay.ConfigPath, []byte("# live config\n"), 0o640))
		must(t, h.st.Close())
		o := h.svc.o
		calls := 0
		o.BeforeSwap = func() error {
			calls++
			if b, _ := os.ReadFile(h.lay.ConfigPath); string(b) != "# live config\n" {
				t.Error("the live config was already replaced when BeforeSwap ran")
			}
			return nil
		}
		if _, err := New(o).Restore(bg, bytes.NewReader(data), testPass); err != nil {
			t.Fatal(err)
		}
		if calls != 1 {
			t.Errorf("BeforeSwap ran %d times", calls)
		}
	})

	t.Run("an error cancels the restore", func(t *testing.T) {
		h := newHub(t)
		data := downloadBytes(t, h, testPass)
		must(t, h.st.Close())
		before := fileState(t, h.root, true)
		o := h.svc.o
		o.BeforeSwap = func() error { return errors.New("busy") }
		if _, err := New(o).Restore(bg, bytes.NewReader(data), testPass); err == nil || !strings.Contains(err.Error(), "busy") {
			t.Fatalf("err = %v", err)
		}
		sameState(t, before, fileState(t, h.root, true))
	})

	t.Run("a failed swap after the close says the hub must restart", func(t *testing.T) {
		h := newHub(t)
		data := downloadBytes(t, h, testPass)
		must(t, h.st.Close())
		before := fileState(t, h.root, true)
		o := h.svc.o
		o.BeforeSwap = func() error { return nil }
		svc := New(o)
		svc.rename = func(string, string) error { return errors.New("injected") }
		_, err := svc.Restore(bg, bytes.NewReader(data), testPass)
		if !errors.Is(err, ErrStoreClosed) {
			t.Fatalf("err = %v, want ErrStoreClosed", err)
		}
		sameState(t, before, fileState(t, h.root, true))
	})
}

// buildTar encrypts a tar built by fn with the test key.
func buildArchive(t *testing.T, m Manifest, fn func(tw *tar.Writer)) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	mb := mustJSON(t, m)
	must(t, tw.WriteHeader(&tar.Header{Name: nameManifest, Size: int64(len(mb)), Mode: 0o600, Typeflag: tar.TypeReg}))
	_, _ = tw.Write(mb)
	fn(tw)
	must(t, tw.Close())
	return buf.Bytes()
}

func fixtureManifest(size int64) Manifest {
	m := Manifest{Format: ArchiveVersion, SchemaVersion: 1, HubName: "x", Reason: ReasonDownload}
	for _, mem := range members {
		if mem.required {
			m.Files = append(m.Files, FileEntry{Name: mem.name, Size: size, SHA256: strings.Repeat("0", 64)})
		}
	}
	return m
}

// Security review A-05.
func TestArchiveRejectsSparseAndOversizedMembers(t *testing.T) {
	t.Run("PAX records on a member", func(t *testing.T) {
		m := fixtureManifest(1)
		b := buildArchive(t, m, func(tw *tar.Writer) {
			must(t, tw.WriteHeader(&tar.Header{Name: m.Files[0].Name, Size: 1, Mode: 0o600, Typeflag: tar.TypeReg,
				Format: tar.FormatPAX, PAXRecords: map[string]string{"comment": "x"}}))
			_, _ = tw.Write([]byte("x"))
		})
		_, err := readArchive(bytes.NewReader(b), readVerify, "")
		if err == nil || !strings.Contains(err.Error(), "unexpected archive member") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("a PAX sparse header", func(t *testing.T) {
		// Hand-made blocks: the tar writer refuses to emit GNU.sparse records.
		m := fixtureManifest(1)
		mb := mustJSON(t, m)
		pax := paxRecord("GNU.sparse.major", "1") + paxRecord("GNU.sparse.minor", "0") +
			paxRecord("GNU.sparse.realsize", "1500000000") + paxRecord("GNU.sparse.name", m.Files[0].Name)
		var buf bytes.Buffer
		buf.Write(rawTarBlock(nameManifest, int64(len(mb)), '0'))
		buf.Write(padBlock(mb))
		buf.Write(rawTarBlock("PaxHeaders/x", int64(len(pax)), 'x'))
		buf.Write(padBlock([]byte(pax)))
		buf.Write(rawTarBlock("sparse", 512+1, '0')) // sparse map block + 1 data byte
		buf.Write(padBlock([]byte("1\n0\n1\n")))
		buf.Write(padBlock([]byte("x")))
		buf.Write(make([]byte, 1024))
		if _, err := readArchive(&buf, readExtract, t.TempDir()); err == nil || !strings.Contains(err.Error(), "unexpected archive member") {
			t.Fatalf("a sparse member: err = %v", err)
		}
	})
	t.Run("PAX records on the manifest", func(t *testing.T) {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		mb := mustJSON(t, fixtureManifest(1))
		must(t, tw.WriteHeader(&tar.Header{Name: nameManifest, Size: int64(len(mb)), Mode: 0o600, Typeflag: tar.TypeReg,
			Format: tar.FormatPAX, PAXRecords: map[string]string{"comment": "x"}}))
		_, _ = tw.Write(mb)
		must(t, tw.Close())
		if _, err := readArchive(&buf, readVerify, ""); err == nil {
			t.Fatal("accepted a PAX manifest header")
		}
	})
	t.Run("sum of member sizes over the cap", func(t *testing.T) {
		old := archiveLimit
		archiveLimit = 100
		t.Cleanup(func() { archiveLimit = old })
		m := fixtureManifest(60) // two or more required members: 120+ > 100
		b := buildArchive(t, m, func(*tar.Writer) {})
		_, err := readArchive(bytes.NewReader(b), readExtract, t.TempDir())
		if !errors.Is(err, errTooLarge) {
			t.Fatalf("err = %v, want errTooLarge", err)
		}
	})
	t.Run("a single member over the cap", func(t *testing.T) {
		m := fixtureManifest(MaxArchiveBytes + 1)
		b := buildArchive(t, m, func(*tar.Writer) {})
		if _, err := readArchive(bytes.NewReader(b), readVerify, ""); !errors.Is(err, errTooLarge) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("the decrypted stream is capped too", func(t *testing.T) {
		// Members that honestly fit the manifest, but the stream limit is below their framing.
		old := archiveLimit
		t.Cleanup(func() { archiveLimit = old })
		h := newHub(t)
		data := downloadBytes(t, h, testPass)
		dec, err := Decrypt(bytes.NewReader(data), PassphraseKey(testPass, testKDF))
		must(t, err)
		archiveLimit = -2*maxManifestSize + 10 // the reader may deliver 10 bytes only
		if _, err := readArchive(dec, readVerify, ""); err == nil {
			t.Fatal("a stream beyond the limit was read")
		}
	})
}

func TestKDFCeilings(t *testing.T) {
	tests := []struct {
		name string
		p    KDFParams
		ok   bool
	}{
		{"default", DefaultKDF, true},
		{"the ceiling", KDFParams{Time: 6, MemoryKiB: 256 * 1024, Threads: 4}, true},
		{"too much memory", KDFParams{Time: 3, MemoryKiB: 256*1024 + 1, Threads: 2}, false},
		{"too many passes", KDFParams{Time: 7, MemoryKiB: 128 * 1024, Threads: 2}, false},
		{"too many lanes", KDFParams{Time: 3, MemoryKiB: 128 * 1024, Threads: 5}, false},
		{"zero passes", KDFParams{Time: 0, MemoryKiB: 128 * 1024, Threads: 2}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.p.validate(); (err == nil) != tc.ok {
				t.Errorf("validate(%+v) = %v, want ok=%v", tc.p, err, tc.ok)
			}
		})
	}
}

func paxRecord(k, v string) string {
	l := len(k) + len(v) + 3
	for {
		s := fmt.Sprintf("%d %s=%s\n", l, k, v)
		if len(s) == l {
			return s
		}
		l = len(s)
	}
}

// rawTarBlock is a ustar header block.
func rawTarBlock(name string, size int64, flag byte) []byte {
	b := make([]byte, 512)
	copy(b[0:], name)
	copy(b[100:], "0000600\x00")
	copy(b[108:], "0000000\x00")
	copy(b[116:], "0000000\x00")
	copy(b[124:], fmt.Sprintf("%011o\x00", size))
	copy(b[136:], "00000000000\x00")
	b[156] = flag
	copy(b[257:], "ustar\x0000")
	copy(b[148:], "        ")
	sum := 0
	for _, c := range b {
		sum += int(c)
	}
	copy(b[148:], fmt.Sprintf("%06o\x00 ", sum))
	return b
}

func padBlock(p []byte) []byte {
	out := append([]byte(nil), p...)
	if r := len(out) % 512; r != 0 {
		out = append(out, make([]byte, 512-r)...)
	}
	return out
}
