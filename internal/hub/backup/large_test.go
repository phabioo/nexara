package backup

import (
	"context"
	"database/sql"
	"io"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/store"
)

// heapSampler records the peak live heap while it runs.
type heapSampler struct {
	peak atomic.Uint64
	stop chan struct{}
	wg   sync.WaitGroup
}

func startHeapSampler() *heapSampler {
	runtime.GC()
	h := &heapSampler{stop: make(chan struct{})}
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		var ms runtime.MemStats
		t := time.NewTicker(5 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-h.stop:
				return
			case <-t.C:
				runtime.ReadMemStats(&ms)
				if ms.HeapAlloc > h.peak.Load() {
					h.peak.Store(ms.HeapAlloc)
				}
			}
		}
	}()
	return h
}

func (h *heapSampler) finish() uint64 {
	close(h.stop)
	h.wg.Wait()
	return h.peak.Load()
}

// patternReader yields n bytes of a cheap, incompressible-enough pattern.
type patternReader struct{ left int64 }

func (p *patternReader) Read(b []byte) (int, error) {
	if p.left <= 0 {
		return 0, io.EOF
	}
	n := int64(len(b))
	if n > p.left {
		n = p.left
	}
	for i := int64(0); i < n; i++ {
		b[i] = byte(i*131 + p.left)
	}
	p.left -= n
	return int(n), nil
}

func TestEnvelopeStreamsLargeDataWithBoundedMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("large streaming test")
	}
	size, limit := int64(400<<20), uint64(48<<20)
	if raceEnabled {
		size, limit = 96<<20, 24<<20
	}
	s := startHeapSampler()
	pr, pw := io.Pipe()
	errc := make(chan error, 1)
	go func() {
		w, err := Encrypt(pw, passKey)
		if err == nil {
			_, err = io.Copy(w, &patternReader{left: size})
		}
		if err == nil {
			err = w.Close()
		}
		_ = pw.CloseWithError(err)
		errc <- err
	}()
	dec, err := Decrypt(pr, passKey)
	if err != nil {
		t.Fatal(err)
	}
	n, err := io.Copy(io.Discard, dec)
	if err != nil || n != size {
		t.Fatalf("read %d bytes, %v", n, err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	if peak := s.finish(); peak > limit {
		t.Errorf("peak heap %d MiB while streaming %d MiB; memory must not grow with the data", peak>>20, size>>20)
	}
}

func TestLargeDatabaseBackupAndRestoreStaysSmall(t *testing.T) {
	if testing.Short() {
		t.Skip("large database test")
	}
	h := newHub(t)
	must(t, h.st.Close())
	raw, err := sql.Open("sqlite", h.lay.Database)
	must(t, err)
	_, err = raw.Exec("CREATE TABLE junk (b BLOB)")
	must(t, err)
	rows, minSize, limit := 160, int64(150<<20), uint64(64<<20)
	if raceEnabled {
		rows, minSize, limit = 12, 11<<20, 40<<20
	}
	for i := 0; i < rows; i++ {
		_, err = raw.Exec("INSERT INTO junk VALUES (randomblob(1048576))")
		must(t, err)
	}
	must(t, raw.Close())
	fi, err := os.Stat(h.lay.Database)
	must(t, err)
	if fi.Size() < minSize {
		t.Fatalf("test database is only %d MiB", fi.Size()>>20)
	}
	// The hub keeps running in production; here the store is closed, so
	// snapshot through the file based path used by the CLI.
	o := h.svc.o
	o.Snapshot = func(ctx context.Context, dest string) error { return store.SnapshotFile(ctx, h.lay.Database, dest) }
	h.svc = New(o)

	s := startHeapSampler()
	info, err := h.svc.CreateLocal(bg, ReasonManual)
	must(t, err)
	var sink countingWriter
	must(t, h.svc.WriteDownload(bg, &sink, testPass))
	if _, err := h.svc.RestoreLocal(bg, info.Name); err != nil {
		t.Fatal(err)
	}
	if peak := s.finish(); peak > limit {
		t.Errorf("peak heap %d MiB for a %d MiB database", peak>>20, fi.Size()>>20)
	}
	if sink.n < fi.Size() {
		t.Errorf("download is %d bytes for a %d byte database", sink.n, fi.Size())
	}
	fi2, err := os.Stat(h.lay.Database)
	must(t, err)
	if fi2.Size() < minSize {
		t.Errorf("restored database is %d MiB", fi2.Size()>>20)
	}
}
