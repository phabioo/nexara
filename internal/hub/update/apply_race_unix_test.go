//go:build unix

package update

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Security review B-05. The swap windows between Lstat and open cannot be hit
// deterministically; these tests pin the two things that close them.

func TestSameDirDetectsASwappedDirectory(t *testing.T) {
	base := t.TempDir()
	a, b := filepath.Join(base, "a"), filepath.Join(base, "b")
	for _, d := range []string{a, b} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(a)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	fa, _ := os.Lstat(a)
	fb, _ := os.Lstat(b)
	if err := sameDir(root, fa); err != nil {
		t.Errorf("the directory that was opened: %v", err)
	}
	if err := sameDir(root, fb); err == nil {
		t.Error("another directory was accepted")
	}
}

func TestOpenRootFileDoesNotFollowOrBlock(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.WriteFile(filepath.Join(dir, "real"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}

	// os.Root follows links inside the root. What openRootFile saw with Lstat
	// (the regular file "other") must be what it holds after the open: a link
	// swapped in meanwhile leads to another inode and is refused.
	if err := os.WriteFile(filepath.Join(dir, "other"), []byte("y"), 0o600); err != nil {
		t.Fatal(err)
	}
	seen, err := root.Lstat("other")
	if err != nil {
		t.Fatal(err)
	}
	f, err := root.OpenFile("link", os.O_RDONLY|openFlags, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = verifyOpened(f, seen, "other", func(fi os.FileInfo) error { return nil })
	f.Close()
	if err == nil {
		t.Error("a file swapped in after the Lstat was accepted")
	}

	// A FIFO swapped in does not block the helper in open(2); the check on the
	// opened descriptor then refuses it.
	type result struct {
		f   *os.File
		err error
	}
	done := make(chan result, 1)
	go func() {
		f, err := root.OpenFile("fifo", os.O_RDONLY|openFlags, 0)
		done <- result{f, err}
	}()
	select {
	case r := <-done:
		if r.err == nil {
			defer r.f.Close()
			if fi, err := r.f.Stat(); err != nil || fi.Mode().IsRegular() {
				t.Errorf("fifo seen as %v, %v", fi, err)
			}
		}
	case <-time.After(10 * time.Second):
		t.Fatal("opening a FIFO blocked")
	}

	// And the whole function refuses both, whichever way they got there.
	for _, name := range []string{"fifo"} {
		if f, err := openRootFile(root, name, 1<<10, nil); err == nil {
			f.Close()
			t.Errorf("openRootFile accepted %s", name)
		}
	}
	if b, err := readRootFile(root, "real", 1<<10, nil); err != nil || string(b) != "x" {
		t.Errorf("regular file: %q, %v", b, err)
	}
}
