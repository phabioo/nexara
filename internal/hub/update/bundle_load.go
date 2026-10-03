package update

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// loadedBundle is a verified bundle whose package has been copied into the
// helper's own work directory, so nothing the hub user can modify is used
// after the check.
type loadedBundle struct {
	debName string
	debPath string // root-owned copy
	sums    []byte
	sig     []byte
	digest  string
}

// loadBundle reads SHA256SUMS and its signature from src, verifies them,
// copies the package into dst and verifies the copy against the sums.
func (a *applier) loadBundle(src *os.Root, owner func(fs.FileInfo) error, debName, dst string) (*loadedBundle, error) {
	sums, err := readRootFile(src, SumsFile, MaxSumsBytes, owner)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrBadBundle, SumsFile, err)
	}
	sig, err := readRootFile(src, SigFile, MaxSumsBytes, owner)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrBadBundle, SigFile, err)
	}
	digest, err := verifyMeta(a.Key, sums, sig, debName)
	if err != nil {
		return nil, err
	}
	in, err := openRootFile(src, debName, maxDeb, owner)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrBadBundle, debName, err)
	}
	defer in.Close()
	// 0755/0644: the copy holds public release files, and apt's _apt user
	// should be able to read it (otherwise apt warns about unsandboxed access).
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return nil, err
	}
	debPath := filepath.Join(dst, debName)
	out, err := os.OpenFile(debPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return nil, err
	}
	n, err := io.Copy(out, io.LimitReader(in, maxDeb+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, err
	}
	if n > maxDeb {
		return nil, fmt.Errorf("%w: %s", ErrTooLarge, debName)
	}
	cp, err := os.Open(debPath)
	if err != nil {
		return nil, err
	}
	defer cp.Close()
	if err := verifyDeb(sums, debName, cp); err != nil {
		return nil, err
	}
	return &loadedBundle{debName: debName, debPath: debPath, sums: sums, sig: sig, digest: digest}, nil
}

const (
	installedDir = "installed"
	installedNew = "installed.new"
	installedOld = "installed.old"
)

// prepareRollback finds a verified copy of the running version to fall back
// to: first the copy kept after the last successful update, then a bundle of
// that version still staged in the updates directory. The second return value
// says why nothing was found.
func (a *applier) prepareRollback() (*loadedBundle, string) {
	cur, err := ParseVersion(a.CurrentVersion)
	if err != nil {
		return nil, "this is a development build"
	}
	debName := DebName(cur.String(), a.Arch)
	dst := filepath.Join(a.work, "rollback")

	reason := "no copy of " + debName + " was kept by an earlier update"
	if kept, err := os.OpenRoot(filepath.Join(a.StateDir, installedDir)); err == nil {
		defer kept.Close()
		// The directory belongs to root; ownership is not checked, the
		// signature is.
		b, lerr := a.loadBundle(kept, nil, debName, dst)
		if lerr == nil {
			return b, ""
		}
		reason = "the kept copy is unusable: " + lerr.Error()
		_ = os.RemoveAll(dst)
	}
	if staged, err := a.root.OpenRoot(cur.String()); err == nil {
		defer staged.Close()
		if fi, err := a.root.Lstat(cur.String()); err == nil && fi.IsDir() && sameDir(staged, fi) == nil && checkTrustedDir(staged, a.CheckOwner) == nil {
			if b, lerr := a.loadBundle(staged, a.CheckOwner, debName, dst); lerr == nil {
				return b, ""
			}
			_ = os.RemoveAll(dst)
		}
	}
	return nil, reason
}

// saveInstalled keeps the package that was just installed (and proved
// healthy) as the rollback material of the next update.
func (a *applier) saveInstalled(b *loadedBundle) error {
	tmp := filepath.Join(a.StateDir, installedNew)
	if err := os.RemoveAll(tmp); err != nil {
		return err
	}
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		return err
	}
	in, err := os.Open(b.debPath)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(filepath.Join(tmp, b.debName), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(tmp, SumsFile), b.sums, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(tmp, SigFile), b.sig, 0o644); err != nil {
		return err
	}
	final, old := filepath.Join(a.StateDir, installedDir), filepath.Join(a.StateDir, installedOld)
	if err := os.RemoveAll(old); err != nil {
		return err
	}
	if err := os.Rename(final, old); err != nil && !isNotExist(err) {
		return err
	}
	if err := os.Rename(tmp, final); err != nil {
		return err
	}
	return os.RemoveAll(old)
}
