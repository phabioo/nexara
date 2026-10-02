package update

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/phabioo/nexara/internal/release"
)

// sourceFile records, for the view, where a staged bundle came from. The
// helper ignores it.
const sourceFile = "source"

// Staging sources.
const (
	SourceGitHub = "github"
	SourceUpload = "upload"
)

// StageInput is an uploaded bundle: the three release files. DebName must be
// the original file name (nexus_<version>_<arch>.deb); Sums is the complete
// SHA256SUMS of the release and Sig its SHA256SUMS.sig. A multipart handler
// passes the three form parts here.
type StageInput struct {
	DebName string
	Deb     io.Reader
	Sums    io.Reader
	Sig     io.Reader
}

// StageRelease downloads the newest release found by the GitHub check
// (running the check first if needed), verifies it and stages it. It fails
// with ErrCheckDisabled while the check is off and ErrNoUpdate when the
// release is not newer than the running version.
func (s *Service) StageRelease(ctx context.Context, actor string) (Staged, error) {
	cfg, err := loadConfig(ctx, s.o.Settings)
	if err != nil {
		return Staged{}, err
	}
	if !cfg.CheckGitHub {
		return Staged{}, ErrCheckDisabled
	}
	if !s.opMu.TryLock() {
		return Staged{}, ErrBusy
	}
	defer s.opMu.Unlock()

	st, err := s.stageRelease(ctx, cfg)
	s.audit(ctx, actor, ActionStage, stageDetail(SourceGitHub, st.Version), err)
	return st, err
}

func (s *Service) stageRelease(ctx context.Context, cfg Config) (Staged, error) {
	s.mu.Lock()
	chk := s.check
	fresh := chk != nil && chk.Error == "" && chk.Channel == cfg.Channel && s.now().Sub(chk.CheckedAt) < checkEvery
	s.mu.Unlock()
	if !fresh {
		res, err := s.doCheck(ctx, cfg)
		if err != nil {
			return Staged{}, err
		}
		chk = &res
	}
	if chk.Latest == nil || (!s.newer(chk.Latest.Version) && !cfg.AllowDowngrade) {
		return Staged{}, ErrNoUpdate
	}
	rel := *chk.Latest
	debName := DebName(rel.Version, s.o.Arch)
	if _, err := checkPolicy(debName, s.o.Arch, s.o.CurrentVersion, cfg.AllowDowngrade); err != nil {
		return Staged{}, err
	}
	tmp, err := os.MkdirTemp(s.o.Dir, ".incoming-")
	if err != nil {
		return Staged{}, err
	}
	defer os.RemoveAll(tmp)
	for _, a := range []struct {
		name string
		max  int64
	}{{SumsFile, MaxSumsBytes}, {SigFile, MaxSumsBytes}, {debName, maxDeb}} {
		if err := s.gh.download(ctx, rel.Tag, a.name, filepath.Join(tmp, a.name), a.max); err != nil {
			return Staged{}, err
		}
	}
	return s.finishStage(tmp, debName, SourceGitHub, cfg.AllowDowngrade)
}

// StageFiles verifies an uploaded bundle and stages it. The checks are the
// same as for a download: signature, checksum, architecture, no downgrade.
func (s *Service) StageFiles(ctx context.Context, actor string, in StageInput) (Staged, error) {
	if !s.opMu.TryLock() {
		return Staged{}, ErrBusy
	}
	defer s.opMu.Unlock()
	st, err := s.stageFiles(ctx, in)
	s.audit(ctx, actor, ActionStage, stageDetail(SourceUpload, st.Version), err)
	return st, err
}

func (s *Service) stageFiles(ctx context.Context, in StageInput) (Staged, error) {
	cfg, err := loadConfig(ctx, s.o.Settings)
	if err != nil {
		return Staged{}, err
	}
	// Cheap refusals first, before reading hundreds of megabytes.
	if _, err := checkPolicy(in.DebName, s.o.Arch, s.o.CurrentVersion, cfg.AllowDowngrade); err != nil {
		return Staged{}, err
	}
	if in.Deb == nil || in.Sums == nil || in.Sig == nil {
		return Staged{}, fmt.Errorf("%w: package, %s and %s are all required", ErrBadBundle, SumsFile, SigFile)
	}
	tmp, err := os.MkdirTemp(s.o.Dir, ".incoming-")
	if err != nil {
		return Staged{}, err
	}
	defer os.RemoveAll(tmp)
	for _, p := range []struct {
		name string
		r    io.Reader
		max  int64
	}{{SumsFile, in.Sums, MaxSumsBytes}, {SigFile, in.Sig, MaxSumsBytes}, {in.DebName, in.Deb, maxDeb}} {
		if err := copyNew(filepath.Join(tmp, p.name), p.r, p.max); err != nil {
			return Staged{}, fmt.Errorf("%s: %w", p.name, err)
		}
	}
	return s.finishStage(tmp, in.DebName, SourceUpload, cfg.AllowDowngrade)
}

// StageTar stages a bundle uploaded as one uncompressed tar archive that
// holds exactly three regular files: nexus_<version>_<arch>.deb, SHA256SUMS
// and SHA256SUMS.sig (a leading "./" is fine, directories or anything else
// are not). The three release assets can be packed with:
//
//	tar cf nexus-update.tar nexus_0.2.0_arm64.deb SHA256SUMS SHA256SUMS.sig
//
// Callers should limit the body to MaxBundleBytes.
func (s *Service) StageTar(ctx context.Context, actor string, r io.Reader) (Staged, error) {
	if !s.opMu.TryLock() {
		return Staged{}, ErrBusy
	}
	defer s.opMu.Unlock()
	st, err := s.stageTar(ctx, r)
	s.audit(ctx, actor, ActionStage, stageDetail(SourceUpload, st.Version), err)
	return st, err
}

func (s *Service) stageTar(ctx context.Context, r io.Reader) (Staged, error) {
	cfg, err := loadConfig(ctx, s.o.Settings)
	if err != nil {
		return Staged{}, err
	}
	tmp, err := os.MkdirTemp(s.o.Dir, ".incoming-")
	if err != nil {
		return Staged{}, err
	}
	defer os.RemoveAll(tmp)

	tr := tar.NewReader(io.LimitReader(r, MaxBundleBytes))
	seen := map[string]bool{}
	debName := ""
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Staged{}, fmt.Errorf("%w: reading tar: %v", ErrBadBundle, err)
		}
		if err := ctx.Err(); err != nil {
			return Staged{}, err
		}
		if hdr.Typeflag != tar.TypeReg {
			return Staged{}, fmt.Errorf("%w: %q is not a regular file", ErrBadBundle, hdr.Name)
		}
		name := strings.TrimPrefix(hdr.Name, "./")
		var max int64
		switch {
		case name == SumsFile || name == SigFile:
			max = MaxSumsBytes
		case debNameRe.MatchString(name):
			if debName != "" {
				return Staged{}, fmt.Errorf("%w: more than one package", ErrBadBundle)
			}
			debName, max = name, maxDeb
			if _, err := checkPolicy(debName, s.o.Arch, s.o.CurrentVersion, cfg.AllowDowngrade); err != nil {
				return Staged{}, err
			}
		default:
			return Staged{}, fmt.Errorf("%w: unexpected entry %q", ErrBadBundle, hdr.Name)
		}
		if seen[name] {
			return Staged{}, fmt.Errorf("%w: duplicate entry %q", ErrBadBundle, name)
		}
		seen[name] = true
		if hdr.Size > max {
			return Staged{}, fmt.Errorf("%w: %s", ErrTooLarge, name)
		}
		if err := copyNew(filepath.Join(tmp, name), tr, max); err != nil {
			return Staged{}, fmt.Errorf("%s: %w", name, err)
		}
	}
	if debName == "" || !seen[SumsFile] || !seen[SigFile] {
		return Staged{}, fmt.Errorf("%w: the archive must hold the package, %s and %s", ErrBadBundle, SumsFile, SigFile)
	}
	return s.finishStage(tmp, debName, SourceUpload, cfg.AllowDowngrade)
}

// finishStage verifies the files in tmp and moves them to <Dir>/<version>.
// Only one bundle stays staged: an older one is removed to spare the SD card.
func (s *Service) finishStage(tmp, debName, source string, allowDowngrade bool) (Staged, error) {
	v, err := checkPolicy(debName, s.o.Arch, s.o.CurrentVersion, allowDowngrade)
	if err != nil {
		return Staged{}, err
	}
	digest, size, err := s.verifyDir(tmp, debName)
	if err != nil {
		return Staged{}, err
	}
	if err := os.WriteFile(filepath.Join(tmp, sourceFile), []byte(source+"\n"), 0o600); err != nil {
		return Staged{}, err
	}
	if err := os.Chmod(tmp, 0o700); err != nil {
		return Staged{}, err
	}
	s.removeStaged()
	final := filepath.Join(s.o.Dir, v.String())
	if err := os.Rename(tmp, final); err != nil {
		return Staged{}, err
	}
	fi, err := os.Stat(filepath.Join(final, debName))
	if err != nil {
		return Staged{}, err
	}
	return Staged{Version: v.String(), Arch: s.o.Arch, Deb: debName, SHA256: digest, Size: size,
		StagedAt: fi.ModTime(), Source: source}, nil
}

// removeStaged deletes every staged version directory.
func (s *Service) removeStaged() {
	entries, err := os.ReadDir(s.o.Dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if v, err := ParseVersion(e.Name()); err == nil && v.String() == e.Name() && e.IsDir() {
			_ = os.RemoveAll(filepath.Join(s.o.Dir, e.Name()))
		}
	}
}

// verifyDir checks signature and checksum of the bundle in dir and returns the
// package digest and size. It reads each file once, regular files only.
func (s *Service) verifyDir(dir, debName string) (digest string, size int64, err error) {
	sums, err := readLimited(filepath.Join(dir, SumsFile), MaxSumsBytes)
	if err != nil {
		return "", 0, fmt.Errorf("%w: %s: %v", ErrBadBundle, SumsFile, err)
	}
	sig, err := readLimited(filepath.Join(dir, SigFile), MaxSumsBytes)
	if err != nil {
		return "", 0, fmt.Errorf("%w: %s: %v", ErrBadBundle, SigFile, err)
	}
	digest, err = verifyMeta(s.o.Key, sums, sig, debName)
	if err != nil {
		return "", 0, err
	}
	debPath := filepath.Join(dir, debName)
	fi, err := os.Lstat(debPath)
	if err != nil || !fi.Mode().IsRegular() {
		return "", 0, fmt.Errorf("%w: %s is missing or not a regular file", ErrBadBundle, debName)
	}
	if fi.Size() > maxDeb {
		return "", 0, fmt.Errorf("%w: %s", ErrTooLarge, debName)
	}
	f, err := os.Open(debPath)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	if err := verifyDeb(sums, debName, io.LimitReader(f, maxDeb+1)); err != nil {
		return "", 0, err
	}
	return digest, fi.Size(), nil
}

// copyNew writes r to a new file (0600) and fails with ErrTooLarge beyond max.
func copyNew(path string, r io.Reader, max int64) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, io.LimitReader(r, max+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n > max {
		return ErrTooLarge
	}
	return nil
}

func stageDetail(source, version string) string {
	if version == "" {
		return "source " + source
	}
	return "version " + version + ", source " + source
}

func parseSumsDigest(sums []byte, name string) (string, error) {
	entries, err := release.ParseSums(sums)
	if err != nil {
		return "", err
	}
	d, ok := entries[name]
	if !ok {
		return "", fmt.Errorf("%s not listed", name)
	}
	return d, nil
}

// --- install request ---

// RequestInstall asks the root helper to install a staged version: it
// verifies the bundle again, then writes request.json atomically. The path
// unit nexus-update.path starts the helper; the state reads "installing"
// until the helper's result is reported (see Reconcile).
func (s *Service) RequestInstall(ctx context.Context, actor, version string) error {
	if !s.opMu.TryLock() {
		return ErrBusy
	}
	defer s.opMu.Unlock()
	err := s.requestInstall(ctx, actor, version)
	s.audit(ctx, actor, ActionRequest, "version "+version, err)
	return err
}

func (s *Service) requestInstall(ctx context.Context, actor, version string) error {
	if !s.o.HelperWatches {
		return ErrUnsupported
	}
	v, err := ParseVersion(version)
	if err != nil || v.String() != version {
		return fmt.Errorf("%w: %q", ErrNotStaged, version)
	}
	cfg, err := loadConfig(ctx, s.o.Settings)
	if err != nil {
		return err
	}
	// An unreported result comes first (it also clears applying.json).
	if _, err := s.Reconcile(ctx); err != nil {
		return err
	}
	if cur := s.installing(); cur != nil && !cur.Stale {
		return ErrBusy
	}
	dir := filepath.Join(s.o.Dir, v.String())
	if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() {
		return fmt.Errorf("%w: %s", ErrNotStaged, version)
	}
	debName := DebName(v.String(), s.o.Arch)
	if _, err := checkPolicy(debName, s.o.Arch, s.o.CurrentVersion, cfg.AllowDowngrade); err != nil {
		return err
	}
	digest, _, err := s.verifyDir(dir, debName)
	if err != nil {
		return err
	}
	// Leftovers of a dead helper must not be mistaken for this update.
	_ = os.Remove(filepath.Join(s.o.Dir, ApplyingFile))
	_ = os.Remove(filepath.Join(s.o.Dir, ResultFile))
	req := Request{Version: v.String(), Arch: s.o.Arch, Deb: debName, SHA256: digest,
		RequestedBy: actor, RequestedAt: s.now().UTC()}
	return writeJSONAtomic(s.o.Dir, RequestFile, req, 0o600)
}

// CancelRequest withdraws a request the helper has not picked up yet. It
// returns false when there is nothing to cancel (the helper already started).
func (s *Service) CancelRequest(ctx context.Context, actor string) (bool, error) {
	err := os.Remove(filepath.Join(s.o.Dir, RequestFile))
	if isNotExist(err) {
		return false, nil
	}
	s.audit(ctx, actor, ActionRequest, "cancelled", err)
	return err == nil, err
}
