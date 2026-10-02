package update

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// Fixed locations. The helper never reads them from configuration: the hub
// process (user nexus) can edit nexus.yaml, and root must not follow a path
// the hub chose (decision #50).
const (
	// DefaultDataDir is the hub data directory of the package; the path unit
	// nexus-update.path watches <DefaultDataDir>/updates/request.json.
	DefaultDataDir = "/var/lib/nexus"
	// DefaultStateDir belongs to root: rollback material and the work area of
	// the helper. Provided by nexus-update.service (StateDirectory).
	DefaultStateDir = "/var/lib/nexus-update"
	// UpdatesDirName is the hub-owned directory below the data directory.
	UpdatesDirName = "updates"
)

// Files below the updates directory.
const (
	RequestFile    = "request.json"     // hub -> helper: install this staged version
	ApplyingFile   = "applying.json"    // helper: claimed request plus the current phase
	ResultFile     = "result.json"      // helper -> hub: outcome, read after the restart
	LastResultFile = "last-result.json" // hub: result after it was audited
	checkCacheFile = "check.json"       // hub: cached GitHub check
)

// Phases the helper reports while it works.
const (
	PhaseQueued   = "queued"
	PhaseVerify   = "verify"
	PhaseBackup   = "backup"
	PhaseInstall  = "install"
	PhaseHealth   = "health"
	PhaseRollback = "rollback"
)

// Result statuses.
const (
	StatusOK         = "ok"
	StatusRolledBack = "rolled_back"
	StatusError      = "error"
)

var sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Request is request.json: a pointer to a staged bundle. The helper uses it
// only to find the bundle; everything is verified again.
type Request struct {
	Version     string    `json:"version"`
	Arch        string    `json:"arch"`
	Deb         string    `json:"deb"`
	SHA256      string    `json:"sha256"`
	RequestedBy string    `json:"requested_by,omitempty"`
	RequestedAt time.Time `json:"requested_at"`
}

// validate checks the shape. File names are derived, never taken as given.
func (r Request) validate() error {
	v, err := ParseVersion(r.Version)
	if err != nil || v.String() != r.Version {
		return fmt.Errorf("%w: bad version %q", ErrBadBundle, r.Version)
	}
	if r.Arch != "arm64" && r.Arch != "amd64" {
		return fmt.Errorf("%w: bad architecture %q", ErrBadBundle, r.Arch)
	}
	if r.Deb != DebName(r.Version, r.Arch) {
		return fmt.Errorf("%w: unexpected package name %q", ErrBadBundle, r.Deb)
	}
	if !sha256Re.MatchString(r.SHA256) {
		return fmt.Errorf("%w: bad checksum", ErrBadBundle)
	}
	return nil
}

// Applying is applying.json: the request the helper claimed, and where it is.
type Applying struct {
	Request
	Phase     string    `json:"phase"`
	StartedAt time.Time `json:"started_at"`
}

// Result is result.json, written by the helper and reported by the hub.
type Result struct {
	Status          string    `json:"status"` // StatusOK, StatusRolledBack or StatusError
	Version         string    `json:"version,omitempty"`
	PreviousVersion string    `json:"previous_version,omitempty"`
	Phase           string    `json:"phase,omitempty"` // where it failed
	Message         string    `json:"message"`
	LogTail         string    `json:"log_tail,omitempty"`
	RequestedBy     string    `json:"requested_by,omitempty"`
	StartedAt       time.Time `json:"started_at"`
	FinishedAt      time.Time `json:"finished_at"`
}

// readLimited reads a regular file of at most max bytes. It refuses symlinks
// and anything that is not a regular file.
func readLimited(path string, max int64) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", filepath.Base(path))
	}
	if fi.Size() > max {
		return nil, fmt.Errorf("%w: %s", ErrTooLarge, filepath.Base(path))
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readAllLimited(f, max)
}

func readAllLimited(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, ErrTooLarge
	}
	return b, nil
}

func tempName() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return ".tmp-" + hex.EncodeToString(b[:])
}

// writeFileAtomic writes dir/name through a temp file and a rename, so a
// reader (the path unit, the helper) never sees a partial file.
func writeFileAtomic(dir, name string, data []byte, mode fs.FileMode) error {
	tmp := filepath.Join(dir, tempName())
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func writeJSONAtomic(dir, name string, v any, mode fs.FileMode) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(dir, name, append(b, '\n'), mode)
}

// readJSON decodes a small JSON file; a missing file returns fs.ErrNotExist.
func readJSON(path string, max int64, v any) error {
	b, err := readLimited(path, max)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	return nil
}

func isNotExist(err error) bool { return errors.Is(err, fs.ErrNotExist) }
