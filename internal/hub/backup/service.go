package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/phabioo/nexara/internal/hub/auth"
	"github.com/phabioo/nexara/internal/hub/store"
)

// Audit actions.
const (
	ActionCreate   = "backup.create"
	ActionDownload = "backup.download"
	ActionRestore  = "backup.restore"
)

// Settings keys (the settings table of decision #49) and their defaults.
const (
	SettingTime = "backup.time" // "HH:MM" in the hub's time zone
	SettingKeep = "backup.keep" // number of local backups to keep

	DefaultTime = "03:00"
	DefaultKeep = 7
	maxKeep     = 100
)

// Settings is the part of the settings store the backup uses.
type Settings interface {
	Get(ctx context.Context, key string) (value string, ok bool, err error)
	Set(ctx context.Context, key, value string) error
}

// AuditFunc writes an audit entry; failures are the caller's to log.
type AuditFunc func(ctx context.Context, e store.AuditEntry)

// Options configure a Service.
type Options struct {
	Layout Layout
	// Snapshot writes a consistent copy of the live database to dest, which
	// must not exist: (*store.Store).Snapshot in the hub, a store.SnapshotFile
	// closure in the CLI.
	Snapshot func(ctx context.Context, dest string) error
	// Settings holds backup.time and backup.keep; nil means defaults only.
	Settings Settings
	// Audit receives backup.create and backup.download entries; nil is silent.
	Audit AuditFunc
	// AuditRestore writes the backup.restore entry into the database file that
	// was just restored (the old one is gone). Nil skips it.
	AuditRestore func(ctx context.Context, dbPath string, e store.AuditEntry) error

	HubName    string
	HubVersion string
	// KDF are the argon2id parameters of passphrase backups; zero means DefaultKDF.
	KDF KDFParams
	// LatestSchema is the schema version this binary expects; nil means
	// store.LatestSchemaVersion.
	LatestSchema func() int
	Now          func() time.Time
	Logger       *slog.Logger
}

// Service creates, lists and restores backups. It is safe for concurrent use;
// operations that touch files run one at a time.
type Service struct {
	o      Options
	mu     sync.Mutex
	rename func(oldpath, newpath string) error // replaced in tests
}

// New returns a Service.
func New(o Options) *Service {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.KDF == (KDFParams{}) {
		o.KDF = DefaultKDF
	}
	if o.LatestSchema == nil {
		o.LatestSchema = store.LatestSchemaVersion
	}
	return &Service{o: o, rename: os.Rename}
}

type actorKey struct{}

// WithActor names who triggered an operation in the audit entry (operator ID,
// "cli"); the default is "system".
func WithActor(ctx context.Context, actor string) context.Context {
	return context.WithValue(ctx, actorKey{}, actor)
}

func actorOf(ctx context.Context) string {
	if a, _ := ctx.Value(actorKey{}).(string); a != "" {
		return a
	}
	return "system"
}

func (s *Service) audit(ctx context.Context, action, detail string, err error) {
	if s.o.Audit == nil {
		return
	}
	res := store.AuditOK
	if err != nil {
		res = store.AuditError
		detail += "; error: " + err.Error()
	}
	s.o.Audit(ctx, store.AuditEntry{User: actorOf(ctx), Action: action, Detail: detail, Result: res})
}

// --- Info and listing ---

// Info describes a local backup file.
type Info struct {
	Name      string    // file name inside the backup directory
	Path      string    // absolute path
	Size      int64     // bytes
	CreatedAt time.Time // UTC, from the file name
	Reason    string    // nightly, manual, pre-update
	// HubVersion is the version that wrote the backup; empty when the file
	// cannot be opened with this hub's secret.key (Readable is false).
	HubVersion string
	Readable   bool

	seq int // 1, or n for "-n" file names made in the same second
}

const (
	fileExt    = ".nxbk"
	fileTime   = "20060102T150405Z"
	filePrefix = "nexus-"
)

var (
	reasonRe   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,23}$`)
	fileNameRe = regexp.MustCompile(`^nexus-(\d{8}T\d{6}Z)-([a-z][a-z0-9-]{0,23})(?:-(\d+))?\.nxbk$`)
)

func parseFileName(name string) (time.Time, string, bool) {
	t, reason, _, ok := parseFileNameSeq(name)
	return t, reason, ok
}

func parseFileNameSeq(name string) (time.Time, string, int, bool) {
	m := fileNameRe.FindStringSubmatch(name)
	if m == nil {
		return time.Time{}, "", 0, false
	}
	t, err := time.Parse(fileTime, m[1])
	if err != nil {
		return time.Time{}, "", 0, false
	}
	seq := 1
	if m[3] != "" {
		seq, _ = strconv.Atoi(m[3])
	}
	return t, m[2], seq, true
}

// List returns the local backups, newest first. A file that cannot be opened
// (made with another hub's secret.key) is listed with Readable false.
func (s *Service) List(ctx context.Context) ([]Info, error) {
	infos, err := s.listNames()
	if err != nil {
		return nil, err
	}
	key, kerr := s.localKey()
	for i := range infos {
		if kerr != nil || ctx.Err() != nil {
			continue
		}
		if m, err := s.readLocalManifest(infos[i].Path, key); err == nil {
			infos[i].HubVersion, infos[i].Readable = m.HubVersion, true
		}
	}
	return infos, ctx.Err()
}

// listNames lists the backup files by name only.
func (s *Service) listNames() ([]Info, error) {
	ents, err := os.ReadDir(s.o.Layout.BackupDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("backup: list %s: %w", s.o.Layout.BackupDir, err)
	}
	var out []Info
	for _, e := range ents {
		t, reason, seq, ok := parseFileNameSeq(e.Name())
		if !ok || !e.Type().IsRegular() {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, Info{Name: e.Name(), Path: filepath.Join(s.o.Layout.BackupDir, e.Name()),
			Size: fi.Size(), CreatedAt: t, Reason: reason, seq: seq})
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].seq > out[j].seq
	})
	return out, nil
}

func (s *Service) readLocalManifest(path string, key Key) (Manifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return Manifest{}, err
	}
	defer f.Close()
	dec, err := Decrypt(f, key)
	if err != nil {
		return Manifest{}, err
	}
	return readArchive(dec, readManifestOnly, "")
}

func (s *Service) localKey() (Key, error) {
	b, err := os.ReadFile(s.o.Layout.SecretKey)
	if err != nil {
		return Key{}, fmt.Errorf("backup: read the secret key: %w", err)
	}
	if len(b) != auth.SecretKeyLen {
		return Key{}, errors.New("backup: the secret key has the wrong size")
	}
	return LocalKey(b), nil
}

// --- Schedule settings ---

// Schedule is the nightly backup configuration.
type Schedule struct {
	Time string // "HH:MM" in the hub's time zone
	Keep int    // local backups to keep
}

var timeRe = regexp.MustCompile(`^([01]\d|2[0-3]):([0-5]\d)$`)

// ValidateSchedule checks a schedule from the Settings form.
func ValidateSchedule(sc Schedule) error {
	if !timeRe.MatchString(sc.Time) {
		return errors.New("backup: the time must be HH:MM (24 hours)")
	}
	if sc.Keep < 1 || sc.Keep > maxKeep {
		return fmt.Errorf("backup: keep between 1 and %d backups", maxKeep)
	}
	return nil
}

// Schedule returns the configured schedule; missing or invalid settings fall
// back to the defaults (03:00, keep 7).
func (s *Service) Schedule(ctx context.Context) Schedule {
	sc := Schedule{Time: DefaultTime, Keep: DefaultKeep}
	if s.o.Settings == nil {
		return sc
	}
	if v, ok, err := s.o.Settings.Get(ctx, SettingTime); err == nil && ok && timeRe.MatchString(strings.TrimSpace(v)) {
		sc.Time = strings.TrimSpace(v)
	}
	if v, ok, err := s.o.Settings.Get(ctx, SettingKeep); err == nil && ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= 1 && n <= maxKeep {
			sc.Keep = n
		}
	}
	return sc
}

// SetSchedule validates and stores the schedule.
func (s *Service) SetSchedule(ctx context.Context, sc Schedule) error {
	if err := ValidateSchedule(sc); err != nil {
		return err
	}
	if s.o.Settings == nil {
		return errors.New("backup: no settings store")
	}
	if err := s.o.Settings.Set(ctx, SettingTime, sc.Time); err != nil {
		return err
	}
	return s.o.Settings.Set(ctx, SettingKeep, strconv.Itoa(sc.Keep))
}

// --- Creating backups ---

func (s *Service) now() time.Time { return s.o.Now().UTC().Truncate(time.Second) }

// CreateLocal writes a backup encrypted with the hub's own secret.key into the
// backup directory. reason is "nightly", "manual" or "pre-update" (any
// lower-case word works). It does not prune; see Prune.
func (s *Service) CreateLocal(ctx context.Context, reason string) (info Info, err error) {
	if !reasonRe.MatchString(reason) {
		return Info{}, fmt.Errorf("backup: invalid reason %q", reason)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	defer func() {
		if err != nil {
			s.audit(ctx, ActionCreate, "reason: "+reason, err)
			return
		}
		s.audit(ctx, ActionCreate, fmt.Sprintf("reason: %s; file: %s; %d bytes", reason, info.Name, info.Size), nil)
	}()

	key, err := s.localKey()
	if err != nil {
		return Info{}, err
	}
	if err := s.ensureBackupDir(); err != nil {
		return Info{}, err
	}
	s.cleanStale()

	created := s.now()
	final, f, err := s.createBackupFile(created, reason)
	if err != nil {
		return Info{}, err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if _, err := s.write(ctx, f, key, reason, created); err != nil {
		return Info{}, err
	}
	if err := f.Sync(); err != nil {
		return Info{}, err
	}
	fi, err := f.Stat()
	if err != nil {
		return Info{}, err
	}
	if err := f.Close(); err != nil {
		return Info{}, err
	}
	if err := os.Rename(tmp, final); err != nil {
		return Info{}, err
	}
	ok = true
	syncDir(s.o.Layout.BackupDir)
	return Info{Name: filepath.Base(final), Path: final, Size: fi.Size(), CreatedAt: created,
		Reason: reason, HubVersion: s.o.HubVersion, Readable: true}, nil
}

// createBackupFile reserves the final name and opens "<name>.tmp" (0600).
func (s *Service) createBackupFile(created time.Time, reason string) (string, *os.File, error) {
	base := filePrefix + created.Format(fileTime) + "-" + reason
	for i := 0; i < 100; i++ {
		name := base + fileExt
		if i > 0 {
			name = base + "-" + strconv.Itoa(i+1) + fileExt
		}
		final := filepath.Join(s.o.Layout.BackupDir, name)
		if _, err := os.Lstat(final); err == nil {
			continue
		}
		f, err := os.OpenFile(final+".tmp", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return "", nil, err
		}
		return final, f, nil
	}
	return "", nil, errors.New("backup: cannot find a free file name")
}

// WriteDownload streams a fresh backup, encrypted with passphrase, to w. The
// passphrase must meet the operator passphrase policy (12 characters or
// more). Everything that can fail without side effects (policy check, key
// derivation, database snapshot, reading the files) happens before the first
// byte reaches w, so an HTTP handler can still answer with an error status
// when this returns an error before anything was written. Memory use does
// not depend on the size of the database.
//
// Name the download with DownloadName. Set the actor with WithActor.
func (s *Service) WriteDownload(ctx context.Context, w io.Writer, passphrase string) (err error) {
	defer func() { s.audit(ctx, ActionDownload, "passphrase-encrypted download", err) }()
	if err := ValidatePassphrase(passphrase); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureBackupDir(); err != nil {
		return err
	}
	s.cleanStale()
	_, err = s.write(ctx, w, PassphraseKey(passphrase, s.o.KDF), ReasonDownload, s.now())
	return err
}

// DownloadName is the suggested file name of a download.
func (s *Service) DownloadName() string {
	name := s.o.HubName
	if name == "" {
		name = "nexus"
	}
	return fmt.Sprintf("nexus-backup-%s-%s%s", name, s.now().Format("20060102-150405"), fileExt)
}

// write stages the files, then streams the encrypted archive to w.
func (s *Service) write(ctx context.Context, w io.Writer, key Key, reason string, created time.Time) (Manifest, error) {
	stage, err := os.MkdirTemp(s.o.Layout.BackupDir, ".staging-")
	if err != nil {
		return Manifest{}, err
	}
	defer os.RemoveAll(stage)

	m := Manifest{Format: ArchiveVersion, HubVersion: s.o.HubVersion, CreatedAt: created,
		HubName: s.o.HubName, Reason: reason}
	for _, mem := range members {
		if err := ctx.Err(); err != nil {
			return m, err
		}
		dst := filepath.Join(stage, filepath.FromSlash(mem.name))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return m, err
		}
		if mem.name == nameDatabase {
			if s.o.Snapshot == nil {
				return m, errors.New("backup: no database snapshot function")
			}
			if err := s.o.Snapshot(ctx, dst); err != nil {
				return m, err
			}
			v, err := store.CheckFile(ctx, dst)
			if err != nil {
				return m, err
			}
			m.SchemaVersion = v
		} else {
			err := copyFile(mem.path(s.o.Layout), dst)
			if errors.Is(err, fs.ErrNotExist) && !mem.required {
				continue
			}
			if err != nil {
				return m, fmt.Errorf("backup: %s: %w", mem.name, err)
			}
		}
		size, sum, err := hashFile(dst)
		if err != nil {
			return m, err
		}
		m.Files = append(m.Files, FileEntry{Name: mem.name, Size: size, SHA256: sum})
	}

	enc, err := Encrypt(ctxWriter{ctx, w}, key)
	if err != nil {
		return m, err
	}
	if err := writeArchive(enc, stage, m); err != nil {
		return m, err
	}
	return m, enc.Close()
}

// --- Retention ---

// Prune deletes all but the newest keep local backups and returns the names it
// removed. keep < 1 deletes nothing.
func (s *Service) Prune(ctx context.Context, keep int) ([]string, error) {
	if keep < 1 {
		return nil, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	infos, err := s.listNames()
	if err != nil || len(infos) <= keep {
		return nil, err
	}
	var removed []string
	for _, in := range infos[keep:] {
		if err := os.Remove(in.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return removed, err
		}
		removed = append(removed, in.Name)
	}
	return removed, nil
}

// CreateAndPrune is what the nightly job does: a local backup, then retention
// as configured in the settings.
func (s *Service) CreateAndPrune(ctx context.Context, reason string) (Info, error) {
	info, err := s.CreateLocal(ctx, reason)
	if err != nil {
		return info, err
	}
	if _, err := s.Prune(ctx, s.Schedule(ctx).Keep); err != nil {
		s.o.Logger.Warn("pruning old backups failed", "err", err)
	}
	return info, nil
}

// staleAfter is how old an abandoned staging directory or temp file must be
// before cleanStale removes it (a running operation touches its own).
const staleAfter = time.Hour

func (s *Service) cleanStale() {
	ents, err := os.ReadDir(s.o.Layout.BackupDir)
	if err != nil {
		return
	}
	for _, e := range ents {
		n := e.Name()
		if !(strings.HasPrefix(n, ".staging-") || strings.HasPrefix(n, ".restore-") || strings.HasSuffix(n, ".tmp")) {
			continue
		}
		fi, err := e.Info()
		if err != nil || s.o.Now().Sub(fi.ModTime()) < staleAfter {
			continue
		}
		_ = os.RemoveAll(filepath.Join(s.o.Layout.BackupDir, n))
	}
}

func (s *Service) ensureBackupDir() error {
	dir := s.o.Layout.BackupDir
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("backup: create %s: %w", dir, err)
	}
	if err := os.Chmod(dir, 0o700); err != nil && !isWindows() {
		return fmt.Errorf("backup: %s: %w", dir, err)
	}
	return nil
}

// --- file helpers ---

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func hashFile(path string) (int64, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return 0, "", err
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

// syncDir flushes a directory entry change to disk (best effort).
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

// ctxReader and ctxWriter make long streams stop when the request or the
// service context ends.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

type ctxWriter struct {
	ctx context.Context
	w   io.Writer
}

func (c ctxWriter) Write(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.w.Write(p)
}
