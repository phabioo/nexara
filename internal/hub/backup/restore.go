package backup

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"

	"github.com/phabioo/nexara/internal/config"
	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/pki"
)

// Errors of the restore.
var (
	// ErrTooNew means the backup comes from a newer Nexus than this one.
	ErrTooNew = errors.New("backup: this backup was made by a newer Nexus; update Nexus first, then restore")
	// ErrPassphraseRequired means the file is a passphrase backup and none was given.
	ErrPassphraseRequired = errors.New("backup: this backup needs its passphrase")
	// ErrStoreClosed is added to a restore error when the swap failed after the
	// hub had closed its database: the files are back as they were, but this
	// process can no longer use them and must be restarted.
	ErrStoreClosed = errors.New("the hub closed its database for the restore; restart Nexus (sudo systemctl restart nexus)")
)

const (
	restoreNewSuffix = ".restore-new"
	// BeforeRestoreSuffix is appended to every file a restore replaced.
	BeforeRestoreSuffix = ".before-restore"
)

// RestoreResult describes a finished restore.
type RestoreResult struct {
	Manifest Manifest
	// Replaced lists the files that were moved aside as <file>.before-restore.
	Replaced []string
	// ConfigAdjusted is true when the restored nexus.yaml pointed the database
	// or the TLS directory elsewhere and was changed to this hub's paths.
	ConfigAdjusted bool
	// RestartRequired is always true: a running hub still holds the old
	// database; it must exit and start again before it serves anything else.
	RestartRequired bool
}

// Inspect decrypts and fully verifies a passphrase backup (every chunk, every
// checksum) without keeping anything, and returns its manifest. The setup
// wizard calls it to preview an uploaded file.
func (s *Service) Inspect(ctx context.Context, r io.Reader, passphrase string) (Manifest, error) {
	dec, err := Decrypt(r, PassphraseKey(passphrase, s.o.KDF))
	if err != nil {
		return Manifest{}, err
	}
	return readArchive(dec, readVerify, "")
}

// InspectFile is Inspect for a file on disk; local backups of this hub
// (recognized by their header) need no passphrase.
func (s *Service) InspectFile(ctx context.Context, path, passphrase string) (Manifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return Manifest{}, err
	}
	defer f.Close()
	return s.InspectFrom(ctx, f, passphrase)
}

// InspectFrom is InspectFile for an already opened file.
func (s *Service) InspectFrom(ctx context.Context, f io.ReadSeeker, passphrase string) (Manifest, error) {
	key, err := s.keyFor(f, passphrase)
	if err != nil {
		return Manifest{}, err
	}
	dec, err := Decrypt(ctxReader{ctx, f}, key)
	if err != nil {
		return Manifest{}, err
	}
	return readArchive(dec, readVerify, "")
}

// keyFor picks the key by the file's header and rewinds f.
func (s *Service) keyFor(f io.ReadSeeker, passphrase string) (Key, error) {
	kind, err := KindOf(f)
	if err == nil {
		_, err = f.Seek(0, io.SeekStart)
	}
	if err != nil {
		return Key{}, err
	}
	if kind == "local" {
		return s.localKey()
	}
	if passphrase == "" {
		return Key{}, ErrPassphraseRequired
	}
	return PassphraseKey(passphrase, s.o.KDF), nil
}

// RestoreFile restores from a file on disk. A local backup of this hub is
// opened with its secret.key; a downloaded backup needs the passphrase.
func (s *Service) RestoreFile(ctx context.Context, path, passphrase string) (*RestoreResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, s.restoreFailed(ctx, err)
	}
	defer f.Close()
	return s.RestoreFrom(ctx, f, passphrase)
}

// RestoreFrom is RestoreFile for an already opened file (the command line
// opens it before it gives up root).
func (s *Service) RestoreFrom(ctx context.Context, f io.ReadSeeker, passphrase string) (*RestoreResult, error) {
	key, err := s.keyFor(f, passphrase)
	if err != nil {
		return nil, s.restoreFailed(ctx, err)
	}
	return s.restore(ctx, f, key)
}

// RestoreLocal restores the local backup with the given file name (as List
// returns it).
func (s *Service) RestoreLocal(ctx context.Context, name string) (*RestoreResult, error) {
	if _, _, ok := parseFileName(name); !ok {
		return nil, s.restoreFailed(ctx, fmt.Errorf("backup: %q is not a local backup name", sanitize(name)))
	}
	return s.RestoreFile(ctx, filepath.Join(s.o.Layout.BackupDir, name), "")
}

// Restore restores from an uploaded passphrase backup.
//
// Order: (1) decrypt and verify everything into a staging directory (all
// chunks, all checksums); (2) check compatibility and vet the content (schema
// not newer than this binary, database passes SQLite's integrity check,
// config parses, CA certificate and key match, secret.key has the right
// size); (3) copy each file next to its destination; (4) swap them in with
// renames, moving the old files aside as <file>.before-restore. A failure in
// 1 to 3 changes nothing; a failure in 4 is rolled back. Only one step back
// is kept: an older .before-restore is overwritten.
//
// The stopped service is the safe case (`nexus backup restore`). A running
// hub, as in the setup wizard, still has the old database open: it must exit
// right after Restore returns so that the service manager starts it on the
// restored files (RestoreResult.RestartRequired).
func (s *Service) Restore(ctx context.Context, r io.Reader, passphrase string) (*RestoreResult, error) {
	return s.restore(ctx, r, PassphraseKey(passphrase, s.o.KDF))
}

// restoreFailed audits a failed restore and returns err. A restore that
// changed nothing is still an attempt somebody should be able to see.
func (s *Service) restoreFailed(ctx context.Context, err error) error {
	s.audit(context.WithoutCancel(ctx), ActionRestore, "restore failed", err)
	return err
}

func (s *Service) restore(ctx context.Context, r io.Reader, key Key) (res *RestoreResult, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer func() {
		if err != nil {
			s.restoreFailed(ctx, err)
		}
	}()
	lay := s.o.Layout
	if err := s.ensureBackupDir(); err != nil {
		return nil, err
	}
	s.cleanStale()

	stage, err := os.MkdirTemp(lay.BackupDir, ".restore-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(stage)

	dec, err := Decrypt(ctxReader{ctx, r}, key)
	if err != nil {
		return nil, err
	}
	m, err := readArchive(dec, readExtract, stage)
	if err != nil {
		return nil, err
	}
	adjusted, err := s.vet(ctx, stage, m)
	if err != nil {
		return nil, err
	}

	plan := s.plan(stage, m)
	if err := s.prepare(plan); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		s.discard(plan)
		return nil, err
	}
	closed := false
	if s.o.BeforeSwap != nil {
		if err := s.o.BeforeSwap(); err != nil {
			s.discard(plan)
			return nil, fmt.Errorf("backup: cannot close the database before the restore: %w", err)
		}
		closed = true
	}
	replaced, err := s.swap(plan)
	if err != nil {
		if closed {
			err = fmt.Errorf("%w; %w", err, ErrStoreClosed)
		}
		return nil, err
	}
	res = &RestoreResult{Manifest: m, Replaced: replaced, ConfigAdjusted: adjusted, RestartRequired: true}
	s.finish(ctx, m)
	return res, nil
}

// vet checks the extracted files. It may rewrite the staged nexus.yaml.
func (s *Service) vet(ctx context.Context, stage string, m Manifest) (adjusted bool, err error) {
	if m.SchemaVersion < 1 {
		return false, errors.New("backup: the manifest has no database schema version")
	}
	if latest := s.o.LatestSchema(); m.SchemaVersion > latest {
		return false, fmt.Errorf("%w (backup schema %d, this Nexus supports up to %d)", ErrTooNew, m.SchemaVersion, latest)
	}
	at := func(name string) string { return filepath.Join(stage, filepath.FromSlash(name)) }

	v, err := store.CheckFile(ctx, at(nameDatabase))
	if err != nil {
		return false, fmt.Errorf("backup: the database in the backup is not usable: %w", err)
	}
	if v != m.SchemaVersion {
		return false, fmt.Errorf("backup: the database has schema %d but the manifest says %d", v, m.SchemaVersion)
	}

	cfgPath := at(nameConfig)
	cfg, err := config.LoadHub(cfgPath)
	if err != nil {
		return false, fmt.Errorf("backup: the configuration in the backup is not usable with this Nexus: %w", err)
	}
	lay := s.o.Layout
	if cfg.Storage.Database != lay.Database || cfg.TLS.Dir != lay.TLSDir {
		// A restore must leave a hub that finds its files, whatever the
		// layout of the device the backup came from.
		cfg.Storage.Database, cfg.TLS.Dir = lay.Database, lay.TLSDir
		if err := config.SaveHub(cfgPath, cfg); err != nil {
			return false, err
		}
		adjusted = true
	}

	if sk, err := os.ReadFile(at(nameSecretKey)); err != nil || len(sk) != 32 {
		return false, errors.New("backup: secret.key in the backup has the wrong size")
	}
	if _, err := pki.LoadOrCreateCA(filepath.Dir(at(nameCACert))); err != nil {
		return false, fmt.Errorf("backup: the CA in the backup is not usable: %w", err)
	}
	if _, err := os.Stat(at(nameServerPEM)); err == nil {
		if _, err := tls.LoadX509KeyPair(at(nameServerPEM), at(nameServerKey)); err != nil {
			return false, fmt.Errorf("backup: the server certificate in the backup is not usable: %w", err)
		}
	}
	if b, err := os.ReadFile(at(nameSSHKey)); err == nil {
		if _, err := ssh.ParsePrivateKey(b); err != nil {
			return false, errors.New("backup: the SSH key in the backup is not usable")
		}
	}
	return adjusted, nil
}

// step is one file of the swap.
type step struct {
	dest    string
	src     string // staged file; empty means "move the existing file aside and install nothing"
	mode    os.FileMode
	newPath string // dest + restoreNewSuffix once prepared
	bak     string

	dirMode os.FileMode

	prepared  bool
	movedOld  bool
	installed bool
}

func (s *Service) plan(stage string, m Manifest) []*step {
	lay := s.o.Layout
	in := map[string]bool{}
	for _, f := range m.Files {
		in[f.Name] = true
	}
	var steps []*step
	add := func(dest, src string, mode os.FileMode, dirMode os.FileMode) {
		steps = append(steps, &step{dest: dest, src: src, mode: mode, dirMode: dirMode,
			newPath: dest + restoreNewSuffix, bak: dest + BeforeRestoreSuffix})
	}
	for _, mem := range members {
		dest := mem.path(lay)
		src := ""
		if in[mem.name] {
			src = filepath.Join(stage, filepath.FromSlash(mem.name))
		}
		if mem.name == nameDatabase {
			// Stale journal files must never meet the restored database.
			add(dest+"-wal", "", 0, 0)
			add(dest+"-shm", "", 0, 0)
		}
		dirMode := os.FileMode(0o750)
		if mem.name == nameSSHKey {
			dirMode = 0o700
		}
		add(dest, src, mem.mode, dirMode)
	}
	return steps
}

// prepare copies every staged file next to its destination. On error it
// removes what it created.
func (s *Service) prepare(plan []*step) error {
	for _, st := range plan {
		if st.src == "" {
			continue
		}
		if err := s.ensureParent(st.dest, st.dirMode); err != nil {
			s.discard(plan)
			return err
		}
		if err := s.copyInto(st); err != nil {
			s.discard(plan)
			return fmt.Errorf("backup: cannot prepare %s: %w", st.dest, err)
		}
		st.prepared = true
	}
	return nil
}

func (s *Service) copyInto(st *step) error {
	_ = os.Remove(st.newPath)
	in, err := os.Open(st.src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(st.newPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	if err := os.Chmod(st.newPath, st.mode); err != nil && !isWindows() {
		return err
	}
	return nil
}

func (s *Service) ensureParent(path string, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if _, err := os.Stat(dir); err == nil {
		return nil
	}
	return os.MkdirAll(dir, mode)
}

func (s *Service) discard(plan []*step) {
	for _, st := range plan {
		if st.prepared {
			_ = os.Remove(st.newPath)
			st.prepared = false
		}
	}
}

// swap moves the old files aside and the new ones in. On a failure it undoes
// every step already taken, newest first.
func (s *Service) swap(plan []*step) (replaced []string, err error) {
	var touched []*step
	for _, st := range plan {
		touched = append(touched, st)
		if _, serr := os.Lstat(st.dest); serr == nil {
			if err = s.rename(st.dest, st.bak); err != nil {
				err = fmt.Errorf("backup: cannot move %s aside: %w", st.dest, err)
				break
			}
			st.movedOld = true
		} else if !errors.Is(serr, fs.ErrNotExist) {
			err = serr
			break
		}
		if st.src != "" {
			if err = s.rename(st.newPath, st.dest); err != nil {
				err = fmt.Errorf("backup: cannot install %s: %w", st.dest, err)
				break
			}
			st.installed = true
		}
	}
	if err == nil {
		for _, st := range plan {
			if st.movedOld {
				replaced = append(replaced, st.bak)
			}
			if st.installed {
				syncDir(filepath.Dir(st.dest))
			}
		}
		return replaced, nil
	}

	var rbErrs []error
	for i := len(touched) - 1; i >= 0; i-- {
		st := touched[i]
		if st.installed {
			if rerr := s.rename(st.dest, st.newPath); rerr != nil {
				if rerr = os.Remove(st.dest); rerr != nil {
					rbErrs = append(rbErrs, rerr)
				}
			}
		}
		if st.movedOld {
			if rerr := s.rename(st.bak, st.dest); rerr != nil {
				rbErrs = append(rbErrs, rerr)
			}
		}
	}
	for _, st := range plan {
		_ = os.Remove(st.newPath)
	}
	if len(rbErrs) > 0 {
		return nil, fmt.Errorf("%w; ROLLBACK INCOMPLETE (%v): the previous files are kept as *%s", err, errors.Join(rbErrs...), BeforeRestoreSuffix)
	}
	return nil, err
}

// finish writes the audit entries into the restored database: first what the
// caller carried over (the setup wizard's earlier attempts), then the
// restore itself.
func (s *Service) finish(ctx context.Context, m Manifest) {
	if s.o.AuditRestore == nil {
		return
	}
	write := func(e store.AuditEntry) {
		if err := s.o.AuditRestore(ctx, s.o.Layout.Database, e); err != nil {
			s.o.Logger.Warn("writing a restore audit entry failed", "action", e.Action, "err", err)
		}
	}
	for _, e := range carriedOf(ctx) {
		e.ID = 0
		write(e)
	}
	detail := fmt.Sprintf("restored backup of %s (hub %s, created %s, reason %s)",
		m.HubName, m.HubVersion, m.CreatedAt.UTC().Format("2006-01-02 15:04:05 UTC"), m.Reason)
	if ip := remoteOf(ctx); ip != "" {
		detail += "; ip=" + ip
	}
	write(store.AuditEntry{User: actorOf(ctx), Action: ActionRestore, Result: store.AuditOK, Detail: detail})
}
