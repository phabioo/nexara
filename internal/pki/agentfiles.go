package pki

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"
)

// Suffixes of the files next to an agent's certificate and key while a
// renewal (decision #47) is under way.
const (
	StagedSuffix = ".new"  // the renewed pair, tried before it replaces the active one
	PrevSuffix   = ".prev" // the previous pair, kept after a renewal for recovery
)

// AgentFiles are the agent's certificate and key files (agent.yaml tls.cert,
// tls.key). The active pair is never modified until a renewed pair has
// connected once, so an interrupted renewal always leaves an agent that can
// still connect with the old certificate:
//
//  1. Stage writes <cert>.new / <key>.new (key first, each temp file + rename,
//     mode 0600). The active pair is untouched.
//  2. The agent connects with the staged pair. Once the hub has accepted it,
//     Promote copies the active pair to <cert>.prev / <key>.prev and renames
//     the staged files over the active ones.
//  3. If the staged pair never works, Discard removes it.
//
// Promote is two renames and therefore not atomic as a pair; Recover repairs
// the state a crash between them leaves behind and runs when the TLS
// configuration is built (AgentTLSConfig), before the agent connects.
type AgentFiles struct{ Cert, Key string }

func (f AgentFiles) stagedCert() string { return f.Cert + StagedSuffix }
func (f AgentFiles) stagedKey() string  { return f.Key + StagedSuffix }
func (f AgentFiles) prevCert() string   { return f.Cert + PrevSuffix }
func (f AgentFiles) prevKey() string    { return f.Key + PrevSuffix }

// Stage writes the renewed certificate and key as the staged pair, replacing
// an older staged pair. The pair must match; nothing is written otherwise.
func (f AgentFiles) Stage(certPEM, keyPEM []byte) error {
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return errors.New("pki: renewed certificate does not match the new key")
	}
	if err := writeFileAtomic(f.stagedKey(), keyPEM, 0o600); err != nil {
		return err
	}
	return writeFileAtomic(f.stagedCert(), certPEM, 0o600)
}

// LoadActive loads the active pair.
func (f AgentFiles) LoadActive() (*tls.Certificate, error) { return loadPair(f.Cert, f.Key) }

// LoadStaged loads the staged pair; it fails if there is none or the files
// do not match.
func (f AgentFiles) LoadStaged() (*tls.Certificate, error) {
	return loadPair(f.stagedCert(), f.stagedKey())
}

func loadPair(certFile, keyFile string) (*tls.Certificate, error) {
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("pki: load agent certificate: %w", err)
	}
	return &pair, nil
}

// StagedModTime is the time the staged certificate was written; ok is false
// if there is no staged certificate file.
func (f AgentFiles) StagedModTime() (t time.Time, ok bool) {
	fi, err := os.Stat(f.stagedCert())
	if err != nil {
		return time.Time{}, false
	}
	return fi.ModTime(), true
}

// HasStaged reports whether a staged certificate or key file exists (even a
// broken one, so the caller can discard it).
func (f AgentFiles) HasStaged() bool {
	for _, p := range []string{f.stagedCert(), f.stagedKey()} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// Discard removes the staged pair. Missing files are not an error.
func (f AgentFiles) Discard() error {
	var first error
	for _, p := range []string{f.stagedCert(), f.stagedKey()} {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) && first == nil {
			first = fmt.Errorf("pki: remove %s: %w", p, err)
		}
	}
	return first
}

// Promote makes the staged pair the active one and keeps the previous pair as
// <cert>.prev / <key>.prev. The staged pair must load before anything is
// touched.
func (f AgentFiles) Promote() error {
	if _, err := f.LoadStaged(); err != nil {
		return err
	}
	for _, p := range [][2]string{{f.Key, f.prevKey()}, {f.Cert, f.prevCert()}} {
		data, err := os.ReadFile(p[0])
		if err != nil {
			return fmt.Errorf("pki: keep previous pair: %w", err)
		}
		if err := writeFileAtomic(p[1], data, 0o600); err != nil {
			return err
		}
	}
	// Key first: a crash in between leaves the new key with the old
	// certificate, which Recover completes from the staged certificate.
	if err := os.Rename(f.stagedKey(), f.Key); err != nil {
		return fmt.Errorf("pki: activate renewed key: %w", err)
	}
	if err := os.Rename(f.stagedCert(), f.Cert); err != nil {
		return fmt.Errorf("pki: activate renewed certificate: %w", err)
	}
	return nil
}

// Recover makes the active pair usable again after a crash during Promote. It
// does nothing when the active pair loads. Otherwise it completes the
// promotion when the staged certificate belongs to the active key, and falls
// back to the previous pair when that does not help. It reports what it did
// ("" = nothing to repair).
func (f AgentFiles) Recover() (string, error) {
	if _, err := f.LoadActive(); err == nil {
		return "", nil
	}
	if _, err := os.Stat(f.Cert); errors.Is(err, fs.ErrNotExist) {
		return "", nil // not enrolled; the caller reports the missing files
	}
	if _, err := loadPair(f.stagedCert(), f.Key); err == nil {
		if err := os.Rename(f.stagedCert(), f.Cert); err != nil {
			return "", fmt.Errorf("pki: complete interrupted certificate renewal: %w", err)
		}
		_ = os.Remove(f.stagedKey())
		return "completed an interrupted certificate renewal", nil
	}
	if _, err := loadPair(f.prevCert(), f.prevKey()); err == nil {
		for _, p := range [][2]string{{f.prevKey(), f.Key}, {f.prevCert(), f.Cert}} {
			data, err := os.ReadFile(p[0])
			if err != nil {
				return "", fmt.Errorf("pki: restore previous certificate: %w", err)
			}
			if err := writeFileAtomic(p[1], data, 0o600); err != nil {
				return "", err
			}
		}
		return "restored the previous certificate after an interrupted renewal", nil
	}
	return "", errors.New("pki: agent certificate and key do not match and no usable backup exists; re-enroll the agent")
}
