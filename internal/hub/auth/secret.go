package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
)

// SecretKeyLen is the size of secret.key (AES-256).
const SecretKeyLen = 32

// HKDF "info" labels: one subkey per purpose, so a flaw in one use of
// secret.key cannot be turned against another (security review S-19).
const (
	hkdfInfoCSRF = "nexus/v1 csrf-token-hmac"
	hkdfInfoSeal = "nexus/v1 sealed-secrets-aes-gcm"
)

// deriveKey expands the master key from secret.key into a 32-byte subkey for
// one purpose (HKDF-SHA-256, no salt: the master key is already uniformly random).
func deriveKey(master []byte, info string) ([]byte, error) {
	if len(master) != SecretKeyLen {
		return nil, errors.New("auth: secret key must be 32 bytes")
	}
	return hkdf.Key(sha256.New, master, nil, info, SecretKeyLen)
}

// TOTPAAD is the associated data of a sealed TOTP secret: its purpose and
// the owning user's ID. A blob copied from one user's row into another's, or
// into a different kind of column, no longer opens.
//
// v0.1 is not deployed anywhere, so there are no blobs sealed with the old
// shared key and constant AAD to migrate; nothing reads them any more.
func TOTPAAD(userID int64) []byte {
	return []byte("nexus:totp-secret:v2:user=" + strconv.FormatInt(userID, 10))
}

const sealVersion = 1

// LoadOrCreateSecretKey returns the 32-byte key stored at path. If the file
// does not exist it is created with mode 0600 and fresh random bytes. The
// content is written to a temporary file first and hard-linked into place,
// so the path either does not exist or holds a complete key, and two
// processes racing on first start end up with the same key.
func LoadOrCreateSecretKey(path string) ([]byte, error) {
	if key, err := readSecretKey(path); err == nil {
		return key, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("auth: create key directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".secret.key.*")
	if err != nil {
		return nil, fmt.Errorf("auth: create temporary key file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	key := make([]byte, SecretKeyLen)
	if _, err := rand.Read(key); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("auth: generate secret key: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		_ = tmp.Close()
		return nil, fmt.Errorf("auth: set key file mode: %w", err)
	}
	if _, err := tmp.Write(key); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("auth: write secret key: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("auth: sync secret key: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("auth: close secret key: %w", err)
	}
	if err := os.Link(tmpName, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return readSecretKey(path) // lost the race; use the winner's key
		}
		return nil, fmt.Errorf("auth: install secret key: %w", err)
	}
	return key, nil
}

func readSecretKey(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		return nil, fmt.Errorf("auth: read secret key: %w", err)
	}
	if len(b) != SecretKeyLen {
		return nil, fmt.Errorf("auth: %s has %d bytes, want %d; refusing to replace it", path, len(b), SecretKeyLen)
	}
	return b, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != SecretKeyLen {
		return nil, errors.New("auth: secret key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Seal encrypts plaintext with AES-256-GCM. The output is
// version(1) || nonce(12) || ciphertext+tag. aad is authenticated but not
// stored; pass the same value to Open.
func Seal(key, plaintext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 1, 1+gcm.NonceSize()+len(plaintext)+gcm.Overhead())
	out[0] = sealVersion
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("auth: read random nonce: %w", err)
	}
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, plaintext, aad), nil
}

// Open decrypts the output of Seal. Any modification of the blob, a wrong
// key or a wrong aad yields an error.
func Open(key, sealed, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	n := gcm.NonceSize()
	if len(sealed) < 1+n+gcm.Overhead() || sealed[0] != sealVersion {
		return nil, errors.New("auth: sealed data malformed")
	}
	pt, err := gcm.Open(nil, sealed[1:1+n], sealed[1+n:], aad)
	if err != nil {
		return nil, errors.New("auth: sealed data rejected (wrong key or tampered)")
	}
	return pt, nil
}
