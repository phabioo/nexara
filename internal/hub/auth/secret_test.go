package auth

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadOrCreateSecretKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "secret.key")

	key, err := LoadOrCreateSecretKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != SecretKeyLen {
		t.Fatalf("key length %d", len(key))
	}
	if bytes.Equal(key, make([]byte, SecretKeyLen)) {
		t.Fatal("key is all zero")
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v, want 0600", fi.Mode().Perm())
		}
	}

	again, err := LoadOrCreateSecretKey(path)
	if err != nil || !bytes.Equal(key, again) {
		t.Fatalf("second load = %x, %v; want the same key", again, err)
	}

	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
}

func TestLoadSecretKeyRefusesWrongSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.key")
	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateSecretKey(path); err == nil {
		t.Fatal("expected an error for a key of the wrong size")
	}
	if b, _ := os.ReadFile(path); string(b) != "short" {
		t.Fatal("existing file must not be replaced")
	}
}

func TestSealOpen(t *testing.T) {
	key := bytes.Repeat([]byte{7}, SecretKeyLen)
	otherKey := bytes.Repeat([]byte{8}, SecretKeyLen)
	plain := []byte("JBSWY3DPEHPK3PXP")

	sealed, err := Seal(key, plain, AADTOTP)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, plain) {
		t.Fatal("ciphertext contains the plaintext")
	}
	got, err := Open(key, sealed, AADTOTP)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("Open = %q, %v", got, err)
	}
	sealed2, _ := Seal(key, plain, AADTOTP)
	if bytes.Equal(sealed, sealed2) {
		t.Fatal("two seals of the same data must differ (random nonce)")
	}

	t.Run("empty plaintext", func(t *testing.T) {
		s, err := Seal(key, nil, AADTOTP)
		if err != nil {
			t.Fatal(err)
		}
		if g, err := Open(key, s, AADTOTP); err != nil || len(g) != 0 {
			t.Fatalf("Open = %q, %v", g, err)
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		if _, err := Open(otherKey, sealed, AADTOTP); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("wrong aad", func(t *testing.T) {
		if _, err := Open(key, sealed, []byte("other")); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("every byte tampered", func(t *testing.T) {
		for i := range sealed {
			mod := append([]byte(nil), sealed...)
			mod[i] ^= 0x01
			if _, err := Open(key, mod, AADTOTP); err == nil {
				t.Fatalf("flipping byte %d went unnoticed", i)
			}
		}
	})
	t.Run("truncated or empty", func(t *testing.T) {
		for _, b := range [][]byte{nil, {}, {1}, sealed[:5], sealed[:len(sealed)-1]} {
			if _, err := Open(key, b, AADTOTP); err == nil {
				t.Fatalf("Open(%x) succeeded", b)
			}
		}
	})
	t.Run("bad key size", func(t *testing.T) {
		if _, err := Seal(key[:16], plain, nil); err == nil {
			t.Fatal("Seal accepted a 16-byte key")
		}
		if _, err := Open(key[:16], sealed, nil); err == nil {
			t.Fatal("Open accepted a 16-byte key")
		}
	})
}
