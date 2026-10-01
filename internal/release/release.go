// Package release verifies signed release metadata (decisions #36 and #43).
//
// A release carries SHA256SUMS (the format of `sha256sum`) and
// SHA256SUMS.sig, a raw 64-byte ed25519 signature over SHA256SUMS. The
// self-update (v0.2) verifies the signature with the embedded public key and
// then checks each downloaded file against the sums.
package release

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"
)

// publicKeyPEM is a copy of deploy/keys/nexara-release.pub (go:embed cannot
// reach parent directories); a test keeps both identical.
//
//go:embed nexara-release.pub
var publicKeyPEM []byte

// PublicKey returns the embedded release signing key.
func PublicKey() ed25519.PublicKey {
	key, err := ParsePublicKey(publicKeyPEM)
	if err != nil {
		panic("release: embedded public key is invalid: " + err.Error())
	}
	return key
}

// ParsePublicKey decodes a PEM "PUBLIC KEY" block holding an ed25519 key.
func ParsePublicKey(pemData []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("release: no PUBLIC KEY PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("release: parse public key: %w", err)
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("release: public key is %T, want ed25519", parsed)
	}
	return key, nil
}

// VerifySums checks sig over sums with the embedded public key.
func VerifySums(sums, sig []byte) error {
	return VerifySumsWithKey(PublicKey(), sums, sig)
}

// VerifySumsWithKey checks sig over sums with key.
func VerifySumsWithKey(key ed25519.PublicKey, sums, sig []byte) error {
	if len(key) != ed25519.PublicKeySize {
		return errors.New("release: invalid public key")
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("release: signature is %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}
	if !ed25519.Verify(key, sums, sig) {
		return errors.New("release: signature does not match SHA256SUMS")
	}
	return nil
}

// ParseSums parses sha256sum output into file name -> lower-case hex digest.
// Both text ("  ") and binary (" *") separators are accepted.
func ParseSums(sums []byte) (map[string]string, error) {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(sums))
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(text) == "" {
			continue
		}
		if len(text) < sha256.Size*2+3 || (text[64:66] != "  " && text[64:66] != " *") {
			return nil, fmt.Errorf("release: SHA256SUMS line %d: malformed", line)
		}
		digest := strings.ToLower(text[:64])
		if _, err := hex.DecodeString(digest); err != nil {
			return nil, fmt.Errorf("release: SHA256SUMS line %d: bad digest", line)
		}
		name := text[66:]
		if name == "" || strings.ContainsAny(name, "/\\") {
			return nil, fmt.Errorf("release: SHA256SUMS line %d: bad file name", line)
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("release: SHA256SUMS line %d: duplicate entry %q", line, name)
		}
		out[name] = digest
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errors.New("release: SHA256SUMS is empty")
	}
	return out, nil
}

// CheckFile parses the verified SHA256SUMS content, reads data and compares
// its SHA-256 with the entry for name.
func CheckFile(sums []byte, name string, data io.Reader) error {
	entries, err := ParseSums(sums)
	if err != nil {
		return err
	}
	want, ok := entries[name]
	if !ok {
		return fmt.Errorf("release: %q is not listed in SHA256SUMS", name)
	}
	h := sha256.New()
	if _, err := io.Copy(h, data); err != nil {
		return fmt.Errorf("release: read %q: %w", name, err)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return fmt.Errorf("release: checksum mismatch for %q", name)
	}
	return nil
}
