package release

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func pubPEM(t *testing.T, pub ed25519.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func sumLine(name, content string) string {
	d := sha256.Sum256([]byte(content))
	return hex.EncodeToString(d[:]) + "  " + name + "\n"
}

func TestEmbeddedKeyMatchesDeploy(t *testing.T) {
	deploy, err := os.ReadFile(filepath.Join("..", "..", "deploy", "keys", "nexara-release.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(deploy, publicKeyPEM) {
		t.Fatal("internal/release/nexara-release.pub differs from deploy/keys/nexara-release.pub")
	}
	if len(PublicKey()) != ed25519.PublicKeySize {
		t.Fatal("embedded key has wrong size")
	}
}

func TestParsePublicKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	good := pubPEM(t, pub)
	tests := []struct {
		name    string
		in      []byte
		wantErr bool
	}{
		{"ok", good, false},
		{"empty", nil, true},
		{"wrong block type", bytes.ReplaceAll(good, []byte("PUBLIC KEY"), []byte("PRIVATE KEY")), true},
		{"garbage der", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("x")}), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePublicKey(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && !got.Equal(pub) {
				t.Fatal("key mismatch")
			}
		})
	}
}

func TestVerifySumsWithKey(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	sums := []byte(sumLine("a", "1"))
	sig := ed25519.Sign(priv, sums)
	tests := []struct {
		name    string
		key     ed25519.PublicKey
		sums    []byte
		sig     []byte
		wantErr bool
	}{
		{"ok", pub, sums, sig, false},
		{"tampered sums", pub, append([]byte("x"), sums...), sig, true},
		{"wrong key", other, sums, sig, true},
		{"short sig", pub, sums, sig[:63], true},
		{"empty sig", pub, sums, nil, true},
		{"bad key", ed25519.PublicKey("short"), sums, sig, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := VerifySumsWithKey(tt.key, tt.sums, tt.sig); (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
	// The embedded production key must reject a throwaway signature.
	if err := VerifySums(sums, sig); err == nil {
		t.Fatal("embedded key accepted a foreign signature")
	}
}

func TestParseSumsAndCheckFile(t *testing.T) {
	good := sumLine("a.deb", "AAA") + sumLine("install.sh", "BBB")
	tests := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"ok", good, false},
		{"binary marker", strings.Replace(good, "  a.deb", " *a.deb", 1), false},
		{"crlf", strings.ReplaceAll(good, "\n", "\r\n"), false},
		{"empty", "", true},
		{"short digest", "abcd  x\n", true},
		{"non-hex", strings.Repeat("z", 64) + "  x\n", true},
		{"path in name", strings.Repeat("a", 64) + "  ../x\n", true},
		{"duplicate", good + sumLine("a.deb", "AAA"), true},
		{"missing separator", strings.Repeat("a", 64) + " x\n", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseSums([]byte(tt.in))
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}

	sums := []byte(good)
	checks := []struct {
		name, file, data string
		wantErr          bool
	}{
		{"match", "a.deb", "AAA", false},
		{"mismatch", "a.deb", "AAB", true},
		{"unlisted", "other", "AAA", true},
	}
	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) {
			err := CheckFile(sums, c.file, strings.NewReader(c.data))
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, c.wantErr)
			}
		})
	}
}

func TestOpenSSLInterop(t *testing.T) {
	ossl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not on PATH")
	}
	dir := t.TempDir()
	key := filepath.Join(dir, "key.pem")
	run := func(args ...string) []byte {
		out, err := exec.Command(ossl, args...).CombinedOutput()
		if err != nil {
			t.Skipf("openssl %v unsupported: %v: %s", args[:2], err, out)
		}
		return out
	}
	run("genpkey", "-algorithm", "ed25519", "-out", key)
	pub := run("pkey", "-in", key, "-pubout")
	sumsPath := filepath.Join(dir, "SHA256SUMS")
	sums := []byte(sumLine("nexus_linux_arm64", "binary"))
	if err := os.WriteFile(sumsPath, sums, 0o600); err != nil {
		t.Fatal(err)
	}
	sigPath := filepath.Join(dir, "SHA256SUMS.sig")
	run("pkeyutl", "-sign", "-rawin", "-inkey", key, "-in", sumsPath, "-out", sigPath)
	sig, err := os.ReadFile(sigPath)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := ParsePublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySumsWithKey(pk, sums, sig); err != nil {
		t.Fatalf("openssl signature rejected: %v", err)
	}
	if err := VerifySumsWithKey(pk, append(sums, '\n'), sig); err == nil {
		t.Fatal("modified sums accepted")
	}
}
