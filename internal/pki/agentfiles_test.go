package pki

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

type pairPEM struct{ cert, key []byte }

func issuePair(t *testing.T, ca *CA, hostID string, now time.Time) pairPEM {
	t.Helper()
	key, csr, err := NewAgentKeyAndCSR(hostID)
	if err != nil {
		t.Fatal(err)
	}
	cert, _, err := SignAgentCSR(ca, csr, hostID, now)
	if err != nil {
		t.Fatal(err)
	}
	return pairPEM{cert: cert, key: key}
}

func writePair(t *testing.T, certFile, keyFile string, p pairPEM) {
	t.Helper()
	if err := os.WriteFile(certFile, p.cert, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, p.key, 0o600); err != nil {
		t.Fatal(err)
	}
}

func fpOf(t *testing.T, certFile string) string {
	t.Helper()
	b, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	fp, err := FingerprintFromPEM(b)
	if err != nil {
		t.Fatal(err)
	}
	return fp
}

func TestAgentFilesLifecycle(t *testing.T) {
	ca, _ := newCA(t)
	now := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	f := AgentFiles{Cert: filepath.Join(dir, "agent.pem"), Key: filepath.Join(dir, "agent.key")}
	oldP, newP := issuePair(t, ca, "h1", now), issuePair(t, ca, "h1", now)
	writePair(t, f.Cert, f.Key, oldP)
	oldFP := fpOf(t, f.Cert)

	if f.HasStaged() {
		t.Fatal("staged pair before Stage")
	}
	// A pair that does not match is refused and nothing is written.
	if err := f.Stage(newP.cert, oldP.key); err == nil {
		t.Fatal("Stage accepted a certificate that does not match the key")
	}
	if f.HasStaged() {
		t.Fatal("a refused Stage left files behind")
	}

	if err := f.Stage(newP.cert, newP.key); err != nil {
		t.Fatal(err)
	}
	if got := fpOf(t, f.Cert); got != oldFP {
		t.Fatal("Stage touched the active certificate")
	}
	if runtime.GOOS != "windows" {
		for _, p := range []string{f.Cert + StagedSuffix, f.Key + StagedSuffix} {
			if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o600 {
				t.Errorf("%s: %v %v, want mode 0600", p, fi, err)
			}
		}
	}
	if _, ok := f.StagedModTime(); !ok {
		t.Error("StagedModTime: no staged file")
	}
	staged, err := f.LoadStaged()
	if err != nil {
		t.Fatal(err)
	}

	if err := f.Promote(); err != nil {
		t.Fatal(err)
	}
	if f.HasStaged() {
		t.Error("staged files remain after Promote")
	}
	active, err := f.LoadActive()
	if err != nil || string(active.Certificate[0]) != string(staged.Certificate[0]) {
		t.Fatalf("active pair after Promote: %v", err)
	}
	if got := fpOf(t, f.Cert+PrevSuffix); got != oldFP {
		t.Error("the previous certificate was not kept as .prev")
	}
	if _, err := loadPair(f.Cert+PrevSuffix, f.Key+PrevSuffix); err != nil {
		t.Errorf("previous pair is not usable: %v", err)
	}

	// Discard removes a staged pair, also a broken one, and tolerates none.
	if err := f.Stage(oldP.cert, oldP.key); err != nil {
		t.Fatal(err)
	}
	if err := f.Discard(); err != nil || f.HasStaged() {
		t.Fatalf("Discard: %v, staged left: %v", err, f.HasStaged())
	}
	if err := f.Discard(); err != nil {
		t.Errorf("second Discard: %v", err)
	}
	if err := f.Promote(); err == nil {
		t.Error("Promote without a staged pair succeeded")
	}
}

func TestAgentFilesRecover(t *testing.T) {
	ca, _ := newCA(t)
	now := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	oldP, newP := issuePair(t, ca, "h1", now), issuePair(t, ca, "h1", now)

	tests := []struct {
		name    string
		setup   func(t *testing.T, f AgentFiles)
		want    string // fingerprint source of the active cert afterwards
		action  bool
		wantErr bool
	}{
		{name: "healthy pair", setup: func(t *testing.T, f AgentFiles) { writePair(t, f.Cert, f.Key, oldP) }, want: "old"},
		{name: "not enrolled", setup: func(t *testing.T, f AgentFiles) {}, want: ""},
		{
			name: "crash between the two renames of Promote",
			setup: func(t *testing.T, f AgentFiles) {
				// new key already active, old certificate still there, staged certificate waiting
				writePair(t, f.Cert, f.Key, pairPEM{cert: oldP.cert, key: newP.key})
				if err := os.WriteFile(f.Cert+StagedSuffix, newP.cert, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(f.Cert+PrevSuffix, oldP.cert, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(f.Key+PrevSuffix, oldP.key, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			want: "new", action: true,
		},
		{
			name: "mismatch without a staged certificate falls back to .prev",
			setup: func(t *testing.T, f AgentFiles) {
				writePair(t, f.Cert, f.Key, pairPEM{cert: oldP.cert, key: newP.key})
				if err := os.WriteFile(f.Cert+PrevSuffix, oldP.cert, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(f.Key+PrevSuffix, oldP.key, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			want: "old", action: true,
		},
		{
			name:    "mismatch and nothing to recover from",
			setup:   func(t *testing.T, f AgentFiles) { writePair(t, f.Cert, f.Key, pairPEM{cert: oldP.cert, key: newP.key}) },
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			f := AgentFiles{Cert: filepath.Join(dir, "agent.pem"), Key: filepath.Join(dir, "agent.key")}
			tc.setup(t, f)
			msg, err := f.Recover()
			if tc.wantErr {
				if err == nil {
					t.Fatal("Recover succeeded, want an error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if (msg != "") != tc.action {
				t.Errorf("Recover message = %q, want action %v", msg, tc.action)
			}
			if tc.want == "" {
				return
			}
			if _, err := f.LoadActive(); err != nil {
				t.Fatalf("active pair unusable after Recover: %v", err)
			}
			wantCert := oldP.cert
			if tc.want == "new" {
				wantCert = newP.cert
			}
			wantFP, _ := FingerprintFromPEM(wantCert)
			if got := fpOf(t, f.Cert); got != wantFP {
				t.Errorf("active certificate = %s, want the %s one", got, tc.want)
			}
		})
	}
}

func TestAgentTLSConfigRecovers(t *testing.T) {
	ca, _ := newCA(t)
	now := time.Now()
	oldP, newP := issuePair(t, ca, "h1", now), issuePair(t, ca, "h1", now)
	dir := t.TempDir()
	f := AgentFiles{Cert: filepath.Join(dir, "agent.pem"), Key: filepath.Join(dir, "agent.key")}
	writePair(t, f.Cert, f.Key, pairPEM{cert: oldP.cert, key: newP.key})
	if err := os.WriteFile(f.Cert+StagedSuffix, newP.cert, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := AgentTLSConfig(ca.CertPEM(), f.Cert, f.Key); err != nil {
		t.Fatalf("AgentTLSConfig on a crashed promotion: %v", err)
	}
}
