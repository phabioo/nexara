package auth

import (
	"bytes"
	"errors"
	"testing"
)

// S-19 (a): independent subkeys per purpose.
func TestSubkeysAreDerivedAndIndependent(t *testing.T) {
	e := newEnv(t)
	if bytes.Equal(e.svc.csrfKey, e.svc.sealKey) {
		t.Fatal("CSRF and sealing keys must differ")
	}
	for name, k := range map[string][]byte{"csrf": e.svc.csrfKey, "seal": e.svc.sealKey} {
		if len(k) != SecretKeyLen || bytes.Equal(k, e.key) {
			t.Fatalf("%s subkey must be %d bytes and not the master key", name, SecretKeyLen)
		}
	}
	// The master key itself opens nothing sealed by the service, and vice versa.
	sealed, err := e.svc.SealTOTPSecret(1, "JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(e.key, sealed, TOTPAAD(1)); err == nil {
		t.Fatal("the master key must not open a blob sealed with the subkey")
	}
	// A CSRF token computed with the master key is not accepted.
	u := e.addUser("alice", testPass)
	_, sess, _ := e.svc.Sessions().Create(e.ctx, u, false, testIP, testUA)
	if e.svc.CheckCSRF(sess, csrfToken(e.key, sess.IDHash)) {
		t.Fatal("token derived from the raw master key must not validate")
	}
	if !e.svc.CheckCSRF(sess, e.svc.CSRFToken(sess)) {
		t.Fatal("own token must validate")
	}
	// The derivation is deterministic (a restart keeps sessions' tokens and sealed blobs valid) ...
	again, err := deriveKey(e.key, hkdfInfoCSRF)
	if err != nil || !bytes.Equal(again, e.svc.csrfKey) {
		t.Fatalf("derivation not deterministic: %v", err)
	}
	// ... and depends on the master key.
	other := bytes.Repeat([]byte{9}, SecretKeyLen)
	if k, _ := deriveKey(other, hkdfInfoCSRF); bytes.Equal(k, e.svc.csrfKey) {
		t.Fatal("different master keys must give different subkeys")
	}
	if _, err := deriveKey(other[:5], hkdfInfoCSRF); err == nil {
		t.Fatal("short master key must be rejected")
	}
}

// S-19 (c): a sealed TOTP blob belongs to one user.
func TestTOTPSecretIsBoundToUser(t *testing.T) {
	e := newEnv(t)
	sealed, err := e.svc.SealTOTPSecret(7, "JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := e.svc.OpenTOTPSecret(7, sealed); err != nil || got != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("own user: %q, %v", got, err)
	}
	if _, err := e.svc.OpenTOTPSecret(8, sealed); err == nil {
		t.Fatal("another user's ID must not open the blob")
	}

	// Copying alice's blob into bob's row must not give bob alice's second factor.
	alice, secret := e.addTOTPUser("alice", testPass)
	bob := e.addUser("bob", testPass2)
	if err := e.store.SetTOTP(e.ctx, bob.ID, alice.TOTPSecretEnc, true); err != nil {
		t.Fatal(err)
	}
	res, err := e.svc.Login(e.ctx, "bob", testPass2, testIP, testUA, false)
	if !errors.Is(err, ErrSecondFactorRequired) {
		t.Fatalf("bob login: %v", err)
	}
	_, err = e.svc.VerifySecondFactor(e.ctx, res.Challenge, codeAt(t, secret, e.clock.Now()), testIP)
	if err == nil || errors.Is(err, ErrInvalidCode) || errors.Is(err, ErrInvalidChallenge) {
		t.Fatalf("swapped blob: %v, want an internal 'cannot open' error, not a session", err)
	}
	// Alice herself still works.
	res, err = e.svc.Login(e.ctx, "alice", testPass, testIP, testUA, false)
	if !errors.Is(err, ErrSecondFactorRequired) {
		t.Fatal(err)
	}
	if _, err := e.svc.VerifySecondFactor(e.ctx, res.Challenge, codeAt(t, secret, e.clock.Now()), testIP); err != nil {
		t.Fatalf("alice: %v", err)
	}
}
