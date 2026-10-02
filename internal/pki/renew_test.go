package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"net"
	"testing"
	"time"
)

func csrWith(t *testing.T, key *ecdsa.PrivateKey, tmpl x509.CertificateRequest) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func TestSignAgentRenewal(t *testing.T) {
	ca, _ := newCA(t)
	now := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	const hostID = "a1c5e0d2b7f34961"

	// The certificate the agent presents today.
	_, oldCSR, err := NewAgentKeyAndCSR(hostID)
	if err != nil {
		t.Fatal(err)
	}
	_, oldCert, err := SignAgentCSR(ca, oldCSR, hostID, now.Add(-340*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	freshKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// A certificate whose key the CSR below reuses.
	reusedKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	reusedCSR := csrWith(t, reusedKey, x509.CertificateRequest{Subject: pkix.Name{CommonName: hostID}})
	_, reusedCert, err := SignAgentCSR(ca, reusedCSR, hostID, now)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		csr     func() []byte
		current *x509.Certificate
		wantErr error
		anyErr  bool
	}{
		{name: "fresh key, own id", csr: func() []byte {
			return csrWith(t, freshKey, x509.CertificateRequest{Subject: pkix.Name{CommonName: hostID}})
		}, current: oldCert},
		{name: "no current certificate known", csr: func() []byte {
			return csrWith(t, freshKey, x509.CertificateRequest{Subject: pkix.Name{CommonName: hostID}})
		}},
		{name: "foreign common name", csr: func() []byte {
			return csrWith(t, freshKey, x509.CertificateRequest{Subject: pkix.Name{CommonName: "ffffffffffffffff"}})
		}, current: oldCert, wantErr: ErrRenewalIdentity},
		{name: "empty common name", csr: func() []byte {
			return csrWith(t, freshKey, x509.CertificateRequest{})
		}, current: oldCert, wantErr: ErrRenewalIdentity},
		{name: "asks for DNS SANs", csr: func() []byte {
			return csrWith(t, freshKey, x509.CertificateRequest{Subject: pkix.Name{CommonName: hostID}, DNSNames: []string{"evil.local"}})
		}, current: oldCert, wantErr: ErrRenewalIdentity},
		{name: "asks for IP SANs", csr: func() []byte {
			return csrWith(t, freshKey, x509.CertificateRequest{Subject: pkix.Name{CommonName: hostID}, IPAddresses: []net.IP{net.ParseIP("10.0.0.1")}})
		}, current: oldCert, wantErr: ErrRenewalIdentity},
		{name: "reuses the current key", csr: func() []byte { return reusedCSR }, current: reusedCert, wantErr: ErrRenewalKeyReuse},
		{name: "P-384 key", csr: func() []byte {
			key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: hostID}}, key)
			return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
		}, current: oldCert, anyErr: true},
		{name: "garbage", csr: func() []byte { return []byte("nope") }, current: oldCert, anyErr: true},
		{name: "tampered signature", csr: func() []byte {
			p := csrWith(t, freshKey, x509.CertificateRequest{Subject: pkix.Name{CommonName: hostID}})
			blk, _ := pem.Decode(p)
			blk.Bytes[len(blk.Bytes)-3] ^= 0xff
			return pem.EncodeToMemory(blk)
		}, current: oldCert, anyErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			certPEM, cert, err := SignAgentRenewal(ca, tc.csr(), hostID, tc.current, now)
			if tc.wantErr != nil || tc.anyErr {
				if err == nil {
					t.Fatal("renewal succeeded, want an error")
				}
				if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
					t.Fatalf("error = %v, want %v", err, tc.wantErr)
				}
				if certPEM != nil || cert != nil {
					t.Fatal("a certificate came back with the error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cert.Subject.CommonName != hostID || len(cert.DNSNames)+len(cert.IPAddresses) != 0 {
				t.Errorf("subject/SANs = %v / %v %v", cert.Subject, cert.DNSNames, cert.IPAddresses)
			}
			if got, want := cert.NotAfter.Sub(now), LeafValidity; got != want {
				t.Errorf("lifetime from now = %v, want %v", got, want)
			}
			if err := cert.CheckSignatureFrom(ca.Cert); err != nil {
				t.Error(err)
			}
			if cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
				t.Errorf("ext key usage = %v", cert.ExtKeyUsage)
			}
			if Fingerprint(cert) == Fingerprint(oldCert) {
				t.Error("renewal returned the old certificate")
			}
		})
	}
}
