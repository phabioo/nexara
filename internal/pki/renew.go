package pki

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// Errors of SignAgentRenewal; callers map them to protocol error codes.
var (
	// ErrRenewalIdentity means the CSR claims another identity than the host
	// the request arrived from.
	ErrRenewalIdentity = errors.New("pki: certificate request is for another host")
	// ErrRenewalKeyReuse means the CSR carries the public key of the current
	// certificate; a renewal must come with a fresh key.
	ErrRenewalKeyReuse = errors.New("pki: certificate request reuses the current key")
)

// SignAgentRenewal issues a replacement client certificate for hostID, the
// host the hub has already authenticated on the connection the request came
// in on (decision #47). On top of SignAgentCSR it refuses a CSR whose common
// name is not hostID (a sign of a confused or hostile client; the issued
// certificate never takes a name from the CSR anyway), a CSR asking for SANs,
// and, when current is the certificate the client presented, a CSR that reuses
// its public key. The certificate has the normal agent lifetime.
func SignAgentRenewal(ca *CA, csrPEM []byte, hostID string, current *x509.Certificate, now time.Time) ([]byte, *x509.Certificate, error) {
	blk, _ := pem.Decode(csrPEM)
	if blk == nil || blk.Type != "CERTIFICATE REQUEST" {
		return nil, nil, errors.New("pki: no certificate request found")
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		return nil, nil, errors.New("pki: malformed certificate request")
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, errors.New("pki: certificate request signature invalid")
	}
	if csr.Subject.CommonName != hostID {
		return nil, nil, ErrRenewalIdentity
	}
	if len(csr.DNSNames)+len(csr.IPAddresses)+len(csr.EmailAddresses)+len(csr.URIs) > 0 {
		return nil, nil, fmt.Errorf("%w: names beyond the common name are not accepted", ErrRenewalIdentity)
	}
	if current != nil {
		if cur, ok := current.PublicKey.(interface{ Equal(crypto.PublicKey) bool }); ok && cur.Equal(csr.PublicKey) {
			return nil, nil, ErrRenewalKeyReuse
		}
	}
	return SignAgentCSR(ca, csrPEM, hostID, now)
}
