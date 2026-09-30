package pki

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync"
)

// ServerTLSConfig builds the hub's listener configuration. Browsers and agents
// share one port: a client certificate is optional (VerifyClientCertIfGiven)
// but, when presented, must chain to ca and must not be revoked. The server
// certificate is reloaded from disk when the files change, so re-issuing
// needs no restart. Callers set NextProtos as needed.
func ServerTLSConfig(ca *CA, certFile, keyFile string, isRevoked func(fingerprint string) bool) (*tls.Config, error) {
	rl := &reloader{certFile: certFile, keyFile: keyFile}
	if _, err := rl.get(); err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	return &tls.Config{
		MinVersion:     tls.VersionTLS13,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return rl.get() },
		ClientAuth:     tls.VerifyClientCertIfGiven,
		ClientCAs:      pool,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 || isRevoked == nil {
				return nil
			}
			if isRevoked(Fingerprint(cs.PeerCertificates[0])) {
				return errors.New("pki: client certificate revoked")
			}
			return nil
		},
	}, nil
}

// reloader caches a certificate pair and reloads it when either file is
// replaced. If a reload fails (e.g. key and cert are mid-rotation), the last
// good pair keeps being served and the reload is retried on the next handshake.
type reloader struct {
	certFile, keyFile string

	mu       sync.Mutex
	cert     *tls.Certificate
	certInfo os.FileInfo
	keyInfo  os.FileInfo
}

func (r *reloader) get() (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ci, cerr := os.Stat(r.certFile)
	ki, kerr := os.Stat(r.keyFile)
	if cerr == nil && kerr == nil && r.cert != nil && sameFile(r.certInfo, ci) && sameFile(r.keyInfo, ki) {
		return r.cert, nil
	}
	pair, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		if r.cert != nil {
			return r.cert, nil
		}
		return nil, fmt.Errorf("pki: load server certificate: %w", err)
	}
	if cerr == nil && kerr == nil {
		r.certInfo, r.keyInfo = ci, ki
	}
	r.cert = &pair
	return r.cert, nil
}

func sameFile(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) && a.ModTime().Equal(b.ModTime()) && a.Size() == b.Size()
}

// AgentTLSConfig builds the agent's mTLS client configuration for the hub
// connection: only caPEM is trusted (no system roots) and the client
// certificate is read from disk at handshake time.
func AgentTLSConfig(caPEM []byte, certFile, keyFile string) (*tls.Config, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("pki: no valid CA certificate in ca_pem")
	}
	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		return nil, fmt.Errorf("pki: load agent certificate: %w", err)
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    pool,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			pair, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				return nil, fmt.Errorf("pki: load agent certificate: %w", err)
			}
			return &pair, nil
		},
	}, nil
}

// PinnedTLSConfig is the enrollment client configuration: the hub is accepted
// only if the presented chain contains a CA certificate with the given
// fingerprint and the leaf verifies against it (and matches the requested
// host name or IP). System roots are not used. The hub sends its CA
// certificate as part of server.pem. caFingerprint may be colon separated.
func PinnedTLSConfig(caFingerprint string) (*tls.Config, error) {
	want, err := NormalizeFingerprint(caFingerprint)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		// The standard verification is replaced by VerifyConnection below,
		// which trusts exactly one CA, identified by fingerprint.
		InsecureSkipVerify: true, //nolint:gosec
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("pki: hub presented no certificate")
			}
			var pinned *x509.Certificate
			inter := x509.NewCertPool()
			for _, c := range cs.PeerCertificates[1:] {
				if Fingerprint(c) == want {
					pinned = c
				} else {
					inter.AddCert(c)
				}
			}
			if pinned == nil {
				return errors.New("pki: hub CA does not match the pinned fingerprint")
			}
			if !pinned.IsCA {
				return errors.New("pki: pinned certificate is not a CA")
			}
			roots := x509.NewCertPool()
			roots.AddCert(pinned)
			_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{
				Roots:         roots,
				Intermediates: inter,
				DNSName:       cs.ServerName,
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			})
			if err != nil {
				return fmt.Errorf("pki: hub certificate rejected: %w", err)
			}
			return nil
		},
	}, nil
}
