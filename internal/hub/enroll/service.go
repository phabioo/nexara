// Package enroll is the hub side of adding hosts (decisions #2, #17, #20, #38,
// #40, #41): one-time enrollment codes, the public enrollment endpoints
// (POST /grid/enroll, GET /grid/install.sh, GET /grid/download/{os}/{arch}),
// the SSH bootstrap that installs the agent on a new Linux host, and the
// self-link token for the hub's own agent.
//
// Secrets: enrollment codes are stored only as SHA-256 hashes, SSH passwords
// are used for the one install and never stored, logged, audited or echoed.
package enroll

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/phabioo/nexara/internal/hub/agentbin"
	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/pki"
	"github.com/phabioo/nexara/internal/protocol"
)

// CodeTTL is how long an enrollment code (or internal token) stays valid.
const CodeTTL = 15 * time.Minute

// codeAlphabet has no I, L, O, 0 or 1, which are easily confused when typed.
const codeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

// Enrollment codes are "GRID-" plus codeGroups groups of codeGroupLen symbols
// (16 symbols from 31, about 79 bits; S-10). The install script and the agent
// validate the same shape; a test keeps the three in sync.
const (
	codeGroups   = 4
	codeGroupLen = 4
)

var codeRE = regexp.MustCompile(`^GRID(-[` + codeAlphabet + `]{4}){4}$`)

// replaceGrantTTL bounds how long an operator's "replace this host" choice
// stays usable; it matches the token lifetime.
const replaceGrantTTL = CodeTTL

// Options configures a Service.
type Options struct {
	Store *store.Store
	CA    *pki.CA
	// ServerCertFile is the hub's server.pem; the install script pins its public key.
	ServerCertFile string
	// HubAddress is the host name or IPv4 address agents use to reach the hub
	// (e.g. frpi5.local). It ends up in URLs and shell scripts, so it is validated.
	HubAddress string
	Port       int
	// DataDir holds the hub's SSH key in <DataDir>/ssh.
	DataDir string
	Logger  *slog.Logger
	Now     func() time.Time
	// OnEnrolled is called after a host was enrolled (created, or re-enrolled
	// with a new certificate) and before the agent receives its response.
	OnEnrolled func(ctx context.Context, h store.Host)
	// WaitOnline blocks until the host's agent is connected (or ctx ends). Used
	// by the last step of the SSH bootstrap; nil skips the wait.
	WaitOnline func(ctx context.Context, id grid.HostID) error

	// HostOnline reports whether a host's agent is currently connected. If
	// set, replacing a host is refused while it is online (decision #46).
	HostOnline func(id grid.HostID) bool

	// SSH replaces the real SSH client (tests). AgentBinary replaces
	// agentbin.Lookup (tests).
	SSH         SSHDialer
	AgentBinary func(goos, goarch string) (agentbin.Binary, bool)
}

// Service implements grid.Enroller and serves the enrollment HTTP endpoints.
type Service struct {
	st       *store.Store
	ca       *pki.CA
	certFn   string
	addr     string
	port     int
	log      *slog.Logger
	now      func() time.Time
	enrolled func(ctx context.Context, h store.Host)
	waitOn   func(ctx context.Context, id grid.HostID) error
	dialer   SSHDialer
	binary   func(goos, goarch string) (agentbin.Binary, bool)
	hubKey   *hubKey

	hostOnline func(id grid.HostID) bool

	limiter       *ipLimiter // per client (IPv4 address or IPv6 /64)
	globalLimiter *ipLimiter // all clients together
	onlineTimeout time.Duration

	grantMu sync.Mutex
	grants  map[string]replaceGrant // by enrollment token hash
}

// replaceGrant is the operator's explicit permission for one enrollment token
// to replace one existing host.
type replaceGrant struct {
	hostID  string
	actor   grid.Actor
	expires time.Time
}

func (s *Service) grantReplace(tokenHash, hostID string, actor grid.Actor, now time.Time) {
	s.grantMu.Lock()
	defer s.grantMu.Unlock()
	for k, g := range s.grants { // drop stale grants
		if !g.expires.After(now) {
			delete(s.grants, k)
		}
	}
	s.grants[tokenHash] = replaceGrant{hostID: hostID, actor: actor, expires: now.Add(replaceGrantTTL)}
}

// takeReplace returns and removes the grant of a token.
func (s *Service) takeReplace(tokenHash string, now time.Time) (replaceGrant, bool) {
	s.grantMu.Lock()
	defer s.grantMu.Unlock()
	g, ok := s.grants[tokenHash]
	delete(s.grants, tokenHash)
	return g, ok && g.expires.After(now)
}

var _ grid.Enroller = (*Service)(nil)

var hostAddrRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)

// validAddress accepts DNS names and IPv4 addresses. IPv6 literals are not
// supported (they would need brackets in URLs and scripts).
func validAddress(s string) bool {
	if !hostAddrRE.MatchString(s) {
		return false
	}
	if strings.Contains(s, "..") {
		return false
	}
	return true
}

// New validates the options, loads or creates the hub's SSH key and returns the service.
func New(o Options) (*Service, error) {
	switch {
	case o.Store == nil:
		return nil, errors.New("enroll: store is required")
	case o.CA == nil:
		return nil, errors.New("enroll: CA is required")
	case o.ServerCertFile == "":
		return nil, errors.New("enroll: server certificate file is required")
	case !validAddress(o.HubAddress):
		return nil, fmt.Errorf("enroll: hub address %q must be a DNS name or IPv4 address", o.HubAddress)
	case o.Port < 1 || o.Port > 65535:
		return nil, fmt.Errorf("enroll: invalid port %d", o.Port)
	case o.DataDir == "":
		return nil, errors.New("enroll: data dir is required")
	}
	s := &Service{
		st: o.Store, ca: o.CA, certFn: o.ServerCertFile,
		addr: o.HubAddress, port: o.Port,
		log: o.Logger, now: o.Now,
		enrolled: o.OnEnrolled, waitOn: o.WaitOnline,
		dialer: o.SSH, binary: o.AgentBinary,
		hostOnline:    o.HostOnline,
		grants:        map[string]replaceGrant{},
		onlineTimeout: 60 * time.Second,
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.dialer == nil {
		s.dialer = realDialer{}
	}
	if s.binary == nil {
		s.binary = agentbin.Lookup
	}
	key, err := loadOrCreateHubKey(filepath.Join(o.DataDir, "ssh"), o.HubAddress)
	if err != nil {
		return nil, err
	}
	s.hubKey = key
	s.limiter = newIPLimiter(enrollRate, time.Minute)
	s.globalLimiter = newIPLimiter(enrollGlobalRate, time.Minute)
	return s, nil
}

// PublicKey returns the hub's SSH public key in authorized_keys format, for
// the "Via SSH" dialog ("Use the hub's SSH key").
func (s *Service) PublicKey() string { return s.hubKey.authorized }

// hubURL is the base URL agents enroll against.
func (s *Service) hubURL() string { return "https://" + s.hostPort() }

func (s *Service) hostPort() string { return s.addr + ":" + strconv.Itoa(s.port) }

func (s *Service) connectURL() string { return "wss://" + s.hostPort() + "/grid/connect" }

// pin returns the value for curl --pinnedpubkey: base64 of the SHA-256 of the
// server certificate's SubjectPublicKeyInfo. It is read from disk each time, so
// a re-issued server certificate is picked up.
func (s *Service) pin() (string, error) {
	data, err := os.ReadFile(s.certFn)
	if err != nil {
		return "", fmt.Errorf("enroll: read server certificate: %w", err)
	}
	cert, err := pki.ParseCertPEM(data)
	if err != nil {
		return "", fmt.Errorf("enroll: server certificate: %w", err)
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:]), nil
}

// normalizeCode makes hand-typed codes comparable: trimmed and upper-cased.
func normalizeCode(code string) string { return strings.ToUpper(strings.TrimSpace(code)) }

func hashCode(code string) string {
	sum := sha256.Sum256([]byte(normalizeCode(code)))
	return hex.EncodeToString(sum[:])
}

// randomCode returns "GRID-XXXX-XXXX-XXXX-XXXX" drawn uniformly from codeAlphabet.
func randomCode() (string, error) {
	const n = codeGroups * codeGroupLen
	out := make([]byte, 0, n)
	limit := byte(256 - 256%len(codeAlphabet)) // reject the biased tail
	buf := make([]byte, 16)
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("enroll: random code: %w", err)
		}
		for _, b := range buf {
			if b >= limit {
				continue
			}
			out = append(out, codeAlphabet[int(b)%len(codeAlphabet)])
			if len(out) == n {
				break
			}
		}
	}
	var b strings.Builder
	b.WriteString("GRID")
	for i := 0; i < n; i += codeGroupLen {
		b.WriteByte('-')
		b.Write(out[i : i+codeGroupLen])
	}
	return b.String(), nil
}

// normalizeCaps validates capability names and removes duplicates, keeping
// nil as nil ("agent defaults").
func normalizeCaps(caps []string) ([]string, error) {
	if caps == nil {
		return nil, nil
	}
	known := map[string]bool{}
	for _, c := range protocol.Capabilities() {
		known[c] = true
	}
	seen := map[string]bool{}
	out := []string{}
	for _, c := range caps {
		if !known[c] {
			return nil, fmt.Errorf("%w: unknown capability %q", grid.ErrInvalidArgument, c)
		}
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out, nil
}

// newToken creates and stores a one-time token and returns its plain value.
func (s *Service) newToken(ctx context.Context, caps []string) (code string, expires time.Time, err error) {
	code, err = randomCode()
	if err != nil {
		return "", time.Time{}, err
	}
	expires = s.now().Add(CodeTTL)
	if err := s.st.CreateEnrollToken(ctx, hashCode(code), expires, caps); err != nil {
		return "", time.Time{}, fmt.Errorf("enroll: store token: %w", err)
	}
	return code, expires, nil
}

func (s *Service) audit(ctx context.Context, actor, host, action, detail, result string) {
	if _, err := s.st.AppendAudit(ctx, store.AuditEntry{
		User: actor, Host: host, Action: action, Detail: detail, Result: result,
	}); err != nil {
		s.log.Error("audit write failed", "action", action, "err", err)
	}
}

func capsDetail(caps []string) string {
	if caps == nil {
		return "capabilities: defaults"
	}
	if len(caps) == 0 {
		return "capabilities: none"
	}
	return "capabilities: " + strings.Join(caps, ",")
}

// NewEnrollCode implements grid.Enroller.
func (s *Service) NewEnrollCode(ctx context.Context, actor grid.Actor, opts grid.EnrollOptions) (grid.EnrollCode, error) {
	caps, err := normalizeCaps(opts.Capabilities)
	if err != nil {
		return grid.EnrollCode{}, err
	}
	pin, err := s.pin()
	if err != nil {
		return grid.EnrollCode{}, err
	}
	code, expires, err := s.newToken(ctx, caps)
	if err != nil {
		return grid.EnrollCode{}, err
	}
	s.audit(ctx, actor.Operator, "", "enroll.code", capsDetail(caps), store.AuditOK)
	return grid.EnrollCode{
		Code:    code,
		Expires: expires,
		Command: "curl -fsSL --insecure --pinnedpubkey sha256//" + pin + " " +
			s.hubURL() + "/grid/install.sh | sudo sh -s -- " + code,
	}, nil
}

// selfLink is the JSON the hub's own agent reads (agent.yaml enroll.token_file).
type selfLink struct {
	Token         string `json:"token"`
	CAFingerprint string `json:"ca_fingerprint"`
	Hub           string `json:"hub"`
}

// WriteSelfLinkToken creates a 15 minute token and writes the self-link JSON
// to path with mode 0640 (the installer creates the directory and sets its
// group so root's agent can read the file). caps nil means agent defaults.
func (s *Service) WriteSelfLinkToken(ctx context.Context, path string, caps []string) error {
	caps, err := normalizeCaps(caps)
	if err != nil {
		return err
	}
	code, _, err := s.newToken(ctx, caps)
	if err != nil {
		return err
	}
	data := `{"token":"` + code + `","ca_fingerprint":"` + s.ca.Fingerprint() +
		`","hub":"https://127.0.0.1:` + strconv.Itoa(s.port) + `"}` + "\n"
	if err := writeFileAtomic(path, []byte(data), 0o640); err != nil {
		return err
	}
	s.audit(ctx, grid.SystemActor.Operator, "", "enroll.code", "self-link; "+capsDetail(caps), store.AuditOK)
	return nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp*")
	if err != nil {
		return fmt.Errorf("enroll: write %s: %w", path, err)
	}
	name := tmp.Name()
	fail := func(err error) error {
		_ = tmp.Close()
		_ = os.Remove(name)
		return fmt.Errorf("enroll: write %s: %w", path, err)
	}
	if err := tmp.Chmod(perm); err != nil && runtime.GOOS != "windows" {
		return fail(err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		return fail(err)
	}
	if err := os.Rename(name, path); err != nil {
		return fail(err)
	}
	return nil
}

// ipOf extracts the host part of a remote address.
func ipOf(remote string) string {
	if h, _, err := net.SplitHostPort(remote); err == nil {
		return h
	}
	return remote
}
