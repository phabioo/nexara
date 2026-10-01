// Package enroll is the agent side of enrollment (decision #38): it creates the
// agent's key and CSR, trades the one-time token for a client certificate over
// HTTPS (the hub CA is pinned by fingerprint, system roots are not used) and
// writes key, certificate, CA and agent.yaml.
//
// The token and the private key never appear in errors or logs.
package enroll

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/phabioo/nexara/internal/agent/metrics"
	"github.com/phabioo/nexara/internal/buildinfo"
	"github.com/phabioo/nexara/internal/config"
	"github.com/phabioo/nexara/internal/pki"
	"github.com/phabioo/nexara/internal/protocol"
)

// Default locations (match config.DefaultAgent and the systemd unit).
const (
	DefaultStateDir = "/var/lib/grid-agent"

	caFile   = "ca.pem"
	certFile = "agent.pem"
	keyFile  = "agent.key"

	requestTimeout  = 30 * time.Second
	maxResponseSize = 1 << 20
	maxTokenFile    = 4 << 10
)

// Options configures Enroll.
type Options struct {
	Hub           string // https://host:port (a bare host:port is treated as https)
	Token         string
	CAFingerprint string // SHA-256 of the hub CA certificate, hex (colons allowed)
	ConfigPath    string // agent.yaml to write, e.g. /etc/grid-agent/agent.yaml
	StateDir      string // where key, certificate and CA go, e.g. /var/lib/grid-agent
	ShellUser     string // the device's normal sudo user; never root
}

// codeRE is the shape of an enrollment code, "GRID-XXXX-XXXX-XXXX-XXXX". The
// alphabet has no I, L, O, 0 or 1. It must stay equal to the hub's
// (internal/hub/enroll, enforced by a test there and in the install script).
var codeRE = regexp.MustCompile(`^GRID(-[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{4}){4}$`)

// NormalizeCode trims and upper-cases a hand-typed code and checks its shape.
func NormalizeCode(code string) (string, error) {
	c := strings.ToUpper(strings.TrimSpace(code))
	if !codeRE.MatchString(c) {
		return "", errors.New("the enrollment code is malformed (expected GRID-XXXX-XXXX-XXXX-XXXX)")
	}
	return c, nil
}

// ReadTokenFile reads an enrollment code from a file, so that it does not
// have to appear on a command line (visible in ps and in the sudo log). On
// Unix the file must not be readable by group or others.
func ReadTokenFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("enroll: open token file: %w", err)
	}
	defer f.Close()
	if runtime.GOOS != "windows" {
		fi, err := f.Stat()
		if err != nil {
			return "", fmt.Errorf("enroll: stat token file: %w", err)
		}
		if fi.Mode().Perm()&0o077 != 0 {
			return "", errors.New("enroll: token file must not be accessible by group or others (chmod 600)")
		}
	}
	data, err := io.ReadAll(io.LimitReader(f, maxTokenFile+1))
	if err != nil {
		return "", fmt.Errorf("enroll: read token file: %w", err)
	}
	if len(data) > maxTokenFile {
		return "", errors.New("enroll: token file is too large")
	}
	return NormalizeCode(string(data))
}

// ErrTokenRejected means the hub refused the token (unknown, expired or used).
var ErrTokenRejected = errors.New("enrollment code is invalid, expired or already used")

func validShellUser(u string) error {
	switch {
	case u == "":
		return errors.New("shell user must be set (the device's normal user, not root)")
	case u == "root":
		return errors.New("shell user must not be root")
	case u != strings.TrimSpace(u) || strings.ContainsAny(u, " \t:/\\"):
		return fmt.Errorf("shell user %q is not a valid user name", u)
	}
	return nil
}

func hubBase(hub string) (string, error) {
	hub = strings.TrimSpace(hub)
	if hub == "" {
		return "", errors.New("hub address is required")
	}
	if !strings.Contains(hub, "://") {
		hub = "https://" + hub
	}
	u, err := url.Parse(hub)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return "", errors.New("hub must be an https:// address")
	}
	return "https://" + u.Host, nil
}

// Enroll pairs this device with the hub and writes its configuration.
func Enroll(ctx context.Context, o Options) error {
	if err := validShellUser(o.ShellUser); err != nil {
		return err
	}
	if o.Token == "" {
		return errors.New("enrollment token is required")
	}
	token, err := NormalizeCode(o.Token)
	if err != nil {
		return err
	}
	o.Token = token
	if o.ConfigPath == "" || o.StateDir == "" {
		return errors.New("config path and state dir are required")
	}
	base, err := hubBase(o.Hub)
	if err != nil {
		return err
	}
	wantCA, err := pki.NormalizeFingerprint(o.CAFingerprint)
	if err != nil {
		return err
	}
	tlsCfg, err := pki.PinnedTLSConfig(wantCA)
	if err != nil {
		return err
	}

	facts := metrics.Facts()
	keyPEM, csrPEM, err := pki.NewAgentKeyAndCSR(facts.Hostname)
	if err != nil {
		return err
	}
	defaults := config.DefaultAgent()
	body, err := json.Marshal(protocol.EnrollRequest{
		Token:  o.Token,
		CSRPEM: string(csrPEM),
		Hello: protocol.Hello{
			AgentVersion:    buildinfo.Version,
			ProtocolVersion: protocol.ProtocolVersion,
			Hostname:        facts.Hostname,
			OS:              facts.OS,
			Arch:            facts.Arch,
			Kernel:          facts.Kernel,
			Model:           facts.Model,
			Capabilities:    defaults.Capabilities.Enabled(),
			MAC:             facts.MAC,
		},
	})
	if err != nil {
		return errors.New("enroll: encode request")
	}

	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/grid/enroll", bytes.NewReader(body))
	if err != nil {
		return errors.New("enroll: build request")
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{
		Timeout: requestTimeout,
		Transport: &http.Transport{
			TLSClientConfig:   tlsCfg,
			Proxy:             nil, // never route enrollment through an environment proxy
			DisableKeepAlives: true,
		},
		// The hub never redirects; refuse to follow one (it would carry the token body elsewhere).
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("enroll: cannot reach the hub: %w", scrub(err, o.Token))
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return ErrTokenRejected
	case resp.StatusCode == http.StatusTooManyRequests:
		return errors.New("enroll: the hub is rate limiting enrollment attempts, try again in a minute")
	case resp.StatusCode == http.StatusConflict:
		return conflictError(resp.Body)
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("enroll: the hub answered with status %d", resp.StatusCode)
	}
	var out protocol.EnrollResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseSize)).Decode(&out); err != nil {
		return errors.New("enroll: malformed answer from the hub")
	}
	return install(o, wantCA, keyPEM, out)
}

// conflictError explains a 409 from the hub: the host name is taken, or the
// host is revoked.
func conflictError(body io.Reader) error {
	var e struct {
		Error string `json:"error"`
	}
	_ = json.NewDecoder(io.LimitReader(body, 4<<10)).Decode(&e)
	if e.Error == "host exists" {
		return errors.New("enroll: the hub already has a host with this name; give this device a unique host name, or replace the old host from the hub's Add host dialog")
	}
	return errors.New("enroll: the hub refused this host (it is revoked there; remove it first)")
}

// scrub removes the token from an error text (it should never be in there, but
// http errors echo URLs and we do not rely on that).
func scrub(err error, secret string) error {
	if secret == "" || !strings.Contains(err.Error(), secret) {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), secret, "[redacted]"))
}

// install validates the hub's answer and writes all files; agent.yaml goes last
// so a half-finished enrollment is never mistaken for a working agent.
func install(o Options, wantCA string, keyPEM []byte, r protocol.EnrollResponse) error {
	caFP, err := pki.FingerprintFromPEM([]byte(r.CAPEM))
	if err != nil || caFP != wantCA {
		return errors.New("enroll: the hub returned a CA that does not match the pinned fingerprint")
	}
	if _, err := tls.X509KeyPair([]byte(r.CertPEM), keyPEM); err != nil {
		return errors.New("enroll: the hub returned a certificate that does not match this agent's key")
	}
	if r.HostID == "" {
		return errors.New("enroll: the hub returned no host id")
	}

	cfg := config.DefaultAgent()
	cfg.Hub.URL = r.HubURL
	cfg.TLS = config.AgentTLSSection{
		CA:   filepath.Join(o.StateDir, caFile),
		Cert: filepath.Join(o.StateDir, certFile),
		Key:  filepath.Join(o.StateDir, keyFile),
	}
	cfg.Shell.User = o.ShellUser
	if r.Settings.Capabilities != nil { // nil keeps the defaults; non-nil sets exactly these
		cfg.Capabilities = config.Capabilities{}
		for _, name := range r.Settings.Capabilities {
			setCapability(&cfg.Capabilities, name)
		}
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("enroll: hub settings rejected: %w", err)
	}

	if err := os.MkdirAll(o.StateDir, 0o700); err != nil {
		return fmt.Errorf("enroll: create %s: %w", o.StateDir, err)
	}
	if err := os.MkdirAll(filepath.Dir(o.ConfigPath), 0o755); err != nil {
		return fmt.Errorf("enroll: create %s: %w", filepath.Dir(o.ConfigPath), err)
	}
	if err := writeFileAtomic(cfg.TLS.Key, keyPEM, 0o600); err != nil {
		return err
	}
	if err := writeFileAtomic(cfg.TLS.Cert, []byte(r.CertPEM), 0o644); err != nil {
		return err
	}
	if err := writeFileAtomic(cfg.TLS.CA, []byte(r.CAPEM), 0o644); err != nil {
		return err
	}
	return config.SaveAgent(o.ConfigPath, cfg)
}

func setCapability(c *config.Capabilities, name string) {
	switch name {
	case protocol.CapMonitoring:
		c.Monitoring = true
	case protocol.CapPackages:
		c.Packages = true
	case protocol.CapServices:
		c.Services = true
	case protocol.CapShell:
		c.Shell = true
	case protocol.CapPower:
		c.Power = true
	case protocol.CapDocker:
		c.Docker = true
	}
}

// selfLink is the JSON written by the hub's WriteSelfLinkToken.
type selfLink struct {
	Token         string `json:"token"`
	CAFingerprint string `json:"ca_fingerprint"`
	Hub           string `json:"hub"`
}

// EnrollFromTokenFile enrolls the hub's own agent (self-link, agent.yaml
// enroll.token_file) and deletes the token file afterwards.
func EnrollFromTokenFile(ctx context.Context, cfgPath, stateDir, tokenFile, shellUser string) error {
	f, err := os.Open(tokenFile)
	if err != nil {
		return fmt.Errorf("enroll: open token file: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxTokenFile+1))
	_ = f.Close()
	if err != nil {
		return fmt.Errorf("enroll: read token file: %w", err)
	}
	if len(data) > maxTokenFile {
		return errors.New("enroll: token file is too large")
	}
	var sl selfLink
	if err := json.Unmarshal(data, &sl); err != nil {
		return errors.New("enroll: token file is not valid JSON")
	}
	if err := Enroll(ctx, Options{
		Hub: sl.Hub, Token: sl.Token, CAFingerprint: sl.CAFingerprint,
		ConfigPath: cfgPath, StateDir: stateDir, ShellUser: shellUser,
	}); err != nil {
		return err
	}
	if err := os.Remove(tokenFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("enroll: enrolled, but could not delete the token file: %w", err)
	}
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
