package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	goruntime "runtime"
	"strings"
	"time"

	"github.com/phabioo/nexara/internal/protocol"
)

const (
	maxBinarySize  = 256 << 20
	updateTimeout  = 10 * time.Minute
	agentPathStart = "/grid/agent/"
)

var (
	updatePathRe = regexp.MustCompile(`^/grid/agent/[a-z0-9_]+/[a-z0-9_]+$`)
	sha256HexRe  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// validateUpdate checks the hub's agent.update request and returns the
// download path. An empty path selects this platform's binary.
func (a *Agent) validateUpdate(up protocol.AgentUpdate) (string, error) {
	if a.opts.BinaryPath == "" {
		return "", errors.New("agent cannot locate its own binary")
	}
	if packageManaged(a.opts.BinaryPath) {
		return "", errors.New("managed by package; update the nexus package")
	}
	if !sha256HexRe.MatchString(strings.ToLower(up.SHA256)) {
		return "", errors.New("invalid sha256")
	}
	path := up.Path
	if path == "" {
		path = agentPathStart + goruntime.GOOS + "/" + goruntime.GOARCH
	}
	if !updatePathRe.MatchString(path) {
		return "", errors.New("invalid update path")
	}
	return path, nil
}

// packageManagedDirs hold binaries owned by the distribution's package
// manager. Replacing them behind dpkg's back breaks verification and is undone
// by the next package upgrade; the package update path handles them instead.
var packageManagedDirs = []string{"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/"}

// packageManaged reports whether the binary lives in a package-managed
// directory (the .deb installs /usr/bin/grid-agent). Binaries from SSH
// enrollment live in /usr/local/bin and self-update normally. The path is
// resolved through symlinks first so /bin on a usr-merged system matches too.
func packageManaged(binary string) bool {
	paths := []string{filepath.ToSlash(filepath.Clean(binary))}
	if r, err := filepath.EvalSymlinks(binary); err == nil {
		paths = append(paths, filepath.ToSlash(r))
	}
	for _, p := range paths {
		for _, d := range packageManagedDirs {
			if strings.HasPrefix(p, d) {
				return true
			}
		}
	}
	return false
}

// hubOrigin derives https://host:port from the hub's wss:// URL.
func hubOrigin(hubURL string) (string, error) {
	u, err := url.Parse(hubURL)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid hub url")
	}
	return "https://" + u.Host, nil
}

func (s *session) agentUpdate(env protocol.Envelope) {
	up, ok := decode[protocol.AgentUpdate](s, env)
	if !ok {
		return
	}
	path, err := s.a.validateUpdate(up)
	if err != nil {
		s.result(env.ID, err)
		return
	}
	if !s.a.updating.CompareAndSwap(false, true) {
		s.resultMsg(env.ID, "an update is already in progress")
		return
	}
	if err := s.send(protocol.TypeResult, env.ID, protocol.Result{OK: true}); err != nil {
		s.a.updating.Store(false)
		return
	}
	s.spawn(func() {
		defer s.a.updating.Store(false)
		ctx, cancel := context.WithTimeout(s.ctx, updateTimeout)
		defer cancel()
		if err := s.a.installUpdate(ctx, up, path); err != nil {
			s.a.log.Error("agent update failed, keeping the current binary", "version", up.Version, "error", err)
			return
		}
		s.a.log.Info("agent update installed, restarting", "version", up.Version)
		s.a.restarting.Store(true)
		s.a.stop() // graceful shutdown; Run calls Exit(0) afterwards
	})
}

// installUpdate downloads the new binary from the hub, verifies its SHA-256
// and atomically replaces the running executable. On any error the old binary
// stays untouched and the temporary file is removed.
func (a *Agent) installUpdate(ctx context.Context, up protocol.AgentUpdate, path string) (err error) {
	origin, err := hubOrigin(a.cfg.Hub.URL)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+path, nil)
	if err != nil {
		return err
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download: hub answered %s", resp.Status)
	}

	dir := filepath.Dir(a.opts.BinaryPath)
	tmp, err := os.CreateTemp(dir, ".grid-agent-update-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, maxBinarySize+1))
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	if n > maxBinarySize {
		return errors.New("download: binary too large")
	}
	if n == 0 {
		return errors.New("download: empty binary")
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != strings.ToLower(up.SHA256) {
		return errors.New("checksum mismatch")
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}
	if err := os.Chmod(tmp.Name(), 0o755); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}
	if err := os.Rename(tmp.Name(), a.opts.BinaryPath); err != nil {
		return fmt.Errorf("replace binary: %w", err)
	}
	syncDir(dir)
	return nil
}

// syncDir makes the rename durable where the platform allows it.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}
