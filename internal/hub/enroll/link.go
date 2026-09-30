package enroll

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/hub/store"
)

var (
	sshUserRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,31}$`)
	tmpPathRE = regexp.MustCompile(`^/[A-Za-z0-9._/-]{1,200}$`)
)

// validSSHTarget reports whether s is a DNS name or IP address.
func validSSHTarget(s string) bool { return validAddress(s) || net.ParseIP(s) != nil }

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// linkRun carries the state of one LinkViaSSH call.
type linkRun struct {
	s        *Service
	progress func(grid.LinkStep)
	secret   []byte   // SSH password copy, zeroed by the caller; used for redaction
	tmp      []string // temp files created on the host, removed by cleanup
}

func (l *linkRun) emit(step grid.LinkStepName, state grid.LinkState, detail string) {
	if l.progress != nil {
		l.progress(grid.LinkStep{Step: step, State: state, Detail: detail})
	}
}

// safe makes remote-provided text fit for the progress list: one short line
// that cannot contain the SSH password.
func (l *linkRun) safe(s string) string {
	s = cleanLine(s, 160)
	if len(l.secret) > 0 {
		s = strings.ReplaceAll(s, string(l.secret), "[redacted]")
	}
	return s
}

func (l *linkRun) fail(step grid.LinkStepName, detail string, cause error) error {
	l.emit(step, grid.LinkFailed, detail)
	return fmt.Errorf("%w at step %s: %w", grid.ErrLinkFailed, step, errors.New(l.safe(cause.Error())))
}

// describe turns a Run error into a short reason for the progress detail.
func (l *linkRun) describe(err error) string {
	var ee *ExitError
	if errors.As(err, &ee) && ee.Stderr != "" {
		return l.safe(ee.Stderr)
	}
	return l.safe(err.Error())
}

// LinkViaSSH implements grid.Enroller: it installs the Grid Agent on a Linux
// host over SSH and enrolls it (concept: "Kopplung eines neuen Hosts"). The SSH
// credentials live only in this call.
func (s *Service) LinkViaSSH(ctx context.Context, actor grid.Actor, req grid.SSHLinkRequest, progress func(grid.LinkStep)) (grid.HostInfo, error) {
	port := req.Port
	if port == 0 {
		port = 22
	}
	display := strings.TrimSpace(req.DisplayName)
	switch {
	case !validSSHTarget(req.Address):
		return grid.HostInfo{}, fmt.Errorf("%w: invalid address", grid.ErrInvalidArgument)
	case port < 1 || port > 65535:
		return grid.HostInfo{}, fmt.Errorf("%w: invalid SSH port", grid.ErrInvalidArgument)
	case !sshUserRE.MatchString(req.User):
		return grid.HostInfo{}, fmt.Errorf("%w: invalid user name", grid.ErrInvalidArgument)
	case req.User == "root":
		return grid.HostInfo{}, fmt.Errorf("%w: the shell runs as the SSH user, which must not be root", grid.ErrInvalidArgument)
	case req.UseHubKey == (req.Password != ""):
		return grid.HostInfo{}, fmt.Errorf("%w: choose either a password or the hub key", grid.ErrInvalidArgument)
	case len(display) > 64 || strings.IndexFunc(display, unicode.IsControl) >= 0:
		return grid.HostInfo{}, fmt.Errorf("%w: invalid display name", grid.ErrInvalidArgument)
	}

	// The copy can be wiped; the Secret string itself cannot (Go strings are immutable).
	var pw []byte
	if !req.UseHubKey {
		pw = []byte(req.Password.Reveal())
		defer zero(pw)
	}
	l := &linkRun{s: s, progress: progress, secret: pw}

	auth := "password"
	if req.UseHubKey {
		auth = "hub key"
	}
	target := req.User + "@" + req.Address + ":" + strconv.Itoa(port)
	host, err := l.run(ctx, req, port, display, pw)
	if err != nil {
		name := req.Address
		s.audit(ctx, actor.Operator, name, "host.link", target+" ["+auth+"] failed", store.AuditError)
		s.log.Warn("ssh link failed", "address", req.Address, "user", req.User)
		return grid.HostInfo{}, err
	}
	s.audit(ctx, actor.Operator, host.Name, "host.link", target+" ["+auth+"]", store.AuditOK)
	s.log.Info("host linked via ssh", "host", host.Name, "address", req.Address, "user", req.User)
	return toHostInfo(host), nil
}

func toHostInfo(h store.Host) grid.HostInfo {
	return grid.HostInfo{
		ID: grid.HostID(h.ID), Name: h.Name, DisplayName: h.DisplayName, Address: h.Address,
		OS: h.OS, Arch: h.Arch, AgentVersion: h.AgentVersion, Online: true,
		Capabilities: append([]string(nil), h.Capabilities...),
	}
}

func (l *linkRun) run(ctx context.Context, req grid.SSHLinkRequest, port int, display string, pw []byte) (store.Host, error) {
	s := l.s

	// --- connect
	l.emit(grid.StepConnect, grid.LinkRunning, "")
	cfg := SSHDialConfig{Addr: net.JoinHostPort(req.Address, strconv.Itoa(port)), User: req.User, Timeout: 10 * time.Second}
	if req.UseHubKey {
		cfg.Signer = s.hubKey.signer
	} else {
		cfg.Password = pw
	}
	conn, err := s.dialer.Dial(ctx, cfg)
	if err != nil {
		return store.Host{}, l.fail(grid.StepConnect, "Could not connect: "+l.describe(err), err)
	}
	defer conn.Close()
	defer l.cleanup(ctx, conn) // runs before conn.Close
	l.emit(grid.StepConnect, grid.LinkDone, "Connected as "+req.User+" · Host key "+conn.HostKeyFingerprint())

	// --- detect
	l.emit(grid.StepDetect, grid.LinkRunning, "")
	osName, err := conn.Run(ctx, "uname -s", nil)
	if err != nil {
		return store.Host{}, l.fail(grid.StepDetect, "Detection failed: "+l.describe(err), err)
	}
	if strings.TrimSpace(string(osName)) != "Linux" {
		return store.Host{}, l.fail(grid.StepDetect, "Unsupported system: "+l.safe(string(osName))+" (Linux only)", errors.New("unsupported operating system"))
	}
	machine, err := conn.Run(ctx, "uname -m", nil)
	if err != nil {
		return store.Host{}, l.fail(grid.StepDetect, "Detection failed: "+l.describe(err), err)
	}
	arch, ok := archFromUname(string(machine))
	if !ok {
		return store.Host{}, l.fail(grid.StepDetect, "Unsupported architecture: "+l.safe(string(machine)), errors.New("unsupported architecture"))
	}
	osRelease, _ := conn.Run(ctx, "cat /etc/os-release", nil) // optional
	bin, ok := s.binary("linux", arch)
	if !ok {
		return store.Host{}, l.fail(grid.StepDetect, "This hub has no Grid Agent build for linux/"+arch, errors.New("no embedded agent binary"))
	}
	l.emit(grid.StepDetect, grid.LinkDone, distroName(string(osRelease))+" · "+arch)

	// --- install
	l.emit(grid.StepInstall, grid.LinkRunning, "")
	sudo := "sudo -n "
	if !req.UseHubKey {
		sudo = "sudo -S -p '' "
	}
	runSudo := func(cmd string) error {
		var stdin *bytes.Reader
		if req.UseHubKey {
			stdin = bytes.NewReader(nil)
		} else {
			line := append(append([]byte(nil), pw...), '\n')
			defer zero(line)
			stdin = bytes.NewReader(line)
		}
		_, err := conn.Run(ctx, sudo+cmd, stdin)
		return err
	}
	tmpBin, err := l.upload(ctx, conn, bin.Data)
	if err != nil {
		return store.Host{}, l.fail(grid.StepInstall, "Upload failed: "+l.describe(err), err)
	}
	if err := runSudo("sh -c 'systemctl stop grid-agent >/dev/null 2>&1; install -m 0755 " + tmpBin + " " + agentBinaryPath + "'"); err != nil {
		return store.Host{}, l.fail(grid.StepInstall, "Install failed: "+l.describe(err), err)
	}
	l.emit(grid.StepInstall, grid.LinkDone, "Grid Agent "+bin.Version+" · systemd unit")

	// --- enroll
	l.emit(grid.StepEnroll, grid.LinkRunning, "")
	token, _, err := s.newToken(ctx, nil)
	if err != nil {
		return store.Host{}, l.fail(grid.StepEnroll, "Could not create an enrollment token", err)
	}
	tokenHash := hashCode(token)
	enrollCmd := agentBinaryPath + " enroll --hub " + s.hubURL() + " --token " + token +
		" --ca-fingerprint " + s.ca.Fingerprint() + " --shell-user " + req.User
	if err := runSudo(enrollCmd); err != nil {
		return store.Host{}, l.fail(grid.StepEnroll, "Enrollment failed: "+l.describe(err), err)
	}
	tmpUnit, err := l.upload(ctx, conn, []byte(unitFile))
	if err != nil {
		return store.Host{}, l.fail(grid.StepEnroll, "Upload failed: "+l.describe(err), err)
	}
	if err := runSudo("sh -c 'install -m 0644 " + tmpUnit + " " + agentUnitPath +
		" && systemctl daemon-reload && systemctl enable --now grid-agent'"); err != nil {
		return store.Host{}, l.fail(grid.StepEnroll, "Starting the agent failed: "+l.describe(err), err)
	}
	host, err := l.finishHost(ctx, tokenHash, req.Address, display)
	if err != nil {
		return store.Host{}, l.fail(grid.StepEnroll, "The agent did not report back to the hub", err)
	}
	l.cleanup(ctx, conn)
	_ = conn.Close() // SSH is no longer needed; credentials are discarded
	l.emit(grid.StepEnroll, grid.LinkDone, "mTLS · valid 1 year · SSH closed")

	// --- online
	l.emit(grid.StepOnline, grid.LinkRunning, "")
	if s.waitOn != nil {
		wctx, cancel := context.WithTimeout(ctx, s.onlineTimeout)
		defer cancel()
		if err := s.waitOn(wctx, grid.HostID(host.ID)); err != nil {
			return store.Host{}, l.fail(grid.StepOnline, "The agent did not come online within "+strconv.Itoa(int(s.onlineTimeout/time.Second))+" s", err)
		}
	}
	l.emit(grid.StepOnline, grid.LinkDone, "First sync running")
	return host, nil
}

// finishHost looks up the host created by the agent's enrollment and applies
// the operator's display name and the address used for SSH.
func (l *linkRun) finishHost(ctx context.Context, tokenHash, address, display string) (store.Host, error) {
	st := l.s.st
	tok, err := st.GetEnrollToken(ctx, tokenHash)
	if err != nil {
		return store.Host{}, err
	}
	if tok.HostID == "" {
		return store.Host{}, errors.New("enrollment token was not used")
	}
	h, err := st.GetHost(ctx, tok.HostID)
	if err != nil {
		return store.Host{}, err
	}
	if display != "" {
		if err := st.SetHostDisplayName(ctx, h.ID, display); err != nil {
			return store.Host{}, err
		}
	}
	if err := st.UpdateHostStatus(ctx, h.ID, store.HostStatus{
		Address: address, OS: h.OS, Arch: h.Arch, AgentVersion: h.AgentVersion,
		MAC: h.MAC, Capabilities: h.Capabilities, LastSeenAt: h.LastSeenAt,
	}); err != nil {
		return store.Host{}, err
	}
	return st.GetHost(ctx, h.ID)
}

// upload copies data into a fresh mktemp file on the host and returns its path.
func (l *linkRun) upload(ctx context.Context, conn SSHConn, data []byte) (string, error) {
	out, err := conn.Run(ctx, "mktemp", nil)
	if err != nil {
		return "", err
	}
	path := strings.TrimSpace(string(out))
	if !tmpPathRE.MatchString(path) {
		return "", errors.New("unexpected mktemp output")
	}
	l.tmp = append(l.tmp, path)
	if _, err := conn.Run(ctx, "cat > "+path, bytes.NewReader(data)); err != nil {
		return "", err
	}
	return path, nil
}

// cleanup deletes the temp files created on the host (best effort, idempotent).
func (l *linkRun) cleanup(ctx context.Context, conn SSHConn) {
	if len(l.tmp) == 0 {
		return
	}
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_, _ = conn.Run(cctx, "rm -f "+strings.Join(l.tmp, " "), nil)
	l.tmp = nil
}

func archFromUname(s string) (string, bool) {
	switch strings.TrimSpace(s) {
	case "aarch64", "arm64":
		return "arm64", true
	case "x86_64", "amd64":
		return "amd64", true
	}
	return "", false
}

// distroName returns a short name like "Debian 12" from /etc/os-release.
func distroName(osRelease string) string {
	kv := map[string]string{}
	for _, line := range strings.Split(osRelease, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok {
			kv[k] = strings.Trim(v, `"'`)
		}
	}
	name := strings.TrimSpace(strings.TrimSuffix(kv["NAME"], " GNU/Linux"))
	switch {
	case name != "" && kv["VERSION_ID"] != "":
		return cleanLine(name+" "+kv["VERSION_ID"], 60)
	case kv["PRETTY_NAME"] != "":
		return cleanLine(kv["PRETTY_NAME"], 60)
	}
	return "Linux"
}
