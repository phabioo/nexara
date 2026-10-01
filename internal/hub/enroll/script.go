package enroll

import (
	"bytes"
	"errors"
	"regexp"
	"strconv"
	"text/template"
)

// unitFile is the systemd unit installed on new hosts. It must equal
// deploy/systemd/grid-agent.service byte for byte (enforced by a test).
const unitFile = `# Nexara Grid Agent (draft)
# Runs as root because it manages packages, services and power.
# It only exposes a fixed set of actions; the shell drops to the configured user
# (e.g. pi), whose home directory must stay writable, so ProtectHome is not set.
# No further sandboxing on purpose (see docs/decisions.md #30): apt and power need
# a writable system, and NoNewPrivileges would break sudo inside Nexara Shell.
[Unit]
Description=Nexara Grid Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/grid-agent run --config /etc/grid-agent/agent.yaml
Restart=always
RestartSec=5
StateDirectory=grid-agent
ConfigurationDirectory=grid-agent
PrivateTmp=true

[Install]
WantedBy=multi-user.target
`

const (
	agentBinaryPath = "/usr/local/bin/grid-agent"
	agentUnitPath   = "/etc/systemd/system/grid-agent.service"
)

// installScript is the POSIX sh installer served at /grid/install.sh. All
// substituted values are validated by renderInstallScript; none can contain
// quotes, spaces or shell metacharacters.
//
// Commands read /dev/null on purpose: the script itself arrives on stdin
// (curl | sudo sh), and a command that reads stdin would swallow it.
var installScript = template.Must(template.New("install.sh").Parse(`#!/bin/sh
# Nexara Grid Agent installer, served by the hub.
# Usage: curl -fsSL --insecure --pinnedpubkey sha256//<key> https://<hub>/grid/install.sh | sudo sh -s -- <code>
set -eu

HUB_ADDR='{{.Address}}'
HUB_PORT='{{.Port}}'
PIN='sha256//{{.Pin}}'
CA_FP='{{.CAFingerprint}}'
CODE="$(printf '%s' "${1:-}" | tr 'a-z' 'A-Z')"

die() {
	echo "grid-agent installer: $*" >&2
	exit 1
}

[ "$(id -u)" -eq 0 ] || die "must run as root: curl ... | sudo sh -s -- <code>"
[ -n "$CODE" ] || die "missing enrollment code"
printf '%s\n' "$CODE" | LC_ALL=C grep -Eq '^GRID(-[{{.CodeClass}}]{4}){4}$' || die "invalid enrollment code (expected GRID-XXXX-XXXX-XXXX-XXXX)"
[ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ] || die "run this through sudo from your normal user (the shell runs as that user, never as root)"
[ "$(uname -s)" = Linux ] || die "this installer supports Linux only"
command -v curl >/dev/null 2>&1 || die "curl is required"
command -v systemctl >/dev/null 2>&1 || die "systemd is required"

case "$(uname -m)" in
aarch64 | arm64) ARCH=arm64 ;;
x86_64 | amd64) ARCH=amd64 ;;
*) die "unsupported architecture: $(uname -m)" ;;
esac

TMP="$(mktemp)"
TOKFILE="$(mktemp)"
trap 'rm -f "$TMP" "$TOKFILE"' EXIT
# The code goes through a 0600 file, not the enroll command line.
printf '%s\n' "$CODE" >"$TOKFILE"

echo "Downloading Grid Agent (linux/$ARCH) from the hub ..."
curl -fsSL --insecure --pinnedpubkey "$PIN" -o "$TMP" "https://$HUB_ADDR:$HUB_PORT/grid/download/linux/$ARCH" </dev/null

systemctl stop grid-agent </dev/null >/dev/null 2>&1 || true
install -m 0755 "$TMP" /usr/local/bin/grid-agent </dev/null

echo "Enrolling ..."
/usr/local/bin/grid-agent enroll --hub "https://$HUB_ADDR:$HUB_PORT" --token-file "$TOKFILE" --ca-fingerprint "$CA_FP" --shell-user "${SUDO_USER:-}" </dev/null

cat >/etc/systemd/system/grid-agent.service <<'NEXARA_UNIT'
{{.Unit}}NEXARA_UNIT
chmod 0644 /etc/systemd/system/grid-agent.service
systemctl daemon-reload </dev/null
systemctl enable --now grid-agent </dev/null

echo "Grid Agent installed and started."
`))

type scriptData struct {
	Address, Port, Pin, CAFingerprint, Unit string
	CodeClass                               string // characters allowed in an enrollment code
}

var (
	pinRE = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)
	fpRE  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// renderInstallScript renders the installer. It re-validates every value so a
// bug elsewhere can never turn into shell injection.
func renderInstallScript(address string, port int, pin, caFingerprint string) ([]byte, error) {
	if !validAddress(address) || port < 1 || port > 65535 || !pinRE.MatchString(pin) || !fpRE.MatchString(caFingerprint) {
		return nil, errors.New("enroll: refusing to render install script with invalid values")
	}
	var buf bytes.Buffer
	err := installScript.Execute(&buf, scriptData{
		Address: address, Port: strconv.Itoa(port), Pin: pin, CAFingerprint: caFingerprint, Unit: unitFile, CodeClass: codeAlphabet,
	})
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
