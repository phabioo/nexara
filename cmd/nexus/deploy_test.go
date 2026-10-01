package main

// Consistency checks for the packaging files under deploy/ (install.sh, the
// maintainer scripts, the systemd units). They read the files from the
// repository, so they live next to the command that those files install.

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/phabioo/nexara/internal/config"
)

func deployFile(t *testing.T, rel ...string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(append([]string{"..", "..", "deploy"}, rel...)...))
	if err != nil {
		t.Fatal(err)
	}
	// .gitattributes pins LF; tolerate a CRLF checkout on Windows.
	return strings.ReplaceAll(string(data), "\r\n", "\n")
}

// heredoc returns the body of the first here-document that starts after marker.
func heredoc(t *testing.T, script, marker, delim string) string {
	t.Helper()
	_, rest, ok := strings.Cut(script, marker)
	if !ok {
		t.Fatalf("marker %q not found", marker)
	}
	_, rest, _ = strings.Cut(rest, "\n")
	body, _, ok := strings.Cut(rest, "\n"+delim+"\n")
	if !ok {
		t.Fatalf("heredoc end %q not found", delim)
	}
	return body + "\n"
}

func TestInstallScriptEmbedsReleaseKey(t *testing.T) {
	want := deployFile(t, "keys", "nexara-release.pub")
	got := heredoc(t, deployFile(t, "install.sh"), "<<'NEXARA_RELEASE_PUBKEY'", "NEXARA_RELEASE_PUBKEY")
	if got != want {
		t.Fatalf("install.sh embeds a different key than deploy/keys/nexara-release.pub:\n got %q\nwant %q", got, want)
	}
}

func TestPostinstConfigsLoad(t *testing.T) {
	post := deployFile(t, "debian", "postinst")
	dir := t.TempDir()

	hubYAML := heredoc(t, post, `cat >"$NEXUS_CONF" <<CONF`, "CONF")
	hubYAML = strings.NewReplacer("$(host_name)", "frpi5", "$(time_zone)", "Europe/Berlin").Replace(hubYAML)
	hubPath := filepath.Join(dir, "nexus.yaml")
	if err := os.WriteFile(hubPath, []byte(hubYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	hub, err := config.LoadHub(hubPath)
	if err != nil {
		t.Fatalf("generated nexus.yaml does not load: %v\n%s", err, hubYAML)
	}
	want := config.DefaultHub()
	want.Hub.Name, want.Hub.Timezone = "frpi5", "Europe/Berlin"
	if hub != want {
		t.Fatalf("generated nexus.yaml differs from the defaults:\n got %+v\nwant %+v", hub, want)
	}

	agentYAML := heredoc(t, post, `cat >"$AGENT_CONF" <<CONF`, "CONF")
	agentYAML = strings.ReplaceAll(agentYAML, "$shell_user", "pi")
	agentPath := filepath.Join(dir, "agent.yaml")
	if err := os.WriteFile(agentPath, []byte(agentYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	ag, err := config.LoadAgent(agentPath)
	if err != nil {
		t.Fatalf("generated agent.yaml does not load: %v\n%s", err, agentYAML)
	}
	if ag.Hub.URL != "wss://127.0.0.1:8443/grid/connect" || ag.Shell.User != "pi" ||
		ag.Enroll.TokenFile != "/var/lib/nexus/self-enroll.token" || !ag.Capabilities.Shell {
		t.Fatalf("generated agent.yaml: %+v", ag)
	}
}

func TestNexusUnit(t *testing.T) {
	unit := deployFile(t, "systemd", "nexus.service")
	for _, want := range []string{
		"User=nexus", "Group=nexus",
		"ExecStart=/usr/bin/nexus serve --config /etc/nexus/nexus.yaml",
		"StateDirectory=nexus", "RuntimeDirectory=nexus", "RuntimeDirectoryMode=0750", "ConfigurationDirectory=nexus",
		"NoNewPrivileges=true", "ProtectSystem=strict", "ProtectHome=true", "PrivateTmp=true", "PrivateDevices=true",
		"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6", "CapabilityBoundingSet=\n",
		"ReadWritePaths=/var/lib/nexus /etc/nexus", "Restart=on-failure",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("nexus.service lacks %q", want)
		}
	}
	// Port 8443 needs no privileges; a capability would only widen the sandbox.
	if m := regexp.MustCompile(`(?m)^AmbientCapabilities=(.+)$`).FindString(unit); m != "" {
		t.Errorf("unexpected %s", m)
	}
}

func TestScriptsAreValidShell(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	for _, f := range [][]string{{"install.sh"}, {"debian", "postinst"}, {"debian", "prerm"}, {"debian", "postrm"}} {
		path := filepath.Join(append([]string{"..", "..", "deploy"}, f...)...)
		if out, err := exec.Command(sh, "-n", path).CombinedOutput(); err != nil {
			t.Errorf("%s: %v\n%s", path, err, out)
		}
	}
}
