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
	"github.com/phabioo/nexara/internal/hub/update"
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
		"SystemCallFilter=@system-service", "SystemCallErrorNumber=EPERM", "ProtectProc=invisible",
		"ProcSubset=pid", "MemoryDenyWriteExecute=true",
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

// A download cut off by a dropped connection must not execute a partial
// script: everything is inside main(), which is called on the last line.
func TestInstallShIsWrappedInMain(t *testing.T) {
	lines := strings.Split(strings.TrimRight(deployFile(t, "install.sh"), "\n"), "\n")
	if last := lines[len(lines)-1]; last != `main "$@"` {
		t.Errorf("last line = %q, want main \"$@\"", last)
	}
	start := -1
	for i, l := range lines {
		if l == "main() {" {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatal("install.sh has no main() { ... } wrapper")
	}
	// Only comments, set -eu and the function header may precede main, so no
	// command runs before the whole file has been received.
	for _, l := range lines[:start] {
		if l != "" && !strings.HasPrefix(l, "#") && l != "set -eu" {
			t.Errorf("statement before main(): %q", l)
		}
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

// The root helper (decision #50): the path unit watches exactly the file the
// hub writes, the service runs the helper command, and the package ships,
// enables and removes both.
func TestUpdateUnits(t *testing.T) {
	path := deployFile(t, "systemd", "nexus-update.path")
	for _, want := range []string{
		"PathExists=" + update.DefaultDataDir + "/" + update.UpdatesDirName + "/" + update.RequestFile,
		"Unit=nexus-update.service",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(path, want) {
			t.Errorf("nexus-update.path lacks %q", want)
		}
	}

	svc := deployFile(t, "systemd", "nexus-update.service")
	for _, want := range []string{
		"Type=oneshot",
		"ExecStart=/usr/bin/nexus update-apply\n",
		"ConditionPathExists=" + update.DefaultDataDir + "/" + update.UpdatesDirName + "/" + update.RequestFile,
		"StateDirectory=" + filepath.Base(update.DefaultStateDir),
		"PrivateNetwork=true", "PrivateTmp=true", "ProtectHome=true", "NoNewPrivileges=true",
		"RestrictAddressFamilies=AF_UNIX\n", "ProtectKernelModules=true",
	} {
		if !strings.Contains(svc, want) {
			t.Errorf("nexus-update.service lacks %q", want)
		}
	}
	// It must run as root (apt) and must not be enabled on its own.
	for _, bad := range []string{"\nUser=", "\nGroup=", "[Install]", "ProtectSystem="} {
		if strings.Contains(svc, bad) {
			t.Errorf("nexus-update.service contains %q", bad)
		}
	}
	if update.DefaultStateDir != "/var/lib/"+filepath.Base(update.DefaultStateDir) {
		t.Errorf("state dir %s is not what StateDirectory= creates", update.DefaultStateDir)
	}
	// The hub may write the updates directory (ReadWritePaths of the hub unit).
	if hub := deployFile(t, "systemd", "nexus.service"); !strings.Contains(hub, "ReadWritePaths="+update.DefaultDataDir+" ") {
		t.Errorf("nexus.service does not allow writing %s", update.DefaultDataDir)
	}
}

func TestPackagingShipsAndEnablesTheUpdateUnits(t *testing.T) {
	pkg, err := os.ReadFile(filepath.Join("..", "..", "scripts", "package-deb.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, unit := range []string{"nexus-update.path", "nexus-update.service"} {
		if n := strings.Count(string(pkg), "deploy/systemd/"+unit); n < 2 { // required-file check + install
			t.Errorf("package-deb.sh mentions %s %d times, want the existence check and the install", unit, n)
		}
	}
	if !strings.Contains(deployFile(t, "debian", "postinst"), `activate nexus-update.path "$2"`) {
		t.Error("postinst does not enable nexus-update.path")
	}
	if !strings.Contains(deployFile(t, "debian", "prerm"), "stop_unit nexus-update.path") {
		t.Error("prerm does not stop nexus-update.path")
	}
	post := deployFile(t, "debian", "postrm")
	for _, want := range []string{"purge nexus.service grid-agent.service nexus-update.path", "/var/lib/nexus-update"} {
		if !strings.Contains(post, want) {
			t.Errorf("postrm lacks %q", want)
		}
	}
}

// install.sh keeps the verified package for the first update's rollback
// (decision #50) exactly where and how the root update helper looks for it.
func TestInstallShKeepsRollbackMaterial(t *testing.T) {
	script := deployFile(t, "install.sh")
	if !strings.Contains(script, "KEEP="+update.DefaultStateDir+"\n") {
		t.Errorf("install.sh does not keep the package under %s", update.DefaultStateDir)
	}
	for _, want := range []string{
		`install -m 0644 "$TMP/$DEB" "$TMP/SHA256SUMS" "$TMP/SHA256SUMS.sig" "$KEEP/installed.new/"`,
		`mv "$KEEP/installed.new" "$KEEP/installed"`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("install.sh lacks %q", want)
		}
	}
	// The copy follows a successful apt install, never precedes it.
	if strings.Index(script, "KEEP=") < strings.Index(script, "apt-get install -y \"$TMP/$DEB\"") {
		t.Error("rollback material is kept before the package is installed")
	}
}
