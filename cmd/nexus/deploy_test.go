package main

// Consistency checks for the packaging files under deploy/ (install.sh, the
// maintainer scripts, the systemd units). They read the files from the
// repository, so they live next to the command that those files install.

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
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

	hubYAML := heredoc(t, post, `cat >"$hub_tmp/nexus.yaml" <<CONF`, "CONF")
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

// Security review B-01: the hub user owns /etc/nexus and can plant a symlink at
// nexus.yaml, so postinst (root) must never chown, chmod or write an existing
// nexus.yaml. These tests check the script text and then run the real script,
// with its absolute paths moved into a temp tree and the system tools stubbed.
func TestPostinstNeverTouchesAnExistingHubConfig(t *testing.T) {
	post := deployFile(t, "debian", "postinst")
	for _, bad := range []string{`chown "$NEXUS_USER:$NEXUS_USER" "$NEXUS_CONF"`, `chmod 0640 "$NEXUS_CONF"`, `>"$NEXUS_CONF"`, "totp_required"} {
		if strings.Contains(post, bad) {
			t.Errorf("postinst contains %q", bad)
		}
	}
	for _, want := range []string{
		`if [ ! -e "$NEXUS_CONF" ] && [ ! -L "$NEXUS_CONF" ]; then`,
		`install -m 0640 -o "$NEXUS_USER" -g "$NEXUS_USER" "$hub_tmp/nexus.yaml" "$NEXUS_CONF"`,
		"hub_tmp=$(mktemp -d)",
	} {
		if !strings.Contains(post, want) {
			t.Errorf("postinst lacks %q", want)
		}
	}
}

// runPostinst runs `postinst configure` with /etc, /var/lib and /run moved below
// root. Tools that need real root or a running system are stubbed; install(1)
// is the real one without -o/-g (the tests do not run as root).
func runPostinst(t *testing.T, root string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX shell")
	}
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"sh", "cat", "cut", "tr", "head", "sed", "readlink", "mktemp", "rm", "rmdir", "mkdir", "chmod", "cp", "mv", "dirname", "basename"} {
		p, err := exec.LookPath(tool)
		if err != nil {
			t.Skipf("no %s", tool)
		}
		if err := os.Symlink(p, filepath.Join(bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	realInstall, err := exec.LookPath("install")
	if err != nil {
		t.Skip("no install")
	}
	stubs := map[string]string{
		"install": "#!/bin/sh\n" + `args=; skip=
for a in "$@"; do
	if [ -n "$skip" ]; then skip=; continue; fi
	case "$a" in -o | -g) skip=1; continue ;; esac
	args="$args '$a'"
done
eval "exec ` + realInstall + ` $args"
`,
		"getent":   "#!/bin/sh\ncase \"$1\" in passwd) echo \"$2:x:1000:1000::/home/$2:/bin/sh\" ;; group) echo 'sudo:x:27:pi' ;; esac\n",
		"hostname": "#!/bin/sh\necho frpi5\n",
		"adduser":  "#!/bin/sh\nexit 0\n",
		// The tests do not run as root; chown is a no-op, and every call is
		// visible through the paths it was given.
		"chown": "#!/bin/sh\nexit 0\n",
	}
	for name, body := range stubs {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	script := deployFile(t, "debian", "postinst")
	script = strings.NewReplacer("/etc/", root+"/etc/", "/var/lib/", root+"/var/lib/", "/run/systemd/system", root+"/run/systemd/system",
		"/usr/share/zoneinfo", root+"/zoneinfo").Replace(script)
	for _, d := range []string{"etc/nexus", "etc/grid-agent", "etc/systemd/system", "var/lib/nexus", "var/lib/grid-agent"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(root, "postinst")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(filepath.Join(bin, "sh"), path, "configure")
	cmd.Env = []string{"PATH=" + bin, "TMPDIR=" + root, "HOME=" + root}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("postinst: %v\n%s", err, out)
	}
}

func TestPostinstCreatesTheHubConfigOnlyWhenAbsent(t *testing.T) {
	const victimText = "root-only secret\n"
	cases := []struct {
		name   string
		plant  func(t *testing.T, conf, victim string)
		create bool // a new regular nexus.yaml is expected
		keep   func(t *testing.T, conf string)
	}{
		{name: "fresh install", create: true, plant: func(*testing.T, string, string) {}},
		{name: "symlink to an existing file", plant: func(t *testing.T, conf, victim string) {
			if err := os.Symlink(victim, conf); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "dangling symlink", plant: func(t *testing.T, conf, victim string) {
			if err := os.Symlink(victim+".new", conf); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "existing regular file keeps content and mode", plant: func(t *testing.T, conf, _ string) {
			if err := os.WriteFile(conf, []byte("hub:\n  name: mine\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, keep: func(t *testing.T, conf string) {
			b, _ := os.ReadFile(conf)
			fi, _ := os.Stat(conf)
			if string(b) != "hub:\n  name: mine\n" || fi.Mode().Perm() != 0o600 {
				t.Errorf("existing nexus.yaml changed: %q %v", b, fi.Mode())
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			// runPostinst creates the directories; plant first needs them.
			conf := filepath.Join(root, "etc", "nexus", "nexus.yaml")
			victim := filepath.Join(root, "var", "lib", "victim")
			if err := os.MkdirAll(filepath.Dir(conf), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(victim), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(victim, []byte(victimText), 0o600); err != nil {
				t.Fatal(err)
			}
			c.plant(t, conf, victim)
			runPostinst(t, root)

			// Whatever was planted, the victim keeps content and mode and no file is created through a link.
			if b, _ := os.ReadFile(victim); string(b) != victimText {
				t.Errorf("victim file changed: %q", b)
			}
			if fi, _ := os.Stat(victim); fi.Mode().Perm() != 0o600 {
				t.Errorf("victim mode = %v, want 0600", fi.Mode().Perm())
			}
			if _, err := os.Lstat(victim + ".new"); err == nil {
				t.Error("a file was created through the dangling link")
			}
			fi, err := os.Lstat(conf)
			if err != nil {
				t.Fatal(err)
			}
			if c.create {
				if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o640 {
					t.Errorf("nexus.yaml = %v, want a regular 0640 file", fi.Mode())
				}
				if _, err := config.LoadHub(conf); err != nil {
					t.Errorf("generated nexus.yaml does not load: %v", err)
				}
			}
			if c.keep != nil {
				c.keep(t, conf)
			}
			if !c.create && c.keep == nil && fi.Mode()&os.ModeSymlink == 0 {
				t.Errorf("the planted link was replaced: %v", fi.Mode())
			}
			if left, _ := filepath.Glob(filepath.Join(root, "tmp.*")); len(left) != 0 {
				t.Errorf("temp files left behind: %v", left)
			}
		})
	}
}
