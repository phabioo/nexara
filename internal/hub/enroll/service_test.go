package enroll

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	agentenroll "github.com/phabioo/nexara/internal/agent/enroll"
	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/pki"
)

func TestCodeFormatAndAlphabet(t *testing.T) {
	re := regexp.MustCompile(`^GRID(-[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{4}){4}$`)
	seen := map[string]bool{}
	for i := 0; i < 500; i++ {
		c, err := randomCode()
		if err != nil {
			t.Fatal(err)
		}
		if !re.MatchString(c) {
			t.Fatalf("bad code %q", c)
		}
		if seen[c] {
			t.Fatalf("duplicate code %q", c)
		}
		seen[c] = true
	}
}

// The code shape is checked in four places: the hub's handler, the install
// script, the agent's flags and this generator. They must agree (S-10).
func TestCodeShapeIsInSyncEverywhere(t *testing.T) {
	// the script's grep pattern, rendered from the same alphabet
	script, err := renderInstallScript("frpi5.local", 8443, base64.StdEncoding.EncodeToString(make([]byte, 32)), strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`grep -Eq '(\^GRID[^']*)'`).FindSubmatch(script)
	if m == nil {
		t.Fatal("the install script does not validate the code")
	}
	scriptRE := regexp.MustCompile(string(m[1]))

	valid := []string{}
	for i := 0; i < 50; i++ {
		c, err := randomCode()
		if err != nil {
			t.Fatal(err)
		}
		valid = append(valid, c)
	}
	invalid := []string{
		"", "GRID-ABCD-EFGH", "GRID-ABCD-EFGH-JKMN", "GRID-ABCD-EFGH-JKMN-PQRS-TUVW", "GRID-ABCD-EFGH-JKMN-PQR",
		"GRID-ABCD-EFGH-JKMN-PQR0", "GRID-ABCD-EFGH-JKMN-PQRI", "GRID-ABCD-EFGH-JKMN-PQRO",
		"GRID-ABCD-EFGH-JKMN-PQR1", "GRID-ABCD-EFGH-JKMN-PQRL", "GRIDABCDEFGHJKMNPQRS",
		"GRID-ABCD-EFGH-JKMN-PQRS; reboot",
	}
	for _, c := range valid {
		if !codeRE.MatchString(c) || !scriptRE.MatchString(c) {
			t.Errorf("valid code %q rejected (hub=%v script=%v)", c, codeRE.MatchString(c), scriptRE.MatchString(c))
		}
		if got, err := agentenroll.NormalizeCode(strings.ToLower(" " + c + " ")); err != nil || got != c {
			t.Errorf("agent rejects %q: %q %v", c, got, err)
		}
	}
	for _, c := range invalid {
		if codeRE.MatchString(c) || scriptRE.MatchString(c) {
			t.Errorf("invalid code %q accepted (hub=%v script=%v)", c, codeRE.MatchString(c), scriptRE.MatchString(c))
		}
		if _, err := agentenroll.NormalizeCode(c); err == nil {
			t.Errorf("agent accepts %q", c)
		}
	}
}

func TestNewEnrollCode(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	code, err := e.svc.NewEnrollCode(ctx, grid.Actor{Operator: "7"}, grid.EnrollOptions{Capabilities: []string{"monitoring", "shell", "monitoring"}})
	if err != nil {
		t.Fatal(err)
	}
	if want := e.clock.Now().Add(15 * time.Minute); !code.Expires.Equal(want) {
		t.Fatalf("expires %v, want %v", code.Expires, want)
	}

	// The command pins the server key and carries the code.
	certPEM, _ := os.ReadFile(filepath.Join(e.dir, "pki", pki.ServerCertFile))
	cert, err := pki.ParseCertPEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	want := "curl -fsSL --insecure --pinnedpubkey sha256//" + base64.StdEncoding.EncodeToString(sum[:]) +
		" https://frpi5.local:8443/grid/install.sh | sudo sh -s -- " + code.Code
	if code.Command != want {
		t.Fatalf("command\n got %q\nwant %q", code.Command, want)
	}

	// Only the hash is stored, together with the capabilities (deduplicated).
	if _, err := e.st.GetEnrollToken(ctx, code.Code); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("plain code must not be a key in the store: %v", err)
	}
	row, err := e.st.GetEnrollToken(ctx, hashCode(code.Code))
	if err != nil {
		t.Fatal(err)
	}
	if row.TokenHash == code.Code || strings.Contains(row.TokenHash, "GRID") {
		t.Fatal("token stored in plain")
	}
	if len(row.Capabilities) != 2 || row.Capabilities[0] != "monitoring" || row.Capabilities[1] != "shell" {
		t.Fatalf("capabilities %v", row.Capabilities)
	}
	if !row.ExpiresAt.Equal(code.Expires) {
		t.Fatalf("stored expiry %v", row.ExpiresAt)
	}

	// Audited without the code.
	audit := e.auditActions()
	if len(audit) != 1 || audit[0].Action != "enroll.code" || audit[0].Result != store.AuditOK || audit[0].User != "7" {
		t.Fatalf("audit %+v", audit)
	}
	if strings.Contains(audit[0].Detail, code.Code) || strings.Contains(audit[0].Detail, "GRID") {
		t.Fatalf("code in audit detail: %q", audit[0].Detail)
	}
}

func TestNewEnrollCodeNilCapsAndInvalid(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	c, err := e.svc.NewEnrollCode(ctx, grid.Actor{Operator: "1"}, grid.EnrollOptions{})
	if err != nil {
		t.Fatal(err)
	}
	row, _ := e.st.GetEnrollToken(ctx, hashCode(c.Code))
	if row.Capabilities != nil {
		t.Fatalf("nil capabilities must stay nil (agent defaults), got %v", row.Capabilities)
	}
	if _, err := e.svc.NewEnrollCode(ctx, grid.Actor{}, grid.EnrollOptions{Capabilities: []string{"root-shell"}}); !errors.Is(err, grid.ErrInvalidArgument) {
		t.Fatalf("got %v", err)
	}
	c2, err := e.svc.NewEnrollCode(ctx, grid.Actor{}, grid.EnrollOptions{Capabilities: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	row, _ = e.st.GetEnrollToken(ctx, hashCode(c2.Code))
	if row.Capabilities == nil || len(row.Capabilities) != 0 {
		t.Fatalf("empty list means all off, got %#v", row.Capabilities)
	}
}

func TestNormalizeCode(t *testing.T) {
	if hashCode(" grid-abcd-efgh\n") != hashCode("GRID-ABCD-EFGH") {
		t.Fatal("codes must be compared case-insensitively and trimmed")
	}
}

func TestNewValidation(t *testing.T) {
	tests := []struct {
		name string
		mod  func(*Options)
	}{
		{"address with quote", func(o *Options) { o.HubAddress = "x'; rm -rf /; '" }},
		{"address with space", func(o *Options) { o.HubAddress = "frpi5 local" }},
		{"address with slash", func(o *Options) { o.HubAddress = "frpi5.local/evil" }},
		{"address with newline", func(o *Options) { o.HubAddress = "frpi5\nx" }},
		{"empty address", func(o *Options) { o.HubAddress = "" }},
		{"ipv6", func(o *Options) { o.HubAddress = "::1" }},
		{"double dot", func(o *Options) { o.HubAddress = "a..b" }},
		{"port zero", func(o *Options) { o.Port = 0 }},
		{"port too big", func(o *Options) { o.Port = 70000 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			st, _ := store.Open(filepath.Join(dir, "x.db"))
			defer st.Close()
			ca, _ := pki.LoadOrCreateCA(dir)
			o := Options{Store: st, CA: ca, ServerCertFile: filepath.Join(dir, "server.pem"), HubAddress: "frpi5.local", Port: 8443, DataDir: dir}
			tt.mod(&o)
			if _, err := New(o); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestRenderInstallScript(t *testing.T) {
	pin := base64.StdEncoding.EncodeToString(make([]byte, 32))
	fp := strings.Repeat("ab", 32)
	script, err := renderInstallScript("frpi5.local", 8443, pin, fp)
	if err != nil {
		t.Fatal(err)
	}
	s := string(script)
	for _, want := range []string{
		"#!/bin/sh", "set -eu",
		"HUB_ADDR='frpi5.local'", "HUB_PORT='8443'", "PIN='sha256//" + pin + "'", "CA_FP='" + fp + "'",
		`--pinnedpubkey "$PIN"`, `/grid/download/linux/$ARCH`,
		"aarch64 | arm64) ARCH=arm64", "x86_64 | amd64) ARCH=amd64",
		`grid-agent enroll --hub "https://$HUB_ADDR:$HUB_PORT" --token-file "$TOKFILE" --ca-fingerprint "$CA_FP" --shell-user "${SUDO_USER:-}"`,
		"invalid enrollment code",
		"systemctl daemon-reload", "systemctl enable --now grid-agent",
		"/usr/local/bin/grid-agent", "id -u",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q", want)
		}
	}
	if !strings.Contains(s, "\n"+unitFile+"NEXARA_UNIT\n") {
		t.Error("script does not embed the unit file verbatim")
	}
	if strings.Contains(s, "{{") {
		t.Error("unrendered template action")
	}
	// The code never appears on the enroll command line (S-19).
	if strings.Contains(s, `--token "$CODE"`) {
		t.Error("the script passes the code on the command line")
	}
}

func TestRenderInstallScriptRejectsInjection(t *testing.T) {
	pin := base64.StdEncoding.EncodeToString(make([]byte, 32))
	fp := strings.Repeat("ab", 32)
	tests := []struct {
		name, addr, pin, fp string
		port                int
	}{
		{"address quote", "a'; touch /tmp/x; '", pin, fp, 8443},
		{"address subshell", "$(id)", pin, fp, 8443},
		{"address backtick", "`id`", pin, fp, 8443},
		{"pin quote", "frpi5.local", "abc'; id; '", fp, 8443},
		{"fingerprint quote", "frpi5.local", pin, "x'; id; '", 8443},
		{"port 0", "frpi5.local", pin, fp, 0},
	}
	for _, tt := range tests {
		if _, err := renderInstallScript(tt.addr, tt.port, tt.pin, tt.fp); err == nil {
			t.Errorf("%s: accepted", tt.name)
		}
	}
}

func TestUnitFileMatchesDeployFile(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "deploy", "systemd", "grid-agent.service"))
	if err != nil {
		t.Fatal(err)
	}
	// .gitattributes pins LF; tolerate a CRLF checkout on Windows.
	got := strings.ReplaceAll(string(data), "\r\n", "\n")
	if got != unitFile {
		t.Fatal("unitFile differs from deploy/systemd/grid-agent.service; keep them identical")
	}
}

func TestWriteSelfLinkToken(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	path := filepath.Join(e.dir, "self-enroll.token")
	if err := e.svc.WriteSelfLinkToken(ctx, path, []string{"monitoring"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Token         string `json:"token"`
		CAFingerprint string `json:"ca_fingerprint"`
		Hub           string `json:"hub"`
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.CAFingerprint != e.ca.Fingerprint() || got.Hub != "https://127.0.0.1:8443" || got.Token == "" {
		t.Fatalf("%+v", got)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o640 {
			t.Fatalf("mode %v", fi.Mode().Perm())
		}
	}
	caps, err := e.st.ConsumeEnrollToken(ctx, hashCode(got.Token), e.clock.Now())
	if err != nil {
		t.Fatalf("token not usable: %v", err)
	}
	if len(caps) != 1 || caps[0] != "monitoring" {
		t.Fatalf("caps %v", caps)
	}
	// 15 minute lifetime
	path2 := filepath.Join(e.dir, "second.token")
	if err := e.svc.WriteSelfLinkToken(ctx, path2, nil); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(path2)
	_ = json.Unmarshal(data, &got)
	e.clock.Advance(16 * time.Minute)
	if _, err := e.st.ConsumeEnrollToken(ctx, hashCode(got.Token), e.clock.Now()); !errors.Is(err, store.ErrTokenInvalid) {
		t.Fatalf("expired token accepted: %v", err)
	}
	if err := e.svc.WriteSelfLinkToken(ctx, path, []string{"bogus"}); !errors.Is(err, grid.ErrInvalidArgument) {
		t.Fatalf("got %v", err)
	}
}

func TestIPLimiter(t *testing.T) {
	l := newIPLimiter(3, time.Minute)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		if !l.allow("a", now) {
			t.Fatal("blocked early")
		}
	}
	if l.allow("a", now.Add(10*time.Second)) {
		t.Fatal("4th attempt allowed")
	}
	if !l.allow("b", now) {
		t.Fatal("other key affected")
	}
	if !l.allow("a", now.Add(61*time.Second)) {
		t.Fatal("window did not slide")
	}
}
