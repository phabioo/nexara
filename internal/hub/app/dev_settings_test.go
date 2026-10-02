package app

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/phabioo/nexara/internal/hub/auth"
	"github.com/phabioo/nexara/internal/hub/demo"
	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/protocol"
)

// signIn signs the demo operator in and returns the CSRF token of the session.
func (d *devProc) signIn() string {
	d.t.Helper()
	u, _ := url.Parse(d.base)
	var pre string
	d.get("/login")
	for _, c := range d.client.Jar.Cookies(u) {
		if c.Name == auth.CSRFCookieName {
			pre = c.Value
		}
	}
	resp, err := d.client.PostForm(d.base+"/login", url.Values{"csrf_token": {pre}, "operator_id": {DevOperator}, "passphrase": {DevPassphrase}})
	if err != nil {
		d.t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		d.t.Fatalf("sign-in: %d", resp.StatusCode)
	}
	return ""
}

func (d *devProc) page(path string) (string, string) {
	d.t.Helper()
	resp := d.get(path)
	b, _ := io.ReadAll(resp.Body)
	body := string(b)
	m := regexp.MustCompile(`<meta name="csrf-token" content="([^"]+)"`).FindStringSubmatch(body)
	csrf := ""
	if m != nil {
		csrf = m[1]
	}
	if resp.StatusCode != http.StatusOK {
		d.t.Fatalf("GET %s = %d", path, resp.StatusCode)
	}
	return body, csrf
}

func TestDevSettings(t *testing.T) {
	d := startDev(t, true)
	d.signIn()
	body, csrf := d.page("/settings")
	for _, want := range []string{
		">Operators<", ">Security<", ">Updates<", ">Backup<", "Hosts &amp; capabilities", ">Certificates<", ">Diagnostics<", ">Audit log<",
		"Hub &#43; agent", "frpi5.local", "Hub log", "Upload update file",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("settings page lacks %q", want)
		}
	}
	// The demo cannot restart itself, so it offers no restore.
	if strings.Contains(body, "/settings/backup/restore") {
		t.Error("restore is offered in the demo")
	}
	// The demo log has its sample lines.
	logBody := func() string {
		req, _ := http.NewRequest(http.MethodGet, d.base+"/settings/logs/hub", nil)
		req.Header.Set("HX-Request", "true")
		resp, err := d.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}()
	if !strings.Contains(logBody, "agent connected") || !strings.Contains(logBody, "is-error") {
		t.Errorf("demo log = %s", logBody)
	}

	// Capabilities can be switched in the demo like in the real grid.
	post := func(path string, form url.Values) (int, string) {
		req, _ := http.NewRequest(http.MethodPost, d.base+path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-CSRF-Token", csrf)
		req.Header.Set("HX-Request", "true")
		resp, err := d.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, out := post("/settings/hosts/pi3-dns/capabilities/shell", url.Values{"enabled": {"false"}}); code != http.StatusOK || !strings.Contains(out, "pi3-dns | Shell off") {
		t.Fatalf("switch shell off: %d %s", code, out)
	}
	if code, _ := post("/settings/hosts/pi3-dns/capabilities/power", url.Values{"enabled": {"false"}}); code != http.StatusNotFound {
		t.Errorf("power is not a switch: %d", code)
	}
	if code, out := post("/settings/backup/run", nil); code != http.StatusOK || !strings.Contains(out, "Backed up") {
		t.Errorf("backup: %d %s", code, out)
	}
	if code, out := post("/settings/updates/check", nil); code != http.StatusConflict || !strings.Contains(out, "Turn on the GitHub check first.") {
		t.Errorf("check while off: %d %s", code, out)
	}
	// With the check on, the demo still makes no outbound connection: the check fails visibly.
	post("/settings/updates/config", url.Values{"check_github": {"true"}})
	if code, out := post("/settings/updates/check", nil); code != http.StatusBadGateway || !strings.Contains(out, "GitHub could not be reached") {
		t.Errorf("check in the demo: %d %s", code, out)
	}
	if code, out := post("/settings/certs/pi5-media/renew", nil); code != http.StatusOK || !strings.Contains(out, "new certificate requested") {
		t.Errorf("renew: %d %s", code, out)
	}
	if code, _ := post("/settings/certs/pi4/renew", nil); code != http.StatusConflict {
		t.Errorf("renew of an offline host: %d", code)
	}
	if err := d.stop(); err != nil {
		t.Fatalf("RunDev = %v", err)
	}
}

func TestDevCapHub(t *testing.T) {
	hub := demo.New(demo.Options{TimeScale: 0.001})
	defer hub.Close()
	st := openStore(t, t.TempDir())
	log, _ := testLogger()
	dh := newDevCapHub(hub, st, log, time.Now)
	ctx := context.Background()
	hosts := dh.Hosts()
	if len(hosts) == 0 {
		t.Fatal("no demo hosts")
	}
	id := hosts[0].ID
	actor := grid.Actor{Operator: "demo"}

	for name, tc := range map[string]struct {
		id   grid.HostID
		capa string
		want error
	}{
		"unknown host": {"nope", protocol.CapShell, grid.ErrHostNotFound},
		"monitoring":   {id, protocol.CapMonitoring, grid.ErrInvalidArgument},
		"unknown":      {id, "root", grid.ErrInvalidArgument},
		"not offered":  {id, protocol.CapDocker, grid.ErrUnsupported},
	} {
		if err := dh.SetCapability(ctx, actor, tc.id, tc.capa, false); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}

	if err := dh.SetCapability(ctx, actor, id, protocol.CapShell, false); err != nil {
		t.Fatal(err)
	}
	info, _ := dh.Host(id)
	if info.HasCapability(protocol.CapShell) || len(info.DisabledCapabilities) != 1 || info.DisabledCapabilities[0] != protocol.CapShell {
		t.Fatalf("info = %+v", info)
	}
	if snap, _ := dh.Snapshot(id); snap.Host.HasCapability(protocol.CapShell) {
		t.Error("the snapshot still offers the shell")
	}
	if _, err := dh.OpenShell(ctx, actor, id, 80, 24); !errors.Is(err, grid.ErrCapabilityDisabled) {
		t.Errorf("OpenShell: %v", err)
	}
	if err := dh.SetCapability(ctx, actor, id, protocol.CapPackages, false); err != nil {
		t.Fatal(err)
	}
	if _, err := dh.StartJob(ctx, actor, id, grid.JobSpec{Kind: protocol.JobAptUpdate}); !errors.Is(err, grid.ErrCapabilityDisabled) {
		t.Errorf("StartJob: %v", err)
	}
	if err := dh.RefreshPackages(ctx, id); !errors.Is(err, grid.ErrCapabilityDisabled) {
		t.Errorf("RefreshPackages: %v", err)
	}
	if _, err := dh.SearchPackages(ctx, id, "htop"); !errors.Is(err, grid.ErrCapabilityDisabled) {
		t.Errorf("SearchPackages: %v", err)
	}
	// Switching back on lifts the refusal; the other hosts were never touched.
	if err := dh.SetCapability(ctx, actor, id, protocol.CapShell, true); err != nil {
		t.Fatal(err)
	}
	if info, _ = dh.Host(id); !info.HasCapability(protocol.CapShell) || len(info.DisabledCapabilities) != 1 {
		t.Errorf("info after switching on = %+v", info)
	}
	if other := dh.Hosts()[1]; len(other.DisabledCapabilities) != 0 {
		t.Errorf("another host changed: %+v", other)
	}
}
