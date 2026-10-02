package grid

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/protocol"
)

func TestSetCapabilityErrors(t *testing.T) {
	e := newEnv(t)
	id := e.addHost("alpha", protocol.CapMonitoring, protocol.CapShell)
	ctx := context.Background()
	tests := []struct {
		name string
		id   HostID
		capa string
		on   bool
		want error
	}{
		{"unknown host", "missing", protocol.CapShell, false, ErrHostNotFound},
		{"unknown capability", id, "root", false, ErrInvalidArgument},
		{"monitoring cannot be switched", id, protocol.CapMonitoring, false, ErrInvalidArgument},
		{"not offered by the agent", id, protocol.CapPackages, true, ErrUnsupported},
		{"switching off what is not offered", id, protocol.CapDocker, false, ErrUnsupported},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := e.g.SetCapability(ctx, Actor{Operator: "op"}, tc.id, tc.capa, tc.on); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	if got := e.auditFor("host.capabilities"); len(got) != 0 {
		t.Errorf("rejected calls were audited: %+v", got)
	}
}

func TestSetCapabilitySwitchesAndPersists(t *testing.T) {
	e := newEnv(t)
	id := e.addHost("alpha", protocol.CapMonitoring, protocol.CapPackages, protocol.CapShell)
	ctx := context.Background()
	actor := Actor{Operator: "op", IP: "192.0.2.7"}

	if err := e.g.SetCapability(ctx, actor, id, protocol.CapShell, false); err != nil {
		t.Fatal(err)
	}
	info, _ := e.g.Host(id)
	if slices.Contains(info.Capabilities, protocol.CapShell) || !slices.Equal(info.DisabledCapabilities, []string{protocol.CapShell}) {
		t.Fatalf("info after off: caps %v, disabled %v", info.Capabilities, info.DisabledCapabilities)
	}
	if info.HasCapability(protocol.CapShell) || !info.HasCapability(protocol.CapPackages) {
		t.Fatal("HasCapability does not follow the switch")
	}
	v, ok, err := e.st.GetSetting(ctx, capsOffKey(id))
	if err != nil || !ok || v != protocol.CapShell {
		t.Fatalf("stored switch = %q, %v, %v", v, ok, err)
	}
	// A no-op does not write another audit entry.
	if err := e.g.SetCapability(ctx, actor, id, protocol.CapShell, false); err != nil {
		t.Fatal(err)
	}
	au := e.auditFor("host.capabilities")
	if len(au) != 1 || au[0].User != "op" || au[0].Host != "alpha" || au[0].Result != store.AuditOK ||
		!strings.Contains(au[0].Detail, "shell off") || !strings.Contains(au[0].Detail, "192.0.2.7") {
		t.Fatalf("audit = %+v", au)
	}

	if err := e.g.SetCapability(ctx, actor, id, protocol.CapShell, true); err != nil {
		t.Fatal(err)
	}
	info, _ = e.g.Host(id)
	if !slices.Contains(info.Capabilities, protocol.CapShell) || len(info.DisabledCapabilities) != 0 {
		t.Fatalf("info after on: caps %v, disabled %v", info.Capabilities, info.DisabledCapabilities)
	}
	if _, ok, _ := e.st.GetSetting(ctx, capsOffKey(id)); ok {
		t.Error("switch setting stays after switching back on")
	}
}

func TestSwitchedOffCapabilityIsRefused(t *testing.T) {
	e := newEnv(t)
	sa := newShellAgent(t)
	id, _ := e.shellHost(sa)
	ctx := context.Background()
	if err := e.g.SetCapability(ctx, Actor{Operator: "op"}, id, protocol.CapShell, false); err != nil {
		t.Fatal(err)
	}
	if _, err := e.g.OpenShell(ctx, Actor{Operator: "op"}, id, 80, 24); !errors.Is(err, ErrCapabilityDisabled) {
		t.Fatalf("OpenShell with the shell switched off: %v", err)
	}
	if err := e.g.SetCapability(ctx, Actor{Operator: "op"}, id, protocol.CapShell, true); err != nil {
		t.Fatal(err)
	}
	sh, err := e.g.OpenShell(ctx, Actor{Operator: "op"}, id, 80, 24)
	if err != nil {
		t.Fatalf("OpenShell after switching on: %v", err)
	}
	sa.nextOpen()
	_ = sh.Close()
}

func TestSwitchedOffPackagesRefuseJobsAndRefresh(t *testing.T) {
	e := newEnv(t)
	ja := newJobAgent(t)
	id, _ := e.jobHost(ja)
	ctx := context.Background()
	if err := e.g.SetCapability(ctx, Actor{Operator: "op"}, id, protocol.CapPackages, false); err != nil {
		t.Fatal(err)
	}
	if _, err := e.g.StartJob(ctx, Actor{Operator: "op"}, id, JobSpec{Kind: protocol.JobAptUpdate}); !errors.Is(err, ErrCapabilityDisabled) {
		t.Errorf("StartJob: %v", err)
	}
	if err := e.g.RefreshPackages(ctx, id); !errors.Is(err, ErrCapabilityDisabled) {
		t.Errorf("RefreshPackages: %v", err)
	}
	if _, err := e.g.SearchPackages(ctx, id, "htop"); !errors.Is(err, ErrCapabilityDisabled) {
		t.Errorf("SearchPackages: %v", err)
	}
	if len(ja.starts) != 0 {
		t.Error("a refused job reached the agent")
	}
}

func TestSwitchingShellOffClosesOpenSessions(t *testing.T) {
	e := newEnv(t)
	sa := newShellAgent(t)
	id, _ := e.shellHost(sa)
	ctx := context.Background()
	sh, err := e.g.OpenShell(ctx, Actor{Operator: "op"}, id, 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	sa.nextOpen()
	if err := e.g.SetCapability(ctx, Actor{Operator: "op"}, id, protocol.CapShell, false); err != nil {
		t.Fatal(err)
	}
	if _, err := readAllWithin(t, sh); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("open session after switching the shell off: err %v", err)
	}
	e.waitAudit("shell.close")
}

func TestCapabilitySwitchSurvivesReconnectAndRestart(t *testing.T) {
	e := newEnv(t)
	id := e.addHost("alpha", protocol.CapMonitoring, protocol.CapShell)
	ctx := context.Background()
	if err := e.g.SetCapability(ctx, Actor{Operator: "op"}, id, protocol.CapShell, false); err != nil {
		t.Fatal(err)
	}
	// The agent reports the same capabilities again on every connect; the switch stays.
	e.connect("alpha", helloFor("0.1.0", protocol.CapMonitoring, protocol.CapShell), nil)
	eventually(t, func() bool { i, _ := e.g.Host(id); return i.Online })
	info, _ := e.g.Host(id)
	if info.HasCapability(protocol.CapShell) || !slices.Contains(info.DisabledCapabilities, protocol.CapShell) {
		t.Fatalf("after reconnect: caps %v, disabled %v", info.Capabilities, info.DisabledCapabilities)
	}

	// A new Grid on the same store (hub restart) restores it.
	g2, err := NewGrid(Options{Store: e.st, HubVersion: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	defer g2.Close()
	info, ok := g2.Host(id)
	if !ok || info.HasCapability(protocol.CapShell) || !slices.Contains(info.DisabledCapabilities, protocol.CapShell) {
		t.Fatalf("after restart: %+v", info)
	}

	// Removing the host drops the switch.
	if err := e.g.RemoveHost(ctx, Actor{Operator: "op"}, id); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := e.st.GetSetting(ctx, capsOffKey(id)); ok {
		t.Error("switch of a removed host stays")
	}
}

func TestParseCapsOff(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"shell", []string{"shell"}},
		{"shell, packages,shell", []string{"shell", "packages"}},
		{"monitoring,shell", []string{"shell"}},
		{"root,,shell", []string{"shell"}},
	}
	for _, tc := range tests {
		if got := parseCapsOff(tc.in); !slices.Equal(got, tc.want) {
			t.Errorf("parseCapsOff(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
