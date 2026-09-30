package services

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/phabioo/nexara/internal/protocol"
)

type fakeAPI struct {
	units     []unitState
	enabled   map[string]bool
	result    string
	err       error
	restarted []string
}

func (f *fakeAPI) Units(context.Context) ([]unitState, error) { return f.units, nil }
func (f *fakeAPI) EnabledUnits(context.Context) (map[string]bool, error) {
	return f.enabled, nil
}
func (f *fakeAPI) Restart(_ context.Context, u string) (string, error) {
	f.restarted = append(f.restarted, u)
	return f.result, f.err
}

func u(name, active, sub string) unitState {
	return unitState{Name: name, Description: name + " desc", LoadState: "loaded", ActiveState: active, SubState: sub}
}

func newFake() *fakeAPI {
	return &fakeAPI{
		units: []unitState{
			u("ssh.service", "active", "running"),
			u("nginx.service", "active", "running"),
			u("broken.service", "failed", "failed"),
			u("systemd-journald.service", "active", "running"),
			u("getty@tty1.service", "active", "running"),
			u("user@1000.service", "active", "running"),
			u("dbus-broker.service", "active", "running"),
			u("modprobe@drm.service", "failed", "failed"),
			u("sys-kernel-debug.service", "active", "running"),
			u("openvpn@client.service", "failed", "failed"),
			u("openvpn@other.service", "active", "running"),
			u("static.service", "active", "running"), // not enabled
			{Name: "ghost.service", LoadState: "not-found", ActiveState: "failed"},
			u("cron.timer", "active", "waiting"),
		},
		enabled: map[string]bool{
			"ssh.service": true, "nginx.service": true, "openvpn@other.service": true,
			"systemd-journald.service": true, "ghost.service": true,
		},
		result: "done",
	}
}

func TestList(t *testing.T) {
	m := &manager{api: newFake(), ports: func() ([]protocol.ListeningPort, error) {
		return []protocol.ListeningPort{{Proto: "tcp", Port: 22, Process: "sshd"}}, nil
	}}
	got, err := m.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, x := range got.Units {
		names = append(names, x.Name)
	}
	want := []string{"broken.service", "openvpn@client.service", "nginx.service", "ssh.service"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("got %v, want %v", names, want)
	}
	if got.Units[2].Description != "nginx.service desc" || got.Units[2].ActiveState != "active" || got.Units[2].SubState != "running" {
		t.Fatalf("fields not filled: %+v", got.Units[2])
	}
	if len(got.Ports) != 1 {
		t.Fatalf("ports: %v", got.Ports)
	}
}

func TestListPortsFailureIsNotFatal(t *testing.T) {
	m := &manager{api: newFake(), ports: func() ([]protocol.ListeningPort, error) { return nil, errors.New("boom") }}
	got, err := m.List(context.Background())
	if err != nil || len(got.Units) == 0 || got.Ports != nil {
		t.Fatalf("got %+v, err %v", got, err)
	}
}

func TestRestart(t *testing.T) {
	tests := []struct {
		name    string
		unit    string
		result  string
		apiErr  error
		wantErr string // substring; "" means success
		wantRun bool
	}{
		{"ok", "ssh.service", "done", nil, "", true},
		{"failed job", "nginx.service", "failed", nil, "failed to start", true},
		{"timeout job", "nginx.service", "timeout", nil, "timed out", true},
		{"deadline", "nginx.service", "", context.DeadlineExceeded, "timed out", true},
		{"dbus error", "nginx.service", "", errors.New("no bus"), "no bus", true},
		{"failed unit allowed", "broken.service", "done", nil, "", true},
		{"invalid name", "ssh.service; rm -rf /", "done", nil, "invalid unit name", false},
		{"not a service", "cron.timer", "done", nil, "invalid unit name", false},
		{"empty", "", "done", nil, "invalid unit name", false},
		{"hidden noise", "systemd-journald.service", "done", nil, "not a manageable", false},
		{"not enabled", "static.service", "done", nil, "not a manageable", false},
		{"unknown", "nope.service", "done", nil, "not a manageable", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := newFake()
			api.result, api.err = tt.result, tt.apiErr
			err := (&manager{api: api}).Restart(context.Background(), tt.unit)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Fatalf("got %v, want error containing %q", err, tt.wantErr)
			}
			if ran := len(api.restarted) > 0; ran != tt.wantRun {
				t.Fatalf("restart called = %v, want %v", ran, tt.wantRun)
			}
		})
	}
}

func TestUnitNameRe(t *testing.T) {
	for name, want := range map[string]bool{
		"ssh.service": true, "openvpn@client.service": true, "a-b_c.d:e.service": true,
		"ssh": false, "ssh.service ": false, "a b.service": false, "$(x).service": false, "../x.service": false,
	} {
		if got := unitNameRe.MatchString(name); got != want {
			t.Errorf("%q: got %v, want %v", name, got, want)
		}
	}
}
