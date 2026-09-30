package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cfg.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestHubDefaults(t *testing.T) {
	c := DefaultHub()
	if err := c.Validate(); err != nil {
		t.Fatalf("defaults must be valid: %v", err)
	}
	if c.Hub.Listen != ":8443" || c.TLS.Mode != TLSModeSelf || c.Storage.History.MinuteDays != 7 ||
		c.Storage.History.HourDays != 365 || c.Security.SessionIdleHours != 12 || c.Security.TOTPRequired ||
		c.Security.LoginRateLimit.Attempts != 5 || c.Alerts.CPUTempC != 75 {
		t.Fatalf("unexpected defaults: %+v", c)
	}
	if c.SessionIdleTimeout() != 12*time.Hour || c.LoginRateWindow() != 15*time.Minute ||
		c.HostOfflineAfter() != time.Minute || c.MinuteRetention() != 7*24*time.Hour ||
		c.HourRetention() != 365*24*time.Hour {
		t.Fatal("duration helpers wrong")
	}
}

func TestAgentDefaults(t *testing.T) {
	c := DefaultAgent()
	if c.Metrics.IntervalSeconds != 2 || c.MetricsInterval() != 2*time.Second || !c.Capabilities.Shell || c.Capabilities.Docker {
		t.Fatalf("unexpected defaults: %+v", c)
	}
	if err := c.Validate(); err == nil {
		t.Fatal("defaults lack hub.url and shell.user and must not validate")
	}
}

func TestLoadExampleFiles(t *testing.T) {
	hub, err := LoadHub("../../configs/nexus.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	want := DefaultHub()
	want.Hub.Name, want.Hub.Timezone, want.Hub.AgentAddress = "frpi5", "Europe/Berlin", "frpi5.local"
	if !reflect.DeepEqual(hub, want) {
		t.Fatalf("hub example differs from defaults+wizard values:\n got %+v\nwant %+v", hub, want)
	}
	if hub.Location().String() != "Europe/Berlin" {
		t.Fatalf("location %v", hub.Location())
	}

	ag, err := LoadAgent("../../configs/agent.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if ag.Hub.URL != "wss://frpi5.local:8443/grid/connect" || ag.Shell.User != "pi" || ag.TLS.Key != "/var/lib/grid-agent/agent.key" {
		t.Fatalf("agent example: %+v", ag)
	}
	wantCaps := []string{"monitoring", "packages", "services", "shell", "power"}
	if got := ag.Capabilities.Enabled(); !reflect.DeepEqual(got, wantCaps) {
		t.Fatalf("enabled capabilities %v, want %v", got, wantCaps)
	}
	if ag.Capabilities.Has("docker") || !ag.Capabilities.Has("shell") || ag.Capabilities.Has("bogus") {
		t.Fatal("Has wrong")
	}
}

func TestLoadPartialKeepsDefaults(t *testing.T) {
	p := writeTemp(t, "hub:\n  name: pi-a\nalerts:\n  cpu_temp_c: 80\n")
	c, err := LoadHub(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Hub.Name != "pi-a" || c.Alerts.CPUTempC != 80 || c.Hub.Listen != ":8443" || c.Alerts.DiskUsedPercent != 90 {
		t.Fatalf("got %+v", c)
	}
	// Empty file is all defaults.
	if c, err = LoadHub(writeTemp(t, "")); err != nil || !reflect.DeepEqual(c, DefaultHub()) {
		t.Fatalf("empty file: %+v %v", c, err)
	}
}

func TestUnknownKeysRejected(t *testing.T) {
	tests := []struct{ name, yaml string }{
		{"top level", "bogus: 1\n"},
		{"nested", "hub:\n  nmae: x\n"},
		{"deep", "security:\n  login_rate_limit:\n    attemps: 3\n"},
	}
	for _, tt := range tests {
		t.Run("hub "+tt.name, func(t *testing.T) {
			if _, err := LoadHub(writeTemp(t, tt.yaml)); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	agent := "hub:\n  url: wss://h:1/grid/connect\nshell:\n  user: pi\ncapabilities:\n  dockr: true\n"
	if _, err := LoadAgent(writeTemp(t, agent)); err == nil {
		t.Fatal("agent: expected unknown key error")
	}
}

func TestLoadErrors(t *testing.T) {
	if _, err := LoadHub(filepath.Join(t.TempDir(), "missing.yaml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("want ErrNotExist, got %v", err)
	}
	if _, err := LoadHub(writeTemp(t, "hub: [unclosed")); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestHubValidation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*HubConfig)
		want   string // substring of the problem; empty = valid
	}{
		{"ok", func(*HubConfig) {}, ""},
		{"agent address with port", func(c *HubConfig) { c.Hub.AgentAddress = "frpi5.local:8443" }, ""},
		{"agent address ipv6", func(c *HubConfig) { c.Hub.AgentAddress = "[fe80::1]:8443" }, ""},
		{"empty name", func(c *HubConfig) { c.Hub.Name = "" }, "hub.name"},
		{"bad name", func(c *HubConfig) { c.Hub.Name = "bad name" }, "hub.name"},
		{"bad timezone", func(c *HubConfig) { c.Hub.Timezone = "Mars/Base" }, "hub.timezone"},
		{"empty timezone", func(c *HubConfig) { c.Hub.Timezone = "" }, "hub.timezone"},
		{"agent address scheme", func(c *HubConfig) { c.Hub.AgentAddress = "https://frpi5.local" }, "hub.agent_address"},
		{"agent address port", func(c *HubConfig) { c.Hub.AgentAddress = "frpi5.local:99999" }, "hub.agent_address"},
		{"listen no port", func(c *HubConfig) { c.Hub.Listen = "localhost" }, "hub.listen"},
		{"listen port 0", func(c *HubConfig) { c.Hub.Listen = ":0" }, "hub.listen"},
		{"tls mode", func(c *HubConfig) { c.TLS.Mode = "acme" }, "tls.mode"},
		{"tls dir", func(c *HubConfig) { c.TLS.Dir = "" }, "tls.dir"},
		{"database", func(c *HubConfig) { c.Storage.Database = "" }, "storage.database"},
		{"minute days", func(c *HubConfig) { c.Storage.History.MinuteDays = 0 }, "minute_days"},
		{"hour days", func(c *HubConfig) { c.Storage.History.HourDays = 5000 }, "hour_days"},
		{"idle hours", func(c *HubConfig) { c.Security.SessionIdleHours = 0 }, "session_idle_hours"},
		{"attempts", func(c *HubConfig) { c.Security.LoginRateLimit.Attempts = 0 }, "attempts"},
		{"window", func(c *HubConfig) { c.Security.LoginRateLimit.WindowMinutes = -1 }, "window_minutes"},
		{"cpu temp", func(c *HubConfig) { c.Alerts.CPUTempC = 5 }, "cpu_temp_c"},
		{"disk percent", func(c *HubConfig) { c.Alerts.DiskUsedPercent = 101 }, "disk_used_percent"},
		{"offline", func(c *HubConfig) { c.Alerts.HostOfflineSeconds = 1 }, "host_offline_seconds"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := DefaultHub()
			tt.mutate(&c)
			err := c.Validate()
			if tt.want == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			var ve *ValidationError
			if !errors.As(err, &ve) || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("want validation error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestValidationReportsAllProblems(t *testing.T) {
	c := DefaultHub()
	c.Hub.Name, c.Alerts.CPUTempC = "", 0
	var ve *ValidationError
	if err := c.Validate(); !errors.As(err, &ve) || len(ve.Problems) != 2 {
		t.Fatalf("want 2 problems, got %v", err)
	}
}

func TestAgentValidation(t *testing.T) {
	valid := func() AgentConfig {
		c := DefaultAgent()
		c.Hub.URL, c.Shell.User = "wss://frpi5.local:8443/grid/connect", "pi"
		return c
	}
	tests := []struct {
		name   string
		mutate func(*AgentConfig)
		want   string
	}{
		{"ok", func(*AgentConfig) {}, ""},
		{"shell off needs no user", func(c *AgentConfig) { c.Capabilities.Shell, c.Shell.User = false, "" }, ""},
		{"no url", func(c *AgentConfig) { c.Hub.URL = "" }, "hub.url"},
		{"plain ws", func(c *AgentConfig) { c.Hub.URL = "ws://h:1/x" }, "hub.url"},
		{"https url", func(c *AgentConfig) { c.Hub.URL = "https://h:1/x" }, "hub.url"},
		{"no host", func(c *AgentConfig) { c.Hub.URL = "wss:///x" }, "hub.url"},
		{"ca", func(c *AgentConfig) { c.TLS.CA = "" }, "tls.ca"},
		{"cert", func(c *AgentConfig) { c.TLS.Cert = "" }, "tls.cert"},
		{"key", func(c *AgentConfig) { c.TLS.Key = "" }, "tls.key"},
		{"interval 0", func(c *AgentConfig) { c.Metrics.IntervalSeconds = 0 }, "interval_seconds"},
		{"interval big", func(c *AgentConfig) { c.Metrics.IntervalSeconds = 4000 }, "interval_seconds"},
		{"shell user empty", func(c *AgentConfig) { c.Shell.User = "" }, "shell.user"},
		{"shell user root", func(c *AgentConfig) { c.Shell.User = "root" }, "must not be root"},
		{"shell user junk", func(c *AgentConfig) { c.Shell.User = "a b" }, "shell.user"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := valid()
			tt.mutate(&c)
			err := c.Validate()
			if tt.want == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("want error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestHubSaveLoadRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nexus.yaml")
	c := DefaultHub()
	c.Hub.Name, c.Hub.Timezone, c.Hub.AgentAddress, c.Hub.Listen = "frpi5", "Europe/Berlin", "frpi5.local", ":9443"
	c.Security.TOTPRequired = true
	if err := c.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := LoadHub(path)
	if err != nil || !reflect.DeepEqual(got, c) {
		t.Fatalf("roundtrip: %+v %v", got, err)
	}
	// Overwrite atomically, no temp files left behind.
	c.Hub.Name = "frpi6"
	if err := SaveHub(path, c); err != nil {
		t.Fatal(err)
	}
	if got, _ = LoadHub(path); got.Hub.Name != "frpi6" {
		t.Fatalf("not overwritten: %+v", got)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("leftover files: %v", entries)
	}
	if runtimeHasUnixModes() {
		if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o640 {
			t.Fatalf("mode %v, want 0640", fi.Mode().Perm())
		}
	}
}

func TestSaveRejectsInvalid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nexus.yaml")
	c := DefaultHub()
	c.Hub.Listen = "nope"
	if err := c.Save(path); err == nil {
		t.Fatal("expected error")
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("file must not be written for invalid config")
	}
	// Directory missing: error, not panic.
	if err := DefaultHub().Save(filepath.Join(t.TempDir(), "no", "such", "dir", "x.yaml")); err == nil {
		t.Fatal("expected error for missing directory")
	}
}

func TestAgentSaveLoadRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.yaml")
	c := DefaultAgent()
	c.Hub.URL, c.Shell.User, c.Capabilities.Docker = "wss://frpi5.local:8443/grid/connect", "pi", true
	if err := c.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := LoadAgent(path)
	if err != nil || !reflect.DeepEqual(got, c) {
		t.Fatalf("roundtrip: %+v %v", got, err)
	}
}
