package config

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata" // timezone names must resolve on hosts without a tz database (Windows, minimal images)
)

// TLS modes of the hub.
const (
	// TLSModeSelf means the hub issues its own server certificate from its CA.
	TLSModeSelf = "self"
)

// HubConfig is nexus.yaml. The setup wizard writes the hub.* section.
type HubConfig struct {
	Hub      HubSection      `yaml:"hub"`
	TLS      TLSSection      `yaml:"tls"`
	Storage  StorageSection  `yaml:"storage"`
	Security SecuritySection `yaml:"security"`
	Alerts   AlertsSection   `yaml:"alerts"`
}

// HubSection identifies the hub and where it listens.
type HubSection struct {
	Name         string `yaml:"name"`          // hub/host name shown in the UI
	Timezone     string `yaml:"timezone"`      // IANA name, e.g. "Europe/Berlin"
	AgentAddress string `yaml:"agent_address"` // host[:port] agents use to reach the hub; empty until the wizard sets it
	Listen       string `yaml:"listen"`        // listen address, e.g. ":8443"
}

// TLSSection configures the hub's own certificates.
type TLSSection struct {
	Mode string `yaml:"mode"` // TLSModeSelf
	Dir  string `yaml:"dir"`  // directory for CA and certificates
}

// StorageSection locates the database and sets history retention.
type StorageSection struct {
	Database string         `yaml:"database"`
	History  HistorySection `yaml:"history"`
}

// HistorySection is the metrics retention (used from v0.2).
type HistorySection struct {
	MinuteDays int `yaml:"minute_days"` // retention of per-minute averages
	HourDays   int `yaml:"hour_days"`   // retention of per-hour averages
}

// SecuritySection holds session and login policy.
type SecuritySection struct {
	SessionIdleHours int              `yaml:"session_idle_hours"`
	TOTPRequired     bool             `yaml:"totp_required"` // true from v0.2
	LoginRateLimit   LoginRateSection `yaml:"login_rate_limit"`
}

// LoginRateSection limits failed logins per IP and per account.
type LoginRateSection struct {
	Attempts      int `yaml:"attempts"`
	WindowMinutes int `yaml:"window_minutes"`
}

// AlertsSection holds the default alert thresholds (used from v0.3).
type AlertsSection struct {
	CPUTempC           float64 `yaml:"cpu_temp_c"`
	DiskUsedPercent    float64 `yaml:"disk_used_percent"`
	HostOfflineSeconds int     `yaml:"host_offline_seconds"`
}

// DefaultHub returns the defaults (same values as configs/nexus.example.yaml,
// except that agent_address is empty until the setup wizard sets it).
func DefaultHub() HubConfig {
	return HubConfig{
		Hub: HubSection{
			Name:     "nexus",
			Timezone: "UTC",
			Listen:   ":8443",
		},
		TLS: TLSSection{Mode: TLSModeSelf, Dir: "/var/lib/nexus/pki"},
		Storage: StorageSection{
			Database: "/var/lib/nexus/nexus.db",
			History:  HistorySection{MinuteDays: 7, HourDays: 365},
		},
		Security: SecuritySection{
			SessionIdleHours: 12,
			TOTPRequired:     false,
			LoginRateLimit:   LoginRateSection{Attempts: 5, WindowMinutes: 15},
		},
		Alerts: AlertsSection{CPUTempC: 75, DiskUsedPercent: 90, HostOfflineSeconds: 60},
	}
}

// LoadHub reads, strictly decodes and validates nexus.yaml. Missing optional
// keys keep their defaults; unknown keys and invalid values are errors.
func LoadHub(path string) (HubConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return HubConfig{}, fmt.Errorf("config: read %s: %w", path, err)
	}
	cfg := DefaultHub()
	if err := decodeStrict(data, &cfg); err != nil {
		return HubConfig{}, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return HubConfig{}, fmt.Errorf("config: %s: %w", path, err)
	}
	return cfg, nil
}

// SaveHub validates and atomically writes cfg to path (temp file + rename,
// mode 0640). Comments in an existing file are not preserved.
func SaveHub(path string, cfg HubConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	data, err := marshal("# Nexara Nexus hub configuration. The setup wizard writes hub.*; edit with care.\n", cfg)
	if err != nil {
		return fmt.Errorf("config: encode hub config: %w", err)
	}
	return writeFileAtomic(path, data, fileMode)
}

// Save is shorthand for SaveHub(path, c).
func (c HubConfig) Save(path string) error { return SaveHub(path, c) }

var hubNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

// Validate checks all values and reports every problem at once as *ValidationError.
func (c HubConfig) Validate() error {
	var p problems

	if !hubNameRe.MatchString(c.Hub.Name) {
		p.addf("hub.name %q must be 1-63 characters of letters, digits, '.', '_' or '-'", c.Hub.Name)
	}
	if _, err := time.LoadLocation(c.Hub.Timezone); err != nil || c.Hub.Timezone == "" || c.Hub.Timezone == "Local" {
		p.addf("hub.timezone %q is not a valid IANA timezone name", c.Hub.Timezone)
	}
	if a := c.Hub.AgentAddress; a != "" {
		if strings.ContainsAny(a, " \t/\\@") || strings.Contains(a, "://") {
			p.addf("hub.agent_address %q must be a host name or IP with an optional port, without scheme or path", a)
		} else if strings.Contains(a, ":") && !strings.HasPrefix(a, "[") && strings.Count(a, ":") == 1 {
			if _, port, err := net.SplitHostPort(a); err != nil || !validPort(port) {
				p.addf("hub.agent_address %q has an invalid port", a)
			}
		}
	}
	if _, port, err := net.SplitHostPort(c.Hub.Listen); err != nil || !validPort(port) {
		p.addf("hub.listen %q must look like \":8443\" or \"0.0.0.0:8443\"", c.Hub.Listen)
	}

	if c.TLS.Mode != TLSModeSelf {
		p.addf("tls.mode %q is not supported (only %q)", c.TLS.Mode, TLSModeSelf)
	}
	if c.TLS.Dir == "" {
		p.addf("tls.dir must not be empty")
	}
	if c.Storage.Database == "" {
		p.addf("storage.database must not be empty")
	}
	if d := c.Storage.History.MinuteDays; d < 1 || d > 365 {
		p.addf("storage.history.minute_days is %d, must be 1-365", d)
	}
	if d := c.Storage.History.HourDays; d < 1 || d > 3650 {
		p.addf("storage.history.hour_days is %d, must be 1-3650", d)
	}
	if h := c.Security.SessionIdleHours; h < 1 || h > 720 {
		p.addf("security.session_idle_hours is %d, must be 1-720", h)
	}
	if n := c.Security.LoginRateLimit.Attempts; n < 1 || n > 100 {
		p.addf("security.login_rate_limit.attempts is %d, must be 1-100", n)
	}
	if m := c.Security.LoginRateLimit.WindowMinutes; m < 1 || m > 1440 {
		p.addf("security.login_rate_limit.window_minutes is %d, must be 1-1440", m)
	}
	if t := c.Alerts.CPUTempC; t < 30 || t > 120 {
		p.addf("alerts.cpu_temp_c is %v, must be 30-120", t)
	}
	if d := c.Alerts.DiskUsedPercent; d < 1 || d > 100 {
		p.addf("alerts.disk_used_percent is %v, must be 1-100", d)
	}
	if s := c.Alerts.HostOfflineSeconds; s < 5 || s > 86400 {
		p.addf("alerts.host_offline_seconds is %d, must be 5-86400", s)
	}
	return p.err()
}

func validPort(s string) bool {
	n, err := strconv.Atoi(s)
	return err == nil && n >= 1 && n <= 65535
}

// Location returns the configured timezone (UTC if it cannot be loaded; Validate rejects that case).
func (c HubConfig) Location() *time.Location {
	loc, err := time.LoadLocation(c.Hub.Timezone)
	if err != nil {
		return time.UTC
	}
	return loc
}

// SessionIdleTimeout is the idle timeout of browser sessions.
func (c HubConfig) SessionIdleTimeout() time.Duration {
	return time.Duration(c.Security.SessionIdleHours) * time.Hour
}

// LoginRateWindow is the sliding window of the login rate limit.
func (c HubConfig) LoginRateWindow() time.Duration {
	return time.Duration(c.Security.LoginRateLimit.WindowMinutes) * time.Minute
}

// HostOfflineAfter is how long without data before a host counts as offline.
func (c HubConfig) HostOfflineAfter() time.Duration {
	return time.Duration(c.Alerts.HostOfflineSeconds) * time.Second
}

// MinuteRetention is the retention of per-minute metrics.
func (c HubConfig) MinuteRetention() time.Duration {
	return time.Duration(c.Storage.History.MinuteDays) * 24 * time.Hour
}

// HourRetention is the retention of per-hour metrics.
func (c HubConfig) HourRetention() time.Duration {
	return time.Duration(c.Storage.History.HourDays) * 24 * time.Hour
}
