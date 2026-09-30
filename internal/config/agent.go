package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/phabioo/nexara/internal/protocol"
)

// AgentConfig is agent.yaml. The hub writes it during enrollment.
type AgentConfig struct {
	Hub          AgentHubSection     `yaml:"hub"`
	TLS          AgentTLSSection     `yaml:"tls"`
	Metrics      AgentMetricsSection `yaml:"metrics"`
	Shell        AgentShellSection   `yaml:"shell"`
	Capabilities Capabilities        `yaml:"capabilities"`
	Enroll       AgentEnrollSection  `yaml:"enroll,omitempty"`
}

// AgentEnrollSection is optional and used for self-link on the hub device.
type AgentEnrollSection struct {
	// TokenFile is a file containing a one-time enrollment token. On the hub
	// device the installer sets it to /var/lib/nexus/self-enroll.token;
	// `grid-agent run` without a certificate then enrolls with that token
	// against the local hub (self-link). Empty (default) disables this.
	TokenFile string `yaml:"token_file,omitempty"`
}

// AgentHubSection tells the agent where the hub is.
type AgentHubSection struct {
	URL string `yaml:"url"` // wss://host:port/grid/connect
}

// AgentTLSSection locates the mTLS material.
type AgentTLSSection struct {
	CA   string `yaml:"ca"`   // hub CA certificate (PEM)
	Cert string `yaml:"cert"` // agent client certificate (PEM)
	Key  string `yaml:"key"`  // agent private key (PEM)
}

// AgentMetricsSection sets the sampling rate.
type AgentMetricsSection struct {
	IntervalSeconds int `yaml:"interval_seconds"`
}

// AgentShellSection configures Nexara Shell on the device.
type AgentShellSection struct {
	User string `yaml:"user"` // the device's normal sudo user, never root
}

// Capabilities switches agent features on or off. A disabled capability is
// neither advertised in hello nor executed if the hub asks for it.
type Capabilities struct {
	Monitoring bool `yaml:"monitoring"`
	Packages   bool `yaml:"packages"`
	Services   bool `yaml:"services"`
	Shell      bool `yaml:"shell"`
	Power      bool `yaml:"power"`
	Docker     bool `yaml:"docker"`
}

// Has reports whether the named capability (protocol.Cap*) is enabled.
func (c Capabilities) Has(name string) bool {
	switch name {
	case protocol.CapMonitoring:
		return c.Monitoring
	case protocol.CapPackages:
		return c.Packages
	case protocol.CapServices:
		return c.Services
	case protocol.CapShell:
		return c.Shell
	case protocol.CapPower:
		return c.Power
	case protocol.CapDocker:
		return c.Docker
	}
	return false
}

// Enabled returns the enabled capability names in protocol.Capabilities() order,
// ready for protocol.Hello.Capabilities.
func (c Capabilities) Enabled() []string {
	var out []string
	for _, name := range protocol.Capabilities() {
		if c.Has(name) {
			out = append(out, name)
		}
	}
	return out
}

// DefaultAgent returns the defaults. Hub URL and shell user have no sensible
// default and stay empty; enrollment fills them in (Validate rejects the
// defaults until then).
func DefaultAgent() AgentConfig {
	return AgentConfig{
		TLS: AgentTLSSection{
			CA:   "/var/lib/grid-agent/ca.pem",
			Cert: "/var/lib/grid-agent/agent.pem",
			Key:  "/var/lib/grid-agent/agent.key",
		},
		Metrics: AgentMetricsSection{IntervalSeconds: 2},
		Capabilities: Capabilities{
			Monitoring: true, Packages: true, Services: true, Shell: true, Power: true, Docker: false,
		},
	}
}

// LoadAgent reads, strictly decodes and validates agent.yaml.
func LoadAgent(path string) (AgentConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return AgentConfig{}, fmt.Errorf("config: read %s: %w", path, err)
	}
	cfg := DefaultAgent()
	if err := decodeStrict(data, &cfg); err != nil {
		return AgentConfig{}, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return AgentConfig{}, fmt.Errorf("config: %s: %w", path, err)
	}
	return cfg, nil
}

// SaveAgent validates and atomically writes cfg to path (mode 0640). Used by
// `grid-agent enroll` and the hub's SSH bootstrap.
func SaveAgent(path string, cfg AgentConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	data, err := marshal("# Nexara Grid Agent configuration. Written by the hub during enrollment.\n", cfg)
	if err != nil {
		return fmt.Errorf("config: encode agent config: %w", err)
	}
	return writeFileAtomic(path, data, fileMode)
}

// Save is shorthand for SaveAgent(path, c).
func (c AgentConfig) Save(path string) error { return SaveAgent(path, c) }

// Validate checks all values and reports every problem at once as *ValidationError.
func (c AgentConfig) Validate() error {
	var p problems

	if c.Hub.URL == "" {
		p.addf("hub.url must be set (wss://host:port/grid/connect)")
	} else if u, err := url.Parse(c.Hub.URL); err != nil || u.Scheme != "wss" || u.Hostname() == "" {
		p.addf("hub.url %q must be a wss:// URL with a host", c.Hub.URL)
	}
	if c.TLS.CA == "" {
		p.addf("tls.ca must not be empty")
	}
	if c.TLS.Cert == "" {
		p.addf("tls.cert must not be empty")
	}
	if c.TLS.Key == "" {
		p.addf("tls.key must not be empty")
	}
	if s := c.Metrics.IntervalSeconds; s < 1 || s > 3600 {
		p.addf("metrics.interval_seconds is %d, must be 1-3600", s)
	}
	if c.Capabilities.Shell {
		u := strings.TrimSpace(c.Shell.User)
		switch {
		case u == "":
			p.addf("shell.user must be set while capabilities.shell is enabled")
		case u == "root":
			p.addf("shell.user must not be root")
		case u != c.Shell.User || strings.ContainsAny(u, " \t:/\\"):
			p.addf("shell.user %q is not a valid user name", c.Shell.User)
		}
	}
	return p.err()
}

// MetricsInterval is the sampling interval.
func (c AgentConfig) MetricsInterval() time.Duration {
	return time.Duration(c.Metrics.IntervalSeconds) * time.Second
}
