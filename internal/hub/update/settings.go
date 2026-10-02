package update

import (
	"context"
	"fmt"
	"sync"
)

// Setting keys in the hub's key-value settings (decision #49).
const (
	SettingCheckGitHub    = "update.check_github"    // "true" turns the GitHub check on (default off, #53)
	SettingChannel        = "update.channel"         // ChannelStable (default) or ChannelRC
	SettingAllowDowngrade = "update.allow_downgrade" // "true" lets the hub stage an older version
)

// Update channels.
const (
	ChannelStable = "stable"
	ChannelRC     = "rc"
)

// Settings is the part of the settings store this package needs.
type Settings interface {
	Get(ctx context.Context, key string) (value string, ok bool, err error)
	Set(ctx context.Context, key, value string) error
}

// Config is what the Settings view edits.
type Config struct {
	CheckGitHub    bool   `json:"check_github"`
	Channel        string `json:"channel"`
	AllowDowngrade bool   `json:"allow_downgrade"`
}

func loadConfig(ctx context.Context, s Settings) (Config, error) {
	c := Config{Channel: ChannelStable}
	if s == nil {
		return c, nil
	}
	get := func(key string) (string, error) {
		v, _, err := s.Get(ctx, key)
		return v, err
	}
	v, err := get(SettingCheckGitHub)
	if err != nil {
		return c, err
	}
	c.CheckGitHub = v == "true"
	if v, err = get(SettingChannel); err != nil {
		return c, err
	}
	if v == ChannelRC {
		c.Channel = ChannelRC
	}
	if v, err = get(SettingAllowDowngrade); err != nil {
		return c, err
	}
	c.AllowDowngrade = v == "true"
	return c, nil
}

func saveConfig(ctx context.Context, s Settings, c Config) error {
	if c.Channel != ChannelStable && c.Channel != ChannelRC {
		return fmt.Errorf("update: unknown channel %q", c.Channel)
	}
	if s == nil {
		return fmt.Errorf("update: no settings store")
	}
	b := func(v bool) string {
		if v {
			return "true"
		}
		return "false"
	}
	for _, kv := range [][2]string{
		{SettingCheckGitHub, b(c.CheckGitHub)},
		{SettingChannel, c.Channel},
		{SettingAllowDowngrade, b(c.AllowDowngrade)},
	} {
		if err := s.Set(ctx, kv[0], kv[1]); err != nil {
			return err
		}
	}
	return nil
}

// MemorySettings is an in-memory Settings, for tests and the demo.
type MemorySettings struct {
	mu sync.Mutex
	m  map[string]string
}

// NewMemorySettings returns an empty store.
func NewMemorySettings() *MemorySettings { return &MemorySettings{m: map[string]string{}} }

// Get implements Settings.
func (s *MemorySettings) Get(_ context.Context, key string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[key]
	return v, ok, nil
}

// Set implements Settings.
func (s *MemorySettings) Set(_ context.Context, key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[key] = value
	return nil
}
