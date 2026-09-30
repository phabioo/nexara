package main

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/phabioo/nexara/internal/config"
)

func TestLoadAgentTLSNotEnrolled(t *testing.T) {
	dir := t.TempDir()
	cfg := config.DefaultAgent()
	cfg.TLS = config.AgentTLSSection{
		CA:   filepath.Join(dir, "ca.pem"),
		Cert: filepath.Join(dir, "agent.pem"),
		Key:  filepath.Join(dir, "agent.key"),
	}
	if _, err := loadAgentTLS(cfg); !errors.Is(err, errNotEnrolled) {
		t.Fatalf("err = %v, want errNotEnrolled", err)
	}
}
