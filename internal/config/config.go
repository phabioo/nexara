// Package config loads, validates and saves the startup configuration files
// nexus.yaml (hub) and agent.yaml (Grid Agent).
//
// YAML holds only values needed before the first start; everything the UI
// creates lives in SQLite. The YAML keys mirror configs/*.example.yaml exactly.
// Loading starts from Default(), so missing optional keys get their defaults,
// and unknown keys are an error (typos must not be silently ignored).
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"go.yaml.in/yaml/v3"
)

// Default locations used by the installer and systemd units.
const (
	DefaultHubConfigPath   = "/etc/nexus/nexus.yaml"
	DefaultAgentConfigPath = "/etc/grid-agent/agent.yaml"
)

// fileMode is the permission of written config files (owner rw, group r).
const fileMode os.FileMode = 0o640

// decodeStrict unmarshals YAML into v, rejecting unknown keys. An empty
// document leaves v untouched.
func decodeStrict(data []byte, v any) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// writeFileAtomic writes data to path through a temp file in the same
// directory followed by a rename, so readers never see a partial file.
func writeFileAtomic(path string, data []byte, mode os.FileMode) (err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("config: create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()
	// Windows has no Unix permission bits; Chmod is best effort there.
	if cerr := tmp.Chmod(mode); cerr != nil && runtime.GOOS != "windows" {
		return fmt.Errorf("config: chmod %s: %w", tmpName, cerr)
	}
	if _, err = tmp.Write(data); err != nil {
		return fmt.Errorf("config: write %s: %w", tmpName, err)
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("config: sync %s: %w", tmpName, err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("config: close %s: %w", tmpName, err)
	}
	if err = os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("config: replace %s: %w", path, err)
	}
	return nil
}

func marshal(header string, v any) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString(header)
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ValidationError collects every problem found by Validate so the operator
// can fix them in one go.
type ValidationError struct {
	Problems []string
}

func (e *ValidationError) Error() string {
	if len(e.Problems) == 1 {
		return "invalid configuration: " + e.Problems[0]
	}
	var b bytes.Buffer
	b.WriteString("invalid configuration:")
	for _, p := range e.Problems {
		b.WriteString("\n  - ")
		b.WriteString(p)
	}
	return b.String()
}

// problems accumulates validation problems.
type problems []string

func (p *problems) addf(format string, args ...any) {
	*p = append(*p, fmt.Sprintf(format, args...))
}

func (p problems) err() error {
	if len(p) == 0 {
		return nil
	}
	return &ValidationError{Problems: p}
}
