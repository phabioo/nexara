package backup

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ArchiveVersion is the version of the archive content (manifest and member
// names), independent of the envelope version. Restore refuses newer ones.
const ArchiveVersion = 1

// Reasons recorded in a manifest and in local file names.
const (
	ReasonNightly   = "nightly"
	ReasonManual    = "manual"
	ReasonPreUpdate = "pre-update"
	ReasonDownload  = "download"
)

// Manifest is manifest.json, the first member of every archive.
type Manifest struct {
	Format        int         `json:"format"`         // ArchiveVersion
	HubVersion    string      `json:"hub_version"`    // buildinfo.Version of the creating hub
	SchemaVersion int         `json:"schema_version"` // SQLite user_version of the snapshot
	CreatedAt     time.Time   `json:"created_at"`     // UTC
	HubName       string      `json:"hub_name"`
	Reason        string      `json:"reason"`
	Files         []FileEntry `json:"files"`
}

// FileEntry lists one archive member.
type FileEntry struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"` // lower-case hex
}

const maxManifestSize = 1 << 20

func parseManifest(b []byte) (Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return m, fmt.Errorf("backup: the manifest is not readable: %w", err)
	}
	if m.Format < 1 {
		return m, errors.New("backup: the manifest has no format version")
	}
	return m, nil
}

// validate checks a manifest that claims to be of a format we understand.
func (m Manifest) validate() error {
	seen := map[string]bool{}
	for _, f := range m.Files {
		if _, ok := memberByName(f.Name); !ok {
			return fmt.Errorf("backup: the manifest lists an unknown file %q", f.Name)
		}
		if seen[f.Name] {
			return fmt.Errorf("backup: the manifest lists %q twice", f.Name)
		}
		seen[f.Name] = true
		if f.Size < 0 || len(f.SHA256) != 64 {
			return fmt.Errorf("backup: the manifest entry for %q is invalid", f.Name)
		}
	}
	for _, mem := range members {
		if mem.required && !seen[mem.name] {
			return fmt.Errorf("backup: the backup does not contain %s", mem.name)
		}
	}
	return nil
}
