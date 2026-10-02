package backup

import (
	"os"
	"path/filepath"

	"github.com/phabioo/nexara/internal/config"
	"github.com/phabioo/nexara/internal/pki"
)

// Archive member names. Restore accepts exactly these names and nothing else:
// the archive never decides where a file goes.
const (
	nameManifest  = "manifest.json"
	nameDatabase  = "nexus.db"
	nameConfig    = "nexus.yaml"
	nameCACert    = "tls/" + pki.CACertFile
	nameCAKey     = "tls/" + pki.CAKeyFile
	nameServerPEM = "tls/" + pki.ServerCertFile
	nameServerKey = "tls/" + pki.ServerKeyFile
	nameSecretKey = "secret.key"
	nameSSHKey    = "ssh/id_ed25519"
)

// BackupDirName is the directory for local backups inside the data directory.
const BackupDirName = "backups"

// Layout says where the files of one hub live.
type Layout struct {
	ConfigPath string // nexus.yaml
	Database   string // nexus.db
	TLSDir     string // ca.pem, ca.key, server.pem, server.key
	SecretKey  string // secret.key
	SSHKey     string // <data>/ssh/id_ed25519
	BackupDir  string // <data>/backups (local backups, 0700)
}

// LayoutFor derives the layout from the loaded configuration the same way the
// hub does: everything else lives next to the database.
func LayoutFor(configPath string, cfg config.HubConfig) Layout {
	data := filepath.Dir(cfg.Storage.Database)
	return Layout{
		ConfigPath: configPath,
		Database:   cfg.Storage.Database,
		TLSDir:     cfg.TLS.Dir,
		SecretKey:  filepath.Join(data, "secret.key"),
		SSHKey:     filepath.Join(data, "ssh", "id_ed25519"),
		BackupDir:  filepath.Join(data, BackupDirName),
	}
}

// member describes one file of the archive.
type member struct {
	name     string
	required bool
	mode     os.FileMode
	path     func(Layout) string
}

// members is the fixed content of a backup, in archive order. Not included on
// purpose: the admin socket (/run/nexus), the self-link token and other
// runtime state, the agents' own files, and the backups directory itself.
var members = []member{
	{nameDatabase, true, 0o600, func(l Layout) string { return l.Database }},
	{nameConfig, true, 0o640, func(l Layout) string { return l.ConfigPath }},
	{nameCACert, true, 0o644, func(l Layout) string { return filepath.Join(l.TLSDir, pki.CACertFile) }},
	{nameCAKey, true, 0o600, func(l Layout) string { return filepath.Join(l.TLSDir, pki.CAKeyFile) }},
	{nameServerPEM, false, 0o644, func(l Layout) string { return filepath.Join(l.TLSDir, pki.ServerCertFile) }},
	{nameServerKey, false, 0o600, func(l Layout) string { return filepath.Join(l.TLSDir, pki.ServerKeyFile) }},
	{nameSecretKey, true, 0o600, func(l Layout) string { return l.SecretKey }},
	{nameSSHKey, false, 0o600, func(l Layout) string { return l.SSHKey }},
}

func memberByName(name string) (member, bool) {
	for _, m := range members {
		if m.name == name {
			return m, true
		}
	}
	return member{}, false
}
