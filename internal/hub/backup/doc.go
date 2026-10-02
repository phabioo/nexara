// Package backup creates, lists, verifies and restores Nexus backups
// (decisions #23 and #28).
//
// # What a backup contains
//
// One tar archive with these members, in this order:
//
//	manifest.json     format version, hub version, schema version, creation time
//	                  (UTC), hub name, reason, and for every other member its
//	                  size and SHA-256
//	nexus.db          consistent SQLite snapshot (VACUUM INTO), never a copy of
//	                  the live file
//	nexus.yaml        startup configuration
//	tls/ca.pem        CA certificate and key, server certificate and key
//	tls/ca.key        (server.pem/server.key are optional: the hub re-issues them)
//	tls/server.pem
//	tls/server.key
//	secret.key        master key of the sealed TOTP secrets
//	ssh/id_ed25519    the hub's SSH key (optional, created on first use)
//
// Not included: the admin socket and other runtime state (/run/nexus), the
// self-link token, the agents' own files and the backups directory.
// Restore accepts exactly these member names; the archive never chooses a path.
//
// # File format
//
// The archive is wrapped in an authenticated encryption envelope:
//
//	header (41 bytes, plain text, authenticated as AAD of every chunk)
//	  "NXBKUP"      magic
//	  1 byte        envelope version (1)
//	  1 byte        key kind: 1 = passphrase (argon2id), 2 = local (HKDF)
//	  1 byte        chunk size as log2 (16 = 64 KiB)
//	  uint32 BE     argon2id time cost     (0 for local)
//	  uint32 BE     argon2id memory in KiB (0 for local)
//	  1 byte        argon2id threads       (0 for local)
//	  16 bytes      random salt
//	  7 bytes       random nonce prefix
//	chunk 0 .. chunk n
//	  AES-256-GCM(plaintext chunk of up to 64 KiB), 16-byte tag appended
//
// The nonce of chunk i is prefix || uint32(i) || last, where last is 1 for the
// final chunk and 0 otherwise (the STREAM construction). Truncation, reordering,
// duplication and appended data therefore fail authentication; so does any
// change to the header. The writer and the reader hold one chunk at a time, so
// memory use does not depend on the size of the database.
//
// Key kinds:
//
//	passphrase  key = argon2id(passphrase, salt, header parameters), 32 bytes.
//	            This is the downloadable disaster copy. Parameters are capped on
//	            reading so a hostile file cannot make the hub allocate gigabytes.
//	local       key = HKDF-SHA-256(secret.key, salt, "nexus/v1 local-backup-aes-gcm").
//	            Automatic backups in <data dir>/backups. They have the same
//	            protection as the data itself (whoever can read secret.key can
//	            read the database anyway) and serve rollback on the same device,
//	            for example after a failed update. They cannot restore a hub
//	            whose secret.key is lost: for SD-card failure keep a downloaded
//	            passphrase backup somewhere else.
//
// Local backups are named nexus-<UTC time>-<reason>.nxbk (reason: nightly,
// manual or pre-update), directory mode 0700, files 0600. The newest backup.keep
// (default 7) stay; backup.time (default 03:00, hub time zone) sets the nightly
// run. Both are settings (decision #49).
//
// # API for the views (wave 8)
//
//	svc := backup.New(backup.Options{...})              // app wires it, see internal/hub/app/backup.go
//	svc.WriteDownload(ctx, w, passphrase)               // Settings: download; set the file name from svc.DownloadName()
//	svc.CreateAndPrune(ctx, backup.ReasonManual)        // Settings: "Back up now"
//	svc.List(ctx)                                       // Settings: table of local backups
//	svc.Schedule(ctx) / svc.SetSchedule(ctx, sc)        // Settings: time and number to keep
//	svc.Inspect(ctx, r, passphrase)                     // setup wizard: preview of an uploaded file
//	svc.Restore(ctx, r, passphrase)                     // setup wizard: restore; the hub must restart afterwards
//	svc.RestoreLocal(ctx, name)                         // Settings: roll back to a local backup (restart afterwards)
//
// Use WithActor to put the operator ID into the audit entries. Errors that the
// operator can act on (ErrAuth, ErrCorrupt, ErrTooNew, ErrNotBackup,
// ErrUnsupportedFormat, auth.ErrWeakPassphrase) have readable messages.
//
// # Command line
//
//	nexus backup create [--reason pre-update|nightly|manual] [--keep N]
//	nexus backup list
//	nexus backup inspect <file> [--passphrase-file f]
//	nexus backup restore <file> [--passphrase-file f] [--yes]   (service stopped)
//
// The commands read the user's own files (the backup file, the passphrase
// file) first and then give up root for the nexus user, because everything
// they touch belongs to it: a compromised hub cannot use the root update
// helper to read other files by planting symlinks in /var/lib/nexus, and new
// files get the right owner and mode. `create` works while the hub runs (it
// snapshots the database through a second read-only connection). It prunes
// only when --keep is given; the nightly job applies backup.keep.
//
// # Restore
// //
// Restore first decrypts and verifies the whole file into a staging directory
// next to the data (all chunks, all checksums), checks compatibility (schema
// version not newer than this binary, SQLite integrity, configuration, CA,
// keys) and only then swaps the files in with renames. Replaced files stay
// next to their new versions as <name>.before-restore (one step back). A failed
// or tampered backup changes nothing.
package backup
