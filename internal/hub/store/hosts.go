package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Host is a row of the hosts table.
type Host struct {
	ID              string // opaque, see NewID
	Name            string // unique short name
	DisplayName     string
	Address         string
	OS              string
	Arch            string
	AgentVersion    string
	CertFingerprint string // hex SHA-256 of the agent client certificate
	CertSerial      string
	CertNotAfter    time.Time // zero = unset
	MAC             string
	Capabilities    []string // enabled capability names
	Revoked         bool
	CreatedAt       time.Time
	LastSeenAt      time.Time // zero = never connected
}

// HostStatus are the fields refreshed when an agent connects. UpdateHostStatus
// overwrites all of them, so read the host first to change only one field.
type HostStatus struct {
	Address      string
	OS           string
	Arch         string
	AgentVersion string
	MAC          string
	Capabilities []string
	LastSeenAt   time.Time
}

const hostCols = `id, name, display_name, address, os, arch, agent_version, cert_fingerprint, cert_serial,
	cert_not_after, mac, capabilities, revoked, created_at, last_seen_at`

func scanHost(row interface{ Scan(...any) error }) (Host, error) {
	var (
		h        Host
		notAfter sql.NullInt64
		lastSeen sql.NullInt64
		caps     string
		revoked  int
		created  int64
	)
	err := row.Scan(&h.ID, &h.Name, &h.DisplayName, &h.Address, &h.OS, &h.Arch, &h.AgentVersion,
		&h.CertFingerprint, &h.CertSerial, &notAfter, &h.MAC, &caps, &revoked, &created, &lastSeen)
	if errors.Is(err, sql.ErrNoRows) {
		return Host{}, ErrNotFound
	}
	if err != nil {
		return Host{}, err
	}
	if err := json.Unmarshal([]byte(caps), &h.Capabilities); err != nil {
		return Host{}, fmt.Errorf("store: host %s has corrupt capabilities: %w", h.ID, err)
	}
	h.CertNotAfter, h.LastSeenAt = fromNull(notAfter), fromNull(lastSeen)
	h.Revoked = revoked != 0
	h.CreatedAt = fromUnix(created)
	return h, nil
}

func encodeCaps(caps []string) (string, error) {
	if caps == nil {
		caps = []string{}
	}
	b, err := json.Marshal(caps)
	return string(b), err
}

// CreateHost inserts a host. Name is required. ID is generated when empty and
// CreatedAt defaults to now. ErrExists if the name (or ID) is taken.
func (s *Store) CreateHost(ctx context.Context, h Host) (Host, error) {
	if h.Name == "" {
		return Host{}, errors.New("store: host needs a name")
	}
	if h.ID == "" {
		h.ID = NewID()
	}
	if h.CreatedAt.IsZero() {
		h.CreatedAt = s.now()
	}
	h.CreatedAt = fromUnix(unix(h.CreatedAt))
	caps, err := encodeCaps(h.Capabilities)
	if err != nil {
		return Host{}, err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO hosts (`+hostCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		h.ID, h.Name, h.DisplayName, h.Address, h.OS, h.Arch, h.AgentVersion, h.CertFingerprint, h.CertSerial,
		nullUnix(h.CertNotAfter), h.MAC, caps, boolInt(h.Revoked), unix(h.CreatedAt), nullUnix(h.LastSeenAt))
	if isUnique(err) {
		return Host{}, ErrExists
	}
	if err != nil {
		return Host{}, fmt.Errorf("store: create host: %w", err)
	}
	return h, nil
}

// GetHost returns the host with the given ID. ErrNotFound if unknown.
func (s *Store) GetHost(ctx context.Context, id string) (Host, error) {
	return scanHost(s.db.QueryRowContext(ctx, "SELECT "+hostCols+" FROM hosts WHERE id = ?", id))
}

// GetHostByName returns the host with the given unique name. ErrNotFound if unknown.
func (s *Store) GetHostByName(ctx context.Context, name string) (Host, error) {
	return scanHost(s.db.QueryRowContext(ctx, "SELECT "+hostCols+" FROM hosts WHERE name = ?", name))
}

// GetHostByFingerprint looks a host up by its client certificate fingerprint
// (used to authenticate agents after the mTLS handshake). Revoked hosts are
// returned with Revoked set; callers must reject them. ErrNotFound if unknown
// or fingerprint is empty.
func (s *Store) GetHostByFingerprint(ctx context.Context, fingerprint string) (Host, error) {
	if fingerprint == "" {
		return Host{}, ErrNotFound
	}
	return scanHost(s.db.QueryRowContext(ctx, "SELECT "+hostCols+" FROM hosts WHERE cert_fingerprint = ?", fingerprint))
}

// ListHosts returns all hosts, including revoked ones, oldest first.
func (s *Store) ListHosts(ctx context.Context) ([]Host, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+hostCols+" FROM hosts ORDER BY created_at, name")
	if err != nil {
		return nil, fmt.Errorf("store: list hosts: %w", err)
	}
	defer rows.Close()
	var out []Host
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, fmt.Errorf("store: list hosts: %w", err)
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// UpdateHostStatus overwrites the fields in HostStatus. ErrNotFound if unknown.
func (s *Store) UpdateHostStatus(ctx context.Context, id string, st HostStatus) error {
	caps, err := encodeCaps(st.Capabilities)
	if err != nil {
		return err
	}
	return affected(s.db.ExecContext(ctx,
		`UPDATE hosts SET address = ?, os = ?, arch = ?, agent_version = ?, mac = ?, capabilities = ?, last_seen_at = ?
		 WHERE id = ?`,
		st.Address, st.OS, st.Arch, st.AgentVersion, st.MAC, caps, nullUnix(st.LastSeenAt), id))
}

// TouchHost sets last_seen_at only (e.g. when an agent disconnects).
func (s *Store) TouchHost(ctx context.Context, id string, seen time.Time) error {
	return affected(s.db.ExecContext(ctx, "UPDATE hosts SET last_seen_at = ? WHERE id = ?", nullUnix(seen), id))
}

// SetHostCert records the issued client certificate (enrollment and renewal).
func (s *Store) SetHostCert(ctx context.Context, id, fingerprint, serial string, notAfter time.Time) error {
	return affected(s.db.ExecContext(ctx,
		"UPDATE hosts SET cert_fingerprint = ?, cert_serial = ?, cert_not_after = ? WHERE id = ?",
		fingerprint, serial, nullUnix(notAfter), id))
}

// ReplaceHostCert swaps the client certificate of a renewal (decision #47) in
// one statement: fingerprint, serial and expiry change together, and only if
// the host still carries oldFingerprint and is not revoked. A concurrent
// renewal, a re-enrollment or a removal therefore makes the swap fail with
// ErrNotFound instead of overwriting the newer state.
func (s *Store) ReplaceHostCert(ctx context.Context, id, oldFingerprint, newFingerprint, serial string, notAfter time.Time) error {
	if newFingerprint == "" {
		return errors.New("store: new certificate fingerprint is required")
	}
	return affected(s.db.ExecContext(ctx,
		`UPDATE hosts SET cert_fingerprint = ?, cert_serial = ?, cert_not_after = ?
		 WHERE id = ? AND cert_fingerprint = ? AND revoked = 0`,
		newFingerprint, serial, nullUnix(notAfter), id, oldFingerprint))
}

// SetHostDisplayName changes the display name.
func (s *Store) SetHostDisplayName(ctx context.Context, id, displayName string) error {
	return affected(s.db.ExecContext(ctx, "UPDATE hosts SET display_name = ? WHERE id = ?", displayName, id))
}

// RevokeHost marks the host revoked. The caller is responsible for dropping
// its connection and recording the certificate serial in the CA's revocation list.
func (s *Store) RevokeHost(ctx context.Context, id string) error {
	return affected(s.db.ExecContext(ctx, "UPDATE hosts SET revoked = 1 WHERE id = ?", id))
}

// RetireHost revokes the host and frees its name: the row stays (the revoked
// flag and the certificate fingerprint keep rejecting the old agent, audit
// entries keep their context), but the unique name becomes "<name>~<id>" so a
// device with the same host name can be linked again as a new host (decision
// #47). Retiring an already revoked host changes nothing. ErrNotFound if unknown.
func (s *Store) RetireHost(ctx context.Context, id string) error {
	return affected(s.db.ExecContext(ctx,
		`UPDATE hosts SET name = CASE WHEN revoked = 0 THEN name || '~' || id ELSE name END, revoked = 1
		 WHERE id = ?`, id))
}

// DeleteHost removes the host row (host removal in Settings; revoke first).
// Enrollment tokens that referenced it keep existing with host_id NULL; audit
// entries are unaffected.
func (s *Store) DeleteHost(ctx context.Context, id string) error {
	return affected(s.db.ExecContext(ctx, "DELETE FROM hosts WHERE id = ?", id))
}
