package views

import (
	"fmt"
	"time"

	"github.com/phabioo/nexara/internal/hub/backup"
)

// SettingsBackupRow is one local backup.
type SettingsBackupRow struct {
	Name       string
	When       string
	Reason     string
	Size       string
	Readable   bool
	RestoreURL string // GET: the confirm dialog; empty when restoring is not possible
}

// SettingsBackup is the Backup card.
type SettingsBackup struct {
	Schedule string // "Nightly 03:00 · keeps 7 · before updates"
	Time     string
	Keep     int
	Last     string
	Backups  []SettingsBackupRow
	// Err is the error row of a failed action (invalid schedule, backup failed).
	Err string
	// OOB renders the card as an out-of-band swap (the answer to a dialog).
	OOB bool
}

func reasonLabel(r string) string {
	switch r {
	case backup.ReasonNightly:
		return "Nightly"
	case backup.ReasonManual:
		return "Manual"
	case backup.ReasonPreUpdate:
		return "Before update"
	}
	return capitalize(r)
}

// NewSettingsBackup builds the card. canRestore is false when the hub cannot restart itself (demo).
func NewSettingsBackup(now time.Time, sc backup.Schedule, infos []backup.Info, canRestore bool) *SettingsBackup {
	b := &SettingsBackup{
		Time: sc.Time, Keep: sc.Keep, Last: "No backup yet",
		Schedule: fmt.Sprintf("Nightly %s · keeps %d · before updates", sc.Time, sc.Keep),
	}
	for i, in := range infos {
		row := SettingsBackupRow{
			Name: in.Name, When: SettingsWhen(now, in.CreatedAt), Reason: reasonLabel(in.Reason),
			Size: SizeText(in.Size), Readable: in.Readable,
		}
		if canRestore && in.Readable {
			row.RestoreURL = "/settings/backup/restore?name=" + in.Name
		}
		if i == 0 {
			b.Last = row.When + " · " + row.Size
		}
		b.Backups = append(b.Backups, row)
	}
	return b
}

// BackupPassphraseDialog is the data of the download dialog (step 1: the passphrase twice).
type BackupPassphraseDialog struct {
	PostURL string
	Error   string
	NoCode  bool // the operator has no authenticator (demo): the step-up asks for the passphrase only
}

// BackupReadyDialog is step 2: the passphrase was accepted, the browser posts it again to fetch the file.
// The passphrase stays in the dialog (a hidden field) and nowhere on the server. Grant is the single-use token the
// step-up issued; the file is only sent against it.
type BackupReadyDialog struct {
	PostURL    string
	CSRF       string
	Passphrase string
	Grant      string
}

// BackupRestoreConfirm is the confirm dialog of "Restore".
type BackupRestoreConfirm struct {
	Name    string
	When    string
	Reason  string
	PostURL string
	Error   string // step-up failure
	NoCode  bool
}

// NewBackupRestoreConfirm builds the dialog for one local backup.
func NewBackupRestoreConfirm(now time.Time, in backup.Info) BackupRestoreConfirm {
	return BackupRestoreConfirm{
		Name: in.Name, When: SettingsWhen(now, in.CreatedAt), Reason: reasonLabel(in.Reason), PostURL: "/settings/backup/restore",
	}
}

// SettingsRestarting is the dialog shown while the hub restarts after a restore. It polls until a new hub process
// answers (its boot ID differs).
type SettingsRestarting struct {
	Boot    string
	PollURL string
	Done    bool
	Failed  bool // the restore did not go through, but the hub had closed its database and restarts to recover
}

// RestartPollURL returns the polling URL for a boot ID.
func RestartPollURL(boot string) string { return "/settings/restart?boot=" + boot }

// RestartFailedPollURL is the polling URL of the dialog for a restore that failed after the database was closed.
func RestartFailedPollURL(boot string) string { return RestartPollURL(boot) + "&failed=1" }
