package httpserver

import (
	"context"
	"errors"
	"io/fs"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/phabioo/nexara/internal/hub/auth"
	"github.com/phabioo/nexara/internal/hub/backup"
	"github.com/phabioo/nexara/internal/hub/views"
)

// auditBackupSchedule is the audit action of a change of the nightly backup time or count.
const auditBackupSchedule = "backup.schedule"

// routesSettingsBackup registers the Backup card.
//
//	POST /settings/backup/schedule   time=HH:MM keep=N
//	POST /settings/backup/run        "Back up now" (local backup, reason manual)
//	GET  /settings/backup/download   passphrase dialog
//	POST /settings/backup/download   HTMX: check the passphrase and answer with the "ready" dialog;
//	                                 plain form post of that dialog: the encrypted file (attachment)
//	GET  /settings/backup/restore    confirm dialog (?name=)
//	POST /settings/backup/restore    restore a local backup, then restart the hub
//	GET  /settings/restart           the restart dialog, polled until a new hub process answers
//
// The backup service audits creating, downloading and restoring itself.
func (s *Server) routesSettingsBackup(mux *http.ServeMux) {
	mux.HandleFunc("POST /settings/backup/schedule", s.handleBackupSchedule)
	mux.HandleFunc("POST /settings/backup/run", s.handleBackupRun)
	mux.HandleFunc("GET /settings/backup/download", s.handleBackupDownloadDialog)
	mux.HandleFunc("POST /settings/backup/download", s.handleBackupDownload)
	mux.HandleFunc("GET /settings/backup/restore", s.handleBackupRestoreDialog)
	mux.HandleFunc("POST /settings/backup/restore", s.handleBackupRestore)
	mux.HandleFunc("GET /settings/restart", s.handleRestartPoll)
}

func (s *Server) backupCard(ctx context.Context, now time.Time, mod func(*views.SettingsBackup)) (*views.SettingsBackup, error) {
	infos, err := s.svc.Backup.List(ctx)
	if err != nil {
		return nil, err
	}
	card := views.NewSettingsBackup(now, s.svc.Backup.Schedule(ctx), infos, s.svc.Restart != nil)
	if mod != nil {
		mod(card)
	}
	return card, nil
}

func (s *Server) needBackup(w http.ResponseWriter, r *http.Request) bool {
	if s.svc.Backup == nil {
		s.toastError(w, r, http.StatusNotFound, "Not available", "Backups are not available on this hub.")
		return false
	}
	return true
}

// answerBackup answers with the Backup card; errMsg goes into its error row. After a dialog action the dialog is
// closed and the card arrives out of band.
func (s *Server) answerBackup(w http.ResponseWriter, r *http.Request, status int, mod func(*views.SettingsBackup), toast *views.Toast, fromDialog bool) {
	card, err := s.backupCard(r.Context(), s.now(), func(b *views.SettingsBackup) {
		b.OOB = fromDialog
		if mod != nil {
			mod(b)
		}
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	var parts []fragment
	if fromDialog {
		parts = append(parts, closeDialog())
	}
	parts = append(parts, fragment{"settings-backup", card})
	if toast != nil {
		parts = append(parts, toastFragment(toast.Title, toast.Sub))
	}
	s.writeFragments(w, r, status, parts...)
}

func withBackupError(msg string) func(*views.SettingsBackup) {
	return func(b *views.SettingsBackup) { b.Err = msg }
}

// backupProblem maps an error of the backup service to a status and a message that is safe to show.
func backupProblem(err error) (int, string, bool) {
	switch {
	case errors.Is(err, backup.ErrTooNew):
		return http.StatusUnprocessableEntity, "This backup was made by a newer Nexus. Update Nexus first, then restore it.", true
	case errors.Is(err, backup.ErrCorrupt):
		return http.StatusUnprocessableEntity, "The backup file is damaged or has been modified. Nothing was changed.", true
	case errors.Is(err, backup.ErrAuth), errors.Is(err, backup.ErrWrongKeyKind), errors.Is(err, backup.ErrPassphraseRequired):
		return http.StatusUnprocessableEntity, "This backup cannot be opened with this hub's key. Restore a downloaded backup in the setup wizard instead.", true
	case errors.Is(err, backup.ErrNotBackup), errors.Is(err, backup.ErrUnsupportedFormat):
		return http.StatusUnprocessableEntity, "This is not a backup this Nexus can read.", true
	case errors.Is(err, auth.ErrWeakPassphrase):
		return http.StatusUnprocessableEntity, "Use a passphrase of at least " + strconv.Itoa(auth.MinPassphraseLength) + " characters.", true
	case errors.Is(err, context.DeadlineExceeded):
		return http.StatusGatewayTimeout, "The request took too long.", true
	}
	return http.StatusInternalServerError, "", false
}

func (s *Server) handleBackupSchedule(w http.ResponseWriter, r *http.Request) {
	if !s.needBackup(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.toastError(w, r, http.StatusBadRequest, "Not saved", "The form could not be read.")
		return
	}
	at := strings.TrimSpace(r.PostForm.Get("time"))
	keep, kerr := strconv.Atoi(strings.TrimSpace(r.PostForm.Get("keep")))
	// The form shows again what was typed, next to the error.
	typed := func(msg string) func(*views.SettingsBackup) {
		return func(b *views.SettingsBackup) {
			b.Err, b.Time = msg, at
			if kerr == nil {
				b.Keep = keep
			}
		}
	}
	if kerr != nil {
		s.answerBackup(w, r, http.StatusUnprocessableEntity, typed("Keep must be a whole number of backups."), nil, false)
		return
	}
	sc := backup.Schedule{Time: at, Keep: keep}
	if err := backup.ValidateSchedule(sc); err != nil {
		s.answerBackup(w, r, http.StatusUnprocessableEntity, typed(strings.TrimPrefix(err.Error(), "backup: ")), nil, false)
		return
	}
	if err := s.svc.Backup.SetSchedule(r.Context(), sc); err != nil {
		s.log.Error("settings: save backup schedule", "err", err)
		s.auditSettings(r, auditBackupSchedule, "", "save failed", "error")
		s.answerBackup(w, r, http.StatusInternalServerError, typed("The schedule could not be saved."), nil, false)
		return
	}
	s.auditSettings(r, auditBackupSchedule, "", "time="+sc.Time+" keep="+strconv.Itoa(sc.Keep), "ok")
	s.answerBackup(w, r, http.StatusOK, nil, &views.Toast{Title: "Saved", Sub: "Backup | nightly " + sc.Time + ", keeps " + strconv.Itoa(sc.Keep)}, false)
}

func (s *Server) handleBackupRun(w http.ResponseWriter, r *http.Request) {
	if !s.needBackup(w, r) {
		return
	}
	// A backup that was started is finished even when the browser goes away.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), settingsOpTimeout)
	defer cancel()
	info, err := s.svc.Backup.CreateAndPrune(backup.WithActor(ctx, operatorName(r)), backup.ReasonManual)
	if err != nil {
		s.log.Error("settings: manual backup", "err", err)
		s.answerBackup(w, r, http.StatusInternalServerError, withBackupError("The backup could not be created. The hub log has the reason."), nil, false)
		return
	}
	s.answerBackup(w, r, http.StatusOK, nil, &views.Toast{Title: "Backed up", Sub: "Backup | " + views.SizeText(info.Size)}, false)
}

func (s *Server) handleBackupDownloadDialog(w http.ResponseWriter, r *http.Request) {
	if !s.needBackup(w, r) {
		return
	}
	s.writeFragments(w, r, http.StatusOK, fragment{"settings-backup-download", views.BackupPassphraseDialog{PostURL: "/settings/backup/download"}})
}

func (s *Server) backupPassphraseError(w http.ResponseWriter, r *http.Request, status int, msg string) {
	s.writeFragments(w, r, status, fragment{"settings-backup-download", views.BackupPassphraseDialog{PostURL: "/settings/backup/download", Error: msg}})
}

func (s *Server) handleBackupDownload(w http.ResponseWriter, r *http.Request) {
	if !s.needBackup(w, r) {
		return
	}
	pass := r.PostFormValue("passphrase")
	if r.Header.Get("HX-Request") == "true" {
		// Step 1: check what was typed. The file follows from the dialog this answers with.
		switch {
		case pass != r.PostFormValue("confirm"):
			s.backupPassphraseError(w, r, http.StatusUnprocessableEntity, "The passphrases do not match.")
			return
		}
		if err := auth.ValidatePassphrase(pass); err != nil {
			_, msg, _ := backupProblem(err)
			s.backupPassphraseError(w, r, http.StatusUnprocessableEntity, msg)
			return
		}
		sess, _ := SessionFrom(r)
		s.writeFragments(w, r, http.StatusOK, fragment{"settings-backup-ready", views.BackupReadyDialog{
			PostURL: "/settings/backup/download", CSRF: s.auth.CSRFToken(sess), Passphrase: pass,
		}})
		return
	}
	s.streamBackup(w, r, pass)
}

// trackWriter notes whether anything reached the browser, to tell an error that can still be answered from one
// that cut the file short.
type trackWriter struct {
	http.ResponseWriter
	wrote bool
}

func (t *trackWriter) Write(p []byte) (int, error) {
	if len(p) > 0 {
		t.wrote = true
	}
	return t.ResponseWriter.Write(p)
}

func (t *trackWriter) Unwrap() http.ResponseWriter { return t.ResponseWriter }

// streamBackup sends the passphrase-encrypted backup as a download. The backup service does everything that can
// fail before it writes the first byte, so an error then still gets a proper status.
func (s *Server) streamBackup(w http.ResponseWriter, r *http.Request, pass string) {
	name := mime.FormatMediaType("attachment", map[string]string{"filename": s.svc.Backup.DownloadName()})
	if name == "" {
		name = "attachment"
	}
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Disposition", name)
	h.Set("Cache-Control", "no-store")
	tw := &trackWriter{ResponseWriter: w}
	err := s.svc.Backup.WriteDownload(backup.WithActor(r.Context(), operatorName(r)), tw, pass)
	if err == nil {
		return
	}
	if tw.wrote {
		// A truncated file must not look like a finished one: reset the connection.
		s.log.Error("settings: backup download aborted", "err", err)
		panic(http.ErrAbortHandler)
	}
	status, msg, known := backupProblem(err)
	if !known {
		s.log.Error("settings: backup download", "err", err)
		msg = "The backup could not be created."
	}
	h.Del("Content-Disposition")
	s.renderStub(w, status, msg)
}

func (s *Server) handleBackupRestoreDialog(w http.ResponseWriter, r *http.Request) {
	if !s.needBackup(w, r) {
		return
	}
	if s.svc.Restart == nil {
		s.toastError(w, r, http.StatusNotFound, "Not available", "Restoring is not available on this hub.")
		return
	}
	name := r.URL.Query().Get("name")
	infos, err := s.svc.Backup.List(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	for _, in := range infos {
		if in.Name == name && in.Readable {
			s.writeFragments(w, r, http.StatusOK, fragment{"settings-restore-confirm", views.NewBackupRestoreConfirm(s.now(), in)})
			return
		}
	}
	s.toastError(w, r, http.StatusNotFound, "Not found", "That backup no longer exists or cannot be opened.")
}

func (s *Server) handleBackupRestore(w http.ResponseWriter, r *http.Request) {
	if !s.needBackup(w, r) {
		return
	}
	if s.svc.Restart == nil {
		s.toastError(w, r, http.StatusNotFound, "Not available", "Restoring is not available on this hub.")
		return
	}
	// Once started, a restore runs to its end; stopping it halfway is what must not happen.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), settingsOpTimeout)
	defer cancel()
	if _, err := s.svc.Backup.RestoreLocal(backup.WithActor(ctx, operatorName(r)), r.PostFormValue("name")); err != nil {
		status, msg, known := backupProblem(err)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			status, msg = http.StatusNotFound, "That backup no longer exists."
		case !known:
			s.log.Error("settings: restore", "err", err)
			msg = "The backup could not be restored. Nothing was changed."
		case status != http.StatusNotFound && !strings.Contains(msg, "Nothing was changed"):
			msg += " Nothing was changed." // a failed restore leaves the hub as it was (backup.Restore)
		}
		s.answerBackup(w, r, status, withBackupError(msg), nil, true)
		return
	}
	// The running hub still holds the old database: answer first, then stop, and let the service manager start it
	// again on the restored data (decision #55).
	s.writeFragments(w, r, http.StatusOK, fragment{"settings-restarting", views.SettingsRestarting{
		Boot: processBoot, PollURL: views.RestartPollURL(processBoot),
	}})
	s.svc.Restart()
}

// handleRestartPoll answers the restart dialog's poll: the same dialog while this is still the process that did the
// restore, the finished one when another process answers.
func (s *Server) handleRestartPoll(w http.ResponseWriter, r *http.Request) {
	boot := r.URL.Query().Get("boot")
	if !validBoot(boot) {
		boot = ""
	}
	d := views.SettingsRestarting{Boot: boot, PollURL: views.RestartPollURL(boot), Done: boot != processBoot}
	s.writeFragments(w, r, http.StatusOK, fragment{"settings-restarting", d})
}

// validBoot accepts what processBoot looks like, so a polled URL cannot carry anything else back into the dialog.
func validBoot(v string) bool {
	if len(v) != len(processBoot) {
		return false
	}
	for _, c := range []byte(v) {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
