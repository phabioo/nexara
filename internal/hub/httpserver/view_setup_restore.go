package httpserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/phabioo/nexara/internal/hub/auth"
	"github.com/phabioo/nexara/internal/hub/backup"
	"github.com/phabioo/nexara/internal/hub/setup"
	"github.com/phabioo/nexara/internal/hub/store"
)

// Restore from a backup in the setup wizard (decisions #28 lifted, #55).
//
// Everything here sits behind the setup session, so the setup code gates it:
// no route answers anything but a redirect to the Unlock step until the code
// was verified. The flow:
//
//	Unlock ("Restore from a backup instead" submits the code form with restore=1)
//	  -> GET  /setup/restore                upload form (file + passphrase)
//	  -> POST /setup/restore/upload         stream to a temp file, Inspect, preview
//	  -> POST /setup/restore/confirm        Restore, answer "Restored", then Restart
//	  -> POST /setup/restore/cancel         throw the upload away
//
// A failed check or restore changes nothing (the backup package guarantees
// that for Restore); the temp file is deleted in every error path.

const (
	setupRestorePath    = "/setup/restore"
	setupRestoreUpload  = "/setup/restore/upload"
	setupRestoreConfirm = "/setup/restore/confirm"
	setupRestoreCancel  = "/setup/restore/cancel"

	// restoreIdleTimeout is how long the browser may stay silent while
	// uploading. It replaces the fixed body deadline of the other routes,
	// which would cut off a slow upload.
	restoreIdleTimeout = 30 * time.Second
	// maxRestoreField caps the small text fields (token, passphrase).
	maxRestoreField = 4 << 10

	fieldBackupFile       = "backup"
	fieldBackupPassphrase = "passphrase"
)

// maxRestoreUpload caps the uploaded file. A hub's backup is its database
// (history included), a few keys and certificates: tens of megabytes. The cap
// keeps a client from filling the disk of a Pi. A variable so tests can use a
// small one.
var maxRestoreUpload int64 = 512 << 20

// isRestoreUpload reports the one path whose body is a large multipart
// upload: the generic body limit and the generic CSRF body read skip it, and
// the handler enforces both itself (size, idle timeout, token in the first part).
func isRestoreUpload(p string) bool { return p == setupRestoreUpload }

// setupRestorer is what the restore needs from the backup service.
type setupRestorer interface {
	Inspect(ctx context.Context, r io.Reader, passphrase string) (backup.Manifest, error)
	Restore(ctx context.Context, r io.Reader, passphrase string) (*backup.RestoreResult, error)
}

// restorer returns the backup service, or nil when restoring is not offered
// (demo, tests without backup).
func (s *Server) restorer() setupRestorer {
	if s.svc.Backup == nil {
		return nil
	}
	return s.svc.Backup
}

// setupRestoreView is the data of the restore pages (inside setupPage).
type setupRestoreView struct {
	MaxSize string
	// Preview rows of the checked backup.
	Rows []setupSummaryRow
	// Done page.
	AutoRestart bool
}

func (s *Server) routesSetupRestore(mux *http.ServeMux) {
	mux.HandleFunc("GET "+setupRestorePath, s.handleSetupRestoreGet)
	mux.HandleFunc("POST "+setupRestoreUpload, s.handleSetupRestoreUpload)
	mux.HandleFunc("POST "+setupRestoreConfirm, s.handleSetupRestoreConfirm)
	mux.HandleFunc("POST "+setupRestoreCancel, s.handleSetupRestoreCancel)
}

// restoreSession is the common gate: restoring must be on offer, and the
// request must carry a setup session (the code was verified). It writes the
// answer and returns false otherwise.
func (s *Server) restoreSession(w http.ResponseWriter, r *http.Request) (*setup.Session, bool) {
	if s.restorer() == nil {
		s.notFound(w, r)
		return nil, false
	}
	sess, ok := s.setup.Sessions.FromRequest(r)
	if !ok {
		if r.Method == http.MethodGet {
			s.setupRedirect(w, r, "/setup")
		} else {
			p := s.setupUnlockPage(w, r, false)
			p.Errors = []string{setupSessionExpired}
			s.renderSetup(w, r, http.StatusUnauthorized, p)
		}
		return nil, false
	}
	return sess, true
}

// setupRestoreBase is the card of the restore pages: the Unlock step stays
// the current step (as in the mockup), the card carries its own copy.
func (s *Server) setupRestoreBase(w http.ResponseWriter, r *http.Request, key, title, tag, lead, log string) *setupPage {
	p := s.setupBase(w, r, setup.StepUnlock, log)
	p.Key, p.Title, p.Tag, p.Lead = key, title, tag, lead
	p.LeadShort = ""
	p.Back = ""
	p.RestoreAvailable = true
	p.Restore = &setupRestoreView{MaxSize: fmt.Sprintf("%d MB", maxRestoreUpload>>20)}
	return p
}

func (s *Server) setupRestoreUploadPage(w http.ResponseWriter, r *http.Request, errs ...string) *setupPage {
	p := s.setupRestoreBase(w, r, "restore", "Restore from backup", "Restore",
		"Upload a backup you downloaded from Settings › Backup and enter its passphrase. The file is checked first; nothing changes until you confirm.",
		"Hub claimed · choose a backup to restore")
	p.NextLabel = "Check backup"
	p.Errors = errs
	if len(errs) > 0 {
		p.Log = "Backup rejected · nothing was changed"
	}
	return p
}

func (s *Server) setupRestorePreviewPage(w http.ResponseWriter, r *http.Request, up setup.Upload, errs ...string) *setupPage {
	p := s.setupRestoreBase(w, r, "restore-preview", "Restore this backup?", "Backup verified",
		"The backup is complete and its checksums match. Restoring replaces everything this hub has now (operators, hosts, history, certificates, settings) and restarts Nexus.",
		"Backup verified · waiting for confirmation")
	p.NextLabel = "Restore and restart"
	p.Errors = errs
	pv := up.Preview
	p.Restore.Rows = []setupSummaryRow{
		{"File", fmt.Sprintf("%s · %s", up.Name, setupByteSize(up.Size))},
		{"Hub", pv.HubName},
		{"Created", pv.CreatedAt.UTC().Format("2006-01-02 15:04 UTC")},
		{"Made by Nexus", pv.HubVersion},
		{"Database schema", strconv.Itoa(pv.SchemaVersion)},
		{"Kind", pv.Reason},
	}
	return p
}

func setupByteSize(n int64) string {
	switch {
	case n >= 10<<20:
		return fmt.Sprintf("%d MB", n>>20)
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%d KB", n>>10)
	}
	return fmt.Sprintf("%d bytes", n)
}

func (s *Server) handleSetupRestoreGet(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.restoreSession(w, r)
	if !ok {
		return
	}
	if up, has := sess.Upload(); has {
		s.renderSetup(w, r, http.StatusOK, s.setupRestorePreviewPage(w, r, up))
		return
	}
	s.renderSetup(w, r, http.StatusOK, s.setupRestoreUploadPage(w, r))
}

func (s *Server) handleSetupRestoreCancel(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.restoreSession(w, r)
	if !ok {
		return
	}
	sess.DropUpload()
	s.setupRedirect(w, r, setupRestorePath)
}

// idleReader extends the connection's read deadline before every read, so an
// upload may take as long as it likes while the browser keeps sending.
type idleReader struct {
	r    io.Reader
	rc   *http.ResponseController
	idle time.Duration
}

func (i idleReader) Read(p []byte) (int, error) {
	_ = i.rc.SetReadDeadline(time.Now().Add(i.idle)) // unsupported writers (tests) just skip it
	return i.r.Read(p)
}

// restoreUploadError is a problem with the request itself.
type restoreUploadError struct {
	status int
	msg    string
}

func (e *restoreUploadError) Error() string { return e.msg }

func (s *Server) handleSetupRestoreUpload(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.restoreSession(w, r)
	if !ok {
		return
	}
	ip := ClientIP(r)
	rc := http.NewResponseController(w)
	defer func() { _ = rc.SetReadDeadline(time.Time{}) }()

	body := http.MaxBytesReader(w, r.Body, maxRestoreUpload+(1<<20))
	r.Body = struct {
		io.Reader
		io.Closer
	}{idleReader{r: body, rc: rc, idle: restoreIdleTimeout}, body}
	mr, err := r.MultipartReader()
	if err != nil {
		s.renderSetup(w, r, http.StatusBadRequest, s.setupRestoreUploadPage(w, r, "Choose a backup file and enter its passphrase."))
		return
	}

	// 1. The CSRF token must be the first part: the (possibly huge) file is not
	// touched before the request has proven it comes from our form.
	if !s.restoreCSRFOK(r, mr) {
		s.log.Warn("csrf check failed", "method", r.Method, "path", logPath(r), "ip", ip)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// 2. Attempt limits and the single work slot, before any disk or argon2 work.
	limits := s.setup.Sessions.RestoreLimits()
	if allowed, retry := limits.Allow(ip); !allowed {
		s.log.Warn("setup restore rate limited", "ip", ip)
		s.restoreAudit(r.Context(), store.AuditDenied, "ip="+ip+" reason=rate_limited")
		secs := int((retry + time.Second - 1) / time.Second)
		w.Header().Set("Retry-After", strconv.Itoa(max(secs, 1)))
		mins := max(int((retry+time.Minute-1)/time.Minute), 1)
		s.renderSetup(w, r, http.StatusTooManyRequests, s.setupRestoreUploadPage(w, r,
			fmt.Sprintf("Too many restore attempts. Try again in %d minute%s.", mins, plural(mins))))
		return
	}
	release, free := limits.Begin()
	if !free {
		w.Header().Set("Retry-After", "10")
		s.renderSetup(w, r, http.StatusServiceUnavailable, s.setupRestoreUploadPage(w, r, "Another backup is being checked right now. Try again in a moment."))
		return
	}
	defer release()

	// 3. The rest of the form: passphrase and the file, in any order.
	dir := s.setup.Sessions.UploadDir()
	var (
		passphrase string
		havePass   bool
		tmpPath    string
		fileName   string
		size       int64
	)
	keep := false
	defer func() {
		if tmpPath != "" && !keep {
			_ = os.Remove(tmpPath)
		}
	}()
	fail := func(status int, msg, reason string) {
		s.restoreAudit(r.Context(), store.AuditDenied, "ip="+ip+" reason="+reason)
		s.renderSetup(w, r, status, s.setupRestoreUploadPage(w, r, msg))
	}
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			s.restoreReadFailed(w, r, err)
			return
		}
		switch part.FormName() {
		case fieldBackupPassphrase:
			v, err := readSmallField(part)
			if err != nil {
				fail(http.StatusBadRequest, "That passphrase is too long.", "bad_field")
				return
			}
			passphrase, havePass = v, true
		case fieldBackupFile:
			if tmpPath != "" {
				fail(http.StatusBadRequest, "Send one backup file only.", "bad_form")
				return
			}
			tmpPath, size, err = s.saveUpload(dir, part)
			fileName = displayFileName(part.FileName())
			if err != nil {
				var ue *restoreUploadError
				if errors.As(err, &ue) {
					fail(ue.status, ue.msg, "bad_upload")
				} else {
					s.restoreReadFailed(w, r, err)
				}
				return
			}
		default:
			_, _ = io.Copy(io.Discard, io.LimitReader(part, maxRestoreField)) // unknown field: ignore
		}
	}
	switch {
	case tmpPath == "" || size == 0:
		fail(http.StatusBadRequest, "Choose a backup file (.nxbk).", "no_file")
		return
	case !havePass || passphrase == "":
		fail(http.StatusBadRequest, "Enter the passphrase of this backup.", "no_passphrase")
		return
	}

	// 4. Check the backup completely: key derivation, every chunk, every checksum.
	f, err := os.Open(tmpPath)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	man, err := s.restorer().Inspect(r.Context(), f, passphrase)
	_ = f.Close()
	if err != nil {
		msg, status := restoreErrorMessage(err)
		if status == http.StatusInternalServerError {
			s.log.Error("setup restore: check failed", "err", err)
		} else {
			s.log.Warn("setup restore: backup rejected", "ip", ip, "reason", err)
		}
		fail(status, msg, "inspect_failed")
		return
	}

	keep = true
	sess.SetUpload(setup.Upload{
		Path: tmpPath, Name: fileName, Size: size, Passphrase: passphrase,
		Preview: setup.RestorePreview{
			HubName: man.HubName, HubVersion: man.HubVersion, Reason: man.Reason,
			CreatedAt: man.CreatedAt, SchemaVersion: man.SchemaVersion, Files: len(man.Files),
		},
	})
	s.log.Info("setup restore: backup checked", "ip", ip, "bytes", size)
	s.setupRedirect(w, r, setupRestorePath)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// restoreCSRFOK reads the first part and checks it against the double-submit
// cookie.
func (s *Server) restoreCSRFOK(r *http.Request, mr *multipart.Reader) bool {
	part, err := mr.NextPart()
	if err != nil || part.FormName() != auth.CSRFFormField {
		return false
	}
	tok, err := readSmallField(part)
	if err != nil {
		return false
	}
	c, err := r.Cookie(s.auth.Cookies().CSRFName())
	return err == nil && auth.CheckDoubleSubmit(c.Value, tok)
}

func readSmallField(part *multipart.Part) (string, error) {
	b, err := io.ReadAll(io.LimitReader(part, maxRestoreField+1))
	if err != nil {
		return "", err
	}
	if len(b) > maxRestoreField {
		return "", errors.New("field too long")
	}
	return string(b), nil
}

// restoreReadFailed answers a request whose body broke off or was too large.
func (s *Server) restoreReadFailed(w http.ResponseWriter, r *http.Request, err error) {
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) {
		s.renderSetup(w, r, http.StatusRequestEntityTooLarge, s.setupRestoreUploadPage(w, r,
			fmt.Sprintf("That file is larger than %d MB.", maxRestoreUpload>>20)))
		return
	}
	s.log.Warn("setup restore: upload failed", "ip", ClientIP(r), "err", err)
	s.renderSetup(w, r, http.StatusBadRequest, s.setupRestoreUploadPage(w, r, "The upload did not arrive completely. Try again."))
}

// saveUpload streams the file part into a new 0600 file in dir.
func (s *Server) saveUpload(dir string, part *multipart.Part) (path string, size int64, err error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", 0, err
	}
	f, err := os.CreateTemp(dir, ".upload-*.tmp")
	if err != nil {
		return "", 0, err
	}
	path = f.Name()
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			_ = os.Remove(path)
			path = ""
		}
	}()
	n, err := io.Copy(f, io.LimitReader(part, maxRestoreUpload+1))
	if err != nil {
		return path, n, err
	}
	if n > maxRestoreUpload {
		return path, n, &restoreUploadError{http.StatusRequestEntityTooLarge, fmt.Sprintf("That file is larger than %d MB.", maxRestoreUpload>>20)}
	}
	return path, n, f.Sync()
}

// displayFileName shortens the browser-supplied name for display only (it is
// never used as a path).
func displayFileName(n string) string {
	n = filepath.Base(strings.ReplaceAll(n, "\\", "/"))
	var b strings.Builder
	for _, r := range n {
		if r < ' ' || r == 0x7f {
			continue
		}
		b.WriteRune(r)
		if b.Len() >= 80 {
			break
		}
	}
	if b.Len() == 0 || n == "." || n == "/" {
		return "backup.nxbk"
	}
	return b.String()
}

// restoreErrorMessage maps the errors of Inspect and Restore to the copy the
// operator sees and a status. Anything unknown is generic (and logged by the
// caller): paths and internals stay out of the page.
func restoreErrorMessage(err error) (string, int) {
	switch {
	case errors.Is(err, backup.ErrAuth):
		return "Wrong passphrase, or the file is damaged.", http.StatusUnprocessableEntity
	case errors.Is(err, backup.ErrCorrupt):
		return "The file is damaged or has been modified. Download the backup again.", http.StatusUnprocessableEntity
	case errors.Is(err, backup.ErrNotBackup):
		return "This is not a Nexara backup file.", http.StatusUnprocessableEntity
	case errors.Is(err, backup.ErrTooNew), errors.Is(err, backup.ErrUnsupportedFormat):
		return "This backup was made by a newer Nexus than this one. Update Nexus first, then restore.", http.StatusUnprocessableEntity
	case errors.Is(err, backup.ErrWrongKeyKind), errors.Is(err, backup.ErrPassphraseRequired):
		return "This is an automatic backup of a hub. Restore a backup you downloaded with a passphrase instead.", http.StatusUnprocessableEntity
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "The check was interrupted. Try again.", http.StatusServiceUnavailable
	}
	if m := err.Error(); strings.HasPrefix(m, "backup: ") && !strings.ContainsAny(m, "/\\") {
		// The backup package words these for the screen (manifest and content problems).
		m = strings.TrimPrefix(m, "backup: ")
		return strings.ToUpper(m[:1]) + m[1:] + ".", http.StatusUnprocessableEntity
	}
	return "The backup could not be checked.", http.StatusInternalServerError
}

func (s *Server) handleSetupRestoreConfirm(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.restoreSession(w, r)
	if !ok {
		return
	}
	ip := ClientIP(r)
	release, free := s.setup.Sessions.RestoreLimits().Begin()
	if !free {
		w.Header().Set("Retry-After", "10")
		s.renderSetup(w, r, http.StatusServiceUnavailable, s.setupRestoreUploadPage(w, r, "Another backup is being restored right now."))
		return
	}
	defer release()

	up, has := sess.TakeUpload() // of two concurrent confirms only one gets the file
	if !has {
		s.setupRedirect(w, r, setupRestorePath)
		return
	}
	defer func() { _ = os.Remove(up.Path) }()
	f, err := os.Open(up.Path)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	defer f.Close()

	// The restore must not be interrupted half way by the browser going away.
	// The wizard's own entries (unlock, refused uploads) sit in the database
	// that the restore replaces: hand them over, so they end up in the
	// restored one together with the restore entry and the client address
	// (security review A-09). A failed restore is audited by the backup
	// service itself, with the same address.
	ctx := backup.WithRemoteAddr(backup.WithActor(context.WithoutCancel(r.Context()), "setup"), ip)
	ctx = backup.WithCarriedAudit(ctx, s.setupAuditEntries(ctx))
	res, err := s.restorer().Restore(ctx, f, up.Passphrase)
	up.Passphrase = ""
	if err != nil {
		msg, status := restoreErrorMessage(err)
		s.log.Error("setup restore failed", "ip", ip, "err", err)
		s.renderSetup(w, r, status, s.setupRestoreUploadPage(w, r, msg+" Nothing was changed."))
		return
	}
	s.log.Info("setup restore: backup restored", "ip", ip, "replaced_files", len(res.Replaced), "config_adjusted", res.ConfigAdjusted)

	// The hub on these files is finished: no more wizard steps, no setup code.
	// The old process keeps its stale database until it exits, so nothing else
	// may be served from it for long.
	s.setup.Sessions.Clear()
	s.setup.Codes.Invalidate()
	http.SetCookie(w, s.setup.Sessions.ClearCookie())

	lead := "The backup is in place. Nexus restarts now with the restored data; this page continues to the sign-in page when the hub is back. Grid Agents reconnect on their own."
	if len(res.Replaced) > 0 {
		// The old keys stay readable on disk until somebody deletes them (security review B-07).
		lead += " The files this hub had before, including its old keys and certificates, are kept next to the new ones as *" +
			backup.BeforeRestoreSuffix + ". Delete them once you are sure."
	}
	p := s.setupRestoreBase(w, r, "restore-done", "Restored", "Done", lead, "Backup restored · Nexus restarts")
	p.Back = ""
	p.Banner = "Restored"
	p.Restore.AutoRestart = s.svc.Restart != nil
	s.renderSetup(w, r, http.StatusOK, p)
	_ = http.NewResponseController(w).Flush()
	if restart := s.svc.Restart; restart != nil {
		// The hub exits only after the response is out: net/http cancels the
		// request context when this handler returns (the flush above already
		// put the page on the wire), and the service manager then starts the
		// hub on the restored files.
		ctx := r.Context()
		go func() {
			<-ctx.Done()
			restart()
		}()
	}
}

// maxCarriedAudit bounds how many setup entries a restore copies over.
const maxCarriedAudit = 500

// setupAuditEntries returns the audit entries written during setup, oldest
// first. A hub in setup mode has no operator, so they are all "setup" entries.
func (s *Server) setupAuditEntries(ctx context.Context) []store.AuditEntry {
	if s.svc.Store == nil {
		return nil
	}
	list, err := s.svc.Store.ListAudit(ctx, maxCarriedAudit)
	if err != nil {
		s.log.Warn("setup restore: reading the setup audit entries failed", "err", err)
		return nil
	}
	var out []store.AuditEntry
	for i := len(list) - 1; i >= 0; i-- { // ListAudit is newest first
		if list[i].User == "setup" {
			out = append(out, list[i])
		}
	}
	return out
}

// restoreAudit records a refused or failed restore in the (still empty) hub's
// audit log. Best effort; it never contains the passphrase or the file.
func (s *Server) restoreAudit(ctx context.Context, result, detail string) {
	if s.svc.Store == nil {
		return
	}
	_, err := s.svc.Store.AppendAudit(ctx, store.AuditEntry{
		Time: s.now().UTC(), User: "setup", Action: backup.ActionRestore, Detail: detail, Result: result,
	})
	if err != nil {
		s.log.Error("write audit entry failed", "action", backup.ActionRestore, "err", err)
	}
}
