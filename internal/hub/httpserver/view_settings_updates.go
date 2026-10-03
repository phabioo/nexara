package httpserver

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/phabioo/nexara/internal/hub/update"
	"github.com/phabioo/nexara/internal/hub/views"
)

// uploadPathUpdate is the one request that may carry a body of the size of a release package. bodylimit.go and the
// CSRF middleware size their limits by it (bodyLimit).
const uploadPathUpdate = "/settings/updates/upload"

// routesSettingsUpdates registers the Updates card.
//
//	POST /settings/updates/config    check_github=true|false and/or channel=stable|rc
//	POST /settings/updates/check     "Check now" (GitHub check, opt-in)
//	POST /settings/updates/stage     download the newest release found by the check
//	POST /settings/updates/upload    multipart: .deb + SHA256SUMS + SHA256SUMS.sig, or one .tar of the three
//	GET  /settings/updates/install   confirm dialog (?version=)
//	POST /settings/updates/install   ask the root helper to install a staged version
//	POST /settings/updates/cancel    withdraw a request the helper has not started
//	GET  /settings/updates/status    the card again (polled while an update runs)
func (s *Server) routesSettingsUpdates(mux *http.ServeMux) {
	mux.HandleFunc("POST /settings/updates/config", s.handleUpdatesConfig)
	mux.HandleFunc("POST /settings/updates/check", s.handleUpdatesCheck)
	mux.HandleFunc("POST /settings/updates/stage", s.handleUpdatesStage)
	mux.HandleFunc("POST "+uploadPathUpdate, s.handleUpdatesUpload)
	mux.HandleFunc("GET /settings/updates/install", s.handleUpdatesInstallDialog)
	mux.HandleFunc("POST /settings/updates/install", s.handleUpdatesInstall)
	mux.HandleFunc("POST /settings/updates/cancel", s.handleUpdatesCancel)
	mux.HandleFunc("GET /settings/updates/status", s.handleUpdatesStatus)
}

func (s *Server) updatesCard(ctx context.Context, now time.Time, mod func(*views.SettingsUpdates)) (*views.SettingsUpdates, error) {
	st, err := s.svc.Updates.Status(ctx)
	if err != nil {
		return nil, err
	}
	card := views.NewSettingsUpdates(now, st, s.hub.Hosts())
	if mod != nil {
		mod(card)
	}
	return card, nil
}

func (s *Server) needUpdates(w http.ResponseWriter, r *http.Request) bool {
	if s.svc.Updates == nil {
		s.toastError(w, r, http.StatusNotFound, "Not available", "Updates are not available on this hub.")
		return false
	}
	return true
}

// answerUpdates answers with the Updates card, with errMsg in its error row. After a dialog action the dialog is
// closed and the card arrives out of band.
func (s *Server) answerUpdates(w http.ResponseWriter, r *http.Request, status int, errMsg string, toast *views.Toast, fromDialog bool) {
	card, err := s.updatesCard(r.Context(), s.now(), func(c *views.SettingsUpdates) { c.Err, c.OOB = errMsg, fromDialog })
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	var parts []fragment
	if fromDialog {
		parts = append(parts, closeDialog())
	}
	parts = append(parts, fragment{"settings-updates", card})
	if toast != nil {
		parts = append(parts, toastFragment(toast.Title, toast.Sub))
	}
	s.writeFragments(w, r, status, parts...)
}

// updateProblem maps an error of the update service to a status and a message that is safe to show. Errors it
// does not know get fallback, and the caller logs them.
func updateProblem(err error, fallbackStatus int, fallback string) (int, string, bool) {
	var tooBig *http.MaxBytesError
	switch {
	case errors.As(err, &tooBig), errors.Is(err, update.ErrTooLarge):
		return http.StatusRequestEntityTooLarge, "The file is larger than the hub accepts for an update.", true
	case errors.Is(err, update.ErrBadSignature):
		return http.StatusUnprocessableEntity, "The signature does not match. Only releases signed by Nexara are accepted.", true
	case errors.Is(err, update.ErrChecksum):
		return http.StatusUnprocessableEntity, "The package does not match its checksum. The file is damaged or was changed.", true
	case errors.Is(err, update.ErrBadBundle):
		return http.StatusUnprocessableEntity, "This is not an update bundle. Choose the .deb with SHA256SUMS and SHA256SUMS.sig, or one .tar that holds the three.", true
	case errors.Is(err, update.ErrWrongArch):
		return http.StatusUnprocessableEntity, "This package is built for another processor architecture than this hub.", true
	case errors.Is(err, update.ErrDowngrade):
		return http.StatusUnprocessableEntity, "This package is older than the running version.", true
	case errors.Is(err, update.ErrAlreadyInstalled):
		return http.StatusConflict, "This version is already installed.", true
	case errors.Is(err, update.ErrDevBuild):
		return http.StatusUnprocessableEntity, "This hub is a development build and cannot be updated from here.", true
	case errors.Is(err, update.ErrCheckDisabled):
		return http.StatusConflict, "Turn on the GitHub check first.", true
	case errors.Is(err, update.ErrBusy):
		return http.StatusConflict, "Another update step is in progress. Try again in a moment.", true
	case errors.Is(err, update.ErrNotStaged):
		return http.StatusNotFound, "That version is no longer staged.", true
	case errors.Is(err, update.ErrUnsupported):
		return http.StatusUnprocessableEntity, "This hub has no update helper, so installing from here is not available.", true
	case errors.Is(err, update.ErrNoUpdate):
		return http.StatusConflict, "There is no newer release.", true
	case errors.Is(err, update.ErrNoRequest):
		return http.StatusConflict, "There is no pending request.", true
	case errors.Is(err, context.DeadlineExceeded):
		return http.StatusGatewayTimeout, "The request took too long.", true
	}
	return fallbackStatus, fallback, false
}

// failUpdates answers a failed action. Unknown errors are logged with their cause; the browser gets fixed text.
func (s *Server) failUpdates(w http.ResponseWriter, r *http.Request, err error, fromDialog bool, fallbackStatus int, fallback string) {
	status, msg, known := updateProblem(err, fallbackStatus, fallback)
	if !known {
		s.log.Warn("settings: update action failed", "path", logPath(r), "err", err)
	}
	s.answerUpdates(w, r, status, msg, nil, fromDialog)
}

func (s *Server) handleUpdatesStatus(w http.ResponseWriter, r *http.Request) {
	if !s.needUpdates(w, r) {
		return
	}
	s.answerUpdates(w, r, http.StatusOK, "", nil, false)
}

func (s *Server) handleUpdatesConfig(w http.ResponseWriter, r *http.Request) {
	if !s.needUpdates(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.toastError(w, r, http.StatusBadRequest, "Not saved", "The form could not be read.")
		return
	}
	ctx := r.Context()
	cfg, err := s.svc.Updates.Config(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	switch v := r.PostForm.Get("check_github"); v {
	case "":
	case "true", "false":
		cfg.CheckGitHub = v == "true"
	default:
		s.toastError(w, r, http.StatusBadRequest, "Not saved", "The setting is not valid.")
		return
	}
	switch v := r.PostForm.Get("channel"); v {
	case "":
	case update.ChannelStable, update.ChannelRC:
		cfg.Channel = v
	default:
		s.toastError(w, r, http.StatusBadRequest, "Not saved", "The update channel is not valid.")
		return
	}
	if err := s.svc.Updates.SetConfig(ctx, operatorName(r), cfg); err != nil {
		s.log.Error("settings: save update settings", "err", err)
		s.answerUpdates(w, r, http.StatusInternalServerError, "The setting could not be saved.", nil, false)
		return
	}
	s.answerUpdates(w, r, http.StatusOK, "", nil, false)
}

func (s *Server) handleUpdatesCheck(w http.ResponseWriter, r *http.Request) {
	if !s.needUpdates(w, r) {
		return
	}
	res, err := s.svc.Updates.CheckNow(r.Context(), operatorName(r))
	if err != nil {
		s.failUpdates(w, r, err, false, http.StatusBadGateway, "GitHub could not be reached or answered with an error.")
		return
	}
	toast := &views.Toast{Title: "Up to date", Sub: "Nexus | " + views.VersionLabel(res.Current)}
	if res.UpdateAvailable && res.Latest != nil {
		toast = &views.Toast{Title: "Update found", Sub: "Nexus | " + views.VersionLabel(res.Latest.Version)}
	}
	s.answerUpdates(w, r, http.StatusOK, "", toast, false)
}

func (s *Server) handleUpdatesStage(w http.ResponseWriter, r *http.Request) {
	if !s.needUpdates(w, r) {
		return
	}
	// Downloading can take a while on a slow line; do not abandon it when the browser tab goes.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), settingsOpTimeout)
	defer cancel()
	st, err := s.svc.Updates.StageRelease(ctx, operatorName(r))
	if err != nil {
		s.failUpdates(w, r, err, false, http.StatusBadGateway, "The release could not be downloaded from GitHub.")
		return
	}
	s.answerUpdates(w, r, http.StatusOK, "", &views.Toast{Title: "Downloaded", Sub: "Nexus | " + views.VersionLabel(st.Version)}, false)
}

// uploadReadLimit is the most one text member of an upload may hold (the checksum list, the signature).
const uploadReadLimit = update.MaxSumsBytes

var errUploadIncomplete = update.ErrBadBundle

func (s *Server) handleUpdatesUpload(w http.ResponseWriter, r *http.Request) {
	if !s.needUpdates(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, update.MaxBundleBytes)
	mr, err := r.MultipartReader()
	if err != nil {
		s.answerUpdates(w, r, http.StatusBadRequest, "Choose the update files first.", nil, false)
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), settingsOpTimeout)
	defer cancel()
	st, err := s.stageUpload(ctx, operatorName(r), mr)
	if err != nil {
		s.failUpdates(w, r, err, false, http.StatusInternalServerError, "The update could not be staged.")
		return
	}
	s.answerUpdates(w, r, http.StatusOK, "", &views.Toast{Title: "Verified", Sub: "Nexus | " + views.VersionLabel(st.Version) + " staged"}, false)
}

// stageUpload reads the parts of the upload one after the other. Package parts are spooled to a temporary file (the
// browser sends the three files in the order they were picked, and the update service wants the small ones first),
// the two small files are held in memory. One part named *.tar is handed to the service as it is.
func (s *Server) stageUpload(ctx context.Context, actor string, mr *multipart.Reader) (update.Staged, error) {
	var (
		debName   string
		deb       *os.File
		sums, sig []byte
		haveSums  bool
		haveSig   bool
		files     int
	)
	defer func() {
		if deb != nil {
			name := deb.Name()
			_ = deb.Close()
			_ = os.Remove(name)
		}
	}()
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return update.Staged{}, err
		}
		name := filepath.Base(strings.ReplaceAll(part.FileName(), "\\", "/"))
		if part.FileName() == "" {
			_ = part.Close()
			continue
		}
		files++
		switch {
		case strings.HasSuffix(name, ".tar"):
			if files > 1 {
				return update.Staged{}, errUploadIncomplete
			}
			return s.svc.Updates.StageTar(ctx, actor, part)
		case strings.HasSuffix(name, ".deb"):
			if deb != nil {
				return update.Staged{}, errUploadIncomplete
			}
			f, err := os.CreateTemp("", "nexus-update-*")
			if err != nil {
				return update.Staged{}, err
			}
			deb, debName = f, name
			n, err := io.Copy(f, io.LimitReader(part, update.MaxDebBytes+1))
			if err != nil {
				return update.Staged{}, err
			}
			if n > update.MaxDebBytes {
				return update.Staged{}, update.ErrTooLarge
			}
		case name == update.SumsFile, name == update.SigFile:
			b, err := io.ReadAll(io.LimitReader(part, uploadReadLimit+1))
			if err != nil {
				return update.Staged{}, err
			}
			if len(b) > uploadReadLimit {
				return update.Staged{}, update.ErrTooLarge
			}
			if name == update.SumsFile {
				if haveSums {
					return update.Staged{}, errUploadIncomplete
				}
				sums, haveSums = b, true
			} else {
				if haveSig {
					return update.Staged{}, errUploadIncomplete
				}
				sig, haveSig = b, true
			}
		default:
			return update.Staged{}, errUploadIncomplete
		}
	}
	if deb == nil || !haveSums || !haveSig {
		return update.Staged{}, errUploadIncomplete
	}
	if _, err := deb.Seek(0, io.SeekStart); err != nil {
		return update.Staged{}, err
	}
	return s.svc.Updates.StageFiles(ctx, actor, update.StageInput{
		DebName: debName, Deb: deb, Sums: bytes.NewReader(sums), Sig: bytes.NewReader(sig),
	})
}

func (s *Server) handleUpdatesInstallDialog(w http.ResponseWriter, r *http.Request) {
	if !s.needUpdates(w, r) {
		return
	}
	st, err := s.svc.Updates.Status(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	c, ok := views.NewSettingsInstallConfirm(s.now(), st, r.URL.Query().Get("version"))
	if !ok {
		s.toastError(w, r, http.StatusNotFound, "Not found", "That version is no longer staged.")
		return
	}
	s.writeFragments(w, r, http.StatusOK, fragment{"settings-install-confirm", c})
}

func (s *Server) handleUpdatesInstall(w http.ResponseWriter, r *http.Request) {
	if !s.needUpdates(w, r) {
		return
	}
	version := r.PostFormValue("version")
	if err := s.svc.Updates.RequestInstall(r.Context(), operatorName(r), version); err != nil {
		s.failUpdates(w, r, err, true, http.StatusInternalServerError, "The update could not be started.")
		return
	}
	s.answerUpdates(w, r, http.StatusOK, "", &views.Toast{Title: "Update queued", Sub: "Nexus | " + views.VersionLabel(version)}, true)
}

func (s *Server) handleUpdatesCancel(w http.ResponseWriter, r *http.Request) {
	if !s.needUpdates(w, r) {
		return
	}
	cancelled, err := s.svc.Updates.CancelRequest(r.Context(), operatorName(r))
	switch {
	case err != nil:
		s.failUpdates(w, r, err, false, http.StatusInternalServerError, "The request could not be withdrawn.")
	case !cancelled:
		s.answerUpdates(w, r, http.StatusConflict, "The update helper has already started; it cannot be cancelled now.", nil, false)
	default:
		s.answerUpdates(w, r, http.StatusOK, "", &views.Toast{Title: "Cancelled", Sub: "Nexus | update request withdrawn"}, false)
	}
}
