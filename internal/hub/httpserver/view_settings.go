package httpserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/phabioo/nexara/internal/hub/auth"
	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/hub/views"
)

// Settings (wave 8): eight cards (Operators, Security, Updates, Backup, Hosts & capabilities, Certificates,
// Diagnostics, Audit log). The page is a full page; every action answers with the card (or the row) it changed,
// which htmx swaps in place, plus a toast. Dialogs are fragments for #modal-root. The cards live in
// view_settings_*.go next to this file.
//
//	GET  /settings                         the page
//	GET  /settings/passphrase              change-passphrase dialog
//	POST /settings/passphrase              change it, end the other sessions, rotate this session
//	…/settings/updates/…                   view_settings_updates.go
//	…/settings/backup/…, /settings/restart view_settings_backup.go
//	…/settings/hosts/…, /settings/certs/…  view_settings_hosts.go
//	GET  /settings/logs/hub                view_settings_diag.go
func (s *Server) routesSettings(mux *http.ServeMux) {
	mux.HandleFunc("GET /settings", s.handleSettings)
	mux.HandleFunc("GET /settings/passphrase", s.handlePassphraseDialog)
	mux.HandleFunc("POST /settings/passphrase", s.handlePassphrase)
	s.routesSettingsUpdates(mux)
	s.routesSettingsBackup(mux)
	s.routesSettingsHosts(mux)
	s.routesSettingsDiag(mux)
}

// settingsAuditRows is how many audit entries the Audit log card shows.
const settingsAuditRows = 3

// settingsOpTimeout bounds work a request starts that must not stop when the browser goes away (a backup).
const settingsOpTimeout = 10 * time.Minute

// processBoot identifies this hub process. The restart dialog polls until another process answers.
var processBoot = func() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}()

// fragment is one rendered part of a multi-part answer.
type fragment struct {
	name string
	data any
}

// toastFragment is the out-of-band toast of an answer.
func toastFragment(title, sub string) fragment {
	return fragment{"toasts", views.Toast{Title: title, Sub: sub}}
}

// writeFragments renders the parts one after the other into one response. The first part is the main swap, the
// others carry hx-swap-oob. Nothing is written when a part fails to render.
func (s *Server) writeFragments(w http.ResponseWriter, r *http.Request, status int, parts ...fragment) {
	if s.renderer == nil {
		s.notImplemented(w, r)
		return
	}
	var b strings.Builder
	for _, p := range parts {
		out, err := s.partialString(p.name, p.data)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		b.WriteString(out)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(b.String()))
}

// closeDialog is the main part of an answer to a dialog action: it empties #modal-root while the OOB parts
// update the page.
func closeDialog() fragment { return fragment{"settings-nothing", nil} }

func settingsHostURL(name string) string { return "/settings/hosts/" + url.PathEscape(name) }

// --- the page ----------------------------------------------------------------

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	if s.renderer == nil {
		s.notImplemented(w, r)
		return
	}
	var host *grid.HostInfo
	if h, ok := s.defaultHost(); ok {
		host = &h
	}
	var page views.SettingsPage
	page.Layout = s.layout(r, "settings", host)
	page.Title = "Settings"
	ctx := r.Context()
	now := s.now()

	if u, ok := UserFrom(r); ok {
		sess, _ := SessionFrom(r)
		page.Operators = views.NewSettingsOperators(now, u.OperatorID, u.TOTPEnabled, sess.CreatedAt, sess.IP)
	}
	hosts := s.hub.Hosts()
	if s.svc.Updates != nil {
		if card, err := s.updatesCard(ctx, now, nil); err != nil {
			s.log.Error("settings: update status", "err", err)
		} else {
			page.Updates = card
		}
	}
	if s.svc.Backup != nil {
		if card, err := s.backupCard(ctx, now, nil); err != nil {
			s.log.Error("settings: backups", "err", err)
		} else {
			page.Backup = card
		}
	}
	page.HostCard = s.hostsCard(hosts)
	page.CertCard = s.certsCard(now, hosts)
	page.DiagCard = s.diagCard()
	if s.svc.Store != nil {
		entries, err := s.svc.Store.ListAudit(ctx, settingsAuditRows)
		if err != nil {
			s.log.Error("settings: audit entries", "err", err)
		}
		page.Audit = views.NewSettingsAudit(now, entries)
	}
	if err := s.renderer.Render(w, "settings", page); err != nil {
		s.serverError(w, r, err)
	}
}

// --- change passphrase -------------------------------------------------------

// auditPassphrase is the audit action of a passphrase change.
const auditPassphrase = "user.passphrase"

func (s *Server) handlePassphraseDialog(w http.ResponseWriter, r *http.Request) {
	s.writeFragments(w, r, http.StatusOK, fragment{"settings-passphrase", views.PassphraseDialog{PostURL: "/settings/passphrase"}})
}

func (s *Server) passphraseError(w http.ResponseWriter, r *http.Request, status int, msg string) {
	s.writeFragments(w, r, status, fragment{"settings-passphrase", views.PassphraseDialog{PostURL: "/settings/passphrase", Error: msg}})
}

// handlePassphrase changes the signed-in operator's passphrase. It verifies the current one first, applies the
// passphrase policy, stores an argon2id hash, ends every session of the operator (a stolen cookie dies with the old
// passphrase) and gives this browser a new one. The new session has a new CSRF token, which the page shell
// carries, so the answer sends the browser to a full page load of /settings.
func (s *Server) handlePassphrase(w http.ResponseWriter, r *http.Request) {
	user, ok := UserFrom(r)
	sess, okSess := SessionFrom(r)
	if !ok || !okSess || s.svc.Store == nil {
		s.notFound(w, r)
		return
	}
	// One change per operator at a time: the check below is an argon2
	// evaluation of attacker-chosen input (security review A-02).
	done, err := s.auth.BeginOperatorAction(user.ID)
	if err != nil {
		s.passphraseError(w, r, http.StatusTooManyRequests, "Another change is in progress. Try again in a moment.")
		return
	}
	defer done()
	if err := r.ParseForm(); err != nil {
		s.passphraseError(w, r, http.StatusBadRequest, "The form could not be read.")
		return
	}
	current, next, confirm := r.PostForm.Get("current"), r.PostForm.Get("passphrase"), r.PostForm.Get("confirm")
	if current == "" || next == "" {
		s.passphraseError(w, r, http.StatusUnprocessableEntity, "Enter your current and your new passphrase.")
		return
	}
	// The check goes through the auth service: argon2 semaphore, attempts
	// counted per operator before they are evaluated, throttled attempts audited.
	err = s.auth.CheckPassphrase(r.Context(), user, current, ClientIP(r), auditPassphrase)
	switch {
	case err == nil:
	case errors.Is(err, auth.ErrRateLimited):
		s.passphraseError(w, r, http.StatusTooManyRequests,
			"Too many wrong entries. Try again in "+waitText(auth.RetryAfter(err))+".")
		return
	case errors.Is(err, auth.ErrBusy):
		w.Header().Set("Retry-After", "2")
		s.passphraseError(w, r, http.StatusServiceUnavailable, "The hub is busy. Try again in a moment.")
		return
	case errors.Is(err, auth.ErrWrongPassphrase):
		s.auditSettings(r, auditPassphrase, "", "wrong current passphrase", store.AuditDenied)
		s.passphraseError(w, r, http.StatusUnprocessableEntity, "The current passphrase is not correct.")
		return
	default:
		s.log.Error("settings: verify passphrase", "err", err)
		s.passphraseError(w, r, http.StatusInternalServerError, "The passphrase could not be checked.")
		return
	}
	switch {
	case next != confirm:
		s.passphraseError(w, r, http.StatusUnprocessableEntity, "The new passphrases do not match.")
		return
	case next == current:
		s.passphraseError(w, r, http.StatusUnprocessableEntity, "Choose a passphrase that differs from the current one.")
		return
	}
	if err := auth.ValidatePassphrase(next); err != nil {
		s.passphraseError(w, r, http.StatusUnprocessableEntity, passphrasePolicyMessage(err))
		return
	}
	ctx := r.Context()
	hash, err := s.auth.HashPassphrase(ctx, next)
	if err != nil {
		s.log.Error("settings: hash passphrase", "err", err)
		s.passphraseError(w, r, http.StatusInternalServerError, "The passphrase could not be changed.")
		return
	}
	if err := s.svc.Store.UpdatePassword(ctx, user.ID, hash); err != nil {
		s.log.Error("settings: store passphrase", "err", err)
		s.auditSettings(r, auditPassphrase, "", "store failed", store.AuditError)
		s.passphraseError(w, r, http.StatusInternalServerError, "The passphrase could not be changed.")
		return
	}
	ended, err := s.auth.Sessions().DeleteAllForUser(ctx, user.ID)
	if err != nil {
		// The new passphrase is stored; old sessions that survive a failure here would be a hole, so say so loudly.
		s.log.Error("settings: ending sessions after a passphrase change", "err", err)
	}
	raw, fresh, err := s.auth.Sessions().Create(ctx, user, sess.Persistent, ClientIP(r), r.UserAgent())
	if err != nil {
		s.log.Error("settings: new session after a passphrase change", "err", err)
		s.auditSettings(r, auditPassphrase, "", "changed; new session failed", store.AuditOK)
		w.Header().Set("HX-Redirect", "/login")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	s.auditSettings(r, auditPassphrase, "", "other sessions ended: "+strconv.FormatInt(ended, 10), store.AuditOK)
	http.SetCookie(w, s.auth.Cookies().Session(raw, fresh))
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/settings")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func passphrasePolicyMessage(err error) string {
	if errors.Is(err, auth.ErrWeakPassphrase) {
		return "The new passphrase needs at least " + strconv.Itoa(auth.MinPassphraseLength) + " characters."
	}
	return "The new passphrase is not acceptable."
}

// auditSettings writes an audit entry for the signed-in operator. Failures are logged, never shown. detail must
// not hold secrets.
func (s *Server) auditSettings(r *http.Request, action, host, detail, result string) {
	if s.svc.Store == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer cancel()
	if ip := ClientIP(r); ip != "" {
		detail = strings.TrimSpace(detail + " ip=" + ip)
	}
	if _, err := s.svc.Store.AppendAudit(ctx, store.AuditEntry{
		Time: s.now().UTC(), User: operatorName(r), Host: host, Action: action, Detail: detail, Result: result,
	}); err != nil {
		s.log.Error("settings: audit entry", "action", action, "err", err)
	}
}

func waitText(d time.Duration) string {
	m := int((d + time.Minute - 1) / time.Minute)
	if m <= 1 {
		return "1 minute"
	}
	return strconv.Itoa(m) + " minutes"
}
