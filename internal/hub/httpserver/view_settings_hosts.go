package httpserver

import (
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/hub/views"
	"github.com/phabioo/nexara/internal/protocol"
)

// Capabilities with a switch in v0.2. Power and Docker belong to later versions (decision #31).
var switchableCapabilities = map[string]string{protocol.CapShell: "Shell", protocol.CapPackages: "Packages"}

// routesSettingsHosts registers the Hosts & capabilities and Certificates cards.
//
//	POST /settings/hosts/{host}/capabilities/{cap}   enabled=true|false (shell, packages)
//	GET  /settings/hosts/{host}/remove               confirm dialog (the overview's dialog)
//	POST /settings/hosts/{host}/remove               retire the host, back to Settings
//	POST /settings/certs/{host}/renew                renew the agent certificate of an online host now
//
// Capability changes and renewals are audited by the grid.
func (s *Server) routesSettingsHosts(mux *http.ServeMux) {
	mux.HandleFunc("POST /settings/hosts/{host}/capabilities/{cap}", s.handleHostCapability)
	mux.HandleFunc("GET /settings/hosts/{host}/remove", s.handleSettingsRemoveConfirm)
	mux.HandleFunc("POST /settings/hosts/{host}/remove", s.handleSettingsRemove)
	mux.HandleFunc("POST /settings/certs/{host}/renew", s.handleCertRenew)
}

func (s *Server) hostsCard(hosts []grid.HostInfo) views.SettingsHosts {
	return views.NewSettingsHosts(hosts, s.hubOwn, s.svc.Caps != nil, settingsHostURL)
}

func (s *Server) certsCard(now time.Time, hosts []grid.HostInfo) views.SettingsCerts {
	var ca, server *x509.Certificate
	if s.svc.CA != nil {
		ca = s.svc.CA.Cert
	}
	if s.svc.ServerCert != nil {
		c, err := s.svc.ServerCert()
		if err != nil {
			s.log.Warn("settings: reading the hub certificate", "err", err)
		}
		server = c
	}
	var renew func(string) string
	if s.svc.Certs != nil {
		renew = func(name string) string { return "/settings/certs/" + url.PathEscape(name) + "/renew" }
	}
	return views.NewSettingsCerts(now, ca, server, hosts, renew)
}

func (s *Server) handleHostCapability(w http.ResponseWriter, r *http.Request) {
	if s.svc.Caps == nil {
		s.toastError(w, r, http.StatusNotFound, "Not available", "Capabilities cannot be changed on this hub.")
		return
	}
	h, ok := s.requireHost(w, r)
	if !ok {
		return
	}
	capName := r.PathValue("cap")
	label, switchable := switchableCapabilities[capName]
	if !switchable {
		s.toastError(w, r, http.StatusNotFound, "Not found", "That capability cannot be switched.")
		return
	}
	var enabled bool
	switch r.PostFormValue("enabled") {
	case "true":
		enabled = true
	case "false":
	default:
		s.toastError(w, r, http.StatusBadRequest, "Not changed", "Say whether to switch it on or off.")
		return
	}
	if err := s.svc.Caps.SetCapability(r.Context(), ActorFrom(r), h.ID, capName, enabled); err != nil {
		if errors.Is(err, grid.ErrUnsupported) {
			s.toastError(w, r, http.StatusUnprocessableEntity, "Not changed", "The agent on "+h.Name+" does not offer "+label+".")
			return
		}
		s.gridErrorTitled(w, r, err, "Not changed")
		return
	}
	cur, ok := s.hub.Host(h.ID)
	if !ok {
		s.notFound(w, r)
		return
	}
	state := "off"
	if enabled {
		state = "on"
	}
	row := views.NewSettingsHost(cur, s.hubOwn(cur), true, settingsHostURL)
	s.writeFragments(w, r, http.StatusOK,
		fragment{"settings-host", row},
		toastFragment("Saved", h.Name+" | "+label+" "+state))
}

func (s *Server) handleSettingsRemoveConfirm(w http.ResponseWriter, r *http.Request) {
	h, ok := s.requireHost(w, r)
	if !ok {
		return
	}
	if s.refuseHubRemoval(w, r, h) {
		return
	}
	d := views.NewOverviewRemove(hostLabel(h), settingsHostURL(h.Name), false)
	s.writeFragments(w, r, http.StatusOK, fragment{"overview-remove", d})
}

// handleSettingsRemove removes the host like the overview does (the grid revokes its certificate and audits it) and
// stays in Settings.
func (s *Server) handleSettingsRemove(w http.ResponseWriter, r *http.Request) {
	h, ok := s.requireHost(w, r)
	if !ok {
		return
	}
	if s.refuseHubRemoval(w, r, h) {
		return
	}
	if err := s.hub.RemoveHost(r.Context(), ActorFrom(r), h.ID); err != nil {
		s.gridErrorTitled(w, r, err, "Not removed")
		return
	}
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Location", s.navLocation("/settings"))
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) handleCertRenew(w http.ResponseWriter, r *http.Request) {
	if s.svc.Certs == nil {
		s.toastError(w, r, http.StatusNotFound, "Not available", "Certificates cannot be renewed on this hub.")
		return
	}
	h, ok := s.requireHost(w, r)
	if !ok {
		return
	}
	if err := s.svc.Certs.RenewCert(r.Context(), ActorFrom(r), h.ID); err != nil {
		switch {
		case errors.Is(err, grid.ErrRenewInProgress):
			s.toastError(w, r, http.StatusConflict, "Not renewed", "A renewal is already running for "+h.Name+".")
		case errors.Is(err, grid.ErrUnsupported):
			s.toastError(w, r, http.StatusUnprocessableEntity, "Not renewed", "The agent on "+h.Name+" cannot renew its certificate. Update the agent first.")
		case errors.Is(err, grid.ErrHostOffline):
			s.toastError(w, r, http.StatusConflict, "Not renewed", h.Name+" is offline. A certificate can only be renewed while the agent is connected.")
		default:
			s.gridErrorTitled(w, r, err, "Not renewed")
		}
		return
	}
	card := s.certsCard(s.now(), s.hub.Hosts())
	s.writeFragments(w, r, http.StatusOK,
		fragment{"settings-certs", card},
		toastFragment("Renewing", h.Name+" | new certificate requested"))
}
