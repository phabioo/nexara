package httpserver

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/phabioo/nexara/internal/hub/grid"
	"github.com/phabioo/nexara/internal/hub/views"
	"github.com/phabioo/nexara/internal/protocol"
)

// eventsURL is the one event stream of every app page. It is not filtered by host: the page keeps a single
// connection while the operator moves between hosts and views, and nexus.js drops the events of hosts other
// than the one on screen (the SSE id field names the host, see sse.go).
const eventsURL = "/events"

// layout builds the app-shell view model for the current request: host tabs
// with badges, the top-bar pill, navigation, CSRF token and the status bar.
// active is the nav key ("overview", "packages", "shell"); host is the
// selected host, or nil when the page is not host specific (no tab active, no
// host data). Page code sets Title and any other page-specific field.
//
// Cost: one Hub.Snapshot per host (badges and reboot flags), which copies the
// package lists; fine for a home network, not for hundreds of hosts.
func (s *Server) layout(r *http.Request, active string, host *grid.HostInfo) views.Layout {
	l := views.Layout{
		ActiveNav:  active,
		AddHostURL: "/hosts/new",
		Operator:   operatorName(r),
		EventsURL:  eventsURL,
	}
	if sess, ok := SessionFrom(r); ok {
		l.CSRF = s.auth.CSRFToken(sess)
	}

	hosts := s.hub.Hosts()
	var current grid.Snapshot
	var haveCurrent bool
	for i, h := range hosts {
		if h.Online {
			l.Online++
		}
		snap, ok := s.hub.Snapshot(h.ID)
		tab := views.HostTab{
			Name:    hostLabel(h),
			Href:    hostViewURL(active, h.Name),
			Offline: !h.Online,
			Reboot:  h.RebootRequired,
		}
		if ok {
			tab.Badge = countUpdates(snap.Packages)
			tab.Reboot = tab.Reboot || (snap.Packages != nil && snap.Packages.RebootRequired)
		}
		if host != nil && h.ID == host.ID {
			tab.Active = true
			current, haveCurrent = snap, ok
			l.NodeNo = fmt.Sprintf("%02d", i+1)
		}
		l.Hosts = append(l.Hosts, tab)
	}

	updates := 0
	if host != nil {
		l.HostName = hostLabel(*host)
		l.HostKey = host.Name
		l.HostIP = host.Address
		if host.Latency > 0 {
			l.Latency = fmt.Sprintf("%d ms", host.Latency.Milliseconds())
		}
		if haveCurrent {
			updates = countUpdates(current.Packages)
			l.Packages = packagePill(current.Packages)
			if m := current.Metrics; m != nil {
				if m.TempC != nil {
					l.Temp = fmt.Sprintf("%.1f", *m.TempC)
				}
				l.Uptime = formatUptime(m.UptimeSeconds)
			}
		}
		jobs := s.hub.Jobs(host.ID)
		l.Job = views.JobChipFor(hostURL(host.Name), jobs)
		l.Log = statusLine(*host, jobs)
	}

	l.Nav = hostNav(updates, host)
	return l
}

// statusLine is the default text of the status bar: the newest job, else the connection state.
func statusLine(h grid.HostInfo, jobs []grid.Job) string {
	switch {
	case len(jobs) > 0:
		return jobLogLine(jobs[0])
	case h.Online:
		return "Connected to " + hostLabel(h)
	default:
		return hostLabel(h) + " is offline"
	}
}

func hostLabel(h grid.HostInfo) string {
	if h.DisplayName != "" {
		return h.DisplayName
	}
	return h.Name
}

func hostURL(name string) string { return "/hosts/" + url.PathEscape(name) }

// hostViewURL is the page of the view active (the nav key) for a host. The host tabs and the Q/E keys use it, so
// switching hosts stays in the view on screen: the packages list of the next host, the terminal of the next host,
// the overview of the next host. It carries no filter or search term: a filter chip that makes sense for one host
// (updates) can be empty on the next, and the plain URL is what a reload or the history entry reproduces.
// Anything but packages and shell (the overview, pages that are not host views) goes to the host's overview.
func hostViewURL(active, name string) string {
	switch active {
	case "packages":
		return hostURL(name) + "/packages"
	case "shell":
		return hostURL(name) + "/shell"
	}
	return hostURL(name)
}

// hostNav is views.DefaultNav with the per-host links filled in, so the selected
// host survives a click on the navigation; without a host the host-bound
// entries point at the overview.
func hostNav(updates int, host *grid.HostInfo) []views.NavItem {
	nav := views.DefaultNav(updates)
	for i := range nav {
		switch nav[i].Key {
		case "overview":
			if host != nil {
				nav[i].Href = hostURL(host.Name)
			}
		case "packages", "shell":
			nav[i].Href = "/"
			if host != nil {
				nav[i].Href = hostViewURL(nav[i].Key, host.Name)
			}
		}
	}
	return nav
}

func countUpdates(p *protocol.Packages) int {
	if p == nil {
		return 0
	}
	n := 0
	for _, it := range p.Items {
		if it.State == protocol.PackageUpdate {
			n++
		}
	}
	return n
}

// packagePill renders "up-to-date/installed", e.g. "7/10"; empty if unknown.
func packagePill(p *protocol.Packages) string {
	if p == nil {
		return ""
	}
	upToDate, installed := 0, 0
	for _, it := range p.Items {
		switch it.State {
		case protocol.PackageInstalled:
			upToDate++
			installed++
		case protocol.PackageUpdate:
			installed++
		}
	}
	return fmt.Sprintf("%d/%d", upToDate, installed)
}

// formatUptime renders seconds as "41D 06H".
func formatUptime(sec uint64) string {
	return fmt.Sprintf("%02dD %02dH", sec/86400, sec%86400/3600)
}

func jobLogLine(j grid.Job) string {
	var what string
	switch j.Kind {
	case protocol.JobAptUpdate:
		what = "apt update"
	case protocol.JobAptUpgrade:
		what = "apt upgrade"
	case protocol.JobAptClean:
		what = "apt clean"
	case protocol.JobPkgInstall:
		what = "install " + j.Package
	case protocol.JobPkgRemove:
		what = "remove " + j.Package
	case protocol.JobPkgUpgrade:
		what = "upgrade " + j.Package
	default:
		what = string(j.Kind)
	}
	return fmt.Sprintf("%s · %s", what, j.State)
}
