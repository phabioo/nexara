package grid

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/phabioo/nexara/internal/hub/agentbin"
	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/protocol"
)

// autoUpdateBackoff keeps a broken update from looping: a host is auto-updated
// at most once per interval.
const autoUpdateBackoff = 10 * time.Minute

// UpdateAgent implements Hub: push the embedded agent binary to the host.
func (g *Grid) UpdateAgent(ctx context.Context, actor Actor, id HostID) error {
	st, c, err := g.connFor(id, "")
	if err != nil {
		return err
	}
	g.mu.Lock()
	goos, arch := st.host.OS, st.host.Arch
	g.mu.Unlock()
	bin, ok := g.opts.AgentBinary(goos, arch)
	if !ok {
		return ErrUnsupported
	}
	return g.pushUpdate(ctx, actor, st, c, bin)
}

func (g *Grid) pushUpdate(ctx context.Context, actor Actor, st *hostState, c *agentConn, bin agentbin.Binary) error {
	msg := protocol.AgentUpdate{
		Version: g.opts.HubVersion,
		SHA256:  bin.SHA256,
		Path:    "/grid/agent/" + bin.OS + "/" + bin.Arch,
	}
	env, err := c.request(ctx, protocol.TypeAgentUpdate, msg, g.to.update)
	if err == nil {
		err = resultErr(env, "agent update")
	}
	g.audit(store.AuditEntry{User: actor.Operator, Host: st.name, Action: "agent.update", Detail: msg.Version, Result: auditResult(err)})
	return err
}

// maybeAutoUpdate pushes an update to an agent older than the hub (decision #20).
func (g *Grid) maybeAutoUpdate(id HostID, hello protocol.Hello) {
	if !needsUpdate(hello.AgentVersion, g.opts.HubVersion) {
		return
	}
	bin, ok := g.opts.AgentBinary(hello.OS, hello.Arch)
	if !ok {
		return
	}
	g.mu.Lock()
	st, known := g.hosts[id]
	if !known || st.conn == nil || time.Since(st.lastAutoUpdate) < autoUpdateBackoff {
		g.mu.Unlock()
		return
	}
	st.lastAutoUpdate = time.Now()
	c := st.conn
	g.mu.Unlock()
	if err := g.pushUpdate(g.ctx, SystemActor, st, c, bin); err != nil {
		g.log.Warn("grid: automatic agent update failed", "host", st.name, "err", err)
	}
}

// AgentDownloadHandler serves GET /grid/agent/{os}/{arch} to authenticated agents.
func (g *Grid) AgentDownloadHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := g.authenticate(r); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		goos, arch := r.PathValue("os"), r.PathValue("arch")
		if goos == "" || arch == "" {
			parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
			if len(parts) < 2 {
				http.NotFound(w, r)
				return
			}
			goos, arch = parts[len(parts)-2], parts[len(parts)-1]
		}
		bin, ok := g.opts.AgentBinary(goos, arch)
		if !ok {
			http.NotFound(w, r)
			return
		}
		h := w.Header()
		h.Set("Content-Type", "application/octet-stream")
		h.Set("Content-Length", strconv.Itoa(len(bin.Data)))
		h.Set("X-Nexara-SHA256", bin.SHA256)
		h.Set("Cache-Control", "no-store")
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(bin.Data)
	})
}

// needsUpdate reports whether an agent version is older than the hub's.
// "dev" builds and unparsable versions never update.
func needsUpdate(agent, hub string) bool {
	if hub == "dev" || agent == "dev" {
		return false
	}
	cmp, ok := compareVersions(agent, hub)
	return ok && cmp < 0
}

// compareVersions compares two semantic versions ("v" prefix and build
// metadata ignored, a pre-release sorts before its release). ok is false if
// either does not parse.
func compareVersions(a, b string) (cmp int, ok bool) {
	ac, ap, ok1 := parseVersion(a)
	bc, bp, ok2 := parseVersion(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	for i := range ac {
		if ac[i] != bc[i] {
			if ac[i] < bc[i] {
				return -1, true
			}
			return 1, true
		}
	}
	switch {
	case ap == bp:
		return 0, true
	case ap == "":
		return 1, true
	case bp == "":
		return -1, true
	}
	return strings.Compare(ap, bp), true
}

func parseVersion(s string) (core [3]int, pre string, ok bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, '-'); i >= 0 {
		s, pre = s[:i], s[i+1:]
	}
	parts := strings.Split(s, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return core, "", false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return core, "", false
		}
		core[i] = n
	}
	return core, pre, true
}
