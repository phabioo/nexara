package grid

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/protocol"
)

// Hub-side capability switches (Settings > Hosts & capabilities).
//
// The agent reports which capabilities it offers (agent.yaml, Hello). The
// operator can additionally switch a capability off in the hub: the hub then
// refuses the matching actions for that host (ErrCapabilityDisabled) whatever
// the agent would do. The switch is stored in the settings table under
// "grid.caps_off.h<host id>" as a comma separated list, so it survives
// reconnects (a Hello replaces the offered set, never the switches) and
// restarts, and no schema change is needed. HostInfo.Capabilities holds what
// is on (offered and not switched off), HostInfo.DisabledCapabilities what the
// agent offers but the hub has switched off. A capability in neither list is
// not offered by the agent at all.

const settingCapsOffPrefix = "grid.caps_off."

func capsOffKey(id HostID) string { return settingCapsOffPrefix + "h" + strings.ToLower(string(id)) }

// CapabilityController switches capabilities of a host on or off (v0.2
// Settings). *Grid implements it; Hub does not, because the demo hub keeps no
// switches.
type CapabilityController interface {
	// SetCapability turns one capability on or off for the host (audited as
	// host.capabilities). Errors: ErrHostNotFound, ErrInvalidArgument (unknown
	// capability, or monitoring, which cannot be switched), ErrUnsupported (the
	// agent does not offer it).
	SetCapability(ctx context.Context, actor Actor, id HostID, capability string, enabled bool) error
}

var _ CapabilityController = (*Grid)(nil)

// capEnabled reports whether the capability is offered by the agent and not
// switched off in the hub. g.mu must be held.
func (st *hostState) capEnabled(name string) bool {
	return hasCap(st.host.Capabilities, name) && !slices.Contains(st.capsOff, name)
}

// enabledCaps is the offered set minus the switched-off capabilities, in the
// order the agent reported them. g.mu must be held.
func (st *hostState) enabledCaps() []string {
	out := make([]string, 0, len(st.host.Capabilities))
	for _, c := range st.host.Capabilities {
		if !slices.Contains(st.capsOff, c) {
			out = append(out, c)
		}
	}
	return out
}

// disabledCaps are the offered capabilities the hub has switched off, in
// protocol order. g.mu must be held.
func (st *hostState) disabledCaps() []string {
	var out []string
	for _, c := range protocol.Capabilities() {
		if hasCap(st.host.Capabilities, c) && slices.Contains(st.capsOff, c) {
			out = append(out, c)
		}
	}
	return out
}

// parseCapsOff reads the stored list, dropping unknown names.
func parseCapsOff(v string) []string {
	var out []string
	for _, c := range strings.Split(v, ",") {
		c = strings.TrimSpace(c)
		if c != "" && c != protocol.CapMonitoring && slices.Contains(protocol.Capabilities(), c) && !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	return out
}

// loadCapsOff restores the switches of all known hosts. A failure leaves every
// capability on (the agents' own configuration still applies) and is logged.
func (g *Grid) loadCapsOff(ctx context.Context) {
	m, err := g.opts.Store.ListSettings(ctx, settingCapsOffPrefix)
	if err != nil {
		g.log.Warn("grid: reading the capability switches failed", "err", err)
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for id, st := range g.hosts {
		if v, ok := m[capsOffKey(id)]; ok {
			st.capsOff = parseCapsOff(v)
		}
	}
}

// SetCapability implements CapabilityController.
func (g *Grid) SetCapability(ctx context.Context, actor Actor, id HostID, capability string, enabled bool) error {
	if capability == protocol.CapMonitoring || !slices.Contains(protocol.Capabilities(), capability) {
		return fmt.Errorf("%w: capability %q cannot be switched", ErrInvalidArgument, capability)
	}
	g.capMu.Lock()
	defer g.capMu.Unlock()

	g.mu.Lock()
	st, ok := g.hosts[id]
	if !ok {
		g.mu.Unlock()
		return ErrHostNotFound
	}
	name := st.name
	if !hasCap(st.host.Capabilities, capability) {
		g.mu.Unlock()
		return fmt.Errorf("%w: the agent on %s does not offer %s", ErrUnsupported, name, capability)
	}
	next := slices.Clone(st.capsOff)
	if enabled {
		next = slices.DeleteFunc(next, func(c string) bool { return c == capability })
	} else if !slices.Contains(next, capability) {
		next = append(next, capability)
	}
	changed := len(next) != len(st.capsOff)
	g.mu.Unlock()
	if !changed {
		return nil
	}

	err := g.saveCapsOff(ctx, id, next)
	state := "off"
	if enabled {
		state = "on"
	}
	g.audit(store.AuditEntry{User: actor.Operator, Host: name, Action: "host.capabilities",
		Detail: strings.TrimSpace(capability + " " + state + " " + auditDetailIP(actor)), Result: auditResult(err)})
	if err != nil {
		return fmt.Errorf("grid: save capability switch: %w", err)
	}

	g.mu.Lock()
	st, ok = g.hosts[id]
	if !ok {
		g.mu.Unlock()
		return ErrHostNotFound
	}
	st.capsOff = next
	c := st.conn
	g.mu.Unlock()

	switch {
	case !enabled && capability == protocol.CapShell && c != nil:
		// A switched-off shell must not stay open.
		c.mu.Lock()
		open := make([]*shellSession, 0, len(c.shells))
		for _, s := range c.shells {
			open = append(open, s)
		}
		c.mu.Unlock()
		for _, s := range open {
			s.endLocal("shell switched off")
		}
	case enabled && c != nil && (capability == protocol.CapPackages || capability == protocol.CapServices):
		// The lists were not fetched while the capability was off.
		go func() {
			var err error
			if capability == protocol.CapPackages {
				err = g.RefreshPackages(g.ctx, id)
			} else {
				err = g.RefreshServices(g.ctx, id)
			}
			if err != nil && !errors.Is(err, ErrHostNotFound) {
				g.log.Debug("grid: refresh after switching a capability on failed", "host", name, "capability", capability, "err", err)
			}
		}()
	}
	return nil
}

func (g *Grid) saveCapsOff(ctx context.Context, id HostID, caps []string) error {
	key := capsOffKey(id)
	if len(caps) == 0 {
		return g.opts.Store.DeleteSetting(ctx, key)
	}
	return g.opts.Store.SetSetting(ctx, key, strings.Join(caps, ","))
}
