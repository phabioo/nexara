package grid

import (
	"context"
	"fmt"
	"regexp"
	"slices"

	"github.com/phabioo/nexara/internal/hub/store"
	"github.com/phabioo/nexara/internal/protocol"
)

var (
	unitRe    = regexp.MustCompile(`^[A-Za-z0-9@._:-]{1,200}\.service$`)
	packageRe = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{1,127}(:[a-z0-9]+)?$`)
)

// RefreshServices implements Hub.
func (g *Grid) RefreshServices(ctx context.Context, id HostID) error {
	st, c, err := g.connFor(id, protocol.CapServices)
	if err != nil {
		return err
	}
	env, err := c.request(ctx, protocol.TypeServicesList, nil, g.to.servicesList)
	if err != nil {
		return err
	}
	if env.Type != protocol.TypeServices {
		return fmt.Errorf("grid: unexpected %q answer to services.list", env.Type)
	}
	sv, err := protocol.DecodeData[protocol.Services](env)
	if err != nil {
		return fmt.Errorf("grid: bad services answer: %w", err)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if st.conn != c {
		return ErrHostOffline
	}
	st.services = cloneServices(&sv)
	g.emitLocked(Event{Kind: EventServices, Host: st.id, Payload: *cloneServices(&sv)})
	return nil
}

// RefreshPackages implements Hub.
func (g *Grid) RefreshPackages(ctx context.Context, id HostID) error {
	st, c, err := g.connFor(id, protocol.CapPackages)
	if err != nil {
		return err
	}
	env, err := c.request(ctx, protocol.TypePackagesList, nil, g.to.packagesList)
	if err != nil {
		return err
	}
	if env.Type != protocol.TypePackages {
		return fmt.Errorf("grid: unexpected %q answer to packages.list", env.Type)
	}
	pk, err := protocol.DecodeData[protocol.Packages](env)
	if err != nil {
		return fmt.Errorf("grid: bad packages answer: %w", err)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if st.conn != c {
		return ErrHostOffline
	}
	st.packages = clonePackages(&pk)
	st.rebootRequired = pk.RebootRequired
	g.emitLocked(Event{Kind: EventPackages, Host: st.id, Payload: *clonePackages(&pk)})
	return nil
}

// SearchPackages implements Hub.
func (g *Grid) SearchPackages(ctx context.Context, id HostID, query string) ([]protocol.Package, error) {
	if !packageRe.MatchString(query) {
		return nil, fmt.Errorf("%w: search query", ErrInvalidArgument)
	}
	_, c, err := g.connFor(id, protocol.CapPackages)
	if err != nil {
		return nil, err
	}
	env, err := c.request(ctx, protocol.TypePackagesSearch, protocol.PackagesSearch{Query: query}, g.to.packagesSearch)
	if err != nil {
		return nil, err
	}
	if env.Type != protocol.TypePackages {
		return nil, fmt.Errorf("grid: unexpected %q answer to packages.search", env.Type)
	}
	pk, err := protocol.DecodeData[protocol.Packages](env)
	if err != nil {
		return nil, fmt.Errorf("grid: bad search answer: %w", err)
	}
	return slices.Clone(pk.Items), nil
}

// RestartService implements Hub.
func (g *Grid) RestartService(ctx context.Context, actor Actor, id HostID, unit string) error {
	if !unitRe.MatchString(unit) {
		return fmt.Errorf("%w: service unit name", ErrInvalidArgument)
	}
	st, c, err := g.connFor(id, protocol.CapServices)
	if err != nil {
		return err
	}
	env, err := c.request(ctx, protocol.TypeServiceRestart, protocol.ServiceRestart{Unit: unit}, g.to.serviceRestart)
	if err == nil {
		err = resultErr(env, "restart of "+unit)
	}
	g.audit(store.AuditEntry{User: actor.Operator, Host: st.name, Action: "service.restart", Detail: unit, Result: auditResult(err)})
	if err != nil {
		return err
	}
	go func() {
		if err := g.RefreshServices(g.ctx, id); err != nil {
			g.log.Debug("grid: services refresh after restart failed", "host", st.name, "err", err)
		}
	}()
	return nil
}
