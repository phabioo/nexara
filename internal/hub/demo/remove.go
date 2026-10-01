package demo

import (
	"context"
	"slices"

	"github.com/phabioo/nexara/internal/hub/grid"
)

// RemoveHost implements grid.Hub: the simulated host disappears (online or
// offline) and EventHostRemoved is emitted. Nothing is audited in the demo.
func (h *Hub) RemoveHost(_ context.Context, _ grid.Actor, id grid.HostID) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	hst := h.find(id)
	if hst == nil {
		return grid.ErrHostNotFound
	}
	h.hosts = slices.DeleteFunc(h.hosts, func(x *host) bool { return x == hst })
	h.emit(grid.Event{Kind: grid.EventHostRemoved, Host: id, Payload: cloneInfo(hst.info)})
	return nil
}
