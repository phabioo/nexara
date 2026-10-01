package app

import (
	"context"
	"net/http"
	"sync/atomic"

	"github.com/phabioo/nexara/internal/hub/enroll"
	"github.com/phabioo/nexara/internal/hub/grid"
)

// enrollHolder lets the running hub switch to a new enroll.Service when the
// setup wizard changes the address agents use to reach the hub (the service
// bakes address and port into enrollment URLs and install scripts). It is the
// grid.Enroller of the UI and the http.Handler of /grid/enroll, /grid/install.sh
// and /grid/download/.
type enrollHolder struct {
	cur atomic.Pointer[enrollState]
}

type enrollState struct {
	svc     *enroll.Service
	handler http.Handler
}

var (
	_ grid.Enroller = (*enrollHolder)(nil)
	_ http.Handler  = (*enrollHolder)(nil)
)

func newEnrollHolder(svc *enroll.Service) *enrollHolder {
	h := &enrollHolder{}
	h.Replace(svc)
	return h
}

// Replace installs svc for all following requests.
func (h *enrollHolder) Replace(svc *enroll.Service) {
	h.cur.Store(&enrollState{svc: svc, handler: svc.Handler()})
}

// Service returns the current service.
func (h *enrollHolder) Service() *enroll.Service { return h.cur.Load().svc }

func (h *enrollHolder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.cur.Load().handler.ServeHTTP(w, r)
}

func (h *enrollHolder) LinkViaSSH(ctx context.Context, actor grid.Actor, req grid.SSHLinkRequest, progress func(grid.LinkStep)) (grid.HostInfo, error) {
	return h.Service().LinkViaSSH(ctx, actor, req, progress)
}

func (h *enrollHolder) ProbeSSH(ctx context.Context, actor grid.Actor, host string, port int) (grid.HostKeyInfo, error) {
	return h.Service().ProbeSSH(ctx, actor, host, port)
}

func (h *enrollHolder) NewEnrollCode(ctx context.Context, actor grid.Actor, opts grid.EnrollOptions) (grid.EnrollCode, error) {
	return h.Service().NewEnrollCode(ctx, actor, opts)
}
