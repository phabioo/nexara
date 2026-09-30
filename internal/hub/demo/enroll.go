package demo

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/phabioo/nexara/internal/hub/grid"
)

const codeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// failAddress makes LinkViaSSH fail at the connect step (demo of the error state).
const failAddress = "fail.local"

// randString returns n characters of alphabet. Callers hold h.mu.
func (h *Hub) randString(alphabet string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[h.rng.IntN(len(alphabet))]
	}
	return string(b)
}

// randBase64 returns a fake fingerprint-like base64 string of the given raw length.
func (h *Hub) randBase64(n int, padded bool) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(h.rng.UintN(256))
	}
	enc := base64.StdEncoding
	if !padded {
		enc = enc.WithPadding(base64.NoPadding)
	}
	return enc.EncodeToString(b)
}

// NewEnrollCode implements grid.Enroller. About 8 s later a host "pi-new" comes
// online, unless another code was created in the meantime.
func (h *Hub) NewEnrollCode(_ context.Context, _ grid.Actor, opts grid.EnrollOptions) (grid.EnrollCode, error) {
	h.mu.Lock()
	code := "GRID-" + h.randString(codeAlphabet, 4) + "-" + h.randString(codeAlphabet, 4)
	pin := h.randBase64(32, true)
	h.enrollGen++
	gen := h.enrollGen
	ec := grid.EnrollCode{
		Code:    code,
		Expires: h.now().UTC().Add(enrollCodeTTL),
		Command: fmt.Sprintf("curl -fsSL --insecure --pinnedpubkey sha256//%s https://%s/grid/install.sh | sudo sh -s -- %s", pin, demoHubAddress, code),
	}
	h.mu.Unlock()

	caps := append([]string(nil), opts.Capabilities...)
	go func() {
		if !h.wait(h.ctx, enrollDelay) {
			return
		}
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.enrollGen != gen {
			return
		}
		name := h.freeName("pi-new")
		h.addHost(name, name, name+".local", caps)
	}()
	return ec, nil
}

// freeName returns base or base-2, base-3, ... Callers hold h.mu.
func (h *Hub) freeName(base string) string {
	name := base
	for i := 2; h.byName(name) != nil; i++ {
		name = fmt.Sprintf("%s-%d", base, i)
	}
	return name
}

func (h *Hub) byName(name string) *host {
	for _, hst := range h.hosts {
		if hst.info.Name == name {
			return hst
		}
	}
	return nil
}

// addHost creates an online host and announces it. Callers hold h.mu.
func (h *Hub) addHost(name, display, addr string, caps []string) *host {
	hst := &host{info: grid.HostInfo{
		ID: h.newHostID(), Name: name, DisplayName: display, Address: addr,
		OS: "linux", Arch: "arm64", Capabilities: defaultCaps,
	}}
	if len(caps) > 0 {
		hst.info.Capabilities = caps
	}
	hst.info.Capabilities = append([]string(nil), hst.info.Capabilities...)
	h.hosts = append(h.hosts, hst)
	h.activate(hst, h.now().UTC())
	h.emit(grid.Event{Kind: grid.EventHostAdded, Host: hst.info.ID, Payload: cloneInfo(hst.info)})
	h.emit(grid.Event{Kind: grid.EventHostOnline, Host: hst.info.ID, Payload: cloneInfo(hst.info)})
	return hst
}

// slug turns an address or display name into a URL-safe host name.
func slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if net.ParseIP(s) == nil {
		s = strings.TrimSuffix(s, ".local")
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			if b.Len() > 0 && !strings.HasSuffix(b.String(), "-") {
				b.WriteByte('-')
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

// LinkViaSSH implements grid.Enroller: five steps of about 0.8 s each. The
// address "fail.local" fails at the connect step. Linking the address or name
// of the offline host brings that host online.
func (h *Hub) LinkViaSSH(ctx context.Context, _ grid.Actor, req grid.SSHLinkRequest, progress func(grid.LinkStep)) (grid.HostInfo, error) {
	addr := strings.TrimSpace(req.Address)
	user := strings.TrimSpace(req.User)
	if addr == "" || user == "" || req.Port < 0 || req.Port > 65535 ||
		(req.UseHubKey == (req.Password != "")) {
		return grid.HostInfo{}, fmt.Errorf("%w: address, user and exactly one of password or hub key are required", grid.ErrInvalidArgument)
	}
	display := strings.TrimSpace(req.DisplayName)
	if display == "" {
		display = addr
	}
	name := slug(display)
	if name == "" {
		return grid.HostInfo{}, fmt.Errorf("%w: host name", grid.ErrInvalidArgument)
	}
	report := func(st grid.LinkStepName, state grid.LinkState, detail string) {
		if progress != nil {
			progress(grid.LinkStep{Step: st, State: state, Detail: detail})
		}
	}

	h.mu.Lock()
	existing := h.byName(name)
	if existing == nil {
		for _, hst := range h.hosts {
			if hst.info.Address == addr {
				existing = hst
			}
		}
	}
	if existing != nil && existing.info.Online {
		h.mu.Unlock()
		return grid.HostInfo{}, grid.ErrHostExists
	}
	fp := h.randBase64(32, false)
	h.mu.Unlock()

	fail := func(step grid.LinkStepName, detail string, cause error) (grid.HostInfo, error) {
		report(step, grid.LinkFailed, detail)
		return grid.HostInfo{}, fmt.Errorf("%w: %w", grid.ErrLinkFailed, cause)
	}
	steps := []struct {
		name   grid.LinkStepName
		detail string
	}{
		{grid.StepConnect, fmt.Sprintf("Connected as %s · Host key SHA256:%s", user, fp)},
		{grid.StepDetect, "Debian 12 · arm64"},
		{grid.StepInstall, "v0.1.0 · systemd unit"},
		{grid.StepEnroll, "mTLS · valid 1 year · SSH closed"},
		{grid.StepOnline, "first sync running"},
	}
	var info grid.HostInfo
	for _, st := range steps {
		report(st.name, grid.LinkRunning, "")
		if st.name == grid.StepConnect && strings.EqualFold(addr, failAddress) {
			if !h.wait(ctx, linkStepDelay) {
				return fail(st.name, "Canceled", ctx.Err())
			}
			return fail(st.name, "Connection timed out", errors.New("connect "+addr+": connection timed out"))
		}
		if !h.wait(ctx, linkStepDelay) {
			return fail(st.name, "Canceled", ctx.Err())
		}
		if st.name == grid.StepOnline {
			var err error
			if info, err = h.finishLink(name, display, addr, existing); err != nil {
				return fail(st.name, "Host already exists", err)
			}
		}
		report(st.name, grid.LinkDone, st.detail)
	}
	return info, nil
}

// finishLink adds the new host (or revives the offline one) after the last step.
func (h *Hub) finishLink(name, display, addr string, existing *host) (grid.HostInfo, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if existing != nil && h.find(existing.info.ID) == existing {
		if existing.info.Online {
			return grid.HostInfo{}, grid.ErrHostExists
		}
		h.activate(existing, h.now().UTC())
		h.emit(grid.Event{Kind: grid.EventHostOnline, Host: existing.info.ID, Payload: cloneInfo(existing.info)})
		return cloneInfo(existing.info), nil
	}
	if h.byName(name) != nil {
		return grid.HostInfo{}, grid.ErrHostExists
	}
	return cloneInfo(h.addHost(name, display, addr, nil).info), nil
}
