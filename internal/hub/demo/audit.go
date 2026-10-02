package demo

import (
	"context"
	"fmt"
	"time"

	"github.com/phabioo/nexara/internal/hub/store"
)

// SeedAudit writes a plausible audit history of the demo hosts, ending at now:
// about two entries per hour for 40 days (a few thousand rows), with a few
// failures and refused sign-ins. It is deterministic and does nothing when the
// audit log already has entries.
func SeedAudit(ctx context.Context, st *store.Store, now time.Time) error {
	if existing, err := st.ListAudit(ctx, 1); err != nil || len(existing) > 0 {
		return err
	}
	type tpl struct {
		user, host, action, result, detail string
	}
	cycle := []tpl{
		{"fabio", "", "login", store.AuditOK, "ip=192.168.10.44"},
		{"fabio", "pi5-media", "job.apt_update", store.AuditOK, ""},
		{"fabio", "pi5-media", "shell.open", store.AuditOK, "session s1"},
		{"fabio", "pi5-media", "shell.close", store.AuditOK, "after 12 min"},
		{"fabio", "pi3-dns", "job.apt_upgrade", store.AuditOK, ""},
		{"system", "pi3-dns", "agent.update", store.AuditOK, "v0.2.0"},
		{"mallory", "", "login", store.AuditDenied, "ip=192.168.10.77 reason=bad_password"},
		{"fabio", "pi5-media", "service.restart", store.AuditOK, "nginx.service"},
		{"fabio", "pi3-dns", "job.pkg_install", store.AuditError, "tmux E: Unable to locate package"},
		{"system", "pi5-media", "cert.renew", store.AuditOK, "activated"},
		{"fabio", "pi5-media", "job.pkg_upgrade", store.AuditOK, "openssh-server"},
		{"system", "", "backup.create", store.AuditOK, "reason: nightly; 2.1 MB"},
		{"fabio", "", "logout", store.AuditOK, "ip=192.168.10.44"},
		{"fabio", "pi3-dns", "job.apt_clean", store.AuditError, "canceled by fabio"},
	}
	const entries = 40 * 24 * 2
	for i := entries - 1; i >= 0; i-- {
		c := cycle[i%len(cycle)]
		e := store.AuditEntry{
			Time: now.Add(-time.Duration(i)*30*time.Minute - time.Duration(i%7)*time.Minute),
			User: c.user, Host: c.host, Action: c.action, Result: c.result, Detail: c.detail,
		}
		if _, err := st.AppendAudit(ctx, e); err != nil {
			return fmt.Errorf("demo: seed audit: %w", err)
		}
	}
	return nil
}
