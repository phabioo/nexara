package history

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/phabioo/nexara/internal/hub/store"
)

// Bounds of the retention settings, in days.
const (
	MinRetentionDays = 1
	MaxRetentionDays = 3650 // same bound as storage.history.hour_days in nexus.yaml

	DefaultAuditRetentionDays = 365
	MinAuditRetentionDays     = 30
	MaxAuditRetentionDays     = 3650
)

// ErrInvalidRetention means a retention value is outside its bounds.
var ErrInvalidRetention = errors.New("history: retention out of range")

// RetentionDays is the effective retention of hourly history: the setting
// history.retention_days if it is set and valid, else the nexus.yaml value
// given in Options.DefaultRetentionDays.
func (s *Service) RetentionDays(ctx context.Context) int {
	n, err := s.st.GetSettingInt(ctx, store.SettingHistoryRetentionDays, s.defaultDays)
	if err != nil {
		if ctx.Err() == nil {
			s.log.Warn("ignoring the history retention setting", "err", err)
		}
		return s.defaultDays
	}
	if n < MinRetentionDays || n > MaxRetentionDays {
		s.log.Warn("ignoring the history retention setting: out of range", "days", n)
		return s.defaultDays
	}
	return n
}

// SetRetentionDays stores the hourly history retention (1-3650 days). It takes
// effect at the next hourly run; shorter values delete older hours then.
func (s *Service) SetRetentionDays(ctx context.Context, days int) error {
	if days < MinRetentionDays || days > MaxRetentionDays {
		return fmt.Errorf("%w: %d days (allowed %d-%d)", ErrInvalidRetention, days, MinRetentionDays, MaxRetentionDays)
	}
	return s.st.SetSettingInt(ctx, store.SettingHistoryRetentionDays, days)
}

// AuditRetentionDays is the effective audit log retention: the setting
// audit.retention_days if valid, else 365.
func (s *Service) AuditRetentionDays(ctx context.Context) int {
	n, err := s.st.GetSettingInt(ctx, store.SettingAuditRetentionDays, DefaultAuditRetentionDays)
	if err != nil {
		if ctx.Err() == nil {
			s.log.Warn("ignoring the audit retention setting", "err", err)
		}
		return DefaultAuditRetentionDays
	}
	if n < MinAuditRetentionDays || n > MaxAuditRetentionDays {
		s.log.Warn("ignoring the audit retention setting: out of range", "days", n)
		return DefaultAuditRetentionDays
	}
	return n
}

// SetAuditRetentionDays stores the audit retention (30-3650 days; a floor so
// the trail cannot be erased through the settings).
func (s *Service) SetAuditRetentionDays(ctx context.Context, days int) error {
	if days < MinAuditRetentionDays || days > MaxAuditRetentionDays {
		return fmt.Errorf("%w: %d days (allowed %d-%d)", ErrInvalidRetention, days, MinAuditRetentionDays, MaxAuditRetentionDays)
	}
	return s.st.SetSettingInt(ctx, store.SettingAuditRetentionDays, days)
}

// AuditActionPrune is the audit action recorded when entries were pruned.
const AuditActionPrune = "audit.prune"

// PruneAudit deletes audit entries older than the audit retention, keeping the
// newest store.AuditKeepNewest, and records what it did (user "system"). Run
// calls it once a day; it is exported for the admin tools.
func (s *Service) PruneAudit(ctx context.Context) error {
	days := s.AuditRetentionDays(ctx)
	now := s.now()
	n, err := s.st.PruneAudit(ctx, now.Add(-time.Duration(days)*24*time.Hour), store.AuditKeepNewest)
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	s.log.Info("pruned the audit log", "entries", n, "retention_days", days)
	_, err = s.st.AppendAudit(ctx, store.AuditEntry{
		Time: now, User: "system", Action: AuditActionPrune, Result: store.AuditOK,
		Detail: fmt.Sprintf("removed %d entries older than %d days", n, days),
	})
	return err
}
