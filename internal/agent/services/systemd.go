package services

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/phabioo/nexara/internal/protocol"
)

// ErrNotSupported is returned on platforms without a service backend.
var ErrNotSupported = errors.New("services: not supported on this platform")

// restartTimeout bounds the wait for a restart job.
const restartTimeout = 60 * time.Second

var unitNameRe = regexp.MustCompile(`^[A-Za-z0-9@._:-]{1,200}\.service$`)

// unitState is one loaded unit as reported by the service manager.
type unitState struct {
	Name        string
	Description string
	LoadState   string
	ActiveState string
	SubState    string
}

// systemdAPI is the small part of the systemd D-Bus API the manager needs.
// The Linux implementation talks to the system bus; tests use a fake.
type systemdAPI interface {
	// Units returns all loaded units.
	Units(ctx context.Context) ([]unitState, error)
	// EnabledUnits returns the names of unit files in state enabled or enabled-runtime.
	EnabledUnits(ctx context.Context) (map[string]bool, error)
	// Restart restarts the unit (mode "replace") and returns the job result
	// string ("done", "failed", "timeout", ...).
	Restart(ctx context.Context, unit string) (string, error)
}

// portsReader returns the listening ports summary.
type portsReader func() ([]protocol.ListeningPort, error)

type manager struct {
	api   systemdAPI
	ports portsReader
}

// noisePrefixes are unit name prefixes that are never shown.
var noisePrefixes = []string{"systemd-", "getty@", "serial-getty@", "user@", "dbus-", "modprobe@", "sys-"}

// visible reports whether the operator should see the unit: a loaded service
// that is enabled or failed, without system noise. Template instances
// (name@instance.service) are only shown when failed.
func visible(u unitState, enabled map[string]bool) bool {
	if !strings.HasSuffix(u.Name, ".service") || u.LoadState != "loaded" {
		return false
	}
	for _, p := range noisePrefixes {
		if strings.HasPrefix(u.Name, p) {
			return false
		}
	}
	failed := u.ActiveState == "failed"
	if strings.Contains(u.Name, "@") && !failed {
		return false
	}
	return failed || enabled[u.Name]
}

// filterUnits applies visible and sorts failed units first, then by name.
func filterUnits(all []unitState, enabled map[string]bool) []protocol.ServiceUnit {
	out := []protocol.ServiceUnit{}
	for _, u := range all {
		if !visible(u, enabled) {
			continue
		}
		out = append(out, protocol.ServiceUnit{
			Name: u.Name, Description: u.Description,
			ActiveState: u.ActiveState, SubState: u.SubState,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		fi, fj := out[i].ActiveState == "failed", out[j].ActiveState == "failed"
		if fi != fj {
			return fi
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func (m *manager) List(ctx context.Context) (protocol.Services, error) {
	all, err := m.api.Units(ctx)
	if err != nil {
		return protocol.Services{}, fmt.Errorf("list units: %w", err)
	}
	enabled, err := m.api.EnabledUnits(ctx)
	if err != nil {
		return protocol.Services{}, fmt.Errorf("list unit files: %w", err)
	}
	res := protocol.Services{Units: filterUnits(all, enabled)}
	if m.ports != nil {
		// Ports are best effort; the units list is still useful without them.
		if ports, err := m.ports(); err == nil {
			res.Ports = ports
		}
	}
	return res, nil
}

func (m *manager) Restart(ctx context.Context, unit string) error {
	if !unitNameRe.MatchString(unit) {
		return fmt.Errorf("invalid unit name %q", unit)
	}
	all, err := m.api.Units(ctx)
	if err != nil {
		return fmt.Errorf("list units: %w", err)
	}
	enabled, err := m.api.EnabledUnits(ctx)
	if err != nil {
		return fmt.Errorf("list unit files: %w", err)
	}
	allowed := false
	for _, u := range all {
		if u.Name == unit && visible(u, enabled) {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("unit %q is not a manageable service", unit)
	}

	ctx, cancel := context.WithTimeout(ctx, restartTimeout)
	defer cancel()
	result, err := m.api.Restart(ctx, unit)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("restart %s: timed out after %s", unit, restartTimeout)
		}
		return fmt.Errorf("restart %s: %w", unit, err)
	}
	switch result {
	case "done":
		return nil
	case "timeout":
		return fmt.Errorf("restart %s: timed out", unit)
	case "failed":
		return fmt.Errorf("restart %s: the service failed to start (see its journal)", unit)
	default:
		return fmt.Errorf("restart %s: job ended with %q", unit, result)
	}
}
