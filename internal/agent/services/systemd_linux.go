//go:build linux

package services

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/coreos/go-systemd/v22/dbus"

	"github.com/phabioo/nexara/internal/protocol"
)

// New returns the systemd backed Manager. The D-Bus connection is opened per
// call so the agent survives systemd restarts.
func New() Manager {
	return &manager{api: dbusAPI{}, ports: readPorts}
}

type dbusAPI struct{}

func (dbusAPI) Units(ctx context.Context) ([]unitState, error) {
	conn, err := dbus.NewWithContext(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	units, err := conn.ListUnitsContext(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]unitState, 0, len(units))
	for _, u := range units {
		out = append(out, unitState{
			Name: u.Name, Description: u.Description, LoadState: u.LoadState,
			ActiveState: u.ActiveState, SubState: u.SubState,
		})
	}
	return out, nil
}

func (dbusAPI) EnabledUnits(ctx context.Context) (map[string]bool, error) {
	conn, err := dbus.NewWithContext(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	files, err := conn.ListUnitFilesContext(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, f := range files {
		if f.Type == "enabled" || f.Type == "enabled-runtime" {
			out[filepath.Base(f.Path)] = true
		}
	}
	return out, nil
}

func (dbusAPI) Restart(ctx context.Context, unit string) (string, error) {
	conn, err := dbus.NewWithContext(ctx)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	ch := make(chan string, 1)
	if _, err := conn.RestartUnitContext(ctx, unit, "replace", ch); err != nil {
		return "", err
	}
	select {
	case res := <-ch:
		return res, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// readPorts lists listening sockets with their owning process (best effort).
func readPorts() ([]protocol.ListeningPort, error) {
	var ls []listener
	for _, f := range []struct{ file, proto string }{
		{"tcp", "tcp"}, {"tcp6", "tcp"}, {"udp", "udp"}, {"udp6", "udp"},
	} {
		raw, err := os.ReadFile("/proc/net/" + f.file)
		if err != nil {
			continue // e.g. IPv6 disabled
		}
		ls = append(ls, parseProcNet(f.proto, string(raw))...)
	}
	return summarizePorts(ls, socketOwners(ls)), nil
}

// socketOwners maps the inodes of ls to process names by walking
// /proc/[pid]/fd. Unreadable processes are skipped.
func socketOwners(ls []listener) map[uint64]string {
	want := make(map[uint64]bool, len(ls))
	for _, l := range ls {
		want[l.Inode] = true
	}
	owners := map[uint64]string{}
	pids, _ := filepath.Glob("/proc/[0-9]*")
	for _, dir := range pids {
		if len(owners) == len(want) {
			break
		}
		fds, err := os.ReadDir(filepath.Join(dir, "fd"))
		if err != nil {
			continue
		}
		name := ""
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(dir, "fd", fd.Name()))
			if err != nil {
				continue
			}
			inode, ok := parseSocketLink(target)
			if !ok || !want[inode] {
				continue
			}
			if name == "" {
				raw, err := os.ReadFile(filepath.Join(dir, "comm"))
				if err != nil {
					break
				}
				name = strings.TrimSpace(string(raw))
			}
			owners[inode] = name
		}
	}
	return owners
}
