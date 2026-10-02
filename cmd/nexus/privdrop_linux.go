//go:build linux

package main

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// dropToNexus gives up root for the `nexus` user (and group, without extra
// groups). `nexus backup` reads and writes only files the hub's user owns, so
// it never needs root; running it as that user means a compromised hub cannot
// turn the root helper into a file reader by planting symlinks in
// /var/lib/nexus, and everything it creates has the right owner and mode.
// Without root, or without a `nexus` user (development), it does nothing.
func dropToNexus() error {
	if os.Geteuid() != 0 {
		return nil
	}
	u, err := user.Lookup("nexus")
	if err != nil {
		return nil
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return fmt.Errorf("cannot switch to the nexus user: unexpected ids %q/%q", u.Uid, u.Gid)
	}
	if err := syscall.Setgroups([]int{gid}); err != nil {
		return fmt.Errorf("cannot switch to the nexus user: %w", err)
	}
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("cannot switch to the nexus user: %w", err)
	}
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("cannot switch to the nexus user: %w", err)
	}
	if os.Geteuid() != uid || os.Getuid() != uid {
		return fmt.Errorf("cannot switch to the nexus user")
	}
	return nil
}
