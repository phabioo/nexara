//go:build linux

package main

import (
	"errors"
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
// Without root it does nothing. As root without a `nexus` user it fails
// instead of carrying on as root (security review B-02): the safe state of
// this command is "not running".
func dropToNexus() error {
	return dropTo(os.Geteuid(), user.Lookup, switchIDs)
}

// switchIDs is the Linux part of the switch; tests replace it.
func switchIDs(uid, gid int) error {
	if err := syscall.Setgroups([]int{gid}); err != nil {
		return err
	}
	if err := syscall.Setgid(gid); err != nil {
		return err
	}
	if err := syscall.Setuid(uid); err != nil {
		return err
	}
	if os.Geteuid() != uid || os.Getuid() != uid {
		return errors.New("the user ids did not change")
	}
	return nil
}

func dropTo(euid int, lookup func(string) (*user.User, error), swtch func(uid, gid int) error) error {
	if euid != 0 {
		return nil
	}
	u, err := lookup("nexus")
	if err != nil {
		return fmt.Errorf("refusing to run as root: the nexus user does not exist (%w)", err)
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return fmt.Errorf("cannot switch to the nexus user: unexpected ids %q/%q", u.Uid, u.Gid)
	}
	if uid == 0 {
		return errors.New("refusing to run as root: the nexus user has the id 0")
	}
	if err := swtch(uid, gid); err != nil {
		return fmt.Errorf("cannot switch to the nexus user: %w", err)
	}
	return nil
}
