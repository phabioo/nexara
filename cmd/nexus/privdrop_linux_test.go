//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// TestDropToNexusHelper is the child process of TestDropToNexus.
func TestDropToNexusHelper(t *testing.T) {
	if os.Getenv("NEXUS_DROP_HELPER") != "1" {
		t.Skip("helper process")
	}
	if err := dropToNexus(); err != nil {
		fmt.Println("error:", err)
		os.Exit(3)
	}
	groups, _ := os.Getgroups()
	fmt.Println("ids", os.Getuid(), os.Geteuid(), os.Getgid(), os.Getegid(), len(groups))
	// Root must really be gone: regaining it has to fail.
	if err := syscall.Setuid(0); err == nil {
		fmt.Println("error: could switch back to root")
		os.Exit(4)
	}
	os.Exit(0)
}

func TestDropToNexus(t *testing.T) {
	u, err := user.Lookup("nexus")
	if os.Geteuid() != 0 || err != nil {
		t.Skip("needs root and a nexus user")
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	cmd := exec.Command(os.Args[0], "-test.run=^TestDropToNexusHelper$")
	cmd.Env = append(os.Environ(), "NEXUS_DROP_HELPER=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper failed: %v\n%s", err, out)
	}
	want := fmt.Sprintf("ids %d %d %d %d 1", uid, uid, gid, gid)
	if !strings.Contains(string(out), want) {
		t.Fatalf("output %q does not contain %q", out, want)
	}
}

func TestDropToNexusWithoutRootDoesNothing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	if err := dropToNexus(); err != nil {
		t.Fatal(err)
	}
}
