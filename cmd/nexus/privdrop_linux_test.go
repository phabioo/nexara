//go:build linux

package main

import (
	"errors"
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

func TestDropToErrors(t *testing.T) {
	missing := func(string) (*user.User, error) { return nil, user.UnknownUserError("nexus") }
	good := func(string) (*user.User, error) { return &user.User{Uid: "998", Gid: "997"}, nil }
	cases := []struct {
		name    string
		euid    int
		lookup  func(string) (*user.User, error)
		swtch   func(uid, gid int) error
		wantErr string
		wantIDs [2]int
	}{
		{name: "not root does nothing", euid: 1000, lookup: missing},
		{name: "root without a nexus user fails", euid: 0, lookup: missing, wantErr: "nexus user does not exist"},
		{name: "root with the nexus user switches", euid: 0, lookup: good, wantIDs: [2]int{998, 997}},
		{name: "nexus with id 0 is refused", euid: 0, wantErr: "id 0",
			lookup: func(string) (*user.User, error) { return &user.User{Uid: "0", Gid: "0"}, nil }},
		{name: "bad ids", euid: 0, wantErr: "unexpected ids",
			lookup: func(string) (*user.User, error) { return &user.User{Uid: "x", Gid: "y"}, nil }},
		{name: "a failing switch is an error", euid: 0, lookup: good, wantErr: "cannot switch",
			swtch: func(int, int) error { return errors.New("EPERM") }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var got [2]int
			swtch := c.swtch
			if swtch == nil {
				swtch = func(uid, gid int) error { got = [2]int{uid, gid}; return nil }
			}
			err := dropTo(c.euid, c.lookup, swtch)
			switch {
			case c.wantErr == "" && err != nil:
				t.Fatal(err)
			case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
				t.Fatalf("err = %v, want %q", err, c.wantErr)
			}
			if got != c.wantIDs {
				t.Errorf("switched to %v, want %v", got, c.wantIDs)
			}
		})
	}
}
