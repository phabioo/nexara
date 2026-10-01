package main

import (
	"context"
	"fmt"
	"io"
	"os/signal"
	"syscall"

	"github.com/phabioo/nexara/internal/agent/enroll"
	"github.com/phabioo/nexara/internal/config"
)

const exitEnrollFailed = 1

// runEnroll implements `grid-agent enroll`: pair this device with a hub using a
// one-time token. The token is never printed.
func runEnroll(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("enroll", stderr)
	hub := fs.String("hub", "", "hub address, e.g. https://frpi5.local:8443")
	token := fs.String("token", "", "one-time enrollment code (visible in ps; prefer --token-file)")
	tokenFile := fs.String("token-file", "", "file with the one-time enrollment code (mode 0600)")
	fingerprint := fs.String("ca-fingerprint", "", "SHA-256 fingerprint of the hub CA (from the installer output)")
	shellUser := fs.String("shell-user", "", "user the Nexara Shell runs as (the device's normal user, not root)")
	cfgPath := fs.String("config", config.DefaultAgentConfigPath, "path of agent.yaml to write")
	stateDir := fs.String("state-dir", enroll.DefaultStateDir, "directory for the agent key and certificates")
	if code, done := parse(fs, args); done {
		return code
	}
	if *hub == "" {
		fmt.Fprintln(stderr, "grid-agent enroll: --hub is required")
		return exitUsageOrStub
	}
	switch {
	case *token != "" && *tokenFile != "":
		fmt.Fprintln(stderr, "grid-agent enroll: use either --token or --token-file, not both")
		return exitUsageOrStub
	case *tokenFile != "":
		code, err := enroll.ReadTokenFile(*tokenFile)
		if err != nil {
			fmt.Fprintf(stderr, "grid-agent enroll: %v\n", err)
			return exitEnrollFailed
		}
		*token = code
	case *token == "":
		fmt.Fprintln(stderr, "grid-agent enroll: --token or --token-file is required")
		return exitUsageOrStub
	}
	if *fingerprint == "" {
		fmt.Fprintln(stderr, "grid-agent enroll: --ca-fingerprint is required")
		return exitUsageOrStub
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	err := enroll.Enroll(ctx, enroll.Options{
		Hub: *hub, Token: *token, CAFingerprint: *fingerprint,
		ConfigPath: *cfgPath, StateDir: *stateDir, ShellUser: *shellUser,
	})
	if err != nil {
		fmt.Fprintf(stderr, "grid-agent enroll: %v\n", err)
		return exitEnrollFailed
	}
	fmt.Fprintf(stdout, "Enrolled. Configuration written to %s.\n", *cfgPath)
	return exitOK
}
