package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/phabioo/nexara/internal/config"
	"github.com/phabioo/nexara/internal/hub/app"
	"github.com/phabioo/nexara/internal/hub/backup"
)

const backupUsage = `Usage: nexus backup <command> [flags]

Commands:
  create [--reason pre-update|nightly|manual] [--keep N]
                                   write a local backup now (run as root or nexus; the hub may be running)
  list                             list the local backups
  inspect <file> [--passphrase-file <file>]
                                   verify a backup file and show what it contains
  restore <file> [--passphrase-file <file>] [--yes]
                                   restore a backup; stop the service first (sudo systemctl stop nexus)

Common flag: --config <file> (default /etc/nexus/nexus.yaml)
`

// Seams for tests.
var (
	// hubRunning reports whether a hub answers on its admin socket.
	hubRunning = func(socket string) bool {
		c, err := net.DialTimeout("unix", socket, 500*time.Millisecond)
		if err != nil {
			return false
		}
		_ = c.Close()
		return true
	}
	// setEcho switches terminal echo for the passphrase prompt.
	setEcho = func(in *os.File, on bool) {
		arg := "-echo"
		if on {
			arg = "echo"
		}
		cmd := exec.Command("stty", arg)
		cmd.Stdin = in
		_ = cmd.Run()
	}
	openBackupService = app.OpenBackupService
	// dropPrivileges runs before any hub file is touched (see dropToNexus).
	dropPrivileges = dropToNexus
)

// cmdBackup implements `nexus backup ...`.
func cmdBackup(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, backupUsage)
		return exitUsageOrStub
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "create":
		return backupCreate(ctx, rest, stdout, stderr)
	case "list":
		return backupList(ctx, rest, stdout, stderr)
	case "inspect":
		return backupInspect(ctx, rest, stdin, stdout, stderr)
	case "restore":
		return backupRestore(ctx, rest, stdin, stdout, stderr)
	case "help", "--help", "-h":
		fmt.Fprint(stdout, backupUsage)
		return exitOK
	default:
		fmt.Fprintf(stderr, "nexus backup: unknown command %q\n\n%s", sub, backupUsage)
		return exitUsageOrStub
	}
}

// backupService gives up root and then opens the service.
func backupService(configPath string, stderr io.Writer) (*backup.Service, backup.Layout, error) {
	if err := dropPrivileges(); err != nil {
		return nil, backup.Layout{}, err
	}
	return openBackupService(configPath, slog.New(slog.NewTextHandler(stderr, nil)))
}

func backupCreate(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("backup create", stderr)
	cfgPath := fs.String("config", config.DefaultHubConfigPath, "path to nexus.yaml")
	reason := fs.String("reason", backup.ReasonManual, "why the backup is made: pre-update, nightly or manual")
	keep := fs.Int("keep", 0, "also delete all but the newest N local backups (0 keeps everything; the nightly job applies backup.keep)")
	if code, done := parse(fs, args); done {
		return code
	}
	if fs.NArg() != 0 {
		fmt.Fprint(stderr, backupUsage)
		return exitUsageOrStub
	}
	svc, _, err := backupService(*cfgPath, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "nexus backup create: %v\n", err)
		return exitFailure
	}
	ctx = backup.WithActor(ctx, "cli")
	info, err := svc.CreateLocal(ctx, *reason)
	if err != nil {
		fmt.Fprintf(stderr, "nexus backup create: %v\n", err)
		return exitFailure
	}
	fmt.Fprintf(stdout, "Backup created: %s (%d bytes)\n", info.Path, info.Size)
	if *keep > 0 {
		removed, err := svc.Prune(ctx, *keep)
		if err != nil {
			fmt.Fprintf(stderr, "nexus backup create: the backup was made, but pruning failed: %v\n", err)
			return exitFailure
		}
		if len(removed) > 0 {
			fmt.Fprintf(stdout, "Removed %d old backup(s).\n", len(removed))
		}
	}
	return exitOK
}

func backupList(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("backup list", stderr)
	cfgPath := fs.String("config", config.DefaultHubConfigPath, "path to nexus.yaml")
	if code, done := parse(fs, args); done {
		return code
	}
	svc, lay, err := backupService(*cfgPath, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "nexus backup list: %v\n", err)
		return exitFailure
	}
	infos, err := svc.List(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "nexus backup list: %v\n", err)
		return exitFailure
	}
	if len(infos) == 0 {
		fmt.Fprintf(stdout, "No local backups in %s\n", lay.BackupDir)
		return exitOK
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "FILE\tCREATED (UTC)\tREASON\tVERSION\tSIZE")
	for _, in := range infos {
		ver := in.HubVersion
		if !in.Readable {
			ver = "(cannot be opened with this hub's key)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\n", in.Name, in.CreatedAt.Format("2006-01-02 15:04:05"), in.Reason, ver, in.Size)
	}
	_ = tw.Flush()
	return exitOK
}

// inputOf wraps stdin once, so that the passphrase and the confirmation can
// both be read from it, and returns the terminal (if stdin is one) whose echo
// is switched off for the passphrase.
func inputOf(stdin io.Reader) (*bufio.Reader, *os.File) {
	var tty *os.File
	if f, ok := stdin.(*os.File); ok {
		if fi, err := f.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
			tty = f
		}
	}
	return bufio.NewReader(stdin), tty
}

// openInputs opens the backup file and gets its passphrase: from
// --passphrase-file, or asked on the terminal. Local backups of this hub need
// none.
func openInputs(file, passFile string, stdin *bufio.Reader, tty *os.File, stdout io.Writer) (*os.File, string, error) {
	pass := ""
	havePass := false
	if passFile != "" {
		b, err := os.ReadFile(passFile)
		if err != nil {
			return nil, "", err
		}
		pass, havePass = strings.TrimRight(string(b), "\r\n"), true
	}
	f, err := os.Open(file)
	if err != nil {
		return nil, "", err
	}
	kind, err := backup.KindOf(f)
	if err == nil {
		_, err = f.Seek(0, io.SeekStart)
	}
	if err != nil {
		_ = f.Close()
		return nil, "", err
	}
	if kind == "local" || havePass {
		return f, pass, nil
	}
	fmt.Fprint(stdout, "Backup passphrase: ")
	if tty != nil {
		setEcho(tty, false)
	}
	line, rerr := stdin.ReadString('\n')
	if tty != nil {
		setEcho(tty, true)
		fmt.Fprintln(stdout)
	}
	if rerr != nil && line == "" {
		_ = f.Close()
		return nil, "", errors.New("no passphrase given")
	}
	return f, strings.TrimRight(line, "\r\n"), nil
}

func backupInspect(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := newFlagSet("backup inspect", stderr)
	cfgPath := fs.String("config", config.DefaultHubConfigPath, "path to nexus.yaml")
	passFile := fs.String("passphrase-file", "", "read the passphrase from this file")
	file, code, done := fileArg(fs, args, stderr)
	if done {
		return code
	}
	in, tty := inputOf(stdin)
	// The user's files are opened while the command still has the user's
	// rights (root); the service then runs as the hub's user.
	f, pass, err := openInputs(file, *passFile, in, tty, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "nexus backup inspect: %v\n", err)
		return exitFailure
	}
	defer f.Close()
	svc, _, err := backupService(*cfgPath, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "nexus backup inspect: %v\n", err)
		return exitFailure
	}
	m, err := svc.InspectFrom(ctx, f, pass)
	if err != nil {
		fmt.Fprintf(stderr, "nexus backup inspect: %v\n", err)
		return exitFailure
	}
	fmt.Fprintf(stdout, "Backup of %q made %s by Nexus %s (%s)\nDatabase schema %d, archive format %d. All checksums match.\n",
		m.HubName, m.CreatedAt.UTC().Format("2006-01-02 15:04:05 UTC"), m.HubVersion, m.Reason, m.SchemaVersion, m.Format)
	for _, f := range m.Files {
		fmt.Fprintf(stdout, "  %-16s %10d bytes\n", f.Name, f.Size)
	}
	return exitOK
}

func backupRestore(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := newFlagSet("backup restore", stderr)
	cfgPath := fs.String("config", config.DefaultHubConfigPath, "path to nexus.yaml")
	passFile := fs.String("passphrase-file", "", "read the passphrase from this file")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	socket := fs.String("admin-socket", app.DefaultAdminSocket, "admin Unix socket of the hub (used to detect a running service)")
	file, code, done := fileArg(fs, args, stderr)
	if done {
		return code
	}
	if hubRunning(*socket) {
		fmt.Fprintln(stderr, "nexus backup restore: the nexus service is running. Stop it first: sudo systemctl stop nexus")
		return exitFailure
	}
	in, tty := inputOf(stdin)
	f, pass, err := openInputs(file, *passFile, in, tty, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "nexus backup restore: %v\n", err)
		return exitFailure
	}
	defer f.Close()
	svc, lay, err := backupService(*cfgPath, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "nexus backup restore: %v\n", err)
		return exitFailure
	}
	// Verify first, so that the question below is about a file known to be good.
	m, err := svc.InspectFrom(ctx, f, pass)
	if err != nil {
		fmt.Fprintf(stderr, "nexus backup restore: %v\n", err)
		return exitFailure
	}
	fmt.Fprintf(stdout, "Backup of %q made %s by Nexus %s: verified.\n", m.HubName, m.CreatedAt.UTC().Format("2006-01-02 15:04:05 UTC"), m.HubVersion)
	if !*yes && !confirm(in, stdout, fmt.Sprintf(
		"This replaces the database, configuration, certificates and keys of this hub (%s, %s).\nThe current files are kept as *.before-restore. Continue? [y/N] ", lay.Database, lay.ConfigPath)) {
		fmt.Fprintln(stderr, "nexus backup restore: cancelled")
		return exitFailure
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		fmt.Fprintf(stderr, "nexus backup restore: %v\n", err)
		return exitFailure
	}
	res, err := svc.RestoreFrom(backup.WithActor(ctx, "cli"), f, pass)
	if err != nil {
		fmt.Fprintf(stderr, "nexus backup restore: %v\nNothing was changed.\n", err)
		return exitFailure
	}
	fmt.Fprintf(stdout, "Restored. %d file(s) were kept as *%s.\n", len(res.Replaced), backup.BeforeRestoreSuffix)
	if res.ConfigAdjusted {
		fmt.Fprintln(stdout, "The backup came from other paths; storage.database and tls.dir in nexus.yaml now point to this hub's files.")
	}
	fmt.Fprintln(stdout, "Start the service again: sudo systemctl start nexus")
	return exitOK
}

// fileArg parses flags and the single file argument, which may stand before
// or after the flags.
func fileArg(fs *flag.FlagSet, args []string, stderr io.Writer) (file string, code int, done bool) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		file, args = args[0], args[1:]
	}
	if code, done := parse(fs, args); done {
		return "", code, true
	}
	switch {
	case file == "" && fs.NArg() == 1:
		file = fs.Arg(0)
	case file == "" || fs.NArg() != 0:
		fmt.Fprint(stderr, backupUsage)
		return "", exitUsageOrStub, true
	}
	return file, 0, false
}
