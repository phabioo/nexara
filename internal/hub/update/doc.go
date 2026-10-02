// Package update is the self-update of the hub (decisions #21, #43, #50, #53).
//
// The hub process never gets root. It checks, downloads (or receives),
// verifies and stages a signed release, then drops a request file. A root
// helper, `nexus update-apply`, started by systemd when the request appears,
// verifies everything again, backs up, installs the package with apt and
// rolls back if the new hub does not come up.
//
//	hub (user nexus)                          helper (root)
//	────────────────                          ─────────────
//	Check (opt-in) ──► GitHub Releases
//	StageRelease / StageFiles / StageTar
//	  verify SHA256SUMS.sig + sha256
//	  → <data>/updates/<version>/
//	RequestInstall
//	  verify again
//	  → <data>/updates/request.json  ──path unit──►  claim: request.json → applying.json
//	state "installing"                              copy files into /var/lib/nexus-update/work,
//	                                                verify signature + sha256 on the copy
//	                                                nexus backup create --reason pre-update
//	                                                apt-get install -y <copy>
//	                                                poll the admin socket (version) up to 60 s
//	                                                  ok     → keep the package as rollback copy
//	                                                  failed → apt-get install --allow-downgrades <previous>
//	Reconcile (Run, every 15 s) ◄── result.json ──  write result.json (ok | rolled_back | error)
//	  audit "update.apply", last-result.json
//
// # Files
//
// Below <data dir>/updates (owned by nexus, mode 0700; files 0600):
//
//	<version>/nexus_<version>_<arch>.deb, SHA256SUMS, SHA256SUMS.sig, source
//	request.json     hub → helper: {version, arch, deb, sha256, requested_by, requested_at}
//	applying.json    helper: the claimed request plus {phase, started_at}; phases verify, backup, install, health, rollback
//	result.json      helper → hub: {status, version, previous_version, phase, message, log_tail, requested_by, started_at, finished_at}
//	last-result.json hub: the reported result, for the view
//	check.json       hub: cached GitHub check
//
// Root-owned, in /var/lib/nexus-update (created by nexus-update.service):
//
//	installed/       the package of the running version with its SHA256SUMS and signature: the rollback material
//	work/            scratch copy of the files being installed, removed afterwards
//
// The paths are fixed (DefaultDataDir, DefaultStateDir). The helper does not
// read nexus.yaml: the hub user can write it, and root must not follow a path
// the hub chose.
//
// # Trust
//
// The helper trusts nothing the hub wrote beyond "look in updates/<version>".
// It re-verifies the ed25519 signature over SHA256SUMS with the embedded key
// and the package checksum itself. Paths are derived (version and
// architecture are validated, file names are built, never taken from the
// request) and opened through os.Root, so a symlink swapped in by the hub user
// cannot lead out of the directory; files must be regular, correctly owned
// (root or nexus), size-limited, in a directory that group and others cannot
// write. The package is copied into a root-owned directory and verified there,
// so a swap after the check does not matter. A downgrade (or reinstall) is
// refused unless the operator passes --allow-downgrade on the command line:
// the request file cannot ask for it.
//
// # Rollback material
//
// After a healthy update the helper keeps the new package in installed/. The
// next update falls back to it. If installed/ does not hold the running
// version, a verified bundle of that version still staged in updates/ is used.
// With neither, the helper refuses (the running version could not be restored)
// unless --no-rollback is given. install.sh should seed installed/ on a fresh
// install (package, SHA256SUMS, SHA256SUMS.sig, mode 0644, directory 0755).
//
// # API for the Settings view
//
//	svc, _ := update.New(update.Options{Dir: dataDir + "/updates", Settings: settings, Audit: ..., HelperWatches: ...})
//	go svc.Run(ctx)                                  // result reporting + 6-hourly check when enabled
//
//	svc.Status(ctx)                                  // Status: version, config, cached check, staged bundles, installing, last result
//	svc.Config(ctx) / svc.SetConfig(ctx, actor, c)   // settings update.check_github (default off), update.channel (stable|rc), update.allow_downgrade
//	svc.CheckNow(ctx, actor)                         // "Check now"; ErrCheckDisabled while the check is off
//	svc.StageRelease(ctx, actor)                     // "Download": newest release from GitHub; needs the check enabled
//	svc.StageFiles(ctx, actor, StageInput{...})      // upload: three files (multipart: package, SHA256SUMS, SHA256SUMS.sig)
//	svc.StageTar(ctx, actor, body)                   // upload: one tar with exactly those three files
//	svc.RequestInstall(ctx, actor, version)          // "Install": writes request.json
//	svc.CancelRequest(ctx, actor)                    // withdraw a request the helper has not claimed yet
//
// An upload handler should wrap the body in http.MaxBytesReader(w, r.Body,
// MaxBundleBytes) and pass the original package file name as DebName. Errors
// are sentinels (ErrBadSignature, ErrChecksum, ErrWrongArch, ErrDowngrade,
// ErrAlreadyInstalled, ErrBusy, ...) for errors.Is. The view shows
// Status.Installing while the helper works, polling Status or reacting to the
// connection loss while the hub restarts, and Status.Last afterwards.
//
// # Agents
//
// Nothing extra is needed. The new hub embeds the new agent binaries; every
// agent that reconnects with an older version is updated automatically
// (decision #20). The hub's own agent is packaged: its binary comes with the
// .deb and the maintainer script restarts it.
package update
