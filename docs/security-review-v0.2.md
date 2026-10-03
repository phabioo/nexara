# Security review v0.2

Date: 2026-10-03 · Base: `claude/zealous-wozniak-26b1q7` @ `fcd948d` (= `main` after wave 8 plus a docs commit) · Three read-only reviews by subagents (A: authentication, sessions, setup; B: self-update, root helper, backups; C: grid, certificates, v0.2 views), each finding confirmed by the reviewer (live, by a throwaway test, or by code reading as noted) and spot-checked by the orchestrator.

## Summary

One High finding: the package's `postinst` follows a symlink the hub user can plant in `/etc/nexus`, so a compromised hub process can make root hand it any file on the next package configure (B-01). It breaks the self-update design rule that the hub never gets root (#50). No remote code execution and no authentication bypass from the network. The signed update chain (no unsigned install, no downgrade), the backup encryption and archive handling, certificate renewal, the TOTP enrollment gate, CSRF on all new routes and the escaping in the new views hold up.

The Medium findings are about rate limits that can be raced with parallel requests (A-01, A-02), streams without a body deadline (A-03), a misbehaving agent filling the audit log or the History view's memory (C-01, C-02), and queued package jobs that still run after "Packages" is switched off (C-03).

## Findings

| ID | Sev | Title | Location | Proposed fix | Confirmed |
| --- | --- | --- | --- | --- | --- |
| B-01 | High | `postinst` follows a symlink planted by the hub user: root `chown`/`chmod` (and create) on any path | `deploy/debian/postinst` (`[ ! -e ] && cat >`, unconditional `chown`/`chmod` of `/etc/nexus/nexus.yaml`) | Never touch an existing hub-writable path as root; create the file only when absent, from a root-owned temp file with `install -m 0640 -o nexus -g nexus` (replaces a planted link instead of following it) | live (shell, as root against a link planted by another user) |
| A-01 | Medium | Sign-in and second-factor limits can be raced: the check comes before verification, the failure is counted after | `auth/login.go` (`Login`, `VerifySecondFactor`), `auth/loginlimits.go` | Reserve the attempt atomically before verifying (IP, account+IP, account, challenge), refund on success | Go test over HTTP: 148 of 1000 parallel TOTP guesses on one challenge evaluated; 60 parallel passphrase guesses from one IP, none limited |
| A-02 | Medium | Passphrase change: argon2 outside the hash semaphore, attempt lock racy → a session holder can OOM the hub or brute-force the current passphrase | `httpserver/view_settings.go` (`handlePassphrase`) | Verify through `auth.Service` (semaphore), reserve attempts atomically, one change in flight per operator, audit throttled attempts | live: 300 parallel requests OOM-killed the dev hub; 100 parallel wrong values all evaluated |
| A-03 | Medium | Stalled request bodies hold connections forever on the body-limit-exempt paths (S-02 only half fixed); the restore upload adds an unauthenticated one | `httpserver/bodylimit.go` | Apply the body deadline and cap whenever an exempt path has a body; the restore upload starts with the normal deadline and extends it per read | live (raw sockets, held > 70 s) |
| C-01 | Medium | A connected agent can flood the audit log with `cert.csr` ("not due" is audited per message) | `grid/renew.go` (`onCertCSR`) | Audit "not due" at most once per host and hour; close the connection after repeated bad requests | Go test: 3000 audit rows in 0.66 s over mTLS |
| C-02 | Medium | History: unbounded distinct mount names → memory/CPU per page load (a compromised agent or mount churn) | `history/series.go` (`DiskSeries`) | Pick at most 12 mounts (those of the newest sample) before allocating | Go test: 768 MB allocated for one 24 h load |
| C-03 | Medium | Queued package jobs still run after "Packages" is switched off (#56) | `grid/jobs.go` (`pumpLocked`), `grid/capabilities.go` | Check the capability in `pumpLocked`; cancel queued jobs on switch-off; running job: owner decision | Go test: queued job started after switch-off |
| A-04 | Low | Per-IP limits key on the exact IPv6 address; unknown-user floods use both argon2 slots indefinitely; setup lock can be held with ≥ 10 addresses | `auth/loginlimits.go`, `setup/codes.go`, `auth/service.go` | Key IPv6 by /64; bound the hash-semaphore queue (429 above N waiters); small global budget for unknown users | Go test: 1000 logins from one /64, none limited |
| A-05 | Low | Crafted backup (sparse tar member, hostile KDF header) forces GBs of hashing/disk writes; needs a setup session | `backup/archive.go`, `backup/crypt.go` | Reject PAX/sparse members, cap the sum of member sizes and the decrypted stream, lower the restore KDF ceiling | Go test: 8.7 KB file → 1.5 GB staged |
| A-06 | Low | The "one-time" setup code is not consumed by a successful unlock | `setup/codes.go`, `setup/session.go` | Invalidate the code after a successful unlock (`sudo nexus setup code` issues a new one) | code |
| B-02 | Low | Backup CLI stays root when the `nexus` user is missing (fail-open) | `cmd/nexus/privdrop_linux.go` | Fail instead | code |
| B-03 | Low | Audit gaps: failed restores, CLI backups (incl. the helper's pre-update backup) | `backup/restore.go`, `app/backup.go` | Audit failures; audit CLI backups into the database file | code |
| B-04 | Low | Version order of `rc10` vs `rc2` is lexical (differs from dpkg): a legitimate rc2 → rc10 update is refused | `update/version.go` (`cmpIdent`) | Compare numeric tails like dpkg | `go run` |
| B-05 | Low | Root helper: `Lstat` then `OpenRoot`/`Open` on hub-controlled paths (symlink/FIFO swap window; self-inflicted DoS only) | `update/apply.go` | `os.SameFile` after `OpenRoot`; `O_NOFOLLOW\|O_NONBLOCK` and re-check on the fd | code |
| C-04 | Low | An agent handshake in flight survives host removal (accepted on a detached host state) | `grid/conn.go` (`accept`) | Under `g.mu`, require the host still registered and the certificate not revoked | Go test |
| C-05 | Low | Race between opening a shell and switching the shell off | `grid/shell.go` (`OpenShell`) | Re-check the capability when registering the session | code |
| C-06 | Low | Capability switches fail open if the settings read fails at startup | `grid/capabilities.go` (`loadCapsOff`) | Fail startup | code |
| C-07 | Low | CSV export not audited when the client aborts | `httpserver/view_audit.go` | Audit with a non-cancelled context, before streaming | code |
| C-08 | Low | The hub's own host is protected from removal only in the UI | `httpserver/view_settings_hosts.go`, `view_overview.go` | Owner decision | code |
| A-07 | Info | v0.1 operators without TOTP: whoever knows the passphrase can enroll first and lock the owner out | `auth/enroll.go` | Inherent to #51; release note; admin-socket "reset TOTP" later | code |
| A-08 | Info | `nexus.yaml` accepts a session idle timeout up to 720 h (#52 says fixed 12 h); `security.totp_required` is a dead key | `config/hub.go` | Pin 12 h in `auth`, ignore both keys | code |
| A-09 | Info | Setup-restore audit entries land in the database that the restore replaces; throttled passphrase changes not audited | `view_setup_restore.go`, `backup/restore.go`, `view_settings.go` | Carry the entries over; audit the 429 path | code |
| B-06 | Info | Backup download/restore and update install need only a session (no step-up) | `view_settings_backup.go`, `view_settings_updates.go` | Owner decision (re-enter passphrase + TOTP) | live |
| B-07 | Info | `*.before-restore` key copies stay on disk; DB pool after the swap until exit | `backup/restore.go` | Close the store before the swap; mention the copies in the UI | code |
| B-08 | Info | After a manual `apt install`, UI updates are refused until `sudo nexus update-apply --no-rollback` (no rollback copy) | `update`, `deploy/install.sh` | Owner decision (UI hint) | code |
| C-09 | Info | Hub-log redaction is key-name based only | `app/logring.go` | Extend the key list | Go test |
| C-10 | Info | Agent-controlled text lands unbounded in audit `Detail` | `store/audit.go` | Cap at 500 characters | code |

Also noted (no finding): the hub's own root agent reads `/var/lib/nexus/self-enroll.token`, which the hub writes; a compromised hub can point it at another hub, but it controls that agent already (#4/#5).

## CLAUDE.md security rules

| Rule | Status |
| --- | --- |
| argon2id passwords | met; the passphrase change bypasses the hash semaphore (A-02) |
| Sessions: random, hashed, cookie flags, 12 h idle | met in code; config allows more (A-08) |
| CSRF on every state-changing request | met (22 new routes checked live) |
| Strict CSP without inline scripts | met (no inline script/style/handlers in the new templates) |
| Login rate limiting per IP and per account | met sequentially; raceable (A-01), IPv6 /64 (A-04) |
| TOTP mandatory from v0.2 | met (gate covers views, SSE, shell, POSTs) |
| Fixed agent action list, shell never as root | met; capability switch leaks queued jobs (C-03) |
| Every action audited | mostly; gaps B-03, C-07, A-09 |
| Setup code one-time, 60 min, 5 tries → lock | not consumed on unlock (A-06) |
| Never store SSH passwords, never log secrets | met |
| Hub never gets root (#50) | broken by `postinst` (B-01) |

## Status (wave 9)

All findings were fixed in wave 9 except where noted; each fix has a regression test.

| ID | Status |
| --- | --- |
| B-01 | fixed: `postinst` creates `nexus.yaml` only when nothing is there and never touches an existing one |
| A-01, A-02, A-04 | fixed: atomic reserve-and-refund limits (sign-in, second factor, passphrase check), one operator action at a time, IPv6 keyed by /64, bounded hash queue, separate budget for unknown users |
| A-03 | fixed: every request with a body gets the deadline and cap; only the restore upload skips the size cap |
| A-05 | fixed: no PAX/sparse members, 1 GiB archive cap, lower KDF ceiling on restore |
| A-06 | fixed: the setup code works once |
| A-07 | accepted (inherent to #51); noted in `docs/status.md`, admin "reset TOTP" planned for v0.3 |
| A-08 | fixed: idle timeout pinned at 12 h, `session_idle_hours` and `totp_required` ignored |
| A-09 | fixed: restore audit entries end up in the restored database; first throttled passphrase attempt of a block audited |
| B-02, B-03, B-04, B-05, B-07 | fixed |
| B-06 | in progress: step-up with passphrase + TOTP for backup download, restore and update install (#58) |
| B-08 | fixed: the Updates card explains a missing rollback copy and shows the command (#61) |
| C-01 … C-10 | fixed (C-03 per #59, C-08 per #60) |

