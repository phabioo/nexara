# Security review v0.1

Date: 2026-10-01 · Base: `main` @ `8eb7c86` · Read-only review by a subagent, checked by the orchestrator. Live checks ran against `nexus dev --demo` and two local `nexus serve` instances.

## Summary

No Critical or High findings; no remote code execution or authentication bypass found. Auth (argon2id, hashed session IDs, TOTP replay guard, strict cookies), CSRF on every state-changing route, WebSocket CSRF + Origin check, strict CSP, the fixed agent action list with validated arguments, remote-command construction, PKI key modes and the release signature chain hold up. The findings are hardening and design gaps.

## Findings

| ID | Sev | Title | Location | Proposed fix | Confirmed |
| --- | --- | --- | --- | --- | --- |
| S-01 | Medium | Open SSE/shell streams survive logout, session expiry and operator reset | `httpserver/shellws.go`, `httpserver/sse.go` | Re-validate the session on every heartbeat/ping; close streams on logout/reset | SSE live, shell by code |
| S-02 | Medium | Unauthenticated slow-body connections are held forever (no read deadline for bodies) | `httpserver/server.go`, `middleware.go` | Per-request read deadline (30 s) for non-stream paths | live |
| S-03 | Medium | Enrollment with an existing hostname silently replaces that host (cert fingerprint swapped) | `enroll/handler.go` (`registerHost`→`reuseHost`) | Refuse (`ErrHostExists`) or suffix the name; replacing needs an explicit operator action | code + existing tests |
| S-04 | Medium | SSH bootstrap sends the password before the operator sees the host key (TOFU, #41) | `enroll/sshclient.go` | Two-phase flow (show fingerprint, confirm, then authenticate); at least audit the fingerprint | code (accepted design) |
| S-05 | Medium | Hub CA installed as a trusted root on devices has no name constraints, 10-year validity | `pki/pki.go` | Critical NameConstraints (.local, hostnames, private/loopback IP ranges, configured agent host), shorter validity | code |
| S-06 | Medium | No host removal/revocation route and no agent certificate renewal (agent certs expire after 1 year) | `grid/grid.go` | Remove host (revoke in DB + `Grid.Remove`), agent cert renewal over the mTLS channel | code |
| S-07 | Medium | Builds pinned to exactly Go 1.26.0 (patch releases with stdlib fixes exist) | `go.mod`, workflows | `toolchain` line with the latest 1.26.x or `check-latest`; `govulncheck` job in CI | partly (CVE scan blocked) |
| S-08 | Low | Per-account login limit lets a LAN attacker lock out the operator | `auth/login.go`, `ratelimit.go` | Lock per account+IP / progressive delay; let the admin socket clear it | live |
| S-09 | Low | Setup-code lock is global; anyone can grief the setup every 15 min | `setup/codes.go` | Per-IP counter or keep the printed code valid | live |
| S-10 | Low | Enrollment code ≈ 39.6 bits, rate limit per IPv6 address; CSR check before token check | `enroll/service.go`, `handler.go` | Longer code (pasted anyway), limit per /64 + global, check token first | code |
| S-11 | Low | No HSTS header | `httpserver/middleware.go` | `Strict-Transport-Security` on TLS responses | live |
| S-12 | Low | `nexus.db` (+ wal/shm) created with process umask (0644 outside systemd) | `store/store.go` | chmod 0600 after open | live |
| S-13 | Low | Agent self-update can overwrite the dpkg-owned `/usr/bin/grid-agent` (only on version skew) | `agent/runtime/update.go` | Refuse self-update for package-managed binaries | code |
| S-14 | Low | Release secret reachable by anyone who can push a tag; actions not SHA-pinned | `.github/workflows/release.yml` | GitHub Environment with required reviewer, tag protection, SHA-pinned actions | code |
| S-15 | Low | Audit gaps: setup unlock/lock, admin-socket commands, job queued, SSH host key in `host.link`; audit write failures only logged | `setup/*`, `grid/jobs.go`, `view_setup.go` | Add entries | code |
| S-16 | Low | `install.sh` not wrapped against truncated `curl \| sh` | `deploy/install.sh` | `main() { … }; main "$@"` | code |
| S-17 | Low | Pre-session cookies without `__Host-` prefix (cookie tossing from other services on the same host) | `auth/session.go`, `httpserver/helpers.go` | `__Host-` names | reasoning |
| S-18 | Info | After setup, an expired lock still rotates and logs a (useless) setup code | `setup/codes.go` | Clear `lockedUntil` in `Invalidate` | code |
| S-19 | Info | Smaller notes: HKDF subkeys instead of sharing `secret.key`; plaintext passphrase in wizard memory until commit; TOTP blob AAD not user-bound; `--token` visible in `ps`/sudo log during SSH link; no Host-header check; extra systemd hardening (`SystemCallFilter`, `ProtectProc`, `MemoryDenyWriteExecute`); no breach check, no step-up for the shell | various | as time allows | code |

## CLAUDE.md security rules

| Rule | Status |
| --- | --- |
| argon2id passwords | met (m=64 MiB, t=3, p=2) |
| Sessions: random, hashed, cookie flags, 12 h idle | met; streams not covered (S-01) |
| CSRF on every state-changing request | met (all non-GET routes verified live) |
| Strict CSP without inline scripts | met |
| Login rate limiting per IP and account | met; lockout side effect (S-08) |
| TOTP (optional in v0.1) | met |
| Fixed agent action list, no arbitrary commands | met (argv only, validated names, `--` before package names) |
| Shell as enrolled user, never root | met |
| Every action audited | partially (S-15) |
| First-run setup mode | met; global lock (S-09), stray code (S-18) |
| Never store SSH passwords / never log secrets | met |

## Not checked

- `govulncheck`: the vulnerability database was not reachable from the review environment → run in CI (S-07).
- Real agent on a Pi (mTLS, shell, apt) end to end; reviewed by code only.
- Timing side channels measured (reviewed in code only).
- GitHub repository settings (secret scope, tag protection).

## Resolution (wave 5)

All findings S-01 to S-18 were fixed in wave 5, S-19 (a, c, e, h) as well; S-19 (b, d, f, g, j) remain notes for later. Design decisions: #41 (two-phase SSH link), #45 (CA name constraints; the setup wizard only accepts agent addresses the CA covers), #46 (no silent host replacement), #47 (host removal now, agent certificate renewal in v0.2). S-14 also needs the repository settings (environment `release` with required reviewer, tag ruleset for `v*`), which the owner configures.
