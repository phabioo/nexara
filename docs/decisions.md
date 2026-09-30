# Decisions

Settled decisions. Change them only deliberately and record the change here.

| # | Decision | Reason |
| --- | --- | --- |
| 1 | Hub + Grid Agent architecture; agents connect outbound to the hub | Cross-platform later, no open ports on hosts, no root SSH keys stored on the hub |
| 2 | Hybrid enrollment: SSH once to install the agent, then agent only; manual token enrollment as alternative | Convenient for Linux, works for Windows/macOS later |
| 3 | Hub runs on the Pi 5 `frpi5` | Most capable device in the network |
| 4 | The hub manages itself via its own Grid Agent | Appears like every other host |
| 5 | Shell runs as the Pi's normal sudo user, never root | Least privilege, same as SSH login |
| 6 | Friends run their own instance; no multi-tenant hub | Keeps auth and data model simple and safe |
| 7 | Remote access only through the existing WireGuard VPN | No public exposure of a root-capable dashboard |
| 8 | Stack: Go stdlib + html/template + HTMX (+SSE) + plain CSS; xterm.js for the shell only | Lightweight, no frontend build |
| 9 | YAML for startup config only; SQLite (`modernc.org/sqlite`, no CGO) for state | Hand-editable config, safe concurrent state |
| 10 | Hub ↔ agent: WebSocket + JSON over mTLS, hub is its own CA | Simple, bidirectional, revocable |
| 11 | argon2id passwords, TOTP 2FA (optional v0.1, mandatory v0.2), CSRF, strict CSP, audit log | Security baseline |
| 12 | First run: setup mode with one-time setup code in the journal (60 min, auto-renew, `sudo nexus setup code`, 5 tries → 15 min lock) | Nobody else in the LAN can claim a fresh hub |
| 13 | Alerts: dashboard only at first, e-mail later; no cloud push | Local-only principle |
| 14 | Extra features: Power (WoL/reboot/shutdown), history, alerts, Docker | Chosen scope beyond monitoring, packages, shell |
| 15 | Brand: Nexara (company), Nexus (hub/dashboard), Grid (host management/agent), Shell (terminal); mark = split hex, wordmark = Instrument Serif | Consistent naming in UI, code and docs |
| 16 | UI language English | Consistent with the design |
| 17 | One terminal command on the hub device installs everything; afterwards all administration happens in Nexus | Simplest setup for me and friends |
| 18 | Installer prints URL, setup code and certificate fingerprint; setup wizard step "Trust" installs the Nexara CA on devices | One browser warning at most, verifiable |
| 19 | Certificates include hostname, hostname.local (mDNS) and all IPs; hub re-issues them itself | Works without a DNS entry |
| 20 | Agent binaries are embedded in the hub; hub auto-updates agents | No internet needed for enrolling/updating agents |
| 21 | Self-update from Settings (opt-in GitHub check or uploaded file), signed, backup first, automatic rollback | Updates without terminal |
| 22 | Per-host job queue with live output, dpkg-lock wait, reboot-required detection | Safe, visible apt operations |
| 23 | Nightly + pre-update backups on the hub, encrypted download, restore in setup wizard (v0.2, see #28) | Recover from SD-card failure |
| 24 | Public monorepo github.com/phabioo/nexara (Go module `github.com/phabioo/nexara`); GitHub Actions builds signed releases; installer downloads from its GitHub Releases | One protocol, one version, token-free install |
| 25 | `nexus dev --demo` with simulated agents and the design's sample data | UI work without real Pis |
| 26 | Installable web app (manifest, app icon, favicon) | Feels like an app on phones and desktops |
| 27 | Audit log is written from v0.1; the audit view comes with Settings in v0.2 | No gap in the record, UI can wait |
| 28 | Backup & restore (nightly, pre-update, download, restore in setup) moves to v0.2; the "Restore" link is hidden in v0.1 | Keeps v0.1 small; belongs with Settings and self-update |
| 29 | "Keep me signed in": unchecked = browser-session cookie, checked = persistent cookie; both keep the 12 h idle timeout and a 30-day absolute limit; never skips TOTP | Survives phone/browser restarts without weakening the session rules |
| 30 | Grid Agent unit is not sandboxed (root, no `NoNewPrivileges`/`ProtectSystem`); safety comes from the fixed action list | apt, services, power and `sudo` in the shell need it |
| 31 | Views of later versions are hidden until that version ships | No dead buttons in the UI |
| 32 | YAML library `go.yaml.in/yaml/v3`; QR codes with `rsc.io/qr`, rendered as inline SVG | Maintained YAML fork; tiny QR encoder, CSP-friendly output |
| 33 | Jobs live in memory only (no table); `audit_log` is the record. Minute/hour history tables come with the History view in v0.2 | No new tables in v0.1; the live ring buffer covers the overview |
| 34 | `nexus dev --demo` serves plain HTTP on 127.0.0.1 only | Browsers treat localhost as secure; no certificates needed for UI work |
| 35 | `sudo nexus setup code` / `sudo nexus user reset` talk to the running service over a local admin Unix socket (`/run/nexus/admin.sock`, 0660 root:nexus) | No network surface, works while the service runs |
| 36 | Release signature: ed25519 over `SHA256SUMS`; verified with `crypto/ed25519` in the hub and `openssl` in `install.sh` | No extra tooling on the Pi or in Go |
| 37 | Hub code stays platform-neutral (develop on Windows); Linux-only code sits behind build tags | Fast local UI iteration |
| 38 | Enrollment runs over HTTPS `POST /grid/enroll` (token + CSR, agent pins the CA fingerprint); the response carries cert, CA, hub URL and the capabilities chosen in the UI. Self-link: the installer sets up the agent with `enroll.token_file`, the setup wizard writes that token | One enrollment path for SSH, code and self-link |
| 39 | Go directive 1.26 (required by `modernc.org/sqlite`) | Current SQLite driver |
