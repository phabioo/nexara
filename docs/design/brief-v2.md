# Nexara Nexus – design brief v2 (for Claude Design)

Goal: a new visual design and UX for the existing Nexara Nexus web interface. **Features stay the same**; layout, visual language and interaction may change. Reference for the design *language and UX* (not a 1:1 copy): the FrameBeam Hub (`github.com/phabioo/framebeam`, `docs/design/tokens.md`, `docs/design/hub.md`, `server/internal/web`): calm, light-first, warm off-white surfaces, white cards with fine borders, IBM Plex Sans/Mono, mono for technical values and small uppercase labels, cyan accent, dark primary buttons, status pills, a fixed left sidebar, light/dark/system themes.

## Product in one paragraph

Self-hosted dashboard on a Raspberry Pi ("hub", e.g. `frpi5`) to monitor and manage the computers of a home network (Raspberry Pis now, Windows/macOS later). One operator (owner), private use, LAN/VPN only. Each managed device runs a Grid Agent; the hub shows live values, manages packages (apt), opens an in-browser terminal (Nexara Shell), keeps history and an audit log, does backups and self-updates. Brand: **Nexara** (products: Nexara Nexus = the hub/UI, Nexara Grid = host management, Nexara Shell = terminal). Keep the Nexara name and mark (`web/static/img/icon.svg`, `favicon.svg`); the logo may be redrawn in the new style.

## Hard constraints for the design

- **Responsive is required**: one set of screens that reflows; design at **1440 × 900** (desktop) and **390 × 844** (phone); it must also work at 768, 1024 and 1920. Touch targets ≥ 44 px on touch devices; nothing may need hover.
- **Themes**: light (default) and dark, plus "system". The Nexara Shell terminal stays dark in both themes.
- **Self-hosted, offline**: no external fonts/CDNs at runtime. IBM Plex Sans/Mono (OFL) will be vendored; any other font must be freely licensed.
- **Technical style limits** (implementation: server-rendered HTML + HTMX, strict CSP): no inline styles per element → widths/percentages come from classes (bars in steps of 1 %), charts are simple inline SVG (lines, areas, bars), no canvas/WebGL. Animations: CSS only, subtle; respect reduced motion.
- **Live data**: values update in place every few seconds (CPU, memory, temperature, job output). Designs should show where live values sit and how "updating", "offline" and "reconnecting" look.
- **Keyboard**: switching hosts with `Q`/`E` (previous/next) must stay possible; show the hint in the host switcher.
- UI copy is **English**.

## Information architecture

Global (no host): Overview of all hosts (new idea welcome), History, Settings (+ Audit log), Add host.
Per host: Overview (live), Packages, Shell, History. Switching the host keeps the current view (on Packages of host A → Packages of host B).
Host switcher: today host tabs at the top (name, update badge, red dot when offline/reboot required, "+ Host"). **Place it where it fits the new design** (sidebar list, header switcher, …); it must handle 1–10+ hosts and work on phones.
Navigation today: Overview, Packages, Shell, History, Settings; phone: bottom nav (Overview, Packages, Shell, More → History, Settings, operator, sign out).
Reserve room (do not design in detail) for later versions: **Power** (reboot/shutdown/Wake-on-LAN, v0.3), **Alerts** (view + badge, v0.3), **Containers** (Docker, v0.4), **Logs** (incl. agent logs, v0.4), Windows/macOS hosts (v1.0, different OS icons).

## Screens and their content

Sample data (demo mode): hosts `pi5-media` (192.168.10.21, hub + agent, Raspberry Pi 5, 4 cores, 47.2 °C, uptime 41 d 6 h, 3 updates), `pi3-dns` (192.168.10.5, 2 updates), `pi4` (192.168.10.30, offline). Operator `fabio`.

1. **Login** – operator ID, passphrase, "remember this device"; second step: 6-digit TOTP code; states: wrong entry, rate-limited ("try again in 12 min"), "Hub online" notice after setup, "Access granted" interstitial.
2. **Two-factor enrollment** (operator without TOTP after sign-in, mandatory) – QR code, manual key (grouped), 6-digit code, sign out link, recovery hint `sudo nexus user reset`.
3. **Setup wizard (first run, 7 steps)** – Unlock (setup code from installer output, attempts left, lock state; "Restore from a backup instead"), Trust (CA certificate: QR, per-device downloads iOS/Android/macOS/Windows/Linux, fingerprint), Operator (ID, passphrase ×2, strength meter), Two-factor (QR, key, code; no skip), Hub (name, time zone, agent address, HTTPS port, history retention), Self-link (manage this device too: toggle + capabilities), Ready (summary, "Enter Nexus"). Restore path: upload backup file (.nxbk) + passphrase → preview (hub, created, version, files) → confirm → restarting.
4. **Host overview (live)** – CPU (usage %, model, per-core bars, SoC temperature with throttling threshold, load average, "Show processes"), "Open shell" shortcut, "Restart failed units", Memory & storage (RAM %, swap, disks with % bars, a small usage curve), temperature, uptime, network, Services (systemd units: running/failed/inactive, restart button; failed first), host state (online/offline card with "last seen", reboot required), Remove host (confirm dialog). Empty state: "No hosts yet" → Add host.
5. **Packages** – filter tabs All / Updates / Installed / Available / Orphaned with counts, search, package tiles (name, version → new version, description, action: upgrade/install/remove), paging ("show more", ~900 packages on a real Pi), maintenance cards: Sync sources (`apt update`, last sync), System upgrade (n updates), Clean up (orphans). Confirm dialog per action (danger variant for remove/clean). **Job dialog**: live terminal output, progress bar, state (queued/running/done/failed/canceled), cancel, "Reboot required" tag. A small running-job indicator visible on every page.
6. **Nexara Shell** – full-height terminal (xterm), header with host, user, protocol "GRID · mTLS", connection state (connecting/ready/closed, reconnect), phone: extra key bar (Esc, Tab, Ctrl, arrows, |, ~, /).
7. **History** – ranges 24 h / 7 d / 30 d; charts: CPU %, Memory %, SoC temperature °C, Network (RX/TX), one per disk mount; each with current value, min/avg/max, time axis (start, middle, now), gaps when the host was offline.
8. **Settings** – cards: Operators (ID, role, two-factor, last sign-in, change passphrase), Security (read-only facts: 2FA required, lockout after 5 attempts / 15 min, session timeout 12 h), Updates (hub version, agents x/y current, opt-in GitHub check, check now, upload update file, install with confirm, progress/rollback result, "no rollback copy" hint with command), Backup (nightly time, keep n, last backup, back up now, download (passphrase), restore local backup → restart), Hosts & capabilities (per host: shell/packages switches, remove; hub's own host not removable), Certificates (CA fingerprint + expiry, hub certificate, names, per-host agent certificate expiry + renew, download CA), Diagnostics (hub log viewer), Audit log (last entries + "View all"). **Step-up dialog**: sign-in passphrase + 6-digit code before backup download, restore and update install.
9. **Audit log** – filters: range (24 h/7 d/30 d/all), result (all/ok/error/denied), host, operator, action group, search; list grouped by day, readable sentences ("apt upgrade on pi5-media finished"), error/denied tags, row expands to raw fields; CSV export; infinite "show more".
10. **Add host dialog** – two ways: (a) via SSH: address, user, port, display name, auth (password or hub key) → step 2 shows the host key fingerprint to confirm → progress steps (Connect, Detect system, Install agent, Enroll certificate, Agent online) with live state, failure + retry, "replace existing host" offer; (b) enrollment code: one-line command to copy, code expiry, waits for the agent and switches to progress.
11. **Shared states/components** – toasts (error with status), connection-lost band ("reconnecting"), session expired → login, offline host, empty states, confirm dialogs (normal/danger), forms with inline errors, tags/pills (ok, warn, error, neutral, update count), badges in navigation, progress bars, copy-to-clipboard command boxes, code/fingerprint display, loading states.

## Deliverables expected from Claude Design

- Design tokens (colors light + dark, type scale, spacing, radii, shadows) and components.
- All screens above at 1440 × 900, the main ones (overview, packages + job dialog, shell, settings, login, setup step) also at 390 × 844, plus dark-theme versions of overview and packages.
- Interaction notes: host switcher behaviour (incl. Q/E), live updates, dialogs, phone navigation.
- Handoff as before (`.dc.html` + screenshots), to be documented in a new `docs/design/DESIGN.md` (v2) before implementation.
