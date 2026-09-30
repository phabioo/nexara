# Nexara Nexus

Self-hosted dashboard to monitor and manage computers in a home network (first: Raspberry Pis on Linux; later: Windows and macOS). Private use only, no cloud.

Product names (fictional brand **Nexara**):
- **Nexara Nexus** — the hub: web UI, API, auth, storage (`cmd/nexus`)
- **Nexara Grid** — host management; the per-device **Grid Agent** (`cmd/grid-agent`)
- **Nexara Shell** — the in-browser terminal (PTY on the agent, xterm.js in the browser)

## Source of truth

Read these before working on a feature:
- `docs/concept.md` — architecture, stack, data model, security, first-run setup, features, roadmap (German)
- `docs/decisions.md` — decisions already made; do not re-open them without asking
- `docs/design/DESIGN.md` — visual spec: tokens, typography, components, views
- `docs/design/mockups/*.dc.html` — design mockups (see "Porting the design")
- `docs/img/architecture.png`, `docs/img/roadmap.png`

If code and docs disagree, ask. When a decision changes, update `docs/decisions.md` in the same change.

## Architecture in one paragraph

One hub (`nexus`) runs on the Pi `frpi5`. Each managed device runs a Grid Agent that connects **outbound** to the hub over WebSocket with mTLS (hub = its own small CA). The browser only talks to the hub (HTTPS, HTMX, SSE; WebSocket for the shell). New Linux hosts are enrolled **hybrid**: the hub installs the agent once via SSH, then everything runs through the agent; the SSH credentials are discarded. Manual enrollment with a one-time token also exists (`grid-agent enroll --hub … --token …`). The hub also manages itself (its own agent).

## Repository

- Public GitHub repo `phabioo/nexara`, Go module path `github.com/phabioo/nexara`.
- Releases (binaries, `.deb`, `install.sh`, checksums, signature) come from GitHub Actions on version tags; the installer URL is `https://github.com/phabioo/nexara/releases/latest/download/install.sh`.
- Never commit secrets, keys, real hostnames/IPs beyond the documented examples, or backups.

## Stack and hard constraints

- Go, standard library first. `net/http` pattern routing, `html/template`, `embed`. No web framework.
- HTMX + SSE extension for UI updates; xterm.js only for the shell. **No Node, no bundler, no build step for the frontend.**
- Plain CSS with custom properties from `DESIGN.md`. Fonts are already vendored in `web/static/fonts` with `web/static/css/fonts.css` (Archivo variable incl. width axis, JetBrains Mono, Instrument Serif). HTMX, the SSE extension and xterm.js are vendored in `web/static/js/vendor` (see its README). No external CDNs at runtime.
- SQLite via `modernc.org/sqlite` (pure Go, **no CGO**). YAML only for startup config (`nexus.yaml`, `agent.yaml`).
- Libraries (keep this list short, ask before adding others): `coder/websocket`, `gopsutil`, `creack/pty`, `coreos/go-systemd` (D-Bus), `golang.org/x/crypto` (ssh, argon2), `pquerna/otp`, a YAML library.
- Cross-compile targets: linux/arm64 first, then linux/amd64; windows and darwin later. Build with `CGO_ENABLED=0`.
- No telemetry, no outbound calls except agent ↔ hub and optional SMTP later.

## Security rules (non-negotiable)

- Passwords: argon2id. Sessions: random ID, stored hashed, cookie `HttpOnly; Secure; SameSite=Strict`, 12 h idle timeout.
- CSRF token on every state-changing request (HTMX sends it as a header). Strict CSP without inline scripts.
- Login rate limiting per IP and per account. TOTP 2FA (optional in v0.1, mandatory from v0.2).
- Agent exposes only a fixed set of actions (packages, services, power, docker, shell). Never an endpoint that runs arbitrary commands as root.
- Shell runs as the enrolled user (the Pi's normal sudo user), never as root.
- Every action goes to the audit log (user, host, action, time, result).
- Install: one command (`install.sh`) on the hub device; everything after that happens in the UI. The installer prints URL, setup code and CA fingerprint.
- First run: hub starts in setup mode, prints a one-time setup code (installer output + journal) (8 chars, 60 min, auto-renew every 60 min, `sudo nexus setup code` for a new one, 5 wrong tries → 15 min lock). Until an operator exists, only the setup wizard is served and the agent endpoint is closed.
- Never store SSH passwords. Never log secrets.

## Porting the design

The mockups use a proprietary format (`<x-dc>`, `<sc-for>`, `<sc-if>`, `{{holes}}`, a `DCLogic` class). **Do not reuse or emulate that runtime.** Use them as the source for markup structure, exact CSS values, copy and behavior, and port to:
- `web/templates/layouts` — page shell (top bar, sidebar, bottom bar)
- `web/templates/pages` — full views (overview, packages, shell, login, setup, …)
- `web/templates/partials` — HTMX fragments (cards, tiles, tabs, live values, dialogs, banner)
- `web/static/css/nexus.css` — tokens + components, one file to start

Keep class names semantic (`.card`, `.tile`, `.tab`, `.banner`…). UI copy is English.

**Responsive is required from the start** (see "Responsive behavior" in `DESIGN.md` and `mockups/mobile/`): same components on every screen, only reflowed. Mobile-first CSS is fine, but the desktop look must match the mockups exactly. No separate mobile templates: one set of templates, layout changes only via CSS (media queries, container queries, `pointer`/`hover` queries). Test at 390, 768, 1024, 1440 and 1920 px widths.

## Repository map

```
cmd/nexus/              hub main
cmd/grid-agent/         agent main
internal/config/        YAML loading + defaults (shared)
internal/protocol/      hub ↔ agent message types (shared, versioned)
internal/pki/           CA, cert issuing, mTLS helpers
internal/hub/httpserver routes, middleware (auth, CSRF, headers), SSE, WebSocket
internal/hub/auth       users, argon2id, sessions, TOTP, rate limit
internal/hub/setup      first-run setup mode, setup code
internal/hub/grid       connected agents, enrollment, command dispatch, SSH bootstrap
internal/hub/store      SQLite schema, migrations, queries
internal/hub/alerts     rules + evaluation
internal/hub/views      template rendering, view models
internal/agent/*        metrics, packages (apt first), services, power, shell (PTY), docker, enroll
web/                    templates + static assets (embedded)
configs/                example YAML
deploy/systemd/         unit files
scripts/                build / cross-compile helpers
docs/                   concept, decisions, design
```

OS-specific code lives behind interfaces with build-tagged files, e.g. `packages/apt_linux.go`, later `packages/winget_windows.go`.

## Operations built in from v0.1

- Agent binaries are embedded in the hub (`go:embed`), the hub enrolls and auto-updates agents.
- Every host action is a job in a per-host queue with streamed output (SSE), dpkg-lock wait, audit entry.
- Audit log is written from v0.1 (the view comes in v0.2).
- Certificates (own CA, SANs incl. `.local`, auto-renew) as described in `docs/concept.md` → "Installation, Updates & Betrieb". Backup/restore and self-update follow in v0.2.
- `nexus dev --demo` runs the hub with simulated agents and the mockup sample data; build the UI against it first.
- PWA: `web/static/img/icon*.png|svg`, `favicon.svg`, `manifest.webmanifest` are ready to use.

## Working agreements

- Build in the order of the roadmap. Current target: **v0.1** (hub + Linux agent, SSH enrollment, login, setup wizard, live overview, packages via apt, Nexara Shell).
- Small, reviewable steps; each step compiles and has tests where logic exists (`go test ./...`, `go vet ./...`).
- Code, identifiers, comments, commit messages: English. Docs in `docs/` may be German.
- Prefer boring solutions. Ask before adding a dependency, a new table, or a new agent capability.
