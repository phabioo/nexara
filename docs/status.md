# Umsetzungsstand v0.1

Stand: 01.10.2026 · nach Welle 4 · CI grün (Linux amd64 + arm64, `go test -race`)

Die Umsetzung folgt dem Plan „v0.1 mit Subagents“: Wellen mit parallel arbeitenden Sonnet-Agents, jedes Ergebnis vom Orchestrator geprüft, gemergt und per GitHub Actions getestet. **Pausiert nach Welle 4** auf Wunsch. Welle 4 liegt auf dem Session-Branch `claude/zealous-wozniak-26b1q7` (PR nach `main`).

## Fertig

| Welle | Paket | Pfad | Inhalt |
| --- | --- | --- | --- |
| 0 | Fundament | `internal/config`, `internal/protocol`, `internal/hub/store`, `internal/hub/grid/hub.go`, `cmd/*` | YAML-Config, Protokoll v1 (inkl. Enrollment, Paketsuche), SQLite-Schema + Migrationen, Verträge `grid.Hub`/`grid.Enroller`, Kommando-Gerüst |
| 1 | PKI | `internal/pki` | Eigene CA, Server-Zertifikat mit SANs + Neuausstellung, Agent-Zertifikate aus CSR, TLS-Configs inkl. Pinning und Widerruf |
| 1 | Auth | `internal/hub/auth` | argon2id, Sessions (12 h idle, 30 d absolut, Remember #29), TOTP mit Replay-Schutz, Rate-Limit, CSRF, Audit, Operator-Reset |
| 1 | Setup-Modus | `internal/hub/setup` | Setup-Code (Rotation, Sperre), Setup-Session, Wizard-Zustand (7 Schritte), Admin-Socket |
| 1 | UI-Grundlage | `web/`, `internal/hub/views` | `nexus.css` (Tokens, Komponenten, alle Breakpoints), Layouts, Partials, Icon-Sprite, `nexus.js`, Renderer, Vorschau-Tool |
| 1 | Agent: Metriken + Dienste | `internal/agent/metrics`, `internal/agent/services` | gopsutil, SoC-Temperatur, systemd per D-Bus, Ports |
| 1 | Agent: apt | `internal/agent/packages` | Liste, Suche, Jobs, dpkg-Lock-Wartezeit, Abbruch, reboot-required |
| 1 | Agent: Shell | `internal/agent/shell` | PTY als Pi-User, nie root, saubere Umgebung |
| 2 | HTTP-Server | `internal/hub/httpserver` | Middleware (Header/CSP, Setup-Gate, Auth, CSRF), Login-Handler, Layout-Modell, SSE, Shell-WebSocket; Views als Stubs |
| 2 | Grid (Hub) | `internal/hub/grid` | Agent-Verbindungen (mTLS/WS), Registry, Live-Werte, Job-Queue, Shell-Sessions, Auto-Update, Update-Required-Ablauf |
| 2 | Kopplung | `internal/hub/enroll`, `internal/agent/enroll`, `cmd/grid-agent/enroll.go` | Enrollment-Codes, `install.sh`, SSH-Bootstrap, `grid-agent enroll`, Self-Link-Token |
| 2 | Agent-Laufzeit | `internal/agent/runtime`, `cmd/grid-agent/run.go` | Verbindungsschleife mit Backoff, Puffer 10 min, Dispatch, Selbst-Update |
| 2 | Demo-Modus | `internal/hub/demo` | Simulierte Hosts mit den Design-Beispieldaten, Jobs, Shell, Kopplung |
| 2½ | Integration | `internal/hub/app`, `cmd/nexus`, `cmd/grid-agent/run.go` | `nexus serve` (TLS, Zertifikats-Erneuerung ohne Neustart, Setup-Codes, Admin-Socket, Grid, Enroll), `nexus dev --demo [--seed]`, `nexus setup code`/`user reset`, Self-Link über `enroll.token_file`, Setup-Commit-Hook, `gridStatus`-Mapping |
| 3 | Login | `view_login.go`, `pages/login.html` | Anmeldung, TOTP-Schritt, „Access granted“ nach TOTP, Rate-Limit-Meldungen, „Hub online“ nach dem Setup |
| 3 | Setup-Assistent | `view_setup*.go`, `views/qr.go` | 7 Schritte, Sperrzustand, QR als Inline-SVG, CA-Download (`.crt`, iOS-Profil), Commit über den Hook |
| 3 | Overview | `view_overview.go`, `models_overview.go` | CPU/Prozesse, Memory & Storage mit SVG-Kurve, Services + Neustart, Host-Tabs Q/E, Offline-Karte, Live-Werte per SSE |
| 3 | Packages | `view_packages.go`, `models_packages.go` | Filter, Suche, Kacheln, Wartungskarten, Confirm- und Job-Dialog mit Live-Ausgabe, Abbruch, Reboot-Hinweis |
| 3 | Shell + Add host | `view_shell.go`, `view_addhost*.go`, `shell.js` | xterm.js mit Fit, mobile Tastenleiste, Reconnect; Add-Host-Dialog (SSH mit Fortschritt, Enrollment-Code) |
| 3 | Querschnitt | Layout, `nexus.js`, `layout_live.go` | Abmelden, Job-Chip auf allen Seiten, eine SSE-Verbindung pro Seite, Live-Topbar, Fehler-Toasts mit echten Statuscodes, Session-Ablauf → Login |
| 4 | Build & Release | `scripts/`, `.github/workflows/release.yml`, `internal/release` | `build.sh` (Agents vor dem Hub, `CGO_ENABLED=0`, Version per ldflags), `package-deb.sh`, `release.sh` (`SHA256SUMS` + ed25519-Signatur), Release-Workflow bei `v*.*.*` (Tag streng geprüft, Secret nur im Signierschritt), Go-Prüfung der Signatur für das Selbst-Update in v0.2 |
| 4 | Install & Paket | `deploy/`, `cmd/nexus/uninstall.go`, `internal/hub/app/uninstall.go` | systemd-Units (Hub gehärtet, `RuntimeDirectory=nexus`), Maintainer-Skripte (Benutzer `nexus`, Verzeichnisse, Configs, Self-Link-Agent), `install.sh` (Signatur + Prüfsumme, Ausgabe URL, Setup-Code, Fingerprint), `nexus uninstall [--purge]` |

Zusätzlich vom Orchestrator: `internal/hub/agentbin` (eingebettete Agent-Binaries), CI-Workflow `.github/workflows/ci.yml`, Entscheidungen #27–#42 in `decisions.md`.

Umfang: 201 Go-Dateien, davon 82 Testdateien.

## Nächste Schritte

1. **Erstes Release:** Tag `v0.1.0-rc1` setzen → Release-Workflow baut, signiert und veröffentlicht. Voraussetzung: Secret `NEXARA_RELEASE_SIGNING_KEY` ist angelegt (öffentlicher Schlüssel: `deploy/keys/nexara-release.pub`, #43).
2. **Sicherheits-Review** durch einen read-only Agenten.
3. **Test auf den Pis** durch den Nutzer: `curl -fsSL https://github.com/phabioo/nexara/releases/latest/download/install.sh | sudo sh` (bei einem Pre-Release die URL des Tags verwenden), Gate: 2 Wochen stabil.

## Offene Punkte aus Welle 4

- Der Hub-eigene Agent liegt als `/usr/bin/grid-agent` im Paket; die Unit stammt aus `script.go` (`/usr/local/bin/grid-agent`), ein Drop-in `/etc/systemd/system/grid-agent.service.d/10-package-binary.conf` setzt `ExecStart` auf `/usr/bin/grid-agent`. Auto-Update des Hub-eigenen Agenten würde eine dpkg-Datei überschreiben; da Hub und Agent aus demselben Build stammen, tritt es nur bei Versionsabweichung auf – im Review prüfen.
- `nexus.db` entsteht mit 0644 (Verzeichnis 0750 schützt); im Review auf 0600 setzen.
- `install.sh` braucht OpenSSL ≥ 3 (`-rawin`), also Raspberry Pi OS/Debian Bookworm oder neuer.

## UI ausprobieren

- `go run ./cmd/nexus dev --demo --seed` → http://127.0.0.1:8080, Anmeldung `demo` / `nexara-demo-passphrase`
- `go run ./cmd/nexus dev --demo` → Setup-Assistent, Setup-Code steht auf der Konsole

## So geht es weiter (für eine neue Session)

Die Session, die weitermacht, arbeitet als **Orchestrator**: Sie schreibt selbst wenig Code, verteilt Arbeitspakete an Sonnet-Subagents (Agent-Typen `nexara-sonnet-high` / `nexara-sonnet-medium` aus `.claude/agents/`), prüft jedes Ergebnis und gibt es bei Mängeln an denselben Agenten zurück.

**Ablauf pro Welle**
1. Pakete mit klarem Scope schneiden: erlaubte Pfade, zu lesende Doku/Mockups/Screenshots, Akzeptanzkriterien, Tests. Pakete, die parallel laufen, dürfen keine gemeinsamen Dateien ändern (Ausnahme: `go.mod`/`go.sum`, beim Merge per `go mod tidy` lösen).
2. Jeder Agent arbeitet in einem eigenen Git-Worktree/Branch (`w<N>/<name>`) und committet dort.
3. Prüfung durch den Orchestrator: Diff lesen (Scope, Sicherheitsregeln aus `CLAUDE.md`), `gofmt -l`, `go build`, `go vet` (auch `GOOS=linux GOARCH=arm64`), `go test -race ./...`; UI-Pakete zusätzlich im Browser bei 390/768/1024/1440/1920 px gegen `docs/design/screenshots/` vergleichen.
4. Mängel als konkrete Liste an denselben Agenten zurück; erst nach erneuter Prüfung mergen (`--no-ff`).
5. Nach der Welle: alle Branches nach `main` mergen, CI grün abwarten, pushen, `docs/status.md` aktualisieren, **pausieren** und auf Freigabe warten.

## Rahmenbedingungen der Arbeitsumgebung

- **Cloud/Linux-Session:** Tests inkl. `-race` laufen direkt; kein Sonderfall nötig.
- **Lokaler Windows-PC:** Smart App Control blockiert zeitweise frisch gebaute Test-Binaries; dort sind die Tests in GitHub Actions maßgeblich (#42). Worktrees ggf. von Hand unter `.worktrees/` (gitignored).
- GitHub-Job-Logs sind ohne Login nicht lesbar; CI meldet Test- und gofmt-Fehler deshalb zusätzlich als Annotationen (öffentlich über die REST-API `check-runs/{id}/annotations`).
- Go lokal 1.27, CI nutzt die Version aus `go.mod` (1.26); gofmt kann sich zwischen den Versionen minimal unterscheiden.
- Die Pis im Heimnetz sind nur lokal erreichbar; der Hardware-Test macht der Nutzer.
