# Umsetzungsstand v0.1

Stand: 30.09.2026 · Commit `eb1b87e` auf `main` · CI grün (Linux amd64 + arm64, `go test -race`)

Die Umsetzung folgt dem Plan „v0.1 mit Subagents“: Wellen mit parallel arbeitenden Sonnet-Agents, jedes Ergebnis vom Orchestrator geprüft, gemergt und per GitHub Actions getestet. **Pausiert nach Welle 2** auf Wunsch.

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

Zusätzlich vom Orchestrator: `internal/hub/agentbin` (eingebettete Agent-Binaries), CI-Workflow `.github/workflows/ci.yml`, Entscheidungen #27–#42 in `decisions.md`.

Umfang: 148 Go-Dateien, davon 52 Testdateien.

## Nächste Schritte

1. **Integration (1 Agent, sequenziell):** `nexus serve` und `nexus dev --demo` zusammenstecken (Config, Store, Secret-Key, CA + Server-Zertifikat mit Erneuerungsschleife, Setup-Codes ins Journal, Admin-Socket, Auth, Grid, Enroll, HTTP-Server mit TLS, `NextProtos: http/1.1`), `grid-agent run` mit Self-Link über `enroll.token_file`, `OnEnrolled` → `grid.Register`. Danach ist der Hub im Browser bedienbar.
2. **Welle 3 – Views (5 Agents parallel):** Login/TOTP, Setup-Assistent (QR mit `boombuler/barcode`), Overview, Packages mit Job- und Confirm-Dialog, Shell (xterm.js) + Add-Host-Dialog. Erweiterungspunkte: je eine `view_*.go` mit `routes<View>(mux)`, `s.layout(...)`, `s.sse.Register(...)`.
3. **Welle 4 – Auslieferung:** `scripts/build.sh`, Release-Workflow (Binaries, `.deb`, `SHA256SUMS`, ed25519-Signatur), `install.sh` für den Hub, `nexus uninstall`, systemd-Units (`RuntimeDirectory=nexus` für den Admin-Socket).
4. **Sicherheits-Review** durch einen read-only Agenten, danach Test auf den Pis (Gate: 2 Wochen stabil).

## Offene Punkte für die Integration

- Setup-Commit (Schritt „Ready“) muss `codes.Invalidate()`, `sessions.Clear()` und `mode.Invalidate()` aufrufen.
- `Options.SecureCookies` im HTTP-Server und die Cookies des Auth-Service aus derselben Einstellung speisen (dev: `false` auf 127.0.0.1).
- `views.Layout` hat noch kein Operator-Feld; der Server liefert `operatorName(r)`.
- Fehler-Mapping `grid.Err*` → HTTP-Status für die Views einheitlich festlegen.
- Installer muss das Verzeichnis für das Self-Link-Token anlegen (Gruppe lesbar für den Agenten).

## So geht es weiter (für eine neue Session)

Die Session, die weitermacht, arbeitet als **Orchestrator**: Sie schreibt selbst wenig Code, verteilt Arbeitspakete an Sonnet-Subagents (Agent-Typen `nexara-sonnet-high` / `nexara-sonnet-medium` aus `.claude/agents/`), prüft jedes Ergebnis und gibt es bei Mängeln an denselben Agenten zurück.

**Ablauf pro Welle**
1. Pakete mit klarem Scope schneiden: erlaubte Pfade, zu lesende Doku/Mockups/Screenshots, Akzeptanzkriterien, Tests. Pakete, die parallel laufen, dürfen keine gemeinsamen Dateien ändern (Ausnahme: `go.mod`/`go.sum`, beim Merge per `go mod tidy` lösen).
2. Jeder Agent arbeitet in einem eigenen Git-Worktree/Branch (`w<N>/<name>`) und committet dort.
3. Prüfung durch den Orchestrator: Diff lesen (Scope, Sicherheitsregeln aus `CLAUDE.md`), `gofmt -l`, `go build`, `go vet` (auch `GOOS=linux GOARCH=arm64`), `go test -race ./...`; UI-Pakete zusätzlich im Browser bei 390/768/1024/1440/1920 px gegen `docs/design/screenshots/` vergleichen.
4. Mängel als konkrete Liste an denselben Agenten zurück; erst nach erneuter Prüfung mergen (`--no-ff`).
5. Nach der Welle: alle Branches nach `main` mergen, CI grün abwarten, pushen, `docs/status.md` aktualisieren, **pausieren** und auf Freigabe warten.

**Pakete der nächsten Schritte**

*Integration (1 Agent, high):* `cmd/nexus` `serve` und `dev --demo` verdrahten.
- serve: Config laden, Store öffnen, `auth.LoadOrCreateSecretKey`, `pki.LoadOrCreateCA` + `EnsureServerCert(LocalNames, LocalIPs)` mit täglicher Prüfschleife, `setup.Codes` (Rotate beim Start, Ankündigung per slog ins Journal, `Run`), Admin-Socket (`setup-code`, `user-reset` → `auth.ResetOperators` + `Mode.Invalidate`), `grid.NewGrid` (HubVersion = buildinfo), `enroll.New` (OnEnrolled → `grid.Register`, WaitOnline über grid-Events), `httpserver.New` mit AgentHandler/AgentDownloadHandler/EnrollHandler, TLS über `pki.ServerTLSConfig(isRevoked = grid.IsRevoked)` mit `NextProtos: ["http/1.1"]`, sauberes Herunterfahren.
- dev --demo: HTTP nur auf 127.0.0.1, temporärer Store, `demo.Hub` als Hub und Enroller (`go hub.Start(ctx)`), SecureCookies aus; Flag `--seed` legt einen Demo-Operator an und überspringt das Setup, ohne Flag startet der Setup-Assistent mit Code auf der Konsole.
- `nexus setup code` / `nexus user reset` als Admin-Socket-Clients. `grid-agent run`: ohne Zertifikat und mit `enroll.token_file` zuerst `EnrollFromTokenFile`.
- Offene Punkte aus dem Abschnitt oben erledigen.

*Welle 3 – Views (5 Agents parallel, je eine `view_*.go` + Templates in `web/templates/pages` + eigene CSS-Sektion + Handler-Tests):*
| Paket | Inhalt | Referenz |
| --- | --- | --- |
| Login | Login, TOTP-Schritt, Access granted, Logout (`renderLogin` ersetzen, Handler existieren) | `Sign-in@2x*.png`, `Mobile · Sign-in` |
| Setup | 7 Schritte, Restore-Link ausgeblendet (#28), QR für Trust und TOTP (`boombuler/barcode`, inline SVG), Sperrzustand, Commit bei „Ready“ (User anlegen, TOTP versiegeln, `nexus.yaml` schreiben, Self-Link-Token) | `Setup@2x-*.png`, `Mobile · Setup` |
| Overview | CPU/Prozesse, Memory & Storage mit SVG-Kurve, Services + Neustart, Host-Tabs mit Q/E, Offline-Karte ohne WoL, Connection-lost-Band, Toast; Live-Werte per `s.sse.Register` | `@2x-overview`, `@2x-deviceoffline`, `Mobile · Overview` |
| Packages | Filter, Suche (inkl. `SearchPackages`), Ticker, Kacheln, drei Wartungskarten, Job-Dialog mit Live-Ausgabe (`job_started`/`job_output`/`job_done`), Hintergrund-Chip, Confirm-Dialog, Reboot-required | `@2x-packages`, `Mobile · Packages` |
| Shell + Add host | xterm.js + Fit-Addon über `/hosts/{host}/shell/ws?csrf=…`, mobile Tastenleiste, Texte laut „Deviations“; Add-Host-Dialog (SSH, Code, Fortschritt, Fehler) | `@2x-shell`, `@2x-linknewhost*`, `Mobile · Shell` |

Views späterer Versionen (History, Alerts, Containers, Settings, Power) werden nicht gerendert (#31).

*Welle 4 – Auslieferung (2 Agents, medium):* `scripts/build.sh` (erst Agents linux/arm64+amd64 nach `internal/hub/agentbin/bin/`, dann Hub, `CGO_ENABLED=0`, ldflags `internal/buildinfo.Version/Commit`), Release-Workflow bei Tags (Binaries, `.deb` per `dpkg-deb`, `SHA256SUMS`, ed25519-Signatur aus einem GitHub-Secret — Schlüssel legt der Nutzer selbst an), `install.sh` für den Hub (Arch, Prüfsumme + Signatur via `openssl`, Benutzer/Verzeichnisse/Dienst, Agent mit `enroll.token_file`, Ausgabe URL + Setup-Code + Fingerprint), `nexus uninstall`, systemd-Units (`RuntimeDirectory=nexus`).

Danach: Sicherheits-Review durch einen read-only Agenten, dann Test auf den Pis durch den Nutzer.

## Rahmenbedingungen der Arbeitsumgebung

- **Cloud/Linux-Session:** Tests inkl. `-race` laufen direkt; kein Sonderfall nötig.
- **Lokaler Windows-PC:** Smart App Control blockiert zeitweise frisch gebaute Test-Binaries; dort sind die Tests in GitHub Actions maßgeblich (#42). Worktrees ggf. von Hand unter `.worktrees/` (gitignored).
- GitHub-Job-Logs sind ohne Login nicht lesbar; CI meldet Test- und gofmt-Fehler deshalb zusätzlich als Annotationen (öffentlich über die REST-API `check-runs/{id}/annotations`).
- Go lokal 1.27, CI nutzt die Version aus `go.mod` (1.26); gofmt kann sich zwischen den Versionen minimal unterscheiden.
- Die Pis im Heimnetz sind nur lokal erreichbar; der Hardware-Test macht der Nutzer.
