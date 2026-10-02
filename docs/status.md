# Umsetzungsstand v0.1

Stand: 03.10.2026 · nach Welle 8 · CI grün (Linux amd64 + arm64, `go test -race`)

Die Umsetzung folgt dem Plan „v0.1 mit Subagents“: Wellen mit parallel arbeitenden Sonnet-Agents, jedes Ergebnis vom Orchestrator geprüft, gemergt und per GitHub Actions getestet. **v0.2 in Arbeit:** Wellen 7 (Unterbau) und 8 (Ansichten) fertig, Welle 9 (Sicherheits-Review, `v0.2.0-rc1`) als Nächstes. Das 2-Wochen-Gate für v0.1 wurde auf Wunsch übersprungen; rc2 läuft weiter auf frpi5.

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
| 5 | Sicherheits-Fixes | siehe `docs/security-review-v0.1.md` | Review ohne kritische/hohe Befunde; behoben: Streams enden mit der Session, Body-Zeitlimit, Login-Sperre pro Konto+IP, HSTS, `__Host-`-Cookies, HKDF-Teilschlüssel; zweistufiger SSH-Link mit Fingerprint-Bestätigung (#41), keine stille Host-Übernahme (#46), längere Codes, Token nicht mehr in `ps`; CA mit NameConstraints, 5 Jahre (#45); Host entfernen mit Widerruf (#47); Go 1.26.8 + `govulncheck` in CI, Release-Environment, `nexus.db` 0600, kein Self-Update paketierter Agents, Setup-Sperre pro IP, mehr Audit, `nexus user unlock`, mehr systemd-Härtung |
| 6 | Pi-Feedback | `nexus.js`, `layout*.go`, `sse.go`, Templates, `nexus.css`, `demo/large.go` | Navigation ohne Neuladen (htmx boost + OOB-Regionen, eine SSE-Verbindung, Ereignisse tauschen Fragmente, #48); Ansichten passen ab 1024 px in die Fensterhöhe, Listen scrollen in der Karte; Paketliste seitenweise (60) mit Updates zuerst; Services: fehlgeschlagene zuerst, inaktive gedimmt; Laufbänder lückenlos bei jeder Breite; `nexus dev --demo --demo-large` |
| 7 | v0.2-Unterbau | `history`, `backup`, `update`, `grid/renew.go`, `store` | Host-Tabs bleiben in der Ansicht (#54); Verlauf (`metrics_1m/1h`, Aggregation, Aufbewahrung, Abfragen 24 h/7 d/30 d), Tabelle `settings`, Audit-Aufräumen; Agent-Zertifikate erneuern sich über mTLS (#47); verschlüsselte Backups (nächtlich, vor Updates, Download, Restore, #55); Self-Update mit Root-Helfer `nexus-update.path/.service`, Signaturprüfung, Rollback (#50); `install.sh` legt das Paket als Rollback-Material ab |
| 8 | v0.2-Ansichten | `view_settings*.go`, `view_history.go`, `view_audit.go`, `view_totp.go`, `view_setup_restore.go`, `grid/capabilities.go`, `app/logring.go` | Settings mit 8 Karten (Operators inkl. Passphrase ändern, Security fest, Updates mit Prüfung/Upload/Installation, Backup mit Zeitplan/Download/Restore, Hosts & Capabilities mit Schaltern #56, Zertifikate mit Erneuern, Diagnose = Hub-Log, Audit-Karte); History mit SVG-Kurven 24 h/7 d/30 d in der Hub-Zeitzone; Audit-Vollansicht mit Filtern, Seiten und CSV-Export; TOTP-Pflicht mit Einrichtungsseite (#51, Demo-Ausnahme #57); Restore aus Backup im Setup mit Neustart (#55) |

Zusätzlich vom Orchestrator: `internal/hub/agentbin` (eingebettete Agent-Binaries), CI-Workflow `.github/workflows/ci.yml`, Entscheidungen #27–#42 in `decisions.md`.

Umfang: 359 Go-Dateien, davon 164 Testdateien.

## Nächste Schritte

1. **Welle 9:** Sicherheits-Review v0.2 (u. a. Passphrase-Prüfung in Settings außerhalb des Hash-Semaphors, Backup-Passphrase im Download-Dialog, Upload-Pfade, Capability-Schalter), Fixes, Release `v0.2.0-rc1` (Tag pusht der Owner).

## Offene Punkte

- Hub-eigener Agent: Unit aus `script.go` (`/usr/local/bin/grid-agent`) plus Drop-in auf `/usr/bin/grid-agent`; Self-Update verweigert paketierte Binaries (S-13), Update kommt mit dem Paket.
- `install.sh` braucht OpenSSL ≥ 3 (Bookworm oder neuer).
- Setup-Session-Cookie: das `__Host-`-Präfix setzt ein Shim in `httpserver/cookies.go`; sauberer wäre eine Namensoption in `setup.SessionOptions`.
- Bei der Kopplung per Code gibt es kein „Ersetzen“ (nur beim SSH-Link); ein abgelehnter Code ist verbraucht.
- Diagnose: Agent-Logs bräuchten eine neue Agent-Fähigkeit – offen, braucht eine Entscheidung (#56).
- Settings: Karte „History retention“ aus dem Mockup fehlt (Aufbewahrung über `history.retention_days` geht bisher nur per Einstellung); Audit-Karte ohne Gesamtzahl.
- Audit-Log: bei sehr großen Logs könnte ein Index `audit_log(host, ts)` helfen (Migration).
- `grid-agent --help` nennt nur `--token`, nicht `--token-file`.
- `govulncheck` lief noch nie (Datenbank aus der Session nicht erreichbar) – erster CI-Lauf zeigt es.

## UI ausprobieren

- `go run ./cmd/nexus dev --demo --seed` → http://127.0.0.1:8080, Anmeldung `demo` / `nexara-demo-passphrase` (ohne TOTP, nur im Demo-Modus, #57)
- `go run ./cmd/nexus dev --demo` → Setup-Assistent, Setup-Code steht auf der Konsole
- `--demo-large` dazu → ein Demo-Host mit ~900 Paketen, 31 Units und 5 Mounts (Größenordnung des echten frpi5)

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
