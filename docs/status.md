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

## Rahmenbedingungen der Arbeitsumgebung

- Windows **Smart App Control** blockiert zeitweise frisch gebaute Test-Binaries. Maßgeblich sind die Tests in GitHub Actions (#42).
- GitHub-Logs sind ohne Login nicht lesbar; CI meldet Test- und gofmt-Fehler deshalb als Annotationen.
- Eigene Agent-Typen (`.claude/agents/nexara-sonnet-*.md`) und automatische Worktree-Isolation greifen erst nach einem Neustart der Claude-App (Git wurde während der Session installiert). Bis dahin: `general-purpose` mit Sonnet, Worktrees unter `.worktrees/` von Hand.
