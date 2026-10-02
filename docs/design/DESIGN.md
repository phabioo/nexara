# Nexara Nexus — Design Handoff

Visual spec for implementing Nexara Nexus with **Go + server-side HTML (html/template) + HTMX + plain CSS + YAML**.

The files in `mockups/` are the design mockups. They use a proprietary mockup format (`<x-dc>`, `<sc-for>`, `<sc-if>`, `{{holes}}`, a `DCLogic` class) — **do not reuse that runtime**. Treat them as the source of truth for markup structure, CSS values, copy and behavior, and port them to Go templates + plain CSS + HTMX.

- `mockups/dashboard.dc.html` — main app: Overview, Packages, Shell, History, Alerts, Containers, Settings; Add-host, Job, Confirm and Power dialogs; offline, connection-lost and toast states
- `mockups/login.dc.html` — sign-in screen incl. TOTP step and "Access granted"
- `mockups/setup.dc.html` — first-run setup wizard (7 steps incl. Trust and Restore, code expiry and lockout states)
- `mockups/brand-mark.dc.html` — logo explorations (final = column "B+C")
- `mockups/mobile/*.dc.html` — phone layouts (overview, packages, shell, alerts, more menu, login, setup) at 390 × 844
- `mockups/app-icon.dc.html` — app icon, favicon, manifest; files in `web/static/img/`
- `web/static/img/nexara-mark.svg` — final logo mark, uses `currentColor`
- `screenshots/` — PNG exports of the artboards as visual reference

## Brand

- Company: **Nexara** (fictional). Products: **Nexara Nexus** (dashboard), **Nexara Grid** (device/host management), **Nexara Shell** (terminal).
- Mark: open hexagon + diamond core + data line in the gap (`web/static/img/nexara-mark.svg`). Used in the top pill, the sidebar node card, login/setup lockups and the bottom bar.
- Wordmark: "NEXARA" in Instrument Serif, uppercase. Product name next to it in Archivo Expanded, lime.
- All UI copy is English.

## Design tokens

```css
:root {
  --bg: #111214;          /* page */
  --bg-deep: #0b0c0d;     /* terminal, hero panels */
  --ink: #0d0e0f;         /* text on light/lime, black buttons, inputs on grey */
  --panel: #1d1f22;       /* chips, empty slots */
  --panel-2: #2a2c2f;     /* inactive tabs, dark pill segment */
  --line: #25282b;
  --text: #eceee9;
  --text-2: #c9cacc;
  --muted: #8d9093;
  --micro: #7a7e82;       /* tiny decorative metadata text */
  --lime: #c6f500;        /* primary accent */
  --lime-dark: #a3cc00;
  --card: #b4b6b9;        /* grey "contract" cards */
  --card-head: #c9cacd;
  --card-line: #8e9093;
  --chip-light: #d9dadc;
  --green: #22e06a;  --green-term: #35e36a;  --green-band: #0e3a1d;
  --blue: #2f9bff;   --blue-band: #3aa0e8;   --violet: #3000d6;
  --purple: #b04dff;
  --pink: #ff3f74;        /* errors, failed, orphaned */
}
```

Tile tones (colored strip + body gradient `linear-gradient(180deg, var(--b0) 0%, #17191b 80%)`):
lime `#c6f500/#2c3a08`, green `#22e06a/#0f3f2b`, blue `#2f9bff/#11304a`, purple `#b04dff/#2f1446`, pink `#ff3f74/#44121f`, grey `#b4b6b9/#2c2e31`.

## Typography

Self-host the fonts (no Google Fonts at runtime):

- **Archivo** at width 125 (expanded), weight 800/900, uppercase — headings, tabs, nav, card headers, labels (`font-stretch:125%`).
- **JetBrains Mono** 400–700 — body, data, inputs, buttons.
- **Instrument Serif** — wordmark and big banner titles ("UPDATED", "ACCESS GRANTED").

Sizes: card header 14px, section label 11px, body 12–13px, micro text 8px/10px uppercase.

## Layout (1440×900 reference, desktop)

- **Top bar (72px):** left = pill group (lime segment with mark + node number, dark segment with online count, two light-grey segments: packages up-to-date, temperature; rounded 19px ends). Right = host tabs (Nexara Grid) with `Q`/`E` key buttons and a dashed "+ Host" button. A host tab opens the view that is on screen for that host (decision #49). Tiny micro text lines at the top.
- **Sidebar (208px):** lime node card (title, uptime, `+` corner marks, big mark), nav (Overview / Packages / Shell; active = light grey, has-badge = lime + count box), host "portrait" card at bottom (pixel-art board on violet).
- **Main:** one of three views.
- **Bottom bar (44px):** left = last action log line (`>` in lime). Right = live indicator + host + IP + mark + NEXARA NEXUS wordmark. No game-style buttons.

## Components

- **Contract card:** grey card, header bar (lime for primary, `--card-head` otherwise), tag chip (dark/light/lime), mono description, stepped checker divider, objective rows (label + black 14px bar with lime fill + 38–46px value box), full-width black button (or light variant) with ⓘ/arrow icon at the right. Dark variant: `#141618` bg, lime header text.
- **Checker divider:** `repeating-linear-gradient(90deg,#9c9ea1 0 40px,transparent 40px 80px) top/100% 5px no-repeat, repeating-linear-gradient(90deg,transparent 0 40px,#9c9ea1 40px 80px) bottom/100% 5px no-repeat`, height 10px.
- **Item tile:** 16px colored strip with small glyph + label, 2×2 pixel squares on the right, gradient body, optional value badge bottom-right.
- **Tabs / chips:** 32px, Archivo 13px, `--panel-2` → hover `#3a3d40` → active lime; count box with 2px dark left border.
- **Ticker band:** 24px, scrolling uppercase Archivo text with `+` separators (CSS `translateX(-50%)` loop). Blue on Packages, dark green on Shell, blue on Login.
- **Banner/toast:** lime box 620px, serif title between two `+` crosshairs, subtitle row, small square corner markers, auto-hide ~2.6s.
- **Modal (Add host):** grey card with lime header + close button, dark 36px inputs, auth toggle (SSH key / Password), pink error row, Cancel (light grey) + Link host (black).
- **Decor:** faint scanline background, crosshair `+` marks, micro metadata text. Decorative only.

## Views & behavior

- **Overview:** three cards — CPU (per-core bars + temperature; toggle to top-process list), Memory & storage (dark card, live CPU curve on dotted green background, resource tiles for RAM/Swap/Disks, "Open shell"), Services (one row per systemd unit, failed = pink, "Restart failed units").
- **Packages:** filter tabs (All/Updates/Installed/Available/Orphaned) with counts, search, ticker, 3-column package tiles with per-package action, right column with three cards: Sync sources (`apt update`), System upgrade (`apt upgrade`), Clean up (`autoremove + clean`).
- **Shell:** green terminal panel with ticker bands, connection info on the left, scrollable output. In the real app use **xterm.js over WebSocket** to a PTY session, styled to match.
- **Login:** violet band with mark + serif wordmark, grey card (Operator ID, Passphrase with show toggle, remember me, error row, Sign in), second state "Step 2 of 2" with a 6-digit TOTP field (Back + Verify), success state "Access granted" → Enter Nexus. "Keep me signed in on this device" is defined in `docs/decisions.md` (#29).
- **Setup wizard (first run):** top pill "Nexus · Setup · n/7", blue ticker, left = serif lockup + step list (done = lime number box with check, current = light-grey label, upcoming = muted), right = grey card with lime header "Step n/7", progress segments, tag, lead, checker divider, step fields, pink error row, Back (light grey) + Continue (black). 7 steps: Unlock (installer output with URL/code/fingerprint, code field, attempts counter, 15-min lock state, "Restore from a backup instead"), Trust (QR + per-device CA download chips + fingerprint, skippable), Operator (ID, passphrase ×2, 5-segment strength meter), Two-factor (QR, manual key, 6-digit code; no "Skip for now" from v0.2, #51), Hub (name, time zone, agent address, HTTPS port, history retention chips), Self-link (toggle + capability chips), Ready (lime "Hub online" serif banner + summary rows, Link first host / Enter Nexus).
- **Add host dialog:** grey modal with lime header and corner squares; tabs, SSH progress and enrollment code see "Additional components (v2)" below.

## Mapping to Go + HTMX

- Views = `html/template` partials; nav/tabs/filters use `hx-get` + `hx-target` swaps and `hx-push-url`.
- Live values (CPU, temp, curve SVG, services) via HTMX SSE extension, server renders fragments every 1–2s.
- Package actions: `hx-post`, stream `apt` output via SSE, then show banner.
- Add host: `hx-post` form, validate server-side, return form with error row or new tab list; hosts stored in SQLite (`hosts` table); SSH credentials are used once for enrollment and never stored.
- Static assets (CSS, fonts, htmx, xterm.js, mark SVG) via `embed`.

## Responsive behavior

Goal: the same design on every screen. Nothing is redesigned for mobile; components keep their look and only **reflow**. Mobile references: `mockups/mobile/*.dc.html` (390 × 844).

**Principles**
- Fluid layout, no fixed 1440 px frame. Use flex/grid with `minmax(0,1fr)`, `gap`, and `clamp()` only where a size must scale (e.g. the login wordmark: `clamp(56px, 8vw, 118px)`).
- Full height with `100dvh`, respect `env(safe-area-inset-*)` on phones.
- Wide screens (≥ 1920 px): content grows, cards stay readable; cap the main content at `max-width: 1760px` and center it.
- Input by capability, not by width: `@media (pointer: coarse)` raises every hit target to ≥ 44 px (tabs 36 → 44 inside a 48 px row is fine), `@media (hover: none)` never hides actions behind hover.
- Horizontal overflow is allowed only inside explicit scrollers (host tabs, filter chips, shell key bar), never for the page.
- Decorative micro text, crosshairs and tickers stay; micro text shows at most one line on phones.

**Breakpoints**

| Width | Layout |
| --- | --- |
| ≥ 1280 px | As designed: sidebar 208 px, three overview cards side by side, packages 3-column grid + card column on the right |
| 1024–1279 px | Sidebar stays; overview cards 2 + 1 (third card full width below); packages grid 2 columns, maintenance cards below the grid |
| 768–1023 px | Sidebar becomes a 72 px icon rail (same colors: active light grey, badge lime); host tabs stay in the top bar and scroll horizontally |
| < 768 px | Phone layout below |

**Phone layout (< 768 px)**
- Top bar: pill group (lime node + packages + temperature), latency; one micro line. Add-host moves to the end of the host tab row (dashed "+ Host").
- Host tabs: own 48 px row under the top bar, horizontal scroll.
- Sidebar → bottom navigation (5 items, 66 px + safe area): Overview, Packages, Shell, Alerts, More (History, Containers, Settings). Active = light grey block like the desktop nav, counts as lime badge.
- Bottom status bar: slim 28 px log line directly above the bottom navigation.
- Overview: Reboot / Shut down as two full-width buttons, then the three cards stacked.
- Packages: search full width, filter chips scroll horizontally, ticker, "System upgrade" card first, package tiles one column, then Sync and Clean-up cards.
- Shell: full-width terminal, connection info as one line, extra key bar above the keyboard (Esc, Tab, Ctrl, Alt, arrows, `|`, `~`, `/`).
- Login / Setup: violet band on top, card below overlapping the band by ~34 px; inputs 44 px; setup step list becomes a compact progress row above the card.
- Dialogs (Add host, Power, Setup steps): full width with 14 px margin, buttons stacked if they do not fit side by side.


## Additional components (v2)

- **Add host dialog:** tabs "Via SSH" / "Enrollment code". SSH: address, port, user with sudo, display name, sign-in by password or hub SSH key (public key shown with Copy). Progress list with 5 steps (square status box: grey waiting, blinking lime running, black with lime check done). Code: big lime code block, copyable one-line command, "Waiting for the agent" live indicator, "New code".
- **Job dialog:** grey card, header grey while running / lime when done, host tag + state tag, lime progress bar, green terminal output (300 px, auto-scroll), "Run in background" → lime job chip in the bottom bar. Lines starting with "Waiting"/"W:" in lime, errors in pink.
- **Confirm dialog:** pink header for destructive actions (remove package, shut down), Cancel light grey + confirm black.
- **Reboot required:** pink chip button in the overview header and a pink-edged notice under the packages ticker.
- **Connection lost:** pink ticker band on top of the main area; bottom bar live square turns pink and reads RECONNECTING.
- **Settings:** Updates, Backup (passphrase field + download), Certificates, Diagnostics (logs open in the job dialog), plus the existing cards.
- **Login:** second card state "Step 2 of 2" with a large 6-digit code field.
- **Setup:** 7 steps; Unlock shows the installer output and "Restore from a backup instead"; Trust shows QR + per-device download chips + fingerprint.
- **Mobile More:** bottom sheet over the dimmed page with History, Containers, Settings rows, operator/hub info and Sign out.

## Deviations from the mockups

The implementation follows the mockups except for these points:

- **Shell copy:** the shell does not use SSH, it runs over the Grid Agent. Replace "PROTOCOL: SSH · PORT 22" with "PROTOCOL: GRID · mTLS", the ticker "NEXARA SHELL 1.0 (SSH.SESSION)" with "NEXARA SHELL 1.0 (GRID.SESSION)", and the top micro text "GRID (SSH KEY) INTERFACE INITIALIZED" with "GRID (mTLS) INTERFACE INITIALIZED".
- **Reset hints:** always `sudo nexus user reset` (login and TOTP step).
- **CPU card header:** "CPU · 4 CORES" with spaces (desktop mockup renders "CPU ·4CORES").
- **Enrollment command:** the one-liner in the Add-host dialog carries `--insecure --pinnedpubkey sha256//…` (decision #40), so it is longer than in the mockup; the code block wraps.
- **Mockup-only controls:** "Simulate agent connect" in the enrollment-code dialog does not exist; the dialog switches to the progress state when the agent connects.
- **Sample data:** `nexus dev --demo` uses one consistent data set (desktop values win where desktop and mobile differ).
- **Roadmap gating:** views and controls of later versions are not rendered until that version (e.g. no Wake-on-LAN or Reboot/Shut down before v0.3, no Alerts/Containers nav before their version). The offline card in v0.1 shows the pink header and text without the WoL row.
- **Sign out (v0.1):** the mockups show no sign-out control. The desktop sidebar has a small operator block under the nav ("OPERATOR <id>" + "SIGN OUT"), the icon rail a sign-out icon, and the phone bottom nav a "More" item whose sheet holds the operator and Sign out; from v0.2 it also lists History and Settings (Containers stays hidden until its version).
- **Setup "Ready" step:** the commit happens on "Finish setup"; afterwards the browser goes to the sign-in page, which shows a "Hub online" notice. The "Link first host" button is dropped (no session yet). With non-fatal warnings (e.g. self-link failed) a "Setup complete" page lists them.
- **Sign-in "Access granted":** shown only after the TOTP step, as a 2-second interstitial (meta refresh, no script); password-only sign-in goes straight to the overview.
- **Settings (v0.2):** Security shows facts without toggles or session chips (2FA "Required" #51, timeout "12 h" #52); Hosts & capabilities shows only Shell and Packages chips (#31), no Remove for the hub's own host; "Change passphrase" is an extra button in Operators; the backup passphrase is asked in a dialog instead of inline; agent certificates get per-host rows with Renew; channel chips only while the GitHub check is on; the backup time is a 24 h text field; Diagnostics has the hub log only (#56); the audit card tag reads "Last 3 entries" and "View all" opens the full audit view; the History retention card is not built.
- **History (v0.2):** axis labels are real times in the hub's time zone (start, middle, "NOW") instead of "-24 H / -12 H"; the network card is titled "Network" (history has no interface name) and has a dim second stats line for TX; one chart per mount follows the four charts; the 30-day range uses 2 h steps; the charts refresh by polling the fragment (60 s for 24 h, 5 min otherwise).
- **Audit log view (v0.2):** no full-page mockup; built from the audit card, tabs, selects and search (range and result as radio tabs, host/operator/action selects, search over details), rows expand to the raw fields, CSV export.
- **Two-factor enrollment (v0.2):** an operator without TOTP lands on a sign-in-style page (band + card with QR, key, code) and reaches nothing else until done (#51).
- **Restore in setup (v0.2):** the backup extension is `.nxbk` (mockup: `.nxb`); "Restore from a backup instead" checks the setup code first, then shows upload, preview and confirm; the hub restarts afterwards.
- **Derived copy:** texts the mockups hard-code come from live data: the CPU description from the reported model ("Raspberry Pi 5 Model B Rev 1.0, 4 cores"), the curve label from the actual sample window, "Sources read" from the last `apt update` job ("not synced" before), the clean-up size from the orphaned packages, the terminal header from the host label and kernel.
