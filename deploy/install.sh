#!/bin/sh
# Nexara Nexus installer for the device that becomes the hub (Debian, Raspberry Pi OS;
# arm64 or amd64).
#
#   curl -fsSL https://github.com/phabioo/nexara/releases/latest/download/install.sh | sudo sh
#
# What it does: downloads SHA256SUMS and SHA256SUMS.sig, verifies the ed25519
# signature with the release key embedded below, downloads the matching
# nexus_<version>_<arch>.deb, checks its SHA-256 and installs it with apt. The
# package creates the nexus user, directories and configuration and starts the
# service. The script then prints the URL, the setup code and the CA fingerprint.
#
# Offline: copy nexus_<version>_<arch>.deb to the device and run
#   sudo apt install ./nexus_<version>_<arch>.deb
# and read the setup code with: sudo journalctl -u nexus | grep "setup code"
#
# Environment (all optional):
#   NEXARA_BASE_URL     release download directory (default: GitHub latest release);
#                       for mirrors and tests, the signature check still applies
#   NEXARA_PUBKEY_FILE  TESTING ONLY: verify with this PEM public key instead of the
#                       embedded release key
#
# Commands that could read stdin use </dev/null: when piped from curl, stdin
# is this script.
set -eu

# Everything runs inside main() and is called on the last line, so a download
# truncated by a dropped connection ends in a syntax error instead of running a
# partial script (curl | sh).
main() {

	BASE_URL="${NEXARA_BASE_URL:-https://github.com/phabioo/nexara/releases/latest/download}"
	WAIT_SECONDS=60

	TMP=""
	cleanup() {
		if [ -n "$TMP" ] && [ -d "$TMP" ]; then
			rm -rf "$TMP"
		fi
	}
	trap cleanup EXIT
	trap 'exit 130' INT TERM

	say() { printf '%s\n' "$*"; }
	die() {
		printf 'nexus installer: %s\n' "$*" >&2
		exit 1
	}

	# --- preconditions -------------------------------------------------------------

	[ "$(id -u)" -eq 0 ] || die "run as root, e.g. curl -fsSL <url> | sudo sh"

	if ! command -v apt-get >/dev/null 2>&1 || ! command -v dpkg >/dev/null 2>&1; then
		die "this installer needs Debian or Raspberry Pi OS (apt and dpkg). Other systems are not supported yet."
	fi

	ARCH=$(dpkg --print-architecture)
	case "$ARCH" in
	arm64 | amd64) ;;
	*) die "unsupported architecture '$ARCH'. Nexara Nexus supports arm64 (64-bit Raspberry Pi OS) and amd64." ;;
	esac

	missing=""
	command -v curl >/dev/null 2>&1 || missing="$missing curl"
	command -v openssl >/dev/null 2>&1 || missing="$missing openssl"
	if [ -n "$missing" ]; then
		say "Installing prerequisites:$missing"
		apt-get update -qq </dev/null
		# shellcheck disable=SC2086 # intentional word splitting of the package list
		DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ca-certificates $missing </dev/null
	fi

	# Verifying ed25519 with `openssl pkeyutl -rawin` needs OpenSSL 3.
	ossl_major=$(openssl version | sed -n 's/^[A-Za-z]* \([0-9][0-9]*\)\..*/\1/p')
	[ "${ossl_major:-0}" -ge 3 ] 2>/dev/null ||
		die "OpenSSL 3 or newer is required to verify the release signature (found: $(openssl version)). Use Debian 12 / Raspberry Pi OS bookworm or newer."

	TMP=$(mktemp -d)
	# apt downloads as the _apt user; it must be able to read the .deb.
	chmod 0755 "$TMP"

	# --- download and verify ---------------------------------------------------------

	fetch() { # fetch <name> <dest>
		case "$BASE_URL" in
		https://*) curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$BASE_URL/$1" </dev/null ;;
		*) curl -fsSL -o "$2" "$BASE_URL/$1" </dev/null ;;
		esac || die "download failed: $BASE_URL/$1"
	}

	if [ -n "${NEXARA_PUBKEY_FILE:-}" ]; then
		[ -r "$NEXARA_PUBKEY_FILE" ] || die "NEXARA_PUBKEY_FILE is not readable"
		say "WARNING: verifying with $NEXARA_PUBKEY_FILE instead of the embedded release key (testing only)." >&2
		cp "$NEXARA_PUBKEY_FILE" "$TMP/release.pub"
	else
		# Must stay byte-identical to deploy/keys/nexara-release.pub (checked by a test).
		cat >"$TMP/release.pub" <<'NEXARA_RELEASE_PUBKEY'
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAksSidnrzOdoTgYX4qgpK8cZ5RqKyJea4q24aTYzzFxw=
-----END PUBLIC KEY-----
NEXARA_RELEASE_PUBKEY
	fi

	say "Downloading release metadata ..."
	fetch SHA256SUMS "$TMP/SHA256SUMS"
	fetch SHA256SUMS.sig "$TMP/SHA256SUMS.sig"

	[ "$(wc -c <"$TMP/SHA256SUMS.sig")" -eq 64 ] || die "SHA256SUMS.sig is not a 64-byte ed25519 signature"
	if ! openssl pkeyutl -verify -pubin -inkey "$TMP/release.pub" -rawin \
		-in "$TMP/SHA256SUMS" -sigfile "$TMP/SHA256SUMS.sig" >/dev/null 2>&1 </dev/null; then
		die "signature check of SHA256SUMS FAILED. Nothing was installed."
	fi
	say "Signature OK."

	# The file name comes from the signed list, but is validated anyway.
	DEB_LINES=$(grep -E "^[0-9a-f]{64}  nexus_[0-9][0-9A-Za-z.+~-]*_${ARCH}\.deb\$" "$TMP/SHA256SUMS" || true)
	[ -n "$DEB_LINES" ] || die "no nexus package for $ARCH in SHA256SUMS"
	[ "$(printf '%s\n' "$DEB_LINES" | wc -l)" -eq 1 ] || die "SHA256SUMS lists more than one nexus package for $ARCH"
	DEB=${DEB_LINES#*  }

	say "Downloading $DEB ..."
	fetch "$DEB" "$TMP/$DEB"
	printf '%s\n' "$DEB_LINES" >"$TMP/deb.sum"
	(cd "$TMP" && sha256sum -c deb.sum >/dev/null 2>&1 </dev/null) || die "checksum of $DEB does not match. Nothing was installed."
	say "Checksum OK."

	# --- install -----------------------------------------------------------------------

	START=$(date '+%Y-%m-%d %H:%M:%S')
	say "Installing $DEB ..."
	# SUDO_USER becomes the user of Nexara Shell; the package validates it.
	if ! NEXARA_SHELL_USER="${SUDO_USER:-}" DEBIAN_FRONTEND=noninteractive apt-get install -y "$TMP/$DEB" </dev/null; then
		die "apt could not install the package. If dependencies are missing, run 'sudo apt-get update' and try again."
	fi

	# Keep the verified package as rollback material for the first update from
	# Settings (decision #50): the root update helper reinstalls it if a new
	# version does not come up, and checks its signature again before use.
	KEEP=/var/lib/nexus-update
	if install -d -m 0755 "$KEEP" && rm -rf "$KEEP/installed.new" &&
		install -d -m 0755 "$KEEP/installed.new" &&
		install -m 0644 "$TMP/$DEB" "$TMP/SHA256SUMS" "$TMP/SHA256SUMS.sig" "$KEEP/installed.new/" &&
		rm -rf "$KEEP/installed" && mv "$KEEP/installed.new" "$KEEP/installed"; then
		:
	else
		say "Note: could not keep a copy of the package for rollbacks; the first update from Settings will need 'sudo nexus update-apply --no-rollback'."
	fi

	# --- report ------------------------------------------------------------------------

	have_journal() { command -v journalctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; }

	if ! have_journal; then
		say ""
		say "Installed. systemd is not running here, so the service was not started."
		say "Start it with: sudo systemctl enable --now nexus"
		exit 0
	fi

	journal() {
		journalctl -u nexus --since "$START" --no-pager -o cat 2>/dev/null </dev/null || true
	}

	say "Waiting for the hub to start (up to ${WAIT_SECONDS}s) ..."
	LOG=""
	i=0
	while [ "$i" -lt "$WAIT_SECONDS" ]; do
		LOG=$(journal)
		case "$LOG" in *'msg="nexus listening"'*) break ;; esac
		if [ "$(systemctl is-active nexus 2>/dev/null </dev/null || true)" = failed ]; then
			break
		fi
		i=$((i + 1))
		sleep 1
	done

	LISTEN=$(printf '%s\n' "$LOG" | grep 'msg="nexus listening"' | tail -n 1 || true)
	if [ -z "$LISTEN" ]; then
		say "" >&2
		say "The hub did not report that it is listening. Check: sudo systemctl status nexus ; sudo journalctl -u nexus" >&2
		exit 1
	fi

	PORT=$(printf '%s\n' "$LISTEN" | sed -n 's/.* addr=[^ ]*:\([0-9][0-9]*\)\( .*\)\{0,1\}$/\1/p')
	PORT=${PORT:-8443}
	SETUP_MODE=$(printf '%s\n' "$LISTEN" | sed -n 's/.* setup_mode=\([a-z]*\).*/\1/p')
	CODE=$(printf '%s\n' "$LOG" | sed -n 's/.*msg="setup code" code=\([A-Za-z0-9-]*\).*/\1/p' | tail -n 1)
	FP=$(printf '%s\n' "$LOG" | sed -n 's/.*msg="CA fingerprint" sha256=\([0-9A-Fa-f:]*\).*/\1/p' | tail -n 1)
	HOST=$(hostname -s 2>/dev/null || hostname)

	say ""
	say "Nexara Nexus is running."
	say ""
	say "  Open:  https://$HOST.local:$PORT"
	for ip in $(hostname -I 2>/dev/null || true); do
		case "$ip" in
		*:*) say "         https://[$ip]:$PORT" ;;
		*) say "         https://$ip:$PORT" ;;
		esac
	done
	if [ "$SETUP_MODE" = false ] || [ -z "$CODE" ]; then
		say ""
		say "  This hub is already set up, so there is no setup code."
		say "  Lost access? Run: sudo nexus user reset"
	else
		say ""
		say "  Setup code:  $CODE   (valid 60 minutes, renewed automatically)"
		say "  New code:    sudo nexus setup code"
	fi
	if [ -n "$FP" ]; then
		say ""
		say "  CA fingerprint (SHA-256):"
		say "  $FP"
		say "  The browser warns once about the certificate; compare this fingerprint with the one it shows."
	fi
	say ""
}

main "$@"
