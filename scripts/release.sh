#!/bin/sh
# Assembles the release assets from a dist/ directory made by scripts/build.sh.
#
#   scripts/release.sh <version> <dist>
#
# Writes the .deb files, install.sh (if deploy/install.sh exists) and
# SHA256SUMS into <dist>. When NEXARA_RELEASE_SIGNING_KEY (PEM content) or
# NEXARA_RELEASE_SIGNING_KEY_FILE is set, SHA256SUMS.sig is written and
# verified against deploy/keys/nexara-release.pub (override for tests:
# NEXARA_RELEASE_PUBKEY_FILE).
set -eu

if [ $# -ne 2 ]; then
	echo "usage: release.sh <version> <dist>" >&2
	exit 2
fi
version=$1
dist=$2

root=$(cd "$(dirname "$0")/.." && pwd)
[ -d "$dist" ] || { echo "release.sh: no such directory: $dist" >&2; exit 1; }
dist=$(cd "$dist" && pwd)

sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$@"
	else
		shasum -a 256 "$@"
	fi
}

for arch in arm64 amd64; do
	for f in "nexus_linux_$arch" "grid-agent_linux_$arch"; do
		[ -f "$dist/$f" ] || { echo "release.sh: missing $dist/$f" >&2; exit 1; }
	done
	"$root/scripts/package-deb.sh" "$version" "$arch" "$dist/nexus_linux_$arch" "$dist/grid-agent_linux_$arch" "$dist"
done

if [ -f "$root/deploy/install.sh" ]; then
	cp "$root/deploy/install.sh" "$dist/install.sh"
else
	echo "release.sh: deploy/install.sh not found, skipping install.sh" >&2
fi

rm -f "$dist/SHA256SUMS" "$dist/SHA256SUMS.sig"
assets=$(cd "$dist" && ls -1 | LC_ALL=C sort)
(cd "$dist" && sha256_of $assets >SHA256SUMS)
echo "release: wrote $dist/SHA256SUMS"

keyfile=""
tmp=""
cleanup() {
	[ -z "$tmp" ] || rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

if [ -n "${NEXARA_RELEASE_SIGNING_KEY_FILE:-}" ]; then
	keyfile=$NEXARA_RELEASE_SIGNING_KEY_FILE
elif [ -n "${NEXARA_RELEASE_SIGNING_KEY:-}" ]; then
	umask 077
	tmp=$(mktemp -d)
	keyfile="$tmp/key.pem"
	# printf with %s keeps the content out of argv beyond this builtin.
	printf '%s\n' "$NEXARA_RELEASE_SIGNING_KEY" >"$keyfile"
fi

if [ -z "$keyfile" ]; then
	echo "release: no signing key configured, SHA256SUMS.sig NOT written" >&2
	exit 0
fi

pub=${NEXARA_RELEASE_PUBKEY_FILE:-$root/deploy/keys/nexara-release.pub}
openssl pkeyutl -sign -rawin -inkey "$keyfile" -in "$dist/SHA256SUMS" -out "$dist/SHA256SUMS.sig"
if ! openssl pkeyutl -verify -pubin -inkey "$pub" -rawin -in "$dist/SHA256SUMS" -sigfile "$dist/SHA256SUMS.sig" >/dev/null; then
	rm -f "$dist/SHA256SUMS.sig"
	echo "release: signature does not verify against $pub; signature removed" >&2
	exit 1
fi
chmod 0644 "$dist/SHA256SUMS.sig"
echo "release: wrote and verified $dist/SHA256SUMS.sig"
