#!/bin/sh
# Builds the hub package (decision #44).
#
#   scripts/package-deb.sh <version> <arch> <nexus-bin> <agent-bin> <outdir>
#
# Writes <outdir>/nexus_<version>_<arch>.deb. Maintainer scripts come from
# deploy/debian/{postinst,prerm,postrm} and are skipped when absent.
set -eu

if [ $# -ne 5 ]; then
	echo "usage: package-deb.sh <version> <arch> <nexus-bin> <agent-bin> <outdir>" >&2
	exit 2
fi
version=$1
arch=$2
nexus_bin=$3
agent_bin=$4
outdir=$5

case "$arch" in
arm64 | amd64) ;;
*) echo "package-deb.sh: unsupported arch: $arch" >&2; exit 2 ;;
esac
case "$version" in
[0-9]*) ;;
*) echo "package-deb.sh: version must start with a digit: $version" >&2; exit 2 ;;
esac
for f in "$nexus_bin" "$agent_bin"; do
	[ -f "$f" ] || { echo "package-deb.sh: missing file: $f" >&2; exit 1; }
done

root=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$outdir"
outdir=$(cd "$outdir" && pwd)
nexus_bin=$(cd "$(dirname "$nexus_bin")" && pwd)/$(basename "$nexus_bin")
agent_bin=$(cd "$(dirname "$agent_bin")" && pwd)/$(basename "$agent_bin")

for f in deploy/systemd/nexus.service deploy/systemd/grid-agent.service configs/nexus.example.yaml configs/agent.example.yaml; do
	[ -f "$root/$f" ] || { echo "package-deb.sh: missing $f" >&2; exit 1; }
done

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT INT TERM
umask 022

pkg="$stage/pkg"
mkdir -p "$pkg/DEBIAN" "$pkg/usr/bin" "$pkg/lib/systemd/system" "$pkg/usr/share/nexara"
chmod 0755 "$pkg" "$pkg/DEBIAN"

install -m 0755 "$nexus_bin" "$pkg/usr/bin/nexus"
install -m 0755 "$agent_bin" "$pkg/usr/bin/grid-agent"
install -m 0644 "$root/deploy/systemd/nexus.service" "$pkg/lib/systemd/system/nexus.service"
install -m 0644 "$root/deploy/systemd/grid-agent.service" "$pkg/lib/systemd/system/grid-agent.service"
install -m 0644 "$root/configs/nexus.example.yaml" "$pkg/usr/share/nexara/nexus.example.yaml"
install -m 0644 "$root/configs/agent.example.yaml" "$pkg/usr/share/nexara/agent.example.yaml"

for s in postinst prerm postrm; do
	if [ -f "$root/deploy/debian/$s" ]; then
		install -m 0755 "$root/deploy/debian/$s" "$pkg/DEBIAN/$s"
	fi
done

size=$(du -sk "$pkg/usr" "$pkg/lib" | awk '{s += $1} END {print s}')
cat >"$pkg/DEBIAN/control" <<CTRL
Package: nexus
Version: $version
Architecture: $arch
Maintainer: phabioo <phabioo@users.noreply.github.com>
Installed-Size: $size
Depends: adduser, openssl, ca-certificates
Section: admin
Priority: optional
Homepage: https://github.com/phabioo/nexara
Description: Nexara Nexus - self-hosted dashboard for the home network
 Hub with web UI, API and storage, plus the Grid Agent that manages the
 hub device itself. Private use only; no cloud.
CTRL

dpkg-deb --root-owner-group --build "$pkg" "$outdir/nexus_${version}_${arch}.deb" >/dev/null
echo "package-deb: $outdir/nexus_${version}_${arch}.deb"
