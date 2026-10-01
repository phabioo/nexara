#!/bin/sh
# Builds the Grid Agent and the hub for linux/arm64 and linux/amd64.
#
#   scripts/build.sh [--version X.Y.Z] [--out dist]
#
# Order matters: the agents are built first and placed in
# internal/hub/agentbin/bin/ so that every hub binary embeds both of them
# (decision #20). The placed copies are removed again on exit.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

version=""
out="dist"
while [ $# -gt 0 ]; do
	case "$1" in
	--version)
		[ $# -ge 2 ] || { echo "build.sh: --version needs a value" >&2; exit 2; }
		version=$2
		shift 2
		;;
	--out)
		[ $# -ge 2 ] || { echo "build.sh: --out needs a value" >&2; exit 2; }
		out=$2
		shift 2
		;;
	-h | --help)
		echo "usage: scripts/build.sh [--version X.Y.Z] [--out dist]"
		exit 0
		;;
	*)
		echo "build.sh: unknown argument: $1" >&2
		exit 2
		;;
	esac
done

if [ -z "$version" ]; then
	version=$(git describe --tags 2>/dev/null || true)
	version=${version#v}
	[ -n "$version" ] || version="0.0.0-dev"
fi
commit=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)

pkg=github.com/phabioo/nexara/internal/buildinfo
ldflags="-s -w -X $pkg.Version=$version -X $pkg.Commit=$commit"
archs="arm64 amd64"
embed_dir="internal/hub/agentbin/bin"

cleanup() {
	rm -f "$embed_dir"/grid-agent_*
}
trap cleanup EXIT INT TERM

mkdir -p "$out"
cleanup

echo "build: version=$version commit=$commit out=$out"

export CGO_ENABLED=0 GOOS=linux

for arch in $archs; do
	echo "build: grid-agent linux/$arch"
	GOARCH=$arch go build -trimpath -ldflags "$ldflags" -o "$out/grid-agent_linux_$arch" ./cmd/grid-agent
	cp "$out/grid-agent_linux_$arch" "$embed_dir/grid-agent_linux_$arch"
done

for arch in $archs; do
	echo "build: nexus linux/$arch"
	GOARCH=$arch go build -trimpath -ldflags "$ldflags" -o "$out/nexus_linux_$arch" ./cmd/nexus
done

echo "build: done"
