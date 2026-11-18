#!/bin/sh
# Packs release binaries with the license and README, and writes the SHA-256.
#
#   packaging/tarball.sh target/release/kagebunshin kagebunshin 0.1.0 x86_64-unknown-linux-gnu \
#       [target/release/kagebunshin-app ...]
#
# Writes dist/<name>-<version>-<target>.tar.gz and a .sha256 beside it. Any
# binaries after the target go in the same tarball: the release ships the
# CLI and the app together.
set -eu

bin=$1 name=$2 version=$3 target=$4
shift 4
top="$name-$version-$target"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

mkdir -p "$stage/$top" dist
for b in "$bin" "$@"; do
	cp "$b" "$stage/$top/"
done
cp LICENSE README.md "$stage/$top/"
tar -C "$stage" -czf "dist/$top.tar.gz" "$top"
if command -v sha256sum >/dev/null; then sum="sha256sum"; else sum="shasum -a 256"; fi
(cd dist && $sum "$top.tar.gz" > "$top.tar.gz.sha256")
echo "dist/$top.tar.gz"
