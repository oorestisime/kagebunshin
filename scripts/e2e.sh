#!/bin/sh
# Runs the end-to-end suite against the AWS Emulator, tests marked `ignore`
# included. Usage: scripts/e2e.sh [arguments for the test binaries]
#
# The first run downloads the emulator (about 190 MB, 1 GB unpacked) into a
# cache, after checking AWS's signature on it. Nothing is installed. Linux
# only: AWS publishes the emulator as Debian and RPM packages.
set -eu

# The emulator's release. Change it here to test against a newer one.
VERSION=1.0.385-1
# AWS's package signing key. The key is downloaded; this is what makes it
# the right one.
FINGERPRINT=98BCF336A3BE53B734E967C52E5BF49BD940F624
BASE=https://downloads.aws.com
CACHE=${KAGEBUNSHIN_E2E_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/kagebunshin-e2e}

case $(uname -s)/$(uname -m) in
  Linux/x86_64) arch=amd64 ;;
  Linux/aarch64) arch=arm64 ;;
  *) echo "e2e.sh: the AWS Emulator is published for Linux only; plain \`cargo test -p kagebunshin-e2e\` runs the suite with the in-process fake" >&2; exit 1 ;;
esac

dir=$CACHE/aws-emulator-$VERSION-$arch
emulator=$dir/opt/aws-emulator/bin/aws-emulator
if [ ! -x "$emulator" ]; then
  for tool in curl gpg ar tar; do
    command -v "$tool" >/dev/null || { echo "e2e.sh: $tool is needed to fetch the AWS Emulator" >&2; exit 1; }
  done
  tmp=$(mktemp -d "${TMPDIR:-/tmp}/kb-e2e.XXXXXX")
  trap 'rm -rf "$tmp"' EXIT
  deb=aws-emulator_${VERSION}_$arch.deb
  echo "e2e.sh: fetching AWS Emulator $VERSION" >&2
  curl -fsS -o "$tmp/$deb" "$BASE/aws-emulator/packages/aws-emulator/LTS/$deb"
  curl -fsS -o "$tmp/$deb.sig" "$BASE/aws-emulator/packages/aws-emulator/LTS/$deb.sig"
  curl -fsS -o "$tmp/key.asc" "$BASE/keys/gpg/current.asc"
  mkdir -m 700 "$tmp/gnupg"
  gpg --homedir "$tmp/gnupg" --quiet --batch --import "$tmp/key.asc"
  # Only the pinned key may have signed it, whatever else the file held.
  gpg --homedir "$tmp/gnupg" --batch --status-fd 1 --verify "$tmp/$deb.sig" "$tmp/$deb" 2>/dev/null \
    | grep -q "^\[GNUPG:\] VALIDSIG $FINGERPRINT " \
    || { echo "e2e.sh: $deb is not signed by $FINGERPRINT" >&2; exit 1; }
  mkdir "$tmp/deb" "$tmp/root"
  (cd "$tmp/deb" && ar x "../$deb")
  tar -xf "$tmp"/deb/data.tar.* -C "$tmp/root"
  mkdir -p "$CACHE"
  rm -rf "$dir"
  mv "$tmp/root" "$dir"
  rm -rf "$tmp"
  trap - EXIT
fi

cd "$(dirname "$0")/.."
KAGEBUNSHIN_E2E_AWS_EMULATOR=$emulator exec cargo test -p kagebunshin-e2e -- --include-ignored "$@"
