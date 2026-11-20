#!/bin/sh
# Installs kagebunshin from a GitHub release, or upgrades it in place.
#
#   sh install.sh [--version 0.0.1-alpha.14] [--no-setup]
#   sh install.sh --uninstall [--purge] [--dry-run]
#
# The release is downloaded with curl, or with the GitHub CLI (`gh`) if
# curl fails and `gh` is here. The tarball is checked against its SHA-256,
# the binaries go
# to ~/.local/bin (or $KAGEBUNSHIN_BIN_DIR), the agent skill goes where each
# agent found here looks for skills, and `kagebunshin setup` then creates
# the store, installs the daemon as a user service and unlocks it.
#
# --uninstall runs `kagebunshin uninstall` and also removes binaries that
# `cargo install` put in ~/.cargo/bin.
set -eu

repo=oorestisime/kagebunshin
version=
setup=1
uninstall=
purge=
dry_run=

die() {
	echo "install.sh: $*" >&2
	exit 1
}

while [ $# -gt 0 ]; do
	case $1 in
	--version)
		[ $# -ge 2 ] || die "--version needs a version, e.g. 0.0.1-alpha.14"
		version=${2#v}
		shift 2
		;;
	--version=*)
		version=${1#--version=}
		version=${version#v}
		shift
		;;
	--no-setup) setup= && shift ;;
	--uninstall) uninstall=1 && shift ;;
	--purge) purge=--purge && shift ;;
	--dry-run) dry_run=--dry-run && shift ;;
	-h | --help)
		sed -n '2,15p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//'
		exit 0
		;;
	*) die "unknown option $1 (see --help)" ;;
	esac
done

bin_dir=${KAGEBUNSHIN_BIN_DIR:-$HOME/.local/bin}
config_home=${XDG_CONFIG_HOME:-$HOME/.config}
cargo_bin=${CARGO_HOME:-$HOME/.cargo}/bin

if [ -n "$uninstall" ]; then
	if [ -x "$bin_dir/kagebunshin" ]; then
		kb=$bin_dir/kagebunshin
	elif [ -x "$cargo_bin/kagebunshin" ]; then
		kb=$cargo_bin/kagebunshin
	else
		kb=$(command -v kagebunshin || true)
	fi
	[ -n "$kb" ] || die "kagebunshin is not installed"
	if "$kb" uninstall --help >/dev/null 2>&1; then
		# Lists what it removes, and asks at the terminal before it does.
		"$kb" uninstall $purge $dry_run
	else
		echo "$kb has no uninstall command (an older build): remove its service, skills and data by hand" >&2
	fi
	crates=
	for b in kagebunshin kagebunshin-app; do
		[ -e "$cargo_bin/$b" ] && crates="$crates $b"
	done
	if [ -n "$crates" ]; then
		if [ -n "$dry_run" ]; then
			echo "would run: cargo uninstall$crates"
		else
			# shellcheck disable=SC2086 # one word per crate
			cargo uninstall $crates
		fi
	fi
	exit 0
fi

[ -n "$dry_run$purge" ] && die "--purge and --dry-run go with --uninstall"
has() { command -v "$1" >/dev/null; }
has curl || has gh || die "needs curl"

case "$(uname -s)/$(uname -m)" in
Linux/x86_64) target=x86_64-unknown-linux-gnu ;;
Linux/aarch64 | Linux/arm64) target=aarch64-unknown-linux-gnu ;;
Darwin/arm64 | Darwin/aarch64) target=aarch64-apple-darwin ;;
*) die "no release build for $(uname -s) $(uname -m); build from source with cargo install" ;;
esac

if [ -z "$version" ]; then
	# The newest release, pre-releases included; GitHub's "latest" and
	# `gh release download` alone take the newest full release only.
	tag=
	if has curl; then
		tag=$(curl -fsSL "https://api.github.com/repos/$repo/releases?per_page=1" 2>/dev/null |
			grep -o '"tag_name": *"[^"]*"' | head -n 1 | sed 's/.*"\([^"]*\)"$/\1/') || tag=
	fi
	if [ -z "$tag" ] && has gh; then
		tag=$(gh release list -R "$repo" --exclude-drafts --limit 1 --json tagName --jq '.[0].tagName')
	fi
	[ -n "$tag" ] || die "no release of $repo found"
	version=${tag#v}
fi
tag=v$version

if command -v sha256sum >/dev/null; then
	check="sha256sum -c"
else
	check="shasum -a 256 -c"
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Downloads one tarball and its checksum, checks it and unpacks it. Fails
# if the release has no such tarball.
fetch() {
	name=$1-$version-$target.tar.gz
	url=https://github.com/$repo/releases/download/$tag/$name
	if ! { has curl && curl -fsSL -o "$work/$name" "$url" &&
		curl -fsSL -o "$work/$name.sha256" "$url.sha256"; } 2>/dev/null; then
		rm -f "$work/$name" "$work/$name.sha256"
		has gh || return 1
		gh release download "$tag" -R "$repo" -D "$work" -p "$name" -p "$name.sha256" ||
			return 1
	fi
	[ -f "$work/$name" ] && [ -f "$work/$name.sha256" ] || return 1
	(cd "$work" && $check "$name.sha256" >/dev/null) ||
		die "$name does not match its SHA-256; nothing was installed"
	tar -C "$work" -xzf "$work/$name"
}

echo "kagebunshin $version for $target"
fetch kagebunshin || die "release $tag has no kagebunshin-$version-$target.tar.gz"
top=$work/kagebunshin-$version-$target
# Releases that ship the app apart from the CLI.
if [ ! -f "$top/kagebunshin-app" ]; then
	if fetch kagebunshin-app 2>/dev/null; then
		cp "$work/kagebunshin-app-$version-$target/kagebunshin-app" "$top/"
	else
		echo "no kagebunshin-app in this release; installing the CLI only"
	fi
fi

mkdir -p "$bin_dir"
for b in kagebunshin kagebunshin-app; do
	[ -f "$top/$b" ] || continue
	# Beside the old binary, then renamed over it: a running daemon keeps
	# its file, and the copy is never seen half written.
	cp "$top/$b" "$bin_dir/.$b.new"
	chmod 755 "$bin_dir/.$b.new"
	if [ "$(uname -s)" = Darwin ]; then
		xattr -d com.apple.quarantine "$bin_dir/.$b.new" 2>/dev/null || true
	fi
	mv -f "$bin_dir/.$b.new" "$bin_dir/$b"
	echo "installed $bin_dir/$b"
done
kb=$bin_dir/kagebunshin
"$kb" --version

# The skill and the hooks, for each agent that is installed here.
skill() {
	mkdir -p "$1"
	"$kb" init --agent --skill >"$1/SKILL.md"
	echo "installed the agent skill in $1/SKILL.md"
}
if command -v opencode >/dev/null || [ -d "$config_home/opencode" ]; then
	skill "$config_home/opencode/skills/kagebunshin"
	"$kb" hook install opencode || echo "skipped the OpenCode hooks" >&2
fi
if command -v claude >/dev/null || [ -d "$HOME/.claude" ]; then
	skill "$HOME/.claude/skills/kagebunshin"
	"$kb" hook install claude || echo "skipped the Claude Code hooks" >&2
fi

case ":$PATH:" in
*":$bin_dir:"*) ;;
*) echo "$bin_dir is not on PATH; add it, e.g. in ~/.profile: export PATH=\"$bin_dir:\$PATH\"" ;;
esac

if [ -n "$setup" ]; then
	# Creates the store or asks for its passphrase, (re)installs the user
	# service on this binary and unlocks it, and on Linux puts the app in
	# the launcher and at login, and in the tray on a first install.
	"$kb" setup
else
	echo "next: run \`$kb setup\`, then \`$kb onboard DIR…\` with the folders of your projects"
fi
