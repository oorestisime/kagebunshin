# Install, upgrade, uninstall

From a release, on Linux x86_64 and aarch64 with glibc 2.35 or later
(Ubuntu 22.04, Debian 12), and on macOS arm64. The release workflow builds
each on a machine of its own kind and smoke-tests it there; only the Linux
x86_64 build is in daily use, and the macOS one is unsigned.

```sh
curl -fsSLO https://raw.githubusercontent.com/oorestisime/kagebunshin/main/packaging/install.sh
sh install.sh                          # the newest release
sh install.sh --version 0.0.1-alpha.18  # or a given one
```

It downloads the release tarball (the CLI and the app) with curl, or with
the GitHub CLI (`gh`) if curl fails and `gh` is installed, checks its
SHA-256, installs both to `~/.local/bin`, installs the agent skill and hooks
for OpenCode and Claude Code when it finds them, then runs `kagebunshin setup`,
which asks for the store passphrase and, on Linux, adds the app to the
launcher, starts it in the tray and has it start there at login. Run it
again to upgrade in place; `--no-setup` stops after installing.

`kagebunshin uninstall` removes the service, the skills, the hooks, the
app's launcher and login entries and the binaries,
listing every path and asking first; `--dry-run` only lists, `--purge` also
removes the config, the store, the audit log and the Proton session, each
only if it holds nothing but kagebunshin's own files. Nothing in `~/.aws` or your
repositories is touched. `sh install.sh --uninstall [--purge] [--dry-run]`
runs it and also removes binaries from `cargo install`.

From source, with Rust 1.98 or later:

```sh
cargo install --locked --git https://github.com/oorestisime/kagebunshin kagebunshin
# The window, optional; on Linux it needs libxkbcommon and Wayland or X11.
# Installed before `kagebunshin setup`, setup puts it in the launcher and
# at login; installed after, `kagebunshin app install` does.
cargo install --locked --git https://github.com/oorestisime/kagebunshin kagebunshin-app
```
