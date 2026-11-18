//! `packaging/install.sh` against a fake `gh` and `curl` that serve release
//! assets from a directory, in a throwaway HOME. No network, no service.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test code")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const TARGET: &str = if cfg!(target_os = "macos") {
    "aarch64-apple-darwin"
} else if cfg!(target_arch = "aarch64") {
    "aarch64-unknown-linux-gnu"
} else {
    "x86_64-unknown-linux-gnu"
};

/// Answers `release list` with `$FAKE_GH_LATEST` and `release download`
/// with the files of `$FAKE_GH_RELEASES/<tag>` matching each `-p`.
const FAKE_GH: &str = r#"#!/bin/sh
case $1/$2 in
release/list) echo "v$FAKE_GH_LATEST" ;;
release/download)
	shift 2
	tag=$1 dir=. pats= found=
	shift
	while [ $# -gt 0 ]; do
		case $1 in
		-D) dir=$2 && shift 2 ;;
		-p) pats="$pats $2" && shift 2 ;;
		*) shift ;;
		esac
	done
	for p in $pats; do
		if [ -f "$FAKE_GH_RELEASES/$tag/$p" ]; then
			cp "$FAKE_GH_RELEASES/$tag/$p" "$dir/" && found=1
		fi
	done
	[ -n "$found" ] || { echo "no assets match" >&2; exit 1; }
	;;
*) echo "fake gh: $*" >&2 && exit 1 ;;
esac
"#;

/// Fails as GitHub does for what it will not serve (HTTP 404), or, with
/// `$FAKE_PUBLIC` set, serves the API's release list and the files of
/// `$FAKE_GH_RELEASES`.
const FAKE_CURL: &str = r#"#!/bin/sh
[ -n "$FAKE_PUBLIC" ] || { echo "curl: (22) 404" >&2; exit 22; }
out= url=
while [ $# -gt 0 ]; do
	case $1 in
	-o) out=$2 && shift 2 ;;
	-*) shift ;;
	*) url=$1 && shift ;;
	esac
done
case $url in
https://api.github.com/repos/*/releases\?per_page=1)
	printf '[\n  {\n    "tag_name": "v%s",\n    "draft": false\n  }\n]\n' "$FAKE_GH_LATEST" ;;
https://github.com/*/releases/download/*)
	f=$FAKE_GH_RELEASES/${url#*/releases/download/}
	[ -f "$f" ] || { echo "curl: (22) 404" >&2; exit 22; }
	cp "$f" "$out" ;;
*) echo "fake curl: $url" >&2 && exit 1 ;;
esac
"#;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn executable(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

struct World {
    tmp: tempfile::TempDir,
}

impl World {
    fn new() -> Self {
        let w = World {
            tmp: tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap(),
        };
        for d in ["home", "fakebin", "releases", "stage", "run"] {
            fs::create_dir_all(w.path(d)).unwrap();
        }
        executable(&w.path("fakebin/gh"), FAKE_GH);
        executable(&w.path("fakebin/curl"), FAKE_CURL);
        for f in ["LICENSE", "README.md"] {
            fs::copy(root().join(f), w.path("stage").join(f)).unwrap();
        }
        w
    }

    fn path(&self, p: &str) -> PathBuf {
        self.tmp.path().join(p)
    }

    /// Packs `name`'s tarball for release `version` with `bins`, as the
    /// release does.
    fn pack(&self, version: &str, name: &str, bins: &[&Path]) {
        let stage = self.path("stage");
        let out = Command::new("sh")
            .arg(root().join("packaging/tarball.sh"))
            .arg(bins[0])
            .args([name, version, TARGET])
            .args(&bins[1..])
            .current_dir(&stage)
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        let release = self.path(&format!("releases/v{version}"));
        fs::create_dir_all(&release).unwrap();
        let file = format!("{name}-{version}-{TARGET}.tar.gz");
        for f in [file.clone(), format!("{file}.sha256")] {
            fs::rename(stage.join("dist").join(&f), release.join(&f)).unwrap();
        }
    }

    /// The CLI, as a script that runs the test build: the debug binary is
    /// too big to copy around.
    fn cli(&self) -> PathBuf {
        let p = self.path("stage/kagebunshin");
        let kb = env!("CARGO_BIN_EXE_kagebunshin");
        executable(&p, &format!("#!/bin/sh\nexec '{kb}' \"$@\"\n"));
        p
    }

    /// A stand-in for the app, telling which release it came from.
    fn app(&self, version: &str) -> PathBuf {
        let p = self.path(&format!("stage/{version}/kagebunshin-app"));
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        executable(&p, &format!("#!/bin/sh\necho app {version}\n"));
        p
    }

    fn install(&self, latest: &str, args: &[&str]) -> Output {
        self.installer(latest, args).output().unwrap()
    }

    /// `install.sh`, with curl failing, so that `gh` downloads, unless
    /// `FAKE_PUBLIC` is set on it.
    fn installer(&self, latest: &str, args: &[&str]) -> Command {
        let mut cmd = Command::new("sh");
        cmd.arg(root().join("packaging/install.sh"))
            .args(args)
            .env_clear()
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.path("fakebin").display()),
            )
            .env("HOME", self.path("home"))
            .env("XDG_CONFIG_HOME", self.path("home/.config"))
            .env("XDG_STATE_HOME", self.path("home/.local/state"))
            .env("XDG_RUNTIME_DIR", self.path("run"))
            .env("TMPDIR", self.path("run"))
            .env("FAKE_GH_RELEASES", self.path("releases"))
            .env("FAKE_GH_LATEST", latest);
        cmd
    }

    fn run(&self, bin: &str, args: &[&str]) -> String {
        let out = Command::new(self.path("home/.local/bin").join(bin))
            .args(args)
            .output()
            .unwrap();
        String::from_utf8(out.stdout).unwrap()
    }
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// The newest release is installed with the skill for the agent found,
/// and a newer one, shipping the app apart, is installed over it.
#[test]
fn installs_the_newest_release_then_upgrades_in_place() {
    let w = World::new();
    let kb = &w.cli();
    w.pack("1.0.0", "kagebunshin", &[kb, &w.app("1.0.0")]);
    fs::create_dir_all(w.path("home/.config/opencode")).unwrap();

    let out = w.install("1.0.0", &["--no-setup"]);
    let all = text(&out);
    assert!(out.status.success(), "{all}");
    assert!(
        all.contains(&format!("kagebunshin 1.0.0 for {TARGET}")),
        "{all}"
    );
    assert!(all.contains("is not on PATH"), "{all}");
    assert!(all.contains("next: run `"), "{all}");
    assert_eq!(w.run("kagebunshin-app", &[]), "app 1.0.0\n");
    let skill =
        fs::read_to_string(w.path("home/.config/opencode/skills/kagebunshin/SKILL.md")).unwrap();
    assert!(skill.starts_with("---\nname: kagebunshin\n"), "{skill}");
    let plugin =
        fs::read_to_string(w.path("home/.config/opencode/plugins/kagebunshin.js")).unwrap();
    // `w.cli()` is a script that runs this build, so the plugin names it.
    let exe = env!("CARGO_BIN_EXE_kagebunshin");
    assert!(
        plugin.contains(&format!("const KAGEBUNSHIN = \"{exe}\"")),
        "{plugin}"
    );
    assert!(
        !w.path("home/.claude").exists(),
        "no Claude Code here, so no skill or hooks for it"
    );

    // The layout the release workflow builds today: the app in its own tarball.
    w.pack("1.1.0", "kagebunshin", &[kb]);
    w.pack("1.1.0", "kagebunshin-app", &[&w.app("1.1.0")]);
    let out = w.install("9.9.9", &["--version", "v1.1.0", "--no-setup"]);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(w.run("kagebunshin-app", &[]), "app 1.1.0\n");
    assert!(
        w.run("kagebunshin", &["--version"])
            .starts_with("kagebunshin ")
    );
}

/// Once the repository is public, curl is enough: `gh` is never run.
#[test]
fn a_public_release_installs_without_gh() {
    let w = World::new();
    w.pack("1.0.0", "kagebunshin", &[&w.cli(), &w.app("1.0.0")]);
    executable(
        &w.path("fakebin/gh"),
        "#!/bin/sh\necho \"gh was run: $*\" >&2\nexit 1\n",
    );

    let out = w
        .installer("1.0.0", &["--no-setup"])
        .env("FAKE_PUBLIC", "1")
        .output()
        .unwrap();
    let all = text(&out);
    assert!(out.status.success(), "{all}");
    assert!(!all.contains("gh was run"), "{all}");
    assert!(
        all.contains(&format!("kagebunshin 1.0.0 for {TARGET}")),
        "{all}"
    );
    assert_eq!(w.run("kagebunshin-app", &[]), "app 1.0.0\n");
}

/// When curl fails and there is no `gh`, nothing else can download it.
#[test]
fn a_release_curl_cannot_get_is_not_installed_without_gh() {
    let w = World::new();
    w.pack("1.0.0", "kagebunshin", &[&w.cli(), &w.app("1.0.0")]);
    fs::remove_file(w.path("fakebin/gh")).unwrap();
    // /usr/bin and /bin without a real gh.
    let sys = w.path("sysbin");
    fs::create_dir_all(&sys).unwrap();
    for dir in ["/usr/bin", "/bin"] {
        for entry in fs::read_dir(dir).unwrap() {
            let name = entry.unwrap().file_name();
            let link = sys.join(&name);
            if name != "gh" && fs::symlink_metadata(&link).is_err() {
                std::os::unix::fs::symlink(Path::new(dir).join(&name), link).unwrap();
            }
        }
    }

    let out = w
        .installer("1.0.0", &["--no-setup", "--version", "1.0.0"])
        .env(
            "PATH",
            format!("{}:{}", w.path("fakebin").display(), sys.display()),
        )
        .output()
        .unwrap();
    let all = text(&out);
    assert!(!out.status.success(), "{all}");
    assert!(
        all.contains(&format!(
            "release v1.0.0 has no kagebunshin-1.0.0-{TARGET}.tar.gz"
        )),
        "{all}"
    );
    assert!(!w.path("home/.local/bin/kagebunshin").exists());
}

#[test]
fn a_tarball_that_does_not_match_its_checksum_is_not_installed() {
    let w = World::new();
    let kb = &w.cli();
    w.pack("1.0.0", "kagebunshin", &[kb, &w.app("1.0.0")]);
    let sum = w.path(&format!(
        "releases/v1.0.0/kagebunshin-1.0.0-{TARGET}.tar.gz.sha256"
    ));
    let line = fs::read_to_string(&sum).unwrap();
    let flipped = if line.starts_with('0') { "1" } else { "0" };
    fs::write(&sum, format!("{flipped}{}", &line[1..])).unwrap();

    let out = w.install("1.0.0", &["--no-setup"]);
    let all = text(&out);
    assert!(!out.status.success(), "{all}");
    assert!(all.contains("does not match its SHA-256"), "{all}");
    assert!(!w.path("home/.local/bin/kagebunshin").exists());
}

#[test]
fn a_missing_release_fails_with_its_name() {
    let w = World::new();
    let out = w.install("1.0.0", &["--no-setup"]);
    let all = text(&out);
    assert!(!out.status.success());
    assert!(
        all.contains(&format!(
            "release v1.0.0 has no kagebunshin-1.0.0-{TARGET}.tar.gz"
        )),
        "{all}"
    );
}

/// `--uninstall` hands the listing to `kagebunshin uninstall`, and adds
/// `cargo uninstall` for what cargo installed.
#[test]
fn uninstall_lists_what_goes_including_cargo_binaries() {
    let w = World::new();
    w.pack("1.0.0", "kagebunshin", &[&w.cli(), &w.app("1.0.0")]);
    let out = w.install("1.0.0", &["--no-setup"]);
    assert!(out.status.success(), "{}", text(&out));
    let cargo = w.path("home/.cargo/bin/kagebunshin");
    fs::create_dir_all(cargo.parent().unwrap()).unwrap();
    fs::write(&cargo, "").unwrap();

    let out = w.install("1.0.0", &["--uninstall", "--purge", "--dry-run"]);
    let all = text(&out);
    assert!(out.status.success(), "{all}");
    assert!(all.contains("would remove:"), "{all}");
    let bin = w.path("home/.local/bin/kagebunshin-app");
    assert!(all.contains(&bin.display().to_string()), "{all}");
    assert!(
        all.contains("would run: cargo uninstall kagebunshin\n"),
        "{all}"
    );
    assert!(bin.exists() && cargo.exists());

    let out = w.install("1.0.0", &["--purge"]);
    assert!(!out.status.success(), "--purge alone is a mistake");
}

/// A `kagebunshin` from before `uninstall` existed, as `cargo install`
/// left it: `--uninstall` says so and still runs `cargo uninstall`.
#[test]
fn uninstall_goes_on_past_a_build_without_the_command() {
    let w = World::new();
    let cargo_bin = w.path("home/.cargo/bin");
    fs::create_dir_all(&cargo_bin).unwrap();
    executable(
        &cargo_bin.join("kagebunshin"),
        "#!/bin/sh\necho \"error: unrecognized subcommand '$1'\" >&2\nexit 2\n",
    );
    let log = w.path("cargo.log");
    executable(
        &w.path("fakebin/cargo"),
        &format!("#!/bin/sh\necho \"cargo $*\" >> '{}'\n", log.display()),
    );
    let out = w.install("1.0.0", &["--uninstall"]);
    let all = text(&out);
    assert!(out.status.success(), "{all}");
    assert!(all.contains("has no uninstall command"), "{all}");
    let ran = fs::read_to_string(&log).unwrap_or_default();
    assert_eq!(ran, "cargo uninstall kagebunshin\n", "{all}");
}
