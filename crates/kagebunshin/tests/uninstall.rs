//! `kagebunshin uninstall` in a throwaway HOME, with a fake service
//! manager on PATH so the real user's service is never touched.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test code")]

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use common::{on_terminal_after, on_terminal_at};

struct World {
    tmp: tempfile::TempDir,
}

impl World {
    /// Everything installed: service, skills, binaries, config, store,
    /// audit log and socket directory, plus `~/.aws` and cargo's binaries.
    fn installed() -> Self {
        let w = World {
            tmp: tempfile::tempdir().unwrap(),
        };
        for f in [
            "home/.config/opencode/skills/kagebunshin/SKILL.md",
            "home/.claude/skills/kagebunshin/SKILL.md",
            "home/.local/bin/kagebunshin",
            "home/.local/bin/kagebunshin-app",
            "home/.local/bin/other-tool",
            "home/.config/kagebunshin/store.age",
            "home/.config/kagebunshin/projects/widget.toml",
            "home/.local/state/kagebunshin/audit.jsonl",
            "home/.local/state/kagebunshin/runs.jsonl",
            "home/.local/state/kagebunshin/proofs.json",
            "home/.local/state/kagebunshin/imported.json",
            "home/.local/state/kagebunshin/left-out.json",
            "home/.local/share/kagebunshin/proton/local.key",
            "home/.local/share/kagebunshin/proton/.kagebunshin-session",
            "home/.local/share/kagebunshin/proton.old/session",
            "home/.local/share/kagebunshin/proton.old/.kagebunshin-session",
            "run/kagebunshin/kagebunshind.sock",
            "home/.aws/config",
            "home/.cargo/bin/kagebunshin",
            &World::unit(),
        ] {
            let p = w.path(f);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, "x").unwrap();
        }
        let log = w.path("service.log");
        for manager in ["systemctl", "launchctl"] {
            let p = w.path(&format!("fakebin/{manager}"));
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(
                &p,
                format!("#!/bin/sh\necho \"{manager} $*\" >> '{}'\n", log.display()),
            )
            .unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        }
        // The hooks as `hook install` writes them, beside the user's own.
        fs::write(w.path("home/.claude/settings.json"), USER_SETTINGS).unwrap();
        for agent in ["claude", "opencode"] {
            let out = Command::new(env!("CARGO_BIN_EXE_kagebunshin"))
                .args(["hook", "install", agent])
                .env_clear()
                .env("HOME", w.path("home"))
                .env("XDG_CONFIG_HOME", w.path("home/.config"))
                .output()
                .unwrap();
            assert!(out.status.success(), "{out:?}");
        }
        w
    }

    fn unit() -> String {
        if cfg!(target_os = "macos") {
            "home/Library/LaunchAgents/io.github.oorestisime.kagebunshin.plist".into()
        } else {
            "home/.config/systemd/user/kagebunshin.service".into()
        }
    }

    fn path(&self, p: &str) -> PathBuf {
        self.tmp.path().join(p)
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = self.kb(&["uninstall"]);
        c.args(args);
        c
    }

    /// The CLI in this world.
    fn kb(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_kagebunshin"));
        c.args(args).env_clear();
        for (k, v) in [
            (
                "PATH",
                format!("{}:/usr/bin:/bin", self.path("fakebin").display()),
            ),
            ("HOME", self.path("home").display().to_string()),
            (
                "XDG_CONFIG_HOME",
                self.path("home/.config").display().to_string(),
            ),
            (
                "XDG_STATE_HOME",
                self.path("home/.local/state").display().to_string(),
            ),
            ("XDG_RUNTIME_DIR", self.path("run").display().to_string()),
            ("TMPDIR", self.path("run").display().to_string()),
        ] {
            c.env(k, v);
        }
        c
    }

    fn exists(&self, p: &str) -> bool {
        self.path(p).exists()
    }

    fn service_log(&self) -> String {
        fs::read_to_string(self.path("service.log")).unwrap_or_default()
    }
}

fn run(c: &mut Command) -> (bool, String) {
    let out = c.output().unwrap();
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), all)
}

/// Claude Code settings with a hook of the user's own.
const USER_SETTINGS: &str = r#"{
  "model": "opus",
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash", "hooks": [{ "type": "command", "command": "my-check" }] }
    ]
  }
}"#;

const PLUGIN: &str = "home/.config/opencode/plugins/kagebunshin.js";

fn claude_settings(w: &World) -> serde_json::Value {
    serde_json::from_str(&fs::read_to_string(w.path("home/.claude/settings.json")).unwrap())
        .unwrap()
}

const KEPT: [&str; 4] = [
    "home/.config/kagebunshin/store.age",
    "home/.local/state/kagebunshin/audit.jsonl",
    "home/.aws/config",
    "home/.cargo/bin/kagebunshin",
];

#[test]
fn a_dry_run_lists_every_path_and_removes_nothing() {
    let w = World::installed();
    let (ok, all) = run(&mut w.cmd(&["--dry-run"]));
    assert!(ok, "{all}");
    for p in [
        &World::unit(),
        "home/.config/opencode/skills/kagebunshin",
        "home/.claude/skills/kagebunshin",
        PLUGIN,
        "home/.claude/settings.json",
        "home/.local/bin/kagebunshin",
        "home/.local/bin/kagebunshin-app",
        "home/.config/kagebunshin",
        "home/.local/state/kagebunshin",
        "home/.local/share/kagebunshin",
        "run/kagebunshin",
    ] {
        assert!(all.contains(&w.path(p).display().to_string()), "{p}: {all}");
        assert!(w.exists(p), "{p}");
    }
    assert!(all.contains("would remove:"), "{all}");
    assert!(all.contains("kept (--purge removes them):"), "{all}");
    assert!(
        all.contains("cargo uninstall kagebunshin kagebunshin-app"),
        "{all}"
    );
    assert!(!all.contains("other-tool"), "{all}");
    assert!(!all.contains(".aws/config"), "{all}");
    assert_eq!(w.service_log(), "", "a dry run asks no service manager");

    let (ok, all) = run(&mut w.cmd(&["--dry-run", "--purge", "--json"]));
    assert!(ok, "{all}");
    let v: serde_json::Value = serde_json::from_str(all.trim()).unwrap();
    let whats: Vec<_> = v["remove"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["what"].as_str().unwrap())
        .collect();
    for what in [
        "service",
        "skill",
        "OpenCode hooks",
        "Claude Code hooks",
        "binary",
        "config and store",
        "audit log",
        "socket",
        "proton session",
    ] {
        assert!(whats.contains(&what), "{what}: {v}");
    }
    assert_eq!(v["removed"], false);
}

#[test]
fn removes_once_confirmed_and_keeps_the_store_without_purge() {
    let w = World::installed();
    let (code, out) = on_terminal_at(&w.cmd(&[]), "[y/N]", "n\n");
    assert_ne!(code, 0, "{out}");
    assert!(out.contains("nothing was removed"), "{out}");
    assert!(w.exists("home/.local/bin/kagebunshin"));

    let settings = claude_settings(&w);
    assert!(settings["hooks"]["SessionStart"].is_array(), "{settings}");
    assert_eq!(settings["hooks"]["PreToolUse"].as_array().unwrap().len(), 2);

    let (code, out) = on_terminal_at(&w.cmd(&[]), "[y/N]", "y\n");
    assert_eq!(code, 0, "{out}");
    assert_eq!(
        claude_settings(&w),
        serde_json::from_str::<serde_json::Value>(USER_SETTINGS).unwrap(),
        "only kagebunshin's hooks come out"
    );
    for p in [
        &World::unit(),
        "home/.config/opencode/skills/kagebunshin",
        "home/.claude/skills/kagebunshin",
        PLUGIN,
        "home/.local/bin/kagebunshin",
        "home/.local/bin/kagebunshin-app",
    ] {
        assert!(!w.exists(p), "{p} is still there");
    }
    for p in KEPT.iter().chain(&[
        "run/kagebunshin/kagebunshind.sock",
        "home/.local/bin/other-tool",
    ]) {
        assert!(w.exists(p), "{p} is gone");
    }
    let log = w.service_log();
    if cfg!(target_os = "macos") {
        assert!(log.contains("launchctl bootout"), "{log}");
    } else {
        // The app's unit is stopped first, then the daemon's.
        assert!(
            log.starts_with("systemctl --user stop kagebunshin-app.service\n")
                && log.contains("systemctl --user disable --now kagebunshin.service"),
            "{log}"
        );
    }
}

#[test]
fn purge_removes_the_store_and_logs_but_not_aws() {
    let w = World::installed();
    let (code, out) = on_terminal_at(&w.cmd(&["--purge"]), "[y/N]", "yes\n");
    assert_eq!(code, 0, "{out}");
    for p in [
        "home/.config/kagebunshin",
        "home/.local/state/kagebunshin",
        "home/.local/share/kagebunshin",
        "run/kagebunshin",
    ] {
        assert!(!w.exists(p), "{p} is still there");
    }
    assert!(w.exists("home/.aws/config"));
    assert!(w.exists("home/.cargo/bin/kagebunshin"));
    assert!(w.exists("home/.config"), "only kagebunshin's own directory");
    assert!(
        w.exists("home/.local/share"),
        "only kagebunshin's own directory"
    );

    let (ok, all) = run(&mut w.cmd(&["--dry-run"]));
    assert!(ok, "{all}");
    assert!(all.contains("nothing to remove"), "{all}");
}

/// A config directory an override points at is not removed whole.
#[test]
fn purge_leaves_alone_a_directory_that_is_not_its_own() {
    let w = World::installed();
    let mine = w.path("home/secrets");
    fs::create_dir_all(&mine).unwrap();
    fs::write(mine.join("notes.txt"), "mine").unwrap();
    let mut cmd = w.cmd(&["--purge", "--dry-run"]);
    cmd.env("KAGEBUNSHIN_CONFIG_DIR", &mine);
    let (ok, all) = run(&mut cmd);
    assert!(ok, "{all}");
    assert!(all.contains("left alone"), "{all}");
    let (_, remove) = all.split_once("would remove:").unwrap();
    let (remove, _) = remove.split_once("left alone").unwrap();
    assert!(!remove.contains(&mine.display().to_string()), "{all}");
    assert!(Path::new(&mine).join("notes.txt").exists());
}

/// A checkout named `kagebunshin`, as an override or under
/// `XDG_CONFIG_HOME`, is not kagebunshin's however it is named: nothing in
/// it is removed, not even files with kagebunshin's names.
#[test]
fn purge_leaves_alone_a_repository_named_kagebunshin() {
    let w = World::installed();
    let repo = w.path("home/src/kagebunshin");
    for f in [".git/HEAD", "Cargo.toml", "config.toml", "store.age"] {
        let p = repo.join(f);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, "mine").unwrap();
    }
    for (var, value) in [
        ("KAGEBUNSHIN_CONFIG_DIR", repo.clone()),
        ("XDG_CONFIG_HOME", w.path("home/src")),
    ] {
        let mut cmd = w.cmd(&["--purge"]);
        cmd.env(var, &value);
        let (code, out) = on_terminal_at(&cmd, "[y/N]", "yes\n");
        assert_eq!(code, 0, "{var}: {out}");
        assert!(
            out.contains(&format!(
                "{} (holds files that are not kagebunshin's)",
                repo.display()
            )),
            "{var}: {out}"
        );
        for f in [".git/HEAD", "Cargo.toml", "config.toml", "store.age"] {
            assert!(repo.join(f).exists(), "{var}: {f} is gone");
        }
    }
}

/// `~/.aws` is never touched, also when a symlink leads into it, or it is
/// itself a symlink.
#[test]
fn purge_never_reaches_into_aws_through_a_symlink() {
    use std::os::unix::fs::symlink;
    let w = World::installed();
    // Only kagebunshin's files, but in ~/.aws, reached through ~/link.
    let inside = w.path("home/.aws/kagebunshin");
    fs::create_dir_all(&inside).unwrap();
    fs::write(inside.join("store.age"), "x").unwrap();
    symlink(w.path("home/.aws"), w.path("home/link")).unwrap();
    let mut cmd = w.cmd(&["--purge"]);
    cmd.env("KAGEBUNSHIN_CONFIG_DIR", w.path("home/link/kagebunshin"));
    let (code, out) = on_terminal_at(&cmd, "[y/N]", "yes\n");
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("(is in or holds ~/.aws)"), "{out}");
    assert!(inside.join("store.age").exists());
    assert!(w.exists("home/.aws/config"));

    // ~/.aws a symlink to dotfiles, the audit log's directory inside them.
    let w = World::installed();
    let real = w.path("home/dotfiles/aws");
    fs::create_dir_all(real.join("kagebunshin")).unwrap();
    fs::write(real.join("kagebunshin/audit.jsonl"), "x").unwrap();
    fs::rename(w.path("home/.aws/config"), real.join("config")).unwrap();
    fs::remove_dir(w.path("home/.aws")).unwrap();
    symlink(&real, w.path("home/.aws")).unwrap();
    let mut cmd = w.cmd(&["--purge"]);
    cmd.env("XDG_STATE_HOME", &real);
    let (code, out) = on_terminal_at(&cmd, "[y/N]", "yes\n");
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("(is in or holds ~/.aws)"), "{out}");
    assert!(real.join("kagebunshin/audit.jsonl").exists());
    assert!(real.join("config").exists());
}

/// A directory named like a Proton session but without kagebunshin's
/// marker is not kagebunshin's: nothing beside it goes.
#[test]
fn purge_leaves_alone_a_proton_directory_it_did_not_make() {
    let w = World::installed();
    fs::remove_file(w.path("home/.local/share/kagebunshin/proton/.kagebunshin-session")).unwrap();
    fs::write(
        w.path("home/.local/share/kagebunshin/proton/notes.txt"),
        "mine",
    )
    .unwrap();
    let (code, out) = on_terminal_at(&w.cmd(&["--purge"]), "[y/N]", "yes\n");
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains(&format!(
            "{} (holds files that are not kagebunshin's)",
            w.path("home/.local/share/kagebunshin").display()
        )),
        "{out}"
    );
    assert!(w.exists("home/.local/share/kagebunshin/proton/notes.txt"));
    assert!(w.exists("home/.local/share/kagebunshin/proton.old/session"));
    assert!(!w.exists("home/.config/kagebunshin"));
}

/// What changes between the listing and the confirmation is checked again:
/// a directory a file was added to since, replaced since, or reached
/// through a symlink pointed elsewhere since, is left alone entirely.
#[test]
fn purge_checks_again_once_confirmed() {
    use std::os::unix::fs::symlink;

    let w = World::installed();
    let config = w.path("home/.config/kagebunshin");
    let (code, out) = on_terminal_after(
        &w.cmd(&["--purge"]),
        "[y/N]",
        || fs::write(config.join("notes.txt"), "mine").unwrap(),
        "yes\n",
    );
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains(&format!(
            "left alone {} (holds files that are not kagebunshin's)",
            config.display()
        )),
        "{out}"
    );
    assert!(config.join("notes.txt").exists());
    assert!(config.join("store.age").exists());
    assert!(!w.exists("home/.local/state/kagebunshin"));

    // Replaced by another directory holding only kagebunshin's names.
    let w = World::installed();
    let config = w.path("home/.config/kagebunshin");
    let (code, out) = on_terminal_after(
        &w.cmd(&["--purge"]),
        "[y/N]",
        || {
            fs::rename(&config, w.path("home/moved")).unwrap();
            fs::create_dir(&config).unwrap();
            fs::write(config.join("store.age"), "other").unwrap();
        },
        "yes\n",
    );
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("(changed since it was listed)"), "{out}");
    assert!(config.join("store.age").exists());

    // Reached through ~/link, pointed at another directory since.
    let w = World::installed();
    for d in ["home/a/kagebunshin", "home/b/kagebunshin"] {
        fs::create_dir_all(w.path(d)).unwrap();
        fs::write(w.path(d).join("store.age"), "x").unwrap();
    }
    let link = w.path("home/link");
    symlink(w.path("home/a"), &link).unwrap();
    let mut cmd = w.cmd(&["--purge"]);
    cmd.env("KAGEBUNSHIN_CONFIG_DIR", link.join("kagebunshin"));
    let (code, out) = on_terminal_after(
        &cmd,
        "[y/N]",
        || {
            fs::remove_file(&link).unwrap();
            symlink(w.path("home/b"), &link).unwrap();
        },
        "yes\n",
    );
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("(changed since it was listed)"), "{out}");
    assert!(w.exists("home/a/kagebunshin/store.age"));
    assert!(w.exists("home/b/kagebunshin/store.age"));
}

/// `app install` puts the app in the launcher and at login, for the socket
/// the CLI resolves. A file of the same name that is not kagebunshin's
/// stays as it is, through install and uninstall both; and what an app
/// that ran leaves beside the daemon's socket does not stop a purge.
#[test]
#[cfg(target_os = "linux")]
fn the_apps_launcher_is_written_and_removed_only_where_it_is_its_own() {
    const ID: &str = "io.github.oorestisime.kagebunshin";
    let w = World::installed();
    // Found on PATH, unless a built one is next to the CLI.
    let app = w.path("fakebin/kagebunshin-app");
    fs::write(&app, "#!/bin/sh\n").unwrap();
    fs::set_permissions(&app, fs::Permissions::from_mode(0o755)).unwrap();
    let launcher = format!("home/.local/share/applications/{ID}.desktop");
    let login = format!("home/.config/autostart/{ID}.desktop");
    let icon = format!("home/.local/share/icons/hicolor/scalable/apps/{ID}.svg");
    let read = |p: &str| fs::read_to_string(w.path(p)).unwrap();

    // Someone else's login entry of the same name.
    const MINE: &str = "[Desktop Entry]\nName=Mine\n";
    fs::create_dir_all(w.path(&login).parent().unwrap()).unwrap();
    fs::write(w.path(&login), MINE).unwrap();

    let (ok, all) = run(&mut w.kb(&["--json", "app", "install"]));
    assert!(ok, "{all}");
    let v: serde_json::Value = serde_json::from_str(all.trim()).unwrap();
    let reasons: Vec<_> = v["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| (f["what"].as_str().unwrap(), f["reason"].as_str()))
        .collect();
    assert_eq!(
        reasons,
        [
            ("launcher", None),
            ("login entry", Some("is not kagebunshin's")),
            ("icon", None),
        ]
    );
    assert_eq!(read(&login), MINE);
    let socket = w.path("run/kagebunshin/kagebunshind.sock");
    let text = read(&launcher);
    assert!(
        text.contains(&format!(
            "kagebunshin\" --socket \"{}\" app\n",
            socket.display()
        )),
        "{text}"
    );
    assert!(read(&icon).contains("</svg>"));
    match Command::new("desktop-file-validate")
        .arg(w.path(&launcher))
        .output()
    {
        Ok(o) => assert!(o.status.success(), "{o:?}"),
        Err(e) => assert!(
            std::env::var_os("CI").is_none(),
            "desktop-file-validate: {e}"
        ),
    }

    // Run again, its own files are replaced; the login entry is free now.
    fs::remove_file(w.path(&login)).unwrap();
    fs::write(
        w.path(&launcher),
        text.replace("Name=Kagebunshin", "Name=Old"),
    )
    .unwrap();
    let (ok, all) = run(&mut w.kb(&["app", "install"]));
    assert!(ok, "{all}");
    assert!(!all.contains("left alone"), "{all}");
    assert_eq!(read(&launcher), text);
    assert!(read(&login).contains(" --hidden\n"), "{}", read(&login));

    // The icon is someone else's now, and the app has run.
    fs::write(w.path(&icon), "<svg/>").unwrap();
    for f in ["app.lock", "app.sock"] {
        fs::write(w.path("run/kagebunshin").join(f), "").unwrap();
    }
    let (ok, all) = run(&mut w.cmd(&["--dry-run"]));
    assert!(ok, "{all}");
    for p in [&launcher, &login] {
        assert!(all.contains(&w.path(p).display().to_string()), "{p}: {all}");
    }
    assert!(!all.contains(&icon), "{all}");

    let (code, out) = on_terminal_at(&w.cmd(&["--purge"]), "[y/N]", "y\n");
    assert_eq!(code, 0, "{out}");
    for p in [launcher.as_str(), &login, "run/kagebunshin"] {
        assert!(!w.exists(p), "{p} is still there");
    }
    assert_eq!(read(&icon), "<svg/>");

    // `app uninstall` removes only the three files, where they are its own.
    let (ok, all) = run(&mut w.kb(&["app", "install"]));
    assert!(ok, "{all}");
    assert!(w.exists(&launcher) && w.exists(&login));
    let (ok, all) = run(&mut w.kb(&["app", "uninstall"]));
    assert!(ok, "{all}");
    assert!(!w.exists(&launcher) && !w.exists(&login));
    assert_eq!(read(&icon), "<svg/>");
    let (ok, all) = run(&mut w.kb(&["app", "uninstall"]));
    assert!(ok && all.starts_with("not installed"), "{all}");
}
