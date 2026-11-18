//! `kagebunshin uninstall [--purge] [--dry-run]`: removes what `install.sh`
//! and `setup` put on this machine, listing every path first. Agent hooks
//! go too: the OpenCode plugin file, and only kagebunshin's entries in
//! Claude Code's settings, which keep everything else. So do the app's
//! launcher entry, login entry and icon, where kagebunshin wrote them, and
//! the app in the tray is told to end.
//!
//! Without `--purge` the config, the store, the audit log and the Proton
//! session stay. With it, each of their directories is removed only if
//! everything in it is something kagebunshin writes there (by name, and
//! Proton sessions by the marker kagebunshin puts in them), it is not a
//! symlink, and, with symlinks resolved, it is neither in `~/.aws` nor
//! holds it; otherwise it is left alone, whatever it is called. Once
//! confirmed, each is checked again, and must still be the directory that
//! was listed; then its own files are removed one by one, never through a
//! symlink, and the directory last, which fails if anything else is in it.
//! Binaries that `cargo install` put in place are left to `cargo
//! uninstall`, which `install.sh --uninstall` runs.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use super::{CliError, Exit, print_json, print_line, units};
use crate::audit::AuditLog;
use crate::config::ConfigDir;
use crate::ipc::paths;
use crate::source::proton::{PassCli, SESSION_MARKER};

/// What the release and `cargo install` put in a bin directory.
const BINARIES: [&str; 3] = ["kagebunshin", "kagebunshind", "kagebunshin-app"];

#[derive(Debug, serde::Serialize)]
struct Item {
    what: &'static str,
    path: PathBuf,
    /// Why a directory is left alone.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
}

/// What kagebunshin writes in one of its directories, by name.
type Owns = Box<dyn Fn(&str) -> Option<Kind>>;

enum Kind {
    /// A file (or socket), never a symlink.
    File,
    /// A directory holding only what this says.
    Dir(Owns),
    /// A `pass-cli` session directory, whose files are `pass-cli`'s:
    /// kagebunshin's if it holds [`SESSION_MARKER`].
    Session,
}

const NOT_OURS: &str = "holds files that are not kagebunshin's";

/// `.<name>.<random>.tmp`, an atomic write's temp file.
fn is_temp(name: &str) -> bool {
    name.starts_with('.') && name.ends_with(crate::atomic::TEMP_SUFFIX)
}

/// Files named `names`, and temp files.
fn files(names: Vec<String>) -> Owns {
    Box::new(move |n| (names.iter().any(|k| k == n) || is_temp(n)).then_some(Kind::File))
}

/// What `owns` makes of `e`, if it is kagebunshin's; never follows a
/// symlink.
fn kind_of(e: &std::fs::DirEntry, owns: &Owns) -> Option<Kind> {
    let t = e.file_type().ok()?;
    let kind = owns(e.file_name().to_str()?)?;
    let ours = match &kind {
        Kind::File => !t.is_dir() && !t.is_symlink(),
        Kind::Dir(_) => t.is_dir(),
        Kind::Session => {
            t.is_dir()
                && e.path()
                    .join(SESSION_MARKER)
                    .symlink_metadata()
                    .is_ok_and(|m| m.is_file())
        }
    };
    ours.then_some(kind)
}

/// Whether everything in `dir` is kagebunshin's.
fn all_ours(dir: &Path, owns: &Owns) -> bool {
    std::fs::read_dir(dir).is_ok_and(|entries| {
        entries.into_iter().all(|e| {
            e.is_ok_and(|e| match kind_of(&e, owns) {
                Some(Kind::Dir(inner)) => all_ours(&e.path(), &inner),
                Some(_) => true,
                None => false,
            })
        })
    })
}

/// Removes what is kagebunshin's in `dir`, one entry at a time and never
/// through a symlink, then `dir`, which fails if anything else is left.
/// An entry that cannot go does not stop the rest: the first such error
/// is returned once every entry was tried.
fn remove_ours(dir: &Path, owns: &Owns) -> std::io::Result<()> {
    let mut failed = None;
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        let gone = match kind_of(&e, owns) {
            None => continue,
            Some(Kind::File) => std::fs::remove_file(e.path()),
            Some(Kind::Dir(inner)) => remove_ours(&e.path(), &inner),
            // `remove_dir_all` does not follow symlinks.
            Some(Kind::Session) => std::fs::remove_dir_all(e.path()),
        };
        match gone {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                failed.get_or_insert(e);
            }
            _ => {}
        }
    }
    match failed {
        Some(e) => Err(e),
        None => std::fs::remove_dir(dir),
    }
}

/// The directory a purge removes: where it is with symlinks resolved, and
/// which one it is (device and inode).
#[derive(PartialEq)]
struct Pin {
    real: PathBuf,
    id: (u64, u64),
}

/// Which directory `dir` is, if it can be removed whole; else why not:
/// something in it is not kagebunshin's, it is a symlink, or it is in or
/// holds `aws`, `~/.aws` with symlinks resolved.
fn pin(dir: &Path, owns: &Owns, aws: Option<&Path>) -> Result<Pin, &'static str> {
    use std::os::unix::fs::MetadataExt;
    if dir
        .symlink_metadata()
        .is_ok_and(|m| m.file_type().is_symlink())
    {
        return Err("is a symlink");
    }
    let real = dir.canonicalize().map_err(|_| NOT_OURS)?;
    if aws.is_some_and(|aws| real.starts_with(aws) || aws.starts_with(&real)) {
        return Err("is in or holds ~/.aws");
    }
    let meta = real.symlink_metadata().map_err(|_| NOT_OURS)?;
    if !meta.is_dir() || !all_ours(&real, owns) {
        return Err(NOT_OURS);
    }
    Ok(Pin {
        real,
        id: (meta.dev(), meta.ino()),
    })
}

fn failed(code: &'static str, message: impl Into<String>) -> CliError {
    CliError::new(Exit::Failure, code, message.into())
}

pub fn uninstall(
    json: bool,
    socket: Option<PathBuf>,
    purge: bool,
    dry_run: bool,
) -> Result<(), CliError> {
    let var = |k: &str| {
        std::env::var_os(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
    };
    let home =
        var("HOME").ok_or_else(|| failed("config", "HOME is not set to an absolute path"))?;
    let config_home = var("XDG_CONFIG_HOME").unwrap_or_else(|| home.join(".config"));

    let mut remove = Vec::new();
    let mut push = |what, path: PathBuf| {
        if path.symlink_metadata().is_ok() {
            remove.push(Item {
                what,
                path,
                reason: None,
            });
        }
    };
    let unit = units::unit_path()?;
    push("service", unit.clone());
    #[cfg(target_os = "macos")]
    push("service logs", units::log_dir(&unit));
    push("skill", config_home.join("opencode/skills/kagebunshin"));
    push("skill", home.join(".claude/skills/kagebunshin"));
    let (claude_settings, opencode_plugin) = super::hook::paths()?;
    push("OpenCode hooks", opencode_plugin);
    // Only kagebunshin's hooks come out of it; the file stays.
    if super::hook::has_claude_hooks(&claude_settings) {
        push("Claude Code hooks", claude_settings.clone());
    }
    let bin_dir = var("KAGEBUNSHIN_BIN_DIR").unwrap_or_else(|| home.join(".local/bin"));
    for b in BINARIES {
        push("binary", bin_dir.join(b));
    }
    // The app's launcher entry, login entry and icon, where kagebunshin
    // wrote them.
    if cfg!(target_os = "linux") {
        for (what, path) in super::desktop::paths()? {
            if super::desktop::managed(&path) {
                push(what, path);
            }
        }
    }

    let config = ConfigDir::from_env()
        .map_err(|e| failed("config", e.to_string()))?
        .path()
        .to_owned();
    let audit = AuditLog::from_env().map_err(|e| failed("config", e.to_string()))?;
    let socket = match socket {
        Some(s) => s,
        None => paths::default_socket_path().map_err(|e| failed("socket", e.to_string()))?,
    };
    let socket_name = socket
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let daemon_socket = socket.clone();
    let socket = paths::socket_dir(&socket).to_owned();
    let audit_name = audit
        .path()
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let audit = audit.path().parent().unwrap_or(audit.path()).to_owned();
    // The Proton session and the staging and old copies `connect proton`
    // swaps through, all beside it.
    let data = PassCli::from_env()
        .session_dir
        .and_then(|s| s.parent().map(Path::to_owned));
    let aws = home.join(".aws").canonicalize().ok();

    let config_owns: Owns = {
        let files = files(
            [
                "config.toml",
                crate::config::LOCK_FILE,
                "store.age",
                "store.age.lock",
            ]
            .map(String::from)
            .to_vec(),
        );
        Box::new(move |n| {
            if n == "projects" {
                return Some(Kind::Dir(Box::new(|n| {
                    #[expect(
                        clippy::case_sensitive_file_extension_comparisons,
                        reason = "only the lowercase names kagebunshin writes are its own"
                    )]
                    (n.ends_with(".toml") || is_temp(n)).then_some(Kind::File)
                })));
            }
            files(n)
        })
    };
    let audit_owns = files(vec![
        audit_name.clone(),
        format!("{audit_name}.1"),
        "audit.lock".into(),
    ]);
    let socket_owns = files(vec![
        socket_name.clone(),
        format!("{socket_name}.lock"),
        paths::APP_LOCK_FILE.into(),
        paths::APP_SOCKET_FILE.into(),
    ]);
    let data_owns: Owns = Box::new(|n| {
        ["proton", "proton.staging", "proton.old"]
            .contains(&n)
            .then_some(Kind::Session)
    });
    let mut dirs = vec![
        ("config and store", config, config_owns),
        ("audit log", audit, audit_owns),
        ("socket", socket, socket_owns),
    ];
    if let Some(data) = data {
        dirs.push(("proton session", data, data_owns));
    }

    let (mut kept, mut refused, mut pins) = (Vec::new(), Vec::new(), Vec::new());
    for (what, path, owns) in dirs {
        if path.symlink_metadata().is_err() {
            continue;
        }
        let mut item = Item {
            what,
            path,
            reason: None,
        };
        if !purge {
            kept.push(item);
            continue;
        }
        match pin(&item.path, &owns, aws.as_deref()) {
            Ok(pin) => {
                pins.push((item.path.clone(), pin, owns));
                remove.push(item);
            }
            Err(why) => {
                item.reason = Some(why);
                refused.push(item);
            }
        }
    }
    let cargo_bin = var("CARGO_HOME")
        .unwrap_or_else(|| home.join(".cargo"))
        .join("bin");
    let cargo = cargo_bin != bin_dir && BINARIES.iter().any(|b| cargo_bin.join(b).exists());

    if json && (dry_run || remove.is_empty()) {
        return print_json(&serde_json::json!({
            "remove": remove,
            "kept": kept,
            "left_alone": refused,
            "cargo_bin": cargo.then_some(&cargo_bin),
            "removed": false,
        }));
    }
    if !json {
        list(
            &remove,
            &kept,
            &refused,
            cargo.then_some(&cargo_bin),
            dry_run,
        )?;
    }
    if remove.is_empty() || dry_run {
        return Ok(());
    }
    if !confirm("Remove these? [y/N] ")? {
        return Err(CliError::new(
            Exit::Failure,
            "cancelled",
            "nothing was removed".to_owned(),
        ));
    }
    // The app in the tray is ended, before its binary and its socket go.
    super::desktop::stop(&daemon_socket);
    let mut removed = Vec::new();
    for mut item in remove {
        if let Some((_, was, owns)) = pins.iter().find(|(p, ..)| *p == item.path) {
            // Checked again: still all kagebunshin's, and the same directory.
            let why = match pin(&item.path, owns, aws.as_deref()) {
                Ok(now) if now == *was => match remove_ours(&now.real, owns) {
                    Ok(()) => None,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                    Err(e) if e.kind() == std::io::ErrorKind::DirectoryNotEmpty => Some(NOT_OURS),
                    Err(e) => {
                        return Err(failed(
                            "uninstall",
                            format!("cannot remove {}: {e}", item.path.display()),
                        ));
                    }
                },
                Ok(_) => Some("changed since it was listed"),
                Err(why) => Some(why),
            };
            if let Some(why) = why {
                if !json {
                    print_line(&format!("left alone {} ({why})", item.path.display()))?;
                }
                item.reason = Some(why);
                refused.push(item);
                continue;
            }
        } else if item.path == unit {
            // Stopped first, so the daemon does not outlive its unit.
            let (_, _, warnings) = units::remove_unit(false)?;
            for w in warnings {
                super::error::warn(&w);
            }
        } else if item.path == claude_settings {
            super::hook::remove_claude(&item.path)?;
            if !json {
                print_line(&format!("removed the hooks from {}", item.path.display()))?;
            }
            removed.push(item);
            continue;
        } else {
            let gone = if item.path.is_dir() && !item.path.is_symlink() {
                std::fs::remove_dir_all(&item.path)
            } else {
                std::fs::remove_file(&item.path)
            };
            match gone {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(failed(
                        "uninstall",
                        format!("cannot remove {}: {e}", item.path.display()),
                    ));
                }
            }
        }
        if !json {
            print_line(&format!("removed {}", item.path.display()))?;
        }
        removed.push(item);
    }
    if json {
        return print_json(&serde_json::json!({
            "remove": removed,
            "kept": kept,
            "left_alone": refused,
            "cargo_bin": cargo.then_some(&cargo_bin),
            "removed": true,
        }));
    }
    Ok(())
}

fn list(
    remove: &[Item],
    kept: &[Item],
    refused: &[Item],
    cargo_bin: Option<&PathBuf>,
    dry_run: bool,
) -> Result<(), CliError> {
    let rows = |items: &[Item]| -> Result<(), CliError> {
        for i in items {
            let why = i.reason.map(|r| format!(" ({r})")).unwrap_or_default();
            print_line(&format!("  {:<17} {}{why}", i.what, i.path.display()))?;
        }
        Ok(())
    };
    if remove.is_empty() {
        print_line("nothing to remove")?;
    } else {
        print_line(if dry_run { "would remove:" } else { "removes:" })?;
        rows(remove)?;
    }
    if !kept.is_empty() {
        print_line("kept (--purge removes them):")?;
        rows(kept)?;
    }
    if !refused.is_empty() {
        print_line("left alone (remove it yourself):")?;
        rows(refused)?;
    }
    if let Some(bin) = cargo_bin {
        print_line(&format!(
            "installed by cargo in {}, left to it: cargo uninstall kagebunshin kagebunshin-app",
            bin.display()
        ))?;
    }
    print_line("never touched: ~/.aws and your repositories")
}

/// Asks at the controlling terminal; anything but y or yes is a no.
fn confirm(question: &str) -> Result<bool, CliError> {
    let no_terminal = |e: std::io::Error| {
        CliError::new(
            Exit::Failure,
            "no_terminal",
            format!("cannot ask for confirmation at the terminal: {e}"),
        )
        .with_hint("run this in an interactive terminal, or with --dry-run to only list")
    };
    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(no_terminal)?;
    tty.write_all(question.as_bytes()).map_err(no_terminal)?;
    let mut answer = String::new();
    BufReader::new(tty)
        .read_line(&mut answer)
        .map_err(no_terminal)?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only kagebunshin's own files go, never through a symlink, and the
    /// directory stays if anything else is in it.
    #[test]
    fn removes_only_its_own_files() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("kagebunshin");
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(dir.join("projects")).unwrap();
        std::fs::create_dir_all(dir.join("session")).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("store.age"), "mine").unwrap();
        for f in [
            "store.age",
            "projects/widget.toml",
            "notes.txt",
            "session/key",
        ] {
            std::fs::write(dir.join(f), "x").unwrap();
        }
        std::os::unix::fs::symlink(outside.join("store.age"), dir.join("config.toml")).unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("projects/more.toml")).unwrap();
        let owns: Owns = Box::new(|n| match n {
            "projects" => Some(Kind::Dir(Box::new(|n| {
                #[expect(
                    clippy::case_sensitive_file_extension_comparisons,
                    reason = "mirrors the purge rule: only lowercase names are its own"
                )]
                n.ends_with(".toml").then_some(Kind::File)
            }))),
            // Not marked, so not its own.
            "session" => Some(Kind::Session),
            _ => files(vec!["store.age".into(), "config.toml".into()])(n),
        });
        assert!(!all_ours(&dir, &owns));
        let e = remove_ours(&dir, &owns).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::DirectoryNotEmpty);
        assert!(!dir.join("store.age").exists());
        assert!(!dir.join("projects/widget.toml").exists());
        for kept in [
            "notes.txt",
            "config.toml",
            "projects/more.toml",
            "session/key",
        ] {
            assert!(dir.join(kept).symlink_metadata().is_ok(), "{kept} is gone");
        }
        assert!(outside.join("store.age").exists());
    }
}
