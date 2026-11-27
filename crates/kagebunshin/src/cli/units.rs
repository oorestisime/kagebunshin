//! `daemon install|uninstall|status`: runs the daemon as a systemd user
//! service on Linux, or a launchd agent on macOS.
//!
//! The unit names the absolute path of this binary and the socket the CLI
//! resolves now, so the daemon listens where later commands look. The
//! daemon starts locked, as it always does: a restart is a lock.
//!
//! A service gets neither the shell's `PATH` nor its `AWS_*` variables, so
//! the AWS file locations set at install time ([`PASSED_ENV`]) are written
//! into the unit.

use std::path::{Path, PathBuf};
use std::process::Command;

use super::{CliError, Exit, connect, print_json, print_line};
use crate::ipc::paths;
use crate::ipc::protocol::{Request, Response};

// Both generators build on both systems, so both golden tests run in CI.

/// The launchd label.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub const LABEL: &str = "io.github.oorestisime.kagebunshin";
#[cfg(target_os = "linux")]
const UNIT: &str = "kagebunshin.service";

/// Variables copied into the unit when set: where the AWS configuration
/// lives. Only paths; never credentials.
pub const PASSED_ENV: [&str; 2] = ["AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"];

/// [`PASSED_ENV`] as set in this process, non-empty ones only.
fn passed_env() -> Vec<(&'static str, PathBuf)> {
    PASSED_ENV
        .iter()
        .filter_map(|&k| {
            let v = std::env::var_os(k).filter(|v| !v.is_empty())?;
            Some((k, PathBuf::from(v)))
        })
        .collect()
}

fn failed(message: String) -> CliError {
    CliError::new(Exit::Failure, "service", message)
}

/// Where the unit file goes: `$XDG_CONFIG_HOME/systemd/user/`, or
/// `~/Library/LaunchAgents/`.
pub(super) fn unit_path() -> Result<PathBuf, CliError> {
    let home = || {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .ok_or_else(|| failed("HOME is not set to an absolute path".into()))
    };
    #[cfg(target_os = "linux")]
    {
        let config = match std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from) {
            Some(p) if p.is_absolute() => p,
            _ => home()?.join(".config"),
        };
        Ok(config.join("systemd/user").join(UNIT))
    }
    #[cfg(target_os = "macos")]
    {
        Ok(home()?.join(format!("Library/LaunchAgents/{LABEL}.plist")))
    }
}

/// `p` as one quoted word of a unit. ExecStart is split like a shell line,
/// then `%` specifiers and `$` variables are expanded; Environment=
/// expands specifiers only, so there `dollars` stay as they are.
fn quote_as(p: &Path, dollars: bool) -> Result<String, String> {
    let s = p
        .to_str()
        .filter(|s| !s.chars().any(char::is_control))
        .ok_or_else(|| format!("{} cannot be written into a unit", p.display()))?;
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '\\' | '"' => out.extend(['\\', c]),
            '%' => out.push_str("%%"),
            '$' if dollars => out.push_str("$$"),
            c => out.push(c),
        }
    }
    out.push('"');
    Ok(out)
}

/// What a unit's ExecStart ends with when its daemon listens on `socket`.
fn listens_on(socket: &Path) -> Result<String, String> {
    Ok(format!(" --socket {} daemon run", quote_as(socket, true)?))
}

/// Whether the daemon is a systemd user service on `socket`: its unit is
/// written, for that socket. The app is then a unit too; see
/// `desktop::start`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(super) fn serves(socket: &Path) -> bool {
    let Ok(tail) = listens_on(socket) else {
        return false;
    };
    unit_path()
        .and_then(|path| std::fs::read_to_string(path).map_err(|e| failed(e.to_string())))
        .is_ok_and(|unit| (unit.lines()).any(|l| l.starts_with("ExecStart=") && l.ends_with(&tail)))
}

/// The systemd user unit that runs `exe`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn systemd_unit(exe: &Path, socket: &Path, env: &[(&str, PathBuf)]) -> Result<String, String> {
    let quote = |p: &Path| quote_as(p, true);
    let mut environment = String::new();
    for (k, v) in env {
        // `Environment="K=V"`: the whole assignment is one quoted word.
        let quoted = quote_as(&PathBuf::from(format!("{k}={}", v.display())), false)?;
        environment.push_str(&format!("Environment={quoted}\n"));
    }
    Ok(format!(
        "\
# Written by `kagebunshin daemon install`; `kagebunshin daemon uninstall` removes it.
[Unit]
Description=kagebunshin daemon: hands secrets to the commands it runs
Documentation=https://github.com/oorestisime/kagebunshin

[Service]
{environment}ExecStart={}{}
Restart=on-failure
RestartSec=2
# The daemon also turns core dumps off itself.
LimitCORE=0
NoNewPrivileges=yes
UMask=0077

[Install]
WantedBy=default.target
",
        quote(exe)?,
        listens_on(socket)?
    ))
}

/// The launchd agent that runs `exe`, logging to `log`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn launchd_plist(
    exe: &Path,
    socket: &Path,
    log: &Path,
    env: &[(&str, PathBuf)],
) -> Result<String, String> {
    let string = |p: &Path| -> Result<String, String> {
        let s = p
            .to_str()
            .filter(|s| !s.chars().any(char::is_control))
            .ok_or_else(|| format!("{} cannot be written into a plist", p.display()))?;
        let escaped = s
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");
        Ok(format!("<string>{escaped}</string>"))
    };
    let mut environment = String::new();
    if !env.is_empty() {
        environment.push_str("\t<key>EnvironmentVariables</key>\n\t<dict>\n");
        for (k, v) in env {
            environment.push_str(&format!("\t\t<key>{k}</key>\n\t\t{}\n", string(v)?));
        }
        environment.push_str("\t</dict>\n");
    }
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- Written by `kagebunshin daemon install`; `kagebunshin daemon uninstall` removes it. -->
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{LABEL}</string>
	<key>ProgramArguments</key>
	<array>
		{}
		<string>--socket</string>
		{}
		<string>daemon</string>
		<string>run</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>SoftResourceLimits</key>
	<dict>
		<key>Core</key>
		<integer>0</integer>
	</dict>
	<key>HardResourceLimits</key>
	<dict>
		<key>Core</key>
		<integer>0</integer>
	</dict>
	<key>Umask</key>
	<integer>63</integer>
	<key>StandardErrorPath</key>
	{}
{environment}</dict>
</plist>
"#,
        string(exe)?,
        string(socket)?,
        string(log)?
    ))
}

pub(super) fn socket(socket: Option<PathBuf>) -> Result<PathBuf, CliError> {
    let usage = |e: paths::PathError| CliError::new(Exit::Usage, "usage", e.to_string());
    match socket {
        Some(p) => paths::check_socket_path(&p).map_err(usage).map(|()| p),
        None => paths::default_socket_path().map_err(usage),
    }
}

pub(super) fn this_binary() -> Result<PathBuf, CliError> {
    std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .map_err(|e| failed(format!("cannot find this binary's path: {e}")))
}

/// The unit `install` writes at `path`.
fn unit_text(path: &Path, exe: &Path, socket: &Path) -> Result<String, CliError> {
    #[cfg(target_os = "linux")]
    let text = {
        let _ = path;
        systemd_unit(exe, socket, &passed_env())
    };
    #[cfg(target_os = "macos")]
    let text = launchd_plist(
        exe,
        socket,
        &log_dir(path).join("daemon.log"),
        &passed_env(),
    );
    text.map_err(failed)
}

/// `~/Library/Logs/kagebunshin`, next to `~/Library/LaunchAgents`.
#[cfg(target_os = "macos")]
pub(super) fn log_dir(plist: &Path) -> PathBuf {
    #[expect(
        clippy::expect_used,
        reason = "the plist path is ~/Library/LaunchAgents/<name>.plist"
    )]
    let library = plist.ancestors().nth(2).expect("under ~/Library");
    library.join("Logs/kagebunshin")
}

/// Runs a service manager command, returning its error output on failure.
pub(super) fn manage<S: AsRef<std::ffi::OsStr>>(program: &str, args: &[S]) -> Result<(), String> {
    let out = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("cannot run {program}: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&out.stderr);
    // launchctl's advice for every failure, and wrong for a user's own
    // service, which root cannot load.
    let err: Vec<&str> = (err.lines())
        .filter(|l| !l.starts_with("Try re-running the command as root"))
        .collect();
    let err = err.join("\n");
    let args: Vec<_> = (args.iter())
        .map(|a| a.as_ref().to_string_lossy())
        .collect();
    Err(format!(
        "`{program} {}` failed: {}",
        args.join(" "),
        err.trim()
    ))
}

#[cfg(target_os = "macos")]
fn domain() -> String {
    format!("gui/{}", crate::sys::effective_uid())
}

/// The unit `daemon install` wrote, for this binary and socket.
pub struct Installed {
    pub unit: PathBuf,
    pub binary: PathBuf,
    pub socket: PathBuf,
}

/// `daemon install`. With `files_only`, writes the unit without loading it.
pub fn install(json: bool, socket_arg: Option<PathBuf>, files_only: bool) -> Result<(), CliError> {
    let Installed {
        unit: path,
        binary: exe,
        socket,
    } = write_unit(socket_arg, !files_only)?;
    if json {
        return print_json(&serde_json::json!({
            "unit": path,
            "binary": exe,
            "socket": socket,
            "started": !files_only,
        }));
    }
    print_line(&format!("wrote {}", path.display()))?;
    if files_only {
        print_line("not started: --files-only")
    } else {
        print_line("started the daemon, locked; run `kagebunshin unlock`")
    }
}

/// Writes the unit for this binary and socket, and with `start` starts it,
/// restarting it if it runs.
pub fn write_unit(socket_arg: Option<PathBuf>, start: bool) -> Result<Installed, CliError> {
    let exe = this_binary()?;
    let socket = socket(socket_arg)?;
    let path = unit_path()?;
    let text = unit_text(&path, &exe, &socket)?;
    #[cfg(target_os = "macos")]
    {
        let logs = log_dir(&path);
        std::fs::create_dir_all(&logs)
            .map_err(|e| failed(format!("cannot create {}: {e}", logs.display())))?;
    }
    #[expect(clippy::expect_used, reason = "a unit file path always has a parent")]
    let dir = path.parent().expect("a file in a directory");
    std::fs::create_dir_all(dir)
        .map_err(|e| failed(format!("cannot create {}: {e}", dir.display())))?;
    crate::atomic::write_private(&path, text.as_bytes())
        .map_err(|e| failed(format!("cannot write {}: {e}", path.display())))?;
    if start {
        load(&path).map_err(|e| {
            failed(e).with_hint(format!(
                "{} is written, but the service manager did not start it: run this command \
                 again",
                path.display()
            ))
        })?;
    }
    Ok(Installed {
        unit: path,
        binary: exe,
        socket,
    })
}

/// Starts the unit at `path`, restarting it if it runs: a reinstall may
/// point at a new binary.
fn load(path: &Path) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        let _ = path;
        manage("systemctl", &["--user", "daemon-reload"])?;
        manage("systemctl", &["--user", "enable", UNIT])?;
        manage("systemctl", &["--user", "restart", UNIT])
    }
    #[cfg(target_os = "macos")]
    {
        let plist = path.to_str().ok_or("the plist path is not UTF-8")?;
        reload(
            |args| manage("launchctl", args),
            std::thread::sleep,
            &domain(),
            plist,
        )
    }
}

/// Has launchd run the service of `plist` in `domain`, in place of one it
/// runs now. `bootout` returns while the old one is still ending, and a
/// `bootstrap` then fails (5, input/output error) and leaves no service
/// at all: so the old one is waited for, until `print` no longer finds
/// it, and the bootstrap is tried again while it fails.
#[cfg(any(test, target_os = "macos"))]
fn reload(
    mut launchctl: impl FnMut(&[&str]) -> Result<(), String>,
    mut wait: impl FnMut(std::time::Duration),
    domain: &str,
    plist: &str,
) -> Result<(), String> {
    use std::time::Duration;
    let service = format!("{domain}/{LABEL}");
    // Not loaded is fine.
    let _ = launchctl(&["bootout", &service]);
    for _ in 0..50 {
        if launchctl(&["print", &service]).is_err() {
            break;
        }
        wait(Duration::from_millis(100));
    }
    let mut again = 5;
    loop {
        match launchctl(&["bootstrap", domain, plist]) {
            Ok(()) => return Ok(()),
            Err(e) if again == 0 => return Err(e),
            Err(_) => {
                again -= 1;
                wait(Duration::from_millis(500));
            }
        }
    }
}

/// `daemon uninstall`. With `files_only`, removes the unit without
/// stopping it.
pub fn uninstall(json: bool, files_only: bool) -> Result<(), CliError> {
    let (path, removed, warnings) = remove_unit(files_only)?;
    if json {
        return print_json(&serde_json::json!({
            "unit": path,
            "removed": removed,
            "warnings": warnings,
        }));
    }
    for w in &warnings {
        eprintln!("warning: {w}");
    }
    if removed {
        print_line(&format!("removed {}", path.display()))
    } else {
        print_line(&format!("not installed: no {}", path.display()))
    }
}

/// Stops the service (unless `files_only`) and removes its unit. Returns
/// the unit's path, whether it was there, and what the service manager
/// said when it failed.
pub(super) fn remove_unit(files_only: bool) -> Result<(PathBuf, bool, Vec<String>), CliError> {
    let path = unit_path()?;
    let mut warnings = Vec::new();
    if !files_only {
        #[cfg(target_os = "linux")]
        let stopped = manage("systemctl", &["--user", "disable", "--now", UNIT]);
        #[cfg(target_os = "macos")]
        let stopped = manage("launchctl", &["bootout", &format!("{}/{LABEL}", domain())]);
        if let Err(e) = stopped {
            warnings.push(e);
        }
    }
    let removed = match std::fs::remove_file(&path) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(failed(format!("cannot remove {}: {e}", path.display()))),
    };
    #[cfg(target_os = "linux")]
    if removed
        && !files_only
        && let Err(e) = manage("systemctl", &["--user", "daemon-reload"])
    {
        warnings.push(e);
    }
    Ok((path, removed, warnings))
}

/// `daemon status`: whether the unit is written, whether it runs this
/// binary, and whether the daemon answers. Asks no service manager.
pub fn status(json: bool, socket_arg: Option<PathBuf>) -> Result<(), CliError> {
    let path = unit_path()?;
    let written = std::fs::read_to_string(&path).ok();
    // Whether it is the unit `install` would write now.
    let current = written.as_ref().map(|text| {
        let socket = socket(socket_arg.clone());
        this_binary()
            .and_then(|exe| unit_text(&path, &exe, &socket?))
            .is_ok_and(|expected| &expected == text)
    });
    let answering = connect(socket_arg)
        .ok()
        .and_then(|mut c| c.request(Request::Ping).ok())
        .is_some_and(|r| matches!(r, Response::Pong));
    if json {
        return print_json(&serde_json::json!({
            "unit": path,
            "installed": written.is_some(),
            "current": current,
            "answering": answering,
        }));
    }
    match current {
        None => print_line(&format!("not installed: no {}", path.display()))?,
        Some(true) => print_line(&format!("installed: {}", path.display()))?,
        Some(false) => print_line(&format!(
            "installed: {}, but for another binary or socket; run `kagebunshin daemon install` again",
            path.display()
        ))?,
    }
    print_line(if answering {
        "daemon: answering"
    } else {
        "daemon: not answering"
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// launchd is given the new service only once the old one is gone,
    /// and again if it still refuses: an upgrade replaces a daemon that
    /// runs, and must not end with none.
    #[test]
    fn a_running_service_is_waited_for_before_the_new_one_is_loaded() {
        let run = |print_finds: usize, bootstrap_fails: usize| {
            let (mut prints, mut failures) = (print_finds, bootstrap_fails);
            let calls = std::cell::RefCell::new(Vec::new());
            let waited = std::cell::Cell::new(std::time::Duration::ZERO);
            let done = reload(
                |args| {
                    calls.borrow_mut().push(args.join(" "));
                    match args[0] {
                        "print" if prints > 0 => {
                            prints -= 1;
                            Ok(())
                        }
                        "print" => Err("Could not find service".into()),
                        "bootstrap" if failures > 0 => {
                            failures -= 1;
                            Err("Bootstrap failed: 5: Input/output error".into())
                        }
                        _ => Ok(()),
                    }
                },
                |d| waited.set(waited.get() + d),
                "gui/501",
                "/h/a.plist",
            );
            (done, calls.into_inner(), waited.get())
        };
        let service = format!("gui/501/{LABEL}");
        let (bootout, print) = (format!("bootout {service}"), format!("print {service}"));
        let (bootout, print, bootstrap) = (
            bootout.as_str(),
            print.as_str(),
            "bootstrap gui/501 /h/a.plist",
        );

        // Nothing was loaded: no waiting.
        let (done, calls, waited) = run(0, 0);
        assert_eq!(done, Ok(()));
        assert_eq!(calls, [bootout, print, bootstrap]);
        assert_eq!(waited, std::time::Duration::ZERO);

        // The old one takes a moment to go, and the first load still fails.
        let (done, calls, waited) = run(2, 1);
        assert_eq!(done, Ok(()));
        assert_eq!(calls, [bootout, print, print, print, bootstrap, bootstrap]);
        assert_eq!(waited, std::time::Duration::from_millis(700));

        // A load that keeps failing is given up on, with what launchd said.
        let (done, calls, _) = run(0, 99);
        assert_eq!(done, Err("Bootstrap failed: 5: Input/output error".into()));
        assert_eq!(calls.iter().filter(|c| *c == bootstrap).count(), 6);
        // One that never goes is not waited for without end.
        let (done, calls, _) = run(999, 0);
        assert_eq!(done, Ok(()));
        assert_eq!(calls.iter().filter(|c| *c == print).count(), 50);
    }

    #[test]
    fn systemd_unit_golden() {
        let unit = systemd_unit(
            Path::new("/home/o/.cargo/bin/kagebunshin"),
            Path::new("/run/user/1000/kagebunshin/kagebunshind.sock"),
            &[],
        )
        .unwrap();
        insta::assert_snapshot!("systemd_unit", unit);
    }

    #[test]
    fn systemd_unit_quotes_what_systemd_expands() {
        let unit = systemd_unit(
            Path::new("/opt/my apps/100%/$HOME/\"kb\"\\bin"),
            Path::new("/tmp/s.sock"),
            &[],
        )
        .unwrap();
        let exec = unit.lines().find(|l| l.starts_with("ExecStart=")).unwrap();
        assert_eq!(
            exec,
            r#"ExecStart="/opt/my apps/100%%/$$HOME/\"kb\"\\bin" --socket "/tmp/s.sock" daemon run"#
        );
        assert!(systemd_unit(Path::new("/a\nb"), Path::new("/s"), &[]).is_err());
    }

    #[test]
    fn units_carry_the_aws_file_locations() {
        let env = [
            ("AWS_CONFIG_FILE", PathBuf::from("/home/o/aws dir/config")),
            (
                "AWS_SHARED_CREDENTIALS_FILE",
                PathBuf::from("/home/o/100%/$x"),
            ),
        ];
        let unit = systemd_unit(Path::new("/bin/kb"), Path::new("/s"), &env).unwrap();
        assert!(
            unit.contains("Environment=\"AWS_CONFIG_FILE=/home/o/aws dir/config\"\n"),
            "{unit}"
        );
        assert!(
            unit.contains("Environment=\"AWS_SHARED_CREDENTIALS_FILE=/home/o/100%%/$x\"\n"),
            "{unit}"
        );
        let plist =
            launchd_plist(Path::new("/bin/kb"), Path::new("/s"), Path::new("/l"), &env).unwrap();
        assert!(
            plist.contains(
                "<key>EnvironmentVariables</key>\n\t<dict>\n\t\t<key>AWS_CONFIG_FILE</key>\n\t\t<string>/home/o/aws dir/config</string>\n"
            ),
            "{plist}"
        );
    }

    #[test]
    fn the_not_running_hint_names_this_service() {
        let hint = super::super::error::start_daemon_hint();
        #[cfg(target_os = "linux")]
        assert!(hint.contains(UNIT.trim_end_matches(".service")), "{hint}");
        #[cfg(target_os = "macos")]
        assert!(hint.contains(LABEL), "{hint}");
    }

    #[test]
    fn launchd_plist_golden() {
        let plist = launchd_plist(
            Path::new("/Users/o/.cargo/bin/kagebunshin"),
            Path::new("/var/folders/xy/T/kagebunshin/kagebunshind.sock"),
            Path::new("/Users/o/Library/Logs/kagebunshin/daemon.log"),
            &[],
        )
        .unwrap();
        insta::assert_snapshot!("launchd_plist", plist);
        let odd =
            launchd_plist(Path::new("/a&<b>"), Path::new("/s"), Path::new("/l"), &[]).unwrap();
        assert!(odd.contains("<string>/a&amp;&lt;b&gt;</string>"));
    }
}
