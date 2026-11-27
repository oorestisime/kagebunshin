//! `app install|uninstall`: puts the app in the desktop's launcher and
//! starts it in the tray at login, on Linux; on macOS, makes it an app
//! there, `~/Applications/Kagebunshin.app` ([`write_bundle`]).
//!
//! Three files, each named for the app id its windows carry: a launcher
//! entry, a login entry that starts the app with `--hidden`, and the icon
//! both name. Like the service unit, the entries name the absolute path of
//! this binary and the socket the CLI resolves now: both run
//! `kagebunshin app`, so the app starts the same way from either as from a
//! terminal.
//!
//! Each file carries [`MARK`]. A file of the same name without it, or a
//! symlink, is someone else's: it is neither replaced nor removed.
//!
//! This is also where the app is started ([`start`]), so that
//! `kagebunshin app` returns to the prompt. Where the daemon is a systemd
//! user service, the app is made a unit beside it, [`APP_UNIT`]: the
//! service manager restarts it when it fails and keeps what it prints,
//! and `setup` and `uninstall` restart and stop it there. It is a
//! transient unit, made by `systemd-run` from the session that asks for
//! the app, since that session knows where the display is and the service
//! manager may not. Anywhere else the app is started in a session of its
//! own.

use std::ffi::OsString;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use super::{CliError, Exit, print_json, print_line, units};
use crate::ipc::paths;

/// The line that says a file is kagebunshin's to replace and remove.
const MARK: &str = "X-Kagebunshin-Managed=true";
const ICON: &str = include_str!("../../../../packaging/icons/kagebunshin.svg");

const LAUNCHER: &str = "launcher";
const LOGIN: &str = "login entry";

/// The app as macOS knows one: a folder with the binary, what says which
/// app it is, and its icon. Finder, Spotlight, Launchpad and the Dock show
/// only these.
const BUNDLE: &str = "Kagebunshin.app";
const ICNS: &[u8] = include_bytes!("../../../../packaging/icons/kagebunshin.icns");
const APP: &str = "app";

/// The app's unit, where the daemon is a systemd user service.
const APP_UNIT: &str = "kagebunshin-app.service";

/// What the app's unit is given of the session it is asked for in, when
/// set there: where the display and the session bus are, and what the
/// window is drawn with. The rest is the service manager's own
/// environment, as for the daemon.
const SESSION_ENV: [&str; 10] = [
    "WAYLAND_DISPLAY",
    "DISPLAY",
    "XAUTHORITY",
    "DBUS_SESSION_BUS_ADDRESS",
    "XDG_CURRENT_DESKTOP",
    "XDG_SESSION_TYPE",
    "XCURSOR_THEME",
    "XCURSOR_SIZE",
    "XDG_DATA_DIRS",
    "LANG",
];

/// How long a started app has to answer on its socket.
const START: Duration = Duration::from_secs(10);
/// How long an app that was told to end has to.
const END: Duration = Duration::from_secs(5);

/// One of the three files: written or removed, or with `reason`, left
/// alone.
#[derive(Debug, serde::Serialize)]
pub struct File {
    pub what: &'static str,
    pub path: PathBuf,
    /// Why it is left alone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
}

fn failed(message: String) -> CliError {
    CliError::new(Exit::Failure, "launcher", message)
}

/// Where the three files go: `$XDG_DATA_HOME/applications`,
/// `$XDG_CONFIG_HOME/autostart` and the user's `hicolor` icon theme.
pub(super) fn paths() -> Result<[(&'static str, PathBuf); 3], CliError> {
    let var = |k: &str| {
        std::env::var_os(k)
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
    };
    let dir = |xdg: &str, default: &str| {
        var(xdg)
            .or_else(|| var("HOME").map(|h| h.join(default)))
            .ok_or_else(|| failed("HOME is not set to an absolute path".into()))
    };
    let (data, config) = (
        dir("XDG_DATA_HOME", ".local/share")?,
        dir("XDG_CONFIG_HOME", ".config")?,
    );
    let id = units::LABEL;
    Ok([
        (LAUNCHER, data.join(format!("applications/{id}.desktop"))),
        (LOGIN, config.join(format!("autostart/{id}.desktop"))),
        (
            "icon",
            data.join(format!("icons/hicolor/scalable/apps/{id}.svg")),
        ),
    ])
}

/// The desktop entry that has `cli`, this binary, run the app on `socket`:
/// the launcher's, or with `login` the one that starts it in the tray.
pub fn entry(cli: &Path, socket: &Path, login: bool) -> Result<String, String> {
    // A quoted argument escapes `"`, `` ` ``, `$` and `\` with a backslash,
    // and a string value then doubles each backslash. `%` starts a field
    // code.
    let quote = |p: &Path| -> Result<String, String> {
        let s = p
            .to_str()
            .filter(|s| !s.chars().any(char::is_control))
            .ok_or_else(|| format!("{} cannot be written into a desktop entry", p.display()))?;
        let mut out = String::from("\"");
        for c in s.chars() {
            match c {
                '\\' => out.push_str(r"\\\\"),
                '"' | '`' | '$' => out.extend(['\\', '\\', c]),
                '%' => out.push_str("%%"),
                c => out.push(c),
            }
        }
        out.push('"');
        Ok(out)
    };
    let exec = format!("{} --socket {} app", quote(cli)?, quote(socket)?);
    let id = units::LABEL;
    let head = format!(
        "\
[Desktop Entry]
Type=Application
Name=Kagebunshin
Comment=Your projects' secrets: keys, approvals and the audit log
Icon={id}
Terminal=false
"
    );
    Ok(if login {
        format!(
            "\
{head}Exec={exec} --hidden
X-GNOME-Autostart-enabled=true
{MARK}
"
        )
    } else {
        format!(
            "\
{head}Exec={exec}
Categories=Utility;
StartupWMClass={id}
Actions=quit;
{MARK}

[Desktop Action quit]
Name=Quit Kagebunshin
Exec={exec} --quit
"
        )
    })
}

/// Where the app's bundle goes on macOS: the user's own Applications
/// folder, which needs no administrator and is searched like the system's.
pub(super) fn bundle_path() -> Result<PathBuf, CliError> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .map(|home| home.join("Applications").join(BUNDLE))
        .ok_or_else(|| failed("HOME is not set to an absolute path".into()))
}

/// The bundle's `Info.plist`: what macOS reads of an app before it runs.
/// It carries [`MARK`], as a comment.
fn info_plist() -> String {
    let (id, version) = (units::LABEL, env!("CARGO_PKG_VERSION"));
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- {MARK} -->
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key>
	<string>{id}</string>
	<key>CFBundleName</key>
	<string>Kagebunshin</string>
	<key>CFBundleDisplayName</key>
	<string>Kagebunshin</string>
	<key>CFBundleExecutable</key>
	<string>{}</string>
	<key>CFBundleIconFile</key>
	<string>kagebunshin</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>CFBundleShortVersionString</key>
	<string>{version}</string>
	<key>CFBundleVersion</key>
	<string>{version}</string>
	<key>LSMinimumSystemVersion</key>
	<string>11.0</string>
	<key>LSApplicationCategoryType</key>
	<string>public.app-category.developer-tools</string>
	<key>NSHighResolutionCapable</key>
	<true/>
</dict>
</plist>
"#,
        super::APP
    )
}

/// Whether the bundle at `bundle` is one kagebunshin wrote.
pub(super) fn bundle_managed(bundle: &Path) -> bool {
    bundle.symlink_metadata().is_ok_and(|m| m.is_dir())
        && managed(&bundle.join("Contents/Info.plist"))
}

/// Makes `bundle` the app whose binary is `app`, or brings it up to date,
/// and returns the binary in it: run from there, the window is that app's,
/// with its name and icon. The binary is a copy, written beside the old
/// one and renamed over it, so an app that runs keeps its file. One that
/// is as new as `app`, with this build's `Info.plist`, is left as it is.
/// A bundle kagebunshin did not write is not touched.
pub(super) fn write_bundle(bundle: &Path, app: &Path) -> Result<PathBuf, String> {
    let io = |what: &Path| {
        let what = what.display().to_string();
        move |e: std::io::Error| format!("cannot write {what}: {e}")
    };
    match bundle.symlink_metadata() {
        Err(_) => {}
        Ok(_) if bundle_managed(bundle) => {}
        Ok(_) => return Err(format!("{} is not kagebunshin's", bundle.display())),
    }
    let contents = bundle.join("Contents");
    let (plist, inner) = (
        contents.join("Info.plist"),
        contents.join("MacOS").join(super::APP),
    );
    let text = info_plist();
    let written = |p: &Path| p.metadata().and_then(|m| m.modified()).ok();
    let current = std::fs::read_to_string(&plist).is_ok_and(|t| t == text)
        && matches!((written(&inner), written(app)), (Some(copy), Some(of)) if copy >= of);
    if current {
        return Ok(inner);
    }
    let resources = contents.join("Resources");
    for dir in [&contents.join("MacOS"), &resources] {
        std::fs::create_dir_all(dir).map_err(io(dir))?;
    }
    // First what says the bundle is kagebunshin's: one left half written
    // is finished the next time.
    crate::atomic::write_private(&plist, text.as_bytes()).map_err(io(&plist))?;
    let new = inner.with_extension("new");
    std::fs::copy(app, &new).map_err(io(&new))?;
    std::fs::rename(&new, &inner).map_err(io(&inner))?;
    let icon = resources.join("kagebunshin.icns");
    std::fs::write(&icon, ICNS).map_err(io(&icon))?;
    // Not from a test, which writes its bundle where no app belongs.
    if cfg!(target_os = "macos") && !cfg!(test) {
        // Seals the bundle with the signature its binary already has the
        // kind of: one that names no developer. Without it the app still
        // runs; with it macOS knows the folder and the binary as one app.
        let quiet = |program: &str, args: &[&str]| {
            let _ = Command::new(program)
                .args(args)
                .arg(bundle)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        };
        quiet("codesign", &["--force", "--sign", "-"]);
        // Tells the launcher of it now, not when Finder next looks.
        quiet(
            "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister",
            &["-f"],
        );
    }
    Ok(inner)
}

/// For `setup` on macOS: makes the app found next to this binary or on
/// `PATH` an app there. None with no app installed; a failure warns.
pub(super) fn written_bundle() -> Option<File> {
    let app = super::find_app()?;
    let written = bundle_path()
        .map_err(|e| e.message)
        .and_then(|bundle| write_bundle(&bundle, &app).map(|_| bundle));
    match written {
        Ok(path) => Some(File {
            what: APP,
            path,
            reason: None,
        }),
        Err(why) => {
            super::error::warn(&why);
            None
        }
    }
}

/// Opens the app's window for the daemon on `socket`, as `kagebunshin app`
/// does, for a first `setup` on macOS: there is no tray for it to wait
/// in, and the agent's first import waits in the window. A failure warns.
pub(super) fn opened(socket: &Path) -> bool {
    let done = units::this_binary().ok().and_then(|cli| {
        Command::new(cli)
            .arg("--socket")
            .arg(socket)
            .arg("app")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .status()
            .ok()
    });
    let opened = done.is_some_and(|status| status.success());
    if !opened {
        super::error::warn("the app did not open; `kagebunshin app` opens it");
    }
    opened
}

/// For `setup` on macOS, where an app that runs is one with its window
/// open, on the build before this: ends it and opens this build's.
/// `false` when none runs; a failure warns.
pub(super) fn reopened(socket: &Path) -> bool {
    if !answers(socket) {
        return false;
    }
    stop(socket);
    let deadline = Instant::now() + END;
    while answers(socket) {
        if Instant::now() >= deadline {
            super::error::warn(
                "the app did not end, so it still runs the build it was started on: quit it, \
                 then `kagebunshin app`",
            );
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    opened(socket)
}

/// On macOS, the binary to start the app from: the one in its bundle, made
/// or brought up to date from `app` now. Where the bundle cannot be
/// written, `app` itself, with a warning: the window then has no icon.
pub(super) fn in_bundle(app: PathBuf) -> PathBuf {
    if !cfg!(target_os = "macos") {
        return app;
    }
    let written = bundle_path()
        .map_err(|e| e.message)
        .and_then(|bundle| write_bundle(&bundle, &app));
    match written {
        Ok(inner) => inner,
        Err(why) => {
            super::error::warn(&format!(
                "the app is started from {}, with no icon of its own: {why}",
                app.display()
            ));
            app
        }
    }
}

/// Whether `path` is a file kagebunshin wrote: a regular file, not a
/// symlink, that carries [`MARK`].
pub(super) fn managed(path: &Path) -> bool {
    path.symlink_metadata().is_ok_and(|m| m.is_file())
        && std::fs::read_to_string(path).is_ok_and(|text| text.contains(MARK))
}

/// Writes the three files for the app found next to this binary or on
/// `PATH`, leaving alone any that is not kagebunshin's.
pub(super) fn write(socket_arg: Option<PathBuf>) -> Result<Vec<File>, CliError> {
    // The entries run this binary, which is no use without the app.
    super::find_app().ok_or_else(super::no_app)?;
    let cli = units::this_binary()?;
    let socket = units::socket(socket_arg)?;
    // All three texts first: a path that cannot be written stops it before
    // any file is.
    let mut texts = Vec::new();
    for (what, path) in paths()? {
        let text = match what {
            LAUNCHER => entry(&cli, &socket, false).map_err(failed)?,
            LOGIN => entry(&cli, &socket, true).map_err(failed)?,
            // A comment after the root element.
            _ => format!("{ICON}<!-- {MARK} -->\n"),
        };
        texts.push((what, path, text));
    }
    let mut files = Vec::new();
    for (what, path, text) in texts {
        let reason = match path.symlink_metadata() {
            Err(_) => None,
            Ok(m) if m.file_type().is_symlink() => Some("is a symlink"),
            Ok(_) if managed(&path) => None,
            Ok(_) => Some("is not kagebunshin's"),
        };
        if reason.is_none() {
            #[expect(clippy::expect_used, reason = "each path is a file in a directory")]
            let dir = path.parent().expect("a file in a directory");
            std::fs::create_dir_all(dir)
                .map_err(|e| failed(format!("cannot create {}: {e}", dir.display())))?;
            crate::atomic::write_private(&path, text.as_bytes())
                .map_err(|e| failed(format!("cannot write {}: {e}", path.display())))?;
            if what == "icon" {
                refresh(&path);
            }
        }
        files.push(File { what, path, reason });
    }
    Ok(files)
}

/// Touches the icon theme's directory, which is how its users see that an
/// icon came or went.
fn refresh(icon: &Path) {
    // `hicolor`, above `scalable/apps/<icon>`.
    if let Some(theme) = icon.ancestors().nth(3) {
        let _ = std::fs::File::open(theme)
            .and_then(|dir| dir.set_modified(std::time::SystemTime::now()));
    }
}

/// Removes those of the three files that are kagebunshin's, and on macOS
/// the app's bundle if it is, and returns them.
fn remove() -> Result<Vec<File>, CliError> {
    let mut files = Vec::new();
    if cfg!(target_os = "macos") {
        let bundle = bundle_path()?;
        if bundle_managed(&bundle) {
            std::fs::remove_dir_all(&bundle)
                .map_err(|e| failed(format!("cannot remove {}: {e}", bundle.display())))?;
            files.push(File {
                what: APP,
                path: bundle,
                reason: None,
            });
        }
        return Ok(files);
    }
    for (what, path) in paths()? {
        if !managed(&path) {
            continue;
        }
        std::fs::remove_file(&path)
            .map_err(|e| failed(format!("cannot remove {}: {e}", path.display())))?;
        if what == "icon" {
            refresh(&path);
        }
        files.push(File {
            what,
            path,
            reason: None,
        });
    }
    Ok(files)
}

/// Whether an app answers for the daemon on `socket`.
pub(super) fn answers(socket: &Path) -> bool {
    UnixStream::connect(paths::socket_dir(socket).join(paths::APP_SOCKET_FILE)).is_ok()
}

/// What `systemd-run` is given to make the unit that runs `app` in the
/// tray, for the daemon on `socket`, with what `env` has of
/// [`SESSION_ENV`].
fn unit_args(
    app: &Path,
    socket: &Path,
    env: impl Fn(&str) -> Option<OsString>,
) -> Result<Vec<String>, String> {
    // Each word of the command is one argument, in which `$` starts a
    // variable and `$$` is a dollar.
    let word = |p: &Path| {
        p.to_str()
            .filter(|s| !s.chars().any(char::is_control))
            .map(|s| s.replace('$', "$$"))
            .ok_or_else(|| format!("{} cannot be written into a unit", p.display()))
    };
    let mut args: Vec<String> = [
        "--user",
        "--quiet",
        // Gone once it ends, however it ends, so it can be made again.
        "--collect",
        &format!("--unit={APP_UNIT}"),
        "--description=Kagebunshin, in the tray",
        "--property=Restart=on-failure",
        "--property=RestartSec=2",
        // A display that is gone fails it at once, each time.
        "--property=StartLimitIntervalSec=30",
        "--property=StartLimitBurst=5",
        "--property=PartOf=graphical-session.target",
    ]
    .map(String::from)
    .into();
    // Values are taken as they are; one that a unit cannot hold is left
    // to the service manager's own.
    args.extend(SESSION_ENV.iter().filter_map(|k| {
        let v = env(k)?.into_string().ok()?;
        (!v.is_empty() && !v.chars().any(char::is_control)).then(|| format!("--setenv={k}={v}"))
    }));
    args.extend(["--".into(), word(app)?, "--socket".into(), word(socket)?]);
    args.push("--hidden".into());
    Ok(args)
}

fn not_started(message: String) -> CliError {
    CliError::new(Exit::Failure, "app_not_started", message)
}

/// Waits until the app answers for the daemon on `socket`. A `child` that
/// ends first is an app that did not start; `see` is where it said why.
fn started(socket: &Path, mut child: Option<Child>, see: String) -> Result<(), CliError> {
    let deadline = Instant::now() + START;
    while !answers(socket) {
        let ended = (child.as_mut()).is_some_and(|c| !matches!(c.try_wait(), Ok(None)));
        if ended || Instant::now() >= deadline {
            return Err(not_started("the app did not start".into()).with_hint(see));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(())
}

/// Starts `app` in the tray, for the daemon on `socket`, and returns once
/// it answers there: as a unit of the service manager where the daemon is
/// one, else in a session of its own, which a Ctrl+C in this terminal and
/// the terminal closing do not reach.
pub(super) fn start(app: &Path, socket: &Path) -> Result<(), CliError> {
    let app = app
        .canonicalize()
        .map_err(|e| not_started(format!("cannot resolve {}: {e}", app.display())))?;
    if cfg!(target_os = "linux") && units::serves(socket) {
        let args = unit_args(&app, socket, |k| std::env::var_os(k)).map_err(not_started)?;
        units::manage("systemd-run", &args).map_err(not_started)?;
        return started(
            socket,
            None,
            format!("`journalctl --user -u {APP_UNIT}` has what it printed"),
        );
    }
    let mut cmd = Command::new(&app);
    cmd.arg("--socket")
        .arg(socket)
        .arg("--hidden")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    crate::sys::own_session(&mut cmd);
    let child = cmd
        .spawn()
        .map_err(|e| not_started(format!("cannot start {}: {e}", app.display())))?;
    let see = format!(
        "`{} --socket {}` prints why",
        app.display(),
        socket.display()
    );
    started(socket, Some(child), see)
}

/// Tells the app that runs for the daemon on `socket` to end. Its answer
/// does not matter: it may not be running.
fn quit(app: &Path, socket: &Path) {
    let _ = Command::new(app)
        .arg("--socket")
        .arg(socket)
        .arg("--quit")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn systemctl(verb: &str) -> Result<(), String> {
    units::manage("systemctl", &["--user", verb, APP_UNIT])
}

/// Ends the app for the daemon on `socket`: through the service manager
/// where it is a unit, and told to where it is not. Neither answer
/// matters.
pub(super) fn stop(socket: &Path) {
    if cfg!(target_os = "linux") {
        let _ = systemctl("stop");
    }
    if answers(socket)
        && let Some(app) = super::find_app()
    {
        quit(&app, socket);
    }
}

/// Has an app that runs for the daemon on `socket` run this build's
/// binary: restarted as the unit it is, or, started some other way, told
/// to end and started as [`start`] does. `false` when none runs.
pub(super) fn restart(socket: &Path) -> Result<bool, CliError> {
    if !answers(socket) {
        return Ok(false);
    }
    let app = super::find_app().ok_or_else(super::no_app)?;
    if cfg!(target_os = "linux") && units::serves(socket) && systemctl("is-active").is_ok() {
        systemctl("restart").map_err(not_started)?;
        let see = format!("`journalctl --user -u {APP_UNIT}` has what it printed");
        return started(socket, None, see).map(|()| true);
    }
    quit(&app, socket);
    let deadline = Instant::now() + END;
    while answers(socket) {
        if Instant::now() >= deadline {
            return Err(not_started(
                "the app in the tray did not end, so it still runs the build it was started on"
                    .into(),
            )
            .with_hint("quit it from the tray, then `kagebunshin app --hidden`"));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    start(&app, socket).map(|()| true)
}

/// For `setup` and `app install`, where the files are written by now: a
/// failure warns.
fn or_warn(done: Result<bool, CliError>) -> bool {
    done.unwrap_or_else(|e| {
        super::error::warn(&match &e.hint {
            Some(hint) => format!("{}: {hint}", e.message),
            None => e.message.clone(),
        });
        false
    })
}

/// [`restart`], where a failure warns.
pub(super) fn restarted(socket: &Path) -> bool {
    or_warn(restart(socket))
}

/// Starts the app in the tray for the daemon on `socket`, for a first
/// `setup`: the agent's first import waits there for approval. Only where
/// this session has a display, as an app with none ends at once, and not
/// where one answers already. A failure warns.
pub(super) fn started_first(socket: &Path) -> bool {
    let display = ["WAYLAND_DISPLAY", "DISPLAY"]
        .iter()
        .any(|k| std::env::var_os(k).is_some_and(|v| !v.is_empty()));
    if !display || answers(socket) {
        return false;
    }
    let Some(app) = super::find_app() else {
        return false;
    };
    or_warn(start(&app, socket).map(|()| true))
}

/// `app install`.
pub fn install(json: bool, socket: Option<PathBuf>) -> Result<(), CliError> {
    if cfg!(target_os = "macos") {
        let app = super::find_app().ok_or_else(super::no_app)?;
        let bundle = bundle_path()?;
        write_bundle(&bundle, &app).map_err(failed)?;
        if json {
            let file = File {
                what: APP,
                path: bundle,
                reason: None,
            };
            return print_json(&serde_json::json!({ "files": [file], "restarted": false }));
        }
        return print_line(&format!(
            "wrote {}: open it from Spotlight or Launchpad, or with `kagebunshin app`",
            bundle.display()
        ));
    }
    if !cfg!(target_os = "linux") {
        return Err(failed(
            "the launcher and login entries are for Linux desktops".into(),
        ));
    }
    let files = write(socket.clone())?;
    let restarted = restarted(&units::socket(socket)?);
    if json {
        return print_json(&serde_json::json!({ "files": files, "restarted": restarted }));
    }
    for f in &files {
        let path = f.path.display();
        print_line(&match f.reason {
            None => format!("wrote {path}"),
            Some(why) => format!("left alone {path} ({why})"),
        })?;
    }
    print_line(if restarted {
        "restarted the app: it is in the tray, and starts there at login"
    } else {
        "the app starts in the tray at login; to start it now: kagebunshin app --hidden"
    })
}

/// `app uninstall`.
pub fn uninstall(json: bool) -> Result<(), CliError> {
    let files = remove()?;
    if json {
        return print_json(&serde_json::json!({ "files": files }));
    }
    if files.is_empty() {
        return print_line(if cfg!(target_os = "macos") {
            "not installed: no Kagebunshin.app of kagebunshin's in ~/Applications"
        } else {
            "not installed: no launcher or login entry of kagebunshin's"
        });
    }
    for f in &files {
        print_line(&format!("removed {}", f.path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_name_the_cli_and_the_socket() {
        let (cli, socket) = (
            Path::new("/home/someone/.local/bin/kagebunshin"),
            Path::new("/run/user/1000/kagebunshin/kagebunshind.sock"),
        );
        insta::assert_snapshot!("launcher", entry(cli, socket, false).unwrap());
        insta::assert_snapshot!("login_entry", entry(cli, socket, true).unwrap());
    }

    /// On macOS the app is a bundle in ~/Applications: the binary, what
    /// says which app it is, and its icon. It is written once, kept up to
    /// date with the binary, and never over a bundle that is someone
    /// else's.
    #[test]
    fn the_bundle_is_the_app_as_macos_knows_one() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let app = tmp.path().join("bin/kagebunshin-app");
        std::fs::create_dir_all(app.parent().unwrap()).unwrap();
        std::fs::write(&app, "one").unwrap();
        std::fs::set_permissions(&app, std::fs::Permissions::from_mode(0o755)).unwrap();
        let bundle = tmp.path().join("Applications/Kagebunshin.app");
        assert!(!bundle_managed(&bundle));

        let inner = write_bundle(&bundle, &app).unwrap();
        assert_eq!(inner, bundle.join("Contents/MacOS/kagebunshin-app"));
        assert_eq!(std::fs::read_to_string(&inner).unwrap(), "one");
        assert_eq!(
            inner.metadata().unwrap().permissions().mode() & 0o777,
            0o755
        );
        let plist = std::fs::read_to_string(bundle.join("Contents/Info.plist")).unwrap();
        for has in [
            "<string>kagebunshin-app</string>",
            "<string>io.github.oorestisime.kagebunshin</string>",
            "<string>kagebunshin</string>",
            concat!("<string>", env!("CARGO_PKG_VERSION"), "</string>"),
            MARK,
        ] {
            assert!(plist.contains(has), "{has}: {plist}");
        }
        let icon = std::fs::read(bundle.join("Contents/Resources/kagebunshin.icns")).unwrap();
        assert_eq!(&icon[..4], b"icns");
        assert_eq!(
            u32::from_be_bytes([icon[4], icon[5], icon[6], icon[7]]) as usize,
            icon.len()
        );
        assert!(bundle_managed(&bundle));

        // As new as the binary: left as it is.
        std::fs::write(&inner, "kept").unwrap();
        write_bundle(&bundle, &app).unwrap();
        assert_eq!(std::fs::read_to_string(&inner).unwrap(), "kept");
        // An upgrade put a newer binary there: it is copied.
        std::fs::write(&app, "two").unwrap();
        let later = std::time::SystemTime::now() + Duration::from_secs(60);
        std::fs::File::options()
            .write(true)
            .open(&app)
            .unwrap()
            .set_modified(later)
            .unwrap();
        write_bundle(&bundle, &app).unwrap();
        assert_eq!(std::fs::read_to_string(&inner).unwrap(), "two");

        // Someone else's app of that name, or a file there, is not touched.
        let other = tmp.path().join("Other/Kagebunshin.app");
        std::fs::create_dir_all(other.join("Contents")).unwrap();
        std::fs::write(other.join("Contents/Info.plist"), "<plist/>").unwrap();
        let e = write_bundle(&other, &app).unwrap_err();
        assert!(e.ends_with("Kagebunshin.app is not kagebunshin's"), "{e}");
        assert!(!other.join("Contents/MacOS").exists());
        assert!(!bundle_managed(&other));
        let file = tmp.path().join("Kagebunshin.app");
        std::fs::write(&file, "").unwrap();
        assert!(write_bundle(&file, &app).is_err());
    }

    /// The unit runs the app in the tray, with what the session has of the
    /// display. A dollar in a path stays one; a value a unit cannot hold,
    /// or an empty one, is not passed.
    #[test]
    fn the_unit_is_given_the_session_and_runs_the_app_hidden() {
        let env = |k: &str| match k {
            "WAYLAND_DISPLAY" => Some("wayland-1".into()),
            "DISPLAY" => Some(String::new().into()),
            "XDG_CURRENT_DESKTOP" => Some("a$b %c".into()),
            "LANG" => Some("x\ny".into()),
            "HOME" => Some("/home/someone".into()),
            _ => None,
        };
        let args = unit_args(
            Path::new("/opt/a b/$x/kagebunshin-app"),
            Path::new("/run/s.sock"),
            env,
        )
        .unwrap();
        assert_eq!(
            args,
            [
                "--user",
                "--quiet",
                "--collect",
                "--unit=kagebunshin-app.service",
                "--description=Kagebunshin, in the tray",
                "--property=Restart=on-failure",
                "--property=RestartSec=2",
                "--property=StartLimitIntervalSec=30",
                "--property=StartLimitBurst=5",
                "--property=PartOf=graphical-session.target",
                "--setenv=WAYLAND_DISPLAY=wayland-1",
                "--setenv=XDG_CURRENT_DESKTOP=a$b %c",
                "--",
                "/opt/a b/$$x/kagebunshin-app",
                "--socket",
                "/run/s.sock",
                "--hidden",
            ]
        );
        assert!(unit_args(Path::new("/opt/a\nb/app"), Path::new("/run/s.sock"), env).is_err());
    }

    /// What a desktop entry would expand or split is escaped; what it
    /// cannot hold is refused.
    #[test]
    fn exec_paths_are_quoted() {
        let socket = Path::new("/run/s.sock");
        let text = entry(Path::new(r#"/opt/a b/$x`y"z\w%f/app"#), socket, true).unwrap();
        let exec = text.lines().find(|l| l.starts_with("Exec=")).unwrap();
        assert_eq!(
            exec,
            r#"Exec="/opt/a b/\\$x\\`y\\"z\\\\w%%f/app" --socket "/run/s.sock" app --hidden"#
        );
        assert!(entry(Path::new("/opt/a\nb/app"), socket, false).is_err());
    }

    /// The icon stays well-formed with the mark after it.
    #[test]
    fn the_icon_carries_the_mark() {
        assert!(ICON.trim_end().ends_with("</svg>"));
        assert!(!ICON.contains(MARK));
    }

    #[test]
    fn only_marked_regular_files_are_managed() {
        let tmp = tempfile::tempdir().unwrap();
        let (ours, theirs, link) = (
            tmp.path().join("ours.desktop"),
            tmp.path().join("theirs.desktop"),
            tmp.path().join("link.desktop"),
        );
        std::fs::write(&ours, format!("[Desktop Entry]\n{MARK}\n")).unwrap();
        std::fs::write(&theirs, "[Desktop Entry]\nName=Kagebunshin\n").unwrap();
        std::os::unix::fs::symlink(&ours, &link).unwrap();
        assert!(managed(&ours));
        assert!(!managed(&theirs));
        assert!(!managed(&link));
        assert!(!managed(&tmp.path().join("missing.desktop")));
    }
}
