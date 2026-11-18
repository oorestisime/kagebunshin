//! `kagebunshin app`, and what restarts and stops the app, in a throwaway
//! HOME: the app, `systemd-run` and `systemctl` are fakes that log, so no
//! window opens and the real user's units are never touched. The test
//! itself stands in for a running app, by listening on its socket.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test code")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{Duration, Instant};

struct World {
    tmp: tempfile::TempDir,
}

impl World {
    /// The CLI beside a fake app that logs how it was run, and ends with
    /// `app` after that.
    fn new(app: &str) -> Self {
        let w = World {
            tmp: tempfile::tempdir().unwrap(),
        };
        fs::create_dir_all(w.path("bin")).unwrap();
        fs::create_dir_all(w.path("run/kagebunshin")).unwrap();
        fs::set_permissions(w.path("run/kagebunshin"), fs::Permissions::from_mode(0o700)).unwrap();
        // Its own copy, so the app it finds next to itself is the fake.
        fs::copy(env!("CARGO_BIN_EXE_kagebunshin"), w.path("bin/kagebunshin")).unwrap();
        let root = w.root();
        let root = root.display();
        // A session leader's id is its session's.
        w.fake(
            "kagebunshin-app",
            &format!(
                "read -r pid _ _ _ _ sid _ < /proc/$$/stat\n\
                 [ \"$pid\" = \"$sid\" ] && own=own || own=shared\n\
                 echo \"$own session: $*\" >> '{root}/app.log'\n\
                 case \" $* \" in *' --quit '*) echo asked > '{root}/quit' ;; esac\n\
                 {app}\n"
            ),
        );
        w.fake(
            "systemd-run",
            &format!("echo \"systemd-run $*\" >> '{root}/service.log'\n"),
        );
        // The app's unit is active once the test says so.
        w.fake(
            "systemctl",
            &format!(
                "echo \"systemctl $*\" >> '{root}/service.log'\n\
                 [ \"$2\" != is-active ] || [ -e '{root}/active' ] || exit 3\n"
            ),
        );
        w
    }

    fn fake(&self, name: &str, body: &str) {
        let p = self.path(&format!("bin/{name}"));
        fs::write(&p, format!("#!/bin/sh\n{body}")).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn root(&self) -> PathBuf {
        self.tmp.path().canonicalize().unwrap()
    }

    fn path(&self, p: &str) -> PathBuf {
        self.root().join(p)
    }

    fn socket(&self) -> String {
        self.path("run/kagebunshin/kagebunshind.sock")
            .display()
            .to_string()
    }

    fn kb(&self, args: &[&str]) -> Output {
        let home = self.path("home");
        let mut cmd = Command::new(self.path("bin/kagebunshin"));
        cmd.args(args)
            .env_clear()
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.path("bin").display()),
            )
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env("XDG_RUNTIME_DIR", self.path("run"))
            .env("WAYLAND_DISPLAY", "wayland-7")
            .env("XDG_ACTIVATION_TOKEN", "not-for-the-unit");
        // The copy was just written: a process another test forked
        // meanwhile may still hold it open for writing, for a moment.
        let start = Instant::now();
        loop {
            match cmd.output() {
                Err(e)
                    if e.kind() == std::io::ErrorKind::ExecutableFileBusy
                        && start.elapsed() < Duration::from_secs(5) =>
                {
                    std::thread::sleep(Duration::from_millis(10));
                }
                out => return out.unwrap(),
            }
        }
    }

    /// The daemon as a service on this world's socket, as far as its unit.
    fn with_the_service(self) -> Self {
        let out = self.kb(&["daemon", "install", "--files-only"]);
        assert!(out.status.success(), "{}", text(&out));
        fs::remove_file(self.path("service.log")).ok();
        self
    }

    fn log(&self, name: &str) -> String {
        fs::read_to_string(self.path(name)).unwrap_or_default()
    }

    /// Stands in for an app that runs: answers on the app's socket.
    fn app_answers(&self) -> UnixListener {
        let socket = self.path("run/kagebunshin/app.sock");
        fs::remove_file(&socket).ok();
        UnixListener::bind(socket).unwrap()
    }

    /// Waits until `log` has `needle`, as the fake that writes it runs.
    fn wait_for(&self, log: &str, needle: &str) {
        let start = Instant::now();
        while !self.log(log).contains(needle) {
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "{log} never had {needle}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// The `systemd-run` line that makes the app's unit.
    fn unit_line(&self) -> String {
        format!(
            "systemd-run --user --quiet --collect --unit=kagebunshin-app.service \
             --description=Kagebunshin, in the tray --property=Restart=on-failure \
             --property=RestartSec=2 --property=StartLimitIntervalSec=30 \
             --property=StartLimitBurst=5 --property=PartOf=graphical-session.target \
             --setenv=WAYLAND_DISPLAY=wayland-7 -- {} --socket {} --hidden\n",
            self.path("bin/kagebunshin-app").display(),
            self.socket()
        )
    }
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Where the daemon is a service, `app` makes the app a unit beside it
/// and returns once the app answers; with one answering it starts
/// nothing, and only has it show its window.
#[test]
fn the_app_starts_as_a_unit_where_the_daemon_is_one() {
    let w = World::new("").with_the_service();
    let app = std::thread::scope(|s| {
        let app = s.spawn(|| {
            w.wait_for("service.log", "systemd-run");
            w.app_answers()
        });
        let out = w.kb(&["app", "--hidden"]);
        assert!(out.status.success(), "{}", text(&out));
        app.join().unwrap()
    });
    assert_eq!(w.log("service.log"), w.unit_line());
    assert_eq!(w.log("app.log"), "", "only the unit runs the app");

    // In the tray already: nothing to do.
    let out = w.kb(&["app", "--hidden"]);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(w.log("app.log"), "");
    // The window is asked of the one that runs.
    let out = w.kb(&["app"]);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(
        w.log("app.log"),
        format!("shared session: --socket {}\n", w.socket())
    );
    assert_eq!(w.log("service.log"), w.unit_line(), "started once");
    drop(app);

    // Asked for the window with none running: started in the tray, then
    // asked to show it.
    fs::remove_file(w.path("service.log")).unwrap();
    fs::remove_file(w.path("app.log")).unwrap();
    std::thread::scope(|s| {
        let app = s.spawn(|| {
            w.wait_for("service.log", "systemd-run");
            w.app_answers()
        });
        let out = w.kb(&["app"]);
        assert!(out.status.success(), "{}", text(&out));
        app.join().unwrap();
    });
    assert_eq!(w.log("service.log"), w.unit_line());
    assert_eq!(
        w.log("app.log"),
        format!("shared session: --socket {}\n", w.socket())
    );
}

/// With no service, the app is started in a session of its own, which
/// the terminal's Ctrl+C does not reach, and `app` returns all the same.
#[test]
fn without_the_service_the_app_starts_in_a_session_of_its_own() {
    let w = World::new("case \" $* \" in *' --hidden '*) exec sleep 5 ;; esac");
    std::thread::scope(|s| {
        let app = s.spawn(|| {
            w.wait_for("app.log", "--hidden");
            w.app_answers()
        });
        let out = w.kb(&["app"]);
        assert!(out.status.success(), "{}", text(&out));
        app.join().unwrap();
    });
    let socket = w.socket();
    assert_eq!(
        w.log("app.log"),
        format!(
            "own session: --socket {socket} --hidden\n\
             shared session: --socket {socket}\n"
        )
    );
    assert_eq!(w.log("service.log"), "", "no service manager is asked");
}

/// An app that does not come up is an error that says where to look.
#[test]
fn an_app_that_does_not_start_is_said() {
    // It ends at once: no display, say.
    let w = World::new("exit 1");
    let out = w.kb(&["app", "--hidden"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    let all = text(&out);
    assert!(all.contains("the app did not start"), "{all}");
    assert!(
        all.contains(&format!(
            "hint: `{} --socket {}` prints why",
            w.path("bin/kagebunshin-app").display(),
            w.socket()
        )),
        "{all}"
    );

    // The service manager refuses the unit.
    let w = World::new("").with_the_service();
    w.fake("systemd-run", "echo 'no such session' >&2\nexit 1\n");
    let out = w.kb(&["--json", "app"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    let all = text(&out);
    assert!(all.contains(r#""code":"app_not_started""#), "{all}");
    assert!(all.contains("no such session"), "{all}");
    assert_eq!(w.log("app.log"), "", "no window is asked of no app");
}

/// `app install` writes entries that run this binary's `app`, and has an
/// app that runs go on with the binary found now: the unit restarted, and
/// one started some other way told to end and made the unit.
#[test]
fn app_install_restarts_a_running_app() {
    let w = World::new("").with_the_service();
    let (cli, socket) = (w.path("bin/kagebunshin"), w.socket());

    // None runs: none is started.
    let out = w.kb(&["app", "install"]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        text(&out).ends_with("to start it now: kagebunshin app --hidden\n"),
        "{}",
        text(&out)
    );
    assert_eq!(w.log("service.log"), "");
    let entry = |name: &str| {
        let id = "io.github.oorestisime.kagebunshin";
        fs::read_to_string(w.path(&format!("home/{name}/{id}.desktop"))).unwrap()
    };
    let exec = format!("Exec=\"{}\" --socket \"{socket}\" app", cli.display());
    let login = entry(".config/autostart");
    assert!(login.contains(&format!("{exec} --hidden\n")), "{login}");
    let launcher = entry(".local/share/applications");
    assert!(launcher.contains(&format!("{exec}\n")), "{launcher}");
    assert!(launcher.contains(&format!("{exec} --quit\n")), "{launcher}");

    // The unit runs: the service manager restarts it.
    let app = w.app_answers();
    fs::write(w.path("active"), "").unwrap();
    let out = w.kb(&["app", "install"]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("restarted the app"), "{}", text(&out));
    assert_eq!(
        w.log("service.log"),
        "systemctl --user is-active kagebunshin-app.service\n\
         systemctl --user restart kagebunshin-app.service\n"
    );
    assert_eq!(w.log("app.log"), "");

    // One that is no unit, as before the app was one, or started by hand.
    fs::remove_file(w.path("active")).unwrap();
    fs::remove_file(w.path("service.log")).unwrap();
    std::thread::scope(|s| {
        let app = s.spawn(|| {
            w.wait_for("quit", "asked");
            drop(app);
            w.wait_for("service.log", "systemd-run");
            w.app_answers()
        });
        let out = w.kb(&["--json", "app", "install"]);
        assert!(out.status.success(), "{}", text(&out));
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(v["restarted"], true, "{v}");
        app.join().unwrap();
    });
    assert_eq!(
        w.log("app.log"),
        format!("shared session: --socket {socket} --quit\n")
    );
    assert_eq!(
        w.log("service.log"),
        format!(
            "systemctl --user is-active kagebunshin-app.service\n{}",
            w.unit_line()
        )
    );
}
