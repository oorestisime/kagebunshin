//! The `kagebunshin` binary: exit codes, error shapes and the daemon commands
//! against an in-process daemon.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test code")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::time::Duration;

use kagebunshin::audit::AuditLog;
use kagebunshin::config::{ConfigDir, Registry};
use kagebunshin::daemon::Daemon;
use kagebunshin::ipc::client::{Client, DEFAULT_TIMEOUT};
use kagebunshin::ipc::protocol::{
    Caller, DiffReport, Request, Response, StatusReport, SyncReport, WireSecret,
};
use kagebunshin::ipc::server::ServerConfig;
use kagebunshin::store::StoreFile;
use kagebunshin::sys;
use kagebunshin::test_support::{Canary, FakeSources, TestDaemon, assert_no_canary};
use kagebunshin::types::{Origin, Provider};

mod common;

fn kb(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kagebunshin"))
        .args(args)
        // Never fall back to the developer's real socket or configuration.
        .env_remove("KAGEBUNSHIN_SOCKET")
        .env(
            "KAGEBUNSHIN_CONFIG_DIR",
            "/nonexistent/kagebunshin-test-config",
        )
        .env("XDG_STATE_HOME", "/nonexistent/kagebunshin-test-state")
        .output()
        .unwrap()
}

fn code(o: &Output) -> i32 {
    o.status.code().expect("exited normally")
}

fn stdout(o: &Output) -> String {
    String::from_utf8(o.stdout.clone()).unwrap()
}

fn stderr(o: &Output) -> String {
    String::from_utf8(o.stderr.clone()).unwrap()
}

/// stderr must be exactly one JSON object with exactly these five keys.
fn json_error(o: &Output) -> serde_json::Map<String, serde_json::Value> {
    let err = stderr(o);
    assert_eq!(err.lines().count(), 1, "one line of JSON: {err}");
    let v: serde_json::Value = serde_json::from_str(&err).unwrap();
    let obj = v.as_object().unwrap().clone();
    let mut keys: Vec<_> = obj.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["code", "hint", "message", "tell", "who"]);
    assert!(obj["code"].is_string() && obj["message"].is_string());
    assert!(obj["hint"].is_string() || obj["hint"].is_null());
    assert!(["agent", "human"].contains(&obj["who"].as_str().unwrap_or("agent")));
    assert!(obj["tell"].is_string() || obj["tell"].is_null());
    // A step for a human always says what to ask them.
    assert_eq!(obj["who"] == "human", obj["tell"].is_string(), "{obj:?}");
    obj
}

fn sock(p: &Path) -> &str {
    p.to_str().unwrap()
}

/// A private socket directory with nothing listening in it.
fn no_daemon(tmp: &Path) -> PathBuf {
    let dir = tmp.join("kb");
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    dir.join("kagebunshind.sock")
}

#[test]
fn daemon_ping() {
    let tmp = tempfile::tempdir().unwrap();
    let d = TestDaemon::start(tmp.path()).unwrap();
    let o = kb(&["daemon", "ping", "--socket", sock(d.socket())]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(stdout(&o), "pong\n");

    let o = kb(&["--json", "daemon", "ping", "--socket", sock(d.socket())]);
    assert_eq!(code(&o), 0);
    assert_eq!(stdout(&o), "{\"pong\":true}\n");
}

#[test]
fn daemon_whoami_reports_the_cli_process() {
    let tmp = tempfile::tempdir().unwrap();
    let d = TestDaemon::start(tmp.path()).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_kagebunshin"))
        .args(["daemon", "whoami", "--json", "--socket", sock(d.socket())])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id() as i32;
    let o = child.wait_with_output().unwrap();
    assert_eq!(code(&o), 0);
    let me: Caller = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(me.pid, pid);
    assert_eq!(me.uid, sys::effective_uid());

    let o = kb(&["daemon", "whoami", "--socket", sock(d.socket())]);
    assert!(stdout(&o).starts_with(&format!("uid={} ", sys::effective_uid())));
}

#[test]
fn daemon_not_running() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = no_daemon(tmp.path());

    let o = kb(&["daemon", "ping", "--socket", sock(&socket)]);
    assert_eq!(code(&o), 3);
    let err = stderr(&o);
    assert!(err.contains("not running"), "{err}");
    assert!(
        err.contains("ask the human: run `kagebunshin daemon install` once"),
        "{err}"
    );
    #[cfg(target_os = "linux")]
    assert!(
        err.contains("`systemctl --user start kagebunshin`"),
        "{err}"
    );
    #[cfg(target_os = "macos")]
    assert!(err.contains("`launchctl kickstart"), "{err}");

    let o = kb(&["daemon", "ping", "--json", "--socket", sock(&socket)]);
    assert_eq!(code(&o), 3);
    let e = json_error(&o);
    assert_eq!(e["code"], "daemon_not_running");
    assert!(e["hint"].as_str().unwrap().contains("kagebunshin daemon"));
    assert!(o.stdout.is_empty());
}

#[test]
fn build_mismatch_exits_4() {
    let tmp = tempfile::tempdir().unwrap();
    let mut cfg = ServerConfig::new(tmp.path().join("kb").join("kagebunshind.sock"));
    cfg.build_id = "0.0.0-older".into();
    let d = TestDaemon::start_with(cfg).unwrap();
    let o = kb(&["--json", "daemon", "ping", "--socket", sock(d.socket())]);
    assert_eq!(code(&o), 4);
    let e = json_error(&o);
    assert_eq!(e["code"], "build_mismatch");
    assert!(e["hint"].as_str().unwrap().contains("restart the daemon"));
}

#[test]
fn usage_errors_exit_2() {
    for args in [&["bogus"][..], &["get"], &["get", "not-a-key"], &[]] {
        assert_eq!(code(&kb(args)), 2, "{args:?}");
    }
    let o = kb(&["--json", "get", "not-a-key"]);
    assert_eq!(code(&o), 2);
    let e = json_error(&o);
    assert_eq!(e["code"], "usage");
    assert!(!e["message"].as_str().unwrap().starts_with("error:"));

    let o = kb(&["daemon", "ping", "--socket", "relative.sock"]);
    assert_eq!(code(&o), 2);
}

#[test]
fn help_and_version_exit_0() {
    let o = kb(&["--help"]);
    assert_eq!(code(&o), 0);
    assert!(stdout(&o).contains("Usage: kagebunshin"));
    let o = kb(&["--version"]);
    assert_eq!(code(&o), 0);
    assert!(stdout(&o).starts_with("kagebunshin "));
}

/// The widget project: a prefix, then a single secret that overrides it.
/// Its `.env.example` lives in apps/web, set through `env_example`.
const WIDGET: &str = r#"
schema = 1
remotes = ["git@github.com:acme/widget.git"]
env_example = "apps/web/.env.example"

[envs.dev]
[[envs.dev.sources]]
provider = "aws_sm"
prefix = "widget/dev/"
[[envs.dev.sources]]
provider = "aws_sm"
secret = "widget/override"

[envs.qa]
[[envs.qa.sources]]
provider = "aws_sm"
secret = "widget/qa"

# Marked sensitive in the store by `World::mark_prod`.
[envs.prod]
"#;

/// A temp HOME, config dir and git checkout, an in-process daemon over
/// [`FakeSources`], and a canary in every value.
struct World {
    tmp: tempfile::TempDir,
    canary: Canary,
    fake: Arc<FakeSources>,
    daemon: TestDaemon,
}

impl World {
    fn new() -> Self {
        Self::with_idle(Duration::from_secs(60))
    }

    /// A world whose daemon closes a connection left idle for `idle`.
    fn with_idle(idle: Duration) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        for dir in ["home", "config/projects", "widget/apps/web", "elsewhere"] {
            fs::create_dir_all(root.join(dir)).unwrap();
        }
        fs::write(root.join("config/projects/widget.toml"), WIDGET).unwrap();
        fs::write(
            root.join("widget/apps/web/.env.example"),
            "API_URL=\nDB_PASSWORD=\nMISSING_KEY=changeme\n",
        )
        .unwrap();
        let w = root.join("widget");
        git(&root, &w, &["init", "-q"]);
        git(
            &root,
            &w,
            &["remote", "add", "origin", "git@github.com:acme/widget.git"],
        );

        let canary = Canary::new();
        let v = canary.value();
        let fake = FakeSources::new();
        fake.set("widget/dev/app", &[("API_URL", v), ("DB_PASSWORD", v)])
            .set("widget/override", &[("DB_PASSWORD", v), ("EXTRA", v)])
            .set(
                "widget/qa",
                &[("API_URL", v), ("DB_PASSWORD", v), ("MISSING_KEY", v)],
            );
        let dir = ConfigDir::new(root.join("config"));
        let store = StoreFile::new(dir.store_file()).with_test_work_factor();
        // Where the CLI writes its own events too, through XDG_STATE_HOME.
        let audit = AuditLog::new(root.join("state/kagebunshin/audit.jsonl"));
        let daemon = Daemon::new(Box::new(move || Registry::load(&dir)), fake.clone(), store)
            .with_audit(audit);
        let mut cfg = ServerConfig::new(root.join("kb").join("kagebunshind.sock"));
        cfg.idle_timeout = idle;
        let daemon = TestDaemon::start_with_daemon(cfg, daemon).unwrap();
        Self {
            tmp,
            canary,
            fake,
            daemon,
        }
    }

    fn root(&self) -> PathBuf {
        self.tmp.path().canonicalize().unwrap()
    }

    /// Runs the CLI in `dir` (relative to the temp root), isolated from the
    /// user's git config, HOME and kagebunshin config, and checks that no
    /// value reached its output.
    fn kb(&self, dir: &str, args: &[&str]) -> Output {
        self.kb_env(dir, args, &[])
    }

    /// [`World::kb`] with extra environment variables.
    fn kb_env(&self, dir: &str, args: &[&str], vars: &[(&str, &str)]) -> Output {
        let o = self
            .command(dir, args)
            .envs(vars.iter().copied())
            .output()
            .unwrap();
        assert_no_canary(&self.canary, &stdout(&o));
        assert_no_canary(&self.canary, &stderr(&o));
        o
    }

    /// The CLI as [`World::kb`] runs it, not yet started.
    fn command(&self, dir: &str, args: &[&str]) -> Command {
        let root = self.root();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_kagebunshin"));
        // Before the arguments, so it is not taken as part of `run`'s command.
        cmd.args(["--socket", sock(self.daemon.socket())])
            .args(args)
            .current_dir(root.join(dir))
            .env_remove("KAGEBUNSHIN_SOCKET")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env("KAGEBUNSHIN_CONFIG_DIR", root.join("config"))
            .env("HOME", root.join("home"))
            .env("XDG_CONFIG_HOME", root.join("home/.config"))
            .env("XDG_STATE_HOME", root.join("state"))
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CEILING_DIRECTORIES", &root);
        cmd
    }
}

impl World {
    /// Creates the local store with passphrase `pw` and unlocks the daemon
    /// with it, as `store init` does after prompting at /dev/tty.
    fn init_store(&self) {
        let dir = ConfigDir::new(self.root().join("config"));
        StoreFile::new(dir.store_file())
            .with_test_work_factor()
            .create(&WireSecret::new("pw".into()).into_passphrase())
            .unwrap();
        let mut client = Client::connect(self.daemon.socket(), DEFAULT_TIMEOUT).unwrap();
        client.request(Request::Lock).unwrap();
        client
            .request(Request::Unlock {
                passphrase: Some(WireSecret::new("pw".into())),
            })
            .unwrap();
    }

    /// Marks or unmarks something as a human does in the app: in the store,
    /// with its passphrase `pw`. The CLI has no command for it.
    fn mark(&self, req: Request) {
        let mut client = Client::connect(self.daemon.socket(), DEFAULT_TIMEOUT).unwrap();
        let r = client.request(req).unwrap();
        assert!(matches!(r, Response::Store { .. }), "{r:?}");
    }

    /// Creates the store, unlocking the daemon, and marks environment prod
    /// of widget sensitive.
    fn mark_prod(&self) {
        self.init_store();
        self.mark(Request::MarkEnv {
            project: "widget".parse().unwrap(),
            env: "prod".parse().unwrap(),
            sensitive: true,
            also: Vec::new(),
            passphrase: WireSecret::new("pw".into()),
        });
    }
}

fn git(root: &Path, dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("HOME", root.join("home"))
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn status_diff_sync_lock_unlock() {
    let w = World::new();

    let o = w.kb("widget", &["status"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(
        stdout(&o),
        "daemon: locked
providers:
  aws_sm  fake  ok
runs in the last day: none
run `kagebunshin unlock` to see where each key comes from
"
    );
    let o = w.kb("widget", &["status", "--json"]);
    let mut out: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    // Counted from a day ago, which is not the same twice.
    assert!(out["runs"]["since"].take().is_u64(), "{out}");
    assert_eq!(
        out,
        serde_json::json!({
            "locked": true,
            "env": null,
            "providers": [{"provider": "aws_sm", "detail": "fake", "health": {"state": "ok"}}],
            "runs": {"since": null, "count": 0, "projects": 0},
        })
    );
    let o = w.kb("widget", &["diff", "--json"]);
    assert_eq!(code(&o), 5);
    let e = json_error(&o);
    assert_eq!(e["code"], "locked");
    assert_eq!(e["who"], "human");
    assert_eq!(
        e["tell"],
        "unlock kagebunshin: run `kagebunshin unlock` in a terminal"
    );

    let o = w.kb("widget", &["unlock"]);
    assert_eq!((code(&o), stdout(&o).as_str()), (0, "unlocked\n"));

    // From the checkout root, the project file's env_example (apps/web) is
    // the one compared against.
    let o = w.kb("widget", &["status"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(
        stdout(&o),
        "daemon: unlocked
providers:
  aws_sm  fake  ok
project: widget
env: dev
3 keys
  API_URL      aws_sm:widget/dev/app
  DB_PASSWORD  aws_sm:widget/override  overrides aws_sm:widget/dev/app
  EXTRA        aws_sm:widget/override  not in .env.example
missing (in .env.example, set by no source):
  MISSING_KEY
to fill in what is missing:
  you can run:
    kagebunshin project set-var widget dev MISSING_KEY changeme
      (only if .env.example's value is the real setting, not a placeholder; a secret belongs in the store or a provider)
"
    );
    let o = w.kb("widget/apps", &["status", "--json"]);
    let r: StatusReport = serde_json::from_str(&stdout(&o)).unwrap();
    let env = r.env.unwrap();
    let keys: Vec<_> = env
        .keys
        .iter()
        .map(|k| (k.key.as_str(), k.in_example))
        .collect();
    assert_eq!(
        keys,
        [("API_URL", true), ("DB_PASSWORD", true), ("EXTRA", false)]
    );
    assert_eq!(w.fake.fetches(), 2, "status is served from the cache");

    // Missing keys are listed; the rest are counted per secret, and
    // listed with --verbose.
    let o = w.kb("widget/apps/web", &["diff"]);
    assert_eq!(code(&o), 1);
    assert_eq!(
        stdout(&o),
        "project: widget
env: dev
missing (in .env.example, set by no source):
  MISSING_KEY
extra (set by a source, not in .env.example): 1 key
  aws_sm:widget/override  1 key
conflicts (set by more than one source, the last wins): 1 key
  aws_sm:widget/override  1 key  overrides aws_sm:widget/dev/app
to fill in what is missing:
  you can run:
    kagebunshin project set-var widget dev MISSING_KEY changeme
      (only if .env.example's value is the real setting, not a placeholder; a secret belongs in the store or a provider)
"
    );
    let o = w.kb("widget/apps/web", &["diff", "--verbose"]);
    assert_eq!(code(&o), 1);
    assert_eq!(
        stdout(&o),
        "project: widget
env: dev
missing (in .env.example, set by no source):
  MISSING_KEY
extra (set by a source, not in .env.example):
  EXTRA
conflicts (set by more than one source, the last wins):
  DB_PASSWORD  aws_sm:widget/override  overrides aws_sm:widget/dev/app
to fill in what is missing:
  you can run:
    kagebunshin project set-var widget dev MISSING_KEY changeme
      (only if .env.example's value is the real setting, not a placeholder; a secret belongs in the store or a provider)
"
    );
    assert_eq!(
        stderr(&o),
        "kagebunshin: 1 key in .env.example is not set by any source\n"
    );
    let o = w.kb("widget", &["--json", "diff"]);
    assert_eq!(code(&o), 1);
    assert_eq!(json_error(&o)["code"], "missing_keys");
    let r: DiffReport = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(r.missing.len(), 1);

    // Nothing missing: exit 0 even with extra keys.
    let o = w.kb("widget", &["diff", "--env", "qa"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(
        stdout(&o).ends_with("env: qa\nno differences\n"),
        "{}",
        stdout(&o)
    );

    let o = w.kb("elsewhere", &["sync", "widget"]);
    assert_eq!((code(&o), stdout(&o).as_str()), (0, "widget dev: 3 keys\n"));
    assert_eq!(w.fake.fetches(), 5);
    let o = w.kb("elsewhere", &["sync", "--json"]);
    let r: SyncReport = serde_json::from_str(&stdout(&o)).unwrap();
    let mut synced: Vec<_> = r
        .refreshed
        .iter()
        .map(|s| (s.env.as_str(), s.keys))
        .collect();
    synced.sort();
    assert_eq!(synced, [("dev", Some(3)), ("qa", Some(3))]);
    assert_eq!(code(&w.kb("elsewhere", &["sync", "--env", "qa"])), 2);
    assert_eq!(
        code(&w.kb("elsewhere", &["sync", "widget", "qa", "--env", "dev"])),
        2
    );

    let o = w.kb("widget", &["lock", "--json"]);
    assert_eq!((code(&o), stdout(&o).as_str()), (0, "{\"locked\":true}\n"));
    assert!(stdout(&w.kb("widget", &["status"])).starts_with("daemon: locked\n"));
    let o = w.kb("elsewhere", &["sync"]);
    assert_eq!(code(&o), 5);
    assert!(
        stderr(&o).contains("the daemon is locked\nask the human: unlock kagebunshin"),
        "{}",
        stderr(&o)
    );
}

/// A plain setting fills in a key no source sets, unmasked, without a sync;
/// a source setting the same key wins over it.
#[test]
fn a_plain_setting_fills_in_a_missing_key() {
    let w = World::new();
    w.mark_prod();
    let set_var = "kagebunshin project set-var widget dev MISSING_KEY changeme";
    let o = w.kb("widget", &["diff"]);
    assert_eq!(code(&o), 1);
    assert!(
        stdout(&o).contains(&format!("  {set_var}\n")),
        "{}",
        stdout(&o)
    );
    let o = w.kb("widget", &["--json", "status"]);
    let r: StatusReport = serde_json::from_str(&stdout(&o)).unwrap();
    let fixes = r.env.unwrap().fixes;
    assert_eq!(fixes.len(), 1, "{fixes:?}");
    assert_eq!(fixes[0].command, set_var);
    assert!(fixes[0].note.contains("not a placeholder"), "{fixes:?}");
    let fetches = w.fake.fetches();

    let o = w.kb(
        "widget",
        &[
            "project",
            "set-var",
            "widget",
            "dev",
            "MISSING_KEY",
            "plain value",
        ],
    );
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(
        stdout(&o),
        "set MISSING_KEY for environment dev of project widget\n"
    );
    let text = fs::read_to_string(w.root().join("config/projects/widget.toml")).unwrap();
    assert!(
        text.contains("[envs.dev.vars]\nMISSING_KEY = \"plain value\"\n"),
        "{text}"
    );

    let o = w.kb("widget", &["diff"]);
    assert_eq!(code(&o), 0, "{}", stdout(&o));
    assert!(!stdout(&o).contains("missing"), "{}", stdout(&o));
    let o = w.kb("widget", &["status"]);
    let out = stdout(&o);
    let row = out
        .lines()
        .find(|l| l.starts_with("  MISSING_KEY "))
        .unwrap_or_default();
    let cells: Vec<&str> = row
        .split("  ")
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .collect();
    assert_eq!(
        cells,
        ["MISSING_KEY", "project file", "= 'plain value'"],
        "{out}"
    );
    // Injected, unmasked, and nothing is missing for --strict.
    let o = w.kb(
        "widget",
        &[
            "run",
            "--strict",
            "--",
            "sh",
            "-c",
            r#"printf '%s\n' "$MISSING_KEY""#,
        ],
    );
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(stdout(&o), "plain value\n");
    assert!(!stderr(&o).contains("MISSING_KEY"), "{}", stderr(&o));
    assert_eq!(w.fake.fetches(), fetches, "no fetch, no sync needed");

    // A source that sets the key wins, and its value is masked again.
    let o = w.kb(
        "widget",
        &["project", "set-var", "widget", "qa", "MISSING_KEY", "plain"],
    );
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let o = w.kb(
        "widget",
        &[
            "run",
            "--env",
            "qa",
            "--",
            "sh",
            "-c",
            r#"printf '%s\n' "$MISSING_KEY""#,
        ],
    );
    // Every value here is the canary, so the mask may name another key.
    assert!(stdout(&o).starts_with("<redacted:"), "{}", stderr(&o));

    let o = w.kb(
        "widget",
        &["project", "unset-var", "widget", "dev", "MISSING_KEY"],
    );
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(code(&w.kb("widget", &["diff"])), 1);
    let o = w.kb(
        "widget",
        &[
            "--json",
            "project",
            "unset-var",
            "widget",
            "dev",
            "MISSING_KEY",
        ],
    );
    assert_eq!(code(&o), 1);
    assert_eq!(
        json_error(&o)["message"],
        "environment dev of project widget has no plain setting MISSING_KEY"
    );
    let log = fs::read_to_string(w.root().join("state/kagebunshin/audit.jsonl")).unwrap();
    assert!(log.contains("\"project set-var\""), "{log}");
    assert!(!log.contains("plain value"), "{log}");
}

#[test]
fn unreadable_env_example_lines_are_warned_about_and_fail_diff() {
    let w = World::new();
    // qa sets all three keys, so only the unreadable lines are wrong. The
    // value after the open quote must never be shown.
    fs::write(
        w.root().join("widget/apps/web/.env.example"),
        "API_URL=\nDB PASSWORD=\nMISSING_KEY=\"never-shown\nLATER=\n",
    )
    .unwrap();
    assert_eq!(code(&w.kb("widget", &["unlock"])), 0);

    let o = w.kb("widget", &["diff", "--env", "qa"]);
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert_eq!(
        stderr(&o),
        "warning: .env.example line 2 is not a KEY=value line with a valid key name
warning: .env.example line 3 starts a quoted value that is never closed; the rest of the file was skipped
kagebunshin: 2 lines of .env.example could not be read, so a key on them may be missing
"
    );
    assert!(!stdout(&o).contains("never-shown") && !stderr(&o).contains("never-shown"));

    let o = w.kb("widget", &["--json", "diff", "--env", "qa"]);
    assert_eq!(code(&o), 1);
    assert_eq!(json_error(&o)["code"], "env_example_unreadable");
    let v: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(
        v["bad_lines"],
        serde_json::json!([
            {"line": 2, "problem": "bad_key"},
            {"line": 3, "problem": "unterminated_quote"}
        ])
    );
    let r: DiffReport = serde_json::from_value(v).unwrap();
    assert!(r.missing.is_empty());

    // status warns the same way but still exits 0.
    let o = w.kb("widget", &["status", "--env", "qa"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(stderr(&o).lines().count(), 2, "{}", stderr(&o));
    let o = w.kb("widget", &["status", "--json", "--env", "qa"]);
    let v: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(v["bad_lines"].as_array().unwrap().len(), 2);
}

/// An unmarked environment that looks like production is refused like a
/// marked one until it is decided; names-only commands say it waits. One
/// named production outright is the caller's to mark, and each says how.
#[test]
fn a_production_looking_environment_waits_for_a_human() {
    let w = World::new();
    w.init_store();
    w.fake.set("acme/db", &[("API_URL", w.canary.value())]);
    let o = w.kb(
        "elsewhere",
        &[
            "project",
            "add-source",
            "widget",
            "prod",
            "--provider",
            "aws_sm",
            "--secret",
            "acme/db",
        ],
    );
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    // add-env warns of its name, as it gives the environment the default
    // source; a source added to it later does not say it again.
    let o = w.kb("elsewhere", &["project", "add-env", "widget", "production"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(
        stderr(&o),
        "warning: environment production of project widget looks like production (its name has \
         the segment production) and waits for a human decision; mark it sensitive with \
         `kagebunshin mark env widget production`, since it is production by its name, or ask \
         the human: open the app (`kagebunshin app`) and either mark widget/production sensitive \
         or acknowledge it is not production\n"
    );
    for secret in ["acme/db", "acme/cache"] {
        let o = w.kb(
            "elsewhere",
            &[
                "project",
                "add-source",
                "widget",
                "production",
                "--provider",
                "aws_sm",
                "--secret",
                secret,
            ],
        );
        assert_eq!((code(&o), stderr(&o).as_str()), (0, ""));
    }

    let o = w.kb("widget", &["--json", "--env", "prod", "run", "--", "true"]);
    assert_eq!(code(&o), 5, "{}", stderr(&o));
    let e = json_error(&o);
    assert_eq!(e["code"], "sensitive_env");
    assert_eq!(
        e["message"],
        "environment prod of project widget looks like production (its name has the segment \
         prod) and waits for a human decision"
    );
    assert_eq!(
        (&e["who"], &e["tell"]),
        (&serde_json::json!("agent"), &serde_json::Value::Null)
    );
    let hint = "it is production by its name: mark it sensitive with `kagebunshin mark env \
                widget prod`; its values are then handed out once the human approves the \
                request in the app";
    assert_eq!(e["hint"], hint);
    // The text form ends with the command that marks it.
    let o = w.kb("widget", &["--env", "prod", "run", "--", "true"]);
    assert_eq!(code(&o), 5, "{}", stderr(&o));
    assert!(
        stderr(&o).ends_with(&format!("\nhint: {hint}\n")),
        "{}",
        stderr(&o)
    );

    let note = "warning: environment prod of project widget looks like production (its name \
                has the segment prod) and waits for a human decision; mark it sensitive with \
                `kagebunshin mark env widget prod`, since it is production by its name, or ask \
                the human: open the app (`kagebunshin app`) and either mark widget/prod sensitive";
    let o = w.kb("widget", &["status", "--env", "prod"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    // status lists its warnings with the rest of its report, on stdout.
    assert!(stdout(&o).contains(note), "{}", stdout(&o));
    assert!(!stdout(&o).contains("agents can read it"), "{}", stdout(&o));
    for args in [&["project", "show", "widget"][..], &["project", "list"]] {
        let o = w.kb("elsewhere", args);
        assert_eq!(code(&o), 0, "{}", stderr(&o));
        assert!(stderr(&o).contains(note), "{args:?}: {}", stderr(&o));
    }

    // Once a human says it is not production, it is a normal environment.
    w.mark(Request::AcknowledgeEnvs {
        envs: vec![
            "widget.prod".parse().unwrap(),
            "widget.production".parse().unwrap(),
        ],
        passphrase: WireSecret::new("pw".into()),
    });
    let o = w.kb("widget", &["--env", "prod", "run", "--", "true"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let o = w.kb("elsewhere", &["project", "show", "widget"]);
    assert_eq!(stderr(&o), "");
}

/// `mark` adds a mark with no passphrase; nothing takes one off, and it
/// does not go against what a human decided.
#[test]
fn mark_adds_a_mark_and_nothing_removes_one() {
    let w = World::new();
    w.init_store();
    let o = w.kb("elsewhere", &["mark", "env", "widget", "prod"]);
    assert_eq!(
        (code(&o), stdout(&o).as_str(), stderr(&o).as_str()),
        (0, "marked sensitive\n", "")
    );
    let o = w.kb("widget", &["--json", "--env", "prod", "run", "--", "true"]);
    assert_eq!(code(&o), 5, "{}", stderr(&o));
    let e = json_error(&o);
    assert!(
        e["message"].as_str().unwrap().contains("marked sensitive"),
        "{e:?}"
    );
    // Marked already: the same answer.
    let o = w.kb("elsewhere", &["--json", "mark", "env", "widget", "prod"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&stdout(&o)).unwrap(),
        serde_json::json!({ "change": "marked", "locked": false })
    );
    let o = w.kb("elsewhere", &["mark", "env", "widget", "nope"]);
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert!(
        stderr(&o).contains("has no environment nope"),
        "{}",
        stderr(&o)
    );
    let o = w.kb(
        "elsewhere",
        &["mark", "env", "widget", "prod", "--env", "dev"],
    );
    assert_eq!(code(&o), 2, "{}", stderr(&o));

    for args in [
        &["unmark", "env", "widget", "prod"][..],
        &["mark", "env", "widget", "prod", "--off"],
        &["acknowledge", "widget", "prod"],
    ] {
        let o = w.kb("elsewhere", args);
        assert_eq!(code(&o), 2, "{args:?}: {}", stderr(&o));
    }

    w.mark(Request::AcknowledgeEnvs {
        envs: vec!["widget.qa".parse().unwrap()],
        passphrase: WireSecret::new("pw".into()),
    });
    let o = w.kb("elsewhere", &["--json", "mark", "env", "widget", "qa"]);
    assert_eq!(code(&o), 5, "{}", stderr(&o));
    assert_eq!(json_error(&o)["code"], "permission_denied");
}

#[test]
fn refusals_and_failures_exit_with_stable_codes() {
    let w = World::new();
    w.mark_prod();

    let o = w.kb("widget", &["--json", "status", "--env", "prod"]);
    assert_eq!(code(&o), 5);
    let e = json_error(&o);
    assert_eq!(e["code"], "sensitive_env");
    assert_eq!(
        e["message"],
        "refusing environment prod of project widget: it is marked sensitive"
    );

    w.fake.fail("widget/override");
    let o = w.kb("widget", &["--json", "diff"]);
    assert_eq!(code(&o), 1);
    let e = json_error(&o);
    assert_eq!(e["code"], "source_failed");
    assert!(
        e["message"]
            .as_str()
            .unwrap()
            .contains("widget/override was denied"),
        "{e:?}"
    );

    let o = w.kb("widget", &["diff", "--env", "staging"]);
    assert_eq!(code(&o), 1);
    assert!(
        stderr(&o).contains("has no environment staging"),
        "{}",
        stderr(&o)
    );

    // Outside a checkout, status still reports the lock state; diff cannot.
    let o = w.kb("elsewhere", &["status"]);
    assert_eq!(
        (code(&o), stdout(&o).as_str()),
        (0, "daemon: unlocked\nruns in the last day: none\n")
    );
    let o = w.kb("elsewhere", &["--json", "diff"]);
    assert_eq!(code(&o), 1);
    assert_eq!(json_error(&o)["code"], "no_project");
    assert_eq!(w.fake.fetches(), 2);
}

/// A command that reports on its environment without printing a value
/// (except `DB_PASSWORD`, to stderr, to show it is masked), then exits 7.
const REPORT: &str = r#"printf '%s|%s|%s\n' "$API_URL" "${#DB_PASSWORD}" "${EXTRA-unset}"; printf 'db=%s\n' "$DB_PASSWORD" >&2; exit 7"#;

#[test]
fn run_injects_masks_and_passes_the_exit_status_back() {
    let w = World::new();
    let o = w.kb("widget", &["--json", "run", "--", "true"]);
    assert_eq!(code(&o), 5);
    assert_eq!(json_error(&o)["code"], "locked");
    w.mark_prod();

    let o = w
        .command("widget", &["run", "--", "sh", "-c", REPORT])
        .env("API_URL", "http://old")
        .output()
        .unwrap();
    assert_eq!(code(&o), 7, "{}", stderr(&o));
    let (out, err) = (stdout(&o), stderr(&o));
    assert_no_canary(&w.canary, &out);
    assert_no_canary(&w.canary, &err);
    // Both injected keys hold the canary; the mask names the first.
    let len = w.canary.value().len();
    assert_eq!(out, format!("<redacted:API_URL>|{len}|unset\n"));
    assert!(err.contains("db=<redacted:API_URL>\n"), "{err}");
    assert!(
        err.contains("kagebunshin: warning: API_URL replaces the value already in the environment"),
        "{err}"
    );
    assert!(
        err.contains("1 key in .env.example is not set by any source: MISSING_KEY"),
        "{err}"
    );
    // With --json, each warning is one JSON line on stderr; the command's
    // own output is left as it is.
    let o = w
        .command("widget", &["--json", "run", "--", "sh", "-c", REPORT])
        .env("API_URL", "http://old")
        .output()
        .unwrap();
    assert_eq!(code(&o), 7, "{}", stderr(&o));
    assert_eq!(stdout(&o), format!("<redacted:API_URL>|{len}|unset\n"));
    let err = stderr(&o);
    assert_no_canary(&w.canary, &err);
    let mut warnings = Vec::new();
    for line in err.lines() {
        if line.starts_with("db=") {
            assert_eq!(line, "db=<redacted:API_URL>");
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        let obj = v.as_object().unwrap();
        assert_eq!(obj.keys().collect::<Vec<_>>(), ["warning"], "{line}");
        warnings.push(obj["warning"].as_str().unwrap().to_owned());
    }
    assert!(
        warnings
            .iter()
            .any(|w| w == "API_URL replaces the value already in the environment"),
        "{warnings:?}"
    );
    assert!(
        warnings.iter().any(|w| w.contains("MISSING_KEY")),
        "{warnings:?}"
    );

    // --strict refuses to run with a key missing.
    let marker = w.root().join("ran");
    let touch = format!("touch {}", marker.display());
    let o = w.kb("widget", &["--json", "run", "--strict", "sh", "-c", &touch]);
    assert_eq!(code(&o), 1);
    assert_eq!(json_error(&o)["code"], "missing_keys");
    assert!(!marker.exists());
    // qa sets every key in .env.example.
    let o = w.kb(
        "widget",
        &["run", "--strict", "--env", "qa", "sh", "-c", &touch],
    );
    assert_eq!((code(&o), stderr(&o).as_str()), (0, ""));
    assert!(marker.exists());

    let o = w.kb("widget", &["--json", "run", "--env", "prod", "true"]);
    assert_eq!(code(&o), 5);
    assert_eq!(json_error(&o)["code"], "sensitive_env");
    let o = w.kb("elsewhere", &["--json", "run", "true"]);
    assert_eq!(code(&o), 1);
    assert_eq!(json_error(&o)["code"], "no_project");
    let o = w.kb(
        "widget",
        &["--json", "run", "--env", "qa", "/nonexistent/command"],
    );
    assert_eq!(code(&o), 1);
    assert_eq!(json_error(&o)["code"], "exec");

    // Marking one secret refuses the whole run, before the command starts,
    // without a sync.
    w.mark(Request::MarkSecret {
        secret: Origin::new(Provider::AwsSm, "widget/dev/app"),
        sensitive: true,
        passphrase: WireSecret::new("pw".into()),
    });
    fs::remove_file(&marker).unwrap();
    let o = w.kb("widget", &["--json", "run", "sh", "-c", &touch]);
    assert_eq!(code(&o), 5);
    let e = json_error(&o);
    assert_eq!(e["code"], "sensitive_env");
    assert_eq!(
        e["message"],
        "refusing key API_URL of environment dev of project widget: it comes from \
         aws_sm:widget/dev/app, which is marked sensitive; handing it out takes approval \
         in the app, which is not open"
    );
    assert!(!marker.exists());

    // Without a .env.example every key is passed, with a warning.
    fs::remove_file(w.root().join("widget/apps/web/.env.example")).unwrap();
    let file = w.root().join("config/projects/widget.toml");
    let text = fs::read_to_string(&file).unwrap();
    fs::write(
        &file,
        text.replace("env_example = \"apps/web/.env.example\"\n", ""),
    )
    .unwrap();
    let o = w.kb("widget", &["run", "--env", "qa", "true"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(
        stderr(&o).contains(
            "warning: no .env.example found, so every key the environment has is passed (3 keys)"
        ),
        "{}",
        stderr(&o)
    );

    let logs = w.daemon.logs();
    assert!(logs.contains("values for run"), "{logs}");
    assert_no_canary(&w.canary, &logs);
}

#[test]
fn run_passes_signals_on_and_back() {
    use std::io::{BufRead, BufReader};
    use std::os::unix::process::ExitStatusExt;

    let w = World::new();
    assert_eq!(code(&w.kb("widget", &["unlock"])), 0);

    // The child dies by a signal: so does the CLI.
    let o = w.kb("widget", &["run", "sh", "-c", "kill -TERM $$"]);
    assert_eq!(o.status.signal(), Some(libc::SIGTERM), "{}", stderr(&o));

    // SIGTERM to the CLI reaches the child.
    for (sig, name) in [(libc::SIGTERM, "TERM"), (libc::SIGHUP, "HUP")] {
        let mut cli = w
            .command("widget", &["run", "sh", "-c", "echo ready; exec sleep 30"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(cli.stdout.as_mut().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert_eq!(line, "ready\n");
        let kill = Command::new("kill")
            .args([format!("-{name}"), cli.id().to_string()])
            .status()
            .unwrap();
        assert!(kill.success());
        let started = std::time::Instant::now();
        let status = cli.wait().unwrap();
        assert_eq!(status.signal(), Some(sig));
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
    }
}

/// `get` checks the lock before asking for a passphrase, so this needs no
/// terminal; the rest of `get` is covered by the daemon tests.
#[test]
fn get_when_locked_does_not_prompt() {
    let w = World::new();
    let o = w.kb("widget", &["--json", "get", "API_URL"]);
    assert_eq!(code(&o), 5);
    assert_eq!(json_error(&o)["code"], "locked");
}

/// A person may take longer to type the passphrase than the daemon keeps an
/// idle connection open, say to fetch it from a password manager: what the
/// command sends after the prompt still reaches the daemon.
#[test]
fn a_passphrase_typed_slowly_still_reaches_the_daemon() {
    let w = World::with_idle(Duration::from_millis(500));
    w.init_store();
    let slowly = |cmd: &Command, typed: &str| {
        let wait = || std::thread::sleep(Duration::from_millis(1500));
        let (exit, out) = common::on_terminal_after(cmd, "passphrase", wait, typed);
        assert!(!out.contains("lost the connection"), "{out}");
        assert_eq!(exit, 0, "{out}");
        out
    };
    let lock = || {
        let mut client = Client::connect(w.daemon.socket(), DEFAULT_TIMEOUT).unwrap();
        client.request(Request::Lock).unwrap();
    };

    let out = slowly(&w.command("widget", &["get", "API_URL"]), "pw\n");
    assert!(out.contains(w.canary.value()), "the value");

    lock();
    let out = slowly(&w.command("elsewhere", &["unlock"]), "pw\n");
    assert!(out.contains("unlocked"), "{out}");

    w.mark(Request::StoreSet {
        section: "gone.dev".parse().unwrap(),
        key: "LEFT".parse().unwrap(),
        value: WireSecret::new("x".into()),
        passphrase: WireSecret::new("pw".into()),
        sensitive: false,
    });
    let out = slowly(&w.command("elsewhere", &["store", "clear", "gone"]), "pw\n");
    assert!(out.contains("removed [gone.dev] (1 key)"), "{out}");

    // `onboard` unlocks and imports with the one passphrase.
    let root = w.root();
    let blog = root.join("blog");
    fs::create_dir(&blog).unwrap();
    git(&root, &blog, &["init", "-q"]);
    git(
        &root,
        &blog,
        &["remote", "add", "origin", "git@github.com:acme/blog.git"],
    );
    fs::write(blog.join(".env"), "TOKEN=t\n").unwrap();
    lock();
    let out = slowly(&w.command("elsewhere", &["onboard", "../blog"]), "pw\nn\n");
    let o = w.kb("elsewhere", &["store", "list"]);
    assert!(stdout(&o).contains("[blog.dev]"), "{out}\n{}", stdout(&o));
}

/// Prompts are not exercised: they read /dev/tty, which a test must not
/// touch. Writes go straight to the daemon instead.
#[test]
fn store_list_shows_names_only() {
    let w = World::new();
    let o = w.kb("elsewhere", &["store", "list", "--json"]);
    assert_eq!(code(&o), 5);
    assert_eq!(json_error(&o)["code"], "locked");

    let o = w.kb("elsewhere", &["unlock"]);
    assert_eq!((code(&o), stdout(&o).as_str()), (0, "unlocked\n"));
    let o = w.kb("elsewhere", &["store", "list", "--json"]);
    assert_eq!(code(&o), 1);
    let e = json_error(&o);
    assert_eq!(e["code"], "no_store");
    assert_eq!(e["who"], "human");
    assert_eq!(
        e["tell"],
        "create the local store: run `kagebunshin store init` in a terminal"
    );

    w.init_store();
    let mut client = Client::connect(w.daemon.socket(), DEFAULT_TIMEOUT).unwrap();
    let pass = || WireSecret::new("pw".into());
    for (section, key, sensitive) in [
        ("widget.dev", "API_KEY", false),
        ("widget.dev", "DB_URL", true),
        ("widget.qa", "API_KEY", false),
    ] {
        client
            .request(Request::StoreSet {
                section: section.parse().unwrap(),
                key: key.parse().unwrap(),
                value: WireSecret::new(w.canary.value().into()),
                passphrase: pass(),
                sensitive,
            })
            .unwrap();
    }
    let store = w.root().join("config/store.age");
    assert_eq!(
        fs::metadata(&store).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_no_canary(
        &w.canary,
        &String::from_utf8_lossy(&fs::read(&store).unwrap()),
    );

    let o = w.kb("elsewhere", &["store", "list"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(
        stdout(&o),
        "[widget.dev]\n  API_KEY\n  DB_URL (sensitive)\n[widget.qa]\n  API_KEY\n"
    );
    let o = w.kb("elsewhere", &["store", "list", "--json"]);
    let v: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(
        v,
        serde_json::json!({"sections": [
            {"section": "widget.dev", "keys": ["API_KEY", "DB_URL"], "sensitive": ["DB_URL"]},
            {"section": "widget.qa", "keys": ["API_KEY"]},
        ]})
    );

    // A value is never an argument, and a section is <project>.<env>.
    let o = w.kb(
        "elsewhere",
        &["store", "set", "widget.dev", "API_KEY", "oops"],
    );
    assert_eq!(code(&o), 2);
    let o = w.kb("elsewhere", &["store", "unset", "widget", "API_KEY"]);
    assert_eq!(code(&o), 2);
    // Several keys are upper case, so a value in their place is refused
    // without being echoed, before any prompt.
    let o = w.kb(
        "elsewhere",
        &[
            "--json",
            "store",
            "set",
            "widget.dev",
            "API_KEY",
            "DB_URL",
            "oops",
        ],
    );
    assert_eq!(code(&o), 2);
    let e = json_error(&o);
    assert!(
        e["message"]
            .as_str()
            .unwrap()
            .starts_with("argument 4 has lower-case letters"),
        "{e:?}"
    );
    assert!(!stderr(&o).contains("oops"), "{}", stderr(&o));
    let o = w.kb(
        "elsewhere",
        &["--json", "store", "set", "widget.dev", "API_KEY", "API_KEY"],
    );
    assert_eq!(code(&o), 2);
}

/// Sources are removed, moved and deduplicated by number, comments kept;
/// project files hold no sensitive marks to lose.
#[test]
fn project_sources_are_removed_moved_and_deduplicated() {
    let w = World::new();
    let file = w.root().join("config/projects/widget.toml");
    let text = fs::read_to_string(&file).unwrap().replace(
        "[envs.dev]\n",
        "# Dev reads the shared prefix.\n[envs.dev]\n",
    );
    fs::write(&file, &text).unwrap();
    let secrets = || {
        let o = w.kb("elsewhere", &["--json", "project", "show", "widget"]);
        assert_eq!(code(&o), 0, "{}", stderr(&o));
        let v: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
        v["envs"]["dev"]["sources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| {
                s["prefix"]
                    .as_str()
                    .or(s["secret"].as_str())
                    .unwrap()
                    .to_owned()
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(secrets(), ["widget/dev/", "widget/override"]);

    let o = w.kb(
        "elsewhere",
        &["project", "move-source", "widget", "dev", "2", "--to", "1"],
    );
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(
        stdout(&o).starts_with("moved source 2 of environment dev of project widget to 1"),
        "{}",
        stdout(&o)
    );
    assert_eq!(secrets(), ["widget/override", "widget/dev/"]);

    // A copy appended by hand: dedupe keeps the one that wins, the last.
    let text = fs::read_to_string(&file).unwrap().replace(
        "\n[envs.qa]",
        "[[envs.dev.sources]]\nprovider = \"aws_sm\"\nsecret = \"widget/override\"\n\n[envs.qa]",
    );
    fs::write(&file, &text).unwrap();
    assert_eq!(
        secrets(),
        ["widget/override", "widget/dev/", "widget/override"]
    );
    let o = w.kb(
        "elsewhere",
        &["--json", "project", "dedupe", "widget", "dev"],
    );
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let v: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(v["removed"].as_array().unwrap().len(), 1, "{v}");
    assert_eq!(secrets(), ["widget/dev/", "widget/override"]);
    let o = w.kb("elsewhere", &["project", "dedupe", "widget", "dev"]);
    assert_eq!(
        stdout(&o),
        "environment dev of project widget has no duplicate sources\n"
    );

    let o = w.kb(
        "elsewhere",
        &["project", "remove-source", "widget", "dev", "1"],
    );
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(secrets(), ["widget/override"]);
    assert!(
        fs::read_to_string(&file)
            .unwrap()
            .contains("# Dev reads the shared prefix.\n[envs.dev]\n")
    );

    for args in [
        &["project", "remove-source", "widget", "dev", "2"][..],
        &["project", "move-source", "widget", "dev", "1", "--to", "3"],
    ] {
        let mut args = args.to_vec();
        args.insert(0, "--json");
        let o = w.kb("elsewhere", &args);
        assert_eq!(code(&o), 1, "{args:?}");
    }
    assert_eq!(
        code(&w.kb(
            "elsewhere",
            &["project", "remove-source", "widget", "dev", "0"]
        )),
        2
    );
}

/// An edit that starts while another is being written waits for it, then
/// builds on it, rather than writing its own copy of the file over it.
#[test]
fn config_edits_do_not_interleave() {
    let w = World::new();
    let file = w.root().join("config/projects/widget.toml");
    let lock = ConfigDir::new(w.root().join("config")).lock().unwrap();
    let agent = w
        .command(
            "elsewhere",
            &[
                "--json",
                "project",
                "add-source",
                "widget",
                "qa",
                "--provider",
                "aws_sm",
                "--secret",
                "widget/qa2",
            ],
        )
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(300));
    let mut agent = agent;
    assert!(agent.try_wait().unwrap().is_none(), "the edit did not wait");

    // A human's edit, written under the lock.
    let edited = fs::read_to_string(&file).unwrap().replace(
        "[envs.qa]\n",
        "# QA talks to the shared sandbox.\n[envs.qa]\n",
    );
    fs::write(&file, &edited).unwrap();
    drop(lock);

    let o = agent.wait_with_output().unwrap();
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let after = fs::read_to_string(&file).unwrap();
    assert!(
        after.contains("# QA talks to the shared sandbox.\n[envs.qa]\n"),
        "{after}"
    );
    assert!(after.contains("widget/qa2"), "{after}");
}

/// The daemon creates no store, so `store init` writes it: refused over an
/// existing store, before any prompt.
#[test]
fn store_init_is_refused_over_an_existing_store() {
    let w = World::new();
    let store = ConfigDir::new(w.root().join("config")).store_file();
    w.init_store();
    let before = fs::read(&store).unwrap();
    let o = w.kb("elsewhere", &["--json", "store", "init"]);
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert_eq!(json_error(&o)["code"], "store_exists");
    assert_eq!(fs::read(&store).unwrap(), before);
}

#[test]
fn init_agent_prints_the_agent_instructions() {
    let o = kb(&["init"]);
    assert_eq!(code(&o), 2, "init alone needs --agent");
    let o = kb(&["init", "--agent"]);
    assert_eq!(code(&o), 0);
    let text = stdout(&o);
    assert!(text.starts_with("# kagebunshin"), "{text}");
    for needle in [
        "kagebunshin run --",
        "kagebunshin get",
        "kagebunshin unlock",
        "kagebunshin list",
        "kagebunshin next",
        "kagebunshin project add-source",
        "Never",
    ] {
        assert!(text.contains(needle), "{needle}");
    }
    let o = kb(&["init", "--agent", "--skill"]);
    assert_eq!(code(&o), 0);
    let skill = stdout(&o);
    assert!(
        skill.starts_with("---\nname: kagebunshin\ndescription: "),
        "{skill}"
    );
    assert!(
        skill.ends_with(&text),
        "the same instructions after the front matter"
    );
}

#[test]
fn project_commands_write_the_project_file() {
    let w = World::new();
    let file = w.root().join("config/projects/gadget.toml");

    let o = w.kb(
        "elsewhere",
        &[
            "project",
            "init",
            "gadget",
            "--remote",
            "https://github.com/acme/gadget.git",
        ],
    );
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(stdout(&o), "created project gadget with environment dev\n");
    assert_eq!(
        fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    // Once only, and a remote belongs to one project.
    let o = w.kb(
        "elsewhere",
        &[
            "--json",
            "project",
            "init",
            "gadget",
            "--remote",
            "github.com:acme/x",
        ],
    );
    assert_eq!(
        (code(&o), json_error(&o)["code"].as_str()),
        (1, Some("config"))
    );
    let o = w.kb("widget", &["--json", "project", "init", "copy"]);
    assert_eq!(code(&o), 1);
    assert!(
        json_error(&o)["message"]
            .as_str()
            .unwrap()
            .contains("widget")
    );
    assert!(!w.root().join("config/projects/copy.toml").exists());
    // Without --remote, outside a checkout.
    let o = w.kb("elsewhere", &["--json", "project", "init", "loose"]);
    assert_eq!(
        (code(&o), json_error(&o)["code"].as_str()),
        (1, Some("no_project"))
    );

    let add = |args: &[&str]| {
        let mut a = vec!["project", "add-source", "gadget"];
        a.extend_from_slice(args);
        w.kb("elsewhere", &a)
    };
    let o = add(&[
        "dev",
        "--provider",
        "aws_sm",
        "--prefix",
        "gadget/dev/",
        "--profile",
        "acme-dev",
        "--region",
        "eu-west-1",
    ]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stdout(&o).contains("replaces the default source"));
    let o = add(&["dev", "--provider", "file", "--optional"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(!stdout(&o).contains("replaces"));
    let o = w.kb(
        "elsewhere",
        &["project", "add-env", "gadget", "qa", "--profile", "acme-qa"],
    );
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let o = w.kb(
        "elsewhere",
        &["--json", "project", "add-env", "gadget", "qa"],
    );
    assert_eq!(
        (code(&o), json_error(&o)["code"].as_str()),
        (1, Some("config"))
    );

    // Rejected by the schema, and nothing is written.
    let before = fs::read_to_string(&file).unwrap();
    for args in [
        &["qa", "--provider", "file", "--profile", "acme"][..],
        &["qa", "--provider", "aws_sm"],
        &["nope", "--provider", "aws_sm", "--secret", "gadget/x"],
    ] {
        let o = add(args);
        assert_eq!(code(&o), 1, "{args:?}");
    }
    assert_eq!(fs::read_to_string(&file).unwrap(), before);

    let o = w.kb("elsewhere", &["project", "show", "gadget"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(
        stdout(&o),
        r#"schema = 1
remotes = ["github.com/acme/gadget"]

[[envs.dev.sources]]
provider = "aws_sm"
prefix = "gadget/dev/"
profile = "acme-dev"
region = "eu-west-1"

[[envs.dev.sources]]
provider = "file"
optional = true

[envs.qa]
profile = "acme-qa"
"#
    );
    let o = w.kb("elsewhere", &["--json", "project", "show", "nope"]);
    assert_eq!(
        (code(&o), json_error(&o)["code"].as_str()),
        (1, Some("no_project"))
    );

    // The daemon sees the edit at once.
    w.fake.set("gadget.qa", &[("API_URL", w.canary.value())]);
    assert_eq!(code(&w.kb("widget", &["unlock"])), 0);
    let o = w.kb("elsewhere", &["--json", "sync", "gadget", "qa"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
}

#[test]
fn project_list_set_and_set_source() {
    let w = World::new();
    let file = w.root().join("config/projects/gadget.toml");
    let kb = |args: &[&str]| w.kb("elsewhere", args);
    let ok = |args: &[&str]| {
        let o = kb(args);
        assert_eq!(code(&o), 0, "{args:?}: {}", stderr(&o));
        stdout(&o)
    };
    ok(&[
        "project",
        "init",
        "gadget",
        "--remote",
        "github.com/acme/gadget",
    ]);
    let add = ["project", "add-source", "gadget", "dev", "--provider"];
    // Several --secret are one `secrets` list, one is `secret`.
    ok(&[
        &add[..],
        &["aws_sm", "--secret", "gadget/a", "--secret", "gadget/b"],
    ]
    .concat());
    ok(&[&add[..], &["aws_sm", "--secret", "gadget/c"]].concat());
    ok(&[&add[..], &["file"]].concat());
    let o = kb(&[
        &add[..],
        &["aws_sm", "--secret", "a", "--secret", "b", "--key", "K"],
    ]
    .concat());
    assert_eq!(code(&o), 2, "{}", stderr(&o));
    assert!(stderr(&o).contains("--key takes exactly one --secret"));

    let set_source = ["project", "set-source", "gadget", "dev"];
    ok(&[&set_source[..], &["1", "--region", "eu-west-1"]].concat());
    let o = kb(&[&set_source[..], &["3", "--profile", "acme-x"]].concat());
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert!(stderr(&o).contains("only aws_sm sources"), "{}", stderr(&o));
    for args in [
        &[][..],
        &["1"],
        &["--all"],
        &["1", "--all", "--profile", "p"],
    ] {
        let o = kb(&[&set_source[..], args].concat());
        assert_eq!(code(&o), 2, "{args:?}");
    }
    ok(&[&set_source[..], &["--all", "--profile", "acme-qa"]].concat());

    ok(&["project", "set", "gadget", "--profile", "acme-ops"]);
    ok(&[
        "--env",
        "dev",
        "project",
        "set",
        "gadget",
        "--profile",
        "acme-dev",
    ]);
    let o = kb(&[
        "--json",
        "--env",
        "nope",
        "project",
        "set",
        "gadget",
        "--profile",
        "p",
    ]);
    assert_eq!(code(&o), 1, "{}", stderr(&o));
    assert_eq!(
        fs::read_to_string(&file).unwrap(),
        r#"schema = 1
remotes = ["github.com/acme/gadget"]
profile = "acme-ops"

[envs.dev]
profile = "acme-dev"

[[envs.dev.sources]]
provider = "aws_sm"
secrets = ["gadget/a", "gadget/b"]
region = "eu-west-1"
profile = "acme-qa"

[[envs.dev.sources]]
provider = "aws_sm"
secret = "gadget/c"
profile = "acme-qa"

[[envs.dev.sources]]
provider = "file"
"#
    );

    assert_eq!(
        ok(&["project", "list"]),
        "PROJECT  PATH                ENVS           PROVIDERS\n\
         gadget   (whole repository)  dev            aws_sm, file\n\
         widget   (whole repository)  dev, prod, qa  aws_sm, file\n"
    );
    let listed: serde_json::Value =
        serde_json::from_str(&ok(&["--json", "project", "list"])).unwrap();
    assert_eq!(
        listed["projects"][0],
        serde_json::json!({
            "name": "gadget",
            "remotes": ["github.com/acme/gadget"],
            "envs": ["dev"],
            "providers": ["aws_sm", "file"],
        })
    );
}

/// Adding a source that looks like production says the environment waits
/// for a human decision.
#[test]
fn a_production_looking_source_makes_its_environment_wait() {
    let w = World::new();
    assert_eq!(
        code(&w.kb("elsewhere", &["project", "add-env", "widget", "test"])),
        0
    );
    let o = w.kb(
        "elsewhere",
        &[
            "project",
            "add-source",
            "widget",
            "test",
            "--provider",
            "aws_sm",
            "--secret",
            "acme/prod/db",
        ],
    );
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(
        stderr(&o),
        format!(
            "warning: environment test of project widget looks like production (the aws_sm \
             source secret acme/prod/db has the segment prod) {WAIT}test {ASK}\n"
        )
    );
    let add = |secret: &str, profile: &str| {
        w.kb(
            "elsewhere",
            &[
                "--json",
                "project",
                "add-source",
                "widget",
                "qa",
                "--provider",
                "aws_sm",
                "--secret",
                secret,
                "--profile",
                profile,
            ],
        )
    };
    // A secret whose name says qa outweighs its profile's.
    let o = add("acme/qa/db", "acme-prod_admin");
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let v: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert!(v.get("warnings").is_none(), "{v}");
    let o = add("acme/db", "acme-prod_admin");
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let v: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(
        v["warnings"],
        serde_json::json!([format!(
            "environment qa of project widget looks like production (AWS profile \
             acme-prod_admin, used by a source here, has the part prod) {WAIT}qa {ASK}"
        )])
    );
    // A source edit takes effect by itself, so nothing is left to do.
    assert!(v.get("hint").is_none(), "{v}");

    // An exact copy is refused and the file is left as it was.
    let file = w.root().join("config/projects/widget.toml");
    let before = fs::read_to_string(&file).unwrap();
    let o = add("acme/qa/db", "acme-prod_admin");
    assert_eq!(code(&o), 1);
    assert_eq!(
        json_error(&o)["message"],
        "environment qa of project widget already has the aws_sm source secret acme/qa/db; \
         nothing changed"
    );
    assert_eq!(fs::read_to_string(&file).unwrap(), before);

    // One warning per profile, however many sources it covers.
    assert_eq!(code(&add("acme/cache", "acme-ops")), 0);
    let o = w.kb(
        "elsewhere",
        &[
            "--json",
            "project",
            "set-source",
            "widget",
            "qa",
            "--all",
            "--profile",
            "acme-live-prod",
        ],
    );
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let v: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(
        v["warnings"],
        serde_json::json!([format!(
            "environment qa of project widget looks like production (AWS profile \
             acme-live-prod, used by 2 sources here, has the part prod) {WAIT}qa {ASK}"
        )])
    );
}

/// How every production warning goes on after its reason, up to the
/// environment's name, then after it.
const WAIT: &str = "and waits for a human decision; ask the human: open the app (`kagebunshin \
                    app`) and either mark widget/";
const ASK: &str = "sensitive or acknowledge it is not production";

/// The daemon's events and the CLI's own config edits land in one log,
/// which `audit` reads without the daemon: names, never values. A run that
/// needed no approval is in the runs log, which `audit --all` reads too
/// and `status` counts.
#[test]
fn audit_shows_what_was_asked_and_decided() {
    let w = World::new();
    w.mark_prod();
    let o = w.kb("elsewhere", &["status"]);
    assert!(
        stdout(&o).contains("\nruns in the last day: none"),
        "{}",
        stdout(&o)
    );
    assert_eq!(code(&w.kb("widget", &["run", "--", "true"])), 0);
    let o = w.kb("elsewhere", &["status"]);
    let text = stdout(&o);
    let line = text.lines().find(|l| l.starts_with("runs in")).unwrap();
    assert!(
        line.starts_with("runs in the last day: 1 in 1 project, last at ")
            && line.ends_with("Z (widget/dev)"),
        "{line}"
    );
    let o = w.kb("widget", &["status"]);
    let text = stdout(&o);
    let line = text.lines().find(|l| l.starts_with("runs in")).unwrap();
    assert!(
        line.starts_with("runs in the last day: 1, last at ") && line.ends_with('Z'),
        "{line}"
    );
    let o = w.kb("widget", &["status", "--json"]);
    let out: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    let runs = &out["runs"];
    assert_eq!((&runs["count"], &runs["projects"]), (&1.into(), &1.into()));
    assert_eq!(
        (&runs["last"]["project"], &runs["last"]["env"]),
        (&"widget".into(), &"dev".into())
    );
    assert_ne!(
        code(&w.kb("widget", &["--env", "prod", "run", "--", "true"])),
        0
    );
    let o = w.kb(
        "widget",
        &["project", "remove-source", "widget", "dev", "2"],
    );
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(code(&w.kb("widget", &["lock"])), 0);

    let o = w.kb("elsewhere", &["audit", "--json", "--since", "1h"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let out: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    let actions: Vec<String> = out["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            format!(
                "{} {}",
                e["action"].as_str().unwrap(),
                e["decision"].as_str().unwrap()
            )
        })
        .collect();
    // The dev run is left out: it needed no approval.
    assert_eq!(
        actions,
        [
            "lock allowed",
            "unlock allowed",
            "mark env allowed",
            "run denied",
            "project remove-source allowed",
            "lock allowed",
        ]
    );
    assert_eq!(out["unreadable"], 0);
    let mark = &out["events"][2];
    assert_eq!(
        (&mark["project"], &mark["env"]),
        (&"widget".into(), &"prod".into())
    );
    let denied = &out["events"][3];
    assert_eq!(denied["project"], "widget");
    assert_eq!(denied["env"], "prod");
    assert_eq!(denied["program"], "true");

    let o = w.kb("elsewhere", &["audit"]);
    assert_eq!(code(&o), 0);
    let text = stdout(&o);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 6);
    assert!(lines[2].contains("mark env widget/prod"), "{}", lines[2]);
    assert!(
        lines[3].contains(" denied  run widget/prod pid "),
        "{}",
        lines[3]
    );
    assert!(
        lines[4].contains("project remove-source widget/dev"),
        "{}",
        lines[4]
    );

    // With --all the runs log is read too, and the filters hold over both.
    let listed = |args: &[&str]| -> Vec<String> {
        let o = w.kb("elsewhere", &[&["--json", "audit"], args].concat());
        assert_eq!(code(&o), 0, "{}", stderr(&o));
        let out: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
        assert_eq!(out["runs_path"].is_string(), args.contains(&"--all"));
        (out["events"].as_array().unwrap().iter())
            .map(|e| {
                format!(
                    "{} {}",
                    e["action"].as_str().unwrap(),
                    e["decision"].as_str().unwrap()
                )
            })
            .collect()
    };
    assert_eq!(listed(&["--all"]).len(), 7);
    assert_eq!(listed(&["--action", "run"]), ["run denied"]);
    assert_eq!(
        listed(&["--all", "--action", "run", "--env", "dev"]),
        ["run allowed"]
    );
    assert_eq!(
        listed(&["--all", "--project", "widget", "--env", "prod"]),
        ["mark env allowed", "run denied"]
    );
    assert_eq!(listed(&["--all", "--project", "gadget"]).len(), 0);
    let o = w.kb(
        "elsewhere",
        &["audit", "--all", "--action", "run", "--env", "dev"],
    );
    assert!(
        stdout(&o).contains(" allowed run widget/dev pid ") && stdout(&o).contains(" program true"),
        "{}",
        stdout(&o)
    );

    let state = w.root().join("state/kagebunshin");
    for file in ["audit.jsonl", "runs.jsonl"] {
        assert_no_canary(&w.canary, &fs::read_to_string(state.join(file)).unwrap());
    }
    let o = w.kb("elsewhere", &["audit", "--since", "soon"]);
    assert_eq!(code(&o), 2);
}

/// `export` hands over the project file as it is; `import` installs one as
/// a new project, never over an existing one or its remotes.
#[test]
fn export_then_import() {
    let w = World::new();
    let root = w.root();
    let o = w.kb("elsewhere", &["export", "widget"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(stdout(&o), format!("{}\n", WIDGET.trim_end()));
    let o = w.kb("elsewhere", &["export", "widget", "--output", "w.toml"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(
        fs::read_to_string(root.join("elsewhere/w.toml")).unwrap(),
        WIDGET
    );
    assert_eq!(code(&w.kb("elsewhere", &["export", "nope"])), 1);

    // Its remote is widget's.
    let o = w.kb("elsewhere", &["--json", "import", "w.toml"]);
    assert_eq!(code(&o), 1);
    assert!(
        json_error(&o)["message"]
            .as_str()
            .unwrap()
            .contains("widget")
    );
    let o = w.kb(
        "elsewhere",
        &["--json", "import", "w.toml", "--name", "widget"],
    );
    assert_eq!(json_error(&o)["message"], "project widget already exists");

    fs::create_dir_all(root.join("home/.aws")).unwrap();
    fs::write(
        root.join("home/.aws/config"),
        "[profile known]\nregion = eu-west-1\n",
    )
    .unwrap();
    fs::write(
        root.join("elsewhere/gadget.toml"),
        "# handed over\nschema = 1\nremotes = [\"git@github.com:acme/gadget.git\"]\nprofile = \"known\"\n\n[envs.dev]\n[[envs.dev.sources]]\nprovider = \"aws_sm\"\nprefix = \"gadget/dev/\"\nprofile = \"missing\"\n[envs.qa]\n",
    )
    .unwrap();
    let aws = [
        ("AWS_CONFIG_FILE", root.join("home/.aws/config")),
        (
            "AWS_SHARED_CREDENTIALS_FILE",
            root.join("home/.aws/credentials"),
        ),
    ];
    let o = w
        .command("elsewhere", &["--json", "import", "gadget.toml"])
        .envs(aws.clone())
        .output()
        .unwrap();
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let out: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(out["project"], "gadget");
    assert_eq!(
        out["warnings"],
        serde_json::json!(["AWS profile missing is not in your AWS configuration"])
    );
    let written = root.join("config/projects/gadget.toml");
    assert_eq!(
        fs::read_to_string(&written).unwrap(),
        fs::read_to_string(root.join("elsewhere/gadget.toml")).unwrap()
    );
    let o = w.kb("elsewhere", &["project", "show", "gadget"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let o = w.kb("elsewhere", &["--json", "audit"]);
    let log: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(log["events"][0]["action"], "import");
    assert_eq!(log["events"][0]["project"], "gadget");
}

/// `onboard` turns a checkout's `.env` into a project reading the local
/// store, so `run` works and the file can go. Every refusal comes before
/// anything is written, and a wrong passphrase leaves no project behind.
#[test]
fn onboard_moves_a_dot_env_into_the_store() {
    let w = World::new();
    let root = w.root();
    let gadget = root.join("gadget");
    fs::create_dir_all(&gadget).unwrap();
    git(&root, &gadget, &["init", "-q"]);
    let c = w.canary.value();
    let dot_env = format!("# fake values\nAPI_KEY={c}\nexport DB_URL=\"{c}\"\n");
    let project = root.join("config/projects/gadget.toml");

    // No store yet, then no remote.
    let o = w.kb("gadget", &["--json", "onboard"]);
    assert_eq!(json_error(&o)["code"], "no_store");
    w.init_store();
    // The project reads the store whatever the default provider is.
    fs::write(
        root.join("config/config.toml"),
        "schema = 1\ndefault_provider = \"aws_sm\"\n",
    )
    .unwrap();
    let o = w.kb("gadget", &["--json", "onboard"]);
    assert_eq!(json_error(&o)["code"], "no_remote");
    git(
        &root,
        &gadget,
        &["remote", "add", "origin", "git@github.com:acme/gadget.git"],
    );
    fs::write(gadget.join(".env"), &dot_env).unwrap();

    // Locked, a wrong passphrase writes nothing and unlocks nothing.
    let o = w.kb("gadget", &["lock"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let cmd = w.command("gadget", &["onboard"]);
    let (exit, out) = common::on_terminal(&cmd, "nope\n");
    assert_eq!(exit, 1, "{out}");
    assert!(
        out.contains("(to unlock, and to import 1 .env file)"),
        "{out}"
    );
    assert!(out.contains("nothing was written"), "{out}");
    assert_no_canary(&w.canary, &out);
    assert!(!project.exists());
    assert!(gadget.join(".env").exists());
    let o = w.kb("elsewhere", &["--json", "status"]);
    assert!(
        stdout(&o).starts_with(r#"{"locked":true"#),
        "{}",
        stdout(&o)
    );

    let (exit, out) = common::on_terminal(&cmd, "pw\ny\n");
    assert_eq!(exit, 0, "{out}");
    assert_no_canary(&w.canary, &out);
    assert!(
        out.contains("put 2 keys from .env in the local store's [gadget.dev]: API_KEY, DB_URL"),
        "{out}"
    );
    assert!(out.contains("Delete "), "{out}");
    assert!(out.contains("deleted "), "{out}");
    assert!(!gadget.join(".env").exists());
    // The test daemon's sources are fakes, so the store is read directly.
    let store = StoreFile::new(root.join("config/store.age"))
        .open(&WireSecret::new("pw".into()).into_passphrase())
        .unwrap();
    let section = store.section(&"gadget.dev".parse().unwrap()).unwrap();
    let got: Vec<(&str, bool)> = section
        .iter()
        .map(|(k, v)| (k.as_str(), v.expose() == c))
        .collect();
    assert_eq!(got, [("API_KEY", true), ("DB_URL", true)]);
    let toml = fs::read_to_string(&project).unwrap();
    assert!(
        toml.contains("remotes = [\"github.com/acme/gadget\"]"),
        "{toml}"
    );
    let o = w.kb("elsewhere", &["--json", "project", "show", "gadget"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let shown: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    let sources = &shown["envs"]["dev"]["sources"];
    assert_eq!(sources.as_array().map(Vec::len), Some(1), "{shown}");
    assert_eq!(sources[0]["provider"], "file", "{shown}");

    // Onboarding again leaves the project alone, and another name for it
    // is refused.
    fs::write(gadget.join(".env"), &dot_env).unwrap();
    let o = w.kb("gadget", &["--json", "onboard"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let out: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    let p = &out["projects"][0];
    assert_eq!(p["project"], "gadget", "{out}");
    assert!(
        p["note"]
            .as_str()
            .unwrap()
            .contains("already has keys in [gadget.dev]"),
        "{out}"
    );
    let o = w.kb("gadget", &["--json", "onboard", "--name", "other"]);
    let e = json_error(&o);
    assert_eq!(e["code"], "config");
    assert!(
        e["message"]
            .as_str()
            .unwrap()
            .contains("project gadget already claims"),
        "{e:?}"
    );
    assert_eq!(fs::read_to_string(gadget.join(".env")).unwrap(), dot_env);
    assert_no_canary(&w.canary, &w.daemon.logs());
}

/// A checkout with only a `.env`: `status` points the agent at asking the
/// human to run `onboard`, `project init` still works but says so, and
/// `onboard` then fills the project `project init` made.
#[test]
fn onboard_fills_the_project_init_made_in_a_dot_env_checkout() {
    let w = World::new();
    let root = w.root();
    let trap = root.join("trap");
    fs::create_dir_all(&trap).unwrap();
    git(&root, &trap, &["init", "-q"]);
    git(
        &root,
        &trap,
        &["remote", "add", "origin", "git@github.com:acme/trap.git"],
    );
    w.init_store();

    // Without a .env the hint is `next`, or `project init` with the folder's name.
    let o = w.kb("trap", &["status"]);
    assert_eq!(code(&o), 1);
    let err = stderr(&o);
    assert!(
        err.contains("no project claims github.com/acme/trap\nhint: run `kagebunshin next`")
            && err.contains("by hand with `kagebunshin project init trap`"),
        "{err}"
    );
    // An example file holds no values to move.
    fs::write(trap.join(".env.example"), "API_KEY=\n").unwrap();
    fs::write(trap.join(".env"), "# nothing yet\n").unwrap();
    let o = w.kb("trap", &["--json", "status"]);
    let e = json_error(&o);
    assert_eq!(e["code"], "no_project");
    assert!(
        e["hint"]
            .as_str()
            .unwrap()
            .contains("`kagebunshin project init trap`")
    );

    let c = w.canary.value();
    let dot_env = format!("API_KEY={c}\nDB_URL={c}\n");
    fs::write(trap.join(".env"), &dot_env).unwrap();
    let o = w.kb("trap", &["--json", "status"]);
    let e = json_error(&o);
    assert_eq!(e["code"], "no_project");
    let message = e["message"].as_str().unwrap();
    assert!(!message.contains("project init"), "{message}");
    let hint = e["hint"].as_str().unwrap();
    let onboard = format!("`kagebunshin onboard {}`", trap.display());
    assert!(hint.contains(&onboard), "{hint}");
    assert!(hint.contains("once a person approves that"), "{hint}");

    let o = w.kb("trap", &["project", "init", "trap"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let out = stdout(&o);
    assert!(
        out.starts_with("created project trap with environment dev"),
        "{out}"
    );
    assert!(out.contains(&onboard), "{out}");

    let cmd = w.command("trap", &["onboard"]);
    let (exit, out) = common::on_terminal(&cmd, "pw\nn\n");
    assert_eq!(exit, 0, "{out}");
    assert_no_canary(&w.canary, &out);
    assert!(
        out.contains(
            "used the existing project trap, whose environment dev reads the local store, and \
             put 2 keys from .env in the local store's [trap.dev]: API_KEY, DB_URL"
        ),
        "{out}"
    );
    let store = StoreFile::new(root.join("config/store.age"))
        .open(&WireSecret::new("pw".into()).into_passphrase())
        .unwrap();
    let section = store.section(&"trap.dev".parse().unwrap()).unwrap();
    assert_eq!(section.iter().count(), 2);

    // Again: the section has keys now, so the project is left alone.
    let note = |args: &[&str]| -> String {
        let o = w.kb("trap", args);
        assert_eq!(code(&o), 0, "{}", stderr(&o));
        let out: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
        out["projects"][0]["note"].as_str().unwrap().to_owned()
    };
    let n = note(&["--json", "onboard"]);
    assert!(n.contains("already has keys in [trap.dev]"), "{n}");

    // An environment with sources of its own is not filled.
    let o = w.kb("trap", &["project", "add-env", "trap", "qa"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let o = w.kb(
        "trap",
        &[
            "project",
            "add-source",
            "trap",
            "qa",
            "--provider",
            "aws_sm",
            "--secret",
            "trap/qa",
        ],
    );
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let n = note(&["--json", "--env", "qa", "onboard"]);
    assert!(n.contains("has sources other than"), "{n}");
    // Nor one it does not have, nor under another name.
    let n = note(&["--json", "--env", "stage", "onboard"]);
    let by_file = format!(
        "`kagebunshin onboard --file {} --env stage`",
        trap.join(".env").display()
    );
    assert!(n.contains(&by_file), "{n}");
    let o = w.kb("trap", &["--json", "onboard", "--name", "other"]);
    let e = json_error(&o);
    assert!(
        e["message"]
            .as_str()
            .unwrap()
            .contains("project trap already claims"),
        "{e:?}"
    );
    // --name names one project.
    let o = w.kb("trap", &["--json", "onboard", ".", "..", "--name", "x"]);
    assert_eq!(code(&o), 2, "{}", stderr(&o));
    assert_eq!(json_error(&o)["code"], "usage");
    assert_eq!(fs::read_to_string(trap.join(".env")).unwrap(), dot_env);
    assert_no_canary(&w.canary, &w.daemon.logs());
}

/// `project remove` deletes the file, refused while the store holds a
/// human's decision about the project or the daemon cannot say; it leaves
/// the store's keys, which `store clear` removes, and drops the daemon's
/// cached values.
#[test]
fn project_remove_checks_the_store_and_drops_the_cache() {
    let w = World::new();
    let root = w.root();
    let file = root.join("config/projects/widget.toml");
    let remove = |args: &[&str]| w.kb("elsewhere", args);

    // Stopped, then locked: whether anything is marked is unknown.
    let socket = no_daemon(&root.join("elsewhere"));
    let o = Command::new(env!("CARGO_BIN_EXE_kagebunshin"))
        .args([
            "--json",
            "--socket",
            sock(&socket),
            "project",
            "remove",
            "widget",
        ])
        .current_dir(root.join("elsewhere"))
        .env("KAGEBUNSHIN_CONFIG_DIR", root.join("config"))
        .env("XDG_STATE_HOME", root.join("state"))
        .output()
        .unwrap();
    let e = json_error(&o);
    assert!(
        e["message"]
            .as_str()
            .unwrap()
            .starts_with("the daemon is not running"),
        "{e:?}"
    );
    assert_eq!(e["who"], "human");
    assert!(e["tell"].as_str().unwrap().contains("kagebunshin daemon"));
    let o = remove(&["--json", "project", "remove", "widget"]);
    let e = json_error(&o);
    assert!(
        e["message"]
            .as_str()
            .unwrap()
            .starts_with("the daemon is locked"),
        "{e:?}"
    );
    assert_eq!(
        (code(&o), &e["code"], &e["who"]),
        (5, &"locked".into(), &"human".into())
    );
    assert!(e["tell"].as_str().unwrap().contains("`kagebunshin unlock`"));
    assert!(file.exists());

    // Marked sensitive, then acknowledged as not production.
    w.mark_prod();
    let o = remove(&["project", "remove", "widget"]);
    assert_eq!(code(&o), 5, "{}", stderr(&o));
    let err = stderr(&o);
    assert!(
        err.contains("environment prod is marked sensitive"),
        "{err}"
    );
    assert!(err.contains("`kagebunshin app`"), "{err}");
    let prod = |sensitive| Request::MarkEnv {
        project: "widget".parse().unwrap(),
        env: "prod".parse().unwrap(),
        sensitive,
        also: Vec::new(),
        passphrase: WireSecret::new("pw".into()),
    };
    let ack = |acknowledged| Request::AcknowledgeEnv {
        project: "widget".parse().unwrap(),
        env: "qa".parse().unwrap(),
        acknowledged,
        unmark: Vec::new(),
        passphrase: WireSecret::new("pw".into()),
    };
    w.mark(prod(false));
    w.mark(ack(true));
    let o = remove(&["project", "remove", "widget"]);
    assert_eq!(code(&o), 5, "{}", stderr(&o));
    assert!(
        stderr(&o).contains("environment qa is acknowledged as not production"),
        "{}",
        stderr(&o)
    );
    w.mark(ack(false));
    assert!(file.exists());

    // Values fetched before the removal are not served to a project made
    // again under the name.
    w.mark(Request::StoreSet {
        section: "widget.dev".parse().unwrap(),
        key: "LEFT".parse().unwrap(),
        value: WireSecret::new("x".into()),
        passphrase: WireSecret::new("pw".into()),
        sensitive: false,
    });
    let o = w.kb("widget", &["status"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let fetches = w.fake.fetches();
    let o = remove(&["project", "remove", "widget"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let out = stdout(&o);
    assert!(out.starts_with("removed project widget"), "{out}");
    assert!(
        out.contains(
            "\nits values are still in the local store: [widget.dev] (1 key)\n\
             to remove them, run `kagebunshin store clear widget` in a terminal"
        ),
        "{out}"
    );
    assert!(!file.exists());
    let o = w.kb("widget", &["--json", "status"]);
    assert_eq!(json_error(&o)["code"], "no_project");

    // `store clear` removes what it left, naming it before the passphrase,
    // and asks for nothing when nothing is there.
    let clear = w.command("elsewhere", &["store", "clear", "widget"]);
    let (exit, out) = common::on_terminal(&clear, "pw\n");
    assert_eq!(exit, 0, "{out}");
    let asked = out.find("Passphrase").unwrap();
    let named = out
        .find("this removes [widget.dev] (1 key) from the local store")
        .unwrap();
    assert!(named < asked, "{out}");
    assert!(out.contains("\nremoved [widget.dev] (1 key)\n"), "{out}");
    let o = w.kb("elsewhere", &["store", "list"]);
    assert_eq!(stdout(&o), "the local store is empty\n");
    let o = w.kb("elsewhere", &["--json", "store", "clear", "widget"]);
    let e = json_error(&o);
    assert_eq!((code(&o), &e["code"]), (1, &"store".into()), "{e:?}");
    assert_eq!(
        e["message"],
        "the local store has no section of project widget"
    );

    fs::write(&file, WIDGET).unwrap();
    let o = w.kb("widget", &["status"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(w.fake.fetches() > fetches);
    // Not while the project is there: its environments read the values.
    let o = w.kb("elsewhere", &["store", "clear", "widget"]);
    assert_eq!(code(&o), 5, "{}", stderr(&o));
    assert!(
        stderr(&o).contains("project widget is still there"),
        "{}",
        stderr(&o)
    );

    let o = remove(&["--json", "project", "remove", "nope"]);
    assert_eq!(json_error(&o)["code"], "no_project");
}

/// The agent hooks: a session in a registered project is told so, and
/// writing a real env file there is refused. Anything else, and anything
/// that goes wrong, is no answer and exit 0.
#[test]
fn hooks_tell_the_agent_and_refuse_env_writes_in_a_project() {
    use std::io::Write;
    let w = World::new();
    let root = w.root();
    let hook_on = |socket: &Path, event: &str, input: serde_json::Value| {
        // As `World::command`, with this socket.
        let base = w.command("elsewhere", &[]);
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_kagebunshin"));
        cmd.args(["--socket", sock(socket), "hook", event])
            .current_dir(base.get_current_dir().unwrap());
        for (k, v) in base.get_envs() {
            match v {
                Some(v) => cmd.env(k, v),
                None => cmd.env_remove(k),
            };
        }
        let mut child = cmd
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.to_string().as_bytes())
            .unwrap();
        let o = child.wait_with_output().unwrap();
        assert_eq!(code(&o), 0, "{}", stderr(&o));
        stdout(&o)
    };
    let hook = |event: &str, input| hook_on(w.daemon.socket(), event, input);
    let answer = |out: String| -> serde_json::Value {
        serde_json::from_str::<serde_json::Value>(&out).unwrap()["hookSpecificOutput"].clone()
    };

    let out = answer(hook(
        "session-start",
        serde_json::json!({ "cwd": root.join("widget/apps") }),
    ));
    assert_eq!(out["hookEventName"], "SessionStart");
    let context = out["additionalContext"].as_str().unwrap();
    assert!(context.contains("project widget"), "{context}");
    assert!(context.contains("kagebunshin run --"), "{context}");
    // The daemon is locked, then unlocked, then not running.
    assert!(
        context.contains("daemon is locked") && context.contains("`kagebunshin unlock`"),
        "{context}"
    );
    w.init_store();
    let in_widget = serde_json::json!({ "cwd": root.join("widget") });
    let context = answer(hook("session-start", in_widget.clone()))["additionalContext"].clone();
    let context = context.as_str().unwrap();
    assert!(context.contains("project widget"), "{context}");
    assert!(!context.contains("daemon is"), "{context}");
    // Never proven: it says what to do.
    assert!(context.contains("`kagebunshin next`"), "{context}");
    let stopped = no_daemon(&root.join("elsewhere"));
    let context =
        answer(hook_on(&stopped, "session-start", in_widget))["additionalContext"].clone();
    let context = context.as_str().unwrap();
    assert!(context.contains("daemon is not running"), "{context}");

    // In no project: silent, unless there is an env file or an example.
    let unregistered = serde_json::json!({ "cwd": root.join("elsewhere") });
    assert_eq!(hook("session-start", unregistered.clone()), "");
    fs::write(root.join("elsewhere/.env.example"), "A=\n").unwrap();
    let context = answer(hook("session-start", unregistered.clone()))["additionalContext"].clone();
    let context = context.as_str().unwrap();
    assert!(
        context.ends_with("run `kagebunshin next` and do what it says."),
        "{context}"
    );
    assert!(!context.contains("onboard"), "{context}");
    fs::write(root.join("elsewhere/.env"), "A=1\n").unwrap();
    let context = answer(hook("session-start", unregistered))["additionalContext"].clone();
    let context = context.as_str().unwrap();
    assert!(
        context.contains(".env here has values: do not read it.")
            && !context.contains("onboard")
            && context.ends_with("run `kagebunshin next` and do what it says."),
        "{context}"
    );

    let write = |tool: &str, file: &str| {
        serde_json::json!({
            "cwd": root.join("widget"),
            "tool_name": tool,
            "tool_input": { "file_path": file, "content": "SECRET=x" },
        })
    };
    for (tool, file) in [
        ("Write", "apps/web/.env"),
        ("Edit", ".env.local"),
        // In a folder that does not exist yet.
        ("Write", "new/dir/.env"),
    ] {
        let out = answer(hook("pre-tool-use", write(tool, file)));
        assert_eq!(out["permissionDecision"], "deny", "{file}");
        let reason = out["permissionDecisionReason"].as_str().unwrap();
        assert!(reason.contains("kagebunshin run --"), "{reason}");
    }
    let shell = |dir: &str, command: &str| {
        serde_json::json!({
            "cwd": root.join(dir),
            "tool_name": "Bash",
            "tool_input": { "command": command },
        })
    };
    for command in [
        "cp .env.example .env",
        "echo \"A=1\" > apps/web/.env",
        "cd apps/web && cp .env.example .env.local",
    ] {
        let out = answer(hook("pre-tool-use", shell("widget", command)));
        assert_eq!(out["permissionDecision"], "deny", "{command}");
        let reason = out["permissionDecisionReason"].as_str().unwrap();
        assert!(reason.contains("kagebunshin run --"), "{reason}");
    }
    for input in [
        shell("widget", "cat .env"),
        shell("widget", "grep FOO apps/web/.env.example"),
        shell("widget", "git add apps/web/.env.example"),
        shell("widget", "echo A= >> apps/web/.env.example"),
        shell("elsewhere", "cp .env.example .env"),
    ] {
        assert_eq!(hook("pre-tool-use", input.clone()), "", "{input}");
    }
    let outside = root.join("elsewhere/.env");
    for input in [
        write("Write", "apps/web/.env.example"),
        write("Write", "src/main.rs"),
        write("Bash", ".env"),
        write("Write", outside.to_str().unwrap()),
        serde_json::json!("not the input"),
    ] {
        assert_eq!(hook("pre-tool-use", input.clone()), "", "{input}");
    }
    assert!(!root.join("widget/.env").exists());
}

/// `setup --no-service` creates the config directory and the store, asking
/// for the passphrase twice, and unlocks the running daemon. Run again it
/// checks the passphrase before touching anything.
#[test]
fn setup_creates_the_store_and_unlocks() {
    let w = World::new();
    let config = w.root().join("config");
    fs::remove_dir_all(&config).unwrap();
    let last_json = |out: &str| -> serde_json::Value {
        serde_json::from_str(out.lines().rfind(|l| l.starts_with('{')).unwrap()).unwrap()
    };

    let cmd = w.command("elsewhere", &["--json", "setup", "--no-service"]);
    let (exit, out) = common::on_terminal(&cmd, "pw\npw\n");
    assert_eq!(exit, 0, "{out}");
    let v = last_json(&out);
    assert_eq!(v["store"], "created", "{v}");
    assert!(v["unit"].is_null(), "{v}");
    assert_eq!(
        fs::metadata(&config).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let store = config.join("store.age");
    let before = fs::read(&store).unwrap();
    let o = w.kb("elsewhere", &["status"]);
    assert_eq!(stdout(&o), "daemon: unlocked\nruns in the last day: none\n");

    // A wrong passphrase leaves the store and the daemon as they were.
    assert_eq!(code(&w.kb("elsewhere", &["lock"])), 0);
    let (exit, out) = common::on_terminal(&cmd, "nope\n");
    assert_eq!(exit, 1, "{out}");
    assert!(out.contains("passphrase"), "{out}");
    assert_eq!(fs::read(&store).unwrap(), before);
    assert!(stdout(&w.kb("elsewhere", &["status"])).starts_with("daemon: locked\n"));

    let (exit, out) = common::on_terminal(&cmd, "pw\n");
    assert_eq!(exit, 0, "{out}");
    assert_eq!(last_json(&out)["store"], "existing");
    assert_eq!(
        stdout(&w.kb("elsewhere", &["status"])),
        "daemon: unlocked\nruns in the last day: none\n"
    );

    // Mismatched new passphrases create nothing.
    fs::remove_file(&store).unwrap();
    let (exit, out) = common::on_terminal(&cmd, "pw\nother\n");
    assert_eq!(exit, 1, "{out}");
    assert!(out.contains("do not match"), "{out}");
    assert!(!store.exists());

    // No daemon answering: the store is made, but setup says it is locked.
    let tmp = tempfile::tempdir().unwrap();
    let socket = no_daemon(tmp.path());
    let mut cmd = w.command("elsewhere", &["--json", "setup", "--no-service"]);
    cmd.args(["--socket", sock(&socket)]);
    let (exit, out) = common::on_terminal(&cmd, "pw\npw\n");
    assert_eq!(exit, 3, "{out}");
    assert!(out.contains("daemon_not_running"), "{out}");
    assert!(store.exists());
}

/// With the service, `setup` also puts the app in the launcher and at
/// login, for the socket it set the service up on. The setup that makes
/// the store starts the app in the tray; a later one restarts an app that
/// runs, as it does the daemon, and starts none. The service manager here
/// is a fake that only logs, and the test stands in for the app.
#[test]
#[cfg(target_os = "linux")]
fn setup_installs_the_service_and_the_apps_launcher() {
    let w = World::new();
    let root = w.root();
    fs::remove_dir_all(root.join("config")).unwrap();
    let bin = root.join("fakebin");
    fs::create_dir_all(&bin).unwrap();
    let log = root.join("service.log");
    for (name, body) in [
        ("systemctl", format!("echo \"$*\" >> '{}'\n", log.display())),
        (
            "systemd-run",
            format!("echo \"systemd-run $*\" >> '{}'\n", log.display()),
        ),
        // Found on PATH, unless a built one is next to the CLI.
        ("kagebunshin-app", String::new()),
    ] {
        fs::write(bin.join(name), format!("#!/bin/sh\n{body}")).unwrap();
        fs::set_permissions(bin.join(name), fs::Permissions::from_mode(0o755)).unwrap();
    }
    let app_socket = w.daemon.socket().with_file_name("app.sock");
    let mut cmd = w.command("elsewhere", &["--json", "setup"]);
    cmd.env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .env("WAYLAND_DISPLAY", "wayland-7")
        .env_remove("DISPLAY");
    let last_json = |out: &str| -> serde_json::Value {
        serde_json::from_str(out.lines().rfind(|l| l.starts_with('{')).unwrap()).unwrap()
    };

    // The first setup, with no app running: it is started as a unit, and
    // setup goes on once it answers.
    let (app, (exit, out)) = std::thread::scope(|s| {
        let app = s.spawn(|| {
            let start = std::time::Instant::now();
            while !fs::read_to_string(&log).is_ok_and(|l| l.contains("systemd-run")) {
                assert!(start.elapsed().as_secs() < 30, "the app was never started");
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            std::os::unix::net::UnixListener::bind(&app_socket).unwrap()
        });
        let done = common::on_terminal(&cmd, "pw\npw\n");
        (app.join().unwrap(), done)
    });
    assert_eq!(exit, 0, "{out}");
    let v = last_json(&out);
    assert_eq!(
        (&v["store"], &v["app_started"]),
        (&"created".into(), &true.into()),
        "{v}"
    );
    assert_eq!(v["app_restarted"], false, "{v}");
    let started = fs::read_to_string(&log).unwrap();
    assert!(
        started.contains("systemd-run --user --quiet --collect --unit=kagebunshin-app.service")
            && started.contains("--setenv=WAYLAND_DISPLAY=wayland-7"),
        "{started}"
    );
    assert!(
        !started.contains("restart kagebunshin-app.service"),
        "{started}"
    );

    // A later setup restarts the one that runs.
    fs::remove_file(&log).unwrap();
    let (exit, out) = common::on_terminal(&cmd, "pw\n");
    assert_eq!(exit, 0, "{out}");
    let v = last_json(&out);
    assert_eq!(v["app_restarted"], true, "{v}");
    assert_eq!(v["app_started"], false, "{v}");
    assert!(
        fs::read_to_string(&log)
            .unwrap()
            .ends_with("--user restart kagebunshin-app.service\n")
    );
    drop(app);
    let home = root.join("home");
    assert_eq!(
        v["unit"],
        home.join(".config/systemd/user/kagebunshin.service")
            .to_str()
            .unwrap(),
        "{v}"
    );
    assert!(
        fs::read_to_string(&log)
            .unwrap()
            .contains("--user restart kagebunshin.service")
    );
    const ID: &str = "io.github.oorestisime.kagebunshin";
    let files = [
        home.join(format!(".local/share/applications/{ID}.desktop")),
        home.join(format!(".config/autostart/{ID}.desktop")),
        home.join(format!(".local/share/icons/hicolor/scalable/apps/{ID}.svg")),
    ];
    let listed: Vec<_> = v["launcher"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["path"].as_str().unwrap())
        .collect();
    assert_eq!(listed, files.each_ref().map(|p| p.to_str().unwrap()), "{v}");
    let login = fs::read_to_string(&files[1]).unwrap();
    let exec = format!(
        "kagebunshin\" --socket \"{}\" app --hidden\n",
        sock(w.daemon.socket())
    );
    assert!(login.contains(&exec), "{login}");
    assert_eq!(
        stdout(&w.kb("elsewhere", &["status"])),
        "daemon: unlocked\nruns in the last day: none\n"
    );

    // With none running, a later setup starts none: its person ended it.
    fs::remove_file(&log).unwrap();
    let (exit, out) = common::on_terminal(&cmd, "pw\n");
    assert_eq!(exit, 0, "{out}");
    let v = last_json(&out);
    assert_eq!(
        (&v["app_restarted"], &v["app_started"]),
        (&false.into(), &false.into()),
        "{v}"
    );
    assert!(!fs::read_to_string(&log).unwrap().contains("systemd-run"));

    // Without the service, neither is written.
    for f in &files {
        fs::remove_file(f).unwrap();
    }
    let cmd = w.command("elsewhere", &["--json", "setup", "--no-service"]);
    let (exit, out) = common::on_terminal(&cmd, "pw\n");
    assert_eq!(exit, 0, "{out}");
    assert!(files.iter().all(|f| !f.exists()), "{out}");
}

/// `daemon install --files-only` writes a unit that runs this binary on the
/// socket it resolved, `status` sees it, and `uninstall` removes it. The
/// system's own checker accepts the unit; in CI it must be there.
#[test]
fn daemon_install_writes_a_unit_for_this_binary() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().canonicalize().unwrap();
    let socket = home.join("run/kagebunshind.sock");
    let kb = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_kagebunshin"))
            .args(args)
            .arg("--socket")
            .arg(&socket)
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .output()
            .unwrap()
    };
    #[cfg(target_os = "linux")]
    let (unit, checker) = (
        home.join(".config/systemd/user/kagebunshin.service"),
        ["systemd-analyze", "verify"],
    );
    #[cfg(target_os = "macos")]
    let (unit, checker) = (
        home.join("Library/LaunchAgents/io.github.oorestisime.kagebunshin.plist"),
        ["plutil", "-lint"],
    );

    let o = kb(&["--json", "daemon", "status"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let out: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(out["installed"], false);
    assert_eq!(out["answering"], false);

    let o = kb(&["--json", "daemon", "install", "--files-only"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let out: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(out["unit"], unit.to_str().unwrap());
    assert_eq!(out["started"], false);
    let text = fs::read_to_string(&unit).unwrap();
    let exe = Path::new(env!("CARGO_BIN_EXE_kagebunshin"))
        .canonicalize()
        .unwrap();
    assert!(text.contains(exe.to_str().unwrap()), "{text}");
    assert!(text.contains(socket.to_str().unwrap()), "{text}");
    assert_eq!(
        fs::metadata(&unit).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let o = kb(&["--json", "daemon", "status"]);
    let out: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(
        (&out["installed"], &out["current"]),
        (&true.into(), &true.into())
    );
    // Another socket is another unit.
    let o = Command::new(env!("CARGO_BIN_EXE_kagebunshin"))
        .args([
            "--json",
            "daemon",
            "status",
            "--socket",
            "/tmp/elsewhere.sock",
        ])
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .output()
        .unwrap();
    let out: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(out["current"], false);

    match Command::new(checker[0]).arg(checker[1]).arg(&unit).output() {
        Ok(o) => assert!(
            o.status.success(),
            "{}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        ),
        Err(e) => assert!(std::env::var_os("CI").is_none(), "{}: {e}", checker[0]),
    }

    let o = kb(&["daemon", "uninstall", "--files-only"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(!unit.exists());
    let o = kb(&["daemon", "uninstall", "--files-only"]);
    assert_eq!(code(&o), 0);
    assert!(stdout(&o).starts_with("not installed"));
}

#[test]
fn list_and_search_show_names_and_keys_only() {
    let w = World::new();

    // Locked: AWS lists, the local store is said not to have been.
    let o = w.kb("elsewhere", &["list"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(
        stdout(&o),
        "3 matches
  widget/dev/app   aws_sm  API_URL, DB_PASSWORD
  widget/override  aws_sm  DB_PASSWORD, EXTRA
  widget/qa        aws_sm  API_URL, DB_PASSWORD, MISSING_KEY
"
    );
    assert!(stderr(&o).contains("warning: file: not searched while the daemon is locked"));
    // One provider asked, and it cannot be listed while locked: a refusal.
    let o = w.kb("elsewhere", &["--json", "list", "--provider", "proton"]);
    assert_eq!(code(&o), 5, "{}", stderr(&o));
    assert_eq!(json_error(&o)["code"], "locked");

    assert_eq!(code(&w.kb("elsewhere", &["unlock"])), 0);
    let o = w.kb("elsewhere", &["search", "missing"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(
        stdout(&o).starts_with("1 match\n  widget/qa "),
        "{}",
        stdout(&o)
    );
    assert_eq!(
        stderr(&o),
        "",
        "no store and no Proton token: skipped quietly"
    );

    let o = w.kb(
        "elsewhere",
        &[
            "--json",
            "list",
            "--provider",
            "aws_sm",
            "--prefix",
            "widget/dev/",
        ],
    );
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let v: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(
        v,
        serde_json::json!({
            "items": [{
                "id": {"provider": "aws_sm", "location": "widget/dev/app"},
                "name": "widget/dev/app",
                "keys": ["API_URL", "DB_PASSWORD"],
            }],
            "warnings": [],
        })
    );

    assert_eq!(code(&w.kb("elsewhere", &["list", "--prefix", "a b"])), 2);
}

/// Stands in for `opencode`: loads the plugin, then for each call runs the
/// tool hook (when the call has an input) and the permission hook, as
/// version 2 does, and prints the effect each permission ends with.
const OPENCODE_DRIVER: &str = r#"
const [plugin, dir, calls] = process.argv.slice(2)
const hooks = {}
const on = (domain) => ({
  hook: async (name, f) => void (hooks[`${domain}.${name}`] ??= []).push(f),
})
const { default: p } = await import(plugin)
await p.setup({
  location: { directory: dir },
  session: on("session"),
  tool: on("tool"),
  permission: on("permission"),
})
const effects = []
for (const [i, call] of JSON.parse(calls).entries()) {
  const id = `call_${i}`
  if (call.input) {
    for (const f of hooks["tool.execute.before"] ?? []) await f({ tool: "shell", id, input: call.input })
  }
  const event = {
    action: call.action,
    resources: call.resources,
    source: { type: "tool", id },
    effect: "allow",
  }
  for (const f of hooks["permission.evaluate"] ?? []) await f(event)
  effects.push(event.effect)
}
console.log(JSON.stringify(effects))
"#;

/// The `opencode` plugin under node. Its shell permission names the
/// call's simple commands one by one, without its `cd`s or its working
/// folder, so a `.env` written in a project's folder from a session
/// started elsewhere is refused only if the plugin checks the whole call.
#[test]
fn the_opencode_plugin_checks_a_shell_call_in_its_own_folder() {
    let runs = |program: &str| {
        Command::new(program)
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success())
    };
    let Some(node) = ["node", "bun"].into_iter().find(|p| runs(p)) else {
        eprintln!("skipped: no node or bun here to run the plugin");
        return;
    };
    let w = World::new();
    let root = w.root();
    let o = w.kb("elsewhere", &["hook", "install", "opencode"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    // `.mjs`, so an older node takes it as a module too.
    fs::copy(
        root.join("home/.config/opencode/plugins/kagebunshin.js"),
        root.join("plugin.mjs"),
    )
    .unwrap();
    fs::write(root.join("driver.mjs"), OPENCODE_DRIVER).unwrap();

    let web = root.join("widget/apps/web");
    let shell = |command: &str, workdir: Option<&Path>, resources: &[&str]| {
        serde_json::json!({
            "action": "shell",
            "input": { "command": command, "workdir": workdir },
            "resources": resources,
        })
    };
    let calls = serde_json::json!([
        shell("cd ../widget && echo \"A=1\" > .env", None, &["echo \"A=1\" > .env"]),
        shell("cp .env.example .env.local", Some(&web), &["cp .env.example .env.local"]),
        // In the session's own folder, which is in no project.
        shell("echo \"A=1\" > .env", None, &["echo \"A=1\" > .env"]),
        shell("cd ../widget && cat .env", None, &["cat .env"]),
        // No tool hook ran: the permission's own commands are checked.
        { "action": "shell", "resources": ["echo A=1 > ../widget/.env"] },
        { "action": "edit", "resources": ["../widget/.env"] },
        { "action": "edit", "resources": ["../widget/.env.example"] },
    ]);
    let base = w.command("elsewhere", &[]);
    let mut cmd = Command::new(node);
    cmd.args(["driver.mjs", "./plugin.mjs"])
        .arg(root.join("elsewhere"))
        .arg(calls.to_string())
        .current_dir(&root)
        .env("KAGEBUNSHIN_SOCKET", w.daemon.socket());
    for (k, v) in base.get_envs() {
        if let Some(v) = v {
            cmd.env(k, v);
        }
    }
    let o = cmd.output().unwrap();
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let effects: Vec<String> = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(
        effects,
        ["deny", "deny", "allow", "allow", "deny", "deny", "allow"]
    );
    assert!(!root.join("widget/.env").exists());
}
