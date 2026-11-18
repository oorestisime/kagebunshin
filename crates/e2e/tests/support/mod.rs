//! A sandboxed machine: a fresh HOME, the real daemon and CLI binaries, AWS
//! answered by [`aws::Aws`], and nothing of the developer's environment.
//! [`Walk`] runs commands on it as the agent or the human would, and keeps
//! what each printed.

#![allow(dead_code, reason = "not every test binary uses every helper")]

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

pub mod aws;
#[path = "../../../kagebunshin/tests/common/mod.rs"]
mod common;

use aws::Aws;
use kagebunshin::test_support::FakePassCli;

/// The local store's passphrase.
pub const PASS: &str = "trial-passphrase-1";
/// Every value a sandbox holds has this in it; none may be printed where an
/// agent reads.
pub const CANARY: &str = "CANARY";
/// How long one command may take before the test gives up on it.
const DEADLINE: Duration = Duration::from_secs(120);

/// A binary this workspace builds, next to the test's own, and up to date:
/// `cargo test` builds only what the tests link, not the binaries they run.
pub fn bin(name: &str) -> PathBuf {
    static BUILT: OnceLock<()> = OnceLock::new();
    let exe = std::env::current_exe().unwrap();
    // target/<profile>/deps/<test>
    let profile = exe.parent().unwrap().parent().unwrap();
    BUILT.get_or_init(|| {
        let mut cargo = Command::new(env!("CARGO"));
        cargo
            .args(["build", "--workspace", "--bins", "--quiet"])
            .arg("--manifest-path")
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml"))
            .arg("--target-dir")
            .arg(profile.parent().unwrap());
        match profile.file_name().unwrap().to_str().unwrap() {
            "debug" => {}
            name => {
                cargo.args(["--profile", name]);
            }
        }
        assert!(
            cargo.status().unwrap().success(),
            "the workspace's binaries do not build"
        );
    });
    profile.join(name)
}

pub struct Sandbox {
    tmp: tempfile::TempDir,
    pub aws: Aws,
    /// The `pass-cli` that answers for Proton Pass, if one does.
    pass_cli: Option<PathBuf>,
    daemon: Option<Child>,
}

impl Sandbox {
    /// A machine with AWS profiles `acme-dev` and `acme-prod` that reach
    /// `secrets`, and the daemon running with no store yet.
    pub fn start(secrets: &[(&str, &str)]) -> Self {
        let mut tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        // To look at what a failing test left: its logs and screenshots.
        if std::env::var_os("KAGEBUNSHIN_E2E_KEEP").is_some() {
            tmp.disable_cleanup(true);
            #[expect(clippy::print_stderr, reason = "where to look is for the developer")]
            {
                eprintln!("the sandbox is kept at {}", root.display());
            }
        }
        for dir in ["home/.aws", "run", "work"] {
            fs::create_dir_all(root.join(dir)).unwrap();
        }
        fs::set_permissions(root.join("run"), fs::Permissions::from_mode(0o700)).unwrap();
        let aws = Aws::start(&root, secrets);
        let (id, key) = aws.keys();
        let region = aws::REGION;
        fs::write(
            root.join("home/.aws/config"),
            format!(
                "[profile acme-dev]\nregion = {region}\n\n[profile acme-prod]\nregion = {region}\n"
            ),
        )
        .unwrap();
        fs::write(
            root.join("home/.aws/credentials"),
            format!(
                "[acme-dev]\naws_access_key_id = {id}\naws_secret_access_key = {key}\n\n\
                 [acme-prod]\naws_access_key_id = {id}\naws_secret_access_key = {key}\n"
            ),
        )
        .unwrap();
        let mut sb = Self {
            tmp,
            aws,
            pass_cli: None,
            daemon: None,
        };
        sb.start_daemon();
        sb
    }

    /// As [`Sandbox::start`], after the human has run `setup`: the store
    /// exists and the daemon is unlocked.
    pub fn ready(secrets: &[(&str, &str)]) -> Self {
        let sb = Self::start(secrets);
        let (code, out) = sb.human(
            &sb.root(),
            &format!("{PASS}\n{PASS}\n"),
            "kagebunshin setup --no-service",
        );
        assert_eq!(code, 0, "{out}");
        sb
    }

    /// A checkout of `acme/<name>` at `work/<name>`.
    pub fn checkout(&self, name: &str) -> PathBuf {
        let dir = self.root().join("work").join(name);
        fs::create_dir_all(&dir).unwrap();
        git(&dir, &["init", "-q"]);
        let origin = format!("git@github.com:acme/{name}.git");
        git(&dir, &["remote", "add", "origin", &origin]);
        dir
    }

    pub fn root(&self) -> PathBuf {
        self.tmp.path().canonicalize().unwrap()
    }

    pub fn socket(&self) -> PathBuf {
        self.root().join("run/kb.sock")
    }

    /// `program` in `dir`, with only this machine's environment: the
    /// workspace's binaries first on a `PATH` of system directories only, so
    /// what the developer has installed changes nothing.
    pub fn command(&self, program: &str, dir: &Path) -> Command {
        let root = self.root();
        let home = root.join("home");
        let mut path = bin("kagebunshin").parent().unwrap().as_os_str().to_owned();
        path.push(":/usr/bin:/bin");
        let mut cmd = Command::new(program);
        cmd.current_dir(dir)
            .env_clear()
            .env("PATH", path)
            .env("T", &root)
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env("XDG_STATE_HOME", home.join(".local/state"))
            .env("XDG_DATA_HOME", home.join(".local/share"))
            .env("XDG_RUNTIME_DIR", root.join("run"))
            .env("KAGEBUNSHIN_SOCKET", self.socket())
            .env("AWS_CONFIG_FILE", home.join(".aws/config"))
            .env("AWS_SHARED_CREDENTIALS_FILE", home.join(".aws/credentials"))
            .env("AWS_ENDPOINT_URL", self.aws.endpoint())
            .env("AWS_EC2_METADATA_DISABLED", "true")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CEILING_DIRECTORIES", &root);
        if let Some(pass_cli) = &self.pass_cli {
            cmd.env("KAGEBUNSHIN_PASS_CLI", pass_cli);
        }
        if let Some(ca) = self.aws.ca() {
            // The AWS SDK takes its trusted roots from here.
            cmd.env("SSL_CERT_FILE", ca);
        }
        cmd
    }

    /// The CLI in `dir`.
    pub fn kb(&self, dir: &Path) -> Command {
        self.command(bin("kagebunshin").to_str().unwrap(), dir)
    }

    /// `sh -c script` in `dir`.
    pub fn sh(&self, dir: &Path, script: &str) -> Command {
        let mut cmd = self.command("sh", dir);
        cmd.args(["-c", script]);
        cmd
    }

    pub fn start_daemon(&mut self) {
        let root = self.root();
        let log = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(root.join("daemon.log"))
            .unwrap();
        let child = self
            .kb(&root)
            .args(["daemon", "run"])
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap();
        self.daemon = Some(child);
        let start = Instant::now();
        while !self.ok(&root, "kagebunshin daemon ping") {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "the daemon did not start: {}",
                self.daemon_log()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// From now on Proton Pass is the returned fake `pass-cli`, which logs
    /// in with `token` only. The daemon is started again, locked.
    pub fn proton(&mut self, token: &str) -> FakePassCli {
        let root = self.root().join("proton");
        fs::create_dir_all(&root).unwrap();
        let fake = FakePassCli::new(&root, token);
        self.stop_daemon();
        self.pass_cli = Some(fake.bin());
        self.start_daemon();
        fake
    }

    pub fn stop_daemon(&mut self) {
        if let Some(mut d) = self.daemon.take() {
            let _ = d.kill();
            let _ = d.wait();
        }
    }

    pub fn daemon_log(&self) -> String {
        fs::read_to_string(self.root().join("daemon.log")).unwrap_or_default()
    }

    /// Waits until the audit log says `action` was allowed on
    /// `project`/`env`. The app can close before the daemon is done with
    /// what was clicked in it: checking the passphrase takes a while.
    pub fn audited(&self, action: &str, project: &str, env: &str) {
        let log = self
            .root()
            .join("home/.local/state/kagebunshin/audit.jsonl");
        let start = Instant::now();
        loop {
            let text = fs::read_to_string(&log).unwrap_or_default();
            let done = text
                .lines()
                .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
                .any(|e| {
                    e["action"] == action
                        && e["decision"] == "allowed"
                        && e["project"] == project
                        && e["env"] == env
                });
            if done {
                return;
            }
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "no `{action}` of {project}/{env} in the audit log:\n{text}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Whether `script` succeeds, with its output dropped.
    pub fn ok(&self, dir: &Path, script: &str) -> bool {
        self.sh(dir, script)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    }

    /// `script` as an agent runs it: no terminal. Returns the exit code and
    /// what it printed, stdout and stderr together.
    pub fn agent(&self, dir: &Path, script: &str) -> (i32, String) {
        let mut cmd = self.sh(dir, &format!("exec 2>&1\n{script}"));
        no_terminal(&mut cmd);
        let mut child = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let reader = std::thread::spawn(move || {
            let mut out = String::new();
            let _ = stdout.read_to_string(&mut out);
            out
        });
        let start = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if start.elapsed() > DEADLINE {
                let _ = child.kill();
                panic!("`{script}` did not end");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        (status.code().unwrap_or(-1), reader.join().unwrap())
    }

    /// `script` as a person at a terminal, who types `typed` at its first
    /// passphrase prompt. Returns the exit code and what the terminal showed.
    pub fn human(&self, dir: &Path, typed: &str, script: &str) -> (i32, String) {
        let cmd = self.sh(dir, script);
        // Typed once the prompt is up and the terminal has stopped echoing,
        // so that what is typed never shows.
        let (code, out) = common::on_terminal_after(
            &cmd,
            "passphrase",
            || std::thread::sleep(Duration::from_millis(200)),
            typed,
        );
        (code, out)
    }

    /// The app, headless, as a window opened in `dir` and left open for
    /// `seconds`, doing what `script` says: a list of
    /// `{"t": seconds, "type": "click", "key": …}` and
    /// `{"t": seconds, "type": "type", "text": …}`.
    pub fn app(&self, dir: &Path, seconds: f32, script: Option<&serde_json::Value>) -> Child {
        let root = self.root();
        let shots = root.join("shots");
        fs::create_dir_all(&shots).unwrap();
        let n = fs::read_dir(&shots).unwrap().count();
        let log = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(root.join("app.log"))
            .unwrap();
        let mut cmd = self.command(bin("kagebunshin-app").to_str().unwrap(), dir);
        cmd.arg("--snap")
            .arg(shots.join(format!("{n}.png")))
            .args(["--realtime", "--at", &seconds.to_string()])
            .args(["--theme", "dark", "--size", "980x640"])
            .arg("--socket")
            .arg(self.socket());
        if let Some(script) = script {
            let file = shots.join(format!("{n}.json"));
            fs::write(&file, script.to_string()).unwrap();
            cmd.arg("--script").arg(file);
        }
        cmd.stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap()
    }

    /// Waits until the daemon counts the app as closed: it still counts as
    /// open for a few seconds after it ended, unless it ended mid-request.
    pub fn app_closed(&self) {
        use kagebunshin::ipc::client::Client;
        use kagebunshin::ipc::protocol::{Request, Response};
        let start = Instant::now();
        loop {
            let mut client = Client::connect(&self.socket(), Duration::from_secs(5)).unwrap();
            let Response::Status(report) = client.request(Request::Status { facts: None }).unwrap()
            else {
                panic!("no status");
            };
            if !report.app {
                return;
            }
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "the daemon still counts the app as open"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        self.stop_daemon();
    }
}

/// Takes the terminal the tests were started from away from `cmd`. The CLI
/// prompts at /dev/tty, not stdin, so without this a command that prompts
/// would wait at the developer's own terminal.
fn no_terminal(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;
    #[expect(
        unsafe_code,
        reason = "std has no stable way to start a child in its own session"
    )]
    // SAFETY: `setsid` is async-signal-safe, and the closure allocates
    // nothing and touches no state of the parent.
    unsafe {
        cmd.pre_exec(|| match libc::setsid() {
            -1 => Err(std::io::Error::last_os_error()),
            _ => Ok(()),
        });
    }
}

pub fn git(dir: &Path, args: &[&str]) {
    let ok = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["-c", "user.email=a@b", "-c", "user.name=a"])
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .stdout(Stdio::null())
        .status()
        .unwrap()
        .success();
    assert!(ok, "git {args:?}");
}

/// What a walk through the product printed, in sections.
pub struct Walk {
    pub sb: Sandbox,
    cwd: PathBuf,
    sections: Vec<(String, String)>,
}

impl Walk {
    pub fn new(sb: Sandbox) -> Self {
        let cwd = sb.root();
        Self {
            sb,
            cwd,
            sections: Vec::new(),
        }
    }

    /// Starts a section; `name` is its snapshot's name.
    pub fn sec(&mut self, name: &str, title: &str) {
        self.sections
            .push((name.to_owned(), format!("######## {title}\n")));
    }

    /// Adds `text` to the open section as it is.
    pub fn say(&mut self, text: &str) {
        let (_, section) = self.sections.last_mut().expect("a section is open");
        section.push_str(text);
        if !text.ends_with('\n') {
            section.push('\n');
        }
    }

    pub fn note(&mut self, text: &str) {
        self.say(&format!("\n-- {text}"));
    }

    /// Moves to `dir`, relative to the sandbox's root.
    pub fn cd(&mut self, dir: &str) {
        self.cwd = self.sb.root().join(dir);
        fs::create_dir_all(&self.cwd).unwrap();
    }

    /// The agent runs `cmd`: no terminal. Returns its exit code.
    pub fn r(&mut self, cmd: &str) -> i32 {
        let (code, out) = self.sb.agent(&self.cwd, cmd);
        let mut text = format!("\n$ {cmd}\n{out}");
        if !text.ends_with('\n') {
            text.push('\n');
        }
        if code != 0 {
            text.push_str(&format!("[exit {code}]\n"));
        }
        self.say(&text);
        code
    }

    /// The human runs `cmd` at a terminal and types `typed` at its prompts.
    pub fn h(&mut self, typed: &str, cmd: &str) -> i32 {
        let (code, out) = self.sb.human(&self.cwd, typed, cmd);
        let mut text = format!("\n(human) $ {cmd}\n{out}");
        if !text.ends_with('\n') {
            text.push('\n');
        }
        if code != 0 {
            text.push_str(&format!("[exit {code}]\n"));
        }
        // What the human typed is theirs to see, and no part of what
        // kagebunshin said.
        for line in typed.lines().filter(|l| l.len() > 3) {
            text = text.replace(line, "");
        }
        self.say(&text);
        code
    }

    /// What an agent harness's hook tells the agent: `start` when a session
    /// starts in this folder, `bash COMMAND` before a shell command, `write
    /// PATH` before a file is written.
    pub fn hook(&mut self, kind: &str, arg: &str) {
        let cwd = self.cwd.to_str().unwrap().to_owned();
        let (event, input) = match kind {
            "start" => (
                "session-start",
                serde_json::json!({ "hook_event_name": "SessionStart", "cwd": cwd, "source": "startup" }),
            ),
            "bash" => (
                "pre-tool-use",
                serde_json::json!({
                    "hook_event_name": "PreToolUse", "cwd": cwd, "tool_name": "Bash",
                    "tool_input": { "command": arg },
                }),
            ),
            "write" => (
                "pre-tool-use",
                serde_json::json!({
                    "hook_event_name": "PreToolUse", "cwd": cwd, "tool_name": "Write",
                    "tool_input": { "file_path": self.cwd.join(arg), "content": "A=1" },
                }),
            ),
            other => panic!("no hook {other}"),
        };
        let mut child = self
            .sb
            .kb(&self.cwd)
            .args(["hook", event])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        (child.stdin.take().unwrap())
            .write_all(input.to_string().as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        let stdout = String::from_utf8(out.stdout).unwrap();
        let told = if stdout.trim().is_empty() {
            "(nothing: the hook stays out of the way)".to_owned()
        } else {
            let reply: serde_json::Value = serde_json::from_str(&stdout).unwrap();
            let o = &reply["hookSpecificOutput"];
            match o["permissionDecision"].as_str() {
                Some(decision) => format!(
                    "{}: {}",
                    decision.to_uppercase(),
                    o["permissionDecisionReason"].as_str().unwrap_or_default()
                ),
                None => o["additionalContext"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
            }
        };
        let stderr = String::from_utf8(out.stderr).unwrap();
        let what = format!("{kind} {arg}");
        self.say(&format!("\n(hook) {}\n{told}\n{stderr}", what.trim_end()));
    }

    /// The last section's text, checked: no value was printed where the
    /// agent reads, and none is in the daemon's log.
    pub fn transcript(&self) -> String {
        let (_, text) = self.sections().pop().expect("a section is open");
        assert!(!text.contains(CANARY), "a value was printed:\n{text}");
        assert!(
            !self.sb.daemon_log().contains(CANARY),
            "a value in the daemon's log"
        );
        text
    }

    /// The sections, name and text, with what differs from run to run
    /// replaced: the sandbox's folder, times, the day and process ids.
    pub fn sections(&self) -> Vec<(String, String)> {
        let root = self.sb.root();
        let root = root.to_str().unwrap();
        self.sections
            .iter()
            .map(|(name, text)| {
                let text = text.replace(root, "$T");
                let lines: Vec<String> = text.lines().map(stable).collect();
                (name.clone(), lines.join("\n") + "\n")
            })
            .collect()
    }
}

/// `line` with an audit line's time, the time a source was last checked, the
/// day a command ran with the keys and every `pid N` replaced.
fn stable(line: &str) -> String {
    let b = line.as_bytes();
    // 2026-11-15 06:29:43Z
    let shape = b"dddd-dd-dd dd:dd:ddZ";
    let timed = b.len() >= shape.len()
        && shape.iter().zip(b).all(|(s, c)| match s {
            b'd' => c.is_ascii_digit(),
            other => c == other,
        });
    let mut line = if timed {
        format!("<time>{}", &line[shape.len()..])
    } else {
        line.to_owned()
    };
    // checked 08:15:03 UTC
    if let Some(at) = line.find("checked ") {
        let time = at + "checked ".len();
        let shape = b"dd:dd:dd UTC";
        let b = &line.as_bytes()[time..];
        if b.len() >= shape.len()
            && shape.iter().zip(b).all(|(s, c)| match s {
                b'd' => c.is_ascii_digit(),
                other => c == other,
            })
        {
            line.replace_range(time..time + 8, "<time>");
        }
    }
    // ran with them on 15 Nov
    let mut from = 0;
    while let Some(at) = line[from..].find("ran with them on ") {
        let day = from + at + "ran with them on ".len();
        let digits = line[day..].bytes().take_while(u8::is_ascii_digit).count();
        let month = line[day + digits..]
            .strip_prefix(' ')
            .map_or(0, |m| m.bytes().take_while(u8::is_ascii_alphabetic).count());
        if digits > 0 && month == 3 {
            line.replace_range(day..day + digits + 1 + month, "<day>");
        }
        from = day;
    }
    let mut from = 0;
    while let Some(at) = line[from..].find("pid ") {
        let digits = from + at + 4;
        let len = line[digits..]
            .bytes()
            .take_while(u8::is_ascii_digit)
            .count();
        if len > 0 {
            line.replace_range(digits..digits + len, "<n>");
        }
        from = digits;
    }
    line
}
