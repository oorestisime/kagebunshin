//! `kagebunshin connect`, against fakes only: AWS is a local HTTP server
//! and a fake `aws` CLI on PATH, Proton a fake `pass-cli`, so nothing
//! reaches real AWS or Proton or reads the developer's configuration.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test code")]

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

mod common;

fn tmp() -> tempfile::TempDir {
    tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap()
}

fn script(path: &Path, body: &str) {
    fs::write(path, format!("#!/bin/sh\n{body}")).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// Answers every Secrets Manager call with an empty list; counts them.
fn fake_secrets_manager() -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(conn) = conn else { return };
            let counted = counted.clone();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(conn.try_clone().unwrap());
                let mut conn = conn;
                loop {
                    let mut len = 0;
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).unwrap_or(0) == 0 {
                            return;
                        }
                        if line == "\r\n" {
                            break;
                        }
                        if let Some((k, v)) = line.split_once(':')
                            && k.eq_ignore_ascii_case("content-length")
                        {
                            len = v.trim().parse().unwrap();
                        }
                    }
                    let mut body = vec![0; len];
                    reader.read_exact(&mut body).unwrap();
                    counted.fetch_add(1, Ordering::SeqCst);
                    let reply = r#"{"SecretList":[]}"#;
                    let _ = write!(
                        conn,
                        "HTTP/1.1 200 OK\r\ncontent-type: application/x-amz-json-1.1\r\ncontent-length: {}\r\n\r\n{reply}",
                        reply.len()
                    );
                }
            });
        }
    });
    (url, calls)
}

struct Aws {
    _dir: tempfile::TempDir,
    root: PathBuf,
    endpoint: String,
    calls: Arc<AtomicUsize>,
}

impl Aws {
    /// Profiles `a` (static keys) and `b`, whose credentials appear only
    /// once the fake `aws login --profile b` has run.
    fn new() -> Self {
        let dir = tmp();
        let root = dir.path().to_owned();
        let bin = root.join("bin");
        fs::create_dir(&bin).unwrap();
        let logged_in = root.join("logged-in");
        script(
            &root.join("creds"),
            &format!(
                "[ -e '{}' ] || {{ echo expired >&2; exit 1; }}\n\
                 echo '{{\"Version\":1,\"AccessKeyId\":\"AKIDFAKE\",\"SecretAccessKey\":\"fake\"}}'\n",
                logged_in.display()
            ),
        );
        script(
            &bin.join("aws"),
            &format!(
                "echo \"$@\" >> '{}'\ntouch '{}'\n",
                root.join("aws-calls").display(),
                logged_in.display()
            ),
        );
        fs::write(
            root.join("config"),
            format!(
                "[profile a]\nregion = eu-west-1\naws_access_key_id = AKIDFAKE\naws_secret_access_key = fake\n\n\
                 [profile b]\nregion = eu-west-1\ncredential_process = {}\n",
                root.join("creds").display()
            ),
        )
        .unwrap();
        fs::write(root.join("credentials"), "").unwrap();
        let (endpoint, calls) = fake_secrets_manager();
        Self {
            _dir: dir,
            root,
            endpoint,
            calls,
        }
    }

    fn kb(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_kagebunshin"));
        let path = format!(
            "{}:{}",
            self.root.join("bin").display(),
            std::env::var("PATH").unwrap()
        );
        cmd.args(args)
            .env_clear()
            .env("PATH", path)
            .env("HOME", self.root.join("home"))
            .env("KAGEBUNSHIN_CONFIG_DIR", self.root.join("kb"))
            .env("XDG_STATE_HOME", self.root.join("state"))
            .env("AWS_CONFIG_FILE", self.root.join("config"))
            .env("AWS_SHARED_CREDENTIALS_FILE", self.root.join("credentials"))
            .env("AWS_ENDPOINT_URL_SECRETS_MANAGER", &self.endpoint)
            .env("AWS_EC2_METADATA_DISABLED", "true");
        cmd
    }

    fn aws_calls(&self) -> String {
        fs::read_to_string(self.root.join("aws-calls")).unwrap_or_default()
    }

    fn config_toml(&self) -> String {
        fs::read_to_string(self.root.join("kb/config.toml")).unwrap_or_default()
    }
}

#[test]
fn connect_aws_picks_a_profile_logs_in_and_saves_it() {
    let aws = Aws::new();
    let (code, out) =
        common::on_terminal_at(&aws.kb(&["connect", "aws"]), "AWS profile [1-2]", "2\n");
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("1) a") && out.contains("2) b"), "{out}");
    assert!(out.contains("connected AWS profile b"), "{out}");
    assert_eq!(aws.aws_calls(), "login --profile b\n");
    assert!(aws.calls.load(Ordering::SeqCst) >= 1);
    assert_eq!(aws.config_toml(), "schema = 1\n\n[aws]\nprofile = \"b\"\n");

    // Already logged in: no login, and the region is saved too.
    let (code, out) = common::on_terminal_at(
        &aws.kb(&["connect", "aws", "--profile", "a", "--region", "us-east-1"]),
        "",
        "",
    );
    assert_eq!(code, 0, "{out}");
    assert_eq!(aws.aws_calls(), "login --profile b\n");
    assert!(
        aws.config_toml()
            .contains("[aws]\nprofile = \"a\"\nregion = \"us-east-1\"\n"),
        "{}",
        aws.config_toml()
    );
}

#[test]
fn connect_aws_without_a_terminal_never_asks_or_logs_in() {
    let aws = Aws::new();
    let out = aws.kb(&["--json", "connect", "aws"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err: serde_json::Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(err["message"], "several AWS profiles: a, b");
    assert_eq!(err["hint"], "pick one with --profile");

    let out = aws
        .kb(&["--json", "connect", "aws", "--profile", "b"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let err: serde_json::Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(err["code"], "needs_login");
    assert!(
        err["hint"]
            .as_str()
            .unwrap()
            .contains("aws login --profile b"),
        "{err}"
    );
    assert_eq!(aws.aws_calls(), "", "never logs in without a terminal");

    let out = aws
        .kb(&["--json", "connect", "aws", "--profile", "nope"])
        .output()
        .unwrap();
    let err: serde_json::Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(err["code"], "aws_profile");
    assert_eq!(aws.config_toml(), "", "nothing saved");

    let out = aws
        .kb(&["--json", "connect", "aws", "--profile", "a"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let ok: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(ok["profile"], "a");
}

/// A daemon over a store with passphrase `pw`, and a fake `pass-cli` that
/// takes only `pst_<canary>`.
struct Proton {
    _dir: tempfile::TempDir,
    root: PathBuf,
    canary: kagebunshin::test_support::Canary,
    fake: kagebunshin::test_support::FakePassCli,
    store: kagebunshin::store::StoreFile,
    daemon: kagebunshin::test_support::TestDaemon,
}

impl Proton {
    fn new() -> Self {
        use kagebunshin::test_support::{Canary, FakePassCli, TestDaemon};
        let dir = tmp();
        let root = dir.path().canonicalize().unwrap();
        for d in ["pass", "home", "data", "kb"] {
            fs::create_dir(root.join(d)).unwrap();
        }
        let canary = Canary::new();
        let fake = FakePassCli::new(&root.join("pass"), &format!("pst_{}", canary.value()));
        fake.vault("widget", "S1").vault("global", "S2");
        let store =
            kagebunshin::store::StoreFile::new(root.join("kb/store.age")).with_test_work_factor();
        store
            .create(&kagebunshin::store::Passphrase::new("pw".into()))
            .unwrap();
        let config = kagebunshin::config::ConfigDir::new(root.join("kb"));
        // The daemon runs pass-cli, with the session where the CLI says.
        let cli = kagebunshin::source::proton::PassCli {
            bin: fake.bin(),
            session_dir: Some(root.join("data/kagebunshin/proton")),
            key_provider: "fs".into(),
        };
        let daemon = kagebunshin::daemon::Daemon::new(
            Box::new(move || kagebunshin::config::Registry::load(&config)),
            std::sync::Arc::new(kagebunshin::daemon::Providers::new().with_proton(cli)),
            store.clone(),
        );
        let cfg = kagebunshin::ipc::server::ServerConfig::new(root.join("sock/kagebunshind.sock"));
        let daemon = TestDaemon::start_with_daemon(cfg, daemon).unwrap();
        Self {
            _dir: dir,
            root,
            canary,
            fake,
            store,
            daemon,
        }
    }

    /// `sh -c script` with the CLI as `$KB`, isolated like [`Aws::kb`].
    fn sh(&self, script: &str) -> Command {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", script])
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap())
            .env("KB", env!("CARGO_BIN_EXE_kagebunshin"))
            .env("HOME", self.root.join("home"))
            .env("XDG_DATA_HOME", self.root.join("data"))
            .env("KAGEBUNSHIN_CONFIG_DIR", self.root.join("kb"))
            .env("XDG_STATE_HOME", self.root.join("state"))
            .env("KAGEBUNSHIN_SOCKET", self.daemon.socket())
            .env("KAGEBUNSHIN_PASS_CLI", self.fake.bin())
            // Outside any checkout: not this repository's.
            .env("GIT_CEILING_DIRECTORIES", &self.root)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1");
        cmd
    }

    fn saved(&self) -> Option<(String, Option<u64>)> {
        let st = self
            .store
            .open(&kagebunshin::store::Passphrase::new("pw".into()))
            .unwrap();
        st.proton_token()
            .map(|t| (t.token.expose().to_owned(), t.expires))
    }

    fn clean(&self, out: &str) {
        kagebunshin::test_support::assert_no_canary(&self.canary, out);
        let calls = self.fake.calls();
        kagebunshin::test_support::assert_no_canary(&self.canary, &calls);
        assert!(!calls.contains("token-in-env"), "{calls}");
    }
}

#[test]
fn connect_proton_takes_the_token_on_stdin_or_from_the_environment() {
    let p = Proton::new();
    let session = p.root.join("data/kagebunshin/proton");

    // On stdin, with the passphrase at the terminal.
    let mut cmd = p.sh(r#"printf '%s\n' "$T" | "$KB" connect proton --expires 2027-01-31"#);
    cmd.env("T", &p.fake.token);
    let (code, out) = common::on_terminal(&cmd, "pw\n");
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("the token reads 2 vaults"), "{out}");
    p.clean(&out);
    assert_eq!(p.saved(), Some((p.fake.token.clone(), Some(1_801_353_600))));
    // pass-cli logged in beside kagebunshin's own session directory, which
    // the new session then became.
    assert_eq!(p.fake.env(), format!("{}.staging fs", session.display()));
    assert!(session.join("session").exists());
    let mode = fs::metadata(&session).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o700);
    assert_eq!(p.fake.calls(), "login\nvault list --output json\n");

    // From the environment, as JSON; it replaces the first.
    let mut cmd = p.sh(r#""$KB" --json connect proton < /dev/null"#);
    cmd.env("KAGEBUNSHIN_PROTON_TOKEN", &p.fake.token);
    let (code, out) = common::on_terminal(&cmd, "pw\n");
    assert_eq!(code, 0, "{out}");
    p.clean(&out);
    let json = out.lines().find(|l| l.starts_with('{')).unwrap();
    let ok: serde_json::Value = serde_json::from_str(json).unwrap();
    assert_eq!(ok["vaults"], 2);
    assert_eq!(ok["change"], "replaced");
    assert_eq!(p.saved(), Some((p.fake.token.clone(), None)));

    // Once connected, a wrong passphrase or a refused token changes
    // neither the saved token nor the session pass-cli is using.
    let before = fs::read_dir(session.parent().unwrap()).unwrap().count();
    let mut cmd = p.sh(r#""$KB" connect proton < /dev/null"#);
    cmd.env("KAGEBUNSHIN_PROTON_TOKEN", &p.fake.token);
    let (code, out) = common::on_terminal(&cmd, "nope\n");
    assert_ne!(code, 0, "{out}");
    p.clean(&out);
    let mut cmd = p.sh(r#""$KB" --json connect proton < /dev/null"#);
    cmd.env(
        "KAGEBUNSHIN_PROTON_TOKEN",
        format!("pst_wrong{}", p.canary.value()),
    );
    let (code, out) = common::on_terminal(&cmd, "pw\n");
    assert_eq!(code, 1, "{out}");
    p.clean(&out);
    assert!(out.contains("\"code\":\"needs_login\""), "{out}");
    assert_eq!(p.saved(), Some((p.fake.token.clone(), None)));
    assert!(session.join("session").exists());
    assert_eq!(
        fs::read_dir(session.parent().unwrap()).unwrap().count(),
        before,
        "a staging or old session was left"
    );
}

#[test]
fn connect_proton_refuses_a_bad_token_and_a_missing_pass_cli() {
    let p = Proton::new();

    let mut cmd = p.sh(r#"printf '%s' "$T" | "$KB" connect proton"#);
    let wrong = format!("pst_wrong{}", p.canary.value());
    cmd.env("T", &wrong);
    let (code, out) = common::on_terminal(&cmd, "pw\n");
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("Proton refused the token"), "{out}");
    p.clean(&out);
    assert_eq!(p.saved(), None, "nothing saved");

    // The right token, the wrong passphrase.
    let mut cmd = p.sh(r#"printf '%s' "$T" | "$KB" connect proton"#);
    cmd.env("T", &p.fake.token);
    let (code, out) = common::on_terminal(&cmd, "nope\n");
    assert_ne!(code, 0, "{out}");
    p.clean(&out);
    assert_eq!(p.saved(), None, "nothing saved");

    // No pass-cli and no terminal: says how to install it, asks nothing.
    let out = p
        .sh(r#"printf x | "$KB" --json connect proton"#)
        .env("KAGEBUNSHIN_PASS_CLI", p.root.join("no-pass-cli"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let err: serde_json::Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(err["code"], "pass_cli");
    let hint = err["hint"].as_str().unwrap();
    assert!(
        hint.contains("proton.me/download/pass-cli/install.sh")
            && hint.contains("KAGEBUNSHIN_PASS_CLI"),
        "{hint}"
    );
}

#[test]
fn status_warns_before_the_proton_token_expires() {
    let p = Proton::new();
    let soon =
        kagebunshin::source::proton::format_date(kagebunshin::source::unix_now() + 5 * 86_400);
    let mut cmd = p.sh(r#"printf '%s' "$T" | "$KB" connect proton --expires "$D""#);
    cmd.env("T", &p.fake.token).env("D", &soon);
    let (code, out) = common::on_terminal(&cmd, "pw\n");
    assert_eq!(code, 0, "{out}");
    let (code, out) = common::on_terminal(&p.sh(r#"cd "$HOME" && "$KB" unlock"#), "pw\n");
    assert_eq!(code, 0, "{out}");

    let out = p.sh(r#"cd "$HOME" && "$KB" status"#).output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        out.status.success(),
        "{text}{out:?}",
        out = String::from_utf8_lossy(&out.stderr)
    );
    p.clean(&text);
    let want = format!(
        "warning: the Proton Pass token expires in 4 days ({soon}); make a new one and run `kagebunshin connect proton`"
    );
    assert!(text.contains(&want), "{text}");

    // `list` shows an item's title and provider; its raw id only in --json.
    p.fake.api_key(
        "S1",
        "i1",
        "Stripe",
        "API key",
        "STRIPE_KEY",
        p.canary.value(),
    );
    let out = p
        .sh(r#"cd "$HOME" && "$KB" list --provider proton"#)
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    p.clean(&text);
    assert_eq!(
        text,
        "1 match\n  widget/STRIPE_KEY  item i1  proton  STRIPE_KEY\n"
    );

    let out = p
        .sh(r#"cd "$HOME" && "$KB" --json status"#)
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["expiring"][0]["provider"], "proton");
    assert_eq!(v["providers"][0]["provider"], "proton");

    // Far off: no warning.
    let mut cmd = p.sh(r#"printf '%s' "$T" | "$KB" connect proton --expires 2099-01-01"#);
    cmd.env("T", &p.fake.token);
    assert_eq!(common::on_terminal(&cmd, "pw\n").0, 0);
    let out = p.sh(r#"cd "$HOME" && "$KB" status"#).output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(!text.contains("warning"), "{text}");
}
