//! End to end, the way a person sets kagebunshin up for a coding agent: a
//! fresh HOME, the real daemon binary and a fake AWS Secrets Manager
//! endpoint. The human creates the store and the project; the agent looks
//! up secret names, adds a source and runs a command with the values.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test code")]

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kagebunshin::config::ConfigDir;
use kagebunshin::ipc::client::{Client, DEFAULT_TIMEOUT};
use kagebunshin::ipc::protocol::{Request, WireSecret};
use kagebunshin::store::StoreFile;
use kagebunshin::test_support::{Canary, assert_no_canary};

mod common;

/// Answers `ListSecrets` with every secret it holds (the client filters the
/// names again, as with AWS's loose name filter) and `GetSecretValue` with
/// one value. Records each request's `X-Amz-Target`.
struct FakeAws {
    url: String,
    targets: Arc<Mutex<Vec<String>>>,
}

impl FakeAws {
    fn start(secrets: Vec<(&'static str, String)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let targets = Arc::new(Mutex::new(Vec::new()));
        let seen = targets.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let (mut target, mut len) = (String::new(), 0);
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    let (name, value) = line.split_once(':').unwrap_or((&line, ""));
                    match name.to_ascii_lowercase().as_str() {
                        "x-amz-target" => value.trim().clone_into(&mut target),
                        "content-length" => len = value.trim().parse().unwrap(),
                        _ => {}
                    }
                }
                let mut body = vec![0; len];
                reader.read_exact(&mut body).unwrap();
                let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
                seen.lock().unwrap().push(target.clone());
                let (status, reply) = match target.as_str() {
                    "secretsmanager.ListSecrets" => {
                        let list: Vec<_> = secrets
                            .iter()
                            .map(|(name, _)| {
                                serde_json::json!({
                                    "Name": name,
                                    "ARN": format!("arn:aws:secretsmanager:eu-west-1:123456789012:secret:{name}-AbCdEf"),
                                })
                            })
                            .collect();
                        ("200 OK", serde_json::json!({ "SecretList": list }))
                    }
                    "secretsmanager.GetSecretValue" => {
                        let id = body["SecretId"].as_str().unwrap();
                        match secrets.iter().find(|(n, _)| *n == id) {
                            Some((name, value)) => (
                                "200 OK",
                                serde_json::json!({ "Name": name, "SecretString": value }),
                            ),
                            None => (
                                "400 Bad Request",
                                serde_json::json!({
                                    "__type": "ResourceNotFoundException",
                                    "message": "not found",
                                }),
                            ),
                        }
                    }
                    _ => (
                        "400 Bad Request",
                        serde_json::json!({ "__type": "Unknown" }),
                    ),
                };
                let reply = reply.to_string();
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Type: application/x-amz-json-1.1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                    reply.len()
                );
            }
        });
        Self { url, targets }
    }

    fn targets(&self) -> Vec<String> {
        self.targets.lock().unwrap().clone()
    }
}

/// A fresh HOME with an AWS profile of fake static keys, a git checkout, and
/// nothing else: no kagebunshin configuration, no store.
struct Machine {
    tmp: tempfile::TempDir,
    aws: FakeAws,
    daemon: Option<Child>,
}

impl Machine {
    fn root(&self) -> PathBuf {
        self.tmp.path().canonicalize().unwrap()
    }

    /// A kagebunshin process with only this machine's environment.
    fn kb(&self, dir: &str, args: &[&str]) -> Command {
        self.command(env!("CARGO_BIN_EXE_kagebunshin"), dir, args)
    }

    /// Any process with only this machine's environment.
    fn command(&self, program: &str, dir: &str, args: &[&str]) -> Command {
        let root = self.root();
        let mut cmd = Command::new(program);
        cmd.args(args)
            .current_dir(root.join(dir))
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap())
            .env("HOME", root.join("home"))
            .env("KB", env!("CARGO_BIN_EXE_kagebunshin"))
            .env("KAGEBUNSHIN_SOCKET", root.join("run/kagebunshind.sock"))
            .env("AWS_CONFIG_FILE", root.join("home/.aws/config"))
            .env(
                "AWS_SHARED_CREDENTIALS_FILE",
                root.join("home/.aws/credentials"),
            )
            .env("AWS_ENDPOINT_URL", &self.aws.url)
            .env("AWS_EC2_METADATA_DISABLED", "true")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CEILING_DIRECTORIES", &root);
        cmd
    }

    fn run(&self, dir: &str, args: &[&str]) -> Output {
        self.kb(dir, args).output().unwrap()
    }
}

impl Machine {
    /// A fresh machine with a checkout at `repo` whose origin is
    /// acme/widget, an empty store, and the daemon running and unlocked, as
    /// the human leaves it after `setup`. `out` is for the test's files.
    fn start(aws: FakeAws) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let mut m = Machine {
            tmp,
            aws,
            daemon: None,
        };
        let root = m.root();
        for dir in ["home/.aws", "repo", "out", "run"] {
            fs::create_dir_all(root.join(dir)).unwrap();
        }
        fs::set_permissions(root.join("run"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(
            root.join("home/.aws/config"),
            "[profile acme-dev]\naws_access_key_id = AKIDFAKE\naws_secret_access_key = fake\nregion = eu-west-1\n",
        )
        .unwrap();
        git(&root.join("repo"), &["init", "-q"]);
        git(
            &root.join("repo"),
            &["remote", "add", "origin", "git@github.com:acme/widget.git"],
        );

        // As `store init` would, after its prompt.
        let config = ConfigDir::new(root.join("home/.config/kagebunshin"));
        fs::create_dir_all(config.path()).unwrap();
        StoreFile::new(config.store_file())
            .with_test_work_factor()
            .create(&WireSecret::new("pw".into()).into_passphrase())
            .unwrap();
        let log = fs::File::create(root.join("daemon.log")).unwrap();
        m.daemon = Some(m.kb("home", &["daemon"]).stderr(log).spawn().unwrap());
        let start = Instant::now();
        while !m.run("home", &["daemon", "ping"]).status.success() {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "daemon did not start"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        // As `unlock` does after its prompt at /dev/tty.
        Client::connect(&root.join("run/kagebunshind.sock"), DEFAULT_TIMEOUT)
            .unwrap()
            .request(Request::Unlock {
                passphrase: Some(WireSecret::new("pw".into())),
            })
            .unwrap();
        m
    }
}

impl Drop for Machine {
    fn drop(&mut self) {
        if let Some(mut d) = self.daemon.take() {
            let _ = d.kill();
            let _ = d.wait();
        }
    }
}

fn git(dir: &Path, args: &[&str]) {
    let ok = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .status()
        .unwrap()
        .success();
    assert!(ok, "git {args:?}");
}

fn text(b: &[u8]) -> String {
    String::from_utf8(b.to_vec()).unwrap()
}

/// What the agent does: the same commands a person would run. Exit codes are
/// printed, values never: the command `run` runs compares them with files
/// instead.
const AGENT: &str = r#"
"$KB" aws list --prefix widget/dev/ --profile acme-dev > "$OUT/names"; echo "list=$?"
"$KB" project add-source widget dev --provider aws_sm --prefix widget/dev/ --region eu-west-1 >/dev/null; echo "add=$?"
"$KB" run -- sh -c 'test "$API_KEY" = "$(cat "$OUT/api")" && test "$DB_PASSWORD" = "$(cat "$OUT/db")"'; echo "run=$?"
"#;

#[test]
fn a_fresh_install_set_up_by_an_agent() {
    let canary = Canary::new();
    let (api, db) = (
        format!("{}-api", canary.value()),
        format!("{}-db", canary.value()),
    );
    let aws = FakeAws::start(vec![
        (
            "widget/dev/api",
            serde_json::json!({ "API_KEY": api }).to_string(),
        ),
        (
            "widget/dev/db",
            serde_json::json!({ "DB_PASSWORD": db }).to_string(),
        ),
        (
            "widget/devops/ci",
            serde_json::json!({ "CI": canary.value() }).to_string(),
        ),
        (
            "widget/prod/db",
            serde_json::json!({ "DB_PASSWORD": canary.value() }).to_string(),
        ),
    ]);
    let m = Machine::start(aws);
    let root = m.root();
    fs::write(root.join("out/api"), &api).unwrap();
    fs::write(root.join("out/db"), &db).unwrap();
    fs::write(root.join("repo/.env.example"), "API_KEY=\nDB_PASSWORD=\n").unwrap();
    let o = m.run(
        "repo",
        &["project", "init", "widget", "--profile", "acme-dev"],
    );
    assert!(o.status.success(), "{}", text(&o.stderr));
    // Listing names fetches no value.
    let o = m.run(
        "repo",
        &[
            "--json",
            "aws",
            "list",
            "--prefix",
            "widget/dev/",
            "--profile",
            "acme-dev",
        ],
    );
    assert!(o.status.success(), "{}", text(&o.stderr));
    assert_eq!(
        text(&o.stdout),
        "{\"names\":[\"widget/dev/api\",\"widget/dev/db\"]}\n"
    );
    assert_eq!(m.aws.targets(), ["secretsmanager.ListSecrets"]);

    // The agent.
    let o = m
        .command("sh", "repo", &["-c", AGENT])
        .env("OUT", root.join("out"))
        .output()
        .unwrap();
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_no_canary(&canary, &out);
    assert_no_canary(&canary, &err);
    assert!(o.status.success(), "{err}");
    assert_eq!(out, "list=0\nadd=0\nrun=0\n", "{err}");
    assert_eq!(
        fs::read_to_string(root.join("out/names")).unwrap(),
        "widget/dev/api\nwidget/dev/db\n",
        "names under the prefix only, never ARNs"
    );
    let gets: Vec<_> = m
        .aws
        .targets()
        .into_iter()
        .filter(|t| t == "secretsmanager.GetSecretValue")
        .collect();
    assert_eq!(
        gets.len(),
        2,
        "only run fetched values, and only widget/dev/"
    );

    let o = m.run("repo", &["project", "show", "widget"]);
    assert_eq!(
        text(&o.stdout),
        r#"schema = 1
remotes = ["github.com/acme/widget"]
profile = "acme-dev"

[[envs.dev.sources]]
provider = "aws_sm"
prefix = "widget/dev/"
region = "eu-west-1"
"#
    );
    assert_no_canary(
        &canary,
        &fs::read_to_string(root.join("daemon.log")).unwrap(),
    );
}

/// What the agent does in a repository with one project per app.
const MONOREPO_AGENT: &str = r#"
cd apps/web/src
"$KB" run -- sh -c 'test "$WEB_KEY" = "$(cat "$OUT/web")" && test -z "${API_KEY+set}"'; echo "web=$?"
cd ../../..
"$KB" run -- true 2>"$OUT/root-err"; echo "root=$?"
"$KB" --project api run -- sh -c 'test "$API_KEY" = "$(cat "$OUT/api")" && test -z "${WEB_KEY+set}"'; echo "named=$?"
"$KB" --project api project show api 2>/dev/null; echo "show=$?"
"#;

#[test]
fn one_project_per_app() {
    let canary = Canary::new();
    let (web, api) = (
        format!("{}-web", canary.value()),
        format!("{}-api", canary.value()),
    );
    let aws = FakeAws::start(vec![
        (
            "widget/web/a",
            serde_json::json!({ "WEB_KEY": web, "SHARED": "w" }).to_string(),
        ),
        (
            "widget/api/a",
            serde_json::json!({ "API_KEY": api, "SHARED": "a" }).to_string(),
        ),
    ]);
    let m = Machine::start(aws);
    let root = m.root();
    fs::write(root.join("out/web"), &web).unwrap();
    fs::write(root.join("out/api"), &api).unwrap();
    // The root's file belongs to no app and must not be read for either.
    fs::write(root.join("repo/.env.example"), "ROOT_ONLY=\n").unwrap();
    for (app, key) in [("web", "WEB_KEY"), ("api", "API_KEY")] {
        fs::create_dir_all(root.join(format!("repo/apps/{app}/src"))).unwrap();
        fs::write(
            root.join(format!("repo/apps/{app}/.env.example")),
            format!("{key}=\n"),
        )
        .unwrap();
    }

    // The human: one project per app, from the root and from the app's folder.
    let o = m.run(
        "repo",
        &[
            "project",
            "init",
            "web",
            "--profile",
            "acme-dev",
            "--path",
            "apps/web",
        ],
    );
    assert!(o.status.success(), "{}", text(&o.stderr));
    let o = m.run(
        "repo/apps/api",
        &[
            "project",
            "init",
            "api",
            "--profile",
            "acme-dev",
            "--path",
            ".",
        ],
    );
    assert!(o.status.success(), "{}", text(&o.stderr));
    for (args, why) in [
        (
            &["project", "init", "x", "--path", "apps/nope"][..],
            "is not a folder",
        ),
        (
            &["project", "init", "x", "--path", "."],
            "names the whole repository",
        ),
        (
            &["project", "init", "x", "--path", ".."],
            "is not inside the checkout",
        ),
    ] {
        let o = m.run("repo", args);
        assert!(!o.status.success(), "{args:?}");
        assert!(
            text(&o.stderr).contains(why),
            "{args:?}: {}",
            text(&o.stderr)
        );
    }
    for app in ["web", "api"] {
        let o = m.run(
            "repo",
            &[
                "project",
                "add-source",
                app,
                "dev",
                "--provider",
                "aws_sm",
                "--prefix",
                &format!("widget/{app}/"),
                "--region",
                "eu-west-1",
            ],
        );
        assert!(o.status.success(), "{}", text(&o.stderr));
    }
    let o = m.run("repo", &["project", "list"]);
    assert_eq!(
        text(&o.stdout),
        "PROJECT  PATH      ENVS  PROVIDERS\napi      apps/api  dev   aws_sm\nweb      apps/web  dev   aws_sm\n"
    );
    let o = m.run("repo", &["project", "show", "api"]);
    assert!(
        text(&o.stdout).contains("path = \"apps/api\"\n"),
        "{}",
        text(&o.stdout)
    );

    // The agent.
    let o = m
        .command("sh", "repo", &["-c", MONOREPO_AGENT])
        .env("OUT", root.join("out"))
        .output()
        .unwrap();
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_no_canary(&canary, &out);
    assert_no_canary(&canary, &err);
    assert_eq!(out, "web=0\nroot=1\nnamed=0\nshow=2\n", "{err}");
    let root_err = fs::read_to_string(root.join("out/root-err")).unwrap();
    assert!(
        root_err.contains("the repository root is in no project")
            && root_err.contains("api (apps/api), web (apps/web)"),
        "{root_err}"
    );

    // `next` at the root goes through the apps, and steps into one.
    let o = m.run("repo", &["next"]);
    assert!(o.status.success(), "{}", text(&o.stderr));
    assert_eq!(
        text(&o.stdout),
        "this repository has 2 apps, each its own project
  apps/api: project api, environment dev: 1 of 1 keys set, not yet proven
  apps/web: project web, environment dev: 1 of 1 keys set, not yet proven
next (you): in apps/api: prove the setup: run the project's tests or its start command with its \
         keys; pick the command
  cd apps/api && kagebunshin run --strict -- COMMAND
"
    );
}

/// A project that names no sources reads its own store section, and one
/// not stored yet reads as empty: the agent sees what to ask a human to
/// store. So does a `file` source added without a selection, as the draft
/// suggests beside provider sources; a source that names another section
/// still needs it.
#[test]
fn a_new_project_reads_as_empty_until_stored() {
    let m = Machine::start(FakeAws::start(vec![]));
    let root = m.root();
    fs::write(root.join("repo/.env.example"), "API_KEY=\nDB_PASSWORD=\n").unwrap();
    let o = m.run("repo", &["project", "init", "widget"]);
    assert!(o.status.success(), "{}", text(&o.stderr));

    let o = m.run("repo", &["status"]);
    assert!(o.status.success(), "{}", text(&o.stderr));
    assert!(
        text(&o.stdout).ends_with(
            "missing (in .env.example, set by no source):
  API_KEY
  DB_PASSWORD
to fill in what is missing:
  ask the human:
    kagebunshin store set widget.dev API_KEY DB_PASSWORD
      (it asks for the store passphrase, then each value)
"
        ),
        "{}",
        text(&o.stdout)
    );

    let o = m.run("repo", &["--json", "diff"]);
    assert_eq!(o.status.code(), Some(1), "{}", text(&o.stderr));
    let v: serde_json::Value = serde_json::from_str(&text(&o.stdout)).unwrap();
    assert_eq!(v["missing"], serde_json::json!(["API_KEY", "DB_PASSWORD"]));
    assert_eq!(
        v["fixes"][0]["command"],
        "kagebunshin store set widget.dev API_KEY DB_PASSWORD"
    );

    let o = m.run("repo", &["run", "--", "true"]);
    assert!(o.status.success(), "{}", text(&o.stderr));
    let o = m.run("repo", &["--json", "run", "--strict", "--", "true"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(
        text(&o.stderr).contains("\"missing_keys\""),
        "{}",
        text(&o.stderr)
    );

    for args in [
        &["project", "add-env", "widget", "named"][..],
        &[
            "project",
            "add-source",
            "widget",
            "named",
            "--provider",
            "file",
        ],
    ] {
        let o = m.run("repo", args);
        assert!(o.status.success(), "{}", text(&o.stderr));
    }
    let o = m.run("repo", &["--json", "diff", "--env", "named"]);
    assert_eq!(o.status.code(), Some(1), "{}", text(&o.stderr));
    let v: serde_json::Value = serde_json::from_str(&text(&o.stdout)).unwrap();
    assert_eq!(
        v["fixes"][0]["command"],
        "kagebunshin store set widget.named API_KEY DB_PASSWORD"
    );

    let o = m.run(
        "repo",
        &[
            "project",
            "add-source",
            "widget",
            "named",
            "--provider",
            "file",
            "--secret",
            "widget.other",
        ],
    );
    assert!(o.status.success(), "{}", text(&o.stderr));
    let o = m.run("repo", &["status", "--env", "named"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(
        text(&o.stderr).contains("section [widget.other] is not in the local store"),
        "{}",
        text(&o.stderr)
    );
}

/// A prefix with a plain string under it reads the rest, names what it
/// left out and the command that adds it, never its value; `run --strict`
/// still fails on the key that leaves missing. Named alone without a key,
/// the same secret fails, with that command as the hint.
#[test]
fn a_prefix_skips_a_plain_string_secret() {
    let canary = Canary::new();
    let (api, token) = (
        format!("{}-api", canary.value()),
        format!("{}-token", canary.value()),
    );
    let aws = FakeAws::start(vec![
        (
            "widget/dev/api",
            serde_json::json!({ "API_KEY": api }).to_string(),
        ),
        ("widget/dev/token", token.clone()),
    ]);
    let m = Machine::start(aws);
    let root = m.root();
    fs::write(root.join("out/token"), &token).unwrap();
    fs::write(root.join("repo/.env.example"), "API_KEY=\nTOKEN=\n").unwrap();
    let ok = |args: &[&str]| {
        let o = m.run("repo", args);
        assert!(o.status.success(), "{args:?}: {}", text(&o.stderr));
        let (out, err) = (text(&o.stdout), text(&o.stderr));
        assert_no_canary(&canary, &out);
        assert_no_canary(&canary, &err);
        out
    };
    ok(&["project", "init", "widget", "--profile", "acme-dev"]);
    ok(&[
        "project",
        "add-source",
        "widget",
        "dev",
        "--provider",
        "aws_sm",
        "--prefix",
        "widget/dev/",
        "--region",
        "eu-west-1",
    ]);
    let add = "kagebunshin project add-source widget dev --provider aws_sm --secret widget/dev/token \
               --key NAME --profile acme-dev --region eu-west-1";

    let out = ok(&["status"]);
    assert!(
        out.contains(&format!("\n  you can run:\n    {add}\n")),
        "{out}"
    );
    assert!(
        out.contains(
            "warning: aws_sm prefix widget/dev/ (profile acme-dev, region eu-west-1): skipped \
             secret widget/dev/token, which is not a JSON object"
        ),
        "{out}"
    );
    let o = m.run("repo", &["--json", "diff"]);
    assert_eq!(o.status.code(), Some(1), "{}", text(&o.stderr));
    assert_no_canary(&canary, &text(&o.stdout));
    let v: serde_json::Value = serde_json::from_str(&text(&o.stdout)).unwrap();
    assert_eq!(v["missing"], serde_json::json!(["TOKEN"]));
    assert_eq!(v["skipped"], serde_json::json!(["widget/dev/token"]));
    assert_eq!(v["fixes"][0]["command"], add);
    let o = m.run("repo", &["--json", "run", "--strict", "--", "true"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(
        text(&o.stderr).contains("\"missing_keys\""),
        "{}",
        text(&o.stderr)
    );

    // The same secret named alone, without a key.
    ok(&[
        "project",
        "add-source",
        "widget",
        "dev",
        "--provider",
        "aws_sm",
        "--secret",
        "widget/dev/token",
        "--region",
        "eu-west-1",
    ]);
    // The edit takes effect by itself: the daemon fetches the new sources.
    let o = m.run("repo", &["--json", "status"]);
    assert_eq!(o.status.code(), Some(1), "{}", text(&o.stdout));
    let err: serde_json::Value = serde_json::from_str(&text(&o.stderr)).unwrap();
    assert!(
        err["message"]
            .as_str()
            .unwrap()
            .contains("secret widget/dev/token: is not a JSON object"),
        "{err}"
    );
    assert_eq!(
        err["hint"],
        format!(
            "to use its whole string as one key: `{add}`, then \
             `kagebunshin project remove-source widget dev 2`"
        )
    );

    // What the hint says, with the key named.
    ok(&["project", "remove-source", "widget", "dev", "2"]);
    ok(&add
        .replace("NAME", "TOKEN")
        .split(' ')
        .skip(1)
        .collect::<Vec<_>>());
    let out = ok(&["status"]);
    assert!(
        !out.contains("skipped") && !out.contains("add-source"),
        "{out}"
    );
    ok(&[
        "run",
        "--strict",
        "--",
        "sh",
        "-c",
        &format!(
            "test \"$TOKEN\" = \"$(cat {})\"",
            root.join("out/token").display()
        ),
    ]);
    assert_no_canary(
        &canary,
        &fs::read_to_string(root.join("daemon.log")).unwrap(),
    );
}

/// `next` walks an agent from an unregistered checkout to a proven setup:
/// each step it names is the one taken next, until it says it is done.
#[test]
fn next_walks_an_agent_to_done() {
    let canary = Canary::new();
    let m = Machine::start(FakeAws::start(vec![(
        "widget/dev/api",
        serde_json::json!({ "API_KEY": canary.value() }).to_string(),
    )]));
    fs::write(m.root().join("repo/.env.example"), "API_KEY=\n").unwrap();
    let next = |m: &Machine| {
        let o = m.run("repo", &["next"]);
        let (out, err) = (text(&o.stdout), text(&o.stderr));
        assert_no_canary(&canary, &out);
        assert_no_canary(&canary, &err);
        assert!(o.status.success(), "{err}");
        out
    };
    let ok = |args: &[&str]| {
        let o = m.run("repo", args);
        assert!(o.status.success(), "{args:?}: {}", text(&o.stderr));
    };

    assert_eq!(
        next(&m),
        "this checkout is in no kagebunshin project
next (you): draft this folder's project from what the checkout and the connected providers say, and apply it
  kagebunshin project draft --apply
"
    );
    // What `project draft --apply` would write, by hand.
    ok(&["project", "init", "widget", "--profile", "acme-dev"]);
    assert!(next(&m).contains("`kagebunshin store set widget.dev API_KEY`"));
    ok(&[
        "project",
        "add-source",
        "widget",
        "dev",
        "--provider",
        "aws_sm",
        "--prefix",
        "widget/dev/",
        "--region",
        "eu-west-1",
    ]);
    // The daemon fetches the new sources by itself, with no `sync`.
    assert_eq!(
        next(&m),
        "project widget, environment dev: 1 of 1 keys set, not yet proven
next (you): prove the setup: run the project's tests or its start command with its keys; pick the command
  kagebunshin run --strict -- COMMAND
"
    );
    // A failing command proves nothing.
    let o = m.run("repo", &["run", "--strict", "--", "false"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(next(&m).contains("not yet proven"));
    ok(&["run", "--strict", "--", "true"]);
    let done = next(&m);
    assert!(
        done.starts_with(
            "project widget, environment dev: done. 1 of 1 keys set; `true` ran with them on "
        ) && done.ends_with(". They come from aws_sm:widget/dev/api (1).\n"),
        "{done}"
    );
    let o = m.run("repo", &["--json", "next"]);
    let mut v: serde_json::Value = serde_json::from_str(&text(&o.stdout)).unwrap();
    let headline = v["headline"].take();
    assert_eq!(headline.as_str(), Some(done.trim_end()));
    assert_eq!(
        v,
        serde_json::json!({
            "project": "widget", "env": "dev", "done": true,
            "keys": {"set": 1, "wanted": 1},
            "headline": null, "step": null, "human": [],
        })
    );
    let o = m.run("repo", &["status"]);
    assert!(
        text(&o.stdout).contains("every key set; `true` ran with them on "),
        "{}",
        text(&o.stdout)
    );
}

/// An app with no `.env.example` gets every key of its environment. Setup
/// is done all the same, and `next` then suggests the file, of what the
/// code reads. Written, a command gets those keys and no other.
#[test]
fn an_app_with_no_example_is_done_and_offered_one_of_the_keys_it_reads() {
    let canary = Canary::new();
    let m = Machine::start(FakeAws::start(vec![(
        "widget/dev/api",
        serde_json::json!({
            "API_KEY": canary.value(),
            "DB_URL": canary.value(),
            "MAIL_TOKEN": canary.value(),
            "QUEUE_URL": canary.value(),
            "SESSION_SECRET": canary.value(),
        })
        .to_string(),
    )]));
    let repo = m.root().join("repo");
    let run = |args: &[&str]| {
        let o = m.run("repo", args);
        let (out, err) = (text(&o.stdout), text(&o.stderr));
        assert_no_canary(&canary, &out);
        assert_no_canary(&canary, &err);
        (o.status.code(), out, err)
    };
    let ok = |args: &[&str]| {
        let (code, out, err) = run(args);
        assert_eq!(code, Some(0), "{args:?}: {err}");
        out
    };
    ok(&["project", "init", "widget", "--profile", "acme-dev"]);
    ok(&[
        "project",
        "add-source",
        "widget",
        "dev",
        "--provider",
        "aws_sm",
        "--prefix",
        "widget/dev/",
        "--region",
        "eu-west-1",
    ]);

    // No code yet: nothing to list, so nothing is written.
    let (code, _, err) = run(&["--json", "project", "example"]);
    assert_eq!(code, Some(1), "{err}");
    let e: serde_json::Value = serde_json::from_str(&err).unwrap();
    assert_eq!(e["code"], "no_keys", "{err}");
    assert!(!repo.join(".env.example").exists());
    // The file is no step: the proof is next, and until then nothing is
    // said of it. A command gets all five.
    assert_eq!(
        ok(&["next"]),
        "project widget, environment dev: 5 keys set (no .env.example to compare with), not yet proven
next (you): prove the setup: run the project's tests or its start command with its keys; pick the command
  kagebunshin run --strict -- COMMAND
"
    );
    ok(&[
        "run",
        "--strict",
        "--",
        "sh",
        "-c",
        r#"test -n "$MAIL_TOKEN""#,
    ]);
    let next = ok(&["next"]);
    assert!(
        next.starts_with("project widget, environment dev: done. 5 of 5 keys set; ")
            && next.contains(
                "\nsuggested, not needed: this app has no .env.example, so a command run here \
                 gets all 5 keys of the environment. One listing the keys the app reads"
            )
            && !next.contains("kagebunshin project example"),
        "{next}"
    );

    // The app reads three of the five. Another app below it, files git
    // ignores and the platform's own names are not this app's keys.
    for (file, body) in [
        (
            "src/server.js",
            "const db = connect(process.env.DB_URL);\nlisten(process.env.PORT, process.env.API_KEY);\n\
             if (process.env.NODE_ENV === 'production') quiet();\n",
        ),
        (
            "jobs/worker.py",
            "import os\nsecret = os.environ[\"SESSION_SECRET\"]\n",
        ),
        ("admin/.env.example", "ADMIN_TOKEN=\n"),
        ("admin/index.js", "login(process.env.ADMIN_TOKEN);\n"),
        ("dist/server.js", "connect(process.env.BUILD_ONLY);\n"),
        (".gitignore", "dist/\n"),
    ] {
        fs::create_dir_all(repo.join(file).parent().unwrap()).unwrap();
        fs::write(repo.join(file), body).unwrap();
    }
    let next = ok(&["next"]);
    assert!(
        next.ends_with(
            "\nsuggested, not needed: this app has no .env.example, so a command run here gets \
             all 5 keys of the environment. `kagebunshin project example` writes one from the 4 \
             keys kagebunshin finds its code reading, names only, and a command then gets those \
             and no more.\n"
        ),
        "{next}"
    );

    let wrote = ok(&["project", "example"]);
    assert!(
        wrote.starts_with(&format!(
            "wrote {} with the 4 keys the code reads, names only:\n  API_KEY  (src/server.js)\n",
            repo.join(".env.example").display()
        )),
        "{wrote}"
    );
    assert_eq!(
        fs::read_to_string(repo.join(".env.example")).unwrap(),
        "# The environment keys this app reads, by name. No values here.\n\
         API_KEY=\nDB_URL=\nPORT=\nSESSION_SECRET=\n"
    );
    // It is the agent's to check: PORT is no secret here.
    fs::write(
        repo.join(".env.example"),
        "API_KEY=\nDB_URL=\nSESSION_SECRET=\n",
    )
    .unwrap();
    // The file is never written over.
    let (code, _, err) = run(&["--json", "project", "example"]);
    assert_eq!(code, Some(1), "{err}");
    let e: serde_json::Value = serde_json::from_str(&err).unwrap();
    assert_eq!(e["code"], "exists", "{err}");

    // A command gets the three, and not the other two.
    let only = r#"test -n "$API_KEY" && test -n "$DB_URL" && test -n "$SESSION_SECRET" \
        && test -z "${MAIL_TOKEN+set}" && test -z "${QUEUE_URL+set}""#;
    ok(&["run", "--strict", "--", "sh", "-c", only]);
    // Still done, and with the file there nothing more is suggested.
    let done = ok(&["next"]);
    assert!(
        done.starts_with("project widget, environment dev: done. 3 of 3 keys set; ")
            && !done.contains("suggested"),
        "{done}"
    );
}

/// `project facts`: what the checkout says, by name, and which listed
/// secrets its tracked files name; no value is fetched.
#[test]
fn facts_name_what_the_checkout_says() {
    let canary = Canary::new();
    let aws = FakeAws::start(vec![
        (
            "acme/dev/api",
            serde_json::json!({ "API_KEY": canary.value() }).to_string(),
        ),
        (
            "acme/dev/unused",
            serde_json::json!({ "X": canary.value() }).to_string(),
        ),
    ]);
    let m = Machine::start(aws);
    let root = m.root();
    fs::write(root.join("repo/.env.example"), "API_KEY=\nPORT=3000\n").unwrap();
    fs::write(
        root.join("repo/.env"),
        format!("API_KEY={}\n", canary.value()),
    )
    .unwrap();
    fs::create_dir_all(root.join("repo/.github/workflows")).unwrap();
    fs::write(
        root.join("repo/.github/workflows/deploy.yml"),
        "env:\n  SECRET: acme/dev/api\n",
    )
    .unwrap();
    git(&root.join("repo"), &["add", ".github"]);

    let o = m.run("repo", &["--json", "project", "facts"]);
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert!(o.status.success(), "{err}");
    assert_no_canary(&canary, &out);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(
        v["apps"][0]["example"]["keys"],
        serde_json::json!([
            { "key": "API_KEY", "has_value": false },
            { "key": "PORT", "has_value": true },
        ])
    );
    assert_eq!(
        v["apps"][0]["env_files"][0]["keys"],
        serde_json::json!([{ "key": "API_KEY", "has_value": true }])
    );
    assert_eq!(v["profiles"][0]["name"], "acme-dev");
    assert_eq!(v["profiles"][0]["usable"], true);
    assert_eq!(
        v["named_in_files"]["found"],
        serde_json::json!([{ "name": "acme/dev/api", "files": [".github/workflows/deploy.yml"] }])
    );
    assert!(
        !m.aws
            .targets()
            .contains(&"secretsmanager.GetSecretValue".to_owned())
    );
    let o = m.run("repo", &["project", "facts"]);
    let out = text(&o.stdout);
    assert_no_canary(&canary, &out);
    assert!(
        out.contains(
            "    .env.example: API_KEY, PORT (has a value)\n    .env: 1 keys, 1 with a value"
        ),
        "{out}"
    );
}

const APPLIED: &str = r#"schema = 1
remotes = ["git@github.com:acme/widget.git"]
profile = "acme-dev"

[[envs.dev.sources]]
provider = "aws_sm"
prefix = "acme/dev/"
region = "eu-west-1"

[[envs.staging.sources]]
provider = "aws_sm"
secret = "acme/dev/api"
region = "eu-west-1"

[[envs.rc.sources]]
provider = "aws_sm"
secret = "acme/dev/api"
region = "eu-west-1"
"#;

/// `project apply`: a file that does not load or resolve installs nothing;
/// one that does is checked, then installed whole; replacing it keeps the
/// marks a human made, and a replacement that would move them is refused.
#[test]
fn apply_checks_then_installs_and_keeps_marks() {
    let canary = Canary::new();
    let aws = FakeAws::start(vec![
        (
            "acme/dev/api",
            serde_json::json!({ "API_KEY": canary.value() }).to_string(),
        ),
        (
            "acme/dev/db",
            serde_json::json!({ "DB_PASSWORD": canary.value() }).to_string(),
        ),
    ]);
    let m = Machine::start(aws);
    let root = m.root();
    fs::write(
        root.join("repo/.env.example"),
        "API_KEY=\nDB_PASSWORD=\nPORT=3000\n",
    )
    .unwrap();
    let run = |args: &[&str]| {
        let o = m.run("repo", args);
        let (out, err) = (text(&o.stdout), text(&o.stderr));
        assert_no_canary(&canary, &out);
        assert_no_canary(&canary, &err);
        (o.status.code(), out, err)
    };
    let installed = || run(&["project", "list"]).1;
    let file = |name: &str, body: &str| {
        let path = root.join("out").join(name);
        fs::write(&path, body).unwrap();
        path.display().to_string()
    };

    // Neither a file that does not load nor one with a source that fails.
    let bad = file("widget.toml", "schema = 1\nremotes = 3\n");
    let (code, _, err) = run(&["project", "apply", &bad, "--check"]);
    assert_eq!(code, Some(1), "{err}");
    assert!(
        err.contains("does not load, so nothing was installed"),
        "{err}"
    );
    let failing = APPLIED.replacen("secret = \"acme/dev/api\"", "secret = \"acme/dev/gone\"", 1);
    let bad = file("widget.toml", &failing);
    let (code, out, err) = run(&["project", "apply", &bad]);
    assert_eq!(code, Some(1), "{out}{err}");
    assert!(out.contains("env staging:\n  does not resolve:"), "{out}");
    assert!(
        err.contains(
            "environment staging of project widget does not resolve, so nothing was installed"
        ),
        "{err}"
    );
    assert!(!installed().contains("widget"), "{}", installed());

    // A good file, checked only.
    let good = file("widget.toml", APPLIED);
    let (code, out, err) = run(&["project", "apply", &good, "--check"]);
    assert_eq!(code, Some(0), "{err}");
    assert!(
        out.contains("env dev:\n  2 keys set\n    1 from aws_sm:acme/dev/api\n    1 from aws_sm:acme/dev/db\n"),
        "{out}"
    );
    assert!(
        out.contains("missing (in .env.example, set by no source): PORT"),
        "{out}"
    );
    assert!(
        out.contains("kagebunshin project set-var widget dev PORT 3000"),
        "{out}"
    );
    assert!(
        out.ends_with("checked only; nothing was installed\n"),
        "{out}"
    );
    assert!(!installed().contains("widget"));

    // Installed; then a human marks staging sensitive.
    let (code, out, err) = run(&["project", "apply", &good]);
    assert_eq!(code, Some(0), "{err}");
    assert!(out.contains("installed "), "{out}");
    assert_eq!(run(&["status"]).0, Some(0));
    let mut client = Client::connect(&root.join("run/kagebunshind.sock"), DEFAULT_TIMEOUT).unwrap();
    client
        .request(Request::MarkEnv {
            project: "widget".parse().unwrap(),
            env: "staging".parse().unwrap(),
            sensitive: true,
            also: Vec::new(),
            passphrase: WireSecret::new("pw".into()),
        })
        .unwrap();
    let (_, out, _) = run(&["status", "--env", "rc"]);
    assert!(out.contains("looks like production"), "{out}");
    client
        .request(Request::AcknowledgeEnv {
            project: "widget".parse().unwrap(),
            env: "rc".parse().unwrap(),
            acknowledged: true,
            unmark: Vec::new(),
            passphrase: WireSecret::new("pw".into()),
        })
        .unwrap();

    // Replaced with one source fewer: the change is named and the mark
    // stays.
    let fewer = file(
        "widget.toml",
        &APPLIED.replace("prefix = \"acme/dev/\"", "secret = \"acme/dev/db\""),
    );
    let (code, out, err) = run(&["project", "apply", &fewer]);
    assert_eq!(code, Some(0), "{err}");
    assert!(out.contains("replaces: widget"), "{out}");
    assert!(
        out.contains("widget: dev: removes the aws_sm source prefix acme/dev/ (profile acme-dev)"),
        "{out}"
    );
    assert!(
        out.contains("widget: dev: adds the aws_sm source secret acme/dev/db (profile acme-dev)"),
        "{out}"
    );
    let (code, _, err) = run(&["status", "--env", "staging"]);
    assert_eq!(code, Some(5), "{err}");
    assert!(err.contains("it is marked sensitive"), "{err}");
    let (code, out, err) = run(&["status", "--env", "rc"]);
    assert_eq!(code, Some(0), "{err}");
    assert!(!out.contains("looks like production"), "{out}");
    // The values cached for the old file are not served for the new one.
    let (_, out, _) = run(&["status"]);
    assert!(
        out.contains("API_KEY") && !out.contains("acme/dev/api"),
        "{out}"
    );

    // Dropping the acknowledged environment, or renaming, is refused.
    let dropped = file(
        "widget.toml",
        &APPLIED.replace("[[envs.rc.sources]]", "[[envs.rc2.sources]]"),
    );
    let renamed = file("other.toml", APPLIED);
    for f in [dropped, renamed] {
        let (code, _, err) = run(&["project", "apply", &f]);
        assert_eq!(code, Some(5), "{err}");
        assert!(err.contains("nothing was installed"), "{err}");
        assert!(err.contains("kagebunshin app"), "{err}");
    }
    let list = installed();
    assert!(list.contains("widget") && !list.contains("other"), "{list}");
    assert_no_canary(
        &canary,
        &fs::read_to_string(root.join("daemon.log")).unwrap(),
    );
}

/// `project draft`: a checkout with only a `.env.example` and a deploy
/// workflow listing each job's secrets goes from no project to one that
/// resolves, with the secrets in the workflow's order; what it cannot
/// decide is left as commands, the job for production becomes an
/// environment that waits, and a second `--apply` does not replace what is
/// there.
#[test]
fn draft_takes_a_checkout_from_nothing_to_resolving() {
    let canary = Canary::new();
    let (api, db, stripe) = (
        format!("{}-api", canary.value()),
        format!("{}-db", canary.value()),
        format!("{}-stripe", canary.value()),
    );
    let aws = FakeAws::start(vec![
        (
            "acme/dev/api",
            serde_json::json!({ "API_KEY": api }).to_string(),
        ),
        (
            "acme/dev/db",
            serde_json::json!({ "DB_PASSWORD": db }).to_string(),
        ),
        ("acme/dev/stripe-key", stripe.clone()),
        (
            "acme/prod/api",
            serde_json::json!({ "API_KEY": canary.value() }).to_string(),
        ),
    ]);
    let m = Machine::start(aws);
    let root = m.root();
    for (name, value) in [("api", &api), ("db", &db), ("stripe", &stripe)] {
        fs::write(root.join("out").join(name), value).unwrap();
    }
    fs::write(
        root.join("repo/.env.example"),
        "API_KEY=\nDB_PASSWORD=\nSTRIPE_KEY=\nPORT=3000\nSESSION_SECRET=\n",
    )
    .unwrap();
    fs::create_dir_all(root.join("repo/.github/workflows")).unwrap();
    fs::write(
        root.join("repo/.github/workflows/deploy.yml"),
        "jobs:\n  dev:\n    env:\n      SECRETS: acme/dev/db, acme/dev/stripe-key, acme/dev/api\n  prod:\n    env:\n      SECRETS: acme/prod/api\n",
    )
    .unwrap();
    git(&root.join("repo"), &["add", ".github"]);
    let run = |args: &[&str]| {
        let o = m.run("repo", args);
        let (out, err) = (text(&o.stdout), text(&o.stderr));
        assert_no_canary(&canary, &out);
        assert_no_canary(&canary, &err);
        (o.status.code(), out, err)
    };

    // The draft on stdout, the report on stderr; nothing installed.
    let (code, toml, report) = run(&["project", "draft"]);
    assert_eq!(code, Some(0), "{report}");
    assert_eq!(
        toml,
        r#"# Drafted by `kagebunshin project draft`. Check it with
# `kagebunshin project apply FILE --check`.
schema = 1
remotes = ["github.com/acme/widget"]
profile = "acme-dev"

[envs.dev]
# its secrets as .github/workflows/deploy.yml:4 lists them, in that order
# open: PORT: no secret holds it, and .env.example gives it a value; only if .env.example's value is the real setting, not a placeholder; a secret belongs in the store or a provider
#   kagebunshin project set-var repo dev PORT 3000
# open: no secret found for SESSION_SECRET
#   kagebunshin project add-source repo dev --provider file
#   kagebunshin store set repo.dev SESSION_SECRET   (human)

[[envs.dev.sources]]
provider = "aws_sm"
secret = "acme/dev/db"

[[envs.dev.sources]]
provider = "aws_sm"
secret = "acme/dev/stripe-key"
key = "STRIPE_KEY"

[[envs.dev.sources]]
provider = "aws_sm"
secret = "acme/dev/api"

[envs.prod]
# its secrets as .github/workflows/deploy.yml:7 lists them, in that order

[[envs.prod.sources]]
provider = "aws_sm"
secret = "acme/prod/api"
"#,
        "{report}"
    );
    assert!(report.contains("(human)"), "{report}");
    assert!(!run(&["project", "list"]).1.contains("repo"));

    // Installed, it resolves the keys it holds.
    let (code, out, err) = run(&["project", "draft", "--apply"]);
    assert_eq!(code, Some(0), "{out}{err}");
    assert!(out.contains("installed "), "{out}");
    let o = m
        .command(
            env!("CARGO_BIN_EXE_kagebunshin"),
            "repo",
            &[
                "run",
                "--",
                "sh",
                "-c",
                r#"test "$API_KEY" = "$(cat "$OUT/api")" && test "$DB_PASSWORD" = "$(cat "$OUT/db")" && test "$STRIPE_KEY" = "$(cat "$OUT/stripe")""#,
            ],
        )
        .env("OUT", root.join("out"))
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", text(&o.stderr));
    assert_no_canary(&canary, &text(&o.stderr));

    // The production job's environment is installed too, and waits.
    let (code, _, err) = run(&["--env", "prod", "run", "--", "true"]);
    assert_eq!(code, Some(5), "{err}");
    assert!(err.contains("waits for a human decision"), "{err}");

    // A second `--apply` refuses to replace it, and says how to.
    let (code, _, err) = run(&["project", "draft", "--apply"]);
    assert_eq!(code, Some(1), "{err}");
    assert!(err.contains("already exists or claims"), "{err}");
    assert!(
        err.contains("kagebunshin project draft -o repo.toml")
            && err.contains("kagebunshin project apply repo.toml"),
        "{err}"
    );
    assert_no_canary(
        &canary,
        &fs::read_to_string(root.join("daemon.log")).unwrap(),
    );
}

/// Three checkouts for `onboard`, beside the machine's `repo`: `blog` and
/// `web` with a `.env` of `canary`'s values, and `notes`, a plain folder.
/// `repo` names an AWS secret and a key no secret holds.
fn three_checkouts(m: &Machine, canary: &Canary) {
    let root = m.root();
    fs::write(
        root.join("repo/.env.example"),
        "API_KEY=\nSESSION_SECRET=\n",
    )
    .unwrap();
    fs::create_dir_all(root.join("repo/.github/workflows")).unwrap();
    fs::write(
        root.join("repo/.github/workflows/deploy.yml"),
        "jobs:\n  dev:\n    env:\n      SECRET: acme/dev/api\n",
    )
    .unwrap();
    git(&root.join("repo"), &["add", ".github"]);
    for name in ["blog", "web"] {
        let dir = root.join(name);
        fs::create_dir_all(&dir).unwrap();
        git(&dir, &["init", "-q"]);
        git(
            &dir,
            &[
                "remote",
                "add",
                "origin",
                &format!("git@github.com:acme/{name}.git"),
            ],
        );
        fs::write(
            dir.join(".env"),
            format!(
                "TOKEN={}-{name}\nexport DB_URL=\"{}\"\n",
                canary.value(),
                canary.value()
            ),
        )
        .unwrap();
    }
    fs::create_dir_all(root.join("notes")).unwrap();
}

/// The project files and the store's section names, to see that nothing
/// changed.
fn written(m: &Machine) -> (Vec<(String, String)>, Vec<String>) {
    let config = m.root().join("home/.config/kagebunshin");
    let mut files: Vec<(String, String)> = fs::read_dir(config.join("projects"))
        .map(|d| {
            d.map(|e| {
                let p = e.unwrap().path();
                (
                    p.file_name().unwrap().to_string_lossy().into_owned(),
                    fs::read_to_string(&p).unwrap(),
                )
            })
            .collect()
        })
        .unwrap_or_default();
    files.sort();
    let store = StoreFile::new(config.join("store.age"))
        .open(&WireSecret::new("pw".into()).into_passphrase())
        .unwrap();
    let sections = store.sections().map(|(s, _)| s.to_string()).collect();
    (files, sections)
}

fn locked(m: &Machine) -> bool {
    let o = m.run("home", &["--json", "status"]);
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    v["locked"].as_bool().unwrap()
}

/// `onboard` with several folders: one passphrase prompt unlocks the daemon
/// and imports both `.env` files, `repo` is drafted, `notes` is skipped, the
/// `.env` question comes once; a second run changes nothing.
#[test]
fn onboard_sets_up_several_checkouts_with_one_passphrase() {
    let canary = Canary::new();
    let m = Machine::start(FakeAws::start(vec![(
        "acme/dev/api",
        serde_json::json!({ "API_KEY": canary.value() }).to_string(),
    )]));
    three_checkouts(&m, &canary);
    let root = m.root();
    assert!(m.run("home", &["lock"]).status.success());
    let dirs = ["../repo", "../blog", "../web", "../notes", "../blog"];

    let cmd = m.kb("home", &[&["onboard"][..], &dirs].concat());
    let (exit, out) = common::on_terminal(&cmd, "pw\nn\n");
    assert_no_canary(&canary, &out);
    assert_eq!(exit, 0, "{out}");
    assert_eq!(out.matches("assphrase for").count(), 1, "{out}");
    assert!(
        out.contains("Passphrase for the local store (to unlock, and to import 2 .env files): "),
        "{out}"
    );
    assert_eq!(
        out.matches("now that their values are in the store?")
            .count(),
        1,
        "{out}"
    );
    assert!(!locked(&m));
    assert!(
        out.contains(&format!(
            "skipped {}/notes: it is not inside a git checkout",
            root.display()
        )),
        "{out}"
    );
    assert!(
        out.contains("Set up kagebunshin here: run `kagebunshin next`"),
        "{out}"
    );
    assert!(root.join("blog/.env").exists() && root.join("web/.env").exists());
    for (project, state) in [
        (
            "repo",
            "needs your agent: SESSION_SECRET is set by no source",
        ),
        // Neither has a .env.example: that holds nothing up.
        ("blog", "ready: your agent proves it with a run"),
        ("web", "ready: your agent proves it with a run"),
    ] {
        let at = out.find(&format!("\n{project} (")).unwrap();
        let block = out[at..].split("\n\n").next().unwrap();
        assert!(block.contains(state), "{block}");
    }
    assert!(
        out.contains("put 2 keys from .env in the local store's [blog.dev]: TOKEN, DB_URL"),
        "{out}"
    );
    let before = written(&m);
    assert_eq!(before.1, ["blog.dev", "web.dev"], "{before:?}");

    // Each step is named as it starts, in order: what there is to do before
    // the passphrase, then the files, the one write, the draft, the states.
    let r = root.display();
    let steps = [
        "onboarding 3 apps in 3 checkouts: 2 env files to import, 1 to draft".to_owned(),
        "Passphrase for the local store".to_owned(),
        format!("importing {r}/blog/.env into [blog.dev]"),
        format!("importing {r}/web/.env into [web.dev]"),
        "writing 4 keys from 2 files to the local store".to_owned(),
        format!("drafting {r}/repo from the checkout and the providers"),
        "reading the state of repo (1 of 3)".to_owned(),
        "reading the state of web (3 of 3)".to_owned(),
        "\nrepo (".to_owned(),
    ];
    let mut from = 0;
    for step in &steps {
        let at = out[from..].find(step.as_str());
        from += at.unwrap_or_else(|| panic!("no {step:?} after {from} in {out}"));
    }
    // Both files went in with one store write.
    let o = m.run("home", &["audit", "--json", "--since", "1h"]);
    let events: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    let sets: Vec<&serde_json::Value> = events["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["action"] == "store import")
        .collect();
    assert_eq!(sets.len(), 1, "{events}");
    assert_eq!(sets[0]["keys"].as_array().unwrap().len(), 4, "{events}");

    // Again: nothing to unlock or import, so no prompt and no question.
    let o = m.run("home", &[&["--json", "onboard"][..], &dirs].concat());
    let (stdout, stderr) = (text(&o.stdout), text(&o.stderr));
    assert_no_canary(&canary, &stdout);
    assert!(o.status.success(), "{stderr}");
    // The steps go to stderr, so stdout is the one document.
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(
        stderr.contains("onboarding 3 apps in 3 checkouts: 3 already set up"),
        "{stderr}"
    );
    assert!(
        stderr.contains("reading the state of blog (2 of 3)"),
        "{stderr}"
    );
    assert!(!stderr.contains("importing"), "{stderr}");
    assert_eq!(written(&m), before);
    let states: Vec<(String, serde_json::Value)> = v["projects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            (
                p["project"].as_str().unwrap().to_owned(),
                p["state"].clone(),
            )
        })
        .collect();
    let want = |s: &str| serde_json::json!([s]);
    assert_eq!(
        states,
        [
            ("repo".to_owned(), want("needs your agent")),
            ("blog".to_owned(), want("ready")),
            ("web".to_owned(), want("ready")),
        ],
        "{v}"
    );
    assert_eq!(v["skipped"].as_array().unwrap().len(), 1, "{v}");
    assert_eq!(v["deleted"], serde_json::json!([]), "{v}");
    assert_no_canary(
        &canary,
        &fs::read_to_string(root.join("daemon.log")).unwrap(),
    );
}

/// `onboard --exclude` leaves an app out, by its folder or its project's
/// name: no project file, no store section. It stays left out when the
/// whole checkout is onboarded or drafted again, until its own folder is
/// named.
#[test]
fn onboard_leaves_out_the_apps_excluded() {
    let canary = Canary::new();
    let m = Machine::start(FakeAws::start(Vec::new()));
    let root = m.root();
    for app in ["web", "worker", "admin"] {
        let dir = root.join(format!("repo/apps/{app}"));
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(dir.join(".env.example"), "TOKEN=\n").unwrap();
        if app != "admin" {
            fs::write(
                dir.join(".env"),
                format!("TOKEN={}-{app}\n", canary.value()),
            )
            .unwrap();
        }
    }
    let names = |m: &Machine| {
        let (files, sections) = written(m);
        let files: Vec<String> = files.into_iter().map(|(name, _)| name).collect();
        (files, sections)
    };
    let skipped = |m: &Machine| {
        let o = m.run("home", &["--json", "onboard", "../repo"]);
        assert!(o.status.success(), "{}", text(&o.stderr));
        let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
        let skipped: Vec<(String, String)> = (v["skipped"].as_array().unwrap().iter())
            .map(|s| {
                let dir = s["dir"].as_str().unwrap().rsplit('/').next().unwrap();
                (dir.to_owned(), s["why"].as_str().unwrap().to_owned())
            })
            .collect();
        skipped
    };

    // A name that is no app's is said before anything is written.
    let before = written(&m);
    let o = m.run(
        "home",
        &[
            "onboard",
            "../repo",
            "--exclude",
            "apps/worker",
            "--exclude",
            "nope",
        ],
    );
    let err = text(&o.stderr);
    assert_eq!(o.status.code(), Some(2), "{err}");
    assert!(
        err.contains("--exclude nope names no app, by its folder or its project's name")
            && err.contains(&format!("{}/repo/apps/admin (repo-admin)", root.display())),
        "{err}"
    );
    assert_eq!(written(&m), before);
    let remembered = root.join("home/.local/state/kagebunshin/left-out.json");
    assert!(!remembered.exists());

    // By folder and by name; what is done is listed before the passphrase.
    let cmd = m.kb(
        "home",
        &[
            "onboard",
            "../repo",
            "--exclude",
            "apps/worker",
            "--exclude",
            "repo-admin",
        ],
    );
    let (exit, out) = common::on_terminal(&cmd, "pw\nn\n");
    assert_no_canary(&canary, &out);
    assert_eq!(exit, 0, "{out}");
    let listed = out
        .find(
            "onboarding 1 app in 1 checkout: 1 env file to import\n  \
             apps/web: import .env into new project repo-web\n  \
             apps/admin: left out\n  \
             apps/worker: left out\n",
        )
        .unwrap_or_else(|| panic!("{out}"));
    assert!(listed < out.find("Passphrase").unwrap(), "{out}");
    assert_eq!(
        names(&m),
        (
            vec!["repo-web.toml".to_owned()],
            vec!["repo-web.dev".to_owned()]
        )
    );

    // The whole checkout again, by `onboard`, `project draft --apply` and
    // `next`: both stay out, and nothing waits for them.
    let why = "left out before with --exclude";
    let left = skipped(&m);
    assert_eq!(left.len(), 2, "{left:?}");
    assert!(left.iter().all(|(_, w)| w.starts_with(why)), "{left:?}");
    let o = m.run("repo", &["project", "draft", "--apply"]);
    let all = text(&o.stdout) + &text(&o.stderr);
    assert!(
        all.contains("left out, as `kagebunshin onboard --exclude` said: apps/admin, apps/worker"),
        "{all}"
    );
    let o = m.run("repo", &["next"]);
    let said = text(&o.stdout);
    assert!(
        said.contains("\n  apps/worker: left out; `kagebunshin onboard` of its folder sets it up"),
        "{said}"
    );
    assert!(!said.contains("apps/worker/.env"), "{said}");
    assert_eq!(names(&m).0, ["repo-web.toml"]);

    // Its own folder named: set up, and no longer left out.
    let cmd = m.kb("repo/apps/worker", &["onboard"]);
    let (exit, out) = common::on_terminal(&cmd, "pw\nn\n");
    assert_no_canary(&canary, &out);
    assert_eq!(exit, 0, "{out}");
    assert_eq!(
        names(&m),
        (
            vec!["repo-web.toml".to_owned(), "repo-worker.toml".to_owned()],
            vec!["repo-web.dev".to_owned(), "repo-worker.dev".to_owned()]
        )
    );
    let left = skipped(&m);
    assert_eq!(left.len(), 1, "{left:?}");
    assert_eq!(left[0].0, "admin");
}

/// A wrong passphrase writes nothing and leaves the daemon locked.
#[test]
fn onboard_with_a_wrong_passphrase_writes_nothing() {
    let canary = Canary::new();
    let m = Machine::start(FakeAws::start(Vec::new()));
    three_checkouts(&m, &canary);
    assert!(m.run("home", &["lock"]).status.success());
    let before = written(&m);
    let cmd = m.kb("home", &["onboard", "../blog", "../web", "../repo"]);
    let (exit, out) = common::on_terminal(&cmd, "nope\n");
    assert_no_canary(&canary, &out);
    assert_eq!(exit, 1, "{out}");
    assert!(
        out.contains("wrong passphrase for the local store; nothing was written"),
        "{out}"
    );
    assert_eq!(written(&m), before);
    assert!(locked(&m));
    assert!(m.root().join("blog/.env").exists());
}
