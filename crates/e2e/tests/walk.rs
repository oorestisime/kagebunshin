//! The whole setup, start to finish, on a fresh machine: every command an
//! agent or a human runs on the way, with what it printed. The snapshots are
//! what a user and their agent are told; a change to one is a change to the
//! product's words, to be read as such.
//!
//! By default AWS is a fake in this process. `scripts/e2e.sh` runs the same
//! walk against the AWS Emulator, with the same snapshots.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test code")]

mod support;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::json;
use support::{CANARY, PASS, Sandbox, Walk, git};

/// What the organisation keeps in AWS Secrets Manager.
const SECRETS: [(&str, &str); 7] = [
    (
        "acme/dev/api",
        r#"{"API_KEY": "CANARYapikey5521900", "API_URL": "https://api.dev.acme.test"}"#,
    ),
    (
        "acme/dev/db",
        r#"{"DATABASE_URL": "postgres://app:CANARYdevdb7733@db.dev.acme.test/app"}"#,
    ),
    (
        "acme/dev/queue",
        r#"{"QUEUE_URL": "amqp://q:CANARYqueue9911@mq.dev.acme.test"}"#,
    ),
    ("acme/dev/signing", "CANARYplainstring88120"),
    (
        "acme/prod/db",
        r#"{"DATABASE_URL": "postgres://app:CANARYproddb1199@db.prod.acme.test/app"}"#,
    ),
    (
        "acme/prod/api",
        r#"{"API_KEY": "CANARYprodapi3300", "API_URL": "https://api.acme.test"}"#,
    ),
    ("other/dev/x", r#"{"X": "CANARYother4411"}"#),
];

/// `dir/test.sh`: says which of `vars` are set, never their values, and
/// fails when one is missing.
fn test_script(dir: &Path, vars: &[&str]) {
    let mut script = "#!/bin/sh\nrc=0\n".to_owned();
    for v in vars {
        script.push_str(&format!(
            "if [ -n \"${{{v}:-}}\" ]; then echo \"ok   {v}\"; else echo \"MISSING {v}\"; rc=1; fi\n"
        ));
    }
    script.push_str("exit $rc\n");
    let file = dir.join("test.sh");
    fs::write(&file, script).unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o755)).unwrap();
}

/// Four repositories, each a different starting point.
fn checkouts(sb: &Sandbox) {
    let work = sb.root().join("work");
    let write = |path: std::path::PathBuf, text: &str| {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    };

    // blog: a .env with values, and plain settings in the example.
    let d = sb.checkout("blog");
    write(
        d.join(".env.example"),
        "DATABASE_URL=\nSESSION_SECRET=\nPORT=3000\nLOG_LEVEL=info\n",
    );
    write(
        d.join(".env"),
        "DATABASE_URL=postgres://blog:CANARYblogdb1@localhost/blog\nSESSION_SECRET=CANARYblogsession2\nPORT=3000\nLOG_LEVEL=debug\n",
    );
    write(d.join(".gitignore"), ".env\n");
    test_script(&d, &["DATABASE_URL", "SESSION_SECRET", "PORT", "LOG_LEVEL"]);
    write(
        d.join("README.md"),
        "# blog\n\nRun the tests with `./test.sh`. It needs the variables in `.env.example`.\n",
    );

    // api: secrets in AWS Secrets Manager, listed by two deploy workflows
    // (a variable one passes on, the commands of the other), and one more
    // named by a script that no workflow runs.
    let d = sb.checkout("api");
    write(
        d.join(".env.example"),
        "API_KEY=\nAPI_URL=\nDATABASE_URL=\nSIGNING_KEY=\nLOG_LEVEL=info\n",
    );
    write(
        d.join(".github/workflows/deploy-dev.yml"),
        "name: deploy (dev)\non: { push: { branches: [main] } }\nenv:\n  LOADS: acme/dev/db,acme/dev/api\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: ./scripts/deploy.sh \"${{ env.LOADS }}\"\n",
    );
    write(
        d.join(".github/workflows/deploy-prod.yml"),
        "name: deploy (prod)\non: { release: { types: [published] } }\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    environment: production\n    steps:\n      - uses: actions/checkout@v4\n      - name: secrets\n        run: |\n          aws secretsmanager get-secret-value --secret-id acme/prod/db\n          aws secretsmanager get-secret-value --secret-id acme/prod/api\n",
    );
    write(
        d.join("scripts/seed.sh"),
        "#!/bin/sh\naws secretsmanager get-secret-value --secret-id acme/dev/queue\n",
    );
    test_script(
        &d,
        &[
            "API_KEY",
            "API_URL",
            "DATABASE_URL",
            "SIGNING_KEY",
            "LOG_LEVEL",
        ],
    );
    write(
        d.join("README.md"),
        "# api\n\nRun the tests with `./test.sh`. It needs the variables in `.env.example`. Development secrets are in AWS Secrets Manager under `acme/dev/` (profile `acme-dev`).\n",
    );

    // mono: two apps, one with a .env, one on AWS.
    let d = sb.checkout("mono");
    write(
        d.join("apps/web/.env.example"),
        "SESSION_SECRET=\nPUBLIC_URL=http://localhost:3000\n",
    );
    write(
        d.join("apps/web/.env"),
        "SESSION_SECRET=CANARYmonosession3\nPUBLIC_URL=http://localhost:3000\n",
    );
    write(d.join("apps/worker/.env.example"), "QUEUE_URL=\nAPI_KEY=\n");
    test_script(&d.join("apps/web"), &["SESSION_SECRET", "PUBLIC_URL"]);
    test_script(&d.join("apps/worker"), &["QUEUE_URL", "API_KEY"]);
    write(
        d.join("README.md"),
        "# mono\n\nTwo apps: `apps/web` and `apps/worker`. Each has `./test.sh` and a `.env.example`. The worker reads AWS Secrets Manager (`acme/dev/`, profile `acme-dev`).\n",
    );

    // shop: no .env and no provider; every value comes from the human or a
    // plain setting.
    let d = sb.checkout("shop");
    write(
        d.join(".env.example"),
        "DATABASE_URL=\nSTRIPE_SECRET=\nPORT=3000\n",
    );
    test_script(&d, &["DATABASE_URL", "STRIPE_SECRET", "PORT"]);
    write(
        d.join("README.md"),
        "# shop\n\nRun the tests with `./test.sh`. It needs the variables in `.env.example`.\n",
    );

    for name in ["blog", "api", "mono", "shop"] {
        git(&work.join(name), &["add", "-A"]);
        git(&work.join(name), &["commit", "-qm", "init"]);
    }
}

/// Opens the app in `dir` for `seconds`, has the human do `script` in it,
/// and waits for it to close.
fn in_app(sb: &Sandbox, dir: &str, seconds: f32, script: serde_json::Value) {
    let status = sb
        .app(&sb.root().join(dir), seconds, Some(&script))
        .wait()
        .unwrap();
    assert!(status.success(), "the app failed: {status}");
}

#[test]
fn the_setup_walk() {
    let sb = Sandbox::start(&SECRETS);
    checkouts(&sb);
    let mut w = Walk::new(sb);
    let typed_pass = format!("{PASS}\n");

    w.sec("setup", "S. Machine setup");
    w.cd("work/blog");
    w.r("kagebunshin next");
    w.cd("work");
    w.h(
        &format!("{PASS}\n{PASS}\n"),
        "kagebunshin setup --no-service",
    );
    w.r("kagebunshin --help | grep -E '^  (onboard|next) '");

    w.sec("55_env_only", "55. A .env-only repository (blog)");
    w.cd("work/blog");
    w.r("kagebunshin status");
    w.r("kagebunshin --json status");
    w.hook("start", "");
    w.r("kagebunshin next");
    w.r("kagebunshin --json next");
    w.note("the old trap: the agent runs project init anyway");
    w.r("kagebunshin project init blog");
    w.r("kagebunshin next");
    w.h(&format!("{PASS}\nn\n"), "kagebunshin onboard $T/work/blog");
    w.r("kagebunshin next");
    w.r("kagebunshin run --strict -- ./test.sh");
    w.r("kagebunshin next");
    w.r("kagebunshin status");
    w.note("project remove");
    w.sb.checkout("scratch");
    w.cd("work/scratch");
    w.r("kagebunshin project init scratch");
    w.r("kagebunshin project remove scratch");
    w.r("kagebunshin status");

    w.sec(
        "56_57_no_provider",
        "56, 57. A new project can be read before its store section exists, and plain settings (shop)",
    );
    w.cd("work/shop");
    w.r("kagebunshin project init shop");
    w.r("kagebunshin status");
    w.r("kagebunshin diff");
    w.r("kagebunshin run -- ./test.sh");
    w.r("kagebunshin next");
    w.note("57: a plain setting");
    w.r("kagebunshin project set-var shop dev PORT 3000");
    w.r("kagebunshin status");
    w.r("kagebunshin run --strict -- ./test.sh");
    w.r("kagebunshin next");
    w.note("56 again: the human sets both secrets with one passphrase prompt");
    w.h(
        &format!("{PASS}\npostgres://shop:CANARYshopdb@localhost/shop\nsk_test_CANARYstripe\n"),
        "kagebunshin store set shop.dev DATABASE_URL STRIPE_SECRET",
    );
    w.r("kagebunshin run --strict -- ./test.sh");
    w.r("kagebunshin next");
    w.r(r#"kagebunshin run -- sh -c 'echo "port is $PORT, db is $DATABASE_URL"'"#);
    w.note("a source wins over a plain setting");
    w.r("kagebunshin project set-var shop dev DATABASE_URL from-the-project-file");
    w.r("kagebunshin status | grep -E 'DATABASE_URL|overrid'");
    w.r("kagebunshin project unset-var shop dev DATABASE_URL");
    w.note("known gap: a secret-looking name is accepted without a warning");
    w.r("kagebunshin project set-var shop dev API_TOKEN abc");
    w.r("kagebunshin project unset-var shop dev API_TOKEN");
    w.r("cat $HOME/.config/kagebunshin/projects/shop.toml");

    w.sec(
        "61_find_a_key",
        "61. Finding which secret holds a key (api)",
    );
    w.cd("work/api");
    w.r("kagebunshin list --keys --prefix acme/dev/ --profile acme-dev");
    w.r("kagebunshin search DATABASE_URL --keys --profile acme-dev");
    w.r("kagebunshin project facts");
    w.r("kagebunshin project draft");

    w.sec("onboard", "O. onboard several checkouts at once");
    w.cd("work");
    w.h(&format!("{PASS}\nn\n"), "kagebunshin onboard api mono");

    w.sec("agent_to_done", "A. The agent walks api to done with next");
    w.cd("work/api");
    w.hook("start", "");
    w.r("kagebunshin next");
    w.r("kagebunshin project set-var api dev LOG_LEVEL info");
    w.r("kagebunshin next");
    w.r("kagebunshin list --keys --prefix acme/dev/");
    w.r("kagebunshin project add-source api dev --provider aws_sm --secret acme/dev/signing --key SIGNING_KEY --profile acme-dev");
    w.r("kagebunshin next");
    w.note("a failing command proves nothing");
    w.r("kagebunshin run --strict -- false");
    w.r("kagebunshin next");
    w.r("kagebunshin run --strict -- ./test.sh");
    w.r("kagebunshin next");
    w.note("78: the prod environment the draft took from deploy-prod.yml is the agent's to mark");
    w.r("kagebunshin mark env api prod");
    w.sb.audited("add mark env", "api", "prod");
    w.r("kagebunshin next");
    w.r("kagebunshin --json next");
    w.r("kagebunshin status");
    w.hook("start", "");
    w.note("the proof is dropped when the environment changes, and comes back when it is put back");
    w.r("kagebunshin project set-var api dev EXTRA 1");
    w.r("kagebunshin next");
    w.r("kagebunshin project unset-var api dev EXTRA");
    w.r("kagebunshin next");

    w.sec(
        "59_plain_string_secret",
        "59. One plain-string secret under an AWS prefix (api, environment qa)",
    );
    w.r("kagebunshin project add-env api qa");
    w.r("kagebunshin project add-source api qa --provider aws_sm --prefix acme/dev/ --profile acme-dev");
    w.r("kagebunshin --env qa status");
    w.r("kagebunshin --env qa diff");
    w.r("kagebunshin --env qa run -- ./test.sh");
    w.r("kagebunshin --env qa run --strict -- ./test.sh");
    w.note("58: with --json, the warning is JSON too");
    w.r("kagebunshin --json --env qa run -- true");
    w.note("the fix the warning names, with no sync after it");
    w.r("kagebunshin project add-source api qa --provider aws_sm --secret acme/dev/signing --key SIGNING_KEY --profile acme-dev");
    w.r("kagebunshin project set-var api qa LOG_LEVEL info");
    w.r("kagebunshin --env qa run --strict -- ./test.sh");
    w.r("kagebunshin --env qa next");

    w.sec(
        "58_refusals",
        "58. Refusals name what the agent can do, and who does the rest",
    );
    w.r("kagebunshin --env staging status");
    w.r("kagebunshin --json --env staging status");
    w.note("locked");
    w.r("kagebunshin lock");
    w.r("kagebunshin run -- ./test.sh");
    w.r("kagebunshin --json run -- ./test.sh");
    w.r("kagebunshin next");
    w.hook("start", "");
    w.h(&typed_pass, "kagebunshin unlock");
    w.note("daemon not running");
    w.sb.stop_daemon();
    w.r("kagebunshin run -- ./test.sh");
    w.r("kagebunshin next");
    w.hook("start", "");
    w.sb.start_daemon();
    w.h(&typed_pass, "kagebunshin unlock");

    w.sec("60_hooks", "60. Hooks");
    w.hook("bash", "cp .env.example .env");
    w.hook("bash", r#"echo "A=1" > .env"#);
    w.hook("bash", "cat > .env.local <<EOF");
    w.hook("bash", "tee .env.production");
    w.hook("write", ".env");
    w.note("allowed");
    w.hook("bash", "cat .env.example");
    w.hook("bash", "echo hi > .env.example");
    w.hook("bash", "grep FOO .env");
    w.hook("write", ".env.example");
    w.note("known limits");
    w.hook("bash", "cp .env.example .env.sample");
    w.hook("bash", "sh -c 'echo A=1 > .env'");
    w.note("session start, in an app that is registered and not yet proven");
    w.cd("work/mono/apps/worker");
    w.hook("start", "");
    w.note("session start, at the root of a repository of several apps");
    w.cd("work/mono");
    w.hook("start", "");
    w.note("session start, in no project, with only a .env.example");
    let fresh = w.sb.checkout("fresh");
    fs::write(fresh.join(".env.example"), "TOKEN=\n").unwrap();
    w.cd("work/fresh");
    w.hook("start", "");
    w.note("session start, in no project, with no env files");
    w.cd("work/empty");
    w.hook("start", "");

    w.sec("mono", "M. A repository of several apps (mono)");
    w.cd("work/mono");
    w.r("kagebunshin next");
    w.r("kagebunshin status");
    w.r("(cd apps/web && kagebunshin run --strict -- ./test.sh)");
    w.r("kagebunshin next");
    w.r("(cd apps/worker && kagebunshin run --strict -- ./test.sh)");
    w.r("kagebunshin next");

    w.sec(
        "62_production_waits",
        "62. Production: the agent marks what is named so, the human decides the rest",
    );
    w.cd("work/api");
    w.note("api's prod was drafted from a workflow and marked in A; here is one added by hand, read with the production account's profile");
    w.r("kagebunshin project add-env api production");
    w.r("kagebunshin project add-source api production --provider aws_sm --secret acme/prod/api --profile acme-prod");
    w.r("kagebunshin --env production run -- ./test.sh");
    w.r("kagebunshin --json --env production run -- ./test.sh");
    w.r("kagebunshin --env production status");
    w.r("kagebunshin --env production next");
    w.r("kagebunshin next");
    w.note("the agent marks it: no passphrase, no human");
    w.r("kagebunshin mark env api production");
    w.sb.audited("add mark env", "api", "production");
    w.r("kagebunshin --env production next");
    w.r("kagebunshin next");
    w.note("there is no command that takes a mark off or says it is not production");
    w.r("kagebunshin unmark env api production");
    w.r("kagebunshin mark --help | grep -E '^  [a-z]'");
    w.note(
        "the store takes the passphrase to write: the mark waits beside it until the next unlock",
    );
    w.r("ls $HOME/.config/kagebunshin | grep store");
    w.r("kagebunshin lock");
    w.h(&typed_pass, "kagebunshin unlock");
    w.r("ls $HOME/.config/kagebunshin | grep store");
    w.r("kagebunshin --env prod run -- ./test.sh");
    w.note("what only may be production is the human's to decide: an environment named rc");
    w.r("kagebunshin project add-env api rc");
    w.r("kagebunshin --env rc next");
    w.cd("work/shop");
    w.r("kagebunshin project add-env shop prod");
    w.cd("work/api");
    w.note("the human, in the app: api/rc -> Mark sensitive");
    in_app(
        &w.sb,
        "work/api",
        6.0,
        json!([
            { "t": 2, "type": "click", "key": "kb-waiting-mark-api-rc" },
            { "t": 3, "type": "type", "text": PASS },
            { "t": 4, "type": "click", "key": "kb-passphrase-ok" },
        ]),
    );
    w.sb.audited("mark env", "api", "rc");
    w.note("both are marked sensitive, and the app is closed: refused at once");
    std::thread::sleep(Duration::from_secs(1));
    let start = Instant::now();
    w.r("kagebunshin --env prod run -- ./test.sh");
    assert!(start.elapsed() < Duration::from_secs(5), "not at once");
    w.r("kagebunshin --env prod next");
    w.note("the app is open: the run waits and the app asks. The human closes the app with no answer, and the run is refused");
    let mut app = w.sb.app(&w.sb.root().join("work/api"), 5.0, None);
    std::thread::sleep(Duration::from_secs(2));
    let start = Instant::now();
    w.r("kagebunshin --env prod run -- ./test.sh");
    let waited = start.elapsed();
    assert!(
        waited > Duration::from_secs(1) && waited < Duration::from_secs(15),
        "the run waited {waited:?}"
    );
    app.wait().unwrap();
    w.note("the app is open and the human does not answer: the run is refused once `approval_timeout` in config.toml is over (3 seconds here, 5 minutes unless set), and says what it asked for");
    let config = w.sb.root().join("home/.config/kagebunshin/config.toml");
    assert!(!config.exists(), "the walk has no config.toml of its own");
    fs::write(&config, "schema = 1\napproval_timeout = \"3s\"\n").unwrap();
    let mut app = w.sb.app(&w.sb.root().join("work/api"), 7.0, None);
    std::thread::sleep(Duration::from_secs(2));
    let start = Instant::now();
    w.r("kagebunshin --env prod run -- ./test.sh");
    let waited = start.elapsed();
    assert!(
        waited > Duration::from_secs(2) && waited < Duration::from_secs(6),
        "the run waited {waited:?}"
    );
    app.wait().unwrap();
    fs::remove_file(&config).unwrap();
    w.note("the human clicks Deny");
    let mut app = w.sb.app(
        &w.sb.root().join("work/api"),
        6.0,
        Some(&json!([{ "t": 4, "type": "click", "key": "kb-approval-deny" }])),
    );
    std::thread::sleep(Duration::from_secs(2));
    w.r("kagebunshin --env prod run -- ./test.sh");
    app.wait().unwrap();
    w.note("the human types the passphrase and clicks Approve");
    let mut app = w.sb.app(
        &w.sb.root().join("work/api"),
        7.0,
        Some(&json!([
            { "t": 3.5, "type": "click", "key": "kb-approval-field" },
            { "t": 4, "type": "type", "text": PASS },
            { "t": 5, "type": "click", "key": "kb-approval-ok" },
        ])),
    );
    std::thread::sleep(Duration::from_secs(2));
    w.r("kagebunshin --env prod run -- ./test.sh");
    app.wait().unwrap();
    w.note("the human, in the app: shop/prod -> Not production");
    in_app(
        &w.sb,
        "work/shop",
        6.0,
        json!([
            { "t": 2, "type": "click", "key": "kb-waiting-ack-shop-prod" },
            { "t": 3, "type": "type", "text": PASS },
            { "t": 4, "type": "click", "key": "kb-passphrase-ok" },
        ]),
    );
    w.sb.audited("acknowledge env", "shop", "prod");
    w.cd("work/shop");
    w.r("kagebunshin --env prod status");
    w.r("kagebunshin --env prod run -- ./test.sh");
    w.note("what the human decided, an agent's mark does not undo");
    w.r("kagebunshin mark env shop prod");

    w.sec(
        "76_other_env_files",
        "76. Env files under other names (.dev.env, production.env) go in with --file",
    );
    // The app of the section before just ended; open, `next` words the
    // steps for it.
    w.sb.app_closed();
    let site = w.sb.checkout("site");
    fs::write(site.join(".env.example"), "API_TOKEN=\nSITE_URL=\n").unwrap();
    fs::write(
        site.join(".dev.env"),
        "API_TOKEN=CANARYsitedev5\nSITE_URL=http://localhost:4000\n",
    )
    .unwrap();
    fs::write(
        site.join("production.env"),
        "API_TOKEN=CANARYsiteprod6\nSITE_URL=https://site.acme.test\n",
    )
    .unwrap();
    test_script(&site, &["API_TOKEN", "SITE_URL"]);
    w.cd("work/site");
    w.r("kagebunshin next");
    w.note("onboard takes neither by itself, and says so");
    w.h("", "kagebunshin onboard");
    w.note("each goes in by its line, with its environment");
    w.h(
        &format!("{PASS}\nn\n"),
        "kagebunshin onboard --file $T/work/site/.dev.env --env dev",
    );
    w.h(
        &format!("{PASS}\nn\n"),
        "kagebunshin onboard --file production.env --env production",
    );
    w.r("cat $HOME/.config/kagebunshin/projects/site.toml");
    w.r("kagebunshin run --strict -- ./test.sh");
    w.r("kagebunshin next");
    w.note(
        "a second file for the same environment goes in over the first, and says what it replaced",
    );
    fs::write(site.join("local.env"), "API_TOKEN=CANARYsitelocal7\n").unwrap();
    w.h(
        &typed_pass,
        "kagebunshin --json onboard --file local.env --env dev --keep-env",
    );
    w.note("in a repository of several apps, a file outside every app's folder needs its project named");
    fs::write(
        w.sb.root().join("work/mono/staging.env"),
        "SESSION_SECRET=CANARYmonostaging8\nPUBLIC_URL=https://staging.acme.test\n",
    )
    .unwrap();
    w.cd("work/mono");
    w.r("kagebunshin next");
    w.h("", "kagebunshin onboard --file staging.env --env staging");
    w.h(
        &format!("{PASS}\ny\n"),
        "kagebunshin onboard --file staging.env --env staging --name mono-web",
    );
    w.r("(cd apps/web && kagebunshin --env staging run --strict -- ./test.sh)");
    w.r("kagebunshin next");
    w.note("with one app, a file outside its folder is that app's: no name to give");
    let solo = w.sb.checkout("solo");
    fs::create_dir_all(solo.join("apps/web")).unwrap();
    fs::write(solo.join("apps/web/.env.example"), "API_TOKEN=\n").unwrap();
    fs::write(solo.join("apps/web/.env"), "API_TOKEN=CANARYsolodev20\n").unwrap();
    fs::write(solo.join("production.env"), "API_TOKEN=CANARYsoloprod21\n").unwrap();
    w.cd("work/solo");
    w.h(&format!("{PASS}\nn\n"), "kagebunshin onboard");
    w.h(
        &format!("{PASS}\nn\n"),
        "kagebunshin onboard --file production.env --env production",
    );

    w.sec(
        "71_agent_imports",
        "71. The agent imports env files, and the human approves it in the app",
    );
    for (name, token) in [("inbox", "CANARYinbox9"), ("ledger", "CANARYledger10")] {
        let dir = w.sb.checkout(name);
        fs::write(dir.join(".env.example"), "API_TOKEN=\nPORT=\n").unwrap();
        fs::write(dir.join(".env"), format!("API_TOKEN={token}\nPORT=4100\n")).unwrap();
        test_script(&dir, &["API_TOKEN", "PORT"]);
    }
    w.cd("work");
    w.sb.app_closed();
    w.note("the app is closed: the human is asked to open it, and an onboard run anyway imports nothing");
    w.r("kagebunshin next inbox ledger");
    w.r("kagebunshin onboard inbox ledger");
    w.r("kagebunshin --json onboard inbox ledger");
    w.note("the app is open: the import is the agent's step");
    let mut app = w.sb.app(&w.sb.root().join("work"), 6.0, None);
    std::thread::sleep(Duration::from_secs(2));
    w.r("kagebunshin next inbox ledger");
    w.note("the human does not answer (`approval_timeout` is 3 seconds here): nothing is imported");
    let config = w.sb.root().join("home/.config/kagebunshin/config.toml");
    fs::write(&config, "schema = 1\napproval_timeout = \"3s\"\n").unwrap();
    w.r("kagebunshin onboard inbox ledger");
    app.wait().unwrap();
    fs::remove_file(&config).unwrap();
    w.note("the human clicks Deny: nothing is imported");
    let mut app = w.sb.app(
        &w.sb.root().join("work"),
        6.0,
        Some(&json!([{ "t": 4, "type": "click", "key": "kb-approval-deny" }])),
    );
    std::thread::sleep(Duration::from_secs(2));
    w.r("kagebunshin onboard inbox ledger");
    app.wait().unwrap();
    w.r("ls $HOME/.config/kagebunshin/projects | grep -E 'inbox|ledger'");
    w.note("the human types the passphrase once and clicks Approve: both checkouts are imported");
    let mut app = w.sb.app(
        &w.sb.root().join("work"),
        7.0,
        Some(&json!([
            { "t": 3.5, "type": "click", "key": "kb-approval-field" },
            { "t": 4, "type": "type", "text": PASS },
            { "t": 5, "type": "click", "key": "kb-approval-ok" },
        ])),
    );
    std::thread::sleep(Duration::from_secs(2));
    w.r("kagebunshin onboard inbox ledger");
    app.wait().unwrap();
    w.note("the agent goes on to done, with nothing more from the human");
    w.r("kagebunshin next inbox ledger");
    w.r("cd $T/work/inbox && kagebunshin run --strict -- ./test.sh");
    w.r("kagebunshin next inbox ledger");
    w.r("cd $T/work/ledger && kagebunshin run --strict -- ./test.sh");
    w.r("kagebunshin next inbox ledger");
    w.note(
        "the daemon has locked meanwhile: `next` asks for the unlock first, and an onboard run \
         anyway is not stuck, its approval unlocks too",
    );
    let dir = w.sb.checkout("pager");
    fs::write(dir.join(".env.example"), "API_TOKEN=\n").unwrap();
    fs::write(dir.join(".env"), "API_TOKEN=CANARYpager11\n").unwrap();
    test_script(&dir, &["API_TOKEN"]);
    w.r("kagebunshin lock");
    let mut app = w.sb.app(
        &w.sb.root().join("work"),
        7.0,
        Some(&json!([
            { "t": 3.5, "type": "click", "key": "kb-approval-field" },
            { "t": 4, "type": "type", "text": PASS },
            { "t": 5, "type": "click", "key": "kb-approval-ok" },
        ])),
    );
    std::thread::sleep(Duration::from_secs(2));
    w.r("kagebunshin next pager");
    w.r("kagebunshin onboard pager");
    app.wait().unwrap();
    w.r("cd $T/work/pager && kagebunshin run --strict -- ./test.sh");
    w.note("each request is in the audit log, by key name");
    w.r("kagebunshin audit | grep -E 'store import|unlock' | tail -8");

    w.sec(
        "77_leave_out_and_clear",
        "77. Leaving an app out, and clearing what a removed project left",
    );
    let dir = w.sb.checkout("depot");
    for (app, token) in [
        ("front", "CANARYfront12"),
        ("back", "CANARYback13"),
        ("legacy", "CANARYlegacy14"),
    ] {
        let dir = dir.join("apps").join(app);
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(dir.join(".env.example"), "API_TOKEN=\n").unwrap();
        fs::write(dir.join(".env"), format!("API_TOKEN={token}\n")).unwrap();
        test_script(&dir, &["API_TOKEN"]);
    }
    w.cd("work");
    w.note("a name that is no app's is said before anything is written");
    w.r("kagebunshin onboard depot --exclude apps/old");
    w.note("the apps are listed before the passphrase; the one left out gets no project and no section");
    w.h(
        &format!("{PASS}\nn\n"),
        "kagebunshin onboard depot --exclude apps/legacy",
    );
    w.r("kagebunshin store list | grep depot");
    w.cd("work/depot");
    w.note(
        "it stays out: `next` does not wait for it, and the checkout drafted again passes over it",
    );
    w.r("kagebunshin next");
    w.r("kagebunshin project draft --apply");
    w.r("ls $HOME/.config/kagebunshin/projects | grep depot");
    w.note("a project removed leaves its values in the store, and says how to clear them");
    w.r("kagebunshin project remove depot-back");
    w.note("clearing is refused while the project is there, and takes the passphrase: a person's");
    w.r("kagebunshin store clear depot-front");
    w.r("kagebunshin --json store clear depot-back");
    w.h(&typed_pass, "kagebunshin store clear depot-back");
    w.r("kagebunshin store list | grep depot");

    w.sec(
        "80_no_example",
        "80. An app with no .env.example is done without one, and is offered it",
    );
    let dir = w.sb.checkout("kiosk");
    fs::create_dir_all(dir.join("src")).unwrap();
    fs::write(
        dir.join(".env"),
        "API_TOKEN=CANARYkiosk15\nDB_URL=postgres://kiosk:CANARYkiosk16@db.acme.test/kiosk\n\
         MAIL_TOKEN=CANARYkiosk17\nQUEUE_URL=amqp://q:CANARYkiosk18@mq.acme.test\n\
         SESSION_SECRET=CANARYkiosk19\n",
    )
    .unwrap();
    fs::write(
        dir.join("src/env.ts"),
        "export const env = schema({\n  API_TOKEN: string(),\n  SESSION_SECRET: string().optional(),\n});\n",
    )
    .unwrap();
    fs::write(
        dir.join("src/server.ts"),
        "import { env } from './env';\nconst db = connect(process.env.DB_URL);\n\
         serve(db, env.API_TOKEN, process.env.NODE_ENV);\n",
    )
    .unwrap();
    w.cd("work");
    w.h(&format!("{PASS}\nn\n"), "kagebunshin onboard kiosk");
    w.cd("work/kiosk");
    w.note("with no list of its keys, a command gets all five");
    let passed = "env | cut -d= -f1 | grep -xE 'API_TOKEN|DB_URL|MAIL_TOKEN|QUEUE_URL|SESSION_SECRET' | sort";
    w.r(&format!("kagebunshin run -- sh -c \"{passed}\""));
    w.note("the list is no step: the proof is next, and setup is done with all five");
    w.r("kagebunshin next");
    w.r(&format!("kagebunshin run --strict -- sh -c \"{passed}\""));
    w.note("done, with the list suggested: the agent passes that on, and writes it if asked");
    w.r("kagebunshin next");
    w.note("asked: the command reads the code, never the .env");
    w.r("kagebunshin project example");
    w.r("cat .env.example");
    w.note("it is written once, and the agent's to edit from then on");
    w.r("kagebunshin project example");
    w.note("now a command gets the three the app reads, and nothing more is suggested");
    w.r(&format!("kagebunshin run --strict -- sh -c \"{passed}\""));
    w.r("kagebunshin next");

    w.sec(
        "88_typed_in_the_app",
        "88. Secrets in no file: the agent asks, and the human types them in the app",
    );
    let dir = w.sb.checkout("beacon");
    fs::write(dir.join(".env.example"), "API_TOKEN=\nWEBHOOK_SECRET=\n").unwrap();
    test_script(&dir, &["API_TOKEN", "WEBHOOK_SECRET"]);
    w.cd("work/beacon");
    w.r("kagebunshin project init beacon");
    let set = "kagebunshin store set beacon.dev API_TOKEN WEBHOOK_SECRET";
    w.sb.app_closed();
    w.note(
        "the app is closed: typing them is the human's, and the command run anyway sets nothing",
    );
    w.r("kagebunshin next");
    w.r(set);
    w.r(&format!(
        "kagebunshin --json {}",
        set.strip_prefix("kagebunshin ").unwrap()
    ));
    w.note("the app is open: asking for them is the agent's step");
    let mut app = w.sb.app(&dir, 6.0, None);
    std::thread::sleep(Duration::from_secs(2));
    w.r("kagebunshin next");
    app.wait().unwrap();
    w.note("the human clicks Deny: nothing is set");
    let mut app = w.sb.app(
        &dir,
        6.0,
        Some(&json!([{ "t": 4, "type": "click", "key": "kb-approval-deny" }])),
    );
    std::thread::sleep(Duration::from_secs(2));
    w.r(set);
    app.wait().unwrap();
    w.note(
        "the human types one value and the passphrase, and clicks Save: the other key is as before",
    );
    let mut app = w.sb.app(
        &dir,
        8.0,
        Some(&json!([
            { "t": 3.5, "type": "click", "key": "kb-approval-value-0" },
            { "t": 4, "type": "type", "text": "CANARYbeacon20" },
            { "t": 4.5, "type": "click", "key": "kb-approval-field" },
            { "t": 5, "type": "type", "text": PASS },
            { "t": 6, "type": "click", "key": "kb-approval-ok" },
        ])),
    );
    std::thread::sleep(Duration::from_secs(2));
    w.r(set);
    app.wait().unwrap();
    w.r("kagebunshin store list | grep beacon");
    w.note("asked again, the human types both: the one there is replaced, which the agent is told");
    let mut app = w.sb.app(
        &dir,
        9.0,
        Some(&json!([
            { "t": 3.5, "type": "click", "key": "kb-approval-value-0" },
            { "t": 4, "type": "type", "text": "CANARYbeacon21" },
            { "t": 4.5, "type": "click", "key": "kb-approval-value-1" },
            { "t": 5, "type": "type", "text": "CANARYbeacon22" },
            { "t": 5.5, "type": "click", "key": "kb-approval-field" },
            { "t": 6, "type": "type", "text": PASS },
            { "t": 7, "type": "click", "key": "kb-approval-ok" },
        ])),
    );
    std::thread::sleep(Duration::from_secs(2));
    w.r(&format!(
        "kagebunshin --json {}",
        set.strip_prefix("kagebunshin ").unwrap()
    ));
    app.wait().unwrap();
    w.r("kagebunshin run --strict -- ./test.sh");
    w.note("what was typed is what a command gets: 14 characters each");
    w.r(r#"kagebunshin run -- sh -c 'echo "${#API_TOKEN} ${#WEBHOOK_SECRET}"'"#);
    w.r("kagebunshin next");
    w.note("each request is in the audit log, with the keys that were typed");
    w.r("kagebunshin audit | grep -E 'beacon' | tail -8");

    w.sec("values", "V. Values stay out of the agent's sight");
    w.cd("work/api");
    w.r(r#"kagebunshin run -- sh -c 'echo "key is $API_KEY"'"#);
    w.r("kagebunshin get API_KEY");
    w.h(&typed_pass, "kagebunshin get API_URL");
    w.h(&typed_pass, "kagebunshin get LOG_LEVEL");
    w.r("kagebunshin audit | grep -E 'api/prod|api/rc|shop/prod' | tail -20");

    // No stored value in anything printed above, nor in what the daemon
    // logged or audited. What the human typed was taken out as it was read.
    let sections = w.sections();
    for (name, text) in &sections {
        assert!(
            !text.contains(CANARY),
            "a value was printed in section {name}"
        );
    }
    assert!(
        !w.sb.daemon_log().contains(CANARY),
        "a value in the daemon's log"
    );
    let audit = w.sb.sh(&w.sb.root(), "kagebunshin audit").output().unwrap();
    assert!(
        !String::from_utf8_lossy(&audit.stdout).contains(CANARY),
        "a value in the audit log"
    );
    for (name, text) in sections {
        insta::assert_snapshot!(name, text);
    }
}
