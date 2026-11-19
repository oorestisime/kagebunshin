//! The daemon's state machine, cache and resolver, in process, with
//! [`FakeSources`] for every provider.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::broker::Daemon;
use super::resolve::{AwsClients, ResolveError};
use crate::config::{Config, Profile, Region, Registry, RemoteId, parse_project};
use crate::ipc::protocol::{
    ErrorCode, Facts, MarkTarget, Request, Response, StatusReport, WireSecret,
};
use crate::secret::SecretValue;
use crate::source::aws_sm::{ApiError, Got, Page, RawSecret, SmApi};
use crate::store::{Change, Passphrase, STORE_FILE, Store, StoreFile};
use crate::test_support::{Canary, FakeSources, assert_no_canary, this_process};
use crate::types::{KeyName, Origin, Provider};

/// A file-store section, then an AWS prefix, then an optional AWS secret:
/// later wins.
const WIDGET: &str = r#"
schema = 1
remotes = ["git@github.com:acme/widget.git"]

[envs.dev]
[[envs.dev.sources]]
provider = "file"
secret = "widget.dev"
[[envs.dev.sources]]
provider = "aws_sm"
prefix = "widget/dev/"
[[envs.dev.sources]]
provider = "aws_sm"
secret = "widget/local"
optional = true

# Marked sensitive in the store by `staging_marked`.
[envs.staging]
[[envs.staging.sources]]
provider = "aws_sm"
secret = "widget/staging"

[envs.prod]
[envs.production]
[envs.rc]

[envs.leaky]
[[envs.leaky.sources]]
provider = "aws_sm"
prefix = "widget/prod/"

[envs.leaky-rc]
[[envs.leaky-rc.sources]]
provider = "aws_sm"
secret = "widget/rc/db"
"#;

fn daemon(fake: &Arc<FakeSources>) -> Daemon {
    daemon_for(WIDGET, fake)
}

fn daemon_for(project: &str, fake: &Arc<FakeSources>) -> Daemon {
    let project = parse_project(Path::new("/cfg/projects/widget.toml"), project).unwrap();
    let registry = Registry::new(Config::default(), vec![project]).unwrap();
    // A store path that never exists, for tests that do not use the store.
    let store = StoreFile::new("/nonexistent/kagebunshin-test/store.age");
    Daemon::new(Box::new(move || Ok(registry.clone())), fake.clone(), store)
}

/// A daemon for `project` whose store, with passphrase `pw`, holds the marks
/// `mark` makes; unlocked.
async fn marked_daemon(
    project: &str,
    fake: &Arc<FakeSources>,
    mark: impl FnOnce(&mut Store),
) -> (tempfile::TempDir, Daemon) {
    let tmp = tempfile::tempdir().unwrap();
    let file = StoreFile::new(tmp.path().join(STORE_FILE)).with_test_work_factor();
    let pass = Passphrase::new("pw".into());
    file.create(&pass).unwrap();
    file.update(&pass, None, |st| {
        mark(st);
        Ok(())
    })
    .unwrap();
    let project = parse_project(Path::new("/cfg/projects/widget.toml"), project).unwrap();
    let registry = Registry::new(Config::default(), vec![project]).unwrap();
    let d = Daemon::new(Box::new(move || Ok(registry.clone())), fake.clone(), file);
    d.unlock(Some(pass)).await.unwrap();
    (tmp, d)
}

/// As [`marked_daemon`], for a project file that changes: the daemon reads
/// `project` again on every request.
async fn changing_daemon(
    project: &Arc<Mutex<String>>,
    fake: &Arc<FakeSources>,
    mark: impl FnOnce(&mut Store),
) -> (tempfile::TempDir, Daemon) {
    let tmp = tempfile::tempdir().unwrap();
    let file = StoreFile::new(tmp.path().join(STORE_FILE)).with_test_work_factor();
    let pass = Passphrase::new("pw".into());
    file.create(&pass).unwrap();
    file.update(&pass, None, |st| {
        mark(st);
        Ok(())
    })
    .unwrap();
    let load = {
        let project = project.clone();
        move || {
            let path = Path::new("/cfg/projects/widget.toml");
            let project = parse_project(path, &project.lock().unwrap()).unwrap();
            Registry::new(Config::default(), vec![project])
        }
    };
    let d = Daemon::new(Box::new(load), fake.clone(), file);
    d.unlock(Some(pass)).await.unwrap();
    (tmp, d)
}

/// [`WIDGET`] with environment staging marked sensitive.
async fn staging_marked(fake: &Arc<FakeSources>) -> (tempfile::TempDir, Daemon) {
    marked_daemon(WIDGET, fake, |st| {
        st.mark_env("widget.staging".parse().unwrap(), true);
    })
    .await
}

fn facts(env: Option<&str>, example: Option<&[&str]>) -> Facts {
    Facts {
        cwd: "/src/widget/apps/web".into(),
        remotes: vec![RemoteId::from_url("https://github.com/acme/widget").unwrap()],
        subdir: None,
        root: None,
        project: None,
        env: env.map(|e| e.parse().unwrap()),
        example_keys: example.map(|keys| keys.iter().map(|k| k.parse().unwrap()).collect()),
        example_values: Vec::new(),
        env_file: None,
    }
}

fn key(k: &str) -> KeyName {
    k.parse().unwrap()
}

fn file(loc: &str) -> Origin {
    Origin::new(Provider::File, loc)
}

fn sm(loc: &str) -> Origin {
    Origin::new(Provider::AwsSm, loc)
}

/// Fills the dev sources with canary values.
fn dev_sources(c: &Canary) -> Arc<FakeSources> {
    let v = c.value();
    let fake = FakeSources::new();
    fake.set("widget.dev", &[("A", v), ("B", v)])
        .set("widget/dev/shared", &[("B", v), ("C", v)])
        .set("widget/dev/zz", &[("C", v)])
        .set("widget/local", &[("D", v)]);
    fake
}

/// Every way a report or error can be rendered.
fn assert_clean(c: &Canary, x: &(impl serde::Serialize + std::fmt::Debug)) {
    assert_no_canary(c, &serde_json::to_string(x).unwrap());
    assert_no_canary(c, &format!("{x:?}"));
}

fn assert_clean_err(c: &Canary, e: &ResolveError) {
    assert_no_canary(c, &e.to_string());
    assert_no_canary(c, &format!("{e:?}"));
    assert_clean(c, &super::broker::wire_error(e));
}

async fn settle() {
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
}

/// Under `strict_memory`, values that cannot be locked are refused rather
/// than served from the heap, and not cached.
#[tokio::test]
async fn strict_memory_refuses_values_that_cannot_be_locked() {
    use crate::test_support::{in_child, without_locked_memory};
    if !in_child("daemon::tests::strict_memory_refuses_values_that_cannot_be_locked")
        || !without_locked_memory()
    {
        return;
    }
    let c = Canary::new();
    for strict in [true, false] {
        let fake = dev_sources(&c);
        let project = parse_project(Path::new("/cfg/projects/widget.toml"), WIDGET).unwrap();
        let config = Config {
            strict_memory: strict,
            ..Config::default()
        };
        let registry = Registry::new(config, vec![project]).unwrap();
        let store = StoreFile::new("/nonexistent/kagebunshin-test/store.age");
        let d = Daemon::new(Box::new(move || Ok(registry.clone())), fake.clone(), store);
        d.unlock(None).await.unwrap();
        let result = d.status(Some(facts(None, None))).await;
        if strict {
            let err = result.unwrap_err();
            assert!(matches!(err, ResolveError::Memory(_)), "{err:?}");
            assert_clean_err(&c, &err);
            // Not cached: the next request fetches again, and is refused again.
            let fetches = fake.fetches();
            assert!(d.status(Some(facts(None, None))).await.is_err());
            assert!(fake.fetches() > fetches);
        } else {
            assert!(result.unwrap().env.is_some());
        }
    }
}

#[tokio::test]
async fn starts_locked_and_refuses_values() {
    let fake = FakeSources::new();
    let d = daemon(&fake);
    assert!(d.is_locked());
    let s = d.status(Some(facts(None, None))).await.unwrap();
    assert_eq!(
        s,
        StatusReport {
            locked: true,
            env: None,
            expiring: Vec::new(),
            remote: None,
            waiting: Vec::new(),
            acknowledged: Vec::new(),
            shared: Vec::new(),
            app: false,
            phone: None,
        }
    );
    assert_eq!(
        d.diff(&facts(None, None)).await.unwrap_err(),
        ResolveError::Locked
    );
    assert_eq!(
        d.hand_out(&facts(None, None)).await.unwrap_err(),
        ResolveError::Locked
    );
    assert_eq!(
        d.run_env(&facts(None, None)).await.unwrap_err(),
        ResolveError::Locked
    );
    assert_eq!(d.sync(None, None).await.unwrap_err(), ResolveError::Locked);
    let w = super::broker::wire_error(&ResolveError::Locked);
    assert_eq!(w.code, ErrorCode::Locked);
    assert_eq!(w.who, Some(crate::ipc::protocol::Who::Human));
    assert_eq!(
        w.tell.as_deref(),
        Some("unlock kagebunshin: run `kagebunshin unlock` in a terminal")
    );
    assert_eq!(fake.fetches(), 0);
}

#[tokio::test]
async fn status_and_diff_show_origins_and_conflicts_without_values() {
    let c = Canary::new();
    let fake = dev_sources(&c);
    let d = daemon(&fake);
    d.unlock(None).await.unwrap();

    let example = ["A", "MISSING", "B", "MISSING", "C"];
    let report = d.status(Some(facts(None, Some(&example)))).await.unwrap();
    assert_clean(&c, &report);
    assert!(!report.locked);
    let env = report.env.unwrap();
    assert_eq!((env.project.as_str(), env.env.as_str()), ("widget", "dev"));
    assert!(env.example);
    assert!(env.warnings.is_empty());
    let rows: Vec<_> = env
        .keys
        .iter()
        .map(|k| {
            (
                k.key.as_str(),
                k.origin.clone(),
                k.overridden.clone(),
                k.in_example,
            )
        })
        .collect();
    assert_eq!(
        rows,
        [
            ("A", file("widget.dev"), vec![], true),
            ("B", sm("widget/dev/shared"), vec![file("widget.dev")], true),
            (
                "C",
                sm("widget/dev/zz"),
                vec![sm("widget/dev/shared")],
                true
            ),
            ("D", sm("widget/local"), vec![], false),
        ]
    );

    let diff = d.diff(&facts(None, Some(&example))).await.unwrap();
    assert_clean(&c, &diff);
    assert_eq!(diff.missing, [key("MISSING")]);
    assert_eq!(diff.extra, [key("D")]);
    let conflicts: Vec<_> = diff.conflicts.iter().map(|k| k.key.as_str()).collect();
    assert_eq!(conflicts, ["B", "C"]);
    assert_eq!(diff.conflicts[0].overridden, [file("widget.dev")]);

    // Without a .env.example nothing is missing or extra.
    let diff = d.diff(&facts(None, None)).await.unwrap();
    assert!(!diff.example && diff.missing.is_empty() && diff.extra.is_empty());
    assert_eq!(diff.conflicts.len(), 2);

    // All of that came from one fetch of each source.
    assert_eq!(fake.fetches(), 3);

    // The values themselves are only reachable through the handout path.
    let values = d.hand_out(&facts(None, None)).await.unwrap();
    assert_eq!(values.keys[&key("B")].value.expose(), c.value());
}

#[tokio::test]
async fn a_failing_source_fails_the_whole_env() {
    let c = Canary::new();
    let fake = dev_sources(&c);
    fake.fail("widget/dev/zz");
    let d = daemon(&fake);
    d.unlock(None).await.unwrap();

    let err = d.status(Some(facts(None, None))).await.unwrap_err();
    assert_clean_err(&c, &err);
    let ResolveError::Sources { failures, .. } = &err else {
        panic!("{err:?}")
    };
    assert_eq!(
        failures,
        &["aws_sm prefix widget/dev/: access to secret widget/dev/zz was denied"]
    );
    assert_eq!(
        super::broker::wire_error(&err).code,
        ErrorCode::SourceFailed
    );
    // No partial environment: the handout fails too, and nothing was cached,
    // so the next request fetches again.
    let before = fake.fetches();
    assert!(matches!(
        d.hand_out(&facts(None, None)).await,
        Err(ResolveError::Sources { .. })
    ));
    assert_eq!(fake.fetches(), before + 3);

    let v = c.value();
    fake.set("widget/dev/zz", &[("C", v)]);
    let report = d.status(Some(facts(None, None))).await.unwrap();
    assert_eq!(report.env.unwrap().keys.len(), 4);
}

#[tokio::test]
async fn an_optional_source_failing_only_warns() {
    let c = Canary::new();
    let fake = dev_sources(&c);
    fake.fail("widget/local");
    let d = daemon(&fake);
    d.unlock(None).await.unwrap();

    let env = d
        .status(Some(facts(None, None)))
        .await
        .unwrap()
        .env
        .unwrap();
    assert_clean(&c, &env);
    let keys: Vec<_> = env.keys.iter().map(|k| k.key.as_str()).collect();
    assert_eq!(keys, ["A", "B", "C"]);
    assert_eq!(
        env.warnings,
        [
            "skipped optional source: aws_sm secret widget/local: access to secret widget/local was denied"
        ]
    );
    let diff = d.diff(&facts(None, Some(&["D"]))).await.unwrap();
    assert_eq!(diff.missing, [key("D")]);
    assert_eq!(diff.warnings, env.warnings);
}

#[tokio::test]
async fn an_optional_prefix_matching_nothing_is_fine() {
    let project = r#"
schema = 1
remotes = ["github.com/acme/widget"]
[envs.dev]
[[envs.dev.sources]]
provider = "aws_sm"
prefix = "widget/dev/"
[[envs.dev.sources]]
provider = "aws_sm"
prefix = "widget/extra/"
optional = true
"#;
    let fake = FakeSources::new();
    fake.set("widget/dev/a", &[("A", "x")]);
    let d = daemon_for(project, &fake);
    d.unlock(None).await.unwrap();
    let env = d
        .status(Some(facts(None, None)))
        .await
        .unwrap()
        .env
        .unwrap();
    assert_eq!(env.keys.len(), 1);
    assert!(env.warnings.is_empty(), "{:?}", env.warnings);
}

#[tokio::test]
async fn sensitive_envs_are_refused_before_any_fetch() {
    let c = Canary::new();
    let fake = FakeSources::new();
    fake.set("widget/staging", &[("A", c.value())]);
    let (_tmp, d) = staging_marked(&fake).await;

    let f = facts(Some("staging"), None);
    for err in [
        d.status(Some(f.clone())).await.unwrap_err(),
        d.diff(&f).await.unwrap_err(),
        d.hand_out(&f).await.unwrap_err(),
    ] {
        assert_clean_err(&c, &err);
        assert_eq!(
            err.to_string(),
            "refusing environment staging of project widget: it is marked sensitive"
        );
        assert_eq!(
            super::broker::wire_error(&err).code,
            ErrorCode::SensitiveEnv
        );
    }
    // `run` could be approved in the app, which is not open.
    let err = d.run_env(&f).await.unwrap_err();
    assert_clean_err(&c, &err);
    assert_eq!(
        err.to_string(),
        "refusing environment staging of project widget: it is marked sensitive; \
         handing it out takes approval in the app, which is not open"
    );
    let wire = super::broker::wire_error(&err);
    assert_eq!(wire.code, ErrorCode::SensitiveEnv);
    assert_eq!(wire.who, Some(crate::ipc::protocol::Who::Human));
    assert!(wire.tell.unwrap().contains("kagebunshin app"));
    let synced = d
        .sync(
            Some("widget".parse().unwrap()),
            Some("staging".parse().unwrap()),
        )
        .await
        .unwrap();
    let error = synced.refreshed[0].error.as_ref().unwrap();
    assert_eq!(error.code, ErrorCode::SensitiveEnv);
    assert_eq!(fake.fetches(), 0);

    // The same environment, unmarked, is read.
    let d = daemon(&fake);
    d.unlock(None).await.unwrap();
    assert!(d.status(Some(f)).await.unwrap().env.is_some());
}

/// `project apply`'s dry run resolves a file it is handed, with the marks
/// of the project of its name, names only, and leaves nothing cached.
#[tokio::test]
async fn a_project_file_is_checked_without_caching() {
    let c = Canary::new();
    let fake = dev_sources(&c);
    fake.set("widget/staging", &[("A", c.value())])
        .set("widget/prod/db", &[("A", c.value())]);
    let (_tmp, d) = staging_marked(&fake).await;
    let reply = d
        .handle(Request::CheckProject {
            project: "widget".parse().unwrap(),
            text: WIDGET.into(),
            example_keys: Some(vec![key("A"), key("B"), key("Z")]),
            example_values: Vec::new(),
        })
        .await;
    assert_clean(&c, &reply);
    let Response::Checked(check) = reply else {
        panic!("{reply:?}");
    };
    let env = |name: &str| check.envs.iter().find(|e| e.env.as_str() == name).unwrap();

    let dev = env("dev");
    let status = dev.status.as_ref().unwrap();
    assert_eq!(status.missing, [key("Z")]);
    assert_eq!(dev.extra, [key("C"), key("D")]);
    let conflicted: Vec<_> = dev.conflicts.iter().map(|c| c.key.as_str()).collect();
    assert_eq!(conflicted, ["B", "C"]);
    assert_eq!(dev.waiting, None);
    // Marked in the store, so not read.
    let staging = env("staging").error.as_ref().unwrap();
    assert_eq!(staging.code, ErrorCode::SensitiveEnv);
    // Looks like production: names resolve, and once installed it waits.
    assert!(env("leaky").waiting.as_ref().unwrap().contains("prod"));

    // Nothing was cached: status fetches again.
    let before = fake.fetches();
    d.status(Some(facts(Some("dev"), None))).await.unwrap();
    assert!(fake.fetches() > before);

    // A file that does not parse is refused.
    let reply = d
        .handle(Request::CheckProject {
            project: "widget".parse().unwrap(),
            text: "schema = 1\nremotes = 3\n".into(),
            example_keys: None,
            example_values: Vec::new(),
        })
        .await;
    assert!(matches!(reply, Response::Error(_)), "{reply:?}");
}

fn unmarked(env: &str, why: &str) -> String {
    // One named production outright is the caller's to mark.
    let mark = if matches!(env, "prod" | "production") {
        format!(
            " mark it sensitive with `kagebunshin mark env widget {env}`, since it is \
             production by its name, or"
        )
    } else {
        String::new()
    };
    format!(
        "environment {env} of project widget looks like production ({why}) and waits for a \
         human decision;{mark} ask the human: open the app (`kagebunshin app`) and either mark \
         widget/{env} sensitive or acknowledge it is not production"
    )
}

/// An environment that looks like production and that no human has decided
/// about is sensitive by rule: names still resolve, saying it waits, but
/// values are handed out only with approval, as if it were marked.
#[tokio::test]
async fn production_like_names_wait_for_a_human() {
    let c = Canary::new();
    let fake = FakeSources::new();
    for name in [
        "widget/prod/db",
        "widget/rc/db",
        "widget.prod",
        "widget.production",
        "widget.rc",
    ] {
        fake.set(name, &[("A", c.value())]);
    }
    let d = daemon(&fake);
    let warnings = d.unlock(None).await.unwrap();
    assert_eq!(
        warnings,
        [
            unmarked(
                "leaky",
                "source aws_sm prefix widget/prod/ reads widget/prod/, which has the segment prod"
            ),
            unmarked(
                "leaky-rc",
                "source aws_sm secret widget/rc/db reads widget/rc/db, which has the segment rc"
            ),
            unmarked("prod", "its name has the segment prod"),
            unmarked("production", "its name has the segment production"),
            unmarked("rc", "its name has the segment rc"),
        ],
        "not staging nor dev, whose names do not look like production"
    );

    let cases = [
        ("prod", "its name has the segment prod"),
        ("production", "its name has the segment production"),
        ("rc", "its name has the segment rc"),
        (
            "leaky-rc",
            "source aws_sm secret widget/rc/db reads widget/rc/db, which has the segment rc",
        ),
        (
            "leaky",
            "source aws_sm prefix widget/prod/ reads widget/prod/db, which has the segment prod",
        ),
    ];
    for (env, why) in cases {
        let f = facts(Some(env), None);
        let status = d.status(Some(f.clone())).await.unwrap().env.unwrap();
        assert_clean(&c, &status);
        assert_eq!(status.warnings, [unmarked(env, why)]);
        let diff = d.diff(&f).await.unwrap();
        assert_eq!(diff.warnings, status.warnings);
        let err = d.run_env(&f).await.unwrap_err();
        assert_clean_err(&c, &err);
        let ResolveError::NoApp(inner) = &err else {
            panic!("{err:?}");
        };
        assert!(matches!(**inner, ResolveError::Sensitive { .. }), "{err:?}");
        assert_eq!(
            err.to_string(),
            format!(
                "environment {env} of project widget looks like production ({why}) and waits \
                 for a human decision"
            )
        );
        let wire = super::broker::wire_error(&err);
        assert_eq!(wire.code, ErrorCode::SensitiveEnv);
        // One named production outright is the caller's to mark.
        if matches!(env, "prod" | "production") {
            assert_eq!(wire.who, Some(crate::ipc::protocol::Who::Agent));
            assert_eq!(wire.tell, None);
            let hint = wire.hint.unwrap();
            let command = format!("`kagebunshin mark env widget {env}`");
            assert!(hint.contains(&command), "{hint}");
            continue;
        }
        assert_eq!(wire.who, Some(crate::ipc::protocol::Who::Human));
        assert_eq!(
            wire.tell.unwrap(),
            format!(
                "open the app (`kagebunshin app`) and either mark widget/{env} sensitive or \
                 acknowledge it is not production"
            )
        );
    }
    // `status` lists them all for the app, in order.
    let all = d.handle(Request::Status { facts: None }).await;
    let Response::Status(all) = all else {
        panic!("{all:?}");
    };
    let waiting: Vec<_> = all.waiting.iter().map(|w| w.env.as_str()).collect();
    assert_eq!(waiting, ["leaky", "leaky-rc", "prod", "production", "rc"]);
    let sync = d
        .sync(Some("widget".parse().unwrap()), Some("rc".parse().unwrap()))
        .await
        .unwrap();
    assert_eq!(
        sync.refreshed[0].warnings,
        [unmarked("rc", "its name has the segment rc")]
    );
}

/// A human decides about an environment sensitive by rule: acknowledged
/// as not production it is handed out as any other, marked it stays
/// refused, and the batch acknowledges several with one passphrase.
#[tokio::test]
async fn a_human_decision_ends_the_wait() {
    let c = Canary::new();
    let fake = FakeSources::new();
    for name in ["widget.prod", "widget.production", "widget.rc"] {
        fake.set(name, &[("A", c.value())]);
    }
    let (_tmp, d) = marked_daemon(WIDGET, &fake, |st| {
        st.mark_env("widget.production".parse().unwrap(), true);
    })
    .await;
    // Acknowledged once the values were fetched: takes effect without a
    // sync, as marks do.
    let prod = facts(Some("prod"), None);
    assert!(d.run_env(&prod).await.is_err());
    let r = d
        .handle(Request::AcknowledgeEnvs {
            envs: vec!["widget.prod".parse().unwrap(), "widget.rc".parse().unwrap()],
            passphrase: pw("pw"),
        })
        .await;
    assert!(matches!(r, Response::Store { .. }), "{r:?}");
    for env in ["prod", "rc"] {
        let f = facts(Some(env), None);
        let run = d.run_env(&f).await.unwrap();
        assert_eq!(run.vars.len(), 1);
        assert!(run.warnings.is_empty(), "{:?}", run.warnings);
        let status = d.status(Some(f)).await.unwrap().env.unwrap();
        assert!(status.warnings.is_empty(), "{:?}", status.warnings);
        assert!(status.acknowledged);
    }
    // Marked: refused before it is read, as before, and not waiting.
    let err = d
        .run_env(&facts(Some("production"), None))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("it is marked sensitive"), "{err}");
    let Response::Status(all) = d.handle(Request::Status { facts: None }).await else {
        panic!("not status");
    };
    let waiting: Vec<_> = all.waiting.iter().map(|w| w.env.as_str()).collect();
    assert_eq!(
        waiting,
        ["leaky", "leaky-rc"],
        "not prod, production nor rc"
    );
    // A wrong passphrase acknowledges nothing.
    let r = d
        .handle(Request::AcknowledgeEnvs {
            envs: vec!["widget.production".parse().unwrap()],
            passphrase: pw("wrong"),
        })
        .await;
    assert_eq!(error_code(r), ErrorCode::WrongPassphrase);
}

#[test]
fn production_like_names() {
    use super::resolve::prod_like;
    let live = [crate::config::SourcePattern::try_from("*/live/*".to_owned()).unwrap()];
    for extra in [&[][..], &live[..]] {
        for name in [
            "widget/prod",
            "widget/prod/db",
            "prod/widget",
            "widget.prod.db",
            "widget.prod",
            "WIDGET.PROD",
            "x/RC/y",
            "a/Production.b/c",
            "widget/prod/",
            "arn:aws:secretsmanager:eu-west-1:123456789012:secret:widget/prod-AbCdEf",
            "arn:aws:secretsmanager:eu-west-1:123456789012:secret:prod/widget-AbCdEf",
            "arn:aws:secretsmanager:eu-west-1:123456789012:secret:prod-AbCdEf",
        ] {
            assert!(prod_like(name, extra).is_some(), "{name}");
        }
        for name in [
            "widget/product",
            "widget/prodigy/db",
            "widget.product",
            "widget.rcx",
            "widget/preprod",
            "widgetprod",
            "widget/dev/db",
            // `-`, `_`, `+` and `@` do not separate segments.
            "widget-prod",
            "widget_prod",
            "widget+prod",
            "widget@prod",
            "arn:aws:secretsmanager:eu-west-1:123456789012:secret:widget/dev-AbCdEf",
        ] {
            assert!(prod_like(name, extra).is_none(), "{name}");
        }
    }
    assert_eq!(
        prod_like("widget/PROD/db", &[]).as_deref(),
        Some("has the segment prod")
    );
    // A custom pattern adds to the built-in rule, ignoring case, and sees
    // an ARN's secret name.
    assert_eq!(
        prod_like("widget/LIVE/db", &live).as_deref(),
        Some("matches the sensitive pattern */live/*")
    );
    assert!(prod_like("widget/live/db", &[]).is_none());
    let dash = [crate::config::SourcePattern::try_from("*-prod*".to_owned()).unwrap()];
    assert!(prod_like("widget-prod", &dash).is_some());
    assert!(
        prod_like(
            "arn:aws:secretsmanager:eu-west-1:123456789012:secret:widget-prod-AbCdEf",
            &dash
        )
        .is_some()
    );
}

#[test]
fn profiles_are_split_on_dashes_and_underscores_too() {
    use super::resolve::prod_like_profile;
    for p in ["acme-prod", "prod_admin", "ACME-Production", "x.rc", "rc"] {
        assert!(prod_like_profile(p).is_some(), "{p}");
    }
    for p in ["acme-dev", "product-team", "preprod", "acmeprod"] {
        assert!(prod_like_profile(p).is_none(), "{p}");
    }
    assert_eq!(
        prod_like_profile("acme-prod").as_deref(),
        Some("has the part prod")
    );
}

/// A secret whose own name says it is not production is not warned about
/// for its profile; one whose name looks like production still is, unless a
/// human acknowledged the environment is not production.
#[tokio::test]
async fn a_secrets_own_name_outweighs_its_profile() {
    let c = Canary::new();
    let project = |secret: &str| {
        format!(
            r#"
schema = 1
remotes = ["github.com/acme/widget"]
[envs.local]
profile = "acme-prod"
[[envs.local.sources]]
provider = "aws_sm"
secret = "{secret}"
"#
        )
    };
    let fake = FakeSources::new();
    for name in ["dev/aws", "widget/dev/prod", "widget/app"] {
        fake.set(name, &[("A", c.value())]);
    }
    let d = daemon_for(&project("dev/aws"), &fake);
    assert_eq!(d.unlock(None).await.unwrap(), Vec::<String>::new());
    let d = daemon_for(&project("widget/dev/prod"), &fake);
    assert_eq!(
        d.unlock(None).await.unwrap(),
        [unmarked(
            "local",
            "source aws_sm secret widget/dev/prod (profile acme-prod) reads widget/dev/prod, which has \
             the segment prod"
        )]
    );
    let d = daemon_for(&project("widget/app"), &fake);
    let warnings = d.unlock(None).await.unwrap();
    assert_eq!(warnings.len(), 1);
    assert!(
        warnings[0].contains("uses AWS profile acme-prod, whose name has the part prod"),
        "{warnings:?}"
    );

    let (_tmp, d) = marked_daemon(&project("widget/dev/prod"), &fake, |st| {
        st.acknowledge_env("widget.local".parse().unwrap(), true);
    })
    .await;
    let status = d
        .status(Some(facts(Some("local"), None)))
        .await
        .unwrap()
        .env
        .unwrap();
    assert_clean(&c, &status);
    assert!(status.warnings.is_empty(), "{:?}", status.warnings);
    assert!(status.acknowledged);
}

/// An environment that is not marked warns about a production-looking
/// profile, and every environment about sources that read the same thing,
/// from the current project file: dedupe clears it without a sync.
#[tokio::test]
async fn profiles_and_duplicate_sources_warn() {
    let c = Canary::new();
    let text = r#"
schema = 1
remotes = ["git@github.com:acme/widget.git"]

[envs.dev]
profile = "acme-prod"
[[envs.dev.sources]]
provider = "aws_sm"
secret = "widget/app"
[[envs.dev.sources]]
provider = "aws_sm"
secret = "widget/app"
[[envs.dev.sources]]
provider = "aws_sm"
secret = "widget/app"
optional = true
[[envs.dev.sources]]
provider = "aws_sm"
secret = "widget/app"
region = "us-east-1"
"#;
    let fake = FakeSources::new();
    fake.set("widget/app", &[("A", c.value())]);
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("widget.toml");
    std::fs::write(&path, text).unwrap();
    let load_path = path.clone();
    let d = Daemon::new(
        Box::new(move || {
            let text = std::fs::read_to_string(&load_path).unwrap();
            let project = parse_project(&load_path, &text).unwrap();
            Registry::new(Config::default(), vec![project])
        }),
        fake.clone(),
        StoreFile::new("/nonexistent/kagebunshin-test/store.age"),
    );
    let unlock = d.unlock(None).await.unwrap();
    assert_eq!(unlock.len(), 1, "{unlock:?}");
    assert!(unlock[0].contains("uses AWS profile acme-prod, whose name has the part prod"));

    let f = facts(Some("dev"), None);
    let status = d.status(Some(f.clone())).await.unwrap().env.unwrap();
    assert_clean(&c, &status);
    let src = "aws_sm secret widget/app (profile acme-prod)";
    assert_eq!(
        status.warnings[1..],
        [
            format!(
                "environment dev of project widget reads {src} twice, in sources 1 and 2; \
                 run `kagebunshin project dedupe widget dev`"
            ),
            format!(
                "environment dev of project widget reads {src} twice, in sources 1 and 3; \
                 remove one with `kagebunshin project remove-source widget dev <N>`"
            ),
        ]
    );
    assert_eq!(status.warnings[0], unlock[0]);
    let diff = d.diff(&f).await.unwrap();
    assert_eq!(diff.warnings, status.warnings);

    std::fs::write(
        &path,
        text.replacen(
            "[[envs.dev.sources]]\nprovider = \"aws_sm\"\nsecret = \"widget/app\"\n",
            "",
            1,
        ),
    )
    .unwrap();
    let status = d.status(Some(f)).await.unwrap().env.unwrap();
    assert_eq!(status.warnings.len(), 2, "{:?}", status.warnings);
}

#[test]
fn arn_secret_names() {
    use crate::source::aws_sm::arn_secret_name;
    use crate::source::stable_origin;
    let arn = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:widget/prod-AbCdEf";
    assert_eq!(arn_secret_name(arn), Some("widget/prod"));
    assert_eq!(
        arn_secret_name("arn:aws:secretsmanager:eu-west-1:1:secret:prod-AbCdEf"),
        Some("prod")
    );
    // A partial ARN, without the random suffix, keeps its whole name.
    assert_eq!(
        arn_secret_name("arn:aws:secretsmanager:eu-west-1:1:secret:widget/db"),
        Some("widget/db")
    );
    assert_eq!(arn_secret_name("widget/prod-AbCdEf"), None);

    // Marks are keyed by stable ids: an ARN and the secret's name are one
    // secret; other providers' locations are taken as they are.
    let id = |p, l| stable_origin(p, l);
    assert_eq!(id(Provider::AwsSm, arn), id(Provider::AwsSm, "widget/prod"));
    assert_ne!(
        id(Provider::AwsSm, "widget/prod"),
        id(Provider::AwsSm, "widget/prod/db")
    );
    assert_ne!(id(Provider::AwsSm, "widget/dev"), id(Provider::AwsSm, arn));
    assert_eq!(id(Provider::Proton, arn).location, arn);
}

/// Names a prefix expands to are checked before anything is read, and only
/// warn.
const EXPANDS: &str = r#"
schema = 1
remotes = ["git@github.com:acme/widget.git"]

[[envs.dev.sources]]
provider = "file"
secret = "widget.dev"
[[envs.dev.sources]]
provider = "aws_sm"
prefix = "widget/"

# Only an optional source expands to a release candidate.
[[envs.opt.sources]]
provider = "aws_sm"
secret = "widget/dev/a"
[[envs.opt.sources]]
provider = "aws_sm"
prefix = "shared/"
optional = true

# Store sections: a dotted name, given or expanded.
[[envs.section.sources]]
provider = "file"
secret = "widget.prod"
[[envs.sections.sources]]
provider = "file"
prefix = "widget."
"#;

#[tokio::test]
async fn expanded_names_only_warn() {
    let c = Canary::new();
    let fake = FakeSources::new();
    for name in [
        "widget.dev",
        "widget.prod",
        "widget/dev/a",
        "widget/prod/db",
        "shared/dev/x",
        "shared/rc/x",
    ] {
        fake.set(name, &[("A", c.value())]);
    }
    let d = daemon_for(EXPANDS, &fake);
    d.unlock(None).await.unwrap();

    let cases = [
        (
            "dev",
            "source aws_sm prefix widget/ reads widget/prod/db, which has the segment prod",
        ),
        (
            "opt",
            "source aws_sm prefix shared/ reads shared/rc/x, which has the segment rc",
        ),
        (
            "section",
            "source file secret widget.prod reads widget.prod, which has the segment prod",
        ),
        (
            "sections",
            "source file prefix widget. reads widget.prod, which has the segment prod",
        ),
    ];
    for (env, why) in cases {
        let f = facts(Some(env), None);
        let status = d.status(Some(f.clone())).await.unwrap().env.unwrap();
        assert_clean(&c, &status);
        assert_eq!(status.warnings, [unmarked(env, why)]);
        assert_eq!(d.hand_out(&f).await.unwrap().keys.len(), 1);
    }
}

/// Two AWS secrets in a dev env, one read through a prefix and one given
/// as a full ARN; [`mark_billing_and_payroll`] marks both by name.
const MARKED: &str = r#"
schema = 1
remotes = ["git@github.com:acme/widget.git"]

[[envs.dev.sources]]
provider = "aws_sm"
prefix = "widget/dev/"
[[envs.dev.sources]]
provider = "aws_sm"
secret = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:widget/dev/payroll-AbCdEf"
# Overrides OVERRIDDEN from the billing secret.
[[envs.dev.sources]]
provider = "aws_sm"
secret = "widget/override"
"#;

fn mark_billing_and_payroll(st: &mut Store) {
    for name in ["widget/dev/billing", "widget/dev/payroll"] {
        st.mark_secret(sm(name), true).unwrap();
    }
}

#[tokio::test]
async fn a_sensitive_aws_secret_is_refused_by_key() {
    let c = Canary::new();
    let v = c.value();
    let fake = FakeSources::new();
    fake.set("widget/dev/app", &[("APP", v)])
        .set("widget/dev/billing", &[("STRIPE", v), ("OVERRIDDEN", v)])
        .set(
            "arn:aws:secretsmanager:eu-west-1:123456789012:secret:widget/dev/payroll-AbCdEf",
            &[("PAYROLL", v)],
        )
        .set("widget/override", &[("OVERRIDDEN", v)]);
    let (_tmp, d) = marked_daemon(MARKED, &fake, mark_billing_and_payroll).await;
    assert!(d.unlock(None).await.unwrap().is_empty());
    let f = facts(None, None);
    let status = d.status(Some(f.clone())).await.unwrap().env.unwrap();
    let marks: Vec<_> = status
        .keys
        .iter()
        .map(|k| (k.key.as_str(), k.sensitive))
        .collect();
    assert_eq!(
        marks,
        [
            ("APP", false),
            ("OVERRIDDEN", false),
            ("PAYROLL", true),
            ("STRIPE", true)
        ]
    );

    // `run` fails closed: one sensitive key it would inject refuses the
    // whole run, naming the key and never a value.
    for example in [None, Some(&["APP", "STRIPE"][..])] {
        let err = d.run_env(&facts(None, example)).await.unwrap_err();
        assert_clean_err(&c, &err);
        assert_eq!(
            super::broker::wire_error(&err).code,
            ErrorCode::SensitiveEnv
        );
        assert!(err.to_string().contains("refusing key"), "{err}");
    }
    let r = d
        .run_env(&facts(None, Some(&["APP", "OVERRIDDEN", "NOT_SET"])))
        .await
        .unwrap();
    assert_eq!(r.vars.len(), 2);

    let values = d.hand_out(&f).await.unwrap();
    let env = ("widget".parse().unwrap(), "dev".parse().unwrap());
    // Only the winning origin counts.
    d.refuse_sensitive_keys(&env, &values, [&key("APP"), &key("OVERRIDDEN")])
        .unwrap();
    for (k, origin) in [
        ("STRIPE", "aws_sm:widget/dev/billing"),
        (
            "PAYROLL",
            "aws_sm:arn:aws:secretsmanager:eu-west-1:123456789012:secret:widget/dev/payroll-AbCdEf",
        ),
    ] {
        // All or nothing: one sensitive key refuses the lot.
        let err = d
            .refuse_sensitive_keys(&env, &values, [&key("APP"), &key(k)])
            .unwrap_err();
        assert_clean_err(&c, &err);
        assert_eq!(
            err.to_string(),
            format!(
                "refusing key {k} of environment dev of project widget: it comes from {origin}, \
                 which is marked sensitive"
            )
        );
        assert_eq!(
            super::broker::wire_error(&err).code,
            ErrorCode::SensitiveEnv
        );
    }
}

/// Marks change through the daemon only with the store passphrase, and a
/// secret mark holds in every environment that reads the secret.
#[tokio::test]
async fn marks_take_the_passphrase_and_follow_the_secret() {
    let c = Canary::new();
    let text = r#"
schema = 1
remotes = ["git@github.com:acme/widget.git"]

[[envs.dev.sources]]
provider = "aws_sm"
prefix = "widget/shared/"
[[envs.qa.sources]]
provider = "aws_sm"
secret = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:widget/shared/db-AbCdEf"
"#;
    let fake = FakeSources::new();
    fake.set("widget/shared/db", &[("DB", c.value())]).set(
        "arn:aws:secretsmanager:eu-west-1:123456789012:secret:widget/shared/db-AbCdEf",
        &[("DB", c.value())],
    );
    let (_tmp, d) = marked_daemon(text, &fake, |_| {}).await;
    let sensitive = |env: &'static str| {
        let d = &d;
        async move {
            let status = d.status(Some(facts(Some(env), None))).await.unwrap();
            status.env.unwrap().keys[0].sensitive
        }
    };
    assert!(!sensitive("dev").await && !sensitive("qa").await);

    let mark = |sensitive, pass: &str| Request::MarkSecret {
        secret: sm("widget/shared/db"),
        sensitive,
        passphrase: pw(pass),
    };
    for pass in ["wrong", c.value()] {
        let r = d.handle(mark(true, pass)).await;
        assert_clean(&c, &r);
        assert_eq!(error_code(r), ErrorCode::WrongPassphrase);
    }
    assert!(!sensitive("dev").await);
    assert_eq!(
        d.handle(mark(true, "pw")).await,
        Response::Store {
            change: Change::Marked,
            locked: false
        }
    );
    assert!(sensitive("dev").await && sensitive("qa").await);
    let err = d.run_env(&facts(Some("qa"), None)).await.unwrap_err();
    assert_eq!(
        super::broker::wire_error(&err).code,
        ErrorCode::SensitiveEnv
    );

    let env = |sensitive, pass: &str| Request::MarkEnv {
        project: "widget".parse().unwrap(),
        env: "dev".parse().unwrap(),
        sensitive,
        also: Vec::new(),
        passphrase: pw(pass),
    };
    assert_eq!(
        error_code(d.handle(env(true, "wrong")).await),
        ErrorCode::WrongPassphrase
    );
    assert!(matches!(
        d.handle(env(true, "pw")).await,
        Response::Store { .. }
    ));
    let err = d.status(Some(facts(Some("dev"), None))).await.unwrap_err();
    assert_eq!(
        super::broker::wire_error(&err).code,
        ErrorCode::SensitiveEnv
    );
    let list = d.store_list().unwrap();
    assert_eq!(list.sensitive_envs, ["widget.dev".parse().unwrap()]);
    assert_eq!(list.sensitive_secrets, [sm("widget/shared/db")]);

    // A file secret is a store section: its keys are marked instead.
    let r = d
        .handle(Request::MarkSecret {
            secret: file("widget.dev"),
            sensitive: true,
            passphrase: pw("pw"),
        })
        .await;
    assert_eq!(error_code(r), ErrorCode::Store);

    d.handle(env(false, "pw")).await;
    // Marking dev also marked its prefix, which unmarking dev leaves; while
    // it is marked, the secret under it cannot be unmarked on its own.
    let Response::Error(e) = d.handle(mark(false, "pw")).await else {
        panic!("unmarked a secret its prefix still covers");
    };
    assert_eq!(e.code, ErrorCode::Store);
    assert!(e.message.contains("widget/shared/"), "{}", e.message);
    assert!(sensitive("dev").await && sensitive("qa").await);
    let r = d
        .handle(Request::MarkSecret {
            secret: sm("widget/shared/"),
            sensitive: false,
            passphrase: pw("pw"),
        })
        .await;
    assert!(matches!(r, Response::Store { .. }), "{r:?}");
    assert!(sensitive("dev").await, "still marked by name");
    assert!(matches!(
        d.handle(mark(false, "pw")).await,
        Response::Store { .. }
    ));
    assert!(!sensitive("dev").await && !sensitive("qa").await);
    let list = d.store_list().unwrap();
    assert!(list.sensitive_envs.is_empty() && list.sensitive_secrets.is_empty());
}

/// Several secrets are unmarked with one passphrase, in one write: all of
/// them, or none if one cannot be.
#[tokio::test]
async fn several_secrets_unmark_at_once_or_not_at_all() {
    let text = r#"
schema = 1
remotes = ["git@github.com:acme/widget.git"]

[[envs.dev.sources]]
provider = "aws_sm"
secrets = ["widget/db", "widget/mail", "widget/kept/api"]
"#;
    let fake = FakeSources::new();
    fake.set("widget/db", &[("DB", "1")])
        .set("widget/mail", &[("MAIL", "2")])
        .set("widget/kept/api", &[("API", "3")]);
    let (_tmp, d) = marked_daemon(text, &fake, |st| {
        for secret in ["widget/db", "widget/mail", "widget/kept/api"] {
            st.mark_secret(sm(secret), true).unwrap();
        }
        st.mark_prefix(sm("widget/kept/")).unwrap();
    })
    .await;
    let marked = || d.store_list().unwrap().sensitive_secrets;
    let unmark = |secrets: &[&str], pass: &str| Request::UnmarkSecrets {
        secrets: secrets.iter().map(|s| sm(s)).collect(),
        passphrase: pw(pass),
    };
    let all = marked();

    let r = d
        .handle(unmark(&["widget/db", "widget/mail"], "wrong"))
        .await;
    assert_eq!(error_code(r), ErrorCode::WrongPassphrase);
    // One a marked prefix still covers cannot be unmarked: nor are the rest.
    let r = d
        .handle(unmark(&["widget/db", "widget/kept/api"], "pw"))
        .await;
    assert_eq!(error_code(r), ErrorCode::Store);
    assert_eq!(marked(), all);

    assert_eq!(
        d.handle(unmark(&["widget/db", "widget/mail"], "pw")).await,
        Response::Store {
            change: Change::Unmarked,
            locked: false
        }
    );
    assert!(!marked().contains(&sm("widget/db")) && !marked().contains(&sm("widget/mail")));
    assert!(marked().contains(&sm("widget/kept/api")));
}

/// An environment that reads a database, everything under a prefix, a
/// store section and a Proton item.
const LIVE: &str = r#"
schema = 1
remotes = ["git@github.com:acme/widget.git"]

[[envs.live.sources]]
provider = "aws_sm"
secret = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:widget/shared/db-AbCdEf"
[[envs.live.sources]]
provider = "aws_sm"
prefix = "widget/live/"
[[envs.live.sources]]
provider = "file"
secret = "shared.cfg"
[[envs.live.sources]]
provider = "proton"
secret = "Ops/TOKEN"
"#;

/// Another that reads the same, naming one secret under the prefix.
const COPY: &str = r#"
[[envs.copy.sources]]
provider = "aws_sm"
secret = "widget/shared/db"
[[envs.copy.sources]]
provider = "aws_sm"
secret = "widget/live/later"
[[envs.copy.sources]]
provider = "file"
secret = "shared.cfg"
[[envs.copy.sources]]
provider = "proton"
secret = "Ops/TOKEN"
"#;

/// What [`LIVE`] and [`COPY`] read, and a store that holds the section.
fn live_sources(c: &Canary) -> (Arc<FakeSources>, impl FnOnce(&mut Store)) {
    let v = c.value().to_owned();
    let fake = FakeSources::new();
    fake.set("widget/shared/db", &[("DB", &v)])
        .set("shared.cfg", &[("CFG", &v)])
        .set("Ops/TOKEN", &[("TOKEN", &v)])
        .set("widget/live/later", &[("LATER", &v)]);
    let stored = move |st: &mut Store| {
        st.set(
            "shared.cfg".parse().unwrap(),
            key("CFG"),
            SecretValue::new(v),
        );
    };
    (fake, stored)
}

fn mark_live(sensitive: bool, also: Vec<Origin>) -> Request {
    Request::MarkEnv {
        project: "widget".parse().unwrap(),
        env: "live".parse().unwrap(),
        sensitive,
        also,
        passphrase: pw("pw"),
    }
}

/// The keys environment copy sets, and whether each is sensitive.
async fn copy_keys(d: &Daemon) -> Vec<(String, bool)> {
    let status = d.status(Some(facts(Some("copy"), None))).await.unwrap();
    let keys = status.env.unwrap().keys;
    keys.into_iter()
        .map(|k| (k.key.to_string(), k.sensitive))
        .collect()
}

/// Marking an environment marks what only its sources read, so copying them
/// into another environment afterwards does not get around the mark; a
/// marked AWS prefix covers secrets created under it later.
#[tokio::test]
async fn an_env_mark_follows_its_sources_into_copies() {
    let c = Canary::new();
    let (fake, stored) = live_sources(&c);
    let text = Arc::new(Mutex::new(LIVE.to_owned()));
    let (_tmp, d) = changing_daemon(&text, &fake, stored).await;
    let r = d.handle(mark_live(true, Vec::new())).await;
    assert!(matches!(r, Response::Store { .. }), "{r:?}");

    text.lock().unwrap().push_str(COPY);
    assert_eq!(
        copy_keys(&d).await,
        [
            ("CFG".to_owned(), true),
            ("DB".to_owned(), true),
            ("LATER".to_owned(), true),
            ("TOKEN".to_owned(), true),
        ]
    );
    let r = d.handle(run_req(Some("copy"))).await;
    assert_clean(&c, &r);
    assert_eq!(error_code(r), ErrorCode::SensitiveEnv);

    // Unmarking the environment leaves the marks on what it read.
    let r = d.handle(mark_live(false, Vec::new())).await;
    assert!(matches!(r, Response::Store { .. }), "{r:?}");
    assert!(copy_keys(&d).await.iter().all(|(_, s)| *s));
}

/// A secret that an open environment reads too is left unmarked when
/// another that reads it is marked: marking one environment does not make
/// the other ask for approval. What only the marked one reads is marked: a
/// prefix is not shared with an environment that names one secret under
/// it. A human can mark a shared secret all the same.
#[tokio::test]
async fn marking_an_env_leaves_what_an_open_one_reads_too() {
    let c = Canary::new();
    let (fake, stored) = live_sources(&c);
    let text = format!("{LIVE}{COPY}");
    let (_tmp, d) = marked_daemon(&text, &fake, stored).await;
    assert!(copy_keys(&d).await.iter().all(|(_, s)| !s));

    let status = d.handle(Request::Status { facts: None }).await;
    let Response::Status(status) = status else {
        panic!("{status:?}")
    };
    let shared = |report: &StatusReport, env: &str| -> Vec<(String, bool, bool)> {
        report
            .shared
            .iter()
            .filter(|s| s.env.as_str() == env)
            .map(|s| (s.secret.to_string(), s.stays_unmarked(), s.sensitive))
            .collect()
    };
    assert_eq!(
        shared(&status, "live"),
        [
            ("aws_sm:widget/shared/db".to_owned(), true, false),
            ("file:shared.cfg".to_owned(), true, false),
            ("proton:Ops/TOKEN".to_owned(), true, false),
        ]
    );

    let r = d.handle(mark_live(true, Vec::new())).await;
    assert!(matches!(r, Response::Store { .. }), "{r:?}");
    assert_eq!(
        copy_keys(&d).await,
        [
            ("CFG".to_owned(), false),
            ("DB".to_owned(), false),
            ("LATER".to_owned(), true),
            ("TOKEN".to_owned(), false),
        ]
    );
    // Copy hands out what it shares, and waits for approval only for what
    // is live's alone.
    let r = d.handle(get(Some("copy"), "DB", "pw")).await;
    assert!(matches!(r, Response::Value { .. }), "{r:?}");
    let r = d.handle(get(Some("copy"), "LATER", "pw")).await;
    assert_clean(&c, &r);
    assert_eq!(error_code(r), ErrorCode::SensitiveEnv);

    // Asked for, a shared secret is marked with it, by the name the
    // sources give it.
    let also = vec![
        sm("widget/shared/db"),
        Origin::new(Provider::Proton, "Ops/TOKEN"),
    ];
    let r = d.handle(mark_live(true, also)).await;
    assert!(matches!(r, Response::Store { .. }), "{r:?}");
    assert_eq!(
        copy_keys(&d).await,
        [
            ("CFG".to_owned(), false),
            ("DB".to_owned(), true),
            ("LATER".to_owned(), true),
            ("TOKEN".to_owned(), true),
        ]
    );
    let Response::Status(status) = d.handle(Request::Status { facts: None }).await else {
        panic!("not a status")
    };
    // Live is marked now, so nothing copy reads is shared with an open
    // environment: marking copy would mark all of it. What it names under
    // live's prefix it shares with live.
    assert_eq!(
        shared(&status, "copy"),
        [
            ("aws_sm:widget/shared/db".to_owned(), false, true),
            ("aws_sm:widget/live/later".to_owned(), false, true),
            ("file:shared.cfg".to_owned(), false, false),
            ("proton:Ops/TOKEN".to_owned(), false, true),
        ]
    );
}

/// What is shared does not get around three things: a secret whose name
/// looks like production is marked with any environment that reads it; an
/// environment that waits for a decision is not an open one; and a mark
/// that is there stays.
#[tokio::test]
async fn sharing_does_not_unmark_or_cover_production() {
    let text = r#"
schema = 1
remotes = ["git@github.com:acme/widget.git"]

[[envs.live.sources]]
provider = "aws_sm"
secrets = ["acme/prod/db", "mail", "ledger", "sentry"]

[[envs.qa.sources]]
provider = "aws_sm"
secrets = ["acme/prod/db", "mail", "sentry"]

[[envs.rc.sources]]
provider = "aws_sm"
secrets = ["ledger"]
"#;
    let fake = FakeSources::new();
    let (tmp, d) = marked_daemon(text, &fake, |st| {
        // A human said qa is not production, whatever it reads.
        st.acknowledge_env("widget.qa".parse().unwrap(), true);
        st.mark_secret(sm("sentry"), true).unwrap();
    })
    .await;
    let r = d.handle(mark_live(true, Vec::new())).await;
    assert!(matches!(r, Response::Store { .. }), "{r:?}");
    let store = StoreFile::new(tmp.path().join(STORE_FILE))
        .with_test_work_factor()
        .open(&Passphrase::new("pw".into()))
        .unwrap();
    let marked: Vec<String> = store.marked_secrets().map(ToString::to_string).collect();
    // Not mail, which qa reads openly. The database's name says
    // production; rc waits for a decision, so the ledger is not shared
    // with an open environment; sentry was marked before.
    assert_eq!(
        marked,
        ["aws_sm:acme/prod/db", "aws_sm:ledger", "aws_sm:sentry"]
    );
}

/// Acknowledging an environment as not production leaves the marks on the
/// secrets it reads, so it still asks for approval for their keys: a human
/// can unmark those they name in the same write. The environment that is
/// marked stays refused, and nothing is written if one cannot be unmarked.
#[tokio::test]
async fn acknowledging_an_env_unmarks_the_secrets_named_with_it() {
    let c = Canary::new();
    let text = r#"
schema = 1
remotes = ["git@github.com:acme/widget.git"]

[[envs.dev.sources]]
provider = "aws_sm"
secrets = ["mail", "sentry"]

[[envs.live.sources]]
provider = "aws_sm"
secrets = ["mail", "sentry", "acme/errors"]

[[envs.rc.sources]]
provider = "aws_sm"
secrets = ["mail", "sentry", "acme/errors"]
"#;
    let fake = FakeSources::new();
    fake.set("mail", &[("MAIL", c.value())])
        .set("sentry", &[("SENTRY", c.value())])
        .set("acme/errors", &[("ERRORS", c.value())]);
    // As an older version left it: live marked, and all it read with it.
    let tmp = tempfile::tempdir().unwrap();
    let file = StoreFile::new(tmp.path().join(STORE_FILE)).with_test_work_factor();
    let pass = Passphrase::new("pw".into());
    file.create(&pass).unwrap();
    file.update(&pass, None, |st| {
        st.mark_env("widget.live".parse().unwrap(), true);
        st.mark_secret(sm("mail"), true)?;
        st.mark_secret(sm("sentry"), true)?;
        st.mark_prefix(sm("acme/"))?;
        Ok(())
    })
    .unwrap();
    let project = parse_project(Path::new("/cfg/projects/widget.toml"), text).unwrap();
    let registry = Registry::new(Config::default(), vec![project]).unwrap();
    let log = state_log(tmp.path());
    let d = Daemon::new(Box::new(move || Ok(registry.clone())), fake.clone(), file)
        .with_audit(log.clone());
    d.unlock(Some(pass)).await.unwrap();
    let status = || async {
        match d.handle(Request::Status { facts: None }).await {
            Response::Status(status) => status,
            other => panic!("{other:?}"),
        }
    };
    let offered = |report: &StatusReport, env: &str| -> Vec<String> {
        report
            .shared
            .iter()
            .filter(|s| s.env.as_str() == env && s.stays_marked())
            .map(|s| s.secret.to_string())
            .collect()
    };
    let before = status().await;
    assert_eq!(
        offered(&before, "rc"),
        ["aws_sm:mail", "aws_sm:sentry", "aws_sm:acme/errors"]
    );
    assert!(before.waiting.iter().any(|w| w.env.as_str() == "rc"));
    let ack = |unmark: &[&str]| Request::AcknowledgeEnv {
        project: "widget".parse().unwrap(),
        env: "rc".parse().unwrap(),
        acknowledged: true,
        unmark: unmark.iter().map(|s| sm(s)).collect(),
        passphrase: pw("pw"),
    };

    // A prefix covers the errors: unmarking them alone would do nothing,
    // so nothing is written, the acknowledgement neither.
    let r = d.handle(ack(&["mail", "acme/errors"])).await;
    let Response::Error(e) = r else {
        panic!("{r:?}")
    };
    assert!(e.message.contains("through prefix aws_sm:acme/"), "{e:?}");
    let after = status().await;
    assert_eq!(after.waiting, before.waiting);
    assert_eq!(after.shared, before.shared);
    assert_eq!(after.acknowledged, []);

    let r = d.handle(ack(&["mail"])).await;
    assert!(matches!(r, Response::Store { .. }), "{r:?}");
    let after = status().await;
    assert!(after.waiting.is_empty(), "{:?}", after.waiting);
    // The app reads an acknowledged environment without being asked.
    assert_eq!(after.acknowledged, ["widget.rc".parse().unwrap()]);
    assert_eq!(
        offered(&after, "rc"),
        ["aws_sm:sentry", "aws_sm:acme/errors"]
    );
    // rc and dev read the mail freely now; what stayed marked still asks
    // in rc, and live is as refused as it was.
    for env in ["rc", "dev"] {
        let r = d.handle(get(Some(env), "MAIL", "pw")).await;
        assert!(matches!(r, Response::Value { .. }), "{env}: {r:?}");
    }
    for (env, key) in [("rc", "SENTRY"), ("rc", "ERRORS"), ("live", "MAIL")] {
        let r = d.handle(get(Some(env), key, "pw")).await;
        assert_clean(&c, &r);
        assert_eq!(error_code(r), ErrorCode::SensitiveEnv, "{env} {key}");
    }

    let (events, _) = log.read().unwrap();
    let asked: Vec<_> = events
        .iter()
        .filter(|e| e.action == "acknowledge env")
        .map(|e| (e.decision, e.target.as_deref()))
        .collect();
    assert_eq!(
        asked,
        [
            (
                crate::audit::Decision::Denied,
                Some("unmark aws_sm mail, aws_sm acme/errors")
            ),
            (crate::audit::Decision::Allowed, Some("unmark aws_sm mail")),
        ]
    );
}

#[tokio::test]
async fn expanded_names_are_listed_before_secrets_manager_is_read() {
    let c = Canary::new();
    let json = format!(r#"{{"A":"{}"}}"#, c.value());
    let text = r#"
schema = 1
remotes = ["git@github.com:acme/widget.git"]

[[envs.dev.sources]]
provider = "aws_sm"
secret = "widget/dev/a"
[[envs.dev.sources]]
provider = "aws_sm"
prefix = "widget/"
optional = true
"#;
    let mut aws = FakeAws::default();
    aws.accounts.insert(
        String::new(),
        account(&[("widget/dev/a", json.clone()), ("widget/prod/db", json)]),
    );
    let aws = Arc::new(aws);
    let d = aws_daemon(text, &aws);
    d.unlock(None).await.unwrap();
    let env = d
        .status(Some(facts(None, None)))
        .await
        .unwrap()
        .env
        .unwrap();
    assert_clean(&c, &env);
    assert_eq!(
        env.warnings,
        [unmarked(
            "dev",
            "source aws_sm prefix widget/ reads widget/prod/db, which has the segment prod"
        )]
    );
    assert!(!aws.gets.lock().unwrap().is_empty(), "it read the values");
}

#[tokio::test]
async fn unknown_projects_and_envs() {
    let fake = FakeSources::new();
    let d = daemon(&fake);
    d.unlock(None).await.unwrap();
    let mut f = facts(None, None);
    f.remotes = vec![RemoteId::from_url("https://github.com/acme/other").unwrap()];
    let err = d.status(Some(f.clone())).await.unwrap_err();
    assert!(matches!(err, ResolveError::NoProject(_)), "{err:?}");
    assert!(
        err.to_string().contains("run kagebunshin project init"),
        "{err}"
    );
    f.remotes.clear();
    let err = d.diff(&f).await.unwrap_err();
    assert!(err.to_string().contains("no network git remotes"), "{err}");

    let err = d.status(Some(facts(Some("qa"), None))).await.unwrap_err();
    assert!(matches!(err, ResolveError::UnknownEnv { .. }), "{err:?}");
    assert!(err.to_string().contains("has no environment qa"), "{err}");
    let wire = super::broker::wire_error(&err);
    assert_eq!(wire.code, ErrorCode::Config);
    assert_eq!(wire.who, Some(crate::ipc::protocol::Who::Agent));
    assert_eq!(
        wire.hint.as_deref(),
        Some("add it with `kagebunshin project add-env widget qa`")
    );

    let synced = d.sync(Some("ghost".parse().unwrap()), None).await.unwrap();
    let error = synced.refreshed[0].error.as_ref().unwrap();
    assert_eq!(error.code, ErrorCode::NoProject);
    assert_eq!(synced.refreshed[0].env.as_str(), "dev");
}

#[tokio::test]
async fn concurrent_requests_share_one_fetch() {
    let c = Canary::new();
    let fake = dev_sources(&c);
    let d = daemon(&fake);
    d.unlock(None).await.unwrap();

    let gate = fake.hold();
    let mut waiting = Vec::new();
    for i in 0..10 {
        let d = d.clone();
        waiting.push(tokio::spawn(async move {
            let f = facts(None, Some(&["A"]));
            match i % 3 {
                0 => d.status(Some(f)).await.map(|_| ()),
                1 => d.diff(&f).await.map(|_| ()),
                _ => d.hand_out(&f).await.map(|_| ()),
            }
        }));
    }
    settle().await;
    // One fetch of each of the three sources, however many requests wait.
    assert_eq!(fake.fetches(), 3);
    gate.open();
    for w in waiting {
        w.await.unwrap().unwrap();
    }
    assert_eq!(fake.fetches(), 3);
    d.status(Some(facts(None, None))).await.unwrap();
    assert_eq!(fake.fetches(), 3);
}

#[tokio::test]
async fn sync_refetches() {
    let fake = FakeSources::new();
    fake.set("widget.dev", &[("A", "one")])
        .set("widget/dev/x", &[("B", "one")]);
    let d = daemon(&fake);
    d.unlock(None).await.unwrap();
    let value = |v: &super::EnvValues| v.keys[&key("A")].value.expose().to_owned();

    assert_eq!(value(&d.hand_out(&facts(None, None)).await.unwrap()), "one");
    fake.set("widget.dev", &[("A", "two")]);
    // Cached until sync.
    assert_eq!(value(&d.hand_out(&facts(None, None)).await.unwrap()), "one");
    let n = fake.fetches();

    let report = d.sync(Some("widget".parse().unwrap()), None).await.unwrap();
    assert_eq!(report.refreshed.len(), 1);
    let r = &report.refreshed[0];
    assert_eq!(
        (r.env.as_str(), r.keys, r.error.is_none()),
        ("dev", Some(2), true)
    );
    assert_eq!(fake.fetches(), n + 3);
    assert_eq!(value(&d.hand_out(&facts(None, None)).await.unwrap()), "two");

    // Without a project, every cached environment is fetched again.
    fake.set("widget.dev", &[("A", "three")]);
    let report = d.sync(None, None).await.unwrap();
    assert_eq!(report.refreshed.len(), 1);
    assert_eq!(fake.fetches(), n + 6);
    assert_eq!(
        value(&d.hand_out(&facts(None, None)).await.unwrap()),
        "three"
    );

    // Nothing cached, nothing to do.
    d.lock();
    d.unlock(None).await.unwrap();
    assert!(d.sync(None, None).await.unwrap().refreshed.is_empty());
}

#[tokio::test]
async fn a_fetch_started_before_sync_does_not_overwrite_the_cache() {
    let fake = FakeSources::new();
    fake.set("widget.dev", &[("A", "old")])
        .set("widget/dev/x", &[("B", "old")]);
    let d = daemon(&fake);
    d.unlock(None).await.unwrap();

    let gate = fake.hold();
    let early = tokio::spawn({
        let d = d.clone();
        async move { d.hand_out(&facts(None, None)).await }
    });
    settle().await;
    assert_eq!(fake.fetches(), 3);

    fake.set("widget.dev", &[("A", "new")]);
    fake.pass();
    d.sync(Some("widget".parse().unwrap()), None).await.unwrap();
    assert_eq!(fake.fetches(), 6);

    // The early request still gets what it waited for...
    gate.open();
    let old = early.await.unwrap().unwrap();
    assert_eq!(old.keys[&key("A")].value.expose(), "old");
    // ...but the cache keeps the sync's result.
    let now = d.hand_out(&facts(None, None)).await.unwrap();
    assert_eq!(now.keys[&key("A")].value.expose(), "new");
    assert_eq!(fake.fetches(), 6);
}

#[tokio::test]
async fn lock_drops_and_zeroes_cached_values() {
    let c = Canary::new();
    let fake = dev_sources(&c);
    let d = daemon(&fake);
    d.unlock(None).await.unwrap();

    let values = d.hand_out(&facts(None, None)).await.unwrap();
    let weak = Arc::downgrade(&values);
    drop(values);
    assert!(weak.upgrade().is_some(), "the cache holds the values");

    assert_eq!(
        d.handle(Request::Lock).await,
        Response::LockState {
            locked: true,
            warnings: Vec::new(),
        }
    );
    // Freed, so every SecretValue in it has been zeroed on drop.
    assert!(weak.upgrade().is_none());
    assert!(d.is_locked());
    assert_eq!(
        d.hand_out(&facts(None, None)).await.unwrap_err(),
        ResolveError::Locked
    );

    // Locking during a fetch cancels it; its waiters get "locked" and
    // nothing is cached.
    d.unlock(None).await.unwrap();
    let _gate = fake.hold();
    let waiter = tokio::spawn({
        let d = d.clone();
        async move { d.hand_out(&facts(None, None)).await }
    });
    settle().await;
    d.lock();
    assert_eq!(waiter.await.unwrap().unwrap_err(), ResolveError::Locked);
    fake.pass();
    d.unlock(None).await.unwrap();
    let before = fake.fetches();
    d.status(Some(facts(None, None))).await.unwrap();
    assert_eq!(fake.fetches(), before + 3);
}

/// A fetch that sync replaced no longer feeds the cache, but a lock must
/// still cancel it: otherwise whoever waits on it gets values after the
/// lock.
#[tokio::test]
async fn lock_cancels_fetches_that_sync_superseded() {
    let c = Canary::new();
    let fake = dev_sources(&c);
    let d = daemon(&fake);
    d.unlock(None).await.unwrap();

    let gate = fake.hold();
    let early = tokio::spawn({
        let d = d.clone();
        async move { d.hand_out(&facts(None, None)).await }
    });
    settle().await;
    let syncing = tokio::spawn({
        let d = d.clone();
        async move { d.sync(Some("widget".parse().unwrap()), None).await }
    });
    settle().await;
    // Both fetches are in flight: the early one, now superseded, and sync's.
    assert_eq!(fake.fetches(), 6);

    d.lock();
    gate.open();
    assert_eq!(early.await.unwrap().unwrap_err(), ResolveError::Locked);
    let synced = syncing.await.unwrap().unwrap();
    assert_eq!(
        synced.refreshed[0].error.as_ref().unwrap().code,
        ErrorCode::Locked
    );
    settle().await;
    assert_eq!(fake.reads(), 0, "no value was read after the lock");
}

/// A lock that arrives while unlock decrypts the store wins.
#[tokio::test]
async fn a_lock_during_unlock_is_not_undone() {
    let (_tmp, file, d) = stored_daemon();
    init(&file, &d).await;
    d.lock();

    // Unlock reads the lock count, then waits for the store, as it would
    // while another store request runs; the lock lands in that window.
    let io = d.hold_store_io().await;
    let unlocking = tokio::spawn({
        let d = d.clone();
        async move { d.unlock(Some(Passphrase::new("pw".into()))).await }
    });
    settle().await;
    d.lock();
    drop(io);
    assert_eq!(unlocking.await.unwrap(), Err(ResolveError::Locked));
    assert!(d.is_locked());

    // Without a lock in between it unlocks as usual.
    d.unlock(Some(Passphrase::new("pw".into()))).await.unwrap();
    assert!(!d.is_locked());
}

const IDLE: Duration = Duration::from_mins(30);
const MINUTE: Duration = Duration::from_secs(60);

#[tokio::test(start_paused = true)]
async fn locks_after_the_idle_timeout() {
    let fake = dev_sources(&Canary::new());
    let d = daemon(&fake);
    d.unlock(None).await.unwrap();
    tokio::time::sleep(IDLE.checked_sub(MINUTE).unwrap()).await;
    assert!(!d.is_locked());
    tokio::time::sleep(2 * MINUTE).await;
    assert!(d.is_locked());
}

#[tokio::test(start_paused = true)]
async fn handing_out_values_resets_the_idle_timer() {
    let fake = dev_sources(&Canary::new());
    let d = daemon(&fake);
    d.unlock(None).await.unwrap();
    for _ in 0..3 {
        tokio::time::sleep(IDLE.checked_sub(MINUTE).unwrap()).await;
        d.hand_out(&facts(None, None)).await.unwrap();
        assert!(!d.is_locked());
    }
    tokio::time::sleep(IDLE + MINUTE).await;
    assert!(d.is_locked());
}

#[tokio::test(start_paused = true)]
async fn polling_does_not_extend_the_idle_timer() {
    let fake = dev_sources(&Canary::new());
    let d = daemon(&fake);
    d.unlock(None).await.unwrap();
    let f = facts(None, Some(&["A"]));
    let mut elapsed = Duration::ZERO;
    while elapsed < IDLE.checked_sub(MINUTE).unwrap() {
        tokio::time::sleep(MINUTE).await;
        elapsed += MINUTE;
        d.status(Some(f.clone())).await.unwrap();
        d.status(None).await.unwrap();
        d.diff(&f).await.unwrap();
        d.sync(None, None).await.unwrap();
        // Unlocking again is not a reset either.
        d.handle(Request::Unlock { passphrase: None }).await;
        assert_eq!(
            d.handle(Request::Ping).await,
            Response::Error(crate::ipc::protocol::WireError::new(
                ErrorCode::BadRequest,
                "not a daemon state request"
            ))
        );
    }
    assert!(!d.is_locked());
    tokio::time::sleep(2 * MINUTE).await;
    assert!(d.is_locked());
}

#[tokio::test]
async fn handle_answers_with_value_free_responses() {
    let c = Canary::new();
    let fake = dev_sources(&c);
    fake.set("widget/staging", &[("A", c.value())]);
    let d = daemon(&fake);
    let r = d.handle(Request::Diff {
        facts: facts(None, None),
    });
    let Response::Error(e) = r.await else {
        panic!()
    };
    assert_eq!(e.code, ErrorCode::Locked);
    let Response::LockState {
        locked: false,
        warnings,
    } = d.handle(Request::Unlock { passphrase: None }).await
    else {
        panic!()
    };
    assert_eq!(warnings.len(), 5, "WIDGET's production-like envs");
    let f = facts(None, Some(&["A", "Z"]));
    for req in [
        Request::Status {
            facts: Some(f.clone()),
        },
        Request::Diff { facts: f.clone() },
        Request::Sync {
            project: None,
            env: None,
        },
        Request::Status {
            facts: Some(facts(Some("staging"), None)),
        },
    ] {
        let resp = d.handle(req).await;
        assert!(!matches!(resp, Response::Error(_)), "{resp:?}");
        assert_clean(&c, &resp);
    }
}

#[tokio::test]
async fn run_env_injects_the_example_keys_or_all_of_them() {
    let c = Canary::new();
    let fake = dev_sources(&c);
    let (_tmp, d) = staging_marked(&fake).await;

    let names = |r: &crate::ipc::protocol::RunEnvReply| -> Vec<String> {
        r.vars.iter().map(|v| v.key.to_string()).collect()
    };
    let r = d
        .run_env(&facts(None, Some(&["C", "Z", "A", "C"])))
        .await
        .unwrap();
    assert_eq!((r.project.as_str(), r.env.as_str()), ("widget", "dev"));
    assert_eq!(names(&r), ["A", "C"]);
    assert_eq!(r.missing, [key("Z")]);
    assert!(r.vars.iter().all(|v| v.value.expose() == c.value()));
    assert_eq!(r.mask_min_len, 8);
    assert_no_canary(&c, &format!("{r:?}"));

    let r = d.run_env(&facts(None, None)).await.unwrap();
    assert_eq!(names(&r), ["A", "B", "C", "D"]);
    assert!(r.missing.is_empty());

    // Through `handle`, as the socket sees it: values only in the reply.
    let resp = d
        .handle(Request::RunEnv {
            facts: facts(Some("staging"), None),
            program: None,
            command: Vec::new(),
        })
        .await;
    assert_eq!(error_code(resp), ErrorCode::SensitiveEnv);
    let Response::RunEnv(r) = d
        .handle(Request::RunEnv {
            facts: facts(None, Some(&["B"])),
            program: None,
            command: Vec::new(),
        })
        .await
    else {
        panic!()
    };
    assert_eq!(names(&r), ["B"]);
}

/// Plain settings are the lowest layer, go out marked plain, count as set,
/// and are read from the project file on each request, with no sync.
#[tokio::test]
async fn plain_settings_fill_in_what_no_source_sets() {
    let fake = FakeSources::new();
    fake.set("widget.dev", &[("A", "from-the-source"), ("B", "bee")]);
    let file = Arc::new(Mutex::new(
        r#"
schema = 1
remotes = ["git@github.com:acme/widget.git"]
[envs.dev.vars]
A = "plain-a"
PORT = "3000"
LOG = "debug"
"#
        .to_owned(),
    ));
    let text = file.clone();
    let d = Daemon::new(
        Box::new(move || {
            let text = text.lock().unwrap().clone();
            let project = parse_project(Path::new("/cfg/projects/widget.toml"), &text)?;
            Registry::new(Config::default(), vec![project])
        }),
        fake.clone(),
        StoreFile::new("/nonexistent/kagebunshin-test/store.age"),
    );
    d.unlock(None).await.unwrap();
    let rows = |r: &crate::ipc::protocol::RunEnvReply| -> Vec<(String, String, bool)> {
        r.vars
            .iter()
            .map(|v| (v.key.to_string(), v.value.expose().to_owned(), v.plain))
            .collect()
    };
    let row = |k: &str, v: &str, plain| (k.to_owned(), v.to_owned(), plain);

    let example = ["A", "PORT", "MISSING"];
    let r = d.run_env(&facts(None, Some(&example))).await.unwrap();
    assert_eq!(
        rows(&r),
        [
            row("A", "from-the-source", false),
            row("PORT", "3000", true)
        ]
    );
    assert_eq!(r.missing, [key("MISSING")]);
    let r = d.run_env(&facts(None, None)).await.unwrap();
    assert_eq!(
        rows(&r),
        [
            row("A", "from-the-source", false),
            row("B", "bee", false),
            row("LOG", "debug", true),
            row("PORT", "3000", true),
        ]
    );

    let env = d
        .status(Some(facts(None, Some(&example))))
        .await
        .unwrap()
        .env
        .unwrap();
    let vars: Vec<_> = env
        .vars
        .iter()
        .map(|v| (v.key.as_str(), v.value.as_str(), v.in_example))
        .collect();
    assert_eq!(vars, [("LOG", "debug", false), ("PORT", "3000", true)]);
    assert_eq!(env.missing, [key("MISSING")]);
    let diff = d.diff(&facts(None, Some(&example))).await.unwrap();
    assert_eq!(diff.missing, [key("MISSING")]);
    assert!(diff.extra.iter().all(|k| k.as_str() == "B"), "{diff:?}");

    // An edit to the file shows at once, without a sync or a fetch.
    {
        let mut text = file.lock().unwrap();
        *text = text.replace("3000", "4000") + "MISSING = \"x\"\n";
    }
    let r = d.run_env(&facts(None, Some(&example))).await.unwrap();
    assert_eq!(
        rows(&r),
        [
            row("A", "from-the-source", false),
            row("MISSING", "x", true),
            row("PORT", "4000", true),
        ]
    );
    assert!(r.missing.is_empty());
    assert_eq!(fake.fetches(), 1);
}

/// Only the local store, through the real providers (no AWS source, so
/// nothing leaves the process).
const STORED: &str = r#"
schema = 1
remotes = ["git@github.com:acme/widget.git"]

# No sources: with `default_provider = "file"` that is section [widget.dev].
[envs.dev]

# A bare file source: section [widget.local], as in the spec's sample.
[[envs.local.sources]]
provider = "file"

# Marked sensitive in the store by `create`.
[envs.prod]
[envs.rc]
"#;

fn stored_daemon() -> (tempfile::TempDir, StoreFile, Daemon) {
    let tmp = tempfile::tempdir().unwrap();
    let file = StoreFile::new(tmp.path().join(STORE_FILE)).with_test_work_factor();
    let project = parse_project(Path::new("/cfg/projects/widget.toml"), STORED).unwrap();
    let config = Config {
        default_provider: Provider::File,
        ..Config::default()
    };
    let registry = Registry::new(config, vec![project]).unwrap();
    let d = Daemon::new(
        Box::new(move || Ok(registry.clone())),
        Arc::new(super::Providers::new()),
        file.clone(),
    );
    (tmp, file, d)
}

/// Creates the store with passphrase `pw` and unlocks with it, as
/// `kagebunshin store init` does: the daemon itself creates no store.
async fn init(file: &StoreFile, d: &Daemon) {
    init_with(file, d, "pw").await;
}

async fn init_with(file: &StoreFile, d: &Daemon, pass: &str) {
    create(file, pass);
    d.lock();
    d.unlock(Some(Passphrase::new(pass.into()))).await.unwrap();
}

/// Creates the store, with [`STORED`]'s environment prod marked sensitive.
fn create(file: &StoreFile, pass: &str) {
    let pass = Passphrase::new(pass.into());
    file.create(&pass).unwrap();
    file.update(&pass, None, |st| {
        Ok(st.mark_env("widget.prod".parse().unwrap(), true))
    })
    .unwrap();
}

fn pw(s: &str) -> WireSecret {
    WireSecret::new(s.into())
}

fn store_set(k: &str, v: &str, pass: &str) -> Request {
    Request::StoreSet {
        section: "widget.dev".parse().unwrap(),
        key: key(k),
        value: WireSecret::new(v.into()),
        passphrase: pw(pass),
        sensitive: false,
    }
}

fn error_code(r: Response) -> ErrorCode {
    match r {
        Response::Error(e) => e.code,
        other => panic!("{other:?}"),
    }
}

fn listing(d: &Daemon) -> Vec<(String, Vec<String>)> {
    d.store_list()
        .unwrap()
        .sections
        .into_iter()
        .map(|s| {
            let keys = s.keys.iter().map(ToString::to_string).collect();
            (s.section.to_string(), keys)
        })
        .collect()
}

#[tokio::test]
async fn store_init_unlocks_and_file_sources_read_the_store() {
    let c = Canary::new();
    let (_tmp, store, d) = stored_daemon();
    assert!(d.is_locked());
    // First run: one passphrase, and the daemon is unlocked with it.
    init(&store, &d).await;
    assert!(!d.is_locked());
    for (k, change) in [
        ("A", Change::Added),
        ("B", Change::Added),
        ("A", Change::Replaced),
    ] {
        let r = d.handle(store_set(k, c.value(), "pw")).await;
        assert_eq!(
            r,
            Response::Store {
                change,
                locked: false
            }
        );
    }

    let values = d.hand_out(&facts(None, None)).await.unwrap();
    let a = &values.keys[&key("A")];
    assert_eq!(a.value.expose(), c.value());
    assert_eq!(a.origin, file("widget.dev"));
    let s = d.handle(Request::Status {
        facts: Some(facts(None, Some(&["A", "B"]))),
    });
    let s = s.await;
    assert_clean(&c, &s);
    let Response::Status(StatusReport { env: Some(env), .. }) = s else {
        panic!("{s:?}")
    };
    let origins: Vec<_> = env.keys.iter().map(|k| k.origin.to_string()).collect();
    assert_eq!(origins, ["file:widget.dev", "file:widget.dev"]);

    // Names only.
    let list = d.handle(Request::StoreList).await;
    assert_clean(&c, &list);
    assert_eq!(
        listing(&d),
        [("widget.dev".into(), vec!["A".into(), "B".into()])]
    );
}

/// An environment's mark holds for its store section wherever it is read:
/// a `file` source added to an unmarked environment, which takes no
/// passphrase, does not hand out a marked one's keys.
#[tokio::test]
async fn an_env_mark_follows_its_section_into_other_environments() {
    let c = Canary::new();
    let tmp = tempfile::tempdir().unwrap();
    let file = StoreFile::new(tmp.path().join(STORE_FILE)).with_test_work_factor();
    let text = r#"
schema = 1
remotes = ["git@github.com:acme/widget.git"]
[envs.prod]
[[envs.dev.sources]]
provider = "file"
secret = "widget.prod"
"#;
    let project = parse_project(Path::new("/cfg/projects/widget.toml"), text).unwrap();
    let config = Config {
        default_provider: Provider::File,
        ..Config::default()
    };
    let registry = Registry::new(config, vec![project]).unwrap();
    let d = Daemon::new(
        Box::new(move || Ok(registry.clone())),
        Arc::new(super::Providers::new()),
        file.clone(),
    );
    init(&file, &d).await;
    // Reading widget.prod makes dev look like production; acknowledged as
    // not, only the marked section's keys are refused.
    let ack = Request::AcknowledgeEnv {
        project: "widget".parse().unwrap(),
        env: "dev".parse().unwrap(),
        acknowledged: true,
        unmark: Vec::new(),
        passphrase: pw("pw"),
    };
    assert!(matches!(d.handle(ack).await, Response::Store { .. }));
    let set = Request::StoreSet {
        section: "widget.prod".parse().unwrap(),
        key: key("DB_URL"),
        value: WireSecret::new(c.value().into()),
        passphrase: pw("pw"),
        sensitive: false,
    };
    assert!(matches!(d.handle(set).await, Response::Store { .. }));

    let env = ("widget".parse().unwrap(), "dev".parse().unwrap());
    let values = d.hand_out(&facts(Some("dev"), None)).await.unwrap();
    assert_eq!(
        values.keys[&key("DB_URL")].origin,
        self::file("widget.prod")
    );
    let err = d
        .refuse_sensitive_keys(&env, &values, [&key("DB_URL")])
        .unwrap_err();
    assert_clean_err(&c, &err);
    assert_eq!(
        err.to_string(),
        "refusing key DB_URL of environment dev of project widget: it comes from \
         file:widget.prod, which is marked sensitive"
    );
    let r = d
        .handle(Request::RunEnv {
            facts: facts(Some("dev"), None),
            program: None,
            command: Vec::new(),
        })
        .await;
    assert_clean(&c, &r);
    assert_eq!(error_code(r), ErrorCode::SensitiveEnv);
    let Response::Status(StatusReport { env: Some(st), .. }) = d
        .handle(Request::Status {
            facts: Some(facts(Some("dev"), None)),
        })
        .await
    else {
        panic!()
    };
    assert!(st.keys[0].sensitive);

    // Unmarking prod, with the passphrase, frees it.
    let unmark = Request::MarkEnv {
        project: "widget".parse().unwrap(),
        env: "prod".parse().unwrap(),
        sensitive: false,
        also: Vec::new(),
        passphrase: pw("pw"),
    };
    assert!(matches!(d.handle(unmark).await, Response::Store { .. }));
    d.refuse_sensitive_keys(&env, &values, [&key("DB_URL")])
        .unwrap();
}

#[tokio::test]
async fn a_sensitive_store_key_is_refused_until_unmarked() {
    let c = Canary::new();
    let (_tmp, file, d) = stored_daemon();
    init(&file, &d).await;
    let marked = Request::StoreSet {
        section: "widget.dev".parse().unwrap(),
        key: key("A"),
        value: WireSecret::new(c.value().into()),
        passphrase: pw("pw"),
        sensitive: true,
    };
    assert_eq!(
        d.handle(marked).await,
        Response::Store {
            change: Change::Added,
            locked: false
        }
    );
    d.handle(store_set("B", c.value(), "pw")).await;
    // Replacing a value keeps its mark.
    d.handle(store_set("A", c.value(), "pw")).await;
    assert!(
        file.open(&Passphrase::new("pw".into()))
            .unwrap()
            .is_sensitive(&"widget.dev".parse().unwrap(), &key("A"))
    );
    let Response::StoreList(list) = d.handle(Request::StoreList).await else {
        panic!()
    };
    assert_eq!(list.sections[0].sensitive, [key("A")]);

    let env = ("widget".parse().unwrap(), "dev".parse().unwrap());
    let values = d.hand_out(&facts(None, None)).await.unwrap();
    d.refuse_sensitive_keys(&env, &values, [&key("B")]).unwrap();
    let err = d
        .refuse_sensitive_keys(&env, &values, [&key("B"), &key("A")])
        .unwrap_err();
    assert_clean_err(&c, &err);
    assert_eq!(
        err.to_string(),
        "refusing key A of environment dev of project widget: it comes from file:widget.dev, \
         which is marked sensitive"
    );
    assert_eq!(
        super::broker::wire_error(&err).code,
        ErrorCode::SensitiveEnv
    );

    // Unmarking takes the passphrase, and applies to values already handed
    // out, without a sync.
    let unmark = |p: &str| Request::StoreMark {
        section: "widget.dev".parse().unwrap(),
        key: key("A"),
        sensitive: false,
        passphrase: pw(p),
    };
    assert_eq!(
        error_code(d.handle(unmark("wrong")).await),
        ErrorCode::WrongPassphrase
    );
    assert!(d.refuse_sensitive_keys(&env, &values, [&key("A")]).is_err());
    assert_eq!(
        d.handle(unmark("pw")).await,
        Response::Store {
            change: Change::Unmarked,
            locked: false
        }
    );
    d.refuse_sensitive_keys(&env, &values, [&key("A")]).unwrap();
    // And marking back again.
    let mark = Request::StoreMark {
        section: "widget.dev".parse().unwrap(),
        key: key("A"),
        sensitive: true,
        passphrase: pw("pw"),
    };
    assert_eq!(
        d.handle(mark).await,
        Response::Store {
            change: Change::Marked,
            locked: false
        }
    );
    assert!(d.refuse_sensitive_keys(&env, &values, [&key("A")]).is_err());
    let Response::Status(StatusReport { env: Some(st), .. }) = d
        .handle(Request::Status {
            facts: Some(facts(None, None)),
        })
        .await
    else {
        panic!()
    };
    let marks: Vec<_> = st.keys.iter().map(|k| k.sensitive).collect();
    assert_eq!(marks, [true, false]);
    // A key that is not there cannot be marked.
    let missing = Request::StoreMark {
        section: "widget.dev".parse().unwrap(),
        key: key("NOPE"),
        sensitive: true,
        passphrase: pw("pw"),
    };
    assert_eq!(error_code(d.handle(missing).await), ErrorCode::Store);
}

#[tokio::test]
async fn a_bare_file_source_reads_its_env_section() {
    let c = Canary::new();
    let (_tmp, store, d) = stored_daemon();
    init(&store, &d).await;
    let set = Request::StoreSet {
        section: "widget.local".parse().unwrap(),
        key: key("A"),
        value: WireSecret::new(c.value().into()),
        passphrase: pw("pw"),
        sensitive: false,
    };
    d.handle(set).await;
    d.handle(store_set("B", c.value(), "pw")).await;

    let values = d.hand_out(&facts(Some("local"), None)).await.unwrap();
    let keys: Vec<_> = values.keys.keys().map(ToString::to_string).collect();
    assert_eq!(keys, ["A"], "only [widget.local], not [widget.dev]");
    assert_eq!(values.keys[&key("A")].origin, file("widget.local"));
}

#[tokio::test]
async fn unlocking_a_store_needs_its_passphrase() {
    let c = Canary::new();
    let (_tmp, file, d) = stored_daemon();
    create(&file, "pw");
    assert_eq!(
        d.handle(store_set("A", c.value(), "pw")).await,
        Response::Store {
            change: Change::Added,
            locked: true
        },
        "a write needs the passphrase, not an unlocked daemon"
    );
    assert_eq!(
        error_code(d.handle(Request::StoreList).await),
        ErrorCode::Locked
    );

    let e = d.unlock(None).await.unwrap_err();
    assert_eq!(
        super::broker::wire_error(&e).code,
        ErrorCode::PassphraseRequired
    );
    let e = d
        .unlock(Some(Passphrase::new(c.value().into())))
        .await
        .unwrap_err();
    assert_clean_err(&c, &e);
    assert_eq!(
        super::broker::wire_error(&e).code,
        ErrorCode::WrongPassphrase
    );
    assert!(d.is_locked());

    let r = d
        .handle(Request::Unlock {
            passphrase: Some(pw("pw")),
        })
        .await;
    assert!(
        matches!(&r, Response::LockState { locked: false, warnings } if warnings.len() == 1),
        "{r:?}: STORED's unmarked rc env warns"
    );
    assert_eq!(listing(&d), [("widget.dev".into(), vec!["A".into()])]);
    let values = d.hand_out(&facts(None, None)).await.unwrap();
    assert_eq!(values.keys[&key("A")].value.expose(), c.value());

    // Locking drops the store with the cache.
    d.lock();
    assert_eq!(d.store_list().unwrap_err(), ResolveError::Locked);
}

fn get(env: Option<&str>, k: &str, pass: &str) -> Request {
    Request::Get {
        facts: facts(env, None),
        key: key(k),
        passphrase: pw(pass),
    }
}

#[tokio::test]
async fn get_needs_the_store_passphrase() {
    let c = Canary::new();
    let (_tmp, file, d) = stored_daemon();
    assert_eq!(
        error_code(d.handle(get(None, "A", "pw")).await),
        ErrorCode::Locked
    );
    init(&file, &d).await;
    d.handle(store_set("A", c.value(), "pw")).await;
    for (section, k, sensitive) in [
        ("widget.prod", "A", false),
        ("widget.rc", "A", false),
        ("widget.dev", "S", true),
    ] {
        d.handle(Request::StoreSet {
            section: section.parse().unwrap(),
            key: key(k),
            value: WireSecret::new(c.value().into()),
            passphrase: pw("pw"),
            sensitive,
        })
        .await;
    }
    assert!(!d.is_locked());

    let r = d.handle(get(None, "A", "pw")).await;
    let Response::Value { value } = &r else {
        panic!("{r:?}")
    };
    assert_eq!(value.expose(), c.value());
    assert_no_canary(&c, &format!("{r:?}"));

    // Unlocked is not enough: the passphrase must be right every time.
    for (req, want) in [
        (get(None, "A", "wrong"), ErrorCode::WrongPassphrase),
        (get(None, "A", c.value()), ErrorCode::WrongPassphrase),
        (get(None, "NOPE", "pw"), ErrorCode::NoKey),
        (get(Some("prod"), "A", "pw"), ErrorCode::SensitiveEnv),
        (get(None, "S", "pw"), ErrorCode::SensitiveEnv),
    ] {
        let r = d.handle(req).await;
        assert_clean(&c, &r);
        assert_eq!(error_code(r), want);
    }
    // A production-like name nobody decided about waits for approval, as
    // a mark does, even with the passphrase; acknowledged, it is handed out.
    let r = d.handle(get(Some("rc"), "A", "pw")).await;
    assert_clean(&c, &r);
    assert_eq!(error_code(r), ErrorCode::SensitiveEnv);
    let ack = Request::AcknowledgeEnv {
        project: "widget".parse().unwrap(),
        env: "rc".parse().unwrap(),
        acknowledged: true,
        unmark: Vec::new(),
        passphrase: pw("pw"),
    };
    assert!(matches!(d.handle(ack).await, Response::Store { .. }));
    let r = d.handle(get(Some("rc"), "A", "pw")).await;
    assert!(matches!(r, Response::Value { .. }), "{r:?}");
}

/// The app's view: with the passphrase, a human may list the keys of an
/// environment marked sensitive and reveal any value, sensitive or not.
/// Nothing about it opens the sensitive environment to anyone else.
#[tokio::test]
async fn a_human_may_inspect_and_reveal_what_is_sensitive() {
    let c = Canary::new();
    let fake = dev_sources(&c);
    fake.set("widget/staging", &[("A", c.value())]);
    let (_tmp, d) = marked_daemon(WIDGET, &fake, |st| {
        st.mark_env("widget.staging".parse().unwrap(), true);
        st.mark_secret(sm("widget/local"), true).unwrap();
    })
    .await;
    let inspect = |env: &str, pass: &str| Request::Inspect {
        facts: facts(Some(env), None),
        passphrase: pw(pass),
    };
    let reveal = |env: &str, k: &str, pass: &str| Request::Reveal {
        facts: facts(Some(env), None),
        key: key(k),
        passphrase: pw(pass),
    };

    let r = d.handle(inspect("staging", "pw")).await;
    assert_clean(&c, &r);
    let Response::Status(StatusReport { env: Some(env), .. }) = r else {
        panic!("{r:?}")
    };
    assert_eq!(env.keys.len(), 1);
    assert_eq!(env.keys[0].origin, sm("widget/staging"));

    for (req, k) in [
        (reveal("staging", "A", "pw"), "A"),
        (reveal("dev", "D", "pw"), "D"),
    ] {
        let r = d.handle(req).await;
        assert_no_canary(&c, &format!("{r:?}"));
        let Response::Value { value } = r else {
            panic!("{k}: {r:?}")
        };
        assert_eq!(value.expose(), c.value());
    }
    for (req, want) in [
        (inspect("staging", "wrong"), ErrorCode::WrongPassphrase),
        (reveal("staging", "A", "wrong"), ErrorCode::WrongPassphrase),
        (reveal("staging", "NOPE", "pw"), ErrorCode::NoKey),
        (get(Some("staging"), "A", "pw"), ErrorCode::SensitiveEnv),
        (get(Some("dev"), "D", "pw"), ErrorCode::SensitiveEnv),
    ] {
        let r = d.handle(req).await;
        assert_clean(&c, &r);
        assert_eq!(error_code(r), want);
    }
    // Fetched for a human, still refused to everyone else.
    let f = facts(Some("staging"), None);
    assert!(d.status(Some(f.clone())).await.is_err());
    assert!(d.run_env(&f).await.is_err());

    d.lock();
    let r = d.handle(reveal("dev", "A", "pw")).await;
    assert_eq!(error_code(r), ErrorCode::Locked);
}

#[tokio::test]
async fn without_a_store_get_is_refused() {
    let c = Canary::new();
    let d = daemon(&dev_sources(&c));
    d.unlock(None).await.unwrap();
    let r = d.handle(get(None, "A", "anything")).await;
    assert_clean(&c, &r);
    assert_eq!(error_code(r), ErrorCode::NoStore);
}

#[tokio::test]
async fn every_store_write_checks_the_passphrase() {
    let c = Canary::new();
    let (_tmp, file, d) = stored_daemon();
    let none = d.handle(store_set("A", c.value(), "pw")).await;
    assert_eq!(error_code(none), ErrorCode::NoStore);
    init(&file, &d).await;
    d.handle(store_set("A", c.value(), "pw")).await;
    let before = std::fs::read(file.path()).unwrap();

    for req in [
        store_set("B", c.value(), "wrong"),
        Request::StoreUnset {
            section: "widget.dev".parse().unwrap(),
            key: key("A"),
            passphrase: pw("wrong"),
        },
        Request::StoreClear {
            project: "widget".parse().unwrap(),
            passphrase: pw("wrong"),
        },
        Request::StorePasswd {
            passphrase: pw("wrong"),
            new_passphrase: pw("new"),
        },
    ] {
        let r = d.handle(req).await;
        assert_clean(&c, &r);
        assert_eq!(error_code(r), ErrorCode::WrongPassphrase);
    }
    assert_eq!(std::fs::read(file.path()).unwrap(), before);
    assert_eq!(listing(&d), [("widget.dev".into(), vec!["A".into()])]);

    let missing = d
        .handle(Request::StoreUnset {
            section: "widget.dev".parse().unwrap(),
            key: key("NOPE"),
            passphrase: pw("pw"),
        })
        .await;
    assert_eq!(error_code(missing), ErrorCode::Store);

    let r = d
        .handle(Request::StorePasswd {
            passphrase: pw("pw"),
            new_passphrase: pw("new"),
        })
        .await;
    assert_eq!(
        r,
        Response::Store {
            change: Change::Rekeyed,
            locked: false
        }
    );
    d.lock();
    let old = d.unlock(Some(Passphrase::new("pw".into()))).await;
    assert_eq!(
        super::broker::wire_error(&old.unwrap_err()).code,
        ErrorCode::WrongPassphrase
    );
    d.unlock(Some(Passphrase::new("new".into()))).await.unwrap();
    assert_eq!(listing(&d), [("widget.dev".into(), vec!["A".into()])]);
}

#[tokio::test]
async fn store_clear_removes_a_projects_sections_even_while_locked() {
    let c = Canary::new();
    let (_tmp, file, d) = stored_daemon();
    init(&file, &d).await;
    let many = |sections: &[&str]| Request::StoreSetMany {
        sections: sections
            .iter()
            .map(|s| {
                let value = WireSecret::new(c.value().into());
                (s.parse().unwrap(), vec![(key("A"), value)])
            })
            .collect(),
        passphrase: pw("pw"),
    };
    d.handle(many(&["widget.dev", "widget.staging", "gadget.dev"]))
        .await;
    let clear = |project: &str| Request::StoreClear {
        project: project.parse().unwrap(),
        passphrase: pw("pw"),
    };

    let r = d.handle(clear("widget")).await;
    assert_clean(&c, &r);
    assert_eq!(
        r,
        Response::Store {
            change: Change::Removed,
            locked: false
        }
    );
    assert_eq!(listing(&d), [("gadget.dev".into(), vec!["A".into()])]);
    assert_eq!(
        error_code(d.handle(clear("widget")).await),
        ErrorCode::Store
    );

    // The passphrase is what it takes, so a locked daemon writes too, and
    // stays locked.
    d.lock();
    let r = d.handle(clear("gadget")).await;
    assert_eq!(
        r,
        Response::Store {
            change: Change::Removed,
            locked: true
        }
    );
    d.unlock(Some(Passphrase::new("pw".into()))).await.unwrap();
    assert!(listing(&d).is_empty());
}

#[tokio::test]
async fn without_a_store_file_sources_fail_and_unlock_needs_no_passphrase() {
    let (_tmp, file, d) = stored_daemon();
    d.unlock(None).await.unwrap();
    let e = d.hand_out(&facts(None, None)).await.unwrap_err();
    let w = super::broker::wire_error(&e);
    assert_eq!(w.code, ErrorCode::SourceFailed);
    assert!(w.message.contains("no local store"), "{}", w.message);
    assert!(w.hint.unwrap().contains("store init"));
    assert_eq!(
        error_code(d.handle(Request::StoreList).await),
        ErrorCode::NoStore
    );

    // Creating the store while unlocked hands it to the session; the
    // failed fetch was not cached, so the next request sees it.
    init(&file, &d).await;
    d.handle(store_set("A", "v", "pw")).await;
    let values = d.hand_out(&facts(None, None)).await.unwrap();
    assert_eq!(values.keys[&key("A")].value.expose(), "v");
}

/// Secrets Manager per AWS profile, behind the real [`super::Providers`]:
/// each profile is its own account, so a value shows which client read it.
#[derive(Default)]
struct FakeAws {
    /// Profile (`""` for the ambient credentials) to secret name to JSON.
    accounts: BTreeMap<String, BTreeMap<String, String>>,
    /// Profiles whose credentials have expired.
    expired: BTreeSet<String>,
    /// Every client made, as (profile, region).
    clients: Mutex<Vec<(Option<String>, Option<String>)>>,
    /// Every secret whose value was asked for, over all clients.
    gets: Arc<Mutex<Vec<String>>>,
}

struct FakeAccount {
    secrets: BTreeMap<String, String>,
    expired: bool,
    gets: Arc<Mutex<Vec<String>>>,
}

#[async_trait::async_trait]
impl AwsClients for Arc<FakeAws> {
    async fn client(&self, profile: Option<&Profile>, region: Option<&Region>) -> Arc<dyn SmApi> {
        let profile = profile.map(|p| p.as_str().to_owned());
        let region = region.map(|r| r.as_str().to_owned());
        self.clients.lock().unwrap().push((profile.clone(), region));
        let name = profile.unwrap_or_default();
        Arc::new(FakeAccount {
            secrets: self.accounts.get(&name).cloned().unwrap_or_default(),
            expired: self.expired.contains(&name),
            gets: self.gets.clone(),
        })
    }
}

#[async_trait::async_trait]
impl SmApi for FakeAccount {
    async fn list_page(&self, prefix: &str, _: Option<String>) -> Result<Page, ApiError> {
        if self.expired {
            return Err(ApiError::NeedsLogin);
        }
        let names = self.secrets.keys().filter(|n| n.starts_with(prefix));
        Ok(Page {
            names: names.cloned().collect(),
            next_token: None,
        })
    }

    async fn get_value(&self, name: &str) -> Result<Got, ApiError> {
        self.gets.lock().unwrap().push(name.to_owned());
        if self.expired {
            return Err(ApiError::NeedsLogin);
        }
        let json = self.secrets.get(name).ok_or(ApiError::NotFound)?;
        Ok(RawSecret::String(SecretValue::new(json.clone())).into())
    }
}

fn aws_daemon(project: &str, aws: &Arc<FakeAws>) -> Daemon {
    let project = parse_project(Path::new("/cfg/projects/widget.toml"), project).unwrap();
    let registry = Registry::new(Config::default(), vec![project]).unwrap();
    let store = StoreFile::new("/nonexistent/kagebunshin-test/store.age");
    let providers = super::Providers::with_aws(aws.clone());
    Daemon::new(
        Box::new(move || Ok(registry.clone())),
        Arc::new(providers),
        store,
    )
}

fn account(secrets: &[(&str, String)]) -> BTreeMap<String, String> {
    secrets
        .iter()
        .map(|(n, j)| ((*n).to_owned(), j.clone()))
        .collect()
}

/// One env, three AWS sources on two profiles (one inherited from the
/// project, one the source's own with its own region), one daemon.
#[tokio::test]
async fn one_env_mixes_aws_profiles_and_regions() {
    let (app, platform) = (Canary::new(), Canary::new());
    let text = r#"
schema = 1
remotes = ["git@github.com:acme/widget.git"]
profile = "widget-dev"

[[envs.dev.sources]]
provider = "aws_sm"
prefix = "widget/dev/"

[[envs.dev.sources]]
provider = "aws_sm"
secret = "shared/dev"
profile = "platform"
region = "eu-west-3"

[[envs.dev.sources]]
provider = "aws_sm"
secret = "widget/eu"
region = "eu-central-1"
"#;
    let mut aws = FakeAws::default();
    aws.accounts.insert(
        "widget-dev".into(),
        account(&[
            ("widget/dev/app", format!(r#"{{"A":"{}"}}"#, app.value())),
            // The same name in the other account: proves which client read it.
            ("shared/dev", r#"{"B":"from-the-wrong-account"}"#.into()),
            ("widget/eu", r#"{"C":"eu-value"}"#.into()),
        ]),
    );
    aws.accounts.insert(
        "platform".into(),
        account(&[("shared/dev", format!(r#"{{"B":"{}"}}"#, platform.value()))]),
    );
    let aws = Arc::new(aws);
    let d = aws_daemon(text, &aws);
    d.unlock(None).await.unwrap();

    let values = d.hand_out(&facts(None, None)).await.unwrap();
    let got: Vec<_> = values
        .keys
        .iter()
        .map(|(k, r)| (k.as_str(), r.value.expose(), r.origin.location.as_str()))
        .collect();
    assert_eq!(
        got,
        [
            ("A", app.value(), "widget/dev/app"),
            ("B", platform.value(), "shared/dev"),
            ("C", "eu-value", "widget/eu"),
        ]
    );
    let mut clients = aws.clients.lock().unwrap().clone();
    clients.sort();
    let s = |x: &str| Some(x.to_owned());
    assert_eq!(
        clients,
        [
            (s("platform"), s("eu-west-3")),
            (s("widget-dev"), None),
            (s("widget-dev"), s("eu-central-1")),
        ]
    );
    let report = d.status(Some(facts(None, None))).await.unwrap();
    assert_clean(&app, &report);
    assert_clean(&platform, &report);
}

/// Every failing profile gets one line and its own login hint, once; a
/// source with no profile says it used the ambient credentials. Values the healthy source
/// read appear nowhere.
#[tokio::test]
async fn needs_login_names_each_failing_profile() {
    let c = Canary::new();
    let text = r#"
schema = 1
remotes = ["git@github.com:acme/widget.git"]

[[envs.dev.sources]]
provider = "aws_sm"
prefix = "a/"
profile = "alpha"

[[envs.dev.sources]]
provider = "aws_sm"
secret = "ok/dev"
profile = "gamma"

[[envs.dev.sources]]
provider = "aws_sm"
secret = "b/dev"
profile = "beta"
region = "us-west-2"

[[envs.dev.sources]]
provider = "aws_sm"
secret = "a/other"
profile = "alpha"

[[envs.dev.sources]]
provider = "aws_sm"
secret = "ambient/dev"
"#;
    let mut aws = FakeAws::default();
    aws.accounts.insert(
        "gamma".into(),
        account(&[("ok/dev", format!(r#"{{"K":"{}"}}"#, c.value()))]),
    );
    aws.expired = ["alpha", "beta", ""].map(String::from).into();
    let aws = Arc::new(aws);
    let d = aws_daemon(text, &aws);
    d.unlock(None).await.unwrap();

    let err = d.hand_out(&facts(None, None)).await.unwrap_err();
    assert_clean_err(&c, &err);
    let ResolveError::Sources { failures, hint, .. } = &err else {
        panic!("{err:?}");
    };
    // One line per login, with when it was checked.
    let lines: Vec<&str> = failures
        .iter()
        .map(|f| {
            let (line, at) = f.split_once(", checked ").unwrap();
            assert!(at.len() == 13 && at.ends_with(" UTC)"), "{f}");
            line
        })
        .collect();
    assert!(
        err.to_string().ends_with(&format!("\n  {}", failures[2])),
        "{err}"
    );
    let expired = "credentials missing or expired";
    assert_eq!(
        lines,
        [
            format!("profile alpha: {expired} (2 sources"),
            format!("profile beta: {expired} (1 source"),
            format!("the default AWS credentials: {expired} (1 source"),
        ]
    );
    let want = "run `aws login --profile alpha` (`aws sso login` for an SSO profile); \
                run `aws login --profile beta` (`aws sso login` for an SSO profile); \
                this source has no profile, so it used the ambient/default AWS credentials; \
                refresh them (e.g. `aws login`) or set `profile` on the source";
    assert_eq!(hint.as_deref(), Some(want));
    let wire = super::broker::wire_error(&err);
    assert_eq!(wire.hint.as_deref(), Some(want));
    assert_eq!(wire.code, ErrorCode::SourceFailed, "{wire:?}");
}

fn run_req(env: Option<&str>) -> Request {
    Request::RunEnv {
        facts: facts(env, None),
        program: None,
        command: Vec::new(),
    }
}

/// Every caller gets the same policy: what only a human may do needs the
/// passphrase, and the rest is what an agent may do anyway or hands out no
/// values.
#[tokio::test]
async fn what_only_a_human_may_do_needs_the_passphrase() {
    let (_tmp, file, d) = stored_daemon();
    let me = this_process();
    init(&file, &d).await;
    d.handle(store_set("A", "v", "pw")).await;
    let section = || "widget.dev".parse().unwrap();
    let needs_passphrase = [
        get(None, "A", "wrong"),
        store_set("A", "v", "wrong"),
        Request::StoreMark {
            section: section(),
            key: key("A"),
            sensitive: false,
            passphrase: pw("wrong"),
        },
        Request::StoreUnset {
            section: section(),
            key: key("A"),
            passphrase: pw("wrong"),
        },
        Request::StorePasswd {
            passphrase: pw("wrong"),
            new_passphrase: pw("new"),
        },
        Request::AcknowledgeEnv {
            project: "widget".parse().unwrap(),
            env: "dev".parse().unwrap(),
            acknowledged: true,
            unmark: Vec::new(),
            passphrase: pw("wrong"),
        },
    ];
    for req in needs_passphrase {
        let what = format!("{req:?}");
        let resp = d.handle_from(req, &me).await;
        assert_eq!(error_code(resp), ErrorCode::WrongPassphrase, "{what}");
    }
    let open = [
        Request::Status {
            facts: Some(facts(None, None)),
        },
        Request::Diff {
            facts: facts(None, None),
        },
        run_req(None),
        Request::Sync {
            project: None,
            env: None,
        },
        // Adds a mark only: the worst it does is ask for an approval more.
        Request::AddMark {
            target: MarkTarget::Key {
                section: section(),
                key: key("A"),
            },
        },
        Request::StoreList,
        Request::Lock,
    ];
    for req in open {
        let what = format!("{req:?}");
        let resp = d.handle_from(req, &me).await;
        assert!(!matches!(resp, Response::Error(_)), "{what}: {resp:?}");
    }
    // Locked now; unlocking with a store takes its passphrase.
    let resp = d
        .handle_from(Request::Unlock { passphrase: None }, &me)
        .await;
    assert_eq!(error_code(resp), ErrorCode::PassphraseRequired);
}

fn audited(
    log: impl FnOnce(&Path) -> crate::audit::AuditLog,
) -> (tempfile::TempDir, crate::audit::AuditLog, Daemon) {
    let tmp = tempfile::tempdir().unwrap();
    let file = StoreFile::new(tmp.path().join(STORE_FILE)).with_test_work_factor();
    let project = parse_project(Path::new("/cfg/projects/widget.toml"), STORED).unwrap();
    let config = Config {
        default_provider: Provider::File,
        ..Config::default()
    };
    let registry = Registry::new(config, vec![project]).unwrap();
    let log = log(tmp.path());
    let d = Daemon::new(
        Box::new(move || Ok(registry.clone())),
        Arc::new(super::Providers::new()),
        file,
    )
    .with_audit(log.clone());
    (tmp, log, d)
}

fn state_log(dir: &Path) -> crate::audit::AuditLog {
    crate::audit::AuditLog::new(dir.join("state/kagebunshin/audit.jsonl"))
}

fn logged(log: &crate::audit::AuditLog) -> Vec<String> {
    let (events, unreadable) = log.read().unwrap();
    assert_eq!(unreadable, 0);
    events
        .iter()
        .map(|e| format!("{} {:?}", e.action, e.decision).to_lowercase())
        .collect()
}

/// State changes, value printing and every denial are recorded, with names
/// and never values or passphrases; an ordinary run goes to the runs log.
#[tokio::test]
async fn the_audit_log_records_changes_and_denials() {
    use crate::audit::Decision;
    let canary = Canary::new();
    let pass = Canary::new();
    let (tmp, log, d) = audited(state_log);
    let me = this_process();
    let ok = |r: &Response| assert!(!matches!(r, Response::Error(_)), "{r:?}");

    let file = StoreFile::new(tmp.path().join(STORE_FILE)).with_test_work_factor();
    init_with(&file, &d, pass.value()).await;
    ok(&d.handle(store_set("A", canary.value(), pass.value())).await);
    ok(&d.handle(Request::Lock).await);
    let resp = d.handle(run_req(None)).await;
    assert_eq!(error_code(resp), ErrorCode::Locked);
    ok(&d
        .handle(Request::Unlock {
            passphrase: Some(pw(pass.value())),
        })
        .await);
    ok(&d.handle(run_req(None)).await);
    let resp = d.handle(run_req(Some("prod"))).await;
    assert_eq!(error_code(resp), ErrorCode::SensitiveEnv);
    ok(&d.handle(get(None, "A", pass.value())).await);
    ok(&d
        .handle(Request::Reveal {
            facts: facts(None, None),
            key: key("A"),
            passphrase: pw(pass.value()),
        })
        .await);
    ok(&d
        .handle(Request::Status {
            facts: Some(facts(None, None)),
        })
        .await);

    assert_eq!(
        logged(&log),
        [
            "store set allowed",
            "lock allowed",
            "run denied",
            "unlock allowed",
            "run denied",
            "get allowed",
            "reveal allowed",
        ]
    );
    assert_eq!(logged(&log.runs()), ["run allowed"]);
    let (events, _) = log.read().unwrap();
    let ev = |action: &str, decision| {
        events
            .iter()
            .find(|e| e.action == action && e.decision == decision)
            .unwrap()
    };
    assert_eq!(ev("store set", Decision::Allowed).keys, ["widget.dev.A"]);
    let refused = ev("run", Decision::Denied);
    assert!(refused.reason.is_some());
    let sensitive = events.iter().filter(|e| e.action == "run").nth(1).unwrap();
    assert_eq!(
        (
            sensitive.project.as_ref().unwrap().as_str(),
            sensitive.env.as_ref().unwrap().as_str()
        ),
        ("widget", "prod")
    );
    let got = ev("get", Decision::Allowed);
    assert_eq!(got.keys, ["A"]);
    assert_eq!(
        (
            got.project.as_ref().unwrap().as_str(),
            got.env.as_ref().unwrap().as_str()
        ),
        ("widget", "dev")
    );
    assert_eq!((got.pid, got.uid), (me.pid, me.uid));
    assert_eq!(got.start_time, me.start_time.0);
    let text = std::fs::read_to_string(log.path()).unwrap();
    assert_no_canary(&canary, &text);
    assert_no_canary(&pass, &text);
}

fn add_mark_env(env: &str) -> Request {
    Request::AddMark {
        target: MarkTarget::Env {
            project: "widget".parse().unwrap(),
            env: env.parse().unwrap(),
        },
    }
}

fn marked(r: Response) {
    let Response::Store { change, locked } = r else {
        panic!("{r:?}")
    };
    assert_eq!((change, locked), (Change::Marked, false));
}

/// An agent marks an environment or a store key with no passphrase: the
/// mark holds at once, waits beside the store, which only a passphrase
/// writes, and is in it after the next unlock. Each is in the audit log
/// with who asked.
#[tokio::test]
async fn a_mark_added_with_no_passphrase_holds_and_reaches_the_store() {
    use crate::audit::Decision;
    let (tmp, log, d) = audited(state_log);
    let file = StoreFile::new(tmp.path().join(STORE_FILE)).with_test_work_factor();
    let pass = || Passphrase::new("pw".into());
    let dev = || "widget.dev".parse().unwrap();
    init(&file, &d).await;
    d.handle(store_set("A", "v", "pw")).await;
    let r = d.handle(run_req(None)).await;
    assert!(matches!(r, Response::RunEnv(_)), "{r:?}");

    // A key that is not set has no mark to take, and nothing is written.
    let no_key = Request::AddMark {
        target: MarkTarget::Key {
            section: dev(),
            key: key("NOPE"),
        },
    };
    assert_eq!(error_code(d.handle(no_key).await), ErrorCode::Store);
    assert!(!file.marks_wait());

    marked(
        d.handle(Request::AddMark {
            target: MarkTarget::Key {
                section: dev(),
                key: key("A"),
            },
        })
        .await,
    );
    let status = d.status(Some(facts(None, None))).await.unwrap();
    assert!(status.env.unwrap().keys.iter().all(|k| k.sensitive));

    marked(d.handle(add_mark_env("dev")).await);
    let r = d.handle(run_req(None)).await;
    assert_eq!(error_code(r), ErrorCode::SensitiveEnv);
    let envs = |st: &Store| -> Vec<String> { st.marked_envs().map(ToString::to_string).collect() };
    // Waiting: the file is as the last passphrase left it.
    assert!(file.marks_wait());
    let st = file.open(&pass()).unwrap();
    assert_eq!(envs(&st), ["widget.prod"]);
    assert!(!st.is_sensitive(&dev(), &key("A")));

    // Marked already: nothing new to wait.
    let list = std::fs::read(file.marks_path()).unwrap();
    marked(d.handle(add_mark_env("dev")).await);
    assert_eq!(std::fs::read(file.marks_path()).unwrap(), list);

    // An environment the project does not have gets no mark: only a human
    // could remove it.
    let r = d.handle(add_mark_env("nope")).await;
    assert_eq!(error_code(r), ErrorCode::Config);
    assert_eq!(d.store_list().unwrap().sensitive_envs.len(), 2);

    // Locked, nothing is marked; the unlock moves the list into the store.
    d.lock();
    let r = d.handle(add_mark_env("local")).await;
    assert_eq!(error_code(r), ErrorCode::Locked);
    d.unlock(Some(pass())).await.unwrap();
    assert!(!file.marks_wait());
    let st = file.open(&pass()).unwrap();
    assert_eq!(envs(&st), ["widget.dev", "widget.prod"]);
    assert!(st.is_sensitive(&dev(), &key("A")));
    let r = d.handle(run_req(None)).await;
    assert_eq!(error_code(r), ErrorCode::SensitiveEnv);

    let all = logged(&log);
    let marks: Vec<&str> = (all.iter().map(String::as_str))
        .filter(|l| l.starts_with("add mark"))
        .collect();
    assert_eq!(
        marks,
        [
            "add mark key denied",
            "add mark key allowed",
            "add mark env allowed",
            "add mark env allowed",
            "add mark env denied",
            "add mark env denied",
        ]
    );
    let (events, _) = log.read().unwrap();
    let me = this_process();
    let ev = events
        .iter()
        .find(|e| e.action == "add mark env" && e.decision == Decision::Allowed)
        .unwrap();
    assert_eq!(
        (
            ev.project.as_ref().unwrap().as_str(),
            ev.env.as_ref().unwrap().as_str()
        ),
        ("widget", "dev")
    );
    assert_eq!((ev.pid, ev.uid), (me.pid, me.uid));
    let ev = events
        .iter()
        .find(|e| e.action == "add mark key" && e.decision == Decision::Allowed)
        .unwrap();
    assert_eq!(ev.keys, ["widget.dev.A"]);
}

/// An environment named production outright that waits for a decision is
/// the caller's to mark, and the refusal and the warning say how; one that
/// only may be production is the human's to decide. Marked, it is refused
/// as any marked one.
#[tokio::test]
async fn an_env_named_production_is_refused_with_the_command_that_marks_it() {
    use crate::ipc::protocol::Who;
    let (_tmp, file, d) = stored_daemon();
    let pass = Passphrase::new("pw".into());
    file.create(&pass).unwrap();
    d.unlock(Some(pass)).await.unwrap();
    let refused = |r: Response| match r {
        Response::Error(e) => {
            assert_eq!(e.code, ErrorCode::SensitiveEnv, "{e:?}");
            e
        }
        other => panic!("{other:?}"),
    };

    let e = refused(d.handle(run_req(Some("prod"))).await);
    assert_eq!(e.who, Some(Who::Agent), "{e:?}");
    let hint = e.hint.unwrap();
    assert!(
        hint.contains("`kagebunshin mark env widget prod`"),
        "{hint}"
    );
    let status = d.status(Some(facts(Some("prod"), None))).await.unwrap();
    let warnings = status.env.unwrap().warnings;
    assert!(
        warnings.iter().any(|w| {
            w.contains("`kagebunshin mark env widget prod`, since it is production by its name")
                && w.ends_with(super::resolve::ACKNOWLEDGE_HINT)
        }),
        "{warnings:?}"
    );

    let e = refused(d.handle(run_req(Some("rc"))).await);
    assert_eq!(e.who, Some(Who::Human), "{e:?}");
    assert!(!e.hint.unwrap().contains("kagebunshin mark"));

    marked(d.handle(add_mark_env("prod")).await);
    let e = refused(d.handle(run_req(Some("prod"))).await);
    assert!(e.message.contains("marked sensitive"), "{e:?}");
    assert!(!e.hint.unwrap_or_default().contains("kagebunshin mark"));
}

/// With no store there is nothing to mark in, and nothing is left waiting
/// for one.
#[tokio::test]
async fn a_mark_needs_a_store() {
    let (_tmp, file, d) = stored_daemon();
    d.unlock(None).await.unwrap();
    let r = d.handle(add_mark_env("dev")).await;
    assert_eq!(error_code(r), ErrorCode::NoStore);
    assert!(!file.marks_wait());
}

/// A mark added with no passphrase never undoes what a human decided with
/// one: an environment acknowledged as not production stays so.
#[tokio::test]
async fn a_mark_with_no_passphrase_leaves_an_acknowledged_env() {
    let (_tmp, file, d) = stored_daemon();
    init(&file, &d).await;
    let ack = Request::AcknowledgeEnv {
        project: "widget".parse().unwrap(),
        env: "rc".parse().unwrap(),
        acknowledged: true,
        unmark: Vec::new(),
        passphrase: pw("pw"),
    };
    assert!(matches!(d.handle(ack).await, Response::Store { .. }));

    let Response::Error(e) = d.handle(add_mark_env("rc")).await else {
        panic!("marked")
    };
    assert_eq!(e.code, ErrorCode::PermissionDenied);
    assert!(
        e.message
            .contains("environment rc of project widget is acknowledged as not production")
            && e.message.contains("a human decided that"),
        "{e:?}"
    );
    let list = d.store_list().unwrap();
    assert_eq!(list.acknowledged_envs.len(), 1);
    assert_eq!(list.sensitive_envs.len(), 1, "prod only");
    assert!(!file.marks_wait());
}

/// An environment marked with no passphrase is marked as a human marks
/// one: with what only its sources read, leaving what an open environment
/// reads too. The same holds once the marks are in the store.
#[tokio::test]
async fn a_mark_with_no_passphrase_marks_an_envs_sources_as_a_human_does() {
    let c = Canary::new();
    let (fake, stored) = live_sources(&c);
    let text = format!("{LIVE}{COPY}");
    let (tmp, d) = marked_daemon(&text, &fake, stored).await;
    let store = StoreFile::new(tmp.path().join(STORE_FILE)).with_test_work_factor();
    let expected = [
        ("CFG".to_owned(), false),
        ("DB".to_owned(), false),
        ("LATER".to_owned(), true),
        ("TOKEN".to_owned(), false),
    ];

    marked(d.handle(add_mark_env("live")).await);
    assert_eq!(copy_keys(&d).await, expected);
    let r = d.handle(run_req(Some("live"))).await;
    assert_clean(&c, &r);
    assert_eq!(error_code(r), ErrorCode::SensitiveEnv);
    // Names only wait beside the store.
    let list = std::fs::read_to_string(store.marks_path()).unwrap();
    assert_no_canary(&c, &list);
    assert!(list.contains("widget/live/"), "{list}");

    d.lock();
    d.unlock(Some(Passphrase::new("pw".into()))).await.unwrap();
    assert!(!store.marks_wait());
    assert_eq!(copy_keys(&d).await, expected);

    // One secret, wherever it is read.
    marked(
        d.handle(Request::AddMark {
            target: MarkTarget::Secret {
                secret: sm("widget/shared/db"),
            },
        })
        .await,
    );
    let keys = copy_keys(&d).await;
    assert!(keys.contains(&("DB".to_owned(), true)), "{keys:?}");
    // A store section is marked key by key.
    let r = d
        .handle(Request::AddMark {
            target: MarkTarget::Secret {
                secret: file("shared.cfg"),
            },
        })
        .await;
    assert_eq!(error_code(r), ErrorCode::Store);
}

/// An ordinary run is recorded in the runs log, with its keys and program
/// and nothing of the audit log's, and goes ahead when it cannot be.
#[tokio::test]
async fn ordinary_runs_go_to_the_runs_log() {
    async fn setup(tmp: &tempfile::TempDir, d: &Daemon) {
        let pass = "audit test";
        let file = StoreFile::new(tmp.path().join(STORE_FILE)).with_test_work_factor();
        init_with(&file, d, pass).await;
        d.handle(store_set("A", "x", pass)).await;
    }
    let run = || Request::RunEnv {
        facts: facts(None, None),
        program: Some("npm".into()),
        command: Vec::new(),
    };

    let (tmp, log, d) = audited(state_log);
    setup(&tmp, &d).await;
    let before = logged(&log);
    let Response::RunEnv(reply) = d.handle(run()).await else {
        panic!()
    };
    assert_eq!(reply.vars.len(), 1);
    assert_eq!(logged(&log), before);
    let (events, unreadable) = log.runs().read().unwrap();
    assert_eq!((events.len(), unreadable), (1, 0));
    let event = &events[0];
    assert_eq!(event.action, "run");
    assert_eq!(event.decision, crate::audit::Decision::Allowed);
    assert_eq!(
        event.project.as_ref().map(ToString::to_string).as_deref(),
        Some("widget")
    );
    assert_eq!(
        event.env.as_ref().map(ToString::to_string).as_deref(),
        Some("dev")
    );
    assert_eq!(event.program.as_deref(), Some("npm"));
    assert_eq!(event.keys, ["A"]);

    // Logs that cannot be written: under a regular file. The run goes
    // ahead all the same; a value that needs the audit log does not.
    let blocked = |dir: &Path| {
        std::fs::write(dir.join("state"), "").unwrap();
        state_log(dir)
    };
    let (tmp, _, d) = audited(blocked);
    setup(&tmp, &d).await;
    assert!(matches!(d.handle(run()).await, Response::RunEnv(_)));
    let resp = d.handle(get(None, "A", "audit test")).await;
    assert_eq!(error_code(resp), ErrorCode::Internal);
}

/// Proton keys through the real providers and a fake `pass-cli`: the token
/// is saved behind the passphrase, and a key or an environment marked
/// sensitive is refused like any other.
#[tokio::test]
async fn proton_keys_need_a_saved_token_and_obey_marks() {
    let c = Canary::new();
    let tmp = tempfile::tempdir().unwrap();
    let pass_dir = tmp.path().join("pass-cli");
    std::fs::create_dir(&pass_dir).unwrap();
    let fake = crate::test_support::FakePassCli::new(&pass_dir, &format!("pst_{}", c.value()));
    fake.vault("widget", "S1")
        .vault("global", "S2")
        .api_key("S1", "i1", "Stripe", "API key", "STRIPE_KEY", c.value())
        .api_key("S1", "i2", "Database", "API key", "DB_URL", c.value())
        .api_key("S2", "g1", "OpenAI", "API key", "OPENAI_KEY", c.value());
    let text = r#"
schema = 1
remotes = ["git@github.com:acme/widget.git"]

[envs.dev]
[[envs.dev.sources]]
provider = "proton"
prefix = "widget/"
[[envs.dev.sources]]
provider = "proton"
secret = "global/OPENAI_KEY"
key = "OPENAI_API_KEY"

[envs.qa]
[[envs.qa.sources]]
provider = "proton"
secret = "widget/DB_URL"
"#;
    let file = StoreFile::new(tmp.path().join(STORE_FILE)).with_test_work_factor();
    let pass = Passphrase::new("pw".into());
    file.create(&pass).unwrap();
    let project = parse_project(Path::new("/cfg/projects/widget.toml"), text).unwrap();
    let registry = Registry::new(Config::default(), vec![project]).unwrap();
    let providers = super::Providers::new().with_proton(fake.cli());
    let d = Daemon::new(
        Box::new(move || Ok(registry.clone())),
        Arc::new(providers),
        file,
    );
    d.unlock(Some(pass)).await.unwrap();

    // No token yet: the environment says to connect.
    let err = super::broker::wire_error(&d.run_env(&facts(None, None)).await.unwrap_err());
    assert_eq!(err.code, ErrorCode::SourceFailed, "{err:?}");
    assert!(err.hint.unwrap_or_default().contains("connect proton"));

    let connect = |token: &str, pass: &str| Request::ProtonConnect {
        token: WireSecret::new(token.into()),
        expires: Some(2_000_000_000),
        passphrase: pw(pass),
    };
    for p in ["wrong", c.value()] {
        let r = d.handle(connect(&fake.token, p)).await;
        assert_clean(&c, &r);
        assert_eq!(error_code(r), ErrorCode::WrongPassphrase);
    }
    let r = d.handle(connect(&fake.token, "pw")).await;
    assert_eq!(
        r,
        Response::ProtonConnected {
            change: Change::Added,
            locked: false,
            vaults: 2,
        }
    );

    let run = d.run_env(&facts(None, None)).await.unwrap();
    let keys: Vec<&str> = run.vars.iter().map(|v| v.key.as_str()).collect();
    assert_eq!(keys, ["DB_URL", "OPENAI_API_KEY", "STRIPE_KEY"]);
    assert!(run.vars.iter().all(|v| v.value.expose() == c.value()));
    assert!(!fake.calls().contains("token-in-env"), "{}", fake.calls());

    // Each is the item its ids say, and shown by the name a project file
    // selects it by.
    let status = d.status(Some(facts(None, None))).await.unwrap();
    let origins: Vec<(String, String)> = (status.env.unwrap().keys.iter())
        .map(|k| (k.origin.id(), k.origin.to_string()))
        .collect();
    let pair = |id: &str, shown: &str| (id.to_owned(), shown.to_owned());
    assert_eq!(
        origins,
        [
            pair("proton:S1/i2", "proton:widget/DB_URL"),
            pair("proton:S2/g1", "proton:global/OPENAI_KEY"),
            pair("proton:S1/i1", "proton:widget/STRIPE_KEY"),
        ]
    );

    // A Proton key marked sensitive, by its stable id: every environment
    // that would hand it out refuses, naming the key and no value.
    let stripe = Origin::new(Provider::Proton, "S1/i1");
    let r = d
        .handle(Request::MarkSecret {
            secret: stripe.clone(),
            sensitive: true,
            passphrase: pw("pw"),
        })
        .await;
    assert!(matches!(r, Response::Store { .. }), "{r:?}");
    let err = d.run_env(&facts(None, None)).await.unwrap_err();
    assert_clean_err(&c, &err);
    assert_eq!(
        super::broker::wire_error(&err).code,
        ErrorCode::SensitiveEnv
    );
    assert!(err.to_string().contains("STRIPE_KEY"), "{err}");
    assert!(!err.to_string().contains("S1/i1"), "{err}");
    assert_eq!(
        error_code(d.handle(get(None, "STRIPE_KEY", "pw")).await),
        ErrorCode::SensitiveEnv
    );
    // qa does not read it.
    assert_eq!(
        d.run_env(&facts(Some("qa"), None))
            .await
            .unwrap()
            .vars
            .len(),
        1
    );

    // A whole environment marked sensitive.
    let r = d
        .handle(Request::MarkEnv {
            project: "widget".parse().unwrap(),
            env: "qa".parse().unwrap(),
            sensitive: true,
            also: Vec::new(),
            passphrase: pw("pw"),
        })
        .await;
    assert!(matches!(r, Response::Store { .. }), "{r:?}");
    let err = d.run_env(&facts(Some("qa"), None)).await.unwrap_err();
    assert_eq!(
        super::broker::wire_error(&err).code,
        ErrorCode::SensitiveEnv
    );

    // A second token replaces the first.
    let r = d.handle(connect(&fake.token, "pw")).await;
    assert!(
        matches!(
            r,
            Response::ProtonConnected {
                change: Change::Replaced,
                ..
            }
        ),
        "{r:?}"
    );

    // Marked with no passphrase, by the name a project file gives it: the
    // mark is kept under the item's ids, where it holds. A name Proton does
    // not have is refused and marks nothing.
    let add = |name: &str| Request::AddMark {
        target: MarkTarget::Secret {
            secret: Origin::new(Provider::Proton, name),
        },
    };
    let secrets = || d.store_list().unwrap().sensitive_secrets;
    let r = d.handle(add("widget/NOPE")).await;
    assert_eq!(error_code(r), ErrorCode::SourceFailed);
    assert_eq!(secrets(), std::slice::from_ref(&stripe));
    marked(d.handle(add("global/OPENAI_KEY")).await);
    let openai = Origin::new(Provider::Proton, "S2/g1");
    assert_eq!(secrets(), [stripe, openai]);
    let status = d.status(Some(facts(None, None))).await.unwrap();
    let sensitive: Vec<&str> = (status.env.as_ref().unwrap().keys.iter())
        .filter(|k| k.sensitive)
        .map(|k| k.key.as_str())
        .collect();
    assert_eq!(sensitive, ["OPENAI_API_KEY", "STRIPE_KEY"]);
}

/// A daemon over a store with passphrase `pw` and one environment that
/// reads Proton, running `bin` (the fake, or a wrapper of it) with the
/// fake's session directory.
fn proton_daemon(tmp: &Path, fake: &crate::test_support::FakePassCli, bin: PathBuf) -> Daemon {
    let text = r#"
schema = 1
remotes = ["git@github.com:acme/widget.git"]
[[envs.dev.sources]]
provider = "proton"
prefix = "widget/"
"#;
    let file = StoreFile::new(tmp.join(STORE_FILE)).with_test_work_factor();
    file.create(&Passphrase::new("pw".into())).unwrap();
    let project = parse_project(Path::new("/cfg/projects/widget.toml"), text).unwrap();
    let registry = Registry::new(Config::default(), vec![project]).unwrap();
    let cli = crate::source::proton::PassCli { bin, ..fake.cli() };
    Daemon::new(
        Box::new(move || Ok(registry.clone())),
        Arc::new(super::Providers::new().with_proton(cli)),
        file,
    )
}

fn proton_connect(token: &str, pass: &str) -> Request {
    Request::ProtonConnect {
        token: WireSecret::new(token.into()),
        expires: None,
        passphrase: pw(pass),
    }
}

/// `connect proton` logs in beside the live session, then swaps it in and
/// saves the token: a wrong passphrase or a refused token leaves
/// the saved token and the session `pass-cli` is using as they were.
#[tokio::test]
async fn a_refused_connect_leaves_the_token_and_the_session_alone() {
    let c = Canary::new();
    let tmp = tempfile::tempdir().unwrap();
    let pass_dir = tmp.path().join("pass-cli");
    std::fs::create_dir(&pass_dir).unwrap();
    let fake = crate::test_support::FakePassCli::new(&pass_dir, &format!("pst_{}", c.value()));
    fake.vault("widget", "S1")
        .api_key("S1", "i1", "Stripe", "API key", "STRIPE_KEY", c.value());
    let d = proton_daemon(tmp.path(), &fake, fake.bin());
    let live = fake.session_dir();
    let staging = pass_dir.join("session.staging");
    let old = pass_dir.join("session.old");
    let saved = || {
        let st = StoreFile::new(tmp.path().join(STORE_FILE))
            .open(&Passphrase::new("pw".into()))
            .unwrap();
        st.proton_token().map(|t| t.token.expose().to_owned())
    };

    // The first connect logs in in the staging directory, then swaps it in.
    let r = d.handle(proton_connect(&fake.token, "pw")).await;
    assert!(
        matches!(r, Response::ProtonConnected { vaults: 1, .. }),
        "{r:?}"
    );
    assert_eq!(fake.env(), format!("{} fs", staging.display()));
    assert!(live.join("session").exists());
    assert!(!staging.exists() && !old.exists());
    assert_eq!(saved(), Some(fake.token.clone()));
    d.unlock(Some(Passphrase::new("pw".into()))).await.unwrap();
    let run = d.run_env(&facts(None, None)).await.unwrap();
    assert_eq!(run.vars.len(), 1);
    assert_eq!(fake.env(), format!("{} fs", live.display()));
    let logins = fake.logins();

    // The right token with the wrong passphrase: pass-cli never runs.
    let calls = fake.calls();
    let r = d.handle(proton_connect(&fake.token, "nope")).await;
    assert_clean(&c, &r);
    assert_eq!(error_code(r), ErrorCode::WrongPassphrase);
    assert_eq!(fake.calls(), calls, "pass-cli ran");

    // A token Proton refuses: tried in staging, which is then removed.
    let wrong = format!("pst_wrong{}", c.value());
    let r = d.handle(proton_connect(&wrong, "pw")).await;
    assert_clean(&c, &r);
    let Response::Error(e) = r else {
        panic!("{r:?}")
    };
    assert_eq!(e.code, ErrorCode::SourceFailed);
    assert_eq!(e.message, crate::source::proton::REFUSED);
    assert!(e.hint.unwrap().contains("check the token"));
    assert_eq!(fake.env(), format!("{} fs", staging.display()));
    assert!(!staging.exists() && !old.exists());

    // Neither touched the saved token or the live session: a fresh fetch
    // still reads through it, without logging in again.
    assert_eq!(saved(), Some(fake.token.clone()));
    assert!(live.join("session").exists());
    d.handle(Request::Sync {
        project: None,
        env: None,
    })
    .await;
    let run = d.run_env(&facts(None, None)).await.unwrap();
    assert_eq!(run.vars.len(), 1);
    assert!(run.vars.iter().all(|v| v.value.expose() == c.value()));
    assert_eq!(fake.logins(), logins, "logged in again");
    assert!(!fake.calls().contains("token-in-env"), "{}", fake.calls());
}

/// A swap that fails moving the new session in, or a token save that fails
/// after it, puts the previous session back and returns an error: the
/// saved token and the live session still match, and nothing is left in
/// staging or aside. What a failed connect leaves, the next one clears.
#[tokio::test]
async fn a_failed_swap_or_save_puts_the_previous_session_back() {
    use std::os::unix::fs::PermissionsExt;
    let c = Canary::new();
    let tmp = tempfile::tempdir().unwrap();
    let pass_dir = tmp.path().join("pass-cli");
    std::fs::create_dir(&pass_dir).unwrap();
    let fake = crate::test_support::FakePassCli::new(&pass_dir, &format!("pst_{}", c.value()));
    fake.vault("widget", "S1")
        .api_key("S1", "i1", "Stripe", "API key", "STRIPE_KEY", c.value());
    let d = proton_daemon(tmp.path(), &fake, fake.bin());
    let live = fake.session_dir();
    let staging = pass_dir.join("session.staging");
    let old = pass_dir.join("session.old");
    // Which connect saved the token, by its expiry.
    let expires = || {
        StoreFile::new(tmp.path().join(STORE_FILE))
            .open(&Passphrase::new("pw".into()))
            .unwrap()
            .proton_token()
            .map(|t| t.expires)
    };
    let connect = |expires: u64| Request::ProtonConnect {
        token: WireSecret::new(fake.token.clone()),
        expires: Some(expires),
        passphrase: pw("pw"),
    };
    let r = d.handle(connect(1)).await;
    assert!(matches!(r, Response::ProtonConnected { .. }), "{r:?}");
    // Marks the session in use, to tell it from a new one.
    let marker = live.join("marker");
    std::fs::write(&marker, "").unwrap();
    let previous_is_back = || {
        assert!(marker.exists(), "the previous session is gone");
        assert!(!staging.exists() && !old.exists());
    };

    // Early: the new session cannot be moved in.
    crate::source::proton::faults::fail_rename_onto(&live);
    let r = d.handle(connect(2)).await;
    assert_clean(&c, &r);
    let Response::Error(e) = r else {
        panic!("{r:?}")
    };
    assert_eq!(e.code, ErrorCode::SourceFailed);
    assert!(
        e.message.contains("previous session is back"),
        "{}",
        e.message
    );
    previous_is_back();
    assert_eq!(expires(), Some(Some(1)));

    // Late: moved in, but the token cannot be saved.
    let perms =
        |mode| std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(mode)).unwrap();
    perms(0o555);
    let r = d.handle(connect(3)).await;
    perms(0o755);
    assert_clean(&c, &r);
    assert_eq!(error_code(r), ErrorCode::Store);
    previous_is_back();
    assert_eq!(expires(), Some(Some(1)));

    // Still reads through the previous session.
    d.unlock(Some(Passphrase::new("pw".into()))).await.unwrap();
    let run = d.run_env(&facts(None, None)).await.unwrap();
    assert_eq!(run.vars.len(), 1);

    // An old session with no live one is put back by the next connect,
    // here one Proton refuses; leftover staging is removed.
    std::fs::rename(&live, &old).unwrap();
    std::fs::create_dir(&staging).unwrap();
    let r = d
        .handle(proton_connect(&format!("pst_wrong{}", c.value()), "pw"))
        .await;
    assert!(matches!(r, Response::Error(_)), "{r:?}");
    previous_is_back();

    // With both, the live session is the saved token's: it stays, also
    // when Proton refuses the new token, and the old one goes.
    std::fs::create_dir(&old).unwrap();
    std::fs::create_dir(&staging).unwrap();
    let logins = fake.logins();
    let r = d
        .handle(proton_connect(&format!("pst_wrong{}", c.value()), "pw"))
        .await;
    assert!(matches!(r, Response::Error(_)), "{r:?}");
    previous_is_back();
    assert!(live.join("session").exists());
    d.handle(Request::Sync {
        project: None,
        env: None,
    })
    .await;
    let run = d.run_env(&facts(None, None)).await.unwrap();
    assert_eq!(run.vars.len(), 1);
    assert_eq!(fake.logins(), logins, "logged in again");

    // And the next good connect swaps in cleanly.
    std::fs::create_dir(&old).unwrap();
    let r = d.handle(connect(4)).await;
    assert!(matches!(r, Response::ProtonConnected { .. }), "{r:?}");
    assert!(live.join("session").exists() && !marker.exists());
    assert!(!staging.exists() && !old.exists());
    assert_eq!(expires(), Some(Some(4)));
}

/// Connects and fetches through the daemon take turns: no two `pass-cli`
/// calls overlap, and a connect's staging and swap never run under a
/// fetch.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proton_connects_and_fetches_never_overlap() {
    use std::os::unix::fs::PermissionsExt;
    let c = Canary::new();
    let tmp = tempfile::tempdir().unwrap();
    let pass_dir = tmp.path().join("pass-cli");
    std::fs::create_dir(&pass_dir).unwrap();
    let fake = crate::test_support::FakePassCli::new(&pass_dir, &format!("pst_{}", c.value()));
    fake.vault("widget", "S1")
        .api_key("S1", "i1", "Stripe", "API key", "STRIPE_KEY", c.value());
    // Logs when each call starts and ends, slowly enough to overlap.
    let log = tmp.path().join("spans");
    let wrapper = tmp.path().join("slow-pass-cli");
    std::fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\necho \"begin $1\" >> '{log}'\nsleep 0.05\n'{bin}' \"$@\"\nrc=$?\necho \"end $1\" >> '{log}'\nexit $rc\n",
            log = log.display(),
            bin = fake.bin().display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).unwrap();
    let d = proton_daemon(tmp.path(), &fake, wrapper);
    let r = d.handle(proton_connect(&fake.token, "pw")).await;
    assert!(matches!(r, Response::ProtonConnected { .. }), "{r:?}");
    d.unlock(Some(Passphrase::new("pw".into()))).await.unwrap();

    let mut tasks = Vec::new();
    for i in 0..6 {
        let d = d.clone();
        let token = fake.token.clone();
        tasks.push(tokio::spawn(async move {
            if i % 2 == 0 {
                let r = d.handle(proton_connect(&token, "pw")).await;
                assert!(matches!(r, Response::ProtonConnected { .. }), "{r:?}");
            } else {
                d.handle(Request::Sync {
                    project: None,
                    env: None,
                })
                .await;
                d.run_env(&facts(None, None)).await.unwrap();
            }
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    let spans = std::fs::read_to_string(&log).unwrap();
    let lines: Vec<&str> = spans.lines().collect();
    assert!(lines.len() >= 12, "{spans}");
    for pair in lines.chunks(2) {
        let [begin, end] = pair else {
            panic!("{spans}")
        };
        assert_eq!(
            begin.strip_prefix("begin "),
            end.strip_prefix("end "),
            "calls overlap:\n{spans}"
        );
    }
    assert!(fake.session_dir().join("session").exists());
    assert!(!pass_dir.join("session.staging").exists());
    assert!(!pass_dir.join("session.old").exists());
}

/// `list --keys` over fake AWS: the key names of each JSON secret and
/// which are plain strings, never a value; secrets marked sensitive, that
/// look like production, or read with a production-looking profile are not
/// read, nor any while locked; the lookup is audited with the secrets read.
#[tokio::test]
async fn list_keys_reads_key_names_only() {
    use crate::source::aws_sm::AwsSettings;

    let c = Canary::new();
    let tmp = tempfile::tempdir().unwrap();
    let json = format!(r#"{{"DB_URL":"{0}","API_KEY":"{0}"}}"#, c.value());
    let mut aws = FakeAws::default();
    let secrets = account(&[
        ("acme/dev/api", json.clone()),
        ("acme/dev/token", c.value().to_owned()),
        ("acme/dev/marked", json.clone()),
        ("acme/prod/api", json.clone()),
    ]);
    aws.accounts.insert(String::new(), secrets.clone());
    aws.accounts.insert("acme-prod".into(), secrets);
    let aws = Arc::new(aws);
    let file = StoreFile::new(tmp.path().join(STORE_FILE)).with_test_work_factor();
    file.create(&Passphrase::new("pw".into())).unwrap();
    let registry = Registry::new(Config::default(), Vec::new()).unwrap();
    let log = state_log(tmp.path());
    let d = Daemon::new(
        Box::new(move || Ok(registry.clone())),
        Arc::new(super::Providers::with_aws(aws.clone())),
        file,
    )
    .with_audit(log.clone());
    let list = |profile: Option<&str>, search: Option<&str>| Request::List {
        provider: Some(Provider::AwsSm),
        prefix: "acme/".into(),
        search: search.map(Into::into),
        aws: AwsSettings {
            profile: profile.map(|p| Profile::try_from(p.to_owned()).unwrap()),
            region: None,
        },
        keys: true,
    };
    let listed = |r: Response| match r {
        Response::Listed { items, read, .. } => (items, read),
        r => panic!("{r:?}"),
    };

    // Locked: the marks are not known, so nothing is read.
    let (items, read) = listed(d.handle(list(None, None)).await);
    assert!(read.is_empty());
    assert!(
        items
            .iter()
            .all(|l| l.unread.as_deref().unwrap().contains("locked"))
    );
    assert!(aws.gets.lock().unwrap().is_empty());

    d.unlock(Some(Passphrase::new("pw".into()))).await.unwrap();
    d.handle(Request::MarkSecret {
        secret: Origin::new(Provider::AwsSm, "acme/dev/marked"),
        sensitive: true,
        passphrase: pw("pw"),
    })
    .await;
    let r = d.handle(list(None, None)).await;
    assert_clean(&c, &r);
    let (items, read) = listed(r);
    assert_eq!(read, ["acme/dev/api", "acme/dev/token"]);
    assert_eq!(*aws.gets.lock().unwrap(), read);
    let by = |n: &str| items.iter().find(|l| l.name == n).unwrap().clone();
    assert_eq!(by("acme/dev/api").keys, [key("API_KEY"), key("DB_URL")]);
    let token = by("acme/dev/token");
    assert!(token.plain && token.keys.is_empty() && token.unread.is_none());
    assert!(
        by("acme/dev/marked")
            .unread
            .unwrap()
            .contains("marked sensitive")
    );
    assert!(by("acme/prod/api").unread.unwrap().contains("production"));

    // Search matches the key names it read.
    let (items, _) = listed(d.handle(list(None, Some("db_url"))).await);
    let names: Vec<_> = items.iter().map(|l| l.name.as_str()).collect();
    assert_eq!(names, ["acme/dev/api"]);

    // A production-looking profile: nothing is read.
    aws.gets.lock().unwrap().clear();
    let (items, read) = listed(d.handle(list(Some("acme-prod"), None)).await);
    assert!(read.is_empty() && aws.gets.lock().unwrap().is_empty());
    assert!(
        items
            .iter()
            .all(|l| l.unread.as_deref().unwrap().contains("acme-prod"))
    );

    // Each lookup is recorded with the secrets read, never a value.
    let (events, _) = log.read().unwrap();
    let lookups: Vec<_> = events.iter().filter(|e| e.action == "list keys").collect();
    assert_eq!(lookups.len(), 4);
    assert_eq!(lookups[1].keys, ["acme/dev/api", "acme/dev/token"]);
    let text = std::fs::read_to_string(log.path()).unwrap();
    assert_no_canary(&c, &text);
}

/// Asked about no one environment, the daemon checks what every project
/// reads: each AWS profile sources name, although `connect aws` set no
/// default, and the local store, which waits for unlock.
#[tokio::test]
async fn providers_of_no_environment_are_those_every_project_reads() {
    use crate::source::{Health, ProviderStatus};

    let tmp = tempfile::tempdir().unwrap();
    let mut aws = FakeAws::default();
    aws.accounts.insert("widget-dev".into(), BTreeMap::new());
    aws.accounts.insert("old".into(), BTreeMap::new());
    aws.expired.insert("old".into());
    let project = |name: &str, profile: &str| {
        let text = format!(
            r#"
schema = 1
remotes = ["git@github.com:acme/{name}.git"]

[[envs.dev.sources]]
provider = "aws_sm"
prefix = "{name}/dev/"
profile = "{profile}"
[[envs.dev.sources]]
provider = "file"

[[envs.prod.sources]]
provider = "aws_sm"
prefix = "{name}/prod/"
profile = "{profile}"
"#
        );
        parse_project(Path::new(&format!("/cfg/projects/{name}.toml")), &text).unwrap()
    };
    let projects = vec![project("widget", "widget-dev"), project("gadget", "old")];
    let registry = Registry::new(Config::default(), projects).unwrap();
    let file = StoreFile::new(tmp.path().join(STORE_FILE)).with_test_work_factor();
    let pass = Passphrase::new("pw".into());
    file.create(&pass).unwrap();
    let d = Daemon::new(
        Box::new(move || Ok(registry.clone())),
        Arc::new(super::Providers::with_aws(Arc::new(aws))),
        file,
    );

    let of = |health: &[ProviderStatus], detail: &str| {
        let found: Vec<_> = health.iter().filter(|p| p.detail == detail).collect();
        assert_eq!(found.len(), 1, "{detail}: {health:?}");
        found[0].health.clone()
    };
    // The CLI, outside a project, asks about what is connected alone.
    assert_eq!(d.providers(None, false).await, []);
    let health = d.providers(None, true).await;
    assert_eq!(
        health.len(),
        3,
        "each profile once, and the store: {health:?}"
    );
    assert_eq!(of(&health, "profile widget-dev"), Health::Ok);
    assert!(
        matches!(of(&health, "profile old"), Health::NeedsLogin { .. }),
        "{health:?}"
    );
    let store = health.iter().find(|p| p.provider == Provider::File);
    assert_eq!(store.map(|p| &p.health), Some(&Health::Locked));

    d.unlock(Some(pass)).await.unwrap();
    let health = d.providers(None, true).await;
    let store = health.iter().find(|p| p.provider == Provider::File);
    assert_eq!(store.map(|p| &p.health), Some(&Health::Ok), "{health:?}");
}

/// `list`, `search` and provider health over fake AWS, the local store and
/// a fake `pass-cli`: names, ids and keys, never a value; providers that
/// read the store wait for unlock.
#[tokio::test]
async fn list_search_and_providers_span_every_provider() {
    use crate::source::Health;
    use crate::source::aws_sm::AwsSettings;

    let c = Canary::new();
    let tmp = tempfile::tempdir().unwrap();
    let pass_dir = tmp.path().join("pass-cli");
    std::fs::create_dir(&pass_dir).unwrap();
    let fake = crate::test_support::FakePassCli::new(&pass_dir, &format!("pst_{}", c.value()));
    fake.vault("widget", "S1")
        .vault("global", "S2")
        .api_key("S1", "i1", "Stripe", "API key", "STRIPE_KEY", c.value())
        .api_key("S2", "g1", "OpenAI", "API key", "OPENAI_KEY", c.value());
    let mut aws = FakeAws::default();
    let json = format!(r#"{{"STRIPE_SECRET":"{}"}}"#, c.value());
    aws.accounts.insert(
        "widget-dev".into(),
        account(&[("widget/dev/stripe", json.clone()), ("widget/dev/db", json)]),
    );
    aws.accounts.insert("old".into(), BTreeMap::new());
    aws.expired.insert("old".into());
    let aws = Arc::new(aws);
    let text = r#"
schema = 1
remotes = ["git@github.com:acme/widget.git"]

[[envs.dev.sources]]
provider = "aws_sm"
prefix = "widget/dev/"
[[envs.dev.sources]]
provider = "proton"
prefix = "widget/"
"#;
    let file = StoreFile::new(tmp.path().join(STORE_FILE)).with_test_work_factor();
    let pass = Passphrase::new("pw".into());
    file.create(&pass).unwrap();
    let project = parse_project(Path::new("/cfg/projects/widget.toml"), text).unwrap();
    let config = Config {
        aws: AwsSettings {
            profile: Some(Profile::try_from("widget-dev".to_owned()).unwrap()),
            region: None,
        },
        ..Config::default()
    };
    let registry = Registry::new(config, vec![project]).unwrap();
    let providers = super::Providers::with_aws(aws.clone()).with_proton(fake.cli());
    let d = Daemon::new(
        Box::new(move || Ok(registry.clone())),
        Arc::new(providers),
        file,
    );
    let list_as = |aws, provider, prefix: &str, search: Option<&str>| Request::List {
        provider,
        prefix: prefix.into(),
        search: search.map(Into::into),
        aws,
        keys: false,
    };
    let list = |provider, prefix: &str, search: Option<&str>| {
        list_as(AwsSettings::default(), provider, prefix, search)
    };
    let names = |r: &Response| match r {
        Response::Listed { items, .. } => items.iter().map(|l| l.name.clone()).collect::<Vec<_>>(),
        r => panic!("{r:?}"),
    };

    // Locked: AWS lists; the store and Proton say why they were not.
    let r = d.handle(list(None, "", None)).await;
    assert_clean(&c, &r);
    assert_eq!(names(&r), ["widget/dev/db", "widget/dev/stripe"]);
    let Response::Listed { warnings, .. } = &r else {
        unreachable!()
    };
    assert_eq!(warnings.len(), 2, "{warnings:?}");
    assert!(
        warnings.iter().all(|w| w.contains("locked")),
        "{warnings:?}"
    );
    assert_eq!(
        error_code(d.handle(list(Some(Provider::Proton), "", None)).await),
        ErrorCode::Locked
    );
    let health = d.providers(Some(&facts(None, None)), false).await;
    assert!(
        health
            .iter()
            .any(|p| p.provider == Provider::Proton && p.health == Health::Locked),
        "{health:?}"
    );

    d.unlock(Some(pass)).await.unwrap();
    d.handle(Request::StoreSet {
        section: "widget.dev".parse().unwrap(),
        key: key("STRIPE_TEST"),
        value: WireSecret::new(c.value().into()),
        passphrase: pw("pw"),
        sensitive: false,
    })
    .await;
    // Before connect proton, Proton is skipped, not a warning.
    let r = d.handle(list(None, "", None)).await;
    assert_eq!(
        names(&r),
        ["widget/dev/db", "widget/dev/stripe", "widget.dev"]
    );
    assert_eq!(
        d.handle(Request::ProtonConnect {
            token: WireSecret::new(fake.token.clone()),
            expires: Some(crate::source::unix_now() + 3 * 86_400),
            passphrase: pw("pw"),
        })
        .await,
        Response::ProtonConnected {
            change: Change::Added,
            locked: false,
            vaults: 2,
        }
    );

    // Every provider, the global vault included: it is listed, never
    // picked up by a source's prefix.
    let r = d.handle(list(None, "", None)).await;
    assert_clean(&c, &r);
    assert_eq!(
        names(&r),
        [
            "widget/dev/db",
            "widget/dev/stripe",
            "widget.dev",
            "global/OPENAI_KEY",
            "widget/STRIPE_KEY"
        ]
    );
    let Response::Listed {
        items, warnings, ..
    } = &r
    else {
        unreachable!()
    };
    assert!(warnings.is_empty(), "{warnings:?}");
    let stripe = items
        .iter()
        .find(|l| l.name == "widget/STRIPE_KEY")
        .unwrap();
    assert_eq!(stripe.id, Origin::new(Provider::Proton, "S1/i1"));
    assert_eq!(stripe.keys, [key("STRIPE_KEY")]);
    assert_eq!(stripe.title.as_deref(), Some("item i1"));

    // Search: names or keys, ignoring case, in every provider.
    let r = d.handle(list(None, "", Some("sTrIpE"))).await;
    assert_clean(&c, &r);
    assert_eq!(
        names(&r),
        ["widget/dev/stripe", "widget.dev", "widget/STRIPE_KEY"]
    );
    let r = d
        .handle(list(Some(Provider::Proton), "global/", Some("openai")))
        .await;
    assert_eq!(names(&r), ["global/OPENAI_KEY"]);

    // An AWS profile that needs a login: one provider asked fails with
    // the hint; every provider warns and lists the rest.
    let old = || AwsSettings {
        profile: Some(Profile::try_from("old".to_owned()).unwrap()),
        region: None,
    };
    let r = d
        .handle(list_as(old(), Some(Provider::AwsSm), "", None))
        .await;
    assert_eq!(error_code(r), ErrorCode::SourceFailed);
    let r = d.handle(list_as(old(), None, "", None)).await;
    let Response::Listed {
        items, warnings, ..
    } = &r
    else {
        panic!("{r:?}")
    };
    assert_eq!(items.len(), 3);
    assert!(warnings[0].starts_with("aws_sm: "), "{warnings:?}");

    // Health of the env's providers and the connected ones.
    let health = d.providers(Some(&facts(None, None)), false).await;
    assert_clean(&c, &health);
    assert!(health.iter().all(|p| p.health == Health::Ok), "{health:?}");
    for p in [Provider::AwsSm, Provider::Proton] {
        assert!(health.iter().any(|h| h.provider == p), "{health:?}");
    }
    fake.expire();
    fake.revoke();
    let health = d.providers(None, false).await;
    let proton = health
        .iter()
        .find(|p| p.provider == Provider::Proton)
        .unwrap();
    assert!(
        matches!(proton.health, Health::NeedsLogin { .. }),
        "{proton:?}"
    );
    assert_clean(&c, &health);

    // The token expires in three days: status says so.
    let s = d.status(None).await.unwrap();
    assert_eq!(s.expiring.len(), 1);
    assert_eq!(s.expiring[0].provider, Provider::Proton);
}

/// What the app sees once a request waits for approval: it waits for
/// approvals first, so the daemon counts it as open, then `req` is sent.
async fn asked_in_the_app(
    d: &Daemon,
    req: Request,
) -> (
    tokio::task::JoinHandle<Response>,
    Vec<crate::ipc::protocol::ApprovalPrompt>,
) {
    let app = tokio::spawn({
        let d = d.clone();
        async move { d.handle(Request::WaitApprovals { known: Vec::new() }).await }
    });
    tokio::task::yield_now().await;
    let asked = tokio::spawn({
        let d = d.clone();
        async move { d.handle(req).await }
    });
    let Response::Approvals { pending } = app.await.unwrap() else {
        panic!("not approvals");
    };
    (asked, pending)
}

/// The prompt says why a request waits: a key marked sensitive, the
/// environment marked sensitive, or the environment looking like
/// production with no human decision, and then why it looks it.
#[tokio::test]
async fn an_approval_prompt_says_why_it_waits() {
    use crate::ipc::protocol::ApprovalReason;
    let (_tmp, file, d) = stored_daemon();
    init(&file, &d).await;
    for (section, k, sensitive) in [
        ("widget.dev", "S", true),
        ("widget.prod", "A", false),
        ("widget.rc", "A", false),
    ] {
        let set = d
            .handle(Request::StoreSet {
                section: section.parse().unwrap(),
                key: key(k),
                value: pw("v"),
                passphrase: pw("pw"),
                sensitive,
            })
            .await;
        assert!(matches!(set, Response::Store { .. }), "{set:?}");
    }
    for (env, k, want) in [
        ("dev", "S", ApprovalReason::Keys),
        ("prod", "A", ApprovalReason::Marked),
        (
            "rc",
            "A",
            ApprovalReason::Waiting {
                why: "its name has the segment rc".into(),
            },
        ),
    ] {
        let (asked, pending) = asked_in_the_app(&d, get(Some(env), k, "pw")).await;
        let [prompt] = &pending[..] else {
            panic!("{env}: {pending:?}")
        };
        assert_eq!(prompt.reason, want, "{env}");
        assert_eq!(prompt.keys, [key(k)], "{env}");
        // A store key is marked by itself: no secret to name.
        assert_eq!(prompt.secrets, [], "{env}");
        let r = d
            .handle(Request::Approve {
                id: prompt.id,
                passphrase: None,
                values: Vec::new(),
            })
            .await;
        assert_eq!(r, Response::Approvals { pending: vec![] });
        assert_eq!(error_code(asked.await.unwrap()), ErrorCode::NotApproved);
    }
}

/// With no `.env.example` a command gets every key, and the prompt says
/// so. It names them where the daemon knows them without reading: an
/// environment that looks like production is read before it asks, a marked
/// one only once approved, and the caller is not told its names. Approved
/// key by key, another key voids the approval.
#[tokio::test]
async fn an_approval_with_no_example_is_for_every_key() {
    let (_tmp, file, d) = stored_daemon();
    init(&file, &d).await;
    let set = |section: &str, k: &str| Request::StoreSet {
        section: section.parse().unwrap(),
        key: key(k),
        value: pw("v"),
        passphrase: pw("pw"),
        sensitive: false,
    };
    for (section, k) in [
        ("widget.prod", "A"),
        ("widget.prod", "B"),
        ("widget.rc", "A"),
        ("widget.rc", "B"),
    ] {
        let r = d.handle(set(section, k)).await;
        assert!(matches!(r, Response::Store { .. }), "{r:?}");
    }
    let run = |env: &str, example: Option<&[&str]>| Request::RunEnv {
        facts: facts(Some(env), example),
        program: None,
        command: vec!["deploy".into()],
    };
    let approve = |id| Request::Approve {
        id,
        passphrase: Some(pw("pw")),
        values: Vec::new(),
    };
    let deny = |id| Request::Approve {
        id,
        passphrase: None,
        values: Vec::new(),
    };

    // A list of keys is asked for as that list.
    let (asked, pending) = asked_in_the_app(&d, run("prod", Some(&["A"]))).await;
    assert!(!pending[0].every_key);
    assert_eq!(pending[0].keys, [key("A")]);
    d.handle(deny(pending[0].id)).await;
    assert_eq!(error_code(asked.await.unwrap()), ErrorCode::NotApproved);

    // Marked and not read yet: every key, whichever they are.
    let (asked, pending) = asked_in_the_app(&d, run("prod", None)).await;
    assert!(pending[0].every_key);
    assert_eq!(pending[0].keys, []);
    d.handle(approve(pending[0].id)).await;
    let Response::RunEnv(reply) = asked.await.unwrap() else {
        panic!("not approved");
    };
    assert_eq!(reply.vars.len(), 2);

    // Held now: the person is shown them, the caller is not.
    let (asked, pending) = asked_in_the_app(&d, run("prod", None)).await;
    assert!(pending[0].every_key);
    assert_eq!(pending[0].keys, [key("A"), key("B")]);
    d.handle(deny(pending[0].id)).await;
    let Response::Error(e) = asked.await.unwrap() else {
        panic!("handed out what was denied");
    };
    assert!(
        e.message.contains("every value of the environment"),
        "{}",
        e.message
    );

    // Another key while the prompt waits is not one the person saw.
    let (asked, pending) = asked_in_the_app(&d, run("prod", None)).await;
    assert_eq!(pending[0].keys, [key("A"), key("B")]);
    let r = d.handle(set("widget.prod", "C")).await;
    assert!(matches!(r, Response::Store { .. }), "{r:?}");
    d.handle(approve(pending[0].id)).await;
    let Response::Error(e) = asked.await.unwrap() else {
        panic!("handed out a key nobody approved");
    };
    assert!(e.message.contains("changed while waiting"), "{}", e.message);

    // One that looks like production is read before it asks.
    let (asked, pending) = asked_in_the_app(&d, run("rc", None)).await;
    assert!(pending[0].every_key);
    assert_eq!(pending[0].keys, [key("A"), key("B")]);
    d.handle(approve(pending[0].id)).await;
    let Response::RunEnv(reply) = asked.await.unwrap() else {
        panic!("not approved");
    };
    assert_eq!(reply.vars.len(), 2);

    // A key marked by itself is asked for as that key.
    let r = d
        .handle(Request::StoreSet {
            section: "widget.dev".parse().unwrap(),
            key: key("S"),
            value: pw("v"),
            passphrase: pw("pw"),
            sensitive: true,
        })
        .await;
    assert!(matches!(r, Response::Store { .. }), "{r:?}");
    let (asked, pending) = asked_in_the_app(&d, run("dev", None)).await;
    assert!(!pending[0].every_key);
    assert_eq!(pending[0].keys, [key("S")]);
    d.handle(deny(pending[0].id)).await;
    assert_eq!(error_code(asked.await.unwrap()), ErrorCode::NotApproved);
}

/// A request whose process ends while it waits, as an agent's command does
/// when it runs out of time, is refused, and its prompt goes: nobody is
/// left to hand the values to.
#[tokio::test]
async fn a_prompt_goes_when_its_caller_ends() {
    let (tmp, log, d) = audited(state_log);
    let file = StoreFile::new(tmp.path().join(STORE_FILE)).with_test_work_factor();
    init(&file, &d).await;
    let set = d
        .handle(Request::StoreSet {
            section: "widget.prod".parse().unwrap(),
            key: key("A"),
            value: pw("v"),
            passphrase: pw("pw"),
            sensitive: false,
        })
        .await;
    assert!(matches!(set, Response::Store { .. }), "{set:?}");
    let mut child = std::process::Command::new("sleep")
        .arg("60")
        .spawn()
        .unwrap();
    let caller = crate::test_support::caller_for(child.id() as i32);

    let app = tokio::spawn({
        let d = d.clone();
        async move { d.handle(Request::WaitApprovals { known: Vec::new() }).await }
    });
    tokio::task::yield_now().await;
    let asked = tokio::spawn({
        let d = d.clone();
        async move {
            let run = Request::RunEnv {
                facts: facts(Some("prod"), Some(&["A"])),
                program: Some("deploy".into()),
                command: vec!["deploy".into()],
            };
            d.handle_from(run, &caller).await
        }
    });
    let Response::Approvals { pending } = app.await.unwrap() else {
        panic!("not approvals");
    };
    assert_eq!(pending.len(), 1, "{pending:?}");

    child.kill().unwrap();
    child.wait().unwrap();
    let Response::Error(e) = asked.await.unwrap() else {
        panic!("handed out");
    };
    assert_eq!(e.code, ErrorCode::NotApproved);
    assert!(e.message.contains("ended before"), "{}", e.message);
    let r = d
        .handle(Request::Approve {
            id: pending[0].id,
            passphrase: Some(pw("pw")),
            values: Vec::new(),
        })
        .await;
    assert_eq!(error_code(r), ErrorCode::BadRequest);
    assert_eq!(
        logged(&log),
        [
            "store set allowed",
            "ask approval allowed",
            "run denied",
            "approve denied",
        ]
    );
}

/// When the app's process ends, the daemon stops counting it as open at
/// once: a request already waiting is refused as one made with no app is,
/// instead of waiting out the timeout, and so is the next one.
#[tokio::test]
async fn a_prompt_is_refused_when_the_app_ends() {
    let (_tmp, file, d) = stored_daemon();
    init(&file, &d).await;
    let set = d
        .handle(Request::StoreSet {
            section: "widget.prod".parse().unwrap(),
            key: key("A"),
            value: pw("v"),
            passphrase: pw("pw"),
            sensitive: false,
        })
        .await;
    assert!(matches!(set, Response::Store { .. }), "{set:?}");
    let run = || Request::RunEnv {
        facts: facts(Some("prod"), Some(&["A"])),
        program: Some("deploy".into()),
        command: vec!["deploy".into()],
    };
    let mut child = std::process::Command::new("sleep")
        .arg("60")
        .spawn()
        .unwrap();
    let app = crate::test_support::caller_for(child.id() as i32);
    let watch = |known: Vec<u64>| {
        let (d, app) = (d.clone(), app.clone());
        tokio::spawn(async move { d.handle_from(Request::WaitApprovals { known }, &app).await })
    };

    let first = watch(Vec::new());
    tokio::task::yield_now().await;
    let asked = tokio::spawn({
        let (d, run) = (d.clone(), run());
        async move { d.handle(run).await }
    });
    let Response::Approvals { pending } = first.await.unwrap() else {
        panic!("not approvals");
    };
    assert_eq!(pending.len(), 1, "{pending:?}");
    // The app shows the prompt and waits for the next change.
    let second = watch(vec![pending[0].id]);
    tokio::task::yield_now().await;

    child.kill().unwrap();
    child.wait().unwrap();
    let started = std::time::Instant::now();
    let Response::Error(e) = asked.await.unwrap() else {
        panic!("handed out");
    };
    assert!(started.elapsed() < Duration::from_secs(5), "waited");
    assert_eq!(e.code, ErrorCode::SensitiveEnv);
    assert!(e.message.contains("which is not open"), "{}", e.message);
    assert!(matches!(second.await.unwrap(), Response::Approvals { .. }));

    // No grace for an app that is gone.
    let Response::Error(e) = d.handle(run()).await else {
        panic!("handed out");
    };
    assert!(e.message.contains("which is not open"), "{}", e.message);
    // And the prompt went with the request.
    let now = d.handle(Request::WaitApprovals { known: vec![0] }).await;
    assert_eq!(now, Response::Approvals { pending: vec![] });
}

/// A refusal after the app asked says what it asked for: the keys, cut
/// short when there are many, and what marks them.
#[test]
fn an_unapproved_request_says_what_was_asked() {
    use super::resolve::Unapproved;
    use crate::ipc::protocol::ApprovalReason;
    let asked = |keys: usize, secrets: &[&str], waited: Option<u64>| {
        ResolveError::NotApproved(Box::new(Unapproved {
            project: "widget".parse().unwrap(),
            env: "dev".parse().unwrap(),
            waited: waited.map(Duration::from_secs),
            keys: (0..keys).map(|i| key(&format!("K{i}"))).collect(),
            reason: ApprovalReason::Keys,
            secrets: secrets.iter().map(|s| sm(s)).collect(),
        }))
        .to_string()
    };
    assert_eq!(
        asked(2, &["acme/prod/db"], Some(90)),
        "environment dev of project widget: nobody answered the app's prompt within 90 seconds, \
         so nothing was handed out. It asked for K0, K1, read from aws_sm:acme/prod/db, which \
         is marked sensitive"
    );
    assert_eq!(
        asked(11, &["a", "b"], None),
        "environment dev of project widget: a person denied the request in the app, so \
         nothing was handed out. It asked for K0, K1, K2, K3, K4, K5, K6, K7 and 3 more, read \
         from secrets marked sensitive (aws_sm:a, aws_sm:b)"
    );
    let waiting = ResolveError::NotApproved(Box::new(Unapproved {
        project: "widget".parse().unwrap(),
        env: "rc".parse().unwrap(),
        waited: Some(Duration::from_mins(1)),
        keys: Vec::new(),
        reason: ApprovalReason::Waiting {
            why: "its name".into(),
        },
        secrets: Vec::new(),
    }));
    assert_eq!(
        waiting.to_string(),
        "environment rc of project widget: nobody answered the app's prompt within a minute, \
         so nothing was handed out. It asked for every value of the environment, which looks \
         like production (its name) and waits for a human decision"
    );
}

/// A `run` or `get` that needs a value marked sensitive waits until a
/// person approves it in the app with the store passphrase, or denies it,
/// or it times out; without the app it is refused at once. Each step is in
/// the audit log, with no value and no command line.
#[tokio::test]
async fn sensitive_values_wait_for_approval_in_the_app() {
    let canary = Canary::new();
    let (tmp, log, d) = audited(state_log);
    let file = StoreFile::new(tmp.path().join(STORE_FILE)).with_test_work_factor();
    init(&file, &d).await;
    let set = d
        .handle(Request::StoreSet {
            section: "widget.prod".parse().unwrap(),
            key: key("A"),
            value: WireSecret::new(canary.value().into()),
            passphrase: pw("pw"),
            sensitive: false,
        })
        .await;
    assert!(matches!(set, Response::Store { .. }), "{set:?}");
    let run = || Request::RunEnv {
        facts: facts(Some("prod"), Some(&["A"])),
        program: Some("deploy".into()),
        command: vec!["deploy".into(), "--to".into(), "the moon".into()],
    };
    let approve = |id, pass: Option<&str>| Request::Approve {
        id,
        passphrase: pass.map(pw),
        values: Vec::new(),
    };

    // No app: refused, saying to open it.
    let r = d.handle(run()).await;
    assert_eq!(error_code(r), ErrorCode::SensitiveEnv);

    // Approved: the prompt names what it hands out and to whom.
    let (asked, pending) = asked_in_the_app(&d, run()).await;
    let [prompt] = &pending[..] else {
        panic!("{pending:?}")
    };
    assert_eq!(
        (prompt.project.as_str(), prompt.env.as_str()),
        ("widget", "prod")
    );
    assert_eq!(prompt.keys, [key("A")]);
    assert_eq!(prompt.command, r#"deploy --to "the moon""#);
    assert_eq!(prompt.argv, ["deploy", "--to", "the moon"]);
    // Who asks: what started this test, and the time left to answer.
    assert!(!prompt.parents.is_empty(), "{prompt:?}");
    assert!(
        prompt.left.is_some_and(|s| (290..=300).contains(&s)),
        "{prompt:?}"
    );
    assert_eq!(prompt.pid, this_process().pid);
    assert_eq!(prompt.cwd, facts(None, None).cwd);
    let r = d.handle(approve(prompt.id, Some("wrong"))).await;
    assert_eq!(error_code(r), ErrorCode::WrongPassphrase);
    let r = d.handle(approve(prompt.id, Some("pw"))).await;
    assert_eq!(r, Response::Approvals { pending: vec![] });
    let Response::RunEnv(reply) = asked.await.unwrap() else {
        panic!("not approved");
    };
    assert_eq!(reply.vars.len(), 1);
    assert_eq!(reply.vars[0].value.expose(), canary.value());

    // Denied: `get` asks the same way, after its passphrase.
    let (asked, pending) = asked_in_the_app(&d, get(Some("prod"), "A", "pw")).await;
    assert_eq!(pending[0].command, "kagebunshin get A");
    assert_eq!(pending[0].argv, ["kagebunshin", "get", "A"]);
    let r = d.handle(approve(pending[0].id, None)).await;
    assert_eq!(r, Response::Approvals { pending: vec![] });
    // The caller is told what was asked, so it can tell the person.
    let Response::Error(e) = asked.await.unwrap() else {
        panic!("approved");
    };
    assert_eq!(e.code, ErrorCode::NotApproved);
    assert_eq!(
        e.message,
        "environment prod of project widget: a person denied the request in the app, so \
         nothing was handed out. It asked for every value of the environment, which is \
         marked sensitive"
    );
    assert_eq!(
        e.hint.as_deref(),
        Some("a person refused this: ask them before running it again")
    );

    // Not answered in time, with the app open all the while as it keeps
    // asking what waits: denied, and its prompt goes.
    tokio::time::pause();
    let (asked, pending) = asked_in_the_app(&d, run()).await;
    let app = tokio::spawn({
        let d = d.clone();
        let mut known = vec![pending[0].id];
        async move {
            while let Response::Approvals { pending } =
                d.handle(Request::WaitApprovals { known }).await
            {
                known = pending.iter().map(|p| p.id).collect();
            }
        }
    });
    let Response::Error(e) = asked.await.unwrap() else {
        panic!("approved");
    };
    app.abort();
    assert_eq!(e.code, ErrorCode::NotApproved);
    assert_eq!(
        e.message,
        "environment prod of project widget: nobody answered the app's prompt within 5 \
         minutes, so nothing was handed out. It asked for every value of the environment, \
         which is marked sensitive"
    );
    assert!(
        e.hint
            .as_deref()
            .is_some_and(|h| h.contains("run the command again")),
        "{e:?}"
    );
    assert_eq!(e.who, Some(crate::ipc::protocol::Who::Human));
    let r = d.handle(approve(pending[0].id, Some("pw"))).await;
    assert_eq!(error_code(r), ErrorCode::BadRequest);

    assert_eq!(
        logged(&log),
        [
            "store set allowed",
            "run denied",
            "ask approval allowed",
            "approve denied",
            "run allowed",
            "ask approval allowed",
            "get denied",
            "ask approval allowed",
            "run timedout",
            "approve denied",
        ]
    );
    let (events, _) = log.read().unwrap();
    let ran = events
        .iter()
        .find(|e| e.action == "run" && e.reason.is_none())
        .unwrap();
    assert_eq!(ran.keys, ["A"]);
    assert_eq!(ran.program.as_deref(), Some("deploy"));
    let text = std::fs::read_to_string(log.path()).unwrap();
    assert_no_canary(&canary, &text);
    assert!(!text.contains("the moon"), "{text}");
}

// The remote endpoint: callers on other machines, as `ipc::remote` hands
// them over once tailscaled has named them.

fn laptop_peer(node: &str) -> crate::ipc::protocol::RemotePeer {
    crate::ipc::protocol::RemotePeer {
        node: node.into(),
        machine: "laptop".into(),
        user: "dev@example.com".into(),
        tags: Vec::new(),
        token: None,
    }
}

/// The machine `laptop` as node `node`, sending `token`.
fn laptop_with(node: &str, token: Option<&str>) -> crate::ipc::protocol::Caller {
    crate::ipc::protocol::Caller::remote(crate::ipc::protocol::RemotePeer {
        token: token.map(crate::store::TokenHash::of),
        ..laptop_peer(node)
    })
}

/// The token of a grant a test writes to the store itself.
const TOKEN: &str = "kbr_a-token-a-test-wrote";

/// A grant to laptop for widget's `envs`, with [`TOKEN`].
fn stored_grant(envs: &[&str], expires: Option<u64>) -> crate::store::RemoteGrant {
    crate::store::RemoteGrant {
        machine: "laptop".into(),
        node: "nLAPTOP".into(),
        project: "widget".parse().unwrap(),
        envs: envs.iter().map(|e| e.parse().unwrap()).collect(),
        token: Some(crate::store::TokenHash::of(TOKEN)),
        expires,
    }
}

/// The token a grant or a rotation gave.
fn token_of(r: Response) -> String {
    match r {
        Response::RemoteGranted { token, .. } => token.expose().to_owned(),
        other => panic!("{other:?}"),
    }
}

/// Grants laptop widget's `envs`; gives laptop as a caller that sends the
/// token the grant came with.
async fn granted(d: &Daemon, envs: &[&str]) -> crate::ipc::protocol::Caller {
    let token = token_of(d.handle(grant(envs, None)).await);
    laptop_with("nLAPTOP", Some(&token))
}

fn grant(envs: &[&str], expires: Option<u64>) -> Request {
    grant_as("laptop", envs, expires, "pw")
}

fn grant_as(machine: &str, envs: &[&str], expires: Option<u64>, pass: &str) -> Request {
    Request::RemoteGrant {
        machine: machine.into(),
        project: "widget".parse().unwrap(),
        envs: envs.iter().map(|e| e.parse().unwrap()).collect(),
        expires,
        passphrase: pw(pass),
    }
}

fn error(r: Response) -> crate::ipc::protocol::WireError {
    match r {
        Response::Error(e) => e,
        other => panic!("{other:?}"),
    }
}

/// [`STORED`], audited, on a tailnet where `laptop` is node nLAPTOP; its
/// store (passphrase pw) holds A in dev and in prod, which is marked
/// sensitive, and turns the endpoint on.
async fn remote_daemon() -> (
    tempfile::TempDir,
    crate::audit::AuditLog,
    Daemon,
    Arc<crate::tailnet::fake::FakeTailnet>,
) {
    let tailnet = Arc::new(crate::tailnet::fake::FakeTailnet::running(&[(
        "nLAPTOP", "laptop",
    )]));
    let (tmp, log, d) = audited(state_log);
    let d = d.with_tailnet(tailnet.clone());
    let file = StoreFile::new(tmp.path().join(STORE_FILE)).with_test_work_factor();
    init(&file, &d).await;
    for section in ["widget.dev", "widget.prod"] {
        let set = d
            .handle(Request::StoreSet {
                section: section.parse().unwrap(),
                key: key("A"),
                value: pw(&format!("{section} value")),
                passphrase: pw("pw"),
                sensitive: false,
            })
            .await;
        assert!(matches!(set, Response::Store { .. }), "{set:?}");
    }
    assert_eq!(d.remote_enabled(), Some(false), "off by default");
    let on = d
        .handle(Request::RemoteEnable {
            enabled: true,
            passphrase: pw("pw"),
        })
        .await;
    assert!(
        matches!(
            on,
            Response::Store {
                change: Change::Enabled,
                ..
            }
        ),
        "{on:?}"
    );
    assert_eq!(d.remote_enabled(), Some(true));
    (tmp, log, d, tailnet)
}

fn remote_run(env: &str) -> Request {
    Request::RunEnv {
        facts: facts(Some(env), Some(&["A"])),
        program: Some("deploy".into()),
        command: vec!["deploy".into(), "--now".into()],
    }
}

/// No grant, no access: not even whether the daemon is locked. A grant
/// covers the environments it names, of one project, for the node it was
/// given to, until it is revoked; a machine renamed to the granted name
/// gets nothing.
#[tokio::test]
async fn a_remote_machine_needs_a_grant_for_the_environment() {
    let (_tmp, log, d, tailnet) = remote_daemon().await;
    let me = laptop_with("nLAPTOP", None);
    for req in [
        remote_run("dev"),
        Request::Status { facts: None },
        Request::Status {
            facts: Some(facts(None, None)),
        },
        Request::Diff {
            facts: facts(None, Some(&["A"])),
        },
    ] {
        let e = error(d.handle_from(req, &me).await);
        assert_eq!(e.code, ErrorCode::PermissionDenied, "{e:?}");
        assert_eq!(e.message, "machine laptop has no remote grant");
        assert_eq!(
            e.hint.as_deref(),
            Some("on the daemon's machine, run `kagebunshin remote grant laptop <project> <env>`")
        );
    }

    // Granting is refused for what it cannot pin down.
    for (req, why) in [
        (grant(&[], None), "at least one environment"),
        (grant(&["nope"], None), "nope"),
        (grant(&["dev"], Some(1)), "has passed"),
    ] {
        let e = error(d.handle(req).await);
        assert!(e.message.contains(why), "{why}: {e:?}");
    }
    let e = error(d.handle(grant_as("desktop", &["dev"], None, "pw")).await);
    assert!(e.message.contains("no other machine"), "{e:?}");
    let wrong = grant_as("laptop", &["dev"], None, "wrong");
    assert_eq!(
        error_code(d.handle(wrong).await),
        ErrorCode::WrongPassphrase
    );

    let r = d.handle(grant(&["dev"], None)).await;
    assert!(
        matches!(
            &r,
            Response::RemoteGranted {
                change: Change::Added,
                machine,
                ..
            } if machine == "laptop"
        ),
        "{r:?}"
    );
    let token = token_of(r);
    let me = laptop_with("nLAPTOP", Some(&token));
    let Response::RunEnv(reply) = d.handle_from(remote_run("dev"), &me).await else {
        panic!("dev is granted");
    };
    assert_eq!(reply.vars[0].value.expose(), "widget.dev value");
    let Response::Status(report) = d
        .handle_from(
            Request::Status {
                facts: Some(facts(None, None)),
            },
            &me,
        )
        .await
    else {
        panic!("status");
    };
    assert!(
        report.remote.is_none() && report.expiring.is_empty(),
        "{report:?}"
    );
    let r = d
        .handle_from(
            Request::Diff {
                facts: facts(None, Some(&["A"])),
            },
            &me,
        )
        .await;
    assert!(matches!(r, Response::Diff(_)), "{r:?}");

    // Another environment of the project is not granted.
    let e = error(d.handle_from(remote_run("local"), &me).await);
    assert_eq!(e.code, ErrorCode::PermissionDenied);
    assert_eq!(
        e.message,
        "machine laptop has no remote grant for environment local of project widget"
    );

    // Another node, now named laptop, gets nothing, whatever it sends.
    tailnet.set_status("Running", &[("nOTHER", "laptop")]);
    let other = laptop_with("nOTHER", Some(&token));
    let e = error(d.handle_from(remote_run("dev"), &other).await);
    assert_eq!(e.message, "machine laptop has no remote grant");

    // This machine sees the grant.
    let Response::Status(report) = d.handle(Request::Status { facts: None }).await else {
        panic!("status");
    };
    let remote = report.remote.unwrap();
    assert_eq!(remote.enabled, Some(true));
    assert_eq!(remote.grants.len(), 1);
    assert_eq!(remote.grants[0].node, "nLAPTOP");
    assert!(remote.grants[0].token);

    // Revoked: nothing again; revoking again finds nothing.
    let revoke = || Request::RemoteRevoke {
        machine: "LAPTOP".into(),
        project: None,
        passphrase: pw("pw"),
    };
    let r = d.handle(revoke()).await;
    assert!(
        matches!(
            r,
            Response::Store {
                change: Change::Removed,
                ..
            }
        ),
        "{r:?}"
    );
    let e = error(d.handle_from(remote_run("dev"), &me).await);
    assert_eq!(e.message, "machine laptop has no remote grant");
    assert_eq!(error_code(d.handle(revoke()).await), ErrorCode::Store);

    // Every remote request is recorded, with the machine, allowed or not.
    let (events, _) = log.read().unwrap();
    let remote: Vec<_> = events.iter().filter(|e| e.remote.is_some()).collect();
    assert_eq!(remote.len(), 10, "{remote:#?}");
    assert!(remote.iter().all(|e| e.pid == 0));
    let ran = remote
        .iter()
        .find(|e| e.action == "run" && e.reason.is_none())
        .unwrap();
    assert_eq!(
        ran.remote,
        Some(laptop_peer("nLAPTOP")),
        "without what it sent"
    );
    assert_eq!(
        (
            ran.project.as_ref().unwrap().as_str(),
            ran.env.as_ref().unwrap().as_str()
        ),
        ("widget", "dev")
    );
    assert_eq!(ran.keys, ["A"]);
}

/// Only run, status and diff: nothing that changes this machine's state,
/// prints a value or answers a prompt, whatever passphrase comes with it.
#[tokio::test]
async fn remote_machines_may_only_run_and_look() {
    let (_tmp, _log, d, _) = remote_daemon().await;
    let me = granted(&d, &["dev", "prod"]).await;
    let section = || "widget.dev".parse().unwrap();
    for req in [
        Request::Lock,
        Request::Unlock {
            passphrase: Some(pw("pw")),
        },
        Request::Sync {
            project: None,
            env: None,
        },
        Request::StoreList,
        get(Some("dev"), "A", "pw"),
        store_set("A", "v", "pw"),
        Request::StoreMark {
            section: section(),
            key: key("A"),
            sensitive: false,
            passphrase: pw("pw"),
        },
        Request::RemoteEnable {
            enabled: true,
            passphrase: pw("pw"),
        },
        add_mark_env("dev"),
        grant(&["local"], None),
        ask_values(&["A"]),
        Request::WaitApprovals { known: Vec::new() },
        Request::Approve {
            id: 1,
            passphrase: Some(pw("pw")),
            values: Vec::new(),
        },
        Request::Providers {
            facts: None,
            every: false,
        },
        Request::Inspect {
            facts: facts(None, None),
            passphrase: pw("pw"),
        },
    ] {
        let what = format!("{req:?}");
        let e = error(d.handle_from(req, &me).await);
        assert_eq!(e.code, ErrorCode::PermissionDenied, "{what}");
        assert!(
            e.message.starts_with("machine laptop asked for ")
                && e.message
                    .ends_with("remotely, only run, status and diff work"),
            "{what}: {e:?}"
        );
    }
    assert!(!d.is_locked());
    assert_eq!(listing(&d).len(), 2, "unchanged");
}

/// Locked, the daemon refuses remote callers, and they cannot unlock it;
/// turned off, it refuses them even on a connection already open.
#[tokio::test]
async fn a_locked_or_disabled_daemon_refuses_remote_machines() {
    let (_tmp, _log, d, _) = remote_daemon().await;
    let me = granted(&d, &["dev"]).await;
    d.lock();
    for req in [remote_run("dev"), Request::Status { facts: None }] {
        let e = error(d.handle_from(req, &me).await);
        assert_eq!(e.code, ErrorCode::Locked);
        // Unlocking is done here, not where the caller is.
        let there = "on the daemon's machine, unlock kagebunshin: run `kagebunshin unlock` in a \
                     terminal";
        assert_eq!(
            (e.hint.as_deref(), e.tell.as_deref()),
            (Some(there), Some(there))
        );
    }
    d.unlock(Some(Passphrase::new("pw".into()))).await.unwrap();
    assert_eq!(d.remote_enabled(), Some(true), "read again on unlock");
    let off = d
        .handle(Request::RemoteEnable {
            enabled: false,
            passphrase: pw("pw"),
        })
        .await;
    assert!(
        matches!(
            off,
            Response::Store {
                change: Change::Disabled,
                ..
            }
        ),
        "{off:?}"
    );
    let e = error(d.handle_from(remote_run("dev"), &me).await);
    assert_eq!(e.message, "the remote endpoint is off");
}

/// A grant whose end has passed gives nothing.
#[tokio::test]
async fn an_expired_grant_gives_nothing() {
    let (tmp, _log, d, _) = remote_daemon().await;
    let file = StoreFile::new(tmp.path().join(STORE_FILE)).with_test_work_factor();
    let pass = Passphrase::new("pw".into());
    file.update(&pass, None, |st| {
        st.grant_remote(stored_grant(&["dev"], Some(1)));
        Ok(())
    })
    .unwrap();
    d.lock();
    d.unlock(Some(pass)).await.unwrap();
    let me = laptop_with("nLAPTOP", Some(TOKEN));
    let e = error(d.handle_from(remote_run("dev"), &me).await);
    assert_eq!(e.message, "machine laptop has no remote grant");
}

/// Remotely `--project` is enough: the grant says which projects a machine
/// may use, and a checkout's remotes are only what that machine reports.
/// So a plain folder, or another repository's checkout, gets the named
/// project. Of a project no grant names, nothing is said. With no name the
/// checkout's remotes still find the project, and a folder with none is
/// told to name it.
#[tokio::test]
async fn a_remote_machine_names_a_project_without_a_checkout() {
    let (_tmp, _log, d, _) = remote_daemon().await;
    let me = granted(&d, &["dev"]).await;
    let from = |remotes: &[&str], project: Option<&str>| Facts {
        cwd: "/home/bot".into(),
        remotes: remotes
            .iter()
            .map(|r| RemoteId::from_url(r).unwrap())
            .collect(),
        project: project.map(|p| p.parse().unwrap()),
        ..facts(Some("dev"), Some(&["A"]))
    };
    let run = |facts| Request::RunEnv {
        facts,
        program: Some("deploy".into()),
        command: vec!["deploy".into()],
    };
    for remotes in [&[][..], &["https://github.com/acme/other"]] {
        let r = d.handle_from(run(from(remotes, Some("widget"))), &me).await;
        let Response::RunEnv(reply) = r else {
            panic!("{remotes:?}: {r:?}");
        };
        assert_eq!(reply.project.as_str(), "widget");
        assert_eq!(reply.vars[0].value.expose(), "widget.dev value");
        for req in [
            Request::Status {
                facts: Some(from(remotes, Some("widget"))),
            },
            Request::Diff {
                facts: from(remotes, Some("widget")),
            },
        ] {
            let r = d.handle_from(req, &me).await;
            assert!(
                matches!(r, Response::Status(_) | Response::Diff(_)),
                "{r:?}"
            );
        }
    }
    // A grant names environments too.
    let prod = Facts {
        env: Some("prod".parse().unwrap()),
        ..from(&[], Some("widget"))
    };
    let e = error(d.handle_from(run(prod), &me).await);
    assert_eq!(
        e.message,
        "machine laptop has no remote grant for environment prod of project widget"
    );

    // The same of a project that is not there as of one that is.
    let e = error(d.handle_from(run(from(&[], Some("secretive"))), &me).await);
    assert_eq!(e.code, ErrorCode::PermissionDenied);
    assert_eq!(
        e.message,
        "machine laptop has no remote grant for project secretive"
    );
    assert_eq!(
        e.hint.as_deref(),
        Some("on the daemon's machine, run `kagebunshin remote grant laptop secretive <env>`")
    );

    let e = error(d.handle_from(run(from(&[], None)), &me).await);
    assert_eq!(
        e.message,
        "machine laptop named no project, and /home/bot is not a checkout with a git remote to \
         find one by"
    );
    assert_eq!(e.hint.as_deref(), Some("name the project with `--project`"));

    // Only a remote caller: locally the checkout decides.
    let e = error(d.handle(run(from(&[], Some("widget")))).await);
    assert_eq!(e.code, ErrorCode::NoProject, "{e:?}");
    let e = error(
        d.handle(run(from(
            &["https://github.com/acme/other"],
            Some("widget"),
        )))
        .await,
    );
    assert_eq!(e.code, ErrorCode::NoProject, "{e:?}");
}

/// What fixes a remote caller's refusal is done on the daemon's machine,
/// and the caller is told so: the app to open, the command to run. None of
/// it is the caller's own to do. What it does next itself is said as it is
/// to a local caller.
#[tokio::test]
async fn a_remote_machine_is_told_where_the_fix_is_done() {
    use crate::ipc::protocol::Who;
    let (_tmp, _log, d, _) = remote_daemon().await;
    let me = granted(&d, &["prod"]).await;
    // Marked sensitive, and the app is not open.
    let e = error(d.handle_from(remote_run("prod"), &me).await);
    assert!(e.message.ends_with("which is not open"), "{e:?}");
    assert_eq!(
        (e.who, e.tell.as_deref()),
        (
            Some(Who::Human),
            Some(
                "on the daemon's machine, open the app (`kagebunshin app`), so a request for \
                 values marked sensitive can be approved there"
            )
        )
    );
    assert_eq!(
        e.hint.as_deref(),
        Some("once the app is open, run the command again; the app asks to approve it")
    );

    // A local caller adds the environment itself; a remote one cannot.
    let unknown = ResolveError::UnknownEnv {
        project: "widget".parse().unwrap(),
        env: "staging".parse().unwrap(),
    };
    assert_eq!(super::broker::wire_error(&unknown).who, Some(Who::Agent));
    let e = super::broker::remote_wire_error(&unknown);
    assert_eq!(
        (e.who, e.tell, e.hint.as_deref()),
        (
            None,
            None,
            Some(
                "on the daemon's machine, add it with `kagebunshin project add-env widget \
                 staging`"
            )
        )
    );

    // A provider this machine reads.
    let e = super::broker::remote_wire_error(&ResolveError::Provider {
        message: "m".into(),
        hint: Some("run `x login`".into()),
    });
    assert_eq!(
        e.hint.as_deref(),
        Some("on the daemon's machine, run `x login`")
    );

    // It says where already.
    let said = ResolveError::Remote {
        message: "m".into(),
        hint: Some("on the daemon's machine, run y".into()),
    };
    assert_eq!(
        super::broker::remote_wire_error(&said),
        super::broker::wire_error(&said)
    );
}

/// A remote request for values marked sensitive waits for approval in the
/// app, as a local one does; the prompt names the machine. One machine
/// gets one prompt at a time: the next is refused, not queued.
#[tokio::test]
async fn a_remote_machine_waits_on_one_prompt_at_a_time() {
    let (_tmp, _log, d, _) = remote_daemon().await;
    let me = granted(&d, &["prod"]).await;
    let app = tokio::spawn({
        let d = d.clone();
        async move { d.handle(Request::WaitApprovals { known: Vec::new() }).await }
    });
    tokio::task::yield_now().await;
    let asked = tokio::spawn({
        let (d, me) = (d.clone(), me.clone());
        async move { d.handle_from(remote_run("prod"), &me).await }
    });
    let Response::Approvals { pending } = app.await.unwrap() else {
        panic!("not approvals");
    };
    let [prompt] = &pending[..] else {
        panic!("{pending:?}")
    };
    assert_eq!(prompt.remote, Some(laptop_peer("nLAPTOP")));
    assert_eq!(prompt.command, "deploy --now");
    assert_eq!(prompt.pid, 0);

    let e = error(d.handle_from(remote_run("prod"), &me).await);
    assert_eq!(e.code, ErrorCode::PermissionDenied);
    assert_eq!(
        e.message,
        "machine laptop already has a request waiting for approval in the app"
    );
    let r = d
        .handle(Request::Approve {
            id: prompt.id,
            passphrase: Some(pw("pw")),
            values: Vec::new(),
        })
        .await;
    assert_eq!(r, Response::Approvals { pending: vec![] });
    let Response::RunEnv(reply) = asked.await.unwrap() else {
        panic!("not approved");
    };
    assert_eq!(reply.vars[0].value.expose(), "widget.prod value");

    // Answered, the next one may ask.
    let (asked, pending) = {
        let app = tokio::spawn({
            let d = d.clone();
            async move { d.handle(Request::WaitApprovals { known: Vec::new() }).await }
        });
        tokio::task::yield_now().await;
        let asked = tokio::spawn({
            let (d, me) = (d.clone(), me.clone());
            async move { d.handle_from(remote_run("prod"), &me).await }
        });
        let Response::Approvals { pending } = app.await.unwrap() else {
            panic!("not approvals");
        };
        (asked, pending)
    };
    assert_eq!(pending.len(), 1);
    d.handle(Request::Approve {
        id: pending[0].id,
        passphrase: None,
        values: Vec::new(),
    })
    .await;
    assert_eq!(error_code(asked.await.unwrap()), ErrorCode::NotApproved);
}

/// A remote request for an environment that looks like production and
/// that no human decided about waits for approval as a marked one does;
/// the list of such environments is this machine's business.
#[tokio::test]
async fn a_remote_machine_waits_for_a_production_looking_environment() {
    let (_tmp, _log, d, _) = remote_daemon().await;
    let me = granted(&d, &["rc"]).await;
    let set = d
        .handle(Request::StoreSet {
            section: "widget.rc".parse().unwrap(),
            key: key("A"),
            value: pw("widget.rc value"),
            passphrase: pw("pw"),
            sensitive: false,
        })
        .await;
    assert!(matches!(set, Response::Store { .. }), "{set:?}");

    let e = error(d.handle_from(remote_run("rc"), &me).await);
    assert_eq!(e.code, ErrorCode::SensitiveEnv);
    assert!(
        e.message.contains("looks like production") && e.message.contains("human decision"),
        "{e:?}"
    );
    assert_eq!(e.who, Some(crate::ipc::protocol::Who::Human));
    let tell = e.tell.as_deref().unwrap();
    assert!(
        tell.starts_with("on the daemon's machine, open the app") && tell.contains("widget/rc"),
        "{e:?}"
    );
    assert_eq!(e.hint, e.tell);
    let Response::Status(report) = d
        .handle_from(
            Request::Status {
                facts: Some(facts(Some("rc"), None)),
            },
            &me,
        )
        .await
    else {
        panic!("status");
    };
    assert!(report.waiting.is_empty(), "{report:?}");
    // Names still resolve, and the decision is made on the daemon's machine.
    let warning = report.env.unwrap().warnings.remove(0);
    assert!(
        warning.contains("waits for a human decision; ask the human: on the daemon's machine, ")
            && !warning.contains("mark env"),
        "{warning}"
    );
    let Response::Diff(diff) = d
        .handle_from(
            Request::Diff {
                facts: facts(Some("rc"), None),
            },
            &me,
        )
        .await
    else {
        panic!("diff");
    };
    assert_eq!(diff.warnings[0], warning);
    // Locally it is as it was.
    let Response::Diff(diff) = d
        .handle(Request::Diff {
            facts: facts(Some("rc"), None),
        })
        .await
    else {
        panic!("diff");
    };
    assert!(
        !diff.warnings[0].contains("on the daemon's machine"),
        "{diff:?}"
    );

    let app = tokio::spawn({
        let d = d.clone();
        async move { d.handle(Request::WaitApprovals { known: Vec::new() }).await }
    });
    tokio::task::yield_now().await;
    let asked = tokio::spawn({
        let (d, me) = (d.clone(), me.clone());
        async move { d.handle_from(remote_run("rc"), &me).await }
    });
    let Response::Approvals { pending } = app.await.unwrap() else {
        panic!("not approvals");
    };
    let [prompt] = &pending[..] else {
        panic!("{pending:?}")
    };
    assert_eq!(prompt.remote, Some(laptop_peer("nLAPTOP")));
    assert_eq!(prompt.env.as_str(), "rc");
    let r = d
        .handle(Request::Approve {
            id: prompt.id,
            passphrase: Some(pw("pw")),
            values: Vec::new(),
        })
        .await;
    assert_eq!(r, Response::Approvals { pending: vec![] });
    let Response::RunEnv(reply) = asked.await.unwrap() else {
        panic!("not approved");
    };
    assert_eq!(reply.vars[0].value.expose(), "widget.rc value");
}

/// Ends laptop's grant for `env` of widget while a request waits: revoked,
/// narrowed to another environment, past its end, or given another token.
/// `me` is laptop with the grant's token, which only `rotated` changes.
async fn lose_grant(d: &Daemon, how: &str, env: &str, me: &crate::ipc::protocol::Caller) {
    let rewrite = |envs: &[&str], expires| {
        let grant = crate::store::RemoteGrant {
            token: me.remote.as_ref().unwrap().token,
            ..stored_grant(envs, expires)
        };
        d.store_write(Passphrase::new("pw".into()), None, move |st| {
            Ok(st.grant_remote(grant))
        })
    };
    let r = match how {
        "revoked" => {
            d.handle(Request::RemoteRevoke {
                machine: "laptop".into(),
                project: None,
                passphrase: pw("pw"),
            })
            .await
        }
        "narrowed" => rewrite(&["rc"], None).await.unwrap(),
        "expired" => rewrite(&[env], Some(1)).await.unwrap(),
        "rotated" => {
            let r = d
                .handle(Request::RemoteRotate {
                    machine: "laptop".into(),
                    project: "widget".parse().unwrap(),
                    passphrase: pw("pw"),
                })
                .await;
            assert!(matches!(r, Response::RemoteGranted { .. }), "{r:?}");
            return;
        }
        _ => unreachable!("{how}"),
    };
    assert!(matches!(r, Response::Store { .. }), "{how}: {r:?}");
}

/// A grant that ends while its machine's request for a marked environment
/// waits in the app is checked again after approval: nothing goes out.
#[tokio::test]
async fn a_grant_lost_while_a_prompt_waits_gets_nothing() {
    for how in ["revoked", "narrowed", "expired", "rotated"] {
        let (_tmp, _log, d, _) = remote_daemon().await;
        let me = granted(&d, &["prod"]).await;
        let app = tokio::spawn({
            let d = d.clone();
            async move { d.handle(Request::WaitApprovals { known: Vec::new() }).await }
        });
        tokio::task::yield_now().await;
        let asked = tokio::spawn({
            let (d, me) = (d.clone(), me.clone());
            async move { d.handle_from(remote_run("prod"), &me).await }
        });
        let Response::Approvals { pending } = app.await.unwrap() else {
            panic!("not approvals");
        };
        assert_eq!(pending.len(), 1, "{how}");

        lose_grant(&d, how, "prod", &me).await;
        let r = d
            .handle(Request::Approve {
                id: pending[0].id,
                passphrase: Some(pw("pw")),
                values: Vec::new(),
            })
            .await;
        assert_eq!(r, Response::Approvals { pending: vec![] }, "{how}");
        let e = error(asked.await.unwrap());
        assert_eq!(e.code, ErrorCode::PermissionDenied, "{how}: {e:?}");
        assert!(e.message.contains("remote grant"), "{how}: {e:?}");
        assert!(!e.message.contains("widget.prod value"), "{how}: {e:?}");
    }
}

/// A grant that ends while its machine's run of an unmarked environment
/// waits on a fetch is checked again before the values go out.
#[tokio::test]
async fn a_grant_lost_while_a_fetch_waits_gets_nothing() {
    for how in ["kept", "revoked", "narrowed", "expired", "rotated"] {
        let c = Canary::new();
        let fake = dev_sources(&c);
        let tmp = tempfile::tempdir().unwrap();
        let file = StoreFile::new(tmp.path().join(STORE_FILE)).with_test_work_factor();
        let pass = Passphrase::new("pw".into());
        file.create(&pass).unwrap();
        file.update(&pass, None, |st| {
            st.set_remote_enabled(true);
            st.grant_remote(stored_grant(&["dev"], None));
            Ok(())
        })
        .unwrap();
        let project = parse_project(Path::new("/cfg/projects/widget.toml"), WIDGET).unwrap();
        let registry = Registry::new(Config::default(), vec![project]).unwrap();
        let d = Daemon::new(Box::new(move || Ok(registry.clone())), fake.clone(), file)
            .with_tailnet(Arc::new(crate::tailnet::fake::FakeTailnet::running(&[(
                "nLAPTOP", "laptop",
            )])));
        d.unlock(Some(pass)).await.unwrap();
        let me = laptop_with("nLAPTOP", Some(TOKEN));

        let gate = fake.hold();
        let asked = tokio::spawn({
            let (d, me) = (d.clone(), me.clone());
            async move { d.handle_from(remote_run("dev"), &me).await }
        });
        settle().await;
        assert!(fake.fetches() > 0, "{how}: waiting on a fetch");
        if how != "kept" {
            lose_grant(&d, how, "dev", &me).await;
        }
        gate.open();
        match asked.await.unwrap() {
            Response::RunEnv(reply) => {
                assert_eq!(how, "kept", "values went out");
                assert_eq!(reply.vars[0].value.expose(), c.value());
            }
            Response::Error(e) => {
                assert_ne!(how, "kept", "{e:?}");
                assert_eq!(e.code, ErrorCode::PermissionDenied, "{how}: {e:?}");
                assert!(e.message.contains("remote grant"), "{how}: {e:?}");
                assert_no_canary(&c, &format!("{e:?}"));
            }
            other => panic!("{how}: {other:?}"),
        }
    }
}

/// Only this machine's own use keeps it unlocked.
#[tokio::test]
async fn remote_runs_do_not_reset_the_idle_timer() {
    let (_tmp, _log, d, _) = remote_daemon().await;
    let me = granted(&d, &["dev"]).await;
    tokio::time::pause();
    tokio::time::sleep(IDLE.checked_sub(MINUTE).unwrap()).await;
    let r = d.handle_from(remote_run("dev"), &me).await;
    assert!(matches!(r, Response::RunEnv(_)), "{r:?}");
    tokio::time::sleep(2 * MINUTE).await;
    assert!(d.is_locked());
}

/// Being the granted machine on the tailnet is not enough: a grant is used
/// with the token it was made with, which the daemon says once and keeps
/// only the hash of. A new token ends the old one, a grant of another
/// project has its own, and a grant with none, made before grants had
/// tokens, lets nothing through. No token reaches the audit log.
#[tokio::test]
async fn a_grant_is_used_with_its_token() {
    let (_tmp, log, d, _) = remote_daemon().await;
    let token = token_of(d.handle(grant(&["dev"], None)).await);
    assert!(
        token.starts_with(crate::store::TOKEN_PREFIX) && token.len() == 68,
        "{}",
        token.len()
    );
    let me = laptop_with("nLAPTOP", Some(&token));
    let r = d.handle_from(remote_run("dev"), &me).await;
    assert!(matches!(r, Response::RunEnv(_)), "{r:?}");

    let none = laptop_with("nLAPTOP", None);
    let wrong = laptop_with("nLAPTOP", Some("kbr_guessed"));
    let asks = || {
        [
            remote_run("dev"),
            Request::Status { facts: None },
            Request::Diff {
                facts: facts(None, Some(&["A"])),
            },
        ]
    };
    for (req, again) in asks().into_iter().zip(asks()) {
        let e = error(d.handle_from(req, &none).await);
        assert_eq!(e.code, ErrorCode::PermissionDenied, "{e:?}");
        assert_eq!(
            e.message,
            "machine laptop sent no token, and a remote grant is used with its token"
        );
        assert!(
            e.hint
                .as_deref()
                .unwrap()
                .contains("KAGEBUNSHIN_REMOTE_TOKEN"),
            "{e:?}"
        );
        let e = error(d.handle_from(again, &wrong).await);
        assert_eq!(e.code, ErrorCode::PermissionDenied, "{e:?}");
        assert_eq!(
            e.message,
            "the token machine laptop sent is not the token of a remote grant it has"
        );
        assert_eq!(
            e.hint.as_deref(),
            Some(
                "on the daemon's machine, run `kagebunshin remote rotate laptop <project>` for \
                 a new one"
            )
        );
    }

    // A new token, by the machine's name or its node id: the old one ends.
    let rotate = |machine: &str, pass: &str| Request::RemoteRotate {
        machine: machine.into(),
        project: "widget".parse().unwrap(),
        passphrase: pw(pass),
    };
    assert_eq!(
        error_code(d.handle(rotate("laptop", "wrong")).await),
        ErrorCode::WrongPassphrase
    );
    assert_eq!(
        error_code(d.handle(rotate("desktop", "pw")).await),
        ErrorCode::Store
    );
    let r = d.handle_from(rotate("laptop", "pw"), &me).await;
    assert_eq!(error_code(r), ErrorCode::PermissionDenied, "not remotely");
    let r = d.handle_from(remote_run("dev"), &me).await;
    assert!(
        matches!(r, Response::RunEnv(_)),
        "refused, it changed nothing"
    );
    let mut last = token.clone();
    for machine in ["LAPTOP", "nLAPTOP"] {
        let r = d.handle(rotate(machine, "pw")).await;
        assert!(
            matches!(
                &r,
                Response::RemoteGranted {
                    change: Change::Replaced,
                    machine,
                    ..
                } if machine == "laptop"
            ),
            "{r:?}"
        );
        let next = token_of(r);
        assert_ne!(next, last);
        let e = error(
            d.handle_from(remote_run("dev"), &laptop_with("nLAPTOP", Some(&last)))
                .await,
        );
        assert!(
            e.message.starts_with("the token machine laptop sent"),
            "{e:?}"
        );
        let r = d
            .handle_from(remote_run("dev"), &laptop_with("nLAPTOP", Some(&next)))
            .await;
        assert!(matches!(r, Response::RunEnv(_)), "{r:?}");
        last = next;
    }

    // Granting again gives a new token too, and what the grant now covers.
    let again = token_of(d.handle(grant(&["prod"], None)).await);
    let e = error(
        d.handle_from(remote_run("dev"), &laptop_with("nLAPTOP", Some(&last)))
            .await,
    );
    assert!(
        e.message.starts_with("the token machine laptop sent"),
        "{e:?}"
    );
    let e = error(
        d.handle_from(remote_run("dev"), &laptop_with("nLAPTOP", Some(&again)))
            .await,
    );
    assert_eq!(
        e.message,
        "machine laptop has no remote grant for environment dev of project widget"
    );

    // A grant from before grants had tokens: nobody has what it takes.
    d.store_write(Passphrase::new("pw".into()), None, |st| {
        Ok(st.grant_remote(crate::store::RemoteGrant {
            token: None,
            ..stored_grant(&["dev"], None)
        }))
    })
    .await
    .unwrap();
    for caller in [none, wrong, laptop_with("nLAPTOP", Some(&again))] {
        let e = error(d.handle_from(remote_run("dev"), &caller).await);
        assert_eq!(e.code, ErrorCode::PermissionDenied, "{e:?}");
        assert!(e.message.contains("token"), "{e:?}");
    }
    let Response::Status(report) = d.handle(Request::Status { facts: None }).await else {
        panic!("status");
    };
    assert!(!report.remote.unwrap().grants[0].token);

    // Granting and rotating are recorded; no token is, nor a hash of one.
    let (events, _) = log.read().unwrap();
    let text = format!("{events:?}");
    assert!(
        events
            .iter()
            .any(|e| e.action == "remote rotate" && e.target.as_deref() == Some("machine laptop")),
        "{text}"
    );
    for secret in [&token, &last, &again] {
        assert!(!text.contains(secret.as_str()), "{text}");
    }
    assert!(
        events
            .iter()
            .all(|e| { e.remote.as_ref().is_none_or(|peer| peer.token.is_none()) })
    );
}

/// A machine with grants for two projects uses each with its own token.
#[tokio::test]
async fn a_token_is_one_grants() {
    let (_tmp, _log, d, _) = remote_daemon().await;
    let me = granted(&d, &["dev"]).await;
    d.store_write(Passphrase::new("pw".into()), None, |st| {
        Ok(st.grant_remote(crate::store::RemoteGrant {
            project: "gadget".parse().unwrap(),
            ..stored_grant(&["dev"], None)
        }))
    })
    .await
    .unwrap();
    let other = laptop_with("nLAPTOP", Some(TOKEN));
    let r = d.handle_from(remote_run("dev"), &me).await;
    assert!(matches!(r, Response::RunEnv(_)), "{r:?}");
    let e = error(d.handle_from(remote_run("dev"), &other).await);
    assert_eq!(
        e.message,
        "machine laptop has no remote grant for environment dev of project widget"
    );
}

/// The endpoint on a loopback port, every connection taken as laptop's;
/// a reply that is not ready gets a newline every `heartbeat`.
async fn endpoint(
    d: &Daemon,
    tailnet: &Arc<crate::tailnet::fake::FakeTailnet>,
    heartbeat: Duration,
) -> std::net::SocketAddr {
    use crate::ipc::remote::{Want, connection};
    let laptop: std::net::SocketAddr = "100.64.0.9:41000".parse().unwrap();
    tailnet.set_whois(laptop, Ok(("nLAPTOP", "laptop", "dev@example.com", &[])));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let at = Arc::new(Want::new(
        addr.ip(),
        addr.port(),
        "nSELF".into(),
        "self.example.ts.net.",
    ));
    let cfg = Arc::new(crate::ipc::server::ServerConfig {
        heartbeat,
        ..crate::ipc::server::ServerConfig::new("/nonexistent/kagebunshin-test/sock".into())
    });
    let (d, tailnet) = (d.clone(), tailnet.clone());
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let (at, cfg, d, tailnet) = (at.clone(), cfg.clone(), d.clone(), tailnet.clone());
            tokio::spawn(async move {
                connection(stream, laptop, &at, tailnet.as_ref(), &cfg, &d).await;
            });
        }
    });
    addr
}

/// What the CLI's client gets for `req` from the endpoint at `addr`,
/// sending `token`; it gives up after `silence` of nothing.
async fn over_http(
    addr: std::net::SocketAddr,
    token: Option<&str>,
    silence: Duration,
    req: Request,
) -> Result<Response, crate::ipc::client::ClientError> {
    use crate::ipc::client::Client;
    let token = token.map(str::to_owned);
    tokio::task::spawn_blocking(move || {
        let host = addr.ip().to_string();
        Client::connect_remote(
            "desk",
            addr,
            &host,
            token.as_deref(),
            Duration::from_secs(5),
        )?
        .with_silence(silence)
        .request(req)
    })
    .await
    .unwrap()
}

/// The whole way, as `--machine` goes it: the CLI's client, HTTP over
/// TCP, the endpoint, the daemon. The token picks the grant; a run that
/// waits for approval in the app is kept alive until it is answered.
#[tokio::test]
async fn the_cli_reaches_a_grant_over_http() {
    use crate::ipc::client::ClientError;
    let (_tmp, _log, d, tailnet) = remote_daemon().await;
    let token = token_of(d.handle(grant(&["dev", "prod"], None)).await);
    let addr = endpoint(&d, &tailnet, Duration::from_millis(10)).await;
    let patient = Duration::from_secs(5);

    let r = over_http(addr, None, patient, Request::Ping).await;
    assert_eq!(r.unwrap(), Response::Pong);
    for (sent, why) in [
        (None, "machine laptop sent no token"),
        (Some("kbr_guessed"), "the token machine laptop sent is not"),
    ] {
        let e = over_http(addr, sent, patient, remote_run("dev")).await;
        let Err(ClientError::Daemon(e)) = e else {
            panic!("{e:?}");
        };
        assert_eq!(e.code, ErrorCode::PermissionDenied);
        assert!(e.message.starts_with(why), "{e:?}");
    }
    let r = over_http(addr, Some(&token), patient, remote_run("dev")).await;
    let Ok(Response::RunEnv(reply)) = r else {
        panic!("{r:?}");
    };
    assert_eq!(reply.vars[0].value.expose(), "widget.dev value");
    let r = over_http(addr, Some(&token), patient, store_set("A", "v", "pw")).await;
    let Err(ClientError::Daemon(e)) = r else {
        panic!("{r:?}");
    };
    assert!(
        e.message.ends_with("only run, status and diff work"),
        "{e:?}"
    );

    // Marked sensitive: it waits, through many heartbeats, for the app.
    let asked = tokio::spawn({
        let token = token.clone();
        async move { over_http(addr, Some(&token), patient, remote_run("prod")).await }
    });
    let Response::Approvals { pending } =
        d.handle(Request::WaitApprovals { known: Vec::new() }).await
    else {
        panic!("not approvals");
    };
    let [prompt] = &pending[..] else {
        panic!("{pending:?}")
    };
    assert_eq!(prompt.remote, Some(laptop_peer("nLAPTOP")));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!asked.is_finished());
    let r = d
        .handle(Request::Approve {
            id: prompt.id,
            passphrase: Some(pw("pw")),
            values: Vec::new(),
        })
        .await;
    assert_eq!(r, Response::Approvals { pending: vec![] });
    let r = asked.await.unwrap();
    let Ok(Response::RunEnv(reply)) = r else {
        panic!("{r:?}");
    };
    assert_eq!(reply.vars[0].value.expose(), "widget.prod value");
}

/// A reply that says nothing for too long is given up on, whatever is in
/// between the two machines; the caller gone, its prompt goes too.
#[tokio::test]
async fn a_silent_endpoint_is_given_up_on() {
    use crate::ipc::client::ClientError;
    let (_tmp, _log, d, tailnet) = remote_daemon().await;
    let token = token_of(d.handle(grant(&["prod"], None)).await);
    let addr = endpoint(&d, &tailnet, Duration::from_secs(600)).await;
    let asked = tokio::spawn(async move {
        let silence = Duration::from_millis(200);
        over_http(addr, Some(&token), silence, remote_run("prod")).await
    });
    let Response::Approvals { pending } =
        d.handle(Request::WaitApprovals { known: Vec::new() }).await
    else {
        panic!("not approvals");
    };
    assert_eq!(pending.len(), 1);
    let r = asked.await.unwrap();
    let Err(ClientError::Remote { machine, reason }) = r else {
        panic!("{r:?}");
    };
    assert_eq!(machine, "desk");
    assert!(reason.starts_with("nothing arrived for"), "{reason}");
    let known = vec![pending[0].id];
    let gone = tokio::time::timeout(
        Duration::from_secs(5),
        d.handle(Request::WaitApprovals { known }),
    )
    .await
    .expect("the prompt is still there");
    assert_eq!(gone, Response::Approvals { pending: vec![] });
}

/// `sensitive` flags in a project file are copied into the store at
/// unlock, so deleting them later changes nothing. Without a store there is
/// nowhere to keep them, and unlock fails.
#[tokio::test]
async fn unlock_copies_project_file_flags_into_the_store() {
    let tmp = tempfile::tempdir().unwrap();
    let file = StoreFile::new(tmp.path().join(STORE_FILE)).with_test_work_factor();
    let head = "schema = 1\nremotes = [\"git@github.com:acme/widget.git\"]\n";
    let text = Arc::new(Mutex::new(format!(
        "{head}[envs.live]\nsensitive = true\n[[envs.live.sources]]\nprovider = \"aws_sm\"\n\
         prefix = \"acme/live/\"\n[[envs.dev.sources]]\nprovider = \"aws_sm\"\n\
         prefix = \"acme/dev/\"\nsensitive = [\"acme/dev/payroll\"]\n"
    )));
    let d = Daemon::new(
        Box::new({
            let text = text.clone();
            move || {
                let path = Path::new("/cfg/projects/widget.toml");
                let project = parse_project(path, &text.lock().unwrap()).unwrap();
                Registry::new(Config::default(), vec![project])
            }
        }),
        Arc::new(super::Providers::new()),
        file.clone(),
    );
    assert!(matches!(d.unlock(None).await, Err(ResolveError::Config(_))));
    assert!(d.is_locked());

    let pass = || Passphrase::new("pw".into());
    file.create(&pass()).unwrap();
    d.unlock(Some(pass())).await.unwrap();
    d.lock();
    *text.lock().unwrap() = format!("{head}[envs.live]\n[envs.dev]\n");
    d.unlock(Some(pass())).await.unwrap();
    let st = file.open(&pass()).unwrap();
    assert!(st.env_marked(&"widget".parse().unwrap(), &"live".parse().unwrap()));
    assert_eq!(
        st.marked_secrets().collect::<Vec<_>>(),
        [&sm("acme/dev/payroll")]
    );
    assert_eq!(
        st.marked_prefixes().collect::<Vec<_>>(),
        [&sm("acme/live/")],
        "marked along with its environment"
    );
}

/// Environments a project file flags `sensitive` mark their sources as a
/// human's mark does: what an open environment reads too is left. One
/// flagged environment is not open to another, whichever comes first.
#[tokio::test]
async fn flagged_environments_leave_what_an_open_one_reads() {
    let tmp = tempfile::tempdir().unwrap();
    let file = StoreFile::new(tmp.path().join(STORE_FILE)).with_test_work_factor();
    let text = r#"
schema = 1
remotes = ["git@github.com:acme/widget.git"]

[envs.alpha]
sensitive = true
sources = [{ provider = "aws_sm", secrets = ["both-flagged", "with-open", "alone"] }]

[envs.beta]
sensitive = true
sources = [{ provider = "aws_sm", secrets = ["both-flagged"] }]

[envs.dev]
sources = [{ provider = "aws_sm", secrets = ["with-open"] }]
"#;
    let project = parse_project(Path::new("/cfg/projects/widget.toml"), text).unwrap();
    let registry = Registry::new(Config::default(), vec![project]).unwrap();
    let d = Daemon::new(
        Box::new(move || Ok(registry.clone())),
        Arc::new(super::Providers::new()),
        file.clone(),
    );
    let pass = || Passphrase::new("pw".into());
    file.create(&pass()).unwrap();
    d.unlock(Some(pass())).await.unwrap();
    let st = file.open(&pass()).unwrap();
    assert_eq!(
        st.marked_secrets().collect::<Vec<_>>(),
        [&sm("alone"), &sm("both-flagged")]
    );
}

/// An approval releases only what its prompt named: if the environment's
/// sources, or the keys marked sensitive, change while the person reads
/// it, nothing is handed out. (Its environment's name does not look like
/// production, which would make the whole of it wait.)
#[tokio::test]
async fn an_approval_is_void_if_what_it_named_changed() {
    let canary = Canary::new();
    let tmp = tempfile::tempdir().unwrap();
    let file = StoreFile::new(tmp.path().join(STORE_FILE)).with_test_work_factor();
    let text = Arc::new(Mutex::new(String::from(
        "schema = 1\nremotes = [\"git@github.com:acme/widget.git\"]\n[envs.qa]\n",
    )));
    let d = Daemon::new(
        Box::new({
            let text = text.clone();
            move || {
                let path = Path::new("/cfg/projects/widget.toml");
                let project = parse_project(path, &text.lock().unwrap()).unwrap();
                let config = Config {
                    default_provider: Provider::File,
                    ..Config::default()
                };
                Registry::new(config, vec![project])
            }
        }),
        Arc::new(super::Providers::new()),
        file.clone(),
    );
    init(&file, &d).await;
    for (section, k, sensitive) in [("widget.qa", "A", true), ("widget.qa", "B", false)] {
        let set = d
            .handle(Request::StoreSet {
                section: section.parse().unwrap(),
                key: key(k),
                value: WireSecret::new(canary.value().into()),
                passphrase: pw("pw"),
                sensitive,
            })
            .await;
        assert!(matches!(set, Response::Store { .. }), "{set:?}");
    }
    let run = || Request::RunEnv {
        facts: facts(Some("qa"), None),
        program: None,
        command: vec!["deploy".into()],
    };
    let approve = |id| Request::Approve {
        id,
        passphrase: Some(pw("pw")),
        values: Vec::new(),
    };

    // The project file now points rc at another section.
    let (asked, pending) = asked_in_the_app(&d, run()).await;
    assert_eq!(pending[0].keys, [key("A")]);
    *text.lock().unwrap() = "schema = 1\nremotes = [\"git@github.com:acme/widget.git\"]\n\
         [[envs.qa.sources]]\nprovider = \"file\"\nsecret = \"widget.other\"\n"
        .into();
    let r = d.handle(approve(pending[0].id)).await;
    assert_eq!(r, Response::Approvals { pending: vec![] });
    let Response::Error(e) = asked.await.unwrap() else {
        panic!("handed out what was not approved");
    };
    assert_eq!(e.code, ErrorCode::NotApproved);
    assert!(e.message.contains("changed while waiting"), "{}", e.message);

    // Another key is marked sensitive while it waits.
    *text.lock().unwrap() =
        "schema = 1\nremotes = [\"git@github.com:acme/widget.git\"]\n[envs.qa]\n".into();
    let (asked, pending) = asked_in_the_app(&d, run()).await;
    assert_eq!(pending[0].keys, [key("A")]);
    let set = d
        .handle(Request::StoreSet {
            section: "widget.qa".parse().unwrap(),
            key: key("B"),
            value: WireSecret::new(canary.value().into()),
            passphrase: pw("pw"),
            sensitive: true,
        })
        .await;
    assert!(matches!(set, Response::Store { .. }), "{set:?}");
    let r = d.handle(approve(pending[0].id)).await;
    assert_eq!(r, Response::Approvals { pending: vec![] });
    assert_eq!(error_code(asked.await.unwrap()), ErrorCode::NotApproved);

    // Unchanged, the same approval hands both out.
    let (asked, pending) = asked_in_the_app(&d, run()).await;
    assert_eq!(pending[0].keys, [key("A"), key("B")]);
    d.handle(approve(pending[0].id)).await;
    let Response::RunEnv(reply) = asked.await.unwrap() else {
        panic!("not approved");
    };
    assert_eq!(reply.vars.len(), 2);
}

/// Pointing the default environment at other sources, syncing, and
/// restoring the file while the prompt waits leaves the other sources'
/// values cached under the same environment. The approval does not hand
/// them out: what goes out is fetched from the sources it named.
#[tokio::test]
async fn an_approval_hands_out_only_values_from_the_sources_it_named() {
    let canary = Canary::new();
    let tmp = tempfile::tempdir().unwrap();
    let file = StoreFile::new(tmp.path().join(STORE_FILE)).with_test_work_factor();
    let original = "schema = 1\nremotes = [\"git@github.com:acme/widget.git\"]\n[envs.dev]\n";
    let text = Arc::new(Mutex::new(String::from(original)));
    let d = Daemon::new(
        Box::new({
            let text = text.clone();
            move || {
                let path = Path::new("/cfg/projects/widget.toml");
                let project = parse_project(path, &text.lock().unwrap()).unwrap();
                let config = Config {
                    default_provider: Provider::File,
                    ..Config::default()
                };
                Registry::new(config, vec![project])
            }
        }),
        Arc::new(super::Providers::new()),
        file.clone(),
    );
    let pass = Passphrase::new("pw".into());
    file.create(&pass).unwrap();
    d.unlock(Some(pass)).await.unwrap();
    for (section, value, sensitive) in [
        ("widget.dev", "approved", true),
        ("widget.prod", canary.value(), false),
    ] {
        let set = d
            .handle(Request::StoreSet {
                section: section.parse().unwrap(),
                key: key("API_KEY"),
                value: WireSecret::new(value.into()),
                passphrase: pw("pw"),
                sensitive,
            })
            .await;
        assert!(matches!(set, Response::Store { .. }), "{set:?}");
    }
    // No `--env`: dev is the default environment.
    let run = Request::RunEnv {
        facts: facts(None, None),
        program: None,
        command: vec!["deploy".into()],
    };
    let (asked, pending) = asked_in_the_app(&d, run).await;
    assert_eq!(pending[0].keys, [key("API_KEY")]);

    *text.lock().unwrap() =
        format!("{original}[[envs.dev.sources]]\nprovider = \"file\"\nsecret = \"widget.prod\"\n");
    let synced = d
        .handle(Request::Sync {
            project: Some("widget".parse().unwrap()),
            env: None,
        })
        .await;
    assert!(matches!(synced, Response::Sync(_)), "{synced:?}");
    *text.lock().unwrap() = original.into();

    let r = d
        .handle(Request::Approve {
            id: pending[0].id,
            passphrase: Some(pw("pw")),
            values: Vec::new(),
        })
        .await;
    assert_eq!(r, Response::Approvals { pending: vec![] });
    let out = asked.await.unwrap();
    assert_clean(&canary, &out);
    let Response::RunEnv(reply) = out else {
        panic!("not approved: {out:?}");
    };
    let handed: Vec<_> = reply
        .vars
        .iter()
        .map(|v| (v.key.as_str(), v.value.expose()))
        .collect();
    assert_eq!(handed, [("API_KEY", "approved")]);
}

/// A fix that takes the store's passphrase or a login is the human's, and
/// the CLI is told so with the hint as what to ask them.
#[test]
fn source_fixes_say_who_makes_them() {
    use super::resolve::source_who;
    use crate::ipc::protocol::Who;
    use crate::source::SourceError;
    let name = "widget.dev".to_owned();
    assert_eq!(source_who(&SourceError::NoSection { name }), Who::Human);
    let hint = "set its keys with `kagebunshin store set widget.dev KEY...`, naming every key";
    let err = ResolveError::Sources {
        project: "widget".parse().unwrap(),
        env: "dev".parse().unwrap(),
        failures: vec!["the file source secret widget.dev: no section".into()],
        hint: Some(hint.into()),
        who: Some(Who::Human),
    };
    let wire = super::broker::wire_error(&err);
    assert_eq!(wire.code, ErrorCode::SourceFailed);
    assert_eq!(
        (wire.who, wire.tell.as_deref()),
        (Some(Who::Human), Some(hint))
    );
    // Unknown who: neither is said.
    let err = ResolveError::Sources {
        project: "widget".parse().unwrap(),
        env: "dev".parse().unwrap(),
        failures: vec!["x".into()],
        hint: None,
        who: None,
    };
    let wire = super::broker::wire_error(&err);
    assert_eq!((wire.who, wire.tell), (None, None));
}

/// The commands a `status` with `facts` suggests, and who runs each.
async fn fixes_of(d: &Daemon, facts: Facts) -> Vec<(String, crate::ipc::protocol::Who)> {
    let r = d.handle(Request::Status { facts: Some(facts) }).await;
    let Response::Status(StatusReport { env: Some(env), .. }) = r else {
        panic!("{r:?}")
    };
    env.fixes.into_iter().map(|f| (f.command, f.who)).collect()
}

/// A key `.env.example` gives a value is left out of `store set`, as the
/// CLI suggests `project set-var` for it; with an env file here and an
/// empty section as the only source, the human's fix is `onboard`.
#[tokio::test]
async fn store_fixes_leave_out_valued_keys_and_offer_onboard() {
    use crate::ipc::protocol::Who;
    const STORE_ONLY: &str = r#"
schema = 1
remotes = ["git@github.com:acme/widget.git"]
[envs.dev]
[envs.staging]
"#;
    // The fake ignores the local store, so it is seeded to match it.
    let fake = FakeSources::new();
    fake.set("widget.dev", &[]);
    fake.set("widget.staging", &[]);
    let (_tmp, d) = marked_daemon(STORE_ONLY, &fake, |_| {}).await;
    let mut f = facts(None, Some(&["DB_URL", "PORT", "TOKEN"]));
    f.example_values = vec![key("PORT")];
    assert_eq!(
        fixes_of(&d, f.clone()).await,
        [(
            "kagebunshin store set widget.dev DB_URL TOKEN".into(),
            Who::Human
        )]
    );
    f.env_file = Some(".env".into());
    assert_eq!(
        fixes_of(&d, f.clone()).await,
        [(
            "kagebunshin onboard /src/widget/apps/web".into(),
            Who::Human
        )]
    );
    f.env = Some("dev".parse().unwrap());
    assert_eq!(
        fixes_of(&d, f.clone()).await,
        [(
            "kagebunshin onboard --env dev /src/widget/apps/web".into(),
            Who::Human
        )]
    );
    // The env file is taken to be for the default environment: another
    // one is filled key by key.
    f.env = Some("staging".parse().unwrap());
    assert_eq!(
        fixes_of(&d, f.clone()).await,
        [(
            "kagebunshin store set widget.staging DB_URL TOKEN".into(),
            Who::Human
        )]
    );
    // Only valued keys are missing: nothing for the store.
    f.example_keys = Some(vec![key("PORT")]);
    assert_eq!(fixes_of(&d, f).await, []);

    // A section that has keys already is filled key by key.
    fake.set("widget.dev", &[("OTHER", "x")]);
    let (_tmp, d) = marked_daemon(STORE_ONLY, &fake, |st| {
        st.set(
            "widget.dev".parse().unwrap(),
            key("OTHER"),
            SecretValue::new("x".into()),
        );
    })
    .await;
    let mut f = facts(None, Some(&["DB_URL"]));
    f.env_file = Some(".env".into());
    assert_eq!(
        fixes_of(&d, f).await,
        [("kagebunshin store set widget.dev DB_URL".into(), Who::Human)]
    );
}

/// A source edit takes effect at the next request: values cached from the
/// sources the project file named before are not used, and nothing has to
/// `sync`. With the sources unchanged, the cache is.
#[tokio::test]
async fn a_source_edit_is_fetched_without_a_sync() {
    let c = Canary::new();
    let fake = FakeSources::new();
    fake.set("widget/one", &[("A", c.value())])
        .set("widget/two", &[("B", c.value())]);
    let head = "schema = 1\nremotes = [\"git@github.com:acme/widget.git\"]\n";
    let source = |secret: &str| {
        format!("[[envs.dev.sources]]\nprovider = \"aws_sm\"\nsecret = \"{secret}\"\n")
    };
    let text = Arc::new(Mutex::new(format!("{head}{}", source("widget/one"))));
    let d = Daemon::new(
        Box::new({
            let text = text.clone();
            move || {
                let path = Path::new("/cfg/projects/widget.toml");
                let project = parse_project(path, &text.lock().unwrap())?;
                Registry::new(Config::default(), vec![project])
            }
        }),
        fake.clone(),
        StoreFile::new("/nonexistent/kagebunshin-test/store.age"),
    );
    d.unlock(None).await.unwrap();
    let keys = || async {
        let env = d.status(Some(facts(None, None))).await.unwrap().env;
        let keys: Vec<_> = env.unwrap().keys.into_iter().map(|k| k.key).collect();
        keys
    };
    assert_eq!(keys().await, [key("A")]);
    let fetched = fake.fetches();
    assert_eq!(keys().await, [key("A")]);
    assert_eq!(fake.fetches(), fetched, "unchanged sources use the cache");

    *text.lock().unwrap() = format!("{head}{}{}", source("widget/one"), source("widget/two"));
    assert_eq!(keys().await, [key("A"), key("B")]);
    assert!(fake.fetches() > fetched);
    let fetched = fake.fetches();
    let run = d.run_env(&facts(None, None)).await.unwrap();
    assert_eq!(run.vars.len(), 2);
    assert_eq!(fake.fetches(), fetched, "the new values are cached in turn");
}

/// A daemon with a store, an audit log and `approval_timeout`.
fn import_daemon(timeout: &str) -> (tempfile::TempDir, crate::audit::AuditLog, StoreFile, Daemon) {
    let tmp = tempfile::tempdir().unwrap();
    let file = StoreFile::new(tmp.path().join(STORE_FILE)).with_test_work_factor();
    let project = parse_project(Path::new("/cfg/projects/widget.toml"), STORED).unwrap();
    let config = Config {
        default_provider: Provider::File,
        approval_timeout: timeout.to_owned().try_into().unwrap(),
        ..Config::default()
    };
    let registry = Registry::new(config, vec![project]).unwrap();
    let log = state_log(tmp.path());
    let d = Daemon::new(
        Box::new(move || Ok(registry.clone())),
        Arc::new(super::Providers::new()),
        file.clone(),
    )
    .with_audit(log.clone());
    (tmp, log, file, d)
}

fn import_section(
    section: &str,
    values: &[(&str, &str)],
    if_empty: bool,
) -> crate::ipc::protocol::ImportSection {
    crate::ipc::protocol::ImportSection {
        section: section.parse().unwrap(),
        values: values.iter().map(|(k, v)| (key(k), pw(v))).collect(),
        files: vec![PathBuf::from("/src/widget/.env")],
        into: crate::ipc::protocol::ImportInto::Existing,
        if_empty,
    }
}

fn import(sections: Vec<crate::ipc::protocol::ImportSection>, pass: Option<&str>) -> Request {
    Request::StoreImport {
        sections,
        passphrase: pass.map(pw),
        cwd: "/src/widget".into(),
        command: vec!["kagebunshin".into(), "onboard".into()],
    }
}

fn written(r: Response) -> Vec<(String, bool, Vec<String>)> {
    let Response::Imported { sections, .. } = r else {
        panic!("{r:?}")
    };
    sections
        .into_iter()
        .map(|s| {
            let replaced = s.replaced.iter().map(ToString::to_string).collect();
            (s.section.to_string(), s.written, replaced)
        })
        .collect()
}

/// With the passphrase, as `onboard` in a terminal sends it, an import is
/// written at once, all of it or none, and says what it replaced.
#[tokio::test]
async fn an_import_with_the_passphrase_is_written_at_once() {
    let c = Canary::new();
    let (_tmp, log, file, d) = import_daemon("5m");
    init(&file, &d).await;
    let set = d.handle(store_set("A", "old", "pw")).await;
    assert!(matches!(set, Response::Store { .. }), "{set:?}");

    let wrong = d
        .handle(import(
            vec![import_section("widget.dev", &[("A", c.value())], false)],
            Some("nope"),
        ))
        .await;
    assert_clean(&c, &wrong);
    assert_eq!(error_code(wrong), ErrorCode::WrongPassphrase);

    let r = d
        .handle(import(
            vec![
                // A later value for a key is the one kept.
                import_section(
                    "widget.dev",
                    &[("A", "first"), ("B", c.value()), ("A", "last")],
                    false,
                ),
                import_section("widget.local", &[("C", "c")], true),
            ],
            Some("pw"),
        ))
        .await;
    assert_clean(&c, &r);
    assert_eq!(
        written(r),
        [
            ("widget.dev".to_owned(), true, vec!["A".to_owned()]),
            ("widget.local".to_owned(), true, vec![]),
        ]
    );
    let st = file.open(&Passphrase::new("pw".into())).unwrap();
    let dev = st.section(&"widget.dev".parse().unwrap()).unwrap();
    assert_eq!(dev[&key("A")].expose(), "last");
    assert_eq!(dev[&key("B")].expose(), c.value());

    // A section that already has keys is left as it is when asked so.
    let r = d
        .handle(import(
            vec![import_section(
                "widget.local",
                &[("C", "again"), ("D", "d")],
                true,
            )],
            Some("pw"),
        ))
        .await;
    assert_eq!(written(r), [("widget.local".to_owned(), false, vec![])]);
    assert_eq!(
        listing(&d),
        [
            (
                "widget.dev".to_owned(),
                vec!["A".to_owned(), "B".to_owned()]
            ),
            ("widget.local".to_owned(), vec!["C".to_owned()]),
        ]
    );
    assert_eq!(
        logged(&log),
        [
            "store set allowed",
            "store import denied",
            "store import allowed",
            "store import allowed",
        ]
    );
    let (events, _) = log.read().unwrap();
    assert_eq!(
        events[2].keys,
        ["widget.dev.A", "widget.dev.B", "widget.local.C"]
    );
    assert_no_canary(&c, &std::fs::read_to_string(log.path()).unwrap());
}

/// Without a passphrase, as an agent's `onboard` sends it, an import waits
/// for a person in the app: the prompt names every file, section and key,
/// and no value; the passphrase typed there writes it. A wrong one leaves
/// it waiting.
#[tokio::test]
async fn an_import_without_a_passphrase_waits_for_approval_in_the_app() {
    use crate::ipc::protocol::{ApprovalReason, ImportInto, ImportNames};
    let c = Canary::new();
    let (_tmp, log, file, d) = import_daemon("5m");
    init(&file, &d).await;
    let set = d.handle(store_set("A", "old", "pw")).await;
    assert!(matches!(set, Response::Store { .. }), "{set:?}");
    assert_eq!(
        listing(&d),
        [("widget.dev".to_owned(), vec!["A".to_owned()])]
    );

    let mut fresh = import_section("widget.rc", &[("N", "n")], true);
    fresh.into = ImportInto::NewEnv;
    fresh.files = vec!["/src/widget/.env.rc".into(), "/src/widget/more.env".into()];
    let (asked, pending) = asked_in_the_app(
        &d,
        import(
            vec![
                import_section(
                    "widget.dev",
                    &[("A", c.value()), ("B", "b"), ("A", "a")],
                    false,
                ),
                // Has keys already, and is to be left then: not asked about.
                import_section("widget.dev", &[("Z", "z")], true),
                fresh,
            ],
            None,
        ),
    )
    .await;
    let [prompt] = &pending[..] else {
        panic!("{pending:?}")
    };
    assert_clean(&c, prompt);
    assert_eq!(prompt.project.as_str(), "widget");
    assert_eq!(prompt.env.as_str(), "dev");
    assert_eq!(prompt.keys, []);
    assert_eq!(prompt.command, "kagebunshin onboard");
    assert_eq!(prompt.cwd, Path::new("/src/widget"));
    assert_eq!(
        prompt.reason,
        ApprovalReason::Import {
            sections: vec![
                ImportNames {
                    section: "widget.dev".parse().unwrap(),
                    files: vec!["/src/widget/.env".into()],
                    keys: vec![key("A"), key("B")],
                    into: ImportInto::Existing,
                    replaces: vec![key("A")],
                    if_empty: false,
                },
                ImportNames {
                    section: "widget.rc".parse().unwrap(),
                    files: vec!["/src/widget/.env.rc".into(), "/src/widget/more.env".into()],
                    keys: vec![key("N")],
                    into: ImportInto::NewEnv,
                    replaces: vec![],
                    if_empty: true,
                },
            ],
            unlock: false,
        }
    );

    let approve = |pass: &'static str| Request::Approve {
        id: prompt.id,
        passphrase: Some(pw(pass)),
        values: Vec::new(),
    };
    assert_eq!(
        error_code(d.handle(approve("nope")).await),
        ErrorCode::WrongPassphrase
    );
    assert!(!asked.is_finished(), "still waiting");
    let r = d.handle(approve("pw")).await;
    assert_eq!(r, Response::Approvals { pending: vec![] });
    let r = asked.await.unwrap();
    assert_clean(&c, &r);
    assert_eq!(
        written(r),
        [
            ("widget.dev".to_owned(), true, vec!["A".to_owned()]),
            ("widget.dev".to_owned(), false, vec![]),
            ("widget.rc".to_owned(), true, vec![]),
        ]
    );
    assert_eq!(
        listing(&d),
        [
            (
                "widget.dev".to_owned(),
                vec!["A".to_owned(), "B".to_owned()]
            ),
            ("widget.rc".to_owned(), vec!["N".to_owned()]),
        ]
    );
    assert_eq!(
        logged(&log),
        [
            "store set allowed",
            "ask approval allowed",
            "approve denied",
            "store import allowed",
        ]
    );
    let (events, _) = log.read().unwrap();
    assert_eq!(events[1].target.as_deref(), Some("store import"));
    assert_eq!(
        events[1].keys,
        [
            "widget.dev.A",
            "widget.dev.B",
            "widget.dev.Z",
            "widget.rc.N"
        ]
    );
    assert_no_canary(&c, &std::fs::read_to_string(log.path()).unwrap());

    // Nothing left to write: nobody is asked.
    let r = d
        .handle(import(
            vec![import_section("widget.dev", &[("Z", "z")], true)],
            None,
        ))
        .await;
    assert_eq!(written(r), [("widget.dev".to_owned(), false, vec![])]);
}

/// The passphrase that approves an import into a locked daemon unlocks it
/// too, and the prompt says it will: one passphrase for both.
#[tokio::test]
async fn approving_an_import_unlocks_a_locked_daemon() {
    use crate::ipc::protocol::ApprovalReason;
    let (_tmp, log, file, d) = import_daemon("5m");
    init(&file, &d).await;
    let set = d.handle(store_set("A", "old", "pw")).await;
    assert!(matches!(set, Response::Store { .. }), "{set:?}");
    d.lock();

    let (asked, pending) = asked_in_the_app(
        &d,
        import(
            vec![
                import_section("widget.dev", &[("B", "b")], true),
                import_section("widget.local", &[("C", "c")], true),
            ],
            None,
        ),
    )
    .await;
    let [prompt] = &pending[..] else {
        panic!("{pending:?}")
    };
    // Locked, the store cannot be seen: both are asked about.
    let ApprovalReason::Import { sections, unlock } = &prompt.reason else {
        panic!("{prompt:?}")
    };
    assert!(*unlock);
    assert_eq!(sections.len(), 2);
    assert!(sections.iter().all(|s| s.if_empty && s.replaces.is_empty()));

    let r = d
        .handle(Request::Approve {
            id: prompt.id,
            passphrase: Some(pw("pw")),
            values: Vec::new(),
        })
        .await;
    assert_eq!(r, Response::Approvals { pending: vec![] });
    let Response::Imported { sections, locked } = asked.await.unwrap() else {
        panic!("not imported");
    };
    assert!(!locked);
    assert!(!d.is_locked());
    assert_eq!(
        sections.iter().map(|s| s.written).collect::<Vec<_>>(),
        [false, true]
    );
    assert_eq!(
        listing(&d),
        [
            ("widget.dev".to_owned(), vec!["A".to_owned()]),
            ("widget.local".to_owned(), vec!["C".to_owned()]),
        ]
    );
    assert_eq!(
        logged(&log)[1..],
        [
            "ask approval allowed",
            "unlock allowed",
            "store import allowed",
        ]
    );
}

/// An import nobody approves writes nothing, and the log says how it
/// ended: refused in the app, not answered in time, or asked with no app
/// open, which is refused at once.
#[tokio::test]
async fn an_import_not_approved_writes_nothing() {
    let (_tmp, log, file, d) = import_daemon("1s");
    init(&file, &d).await;
    let ask = || {
        import(
            vec![import_section("widget.dev", &[("A", "a")], true)],
            None,
        )
    };

    // No app.
    let Response::Error(e) = d.handle(ask()).await else {
        panic!("imported");
    };
    assert_eq!(e.code, ErrorCode::NoApp);
    assert!(e.message.contains("nothing was imported"), "{}", e.message);
    assert_eq!(e.who, Some(crate::ipc::protocol::Who::Human));

    // Denied.
    let (asked, pending) = asked_in_the_app(&d, ask()).await;
    let r = d
        .handle(Request::Approve {
            id: pending[0].id,
            passphrase: None,
            values: Vec::new(),
        })
        .await;
    assert_eq!(r, Response::Approvals { pending: vec![] });
    let Response::Error(e) = asked.await.unwrap() else {
        panic!("imported");
    };
    assert_eq!(e.code, ErrorCode::NotApproved);
    assert_eq!(
        e.message,
        "a person refused the import in the app, so nothing was imported"
    );

    // Not answered.
    let (asked, pending) = asked_in_the_app(&d, ask()).await;
    assert_eq!(pending.len(), 1);
    let Response::Error(e) = asked.await.unwrap() else {
        panic!("imported");
    };
    assert_eq!(e.code, ErrorCode::NotApproved);
    assert_eq!(
        e.message,
        "nobody answered the app's prompt within 1 seconds, so nothing was imported"
    );
    let r = d
        .handle(Request::WaitApprovals {
            known: vec![pending[0].id],
        })
        .await;
    assert_eq!(
        r,
        Response::Approvals { pending: vec![] },
        "the prompt went"
    );

    assert_eq!(listing(&d), []);
    assert_eq!(
        logged(&log),
        [
            "store import denied",
            "ask approval allowed",
            "store import denied",
            "ask approval allowed",
            "store import timedout",
        ]
    );
}

/// `store set` with no terminal: asks for the values of `keys` of
/// [widget.dev] to be typed into the app.
fn ask_values(keys: &[&str]) -> Request {
    let command = ["kagebunshin", "store", "set", "widget.dev"];
    Request::StoreAsk {
        section: "widget.dev".parse().unwrap(),
        keys: keys.iter().map(|k| key(k)).collect(),
        cwd: "/src/widget".into(),
        command: command
            .iter()
            .chain(keys)
            .map(ToString::to_string)
            .collect(),
    }
}

/// What the app sends once a person typed `values` and `pass`.
fn typed(id: u64, pass: &str, values: &[(&str, &str)]) -> Request {
    Request::Approve {
        id,
        passphrase: Some(pw(pass)),
        values: values.iter().map(|(k, v)| (key(k), pw(v))).collect(),
    }
}

/// As an agent's `store set` sends it, with no value: the prompt names the
/// section and each key and says which have a value now; what a person
/// types there, with the passphrase, is written in one write. The caller
/// is told the keys set, those replaced and those left empty, never a
/// value. An answer the prompt does not take, or a wrong passphrase,
/// leaves it waiting.
#[tokio::test]
async fn values_asked_for_are_typed_into_the_app() {
    use crate::ipc::protocol::ApprovalReason;
    let c = Canary::new();
    let (_tmp, log, file, d) = import_daemon("5m");
    init(&file, &d).await;
    let set = d.handle(store_set("A", "old", "pw")).await;
    assert!(matches!(set, Response::Store { .. }), "{set:?}");

    let (asked, pending) = asked_in_the_app(&d, ask_values(&["B", "A", "C"])).await;
    let [prompt] = &pending[..] else {
        panic!("{pending:?}")
    };
    assert_eq!(prompt.project.as_str(), "widget");
    assert_eq!(prompt.env.as_str(), "dev");
    assert_eq!(prompt.keys, [key("B"), key("A"), key("C")]);
    assert_eq!(prompt.command, "kagebunshin store set widget.dev B A C");
    assert_eq!(prompt.cwd, Path::new("/src/widget"));
    assert_eq!(
        prompt.reason,
        ApprovalReason::Type {
            replaces: vec![key("A")],
            unlock: false,
        }
    );

    // What the prompt does not take is refused before the passphrase is
    // looked at, and none of it is written.
    let id = prompt.id;
    for (values, pass, why) in [
        (
            &[][..],
            "pw",
            format!("request {id} is approved with a value for at least one key"),
        ),
        (
            &[("A", "a"), ("Z", c.value())][..],
            "nope",
            format!("request {id} does not ask for Z"),
        ),
        (
            &[("C", "c"), ("C", c.value())][..],
            "pw",
            "C is given twice".to_owned(),
        ),
    ] {
        let Response::Error(e) = d.handle(typed(id, pass, values)).await else {
            panic!("{why}: taken");
        };
        assert_eq!((e.code, e.message.as_str()), (ErrorCode::BadRequest, &*why));
        assert_clean(&c, &e);
    }
    assert_eq!(
        error_code(d.handle(typed(id, "nope", &[("C", c.value())])).await),
        ErrorCode::WrongPassphrase
    );
    assert!(!asked.is_finished(), "still waiting");
    assert_eq!(
        listing(&d),
        [("widget.dev".to_owned(), vec!["A".to_owned()])]
    );

    // B is left empty; the others come in the app's order, not the asked.
    let r = d
        .handle(typed(id, "pw", &[("C", c.value()), ("A", "new")]))
        .await;
    assert_eq!(r, Response::Approvals { pending: vec![] });
    let r = asked.await.unwrap();
    assert_clean(&c, &r);
    assert_eq!(
        r,
        Response::StoreTyped {
            section: "widget.dev".parse().unwrap(),
            set: vec![key("A"), key("C")],
            replaced: vec![key("A")],
            left: vec![key("B")],
            locked: false,
        }
    );
    assert_eq!(
        listing(&d),
        [(
            "widget.dev".to_owned(),
            vec!["A".to_owned(), "C".to_owned()]
        )]
    );
    let value = |k: &'static str| {
        let d = d.clone();
        async move {
            let Response::Value { value } = d.handle(get(Some("dev"), k, "pw")).await else {
                panic!("{k}: no value");
            };
            value.expose().to_owned()
        }
    };
    assert_eq!(value("A").await, "new");
    assert_eq!(value("C").await, c.value());

    assert_eq!(
        logged(&log),
        [
            "store set allowed",
            "ask approval allowed",
            "approve denied",
            "approve denied",
            "approve denied",
            "approve denied",
            "store set allowed",
            "get allowed",
            "get allowed",
        ]
    );
    let (events, _) = log.read().unwrap();
    assert_eq!(events[1].target.as_deref(), Some("store set"));
    assert_eq!(
        events[1].keys,
        ["widget.dev.B", "widget.dev.A", "widget.dev.C"]
    );
    // Those typed, not every key asked for.
    assert_eq!(events[6].keys, ["widget.dev.A", "widget.dev.C"]);
    assert_no_canary(&c, &std::fs::read_to_string(log.path()).unwrap());

    // Values are for a prompt that asks for them: no other takes any.
    let (asked, pending) = asked_in_the_app(
        &d,
        import(vec![import_section("widget.rc", &[("N", "n")], true)], None),
    )
    .await;
    let id = pending[0].id;
    let Response::Error(e) = d.handle(typed(id, "pw", &[("N", "other")])).await else {
        panic!("taken");
    };
    assert_eq!(e.code, ErrorCode::BadRequest);
    assert_eq!(e.message, format!("request {id} takes no values"));
    assert!(!asked.is_finished(), "still waiting");
    d.handle(Request::Approve {
        id,
        passphrase: None,
        values: Vec::new(),
    })
    .await;
    assert_eq!(error_code(asked.await.unwrap()), ErrorCode::NotApproved);
}

/// The passphrase typed with the values unlocks a locked daemon too, and
/// the prompt says it will. Locked, it cannot say which keys have a
/// value; the reply still says which were replaced.
#[tokio::test]
async fn typing_values_unlocks_a_locked_daemon() {
    use crate::ipc::protocol::ApprovalReason;
    let (_tmp, log, file, d) = import_daemon("5m");
    init(&file, &d).await;
    let set = d.handle(store_set("A", "old", "pw")).await;
    assert!(matches!(set, Response::Store { .. }), "{set:?}");
    d.lock();

    let (asked, pending) = asked_in_the_app(&d, ask_values(&["A", "B"])).await;
    let [prompt] = &pending[..] else {
        panic!("{pending:?}")
    };
    assert_eq!(
        prompt.reason,
        ApprovalReason::Type {
            replaces: vec![],
            unlock: true,
        }
    );
    // A wrong passphrase unlocks nothing.
    let wrong = d.handle(typed(prompt.id, "nope", &[("A", "new")])).await;
    assert_eq!(error_code(wrong), ErrorCode::WrongPassphrase);
    assert!(d.is_locked());

    let r = d
        .handle(typed(prompt.id, "pw", &[("A", "new"), ("B", "b")]))
        .await;
    assert_eq!(r, Response::Approvals { pending: vec![] });
    assert_eq!(
        asked.await.unwrap(),
        Response::StoreTyped {
            section: "widget.dev".parse().unwrap(),
            set: vec![key("A"), key("B")],
            replaced: vec![key("A")],
            left: vec![],
            locked: false,
        }
    );
    assert!(!d.is_locked());
    assert_eq!(
        logged(&log)[1..],
        [
            "ask approval allowed",
            "approve denied",
            "unlock allowed",
            "store set allowed",
        ]
    );
}

/// Values nobody types are not set, and the log says how it ended:
/// refused in the app, not answered in time, or asked with no app open,
/// which is refused at once. A request that names no key, or one twice,
/// asks nobody.
#[tokio::test]
async fn values_nobody_types_are_not_set() {
    let (_tmp, log, file, d) = import_daemon("1s");
    init(&file, &d).await;

    // No app.
    let Response::Error(e) = d.handle(ask_values(&["A"])).await else {
        panic!("set");
    };
    assert_eq!(e.code, ErrorCode::NoApp);
    assert_eq!(
        e.message,
        "with no terminal the values are typed into the app, which is not open; nothing was set"
    );
    assert_eq!(e.who, Some(crate::ipc::protocol::Who::Human));

    // Denied: whatever was typed goes nowhere.
    let (asked, pending) = asked_in_the_app(&d, ask_values(&["A"])).await;
    let r = d
        .handle(Request::Approve {
            id: pending[0].id,
            passphrase: None,
            values: vec![(key("A"), pw("typed"))],
        })
        .await;
    assert_eq!(r, Response::Approvals { pending: vec![] });
    let Response::Error(e) = asked.await.unwrap() else {
        panic!("set");
    };
    assert_eq!(e.code, ErrorCode::NotApproved);
    assert_eq!(
        e.message,
        "a person refused, in the app, to type the values, so nothing was set"
    );

    // Not answered.
    let (asked, pending) = asked_in_the_app(&d, ask_values(&["A"])).await;
    assert_eq!(pending.len(), 1);
    let Response::Error(e) = asked.await.unwrap() else {
        panic!("set");
    };
    assert_eq!(e.code, ErrorCode::NotApproved);
    assert_eq!(
        e.message,
        "nobody answered the app's prompt within 1 seconds, so nothing was set"
    );
    assert_eq!(e.who, Some(crate::ipc::protocol::Who::Human));
    let r = d
        .handle(Request::WaitApprovals {
            known: vec![pending[0].id],
        })
        .await;
    assert_eq!(
        r,
        Response::Approvals { pending: vec![] },
        "the prompt went"
    );

    // Nothing to ask for.
    for (keys, why) in [
        (&[][..], "no key to ask a value for"),
        (&["A", "B", "A"][..], "A is asked for twice"),
    ] {
        let Response::Error(e) = d.handle(ask_values(keys)).await else {
            panic!("{why}: set");
        };
        assert_eq!((e.code, e.message.as_str()), (ErrorCode::BadRequest, why));
    }

    assert_eq!(listing(&d), []);
    assert_eq!(
        logged(&log),
        [
            "store set denied",
            "ask approval allowed",
            "store set denied",
            "ask approval allowed",
            "store set timedout",
            "store set denied",
            "store set denied",
        ]
    );
}

mod phone;
