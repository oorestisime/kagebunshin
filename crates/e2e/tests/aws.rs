//! What kagebunshin says when AWS does more than hand over a value: many
//! secrets, a secret it may not read, a binary one, one that changes or goes
//! away, and credentials that have run out.
//!
//! The tests marked `ignore` need the AWS Emulator, which enforces what the
//! in-process fake only pretends: run them with `scripts/e2e.sh`.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test code")]

mod support;

use std::fs;

use aws_sdk_secretsmanager::primitives::Blob;
use support::aws::block_on;
use support::{Sandbox, Walk};

/// A walk in `work/app`, a checkout that project `app` claims.
fn app(secrets: &[(&str, &str)]) -> Walk {
    let sb = Sandbox::ready(secrets);
    sb.checkout("app");
    let mut w = Walk::new(sb);
    w.sec("walk", "");
    w.cd("work/app");
    w.r("kagebunshin project init app");
    w
}

/// `ListSecrets` returns at most 100 names a page and matches the prefix
/// loosely; kagebunshin reads every page and keeps only the true matches.
#[test]
#[ignore = "needs the AWS Emulator: run scripts/e2e.sh"]
fn a_prefix_of_many_secrets_is_read_whole() {
    let mut w = app(&[
        ("bigger/x", r#"{"WRONG_ONE": "CANARYwrong1"}"#),
        ("other/big/y", r#"{"WRONG_TWO": "CANARYwrong2"}"#),
    ]);
    let client = w.sb.aws.emulator().client();
    block_on(async {
        let mut all = tokio::task::JoinSet::new();
        for n in 0..230 {
            let create = client
                .create_secret()
                .name(format!("big/s{n:03}"))
                .secret_string(format!(r#"{{"K{n:03}": "CANARYbig{n}"}}"#));
            all.spawn(async move { create.send().await.unwrap() });
        }
        all.join_all().await;
    });
    w.r("kagebunshin list --prefix big/ --profile acme-dev | wc -l");
    w.r(
        "kagebunshin project add-source app dev --provider aws_sm --prefix big/ --profile acme-dev",
    );
    w.r("kagebunshin status | head -4");
    w.r("kagebunshin run -- sh -c 'env | grep -c \"^K[0-9]\"; env | grep -c WRONG; true'");
    insta::assert_snapshot!("many_secrets", w.transcript());
}

/// A resource policy denies one secret under the prefix.
#[test]
#[ignore = "needs the AWS Emulator: run scripts/e2e.sh"]
fn a_secret_aws_refuses_to_hand_over() {
    let mut w = app(&[
        ("team/open", r#"{"OPEN": "CANARYopen"}"#),
        ("team/closed", r#"{"CLOSED": "CANARYclosed"}"#),
    ]);
    let client = w.sb.aws.emulator().client();
    block_on(async {
        client
            .put_resource_policy()
            .secret_id("team/closed")
            .resource_policy(
                r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"secretsmanager:GetSecretValue","Resource":"*"}]}"#,
            )
            .send()
            .await
            .unwrap();
    });
    w.note("under a prefix");
    w.r(
        "kagebunshin project add-source app dev --provider aws_sm --prefix team/ --profile acme-dev",
    );
    w.r("kagebunshin status");
    w.r("kagebunshin run -- sh -c 'echo open is ${OPEN:+set}, closed is ${CLOSED:-unset}'");
    w.r("kagebunshin --json run --strict -- true");
    w.r("kagebunshin next");
    w.r("kagebunshin list --keys --prefix team/ --profile acme-dev");
    w.note("named on its own");
    w.r("kagebunshin project add-env app only");
    w.r(
        "kagebunshin project add-source app only --provider aws_sm --secret team/closed --profile acme-dev",
    );
    w.r("kagebunshin --env only run -- true");
    w.r("kagebunshin --env only next");
    insta::assert_snapshot!("refused", w.transcript());
}

#[test]
#[ignore = "needs the AWS Emulator: run scripts/e2e.sh"]
fn a_binary_secret() {
    let mut w = app(&[("bin/text", r#"{"TEXT": "CANARYtext"}"#)]);
    let client = w.sb.aws.emulator().client();
    block_on(async {
        client
            .create_secret()
            .name("bin/blob")
            .secret_binary(Blob::new(b"\x00CANARYblob\xff".to_vec()))
            .send()
            .await
            .unwrap();
    });
    w.note("under a prefix");
    w.r(
        "kagebunshin project add-source app dev --provider aws_sm --prefix bin/ --profile acme-dev",
    );
    w.r("kagebunshin status");
    w.r("kagebunshin run -- sh -c 'echo text is ${TEXT:+set}'");
    w.r("kagebunshin list --keys --prefix bin/ --profile acme-dev");
    w.note("named on its own");
    w.r("kagebunshin project add-env app only");
    w.r(
        "kagebunshin project add-source app only --provider aws_sm --secret bin/blob --key BLOB --profile acme-dev",
    );
    w.r("kagebunshin --env only run -- true");
    insta::assert_snapshot!("binary", w.transcript());
}

/// The value is cached until `sync`; a secret that is gone is named.
#[test]
#[ignore = "needs the AWS Emulator: run scripts/e2e.sh"]
fn a_secret_that_changes_and_then_goes() {
    let mut w = app(&[("live/token", "one")]);
    let client = w.sb.aws.emulator().client();
    w.r(
        "kagebunshin project add-source app dev --provider aws_sm --secret live/token --key TOKEN --profile acme-dev",
    );
    let length = "kagebunshin run -- sh -c 'echo the token has ${#TOKEN} characters'";
    w.r(length);
    w.note("AWS has a new value, five characters long");
    block_on(async {
        client
            .put_secret_value()
            .secret_id("live/token")
            .secret_string("three")
            .send()
            .await
            .unwrap();
    });
    w.r(length);
    w.r("kagebunshin sync");
    w.r(length);
    w.note("the secret is deleted, with AWS's recovery window");
    block_on(async {
        client
            .delete_secret()
            .secret_id("live/token")
            .send()
            .await
            .unwrap();
    });
    w.r(length);
    w.r("kagebunshin sync");
    w.r(length);
    w.r("kagebunshin status");
    w.r("kagebunshin next");
    w.note("and restored");
    block_on(async {
        client
            .restore_secret()
            .secret_id("live/token")
            .send()
            .await
            .unwrap();
    });
    w.r("kagebunshin sync");
    w.r(length);
    insta::assert_snapshot!("changes_and_goes", w.transcript());
}

/// An IAM Identity Center profile, as `aws sso login` leaves it.
fn sso_profile(sb: &Sandbox, expires: &str) {
    let home = sb.root().join("home");
    let start = "https://acme.awsapps.test/start";
    let mut config = fs::read_to_string(home.join(".aws/config")).unwrap();
    config.push_str(&format!(
        "\n[profile acme-sso]\nsso_start_url = {start}\nsso_region = {region}\n\
         sso_account_id = 000000000000\nsso_role_name = dev\nregion = {region}\n",
        region = support::aws::REGION
    ));
    fs::write(home.join(".aws/config"), config).unwrap();
    // The AWS CLI names the cached token after the start URL's SHA-1.
    let (code, sha) = sb.agent(
        &home,
        &format!("printf %s '{start}' | sha1sum | cut -d' ' -f1"),
    );
    assert_eq!(code, 0, "{sha}");
    let cache = home.join(".aws/sso/cache");
    fs::create_dir_all(&cache).unwrap();
    fs::write(
        cache.join(format!("{}.json", sha.trim())),
        format!(
            r#"{{"startUrl": "{start}", "region": "{region}", "accessToken": "CANARYssotoken", "expiresAt": "{expires}"}}"#,
            region = support::aws::REGION
        ),
    )
    .unwrap();
}

/// The cached token's time has passed: the SDK stops before any request.
#[test]
fn an_sso_login_that_has_expired() {
    let mut w = app(&[("acme/dev/db", r#"{"DATABASE_URL": "CANARYdb"}"#)]);
    sso_profile(&w.sb, "2020-01-01T00:00:00Z");
    w.r("kagebunshin project add-source app dev --provider aws_sm --secret acme/dev/db --profile acme-sso");
    w.r("kagebunshin run -- true");
    w.r("kagebunshin --json run -- true");
    w.r("kagebunshin status");
    w.r("kagebunshin next");
    w.r("kagebunshin --json next");
    w.hook("start", "");
    insta::assert_snapshot!("sso_expired", w.transcript());
}

/// The cached token still looks good, and AWS refuses it: a session ended
/// from the other side.
#[test]
#[ignore = "needs the AWS Emulator: run scripts/e2e.sh"]
fn an_sso_login_that_aws_ended() {
    let mut w = app(&[("acme/dev/db", r#"{"DATABASE_URL": "CANARYdb"}"#)]);
    sso_profile(&w.sb, "2099-01-01T00:00:00Z");
    w.r("kagebunshin project add-source app dev --provider aws_sm --secret acme/dev/db --profile acme-sso");
    w.r("kagebunshin run -- true");
    w.r("kagebunshin next");
    // It was the emulator's IAM Identity Center that said no.
    assert!(w.sb.daemon_log().contains("UnauthorizedException"));
    insta::assert_snapshot!("sso_ended", w.transcript());
}

/// A profile with no credentials at all.
#[test]
fn a_profile_without_credentials() {
    let mut w = app(&[("acme/dev/db", r#"{"DATABASE_URL": "CANARYdb"}"#)]);
    let config = w.sb.root().join("home/.aws/config");
    let mut text = fs::read_to_string(&config).unwrap();
    text.push_str("\n[profile bare]\nregion = eu-west-1\n");
    fs::write(&config, text).unwrap();
    w.r("kagebunshin project add-source app dev --provider aws_sm --secret acme/dev/db --profile bare");
    w.r("kagebunshin run -- true");
    w.r("kagebunshin next");
    w.note("the human logs in, and the daemon is not restarted");
    let (id, key) = w.sb.aws.keys();
    let credentials = w.sb.root().join("home/.aws/credentials");
    let mut text = fs::read_to_string(&credentials).unwrap();
    text.push_str(&format!(
        "\n[bare]\naws_access_key_id = {id}\naws_secret_access_key = {key}\n"
    ));
    fs::write(&credentials, text).unwrap();
    w.r("kagebunshin run -- sh -c 'echo the database is ${DATABASE_URL:+set}'");
    w.note("a profile that is not there");
    w.r("kagebunshin project add-env app other");
    w.r("kagebunshin project add-source app other --provider aws_sm --secret acme/dev/db --profile nope");
    w.r("kagebunshin --env other run -- true");
    w.r("kagebunshin --env other next");
    insta::assert_snapshot!("no_credentials", w.transcript());
}
