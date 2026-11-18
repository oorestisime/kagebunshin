//! Proton Pass, from connecting it to a token that stops working, with
//! `pass-cli` played by the fake the daemon's own tests use.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test code")]

mod support;

use std::fs;

use kagebunshin::test_support::FakePassCli;
use support::{PASS, Sandbox, Walk};

/// The token the fake `pass-cli` logs in with.
const TOKEN: &str = "CANARYproton-token";

/// A walk in `work/web`, a checkout that project `web` claims, on a machine
/// whose Proton Pass has a vault `web` and the shared vault `global`.
fn web() -> (Walk, FakePassCli) {
    let mut sb = Sandbox::ready(&[]);
    let proton = sb.proton(TOKEN);
    proton
        .vault("web", "s1")
        .vault("global", "s2")
        .api_key(
            "s1",
            "i1",
            "The database",
            "API key",
            "DATABASE_URL",
            "CANARYproton-db",
        )
        .api_key(
            "s1",
            "i2",
            "Stripe",
            "API key",
            "STRIPE_KEY",
            "CANARYproton-stripe",
        )
        .item(
            "s1",
            "i3",
            "login",
            serde_json::json!({ "username": "someone", "password": "CANARYproton-login" }),
        )
        .api_key(
            "s2",
            "i4",
            "OpenAI",
            "API key",
            "OPENAI_KEY",
            "CANARYproton-openai",
        );
    sb.checkout("web");
    let mut w = Walk::new(sb);
    w.sec("walk", "");
    w.cd("work/web");
    w.h(&format!("{PASS}\n"), "kagebunshin unlock");
    (w, proton)
}

/// The human connects Proton Pass with the token in `file`.
fn connect(w: &mut Walk, file: &str, token: &str) {
    fs::write(w.sb.root().join(file), token).unwrap();
    w.h(
        &format!("{PASS}\n"),
        &format!(
            "KAGEBUNSHIN_PROTON_TOKEN=$(cat $T/{file}) kagebunshin connect proton --expires 2099-01-31"
        ),
    );
}

#[test]
fn connecting_reading_and_a_token_that_ends() {
    let (mut w, proton) = web();
    w.r("kagebunshin project init web");
    w.note("before Proton Pass is connected");
    w.r("kagebunshin list --provider proton");
    w.r("kagebunshin project add-source web dev --provider proton --prefix web/");
    w.r("kagebunshin run -- true");
    w.r("kagebunshin next");
    w.note("the human connects it: first with a token Proton refuses");
    connect(&mut w, "old-token", "CANARYwrong-token");
    connect(&mut w, "token", TOKEN);
    w.r("kagebunshin status");
    w.r("kagebunshin list --provider proton");
    w.r(
        "kagebunshin run -- sh -c 'echo database is ${DATABASE_URL:+set}, stripe is ${STRIPE_KEY:+set}'",
    );
    w.note("one key from the shared vault, under another name");
    w.r(
        "kagebunshin project add-source web dev --provider proton --secret global/OPENAI_KEY --key OPENAI_API_KEY",
    );
    w.r("kagebunshin run -- sh -c 'echo openai is ${OPENAI_API_KEY:+set}'");
    w.note("the two-hour session ends: kagebunshin logs in again by itself");
    proton.expire();
    w.r("kagebunshin sync");
    w.r("kagebunshin run -- sh -c 'echo database is ${DATABASE_URL:+set}'");
    assert_eq!(proton.logins(), 2, "{}", proton.calls());
    w.note("the token is revoked in Proton");
    proton.revoke();
    proton.expire();
    w.r("kagebunshin run -- sh -c 'echo database is ${DATABASE_URL:+set}'");
    w.r("kagebunshin sync");
    w.r("kagebunshin run -- true");
    w.r("kagebunshin status");
    w.r("kagebunshin next");
    // The token reaches pass-cli only to log in, and only in its
    // environment.
    let calls = proton.calls();
    assert!(!calls.contains("token-in-env"), "{calls}");
    assert!(!calls.contains(TOKEN), "{calls}");
    insta::assert_snapshot!("token", w.transcript());
}
