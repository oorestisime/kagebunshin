//! The paired phone: pairing it, and answering a request from it.

use super::*;
use crate::audit::AuditLog;
use crate::config::schema::DEFAULT_PHONE_PORT;
use crate::daemon::broker::phone::{Outcome, PhoneError, Place};
use crate::daemon::push::{self, PushState};
use crate::ipc::protocol::{PHONE_PAIRING, PhoneChoice, RemotePeer};
use crate::tailnet::fake::FakeTailnet;
use crate::webauthn::fake::FakePasskey;
use crate::webauthn::{Site, WebauthnError};
use crate::webpush::fake::{FakeBrowser, FakePush};
use crate::webpush::{Delivery, PushError};

fn site() -> Site {
    Site::new("self.example.ts.net", DEFAULT_PHONE_PORT)
}

fn peer(node: &str, machine: &str) -> RemotePeer {
    RemotePeer {
        node: node.into(),
        machine: machine.into(),
        user: "dev@example.com".into(),
        tags: Vec::new(),
        token: None,
    }
}

fn phone() -> RemotePeer {
    peer("nPHONE", "phone")
}

/// [`STORED`], audited and unlocked (passphrase pw), on a tailnet with a
/// laptop, a phone and a tablet. Its store holds S in dev, marked
/// sensitive, so reading it waits for approval.
async fn phone_daemon() -> (tempfile::TempDir, AuditLog, StoreFile, Daemon) {
    let (tmp, log, file, d, _) = push_daemon().await;
    (tmp, log, file, d)
}

/// [`phone_daemon`], and the push service it tells the phone through. Its
/// notifications file is `push.json` in the directory returned.
async fn push_daemon() -> (
    tempfile::TempDir,
    AuditLog,
    StoreFile,
    Daemon,
    Arc<FakePush>,
) {
    let tailnet = Arc::new(FakeTailnet::default());
    tailnet.set_peers(
        "Running",
        &[
            ("nLAPTOP", "laptop", "linux"),
            ("nTABLET", "tablet", "android"),
            ("nPHONE", "phone", "iOS"),
        ],
    );
    let (tmp, log, file, d) = import_daemon("5m");
    let service = Arc::new(FakePush::default());
    let d = d
        .with_tailnet(tailnet)
        .with_push(service.clone(), PushState::new(tmp.path().join(push::FILE)));
    init(&file, &d).await;
    let set = d
        .handle(Request::StoreSet {
            section: "widget.dev".parse().unwrap(),
            key: key("S"),
            value: pw("v"),
            passphrase: pw("pw"),
            sensitive: true,
        })
        .await;
    assert!(matches!(set, Response::Store { .. }), "{set:?}");
    (tmp, log, file, d, service)
}

/// The phone allows notifications in `browser`, its page being served.
fn notified(d: &Daemon, browser: &FakeBrowser) {
    d.set_phone_serving(Some(site().origin), None);
    d.phone_push_key("nPHONE").unwrap();
    d.phone_push_subscribe(
        &phone(),
        &browser.endpoint,
        &browser.p256dh(),
        &browser.auth(),
    )
    .unwrap();
}

/// Asks for the sensitive S with the app not open; the asking.
fn asked_away(d: &Daemon) -> tokio::task::JoinHandle<Response> {
    let d = d.clone();
    tokio::spawn(async move { d.handle(get(Some("dev"), "S", "pw")).await })
}

/// The request the paired phone's page shows waiting, once one does.
async fn waiting_on_the_page(d: &Daemon) -> u64 {
    loop {
        let page = d.phone_page("nPHONE");
        if let Some(waiting) = page.prompts.first() {
            return waiting.prompt.id;
        }
        d.phone_page_wait(page.version, Duration::from_secs(30))
            .await;
    }
}

fn pair(machine: &str, pass: &str) -> Request {
    Request::PhonePair {
        machine: machine.into(),
        passphrase: pw(pass),
    }
}

/// Pairs the phone with a new passkey.
async fn paired(d: &Daemon) -> FakePasskey {
    let r = d.handle(pair("phone", "pw")).await;
    assert!(matches!(r, Response::PhonePairing { .. }), "{r:?}");
    let passkey = FakePasskey::new();
    let begin = d.phone_pair_begin("nPHONE").unwrap();
    let (client, auth) = passkey.create(&site(), &begin.challenge);
    d.phone_pair_finish(&site(), &phone(), &client, &auth)
        .await
        .unwrap();
    passkey
}

/// What the phone sends to approve request `id`.
fn approval(d: &Daemon, passkey: &FakePasskey, id: u64) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let begin = d.phone_approve_begin("nPHONE", id, false).unwrap();
    assert_eq!(
        begin.credential,
        crate::webauthn::encode(&passkey.credential)
    );
    passkey.get(&site(), &begin.challenge)
}

async fn phone_status(d: &Daemon) -> Option<Box<crate::ipc::protocol::PhoneStatus>> {
    match d.handle(Request::Status { facts: None }).await {
        Response::Status(report) => report.phone,
        other => panic!("{other:?}"),
    }
}

/// Pairing names one phone of the tailnet and takes the passphrase; only
/// that phone can then make the passkey, once, and it is in the store.
#[tokio::test]
async fn a_phone_is_paired_with_the_passphrase_and_its_own_passkey() {
    let (_tmp, log, file, d) = phone_daemon().await;
    assert_eq!(phone_status(&d).await, None);
    assert_eq!(d.phone_nodes(), Vec::<String>::new());

    // Phones and tablets only, by name.
    let choice = |name: &str, node: &str, os: &str| PhoneChoice {
        name: name.into(),
        node: node.into(),
        os: os.into(),
    };
    assert_eq!(
        d.handle(Request::Phones).await,
        Response::Phones {
            phones: vec![
                choice("phone", "nPHONE", "iOS"),
                choice("tablet", "nTABLET", "android"),
            ]
        }
    );

    let r = d.handle(pair("phone", "wrong")).await;
    assert_eq!(error_code(r), ErrorCode::WrongPassphrase);
    let e = error(d.handle(pair("laptop", "pw")).await);
    assert_eq!(
        e.message,
        "laptop is not a phone or a tablet, as Tailscale tells it"
    );
    let e = error(d.handle(pair("nobody", "pw")).await);
    assert_eq!(
        e.message,
        "no other machine on this tailnet is named nobody"
    );
    assert_eq!(d.phone_nodes(), Vec::<String>::new());

    // By its node id too, as the app names the one a person picked.
    let r = d.handle(pair("nPHONE", "pw")).await;
    assert_eq!(
        r,
        Response::PhonePairing {
            name: "phone".into(),
            url: "https://self.example.ts.net:47318".into(),
            seconds: PHONE_PAIRING.as_secs(),
        }
    );
    assert_eq!(d.phone_nodes(), ["nPHONE"]);
    let status = phone_status(&d).await.unwrap();
    assert_eq!(status.paired, None);
    assert_eq!(status.pairing.unwrap().name, "phone");

    // The page tells the phone it may pair, and tells any other machine
    // nothing.
    let page = d.phone_page("nPHONE");
    assert!(!page.paired && page.pairing.is_some(), "{page:?}");
    let page = d.phone_page("nTABLET");
    assert!(!page.paired && page.pairing.is_none(), "{page:?}");
    assert_eq!(d.phone_pair_begin("nTABLET"), Err(PhoneError::NotPairing));

    // A passkey made for another challenge or another site is refused, and
    // each challenge is good for one try.
    let passkey = FakePasskey::new();
    let begin = d.phone_pair_begin("nPHONE").unwrap();
    assert_eq!(begin.name, "phone");
    let (client, auth) = passkey.create(
        &Site::new("elsewhere.example.ts.net", 47318),
        &begin.challenge,
    );
    assert!(matches!(
        d.phone_pair_finish(&site(), &phone(), &client, &auth).await,
        Err(PhoneError::Passkey(_))
    ));
    let (client, auth) = passkey.create(&site(), &begin.challenge);
    assert_eq!(
        d.phone_pair_finish(&site(), &phone(), &client, &auth).await,
        Err(PhoneError::NoChallenge)
    );
    let begin = d.phone_pair_begin("nPHONE").unwrap();
    let (client, auth) = passkey.create(&site(), &begin.challenge);
    assert_eq!(
        d.phone_pair_finish(&site(), &peer("nTABLET", "tablet"), &client, &auth)
            .await,
        Err(PhoneError::NotPairing)
    );
    assert_eq!(
        file.open(&Passphrase::new("pw".into())).unwrap().phone(),
        None
    );
    d.phone_pair_finish(&site(), &phone(), &client, &auth)
        .await
        .unwrap();

    // Paired: in the store, in status, and the pairing is over.
    let stored = file.open(&Passphrase::new("pw".into())).unwrap();
    let stored = stored.phone().unwrap();
    assert_eq!(
        (stored.name.as_str(), stored.node.as_str()),
        ("phone", "nPHONE")
    );
    assert_eq!(crate::webauthn::decode(&stored.key).unwrap(), passkey.key());
    let status = phone_status(&d).await.unwrap();
    assert_eq!(status.pairing, None);
    assert_eq!(status.paired.unwrap().name, "phone");
    assert_eq!(d.phone_nodes(), ["nPHONE"]);
    assert_eq!(d.phone_pair_begin("nPHONE"), Err(PhoneError::NotPairing));
    let page = d.phone_page("nPHONE");
    assert!(page.paired && page.pairing.is_none(), "{page:?}");

    // Removing it takes the passphrase.
    let r = d
        .handle(Request::PhoneUnpair {
            passphrase: pw("wrong"),
        })
        .await;
    assert_eq!(error_code(r), ErrorCode::WrongPassphrase);
    assert_eq!(d.phone_nodes(), ["nPHONE"]);
    let r = d
        .handle(Request::PhoneUnpair {
            passphrase: pw("pw"),
        })
        .await;
    assert!(matches!(r, Response::Store { .. }), "{r:?}");
    assert_eq!(d.phone_nodes(), Vec::<String>::new());
    assert_eq!(phone_status(&d).await, None);
    assert!(!d.phone_page("nPHONE").paired);

    let logged = logged(&log);
    for line in [
        "phone pair denied",
        "phone pair allowed",
        "phone paired denied",
        "phone paired allowed",
        "phone unpair denied",
        "phone unpair allowed",
    ] {
        assert!(logged.iter().any(|l| l == line), "{line}: {logged:?}");
    }
}

/// A pairing ends when it is stopped, when the daemon locks and when its
/// time runs out; the passphrase it kept goes with it.
#[tokio::test]
async fn a_pairing_ends_with_a_stop_a_lock_or_its_time() {
    let (_tmp, _log, _file, d) = phone_daemon().await;

    d.handle(pair("phone", "pw")).await;
    assert_eq!(d.phone_nodes(), ["nPHONE"]);
    assert_eq!(
        d.handle(Request::PhonePairStop).await,
        Response::PhonePairStopped
    );
    assert_eq!(d.phone_nodes(), Vec::<String>::new());
    assert_eq!(d.phone_pair_begin("nPHONE"), Err(PhoneError::NotPairing));

    d.handle(pair("phone", "pw")).await;
    d.lock();
    assert_eq!(d.phone_pair_begin("nPHONE"), Err(PhoneError::Locked));
    assert!(!d.phone_page("nPHONE").paired);
    d.unlock(Some(Passphrase::new("pw".into()))).await.unwrap();
    assert_eq!(d.phone_nodes(), Vec::<String>::new());
    assert_eq!(d.phone_pair_begin("nPHONE"), Err(PhoneError::NotPairing));

    // Locked, nothing is paired.
    d.lock();
    assert_eq!(
        error_code(d.handle(pair("phone", "pw")).await),
        ErrorCode::Locked
    );
    d.unlock(Some(Passphrase::new("pw".into()))).await.unwrap();

    d.handle(pair("phone", "pw")).await;
    let begin = d.phone_pair_begin("nPHONE").unwrap();
    tokio::time::pause();
    tokio::time::advance(PHONE_PAIRING + Duration::from_secs(1)).await;
    settle().await;
    tokio::time::resume();
    assert_eq!(d.phone_nodes(), Vec::<String>::new());
    let (client, auth) = FakePasskey::new().create(&site(), &begin.challenge);
    assert_eq!(
        d.phone_pair_finish(&site(), &phone(), &client, &auth).await,
        Err(PhoneError::NotPairing)
    );
}

/// Another machine may not pair a phone or remove one.
#[tokio::test]
async fn only_this_machine_pairs_a_phone() {
    let (_tmp, _log, _file, d) = phone_daemon().await;
    let laptop = laptop_with("nLAPTOP", None);
    for req in [
        Request::Phones,
        pair("phone", "pw"),
        Request::PhonePairStop,
        Request::PhoneUnpair {
            passphrase: pw("pw"),
        },
    ] {
        let r = d.handle_from(req, &laptop).await;
        assert!(matches!(r, Response::Error(_)), "{r:?}");
    }
    assert_eq!(d.phone_nodes(), Vec::<String>::new());
}

/// The paired phone approves a request that hands values out with its
/// passkey's signature over a challenge made for that request, once.
#[tokio::test]
async fn the_paired_phone_approves_with_its_passkey() {
    let (_tmp, log, _file, d) = phone_daemon().await;
    let passkey = paired(&d).await;

    let (asked, pending) = asked_in_the_app(&d, get(Some("dev"), "S", "pw")).await;
    let id = pending[0].id;
    let page = d.phone_page("nPHONE");
    let [prompt] = &page.prompts[..] else {
        panic!("{page:?}")
    };
    assert_eq!(prompt.prompt.id, id);
    assert_eq!(prompt.prompt.keys, [key("S")]);
    assert!(prompt.here);
    // Only the paired phone is shown it, or may answer it.
    assert_eq!(d.phone_page("nTABLET").prompts, []);
    assert_eq!(
        d.phone_approve_begin("nTABLET", id, false),
        Err(PhoneError::NotPaired)
    );
    assert_eq!(
        d.phone_deny(&peer("nTABLET", "tablet"), id),
        Err(PhoneError::NotPaired)
    );
    assert_eq!(
        d.phone_approve_begin("nPHONE", id + 1, false),
        Err(PhoneError::Gone)
    );

    // Another passkey's signature is refused, and spends the challenge.
    let (client, auth, _) = approval(&d, &passkey, id);
    let forged = FakePasskey::new().sign(&auth, &client);
    assert_eq!(
        d.phone_approve(&site(), &phone(), id, &client, &auth, &forged),
        Err(PhoneError::Passkey(WebauthnError::Signature))
    );
    let signature = passkey.sign(&auth, &client);
    assert_eq!(
        d.phone_approve(&site(), &phone(), id, &client, &auth, &signature),
        Err(PhoneError::NoChallenge)
    );
    // So does an approval the phone was not verified for.
    let begin = d.phone_approve_begin("nPHONE", id, false).unwrap();
    let client = FakePasskey::client_data("webauthn.get", &site().origin, &begin.challenge);
    let auth = FakePasskey::auth_data(&site().name, 0x01);
    let signature = passkey.sign(&auth, &client);
    assert!(matches!(
        d.phone_approve(&site(), &phone(), id, &client, &auth, &signature),
        Err(PhoneError::Passkey(_))
    ));
    // A challenge is for one request.
    let (client, auth, signature) = approval(&d, &passkey, id);
    assert_eq!(
        d.phone_approve(&site(), &phone(), id + 1, &client, &auth, &signature),
        Err(PhoneError::NoChallenge)
    );
    assert_eq!(d.phone_page("nPHONE").prompts.len(), 1, "still waiting");

    let (client, auth, signature) = approval(&d, &passkey, id);
    d.phone_approve(&site(), &phone(), id, &client, &auth, &signature)
        .unwrap();
    let r = asked.await.unwrap();
    assert!(matches!(r, Response::Value { .. }), "{r:?}");

    // Answered: gone from the app and the page, and neither side answers
    // it again.
    let page = d.phone_page("nPHONE");
    assert_eq!(page.prompts, []);
    let [last] = &page.recent[..] else {
        panic!("{page:?}")
    };
    assert_eq!(
        (last.id, last.outcome, last.by),
        (id, Outcome::Approved, Some(Place::Phone))
    );
    assert_eq!(
        d.phone_approve(&site(), &phone(), id, &client, &auth, &signature),
        Err(PhoneError::NoChallenge)
    );
    assert_eq!(d.phone_deny(&phone(), id), Err(PhoneError::Gone));
    let r = d
        .handle(Request::Approve {
            id,
            passphrase: None,
            values: Vec::new(),
        })
        .await;
    assert_eq!(
        error(r).message,
        format!("no request {id} waits for approval; it was answered, or it timed out")
    );
    let status = phone_status(&d).await.unwrap();
    let last = status.last.unwrap();
    assert_eq!((last.id, last.approved), (id, true));
    assert!(status.paired.unwrap().seen.is_some());

    let logged = logged(&log);
    assert_eq!(
        logged
            .iter()
            .filter(|l| l.starts_with("phone approve") || l.starts_with("get"))
            .collect::<Vec<_>>(),
        [
            "phone approve denied",
            "phone approve denied",
            "phone approve allowed",
            "get allowed"
        ],
        "{logged:?}"
    );
}

/// A denial on the phone takes no passkey, and whichever side answers
/// first, the other finds the request gone.
#[tokio::test]
async fn the_phone_denies_and_the_first_answer_wins() {
    let (_tmp, log, _file, d) = phone_daemon().await;
    let passkey = paired(&d).await;

    let (asked, pending) = asked_in_the_app(&d, get(Some("dev"), "S", "pw")).await;
    let id = pending[0].id;
    d.phone_deny(&phone(), id).unwrap();
    assert_eq!(error_code(asked.await.unwrap()), ErrorCode::NotApproved);
    let page = d.phone_page("nPHONE");
    assert_eq!(
        (page.recent[0].outcome, page.recent[0].by),
        (Outcome::Denied, Some(Place::Phone))
    );
    assert!(logged(&log).iter().any(|l| l == "phone deny allowed"));

    // Answered in the app first: the phone's approval finds it gone.
    let (asked, pending) = asked_in_the_app(&d, get(Some("dev"), "S", "pw")).await;
    let id = pending[0].id;
    let (client, auth, signature) = approval(&d, &passkey, id);
    let r = d
        .handle(Request::Approve {
            id,
            passphrase: Some(pw("pw")),
            values: Vec::new(),
        })
        .await;
    assert_eq!(r, Response::Approvals { pending: vec![] });
    assert_eq!(
        d.phone_approve(&site(), &phone(), id, &client, &auth, &signature),
        Err(PhoneError::Gone)
    );
    assert!(matches!(asked.await.unwrap(), Response::Value { .. }));
    let page = d.phone_page("nPHONE");
    assert_eq!(
        (page.recent[0].id, page.recent[0].outcome, page.recent[0].by),
        (id, Outcome::Approved, Some(Place::Desk))
    );
    let last = phone_status(&d).await.unwrap().last.unwrap();
    assert!(!last.approved, "the last one answered on the phone");

    // Locked, the phone is told so and nothing else.
    let (asked, pending) = asked_in_the_app(&d, get(Some("dev"), "S", "pw")).await;
    let id = pending[0].id;
    d.lock();
    assert_eq!(
        d.phone_approve_begin("nPHONE", id, false),
        Err(PhoneError::Locked)
    );
    assert_eq!(d.phone_deny(&phone(), id), Err(PhoneError::Locked));
    let page = d.phone_page("nPHONE");
    assert!(
        !page.paired && page.prompts.is_empty() && page.recent.is_empty(),
        "{page:?}"
    );
    drop(asked);
}

/// A request that writes the store takes the passphrase, so the phone is
/// shown it and may deny it, never approve it.
#[tokio::test]
async fn the_phone_does_not_approve_what_takes_the_passphrase() {
    let (_tmp, _log, file, d) = phone_daemon().await;
    paired(&d).await;

    let (asked, pending) = asked_in_the_app(&d, ask_values(&["B"])).await;
    let id = pending[0].id;
    let page = d.phone_page("nPHONE");
    assert!(!page.prompts[0].here, "{page:?}");
    assert_eq!(
        d.phone_approve_begin("nPHONE", id, false),
        Err(PhoneError::DeskOnly)
    );
    d.phone_deny(&phone(), id).unwrap();
    let r = asked.await.unwrap();
    assert!(matches!(r, Response::Error(_)), "{r:?}");
    let store = file.open(&Passphrase::new("pw".into())).unwrap();
    let dev = store.section(&"widget.dev".parse().unwrap()).unwrap();
    assert!(!dev.contains_key(&key("B")));
}

/// The page's state changes version when a request starts or stops
/// waiting, which is what its long poll waits for.
#[tokio::test]
async fn the_page_waits_for_a_change() {
    let (_tmp, _log, _file, d) = phone_daemon().await;
    paired(&d).await;
    let seen = d.phone_page("nPHONE").version;
    // Nothing changed: it waits the whole time.
    d.phone_page_wait(seen, Duration::from_millis(20)).await;
    assert_eq!(d.phone_page("nPHONE").version, seen);

    let waiting = tokio::spawn({
        let d = d.clone();
        async move {
            d.phone_page_wait(seen, Duration::from_secs(30)).await;
            d.phone_page("nPHONE")
        }
    });
    let (asked, pending) = asked_in_the_app(&d, get(Some("dev"), "S", "pw")).await;
    let page = waiting.await.unwrap();
    assert_ne!(page.version, seen);
    assert_eq!(page.prompts[0].prompt.id, pending[0].id);

    let seen = page.version;
    d.phone_deny(&phone(), pending[0].id).unwrap();
    d.phone_page_wait(seen, Duration::from_secs(30)).await;
    assert_eq!(d.phone_page("nPHONE").prompts, []);
    asked.await.unwrap();
}

/// A phone that allowed notifications is told of each request it can
/// approve, in names: what it is for and the program that asks. Only the
/// paired phone subscribes, and only at a push service a browser uses.
#[tokio::test]
async fn the_paired_phone_is_told_of_a_request_it_can_approve() {
    let (_tmp, log, _file, d, service) = push_daemon().await;
    paired(&d).await;
    let browser = FakeBrowser::new();

    assert_eq!(d.phone_push_key("nTABLET"), Err(PhoneError::NotPaired));
    let key = d.phone_push_key("nPHONE").unwrap();
    assert_eq!(d.phone_push_key("nPHONE").unwrap(), key, "made once");
    assert_eq!(
        d.phone_push_subscribe(
            &peer("nTABLET", "tablet"),
            &browser.endpoint,
            &browser.p256dh(),
            &browser.auth()
        ),
        Err(PhoneError::NotPaired)
    );
    assert_eq!(
        d.phone_push_subscribe(
            &phone(),
            "https://push.example.com/one",
            &browser.p256dh(),
            &browser.auth()
        ),
        Err(PhoneError::Push(PushError::Endpoint))
    );
    assert!(!d.phone_page("nPHONE").notified);
    assert!(!phone_status(&d).await.unwrap().paired.unwrap().notifies);

    notified(&d, &browser);
    assert!(d.phone_page("nPHONE").notified);
    assert!(!d.phone_page("nTABLET").notified);
    let view = phone_status(&d).await.unwrap().paired.unwrap();
    assert!(view.notifies && view.untold.is_none(), "{view:?}");
    assert!(
        logged(&log)
            .iter()
            .any(|l| l == "phone notifications allowed")
    );

    let (asked, pending) = asked_in_the_app(&d, get(Some("dev"), "S", "pw")).await;
    settle().await;
    let [message] = &service.sent()[..] else {
        panic!("{:?}", service.sent())
    };
    assert_eq!(message.host, "web.push.apple.com");
    assert_eq!(message.ttl, 300, "as long as the request waits");
    let text: serde_json::Value = serde_json::from_slice(&browser.read(&message.body)).unwrap();
    let program = Path::new(&pending[0].argv[0])
        .file_name()
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(
        text,
        serde_json::json!({
            "id": pending[0].id,
            "title": "A command asks for sensitive values of widget/dev",
            "body": format!("`{program}` waits for you to approve or deny it."),
        })
    );
    d.phone_deny(&phone(), pending[0].id).unwrap();
    asked.await.unwrap();

    // One that takes the passphrase is answered at the desk: not told.
    let (asked, pending) = asked_in_the_app(&d, ask_values(&["B"])).await;
    settle().await;
    assert_eq!(service.sent().len(), 1);
    d.phone_deny(&phone(), pending[0].id).unwrap();
    asked.await.unwrap();

    // Nor is anything told while the page is not served.
    d.set_phone_serving(None, Some("Tailscale is Stopped, not Running".into()));
    let (asked, pending) = asked_in_the_app(&d, get(Some("dev"), "S", "pw")).await;
    settle().await;
    assert_eq!(service.sent().len(), 1);
    d.phone_deny(&phone(), pending[0].id).unwrap();
    asked.await.unwrap();
}

/// With the app closed, a request the phone can approve waits for the
/// phone once it is told; one it is not told of is refused as before.
#[tokio::test]
async fn a_request_waits_for_the_phone_while_the_app_is_closed() {
    let (_tmp, _log, _file, d, service) = push_daemon().await;
    let passkey = paired(&d).await;
    const NO_APP: &str = "handing it out takes approval in the app, which is not open";

    // No notifications: nobody would know of it.
    d.set_phone_serving(Some(site().origin), None);
    let e = error(asked_away(&d).await.unwrap());
    assert!(e.message.ends_with(NO_APP), "{}", e.message);

    let browser = FakeBrowser::new();
    notified(&d, &browser);
    let asked = asked_away(&d);
    let id = waiting_on_the_page(&d).await;
    // It goes on waiting, with no app to close.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(!asked.is_finished());
    let (client, auth, signature) = approval(&d, &passkey, id);
    d.phone_approve(&site(), &phone(), id, &client, &auth, &signature)
        .unwrap();
    let r = asked.await.unwrap();
    assert!(matches!(r, Response::Value { .. }), "{r:?}");
    assert_eq!(service.sent().len(), 1);

    // What takes the passphrase is still the app's alone.
    let e = error(d.handle(ask_values(&["B"])).await);
    assert!(e.message.contains("which is not open"), "{}", e.message);
    assert_eq!(service.sent().len(), 1);

    // The push service is not reached: the phone was not told, so the
    // request does not wait for it.
    service.answering(Err("no route".into()));
    let e = error(asked_away(&d).await.unwrap());
    assert!(e.message.ends_with(NO_APP), "{}", e.message);
    let view = phone_status(&d).await.unwrap().paired.unwrap();
    assert!(view.notifies, "{view:?}");
    assert_eq!(
        view.untold.as_deref(),
        Some("the last notification was not sent: no route")
    );

    // The phone dropped what it gave: it is forgotten here too.
    service.answering(Ok(Delivery::Gone));
    let e = error(asked_away(&d).await.unwrap());
    assert!(e.message.ends_with(NO_APP), "{}", e.message);
    assert!(!d.phone_page("nPHONE").notified);
    let view = phone_status(&d).await.unwrap().paired.unwrap();
    assert!(!view.notifies && view.untold.is_some(), "{view:?}");
    let sent = service.sent().len();
    let e = error(asked_away(&d).await.unwrap());
    assert!(e.message.ends_with(NO_APP), "{}", e.message);
    assert_eq!(service.sent().len(), sent, "nothing to send to");

    // Allowed again, the next one is taken, and nothing is amiss.
    service.answering(Ok(Delivery::Taken));
    notified(&d, &browser);
    let asked = asked_away(&d);
    let id = waiting_on_the_page(&d).await;
    settle().await;
    let view = phone_status(&d).await.unwrap().paired.unwrap();
    assert!(view.notifies && view.untold.is_none(), "{view:?}");
    d.phone_deny(&phone(), id).unwrap();
    assert_eq!(error_code(asked.await.unwrap()), ErrorCode::NotApproved);
}

/// What a phone gave for its notifications is for that pairing: removing
/// the phone, or pairing one again, drops it.
#[tokio::test]
async fn notifications_end_with_the_pairing() {
    let (tmp, _log, _file, d, service) = push_daemon().await;
    let held = || {
        let text = std::fs::read(tmp.path().join(push::FILE)).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&text).unwrap();
        json.get("phone").is_some()
    };
    paired(&d).await;
    let browser = FakeBrowser::new();
    notified(&d, &browser);
    assert!(held());

    // Paired again, with another passkey.
    paired(&d).await;
    assert!(!held());
    assert!(!d.phone_page("nPHONE").notified);
    notified(&d, &browser);
    assert!(held());

    let r = d
        .handle(Request::PhoneUnpair {
            passphrase: pw("pw"),
        })
        .await;
    assert!(matches!(r, Response::Store { .. }), "{r:?}");
    assert!(!held());

    // Locked, nothing is known of the phone, so nothing is told.
    paired(&d).await;
    notified(&d, &browser);
    d.lock();
    assert_eq!(d.phone_push_key("nPHONE"), Err(PhoneError::Locked));
    assert_eq!(service.sent().len(), 0);
}

/// The phone leaves an approval standing only where the prompt offers
/// that, and the choice is made with the challenge, before the passkey
/// signs.
#[tokio::test]
async fn the_phone_leaves_standing_only_what_offers_it() {
    let (_tmp, _log, _file, d) = phone_daemon().await;
    paired(&d).await;
    // Asked by a process no agent stands behind.
    let nobody = crate::test_support::Orphan::start();
    let (asked, pending) = asked_from(&d, get(Some("dev"), "S", "pw"), &nobody.caller()).await;
    let id = pending[0].id;
    assert_eq!(pending[0].standing, None);
    assert_eq!(
        d.phone_approve_begin("nPHONE", id, true),
        Err(PhoneError::NoStanding)
    );
    assert_eq!(d.phone_page("nPHONE").standing, []);
    d.phone_deny(&phone(), id).unwrap();
    asked.await.unwrap();
}

/// Approved on the phone for a while, an agent gets the environment again
/// with nobody asked; the page lists what stands, to the paired phone
/// only, and ends it with no proof, as it denies.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn the_phone_leaves_an_approval_standing_and_ends_it() {
    use super::standing::FakeAgent;
    let (_tmp, log, _file, d) = phone_daemon().await;
    let passkey = paired(&d).await;
    let agent = FakeAgent::start();
    let command = agent.caller();
    let run = || Request::RunEnv {
        facts: facts(Some("dev"), Some(&["S"])),
        program: Some("deploy".into()),
        command: vec!["deploy".into()],
    };

    let (asked, pending) = asked_from(&d, run(), &command).await;
    let id = pending[0].id;
    let begin = d.phone_approve_begin("nPHONE", id, true).unwrap();
    let (client, auth, signature) = passkey.get(&site(), &begin.challenge);
    d.phone_approve(&site(), &phone(), id, &client, &auth, &signature)
        .unwrap();
    let r = asked.await.unwrap();
    assert!(matches!(r, Response::RunEnv(_)), "{r:?}");

    let page = d.phone_page("nPHONE");
    let [stands] = &page.standing[..] else {
        panic!("{page:?}")
    };
    assert_eq!(
        (
            stands.project.as_str(),
            stands.env.as_str(),
            &*stands.holder
        ),
        ("widget", "dev", "Claude Code")
    );
    assert_eq!(d.phone_page("nTABLET").standing, []);
    let r = d.handle_from(run(), &command).await;
    assert!(matches!(r, Response::RunEnv(_)), "{r:?}");
    let lines = logged(&log);
    for line in [
        "phone approve allowed",
        "approval stands allowed",
        "use approval allowed",
    ] {
        assert!(lines.iter().any(|l| l == line), "{line}: {lines:?}");
    }

    let (project, env) = ("widget".parse().unwrap(), "dev".parse().unwrap());
    assert_eq!(
        d.phone_end_standing(&peer("nTABLET", "tablet"), &project, &env),
        Err(PhoneError::NotPaired)
    );
    assert_eq!(d.phone_page("nPHONE").standing.len(), 1);
    d.phone_end_standing(&phone(), &project, &env).unwrap();
    assert_eq!(d.phone_page("nPHONE").standing, []);
    // Ended: the next one is asked about again.
    let (asked, pending) = asked_from(&d, run(), &command).await;
    d.phone_deny(&phone(), pending[0].id).unwrap();
    assert_eq!(error_code(asked.await.unwrap()), ErrorCode::NotApproved);
}
