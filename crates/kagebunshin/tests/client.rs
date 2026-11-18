//! The CLI's synchronous client against an in-process daemon.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test code")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::time::Duration;

use kagebunshin::ipc::client::{Client, ClientError};
use kagebunshin::ipc::protocol::{ErrorCode, Request, Response};
use kagebunshin::ipc::server::ServerConfig;
use kagebunshin::sys;
use kagebunshin::test_support::TestDaemon;

const T: Duration = Duration::from_secs(5);

fn private_dir(tmp: &Path) -> PathBuf {
    let dir = tmp.join("kb");
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

#[test]
fn ping_and_whoami() {
    let tmp = tempfile::tempdir().unwrap();
    let d = TestDaemon::start(tmp.path()).unwrap();
    let mut c = Client::connect(d.socket(), T).unwrap();
    assert_eq!(c.request(Request::Ping).unwrap(), Response::Pong);
    let Response::Whoami(me) = c.request(Request::Whoami).unwrap() else {
        panic!("not whoami")
    };
    assert_eq!(me.pid, std::process::id() as i32);
    assert_eq!(me.uid, sys::effective_uid());
    // Daemon errors surface as ClientError::Daemon and keep the connection.
    let err = c
        .request(Request::Hello {
            build: "again".into(),
        })
        .unwrap_err();
    assert!(matches!(err, ClientError::Daemon(e) if e.code == ErrorCode::BadRequest));
    assert_eq!(c.request(Request::Ping).unwrap(), Response::Pong);
}

#[test]
fn not_running_covers_missing_dir_missing_socket_and_stale_socket() {
    let tmp = tempfile::tempdir().unwrap();
    let missing_dir = tmp.path().join("nope").join("kagebunshind.sock");
    assert!(matches!(
        Client::connect(&missing_dir, T),
        Err(ClientError::NotRunning { .. })
    ));

    let socket = private_dir(tmp.path()).join("kagebunshind.sock");
    assert!(matches!(
        Client::connect(&socket, T),
        Err(ClientError::NotRunning { .. })
    ));

    drop(UnixListener::bind(&socket).unwrap());
    assert!(matches!(
        Client::connect(&socket, T),
        Err(ClientError::NotRunning { .. })
    ));
}

#[test]
fn refuses_a_socket_in_an_open_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = private_dir(tmp.path());
    let socket = dir.join("kagebunshind.sock");
    let _listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        Client::connect(&socket, T),
        Err(ClientError::InsecureDir(_))
    ));
}

#[test]
fn build_mismatch_is_reported_with_its_hint() {
    let tmp = tempfile::tempdir().unwrap();
    let mut cfg = ServerConfig::new(tmp.path().join("kb").join("kagebunshind.sock"));
    cfg.build_id = "0.0.0-older".into();
    let d = TestDaemon::start_with(cfg).unwrap();
    let Err(ClientError::Daemon(e)) = Client::connect(d.socket(), T) else {
        panic!("expected a daemon error")
    };
    assert_eq!(e.code, ErrorCode::BuildMismatch);
    assert!(e.hint.is_some());
}

#[test]
fn a_daemon_that_never_answers_times_out() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = private_dir(tmp.path()).join("kagebunshind.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    // Accept and hold the connection without ever replying.
    let holder = std::thread::spawn(move || listener.accept().map(|(s, _)| s));
    let t = Duration::from_millis(200);
    assert!(matches!(
        Client::connect(&socket, t),
        Err(ClientError::Timeout(d)) if d == t
    ));
    drop(holder.join());
}

/// `connect proton` and other requests that may reach a provider wait
/// longer than local ones: a reply slower than the local deadline still
/// arrives for them, while a local request times out.
#[test]
fn provider_requests_wait_longer_than_local_ones() {
    use kagebunshin::ipc::client::{DEFAULT_TIMEOUT, PROVIDER_TIMEOUT, deadline};
    use kagebunshin::ipc::frame::{read_frame, write_frame};
    use kagebunshin::ipc::protocol::{RequestFrame, ResponseFrame, WireSecret};

    let connect = || Request::ProtonConnect {
        token: WireSecret::new("t".into()),
        expires: None,
        passphrase: WireSecret::new("p".into()),
    };
    assert_eq!(deadline(&connect(), DEFAULT_TIMEOUT), PROVIDER_TIMEOUT);
    assert!(PROVIDER_TIMEOUT >= Duration::from_secs(30));
    assert_eq!(deadline(&Request::Ping, DEFAULT_TIMEOUT), DEFAULT_TIMEOUT);
    // Status alone is the daemon's own state; with facts it may fetch.
    let status = |facts| Request::Status { facts };
    assert_eq!(deadline(&status(None), DEFAULT_TIMEOUT), DEFAULT_TIMEOUT);
    let facts = kagebunshin::ipc::protocol::Facts {
        cwd: "/".into(),
        remotes: Vec::new(),
        subdir: None,
        root: None,
        project: None,
        env: None,
        example_keys: None,
        example_values: Vec::new(),
        env_file: None,
    };
    assert_eq!(
        deadline(&status(Some(facts)), DEFAULT_TIMEOUT),
        PROVIDER_TIMEOUT
    );

    let tmp = tempfile::tempdir().unwrap();
    let socket = private_dir(tmp.path()).join("kagebunshind.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    // Answers the handshake at once and every other request slowly.
    let daemon = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        while let Ok(req) = read_frame::<_, RequestFrame>(&mut s) {
            let body = if let Request::Hello { build } = req.body {
                Response::Hello { build }
            } else {
                std::thread::sleep(Duration::from_millis(600));
                Response::Pong
            };
            if write_frame(&mut s, &ResponseFrame { id: req.id, body }).is_err() {
                break;
            }
        }
    });
    let t = Duration::from_millis(200);
    let mut c = Client::connect(&socket, t).unwrap();
    assert_eq!(c.request(connect()).unwrap(), Response::Pong);
    assert!(matches!(
        c.request(Request::Ping),
        Err(ClientError::Timeout(d)) if d == t
    ));
    drop(c);
    daemon.join().unwrap();
}
