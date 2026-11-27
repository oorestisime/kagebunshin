//! The daemon socket end to end: directory and file modes, the single-daemon
//! lock, stale sockets, the handshake, and caller identity.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test code")]

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use kagebunshin::ipc::frame::{FrameError, read_frame, write_frame};
use kagebunshin::ipc::protocol::{
    BUILD_ID, Caller, ErrorCode, Request, RequestFrame, Response, ResponseFrame,
};
use kagebunshin::ipc::server::{ServerConfig, ServerError};
use kagebunshin::sys;
use kagebunshin::test_support::TestDaemon;

fn connect(socket: &Path) -> UnixStream {
    let s = UnixStream::connect(socket).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s
}

fn call(s: &mut UnixStream, id: u64, body: Request) -> ResponseFrame {
    write_frame(s, &RequestFrame { id, body }).unwrap();
    read_frame(s).unwrap()
}

fn hello(s: &mut UnixStream) {
    let r = call(
        s,
        1,
        Request::Hello {
            build: BUILD_ID.into(),
        },
    );
    assert_eq!(
        r.body,
        Response::Hello {
            build: BUILD_ID.into()
        }
    );
}

fn mode(p: &Path) -> u32 {
    fs::symlink_metadata(p).unwrap().mode() & 0o7777
}

#[test]
fn creates_private_dir_and_socket() {
    let tmp = tempfile::tempdir().unwrap();
    let d = TestDaemon::start(tmp.path()).unwrap();
    assert_eq!(mode(d.socket().parent().unwrap()), 0o700);
    assert_eq!(mode(d.socket()), 0o600);
    let socket = d.socket().to_owned();
    drop(d);
    assert!(!socket.exists(), "socket removed on shutdown");
}

#[test]
fn refuses_an_open_or_symlinked_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let open = tmp.path().join("kb");
    fs::create_dir(&open).unwrap();
    fs::set_permissions(&open, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        TestDaemon::start(tmp.path()),
        Err(ServerError::Dir(_))
    ));

    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("real");
    fs::create_dir(&real).unwrap();
    fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
    std::os::unix::fs::symlink(&real, tmp.path().join("kb")).unwrap();
    assert!(matches!(
        TestDaemon::start(tmp.path()),
        Err(ServerError::Dir(_))
    ));
}

#[test]
fn only_one_daemon_per_socket() {
    let tmp = tempfile::tempdir().unwrap();
    let first = TestDaemon::start(tmp.path()).unwrap();
    assert!(matches!(
        TestDaemon::start(tmp.path()),
        Err(ServerError::AlreadyRunning { .. })
    ));
    // The refused second daemon must not have removed the live socket.
    let mut s = connect(first.socket());
    hello(&mut s);
}

#[test]
fn replaces_a_stale_socket_but_not_other_files() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("kb");
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    let socket = dir.join("kagebunshind.sock");

    // A daemon that died without cleanup leaves the socket file behind.
    drop(UnixListener::bind(&socket).unwrap());
    assert!(socket.exists());
    let d = TestDaemon::start(tmp.path()).unwrap();
    let mut s = connect(d.socket());
    hello(&mut s);
    drop(s);
    drop(d);

    fs::write(&socket, b"not a socket").unwrap();
    assert!(matches!(
        restart(tmp.path()),
        Err(ServerError::NotASocket { .. })
    ));
}

/// Starts a daemon where one has just stopped. A process spawned by another
/// test in this binary shares the old lock's open file description from fork
/// until exec, so for a moment the lock can still look held.
fn restart(dir: &Path) -> Result<TestDaemon, ServerError> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match TestDaemon::start(dir) {
            Err(ServerError::AlreadyRunning { .. }) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            r => return r,
        }
    }
}

#[test]
fn hello_ping_whoami() {
    let tmp = tempfile::tempdir().unwrap();
    let d = TestDaemon::start(tmp.path()).unwrap();
    let mut s = connect(d.socket());
    hello(&mut s);
    assert_eq!(call(&mut s, 2, Request::Ping).body, Response::Pong);
    let r = call(&mut s, 3, Request::Whoami);
    assert_eq!(r.id, 3);
    let Response::Whoami(me) = r.body else {
        panic!("{r:?}")
    };
    let pid = std::process::id() as i32;
    assert_eq!(me.pid, pid);
    assert_eq!(me.uid, sys::effective_uid());
    assert_eq!(me.start_time, sys::process_start(pid).unwrap());
    // A second hello is a protocol error.
    let r = call(
        &mut s,
        4,
        Request::Hello {
            build: BUILD_ID.into(),
        },
    );
    assert!(matches!(r.body, Response::Error(e) if e.code == ErrorCode::BadRequest));
}

#[test]
fn mismatched_build_is_refused_and_closed() {
    let tmp = tempfile::tempdir().unwrap();
    let d = TestDaemon::start(tmp.path()).unwrap();
    let mut s = connect(d.socket());
    let r = call(
        &mut s,
        1,
        Request::Hello {
            build: "0.0.0-other".into(),
        },
    );
    let Response::Error(e) = r.body else {
        panic!("{r:?}")
    };
    assert_eq!(e.code, ErrorCode::BuildMismatch);
    assert!(e.message.contains("0.0.0-other") && e.message.contains(BUILD_ID));
    assert!(
        e.hint
            .unwrap()
            .contains("it restarts the daemon on this build")
    );
    assert!(matches!(
        read_frame::<_, ResponseFrame>(&mut s),
        Err(FrameError::Closed)
    ));
}

#[test]
fn first_message_must_be_hello() {
    let tmp = tempfile::tempdir().unwrap();
    let d = TestDaemon::start(tmp.path()).unwrap();
    let mut s = connect(d.socket());
    let r = call(&mut s, 1, Request::Whoami);
    assert!(matches!(r.body, Response::Error(e) if e.code == ErrorCode::BadRequest));
    assert!(matches!(
        read_frame::<_, ResponseFrame>(&mut s),
        Err(FrameError::Closed)
    ));
}

#[test]
fn garbage_and_oversized_frames_close_the_connection() {
    let tmp = tempfile::tempdir().unwrap();
    let d = TestDaemon::start(tmp.path()).unwrap();

    let mut s = connect(d.socket());
    s.write_all(&5u32.to_be_bytes()).unwrap();
    s.write_all(b"nope!").unwrap();
    let r: ResponseFrame = read_frame(&mut s).unwrap();
    assert!(matches!(r.body, Response::Error(e) if e.code == ErrorCode::BadRequest));
    assert!(matches!(
        read_frame::<_, ResponseFrame>(&mut s),
        Err(FrameError::Closed)
    ));

    let mut s = connect(d.socket());
    s.write_all(&u32::MAX.to_be_bytes()).unwrap();
    let mut rest = Vec::new();
    s.read_to_end(&mut rest).unwrap();
    assert!(rest.is_empty(), "no reply to an oversized frame");

    // The daemon is still serving.
    let mut s = connect(d.socket());
    hello(&mut s);
}

#[test]
fn silent_clients_are_dropped_after_the_handshake_timeout() {
    let tmp = tempfile::tempdir().unwrap();
    let mut cfg = ServerConfig::new(tmp.path().join("kb").join("kagebunshind.sock"));
    cfg.handshake_timeout = Duration::from_millis(100);
    let d = TestDaemon::start_with(cfg).unwrap();
    let mut s = connect(d.socket());
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).unwrap();
    assert!(buf.is_empty());
}

/// Re-executes this test binary as a separate client process, so the daemon
/// sees a different pid from ours. The child reports through a file because
/// libtest may hold its stdout until the test finishes.
#[test]
fn identifies_a_separate_client_process() {
    let tmp = tempfile::tempdir().unwrap();
    let d = TestDaemon::start(tmp.path()).unwrap();
    let report = tmp.path().join("whoami.json");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["child_whoami_helper", "--exact", "--test-threads=1"])
        .env(HELPER_SOCKET_ENV, d.socket())
        .env(HELPER_REPORT_ENV, &report)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let child_pid = child.id() as i32;
    assert!(child.wait().unwrap().success(), "helper failed");

    let (seen, own_start): (Caller, sys::ProcStart) =
        serde_json::from_slice(&fs::read(&report).unwrap()).unwrap();
    assert_eq!(seen.pid, child_pid);
    assert_ne!(seen.pid, std::process::id() as i32);
    assert_eq!(seen.uid, sys::effective_uid());
    assert_eq!(seen.start_time, own_start);
}

const HELPER_SOCKET_ENV: &str = "KB_TEST_WHOAMI_SOCKET";
const HELPER_REPORT_ENV: &str = "KB_TEST_WHOAMI_REPORT";

/// No-op unless spawned by `identifies_a_separate_client_process`. Reports what
/// the daemon saw next to the start time this process reads for itself.
#[test]
fn child_whoami_helper() {
    let (Some(socket), Some(report)) = (
        std::env::var_os(HELPER_SOCKET_ENV),
        std::env::var_os(HELPER_REPORT_ENV),
    ) else {
        return;
    };
    let mut s = connect(Path::new(&socket));
    hello(&mut s);
    let r = call(&mut s, 2, Request::Whoami);
    let Response::Whoami(me) = r.body else {
        panic!("{r:?}")
    };
    let own_start = sys::process_start(std::process::id() as i32).unwrap();
    fs::write(report, serde_json::to_vec(&(me, own_start)).unwrap()).unwrap();
}
