//! An approval left standing: for a while its holder gets the same
//! environment again without a person being asked.

use super::*;
use crate::daemon::broker::{Holder, STANDING, Scope};
use crate::ipc::protocol::{StandingOffer, StandingView};
use crate::test_support::Orphan;

async fn standing(d: &Daemon) -> Vec<StandingView> {
    match d.handle(Request::Status { facts: None }).await {
        Response::Status(report) => report.standing,
        other => panic!("{other:?}"),
    }
}

fn stand(id: u64, pass: &str) -> Request {
    Request::ApproveStanding {
        id,
        passphrase: pw(pass),
    }
}

fn end(env: &str) -> Request {
    Request::EndStanding {
        project: "widget".parse().unwrap(),
        env: env.parse().unwrap(),
    }
}

/// Approved for a while, a machine gets the same environment again with
/// no prompt, and with the app closed, until the time is up, the approval
/// is ended or the daemon locks. Nobody else does, and each hand-out is in
/// the audit log.
#[tokio::test]
async fn an_approval_left_standing_answers_its_holder_until_it_ends() {
    let (_tmp, log, d, _) = remote_daemon().await;
    let me = granted(&d, &["prod"]).await;
    let got = |r: Response| match r {
        Response::RunEnv(reply) => reply.vars[0].value.expose().to_owned(),
        other => panic!("{other:?}"),
    };
    assert_eq!(standing(&d).await, []);

    let (asked, pending) = asked_from(&d, remote_run("prod"), &me).await;
    assert_eq!(
        pending[0].standing,
        Some(StandingOffer {
            seconds: 900,
            holder: "machine laptop".into()
        })
    );
    // The passphrase is what approves, standing or not.
    let r = d.handle(stand(pending[0].id, "wrong")).await;
    assert_eq!(error_code(r), ErrorCode::WrongPassphrase);
    assert_eq!(
        standing(&d).await,
        [],
        "nothing stands before it is approved"
    );
    let r = d.handle(stand(pending[0].id, "pw")).await;
    assert_eq!(r, Response::Approvals { pending: vec![] });
    assert_eq!(got(asked.await.unwrap()), "widget.prod value");

    let [stands] = &standing(&d).await[..] else {
        panic!("one stands")
    };
    assert_eq!(
        (
            stands.project.as_str(),
            stands.env.as_str(),
            &*stands.holder
        ),
        ("widget", "prod", "machine laptop")
    );
    assert!(stands.left > 890 && stands.left <= 900, "{stands:?}");

    // Again, with the app closed: nobody is asked.
    for _ in 0..2 {
        assert_eq!(
            got(d.handle_from(remote_run("prod"), &me).await),
            "widget.prod value"
        );
    }
    // A process of this machine is nobody's holder: it still asks, and
    // with the app closed that is a refusal.
    let r = d.handle(remote_run("prod")).await;
    assert_eq!(error_code(r), ErrorCode::SensitiveEnv);

    let lines = logged(&log);
    let count = |line: &str| lines.iter().filter(|l| *l == line).count();
    assert_eq!(count("approval stands allowed"), 1, "{lines:?}");
    assert_eq!(count("use approval allowed"), 2, "{lines:?}");

    // Ended: it asks again. Ending takes no passphrase, and ends nothing
    // of another environment.
    assert_eq!(
        d.handle(end("dev")).await,
        Response::StandingEnded { ended: 0 }
    );
    assert_eq!(
        d.handle(end("prod")).await,
        Response::StandingEnded { ended: 1 }
    );
    assert_eq!(standing(&d).await, []);
    let r = d.handle_from(remote_run("prod"), &me).await;
    assert_eq!(error_code(r), ErrorCode::SensitiveEnv);
    assert!(logged(&log).iter().any(|l| l == "end approval allowed"));

    // Its time runs out.
    let (asked, pending) = asked_from(&d, remote_run("prod"), &me).await;
    d.handle(stand(pending[0].id, "pw")).await;
    asked.await.unwrap();
    tokio::time::pause();
    tokio::time::advance(STANDING.saturating_sub(Duration::from_secs(5))).await;
    assert_eq!(standing(&d).await.len(), 1);
    assert_eq!(
        got(d.handle_from(remote_run("prod"), &me).await),
        "widget.prod value"
    );
    tokio::time::advance(Duration::from_secs(6)).await;
    assert_eq!(standing(&d).await, []);
    let r = d.handle_from(remote_run("prod"), &me).await;
    assert_eq!(error_code(r), ErrorCode::SensitiveEnv);
    tokio::time::resume();

    // A lock ends it with everything else the session holds.
    let (asked, pending) = asked_from(&d, remote_run("prod"), &me).await;
    d.handle(stand(pending[0].id, "pw")).await;
    asked.await.unwrap();
    assert_eq!(standing(&d).await.len(), 1);
    d.lock();
    d.unlock(Some(Passphrase::new("pw".into()))).await.unwrap();
    assert_eq!(standing(&d).await, []);
    // Another machine may not end one, nor ask for one to stand.
    for req in [end("prod"), stand(1, "pw")] {
        let r = d.handle_from(req, &me).await;
        assert!(matches!(r, Response::Error(_)), "{r:?}");
    }
}

/// A request no coding agent or machine stands behind is approved for
/// itself only: its prompt offers nothing more, and asking for it is
/// refused and leaves the request waiting.
#[tokio::test]
async fn a_request_nobody_stands_behind_is_approved_once() {
    let (_tmp, _log, d, _) = remote_daemon().await;
    let nobody = Orphan::start();
    assert_eq!(Holder::of(&nobody.caller()), None);
    let (asked, pending) = asked_from(&d, remote_run("prod"), &nobody.caller()).await;
    assert_eq!(pending[0].standing, None);
    let r = d.handle(stand(pending[0].id, "pw")).await;
    assert_eq!(error_code(r), ErrorCode::BadRequest);
    assert!(!asked.is_finished());
    let r = d
        .handle(Request::Approve {
            id: pending[0].id,
            passphrase: Some(pw("pw")),
            values: Vec::new(),
        })
        .await;
    assert_eq!(r, Response::Approvals { pending: vec![] });
    assert!(matches!(asked.await.unwrap(), Response::RunEnv(_)));
    assert_eq!(standing(&d).await, []);
}

/// What was approved is what stands: the same kind of request, for no key
/// that was not approved.
#[test]
fn an_approval_covers_no_more_than_was_approved() {
    let keys = |names: &[&str]| Some(names.iter().map(|k| key(k)).collect());
    let whole = Scope {
        whole: true,
        keys: None,
    };
    let listed = Scope {
        whole: true,
        keys: keys(&["A", "B"]),
    };
    let marked = Scope {
        whole: false,
        keys: keys(&["A", "B"]),
    };
    let of = |whole: bool, names: &[&str]| Scope {
        whole,
        keys: keys(names),
    };
    assert!(whole.covers(&whole));
    assert!(!whole.covers(&listed) && !listed.covers(&whole));
    assert!(listed.covers(&of(true, &["A"])) && listed.covers(&listed));
    assert!(!listed.covers(&of(true, &["A", "C"])));
    assert!(marked.covers(&of(false, &["B"])));
    assert!(!marked.covers(&of(false, &["C"])));
    // Some keys marked is not the environment marked.
    assert!(!marked.covers(&listed) && !listed.covers(&marked) && !marked.covers(&whole));
}

/// A process named as a coding agent is, with a child of its own: what an
/// agent's command looks like to the daemon. Both end with it.
#[cfg(target_os = "linux")]
pub(super) struct FakeAgent {
    agent: std::process::Child,
    child: i32,
    _dir: tempfile::TempDir,
}

#[cfg(target_os = "linux")]
impl FakeAgent {
    pub(super) fn start() -> Self {
        use std::io::BufRead as _;
        let dir = tempfile::tempdir().unwrap();
        // The kernel names a process by the path it was run as.
        let bin = dir.path().join("claude");
        std::os::unix::fs::symlink("/bin/sh", &bin).unwrap();
        let mut agent = std::process::Command::new(&bin)
            .args(["-c", "sleep 300 & echo $!; wait"])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut line = String::new();
        std::io::BufReader::new(agent.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        Self {
            agent,
            child: line.trim().parse().unwrap(),
            _dir: dir,
        }
    }

    /// The agent's command, as the daemon sees a caller.
    pub(super) fn caller(&self) -> crate::ipc::protocol::Caller {
        crate::test_support::caller_for(self.child)
    }

    /// The agent exits; its command goes on, a child of nothing here.
    pub(super) fn exit(&mut self) {
        self.agent.kill().unwrap();
        self.agent.wait().unwrap();
    }
}

#[cfg(target_os = "linux")]
impl Drop for FakeAgent {
    fn drop(&mut self) {
        let _ = std::process::Command::new("kill")
            .arg(self.child.to_string())
            .status();
        let _ = self.agent.kill();
        let _ = self.agent.wait();
    }
}

/// A coding agent's approval is for what that agent's process runs: the
/// daemon finds the agent among the caller's parents, and answers what
/// descends from it. Another process is asked about as ever, and so is
/// the agent's own command once the agent has exited.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn an_agents_approval_is_for_what_that_agent_runs() {
    let (_tmp, _log, d, _) = remote_daemon().await;
    let mut agent = FakeAgent::start();
    let command = agent.caller();
    let holder = Holder::of(&command).unwrap();
    assert_eq!(holder.named(), "Claude Code");
    assert!(holder.covers(&command));
    assert!(!holder.covers(&this_process()));

    let (asked, pending) = asked_from(&d, remote_run("prod"), &command).await;
    assert_eq!(
        pending[0].standing.as_ref().map(|s| s.holder.as_str()),
        Some("Claude Code")
    );
    assert_eq!(pending[0].parents[0], "claude");
    d.handle(stand(pending[0].id, "pw")).await;
    assert!(matches!(asked.await.unwrap(), Response::RunEnv(_)));
    assert_eq!(standing(&d).await[0].holder, "Claude Code");

    let r = d.handle_from(remote_run("prod"), &command).await;
    assert!(matches!(r, Response::RunEnv(_)), "{r:?}");
    // The test's own process is not the agent's.
    let r = d.handle(remote_run("prod")).await;
    assert_eq!(error_code(r), ErrorCode::SensitiveEnv);

    // The agent is gone: nothing stands for it, though its command lives.
    agent.exit();
    assert!(!holder.covers(&command));
    let r = d.handle_from(remote_run("prod"), &command).await;
    assert_eq!(error_code(r), ErrorCode::SensitiveEnv);
    assert_eq!(standing(&d).await, []);
}
