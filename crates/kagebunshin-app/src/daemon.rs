//! Talking to the daemon off the main thread.
//!
//! A [`Worker`] thread owns the [`DaemonClient`] and carries out one [`Job`]
//! at a time, in order, waking the window when each answer lands. A job
//! that only reads (an environment's keys, the providers) runs beside it
//! on a thread of its own, so it waits for no other job and none waits for
//! it: one environment that is slow to read does not hold back the next.
//! Jobs and answers carry the [`Attempt`] that asked, so the state machine
//! can drop answers it no longer waits for. Every reply but two carries key names and
//! origins only: [`Job::Reveal`] fetches one value a person asked to see,
//! and [`Job::RotateGrant`] the new token of a remote grant, each held as
//! a [`WireSecret`], zeroed on drop and never shown by `Debug`. The
//! store passphrase a person types, for unlocking, marks, inspecting and
//! revealing, passes through the same way and is sent once, as does a
//! Proton Pass token being connected.
//!
//! An [`Approver`] runs beside it, on threads of its own: it waits on the
//! daemon for `run` and `get` requests that need a person's approval, and
//! sends the answer, with the passphrase typed to approve, the same way.

#[cfg(test)]
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::mpsc;
#[cfg(test)]
use std::sync::{Arc, Mutex};

use kagebunshin::cli::error::start_daemon_hint;
use kagebunshin::ipc::client::{Client, ClientError, DEFAULT_TIMEOUT};
use kagebunshin::ipc::protocol::{
    ApprovalPrompt, ErrorCode, Facts, Fix, GrantView, KeyStatus, PhoneChoice, PhoneStatus, Proof,
    RemoteStatus, Request, Response, SharedSecret, StandingView, TokenExpiry, VarStatus,
    WaitingEnv, WireSecret,
};
use kagebunshin::source::ProviderStatus;
use kagebunshin::store::Section;
use kagebunshin::types::{EnvName, KeyName, Origin, ProjectName};
use rune::Waker;
use rune::machine::Attempt;

/// Sends one request to the daemon and waits for its reply.
pub trait DaemonClient: Send {
    fn request(&mut self, req: Request) -> Result<Response, ClientError>;

    /// Another client of the same daemon, to ask with while this one
    /// waits for an answer; none where requests are answered in order.
    fn beside(&self) -> Option<Box<dyn DaemonClient>> {
        None
    }
}

/// The real daemon, on a fresh connection per request: an idle window holds
/// no connection, and a restarted daemon is picked up on the next request.
pub struct SocketClient {
    pub socket: PathBuf,
}

impl DaemonClient for SocketClient {
    fn request(&mut self, req: Request) -> Result<Response, ClientError> {
        Client::connect(&self.socket, DEFAULT_TIMEOUT)?.request(req)
    }

    fn beside(&self) -> Option<Box<dyn DaemonClient>> {
        Some(Box::new(SocketClient {
            socket: self.socket.clone(),
        }))
    }
}

/// Answers requests from a script, in order, and records what it was asked.
/// With nothing scripted it answers as a daemon that is not running.
#[cfg(test)]
#[derive(Clone, Default)]
pub struct FakeClient {
    pub replies: Arc<Mutex<VecDeque<Result<Response, ClientError>>>>,
    pub asked: Arc<Mutex<Vec<Request>>>,
}

#[cfg(test)]
impl FakeClient {
    pub fn reply(&self, r: Result<Response, ClientError>) -> &Self {
        self.replies.lock().unwrap().push_back(r);
        self
    }
}

#[cfg(test)]
impl DaemonClient for FakeClient {
    fn request(&mut self, req: Request) -> Result<Response, ClientError> {
        self.asked.lock().unwrap().push(req);
        self.replies.lock().unwrap().pop_front().unwrap_or_else(|| {
            Err(ClientError::NotRunning {
                socket: "/fake/kagebunshind.sock".into(),
            })
        })
    }
}

/// What the window asks the worker to find out, or to do.
#[derive(Debug, PartialEq, Eq)]
pub enum Job {
    /// Whether the daemon answers, and whether it is locked.
    Probe,
    /// Whether each provider in play can read: those any environment
    /// reads from, AWS's default profile and, while unlocked, those with a
    /// token saved.
    Providers,
    /// Where each key of one environment comes from.
    Env {
        facts: Facts,
    },
    Lock,
    /// Without a passphrase first; the daemon says if it needs one.
    Unlock {
        passphrase: Option<WireSecret>,
    },
    /// Fetch one environment again.
    Sync {
        project: ProjectName,
        env: EnvName,
    },
    /// Mark something sensitive, or remove its mark.
    Mark {
        mark: Mark,
        sensitive: bool,
        passphrase: WireSecret,
    },
    /// As `Env`, for an environment marked sensitive.
    Inspect {
        facts: Facts,
        passphrase: WireSecret,
    },
    /// One value, sensitive or not.
    Reveal {
        facts: Facts,
        key: KeyName,
        passphrase: WireSecret,
    },
    /// Save a Proton Pass token, once `pass-cli` logs in with it.
    ConnectProton {
        token: WireSecret,
        expires: Option<u64>,
        passphrase: WireSecret,
    },
    /// Acknowledge an environment that looks like production as not, or
    /// take that back.
    Acknowledge {
        project: ProjectName,
        env: EnvName,
        acknowledged: bool,
        /// Marked secrets it reads, to unmark in the same write.
        unmark: Vec<Origin>,
        passphrase: WireSecret,
    },
    /// Acknowledge each of several environments as not production, with
    /// one passphrase.
    AcknowledgeAll {
        envs: Vec<Section>,
        passphrase: WireSecret,
    },
    /// Remove the marks of several secrets, with one passphrase.
    Unmark {
        secrets: Vec<Origin>,
        passphrase: WireSecret,
    },
    /// Give a remote grant a new token, ending the one it had.
    RotateGrant {
        grant: Grant,
        passphrase: WireSecret,
    },
    /// End a remote grant.
    RevokeGrant {
        grant: Grant,
        passphrase: WireSecret,
    },
    /// The phones on this tailnet that could be paired.
    Phones,
    /// Let a phone make the passkey it approves with, for a few minutes.
    PairPhone {
        phone: PhoneChoice,
        passphrase: WireSecret,
    },
    /// End a pairing before its time is up.
    StopPairing,
    /// End the approvals that stand for one environment.
    EndStanding {
        project: ProjectName,
        env: EnvName,
    },
    /// Remove the paired phone, by the name to say of it.
    UnpairPhone {
        name: String,
        passphrase: WireSecret,
    },
}

/// A pairing under way: the phone, and the address it opens to make its
/// passkey. The address is no secret: the page is served to that phone
/// alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pairing {
    pub phone: PhoneChoice,
    pub url: String,
}

/// A remote grant, as a change to it names it: the machine by its node id,
/// which is what the grant is to, and by its name, to say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub node: String,
    pub machine: String,
    pub project: ProjectName,
}

impl From<&GrantView> for Grant {
    fn from(g: &GrantView) -> Self {
        Self {
            node: g.node.clone(),
            machine: g.machine.clone(),
            project: g.project.clone(),
        }
    }
}

/// The token a grant was just given. The daemon says it this once and
/// keeps its hash.
#[derive(Debug, PartialEq, Eq)]
pub struct NewToken {
    pub grant: Grant,
    pub token: WireSecret,
}

/// What a sensitive mark is on. Every mark is kept in the encrypted store,
/// so changing one takes its passphrase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mark {
    /// A local store key.
    Key { section: Section, key: KeyName },
    /// A whole environment. Marking it leaves unmarked the secrets an open
    /// environment reads too, but those in `also`.
    Env {
        project: ProjectName,
        env: EnvName,
        also: Vec<Origin>,
    },
    /// A secret of any provider but `file`, wherever it is read.
    Secret(Origin),
}

impl Mark {
    /// Its name, for the notice.
    fn what(&self) -> String {
        match self {
            Mark::Key { key, .. } => key.to_string(),
            Mark::Env { env, .. } => env.to_string(),
            Mark::Secret(secret) => secret.shown().to_owned(),
        }
    }

    fn request(self, sensitive: bool, passphrase: WireSecret) -> Request {
        match self {
            Mark::Key { section, key } => Request::StoreMark {
                section,
                key,
                sensitive,
                passphrase,
            },
            Mark::Env { project, env, also } => Request::MarkEnv {
                project,
                env,
                sensitive,
                also,
                passphrase,
            },
            Mark::Secret(secret) => Request::MarkSecret {
                secret,
                sensitive,
                passphrase,
            },
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Answer {
    Probe(Result<Probed, Problem>),
    Env(Result<EnvReport, Problem>),
    Revealed(Result<WireSecret, Problem>),
    Providers(Result<Vec<ProviderStatus>, Problem>),
    /// The token a grant now has.
    Token(Result<NewToken, Problem>),
    Phones(Result<Vec<PhoneChoice>, Problem>),
    /// A phone may now make its passkey.
    Pairing(Result<Pairing, Problem>),
    /// What a lock, unlock, sync, mark, connect or acknowledgement did.
    Action(Result<Done, Problem>),
}

/// What a probe learns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probed {
    pub locked: bool,
    /// Saved tokens near or past their expiry; known only while unlocked.
    pub expiring: Vec<TokenExpiry>,
    /// Environments that look like production and wait for a human
    /// decision; known only while unlocked.
    pub waiting: Vec<WaitingEnv>,
    /// Environments acknowledged as not production; known only while
    /// unlocked.
    pub acknowledged: Vec<Section>,
    /// Secrets that more than one environment reads; known only while
    /// unlocked.
    pub shared: Vec<SharedSecret>,
    /// The remote endpoint; its grants are known only while unlocked.
    pub remote: Option<RemoteStatus>,
    /// The approval page and the phone paired with it; none when no phone
    /// is paired or being paired, which is all that is known while locked.
    pub phone: Option<Box<PhoneStatus>>,
    /// The approvals that stand; known only while unlocked.
    pub standing: Vec<StandingView>,
}

#[cfg(test)]
impl Probed {
    pub fn locked(locked: bool) -> Self {
        Self {
            locked,
            expiring: Vec::new(),
            waiting: Vec::new(),
            acknowledged: Vec::new(),
            shared: Vec::new(),
            remote: None,
            phone: None,
            standing: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Done {
    /// Locked or unlocked; warnings from unlocking.
    LockState { locked: bool, warnings: Vec<String> },
    /// The daemon has a store and is locked: ask for its passphrase.
    PassphraseRequired,
    /// Fetched again, to this many keys.
    Synced { keys: usize, warnings: Vec<String> },
    /// `what` was marked sensitive, or with `sensitive` false unmarked: a
    /// key, an environment or a secret, by name.
    Marked { what: String, sensitive: bool },
    /// Proton Pass is connected, reading this many vaults; the daemon is
    /// `locked` or not after it.
    ProtonConnected { vaults: usize, locked: bool },
    /// Acknowledged as not production, or with `acknowledged` false taken
    /// back, and `unmarked` secrets unmarked with it.
    Acknowledged { acknowledged: bool, unmarked: usize },
    /// This many secrets were unmarked, at once.
    Unmarked(usize),
    /// A remote grant was ended.
    GrantRevoked(Grant),
    /// The pairing under way, if any, was ended.
    PairingStopped,
    /// The approvals that stood for an environment were ended.
    StandingEnded,
    /// The phone of this name is paired no more.
    PhoneUnpaired(String),
}

/// One environment as the daemon resolves it: names and origins, never values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvReport {
    /// The daemon is locked, so it resolved nothing.
    Locked,
    /// The environment is marked sensitive, so the daemon refused it.
    Sensitive,
    Resolved {
        /// In key order.
        keys: Vec<KeyStatus>,
        /// Listed in `.env.example` but resolved by no source; `None`
        /// without a `.env.example` to compare against.
        missing: Option<Vec<KeyName>>,
        /// Set by a plain setting of the project file and no source, in
        /// key order.
        vars: Vec<VarStatus>,
        /// Optional sources that failed and were skipped.
        warnings: Vec<String>,
        /// Acknowledged as not production, although it looks it.
        acknowledged: bool,
        /// Secrets a source left out, by name.
        skipped: Vec<String>,
        /// Commands that would fill in what is missing, and who runs each.
        fixes: Vec<Fix>,
        /// The last `run --strict` that succeeded with it as it is now.
        proof: Option<Proof>,
    },
}

/// An error as the window shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    pub message: String,
    pub hint: Option<String>,
    /// The daemon could not be reached at all, or is another build.
    pub unreachable: bool,
}

impl Problem {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            hint: None,
            unreachable: false,
        }
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }
}

impl From<ClientError> for Problem {
    fn from(e: ClientError) -> Self {
        let message = e.to_string();
        let unreachable = |hint: Option<String>| Problem {
            message: message.clone(),
            hint,
            unreachable: true,
        };
        match e {
            ClientError::NotRunning { .. } => unreachable(Some(start_daemon_hint())),
            ClientError::Timeout(_) => {
                unreachable(Some("the daemon may be stuck; restart it".into()))
            }
            ClientError::InsecureDir(_)
            | ClientError::ForeignDaemon { .. }
            | ClientError::Frame(_)
            | ClientError::Connect { .. }
            // The window talks to this machine's daemon only.
            | ClientError::ConnectRemote { .. }
            | ClientError::Remote { .. }
            | ClientError::NotADaemon { .. }
            | ClientError::BadToken => unreachable(None),
            ClientError::UnexpectedReply => Problem::new(message),
            ClientError::Daemon(w) => Problem {
                unreachable: w.code == ErrorCode::BuildMismatch,
                message: w.message,
                hint: w.hint,
            },
        }
    }
}

fn unexpected() -> Problem {
    Problem::from(ClientError::UnexpectedReply)
}

/// Carries out one job.
pub fn run(client: &mut dyn DaemonClient, job: Job) -> Answer {
    match job {
        Job::Probe => Answer::Probe(match client.request(Request::Status { facts: None }) {
            Ok(Response::Status(r)) => Ok(Probed {
                locked: r.locked,
                expiring: r.expiring,
                waiting: r.waiting,
                acknowledged: r.acknowledged,
                shared: r.shared,
                remote: r.remote,
                phone: r.phone,
                standing: r.standing,
            }),
            Ok(_) => Err(unexpected()),
            Err(e) => Err(e.into()),
        }),
        Job::Providers => Answer::Providers(
            match client.request(Request::Providers {
                facts: None,
                every: true,
            }) {
                Ok(Response::Providers { providers }) => Ok(providers),
                Ok(_) => Err(unexpected()),
                Err(e) => Err(e.into()),
            },
        ),
        Job::Env { facts } => Answer::Env(env(client, facts)),
        Job::Inspect { facts, passphrase } => Answer::Env(
            match client.request(Request::Inspect { facts, passphrase }) {
                Ok(Response::Status(s)) => match s.env {
                    Some(status) => Ok(EnvReport::Resolved {
                        keys: status.keys,
                        missing: None,
                        vars: status.vars,
                        warnings: status.warnings,
                        acknowledged: status.acknowledged,
                        skipped: status.skipped,
                        fixes: status.fixes,
                        proof: status.proof,
                    }),
                    None => Err(unexpected()),
                },
                Ok(_) => Err(unexpected()),
                Err(e) => Err(e.into()),
            },
        ),
        Job::Reveal {
            facts,
            key,
            passphrase,
        } => Answer::Revealed(
            match client.request(Request::Reveal {
                facts,
                key,
                passphrase,
            }) {
                Ok(Response::Value { value }) => Ok(value),
                Ok(_) => Err(unexpected()),
                Err(e) => Err(e.into()),
            },
        ),
        Job::RotateGrant { grant, passphrase } => Answer::Token(
            match client.request(Request::RemoteRotate {
                machine: grant.node.clone(),
                project: grant.project.clone(),
                passphrase,
            }) {
                Ok(Response::RemoteGranted { token, .. }) => Ok(NewToken { grant, token }),
                Ok(_) => Err(unexpected()),
                Err(e) => Err(e.into()),
            },
        ),
        Job::Phones => Answer::Phones(match client.request(Request::Phones) {
            Ok(Response::Phones { phones }) => Ok(phones),
            Ok(_) => Err(unexpected()),
            Err(e) => Err(e.into()),
        }),
        Job::PairPhone { phone, passphrase } => Answer::Pairing(
            // By its node id: a name is whatever a machine calls itself.
            match client.request(Request::PhonePair {
                machine: phone.node.clone(),
                passphrase,
            }) {
                Ok(Response::PhonePairing { url, .. }) => Ok(Pairing { phone, url }),
                Ok(_) => Err(unexpected()),
                Err(e) => Err(e.into()),
            },
        ),
        Job::EndStanding { project, env } => Answer::Action(
            match client.request(Request::EndStanding { project, env }) {
                Ok(Response::StandingEnded { .. }) => Ok(Done::StandingEnded),
                Ok(_) => Err(unexpected()),
                Err(e) => Err(e.into()),
            },
        ),
        Job::StopPairing => Answer::Action(match client.request(Request::PhonePairStop) {
            Ok(Response::PhonePairStopped) => Ok(Done::PairingStopped),
            Ok(_) => Err(unexpected()),
            Err(e) => Err(e.into()),
        }),
        Job::UnpairPhone { name, passphrase } => {
            Answer::Action(match client.request(Request::PhoneUnpair { passphrase }) {
                Ok(Response::Store { .. }) => Ok(Done::PhoneUnpaired(name)),
                Ok(_) => Err(unexpected()),
                Err(e) => Err(e.into()),
            })
        }
        job => Answer::Action(action(client, job)),
    }
}

fn action(client: &mut dyn DaemonClient, job: Job) -> Result<Done, Problem> {
    // Whether a passphrase went with it; what an acknowledgement asked.
    let mut asked_passphrase = false;
    let mut acknowledging = None;
    let mut unmarking = None;
    let mut marking = None;
    let mut revoking = None;
    let req = match job {
        Job::Probe
        | Job::Providers
        | Job::Env { .. }
        | Job::Inspect { .. }
        | Job::Reveal { .. }
        | Job::RotateGrant { .. }
        | Job::Phones
        | Job::PairPhone { .. }
        | Job::StopPairing
        | Job::EndStanding { .. }
        | Job::UnpairPhone { .. } => {
            unreachable!("not an action")
        }
        Job::RevokeGrant { grant, passphrase } => {
            let req = Request::RemoteRevoke {
                machine: grant.node.clone(),
                project: Some(grant.project.clone()),
                passphrase,
            };
            revoking = Some(grant);
            req
        }
        Job::Lock => Request::Lock,
        Job::Unlock { passphrase } => {
            asked_passphrase = passphrase.is_some();
            Request::Unlock { passphrase }
        }
        Job::Sync { project, env } => Request::Sync {
            project: Some(project),
            env: Some(env),
        },
        Job::Mark {
            mark,
            sensitive,
            passphrase,
        } => {
            marking = Some((mark.what(), sensitive));
            mark.request(sensitive, passphrase)
        }
        Job::ConnectProton {
            token,
            expires,
            passphrase,
        } => Request::ProtonConnect {
            token,
            expires,
            passphrase,
        },
        Job::Acknowledge {
            project,
            env,
            acknowledged,
            unmark,
            passphrase,
        } => {
            acknowledging = Some((acknowledged, unmark.len()));
            Request::AcknowledgeEnv {
                project,
                env,
                acknowledged,
                unmark,
                passphrase,
            }
        }
        Job::AcknowledgeAll { envs, passphrase } => {
            acknowledging = Some((true, 0));
            Request::AcknowledgeEnvs { envs, passphrase }
        }
        Job::Unmark {
            secrets,
            passphrase,
        } => {
            unmarking = Some(secrets.len());
            Request::UnmarkSecrets {
                secrets,
                passphrase,
            }
        }
    };
    match client.request(req) {
        Ok(Response::LockState { locked, warnings }) => Ok(Done::LockState { locked, warnings }),
        Ok(Response::Sync(report)) => {
            let mut keys = 0;
            let mut warnings = Vec::new();
            for s in report.refreshed {
                if let Some(e) = s.error {
                    return Err(ClientError::Daemon(e).into());
                }
                keys += s.keys.unwrap_or(0);
                warnings.extend(s.warnings);
            }
            Ok(Done::Synced { keys, warnings })
        }
        Ok(Response::Store { .. }) => match (acknowledging, unmarking, marking, revoking) {
            (Some((acknowledged, unmarked)), ..) => Ok(Done::Acknowledged {
                acknowledged,
                unmarked,
            }),
            (None, Some(n), ..) => Ok(Done::Unmarked(n)),
            (None, None, Some((what, sensitive)), _) => Ok(Done::Marked { what, sensitive }),
            (None, None, None, Some(grant)) => Ok(Done::GrantRevoked(grant)),
            (None, None, None, None) => Err(unexpected()),
        },
        Ok(Response::ProtonConnected { vaults, locked, .. }) => {
            Ok(Done::ProtonConnected { vaults, locked })
        }
        Ok(_) => Err(unexpected()),
        Err(ClientError::Daemon(w))
            if w.code == ErrorCode::PassphraseRequired && !asked_passphrase =>
        {
            Ok(Done::PassphraseRequired)
        }
        Err(e) => Err(e.into()),
    }
}

fn env(client: &mut dyn DaemonClient, facts: Facts) -> Result<EnvReport, Problem> {
    let compare = facts.example_keys.is_some();
    let status = match client.request(Request::Status {
        facts: Some(facts.clone()),
    }) {
        Ok(Response::Status(s)) => s,
        Ok(_) => return Err(unexpected()),
        Err(ClientError::Daemon(w)) if w.code == ErrorCode::SensitiveEnv => {
            return Ok(EnvReport::Sensitive);
        }
        Err(e) => return Err(e.into()),
    };
    let Some(status) = status.env else {
        return if status.locked {
            Ok(EnvReport::Locked)
        } else {
            Err(unexpected())
        };
    };
    let missing = if compare {
        match client.request(Request::Diff { facts })? {
            Response::Diff(d) => Some(d.missing),
            _ => return Err(unexpected()),
        }
    } else {
        None
    };
    Ok(EnvReport::Resolved {
        keys: status.keys,
        missing,
        vars: status.vars,
        warnings: status.warnings,
        acknowledged: status.acknowledged,
        skipped: status.skipped,
        fixes: status.fixes,
        proof: status.proof,
    })
}

/// The thread that runs jobs. Dropping it ends the thread once the job in
/// hand is done.
pub struct Worker {
    jobs: mpsc::Sender<(Attempt, Job)>,
    answers: mpsc::Receiver<(Attempt, Answer)>,
    /// Where an answer goes, and what tells the window it is there: for
    /// the jobs that run beside the thread.
    outbox: mpsc::Sender<(Attempt, Answer)>,
    waker: Waker,
    /// Makes the client of a job that runs beside the thread; none where
    /// the daemon's client answers in order only.
    reader: Option<Box<dyn DaemonClient>>,
}

impl Worker {
    /// Fails when the OS cannot start another thread.
    pub fn spawn(mut client: Box<dyn DaemonClient>, waker: Waker) -> Result<Self, Problem> {
        let (jobs, inbox) = mpsc::channel::<(Attempt, Job)>();
        let (outbox, answers) = mpsc::channel();
        let reader = client.beside();
        let (out, wake) = (outbox.clone(), waker.clone());
        std::thread::Builder::new()
            .name("kagebunshin-daemon".into())
            .spawn(move || {
                for (attempt, job) in inbox {
                    if out.send((attempt, run(&mut *client, job))).is_err() {
                        return;
                    }
                    wake();
                }
            })
            .map_err(|e| Problem::new(format!("cannot start the daemon thread: {e}")))?;
        Ok(Self {
            jobs,
            answers,
            outbox,
            waker,
            reader,
        })
    }

    /// A job that only reads and changes nothing runs on a thread of its
    /// own, so its answer may come in any order with the others'. What
    /// changes the daemon, and the probe that says what it changed, wait
    /// their turn on the worker's thread.
    pub fn send(&self, attempt: Attempt, job: Job) {
        let failed: Option<fn(Problem) -> Answer> = match job {
            Job::Env { .. } => Some(|p| Answer::Env(Err(p))),
            Job::Providers => Some(|p| Answer::Providers(Err(p))),
            _ => None,
        };
        let client = self.reader.as_ref().and_then(|r| r.beside());
        let Some((failed, mut client)) = failed.zip(client) else {
            // The thread only stops when this side is dropped.
            let _ = self.jobs.send((attempt, job));
            return;
        };
        let (out, wake) = (self.outbox.clone(), self.waker.clone());
        let started = std::thread::Builder::new()
            .name("kagebunshin-read".into())
            .spawn(move || {
                if out.send((attempt, run(&mut *client, job))).is_ok() {
                    wake();
                }
            });
        if let Err(e) = started {
            // The job went with the thread that did not start: its answer
            // is that the daemon was not asked.
            let problem = Problem::new(format!("cannot start a thread to ask the daemon: {e}"));
            let _ = self.outbox.send((attempt, failed(problem)));
            (self.waker)();
        }
    }

    /// Every answer that has landed, oldest first.
    pub fn answers(&self) -> Vec<(Attempt, Answer)> {
        self.answers.try_iter().collect()
    }
}

/// What the [`Approver`] learns.
#[derive(Debug, PartialEq, Eq)]
pub enum Approval {
    /// The requests waiting for approval now.
    Waiting(Vec<ApprovalPrompt>),
    /// An answer was sent: the requests still waiting, or why it failed
    /// (a wrong passphrase leaves the request waiting).
    Answered(Result<Vec<ApprovalPrompt>, Problem>),
}

/// How long the watcher waits before asking again after an error.
const RETRY: std::time::Duration = std::time::Duration::from_secs(2);

/// Asks the daemon for the requests waiting for approval once they differ
/// from `known`; `None` while it cannot be reached.
pub fn watch(client: &mut dyn DaemonClient, known: Vec<u64>) -> Option<Vec<ApprovalPrompt>> {
    match client.request(Request::WaitApprovals { known }) {
        Ok(Response::Approvals { pending }) => Some(pending),
        _ => None,
    }
}

/// Answers a request waiting for approval: approves it, or denies it.
pub fn approve(
    client: &mut dyn DaemonClient,
    ApprovalAnswer {
        id,
        passphrase,
        values,
        standing,
    }: ApprovalAnswer,
) -> Result<Vec<ApprovalPrompt>, Problem> {
    let req = match (standing, passphrase) {
        (true, Some(passphrase)) => Request::ApproveStanding { id, passphrase },
        (_, passphrase) => Request::Approve {
            id,
            passphrase,
            values,
        },
    };
    match client.request(req) {
        Ok(Response::Approvals { pending }) => Ok(pending),
        Ok(_) => Err(unexpected()),
        Err(e) => Err(e.into()),
    }
}

/// Two threads, each with its own client: one waits on the daemon for the
/// requests that need approval, which also tells the daemon the app is
/// open; the other sends the answers a person gives. Dropping it ends both
/// once the request in hand is done.
pub struct Approver {
    answers: mpsc::Sender<ApprovalAnswer>,
    updates: mpsc::Receiver<Approval>,
}

/// A request's id, and the passphrase that approves it or none to deny
/// it. `values` are what a person typed for the keys of a request that
/// asks for them; none for any other request, or to deny. `standing`
/// leaves the approval standing, where the request's prompt offers that.
#[derive(Debug)]
pub struct ApprovalAnswer {
    pub id: u64,
    pub passphrase: Option<WireSecret>,
    pub values: Vec<(KeyName, WireSecret)>,
    pub standing: bool,
}

impl ApprovalAnswer {
    pub fn deny(id: u64) -> Self {
        Self {
            id,
            passphrase: None,
            values: Vec::new(),
            standing: false,
        }
    }
}

impl Approver {
    /// Fails when the OS cannot start another thread.
    pub fn spawn(
        mut watcher: Box<dyn DaemonClient>,
        mut answerer: Box<dyn DaemonClient>,
        waker: Waker,
    ) -> Result<Self, Problem> {
        let (answers, inbox) = mpsc::channel::<ApprovalAnswer>();
        let (outbox, updates) = mpsc::channel();
        let start = |name: &str, f: Box<dyn FnOnce() + Send>| {
            std::thread::Builder::new()
                .name(name.into())
                .spawn(f)
                .map(drop)
                .map_err(|e| Problem::new(format!("cannot start the approvals thread: {e}")))
        };
        let (out, wake) = (outbox.clone(), waker.clone());
        start(
            "kagebunshin-approvals",
            Box::new(move || {
                let mut known = Vec::new();
                loop {
                    let pending = watch(&mut *watcher, known.clone()).unwrap_or_else(|| {
                        std::thread::sleep(RETRY);
                        Vec::new()
                    });
                    let ids: Vec<u64> = pending.iter().map(|p| p.id).collect();
                    if ids == known {
                        continue;
                    }
                    known = ids;
                    if out.send(Approval::Waiting(pending)).is_err() {
                        return;
                    }
                    wake();
                }
            }),
        )?;
        start(
            "kagebunshin-approve",
            Box::new(move || {
                for answer in inbox {
                    let answer = approve(&mut *answerer, answer);
                    if outbox.send(Approval::Answered(answer)).is_err() {
                        return;
                    }
                    waker();
                }
            }),
        )?;
        Ok(Self { answers, updates })
    }

    pub fn answer(&self, answer: ApprovalAnswer) {
        // The thread only stops when this side is dropped.
        let _ = self.answers.send(answer);
    }

    /// Every update that has landed, oldest first.
    pub fn updates(&self) -> Vec<Approval> {
        self.updates.try_iter().collect()
    }

    /// One with no threads: what it is asked to send, and a way to feed it
    /// updates.
    #[cfg(test)]
    pub fn fake() -> (Self, mpsc::Receiver<ApprovalAnswer>, mpsc::Sender<Approval>) {
        let (answers, sent) = mpsc::channel();
        let (feed, updates) = mpsc::channel();
        (Self { answers, updates }, sent, feed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kagebunshin::ipc::protocol::{
        DiffReport, EnvStatus, StatusReport, SyncReport, Synced, WireError,
    };
    use kagebunshin::store::Change;
    use kagebunshin::types::{Origin, Provider};

    fn facts(example: Option<Vec<&str>>) -> Facts {
        Facts {
            cwd: "/".into(),
            remotes: vec!["github.com/acme/widget".parse().unwrap()],
            subdir: None,
            root: None,
            project: None,
            env: Some("dev".parse().unwrap()),
            example_keys: example.map(|k| k.into_iter().map(|k| k.parse().unwrap()).collect()),
            example_values: Vec::new(),
            env_file: None,
        }
    }

    fn resolved() -> Response {
        Response::Status(StatusReport {
            locked: false,
            env: Some(EnvStatus {
                project: "widget".parse().unwrap(),
                env: "dev".parse().unwrap(),
                example: true,
                keys: vec![KeyStatus {
                    key: "API_KEY".parse().unwrap(),
                    origin: Origin::new(Provider::AwsSm, "acme/dev/api"),
                    overridden: Vec::new(),
                    in_example: true,
                    sensitive: false,
                }],
                vars: Vec::new(),
                missing: Vec::new(),
                skipped: Vec::new(),
                fixes: Vec::new(),
                warnings: Vec::new(),
                acknowledged: false,
                proof: None,
            }),
            expiring: Vec::new(),
            remote: None,
            waiting: Vec::new(),
            acknowledged: Vec::new(),
            shared: Vec::new(),
            app: false,
            phone: None,
            standing: Vec::new(),
        })
    }

    #[test]
    fn an_env_asks_status_then_diff_only_with_an_example() {
        let fake = FakeClient::default();
        fake.reply(Ok(resolved()))
            .reply(Ok(Response::Diff(DiffReport {
                project: "widget".parse().unwrap(),
                env: "dev".parse().unwrap(),
                example: true,
                missing: vec!["DB_URL".parse().unwrap()],
                extra: Vec::new(),
                extra_by_origin: Vec::new(),
                conflicts: Vec::new(),
                skipped: Vec::new(),
                fixes: Vec::new(),
                warnings: Vec::new(),
            })));
        let f = facts(Some(vec!["API_KEY", "DB_URL"]));
        let answer = run(&mut fake.clone(), Job::Env { facts: f.clone() });
        let Answer::Env(Ok(EnvReport::Resolved { keys, missing, .. })) = answer else {
            panic!("{answer:?}");
        };
        assert_eq!(keys[0].origin.to_string(), "aws_sm:acme/dev/api");
        assert_eq!(missing, Some(vec!["DB_URL".parse().unwrap()]));
        assert_eq!(
            *fake.asked.lock().unwrap(),
            [
                Request::Status {
                    facts: Some(f.clone())
                },
                Request::Diff { facts: f }
            ]
        );

        let fake = FakeClient::default();
        fake.reply(Ok(resolved()));
        let answer = run(&mut fake.clone(), Job::Env { facts: facts(None) });
        assert!(matches!(
            answer,
            Answer::Env(Ok(EnvReport::Resolved { missing: None, .. }))
        ));
        assert_eq!(fake.asked.lock().unwrap().len(), 1);
    }

    #[test]
    fn errors_keep_their_hints_and_say_whether_the_daemon_is_reachable() {
        let mut fake = FakeClient::default();
        let Answer::Probe(Err(p)) = run(&mut fake, Job::Probe) else {
            panic!()
        };
        assert!(p.unreachable);
        assert!(p.hint.unwrap().contains("kagebunshin daemon"));

        fake.reply(Err(ClientError::Daemon(
            WireError::new(ErrorCode::SourceFailed, "AWS SSO session expired")
                .with_hint("run `aws sso login`"),
        )));
        let Answer::Env(Err(p)) = run(&mut fake, Job::Env { facts: facts(None) }) else {
            panic!()
        };
        assert_eq!(
            (p.message.as_str(), p.hint.as_deref(), p.unreachable),
            (
                "AWS SSO session expired",
                Some("run `aws sso login`"),
                false
            )
        );
        fake.reply(Err(ClientError::Daemon(WireError::new(
            ErrorCode::BuildMismatch,
            "daemon is 0.0.9",
        ))));
        let Answer::Probe(Err(p)) = run(&mut fake, Job::Probe) else {
            panic!()
        };
        assert!(p.unreachable);
    }

    fn secret(s: &str) -> WireSecret {
        WireSecret::new(s.into())
    }

    #[test]
    fn an_unlock_asks_for_the_passphrase_only_when_none_was_sent() {
        let needs = || {
            Err(ClientError::Daemon(WireError::new(
                ErrorCode::PassphraseRequired,
                "the store is locked",
            )))
        };
        let fake = FakeClient::default();
        fake.reply(needs())
            .reply(needs())
            .reply(Ok(Response::LockState {
                locked: false,
                warnings: vec!["prod looks like production".into()],
            }));
        let mut c = fake.clone();
        let first = run(&mut c, Job::Unlock { passphrase: None });
        assert_eq!(first, Answer::Action(Ok(Done::PassphraseRequired)));
        // Sent and still refused: an error, not another prompt.
        let again = run(
            &mut c,
            Job::Unlock {
                passphrase: Some(secret("wrong")),
            },
        );
        assert!(matches!(
            again,
            Answer::Action(Err(Problem {
                unreachable: false,
                ..
            }))
        ));
        let done = run(
            &mut c,
            Job::Unlock {
                passphrase: Some(secret("right")),
            },
        );
        assert_eq!(
            done,
            Answer::Action(Ok(Done::LockState {
                locked: false,
                warnings: vec!["prod looks like production".into()],
            }))
        );
        assert_eq!(
            *fake.asked.lock().unwrap(),
            [
                Request::Unlock { passphrase: None },
                Request::Unlock {
                    passphrase: Some(secret("wrong"))
                },
                Request::Unlock {
                    passphrase: Some(secret("right"))
                },
            ]
        );
    }

    #[test]
    fn lock_sync_and_store_marks_send_one_request_each() {
        let synced = |keys, error| Synced {
            project: "widget".parse().unwrap(),
            env: "dev".parse().unwrap(),
            keys,
            warnings: vec!["skipped an optional source".into()],
            error,
        };
        let fake = FakeClient::default();
        fake.reply(Ok(Response::LockState {
            locked: true,
            warnings: Vec::new(),
        }))
        .reply(Ok(Response::Sync(SyncReport {
            refreshed: vec![synced(Some(3), None)],
        })))
        .reply(Ok(Response::Sync(SyncReport {
            refreshed: vec![synced(
                None,
                Some(WireError::new(
                    ErrorCode::SourceFailed,
                    "AWS SSO session expired",
                )),
            )],
        })))
        .reply(Ok(Response::Store {
            change: Change::Marked,
            locked: false,
        }));
        let mut c = fake.clone();
        let sync = || Job::Sync {
            project: "widget".parse().unwrap(),
            env: "dev".parse().unwrap(),
        };
        assert_eq!(
            run(&mut c, Job::Lock),
            Answer::Action(Ok(Done::LockState {
                locked: true,
                warnings: Vec::new()
            }))
        );
        assert_eq!(
            run(&mut c, sync()),
            Answer::Action(Ok(Done::Synced {
                keys: 3,
                warnings: vec!["skipped an optional source".into()]
            }))
        );
        let Answer::Action(Err(p)) = run(&mut c, sync()) else {
            panic!()
        };
        assert_eq!(p.message, "AWS SSO session expired");
        let mark = Job::Mark {
            mark: Mark::Key {
                section: "widget.dev".parse().unwrap(),
                key: "API_KEY".parse().unwrap(),
            },
            sensitive: true,
            passphrase: secret("pw"),
        };
        assert_eq!(
            run(&mut c, mark),
            Answer::Action(Ok(Done::Marked {
                what: "API_KEY".into(),
                sensitive: true,
            }))
        );
        let asked = fake.asked.lock().unwrap();
        assert_eq!(asked[0], Request::Lock);
        assert_eq!(
            asked[1],
            Request::Sync {
                project: Some("widget".parse().unwrap()),
                env: Some("dev".parse().unwrap())
            }
        );
        assert_eq!(
            asked[3],
            Request::StoreMark {
                section: "widget.dev".parse().unwrap(),
                key: "API_KEY".parse().unwrap(),
                sensitive: true,
                passphrase: secret("pw"),
            }
        );
    }

    /// The app's view of what is sensitive: both send the passphrase, and only
    /// reveal comes back with a value.
    #[test]
    fn inspect_and_reveal_send_the_passphrase() {
        let fake = FakeClient::default();
        fake.reply(Ok(resolved()))
            .reply(Ok(Response::Value {
                value: secret("s3cret"),
            }))
            .reply(Err(ClientError::Daemon(WireError::new(
                ErrorCode::WrongPassphrase,
                "wrong passphrase",
            ))));
        let mut c = fake.clone();
        let inspect = Job::Inspect {
            facts: facts(Some(vec!["API_KEY"])),
            passphrase: secret("pw"),
        };
        assert!(matches!(
            run(&mut c, inspect),
            Answer::Env(Ok(EnvReport::Resolved { missing: None, .. }))
        ));
        let reveal = || Job::Reveal {
            facts: facts(None),
            key: "API_KEY".parse().unwrap(),
            passphrase: secret("pw"),
        };
        let revealed = run(&mut c, reveal());
        assert_eq!(revealed, Answer::Revealed(Ok(secret("s3cret"))));
        assert!(!format!("{revealed:?}").contains("s3cret"));
        assert!(matches!(run(&mut c, reveal()), Answer::Revealed(Err(_))));
        let asked = fake.asked.lock().unwrap();
        assert!(
            matches!(&asked[0], Request::Inspect { passphrase, .. } if passphrase.expose() == "pw")
        );
        assert!(matches!(&asked[1], Request::Reveal { key, .. } if key.as_str() == "API_KEY"));
        assert_eq!(asked.len(), 3, "no diff for a sensitive env");
    }

    /// Providers are asked about without facts; connecting Proton and
    /// acknowledging send one request each, the token and passphrase with
    /// them, and neither shows in a job's `Debug`.
    #[test]
    fn providers_connect_and_acknowledge() {
        use kagebunshin::source::Health;
        let canary = kagebunshin::test_support::Canary::new();
        let fake = FakeClient::default();
        let proton = ProviderStatus {
            provider: Provider::Proton,
            detail: "store.age".into(),
            health: Health::Ok,
            expires: Some(1_800_000_000),
        };
        fake.reply(Ok(Response::Providers {
            providers: vec![proton.clone()],
        }))
        .reply(Ok(Response::ProtonConnected {
            change: Change::Replaced,
            locked: false,
            vaults: 2,
        }))
        .reply(Ok(Response::Store {
            change: Change::Marked,
            locked: false,
        }))
        .reply(Ok(Response::Store {
            change: Change::Marked,
            locked: false,
        }));
        let mut c = fake.clone();
        assert_eq!(
            run(&mut c, Job::Providers),
            Answer::Providers(Ok(vec![proton]))
        );
        let connect = Job::ConnectProton {
            token: secret(canary.value()),
            expires: Some(1_800_000_000),
            passphrase: secret("pw"),
        };
        assert!(!format!("{connect:?}").contains(canary.value()));
        assert_eq!(
            run(&mut c, connect),
            Answer::Action(Ok(Done::ProtonConnected {
                vaults: 2,
                locked: false
            }))
        );
        let ack = Job::Acknowledge {
            project: "widget".parse().unwrap(),
            env: "prod".parse().unwrap(),
            acknowledged: true,
            unmark: vec![Origin::new(Provider::AwsSm, "acme/mail")],
            passphrase: secret("pw"),
        };
        assert_eq!(
            run(&mut c, ack),
            Answer::Action(Ok(Done::Acknowledged {
                acknowledged: true,
                unmarked: 1,
            }))
        );
        let all = Job::AcknowledgeAll {
            envs: vec!["widget.prod".parse().unwrap(), "gadget.rc".parse().unwrap()],
            passphrase: secret("pw"),
        };
        assert_eq!(
            run(&mut c, all),
            Answer::Action(Ok(Done::Acknowledged {
                acknowledged: true,
                unmarked: 0,
            }))
        );
        let asked = fake.asked.lock().unwrap();
        assert_eq!(
            asked[0],
            Request::Providers {
                facts: None,
                every: true,
            }
        );
        assert!(matches!(
            &asked[1],
            Request::ProtonConnect { token, expires: Some(1_800_000_000), passphrase }
                if token.expose() == canary.value() && passphrase.expose() == "pw"
        ));
        assert!(matches!(
            &asked[2],
            Request::AcknowledgeEnv { env, acknowledged: true, unmark, .. }
                if env.as_str() == "prod" && unmark.len() == 1
        ));
        assert!(matches!(
            &asked[3],
            Request::AcknowledgeEnvs { envs, passphrase }
                if envs.len() == 2 && passphrase.expose() == "pw"
        ));
    }

    /// Watching sends the ids already shown; approving sends the
    /// passphrase, denying none, and a wrong passphrase comes back as an
    /// error.
    #[test]
    fn approvals_are_watched_and_answered() {
        let prompt = ApprovalPrompt {
            id: 7,
            project: "widget".parse().unwrap(),
            env: "prod".parse().unwrap(),
            keys: vec!["API_KEY".parse().unwrap()],
            reason: kagebunshin::ipc::protocol::ApprovalReason::default(),
            command: "npm start".into(),
            argv: vec!["npm".into(), "start".into()],
            pid: 41,
            cwd: "/src/widget".into(),
            parents: Vec::new(),
            left: Some(300),
            remote: None,
            secrets: Vec::new(),
            every_key: false,
            standing: None,
        };
        let fake = FakeClient::default();
        fake.reply(Ok(Response::Approvals {
            pending: vec![prompt.clone()],
        }))
        .reply(Err(ClientError::Daemon(WireError::new(
            ErrorCode::WrongPassphrase,
            "wrong passphrase",
        ))))
        .reply(Ok(Response::Approvals {
            pending: Vec::new(),
        }));
        let mut c = fake.clone();
        assert_eq!(watch(&mut c, vec![3]), Some(vec![prompt]));
        let wrong = approve(
            &mut c,
            ApprovalAnswer {
                id: 7,
                passphrase: Some(secret("nope")),
                values: vec![("TOKEN".parse().unwrap(), secret("typed"))],
                standing: false,
            },
        )
        .unwrap_err();
        assert_eq!(wrong.message, "wrong passphrase");
        assert_eq!(approve(&mut c, ApprovalAnswer::deny(7)), Ok(Vec::new()));
        // Left standing, it is another request; a denial never is.
        fake.reply(Ok(Response::Approvals {
            pending: Vec::new(),
        }));
        let standing = ApprovalAnswer {
            id: 7,
            passphrase: Some(secret("pw")),
            values: Vec::new(),
            standing: true,
        };
        assert_eq!(approve(&mut c, standing), Ok(Vec::new()));
        fake.reply(Ok(Response::StandingEnded { ended: 1 }));
        let end = Job::EndStanding {
            project: "widget".parse().unwrap(),
            env: "prod".parse().unwrap(),
        };
        assert_eq!(run(&mut c, end), Answer::Action(Ok(Done::StandingEnded)));
        assert_eq!(watch(&mut c, Vec::new()), None, "not running");
        let asked = fake.asked.lock().unwrap();
        assert_eq!(asked[0], Request::WaitApprovals { known: vec![3] });
        assert!(matches!(
            &asked[1],
            Request::Approve { id: 7, passphrase: Some(p), values }
                if p.expose() == "nope"
                    && matches!(values.as_slice(), [(k, v)] if k.as_str() == "TOKEN" && v.expose() == "typed")
        ));
        assert_eq!(
            asked[2],
            Request::Approve {
                id: 7,
                passphrase: None,
                values: Vec::new(),
            }
        );
        assert!(matches!(
            &asked[3],
            Request::ApproveStanding { id: 7, passphrase } if passphrase.expose() == "pw"
        ));
        assert_eq!(
            asked[4],
            Request::EndStanding {
                project: "widget".parse().unwrap(),
                env: "prod".parse().unwrap(),
            }
        );
    }

    /// A grant is to a node: the daemon is told its id, not its name,
    /// which another machine may take.
    #[test]
    fn a_grant_is_changed_by_its_node_id() {
        let grant = || Grant {
            node: "nBOT".into(),
            machine: "buildbot".into(),
            project: "widget".parse().unwrap(),
        };
        let fake = FakeClient::default();
        fake.reply(Ok(Response::RemoteGranted {
            change: Change::Replaced,
            locked: false,
            machine: "buildbot".into(),
            token: secret("kbr_new"),
        }))
        .reply(Ok(Response::Store {
            change: Change::Removed,
            locked: false,
        }))
        .reply(Err(ClientError::Daemon(WireError::new(
            ErrorCode::WrongPassphrase,
            "wrong passphrase",
        ))))
        // Not what a rotation is answered with.
        .reply(Ok(Response::Store {
            change: Change::Replaced,
            locked: false,
        }));
        let mut c = fake.clone();
        let rotate = || Job::RotateGrant {
            grant: grant(),
            passphrase: secret("pw"),
        };
        let answer = run(&mut c, rotate());
        assert_eq!(
            answer,
            Answer::Token(Ok(NewToken {
                grant: grant(),
                token: secret("kbr_new"),
            }))
        );
        assert!(!format!("{answer:?}").contains("kbr_new"));
        let revoke = Job::RevokeGrant {
            grant: grant(),
            passphrase: secret("pw"),
        };
        assert_eq!(
            run(&mut c, revoke),
            Answer::Action(Ok(Done::GrantRevoked(grant())))
        );
        let Answer::Token(Err(p)) = run(&mut c, rotate()) else {
            panic!()
        };
        assert_eq!(
            (p.message.as_str(), p.unreachable),
            ("wrong passphrase", false)
        );
        assert!(matches!(run(&mut c, rotate()), Answer::Token(Err(_))));
        let asked = fake.asked.lock().unwrap();
        assert_eq!(
            asked[0],
            Request::RemoteRotate {
                machine: "nBOT".into(),
                project: "widget".parse().unwrap(),
                passphrase: secret("pw"),
            }
        );
        assert_eq!(
            asked[1],
            Request::RemoteRevoke {
                machine: "nBOT".into(),
                project: Some("widget".parse().unwrap()),
                passphrase: secret("pw"),
            }
        );
    }

    /// A phone is paired by its node id; what comes back is where it
    /// opens the page, and the passphrase goes with the request only.
    #[test]
    fn a_phone_is_listed_paired_and_removed() {
        let phone = || PhoneChoice {
            name: "phone".into(),
            node: "nPHONE".into(),
            os: "iOS".into(),
        };
        let fake = FakeClient::default();
        fake.reply(Ok(Response::Phones {
            phones: vec![phone()],
        }))
        .reply(Ok(Response::PhonePairing {
            name: "phone".into(),
            url: "https://self.example.ts.net:47318".into(),
            seconds: 600,
        }))
        .reply(Ok(Response::PhonePairStopped))
        .reply(Ok(Response::Store {
            change: Change::Removed,
            locked: false,
        }))
        .reply(Err(ClientError::Daemon(WireError::new(
            ErrorCode::WrongPassphrase,
            "wrong passphrase",
        ))));
        let mut c = fake.clone();
        assert_eq!(run(&mut c, Job::Phones), Answer::Phones(Ok(vec![phone()])));
        let pair = || Job::PairPhone {
            phone: phone(),
            passphrase: secret("pw"),
        };
        assert_eq!(
            run(&mut c, pair()),
            Answer::Pairing(Ok(Pairing {
                phone: phone(),
                url: "https://self.example.ts.net:47318".into(),
            }))
        );
        assert_eq!(
            run(&mut c, Job::StopPairing),
            Answer::Action(Ok(Done::PairingStopped))
        );
        let unpair = Job::UnpairPhone {
            name: "phone".into(),
            passphrase: secret("pw"),
        };
        assert_eq!(
            run(&mut c, unpair),
            Answer::Action(Ok(Done::PhoneUnpaired("phone".into())))
        );
        let Answer::Pairing(Err(p)) = run(&mut c, pair()) else {
            panic!()
        };
        assert_eq!(
            (p.message.as_str(), p.unreachable),
            ("wrong passphrase", false)
        );
        assert_eq!(
            *fake.asked.lock().unwrap(),
            [
                Request::Phones,
                Request::PhonePair {
                    machine: "nPHONE".into(),
                    passphrase: secret("pw"),
                },
                Request::PhonePairStop,
                Request::PhoneUnpair {
                    passphrase: secret("pw"),
                },
                Request::PhonePair {
                    machine: "nPHONE".into(),
                    passphrase: secret("pw"),
                },
            ]
        );
    }

    #[test]
    fn the_worker_answers_in_order_and_wakes_the_window() {
        let fake = FakeClient::default();
        fake.reply(Ok(Response::Status(StatusReport {
            locked: true,
            env: None,
            expiring: Vec::new(),
            remote: None,
            waiting: Vec::new(),
            acknowledged: Vec::new(),
            shared: Vec::new(),
            app: false,
            phone: None,
            standing: Vec::new(),
        })));
        let (woke, wakes) = mpsc::channel();
        let waker: Waker = Arc::new(move || {
            let _ = woke.send(());
        });
        let worker = Worker::spawn(Box::new(fake), waker).unwrap();
        worker.send(Attempt(1), Job::Probe);
        worker.send(Attempt(2), Job::Probe);
        let timeout = std::time::Duration::from_secs(5);
        wakes.recv_timeout(timeout).unwrap();
        wakes.recv_timeout(timeout).unwrap();
        let answers = worker.answers();
        assert_eq!(answers.len(), 2);
        assert_eq!(
            answers[0],
            (Attempt(1), Answer::Probe(Ok(Probed::locked(true))))
        );
        assert!(matches!(answers[1], (Attempt(2), Answer::Probe(Err(_)))));
    }

    /// A daemon that holds back what it says of environment `slow` until
    /// told to go on, answers the rest at once, and lends clients to ask
    /// with meanwhile, as the real one does.
    #[derive(Clone, Default)]
    struct Held {
        go: Arc<(Mutex<bool>, std::sync::Condvar)>,
    }

    impl Held {
        fn release(&self) {
            *self.go.0.lock().unwrap() = true;
            self.go.1.notify_all();
        }
    }

    impl DaemonClient for Held {
        fn request(&mut self, req: Request) -> Result<Response, ClientError> {
            let slow = matches!(
                &req,
                Request::Status { facts: Some(f) } if f.env.as_ref().is_some_and(|e| e.as_str() == "slow")
            );
            if slow {
                let (held, released) = &*self.go;
                let _go = released
                    .wait_while(held.lock().unwrap(), |go| !*go)
                    .unwrap();
            }
            Ok(match req {
                Request::Providers { .. } => Response::Providers {
                    providers: Vec::new(),
                },
                _ => Response::Status(StatusReport {
                    locked: true,
                    env: None,
                    expiring: Vec::new(),
                    remote: None,
                    waiting: Vec::new(),
                    acknowledged: Vec::new(),
                    shared: Vec::new(),
                    app: false,
                    phone: None,
                    standing: Vec::new(),
                }),
            })
        }

        fn beside(&self) -> Option<Box<dyn DaemonClient>> {
            Some(Box::new(self.clone()))
        }
    }

    /// An environment that is slow to read holds back nothing else: the
    /// other environments, the providers and the probe are answered while
    /// it is still being read, and it is answered when it has been.
    #[test]
    fn a_slow_read_holds_back_no_other_job() {
        let daemon = Held::default();
        let (woke, wakes) = mpsc::channel();
        let waker: Waker = Arc::new(move || {
            let _ = woke.send(());
        });
        let worker = Worker::spawn(Box::new(daemon.clone()), waker).unwrap();
        let env = |name: &str| Job::Env {
            facts: Facts {
                env: Some(name.parse().unwrap()),
                ..facts(None)
            },
        };
        worker.send(Attempt(1), env("slow"));
        worker.send(Attempt(2), env("dev"));
        worker.send(Attempt(3), Job::Providers);
        worker.send(Attempt(4), Job::Probe);
        let timeout = std::time::Duration::from_secs(5);
        for _ in 0..3 {
            wakes.recv_timeout(timeout).unwrap();
        }
        let mut answers = worker.answers();
        answers.sort_by_key(|(attempt, _)| attempt.0);
        assert_eq!(
            answers,
            [
                (Attempt(2), Answer::Env(Ok(EnvReport::Locked))),
                (Attempt(3), Answer::Providers(Ok(Vec::new()))),
                (Attempt(4), Answer::Probe(Ok(Probed::locked(true)))),
            ]
        );

        daemon.release();
        wakes.recv_timeout(timeout).unwrap();
        assert_eq!(
            worker.answers(),
            [(Attempt(1), Answer::Env(Ok(EnvReport::Locked)))]
        );
    }
}
