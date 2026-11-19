//! What the window knows about the daemon, as one state machine.
//!
//! The connection is probed every few seconds while the daemon answers and
//! retried sooner while it does not. A probe is a status request without
//! facts: it reads no source, and the daemon does not log it. The project on
//! show has a column per environment. Each is asked about when the project is
//! picked, except one whose name looks like production, which waits to be
//! clicked; all that were asked are asked again on Refresh and when the
//! daemon's lock state changes, as are the providers once the Providers tab
//! has asked about them. [`step`] decides what happens and returns the
//! jobs and timers for the caller to carry out; every answer carries the
//! attempt that asked, and one the state no longer holds changes nothing.
//!
//! Changes a person asks for go through [`Pending`]: removing a sensitive
//! mark waits for them to confirm it in the window, marking an environment
//! that shares secrets with others shows which first, and anything the store's
//! passphrase unlocks waits for them to type it: every mark, a look at an
//! environment marked sensitive, revealing a value, saving a Proton Pass
//! token, acknowledging an environment as not production, giving a
//! remote grant a new token or ending it, and pairing a phone or removing
//! it. Project-file edits
//! come back as [`Effect::Edit`] for the window to make on its own thread;
//! everything else goes to the daemon, one change at a time. A revealed value
//! is held only until the window hides it, the project changes or the daemon
//! locks, and a grant's new token until the window puts it away, another
//! change is asked for or the daemon locks.
//!
//! A phone being paired is probed for every second, so the window says so
//! as soon as it has made its key. The pairing is ended when the window
//! stops showing the way in: the daemon keeps the passphrase for as long
//! as it lasts.

use kagebunshin::cli::edit::NewSource;
use kagebunshin::ipc::protocol::{
    Facts, PhoneChoice, PhoneStatus, RemoteStatus, SharedSecret, TokenExpiry, WaitingEnv,
    WireSecret,
};
use kagebunshin::source::ProviderStatus;
use kagebunshin::store::Section;
use kagebunshin::types::{EnvName, KeyName, Origin, ProjectName, Provider};
use rune::machine::{Attempt, Effects, Seq};

use crate::daemon::{Answer, Done, EnvReport, Grant, Job, Mark, NewToken, Pairing, Problem};

/// Seconds between probes while the daemon answers.
pub const PROBE_EVERY: f64 = 5.0;
/// Seconds between them while a phone is being paired.
pub const PAIRING_PROBE_EVERY: f64 = 1.0;
/// Seconds before the next try while it does not.
pub const RETRY_AFTER: f64 = 2.0;
/// Seconds a notice that only says a change was made stays up. One with
/// warnings, or a failure, stays until it is dismissed or the next change.
pub const NOTICE_FOR: f64 = 6.0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Conn {
    /// Nothing has answered yet.
    Unknown,
    Up {
        locked: bool,
    },
    Down(Problem),
}

impl Conn {
    /// Whether it is locked, if it answers.
    fn locked(&self) -> Option<bool> {
        match self {
            Conn::Up { locked } => Some(*locked),
            Conn::Unknown | Conn::Down(_) => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Probe {
    Waiting { due: f64 },
    Asking(Attempt),
}

/// One environment of the project on show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    pub project: ProjectName,
    pub env: EnvName,
    pub facts: Facts,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Detail {
    /// Not asked about yet: it waits to be clicked.
    Idle,
    Loading(Attempt),
    Loaded(EnvReport),
    Failed(Problem),
}

/// An environment's column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Column {
    pub sel: Selection,
    pub detail: Detail,
    /// Asked about with the passphrase, as it is marked sensitive.
    pub inspected: bool,
}

impl Column {
    /// Whether it is marked sensitive, once the daemon has said.
    pub fn marked(&self) -> Option<bool> {
        match &self.detail {
            Detail::Loaded(EnvReport::Sensitive) => Some(true),
            Detail::Loaded(EnvReport::Resolved { .. }) => Some(self.inspected),
            _ => None,
        }
    }
}

/// The project on show, a column per environment, in name order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shown {
    pub project: ProjectName,
    pub columns: Vec<Column>,
}

impl Shown {
    pub fn column(&self, env: &EnvName) -> Option<&Column> {
        self.columns.iter().find(|c| &c.sel.env == env)
    }

    fn column_mut(&mut self, env: &EnvName) -> Option<&mut Column> {
        self.columns.iter_mut().find(|c| &c.sel.env == env)
    }
}

/// A value shown in the window, until it is hidden.
#[derive(Debug, PartialEq, Eq)]
pub struct Revealed {
    pub env: EnvName,
    pub key: KeyName,
    pub value: WireSecret,
}

/// A change to a project file, which the window makes itself. Every one is
/// to a source now that marks live in the store; the names match the
/// `project` commands.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub enum Edit {
    RemoveSource {
        project: ProjectName,
        env: EnvName,
        index: usize,
    },
    MoveSource {
        project: ProjectName,
        env: EnvName,
        from: usize,
        to: usize,
    },
    AddSource {
        project: ProjectName,
        env: EnvName,
        source: NewSource,
    },
}

impl Edit {
    /// What it did, for the notice.
    fn done(&self) -> String {
        match self {
            Edit::RemoveSource { index, .. } => format!("Removed source {}.", index + 1),
            Edit::MoveSource { from, to, .. } => {
                format!("Moved source {} to {}.", from + 1, to + 1)
            }
            Edit::AddSource { .. } => "Added a source. Resync to fetch it.".into(),
        }
    }
}

/// A change a person asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    Edit(Edit),
    /// Marks something sensitive, or removes its mark, through the daemon,
    /// with the passphrase.
    Mark {
        mark: Mark,
        sensitive: bool,
    },
    /// Saves the Proton Pass token typed in the window, with the passphrase.
    ConnectProton {
        expires: Option<u64>,
    },
    /// Acknowledges an environment as not production, or takes it back.
    Acknowledge {
        project: ProjectName,
        env: EnvName,
        acknowledged: bool,
    },
    /// Acknowledges each of these environments as not production, with
    /// one passphrase.
    AcknowledgeAll(Vec<Section>),
    /// Gives a remote grant a new token, with the passphrase; `replacing`
    /// when it has one now, which the new one ends.
    RotateGrant {
        grant: Grant,
        replacing: bool,
    },
    /// Ends a remote grant, with the passphrase.
    RevokeGrant(Grant),
    /// Lets a phone make the passkey it approves with, with the
    /// passphrase. One paired before it approves until then.
    PairPhone(PhoneChoice),
    /// Removes the paired phone, of this name, with the passphrase.
    UnpairPhone(String),
}

impl Change {
    /// If it takes something away, a sensitive mark or a remote machine's
    /// way in, what to ask the person first.
    fn question(&self) -> Option<String> {
        let tail = "Agents will be able to read";
        let mark = match self {
            Change::Mark {
                mark,
                sensitive: false,
            } => mark,
            Change::RotateGrant {
                grant,
                replacing: true,
            } => {
                return Some(format!(
                    "Give machine {}'s grant for {} a new token? The one it has stops working at once.",
                    grant.machine, grant.project
                ));
            }
            Change::RevokeGrant(grant) => {
                return Some(format!(
                    "Revoke machine {}'s grant for {}? It will get nothing of that project until it is granted again.",
                    grant.machine, grant.project
                ));
            }
            Change::UnpairPhone(name) => {
                return Some(format!(
                    "Remove {name}? Requests will be approved at this computer only, until a phone is paired again."
                ));
            }
            _ => return None,
        };
        Some(match mark {
            Mark::Env { project, env, .. } => format!(
                "Remove the sensitive mark from environment {env} of {project}? {tail} all of it."
            ),
            Mark::Secret(secret) => format!(
                "Remove the sensitive mark from secret {secret}? {tail} its keys, in every environment that reads it."
            ),
            Mark::Key { section, key } => format!(
                "Remove the sensitive mark from key {key} of [{section}]? {tail} its value."
            ),
        })
    }
}

/// What needs the store's passphrase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Purpose {
    Unlock,
    Mark {
        mark: Mark,
        sensitive: bool,
    },
    /// Show the keys of an environment marked sensitive.
    Inspect(EnvName),
    /// Show one value.
    Reveal {
        env: EnvName,
        key: KeyName,
    },
    /// Save the Proton Pass token typed; it comes with the passphrase, in
    /// [`Event::ConnectProton`].
    ConnectProton {
        expires: Option<u64>,
    },
    /// With `unmark`, the secrets to unmark in the same write: see
    /// [`Unmarking`].
    Acknowledge {
        project: ProjectName,
        env: EnvName,
        acknowledged: bool,
        unmark: Vec<Origin>,
    },
    AcknowledgeAll(Vec<Section>),
    /// Unmark these secrets, ticked in [`Unmarks`].
    Unmark(Vec<Origin>),
    RotateGrant(Grant),
    RevokeGrant(Grant),
    PairPhone(PhoneChoice),
    UnpairPhone(String),
}

/// A change under way, or waiting on the person.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Pending {
    #[default]
    None,
    /// Waiting for them to agree to `change`.
    Confirm { change: Change, question: String },
    /// Waiting for them to agree to mark an environment sensitive, having
    /// seen which of its secrets other environments read.
    Sharing(Sharing),
    /// Waiting for them to agree to acknowledge an environment as not
    /// production, having seen which marked secrets it reads.
    Unmarking(Unmarking),
    /// Waiting for them to agree to unmark secrets, having seen the marked
    /// ones of the environment and who else reads each.
    Unmarks(Unmarks),
    /// Waiting for them to type the passphrase.
    Passphrase(Purpose),
    /// Sent to the daemon.
    Running(Attempt),
}

/// Marking an environment sensitive that reads secrets other environments
/// read too: what the person is shown before the passphrase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sharing {
    pub project: ProjectName,
    pub env: EnvName,
    /// Secrets that stay unmarked, because an open environment reads them
    /// too, unless ticked: see [`SharedSecret::stays_unmarked`].
    pub open: Vec<SharedSecret>,
    /// Those of `open` ticked to mark all the same.
    pub also: Vec<Origin>,
    /// Secrets marked with it although an open environment reads them,
    /// because their names look like production.
    pub production: Vec<SharedSecret>,
}

impl Sharing {
    /// What to show for marking `project`'s `env`, of the `shared` secrets
    /// the daemon knows; `None` if marking it touches no open environment.
    fn of(project: &ProjectName, env: &EnvName, shared: &[SharedSecret]) -> Option<Self> {
        let mine = || shared.iter().filter(|s| s.of(project, env));
        let open: Vec<_> = mine().filter(|s| s.stays_unmarked()).cloned().collect();
        let production: Vec<_> = mine()
            .filter(|s| s.production && !s.sensitive && !s.open.is_empty())
            .cloned()
            .collect();
        (!open.is_empty() || !production.is_empty()).then(|| Self {
            project: project.clone(),
            env: env.clone(),
            open,
            also: Vec::new(),
            production,
        })
    }
}

/// Acknowledging as not production an environment that reads secrets
/// marked sensitive: what the person is shown before the passphrase. The
/// acknowledgement leaves those marks, so the environment would go on
/// asking for approval for their keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unmarking {
    pub project: ProjectName,
    pub env: EnvName,
    /// The marked secrets it reads: see [`SharedSecret::stays_marked`].
    pub marked: Vec<SharedSecret>,
    /// Those of `marked` ticked to unmark with it; none to begin with.
    pub unmark: Vec<Origin>,
}

impl Unmarking {
    /// What to show for acknowledging `project`'s `env`, of the `shared`
    /// secrets the daemon knows; `None` if it reads no marked one.
    fn of(project: &ProjectName, env: &EnvName, shared: &[SharedSecret]) -> Option<Self> {
        let marked: Vec<_> = shared
            .iter()
            .filter(|s| s.of(project, env) && s.stays_marked())
            .cloned()
            .collect();
        (!marked.is_empty()).then(|| Self {
            project: project.clone(),
            env: env.clone(),
            marked,
            unmark: Vec::new(),
        })
    }
}

/// Unmarking a secret from an environment's keys: what the person is shown
/// before the passphrase. The other marked secrets of the environment are
/// listed too, so several are unmarked with one passphrase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unmarks {
    /// The marked secrets the environment's keys come from.
    pub marked: Vec<Marked>,
    /// Those of `marked` ticked to unmark: to begin with, the one asked for.
    pub unmark: Vec<Origin>,
}

/// A secret marked sensitive, as [`Unmarks`] lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Marked {
    pub secret: Origin,
    /// What the daemon said of it, if other environments read it too.
    pub shared: Option<SharedSecret>,
}

/// How the last change went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notice {
    Done {
        message: String,
        warnings: Vec<String>,
    },
    Failed(Problem),
}

/// What the daemon said of the providers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Providers {
    /// Asked about: asked again on Refresh and when the lock state changes.
    pub asked: bool,
    pub asking: Option<Attempt>,
    /// The attempt that saves a token for a provider, which checks it
    /// first: that provider is being checked for as long as it runs.
    pub saving: Option<(Attempt, Provider)>,
    /// The last answer, kept while it is asked again.
    pub last: Option<Result<Vec<ProviderStatus>, Problem>>,
}

/// The phones on the tailnet that could be paired, as the daemon said.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Phones {
    /// Asked about: asked again on Refresh and after every change.
    pub asked: bool,
    pub asking: Option<Attempt>,
    /// The last answer, kept while it is asked again.
    pub last: Option<Result<Vec<PhoneChoice>, Problem>>,
}

#[derive(Debug)]
pub struct Machine {
    seq: Seq,
    pub conn: Conn,
    pub probe: Probe,
    pub shown: Option<Shown>,
    pub pending: Pending,
    pub notice: Option<Notice>,
    /// Saved tokens near or past their expiry, as the last probe saw.
    pub expiring: Vec<TokenExpiry>,
    /// Environments of every project that wait for a human decision, as
    /// the last probe saw; empty while locked.
    pub waiting: Vec<WaitingEnv>,
    /// Environments acknowledged as not production, as the last probe saw.
    pub acknowledged: Vec<Section>,
    /// Secrets that more than one environment reads, as the last probe
    /// saw; empty while locked.
    pub shared: Vec<SharedSecret>,
    /// The remote endpoint, as the last probe saw; its grants are known
    /// only while unlocked.
    pub remote: Option<RemoteStatus>,
    /// The token a grant was just given, until it is put away.
    pub token: Option<NewToken>,
    /// The approval page and the phone paired with it, as the last probe
    /// saw; none when no phone is paired or being paired, or while locked.
    pub phone: Option<Box<PhoneStatus>>,
    pub phones: Phones,
    /// The pairing this window started, while it shows the way in.
    pub pairing: Option<Pairing>,
    /// The value asked for while it is on its way.
    revealing: Option<(EnvName, KeyName)>,
    pub revealed: Option<Revealed>,
    pub providers: Providers,
    /// When the notice on show goes by itself, once a frame has seen it.
    fading: Option<f64>,
}

impl Default for Machine {
    /// Probes on the first frame.
    fn default() -> Self {
        Self {
            seq: Seq::default(),
            conn: Conn::Unknown,
            probe: Probe::Waiting { due: 0.0 },
            shown: None,
            pending: Pending::None,
            notice: None,
            expiring: Vec::new(),
            waiting: Vec::new(),
            acknowledged: Vec::new(),
            shared: Vec::new(),
            remote: None,
            token: None,
            phone: None,
            phones: Phones::default(),
            pairing: None,
            revealing: None,
            revealed: None,
            providers: Providers::default(),
            fading: None,
        }
    }
}

#[derive(Debug)]
pub enum Event {
    /// A frame at `now`, on the clock `Tx::clock` reads.
    Due {
        now: f64,
    },
    /// Ask again now: the probe, and every column asked about.
    Refresh,
    /// Show a project: its environments, and whether to ask about each now.
    Show {
        project: ProjectName,
        columns: Vec<(Selection, bool)>,
    },
    /// A column was clicked: ask about it, with the passphrase if it is
    /// marked sensitive.
    Load(EnvName),
    /// Show one value, once the passphrase is typed.
    Reveal {
        env: EnvName,
        key: KeyName,
    },
    /// Hide the value on show.
    Conceal,
    /// Put away the token a grant was just given, and end the pairing
    /// under way.
    Forget,
    /// Ask how the providers are, and again whenever the columns are.
    CheckProviders,
    /// Ask which phones could be paired, and again whenever the columns
    /// are.
    CheckPhones,
    /// Ask the daemon how it is now, if it is not being asked.
    Probe,
    /// The Proton Pass token and the passphrase, both typed.
    ConnectProton {
        token: WireSecret,
        passphrase: WireSecret,
    },
    Answer {
        attempt: Attempt,
        answer: Answer,
        now: f64,
    },
    /// A person asked for a change.
    Ask(Change),
    /// A person asked to unmark a secret: they are shown these first.
    Unmark(Unmarks),
    /// They agreed to the change they were asked about.
    Confirm,
    /// They ticked, or unticked, a shared secret to mark with the
    /// environment being marked.
    Also(Origin),
    /// They backed out of a confirmation or a passphrase.
    Cancel,
    /// They put the notice away.
    Dismiss,
    Passphrase(WireSecret),
    Lock,
    /// Unlock, with the passphrase if they typed one already; without, the
    /// daemon says whether it needs one.
    Unlock(Option<WireSecret>),
    /// Fetch an environment of the project on show again.
    Resync(EnvName),
    /// The window made an edit; the warnings it gave, or why it failed,
    /// with the failure's code.
    Edited {
        edit: Edit,
        result: Result<Vec<String>, (&'static str, Problem)>,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub enum Effect {
    Run(Attempt, Job),
    /// Make this edit, then send [`Event::Edited`].
    Edit(Edit),
    /// Wake at this time, so a `Due` arrives.
    WakeAt(OrdF64),
}

/// An `f64` that compares, for effects in tests.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct OrdF64(pub f64);
impl Eq for OrdF64 {}

impl Machine {
    fn probe(&mut self, effects: &mut Effects<Effect>) {
        let attempt = self.seq.next();
        self.probe = Probe::Asking(attempt);
        effects.push(Effect::Run(attempt, Job::Probe));
    }

    /// Asks about one column, without the passphrase.
    fn load(&mut self, env: &EnvName, effects: &mut Effects<Effect>) {
        let attempt = self.seq.next();
        let Some(column) = self.shown.as_mut().and_then(|s| s.column_mut(env)) else {
            return;
        };
        column.detail = Detail::Loading(attempt);
        column.inspected = false;
        let facts = column.sel.facts.clone();
        effects.push(Effect::Run(attempt, Job::Env { facts }));
    }

    fn check_providers(&mut self, effects: &mut Effects<Effect>) {
        let attempt = self.seq.next();
        self.providers.asked = true;
        self.providers.asking = Some(attempt);
        effects.push(Effect::Run(attempt, Job::Providers));
    }

    fn check_phones(&mut self, effects: &mut Effects<Effect>) {
        let attempt = self.seq.next();
        self.phones.asked = true;
        self.phones.asking = Some(attempt);
        effects.push(Effect::Run(attempt, Job::Phones));
    }

    /// Takes in what a probe says of the phone. A pairing this window
    /// started that is over says how it ended, and a request answered on
    /// the phone since the last probe says so: the prompt for it closed
    /// here without a word.
    fn heard(&mut self, phone: Option<Box<PhoneStatus>>) {
        // The paired phone, and when: pairing the same one again differs.
        let paired = |p: &Option<Box<PhoneStatus>>| {
            let view = p.as_ref()?.paired.as_ref()?;
            Some((view.node.clone(), view.paired))
        };
        let going = phone.as_ref().is_some_and(|p| p.pairing.is_some());
        if !going && let Some(pairing) = self.pairing.take() {
            let name = pairing.phone.name;
            let now = paired(&phone);
            let done = now != paired(&self.phone)
                && now.is_some_and(|(node, _)| node == pairing.phone.node);
            self.notice = Some(if done {
                Notice::Done {
                    message: format!("Paired {name}: it approves requests now."),
                    warnings: Vec::new(),
                }
            } else {
                Notice::Failed(Problem::new(format!(
                    "{name} was not paired: its time to make a key is up. Pair it again."
                )))
            });
        } else if let (Some(was), Some(now)) = (&self.phone, &phone)
            && was.last != now.last
            && let Some(last) = &now.last
        {
            let name = now.paired.as_ref().map_or("the phone", |p| &p.name);
            self.notice = Some(Notice::Done {
                message: format!(
                    "{} on {name}: {}/{}.",
                    if last.approved { "Approved" } else { "Denied" },
                    last.project,
                    last.env
                ),
                warnings: Vec::new(),
            });
        }
        self.phone = phone;
    }

    /// Asks again about every column asked about before, and the providers
    /// and the phones if they were. One marked sensitive goes back to
    /// waiting for the passphrase.
    fn reload(&mut self, effects: &mut Effects<Effect>) {
        if self.providers.asked {
            self.check_providers(effects);
        }
        if self.phones.asked {
            self.check_phones(effects);
        }
        let asked: Vec<EnvName> = self
            .shown
            .iter()
            .flat_map(|s| &s.columns)
            .filter(|c| c.detail != Detail::Idle)
            .map(|c| c.sel.env.clone())
            .collect();
        for env in asked {
            self.load(&env, effects);
        }
    }

    fn run(&mut self, job: Job, effects: &mut Effects<Effect>) -> Attempt {
        let attempt = self.seq.next();
        self.pending = Pending::Running(attempt);
        effects.push(Effect::Run(attempt, job));
        attempt
    }

    /// Whether what is on show of `provider` is being checked again: every
    /// provider while the daemon is asked about them, and one whose token
    /// is being saved.
    pub fn checking(&self, provider: Provider) -> bool {
        self.providers.asking.is_some()
            || matches!(self.providers.saving, Some((attempt, saved))
                if saved == provider && self.pending == Pending::Running(attempt))
    }

    /// Carries out a change a person asked for, and agreed to if it needed it.
    fn go(&mut self, change: Change, effects: &mut Effects<Effect>) {
        match change {
            Change::Edit(edit) => {
                self.pending = Pending::None;
                effects.push(Effect::Edit(edit));
            }
            Change::Mark { mark, sensitive } => {
                self.pending = Pending::Passphrase(Purpose::Mark { mark, sensitive });
            }
            Change::ConnectProton { expires } => {
                self.pending = Pending::Passphrase(Purpose::ConnectProton { expires });
            }
            Change::Acknowledge {
                project,
                env,
                acknowledged,
            } => {
                self.pending = Pending::Passphrase(Purpose::Acknowledge {
                    project,
                    env,
                    acknowledged,
                    unmark: Vec::new(),
                });
            }
            Change::AcknowledgeAll(envs) => {
                self.pending = Pending::Passphrase(Purpose::AcknowledgeAll(envs));
            }
            Change::RotateGrant { grant, .. } => {
                self.pending = Pending::Passphrase(Purpose::RotateGrant(grant));
            }
            Change::RevokeGrant(grant) => {
                self.pending = Pending::Passphrase(Purpose::RevokeGrant(grant));
            }
            Change::PairPhone(phone) => {
                self.pending = Pending::Passphrase(Purpose::PairPhone(phone));
            }
            Change::UnpairPhone(name) => {
                self.pending = Pending::Passphrase(Purpose::UnpairPhone(name));
            }
        }
    }

    fn failed(&mut self, problem: Problem) {
        if problem.unreachable {
            self.conn = Conn::Down(problem.clone());
        }
        self.notice = Some(Notice::Failed(problem));
    }

    fn facts(&self, env: &EnvName) -> Option<Facts> {
        Some(self.shown.as_ref()?.column(env)?.sel.facts.clone())
    }

    /// The daemon answered, locked or not.
    fn up(&mut self, locked: bool) {
        self.conn = Conn::Up { locked };
        if locked {
            self.revealed = None;
            self.token = None;
            // The daemon dropped it with the session.
            self.pairing = None;
            self.waiting.clear();
            self.acknowledged.clear();
            self.shared.clear();
        }
    }
}

pub fn step(m: &mut Machine, event: Event) -> Effects<Effect> {
    let was = m.notice.clone();
    let effects = react(m, event);
    // Another notice gets its own time.
    if m.notice != was {
        m.fading = None;
    }
    effects
}

impl Machine {
    /// Times the notice out: one that only says a change was made goes
    /// [`NOTICE_FOR`] seconds after the first frame that showed it.
    fn fade(&mut self, now: f64, effects: &mut Effects<Effect>) {
        let passing =
            matches!(&self.notice, Some(Notice::Done { warnings, .. }) if warnings.is_empty());
        match self.fading {
            _ if !passing => self.fading = None,
            None => {
                let due = now + NOTICE_FOR;
                self.fading = Some(due);
                effects.push(Effect::WakeAt(OrdF64(due)));
            }
            Some(due) if now >= due => {
                self.notice = None;
                self.fading = None;
            }
            Some(_) => {}
        }
    }

    /// Whether `env` of the project on show was acknowledged as not
    /// production, as the last probe saw.
    fn acknowledged(&self, env: &EnvName) -> bool {
        self.shown.as_ref().is_some_and(|s| {
            self.acknowledged
                .iter()
                .any(|a| a.project == s.project && &a.env == env)
        })
    }

    /// Asks about every column not asked about yet whose environment was
    /// acknowledged as not production: its name held it back, and it is
    /// read as any other. One that waits for its decision, or is marked
    /// sensitive, stays the person's to ask about: the daemon would refuse
    /// it, and the audit log would say so each time the project is shown.
    fn load_acknowledged(&mut self, effects: &mut Effects<Effect>) {
        if self.conn != (Conn::Up { locked: false }) {
            return;
        }
        let envs: Vec<EnvName> = self
            .shown
            .iter()
            .flat_map(|s| &s.columns)
            .filter(|c| c.detail == Detail::Idle && self.acknowledged(&c.sel.env))
            .map(|c| c.sel.env.clone())
            .collect();
        for env in envs {
            self.load(&env, effects);
        }
    }
}

fn react(m: &mut Machine, event: Event) -> Effects<Effect> {
    let mut effects = Effects::none();
    match event {
        Event::Due { now } => {
            if let Probe::Waiting { due } = m.probe
                && now >= due
            {
                m.probe(&mut effects);
            }
            m.fade(now, &mut effects);
        }
        Event::Refresh => {
            m.probe(&mut effects);
            m.reload(&mut effects);
        }
        Event::Show { project, columns } => {
            let now: Vec<EnvName> = columns
                .iter()
                .filter(|(_, now)| *now)
                .map(|(sel, _)| sel.env.clone())
                .collect();
            let columns = columns
                .into_iter()
                .map(|(sel, _)| Column {
                    sel,
                    detail: Detail::Idle,
                    inspected: false,
                })
                .collect();
            m.shown = Some(Shown { project, columns });
            m.revealed = None;
            for env in now {
                m.load(&env, &mut effects);
            }
            m.load_acknowledged(&mut effects);
        }
        Event::Load(env) => {
            let Some(column) = m.shown.as_ref().and_then(|s| s.column(&env)) else {
                return effects;
            };
            match &column.detail {
                Detail::Idle | Detail::Failed(_) => m.load(&env, &mut effects),
                Detail::Loaded(EnvReport::Sensitive) if m.pending == Pending::None => {
                    m.notice = None;
                    m.pending = Pending::Passphrase(Purpose::Inspect(env));
                }
                _ => {}
            }
        }
        Event::Reveal { env, key } => {
            if m.pending == Pending::None {
                m.notice = None;
                m.pending = Pending::Passphrase(Purpose::Reveal { env, key });
            }
        }
        Event::Conceal => m.revealed = None,
        Event::Forget => {
            m.token = None;
            if m.pairing.take().is_some() {
                // Nothing waits for its answer.
                let attempt = m.seq.next();
                effects.push(Effect::Run(attempt, Job::StopPairing));
            }
        }
        Event::CheckProviders => {
            if m.providers.asking.is_none() {
                m.check_providers(&mut effects);
            }
        }
        Event::CheckPhones => {
            if m.phones.asking.is_none() {
                m.check_phones(&mut effects);
            }
        }
        Event::Probe => {
            if !matches!(m.probe, Probe::Asking(_)) {
                m.probe(&mut effects);
            }
        }
        Event::Answer {
            attempt,
            answer: Answer::Phones(result),
            ..
        } => {
            if m.phones.asking != Some(attempt) {
                return effects;
            }
            m.phones.asking = None;
            if let Err(p) = &result
                && p.unreachable
            {
                m.conn = Conn::Down(p.clone());
            }
            m.phones.last = Some(result);
        }
        Event::Answer {
            attempt,
            answer: Answer::Pairing(result),
            ..
        } => {
            if m.pending != Pending::Running(attempt) {
                return effects;
            }
            m.pending = Pending::None;
            match result {
                Ok(pairing) => {
                    m.pairing = Some(pairing);
                    // Probed from here on for the phone making its key.
                    m.probe(&mut effects);
                }
                Err(p) => m.failed(p),
            }
        }
        Event::Answer {
            attempt,
            answer: Answer::Providers(result),
            ..
        } => {
            if m.providers.asking != Some(attempt) {
                return effects;
            }
            m.providers.asking = None;
            if let Err(p) = &result
                && p.unreachable
            {
                m.conn = Conn::Down(p.clone());
            }
            m.providers.last = Some(result);
        }
        Event::Answer {
            attempt,
            answer: Answer::Probe(result),
            now,
        } => {
            if m.probe != Probe::Asking(attempt) {
                return effects;
            }
            let before = m.conn.locked();
            let due = match result {
                Ok(probed) => {
                    m.up(probed.locked);
                    m.expiring = probed.expiring;
                    m.waiting = probed.waiting;
                    m.acknowledged = probed.acknowledged;
                    m.shared = probed.shared;
                    m.remote = probed.remote;
                    m.heard(probed.phone);
                    if m.pairing.is_some() {
                        now + PAIRING_PROBE_EVERY
                    } else {
                        now + PROBE_EVERY
                    }
                }
                Err(p) => {
                    m.conn = Conn::Down(p);
                    m.expiring.clear();
                    m.waiting.clear();
                    m.acknowledged.clear();
                    m.shared.clear();
                    m.remote = None;
                    m.phone = None;
                    m.pairing = None;
                    now + RETRY_AFTER
                }
            };
            m.probe = Probe::Waiting { due };
            effects.push(Effect::WakeAt(OrdF64(due)));
            // Unlocked, locked, or back up: what the columns show has changed.
            let settled = m.shown.as_ref().is_some_and(|s| {
                !s.columns
                    .iter()
                    .any(|c| matches!(c.detail, Detail::Loading(_)))
            });
            if settled && m.conn.locked().is_some() && m.conn.locked() != before {
                m.reload(&mut effects);
            }
            m.load_acknowledged(&mut effects);
        }
        Event::Answer {
            attempt,
            answer: Answer::Env(result),
            ..
        } => {
            let Some(column) = m.shown.as_mut().and_then(|s| {
                s.columns
                    .iter_mut()
                    .find(|c| c.detail == Detail::Loading(attempt))
            }) else {
                return effects;
            };
            let up = match &result {
                Ok(EnvReport::Locked) => Some(true),
                Ok(EnvReport::Resolved { .. } | EnvReport::Sensitive) => Some(false),
                Err(_) => None,
            };
            let mut failed = None;
            column.detail = match result {
                Ok(report) => Detail::Loaded(report),
                // A wrong passphrase leaves it waiting for the right one.
                Err(p) if column.inspected && !p.unreachable => {
                    column.inspected = false;
                    failed = Some(p);
                    Detail::Loaded(EnvReport::Sensitive)
                }
                Err(p) => {
                    if p.unreachable {
                        m.conn = Conn::Down(p.clone());
                    }
                    Detail::Failed(p)
                }
            };
            if let Some(locked) = up {
                m.up(locked);
            }
            if let Some(p) = failed {
                m.failed(p);
            }
        }
        Event::Answer {
            attempt,
            answer: Answer::Revealed(result),
            ..
        } => {
            if m.pending != Pending::Running(attempt) {
                return effects;
            }
            m.pending = Pending::None;
            let asked = m.revealing.take();
            match (result, asked) {
                (Ok(value), Some((env, key))) => m.revealed = Some(Revealed { env, key, value }),
                (Ok(_), None) => {}
                (Err(p), _) => m.failed(p),
            }
        }
        Event::Answer {
            attempt,
            answer: Answer::Token(result),
            ..
        } => {
            if m.pending != Pending::Running(attempt) {
                return effects;
            }
            m.pending = Pending::None;
            match result {
                Ok(token) => {
                    m.token = Some(token);
                    // The grant has a token now: ask the daemon to say so.
                    m.probe(&mut effects);
                }
                Err(p) => m.failed(p),
            }
        }
        Event::Answer {
            attempt,
            answer: Answer::Action(result),
            ..
        } => {
            if m.pending != Pending::Running(attempt) {
                return effects;
            }
            m.pending = Pending::None;
            // A mark or an acknowledgement may end an environment's wait,
            // and a grant revoked or a phone removed is gone: ask the
            // daemon what is left now, not at the next probe.
            if matches!(
                result,
                Ok(Done::Marked { .. }
                    | Done::Acknowledged { .. }
                    | Done::Unmarked(_)
                    | Done::GrantRevoked(_)
                    | Done::PhoneUnpaired(_))
            ) {
                m.probe(&mut effects);
            }
            let (message, warnings) = match result {
                Err(p) => {
                    m.failed(p);
                    return effects;
                }
                Ok(Done::PassphraseRequired) => {
                    m.pending = Pending::Passphrase(Purpose::Unlock);
                    return effects;
                }
                Ok(Done::LockState { locked, warnings }) => {
                    m.up(locked);
                    let what = if locked { "Locked." } else { "Unlocked." };
                    (what.to_owned(), warnings)
                }
                Ok(Done::Synced { keys, warnings }) => (format!("Fetched {keys} keys."), warnings),
                Ok(Done::Marked {
                    what,
                    sensitive: true,
                }) => (format!("Marked {what} sensitive."), Vec::new()),
                Ok(Done::Marked {
                    what,
                    sensitive: false,
                }) => (format!("Unmarked {what}."), Vec::new()),
                Ok(Done::Unmarked(1)) => ("Unmarked 1 secret.".to_owned(), Vec::new()),
                Ok(Done::Unmarked(n)) => (format!("Unmarked {n} secrets."), Vec::new()),
                Ok(Done::ProtonConnected { vaults, locked }) => {
                    m.up(locked);
                    let s = if vaults == 1 { "" } else { "s" };
                    (
                        format!("Connected Proton Pass: it reads {vaults} vault{s}."),
                        Vec::new(),
                    )
                }
                Ok(Done::Acknowledged {
                    acknowledged: true,
                    unmarked,
                }) => {
                    let also = match unmarked {
                        0 => String::new(),
                        1 => " Unmarked 1 secret.".to_owned(),
                        n => format!(" Unmarked {n} secrets."),
                    };
                    (format!("Acknowledged as not production.{also}"), Vec::new())
                }
                Ok(Done::Acknowledged {
                    acknowledged: false,
                    ..
                }) => ("Took the acknowledgement back.".to_owned(), Vec::new()),
                Ok(Done::GrantRevoked(grant)) => (
                    format!(
                        "Revoked machine {}'s grant for {}.",
                        grant.machine, grant.project
                    ),
                    Vec::new(),
                ),
                Ok(Done::PairingStopped) => ("Stopped pairing.".to_owned(), Vec::new()),
                Ok(Done::PhoneUnpaired(name)) => (
                    format!("Removed {name}: requests are approved at this computer only."),
                    Vec::new(),
                ),
            };
            m.notice = Some(Notice::Done { message, warnings });
            m.reload(&mut effects);
        }
        // One change at a time.
        Event::Ask(_) | Event::Unmark(_) | Event::Lock | Event::Unlock(_) | Event::Resync(_)
            if m.pending != Pending::None => {}
        Event::Unmark(unmarks) => {
            m.notice = None;
            m.pending = Pending::Unmarks(unmarks);
        }
        Event::Ask(change) => {
            m.notice = None;
            m.token = None;
            let sharing = match &change {
                Change::Mark {
                    mark: Mark::Env { project, env, .. },
                    sensitive: true,
                } => Sharing::of(project, env, &m.shared),
                _ => None,
            };
            let unmarking = match &change {
                Change::Acknowledge {
                    project,
                    env,
                    acknowledged: true,
                } => Unmarking::of(project, env, &m.shared),
                _ => None,
            };
            match (sharing, unmarking, change.question()) {
                (Some(sharing), ..) => m.pending = Pending::Sharing(sharing),
                (None, Some(unmarking), _) => m.pending = Pending::Unmarking(unmarking),
                (None, None, Some(question)) => m.pending = Pending::Confirm { change, question },
                (None, None, None) => m.go(change, &mut effects),
            }
        }
        Event::Also(secret) => {
            // The ticked, and whether `secret` is on offer.
            let (ticked, offered) = match &mut m.pending {
                Pending::Sharing(sharing) => {
                    let offered = sharing.open.iter().any(|s| s.secret == secret);
                    (&mut sharing.also, offered)
                }
                Pending::Unmarking(unmarking) => {
                    let offered = unmarking.marked.iter().any(|s| s.secret == secret);
                    (&mut unmarking.unmark, offered)
                }
                Pending::Unmarks(unmarks) => {
                    let offered = unmarks.marked.iter().any(|s| s.secret == secret);
                    (&mut unmarks.unmark, offered)
                }
                _ => return effects,
            };
            match ticked.iter().position(|s| *s == secret) {
                Some(at) => {
                    ticked.remove(at);
                }
                None if offered => ticked.push(secret),
                None => {}
            }
        }
        Event::Confirm => match std::mem::take(&mut m.pending) {
            Pending::Confirm { change, .. } => m.go(change, &mut effects),
            Pending::Sharing(Sharing {
                project, env, also, ..
            }) => {
                let mark = Mark::Env { project, env, also };
                m.go(
                    Change::Mark {
                        mark,
                        sensitive: true,
                    },
                    &mut effects,
                );
            }
            Pending::Unmarking(Unmarking {
                project,
                env,
                unmark,
                ..
            }) => {
                m.pending = Pending::Passphrase(Purpose::Acknowledge {
                    project,
                    env,
                    acknowledged: true,
                    unmark,
                });
            }
            // Nothing ticked is nothing to do: the list stays.
            Pending::Unmarks(Unmarks { unmark, .. }) if !unmark.is_empty() => {
                m.pending = Pending::Passphrase(Purpose::Unmark(unmark));
            }
            other => m.pending = other,
        },
        Event::Dismiss => m.notice = None,
        Event::Cancel => {
            if matches!(
                m.pending,
                Pending::Confirm { .. }
                    | Pending::Sharing(_)
                    | Pending::Unmarking(_)
                    | Pending::Unmarks(_)
                    | Pending::Passphrase(_)
            ) {
                m.pending = Pending::None;
            }
        }
        Event::Passphrase(passphrase) => {
            let job = match std::mem::take(&mut m.pending) {
                Pending::Passphrase(Purpose::Unlock) => Job::Unlock {
                    passphrase: Some(passphrase),
                },
                Pending::Passphrase(Purpose::Mark { mark, sensitive }) => Job::Mark {
                    mark,
                    sensitive,
                    passphrase,
                },
                Pending::Passphrase(Purpose::Acknowledge {
                    project,
                    env,
                    acknowledged,
                    unmark,
                }) => Job::Acknowledge {
                    project,
                    env,
                    acknowledged,
                    unmark,
                    passphrase,
                },
                Pending::Passphrase(Purpose::AcknowledgeAll(envs)) => {
                    Job::AcknowledgeAll { envs, passphrase }
                }
                Pending::Passphrase(Purpose::Unmark(secrets)) => Job::Unmark {
                    secrets,
                    passphrase,
                },
                Pending::Passphrase(Purpose::RotateGrant(grant)) => {
                    Job::RotateGrant { grant, passphrase }
                }
                Pending::Passphrase(Purpose::RevokeGrant(grant)) => {
                    Job::RevokeGrant { grant, passphrase }
                }
                Pending::Passphrase(Purpose::PairPhone(phone)) => {
                    Job::PairPhone { phone, passphrase }
                }
                Pending::Passphrase(Purpose::UnpairPhone(name)) => {
                    Job::UnpairPhone { name, passphrase }
                }
                Pending::Passphrase(Purpose::Inspect(env)) => {
                    let attempt = m.seq.next();
                    let Some(column) = m.shown.as_mut().and_then(|s| s.column_mut(&env)) else {
                        return effects;
                    };
                    column.detail = Detail::Loading(attempt);
                    column.inspected = true;
                    let facts = column.sel.facts.clone();
                    effects.push(Effect::Run(attempt, Job::Inspect { facts, passphrase }));
                    return effects;
                }
                Pending::Passphrase(Purpose::Reveal { env, key }) => {
                    let Some(facts) = m.facts(&env) else {
                        return effects;
                    };
                    m.revealing = Some((env, key.clone()));
                    Job::Reveal {
                        facts,
                        key,
                        passphrase,
                    }
                }
                other => {
                    m.pending = other;
                    return effects;
                }
            };
            m.run(job, &mut effects);
        }
        Event::ConnectProton { token, passphrase } => {
            if let Pending::Passphrase(Purpose::ConnectProton { expires }) = m.pending {
                let job = Job::ConnectProton {
                    token,
                    expires,
                    passphrase,
                };
                let attempt = m.run(job, &mut effects);
                m.providers.saving = Some((attempt, Provider::Proton));
            }
        }
        Event::Lock => {
            m.notice = None;
            m.run(Job::Lock, &mut effects);
        }
        Event::Unlock(passphrase) => {
            m.notice = None;
            m.run(Job::Unlock { passphrase }, &mut effects);
        }
        Event::Resync(env) => {
            let Some(shown) = &m.shown else {
                return effects;
            };
            let job = Job::Sync {
                project: shown.project.clone(),
                env,
            };
            m.notice = None;
            m.run(job, &mut effects);
        }
        Event::Edited { edit, result } => match result {
            Err((_, p)) => m.failed(p),
            Ok(warnings) => {
                m.notice = Some(Notice::Done {
                    message: edit.done(),
                    warnings,
                });
                m.reload(&mut effects);
            }
        },
    }
    effects
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::Probed;

    fn selection(env: &str) -> Selection {
        Selection {
            project: "widget".parse().unwrap(),
            env: env.parse().unwrap(),
            facts: Facts {
                cwd: "/".into(),
                remotes: vec!["github.com/acme/widget".parse().unwrap()],
                subdir: None,
                root: None,
                project: None,
                env: Some(env.parse().unwrap()),
                example_keys: None,
                example_values: Vec::new(),
                env_file: None,
            },
        }
    }

    /// Shows widget with these environments, each asked about now or not.
    fn show(m: &mut Machine, envs: &[(&str, bool)]) -> Vec<(Attempt, Job)> {
        let columns = envs.iter().map(|(e, now)| (selection(e), *now)).collect();
        runs(step(
            m,
            Event::Show {
                project: "widget".parse().unwrap(),
                columns,
            },
        ))
    }

    fn column<'a>(m: &'a Machine, env: &str) -> &'a Column {
        m.shown
            .as_ref()
            .unwrap()
            .column(&env.parse().unwrap())
            .unwrap()
    }

    fn runs(effects: Effects<Effect>) -> Vec<(Attempt, Job)> {
        effects
            .into_iter()
            .filter_map(|e| match e {
                Effect::Run(a, j) => Some((a, j)),
                Effect::WakeAt(_) | Effect::Edit(_) => None,
            })
            .collect()
    }

    fn resolved() -> EnvReport {
        EnvReport::Resolved {
            keys: Vec::new(),
            missing: None,
            vars: Vec::new(),
            warnings: Vec::new(),
            acknowledged: false,
            skipped: Vec::new(),
            fixes: Vec::new(),
            proof: None,
        }
    }

    fn down() -> Problem {
        Problem {
            unreachable: true,
            ..Problem::new("the daemon is not running")
        }
    }

    #[test]
    fn probes_on_the_first_frame_then_on_a_timer() {
        let mut m = Machine::default();
        let first = runs(step(&mut m, Event::Due { now: 0.0 }));
        assert!(matches!(first[..], [(_, Job::Probe)]));
        // Asking: frames don't ask again.
        assert!(step(&mut m, Event::Due { now: 0.5 }).is_empty());
        let effects = step(
            &mut m,
            Event::Answer {
                attempt: first[0].0,
                answer: Answer::Probe(Ok(Probed::locked(true))),
                now: 1.0,
            },
        );
        assert_eq!(m.conn, Conn::Up { locked: true });
        assert_eq!(
            effects.into_iter().collect::<Vec<_>>(),
            [Effect::WakeAt(OrdF64(1.0 + PROBE_EVERY))]
        );
        assert!(step(&mut m, Event::Due { now: 2.0 }).is_empty());
        assert_eq!(runs(step(&mut m, Event::Due { now: 6.0 })).len(), 1);
    }

    /// The tokens near expiry and the environments waiting for a decision.
    #[test]
    fn a_probe_keeps_what_it_learned_until_the_daemon_goes_down() {
        let mut m = Machine::default();
        let (a, _) = runs(step(&mut m, Event::Due { now: 0.0 })).remove(0);
        let expiring = vec![TokenExpiry {
            provider: kagebunshin::types::Provider::Proton,
            expires: 1_801_353_600,
        }];
        let waiting = vec![WaitingEnv {
            project: "widget".parse().unwrap(),
            env: "prod".parse().unwrap(),
            why: "its name has the segment prod".into(),
        }];
        step(
            &mut m,
            Event::Answer {
                attempt: a,
                answer: Answer::Probe(Ok(Probed {
                    locked: false,
                    expiring: expiring.clone(),
                    waiting: waiting.clone(),
                    acknowledged: Vec::new(),
                    shared: Vec::new(),
                    remote: None,
                    phone: None,
                })),
                now: 0.0,
            },
        );
        assert_eq!(m.expiring, expiring);
        assert_eq!(m.waiting, waiting);
        let (a, _) = runs(step(&mut m, Event::Due { now: PROBE_EVERY })).remove(0);
        step(
            &mut m,
            Event::Answer {
                attempt: a,
                answer: Answer::Probe(Err(down())),
                now: PROBE_EVERY,
            },
        );
        assert!(m.expiring.is_empty());
        assert!(m.waiting.is_empty());
    }

    #[test]
    fn a_down_daemon_is_retried_sooner() {
        let mut m = Machine::default();
        let (a, _) = runs(step(&mut m, Event::Due { now: 0.0 })).remove(0);
        step(
            &mut m,
            Event::Answer {
                attempt: a,
                answer: Answer::Probe(Err(down())),
                now: 0.0,
            },
        );
        assert!(matches!(m.conn, Conn::Down(_)));
        assert_eq!(m.probe, Probe::Waiting { due: RETRY_AFTER });
    }

    #[test]
    fn a_stale_answer_changes_nothing() {
        let mut m = Machine::default();
        let (old, _) = runs(step(&mut m, Event::Due { now: 0.0 })).remove(0);
        // Refresh supersedes the probe in flight.
        let fresh = runs(step(&mut m, Event::Refresh));
        assert_ne!(fresh[0].0, old);
        step(
            &mut m,
            Event::Answer {
                attempt: old,
                answer: Answer::Probe(Ok(Probed::locked(false))),
                now: 0.1,
            },
        );
        assert_eq!(m.conn, Conn::Unknown);

        // Showing the project again drops the first answer.
        let (dev, _) = show(&mut m, &[("dev", true)]).remove(0);
        let (prod, _) = show(&mut m, &[("prod", true)]).remove(0);
        step(
            &mut m,
            Event::Answer {
                attempt: dev,
                answer: Answer::Env(Ok(resolved())),
                now: 0.2,
            },
        );
        assert_eq!(column(&m, "prod").detail, Detail::Loading(prod));
    }

    #[test]
    fn unlocking_reloads_the_env_on_show() {
        let mut m = Machine::default();
        let (a, _) = runs(step(&mut m, Event::Due { now: 0.0 })).remove(0);
        step(
            &mut m,
            Event::Answer {
                attempt: a,
                answer: Answer::Probe(Ok(Probed::locked(true))),
                now: 0.0,
            },
        );
        let (e, job) = show(&mut m, &[("dev", true)]).remove(0);
        assert!(
            matches!(job, Job::Env { ref facts } if facts.env.as_ref().unwrap().as_str() == "dev")
        );
        step(
            &mut m,
            Event::Answer {
                attempt: e,
                answer: Answer::Env(Ok(EnvReport::Locked)),
                now: 0.1,
            },
        );
        assert_eq!(column(&m, "dev").detail, Detail::Loaded(EnvReport::Locked));

        // Still locked: nothing to reload.
        let (p, _) = runs(step(&mut m, Event::Due { now: 5.0 })).remove(0);
        let still = step(
            &mut m,
            Event::Answer {
                attempt: p,
                answer: Answer::Probe(Ok(Probed::locked(true))),
                now: 5.0,
            },
        );
        assert!(runs(still).is_empty());
        // Unlocked at the terminal: the env is asked about again.
        let (p, _) = runs(step(&mut m, Event::Due { now: 10.0 })).remove(0);
        let reload = runs(step(
            &mut m,
            Event::Answer {
                attempt: p,
                answer: Answer::Probe(Ok(Probed::locked(false))),
                now: 10.0,
            },
        ));
        assert!(matches!(reload[..], [(_, Job::Env { .. })]));
    }

    #[test]
    fn an_env_answer_updates_the_connection() {
        let mut m = Machine::default();
        let (e, _) = show(&mut m, &[("dev", true)]).remove(0);
        step(
            &mut m,
            Event::Answer {
                attempt: e,
                answer: Answer::Env(Err(down())),
                now: 0.0,
            },
        );
        assert!(matches!(m.conn, Conn::Down(_)));
        assert!(matches!(column(&m, "dev").detail, Detail::Failed(_)));

        // A source failing is the env's problem, not the connection's.
        m.conn = Conn::Up { locked: false };
        let (e, _) = runs(step(&mut m, Event::Refresh)).pop().unwrap();
        step(
            &mut m,
            Event::Answer {
                attempt: e,
                answer: Answer::Env(Err(Problem::new("AWS SSO session expired"))),
                now: 0.0,
            },
        );
        assert_eq!(m.conn, Conn::Up { locked: false });
    }

    fn shown() -> Machine {
        Machine {
            conn: Conn::Up { locked: false },
            shown: Some(Shown {
                project: "widget".parse().unwrap(),
                columns: vec![Column {
                    sel: selection("dev"),
                    detail: Detail::Loaded(resolved()),
                    inspected: false,
                }],
            }),
            ..Machine::default()
        }
    }

    fn pw() -> WireSecret {
        WireSecret::new("pw".into())
    }

    fn answer(m: &mut Machine, attempt: Attempt, answer: Answer) -> Vec<(Attempt, Job)> {
        runs(step(
            m,
            Event::Answer {
                attempt,
                answer,
                now: 0.0,
            },
        ))
    }

    /// A prod-looking column waits to be clicked; one marked sensitive then
    /// waits for the passphrase, and a wrong one leaves it waiting.
    #[test]
    fn prod_columns_wait_and_sensitive_ones_take_the_passphrase() {
        let mut m = Machine::default();
        let asked = show(&mut m, &[("dev", true), ("prod", false)]);
        assert!(
            matches!(&asked[..], [(_, Job::Env { facts })] if facts.env.as_ref().unwrap().as_str() == "dev")
        );
        assert_eq!(column(&m, "prod").detail, Detail::Idle);

        let (a, job) = runs(step(&mut m, Event::Load("prod".parse().unwrap()))).remove(0);
        assert!(matches!(job, Job::Env { .. }));
        answer(&mut m, a, Answer::Env(Ok(EnvReport::Sensitive)));
        assert_eq!(column(&m, "prod").marked(), Some(true));

        for (pass, result) in [
            ("wrong", Err(Problem::new("wrong passphrase"))),
            ("pw", Ok(resolved())),
        ] {
            assert!(step(&mut m, Event::Load("prod".parse().unwrap())).is_empty());
            assert_eq!(
                m.pending,
                Pending::Passphrase(Purpose::Inspect("prod".parse().unwrap()))
            );
            let (a, job) = runs(step(
                &mut m,
                Event::Passphrase(WireSecret::new(pass.into())),
            ))
            .remove(0);
            assert!(
                matches!(job, Job::Inspect { ref passphrase, .. } if passphrase.expose() == pass)
            );
            assert_eq!(m.pending, Pending::None);
            let wrong = result.is_err();
            answer(&mut m, a, Answer::Env(result));
            if wrong {
                let failed = Notice::Failed(Problem::new("wrong passphrase"));
                assert_eq!(m.notice, Some(failed));
                assert_eq!(
                    column(&m, "prod").detail,
                    Detail::Loaded(EnvReport::Sensitive)
                );
            }
        }
        let prod = column(&m, "prod");
        assert!(matches!(
            prod.detail,
            Detail::Loaded(EnvReport::Resolved { .. })
        ));
        assert_eq!(prod.marked(), Some(true));

        // Asked again without the passphrase: back to waiting for it.
        let again = runs(step(&mut m, Event::Refresh));
        assert_eq!(
            again
                .iter()
                .filter(|(_, j)| matches!(j, Job::Env { .. }))
                .count(),
            2
        );
        assert!(!column(&m, "prod").inspected);
    }

    /// A column held back for its name is asked about once the daemon says
    /// its environment was acknowledged as not production. One that waits
    /// or is marked sensitive is not: the daemon would refuse it, and log
    /// that it did.
    #[test]
    fn a_held_back_column_loads_once_its_environment_is_acknowledged() {
        let probed = |m: &mut Machine, locked: bool, acknowledged: &[&str]| {
            let (a, _) = runs(step(m, Event::Refresh)).remove(0);
            let acknowledged = acknowledged
                .iter()
                .map(|env| Section {
                    project: "widget".parse().unwrap(),
                    env: env.parse().unwrap(),
                })
                .collect();
            let probed = Probed {
                acknowledged,
                ..Probed::locked(locked)
            };
            let asked = answer(m, a, Answer::Probe(Ok(probed)));
            let mut envs: Vec<String> = asked
                .into_iter()
                .filter_map(|(_, j)| match j {
                    Job::Env { facts } => facts.env.map(|e| e.to_string()),
                    _ => None,
                })
                .collect();
            envs.sort();
            envs
        };
        let mut m = Machine::default();
        show(&mut m, &[("dev", true), ("prod", false), ("rc", false)]);
        // Nothing is known of either yet.
        assert!(probed(&mut m, false, &[]).is_empty());
        assert_eq!(probed(&mut m, false, &["rc"]), ["rc"]);
        assert_eq!(column(&m, "prod").detail, Detail::Idle);
        assert!(probed(&mut m, false, &["rc"]).is_empty());
        assert_eq!(probed(&mut m, false, &["prod", "rc"]), ["prod"]);

        // Shown while the daemon is known to be unlocked: at once.
        let asked = show(&mut m, &[("dev", true), ("prod", false)]);
        assert_eq!(asked.len(), 2, "{asked:?}");
        // Another project's environment of that name is not this one.
        m.acknowledged = vec![Section {
            project: "gadget".parse().unwrap(),
            env: "prod".parse().unwrap(),
        }];
        assert!(show(&mut m, &[("prod", false)]).is_empty());
        // Locked, the daemon says nothing of it.
        show(&mut m, &[("prod", false)]);
        assert!(probed(&mut m, true, &[]).is_empty());
        assert!(m.acknowledged.is_empty());
    }

    /// A notice of a change made goes [`NOTICE_FOR`] seconds after the
    /// first frame that showed it; a warning or a failure stays; any is
    /// put away when asked.
    #[test]
    fn a_notice_of_a_change_times_out_and_any_is_dismissed() {
        let done = |warnings: &[&str]| Notice::Done {
            message: "Unmarked acme/dev/stripe.".into(),
            warnings: warnings.iter().map(|w| (*w).to_owned()).collect(),
        };
        let mut m = shown();
        m.probe = Probe::Waiting { due: 1000.0 };
        m.notice = Some(done(&[]));
        let woken: Vec<_> = step(&mut m, Event::Due { now: 10.0 }).into_iter().collect();
        assert_eq!(woken, [Effect::WakeAt(OrdF64(10.0 + NOTICE_FOR))]);
        assert!(step(&mut m, Event::Due { now: 15.9 }).is_empty());
        assert!(m.notice.is_some());
        step(
            &mut m,
            Event::Due {
                now: 10.0 + NOTICE_FOR,
            },
        );
        assert_eq!(m.notice, None);

        for stays in [done(&["it warned"]), Notice::Failed(Problem::new("no"))] {
            m.notice = Some(stays.clone());
            assert!(step(&mut m, Event::Due { now: 20.0 }).is_empty());
            step(&mut m, Event::Due { now: 100.0 });
            assert_eq!(m.notice, Some(stays));
            step(&mut m, Event::Dismiss);
            assert_eq!(m.notice, None);
        }

        // One put away early leaves no time behind for the next.
        m.notice = Some(done(&[]));
        step(&mut m, Event::Due { now: 200.0 });
        step(&mut m, Event::Dismiss);
        m.notice = Some(done(&[]));
        step(&mut m, Event::Due { now: 205.0 });
        step(&mut m, Event::Due { now: 207.0 });
        assert!(m.notice.is_some());
        step(&mut m, Event::Due { now: 211.0 });
        assert_eq!(m.notice, None);
    }

    #[test]
    fn a_value_is_revealed_with_the_passphrase_until_hidden_or_locked() {
        let mut m = shown();
        let reveal = || Event::Reveal {
            env: "dev".parse().unwrap(),
            key: "API_KEY".parse().unwrap(),
        };
        let value = || WireSecret::new("s3cret".into());
        for hide in [Event::Conceal, Event::Lock] {
            assert!(step(&mut m, reveal()).is_empty());
            let (a, job) = runs(step(&mut m, Event::Passphrase(pw()))).remove(0);
            let Job::Reveal { facts, key, .. } = job else {
                panic!("{job:?}")
            };
            assert_eq!(
                (facts.env.unwrap().as_str(), key.as_str()),
                ("dev", "API_KEY")
            );
            answer(&mut m, a, Answer::Revealed(Ok(value())));
            let shown = m.revealed.as_ref().unwrap();
            assert_eq!(shown.value, value());
            assert!(!format!("{m:?}").contains("s3cret"));
            match hide {
                Event::Lock => {
                    let (a, _) = runs(step(&mut m, Event::Lock)).remove(0);
                    let done = Done::LockState {
                        locked: true,
                        warnings: Vec::new(),
                    };
                    answer(&mut m, a, Answer::Action(Ok(done)));
                }
                e => drop(step(&mut m, e)),
            }
            assert_eq!(m.revealed, None);
        }
        // A wrong passphrase reveals nothing.
        m.conn = Conn::Up { locked: false };
        step(&mut m, reveal());
        let (a, _) = runs(step(&mut m, Event::Passphrase(pw()))).remove(0);
        answer(
            &mut m,
            a,
            Answer::Revealed(Err(Problem::new("wrong passphrase"))),
        );
        assert_eq!(m.revealed, None);
        assert!(matches!(m.notice, Some(Notice::Failed(_))));
    }

    fn edits(effects: Effects<Effect>) -> Vec<Edit> {
        effects
            .into_iter()
            .filter_map(|e| match e {
                Effect::Edit(edit) => Some(edit),
                _ => None,
            })
            .collect()
    }

    fn mark_secret(sensitive: bool) -> Change {
        Change::Mark {
            mark: Mark::Secret(kagebunshin::types::Origin::new(
                kagebunshin::types::Provider::AwsSm,
                "acme/dev/stripe",
            )),
            sensitive,
        }
    }

    fn remove() -> Edit {
        Edit::RemoveSource {
            project: "widget".parse().unwrap(),
            env: "dev".parse().unwrap(),
            index: 0,
        }
    }

    #[test]
    fn marking_asks_for_the_passphrase_and_unmarking_is_confirmed_first() {
        let mut m = shown();
        assert!(step(&mut m, Event::Ask(mark_secret(true))).is_empty());
        assert!(matches!(
            m.pending,
            Pending::Passphrase(Purpose::Mark {
                sensitive: true,
                ..
            })
        ));
        assert!(step(&mut m, Event::Cancel).is_empty());

        let asked = step(&mut m, Event::Ask(mark_secret(false)));
        assert!(asked.is_empty());
        let Pending::Confirm { question, .. } = &m.pending else {
            panic!("{:?}", m.pending)
        };
        assert!(question.contains("acme/dev/stripe"), "{question}");
        // Nothing else while it waits.
        assert!(step(&mut m, Event::Lock).is_empty());
        assert!(step(&mut m, Event::Confirm).is_empty());
        let (_, job) = runs(step(
            &mut m,
            Event::Passphrase(WireSecret::new("pw".into())),
        ))
        .remove(0);
        assert!(matches!(
            job,
            Job::Mark {
                mark: Mark::Secret(_),
                sensitive: false,
                ..
            }
        ));

        let mut m = shown();
        step(&mut m, Event::Ask(mark_secret(false)));
        assert!(step(&mut m, Event::Cancel).is_empty());
        assert_eq!(m.pending, Pending::None);
        assert!(step(&mut m, Event::Confirm).is_empty());
    }

    /// Unmarking from an environment's keys lists its marked secrets: the
    /// ticked go in one job, with one passphrase, and none ticked goes
    /// nowhere.
    #[test]
    fn several_secrets_are_ticked_and_unmarked_with_one_passphrase() {
        let origin = |name: &str| Origin::new(Provider::AwsSm, name);
        let unmarks = || Unmarks {
            marked: ["acme/db", "acme/mail", "acme/push"]
                .into_iter()
                .map(|name| Marked {
                    secret: origin(name),
                    shared: None,
                })
                .collect(),
            unmark: vec![origin("acme/db")],
        };
        let ticked = |m: &Machine| match &m.pending {
            Pending::Unmarks(unmarks) => unmarks.unmark.clone(),
            other => panic!("{other:?}"),
        };
        let mut m = shown();
        assert!(step(&mut m, Event::Unmark(unmarks())).is_empty());
        assert_eq!(ticked(&m), [origin("acme/db")]);
        // One not on offer cannot be ticked; one ticked is unticked.
        for name in ["acme/push", "acme/other", "acme/db"] {
            assert!(step(&mut m, Event::Also(origin(name))).is_empty());
        }
        assert_eq!(ticked(&m), [origin("acme/push")]);
        step(&mut m, Event::Also(origin("acme/push")));
        assert!(step(&mut m, Event::Confirm).is_empty());
        assert!(ticked(&m).is_empty(), "nothing ticked, nothing asked");

        for name in ["acme/mail", "acme/db"] {
            step(&mut m, Event::Also(origin(name)));
        }
        // Nothing else while it waits.
        assert!(step(&mut m, Event::Unmark(unmarks())).is_empty());
        assert!(step(&mut m, Event::Confirm).is_empty());
        let both = vec![origin("acme/mail"), origin("acme/db")];
        assert_eq!(
            m.pending,
            Pending::Passphrase(Purpose::Unmark(both.clone()))
        );
        let (attempt, job) = runs(step(
            &mut m,
            Event::Passphrase(WireSecret::new("pw".into())),
        ))
        .remove(0);
        assert!(matches!(&job, Job::Unmark { secrets, .. } if *secrets == both));
        step(
            &mut m,
            Event::Answer {
                attempt,
                answer: Answer::Action(Ok(Done::Unmarked(2))),
                now: 0.0,
            },
        );
        assert!(
            matches!(&m.notice, Some(Notice::Done { message, .. }) if message == "Unmarked 2 secrets.")
        );

        let mut m = shown();
        step(&mut m, Event::Unmark(unmarks()));
        assert!(step(&mut m, Event::Cancel).is_empty());
        assert_eq!(m.pending, Pending::None);
    }

    /// Marking an environment that shares secrets with open ones shows
    /// them first; only those that would stay unmarked can be ticked, and
    /// the ticked go with the mark. Unmarking, and marking one that shares
    /// nothing with an open environment, do not.
    #[test]
    fn marking_an_env_that_shares_secrets_shows_them_first() {
        let shared = |env: &str, name: &str, open: &[&str], sensitive, production| SharedSecret {
            project: "widget".parse().unwrap(),
            env: env.parse().unwrap(),
            secret: Origin::new(Provider::AwsSm, name),
            prefix: false,
            with: vec!["widget.qa".parse().unwrap()],
            open: open.iter().map(|s| s.parse().unwrap()).collect(),
            sensitive,
            production,
        };
        let env = |env: &str, sensitive| Change::Mark {
            mark: Mark::Env {
                project: "widget".parse().unwrap(),
                env: env.parse().unwrap(),
                also: Vec::new(),
            },
            sensitive,
        };
        let origin = |name: &str| Origin::new(Provider::AwsSm, name);
        let mut m = shown();
        m.shared = vec![
            shared("dev", "mail", &["widget.qa"], false, false),
            shared("dev", "errors", &["widget.qa"], false, false),
            shared("dev", "acme/prod/db", &["widget.qa"], false, true),
            shared("dev", "sentry", &["widget.qa"], true, false),
            shared("dev", "ledger", &[], false, false),
            shared("rc", "ledger", &[], false, false),
        ];
        assert!(step(&mut m, Event::Ask(env("dev", true))).is_empty());
        let Pending::Sharing(sharing) = &m.pending else {
            panic!("{:?}", m.pending)
        };
        let names = |of: &[SharedSecret]| -> Vec<String> {
            of.iter().map(|s| s.secret.location.clone()).collect()
        };
        assert_eq!(names(&sharing.open), ["mail", "errors"]);
        assert_eq!(names(&sharing.production), ["acme/prod/db"]);

        for name in ["mail", "errors", "mail", "acme/prod/db", "sentry", "other"] {
            assert!(step(&mut m, Event::Also(origin(name))).is_empty());
        }
        assert!(step(&mut m, Event::Confirm).is_empty());
        assert_eq!(
            m.pending,
            Pending::Passphrase(Purpose::Mark {
                mark: Mark::Env {
                    project: "widget".parse().unwrap(),
                    env: "dev".parse().unwrap(),
                    also: vec![origin("errors")],
                },
                sensitive: true,
            })
        );
        assert!(step(&mut m, Event::Cancel).is_empty());

        step(&mut m, Event::Ask(env("dev", true)));
        assert!(step(&mut m, Event::Cancel).is_empty());
        assert_eq!(m.pending, Pending::None);

        step(&mut m, Event::Ask(env("rc", true)));
        assert!(
            matches!(m.pending, Pending::Passphrase(_)),
            "{:?}",
            m.pending
        );
        step(&mut m, Event::Cancel);
        step(&mut m, Event::Ask(env("dev", false)));
        assert!(
            matches!(m.pending, Pending::Confirm { .. }),
            "{:?}",
            m.pending
        );
    }

    /// Acknowledging an environment that reads marked secrets asks which
    /// to unmark first, none ticked; only those offered can be ticked, and
    /// the notice counts what was unmarked.
    #[test]
    fn acknowledging_offers_the_marked_secrets_it_reads() {
        let shared = |env: &str, name: &str, with: &[&str], open: &[&str], sensitive| {
            let sections = |names: &[&str]| names.iter().map(|s| s.parse().unwrap()).collect();
            SharedSecret {
                project: "widget".parse().unwrap(),
                env: env.parse().unwrap(),
                secret: Origin::new(Provider::AwsSm, name),
                prefix: false,
                with: sections(with),
                open: sections(open),
                sensitive,
                production: false,
            }
        };
        let ack = |env: &str, acknowledged| Change::Acknowledge {
            project: "widget".parse().unwrap(),
            env: env.parse().unwrap(),
            acknowledged,
        };
        let origin = |name: &str| Origin::new(Provider::AwsSm, name);
        let both: &[&str] = &["widget.dev", "widget.prod"];
        let mut m = shown();
        m.shared = vec![
            shared("rc", "mail", both, &["widget.dev"], true),
            shared("rc", "errors", both, &["widget.dev"], true),
            // Not marked; and marked, but read besides only by open ones.
            shared("rc", "flags", both, &["widget.dev"], false),
            shared("rc", "tools", &["widget.dev"], &["widget.dev"], true),
            shared("qa", "mail", both, &["widget.dev"], false),
        ];
        assert!(step(&mut m, Event::Ask(ack("rc", true))).is_empty());
        let Pending::Unmarking(unmarking) = &m.pending else {
            panic!("{:?}", m.pending)
        };
        let names: Vec<_> = unmarking.marked.iter().map(SharedSecret::name).collect();
        assert_eq!(names, ["aws_sm:mail", "aws_sm:errors"]);
        assert!(unmarking.unmark.is_empty());

        for name in ["mail", "errors", "mail", "flags", "tools"] {
            assert!(step(&mut m, Event::Also(origin(name))).is_empty());
        }
        assert!(step(&mut m, Event::Confirm).is_empty());
        assert_eq!(
            m.pending,
            Pending::Passphrase(Purpose::Acknowledge {
                project: "widget".parse().unwrap(),
                env: "rc".parse().unwrap(),
                acknowledged: true,
                unmark: vec![origin("errors")],
            })
        );
        let (attempt, job) = runs(step(&mut m, Event::Passphrase(pw()))).remove(0);
        assert!(matches!(
            &job,
            Job::Acknowledge { unmark, .. } if *unmark == [origin("errors")]
        ));
        answer(
            &mut m,
            attempt,
            Answer::Action(Ok(Done::Acknowledged {
                acknowledged: true,
                unmarked: 1,
            })),
        );
        assert!(matches!(
            &m.notice,
            Some(Notice::Done { message, .. })
                if message == "Acknowledged as not production. Unmarked 1 secret."
        ));

        // Nothing marked to offer, and taking one back: straight to the
        // passphrase.
        for change in [ack("qa", true), ack("rc", false)] {
            step(&mut m, Event::Ask(change));
            assert!(
                matches!(m.pending, Pending::Passphrase(_)),
                "{:?}",
                m.pending
            );
            step(&mut m, Event::Cancel);
        }
        step(&mut m, Event::Ask(ack("rc", true)));
        assert!(step(&mut m, Event::Cancel).is_empty());
        assert_eq!(m.pending, Pending::None);
    }

    /// Connecting Proton takes the token and the passphrase together, then
    /// asks about the providers again, as every change does once they were
    /// asked about.
    #[test]
    fn connecting_proton_and_acknowledging_take_the_passphrase() {
        let mut m = shown();
        let (asking, job) = runs(step(&mut m, Event::CheckProviders)).remove(0);
        assert_eq!(job, Job::Providers);
        assert!(
            step(&mut m, Event::CheckProviders).is_empty(),
            "one at a time"
        );
        // Asked about, every provider is being checked.
        assert!(m.checking(Provider::Proton) && m.checking(Provider::AwsSm));
        assert!(answer(&mut m, asking, Answer::Providers(Ok(Vec::new()))).is_empty());
        assert_eq!(m.providers.last, Some(Ok(Vec::new())));
        assert!(!m.checking(Provider::Proton));

        step(
            &mut m,
            Event::Ask(Change::ConnectProton { expires: Some(9) }),
        );
        // A passphrase alone does not connect.
        assert!(step(&mut m, Event::Passphrase(pw())).is_empty());
        let jobs = runs(step(
            &mut m,
            Event::ConnectProton {
                token: WireSecret::new("tok".into()),
                passphrase: pw(),
            },
        ));
        let [
            (
                attempt,
                Job::ConnectProton {
                    token,
                    expires: Some(9),
                    ..
                },
            ),
        ] = &jobs[..]
        else {
            panic!("{jobs:?}")
        };
        assert_eq!(token.expose(), "tok");
        // Saving a token checks it first: its provider alone is checked.
        assert!(m.checking(Provider::Proton) && !m.checking(Provider::AwsSm));
        let again = answer(
            &mut m,
            *attempt,
            Answer::Action(Ok(Done::ProtonConnected {
                vaults: 2,
                locked: false,
            })),
        );
        let Some((asking, _)) = again.iter().find(|(_, j)| *j == Job::Providers) else {
            panic!("{again:?}")
        };
        assert!(matches!(
            &m.notice,
            Some(Notice::Done { message, .. }) if message.contains("2 vaults")
        ));
        // Saved, it is asked about again with the others, and then done.
        assert!(m.checking(Provider::Proton) && m.checking(Provider::AwsSm));
        answer(&mut m, *asking, Answer::Providers(Ok(Vec::new())));
        assert!(!m.checking(Provider::Proton));

        let ack = Change::Acknowledge {
            project: "widget".parse().unwrap(),
            env: "prod".parse().unwrap(),
            acknowledged: true,
        };
        step(&mut m, Event::Ask(ack));
        assert!(matches!(
            m.pending,
            Pending::Passphrase(Purpose::Acknowledge { .. })
        ));
        let (attempt, job) = runs(step(&mut m, Event::Passphrase(pw()))).remove(0);
        assert!(matches!(
            job,
            Job::Acknowledge {
                acknowledged: true,
                ..
            }
        ));
        let after = answer(
            &mut m,
            attempt,
            Answer::Action(Ok(Done::Acknowledged {
                acknowledged: true,
                unmarked: 0,
            })),
        );
        assert!(matches!(
            &m.notice,
            Some(Notice::Done { message, .. }) if message.contains("not production")
        ));
        // Which environments still wait is asked at once.
        assert!(after.iter().any(|(_, j)| *j == Job::Probe), "{after:?}");

        // Several at once, under one passphrase.
        let envs: Vec<Section> = vec!["widget.prod".parse().unwrap(), "gadget.rc".parse().unwrap()];
        step(&mut m, Event::Ask(Change::AcknowledgeAll(envs.clone())));
        assert_eq!(
            m.pending,
            Pending::Passphrase(Purpose::AcknowledgeAll(envs.clone()))
        );
        let (_, job) = runs(step(&mut m, Event::Passphrase(pw()))).remove(0);
        assert!(matches!(
            job,
            Job::AcknowledgeAll { envs: sent, passphrase }
                if sent == envs && passphrase.expose() == "pw"
        ));
    }

    #[test]
    fn removing_a_source_is_made_at_once() {
        let mut m = shown();
        assert_eq!(
            edits(step(&mut m, Event::Ask(Change::Edit(remove())))),
            [remove()]
        );
        // Done: a notice, and the environment asked about again.
        let effects = step(
            &mut m,
            Event::Edited {
                edit: remove(),
                result: Ok(Vec::new()),
            },
        );
        assert!(matches!(runs(effects)[..], [(_, Job::Env { .. })]));
        assert!(matches!(m.notice, Some(Notice::Done { .. })));

        // A failure is shown.
        step(
            &mut m,
            Event::Edited {
                edit: remove(),
                result: Err(("not_found", Problem::new("no source 1"))),
            },
        );
        assert_eq!(m.notice, Some(Notice::Failed(Problem::new("no source 1"))));
    }

    #[test]
    fn unlocking_asks_for_the_passphrase_only_if_the_daemon_wants_it() {
        let mut m = shown();
        m.conn = Conn::Up { locked: true };
        let (a, job) = runs(step(&mut m, Event::Unlock(None))).remove(0);
        assert_eq!(job, Job::Unlock { passphrase: None });
        assert_eq!(m.pending, Pending::Running(a));
        // Busy: one change at a time.
        assert!(step(&mut m, Event::Resync("dev".parse().unwrap())).is_empty());
        step(
            &mut m,
            Event::Answer {
                attempt: a,
                answer: Answer::Action(Ok(Done::PassphraseRequired)),
                now: 0.0,
            },
        );
        assert_eq!(m.pending, Pending::Passphrase(Purpose::Unlock));
        let (b, job) = runs(step(
            &mut m,
            Event::Passphrase(WireSecret::new("pw".into())),
        ))
        .remove(0);
        assert_eq!(
            job,
            Job::Unlock {
                passphrase: Some(WireSecret::new("pw".into()))
            }
        );
        let effects = step(
            &mut m,
            Event::Answer {
                attempt: b,
                answer: Answer::Action(Ok(Done::LockState {
                    locked: false,
                    warnings: vec!["prod looks like production".into()],
                })),
                now: 0.0,
            },
        );
        assert_eq!(m.conn, Conn::Up { locked: false });
        assert_eq!(m.pending, Pending::None);
        assert!(matches!(runs(effects)[..], [(_, Job::Env { .. })]));
        let Some(Notice::Done { warnings, .. }) = &m.notice else {
            panic!("{:?}", m.notice)
        };
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn stale_action_answers_change_nothing_and_failures_show() {
        let mut m = shown();
        let (a, _) = runs(step(&mut m, Event::Lock)).remove(0);
        let stale = step(
            &mut m,
            Event::Answer {
                attempt: Attempt(a.0 + 100),
                answer: Answer::Action(Ok(Done::Marked {
                    what: "API_KEY".into(),
                    sensitive: true,
                })),
                now: 0.0,
            },
        );
        assert!(stale.is_empty());
        assert_eq!(m.pending, Pending::Running(a));
        step(
            &mut m,
            Event::Answer {
                attempt: a,
                answer: Answer::Action(Err(down())),
                now: 0.0,
            },
        );
        assert_eq!(m.pending, Pending::None);
        assert_eq!(m.conn, Conn::Down(down()));
        assert_eq!(m.notice, Some(Notice::Failed(down())));
        // A passphrase nothing asked for goes nowhere.
        assert!(step(&mut m, Event::Passphrase(WireSecret::new("pw".into()))).is_empty());
    }

    fn grant() -> Grant {
        Grant {
            node: "nBOT".into(),
            machine: "buildbot".into(),
            project: "widget".parse().unwrap(),
        }
    }

    const TOKEN: &str = "kbr_0123456789abcdef";

    /// Asks for a new token of the grant and answers with one.
    fn rotated(m: &mut Machine, replacing: bool) -> Vec<(Attempt, Job)> {
        let change = Change::RotateGrant {
            grant: grant(),
            replacing,
        };
        assert!(step(m, Event::Ask(change)).is_empty());
        if replacing {
            assert!(step(m, Event::Confirm).is_empty());
        }
        let (a, job) = runs(step(m, Event::Passphrase(pw()))).remove(0);
        assert_eq!(
            job,
            Job::RotateGrant {
                grant: grant(),
                passphrase: pw()
            }
        );
        let new = NewToken {
            grant: grant(),
            token: WireSecret::new(TOKEN.into()),
        };
        answer(m, a, Answer::Token(Ok(new)))
    }

    /// A grant with no token gets one with the passphrase alone; one that
    /// has a token is asked about first, as the new one ends it.
    #[test]
    fn a_new_token_takes_the_passphrase_and_ending_one_is_confirmed_first() {
        let mut m = shown();
        let change = |replacing| Change::RotateGrant {
            grant: grant(),
            replacing,
        };
        assert!(step(&mut m, Event::Ask(change(false))).is_empty());
        assert_eq!(
            m.pending,
            Pending::Passphrase(Purpose::RotateGrant(grant()))
        );
        assert!(step(&mut m, Event::Cancel).is_empty());

        assert!(step(&mut m, Event::Ask(change(true))).is_empty());
        let Pending::Confirm { question, .. } = &m.pending else {
            panic!("{:?}", m.pending)
        };
        assert!(
            question.contains("buildbot") && question.contains("widget"),
            "{question}"
        );
        assert!(question.contains("stops working"), "{question}");
        assert!(step(&mut m, Event::Cancel).is_empty());
        assert_eq!(m.pending, Pending::None);

        // The daemon is asked again at once: the grant has a token now.
        let after = rotated(&mut m, true);
        assert!(matches!(after[..], [(_, Job::Probe)]), "{after:?}");
        assert_eq!(m.pending, Pending::None);
        let held = m.token.as_ref().unwrap();
        assert_eq!((&held.grant, held.token.expose()), (&grant(), TOKEN));
        assert!(!format!("{m:?}").contains(TOKEN));
    }

    #[test]
    fn a_new_token_is_held_until_put_away_another_change_or_a_lock() {
        let mut m = shown();
        rotated(&mut m, false);
        step(&mut m, Event::Forget);
        assert_eq!(m.token, None);

        rotated(&mut m, false);
        step(&mut m, Event::Ask(mark_secret(true)));
        assert_eq!(m.token, None);
        step(&mut m, Event::Cancel);

        rotated(&mut m, false);
        let (a, _) = runs(step(&mut m, Event::Lock)).remove(0);
        let done = Done::LockState {
            locked: true,
            warnings: Vec::new(),
        };
        answer(&mut m, a, Answer::Action(Ok(done)));
        assert_eq!(m.token, None);

        // A wrong passphrase gives none, and says so.
        m.conn = Conn::Up { locked: false };
        step(
            &mut m,
            Event::Ask(Change::RotateGrant {
                grant: grant(),
                replacing: false,
            }),
        );
        let (a, _) = runs(step(&mut m, Event::Passphrase(pw()))).remove(0);
        // An answer to something else is not a token.
        let stale = Answer::Token(Ok(NewToken {
            grant: grant(),
            token: WireSecret::new(TOKEN.into()),
        }));
        assert!(answer(&mut m, Attempt(a.0 + 100), stale).is_empty());
        assert_eq!(m.token, None);
        let wrong = Problem::new("wrong passphrase");
        assert!(answer(&mut m, a, Answer::Token(Err(wrong.clone()))).is_empty());
        assert_eq!(m.token, None);
        assert_eq!(m.notice, Some(Notice::Failed(wrong)));
    }

    #[test]
    fn revoking_a_grant_is_confirmed_takes_the_passphrase_and_asks_what_is_left() {
        let mut m = shown();
        assert!(step(&mut m, Event::Ask(Change::RevokeGrant(grant()))).is_empty());
        let Pending::Confirm { question, .. } = &m.pending else {
            panic!("{:?}", m.pending)
        };
        assert!(
            question.starts_with("Revoke machine buildbot's grant for widget?"),
            "{question}"
        );
        assert!(step(&mut m, Event::Confirm).is_empty());
        assert_eq!(
            m.pending,
            Pending::Passphrase(Purpose::RevokeGrant(grant()))
        );
        let (a, job) = runs(step(&mut m, Event::Passphrase(pw()))).remove(0);
        assert_eq!(
            job,
            Job::RevokeGrant {
                grant: grant(),
                passphrase: pw()
            }
        );
        let after = answer(&mut m, a, Answer::Action(Ok(Done::GrantRevoked(grant()))));
        assert!(after.iter().any(|(_, job)| *job == Job::Probe), "{after:?}");
        assert!(matches!(
            &m.notice,
            Some(Notice::Done { message, .. })
                if message == "Revoked machine buildbot's grant for widget."
        ));
    }

    /// The endpoint and its grants are as the last probe said, and unknown
    /// once the daemon is down.
    #[test]
    fn a_probe_says_how_the_remote_endpoint_is() {
        let mut m = Machine::default();
        let (a, _) = runs(step(&mut m, Event::Due { now: 0.0 })).remove(0);
        let remote = RemoteStatus {
            enabled: Some(true),
            listening: Some("100.64.0.1:47317".into()),
            problem: None,
            grants: Vec::new(),
        };
        let probed = Probed {
            remote: Some(remote.clone()),
            ..Probed::locked(false)
        };
        answer(&mut m, a, Answer::Probe(Ok(probed)));
        assert_eq!(m.remote, Some(remote));
        let (a, _) = runs(step(&mut m, Event::Due { now: PROBE_EVERY })).remove(0);
        answer(&mut m, a, Answer::Probe(Err(down())));
        assert_eq!(m.remote, None);
    }

    const PAGE: &str = "https://self.example.ts.net:47318";

    fn pocket() -> PhoneChoice {
        PhoneChoice {
            name: "pocket".into(),
            node: "nPOCKET".into(),
            os: "iOS".into(),
        }
    }

    /// What a probe says of the phone: pocket paired at `paired` if at
    /// all, pairing going on or not, and the last answer given on it.
    fn phone(paired: Option<u64>, pairing: bool, last: Option<(u64, bool)>) -> Box<PhoneStatus> {
        use kagebunshin::ipc::protocol::{PhoneAnswer, PhonePairingView, PhoneView};
        Box::new(PhoneStatus {
            paired: paired.map(|paired| PhoneView {
                name: "pocket".into(),
                node: "nPOCKET".into(),
                paired,
                seen: None,
            }),
            url: Some(PAGE.into()),
            problem: None,
            pairing: pairing.then(|| PhonePairingView {
                name: "pocket".into(),
                left: 500,
            }),
            last: last.map(|(id, approved)| PhoneAnswer {
                id,
                project: "widget".parse().unwrap(),
                env: "dev".parse().unwrap(),
                approved,
                time: 1_795_100_000,
            }),
        })
    }

    /// Probes, if no probe is on its way, and answers it at `now`.
    fn hears(m: &mut Machine, now: f64, probed: Result<Probed, Problem>) {
        let a = match m.probe {
            Probe::Asking(a) => a,
            Probe::Waiting { .. } => runs(step(m, Event::Probe)).remove(0).0,
        };
        step(
            m,
            Event::Answer {
                attempt: a,
                answer: Answer::Probe(probed),
                now,
            },
        );
    }

    /// A probe at `now` that says `phone` of the phone, unlocked.
    fn sees(m: &mut Machine, now: f64, phone: Option<Box<PhoneStatus>>) {
        let probed = Probed {
            phone,
            ..Probed::locked(false)
        };
        hears(m, now, Ok(probed));
    }

    /// Asks to pair pocket and gives the passphrase; the daemon lets it in.
    fn pairing(m: &mut Machine) {
        assert!(step(m, Event::Ask(Change::PairPhone(pocket()))).is_empty());
        assert_eq!(m.pending, Pending::Passphrase(Purpose::PairPhone(pocket())));
        let (a, job) = runs(step(m, Event::Passphrase(pw()))).remove(0);
        assert_eq!(
            job,
            Job::PairPhone {
                phone: pocket(),
                passphrase: pw()
            }
        );
        let way_in = Pairing {
            phone: pocket(),
            url: PAGE.into(),
        };
        let after = answer(m, a, Answer::Pairing(Ok(way_in.clone())));
        assert!(matches!(after[..], [(_, Job::Probe)]), "{after:?}");
        assert_eq!(m.pending, Pending::None);
        assert_eq!(m.pairing, Some(way_in));
    }

    fn notice(m: &Machine) -> Option<&str> {
        match &m.notice {
            Some(Notice::Done { message, .. }) => Some(message),
            Some(Notice::Failed(p)) => Some(&p.message),
            None => None,
        }
    }

    /// Pairing takes the passphrase with no question first: the phone
    /// paired before stays until the new one has made its key. From there
    /// the daemon is asked every second, and the window says so when the
    /// phone is in.
    #[test]
    fn a_phone_being_paired_is_probed_for_every_second_until_it_is_in() {
        let mut m = shown();
        pairing(&mut m);
        sees(&mut m, 10.0, Some(phone(None, true, None)));
        assert_eq!(
            m.probe,
            Probe::Waiting {
                due: 10.0 + PAIRING_PROBE_EVERY
            }
        );
        assert!(m.pairing.is_some());
        assert_eq!(notice(&m), None);

        sees(&mut m, 11.0, Some(phone(Some(100), false, None)));
        assert_eq!(m.pairing, None);
        assert_eq!(notice(&m), Some("Paired pocket: it approves requests now."));
        assert_eq!(
            m.probe,
            Probe::Waiting {
                due: 11.0 + PROBE_EVERY
            }
        );

        // The same phone again: paired anew, at another time.
        pairing(&mut m);
        sees(&mut m, 20.0, Some(phone(Some(100), true, None)));
        assert_eq!(notice(&m), None);
        sees(&mut m, 21.0, Some(phone(Some(120), false, None)));
        assert_eq!(notice(&m), Some("Paired pocket: it approves requests now."));
    }

    /// Its time ran out: no phone is paired, or the one paired before
    /// still is.
    #[test]
    fn a_pairing_that_runs_out_says_so() {
        for before in [None, Some(100)] {
            let mut m = shown();
            sees(&mut m, 0.0, Some(phone(before, false, None)));
            pairing(&mut m);
            sees(&mut m, 1.0, Some(phone(before, true, None)));
            sees(&mut m, 2.0, Some(phone(before, false, None)));
            assert_eq!(m.pairing, None);
            assert_eq!(
                notice(&m),
                Some("pocket was not paired: its time to make a key is up. Pair it again.")
            );
        }
        // And so when no phone is spoken of at all.
        let mut m = shown();
        pairing(&mut m);
        sees(&mut m, 1.0, None);
        assert_eq!(m.pairing, None);
        assert!(matches!(m.notice, Some(Notice::Failed(_))));
    }

    /// The daemon keeps the passphrase while a pairing lasts, so the
    /// window ends it when it stops showing the way in. A lock ended it
    /// already, and a daemon that is down has none.
    #[test]
    fn a_pairing_ends_when_put_away_and_is_dropped_by_a_lock() {
        let mut m = shown();
        pairing(&mut m);
        let (a, job) = runs(step(&mut m, Event::Forget)).remove(0);
        assert_eq!(job, Job::StopPairing);
        assert_eq!(m.pairing, None);
        // Nothing waits for its answer, and nothing is said of it.
        assert!(answer(&mut m, a, Answer::Action(Ok(Done::PairingStopped))).is_empty());
        assert_eq!(notice(&m), None);
        // Nothing to end.
        assert!(step(&mut m, Event::Forget).is_empty());

        pairing(&mut m);
        hears(&mut m, 1.0, Ok(Probed::locked(true)));
        assert_eq!(m.pairing, None);
        assert_eq!(notice(&m), None);
        assert_eq!(
            m.probe,
            Probe::Waiting {
                due: 1.0 + PROBE_EVERY
            }
        );

        m.conn = Conn::Up { locked: false };
        pairing(&mut m);
        hears(&mut m, 2.0, Err(down()));
        assert_eq!(m.pairing, None);
        assert_eq!(m.phone, None);
    }

    #[test]
    fn a_pairing_refused_says_why_and_a_stale_answer_starts_none() {
        let mut m = shown();
        step(&mut m, Event::Ask(Change::PairPhone(pocket())));
        let (a, _) = runs(step(&mut m, Event::Passphrase(pw()))).remove(0);
        let way_in = Answer::Pairing(Ok(Pairing {
            phone: pocket(),
            url: PAGE.into(),
        }));
        assert!(answer(&mut m, Attempt(a.0 + 100), way_in).is_empty());
        assert_eq!(m.pairing, None);
        let wrong = Problem::new("wrong passphrase");
        assert!(answer(&mut m, a, Answer::Pairing(Err(wrong.clone()))).is_empty());
        assert_eq!(m.pairing, None);
        assert_eq!(m.pending, Pending::None);
        assert_eq!(m.notice, Some(Notice::Failed(wrong)));
    }

    /// The prompt for a request answered on the phone closes here without
    /// a word, so the next probe says where it was answered. What was
    /// answered before the window looked is not news.
    #[test]
    fn a_request_answered_on_the_phone_is_said_here() {
        let mut m = shown();
        sees(&mut m, 0.0, Some(phone(Some(100), false, Some((6, true)))));
        assert_eq!(notice(&m), None);
        sees(&mut m, 5.0, Some(phone(Some(100), false, Some((7, true)))));
        assert_eq!(notice(&m), Some("Approved on pocket: widget/dev."));
        m.notice = None;
        sees(&mut m, 10.0, Some(phone(Some(100), false, Some((7, true)))));
        assert_eq!(notice(&m), None);
        sees(
            &mut m,
            15.0,
            Some(phone(Some(100), false, Some((8, false)))),
        );
        assert_eq!(notice(&m), Some("Denied on pocket: widget/dev."));
    }

    #[test]
    fn removing_the_phone_is_confirmed_takes_the_passphrase_and_asks_what_is_left() {
        let mut m = shown();
        let remove = Change::UnpairPhone("pocket".into());
        assert!(step(&mut m, Event::Ask(remove)).is_empty());
        let Pending::Confirm { question, .. } = &m.pending else {
            panic!("{:?}", m.pending)
        };
        assert!(question.starts_with("Remove pocket?"), "{question}");
        assert!(step(&mut m, Event::Confirm).is_empty());
        assert_eq!(
            m.pending,
            Pending::Passphrase(Purpose::UnpairPhone("pocket".into()))
        );
        let (a, job) = runs(step(&mut m, Event::Passphrase(pw()))).remove(0);
        assert_eq!(
            job,
            Job::UnpairPhone {
                name: "pocket".into(),
                passphrase: pw()
            }
        );
        let gone = Done::PhoneUnpaired("pocket".into());
        let after = answer(&mut m, a, Answer::Action(Ok(gone)));
        assert!(after.iter().any(|(_, job)| *job == Job::Probe), "{after:?}");
        assert_eq!(
            notice(&m),
            Some("Removed pocket: requests are approved at this computer only.")
        );
    }

    /// Which phones could be paired is asked once at a time, again on
    /// Refresh, and the last answer stays on show meanwhile.
    #[test]
    fn the_phones_that_could_be_paired_are_asked_for_and_again_on_refresh() {
        let mut m = shown();
        assert!(
            !runs(step(&mut m, Event::Refresh))
                .iter()
                .any(|(_, job)| *job == Job::Phones)
        );
        let (a, job) = runs(step(&mut m, Event::CheckPhones)).remove(0);
        assert_eq!(job, Job::Phones);
        assert!(step(&mut m, Event::CheckPhones).is_empty());
        let found = Ok(vec![pocket()]);
        assert!(answer(&mut m, Attempt(a.0 + 100), Answer::Phones(found.clone())).is_empty());
        assert_eq!(m.phones.last, None);
        answer(&mut m, a, Answer::Phones(found.clone()));
        assert_eq!(m.phones.last, Some(found.clone()));

        let again = runs(step(&mut m, Event::Refresh));
        let (a, _) = again
            .into_iter()
            .find(|(_, job)| *job == Job::Phones)
            .unwrap();
        assert_eq!(m.phones.last, Some(found));
        answer(&mut m, a, Answer::Phones(Err(down())));
        assert!(matches!(m.conn, Conn::Down(_)));
        assert_eq!(m.phones.last, Some(Err(down())));
    }
}
