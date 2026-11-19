//! Messages exchanged over the socket.
//!
//! The daemon, CLI and app ship together, so there is no protocol versioning.
//! The first message on every connection is `Hello` with the client's build
//! id; a mismatch (typically an old daemon still running after an upgrade) is
//! refused with a clear error instead of failing on a schema difference.
//!
//! Only two replies carry secret values: `run_env`, for the process `run`
//! starts, and `value`, for `get` and `reveal`. Status, diff, sync and store replies carry
//! key names and origins only. Values travel as a [`WireSecret`]: zeroed on
//! drop and never shown by `Debug`. From the CLI to the daemon they are a
//! passphrase, or the value `store set` writes.

use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

use crate::config::{Place, RemoteId};
use crate::secret::SecretValue;
use crate::source::aws_sm::AwsSettings;
use crate::source::{Listed, ProviderStatus};
use crate::store::{Change, Passphrase, Section};
use crate::sys::ProcStart;
use crate::types::{EnvName, KeyName, Origin, ProjectName, Provider};

/// Release builds set `KAGEBUNSHIN_BUILD_ID` (e.g. version plus commit);
/// local builds fall back to the crate version.
pub const BUILD_ID: &str = match option_env!("KAGEBUNSHIN_BUILD_ID") {
    Some(id) => id,
    None => env!("CARGO_PKG_VERSION"),
};

#[derive(Debug, Serialize, Deserialize)]
pub struct RequestFrame {
    pub id: u64,
    pub body: Request,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Hello {
        build: String,
    },
    Ping,
    Whoami,
    /// Lock state, plus where each key of the caller's environment comes
    /// from when `facts` is given and the daemon is unlocked.
    Status {
        facts: Option<Facts>,
    },
    /// Keys missing from or extra to `.env.example`, and keys set twice.
    Diff {
        facts: Facts,
    },
    /// `project apply`: resolves every environment of the project file
    /// `text`, as project `project`, without installing it or caching
    /// anything, and reports names and origins only. `example_keys` are
    /// those of the `.env.example` to compare against, if any. Reads
    /// values, so it is always recorded in the audit log.
    CheckProject {
        project: ProjectName,
        text: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        example_keys: Option<Vec<KeyName>>,
        /// Those of `example_keys` the file gives a value; see
        /// [`Facts::example_values`].
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        example_values: Vec<KeyName>,
    },
    /// Drops cached values and fetches them again: for one environment of
    /// `project` (its default when `env` is not given), or, without
    /// `project`, for every cached environment.
    Sync {
        project: Option<ProjectName>,
        env: Option<EnvName>,
    },
    Lock,
    /// Unlocks. If a local store exists the daemon decrypts it, and without
    /// a passphrase replies `passphrase_required`.
    Unlock {
        #[serde(default)]
        passphrase: Option<WireSecret>,
    },
    /// Sets one key, after decrypting the store with `passphrase`.
    StoreSet {
        section: Section,
        key: KeyName,
        value: WireSecret,
        passphrase: WireSecret,
        /// Also mark the key sensitive. False keeps any existing mark.
        #[serde(default)]
        sensitive: bool,
    },
    /// Sets several keys, of one section or of several, in one write, after
    /// decrypting the store with `passphrase`: `onboard` putting every
    /// `.env` in, with the store's key derived once. All or none.
    StoreSetMany {
        sections: Vec<(Section, Vec<(KeyName, WireSecret)>)>,
        passphrase: WireSecret,
    },
    /// `onboard`: the values of env files into the store, in one write as
    /// `StoreSetMany` does, all or none. With `passphrase`, typed at a
    /// terminal, it is written at once. Without one it waits until a
    /// person approves it in the app (see [`Request::Approve`]), which
    /// shows every file, section and key name, and is written with the
    /// passphrase typed there; if the daemon is locked, that unlocks it
    /// too. Refused at once if the app is not open.
    StoreImport {
        sections: Vec<ImportSection>,
        #[serde(default)]
        passphrase: Option<WireSecret>,
        /// Where the caller says it runs, and its command line: for the
        /// prompt only. Claims, not facts.
        cwd: PathBuf,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        command: Vec<String>,
    },
    /// `store set` with no terminal to type at: asks a person to type the
    /// values of `keys` of `section` into the app, which writes them with
    /// the passphrase typed there too (see [`Request::Approve`]); if the
    /// daemon is locked, that unlocks it. The caller sends no value and
    /// learns none: the reply names the keys that were set. Refused at
    /// once if the app is not open.
    StoreAsk {
        section: Section,
        keys: Vec<KeyName>,
        /// Where the caller says it runs, and its command line: for the
        /// prompt only. Claims, not facts.
        cwd: PathBuf,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        command: Vec<String>,
    },
    /// Marks one key sensitive, or with `sensitive` false removes the mark,
    /// after decrypting the store with `passphrase`.
    StoreMark {
        section: Section,
        key: KeyName,
        sensitive: bool,
        passphrase: WireSecret,
    },
    /// Marks an environment sensitive, or with `sensitive` false removes the
    /// mark, after decrypting the store with `passphrase`.
    ///
    /// Marking also marks what the environment's sources read, except a
    /// secret that an open environment reads too (see [`SharedSecret`]);
    /// `also` names those to mark all the same.
    MarkEnv {
        project: ProjectName,
        env: EnvName,
        sensitive: bool,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        also: Vec<Origin>,
        passphrase: WireSecret,
    },
    /// Acknowledges an environment that looks like production as not
    /// production, which stops the warning and marks nothing, or with
    /// `acknowledged` false takes that back, after decrypting the store with
    /// `passphrase`.
    ///
    /// A secret it reads that is marked sensitive stays marked, so its
    /// keys still ask for approval there: `unmark` names those to unmark
    /// in the same write, as [`Self::MarkSecret`] would. All or none.
    AcknowledgeEnv {
        project: ProjectName,
        env: EnvName,
        acknowledged: bool,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        unmark: Vec<Origin>,
        passphrase: WireSecret,
    },
    /// Acknowledges several environments as not production at once, with
    /// one passphrase: one store write, all or none.
    AcknowledgeEnvs {
        envs: Vec<Section>,
        passphrase: WireSecret,
    },
    /// Marks a secret of any provider but `file` sensitive, by where it is
    /// read from, or with `sensitive` false removes the mark, after
    /// decrypting the store with `passphrase`.
    MarkSecret {
        secret: Origin,
        sensitive: bool,
        passphrase: WireSecret,
    },
    /// Removes the marks of several secrets at once, each as
    /// [`Self::MarkSecret`] would, with one passphrase: one store write,
    /// all or none.
    UnmarkSecrets {
        secrets: Vec<Origin>,
        passphrase: WireSecret,
    },
    /// Adds a sensitive mark with no passphrase, while the daemon is
    /// unlocked: what an agent may do, since a mark only tightens. It
    /// holds at once; the store file gets it at the next write that has
    /// the passphrase. Nothing here removes a mark or acknowledges an
    /// environment: those take [`Request::MarkEnv`] and its like.
    AddMark {
        target: MarkTarget,
    },
    StoreUnset {
        section: Section,
        key: KeyName,
        passphrase: WireSecret,
    },
    /// Removes every section of `project` from the store, with its keys'
    /// marks: what `project remove` left there.
    StoreClear {
        project: ProjectName,
        passphrase: WireSecret,
    },
    /// The names and stable ids a provider can read, never values: one
    /// provider's under `prefix`, or, without `provider`, those of every
    /// provider the daemon can reach now. `search` keeps only names or keys
    /// that contain it, ignoring case. `aws` overrides `[aws]` in
    /// `config.toml` for the AWS provider. With `keys`, the daemon also
    /// reads each AWS secret listed to learn its key names (or that it is
    /// a plain string), keeps only the names, and records the lookup in
    /// the audit log; secrets marked sensitive or that look like
    /// production are not read.
    List {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        provider: Option<Provider>,
        #[serde(default)]
        prefix: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        search: Option<String>,
        #[serde(default)]
        aws: AwsSettings,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        keys: bool,
    },
    /// Whether each provider in play can read now: those the caller's
    /// environment uses (with `facts`), and those connected. With `every`
    /// and no `facts`, those any project's environment uses too, for a
    /// caller that shows the machine and no one project.
    Providers {
        facts: Option<Facts>,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        every: bool,
    },
    /// `connect proton`: once `passphrase` opens the store, logs `pass-cli`
    /// in with `token` in a staging session, swaps it in, and saves the
    /// token, replacing any earlier one. A wrong passphrase, a refused
    /// token or a failed swap or save changes neither the saved token nor
    /// the session.
    /// `expires` is when it stops working, in Unix seconds.
    ProtonConnect {
        token: WireSecret,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires: Option<u64>,
        passphrase: WireSecret,
    },
    /// Re-encrypts the store with `new_passphrase`.
    StorePasswd {
        passphrase: WireSecret,
        new_passphrase: WireSecret,
    },
    /// Section and key names of the unlocked store.
    StoreList,
    /// The values `run` puts into its child's environment. One that needs a
    /// value marked sensitive waits until a person approves it in the app
    /// (see [`Request::Approve`]), for at most [`APPROVAL_TIMEOUT`].
    RunEnv {
        facts: Facts,
        /// The program `run` starts, without its arguments, for the audit
        /// log. The caller names it, so it is a claim, not a fact.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        program: Option<String>,
        /// The whole command line, shown in an approval prompt only and
        /// never recorded. A claim too.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        command: Vec<String>,
    },
    /// `run --strict` ran `program` with the environment `facts` name and it
    /// exited 0: the daemon keeps that as the environment's proof until its
    /// sources or settings change. A claim of the caller, like `program`.
    Proven {
        facts: Facts,
        program: String,
    },
    /// One value, for a human: the store passphrase shows one is asking.
    /// A value marked sensitive also waits for approval in the app, as
    /// `run_env`.
    Get {
        facts: Facts,
        key: KeyName,
        passphrase: WireSecret,
    },
    /// What `status` shows, for a human, of an environment marked
    /// sensitive too: the app's view of one. Key names and origins only.
    Inspect {
        facts: Facts,
        passphrase: WireSecret,
    },
    /// One value for a human, as `get`, but a sensitive one too: the app's
    /// reveal.
    Reveal {
        facts: Facts,
        key: KeyName,
        passphrase: WireSecret,
    },
    /// The app: the requests waiting for approval, once they differ from
    /// the ids in `known`, or after [`APPROVAL_POLL`] at the latest. While
    /// one of these waits, or for a few seconds after, the daemon counts
    /// the app as open; otherwise a request that needs approval is refused.
    WaitApprovals {
        #[serde(default)]
        known: Vec<u64>,
    },
    /// The app: approves request `id` with the store passphrase, which a
    /// person types in the app, or without one denies it. One approval
    /// covers that one request. A wrong passphrase leaves it waiting.
    ///
    /// `values` answer a request that asks for them
    /// ([`ApprovalReason::Type`]): what the person typed for some or all of
    /// its keys, at least one. Any other request takes none.
    Approve {
        id: u64,
        #[serde(default)]
        passphrase: Option<WireSecret>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        values: Vec<(KeyName, WireSecret)>,
    },
    /// Turns the remote endpoint on or off, after decrypting the store with
    /// `passphrase`. Local callers only.
    RemoteEnable {
        enabled: bool,
        passphrase: WireSecret,
    },
    /// Lets `machine`, a peer on this tailnet, use `project`'s `envs`
    /// remotely until `expires` (Unix seconds), replacing any earlier grant
    /// to that machine for that project and its token, after decrypting the
    /// store with `passphrase`. The reply carries the grant's new token.
    /// Local callers only.
    RemoteGrant {
        machine: String,
        project: ProjectName,
        envs: Vec<EnvName>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires: Option<u64>,
        passphrase: WireSecret,
    },
    /// Removes the grants to `machine`: the one for `project`, or every
    /// one. Local callers only.
    RemoteRevoke {
        machine: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        project: Option<ProjectName>,
        passphrase: WireSecret,
    },
    /// Gives the grant to `machine` (its name or node id) for `project` a
    /// new token, ending the one it had, after decrypting the store with
    /// `passphrase`. The reply carries the new token. Local callers only.
    RemoteRotate {
        machine: String,
        project: ProjectName,
        passphrase: WireSecret,
    },
    /// The phones on this tailnet, to pick the one to pair from. Local
    /// callers only.
    Phones,
    /// Starts pairing `machine`, a phone on this tailnet (its name or node
    /// id), after decrypting the store with `passphrase`: for
    /// [`PHONE_PAIRING`] the approval page lets that phone make the passkey
    /// it will approve requests with, and the daemon keeps the passphrase
    /// to save it with. Replaces a pairing already going; the phone paired
    /// before stays paired until the new one has made its passkey. Local
    /// callers only.
    PhonePair {
        machine: String,
        passphrase: WireSecret,
    },
    /// Ends a pairing that has not finished, and forgets its passphrase.
    /// Local callers only.
    PhonePairStop,
    /// Removes the paired phone, after decrypting the store with
    /// `passphrase`. Local callers only.
    PhoneUnpair {
        passphrase: WireSecret,
    },
}

/// How long a phone has to make its passkey once pairing starts.
pub const PHONE_PAIRING: std::time::Duration = std::time::Duration::from_mins(10);

/// One section of [`Request::StoreImport`]: the values of `files`, in file
/// order, so a later one's value for a key is the one kept.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportSection {
    pub section: Section,
    pub values: Vec<(KeyName, WireSecret)>,
    /// The files the values are from, as the caller names them.
    pub files: Vec<PathBuf>,
    pub into: ImportInto,
    /// Leave the section as it is when it already has keys.
    #[serde(default)]
    pub if_empty: bool,
}

/// What the caller makes of a section it imports into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportInto {
    /// A new project, with this environment.
    NewProject,
    /// A new environment of a project that exists.
    NewEnv,
    /// An environment that exists and reads the local store.
    Existing,
}

/// What an import would write, as an approval prompt shows it: names,
/// never values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportNames {
    pub section: Section,
    pub files: Vec<PathBuf>,
    /// In file order, each once.
    pub keys: Vec<KeyName>,
    pub into: ImportInto,
    /// Those of `keys` the section has a value for now, which this
    /// replaces. Not known while the daemon is locked.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub replaces: Vec<KeyName>,
    /// The section is left as it is if it already has keys, which the
    /// locked daemon cannot see.
    #[serde(default)]
    pub if_empty: bool,
}

/// What became of one section of an import.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportedSection {
    pub section: Section,
    /// False when it already had keys and was to be left then.
    pub written: bool,
    /// The keys written that had a value before.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub replaced: Vec<KeyName>,
}

/// How long a request that needs approval waits for it at most, whatever
/// `approval_timeout` in `config.toml` says; then it is denied. A client
/// waits this long for its reply, as it cannot know the setting.
pub const APPROVAL_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(30);

/// How long [`Request::WaitApprovals`] waits for a change.
pub const APPROVAL_POLL: std::time::Duration = std::time::Duration::from_secs(25);

/// A request waiting for a person to approve it in the app: names, never
/// values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalPrompt {
    pub id: u64,
    pub project: ProjectName,
    pub env: EnvName,
    /// The keys it would hand out that are refused, in key order: those
    /// marked sensitive, or for an environment refused as a whole (see
    /// `reason`) every key it asks for, set or not.
    pub keys: Vec<KeyName>,
    /// Why it waits. An older daemon sends none: read as `Keys`.
    #[serde(default)]
    pub reason: ApprovalReason,
    /// The command line `run` starts, as the caller gave it, or
    /// `kagebunshin get KEY`.
    pub command: String,
    /// The same, argument by argument; none when the caller named no
    /// command, or from an older daemon.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub argv: Vec<String>,
    /// The caller, from kernel peer credentials, and the folder it says
    /// it runs in.
    pub pid: i32,
    pub cwd: PathBuf,
    /// The names of the processes the caller descends from, nearest first:
    /// the shell that ran `kagebunshin`, then what started that. What the
    /// kernel says they are called, which a process chooses; none for a
    /// caller on another machine.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parents: Vec<String>,
    /// Seconds until it is denied unanswered, counted when this was sent.
    /// An older daemon sends none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub left: Option<u64>,
    /// A caller on another machine, as tailscaled identified it. Its
    /// `command` and `cwd` are what it reported; nothing here checks them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<RemotePeer>,
    /// For the reason `Keys`: the secrets marked sensitive that `keys` are
    /// read from, in order. The environment itself is not marked.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<Origin>,
    /// For an environment refused as a whole: the checkout has no
    /// `.env.example`, so the command gets every key the environment sets,
    /// not a list of them. `keys` are then all of them, as far as the
    /// daemon knows without reading: none for a marked environment it does
    /// not hold. Where it names them, no other key is handed out.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub every_key: bool,
}

/// Why a request waits for approval.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ApprovalReason {
    /// Keys it would hand out come from values marked sensitive.
    #[default]
    Keys,
    /// A human marked the environment sensitive.
    Marked,
    /// The environment looks like production, for this reason, and waits
    /// for a human decision.
    Waiting { why: String },
    /// Not a request for values: `onboard` asks to write these into the
    /// local store. With `unlock` the daemon is locked, and approving
    /// unlocks it too. The prompt's `project` and `env` are the first
    /// section's, and it has no `keys` of its own.
    Import {
        sections: Vec<ImportNames>,
        #[serde(default)]
        unlock: bool,
    },
    /// Not a request for values either: `store set`, run with no terminal,
    /// asks a person to type the values of the prompt's `keys` into its
    /// `project` and `env`'s section of the local store. `replaces` are
    /// those that have a value now, not known while the daemon is locked.
    /// With `unlock` the daemon is locked, and approving unlocks it too.
    Type {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        replaces: Vec<KeyName>,
        #[serde(default)]
        unlock: bool,
    },
}

/// A passphrase or value on the socket. Zeroed on drop and never shown by
/// `Debug`; serializable only so it can cross the socket.
#[derive(PartialEq, Eq)]
pub struct WireSecret(Zeroizing<String>);

impl WireSecret {
    /// Takes ownership of `s` without copying it.
    pub fn new(s: String) -> Self {
        Self(Zeroizing::new(s))
    }

    pub fn into_passphrase(mut self) -> Passphrase {
        Passphrase::new(std::mem::take(&mut *self.0))
    }

    pub fn into_value(mut self) -> SecretValue {
        SecretValue::new(std::mem::take(&mut *self.0))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for WireSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WireSecret(<redacted>)")
    }
}

impl Serialize for WireSecret {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for WireSecret {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d).map(Self::new)
    }
}

/// What the CLI found about where it runs. The daemon picks a project from
/// the remotes, `subdir` and `project` (see [`crate::config::Registry::find`])
/// and never reads the checkout itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Facts {
    pub cwd: PathBuf,
    /// The checkout's network remotes, normalized.
    pub remotes: Vec<RemoteId>,
    /// `cwd` relative to the checkout root, as the CLI worked it out; absent
    /// at the root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subdir: Option<PathBuf>,
    /// The checkout root, as git printed it, so a project's `path` is
    /// matched as it resolves on disk ([`crate::config::Place::root`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<PathBuf>,
    /// `--project`, or the project the app shows: that one, if it claims
    /// one of `remotes`, whatever `subdir` is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<ProjectName>,
    /// `--env`; the project's default environment when absent.
    pub env: Option<EnvName>,
    /// The keys `.env.example` lists, or `None` when there is no such file.
    pub example_keys: Option<Vec<KeyName>>,
    /// The keys `.env.example` gives a value, by name only: the CLI
    /// suggests `project set-var` for those, so a `store set` fix leaves
    /// them out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub example_values: Vec<KeyName>,
    /// The name of an env file here that has values, such as `.env`:
    /// `onboard` moves them in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_file: Option<String>,
}

impl Facts {
    /// Where these facts place a request, for [`crate::config::Registry::find`].
    pub fn place(&self) -> Place<'_> {
        Place {
            remotes: &self.remotes,
            subdir: self.subdir.as_deref(),
            root: self.root.as_deref(),
            project: self.project.as_ref(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResponseFrame {
    /// Echoes the request id; 0 when the request could not be parsed.
    pub id: u64,
    pub body: Response,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Response {
    Hello {
        build: String,
    },
    Pong,
    Whoami(Caller),
    Status(StatusReport),
    Diff(DiffReport),
    /// The reply to `check_project`.
    Checked(ProjectCheck),
    Sync(SyncReport),
    /// The reply to `lock` and `unlock`. `unlock` warns about environments
    /// that look like production but are not marked sensitive.
    LockState {
        locked: bool,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        warnings: Vec<String>,
    },
    /// The reply to `proven`.
    Proven,
    /// The reply to a store write, and whether the daemon is now locked.
    Store {
        change: Change,
        locked: bool,
    },
    /// The reply to `remote_grant` and `remote_rotate`: the grant to
    /// `machine` was saved with a new `token`, which is said here and never
    /// again, as the store keeps only its hash.
    RemoteGranted {
        change: Change,
        locked: bool,
        machine: String,
        token: WireSecret,
    },
    /// The reply to `phones`.
    Phones {
        phones: Vec<PhoneChoice>,
    },
    /// The reply to `phone_pair`: the phone `name` may make its passkey on
    /// the approval page at `url` for the next `seconds`.
    PhonePairing {
        name: String,
        url: String,
        seconds: u64,
    },
    /// The reply to `phone_pair_stop`.
    PhonePairStopped,
    /// The reply to `store_ask`: the keys of `section` a person typed a
    /// value for, in the order asked, those of them that had one before,
    /// and the keys asked for that they left empty, which are as they were.
    StoreTyped {
        section: Section,
        set: Vec<KeyName>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        replaced: Vec<KeyName>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        left: Vec<KeyName>,
        locked: bool,
    },
    /// The reply to `store_import`: each section, in the order asked.
    Imported {
        sections: Vec<ImportedSection>,
        locked: bool,
    },
    /// The reply to `connect proton`: the token was saved, and the session
    /// it logged in is now the one `pass-cli` uses. `vaults` is how many
    /// vaults it reads.
    ProtonConnected {
        change: Change,
        locked: bool,
        vaults: usize,
    },
    StoreList(StoreListing),
    /// The reply to `list`: names and ids, never values. `warnings` says
    /// which providers could not be listed when no one provider was asked.
    Listed {
        items: Vec<Listed>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        warnings: Vec<String>,
        /// With `keys`: the secrets whose values the daemon read to learn
        /// their key names, in name order, matched by `search` or not.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        read: Vec<String>,
    },
    Providers {
        providers: Vec<ProviderStatus>,
    },
    RunEnv(RunEnvReply),
    /// The reply to `get` and `reveal`.
    Value {
        value: WireSecret,
    },
    /// The reply to `wait_approvals` and `approve`: the requests waiting
    /// for approval, oldest first.
    Approvals {
        pending: Vec<ApprovalPrompt>,
    },
    Error(WireError),
}

/// What `run` injects. With a `.env.example`, only the keys it lists;
/// without one, every key the environment resolves to.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunEnvReply {
    pub project: ProjectName,
    pub env: EnvName,
    /// In key order.
    pub vars: Vec<WireVar>,
    /// Listed in `.env.example` but set by no source and no plain setting,
    /// in file order.
    pub missing: Vec<KeyName>,
    pub warnings: Vec<String>,
    /// `masking.min_len`: shorter values are not masked in piped output.
    pub mask_min_len: usize,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireVar {
    pub key: KeyName,
    pub value: WireSecret,
    /// A plain setting from the project file (`vars`), not a secret: not
    /// masked in the command's output.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub plain: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreListing {
    /// In name order.
    pub sections: Vec<StoreSection>,
    /// Environments marked sensitive, as `<project>.<env>`, in name order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sensitive_envs: Vec<Section>,
    /// Environments acknowledged as not production, as `<project>.<env>`,
    /// in name order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub acknowledged_envs: Vec<Section>,
    /// Secrets marked sensitive, in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sensitive_secrets: Vec<Origin>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreSection {
    pub section: Section,
    /// In name order. Names only, never values.
    pub keys: Vec<KeyName>,
    /// The keys marked sensitive, in name order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sensitive: Vec<KeyName>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusReport {
    pub locked: bool,
    /// Present when the request had facts and the daemon is unlocked.
    pub env: Option<EnvStatus>,
    /// Saved tokens that expire within
    /// [`crate::source::EXPIRY_WARNING_DAYS`] or have
    /// expired; known only while the daemon is unlocked.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expiring: Vec<TokenExpiry>,
    /// The remote endpoint, for local callers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<RemoteStatus>,
    /// The approval page and the phone paired with it, for local callers;
    /// none when no phone is paired or being paired.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone: Option<Box<PhoneStatus>>,
    /// Every environment that looks like production and waits for a human
    /// to mark it sensitive or acknowledge it is not production, for local
    /// callers while the daemon is unlocked. Names only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub waiting: Vec<WaitingEnv>,
    /// Every environment a human acknowledged as not production, for local
    /// callers while the daemon is unlocked. Names only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub acknowledged: Vec<Section>,
    /// Every secret that more than one environment reads, once for each
    /// environment that reads it, for local callers while the daemon is
    /// unlocked. Names only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shared: Vec<SharedSecret>,
    /// Whether the app is open, so a request that needs a person's
    /// approval can be asked there; for local callers.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub app: bool,
}

/// A secret an environment reads that other environments read too, as far
/// as the project files say.
///
/// A secret's sensitive mark holds in every environment that reads it. So
/// marking this environment sensitive leaves the secret unmarked while an
/// open environment reads it too, unless a human asks for it or its name
/// looks like production: see [`Self::stays_unmarked`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedSecret {
    pub project: ProjectName,
    pub env: EnvName,
    /// Where it is read from; with `prefix`, everything under it.
    pub secret: Origin,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub prefix: bool,
    /// The other environments that read all of it, in name order.
    pub with: Vec<Section>,
    /// Those of `with` that are open: neither marked sensitive nor waiting
    /// for a human decision.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub open: Vec<Section>,
    /// Marked sensitive now: each environment that reads it needs approval
    /// for its keys.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub sensitive: bool,
    /// Its name looks like production, so it is marked with any
    /// environment that reads it, shared or not.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub production: bool,
}

impl SharedSecret {
    /// Whether marking the environment sensitive leaves this secret
    /// unmarked, so the environments in `open` go on reading it without
    /// approval.
    pub fn stays_unmarked(&self) -> bool {
        !self.sensitive && !self.production && !self.open.is_empty()
    }

    /// Whether acknowledging the environment as not production leaves it
    /// asking for approval for this secret's keys, and a human may want
    /// the mark gone: it is marked, an environment that is not open reads
    /// it too, which is where the mark most likely came from, and it is
    /// not a `file` secret, whose mark is on its keys or its environment.
    pub fn stays_marked(&self) -> bool {
        self.sensitive
            && self.secret.provider != Provider::File
            && self.with.len() > self.open.len()
    }

    /// As a sentence or a list names it: where it is read from, with `*`
    /// for everything under a prefix.
    pub fn name(&self) -> String {
        if self.prefix {
            format!("{}*", self.secret)
        } else {
            self.secret.to_string()
        }
    }

    /// Whether this is `project`'s `env` reading it.
    pub fn of(&self, project: &ProjectName, env: &EnvName) -> bool {
        &self.project == project && &self.env == env
    }
}

/// What [`Request::AddMark`] marks sensitive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MarkTarget {
    /// An environment of a project that has it, and what only its sources
    /// read, as [`Request::MarkEnv`] with nothing in `also`.
    Env { project: ProjectName, env: EnvName },
    /// A secret of any provider but `file`, by where it is read from.
    Secret { secret: Origin },
    /// One key of the local store.
    Key { section: Section, key: KeyName },
}

/// An environment that looks like production and that no human has marked
/// sensitive or acknowledged as not production: until one does, handing
/// out its values takes approval in the app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaitingEnv {
    pub project: ProjectName,
    pub env: EnvName,
    /// Why it looks like production, such as "its name has the segment
    /// `prod`".
    pub why: String,
}

/// The remote endpoint: whether it is on, where it listens, and the
/// grants. Names only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteStatus {
    /// As the store says; `None` until the first unlock reads it.
    pub enabled: Option<bool>,
    /// `ip:port`, while it listens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listening: Option<String>,
    /// Why it does not listen, when on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problem: Option<String>,
    /// Known only while the daemon is unlocked.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grants: Vec<GrantView>,
}

/// The approval page: the phone paired with it, and where it is served.
/// Names only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhoneStatus {
    /// The paired phone; known only while the daemon is unlocked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paired: Option<PhoneView>,
    /// The page's address, `https://name:port`, while it is served.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Why it is not served, when it should be.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problem: Option<String>,
    /// The phone being paired now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing: Option<PhonePairingView>,
    /// The last request answered on the phone since the daemon started.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last: Option<PhoneAnswer>,
}

/// A phone on this tailnet that could be paired.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhoneChoice {
    /// The first label of its `MagicDNS` name.
    pub name: String,
    /// Its stable node id, which [`Request::PhonePair`] also takes.
    pub node: String,
    /// Its operating system as tailscaled names it: `iOS` or `android`.
    pub os: String,
}

/// The paired phone as `status` shows it: never its passkey.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhoneView {
    pub name: String,
    pub node: String,
    /// When it was paired, in Unix seconds.
    pub paired: u64,
    /// When it last opened the page since the daemon started, in Unix
    /// seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seen: Option<u64>,
    /// It allowed notifications, so it is told of a request that waits.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub notifies: bool,
    /// Why the last notification did not reach its push service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub untold: Option<String>,
}

/// A pairing going on: which phone, and the seconds it has left.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhonePairingView {
    pub name: String,
    pub left: u64,
}

/// A request answered on the phone: the id its prompt had, what it was
/// for, and the answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhoneAnswer {
    pub id: u64,
    pub project: ProjectName,
    pub env: EnvName,
    pub approved: bool,
    /// Unix seconds.
    pub time: u64,
}

/// A remote grant as `status` shows it: never its token or the token's
/// hash, only whether it has one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantView {
    pub machine: String,
    pub node: String,
    pub project: ProjectName,
    pub envs: Vec<EnvName>,
    /// When it ends, in Unix seconds; `None` for never.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<u64>,
    /// Whether it has a token. One made before grants had tokens has none
    /// and lets nothing through until it is granted again.
    pub token: bool,
}

impl From<&crate::store::RemoteGrant> for GrantView {
    fn from(g: &crate::store::RemoteGrant) -> Self {
        Self {
            machine: g.machine.clone(),
            node: g.node.clone(),
            project: g.project.clone(),
            envs: g.envs.clone(),
            expires: g.expires,
            token: g.token.is_some(),
        }
    }
}

/// A saved provider token and when it stops working, in Unix seconds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenExpiry {
    pub provider: Provider,
    pub expires: u64,
}

impl TokenExpiry {
    /// What `status` and the app say, `now` being Unix seconds.
    pub fn warning(&self, now: u64) -> String {
        let name = match self.provider {
            Provider::Proton => "Proton Pass",
            p => p.as_str(),
        };
        let date = crate::source::proton::format_date(self.expires);
        let fix = format!(
            "make a new one and run `kagebunshin connect {}`",
            self.provider.as_str()
        );
        let left = self.expires as i64 - now as i64;
        match left.div_euclid(86_400) {
            _ if left <= 0 => format!("the {name} token expired on {date}; {fix}"),
            0 => format!("the {name} token expires today ({date}); {fix}"),
            1 => format!("the {name} token expires tomorrow ({date}); {fix}"),
            n => format!("the {name} token expires in {n} days ({date}); {fix}"),
        }
    }
}

/// A plain setting of the project file, as `status` shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VarStatus {
    pub key: KeyName,
    /// Not secret: it is in the project file.
    pub value: String,
    pub in_example: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvStatus {
    pub project: ProjectName,
    pub env: EnvName,
    /// Whether the checkout has a `.env.example` to compare against.
    pub example: bool,
    /// In key order.
    pub keys: Vec<KeyStatus>,
    /// Plain settings from the project file that no source overrides, in
    /// key order. Not in `keys`; not secret, so with their values.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vars: Vec<VarStatus>,
    /// Listed in `.env.example` but set by no source and no plain
    /// setting, in file order, as in [`DiffReport::missing`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing: Vec<KeyName>,
    /// Secrets a source left out, by name: under an AWS prefix, those that
    /// are not JSON objects. Their keys may be among the missing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped: Vec<String>,
    /// Commands that would fill in what is missing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fixes: Vec<Fix>,
    /// Optional sources that failed and were skipped.
    pub warnings: Vec<String>,
    /// Acknowledged in the app as not production, although it looks it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub acknowledged: bool,
    /// The last `run --strict` that exited 0 with the environment as it is
    /// now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
}

/// A `run --strict` that exited 0: when (seconds since the epoch), and the
/// program's name, as the audit log keeps it; never its arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    pub time: u64,
    pub program: String,
}

/// A complete command that fills in part of what an environment lacks, and
/// who should run it. Names only, never values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fix {
    pub command: String,
    /// When to run it.
    pub note: String,
    pub who: Who,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyStatus {
    pub key: KeyName,
    pub origin: Origin,
    /// Origins that also set this key and lost, earliest first.
    pub overridden: Vec<Origin>,
    pub in_example: bool,
    /// Agents are refused this key's value.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub sensitive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffReport {
    pub project: ProjectName,
    pub env: EnvName,
    pub example: bool,
    /// Listed in `.env.example` but set by no source and no plain setting,
    /// in file order.
    pub missing: Vec<KeyName>,
    /// Resolved but not listed in `.env.example`. Empty without one.
    pub extra: Vec<KeyName>,
    /// How many of `extra` each secret set, in origin order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_by_origin: Vec<OriginCount>,
    /// Keys set by more than one source.
    pub conflicts: Vec<Conflict>,
    /// Secrets a source left out, by name: under an AWS prefix, those that
    /// are not JSON objects. Their keys may be among the missing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped: Vec<String>,
    /// Commands that would fill in what is missing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fixes: Vec<Fix>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OriginCount {
    pub origin: Origin,
    pub keys: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Conflict {
    pub key: KeyName,
    /// The origin that won.
    pub origin: Origin,
    pub overridden: Vec<Origin>,
}

/// What a project file would resolve to, one environment at a time; see
/// [`Request::CheckProject`]. Names and origins, never values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectCheck {
    pub project: ProjectName,
    /// In name order.
    pub envs: Vec<EnvCheck>,
}

/// One environment of a [`ProjectCheck`]: `status` when it resolved,
/// `error` when it did not (a source failed, or it is marked sensitive,
/// so it was not read).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvCheck {
    pub env: EnvName,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<EnvStatus>,
    /// Resolved but not listed in `.env.example`. Empty without one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra: Vec<KeyName>,
    /// Keys set by more than one source, and which won.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conflicts: Vec<Conflict>,
    /// Why it looks like production, when no human has decided yet: once
    /// installed, its values wait for that decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waiting: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<WireError>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncReport {
    pub refreshed: Vec<Synced>,
}

/// One environment `sync` fetched again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Synced {
    pub project: ProjectName,
    pub env: EnvName,
    /// How many keys it resolved to; absent when it failed.
    pub keys: Option<usize>,
    pub warnings: Vec<String>,
    pub error: Option<WireError>,
}

/// The caller as the daemon sees it: from kernel peer credentials, never from
/// anything the client sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Caller {
    pub uid: u32,
    pub gid: u32,
    pub pid: i32,
    pub start_time: ProcStart,
    /// A caller on another machine, from tailscaled; its uid, gid, pid and
    /// start time are then 0, as there is no local process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<RemotePeer>,
}

impl Caller {
    /// A caller on another machine.
    pub fn remote(peer: RemotePeer) -> Self {
        Self {
            uid: 0,
            gid: 0,
            pid: 0,
            start_time: ProcStart(0),
            remote: Some(peer),
        }
    }
}

/// The environment variable a remote caller's token is read from.
pub const REMOTE_TOKEN_ENV: &str = "KAGEBUNSHIN_REMOTE_TOKEN";

/// A peer on the tailnet, as tailscaled identified the connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemotePeer {
    /// Its stable node id.
    pub node: String,
    /// The first label of its `MagicDNS` name.
    pub machine: String,
    /// The login of its owner; `tagged-devices` for a tagged one.
    pub user: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// The hash of the token its request carried, which picks the grants
    /// it may use. Never sent anywhere: not to the app, not to the caller.
    #[serde(skip)]
    pub token: Option<crate::store::TokenHash>,
}

impl RemotePeer {
    /// Who it is, without what it sent: for a prompt and for the audit
    /// log, which say who asked.
    pub fn named(&self) -> Self {
        Self {
            token: None,
            ..self.clone()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("{message}")]
pub struct WireError {
    pub code: ErrorCode,
    pub message: String,
    pub hint: Option<String>,
    /// Who can fix it, when that is known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub who: Option<Who>,
    /// For a human step: one sentence a coding agent can pass on as it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tell: Option<String>,
}

impl WireError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            hint: None,
            who: None,
            tell: None,
        }
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    /// Only a human can fix it, by doing `tell`.
    pub fn human(mut self, tell: impl Into<String>) -> Self {
        self.who = Some(Who::Human);
        self.tell = Some(tell.into());
        self
    }

    /// The caller can fix it itself, as the hint says.
    pub fn agent(mut self) -> Self {
        self.who = Some(Who::Agent);
        self
    }
}

/// Who can do what a message asks: the caller itself (no passphrase, no
/// app), or a human (the store passphrase, the app, a browser login or a
/// decision).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Who {
    Agent,
    Human,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    BadRequest,
    BuildMismatch,
    PermissionDenied,
    Internal,
    /// The request needs values and the daemon is locked.
    Locked,
    /// The environment, or a key it would hand out, is marked sensitive,
    /// and the app is not open to approve handing it out.
    SensitiveEnv,
    /// A request for values marked sensitive, or an import into the local
    /// store, was denied in the app, or not approved in time.
    NotApproved,
    /// An import into the local store takes approval in the app, which is
    /// not open.
    NoApp,
    /// The checkout matches no project, or more than one.
    NoProject,
    /// `config.toml` or a project file is invalid, or names an unknown env.
    Config,
    /// A source that is not optional failed, so the environment did.
    SourceFailed,
    /// A local store exists; unlocking needs its passphrase.
    PassphraseRequired,
    WrongPassphrase,
    /// There is no local store.
    NoStore,
    /// `store init`, and a local store exists.
    StoreExists,
    /// The local store cannot be read or written, or lacks the named key.
    Store,
    /// `get`: the environment resolves no such key.
    NoKey,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A prompt says why it waits; one from an older daemon, without a
    /// reason, still parses.
    #[test]
    fn an_approval_prompt_carries_its_reason() {
        let mut prompt = json!({
            "id": 1, "project": "widget", "env": "prod", "keys": ["A"],
            "command": "deploy", "pid": 4, "cwd": "/src/widget",
        });
        let old: ApprovalPrompt = serde_json::from_value(prompt.clone()).unwrap();
        assert_eq!(old.reason, ApprovalReason::Keys);
        prompt["reason"] = json!({"kind": "waiting", "why": "its name has the segment prod"});
        let new: ApprovalPrompt = serde_json::from_value(prompt.clone()).unwrap();
        assert_eq!(
            new.reason,
            ApprovalReason::Waiting {
                why: "its name has the segment prod".into()
            }
        );
        assert_eq!(serde_json::to_value(&new).unwrap(), prompt);
    }

    #[test]
    fn wire_shape_is_stable() {
        let req = RequestFrame {
            id: 3,
            body: Request::Hello {
                build: "0.1.0".into(),
            },
        };
        assert_eq!(
            serde_json::to_value(&req).unwrap(),
            json!({"id": 3, "body": {"op": "hello", "build": "0.1.0"}})
        );
        let resp = ResponseFrame {
            id: 4,
            body: Response::Whoami(Caller {
                uid: 1000,
                gid: 1000,
                pid: 42,
                start_time: ProcStart(99),
                remote: None,
            }),
        };
        assert_eq!(
            serde_json::to_value(&resp).unwrap(),
            json!({"id": 4, "body": {"kind": "whoami", "uid": 1000, "gid": 1000, "pid": 42, "start_time": 99}})
        );
        let err = Response::Error(WireError::new(ErrorCode::BuildMismatch, "m").with_hint("h"));
        assert_eq!(
            serde_json::to_value(&err).unwrap(),
            json!({"kind": "error", "code": "build_mismatch", "message": "m", "hint": "h"})
        );
        let req = Request::Sync {
            project: Some("widget".parse().unwrap()),
            env: None,
        };
        assert_eq!(
            serde_json::to_value(&req).unwrap(),
            json!({"op": "sync", "project": "widget", "env": null})
        );
        assert_eq!(
            serde_json::to_value(Response::LockState {
                locked: true,
                warnings: Vec::new(),
            })
            .unwrap(),
            json!({"kind": "lock_state", "locked": true})
        );
        let status = Response::Status(StatusReport {
            locked: false,
            env: None,
            expiring: Vec::new(),
            remote: None,
            waiting: Vec::new(),
            acknowledged: Vec::new(),
            shared: Vec::new(),
            app: false,
            phone: None,
        });
        let day = 86_400;
        let soon = TokenExpiry {
            provider: Provider::Proton,
            expires: 1_801_353_600, // 2027-01-31
        };
        for (now, want) in [
            (soon.expires - 3 * day - 1, "expires in 3 days (2027-01-31)"),
            (soon.expires - day - 1, "expires tomorrow (2027-01-31)"),
            (soon.expires - 60, "expires today (2027-01-31)"),
            (soon.expires, "expired on 2027-01-31"),
        ] {
            let w = soon.warning(now);
            assert!(w.contains(want), "{w}");
            assert!(w.contains("Proton Pass") && w.ends_with("`kagebunshin connect proton`"));
        }
        assert_eq!(
            serde_json::to_value(&status).unwrap(),
            json!({"kind": "status", "locked": false, "env": null})
        );
    }

    #[test]
    fn store_wire_shape() {
        // An unlock from before the store, with no passphrase field.
        let old: Request = serde_json::from_value(json!({"op": "unlock"})).unwrap();
        assert!(matches!(old, Request::Unlock { passphrase: None }));
        let set = Request::StoreSet {
            section: "widget.dev".parse().unwrap(),
            key: "API_KEY".parse().unwrap(),
            value: WireSecret::new("v".into()),
            passphrase: WireSecret::new("p".into()),
            sensitive: false,
        };
        assert_eq!(
            serde_json::to_value(&set).unwrap(),
            json!({"op": "store_set", "section": "widget.dev", "key": "API_KEY", "value": "v", "passphrase": "p", "sensitive": false})
        );
        // A store_set from before marks, with no sensitive field.
        let old: Request = serde_json::from_value(
            json!({"op": "store_set", "section": "widget.dev", "key": "A", "value": "v", "passphrase": "p"}),
        )
        .unwrap();
        assert!(matches!(
            old,
            Request::StoreSet {
                sensitive: false,
                ..
            }
        ));
        let bad = serde_json::from_value::<Request>(
            json!({"op": "store_unset", "section": "widget", "key": "A", "passphrase": "p"}),
        );
        assert!(bad.is_err());
        let clear = Request::StoreClear {
            project: "widget".parse().unwrap(),
            passphrase: WireSecret::new("p".into()),
        };
        assert_eq!(
            serde_json::to_value(&clear).unwrap(),
            json!({"op": "store_clear", "project": "widget", "passphrase": "p"})
        );
        let list = Response::StoreList(StoreListing {
            sections: vec![StoreSection {
                section: "widget.dev".parse().unwrap(),
                keys: vec!["A".parse().unwrap(), "B".parse().unwrap()],
                sensitive: vec!["B".parse().unwrap()],
            }],
            sensitive_envs: Vec::new(),
            acknowledged_envs: Vec::new(),
            sensitive_secrets: Vec::new(),
        });
        assert_eq!(
            serde_json::to_value(&list).unwrap(),
            json!({"kind": "store_list", "sections": [{"section": "widget.dev", "keys": ["A", "B"], "sensitive": ["B"]}]})
        );
        assert_eq!(
            serde_json::to_value(Response::Store {
                change: Change::Created,
                locked: false
            })
            .unwrap(),
            json!({"kind": "store", "change": "created", "locked": false})
        );
        assert_eq!(
            serde_json::to_value(Response::ProtonConnected {
                change: Change::Replaced,
                locked: false,
                vaults: 2,
            })
            .unwrap(),
            json!({"kind": "proton_connected", "change": "replaced", "locked": false, "vaults": 2})
        );
        assert_eq!(
            serde_json::to_value(WireError::new(ErrorCode::PassphraseRequired, "m")).unwrap()["code"],
            "passphrase_required"
        );
    }

    #[test]
    fn wire_secrets_are_not_debug_printed() {
        let c = crate::test_support::Canary::new();
        let req = Request::StorePasswd {
            passphrase: WireSecret::new(c.value().into()),
            new_passphrase: WireSecret::new(c.value().into()),
        };
        crate::test_support::assert_no_canary(&c, &format!("{req:?}"));
        crate::test_support::assert_no_canary(&c, &format!("{req:#?}"));
        let req = Request::ProtonConnect {
            token: WireSecret::new(c.value().into()),
            expires: Some(1),
            passphrase: WireSecret::new(c.value().into()),
        };
        crate::test_support::assert_no_canary(&c, &format!("{req:?}"));
        let granted = Response::RemoteGranted {
            change: Change::Added,
            locked: false,
            machine: "buildbot".into(),
            token: WireSecret::new(c.value().into()),
        };
        crate::test_support::assert_no_canary(&c, &format!("{granted:?}"));
    }

    /// A grant's token crosses the socket once, in the reply that made it.
    /// What a status says of a grant, and of who asked, has neither it nor
    /// its hash.
    #[test]
    fn remote_wire_shape() {
        let rotate = Request::RemoteRotate {
            machine: "buildbot".into(),
            project: "widget".parse().unwrap(),
            passphrase: WireSecret::new("p".into()),
        };
        assert_eq!(
            serde_json::to_value(&rotate).unwrap(),
            json!({"op": "remote_rotate", "machine": "buildbot", "project": "widget", "passphrase": "p"})
        );
        let granted = Response::RemoteGranted {
            change: Change::Added,
            locked: false,
            machine: "buildbot".into(),
            token: WireSecret::new("kbr_t".into()),
        };
        assert_eq!(
            serde_json::to_value(&granted).unwrap(),
            json!({"kind": "remote_granted", "change": "added", "locked": false, "machine": "buildbot", "token": "kbr_t"})
        );

        let hash = crate::store::TokenHash::of("kbr_t");
        let grant = crate::store::RemoteGrant {
            machine: "buildbot".into(),
            node: "nBOT".into(),
            project: "widget".parse().unwrap(),
            envs: vec!["dev".parse().unwrap()],
            token: Some(hash),
            expires: None,
        };
        assert_eq!(
            serde_json::to_value(GrantView::from(&grant)).unwrap(),
            json!({"machine": "buildbot", "node": "nBOT", "project": "widget", "envs": ["dev"], "token": true})
        );
        let peer = RemotePeer {
            node: "nBOT".into(),
            machine: "buildbot".into(),
            user: "dev@example.com".into(),
            tags: Vec::new(),
            token: Some(hash),
        };
        let sent = serde_json::to_value(&peer).unwrap();
        assert_eq!(
            sent,
            json!({"node": "nBOT", "machine": "buildbot", "user": "dev@example.com"})
        );
        // One that says it has a token is not believed: it is the request's
        // header that gives it one.
        let mut claimed = sent;
        claimed["token"] = json!("00".repeat(32));
        let read: RemotePeer = serde_json::from_value(claimed).unwrap();
        assert_eq!(read, peer.named());
    }

    /// What a status says of the paired phone has nothing of its passkey.
    #[test]
    fn phone_wire_shape() {
        let pair = Request::PhonePair {
            machine: "phone".into(),
            passphrase: WireSecret::new("p".into()),
        };
        assert_eq!(
            serde_json::to_value(&pair).unwrap(),
            json!({"op": "phone_pair", "machine": "phone", "passphrase": "p"})
        );
        assert_eq!(
            serde_json::to_value(Request::Phones).unwrap(),
            json!({"op": "phones"})
        );
        assert_eq!(
            serde_json::to_value(Response::Phones {
                phones: vec![PhoneChoice {
                    name: "phone".into(),
                    node: "nPHONE".into(),
                    os: "iOS".into(),
                }]
            })
            .unwrap(),
            json!({"kind": "phones", "phones": [{"name": "phone", "node": "nPHONE", "os": "iOS"}]})
        );
        assert_eq!(
            serde_json::to_value(Request::PhonePairStop).unwrap(),
            json!({"op": "phone_pair_stop"})
        );
        assert_eq!(
            serde_json::to_value(Request::PhoneUnpair {
                passphrase: WireSecret::new("p".into())
            })
            .unwrap(),
            json!({"op": "phone_unpair", "passphrase": "p"})
        );
        let pairing = Response::PhonePairing {
            name: "phone".into(),
            url: "https://self.example.ts.net:47318".into(),
            seconds: 600,
        };
        assert_eq!(
            serde_json::to_value(&pairing).unwrap(),
            json!({"kind": "phone_pairing", "name": "phone", "url": "https://self.example.ts.net:47318", "seconds": 600})
        );
        let status = PhoneStatus {
            paired: Some(PhoneView {
                name: "phone".into(),
                node: "nPHONE".into(),
                paired: 1_767_225_600,
                seen: None,
                notifies: false,
                untold: None,
            }),
            url: Some("https://self.example.ts.net:47318".into()),
            problem: None,
            pairing: None,
            last: None,
        };
        assert_eq!(
            serde_json::to_value(&status).unwrap(),
            json!({
                "paired": {"name": "phone", "node": "nPHONE", "paired": 1_767_225_600u64},
                "url": "https://self.example.ts.net:47318",
            })
        );
        // One that allowed notifications, and what became of the last.
        let mut told = status;
        if let Some(phone) = &mut told.paired {
            (phone.notifies, phone.untold) = (true, Some("it was not sent".into()));
        }
        let wire = serde_json::to_value(&told).unwrap();
        assert_eq!(wire["paired"]["notifies"], json!(true));
        assert_eq!(wire["paired"]["untold"], json!("it was not sent"));
        assert_eq!(serde_json::from_value::<PhoneStatus>(wire).unwrap(), told);
    }
}
