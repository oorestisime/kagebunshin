//! The daemon's state: locked, or unlocked with a cache of resolved
//! environments.
//!
//! ```text
//!            unlock                      lock, or idle timeout
//!   Locked ─────────▶ Unlocked{cache} ─────────────────────────▶ Locked
//! ```
//!
//! The cache holds one slot per (project, environment): either the values,
//! or the fetch that will produce them. Requests that arrive while a fetch
//! runs wait on that same fetch, so N concurrent requests cost one round of
//! provider calls. Every fetch is tagged with a generation number, and its
//! result is cached only if its slot still holds that generation: after a
//! `sync` or a `lock` an older fetch can finish, but it can no longer
//! populate the cache. Failed fetches are not cached.
//!
//! The idle timer is reset only by [`Daemon::hand_out`], the path that gives
//! values to a caller (`run_env` and `get`). Status, diff, sync and ping never reset it, so
//! polling `status` cannot keep the daemon unlocked.
//!
//! Unlocking decrypts the local store, if there is one, into the session;
//! `file` sources read that copy and locking drops it. Store writes go to
//! the file (each one checks the passphrase it is given) and, when the
//! daemon is unlocked, replace the session's copy and drop every cached
//! environment. An environment whose sources in its project file are not
//! the ones its cached values came from is fetched again; a change at a
//! provider is not seen until `sync`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::Duration;

use futures::future::{BoxFuture, FutureExt, Shared, join_all};
use futures::stream::{self, StreamExt};
use tokio::sync::{oneshot, watch};
use tokio::task::AbortHandle;
use tokio::time::Instant;
use tracing::{debug, info, warn};

pub mod phone;

use crate::secret::SecretValue;
use crate::source::SourceError;

use super::proof::Proofs;
use super::push::PushState;
use super::resolve::{
    EnvValues, ImportRefusal, Refusal, ResolveError, SourceFactory, Unapproved, add_as_one_key,
    duplicate_warnings, env_error, fetch_env, fetched_alike, is_sensitive, mark_hint,
    named_production, prod_like, prod_like_profile, refuse_sensitive, secret_marked,
    unmarked_warnings, waiting_envs, waiting_message, waiting_message_remote, waiting_tell,
};
use super::shared::{Claim, Sharing, shared_secrets};
use crate::audit::{AuditLog, Decision, Event};
use crate::config::schema::ApprovalTimeout;
use crate::config::{ConfigError, Project, Registry, Select, SourcePattern, SourceSpec};
use crate::ipc::protocol::{
    APPROVAL_POLL, ApprovalPrompt, ApprovalReason, Caller, Conflict, DiffReport, EnvCheck,
    EnvStatus, ErrorCode, Facts, Fix, ImportNames, ImportSection, ImportedSection, KeyStatus,
    MarkTarget, OriginCount, ProjectCheck, Proof, RemotePeer, RemoteStatus, Request, Response,
    RunEnvReply, SharedSecret, StatusReport, StoreListing, StoreSection, SyncReport, Synced,
    TokenExpiry, VarStatus, WaitingEnv, WireError, WireSecret, WireVar,
};
use crate::source::aws_sm::AwsSettings;
use crate::source::{Health, Listed, ProviderStatus};
use crate::store::{
    Change, Passphrase, ProtonToken, RemoteGrant, Section, Store, StoreError, StoreFile, TokenHash,
};
use crate::tailnet::LocalApi;
use crate::types::{EnvName, KeyName, Origin, ProjectName, Provider};
use crate::webpush::PushService;

/// What a request that waits for approval asks for.
struct Wanted {
    /// The keys the caller is told were refused.
    keys: Vec<KeyName>,
    /// The keys the person is shown: `keys`, or for a marked environment
    /// with no `.env.example` those the session holds for it.
    shown: Vec<KeyName>,
    /// See [`ApprovalPrompt::every_key`].
    every_key: bool,
}

/// The keys `run` hands out: those `.env.example` lists, once each, or
/// every key when there is no such file.
fn wanted_keys<'a>(facts: &'a Facts, values: &'a EnvValues) -> Vec<&'a KeyName> {
    match &facts.example_keys {
        Some(listed) => {
            let mut seen = BTreeSet::new();
            listed.iter().filter(|k| seen.insert(*k)).collect()
        }
        None => values.keys.keys().collect(),
    }
}

/// The keys `.env.example` lists that no source sets and no plain setting
/// in `vars` does, once each, in file order.
fn missing_keys(example: Option<&[KeyName]>, values: &EnvValues, vars: &Vars) -> Vec<KeyName> {
    let mut seen = BTreeSet::new();
    example
        .into_iter()
        .flatten()
        .filter(|k| !values.keys.contains_key(*k) && !vars.contains_key(*k) && seen.insert(*k))
        .cloned()
        .collect()
}

/// An environment's plain settings, from its project file.
type Vars = BTreeMap<KeyName, String>;

/// The plain settings of `vars` that no source of `values` sets: a source
/// always wins over a plain setting.
fn plain_vars(values: &EnvValues, mut vars: Vars) -> Vars {
    vars.retain(|k, _| !values.keys.contains_key(k));
    vars
}

/// What would fill in `missing`: a skipped secret added as one key, and,
/// when `project`'s `env` reads its own `[<project>.<env>]` store section,
/// one `store set` naming every key `.env.example` gives no value (the CLI
/// suggests `project set-var` for the others). When that section is the
/// only source and is empty, and an env file here has values, `onboard`
/// instead; for `default_env` only, as that is the one an env file is
/// taken to be for.
fn fixes(
    (project, env): (&ProjectName, &EnvName),
    values: &EnvValues,
    missing: &[KeyName],
    facts: &Facts,
    store: Option<&Store>,
    default_env: &EnvName,
) -> Vec<Fix> {
    let section = Section {
        project: project.clone(),
        env: env.clone(),
    };
    let own = section.to_string();
    let reads_own = |s: &SourceSpec| {
        s.provider == Provider::File
            && matches!(&s.select, Select::Secret { name, key: None } if *name == own)
    };
    let mut out = Vec::new();
    for skip in &values.skipped {
        let Some(spec) = values.sources.get(skip.source) else {
            continue;
        };
        out.push(Fix {
            command: add_as_one_key(project, env, spec, &skip.secret),
            note: format!(
                "secret {} is not a JSON object, so it was skipped; this adds its whole string \
                 as one key, if NAME is replaced with the key's name",
                skip.secret
            ),
            who: Fixer::Agent,
        });
    }
    let stored: Vec<&str> = missing
        .iter()
        .filter(|k| !facts.example_values.contains(k))
        .map(KeyName::as_str)
        .collect();
    if stored.is_empty() || !values.sources.iter().any(reads_own) {
        return out;
    }
    let only_source = matches!(values.sources.as_slice(), [s] if reads_own(s));
    let empty = store
        .and_then(|st| st.section(&section))
        .is_none_or(BTreeMap::is_empty);
    match &facts.env_file {
        Some(file) if only_source && empty && env == default_env => out.push(Fix {
            // The folder in full: the human's terminal may be anywhere.
            command: format!(
                "kagebunshin onboard{} {}",
                (facts.env.as_ref()).map_or(String::new(), |env| format!(" --env {env}")),
                crate::types::shell_quote(&facts.cwd.to_string_lossy())
            ),
            note: format!(
                "it moves the values of {file} into [{section}], once a person approves that with \
                 the store passphrase, in the app or at a terminal"
            ),
            who: Fixer::Human,
        }),
        _ => out.push(Fix {
            command: format!("kagebunshin store set {section} {}", stored.join(" ")),
            note: format!(
                "it asks for the store passphrase, then {}",
                if stored.len() == 1 {
                    "the value"
                } else {
                    "each value"
                }
            ),
            who: Fixer::Human,
        }),
    }
    out
}

/// What `status` shows of environment `env` of `project`, resolved to
/// `values`: names, origins and plain settings, never a secret value.
fn env_status(
    (project, env): (ProjectName, EnvName),
    facts: &Facts,
    values: &EnvValues,
    vars: Vars,
    warnings: Vec<String>,
    store: Option<&Store>,
    default_env: &EnvName,
) -> EnvStatus {
    let example_keys = facts.example_keys.as_deref();
    let example: BTreeSet<_> = example_keys.into_iter().flatten().collect();
    let acknowledged = store.is_some_and(|st| st.env_acknowledged(&project, &env));
    let keys = values
        .keys
        .iter()
        .map(|(key, r)| KeyStatus {
            key: key.clone(),
            origin: r.origin.clone(),
            overridden: r.overridden.clone(),
            in_example: example.contains(key),
            sensitive: is_sensitive(store, key, r),
        })
        .collect();
    let plain = plain_vars(values, vars);
    let missing = missing_keys(example_keys, values, &plain);
    let fixes = fixes(
        (&project, &env),
        values,
        &missing,
        facts,
        store,
        default_env,
    );
    let skipped = values.skipped.iter().map(|s| s.secret.clone()).collect();
    let vars = plain
        .into_iter()
        .map(|(key, value)| VarStatus {
            in_example: example.contains(&key),
            key,
            value,
        })
        .collect();
    EnvStatus {
        project,
        env,
        example: example_keys.is_some(),
        keys,
        vars,
        missing,
        skipped,
        fixes,
        warnings,
        acknowledged,
        proof: None,
    }
}

/// What an environment's sources read, to mark along with it unless an
/// open environment reads it too: see [`Daemon::source_marks`] and
/// [`Sharing`].
#[derive(Default)]
struct SourceMarks {
    /// What a source names, and the id its mark is kept by.
    secrets: Vec<(Claim, Origin)>,
    prefixes: Vec<Claim>,
    /// What `file` sources select. Their sections are read from the store
    /// being written, and every key in them marked; the environment's own
    /// section is covered by its mark already.
    files: Vec<Select>,
}

impl SourceMarks {
    /// Adds what `spec` reads, if its provider need not be asked: `false`
    /// for Proton, which [`Daemon::source_marks`] asks.
    fn add_local(&mut self, spec: &SourceSpec) -> bool {
        match spec.provider {
            Provider::File => self.files.push(spec.select.clone()),
            Provider::AwsSm => {
                for claim in Claim::of(spec) {
                    if claim.prefix {
                        self.prefixes.push(claim);
                    } else {
                        let id = claim.origin.clone();
                        self.secrets.push((claim, id));
                    }
                }
            }
            Provider::Proton => return false,
        }
        true
    }

    /// Marks in `st` what `sharing` does not leave to an open environment.
    fn write(self, st: &mut Store, own: &Section, sharing: &Sharing) -> Result<(), StoreError> {
        for (claim, id) in self.secrets {
            if !sharing.leaves(&claim) {
                st.mark_secret(id, true)?;
            }
        }
        for prefix in self.prefixes {
            if !sharing.leaves(&prefix) {
                st.mark_prefix(prefix.origin)?;
            }
        }
        let picks = |s: &Section| {
            let name = s.to_string();
            self.files.iter().any(|select| match select {
                Select::Secret { name: n, .. } => *n == name,
                Select::Secrets(names) => names.contains(&name),
                Select::Prefix(p) => name.starts_with(p.as_str()),
            }) && !sharing.leaves(&Claim::named(Provider::File, &name))
        };
        let keys: Vec<(Section, KeyName)> = st
            .sections()
            .filter(|(s, _)| *s != own && picks(s))
            .flat_map(|(s, keys)| keys.keys().map(|k| (s.clone(), k.clone())))
            .collect();
        for (section, key) in keys {
            st.mark(&section, &key, true)?;
        }
        Ok(())
    }
}

/// Marks environment `section` sensitive in `st`, and with it what its
/// sources read (`marks`) and no open environment reads too. `waiting` are
/// the environments known to wait for a decision beyond those the project
/// files show; `also` what a human asked to mark all the same.
fn mark_env_with_sources(
    st: &mut Store,
    registry: &Registry,
    section: Section,
    marks: SourceMarks,
    mut waiting: Vec<WaitingEnv>,
    also: Vec<Origin>,
) -> Result<Change, StoreError> {
    waiting.extend(waiting_envs(registry, Some(st)));
    let sharing = Sharing::new(registry, Some(st), &waiting, &section, also);
    marks.write(st, &section, &sharing)?;
    Ok(st.mark_env(section, true))
}

/// How long `list` waits for one provider.
const LIST_TIMEOUT: Duration = Duration::from_secs(30);

/// How many secrets `list --keys` reads at once.
const KEY_READS: usize = 8;

/// How long after its last `wait_approvals` ended the app still counts as
/// open: the gap before it asks again.
const APP_GRACE: Duration = Duration::from_secs(5);

/// How often a request waiting for approval checks that the process that
/// made it is still there.
const CALLER_CHECK: Duration = Duration::from_millis(500);

/// Requests waiting for a person to approve them in the app.
#[derive(Default)]
struct Approvals {
    next: u64,
    /// By id, oldest first, each with when it is denied unanswered and
    /// where its answer goes.
    pending: BTreeMap<u64, (ApprovalPrompt, Instant, oneshot::Sender<Reply>)>,
    /// `wait_approvals` requests waiting now, and when the last one ended.
    watching: usize,
    last_seen: Option<Instant>,
}

impl Approvals {
    fn app_open(&self) -> bool {
        self.watching > 0 || self.last_seen.is_some_and(|t| t.elapsed() < APP_GRACE)
    }

    fn prompts(&self) -> Vec<ApprovalPrompt> {
        let now = Instant::now();
        self.pending
            .values()
            .map(|(p, deadline, _)| ApprovalPrompt {
                left: Some(deadline.saturating_duration_since(now).as_secs()),
                ..p.clone()
            })
            .collect()
    }
}

/// The remote endpoint as the daemon knows it.
#[derive(Default)]
struct Remote {
    /// As the store last read or written says; `None` until then.
    enabled: Option<bool>,
    /// Where the listener is, while there is one.
    listening: Option<std::net::SocketAddr>,
    /// Why there is none, while it is on.
    problem: Option<String>,
    /// The nodes with a request waiting for approval: one each.
    prompting: BTreeSet<String>,
}

/// A remote request waiting for approval; its node may ask again once it
/// stops waiting.
struct Prompting<'a> {
    inner: &'a Inner,
    node: String,
}

impl Drop for Prompting<'_> {
    fn drop(&mut self) {
        self.inner.remote().prompting.remove(&self.node);
    }
}

/// A `wait_approvals` in progress: the app is open until it ends, and for
/// [`APP_GRACE`] after, unless it ended because the app did.
struct Watching<'a> {
    inner: &'a Inner,
    /// The app's process ended: it will not ask again.
    gone: bool,
}

impl Drop for Watching<'_> {
    fn drop(&mut self) {
        let mut a = self.inner.approvals();
        a.watching = a.watching.saturating_sub(1);
        a.last_seen = (!self.gone).then(Instant::now);
    }
}

/// Completes once the local process that made a request has ended; never
/// for a caller on another machine, which has no process here.
async fn caller_gone(caller: &Caller) {
    if caller.remote.is_some() {
        return std::future::pending().await;
    }
    let mut tick = tokio::time::interval(CALLER_CHECK);
    loop {
        tick.tick().await;
        let started = crate::sys::process_start(caller.pid).ok();
        if started != Some(caller.start_time) {
            return;
        }
    }
}

/// A request waiting for approval; its prompt goes when it stops waiting,
/// however that happens.
struct Asking<'a> {
    inner: &'a Inner,
    id: u64,
}

impl Drop for Asking<'_> {
    fn drop(&mut self) {
        if self.inner.approvals().pending.remove(&self.id).is_some() {
            self.inner.approvals_changed.send_modify(|n| *n += 1);
        }
    }
}

/// What a person approved a prompt with in the app.
struct Approved {
    /// Opens the store.
    passphrase: Passphrase,
    /// What they typed for the keys of a prompt that asks for values
    /// ([`ApprovalReason::Type`]): at least one, each a key of the prompt,
    /// none twice. Empty for every other prompt.
    values: Vec<(KeyName, SecretValue)>,
}

/// A person's answer to a prompt, by where they gave it.
enum Reply {
    /// In the app: what approved it, or none for a denial.
    Desk(Option<Approved>),
    /// On the paired phone: approved with its passkey, or denied. Only a
    /// prompt that hands values out is approved there.
    Phone(bool),
}

/// How a prompt shown in the app ended.
enum Answer {
    Approved(Approved),
    /// Approved on the paired phone, which has no passphrase to give.
    ApprovedOnPhone,
    Denied,
    TimedOut,
    /// The process that asked ended first.
    CallerGone,
    /// The app closed first.
    AppClosed,
}

/// Who asks `run` or `get` for values: what an approval prompt shows and
/// the audit log records.
struct Ask<'a> {
    action: &'static str,
    caller: &'a Caller,
    cwd: &'a Path,
    /// For the audit log; see [`Request::RunEnv`].
    program: Option<String>,
    /// For the prompt only.
    command: String,
    argv: Vec<String>,
    /// How an approval it waited for ended, for the audit log.
    approval: &'a Mutex<Option<Decision>>,
}

/// What the audit log names of an import: `section.KEY`, each once.
fn import_keys(sections: &[ImportSection]) -> Vec<String> {
    let mut keys = Vec::new();
    for s in sections {
        for (k, _) in &s.values {
            let key = format!("{}.{k}", s.section);
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
    }
    keys
}

/// How far up a caller's parents a prompt looks.
const ANCESTORS: usize = 6;

/// The names of the processes a local caller descends from, nearest
/// first, up to the session's first process: for a prompt to say who
/// asks. As far as they can be read; none for a caller on another machine.
fn ancestors(caller: &Caller) -> Vec<String> {
    let mut names = Vec::new();
    if caller.remote.is_some() {
        return names;
    }
    let mut pid = caller.pid;
    while names.len() < ANCESTORS {
        let Ok(parent) = crate::sys::parent_pid(pid) else {
            break;
        };
        // Pid 1 started everything: it says nothing about who asks.
        if parent <= 1 {
            break;
        }
        let Ok(name) = crate::sys::process_name(parent) else {
            break;
        };
        names.push(name);
        pid = parent;
    }
    names
}

/// An environment a project file flags `sensitive`, with what marking it
/// also marks, and whether some of its sources (Proton's) are left out of
/// that because their provider would have to be asked.
type FlaggedEnv = (Section, SourceMarks, bool);

/// The `sensitive` flags in project files: environments, and the secrets
/// `aws_sm` sources list.
fn file_flags(registry: &Registry) -> (Vec<FlaggedEnv>, Vec<Origin>) {
    let (mut envs, mut secrets) = (Vec::new(), Vec::new());
    for project in registry.projects() {
        for (env, file) in &project.file.envs {
            for source in &file.sources {
                secrets.extend(
                    (source.sensitive.iter())
                        .map(|n| crate::source::stable_origin(Provider::AwsSm, n)),
                );
            }
            if !file.sensitive {
                continue;
            }
            let mut marks = SourceMarks::default();
            let mut unasked = false;
            if let Ok(settings) = registry.env(project, Some(env)) {
                for spec in &settings.sources {
                    unasked |= !marks.add_local(spec);
                }
            }
            let section = Section {
                project: project.name.clone(),
                env: env.clone(),
            };
            envs.push((section, marks, unasked));
        }
    }
    (envs, secrets)
}

/// Unlock's step that copies `envs` and `secrets`, flagged in project
/// files, into `store` as marks, so deleting a flag later changes nothing.
/// A flag only adds a mark; what is marked already is left alone, and the
/// store is written only if something is new. An environment's sources
/// are marked with it as when a human marks it: what an open environment
/// reads too is left unmarked. Fails, unlocking nothing, if
/// it cannot be written.
async fn copy_flags(
    store: Store,
    registry: &Registry,
    file: &StoreFile,
    passphrase: Arc<Passphrase>,
    envs: Vec<FlaggedEnv>,
    secrets: Vec<Origin>,
    warnings: &mut Vec<String>,
) -> Result<Store, ResolveError> {
    let envs: Vec<_> = envs
        .into_iter()
        .filter(|(s, ..)| !store.env_marked(&s.project, &s.env))
        .collect();
    let secrets: Vec<_> = secrets
        .into_iter()
        .filter(|o| !secret_marked(Some(&store), o))
        .collect();
    if envs.is_empty() && secrets.is_empty() {
        return Ok(store);
    }
    for (section, _, unasked) in &envs {
        info!(%section, "marking an environment its project file flags sensitive");
        if *unasked {
            warnings.push(format!(
                "marked [{section}] sensitive, as its project file says; its Proton sources \
                 are marked along with it once you mark it again in the app"
            ));
        }
    }
    let file = file.clone();
    let registry = registry.clone();
    let ((), store) = blocking(move || {
        file.update(&passphrase, None, move |st| {
            // All of them first: one flagged environment is not an open
            // one to another.
            for (section, ..) in &envs {
                st.mark_env(section.clone(), true);
            }
            for (section, marks, _) in envs {
                mark_env_with_sources(st, &registry, section, marks, Vec::new(), Vec::new())?;
            }
            for secret in secrets {
                st.mark_secret(secret, true)?;
            }
            Ok(())
        })
    })
    .await?;
    Ok(store)
}

/// A command line as a prompt shows it: arguments that are empty or hold
/// whitespace or quotes are quoted.
fn shown_command(argv: &[String], program: Option<&str>) -> String {
    if argv.is_empty() {
        return program
            .unwrap_or("a command that did not name itself")
            .to_owned();
    }
    argv.iter()
        .map(|a| {
            if a.is_empty()
                || a.chars()
                    .any(|c| c.is_whitespace() || c == '"' || c == '\'')
            {
                format!("{a:?}")
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Refuses a remote reply about another environment than the one a grant
/// was checked for: a project file changed while it was answered.
fn same_env(granted: &EnvKey, project: &ProjectName, env: &EnvName) -> Result<(), ResolveError> {
    if (&granted.0, &granted.1) == (project, env) {
        return Ok(());
    }
    Err(ResolveError::Remote {
        message: format!(
            "the request resolved to environment {env} of project {project}, not the \
             {} of project {} its grant was checked for; try again",
            granted.1, granted.0
        ),
        hint: None,
    })
}

/// What the audit log records of a request, taken before it is answered.
struct Asked {
    action: &'static str,
    /// Recorded when allowed too, not only when denied.
    always: bool,
    /// Hands out values.
    handover: bool,
    project: Option<ProjectName>,
    env: Option<EnvName>,
    /// Where it came from, to name the project it resolves to.
    facts: Option<Facts>,
    keys: Vec<String>,
    program: Option<String>,
    target: Option<String>,
}

impl Asked {
    /// `None` for the requests the server answers itself.
    fn of(req: &Request) -> Option<Self> {
        let asked = |action, always| Asked {
            action,
            always,
            handover: false,
            project: None,
            env: None,
            facts: None,
            keys: Vec::new(),
            program: None,
            target: None,
        };
        let about = |action, always, facts: &Facts| Asked {
            env: facts.env.clone(),
            facts: Some(facts.clone()),
            ..asked(action, always)
        };
        let entry = |action, section: &crate::store::Section, key: &KeyName| Asked {
            keys: vec![format!("{section}.{key}")],
            ..asked(action, true)
        };
        Some(match req {
            Request::Status { facts } => match facts {
                Some(facts) => about("status", false, facts),
                None => asked("status", false),
            },
            Request::Diff { facts } => about("diff", false, facts),
            // It reads every source's values, for a project that may not
            // exist yet.
            Request::CheckProject { project, .. } => Asked {
                project: Some(project.clone()),
                ..asked("project check", true)
            },
            Request::Sync { project, env } => Asked {
                project: project.clone(),
                env: env.clone(),
                ..asked("sync", false)
            },
            Request::Lock => asked("lock", true),
            Request::Unlock { .. } => asked("unlock", true),
            Request::StoreSet { section, key, .. } => entry("store set", section, key),
            Request::StoreSetMany { sections, .. } => Asked {
                keys: sections
                    .iter()
                    .flat_map(|(section, values)| {
                        values.iter().map(move |(k, _)| format!("{section}.{k}"))
                    })
                    .collect(),
                ..asked("store set", true)
            },
            Request::StoreImport { sections, .. } => Asked {
                keys: import_keys(sections),
                ..asked("store import", true)
            },
            // The keys asked for; those a person typed, once they have.
            Request::StoreAsk { section, keys, .. } => Asked {
                keys: keys.iter().map(|k| format!("{section}.{k}")).collect(),
                ..asked("store set", true)
            },
            Request::StoreMark {
                section,
                key,
                sensitive,
                ..
            } => entry(
                if *sensitive {
                    "store mark"
                } else {
                    "store unmark"
                },
                section,
                key,
            ),
            Request::StoreUnset { section, key, .. } => entry("store unset", section, key),
            Request::StoreClear { project, .. } => Asked {
                project: Some(project.clone()),
                ..asked("store clear", true)
            },
            // Named apart from a mark made with the passphrase: with the
            // caller, the log says which marks no human made.
            Request::AddMark { target } => match target {
                MarkTarget::Env { project, env } => Asked {
                    project: Some(project.clone()),
                    env: Some(env.clone()),
                    ..asked("add mark env", true)
                },
                MarkTarget::Secret { secret } => Asked {
                    target: Some(format!("{} {}", secret.provider.as_str(), secret.shown())),
                    ..asked("add mark secret", true)
                },
                MarkTarget::Key { section, key } => entry("add mark key", section, key),
            },
            Request::MarkEnv {
                project,
                env,
                sensitive,
                ..
            } => Asked {
                project: Some(project.clone()),
                env: Some(env.clone()),
                ..asked(if *sensitive { "mark env" } else { "unmark env" }, true)
            },
            Request::AcknowledgeEnv {
                project,
                env,
                acknowledged,
                unmark,
                ..
            } => Asked {
                project: Some(project.clone()),
                env: Some(env.clone()),
                // The secrets unmarked with it.
                target: (!unmark.is_empty()).then(|| {
                    let secrets: Vec<_> = unmark
                        .iter()
                        .map(|s| format!("{} {}", s.provider.as_str(), s.shown()))
                        .collect();
                    format!("unmark {}", secrets.join(", "))
                }),
                ..asked(
                    if *acknowledged {
                        "acknowledge env"
                    } else {
                        "unacknowledge env"
                    },
                    true,
                )
            },
            Request::AcknowledgeEnvs { envs, .. } => Asked {
                target: Some(
                    envs.iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(" "),
                ),
                ..asked("acknowledge envs", true)
            },
            Request::MarkSecret {
                secret, sensitive, ..
            } => Asked {
                target: Some(format!("{} {}", secret.provider.as_str(), secret.shown())),
                ..asked(
                    if *sensitive {
                        "mark secret"
                    } else {
                        "unmark secret"
                    },
                    true,
                )
            },
            Request::UnmarkSecrets { secrets, .. } => Asked {
                target: Some(
                    secrets
                        .iter()
                        .map(|s| format!("{} {}", s.provider.as_str(), s.shown()))
                        .collect::<Vec<_>>()
                        .join(", "),
                ),
                ..asked("unmark secrets", true)
            },
            Request::StorePasswd { .. } => asked("store passwd", true),
            Request::ProtonConnect { .. } => asked("connect proton", true),
            Request::StoreList => asked("store list", false),
            // Reading key names reads values, so it is always recorded,
            // with the secrets read (see `audit`).
            Request::List {
                provider,
                prefix,
                keys,
                ..
            } => Asked {
                target: Some(format!(
                    "{} {prefix}",
                    provider.map_or("every provider", |p| p.as_str())
                )),
                ..if *keys {
                    asked("list keys", true)
                } else {
                    asked("list", false)
                }
            },
            Request::Providers { facts, .. } => match facts {
                Some(facts) => about("providers", false, facts),
                None => asked("providers", false),
            },
            Request::RemoteEnable { enabled, .. } => asked(
                if *enabled {
                    "remote enable"
                } else {
                    "remote disable"
                },
                true,
            ),
            Request::RemoteGrant {
                machine,
                project,
                envs,
                expires,
                ..
            } => Asked {
                project: Some(project.clone()),
                target: Some(format!(
                    "machine {machine} envs {}{}",
                    envs.iter()
                        .map(EnvName::as_str)
                        .collect::<Vec<_>>()
                        .join(","),
                    expires
                        .map(|t| format!(" until {}", crate::source::proton::format_date(t)))
                        .unwrap_or_default()
                )),
                ..asked("remote grant", true)
            },
            Request::RemoteRevoke {
                machine, project, ..
            } => Asked {
                project: project.clone(),
                target: Some(format!("machine {machine}")),
                ..asked("remote revoke", true)
            },
            Request::RemoteRotate {
                machine, project, ..
            } => Asked {
                project: Some(project.clone()),
                target: Some(format!("machine {machine}")),
                ..asked("remote rotate", true)
            },
            Request::Phones => asked("phones", false),
            Request::PhonePair { machine, .. } => Asked {
                target: Some(format!("machine {machine}")),
                ..asked("phone pair", true)
            },
            Request::PhonePairStop => asked("phone pair stop", true),
            Request::PhoneUnpair { .. } => asked("phone unpair", true),
            Request::WaitApprovals { .. } => asked("wait approvals", false),
            Request::Approve { .. } => asked("approve", false),
            Request::Proven { facts, program } => Asked {
                program: Some(program.clone()),
                ..about("proven", false, facts)
            },
            Request::RunEnv { facts, program, .. } => Asked {
                handover: true,
                program: program.clone(),
                ..about("run", false, facts)
            },
            Request::Get { facts, key, .. } => Asked {
                handover: true,
                keys: vec![key.to_string()],
                ..about("get", true, facts)
            },
            Request::Inspect { facts, .. } => about("inspect", true, facts),
            Request::Reveal { facts, key, .. } => Asked {
                handover: true,
                keys: vec![key.to_string()],
                ..about("reveal", true, facts)
            },
            Request::Hello { .. } | Request::Ping | Request::Whoami => return None,
        })
    }
}

/// Loads the registry. Called on every request that needs it, so edits to
/// project files apply without a restart.
pub type LoadRegistry = Box<dyn Fn() -> Result<Registry, ConfigError> + Send + Sync>;

use crate::ipc::protocol::Who as Fixer;

type EnvKey = (ProjectName, EnvName);

/// Who a resolve is for. Only a request that proved a human, with the
/// store passphrase, may resolve an environment marked sensitive.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Who {
    Anyone,
    Human,
}
type Fetch = Shared<BoxFuture<'static, Result<Arc<EnvValues>, ResolveError>>>;

enum Lookup {
    Cached(Arc<EnvValues>),
    Wait(Fetch),
}

enum Slot {
    Ready(Arc<EnvValues>),
    Fetching {
        generation: u64,
        /// The sources it reads, as [`EnvValues::sources`] will say.
        sources: Vec<SourceSpec>,
        fetch: Fetch,
        abort: AbortHandle,
    },
}

struct Session {
    id: u64,
    idle: Duration,
    deadline: Instant,
    cache: BTreeMap<EnvKey, Slot>,
    /// Fetches `sync` took out of the cache that may still be running.
    /// They no longer populate it, but `lock` must still cancel them: until
    /// they finish, whoever waits on one would get values after the lock.
    superseded: Vec<AbortHandle>,
    /// The local store as decrypted at unlock or last written; `None` if
    /// there was none.
    store: Option<Arc<Store>>,
    /// A phone being paired, and the passphrase that will save it.
    pairing: Option<Box<phone::Pairing>>,
}

enum Phase {
    Locked,
    Unlocked(Session),
}

struct State {
    phase: Phase,
    /// Shared by unlocked sessions and fetches; only ever increases.
    generation: u64,
    /// Counts lock requests, including those that found the daemon
    /// already locked, so an unlock can tell that one arrived while it
    /// decrypted the store.
    locks: u64,
}

impl State {
    fn next_generation(&mut self) -> u64 {
        self.generation += 1;
        self.generation
    }

    /// Drops every cached value and cancels running fetches. Returns whether
    /// the daemon was unlocked.
    fn lock(&mut self) -> bool {
        self.locks += 1;
        match std::mem::replace(&mut self.phase, Phase::Locked) {
            Phase::Locked => false,
            Phase::Unlocked(session) => {
                for slot in session.cache.values() {
                    if let Slot::Fetching { abort, .. } = slot {
                        abort.abort();
                    }
                }
                for abort in &session.superseded {
                    abort.abort();
                }
                // `session` is dropped here; values nobody else holds are
                // zeroed now, the rest when their last holder lets go.
                true
            }
        }
    }
}

struct Inner {
    load: LoadRegistry,
    sources: Arc<dyn SourceFactory>,
    store: StoreFile,
    /// Held across unlock's read and every store write, so the session's
    /// copy of the store always matches the last write. The file lock
    /// guards against other processes.
    store_io: tokio::sync::Mutex<()>,
    /// One `connect proton` at a time, from proving the human to swapping
    /// the session in; `pass-cli` calls themselves are serialized as well.
    proton_connect: tokio::sync::Mutex<()>,
    state: Mutex<State>,
    audit: Option<AuditLog>,
    proofs: Option<Proofs>,
    approvals: Mutex<Approvals>,
    /// Bumped whenever a request starts or stops waiting for approval.
    approvals_changed: watch::Sender<u64>,
    /// The local Tailscale daemon, which names the machines grants are for.
    tailnet: Option<Arc<dyn LocalApi>>,
    remote: Mutex<Remote>,
    /// Woken when the store turns the remote endpoint on or off.
    remote_changed: tokio::sync::Notify,
    phone: Mutex<phone::Phone>,
    /// What notifies the paired phone of a request that waits.
    push: Option<phone::Push>,
    /// Woken when the phones the approval page is for may have changed.
    phone_woken: tokio::sync::Notify,
    /// Bumped whenever what the approval page shows may have changed,
    /// apart from the prompts, which `approvals_changed` covers.
    phone_seq: watch::Sender<u64>,
}

impl Inner {
    fn remote(&self) -> MutexGuard<'_, Remote> {
        self.remote.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn phone(&self) -> MutexGuard<'_, phone::Phone> {
        self.phone.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn state(&self) -> MutexGuard<'_, State> {
        // Nothing panics while holding the lock in a way that leaves the
        // state inconsistent, so a poisoned lock is still usable.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn approvals(&self) -> MutexGuard<'_, Approvals> {
        self.approvals
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

/// The daemon. Cheap to clone; clones share state. Starts locked.
#[derive(Clone)]
pub struct Daemon {
    inner: Arc<Inner>,
}

impl Daemon {
    pub fn new(load: LoadRegistry, sources: Arc<dyn SourceFactory>, store: StoreFile) -> Self {
        Self {
            inner: Arc::new(Inner {
                load,
                sources,
                store,
                store_io: tokio::sync::Mutex::new(()),
                proton_connect: tokio::sync::Mutex::new(()),
                state: Mutex::new(State {
                    phase: Phase::Locked,
                    generation: 0,
                    locks: 0,
                }),
                audit: None,
                proofs: None,
                approvals: Mutex::new(Approvals::default()),
                approvals_changed: watch::channel(0).0,
                tailnet: None,
                remote: Mutex::new(Remote::default()),
                remote_changed: tokio::sync::Notify::new(),
                phone: Mutex::new(phone::Phone::default()),
                push: None,
                phone_woken: tokio::sync::Notify::new(),
                phone_seq: watch::channel(0).0,
            }),
        }
    }

    /// Asks `api` which machine a grant names. Call it before cloning the
    /// daemon.
    #[expect(
        clippy::expect_used,
        reason = "set up once at startup, before any clone; a second owner is a programming error"
    )]
    pub fn with_tailnet(mut self, api: Arc<dyn LocalApi>) -> Self {
        Arc::get_mut(&mut self.inner)
            .expect("with_tailnet is called before the daemon is cloned")
            .tailnet = Some(api);
        self
    }

    /// Tells the paired phone of a request that waits through `service`,
    /// keeping what that takes in `state`. Call it before cloning the
    /// daemon.
    #[expect(
        clippy::expect_used,
        reason = "set up once at startup, before any clone; a second owner is a programming error"
    )]
    pub fn with_push(mut self, service: Arc<dyn PushService>, state: PushState) -> Self {
        Arc::get_mut(&mut self.inner)
            .expect("with_push is called before the daemon is cloned")
            .push = Some(phone::Push { service, state });
        self
    }

    /// Whether the store turns the remote endpoint on; `None` until a store
    /// has been read.
    pub fn remote_enabled(&self) -> Option<bool> {
        self.inner.remote().enabled
    }

    /// Waits until the store may have turned the remote endpoint on or off.
    pub async fn remote_changed(&self) {
        self.inner.remote_changed.notified().await;
    }

    /// What the remote endpoint's supervisor found: where it listens, or
    /// why it does not.
    pub fn set_remote_listening(
        &self,
        listening: Option<std::net::SocketAddr>,
        problem: Option<String>,
    ) {
        let mut r = self.inner.remote();
        r.listening = listening;
        r.problem = problem;
    }

    /// The port `[remote] port` in `config.toml` names, or why it cannot
    /// be read.
    pub fn remote_port(&self) -> Result<u16, String> {
        self.registry()
            .map(|r| r.config.remote.port)
            .map_err(|e| format!("the configuration does not load: {e}"))
    }

    /// Remembers whether `store` turns the remote endpoint on.
    fn note_remote(&self, store: &Store) {
        let enabled = store.remote_enabled();
        let changed = self.inner.remote().enabled.replace(enabled) != Some(enabled);
        if changed {
            self.inner.remote_changed.notify_one();
        }
    }

    /// `None` until a store has been read: nothing is known about it.
    fn remote_status(&self) -> Option<RemoteStatus> {
        let grants = match self.unlocked_store() {
            Some(Some(st)) => st.remote_grants().iter().map(Into::into).collect(),
            _ => Vec::new(),
        };
        let r = self.inner.remote();
        r.enabled.map(|enabled| RemoteStatus {
            enabled: Some(enabled),
            listening: r.listening.map(|a| a.to_string()),
            problem: r.problem.clone(),
            grants,
        })
    }

    /// Records requests in `log`; see [`Self::handle_from`]. Call it
    /// before cloning the daemon.
    #[expect(
        clippy::expect_used,
        reason = "set up once at startup, before any clone; a second owner is a programming error"
    )]
    pub fn with_audit(mut self, log: AuditLog) -> Self {
        Arc::get_mut(&mut self.inner)
            .expect("with_audit is called before the daemon is cloned")
            .audit = Some(log);
        self
    }

    /// Keeps each environment's proof in `proofs`. Call it before cloning
    /// the daemon.
    #[expect(
        clippy::expect_used,
        reason = "set up once at startup, before any clone; a second owner is a programming error"
    )]
    pub fn with_proofs(mut self, proofs: Proofs) -> Self {
        Arc::get_mut(&mut self.inner)
            .expect("with_proofs is called before the daemon is cloned")
            .proofs = Some(proofs);
        self
    }

    pub fn is_locked(&self) -> bool {
        matches!(self.inner.state().phase, Phase::Locked)
    }

    /// Answers the requests that involve daemon state, from `caller`. The
    /// server answers `hello`, `ping` and `whoami` itself.
    ///
    /// Every caller gets the same policy. Any process of this user can reach
    /// the socket, so nothing about a connection shows a human is asking;
    /// what only a human may do needs the store passphrase in the request:
    ///
    /// | Request                                   | Policy                        |
    /// |-------------------------------------------|-------------------------------|
    /// | status, diff, run, lock                   | allowed                       |
    /// | sync, store list                          | allowed; no values            |
    /// | unlock                                    | passphrase, if a store exists |
    /// | store set, unset, mark, passwd            | passphrase                    |
    /// | store import                              | passphrase, or approval in the app |
    /// | store ask                                 | values and passphrase typed in the app |
    /// | mark or unmark an environment or secret   | passphrase                    |
    /// | get                                       | passphrase                    |
    /// | a value marked sensitive, to run or get   | approval in the app, or on the paired phone |
    /// | inspect, reveal (the app's view)          | passphrase; sensitive too     |
    /// | wait for approvals, approve or deny       | allowed; approving takes the passphrase |
    ///
    /// Approval: a `run` or `get` that would hand out a value marked
    /// sensitive waits, for at most `approval_timeout`, until a person
    /// types the store passphrase into the app's prompt for it, approves
    /// it on the paired phone with its passkey (`broker::phone`), or denies
    /// it in either place. If the app is not open, it is refused at once.
    /// A `store import` sent with no passphrase waits the same way, in the
    /// app alone: the prompt names each section, file and key, and the
    /// passphrase typed there does the write, and unlocks a locked daemon.
    /// A `store ask` waits that way too, for the values as well: it sends
    /// none, and the prompt has a field for each key it names.
    ///
    /// With an audit log, records every denial, and every request that
    /// changes state or prints a value, before replying; if a hand-out
    /// cannot be recorded, its values are not handed out. A `run` that
    /// hands out values without an approval is recorded in the runs log
    /// beside it instead, and goes ahead when that cannot be written: it
    /// is a record of use, not a control.
    /// An approval prompt is recorded when it is shown, and the request's
    /// entry says whether it was approved, denied or timed out.
    pub async fn handle_from(&self, req: Request, caller: &Caller) -> Response {
        let mut asked = Asked::of(&req);
        // Every request from another machine is recorded, allowed or not.
        if let Some(asked) = asked.as_mut().filter(|_| caller.remote.is_some()) {
            asked.always = true;
        }
        let approval = Mutex::new(None);
        let response = self.answer(req, caller, &approval).await;
        let approval = approval
            .into_inner()
            .unwrap_or_else(PoisonError::into_inner);
        match asked {
            Some(asked) => self.audit(asked, caller, approval, response),
            None => response,
        }
    }

    fn audit(
        &self,
        mut asked: Asked,
        caller: &Caller,
        approval: Option<Decision>,
        response: Response,
    ) -> Response {
        let Some(log) = &self.inner.audit else {
            return response;
        };
        let (decision, reason) = match &response {
            Response::Error(e) if approval == Some(Decision::TimedOut) => {
                (Decision::TimedOut, Some(e.message.clone()))
            }
            Response::Error(e) => (Decision::Denied, Some(e.message.clone())),
            _ => (Decision::Allowed, None),
        };
        // A request that waited for approval is always recorded.
        asked.always |= approval.is_some();
        // Allowed, and not what the audit log records whatever the answer.
        let routine = decision == Decision::Allowed && !asked.always;
        if routine && !asked.handover {
            return response;
        }
        let registry = self.registry().ok();
        let mut event = Event::new(asked.action, decision, caller);
        event.reason = reason;
        event.keys = asked.keys;
        event.program = asked.program;
        event.target = asked.target;
        (event.project, event.env) = (asked.project, asked.env.clone());
        // The names the daemon resolved, when it got that far.
        if let (Some(registry), Some(facts)) = (&registry, &asked.facts)
            && let Ok(found) = registry.find(facts.place())
        {
            let project = found.project;
            event.project = Some(project.name.clone());
            event.env = registry
                .env(project, asked.env.as_ref())
                .map(|s| s.env)
                .ok()
                .or(asked.env);
        }
        if let Response::Listed { read, .. } = &response {
            event.keys.clone_from(read);
        }
        // The keys a person typed, not every key asked for.
        if let Response::StoreTyped { section, set, .. } = &response {
            event.keys = set.iter().map(|k| format!("{section}.{k}")).collect();
        }
        if let Response::RunEnv(reply) = &response {
            event.project = Some(reply.project.clone());
            event.env = Some(reply.env.clone());
            event.keys = reply.vars.iter().map(|v| v.key.to_string()).collect();
        }
        if routine {
            let runs = log.runs();
            if let Err(e) = runs.append(&event) {
                warn!(error = %e, path = %runs.path().display(), "cannot write the runs log");
            }
            return response;
        }
        match log.append(&event) {
            Ok(()) => response,
            Err(e) => {
                warn!(error = %e, path = %log.path().display(), "cannot write the audit log");
                if asked.handover && decision == Decision::Allowed {
                    // Dropping the reply zeroes the values in it.
                    Response::Error(WireError::new(
                        ErrorCode::Internal,
                        format!(
                            "values are handed out only once the audit log records it, and {} cannot be written: {e}",
                            log.path().display()
                        ),
                    ))
                } else {
                    response
                }
            }
        }
    }

    /// [`Self::handle_from`] for this process.
    #[cfg(test)]
    pub async fn handle(&self, req: Request) -> Response {
        self.handle_from(req, &crate::test_support::this_process())
            .await
    }

    async fn answer(
        &self,
        req: Request,
        caller: &Caller,
        approval: &Mutex<Option<Decision>>,
    ) -> Response {
        if let Some(peer) = &caller.remote {
            return self.answer_remote(req, caller, peer, approval).await;
        }
        let result = match req {
            Request::Status { facts } => self.status(facts).await.map(|mut report| {
                report.app = self.inner.approvals().app_open();
                report.remote = self.remote_status();
                report.phone = self.phone_status();
                report.waiting = self.waiting();
                report.acknowledged = self.acknowledged();
                report.shared = self.shared(&report.waiting);
                Response::Status(report)
            }),
            Request::RemoteEnable {
                enabled,
                passphrase,
            } => {
                self.store_write(passphrase.into_passphrase(), None, move |st| {
                    Ok(st.set_remote_enabled(enabled))
                })
                .await
            }
            Request::RemoteGrant {
                machine,
                project,
                envs,
                expires,
                passphrase,
            } => match self.grant_for(&machine, project, envs, expires).await {
                Ok(mut grant) => {
                    self.token_write(passphrase.into_passphrase(), move |st, token| {
                        grant.token = Some(token);
                        let machine = grant.machine.clone();
                        Ok((st.grant_remote(grant), machine))
                    })
                    .await
                }
                Err(e) => Err(e),
            },
            Request::RemoteRotate {
                machine,
                project,
                passphrase,
            } => {
                self.token_write(passphrase.into_passphrase(), move |st, token| {
                    st.rotate_remote(&machine, &project, token)
                })
                .await
            }
            Request::RemoteRevoke {
                machine,
                project,
                passphrase,
            } => {
                self.store_write(passphrase.into_passphrase(), None, move |st| {
                    st.revoke_remote(&machine, project.as_ref())
                })
                .await
            }
            Request::Phones => self.phones().await,
            Request::PhonePair {
                machine,
                passphrase,
            } => {
                self.phone_pair(&machine, passphrase.into_passphrase())
                    .await
            }
            Request::PhonePairStop => Ok(self.phone_pair_stop()),
            Request::PhoneUnpair { passphrase } => {
                let unpaired = self
                    .store_write(passphrase.into_passphrase(), None, Store::unpair_phone)
                    .await;
                if unpaired.is_ok() {
                    self.forget_push();
                }
                unpaired
            }
            Request::WaitApprovals { known } => Ok(self.wait_approvals(known, caller).await),
            Request::Approve {
                id,
                passphrase,
                values,
            } => self
                .approve(id, passphrase.map(WireSecret::into_passphrase), values)
                .await
                .map(|pending| Response::Approvals { pending }),
            Request::Inspect { facts, passphrase } => self
                .inspect(&facts, passphrase.into_passphrase())
                .await
                .map(Response::Status),
            Request::Reveal {
                facts,
                key,
                passphrase,
            } => self
                .reveal(&facts, &key, passphrase.into_passphrase())
                .await
                .map(|value| Response::Value { value }),
            Request::Diff { facts } => self.diff(&facts).await.map(Response::Diff),
            Request::CheckProject {
                project,
                text,
                example_keys,
                example_values,
            } => self
                .check_project(project, &text, example_keys, example_values)
                .await
                .map(Response::Checked),
            Request::List {
                provider,
                prefix,
                search,
                aws,
                keys,
            } => self
                .list(provider, &prefix, search.as_deref(), aws, keys)
                .await
                .map(|(items, warnings, read)| Response::Listed {
                    items,
                    warnings,
                    read,
                }),
            Request::Providers { facts, every } => Ok(Response::Providers {
                providers: self.providers(facts.as_ref(), every).await,
            }),
            Request::Sync { project, env } => self.sync(project, env).await.map(Response::Sync),
            Request::Lock => {
                self.lock();
                Ok(Response::LockState {
                    locked: true,
                    warnings: Vec::new(),
                })
            }
            Request::Unlock { passphrase } => self
                .unlock(passphrase.map(WireSecret::into_passphrase))
                .await
                .map(|warnings| Response::LockState {
                    locked: false,
                    warnings,
                }),
            Request::StoreSet {
                section,
                key,
                value,
                passphrase,
                sensitive,
            } => {
                let value = value.into_value();
                self.store_write(passphrase.into_passphrase(), None, move |st| {
                    let change = st.set(section.clone(), key.clone(), value);
                    if sensitive {
                        st.mark(&section, &key, true)?;
                    }
                    Ok(change)
                })
                .await
            }
            Request::StoreSetMany {
                sections,
                passphrase,
            } => {
                let values: Vec<_> = sections
                    .into_iter()
                    .flat_map(|(section, values)| {
                        values
                            .into_iter()
                            .map(move |(k, v)| (section.clone(), k, v.into_value()))
                    })
                    .collect();
                self.store_write(passphrase.into_passphrase(), None, move |st| {
                    for (section, key, value) in values {
                        st.set(section, key, value);
                    }
                    Ok(Change::Added)
                })
                .await
            }
            Request::StoreImport {
                sections,
                passphrase,
                cwd,
                command,
            } => {
                let passphrase = passphrase.map(WireSecret::into_passphrase);
                self.store_import(sections, passphrase, (caller, cwd, command), approval)
                    .await
            }
            Request::StoreAsk {
                section,
                keys,
                cwd,
                command,
            } => {
                self.store_ask(section, keys, (caller, cwd, command), approval)
                    .await
            }
            Request::StoreMark {
                section,
                key,
                sensitive,
                passphrase,
            } => {
                self.store_write(passphrase.into_passphrase(), None, move |st| {
                    st.mark(&section, &key, sensitive)
                })
                .await
            }
            Request::MarkEnv {
                project,
                env,
                sensitive: false,
                passphrase,
                ..
            } => {
                self.store_write(passphrase.into_passphrase(), None, move |st| {
                    Ok(st.mark_env(Section { project, env }, false))
                })
                .await
            }
            Request::MarkEnv {
                project,
                env,
                sensitive: true,
                also,
                passphrase,
            } => {
                let marks = self.source_marks(&project, &env).await;
                match (marks, self.registry()) {
                    (Ok(marks), Ok(registry)) => {
                        // Those a fetch found; the rest are read from the
                        // project files once the store is open.
                        let waiting = self.waiting();
                        self.store_write(passphrase.into_passphrase(), None, move |st| {
                            let section = Section { project, env };
                            mark_env_with_sources(st, &registry, section, marks, waiting, also)
                        })
                        .await
                    }
                    (Err(e), _) | (_, Err(e)) => Err(e),
                }
            }
            Request::AcknowledgeEnv {
                project,
                env,
                acknowledged,
                unmark,
                passphrase,
            } => {
                self.store_write(passphrase.into_passphrase(), None, move |st| {
                    for secret in unmark {
                        st.mark_secret(secret, false)?;
                    }
                    Ok(st.acknowledge_env(Section { project, env }, acknowledged))
                })
                .await
            }
            Request::AcknowledgeEnvs { envs, passphrase } => {
                self.store_write(passphrase.into_passphrase(), None, move |st| {
                    let mut change = Change::Marked;
                    for env in envs {
                        change = st.acknowledge_env(env, true);
                    }
                    Ok(change)
                })
                .await
            }
            Request::MarkSecret {
                secret,
                sensitive,
                passphrase,
            } => {
                self.store_write(passphrase.into_passphrase(), None, move |st| {
                    st.mark_secret(secret, sensitive)
                })
                .await
            }
            Request::UnmarkSecrets {
                secrets,
                passphrase,
            } => {
                self.store_write(passphrase.into_passphrase(), None, move |st| {
                    let mut change = Change::Marked;
                    for secret in secrets {
                        change = st.mark_secret(secret, false)?;
                    }
                    Ok(change)
                })
                .await
            }
            Request::AddMark { target } => self.add_mark(target).await,
            Request::StoreUnset {
                section,
                key,
                passphrase,
            } => {
                self.store_write(passphrase.into_passphrase(), None, move |st| {
                    st.unset(&section, &key)
                })
                .await
            }
            Request::StoreClear {
                project,
                passphrase,
            } => {
                self.store_write(passphrase.into_passphrase(), None, move |st| {
                    st.clear_project(&project)
                })
                .await
            }
            Request::ProtonConnect {
                token,
                expires,
                passphrase,
            } => {
                self.proton_connect(token.into_value(), expires, passphrase.into_passphrase())
                    .await
            }
            Request::StorePasswd {
                passphrase,
                new_passphrase,
            } => {
                let new = new_passphrase.into_passphrase();
                self.store_write(passphrase.into_passphrase(), Some(new), |_| {
                    Ok(Change::Rekeyed)
                })
                .await
            }
            Request::StoreList => self.store_list().map(Response::StoreList),
            Request::Proven { facts, program } => self.prove(&facts, &program),
            Request::RunEnv {
                facts,
                program,
                command,
            } => {
                let ask = Ask {
                    action: "run",
                    caller,
                    cwd: &facts.cwd,
                    command: shown_command(&command, program.as_deref()),
                    argv: command,
                    program,
                    approval,
                };
                self.run_env_for(&facts, &ask).await.map(Response::RunEnv)
            }
            Request::Get {
                facts,
                key,
                passphrase,
            } => {
                let ask = Ask {
                    action: "get",
                    caller,
                    cwd: &facts.cwd,
                    program: None,
                    command: format!("kagebunshin get {key}"),
                    argv: vec!["kagebunshin".into(), "get".into(), key.to_string()],
                    approval,
                };
                self.get_for(&facts, &key, passphrase.into_passphrase(), &ask)
                    .await
                    .map(|value| Response::Value { value })
            }
            Request::Hello { .. } | Request::Ping | Request::Whoami => {
                return Response::Error(WireError::new(
                    ErrorCode::BadRequest,
                    "not a daemon state request",
                ));
            }
        };
        result.unwrap_or_else(|e| Response::Error(wire_error(&e)))
    }

    /// [`Self::answer`] for a caller on another machine: `run`, `status`
    /// and `diff` only, never while locked, and only for an environment a
    /// grant to its node covers. What it reports (its checkout, folder and
    /// command line) is taken as given: the grant decides, not those. The
    /// grant is checked again before the reply goes out, so one revoked,
    /// narrowed or ended while the request waited gets nothing, and so does
    /// a reply about another environment, after a project file changed.
    async fn answer_remote(
        &self,
        req: Request,
        caller: &Caller,
        peer: &RemotePeer,
        approval: &Mutex<Option<Decision>>,
    ) -> Response {
        let action = Asked::of(&req).map_or("that", |a| a.action);
        // Turned off while it was connected.
        if self.remote_enabled() != Some(true) {
            return Response::Error(wire_error(&ResolveError::Remote {
                message: "the remote endpoint is off".into(),
                hint: None,
            }));
        }
        let mut req = req;
        // Its checkout root is a path on its machine: matching a project's
        // `path` under it here would look this machine's files up for it.
        if let Request::RunEnv { facts, .. }
        | Request::Status { facts: Some(facts) }
        | Request::Diff { facts } = &mut req
        {
            facts.root = None;
        }
        let result = match req {
            Request::RunEnv {
                mut facts,
                program,
                command,
            } => match self.check_grant(peer, &mut facts) {
                Ok(granted) => {
                    let ask = Ask {
                        action: "run",
                        caller,
                        cwd: &facts.cwd,
                        command: shown_command(&command, program.as_deref()),
                        argv: command,
                        program,
                        approval,
                    };
                    self.run_env_for(&facts, &ask).await.and_then(|reply| {
                        self.still_granted(peer, &granted, &reply.project, &reply.env)?;
                        Ok(Response::RunEnv(reply))
                    })
                }
                Err(e) => Err(e),
            },
            Request::Status { facts: None } => self.live_grants(peer).map(|_| {
                Response::Status(StatusReport {
                    locked: false,
                    env: None,
                    expiring: Vec::new(),
                    remote: None,
                    waiting: Vec::new(),
                    acknowledged: Vec::new(),
                    shared: Vec::new(),
                    app: false,
                    phone: None,
                })
            }),
            Request::Status {
                facts: Some(mut facts),
            } => match self.check_grant(peer, &mut facts) {
                Ok(granted) => self.status(Some(facts)).await.and_then(|mut report| {
                    if let Some(env) = &report.env {
                        self.still_granted(peer, &granted, &env.project, &env.env)?;
                    }
                    // This machine's own business.
                    report.expiring.clear();
                    report.remote = None;
                    if let Some(env) = &mut report.env {
                        self.waiting_said_remotely(&mut env.warnings, &env.project, &env.env);
                    }
                    Ok(Response::Status(report))
                }),
                Err(e) => Err(e),
            },
            Request::Diff { mut facts } => match self.check_grant(peer, &mut facts) {
                Ok(granted) => self.diff(&facts).await.and_then(|mut report| {
                    self.still_granted(peer, &granted, &report.project, &report.env)?;
                    self.waiting_said_remotely(&mut report.warnings, &report.project, &report.env);
                    Ok(Response::Diff(report))
                }),
                Err(e) => Err(e),
            },
            _ => Err(ResolveError::Remote {
                message: format!(
                    "machine {} asked for {}, which only this machine may ask for; \
                     remotely, only run, status and diff work",
                    peer.machine, action
                ),
                hint: None,
            }),
        };
        result.unwrap_or_else(|e| Response::Error(remote_wire_error(&e)))
    }

    /// The environment `facts` name, if a grant to `peer`'s node covers it
    /// now. Refused while locked, and, before anything about this machine's
    /// projects is said, for a node with no grant at all.
    ///
    /// `--project` names the project outright, from a plain folder too, and
    /// `facts` are then that project's. Locally a checkout's remotes keep an
    /// agent in one repository from asking for another's project; a remote
    /// caller's remotes are only what it reports, and its grants say which
    /// projects it may use. Of a project no grant of its names nothing is
    /// said, not even whether there is one.
    fn check_grant(&self, peer: &RemotePeer, facts: &mut Facts) -> Result<EnvKey, ResolveError> {
        let (registry, grants) = self.live_grants(peer)?;
        let now = crate::source::unix_now();
        match &facts.project {
            Some(name) if !grants.iter().any(|g| g.project == *name) => {
                return Err(ResolveError::Remote {
                    message: format!(
                        "machine {} has no remote grant for project {name}",
                        peer.machine
                    ),
                    hint: Some(format!(
                        "on the daemon's machine, run `kagebunshin remote grant {} {name} <env>`",
                        peer.machine
                    )),
                });
            }
            Some(name) => {
                if let Some(project) = registry.project(name) {
                    facts.remotes.clone_from(&project.file.remotes);
                }
            }
            None if facts.remotes.is_empty() => {
                return Err(ResolveError::Remote {
                    message: format!(
                        "machine {} named no project, and {} is not a checkout with a git remote \
                         to find one by",
                        peer.machine,
                        facts.cwd.display()
                    ),
                    hint: Some("name the project with `--project`".into()),
                });
            }
            None => {}
        }
        let found = registry
            .find(facts.place())
            .map_err(|e| ResolveError::NoProject(e.to_string()))?;
        let settings = registry
            .env(found.project, facts.env.as_ref())
            .map_err(|e| ResolveError::Config(e.to_string()))?;
        let key = (settings.project.clone(), settings.env.clone());
        if !grants
            .iter()
            .any(|g| g.covers(&peer.node, &key.0, &key.1, now))
        {
            return Err(ResolveError::Remote {
                message: format!(
                    "machine {} has no remote grant for environment {} of project {}",
                    peer.machine, key.1, key.0
                ),
                hint: Some(format!(
                    "on the daemon's machine, run `kagebunshin remote grant {} {} {}`",
                    peer.machine, key.0, key.1
                )),
            });
        }
        Ok(key)
    }

    /// Rewords, for a remote caller, the warning among `warnings` that `env`
    /// of `project` waits for a human decision: it is made on this machine.
    fn waiting_said_remotely(&self, warnings: &mut [String], project: &ProjectName, env: &EnvName) {
        for w in self.waiting() {
            if w.project != *project || w.env != *env {
                continue;
            }
            let local = waiting_message(project, env, &w.why);
            for warning in warnings.iter_mut().filter(|s| **s == local) {
                *warning = waiting_message_remote(project, env, &w.why);
            }
        }
    }

    /// Refuses a remote reply unless it is about the environment
    /// [`Self::check_grant`] found and a grant to `peer`'s node still
    /// covers it: the grant may have been revoked, narrowed or have ended
    /// while the request waited on a fetch or a prompt.
    fn still_granted(
        &self,
        peer: &RemotePeer,
        granted: &EnvKey,
        project: &ProjectName,
        env: &EnvName,
    ) -> Result<(), ResolveError> {
        same_env(granted, project, env)?;
        let (_, grants) = self.live_grants(peer)?;
        let now = crate::source::unix_now();
        if grants
            .iter()
            .any(|g| g.covers(&peer.node, project, env, now))
        {
            return Ok(());
        }
        Err(ResolveError::Remote {
            message: format!(
                "machine {} no longer has a remote grant for environment {env} of project \
                 {project}",
                peer.machine
            ),
            hint: None,
        })
    }

    /// The grants to `peer`'s node that have not ended and whose token is
    /// the one `peer` sent, with the registry to check them against. Being
    /// that machine on the tailnet is not enough: a grant is used with its
    /// own token, and one with none (made before grants had tokens) by
    /// nobody. Refused while locked, and for a node with no such grant,
    /// before anything about this machine is said.
    fn live_grants(&self, peer: &RemotePeer) -> Result<(Registry, Vec<RemoteGrant>), ResolveError> {
        let (registry, store) = self.marks()?;
        let now = crate::source::unix_now();
        let mut grants: Vec<RemoteGrant> = store
            .as_deref()
            .map(|st| {
                st.remote_grants()
                    .iter()
                    .filter(|g| g.node == peer.node && g.expires.is_none_or(|end| now < end))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        if grants.is_empty() {
            return Err(ResolveError::Remote {
                message: format!("machine {} has no remote grant", peer.machine),
                hint: Some(format!(
                    "on the daemon's machine, run `kagebunshin remote grant {} <project> <env>`",
                    peer.machine
                )),
            });
        }
        let Some(sent) = peer.token else {
            return Err(ResolveError::Remote {
                message: format!(
                    "machine {} sent no token, and a remote grant is used with its token",
                    peer.machine
                ),
                hint: Some(format!(
                    "set {} to the token `kagebunshin remote grant` printed on the daemon's \
                     machine",
                    crate::ipc::protocol::REMOTE_TOKEN_ENV
                )),
            });
        };
        // Every grant is compared, whichever matches.
        grants.retain(|g| g.token.is_some_and(|t| t == sent));
        if grants.is_empty() {
            return Err(ResolveError::Remote {
                message: format!(
                    "the token machine {} sent is not the token of a remote grant it has",
                    peer.machine
                ),
                hint: Some(format!(
                    "on the daemon's machine, run `kagebunshin remote rotate {} <project>` for a \
                     new one",
                    peer.machine
                )),
            });
        }
        Ok((registry, grants))
    }

    /// The grant `remote grant` saves: `machine` as the local tailscaled
    /// names exactly one peer, by that peer's stable node id.
    async fn grant_for(
        &self,
        machine: &str,
        project: ProjectName,
        mut envs: Vec<EnvName>,
        expires: Option<u64>,
    ) -> Result<RemoteGrant, ResolveError> {
        envs.sort();
        envs.dedup();
        if envs.is_empty() {
            return Err(ResolveError::Config(
                "a remote grant names at least one environment".into(),
            ));
        }
        if expires.is_some_and(|end| end <= crate::source::unix_now()) {
            return Err(ResolveError::Config(
                "the remote grant's end date has passed".into(),
            ));
        }
        let registry = self.registry()?;
        let p = registry
            .project(&project)
            .ok_or_else(|| ResolveError::Config(format!("there is no project {project}")))?;
        for env in &envs {
            registry
                .env(p, Some(env))
                .map_err(|e| ResolveError::Config(e.to_string()))?;
        }
        let api =
            self.inner.tailnet.clone().ok_or_else(|| {
                ResolveError::Internal("this daemon does not ask Tailscale".into())
            })?;
        let status =
            crate::tailnet::status(api.as_ref())
                .await
                .map_err(|e| ResolveError::Provider {
                    message: format!("cannot ask Tailscale which machine {machine} is: {e}"),
                    hint: Some("is Tailscale installed and running on this machine?".into()),
                })?;
        let peer = match status.peers_named(machine).as_slice() {
            [peer] if !peer.machine.is_empty() => (*peer).clone(),
            [] | [_] => {
                return Err(ResolveError::Config(format!(
                    "no other machine on this tailnet is named {machine}"
                )));
            }
            _ => {
                return Err(ResolveError::Config(format!(
                    "more than one machine on this tailnet is named {machine}; \
                     give its full MagicDNS name"
                )));
            }
        };
        Ok(RemoteGrant {
            machine: peer.machine,
            node: peer.node,
            project,
            envs,
            // The write gives it one.
            token: None,
            expires,
        })
    }

    /// Unlocks and starts the idle timer. If a local store exists it is
    /// decrypted with `passphrase` first; without one, or with the wrong
    /// one, the daemon stays locked. Unlocking an unlocked daemon changes
    /// nothing, not even the idle deadline, and ignores the passphrase.
    /// A lock that arrives while the store is decrypted wins: the daemon
    /// stays locked and this fails as locked. Must run inside a tokio
    /// runtime.
    ///
    /// Replies with a warning for each environment that looks like
    /// production and waits for a human to mark it sensitive or
    /// acknowledge it is not production.
    pub async fn unlock(
        &self,
        passphrase: Option<Passphrase>,
    ) -> Result<Vec<String>, ResolveError> {
        // Before loading the configuration, so a lock that arrives while it
        // loads is seen.
        let locks = {
            let st = self.inner.state();
            (!matches!(st.phase, Phase::Unlocked(_))).then_some(st.locks)
        };
        let registry = self.registry()?;
        let Some(locks) = locks else {
            let (_, store) = self.marks()?;
            return Ok(unmarked_warnings(&registry, store.as_deref()));
        };
        let idle = registry.config.idle_timeout.get();
        let _io = self.inner.store_io.lock().await;
        let file = self.inner.store.clone();
        let mut moved = Vec::new();
        let (envs, secrets) = file_flags(&registry);
        let store = match (file.exists()?, passphrase) {
            (false, _) if !envs.is_empty() || !secrets.is_empty() => {
                return Err(ResolveError::Config(
                    "project files mark something sensitive, and marks are kept in the local \
                     store; create it with `kagebunshin store init`"
                        .into(),
                ));
            }
            (false, _) => None,
            (true, None) => return Err(StoreError::PassphraseRequired.into()),
            (true, Some(p)) => {
                let p = Arc::new(p);
                let opened = {
                    let (file, p) = (file.clone(), p.clone());
                    blocking(move || file.open(&p)).await?
                };
                let opened = copy_flags(
                    opened,
                    &registry,
                    &file,
                    p.clone(),
                    envs,
                    secrets,
                    &mut moved,
                )
                .await?;
                // Marks added with no passphrase since the last write: any
                // write moves them into the store, so one that changes
                // nothing does.
                let opened = if file.marks_wait() {
                    let file = file.clone();
                    let ((), store) = blocking(move || file.update(&p, None, |_| Ok(()))).await?;
                    info!("wrote the marks added from the command line to the local store");
                    store
                } else {
                    opened
                };
                self.note_remote(&opened);
                Some(Arc::new(opened))
            }
        };
        if registry.config.strict_memory
            && store.as_deref().is_some_and(|s| !store_in_locked_memory(s))
        {
            return Err(ResolveError::Memory("to unlock the local store".into()));
        }
        let mut warnings = unmarked_warnings(&registry, store.as_deref());
        warnings.extend(moved);
        self.start_session(idle, store, locks)?;
        Ok(warnings)
    }

    /// What marking `project`'s `env` sensitive may also mark, so its
    /// sources stay marked wherever they are copied: each secret a source
    /// names, each AWS
    /// prefix, and the Proton keys a source picks now, by stable id. Which
    /// of them an open environment reads too, and so stay unmarked, is
    /// decided when they are written. An environment not configured yet
    /// marks only itself. Fails, writing nothing, if a provider cannot say
    /// what a source reads.
    async fn source_marks(
        &self,
        project: &ProjectName,
        env: &EnvName,
    ) -> Result<SourceMarks, ResolveError> {
        let registry = self.registry()?;
        let mut marks = SourceMarks::default();
        let Some(settings) = registry
            .project(project)
            .and_then(|p| registry.env(p, Some(env)).ok())
        else {
            return Ok(marks);
        };
        let mut proton: Option<Vec<Listed>> = None;
        for spec in &settings.sources {
            if marks.add_local(spec) {
                continue;
            }
            let named: Vec<&String> = match &spec.select {
                Select::Secret { name, .. } => vec![name],
                Select::Secrets(names) => names.iter().collect(),
                Select::Prefix(_) => Vec::new(),
            };
            match (spec.provider, &spec.select) {
                (Provider::File | Provider::AwsSm, _) => {}
                (Provider::Proton, select) => {
                    if proton.is_none() {
                        proton = Some(
                            self.list(Some(Provider::Proton), "", None, spec.aws.clone(), false)
                                .await?
                                .0,
                        );
                    }
                    // By what the source names: a prefix as a whole, a
                    // name on its own.
                    let picked = proton.iter().flatten().filter_map(|l| {
                        let claim = match select {
                            Select::Prefix(p) => l
                                .name
                                .starts_with(p.as_str())
                                .then(|| Claim::under(Provider::Proton, p))?,
                            _ if named.contains(&&l.name) => {
                                Claim::named(Provider::Proton, &l.name)
                            }
                            _ => return None,
                        };
                        Some((claim, l.id.clone()))
                    });
                    marks.secrets.extend(picked);
                }
            }
        }
        Ok(marks)
    }

    /// Moves to unlocked with `store`, unless already unlocked, or locked
    /// again since the caller saw `locks` lock requests.
    fn start_session(
        &self,
        idle: Duration,
        store: Option<Arc<Store>>,
        locks: u64,
    ) -> Result<(), ResolveError> {
        let id = {
            let mut st = self.inner.state();
            if matches!(st.phase, Phase::Unlocked(_)) {
                return Ok(());
            }
            if st.locks != locks {
                debug!("a lock arrived during unlock; staying locked");
                return Err(ResolveError::Locked);
            }
            let id = st.next_generation();
            st.phase = Phase::Unlocked(Session {
                id,
                idle,
                deadline: Instant::now() + idle,
                cache: BTreeMap::new(),
                superseded: Vec::new(),
                store,
                pairing: None,
            });
            id
        };
        tokio::spawn(watch_idle(Arc::downgrade(&self.inner), id));
        self.inner.phone_woken.notify_one();
        info!(idle_timeout = ?idle, "unlocked");
        Ok(())
    }

    /// Drops every cached value and cancels running fetches.
    /// Holds the store lock that unlock and the store requests take, so a
    /// test can interleave a lock with one of them.
    #[cfg(test)]
    pub(super) async fn hold_store_io(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.inner.store_io.lock().await
    }

    pub fn lock(&self) {
        if self.inner.state().lock() {
            info!("locked");
        }
        self.inner.phone_woken.notify_one();
    }

    /// Decrypts the store with `passphrase`, applies `change`, and writes it
    /// back (encrypted with `new_passphrase` if given).
    pub async fn store_write(
        &self,
        passphrase: Passphrase,
        new_passphrase: Option<Passphrase>,
        change: impl FnOnce(&mut Store) -> Result<Change, StoreError> + Send + 'static,
    ) -> Result<Response, ResolveError> {
        let change = self
            .store_update(passphrase, new_passphrase, change)
            .await?;
        info!(?change, "wrote the local store");
        Ok(Response::Store {
            change,
            locked: self.is_locked(),
        })
    }

    /// A store write that gives a remote grant a new token: `change` gets
    /// the token's hash, which is all the store keeps, and says which
    /// machine it is for. The reply carries the token; nothing else ever
    /// does, and it is not logged.
    async fn token_write(
        &self,
        passphrase: Passphrase,
        change: impl FnOnce(&mut Store, TokenHash) -> Result<(Change, String), StoreError>
        + Send
        + 'static,
    ) -> Result<Response, ResolveError> {
        let mut token = crate::store::new_token()
            .map_err(|e| ResolveError::Internal(format!("cannot make a token: {e}")))?;
        let hash = TokenHash::of(&token);
        let (change, machine) = self
            .store_update(passphrase, None, move |st| change(st, hash))
            .await?;
        info!(
            ?change,
            machine, "wrote the local store: a remote grant's token"
        );
        Ok(Response::RemoteGranted {
            change,
            locked: self.is_locked(),
            machine,
            token: WireSecret::new(std::mem::take(&mut *token)),
        })
    }

    /// [`Self::store_write`], giving what `change` gives.
    async fn store_update<T: Send + 'static>(
        &self,
        passphrase: Passphrase,
        new_passphrase: Option<Passphrase>,
        change: impl FnOnce(&mut Store) -> Result<T, StoreError> + Send + 'static,
    ) -> Result<T, ResolveError> {
        let _io = self.inner.store_io.lock().await;
        let file = self.inner.store.clone();
        let (change, store) =
            blocking(move || file.update(&passphrase, new_passphrase.as_ref(), change)).await?;
        // Before anything else can fail: the file says it now.
        self.note_remote(&store);
        let strict = self.registry().is_ok_and(|r| r.config.strict_memory);
        if strict && !store_in_locked_memory(&store) {
            self.lock();
            return Err(ResolveError::Memory(
                "to keep the local store unlocked after writing it; the daemon is now locked"
                    .into(),
            ));
        }
        self.replace_store(store);
        // The paired phone may be another one now, or none.
        self.inner.phone_woken.notify_one();
        self.inner.phone_seq.send_modify(|n| *n += 1);
        Ok(change)
    }

    /// [`Request::AddMark`]: adds a mark to the session's store with no
    /// passphrase. The store file cannot be written without one, so the
    /// mark also goes to the list beside it, which the next write with the
    /// passphrase (an unlock, or any change in the app) moves into the
    /// file.
    ///
    /// Only ever adds, and never against what a human decided with the
    /// passphrase: an environment acknowledged as not production stays
    /// as it is. There is no way from here to remove a mark or acknowledge
    /// an environment.
    async fn add_mark(&self, target: MarkTarget) -> Result<Response, ResolveError> {
        type Write = Box<dyn FnOnce(&mut Store) -> Result<Change, StoreError> + Send>;
        let no_store = || {
            ResolveError::Store(StoreError::Missing {
                path: self.inner.store.path().to_owned(),
            })
        };
        let session = self.unlocked_store().ok_or(ResolveError::Locked)?;
        let session = session.ok_or_else(no_store)?;
        let write: Write = match target {
            MarkTarget::Env { project, env } => {
                let registry = self.registry()?;
                // A human can mark one that is not there yet; here a
                // mistyped name would leave a mark only they can remove.
                if !(registry.project(&project)).is_some_and(|p| p.file.envs.contains_key(&env)) {
                    return Err(ResolveError::UnknownEnv { project, env });
                }
                if session.env_acknowledged(&project, &env) {
                    return Err(ResolveError::Decided(format!(
                        "environment {env} of project {project} is acknowledged as not production"
                    )));
                }
                let marks = self.source_marks(&project, &env).await?;
                let waiting = self.waiting();
                Box::new(move |st| {
                    let section = Section { project, env };
                    mark_env_with_sources(st, &registry, section, marks, waiting, Vec::new())
                })
            }
            MarkTarget::Secret { secret } => {
                let secrets = match secret.provider {
                    Provider::Proton => self.proton_ids(&secret.location).await?,
                    _ => vec![secret],
                };
                Box::new(move |st| {
                    for secret in secrets {
                        st.mark_secret(secret, true)?;
                    }
                    Ok(Change::Marked)
                })
            }
            MarkTarget::Key { section, key } => Box::new(move |st| st.mark(&section, &key, true)),
        };
        let _io = self.inner.store_io.lock().await;
        // As it is now: a write may have replaced it while a provider was
        // asked.
        let store = self.unlocked_store().ok_or(ResolveError::Locked)?;
        let store = store.ok_or_else(no_store)?;
        let (change, marked, added) = blocking(move || {
            let mut marked = store.duplicate()?;
            let change = write(&mut marked)?;
            let added = marked.new_marks(&store);
            Ok((change, marked, added))
        })
        .await?;
        if !added.is_empty() {
            let strict = self.registry().is_ok_and(|r| r.config.strict_memory);
            if strict && !store_in_locked_memory(&marked) {
                return Err(ResolveError::Memory("to mark it while unlocked".into()));
            }
            let file = self.inner.store.clone();
            blocking(move || file.add_waiting(added)).await?;
            // Not if a lock arrived meanwhile: the next unlock reads the
            // list just written.
            self.replace_store(marked);
            info!(
                ?change,
                "added a mark; the local store gets it at its next write"
            );
        }
        Ok(Response::Store {
            change,
            locked: self.is_locked(),
        })
    }

    /// The stable ids of the Proton keys called `name`, a `<vault>/<KEY>`
    /// as a project file selects them: a mark is keyed by those, since a
    /// vault can be renamed. More than one where two items in a vault set
    /// the same key. A name Proton does not have is refused: a mark under
    /// it would hold nothing back and say it did. An id is taken as it is.
    async fn proton_ids(&self, name: &str) -> Result<Vec<Origin>, ResolveError> {
        let (listed, ..) = self
            .list(
                Some(Provider::Proton),
                "",
                None,
                AwsSettings::default(),
                false,
            )
            .await?;
        let ids: Vec<Origin> = listed
            .into_iter()
            .filter(|l| l.name == name || l.id.location == name)
            .map(|l| l.id)
            .collect();
        if ids.is_empty() {
            return Err(ResolveError::Provider {
                message: format!("Proton Pass has no API key named {name}, so nothing was marked"),
                hint: Some(
                    "a Proton key is named <vault>/<KEY>; see them with `kagebunshin list \
                     --provider proton`"
                        .into(),
                ),
            });
        }
        Ok(ids)
    }

    /// `connect proton`, in this order, so a refused passphrase or token
    /// leaves the saved token and the live `pass-cli` session as they were:
    /// proves a human asks, logs in with `token` in a staging session and
    /// lists its vaults, swaps the staging session in, then saves the
    /// token. If the swap or the save fails, the previous session is put
    /// back and the error returned, so the two always match.
    async fn proton_connect(
        &self,
        token: SecretValue,
        expires: Option<u64>,
        passphrase: Passphrase,
    ) -> Result<Response, ResolveError> {
        let _one = self.inner.proton_connect.lock().await;
        let cli = self.inner.sources.pass_cli().cloned().ok_or_else(|| {
            ResolveError::Internal("this daemon does not read Proton Pass".into())
        })?;
        let passphrase = self.prove_human(passphrase).await?;
        let check = SecretValue::new(token.expose().to_owned());
        let staged = tokio::task::spawn_blocking(move || cli.stage(&check))
            .await
            .map_err(|_| ResolveError::Internal("a pass-cli task panicked".into()))?
            .map_err(|e| match e {
                SourceError::NeedsLogin { hint, .. } => ResolveError::Provider {
                    message: crate::source::proton::REFUSED.into(),
                    hint: Some(hint),
                },
                e => ResolveError::Provider {
                    message: e.to_string(),
                    hint: None,
                },
            })?;
        let vaults = staged.vaults;
        let token = ProtonToken { token, expires };
        let _io = self.inner.store_io.lock().await;
        let file = self.inner.store.clone();
        let (change, store) = tokio::task::spawn_blocking(move || {
            staged.swap_then(|| file.update(&passphrase, None, |st| Ok(st.set_proton_token(token))))
        })
        .await
        .map_err(|_| ResolveError::Internal("the pass-cli session swap panicked".into()))?
        .map_err(|e| ResolveError::Provider {
            message: e.to_string(),
            hint: None,
        })??;
        let strict = self.registry().is_ok_and(|r| r.config.strict_memory);
        if strict && !store_in_locked_memory(&store) {
            self.lock();
            return Err(ResolveError::Memory(
                "to keep the local store unlocked after writing it; the daemon is now locked"
                    .into(),
            ));
        }
        self.replace_store(store);
        info!(?change, vaults, "connected Proton Pass");
        Ok(Response::ProtonConnected {
            change,
            locked: self.is_locked(),
            vaults,
        })
    }

    /// Section and key names of the session's store.
    pub fn store_list(&self) -> Result<StoreListing, ResolveError> {
        let st = self.inner.state();
        let Phase::Unlocked(session) = &st.phase else {
            return Err(ResolveError::Locked);
        };
        let Some(store) = &session.store else {
            return Err(StoreError::Missing {
                path: self.inner.store.path().into(),
            }
            .into());
        };
        let sections = store
            .sections()
            .map(|(section, keys)| StoreSection {
                section: section.clone(),
                keys: keys.keys().cloned().collect(),
                sensitive: keys
                    .keys()
                    .filter(|k| store.is_sensitive(section, k))
                    .cloned()
                    .collect(),
            })
            .collect();
        Ok(StoreListing {
            sections,
            sensitive_envs: store.marked_envs().cloned().collect(),
            acknowledged_envs: store.acknowledged_envs().cloned().collect(),
            sensitive_secrets: store.marked_secrets().cloned().collect(),
        })
    }

    /// Makes `store` the session's. A cached environment stays only if it
    /// would be fetched the same with this store ([`fetched_alike`]): one
    /// that reads a section that changed has old values, and one fetched
    /// under other marks may look like production differently. The rest
    /// are dropped as [`Self::sync`] drops them, and so is every fetch
    /// still running, which reads the old store.
    fn replace_store(&self, store: Store) {
        if let Phase::Unlocked(session) = &mut self.inner.state().phase {
            let store = Arc::new(store);
            let old = session.store.replace(store.clone());
            session.superseded.retain(|a| !a.is_finished());
            for (key, slot) in std::mem::take(&mut session.cache) {
                match slot {
                    Slot::Fetching { abort, .. } => session.superseded.push(abort),
                    Slot::Ready(values) => {
                        let stands = old
                            .as_deref()
                            .is_some_and(|old| fetched_alike(&values.sources, old, &store));
                        if stands {
                            session.cache.insert(key, Slot::Ready(values));
                        }
                    }
                }
            }
        }
    }

    pub async fn status(&self, facts: Option<Facts>) -> Result<StatusReport, ResolveError> {
        let Some(facts) = facts.filter(|_| !self.is_locked()) else {
            return Ok(StatusReport {
                locked: self.is_locked(),
                env: None,
                expiring: self.expiring(),
                remote: None,
                waiting: Vec::new(),
                acknowledged: Vec::new(),
                shared: Vec::new(),
                app: false,
                phone: None,
            });
        };
        self.status_of(&facts, Who::Anyone).await
    }

    /// [`Self::status`] for a human, who may see an environment marked
    /// sensitive: key names and origins, still no value.
    pub async fn inspect(
        &self,
        facts: &Facts,
        passphrase: Passphrase,
    ) -> Result<StatusReport, ResolveError> {
        if self.is_locked() {
            return Err(ResolveError::Locked);
        }
        self.prove_human(passphrase).await?;
        self.status_of(facts, Who::Human).await
    }

    async fn status_of(&self, facts: &Facts, who: Who) -> Result<StatusReport, ResolveError> {
        let (key, values, duplicates, _) = self.resolve(facts, who).await?;
        let (registry, store) = self.marks()?;
        let (project, env) = key;
        let vars = self.vars_of(&project, &env)?;
        let waiting = values.waiting((&project, &env), store.as_deref());
        let warnings = [
            waiting.into_iter().collect(),
            values.warnings.clone(),
            duplicates,
        ]
        .concat();
        let proof = self.proof_of(&project, &env);
        let mut env = env_status(
            (project, env),
            facts,
            &values,
            vars,
            warnings,
            store.as_deref(),
            &registry.config.default_env,
        );
        env.proof = proof;
        Ok(StatusReport {
            locked: false,
            env: Some(env),
            expiring: self.expiring(),
            remote: None,
            waiting: Vec::new(),
            acknowledged: Vec::new(),
            shared: Vec::new(),
            app: false,
            phone: None,
        })
    }

    /// [`Request::CheckProject`]: resolves every environment of project
    /// file `text` as project `name`, through the providers directly, so
    /// nothing is cached and the projects installed are not looked at. An
    /// environment marked sensitive is not read. The values are dropped,
    /// zeroed, once each environment's names are taken.
    pub async fn check_project(
        &self,
        name: ProjectName,
        text: &str,
        example_keys: Option<Vec<KeyName>>,
        example_values: Vec<KeyName>,
    ) -> Result<ProjectCheck, ResolveError> {
        // Only what `.env.example` says matters to the fixes: the file is
        // checked wherever it is run from.
        let facts = &Facts {
            cwd: std::path::PathBuf::new(),
            remotes: Vec::new(),
            subdir: None,
            root: None,
            project: None,
            env: None,
            example_keys,
            example_values,
            env_file: None,
        };
        let example_keys = facts.example_keys.as_deref();
        let (registry, store) = self.marks()?;
        let config_error = |e: ConfigError| ResolveError::Config(e.to_string());
        let path = std::path::PathBuf::from(format!("{name}.toml"));
        let project = crate::config::parse_project(&path, text).map_err(config_error)?;
        if project.name != name {
            return Err(ResolveError::Config(format!(
                "{name} is not a project name"
            )));
        }
        let alone = Registry::new(registry.config.clone(), vec![project]).map_err(config_error)?;
        let Some(project) = alone.project(&name) else {
            return Err(ResolveError::Internal("the project checked is gone".into()));
        };
        let patterns = &registry.config.sensitive_source_patterns;
        let example: BTreeSet<&KeyName> = example_keys.into_iter().flatten().collect();
        let store = store.as_ref();
        let envs =
            join_all(project.file.envs.keys().map(|env| {
                let (alone, name, example) = (&alone, &name, &example);
                async move {
                    let failed = |e: &ResolveError| EnvCheck {
                        env: env.clone(),
                        status: None,
                        extra: Vec::new(),
                        conflicts: Vec::new(),
                        waiting: None,
                        error: Some(wire_error(e)),
                    };
                    let settings = match alone.env(project, Some(env)) {
                        Ok(s) => s,
                        Err(e) => return failed(&config_error(e)),
                    };
                    if let Err(e) = refuse_sensitive(name, env, store.map(|s| &**s)) {
                        return failed(&e);
                    }
                    let sources = &settings.sources;
                    let values =
                        match fetch_env(&*self.inner.sources, name, env, sources, store, patterns)
                            .await
                        {
                            Ok(v) => v,
                            Err(e) => return failed(&e),
                        };
                    let waiting = values.waiting((name, env), store.map(|s| &**s));
                    let extra = match example_keys {
                        Some(_) => values
                            .keys
                            .keys()
                            .filter(|k| !example.contains(k))
                            .cloned()
                            .collect(),
                        None => Vec::new(),
                    };
                    let conflicts = values
                        .keys
                        .iter()
                        .filter(|(_, r)| !r.overridden.is_empty())
                        .map(|(key, r)| Conflict {
                            key: key.clone(),
                            origin: r.origin.clone(),
                            overridden: r.overridden.clone(),
                        })
                        .collect();
                    let warnings = [
                        values.warnings.clone(),
                        duplicate_warnings(name, env, sources),
                    ]
                    .concat();
                    let status = env_status(
                        (name.clone(), env.clone()),
                        facts,
                        &values,
                        settings.vars,
                        warnings,
                        store.map(|s| &**s),
                        &alone.config.default_env,
                    );
                    EnvCheck {
                        env: env.clone(),
                        status: Some(status),
                        extra,
                        conflicts,
                        waiting,
                        error: None,
                    }
                }
            }))
            .await;
        Ok(ProjectCheck {
            project: name,
            envs,
        })
    }

    /// The local store while the daemon is unlocked (`Some(None)` when
    /// there is none); `None` while it is locked.
    #[expect(
        clippy::option_option,
        reason = "callers tell locked (None) from unlocked without a store (Some(None))"
    )]
    fn unlocked_store(&self) -> Option<Option<Arc<Store>>> {
        match &self.inner.state().phase {
            Phase::Unlocked(session) => Some(session.store.clone()),
            Phase::Locked => None,
        }
    }

    /// Every secret that more than one environment reads, while unlocked;
    /// `waiting` are the environments [`Self::waiting`] gives.
    fn shared(&self, waiting: &[WaitingEnv]) -> Vec<SharedSecret> {
        match self.marks() {
            Ok((registry, store)) => shared_secrets(&registry, store.as_deref(), waiting),
            Err(_) => Vec::new(),
        }
    }

    /// Every environment acknowledged as not production, while unlocked.
    fn acknowledged(&self) -> Vec<Section> {
        match self.marks() {
            Ok((_, Some(store))) => store.acknowledged_envs().cloned().collect(),
            _ => Vec::new(),
        }
    }

    /// Every environment that waits for a human decision, while unlocked:
    /// those the project files show look like production, and those a
    /// fetch found do (a name read under a listed prefix), in order.
    fn waiting(&self) -> Vec<WaitingEnv> {
        let Ok((registry, store)) = self.marks() else {
            return Vec::new();
        };
        let mut out = waiting_envs(&registry, store.as_deref());
        let cached: Vec<_> = {
            let st = self.inner.state();
            let Phase::Unlocked(session) = &st.phase else {
                return Vec::new();
            };
            session
                .cache
                .iter()
                .filter_map(|((project, env), slot)| match slot {
                    Slot::Ready(values) => values
                        .waiting((project, env), store.as_deref())
                        .and(values.prod_like.clone())
                        .map(|why| WaitingEnv {
                            project: project.clone(),
                            env: env.clone(),
                            why,
                        }),
                    Slot::Fetching { .. } => None,
                })
                .collect()
        };
        for w in cached {
            if !out.iter().any(|o| o.project == w.project && o.env == w.env) {
                out.push(w);
            }
        }
        out.sort_by(|a, b| (&a.project, &a.env).cmp(&(&b.project, &b.env)));
        out
    }

    /// Saved tokens near or past their expiry.
    fn expiring(&self) -> Vec<TokenExpiry> {
        let Some(Some(store)) = self.unlocked_store() else {
            return Vec::new();
        };
        let now = crate::source::unix_now();
        let warn = crate::source::EXPIRY_WARNING_DAYS * 86_400;
        (store.proton_token().and_then(|t| t.expires))
            .filter(|&e| e <= now.saturating_add(warn))
            .map(|expires| TokenExpiry {
                provider: Provider::Proton,
                expires,
            })
            .into_iter()
            .collect()
    }

    /// Names and stable ids, never values; see [`Request::List`]. With no
    /// one provider asked, those that cannot be listed are warnings, and
    /// the local store and Proton Pass are skipped while the daemon is
    /// locked or when they are not set up. With `keys`, each AWS secret
    /// listed is read for its key names ([`Self::key_names`]); the names of
    /// those read come back third.
    pub async fn list(
        &self,
        provider: Option<Provider>,
        prefix: &str,
        search: Option<&str>,
        aws: AwsSettings,
        keys: bool,
    ) -> Result<(Vec<Listed>, Vec<String>, Vec<String>), ResolveError> {
        let registry = self.registry()?;
        let aws = AwsSettings {
            profile: aws.profile.or(registry.config.aws.profile.clone()),
            region: aws.region.or(registry.config.aws.region.clone()),
        };
        let store = self.unlocked_store();
        let wanted = match provider {
            Some(p) => vec![p],
            None => vec![Provider::AwsSm, Provider::File, Provider::Proton],
        };
        let search = search.map(str::to_lowercase);
        let matches = |l: &Listed| match &search {
            None => true,
            Some(s) => {
                l.name.to_lowercase().contains(s)
                    || l.keys.iter().any(|k| k.as_str().to_lowercase().contains(s))
            }
        };
        let (mut items, mut warnings, mut read) = (Vec::new(), Vec::new(), Vec::new());
        for p in wanted {
            let st = match (&store, p) {
                (_, Provider::AwsSm) => None,
                (Some(st), _) => st.as_ref(),
                (None, _) if provider.is_some() => return Err(ResolveError::Locked),
                (None, _) => {
                    warnings.push(format!(
                        "{}: not searched while the daemon is locked; run `kagebunshin unlock`",
                        p.as_str()
                    ));
                    continue;
                }
            };
            if provider.is_none() {
                let set_up = match p {
                    Provider::AwsSm => true,
                    Provider::File => st.is_some(),
                    Provider::Proton => st.is_some_and(|s| s.proton_token().is_some()),
                };
                if !set_up {
                    continue;
                }
            }
            let listed = async {
                let backend = self.inner.sources.backend(p, &aws, st).await?;
                match tokio::time::timeout(LIST_TIMEOUT, backend.list(prefix)).await {
                    Ok(listed) => listed,
                    Err(_) => Err(crate::source::SourceError::Provider {
                        what: p.as_str().into(),
                        message: format!("listing timed out after {LIST_TIMEOUT:?}"),
                    }),
                }
            }
            .await;
            match listed {
                Ok(listed) if keys && p == Provider::AwsSm => {
                    let extra = &registry.config.sensitive_source_patterns;
                    let marks = store.as_ref().map(Option::as_deref);
                    let (listed, names) = self
                        .key_names(listed, &aws, extra, marks.is_none(), marks.flatten())
                        .await;
                    read = names;
                    items.extend(listed.into_iter().filter(|l| matches(l)));
                }
                Ok(listed) => items.extend(listed.into_iter().filter(|l| matches(l))),
                Err(e) if provider.is_some() => {
                    return Err(ResolveError::Provider {
                        message: format!("cannot list {}: {e}", p.as_str()),
                        hint: e.hint().map(str::to_owned),
                    });
                }
                Err(e) => warnings.push(match e.hint() {
                    Some(h) => format!("{}: {e} ({h})", p.as_str()),
                    None => format!("{}: {e}", p.as_str()),
                }),
            }
        }
        Ok((items, warnings, read))
    }

    /// `list --keys` for AWS: reads each secret in `items` to learn its key
    /// names, or that it is a plain string, and keeps only that; every
    /// value is dropped, and so zeroed, as soon as it is parsed. Secrets
    /// marked sensitive or that look like production (their name or the
    /// profile, see [`prod_like`]) are not read, nor any while the daemon
    /// is `locked`, as the marks in `store` are not known then;
    /// each of those gets `unread`. Also returns the names of the secrets
    /// it asked AWS for.
    async fn key_names(
        &self,
        mut items: Vec<Listed>,
        aws: &AwsSettings,
        extra: &[SourcePattern],
        locked: bool,
        store: Option<&Store>,
    ) -> (Vec<Listed>, Vec<String>) {
        let profile = aws.profile.as_ref().and_then(|p| {
            let why = prod_like_profile(p.as_str())?;
            Some(format!(
                "not read: AWS profile {p} looks like production (its name {why})"
            ))
        });
        for l in &mut items {
            l.unread = if locked {
                Some(
                    "not read while the daemon is locked, as its marks are not known; \
                     a human runs `kagebunshin unlock`"
                        .to_owned(),
                )
            } else if profile.is_some() {
                profile.clone()
            } else {
                prod_like(&l.name, extra)
                    .map(|why| format!("not read: it looks like production (its name {why})"))
                    .or_else(|| {
                        secret_marked(store, &l.id)
                            .then(|| "not read: it is marked sensitive".to_owned())
                    })
            };
        }
        let wanted: Vec<String> = items
            .iter()
            .filter(|l| l.unread.is_none())
            .map(|l| l.name.clone())
            .collect();
        if wanted.is_empty() {
            return (items, wanted);
        }
        let backend = match self.inner.sources.backend(Provider::AwsSm, aws, None).await {
            Ok(b) => b,
            Err(e) => {
                for l in items.iter_mut().filter(|l| l.unread.is_none()) {
                    l.unread = Some(format!("keys not read: {e}"));
                }
                return (items, wanted);
            }
        };
        let backend = &*backend;
        enum Read {
            Keys(Vec<KeyName>),
            Plain,
            Unread(String),
        }
        let got: Vec<(String, Read)> = stream::iter(wanted.clone())
            .map(|name| async move {
                let spec = SourceSpec {
                    aws: aws.clone(),
                    ..SourceSpec::new(
                        Provider::AwsSm,
                        Select::Secret {
                            name: name.clone(),
                            key: None,
                        },
                        false,
                    )
                };
                let source = backend.source(&spec);
                let fetched =
                    tokio::time::timeout(LIST_TIMEOUT, source.fetch(std::slice::from_ref(&name)))
                        .await;
                let keys = match fetched {
                    // The entries, and so the values, are dropped here.
                    Ok(Ok(entries)) => Read::Keys(entries.into_iter().map(|e| e.key).collect()),
                    Ok(Err(SourceError::Malformed {
                        problem: crate::source::Problem::NotAnObject,
                        ..
                    })) => Read::Plain,
                    Ok(Err(e)) => Read::Unread(format!("keys not read: {e}")),
                    Err(_) => Read::Unread(format!(
                        "keys not read: reading it timed out after {LIST_TIMEOUT:?}"
                    )),
                };
                (name, keys)
            })
            .buffered(KEY_READS)
            .collect()
            .await;
        let mut got: BTreeMap<String, Read> = got.into_iter().collect();
        for l in &mut items {
            match got.remove(&l.name) {
                Some(Read::Keys(mut keys)) => {
                    keys.sort();
                    keys.dedup();
                    l.keys = keys;
                }
                Some(Read::Plain) => l.plain = true,
                Some(Read::Unread(why)) => l.unread = Some(why),
                None => {}
            }
        }
        (items, wanted)
    }

    /// Whether each provider in play can read now: those `facts`'
    /// environment uses, or with no `facts` and `every` those any
    /// environment of any project uses. Where that is not one environment
    /// (no `facts`, or none of a project here), also AWS when `connect
    /// aws` set a default, and Proton when a token is saved: asking a
    /// provider is a round trip to it, and an environment is not kept
    /// waiting for one it does not read. An AWS source is checked once for
    /// each profile and region in use. The local store and Proton are not
    /// checked while the daemon is locked.
    pub async fn providers(&self, facts: Option<&Facts>, every: bool) -> Vec<ProviderStatus> {
        let Ok(registry) = self.registry() else {
            return Vec::new();
        };
        let store = self.unlocked_store();
        let mut wanted: Vec<(Provider, AwsSettings)> = Vec::new();
        let envs: Vec<_> = match facts {
            Some(f) => (registry.find(f.place()).ok())
                .and_then(|found| registry.env(found.project, f.env.as_ref()).ok())
                .into_iter()
                .collect(),
            None if !every => Vec::new(),
            None => registry
                .projects()
                .flat_map(|p| p.file.envs.keys().map(move |e| (p, e)))
                .filter_map(|(p, e)| registry.env(p, Some(e)).ok())
                .collect(),
        };
        for spec in envs.iter().flat_map(|s| &s.sources) {
            wanted.push((spec.provider, spec.aws.clone()));
        }
        let one_env = facts.is_some() && !envs.is_empty();
        if !one_env && registry.config.aws != AwsSettings::default() {
            wanted.push((Provider::AwsSm, registry.config.aws.clone()));
        }
        if !one_env
            && let Some(Some(st)) = &store
            && st.proton_token().is_some()
        {
            wanted.push((Provider::Proton, AwsSettings::default()));
        }
        let mut seen = Vec::new();
        wanted.retain(|w| {
            let new = !seen.contains(w);
            seen.push(w.clone());
            new
        });
        let checks = wanted.into_iter().map(|(p, aws)| {
            let store = store.clone();
            async move {
                let st = match (store, p) {
                    (_, Provider::AwsSm) => None,
                    (Some(st), _) => st,
                    (None, _) => {
                        return ProviderStatus {
                            provider: p,
                            detail: String::new(),
                            health: Health::Locked,
                            expires: None,
                        };
                    }
                };
                match self.inner.sources.backend(p, &aws, st.as_ref()).await {
                    Ok(b) => b.status().await,
                    Err(e) => ProviderStatus {
                        provider: p,
                        detail: aws.label().trim().to_owned(),
                        health: Health::Failed {
                            message: e.to_string(),
                        },
                        expires: None,
                    },
                }
            }
        });
        join_all(checks).await
    }

    pub async fn diff(&self, facts: &Facts) -> Result<DiffReport, ResolveError> {
        let ((project, env), values, duplicates, _) = self.resolve(facts, Who::Anyone).await?;
        let (registry, store) = self.marks()?;
        let listed = facts.example_keys.as_deref().unwrap_or_default();
        let example: BTreeSet<_> = listed.iter().collect();
        let plain = plain_vars(&values, self.vars_of(&project, &env)?);
        let missing = missing_keys(facts.example_keys.as_deref(), &values, &plain);
        let fixes = fixes(
            (&project, &env),
            &values,
            &missing,
            facts,
            store.as_deref(),
            &registry.config.default_env,
        );
        let skipped = values.skipped.iter().map(|s| s.secret.clone()).collect();
        let extra: Vec<KeyName> = match facts.example_keys {
            Some(_) => values
                .keys
                .keys()
                .filter(|k| !example.contains(k))
                .cloned()
                .collect(),
            None => Vec::new(),
        };
        let mut counts: BTreeMap<&crate::types::Origin, usize> = BTreeMap::new();
        for k in &extra {
            if let Some(r) = values.keys.get(k) {
                *counts.entry(&r.origin).or_default() += 1;
            }
        }
        let extra_by_origin = counts
            .into_iter()
            .map(|(origin, keys)| OriginCount {
                origin: origin.clone(),
                keys,
            })
            .collect();
        let conflicts = values
            .keys
            .iter()
            .filter(|(_, r)| !r.overridden.is_empty())
            .map(|(key, r)| Conflict {
                key: key.clone(),
                origin: r.origin.clone(),
                overridden: r.overridden.clone(),
            })
            .collect();
        let waiting = values.waiting((&project, &env), store.as_deref());
        Ok(DiffReport {
            project,
            env,
            example: facts.example_keys.is_some(),
            missing,
            extra,
            extra_by_origin,
            conflicts,
            skipped,
            fixes,
            warnings: [
                waiting.into_iter().collect(),
                values.warnings.clone(),
                duplicates,
            ]
            .concat(),
        })
    }

    /// Drops cached values and fetches them again: `project`'s `env` (its
    /// default when not given), or every cached environment. A fetch that
    /// was running for a dropped entry finishes for whoever waits on it, but
    /// its result is not cached.
    pub async fn sync(
        &self,
        project: Option<ProjectName>,
        env: Option<EnvName>,
    ) -> Result<SyncReport, ResolveError> {
        let registry = self.registry()?;
        let targets: Vec<EnvKey> = {
            let mut st = self.inner.state();
            let Phase::Unlocked(session) = &mut st.phase else {
                return Err(ResolveError::Locked);
            };
            let dropped: Vec<(EnvKey, Option<Slot>)> = match project {
                Some(p) => {
                    let env = env.unwrap_or_else(|| registry.config.default_env.clone());
                    let key = (p, env);
                    let slot = session.cache.remove(&key);
                    vec![(key, slot)]
                }
                None => std::mem::take(&mut session.cache)
                    .into_iter()
                    .map(|(key, slot)| (key, Some(slot)))
                    .collect(),
            };
            session.superseded.retain(|a| !a.is_finished());
            let mut targets = Vec::with_capacity(dropped.len());
            for (key, slot) in dropped {
                if let Some(Slot::Fetching { abort, .. }) = slot {
                    session.superseded.push(abort);
                }
                targets.push(key);
            }
            targets
        };
        let refreshed = join_all(targets.into_iter().map(|(project, env)| {
            let registry = &registry;
            async move {
                let result = match registry.project(&project) {
                    Some(p) => self.resolve_env(registry, p, Some(&env), Who::Anyone).await,
                    None => Err(ResolveError::NoProject(format!(
                        "no project named {project}; run kagebunshin project init"
                    ))),
                };
                match result {
                    Ok((_, values)) => {
                        let store = self.marks().ok().and_then(|(_, st)| st);
                        let waiting = values.waiting((&project, &env), store.as_deref());
                        Synced {
                            project,
                            env,
                            keys: Some(values.keys.len()),
                            warnings: [waiting.into_iter().collect(), values.warnings.clone()]
                                .concat(),
                            error: None,
                        }
                    }
                    Err(e) => Synced {
                        project,
                        env,
                        keys: None,
                        warnings: Vec::new(),
                        error: Some(wire_error(&e)),
                    },
                }
            }
        }))
        .await;
        Ok(SyncReport { refreshed })
    }

    /// [`Self::run_env_for`] for this process.
    #[cfg(test)]
    pub async fn run_env(&self, facts: &Facts) -> Result<RunEnvReply, ResolveError> {
        let caller = crate::test_support::this_process();
        let approval = Mutex::new(None);
        let ask = Ask {
            action: "run",
            caller: &caller,
            cwd: &facts.cwd,
            program: None,
            command: String::new(),
            argv: Vec::new(),
            approval: &approval,
        };
        self.run_env_for(facts, &ask).await
    }

    /// What `run` injects: the keys `.env.example` lists, or every key when
    /// there is no such file. All or nothing: if any of them is marked
    /// sensitive, the whole run waits for approval in the app.
    async fn run_env_for(&self, facts: &Facts, ask: &Ask<'_>) -> Result<RunEnvReply, ResolveError> {
        let mask_min_len = self.registry()?.config.masking.min_len.get();
        let (env_key, values) = self.hand_out_approved(facts, ask, None).await?;
        let keys = wanted_keys(facts, &values);
        let warnings = values.warnings.clone();
        let (project, env) = env_key;
        let mut plain = plain_vars(&values, self.vars_of(&project, &env)?);
        let mut vars = Vec::new();
        let mut missing = Vec::new();
        for key in keys {
            match values.keys.get(key) {
                Some(r) => vars.push(WireVar {
                    key: key.clone(),
                    value: WireSecret::new(r.value.expose().to_owned()),
                    plain: false,
                }),
                None => match plain.remove(key) {
                    Some(value) => vars.push(WireVar {
                        key: key.clone(),
                        value: WireSecret::new(value),
                        plain: true,
                    }),
                    None => missing.push(key.clone()),
                },
            }
        }
        // With no `.env.example`, every key goes, plain settings too.
        if facts.example_keys.is_none() {
            vars.extend(plain.into_iter().map(|(key, value)| WireVar {
                key,
                value: WireSecret::new(value),
                plain: true,
            }));
        }
        vars.sort_by(|a, b| a.key.cmp(&b.key));
        info!(
            %project,
            %env,
            keys = vars.len(),
            missing = missing.len(),
            "values for run"
        );
        Ok(RunEnvReply {
            project,
            env,
            vars,
            missing,
            warnings,
            mask_min_len,
        })
    }

    /// One value, for a human: see [`Self::prove_human`]. One marked
    /// sensitive waits for approval in the app too, as `run`.
    async fn get_for(
        &self,
        facts: &Facts,
        key: &KeyName,
        passphrase: Passphrase,
        ask: &Ask<'_>,
    ) -> Result<WireSecret, ResolveError> {
        if self.is_locked() {
            return Err(ResolveError::Locked);
        }
        self.prove_human(passphrase).await?;
        let (env_key, values) = self.hand_out_approved(facts, ask, Some(key)).await?;
        let (project, env) = env_key;
        let Some(r) = values.keys.get(key) else {
            return Err(ResolveError::NoKey {
                project,
                env,
                key: key.clone(),
            });
        };
        info!(%project, %env, %key, "value for get");
        Ok(WireSecret::new(r.value.expose().to_owned()))
    }

    /// The values `ask` wants (the one key `only`, or [`wanted_keys`]),
    /// for handing to a process. If the environment or any of those keys
    /// is marked sensitive, a person must approve that in the app first;
    /// then they are resolved again, for a human, and handed out only if
    /// the environment, its sources and the marked keys are still those
    /// the person was asked about.
    async fn hand_out_approved(
        &self,
        facts: &Facts,
        ask: &Ask<'_>,
        only: Option<&KeyName>,
    ) -> Result<(EnvKey, Arc<EnvValues>), ResolveError> {
        let touch = ask.caller.remote.is_none();
        let (env_key, sources, marked, refused, secrets) =
            match self.hand_out_as(facts, Who::Anyone, touch).await {
                Ok((env_key, values, sources)) => {
                    let Some((marked, refused)) =
                        self.marked_keys(&env_key, &values, facts, only)?
                    else {
                        return Ok((env_key, values));
                    };
                    // The secrets whose marks hold the keys back, where
                    // it is not the environment's own. A store key is
                    // marked by itself, not with its section.
                    let secrets: BTreeSet<Origin> = marked
                        .iter()
                        .filter(|_| matches!(refused, ResolveError::SensitiveKey { .. }))
                        .filter_map(|k| values.keys.get(k))
                        .filter(|r| r.origin.provider != Provider::File)
                        .map(|r| r.origin.clone())
                        .collect();
                    (env_key, sources, marked, refused, secrets)
                }
                Err(e) => {
                    // An environment marked sensitive is refused before it is
                    // read, so only the keys asked for by name are known.
                    let ResolveError::Sensitive { project, env, .. } = &e else {
                        return Err(e);
                    };
                    let env_key = (project.clone(), env.clone());
                    let registry = self.registry()?;
                    let sources = registry
                        .project(project)
                        .and_then(|p| registry.env(p, Some(env)).ok())
                        .map(|settings| settings.sources)
                        .unwrap_or_default();
                    let marked = match (only, &facts.example_keys) {
                        (Some(key), _) => vec![key.clone()],
                        (None, Some(listed)) => listed
                            .iter()
                            .collect::<BTreeSet<_>>()
                            .into_iter()
                            .cloned()
                            .collect(),
                        (None, None) => Vec::new(),
                    };
                    (env_key, sources, marked, e, BTreeSet::new())
                }
            };
        let whole = matches!(refused, ResolveError::Sensitive { .. });
        let secrets = secrets.into_iter().collect();
        // With no `.env.example` the command gets every key. The person is
        // shown them where they are known: read just now, or held from an
        // earlier read of a marked environment, whose names the caller is
        // not told.
        let every_key = whole && only.is_none() && facts.example_keys.is_none();
        let shown = if every_key && marked.is_empty() {
            self.held_keys(&env_key, &sources).unwrap_or_default()
        } else {
            marked.clone()
        };
        let wanted = Wanted {
            keys: marked,
            shown: shown.clone(),
            every_key,
        };
        self.wait_for_approval(ask, &env_key, wanted, secrets, refused)
            .await?;
        // The project file, the marks or the cache may have changed while
        // the person read the prompt; what they approved is what goes out,
        // or nothing does. Other sources are not even fetched.
        let changed = || {
            warn!(project = %env_key.0, env = %env_key.1, "approved environment changed while waiting");
            ResolveError::ApprovalChanged {
                project: env_key.0.clone(),
                env: env_key.1.clone(),
            }
        };
        let (named_key, named_sources) = self.named(facts)?;
        if named_key != env_key || named_sources != sources {
            return Err(changed());
        }
        let (now_key, values, now_sources) = self.hand_out_as(facts, Who::Human, touch).await?;
        // A whole environment with a list of keys (`.env.example`) is
        // approved whatever it sets; one shown key by key is approved as
        // those keys.
        let by_key = !whole || (every_key && !shown.is_empty());
        let scope_grew = match self.marked_keys(&now_key, &values, facts, only)? {
            Some((now_marked, _)) => by_key && now_marked.iter().any(|k| !shown.contains(k)),
            None => false,
        };
        // The values must also have been fetched from those sources: the
        // file may have changed again since it was read just above.
        if now_key != env_key || now_sources != sources || values.sources != sources || scope_grew {
            return Err(changed());
        }
        Ok((now_key, values))
    }

    /// The keys of `values` that `facts` wants (or just `only`) and that may
    /// not go to an agent: every one if the environment is marked, else
    /// those that resolved to a secret marked sensitive. With the refusal,
    /// or `None` if nothing is refused.
    fn marked_keys(
        &self,
        env_key: &EnvKey,
        values: &EnvValues,
        facts: &Facts,
        only: Option<&KeyName>,
    ) -> Result<Option<(Vec<KeyName>, ResolveError)>, ResolveError> {
        let keys = match only {
            Some(key) => vec![key],
            None => wanted_keys(facts, values),
        };
        let refused = match self.refuse_sensitive_keys(env_key, values, keys.clone()) {
            Ok(()) => return Ok(None),
            Err(e @ (ResolveError::Sensitive { .. } | ResolveError::SensitiveKey { .. })) => e,
            Err(e) => return Err(e),
        };
        // Marked while it was fetched, the whole environment is.
        let whole = matches!(refused, ResolveError::Sensitive { .. });
        let (_, store) = self.marks()?;
        let marked = keys
            .into_iter()
            .filter(|k| {
                whole
                    || values
                        .keys
                        .get(*k)
                        .is_some_and(|r| is_sensitive(store.as_deref(), k, r))
            })
            .cloned()
            .collect();
        Ok(Some((marked, refused)))
    }

    /// The keys the session holds for `env`, read from `sources`, without
    /// reading anything: `None` if it holds none.
    fn held_keys(&self, env: &EnvKey, sources: &[SourceSpec]) -> Option<Vec<KeyName>> {
        let st = self.inner.state();
        let Phase::Unlocked(session) = &st.phase else {
            return None;
        };
        match session.cache.get(env) {
            Some(Slot::Ready(values)) if values.sources == sources => {
                Some(values.keys.keys().cloned().collect())
            }
            _ => None,
        }
    }

    /// Waits for a person to approve, in the app or on the paired phone,
    /// handing the keys `wanted` of `env` to `ask`, which would be
    /// `refused` otherwise; `secrets` are the marked secrets they are read
    /// from, if that is why. Refused at once if the app is not open and no
    /// phone is told of it, and denied after `approval_timeout`.
    async fn wait_for_approval(
        &self,
        ask: &Ask<'_>,
        (project, env): &EnvKey,
        wanted: Wanted,
        secrets: Vec<Origin>,
        refused: ResolveError,
    ) -> Result<(), ResolveError> {
        let Wanted {
            keys,
            shown,
            every_key,
        } = wanted;
        if !self.inner.approvals().app_open() && !self.phone_listens() {
            return Err(ResolveError::NoApp(Box::new(refused)));
        }
        // One prompt at a time per remote machine, so one cannot bury the
        // app in prompts; the next is refused, not queued.
        let _prompting = match &ask.caller.remote {
            Some(peer) => {
                if !self.inner.remote().prompting.insert(peer.node.clone()) {
                    return Err(ResolveError::Remote {
                        message: format!(
                            "machine {} already has a request waiting for approval",
                            peer.machine
                        ),
                        hint: Some("once the human has answered that one, try again".into()),
                    });
                }
                Some(Prompting {
                    inner: &self.inner,
                    node: peer.node.clone(),
                })
            }
            None => None,
        };
        if let Some(log) = &self.inner.audit {
            let mut event = Event::new("ask approval", Decision::Allowed, ask.caller);
            event.target = Some(ask.action.to_owned());
            (event.project, event.env) = (Some(project.clone()), Some(env.clone()));
            event.keys = keys.iter().map(ToString::to_string).collect();
            event.program.clone_from(&ask.program);
            log.append(&event).map_err(|e| {
                ResolveError::Internal(format!(
                    "approval is asked only once the audit log records it, and {} cannot be written: {e}",
                    log.path().display()
                ))
            })?;
        }
        let reason = match &refused {
            ResolveError::Sensitive {
                reason: Refusal::Waiting(why),
                ..
            } => ApprovalReason::Waiting { why: why.clone() },
            ResolveError::Sensitive { .. } => ApprovalReason::Marked,
            _ => ApprovalReason::Keys,
        };
        let wait = self
            .registry()
            .map_or_else(
                |_| ApprovalTimeout::default(),
                |r| r.config.approval_timeout,
            )
            .get();
        let unapproved = |timed_out: bool| {
            ResolveError::NotApproved(Box::new(Unapproved {
                project: project.clone(),
                env: env.clone(),
                waited: timed_out.then_some(wait),
                keys: keys.clone(),
                reason: reason.clone(),
                secrets: secrets.clone(),
            }))
        };
        let prompt = ApprovalPrompt {
            id: 0,
            project: project.clone(),
            env: env.clone(),
            keys: shown,
            reason: reason.clone(),
            command: ask.command.clone(),
            argv: ask.argv.clone(),
            pid: ask.caller.pid,
            cwd: ask.cwd.to_path_buf(),
            parents: ancestors(ask.caller),
            left: None,
            remote: ask.caller.remote.as_ref().map(RemotePeer::named),
            secrets: secrets.clone(),
            every_key,
        };
        info!(%project, %env, "waiting for approval");
        let decision = match self.ask_app(ask.caller, prompt, wait).await {
            Answer::Approved(_) | Answer::ApprovedOnPhone => Decision::Allowed,
            Answer::Denied => Decision::Denied,
            Answer::TimedOut => Decision::TimedOut,
            Answer::CallerGone => {
                info!(%project, %env, "the caller ended while waiting for approval");
                *ask.approval.lock().unwrap_or_else(PoisonError::into_inner) =
                    Some(Decision::Denied);
                return Err(ResolveError::CallerGone {
                    project: project.clone(),
                    env: env.clone(),
                });
            }
            Answer::AppClosed => {
                info!(%project, %env, "the app closed while a request waited for approval");
                return Err(ResolveError::NoApp(Box::new(refused)));
            }
        };
        *ask.approval.lock().unwrap_or_else(PoisonError::into_inner) = Some(decision);
        match decision {
            Decision::Allowed => Ok(()),
            d => Err(unapproved(d == Decision::TimedOut)),
        }
    }

    /// Shows `prompt` in the app, and tells the paired phone of one it can
    /// answer; the caller has seen that one of them is there. Waits for a
    /// person's answer, for at most `wait`.
    async fn ask_app(&self, caller: &Caller, mut prompt: ApprovalPrompt, wait: Duration) -> Answer {
        let (reply, answer) = oneshot::channel();
        let (id, shown) = {
            let mut a = self.inner.approvals();
            a.next += 1;
            prompt.id = a.next;
            let shown = prompt.clone();
            a.pending
                .insert(prompt.id, (prompt, Instant::now() + wait, reply));
            (a.next, shown)
        };
        let _asking = Asking {
            inner: &self.inner,
            id,
        };
        self.inner.approvals_changed.send_modify(|n| *n += 1);
        let told = self.tell_phone(&shown, wait);
        // A caller that is killed, as an agent's command is when it runs
        // out of time, leaves nobody to answer to: its prompt goes.
        let gone = caller_gone(caller);
        // The app closing leaves nobody to answer, unless the phone was
        // told: the same refusal as if it had not been open, and not a
        // wait for the timeout.
        let closed = async {
            let mut tick = tokio::time::interval(CALLER_CHECK);
            loop {
                tick.tick().await;
                let on_phone = told.as_ref().is_some_and(|t| t.load(Ordering::Relaxed));
                if !on_phone && !self.inner.approvals().app_open() {
                    return;
                }
            }
        };
        // A person's answer, or how it ended without one.
        let reply = tokio::select! {
            answered = tokio::time::timeout(wait, answer) => match answered {
                Ok(Ok(reply)) => Ok(reply),
                Ok(Err(_)) => Ok(Reply::Desk(None)),
                Err(_) => Err(Answer::TimedOut),
            },
            () = gone => Err(Answer::CallerGone),
            () = closed => Err(Answer::AppClosed),
        };
        self.note_answer(
            &shown,
            reply.as_ref().ok(),
            matches!(reply, Err(Answer::TimedOut)),
        );
        match reply {
            Ok(Reply::Desk(Some(approved))) => Answer::Approved(approved),
            Ok(Reply::Phone(true)) => Answer::ApprovedOnPhone,
            Ok(Reply::Desk(None) | Reply::Phone(false)) => Answer::Denied,
            Err(ended) => ended,
        }
    }

    /// [`Request::StoreImport`]: writes `sections` with `passphrase`, or
    /// without one with the passphrase a person approves it with in the
    /// app, which also unlocks a locked daemon.
    async fn store_import(
        &self,
        sections: Vec<ImportSection>,
        passphrase: Option<Passphrase>,
        asks: (&Caller, PathBuf, Vec<String>),
        approval: &Mutex<Option<Decision>>,
    ) -> Result<Response, ResolveError> {
        if sections.is_empty() {
            return Err(ResolveError::Config("an import of no section".into()));
        }
        let (caller, ..) = asks;
        let (passphrase, unlock) = if let Some(p) = passphrase {
            (p, false)
        } else {
            let file = self.inner.store.clone();
            if !file.exists()? {
                return Err(StoreError::Missing {
                    path: file.path().into(),
                }
                .into());
            }
            let unlock = self.is_locked();
            let names = self.import_names(&sections);
            if names.is_empty() {
                // Every section already has keys and was to be left then.
                return Ok(Response::Imported {
                    sections: sections
                        .into_iter()
                        .map(|s| ImportedSection {
                            section: s.section,
                            written: false,
                            replaced: Vec::new(),
                        })
                        .collect(),
                    locked: self.is_locked(),
                });
            }
            let p = self
                .approve_import(&sections, names, unlock, asks, approval)
                .await?;
            (p, unlock)
        };
        if unlock {
            self.unlock(Some(passphrase.copy())).await?;
            if let Some(log) = &self.inner.audit
                && let Err(e) = log.append(&Event::new("unlock", Decision::Allowed, caller))
            {
                warn!(error = %e, path = %log.path().display(), "cannot write the audit log");
            }
        }
        let sections = self
            .store_update(passphrase, None, move |st| {
                let mut done = Vec::new();
                for s in sections {
                    let had: Vec<KeyName> = (st.section(&s.section))
                        .map(|keys| keys.keys().cloned().collect())
                        .unwrap_or_default();
                    let written = !s.if_empty || had.is_empty();
                    let mut replaced = Vec::new();
                    if written {
                        for (key, value) in s.values {
                            if had.contains(&key) && !replaced.contains(&key) {
                                replaced.push(key.clone());
                            }
                            st.set(s.section.clone(), key, value.into_value());
                        }
                    }
                    done.push(ImportedSection {
                        section: s.section,
                        written,
                        replaced,
                    });
                }
                Ok(done)
            })
            .await?;
        info!(sections = sections.len(), "imported into the local store");
        Ok(Response::Imported {
            sections,
            locked: self.is_locked(),
        })
    }

    /// What writing `sections` would do, for the prompt: without the ones
    /// that are left as they are, as far as the store can be seen.
    fn import_names(&self, sections: &[ImportSection]) -> Vec<ImportNames> {
        let store = self.unlocked_store().flatten();
        sections
            .iter()
            .filter_map(|s| {
                let has = store.as_deref().and_then(|st| st.section(&s.section));
                if s.if_empty && has.is_some_and(|keys| !keys.is_empty()) {
                    return None;
                }
                let mut keys: Vec<KeyName> = Vec::new();
                for (k, _) in &s.values {
                    if !keys.contains(k) {
                        keys.push(k.clone());
                    }
                }
                let replaces = (keys.iter())
                    .filter(|k| has.is_some_and(|keys| keys.contains_key(*k)))
                    .cloned()
                    .collect();
                Some(ImportNames {
                    section: s.section.clone(),
                    files: s.files.clone(),
                    keys,
                    into: s.into,
                    replaces,
                    if_empty: s.if_empty,
                })
            })
            .collect()
    }

    /// Waits for a person to approve, in the app, writing `sections` to
    /// the local store, and gives the passphrase they typed. Refused at
    /// once if the app is not open, and denied after `approval_timeout`.
    async fn approve_import(
        &self,
        sections: &[ImportSection],
        names: Vec<ImportNames>,
        unlock: bool,
        (caller, cwd, command): (&Caller, PathBuf, Vec<String>),
        approval: &Mutex<Option<Decision>>,
    ) -> Result<Passphrase, ResolveError> {
        if !self.inner.approvals().app_open() {
            return Err(ResolveError::Import(ImportRefusal::NoApp));
        }
        let Some(Section { project, env }) = names.first().map(|n| n.section.clone()) else {
            return Err(ResolveError::Internal(
                "an import that writes nothing".into(),
            ));
        };
        if let Some(log) = &self.inner.audit {
            let mut event = Event::new("ask approval", Decision::Allowed, caller);
            event.target = Some("store import".to_owned());
            event.keys = import_keys(sections);
            log.append(&event).map_err(|e| {
                ResolveError::Internal(format!(
                    "approval is asked only once the audit log records it, and {} cannot be written: {e}",
                    log.path().display()
                ))
            })?;
        }
        let wait = self
            .registry()
            .map_or_else(
                |_| ApprovalTimeout::default(),
                |r| r.config.approval_timeout,
            )
            .get();
        let prompt = ApprovalPrompt {
            id: 0,
            project,
            env,
            keys: Vec::new(),
            reason: ApprovalReason::Import {
                sections: names,
                unlock,
            },
            command: command.join(" "),
            argv: command,
            pid: caller.pid,
            cwd,
            parents: ancestors(caller),
            left: None,
            remote: None,
            secrets: Vec::new(),
            every_key: false,
        };
        info!(
            sections = sections.len(),
            "an import waits for approval in the app"
        );
        let (decision, refusal) = match self.ask_app(caller, prompt, wait).await {
            Answer::Approved(approved) => {
                *approval.lock().unwrap_or_else(PoisonError::into_inner) = Some(Decision::Allowed);
                return Ok(approved.passphrase);
            }
            // The phone approves no import: it has no passphrase to write
            // the store with, so `phone_answer` refuses before this.
            Answer::Denied | Answer::ApprovedOnPhone => {
                (Some(Decision::Denied), ImportRefusal::Denied)
            }
            Answer::TimedOut => (Some(Decision::TimedOut), ImportRefusal::TimedOut(wait)),
            Answer::CallerGone => (Some(Decision::Denied), ImportRefusal::CallerGone),
            Answer::AppClosed => (None, ImportRefusal::NoApp),
        };
        if decision.is_some() {
            *approval.lock().unwrap_or_else(PoisonError::into_inner) = decision;
        }
        Err(ResolveError::Import(refusal))
    }

    /// [`Request::StoreAsk`]: waits for a person to type the values of
    /// `keys` of `section` into the app, with the passphrase, and writes
    /// those they typed in one write. Approving also unlocks a locked
    /// daemon. Refused at once if the app is not open, and denied after
    /// `approval_timeout`; nothing is written then.
    async fn store_ask(
        &self,
        section: Section,
        keys: Vec<KeyName>,
        (caller, cwd, command): (&Caller, PathBuf, Vec<String>),
        approval: &Mutex<Option<Decision>>,
    ) -> Result<Response, ResolveError> {
        if keys.is_empty() {
            return Err(ResolveError::BadRequest("no key to ask a value for".into()));
        }
        if let Some(twice) = (keys.iter().enumerate()).find_map(|(i, k)| {
            let earlier = keys.get(..i).is_some_and(|before| before.contains(k));
            earlier.then_some(k)
        }) {
            return Err(ResolveError::BadRequest(format!(
                "{twice} is asked for twice"
            )));
        }
        let file = self.inner.store.clone();
        if !file.exists()? {
            return Err(StoreError::Missing {
                path: file.path().into(),
            }
            .into());
        }
        if !self.inner.approvals().app_open() {
            return Err(ResolveError::Typing(ImportRefusal::NoApp));
        }
        let unlock = self.is_locked();
        let replaces: Vec<KeyName> = {
            let store = self.unlocked_store().flatten();
            let has = store.as_deref().and_then(|st| st.section(&section));
            (keys.iter())
                .filter(|k| has.is_some_and(|had| had.contains_key(*k)))
                .cloned()
                .collect()
        };
        if let Some(log) = &self.inner.audit {
            let mut event = Event::new("ask approval", Decision::Allowed, caller);
            event.target = Some("store set".to_owned());
            event.keys = keys.iter().map(|k| format!("{section}.{k}")).collect();
            log.append(&event).map_err(|e| {
                ResolveError::Internal(format!(
                    "values are asked for only once the audit log records it, and {} cannot be written: {e}",
                    log.path().display()
                ))
            })?;
        }
        let wait = self
            .registry()
            .map_or_else(
                |_| ApprovalTimeout::default(),
                |r| r.config.approval_timeout,
            )
            .get();
        let prompt = ApprovalPrompt {
            id: 0,
            project: section.project.clone(),
            env: section.env.clone(),
            keys: keys.clone(),
            reason: ApprovalReason::Type { replaces, unlock },
            command: command.join(" "),
            argv: command,
            pid: caller.pid,
            cwd,
            parents: ancestors(caller),
            left: None,
            remote: None,
            secrets: Vec::new(),
            every_key: false,
        };
        info!(%section, keys = keys.len(), "values wait to be typed into the app");
        let (decision, refusal) = match self.ask_app(caller, prompt, wait).await {
            Answer::Approved(approved) => {
                *approval.lock().unwrap_or_else(PoisonError::into_inner) = Some(Decision::Allowed);
                return self
                    .write_typed(section, keys, approved, unlock, caller)
                    .await;
            }
            // Nor typed values, which it could not give either.
            Answer::Denied | Answer::ApprovedOnPhone => {
                (Some(Decision::Denied), ImportRefusal::Denied)
            }
            Answer::TimedOut => (Some(Decision::TimedOut), ImportRefusal::TimedOut(wait)),
            Answer::CallerGone => (Some(Decision::Denied), ImportRefusal::CallerGone),
            Answer::AppClosed => (None, ImportRefusal::NoApp),
        };
        if decision.is_some() {
            *approval.lock().unwrap_or_else(PoisonError::into_inner) = decision;
        }
        Err(ResolveError::Typing(refusal))
    }

    /// Writes what a person typed for some of `keys` of `section`, in one
    /// write, after unlocking with their passphrase if the daemon was
    /// locked when they were asked.
    async fn write_typed(
        &self,
        section: Section,
        keys: Vec<KeyName>,
        Approved { passphrase, values }: Approved,
        unlock: bool,
        caller: &Caller,
    ) -> Result<Response, ResolveError> {
        if unlock {
            self.unlock(Some(passphrase.copy())).await?;
            if let Some(log) = &self.inner.audit
                && let Err(e) = log.append(&Event::new("unlock", Decision::Allowed, caller))
            {
                warn!(error = %e, path = %log.path().display(), "cannot write the audit log");
            }
        }
        let typed: Vec<KeyName> = values.iter().map(|(k, _)| k.clone()).collect();
        let into = section.clone();
        let replaced = self
            .store_update(passphrase, None, move |st| {
                let mut replaced = Vec::new();
                for (key, value) in values {
                    if st.set(into.clone(), key.clone(), value) == Change::Replaced {
                        replaced.push(key);
                    }
                }
                Ok(replaced)
            })
            .await?;
        // In the order asked, whatever order the app sent them in.
        let (set, left): (Vec<KeyName>, Vec<KeyName>) =
            keys.into_iter().partition(|k| typed.contains(k));
        info!(set = set.len(), "wrote values typed into the app");
        Ok(Response::StoreTyped {
            replaced: (set.iter())
                .filter(|k| replaced.contains(k))
                .cloned()
                .collect(),
            section,
            set,
            left,
            locked: self.is_locked(),
        })
    }

    /// [`Request::WaitApprovals`].
    ///
    /// Ends early when the app's process does, so the app stops counting
    /// as open at once.
    async fn wait_approvals(&self, mut known: Vec<u64>, caller: &Caller) -> Response {
        known.sort_unstable();
        known.dedup();
        self.inner.approvals().watching += 1;
        let mut watching = Watching {
            inner: &self.inner,
            gone: false,
        };
        let gone = caller_gone(caller);
        tokio::pin!(gone);
        // Before looking, so no change after it is missed.
        let mut changed = self.inner.approvals_changed.subscribe();
        let until = Instant::now() + APPROVAL_POLL;
        loop {
            {
                let a = self.inner.approvals();
                if !a.pending.keys().eq(known.iter()) {
                    break;
                }
            }
            tokio::select! {
                changed = tokio::time::timeout_at(until, changed.changed()) => {
                    if !matches!(changed, Ok(Ok(()))) {
                        break;
                    }
                }
                () = &mut gone => {
                    watching.gone = true;
                    break;
                }
            }
        }
        drop(watching);
        Response::Approvals {
            pending: self.inner.approvals().prompts(),
        }
    }

    /// [`Request::Approve`]: approves request `id` with `passphrase`, or
    /// denies it without one. Replies with the requests still waiting.
    ///
    /// `values` are what a request that asks for them is approved with: a
    /// value for at least one of its keys, for no other key and for none
    /// twice. Any other request is approved with none. They are checked
    /// before the passphrase, and what is refused leaves the request
    /// waiting.
    async fn approve(
        &self,
        id: u64,
        passphrase: Option<Passphrase>,
        values: Vec<(KeyName, WireSecret)>,
    ) -> Result<Vec<ApprovalPrompt>, ResolveError> {
        let typed = {
            let a = self.inner.approvals();
            let Some((prompt, ..)) = a.pending.get(&id) else {
                return Err(ResolveError::NoApproval(id));
            };
            matches!(prompt.reason, ApprovalReason::Type { .. }).then(|| prompt.keys.clone())
        };
        if passphrase.is_some() {
            let bad = match &typed {
                None if values.is_empty() => None,
                None => Some(format!("request {id} takes no values")),
                Some(_) if values.is_empty() => Some(format!(
                    "request {id} is approved with a value for at least one key"
                )),
                Some(keys) => (values.iter().enumerate()).find_map(|(i, (k, _))| {
                    if !keys.contains(k) {
                        return Some(format!("request {id} does not ask for {k}"));
                    }
                    let earlier = (values.get(..i)).is_some_and(|v| v.iter().any(|(e, _)| e == k));
                    earlier.then(|| format!("{k} is given twice"))
                }),
            };
            if let Some(bad) = bad {
                return Err(ResolveError::BadRequest(bad));
            }
        }
        let approved = match passphrase {
            Some(p) => Some(Approved {
                passphrase: self.prove_human(p).await?,
                values: (values.into_iter())
                    .map(|(k, v)| (k, v.into_value()))
                    .collect(),
            }),
            None => None,
        };
        let waiting = self.inner.approvals().pending.remove(&id);
        let Some((_, _, reply)) = waiting else {
            return Err(ResolveError::NoApproval(id));
        };
        // Fails only if the request stopped waiting just now; it is then
        // refused anyway.
        let approved = match reply.send(Reply::Desk(approved)) {
            Ok(()) => true,
            Err(sent) => {
                debug!(id, "an answered request stopped waiting");
                matches!(sent, Reply::Desk(Some(_)))
            }
        };
        self.inner.approvals_changed.send_modify(|n| *n += 1);
        info!(id, approved, "answered an approval");
        Ok(self.inner.approvals().prompts())
    }

    /// One value for a human, as [`Self::get_for`], even one marked sensitive
    /// or in an environment marked sensitive: what the app reveals once the
    /// passphrase is typed.
    pub async fn reveal(
        &self,
        facts: &Facts,
        key: &KeyName,
        passphrase: Passphrase,
    ) -> Result<WireSecret, ResolveError> {
        if self.is_locked() {
            return Err(ResolveError::Locked);
        }
        self.prove_human(passphrase).await?;
        let ((project, env), values, _) = self.hand_out_as(facts, Who::Human, true).await?;
        let Some(r) = values.keys.get(key) else {
            return Err(ResolveError::NoKey {
                project,
                env,
                key: key.clone(),
            });
        };
        info!(%project, %env, %key, "value for reveal");
        Ok(WireSecret::new(r.value.expose().to_owned()))
    }

    /// Any process of this user can reach the socket, so being unlocked
    /// shows nothing about who asks. `passphrase` must open the local store,
    /// which only a human knows. Without a store there is nothing to prove
    /// it with.
    /// Gives `passphrase` back, for a write that follows.
    async fn prove_human(&self, passphrase: Passphrase) -> Result<Passphrase, ResolveError> {
        let file = self.inner.store.clone();
        if !file.exists()? {
            return Err(StoreError::Missing {
                path: file.path().into(),
            }
            .into());
        }
        blocking(move || file.open(&passphrase).map(|_| passphrase)).await
    }

    /// The values for the caller's environment, for handing to a process.
    /// This is the only path that resets the idle timer.
    pub async fn hand_out(&self, facts: &Facts) -> Result<Arc<EnvValues>, ResolveError> {
        self.hand_out_env(facts, true)
            .await
            .map(|(_, values)| values)
    }

    async fn hand_out_env(
        &self,
        facts: &Facts,
        touch: bool,
    ) -> Result<(EnvKey, Arc<EnvValues>), ResolveError> {
        let (key, values, _) = self.hand_out_as(facts, Who::Anyone, touch).await?;
        Ok((key, values))
    }

    /// As [`Self::resolve`], with the sources the values came from. Resets
    /// the idle timer when `touch`: not for a caller on another machine,
    /// which cannot keep this one unlocked.
    async fn hand_out_as(
        &self,
        facts: &Facts,
        who: Who,
        touch: bool,
    ) -> Result<(EnvKey, Arc<EnvValues>, Vec<SourceSpec>), ResolveError> {
        let (key, values, _, sources) = self.resolve(facts, who).await?;
        let mut st = self.inner.state();
        let Phase::Unlocked(session) = &mut st.phase else {
            return Err(ResolveError::Locked);
        };
        if touch {
            session.deadline = Instant::now() + session.idle;
        }
        Ok((key, values, sources))
    }

    /// Refuses to hand `keys` of `values`, resolved for `env`, to an agent
    /// if any is marked sensitive; see [`EnvValues::refuse_sensitive_keys`].
    pub fn refuse_sensitive_keys<'a>(
        &self,
        env: &EnvKey,
        values: &EnvValues,
        keys: impl IntoIterator<Item = &'a KeyName>,
    ) -> Result<(), ResolveError> {
        let (_, store) = self.marks()?;
        values.refuse_sensitive_keys((&env.0, &env.1), store.as_deref(), keys)
    }

    /// The configuration and the session's store as they are now, which
    /// hold the sensitive marks.
    fn marks(&self) -> Result<(Registry, Option<Arc<Store>>), ResolveError> {
        let registry = self.registry()?;
        let st = self.inner.state();
        let Phase::Unlocked(session) = &st.phase else {
            return Err(ResolveError::Locked);
        };
        Ok((registry, session.store.clone()))
    }

    fn registry(&self) -> Result<Registry, ResolveError> {
        (self.inner.load)().map_err(|e| ResolveError::Config(e.to_string()))
    }

    /// Records that `program` ran with the environment `facts` name and
    /// exited 0. Without a place for proofs, keeps nothing.
    fn prove(&self, facts: &Facts, program: &str) -> Result<Response, ResolveError> {
        let Some(proofs) = &self.inner.proofs else {
            return Ok(Response::Proven);
        };
        let registry = self.registry()?;
        let project = registry
            .find(facts.place())
            .map_err(|e| ResolveError::NoProject(e.to_string()))?
            .project;
        let settings = registry
            .env(project, facts.env.as_ref())
            .map_err(|e| ResolveError::Config(e.to_string()))?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        proofs.record(&settings, now, program).map_err(|e| {
            warn!(error = %e, path = %proofs.path().display(), "cannot write the proofs");
            ResolveError::Config(format!("cannot write {}: {e}", proofs.path().display()))
        })?;
        Ok(Response::Proven)
    }

    /// The proof of `env` that still holds, if one is kept.
    fn proof_of(&self, project: &ProjectName, env: &EnvName) -> Option<Proof> {
        let proofs = self.inner.proofs.as_ref()?;
        let registry = self.registry().ok()?;
        let settings = registry.env(registry.project(project)?, Some(env)).ok()?;
        proofs.get(&settings)
    }

    /// `env`'s plain settings as its project file has them now: read on
    /// each request, not cached with the values, so `project set-var`
    /// takes effect without a `sync`.
    fn vars_of(&self, project: &ProjectName, env: &EnvName) -> Result<Vars, ResolveError> {
        let registry = self.registry()?;
        Ok(registry
            .project(project)
            .and_then(|p| registry.env(p, Some(env)).ok())
            .map(|settings| settings.vars)
            .unwrap_or_default())
    }

    /// The environment `facts` name and its sources in the project file as
    /// it is now; nothing is fetched.
    fn named(&self, facts: &Facts) -> Result<(EnvKey, Vec<SourceSpec>), ResolveError> {
        let registry = self.registry()?;
        let found = registry
            .find(facts.place())
            .map_err(|e| ResolveError::NoProject(e.to_string()))?;
        let settings = registry
            .env(found.project, facts.env.as_ref())
            .map_err(env_error)?;
        Ok((
            (settings.project.clone(), settings.env.clone()),
            settings.sources,
        ))
    }

    /// The environment `facts` name, the warnings its current project file
    /// gives (duplicate sources), which unlike the fetched values' warnings
    /// change as soon as the file does, and its sources in that file.
    async fn resolve(
        &self,
        facts: &Facts,
        who: Who,
    ) -> Result<(EnvKey, Arc<EnvValues>, Vec<String>, Vec<SourceSpec>), ResolveError> {
        if self.is_locked() {
            return Err(ResolveError::Locked);
        }
        let registry = self.registry()?;
        if facts.remotes.is_empty() {
            return Err(ResolveError::NoProject(format!(
                "{} has no network git remotes; kagebunshin identifies a project by its git remote",
                facts.cwd.display()
            )));
        }
        let found = registry
            .find(facts.place())
            .map_err(|e| ResolveError::NoProject(e.to_string()))?;
        let project = found.project;
        let (key, values) = self
            .resolve_env(&registry, project, facts.env.as_ref(), who)
            .await?;
        let sources = registry
            .env(project, Some(&key.1))
            .map(|settings| settings.sources)
            .unwrap_or_default();
        let mut duplicates = found.warnings;
        duplicates.extend(duplicate_warnings(&key.0, &key.1, &sources));
        Ok((key, values, duplicates, sources))
    }

    async fn resolve_env(
        &self,
        registry: &Registry,
        project: &Project,
        env: Option<&EnvName>,
        who: Who,
    ) -> Result<(EnvKey, Arc<EnvValues>), ResolveError> {
        let settings = registry.env(project, env).map_err(env_error)?;
        let (_, store) = self.marks()?;
        if who == Who::Anyone {
            refuse_sensitive(settings.project, &settings.env, store.as_deref())?;
        }
        let key = (settings.project.clone(), settings.env.clone());
        let patterns = registry.config.sensitive_source_patterns.clone();
        let strict = registry.config.strict_memory;
        let fetch = self.cached_or_fetch(&key, settings.sources, patterns, strict)?;
        let values = match fetch {
            Lookup::Cached(values) => values,
            Lookup::Wait(fetch) => fetch.await?,
        };
        Ok((key, values))
    }

    /// The cached values, or the fetch to wait on (started if need be).
    /// Values that came from other sources than `sources`, those the
    /// project file names now, are not used: a source edit takes effect at
    /// the next request, without a `sync`.
    fn cached_or_fetch(
        &self,
        key: &EnvKey,
        sources: Vec<SourceSpec>,
        patterns: Vec<SourcePattern>,
        strict_memory: bool,
    ) -> Result<Lookup, ResolveError> {
        let mut st = self.inner.state();
        let State {
            phase, generation, ..
        } = &mut *st;
        let Phase::Unlocked(session) = phase else {
            return Err(ResolveError::Locked);
        };
        match session.cache.get(key) {
            Some(Slot::Ready(values)) if values.sources == sources => {
                return Ok(Lookup::Cached(values.clone()));
            }
            Some(Slot::Fetching {
                sources: fetching,
                fetch,
                ..
            }) if *fetching == sources => return Ok(Lookup::Wait(fetch.clone())),
            _ => {}
        }
        // As `sync` does: a fetch of the old sources may still be running,
        // and `lock` must be able to stop it.
        if let Some(Slot::Fetching { abort, .. }) = session.cache.remove(key) {
            session.superseded.retain(|a| !a.is_finished());
            session.superseded.push(abort);
        }
        *generation += 1;
        let generation = *generation;
        let inner = Arc::downgrade(&self.inner);
        let factory = self.inner.sources.clone();
        let store = session.store.clone();
        let task_key = key.clone();
        let fetching = sources.clone();
        // The fetch runs as its own task so it completes, and caches its
        // result, even if every request waiting on it goes away.
        let task = tokio::spawn(async move {
            let (project, env) = &task_key;
            debug!(%project, %env, generation, "fetching");
            let result = fetch_env(&*factory, project, env, &sources, store.as_ref(), &patterns)
                .await
                .and_then(|values| {
                    let unlocked = values.keys.values().any(|r| !r.value.is_locked());
                    if strict_memory && unlocked {
                        Err(ResolveError::Memory(format!(
                            "environment {env} of project {project}"
                        )))
                    } else {
                        Ok(values)
                    }
                })
                .map(Arc::new);
            if let Some(inner) = inner.upgrade() {
                install(&inner, task_key, generation, &result);
            }
            result
        });
        let abort = task.abort_handle();
        let fetch = task
            .map(|joined| match joined {
                Ok(result) => result,
                // Only `lock` aborts fetches.
                Err(e) if e.is_cancelled() => Err(ResolveError::Locked),
                Err(_) => Err(ResolveError::Internal("a fetch task panicked".into())),
            })
            .boxed()
            .shared();
        session.cache.insert(
            key.clone(),
            Slot::Fetching {
                generation,
                sources: fetching,
                fetch: fetch.clone(),
                abort,
            },
        );
        Ok(Lookup::Wait(fetch))
    }
}

/// Runs store file work (scrypt, the file lock) off the async threads.
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, StoreError> + Send + 'static,
) -> Result<T, ResolveError> {
    match tokio::task::spawn_blocking(work).await {
        Ok(result) => Ok(result?),
        Err(_) => Err(ResolveError::Internal("a store task panicked".into())),
    }
}

/// Caches a finished fetch, unless `sync` or `lock` replaced its slot since
/// it started. A failure empties the slot so the next request tries again.
/// Whether every value in `store` is in locked memory.
fn store_in_locked_memory(store: &Store) -> bool {
    store
        .sections()
        .all(|(_, keys)| keys.values().all(crate::secret::SecretValue::is_locked))
}

fn install(
    inner: &Inner,
    key: EnvKey,
    generation: u64,
    result: &Result<Arc<EnvValues>, ResolveError>,
) {
    let mut st = inner.state();
    let Phase::Unlocked(session) = &mut st.phase else {
        return;
    };
    let current = matches!(
        session.cache.get(&key),
        Some(Slot::Fetching { generation: g, .. }) if *g == generation
    );
    if !current {
        debug!(generation, "discarding a superseded fetch");
        return;
    }
    match result {
        Ok(values) => {
            session.cache.insert(key, Slot::Ready(values.clone()));
        }
        Err(_) => {
            session.cache.remove(&key);
        }
    }
}

/// Locks the daemon once session `id` has gone `idle` without a value
/// handout. Exits when that session ends some other way.
async fn watch_idle(inner: Weak<Inner>, id: u64) {
    loop {
        let deadline = {
            let Some(inner) = inner.upgrade() else { return };
            let st = inner.state();
            match &st.phase {
                Phase::Unlocked(s) if s.id == id => s.deadline,
                _ => return,
            }
        };
        tokio::time::sleep_until(deadline).await;
        let Some(inner) = inner.upgrade() else { return };
        let mut st = inner.state();
        match &st.phase {
            Phase::Unlocked(s) if s.id == id => {
                if Instant::now() >= s.deadline {
                    st.lock();
                    inner.phone_woken.notify_one();
                    info!("locked after the idle timeout");
                    return;
                }
            }
            _ => return,
        }
    }
}

/// What to tell the human so the daemon unlocks.
pub const UNLOCK_TELL: &str = "unlock kagebunshin: run `kagebunshin unlock` in a terminal";

/// The wire form of a resolve error, with the hint the CLI shows and, where
/// it is known, who can fix it.
pub fn wire_error(e: &ResolveError) -> WireError {
    let human = |code, tell: String| {
        WireError::new(code, e.to_string())
            .with_hint(tell.clone())
            .human(tell)
    };
    let hinted = |code, hint: Option<&str>| {
        let w = WireError::new(code, e.to_string());
        match hint {
            Some(h) => w.with_hint(h),
            None => w,
        }
    };
    // An environment that waits for a decision: one named production
    // outright is the caller's to mark, the rest a human's to decide.
    let waiting = |project: &ProjectName, env: &EnvName| {
        if named_production(env) {
            WireError::new(ErrorCode::SensitiveEnv, e.to_string())
                .with_hint(format!(
                    "{}; its values are then handed out once the human approves the request",
                    mark_hint(project, env)
                ))
                .agent()
        } else {
            human(ErrorCode::SensitiveEnv, waiting_tell(project, env))
        }
    };
    match e {
        ResolveError::Locked => human(ErrorCode::Locked, UNLOCK_TELL.into()),
        ResolveError::Sensitive {
            project,
            env,
            reason: Refusal::Waiting(_),
        } => waiting(project, env),
        ResolveError::Sensitive { .. } | ResolveError::SensitiveKey { .. } => hinted(
            ErrorCode::SensitiveEnv,
            Some("the daemon does not hand out values marked sensitive"),
        ),
        ResolveError::NoApp(inner) => match &**inner {
            ResolveError::Sensitive {
                project,
                env,
                reason: Refusal::Waiting(_),
            } => waiting(project, env),
            _ => WireError::new(ErrorCode::SensitiveEnv, e.to_string())
                .with_hint(
                    "once the app is open, run the command again; the app asks to approve it",
                )
                .human(
                    "open the app (`kagebunshin app`), so a request for values marked sensitive \
                     can be approved there",
                ),
        },
        ResolveError::NotApproved(n) if n.waited.is_some() => {
            WireError::new(ErrorCode::NotApproved, e.to_string())
                .with_hint(
                    "run the command again once the human can answer: the app's window, or \
                     their paired phone, shows this command",
                )
                .human(
                    "approve the request when it asks, in the app (`kagebunshin app`) or on \
                     your paired phone",
                )
        }
        ResolveError::NotApproved(_)
        | ResolveError::Import(ImportRefusal::Denied)
        | ResolveError::Typing(ImportRefusal::Denied) => hinted(
            ErrorCode::NotApproved,
            Some("a person refused this: ask them before running it again"),
        ),
        ResolveError::CallerGone { .. }
        | ResolveError::ApprovalChanged { .. }
        | ResolveError::Import(ImportRefusal::CallerGone)
        | ResolveError::Typing(ImportRefusal::CallerGone) => hinted(ErrorCode::NotApproved, None),
        ResolveError::Typing(ImportRefusal::NoApp) => {
            WireError::new(ErrorCode::NoApp, e.to_string())
                .with_hint(
                    "once the app is open, run the command again; the app asks for the values. \
                     In a terminal the command asks for them itself",
                )
                .human("open the app (`kagebunshin app`), so the values can be typed into it")
        }
        ResolveError::Typing(ImportRefusal::TimedOut(_)) => {
            WireError::new(ErrorCode::NotApproved, e.to_string())
                .with_hint(
                    "run the command again once the human is at the screen: the app's window \
                     has a field for each value and takes the store's passphrase",
                )
                .human("type the values into the app (`kagebunshin app`) when it asks")
        }
        ResolveError::Import(ImportRefusal::NoApp) => {
            WireError::new(ErrorCode::NoApp, e.to_string())
                .with_hint(
                    "once the app is open, run the command again; the app asks to approve it. \
                     In a terminal the command asks for the passphrase itself",
                )
                .human(
                    "open the app (`kagebunshin app`), so the import into the local store can \
                     be approved there",
                )
        }
        ResolveError::Import(ImportRefusal::TimedOut(_)) => {
            WireError::new(ErrorCode::NotApproved, e.to_string())
                .with_hint(
                    "run the command again once the human is at the screen: the app's window \
                     shows what is imported and takes the store's passphrase",
                )
                .human("approve the import in the app (`kagebunshin app`) when it asks")
        }
        ResolveError::NoApproval(_) | ResolveError::BadRequest(_) => {
            hinted(ErrorCode::BadRequest, None)
        }
        ResolveError::Remote { hint, .. } => hinted(ErrorCode::PermissionDenied, hint.as_deref()),
        ResolveError::Decided(_) => hinted(ErrorCode::PermissionDenied, None),
        ResolveError::NoProject(_) => hinted(ErrorCode::NoProject, None),
        ResolveError::Config(_) => hinted(ErrorCode::Config, None),
        ResolveError::UnknownEnv { project, env } => {
            WireError::new(ErrorCode::Config, e.to_string())
                .with_hint(format!(
                    "add it with `kagebunshin project add-env {project} {env}`"
                ))
                .agent()
        }
        ResolveError::NoKey { .. } => hinted(ErrorCode::NoKey, None),
        ResolveError::Sources { hint, who, .. } => {
            let w = hinted(ErrorCode::SourceFailed, hint.as_deref());
            match (who, hint) {
                (Some(Fixer::Human), Some(h)) => w.human(h.clone()),
                (Some(Fixer::Agent), Some(_)) => w.agent(),
                _ => w,
            }
        }
        ResolveError::Provider { hint, .. } => hinted(ErrorCode::SourceFailed, hint.as_deref()),
        ResolveError::Store(s) => match s {
            StoreError::Missing { .. } => human(
                ErrorCode::NoStore,
                "create the local store: run `kagebunshin store init` in a terminal".into(),
            ),
            StoreError::Exists { .. } => hinted(ErrorCode::StoreExists, None),
            StoreError::PassphraseRequired => hinted(ErrorCode::PassphraseRequired, None),
            StoreError::WrongPassphrase => hinted(ErrorCode::WrongPassphrase, None),
            StoreError::EmptyPassphrase
            | StoreError::Corrupt { .. }
            | StoreError::Parse { .. }
            | StoreError::NoKey { .. }
            | StoreError::NoSection { .. }
            | StoreError::NoGrant { .. }
            | StoreError::NoPhone
            | StoreError::FileSecretMark
            | StoreError::CoveredByPrefix { .. }
            | StoreError::Io { .. } => hinted(ErrorCode::Store, None),
        },
        ResolveError::Memory(_) => hinted(
            ErrorCode::Internal,
            Some("raise the daemon's RLIMIT_MEMLOCK, or unset strict_memory in config.toml"),
        ),
        ResolveError::Internal(_) => hinted(ErrorCode::Internal, None),
    }
}

/// [`wire_error`] for a caller on another machine. What fixes it is done on
/// this machine, the daemon's: `kagebunshin unlock`, the app, a mark, a
/// provider's sign-in. So what to tell the human says where, and so does a
/// hint that is a step to take here; none of it is the caller's own to do.
/// A hint that says what the caller does next, or already says where,
/// stays as it is.
pub(super) fn remote_wire_error(e: &ResolveError) -> WireError {
    let here = |s: String| format!("on the daemon's machine, {s}");
    let mut w = wire_error(e);
    let step_here = (w.tell.is_some() && w.hint == w.tell)
        || w.who == Some(Fixer::Agent)
        || matches!(
            e,
            ResolveError::Sources { .. } | ResolveError::Provider { .. }
        );
    if step_here {
        w.hint = w.hint.map(here);
    }
    w.tell = w.tell.map(here);
    if w.who == Some(Fixer::Agent) {
        w.who = None;
    }
    w
}
