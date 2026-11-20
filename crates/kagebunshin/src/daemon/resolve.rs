//! Turning one environment's sources into values.
//!
//! Sensitive marks live in the encrypted store (see [`crate::store`]), so
//! only someone with the passphrase changes them. An environment marked
//! sensitive is refused before any source is built. Otherwise every source
//! first lists the names it will read. An environment whose name, a listed
//! name, or a source's AWS profile looks like production is sensitive by
//! rule until a human marks it or acknowledges it is not production: its
//! values are handed out only with approval, as if marked. Then every
//! source is fetched at once and the results merged in declared order,
//! later wins. Keys of a secret marked sensitive (a store key, or a secret
//! of another provider) are fetched like any other; [`EnvValues::refuse_sensitive_keys`] refuses to hand
//! them out. The environment fails closed: if any source
//! that is not `optional` fails, nothing is returned and the values the
//! other sources did produce are dropped (and zeroed). An optional source
//! that fails is left out and reported as a warning.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use futures::future::join_all;

use crate::config::{AwsSettings, Profile, Region, Registry, Select, SourcePattern, SourceSpec};
use crate::ipc::protocol::{ApprovalReason, WaitingEnv, Who};
use crate::source::aws_sm::sdk::SdkSm;
use crate::source::aws_sm::{AwsBackend, SmApi, arn_secret_name, secret_id};
use crate::source::file::FileBackend;
use crate::source::proton::{PassCli, ProtonBackend};
use crate::source::{Backend, Problem, Resolved, Skip, SourceError, merge, stable_origin};
use crate::store::{Section, Store, StoreError};
use crate::types::{EnvName, KeyName, Origin, ProjectName, Provider};

/// Name segments that look like production. A release candidate (`rc`)
/// usually runs against production data, so it counts too.
pub const PROD_NAMES: [&str; 3] = ["prod", "production", "rc"];

/// Why `name` looks like production, if it does: one of its `/` or `.`
/// segments is a [`PROD_NAMES`] entry, ignoring case (`widget/prod`,
/// `widget.prod.db`, `x/RC/y`, but not `widget/product` or `widget-prod`),
/// or it matches one of the configured `extra` patterns. A full AWS ARN is
/// also checked by its secret name.
///
/// Only ever a warning: what is refused is decided by the explicit marks in
/// the store, never by a name.
pub fn prod_like(name: &str, extra: &[SourcePattern]) -> Option<String> {
    let names = [Some(name), arn_secret_name(name)];
    for n in names.into_iter().flatten() {
        if let Some(prod) = n
            .split(['/', '.'])
            .find_map(|seg| PROD_NAMES.into_iter().find(|p| seg.eq_ignore_ascii_case(p)))
        {
            return Some(format!("has the segment {prod}"));
        }
    }
    for n in names.into_iter().flatten() {
        if let Some(p) = extra.iter().find(|p| p.matches(n)) {
            return Some(format!("matches the sensitive pattern {}", p.as_str()));
        }
    }
    None
}

/// Whether `env` is named production outright: `prod` or `production`.
/// Marking such an environment is no question, so `next` gives it to the
/// agent; one that only may be production (`rc`, a source's name, a
/// pattern) stays a human's decision.
pub fn named_production(env: &EnvName) -> bool {
    matches!(env.as_str(), "prod" | "production")
}

/// Name segments that say a secret is not production.
pub const NON_PROD_NAMES: [&str; 9] = [
    "dev",
    "development",
    "local",
    "qa",
    "sandbox",
    "stage",
    "staging",
    "test",
    "testing",
];

/// Whether `name` has a [`NON_PROD_NAMES`] `/` or `.` segment, ignoring
/// case (`dev/aws`, `widget.qa`), and does not itself look like production
/// by [`prod_like`].
pub fn non_prod_location(name: &str, extra: &[SourcePattern]) -> bool {
    name.split(['/', '.'])
        .any(|seg| NON_PROD_NAMES.iter().any(|n| seg.eq_ignore_ascii_case(n)))
        && prod_like(name, extra).is_none()
}

/// Why `spec`'s AWS profile looks like production, if it does, unless every
/// location the source names is [`non_prod_location`]: a secret's own name
/// outweighs its profile's, so `dev/aws` read with profile `acme-prod` is
/// not warned about.
pub fn prod_like_source_profile(spec: &SourceSpec, extra: &[SourcePattern]) -> Option<String> {
    let profile = spec.aws.profile.as_ref()?;
    let locations = spec.select.locations();
    if !locations.is_empty() && locations.iter().all(|l| non_prod_location(l, extra)) {
        return None;
    }
    prod_like_profile(profile.as_str())
}

/// Why an AWS profile name looks like production, if it does: split on
/// `-` and `_` as well as `/` and `.`, so `acme-prod` and `prod_admin`
/// match, as profile names are rarely paths.
pub fn prod_like_profile(profile: &str) -> Option<String> {
    profile
        .split(['/', '.', '-', '_'])
        .find_map(|seg| PROD_NAMES.into_iter().find(|p| seg.eq_ignore_ascii_case(p)))
        .map(|prod| format!("has the part {prod}"))
}

/// A warning for each source of `project`'s `env` that reads what an
/// earlier one already reads: the same provider, secret or prefix, profile
/// and region. Exact copies point to `project dedupe`, which removes them
/// without changing what resolves; the rest to `project remove-source`.
pub fn duplicate_warnings(
    project: &ProjectName,
    env: &EnvName,
    sources: &[SourceSpec],
) -> Vec<String> {
    let same = |a: &SourceSpec, b: &SourceSpec| {
        (a.provider, &a.select, &a.aws) == (b.provider, &b.select, &b.aws)
    };
    sources
        .iter()
        .enumerate()
        .filter_map(|(j, later)| {
            let i = sources[..j].iter().position(|s| same(s, later))?;
            let fix = if sources[..j].contains(later) {
                format!("run `kagebunshin project dedupe {project} {env}`")
            } else {
                format!(
                    "remove one with `kagebunshin project remove-source {project} {env} <N>`"
                )
            };
            Some(format!(
                "environment {env} of project {project} reads {} twice, in sources {} and {}; {fix}",
                describe(later),
                i + 1,
                j + 1
            ))
        })
        .collect()
}

/// Whether the secret `secret` is marked sensitive in `store`. Both sides
/// are compared by their stable id (see [`stable_origin`]), so a mark on an
/// AWS secret's name covers its ARN too. A marked prefix covers every id
/// that starts with it: a secret under it is marked, however a source names
/// it.
pub fn secret_marked(store: Option<&Store>, secret: &Origin) -> bool {
    let id = stable_origin(secret.provider, &secret.location);
    store.is_some_and(|st| {
        st.marked_secrets()
            .any(|m| stable_origin(m.provider, &m.location) == id)
            || st
                .marked_prefixes()
                .any(|p| p.provider == id.provider && id.location.starts_with(&p.location))
    })
}

/// How a message that an environment waits for a human decision ends, so
/// the app can offer the two decisions; see [`waiting_tell`].
pub const ACKNOWLEDGE_HINT: &str = "sensitive or acknowledge it is not production";

/// Why environment `env` looks like production, if it does: its name, one
/// of the `names` its sources read, or the AWS profile one of its `sources`
/// uses (see [`prod_like_source_profile`]). The first reason only; secrets
/// marked sensitive are skipped. Marks and acknowledgements of the
/// environment itself are not looked at here.
fn prod_like_env<'a>(
    env: &EnvName,
    sources: &[SourceSpec],
    names: impl IntoIterator<Item = (&'a SourceSpec, &'a str)>,
    extra: &[SourcePattern],
    store: Option<&Store>,
) -> Option<String> {
    prod_like(env.as_str(), extra)
        .map(|why| format!("its name {why}"))
        .or_else(|| {
            names
                .into_iter()
                .filter(|(spec, n)| !secret_marked(store, &Origin::new(spec.provider, *n)))
                .find_map(|(spec, n)| {
                    let why = prod_like(n, extra)?;
                    Some(format!("source {} reads {n}, which {why}", describe(spec)))
                })
        })
        .or_else(|| {
            sources.iter().find_map(|spec| {
                let why = prod_like_source_profile(spec, extra)?;
                let profile = spec.aws.profile.as_ref()?;
                Some(format!(
                    "source {} uses AWS profile {profile}, whose name {why}",
                    describe(spec)
                ))
            })
        })
}

/// Whether an environment fetched from `sources` would be fetched the same
/// with the store `new` as it was with `old`, apart from what its other
/// providers hold: so what the daemon cached of it still stands once `new`
/// replaces `old`. That takes three things of the store:
///
/// - the secrets and prefixes marked sensitive, which
///   [`EnvValues::prod_like`] skips, are the same;
/// - every section a `file` source reads is the same, with the same keys
///   and values, and no section it would read was added or removed;
/// - the Proton token, for a Proton source, is the same.
///
/// The marks on environments and store keys, and the acknowledgements, are
/// read from the store at each request and are not part of what is cached.
pub fn fetched_alike(sources: &[SourceSpec], old: &Store, new: &Store) -> bool {
    let marks = old.marked_secrets().eq(new.marked_secrets())
        && old.marked_prefixes().eq(new.marked_prefixes());
    fn token(st: &Store) -> Option<&str> {
        st.proton_token().map(|t| t.token.expose())
    }
    marks
        && sources.iter().all(|spec| match spec.provider {
            Provider::AwsSm => true,
            Provider::Proton => token(old) == token(new),
            Provider::File => match &spec.select {
                // Refused by the source: nothing of it is cached.
                Select::Secret { key: Some(_), .. } => false,
                Select::Secret { name, key: None } => {
                    old.same_sections(new, |s| s.to_string() == *name)
                }
                Select::Secrets(names) => {
                    old.same_sections(new, |s| names.contains(&s.to_string()))
                }
                Select::Prefix(p) => {
                    old.same_sections(new, |s| s.to_string().starts_with(p.as_str()))
                }
            },
        })
}

/// The one sentence said of an environment that looks like production
/// (`why`) and that no human has marked sensitive or acknowledged as not
/// production: it waits for their decision.
pub fn waiting_core(project: &ProjectName, env: &EnvName, why: &str) -> String {
    format!(
        "environment {env} of project {project} looks like production ({why}) and waits for a \
         human decision"
    )
}

/// What to ask the human to do about an environment [`waiting_core`] is
/// said of. Ends with [`ACKNOWLEDGE_HINT`].
pub fn waiting_tell(project: &ProjectName, env: &EnvName) -> String {
    format!("open the app (`kagebunshin app`) and either mark {project}/{env} {ACKNOWLEDGE_HINT}")
}

/// What an agent does about an environment [`named_production`] that
/// waits: marks it. The first command in it is the one to run.
pub fn mark_hint(project: &ProjectName, env: &EnvName) -> String {
    format!(
        "it is production by its name: mark it sensitive with `kagebunshin mark env {project} \
         {env}`"
    )
}

/// [`waiting_message`] for a caller on another machine. The decision is
/// made on this one, the daemon's, and marking is not the caller's to do.
pub fn waiting_message_remote(project: &ProjectName, env: &EnvName, why: &str) -> String {
    format!(
        "{}; ask the human: on the daemon's machine, {}",
        waiting_core(project, env, why),
        waiting_tell(project, env)
    )
}

/// What `status`, `diff`, `sync` and `unlock` warn of such an environment:
/// [`waiting_core`], then what to ask the human, [`waiting_tell`]. One
/// [`named_production`] is the caller's to mark, which comes first.
pub fn waiting_message(project: &ProjectName, env: &EnvName, why: &str) -> String {
    let mark = if named_production(env) {
        format!(
            " mark it sensitive with `kagebunshin mark env {project} {env}`, since it is \
             production by its name, or"
        )
    } else {
        String::new()
    };
    format!(
        "{};{mark} ask the human: {}",
        waiting_core(project, env, why),
        waiting_tell(project, env)
    )
}

/// Whether environment `env` of `project` waits for a human decision in
/// `store`: it looks like production, and is neither marked sensitive nor
/// acknowledged as not production.
fn undecided(project: &ProjectName, env: &EnvName, store: Option<&Store>) -> bool {
    !store.is_some_and(|st| st.env_marked(project, env) || st.env_acknowledged(project, env))
}

/// Every environment of every project that waits for a human decision
/// (see [`waiting_message`]), from the locations the project files name and
/// the marks in `store`, with why it looks like production. Reads nothing:
/// a name only a listed prefix turns up is not seen here, but is when the
/// environment is fetched.
pub fn waiting_envs(registry: &Registry, store: Option<&Store>) -> Vec<WaitingEnv> {
    let extra = &registry.config.sensitive_source_patterns;
    let mut out = Vec::new();
    for project in registry.projects() {
        for env in project.file.envs.keys() {
            let Ok(settings) = registry.env(project, Some(env)) else {
                continue;
            };
            if !undecided(&project.name, env, store) {
                continue;
            }
            let names = settings
                .sources
                .iter()
                .flat_map(|spec| spec.select.locations().into_iter().map(move |n| (spec, n)));
            if let Some(why) = prod_like_env(env, &settings.sources, names, extra, store) {
                out.push(WaitingEnv {
                    project: project.name.clone(),
                    env: env.clone(),
                    why,
                });
            }
        }
    }
    out
}

/// [`waiting_message`] for each of [`waiting_envs`]; `unlock` shows these.
pub fn unmarked_warnings(registry: &Registry, store: Option<&Store>) -> Vec<String> {
    waiting_envs(registry, store)
        .iter()
        .map(|w| waiting_message(&w.project, &w.env, &w.why))
        .collect()
}

/// Gives the [`Backend`] for a provider, and through it the [`Source`] a
/// project file entry describes. `store` is the local store as the daemon
/// decrypted it at unlock, if there was one; `aws` is empty for providers
/// other than AWS.
#[async_trait]
pub trait SourceFactory: Send + Sync {
    async fn backend(
        &self,
        provider: Provider,
        aws: &AwsSettings,
        store: Option<&Arc<Store>>,
    ) -> Result<Box<dyn Backend>, SourceError>;

    /// How `pass-cli` runs, for `connect proton`; `None` where Proton is
    /// not read through it.
    fn pass_cli(&self) -> Option<&PassCli> {
        None
    }
}

/// Makes the Secrets Manager client for one profile and region.
#[async_trait]
pub trait AwsClients: Send + Sync {
    async fn client(&self, profile: Option<&Profile>, region: Option<&Region>) -> Arc<dyn SmApi>;
}

/// Clients from the standard AWS configuration chain.
struct SdkClients;

#[async_trait]
impl AwsClients for SdkClients {
    async fn client(&self, profile: Option<&Profile>, region: Option<&Region>) -> Arc<dyn SmApi> {
        Arc::new(SdkSm::load(profile.map(Profile::as_str), region.map(Region::as_str)).await)
    }
}

/// The real providers: AWS Secrets Manager, the local store, and Proton
/// Pass through `pass-cli`.
///
/// Every AWS source gets a client for its own profile and region, so one
/// environment can mix profiles and one daemon can serve several at once;
/// the sources of one environment that read with the same profile and
/// region share theirs. Clients are not kept between fetches: each fetch
/// reads the AWS configuration afresh, so a profile added or a login done
/// while the daemon runs is picked up.
pub struct Providers {
    aws: Box<dyn AwsClients>,
    proton: PassCli,
}

impl Providers {
    pub fn new() -> Self {
        Self::with_aws(SdkClients)
    }

    /// The real providers with `aws` making the AWS clients.
    pub fn with_aws(aws: impl AwsClients + 'static) -> Self {
        Self {
            aws: Box::new(aws),
            proton: PassCli::from_env(),
        }
    }

    /// These providers, running `pass-cli` as `proton` says.
    pub fn with_proton(self, proton: PassCli) -> Self {
        Self { proton, ..self }
    }
}

impl Default for Providers {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SourceFactory for Providers {
    async fn backend(
        &self,
        provider: Provider,
        aws: &AwsSettings,
        store: Option<&Arc<Store>>,
    ) -> Result<Box<dyn Backend>, SourceError> {
        match provider {
            Provider::AwsSm => {
                let api = self
                    .aws
                    .client(aws.profile.as_ref(), aws.region.as_ref())
                    .await;
                Ok(Box::new(AwsBackend::new(api, aws.clone())))
            }
            Provider::File => Ok(Box::new(FileBackend::new(store.cloned()))),
            Provider::Proton => Ok(Box::new(ProtonBackend::new(
                self.proton.clone(),
                store.cloned(),
            ))),
        }
    }

    fn pass_cli(&self) -> Option<&PassCli> {
        Some(&self.proton)
    }
}

/// A value-free label for a source entry, e.g. `aws_sm prefix widget/dev/`,
/// or `aws_sm prefix widget/dev/ (profile acme-dev, region eu-west-1)` when
/// it has its own profile or region.
pub fn describe(spec: &SourceSpec) -> String {
    let (kind, what) = match &spec.select {
        Select::Secret { name, .. } => ("secret", name.clone()),
        Select::Secrets(names) => ("secrets", names.join(",")),
        Select::Prefix(p) => ("prefix", p.clone()),
    };
    format!(
        "{} {kind} {what}{}",
        spec.provider.as_str(),
        spec.aws.label()
    )
}

/// The command that adds AWS secret `secret` as one key, its whole string
/// the value, with the profile and region `spec` reads it with. `NAME` is
/// left for whoever runs it to choose.
pub fn add_as_one_key(
    project: &ProjectName,
    env: &EnvName,
    spec: &SourceSpec,
    secret: &str,
) -> String {
    let mut cmd = format!(
        "kagebunshin project add-source {project} {env} --provider aws_sm --secret {secret} --key NAME"
    );
    if let Some(p) = &spec.aws.profile {
        cmd.push_str(&format!(" --profile {p}"));
    }
    if let Some(r) = &spec.aws.region {
        cmd.push_str(&format!(" --region {r}"));
    }
    cmd
}

/// The hint for source `n` (from 1) of `spec` failing with `e`, when it
/// has one of its own: a secret it names without a key that is not a JSON
/// object, one it names that cannot be read at all, a profile that is not
/// there, or a store section that is not there.
fn source_hint(
    (project, env): (&ProjectName, &EnvName),
    n: usize,
    spec: &SourceSpec,
    e: &SourceError,
) -> Option<String> {
    if let SourceError::NoSection { name } = e {
        return Some(format!(
            "set its keys with `kagebunshin store set {name} KEY...`, naming every key"
        ));
    }
    let remove = format!("kagebunshin project remove-source {project} {env} {n}");
    // What a source that names several would lose with it.
    let others = match &spec.select {
        Select::Secrets(_) => " and add its other secrets back with `--secret`",
        _ => "",
    };
    let name = match e {
        SourceError::Malformed {
            name,
            problem: Problem::NotAnObject,
        } => name,
        SourceError::Binary { .. } => {
            return Some(format!(
                "kagebunshin reads no binary secret: take it out with `{remove}`{others}"
            ));
        }
        SourceError::Deleted { .. } => {
            return Some(format!(
                "take it out with `{remove}`{others}, or have the human restore it with `aws \
                 secretsmanager restore-secret`"
            ));
        }
        // No command of its own: whether the project needs the secret is
        // not an agent's to guess.
        SourceError::AccessDenied { .. } => {
            return Some(format!(
                "ask the human to let {} read it (it needs secretsmanager:GetSecretValue on \
                 that secret); or, if this project does not need it, take it out: kagebunshin \
                 project remove-source {project} {env} {n}{}",
                login_label(spec),
                if others.is_empty() {
                    ""
                } else {
                    ", then add its other secrets back with --secret"
                }
            ));
        }
        SourceError::NoProfile { .. } => {
            return Some(format!(
                "name one that is with `kagebunshin project set-source {project} {env} {n} \
                 --profile PROFILE`; `aws configure list-profiles` lists them"
            ));
        }
        _ => return None,
    };
    let add = add_as_one_key(project, env, spec, name);
    Some(match &spec.select {
        Select::Secrets(_) => format!(
            "to use its whole string as one key: `{add}`, then `{remove}` and add its other \
             secrets back with `--secret`"
        ),
        _ => format!("to use its whole string as one key: `{add}`, then `{remove}`"),
    })
}

/// Who can do what the hint for `e` says: a login or the local store take a
/// human; changing the project's sources does not.
pub(super) fn source_who(e: &SourceError) -> Who {
    match e {
        SourceError::NeedsLogin { .. }
        | SourceError::NoStore { .. }
        | SourceError::NoSection { .. } => Who::Human,
        _ => Who::Agent,
    }
}

/// `e`, prefixed with the source it came from unless it already says.
fn labelled(spec: &SourceSpec, e: &SourceError) -> String {
    let (label, message) = (describe(spec), e.to_string());
    if message.starts_with(&label) {
        message
    } else {
        format!("{label}: {message}")
    }
}

/// A source that failed, for [`fetch_env`]'s message.
enum Failure {
    /// Credentials for this login are missing or expired, for this many
    /// sources.
    Login(String, usize),
    Other(String),
}

/// What a source logs in as: its AWS profile, the default AWS credentials,
/// or the provider.
fn login_label(spec: &SourceSpec) -> String {
    match (spec.provider, &spec.aws.profile) {
        (Provider::AwsSm, Some(p)) => format!("profile {p}"),
        (Provider::AwsSm, None) => "the default AWS credentials".to_owned(),
        (Provider::Proton, _) => "Proton Pass".to_owned(),
        (p, _) => p.as_str().to_owned(),
    }
}

/// `HH:MM:SS UTC` of Unix seconds `secs`.
fn format_clock(secs: u64) -> String {
    let s = secs % 86_400;
    format!("{:02}:{:02}:{:02} UTC", s / 3600, s / 60 % 60, s % 60)
}

/// A secret source `source` (an index into [`EnvValues::sources`]) left
/// out: under an AWS prefix, one that is not a JSON object. Those left out
/// for another reason are only warned about: nothing here would read them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    pub source: usize,
    pub secret: String,
}

/// One environment's values. Dropping it zeroes them.
#[derive(Debug, Default)]
pub struct EnvValues {
    pub keys: BTreeMap<KeyName, Resolved>,
    /// Secrets a source left out (see [`Source::skipped`]), in source order.
    pub skipped: Vec<Skipped>,
    /// Optional sources that failed and were left out.
    pub warnings: Vec<String>,
    /// Why the environment looks like production, from its name, the names
    /// its sources listed and their AWS profiles, if it does. Until a human
    /// marks it sensitive or acknowledges it is not production, that makes
    /// it sensitive by rule; see [`Self::refuse_sensitive_keys`].
    pub prod_like: Option<String>,
    /// The sources these were fetched with. The cache is keyed by
    /// environment alone, so its project file may name others by now.
    pub sources: Vec<SourceSpec>,
}

impl EnvValues {
    /// Refuses to hand out `keys` if environment `env` of `project` is now
    /// marked sensitive, or is sensitive by rule because it looks like
    /// production and no human has decided (see [`Self::waiting`]), or any
    /// of the keys resolved to a secret marked sensitive: all or nothing,
    /// so a command never starts with part of what it asked for. Keys that
    /// did not resolve are not checked here.
    ///
    /// Reads the marks from `store` as they are now, not as they were when
    /// the values were fetched, so marking takes effect without a `sync`.
    pub fn refuse_sensitive_keys<'a>(
        &self,
        (project, env): (&ProjectName, &EnvName),
        store: Option<&Store>,
        keys: impl IntoIterator<Item = &'a KeyName>,
    ) -> Result<(), ResolveError> {
        refuse_sensitive(project, env, store)?;
        if let Some(why) = self
            .prod_like
            .as_ref()
            .filter(|_| undecided(project, env, store))
        {
            return Err(ResolveError::Sensitive {
                project: project.clone(),
                env: env.clone(),
                reason: Refusal::Waiting(why.clone()),
            });
        }
        for key in keys {
            if let Some(r) = self.keys.get(key).filter(|r| is_sensitive(store, key, r)) {
                return Err(ResolveError::SensitiveKey {
                    project: project.clone(),
                    env: env.clone(),
                    key: key.clone(),
                    origin: r.origin.to_string(),
                });
            }
        }
        Ok(())
    }

    /// [`waiting_message`] if environment `env` of `project` looks like
    /// production and, in `store` as it is now, no human has marked it
    /// sensitive or acknowledged it is not production.
    pub fn waiting(
        &self,
        (project, env): (&ProjectName, &EnvName),
        store: Option<&Store>,
    ) -> Option<String> {
        let why = self.prod_like.as_ref()?;
        undecided(project, env, store).then(|| waiting_message(project, env, why))
    }
}

/// Whether `key`'s value, from `r.origin`, is marked sensitive in `store`:
/// a store key, or a key of a secret of another provider. A secret mark
/// holds in every environment that reads the secret, which is why marking
/// an environment leaves unmarked what an open one reads too (see
/// [`super::shared`]). A store section is
/// named for an environment, so an environment's mark also holds for its
/// section wherever it is read: a `file` source in an unmarked environment
/// cannot read a marked one's. Only the winning origin counts; an
/// overridden value is not the one handed out.
pub fn is_sensitive(store: Option<&Store>, key: &KeyName, r: &Resolved) -> bool {
    let at = r.origin.location.as_str();
    match r.origin.provider {
        Provider::File => store.is_some_and(|st| {
            at.parse::<Section>().is_ok_and(|section| {
                st.is_sensitive(&section, key) || st.env_marked(&section.project, &section.env)
            })
        }),
        _ => secret_marked(store, &r.origin),
    }
}

/// Why an environment could not be served. Every message names projects,
/// environments, sources and keys, never values. `Clone` so one failed fetch
/// can be reported to every request that waited on it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResolveError {
    #[error("the daemon is locked")]
    Locked,
    #[error("{}", sensitive_text(.project, .env, .reason))]
    Sensitive {
        project: ProjectName,
        env: EnvName,
        reason: Refusal,
    },
    #[error(
        "refusing key {key} of environment {env} of project {project}: it comes from {origin}, \
         which is marked sensitive"
    )]
    SensitiveKey {
        project: ProjectName,
        env: EnvName,
        key: KeyName,
        origin: String,
    },
    #[error("{0}")]
    NoProject(String),
    #[error("{0}")]
    Config(String),
    /// More than one failure: one per line, indented.
    #[error(
        "cannot resolve environment {env} of project {project}:{}{}",
        if failures.len() > 1 { "\n  " } else { " " },
        failures.join("\n  ")
    )]
    Sources {
        project: ProjectName,
        env: EnvName,
        /// One message per failed source, in declared order.
        failures: Vec<String>,
        hint: Option<String>,
        /// Who can do what `hint` says, when every failed source has a
        /// hint and they agree.
        who: Option<Who>,
    },
    /// The environment asked for is not in its project's file.
    #[error("project {project} has no environment {env}")]
    UnknownEnv { project: ProjectName, env: EnvName },
    #[error("environment {env} of project {project} has no key {key}")]
    NoKey {
        project: ProjectName,
        env: EnvName,
        key: KeyName,
    },
    #[error(transparent)]
    Store(#[from] StoreError),
    /// `strict_memory`, and a value could not be put in locked memory.
    #[error("refusing {0}: a value could not be put in locked memory, and strict_memory is set")]
    Memory(String),
    /// A provider could not be listed or checked.
    #[error("{message}")]
    Provider {
        message: String,
        hint: Option<String>,
    },
    #[error("internal error: {0}")]
    Internal(String),
    /// `run` or `get` needs a value marked sensitive (the error inside says
    /// which), and the app, where a person would approve it, is not open.
    /// One that waits for a human decision says only that.
    #[error("{}", no_app_text(.0))]
    NoApp(Box<ResolveError>),
    /// A person denied the request, in the app or on the paired phone, or
    /// nobody answered it.
    #[error("{}", unapproved_text(.0))]
    NotApproved(Box<Unapproved>),
    /// The process that asked ended while its request waited for a person.
    #[error(
        "environment {env} of project {project}: the command that asked for its values ended \
         before a person answered"
    )]
    CallerGone { project: ProjectName, env: EnvName },
    #[error(
        "environment {env} of project {project}: approved, but its sources or the keys \
         marked sensitive changed while waiting; ask again"
    )]
    ApprovalChanged { project: ProjectName, env: EnvName },
    #[error("no request {0} waits for approval; it was answered, or it timed out")]
    NoApproval(u64),
    /// `onboard` asked to move env files into the local store with no
    /// passphrase, and no person approved it in the app.
    #[error("{}", import_refusal_text(.0))]
    Import(ImportRefusal),
    /// `store set` asked, with no terminal, for values to be typed into
    /// the app, and no person typed them.
    #[error("{}", typing_refusal_text(.0))]
    Typing(ImportRefusal),
    /// A request that asks for nothing that can be done, or the app's
    /// answer to a prompt with something it does not take.
    #[error("{0}")]
    BadRequest(String),
    /// A mark asked for with no passphrase would undo what a human decided
    /// with one.
    #[error("{0}; a human decided that, and only they change it, in the app")]
    Decided(String),
    /// A caller on another machine asked for something it may not have:
    /// a request remote callers cannot make, or an environment no grant
    /// covers.
    #[error("{message}")]
    Remote {
        message: String,
        hint: Option<String>,
    },
}

/// Why an environment is refused as a whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// It is marked sensitive.
    Marked,
    /// It looks like production, for this reason, and no human decided.
    Waiting(String),
}

fn sensitive_text(project: &ProjectName, env: &EnvName, reason: &Refusal) -> String {
    match reason {
        Refusal::Marked => {
            format!("refusing environment {env} of project {project}: it is marked sensitive")
        }
        Refusal::Waiting(why) => waiting_core(project, env, why),
    }
}

/// Why an import into the local store, or values to be typed into it,
/// were not written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportRefusal {
    /// The app, where a person would approve it, is not open.
    NoApp,
    Denied,
    /// Nobody answered for this long.
    TimedOut(std::time::Duration),
    /// The process that asked ended while it waited.
    CallerGone,
}

fn import_refusal_text(r: &ImportRefusal) -> String {
    let why = match r {
        ImportRefusal::NoApp => {
            return "moving values into the local store with no passphrase takes a person's \
                    approval in the app, which is not open; nothing was imported"
                .to_owned();
        }
        ImportRefusal::Denied => "a person refused the import in the app".to_owned(),
        ImportRefusal::TimedOut(waited) => {
            format!(
                "nobody answered the app's prompt within {}",
                within(*waited)
            )
        }
        ImportRefusal::CallerGone => {
            "the command that asked for the import ended before the app answered".to_owned()
        }
    };
    format!("{why}, so nothing was imported")
}

fn typing_refusal_text(r: &ImportRefusal) -> String {
    let why = match r {
        ImportRefusal::NoApp => {
            return "with no terminal the values are typed into the app, which is not open; \
                    nothing was set"
                .to_owned();
        }
        ImportRefusal::Denied => "a person refused, in the app, to type the values".to_owned(),
        ImportRefusal::TimedOut(waited) => {
            format!(
                "nobody answered the app's prompt within {}",
                within(*waited)
            )
        }
        ImportRefusal::CallerGone => {
            "the command that asked for the values ended before the app answered".to_owned()
        }
    };
    format!("{why}, so nothing was set")
}

/// `5 minutes`, `a minute` or `90 seconds`.
fn within(waited: std::time::Duration) -> String {
    let secs = waited.as_secs();
    match (secs / 60, secs % 60) {
        (1, 0) => "a minute".to_owned(),
        (m, 0) => format!("{m} minutes"),
        _ => format!("{secs} seconds"),
    }
}

/// A request the app asked a person about, and what it asked, so the
/// caller can say what was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unapproved {
    pub project: ProjectName,
    pub env: EnvName,
    /// How long it waited with no answer; `None` if a person denied it.
    pub waited: Option<std::time::Duration>,
    /// As in the prompt: see [`crate::ipc::protocol::ApprovalPrompt`].
    pub keys: Vec<KeyName>,
    pub reason: ApprovalReason,
    pub secrets: Vec<Origin>,
}

/// How many of the keys a refusal names before it counts the rest.
const NAMED_KEYS: usize = 8;

fn unapproved_text(n: &Unapproved) -> String {
    let Unapproved { project, env, .. } = n;
    let how = match n.waited {
        Some(waited) => format!("nobody answered the request within {}", within(waited)),
        None => "a person denied the request".to_owned(),
    };
    let listed = |names: Vec<String>| match names.len() {
        n if n > NAMED_KEYS => format!(
            "{} and {} more",
            names[..NAMED_KEYS].join(", "),
            n - NAMED_KEYS
        ),
        _ => names.join(", "),
    };
    let asked = match &n.reason {
        ApprovalReason::Keys => {
            let keys = listed(n.keys.iter().map(ToString::to_string).collect());
            match n.secrets.as_slice() {
                [] => format!("{keys}, marked sensitive"),
                [one] => format!("{keys}, read from {one}, which is marked sensitive"),
                many => format!(
                    "{keys}, read from secrets marked sensitive ({})",
                    listed(many.iter().map(ToString::to_string).collect())
                ),
            }
        }
        ApprovalReason::Marked => {
            "every value of the environment, which is marked sensitive".to_owned()
        }
        ApprovalReason::Waiting { why } => format!(
            "every value of the environment, which looks like production ({why}) and waits \
             for a human decision"
        ),
        // An import is refused as `ResolveError::Import`, not as this.
        ApprovalReason::Import { .. } => "an import into the local store".to_owned(),
        // And values to type as `ResolveError::Typing`.
        ApprovalReason::Type { .. } => "values typed into the local store".to_owned(),
    };
    format!(
        "environment {env} of project {project}: {how}, so nothing was handed out. It asked \
         for {asked}"
    )
}

fn no_app_text(inner: &ResolveError) -> String {
    match inner {
        ResolveError::Sensitive {
            reason: Refusal::Waiting(_),
            ..
        } => inner.to_string(),
        e => format!("{e}; handing it out takes approval in the app, which is not open"),
    }
}

/// `e` as a [`ResolveError`]: an unknown environment as
/// [`ResolveError::UnknownEnv`], so its fix can be named.
pub fn env_error(e: crate::config::ConfigError) -> ResolveError {
    match e {
        crate::config::ConfigError::UnknownEnv { project, env } => {
            ResolveError::UnknownEnv { project, env }
        }
        e => ResolveError::Config(e.to_string()),
    }
}

/// Refuses an environment marked sensitive in `store`, before anything is
/// read. One that only looks like production is refused once its sources
/// have listed what they read; see [`EnvValues::refuse_sensitive_keys`].
pub fn refuse_sensitive(
    project: &ProjectName,
    env: &EnvName,
    store: Option<&Store>,
) -> Result<(), ResolveError> {
    if store.is_some_and(|st| st.env_marked(project, env)) {
        return Err(ResolveError::Sensitive {
            project: project.clone(),
            env: env.clone(),
            reason: Refusal::Marked,
        });
    }
    Ok(())
}

/// Fetches every source of `env` concurrently and merges them. See the
/// module docs for how failures and sensitive secrets are handled.
///
/// Every source lists the names it will read first. If the environment's
/// name, or any listed name (such as `widget/prod/db` under a `widget/`
/// prefix), looks like production by [`prod_like`] with the configured
/// `patterns`, the result says why in [`EnvValues::prod_like`]; nothing is
/// refused here.
pub async fn fetch_env(
    factory: &dyn SourceFactory,
    project: &ProjectName,
    env: &EnvName,
    sources: &[SourceSpec],
    store: Option<&Arc<Store>>,
    patterns: &[SourcePattern],
) -> Result<EnvValues, ResolveError> {
    // One backend for each provider and AWS login the sources read with:
    // what a backend's sources share is then read once for the
    // environment, as Proton's account is, and not once for each source.
    let mut logins: Vec<(Provider, &AwsSettings)> = Vec::new();
    for spec in sources {
        if !logins.contains(&(spec.provider, &spec.aws)) {
            logins.push((spec.provider, &spec.aws));
        }
    }
    let backends = join_all(
        logins
            .iter()
            .map(|(provider, aws)| factory.backend(*provider, aws, store)),
    )
    .await;
    let (logins, backends) = (&logins, &backends);
    let listed = join_all(sources.iter().map(|spec| async move {
        let shared = logins
            .iter()
            .position(|login| *login == (spec.provider, &spec.aws))
            .and_then(|at| backends.get(at));
        let source = match shared {
            Some(Ok(backend)) => backend.source(spec),
            // Its backend could not be made: this source says why itself.
            _ => factory
                .backend(spec.provider, &spec.aws, store)
                .await?
                .source(spec),
        };
        let names = source.names().await?;
        Ok::<_, SourceError>((source, names))
    }))
    .await;
    let names = sources.iter().zip(&listed).flat_map(|(spec, listing)| {
        let names = listing
            .as_ref()
            .map(|(_, n)| n.as_slice())
            .unwrap_or_default();
        names.iter().map(move |n| (spec, n.as_str()))
    });
    let prod_like = prod_like_env(env, sources, names, patterns, store.map(|s| &**s));
    // A source whose listing failed reads nothing; its error is reported
    // with the others below.
    let results = join_all(listed.into_iter().map(|listing| async move {
        let (source, names) = listing?;
        let entries = source.fetch(&names).await?;
        Ok::<_, SourceError>((entries, source.skipped()))
    }))
    .await;

    let mut fetched = Vec::with_capacity(sources.len());
    let mut warnings: Vec<String> = Vec::new();
    // Credential failures are one line per login, counting its sources, at
    // the place of the first; every other failure is one line per source.
    let mut failures: Vec<Failure> = Vec::new();
    // One hint per distinct fix, so sources failing on two different AWS
    // profiles each name the login they need.
    let mut hints: Vec<String> = Vec::new();
    // `None` once a failure has no hint, or two disagree.
    let mut who: Option<Option<Who>> = None;
    let mut skipped = Vec::new();
    for (n, (spec, result)) in sources.iter().zip(results).enumerate() {
        match result {
            Ok((entries, left_out)) => {
                fetched.push(entries);
                // One another source reads by name, as `--key` takes it,
                // is not left out.
                let named = |secret: &str| {
                    sources.iter().any(|s| {
                        s.provider == Provider::AwsSm
                            && match &s.select {
                                Select::Secret { name, .. } => secret_id(name) == secret,
                                Select::Secrets(names) => {
                                    names.iter().any(|n| secret_id(n) == secret)
                                }
                                Select::Prefix(_) => false,
                            }
                    })
                };
                for (secret, why) in left_out.into_iter().filter(|(s, _)| !named(s)) {
                    let why_text = match why {
                        Skip::NotAnObject => "which is not a JSON object",
                        Skip::Binary => "which is binary",
                        Skip::Denied => "which this login may not read",
                    };
                    warnings.push(format!(
                        "{}: skipped secret {secret}, {why_text}",
                        describe(spec)
                    ));
                    // Only a plain string can be added as one key instead.
                    if why == Skip::NotAnObject {
                        skipped.push(Skipped { source: n, secret });
                    }
                }
            }
            Err(e) if spec.optional => {
                warnings.push(format!("skipped optional source: {}", labelled(spec, &e)));
            }
            Err(e) => {
                let hint = source_hint((project, env), n + 1, spec, &e)
                    .or_else(|| e.hint().map(str::to_owned));
                let this = hint.as_ref().map(|_| source_who(&e));
                who = match who {
                    None => Some(this),
                    Some(w) => Some(w.filter(|w| this == Some(*w))),
                };
                if let Some(h) = hint.filter(|h| !hints.contains(h)) {
                    hints.push(h);
                }
                if matches!(e, SourceError::NeedsLogin { .. }) {
                    let login = login_label(spec);
                    match failures
                        .iter_mut()
                        .find(|f| matches!(f, Failure::Login(l, _) if *l == login))
                    {
                        Some(Failure::Login(_, n)) => *n += 1,
                        _ => failures.push(Failure::Login(login, 1)),
                    }
                } else {
                    failures.push(Failure::Other(labelled(spec, &e)));
                }
            }
        }
    }
    let hint = (!hints.is_empty()).then(|| hints.join("; "));
    if !failures.is_empty() {
        // Failed fetches are not cached, so this is when they were checked.
        let checked = format_clock(crate::source::unix_now());
        let failures = failures
            .into_iter()
            .map(|f| match f {
                Failure::Login(login, n) => format!(
                    "{login}: credentials missing or expired ({n} source{}, checked {checked})",
                    if n == 1 { "" } else { "s" }
                ),
                Failure::Other(message) => message,
            })
            .collect();
        // `fetched` is dropped here, zeroing whatever the other sources
        // returned: no partial environment survives.
        return Err(ResolveError::Sources {
            project: project.clone(),
            env: env.clone(),
            failures,
            hint,
            who: who.flatten(),
        });
    }
    Ok(EnvValues {
        keys: merge(fetched),
        skipped,
        warnings,
        prod_like,
        sources: sources.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::SecretValue;
    use crate::store::ProtonToken;

    /// What is cached of an environment stands across a store write only
    /// if the write cannot have changed what its sources read or how it
    /// is described: a section a file source reads, the Proton token, or
    /// the secrets marked sensitive.
    #[test]
    fn a_store_write_changes_only_what_reads_what_it_wrote() {
        let set = |st: &mut Store, section: &str, key: &str, value: &str| {
            st.set(
                section.parse().unwrap(),
                key.parse().unwrap(),
                SecretValue::new(value.into()),
            );
        };
        let token = |st: &mut Store, token: &str| {
            st.set_proton_token(ProtonToken {
                token: SecretValue::new(token.into()),
                expires: None,
            });
        };
        let base = || {
            let mut st = Store::default();
            set(&mut st, "widget.dev", "A", "1");
            set(&mut st, "gadget.dev", "A", "1");
            token(&mut st, "pst_one");
            st
        };
        let spec = |provider, select| SourceSpec::new(provider, select, false);
        let secret = |name: &str| Select::Secret {
            name: name.into(),
            key: None,
        };
        let aws = [spec(Provider::AwsSm, Select::Prefix("widget/dev/".into()))];
        let own = [spec(Provider::File, secret("widget.dev"))];
        let both = [aws[0].clone(), own[0].clone()];
        let under = [spec(Provider::File, Select::Prefix("widget.".into()))];
        let several = [spec(
            Provider::File,
            Select::Secrets(vec!["widget.dev".into(), "widget.qa".into()]),
        )];
        let proton = [spec(Provider::Proton, secret("widget/DB_URL"))];
        let all = [&aws[..], &own, &both, &under, &several, &proton];
        // Which of `all` stand once `change` is made.
        let stand = |change: &dyn Fn(&mut Store)| -> Vec<bool> {
            let (old, mut new) = (base(), base());
            change(&mut new);
            all.iter().map(|s| fetched_alike(s, &old, &new)).collect()
        };

        // Nothing changed, or what no source here reads: all stand.
        assert_eq!(stand(&|_| {}), [true; 6]);
        assert_eq!(stand(&|st| set(st, "gadget.dev", "B", "2")), [true; 6]);
        assert_eq!(
            stand(&|st| {
                st.mark_env("widget.dev".parse().unwrap(), true);
                st.acknowledge_env("widget.rc".parse().unwrap(), true);
                st.set_remote_enabled(true);
            }),
            [true; 6],
            "read from the store at each request, not cached"
        );
        // A value of a section, a key added to it, a section added under
        // a prefix or among those named: whatever reads it is fetched again.
        let reads_dev = [true, false, false, false, false, true];
        assert_eq!(stand(&|st| set(st, "widget.dev", "A", "2")), reads_dev);
        assert_eq!(stand(&|st| set(st, "widget.dev", "B", "1")), reads_dev);
        assert_eq!(
            stand(&|st| {
                st.unset(&"widget.dev".parse().unwrap(), &"A".parse().unwrap())
                    .unwrap();
            }),
            reads_dev
        );
        assert_eq!(
            stand(&|st| set(st, "widget.qa", "A", "1")),
            [true, true, true, false, false, true]
        );
        // Another token reads another account.
        assert_eq!(
            stand(&|st| token(st, "pst_two")),
            [true, true, true, true, true, false]
        );
        // A secret marked or unmarked may change why an environment looks
        // like production: nothing stands.
        assert_eq!(
            stand(&|st| {
                st.mark_secret(Origin::new(Provider::AwsSm, "widget/prod/db"), true)
                    .unwrap();
            }),
            [false; 6]
        );
        assert_eq!(
            stand(&|st| {
                st.mark_prefix(Origin::new(Provider::AwsSm, "widget/prod/"))
                    .unwrap();
            }),
            [false; 6]
        );
        // `key` is refused by the file provider: never taken as unchanged.
        let keyed = [spec(
            Provider::File,
            Select::Secret {
                name: "widget.dev".into(),
                key: Some("A".parse().unwrap()),
            },
        )];
        assert!(!fetched_alike(&keyed, &base(), &base()));
    }

    /// What a source that names a secret it cannot read is told to do.
    /// Only a step an agent can take on its own is a command in backquotes.
    #[test]
    fn a_named_secret_that_cannot_be_read_says_what_to_do() {
        let project: ProjectName = "widget".parse().unwrap();
        let env: EnvName = "dev".parse().unwrap();
        let named = |names: &[&str]| {
            let select = match names {
                [one] => Select::Secret {
                    name: (*one).into(),
                    key: None,
                },
                many => Select::Secrets(many.iter().map(|n| (*n).into()).collect()),
            };
            let mut spec = SourceSpec::new(Provider::AwsSm, select, false);
            spec.aws.profile = Some("acme-dev".to_owned().try_into().unwrap());
            spec
        };
        let hint = |spec: &SourceSpec, e: SourceError| {
            source_hint((&project, &env), 2, spec, &e).unwrap_or_default()
        };
        let name = || "widget/dev/x".to_owned();
        let one = named(&["widget/dev/x"]);

        assert_eq!(
            hint(&one, SourceError::Binary { name: name() }),
            "kagebunshin reads no binary secret: take it out with `kagebunshin project \
             remove-source widget dev 2`"
        );
        assert_eq!(
            hint(&one, SourceError::Deleted { name: name() }),
            "take it out with `kagebunshin project remove-source widget dev 2`, or have the \
             human restore it with `aws secretsmanager restore-secret`"
        );
        assert_eq!(
            hint(
                &one,
                SourceError::NoProfile {
                    profile: "acme-dev".into()
                }
            ),
            "name one that is with `kagebunshin project set-source widget dev 2 --profile \
             PROFILE`; `aws configure list-profiles` lists them"
        );
        // Whether the project needs a refused secret is the human's to say.
        let denied = hint(&one, SourceError::AccessDenied { name: name() });
        assert_eq!(
            denied,
            "ask the human to let profile acme-dev read it (it needs \
             secretsmanager:GetSecretValue on that secret); or, if this project does not need \
             it, take it out: kagebunshin project remove-source widget dev 2"
        );
        assert!(!denied.contains('`'));

        // Taking out a source of several loses the others.
        let several = named(&["widget/dev/x", "widget/dev/y"]);
        assert!(
            hint(&several, SourceError::Binary { name: name() })
                .ends_with("dev 2` and add its other secrets back with `--secret`")
        );
        assert!(
            hint(&several, SourceError::AccessDenied { name: name() })
                .ends_with("dev 2, then add its other secrets back with --secret")
        );
        assert_eq!(hint(&one, SourceError::NotFound { name: name() }), "");
    }
}
