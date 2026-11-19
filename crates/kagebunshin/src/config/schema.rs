//! The on-disk shapes of `config.toml` and `projects/<name>.toml`.
//!
//! Every table rejects unknown fields, so a typo such as `sensitve_envs` is an
//! error rather than a silently ignored setting. Checks that involve one value
//! run during deserialization, so their errors carry a line number; checks
//! across fields run in [`ProjectFile::validate`].

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::remote::RemoteId;
use crate::ipc::protocol::APPROVAL_TIMEOUT;
pub use crate::source::aws_sm::{AwsSettings, Profile, Region};
use crate::types::{EnvName, KeyName, Provider};

/// The only schema version this build reads and writes.
pub const SCHEMA: u32 = 1;

/// The `schema = 1` line every file starts with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct Schema;

impl TryFrom<u32> for Schema {
    type Error = String;
    fn try_from(v: u32) -> Result<Self, String> {
        if v == SCHEMA {
            Ok(Schema)
        } else {
            Err(format!(
                "schema {v} is not supported; this version of kagebunshin reads schema {SCHEMA}"
            ))
        }
    }
}

impl From<Schema> for u32 {
    fn from(_: Schema) -> u32 {
        SCHEMA
    }
}

/// `config.toml`. Every field but `schema` has a default, and a missing file
/// means all defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema: Schema,
    /// The environment used when `--env` is not given.
    #[serde(default = "default_env")]
    pub default_env: EnvName,
    /// How long the daemon stays unlocked without a request, e.g. `"30m"`.
    #[serde(default)]
    pub idle_timeout: IdleTimeout,
    /// How long a request for values marked sensitive waits for a person
    /// to answer it in the app before it is denied, e.g. `"5m"`.
    #[serde(default)]
    pub approval_timeout: ApprovalTimeout,
    /// The provider of the source an environment gets when it lists none;
    /// see [`super::Registry::env`].
    #[serde(default = "default_provider")]
    pub default_provider: Provider,
    /// Glob patterns (`*` matches any run of characters) for secret names
    /// that look like production, e.g. `"*-prod*"`. Matched against each
    /// name an environment reads, with a full AWS ARN reduced to its secret
    /// name first.
    ///
    /// These count as the built-in rule does (`prod`, `production` or `rc`
    /// as any `/` or `.` segment, ignoring case): an environment that reads
    /// such a name is sensitive by rule until a human marks it sensitive or
    /// acknowledges it is not production, so handing out its values takes
    /// approval in the app; status, diff and unlock say so. See
    /// `daemon::resolve::prod_like`.
    #[serde(default)]
    pub sensitive_source_patterns: Vec<SourcePattern>,
    #[serde(default)]
    pub masking: MaskingConfig,
    /// Refuse to hold secret values in memory that cannot be locked, rather
    /// than warn and keep them in ordinary memory. See `docs/memory.md`.
    #[serde(default)]
    pub strict_memory: bool,
    /// The AWS profile and region a source uses when neither it, its
    /// environment nor its project names one; `kagebunshin connect aws`
    /// writes it.
    #[serde(default, skip_serializing_if = "is_default_aws")]
    pub aws: AwsSettings,
    /// The remote endpoint, when the store turns it on.
    #[serde(default, skip_serializing_if = "is_default_remote")]
    pub remote: RemoteConfig,
    /// The approval page, when a phone is paired.
    #[serde(default, skip_serializing_if = "is_default_phone")]
    pub phone: PhoneConfig,
}

fn is_default_aws(a: &AwsSettings) -> bool {
    *a == AwsSettings::default()
}

fn is_default_remote(r: &RemoteConfig) -> bool {
    *r == RemoteConfig::default()
}

/// The port the remote endpoint listens on unless `[remote] port` says
/// otherwise, on this machine's tailnet address only.
pub const DEFAULT_REMOTE_PORT: u16 = 47_317;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteConfig {
    /// The TCP port on this machine's tailnet address. Whether it listens
    /// at all is up to the local store, which takes the passphrase to
    /// change; see `kagebunshin remote enable`.
    #[serde(default = "default_remote_port")]
    pub port: u16,
}

impl Default for RemoteConfig {
    fn default() -> Self {
        Self {
            port: DEFAULT_REMOTE_PORT,
        }
    }
}

fn default_remote_port() -> u16 {
    DEFAULT_REMOTE_PORT
}

fn is_default_phone(p: &PhoneConfig) -> bool {
    *p == PhoneConfig::default()
}

/// The port the approval page is served on unless `[phone] port` says
/// otherwise, on this machine's tailnet address only.
pub const DEFAULT_PHONE_PORT: u16 = 47_318;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhoneConfig {
    /// The TCP port on this machine's tailnet address. Whether the page is
    /// served at all is up to the local store, which holds the paired
    /// phone. The port is part of the page's address, so a phone that has
    /// the page on its home screen has to add it again after a change.
    #[serde(default = "default_phone_port")]
    pub port: u16,
}

impl Default for PhoneConfig {
    fn default() -> Self {
        Self {
            port: DEFAULT_PHONE_PORT,
        }
    }
}

fn default_phone_port() -> u16 {
    DEFAULT_PHONE_PORT
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema: Schema,
            default_env: default_env(),
            idle_timeout: IdleTimeout::default(),
            approval_timeout: ApprovalTimeout::default(),
            default_provider: default_provider(),
            sensitive_source_patterns: Vec::new(),
            masking: MaskingConfig::default(),
            strict_memory: false,
            aws: AwsSettings::default(),
            remote: RemoteConfig::default(),
            phone: PhoneConfig::default(),
        }
    }
}

#[expect(clippy::expect_used, reason = "a constant, valid env name")]
fn default_env() -> EnvName {
    "dev".parse().expect("valid env name")
}

fn default_provider() -> Provider {
    Provider::File
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaskingConfig {
    /// Values shorter than this are not masked in output, since short strings
    /// match too much ordinary text.
    #[serde(default = "default_min_len")]
    pub min_len: MinLen,
}

impl Default for MaskingConfig {
    fn default() -> Self {
        Self {
            min_len: default_min_len(),
        }
    }
}

fn default_min_len() -> MinLen {
    MinLen(8)
}

/// The masking threshold, from 1 to 1024 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct MinLen(u32);

impl MinLen {
    pub fn get(self) -> usize {
        self.0 as usize
    }
}

impl TryFrom<u32> for MinLen {
    type Error = &'static str;
    fn try_from(v: u32) -> Result<Self, &'static str> {
        if (1..=1024).contains(&v) {
            Ok(Self(v))
        } else {
            Err("min_len must be between 1 and 1024")
        }
    }
}

impl From<MinLen> for u32 {
    fn from(v: MinLen) -> u32 {
        v.0
    }
}

/// A glob over source locations. Only `*` is special.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SourcePattern(String);

impl SourcePattern {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether the whole of `location` matches, ignoring case, `*` matching
    /// any run of characters, including `/` and none at all.
    pub fn matches(&self, location: &str) -> bool {
        let (pattern, location) = (self.0.to_lowercase(), location.to_lowercase());
        let mut parts = pattern.split('*');
        let first = parts.next().unwrap_or_default();
        let Some(mut rest) = location.strip_prefix(first) else {
            return false;
        };
        let parts: Vec<&str> = parts.collect();
        let Some((last, middle)) = parts.split_last() else {
            // No `*`: an exact match.
            return rest.is_empty();
        };
        for part in middle {
            match rest.find(part) {
                Some(at) => rest = &rest[at + part.len()..],
                None => return false,
            }
        }
        rest.len() >= last.len() && rest.ends_with(last)
    }
}

impl TryFrom<String> for SourcePattern {
    type Error = &'static str;
    fn try_from(s: String) -> Result<Self, &'static str> {
        if s.is_empty() || s.chars().all(|c| c == '*') {
            Err("a sensitive source pattern must contain something other than `*`")
        } else {
            Ok(Self(s))
        }
    }
}

impl From<SourcePattern> for String {
    fn from(p: SourcePattern) -> String {
        p.0
    }
}

/// Seconds in a duration written as a whole number and a unit: `90s`,
/// `30m`, `8h`, `1d`. `None` if it is not written that way, `Some(None)` if
/// it overflows.
pub fn duration_secs(s: &str) -> Option<Option<u64>> {
    let split = s.find(|c: char| !c.is_ascii_digit())?;
    let (n, unit) = s.split_at(split);
    let n: u64 = n.parse().ok()?;
    let per = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        _ => return None,
    };
    Some(n.checked_mul(per))
}

/// A duration written as a whole number and a unit: `90s`, `30m`, `8h`, `1d`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct IdleTimeout(Duration);

impl IdleTimeout {
    pub fn get(self) -> Duration {
        self.0
    }
}

impl Default for IdleTimeout {
    fn default() -> Self {
        Self(Duration::from_mins(30))
    }
}

impl TryFrom<String> for IdleTimeout {
    type Error = &'static str;
    fn try_from(s: String) -> Result<Self, &'static str> {
        const BAD: &str =
            "idle_timeout must be a whole number followed by s, m, h or d, e.g. \"30m\"";
        match duration_secs(&s).ok_or(BAD)? {
            Some(0) => Err("idle_timeout must be more than zero"),
            Some(secs) if secs <= 30 * 24 * 60 * 60 => Ok(Self(Duration::from_secs(secs))),
            _ => Err("idle_timeout must be at most 30d"),
        }
    }
}

impl From<IdleTimeout> for String {
    fn from(t: IdleTimeout) -> String {
        written(t.0)
    }
}

/// `d` as [`duration_secs`] reads it, in its largest whole unit.
fn written(d: Duration) -> String {
    let secs = d.as_secs();
    for (per, unit) in [(86_400, "d"), (3_600, "h"), (60, "m")] {
        if secs.is_multiple_of(per) {
            return format!("{}{unit}", secs / per);
        }
    }
    format!("{secs}s")
}

/// How long an approval prompt waits: a whole number and a unit, `90s` or
/// `5m`, at most [`APPROVAL_TIMEOUT`], which is how long a client waits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ApprovalTimeout(Duration);

impl ApprovalTimeout {
    pub fn get(self) -> Duration {
        self.0
    }
}

impl Default for ApprovalTimeout {
    fn default() -> Self {
        Self(Duration::from_mins(5))
    }
}

impl TryFrom<String> for ApprovalTimeout {
    type Error = &'static str;
    fn try_from(s: String) -> Result<Self, &'static str> {
        const BAD: &str = "approval_timeout must be a whole number followed by s or m, e.g. \"5m\"";
        match duration_secs(&s).ok_or(BAD)? {
            Some(0) => Err("approval_timeout must be more than zero"),
            Some(secs) if secs <= APPROVAL_TIMEOUT.as_secs() => Ok(Self(Duration::from_secs(secs))),
            _ => Err("approval_timeout must be at most 30m"),
        }
    }
}

impl From<ApprovalTimeout> for String {
    fn from(t: ApprovalTimeout) -> String {
        written(t.0)
    }
}

/// `projects/<name>.toml`: how one project maps to its sources. Holds names,
/// never values, so it can be handed to a teammate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectFile {
    pub schema: Schema,
    /// Git remotes that identify this project, in any form git accepts.
    pub remotes: Vec<RemoteId>,
    /// The folder of the checkout this project is, relative to its root,
    /// for a repository with one project per app. Unset means the whole
    /// repository. See [`super::Registry::find`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<ProjectPath>,
    /// The AWS named profile for `aws_sm` sources, unless the environment or
    /// the source sets its own. Unset means the ambient AWS configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<Profile>,
    /// Path of the `.env.example` to read, relative to the repository root,
    /// instead of searching for the nearest one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_example: Option<PathBuf>,
    pub envs: BTreeMap<EnvName, EnvFile>,
}

/// A folder relative to a checkout's root: no `..`, not absolute, not
/// empty, written with `/` and no `./` or trailing slash.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ProjectPath(String);

impl ProjectPath {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_path(&self) -> &std::path::Path {
        std::path::Path::new(&self.0)
    }
}

impl std::fmt::Display for ProjectPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for ProjectPath {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        Self::try_from(s.to_owned())
    }
}

impl TryFrom<String> for ProjectPath {
    type Error = String;
    fn try_from(s: String) -> Result<Self, String> {
        use std::path::Component;
        if s.is_empty() {
            return Err("path must not be empty; leave it out for the whole repository".into());
        }
        if s.chars().any(char::is_control) {
            return Err("path must not contain control characters".into());
        }
        let mut parts = Vec::new();
        for c in std::path::Path::new(&s).components() {
            match c {
                Component::Normal(p) => parts.push(p.to_string_lossy().into_owned()),
                Component::CurDir => {}
                Component::ParentDir => return Err("path must not contain `..`".into()),
                Component::RootDir | Component::Prefix(_) => {
                    return Err("path must be relative to the repository root".into());
                }
            }
        }
        if parts.is_empty() {
            return Err("path must name a folder; leave it out for the whole repository".into());
        }
        Ok(Self(parts.join("/")))
    }
}

impl From<ProjectPath> for String {
    fn from(p: ProjectPath) -> String {
        p.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvFile {
    /// Marks the environment sensitive in the store at the next unlock.
    /// Any process of the user can edit this file, so the mark is kept in
    /// the encrypted store: deleting the flag, or setting it false, does not
    /// remove it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub sensitive: bool,
    /// The AWS named profile for this environment's `aws_sm` sources, over
    /// the project's, unless a source sets its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<Profile>,
    /// `sensitive_keys` was parsed but never enforced; it is refused so
    /// that nobody relies on it. See [`no_sensitive_keys`].
    #[serde(
        default,
        rename = "sensitive_keys",
        skip_serializing,
        deserialize_with = "no_sensitive_keys"
    )]
    removed_sensitive_keys: Option<()>,
    /// Applied in order; a later source wins over an earlier one. Empty
    /// means one default source, see [`super::Registry::env`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<SourceEntry>,
    /// Plain settings that are not secret (`PORT = "3000"`), the lowest
    /// layer: a key any source sets takes the source's value. Never
    /// sensitive, and never masked in a command's output.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub vars: BTreeMap<KeyName, String>,
}

/// Refuses `sensitive_keys`, pointing at the marks that are enforced. The
/// message never quotes the value.
fn no_sensitive_keys<'de, D: serde::Deserializer<'de>>(_: D) -> Result<Option<()>, D::Error> {
    Err(serde::de::Error::custom(
        "sensitive_keys is not supported; mark what agents must not read in the app instead",
    ))
}

impl ProjectFile {
    /// Checks that span fields. Messages name fields and environments only.
    pub fn validate(&self) -> Result<(), String> {
        if self.remotes.is_empty() {
            return Err("remotes must list at least one git remote".into());
        }
        let mut seen = BTreeSet::new();
        for r in &self.remotes {
            if !seen.insert(r) {
                return Err(format!("remote {r} is listed twice"));
            }
        }
        if self.envs.is_empty() {
            return Err("at least one [envs.<name>] table is required".into());
        }
        Ok(())
    }
}

/// One `[[envs.<env>.sources]]` entry, as written in the project file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawSource", into = "RawSource")]
pub struct SourceEntry {
    pub provider: Provider,
    /// `None` only for a `file` source with no `secret`, `secrets` or
    /// `prefix`: it reads the environment's own `[<project>.<env>]` section,
    /// filled in by [`super::Registry::env`].
    pub select: Option<Select>,
    pub optional: bool,
    /// `aws_sm` only, written as `profile` and `region` on the source: the
    /// AWS profile for this source, over the environment's and the
    /// project's, and the region, over the one the AWS configuration chain
    /// (the profile, `AWS_REGION`) would pick. Empty for other providers.
    pub aws: AwsSettings,
    /// `aws_sm` only: secrets to mark sensitive in the store at the next
    /// unlock, as [`EnvFile::sensitive`] does for an environment.
    pub sensitive: Vec<String>,
}

/// A source of one environment, with its selector settled: what the daemon
/// resolves. See [`super::Registry::env`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceSpec {
    pub provider: Provider,
    pub select: Select,
    /// If this source fails, the environment resolves without it and the
    /// failure is reported as a warning; otherwise any failure fails the
    /// whole environment. A prefix that matches nothing is not a failure for
    /// an optional source.
    pub optional: bool,
    /// What only the AWS provider reads. For `aws_sm`, the profile in
    /// effect (see [`super::Registry::env`]; `None` means the ambient AWS
    /// configuration) and the source's region. Empty for other providers.
    pub aws: AwsSettings,
    /// Set only on a `file` source that reads the environment's own
    /// `[<project>.<env>]` section (see [`super::Registry::env`]): that
    /// section not being in the store yet reads as an empty section, so
    /// the environment resolves, and says which keys are missing, before a
    /// human has stored anything. A source naming another section that is
    /// missing still fails.
    pub missing_is_empty: bool,
}

impl SourceSpec {
    /// A source with no provider settings of its own.
    pub fn new(provider: Provider, select: Select, optional: bool) -> Self {
        Self {
            provider,
            select,
            optional,
            aws: AwsSettings::default(),
            missing_is_empty: false,
        }
    }
}

/// Which secrets a source reads. The AWS source takes this type directly.
///
/// For the `file` provider a secret is a section of the local store: `secret
/// = "widget.dev"` reads the `[widget.dev]` table, whose entries become keys
/// the way a JSON secret's fields do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Select {
    /// One secret. With `key`, its whole string is that key's value instead
    /// of a JSON object of keys.
    Secret { name: String, key: Option<KeyName> },
    /// Several secrets, applied in order.
    Secrets(Vec<String>),
    /// Every secret whose name starts with this prefix, in name order.
    Prefix(String),
}

impl Select {
    /// The locations this source names, for display and pattern matching.
    pub fn locations(&self) -> Vec<&str> {
        match self {
            Select::Secret { name, .. } => vec![name],
            Select::Secrets(names) => names.iter().map(String::as_str).collect(),
            Select::Prefix(p) => vec![p],
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSource {
    provider: Provider,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key: Option<KeyName>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    secrets: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    prefix: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    optional: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    profile: Option<Profile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    region: Option<Region>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    sensitive: Vec<String>,
}

impl TryFrom<RawSource> for SourceEntry {
    type Error = String;
    fn try_from(r: RawSource) -> Result<Self, String> {
        if r.provider != Provider::AwsSm {
            for (field, set) in [
                ("profile", r.profile.is_some()),
                ("region", r.region.is_some()),
                ("sensitive", !r.sensitive.is_empty()),
            ] {
                if set {
                    return Err(format!(
                        "{field} can only be used with provider \"aws_sm\", not \"{}\"",
                        r.provider.as_str()
                    ));
                }
            }
        }
        let bare_file = r.provider == Provider::File
            && (&r.secret, &r.secrets, &r.prefix) == (&None, &None, &None);
        if r.key.is_some()
            && r.secret.is_none()
            && (bare_file || r.secrets.is_some() || r.prefix.is_some())
        {
            return Err("key can only be used with secret".into());
        }
        if bare_file {
            return Ok(Self {
                provider: r.provider,
                select: None,
                optional: r.optional,
                aws: AwsSettings::default(),
                sensitive: Vec::new(),
            });
        }
        let select = match (r.secret, r.secrets, r.prefix) {
            (Some(name), None, None) => {
                check_location("secret", &name)?;
                Select::Secret { name, key: r.key }
            }
            (None, Some(names), None) => {
                if names.is_empty() {
                    return Err("secrets must list at least one secret".into());
                }
                let mut seen = BTreeSet::new();
                for n in &names {
                    check_location("secrets", n)?;
                    if !seen.insert(n) {
                        return Err(format!("secret {n} is listed twice"));
                    }
                }
                Select::Secrets(names)
            }
            (None, None, Some(prefix)) => {
                check_location("prefix", &prefix)?;
                if r.provider == Provider::Proton
                    && prefix.starts_with(crate::source::proton::GLOBAL_SCOPE)
                {
                    return Err(format!(
                        "keys in the global vault are added one at a time, each with `--secret {0}KEY` \
                         (`kagebunshin project add-source PROJECT ENV --provider proton --secret {0}KEY`), \
                         not a prefix",
                        crate::source::proton::GLOBAL_SCOPE
                    ));
                }
                Select::Prefix(prefix)
            }
            _ => return Err("a source must set exactly one of secret, secrets or prefix".into()),
        };
        Ok(Self {
            provider: r.provider,
            select: Some(select),
            optional: r.optional,
            aws: AwsSettings {
                profile: r.profile,
                region: r.region,
            },
            sensitive: r.sensitive,
        })
    }
}

fn check_location(field: &str, s: &str) -> Result<(), String> {
    if s.is_empty() {
        Err(format!("{field} must not be empty"))
    } else if s.chars().any(|c| c.is_whitespace() || c.is_control()) {
        Err(format!(
            "{field} must not contain whitespace or control characters"
        ))
    } else {
        Ok(())
    }
}

impl From<SourceEntry> for RawSource {
    fn from(s: SourceEntry) -> Self {
        let mut r = RawSource {
            provider: s.provider,
            secret: None,
            key: None,
            secrets: None,
            prefix: None,
            optional: s.optional,
            profile: s.aws.profile,
            region: s.aws.region,
            sensitive: s.sensitive,
        };
        match s.select {
            None => {}
            Some(Select::Secret { name, key }) => {
                r.secret = Some(name);
                r.key = key;
            }
            Some(Select::Secrets(names)) => r.secrets = Some(names),
            Some(Select::Prefix(p)) => r.prefix = Some(p),
        }
        r
    }
}
