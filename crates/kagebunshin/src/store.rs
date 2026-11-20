//! The local store: one age file, encrypted with a passphrase (age's scrypt
//! recipient), holding TOML sections of keys and string values.
//!
//! ```toml
//! [widget.dev]
//! API_KEY = "…"
//! DB_URL = { value = "…", sensitive = true }
//!
//! [_marks]
//! envs = ["widget.prod"]
//! secrets = [{ provider = "aws_sm", location = "widget/dev/stripe" }]
//! not_production = ["widget.dev"]
//!
//! [_proton]
//! token = "…"
//! expires = 1767225600
//!
//! [_remote]
//! enabled = true
//! grants = [{ machine = "buildbox", node = "nAbC123", project = "widget", envs = ["dev"], token = "9f86…", expires = 1767225600 }]
//!
//! [_phone]
//! name = "phone"
//! node = "nDeF456"
//! credential = "q83v…"
//! key = "BHk1…"
//! paired = 1767225600
//! ```
//!
//! `[_phone]` holds the phone that may approve requests on the approval
//! page: its name and stable node id on the tailnet, and the id and public
//! key of the passkey it made when it was paired. There is no secret in
//! it; it is in the store so that changing it takes the passphrase.
//!
//! `[_remote]` holds the remote endpoint: whether it is on, and which
//! machines on the tailnet may use which environments, each by the stable
//! node id tailscaled gave the machine's name when it was granted, and
//! until when, if the grant ends. Each grant has a token its machine must
//! send; `token` is that token's SHA-256, never the token, so reading the
//! store does not give it. Like the marks, changing it takes the
//! passphrase.
//!
//! `[_proton]` holds the Proton Pass personal access token that
//! `kagebunshin connect proton` saved, and when it expires (Unix seconds),
//! if known.
//!
//! A section is `[<project>.<env>]`; the `file` provider reads it as one
//! secret named `<project>.<env>`. `[_marks]` (no project name starts with
//! `_`) holds the other sensitive marks: whole environments, and secrets of
//! any provider by where they are read from. What is marked sensitive is
//! never handed out. `not_production` lists environments a human
//! acknowledged are not production although they look it: that turns the
//! warning off and marks nothing. Every mark is inside the encrypted file,
//! so changing one takes the passphrase. The file is written atomically, mode 0600,
//! while holding an exclusive lock on `<store>.lock`. Every write decrypts
//! the current file with the passphrase it was given before changing
//! anything, so a write is also a passphrase check.
//!
//! One thing is written without the passphrase: a mark *added* from the
//! command line ([`Mark`]). There is nothing to encrypt it with then, so it
//! waits in `<store>.marks`, a plain JSON list beside the store, and the
//! next write, which has the passphrase, moves it into the store and
//! removes that file. The list only ever adds marks. Deleting it before
//! then drops them; see `docs/threat-model.md`.
//!
//! Errors never contain values. A TOML error quotes the offending line,
//! which here could be a value, so parse errors carry only a line number.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use age::secrecy::SecretString;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::atomic;
use crate::secret::SecretValue;
use crate::types::{EnvName, KeyName, NameError, Origin, ProjectName};

pub const STORE_FILE: &str = "store.age";

/// The passphrase that encrypts the store. Zeroed on drop, never printed.
pub struct Passphrase(SecretString);

impl Passphrase {
    /// Takes ownership of `s` without copying it.
    pub fn new(s: String) -> Self {
        Self(SecretString::from(s))
    }

    fn is_empty(&self) -> bool {
        use age::secrecy::ExposeSecret;
        self.0.expose_secret().is_empty()
    }

    /// The same passphrase again, for a request that opens the store twice.
    pub(crate) fn copy(&self) -> Self {
        use age::secrecy::ExposeSecret;
        Self::new(self.0.expose_secret().to_owned())
    }
}

impl fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Passphrase(<redacted>)")
    }
}

/// A store section name, `<project>.<env>`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Section {
    pub project: ProjectName,
    pub env: EnvName,
}

impl fmt::Display for Section {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.project, self.env)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SectionError {
    #[error("a store section is named <project>.<env>")]
    NoDot,
    #[error(transparent)]
    Name(#[from] NameError),
}

impl FromStr for Section {
    type Err = SectionError;
    fn from_str(s: &str) -> Result<Self, SectionError> {
        let (project, env) = s.split_once('.').ok_or(SectionError::NoDot)?;
        Ok(Self {
            project: project.parse()?,
            env: env.parse()?,
        })
    }
}

impl TryFrom<String> for Section {
    type Error = SectionError;
    fn try_from(s: String) -> Result<Self, SectionError> {
        s.parse()
    }
}

impl From<Section> for String {
    fn from(s: Section) -> Self {
        s.to_string()
    }
}

/// Why the store could not be read or written. Names paths, sections and
/// keys, never values.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    #[error("there is no local store at {}", path.display())]
    Missing { path: PathBuf },
    #[error("a local store already exists at {}", path.display())]
    Exists { path: PathBuf },
    #[error("the local store is encrypted; a passphrase is needed to unlock it")]
    PassphraseRequired,
    #[error("wrong passphrase for the local store")]
    WrongPassphrase,
    #[error("the passphrase must not be empty")]
    EmptyPassphrase,
    #[error("{} is not a readable age file: {problem}", path.display())]
    Corrupt {
        path: PathBuf,
        problem: &'static str,
    },
    /// `line` is 1-based; `None` when the parser gave no position.
    #[error("{} decrypts to invalid store contents{}", path.display(), at_line(*line))]
    Parse { path: PathBuf, line: Option<usize> },
    #[error("a file secret is a store section: mark its keys instead")]
    FileSecretMark,
    #[error(
        "{secret} is marked through prefix {prefix}, which covers every secret under it; \
         nothing was unmarked"
    )]
    CoveredByPrefix { secret: Origin, prefix: Origin },
    #[error("key {key} is not in section [{section}]")]
    NoKey { section: Section, key: KeyName },
    #[error("the local store has no section of project {project}")]
    NoSection { project: ProjectName },
    #[error("no remote grant to {machine}{}", project.as_ref().map(|p| format!(" for project {p}")).unwrap_or_default())]
    NoGrant {
        machine: String,
        project: Option<ProjectName>,
    },
    #[error("no phone is paired")]
    NoPhone,
    #[error("{}: {message}", path.display())]
    Io { path: PathBuf, message: String },
}

/// The 1-based line that byte `offset` of `text` is on.
fn line_of(text: &[u8], offset: usize) -> usize {
    let end = offset.min(text.len());
    text[..end].iter().filter(|b| **b == b'\n').count() + 1
}

fn at_line(line: Option<usize>) -> String {
    line.map(|l| format!(" at line {l}")).unwrap_or_default()
}

fn io_error(path: &Path, e: &io::Error) -> StoreError {
    StoreError::Io {
        path: path.into(),
        message: e.to_string(),
    }
}

/// The decrypted contents: sections of keys. Dropping it zeroes the values.
#[derive(Debug, Default)]
pub struct Store {
    sections: BTreeMap<Section, BTreeMap<KeyName, SecretValue>>,
    /// Keys marked sensitive. Every one is also in `sections`.
    sensitive: BTreeSet<(Section, KeyName)>,
    /// Environments marked sensitive, as `<project>.<env>`. They need not
    /// have a section.
    envs: BTreeSet<Section>,
    /// Secrets marked sensitive, by provider and location: what a key's
    /// [`Origin`] says it came from.
    secrets: BTreeSet<Origin>,
    /// Prefixes marked sensitive, by provider and the start of a stable id:
    /// every secret whose id starts with one is marked, however a source
    /// names it. Written when an environment with a prefix source is marked.
    prefixes: BTreeSet<Origin>,
    /// Environments acknowledged as not production, as `<project>.<env>`:
    /// they look like production but are not, so they are not warned
    /// about. Not a sensitive mark.
    not_production: BTreeSet<Section>,
    /// The Proton Pass token, if one is connected.
    proton: Option<ProtonToken>,
    /// Whether the remote endpoint is on.
    remote_enabled: bool,
    /// Who may use it, at most one per machine and project.
    grants: Vec<RemoteGrant>,
    /// The phone that may approve requests, if one is paired.
    phone: Option<PairedPhone>,
}

/// The phone that may approve requests on the approval page: a machine on
/// the tailnet and the passkey it made when it was paired.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairedPhone {
    /// Its name on the tailnet when it was paired: the first label of its
    /// `MagicDNS` name.
    pub name: String,
    /// The stable node id tailscaled gave it. The page is served to this
    /// node and no other, whatever it is called now.
    pub node: String,
    /// The id of its passkey, base64url without padding.
    pub credential: String,
    /// The passkey's public key, an uncompressed P-256 point, base64url
    /// without padding. An approval is a signature this key verifies.
    pub key: String,
    /// When it was paired, in Unix seconds.
    pub paired: u64,
}

/// A machine on the tailnet that may use some of a project's environments
/// through the remote endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteGrant {
    /// The machine's name, as it was granted: the first label of its
    /// `MagicDNS` name.
    pub machine: String,
    /// The stable node id tailscaled gave that name when it was granted. A
    /// grant matches this, not the name, so another machine renamed to it
    /// gets nothing.
    pub node: String,
    pub project: ProjectName,
    pub envs: Vec<EnvName>,
    /// The SHA-256 of the token its machine must send. `None` for a grant
    /// made before grants had tokens, which lets nothing through.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<TokenHash>,
    /// When it ends, in Unix seconds; `None` for never.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<u64>,
}

/// What a remote grant's token starts with, so one found in a file or a
/// log can be told for what it is.
pub const TOKEN_PREFIX: &str = "kbr_";

/// A new token for a remote grant: [`TOKEN_PREFIX`] and 32 bytes from the
/// operating system, in hex.
pub fn new_token() -> io::Result<Zeroizing<String>> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(bytes.as_mut_slice()).map_err(io::Error::other)?;
    let mut token = Zeroizing::new(String::with_capacity(TOKEN_PREFIX.len() + 64));
    token.push_str(TOKEN_PREFIX);
    push_hex(&mut token, bytes.as_slice());
    Ok(token)
}

/// Appends `bytes` in hex, with no copy of a digit left elsewhere.
fn push_hex(out: &mut String, bytes: &[u8]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0xf)]));
    }
}

/// The SHA-256 of a remote grant's token: what the store keeps of it, and
/// what a request's token is compared by, in constant time. A token is 32
/// random bytes, so its hash says nothing about it; `Debug` still leaves
/// it out.
#[derive(Clone, Copy)]
pub struct TokenHash([u8; 32]);

impl TokenHash {
    pub fn of(token: &str) -> Self {
        Self(Sha256::digest(token.as_bytes()).into())
    }

    fn hex(self) -> String {
        let mut out = String::with_capacity(64);
        push_hex(&mut out, &self.0);
        out
    }

    fn from_hex(s: &str) -> Option<Self> {
        if s.len() != 64 || !s.is_ascii() {
            return None;
        }
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
        }
        Some(Self(out))
    }
}

impl PartialEq for TokenHash {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for TokenHash {}

impl fmt::Debug for TokenHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TokenHash(..)")
    }
}

impl Serialize for TokenHash {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.hex())
    }
}

impl<'de> Deserialize<'de> for TokenHash {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::from_hex(&s)
            .ok_or_else(|| serde::de::Error::custom("a grant's token is 64 hex digits"))
    }
}

impl RemoteGrant {
    /// Whether it lets node `node` use `env` of `project` at `now`.
    pub fn covers(&self, node: &str, project: &ProjectName, env: &EnvName, now: u64) -> bool {
        self.node == node
            && &self.project == project
            && self.envs.contains(env)
            && self.expires.is_none_or(|end| now < end)
    }
}

/// A Proton Pass personal access token. `Debug` never shows it.
#[derive(Debug)]
pub struct ProtonToken {
    pub token: SecretValue,
    /// When it stops working, in Unix seconds, if known.
    pub expires: Option<u64>,
}

/// One sensitive mark to add, as the store keeps it: what
/// [`Store::new_marks`] finds and [`Store::add_mark`] adds again.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mark {
    Env(Section),
    Secret(Origin),
    Prefix(Origin),
    Key(Section, KeyName),
}

/// What a write did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Change {
    Created,
    Added,
    Replaced,
    Removed,
    Rekeyed,
    Marked,
    Unmarked,
    Enabled,
    Disabled,
}

impl Store {
    pub fn section(&self, s: &Section) -> Option<&BTreeMap<KeyName, SecretValue>> {
        self.sections.get(s)
    }

    /// Every section, in name order.
    /// Whether the sections `pick` chooses are the same here and in
    /// `other`: the same sections, each with the same keys and values.
    pub fn same_sections(&self, other: &Self, pick: impl Fn(&Section) -> bool) -> bool {
        let ours: Vec<_> = self.sections.iter().filter(|(s, _)| pick(s)).collect();
        let theirs: Vec<_> = other.sections.iter().filter(|(s, _)| pick(s)).collect();
        ours.len() == theirs.len()
            && ours.iter().zip(&theirs).all(|((s, keys), (t, others))| {
                s == t
                    && keys.len() == others.len()
                    && keys
                        .iter()
                        .zip(others.iter())
                        .all(|((k, v), (l, w))| k == l && v.expose() == w.expose())
            })
    }

    pub fn sections(&self) -> impl Iterator<Item = (&Section, &BTreeMap<KeyName, SecretValue>)> {
        self.sections.iter()
    }

    /// Sets `key`. Replacing a value keeps its sensitive mark: only
    /// [`Store::mark`] removes one.
    pub fn set(&mut self, section: Section, key: KeyName, value: SecretValue) -> Change {
        // A replaced value is dropped, and zeroed, here.
        match self.sections.entry(section).or_default().insert(key, value) {
            Some(_) => Change::Replaced,
            None => Change::Added,
        }
    }

    /// Removes `key`, and its section once empty.
    pub fn unset(&mut self, section: &Section, key: &KeyName) -> Result<Change, StoreError> {
        let missing = || StoreError::NoKey {
            section: section.clone(),
            key: key.clone(),
        };
        let keys = self.sections.get_mut(section).ok_or_else(missing)?;
        keys.remove(key).ok_or_else(missing)?;
        if keys.is_empty() {
            self.sections.remove(section);
        }
        self.sensitive.remove(&(section.clone(), key.clone()));
        Ok(Change::Removed)
    }

    /// Removes every section of `project`, with its keys' marks: what a
    /// removed project left. The marks of its environments are a human's
    /// decisions and stay.
    pub fn clear_project(&mut self, project: &ProjectName) -> Result<Change, StoreError> {
        let before = self.sections.len();
        // The values are dropped, and zeroed, here.
        self.sections.retain(|s, _| s.project != *project);
        if self.sections.len() == before {
            return Err(StoreError::NoSection {
                project: project.clone(),
            });
        }
        self.sensitive.retain(|(s, _)| s.project != *project);
        Ok(Change::Removed)
    }

    pub fn is_sensitive(&self, section: &Section, key: &KeyName) -> bool {
        self.sensitive.contains(&(section.clone(), key.clone()))
    }

    /// Marks `key` sensitive, or with `sensitive` false removes the mark.
    pub fn mark(
        &mut self,
        section: &Section,
        key: &KeyName,
        sensitive: bool,
    ) -> Result<Change, StoreError> {
        if !self.section(section).is_some_and(|k| k.contains_key(key)) {
            return Err(StoreError::NoKey {
                section: section.clone(),
                key: key.clone(),
            });
        }
        let id = (section.clone(), key.clone());
        Ok(if sensitive {
            self.sensitive.insert(id);
            Change::Marked
        } else {
            self.sensitive.remove(&id);
            Change::Unmarked
        })
    }

    /// Whether environment `env` of `project` is marked sensitive.
    pub fn env_marked(&self, project: &ProjectName, env: &EnvName) -> bool {
        self.envs
            .iter()
            .any(|s| &s.project == project && &s.env == env)
    }

    /// The environments marked sensitive, in name order.
    pub fn marked_envs(&self) -> impl Iterator<Item = &Section> {
        self.envs.iter()
    }

    /// Marks an environment sensitive, or with `sensitive` false removes
    /// the mark. The environment need not exist yet.
    pub fn mark_env(&mut self, env: Section, sensitive: bool) -> Change {
        if sensitive {
            self.envs.insert(env);
            Change::Marked
        } else {
            self.envs.remove(&env);
            Change::Unmarked
        }
    }

    /// Whether environment `env` of `project` is acknowledged as not
    /// production.
    pub fn env_acknowledged(&self, project: &ProjectName, env: &EnvName) -> bool {
        self.not_production
            .iter()
            .any(|s| &s.project == project && &s.env == env)
    }

    /// The environments acknowledged as not production, in name order.
    pub fn acknowledged_envs(&self) -> impl Iterator<Item = &Section> {
        self.not_production.iter()
    }

    /// Acknowledges an environment as not production, or with
    /// `acknowledged` false takes that back. The environment need not exist
    /// yet.
    pub fn acknowledge_env(&mut self, env: Section, acknowledged: bool) -> Change {
        if acknowledged {
            self.not_production.insert(env);
            Change::Marked
        } else {
            self.not_production.remove(&env);
            Change::Unmarked
        }
    }

    /// The connected Proton Pass token, if any.
    pub fn proton_token(&self) -> Option<&ProtonToken> {
        self.proton.as_ref()
    }

    /// Saves the Proton Pass token, replacing any earlier one.
    pub fn set_proton_token(&mut self, token: ProtonToken) -> Change {
        // A replaced token is dropped, and zeroed, here.
        match self.proton.replace(token) {
            Some(_) => Change::Replaced,
            None => Change::Added,
        }
    }

    /// Whether the remote endpoint is on.
    pub fn remote_enabled(&self) -> bool {
        self.remote_enabled
    }

    pub fn set_remote_enabled(&mut self, enabled: bool) -> Change {
        self.remote_enabled = enabled;
        if enabled {
            Change::Enabled
        } else {
            Change::Disabled
        }
    }

    /// The remote grants, in the order they were made.
    pub fn remote_grants(&self) -> &[RemoteGrant] {
        &self.grants
    }

    /// Saves `grant`, replacing the one to the same machine for the same
    /// project.
    pub fn grant_remote(&mut self, grant: RemoteGrant) -> Change {
        let same = |g: &RemoteGrant| g.node == grant.node && g.project == grant.project;
        if let Some(old) = self.grants.iter_mut().find(|g| same(g)) {
            *old = grant;
            Change::Replaced
        } else {
            self.grants.push(grant);
            Change::Added
        }
    }

    /// Gives the grant to `machine`, by name or node id, for `project` the
    /// token whose hash is `token`, ending the one it had. Says the
    /// machine's name.
    pub fn rotate_remote(
        &mut self,
        machine: &str,
        project: &ProjectName,
        token: TokenHash,
    ) -> Result<(Change, String), StoreError> {
        let named = |g: &RemoteGrant| g.machine.eq_ignore_ascii_case(machine) || g.node == machine;
        match self
            .grants
            .iter_mut()
            .find(|g| named(g) && &g.project == project)
        {
            Some(g) => {
                g.token = Some(token);
                Ok((Change::Replaced, g.machine.clone()))
            }
            None => Err(StoreError::NoGrant {
                machine: machine.to_owned(),
                project: Some(project.clone()),
            }),
        }
    }

    /// Removes the grants to `machine`, by name or node id: the one for
    /// `project`, or all of them.
    pub fn revoke_remote(
        &mut self,
        machine: &str,
        project: Option<&ProjectName>,
    ) -> Result<Change, StoreError> {
        let before = self.grants.len();
        self.grants.retain(|g| {
            let named = g.machine.eq_ignore_ascii_case(machine) || g.node == machine;
            !(named && project.is_none_or(|p| &g.project == p))
        });
        if self.grants.len() == before {
            return Err(StoreError::NoGrant {
                machine: machine.to_owned(),
                project: project.cloned(),
            });
        }
        Ok(Change::Removed)
    }

    /// The paired phone, if any.
    pub fn phone(&self) -> Option<&PairedPhone> {
        self.phone.as_ref()
    }

    /// Pairs `phone`, replacing the one paired before: there is one.
    pub fn pair_phone(&mut self, phone: PairedPhone) -> Change {
        match self.phone.replace(phone) {
            Some(_) => Change::Replaced,
            None => Change::Added,
        }
    }

    /// Removes the paired phone.
    pub fn unpair_phone(&mut self) -> Result<Change, StoreError> {
        match self.phone.take() {
            Some(_) => Ok(Change::Removed),
            None => Err(StoreError::NoPhone),
        }
    }

    /// The secrets marked sensitive, in order.
    pub fn marked_secrets(&self) -> impl Iterator<Item = &Origin> {
        self.secrets.iter()
    }

    /// The prefixes marked sensitive, in order.
    pub fn marked_prefixes(&self) -> impl Iterator<Item = &Origin> {
        self.prefixes.iter()
    }

    /// Marks every secret whose stable id starts with `prefix` sensitive.
    /// [`Self::mark_secret`] with the same origin and `false` removes it.
    pub fn mark_prefix(&mut self, prefix: Origin) -> Result<Change, StoreError> {
        if prefix.provider == crate::types::Provider::File {
            return Err(StoreError::FileSecretMark);
        }
        self.prefixes.insert(prefix);
        Ok(Change::Marked)
    }

    /// Marks a secret sensitive, or with `sensitive` false removes the
    /// mark. A `file` secret is a section: mark its keys instead.
    /// Unmarking one that a marked prefix still covers fails, naming the
    /// prefix.
    pub fn mark_secret(&mut self, secret: Origin, sensitive: bool) -> Result<Change, StoreError> {
        if secret.provider == crate::types::Provider::File {
            return Err(StoreError::FileSecretMark);
        }
        let secret = crate::source::stable_origin(secret.provider, &secret.location);
        if !sensitive {
            let covering = self.prefixes.iter().find(|p| {
                **p != secret
                    && p.provider == secret.provider
                    && secret.location.starts_with(p.location.as_str())
            });
            if let Some(prefix) = covering {
                return Err(StoreError::CoveredByPrefix {
                    prefix: prefix.clone(),
                    secret,
                });
            }
        }
        Ok(if sensitive {
            self.secrets.insert(secret);
            Change::Marked
        } else {
            self.secrets.remove(&secret);
            self.prefixes.remove(&secret);
            Change::Unmarked
        })
    }

    /// A copy, values included: what writing it and reading it back gives.
    pub fn duplicate(&self) -> Result<Self, StoreError> {
        Self::parse(Path::new("the unlocked store"), &self.render())
    }

    /// The marks added since `before`, a copy of this store made earlier:
    /// what [`Self::add_mark`] needs to add them to another copy.
    pub fn new_marks(&self, before: &Self) -> Vec<Mark> {
        let envs = self.envs.difference(&before.envs).cloned().map(Mark::Env);
        let secrets = (self.secrets.difference(&before.secrets))
            .cloned()
            .map(Mark::Secret);
        let prefixes = (self.prefixes.difference(&before.prefixes))
            .cloned()
            .map(Mark::Prefix);
        let keys = (self.sensitive.difference(&before.sensitive))
            .cloned()
            .map(|(s, k)| Mark::Key(s, k));
        envs.chain(secrets).chain(prefixes).chain(keys).collect()
    }

    /// Adds `mark`. One that cannot be added is skipped: a key that is no
    /// longer set, or a `file` secret, which nothing here writes.
    pub fn add_mark(&mut self, mark: Mark) {
        match mark {
            Mark::Env(env) => {
                self.mark_env(env, true);
            }
            Mark::Secret(secret) => {
                let _ = self.mark_secret(secret, true);
            }
            Mark::Prefix(prefix) => {
                let _ = self.mark_prefix(prefix);
            }
            Mark::Key(section, key) => {
                let _ = self.mark(&section, &key, true);
            }
        }
    }

    /// Parses decrypted contents. On error reports only a line number:
    /// the TOML parser's own message quotes the line, which may hold a value.
    fn parse(path: &Path, text: &str) -> Result<Self, StoreError> {
        let raw: Raw = toml::from_str(text).map_err(|e| StoreError::Parse {
            path: path.into(),
            line: e.span().map(|s| line_of(text.as_bytes(), s.start)),
        })?;
        let mut sections = BTreeMap::new();
        let mut sensitive = BTreeSet::new();
        for (project, envs) in raw.sections {
            for (env, keys) in envs {
                let section = Section {
                    project: project.clone(),
                    env,
                };
                let keys: BTreeMap<_, _> = keys
                    .into_iter()
                    .map(|(k, v)| {
                        if v.sensitive {
                            sensitive.insert((section.clone(), k.clone()));
                        }
                        (k, v.value)
                    })
                    .collect();
                if !keys.is_empty() {
                    sections.insert(section, keys);
                }
            }
        }
        Ok(Self {
            sections,
            sensitive,
            envs: raw.marks.envs.into_iter().collect(),
            secrets: raw.marks.secrets.into_iter().collect(),
            prefixes: raw.marks.prefixes.into_iter().collect(),
            not_production: raw.marks.not_production.into_iter().collect(),
            proton: raw.proton.map(|p| ProtonToken {
                token: p.token.value,
                expires: p.expires,
            }),
            remote_enabled: raw.remote.as_ref().is_some_and(|r| r.enabled),
            grants: raw.remote.map(|r| r.grants).unwrap_or_default(),
            phone: raw.phone,
        })
    }

    /// The TOML plaintext. Written by hand, into one allocation sized up
    /// front, so no partial copy of a value is left behind by reallocation.
    fn render(&self) -> Zeroizing<String> {
        const HEADER: &str = "# kagebunshin local store: [<project>.<env>] sections\n";
        let worst: usize = self
            .sections
            .iter()
            .map(|(s, keys)| {
                let keys: usize = keys
                    .iter()
                    .map(|(k, v)| k.as_str().len() + 6 * v.len() + 8 + SENSITIVE.len())
                    .sum();
                s.to_string().len() + 4 + keys
            })
            .sum();
        let marks: usize = 60
            + self
                .envs
                .iter()
                .map(|e| e.to_string().len() + 4)
                .sum::<usize>()
            + self
                .secrets
                .iter()
                .map(|o| 6 * o.location.len() + 40)
                .sum::<usize>()
            + self
                .not_production
                .iter()
                .map(|e| e.to_string().len() + 24)
                .sum::<usize>()
            + self
                .prefixes
                .iter()
                .map(|o| 6 * o.location.len() + 48)
                .sum::<usize>()
            + self.proton.as_ref().map_or(0, |p| 6 * p.token.len() + 64)
            + 48
            + self
                .grants
                .iter()
                .map(|g| {
                    6 * (g.machine.len() + g.node.len())
                        + g.project.as_str().len()
                        + g.envs.iter().map(|e| e.as_str().len() + 4).sum::<usize>()
                        + 100
                })
                .sum::<usize>()
            + self.phone.as_ref().map_or(0, |p| {
                6 * (p.name.len() + p.node.len() + p.credential.len() + p.key.len()) + 100
            });
        let mut out = Zeroizing::new(String::with_capacity(HEADER.len() + marks + worst));
        out.push_str(HEADER);
        if !self.envs.is_empty()
            || !self.secrets.is_empty()
            || !self.not_production.is_empty()
            || !self.prefixes.is_empty()
        {
            out.push_str("\n[_marks]\nenvs = [");
            for (i, env) in self.envs.iter().enumerate() {
                out.push_str(if i == 0 { "\"" } else { ", \"" });
                out.push_str(&env.to_string());
                out.push('"');
            }
            out.push_str("]\nsecrets = [");
            for (i, secret) in self.secrets.iter().enumerate() {
                out.push_str(if i == 0 { "" } else { ", " });
                out.push_str("{ provider = \"");
                out.push_str(secret.provider.as_str());
                out.push_str("\", location = \"");
                escape_into(&mut out, &secret.location);
                out.push_str("\" }");
            }
            out.push_str("]\n");
            // Only when set, so a store without one still loads in a
            // release that does not know the field.
            if !self.not_production.is_empty() {
                out.push_str("not_production = [");
                for (i, env) in self.not_production.iter().enumerate() {
                    out.push_str(if i == 0 { "\"" } else { ", \"" });
                    out.push_str(&env.to_string());
                    out.push('"');
                }
                out.push_str("]\n");
            }
            // The same: only when set.
            if !self.prefixes.is_empty() {
                out.push_str("prefixes = [");
                for (i, prefix) in self.prefixes.iter().enumerate() {
                    out.push_str(if i == 0 { "" } else { ", " });
                    out.push_str("{ provider = \"");
                    out.push_str(prefix.provider.as_str());
                    out.push_str("\", location = \"");
                    escape_into(&mut out, &prefix.location);
                    out.push_str("\" }");
                }
                out.push_str("]\n");
            }
        }
        if let Some(p) = &self.proton {
            out.push_str("\n[_proton]\ntoken = \"");
            escape_into(&mut out, p.token.expose());
            out.push_str("\"\n");
            if let Some(at) = p.expires {
                out.push_str(&format!("expires = {at}\n"));
            }
        }
        // Only when set, so a store without it still loads in a release
        // that does not know the table.
        if self.remote_enabled || !self.grants.is_empty() {
            out.push_str(if self.remote_enabled {
                "\n[_remote]\nenabled = true\ngrants = ["
            } else {
                "\n[_remote]\nenabled = false\ngrants = ["
            });
            for (i, g) in self.grants.iter().enumerate() {
                out.push_str(if i == 0 { "" } else { ", " });
                out.push_str("{ machine = \"");
                escape_into(&mut out, &g.machine);
                out.push_str("\", node = \"");
                escape_into(&mut out, &g.node);
                out.push_str("\", project = \"");
                out.push_str(g.project.as_str());
                out.push_str("\", envs = [");
                for (j, env) in g.envs.iter().enumerate() {
                    out.push_str(if j == 0 { "\"" } else { ", \"" });
                    out.push_str(env.as_str());
                    out.push('"');
                }
                out.push(']');
                if let Some(token) = g.token {
                    out.push_str(", token = \"");
                    out.push_str(&token.hex());
                    out.push('"');
                }
                if let Some(end) = g.expires {
                    out.push_str(&format!(", expires = {end}"));
                }
                out.push_str(" }");
            }
            out.push_str("]\n");
        }
        // Only when paired, for the same reason.
        if let Some(p) = &self.phone {
            for (name, value) in [
                ("\n[_phone]\nname", &p.name),
                ("node", &p.node),
                ("credential", &p.credential),
                ("key", &p.key),
            ] {
                out.push_str(name);
                out.push_str(" = \"");
                escape_into(&mut out, value);
                out.push_str("\"\n");
            }
            out.push_str(&format!("paired = {}\n", p.paired));
        }
        for (section, keys) in &self.sections {
            out.push_str(&format!("\n[{section}]\n"));
            for (key, value) in keys {
                let sensitive = self.is_sensitive(section, key);
                out.push_str(key.as_str());
                out.push_str(if sensitive {
                    " = { value = \""
                } else {
                    " = \""
                });
                escape_into(&mut out, value.expose());
                out.push_str(if sensitive { SENSITIVE } else { "\"\n" });
            }
        }
        out
    }
}

/// A TOML basic-string body: `"` and `\` escaped, control characters as
/// escapes. At most six bytes per input byte.
fn escape_into(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
}

/// The decrypted file: `[_marks]`, `[_proton]`, `[_remote]`, `[_phone]`,
/// then one table per project.
struct Raw {
    marks: RawMarks,
    proton: Option<RawProton>,
    remote: Option<RawRemote>,
    phone: Option<PairedPhone>,
    sections: BTreeMap<ProjectName, BTreeMap<EnvName, BTreeMap<KeyName, Value>>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRemote {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    grants: Vec<RemoteGrant>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProton {
    token: Value,
    #[serde(default)]
    expires: Option<u64>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMarks {
    #[serde(default)]
    envs: Vec<Section>,
    #[serde(default)]
    secrets: Vec<Origin>,
    #[serde(default)]
    not_production: Vec<Section>,
    #[serde(default)]
    prefixes: Vec<Origin>,
}

impl<'de> Deserialize<'de> for Raw {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::{self, MapAccess, Visitor};
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Raw;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("[_marks] and [<project>.<env>] tables")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Raw, A::Error> {
                let mut raw = Raw {
                    marks: RawMarks::default(),
                    proton: None,
                    remote: None,
                    phone: None,
                    sections: BTreeMap::new(),
                };
                let mut marks = false;
                while let Some(name) = map.next_key::<String>()? {
                    if name == "_marks" {
                        if std::mem::replace(&mut marks, true) {
                            return Err(de::Error::custom("[_marks] appears twice"));
                        }
                        raw.marks = map.next_value()?;
                        continue;
                    }
                    if name == "_proton" {
                        if raw.proton.is_some() {
                            return Err(de::Error::custom("[_proton] appears twice"));
                        }
                        raw.proton = Some(map.next_value()?);
                        continue;
                    }
                    if name == "_remote" {
                        if raw.remote.is_some() {
                            return Err(de::Error::custom("[_remote] appears twice"));
                        }
                        raw.remote = Some(map.next_value()?);
                        continue;
                    }
                    if name == "_phone" {
                        if raw.phone.is_some() {
                            return Err(de::Error::custom("[_phone] appears twice"));
                        }
                        raw.phone = Some(map.next_value()?);
                        continue;
                    }
                    let project: ProjectName = name.parse().map_err(de::Error::custom)?;
                    if raw.sections.contains_key(&project) {
                        return Err(de::Error::custom("a project appears twice"));
                    }
                    raw.sections.insert(project, map.next_value()?);
                }
                Ok(raw)
            }
        }
        d.deserialize_map(V)
    }
}

/// How [`Store::render`] ends a sensitive key's inline table.
const SENSITIVE: &str = "\", sensitive = true }\n";

/// A store value: a string, or `{ value = "…", sensitive = true }`.
/// Deserialized straight into a [`SecretValue`], taking over the parser's
/// `String` without a copy.
struct Value {
    value: SecretValue,
    sensitive: bool,
}

impl<'de> Deserialize<'de> for Value {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::{self, MapAccess, Visitor};
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Value;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a string, or a table with value and sensitive")
            }
            fn visit_string<E: de::Error>(self, s: String) -> Result<Value, E> {
                Ok(Value {
                    value: SecretValue::new(s),
                    sensitive: false,
                })
            }
            fn visit_str<E: de::Error>(self, s: &str) -> Result<Value, E> {
                self.visit_string(s.to_owned())
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
                let mut value = None;
                let mut sensitive = false;
                while let Some(field) = map.next_key::<String>()? {
                    match field.as_str() {
                        "value" if value.is_none() => {
                            value = Some(SecretValue::new(map.next_value::<String>()?));
                        }
                        "sensitive" => sensitive = map.next_value()?,
                        _ => return Err(de::Error::custom("unexpected field in a key's table")),
                    }
                }
                let value = value.ok_or_else(|| de::Error::missing_field("value"))?;
                Ok(Value { value, sensitive })
            }
        }
        d.deserialize_any(V)
    }
}

/// The store on disk.
#[derive(Debug, Clone)]
pub struct StoreFile {
    path: PathBuf,
    /// scrypt cost (log2 N) for writes; `None` lets age pick about one
    /// second's work on this machine.
    work_factor: Option<u8>,
}

impl StoreFile {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            work_factor: None,
        }
    }

    /// A cheap scrypt cost, so tests do not spend a second per write. Only
    /// for tests: a store written this way is easy to brute-force.
    #[doc(hidden)]
    pub fn with_test_work_factor(mut self) -> Self {
        self.work_factor = Some(2);
        self
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn exists(&self) -> Result<bool, StoreError> {
        match fs::symlink_metadata(&self.path) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(io_error(&self.path, &e)),
        }
    }

    /// Creates an empty store. Fails if one exists.
    pub fn create(&self, passphrase: &Passphrase) -> Result<Store, StoreError> {
        if passphrase.is_empty() {
            return Err(StoreError::EmptyPassphrase);
        }
        let _lock = self.lock()?;
        if self.exists()? {
            return Err(StoreError::Exists {
                path: self.path.clone(),
            });
        }
        let store = Store::default();
        self.write(passphrase, &store)?;
        Ok(store)
    }

    /// Decrypts and parses the store.
    pub fn open(&self, passphrase: &Passphrase) -> Result<Store, StoreError> {
        let ciphertext = match fs::read(&self.path) {
            Ok(c) => c,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(StoreError::Missing {
                    path: self.path.clone(),
                });
            }
            Err(e) => return Err(io_error(&self.path, &e)),
        };
        let plaintext = self.decrypt(passphrase, &ciphertext)?;
        let text = std::str::from_utf8(&plaintext).map_err(|_| StoreError::Corrupt {
            path: self.path.clone(),
            problem: "the contents are not UTF-8",
        })?;
        Store::parse(&self.path, text)
    }

    /// Under the lock: decrypts with `passphrase` (which checks it), adds
    /// the marks waiting in `<store>.marks`, applies `change`, and writes
    /// the result encrypted with `new_passphrase`, or `passphrase` again.
    /// The waiting marks come first, so a `change` that removes one of
    /// them wins. If `change` fails nothing is written. Returns what
    /// `change` returned and the store as written.
    pub fn update<T>(
        &self,
        passphrase: &Passphrase,
        new_passphrase: Option<&Passphrase>,
        change: impl FnOnce(&mut Store) -> Result<T, StoreError>,
    ) -> Result<(T, Store), StoreError> {
        if new_passphrase.is_some_and(Passphrase::is_empty) {
            return Err(StoreError::EmptyPassphrase);
        }
        let _lock = self.lock()?;
        let mut store = self.open(passphrase)?;
        for mark in self.read_waiting() {
            store.add_mark(mark);
        }
        let result = change(&mut store)?;
        self.write(new_passphrase.unwrap_or(passphrase), &store)?;
        // The store has them now. If the file stays, the next write adds
        // them again, which changes nothing.
        let path = self.marks_path();
        if let Err(e) = fs::remove_file(&path)
            && e.kind() != io::ErrorKind::NotFound
        {
            tracing::warn!(path = %path.display(), error = %e, "cannot remove the marks moved into the store");
        }
        Ok((result, store))
    }

    /// `<store>.marks`: the marks added without the passphrase that no
    /// write has moved into the store yet.
    pub fn marks_path(&self) -> PathBuf {
        let mut name = self.path.clone().into_os_string();
        name.push(".marks");
        PathBuf::from(name)
    }

    /// Whether marks wait in `<store>.marks` for the next write.
    pub fn marks_wait(&self) -> bool {
        fs::symlink_metadata(self.marks_path()).is_ok()
    }

    /// The marks in `<store>.marks`. One that is missing is no marks; one
    /// that cannot be read or parsed is logged and counts as none, so it
    /// never stops a write the passphrase allows.
    fn read_waiting(&self) -> BTreeSet<Mark> {
        let path = self.marks_path();
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) => {
                if e.kind() != io::ErrorKind::NotFound {
                    tracing::warn!(path = %path.display(), error = %e, "cannot read the marks waiting for the store");
                }
                return BTreeSet::new();
            }
        };
        serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            tracing::warn!(path = %path.display(), error = %e, "cannot parse the marks waiting for the store; dropping them");
            BTreeSet::new()
        })
    }

    /// Under the lock: adds `marks` to those waiting in `<store>.marks`
    /// for the next write to move into the store. Takes no passphrase, so
    /// it can only add.
    pub fn add_waiting(&self, marks: Vec<Mark>) -> Result<(), StoreError> {
        if marks.is_empty() {
            return Ok(());
        }
        let _lock = self.lock()?;
        let mut waiting = self.read_waiting();
        waiting.extend(marks);
        let path = self.marks_path();
        let json = serde_json::to_vec(&waiting).map_err(|e| StoreError::Io {
            path: path.clone(),
            message: e.to_string(),
        })?;
        atomic::write_private(&path, &json).map_err(|e| io_error(&path, &e))
    }

    fn write(&self, passphrase: &Passphrase, store: &Store) -> Result<(), StoreError> {
        let plaintext = store.render();
        let mut recipient = age::scrypt::Recipient::new(passphrase.0.clone());
        if let Some(log_n) = self.work_factor {
            recipient.set_work_factor(log_n);
        }
        let ciphertext =
            age::encrypt(&recipient, plaintext.as_bytes()).map_err(|e| StoreError::Io {
                path: self.path.clone(),
                message: format!("cannot encrypt: {e}"),
            })?;
        atomic::write_private(&self.path, &ciphertext).map_err(|e| io_error(&self.path, &e))
    }

    fn decrypt(
        &self,
        passphrase: &Passphrase,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        use age::DecryptError as E;
        let identity = age::scrypt::Identity::new(passphrase.0.clone());
        let corrupt = |problem| StoreError::Corrupt {
            path: self.path.clone(),
            problem,
        };
        // Not `age::decrypt`: it reads into a growing Vec, and every
        // reallocation would leave an unzeroed copy of the plaintext behind.
        // The plaintext is never longer than the ciphertext, so one buffer
        // of that size holds it without growing.
        let read = || -> Result<Zeroizing<Vec<u8>>, E> {
            use std::io::Read as _;
            let mut reader = age::Decryptor::new_buffered(ciphertext)?
                .decrypt(std::iter::once(&identity as &dyn age::Identity))?;
            // One spare byte, so a read that fills it means the plaintext
            // is longer than it can be, and is refused rather than grown.
            let mut plaintext = Zeroizing::new(vec![0u8; ciphertext.len() + 1]);
            let mut len = 0;
            loop {
                match reader.read(&mut plaintext[len..]) {
                    Ok(0) => break,
                    Ok(n) => len += n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(E::Io(e)),
                }
                if len == plaintext.len() {
                    return Err(E::Io(io::ErrorKind::InvalidData.into()));
                }
            }
            // The bytes past `len` are zeros; dropping zeroes the whole
            // allocation either way.
            plaintext.truncate(len);
            Ok(plaintext)
        };
        match read() {
            Ok(plaintext) => Ok(plaintext),
            // Unwrapping the file key with a wrong passphrase fails its AEAD.
            Err(E::DecryptionFailed | E::KeyDecryptionFailed) => Err(StoreError::WrongPassphrase),
            Err(E::NoMatchingKeys) => Err(corrupt("it is not encrypted with a passphrase")),
            Err(E::ExcessiveWork { .. }) => Err(corrupt(
                "its scrypt work factor is too high for this machine",
            )),
            Err(E::Io(_)) => Err(corrupt("the contents are damaged or truncated")),
            // InvalidHeader, InvalidMac, UnknownFormat, and future variants.
            Err(_) => Err(corrupt("the header is invalid")),
        }
    }

    /// An exclusive lock on `<store>.lock`, released on drop. Not the store
    /// itself: each write replaces that file, so a lock on it would not
    /// cover the next writer.
    fn lock(&self) -> Result<fs::File, StoreError> {
        let mut name = self.path.clone().into_os_string();
        name.push(".lock");
        let path = PathBuf::from(name);
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)
            .map_err(|e| io_error(&path, &e))?;
        file.lock().map_err(|e| io_error(&path, &e))?;
        Ok(file)
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use proptest::prelude::*;

    use super::*;
    use crate::test_support::{Canary, assert_no_canary};

    fn pass(s: &str) -> Passphrase {
        Passphrase::new(s.into())
    }

    fn section(s: &str) -> Section {
        s.parse().unwrap()
    }

    fn key(k: &str) -> KeyName {
        k.parse().unwrap()
    }

    fn setup() -> (tempfile::TempDir, StoreFile) {
        let d = tempfile::tempdir().unwrap();
        let f = StoreFile::new(d.path().join(STORE_FILE)).with_test_work_factor();
        (d, f)
    }

    fn set(f: &StoreFile, p: &str, s: &str, k: &str, v: &str) -> Change {
        let value = SecretValue::new(v.into());
        f.update(&pass(p), None, |st| Ok(st.set(section(s), key(k), value)))
            .unwrap()
            .0
    }

    fn mode(p: &Path) -> u32 {
        fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    fn value<'a>(st: &'a Store, s: &str, k: &str) -> &'a str {
        st.section(&section(s)).unwrap()[&key(k)].expose()
    }

    fn assert_clean(c: &Canary, e: &StoreError) {
        assert_no_canary(c, &e.to_string());
        assert_no_canary(c, &format!("{e:?}"));
    }

    #[test]
    fn round_trip() {
        let (_d, f) = setup();
        let tricky = "multi\nline \"quoted\" \\ back\tslash \u{1} ünï 🔑";
        assert!(f.create(&pass("pw")).unwrap().sections().next().is_none());
        assert_eq!(set(&f, "pw", "widget.dev", "A", "one"), Change::Added);
        assert_eq!(set(&f, "pw", "widget.dev", "B", tricky), Change::Added);
        assert_eq!(set(&f, "pw", "widget.qa", "A", ""), Change::Added);
        assert_eq!(set(&f, "pw", "widget.dev", "A", "two"), Change::Replaced);

        let st = f.open(&pass("pw")).unwrap();
        assert_eq!(value(&st, "widget.dev", "A"), "two");
        assert_eq!(value(&st, "widget.dev", "B"), tricky);
        assert_eq!(value(&st, "widget.qa", "A"), "");
        let names: Vec<String> = st.sections().map(|(s, _)| s.to_string()).collect();
        assert_eq!(names, ["widget.dev", "widget.qa"]);

        let (change, st) = f
            .update(&pass("pw"), None, |st| {
                st.unset(&section("widget.qa"), &key("A"))
            })
            .unwrap();
        assert_eq!(change, Change::Removed);
        assert!(
            st.section(&section("widget.qa")).is_none(),
            "empty sections go"
        );
        let err = f
            .update(&pass("pw"), None, |st| {
                st.unset(&section("widget.qa"), &key("A"))
            })
            .unwrap_err();
        assert!(matches!(err, StoreError::NoKey { .. }), "{err}");
    }

    #[test]
    fn proton_token_round_trips_and_never_shows() {
        let (_d, f) = setup();
        let c = Canary::new();
        f.create(&pass("pw")).unwrap();
        set(&f, "pw", "widget.dev", "A", "one");
        let token = |expires| ProtonToken {
            token: SecretValue::new(c.value().into()),
            expires,
        };
        let (change, st) = f
            .update(&pass("pw"), None, |st| Ok(st.set_proton_token(token(None))))
            .unwrap();
        assert_eq!(change, Change::Added);
        assert_no_canary(&c, &format!("{:?}", st.proton_token()));
        let (change, _) = f
            .update(&pass("pw"), None, |st| {
                Ok(st.set_proton_token(token(Some(1_767_225_600))))
            })
            .unwrap();
        assert_eq!(change, Change::Replaced);

        let st = f.open(&pass("pw")).unwrap();
        let p = st.proton_token().unwrap();
        assert_eq!(p.token.expose(), c.value());
        assert_eq!(p.expires, Some(1_767_225_600));
        assert_eq!(value(&st, "widget.dev", "A"), "one");
        let names: Vec<String> = st.sections().map(|(s, _)| s.to_string()).collect();
        assert_eq!(names, ["widget.dev"], "[_proton] is not a section");
    }

    #[test]
    fn remote_grants_round_trip_and_replace_by_machine_and_project() {
        let (_d, f) = setup();
        f.create(&pass("pw")).unwrap();
        let st = f.open(&pass("pw")).unwrap();
        assert!(!st.remote_enabled(), "off by default");
        assert!(st.remote_grants().is_empty());
        let grant = |node: &str, project: &str, envs: &[&str], expires| RemoteGrant {
            machine: format!("box-{node}"),
            node: node.into(),
            project: project.parse().unwrap(),
            envs: envs.iter().map(|e| e.parse().unwrap()).collect(),
            token: Some(TokenHash::of(&format!("token of {node}"))),
            expires,
        };
        let (change, _) = f
            .update(&pass("pw"), None, |st| {
                st.set_remote_enabled(true);
                st.grant_remote(grant("n1", "widget", &["dev"], None));
                st.grant_remote(grant("n2", "widget", &["dev", "staging"], Some(99)));
                Ok(st.grant_remote(grant("n1", "widget", &["staging"], Some(7))))
            })
            .unwrap();
        assert_eq!(change, Change::Replaced);
        let st = f.open(&pass("pw")).unwrap();
        assert!(st.remote_enabled());
        assert_eq!(
            st.remote_grants(),
            [
                grant("n1", "widget", &["staging"], Some(7)),
                grant("n2", "widget", &["dev", "staging"], Some(99)),
            ]
        );
        let names: Vec<String> = st.sections().map(|(s, _)| s.to_string()).collect();
        assert!(names.is_empty(), "[_remote] is not a section");

        let g = &st.remote_grants()[1];
        let (widget, dev) = ("widget".parse().unwrap(), "dev".parse().unwrap());
        assert!(g.covers("n2", &widget, &dev, 98));
        assert!(!g.covers("n2", &widget, &dev, 99), "ended");
        assert!(!g.covers("n1", &widget, &dev, 0), "another node");
        assert!(!g.covers("n2", &widget, &"prod".parse().unwrap(), 0));

        let (change, st) = f
            .update(&pass("pw"), None, |st| st.revoke_remote("BOX-n2", None))
            .unwrap();
        assert_eq!(change, Change::Removed);
        assert_eq!(st.remote_grants().len(), 1);
        let err = f
            .update(&pass("pw"), None, |st| st.revoke_remote("box-n2", None))
            .unwrap_err();
        assert!(matches!(err, StoreError::NoGrant { .. }));
    }

    /// One phone is paired at a time; pairing another replaces it, and a
    /// store with none has no `[_phone]` table.
    #[test]
    fn a_paired_phone_round_trips_and_is_replaced() {
        let (_d, f) = setup();
        f.create(&pass("pw")).unwrap();
        assert_eq!(f.open(&pass("pw")).unwrap().phone(), None);
        let phone = |node: &str| PairedPhone {
            name: format!("phone \"{node}\""),
            node: node.into(),
            credential: "q83vEjRWeJA".into(),
            key: "BHk1".into(),
            paired: 1_767_225_600,
        };
        let (change, _) = f
            .update(&pass("pw"), None, |st| Ok(st.pair_phone(phone("n1"))))
            .unwrap();
        assert_eq!(change, Change::Added);
        assert_eq!(f.open(&pass("pw")).unwrap().phone(), Some(&phone("n1")));
        let (change, st) = f
            .update(&pass("pw"), None, |st| Ok(st.pair_phone(phone("n2"))))
            .unwrap();
        assert_eq!(change, Change::Replaced);
        assert_eq!(st.phone(), Some(&phone("n2")));
        let names: Vec<String> = st.sections().map(|(s, _)| s.to_string()).collect();
        assert!(names.is_empty(), "[_phone] is not a section");

        let (change, st) = f.update(&pass("pw"), None, Store::unpair_phone).unwrap();
        assert_eq!(change, Change::Removed);
        assert_eq!(st.phone(), None);
        assert!(!st.render().contains("_phone"));
        let err = f
            .update(&pass("pw"), None, Store::unpair_phone)
            .unwrap_err();
        assert!(matches!(err, StoreError::NoPhone));
    }

    /// The store keeps a token's hash, never the token: the file's text has
    /// no token in it. A new token replaces the old one, for that machine
    /// and project only, and a grant saved before grants had tokens still
    /// loads, with none.
    #[test]
    fn a_grants_token_is_kept_as_its_hash() {
        let (_d, f) = setup();
        f.create(&pass("pw")).unwrap();
        let token = new_token().unwrap();
        assert!(
            token.starts_with(TOKEN_PREFIX) && token.len() == 68,
            "{}",
            token.len()
        );
        assert_ne!(*token, *new_token().unwrap());
        let widget: ProjectName = "widget".parse().unwrap();
        let grant = |project: &str, token: Option<&str>| RemoteGrant {
            machine: "box".into(),
            node: "n1".into(),
            project: project.parse().unwrap(),
            envs: vec!["dev".parse().unwrap()],
            token: token.map(TokenHash::of),
            expires: None,
        };
        let (first, other) = (grant("widget", Some(&token)), grant("gadget", None));
        let (_, st) = f
            .update(&pass("pw"), None, {
                let (first, other) = (first.clone(), other.clone());
                move |st| {
                    st.grant_remote(first);
                    Ok(st.grant_remote(other))
                }
            })
            .unwrap();
        let text = st.render();
        assert!(!text.contains(token.as_str()), "the token is in the store");
        assert!(text.contains(&TokenHash::of(&token).hex()), "{}", *text);
        let st = f.open(&pass("pw")).unwrap();
        assert_eq!(st.remote_grants(), [first, other]);
        assert_eq!(st.remote_grants()[1].token, None);
        assert_eq!(format!("{:?}", TokenHash::of(&token)), "TokenHash(..)");

        let next = TokenHash::of("another");
        let (change, st) = f
            .update(&pass("pw"), None, move |st| {
                st.rotate_remote("BOX", &"widget".parse().unwrap(), next)
            })
            .unwrap();
        assert_eq!(change, (Change::Replaced, "box".to_owned()));
        assert_eq!(st.remote_grants()[0].token, Some(next));
        assert_eq!(st.remote_grants()[1].token, None, "the other grant's");
        let err = f
            .update(&pass("pw"), None, move |st| {
                st.rotate_remote("n2", &widget, next)
            })
            .unwrap_err();
        assert!(matches!(err, StoreError::NoGrant { .. }));
    }

    #[test]
    fn create_refuses_an_existing_store_and_an_empty_passphrase() {
        let (_d, f) = setup();
        assert_eq!(
            f.create(&pass("")).unwrap_err(),
            StoreError::EmptyPassphrase
        );
        assert!(!f.exists().unwrap());
        f.create(&pass("pw")).unwrap();
        set(&f, "pw", "widget.dev", "A", "kept");
        let err = f.create(&pass("other")).unwrap_err();
        assert!(matches!(err, StoreError::Exists { .. }), "{err}");
        assert_eq!(
            value(&f.open(&pass("pw")).unwrap(), "widget.dev", "A"),
            "kept"
        );
    }

    #[test]
    fn missing_store() {
        let (_d, f) = setup();
        let err = f.open(&pass("pw")).unwrap_err();
        assert!(matches!(err, StoreError::Missing { .. }), "{err}");
        let err = f.update(&pass("pw"), None, |_| Ok(())).unwrap_err();
        assert!(matches!(err, StoreError::Missing { .. }), "{err}");
    }

    #[test]
    fn wrong_passphrase_reads_and_writes_nothing() {
        let (_d, f) = setup();
        f.create(&pass("right")).unwrap();
        set(&f, "right", "widget.dev", "A", "v");
        let before = fs::read(f.path()).unwrap();

        assert_eq!(
            f.open(&pass("wrong")).unwrap_err(),
            StoreError::WrongPassphrase
        );
        let mut ran = false;
        let err = f
            .update(&pass("wrong"), None, |_| {
                ran = true;
                Ok(())
            })
            .unwrap_err();
        assert_eq!(err, StoreError::WrongPassphrase);
        assert!(!ran);
        assert_eq!(fs::read(f.path()).unwrap(), before);
    }

    #[test]
    fn passwd_rekeys() {
        let (_d, f) = setup();
        f.create(&pass("old")).unwrap();
        set(&f, "old", "widget.dev", "A", "v");
        let err = f
            .update(&pass("old"), Some(&pass("")), |_| Ok(()))
            .unwrap_err();
        assert_eq!(err, StoreError::EmptyPassphrase);
        f.update(&pass("old"), Some(&pass("new")), |_| Ok(()))
            .unwrap();
        assert_eq!(
            f.open(&pass("old")).unwrap_err(),
            StoreError::WrongPassphrase
        );
        assert_eq!(
            value(&f.open(&pass("new")).unwrap(), "widget.dev", "A"),
            "v"
        );
    }

    #[test]
    fn corrupt_files() {
        let (_d, f) = setup();
        fs::write(f.path(), b"not an age file at all").unwrap();
        let err = f.open(&pass("pw")).unwrap_err();
        assert!(matches!(err, StoreError::Corrupt { .. }), "{err}");

        fs::remove_file(f.path()).unwrap();
        f.create(&pass("pw")).unwrap();
        set(
            &f,
            "pw",
            "widget.dev",
            "A",
            "a value long enough to span the payload",
        );
        let good = fs::read(f.path()).unwrap();

        // Truncated payload.
        fs::write(f.path(), &good[..good.len() - 5]).unwrap();
        let err = f.open(&pass("pw")).unwrap_err();
        assert!(matches!(err, StoreError::Corrupt { .. }), "{err}");

        // One flipped bit in the last payload byte.
        let mut flipped = good.clone();
        *flipped.last_mut().unwrap() ^= 1;
        fs::write(f.path(), &flipped).unwrap();
        let err = f.open(&pass("pw")).unwrap_err();
        assert!(matches!(err, StoreError::Corrupt { .. }), "{err}");

        // Not a passphrase-encrypted file.
        let id = age::x25519::Identity::generate();
        let other = age::encrypt(&id.to_public(), b"[a.b]\n").unwrap();
        fs::write(f.path(), other).unwrap();
        let err = f.open(&pass("pw")).unwrap_err();
        assert!(matches!(err, StoreError::Corrupt { .. }), "{err}");
    }

    /// A file encrypted with the right passphrase but holding plaintext we
    /// did not write: broken TOML, a non-string value, a bad key name.
    #[test]
    fn parse_errors_name_a_line_and_never_the_value() {
        let (_d, f) = setup();
        let c = Canary::new();
        let v = c.value();
        let cases = [
            (
                format!("[widget.dev]\nOK = \"fine\"\nA = \"{v}\nB = \"x\"\n"),
                3,
            ),
            (format!("[widget.dev]\nA = {v}\n"), 2),
            (format!("[widget.dev]\nA = \"x\"\nN = 123{v}\n"), 3),
            ("[widget.dev]\nA = 12345\n".to_owned(), 2),
            (format!("\n\n[widget.dev]\n{v}-bad = \"x\"\n"), 4),
            (format!("[widget]\nA = \"{v}\"\n"), 2),
            (format!("{v} = \"{v}\"\n"), 1),
        ];
        for (plaintext, line) in cases {
            let mut r = age::scrypt::Recipient::new(SecretString::from("pw"));
            r.set_work_factor(2);
            fs::write(f.path(), age::encrypt(&r, plaintext.as_bytes()).unwrap()).unwrap();
            let err = f.open(&pass("pw")).unwrap_err();
            assert_clean(&c, &err);
            assert_eq!(
                err,
                StoreError::Parse {
                    path: f.path().into(),
                    line: Some(line)
                },
                "{plaintext:?}"
            );
            assert!(err.to_string().ends_with(&format!("at line {line}")));
        }
    }

    #[test]
    fn errors_never_show_values() {
        let (_d, f) = setup();
        let c = Canary::new();
        f.create(&pass("pw")).unwrap();
        set(&f, "pw", "widget.dev", "A", c.value());
        let st = f.open(&pass("pw")).unwrap();
        assert_no_canary(&c, &format!("{st:?}"));
        assert_clean(&c, &f.open(&pass("wrong")).unwrap_err());
        let mut flipped = fs::read(f.path()).unwrap();
        *flipped.last_mut().unwrap() ^= 1;
        fs::write(f.path(), &flipped).unwrap();
        assert_clean(&c, &f.open(&pass("pw")).unwrap_err());
    }

    /// The temp file cannot be created, so the write fails before the
    /// rename: the old store is untouched and still opens.
    #[test]
    fn failure_before_rename_leaves_the_original() {
        let (d, f) = setup();
        f.create(&pass("pw")).unwrap();
        set(&f, "pw", "widget.dev", "A", "original");
        let before = fs::read(f.path()).unwrap();

        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o500)).unwrap();
        let probe = fs::write(d.path().join("probe"), b"");
        let result = f.update(&pass("pw"), None, |st| {
            Ok(st.set(
                section("widget.dev"),
                key("A"),
                SecretValue::new("new".into()),
            ))
        });
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        if probe.is_ok() {
            eprintln!("skipped: the directory stayed writable (running as root?)");
            return;
        }
        let err = result.unwrap_err();
        assert!(matches!(err, StoreError::Io { .. }), "{err}");
        assert_eq!(fs::read(f.path()).unwrap(), before);
        assert_eq!(
            value(&f.open(&pass("pw")).unwrap(), "widget.dev", "A"),
            "original"
        );
        let names: Vec<_> = fs::read_dir(d.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert!(
            names.iter().all(|n| !n.ends_with(atomic::TEMP_SUFFIX)),
            "{names:?}"
        );
    }

    #[test]
    fn files_are_private() {
        let (_d, f) = setup();
        f.create(&pass("pw")).unwrap();
        assert_eq!(mode(f.path()), 0o600);
        set(&f, "pw", "widget.dev", "A", "v");
        assert_eq!(mode(f.path()), 0o600);
        let lock = f.path().with_extension("age.lock");
        assert_eq!(mode(&lock), 0o600);
    }

    #[test]
    fn section_names() {
        assert_eq!(section("widget.dev").to_string(), "widget.dev");
        for bad in [
            "widget",
            "widget.",
            ".dev",
            "Widget.dev",
            "a.b.c",
            "a b.dev",
        ] {
            assert!(bad.parse::<Section>().is_err(), "{bad}");
        }
    }

    #[test]
    fn clearing_a_project_takes_its_sections_and_key_marks_only() {
        let mut st = Store::default();
        let v = || SecretValue::new("v".into());
        let (dev, prod, other) = (
            section("widget.dev"),
            section("widget.prod"),
            section("gadget.dev"),
        );
        st.set(dev.clone(), key("A"), v());
        st.set(prod.clone(), key("B"), v());
        st.set(other.clone(), key("A"), v());
        st.mark(&dev, &key("A"), true).unwrap();
        st.mark(&other, &key("A"), true).unwrap();
        st.mark_env(prod.clone(), true);

        let widget = "widget".parse().unwrap();
        assert_eq!(st.clear_project(&widget).unwrap(), Change::Removed);
        let left: Vec<&Section> = st.sections().map(|(s, _)| s).collect();
        assert_eq!(left, [&other]);
        assert!(st.is_sensitive(&other, &key("A")));
        // A key set again under the name is not marked, and a human's
        // decision about the environment stays.
        st.set(dev.clone(), key("A"), v());
        assert!(!st.is_sensitive(&dev, &key("A")));
        assert!(st.env_marked(&prod.project, &prod.env));

        assert_eq!(
            st.clear_project(&"nothing".parse().unwrap()),
            Err(StoreError::NoSection {
                project: "nothing".parse().unwrap()
            })
        );
    }

    #[test]
    fn sensitive_marks() {
        let mut st = Store::default();
        let (s, a) = (section("widget.dev"), key("A"));
        assert!(matches!(
            st.mark(&s, &a, true),
            Err(StoreError::NoKey { .. })
        ));
        st.set(s.clone(), a.clone(), SecretValue::new("v".into()));
        assert_eq!(st.mark(&s, &a, true).unwrap(), Change::Marked);
        assert!(
            st.render()
                .contains("A = { value = \"v\", sensitive = true }\n")
        );
        // Replacing the value keeps the mark; unset drops it.
        st.set(s.clone(), a.clone(), SecretValue::new("w".into()));
        assert!(st.is_sensitive(&s, &a));
        st.unset(&s, &a).unwrap();
        st.set(s.clone(), a.clone(), SecretValue::new("v".into()));
        assert!(!st.is_sensitive(&s, &a));
        assert_eq!(st.mark(&s, &a, false).unwrap(), Change::Unmarked);

        let parse = |t: &str| Store::parse(Path::new("store.age"), t);
        let back =
            parse("[widget.dev]\nA = { value = \"v\", sensitive = false }\nB = \"w\"\n").unwrap();
        assert!(!back.is_sensitive(&s, &a));
        for bad in [
            "[widget.dev]\nA = { sensitive = true }\n",
            "[widget.dev]\nA = { value = \"v\", other = 1 }\n",
            "[widget.dev]\nA = { value = \"v\", sensitive = \"yes\" }\n",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn env_and_secret_marks() {
        use crate::types::Provider;
        let mut st = Store::default();
        let (p, prod) = ("widget".parse().unwrap(), "prod".parse().unwrap());
        assert_eq!(st.mark_env(section("widget.prod"), true), Change::Marked);
        let stripe = Origin::new(Provider::AwsSm, "acme/dev/\"stripe\"");
        st.mark_secret(stripe.clone(), true).unwrap();
        assert!(matches!(
            st.mark_secret(Origin::new(Provider::File, "widget.dev"), true),
            Err(StoreError::FileSecretMark)
        ));
        st.set(
            section("widget.dev"),
            key("A"),
            SecretValue::new("v".into()),
        );
        let text = st.render();
        let back = Store::parse(Path::new("store.age"), &text).unwrap();
        assert!(back.env_marked(&p, &prod));
        assert!(!back.env_marked(&p, &"dev".parse().unwrap()));
        assert_eq!(back.marked_secrets().collect::<Vec<_>>(), [&stripe]);
        assert_eq!(value(&back, "widget.dev", "A"), "v");

        assert_eq!(st.mark_env(section("widget.prod"), false), Change::Unmarked);
        st.mark_secret(stripe, false).unwrap();
        assert!(!st.render().contains("_marks"));

        // A prefix mark: only written when set; unmarking the prefix as a
        // secret removes it.
        let live = Origin::new(Provider::AwsSm, "widget/live/");
        assert_eq!(st.mark_prefix(live.clone()).unwrap(), Change::Marked);
        let text = st.render();
        assert!(
            text.contains("prefixes = [{ provider = \"aws_sm\", location = \"widget/live/\" }]\n"),
            "{}",
            text.as_str()
        );
        let back = Store::parse(Path::new("store.age"), &text).unwrap();
        assert_eq!(back.marked_prefixes().collect::<Vec<_>>(), [&live]);
        // A secret under it cannot be unmarked on its own: that fails,
        // naming the prefix, rather than leave it marked.
        let db = Origin::new(Provider::AwsSm, "widget/live/db");
        st.mark_secret(db.clone(), true).unwrap();
        let err = st.mark_secret(db.clone(), false).unwrap_err();
        assert!(
            matches!(&err, StoreError::CoveredByPrefix { prefix, .. } if *prefix == live),
            "{err}"
        );
        assert_eq!(st.marked_secrets().collect::<Vec<_>>(), [&db]);
        st.mark_secret(live, false).unwrap();
        st.mark_secret(db, false).unwrap();
        assert!(!st.render().contains("_marks"));

        // Acknowledged as not production: not a sensitive mark, and only
        // written when set.
        assert_eq!(
            st.acknowledge_env(section("widget.dev"), true),
            Change::Marked
        );
        let text = st.render();
        assert!(
            text.contains("not_production = [\"widget.dev\"]\n"),
            "{}",
            text.as_str()
        );
        let back = Store::parse(Path::new("store.age"), &text).unwrap();
        assert!(back.env_acknowledged(&p, &"dev".parse().unwrap()));
        assert!(!back.env_marked(&p, &"dev".parse().unwrap()));
        assert_eq!(
            st.acknowledge_env(section("widget.dev"), false),
            Change::Unmarked
        );
        assert!(!st.render().contains("_marks"));

        let parse = |t: &str| Store::parse(Path::new("store.age"), t);
        for bad in [
            "[_marks]\nother = []\n",
            "[_marks]\nenvs = [\"nodot\"]\n",
            "[_marks]\nsecrets = [{ provider = \"aws_sm\" }]\n",
            "[Widget.dev]\nA = \"v\"\n",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    fn marks_file(f: &StoreFile) -> PathBuf {
        f.marks_path()
    }

    /// A mark added with no passphrase waits in a plain list beside the
    /// store, and the next write, which has the passphrase, moves it in.
    #[test]
    fn a_waiting_mark_is_moved_into_the_store_by_the_next_write() {
        let (_d, f) = setup();
        f.create(&pass("pw")).unwrap();
        set(&f, "pw", "widget.dev", "TOKEN", "v");
        let stripe = Origin::new(crate::types::Provider::AwsSm, "widget/prod/stripe");
        let all = Origin::new(crate::types::Provider::AwsSm, "widget/prod/");
        assert!(!f.marks_wait());

        f.add_waiting(vec![Mark::Env(section("widget.prod"))])
            .unwrap();
        // A second call adds to the list; one already there is there once.
        f.add_waiting(vec![
            Mark::Env(section("widget.prod")),
            Mark::Secret(stripe.clone()),
            Mark::Prefix(all.clone()),
            Mark::Key(section("widget.dev"), key("TOKEN")),
        ])
        .unwrap();
        assert!(f.marks_wait());
        assert_eq!(mode(&marks_file(&f)), 0o600);
        // Names only, and the store itself is as it was.
        let list = fs::read_to_string(marks_file(&f)).unwrap();
        assert!(
            list.contains("widget.prod") && !list.contains("\"v\""),
            "{list}"
        );
        assert_eq!(f.open(&pass("pw")).unwrap().marked_envs().count(), 0);

        // A wrong passphrase moves nothing.
        assert!(f.update(&pass("no"), None, |_| Ok(())).is_err());
        assert!(f.marks_wait());

        let ((), written) = f.update(&pass("pw"), None, |_| Ok(())).unwrap();
        assert!(!f.marks_wait());
        for st in [written, f.open(&pass("pw")).unwrap()] {
            assert_eq!(
                st.marked_envs().collect::<Vec<_>>(),
                [&section("widget.prod")]
            );
            assert_eq!(st.marked_secrets().collect::<Vec<_>>(), [&stripe]);
            assert_eq!(st.marked_prefixes().collect::<Vec<_>>(), [&all]);
            assert!(st.is_sensitive(&section("widget.dev"), &key("TOKEN")));
        }
    }

    /// The write that moves a waiting mark in can remove it too: a human
    /// unmarking in the app wins over the list.
    #[test]
    fn the_change_of_a_write_wins_over_a_waiting_mark() {
        let (_d, f) = setup();
        f.create(&pass("pw")).unwrap();
        f.add_waiting(vec![Mark::Env(section("widget.prod"))])
            .unwrap();
        let (change, st) = f
            .update(&pass("pw"), None, |st| {
                Ok(st.mark_env(section("widget.prod"), false))
            })
            .unwrap();
        assert_eq!(change, Change::Unmarked);
        assert_eq!(st.marked_envs().count(), 0);
        assert!(!f.marks_wait());
        assert_eq!(f.open(&pass("pw")).unwrap().marked_envs().count(), 0);
    }

    /// The list is not trusted: one that does not parse adds nothing and
    /// stops no write, and a mark that cannot be added (a key since
    /// removed, a `file` secret) is skipped. It can only ever add marks.
    #[test]
    fn a_bad_list_of_waiting_marks_stops_no_write() {
        let (_d, f) = setup();
        f.create(&pass("pw")).unwrap();
        set(&f, "pw", "widget.dev", "TOKEN", "v");
        f.update(&pass("pw"), None, |st| {
            Ok(st.mark_env(section("widget.prod"), true))
        })
        .unwrap();

        for bad in [
            "not json",
            "[{\"unmark\":\"widget.prod\"}]",
            "[{\"env\":\"widget.prod\",\"sensitive\":false}]",
            "{\"not_production\":[\"widget.prod\"]}",
        ] {
            fs::write(marks_file(&f), bad).unwrap();
            let ((), st) = f.update(&pass("pw"), None, |_| Ok(())).unwrap();
            assert!(st.env_marked(&"widget".parse().unwrap(), &"prod".parse().unwrap()));
            assert!(!st.env_acknowledged(&"widget".parse().unwrap(), &"prod".parse().unwrap()));
            assert!(!f.marks_wait(), "{bad}");
        }

        let gone = Mark::Key(section("widget.dev"), key("GONE"));
        let file = Mark::Secret(Origin::new(crate::types::Provider::File, "widget.dev"));
        f.add_waiting(vec![gone, file, Mark::Env(section("widget.rc"))])
            .unwrap();
        let ((), st) = f.update(&pass("pw"), None, |_| Ok(())).unwrap();
        assert_eq!(st.marked_envs().count(), 2);
        assert_eq!(st.marked_secrets().count(), 0);
        assert!(!st.is_sensitive(&section("widget.dev"), &key("TOKEN")));
    }

    /// What a copy gained in marks, to add to another: every kind, and
    /// nothing that was there before.
    #[test]
    fn new_marks_are_those_a_copy_gained() {
        use crate::types::Provider;
        let mut before = Store::default();
        before.set(
            section("widget.dev"),
            key("TOKEN"),
            SecretValue::new("v".into()),
        );
        before.set(
            section("widget.dev"),
            key("OLD"),
            SecretValue::new("v".into()),
        );
        before
            .mark(&section("widget.dev"), &key("OLD"), true)
            .unwrap();
        before.mark_env(section("widget.rc"), true);

        let mut after = before.duplicate().unwrap();
        assert_eq!(value(&after, "widget.dev", "TOKEN"), "v");
        assert_eq!(after.new_marks(&before), []);
        let stripe = Origin::new(Provider::AwsSm, "widget/prod/stripe");
        let all = Origin::new(Provider::AwsSm, "widget/prod/");
        after.mark_env(section("widget.prod"), true);
        after.mark_secret(stripe.clone(), true).unwrap();
        after.mark_prefix(all.clone()).unwrap();
        after
            .mark(&section("widget.dev"), &key("TOKEN"), true)
            .unwrap();
        let added = after.new_marks(&before);
        assert_eq!(
            added,
            [
                Mark::Env(section("widget.prod")),
                Mark::Secret(stripe),
                Mark::Prefix(all),
                Mark::Key(section("widget.dev"), key("TOKEN")),
            ]
        );

        let mut other = before.duplicate().unwrap();
        for mark in added {
            other.add_mark(mark);
        }
        assert_eq!(other.render().as_str(), after.render().as_str());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Whatever a value holds, rendering then parsing gives it back,
        /// with its mark.
        #[test]
        fn render_then_parse_is_identity(values in prop::collection::vec(any::<String>(), 1..5)) {
            let mut st = Store::default();
            for (i, v) in values.iter().enumerate() {
                st.set(section("widget.dev"), key(&format!("K{i}")), SecretValue::new(v.clone()));
                if i % 2 == 1 {
                    st.mark(&section("widget.dev"), &key(&format!("K{i}")), true).unwrap();
                }
            }
            let text = st.render();
            let back = Store::parse(Path::new("store.age"), &text).unwrap();
            for (i, v) in values.iter().enumerate() {
                let k = format!("K{i}");
                prop_assert_eq!(value(&back, "widget.dev", &k), v.as_str());
                prop_assert_eq!(back.is_sensitive(&section("widget.dev"), &key(&k)), i % 2 == 1);
            }
        }
    }
}
