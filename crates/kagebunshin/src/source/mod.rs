//! Where values come from, and how several sources combine.
//!
//! A project declares an ordered list of sources. Each source returns its
//! entries in a fixed order, and [`merge`] applies them in declared order with
//! the later entry winning. For every key the result records the winning
//! origin and every origin it overrode, so `status` and `diff` can explain
//! where a value came from without showing it.

pub mod aws_sm;
pub mod file;
pub mod proton;

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::config::SourceSpec;
use crate::secret::SecretValue;
use crate::types::{KeyName, Origin, Provider};

/// The provider-neutral id of what `provider` reads at `location`: what a
/// key's [`Origin`] records and what sensitive marks are keyed by. Each
/// provider decides what is stable for it: an AWS secret's name (an ARN is
/// reduced to it), a store section, a Proton item's share and item ids.
pub fn stable_origin(provider: Provider, location: &str) -> Origin {
    match provider {
        Provider::AwsSm => Origin::new(provider, aws_sm::secret_id(location)),
        Provider::File | Provider::Proton => Origin::new(provider, location),
    }
}

/// One key from one source.
#[derive(Debug)]
pub struct Entry {
    pub key: KeyName,
    pub value: SecretValue,
    pub origin: Origin,
}

/// One thing a provider can read, as a listing shows it. Never a value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Listed {
    /// The stable id: what a key read from it records as its origin, and
    /// what a sensitive mark on it is keyed by.
    pub id: Origin,
    /// The name a project file selects it by: an AWS secret's name, a store
    /// section's `<project>.<env>`, a Proton key's `<vault>/<KEY>`.
    pub name: String,
    /// The item's own title, when the provider has one apart from its name
    /// (a Proton item's). Free text a human typed, never a value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// The keys it holds, when the provider knows them without reading a
    /// value (store sections and Proton keys), or, for an AWS secret, when
    /// `list --keys` read it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<KeyName>,
    /// `list --keys`: an AWS secret that is a plain string, not a JSON
    /// object, so it holds one value and no key names.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub plain: bool,
    /// `list --keys`: why its keys were not read, such as that it is
    /// marked sensitive or looks like production. Never a value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unread: Option<String>,
}

/// Whether a provider can read right now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Health {
    Ok,
    /// Nothing is set up: `connect` has not been run, or there is no store.
    NotConnected {
        hint: String,
    },
    /// Credentials are missing or expired.
    NeedsLogin {
        hint: String,
    },
    /// It reads from the local store, and the daemon is locked.
    Locked,
    /// Anything else; the message names no value.
    Failed {
        message: String,
    },
}

/// What `status` shows for one provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderStatus {
    pub provider: Provider,
    /// What it reads as, without a value: `profile acme-dev`, `store.age`.
    pub detail: String,
    pub health: Health,
    /// When its token stops working, in Unix seconds, if it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<u64>,
}

/// How long before a token expires `status` and the app start warning.
pub const EXPIRY_WARNING_DAYS: u64 = 14;

/// Now, in Unix seconds.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl ProviderStatus {
    /// Whole days until the token expires, if it has an expiry and that is
    /// within [`EXPIRY_WARNING_DAYS`] of `now` (Unix seconds); 0 or less
    /// once it has expired.
    pub fn expiring_in(&self, now: u64) -> Option<i64> {
        let expires = self.expires?;
        let left = expires as i64 - now as i64;
        (left <= (EXPIRY_WARNING_DAYS * 86_400) as i64).then(|| left.div_euclid(86_400))
    }
}

/// What every provider does: list what it can read by stable id, report
/// whether it can read, and build the [`Source`] for a project file entry,
/// which fetches. Connecting is interactive, so it is the CLI's
/// `kagebunshin connect <provider>`, not part of this trait.
#[async_trait]
pub trait Backend: Send + Sync {
    fn provider(&self) -> Provider;

    /// Everything whose name starts with `prefix`, in name order, without
    /// reading a value.
    async fn list(&self, prefix: &str) -> Result<Vec<Listed>, SourceError>;

    async fn status(&self) -> ProviderStatus;

    /// The source that fetches what `spec` selects. The sources of one
    /// backend may share what they read, so a backend is made for one
    /// request and not kept.
    fn source(&self, spec: &SourceSpec) -> Box<dyn Source>;
}

#[async_trait]
pub trait Source: Send + Sync {
    /// A short, value-free description for logs and errors, e.g.
    /// `aws_sm prefix widget/dev/`.
    fn describe(&self) -> String;

    /// The names this source will read (secret names, store sections),
    /// listing a prefix if it has one, without reading any value. The
    /// resolver checks every name against the sensitive patterns before
    /// it calls [`Source::fetch`].
    async fn names(&self) -> Result<Vec<String>, SourceError>;

    /// Reads `names`, as [`Source::names`] returned them, and nothing else.
    /// The order of the returned entries is part of the contract: entries
    /// later in the list win over earlier ones in [`merge`], and it must not
    /// depend on network timing.
    async fn fetch(&self, names: &[String]) -> Result<Vec<Entry>, SourceError>;

    /// Secrets the last [`Source::fetch`] left out, by name, and why: under
    /// an AWS prefix, those that hold no keys it can read. Never a value.
    fn skipped(&self) -> Vec<(String, Skip)> {
        Vec::new()
    }
}

/// Why a source left a secret out of what it read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skip {
    /// Its string is not a JSON object, so it has no key names.
    NotAnObject,
    /// It is binary.
    Binary,
    /// The login may not read it.
    Denied,
}

/// [`Source::names`] then [`Source::fetch`], as the resolver calls them but
/// without its sensitive check. Tests only.
#[cfg(test)]
#[async_trait]
pub trait ReadAll {
    async fn read_all(&self) -> Result<Vec<Entry>, SourceError>;
}

#[cfg(test)]
#[async_trait]
impl<S: Source + ?Sized> ReadAll for S {
    async fn read_all(&self) -> Result<Vec<Entry>, SourceError> {
        let names = self.names().await?;
        self.fetch(&names).await
    }
}

/// The value a key resolved to, where it came from, and what it replaced.
#[derive(Debug)]
pub struct Resolved {
    pub value: SecretValue,
    pub origin: Origin,
    /// Origins that also set this key and lost, earliest first.
    pub overridden: Vec<Origin>,
}

/// Later wins: applies each source's entries in order, then the next source's.
pub fn merge(sources: impl IntoIterator<Item = Vec<Entry>>) -> BTreeMap<KeyName, Resolved> {
    let mut out: BTreeMap<KeyName, Resolved> = BTreeMap::new();
    for entry in sources.into_iter().flatten() {
        let Entry { key, value, origin } = entry;
        match out.get_mut(&key) {
            Some(r) => {
                let lost = std::mem::replace(&mut r.origin, origin);
                r.overridden.push(lost);
                // The old value is dropped (and zeroed) here.
                r.value = value;
            }
            None => {
                out.insert(
                    key,
                    Resolved {
                        value,
                        origin,
                        overridden: Vec::new(),
                    },
                );
            }
        }
    }
    out
}

/// Why a source could not produce its entries. Messages name secrets and keys
/// but never contain values.
#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("{what}: credentials are missing or expired")]
    NeedsLogin { what: String, hint: String },
    #[error("secret {name} does not exist")]
    NotFound { name: String },
    #[error("access to secret {name} was denied")]
    AccessDenied { name: String },
    #[error("fetching secret {name} timed out after {after:?}")]
    Timeout { name: String, after: Duration },
    #[error("secret {name} is binary; only string secrets are supported")]
    Binary { name: String },
    /// AWS keeps a deleted secret for its recovery window, unreadable.
    #[error("secret {name} is marked for deletion")]
    Deleted { name: String },
    #[error("AWS profile {profile} is not in your AWS configuration")]
    NoProfile { profile: String },
    #[error("secret {name}: {problem}")]
    Malformed { name: String, problem: Problem },
    #[error("{what}: {message}")]
    Provider { what: String, message: String },
    /// A prefix matched no secrets. Usually a typo or the wrong account, so
    /// it fails unless the source is marked optional.
    #[error("{what} matched no secrets; mark the source optional if that is expected")]
    NoMatch { what: String },
    /// A `file` source, and no local store existed when the daemon unlocked.
    #[error("{what}: there is no local store")]
    NoStore { what: String },
    #[error("section [{name}] is not in the local store")]
    NoSection { name: String },
}

impl SourceError {
    pub fn hint(&self) -> Option<&str> {
        match self {
            SourceError::NeedsLogin { hint, .. } => Some(hint),
            SourceError::NoStore { .. } => Some("create it with `kagebunshin store init`"),
            SourceError::NoSection { .. } => Some("add keys with `kagebunshin store set`"),
            _ => None,
        }
    }
}

/// What is wrong with a secret's contents. Deliberately an enum rather than a
/// free-form string, so no code path can paste a value into it.
#[derive(Debug, PartialEq, Eq)]
pub enum Problem {
    NotAnObject,
    /// The value of `key` is null, an array or an object.
    UnsupportedValue {
        key: KeyName,
        kind: &'static str,
    },
    /// A field name is not a valid environment variable name. The name itself
    /// is not shown, in case a value was pasted where a name belongs.
    BadKeyName {
        index: usize,
    },
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Problem::NotAnObject => f.write_str("is not a JSON object"),
            Problem::UnsupportedValue { key, kind } => write!(
                f,
                "key {key} is {kind}; only strings, numbers and booleans are supported"
            ),
            Problem::BadKeyName { index } => write!(
                f,
                "field #{} (in name order) is not a valid environment variable name",
                index + 1
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Provider;

    fn e(key: &str, value: &str, from: &str) -> Entry {
        Entry {
            key: key.parse().unwrap(),
            value: SecretValue::new(value.into()),
            origin: Origin::new(Provider::AwsSm, from),
        }
    }

    #[test]
    fn later_wins_and_records_what_it_overrode() {
        let merged = merge([
            vec![e("A", "a1", "s1"), e("B", "b1", "s1")],
            vec![e("B", "b2", "s2"), e("C", "c2", "s2")],
            vec![e("B", "b3", "s3")],
        ]);
        let keys: Vec<_> = merged.keys().map(KeyName::as_str).collect();
        assert_eq!(keys, ["A", "B", "C"]);

        let b = &merged[&"B".parse::<KeyName>().unwrap()];
        assert_eq!(b.value.expose(), "b3");
        assert_eq!(b.origin.location, "s3");
        let lost: Vec<_> = b.overridden.iter().map(|o| o.location.as_str()).collect();
        assert_eq!(lost, ["s1", "s2"]);

        let a = &merged[&"A".parse::<KeyName>().unwrap()];
        assert_eq!((a.value.expose(), a.overridden.len()), ("a1", 0));
    }

    #[test]
    fn order_within_a_source_matters_too() {
        let merged = merge([vec![e("K", "first", "x"), e("K", "second", "y")]]);
        let k = &merged[&"K".parse::<KeyName>().unwrap()];
        assert_eq!(k.value.expose(), "second");
        assert_eq!(k.overridden[0].location, "x");
    }

    #[test]
    fn empty() {
        assert!(merge(Vec::<Vec<Entry>>::new()).is_empty());
    }

    #[test]
    fn expiry_warns_within_the_window() {
        let day = 86_400;
        let now = 1_000 * day;
        let status = |expires| ProviderStatus {
            provider: Provider::Proton,
            detail: String::new(),
            health: Health::Ok,
            expires,
        };
        assert_eq!(status(None).expiring_in(now), None);
        assert_eq!(status(Some(now + 15 * day)).expiring_in(now), None);
        assert_eq!(
            status(Some(now + EXPIRY_WARNING_DAYS * day)).expiring_in(now),
            Some(14)
        );
        assert_eq!(status(Some(now + day / 2)).expiring_in(now), Some(0));
        assert_eq!(status(Some(now - day / 2)).expiring_in(now), Some(-1));
    }

    #[test]
    fn stable_ids_reduce_arns_only_for_aws() {
        let arn = "arn:aws:secretsmanager:eu-west-1:1:secret:widget/prod-AbCdEf";
        assert_eq!(stable_origin(Provider::AwsSm, arn).location, "widget/prod");
        assert_eq!(stable_origin(Provider::Proton, "s/i").location, "s/i");
    }
}
