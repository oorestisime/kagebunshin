//! AWS Secrets Manager as a source.
//!
//! A source names one secret, a list of secrets, or a name prefix. Each secret
//! holds a JSON object whose fields become keys; with `key = "NAME"` a single
//! secret's whole string becomes one key instead. Secrets are fetched at most
//! [`MAX_CONCURRENT_FETCHES`] at a time, each under its own deadline, and the
//! result keeps a fixed order: declared order for a list, name order for a
//! prefix, field-name order within a secret.
//!
//! A prefix that matches no secrets is an error, unless the source is
//! optional: then it yields no keys.
//!
//! The AWS calls sit behind [`SmApi`] so the logic here is tested without the
//! network.

pub mod connect;
pub mod sdk;

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures::stream::{self, StreamExt, TryStreamExt};
use serde::{Deserialize, Serialize};

use super::{Backend, Entry, Health, Listed, Problem, ProviderStatus, Skip, Source, SourceError};
use crate::config::SourceSpec;
use crate::secret::SecretValue;
use crate::types::{KeyName, Origin, Provider};

pub const MAX_CONCURRENT_FETCHES: usize = 8;
pub const DEFAULT_FETCH_TIMEOUT: Duration = Duration::from_secs(10);
/// Stops a misbehaving `next_token` from looping forever. At AWS's maximum
/// page size this is 100,000 secrets.
const MAX_PAGES: usize = 1000;

/// The two Secrets Manager calls a source needs.
#[async_trait]
pub trait SmApi: Send + Sync {
    /// One page of names of secrets whose name starts with `prefix`, in no
    /// particular order.
    async fn list_page(&self, prefix: &str, next_token: Option<String>) -> Result<Page, ApiError>;

    /// The current value of one secret.
    async fn get_value(&self, name: &str) -> Result<Got, ApiError>;
}

/// A secret's value, and its name as AWS reports it.
#[derive(Debug)]
pub struct Got {
    pub raw: RawSecret,
    /// The secret's name, which differs from the one asked for when that
    /// was an ARN. `None` when the response did not say.
    pub name: Option<String>,
}

impl From<RawSecret> for Got {
    fn from(raw: RawSecret) -> Self {
        Self { raw, name: None }
    }
}

#[derive(Debug, Default)]
pub struct Page {
    pub names: Vec<String>,
    pub next_token: Option<String>,
}

#[derive(Debug)]
pub enum RawSecret {
    String(SecretValue),
    /// The secret has a binary value. Its bytes are not carried.
    Binary,
}

/// Failures an [`SmApi`] reports. Never carries a secret value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApiError {
    #[error("not found")]
    NotFound,
    #[error("access denied")]
    AccessDenied,
    #[error("credentials are missing or expired")]
    NeedsLogin,
    /// The secret is in its recovery window after being deleted.
    #[error("marked for deletion")]
    Deleted,
    /// The client's profile is not in the AWS configuration.
    #[error("the profile is not in the AWS configuration")]
    NoProfile,
    #[error("{0}")]
    Other(String),
}

/// Which secrets a source reads: the project file's selector, used as is.
pub use crate::config::Select;

/// What only AWS sources have: the named profile and the region the client
/// is built for. Both unset means the ambient AWS configuration.
///
/// In `config.toml` this is the `[aws]` table `kagebunshin connect aws`
/// writes: the defaults every AWS source falls back to.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsSettings {
    /// The named profile in effect; see `config::Registry::env` for how it
    /// is inherited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<Profile>,
    /// `None` lets the AWS configuration chain pick it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<Region>,
}

impl AwsSettings {
    /// [`where_suffix`] for these settings.
    pub fn label(&self) -> String {
        where_suffix(
            self.profile.as_ref().map(Profile::as_str),
            self.region.as_ref().map(Region::as_str),
        )
    }
}

/// An AWS named profile. Only the name is kept; nothing here reads the AWS
/// configuration itself.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Profile(String);

impl Profile {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Profile {
    type Error = &'static str;
    fn try_from(s: String) -> Result<Self, &'static str> {
        if s.is_empty() || s.len() > 128 {
            Err("profile must be 1 to 128 bytes")
        } else if s.chars().any(|c| c.is_whitespace() || c.is_control()) {
            Err("profile must not contain whitespace or control characters")
        } else {
            Ok(Self(s))
        }
    }
}

impl From<Profile> for String {
    fn from(p: Profile) -> String {
        p.0
    }
}

impl fmt::Display for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An AWS region name, e.g. `eu-west-1`. It becomes part of the Secrets
/// Manager endpoint's host name, so only lowercase letters, digits and
/// inner `-` are accepted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Region(String);

impl Region {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Region {
    type Error = &'static str;
    fn try_from(s: String) -> Result<Self, &'static str> {
        let ok = (1..=32).contains(&s.len())
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !s.starts_with('-')
            && !s.ends_with('-');
        if ok {
            Ok(Self(s))
        } else {
            Err(
                "region must be 1 to 32 lowercase letters, digits and inner `-`, e.g. \"eu-west-1\"",
            )
        }
    }
}

impl From<Region> for String {
    fn from(r: Region) -> String {
        r.0
    }
}

impl fmt::Display for Region {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The secret name in an AWS Secrets Manager ARN, without the `-` and six
/// random characters AWS appends to it: `widget/prod` for
/// `arn:aws:secretsmanager:eu-west-1:123456789012:secret:widget/prod-AbCdEf`.
/// `None` when `name` is not such an ARN.
pub fn arn_secret_name(name: &str) -> Option<&str> {
    let (_, secret) = name.strip_prefix("arn:")?.split_once(":secret:")?;
    Some(strip_arn_suffix(secret))
}

fn strip_arn_suffix(secret: &str) -> &str {
    match secret.rsplit_once('-') {
        Some((name, tail))
            if !name.is_empty()
                && tail.len() == 6
                && tail.bytes().all(|b| b.is_ascii_alphanumeric()) =>
        {
            name
        }
        _ => secret,
    }
}

/// A secret's stable id: its name, also when it is given as an ARN. What a
/// key's [`Origin`] records, so a sensitive mark on a secret holds however a
/// project file names it.
pub fn secret_id(name: &str) -> &str {
    arn_secret_name(name).unwrap_or(name)
}

/// ` (profile p, region r)`, either part left out when unset; empty when
/// both are. Appended to a source's label so errors from an environment that
/// mixes profiles say which one failed.
pub fn where_suffix(profile: Option<&str>, region: Option<&str>) -> String {
    let parts: Vec<String> = [("profile", profile), ("region", region)]
        .into_iter()
        .filter_map(|(k, v)| Some(format!("{k} {}", v?)))
        .collect();
    if parts.is_empty() {
        String::new()
    } else {
        format!(" ({})", parts.join(", "))
    }
}

/// What a provider status calls AWS read with `profile` and `region`:
/// `profile acme, region eu-west-1`, either part left out when unset, or
/// the ambient configuration with neither.
pub fn read_with(profile: Option<&str>, region: Option<&str>) -> String {
    match where_suffix(profile, region) {
        l if l.is_empty() => "ambient AWS configuration".to_owned(),
        l => l.trim_start_matches(" (").trim_end_matches(')').to_owned(),
    }
}

pub struct AwsSmSource {
    api: Arc<dyn SmApi>,
    select: Select,
    profile: Option<String>,
    region: Option<String>,
    timeout: Duration,
    optional: bool,
    /// Secrets under a prefix the last fetch left out, by name, and why.
    skipped: std::sync::Mutex<Vec<(String, Skip)>>,
}

impl AwsSmSource {
    pub fn new(api: Arc<dyn SmApi>, select: Select) -> Self {
        Self {
            api,
            select,
            profile: None,
            region: None,
            timeout: DEFAULT_FETCH_TIMEOUT,
            optional: false,
            skipped: std::sync::Mutex::default(),
        }
    }

    /// The project file's `optional` (default false). Here it only decides
    /// whether a prefix matching nothing is an error.
    pub fn with_optional(mut self, optional: bool) -> Self {
        self.optional = optional;
        self
    }

    /// The AWS profile the client was built for, used only to label errors
    /// and word the login hint.
    pub fn with_profile(mut self, profile: impl Into<String>) -> Self {
        self.profile = Some(profile.into());
        self
    }

    /// The region the client was built for, used only to label errors.
    pub fn with_region(mut self, region: impl Into<String>) -> Self {
        self.region = Some(region.into());
        self
    }

    /// Deadline for each AWS call.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    async fn list(&self) -> Result<Vec<String>, SourceError> {
        let prefix = match &self.select {
            Select::Secret { name, .. } => return Ok(vec![name.clone()]),
            Select::Secrets(names) => return Ok(names.clone()),
            Select::Prefix(prefix) => prefix,
        };
        let mut names = Vec::new();
        let mut token = None;
        for _ in 0..MAX_PAGES {
            let page = tokio::time::timeout(self.timeout, self.api.list_page(prefix, token))
                .await
                .map_err(|_| {
                    self.provider_error(format!("listing timed out after {:?}", self.timeout))
                })?
                .map_err(|e| match e {
                    ApiError::NeedsLogin => self.needs_login(),
                    ApiError::NoProfile => self.no_profile(),
                    e => self.provider_error(format!("cannot list secrets: {e}")),
                })?;
            names.extend(page.names);
            token = page.next_token;
            if token.is_none() {
                // The AWS name filter is not an exact prefix match, so filter
                // again here.
                names.retain(|n| n.starts_with(prefix.as_str()));
                if names.is_empty() && !self.optional {
                    return Err(SourceError::NoMatch {
                        what: self.describe(),
                    });
                }
                names.sort();
                names.dedup();
                return Ok(names);
            }
        }
        Err(self.provider_error(format!("listing returned more than {MAX_PAGES} pages")))
    }

    async fn fetch_one(
        &self,
        name: &str,
        key: Option<&KeyName>,
    ) -> Result<Vec<Entry>, SourceError> {
        let raw = tokio::time::timeout(self.timeout, self.api.get_value(name))
            .await
            .map_err(|_| SourceError::Timeout {
                name: name.into(),
                after: self.timeout,
            })?
            .map_err(|e| match e {
                ApiError::NotFound => SourceError::NotFound { name: name.into() },
                ApiError::AccessDenied => SourceError::AccessDenied { name: name.into() },
                ApiError::NeedsLogin => self.needs_login(),
                ApiError::Deleted => SourceError::Deleted { name: name.into() },
                ApiError::NoProfile => self.no_profile(),
                ApiError::Other(message) => SourceError::Provider {
                    what: format!("secret {name}"),
                    message,
                },
            })?;
        let Got {
            raw: RawSecret::String(value),
            name: reported,
        } = raw
        else {
            return Err(SourceError::Binary { name: name.into() });
        };
        let origin = Origin::new(
            Provider::AwsSm,
            secret_id(reported.as_deref().unwrap_or(name)),
        );
        if let Some(key) = key {
            return Ok(vec![Entry {
                key: key.clone(),
                value,
                origin,
            }]);
        }
        let fields = parse_object(&value).map_err(|problem| SourceError::Malformed {
            name: name.into(),
            problem,
        })?;
        Ok(fields
            .into_iter()
            .map(|(key, value)| Entry {
                key,
                value,
                origin: origin.clone(),
            })
            .collect())
    }

    fn needs_login(&self) -> SourceError {
        let hint = match &self.profile {
            Some(p) => {
                // Quoted for the shell unless plain: a profile name may
                // hold `;`, `$` or quotes.
                let plain = p
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_.@%+=:,/".contains(c));
                let p = if plain {
                    p.clone()
                } else {
                    format!("'{}'", p.replace('\'', r"'\''"))
                };
                format!("run `aws login --profile {p}` (`aws sso login` for an SSO profile)")
            }
            None => "this source has no profile, so it used the ambient/default AWS credentials; \
                     refresh them (e.g. `aws login`) or set `profile` on the source"
                .into(),
        };
        SourceError::NeedsLogin {
            what: self.describe(),
            hint,
        }
    }

    /// The profile this source reads with is not in the AWS configuration,
    /// so no login would help.
    fn no_profile(&self) -> SourceError {
        match &self.profile {
            Some(profile) => SourceError::NoProfile {
                profile: profile.clone(),
            },
            None => self.needs_login(),
        }
    }

    fn provider_error(&self, message: String) -> SourceError {
        SourceError::Provider {
            what: self.describe(),
            message,
        }
    }
}

/// AWS Secrets Manager as seen through one profile and region.
pub struct AwsBackend {
    api: Arc<dyn SmApi>,
    settings: AwsSettings,
}

impl AwsBackend {
    pub fn new(api: Arc<dyn SmApi>, settings: AwsSettings) -> Self {
        Self { api, settings }
    }

    fn source_for(&self, select: Select, optional: bool) -> AwsSmSource {
        let mut src = AwsSmSource::new(self.api.clone(), select).with_optional(optional);
        if let Some(p) = &self.settings.profile {
            src = src.with_profile(p.as_str());
        }
        if let Some(r) = &self.settings.region {
            src = src.with_region(r.as_str());
        }
        src
    }
}

#[async_trait]
impl Backend for AwsBackend {
    fn provider(&self) -> Provider {
        Provider::AwsSm
    }

    /// Secret names only: the keys of a JSON secret are not known without
    /// reading its value.
    async fn list(&self, prefix: &str) -> Result<Vec<Listed>, SourceError> {
        let names = self
            .source_for(Select::Prefix(prefix.into()), true)
            .names()
            .await?;
        Ok(names
            .into_iter()
            .map(|name| Listed {
                id: Origin::new(Provider::AwsSm, secret_id(&name)),
                name,
                title: None,
                keys: Vec::new(),
                plain: false,
                unread: None,
            })
            .collect())
    }

    /// One page of the secret list: enough to tell working credentials
    /// from missing or expired ones.
    async fn status(&self) -> ProviderStatus {
        let detail = read_with(
            self.settings.profile.as_ref().map(Profile::as_str),
            self.settings.region.as_ref().map(Region::as_str),
        );
        let src = self.source_for(Select::Prefix(String::new()), true);
        let health =
            match tokio::time::timeout(DEFAULT_FETCH_TIMEOUT, self.api.list_page("", None)).await {
                Ok(Ok(_)) => Health::Ok,
                Ok(Err(ApiError::NeedsLogin)) => match src.needs_login() {
                    SourceError::NeedsLogin { hint, .. } => Health::NeedsLogin { hint },
                    e => Health::Failed {
                        message: e.to_string(),
                    },
                },
                Ok(Err(ApiError::NoProfile)) => Health::Failed {
                    message: src.no_profile().to_string(),
                },
                Ok(Err(e)) => Health::Failed {
                    message: format!("cannot list secrets: {e}"),
                },
                Err(_) => Health::Failed {
                    message: format!("listing timed out after {DEFAULT_FETCH_TIMEOUT:?}"),
                },
            };
        ProviderStatus {
            provider: Provider::AwsSm,
            detail,
            health,
            expires: None,
        }
    }

    fn source(&self, spec: &SourceSpec) -> Box<dyn Source> {
        Box::new(self.source_for(spec.select.clone(), spec.optional))
    }
}

#[async_trait]
impl Source for AwsSmSource {
    fn describe(&self) -> String {
        let what = match &self.select {
            Select::Secret { name, .. } => format!("aws_sm secret {name}"),
            Select::Secrets(names) => format!("aws_sm secrets {}", names.join(", ")),
            Select::Prefix(prefix) => format!("aws_sm prefix {prefix}"),
        };
        what + &where_suffix(self.profile.as_deref(), self.region.as_deref())
    }

    /// The secret's or list's names as given; a prefix's, listed, in name
    /// order.
    async fn names(&self) -> Result<Vec<String>, SourceError> {
        self.list().await
    }

    /// Fails as a whole if any secret fails: a partial set of keys would be
    /// silently wrong. The exception is a prefix, which is often mixed: a
    /// secret under it that has no keys this login can read (it is not a
    /// JSON object, is binary, or is refused) is left out and listed by
    /// [`Source::skipped`] instead. A failure that may pass, such as a
    /// timeout, still fails, and so does a prefix whose every secret is
    /// refused: that login reads nothing there.
    async fn fetch(&self, names: &[String]) -> Result<Vec<Entry>, SourceError> {
        let key = match &self.select {
            Select::Secret { key, .. } => key.as_ref(),
            _ => None,
        };
        let prefix = matches!(self.select, Select::Prefix(_));
        // `buffered` keeps output in input order however the fetches finish.
        let per_secret: Vec<Result<Vec<Entry>, Skip>> = stream::iter(names.to_vec())
            .map(|name| async move {
                let why = match self.fetch_one(&name, key).await {
                    Ok(entries) => return Ok(Ok(entries)),
                    Err(e) if !prefix => return Err(e),
                    Err(SourceError::Malformed {
                        problem: Problem::NotAnObject,
                        ..
                    }) => Skip::NotAnObject,
                    Err(SourceError::Binary { .. }) => Skip::Binary,
                    Err(SourceError::AccessDenied { .. }) => Skip::Denied,
                    Err(e) => return Err(e),
                };
                Ok(Err(why))
            })
            .buffered(MAX_CONCURRENT_FETCHES)
            .try_collect()
            .await?;
        if let Some(first) = names.first()
            && per_secret
                .iter()
                .all(|got| matches!(got, Err(Skip::Denied)))
        {
            return Err(SourceError::AccessDenied {
                name: first.clone(),
            });
        }
        let skipped = names
            .iter()
            .zip(&per_secret)
            .filter_map(|(name, got)| Some((name.clone(), *got.as_ref().err()?)))
            .collect();
        if let Ok(mut s) = self.skipped.lock() {
            *s = skipped;
        }
        Ok(per_secret.into_iter().flatten().flatten().collect())
    }

    fn skipped(&self) -> Vec<(String, Skip)> {
        self.skipped.lock().map(|s| s.clone()).unwrap_or_default()
    }
}

/// Splits a JSON object into keys, in field-name order. Strings are taken as
/// they are; numbers and booleans become their JSON text.
///
/// The parsed tree is not zeroed if parsing fails part way; string values are
/// moved, not copied, into `SecretValue`s.
fn parse_object(value: &SecretValue) -> Result<Vec<(KeyName, SecretValue)>, Problem> {
    use serde_json::Value;
    let Ok(Value::Object(map)) = serde_json::from_str::<Value>(value.expose()) else {
        return Err(Problem::NotAnObject);
    };
    // Sort here: `Map`'s own order depends on serde_json's `preserve_order`
    // feature, which any crate in the graph can turn on.
    let mut fields: Vec<(String, Value)> = map.into_iter().collect();
    fields.sort_by(|a, b| a.0.cmp(&b.0));
    fields
        .into_iter()
        .enumerate()
        .map(|(index, (name, v))| {
            let key: KeyName = name.parse().map_err(|_| Problem::BadKeyName { index })?;
            let kind = match v {
                Value::String(s) => return Ok((key, SecretValue::new(s))),
                Value::Number(n) => return Ok((key, SecretValue::new(n.to_string()))),
                Value::Bool(b) => return Ok((key, SecretValue::new(b.to_string()))),
                Value::Null => "null",
                Value::Array(_) => "an array",
                Value::Object(_) => "an object",
            };
            Err(Problem::UnsupportedValue { key, kind })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};
    use std::hash::{BuildHasher, RandomState};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

    use super::*;
    use crate::source::ReadAll;
    use crate::source::merge;
    use crate::test_support::{Canary, assert_no_canary};

    #[derive(Clone)]
    enum Fake {
        Str(String),
        Binary,
        Fail(ApiError),
    }

    /// An in-memory Secrets Manager. Lists in reverse name order (AWS promises
    /// no order), pages by `page_size`, and sleeps per secret on tokio's clock.
    #[derive(Default)]
    struct FakeSm {
        secrets: BTreeMap<String, Fake>,
        delays: HashMap<String, Duration>,
        page_size: usize,
        list_error: Option<ApiError>,
        list_tokens: Mutex<Vec<Option<String>>>,
        completed: Mutex<Vec<String>>,
        in_flight: AtomicUsize,
        max_in_flight: AtomicUsize,
    }

    impl FakeSm {
        fn with(mut self, name: &str, v: Fake) -> Self {
            self.secrets.insert(name.into(), v);
            self
        }

        fn json(self, name: &str, json: serde_json::Value) -> Self {
            self.with(name, Fake::Str(json.to_string()))
        }

        fn delay(mut self, name: &str, d: Duration) -> Self {
            self.delays.insert(name.into(), d);
            self
        }
    }

    #[async_trait]
    impl SmApi for FakeSm {
        async fn list_page(&self, prefix: &str, token: Option<String>) -> Result<Page, ApiError> {
            self.list_tokens.lock().unwrap().push(token.clone());
            if let Some(e) = &self.list_error {
                return Err(e.clone());
            }
            let all: Vec<String> = (self.secrets.keys().rev())
                .filter(|n| n.starts_with(prefix))
                .cloned()
                .collect();
            let start: usize = token.map_or(0, |t| t.parse().unwrap());
            let size = if self.page_size == 0 {
                all.len()
            } else {
                self.page_size
            };
            let end = (start + size).min(all.len());
            Ok(Page {
                names: all[start..end].to_vec(),
                next_token: (end < all.len()).then(|| end.to_string()),
            })
        }

        async fn get_value(&self, name: &str) -> Result<Got, ApiError> {
            let now = self.in_flight.fetch_add(1, SeqCst) + 1;
            self.max_in_flight.fetch_max(now, SeqCst);
            if let Some(d) = self.delays.get(name) {
                tokio::time::sleep(*d).await;
            }
            self.in_flight.fetch_sub(1, SeqCst);
            self.completed.lock().unwrap().push(name.into());
            match self.secrets.get(name) {
                None => Err(ApiError::NotFound),
                Some(Fake::Str(s)) => Ok(RawSecret::String(SecretValue::new(s.clone())).into()),
                Some(Fake::Binary) => Ok(RawSecret::Binary.into()),
                Some(Fake::Fail(e)) => Err(e.clone()),
            }
        }
    }

    fn source(fake: FakeSm, select: Select) -> (Arc<FakeSm>, AwsSmSource) {
        let fake = Arc::new(fake);
        let api: Arc<dyn SmApi> = fake.clone();
        (fake, AwsSmSource::new(api, select))
    }

    fn secret(name: &str) -> Select {
        Select::Secret {
            name: name.into(),
            key: None,
        }
    }

    fn secrets(names: &[&str]) -> Select {
        Select::Secrets(names.iter().map(|s| s.to_string()).collect())
    }

    /// (key, value, origin) for each entry, in order.
    fn flat(entries: &[Entry]) -> Vec<(String, String, String)> {
        let f = |e: &Entry| {
            let k = e.key.as_str().to_owned();
            (k, e.value.expose().to_owned(), e.origin.to_string())
        };
        entries.iter().map(f).collect()
    }

    fn row(k: &str, v: &str, o: &str) -> (String, String, String) {
        (k.into(), v.into(), o.into())
    }

    #[tokio::test]
    async fn json_object_becomes_sorted_keys_with_scalars_stringified() {
        let fake = FakeSm::default().json(
            "app/dev",
            serde_json::json!({"Z_URL": "postgres://x", "PORT": 5432, "RATIO": 1.5, "DEBUG": true}),
        );
        let (_, src) = source(fake, secret("app/dev"));
        assert_eq!(src.describe(), "aws_sm secret app/dev");
        let got = src.read_all().await.unwrap();
        assert_eq!(
            flat(&got),
            [
                row("DEBUG", "true", "aws_sm:app/dev"),
                row("PORT", "5432", "aws_sm:app/dev"),
                row("RATIO", "1.5", "aws_sm:app/dev"),
                row("Z_URL", "postgres://x", "aws_sm:app/dev"),
            ]
        );
    }

    #[tokio::test]
    async fn key_takes_the_whole_string_and_is_required_for_non_json() {
        let fake = || FakeSm::default().with("pem", Fake::Str("-----BEGIN KEY-----".into()));
        let select = Select::Secret {
            name: "pem".into(),
            key: Some("TLS_KEY".parse().unwrap()),
        };
        let (_, src) = source(fake(), select);
        let got = src.read_all().await.unwrap();
        assert_eq!(
            flat(&got),
            [row("TLS_KEY", "-----BEGIN KEY-----", "aws_sm:pem")]
        );

        let (_, src) = source(fake(), secret("pem"));
        let err = src.read_all().await.unwrap_err();
        assert!(matches!(
            err,
            SourceError::Malformed { ref name, problem: Problem::NotAnObject } if name == "pem"
        ));
        assert_eq!(err.to_string(), "secret pem: is not a JSON object");
    }

    /// A prefix is often mixed: a plain string under it is left out and
    /// named, never its value, and the rest is read.
    #[tokio::test]
    async fn a_prefix_skips_a_secret_that_is_not_a_json_object() {
        let canary = Canary::new();
        let fake = FakeSm::default()
            .json("app/a", serde_json::json!({"A": "1"}))
            .with("app/plain", Fake::Str(canary.value().into()))
            .json("app/z", serde_json::json!({"Z": "2"}));
        let (_, src) = source(fake, Select::Prefix("app/".into()));
        let got = src.read_all().await.unwrap();
        assert_eq!(
            flat(&got),
            [row("A", "1", "aws_sm:app/a"), row("Z", "2", "aws_sm:app/z")]
        );
        assert_eq!(src.skipped(), [("app/plain".to_owned(), Skip::NotAnObject)]);
        assert_no_canary(&canary, &format!("{:?}", src.skipped()));
    }

    /// Nor does one secret under a prefix that is binary, or that the login
    /// may not read, take the others with it. Named on its own, each fails.
    #[tokio::test]
    async fn a_prefix_skips_a_secret_it_cannot_read() {
        let fake = || {
            FakeSm::default()
                .json("app/a", serde_json::json!({"A": "1"}))
                .with("app/blob", Fake::Binary)
                .with("app/locked", Fake::Fail(ApiError::AccessDenied))
        };
        let (_, src) = source(fake(), Select::Prefix("app/".into()));
        let got = src.read_all().await.unwrap();
        assert_eq!(flat(&got), [row("A", "1", "aws_sm:app/a")]);
        assert_eq!(
            src.skipped(),
            [
                ("app/blob".to_owned(), Skip::Binary),
                ("app/locked".to_owned(), Skip::Denied)
            ]
        );

        let (_, src) = source(fake(), secrets(&["app/a", "app/locked"]));
        let err = src.read_all().await.unwrap_err();
        assert!(matches!(err, SourceError::AccessDenied { ref name } if name == "app/locked"));
        assert!(src.skipped().is_empty());
    }

    /// A prefix none of whose secrets the login may read fails: there is
    /// nothing to read around. So does one a secret of which fails some
    /// other way, which may pass.
    #[tokio::test]
    async fn a_prefix_wholly_refused_or_failing_still_fails() {
        let fake = FakeSm::default()
            .with("app/a", Fake::Fail(ApiError::AccessDenied))
            .with("app/b", Fake::Fail(ApiError::AccessDenied));
        let (_, src) = source(fake, Select::Prefix("app/".into()));
        let err = src.read_all().await.unwrap_err();
        assert!(matches!(err, SourceError::AccessDenied { ref name } if name == "app/a"));

        let fake = FakeSm::default()
            .json("app/a", serde_json::json!({"A": "1"}))
            .with("app/b", Fake::Fail(ApiError::Other("throttled".into())));
        let (_, src) = source(fake, Select::Prefix("app/".into()));
        let err = src.read_all().await.unwrap_err();
        assert!(matches!(err, SourceError::Provider { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn secrets_keep_declared_order_so_later_ones_win() {
        let fake = FakeSm::default()
            .json("b", serde_json::json!({"K": "from b", "ONLY_B": "1"}))
            .json("a", serde_json::json!({"K": "from a"}));
        let (_, src) = source(fake, secrets(&["b", "a"]));
        let merged = merge([src.read_all().await.unwrap()]);
        let k = &merged[&"K".parse::<KeyName>().unwrap()];
        assert_eq!(k.value.expose(), "from a");
        assert_eq!(k.overridden[0].location, "b");
    }

    #[tokio::test]
    async fn prefix_follows_three_pages_and_sorts_by_name() {
        let mut fake = FakeSm::default();
        for n in ["p/e", "p/a", "p/c", "p/d", "p/b", "other/x"] {
            fake = fake.json(n, serde_json::json!({ "FROM": n }));
        }
        fake.page_size = 2;
        let (fake, src) = source(fake, Select::Prefix("p/".into()));
        let got = src.read_all().await.unwrap();
        let origins: Vec<_> = got.iter().map(|e| e.origin.location.as_str()).collect();
        assert_eq!(origins, ["p/a", "p/b", "p/c", "p/d", "p/e"]);
        assert_eq!(
            *fake.list_tokens.lock().unwrap(),
            [None, Some("2".into()), Some("4".into())]
        );
    }

    #[tokio::test]
    async fn prefix_filters_names_the_api_should_not_have_returned() {
        struct Loose;
        #[async_trait]
        impl SmApi for Loose {
            async fn list_page(&self, _: &str, _: Option<String>) -> Result<Page, ApiError> {
                let names = vec!["P/upper".into(), "p/ok".into(), "xp/no".into()];
                Ok(Page {
                    names,
                    next_token: None,
                })
            }
            async fn get_value(&self, _: &str) -> Result<Got, ApiError> {
                Ok(RawSecret::String(SecretValue::new(r#"{"A":"1"}"#.into())).into())
            }
        }
        let src = AwsSmSource::new(Arc::new(Loose), Select::Prefix("p/".into()));
        let got = src.read_all().await.unwrap();
        assert_eq!(flat(&got), [row("A", "1", "aws_sm:p/ok")]);
    }

    #[tokio::test]
    async fn a_prefix_matching_nothing_is_an_error_unless_optional() {
        let c = Canary::new();
        // Secrets exist, just not under this prefix; one holds a canary.
        let fake = || {
            FakeSm::default()
                .json("other/a", serde_json::json!({ "A": c.value() }))
                .json("widget/prod/x", serde_json::json!({ "B": c.value() }))
        };
        let (fake_api, src) = source(fake(), Select::Prefix("widget/dev/".into()));
        let err = src.read_all().await.unwrap_err();
        assert!(
            matches!(err, SourceError::NoMatch { ref what } if what == "aws_sm prefix widget/dev/"),
            "{err:?}"
        );
        assert_eq!(
            err.to_string(),
            "aws_sm prefix widget/dev/ matched no secrets; mark the source optional if that is expected"
        );
        assert_no_canary(&c, &err.to_string());
        assert_no_canary(&c, &format!("{err:?}"));
        // Nothing was fetched.
        assert!(fake_api.completed.lock().unwrap().is_empty());

        // Empty after the client-side filter counts too.
        struct Loose;
        #[async_trait]
        impl SmApi for Loose {
            async fn list_page(&self, _: &str, _: Option<String>) -> Result<Page, ApiError> {
                let names = vec!["P/upper".into()];
                Ok(Page {
                    names,
                    next_token: None,
                })
            }
            async fn get_value(&self, _: &str) -> Result<Got, ApiError> {
                unreachable!("nothing matches")
            }
        }
        let src = AwsSmSource::new(Arc::new(Loose), Select::Prefix("p/".into()));
        assert!(matches!(
            src.read_all().await,
            Err(SourceError::NoMatch { .. })
        ));

        // Optional: no keys, no error.
        let (_, src) = source(fake(), Select::Prefix("widget/dev/".into()));
        let got = src.with_optional(true).read_all().await.unwrap();
        assert!(got.is_empty());

        // Optional changes nothing when the prefix does match.
        let (_, src) = source(fake(), Select::Prefix("other/".into()));
        let got = src.with_optional(true).read_all().await.unwrap();
        assert_eq!(got.len(), 1);
    }

    #[tokio::test]
    async fn optional_does_not_hide_other_failures() {
        // A named secret that is missing still fails; optional sources are
        // the resolver's business beyond the zero-match case.
        let (_, src) = source(FakeSm::default(), secret("gone"));
        let err = src.with_optional(true).read_all().await.unwrap_err();
        assert!(matches!(err, SourceError::NotFound { .. }), "{err:?}");
        let fake = FakeSm {
            list_error: Some(ApiError::AccessDenied),
            ..FakeSm::default()
        };
        let (_, src) = source(fake, Select::Prefix("p/".into()));
        assert!(matches!(
            src.with_optional(true).read_all().await,
            Err(SourceError::Provider { .. })
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn output_order_does_not_depend_on_completion_order() {
        let names: Vec<String> = (0..12).map(|i| format!("s{i:02}")).collect();
        let expected: Vec<_> = names
            .iter()
            .map(|n| row("N", n, &format!("aws_sm:{n}")))
            .collect();
        let seed = RandomState::new();
        for round in 0..5u64 {
            let mut fake = FakeSm::default();
            for (i, n) in names.iter().enumerate() {
                // Round 0 finishes in exact reverse; the rest at random.
                let ms = if round == 0 {
                    1000 - i as u64 * 10
                } else {
                    seed.hash_one((round, i)) % 1000
                };
                fake = fake
                    .json(n, serde_json::json!({ "N": n }))
                    .delay(n, Duration::from_millis(ms));
            }
            let (fake, src) = source(fake, Select::Prefix("s".into()));
            assert_eq!(
                flat(&src.read_all().await.unwrap()),
                expected,
                "round {round}"
            );
            if round == 0 {
                let done = fake.completed.lock().unwrap().clone();
                // The first batch of 8 starts together and finishes backwards.
                assert_eq!(done[0], "s07");
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn at_most_eight_fetches_run_at_once() {
        let mut fake = FakeSm::default();
        let names: Vec<String> = (0..30).map(|i| format!("s{i:02}")).collect();
        for n in &names {
            fake = fake
                .json(n, serde_json::json!({ "N": n }))
                .delay(n, Duration::from_secs(1));
        }
        let (fake, src) = source(fake, Select::Secrets(names));
        let start = tokio::time::Instant::now();
        assert_eq!(src.read_all().await.unwrap().len(), 30);
        assert_eq!(fake.max_in_flight.load(SeqCst), MAX_CONCURRENT_FETCHES);
        // 30 one-second fetches, eight at a time.
        assert_eq!(start.elapsed(), Duration::from_secs(4));
    }

    #[tokio::test(start_paused = true)]
    async fn each_fetch_has_a_deadline() {
        let fake = FakeSm::default()
            .json("fast", serde_json::json!({"A": "1"}))
            .json("slow", serde_json::json!({"B": "2"}))
            .delay("slow", Duration::from_secs(60));
        let (_, src) = source(fake, secrets(&["fast", "slow"]));
        let src = src.with_timeout(Duration::from_secs(5));
        let err = src.read_all().await.unwrap_err();
        assert!(matches!(
            err,
            SourceError::Timeout { ref name, after } if name == "slow" && after == Duration::from_secs(5)
        ));
    }

    #[tokio::test]
    async fn one_missing_secret_fails_the_whole_source() {
        let fake = FakeSm::default().json("a", serde_json::json!({"A": "1"}));
        let (_, src) = source(fake, secrets(&["a", "gone"]));
        let err = src.read_all().await.unwrap_err();
        assert!(matches!(err, SourceError::NotFound { ref name } if name == "gone"));
        assert_eq!(err.to_string(), "secret gone does not exist");
    }

    #[tokio::test]
    async fn binary_secrets_are_rejected() {
        let fake = FakeSm::default().with("blob", Fake::Binary);
        let (_, src) = source(fake, secret("blob"));
        let err = src.read_all().await.unwrap_err();
        assert!(matches!(err, SourceError::Binary { ref name } if name == "blob"));
    }

    #[tokio::test]
    async fn api_errors_map_to_source_errors() {
        let fake = FakeSm::default().with("x", Fake::Fail(ApiError::AccessDenied));
        let (_, src) = source(fake, secret("x"));
        let err = src.read_all().await.unwrap_err();
        assert!(matches!(err, SourceError::AccessDenied { ref name } if name == "x"));

        let fake = FakeSm::default().with("x", Fake::Fail(ApiError::Deleted));
        let (_, src) = source(fake, secret("x"));
        let err = src.read_all().await.unwrap_err();
        assert_eq!(err.to_string(), "secret x is marked for deletion");

        // A profile that is not there; with none, it is the login after all.
        let fake = FakeSm::default().with("x", Fake::Fail(ApiError::NoProfile));
        let (_, src) = source(fake, secret("x"));
        let err = src.with_profile("dev").read_all().await.unwrap_err();
        assert!(matches!(err, SourceError::NoProfile { ref profile } if profile == "dev"));
        let fake = FakeSm::default().with("x", Fake::Fail(ApiError::NoProfile));
        let (_, src) = source(fake, secret("x"));
        let err = src.read_all().await.unwrap_err();
        assert!(matches!(err, SourceError::NeedsLogin { .. }));

        let fake = FakeSm::default().with("x", Fake::Fail(ApiError::NeedsLogin));
        let (_, src) = source(fake, secret("x"));
        let err = src.with_profile("dev").read_all().await.unwrap_err();
        assert!(matches!(err, SourceError::NeedsLogin { .. }));
        assert_eq!(
            err.hint(),
            Some("run `aws login --profile dev` (`aws sso login` for an SSO profile)")
        );
        let fake = FakeSm::default().with("x", Fake::Fail(ApiError::NeedsLogin));
        let (_, src) = source(fake, secret("x"));
        let quoted = src.with_profile("it's;$(x)").read_all().await.unwrap_err();
        assert_eq!(
            quoted.hint(),
            Some(r"run `aws login --profile 'it'\''s;$(x)'` (`aws sso login` for an SSO profile)")
        );
        assert_eq!(
            err.to_string(),
            "aws_sm secret x (profile dev): credentials are missing or expired"
        );

        // No profile: the hint says the ambient credentials failed.
        let fake = FakeSm {
            list_error: Some(ApiError::NeedsLogin),
            ..FakeSm::default()
        };
        let (_, src) = source(fake, Select::Prefix("p/".into()));
        let err = src.with_region("eu-west-1").read_all().await.unwrap_err();
        assert_eq!(
            err.hint(),
            Some(
                "this source has no profile, so it used the ambient/default AWS credentials; \
                 refresh them (e.g. `aws login`) or set `profile` on the source"
            )
        );
        assert_eq!(
            err.to_string(),
            "aws_sm prefix p/ (region eu-west-1): credentials are missing or expired"
        );
    }

    /// Every malformed-secret error names the secret, and sometimes a key, but
    /// never shows any part of a value.
    #[tokio::test]
    async fn malformed_secret_errors_never_contain_values() {
        let c = Canary::new();
        let v = c.value();
        let cases = [
            ("not-json", format!("{v} plain text")),
            ("truncated", format!(r#"{{"A": "{v}"#)),
            ("json-string", format!(r#""{v}""#)),
            ("array", format!(r#"["{v}"]"#)),
            ("null-field", format!(r#"{{"A": null, "B": "{v}"}}"#)),
            ("nested", format!(r#"{{"A": {{"inner": "{v}"}}}}"#)),
            ("list-field", format!(r#"{{"A": ["{v}"]}}"#)),
            ("bad-key", format!(r#"{{"{v} not a name": "x"}}"#)),
        ];
        for (name, body) in cases {
            let fake = FakeSm::default().with(name, Fake::Str(body));
            let (_, src) = source(fake, secret(name));
            let err = src.read_all().await.unwrap_err();
            assert!(
                matches!(err, SourceError::Malformed { .. }),
                "{name}: {err}"
            );
            assert!(err.to_string().contains(name), "{name}: {err}");
            assert_no_canary(&c, &err.to_string());
            assert_no_canary(&c, &format!("{err:?}"));
        }
    }

    #[test]
    fn problems_name_the_key_and_kind() {
        let p = |s: &str| {
            parse_object(&SecretValue::new(s.into()))
                .unwrap_err()
                .to_string()
        };
        assert_eq!(
            p(r#"{"A": "1", "B": null}"#),
            "key B is null; only strings, numbers and booleans are supported"
        );
        assert!(p(r#"{"A": {}}"#).starts_with("key A is an object"));
        assert!(p(r#"{"A": []}"#).starts_with("key A is an array"));
        assert_eq!(
            p(r#"{"A": "1", "b-c": "2"}"#),
            "field #2 (in name order) is not a valid environment variable name"
        );
    }

    #[tokio::test]
    async fn backend_lists_names_by_stable_id_and_reports_status() {
        let c = Canary::new();
        let fake = FakeSm::default()
            .json("widget/dev", serde_json::json!({ "A": c.value() }))
            .json("widget/prod", serde_json::json!({ "B": c.value() }))
            .json("other/x", serde_json::json!({ "C": c.value() }));
        let settings = AwsSettings {
            profile: Some("acme-dev".to_owned().try_into().unwrap()),
            region: None,
        };
        let backend = AwsBackend::new(Arc::new(fake), settings.clone());
        let listed = backend.list("widget/").await.unwrap();
        let ids: Vec<String> = listed.iter().map(|l| l.id.to_string()).collect();
        assert_eq!(ids, ["aws_sm:widget/dev", "aws_sm:widget/prod"]);
        assert!(listed.iter().all(|l| l.keys.is_empty()));
        assert_no_canary(&c, &format!("{listed:?}"));
        assert_eq!(backend.list("").await.unwrap().len(), 3);

        let status = backend.status().await;
        assert_eq!(status.health, Health::Ok);
        assert_eq!(status.detail, "profile acme-dev");

        let expired = FakeSm {
            list_error: Some(ApiError::NeedsLogin),
            ..FakeSm::default()
        };
        let status = AwsBackend::new(Arc::new(expired), settings).status().await;
        let Health::NeedsLogin { hint } = status.health else {
            panic!("{status:?}");
        };
        assert!(hint.contains("aws login --profile acme-dev"), "{hint}");
    }
}
