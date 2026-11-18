//! Validated names and key origins shared by the daemon, the CLI and the app.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Why a name was rejected. Never echoes the rejected input: it may have come
/// from a secret payload.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NameError {
    #[error("{kind} is empty")]
    Empty { kind: &'static str },
    #[error("{kind} is longer than {max} bytes")]
    TooLong { kind: &'static str, max: usize },
    #[error("{kind} contains a character outside {allowed}")]
    BadChar {
        kind: &'static str,
        allowed: &'static str,
    },
}

/// Lowercase project or environment slug: `[a-z0-9][a-z0-9_-]*`, at most 64
/// bytes. Used in file names and Proton vault names, so kept deliberately narrow.
fn validate_slug(kind: &'static str, s: &str) -> Result<(), NameError> {
    const MAX: usize = 64;
    const ALLOWED: &str = "[a-z0-9][a-z0-9_-]*";
    let mut bytes = s.bytes();
    let first = bytes.next().ok_or(NameError::Empty { kind })?;
    if s.len() > MAX {
        return Err(NameError::TooLong { kind, max: MAX });
    }
    let ok_first = first.is_ascii_lowercase() || first.is_ascii_digit();
    let ok_rest =
        bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
    if ok_first && ok_rest {
        Ok(())
    } else {
        Err(NameError::BadChar {
            kind,
            allowed: ALLOWED,
        })
    }
}

/// Environment variable name: `[A-Za-z_][A-Za-z0-9_]*`, at most 256 bytes.
fn validate_key(s: &str) -> Result<(), NameError> {
    const KIND: &str = "key name";
    const MAX: usize = 256;
    let mut bytes = s.bytes();
    let first = bytes.next().ok_or(NameError::Empty { kind: KIND })?;
    if s.len() > MAX {
        return Err(NameError::TooLong {
            kind: KIND,
            max: MAX,
        });
    }
    let ok_first = first.is_ascii_alphabetic() || first == b'_';
    let ok_rest = bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_');
    if ok_first && ok_rest {
        Ok(())
    } else {
        Err(NameError::BadChar {
            kind: KIND,
            allowed: "[A-Za-z_][A-Za-z0-9_]*",
        })
    }
}

macro_rules! validated_name {
    ($(#[$meta:meta])* $name:ident, $validate:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = NameError;
            fn try_from(s: String) -> Result<Self, NameError> {
                let validate: fn(&str) -> Result<(), NameError> = $validate;
                validate(&s)?;
                Ok(Self(s))
            }
        }

        impl FromStr for $name {
            type Err = NameError;
            fn from_str(s: &str) -> Result<Self, NameError> {
                Self::try_from(s.to_owned())
            }
        }

        impl From<$name> for String {
            fn from(n: $name) -> String {
                n.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

validated_name!(
    /// A registered project, e.g. `widget`.
    ProjectName,
    |s| validate_slug("project name", s)
);
validated_name!(
    /// An environment within a project, e.g. `dev` or `prod`.
    EnvName,
    |s| validate_slug("environment name", s)
);
validated_name!(
    /// An environment variable name, e.g. `DATABASE_URL`.
    KeyName,
    validate_key
);

/// The provider kind a value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    AwsSm,
    File,
    Proton,
}

impl Provider {
    pub fn as_str(self) -> &'static str {
        match self {
            Provider::AwsSm => "aws_sm",
            Provider::File => "file",
            Provider::Proton => "proton",
        }
    }
}

/// Where a key's value came from, e.g. `aws_sm:widget/dev/shared`. Shown in
/// `status` and `diff`; never contains a value.
///
/// Which secret it is, is its provider and location alone: two origins that
/// differ only in `name` are equal, sort together and hash alike, so a mark
/// keyed by one holds whatever the secret is called today.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Origin {
    pub provider: Provider,
    /// Provider-specific location: an AWS secret name, a store section, a
    /// Proton item's share and item ids.
    pub location: String,
    /// What people call it, where the location is an id nobody reads: a
    /// Proton key's `<vault>/<KEY>`, as a project file selects it. Shown in
    /// place of the location. One read from the local store's marks has
    /// none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl Origin {
    pub fn new(provider: Provider, location: impl Into<String>) -> Self {
        Self {
            provider,
            location: location.into(),
            name: None,
        }
    }

    /// This origin, called `name` wherever it is shown.
    pub fn named(self, name: impl Into<String>) -> Self {
        Self {
            name: Some(name.into()),
            ..self
        }
    }

    /// What to show for the location: its name, if it has one.
    pub fn shown(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.location)
    }

    /// `provider:location`, whatever it is called: the same for the same
    /// secret, so it can key what is drawn or logged.
    pub fn id(&self) -> String {
        format!("{}:{}", self.provider.as_str(), self.location)
    }

    fn key(&self) -> (Provider, &str) {
        (self.provider, &self.location)
    }
}

impl PartialEq for Origin {
    fn eq(&self, other: &Self) -> bool {
        self.key() == other.key()
    }
}

impl Eq for Origin {}

impl PartialOrd for Origin {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Origin {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.key().cmp(&other.key())
    }
}

impl std::hash::Hash for Origin {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.key().hash(state);
    }
}

/// `provider:name`, or `provider:location` for one with no name.
impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.provider.as_str(), self.shown())
    }
}

/// `s` as one shell word: bare when it is safe, else in single quotes.
pub fn shell_quote(s: &str) -> String {
    let safe = |c: char| c.is_ascii_alphanumeric() || "_./:@%+=,-".contains(c);
    if !s.is_empty() && s.chars().all(safe) {
        s.to_owned()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_names() {
        let ok = ["A", "_", "DATABASE_URL", "a1", "_X_9", &"K".repeat(256)];
        for k in ok {
            assert!(k.parse::<KeyName>().is_ok(), "{k} should be valid");
        }
        let bad: &[(&str, NameError)] = &[
            ("", NameError::Empty { kind: "key name" }),
            ("1A", bad_key()),
            ("A-B", bad_key()),
            ("A B", bad_key()),
            ("A=B", bad_key()),
            ("É", bad_key()),
            ("A\0", bad_key()),
        ];
        for (k, want) in bad {
            assert_eq!(k.parse::<KeyName>().unwrap_err(), *want, "{k:?}");
        }
        assert!(matches!(
            "K".repeat(257).parse::<KeyName>(),
            Err(NameError::TooLong { .. })
        ));
    }

    /// A name is what an origin is called, not which secret it is.
    #[test]
    fn an_origin_is_its_provider_and_location_whatever_it_is_called() {
        use std::collections::{BTreeSet, HashSet};
        let id = Origin::new(Provider::Proton, "S1/i1");
        let named = id.clone().named("Work/TOKEN");
        assert_eq!(id, named);
        assert_eq!(named.cmp(&id), std::cmp::Ordering::Equal);
        assert!(HashSet::from([id.clone()]).contains(&named));
        assert!(BTreeSet::from([named.clone()]).contains(&id));
        assert_ne!(
            named,
            Origin::new(Provider::Proton, "S1/i2").named("Work/TOKEN")
        );

        assert_eq!(
            (id.shown(), id.to_string().as_str()),
            ("S1/i1", "proton:S1/i1")
        );
        assert_eq!(named.shown(), "Work/TOKEN");
        assert_eq!(named.to_string(), "proton:Work/TOKEN");
        assert_eq!(named.id(), "proton:S1/i1");

        // On the wire the name goes along; one without has no field.
        let wire = serde_json::to_string(&named).unwrap();
        assert_eq!(
            wire,
            r#"{"provider":"proton","location":"S1/i1","name":"Work/TOKEN"}"#
        );
        let back: Origin = serde_json::from_str(&wire).unwrap();
        assert_eq!(back.name.as_deref(), Some("Work/TOKEN"));
        assert_eq!(
            serde_json::to_string(&id).unwrap(),
            r#"{"provider":"proton","location":"S1/i1"}"#
        );
    }

    fn bad_key() -> NameError {
        NameError::BadChar {
            kind: "key name",
            allowed: "[A-Za-z_][A-Za-z0-9_]*",
        }
    }

    #[test]
    fn slugs() {
        for s in ["widget", "blog", "dev", "prod-eu", "a_b", "9lives"] {
            assert!(s.parse::<ProjectName>().is_ok(), "{s}");
            assert!(s.parse::<EnvName>().is_ok(), "{s}");
        }
        for s in ["", "Widget", "-x", "_x", "a/b", "..", "a.b", "a b"] {
            assert!(s.parse::<ProjectName>().is_err(), "{s:?}");
        }
        assert!("a".repeat(65).parse::<EnvName>().is_err());
    }

    #[test]
    fn names_round_trip_through_serde_with_validation() {
        let k: KeyName = serde_json::from_str("\"API_KEY\"").unwrap();
        assert_eq!(serde_json::to_string(&k).unwrap(), "\"API_KEY\"");
        assert!(serde_json::from_str::<KeyName>("\"not a key\"").is_err());
    }

    #[test]
    fn name_errors_do_not_echo_input() {
        let input = "sk_live_DO_NOT_ECHO value";
        let err = input.parse::<KeyName>().unwrap_err().to_string();
        assert!(!err.contains("sk_live"), "{err}");
    }

    #[test]
    fn origin_display() {
        let o = Origin::new(Provider::AwsSm, "widget/dev/shared");
        assert_eq!(o.to_string(), "aws_sm:widget/dev/shared");
        assert_eq!(
            serde_json::to_value(&o).unwrap(),
            serde_json::json!({"provider": "aws_sm", "location": "widget/dev/shared"})
        );
    }
}
