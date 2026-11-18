//! Git remote URLs reduced to one canonical form, so that the different ways of
//! writing a repository's address compare equal.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// A normalized remote: the lowercase host, a slash, then the repository path,
/// e.g. `github.com/acme/widget`.
///
/// Scheme, user, password, port, query and fragment are dropped, so `git@github.com:acme/widget.git`,
/// `ssh://git@github.com:22/acme/widget` and `https://github.com/acme/widget/`
/// are all the same remote. The path keeps its case: only the host is
/// case-insensitive on every forge.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RemoteId(String);

/// Why a remote could not be normalized. Never echoes the input: remote URLs
/// can carry access tokens in their user part.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RemoteError {
    #[error("remote URL is empty")]
    Empty,
    #[error("remote URL contains whitespace or control characters")]
    BadChar,
    #[error("remote is a local path or file:// URL; only network remotes identify a project")]
    Local,
    #[error("remote URL scheme is not one of ssh, git+ssh, git, http or https")]
    UnsupportedScheme,
    #[error("remote URL has no host")]
    NoHost,
    #[error("remote URL has a port that is not a number")]
    BadPort,
    #[error("remote URL has no repository path")]
    NoPath,
    #[error("remote URL has an @ outside its user part; is a credential in the wrong place?")]
    StrayAt,
}

impl RemoteId {
    /// Normalizes a URL as git reports it. A scheme-less address without a
    /// colon before its first slash is a local path, as it is to git.
    pub fn from_url(url: &str) -> Result<Self, RemoteError> {
        if url.is_empty() {
            return Err(RemoteError::Empty);
        }
        if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(RemoteError::BadChar);
        }
        // A query or fragment names no repository and can carry a token.
        // Neither character can appear unencoded before them in a URL.
        let url = url.split(['?', '#']).next().unwrap_or_default();
        let (host, path) = match url.split_once("://") {
            Some((scheme, rest)) => {
                match scheme.to_ascii_lowercase().as_str() {
                    "ssh" | "git+ssh" | "ssh+git" | "git" | "http" | "https" => {}
                    "file" => return Err(RemoteError::Local),
                    _ => return Err(RemoteError::UnsupportedScheme),
                }
                let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
                (url_host(authority)?, path)
            }
            None => scp_like(url)?,
        };
        if host.is_empty() {
            return Err(RemoteError::NoHost);
        }
        let mut path = path
            .split('/')
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("/");
        if let Some(stripped) = path.strip_suffix(".git") {
            path = stripped.trim_end_matches('/').to_owned();
        }
        if path.is_empty() {
            return Err(RemoteError::NoPath);
        }
        // An `@` left in the host or path is a user part git did not read
        // as one, e.g. `user:token@host:path`, where the first colon ends
        // the host. Kept, it would put the credential in the id.
        if host.contains('@') || path.contains('@') {
            return Err(RemoteError::StrayAt);
        }
        Ok(Self(format!("{}/{path}", host.to_ascii_lowercase())))
    }

    /// Normalizes a remote written in a project file: any URL [`from_url`]
    /// accepts, or the canonical `host/path` form it produces, recognised by
    /// a host containing a dot or a bracketed address.
    ///
    /// [`from_url`]: RemoteId::from_url
    pub fn parse(s: &str) -> Result<Self, RemoteError> {
        match Self::from_url(s) {
            Err(RemoteError::Local) if !s.starts_with(['/', '.']) && !s.contains("://") => {
                let host = s.split('/').next().unwrap_or("");
                let bracketed = host.starts_with('[') && host.ends_with(']');
                if bracketed || (host.contains('.') && !host.contains(':')) {
                    Self::from_url(&format!("https://{s}"))
                } else {
                    Err(RemoteError::Local)
                }
            }
            other => other,
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The host of a URL authority `[user[:password]@]host[:port]`, where host
/// may be a bracketed IPv6 address.
fn url_host(authority: &str) -> Result<&str, RemoteError> {
    let hostport = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let (host, port) = split_host(hostport);
    match port {
        Some(p) if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) => {
            Err(RemoteError::BadPort)
        }
        _ => Ok(host),
    }
}

/// Splits `host[:rest]`, keeping a bracketed IPv6 host whole.
fn split_host(s: &str) -> (&str, Option<&str>) {
    if s.starts_with('[')
        && let Some(end) = s.find(']')
    {
        let (host, rest) = s.split_at(end + 1);
        return (host, rest.strip_prefix(':'));
    }
    match s.split_once(':') {
        Some((h, rest)) => (h, Some(rest)),
        None => (s, None),
    }
}

/// Git's scp-like syntax, `[user@]host:path`. Git treats an address as
/// scp-like when a colon comes before the first slash; anything else without
/// a scheme is a local path.
fn scp_like(url: &str) -> Result<(&str, &str), RemoteError> {
    let colon = url.find(':');
    let slash = url.find('/');
    let is_scp = match (colon, slash) {
        (Some(c), Some(s)) => c < s,
        (Some(_), None) => true,
        (None, _) => false,
    };
    // A bracketed IPv6 host contains colons of its own.
    let is_scp = is_scp || url.contains("@[") || url.starts_with('[');
    if !is_scp || url.starts_with('.') {
        return Err(RemoteError::Local);
    }
    let after_user = match url.find('@') {
        Some(at) if colon.is_none_or(|c| at < c) || url[at..].starts_with("@[") => &url[at + 1..],
        _ => url,
    };
    match split_host(after_user) {
        (host, Some(path)) => Ok((host, path)),
        (_, None) => Err(RemoteError::Local),
    }
}

impl TryFrom<String> for RemoteId {
    type Error = RemoteError;
    fn try_from(s: String) -> Result<Self, RemoteError> {
        Self::parse(&s)
    }
}

impl FromStr for RemoteId {
    type Err = RemoteError;
    fn from_str(s: &str) -> Result<Self, RemoteError> {
        Self::parse(s)
    }
}

impl From<RemoteId> for String {
    fn from(r: RemoteId) -> String {
        r.0
    }
}

impl fmt::Display for RemoteId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{Canary, assert_no_canary};

    #[test]
    fn normalization_table() {
        let cases: &[(&str, &str)] = &[
            // scp-like
            ("git@github.com:acme/widget.git", "github.com/acme/widget"),
            ("git@github.com:acme/widget", "github.com/acme/widget"),
            ("github.com:acme/widget.git", "github.com/acme/widget"),
            ("git@GitHub.com:acme/widget.git", "github.com/acme/widget"),
            ("git@github.com:/acme/widget.git/", "github.com/acme/widget"),
            (
                "org-123@ssh.dev.example:team/widget",
                "ssh.dev.example/team/widget",
            ),
            ("git@[::1]:acme/widget.git", "[::1]/acme/widget"),
            // ssh://
            (
                "ssh://git@github.com/acme/widget.git",
                "github.com/acme/widget",
            ),
            (
                "ssh://git@github.com:22/acme/widget",
                "github.com/acme/widget",
            ),
            ("ssh://github.com/acme/widget", "github.com/acme/widget"),
            (
                "git+ssh://git@github.com/acme/widget.git",
                "github.com/acme/widget",
            ),
            (
                "ssh+git://git@github.com/acme/widget.git",
                "github.com/acme/widget",
            ),
            (
                "SSH://git@github.com/acme/widget.git",
                "github.com/acme/widget",
            ),
            ("ssh://git@[::1]:2222/acme/widget", "[::1]/acme/widget"),
            (
                "ssh://git@host.example/~alice/widget.git",
                "host.example/~alice/widget",
            ),
            // https and http
            ("https://github.com/acme/widget", "github.com/acme/widget"),
            (
                "https://github.com/acme/widget.git",
                "github.com/acme/widget",
            ),
            (
                "https://github.com/acme/widget.git/",
                "github.com/acme/widget",
            ),
            ("https://github.com/acme/widget/", "github.com/acme/widget"),
            ("https://github.com//acme//widget", "github.com/acme/widget"),
            (
                "https://alice@github.com/acme/widget",
                "github.com/acme/widget",
            ),
            (
                "https://alice:pw@github.com/acme/widget",
                "github.com/acme/widget",
            ),
            ("http://GITHUB.COM/acme/widget", "github.com/acme/widget"),
            (
                "https://github.com:443/acme/widget",
                "github.com/acme/widget",
            ),
            // git://
            ("git://github.com/acme/widget.git", "github.com/acme/widget"),
            // Nested groups and non-default ports on a self-hosted forge.
            (
                "ssh://git@gitlab.example.com:2222/group/sub/widget.git",
                "gitlab.example.com/group/sub/widget",
            ),
            (
                "https://gitlab.example.com:8443/group/sub/widget",
                "gitlab.example.com/group/sub/widget",
            ),
            (
                "git@gitlab.example.com:group/sub/widget.git",
                "gitlab.example.com/group/sub/widget",
            ),
            // The path keeps its case.
            ("git@github.com:Acme/Widget.git", "github.com/Acme/Widget"),
            // Only one trailing .git is removed.
            (
                "https://github.com/acme/widget.git.git",
                "github.com/acme/widget.git",
            ),
        ];
        for (input, want) in cases {
            let got = RemoteId::from_url(input).unwrap_or_else(|e| panic!("{input}: {e}"));
            assert_eq!(got.as_str(), *want, "{input}");
        }
    }

    #[test]
    fn spellings_of_one_repo_are_equal() {
        let a: RemoteId = "git@github.com:acme/widget.git".parse().unwrap();
        let b: RemoteId = "https://github.com/acme/widget".parse().unwrap();
        assert_eq!(a, b);
        let c: RemoteId = "https://github.com/acme/widget2".parse().unwrap();
        assert_ne!(a, c);
    }

    #[test]
    fn rejects() {
        let cases: &[(&str, RemoteError)] = &[
            ("", RemoteError::Empty),
            ("https://github.com/acme/my widget", RemoteError::BadChar),
            ("https://github.com/acme/widget\n", RemoteError::BadChar),
            ("/srv/git/widget.git", RemoteError::Local),
            ("../widget", RemoteError::Local),
            ("./widget:x", RemoteError::Local),
            ("widget", RemoteError::Local),
            ("srv/git:widget", RemoteError::Local),
            ("file:///srv/git/widget.git", RemoteError::Local),
            ("ftp://example.com/widget", RemoteError::UnsupportedScheme),
            ("https:///acme/widget", RemoteError::NoHost),
            ("https://alice@/acme/widget", RemoteError::NoHost),
            (":acme/widget", RemoteError::NoHost),
            ("git@:acme/widget", RemoteError::NoHost),
            ("ssh://git@github.com:acme/widget.git", RemoteError::BadPort),
            (
                "ssh://git@github.com:/acme/widget.git",
                RemoteError::BadPort,
            ),
            ("https://github.com", RemoteError::NoPath),
            ("https://github.com/", RemoteError::NoPath),
            ("https://github.com/.git", RemoteError::NoPath),
            ("git@github.com:", RemoteError::NoPath),
            ("git@github.com:.git", RemoteError::NoPath),
        ];
        for (input, want) in cases {
            assert_eq!(RemoteId::from_url(input), Err(want.clone()), "{input:?}");
        }
    }

    #[test]
    fn credentials_are_dropped_and_never_echoed() {
        let token = Canary::new();
        let ok = format!(
            "https://x-access-token:{}@github.com/acme/widget.git",
            token.value()
        );
        let id = RemoteId::from_url(&ok).unwrap();
        assert_no_canary(&token, &id.to_string());
        assert_no_canary(&token, &format!("{id:?}"));

        // Queries and fragments are dropped, so the id matches the repo.
        let t = token.value();
        for ok in [
            format!("https://github.com/acme/widget.git?access_token={t}"),
            format!("https://github.com/acme/widget#{t}"),
            format!("https://github.com/acme/widget?a=1#{t}"),
            format!("git@github.com:acme/widget.git?{t}"),
            format!("https://github.com?{t}/acme/widget"),
        ] {
            match RemoteId::from_url(&ok) {
                Ok(id) => {
                    assert_no_canary(&token, &id.to_string());
                    assert_no_canary(&token, &format!("{id:?}"));
                }
                Err(err) => assert_no_canary(&token, &err.to_string()),
            }
        }
        assert_eq!(
            RemoteId::from_url(&format!("https://github.com/acme/widget.git?x={t}#y"))
                .unwrap()
                .as_str(),
            "github.com/acme/widget"
        );

        for bad in [
            format!("https://x:{t}@github.com"),
            format!("https://x:{t}@github.com:notaport/a"),
            format!("ftp://x:{t}@github.com/a"),
            format!("https://x:{t} @github.com/a"),
            // A user part git does not read as one.
            format!("x:{t}@github.com:acme/widget"),
            format!("https://x/{t}@github.com/acme/widget"),
            format!("a@{t}@github.com:acme/widget"),
            format!("https://x:{t}#@github.com/acme/widget"),
        ] {
            let err = RemoteId::from_url(&bad).unwrap_err();
            assert_no_canary(&token, &err.to_string());
            assert_no_canary(&token, &format!("{err:?}"));
            let err = RemoteId::parse(&bad).unwrap_err();
            assert_no_canary(&token, &err.to_string());
        }
        assert_eq!(
            RemoteId::from_url(&format!("x:{t}@github.com:acme/widget")),
            Err(RemoteError::StrayAt)
        );
    }

    #[test]
    fn canonical_form_parses_back_in_config_only() {
        for url in [
            "git@github.com:acme/widget.git",
            "ssh://git@[::1]:2222/acme/widget",
            "https://gitlab.example.com/group/sub/widget",
        ] {
            let id = RemoteId::from_url(url).unwrap();
            assert_eq!(RemoteId::parse(id.as_str()).unwrap(), id, "{url}");
            // To git, the same string is a relative local path.
            assert_eq!(RemoteId::from_url(id.as_str()), Err(RemoteError::Local));
        }
        assert_eq!(
            RemoteId::parse("GitHub.com/acme/widget.git")
                .unwrap()
                .as_str(),
            "github.com/acme/widget"
        );
        for local in [
            "srv/git/widget",
            "/srv/git/widget",
            "./a.b/widget",
            "widget",
        ] {
            assert!(RemoteId::parse(local).is_err(), "{local}");
        }
    }

    #[test]
    fn serde_normalizes() {
        #[derive(Deserialize, Serialize)]
        struct T {
            r: RemoteId,
        }
        let t: T = toml::from_str(r#"r = "git@GitHub.com:acme/widget.git""#).unwrap();
        assert_eq!(t.r.as_str(), "github.com/acme/widget");
        assert_eq!(
            toml::to_string(&t).unwrap().trim(),
            r#"r = "github.com/acme/widget""#
        );
        assert!(toml::from_str::<T>(r#"r = "/srv/widget""#).is_err());
    }
}
