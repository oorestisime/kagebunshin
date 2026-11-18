//! Secrets that more than one environment reads.
//!
//! A secret's sensitive mark holds in every environment that reads it. So
//! marking an environment sensitive does not mark a secret that an open
//! environment reads too: that would make the open one ask for approval,
//! which nobody decided. Open means neither marked sensitive nor waiting
//! for a human decision.
//!
//! Three things hold whatever is shared. A secret whose name looks like
//! production is marked with any environment that reads it: otherwise an
//! agent could add it to an open environment before a human marks the one
//! it belongs to. A mark that is there stays; only a human removes one.
//! And a human may mark a shared secret all the same, when marking the
//! environment or later.
//!
//! All of it is decided from what the project files name, without asking a
//! provider: a secret an environment reads only under a prefix is shared
//! with one that reads the same prefix or a wider one, not with one that
//! names it.

use std::collections::BTreeSet;

use crate::config::{Registry, Select, SourcePattern, SourceSpec};
use crate::ipc::protocol::{SharedSecret, WaitingEnv};
use crate::source::stable_origin;
use crate::store::{Section, Store};
use crate::types::{Origin, Provider};

use super::resolve::{prod_like, secret_marked};

/// What a source reads, as its project file names it: one secret, by its
/// stable id, or with `prefix` everything under one.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Claim {
    pub origin: Origin,
    pub prefix: bool,
}

impl Claim {
    pub fn named(provider: Provider, name: &str) -> Self {
        Self {
            origin: stable_origin(provider, name),
            prefix: false,
        }
    }

    pub fn under(provider: Provider, prefix: &str) -> Self {
        Self {
            origin: Origin::new(provider, prefix),
            prefix: true,
        }
    }

    /// What `spec` reads, in the order it names them.
    pub fn of(spec: &SourceSpec) -> Vec<Self> {
        match &spec.select {
            Select::Prefix(p) => vec![Self::under(spec.provider, p)],
            select => select
                .locations()
                .into_iter()
                .map(|n| Self::named(spec.provider, n))
                .collect(),
        }
    }

    /// Whether a source that reads `self` reads all of `other`.
    fn covers(&self, other: &Self) -> bool {
        let (mine, theirs) = (&self.origin, &other.origin);
        mine.provider == theirs.provider
            && if self.prefix {
                theirs.location.starts_with(mine.location.as_str())
            } else {
                !other.prefix && mine.location == theirs.location
            }
    }
}

/// What each environment of each project reads, in name order.
fn claims(registry: &Registry) -> Vec<(Section, Vec<Claim>)> {
    let mut out = Vec::new();
    for project in registry.projects() {
        for env in project.file.envs.keys() {
            let Ok(settings) = registry.env(project, Some(env)) else {
                continue;
            };
            let section = Section {
                project: project.name.clone(),
                env: env.clone(),
            };
            let claims = settings.sources.iter().flat_map(Claim::of).collect();
            out.push((section, claims));
        }
    }
    out
}

/// Whether `section` is open in `store`: not marked sensitive, and not one
/// of the `waiting`.
fn is_open(section: &Section, store: Option<&Store>, waiting: &[WaitingEnv]) -> bool {
    !store.is_some_and(|st| st.env_marked(&section.project, &section.env))
        && !waiting
            .iter()
            .any(|w| w.project == section.project && w.env == section.env)
}

/// Decides, for marking one environment sensitive, what of its sources is
/// left unmarked because an open environment reads it too.
#[derive(Debug, Default)]
pub struct Sharing {
    /// What the open environments read, the one being marked aside.
    open: Vec<Claim>,
    extra: Vec<SourcePattern>,
    /// What a human asked to mark all the same.
    also: Vec<Origin>,
}

impl Sharing {
    /// For marking `marking`, with the environments `waiting` for a
    /// decision and the marks in `store` as they are now.
    pub fn new(
        registry: &Registry,
        store: Option<&Store>,
        waiting: &[WaitingEnv],
        marking: &Section,
        also: Vec<Origin>,
    ) -> Self {
        let open = claims(registry)
            .into_iter()
            .filter(|(section, _)| section != marking && is_open(section, store, waiting))
            .flat_map(|(_, claims)| claims)
            .collect();
        Self {
            open,
            extra: registry.config.sensitive_source_patterns.clone(),
            also,
        }
    }

    /// Whether `claim` is left unmarked: an open environment reads all of
    /// it, its name does not look like production, and no human asked for
    /// it.
    pub fn leaves(&self, claim: &Claim) -> bool {
        !self.also.contains(&claim.origin)
            && prod_like(&claim.origin.location, &self.extra).is_none()
            && self.open.iter().any(|c| c.covers(claim))
    }
}

/// Whether `claim` is marked sensitive in `store` now, as far as that can
/// be told without a provider: a store section when its environment is
/// marked or every key in it is, a prefix when it is marked, and any other
/// secret by [`secret_marked`].
fn marked(store: Option<&Store>, claim: &Claim) -> bool {
    let at = &claim.origin;
    match (at.provider, claim.prefix) {
        (Provider::File, true) => false,
        (Provider::File, false) => store.is_some_and(|st| {
            at.location.parse::<Section>().is_ok_and(|section| {
                st.env_marked(&section.project, &section.env)
                    || st.sections().any(|(s, keys)| {
                        *s == section
                            && !keys.is_empty()
                            && keys.keys().all(|k| st.is_sensitive(s, k))
                    })
            })
        }),
        (_, true) => store.is_some_and(|st| {
            st.marked_prefixes()
                .any(|p| p.provider == at.provider && at.location.starts_with(&p.location))
        }),
        (_, false) => secret_marked(store, at),
    }
}

/// Every secret that more than one environment reads, once for each
/// environment that reads it: environments in name order, the secrets of
/// each in the order its sources name them. An environment's own store
/// section is not listed for it: its mark covers that section wherever it
/// is read.
pub fn shared_secrets(
    registry: &Registry,
    store: Option<&Store>,
    waiting: &[WaitingEnv],
) -> Vec<SharedSecret> {
    let all = claims(registry);
    let extra = &registry.config.sensitive_source_patterns;
    let mut out = Vec::new();
    for (section, mine) in &all {
        let own = Claim::named(Provider::File, &section.to_string());
        let mut seen = BTreeSet::new();
        for claim in mine.iter().filter(|c| **c != own && seen.insert(*c)) {
            let with: Vec<Section> = all
                .iter()
                .filter(|(other, theirs)| {
                    other != section && theirs.iter().any(|c| c.covers(claim))
                })
                .map(|(other, _)| other.clone())
                .collect();
            if with.is_empty() {
                continue;
            }
            let open = with
                .iter()
                .filter(|s| is_open(s, store, waiting))
                .cloned()
                .collect();
            out.push(SharedSecret {
                project: section.project.clone(),
                env: section.env.clone(),
                secret: claim.origin.clone(),
                prefix: claim.prefix,
                with,
                open,
                sensitive: marked(store, claim),
                production: prod_like(&claim.origin.location, extra).is_some(),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::config::{Config, parse_project};

    /// A registry of one project, `app`, with the environments `envs`.
    fn registry_of(envs: &str) -> Registry {
        let toml = format!("schema = 1\nremotes = [\"git@github.com:acme/app.git\"]\n{envs}");
        let p = parse_project(Path::new("/cfg/projects/app.toml"), &toml).unwrap();
        Registry::new(Config::default(), vec![p]).unwrap()
    }

    fn section(s: &str) -> Section {
        s.parse().unwrap()
    }

    fn waits(project: &str, env: &str) -> WaitingEnv {
        WaitingEnv {
            project: project.parse().unwrap(),
            env: env.parse().unwrap(),
            why: "its name has the segment prod".into(),
        }
    }

    const APP: &str = r#"
        [envs.dev]
        sources = [
          { provider = "aws_sm", secrets = ["mail", "app/dev/db"] },
          { provider = "aws_sm", prefix = "tools/" },
          { provider = "file", secret = "app.dev" },
        ]

        [envs.prod]
        sources = [
          { provider = "aws_sm", secrets = ["mail", "app/prod/db", "ledger"] },
          { provider = "aws_sm", secret = "tools/ci" },
          { provider = "aws_sm", prefix = "tools/" },
          { provider = "file", secret = "app.dev" },
        ]
    "#;

    #[test]
    fn a_secret_is_shared_with_each_other_environment_that_reads_all_of_it() {
        let registry = registry_of(APP);
        let shared = shared_secrets(&registry, None, &[waits("app", "prod")]);
        let of = |env: &str| -> Vec<(String, bool, Vec<String>, bool)> {
            shared
                .iter()
                .filter(|s| s.env.as_str() == env)
                .map(|s| {
                    (
                        s.secret.to_string(),
                        s.prefix,
                        s.open.iter().map(ToString::to_string).collect(),
                        s.stays_unmarked(),
                    )
                })
                .collect()
        };
        // prod: the secret both name, the one dev's prefix covers, the
        // prefix both read, and dev's own store section.
        assert_eq!(
            of("prod"),
            [
                (
                    "aws_sm:mail".to_owned(),
                    false,
                    vec!["app.dev".to_owned()],
                    true
                ),
                (
                    "aws_sm:tools/ci".to_owned(),
                    false,
                    vec!["app.dev".to_owned()],
                    true
                ),
                (
                    "aws_sm:tools/".to_owned(),
                    true,
                    vec!["app.dev".to_owned()],
                    true
                ),
                (
                    "file:app.dev".to_owned(),
                    false,
                    vec!["app.dev".to_owned()],
                    true
                ),
            ]
        );
        // dev: the same, less its own section; prod waits, so it is not
        // open, and marking dev would mark them.
        assert_eq!(
            of("dev"),
            [
                ("aws_sm:mail".to_owned(), false, vec![], false),
                ("aws_sm:tools/".to_owned(), true, vec![], false),
            ]
        );
        assert!(shared.iter().all(|s| !s.sensitive && !s.production));
        assert_eq!(shared[0].with, [section("app.prod")]);
    }

    #[test]
    fn marking_leaves_what_an_open_environment_reads() {
        let registry = registry_of(APP);
        let waiting = [waits("app", "prod")];
        let sharing = Sharing::new(&registry, None, &waiting, &section("app.prod"), Vec::new());
        let aws = |n: &str| Claim::named(Provider::AwsSm, n);
        assert!(sharing.leaves(&aws("mail")));
        assert!(sharing.leaves(&aws("tools/ci")));
        assert!(sharing.leaves(&Claim::under(Provider::AwsSm, "tools/")));
        assert!(sharing.leaves(&Claim::named(Provider::File, "app.dev")));
        // Only prod reads these.
        assert!(!sharing.leaves(&aws("ledger")));
        assert!(!sharing.leaves(&aws("app/prod/db")));
        // A wider prefix than the open one reads is not all read by it.
        assert!(!sharing.leaves(&Claim::under(Provider::AwsSm, "tool")));
        // Another provider's secret of the same name is another secret.
        assert!(!sharing.leaves(&Claim::named(Provider::Proton, "mail")));

        // Marking dev: prod waits for a decision, so it does not count.
        let sharing = Sharing::new(&registry, None, &waiting, &section("app.dev"), Vec::new());
        assert!(!sharing.leaves(&aws("mail")));
        // Decided as not production, it would.
        let sharing = Sharing::new(&registry, None, &[], &section("app.dev"), Vec::new());
        assert!(sharing.leaves(&aws("mail")));
    }

    #[test]
    fn a_shared_secret_named_like_production_or_asked_for_is_marked() {
        let both = r#"
            [envs.dev]
            sources = [{ provider = "aws_sm", secrets = ["prod/db", "mail", "arn:aws:secretsmanager:eu-west-1:123456789012:secret:billing-AbCdEf"] }]

            [envs.live]
            sources = [{ provider = "aws_sm", secrets = ["prod/db", "mail", "billing"] }]
        "#;
        let registry = registry_of(both);
        let live = section("app.live");
        let aws = |n: &str| Claim::named(Provider::AwsSm, n);
        let sharing = Sharing::new(&registry, None, &[], &live, Vec::new());
        assert!(!sharing.leaves(&aws("prod/db")));
        assert!(sharing.leaves(&aws("mail")));
        // An ARN and a name are one secret.
        assert!(sharing.leaves(&aws("billing")));

        let also = vec![Origin::new(Provider::AwsSm, "mail")];
        let sharing = Sharing::new(&registry, None, &[], &live, also);
        assert!(!sharing.leaves(&aws("mail")));
        assert!(sharing.leaves(&aws("billing")));

        let shared = shared_secrets(&registry, None, &[]);
        let db = shared
            .iter()
            .find(|s| s.env.as_str() == "live" && s.secret.location == "prod/db")
            .unwrap();
        assert!(db.production && !db.stays_unmarked());
    }

    #[test]
    fn a_marked_environment_is_not_open_and_shows_what_is_marked() {
        let registry = registry_of(APP);
        let mut store = Store::default();
        store.mark_env(section("app.dev"), true);
        store
            .mark_secret(Origin::new(Provider::AwsSm, "mail"), true)
            .unwrap();
        store
            .mark_prefix(Origin::new(Provider::AwsSm, "tools/"))
            .unwrap();
        let waiting = [waits("app", "prod")];
        let shared = shared_secrets(&registry, Some(&store), &waiting);
        assert!(shared.iter().all(|s| s.open.is_empty()));
        let marked: Vec<_> = shared
            .iter()
            .filter(|s| s.env.as_str() == "prod")
            .map(|s| (s.secret.location.as_str(), s.sensitive))
            .collect();
        assert_eq!(
            marked,
            [
                ("mail", true),
                ("tools/ci", true),
                ("tools/", true),
                // dev's own section: dev's mark covers it.
                ("app.dev", true),
            ]
        );
        let sharing = Sharing::new(
            &registry,
            Some(&store),
            &waiting,
            &section("app.prod"),
            Vec::new(),
        );
        assert!(!sharing.leaves(&Claim::named(Provider::AwsSm, "mail")));
    }
}
