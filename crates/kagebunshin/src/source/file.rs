//! The `file` provider: sections of the local store, read from the copy the
//! daemon decrypted at unlock.
//!
//! A secret is a section name, `<project>.<env>`, and its keys become keys.
//! `secret` reads one section, `secrets` several in order, `prefix` every
//! section whose name starts with it, in name order. A bare `provider =
//! "file"` source, with none of the three, reads the environment's own
//! `[<project>.<env>]` section (filled in by `Registry::env`). `key` has no
//! meaning here (a section is already a set of keys) and is refused.
//!
//! Every section a source would read, a prefix's included, is checked for
//! sensitivity before any is read; a `prod`, `production` or `rc` dot
//! segment covers the `<project>.<env>` section of a production or
//! release-candidate environment.

use std::sync::Arc;

use async_trait::async_trait;

use super::{Backend, Entry, Health, Listed, ProviderStatus, Source, SourceError};
use crate::config::{Select, SourceSpec};
use crate::secret::SecretValue;
use crate::store::{Section, Store};
use crate::types::{Origin, Provider};

pub struct FileSource {
    /// `None` when there was no store at unlock.
    store: Option<Arc<Store>>,
    select: Select,
    optional: bool,
    /// See [`SourceSpec::missing_is_empty`].
    missing_is_empty: bool,
}

impl FileSource {
    pub fn new(store: Option<Arc<Store>>, select: Select, optional: bool) -> Self {
        Self {
            store,
            select,
            optional,
            missing_is_empty: false,
        }
    }

    /// Reads a section not in the store as empty instead of failing.
    pub fn with_missing_is_empty(mut self, missing_is_empty: bool) -> Self {
        self.missing_is_empty = missing_is_empty;
        self
    }

    fn store(&self) -> Result<&Store, SourceError> {
        self.store.as_deref().ok_or_else(|| SourceError::NoStore {
            what: self.describe(),
        })
    }

    fn parse(&self, name: &str) -> Result<Section, SourceError> {
        name.parse::<Section>().map_err(|e| SourceError::Provider {
            what: self.describe(),
            message: format!("{name} is not a store section: {e}"),
        })
    }

    fn sections(&self, store: &Store) -> Result<Vec<Section>, SourceError> {
        let parse = |name: &str| self.parse(name);
        match &self.select {
            Select::Secret { key: Some(_), .. } => Err(SourceError::Provider {
                what: self.describe(),
                message: "`key` cannot be used with the file provider; a section is already a set of keys".into(),
            }),
            Select::Secret { name, key: None } => Ok(vec![parse(name)?]),
            Select::Secrets(names) => names.iter().map(|n| parse(n)).collect(),
            Select::Prefix(p) => {
                let found: Vec<Section> = store
                    .sections()
                    .map(|(s, _)| s)
                    .filter(|s| s.to_string().starts_with(p.as_str()))
                    .cloned()
                    .collect();
                if found.is_empty() && !self.optional {
                    return Err(SourceError::NoMatch {
                        what: self.describe(),
                    });
                }
                Ok(found)
            }
        }
    }
}

/// The local store, as the daemon decrypted it at unlock.
pub struct FileBackend {
    /// `None` when there was no store at unlock.
    store: Option<Arc<Store>>,
}

impl FileBackend {
    pub fn new(store: Option<Arc<Store>>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl Backend for FileBackend {
    fn provider(&self) -> Provider {
        Provider::File
    }

    /// Sections and their key names.
    async fn list(&self, prefix: &str) -> Result<Vec<Listed>, SourceError> {
        let store = self.store.as_deref().ok_or_else(|| SourceError::NoStore {
            what: "file".into(),
        })?;
        Ok(store
            .sections()
            .map(|(s, keys)| (s.to_string(), keys))
            .filter(|(name, _)| name.starts_with(prefix))
            .map(|(name, keys)| Listed {
                id: Origin::new(Provider::File, name.clone()),
                name,
                title: None,
                keys: keys.keys().cloned().collect(),
                plain: false,
                unread: None,
            })
            .collect())
    }

    async fn status(&self) -> ProviderStatus {
        let health = match self.store {
            Some(_) => Health::Ok,
            None => Health::NotConnected {
                hint: "create it with `kagebunshin store init`".into(),
            },
        };
        ProviderStatus {
            provider: Provider::File,
            detail: "local store".into(),
            health,
            expires: None,
        }
    }

    fn source(&self, spec: &SourceSpec) -> Box<dyn Source> {
        Box::new(
            FileSource::new(self.store.clone(), spec.select.clone(), spec.optional)
                .with_missing_is_empty(spec.missing_is_empty),
        )
    }
}

#[async_trait]
impl Source for FileSource {
    fn describe(&self) -> String {
        let (kind, what) = match &self.select {
            Select::Secret { name, .. } => ("secret", name.clone()),
            Select::Secrets(names) => ("secrets", names.join(",")),
            Select::Prefix(p) => ("prefix", p.clone()),
        };
        format!("file {kind} {what}")
    }

    /// Section names; a prefix's are the store's matching sections.
    async fn names(&self) -> Result<Vec<String>, SourceError> {
        let store = self.store()?;
        Ok(self
            .sections(store)?
            .iter()
            .map(Section::to_string)
            .collect())
    }

    async fn fetch(&self, names: &[String]) -> Result<Vec<Entry>, SourceError> {
        let store = self.store()?;
        let mut out = Vec::new();
        for name in names {
            let section = self.parse(name)?;
            let keys = match store.section(&section) {
                Some(keys) => keys,
                None if self.missing_is_empty => continue,
                None => {
                    return Err(SourceError::NoSection {
                        name: section.to_string(),
                    });
                }
            };
            for (key, value) in keys {
                out.push(Entry {
                    key: key.clone(),
                    // The environment owns its values, so the store's copy
                    // stays and this one is zeroed with the environment.
                    value: SecretValue::new(value.expose().to_owned()),
                    origin: Origin::new(Provider::File, section.to_string()),
                });
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::ReadAll;
    use crate::store::Change;
    use crate::test_support::{Canary, assert_no_canary};

    fn store(c: &Canary) -> Arc<Store> {
        let mut st = Store::default();
        for (s, k) in [
            ("widget.dev", "A"),
            ("widget.dev", "B"),
            ("widget.qa", "A"),
            ("other.dev", "Z"),
        ] {
            let change = st.set(
                s.parse().unwrap(),
                k.parse().unwrap(),
                SecretValue::new(format!("{}-{s}-{k}", c.value())),
            );
            assert_eq!(change, Change::Added);
        }
        Arc::new(st)
    }

    fn secret(name: &str) -> Select {
        Select::Secret {
            name: name.into(),
            key: None,
        }
    }

    async fn keys(src: FileSource) -> Vec<(String, String)> {
        src.read_all()
            .await
            .unwrap()
            .into_iter()
            .map(|e| (e.key.to_string(), e.origin.to_string()))
            .collect()
    }

    #[tokio::test]
    async fn reads_sections() {
        let c = Canary::new();
        let st = store(&c);
        let one = FileSource::new(Some(st.clone()), secret("widget.dev"), false);
        let entries = one.read_all().await.unwrap();
        assert_eq!(
            entries[0].value.expose(),
            format!("{}-widget.dev-A", c.value())
        );
        assert_eq!(
            keys(one).await,
            [
                ("A".into(), "file:widget.dev".into()),
                ("B".into(), "file:widget.dev".into())
            ]
        );

        let many = Select::Secrets(vec!["widget.qa".into(), "other.dev".into()]);
        let got = keys(FileSource::new(Some(st.clone()), many, false)).await;
        assert_eq!(
            got,
            [
                ("A".into(), "file:widget.qa".into()),
                ("Z".into(), "file:other.dev".into())
            ]
        );

        let prefix = Select::Prefix("widget.".into());
        let got = keys(FileSource::new(Some(st), prefix, false)).await;
        let origins: Vec<&str> = got.iter().map(|(_, o)| o.as_str()).collect();
        assert_eq!(
            origins,
            ["file:widget.dev", "file:widget.dev", "file:widget.qa"]
        );
    }

    #[tokio::test]
    async fn failures_name_sections_not_values() {
        let c = Canary::new();
        let st = store(&c);
        let cases = [
            (None, secret("widget.dev"), false, "no local store"),
            (
                Some(st.clone()),
                secret("widget.prod"),
                false,
                "[widget.prod]",
            ),
            (
                Some(st.clone()),
                secret("widget"),
                false,
                "not a store section",
            ),
            (
                Some(st.clone()),
                Select::Secret {
                    name: "widget.dev".into(),
                    key: Some("A".parse().unwrap()),
                },
                false,
                "`key` cannot be used",
            ),
            (
                Some(st.clone()),
                Select::Prefix("nope.".into()),
                false,
                "matched no secrets",
            ),
        ];
        for (store, select, optional, want) in cases {
            let err = FileSource::new(store, select, optional)
                .read_all()
                .await
                .unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains(want), "{msg}");
            assert_no_canary(&c, &msg);
            assert_no_canary(&c, &format!("{err:?}"));
        }
        let optional = FileSource::new(Some(st), Select::Prefix("nope.".into()), true);
        assert!(optional.read_all().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_default_source_reads_a_missing_section_as_empty() {
        let c = Canary::new();
        let st = store(&c);
        let default = FileSource::new(Some(st.clone()), secret("widget.prod"), false)
            .with_missing_is_empty(true);
        assert!(default.read_all().await.unwrap().is_empty());
        // Only a missing section: a section that is there is read as usual,
        // and no store at all still fails.
        let there =
            FileSource::new(Some(st), secret("widget.dev"), false).with_missing_is_empty(true);
        assert_eq!(there.read_all().await.unwrap().len(), 2);
        let no_store =
            FileSource::new(None, secret("widget.dev"), false).with_missing_is_empty(true);
        assert!(matches!(
            no_store.read_all().await,
            Err(SourceError::NoStore { .. })
        ));
    }

    #[tokio::test]
    async fn backend_lists_sections_with_their_keys() {
        let c = Canary::new();
        let backend = FileBackend::new(Some(store(&c)));
        let listed = backend.list("widget.").await.unwrap();
        let got: Vec<(String, String, Vec<String>)> = listed
            .iter()
            .map(|l| {
                let keys = l.keys.iter().map(ToString::to_string).collect();
                (l.id.to_string(), l.name.clone(), keys)
            })
            .collect();
        assert_eq!(
            got,
            [
                (
                    "file:widget.dev".into(),
                    "widget.dev".into(),
                    vec!["A".into(), "B".into()]
                ),
                (
                    "file:widget.qa".into(),
                    "widget.qa".into(),
                    vec!["A".into()]
                ),
            ]
        );
        assert_no_canary(&c, &format!("{listed:?}"));
        assert_eq!(backend.status().await.health, Health::Ok);

        let none = FileBackend::new(None);
        assert!(matches!(
            none.status().await.health,
            Health::NotConnected { .. }
        ));
        assert!(matches!(
            none.list("").await,
            Err(SourceError::NoStore { .. })
        ));
    }
}
