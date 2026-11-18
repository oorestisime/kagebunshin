//! The projects, environments and sources the window lists, read from the
//! configuration directory the way the CLI reads it. Names and locations
//! only: the configuration holds no values.

use std::path::{Path, PathBuf};

use kagebunshin::config::{ConfigDir, Git, Place, Registry, RemoteId, Select};
use kagebunshin::ipc::protocol::Facts;
use kagebunshin::repo;
use kagebunshin::types::{EnvName, KeyName, ProjectName};

use crate::daemon::Problem;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Catalog {
    /// In name order.
    pub projects: Vec<ProjectView>,
    /// Why the configuration could not be read; `projects` is empty then.
    pub problem: Option<Problem>,
    /// The checkout the window was opened in, if it is a project's.
    pub here: Option<Here>,
    /// Where the window runs, for the daemon's messages.
    pub cwd: PathBuf,
    /// The profile and region `connect aws` saved, which an AWS source
    /// that names none reads with.
    pub aws: (Option<String>, Option<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectView {
    pub name: ProjectName,
    pub remotes: Vec<RemoteId>,
    /// The folder of the checkout it is for; `None` for the whole repo.
    pub path: Option<String>,
    /// In name order.
    pub envs: Vec<EnvView>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvView {
    pub name: EnvName,
    /// The project's default environment.
    pub default: bool,
    /// In the order they apply: a later one wins.
    pub sources: Vec<SourceView>,
    /// The file lists no sources, so `sources` is the default one alone,
    /// which cannot be moved or removed.
    pub default_source: bool,
    /// Why its sources could not be settled; `sources` is empty then.
    pub problem: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceView {
    pub provider: &'static str,
    /// `secret`, `secrets` or `prefix`.
    pub select: &'static str,
    pub locations: Vec<String>,
    pub optional: bool,
    pub profile: Option<String>,
    pub region: Option<String>,
}

/// The project checkout the window was opened in, and its `.env.example`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Here {
    pub project: ProjectName,
    pub cwd: PathBuf,
    /// `cwd` relative to the checkout root; `None` at the root.
    pub subdir: Option<PathBuf>,
    /// `None` without a `.env.example`.
    pub example_keys: Option<Vec<KeyName>>,
    /// The env file in `cwd` that holds values, by name, if there is one.
    pub env_file: Option<String>,
}

impl Catalog {
    /// Reads `dir`, and finds the project checked out at `cwd`, if any.
    pub fn load(dir: &ConfigDir, cwd: &Path) -> Self {
        let registry = match Registry::load(dir) {
            Ok(r) => r,
            Err(e) => {
                return Self {
                    problem: Some(Problem::new(e.to_string())),
                    cwd: cwd.into(),
                    ..Self::default()
                };
            }
        };
        let projects = registry
            .projects()
            .map(|p| ProjectView {
                name: p.name.clone(),
                remotes: p.file.remotes.clone(),
                path: p.file.path.as_ref().map(|x| x.as_str().to_owned()),
                envs: p
                    .file
                    .envs
                    .iter()
                    .map(|(name, file)| {
                        let (sources, problem) = match registry.env(p, Some(name)) {
                            Ok(settings) => (settings.sources.iter().map(source).collect(), None),
                            Err(e) => (Vec::new(), Some(e.to_string())),
                        };
                        EnvView {
                            name: name.clone(),
                            default: *name == registry.config.default_env,
                            sources,
                            default_source: file.sources.is_empty(),
                            problem,
                        }
                    })
                    .collect(),
            })
            .collect();
        let aws = &registry.config.aws;
        Self {
            projects,
            problem: None,
            here: here(&registry, cwd),
            cwd: cwd.into(),
            aws: (
                aws.profile.as_ref().map(ToString::to_string),
                aws.region.as_ref().map(ToString::to_string),
            ),
        }
    }

    pub fn env(&self, project: &ProjectName, env: &EnvName) -> Option<(&ProjectView, &EnvView)> {
        let p = self.projects.iter().find(|p| p.name == *project)?;
        Some((p, p.envs.iter().find(|e| e.name == *env)?))
    }

    /// What the daemon needs to resolve `env` of `project`. Only the checkout
    /// the window was opened in has a `.env.example` to compare against.
    /// Always names the project: projects can share remotes, so the remotes
    /// alone do not say which one is shown.
    pub fn facts(&self, project: &ProjectView, env: &EnvName) -> Facts {
        let here = self.here.as_ref().filter(|h| h.project == project.name);
        Facts {
            cwd: here.map_or_else(|| self.cwd.clone(), |h| h.cwd.clone()),
            remotes: project.remotes.clone(),
            subdir: here.and_then(|h| h.subdir.clone()),
            // Named, so paths are not matched.
            root: None,
            project: Some(project.name.clone()),
            env: Some(env.clone()),
            example_keys: here.and_then(|h| h.example_keys.clone()),
            example_values: Vec::new(),
            env_file: here.and_then(|h| h.env_file.clone()),
        }
    }
}

fn source(s: &kagebunshin::config::SourceSpec) -> SourceView {
    let select = match s.select {
        Select::Secret { .. } => "secret",
        Select::Secrets(_) => "secrets",
        Select::Prefix(_) => "prefix",
    };
    SourceView {
        provider: s.provider.as_str(),
        select,
        locations: s
            .select
            .locations()
            .into_iter()
            .map(str::to_owned)
            .collect(),
        optional: s.optional,
        profile: s.aws.profile.as_ref().map(ToString::to_string),
        region: s.aws.region.as_ref().map(ToString::to_string),
    }
}

/// The project checked out at `cwd`, as the CLI finds it.
fn here(registry: &Registry, cwd: &Path) -> Option<Here> {
    let checkout = Git::default().checkout(cwd).ok()?;
    let subdir = checkout.subdir(cwd).filter(|d| !d.as_os_str().is_empty());
    let place = Place {
        subdir: subdir.as_deref(),
        root: Some(&checkout.root),
        ..Place::remotes(&checkout.remotes)
    };
    let project = registry.find(place).ok()?.project;
    let configured = project.file.env_example.as_deref();
    let top = project.file.path.as_ref().map(|p| p.as_path());
    let example = repo::load(&checkout.root, cwd, top, configured).ok()?;
    Some(Here {
        project: project.name.clone(),
        cwd: cwd.into(),
        subdir,
        example_keys: example.map(|f| f.example.keys),
        env_file: repo::env_file_with_values(cwd),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_projects_envs_and_sources_in_order() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = ConfigDir::new(tmp.path());
        std::fs::create_dir_all(dir.projects_dir()).unwrap();
        std::fs::write(
            dir.project_file(&"widget".parse().unwrap()),
            r#"
schema = 1
remotes = ["git@github.com:acme/widget.git"]
profile = "acme-dev"

[envs.dev]
[[envs.dev.sources]]
provider = "aws_sm"
prefix = "acme/dev/"
[[envs.dev.sources]]
provider = "file"
optional = true

[envs.prod]
"#,
        )
        .unwrap();
        let c = Catalog::load(&dir, tmp.path());
        assert_eq!(c.problem, None);
        assert_eq!(c.here, None);
        let (p, dev) = c
            .env(&"widget".parse().unwrap(), &"dev".parse().unwrap())
            .unwrap();
        assert!(dev.default);
        let names: Vec<_> = p.envs.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["dev", "prod"]);
        assert_eq!(
            dev.sources[0],
            SourceView {
                provider: "aws_sm",
                select: "prefix",
                locations: vec!["acme/dev/".into()],
                optional: false,
                profile: Some("acme-dev".into()),
                region: None,
            }
        );
        // A bare file source reads the env's own store section.
        assert_eq!(
            (
                dev.sources[1].provider,
                dev.sources[1].locations.clone(),
                dev.sources[1].optional
            ),
            ("file", vec!["widget.dev".to_owned()], true)
        );
        let prod = &p.envs[1];
        assert!(!prod.default);
        assert_eq!(prod.sources.len(), 1, "the default source");

        let facts = c.facts(p, &prod.name);
        assert_eq!(facts.env, Some(prod.name.clone()));
        assert_eq!(facts.remotes, p.remotes);
        assert_eq!(facts.example_keys, None);
    }

    #[test]
    fn a_broken_config_is_a_problem_not_a_panic() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = ConfigDir::new(tmp.path());
        std::fs::write(dir.config_file(), "not = [toml").unwrap();
        let c = Catalog::load(&dir, tmp.path());
        assert!(c.projects.is_empty());
        assert!(c.problem.is_some());
    }
}
