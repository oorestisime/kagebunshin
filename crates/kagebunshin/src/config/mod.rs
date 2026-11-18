//! The user's configuration: `config.toml`, one mapping file per project, and
//! matching a git checkout to its project.
//!
//! ```text
//! $KAGEBUNSHIN_CONFIG_DIR, else $XDG_CONFIG_HOME/kagebunshin, else ~/.config/kagebunshin
//! ├── config.toml          optional; see [`Config`]
//! ├── store.age          optional local store; see [`crate::store`]
//! └── projects/
//!     └── <name>.toml      one per project; see [`ProjectFile`]
//! ```
//!
//! The same layout is used on Linux and macOS.

pub mod git;
pub mod remote;
pub mod schema;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub use git::{Checkout, Git, GitError};
pub use remote::{RemoteError, RemoteId};
pub use schema::{
    AwsSettings, Config, EnvFile, Profile, ProjectFile, ProjectPath, Region, Select, SourceEntry,
    SourcePattern, SourceSpec,
};

use crate::types::{EnvName, KeyName, NameError, ProjectName, Provider};

pub const CONFIG_DIR_ENV: &str = "KAGEBUNSHIN_CONFIG_DIR";
pub const CONFIG_FILE: &str = "config.toml";
pub const PROJECTS_DIR: &str = "projects";
/// Held while a command edits the config; see [`ConfigDir::lock`].
pub const LOCK_FILE: &str = "config.lock";

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot find a config directory; set {CONFIG_DIR_ENV}, XDG_CONFIG_HOME or HOME")]
    NoConfigDir,
    #[error("{var} must be an absolute path")]
    NotAbsolute { var: &'static str },
    #[error("cannot read {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error("{}{}: {message}", path.display(), line_col(*at))]
    Parse {
        path: PathBuf,
        /// 1-based line and column, when the parser knows them.
        at: Option<(usize, usize)>,
        message: String,
    },
    #[error("{}: {message}", path.display())]
    Invalid { path: PathBuf, message: String },
    #[error("{}: the file name is not a valid project name: {source}", path.display())]
    BadFileName { path: PathBuf, source: NameError },
    #[error(
        "remote {remote} is claimed by both project {first} and project {second}{}",
        path.as_ref().map(|p| format!(" with path {p}")).unwrap_or_default()
    )]
    RemoteClaimedTwice {
        remote: RemoteId,
        /// The path both give, if any.
        path: Option<ProjectPath>,
        first: ProjectName,
        second: ProjectName,
    },
    #[error(
        "project {project} has no environment {env}; add it with \
         `kagebunshin project add-env {project} {env}`"
    )]
    UnknownEnv { project: ProjectName, env: EnvName },
    #[error(
        "environment {env} of project {project} lists no sources, and the {} provider \
         has no default source; add one with `kagebunshin project add-source {project} {env} \
         --provider PROVIDER --prefix PREFIX`",
        provider.as_str()
    )]
    NoDefaultSource {
        project: ProjectName,
        env: EnvName,
        provider: Provider,
    },
}

/// Why a checkout could not be matched to exactly one project.
#[derive(Debug, thiserror::Error)]
pub enum MatchError {
    #[error(transparent)]
    Git(#[from] GitError),
    #[error(
        "{} has no network git remotes; kagebunshin identifies a project by its git remote",
        root.display()
    )]
    NoRemotes { root: PathBuf },
    #[error(
        "unknown project: no project claims {}; run kagebunshin project init",
        join(remotes)
    )]
    Unknown { remotes: Vec<RemoteId> },
    #[error(
        "this checkout matches more than one project ({}); a checkout must match exactly one",
        matches.iter().map(|(r, p)| format!("{r} is {p}")).collect::<Vec<_>>().join(", ")
    )]
    Ambiguous {
        /// Each matching remote and the project that claims it.
        matches: Vec<(RemoteId, ProjectName)>,
    },
    #[error("{}", in_no_project(subdir, projects))]
    NoPathMatches {
        /// Where the caller is, relative to the checkout root.
        subdir: PathBuf,
        /// The projects that claim the checkout, each with its path.
        projects: Vec<(ProjectName, ProjectPath)>,
    },
    #[error(
        "projects {} ({}) and {} ({}) are the same folder of this checkout, {}; \
         give each project its own folder",
        projects[0].0, projects[0].1, projects[1].0, projects[1].1, path.display()
    )]
    SamePath {
        /// The folder both paths resolve to, relative to the checkout root.
        path: PathBuf,
        /// The two projects, each with its path as written.
        projects: [(ProjectName, ProjectPath); 2],
    },
    #[error(
        "project {project}'s path {path} leads outside this checkout through a symlink; \
         give it a folder inside the checkout"
    )]
    PathOutsideCheckout {
        project: ProjectName,
        path: ProjectPath,
    },
    #[error("no project is named {0}; run kagebunshin project list")]
    NoSuchProject(ProjectName),
    #[error(
        "project {project} does not claim this checkout's remotes ({})",
        join(remotes)
    )]
    NotThisCheckout {
        project: ProjectName,
        remotes: Vec<RemoteId>,
    },
}

/// `path` under `root` with symlinks resolved, relative to `root` resolved
/// the same way, as [`Checkout::subdir`] works the working directory out.
/// `Ok(None)` when it does not exist; `Err` when it resolves outside `root`.
fn resolved(root: &Path, path: &Path) -> Result<Option<PathBuf>, ()> {
    let (Ok(root), Ok(full)) = (root.canonicalize(), root.join(path).canonicalize()) else {
        return Ok(None);
    };
    match full.strip_prefix(&root) {
        Ok(at) => Ok(Some(at.to_owned())),
        Err(_) => Err(()),
    }
}

/// What every [`MatchError::NoPathMatches`] says, after the folder.
pub const PER_FOLDER: &str = "is in no project: this repository has one project per folder";

fn in_no_project(subdir: &Path, projects: &[(ProjectName, ProjectPath)]) -> String {
    let list = projects
        .iter()
        .map(|(n, p)| format!("{n} ({p})"))
        .collect::<Vec<_>>()
        .join(", ");
    let at = if subdir.as_os_str().is_empty() {
        "the repository root".to_owned()
    } else {
        subdir.display().to_string()
    };
    format!("{at} {PER_FOLDER}, {list}; run from one of those folders, or pass --project NAME")
}

fn join(remotes: &[RemoteId]) -> String {
    remotes
        .iter()
        .map(RemoteId::as_str)
        .collect::<Vec<_>>()
        .join(", ")
}

fn line_col(at: Option<(usize, usize)>) -> String {
    at.map(|(l, c)| format!(":{l}:{c}")).unwrap_or_default()
}

/// The configuration directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigDir(PathBuf);

impl ConfigDir {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self(path.into())
    }

    pub fn from_env() -> Result<Self, ConfigError> {
        Self::resolve(|k| std::env::var_os(k))
    }

    /// `$KAGEBUNSHIN_CONFIG_DIR` as is, else `$XDG_CONFIG_HOME/kagebunshin`,
    /// else `$HOME/.config/kagebunshin`. Empty variables are unset. A relative
    /// `XDG_CONFIG_HOME` is ignored, as the XDG spec says; a relative
    /// override or `HOME` is an error.
    pub fn resolve(env: impl Fn(&str) -> Option<OsString>) -> Result<Self, ConfigError> {
        let var = |k: &str| env(k).filter(|v| !v.is_empty()).map(PathBuf::from);
        if let Some(p) = var(CONFIG_DIR_ENV) {
            return absolute(p, CONFIG_DIR_ENV).map(Self);
        }
        if let Some(p) = var("XDG_CONFIG_HOME").filter(|p| p.is_absolute()) {
            return Ok(Self(p.join("kagebunshin")));
        }
        match var("HOME") {
            Some(home) => Ok(Self(absolute(home, "HOME")?.join(".config/kagebunshin"))),
            None => Err(ConfigError::NoConfigDir),
        }
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn config_file(&self) -> PathBuf {
        self.0.join(CONFIG_FILE)
    }

    pub fn projects_dir(&self) -> PathBuf {
        self.0.join(PROJECTS_DIR)
    }

    /// The local store, `store.age`.
    pub fn store_file(&self) -> PathBuf {
        self.0.join(crate::store::STORE_FILE)
    }

    pub fn project_file(&self, name: &ProjectName) -> PathBuf {
        self.projects_dir().join(format!("{name}.toml"))
    }

    /// Waits for and takes the lock that commands editing the config hold
    /// from reading it to writing it back, so two edits cannot interleave
    /// and drop one another's change. Released when the file is dropped.
    /// Edits made without kagebunshin do not take it.
    pub fn lock(&self) -> io::Result<fs::File> {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.0)?;
        let file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(self.0.join(LOCK_FILE))?;
        file.lock()?;
        Ok(file)
    }
}

fn absolute(p: PathBuf, var: &'static str) -> Result<PathBuf, ConfigError> {
    if p.is_absolute() {
        Ok(p)
    } else {
        Err(ConfigError::NotAbsolute { var })
    }
}

/// A project loaded from its mapping file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Project {
    pub name: ProjectName,
    pub path: PathBuf,
    pub file: ProjectFile,
}

/// Everything needed to resolve one environment of one project, with the
/// conventions applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvSettings<'a> {
    pub project: &'a ProjectName,
    pub env: EnvName,
    /// The declared sources, or the one default source.
    pub sources: Vec<SourceSpec>,
    /// The environment's plain settings; see [`EnvFile::vars`].
    pub vars: BTreeMap<KeyName, String>,
}

/// `config.toml` plus every project file, checked against each other.
#[derive(Debug, Clone)]
pub struct Registry {
    pub config: Config,
    projects: BTreeMap<ProjectName, Project>,
    /// The projects claiming each remote, in name order.
    remotes: BTreeMap<RemoteId, Vec<ProjectName>>,
}

/// Where a request comes from, for [`Registry::find`].
#[derive(Debug, Clone, Copy)]
pub struct Place<'a> {
    /// The checkout's network remotes.
    pub remotes: &'a [RemoteId],
    /// The working directory relative to the checkout root; `None` is the
    /// root. See [`Checkout::subdir`].
    pub subdir: Option<&'a Path>,
    /// The checkout root on disk, as git printed it. Given, each project's
    /// `path` is matched as it resolves under it, symlinks followed, the
    /// way `subdir` was worked out; otherwise as written.
    pub root: Option<&'a Path>,
    /// `--project`: this project, if it claims one of `remotes`, instead of
    /// the closest match.
    pub project: Option<&'a ProjectName>,
}

impl<'a> Place<'a> {
    /// The root of a checkout with `remotes`, with no project named.
    pub fn remotes(remotes: &'a [RemoteId]) -> Self {
        Self {
            remotes,
            subdir: None,
            root: None,
            project: None,
        }
    }
}

/// The project [`Registry::find`] picked, and what to warn about it.
#[derive(Debug, Clone)]
pub struct Found<'a> {
    pub project: &'a Project,
    pub warnings: Vec<String>,
}

impl Registry {
    /// Reads `config.toml` (defaults if missing) and every
    /// `projects/*.toml`. Files whose names start with `.` (editor backups,
    /// the atomic writer's temp files) and files not ending in `.toml` are
    /// skipped.
    pub fn load(dir: &ConfigDir) -> Result<Self, ConfigError> {
        let config_path = dir.config_file();
        let config = match read_optional(&config_path)? {
            Some(text) => parse_config(&config_path, &text)?,
            None => Config::default(),
        };

        let projects_dir = dir.projects_dir();
        let mut paths = Vec::new();
        match fs::read_dir(&projects_dir) {
            Ok(entries) => {
                for entry in entries {
                    let entry = entry.map_err(|source| ConfigError::Io {
                        path: projects_dir.clone(),
                        source,
                    })?;
                    let name = entry.file_name();
                    let name = name.to_string_lossy();
                    if name.starts_with('.') || !name.ends_with(".toml") {
                        continue;
                    }
                    paths.push(entry.path());
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(ConfigError::Io {
                    path: projects_dir,
                    source,
                });
            }
        }
        paths.sort();

        let mut projects = Vec::new();
        for path in paths {
            let text = fs::read_to_string(&path).map_err(|source| ConfigError::Io {
                path: path.clone(),
                source,
            })?;
            projects.push(parse_project(&path, &text)?);
        }
        Self::new(config, projects)
    }

    /// Builds a registry from parsed parts, rejecting two projects that
    /// claim the same remote with the same path (or both with none).
    pub fn new(config: Config, projects: Vec<Project>) -> Result<Self, ConfigError> {
        let mut by_name = BTreeMap::new();
        let mut claims: BTreeMap<(RemoteId, Option<ProjectPath>), ProjectName> = BTreeMap::new();
        let mut remotes: BTreeMap<RemoteId, Vec<ProjectName>> = BTreeMap::new();
        for p in projects {
            for r in &p.file.remotes {
                let claim = (r.clone(), p.file.path.clone());
                if let Some(first) = claims.get(&claim) {
                    return Err(ConfigError::RemoteClaimedTwice {
                        remote: r.clone(),
                        path: p.file.path.clone(),
                        first: first.clone(),
                        second: p.name.clone(),
                    });
                }
                claims.insert(claim, p.name.clone());
                remotes.entry(r.clone()).or_default().push(p.name.clone());
            }
            by_name.insert(p.name.clone(), p);
        }
        Ok(Self {
            config,
            projects: by_name,
            remotes,
        })
    }

    pub fn project(&self, name: &ProjectName) -> Option<&Project> {
        self.projects.get(name)
    }

    pub fn projects(&self) -> impl Iterator<Item = &Project> {
        self.projects.values()
    }

    /// The project that the checkout containing `dir` belongs to.
    pub fn resolve(&self, git: &Git, dir: &Path) -> Result<(&Project, Checkout), MatchError> {
        let checkout = git.checkout(dir)?;
        if checkout.remotes.is_empty() {
            return Err(MatchError::NoRemotes {
                root: checkout.root,
            });
        }
        let subdir = checkout.subdir(dir);
        let place = Place {
            subdir: subdir.as_deref(),
            root: Some(&checkout.root),
            ..Place::remotes(&checkout.remotes)
        };
        let project = self.find(place)?.project;
        Ok((project, checkout))
    }

    /// The project a request from `place` is for. The CLI, the daemon and
    /// the app all pick it here, so they always agree.
    ///
    /// The candidates are the projects that claim any of the remotes, so a
    /// fork with `origin` and `upstream` resolves through either. With
    /// `place.project`, that one, if it is a candidate. Otherwise the
    /// candidate whose `path` is the longest that contains `place.subdir`,
    /// a project with no path containing every folder. Two different
    /// projects tied for the longest (such as one per remote of a fork) are
    /// ambiguous. A project with no path that answers while candidates with
    /// a path exist is warned about: a typo in a path would otherwise fall
    /// back to it silently.
    pub fn find(&self, place: Place<'_>) -> Result<Found<'_>, MatchError> {
        let mut candidates: Vec<(&RemoteId, &Project)> = Vec::new();
        for r in place.remotes {
            for name in self.remotes.get(r).into_iter().flatten() {
                candidates.push((r, &self.projects[name]));
            }
        }
        if candidates.is_empty() {
            return Err(MatchError::Unknown {
                remotes: place.remotes.to_vec(),
            });
        }
        if let Some(wanted) = place.project {
            return match candidates.iter().find(|(_, p)| p.name == *wanted) {
                Some((_, project)) => Ok(Found {
                    project,
                    warnings: Vec::new(),
                }),
                None if self.projects.contains_key(wanted) => Err(MatchError::NotThisCheckout {
                    project: wanted.clone(),
                    remotes: place.remotes.to_vec(),
                }),
                None => Err(MatchError::NoSuchProject(wanted.clone())),
            };
        }
        let subdir = place.subdir.unwrap_or(Path::new(""));
        // Each candidate's path as it resolves on disk, in candidate order.
        let mut paths: Vec<Option<PathBuf>> = Vec::with_capacity(candidates.len());
        for (_, p) in &candidates {
            let Some(path) = &p.file.path else {
                paths.push(None);
                continue;
            };
            paths.push(Some(
                match place.root.map(|r| resolved(r, path.as_path())) {
                    Some(Ok(Some(at))) => at,
                    Some(Err(())) => {
                        return Err(MatchError::PathOutsideCheckout {
                            project: p.name.clone(),
                            path: path.clone(),
                        });
                    }
                    Some(Ok(None)) | None => path.as_path().to_owned(),
                },
            ));
        }
        for (i, (_, a)) in candidates.iter().enumerate() {
            for (j, (_, b)) in candidates.iter().enumerate().skip(i + 1) {
                if let (Some(path), Some(pa), Some(pb)) = (&paths[i], &a.file.path, &b.file.path)
                    && a.name != b.name
                    && pa != pb
                    && paths[j].as_ref() == Some(path)
                {
                    return Err(MatchError::SamePath {
                        path: path.clone(),
                        projects: [(a.name.clone(), pa.clone()), (b.name.clone(), pb.clone())],
                    });
                }
            }
        }
        let depth = |i: usize| paths[i].as_ref().map_or(0, |p| p.components().count());
        let containing: Vec<usize> = (0..candidates.len())
            .filter(|&i| paths[i].as_ref().is_none_or(|p| subdir.starts_with(p)))
            .collect();
        let Some(best) = containing.iter().map(|&i| depth(i)).max() else {
            let mut projects: Vec<(ProjectName, ProjectPath)> = candidates
                .iter()
                .filter_map(|(_, p)| Some((p.name.clone(), p.file.path.clone()?)))
                .collect();
            projects.sort();
            projects.dedup();
            return Err(MatchError::NoPathMatches {
                subdir: subdir.to_owned(),
                projects,
            });
        };
        let closest: Vec<&(&RemoteId, &Project)> = containing
            .into_iter()
            .filter(|&i| depth(i) == best)
            .map(|i| &candidates[i])
            .collect();
        let project = closest[0].1;
        if closest.iter().any(|(_, p)| p.name != project.name) {
            return Err(MatchError::Ambiguous {
                matches: closest
                    .iter()
                    .map(|(r, p)| ((*r).clone(), p.name.clone()))
                    .collect(),
            });
        }
        let mut scoped: Vec<String> = candidates
            .iter()
            .filter_map(|(_, p)| Some(format!("{} ({})", p.name, p.file.path.as_ref()?)))
            .collect();
        scoped.sort();
        scoped.dedup();
        let mut warnings = Vec::new();
        if project.file.path.is_none() && !scoped.is_empty() {
            warnings.push(format!(
                "project {} has no path, so it answers here, while {} {} this repository too; \
                 if one of them should answer here, check its path",
                project.name,
                scoped.join(", "),
                if scoped.len() == 1 { "claims" } else { "claim" },
            ));
        }
        Ok(Found { project, warnings })
    }

    /// The settings for `env` of `project`, or for the default environment.
    ///
    /// An environment that declares no sources gets one from
    /// `default_provider`: for `file` (the default) the local store's
    /// `[<project>.<env>]` section, for `aws_sm` every secret under
    /// `<project>/<env>/`. `proton` has no convention, so the environment
    /// must declare its sources.
    ///
    /// A declared `file` source with no `secret`, `secrets` or `prefix`
    /// reads the same `[<project>.<env>]` section, whatever
    /// `default_provider` is. That section, the environment's own, reads
    /// as empty while it is not in the store yet (see
    /// [`SourceSpec::missing_is_empty`]); any other section a source names
    /// fails when it is missing.
    ///
    /// Each `aws_sm` source gets its own profile if it sets one, else the
    /// environment's, else the project's, else `[aws]` in `config.toml`,
    /// else none; its region is its own, else `[aws]`'s, else whatever the
    /// AWS configuration chain picks for that profile.
    pub fn env<'a>(
        &'a self,
        project: &'a Project,
        env: Option<&EnvName>,
    ) -> Result<EnvSettings<'a>, ConfigError> {
        let env = env.unwrap_or(&self.config.default_env).clone();
        let Some(file) = project.file.envs.get(&env) else {
            return Err(ConfigError::UnknownEnv {
                project: project.name.clone(),
                env,
            });
        };
        let own_section = || Select::Secret {
            name: format!("{}.{env}", project.name),
            key: None,
        };
        // An AWS source's profile: its own, else the env's, else the
        // project's, else config.toml's, else none (the ambient AWS
        // configuration).
        let inherited = (file.profile.as_ref())
            .or(project.file.profile.as_ref())
            .or(self.config.aws.profile.as_ref());
        let aws_for = |provider: Provider, own: &AwsSettings| match provider {
            Provider::AwsSm => AwsSettings {
                profile: own.profile.as_ref().or(inherited).cloned(),
                region: own
                    .region
                    .as_ref()
                    .or(self.config.aws.region.as_ref())
                    .cloned(),
            },
            Provider::File | Provider::Proton => AwsSettings::default(),
        };
        let sources = if file.sources.is_empty() {
            let provider = self.config.default_provider;
            let select = match provider {
                Provider::File => own_section(),
                Provider::AwsSm => Select::Prefix(format!("{}/{env}/", project.name)),
                Provider::Proton => {
                    return Err(ConfigError::NoDefaultSource {
                        project: project.name.clone(),
                        env,
                        provider,
                    });
                }
            };
            vec![SourceSpec {
                aws: aws_for(provider, &AwsSettings::default()),
                missing_is_empty: provider == Provider::File,
                ..SourceSpec::new(provider, select, false)
            }]
        } else {
            file.sources
                .iter()
                .map(|s| {
                    let select = s.select.clone().unwrap_or_else(own_section);
                    SourceSpec {
                        provider: s.provider,
                        missing_is_empty: s.provider == Provider::File && select == own_section(),
                        select,
                        optional: s.optional,
                        aws: aws_for(s.provider, &s.aws),
                    }
                })
                .collect()
        };
        Ok(EnvSettings {
            project: &project.name,
            env,
            sources,
            vars: file.vars.clone(),
        })
    }
}

fn read_optional(path: &Path) -> Result<Option<String>, ConfigError> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(ConfigError::Io {
            path: path.into(),
            source,
        }),
    }
}

pub fn parse_config(path: &Path, text: &str) -> Result<Config, ConfigError> {
    from_toml(path, text)
}

/// Parses a project file. The project's name is the file's stem.
pub fn parse_project(path: &Path, text: &str) -> Result<Project, ConfigError> {
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let name: ProjectName = stem.parse().map_err(|source| ConfigError::BadFileName {
        path: path.into(),
        source,
    })?;
    let file: ProjectFile = from_toml(path, text)?;
    file.validate().map_err(|message| ConfigError::Invalid {
        path: path.into(),
        message,
    })?;
    Ok(Project {
        name,
        path: path.into(),
        file,
    })
}

impl ProjectFile {
    #[expect(
        clippy::expect_used,
        reason = "a ProjectFile is plain strings and tables, which always serialize"
    )]
    pub fn to_toml(&self) -> String {
        toml::to_string(self).expect("a project file always serializes")
    }
}

/// Deserializes TOML, reporting errors by line, column and field. Neither
/// the parser's source excerpt nor the offending value is in the message: a
/// value in the wrong place may be a credential, such as a token in a
/// remote URL.
fn from_toml<T: serde::de::DeserializeOwned>(path: &Path, text: &str) -> Result<T, ConfigError> {
    toml::from_str(text).map_err(|e| {
        let mut message = value_free(e.message());
        if let Some(field) = e.span().and_then(|s| field_at(text, s.start)) {
            message.push_str(&format!(" (field {field})"));
        }
        ConfigError::Parse {
            path: path.into(),
            at: e.span().map(|s| position(text, s.start)),
            message,
        }
    })
}

/// A deserializer message without the value it complains about. serde
/// quotes it: `invalid type: string "…", expected a boolean`, `unknown
/// variant `…`, expected one of …`. Only the value's kind is kept.
fn value_free(message: &str) -> String {
    let message = message.trim_end();
    // The value comes before ", expected", so the last one is serde's.
    fn split(rest: &str) -> Option<(&str, &str)> {
        rest.rfind(", expected ").map(|at| rest.split_at(at))
    }
    for lead in ["invalid type: ", "invalid value: "] {
        if let Some((unexpected, expected)) = message.strip_prefix(lead).and_then(split) {
            let kind = unexpected
                .split(['`', '"', '\''])
                .next()
                .unwrap_or_default();
            return format!("{lead}{}{expected}", kind.trim_end());
        }
    }
    if let Some((_, expected)) = message.strip_prefix("unknown variant ").and_then(split) {
        return format!("unknown variant{expected}");
    }
    message.to_owned()
}

/// The key of the `key = value` line `offset` is in, if it is past the `=`.
/// Bare keys only: anything else before an `=` may be part of a value, as
/// in a string on its own line of a multi-line array.
fn field_at(text: &str, offset: usize) -> Option<&str> {
    let start = text.get(..offset)?.rfind('\n').map_or(0, |i| i + 1);
    let line = text[start..].lines().next().unwrap_or_default();
    let (key, _) = line.split_once('=')?;
    let is_key = |c: char| c.is_ascii_alphanumeric() || "_-.".contains(c);
    let key = key.trim();
    (start + line.find('=')? < offset && !key.is_empty() && key.chars().all(is_key)).then_some(key)
}

/// The 1-based line and column of a byte offset.
fn position(text: &str, offset: usize) -> (usize, usize) {
    let before = &text.as_bytes()[..offset.min(text.len())];
    let line = before.iter().filter(|&&b| b == b'\n').count() + 1;
    let col = before.iter().rev().take_while(|&&b| b != b'\n').count() + 1;
    (line, col)
}

#[cfg(test)]
mod tests;
