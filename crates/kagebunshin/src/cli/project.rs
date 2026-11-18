//! `project`: writes project files so nobody hand-edits TOML, and `aws list`
//! to find the secret names to point them at.
//!
//! The writes happen here, not in the daemon. Each edit is checked by
//! loading it as the daemon would, together with every other project, then
//! written atomically.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::{Subcommand, ValueEnum};
use toml_edit::{Array, ArrayOfTables, DocumentMut, Item, Table, value};

use super::edit::{self, Added, Edited, NewSource, commit, config, existing, no_project};
use super::{print_json, print_line};
use crate::cli::{CliError, Exit};
use crate::config::schema::{Profile, Region};
use crate::config::{ConfigDir, Git, Project, ProjectPath, Registry, RemoteId, Select};
use crate::daemon::broker::UNLOCK_TELL;
use crate::daemon::resolve::waiting_message;
use crate::ipc::protocol::{Request, Response};
use crate::source::Source;
use crate::source::aws_sm::AwsSmSource;
use crate::source::aws_sm::sdk::SdkSm;
use crate::store::Section;
use crate::types::{EnvName, KeyName, ProjectName, Provider};

#[derive(Debug, Subcommand)]
pub enum ProjectAction {
    /// Create a project, identified by its git remotes, with one environment
    ///
    /// The environment is --env, else the configured default (dev). With no
    /// sources it reads the local store's [<project>.<env>] section.
    Init {
        /// The project's name, also its file's: projects/<NAME>.toml
        name: ProjectName,
        /// A git remote of the project; repeat for several [default: the
        /// remotes of the checkout this runs in]
        #[arg(long = "remote", value_name = "URL")]
        remotes: Vec<RemoteId>,
        /// The AWS profile for the project's aws_sm sources
        #[arg(long, value_parser = parse_profile)]
        profile: Option<Profile>,
        /// The app's folder, for a repository with one project per app;
        /// commands run in it or below it use this project
        #[arg(long, value_name = "DIR")]
        path: Option<PathBuf>,
    },
    /// Remove a project: delete its file
    ///
    /// Refused while an environment of it is marked sensitive or
    /// acknowledged as not production, which needs the daemon unlocked to
    /// check. Its values in the local store are left there; the output
    /// names their sections and `kagebunshin store clear`, which removes
    /// them with the passphrase.
    Remove {
        /// The project
        project: ProjectName,
    },
    /// Add an environment to a project
    AddEnv {
        /// The project
        project: ProjectName,
        /// The environment
        #[arg(value_name = "ENV")]
        environment: EnvName,
        /// The AWS profile for the environment's aws_sm sources
        #[arg(long, value_parser = parse_profile)]
        profile: Option<Profile>,
    },
    /// Add a source to an environment; a later source wins over an earlier one
    ///
    /// The first source replaces the default one (the local store's
    /// [<project>.<env>] section); add `--provider file` too to keep it.
    AddSource {
        /// The project
        project: ProjectName,
        /// The environment
        #[arg(value_name = "ENV")]
        environment: EnvName,
        /// Where the values come from: AWS Secrets Manager, the local store or Proton Pass
        #[arg(long, value_enum)]
        provider: SourceProvider,
        /// Read every secret whose name starts with this
        #[arg(long, conflicts_with = "secrets")]
        prefix: Option<String>,
        /// Read one secret (for file: a store section, e.g. widget.dev; for proton: vault/KEY);
        /// repeat to read several, a later one winning a key two set
        #[arg(long = "secret", value_name = "NAME")]
        secrets: Vec<String>,
        /// The secret's whole string is this key's value, not a JSON object (for proton: rename the key);
        /// takes exactly one --secret
        #[arg(long, requires = "secrets")]
        key: Option<KeyName>,
        /// aws_sm only: the AWS profile for this source
        #[arg(long, value_parser = parse_profile)]
        profile: Option<Profile>,
        /// aws_sm only: the AWS region for this source
        #[arg(long, value_parser = parse_region)]
        region: Option<Region>,
        /// If the source fails, resolve the environment without it
        #[arg(long)]
        optional: bool,
    },
    /// Remove one of an environment's sources
    ///
    /// SOURCE counts from 1, in the order `project show` lists them. With
    /// none left, the environment reads the local store's section again.
    RemoveSource {
        /// The project
        project: ProjectName,
        /// The environment
        #[arg(value_name = "ENV")]
        environment: EnvName,
        /// Which source, from 1
        #[arg(value_name = "SOURCE", value_parser = clap::value_parser!(u32).range(1..))]
        source: u32,
    },
    /// Move one of an environment's sources, changing which wins a key two set
    MoveSource {
        /// The project
        project: ProjectName,
        /// The environment
        #[arg(value_name = "ENV")]
        environment: EnvName,
        /// Which source, from 1
        #[arg(value_name = "SOURCE", value_parser = clap::value_parser!(u32).range(1..))]
        source: u32,
        /// Its new position, from 1
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
        to: u32,
    },
    /// Remove an environment's exact duplicate sources, keeping the copy that wins
    Dedupe {
        /// The project
        project: ProjectName,
        /// The environment
        #[arg(value_name = "ENV")]
        environment: EnvName,
    },
    /// Change the AWS profile or region of an environment's aws_sm sources
    ///
    /// SOURCE counts from 1, in the order `project show` lists them; --all
    /// is every aws_sm source of the environment. A source with no profile
    /// of its own inherits one: change that with `project set` instead.
    SetSource {
        /// The project
        project: ProjectName,
        /// The environment
        #[arg(value_name = "ENV")]
        environment: EnvName,
        /// Which source, from 1
        #[arg(
            value_name = "SOURCE",
            value_parser = clap::value_parser!(u32).range(1..),
            required_unless_present = "all",
            conflicts_with = "all"
        )]
        source: Option<u32>,
        /// Every aws_sm source of the environment
        #[arg(long)]
        all: bool,
        /// The AWS profile
        #[arg(long, value_parser = parse_profile, required_unless_present = "region")]
        profile: Option<Profile>,
        /// The AWS region
        #[arg(long, value_parser = parse_region)]
        region: Option<Region>,
    },
    /// Set a plain setting of an environment, one that is not secret (PORT=3000)
    ///
    /// It goes in the project file, readable by anyone, and is never masked
    /// in a command's output. It is the lowest layer: a key any source sets
    /// takes the source's value. A secret belongs in the store (`store set`)
    /// or a provider, never here.
    SetVar {
        /// The project
        project: ProjectName,
        /// The environment
        #[arg(value_name = "ENV")]
        environment: EnvName,
        /// The key
        key: KeyName,
        /// Its value
        value: String,
    },
    /// Remove a plain setting of an environment
    UnsetVar {
        /// The project
        project: ProjectName,
        /// The environment
        #[arg(value_name = "ENV")]
        environment: EnvName,
        /// The key
        key: KeyName,
    },
    /// Change a project's AWS profile, or with --env an environment's
    ///
    /// Sources that set no profile of their own use the environment's, else
    /// the project's.
    Set {
        /// The project
        project: ProjectName,
        /// The AWS profile
        #[arg(long, value_parser = parse_profile)]
        profile: Profile,
    },
    /// List the projects, each with its folder, environments and providers
    List,
    /// Print a project's configuration: names and settings, never values
    Show {
        /// The project
        project: ProjectName,
    },
    /// Print what this checkout and the connected providers say, names only
    ///
    /// The apps (folders with a .env.example or an env file), the keys of each .env.example and env file (whether each has
    /// a value, never the value), the projects claiming the checkout, the
    /// providers, which AWS profiles can list secrets now, and the secret
    /// names they list that the checkout's tracked files name.
    Facts {
        /// A folder in the checkout [default: the working directory]
        #[arg(long, value_name = "DIR")]
        path: Option<PathBuf>,
    },
    /// Write the app's .env.example from the keys its code reads, names only
    ///
    /// For an app with no .env.example, which gets every key of its
    /// environment on every run. Finds the names in the text of the files
    /// git tracks or would, running nothing and opening no env file:
    /// env.KEY (in brackets too) and env.get("KEY") on anything called env
    /// in JavaScript and TypeScript (process.env, import.meta.env, a Worker's
    /// env), the properties of a typed env module (a file called env.*),
    /// os.environ and os.getenv in Python, env::var and env! in Rust, and
    /// secrets.required of a Wrangler config. Names the platform sets, and
    /// what a Wrangler config gives a Worker itself, are left out. The file
    /// goes in the project's folder (its path, else the checkout's root),
    /// and other apps' folders below it are not searched. Check it against
    /// the code: a key read another way is not found.
    Example {
        /// A folder in the checkout [default: the working directory]
        #[arg(long, value_name = "DIR")]
        path: Option<PathBuf>,
    },
    /// Check a project file in a dry run, then install it, all or nothing
    ///
    /// Resolves every environment through the daemon without installing or
    /// caching anything, and reports, names and origins only, the keys of
    /// .env.example that are set, missing and extra, keys two sources set,
    /// and what could not be read or looks like production. A project of
    /// the same name, or one claiming the same checkout, is replaced; what
    /// changes is shown source by source. Marks and acknowledgements in the
    /// store stay. The dry run reads every secret the file names. Missing
    /// keys do not fail it; a file that does not load, or a source that is
    /// not optional failing, does, and then nothing is installed.
    Apply {
        /// The project file
        file: PathBuf,
        /// The project's name [default: the file's name]
        #[arg(long)]
        name: Option<ProjectName>,
        /// Only check: install nothing
        #[arg(long)]
        check: bool,
    },
    /// Draft a project file for this checkout from what it and the providers say
    ///
    /// Reads the checkout's facts and the key names inside the secrets the
    /// connected AWS profiles list, never their values, and picks the
    /// secrets that hold the keys of .env.example, for the default
    /// environment only. What it cannot decide is written into the file as
    /// `# open:` comments, each with the commands that settle it and who
    /// runs them; secrets that look like production are left out. Prints
    /// the file and, on stderr, a report. With --apply it installs the
    /// draft as `project apply` would, one project per app, and refuses a
    /// folder that a project already claims.
    Draft {
        /// A folder in the checkout [default: the working directory]
        #[arg(long, value_name = "DIR")]
        path: Option<PathBuf>,
        /// The project's name [default: from the checkout's folder]
        #[arg(long)]
        name: Option<ProjectName>,
        /// Write the draft to this file instead of stdout
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,
        /// Install the draft after checking it
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum AwsAction {
    /// List the names of AWS Secrets Manager secrets under a prefix (never values)
    List {
        /// List secrets whose name starts with this, e.g. widget/dev/
        #[arg(long)]
        prefix: String,
        /// The AWS profile [default: the ambient AWS configuration]
        #[arg(long, value_parser = parse_profile)]
        profile: Option<Profile>,
        /// The AWS region [default: the profile's, or AWS_REGION]
        #[arg(long, value_parser = parse_region)]
        region: Option<Region>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum SourceProvider {
    #[value(name = "aws_sm")]
    AwsSm,
    File,
    Proton,
}

impl SourceProvider {
    pub fn provider(self) -> Provider {
        match self {
            SourceProvider::AwsSm => Provider::AwsSm,
            SourceProvider::File => Provider::File,
            SourceProvider::Proton => Provider::Proton,
        }
    }
}

pub(super) fn parse_profile(s: &str) -> Result<Profile, &'static str> {
    Profile::try_from(s.to_owned())
}

pub(super) fn parse_region(s: &str) -> Result<Region, &'static str> {
    Region::try_from(s.to_owned())
}

pub fn manage(
    socket: Option<PathBuf>,
    json: bool,
    env: Option<EnvName>,
    action: ProjectAction,
) -> Result<(), CliError> {
    if let (
        Some(given),
        ProjectAction::AddEnv { environment, .. }
        | ProjectAction::AddSource { environment, .. }
        | ProjectAction::RemoveSource { environment, .. }
        | ProjectAction::MoveSource { environment, .. }
        | ProjectAction::SetSource { environment, .. }
        | ProjectAction::SetVar { environment, .. }
        | ProjectAction::UnsetVar { environment, .. }
        | ProjectAction::Dedupe { environment, .. },
    ) = (&env, &action)
        && given != environment
    {
        return Err(super::usage(format!(
            "two environments given: {environment} and --env {given}"
        )));
    }
    let dir = ConfigDir::from_env().map_err(config)?;
    if let ProjectAction::AddSource {
        project,
        environment: env,
        provider,
        prefix,
        secrets,
        key,
        profile,
        region,
        optional,
    } = action
    {
        if key.is_some() && secrets.len() > 1 {
            return Err(super::usage("--key takes exactly one --secret"));
        }
        let source = NewSource {
            provider: provider.provider(),
            prefix,
            secrets,
            key,
            profile,
            region,
            optional,
        };
        let edited = edit::add_source(&dir, &project, &env, &source)?;
        let mut message = format!("added a source to environment {env} of project {project}");
        if edited.replaced_default {
            message.push_str(
                "; it replaces the default source, the local store's section, unless you add `--provider file` too",
            );
        }
        return report(json, edited, &message, None);
    }
    // These take the lock themselves.
    match action {
        ProjectAction::RemoveSource {
            project,
            environment: env,
            source,
        } => {
            let edited = edit::remove_source(&dir, &project, &env, source as usize - 1)?;
            let message =
                format!("removed source {source} of environment {env} of project {project}");
            report(json, edited, &message, None)
        }
        ProjectAction::MoveSource {
            project,
            environment: env,
            source,
            to,
        } => {
            let edited =
                edit::move_source(&dir, &project, &env, source as usize - 1, to as usize - 1)?;
            let message =
                format!("moved source {source} of environment {env} of project {project} to {to}");
            report(json, edited, &message, None)
        }
        ProjectAction::SetSource {
            project,
            environment: env,
            source,
            all: _,
            profile,
            region,
        } => {
            let index = source.map(|n| n as usize - 1);
            let edited = edit::set_source(
                &dir,
                &project,
                &env,
                index,
                profile.as_ref(),
                region.as_ref(),
            )?;
            let which = match source {
                Some(n) => format!("source {n}"),
                None => "the aws_sm sources".to_owned(),
            };
            let message = format!("changed {which} of environment {env} of project {project}");
            report(json, edited, &message, None)
        }
        ProjectAction::SetVar {
            project,
            environment: env,
            key,
            value,
        } => {
            let edited = edit::set_var(&dir, &project, &env, &key, &value)?;
            let message = format!("set {key} for environment {env} of project {project}");
            report(json, edited, &message, None)
        }
        ProjectAction::UnsetVar {
            project,
            environment: env,
            key,
        } => {
            let edited = edit::unset_var(&dir, &project, &env, &key)?;
            let message = format!("removed {key} from environment {env} of project {project}");
            report(json, edited, &message, None)
        }
        ProjectAction::Dedupe {
            project,
            environment: env,
        } => {
            let removed = edit::dedupe(&dir, &project, &env)?;
            if json {
                return print_json(&serde_json::json!({ "removed": removed }));
            }
            if removed.is_empty() {
                return print_line(&format!(
                    "environment {env} of project {project} has no duplicate sources"
                ));
            }
            print_line(&format!("removed {}", removed.join(", ")))
        }
        action => manage_locked(socket, json, env, &dir, action),
    }
}

fn manage_locked(
    socket: Option<PathBuf>,
    json: bool,
    env: Option<EnvName>,
    dir: &ConfigDir,
    action: ProjectAction,
) -> Result<(), CliError> {
    // Held from loading the registry, which the checks below use, to the
    // write.
    let _lock = match action {
        ProjectAction::Show { .. } | ProjectAction::List => None,
        _ => Some(edit::lock(dir)?),
    };
    let registry = Registry::load(dir).map_err(config)?;
    match action {
        ProjectAction::Init {
            name,
            remotes,
            profile,
            path: folder,
        } => {
            let path = dir.project_file(&name);
            if path.exists() || registry.project(&name).is_some() {
                return Err(config(format!("project {name} already exists")));
            }
            let folder = folder.as_deref().map(project_path).transpose()?;
            let remotes = match remotes {
                r if !r.is_empty() => r,
                _ => checkout_remotes()?,
            };
            let env = env.unwrap_or_else(|| registry.config.default_env.clone());
            let mut doc = DocumentMut::new();
            doc.insert("schema", value(1));
            doc.insert(
                "remotes",
                value(remotes.iter().map(|r| r.to_string()).collect::<Array>()),
            );
            if let Some(p) = &folder {
                doc.insert("path", value(p.as_str()));
            }
            if let Some(p) = &profile {
                doc.insert("profile", value(p.as_str()));
            }
            let mut envs = Table::new();
            envs.set_implicit(true);
            envs.insert(env.as_str(), Item::Table(Table::new()));
            doc.insert("envs", Item::Table(envs));
            std::fs::create_dir_all(dir.projects_dir()).map_err(|e| {
                config(format!(
                    "cannot create {}: {e}",
                    dir.projects_dir().display()
                ))
            })?;
            let mut message = format!("created project {name} with environment {env}");
            if let Some(p) = &folder {
                message.push_str(&format!(" for folder {p}"));
            }
            // An agent may be setting up provider sources, so this is not
            // refused, but the human may want the file moved instead.
            let note = std::env::current_dir()
                .ok()
                .and_then(|cwd| Some((crate::repo::env_file_with_values(&cwd)?, cwd)))
                .map(|(file, cwd)| {
                    let here = crate::types::shell_quote(&cwd.to_string_lossy());
                    let onboard = if env == registry.config.default_env {
                        format!("kagebunshin onboard {here}")
                    } else {
                        format!("kagebunshin onboard --env {env} {here}")
                    };
                    format!(
                        "{file} here has values: `{onboard}` moves them into this project's \
                         environment {env}, once a person approves that with the store \
                         passphrase"
                    )
                });
            commit(&registry, dir, &name, &env, doc, Added::All, "project init")
                .and_then(|edited| report(json, edited, &message, note.as_deref()))
        }
        ProjectAction::AddEnv {
            project,
            environment: env,
            profile,
        } => {
            let mut doc = existing(&registry, &project)?;
            let envs = doc
                .entry("envs")
                .or_insert_with(|| Item::Table(Table::new()))
                .as_table_like_mut()
                .ok_or_else(|| config("envs is not a table"))?;
            if envs.contains_key(env.as_str()) {
                return Err(config(format!(
                    "project {project} already has an environment {env}"
                )));
            }
            let mut table = Table::new();
            if let Some(p) = &profile {
                table.insert("profile", value(p.as_str()));
            }
            envs.insert(env.as_str(), Item::Table(table));
            let message = format!("added environment {env} to project {project}");
            commit(
                &registry,
                dir,
                &project,
                &env,
                doc,
                Added::All,
                "project add-env",
            )
            .and_then(|edited| report(json, edited, &message, None))
        }
        ProjectAction::Set { project, profile } => {
            let mut doc = existing(&registry, &project)?;
            let Some(p) = registry.project(&project) else {
                return Err(no_project(&project));
            };
            // The environment whose sources the edit is checked with.
            let checked =
                match &env {
                    Some(e) => e.clone(),
                    None if p.file.envs.contains_key(&registry.config.default_env) => {
                        registry.config.default_env.clone()
                    }
                    None => {
                        p.file.envs.keys().next().cloned().ok_or_else(|| {
                            config(format!("project {project} has no environments"))
                        })?
                    }
                };
            let table: &mut dyn toml_edit::TableLike = match &env {
                None => doc.as_table_mut(),
                Some(e) => doc
                    .get_mut("envs")
                    .and_then(Item::as_table_like_mut)
                    .and_then(|envs| envs.get_mut(e.as_str()))
                    .and_then(Item::as_table_like_mut)
                    .ok_or_else(|| {
                        config(format!("project {project} has no environment {e}"))
                            .with_hint(format!(
                                "add it with `kagebunshin project add-env {project} {e}`"
                            ))
                            .agent()
                    })?,
            };
            table.insert("profile", value(profile.as_str()));
            let whose = match &env {
                Some(e) => format!("environment {e} of project {project}"),
                None => format!("project {project}"),
            };
            let what = format!("profile of {whose} set to {profile}");
            let count = registry
                .env(p, Some(&checked))
                .map(|s| s.sources.len())
                .unwrap_or_default();
            commit(
                &registry,
                dir,
                &project,
                &checked,
                doc,
                Added::Changed((0..count).collect(), what.clone()),
                "project set",
            )
            .and_then(|edited| report(json, edited, &what, None))
        }
        ProjectAction::List => {
            list(json, &registry)?;
            waiting_note(socket, json, None);
            Ok(())
        }
        ProjectAction::AddSource { .. }
        | ProjectAction::RemoveSource { .. }
        | ProjectAction::MoveSource { .. }
        | ProjectAction::SetSource { .. }
        | ProjectAction::SetVar { .. }
        | ProjectAction::UnsetVar { .. }
        | ProjectAction::Dedupe { .. } => unreachable!("handled before the lock"),
        ProjectAction::Remove { .. } => unreachable!("handled by `remove`"),
        ProjectAction::Facts { .. } => unreachable!("handled by `draft::facts`"),
        ProjectAction::Example { .. } => unreachable!("handled by `example::example`"),
        ProjectAction::Apply { .. } => unreachable!("handled by `draft::apply`"),
        ProjectAction::Draft { .. } => unreachable!("handled by `draft::draft`"),
        ProjectAction::Show { project } => {
            let Some(p) = registry.project(&project) else {
                return Err(no_project(&project));
            };
            if json {
                print_json(&p.file)
            } else {
                print_line(p.file.to_toml().trim_end())?;
                waiting_note(socket, json, Some(&project));
                Ok(())
            }
        }
    }
}

/// `project list`: names and settings only.
fn list(json: bool, registry: &Registry) -> Result<(), CliError> {
    #[derive(serde::Serialize)]
    struct Row<'a> {
        name: &'a ProjectName,
        #[serde(skip_serializing_if = "Option::is_none")]
        path: Option<&'a ProjectPath>,
        remotes: &'a [RemoteId],
        envs: Vec<&'a EnvName>,
        providers: Vec<&'static str>,
    }
    let rows: Vec<Row<'_>> = registry
        .projects()
        .map(|p| {
            let mut providers: Vec<&'static str> = p
                .file
                .envs
                .keys()
                .filter_map(|e| registry.env(p, Some(e)).ok())
                .flat_map(|s| s.sources.into_iter().map(|s| s.provider.as_str()))
                .collect();
            providers.sort_unstable();
            providers.dedup();
            Row {
                name: &p.name,
                path: p.file.path.as_ref(),
                remotes: &p.file.remotes,
                envs: p.file.envs.keys().collect(),
                providers,
            }
        })
        .collect();
    if json {
        return print_json(&serde_json::json!({ "projects": rows }));
    }
    if rows.is_empty() {
        return print_line("no projects; create one with `kagebunshin project init NAME`");
    }
    let join = |v: &[&str]| v.join(", ");
    let lines: Vec<[String; 4]> = rows
        .iter()
        .map(|r| {
            [
                r.name.to_string(),
                r.path
                    .map_or_else(|| "(whole repository)".to_owned(), ToString::to_string),
                join(&r.envs.iter().map(|e| e.as_str()).collect::<Vec<_>>()),
                join(&r.providers),
            ]
        })
        .collect();
    let header = ["PROJECT", "PATH", "ENVS", "PROVIDERS"].map(str::to_owned);
    let widths: Vec<usize> = (0..3)
        .map(|i| {
            std::iter::once(&header)
                .chain(&lines)
                .map(|l| l[i].chars().count())
                .max()
                .unwrap_or(0)
        })
        .collect();
    let text = std::iter::once(&header)
        .chain(&lines)
        .map(|l| {
            format!(
                "{:w0$}  {:w1$}  {:w2$}  {}",
                l[0],
                l[1],
                l[2],
                l[3],
                w0 = widths[0],
                w1 = widths[1],
                w2 = widths[2]
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    print_line(&text)
}

/// A warning on stderr for each environment (of `project`, or of every
/// project) that waits for a human decision, as the daemon sees it. Only
/// while the daemon answers and is unlocked; the store that says what was
/// decided is the daemon's. Nothing as JSON.
fn waiting_note(socket: Option<PathBuf>, json: bool, project: Option<&ProjectName>) {
    if json {
        return;
    }
    let Ok(mut client) = super::connect(socket) else {
        return;
    };
    let Ok(Response::Status(status)) = client.request(Request::Status { facts: None }) else {
        return;
    };
    for w in status
        .waiting
        .iter()
        .filter(|w| project.is_none_or(|p| *p == w.project))
    {
        eprintln!("warning: {}", waiting_message(&w.project, &w.env, &w.why));
    }
}

/// `message`, then `hint` after it; as JSON, `hint` is its own field.
fn report(json: bool, edited: Edited, message: &str, hint: Option<&str>) -> Result<(), CliError> {
    if json {
        let mut out = serde_json::json!({ "written": edited.path });
        if !edited.warnings.is_empty() {
            out["warnings"] = edited.warnings.into();
        }
        if let Some(hint) = hint {
            out["hint"] = hint.into();
        }
        return print_json(&out);
    }
    for w in &edited.warnings {
        eprintln!("warning: {w}");
    }
    match hint {
        Some(hint) => print_line(&format!("{message}; {hint}")),
        None => print_line(message),
    }
}

fn checkout_remotes() -> Result<Vec<RemoteId>, CliError> {
    let cwd = std::env::current_dir().map_err(config)?;
    let checkout = Git::default().checkout(&cwd).map_err(|e| {
        CliError::new(Exit::Failure, "no_project", e.to_string())
            .with_hint("run this in the project's git checkout, or give --remote")
    })?;
    if checkout.remotes.is_empty() {
        return Err(
            CliError::new(Exit::Usage, "usage", "this checkout has no network remote")
                .with_hint("give the project's remote with --remote"),
        );
    }
    Ok(checkout.remotes)
}

/// `--path DIR` as a project's `path`: DIR, from the working directory,
/// must be an existing folder inside the checkout, and not its root.
fn project_path(folder: &Path) -> Result<ProjectPath, CliError> {
    let cwd = std::env::current_dir().map_err(config)?;
    let checkout = Git::default().checkout(&cwd).map_err(|e| {
        CliError::new(Exit::Failure, "no_project", e.to_string())
            .with_hint("run project init --path in the project's git checkout")
    })?;
    let full = cwd.join(folder);
    if !full.is_dir() {
        return Err(super::usage(format!(
            "--path {} is not a folder",
            folder.display()
        )));
    }
    let Some(rel) = checkout.subdir(&full) else {
        return Err(super::usage(format!(
            "--path {} is not inside the checkout at {}",
            folder.display(),
            checkout.root.display()
        )));
    };
    if rel.as_os_str().is_empty() {
        return Err(super::usage(
            "--path names the whole repository; leave it out for a project that is the whole repository",
        ));
    }
    let rel = rel
        .to_str()
        .ok_or_else(|| super::usage(format!("--path {} is not UTF-8", folder.display())))?;
    ProjectPath::try_from(rel.to_owned()).map_err(super::usage)
}

pub fn aws(json: bool, action: AwsAction) -> Result<(), CliError> {
    let AwsAction::List {
        prefix,
        profile,
        region,
    } = action;
    // The same checks a source's prefix gets.
    if prefix.is_empty() || prefix.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(CliError::new(
            Exit::Usage,
            "usage",
            "--prefix must be non-empty, without whitespace or control characters",
        ));
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError::new(Exit::Failure, "runtime", e.to_string()))?;
    let names = runtime.block_on(async {
        let profile = profile.as_ref().map(Profile::as_str);
        let region = region.as_ref().map(Region::as_str);
        let api = SdkSm::load(profile, region).await;
        let mut source =
            AwsSmSource::new(Arc::new(api), Select::Prefix(prefix)).with_optional(true);
        if let Some(p) = profile {
            source = source.with_profile(p);
        }
        if let Some(r) = region {
            source = source.with_region(r);
        }
        // Names only: ListSecrets, never GetSecretValue.
        source.names().await
    });
    let names = names.map_err(|e| {
        let hint = e.hint().map(str::to_owned);
        let err = CliError::new(Exit::Failure, "source", e.to_string());
        match hint {
            Some(h) => err.with_hint(h),
            None => err,
        }
    })?;
    if json {
        return print_json(&serde_json::json!({ "names": names }));
    }
    for n in &names {
        print_line(n)?;
    }
    Ok(())
}

/// Reads and parses project file `file`, as project `name` if given, else
/// as its file's name says: what `import` and `project apply` install.
pub(super) fn load_file(
    file: &Path,
    name: Option<&ProjectName>,
) -> Result<(String, Project), CliError> {
    let text = std::fs::read_to_string(file)
        .map_err(|e| config(format!("cannot read {}: {e}", file.display())))?;
    // The name comes from the path parse_project is given.
    let named = match name {
        Some(n) => PathBuf::from(format!("{n}.toml")),
        None => file.to_owned(),
    };
    let project = crate::config::parse_project(&named, &text).map_err(config)?;
    Ok((text, project))
}

/// A warning for each AWS profile project `name` of `registry` uses that
/// the AWS configuration does not have.
pub(super) fn profile_warnings(
    registry: &Registry,
    name: &ProjectName,
) -> Result<Vec<String>, CliError> {
    let p = registry.project(name).ok_or_else(|| no_project(name))?;
    let mut profiles = std::collections::BTreeSet::new();
    for env in p.file.envs.keys() {
        let settings = registry.env(p, Some(env)).map_err(config)?;
        profiles.extend(
            settings
                .sources
                .into_iter()
                .filter_map(|s| s.aws.profile.map(|p| p.as_str().to_owned())),
        );
    }
    let known = known_profiles();
    Ok(profiles
        .iter()
        .filter(|p| known.as_ref().is_some_and(|k| !k.contains(*p)))
        .map(|p| format!("AWS profile {p} is not in your AWS configuration"))
        .collect())
}

/// `import`: installs a project file someone exported, as a new project.
/// Replacing an existing project is refused: that could loosen what is
/// marked sensitive, which only a human may do, by editing or removing the
/// file.
pub fn import(json: bool, file: &Path, name: Option<ProjectName>) -> Result<(), CliError> {
    let (text, mut project) = load_file(file, name.as_ref())?;
    let dir = ConfigDir::from_env().map_err(config)?;
    let _lock = dir
        .lock()
        .map_err(|e| config(format!("cannot lock {}: {e}", dir.path().display())))?;
    let registry = Registry::load(&dir).map_err(config)?;
    let name = project.name.clone();
    let dest = dir.project_file(&name);
    if dest.exists() || registry.project(&name).is_some() {
        return Err(
            config(format!("project {name} already exists")).with_hint(format!(
                "import it under another name with --name, or run `kagebunshin project remove \
                 {name}` first to replace it"
            )),
        );
    }
    project.path.clone_from(&dest);
    let mut projects: Vec<Project> = registry.projects().cloned().collect();
    projects.push(project);
    let edited = Registry::new(registry.config.clone(), projects).map_err(config)?;
    let warnings = profile_warnings(&edited, &name)?;
    std::fs::create_dir_all(dir.projects_dir()).map_err(|e| {
        config(format!(
            "cannot create {}: {e}",
            dir.projects_dir().display()
        ))
    })?;
    crate::atomic::write_private(&dest, text.as_bytes())
        .map_err(|e| config(format!("cannot write {}: {e}", dest.display())))?;
    crate::audit::record_edit("import", &name, None, Vec::new(), None);
    if json {
        let mut out = serde_json::json!({ "project": name, "written": dest });
        if !warnings.is_empty() {
            out["warnings"] = warnings.into();
        }
        return print_json(&out);
    }
    for w in &warnings {
        eprintln!("warning: {w}");
    }
    print_line(&format!("imported project {name} into {}", dest.display()))
}

/// Refuses, with a hint naming what to run instead, unless `onboard` can
/// fill environment `env` of `project`, which already claims the checkout:
/// its one source must be the local store's `[<project>.<env>]`, as with
/// no sources and the default provider `file`, or what `onboard` writes.
/// That the section is empty is checked later, with the daemon. `file` is
/// the env file there, for the hint.
pub(super) fn fillable(
    registry: &Registry,
    project: &Project,
    env: &EnvName,
    file: &Path,
) -> Result<(), CliError> {
    let name = &project.name;
    let claimed = format!("project {name} already claims this checkout");
    let file = super::shell_quote(&file.to_string_lossy());
    if !project.file.envs.contains_key(env) {
        return Err(config(format!(
            "{claimed} and has no environment {env}; nothing was written"
        ))
        .with_hint(format!(
            "to give it that environment with the file's values, run `kagebunshin onboard \
             --file {file} --env {env}`"
        )));
    }
    let section = Section {
        project: name.clone(),
        env: env.clone(),
    };
    if reads_own_section(registry, project, env, false) {
        return Ok(());
    }
    Err(config(format!(
        "{claimed}, and its environment {env} has sources other than the local store's \
         [{section}]; nothing was written"
    ))
    .with_hint(format!(
        "run commands with `kagebunshin run -- COMMAND`; to move the file's values into a new \
         environment of {name} instead, run `kagebunshin onboard --file {file} --env ENV`"
    )))
}

/// Whether environment `env` of `project` reads the local store's
/// `[<project>.<env>]`: as its only source, or with `among`, as one of
/// its sources.
pub(super) fn reads_own_section(
    registry: &Registry,
    project: &Project,
    env: &EnvName,
    among: bool,
) -> bool {
    let section = Section {
        project: project.name.clone(),
        env: env.clone(),
    };
    let own = Select::Secret {
        name: section.to_string(),
        key: None,
    };
    registry.env(project, Some(env)).is_ok_and(|s| {
        let mut own =
            (s.sources.iter()).filter(|s| s.provider == Provider::File && s.select == own);
        own.next().is_some() && (among || s.sources.len() == 1)
    })
}

/// An environment's table whose one source is the local store's section
/// of its name. A bare `file` source reads `[<name>.<env>]`, whatever
/// `default_provider` an empty table would inherit.
fn store_env() -> Item {
    let mut source = Table::new();
    source.insert("provider", value("file"));
    let mut sources = ArrayOfTables::new();
    sources.push(source);
    let mut env_table = Table::new();
    env_table.set_implicit(true);
    env_table.insert("sources", Item::ArrayOfTables(sources));
    Item::Table(env_table)
}

/// Gives project `name` the environment `env`, which it does not have
/// yet, reading the local store's `[<name>.<env>]`.
pub(super) fn add_store_env(
    registry: &Registry,
    dir: &ConfigDir,
    name: &ProjectName,
    env: &EnvName,
) -> Result<Edited, CliError> {
    let mut doc = existing(registry, name)?;
    let mut added = store_env();
    // What the file ends with, such as a draft's comments on the last
    // environment, stays above the new one.
    let trailing = doc.trailing().as_str().unwrap_or_default().to_owned();
    let first = added
        .get_mut("sources")
        .and_then(Item::as_array_of_tables_mut)
        .and_then(|sources| sources.get_mut(0));
    if let (Some(source), false) = (first, trailing.trim().is_empty()) {
        source.decor_mut().set_prefix(format!("{trailing}\n"));
        doc.set_trailing("");
    }
    let envs = doc
        .entry("envs")
        .or_insert_with(|| Item::Table(Table::new()))
        .as_table_like_mut()
        .ok_or_else(|| config("envs is not a table"))?;
    envs.insert(env.as_str(), added);
    commit(registry, dir, name, env, doc, Added::All, "onboard")
}

/// Writes a new project claiming `remotes` (and folder `path` of them, if
/// given) whose environment `env` reads the local store's `[<name>.<env>]`.
pub(super) fn create_store_project(
    registry: &Registry,
    dir: &ConfigDir,
    name: &ProjectName,
    env: &EnvName,
    remotes: &[RemoteId],
    path: Option<&ProjectPath>,
) -> Result<Edited, CliError> {
    let mut doc = DocumentMut::new();
    doc.insert("schema", value(1));
    doc.insert(
        "remotes",
        value(remotes.iter().map(ToString::to_string).collect::<Array>()),
    );
    if let Some(p) = path {
        doc.insert("path", value(p.as_str()));
    }
    let mut envs = Table::new();
    envs.set_implicit(true);
    envs.insert(env.as_str(), store_env());
    doc.insert("envs", Item::Table(envs));
    std::fs::create_dir_all(dir.projects_dir()).map_err(|e| {
        config(format!(
            "cannot create {}: {e}",
            dir.projects_dir().display()
        ))
    })?;
    commit(registry, dir, name, env, doc, Added::All, "onboard")
}

/// `project remove`: deletes the project's file. Refused while an
/// environment of it is marked sensitive or acknowledged as not
/// production: those are a human's decisions, kept in the encrypted store,
/// and a project made again under the name would inherit them unseen. Only
/// the unlocked daemon can tell, so a locked or stopped one refuses too.
/// Keys in the store are left, since removing them takes the passphrase:
/// the output names their sections and the command that clears them. The
/// daemon's cached values are dropped.
pub fn remove(socket: Option<PathBuf>, json: bool, name: &ProjectName) -> Result<(), CliError> {
    use crate::ipc::client::ClientError;
    use crate::ipc::protocol::{ErrorCode, Request, Response};

    let dir = ConfigDir::from_env().map_err(config)?;
    let _lock = edit::lock(&dir)?;
    let registry = Registry::load(&dir).map_err(config)?;
    let project = registry.project(name).ok_or_else(|| no_project(name))?;
    let cannot_tell = |why: &str| {
        config(format!(
            "{why}, so it cannot be checked whether an environment of project {name} is marked \
             sensitive or acknowledged as not production; nothing was removed"
        ))
    };
    let again = format!("then run `kagebunshin project remove {name}` again");
    let mut client = match super::connect(socket) {
        Ok(c) => c,
        Err(e) if e.exit == Exit::DaemonNotRunning => {
            return Err(cannot_tell("the daemon is not running")
                .with_hint(format!("once it runs and is unlocked, {again}"))
                .human(format!(
                    "start kagebunshin and unlock it: {}",
                    super::error::start_daemon_hint()
                )));
        }
        Err(e) => return Err(e),
    };
    let listing = match client.request(Request::StoreList) {
        Ok(Response::StoreList(l)) => Some(l),
        Ok(_) => return Err(super::unexpected()),
        Err(ClientError::Daemon(w)) if w.code == ErrorCode::Locked => {
            return Err(CliError {
                exit: Exit::Refused,
                code: "locked",
                ..cannot_tell("the daemon is locked")
                    .with_hint(format!("once it is unlocked, {again}"))
                    .human(UNLOCK_TELL)
            });
        }
        // No store, so nothing marked.
        Err(ClientError::Daemon(w)) if w.code == ErrorCode::NoStore => None,
        Err(e) => return Err(e.into()),
    };
    let ours = |s: &&Section| &s.project == name;
    if let Some(l) = &listing {
        let decided: Vec<String> = l
            .sensitive_envs
            .iter()
            .filter(ours)
            .map(|s| format!("{} is marked sensitive", s.env))
            .chain(
                l.acknowledged_envs
                    .iter()
                    .filter(ours)
                    .map(|s| format!("{} is acknowledged as not production", s.env)),
            )
            .collect();
        if !decided.is_empty() {
            return Err(CliError::new(
                Exit::Refused,
                "config",
                format!(
                    "project {name} has a human's decisions in the store (environment {}); \
                     nothing was removed",
                    decided.join(", environment ")
                ),
            )
            .with_hint(format!("once they are taken back, {again}"))
            .human(format!(
                "open the app (`kagebunshin app`) and take back the decisions about project {name}"
            )));
        }
    }
    let path = project.path.clone();
    let envs: Vec<EnvName> = project.file.envs.keys().cloned().collect();
    std::fs::remove_file(&path)
        .map_err(|e| config(format!("cannot remove {}: {e}", path.display())))?;
    crate::audit::record_edit("project remove", name, None, Vec::new(), None);
    // The cache is keyed by name: a project made again under it must not
    // get these values. With the file gone each sync just drops the entry.
    for env in &envs {
        let _ = client.request(Request::Sync {
            project: Some(name.clone()),
            env: Some(env.clone()),
        });
    }
    let kept: Vec<(&Section, usize)> = listing
        .iter()
        .flat_map(|l| &l.sections)
        .filter(|s| s.section.project == *name && !s.keys.is_empty())
        .map(|s| (&s.section, s.keys.len()))
        .collect();
    // Clearing takes the passphrase, so it is a person's to run.
    let clear = (!kept.is_empty()).then(|| format!("kagebunshin store clear {name}"));
    let tell = clear.as_ref().map(|clear| {
        format!(
            "Please run `{clear}` in a terminal; it asks for the store passphrase and removes \
             the values project {name} left in the local store."
        )
    });
    if json {
        return print_json(&serde_json::json!({
            "removed": path,
            "store_sections": kept.iter().map(|(s, _)| s.to_string()).collect::<Vec<_>>(),
            "clear": clear,
            "tell": tell,
        }));
    }
    let mut message = format!("removed project {name} ({})", path.display());
    if let Some(clear) = clear {
        let names: Vec<String> = kept
            .iter()
            .map(|(s, n)| format!("[{s}] ({n} {})", super::plural(*n, "key", "keys")))
            .collect();
        message.push_str(&format!(
            "\nits values are still in the local store: {}\n\
             to remove them, run `{clear}` in a terminal; it asks for the passphrase",
            names.join(", ")
        ));
    }
    print_line(&message)
}

/// How the daemon's "no project claims this checkout" error starts, and the
/// advice it ends with (see [`crate::config::MatchError::Unknown`]).
pub(super) const UNKNOWN_PROJECT: &str = "unknown project: ";
const RUN_INIT: &str = "; run kagebunshin project init";

/// The "no project claims this checkout" error with the advice that fits
/// this checkout as its hint: `onboard`, for a human, when an env file here
/// has values, else `project init`. Other errors are returned as they are.
pub(super) fn steer_unknown_project(mut e: CliError) -> CliError {
    if e.code != "no_project" || e.hint.is_some() {
        return e;
    }
    // A folder between the projects of a repository that has one per folder.
    if e.message.contains(crate::config::PER_FOLDER) {
        e.hint = Some("`kagebunshin next` says where each of those projects stands".into());
        return e.agent();
    }
    if !e.message.starts_with(UNKNOWN_PROJECT) {
        return e;
    }
    let Some(message) = e.message.strip_suffix(RUN_INIT).map(str::to_owned) else {
        return e;
    };
    let Ok(cwd) = std::env::current_dir() else {
        return e;
    };
    e.message = message;
    let (hint, tell) = unknown_project_hint(&cwd);
    e.hint = Some(hint);
    match tell {
        Some(tell) => e.human(tell),
        None => e.agent(),
    }
}

/// The hint, and what to ask the human when only they can act: moving
/// values into the store takes its passphrase, typed in the app when an
/// agent runs `onboard`, or at the terminal.
fn unknown_project_hint(cwd: &Path) -> (String, Option<String>) {
    if let Some(file) = crate::repo::env_file_with_values(cwd) {
        // The folder in full: the human's terminal may be anywhere.
        let onboard = format!(
            "kagebunshin onboard {}",
            crate::types::shell_quote(&cwd.to_string_lossy())
        );
        return (
            format!(
                "{file} here has values: `{onboard}` moves them into kagebunshin, once a person \
                 approves that with the store passphrase, in the kagebunshin app or at a \
                 terminal. `kagebunshin next` says whose step it is; do not run `kagebunshin \
                 project init`"
            ),
            Some(format!(
                "move the values in {file} into kagebunshin: approve the import in the \
                 kagebunshin app when it asks, or run `{onboard}` in a terminal"
            )),
        );
    }
    let name = Git::default()
        .checkout(cwd)
        .ok()
        .and_then(|c| c.root.file_name()?.to_str()?.parse::<ProjectName>().ok())
        .map_or_else(|| "NAME".to_owned(), |n| n.to_string());
    (
        format!(
            "run `kagebunshin next`, which says how to set this checkout up step by step; or \
             create an empty project by hand with `kagebunshin project init {name}`"
        ),
        None,
    )
}

/// The profiles in `~/.aws/config` and `~/.aws/credentials` (or where
/// `AWS_CONFIG_FILE` and `AWS_SHARED_CREDENTIALS_FILE` point), or `None` if
/// they cannot be read, so nothing is reported as unknown.
fn known_profiles() -> Option<std::collections::BTreeSet<String>> {
    let set = crate::source::aws_sm::connect::profiles()?;
    Some(set.profiles().map(str::to_owned).collect())
}

/// `export`: the project file as it is, comments and all. It names secrets
/// and where they live, never their values.
pub fn export(json: bool, project: &ProjectName, output: Option<PathBuf>) -> Result<(), CliError> {
    let dir = ConfigDir::from_env().map_err(config)?;
    let registry = Registry::load(&dir).map_err(config)?;
    let p = registry
        .project(project)
        .ok_or_else(|| no_project(project))?;
    let text = std::fs::read_to_string(&p.path)
        .map_err(|e| config(format!("cannot read {}: {e}", p.path.display())))?;
    match output {
        None if json => print_json(&serde_json::json!({ "project": project, "file": text })),
        None => print_line(text.trim_end()),
        Some(path) => {
            crate::atomic::write_private(&path, text.as_bytes())
                .map_err(|e| config(format!("cannot write {}: {e}", path.display())))?;
            if json {
                print_json(&serde_json::json!({ "project": project, "written": path }))
            } else {
                print_line(&format!("wrote project {project} to {}", path.display()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_env_file_with_values_is_found_and_examples_are_not() {
        use crate::repo::env_file_with_values;
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        assert_eq!(env_file_with_values(d), None);
        std::fs::write(d.join(".env.example"), "A=1\n").unwrap();
        std::fs::write(d.join(".env"), "# no keys\n\n").unwrap();
        assert_eq!(env_file_with_values(d), None);
        std::fs::create_dir(d.join(".env.d")).unwrap();
        assert_eq!(env_file_with_values(d), None);
        std::fs::write(d.join(".env.local"), "export A=\"b\"\n").unwrap();
        assert_eq!(env_file_with_values(d).as_deref(), Some(".env.local"));
        std::fs::write(d.join(".env"), "A=1\n").unwrap();
        assert_eq!(env_file_with_values(d).as_deref(), Some(".env"));
    }

    #[test]
    fn the_unknown_project_hint_fits_the_checkout() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        // Not a git checkout, so no folder name to suggest.
        assert_eq!(
            unknown_project_hint(d),
            (
                "run `kagebunshin next`, which says how to set this checkout up step by step; or \
                 create an empty project by hand with `kagebunshin project init NAME`"
                    .into(),
                None
            )
        );
        std::fs::write(d.join(".env"), "A=1\n").unwrap();
        let (hint, tell) = unknown_project_hint(d);
        assert!(hint.starts_with(".env here has values"), "{hint}");
        let onboard = format!("`kagebunshin onboard {}`", d.display());
        assert!(hint.contains(&onboard), "{hint}");
        assert!(
            tell.unwrap()
                .ends_with(&format!("run {onboard} in a terminal"))
        );
    }

    #[test]
    fn only_the_unknown_project_error_is_steered() {
        let unknown = |message: &str| CliError::new(Exit::Failure, "no_project", message);
        let e = steer_unknown_project(unknown(
            "unknown project: no project claims github.com/acme/x; run kagebunshin project init",
        ));
        assert_eq!(
            e.message,
            "unknown project: no project claims github.com/acme/x"
        );
        assert!(e.who.is_some());
        assert!(e.hint.unwrap().contains("kagebunshin"));
        for e in [
            unknown("no project named x"),
            unknown("unknown project: two projects claim it; run kagebunshin project init")
                .with_hint("kept"),
            CliError::new(
                Exit::Failure,
                "config",
                "unknown project: x; run kagebunshin project init",
            ),
        ] {
            let before = (e.message.clone(), e.hint.clone());
            let after = steer_unknown_project(e);
            assert_eq!((after.message, after.hint), before);
        }
    }

    #[test]
    fn onboard_fills_only_an_environment_reading_its_store_section() {
        let dir = tempfile::tempdir().unwrap();
        let config = ConfigDir::new(dir.path().to_path_buf());
        std::fs::create_dir_all(config.projects_dir()).unwrap();
        std::fs::write(
            config.path().join("config.toml"),
            "schema = 1\ndefault_provider = \"aws_sm\"\n",
        )
        .unwrap();
        std::fs::write(
            config.project_file(&"trap".parse().unwrap()),
            r#"schema = 1
remotes = ["github.com/acme/trap"]

[envs.empty]

[envs.store]
[[envs.store.sources]]
provider = "file"

[envs.other]
[[envs.other.sources]]
provider = "file"
secret = "elsewhere.dev"

[envs.aws]
[[envs.aws.sources]]
provider = "aws_sm"
secret = "trap/aws"
"#,
        )
        .unwrap();
        let registry = Registry::load(&config).unwrap();
        let p = registry.project(&"trap".parse().unwrap()).unwrap();
        let file = Path::new("/src/trap/.env");
        let fill = |env: &str| fillable(&registry, p, &env.parse().unwrap(), file);
        // With no sources it reads aws_sm here, the default provider.
        for env in ["empty", "other", "aws"] {
            let e = fill(env).unwrap_err();
            assert!(e.message.contains("has sources other than"), "{env}");
            assert!(
                e.hint
                    .unwrap()
                    .contains("`kagebunshin onboard --file /src/trap/.env --env ENV`")
            );
        }
        assert!(fill("store").is_ok());
        let e = fill("qa").unwrap_err();
        assert!(e.message.contains("has no environment qa"), "{}", e.message);
        assert!(
            e.hint
                .unwrap()
                .contains("`kagebunshin onboard --file /src/trap/.env --env qa`")
        );
    }
}
