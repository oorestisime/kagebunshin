//! `project facts`: what a checkout and the connected providers say, names
//! only. `project draft` builds a project file from these facts.

use std::collections::BTreeSet;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::edit::config;
use super::{CliError, Exit, print_json, print_line};
use crate::config::schema::Profile;
use crate::config::{ConfigDir, Git, Project, ProjectPath, Registry, RemoteId, SourceSpec};
use crate::daemon::resolve::{named_production, prod_like, prod_like_profile};
use crate::ipc::client::{Client, ClientError};
use crate::ipc::protocol::{EnvCheck, ErrorCode, Request, Response};
use crate::repo;
use crate::repo::facts::{self, CheckoutFacts, Mentions};
use crate::repo::workflows::{self, SecretList};
use crate::source::ProviderStatus;
use crate::source::aws_sm::AwsSettings;
use crate::store::Section;
use crate::types::{EnvName, KeyName, ProjectName, Provider};

/// AWS profiles checked at most.
const MAX_PROFILES: usize = 16;

/// Everything `project facts` reports, and what `project draft` drafts from.
#[derive(Debug, Serialize)]
pub(super) struct Gathered {
    pub root: PathBuf,
    /// The folder asked about, relative to `root`; empty for the root.
    pub here: PathBuf,
    pub remotes: Vec<RemoteId>,
    #[serde(flatten)]
    pub checkout: CheckoutFacts,
    /// Projects whose remotes include this checkout's.
    pub projects: Vec<Claim>,
    /// `None` when the daemon does not answer; then nothing is known about
    /// the providers.
    pub daemon: Option<DaemonFacts>,
    pub profiles: Vec<ProfileFacts>,
    /// Secret names the usable profiles list that the checkout's tracked
    /// files name.
    pub named_in_files: Mentions,
    /// The lists of those names in the checkout's workflows: what a deploy
    /// loads, in its order.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub workflow_lists: Vec<SecretList>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct Claim {
    pub project: ProjectName,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<ProjectPath>,
}

#[derive(Debug, Serialize)]
pub(super) struct DaemonFacts {
    pub locked: bool,
    /// The providers connected, and whether each reads now.
    pub providers: Vec<ProviderStatus>,
}

#[derive(Debug, Serialize)]
pub(super) struct ProfileFacts {
    pub name: String,
    /// Whether it could list secrets just now.
    pub usable: bool,
    /// Why it is not usable, or was not checked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    /// The names it listed, in the order AWS gave them.
    #[serde(skip)]
    pub secrets: Vec<String>,
    pub secret_count: usize,
}

/// `kagebunshin project facts [--path DIR]`.
pub(super) fn facts(
    socket: Option<PathBuf>,
    json: bool,
    path: Option<&Path>,
) -> Result<(), CliError> {
    let g = gather(socket, path)?;
    if json {
        return print_json(&g);
    }
    print_line(&render(&g))
}

/// What the checkout containing `path` (else the working directory) and
/// the providers the daemon reaches say. Fails only when that is not a git
/// checkout.
pub(super) fn gather(socket: Option<PathBuf>, path: Option<&Path>) -> Result<Gathered, CliError> {
    let cwd = std::env::current_dir().map_err(config)?;
    let dir = path.map_or_else(|| cwd.clone(), |p| cwd.join(p));
    if !dir.is_dir() {
        return Err(super::usage(format!("{} is not a folder", dir.display())));
    }
    let checkout = Git::default().checkout(&dir).map_err(|e| {
        CliError::new(Exit::Failure, "no_project", e.to_string())
            .with_hint("run this in the project's git checkout, or give --path DIR")
    })?;
    let root = checkout
        .root
        .canonicalize()
        .unwrap_or_else(|_| checkout.root.clone());
    let here = checkout.subdir(&dir).unwrap_or_default();
    let mut notes = Vec::new();

    let projects = match ConfigDir::from_env()
        .map_err(|e| e.to_string())
        .and_then(|d| Registry::load(&d).map_err(|e| e.to_string()))
    {
        Ok(registry) => registry
            .projects()
            .filter(|p| p.file.remotes.iter().any(|r| checkout.remotes.contains(r)))
            .map(|p| Claim {
                project: p.name.clone(),
                path: p.file.path.clone(),
            })
            .collect(),
        Err(e) => {
            notes.push(format!("cannot read the kagebunshin configuration: {e}"));
            Vec::new()
        }
    };

    let mut client = super::connect(socket).ok();
    let daemon = client.as_mut().and_then(|c| {
        let Ok(Response::Status(status)) = c.request(Request::Status { facts: None }) else {
            return None;
        };
        let providers = match c.request(Request::Providers {
            facts: None,
            every: false,
        }) {
            Ok(Response::Providers { providers }) => providers,
            _ => Vec::new(),
        };
        Some(DaemonFacts {
            locked: status.locked,
            providers,
        })
    });
    if daemon.is_none() {
        notes.push(format!(
            "the daemon does not answer, so no provider was asked; a human starts it: {}",
            super::error::start_daemon_hint()
        ));
    }

    let mut names = crate::source::aws_sm::connect::profile_names(
        crate::source::aws_sm::connect::profiles().as_ref(),
    );
    if names.len() > MAX_PROFILES {
        notes.push(format!(
            "checked only the first {MAX_PROFILES} of {} AWS profiles",
            names.len()
        ));
        names.truncate(MAX_PROFILES);
    }
    let profiles: Vec<ProfileFacts> = names
        .into_iter()
        .map(|name| profile_facts(client.as_mut().filter(|_| daemon.is_some()), name))
        .collect();

    let mut listed: Vec<String> = Vec::new();
    for p in profiles.iter().filter(|p| p.usable) {
        for n in &p.secrets {
            if !listed.contains(n) {
                listed.push(n.clone());
            }
        }
    }
    let (named_in_files, workflow_lists) = if listed.is_empty() {
        (Mentions::default(), Vec::new())
    } else {
        match Git::default().tracked_files(&checkout.root) {
            Ok(files) => (
                facts::mentions(&root, &files, &listed),
                workflows::secret_lists(&root, &files, &listed),
            ),
            Err(e) => {
                notes.push(format!("cannot list the checkout's tracked files: {e}"));
                (Mentions::default(), Vec::new())
            }
        }
    };

    Ok(Gathered {
        checkout: facts::read(&root),
        root,
        here,
        remotes: checkout.remotes,
        projects,
        daemon,
        profiles,
        named_in_files,
        workflow_lists,
        notes,
    })
}

/// Whether profile `name` can list secrets now, through the daemon, and
/// the names it lists. A profile that looks like production is not asked.
fn profile_facts(client: Option<&mut Client>, name: String) -> ProfileFacts {
    let mut out = ProfileFacts {
        name,
        usable: false,
        why: None,
        secrets: Vec::new(),
        secret_count: 0,
    };
    if let Some(why) = prod_like_profile(&out.name) {
        out.why = Some(format!("not checked: it looks like production ({why})"));
        return out;
    }
    let Some(client) = client else {
        out.why = Some("not checked: the daemon does not answer".into());
        return out;
    };
    let Ok(profile) = Profile::try_from(out.name.clone()) else {
        out.why = Some("not checked: not a valid profile name".into());
        return out;
    };
    let listed = client.request(Request::List {
        provider: Some(Provider::AwsSm),
        prefix: String::new(),
        search: None,
        aws: AwsSettings {
            profile: Some(profile),
            region: None,
        },
        keys: false,
    });
    match listed {
        Ok(Response::Listed { items, .. }) => {
            out.usable = true;
            out.secrets = items.into_iter().map(|l| l.name).collect();
            out.secret_count = out.secrets.len();
        }
        Ok(_) => out.why = Some("the daemon gave an unexpected reply".into()),
        Err(ClientError::Daemon(w)) => {
            out.why = Some(match w.hint {
                Some(h) => format!("{} ({h})", w.message),
                None => w.message,
            });
        }
        Err(e) => out.why = Some(e.to_string()),
    }
    out
}

fn render(g: &Gathered) -> String {
    let shown = |p: &Path| {
        if p.as_os_str().is_empty() {
            "the repository root".to_owned()
        } else {
            p.display().to_string()
        }
    };
    let remotes: Vec<String> = g.remotes.iter().map(ToString::to_string).collect();
    let mut out = format!(
        "checkout {} (remotes: {})",
        g.root.display(),
        if remotes.is_empty() {
            "none".to_owned()
        } else {
            remotes.join(", ")
        }
    );
    if g.checkout.apps.is_empty() {
        out.push_str("\napps: none (no .env.example or env file)");
    } else {
        out.push_str("\napps:");
    }
    for app in &g.checkout.apps {
        out.push_str(&format!("\n  {}", shown(&app.dir)));
        if let Some(e) = &app.example {
            let keys: Vec<String> = e
                .keys
                .iter()
                .map(|k| {
                    if k.has_value {
                        format!("{} (has a value)", k.key)
                    } else {
                        k.key.to_string()
                    }
                })
                .collect();
            match &e.problem {
                Some(p) => out.push_str(&format!("\n    .env.example: {p}")),
                None => out.push_str(&format!("\n    .env.example: {}", keys.join(", "))),
            }
        }
        for f in &app.env_files {
            let set = f.keys.iter().filter(|k| k.has_value).count();
            let what = f
                .problem
                .clone()
                .unwrap_or_else(|| format!("{} keys, {set} with a value", f.keys.len()));
            out.push_str(&format!("\n    {}: {what}", f.name));
        }
    }
    if !g.projects.is_empty() {
        let claims: Vec<String> = g
            .projects
            .iter()
            .map(|c| match &c.path {
                Some(p) => format!("{} ({p})", c.project),
                None => format!("{} (whole repository)", c.project),
            })
            .collect();
        out.push_str(&format!("\nprojects claiming it: {}", claims.join(", ")));
    }
    if let Some(d) = &g.daemon {
        out.push_str(&format!(
            "\ndaemon: {}",
            if d.locked { "locked" } else { "unlocked" }
        ));
        super::render_providers(&mut out, &d.providers);
    }
    if !g.profiles.is_empty() {
        out.push_str("\naws profiles:");
        for p in &g.profiles {
            match (&p.why, p.usable) {
                (_, true) => out.push_str(&format!(
                    "\n  {}: usable, lists {} secrets",
                    p.name, p.secret_count
                )),
                (Some(why), false) => out.push_str(&format!("\n  {}: {why}", p.name)),
                (None, false) => out.push_str(&format!("\n  {}: not usable", p.name)),
            }
        }
    }
    if !g.named_in_files.found.is_empty() {
        out.push_str("\nsecrets named in the checkout's files:");
        for m in &g.named_in_files.found {
            let files: Vec<String> = m.files.iter().map(|f| f.display().to_string()).collect();
            out.push_str(&format!("\n  {}: {}", m.name, files.join(", ")));
        }
    }
    if !g.workflow_lists.is_empty() {
        out.push_str("\nsecret lists in the workflows, in their order:");
        for l in &g.workflow_lists {
            let mut what = match &l.env {
                Some(e) => format!("environment {e}"),
                None => "no environment named".to_owned(),
            };
            if let Some(d) = &l.dir {
                what.push_str(&format!(", runs in {}", d.display()));
            }
            out.push_str(&format!("\n  {} ({what}): {}", l.at(), l.names.join(", ")));
        }
    }
    for n in g
        .checkout
        .capped
        .iter()
        .chain(&g.named_in_files.capped)
        .chain(&g.notes)
    {
        out.push_str(&format!("\nnote: {n}"));
    }
    out
}

/// What `project apply` did, or would do. Names and origins, never values.
#[derive(Debug, Serialize)]
pub(super) struct Applied {
    pub project: ProjectName,
    /// Where it was installed; `None` when nothing was.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub written: Option<PathBuf>,
    /// The projects it replaces: one of its name, or one claiming the
    /// same checkout.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub replaces: Vec<ProjectName>,
    /// What changes against `replaces`, source by source.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub changes: Vec<String>,
    /// The `.env.example` the keys were compared against.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub example: Option<PathBuf>,
    pub envs: Vec<EnvCheck>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl Applied {
    /// The environments that did not resolve, leaving out those marked
    /// sensitive, which are not read.
    fn failed(&self) -> Vec<&EnvName> {
        self.envs
            .iter()
            .filter(|e| {
                e.error
                    .as_ref()
                    .is_some_and(|w| w.code != ErrorCode::SensitiveEnv)
            })
            .map(|e| &e.env)
            .collect()
    }
}

/// `kagebunshin project apply FILE [--name NAME] [--check]`.
pub(super) fn apply(
    socket: Option<PathBuf>,
    json: bool,
    file: &Path,
    name: Option<&ProjectName>,
    check: bool,
) -> Result<(), CliError> {
    let (text, project) = super::project::load_file(file, name).map_err(|mut e| {
        e.message = format!(
            "the project file does not load, so nothing was installed: {}",
            e.message
        );
        e
    })?;
    let cwd = std::env::current_dir().map_err(config)?;
    let mut client = super::connect(socket)?;
    let again = format!("kagebunshin project apply {}", file.display());
    let applied = install(&mut client, &text, project, &cwd, check, &again, &[])?;
    if json {
        print_json(&applied)?;
    } else {
        print_line(&render_applied(&applied, check))?;
    }
    applied_result(&applied)
}

/// Fails when an environment of `applied` did not resolve.
pub(super) fn applied_result(applied: &Applied) -> Result<(), CliError> {
    let failed = applied.failed();
    if failed.is_empty() {
        return Ok(());
    }
    let names: Vec<String> = failed.iter().map(ToString::to_string).collect();
    Err(CliError::new(
        Exit::Failure,
        "source_failed",
        format!(
            "environment {} of project {} does not resolve, so nothing was installed",
            names.join(", "),
            applied.project
        ),
    ))
}

/// Checks project file `text`, parsed as `project`, in a dry run through
/// the daemon, comparing against the `.env.example` of the checkout of
/// `at` if it is one of the project's; then, unless `check` or an
/// environment other than those of `tolerate` does not resolve, installs
/// it, replacing a project of its name or one claiming the same checkout. Holds the config lock from
/// loading the other projects to the write. `again` is the command to run
/// once a refusal is settled.
pub(super) fn install(
    client: &mut Client,
    text: &str,
    project: Project,
    at: &Path,
    check: bool,
    again: &str,
    tolerate: &[EnvName],
) -> Result<Applied, CliError> {
    let dir = ConfigDir::from_env().map_err(config)?;
    let _lock = if check {
        None
    } else {
        Some(super::edit::lock(&dir)?)
    };
    let registry = Registry::load(&dir).map_err(config)?;
    let name = project.name.clone();
    let claims = |p: &Project| -> Vec<(RemoteId, Option<ProjectPath>)> {
        (p.file.remotes.iter())
            .map(|r| (r.clone(), p.file.path.clone()))
            .collect()
    };
    let ours = claims(&project);
    let replaced: Vec<&Project> = registry
        .projects()
        .filter(|p| p.name == name || claims(p).iter().any(|c| ours.contains(c)))
        .collect();
    refuse_loosening(client, &project, &replaced, again)?;

    let dest = dir.project_file(&name);
    let mut projects: Vec<Project> = registry
        .projects()
        .filter(|p| !replaced.iter().any(|r| r.name == p.name))
        .cloned()
        .collect();
    let mut new = project.clone();
    new.path.clone_from(&dest);
    projects.push(new);
    let edited = Registry::new(registry.config.clone(), projects).map_err(config)?;
    let mut warnings = super::project::profile_warnings(&edited, &name)?;
    let changes = changes(&registry, &replaced, &edited, &name);
    let (example, found) = match example_for(at, &project) {
        Ok(found) => (found.as_ref().map(|f| f.path.clone()), found),
        Err(e) => {
            warnings.push(format!("cannot read the .env.example to compare with: {e}"));
            (None, None)
        }
    };
    let reply = client.request(Request::CheckProject {
        project: name.clone(),
        text: text.to_owned(),
        example_keys: found.as_ref().map(|f| f.example.keys.clone()),
        example_values: found
            .as_ref()
            .map(|f| f.example.values.keys().cloned().collect())
            .unwrap_or_default(),
    })?;
    let Response::Checked(report) = reply else {
        return Err(super::unexpected());
    };
    let mut envs = report.envs;
    if let Some(f) = &found {
        for env in &mut envs {
            if let Some(st) = &mut env.status {
                let more = super::set_var_fixes(&name, &env.env, &st.missing, &f.example.values);
                st.fixes.extend(more);
            }
        }
    }
    let mut applied = Applied {
        project: name.clone(),
        written: None,
        replaces: replaced.iter().map(|p| p.name.clone()).collect(),
        changes,
        example,
        envs,
        warnings,
    };
    if check || applied.failed().iter().any(|e| !tolerate.contains(e)) {
        return Ok(applied);
    }

    std::fs::create_dir_all(dir.projects_dir()).map_err(|e| {
        config(format!(
            "cannot create {}: {e}",
            dir.projects_dir().display()
        ))
    })?;
    // A project of another name that claims the checkout goes first, so
    // the two never claim it at once.
    for old in replaced.iter().filter(|p| p.name != name) {
        std::fs::remove_file(&old.path)
            .map_err(|e| config(format!("cannot remove {}: {e}", old.path.display())))?;
    }
    let written = super::edit::write(&dest, text)?;
    let target = (!applied.replaces.is_empty()).then(|| {
        let names: Vec<String> = applied.replaces.iter().map(ToString::to_string).collect();
        format!("replacing {}", names.join(", "))
    });
    crate::audit::record_edit("project apply", &name, None, Vec::new(), target);
    // The cache is keyed by name: values fetched for the old file must not
    // be served for the new one.
    for old in &replaced {
        for env in old.file.envs.keys() {
            let _ = client.request(Request::Sync {
                project: Some(old.name.clone()),
                env: Some(env.clone()),
            });
        }
    }
    applied.written = Some(written);
    Ok(applied)
}

/// Refuses a replacement that would loosen what a human decided: drop a
/// `sensitive` flag the file has (copied into the store only at the next
/// unlock), or, for a project with marks or acknowledgements in the store,
/// change its name, remotes or folder, or drop a decided environment, as
/// `project remove` refuses.
fn refuse_loosening(
    client: &mut Client,
    project: &Project,
    replaced: &[&Project],
    again: &str,
) -> Result<(), CliError> {
    if replaced.is_empty() {
        return Ok(());
    }
    let refused = |what: String| {
        CliError::new(
            Exit::Refused,
            "config",
            format!("{what}; nothing was installed"),
        )
    };
    // A flag marks an environment of the project of its name, or a secret.
    let flags = |p: &Project| -> Vec<String> {
        let mut out = Vec::new();
        for (env, file) in &p.file.envs {
            if file.sensitive {
                out.push(format!("environment {env} of project {}", p.name));
            }
            for s in &file.sources {
                out.extend(s.sensitive.iter().map(|n| format!("secret {n}")));
            }
        }
        out
    };
    let kept = flags(project);
    for old in replaced {
        let dropped: Vec<String> = flags(old)
            .into_iter()
            .filter(|f| !kept.contains(f))
            .collect();
        if !dropped.is_empty() {
            return Err(refused(format!(
                "project {}'s file flags {} sensitive, and the new file drops that flag",
                old.name,
                dropped.join(", ")
            ))
            .with_hint(format!(
                "keep the flag in the file, then run `{again}` again; a flag is copied into the \
                 store only at the next unlock, so dropping it could loosen it"
            )));
        }
    }
    let listing = match client.request(Request::StoreList) {
        Ok(Response::StoreList(l)) => l,
        Ok(_) => return Err(super::unexpected()),
        // No store, so nothing decided.
        Err(ClientError::Daemon(w)) if w.code == ErrorCode::NoStore => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    for old in replaced {
        let ours = |s: &&Section| s.project == old.name;
        let decided: Vec<&EnvName> = (listing.sensitive_envs.iter().filter(ours))
            .chain(listing.acknowledged_envs.iter().filter(ours))
            .map(|s| &s.env)
            .collect();
        if decided.is_empty() {
            continue;
        }
        let mut old_remotes = old.file.remotes.clone();
        let mut new_remotes = project.file.remotes.clone();
        old_remotes.sort();
        new_remotes.sort();
        let what = if old.name != project.name {
            Some(format!("rename it to {}", project.name))
        } else if old_remotes != new_remotes {
            Some("change the remotes it claims".to_owned())
        } else if old.file.path != project.file.path {
            Some("change the folder it claims".to_owned())
        } else {
            decided
                .iter()
                .find(|e| !project.file.envs.contains_key(**e))
                .map(|e| format!("drop its environment {e}"))
        };
        if let Some(what) = what {
            let names: Vec<String> = decided.iter().map(ToString::to_string).collect();
            return Err(refused(format!(
                "the file would {what}, and project {} has a human's decisions in the store \
                 (environment {})",
                old.name,
                names.join(", ")
            ))
            .with_hint(format!(
                "a human takes them back in the app (`kagebunshin app`), then run `{again}` again"
            )));
        }
    }
    Ok(())
}

/// What installing `edited`'s project `name` changes against `replaced`,
/// one line per change, source by source. Empty for a new project.
fn changes(
    registry: &Registry,
    replaced: &[&Project],
    edited: &Registry,
    name: &ProjectName,
) -> Vec<String> {
    let Some(new) = edited.projects().find(|p| &p.name == name) else {
        return Vec::new();
    };
    let label = |s: &SourceSpec| match &s.aws.profile {
        Some(p) => format!("{} (profile {p})", super::edit::describe(s)),
        None => super::edit::describe(s),
    };
    let sources = |r: &Registry, p: &Project, env: &EnvName| -> Vec<String> {
        r.env(p, Some(env))
            .map(|s| s.sources.iter().map(label).collect())
            .unwrap_or_default()
    };
    let mut out = Vec::new();
    for old in replaced {
        let mut push = |line: String| out.push(format!("{}: {line}", old.name));
        if old.name != new.name {
            push(format!("renamed to {}", new.name));
        }
        if old.file.remotes != new.file.remotes {
            let shown = |r: &[RemoteId]| -> String {
                let v: Vec<String> = r.iter().map(ToString::to_string).collect();
                v.join(", ")
            };
            push(format!(
                "remotes {} become {}",
                shown(&old.file.remotes),
                shown(&new.file.remotes)
            ));
        }
        if old.file.path != new.file.path {
            let shown = |p: &Option<ProjectPath>| {
                p.as_ref()
                    .map_or_else(|| "the whole repository".to_owned(), ToString::to_string)
            };
            push(format!(
                "folder {} becomes {}",
                shown(&old.file.path),
                shown(&new.file.path)
            ));
        }
        for env in old.file.envs.keys() {
            if !new.file.envs.contains_key(env) {
                push(format!("removes environment {env}"));
            }
        }
        for (env, file) in &new.file.envs {
            let Some(was) = old.file.envs.get(env) else {
                push(format!("adds environment {env}"));
                continue;
            };
            let before = sources(registry, old, env);
            let after = sources(edited, new, env);
            for s in before.iter().filter(|s| !after.contains(s)) {
                push(format!("{env}: removes {s}"));
            }
            for s in after.iter().filter(|s| !before.contains(s)) {
                push(format!("{env}: adds {s}"));
            }
            let kept: Vec<&String> = after.iter().filter(|s| before.contains(s)).collect();
            let kept_before: Vec<&String> = before.iter().filter(|s| after.contains(s)).collect();
            if kept != kept_before {
                push(format!("{env}: changes the order of its sources"));
            }
            for (k, v) in &file.vars {
                match was.vars.get(k) {
                    None => push(format!("{env}: sets {k}")),
                    Some(w) if w != v => push(format!("{env}: changes {k}")),
                    Some(_) => {}
                }
            }
            for k in was.vars.keys().filter(|k| !file.vars.contains_key(*k)) {
                push(format!("{env}: unsets {k}"));
            }
        }
    }
    out
}

/// The `.env.example` of the checkout containing `at`, when that checkout
/// is one of `project`'s: its `env_example`, else the nearest one from
/// `at` (or from its folder, when `at` is outside it). `None` outside such
/// a checkout.
fn example_for(at: &Path, project: &Project) -> Result<Option<repo::Found>, String> {
    let Ok(checkout) = Git::default().checkout(at) else {
        return Ok(None);
    };
    if !checkout
        .remotes
        .iter()
        .any(|r| project.file.remotes.contains(r))
    {
        return Ok(None);
    }
    let top = project.file.path.as_ref().map(ProjectPath::as_path);
    let inside = match (top, checkout.subdir(at)) {
        (Some(t), Some(sub)) => sub.starts_with(t),
        (None, Some(_)) => true,
        (_, None) => false,
    };
    let start = match top {
        Some(t) if !inside => checkout.root.join(t),
        _ => at.to_owned(),
    };
    repo::load(
        &checkout.root,
        &start,
        top,
        project.file.env_example.as_deref(),
    )
    .map_err(|e| e.to_string())
}

/// What becomes of an installed environment that looks like production:
/// one named so outright is the agent's to mark, the rest wait for a
/// human.
fn waits(env: &EnvName) -> &'static str {
    if named_production(env) {
        "`kagebunshin next` has you mark it sensitive"
    } else {
        "its values wait for a human's decision"
    }
}

/// `applied` as text: per environment, what is set, missing, extra,
/// conflicting, skipped or waiting for a human.
fn render_applied(a: &Applied, check: bool) -> String {
    let mut out = format!("project: {}", a.project);
    if !a.replaces.is_empty() {
        let names: Vec<String> = a.replaces.iter().map(ToString::to_string).collect();
        out.push_str(&format!("\nreplaces: {}", names.join(", ")));
        if a.changes.is_empty() {
            out.push_str("\n  no change");
        }
        for c in &a.changes {
            out.push_str(&format!("\n  {c}"));
        }
    }
    match &a.example {
        Some(p) => out.push_str(&format!("\n.env.example: {}", p.display())),
        None => out.push_str("\n.env.example: none found, so no keys are missing or extra"),
    }
    for e in &a.envs {
        out.push_str(&format!("\nenv {}:", e.env));
        if let Some(w) = &e.error {
            out.push_str(&format!("\n  does not resolve: {}", w.message));
            if let Some(h) = &w.hint {
                out.push_str(&format!("\n  hint: {h}"));
            }
            continue;
        }
        let Some(st) = &e.status else { continue };
        let set = st.keys.len() + st.vars.len();
        out.push_str(&format!(
            "\n  {set} {} set",
            super::plural(set, "key", "keys")
        ));
        let mut origins: Vec<(String, usize)> = Vec::new();
        for o in st.keys.iter().map(|k| k.origin.to_string()) {
            match origins.iter_mut().find(|(x, _)| *x == o) {
                Some((_, n)) => *n += 1,
                None => origins.push((o, 1)),
            }
        }
        for (o, n) in origins {
            out.push_str(&format!("\n    {n} from {o}"));
        }
        if !st.vars.is_empty() {
            out.push_str(&format!("\n    {} from the project file", st.vars.len()));
        }
        let list = |out: &mut String, title: &str, keys: &[String]| {
            if !keys.is_empty() {
                out.push_str(&format!("\n  {title}: {}", keys.join(", ")));
            }
        };
        let names = |k: &[KeyName]| -> Vec<String> { k.iter().map(ToString::to_string).collect() };
        list(
            &mut out,
            "missing (in .env.example, set by no source)",
            &names(&st.missing),
        );
        list(
            &mut out,
            "extra (set, not in .env.example)",
            &names(&e.extra),
        );
        list(&mut out, "skipped (not JSON objects)", &st.skipped);
        for c in &e.conflicts {
            let lost: Vec<String> = c.overridden.iter().map(ToString::to_string).collect();
            out.push_str(&format!(
                "\n  conflict: {} is set by {} and {}; the last wins",
                c.key,
                lost.join(", "),
                c.origin
            ));
        }
        if let Some(why) = &e.waiting {
            out.push_str(&format!(
                "\n  looks like production ({why}): once installed, {}",
                waits(&e.env)
            ));
        }
        for w in &st.warnings {
            out.push_str(&format!("\n  warning: {w}"));
        }
        if !st.fixes.is_empty() {
            out.push_str("\n  to fill in what is missing:");
            for f in &st.fixes {
                out.push_str(&format!("\n    {}\n      ({})", f.command, f.note));
            }
        }
    }
    for w in &a.warnings {
        out.push_str(&format!("\nwarning: {w}"));
    }
    match (&a.written, check) {
        (Some(p), _) => out.push_str(&format!("\ninstalled {}", p.display())),
        (None, true) => out.push_str("\nchecked only; nothing was installed"),
        (None, false) => out.push_str("\nnothing was installed"),
    }
    out
}

/// `applied` after `project draft --apply`, which has just listed the
/// sources and the open points: only what installing added to that.
fn render_installed(a: &Applied) -> String {
    let mut out = String::new();
    for e in &a.envs {
        if let Some(w) = &e.error {
            out.push_str(&format!(
                "environment {} does not resolve: {}\n",
                e.env, w.message
            ));
            if let Some(h) = &w.hint {
                out.push_str(&format!("  hint: {h}\n"));
            }
            continue;
        }
        let Some(st) = &e.status else { continue };
        out.push_str(&format!(
            "environment {}: {}\n",
            e.env,
            super::next::counted(st)
        ));
        for c in &e.conflicts {
            let lost: Vec<String> = c.overridden.iter().map(ToString::to_string).collect();
            out.push_str(&format!(
                "  conflict: {} is set by {} and {}; the last wins\n",
                c.key,
                lost.join(", "),
                c.origin
            ));
        }
        if let Some(why) = &e.waiting {
            out.push_str(&format!(
                "  looks like production ({why}): {}\n",
                waits(&e.env)
            ));
        }
        for w in &st.warnings {
            out.push_str(&format!("  warning: {w}\n"));
        }
    }
    for w in &a.warnings {
        out.push_str(&format!("warning: {w}\n"));
    }
    match &a.written {
        Some(p) => out.push_str(&format!(
            "installed as {}; `kagebunshin next` says what is left",
            p.display()
        )),
        None => out.push_str("nothing was installed"),
    }
    out
}

/// Secrets a profile lists above which `project draft` does not read their
/// key names: each takes one `GetSecretValue`.
const MAX_KEYED: usize = 200;

/// Who can run a step: the caller, or a human (the passphrase, the app, a
/// login or a decision).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Who {
    Agent,
    Human,
}

/// A command that settles an open point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct Step {
    pub command: String,
    pub who: Who,
    /// For a human step: the sentence to pass on to them.
    pub tell: Option<String>,
}

impl Step {
    fn agent(command: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            who: Who::Agent,
            tell: None,
        }
    }

    fn human(command: impl Into<String>, why: &str) -> Self {
        let command = command.into();
        let tell = Some(format!("Please run `{command}`: {why}."));
        Self {
            command,
            who: Who::Human,
            tell,
        }
    }
}

/// Something the draft does not decide, with the commands that settle it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct Open {
    pub note: String,
    pub steps: Vec<Step>,
}

/// A source the draft writes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum Drafted {
    Prefix { prefix: String },
    Secrets { names: Vec<String> },
    Plain { secret: String, key: KeyName },
}

impl Drafted {
    /// The `project add-source` arguments after `--provider`.
    fn args(&self) -> String {
        match self {
            Self::Prefix { prefix } => format!("aws_sm --prefix {prefix}"),
            Self::Secrets { names } => {
                let s: Vec<String> = names.iter().map(|n| format!("--secret {n}")).collect();
                format!("aws_sm {}", s.join(" "))
            }
            Self::Plain { secret, key } => format!("aws_sm --secret {secret} --key {key}"),
        }
    }

    fn describe(&self) -> String {
        match self {
            Self::Prefix { prefix } => format!("aws_sm prefix {prefix}"),
            Self::Secrets { names } => format!("aws_sm secrets {}", names.join(", ")),
            Self::Plain { secret, key } => format!("aws_sm secret {secret} as {key}"),
        }
    }
}

/// A secret a usable AWS profile lists, with what `list --keys` said of
/// it. Names only.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Secret {
    name: String,
    keys: Vec<KeyName>,
    plain: bool,
    /// Why its keys were not read: marked sensitive, looks like production,
    /// or too many to read.
    unread: Option<String>,
    /// Its place among the names the checkout's tracked files name, by
    /// where each is first found; `None` when they do not name it.
    named: Option<usize>,
}

/// Which project and environment the commands in open points edit.
struct Target<'a> {
    project: &'a ProjectName,
    env: &'a EnvName,
}

impl Target<'_> {
    fn add_source(&self, args: &str, profile: Option<&str>) -> String {
        let mut c = format!(
            "kagebunshin project add-source {} {} --provider {args}",
            self.project, self.env
        );
        if let Some(p) = profile {
            c.push_str(&format!(" --profile {p}"));
        }
        c
    }
}

/// What one profile's secrets give for `example`'s keys.
#[derive(Debug, Default, PartialEq, Eq)]
struct Cover {
    sources: Vec<Drafted>,
    /// The keys of `example` the sources hold.
    covered: BTreeSet<KeyName>,
    /// Keys left to an open point.
    open_keys: BTreeSet<KeyName>,
    open: Vec<Open>,
    left_out: Vec<String>,
}

/// The upper-cased last segment of `name`, with `-` and `.` as `_`: what a
/// plain-string secret may be named for.
fn key_like(name: &str) -> String {
    let last = name.rsplit('/').next().unwrap_or(name);
    last.to_ascii_uppercase().replace(['-', '.'], "_")
}

/// Whether `like`'s words, split at `_`, are a run of `key`'s: `SIGNING` in
/// `SIGNING_KEY`, not `SIGN` in it.
fn words_in(like: &str, key: &KeyName) -> bool {
    let like: Vec<&str> = like.split('_').collect();
    let key: Vec<&str> = key.as_str().split('_').collect();
    !like.is_empty() && key.windows(like.len()).any(|w| w == like)
}

/// The one key of `keys` whose name `like` is part of ([`words_in`]).
fn near<'a>(like: &str, keys: &'a BTreeSet<KeyName>) -> Option<&'a KeyName> {
    let mut found = keys.iter().filter(|k| words_in(like, k));
    let first = found.next()?;
    found.next().is_none().then_some(first)
}

/// The sources that hold `example`'s keys among `secrets`, listed by
/// `profile`: first the secrets the checkout names (those holding a key of
/// `example`, or all when there is none), in the order it first names
/// them, then, greedily and in the order chosen, the secret that
/// holds the most keys still uncovered, as long as no other holds as many
/// of the same; then a plain string for a key its name matches exactly
/// (see [`key_like`]) when no other plain string does. Secrets that look
/// like production or whose keys were not read are never chosen. Several
/// secrets under one prefix become a prefix source when every secret under
/// it is chosen and none is a plain string or unread.
fn cover(t: &Target<'_>, profile: &str, secrets: &[Secret], example: &[KeyName]) -> Cover {
    let mut out = Cover::default();
    let want: BTreeSet<&KeyName> = example.iter().collect();
    let prod = |s: &Secret| prod_like(&s.name, &[]);
    for s in secrets.iter().filter(|s| s.named.is_some()) {
        if let Some(why) = prod(s) {
            out.left_out.push(format!(
                "secret {} (profile {profile}), named in the checkout's files: it looks like \
                 production ({why})",
                s.name
            ));
        } else if let Some(why) = &s.unread {
            out.left_out
                .push(format!("secret {} (profile {profile}): {why}", s.name));
        }
    }
    let usable: Vec<&Secret> = secrets
        .iter()
        .filter(|s| s.unread.is_none() && prod(s).is_none())
        .collect();
    let mut chosen: Vec<&Secret> = Vec::new();
    let mut named: Vec<&Secret> = (usable.iter().copied())
        .filter(|s| s.named.is_some() && !s.plain)
        .collect();
    named.sort_by_key(|s| s.named);
    for s in named {
        if want.is_empty() || s.keys.iter().any(|k| want.contains(k)) {
            chosen.push(s);
        } else {
            out.open.push(Open {
                note: format!(
                    "secret {} is named in the checkout's files but holds none of \
                     .env.example's keys, so it was left out",
                    s.name
                ),
                steps: vec![Step::agent(
                    t.add_source(&format!("aws_sm --secret {}", s.name), Some(profile)),
                )],
            });
        }
    }
    let mut uncovered: BTreeSet<KeyName> = want
        .iter()
        .filter(|k| !chosen.iter().any(|s| s.keys.contains(k)))
        .map(|k| (*k).clone())
        .collect();
    loop {
        let gain = |s: &Secret| -> BTreeSet<KeyName> {
            s.keys
                .iter()
                .filter(|k| uncovered.contains(*k))
                .cloned()
                .collect()
        };
        let candidates: Vec<(&Secret, BTreeSet<KeyName>)> = usable
            .iter()
            .filter(|s| !s.plain && !chosen.iter().any(|c| c.name == s.name))
            .map(|s| (*s, gain(s)))
            .filter(|(_, g)| !g.is_empty())
            .collect();
        let Some(best) = candidates.iter().map(|(_, g)| g.len()).max() else {
            break;
        };
        let top: Vec<&(&Secret, BTreeSet<KeyName>)> =
            candidates.iter().filter(|(_, g)| g.len() == best).collect();
        let (first, first_gain) = top[0];
        let rivals: Vec<&Secret> = (top[1..].iter())
            .filter(|(_, g)| !g.is_disjoint(first_gain))
            .map(|(s, _)| *s)
            .collect();
        if rivals.is_empty() {
            chosen.push(first);
            uncovered.retain(|k| !first_gain.contains(k));
            continue;
        }
        let tied: BTreeSet<KeyName> = (rivals.iter())
            .flat_map(|r| r.keys.iter().filter(|k| first_gain.contains(*k)))
            .cloned()
            .collect();
        let names: Vec<&str> = std::iter::once(*first)
            .chain(rivals.iter().copied())
            .map(|s| s.name.as_str())
            .collect();
        out.open.push(Open {
            note: format!(
                "{} {} held by each of {}; pick the one to read",
                join(&tied),
                if tied.len() == 1 { "is" } else { "are" },
                names.join(", ")
            ),
            steps: names
                .iter()
                .map(|n| Step::agent(t.add_source(&format!("aws_sm --secret {n}"), Some(profile))))
                .collect(),
        });
        uncovered.retain(|k| !tied.contains(k));
        out.open_keys.extend(tied);
    }

    let mut plains: Vec<Drafted> = Vec::new();
    for s in usable.iter().filter(|s| s.plain) {
        let like = key_like(&s.name);
        let same = usable
            .iter()
            .filter(|o| o.plain && key_like(&o.name) == like)
            .count();
        let key = uncovered.iter().find(|k| k.as_str() == like).cloned();
        match key {
            Some(key) if same == 1 => {
                uncovered.remove(&key);
                plains.push(Drafted::Plain {
                    secret: s.name.clone(),
                    key,
                });
            }
            // Its name is part of one key's, and of no other's: a guess
            // the agent can check, not one to make for it.
            None if near(&like, &uncovered).is_some_and(|key| {
                !usable
                    .iter()
                    .any(|o| o.plain && o.name != s.name && words_in(&key_like(&o.name), key))
            }) =>
            {
                let Some(key) = near(&like, &uncovered).cloned() else {
                    continue;
                };
                out.open_keys.insert(key.clone());
                out.open.push(Open {
                    note: format!(
                        "{key} is in no secret read; secret {} is a plain string whose name is \
                         part of that key's, so it may be its value",
                        s.name
                    ),
                    steps: vec![Step::agent(t.add_source(
                        &format!("aws_sm --secret {} --key {key}", s.name),
                        Some(profile),
                    ))],
                });
            }
            _ if s.named.is_some() => out.open.push(Open {
                note: format!(
                    "secret {} is a plain string, not a JSON object, and its name does not say \
                     which key it holds",
                    s.name
                ),
                steps: vec![Step::agent(t.add_source(
                    &format!("aws_sm --secret {} --key NAME", s.name),
                    Some(profile),
                ))],
            }),
            _ => {}
        }
    }

    // Prefixes, then the named secrets, then plain strings.
    let mut prefixed: Vec<String> = Vec::new();
    let mut parents: Vec<&str> = chosen
        .iter()
        .filter_map(|s| s.name.rfind('/').map(|i| &s.name[..=i]))
        .collect();
    parents.sort_unstable();
    parents.dedup();
    for p in parents {
        let under: Vec<&Secret> = secrets.iter().filter(|s| s.name.starts_with(p)).collect();
        let all_chosen = under
            .iter()
            .all(|s| chosen.iter().any(|c| c.name == s.name) && !s.plain && s.unread.is_none());
        if under.len() >= 2 && all_chosen && !prefixed.iter().any(|q| p.starts_with(q.as_str())) {
            prefixed.push(p.to_owned());
        }
    }
    let named: Vec<String> = chosen
        .iter()
        .filter(|s| !prefixed.iter().any(|p| s.name.starts_with(p.as_str())))
        .map(|s| s.name.clone())
        .collect();
    out.sources.extend(
        prefixed
            .into_iter()
            .map(|prefix| Drafted::Prefix { prefix }),
    );
    if !named.is_empty() {
        out.sources.push(Drafted::Secrets { names: named });
    }
    out.sources.extend(plains);

    // Two chosen secrets that set one key.
    let mut keys: BTreeSet<&KeyName> = BTreeSet::new();
    for s in &chosen {
        keys.extend(
            s.keys
                .iter()
                .filter(|k| want.is_empty() || want.contains(k)),
        );
    }
    for k in keys {
        let by: Vec<&str> = (chosen.iter())
            .filter(|s| s.keys.contains(k))
            .map(|s| s.name.as_str())
            .collect();
        if by.len() > 1 {
            out.open.push(Open {
                note: format!(
                    "{k} is set by each of {}; the later source wins",
                    by.join(", ")
                ),
                steps: vec![Step::agent(format!(
                    "kagebunshin project show {}",
                    t.project
                ))],
            });
        }
    }
    out.covered = want
        .iter()
        .filter(|k| !uncovered.contains(*k) && !out.open_keys.contains(*k))
        .map(|k| (*k).clone())
        .collect();
    out
}

fn join(keys: &BTreeSet<KeyName>) -> String {
    let v: Vec<&str> = keys.iter().map(KeyName::as_str).collect();
    v.join(", ")
}

/// One environment of a draft.
#[derive(Debug, Serialize)]
pub(super) struct EnvDraft {
    pub env: EnvName,
    /// The workflow list its secrets were taken from, as `FILE:LINE`.
    /// `None` when no workflow lists them: then the draft chose them, and
    /// their order is a guess.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    pub sources: Vec<Drafted>,
    /// The keys of `.env.example` the sources hold, as far as known.
    pub covered: Vec<KeyName>,
    pub open: Vec<Open>,
}

impl EnvDraft {
    /// Whether the draft chose several secrets itself, so that which one
    /// wins a key two of them hold is a guess.
    fn order_guessed(&self) -> bool {
        self.from.is_none()
            && self
                .sources
                .iter()
                .any(|s| matches!(s, Drafted::Secrets { names } if names.len() > 1))
    }
}

/// One app's draft: the project file, and what it leaves open.
#[derive(Debug, Serialize)]
pub(super) struct AppDraft {
    /// The app's folder, relative to the checkout root; empty for the root.
    pub dir: PathBuf,
    pub project: ProjectName,
    /// The default environment, then one for each list the checkout's
    /// workflows name for another.
    pub envs: Vec<EnvDraft>,
    /// What was left out because it looks like production, or was not read.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub left_out: Vec<String>,
    /// When the app's workflows list secrets: those the checkout's files
    /// name that no workflow loads, and no environment was given.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unused: Vec<String>,
    /// Why nothing was drafted for the app, and what to do instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instead: Option<Open>,
    /// A project already claims the app's folder.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claimed_by: Option<ProjectName>,
    /// The project file; empty when `instead` is set.
    pub toml: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applied: Option<Applied>,
}

impl AppDraft {
    /// How many points the draft leaves open, over its environments.
    pub(super) fn open_points(&self) -> usize {
        self.envs.iter().map(|e| e.open.len()).sum()
    }
}

/// `kagebunshin project draft [--path DIR] [--name NAME] [-o FILE] [--apply]`.
pub(super) fn draft(
    socket: Option<PathBuf>,
    json: bool,
    path: Option<&Path>,
    name: Option<&ProjectName>,
    output: Option<&Path>,
    apply: bool,
) -> Result<(), CliError> {
    let g = gather(socket.clone(), path)?;
    let all_apps = apply && path.is_none() && g.checkout.apps.len() > 1;
    let mut apps: Vec<facts::App> = if all_apps {
        g.checkout.apps.clone()
    } else {
        vec![pick_app(&g.root, &g.here, &g.checkout.apps)?]
    };
    // An app `onboard --exclude` left out is passed over with the rest of
    // its checkout, while no project claims it and this is not its folder.
    let left_out = super::onboard::LeftOut::read();
    let mut passed = Vec::new();
    if all_apps {
        apps.retain(|a| {
            let claimed = (g.projects.iter())
                .any(|c| c.path.as_ref().map_or(Path::new(""), |p| p.as_path()) == a.dir);
            let out = a.dir != g.here && !claimed && left_out.holds(&g.root.join(&a.dir));
            if out {
                passed.push(shown_dir(&a.dir));
            }
            !out
        });
    }
    if apps.len() > 1 && (name.is_some() || output.is_some()) {
        return Err(super::usage(
            "--name and -o name one project; give --path DIR to draft one app",
        ));
    }
    let again = "kagebunshin project draft --apply";
    let (drafted, mut notes) = draft_apps(socket, &g, &apps, name, apply.then_some(again))?;
    if !passed.is_empty() {
        notes.push(format!(
            "left out, as `kagebunshin onboard --exclude` said: {}; `kagebunshin onboard DIR` \
             sets one up",
            passed.join(", ")
        ));
    }
    let mut failed: Option<CliError> = None;
    let mut drafts = Vec::new();
    for (d, error) in drafted {
        if let Some(e) = error {
            failed.get_or_insert(e);
        }
        drafts.push(d);
    }

    let report = render_drafts(&drafts, &notes, apply, output);
    if json {
        #[derive(Serialize)]
        struct Out<'a> {
            drafts: &'a [AppDraft],
            #[serde(skip_serializing_if = "<[String]>::is_empty")]
            notes: &'a [String],
        }
        if let (Some(out), [d]) = (output, &drafts[..]) {
            super::edit::write(out, &d.toml)?;
        }
        print_json(&Out {
            drafts: &drafts,
            notes: &notes,
        })?;
    } else if apply {
        print_line(&report)?;
        if let (Some(out), [d]) = (output, &drafts[..]) {
            super::edit::write(out, &d.toml)?;
        }
    } else {
        let toml = drafts.first().map(|d| d.toml.as_str()).unwrap_or_default();
        if let Some(out) = output {
            super::edit::write(out, toml)?;
            print_line(&format!("{report}\nwrote {}", out.display()))?;
        } else {
            eprintln!("{report}");
            write!(std::io::stdout(), "{toml}").map_err(super::output_error)?;
        }
    }
    failed.map_or(Ok(()), Err)
}

/// The drafts, each with why it was not installed, if it was not, and the
/// notes about them all.
pub(super) type AppDrafts = (Vec<(AppDraft, Option<CliError>)>, Vec<String>);

/// Drafts a project for each of `apps` of the checkout `g` describes, named
/// `name` or after its folder, and with `again` (the command to run once
/// a refusal is settled) installs each through the daemon.
pub(super) fn draft_apps(
    socket: Option<PathBuf>,
    g: &Gathered,
    apps: &[facts::App],
    name: Option<&ProjectName>,
    again: Option<&str>,
) -> Result<AppDrafts, CliError> {
    let registry = ConfigDir::from_env()
        .map_err(|e| e.to_string())
        .and_then(|d| Registry::load(&d).map_err(|e| e.to_string()));
    let env = registry.as_ref().map_or_else(
        |_| crate::config::Config::default().default_env,
        |r| r.config.default_env.clone(),
    );
    let mut client = super::connect(socket).ok();
    let mut notes = g.notes.clone();
    if g.daemon.as_ref().is_some_and(|d| d.locked) {
        notes.push(
            "the daemon is locked, so no key names were read; a human runs `kagebunshin unlock`"
                .into(),
        );
    }
    let keyed = keyed_profiles(client.as_mut(), g, &mut notes);

    let mut dirs: Vec<&Path> = g.checkout.apps.iter().map(|a| a.dir.as_path()).collect();
    dirs.extend(apps.iter().map(|a| a.dir.as_path()));
    for l in g
        .workflow_lists
        .iter()
        .filter(|l| owner(&dirs, l).is_none())
    {
        notes.push(format!(
            "{} lists secrets ({}), and no app here is the folder it runs in, so no environment \
             was drafted from it",
            l.at(),
            l.names.join(", ")
        ));
    }

    let mut drafts = Vec::new();
    for app in apps {
        let project = match name {
            Some(n) => n.clone(),
            None => default_name(&g.root, &app.dir)?,
        };
        // One `onboard` of the root moves in every app's env file, and is
        // what `next` there asks for.
        let onboard_dir = match apps {
            [_] => g.root.join(&app.dir),
            _ => g.root.clone(),
        };
        let mut d = draft_app(g, app, project, &env, &keyed, &onboard_dir);
        if let Ok(r) = &registry
            && d.claimed_by.is_none()
            && r.project(&d.project).is_some()
        {
            d.claimed_by = Some(d.project.clone());
        }
        drafts.push(d);
    }

    let mut out = Vec::new();
    for mut d in drafts {
        let Some(again) = again else {
            out.push((d, None));
            continue;
        };
        if d.instead.is_some() {
            out.push((d, None));
            continue;
        }
        if let Some(owner) = &d.claimed_by {
            let file = format!("{}.toml", d.project);
            let mut redo = format!("kagebunshin project draft -o {file}");
            if !d.dir.as_os_str().is_empty() {
                redo = format!(
                    "kagebunshin project draft --path {} -o {file}",
                    g.root.join(&d.dir).display()
                );
            }
            let e = CliError::new(
                Exit::Failure,
                "config",
                format!(
                    "project {owner} already exists or claims {}, so nothing was installed",
                    shown_dir(&d.dir)
                ),
            )
            .with_hint(format!(
                "to replace it on purpose, `{redo}`, then `kagebunshin project apply {file}`"
            ));
            out.push((d, Some(e)));
            continue;
        }
        let Some(client) = client.as_mut() else {
            let e = CliError::new(
                Exit::DaemonNotRunning,
                "daemon_not_running",
                "the daemon does not answer, so nothing was installed",
            )
            .with_hint(super::error::start_daemon_hint());
            out.push((d, Some(e)));
            continue;
        };
        let parsed =
            crate::config::parse_project(Path::new(&format!("{}.toml", d.project)), &d.toml)
                .map_err(config)?;
        // An environment taken from a workflow is installed as the
        // workflow has it, whether or not it can be read now.
        let tolerate: Vec<EnvName> = d.envs.iter().skip(1).map(|e| e.env.clone()).collect();
        let at = g.root.join(&d.dir);
        let error = match install(client, &d.toml, parsed, &at, false, again, &tolerate) {
            Ok(applied) => {
                let e = match applied.written {
                    Some(_) => None,
                    None => applied_result(&applied).err(),
                };
                d.applied = Some(applied);
                e
            }
            Err(e) => Some(e),
        };
        out.push((d, error));
    }
    Ok((out, notes))
}

fn shown_dir(dir: &Path) -> String {
    if dir.as_os_str().is_empty() {
        "the whole repository".to_owned()
    } else {
        dir.display().to_string()
    }
}

/// The app `project draft` drafts without `--apply` over several: the one
/// at the folder asked about, else the nearest one above it, else the only
/// one. A folder that is no app gets an empty one.
pub(super) fn pick_app(
    root: &Path,
    here: &Path,
    apps: &[facts::App],
) -> Result<facts::App, CliError> {
    if let Some(app) = apps
        .iter()
        .filter(|a| here.starts_with(&a.dir))
        .max_by_key(|a| a.dir.components().count())
    {
        return Ok(app.clone());
    }
    let at_root = here.as_os_str().is_empty();
    match apps {
        [only] if at_root => Ok(only.clone()),
        [_, _, ..] if at_root => {
            let commands: Vec<String> = apps
                .iter()
                .map(|a| {
                    format!(
                        "`kagebunshin project draft --path {}`",
                        root.join(&a.dir).display()
                    )
                })
                .collect();
            Err(super::usage(format!(
                "the repository has {} apps; draft one at a time",
                apps.len()
            ))
            .with_hint(format!(
                "run {}, or `kagebunshin project draft --apply` to install one project per app",
                commands.join(" or ")
            )))
        }
        _ => Ok(facts::App {
            dir: here.to_owned(),
            example: None,
            env_files: Vec::new(),
        }),
    }
}

/// The project name for the app in `dir` of the checkout at `root`: the
/// checkout folder's name, as `onboard` takes it, and for an app folder
/// `<that>-<the app folder's name>`, lower-cased, other characters as `-`.
pub(super) fn default_name(root: &Path, dir: &Path) -> Result<ProjectName, CliError> {
    let slug = |p: &Path| -> String {
        let s = p
            .file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default();
        s.to_ascii_lowercase()
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '_' {
                    c
                } else {
                    '-'
                }
            })
            .collect::<String>()
            .trim_matches(['-', '_'])
            .to_owned()
    };
    let name = if dir.as_os_str().is_empty() {
        slug(root)
    } else {
        format!("{}-{}", slug(root), slug(dir))
    };
    name.parse().map_err(|_| {
        super::usage(format!("{name:?} is not a project name"))
            .with_hint("give one with --name NAME")
    })
}

/// The secrets each usable profile lists, with their key names read
/// through the daemon (`list --keys`), unless it lists more than
/// [`MAX_KEYED`].
fn keyed_profiles(
    mut client: Option<&mut Client>,
    g: &Gathered,
    notes: &mut Vec<String>,
) -> Vec<(String, Vec<Secret>)> {
    let named = |n: &str| g.named_in_files.found.iter().position(|m| m.name == n);
    let mut out = Vec::new();
    for p in g.profiles.iter().filter(|p| p.usable) {
        let bare = |n: &String, unread: Option<String>| Secret {
            name: n.clone(),
            keys: Vec::new(),
            plain: false,
            unread,
            named: named(n),
        };
        if p.secrets.len() > MAX_KEYED {
            notes.push(format!(
                "profile {} lists {} secrets, more than {MAX_KEYED}, so their key names were \
                 not read; see them under a prefix with `kagebunshin list --keys --prefix P \
                 --profile {}`",
                p.name,
                p.secrets.len(),
                p.name
            ));
            let why = || Some("its key names were not read: too many secrets".to_owned());
            out.push((
                p.name.clone(),
                p.secrets.iter().map(|n| bare(n, why())).collect(),
            ));
            continue;
        }
        let Some(c) = client.as_deref_mut() else {
            continue;
        };
        let Ok(profile) = Profile::try_from(p.name.clone()) else {
            continue;
        };
        let listed = c.request(Request::List {
            provider: Some(Provider::AwsSm),
            prefix: String::new(),
            search: None,
            aws: AwsSettings {
                profile: Some(profile),
                region: None,
            },
            keys: true,
        });
        match listed {
            Ok(Response::Listed { items, .. }) => out.push((
                p.name.clone(),
                items
                    .into_iter()
                    .map(|l| Secret {
                        named: named(&l.name),
                        name: l.name,
                        keys: l.keys,
                        plain: l.plain,
                        unread: l.unread,
                    })
                    .collect(),
            )),
            Ok(_) => notes.push(format!("profile {}: an unexpected reply", p.name)),
            Err(e) => notes.push(format!(
                "cannot read key names with profile {}: {e}",
                p.name
            )),
        }
    }
    out
}

/// The app, of `dirs`, that workflow list `l` is for: the deepest one
/// holding the folder the workflow runs in; for a workflow that names no
/// folder, the only app, else the one at the root.
fn owner<'d>(dirs: &[&'d Path], l: &SecretList) -> Option<&'d Path> {
    match &l.dir {
        Some(d) => (dirs.iter().copied())
            .filter(|a| d.starts_with(a))
            .max_by_key(|a| a.components().count()),
        None => match dirs {
            [only] => Some(only),
            _ => dirs.iter().copied().find(|a| a.as_os_str().is_empty()),
        },
    }
}

/// The checkout's app folders, and `dir` if it is none of them.
fn app_dirs<'a>(g: &'a Gathered, dir: &'a Path) -> Vec<&'a Path> {
    let mut dirs: Vec<&Path> = g.checkout.apps.iter().map(|a| a.dir.as_path()).collect();
    if !dirs.contains(&dir) {
        dirs.push(dir);
    }
    dirs
}

/// The list the workflows name for one environment.
#[derive(Debug, PartialEq, Eq)]
struct Picked<'a> {
    env: EnvName,
    list: &'a SecretList,
    /// Other lists for the environment that name a secret `list` does not.
    differing: Vec<&'a SecretList>,
    /// No workflow names the environment: it is the default one.
    unnamed: bool,
}

/// One list for each environment `lists` name, a list that names none
/// counting for `default`: the longest (one that names its environment
/// over one that does not, the first of equals), with the others that name
/// a secret it does not. The same list under two names is one environment:
/// `default`, else the first.
fn pick_lists<'a>(lists: &[&'a SecretList], default: &EnvName) -> Vec<Picked<'a>> {
    let mut by_env: Vec<Picked<'a>> = Vec::new();
    for &l in lists {
        let named = l.env.as_deref().and_then(|e| e.parse::<EnvName>().ok());
        let unnamed = named.is_none();
        let env = named.unwrap_or_else(|| default.clone());
        match by_env.iter_mut().find(|p| p.env == env) {
            None => by_env.push(Picked {
                env,
                list: l,
                differing: Vec::new(),
                unnamed,
            }),
            Some(p) => {
                let better = (p.unnamed && !unnamed)
                    || (p.unnamed == unnamed && l.names.len() > p.list.names.len());
                if better {
                    p.differing.push(std::mem::replace(&mut p.list, l));
                    p.unnamed = unnamed;
                } else {
                    p.differing.push(l);
                }
            }
        }
    }
    let mut out: Vec<Picked<'a>> = Vec::new();
    for mut p in by_env {
        let main = p.list;
        p.differing
            .retain(|l| l.names.iter().any(|n| !main.names.contains(n)));
        p.differing.sort_by_key(|l| (&l.file, l.line));
        match out.iter_mut().find(|o| o.list.names == main.names) {
            Some(o) if p.env == *default => *o = p,
            Some(_) => {}
            None => out.push(p),
        }
    }
    out
}

/// The environment `t` names, with the secrets of list `p` as the workflow
/// has them, read with the usable profile that lists the most of them; and
/// the keys left to an open point; and whether every one's key names were
/// read, so that `covered` is all the keys they hold. A plain string
/// becomes a source only for the key of `example` its name says
/// ([`key_like`]).
fn from_list(
    t: &Target<'_>,
    p: &Picked<'_>,
    g: &Gathered,
    keyed: &[(String, Vec<Secret>)],
    example: &[KeyName],
) -> (EnvDraft, BTreeSet<KeyName>, bool) {
    let names = &p.list.names;
    let mut profile: Option<(&ProfileFacts, usize)> = None;
    for x in g.profiles.iter().filter(|x| x.usable) {
        let n = names.iter().filter(|n| x.secrets.contains(n)).count();
        if n > profile.map_or(0, |(_, most)| most) {
            profile = Some((x, n));
        }
    }
    let profile = profile.map(|(x, _)| x);
    let name = profile.map(|x| x.name.as_str());
    let secrets: &[Secret] = (keyed.iter())
        .find(|(n, _)| Some(n.as_str()) == name)
        .map_or(&[], |(_, s)| s);
    let mut sources = Vec::new();
    let mut run: Vec<String> = Vec::new();
    let mut covered: BTreeSet<KeyName> = BTreeSet::new();
    let mut open_keys: BTreeSet<KeyName> = BTreeSet::new();
    let want: BTreeSet<KeyName> = example.iter().cloned().collect();
    let mut open = Vec::new();
    let mut known = true;
    if p.unnamed {
        open.push(Open {
            note: format!(
                "{} does not say which environment its list is for; it was taken for {}",
                p.list.at(),
                t.env
            ),
            steps: Vec::new(),
        });
    }
    for n in names {
        if !profile.is_some_and(|x| x.secrets.contains(n)) {
            let other = (g.profiles.iter()).find(|x| x.usable && x.secrets.contains(n));
            open.push(Open {
                note: format!(
                    "secret {n} is in the workflow's list, and profile {} does not list it",
                    name.unwrap_or("?")
                ),
                steps: (other.iter())
                    .map(|o| {
                        Step::agent(t.add_source(&format!("aws_sm --secret {n}"), Some(&o.name)))
                    })
                    .collect(),
            });
            continue;
        }
        match secrets.iter().find(|s| s.name == *n) {
            Some(s) if s.plain && s.unread.is_none() => {
                let like = key_like(n);
                if let Some(key) = example.iter().find(|k| k.as_str() == like) {
                    if !run.is_empty() {
                        sources.push(Drafted::Secrets {
                            names: std::mem::take(&mut run),
                        });
                    }
                    covered.insert(key.clone());
                    sources.push(Drafted::Plain {
                        secret: n.clone(),
                        key: key.clone(),
                    });
                } else if let Some(key) = near(&like, &want) {
                    open_keys.insert(key.clone());
                    open.push(Open {
                        note: format!(
                            "secret {n} is in the workflow's list and is a plain string whose \
                             name is part of {key}'s, so it may be its value"
                        ),
                        steps: vec![Step::agent(
                            t.add_source(&format!("aws_sm --secret {n} --key {key}"), name),
                        )],
                    });
                } else {
                    open.push(Open {
                        note: format!(
                            "secret {n} is in the workflow's list and is a plain string, not a \
                             JSON object, and its name does not say which key it holds"
                        ),
                        steps: vec![Step::agent(
                            t.add_source(&format!("aws_sm --secret {n} --key NAME"), name),
                        )],
                    });
                }
            }
            Some(s) if s.unread.is_none() => {
                covered.extend(s.keys.iter().filter(|k| example.contains(k)).cloned());
                run.push(n.clone());
            }
            _ => {
                known = false;
                run.push(n.clone());
            }
        }
    }
    if !run.is_empty() {
        sources.push(Drafted::Secrets { names: run });
    }
    for l in &p.differing {
        let more: Vec<&String> = l.names.iter().filter(|n| !names.contains(n)).collect();
        let listed: Vec<&str> = more.iter().map(|n| n.as_str()).collect();
        open.push(Open {
            note: format!(
                "{} names {} for this environment too, which the list at {} does not",
                l.at(),
                listed.join(", "),
                p.list.at()
            ),
            steps: (more.iter())
                .map(|n| Step::agent(t.add_source(&format!("aws_sm --secret {n}"), name)))
                .collect(),
        });
    }
    let draft = EnvDraft {
        env: t.env.clone(),
        from: Some(p.list.at()),
        profile: name.map(str::to_owned),
        sources,
        covered: covered.into_iter().collect(),
        open,
    };
    (draft, open_keys, known)
}

/// What the other secrets of `draft`'s profile hold of the keys of
/// `example` that the workflow's list does not: offered as open points,
/// not placed, since no workflow loads them. Adds the keys so offered to
/// `open_keys`.
fn offer_the_rest(
    t: &Target<'_>,
    draft: &mut EnvDraft,
    open_keys: &mut BTreeSet<KeyName>,
    keyed: &[(String, Vec<Secret>)],
    example: &[KeyName],
) {
    let Some(profile) = draft.profile.clone() else {
        return;
    };
    let rest: Vec<KeyName> = (example.iter())
        .filter(|k| !draft.covered.contains(k) && !open_keys.contains(*k))
        .cloned()
        .collect();
    let secrets: Vec<Secret> = (keyed.iter())
        .filter(|(n, _)| *n == profile)
        .flat_map(|(_, s)| s.iter().cloned())
        .map(|s| Secret { named: None, ..s })
        .collect();
    if rest.is_empty() || secrets.is_empty() {
        return;
    }
    let c = cover(t, &profile, &secrets, &rest);
    if !c.sources.is_empty() {
        draft.open.push(Open {
            note: format!(
                "{} {} in no secret of the workflow's list; other secrets of profile {profile} \
                 hold {}, and no workflow loads them",
                join(&c.covered),
                if c.covered.len() == 1 { "is" } else { "are" },
                if c.covered.len() == 1 { "it" } else { "them" },
            ),
            steps: (c.sources.iter())
                .map(|s| Step::agent(t.add_source(&s.args(), Some(&profile))))
                .collect(),
        });
    }
    open_keys.extend(c.covered);
    open_keys.extend(c.open_keys);
    draft.open.extend(c.open);
}

/// An environment no workflow lists the secrets of.
struct Guessed {
    draft: EnvDraft,
    /// Keys left to an open point.
    open_keys: BTreeSet<KeyName>,
    left_out: Vec<String>,
    /// Whether any profile's secrets fit, chosen or left open.
    any: bool,
}

/// The environment `t` names, from what each profile's secrets hold of
/// `example`'s keys ([`cover`]). With `unnamed`, a secret counts for its
/// keys only, not for the checkout's files naming it: the app's workflows
/// say what is loaded.
fn guessed(
    t: &Target<'_>,
    keyed: &[(String, Vec<Secret>)],
    example: &[KeyName],
    unnamed: bool,
) -> Guessed {
    let covers: Vec<(&str, Cover)> = keyed
        .iter()
        .map(|(p, secrets)| {
            let c = if unnamed {
                let secrets: Vec<Secret> = (secrets.iter().cloned())
                    .map(|mut s| {
                        s.named = None;
                        s
                    })
                    .collect();
                cover(t, p, &secrets, example)
            } else {
                cover(t, p, secrets, example)
            };
            (p.as_str(), c)
        })
        .collect();
    let fitting: Vec<&(&str, Cover)> = covers
        .iter()
        .filter(|(_, c)| !c.sources.is_empty())
        .collect();
    let mut out = Guessed {
        draft: EnvDraft {
            env: t.env.clone(),
            from: None,
            profile: None,
            sources: Vec::new(),
            covered: Vec::new(),
            open: Vec::new(),
        },
        open_keys: BTreeSet::new(),
        left_out: Vec::new(),
        any: !fitting.is_empty(),
    };
    for (_, c) in &covers {
        out.left_out.extend(c.left_out.iter().cloned());
    }
    let mut covered: BTreeSet<KeyName> = BTreeSet::new();
    match &fitting[..] {
        [] => {}
        [(p, c)] => {
            out.draft.sources.extend(c.sources.iter().cloned());
            covered.extend(c.covered.iter().cloned());
            out.open_keys.extend(c.open_keys.iter().cloned());
            out.draft.open.extend(c.open.iter().cloned());
            out.draft.profile = Some((*p).to_owned());
        }
        several => {
            let names: Vec<&str> = several.iter().map(|(p, _)| *p).collect();
            let mut steps = Vec::new();
            for (p, c) in several {
                covered.extend(c.covered.iter().cloned());
                steps.extend(
                    c.sources
                        .iter()
                        .map(|s| Step::agent(t.add_source(&s.args(), Some(p)))),
                );
            }
            out.draft.open.push(Open {
                note: format!(
                    "AWS profiles {} each list secrets that hold keys of .env.example; pick one \
                     and run its commands",
                    names.join(", ")
                ),
                steps,
            });
        }
    }
    out.draft.covered = covered.into_iter().collect();
    out
}

/// Drafts the project `project` for `app` of the checkout `g` describes:
/// environment `env`, and one more for each list the app's workflows name
/// for another. An environment a workflow lists gets that list as it is;
/// `env` without one gets what the secrets hold of `.env.example`'s keys.
fn draft_app(
    g: &Gathered,
    app: &facts::App,
    project: ProjectName,
    env: &EnvName,
    keyed: &[(String, Vec<Secret>)],
    onboard_dir: &Path,
) -> AppDraft {
    let example = app.example_keys();
    let t = Target {
        project: &project,
        env,
    };
    let folder: Option<ProjectPath> = (!app.dir.as_os_str().is_empty())
        .then(|| ProjectPath::try_from(app.dir.to_string_lossy().into_owned()).ok())
        .flatten();
    let claimed_by = g
        .projects
        .iter()
        .find(|c| c.path == folder)
        .map(|c| c.project.clone());
    let mut left_out = Vec::new();
    for p in g.profiles.iter().filter(|p| !p.usable) {
        if let Some(why) = p.why.as_ref().filter(|w| w.contains("production")) {
            left_out.push(format!("AWS profile {}: {why}", p.name));
        }
    }

    let dirs = app_dirs(g, &app.dir);
    let lists: Vec<&SecretList> = (g.workflow_lists.iter())
        .filter(|l| owner(&dirs, l) == Some(app.dir.as_path()))
        .collect();
    let picked = pick_lists(&lists, env);
    let listed = picked.iter().find(|p| p.env == *env);
    let (mut main, open_keys, known, found_any) = if let Some(p) = listed {
        let (mut draft, mut open_keys, known) = from_list(&t, p, g, keyed, &example);
        if known {
            offer_the_rest(&t, &mut draft, &mut open_keys, keyed, &example);
        }
        (draft, open_keys, known, true)
    } else {
        let guess = guessed(&t, keyed, &example, !lists.is_empty());
        left_out.extend(guess.left_out);
        (guess.draft, guess.open_keys, true, guess.any)
    };

    // What nothing holds; unknown while a listed secret's keys were not
    // read.
    let values = read_example_values(&g.root.join(&app.dir));
    let uncovered: Vec<KeyName> = example
        .iter()
        .filter(|k| known && !main.covered.contains(k) && !open_keys.contains(*k))
        .cloned()
        .collect();
    let mut no_value = Vec::new();
    for k in &uncovered {
        let fixes = super::set_var_fixes(&project, env, std::slice::from_ref(k), &values);
        if fixes.is_empty() {
            no_value.push(k.clone());
        }
        for f in fixes {
            main.open.push(Open {
                note: format!(
                    "{k}: no secret holds it, and .env.example gives it a value; {}",
                    f.note
                ),
                steps: vec![Step::agent(f.command)],
            });
        }
    }
    if !no_value.is_empty() {
        let names: Vec<&str> = no_value.iter().map(KeyName::as_str).collect();
        let store = Step::human(
            format!("kagebunshin store set {project}.{env} {}", names.join(" ")),
            if names.len() == 1 {
                "it asks for the store passphrase, then the value"
            } else {
                "it asks for the store passphrase, then each value"
            },
        );
        let steps = if main.sources.is_empty() {
            vec![store]
        } else {
            vec![Step::agent(t.add_source("file", None)), store]
        };
        main.open.push(Open {
            note: format!("no secret found for {}", names.join(", ")),
            steps,
        });
    }

    let mut envs = vec![main];
    for p in picked.iter().filter(|p| p.env != *env) {
        let t = Target {
            project: &project,
            env: &p.env,
        };
        envs.push(from_list(&t, p, g, keyed, &example).0);
    }
    let drafted = |n: &str| {
        envs.iter().flat_map(|e| &e.sources).any(|s| match s {
            Drafted::Secrets { names } => names.iter().any(|x| x == n),
            Drafted::Plain { secret, .. } => secret == n,
            Drafted::Prefix { prefix } => n.starts_with(prefix.as_str()),
        })
    };
    let in_a_list = |n: &String| g.workflow_lists.iter().any(|l| l.names.contains(n));
    let unused: Vec<String> = (g.named_in_files.found.iter())
        .filter(|m| !lists.is_empty() && !in_a_list(&m.name) && !drafted(&m.name))
        .map(|m| {
            let files: Vec<String> = m.files.iter().map(|f| f.display().to_string()).collect();
            format!(
                "secret {} is named in {}, and no workflow loads it",
                m.name,
                files.join(", ")
            )
        })
        .collect();

    let mut d = AppDraft {
        dir: app.dir.clone(),
        project,
        envs,
        left_out,
        unused,
        instead: None,
        claimed_by,
        toml: String::new(),
        applied: None,
    };
    if let Some(f) = app.env_file_with_values()
        && !found_any
    {
        d.instead = Some(Open {
            note: format!(
                "{} has values and nothing else says where its secrets live, so nothing was \
                 drafted; `onboard` moves them into kagebunshin, with a person's approval",
                g.root.join(&app.dir).join(&f.name).display()
            ),
            steps: vec![Step::human(
                format!(
                    "kagebunshin onboard {}",
                    super::shell_quote(&onboard_dir.to_string_lossy())
                ),
                "it imports the env file's values into the local store, once a person approves \
                 that with the store passphrase, in the app or at a terminal",
            )],
        });
        d.envs.truncate(1);
        for e in &mut d.envs {
            e.open.clear();
            e.sources.clear();
        }
        return d;
    }
    d.toml = render_toml(&d, &g.remotes, folder.as_ref());
    d
}

/// `.env.example`'s values in `dir`, for `project set-var` commands; empty
/// without one. Example values are not secrets.
fn read_example_values(dir: &Path) -> crate::repo::env_example::ExampleValues {
    std::fs::read_to_string(dir.join(".env.example"))
        .map(|t| crate::repo::env_example::parse(&t).values)
        .unwrap_or_default()
}

/// `s` as a TOML basic string.
fn quoted(s: &str) -> String {
    toml_edit::Value::from(s).to_string().trim().to_owned()
}

/// The project file for `d`, with its open points as comments.
fn render_toml(d: &AppDraft, remotes: &[RemoteId], folder: Option<&ProjectPath>) -> String {
    let mut out = String::from(
        "# Drafted by `kagebunshin project draft`. Check it with\n\
         # `kagebunshin project apply FILE --check`.\n\
         schema = 1\n",
    );
    let r: Vec<String> = remotes.iter().map(|r| quoted(&r.to_string())).collect();
    out.push_str(&format!("remotes = [{}]\n", r.join(", ")));
    if let Some(p) = folder {
        out.push_str(&format!("path = {}\n", quoted(p.as_str())));
    }
    // One profile for the project when its environments agree on it.
    let profiles: BTreeSet<&str> = d.envs.iter().filter_map(|e| e.profile.as_deref()).collect();
    let shared = (profiles.len() == 1)
        .then(|| profiles.first().copied())
        .flatten();
    if let Some(p) = shared {
        out.push_str(&format!("profile = {}\n", quoted(p)));
    }
    for l in &d.left_out {
        out.push_str(&format!("# left out: {}\n", one_line(l)));
    }
    for u in &d.unused {
        out.push_str(&format!("# found and unused: {}\n", one_line(u)));
    }
    for e in &d.envs {
        out.push_str(&format!("\n[envs.{}]\n", e.env));
        if let (None, Some(p)) = (shared, &e.profile) {
            out.push_str(&format!("profile = {}\n", quoted(p)));
        }
        if let Some(at) = &e.from {
            out.push_str(&format!(
                "# its secrets as {at} lists them, in that order\n"
            ));
        } else if e.order_guessed() {
            out.push_str(&format!("# {GUESSED}\n"));
        }
        for o in &e.open {
            out.push_str(&format!("# open: {}\n", one_line(&o.note)));
            for s in &o.steps {
                let who = if s.who == Who::Human {
                    "   (human)"
                } else {
                    ""
                };
                out.push_str(&format!("#   {}{who}\n", s.command));
            }
        }
        for s in &e.sources {
            out.push_str(&format!("\n[[envs.{}.sources]]\n", e.env));
            match s {
                Drafted::Prefix { prefix } => {
                    out.push_str(&format!(
                        "provider = \"aws_sm\"\nprefix = {}\n",
                        quoted(prefix)
                    ));
                }
                Drafted::Secrets { names } => {
                    if let [one] = &names[..] {
                        out.push_str(&format!(
                            "provider = \"aws_sm\"\nsecret = {}\n",
                            quoted(one)
                        ));
                    } else {
                        let n: Vec<String> = names.iter().map(|n| quoted(n)).collect();
                        out.push_str(&format!(
                            "provider = \"aws_sm\"\nsecrets = [{}]\n",
                            n.join(", ")
                        ));
                    }
                }
                Drafted::Plain { secret, key } => out.push_str(&format!(
                    "provider = \"aws_sm\"\nsecret = {}\nkey = {}\n",
                    quoted(secret),
                    quoted(key.as_str())
                )),
            }
        }
    }
    out
}

/// Said of an environment whose secrets the draft chose itself.
const GUESSED: &str = "no workflow lists these secrets, so their order is a guess; a later one \
                       wins a key two hold";

fn one_line(s: &str) -> String {
    s.replace(['\n', '\r'], " ")
}

/// The report `project draft` prints beside the TOML, or after installing.
fn render_drafts(
    drafts: &[AppDraft],
    notes: &[String],
    apply: bool,
    saved: Option<&Path>,
) -> String {
    let mut out = String::new();
    for d in drafts {
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&format!(
            "draft of project {} for {}:",
            d.project,
            shown_dir(&d.dir)
        ));
        if let Some(i) = &d.instead {
            out.push_str(&format!("\n  {}", i.note));
            render_steps(&mut out, "      ", &i.steps);
            continue;
        }
        if let Some(owner) = &d.claimed_by {
            out.push_str(&format!(
                "\n  project {owner} already exists or claims it; this draft is for comparison"
            ));
        }
        for e in &d.envs {
            match &e.from {
                Some(at) => out.push_str(&format!(
                    "\n  environment {}, its secrets as {at} lists them:",
                    e.env
                )),
                None => out.push_str(&format!("\n  environment {}:", e.env)),
            }
            if e.sources.is_empty() {
                out.push_str("\n    sources: none, so it reads the local store's section");
            }
            for s in &e.sources {
                match (&e.profile, s) {
                    (
                        Some(p),
                        Drafted::Prefix { .. } | Drafted::Secrets { .. } | Drafted::Plain { .. },
                    ) => {
                        out.push_str(&format!("\n    source: {} (profile {p})", s.describe()));
                    }
                    _ => out.push_str(&format!("\n    source: {}", s.describe())),
                }
            }
            if e.order_guessed() {
                out.push_str(&format!("\n    order: {GUESSED}"));
            }
            if !e.covered.is_empty() {
                let k: Vec<&str> = e.covered.iter().map(KeyName::as_str).collect();
                out.push_str(&format!("\n    holds: {}", k.join(", ")));
            }
            if !e.open.is_empty() && d.applied.is_some() {
                out.push_str("\n    open points:");
            } else if !e.open.is_empty() {
                out.push_str("\n    open points (the commands work once it is installed):");
            }
            for o in &e.open {
                out.push_str(&format!("\n    - {}", o.note));
                render_steps(&mut out, "        ", &o.steps);
            }
        }
        for l in &d.left_out {
            out.push_str(&format!("\n  left out: {l}"));
        }
        for u in &d.unused {
            out.push_str(&format!("\n  found and unused: {u}"));
        }
        if let Some(a) = &d.applied {
            for line in render_installed(a).lines() {
                out.push_str(&format!("\n  {line}"));
            }
        } else if let (false, Some(file)) = (apply, saved) {
            out.push_str(&format!(
                "\n  to install it: `kagebunshin project apply {}`",
                file.display()
            ));
        } else if !apply {
            let file = format!("{}.toml", d.project);
            out.push_str(&format!(
                "\n  to install it: save it as {file}, then `kagebunshin project apply {file}`"
            ));
        }
    }
    for n in notes {
        out.push_str(&format!("\nnote: {n}"));
    }
    out
}

fn render_steps(out: &mut String, indent: &str, steps: &[Step]) {
    for s in steps {
        let who = match s.who {
            Who::Agent => "agent",
            Who::Human => "human",
        };
        out.push_str(&format!("\n{indent}{}   ({who})", s.command));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(k: &str) -> KeyName {
        k.parse().expect("a key name")
    }

    fn keys(ks: &[&str]) -> Vec<KeyName> {
        ks.iter().map(|k| key(k)).collect()
    }

    fn json(name: &str, ks: &[&str]) -> Secret {
        Secret {
            name: name.into(),
            keys: keys(ks),
            plain: false,
            unread: None,
            named: None,
        }
    }

    fn plain(name: &str) -> Secret {
        Secret {
            plain: true,
            ..json(name, &[])
        }
    }

    fn named(s: Secret) -> Secret {
        named_at(0, s)
    }

    /// `s`, as the `at`th name the checkout's files name.
    fn named_at(at: usize, s: Secret) -> Secret {
        Secret {
            named: Some(at),
            ..s
        }
    }

    fn run(secrets: &[Secret], example: &[&str]) -> Cover {
        let project: ProjectName = "acme".parse().expect("a project name");
        let env: EnvName = "dev".parse().expect("an env name");
        let t = Target {
            project: &project,
            env: &env,
        };
        cover(&t, "acme-dev", secrets, &keys(example))
    }

    fn secrets(names: &[&str]) -> Drafted {
        Drafted::Secrets {
            names: names.iter().map(|&n| n.to_owned()).collect(),
        }
    }

    #[test]
    fn the_secret_holding_most_keys_is_picked_first() {
        let c = run(
            &[
                json("acme/dev/api", &["DB_URL", "API_KEY"]),
                json("acme/dev/other", &["API_KEY"]),
                json("acme/stage/api", &["DB_URL", "API_KEY", "PORT"]),
            ],
            &["DB_URL", "API_KEY", "PORT"],
        );
        assert_eq!(c.sources, vec![secrets(&["acme/stage/api"])]);
        assert_eq!(
            c.covered,
            keys(&["API_KEY", "DB_URL", "PORT"]).into_iter().collect()
        );
        assert!(c.open.is_empty(), "{:?}", c.open);
    }

    #[test]
    fn a_tie_on_the_same_keys_is_left_open() {
        let c = run(
            &[
                json("acme/dev/a", &["DB_URL"]),
                json("acme/dev/b", &["DB_URL"]),
                json("acme/dev/c", &["PORT"]),
            ],
            &["DB_URL", "PORT"],
        );
        assert_eq!(c.sources, vec![secrets(&["acme/dev/c"])]);
        assert_eq!(c.open_keys, keys(&["DB_URL"]).into_iter().collect());
        assert!(!c.covered.contains(&key("DB_URL")));
        let [o] = &c.open[..] else {
            panic!("one open point: {:?}", c.open)
        };
        assert!(o.note.contains("acme/dev/a, acme/dev/b"), "{}", o.note);
        assert_eq!(o.steps.len(), 2);
        assert!(
            o.steps
                .iter()
                .all(|s| s.who == Who::Agent && s.command.contains("--profile acme-dev"))
        );
    }

    #[test]
    fn secrets_the_checkout_names_come_first() {
        let c = run(
            &[
                named(json("acme/dev/app", &["API_KEY"])),
                json("acme/dev/everything", &["API_KEY", "DB_URL"]),
                json("acme/dev/db", &["DB_URL"]),
            ],
            &["API_KEY", "DB_URL"],
        );
        // The named one covers API_KEY, so the rest is a one-key race that
        // `everything` and `db` tie on.
        assert!(
            matches!(&c.sources[..], [Drafted::Secrets { names }] if names == &["acme/dev/app"])
        );
        assert_eq!(c.open_keys, keys(&["DB_URL"]).into_iter().collect());
    }

    #[test]
    fn production_and_unread_secrets_are_never_chosen() {
        let unread = Secret {
            unread: Some("marked sensitive".into()),
            ..named(json("acme/dev/locked", &[]))
        };
        let c = run(
            &[
                named(json("acme/prod/api", &["API_KEY"])),
                json("acme/production/db", &["DB_URL"]),
                unread,
            ],
            &["API_KEY", "DB_URL"],
        );
        assert!(c.sources.is_empty(), "{:?}", c.sources);
        assert!(c.covered.is_empty());
        assert_eq!(c.left_out.len(), 2, "{:?}", c.left_out);
        assert!(
            c.left_out
                .iter()
                .any(|l| l.contains("acme/prod/api") && l.contains("production"))
        );
        assert!(
            c.left_out
                .iter()
                .any(|l| l.contains("acme/dev/locked") && l.contains("marked sensitive"))
        );
    }

    #[test]
    fn a_plain_string_is_used_only_when_its_name_is_the_key() {
        let c = run(
            &[
                plain("acme/dev/stripe-key"),
                plain("acme/dev/db"),
                plain("acme/dev/sentry_dsn"),
                plain("acme/stage/sentry-dsn"),
            ],
            &["STRIPE_KEY", "DB_URL", "SENTRY_DSN"],
        );
        // `db` is not `DB_URL`, and two plain strings look like SENTRY_DSN.
        assert_eq!(
            c.sources,
            vec![Drafted::Plain {
                secret: "acme/dev/stripe-key".into(),
                key: key("STRIPE_KEY"),
            }]
        );
        assert_eq!(c.covered, keys(&["STRIPE_KEY"]).into_iter().collect());
    }

    #[test]
    fn a_plain_string_named_for_part_of_one_key_is_offered_not_chosen() {
        let secrets = [
            plain("acme/dev/signing"),
            plain("acme/dev/api"),
            plain("acme/dev/sign"),
        ];
        let c = run(&secrets, &["SIGNING_KEY", "API_KEY", "API_URL"]);
        assert!(c.sources.is_empty(), "{:?}", c.sources);
        // `api` fits two keys and `sign` is no whole word of one.
        let [o] = &c.open[..] else {
            panic!("one open point: {:?}", c.open)
        };
        assert!(
            o.note.starts_with("SIGNING_KEY is in no secret read"),
            "{}",
            o.note
        );
        assert_eq!(
            o.steps[0].command,
            "kagebunshin project add-source acme dev --provider aws_sm --secret acme/dev/signing \
             --key SIGNING_KEY --profile acme-dev"
        );

        // Two plain strings fit the key: neither is offered.
        let c = run(
            &[plain("acme/dev/signing"), plain("acme/stage/signing")],
            &["SIGNING_KEY"],
        );
        assert!(c.sources.is_empty() && c.open.is_empty(), "{c:?}");
    }

    #[test]
    fn a_named_plain_string_that_fits_no_key_is_left_open() {
        let c = run(&[named(plain("acme/dev/token"))], &["API_KEY"]);
        assert!(c.sources.is_empty());
        let [o] = &c.open[..] else {
            panic!("one open point: {:?}", c.open)
        };
        assert!(
            o.steps[0]
                .command
                .ends_with("--key NAME --profile acme-dev"),
            "{}",
            o.steps[0].command
        );
    }

    #[test]
    fn a_prefix_replaces_secrets_only_when_it_holds_nothing_else() {
        let all = run(
            &[
                json("acme/dev/api", &["API_KEY"]),
                json("acme/dev/db", &["DB_URL"]),
            ],
            &["API_KEY", "DB_URL"],
        );
        assert_eq!(
            all.sources,
            vec![Drafted::Prefix {
                prefix: "acme/dev/".into()
            }]
        );

        let more = run(
            &[
                json("acme/dev/api", &["API_KEY"]),
                json("acme/dev/db", &["DB_URL"]),
                json("acme/dev/unrelated", &["OTHER"]),
            ],
            &["API_KEY", "DB_URL"],
        );
        assert_eq!(
            more.sources,
            vec![secrets(&["acme/dev/api", "acme/dev/db"])]
        );

        let alone = run(&[json("acme/dev/api", &["API_KEY"])], &["API_KEY"]);
        assert_eq!(alone.sources, vec![secrets(&["acme/dev/api"])]);
    }

    #[test]
    fn two_chosen_secrets_setting_one_key_are_pointed_out() {
        let c = run(
            &[
                named(json("acme/dev/a", &["API_KEY", "PORT"])),
                named(json("acme/dev/b", &["DB_URL", "PORT"])),
            ],
            &["API_KEY", "DB_URL", "PORT"],
        );
        assert_eq!(c.covered.len(), 3);
        assert!(
            c.open
                .iter()
                .any(|o| o.note.starts_with("PORT is set by each of")),
            "{:?}",
            c.open
        );
    }

    #[test]
    fn named_secrets_keep_the_order_the_checkout_names_them_in() {
        let c = run(
            &[
                named_at(2, json("acme/dev/a", &["API_KEY"])),
                named_at(0, json("acme/dev/z", &["DB_URL"])),
                json("acme/dev/b", &["PORT"]),
                named_at(1, json("acme/dev/m", &["REGION"])),
                json("acme/dev/unrelated", &["OTHER"]),
            ],
            &["API_KEY", "DB_URL", "PORT", "REGION"],
        );
        assert_eq!(
            c.sources,
            vec![secrets(&[
                "acme/dev/z",
                "acme/dev/m",
                "acme/dev/a",
                "acme/dev/b"
            ])]
        );
    }

    fn list(file: &str, env: Option<&str>, dir: Option<&str>, names: &[&str]) -> SecretList {
        SecretList {
            file: PathBuf::from(format!(".github/workflows/{file}")),
            line: 5,
            env: env.map(str::to_owned),
            dir: dir.map(PathBuf::from),
            names: names.iter().map(|&n| n.to_owned()).collect(),
        }
    }

    fn app(dir: &str, example: &[&str]) -> facts::App {
        facts::App {
            dir: PathBuf::from(dir),
            example: Some(facts::Example {
                keys: (example.iter())
                    .map(|k| facts::FileKey {
                        key: key(k),
                        has_value: false,
                    })
                    .collect(),
                bad_lines: Vec::new(),
                problem: None,
            }),
            env_files: Vec::new(),
        }
    }

    /// A checkout of `apps` whose one profile, `acme`, lists `listed`; its
    /// files name `named`, in that order, and its workflows hold `lists`.
    fn checkout(
        apps: Vec<facts::App>,
        listed: &[Secret],
        named: &[&str],
        lists: Vec<SecretList>,
    ) -> (Gathered, Vec<(String, Vec<Secret>)>) {
        let g = Gathered {
            root: PathBuf::from("/nowhere/acme"),
            here: PathBuf::new(),
            remotes: vec!["github.com/acme/acme".parse().expect("a remote")],
            checkout: CheckoutFacts {
                apps,
                other_env_files: Vec::new(),
                capped: Vec::new(),
            },
            projects: Vec::new(),
            daemon: None,
            profiles: vec![ProfileFacts {
                name: "acme".into(),
                usable: true,
                why: None,
                secrets: listed.iter().map(|s| s.name.clone()).collect(),
                secret_count: listed.len(),
            }],
            named_in_files: Mentions {
                found: (named.iter())
                    .map(|n| facts::Mention {
                        name: (*n).to_owned(),
                        files: vec![PathBuf::from("scripts/load.sh")],
                    })
                    .collect(),
                capped: Vec::new(),
            },
            workflow_lists: lists,
            notes: Vec::new(),
        };
        let keyed = (listed.iter().cloned())
            .map(|s| Secret {
                named: named.iter().position(|n| *n == s.name),
                ..s
            })
            .collect();
        (g, vec![("acme".to_owned(), keyed)])
    }

    fn drafted(g: &Gathered, keyed: &[(String, Vec<Secret>)], app: usize) -> AppDraft {
        let app = &g.checkout.apps[app];
        let project = default_name(&g.root, &app.dir).expect("a project name");
        let env: EnvName = "dev".parse().expect("an env name");
        draft_app(g, app, project, &env, keyed, &app.dir)
    }

    /// The draft's environments as the installed project has them: each
    /// with its sources' secrets, in order.
    fn installed(d: &AppDraft) -> Vec<(String, Vec<String>)> {
        let file = crate::config::parse_project(Path::new("acme.toml"), &d.toml)
            .expect("the draft is a project file")
            .file;
        (file.envs.iter())
            .map(|(env, e)| {
                let names = (e.sources.iter())
                    .filter_map(|s| s.select.as_ref())
                    .flat_map(|s| s.locations())
                    .map(str::to_owned)
                    .collect();
                (env.to_string(), names)
            })
            .collect()
    }

    #[test]
    fn two_deploy_workflows_draft_two_environments_as_they_list_them() {
        let (g, keyed) = checkout(
            vec![app("", &["API_KEY", "DATABASE_URL", "LOG_LEVEL"])],
            &[
                json("acme/dev/api", &["API_KEY"]),
                json("acme/dev/db", &["DATABASE_URL"]),
                json("acme/dev/old", &["API_KEY", "DATABASE_URL"]),
                json("acme/dev/queue", &["QUEUE_URL"]),
                json("acme/prod/api", &["API_KEY"]),
                json("acme/prod/db", &["DATABASE_URL"]),
            ],
            &[
                "acme/dev/queue",
                "acme/dev/api",
                "acme/dev/db",
                "acme/prod/db",
                "acme/prod/api",
                "acme/dev/old",
            ],
            vec![
                list(
                    "deploy-dev.yml",
                    Some("dev"),
                    None,
                    &["acme/dev/queue", "acme/dev/db", "acme/dev/api"],
                ),
                list(
                    "deploy-prod.yml",
                    Some("prod"),
                    None,
                    &["acme/prod/db", "acme/prod/api"],
                ),
            ],
        );
        let d = drafted(&g, &keyed, 0);
        assert_eq!(
            installed(&d),
            [
                (
                    "dev".to_owned(),
                    vec![
                        "acme/dev/queue".to_owned(),
                        "acme/dev/db".to_owned(),
                        "acme/dev/api".to_owned()
                    ]
                ),
                (
                    "prod".to_owned(),
                    vec!["acme/prod/db".to_owned(), "acme/prod/api".to_owned()]
                ),
            ]
        );
        // Each list says where it is from; the profile is the project's.
        assert_eq!(
            d.envs[0].from.as_deref(),
            Some(".github/workflows/deploy-dev.yml:5")
        );
        assert!(
            d.toml
                .contains("# its secrets as .github/workflows/deploy-prod.yml:5 lists them"),
            "{}",
            d.toml
        );
        assert!(d.toml.contains("\nprofile = \"acme\"\n"), "{}", d.toml);
        assert!(!d.toml.contains("is a guess"), "{}", d.toml);
        // A secret found in the checkout that no workflow loads is said,
        // not placed, though it holds two of the example's keys.
        assert_eq!(
            d.unused,
            ["secret acme/dev/old is named in scripts/load.sh, and no workflow loads it"]
        );
        assert!(d.toml.contains("# found and unused: secret acme/dev/old"));
        // What the listed secrets do not hold is still open.
        assert_eq!(d.envs[0].covered, keys(&["API_KEY", "DATABASE_URL"]));
        let [o] = &d.envs[0].open[..] else {
            panic!("one open point: {:?}", d.envs[0].open)
        };
        assert_eq!(o.note, "no secret found for LOG_LEVEL");
        assert!(d.envs[1].open.is_empty(), "{:?}", d.envs[1].open);
    }

    #[test]
    fn without_a_workflow_list_the_order_is_said_to_be_a_guess() {
        let (g, keyed) = checkout(
            vec![app("", &["API_KEY", "DATABASE_URL"])],
            &[
                json("acme/dev/api", &["API_KEY"]),
                json("acme/dev/db", &["DATABASE_URL"]),
                json("acme/dev/unrelated", &["OTHER"]),
            ],
            &["acme/dev/db", "acme/dev/api"],
            Vec::new(),
        );
        let d = drafted(&g, &keyed, 0);
        assert_eq!(
            installed(&d),
            [(
                "dev".to_owned(),
                vec!["acme/dev/db".to_owned(), "acme/dev/api".to_owned()]
            )]
        );
        assert_eq!(d.envs[0].from, None);
        assert!(d.toml.contains(&format!("# {GUESSED}\n")), "{}", d.toml);
        assert!(d.unused.is_empty(), "{:?}", d.unused);
        let text = render_drafts(std::slice::from_ref(&d), &[], false, None);
        assert!(text.contains(&format!("order: {GUESSED}")), "{text}");
    }

    #[test]
    fn a_workflow_is_for_the_app_it_runs_in() {
        let (g, keyed) = checkout(
            vec![
                app("apps/web", &["API_KEY"]),
                app("apps/worker", &["QUEUE_URL"]),
            ],
            &[
                json("acme/dev/api", &["API_KEY"]),
                json("acme/dev/queue", &["QUEUE_URL"]),
                json("acme/rc/api", &["API_KEY"]),
            ],
            &["acme/dev/api", "acme/dev/queue", "acme/rc/api"],
            vec![
                list(
                    "web-dev.yml",
                    Some("dev"),
                    Some("apps/web"),
                    &["acme/dev/api"],
                ),
                list(
                    "web-rc.yml",
                    Some("rc"),
                    Some("apps/web/src"),
                    &["acme/dev/api", "acme/rc/api"],
                ),
                list("lint.yml", None, None, &["acme/dev/queue"]),
            ],
        );
        let web = drafted(&g, &keyed, 0);
        assert_eq!(
            installed(&web),
            [
                ("dev".to_owned(), vec!["acme/dev/api".to_owned()]),
                (
                    "rc".to_owned(),
                    vec!["acme/dev/api".to_owned(), "acme/rc/api".to_owned()]
                ),
            ]
        );
        // The worker has no workflow of its own: its secrets are chosen by
        // their keys, as before. A list that runs nowhere is no app's.
        let worker = drafted(&g, &keyed, 1);
        assert_eq!(
            installed(&worker),
            [("dev".to_owned(), vec!["acme/dev/queue".to_owned()])]
        );
        assert_eq!(worker.envs[0].from, None);
        let dirs = app_dirs(&g, Path::new("apps/web"));
        assert_eq!(owner(&dirs, &g.workflow_lists[2]), None);
        assert_eq!(
            owner(&[Path::new("")], &g.workflow_lists[2]),
            Some(Path::new(""))
        );
        assert_eq!(
            owner(
                &[Path::new(""), Path::new("apps/web")],
                &g.workflow_lists[1]
            ),
            Some(Path::new("apps/web"))
        );
    }

    #[test]
    fn one_list_is_picked_for_each_environment() {
        let dev: EnvName = "dev".parse().expect("an env name");
        let short = list("test.yml", Some("dev"), None, &["a", "b"]);
        let long = list("deploy-dev.yml", Some("dev"), None, &["c", "a", "b"]);
        let other = list("migrate.yml", None, None, &["a", "d"]);
        let rc = list("deploy-rc.yml", Some("rc"), None, &["c", "a", "b"]);
        let bad = list("x.yml", Some("Not A Name"), None, &["e"]);
        let picked = pick_lists(&[&short, &long, &other, &rc, &bad], &dev);
        // The longest for dev, with the list that names something more;
        // the short one adds nothing, and `rc` names the same secrets.
        let [p] = &picked[..] else {
            panic!("one environment: {picked:?}")
        };
        assert_eq!((p.env.as_str(), p.list, p.unnamed), ("dev", &long, false));
        assert_eq!(p.differing, [&other, &bad]);
        // A list that names no environment is the default one's.
        let picked = pick_lists(&[&other, &rc], &dev);
        assert_eq!(
            picked
                .iter()
                .map(|p| (p.env.as_str(), p.list, p.unnamed))
                .collect::<Vec<_>>(),
            [("dev", &other, true), ("rc", &rc, false)]
        );
    }

    #[test]
    fn a_listed_secret_the_draft_cannot_place_is_left_open() {
        let (mut g, keyed) = checkout(
            vec![app("", &["API_KEY", "SIGNING_KEY"])],
            &[
                json("acme/dev/api", &["API_KEY"]),
                plain("acme/dev/signing-key"),
                plain("acme/dev/blob"),
            ],
            &[],
            vec![list(
                "deploy.yml",
                None,
                None,
                &[
                    "acme/dev/api",
                    "acme/dev/signing-key",
                    "acme/dev/blob",
                    "acme/dev/elsewhere",
                ],
            )],
        );
        g.profiles.push(ProfileFacts {
            name: "other".into(),
            usable: true,
            why: None,
            secrets: vec!["acme/dev/elsewhere".into()],
            secret_count: 1,
        });
        let d = drafted(&g, &keyed, 0);
        let e = &d.envs[0];
        assert_eq!(
            e.sources,
            vec![
                secrets(&["acme/dev/api"]),
                Drafted::Plain {
                    secret: "acme/dev/signing-key".into(),
                    key: key("SIGNING_KEY"),
                },
            ]
        );
        let notes: Vec<&str> = e.open.iter().map(|o| o.note.as_str()).collect();
        assert_eq!(
            notes,
            [
                ".github/workflows/deploy.yml:5 does not say which environment its list is for; \
                 it was taken for dev",
                "secret acme/dev/blob is in the workflow's list and is a plain string, not a JSON \
                 object, and its name does not say which key it holds",
                "secret acme/dev/elsewhere is in the workflow's list, and profile acme does not \
                 list it",
            ]
        );
        assert_eq!(
            e.open[2].steps,
            [Step::agent(
                "kagebunshin project add-source acme dev --provider aws_sm --secret \
                 acme/dev/elsewhere --profile other"
            )]
        );
    }

    #[test]
    fn keys_the_list_does_not_hold_are_offered_from_other_secrets_not_placed() {
        let (g, keyed) = checkout(
            vec![app("", &["API_KEY", "DATABASE_URL", "SIGNING_KEY", "PORT"])],
            &[
                json("acme/dev/api", &["API_KEY"]),
                json("acme/dev/db", &["DATABASE_URL"]),
                json("acme/prod/db", &["DATABASE_URL", "PORT"]),
                plain("acme/dev/signing"),
            ],
            &[],
            vec![list("deploy.yml", Some("dev"), None, &["acme/dev/api"])],
        );
        let d = drafted(&g, &keyed, 0);
        let e = &d.envs[0];
        assert_eq!(e.sources, vec![secrets(&["acme/dev/api"])]);
        assert_eq!(e.covered, keys(&["API_KEY"]));
        let notes: Vec<&str> = e.open.iter().map(|o| o.note.as_str()).collect();
        assert_eq!(
            notes,
            [
                "DATABASE_URL is in no secret of the workflow's list; other secrets of profile \
                 acme hold it, and no workflow loads them",
                "SIGNING_KEY is in no secret read; secret acme/dev/signing is a plain string \
                 whose name is part of that key's, so it may be its value",
                "no secret found for PORT",
            ]
        );
        assert_eq!(
            e.open[0].steps,
            [Step::agent(
                "kagebunshin project add-source acme dev --provider aws_sm --secret acme/dev/db \
                 --profile acme"
            )]
        );
    }

    #[test]
    fn key_like_takes_the_last_segment() {
        assert_eq!(key_like("acme/dev/stripe-key"), "STRIPE_KEY");
        assert_eq!(key_like("sentry.dsn"), "SENTRY_DSN");
    }

    #[test]
    fn default_names_come_from_the_folders() {
        let n = |root: &str, dir: &str| {
            default_name(Path::new(root), Path::new(dir)).map(|n| n.to_string())
        };
        assert_eq!(n("/src/Acme App", "").ok().as_deref(), Some("acme-app"));
        assert_eq!(n("/src/acme", "apps/web").ok().as_deref(), Some("acme-web"));
        assert!(n("/", "").is_err());
    }
}
