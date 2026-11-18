//! `kagebunshin onboard [DIR]…`: every app of the checkouts named becomes a
//! project, with one passphrase prompt. An app with an env file with values
//! has it moved into the local store; any other is drafted and installed as
//! `project draft --apply` does; one a project already claims is left as it
//! is. Then each project's state, as `next` sees it, and the line to paste
//! into the agent. Values go from the files to the daemon and are never
//! printed.
//!
//! What is done for each app is listed before the passphrase is asked for.
//! `--exclude APP` leaves an app out, which is remembered ([`LeftOut`]):
//! its checkout onboarded or drafted again passes over it, until its own
//! folder is named.
//!
//! `kagebunshin onboard --file PATH… [--env ENV]` imports the files named
//! instead, whatever they are called, into the project of the app each is
//! in: a new project, or an existing one's environment, which is added if
//! it is not there. Either way, the files with values that were not
//! imported are named at the end, with the command that imports each.
//! What was imported is remembered ([`Record`]), so a file that is kept is
//! not named again until it changes.
//!
//! The passphrase is typed at the terminal. With none, as when an agent
//! runs this, the daemon asks a person in the app instead: its window names
//! each file, section and key, takes the passphrase, and unlocks with it
//! too. With the app closed nothing is imported (`no_app`). The files
//! imported are then kept unless `--delete-env` says otherwise: deleting
//! them is the person's choice.
//!
//! Each step is named on stderr as it starts, so nothing is silent for
//! long and `--json` stays one document on stdout.

use std::collections::BTreeMap;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::draft::{self, AppDraft};
use super::edit::config;
use super::next::{self, Plan};
use super::{CliError, Exit, plural, print_json, print_line};
use crate::config::{ConfigDir, Git, ProjectPath, Registry, RemoteId};
use crate::ipc::client::Client;
use crate::ipc::protocol::{ImportInto, ImportSection, Request, Response, WireSecret};
use crate::repo::facts;
use crate::store::{Section, StoreFile};
use crate::types::{EnvName, KeyName, ProjectName};

/// The line a person pastes into their coding agent.
pub(super) const PASTE: &str =
    "Set up kagebunshin here: run `kagebunshin next` and do what it says until it says done.";

/// Whose store section an import fills.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Into {
    /// A new project's.
    New,
    /// That of the project claiming the app, whose environment reads it.
    Existing,
    /// That of the project claiming the app, which gets the environment.
    NewEnv,
}

/// What is done for one app.
enum Work {
    /// Its env files ([`Job::files`]) go into the store.
    Import(Into),
    Draft,
    /// A project claims it; nothing is done. `note` says why an env file
    /// there was not imported.
    Leave {
        note: Option<String>,
    },
    Failed(CliError),
}

struct Job {
    /// The checkout's root, as `project draft` sees it.
    root: PathBuf,
    remotes: Vec<RemoteId>,
    app: facts::App,
    project: Option<ProjectName>,
    work: Work,
    /// What was done, in words.
    did: String,
    /// The env files to import: the app's own first one with values, or
    /// those `--file` named.
    files: Vec<PathBuf>,
    /// Whether `--file` named them: then they go in over keys already in
    /// the section, and into an environment the project does not have yet.
    asked: bool,
    /// The keys imported.
    keys: Vec<KeyName>,
}

impl Job {
    fn dir(&self) -> PathBuf {
        if self.app.dir.as_os_str().is_empty() {
            return self.root.clone();
        }
        self.root.join(&self.app.dir)
    }

    fn folder(&self) -> Option<ProjectPath> {
        (!self.app.dir.as_os_str().is_empty())
            .then(|| ProjectPath::try_from(self.app.dir.to_string_lossy().into_owned()).ok())
            .flatten()
    }

    /// `file` as shown: by name in the app's folder, else in full.
    fn shown(&self, file: &Path) -> String {
        let shown = file.strip_prefix(self.dir()).unwrap_or(file);
        shown.display().to_string()
    }

    fn files_shown(&self) -> String {
        let shown: Vec<String> = self.files.iter().map(|f| self.shown(f)).collect();
        shown.join(", ")
    }

    /// The command that does this job again, for a hint: the files it was
    /// asked for, or the app's folder.
    fn again(&self) -> String {
        let quoted = |p: &Path| super::shell_quote(&p.to_string_lossy());
        if self.asked {
            let files: Vec<String> = (self.files.iter())
                .map(|f| format!("--file {}", quoted(f)))
                .collect();
            format!("kagebunshin onboard {}", files.join(" "))
        } else {
            format!("kagebunshin onboard {}", quoted(&self.dir()))
        }
    }

    fn fail(&mut self, e: CliError) {
        self.did = "nothing was written".into();
        self.work = Work::Failed(e);
    }
}

#[derive(Serialize)]
struct Skipped {
    dir: PathBuf,
    why: String,
    /// An app left out, not a folder that could not be onboarded.
    #[serde(skip)]
    left_out: bool,
}

#[derive(Serialize)]
struct ProjectOut<'a> {
    project: Option<&'a ProjectName>,
    dir: PathBuf,
    env: Option<&'a EnvName>,
    did: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    imported: Option<Imported<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<&'a str>,
    set: Option<usize>,
    of: Option<usize>,
    /// `ready`, or any of `needs your agent` and `needs you`; `failed` when
    /// nothing could be done.
    state: Vec<&'static str>,
    done: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    step: Option<&'a next::Step>,
    tell: Vec<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a CliError>,
}

#[derive(Serialize)]
struct Imported<'a> {
    files: &'a [PathBuf],
    keys: &'a [KeyName],
}

/// A file with values that this run did not import, and the command that
/// does.
#[derive(Debug, Serialize)]
pub(super) struct NotImported {
    pub(super) file: PathBuf,
    pub(super) command: String,
}

const READY: &str = "ready";
const NEEDS_AGENT: &str = "needs your agent";
const NEEDS_YOU: &str = "needs you";

/// The state words of `plan`: ready when nothing is left but the proof run.
fn state(plan: &Plan) -> Vec<&'static str> {
    let proof_only = plan.step.as_ref().is_none_or(|s| s.what == next::PROVE);
    let all_set = plan.keys.is_some_and(|k| k.set == k.wanted);
    if plan.human.is_empty() && proof_only && (plan.done || (all_set && plan.step.is_some())) {
        return vec![READY];
    }
    let mut out = Vec::new();
    if plan.step.is_some() {
        out.push(NEEDS_AGENT);
    }
    if !plan.human.is_empty() {
        out.push(NEEDS_YOU);
    }
    out
}

/// What `onboard` is asked to take in: the folders, or the files instead.
pub(super) struct Wanted {
    pub dirs: Vec<PathBuf>,
    pub files: Vec<PathBuf>,
    pub name: Option<ProjectName>,
    /// The apps of `dirs` to leave out.
    pub exclude: Vec<String>,
}

/// `kagebunshin onboard [DIR]… [--name NAME] [--exclude APP]…`, or with
/// `files`, `kagebunshin onboard --file PATH… [--name NAME]`; see the
/// module docs. `delete_env` answers the question about the imported env
/// files.
pub(super) fn onboard(
    socket: Option<PathBuf>,
    json: bool,
    env: Option<EnvName>,
    wanted: Wanted,
    delete_env: Option<bool>,
) -> Result<(), CliError> {
    let Wanted {
        dirs,
        files,
        name,
        exclude,
    } = wanted;
    if name.is_some() && dirs.len() > 1 {
        return Err(super::usage(
            "--name names one project; give it with one folder",
        ));
    }
    let cwd = std::env::current_dir().map_err(config)?;
    let full = |paths: Vec<PathBuf>| -> Vec<PathBuf> {
        paths
            .into_iter()
            .map(|d| {
                let d = cwd.join(d);
                d.canonicalize().unwrap_or(d)
            })
            .collect()
    };
    let files = full(files);
    let dirs = if dirs.is_empty() {
        vec![cwd.clone()]
    } else {
        full(dirs)
    };
    let dir = ConfigDir::from_env().map_err(config)?;
    let store = StoreFile::new(dir.store_file());
    if !store.exists().map_err(super::store_error)? {
        let tell = "set kagebunshin up first: run `kagebunshin setup` in a terminal";
        return Err(CliError::new(
            Exit::Failure,
            "no_store",
            "there is no local store yet, so nothing was onboarded",
        )
        .with_hint("run `kagebunshin setup` first; it creates the store and starts the daemon")
        .human(tell));
    }
    let registry = Registry::load(&dir).map_err(config)?;
    let asked = env.clone();
    let env = env.unwrap_or_else(|| registry.config.default_env.clone());
    let mut client = super::connect(socket.clone())?;
    let Response::Status(status) = client.request(Request::Status { facts: None })? else {
        return Err(super::unexpected());
    };

    let Planned {
        mut jobs,
        skipped,
        others,
    } = if files.is_empty() {
        plan_jobs(&dirs, &registry, &dir, &env, name.as_ref(), &exclude, &cwd)?
    } else {
        plan_files(&files, &registry, &dir, &env, name.as_ref())?
    };
    // Unlocked, the store says now which sections already have keys; else
    // once the daemon is unlocked.
    if !status.locked {
        settle(&mut client, &mut jobs, &env)?;
    }

    // One passphrase, for what needs it.
    let imports: Vec<&PathBuf> = jobs
        .iter()
        .filter(|j| matches!(j.work, Work::Import(_)))
        .flat_map(|j| &j.files)
        .collect();
    let any = jobs.iter().any(|j| !matches!(j.work, Work::Failed(_)));
    let unlock = status.locked && any;
    if let Some(ahead) = ahead(&jobs, &skipped, &env) {
        eprintln!("{ahead}");
    }
    // With no terminal to type the passphrase at, as when an agent runs
    // this, a person approves the import in the app instead, which takes
    // the passphrase there and unlocks with it too.
    let by_agent = !std::io::stdin().is_terminal();
    let in_app = !imports.is_empty() && by_agent;
    if in_app && !status.app {
        let n = imports.len();
        return Err(CliError::new(
            Exit::Refused,
            "no_app",
            format!(
                "importing {n} env {} takes the local store's passphrase, which a person types: \
                 in the app when this runs with no terminal, and the app is not open; nothing \
                 was imported",
                plural(n, "file", "files")
            ),
        )
        .with_hint(
            "once the app is open, run this again: the app's window lists what is imported and \
             takes the passphrase. In a terminal this asks for the passphrase itself",
        )
        .human(
            "open the app (`kagebunshin app`), so the import into the local store can be \
             approved there",
        ));
    }
    let passphrase = if in_app {
        None
    } else if unlock || !imports.is_empty() {
        let mut why = Vec::new();
        if unlock {
            why.push("to unlock".to_owned());
        }
        if !imports.is_empty() {
            let kind = if imports.iter().all(|f| f.ends_with(".env")) {
                ".env"
            } else {
                "env"
            };
            let n = imports.len();
            why.push(format!(
                "to import {n} {kind} {}",
                plural(n, "file", "files")
            ));
        }
        let p = super::prompt(&format!(
            "Passphrase for the local store ({}): ",
            why.join(", and ")
        ))?;
        // Checked before anything is written, as `setup` does.
        store
            .open(&copy(&p).into_passphrase())
            .map_err(|e| match e {
                crate::store::StoreError::WrongPassphrase => CliError::new(
                    Exit::Failure,
                    "wrong_passphrase",
                    "wrong passphrase for the local store; nothing was written",
                ),
                e => super::store_error(e),
            })?;
        // The daemon closes a connection left idle, and a person may take
        // longer than that to type.
        client = super::connect(socket.clone())?;
        if unlock {
            client.request(Request::Unlock {
                passphrase: Some(copy(&p)),
            })?;
        }
        Some(p)
    } else {
        None
    };

    if let Some(p) = &passphrase {
        if unlock {
            settle(&mut client, &mut jobs, &env)?;
        }
        import(&mut client, &dir, &env, &mut jobs, Some(p));
    } else if in_app {
        import(&mut client, &dir, &env, &mut jobs, None);
    }
    drop(passphrase);

    // Drafts, one gathering per checkout.
    let mut by_root: BTreeMap<PathBuf, Vec<usize>> = BTreeMap::new();
    for (i, j) in jobs.iter().enumerate() {
        if matches!(j.work, Work::Draft) {
            by_root.entry(j.root.clone()).or_default().push(i);
        }
    }
    for (root, at) in by_root {
        let apps: Vec<facts::App> = at.iter().map(|&i| jobs[i].app.clone()).collect();
        let again = format!(
            "kagebunshin onboard {}",
            super::shell_quote(&root.to_string_lossy())
        );
        eprintln!(
            "drafting {} from the checkout and the providers",
            root.display()
        );
        let drafted = draft::gather(socket.clone(), Some(&root)).and_then(|g| {
            draft::draft_apps(socket.clone(), &g, &apps, name.as_ref(), Some(&again))
        });
        match drafted {
            Ok((drafts, _)) => {
                for (&i, (d, error)) in at.iter().zip(drafts) {
                    drafted_job(&mut jobs[i], &d, error);
                }
            }
            Err(e) => {
                for &i in &at {
                    jobs[i].fail(same(&e));
                }
            }
        }
    }

    // Each project's state, as `next` sees it there.
    let looked = jobs
        .iter()
        .filter(|j| !matches!(j.work, Work::Failed(_)))
        .count();
    let mut nth = 0;
    let plans: Vec<Option<Plan>> = jobs
        .iter()
        .map(|j| {
            if matches!(j.work, Work::Failed(_)) {
                return None;
            }
            nth += 1;
            let of = if looked > 1 {
                format!(" ({nth} of {looked})")
            } else {
                String::new()
            };
            match &j.project {
                Some(name) => eprintln!("reading the state of {name}{of}"),
                None => eprintln!("reading the state of {}{of}", j.dir().display()),
            }
            // The files left are named once, at the end, not for each.
            next::look(socket.clone(), j.dir(), asked.clone(), None)
                .ok()
                .map(|mut seen| {
                    seen.others.clear();
                    next::plan(&seen)
                })
        })
        .collect();

    let imported: Vec<PathBuf> = jobs
        .iter()
        .filter(|j| matches!(j.work, Work::Import(_)) && !j.keys.is_empty())
        .flat_map(|j| j.files.clone())
        .collect();
    let not_imported: Vec<NotImported> = others
        .into_iter()
        .filter(|o| !imported.contains(&o.file))
        .collect();
    if !imported.is_empty() {
        Record::read().add(&imported);
    }

    let outs: Vec<ProjectOut<'_>> = jobs
        .iter()
        .zip(&plans)
        .map(|(j, plan)| project_out(j, plan.as_ref()))
        .collect();
    let failed = jobs.iter().find_map(|j| match &j.work {
        Work::Failed(e) => Some(e),
        _ => None,
    });
    let paste = plans.iter().flatten().any(|p| !p.done);

    if json {
        let delete = !imported.is_empty() && delete_env == Some(true);
        let deleted = if delete {
            delete_files(&imported)
        } else {
            Vec::new()
        };
        print_json(&serde_json::json!({
            "projects": outs,
            "skipped": skipped,
            "not_imported": not_imported,
            "deleted": deleted,
            "paste": PASTE,
        }))?;
    } else {
        let mut text = render(&outs, &skipped);
        if let Some(block) = not_imported_block(&not_imported) {
            text.push_str(&format!("\n\n{block}"));
        }
        if paste && by_agent {
            text.push_str(
                "\n\nThen go on with `kagebunshin next` in each checkout above that is not done.",
            );
        } else if paste {
            text.push_str(&format!(
                "\n\nThen, in each checkout above that is not done, paste this line into your \
                 coding agent:\n  {PASTE}"
            ));
        }
        // Apart from the steps above it.
        eprintln!();
        print_line(&text)?;
        if !imported.is_empty() {
            let shown: Vec<String> = imported.iter().map(|p| p.display().to_string()).collect();
            let question = match shown.as_slice() {
                [one] => format!("Delete {one} now that its values are in the store? [y/N] "),
                _ => format!(
                    "Delete {} now that their values are in the store? [y/N] ",
                    shown.join(", ")
                ),
            };
            let delete = match delete_env {
                Some(d) => d,
                // Deleting them is the person's choice: not asked of an agent.
                None if by_agent => false,
                None => super::connect::confirm(&format!("\n{question}")).unwrap_or(false),
            };
            let deleted = if delete {
                delete_files(&imported)
            } else {
                Vec::new()
            };
            let kept: Vec<&String> = shown
                .iter()
                .zip(&imported)
                .filter(|(_, p)| !deleted.contains(p))
                .map(|(s, _)| s)
                .collect();
            if !deleted.is_empty() {
                let d: Vec<String> = deleted.iter().map(|p| p.display().to_string()).collect();
                print_line(&format!("deleted {}", d.join(", ")))?;
            }
            if !kept.is_empty() {
                let k: Vec<&str> = kept.iter().map(|s| s.as_str()).collect();
                print_line(&format!(
                    "kept {}; delete {} once `kagebunshin run -- COMMAND` works",
                    k.join(", "),
                    plural(k.len(), "it", "them")
                ))?;
            }
        }
    }

    if let Some(e) = failed {
        return Err(same(e));
    }
    if jobs.is_empty()
        && let Some(s) = skipped.iter().find(|s| !s.left_out)
    {
        let code = if s.why.contains("no network remote") {
            "no_remote"
        } else {
            "no_project"
        };
        return Err(CliError::new(
            Exit::Failure,
            code,
            "none of the folders is a git checkout with a remote, so nothing was onboarded",
        ));
    }
    Ok(())
}

fn copy(p: &WireSecret) -> WireSecret {
    WireSecret::new(p.expose().to_owned())
}

/// `e` again, for each job one failure stops and for the exit.
fn same(e: &CliError) -> CliError {
    CliError {
        hint: e.hint.clone(),
        who: e.who,
        tell: e.tell.clone(),
        ..CliError::new(e.exit, e.code, e.message.clone())
    }
}

/// What there is to do, said before the passphrase is asked for, so it
/// can be checked first and the lines that follow count towards
/// something: each app and what is done for it, and the apps left out.
/// `None` when there is nothing to do.
fn ahead(jobs: &[Job], skipped: &[Skipped], env: &EnvName) -> Option<String> {
    // A failure says itself, and alone it is all there is to say.
    if jobs.iter().all(|j| matches!(j.work, Work::Failed(_))) {
        return None;
    }
    let what = |j: &Job| {
        let name =
            (j.project.as_ref()).map_or_else(|| "(no project)".to_owned(), |p| p.to_string());
        let files = j.files_shown();
        match &j.work {
            Work::Import(Into::New) => format!("import {files} into new project {name}"),
            Work::Import(Into::Existing) => format!("import {files} into project {name}"),
            Work::Import(Into::NewEnv) => {
                format!("import {files} into project {name}, as its new environment {env}")
            }
            Work::Draft => format!("draft new project {name}"),
            Work::Leave { .. } => format!("already project {name}; left as it is"),
            Work::Failed(_) => "nothing: it cannot be onboarded, and why is said below".to_owned(),
        }
    };
    let left_out: Vec<&Skipped> = skipped.iter().filter(|s| s.left_out).collect();
    if let ([job], true) = (jobs, left_out.is_empty()) {
        return Some(format!("onboarding {}: {}", job.dir().display(), what(job)));
    }
    let count = |is: fn(&Work) -> bool| jobs.iter().filter(|j| is(&j.work)).count();
    let imports: usize = jobs
        .iter()
        .filter(|j| matches!(j.work, Work::Import(_)))
        .map(|j| j.files.len())
        .sum();
    let drafts = count(|w| matches!(w, Work::Draft));
    let left = count(|w| matches!(w, Work::Leave { .. }));
    let mut roots: Vec<&PathBuf> = jobs.iter().map(|j| &j.root).collect();
    roots.sort();
    roots.dedup();
    let mut parts = Vec::new();
    if imports > 0 {
        parts.push(format!(
            "{imports} env {} to import",
            plural(imports, "file", "files")
        ));
    }
    if drafts > 0 {
        parts.push(format!("{drafts} to draft"));
    }
    if left > 0 {
        parts.push(format!("{left} already set up"));
    }
    let summary = if parts.is_empty() {
        String::new()
    } else {
        format!(": {}", parts.join(", "))
    };
    let mut out = format!(
        "onboarding {} {} in {} {}{summary}",
        jobs.len(),
        plural(jobs.len(), "app", "apps"),
        roots.len(),
        plural(roots.len(), "checkout", "checkouts"),
    );
    // In one checkout a folder is named from its root.
    let shown = |dir: &Path| -> String {
        let short = match roots.as_slice() {
            [root] => dir
                .strip_prefix(root)
                .ok()
                .filter(|d| !d.as_os_str().is_empty()),
            _ => None,
        };
        short.unwrap_or(dir).display().to_string()
    };
    for j in jobs {
        out.push_str(&format!("\n  {}: {}", shown(&j.dir()), what(j)));
    }
    for s in left_out {
        out.push_str(&format!("\n  {}: left out", shown(&s.dir)));
    }
    Some(out)
}

/// The files of `paths` it could delete.
fn delete_files(paths: &[PathBuf]) -> Vec<PathBuf> {
    paths
        .iter()
        .filter(|p| std::fs::remove_file(p).is_ok())
        .cloned()
        .collect()
}

/// The command that imports `file` of the checkout at `root`, whose apps
/// are `apps`. `--name PROJECT` is in it when the file is in no app's
/// folder and the checkout has several: then nothing says whose it is.
pub(super) fn import_command(root: &Path, apps: &[facts::App], file: &Path) -> String {
    let here = file
        .parent()
        .and_then(|p| p.strip_prefix(root).ok())
        .unwrap_or(Path::new(""));
    let placed = apps.len() < 2 || apps.iter().any(|a| here.starts_with(&a.dir));
    format!(
        "kagebunshin onboard --file {} --env ENV{}",
        super::shell_quote(&file.to_string_lossy()),
        if placed { "" } else { " --name PROJECT" }
    )
}

/// An env file as it was when it was imported: where, how long and when
/// last changed. Nothing of what is in it.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Stamp {
    path: PathBuf,
    len: u64,
    /// Nanoseconds since the Unix epoch.
    modified: u64,
}

impl Stamp {
    /// Of the file at `path` now; `None` when it cannot be looked at.
    fn of(path: &Path) -> Option<Self> {
        let meta = std::fs::metadata(path).ok()?;
        let modified = meta.modified().ok()?;
        let since = modified.duration_since(std::time::UNIX_EPOCH).ok()?;
        Some(Self {
            path: path.to_owned(),
            len: meta.len(),
            modified: u64::try_from(since.as_nanos()).unwrap_or(u64::MAX),
        })
    }
}

/// The env files `onboard` imported that were still there, unchanged,
/// when last looked: `imported.json` beside the audit log. One of them is
/// not named as not imported. It holds paths, sizes and times only, and a
/// file that cannot be read or written just means nothing is remembered.
pub(super) struct Record {
    path: Option<PathBuf>,
    files: Vec<Stamp>,
}

impl Record {
    const FILE: &str = "imported.json";

    pub(super) fn read() -> Self {
        let log = crate::audit::AuditLog::from_env().ok();
        Self::at(log.map(|log| log.path().with_file_name(Self::FILE)))
    }

    fn at(path: Option<PathBuf>) -> Self {
        let files = (path.as_ref())
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        Self { path, files }
    }

    /// Whether `file` is as it was when it was imported.
    fn holds(&self, file: &Path) -> bool {
        Stamp::of(file).is_some_and(|now| self.files.contains(&now))
    }

    /// Remembers `imported` as they are now, and forgets every file that
    /// has changed or gone since.
    fn add(mut self, imported: &[PathBuf]) {
        let Some(path) = &self.path else {
            return;
        };
        (self.files)
            .retain(|f| !imported.contains(&f.path) && Stamp::of(&f.path).as_ref() == Some(f));
        self.files
            .extend(imported.iter().filter_map(|f| Stamp::of(f)));
        if let (Some(dir), Ok(json)) = (path.parent(), serde_json::to_vec_pretty(&self.files)) {
            let _ = std::fs::create_dir_all(dir);
            let _ = crate::atomic::write_private(path, &json);
        }
    }
}

/// The app folders `onboard --exclude` left out: `left-out.json` beside
/// the audit log. While no project claims one, `onboard` and
/// `project draft --apply` of its whole checkout pass over it and `next`
/// there does not wait for it; naming the folder itself sets it up. It
/// holds paths only, and a file that cannot be read or written just means
/// nothing is remembered.
pub(super) struct LeftOut {
    path: Option<PathBuf>,
    dirs: Vec<PathBuf>,
}

impl LeftOut {
    const FILE: &str = "left-out.json";

    pub(super) fn read() -> Self {
        let log = crate::audit::AuditLog::from_env().ok();
        Self::at(log.map(|log| log.path().with_file_name(Self::FILE)))
    }

    fn at(path: Option<PathBuf>) -> Self {
        let dirs = (path.as_ref())
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        Self { path, dirs }
    }

    /// Whether the app in `dir`, a folder in full, was left out.
    pub(super) fn holds(&self, dir: &Path) -> bool {
        self.dirs.iter().any(|d| d == dir)
    }

    /// Remembers `add`, and forgets `remove` and every folder that has
    /// gone since.
    fn change(mut self, add: &[PathBuf], remove: &[PathBuf]) {
        let Some(path) = &self.path else {
            return;
        };
        if add.is_empty() && remove.is_empty() {
            return;
        }
        self.dirs.retain(|d| d.is_dir() && !remove.contains(d));
        self.dirs.extend(add.iter().cloned());
        self.dirs.sort();
        self.dirs.dedup();
        if let (Some(dir), Ok(json)) = (path.parent(), serde_json::to_vec_pretty(&self.dirs)) {
            let _ = std::fs::create_dir_all(dir);
            let _ = crate::atomic::write_private(path, &json);
        }
    }
}

/// The files with values in the checkout at `root` that `onboard` does not
/// import by itself and has not imported as they are (`record`), added to
/// `others`, each once.
fn note_others(
    root: &Path,
    checkout: &facts::CheckoutFacts,
    record: &Record,
    others: &mut Vec<NotImported>,
) {
    for file in &checkout.other_env_files {
        let file = root.join(file);
        if !others.iter().any(|o| o.file == file) && !record.holds(&file) {
            others.push(NotImported {
                command: import_command(root, &checkout.apps, &file),
                file,
            });
        }
    }
}

/// The files with values in the checkout at `root` that `onboard` does not
/// import by itself and has not imported as they are, and the command for
/// each.
pub(super) fn others_in(root: &Path) -> Vec<NotImported> {
    let mut others = Vec::new();
    note_others(root, &facts::read(root), &Record::read(), &mut others);
    others
}

/// What is said of the files not imported; `None` when there are none.
fn not_imported_block(files: &[NotImported]) -> Option<String> {
    if files.is_empty() {
        return None;
    }
    let n = files.len();
    let mut out = format!(
        "not imported: {n} more {} with values. `onboard` takes one .env file for each app by \
         itself; to import another, run its line with the environment its values are for as \
         ENV:",
        plural(n, "file", "files")
    );
    for f in files {
        out.push_str(&format!("\n  {}", f.command));
    }
    if files.iter().any(|f| f.command.ends_with("PROJECT")) {
        out.push_str(
            "\n  PROJECT is the project a file outside every app's folder is for, by its name \
             above",
        );
    }
    Some(out)
}

/// The app of the checkout at `root` that the file in folder `here` is
/// for, of `apps`: the folder of the project `name`, if there is one and
/// it claims the checkout; else of the project that claims `here`; else
/// the app `here` is in; else the root, in a checkout with no apps; else
/// the app whose project would be called `name`; else the only app there
/// is. A file in none of several apps needs `--name`.
fn owner(
    root: &Path,
    here: &Path,
    file: &Path,
    apps: &[facts::App],
    remotes: &[RemoteId],
    registry: &Registry,
    name: Option<&ProjectName>,
) -> Result<facts::App, CliError> {
    let claims = |p: &&crate::config::Project| p.file.remotes.iter().any(|r| remotes.contains(r));
    let folder = |p: &crate::config::Project| -> PathBuf {
        p.file
            .path
            .as_ref()
            .map_or_else(PathBuf::new, |p| p.as_str().into())
    };
    let app_at = |dir: PathBuf| {
        apps.iter()
            .find(|a| a.dir == dir)
            .cloned()
            .unwrap_or_else(|| facts::App {
                dir,
                example: None,
                env_files: Vec::new(),
            })
    };
    if let Some(p) = name.and_then(|n| registry.project(n)) {
        if !claims(&p) {
            return Err(config(format!(
                "project {} does not claim the checkout {} is in; nothing was written",
                p.name,
                file.display()
            )));
        }
        return Ok(app_at(folder(p)));
    }
    let claimer = registry
        .projects()
        .filter(claims)
        .map(folder)
        .filter(|dir| here.starts_with(dir))
        .max_by_key(|dir| dir.components().count());
    if let Some(dir) = claimer {
        return Ok(app_at(dir));
    }
    let inside = apps
        .iter()
        .filter(|a| here.starts_with(&a.dir))
        .max_by_key(|a| a.dir.components().count());
    if let Some(app) = inside {
        return Ok(app.clone());
    }
    if apps.is_empty() {
        return Ok(app_at(PathBuf::new()));
    }
    // By the name each app's project has, or would get.
    let named = |a: &facts::App| -> Option<ProjectName> {
        registry
            .projects()
            .filter(claims)
            .find(|p| folder(p) == a.dir)
            .map(|p| p.name.clone())
            .or_else(|| draft::default_name(root, &a.dir).ok())
    };
    if let Some(app) = name.and_then(|n| apps.iter().find(|a| named(a).as_ref() == Some(n))) {
        return Ok(app.clone());
    }
    if let ([only], None) = (apps, name) {
        return Ok(only.clone());
    }
    let names: Vec<String> = apps
        .iter()
        .filter_map(|a| Some(format!("{} ({})", named(a)?, a.dir.display())))
        .collect();
    Err(super::usage(format!(
        "{} is in the folder of none of the {} {} of {}, so nothing says which project it is \
         for; nothing was written",
        file.display(),
        apps.len(),
        plural(apps.len(), "app", "apps"),
        root.display()
    ))
    .with_hint(format!(
        "say which with `--name NAME` after the same command: one of {}",
        names.join(", ")
    )))
}

/// What a run of `onboard` is to do: a job per app, the folders skipped,
/// with why, and the files with values that are no job's to import.
struct Planned {
    jobs: Vec<Job>,
    skipped: Vec<Skipped>,
    others: Vec<NotImported>,
}

/// One job per app that one of `files` is for ([`owner`]), and the other
/// files with values in their checkouts. Fails, before anything is asked
/// or written, for a file that is none, is in no checkout with a remote,
/// or is for no one app.
fn plan_files(
    files: &[PathBuf],
    registry: &Registry,
    config_dir: &ConfigDir,
    env: &EnvName,
    name: Option<&ProjectName>,
) -> Result<Planned, CliError> {
    let mut jobs: Vec<Job> = Vec::new();
    let mut others = Vec::new();
    let record = Record::read();
    for file in files {
        let shown = file.display();
        let folder = file
            .parent()
            .filter(|_| file.is_file())
            .ok_or_else(|| super::usage(format!("{shown} is not a file; nothing was written")))?;
        let checkout = Git::default().checkout(folder).map_err(|_| {
            CliError::new(
                Exit::Failure,
                "no_project",
                format!(
                    "{shown} is not inside a git checkout, so no project can be its; nothing \
                     was written"
                ),
            )
        })?;
        if checkout.remotes.is_empty() {
            return Err(CliError::new(
                Exit::Failure,
                "no_remote",
                format!(
                    "the git checkout {shown} is in has no network remote, so no project can \
                     claim it; nothing was written"
                ),
            )
            .with_hint("add one with `git remote add origin URL`"));
        }
        let root = checkout
            .root
            .canonicalize()
            .unwrap_or_else(|_| checkout.root.clone());
        let here = checkout.subdir(folder).unwrap_or_default();
        let found = facts::read(&root);
        note_others(&root, &found, &record, &mut others);
        let app = owner(
            &root,
            &here,
            file,
            &found.apps,
            &checkout.remotes,
            registry,
            name,
        )?;
        if let Some(job) = jobs
            .iter_mut()
            .find(|j| j.root == root && j.app.dir == app.dir)
        {
            if !job.files.contains(file) {
                job.files.push(file.clone());
            }
            continue;
        }
        jobs.push(Job {
            root,
            remotes: checkout.remotes,
            app,
            project: None,
            work: Work::Draft,
            did: String::new(),
            files: vec![file.clone()],
            asked: true,
            keys: Vec::new(),
        });
    }
    if name.is_some() && jobs.len() > 1 {
        return Err(super::usage(
            "--name names one project, and the files are for several; give the files of one \
             project at a time",
        ));
    }
    for job in &mut jobs {
        classify(job, registry, config_dir, env, name);
    }
    Ok(Planned {
        jobs,
        skipped: Vec::new(),
        others,
    })
}

/// The project of `registry` that claims the app in `folder` of a checkout
/// with `remotes`, as `project draft` sees it.
fn claimer<'a>(
    registry: &'a Registry,
    remotes: &[RemoteId],
    folder: Option<&ProjectPath>,
) -> Option<&'a crate::config::Project> {
    registry.projects().find(|p| {
        p.file.path.as_ref() == folder && p.file.remotes.iter().any(|r| remotes.contains(r))
    })
}

/// One job per app of the checkouts of `dirs`, each app once; the folders
/// skipped, with why; and the files with values there that are not any
/// app's to import.
///
/// An app `exclude` names is left out, and remembered as such
/// ([`LeftOut`]): by its folder, from `cwd` or from its checkout's root, or
/// by its project's name, the one it has or would get. So is an app left
/// out before that no project claims, when its whole checkout is
/// onboarded; naming its own folder sets it up again.
///
/// Fails only for a usage error, before anything is written: `--name` for
/// a checkout of several apps, or an `exclude` that names no app.
fn plan_jobs(
    dirs: &[PathBuf],
    registry: &Registry,
    config_dir: &ConfigDir,
    env: &EnvName,
    name: Option<&ProjectName>,
    exclude: &[String],
    cwd: &Path,
) -> Result<Planned, CliError> {
    let mut jobs: Vec<Job> = Vec::new();
    let mut skipped = Vec::new();
    let mut others = Vec::new();
    let record = Record::read();
    let left_out = LeftOut::read();
    // Which of `exclude` named an app, every app seen as it can be named,
    // and what `left_out` is to remember and forget.
    let mut used = vec![false; exclude.len()];
    let mut seen: Vec<String> = Vec::new();
    let (mut add, mut remove) = (Vec::new(), Vec::new());
    for dir in dirs {
        let skip = |why: String| Skipped {
            dir: dir.clone(),
            why,
            left_out: false,
        };
        if !dir.is_dir() {
            skipped.push(skip("it is not a folder".into()));
            continue;
        }
        let Ok(checkout) = Git::default().checkout(dir) else {
            skipped.push(skip("it is not inside a git checkout".into()));
            continue;
        };
        if checkout.remotes.is_empty() {
            skipped.push(skip(
                "its git checkout has no network remote, so no project can claim it; add one \
                 with `git remote add origin URL`"
                    .into(),
            ));
            continue;
        }
        let root = checkout
            .root
            .canonicalize()
            .unwrap_or_else(|_| checkout.root.clone());
        let here = checkout.subdir(dir).unwrap_or_default();
        let found = facts::read(&root);
        note_others(&root, &found, &record, &mut others);
        let found = found.apps;
        let whole = here.as_os_str().is_empty() && found.len() > 1;
        let mut apps = if whole {
            found
        } else {
            vec![draft::pick_app(&root, &here, &found)?]
        };
        apps.retain(|app| {
            let at = root.join(&app.dir);
            let folder = ProjectPath::try_from(app.dir.to_string_lossy().into_owned()).ok();
            let claimed = claimer(registry, &checkout.remotes, folder.as_ref());
            let project = match claimed {
                Some(p) => Some(p.name.clone()),
                None => draft::default_name(&root, &app.dir).ok(),
            };
            let named = |x: &String| {
                let path = cwd.join(x);
                path.canonicalize().unwrap_or(path) == at
                    || (!app.dir.as_os_str().is_empty() && Path::new(x) == app.dir)
                    || project.as_ref().is_some_and(|p| p.to_string() == *x)
            };
            seen.push(match &project {
                Some(p) => format!("{} ({p})", at.display()),
                None => at.display().to_string(),
            });
            let mut out = false;
            for (x, used) in exclude.iter().zip(&mut used) {
                if named(x) {
                    (*used, out) = (true, true);
                }
            }
            let why = if out {
                add.push(at.clone());
                "left out with --exclude".to_owned()
            } else if whole && claimed.is_none() && left_out.holds(&at) {
                format!(
                    "left out before with --exclude; `kagebunshin onboard {}` sets it up",
                    super::shell_quote(&at.to_string_lossy())
                )
            } else {
                if left_out.holds(&at) {
                    remove.push(at);
                }
                return true;
            };
            if !skipped.iter().any(|s: &Skipped| s.dir == at) {
                skipped.push(Skipped {
                    dir: at,
                    why,
                    left_out: true,
                });
            }
            false
        });
        if name.is_some() && apps.len() > 1 {
            return Err(super::usage(format!(
                "{} has {} apps, and --name names one project; give the app's folder",
                root.display(),
                apps.len()
            )));
        }
        for app in apps {
            if jobs.iter().any(|j| j.root == root && j.app.dir == app.dir) {
                continue;
            }
            let mut job = Job {
                root: root.clone(),
                remotes: checkout.remotes.clone(),
                app,
                project: None,
                work: Work::Draft,
                did: String::new(),
                files: Vec::new(),
                asked: false,
                keys: Vec::new(),
            };
            job.files = (job.app.env_file_with_values())
                .map(|f| job.dir().join(&f.name))
                .into_iter()
                .collect();
            classify(&mut job, registry, config_dir, env, name);
            jobs.push(job);
        }
    }
    if let Some((x, _)) = exclude.iter().zip(&used).find(|(_, used)| !**used) {
        let apps = if seen.is_empty() {
            "no app was found there".to_owned()
        } else {
            format!("the apps there are {}", seen.join(", "))
        };
        return Err(super::usage(format!(
            "--exclude {x} names no app, by its folder or its project's name; nothing was \
             written; {apps}"
        )));
    }
    left_out.change(&add, &remove);
    Ok(Planned {
        jobs,
        skipped,
        others,
    })
}

/// What to do for `job`'s app; the claims are those `project draft` sees:
/// a project of the checkout's remotes and the app's folder.
fn classify(
    job: &mut Job,
    registry: &Registry,
    config_dir: &ConfigDir,
    env: &EnvName,
    name: Option<&ProjectName>,
) {
    let folder = job.folder();
    let shown = job.dir().display().to_string();
    let again = job.again();
    let files = job.files_shown();
    if let Some(p) = claimer(registry, &job.remotes, folder.as_ref()) {
        job.project = Some(p.name.clone());
        if let Some(n) = name.filter(|n| **n != p.name) {
            job.fail(
                config(format!(
                    "project {} already claims {shown}, so it cannot be onboarded as {n}; \
                     nothing was written",
                    p.name
                ))
                .with_hint(format!("leave out --name: `{again}`")),
            );
            return;
        }
        job.did = "already a project; left as it is".into();
        if job.files.is_empty() {
            job.work = Work::Leave { note: None };
        } else if !job.asked {
            let file = job.files.first().cloned().unwrap_or_default();
            job.work = match super::project::fillable(registry, p, env, &file) {
                Ok(()) => Work::Import(Into::Existing),
                Err(e) => Work::Leave {
                    note: Some(format!(
                        "{files} was not imported: {}{}",
                        e.message,
                        e.hint.map(|h| format!("; {h}")).unwrap_or_default()
                    )),
                },
            };
        } else if !p.file.envs.contains_key(env) {
            job.work = Work::Import(Into::NewEnv);
        } else if super::project::reads_own_section(registry, p, env, true) {
            job.work = Work::Import(Into::Existing);
        } else {
            let name = &p.name;
            job.fail(
                config(format!(
                    "environment {env} of project {name} does not read the local store's \
                     [{name}.{env}], so the values of {files} would go unused there; nothing \
                     was written"
                ))
                .with_hint(format!(
                    "add it as a source with `kagebunshin project add-source {name} {env} \
                     --provider file`, then run this again; a later source wins over an \
                     earlier one"
                )),
            );
        }
        return;
    }
    let project = match name {
        Some(n) => n.clone(),
        None => match draft::default_name(&job.root, &job.app.dir) {
            Ok(n) => n,
            Err(e) => {
                job.fail(e.with_hint(format!("give one: `{again} --name NAME`")));
                return;
            }
        },
    };
    job.project = Some(project.clone());
    if registry.project(&project).is_some() || config_dir.project_file(&project).exists() {
        job.fail(
            config(format!(
                "project {project} already exists and claims another folder; nothing was \
                 written"
            ))
            .with_hint(format!("give another name: `{again} --name NAME`")),
        );
        return;
    }
    job.work = if job.files.is_empty() {
        Work::Draft
    } else {
        Work::Import(Into::New)
    };
}

/// Settles the imports into a store section that already has keys: an
/// existing project's is left as it is, a new one's is refused. Files
/// `--file` named go into an existing project's whatever is there.
fn settle(client: &mut Client, jobs: &mut [Job], env: &EnvName) -> Result<(), CliError> {
    let Response::StoreList(listing) = client.request(Request::StoreList)? else {
        return Err(super::unexpected());
    };
    for job in jobs {
        let (Work::Import(into), Some(name)) = (&job.work, &job.project) else {
            continue;
        };
        if job.asked && *into != Into::New {
            continue;
        }
        let section = Section {
            project: name.clone(),
            env: env.clone(),
        };
        if !listing
            .sections
            .iter()
            .any(|s| s.section == section && !s.keys.is_empty())
        {
            continue;
        }
        has_keys(job, &section);
    }
    Ok(())
}

/// What becomes of an importing `job` whose `section` already has keys:
/// an existing project's is left as it is, a new one's is refused.
fn has_keys(job: &mut Job, section: &Section) {
    if matches!(job.work, Work::Import(Into::Existing)) {
        let file = job.files_shown();
        job.work = Work::Leave {
            note: Some(format!(
                "{file} is still here, and the local store already has keys in [{section}], so \
                 it was not imported again; delete it once `kagebunshin run -- COMMAND` works"
            )),
        };
    } else {
        let shown = job.dir().display().to_string();
        job.fail(
            config(format!(
                "the local store already has keys in [{section}]; nothing was written"
            ))
            .with_hint(format!(
                "give another name: `kagebunshin onboard {} --name NAME`",
                super::shell_quote(&shown)
            )),
        );
    }
}

/// One job's env files read, to go into the store's `section`.
struct Read {
    /// Whose they are, in the jobs.
    at: usize,
    section: Section,
    /// In file order: a later file's value for a key is the one kept.
    values: Vec<(KeyName, WireSecret)>,
    /// The project file written for it: a new project's, or the one that
    /// got the environment.
    written: Option<super::edit::Edited>,
    /// That file as it was, if it was there.
    before: Option<String>,
}

/// Moves the env files of every importing job into the store: into a new
/// project's section, or an existing one's. Under `passphrase`, or without
/// one once a person approves it in the app, where they type it; the
/// daemon may be locked then, and the approval unlocks it. A file that
/// cannot be read fails its own job. The rest go in with one store write,
/// so the store's key is derived once, and all or none: if the write
/// fails or is refused, the project files are put back as they were and
/// nothing was imported.
fn import(
    client: &mut Client,
    config_dir: &ConfigDir,
    env: &EnvName,
    jobs: &mut [Job],
    passphrase: Option<&WireSecret>,
) {
    let mut reads = Vec::new();
    for (at, job) in jobs.iter_mut().enumerate() {
        let (Work::Import(_), Some(name)) = (&job.work, &job.project) else {
            continue;
        };
        let section = Section {
            project: name.clone(),
            env: env.clone(),
        };
        let read = job.files.iter().try_fold(Vec::new(), |mut all, path| {
            eprintln!("importing {} into [{section}]", path.display());
            all.extend(read_env(path)?);
            Ok(all)
        });
        match read {
            Ok(values) => reads.push(Read {
                at,
                section,
                values,
                written: None,
                before: None,
            }),
            Err(e) => job.fail(e),
        }
    }
    if reads.is_empty() {
        return;
    }

    // The project files of the new ones, under one lock with the write.
    let lock = super::edit::lock(config_dir);
    if let Err(e) = &lock {
        for read in &reads {
            jobs[read.at].fail(same(e));
        }
        return;
    }
    reads.retain_mut(|read| {
        let job = &mut jobs[read.at];
        let name = &read.section.project;
        let into = match job.work {
            Work::Import(Into::Existing) => return true,
            Work::Import(into) => into,
            _ => return false,
        };
        // Loaded again for each: it has the ones just made.
        let written = Registry::load(config_dir)
            .map_err(config)
            .and_then(|registry| {
                if into == Into::NewEnv {
                    read.before = registry
                        .project(name)
                        .and_then(|p| std::fs::read_to_string(&p.path).ok());
                    return super::project::add_store_env(&registry, config_dir, name, env);
                }
                super::project::create_store_project(
                    &registry,
                    config_dir,
                    name,
                    env,
                    &job.remotes,
                    job.folder().as_ref(),
                )
            });
        match written {
            Ok(edited) => {
                read.written = Some(edited);
                true
            }
            Err(e) => {
                job.fail(e);
                false
            }
        }
    });
    if reads.is_empty() {
        return;
    }
    // Put back, when the values do not get in: no new project or
    // environment without them.
    let undo = |read: &Read| match (&read.written, &read.before) {
        (Some(edited), Some(before)) => {
            let _ = std::fs::write(&edited.path, before);
        }
        (Some(edited), None) => {
            let _ = std::fs::remove_file(&edited.path);
        }
        (None, _) => {}
    };

    let keys: Vec<Vec<KeyName>> = reads
        .iter()
        .map(|r| {
            let mut keys: Vec<KeyName> = Vec::new();
            for (k, _) in &r.values {
                if !keys.contains(k) {
                    keys.push(k.clone());
                }
            }
            keys
        })
        .collect();
    let total: usize = keys.iter().map(Vec::len).sum();
    let what = format!(
        "{total} {} from {} {}",
        plural(total, "key", "keys"),
        reads.len(),
        plural(reads.len(), "file", "files")
    );
    if passphrase.is_some() {
        eprintln!("writing {what} to the local store");
    } else {
        eprintln!(
            "waiting for a person to approve, in the kagebunshin app, importing {what} into \
             the local store: its window lists them and takes the store's passphrase"
        );
    }
    let sections = reads
        .iter_mut()
        .map(|r| {
            let job = &jobs[r.at];
            let into = match job.work {
                Work::Import(Into::New) => ImportInto::NewProject,
                Work::Import(Into::NewEnv) => ImportInto::NewEnv,
                _ => ImportInto::Existing,
            };
            ImportSection {
                section: r.section.clone(),
                values: std::mem::take(&mut r.values),
                files: job.files.clone(),
                into,
                // As `settle` has it, for a store only the daemon sees.
                if_empty: !(job.asked && into != ImportInto::NewProject),
            }
        })
        .collect();
    let written = match client.request(Request::StoreImport {
        sections,
        passphrase: passphrase.map(copy),
        cwd: std::env::current_dir().unwrap_or_default(),
        command: std::env::args().collect(),
    }) {
        Ok(Response::Imported { sections, .. }) if sections.len() == reads.len() => Ok(sections),
        Ok(_) => Err(super::unexpected()),
        Err(e) => Err(CliError::from(e)),
    };
    let written = match written {
        Ok(written) => written,
        Err(e) => {
            for read in &reads {
                undo(read);
                jobs[read.at].fail(same(&e));
            }
            return;
        }
    };
    drop(lock);

    for ((read, keys), done) in reads.iter().zip(keys).zip(written) {
        let job = &mut jobs[read.at];
        if !done.written {
            // It already has keys, which the locked daemon could not say.
            undo(read);
            has_keys(job, &read.section);
            continue;
        }
        for w in read.written.iter().flat_map(|e| &e.warnings) {
            eprintln!("warning: {w}");
        }
        let Work::Import(into) = job.work else {
            continue;
        };
        let Section { project: name, .. } = &read.section;
        let names: Vec<&str> = keys.iter().map(KeyName::as_str).collect();
        let over: Vec<&str> = done.replaced.iter().map(KeyName::as_str).collect();
        let replaced = if over.is_empty() {
            String::new()
        } else {
            format!(
                "; {} of them replaced a value already there: {}",
                over.len(),
                over.join(", ")
            )
        };
        job.did = format!(
            "{} and put {} {} from {} in the local store's [{}]: {}{replaced}",
            match into {
                Into::Existing => format!(
                    "used the existing project {name}, whose environment {env} reads the \
                     local store,"
                ),
                Into::NewEnv => format!("gave project {name} the environment {env},"),
                Into::New => format!("created project {name} with environment {env},"),
            },
            keys.len(),
            plural(keys.len(), "key", "keys"),
            job.files_shown(),
            read.section,
            names.join(", ")
        );
        job.keys = keys;
    }
}

/// The keys and values of the env file at `path`, to send to the daemon.
fn read_env(path: &std::path::Path) -> Result<Vec<(KeyName, WireSecret)>, CliError> {
    let text = std::fs::read_to_string(path)
        .map(zeroize::Zeroizing::new)
        .map_err(|e| config(format!("cannot read {}: {e}", path.display())))?;
    let (values, bad) = crate::repo::env_example::parse_values(&text);
    if !bad.is_empty() {
        let lines: Vec<String> = bad.iter().map(ToString::to_string).collect();
        return Err(CliError::new(
            Exit::Failure,
            "env_file",
            format!(
                "cannot read {}: {}; nothing was written",
                path.display(),
                lines.join("; ")
            ),
        ));
    }
    Ok(values
        .into_iter()
        .map(|(k, v)| (k, WireSecret::new(v.expose().to_owned())))
        .collect())
}

/// Records what drafting `job`'s app gave.
fn drafted_job(job: &mut Job, d: &AppDraft, error: Option<CliError>) {
    job.project = Some(d.project.clone());
    if let Some(e) = error {
        job.fail(e);
        return;
    }
    // The environments whose secrets a workflow lists.
    let listed: Vec<&str> = (d.envs.iter())
        .filter(|e| e.from.is_some())
        .map(|e| e.env.as_str())
        .collect();
    let from = if listed.is_empty() {
        "the checkout and the providers".to_owned()
    } else {
        format!(
            "the checkout, its workflows ({} {}) and the providers",
            plural(listed.len(), "environment", "environments"),
            listed.join(", ")
        )
    };
    let open = d.open_points();
    job.did = if open == 0 {
        format!("drafted from {from}, and installed")
    } else {
        format!(
            "drafted from {from}, and installed, with {open} open {}",
            plural(open, "point", "points")
        )
    };
}

fn project_out<'a>(j: &'a Job, plan: Option<&'a Plan>) -> ProjectOut<'a> {
    let error = match &j.work {
        Work::Failed(e) => Some(e),
        _ => None,
    };
    let note = match &j.work {
        Work::Leave { note } => note.as_deref(),
        _ => None,
    };
    let imported = match &j.work {
        Work::Import(_) if !j.keys.is_empty() => Some(Imported {
            files: &j.files,
            keys: &j.keys,
        }),
        _ => None,
    };
    ProjectOut {
        project: plan.and_then(|p| p.project.as_ref()).or(j.project.as_ref()),
        dir: j.dir(),
        env: plan.and_then(|p| p.env.as_ref()),
        did: &j.did,
        imported,
        note,
        set: plan.and_then(|p| p.keys).map(|k| k.set),
        of: plan.and_then(|p| p.keys).map(|k| k.wanted),
        state: match plan {
            Some(p) => state(p),
            None => vec!["failed"],
        },
        done: plan.is_some_and(|p| p.done),
        step: plan.and_then(|p| p.step.as_ref()),
        tell: plan
            .map(|p| p.human.iter().filter_map(|h| h.tell.as_deref()).collect())
            .unwrap_or_default(),
        error,
    }
}

fn render(outs: &[ProjectOut<'_>], skipped: &[Skipped]) -> String {
    let mut blocks = Vec::new();
    for o in outs {
        let name = o
            .project
            .map_or_else(|| "(no project)".to_owned(), ToString::to_string);
        let mut b = format!("{name} ({}): {}", o.dir.display(), o.did);
        if let Some(n) = o.note {
            b.push_str(&format!("\n  note: {n}"));
        }
        if let Some(e) = o.error {
            b.push_str(&format!("\n  failed: {}", e.message));
            if let Some(h) = &e.hint {
                b.push_str(&format!("\n  hint: {h}"));
            }
            blocks.push(b);
            continue;
        }
        match (o.env, o.set, o.of) {
            (Some(env), Some(set), Some(of)) => {
                b.push_str(&format!("\n  environment {env}: {set} of {of} keys set"));
            }
            _ => b.push_str("\n  its environment could not be resolved"),
        }
        for s in &o.state {
            match *s {
                READY if o.done => b.push_str("\n  ready: done, and proven by a run"),
                READY => b.push_str("\n  ready: your agent proves it with a run"),
                NEEDS_AGENT => {
                    let what = o.step.map(|s| s.what.as_str()).unwrap_or_default();
                    b.push_str(&format!("\n  needs your agent: {what}"));
                }
                NEEDS_YOU => {
                    b.push_str("\n  needs you:");
                    for t in &o.tell {
                        b.push_str(&format!("\n    - {t}"));
                    }
                }
                _ => {}
            }
        }
        blocks.push(b);
    }
    for s in skipped {
        blocks.push(format!("skipped {}: {}", s.dir.display(), s.why));
    }
    blocks.join("\n\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::protocol::Who;

    fn plan(done: bool, keys: (usize, usize), agent: Option<&str>, human: usize) -> Plan {
        let step = |what: &str, who| next::Step {
            who,
            what: what.into(),
            command: None,
            tell: (who == Who::Human).then(|| "Please do it.".to_owned()),
        };
        Plan {
            headline: String::new(),
            project: None,
            env: None,
            done,
            keys: Some(next::Keys {
                set: keys.0,
                wanted: keys.1,
            }),
            step: agent.map(|w| step(w, Who::Agent)),
            human: (0..human).map(|_| step("log in", Who::Human)).collect(),
        }
    }

    const SHOP: &str = "/src/shop";

    /// The projects of the checkout at [`SHOP`]: `shop-web` claims its
    /// `apps/web`, and `elsewhere` another repository.
    fn registry() -> (tempfile::TempDir, ConfigDir, Registry) {
        let dir = tempfile::tempdir().unwrap();
        let config = ConfigDir::new(dir.path().to_path_buf());
        std::fs::create_dir_all(config.projects_dir()).unwrap();
        std::fs::write(config.path().join("config.toml"), "schema = 1\n").unwrap();
        let write = |name: &str, text: &str| {
            std::fs::write(config.project_file(&name.parse().unwrap()), text).unwrap();
        };
        write(
            "shop-web",
            r#"schema = 1
remotes = ["github.com/acme/shop"]
path = "apps/web"

[envs.dev]
[[envs.dev.sources]]
provider = "file"

[envs.aws]
[[envs.aws.sources]]
provider = "aws_sm"
secret = "shop/web"

[envs.both]
[[envs.both.sources]]
provider = "aws_sm"
secret = "shop/web"
[[envs.both.sources]]
provider = "file"
"#,
        );
        write(
            "elsewhere",
            "schema = 1\nremotes = [\"github.com/acme/elsewhere\"]\n\n[envs.dev]\n",
        );
        let registry = Registry::load(&config).unwrap();
        (dir, config, registry)
    }

    fn remotes() -> Vec<RemoteId> {
        vec![RemoteId::parse("github.com/acme/shop").unwrap()]
    }

    fn app(dir: &str) -> facts::App {
        facts::App {
            dir: dir.into(),
            example: None,
            env_files: Vec::new(),
        }
    }

    #[test]
    fn a_named_file_goes_to_the_app_it_is_in_or_the_project_named() {
        let (_dir, _config, registry) = registry();
        let own = |apps: &[facts::App], here: &str, name: Option<&str>| {
            let name: Option<ProjectName> = name.map(|n| n.parse().unwrap());
            owner(
                Path::new(SHOP),
                Path::new(here),
                &Path::new(SHOP).join(here).join("production.env"),
                apps,
                &remotes(),
                &registry,
                name.as_ref(),
            )
            .map(|a| a.dir)
        };
        let dir = |d: &str| PathBuf::from(d);
        let apps = [app("apps/api"), app("apps/web")];
        // The project that claims the folder, then the app it is in.
        assert_eq!(own(&apps, "apps/web", None).unwrap(), dir("apps/web"));
        assert_eq!(
            own(&apps, "apps/web/deploy", None).unwrap(),
            dir("apps/web")
        );
        assert_eq!(own(&apps, "apps/api", None).unwrap(), dir("apps/api"));
        // In no app's folder: the project is named, as it is or would be
        // called.
        assert_eq!(own(&apps, "", Some("shop-web")).unwrap(), dir("apps/web"));
        assert_eq!(own(&apps, "", Some("shop-api")).unwrap(), dir("apps/api"));
        let e = own(&apps, "", None).unwrap_err();
        assert_eq!(e.code, "usage");
        assert!(e.message.contains("none of the 2 apps"), "{}", e.message);
        let hint = e.hint.unwrap();
        assert!(hint.contains("`--name NAME`"), "{hint}");
        assert!(
            hint.contains("shop-api (apps/api), shop-web (apps/web)"),
            "{hint}"
        );
        // The only app there is needs no name, wherever the file is.
        assert_eq!(own(&apps[1..], "", None).unwrap(), dir("apps/web"));
        assert_eq!(own(&apps[1..], "deploy", None).unwrap(), dir("apps/web"));
        // A named project wins over the folder, but only one of this
        // checkout.
        assert_eq!(
            own(&apps, "apps/api", Some("shop-web")).unwrap(),
            dir("apps/web")
        );
        let e = own(&apps, "", Some("elsewhere")).unwrap_err();
        assert!(e.message.contains("does not claim"), "{}", e.message);
        // A checkout with no apps, or whose root is one: the root.
        assert_eq!(own(&[], "deploy", None).unwrap(), dir(""));
        let rooted = [app(""), app("apps/web")];
        assert_eq!(own(&rooted, "deploy", None).unwrap(), dir(""));
        assert_eq!(own(&rooted, "apps/web", None).unwrap(), dir("apps/web"));
    }

    #[test]
    fn a_named_file_fills_an_existing_project_and_adds_its_environment() {
        let (_dir, config, registry) = registry();
        let job = |dir: &str, asked: bool, env: &str, name: Option<&str>| {
            let mut job = Job {
                root: SHOP.into(),
                remotes: remotes(),
                app: app(dir),
                project: None,
                work: Work::Draft,
                did: String::new(),
                files: vec![Path::new(SHOP).join(dir).join(".dev.env")],
                asked,
                keys: Vec::new(),
            };
            let name: Option<ProjectName> = name.map(|n| n.parse().unwrap());
            classify(
                &mut job,
                &registry,
                &config,
                &env.parse().unwrap(),
                name.as_ref(),
            );
            job
        };
        let project = |j: &Job| j.project.as_ref().map(ToString::to_string);

        // Its own section is read, alone or among others: filled.
        for env in ["dev", "both"] {
            let j = job("apps/web", true, env, None);
            assert!(matches!(j.work, Work::Import(Into::Existing)), "{env}");
            assert_eq!(project(&j).as_deref(), Some("shop-web"));
        }
        // An environment it does not have is added.
        let j = job("apps/web", true, "qa", None);
        assert!(matches!(j.work, Work::Import(Into::NewEnv)));
        // One that reads elsewhere is not changed.
        let j = job("apps/web", true, "aws", None);
        let Work::Failed(e) = &j.work else {
            panic!("an environment that does not read the store took a file");
        };
        assert!(e.message.contains("[shop-web.aws]"), "{}", e.message);
        let hint = e.hint.as_deref().unwrap();
        assert!(
            hint.contains("`kagebunshin project add-source shop-web aws --provider file`"),
            "{hint}"
        );

        // Not asked for by name, the app's own file is left, and the note
        // says how it gets in.
        let j = job("apps/web", false, "qa", None);
        let Work::Leave { note: Some(note) } = &j.work else {
            panic!("an env file went into an environment that is not there");
        };
        assert!(
            note.contains("`kagebunshin onboard --file /src/shop/apps/web/.dev.env --env qa`"),
            "{note}"
        );

        // An app no project claims gets a new one.
        let j = job("apps/api", true, "dev", None);
        assert!(matches!(j.work, Work::Import(Into::New)));
        assert_eq!(project(&j).as_deref(), Some("shop-api"));
        // A hint names the files again, not a folder.
        let j = job("apps/web", true, "dev", Some("other"));
        let Work::Failed(e) = &j.work else {
            panic!("a claimed app was onboarded under another name");
        };
        assert_eq!(
            e.hint.as_deref(),
            Some("leave out --name: `kagebunshin onboard --file /src/shop/apps/web/.dev.env`")
        );
    }

    #[test]
    fn files_not_imported_are_named_with_their_commands() {
        let root = Path::new(SHOP);
        let apps = [app("apps/api"), app("apps/web")];
        let command =
            |apps: &[facts::App], file: &str| import_command(root, apps, &root.join(file));
        assert_eq!(
            command(&apps, "apps/web/.dev.env"),
            "kagebunshin onboard --file /src/shop/apps/web/.dev.env --env ENV"
        );
        // In no app's folder: nothing says whose it is.
        assert_eq!(
            command(&apps, "production.env"),
            "kagebunshin onboard --file /src/shop/production.env --env ENV --name PROJECT"
        );
        // With no app, or one, it is that one's.
        for apps in [&apps[..0], &apps[..1]] {
            assert_eq!(
                command(apps, "production.env"),
                "kagebunshin onboard --file /src/shop/production.env --env ENV"
            );
        }

        assert_eq!(not_imported_block(&[]), None);
        let files: Vec<NotImported> = ["apps/web/.dev.env", "production.env"]
            .iter()
            .map(|f| NotImported {
                file: root.join(f),
                command: command(&apps, f),
            })
            .collect();
        let block = not_imported_block(&files).unwrap();
        assert!(
            block.starts_with("not imported: 2 more files with values."),
            "{block}"
        );
        assert!(
            block
                .contains("\n  kagebunshin onboard --file /src/shop/apps/web/.dev.env --env ENV\n"),
            "{block}"
        );
        assert!(block.ends_with("by its name above"), "{block}");
        let one = not_imported_block(&files[..1]).unwrap();
        assert!(one.starts_with("not imported: 1 more file with values."));
        assert!(!one.contains("PROJECT"), "{one}");
    }

    #[test]
    fn an_imported_file_is_not_named_again_until_it_changes() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("shop");
        std::fs::create_dir_all(&root).unwrap();
        let canary = crate::test_support::Canary::new();
        let write = |name: &str, more: &str| {
            let text = format!("TOKEN={}{more}\n", canary.value());
            std::fs::write(root.join(name), text).unwrap();
        };
        write(".dev.env", "");
        write("production.env", "");
        let state = tmp.path().join("state/imported.json");
        let named = || {
            let mut others = Vec::new();
            let record = Record::at(Some(state.clone()));
            note_others(&root, &facts::read(&root), &record, &mut others);
            let names: Vec<String> = (others.iter())
                .filter_map(|o| Some(o.file.file_name()?.to_string_lossy().into_owned()))
                .collect();
            names
        };
        assert_eq!(named(), [".dev.env", "production.env"]);

        Record::at(Some(state.clone())).add(&[root.join(".dev.env")]);
        assert_eq!(named(), ["production.env"]);
        // Only where, how long and when: nothing of what is in it.
        let kept = std::fs::read_to_string(&state).unwrap();
        crate::test_support::assert_no_canary(&canary, &kept);
        assert!(!kept.contains("TOKEN"), "{kept}");

        // Changed since: its values may not be the ones imported.
        write(".dev.env", "-and-more");
        assert_eq!(named(), [".dev.env", "production.env"]);
        // And forgotten when the next import is written down.
        Record::at(Some(state.clone())).add(&[root.join("production.env")]);
        assert_eq!(named(), [".dev.env"]);
        assert!(
            !std::fs::read_to_string(&state)
                .unwrap()
                .contains(".dev.env")
        );

        // With nowhere to remember, every file is named.
        Record::at(None).add(&[root.join(".dev.env")]);
        assert_eq!(named(), [".dev.env"]);
    }

    #[test]
    fn a_left_out_app_is_remembered_until_named_or_gone() {
        let tmp = tempfile::tempdir().unwrap();
        let (web, worker) = (tmp.path().join("apps/web"), tmp.path().join("apps/worker"));
        std::fs::create_dir_all(&web).unwrap();
        std::fs::create_dir_all(&worker).unwrap();
        let state = tmp.path().join("state/left-out.json");
        let read = || LeftOut::at(Some(state.clone()));
        assert!(!read().holds(&web));

        read().change(&[web.clone(), worker.clone()], &[]);
        assert!(read().holds(&web) && read().holds(&worker));
        // Nothing to change: nothing is written.
        let before = std::fs::read(&state).unwrap();
        read().change(&[], &[]);
        assert_eq!(std::fs::read(&state).unwrap(), before);

        // Named itself, it is set up and forgotten; so is a folder that is
        // gone, when the next change is written down.
        read().change(&[], std::slice::from_ref(&web));
        assert!(!read().holds(&web) && read().holds(&worker));
        std::fs::remove_dir(&worker).unwrap();
        read().change(std::slice::from_ref(&web), &[]);
        let kept = std::fs::read_to_string(&state).unwrap();
        assert!(
            kept.contains("apps/web") && !kept.contains("apps/worker"),
            "{kept}"
        );

        // With nowhere to remember, nothing is left out next time.
        LeftOut::at(None).change(std::slice::from_ref(&web), &[]);
        assert!(!LeftOut::at(None).holds(&web));
    }

    #[test]
    fn the_state_words_follow_the_plan() {
        assert_eq!(state(&plan(true, (3, 3), None, 0)), [READY]);
        assert_eq!(state(&plan(false, (3, 3), Some(next::PROVE), 0)), [READY]);
        assert_eq!(
            state(&plan(false, (2, 3), Some("add a source"), 0)),
            [NEEDS_AGENT]
        );
        assert_eq!(state(&plan(false, (2, 3), None, 1)), [NEEDS_YOU]);
        assert_eq!(
            state(&plan(false, (2, 3), Some("add a source"), 2)),
            [NEEDS_AGENT, NEEDS_YOU]
        );
        // Every key set, but a human decision is left.
        assert_eq!(
            state(&plan(false, (3, 3), Some(next::PROVE), 1)),
            [NEEDS_AGENT, NEEDS_YOU]
        );
    }
}
