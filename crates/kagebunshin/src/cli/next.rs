//! `kagebunshin next`: the single next step toward a working setup of this
//! checkout, who takes it, and the exact command.
//!
//! [`plan`] is the state table, over what the CLI saw ([`Seen`]): the first
//! state that matches decides the headline, but a human's step does not
//! stop the agent. Every step is collected, the first the agent can take is
//! the one shown as next, and every human step is listed after it with the
//! sentence the agent passes on (`tell`). `status` lists the same human
//! steps as "left for the human".
//!
//! `onboard`, which imports env files into the local store, is the agent's
//! step while the app is open: a person approves the import there. With
//! several folders ([`several`]) there is one plan for them all, with one
//! `onboard`, so one approval.

use std::path::{Path, PathBuf};

use serde::Serialize;

use super::error::start_daemon_command;
use super::onboard::NotImported;
use super::{CliError, gather_at, plural, print_json, print_line, project, set_var_fixes};
use crate::config::{ConfigDir, PER_FOLDER};
use crate::daemon::resolve::named_production;
use crate::ipc::protocol::{
    EnvStatus, Fix, Proof, Request, Response, SharedSecret, WaitingEnv, Who,
};
use crate::source::{Health, ProviderStatus};
use crate::types::{EnvName, ProjectName, Provider};

/// The daemon as the CLI found it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Daemon {
    NotRunning,
    Locked,
    Unlocked,
}

/// Where this checkout stands with the daemon.
#[derive(Debug)]
pub(super) enum Place {
    /// Not asked: the daemon is down or locked.
    Unknown,
    /// No project claims this checkout.
    NoProject,
    /// Its environment is marked sensitive, so an agent is told nothing
    /// of it; the daemon's refusal.
    Sensitive(String),
    /// Its environment could not be resolved.
    Failed {
        message: String,
        hint: Option<String>,
    },
    Env(Box<EnvStatus>),
}

/// What `next` looked at.
#[derive(Debug)]
pub(super) struct Seen {
    pub daemon: Daemon,
    /// Whether the local store exists.
    pub store: bool,
    /// Whether the daemon is installed as a service.
    pub installed: bool,
    /// Whether the app is open: a person approves an import there, so
    /// `onboard` is the agent's to run.
    pub app: bool,
    /// The folder looked at.
    pub dir: PathBuf,
    /// An env file with values in this folder, by name.
    pub env_file: Option<String>,
    /// For an app with no `.env.example`, which gets every key of its
    /// environment: how many keys its code is found to read.
    pub unlisted: Option<usize>,
    /// The files with values in this folder or below that `onboard` does
    /// not import by itself, and the command that imports each.
    pub others: Vec<NotImported>,
    /// The apps of the checkout, when there are several, this is its root
    /// and no project claims the root itself: one project each.
    pub apps: Vec<App>,
    pub place: Place,
    pub providers: Vec<ProviderStatus>,
    /// Every environment waiting for a human decision.
    pub waiting: Vec<WaitingEnv>,
    /// Every secret more than one environment reads.
    pub shared: Vec<SharedSecret>,
    /// `--env`, as given.
    pub env_flag: Option<EnvName>,
    /// What the environment's first AWS source reads with, as flags for
    /// `project add-source`: ` --profile acme-dev`, or nothing.
    pub aws_flags: String,
    /// Unix seconds, for the date of a proof.
    pub now: u64,
}

/// One app of a repository of several, seen from the checkout's root.
#[derive(Debug)]
pub(super) struct App {
    /// Its folder, relative to the root; empty for the root.
    pub dir: String,
    /// An env file with values there, by name.
    pub env_file: Option<String>,
    /// What `next` says in that folder.
    pub plan: Plan,
    /// `onboard --exclude` left it out and no project claims it: nothing
    /// is done for it, and nothing waits for it.
    pub left_out: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct Step {
    pub who: Who,
    pub what: String,
    pub command: Option<String>,
    /// For a human step: one sentence to pass on word for word.
    pub tell: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(super) struct Keys {
    pub set: usize,
    pub wanted: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Plan {
    pub headline: String,
    pub project: Option<ProjectName>,
    pub env: Option<EnvName>,
    pub done: bool,
    pub keys: Option<Keys>,
    /// The first step the agent can take now.
    pub step: Option<Step>,
    /// Every step waiting on the human, in order.
    pub human: Vec<Step>,
}

fn agent(what: impl Into<String>, command: Option<String>) -> Step {
    Step {
        who: Who::Agent,
        what: what.into(),
        command,
        tell: None,
    }
}

fn human(what: impl Into<String>, command: Option<String>, tell: String) -> Step {
    Step {
        who: Who::Human,
        what: what.into(),
        command,
        tell: Some(tell),
    }
}

/// The step for `unplaced`, keys of `.env.example` no source of `env` sets
/// and no fix names: where to look, and how the secret found is added.
/// With AWS sources, the listing is the one that shows each secret's keys,
/// kept to the folder those sources share, and the secret is added with
/// `aws_flags`, so it is read as they are.
fn find_secret(env: &EnvStatus, unplaced: &[&str], aws_flags: &str) -> (String, String) {
    let (p, e) = (&env.project, &env.env);
    let keys = unplaced.join(", ");
    let are = plural(unplaced.len(), "is", "are");
    let mut aws = env
        .keys
        .iter()
        .filter(|k| k.origin.provider == Provider::AwsSm)
        .map(|k| k.origin.location.as_str());
    let Some(first) = aws.next() else {
        return (
            format!(
                "{keys} {are} set by no source: find the secret with `kagebunshin list` or \
                 `kagebunshin search TEXT`, then add it with `kagebunshin project add-source \
                 {p} {e} …`. {}",
                if_none(env, unplaced.len())
            ),
            "kagebunshin list".to_owned(),
        );
    };
    // The folder every AWS secret in use shares, e.g. `acme/dev/`.
    let shared = aws.fold(first, |shared, name| {
        let same = shared
            .split_inclusive('/')
            .zip(name.split_inclusive('/'))
            .take_while(|(a, b)| a == b && a.ends_with('/'))
            .map(|(a, _)| a.len())
            .sum();
        &shared[..same]
    });
    let folder = shared.rfind('/').map_or("", |at| &shared[..=at]);
    let (command, each) = if folder.is_empty() {
        (
            "kagebunshin list --keys".to_owned(),
            "each secret and its keys".to_owned(),
        )
    } else {
        (
            format!("kagebunshin list --keys --prefix {folder}"),
            format!("each secret under {folder} and its keys (drop `--prefix` to look everywhere)"),
        )
    };
    (
        format!(
            "{keys} {are} set by no source: `{command}` names {each}. Add the one that holds \
             {} with `kagebunshin project add-source {p} {e} --provider aws_sm --secret \
             NAME{aws_flags}`; for a secret that is one plain string, not JSON, add `--key KEY` \
             too. {}",
            plural(unplaced.len(), "it", "them"),
            if_none(env, unplaced.len())
        ),
        command,
    )
}

/// What is left when no secret holds the `keys` keys looked for: the local
/// store, where the human types them.
fn if_none(env: &EnvStatus, keys: usize) -> String {
    format!(
        "If none holds {}, run `kagebunshin project add-source {} {} --provider file`: the \
         human then types {} into the local store",
        plural(keys, "it", "them"),
        env.project,
        env.env,
        plural(keys, "its value", "their values"),
    )
}

/// The text inside the first pair of backquotes of `hint`, if any.
fn first_command(hint: &str) -> Option<String> {
    let (_, rest) = hint.split_once('`')?;
    let (command, _) = rest.split_once('`')?;
    Some(command.to_owned())
}

/// `every key set; `./test.sh` ran with them on 14 Nov`.
pub(super) fn proof_line(proof: &Proof, now: u64) -> String {
    format!(
        "every key set; `{}` ran with them on {}",
        proof.program,
        crate::audit::day(proof.time, now)
    )
}

/// Where the keys counted come from, in the order they first set one:
/// `aws_sm:acme/dev/api (2), file:api.dev (1), the project file (1)`.
fn origins(env: &EnvStatus) -> String {
    let wanted = |in_example: bool| !env.example || in_example;
    let mut counts: Vec<(String, usize)> = Vec::new();
    let from_sources = (env.keys.iter())
        .filter(|k| wanted(k.in_example))
        .map(|k| k.origin.to_string());
    let from_file = (env.vars.iter())
        .filter(|v| wanted(v.in_example))
        .map(|_| "the project file".to_owned());
    for origin in from_sources.chain(from_file) {
        match counts.iter_mut().find(|(o, _)| *o == origin) {
            Some((_, n)) => *n += 1,
            None => counts.push((origin, 1)),
        }
    }
    let parts: Vec<String> = counts.iter().map(|(o, n)| format!("{o} ({n})")).collect();
    parts.join(", ")
}

fn keys_of(env: &EnvStatus) -> Keys {
    let wanted_set = |in_example: bool| !env.example || in_example;
    let set = env.keys.iter().filter(|k| wanted_set(k.in_example)).count()
        + env.vars.iter().filter(|v| wanted_set(v.in_example)).count();
    Keys {
        set,
        wanted: set + env.missing.len(),
    }
}

/// `2 of 3 keys set`: the keys `.env.example` lists, as every command
/// counts them.
pub(super) fn counted(env: &EnvStatus) -> String {
    let keys = keys_of(env);
    if env.example {
        format!("{} of {} keys set", keys.set, keys.wanted)
    } else {
        format!(
            "{} {} set (no .env.example to compare with)",
            keys.set,
            plural(keys.set, "key", "keys")
        )
    }
}

fn env_flag(env: Option<&EnvName>) -> String {
    env.map(|e| format!(" --env {e}")).unwrap_or_default()
}

/// The state table; see the module docs.
pub(super) fn plan(seen: &Seen) -> Plan {
    let mut plan = Plan {
        headline: String::new(),
        project: None,
        env: None,
        done: false,
        keys: None,
        step: None,
        human: Vec::new(),
    };
    let mut steps = Vec::new();
    let setup = !seen.store || (seen.daemon == Daemon::NotRunning && !seen.installed);
    match seen.daemon {
        _ if setup => {
            // A store with no service: the daemon may never have been
            // installed, or it is one started by hand that has stopped.
            let (headline, what, tell) = if seen.store {
                (
                    "the kagebunshin daemon is not running, and is not installed as a service",
                    "start the daemon: as a service, or by hand",
                    "Please run `kagebunshin setup` in a terminal; it asks for the store \
                     passphrase, installs the daemon as a service, starts it and unlocks it. If \
                     you start the daemon by hand instead, run `kagebunshin daemon` in another \
                     terminal, then `kagebunshin unlock`.",
                )
            } else {
                (
                    "kagebunshin is not set up on this machine",
                    "set kagebunshin up: the local store and the daemon",
                    "Please run `kagebunshin setup` in a terminal; it creates the local store, \
                     asking for its new passphrase, and starts and unlocks the daemon.",
                )
            };
            plan.headline = headline.into();
            steps.push(human(what, Some("kagebunshin setup".into()), tell.into()));
        }
        Daemon::NotRunning => {
            let start = start_daemon_command();
            plan.headline = "the kagebunshin daemon is not running".into();
            steps.push(human(
                "start the daemon",
                Some(start.into()),
                format!(
                    "Please start the kagebunshin daemon with `{start}`, then unlock it with \
                     `kagebunshin unlock`."
                ),
            ));
        }
        Daemon::Locked => {
            plan.headline = "the kagebunshin daemon is locked".into();
            let tell = if seen.app {
                "Please unlock kagebunshin: type the store passphrase in the app's window, or run \
                 `kagebunshin unlock` in a terminal."
            } else {
                "Please run `kagebunshin unlock` in a terminal; it asks for the store passphrase."
            };
            steps.push(human(
                "unlock the daemon",
                Some("kagebunshin unlock".into()),
                tell.into(),
            ));
        }
        Daemon::Unlocked if !seen.apps.is_empty() => {
            apps_steps(seen, &mut plan, &mut steps);
            steps.extend(others_step(seen));
        }
        Daemon::Unlocked => {
            env_steps(seen, &mut plan, &mut steps);
            if matches!(seen.place, Place::NoProject | Place::Env(_)) {
                steps.extend(others_step(seen));
            }
        }
    }
    plan.step = steps.iter().find(|s| s.who == Who::Agent).cloned();
    plan.human = steps.into_iter().filter(|s| s.who == Who::Human).collect();
    plan
}

/// The agent's last step: a run that proves the setup.
pub(super) const PROVE: &str = "prove the setup: run the project's tests or its start command \
                                with its keys; pick the command";

/// How a checkout no project claims is headed.
const NO_PROJECT: &str = "this checkout is in no kagebunshin project";

/// `kagebunshin onboard` of `dir`. The folder is named in full: the human's
/// terminal may be anywhere.
fn onboard_command(dir: &Path, env: Option<&EnvName>) -> String {
    format!(
        "kagebunshin onboard{} {}",
        env_flag(env),
        super::shell_quote(&dir.to_string_lossy())
    )
}

/// Whether `step` is an `onboard`, the agent's or the human's.
fn is_onboard(step: &Step) -> bool {
    (step.command.as_deref()).is_some_and(|c| c.starts_with("kagebunshin onboard"))
}

/// The `onboard` that moves the values of `files` in. With the app open
/// (`app`) it is the agent's: a person approves the import in the app's
/// window, with the store passphrase. Else the human opens the app, or
/// runs it in a terminal.
fn onboard_step(files: &str, command: String, app: bool) -> Step {
    if app {
        return agent(
            format!(
                "move the values of {files} into kagebunshin. It waits for the human to approve \
                 the import in the kagebunshin app, which shows what is imported and takes the \
                 store passphrase: say so first, then run it"
            ),
            Some(command),
        );
    }
    let tell = format!(
        "Please open the kagebunshin app (`kagebunshin app`) and say when it is open: I then \
         move the values of {files} into kagebunshin, and you approve it in the app's window \
         with the store passphrase. Or run `{command}` in a terminal yourself; it asks for the \
         passphrase there."
    );
    human(
        format!("move the values of {files} into kagebunshin"),
        Some(command),
        tell,
    )
}

/// The `store set` that fills in secrets nobody has in a file: `note` says
/// what it asks for at a terminal. With the app open (`app`) it is the
/// agent's: run with no terminal it waits for a person to type each value,
/// and the store passphrase, in the app's window. Else the human runs it
/// in a terminal, or opens the app. While the environment waits for the
/// human's decision (`waiting`) it is the human's, at a terminal only.
fn type_step(command: String, note: &str, app: bool, waiting: bool) -> Step {
    if app && !waiting {
        return agent(
            "ask the human for the missing secret values. It waits for the human to type them \
             in the kagebunshin app, which has a field for each key and takes the store \
             passphrase; no value passes through you: say so first, then run it",
            Some(command),
        );
    }
    let mut tell = format!("Please run `{command}` in a terminal; {note}.");
    if !waiting {
        tell.push_str(
            " Or open the kagebunshin app (`kagebunshin app`) and say when it is open: I then \
             run it, and you type the values in the app's window.",
        );
    }
    human(
        "type the missing secret values into the local store",
        Some(command),
        tell,
    )
}

/// The files with values that `onboard` does not import by itself
/// ([`Seen::others`]), for the human: each goes in with its command, or
/// goes. It does not hold up being done: nothing says such a file is the
/// project's to have.
fn others_step(seen: &Seen) -> Option<Step> {
    let n = seen.others.len();
    if n == 0 {
        return None;
    }
    let shown = |f: &NotImported| {
        let file = f.file.strip_prefix(&seen.dir).unwrap_or(&f.file);
        file.display().to_string()
    };
    let files: Vec<String> = seen.others.iter().map(shown).collect();
    let files = files.join(", ");
    let commands: Vec<String> = (seen.others.iter())
        .map(|f| format!("`{}`", f.command))
        .collect();
    let (and_project, as_project) = if seen.others.iter().any(|f| f.command.ends_with("PROJECT")) {
        (" and which project", " and PROJECT")
    } else {
        ("", "")
    };
    Some(human(
        format!(
            "import or delete {n} more {} with values in plain text: {files}",
            plural(n, "file", "files")
        ),
        None,
        format!(
            "{n} more {} here {} values in plain text that were not imported into \
             kagebunshin: {files}. To import one, say which environment its values are \
             for{and_project}: I run its line with that as ENV{as_project}, and you approve it \
             in the kagebunshin app with the store passphrase. Or run it in a terminal \
             yourself: {}. Delete one that is not needed.",
            plural(n, "file", "files"),
            plural(n, "holds", "hold"),
            commands.join(", ")
        ),
    ))
}

/// The root of a repository of several apps: where each app stands, the
/// first step the agent can take in one of them, and every human step,
/// with one `onboard` of the root for all the env files.
fn apps_steps(seen: &Seen, plan: &mut Plan, steps: &mut Vec<Step>) {
    let shown = |a: &App| if a.dir.is_empty() { "." } else { &a.dir }.to_owned();
    let apps = || seen.apps.iter().filter(|a| !a.left_out);
    plan.done = apps().all(|a| a.plan.done);
    plan.headline = format!(
        "this repository has {} apps, each its own project{}",
        seen.apps.len(),
        if plan.done { ": all done" } else { "" }
    );
    for a in &seen.apps {
        let headline = match a.plan.headline.as_str() {
            _ if a.left_out => "left out; `kagebunshin onboard` of its folder sets it up",
            NO_PROJECT => "in no kagebunshin project yet",
            h => h,
        };
        plan.headline
            .push_str(&format!("\n  {}: {headline}", shown(a)));
    }

    let files: Vec<String> = apps()
        .filter(|a| a.plan.step.iter().chain(&a.plan.human).any(is_onboard))
        .map(|a| {
            let file = a.env_file.as_deref().unwrap_or("the env file");
            Path::new(&a.dir).join(file).to_string_lossy().into_owned()
        })
        .collect();
    if !files.is_empty() {
        steps.push(onboard_step(
            &files.join(", "),
            onboard_command(&seen.dir, seen.env_flag.as_ref()),
            seen.app,
        ));
    }
    for a in apps() {
        for h in a.plan.human.iter().filter(|h| !is_onboard(h)) {
            if !steps.iter().any(|s| s.tell == h.tell) {
                steps.push(h.clone());
            }
        }
    }
    // Nothing set up yet: one draft at the root makes a project for each.
    let fresh = apps().all(|a| a.plan.headline == NO_PROJECT);
    // The one `onboard` above is every app's.
    let next = apps().find_map(|a| Some((a, a.plan.step.as_ref().filter(|s| !is_onboard(s))?)));
    match next {
        Some(_) if fresh => steps.push(agent(
            "draft a project for each app from what the checkout and the connected providers \
             say, and apply them",
            Some("kagebunshin project draft --apply".into()),
        )),
        Some((a, step)) => {
            let there = !a.dir.is_empty();
            steps.push(agent(
                format!("in {}: {}", shown(a), step.what),
                step.command.as_ref().map(|c| {
                    if there {
                        format!("cd {} && {c}", super::shell_quote(&a.dir))
                    } else {
                        c.clone()
                    }
                }),
            ));
        }
        None => {}
    }
}

fn env_steps(seen: &Seen, plan: &mut Plan, steps: &mut Vec<Step>) {
    let env = match &seen.place {
        Place::Unknown => {
            plan.headline = "the kagebunshin daemon said nothing about this checkout".into();
            return;
        }
        Place::NoProject => {
            plan.headline = NO_PROJECT.into();
            steps.push(match &seen.env_file {
                Some(file) => onboard_step(
                    file,
                    onboard_command(&seen.dir, seen.env_flag.as_ref()),
                    seen.app,
                ),
                None => agent(
                    "draft this folder's project from what the checkout and the connected \
                     providers say, and apply it",
                    Some("kagebunshin project draft --apply".into()),
                ),
            });
            return;
        }
        Place::Sensitive(refusal) => {
            let run = format!(
                "`kagebunshin{} run -- COMMAND` gets its values once the human approves it in \
                 the app",
                env_flag(seen.env_flag.as_ref())
            );
            plan.headline = format!(
                "{refusal}, so an agent is not shown what it holds and nothing here is yours to \
                 set up; {run}"
            );
            // The keys the app reads are in its code, not in the
            // environment, so the file can be written all the same.
            if let Some(found) = seen.unlisted {
                plan.headline
                    .push_str(&suggest_example(found, "every key of the environment"));
            }
            return;
        }
        Place::Failed { message, hint } => {
            plan.headline = "the environment cannot be resolved".into();
            let mut logins = false;
            for p in &seen.providers {
                let (Health::NeedsLogin { hint } | Health::NotConnected { hint }) = &p.health
                else {
                    continue;
                };
                logins = true;
                let command = first_command(hint);
                let tell = match &command {
                    Some(c) => format!(
                        "Please run `{c}` in a terminal, so kagebunshin can read {} ({}).",
                        p.provider.as_str(),
                        p.detail
                    ),
                    None => format!(
                        "Please log in to {} ({}): {hint}.",
                        p.provider.as_str(),
                        p.detail
                    ),
                };
                steps.push(human(
                    format!("log in to {} ({})", p.provider.as_str(), p.detail),
                    command,
                    tell,
                ));
            }
            if !logins {
                let what = match hint {
                    Some(h) => format!("{message}; {h}"),
                    None => message.clone(),
                };
                let command = hint.as_deref().and_then(first_command);
                steps.push(agent(what, command));
            }
            return;
        }
        Place::Env(env) => env,
    };
    let (p, e) = (&env.project, &env.env);
    plan.project = Some(p.clone());
    plan.env = Some(e.clone());
    let keys = keys_of(env);
    plan.keys = Some(keys);
    plan.headline = format!("project {p}, environment {e}: {}", counted(env));

    // An environment that looks like production is decided about first:
    // marked sensitive, nothing of it is an agent's to set up. One named
    // production outright is the agent's to mark; the rest is a question,
    // and the human's.
    let waiting = seen.waiting.iter().find(|w| &w.project == p && &w.env == e);
    match waiting {
        Some(w) if named_production(&w.env) => {
            plan.headline
                .push_str(", and it is production by its name: mark it sensitive");
            steps.push(mark_step(w));
        }
        Some(_) => plan
            .headline
            .push_str(", and it waits for the human's decision in the app"),
        None => {}
    }

    // What the agent can do by itself comes before what it asks a person
    // to type in the app, and neither while the environment waits for the
    // decision: the values are then the human's to type at a terminal.
    let mut agent_fixes = Vec::new();
    let mut typed = Vec::new();
    for f in &env.fixes {
        match f.who {
            Who::Agent => agent_fixes.push(fix_step(f)),
            Who::Human if f.command.starts_with("kagebunshin onboard") => {
                let file = seen.env_file.as_deref().unwrap_or("the env file here");
                steps.push(onboard_step(file, f.command.clone(), seen.app));
            }
            Who::Human if f.command.starts_with("kagebunshin store set") => {
                let step = type_step(f.command.clone(), &f.note, seen.app, waiting.is_some());
                match step.who {
                    Who::Agent => typed.push(step),
                    Who::Human => steps.push(step),
                }
            }
            Who::Human => steps.push(human(
                "type the missing secret values into the local store",
                Some(f.command.clone()),
                format!("Please run `{}` in a terminal; {}.", f.command, f.note),
            )),
        }
    }
    if waiting.is_none() {
        steps.extend(agent_fixes);
    }

    // Missing keys no fix names: nothing says where they come from. A
    // skipped secret may hold any of them, and `onboard` fills them all.
    let onboard = env
        .fixes
        .iter()
        .any(|f| f.command.starts_with("kagebunshin onboard"));
    let named = |k: &str| {
        onboard
            || env
                .fixes
                .iter()
                .any(|f| f.command.split(' ').any(|t| t == k))
    };
    let unplaced: Vec<&str> = env
        .missing
        .iter()
        .map(|k| k.as_str())
        .filter(|k| !named(k))
        .collect();
    if !unplaced.is_empty() && env.skipped.is_empty() && waiting.is_none() {
        let (what, command) = find_secret(env, &unplaced, &seen.aws_flags);
        steps.push(agent(what, Some(command)));
    }
    steps.extend(typed);

    if let Some(w) = waiting.filter(|w| !named_production(&w.env)) {
        steps.push(decide_step(w, &seen.shared));
    }

    if env.missing.is_empty() && waiting.is_none() {
        // The project's other environments that wait for a decision:
        // nothing runs with one until it is made.
        let others = || (seen.waiting.iter()).filter(|w| &w.project == p && &w.env != e);
        let to_mark: Vec<Step> = others()
            .filter(|w| named_production(&w.env))
            .map(mark_step)
            .collect();
        match &env.proof {
            // Not done while one of them is the agent's to mark.
            Some(_) if steps.is_empty() && !to_mark.is_empty() => {
                plan.headline
                    .push_str(", proven; an environment named production is left to mark");
                steps.extend(to_mark);
            }
            Some(proof) if steps.is_empty() => {
                plan.done = true;
                plan.headline = format!(
                    "project {p}, environment {e}: done. {} of {} keys set; `{}` ran with them \
                     on {}. They come from {}.",
                    keys.set,
                    keys.wanted,
                    proof.program,
                    crate::audit::day(proof.time, seen.now),
                    origins(env)
                );
                // With no `.env.example` nothing is missing and nothing is
                // left out. Setup is done all the same: the file is
                // offered, once it is.
                if let Some(found) = seen.unlisted.filter(|_| !env.example) {
                    let all = match keys.set {
                        0 => "every key of the environment".to_owned(),
                        1 => "the one key of the environment".to_owned(),
                        2 => "both keys of the environment".to_owned(),
                        n => format!("all {n} keys of the environment"),
                    };
                    plan.headline.push_str(&suggest_example(found, &all));
                }
                steps.extend(others().map(|w| decide_step(w, &seen.shared)));
                // An env file left behind, as `onboard` leaves one when
                // asked to: the same values, still in plain text.
                if let Some(file) = &seen.env_file {
                    let path = seen.dir.join(file);
                    let path = super::shell_quote(&path.to_string_lossy());
                    steps.push(human(
                        format!("delete {file}, which still holds values in plain text"),
                        Some(format!("rm {path}")),
                        format!(
                            "{path} still holds values in plain text, and {p} now gets its \
                             secrets from kagebunshin: delete the file once nothing in it is \
                             still needed (`rm {path}`)."
                        ),
                    ));
                }
            }
            Some(_) => {}
            None => {
                plan.headline.push_str(", not yet proven");
                steps.push(agent(
                    PROVE,
                    Some(format!(
                        "kagebunshin run{} --strict -- COMMAND",
                        env_flag(seen.env_flag.as_ref())
                    )),
                ));
            }
        }
    }
}

/// A line under the headline for an app with no `.env.example`, whose
/// every command gets `all` the keys: the file would narrow that, and
/// `found` keys its code is seen to read would go in it. A suggestion:
/// nothing waits for it.
fn suggest_example(found: usize, all: &str) -> String {
    let start = format!(
        "\nsuggested, not needed: this app has no .env.example, so a command run here gets {all}"
    );
    if found == 0 {
        return format!(
            "{start}. One listing the keys the app reads from its environment, one `NAME=` to a \
             line, names only, gives a command those and no more (kagebunshin found none in \
             the code itself)."
        );
    }
    format!(
        "{start}. `kagebunshin project example` writes one from the {found} {} kagebunshin finds \
         its code reading, names only, and a command then gets those and no more.",
        plural(found, "key", "keys")
    )
}

/// The agent's step for an environment named production outright, which
/// is no question: mark it. Only a human removes the mark.
fn mark_step(w: &WaitingEnv) -> Step {
    let WaitingEnv { project, env, .. } = w;
    agent(
        format!(
            "mark {project}.{env} sensitive: it is production by its name, so its values are \
             handed out only once the human approves the request"
        ),
        Some(format!("kagebunshin mark env {project} {env}")),
    )
}

/// The human's decision about an environment that looks like production.
///
/// Says which of its secrets marking it leaves unmarked, of the `shared`
/// ones: those an open environment reads too.
fn decide_step(w: &WaitingEnv, shared: &[SharedSecret]) -> Step {
    let WaitingEnv { project, env, why } = w;
    let left: Vec<&SharedSecret> = shared
        .iter()
        .filter(|s| s.of(project, env) && s.stays_unmarked())
        .collect();
    let sharing = match left.as_slice() {
        [] => String::new(),
        left => {
            let n = left.len();
            let names: Vec<String> = left.iter().take(5).map(|s| s.name()).collect();
            let more = match n - names.len() {
                0 => String::new(),
                more => format!(" and {more} more"),
            };
            format!(
                " Marking it sensitive leaves {n} {} unmarked that other environments read too \
                 ({}{more}), so those go on running without approval; the app lists them and \
                 lets you mark them as well.",
                plural(n, "secret", "secrets"),
                names.join(", ")
            )
        }
    };
    human(
        format!("decide in the app whether {project}.{env} is production ({why})"),
        None,
        format!(
            "Please open the kagebunshin app and decide about {project}.{env}, which looks like \
             production ({why}): mark it sensitive, or acknowledge it is not production. Until \
             then a run with it is refused, or waits for your approval.{sharing}"
        ),
    )
}

fn fix_step(f: &Fix) -> Step {
    let words: Vec<&str> = f.command.split(' ').collect();
    let what = match words.as_slice() {
        ["kagebunshin", "project", "set-var", _, _, key, ..] => format!(
            "set {key} as a plain setting to .env.example's value, only if that is the real \
             setting and not a placeholder (a secret belongs in the store or a provider)"
        ),
        _ => f.note.clone(),
    };
    agent(what, Some(f.command.clone()))
}

pub(super) fn render(plan: &Plan) -> String {
    let mut out = plan.headline.clone();
    if let Some(step) = &plan.step {
        out.push_str(&format!("\nnext (you): {}", step.what));
        if let Some(c) = &step.command {
            out.push_str(&format!("\n  {c}"));
        }
    }
    if !plan.human.is_empty() {
        out.push_str(if plan.done {
            "\nleft for the human, when they like; tell them:"
        } else {
            "\nwaiting on the human; tell them:"
        });
        for h in &plan.human {
            out.push_str(&format!("\n  - {}", h.tell.as_deref().unwrap_or(&h.what)));
        }
        if plan.step.is_none() && !plan.done {
            out.push_str("\nnothing more you can do until the human has done the above");
        }
    }
    out
}

/// The `--json` form; documented in `docs/agents.md`.
#[derive(Serialize)]
struct Json<'a> {
    project: Option<&'a ProjectName>,
    env: Option<&'a EnvName>,
    done: bool,
    keys: Option<Keys>,
    /// The first line of the text form: where setup stands, or why there
    /// is nothing to do.
    headline: &'a str,
    step: Option<&'a Step>,
    human: Vec<HumanJson<'a>>,
}

#[derive(Serialize)]
pub(super) struct HumanJson<'a> {
    what: &'a str,
    command: Option<&'a str>,
    tell: Option<&'a str>,
}

pub(super) fn human_json(steps: &[Step]) -> Vec<HumanJson<'_>> {
    steps
        .iter()
        .map(|s| HumanJson {
            what: &s.what,
            command: s.command.as_deref(),
            tell: s.tell.as_deref(),
        })
        .collect()
}

/// The steps of `report`'s environment waiting on the human, as `next`
/// lists them; none when it has no environment.
pub(super) fn left_for_human(
    report: &crate::ipc::protocol::StatusReport,
    facts: &crate::ipc::protocol::Facts,
) -> Vec<Step> {
    let Some(env) = &report.env else {
        return Vec::new();
    };
    let seen = Seen {
        daemon: Daemon::Unlocked,
        store: true,
        installed: true,
        app: report.app,
        dir: facts.cwd.clone(),
        env_file: facts.env_file.clone(),
        // The file is the agent's to write.
        unlisted: None,
        others: others_here(facts),
        apps: Vec::new(),
        place: Place::Env(Box::new(env.clone())),
        providers: Vec::new(),
        waiting: report.waiting.clone(),
        shared: report.shared.clone(),
        env_flag: facts.env.clone(),
        // Only an agent's step names them.
        aws_flags: String::new(),
        now: 0,
    };
    plan(&seen).human
}

/// One plan for several checkouts, each looked at as [`look`] does: where
/// each stands, one `onboard` for every env file among them, so that one
/// approval covers them all, every human step, and the first other step
/// the agent can take, run in its folder.
fn several(seen: &[Seen]) -> Plan {
    let plans: Vec<Plan> = seen.iter().map(plan).collect();
    let done = plans.iter().all(|p| p.done);
    let mut headline = format!(
        "{} checkouts{}",
        seen.len(),
        if done { ": all done" } else { "" }
    );
    for (s, p) in seen.iter().zip(&plans) {
        let at = p.headline.replace('\n', "\n  ");
        headline.push_str(&format!("\n  {}: {at}", s.dir.display()));
    }

    let mut steps = Vec::new();
    let to_onboard: Vec<String> = (seen.iter().zip(&plans))
        .filter(|(_, p)| p.step.iter().chain(&p.human).any(is_onboard))
        .map(|(s, _)| super::shell_quote(&s.dir.to_string_lossy()))
        .collect();
    if let Some(first) = seen.first().filter(|_| !to_onboard.is_empty()) {
        steps.push(onboard_step(
            &format!("the env files of {}", to_onboard.join(", ")),
            format!(
                "kagebunshin onboard{} {}",
                env_flag(first.env_flag.as_ref()),
                to_onboard.join(" ")
            ),
            first.app,
        ));
    }
    for h in plans.iter().flat_map(|p| &p.human) {
        if !is_onboard(h) && !steps.iter().any(|s| s.tell == h.tell) {
            steps.push(h.clone());
        }
    }
    let next = (seen.iter().zip(&plans))
        .find_map(|(s, p)| Some((s, p.step.as_ref().filter(|s| !is_onboard(s))?)));
    if let Some((s, step)) = next {
        let dir = super::shell_quote(&s.dir.to_string_lossy());
        steps.push(agent(
            format!("in {}: {}", s.dir.display(), step.what),
            step.command.as_ref().map(|c| format!("cd {dir} && {c}")),
        ));
    }
    Plan {
        headline,
        project: None,
        env: None,
        done,
        keys: None,
        step: steps.iter().find(|s| s.who == Who::Agent).cloned(),
        human: steps.into_iter().filter(|s| s.who == Who::Human).collect(),
    }
}

pub(super) fn run(
    json: bool,
    socket: Option<PathBuf>,
    env: Option<EnvName>,
    project_flag: Option<ProjectName>,
    dirs: Vec<PathBuf>,
) -> Result<(), CliError> {
    if project_flag.is_some() && dirs.len() > 1 {
        return Err(super::usage(
            "--project names one project; give it with one folder",
        ));
    }
    let cwd = std::env::current_dir().map_err(|e| {
        CliError::new(
            super::Exit::Failure,
            "cwd",
            format!("no working directory: {e}"),
        )
    })?;
    let mut seen = Vec::new();
    for d in if dirs.is_empty() {
        vec![cwd.clone()]
    } else {
        dirs
    } {
        let d = cwd.join(d);
        let d = d.canonicalize().unwrap_or(d);
        seen.push(look(socket.clone(), d, env.clone(), project_flag.clone())?);
    }
    // The daemon down or locked is said once, not for each.
    let plan = match seen.as_slice() {
        [one] => plan(one),
        [first, ..] if first.daemon != Daemon::Unlocked => plan(first),
        many => several(many),
    };
    if json {
        return print_json(&Json {
            project: plan.project.as_ref(),
            env: plan.env.as_ref(),
            done: plan.done,
            keys: plan.keys,
            headline: &plan.headline,
            step: plan.step.as_ref(),
            human: human_json(&plan.human),
        });
    }
    print_line(&render(&plan))
}

/// What `next` sees for the checkout folder `dir`: the daemon, and what it
/// says of the project there. At the root of a checkout of several apps
/// that no project claims as a whole, what it sees in each app's folder.
pub(super) fn look(
    socket: Option<PathBuf>,
    dir: PathBuf,
    env: Option<EnvName>,
    project_flag: Option<ProjectName>,
) -> Result<Seen, CliError> {
    let whole = project_flag.is_none();
    let (mut seen, root) = look_here(socket.clone(), dir, env.clone(), project_flag, true)?;
    // Other folders have projects: the root itself is not an app of its own.
    let per_folder =
        matches!(&seen.place, Place::Failed { message, .. } if message.contains(PER_FOLDER));
    let unclaimed = per_folder || matches!(seen.place, Place::NoProject);
    let Some(root) = root.filter(|_| whole && unclaimed) else {
        return Ok(seen);
    };
    let mut apps = crate::repo::facts::read(&root).apps;
    if per_folder {
        apps.retain(|a| !a.dir.as_os_str().is_empty());
    }
    if apps.len() < 2 {
        return Ok(seen);
    }
    let left_out = super::onboard::LeftOut::read();
    for app in apps {
        // The files `onboard` leaves are named once, for the root.
        let dir = root.join(&app.dir);
        let at = dir.canonicalize().unwrap_or_else(|_| dir.clone());
        let (there, _) = look_here(socket.clone(), dir, env.clone(), None, false)?;
        seen.apps.push(App {
            dir: app.dir.to_string_lossy().into_owned(),
            env_file: there.env_file.clone(),
            plan: plan(&there),
            left_out: matches!(there.place, Place::NoProject) && left_out.holds(&at),
        });
    }
    Ok(seen)
}

/// The files with values in the folder of `facts` or below that `onboard`
/// does not import by itself; none outside a checkout.
fn others_here(facts: &crate::ipc::protocol::Facts) -> Vec<NotImported> {
    let Some(root) = &facts.root else {
        return Vec::new();
    };
    let here = root.join(facts.subdir.as_deref().unwrap_or(Path::new("")));
    let mut others = super::onboard::others_in(root);
    others.retain(|o| o.file.starts_with(&here));
    others
}

/// [`look`] for `dir` alone, and the checkout's root when `dir` is it.
/// With `others`, the files `onboard` leaves are looked for too.
fn look_here(
    socket: Option<PathBuf>,
    dir: PathBuf,
    env: Option<EnvName>,
    project_flag: Option<ProjectName>,
    others: bool,
) -> Result<(Seen, Option<PathBuf>), CliError> {
    let store = ConfigDir::from_env().is_ok_and(|d| d.store_file().exists());
    let installed = super::units::unit_path().is_ok_and(|p| p.exists());
    let facts = match gather_at(dir.clone(), env.clone(), project_flag.clone(), true, false) {
        Ok(gathered) => gathered,
        // No checkout here, and a machine with no store or no daemon:
        // setting it up or starting it comes first, wherever it is asked.
        Err(e) => {
            let down =
                matches!(super::connect(socket), Err(down) if down.code == "daemon_not_running");
            if store && !down {
                return Err(e);
            }
            let seen = Seen {
                // With no store the plan is `setup`, whatever the daemon does.
                daemon: if down {
                    Daemon::NotRunning
                } else {
                    Daemon::Locked
                },
                store,
                installed,
                app: false,
                dir,
                env_file: None,
                unlisted: None,
                others: Vec::new(),
                apps: Vec::new(),
                place: Place::Unknown,
                providers: Vec::new(),
                waiting: Vec::new(),
                shared: Vec::new(),
                env_flag: env,
                aws_flags: String::new(),
                now: crate::source::unix_now(),
            };
            return Ok((seen, None));
        }
    };
    let (facts, _, values) = facts;
    #[expect(
        clippy::expect_used,
        reason = "gather_at(_, _, _, true, _) never returns None"
    )]
    let facts = facts.expect("required facts");
    let root = facts.root.clone().filter(|_| facts.subdir.is_none());
    let is_app =
        facts.subdir.is_some() && (facts.example_keys.is_some() || facts.env_file.is_some());
    let mut seen = Seen {
        daemon: Daemon::NotRunning,
        store,
        installed,
        app: false,
        dir: facts.cwd.clone(),
        env_file: facts.env_file.clone(),
        unlisted: None,
        others: if others {
            others_here(&facts)
        } else {
            Vec::new()
        },
        apps: Vec::new(),
        place: Place::Unknown,
        providers: Vec::new(),
        waiting: Vec::new(),
        shared: Vec::new(),
        env_flag: env,
        aws_flags: super::aws_here(&facts).map_or(String::new(), |aws| {
            let profile = aws.profile.map(|p| format!(" --profile {p}"));
            let region = aws.region.map(|r| format!(" --region {r}"));
            profile.into_iter().chain(region).collect()
        }),
        now: crate::source::unix_now(),
    };
    match super::connect(socket) {
        Ok(mut client) => {
            let reply = client.request(Request::Status {
                facts: Some(facts.clone()),
            });
            match reply {
                Ok(Response::Status(report)) if report.locked => {
                    seen.daemon = Daemon::Locked;
                    seen.app = report.app;
                }
                Ok(Response::Status(report)) => {
                    seen.daemon = Daemon::Unlocked;
                    seen.app = report.app;
                    seen.waiting = report.waiting;
                    seen.shared = report.shared;
                    seen.place = match report.env {
                        Some(mut env) => {
                            let more = set_var_fixes(&env.project, &env.env, &env.missing, &values);
                            env.fixes.extend(more);
                            Place::Env(Box::new(env))
                        }
                        None => Place::Unknown,
                    };
                }
                Ok(_) => return Err(super::unexpected()),
                Err(e) => {
                    let e = CliError::from(e);
                    // Refused for this checkout: the daemon itself still says.
                    if let Ok(Response::Status(report)) =
                        client.request(Request::Status { facts: None })
                    {
                        seen.app = report.app;
                    }
                    seen.daemon = Daemon::Unlocked;
                    seen.place = match e.code {
                        "locked" => {
                            seen.daemon = Daemon::Locked;
                            Place::Unknown
                        }
                        "no_project" if e.message.starts_with(project::UNKNOWN_PROJECT) => {
                            Place::NoProject
                        }
                        // An app's folder that the repository's projects,
                        // one per folder, do not cover: a new app.
                        "no_project" if e.message.contains(PER_FOLDER) && is_app => {
                            Place::NoProject
                        }
                        "sensitive_env" if e.who.is_none() => Place::Sensitive(e.message),
                        _ => Place::Failed {
                            message: e.message,
                            hint: e.hint,
                        },
                    };
                }
            }
            // An app with a project and no `.env.example`: what its code
            // reads. A search that fails only leaves the step without a
            // count.
            if facts.example_keys.is_none()
                && matches!(seen.place, Place::Env(_) | Place::Sensitive(_))
            {
                seen.unlisted = super::example::seed(&facts.cwd, project_flag.as_ref())
                    .ok()
                    .flatten()
                    .map(|seed| seed.keys.len());
            }
            if matches!(seen.place, Place::Failed { .. })
                && let Ok(Response::Providers { providers }) = client.request(Request::Providers {
                    facts: Some(facts),
                    every: false,
                })
            {
                seen.providers = providers;
            }
        }
        Err(e) if e.code == "daemon_not_running" => {}
        Err(e) => return Err(e),
    }
    Ok((seen, root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::protocol::KeyStatus;
    use crate::types::{Origin, Provider};

    const NOW: u64 = 1_794_960_000; // 2026-11-18

    fn seen(daemon: Daemon, place: Place) -> Seen {
        Seen {
            daemon,
            store: true,
            installed: true,
            app: false,
            dir: "/work/api".into(),
            env_file: None,
            unlisted: None,
            others: Vec::new(),
            apps: Vec::new(),
            place,
            providers: Vec::new(),
            waiting: Vec::new(),
            shared: Vec::new(),
            env_flag: None,
            aws_flags: String::new(),
            now: NOW,
        }
    }

    /// Environment `api.dev` with these keys set and these missing.
    fn env(set: &[&str], missing: &[&str], fixes: Vec<Fix>) -> Place {
        let origin = Origin::new(Provider::AwsSm, "acme/dev/api");
        Place::Env(Box::new(EnvStatus {
            project: "api".parse().unwrap(),
            env: "dev".parse().unwrap(),
            example: true,
            keys: set
                .iter()
                .map(|k| KeyStatus {
                    key: k.parse().unwrap(),
                    origin: origin.clone(),
                    overridden: Vec::new(),
                    in_example: true,
                    sensitive: false,
                })
                .collect(),
            vars: Vec::new(),
            missing: missing.iter().map(|k| k.parse().unwrap()).collect(),
            skipped: Vec::new(),
            fixes,
            warnings: Vec::new(),
            acknowledged: false,
            proof: None,
        }))
    }

    fn fix(command: &str, who: Who) -> Fix {
        Fix {
            command: command.into(),
            note: "a note".into(),
            who,
        }
    }

    fn proven(mut place: Place) -> Place {
        if let Place::Env(env) = &mut place {
            env.proof = Some(Proof {
                time: 1_794_657_600, // 2026-11-14, noon UTC
                program: "./test.sh".into(),
            });
        }
        place
    }

    fn command(step: Option<&Step>) -> Option<&str> {
        step?.command.as_deref()
    }

    fn human_commands(plan: &Plan) -> Vec<Option<&str>> {
        plan.human.iter().map(|s| s.command.as_deref()).collect()
    }

    #[test]
    fn files_onboard_leaves_are_the_humans_and_do_not_hold_up_done() {
        let other = |file: &str, command: &str| NotImported {
            file: Path::new("/work/api").join(file),
            command: command.into(),
        };
        let dev_env = "kagebunshin onboard --file /work/api/.dev.env --env ENV";
        let mut s = seen(Daemon::Unlocked, proven(env(&["A"], &[], Vec::new())));
        s.others = vec![other(".dev.env", dev_env)];
        let p = plan(&s);
        assert!(p.done);
        assert_eq!(p.step, None);
        let [step] = p.human.as_slice() else {
            panic!("one step for the file: {:?}", p.human);
        };
        assert_eq!(
            step.what,
            "import or delete 1 more file with values in plain text: .dev.env"
        );
        let tell = step.tell.as_deref().unwrap();
        assert!(tell.contains(&format!("`{dev_env}`")), "{tell}");
        assert!(!tell.contains("PROJECT"), "{tell}");
        assert!(render(&p).contains("left for the human, when they like"));

        // No project yet: the draft is still the agent's, and a file in no
        // app's folder needs its project named.
        let mut s = seen(Daemon::Unlocked, Place::NoProject);
        let production =
            "kagebunshin onboard --file /work/api/production.env --env ENV --name PROJECT";
        s.others = vec![
            other(".dev.env", dev_env),
            other("production.env", production),
        ];
        let p = plan(&s);
        assert_eq!(
            command(p.step.as_ref()),
            Some("kagebunshin project draft --apply")
        );
        let tell = p.human[0].tell.as_deref().unwrap();
        assert!(
            tell.starts_with("2 more files here hold values in plain text that were not imported"),
            "{tell}"
        );
        assert!(tell.contains(".dev.env, production.env"), "{tell}");
        assert!(
            tell.contains("and which project: I run its line with that as ENV and PROJECT"),
            "{tell}"
        );

        // Nothing is said of them while the daemon says nothing.
        let mut s = seen(Daemon::Locked, Place::Unknown);
        s.others = vec![other(".dev.env", dev_env)];
        assert_eq!(human_commands(&plan(&s)), [Some("kagebunshin unlock")]);
    }

    #[test]
    fn the_daemon_and_store_come_first() {
        let mut s = seen(Daemon::NotRunning, Place::Unknown);
        s.store = false;
        let p = plan(&s);
        assert_eq!(human_commands(&p), [Some("kagebunshin setup")]);
        assert_eq!(p.step, None);
        assert!(render(&p).ends_with("nothing more you can do until the human has done the above"));

        // Installed, with a store, only stopped: start it.
        let p = plan(&seen(Daemon::NotRunning, Place::Unknown));
        assert_eq!(human_commands(&p), [Some(start_daemon_command())]);

        // No service: setup installs one, and a daemon started by hand
        // that has stopped is not called "not installed".
        let mut s = seen(Daemon::NotRunning, Place::Unknown);
        s.installed = false;
        let p = plan(&s);
        assert_eq!(human_commands(&p), [Some("kagebunshin setup")]);
        assert_eq!(
            p.headline,
            "the kagebunshin daemon is not running, and is not installed as a service"
        );
        let tell = p.human[0].tell.as_deref().unwrap();
        assert!(tell.contains("`kagebunshin daemon`"), "{tell}");

        // No store: nothing is set up.
        s.store = false;
        let p = plan(&s);
        assert_eq!(human_commands(&p), [Some("kagebunshin setup")]);
        assert_eq!(p.headline, "kagebunshin is not set up on this machine");

        let p = plan(&seen(Daemon::Locked, Place::Unknown));
        assert_eq!(human_commands(&p), [Some("kagebunshin unlock")]);
        assert_eq!(p.headline, "the kagebunshin daemon is locked");
    }

    #[test]
    fn a_checkout_in_no_project_is_drafted_or_onboarded() {
        let p = plan(&seen(Daemon::Unlocked, Place::NoProject));
        assert_eq!(
            command(p.step.as_ref()),
            Some("kagebunshin project draft --apply")
        );
        assert!(p.human.is_empty());

        let mut s = seen(Daemon::Unlocked, Place::NoProject);
        s.env_file = Some(".env".into());
        s.env_flag = Some("dev".parse().unwrap());
        let p = plan(&s);
        assert_eq!(
            human_commands(&p),
            [Some("kagebunshin onboard --env dev /work/api")]
        );
        assert_eq!(p.step, None);
        let tell = p.human[0].tell.as_deref().unwrap();
        assert!(tell.contains("open the kagebunshin app"), "{tell}");

        // With the app open the import is approved there: the agent's.
        s.app = true;
        let p = plan(&s);
        assert_eq!(
            command(p.step.as_ref()),
            Some("kagebunshin onboard --env dev /work/api")
        );
        let what = &p.step.as_ref().unwrap().what;
        assert!(what.contains("approve the import in the kagebunshin app"));
        assert!(p.human.is_empty(), "{:?}", p.human);
    }

    /// Several checkouts at once: one `onboard` for all their env files,
    /// then each one's own step, run in its folder.
    #[test]
    fn several_checkouts_are_onboarded_together() {
        let at = |dir: &str, env_file: Option<&str>, place: Place, app: bool| {
            let mut s = seen(Daemon::Unlocked, place);
            s.dir = dir.into();
            s.env_file = env_file.map(str::to_owned);
            s.app = app;
            s
        };
        let all = |app: bool| {
            [
                at("/work/api", Some(".env"), Place::NoProject, app),
                at("/work/my site", Some(".env.local"), Place::NoProject, app),
                at("/work/tool", None, Place::NoProject, app),
                at(
                    "/work/done",
                    None,
                    proven(env(&["A"], &[], Vec::new())),
                    app,
                ),
            ]
        };
        let p = several(&all(true));
        assert_eq!(
            command(p.step.as_ref()),
            Some("kagebunshin onboard /work/api '/work/my site'")
        );
        assert!(p.human.is_empty() && !p.done);
        assert!(
            p.headline.starts_with(
                "4 checkouts\n  /work/api: this checkout is in no kagebunshin project\n"
            ),
            "{}",
            p.headline
        );

        // The app closed: the human opens it, and the agent goes on with
        // what needs no import.
        let p = several(&all(false));
        assert_eq!(
            human_commands(&p),
            [Some("kagebunshin onboard /work/api '/work/my site'")]
        );
        assert_eq!(
            command(p.step.as_ref()),
            Some("cd /work/tool && kagebunshin project draft --apply")
        );
        assert!(p.step.unwrap().what.starts_with("in /work/tool: draft"));

        let done = [
            at("/work/a", None, proven(env(&["A"], &[], Vec::new())), true),
            at("/work/b", None, proven(env(&["A"], &[], Vec::new())), true),
        ];
        let p = several(&done);
        assert!(p.done && p.step.is_none() && p.human.is_empty());
        assert!(p.headline.starts_with("2 checkouts: all done\n"));
    }

    /// At the root of a repository of several apps: where each stands, one
    /// `onboard` for every env file, and the first app's step, run there.
    #[test]
    fn the_root_of_several_apps_goes_through_each() {
        let app = |dir: &str, env_file: Option<&str>, place: Place| {
            let mut s = seen(Daemon::Unlocked, place);
            s.dir = Path::new("/work/mono").join(dir);
            s.env_file = env_file.map(str::to_owned);
            App {
                dir: dir.into(),
                env_file: s.env_file.clone(),
                plan: plan(&s),
                left_out: false,
            }
        };
        let root = |apps: Vec<App>| {
            let mut s = seen(Daemon::Unlocked, Place::NoProject);
            s.dir = "/work/mono".into();
            s.apps = apps;
            s
        };

        // Nothing set up: the human onboards the root for the env file,
        // and the agent drafts the app that has none.
        let p = plan(&root(vec![
            app("apps/web", Some(".env"), Place::NoProject),
            app("apps/worker", None, Place::NoProject),
        ]));
        assert_eq!(human_commands(&p), [Some("kagebunshin onboard /work/mono")]);
        assert!(
            p.human[0]
                .tell
                .as_deref()
                .unwrap()
                .contains("apps/web/.env"),
            "{:?}",
            p.human
        );
        assert_eq!(
            command(p.step.as_ref()),
            Some("kagebunshin project draft --apply")
        );
        assert!(!p.done);

        // With the app open the one onboard is the agent's, for both.
        let mut open = root(vec![
            app("apps/web", Some(".env"), Place::NoProject),
            app("apps/worker", None, Place::NoProject),
        ]);
        open.app = true;
        open.apps[0].plan = {
            let mut s = seen(Daemon::Unlocked, Place::NoProject);
            s.dir = "/work/mono/apps/web".into();
            s.env_file = Some(".env".into());
            s.app = true;
            plan(&s)
        };
        let p = plan(&open);
        assert_eq!(
            command(p.step.as_ref()),
            Some("kagebunshin onboard /work/mono")
        );
        assert!(p.step.unwrap().what.contains("apps/web/.env"));
        assert!(p.human.is_empty());
        assert!(
            p.headline.starts_with(
                "this repository has 2 apps, each its own project\n  apps/web: in no \
                 kagebunshin project yet\n"
            ),
            "{}",
            p.headline
        );

        // A new app beside one that is set up: drafted in its folder.
        let p = plan(&root(vec![
            app("apps/web", None, proven(env(&["A"], &[], Vec::new()))),
            app("apps/worker", None, Place::NoProject),
        ]));
        assert_eq!(
            command(p.step.as_ref()),
            Some("cd apps/worker && kagebunshin project draft --apply")
        );

        // One proven, one not: the step is the other's, in its folder.
        let p = plan(&root(vec![
            app("apps/web", None, proven(env(&["A"], &[], Vec::new()))),
            app("apps/worker", None, env(&["A"], &[], Vec::new())),
        ]));
        assert_eq!(
            command(p.step.as_ref()),
            Some("cd apps/worker && kagebunshin run --strict -- COMMAND")
        );
        assert!(p.step.unwrap().what.starts_with("in apps/worker: prove"));
        assert!(p.human.is_empty() && !p.done);

        // Every app proven: done.
        let p = plan(&root(vec![
            app("apps/web", None, proven(env(&["A"], &[], Vec::new()))),
            app("apps/worker", None, proven(env(&["A"], &[], Vec::new()))),
        ]));
        assert!(p.done && p.step.is_none() && p.human.is_empty());
        assert!(p.headline.contains("each its own project: all done\n"));

        // An app left out is named, and nothing is done or waited for
        // there: not its env file, not its draft.
        let left_out = |dir: &str, env_file| App {
            left_out: true,
            ..app(dir, env_file, Place::NoProject)
        };
        let p = plan(&root(vec![
            app("apps/web", None, proven(env(&["A"], &[], Vec::new()))),
            left_out("apps/worker", Some(".env")),
        ]));
        assert!(p.done && p.step.is_none() && p.human.is_empty(), "{p:?}");
        assert!(
            p.headline
                .contains("each its own project: all done\n  apps/web: ")
                && p.headline.ends_with(
                    "\n  apps/worker: left out; `kagebunshin onboard` of its folder sets it up"
                ),
            "{}",
            p.headline
        );
        let p = plan(&root(vec![
            app("apps/web", None, Place::NoProject),
            left_out("apps/worker", Some(".env")),
        ]));
        assert_eq!(
            command(p.step.as_ref()),
            Some("kagebunshin project draft --apply")
        );
        assert!(p.human.is_empty() && !p.done);
    }

    #[test]
    fn a_project_reading_an_empty_section_is_onboarded() {
        let mut s = seen(
            Daemon::Unlocked,
            env(
                &[],
                &["DB_URL"],
                vec![fix("kagebunshin onboard /work/api", Who::Human)],
            ),
        );
        s.env_file = Some(".env.local".into());
        let p = plan(&s);
        assert_eq!(human_commands(&p), [Some("kagebunshin onboard /work/api")]);
        assert!(p.human[0].tell.as_deref().unwrap().contains(".env.local"));
        assert_eq!(p.step, None);
    }

    /// An environment marked sensitive is closed to an agent: no step, and
    /// a headline that says so instead of the refusal as a thing to do.
    #[test]
    fn a_sensitive_environment_leaves_nothing_for_the_agent() {
        let refusal = "refusing environment prod of project api: it is marked sensitive";
        let mut s = seen(Daemon::Unlocked, Place::Sensitive(refusal.into()));
        s.env_flag = Some("prod".parse().unwrap());
        let p = plan(&s);
        assert_eq!((p.step.as_ref(), p.human.len(), p.done), (None, 0, false));
        assert!(p.headline.starts_with(refusal), "{}", p.headline);
        assert!(
            p.headline
                .contains("`kagebunshin --env prod run -- COMMAND`"),
            "{}",
            p.headline
        );
    }

    /// An app with no `.env.example` gets every key. That does not hold
    /// setup up: once it is done, the file is suggested, with the command
    /// that writes it when the code names the keys.
    #[test]
    fn an_app_with_no_example_is_done_and_offered_one() {
        let unlisted = |found: usize, proof: bool| {
            let mut place = env(&["A", "B", "C"], &[], Vec::new());
            if let Place::Env(env) = &mut place {
                env.example = false;
            }
            let mut s = seen(Daemon::Unlocked, if proof { proven(place) } else { place });
            s.unlisted = Some(found);
            plan(&s)
        };
        // Not proven yet: the proof is the step, and nothing is said of
        // the file.
        let p = unlisted(2, false);
        assert_eq!(
            command(p.step.as_ref()),
            Some("kagebunshin run --strict -- COMMAND")
        );
        assert!(
            !p.done && !p.headline.contains("suggested"),
            "{}",
            p.headline
        );

        // Proven: done, with the suggestion under the headline.
        let p = unlisted(2, true);
        assert!(p.done && p.step.is_none() && p.human.is_empty());
        assert!(
            p.headline.ends_with(
                "\nsuggested, not needed: this app has no .env.example, so a command run here \
                 gets all 3 keys of the environment. `kagebunshin project example` writes one \
                 from the 2 keys kagebunshin finds its code reading, names only, and a command \
                 then gets those and no more."
            ),
            "{}",
            p.headline
        );

        // Nothing found in the code: no command to offer.
        let p = unlisted(0, true);
        assert!(p.done);
        assert!(
            p.headline.contains("one `NAME=` to a line, names only")
                && !p.headline.contains("project example"),
            "{}",
            p.headline
        );

        // With the file there, the search says nothing.
        let mut s = seen(Daemon::Unlocked, proven(env(&["A"], &[], Vec::new())));
        s.unlisted = Some(1);
        let p = plan(&s);
        assert!(
            p.done && !p.headline.contains("suggested"),
            "{}",
            p.headline
        );

        // A sensitive environment's keys are in the code all the same.
        let refusal = "refusing environment prod of project api: it is marked sensitive";
        let mut s = seen(Daemon::Unlocked, Place::Sensitive(refusal.into()));
        s.unlisted = Some(3);
        let p = plan(&s);
        assert_eq!(p.step, None);
        assert!(
            p.headline.contains("nothing here is yours to set up")
                && p.headline.contains(
                    "\nsuggested, not needed: this app has no .env.example, so a command run \
                     here gets every key of the environment. `kagebunshin project example`"
                ),
            "{}",
            p.headline
        );
    }

    #[test]
    fn a_failed_resolve_asks_for_the_provider_login() {
        let failed = || Place::Failed {
            message: "secret acme/dev/api: credentials expired".into(),
            hint: Some("run `aws login --profile acme-dev`".into()),
        };
        let mut s = seen(Daemon::Unlocked, failed());
        s.providers = vec![ProviderStatus {
            provider: Provider::AwsSm,
            detail: "profile acme-dev".into(),
            health: Health::NeedsLogin {
                hint: "run `aws login --profile acme-dev` (`aws sso login` for an SSO profile)"
                    .into(),
            },
            expires: None,
        }];
        let p = plan(&s);
        assert_eq!(human_commands(&p), [Some("aws login --profile acme-dev")]);
        assert_eq!(p.step, None);

        // No provider to blame: the failure itself, for whoever can.
        let p = plan(&seen(Daemon::Unlocked, failed()));
        assert!(p.human.is_empty());
        let step = p.step.unwrap();
        assert!(
            step.what.starts_with("secret acme/dev/api"),
            "{}",
            step.what
        );
        assert_eq!(
            step.command.as_deref(),
            Some("aws login --profile acme-dev")
        );
    }

    #[test]
    fn agent_fixes_come_one_at_a_time() {
        let p = plan(&seen(
            Daemon::Unlocked,
            env(
                &["A"],
                &["PORT", "LOG"],
                vec![
                    fix("kagebunshin project set-var api dev PORT 3000", Who::Agent),
                    fix("kagebunshin project set-var api dev LOG info", Who::Agent),
                ],
            ),
        ));
        assert_eq!(p.headline, "project api, environment dev: 1 of 3 keys set");
        assert_eq!(
            command(p.step.as_ref()),
            Some("kagebunshin project set-var api dev PORT 3000")
        );
        assert!(
            p.step
                .as_ref()
                .unwrap()
                .what
                .starts_with("set PORT as a plain setting")
        );
        assert!(p.human.is_empty());
        assert!(!p.done);
    }

    /// A human's step is listed, and the agent still gets its own.
    #[test]
    fn a_human_step_does_not_stop_the_agent() {
        let p = plan(&seen(
            Daemon::Unlocked,
            env(
                &[],
                &["DB_URL", "PORT"],
                vec![
                    fix("kagebunshin store set api.dev DB_URL", Who::Human),
                    fix("kagebunshin project set-var api dev PORT 3000", Who::Agent),
                ],
            ),
        ));
        assert_eq!(
            command(p.step.as_ref()),
            Some("kagebunshin project set-var api dev PORT 3000")
        );
        assert_eq!(
            human_commands(&p),
            [Some("kagebunshin store set api.dev DB_URL")]
        );
        assert_eq!(
            render(&p),
            "project api, environment dev: 0 of 2 keys set
next (you): set PORT as a plain setting to .env.example's value, only if that is the real setting and not a placeholder (a secret belongs in the store or a provider)
  kagebunshin project set-var api dev PORT 3000
waiting on the human; tell them:
  - Please run `kagebunshin store set api.dev DB_URL` in a terminal; a note. Or open the kagebunshin app (`kagebunshin app`) and say when it is open: I then run it, and you type the values in the app's window."
        );

        // With the app open the values are typed there, and asking for
        // them is the agent's: after what it can do by itself.
        let mut s = seen(
            Daemon::Unlocked,
            env(
                &[],
                &["DB_URL", "PORT"],
                vec![
                    fix("kagebunshin store set api.dev DB_URL", Who::Human),
                    fix("kagebunshin project set-var api dev PORT 3000", Who::Agent),
                ],
            ),
        );
        s.app = true;
        let p = plan(&s);
        assert_eq!(
            command(p.step.as_ref()),
            Some("kagebunshin project set-var api dev PORT 3000")
        );
        assert!(p.human.is_empty(), "{:?}", p.human);
        s.place = env(
            &["PORT"],
            &["DB_URL"],
            vec![fix("kagebunshin store set api.dev DB_URL", Who::Human)],
        );
        let p = plan(&s);
        assert_eq!(
            command(p.step.as_ref()),
            Some("kagebunshin store set api.dev DB_URL")
        );
        let what = &p.step.as_ref().unwrap().what;
        assert!(
            what.contains("type them in the kagebunshin app") && what.contains("say so first"),
            "{what}"
        );
        assert!(p.human.is_empty(), "{:?}", p.human);

        // Only the human's: says so.
        let p = plan(&seen(
            Daemon::Unlocked,
            env(
                &[],
                &["DB_URL"],
                vec![fix("kagebunshin store set api.dev DB_URL", Who::Human)],
            ),
        ));
        assert_eq!(p.step, None);
        assert!(render(&p).ends_with("nothing more you can do until the human has done the above"));
    }

    #[test]
    fn keys_nothing_places_are_looked_for_beside_the_secrets_in_use() {
        let p = plan(&seen(
            Daemon::Unlocked,
            env(&["A"], &["STRIPE_KEY"], Vec::new()),
        ));
        assert_eq!(
            command(p.step.as_ref()),
            Some("kagebunshin list --keys --prefix acme/dev/")
        );
        let what = &p.step.unwrap().what;
        assert!(
            what.contains(
                "kagebunshin project add-source api dev --provider aws_sm --secret NAME`"
            ) && what.contains("--key KEY"),
            "{what}"
        );
        // No secret may hold it: the store is added, for the human to fill.
        assert!(
            what.ends_with(
                "If none holds it, run `kagebunshin project add-source api dev --provider file`: \
                 the human then types its value into the local store"
            ),
            "{what}"
        );
        // Read as the sources in use are: with their profile.
        let mut s = seen(Daemon::Unlocked, env(&["A"], &["STRIPE_KEY"], Vec::new()));
        s.aws_flags = " --profile acme-dev".into();
        let what = plan(&s).step.unwrap().what;
        assert!(
            what.contains("--provider aws_sm --secret NAME --profile acme-dev`"),
            "{what}"
        );

        // Secrets in two folders share only what is above both; none, and
        // the listing is of everything.
        let with = |names: &[&str]| {
            let Place::Env(mut e) = env(&["A", "B"], &["STRIPE_KEY"], Vec::new()) else {
                unreachable!()
            };
            for (k, name) in e.keys.iter_mut().zip(names) {
                k.origin = Origin::new(Provider::AwsSm, *name);
            }
            let p = plan(&seen(Daemon::Unlocked, Place::Env(e)));
            command(p.step.as_ref()).map(str::to_owned)
        };
        assert_eq!(
            with(&["acme/dev/api", "acme/devops/db"]).as_deref(),
            Some("kagebunshin list --keys --prefix acme/")
        );
        assert_eq!(
            with(&["acme/dev/api", "other/db"]).as_deref(),
            Some("kagebunshin list --keys")
        );

        // No AWS source: nothing to read key names from.
        let Place::Env(mut e) = env(&["A"], &["STRIPE_KEY"], Vec::new()) else {
            unreachable!()
        };
        e.keys[0].origin = Origin::new(Provider::Proton, "Work");
        let p = plan(&seen(Daemon::Unlocked, Place::Env(e)));
        assert_eq!(command(p.step.as_ref()), Some("kagebunshin list"));
    }

    #[test]
    fn a_production_looking_env_waits_for_the_app() {
        let mut s = seen(Daemon::Unlocked, env(&["A"], &[], Vec::new()));
        s.waiting = vec![WaitingEnv {
            project: "api".parse().unwrap(),
            env: "dev".parse().unwrap(),
            why: "its secret names have the segment `prod`".into(),
        }];
        let p = plan(&s);
        assert_eq!(human_commands(&p), [None]);
        assert!(
            p.human[0]
                .tell
                .as_deref()
                .unwrap()
                .contains("kagebunshin app")
        );
        // It cannot run until then, so there is no proving it.
        assert_eq!(p.step, None);
    }

    /// The human is told what marking leaves unmarked: the secrets an open
    /// environment reads too, not one marked already or marked with it.
    #[test]
    fn the_decision_says_which_secrets_marking_leaves_unmarked() {
        let mut s = seen(Daemon::Unlocked, env(&["A"], &[], Vec::new()));
        s.waiting = vec![WaitingEnv {
            project: "api".parse().unwrap(),
            env: "dev".parse().unwrap(),
            why: "its name has the segment prod".into(),
        }];
        let tell = |s: &Seen| plan(s).human[0].tell.clone().unwrap();
        assert!(!tell(&s).contains("unmarked"));

        let shared = |name: &str, prefix: bool| SharedSecret {
            project: "api".parse().unwrap(),
            env: "dev".parse().unwrap(),
            secret: Origin::new(Provider::AwsSm, name),
            prefix,
            with: vec!["api.qa".parse().unwrap()],
            open: vec!["api.qa".parse().unwrap()],
            sensitive: false,
            production: false,
        };
        s.shared = vec![
            shared("mail", false),
            shared("tools/", true),
            SharedSecret {
                sensitive: true,
                ..shared("sentry", false)
            },
            SharedSecret {
                open: Vec::new(),
                ..shared("ledger", false)
            },
            SharedSecret {
                env: "qa".parse().unwrap(),
                ..shared("other", false)
            },
        ];
        let tell = tell(&s);
        assert!(
            tell.contains(
                "leaves 2 secrets unmarked that other environments read too (aws_sm:mail, \
                 aws_sm:tools/*)"
            ),
            "{tell}"
        );
    }

    /// Marked sensitive, nothing of it is the agent's to set up: until the
    /// human decides, the agent is given no step, not even a fix it could
    /// run.
    #[test]
    fn an_env_waiting_for_the_decision_gives_the_agent_no_step() {
        let fixes = vec![
            fix(
                "kagebunshin project set-var api prod LOG_LEVEL info",
                Who::Agent,
            ),
            fix("kagebunshin store set api.prod TOKEN", Who::Human),
        ];
        // DATABASE_URL is named by no fix: the agent would look for it.
        let mut s = seen(
            Daemon::Unlocked,
            env(&["A"], &["LOG_LEVEL", "TOKEN", "DATABASE_URL"], fixes),
        );
        let before = plan(&s);
        assert!(before.step.is_some());

        s.waiting = vec![WaitingEnv {
            project: "api".parse().unwrap(),
            env: "dev".parse().unwrap(),
            why: "its name has the segment prod".into(),
        }];
        let p = plan(&s);
        assert_eq!(p.step, None);
        assert_eq!(
            human_commands(&p),
            [Some("kagebunshin store set api.prod TOKEN"), None]
        );
        assert!(
            p.headline
                .ends_with("waits for the human's decision in the app")
        );
        assert!(render(&p).ends_with("nothing more you can do until the human has done the above"));
        // Nor is the human offered that the agent asks for them in the app.
        assert!(render(&before).contains("I then run it"));
        assert!(!render(&p).contains("I then run it"));

        // The app being open changes nothing: asking for the values there
        // is not the agent's either.
        s.app = true;
        let p = plan(&s);
        assert_eq!(p.step, None);
        assert_eq!(
            human_commands(&p),
            [Some("kagebunshin store set api.prod TOKEN"), None]
        );
        assert!(!render(&p).contains("I then run it"));
    }

    /// Done says which of the project's other environments still wait for
    /// a decision; another project's are not its business.
    #[test]
    fn done_names_the_other_envs_waiting_for_a_decision() {
        let mut s = seen(Daemon::Unlocked, proven(env(&["A"], &[], Vec::new())));
        let waits = |project: &str, env: &str| WaitingEnv {
            project: project.parse().unwrap(),
            env: env.parse().unwrap(),
            why: "its name has the segment prod".into(),
        };
        s.waiting = vec![waits("api", "rc"), waits("shop", "rc")];
        let p = plan(&s);
        assert!(p.done);
        assert_eq!(p.step, None);
        let [h] = &p.human[..] else {
            panic!("{:?}", p.human)
        };
        assert!(h.what.contains("api.rc"), "{}", h.what);
        let out = render(&p);
        assert!(out.contains("left for the human, when they like"), "{out}");
        assert!(out.contains("decide about api.rc"), "{out}");
        assert!(!out.contains("shop"), "{out}");
    }

    /// An environment named production outright is no question: the agent
    /// marks it, and the project is not done until it has. What only may
    /// be production stays the human's decision.
    #[test]
    fn an_env_named_production_is_the_agents_to_mark() {
        let waits = |env: &str| WaitingEnv {
            project: "api".parse().unwrap(),
            env: env.parse().unwrap(),
            why: format!("its name has the segment {env}"),
        };
        // Another environment of the project, once this one is proven.
        let mut s = seen(Daemon::Unlocked, proven(env(&["A"], &[], Vec::new())));
        s.waiting = vec![waits("prod"), waits("rc")];
        let p = plan(&s);
        assert!(!p.done);
        assert_eq!(
            command(p.step.as_ref()),
            Some("kagebunshin mark env api prod")
        );
        assert!(p.human.is_empty(), "{:?}", p.human);
        assert!(p.headline.ends_with("left to mark"), "{}", p.headline);

        // Marked, it no longer waits: done, with the question left.
        s.waiting = vec![waits("rc")];
        let p = plan(&s);
        assert!(p.done);
        assert_eq!(p.step, None);
        assert!(p.human[0].what.contains("api.rc"), "{:?}", p.human);

        // The one looked at: marking comes before anything else of it.
        let fixes = vec![fix(
            "kagebunshin project set-var api dev LOG_LEVEL info",
            Who::Agent,
        )];
        let mut s = seen(Daemon::Unlocked, env(&["A"], &["LOG_LEVEL"], fixes));
        s.waiting = vec![WaitingEnv {
            env: "dev".parse().unwrap(),
            ..waits("production")
        }];
        assert_ne!(
            command(plan(&s).step.as_ref()),
            Some("kagebunshin mark env api dev")
        );
        let Place::Env(e) = &mut s.place else {
            unreachable!()
        };
        e.env = "production".parse().unwrap();
        s.waiting[0].env = "production".parse().unwrap();
        let p = plan(&s);
        assert_eq!(
            command(p.step.as_ref()),
            Some("kagebunshin mark env api production")
        );
        assert!(p.human.is_empty(), "{:?}", p.human);
    }

    #[test]
    fn every_key_set_is_proven_then_done() {
        let p = plan(&seen(Daemon::Unlocked, env(&["A", "B"], &[], Vec::new())));
        assert_eq!(
            p.headline,
            "project api, environment dev: 2 of 2 keys set, not yet proven"
        );
        assert_eq!(
            command(p.step.as_ref()),
            Some("kagebunshin run --strict -- COMMAND")
        );
        assert!(!p.done);

        let p = plan(&seen(
            Daemon::Unlocked,
            proven(env(&["A", "B"], &[], Vec::new())),
        ));
        assert!(p.done);
        assert_eq!(p.step, None);
        assert_eq!(
            render(&p),
            format!(
                "project api, environment dev: done. 2 of 2 keys set; `./test.sh` ran with them \
                 on {}. They come from aws_sm:acme/dev/api (2).",
                crate::audit::day(1_794_657_600, NOW)
            )
        );

        // A proof does not hide a key that went missing since.
        let p = plan(&seen(
            Daemon::Unlocked,
            proven(env(&["A"], &["B"], Vec::new())),
        ));
        assert!(!p.done);

        // Done, with an env file left behind: the human is told, once.
        let mut s = seen(Daemon::Unlocked, proven(env(&["A", "B"], &[], Vec::new())));
        s.env_file = Some(".env".into());
        let p = plan(&s);
        assert!(p.done && p.step.is_none());
        assert_eq!(human_commands(&p), [Some("rm /work/api/.env")]);
        assert!(
            render(&p).ends_with(
                "\nleft for the human, when they like; tell them:\n  - /work/api/.env still holds \
                 values in plain text, and api now gets its secrets from kagebunshin: delete the \
                 file once nothing in it is still needed (`rm /work/api/.env`)."
            ),
            "{}",
            render(&p)
        );
    }
}
