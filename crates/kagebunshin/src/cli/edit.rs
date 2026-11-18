//! Edits to project files, shared by the CLI and the app, so nobody
//! hand-edits TOML.
//!
//! Each edit takes the config lock, makes its change with `toml_edit` (which
//! keeps comments and layout), checks the result loads as the daemon would
//! load it, then replaces the file atomically and records the edit in the
//! audit log.
//!
//! Project files hold no sensitive marks (those are in the encrypted store),
//! so no edit here can loosen one, and anyone may make them: an agent can
//! add, remove, move and dedupe sources.

use std::path::PathBuf;

use toml_edit::{ArrayOfTables, DocumentMut, Item, Table, TableLike, value};

use crate::cli::{CliError, Exit};
use crate::config::schema::{EnvFile, Profile, Region};
use crate::config::{ConfigDir, Project, Registry, Select, SourceSpec};
use crate::daemon::resolve::{
    duplicate_warnings, prod_like, prod_like_source_profile, waiting_message,
};
use crate::types::{EnvName, KeyName, ProjectName, Provider};

/// A source to add, as `project add-source` takes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSource {
    pub provider: Provider,
    pub prefix: Option<String>,
    /// One is written as `secret`, more as `secrets`, read in order.
    pub secrets: Vec<String>,
    pub key: Option<KeyName>,
    pub profile: Option<Profile>,
    pub region: Option<Region>,
    pub optional: bool,
}

/// What an edit wrote.
#[derive(Debug)]
pub struct Edited {
    pub path: PathBuf,
    /// For a human: a source added that looks like production, say.
    pub warnings: Vec<String>,
    /// The environment had no sources, so the one added replaced the
    /// default one, the local store's section.
    pub replaced_default: bool,
}

pub(crate) fn config(e: impl std::fmt::Display) -> CliError {
    CliError::new(Exit::Failure, "config", e.to_string())
}

pub(crate) fn no_project(project: &ProjectName) -> CliError {
    CliError::new(
        Exit::Failure,
        "no_project",
        format!("no project named {project}"),
    )
    .with_hint(format!(
        "create it with `kagebunshin project init {project}`"
    ))
    .agent()
}

pub(crate) fn lock(dir: &ConfigDir) -> Result<std::fs::File, CliError> {
    dir.lock()
        .map_err(|e| config(format!("cannot lock {}: {e}", dir.path().display())))
}

/// The project file, parsed for editing.
pub(crate) fn existing(
    registry: &Registry,
    project: &ProjectName,
) -> Result<DocumentMut, CliError> {
    let p = registry
        .project(project)
        .ok_or_else(|| no_project(project))?;
    let text = std::fs::read_to_string(&p.path)
        .map_err(|e| config(format!("cannot read {}: {e}", p.path.display())))?;
    text.parse().map_err(config)
}

fn env_file<'a>(
    registry: &'a Registry,
    project: &ProjectName,
    env: &EnvName,
) -> Result<(&'a Project, &'a EnvFile), CliError> {
    let p = registry
        .project(project)
        .ok_or_else(|| no_project(project))?;
    let file = p.file.envs.get(env).ok_or_else(|| {
        config(format!("project {project} has no environment {env}"))
            .with_hint(format!(
                "add it with `kagebunshin project add-env {project} {env}`"
            ))
            .agent()
    })?;
    Ok((p, file))
}

/// The environment's table in `doc`.
fn env_table<'a>(
    doc: &'a mut DocumentMut,
    env: &EnvName,
) -> Result<&'a mut dyn TableLike, CliError> {
    doc.get_mut("envs")
        .and_then(Item::as_table_like_mut)
        .and_then(|e| e.get_mut(env.as_str()))
        .and_then(Item::as_table_like_mut)
        .ok_or_else(|| config(format!("cannot edit environment {env}: unexpected layout")))
}

/// Which of the environment's sources an edit added, for [`commit`] to check.
pub(crate) enum Added {
    All,
    Last,
    /// None; what changed, for the audit log.
    Nothing(String),
    /// None, but the sources at these positions (from 0) changed, as
    /// described, so they are checked as if added.
    Changed(Vec<usize>, String),
}

/// Loads the edited file with every other project, as the daemon would,
/// checks what it added, then replaces the file.
pub(crate) fn commit(
    registry: &Registry,
    dir: &ConfigDir,
    name: &ProjectName,
    env: &EnvName,
    doc: DocumentMut,
    added: Added,
    action: &str,
) -> Result<Edited, CliError> {
    let path = dir.project_file(name);
    let text = doc.to_string();
    let project = crate::config::parse_project(&path, &text)
        .map_err(|e| config(format!("the edited project file would not load: {e}")))?;
    let mut projects: Vec<Project> = registry
        .projects()
        .filter(|p| &p.name != name)
        .cloned()
        .collect();
    projects.push(project);
    let edited = Registry::new(registry.config.clone(), projects).map_err(config)?;
    #[expect(clippy::expect_used, reason = "the project was pushed just above")]
    let settings = edited
        .env(edited.project(name).expect("just added"), Some(env))
        .map_err(config)?;
    let appended = matches!(added, Added::Last);
    // Whether it had sources before this edit, as `add-env` gives it the
    // default one: then its name was warned about already.
    let had_sources = matches!(added, Added::Changed(..))
        || registry
            .project(name)
            .and_then(|p| registry.env(p, Some(env)).ok())
            .is_some_and(|s| !s.sources.is_empty());
    let (target, added): (Option<String>, Vec<&SourceSpec>) = match added {
        Added::All => (None, settings.sources.iter().collect()),
        Added::Last => (
            settings.sources.last().map(describe),
            settings.sources.last().into_iter().collect(),
        ),
        Added::Nothing(what) => (Some(what), Vec::new()),
        Added::Changed(at, what) => (
            Some(what),
            at.iter().filter_map(|&i| settings.sources.get(i)).collect(),
        ),
    };
    // An exact copy of a source already there is refused.
    if let (true, [earlier @ .., last]) = (appended, &settings.sources[..])
        && earlier.contains(last)
    {
        return Err(config(format!(
            "environment {env} of project {name} already has {}; nothing changed",
            describe(last)
        )));
    }
    let mut warnings = duplicate_warnings(name, env, &settings.sources);
    // The store, and so whether a human already decided, is the daemon's:
    // this warns whatever was decided.
    let wait = |why: String| waiting_message(name, env, &why);
    let extra = &registry.config.sensitive_source_patterns;
    if let Some(why) = prod_like(env.as_str(), &[]) {
        // Said once, when the environment gets its first sources; one
        // added after them changes nothing about its name.
        if !had_sources && !added.is_empty() {
            warnings.push(wait(format!("its name {why}")));
        }
    } else {
        // A source whose own name looks like production is warned about by
        // itself; one whose profile does, once per profile.
        let mut profiles: Vec<(&Profile, String, usize)> = Vec::new();
        for spec in added {
            if let Some(why) = spec
                .select
                .locations()
                .into_iter()
                .find_map(|l| prod_like(l, extra))
            {
                warnings.push(wait(format!("{} {why}", describe(spec))));
            } else if let (Some(why), Some(profile)) =
                (prod_like_source_profile(spec, extra), &spec.aws.profile)
            {
                match profiles.iter_mut().find(|(p, ..)| *p == profile) {
                    Some((.., n)) => *n += 1,
                    None => profiles.push((profile, why, 1)),
                }
            }
        }
        for (profile, why, n) in profiles {
            let sources = if n == 1 {
                "a source".to_owned()
            } else {
                format!("{n} sources")
            };
            warnings.push(wait(format!(
                "AWS profile {profile}, used by {sources} here, {why}"
            )));
        }
    }
    let target_path = write(&path, &text)?;
    crate::audit::record_edit(action, name, Some(env), Vec::new(), target);
    Ok(Edited {
        path: target_path,
        warnings,
        replaced_default: false,
    })
}

/// Replaces the file, through a symlink to the file itself so a linked
/// project file stays linked.
pub(crate) fn write(path: &std::path::Path, text: &str) -> Result<PathBuf, CliError> {
    let target = std::fs::canonicalize(path).unwrap_or(path.to_owned());
    crate::atomic::write_private(&target, text.as_bytes())
        .map_err(|e| config(format!("cannot write {}: {e}", target.display())))?;
    Ok(target)
}

pub fn describe(spec: &SourceSpec) -> String {
    let what = match &spec.select {
        Select::Prefix(p) => format!("prefix {p}"),
        Select::Secret { name, .. } if spec.provider == Provider::File => format!("section {name}"),
        Select::Secret { name, .. } => format!("secret {name}"),
        Select::Secrets(names) => format!("secrets {}", names.join(", ")),
    };
    format!("the {} source {what}", spec.provider.as_str())
}

/// Appends a source to an environment; a later source wins over an earlier
/// one.
pub fn add_source(
    dir: &ConfigDir,
    project: &ProjectName,
    env: &EnvName,
    source: &NewSource,
) -> Result<Edited, CliError> {
    let _lock = lock(dir)?;
    let registry = Registry::load(dir).map_err(config)?;
    let mut doc = existing(&registry, project)?;
    let (_, file) = env_file(&registry, project, env)?;
    let first = file.sources.is_empty();
    let mut entry = Table::new();
    entry.insert("provider", value(source.provider.as_str()));
    if let Some(p) = &source.prefix {
        entry.insert("prefix", value(p.as_str()));
    }
    match &source.secrets[..] {
        [] => {}
        [one] => {
            entry.insert("secret", value(one.as_str()));
        }
        many => {
            entry.insert("secrets", value(many.iter().collect::<toml_edit::Array>()));
        }
    }
    if let Some(k) = &source.key {
        entry.insert("key", value(k.as_str()));
    }
    if source.optional {
        entry.insert("optional", value(true));
    }
    if let Some(p) = &source.profile {
        entry.insert("profile", value(p.as_str()));
    }
    if let Some(r) = &source.region {
        entry.insert("region", value(r.as_str()));
    }
    let table = env_table(&mut doc, env)?;
    match table.get_mut("sources") {
        None => {
            let mut list = ArrayOfTables::new();
            list.push(entry);
            table.insert("sources", Item::ArrayOfTables(list));
        }
        Some(Item::ArrayOfTables(list)) => list.push(entry),
        Some(Item::Value(toml_edit::Value::Array(list))) => list.push(entry.into_inline_table()),
        Some(_) => return Err(config("sources is not a list of tables")),
    }
    let mut edited = commit(
        &registry,
        dir,
        project,
        env,
        doc,
        Added::Last,
        "project add-source",
    )?;
    edited.replaced_default = first;
    Ok(edited)
}

/// The environment's `sources` list, which must hold `index`.
fn sources_list<'a>(
    doc: &'a mut DocumentMut,
    project: &ProjectName,
    env: &EnvName,
    count: usize,
    index: usize,
) -> Result<&'a mut Item, CliError> {
    if index >= count {
        return Err(config(format!(
            "environment {env} of project {project} has no source {}",
            index + 1
        )));
    }
    env_table(doc, env)?
        .get_mut("sources")
        .filter(|i| i.is_array_of_tables() || i.is_array())
        .ok_or_else(|| config("sources is not a list of tables"))
}

/// Removes the environment's source at `index` (from 0). With none left,
/// the environment reads its default source again.
pub fn remove_source(
    dir: &ConfigDir,
    project: &ProjectName,
    env: &EnvName,
    index: usize,
) -> Result<Edited, CliError> {
    let _lock = lock(dir)?;
    let registry = Registry::load(dir).map_err(config)?;
    let mut doc = existing(&registry, project)?;
    let (p, file) = env_file(&registry, project, env)?;
    let count = file.sources.len();
    let list = sources_list(&mut doc, project, env, count, index)?;
    let what = registry
        .env(p, Some(env))
        .map_err(config)?
        .sources
        .get(index)
        .map(describe)
        .unwrap_or_default();
    match list {
        Item::ArrayOfTables(a) => {
            a.remove(index);
        }
        Item::Value(toml_edit::Value::Array(a)) => {
            a.remove(index);
        }
        _ => unreachable!("checked by sources_list"),
    }
    if count == 1 {
        env_table(&mut doc, env)?.remove("sources");
    }
    commit(
        &registry,
        dir,
        project,
        env,
        doc,
        Added::Nothing(what),
        "project remove-source",
    )
}

/// Moves the environment's source at `from` to `to` (both from 0), which
/// changes which one wins a key two of them set.
pub fn move_source(
    dir: &ConfigDir,
    project: &ProjectName,
    env: &EnvName,
    from: usize,
    to: usize,
) -> Result<Edited, CliError> {
    let _lock = lock(dir)?;
    let registry = Registry::load(dir).map_err(config)?;
    let mut doc = existing(&registry, project)?;
    let (p, file) = env_file(&registry, project, env)?;
    let count = file.sources.len();
    sources_list(&mut doc, project, env, count, to)?;
    let list = sources_list(&mut doc, project, env, count, from)?;
    let what = registry
        .env(p, Some(env))
        .map_err(config)?
        .sources
        .get(from)
        .map(|s| format!("{}, from {} to {}", describe(s), from + 1, to + 1))
        .unwrap_or_default();
    match list {
        Item::ArrayOfTables(a) => {
            // Tables print in the order of their positions in the file, so
            // the moved tables take over the positions in order.
            let positions: Vec<_> = a.iter().map(Table::position).collect();
            let t = a.remove(from);
            a.insert(to, t);
            for (t, pos) in a.iter_mut().zip(positions) {
                t.set_position(pos);
            }
        }
        Item::Value(toml_edit::Value::Array(a)) => {
            let v = a.remove(from);
            a.insert_formatted(to, v);
            a.fmt();
        }
        _ => unreachable!("checked by sources_list"),
    }
    commit(
        &registry,
        dir,
        project,
        env,
        doc,
        Added::Nothing(what),
        "project move-source",
    )
}

/// Sets the AWS profile or region, or both, of the environment's aws_sm
/// source at `index` (from 0), or of every one of them without `index`.
/// Sources that do not set their own profile inherit the environment's or
/// the project's, which `project set` changes instead.
pub fn set_source(
    dir: &ConfigDir,
    project: &ProjectName,
    env: &EnvName,
    index: Option<usize>,
    profile: Option<&Profile>,
    region: Option<&Region>,
) -> Result<Edited, CliError> {
    let _lock = lock(dir)?;
    let registry = Registry::load(dir).map_err(config)?;
    let mut doc = existing(&registry, project)?;
    let (p, file) = env_file(&registry, project, env)?;
    let count = file.sources.len();
    let specs = registry.env(p, Some(env)).map_err(config)?.sources;
    let at: Vec<usize> = match index {
        Some(i) => {
            sources_list(&mut doc, project, env, count, i)?;
            if specs[i].provider != Provider::AwsSm {
                return Err(config(format!(
                    "source {} of environment {env} of project {project} is {}; only aws_sm \
                     sources have a profile and region",
                    i + 1,
                    describe(&specs[i])
                )));
            }
            vec![i]
        }
        None => (0..count)
            .filter(|&i| specs[i].provider == Provider::AwsSm)
            .collect(),
    };
    let Some(&first) = at.first() else {
        return Err(config(format!(
            "environment {env} of project {project} has no aws_sm sources"
        )));
    };
    let list = sources_list(&mut doc, project, env, count, first)?;
    for &i in &at {
        let entry: &mut dyn TableLike = match &mut *list {
            Item::ArrayOfTables(a) => a.get_mut(i).map(|t| t as &mut dyn TableLike),
            Item::Value(toml_edit::Value::Array(a)) => a
                .get_mut(i)
                .and_then(toml_edit::Value::as_inline_table_mut)
                .map(|t| t as &mut dyn TableLike),
            _ => None,
        }
        .ok_or_else(|| config("sources is not a list of tables"))?;
        if let Some(p) = profile {
            entry.insert("profile", value(p.as_str()));
        }
        if let Some(r) = region {
            entry.insert("region", value(r.as_str()));
        }
    }
    let set = [
        profile.map(|p| format!("profile {p}")),
        region.map(|r| format!("region {r}")),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(" and ");
    let what = format!(
        "{} set to {set}",
        at.iter()
            .map(|&i| describe(&specs[i]))
            .collect::<Vec<_>>()
            .join(", ")
    );
    commit(
        &registry,
        dir,
        project,
        env,
        doc,
        Added::Changed(at, what),
        "project set-source",
    )
}

/// Removes the environment's exact duplicate sources: those that resolve
/// to the same source as a later one, which wins anyway. Keeping the last
/// copy leaves what resolves unchanged. Returns what was removed, with the
/// position it had (from 1); writes nothing when there is nothing to remove.
pub fn dedupe(
    dir: &ConfigDir,
    project: &ProjectName,
    env: &EnvName,
) -> Result<Vec<String>, CliError> {
    let _lock = lock(dir)?;
    let registry = Registry::load(dir).map_err(config)?;
    let mut doc = existing(&registry, project)?;
    let (p, file) = env_file(&registry, project, env)?;
    let count = file.sources.len();
    let specs = registry.env(p, Some(env)).map_err(config)?.sources;
    let dupes: Vec<usize> = (0..count)
        .filter(|&i| specs[i + 1..].contains(&specs[i]))
        .collect();
    if dupes.is_empty() {
        return Ok(Vec::new());
    }
    let removed: Vec<String> = dupes
        .iter()
        .map(|&i| format!("{} (source {})", describe(&specs[i]), i + 1))
        .collect();
    let list = sources_list(&mut doc, project, env, count, 0)?;
    for &i in dupes.iter().rev() {
        match list {
            Item::ArrayOfTables(a) => {
                a.remove(i);
            }
            Item::Value(toml_edit::Value::Array(a)) => {
                a.remove(i);
            }
            _ => unreachable!("checked by sources_list"),
        }
    }
    commit(
        &registry,
        dir,
        project,
        env,
        doc,
        Added::Nothing(removed.join(", ")),
        "project dedupe",
    )?;
    Ok(removed)
}

/// Sets a plain setting of the environment, one that is not secret: the
/// lowest layer, which any source setting the key wins over.
pub fn set_var(
    dir: &ConfigDir,
    project: &ProjectName,
    env: &EnvName,
    key: &KeyName,
    val: &str,
) -> Result<Edited, CliError> {
    let _lock = lock(dir)?;
    let registry = Registry::load(dir).map_err(config)?;
    let mut doc = existing(&registry, project)?;
    env_file(&registry, project, env)?;
    let table = env_table(&mut doc, env)?;
    let vars = table
        .entry("vars")
        .or_insert_with(|| Item::Table(Table::new()))
        .as_table_like_mut()
        .ok_or_else(|| config("vars is not a table"))?;
    vars.insert(key.as_str(), value(val));
    commit(
        &registry,
        dir,
        project,
        env,
        doc,
        Added::Nothing(format!("plain setting {key}")),
        "project set-var",
    )
}

/// Removes a plain setting of the environment.
pub fn unset_var(
    dir: &ConfigDir,
    project: &ProjectName,
    env: &EnvName,
    key: &KeyName,
) -> Result<Edited, CliError> {
    let _lock = lock(dir)?;
    let registry = Registry::load(dir).map_err(config)?;
    let mut doc = existing(&registry, project)?;
    let (_, file) = env_file(&registry, project, env)?;
    if !file.vars.contains_key(key) {
        return Err(config(format!(
            "environment {env} of project {project} has no plain setting {key}"
        )));
    }
    let table = env_table(&mut doc, env)?;
    let vars = table
        .get_mut("vars")
        .and_then(Item::as_table_like_mut)
        .ok_or_else(|| config("vars is not a table"))?;
    vars.remove(key.as_str());
    if vars.is_empty() {
        table.remove("vars");
    }
    commit(
        &registry,
        dir,
        project,
        env,
        doc,
        Added::Nothing(format!("plain setting {key}")),
        "project unset-var",
    )
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::test_support::in_child_with;

    const WIDGET: &str = r#"schema = 1
remotes = ["github.com/acme/widget"]

[envs.dev]
# the shared dev secrets
[[envs.dev.sources]]
provider = "aws_sm"
prefix = "acme/dev/"

[[envs.dev.sources]]
provider = "file"

[[envs.dev.sources]]
provider = "aws_sm"
secret = "acme/dev/extra"
"#;

    /// Runs `name` again in a child whose audit log is under a temp dir,
    /// with `vars` set too; in that child, returns the config dir to use.
    fn child(name: &str, vars: &[(&str, &std::ffi::OsStr)]) -> Option<(ConfigDir, PathBuf)> {
        if std::env::var_os("KAGEBUNSHIN_TEST_CHILD").is_none() {
            let tmp = tempfile::tempdir().unwrap();
            let state = tmp.path().join("state");
            let mut all = vec![("XDG_STATE_HOME", state.as_os_str())];
            all.extend_from_slice(vars);
            assert!(!in_child_with(name, &all));
            return None;
        }
        let state = PathBuf::from(std::env::var_os("XDG_STATE_HOME").unwrap());
        let dir = ConfigDir::new(state.parent().unwrap().join("config"));
        std::fs::create_dir_all(dir.projects_dir()).unwrap();
        Some((dir, state))
    }

    fn sources(dir: &ConfigDir) -> Vec<String> {
        let registry = Registry::load(dir).unwrap();
        let p = registry.project(&"widget".parse().unwrap()).unwrap();
        let env = registry.env(p, Some(&"dev".parse().unwrap())).unwrap();
        env.sources.iter().map(describe).collect()
    }

    fn audit(state: &Path) -> String {
        std::fs::read_to_string(state.join("kagebunshin/audit.jsonl")).unwrap_or_default()
    }

    #[test]
    fn moves_and_removes_sources_keeping_the_file_loading() {
        let Some((dir, state)) = child(
            "cli::edit::tests::moves_and_removes_sources_keeping_the_file_loading",
            &[],
        ) else {
            return;
        };
        let (p, e) = ("widget".parse().unwrap(), "dev".parse().unwrap());
        let file = dir.project_file(&p);
        std::fs::write(&file, WIDGET).unwrap();

        move_source(&dir, &p, &e, 2, 0).unwrap();
        assert_eq!(
            sources(&dir),
            [
                "the aws_sm source secret acme/dev/extra",
                "the aws_sm source prefix acme/dev/",
                "the file source section widget.dev",
            ]
        );
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(text.contains("# the shared dev secrets"), "{text}");

        remove_source(&dir, &p, &e, 1).unwrap();
        remove_source(&dir, &p, &e, 0).unwrap();
        assert_eq!(sources(&dir), ["the file source section widget.dev"]);
        // The last one: the environment reads its default source again.
        remove_source(&dir, &p, &e, 0).unwrap();
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(!text.contains("sources"), "{text}");
        assert_eq!(sources(&dir), ["the file source section widget.dev"]);
        assert!(remove_source(&dir, &p, &e, 0).is_err());

        let log = audit(&state);
        assert!(log.contains("project move-source"), "{log}");
        assert_eq!(log.matches("project remove-source").count(), 3, "{log}");
    }

    #[test]
    fn moves_inline_sources_too() {
        let Some((dir, _)) = child("cli::edit::tests::moves_inline_sources_too", &[]) else {
            return;
        };
        let (p, e) = ("widget".parse().unwrap(), "dev".parse().unwrap());
        std::fs::write(
            dir.project_file(&p),
            r#"schema = 1
remotes = ["github.com/acme/widget"]
[envs.dev]
sources = [{ provider = "file" }, { provider = "aws_sm", prefix = "acme/dev/" }]
"#,
        )
        .unwrap();
        move_source(&dir, &p, &e, 0, 1).unwrap();
        assert_eq!(
            sources(&dir),
            [
                "the aws_sm source prefix acme/dev/",
                "the file source section widget.dev"
            ]
        );
        assert!(move_source(&dir, &p, &e, 0, 2).is_err());
    }

    /// Keeps the last copy of each duplicate, so the same source still
    /// wins; a bare file source and its explicit section are the same.
    #[test]
    fn dedupe_keeps_the_copy_that_wins() {
        let Some((dir, state)) = child("cli::edit::tests::dedupe_keeps_the_copy_that_wins", &[])
        else {
            return;
        };
        let (p, e) = ("widget".parse().unwrap(), "dev".parse().unwrap());
        std::fs::write(
            dir.project_file(&p),
            r#"schema = 1
remotes = ["github.com/acme/widget"]

[[envs.dev.sources]]
provider = "aws_sm"
prefix = "acme/dev/"

[[envs.dev.sources]]
provider = "file"

[[envs.dev.sources]]
provider = "aws_sm"
prefix = "acme/dev/"
optional = true

[[envs.dev.sources]]
provider = "file"
secret = "widget.dev"

[[envs.dev.sources]]
provider = "aws_sm"
prefix = "acme/dev/"
"#,
        )
        .unwrap();
        let removed = dedupe(&dir, &p, &e).unwrap();
        assert_eq!(
            removed,
            [
                "the aws_sm source prefix acme/dev/ (source 1)",
                "the file source section widget.dev (source 2)",
            ]
        );
        assert_eq!(
            sources(&dir),
            [
                "the aws_sm source prefix acme/dev/",
                "the file source section widget.dev",
                "the aws_sm source prefix acme/dev/",
            ]
        );
        let text = std::fs::read_to_string(dir.project_file(&p)).unwrap();
        assert!(text.contains("optional = true"), "{text}");
        assert_eq!(dedupe(&dir, &p, &e).unwrap(), Vec::<String>::new());
        assert_eq!(audit(&state).matches("project dedupe").count(), 1);
    }

    #[test]
    fn sets_and_unsets_plain_settings() {
        let Some((dir, state)) = child("cli::edit::tests::sets_and_unsets_plain_settings", &[])
        else {
            return;
        };
        let (p, e) = ("widget".parse().unwrap(), "dev".parse().unwrap());
        let file = dir.project_file(&p);
        std::fs::write(&file, WIDGET).unwrap();
        let vars = |dir: &ConfigDir| {
            let registry = Registry::load(dir).unwrap();
            let project = registry.project(&p).unwrap();
            registry.env(project, Some(&e)).unwrap().vars
        };
        let port: KeyName = "PORT".parse().unwrap();
        set_var(&dir, &p, &e, &port, "3000").unwrap();
        set_var(&dir, &p, &e, &"LOG_LEVEL".parse().unwrap(), "debug").unwrap();
        // Not a number: the log's times and pids are, and may hold any.
        set_var(&dir, &p, &e, &port, "not-logged").unwrap();
        let got = vars(&dir);
        assert_eq!(got.get(&port).map(String::as_str), Some("not-logged"));
        assert_eq!(got.len(), 2);
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(text.contains("[envs.dev.vars]"), "{text}");
        assert!(text.contains("# the shared dev secrets"), "{text}");
        assert_eq!(sources(&dir).len(), 3);

        unset_var(&dir, &p, &e, &port).unwrap();
        unset_var(&dir, &p, &e, &"LOG_LEVEL".parse().unwrap()).unwrap();
        assert!(vars(&dir).is_empty());
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(!text.contains("vars"), "{text}");
        assert!(unset_var(&dir, &p, &e, &port).is_err());
        assert!(set_var(&dir, &p, &"nope".parse().unwrap(), &port, "1").is_err());

        let log = audit(&state);
        assert_eq!(log.matches("project set-var").count(), 3, "{log}");
        assert!(!log.contains("not-logged"), "{log}");
    }
}
