//! `project example`: a `.env.example` for an app that has none, seeded
//! with the keys its code reads ([`crate::repo::reads`]). Names only; no
//! file with values is opened and nothing is run.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::error::{CliError, Exit};
use crate::config::{ConfigDir, Git, Registry};
use crate::repo::reads::{Read, Reads, reads};
use crate::repo::{self, ENV_EXAMPLE};
use crate::types::ProjectName;

/// An app with no `.env.example`: where one goes, and what its code reads.
#[derive(Debug, Serialize)]
pub(super) struct Seed {
    /// The file to write: in the folder of the project that claims the
    /// place, its `path`, else in the checkout's root.
    pub path: PathBuf,
    /// The keys the files of that folder read, each with the files that
    /// name it, relative to the folder.
    pub keys: Vec<Read>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub capped: Vec<String>,
}

/// The [`Seed`] for the app that `dir` is in, as project `project` if
/// named; `None` if it has a `.env.example`.
///
/// The files searched are those git tracks or would, in the app's folder
/// and not in another app's below it: a folder another project of the
/// checkout has as its `path`, or one with a `.env.example` or an env file
/// of its own.
pub(super) fn seed(dir: &Path, project: Option<&ProjectName>) -> Result<Option<Seed>, CliError> {
    let git = Git::default();
    let checkout = git.checkout(dir).map_err(|e| {
        CliError::new(Exit::Failure, "no_project", e.to_string())
            .with_hint("run this in the app's git checkout, or give --path DIR")
    })?;
    let subdir = checkout.subdir(dir).filter(|d| !d.as_os_str().is_empty());
    let (configured, top) = super::local_project(&checkout, subdir.as_deref(), project);
    let top = top.map(|t| t.as_path().to_owned());
    let found = repo::find(&checkout.root, dir, top.as_deref(), configured.as_deref())
        .map_err(|e| CliError::new(Exit::Failure, "env_example", e.to_string()))?;
    if found.is_some() {
        return Ok(None);
    }
    let app = top.unwrap_or_default();

    let mut others: Vec<PathBuf> = (repo::facts::read(&checkout.root).apps.into_iter())
        .map(|a| a.dir)
        .collect();
    if let Some(registry) = ConfigDir::from_env()
        .ok()
        .and_then(|d| Registry::load(&d).ok())
    {
        others.extend(
            registry
                .projects()
                .filter(|p| p.file.remotes.iter().any(|r| checkout.remotes.contains(r)))
                .filter_map(|p| Some(p.file.path.as_ref()?.as_path().to_owned())),
        );
    }
    others.retain(|o| o != &app && o.starts_with(&app));

    let files: Vec<PathBuf> = git
        .files(&checkout.root)
        .map_err(|e| CliError::new(Exit::Failure, "git", e.to_string()))?
        .into_iter()
        .filter(|f| f.starts_with(&app) && !others.iter().any(|o| f.starts_with(o)))
        .collect();
    let Reads { mut keys, capped } = reads(&checkout.root, &files);
    for k in &mut keys {
        for f in &mut k.files {
            if let Ok(rel) = f.strip_prefix(&app) {
                *f = rel.to_owned();
            }
        }
    }
    Ok(Some(Seed {
        path: checkout.root.join(app).join(ENV_EXAMPLE),
        keys,
        capped,
    }))
}

/// The text of a `.env.example` listing `keys`.
fn text(keys: &[Read]) -> String {
    let mut out = String::from("# The environment keys this app reads, by name. No values here.\n");
    for k in keys {
        out.push_str(&format!("{}=\n", k.key));
    }
    out
}

/// `project example`: writes the [`Seed`] of the app in `path`, else the
/// working directory. Refused when the app has a `.env.example`, and when
/// no key is found: an empty file would pass a command nothing.
pub(super) fn example(json: bool, path: Option<&Path>) -> Result<(), CliError> {
    let cwd = std::env::current_dir().map_err(super::edit::config)?;
    let dir = path.map_or_else(|| cwd.clone(), |p| cwd.join(p));
    if !dir.is_dir() {
        return Err(super::usage(format!("{} is not a folder", dir.display())));
    }
    let Some(seed) = seed(&dir, None)? else {
        return Err(CliError::new(
            Exit::Failure,
            "exists",
            "this app has a .env.example; edit it to change the keys a command gets",
        ));
    };
    if seed.keys.is_empty() {
        return Err(CliError::new(
            Exit::Failure,
            "no_keys",
            format!(
                "found no key the code reads, so {} is not written",
                seed.path.display()
            ),
        )
        .with_hint(
            "write it by hand: one `NAME=` to a line for each key the app reads from its \
             environment, names only, never a value",
        ));
    }
    let cannot = |e| super::edit::config(format!("cannot write {}: {e}", seed.path.display()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&seed.path)
        .map_err(cannot)?;
    file.write_all(text(&seed.keys).as_bytes())
        .map_err(cannot)?;

    if json {
        return super::print_json(&seed);
    }
    let n = seed.keys.len();
    let mut out = format!(
        "wrote {} with the {n} {} the code reads, names only:",
        seed.path.display(),
        if n == 1 { "key" } else { "keys" }
    );
    for k in &seed.keys {
        let files: Vec<String> = (k.files.iter().take(3))
            .map(|f| f.display().to_string())
            .collect();
        let more = match k.files.len() - files.len() {
            0 => String::new(),
            more => format!(" and {more} more"),
        };
        out.push_str(&format!("\n  {}  ({}{more})", k.key, files.join(", ")));
    }
    for c in &seed.capped {
        out.push_str(&format!("\nnote: {c}"));
    }
    out.push_str(
        "\ncheck it against the code: add a key it reads another way, and take out a name the \
         app runs without. A command run here now gets only the keys listed, and each must be \
         set: `kagebunshin next` says which are not.",
    );
    super::print_line(&out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_file_lists_names_and_no_values() {
        let read = |k: &str| Read {
            key: k.parse().unwrap(),
            files: vec!["src/a.js".into()],
        };
        assert_eq!(
            text(&[read("API_KEY"), read("DB_URL")]),
            "# The environment keys this app reads, by name. No values here.\nAPI_KEY=\nDB_URL=\n"
        );
    }
}
