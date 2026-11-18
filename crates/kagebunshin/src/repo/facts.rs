//! What a checkout says about the secrets it needs: names only, read from
//! the files on this machine, nothing sent anywhere.
//!
//! [`read`] finds the checkout's apps (the root and folders below it with
//! an example file or an env file), and for each the keys of its
//! `.env.example`, and the key names in its real env files and whether each
//! has a value. Unlike the rest of this module it opens
//! real env files: their values are parsed into zeroing buffers, counted as
//! set or empty, and dropped, never kept or shown. It also names the files
//! with values that `onboard` leaves alone unless asked: `.dev.env`,
//! `production.env` and the like, in any folder.
//!
//! [`mentions`] searches the checkout's tracked text files for secret names
//! a provider listed, letter for letter.

use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::{BadLine, ENV_EXAMPLE, MAX_SIZE, is_other_env_file, is_real_env_file};
use crate::types::KeyName;

/// Folders below the root that are looked in for apps.
pub const MAX_DEPTH: usize = 4;
/// Folders looked in at most, and apps reported at most.
pub const MAX_DIRS: usize = 5000;
pub const MAX_APPS: usize = 64;
/// Tracked files searched at most for secret names, the largest searched,
/// and the names searched for at most.
pub const MAX_FILES: usize = 2000;
pub const MAX_FILE_SIZE: u64 = 256 * 1024;
pub const MAX_NAMES: usize = 500;

/// Folders that hold dependencies, build output or tool state, never an
/// app's own files. Folders whose name starts with `.` are skipped too.
pub(super) const SKIP: &[&str] = &[
    "node_modules",
    "target",
    "vendor",
    "dist",
    "build",
    "out",
    "coverage",
    "venv",
    "__pycache__",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckoutFacts {
    /// Folders with an example file or an env file, the root first, then
    /// by path.
    pub apps: Vec<App>,
    /// Files with a value in them that `onboard` does not import by
    /// itself, by path from the root: an app's real env files after its
    /// first with values, and files that hold values under another name
    /// ([`is_other_env_file`]), wherever they are.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub other_env_files: Vec<PathBuf>,
    /// The caps that were hit, in words.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub capped: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct App {
    /// Relative to the checkout root; empty for the root.
    pub dir: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub example: Option<Example>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub env_files: Vec<EnvFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Example {
    /// In file order.
    pub keys: Vec<FileKey>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub bad_lines: Vec<BadLine>,
    /// Why it could not be read, if it could not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub problem: Option<String>,
}

/// A key of an example or env file. `has_value`: the file gives it a
/// value that is not empty (an example's may be a placeholder).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileKey {
    pub key: KeyName,
    pub has_value: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnvFile {
    /// The file name, in the app's folder.
    pub name: String,
    pub keys: Vec<FileKey>,
    /// Lines that could not be read, by number only.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub bad_lines: Vec<BadLine>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub problem: Option<String>,
}

impl EnvFile {
    pub fn has_values(&self) -> bool {
        self.keys.iter().any(|k| k.has_value)
    }
}

impl App {
    /// The keys the example lists, in file order.
    pub fn example_keys(&self) -> Vec<KeyName> {
        self.example
            .iter()
            .flat_map(|e| e.keys.iter().map(|k| k.key.clone()))
            .collect()
    }

    /// An env file with a value in it, if there is one.
    pub fn env_file_with_values(&self) -> Option<&EnvFile> {
        self.env_files.iter().find(|f| f.has_values())
    }
}

/// The apps of the checkout at `root`. Never fails: a file that cannot be
/// read is reported on the app it belongs to.
pub fn read(root: &Path) -> CheckoutFacts {
    let mut facts = CheckoutFacts {
        apps: Vec::new(),
        other_env_files: Vec::new(),
        capped: Vec::new(),
    };
    let mut queue = vec![(root.to_owned(), 0usize)];
    let mut visited = 0;
    while let Some((dir, depth)) = queue.pop() {
        visited += 1;
        if visited > MAX_DIRS {
            facts
                .capped
                .push(format!("stopped looking for apps after {MAX_DIRS} folders"));
            break;
        }
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        let mut names: Vec<(String, fs::FileType)> = entries
            .filter_map(|e| {
                let e = e.ok()?;
                Some((e.file_name().into_string().ok()?, e.file_type().ok()?))
            })
            .collect();
        names.sort_by(|a, b| a.0.cmp(&b.0));
        let rel = dir.strip_prefix(root).unwrap_or(&dir);
        let app = app_in(root, &dir, &names);
        let later = app.iter().flat_map(|a| {
            let with_values = a.env_files.iter().filter(|f| f.has_values());
            with_values.skip(1).map(|f| f.name.clone())
        });
        let other = names.iter().filter(|(n, t)| {
            t.is_file()
                && is_other_env_file(std::ffi::OsStr::new(n))
                && env_file(&dir.join(n), n).has_values()
        });
        let found: Vec<PathBuf> = later
            .chain(other.map(|(n, _)| n.clone()))
            .map(|n| rel.join(n))
            .collect();
        facts.other_env_files.extend(found);
        if let Some(app) = app {
            if facts.apps.len() == MAX_APPS {
                facts
                    .capped
                    .push(format!("reported only the first {MAX_APPS} apps"));
                break;
            }
            facts.apps.push(app);
        }
        if depth < MAX_DEPTH {
            // Reversed, so the stack pops them in name order.
            for (name, ty) in names.iter().rev() {
                if ty.is_dir() && !name.starts_with('.') && !SKIP.contains(&name.as_str()) {
                    queue.push((dir.join(name), depth + 1));
                }
            }
        }
    }
    facts.apps.sort_by(|a, b| a.dir.cmp(&b.dir));
    facts.other_env_files.sort();
    facts
}

/// The app in `dir`, if it has an example or an env file.
fn app_in(root: &Path, dir: &Path, names: &[(String, fs::FileType)]) -> Option<App> {
    let regular = |n: &str| names.iter().any(|(m, t)| m == n && t.is_file());
    let example = regular(ENV_EXAMPLE).then(|| match super::read(&dir.join(ENV_EXAMPLE)) {
        Ok(e) => Example {
            keys: e
                .keys
                .iter()
                .map(|k| FileKey {
                    key: k.clone(),
                    has_value: e.values.get(k).is_some(),
                })
                .collect(),
            bad_lines: e.bad_lines,
            problem: None,
        },
        Err(e) => Example {
            keys: Vec::new(),
            bad_lines: Vec::new(),
            problem: Some(e.to_string()),
        },
    });
    let env_files: Vec<EnvFile> = names
        .iter()
        .filter(|(n, t)| t.is_file() && is_real_env_file(std::ffi::OsStr::new(n)))
        .map(|(n, _)| env_file(&dir.join(n), n))
        .collect();
    if example.is_none() && env_files.is_empty() {
        return None;
    }
    Some(App {
        dir: dir.strip_prefix(root).unwrap_or(dir).to_owned(),
        example,
        env_files,
    })
}

/// Reads at most [`MAX_SIZE`] bytes of a regular file into a zeroing
/// buffer. Symlinks are refused, and a FIFO does not hang.
fn read_private(path: &Path) -> Result<zeroize::Zeroizing<String>, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| format!("cannot read it: {e}"))?;
    if !file.metadata().is_ok_and(|m| m.is_file()) {
        return Err("it is not a regular file".into());
    }
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    file.take(MAX_SIZE + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read it: {e}"))?;
    if bytes.len() as u64 > MAX_SIZE {
        return Err(format!("it is larger than {MAX_SIZE} bytes"));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| "it is not UTF-8".to_owned())?;
    Ok(zeroize::Zeroizing::new(text.to_owned()))
}

/// A real env file's key names and which have a value. The values are
/// dropped here, which zeroes them.
fn env_file(path: &Path, name: &str) -> EnvFile {
    let mut out = EnvFile {
        name: name.to_owned(),
        keys: Vec::new(),
        bad_lines: Vec::new(),
        problem: None,
    };
    match read_private(path) {
        Ok(text) => {
            let (values, bad) = super::env_example::parse_values(&text);
            let mut seen: Vec<KeyName> = Vec::new();
            for (key, value) in values.iter().rev() {
                // The last value of a key set twice is the one that counts.
                if !seen.contains(key) {
                    seen.push(key.clone());
                    out.keys.push(FileKey {
                        key: key.clone(),
                        has_value: !value.expose().is_empty(),
                    });
                }
            }
            out.keys.reverse();
            out.bad_lines = bad;
        }
        Err(why) => out.problem = Some(why),
    }
    out
}

/// Secret names found in the checkout's files.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct Mentions {
    /// In the order the checkout first names them (by file, as git lists
    /// them, then by place in the file); each with the files, relative to
    /// the root, that name it.
    pub found: Vec<Mention>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub capped: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Mention {
    pub name: String,
    pub files: Vec<PathBuf>,
}

/// Which of `names` appear in `files` (relative to `root`, as git lists
/// the tracked ones), letter for letter and as a whole name: the letters
/// around it are not part of a name (letters, digits, `/`, `_`, `-`, `+`,
/// `=`, `@`). A name followed by `-` and six letters or digits counts too,
/// as an ARN ends. Real env files, big files and binary files are skipped.
pub fn mentions(root: &Path, files: &[PathBuf], names: &[String]) -> Mentions {
    let mut out = Mentions::default();
    let names = if names.len() > MAX_NAMES {
        out.capped.push(format!(
            "searched for only the first {MAX_NAMES} of {} secret names",
            names.len()
        ));
        &names[..MAX_NAMES]
    } else {
        names
    };
    let mut found: Vec<Vec<PathBuf>> = vec![Vec::new(); names.len()];
    // Where each name is first found: the file's number, then the place.
    let mut first: Vec<(usize, usize)> = vec![(0, 0); names.len()];
    let mut searched = 0;
    for rel in files {
        if rel
            .file_name()
            .is_none_or(|n| is_real_env_file(n) || n == ENV_EXAMPLE)
        {
            continue;
        }
        if searched == MAX_FILES {
            out.capped.push(format!(
                "searched only {MAX_FILES} of the {} tracked files",
                files.len()
            ));
            break;
        }
        let path = root.join(rel);
        if fs::symlink_metadata(&path).map_or(true, |m| !m.is_file() || m.len() > MAX_FILE_SIZE) {
            continue;
        }
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        if bytes.contains(&0) {
            continue;
        }
        let Ok(text) = std::str::from_utf8(&bytes) else {
            continue;
        };
        searched += 1;
        for (i, name) in names.iter().enumerate() {
            if let Some(at) = find_whole(text, name) {
                if found[i].is_empty() {
                    first[i] = (searched, at);
                }
                found[i].push(rel.clone());
            }
        }
    }
    let mut order: Vec<usize> = (0..names.len()).filter(|i| !found[*i].is_empty()).collect();
    order.sort_by_key(|i| first[*i]);
    out.found = order
        .into_iter()
        .map(|i| Mention {
            name: names[i].clone(),
            files: std::mem::take(&mut found[i]),
        })
        .collect();
    out
}

fn name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "/_-+=@".contains(c)
}

/// Where `name` is first in `text` with no name letter right before or
/// after it, or followed by an ARN's `-xxxxxx`. An empty name is nowhere.
pub(super) fn find_whole(text: &str, name: &str) -> Option<usize> {
    if name.is_empty() {
        return None;
    }
    text.match_indices(name).map(|(at, _)| at).find(|&at| {
        let before = text[..at].chars().next_back();
        let rest = &text[at + name.len()..];
        if before.is_some_and(name_char) {
            return false;
        }
        let mut after = rest.chars();
        match after.next() {
            None => true,
            Some(c) if !name_char(c) => true,
            Some('-') => {
                let s: Vec<char> = after.take(7).collect();
                s.len() >= 6
                    && s[..6].iter().all(char::is_ascii_alphanumeric)
                    && s.get(6).is_none_or(|c| !name_char(*c))
            }
            Some(_) => false,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{Canary, assert_no_canary};

    fn write(root: &Path, rel: &str, text: &str) {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, text).unwrap();
    }

    #[test]
    fn files_with_values_under_other_names_are_named() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let canary = Canary::new();
        let value = format!("TOKEN={}\n", canary.value());
        write(root, ".env.example", "TOKEN=\n");
        write(root, ".dev.env", &value);
        write(root, "production.env", &value);
        // No value in it, and an example: neither is named.
        write(root, "empty.env", "TOKEN=\n");
        write(root, "staging.env.example", "TOKEN=placeholder\n");
        // An app's first env file with values is `onboard`'s; the next is not.
        write(root, "apps/web/.env", "TOKEN=\n");
        write(root, "apps/web/.env.local", &value);
        write(root, "apps/web/.env.production", &value);
        // A folder that is no app.
        write(root, "deploy/.dev.vars", &value);
        write(root, "node_modules/x/.dev.env", &value);

        let facts = read(root);
        let dirs: Vec<&Path> = facts.apps.iter().map(|a| a.dir.as_path()).collect();
        assert_eq!(dirs, [Path::new(""), Path::new("apps/web")]);
        let others: Vec<&str> = (facts.other_env_files.iter())
            .filter_map(|p| p.to_str())
            .collect();
        assert_eq!(
            others,
            [
                ".dev.env",
                "apps/web/.env.production",
                "deploy/.dev.vars",
                "production.env"
            ]
        );
        assert_no_canary(&canary, &format!("{facts:?}"));
    }

    #[test]
    fn apps_examples_and_env_files_by_name_only() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let canary = Canary::new();
        write(root, ".env.example", "API_KEY=\nPORT=3000\n");
        write(
            root,
            ".env",
            &format!(
                "API_KEY={}\nEMPTY=\nAPI_KEY={}\n",
                canary.value(),
                canary.value()
            ),
        );
        write(
            root,
            "apps/web/.env.example",
            "NEXT_PUBLIC_URL=http://localhost\n",
        );
        write(
            root,
            "apps/web/.env.local",
            &format!("TOKEN={}\n", canary.value()),
        );
        write(root, "apps/api/src/main.rs", "fn main() {}\n");
        write(root, "node_modules/x/.env.example", "NOPE=\n");
        write(root, ".git/.env.example", "NOPE=\n");

        let facts = read(root);
        let dirs: Vec<&Path> = facts.apps.iter().map(|a| a.dir.as_path()).collect();
        assert_eq!(dirs, [Path::new(""), Path::new("apps/web")]);
        let top = &facts.apps[0];
        let ex = top.example.as_ref().unwrap();
        let keys: Vec<(&str, bool)> = ex
            .keys
            .iter()
            .map(|k| (k.key.as_str(), k.has_value))
            .collect();
        assert_eq!(keys, [("API_KEY", false), ("PORT", true)]);
        let env = &top.env_files[0];
        assert_eq!(env.name, ".env");
        let keys: Vec<(&str, bool)> = env
            .keys
            .iter()
            .map(|k| (k.key.as_str(), k.has_value))
            .collect();
        assert_eq!(keys, [("EMPTY", false), ("API_KEY", true)]);
        assert!(top.env_file_with_values().is_some());
        let web = &facts.apps[1];
        assert_eq!(web.env_files[0].name, ".env.local");
        assert!(facts.capped.is_empty());

        let shown = format!("{facts:?}\n{}", serde_json::to_string(&facts).unwrap());
        assert_no_canary(&canary, &shown);
    }

    #[test]
    fn a_symlinked_env_file_is_not_followed() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("repo");
        let canary = Canary::new();
        write(
            tmp.path(),
            "outside",
            &format!("SECRET={}\n", canary.value()),
        );
        fs::create_dir(&root).unwrap();
        std::os::unix::fs::symlink(tmp.path().join("outside"), root.join(".env")).unwrap();
        write(&root, ".env.example", "SECRET=\n");
        let facts = read(&root);
        // A symlink is not a regular file entry, so it is not read at all.
        assert!(facts.apps[0].env_files.is_empty());
        assert_no_canary(&canary, &format!("{facts:?}"));
    }

    #[test]
    fn names_are_found_whole_and_env_files_are_not_searched() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(
            root,
            ".github/workflows/deploy.yml",
            "secret: acme/dev/api\narn: arn:aws:secretsmanager:eu-west-1:1:secret:acme/dev/db-AbC123\n",
        );
        write(
            root,
            "scripts/x.sh",
            "acme/dev/api-keys and acme/dev/apix\n",
        );
        write(root, ".env", "X=acme/dev/cache\n");
        write(root, "bin.dat", "acme/dev/cache\0");
        let files: Vec<PathBuf> = [
            ".github/workflows/deploy.yml",
            "scripts/x.sh",
            ".env",
            "bin.dat",
        ]
        .iter()
        .map(PathBuf::from)
        .collect();
        let names: Vec<String> = [
            "acme/dev/api",
            "acme/dev/db",
            "acme/dev/cache",
            "acme/dev/api-keys",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        let m = mentions(root, &files, &names);
        let found: Vec<(&str, Vec<&Path>)> = m
            .found
            .iter()
            .map(|f| {
                (
                    f.name.as_str(),
                    f.files.iter().map(PathBuf::as_path).collect(),
                )
            })
            .collect();
        assert_eq!(
            found,
            [
                (
                    "acme/dev/api",
                    vec![Path::new(".github/workflows/deploy.yml")]
                ),
                (
                    "acme/dev/db",
                    vec![Path::new(".github/workflows/deploy.yml")]
                ),
                ("acme/dev/api-keys", vec![Path::new("scripts/x.sh")]),
            ]
        );
    }

    #[test]
    fn caps_are_reported() {
        let tmp = tempfile::tempdir().unwrap();
        let names: Vec<String> = (0..=MAX_NAMES).map(|i| format!("acme/{i}")).collect();
        let m = mentions(tmp.path(), &[], &names);
        assert_eq!(m.capped.len(), 1);
    }
}
