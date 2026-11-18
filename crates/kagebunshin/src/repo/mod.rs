//! Finding and reading a checkout's `.env.example`, which lists the keys the
//! project expects.
//!
//! Nothing here opens a real env file. The only files read are a
//! `.env.example` found by walking up from the working directory, or the path
//! a project file sets with `env_example`. Either way the file must stay
//! inside the checkout once symlinks are resolved, and its name must not be
//! `.env` or `.env.*` unless it ends in `.example`. The exception is
//! [`facts`], which reads real env files for their key names only.

pub mod env_example;
pub mod facts;
pub mod reads;
pub mod workflows;

use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};

pub use env_example::{BadLine, EnvExample, LineProblem};

pub const ENV_EXAMPLE: &str = ".env.example";
/// Example files are small; anything bigger is not one.
pub const MAX_SIZE: u64 = 1 << 20;

#[derive(Debug, thiserror::Error)]
pub enum RepoError {
    #[error("{} is not inside the checkout at {}", dir.display(), root.display())]
    OutsideCheckout { dir: PathBuf, root: PathBuf },
    #[error("env_example {} must be a relative path without `..`", path.display())]
    OverrideNotRelative { path: PathBuf },
    #[error("env_example {} does not exist", path.display())]
    OverrideMissing { path: PathBuf },
    #[error("{} resolves to a file outside the checkout", path.display())]
    Escapes { path: PathBuf },
    #[error(
        "{} is a .env file; kagebunshin only reads .env.example and other example files",
        path.display()
    )]
    RealEnvFile { path: PathBuf },
    #[error("{} is not a regular file", path.display())]
    NotAFile { path: PathBuf },
    #[error("{} is larger than {MAX_SIZE} bytes", path.display())]
    TooLarge { path: PathBuf },
    #[error("{} is not UTF-8", path.display())]
    NotUtf8 { path: PathBuf },
    #[error("cannot read {}: {source}", path.display())]
    Io { path: PathBuf, source: io::Error },
}

/// An example file and the keys in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// With symlinks resolved.
    pub path: PathBuf,
    pub example: EnvExample,
}

/// Finds and parses the example file for a checkout. See [`find`].
pub fn load(
    root: &Path,
    start: &Path,
    top: Option<&Path>,
    configured: Option<&Path>,
) -> Result<Option<Found>, RepoError> {
    let Some(path) = find(root, start, top, configured)? else {
        return Ok(None);
    };
    let example = read(&path)?;
    Ok(Some(Found { path, example }))
}

/// The example file for the checkout at `root` when working in `start`.
///
/// With `configured` (the project file's `env_example`, relative to `root`),
/// that file, which must exist. Otherwise the nearest `.env.example` in
/// `start` or a parent of it, stopping at `top` (the project's `path`,
/// relative to `root`), else at `root`; `None` if there is none. When
/// `start` is outside `top` (`--project` from another folder) only `top`
/// itself is looked in, and a `top` that does not exist has no file.
/// Returns the path with symlinks resolved.
pub fn find(
    root: &Path,
    start: &Path,
    top: Option<&Path>,
    configured: Option<&Path>,
) -> Result<Option<PathBuf>, RepoError> {
    let root = canonical(root)?;
    let mut start = canonical(start)?;
    if !start.starts_with(&root) {
        return Err(RepoError::OutsideCheckout { dir: start, root });
    }

    if let Some(rel) = configured {
        let lexically_inside = !rel.as_os_str().is_empty()
            && rel
                .components()
                .all(|c| matches!(c, Component::Normal(_) | Component::CurDir));
        if !lexically_inside {
            return Err(RepoError::OverrideNotRelative { path: rel.into() });
        }
        let path = root.join(rel);
        check_name(&path)?;
        let real = match fs::canonicalize(&path) {
            Ok(real) => real,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(RepoError::OverrideMissing { path });
            }
            Err(source) => return Err(RepoError::Io { path, source }),
        };
        return checked(&root, path, real).map(Some);
    }

    let stop = match top {
        Some(top) => match fs::canonicalize(root.join(top)) {
            Ok(stop) if stop.starts_with(&root) => stop,
            Ok(_) => return Err(RepoError::Escapes { path: top.into() }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(RepoError::Io {
                    path: top.into(),
                    source,
                });
            }
        },
        None => root.clone(),
    };
    if !start.starts_with(&stop) {
        start.clone_from(&stop);
    }
    for dir in start.ancestors() {
        let path = dir.join(ENV_EXAMPLE);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                let real = canonical(&path)?;
                return checked(&root, path, real).map(Some);
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(source) => return Err(RepoError::Io { path, source }),
        }
        if dir == stop {
            break;
        }
    }
    Ok(None)
}

/// A resolved path must stay in the checkout and keep an allowed name: a
/// `.env.example` symlink to `.env` is refused, not followed.
fn checked(root: &Path, path: PathBuf, real: PathBuf) -> Result<PathBuf, RepoError> {
    if !real.starts_with(root) {
        return Err(RepoError::Escapes { path });
    }
    check_name(&real)?;
    Ok(real)
}

/// Parses an example file. Refuses real env files by name, symlinks, and
/// anything that is not a regular file of at most [`MAX_SIZE`] bytes.
pub fn read(path: &Path) -> Result<EnvExample, RepoError> {
    check_name(path)?;
    let io_err = |source| RepoError::Io {
        path: path.into(),
        source,
    };
    // O_NOFOLLOW: `path` was resolved by `find`, so a symlink here means it
    // was swapped since. O_NONBLOCK: opening a FIFO must not hang.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| {
            if e.raw_os_error() == Some(libc::ELOOP) {
                RepoError::NotAFile { path: path.into() }
            } else {
                io_err(e)
            }
        })?;
    let meta = file.metadata().map_err(io_err)?;
    if !meta.is_file() {
        return Err(RepoError::NotAFile { path: path.into() });
    }
    let mut bytes = Vec::new();
    file.take(MAX_SIZE + 1)
        .read_to_end(&mut bytes)
        .map_err(io_err)?;
    if bytes.len() as u64 > MAX_SIZE {
        return Err(RepoError::TooLarge { path: path.into() });
    }
    let text = String::from_utf8(bytes).map_err(|_| RepoError::NotUtf8 { path: path.into() })?;
    Ok(env_example::parse(&text))
}

/// `.env` and `.env.*` are real env files unless the name ends in
/// `.example`. Compared case-insensitively, since macOS file systems usually
/// are.
pub fn is_real_env_file(name: &OsStr) -> bool {
    let name = name.as_bytes().to_ascii_lowercase();
    (name == b".env" || name.starts_with(b".env.")) && !name.ends_with(b".example")
}

/// A file that may hold an app's values under a name [`is_real_env_file`]
/// does not take: one ending in `.env`, such as `.dev.env` or
/// `production.env`, or Wrangler's `.dev.vars` and `.dev.vars.*`. Not an
/// example of one, which ends in `.example`, `.sample` or `.template`.
/// `onboard` imports such a file only when asked to with `--file`.
pub fn is_other_env_file(name: &OsStr) -> bool {
    if is_real_env_file(name) {
        return false;
    }
    let name = name.as_bytes().to_ascii_lowercase();
    let example = [&b".example"[..], b".sample", b".template"]
        .iter()
        .any(|end| name.ends_with(end));
    !example && (name.ends_with(b".env") || name == b".dev.vars" || name.starts_with(b".dev.vars."))
}

/// The first real env file in `dir`, by name, that has a key: `.env`,
/// `.env.local` and the like, not `.env.example`. Values are read only to
/// see that there are some, and are not kept.
pub fn env_file_with_values(dir: &Path) -> Option<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| is_real_env_file(OsStr::new(n)))
        .collect();
    names.sort();
    names.into_iter().find(|n| has_keys(&dir.join(n)))
}

fn has_keys(path: &Path) -> bool {
    // O_NONBLOCK: opening a FIFO must not hang.
    let Ok(file) = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
    else {
        return false;
    };
    if !file.metadata().is_ok_and(|m| m.is_file()) {
        return false;
    }
    let mut text = zeroize::Zeroizing::new(String::new());
    if file.take(MAX_SIZE).read_to_string(&mut text).is_err() {
        return false;
    }
    !env_example::parse_values(&text).0.is_empty()
}

fn check_name(path: &Path) -> Result<(), RepoError> {
    match path.file_name() {
        Some(name) if !is_real_env_file(name) => Ok(()),
        _ => Err(RepoError::RealEnvFile { path: path.into() }),
    }
}

fn canonical(path: &Path) -> Result<PathBuf, RepoError> {
    fs::canonicalize(path).map_err(|source| RepoError::Io {
        path: path.into(),
        source,
    })
}

#[cfg(test)]
mod tests;
