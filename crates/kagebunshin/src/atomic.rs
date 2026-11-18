//! Replacing a file so readers see either the old contents or the new, never a
//! mix, and never a file another user could read.

use std::fs::{self, File, OpenOptions};
use std::hash::{BuildHasher, RandomState};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// Temp files are named `.<name>.<random>.tmp`, so anything that scans a
/// directory can skip names starting with `.`.
pub const TEMP_SUFFIX: &str = ".tmp";

/// Replaces `path` with `contents`, mode 0600 (less if the umask says so).
///
/// Writes a temp file in the same directory, fsyncs it, renames it over
/// `path`, then fsyncs the directory. The parent directory must exist. If
/// `path` is a symlink, the link is replaced, not its target. On error the
/// temp file is removed and `path` is left as it was. Once the rename is
/// done the new contents are in place, so a failed directory fsync after
/// it is only logged, not an error.
pub fn write_private(path: &Path, contents: &[u8]) -> io::Result<()> {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;

    let (tmp, file) = create_temp(dir, &name.to_string_lossy())?;
    let result = finish(file, &tmp, path, dir, contents);
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn create_temp(dir: &Path, name: &str) -> io::Result<(PathBuf, File)> {
    let mut attempts = 0;
    loop {
        let random = RandomState::new().hash_one(attempts);
        let tmp = dir.join(format!(".{name}.{random:016x}{TEMP_SUFFIX}"));
        // create_new is O_CREAT|O_EXCL: it never follows or reuses an
        // existing file or symlink.
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
        {
            Ok(file) => return Ok((tmp, file)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists && attempts < 8 => attempts += 1,
            Err(e) => return Err(e),
        }
    }
}

fn finish(mut file: File, tmp: &Path, path: &Path, dir: &Path, contents: &[u8]) -> io::Result<()> {
    file.write_all(contents)?;
    file.sync_all()?;
    drop(file);
    fs::rename(tmp, path)?;
    if let Err(e) = File::open(dir).and_then(|d| d.sync_all()) {
        tracing::warn!(error = %e, dir = %dir.display(), "wrote a file, but could not fsync its directory");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

    use super::*;

    fn mode(p: &Path) -> u32 {
        fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777
    }

    fn entries(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn creates_a_private_file() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a.toml");
        write_private(&p, b"one").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"one");
        assert_eq!(mode(&p), 0o600);
        assert_eq!(entries(d.path()), ["a.toml"]);
    }

    #[test]
    fn replaces_contents_and_tightens_mode() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a.toml");
        fs::write(&p, b"old contents that are longer").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        write_private(&p, b"new").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"new");
        assert_eq!(mode(&p), 0o600);
        assert_eq!(entries(d.path()), ["a.toml"]);
    }

    #[test]
    fn replaces_a_symlink_not_its_target() {
        let d = tempfile::tempdir().unwrap();
        let target = d.path().join("target");
        fs::write(&target, b"target").unwrap();
        let link = d.path().join("link");
        symlink(&target, &link).unwrap();
        write_private(&link, b"new").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"target");
        assert!(fs::symlink_metadata(&link).unwrap().is_file());
        assert_eq!(fs::read(&link).unwrap(), b"new");
    }

    #[test]
    fn failure_leaves_the_old_file_and_no_temp() {
        let d = tempfile::tempdir().unwrap();
        // Renaming a file over a non-empty directory fails.
        let p = d.path().join("dir");
        fs::create_dir(&p).unwrap();
        fs::write(p.join("keep"), b"x").unwrap();
        assert!(write_private(&p, b"new").is_err());
        assert!(p.join("keep").exists());
        assert_eq!(entries(d.path()), ["dir"]);
    }

    #[test]
    fn missing_parent_is_an_error() {
        let d = tempfile::tempdir().unwrap();
        let err = write_private(&d.path().join("nope/a.toml"), b"x").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }
}
