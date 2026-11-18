//! Where the socket lives, and the checks that keep its directory private.

use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};

/// Overrides the socket path. Must be absolute.
pub const SOCKET_ENV: &str = "KAGEBUNSHIN_SOCKET";
pub const DIR_NAME: &str = "kagebunshin";
pub const SOCKET_FILE: &str = "kagebunshind.sock";
/// The app's two files beside the daemon's socket: the lock the one app
/// that runs holds, and the socket where it hears later launches.
pub const APP_LOCK_FILE: &str = "app.lock";
pub const APP_SOCKET_FILE: &str = "app.sock";

/// `sun_path` holds 108 bytes on Linux and 104 on macOS, including the NUL.
#[cfg(target_os = "linux")]
pub const MAX_SOCKET_PATH: usize = 107;
#[cfg(target_os = "macos")]
pub const MAX_SOCKET_PATH: usize = 103;

#[derive(Debug, thiserror::Error)]
pub enum PathError {
    #[error("socket path {path} is not absolute")]
    NotAbsolute { path: PathBuf },
    #[error(
        "socket path {path} is {len} bytes; the limit on this OS is {MAX_SOCKET_PATH}. \
         Set {SOCKET_ENV} to a shorter path"
    )]
    TooLong { path: PathBuf, len: usize },
}

#[derive(Debug, thiserror::Error)]
pub enum DirError {
    #[error("{path} is a symlink; refusing to use it for the socket")]
    Symlink { path: PathBuf },
    #[error("{path} is not a directory")]
    NotADirectory { path: PathBuf },
    #[error("{path} is owned by uid {owner}, not uid {expected}")]
    WrongOwner {
        path: PathBuf,
        owner: u32,
        expected: u32,
    },
    #[error("{path} has mode {mode:04o}; it must be 0700")]
    WrongMode { path: PathBuf, mode: u32 },
    #[error("cannot use {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
}

/// The default socket path for this user: `$KAGEBUNSHIN_SOCKET`, else
/// `$XDG_RUNTIME_DIR/kagebunshin/` on Linux or `$TMPDIR/kagebunshin/` on macOS,
/// else `/tmp/kagebunshin-<uid>/`.
pub fn default_socket_path() -> Result<PathBuf, PathError> {
    resolve_socket_path(|k| std::env::var_os(k), crate::sys::effective_uid())
}

pub fn resolve_socket_path(
    env: impl Fn(&str) -> Option<OsString>,
    uid: u32,
) -> Result<PathBuf, PathError> {
    let path = if let Some(p) = env(SOCKET_ENV).filter(|p| !p.is_empty()) {
        PathBuf::from(p)
    } else {
        #[cfg(target_os = "linux")]
        let base = "XDG_RUNTIME_DIR";
        #[cfg(target_os = "macos")]
        let base = "TMPDIR";
        match env(base).map(PathBuf::from).filter(|p| p.is_absolute()) {
            Some(base) => base.join(DIR_NAME).join(SOCKET_FILE),
            None => PathBuf::from(format!("/tmp/{DIR_NAME}-{uid}")).join(SOCKET_FILE),
        }
    };
    check_socket_path(&path)?;
    Ok(path)
}

pub fn check_socket_path(path: &Path) -> Result<(), PathError> {
    if !path.is_absolute() {
        return Err(PathError::NotAbsolute { path: path.into() });
    }
    let len = path.as_os_str().len();
    if len > MAX_SOCKET_PATH {
        return Err(PathError::TooLong {
            path: path.into(),
            len,
        });
    }
    Ok(())
}

/// The directory that holds the socket. A validated absolute socket path always
/// has a parent.
pub fn socket_dir(socket: &Path) -> &Path {
    socket.parent().unwrap_or(Path::new("/"))
}

/// Creates `dir` with mode 0700 if it is missing (its parent must exist), then
/// checks it with [`check_private_dir`].
pub fn ensure_private_dir(dir: &Path, uid: u32) -> Result<(), DirError> {
    match fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(source) => {
            return Err(DirError::Io {
                path: dir.into(),
                source,
            });
        }
    }
    check_private_dir(dir, uid)
}

/// The directory must be a real directory (not a symlink), owned by `uid`, with
/// mode exactly 0700. Anything else is refused rather than repaired: a wrong
/// mode or owner means someone else may already have been in there.
pub fn check_private_dir(dir: &Path, uid: u32) -> Result<(), DirError> {
    let meta = fs::symlink_metadata(dir).map_err(|source| DirError::Io {
        path: dir.into(),
        source,
    })?;
    if meta.file_type().is_symlink() {
        return Err(DirError::Symlink { path: dir.into() });
    }
    if !meta.is_dir() {
        return Err(DirError::NotADirectory { path: dir.into() });
    }
    if meta.uid() != uid {
        return Err(DirError::WrongOwner {
            path: dir.into(),
            owner: meta.uid(),
            expected: uid,
        });
    }
    let mode = meta.mode() & 0o7777;
    if mode != 0o700 {
        return Err(DirError::WrongMode {
            path: dir.into(),
            mode,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::os::unix::fs::PermissionsExt;

    fn env(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
        let map: HashMap<String, OsString> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), OsString::from(v)))
            .collect();
        move |k| map.get(k).cloned()
    }

    #[test]
    fn socket_path_resolution() {
        #[cfg(target_os = "linux")]
        let base = "XDG_RUNTIME_DIR";
        #[cfg(target_os = "macos")]
        let base = "TMPDIR";

        let p = resolve_socket_path(env(&[(base, "/run/user/1000")]), 1000).unwrap();
        assert_eq!(p, Path::new("/run/user/1000/kagebunshin/kagebunshind.sock"));

        let p = resolve_socket_path(env(&[]), 1000).unwrap();
        assert_eq!(p, Path::new("/tmp/kagebunshin-1000/kagebunshind.sock"));

        // A relative base directory is ignored, not trusted.
        let p = resolve_socket_path(env(&[(base, "relative")]), 7).unwrap();
        assert_eq!(p, Path::new("/tmp/kagebunshin-7/kagebunshind.sock"));

        let p = resolve_socket_path(env(&[(SOCKET_ENV, "/x/y.sock"), (base, "/run")]), 1).unwrap();
        assert_eq!(p, Path::new("/x/y.sock"));

        assert!(matches!(
            resolve_socket_path(env(&[(SOCKET_ENV, "rel.sock")]), 1),
            Err(PathError::NotAbsolute { .. })
        ));
    }

    #[test]
    fn socket_path_length_limit() {
        let ok = format!("/{}", "a".repeat(MAX_SOCKET_PATH - 1));
        assert!(check_socket_path(Path::new(&ok)).is_ok());
        let long = format!("/{}", "a".repeat(MAX_SOCKET_PATH));
        let err = check_socket_path(Path::new(&long)).unwrap_err();
        assert!(err.to_string().contains(SOCKET_ENV), "{err}");
    }

    #[test]
    fn creates_a_0700_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("kb");
        let uid = crate::sys::effective_uid();
        ensure_private_dir(&dir, uid).unwrap();
        let mode = fs::metadata(&dir).unwrap().mode() & 0o7777;
        assert_eq!(mode, 0o700);
        // Idempotent.
        ensure_private_dir(&dir, uid).unwrap();
    }

    #[test]
    fn refuses_unsafe_directories() {
        let tmp = tempfile::tempdir().unwrap();
        let uid = crate::sys::effective_uid();

        let open = tmp.path().join("open");
        fs::create_dir(&open).unwrap();
        fs::set_permissions(&open, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            ensure_private_dir(&open, uid),
            Err(DirError::WrongMode { mode: 0o755, .. })
        ));

        let real = tmp.path().join("real");
        ensure_private_dir(&real, uid).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(matches!(
            ensure_private_dir(&link, uid),
            Err(DirError::Symlink { .. })
        ));

        let file = tmp.path().join("file");
        fs::write(&file, b"").unwrap();
        assert!(matches!(
            check_private_dir(&file, uid),
            Err(DirError::NotADirectory { .. })
        ));

        // We cannot chown without root, so check the owner rule from the other side.
        assert!(matches!(
            check_private_dir(&real, uid.wrapping_add(1)),
            Err(DirError::WrongOwner { .. })
        ));

        // A missing parent is an error, not a recursive create.
        assert!(matches!(
            ensure_private_dir(&tmp.path().join("no/such"), uid),
            Err(DirError::Io { .. })
        ));
    }
}
