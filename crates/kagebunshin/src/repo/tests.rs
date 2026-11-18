use std::os::unix::fs::{PermissionsExt, symlink};

use super::*;
use crate::test_support::{Canary, assert_no_canary};

/// A temp checkout. Real-looking env files hold a canary and are made
/// unreadable, so any attempt to open one fails the test (unless run as
/// root, where the canary check still applies).
struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    outside: PathBuf,
    canary: Canary,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        let root = base.join("repo");
        let outside = base.join("outside");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside).unwrap();
        Self {
            _dir: dir,
            root,
            outside,
            canary: Canary::new(),
        }
    }

    fn write(&self, rel: &str, text: &str) -> PathBuf {
        let p = self.root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, text).unwrap();
        p
    }

    fn dir(&self, rel: &str) -> PathBuf {
        let p = self.root.join(rel);
        fs::create_dir_all(&p).unwrap();
        p
    }

    /// A real env file with the canary as a value and as a key name.
    fn trap(&self, rel: &str) -> PathBuf {
        let c = self.canary.value();
        let p = self.write(rel, &format!("TRAP_KEY={c}\n{c}=1\n"));
        fs::set_permissions(&p, fs::Permissions::from_mode(0o000)).unwrap();
        p
    }

    fn keys(
        &self,
        start: &str,
        configured: Option<&str>,
    ) -> Result<Option<(PathBuf, Vec<String>)>, RepoError> {
        let found = load(
            &self.root,
            &self.dir(start),
            None,
            configured.map(Path::new),
        )?;
        Ok(found.map(|f| {
            let dbg = format!("{f:?}");
            assert_no_canary(&self.canary, &dbg);
            let keys = f.example.keys.iter().map(|k| k.to_string()).collect();
            (f.path, keys)
        }))
    }
}

#[test]
fn nearest_example_in_a_monorepo() {
    let f = Fixture::new();
    f.write(".env.example", "ROOT_KEY=\n");
    f.write("apps/web/.env.example", "WEB_KEY=\nexport WEB_OTHER=x\n");
    f.dir("apps/api/src");
    f.dir("apps/web/src/components");
    for trap in [
        ".env",
        ".env.local",
        "apps/web/.env",
        "apps/web/.env.development",
        "apps/api/.env",
    ] {
        f.trap(trap);
    }

    let (path, keys) = f.keys("apps/web/src/components", None).unwrap().unwrap();
    assert_eq!(path, f.root.join("apps/web/.env.example"));
    assert_eq!(keys, ["WEB_KEY", "WEB_OTHER"]);

    let (path, keys) = f.keys("apps/api/src", None).unwrap().unwrap();
    assert_eq!(path, f.root.join(".env.example"));
    assert_eq!(keys, ["ROOT_KEY"]);

    let (path, _) = f.keys("", None).unwrap().unwrap();
    assert_eq!(path, f.root.join(".env.example"));
}

#[test]
fn the_walk_stops_at_the_root() {
    let f = Fixture::new();
    // Above the checkout: never used.
    fs::write(f.root.parent().unwrap().join(".env.example"), "ABOVE=1\n").unwrap();
    f.trap(".env");
    assert_eq!(f.keys("src", None).unwrap(), None);
}

#[test]
fn the_walk_stops_at_the_projects_path() {
    let f = Fixture::new();
    f.write(".env.example", "ROOT_KEY=\n");
    f.write("apps/web/.env.example", "WEB_KEY=\n");
    f.dir("apps/api/src");
    f.dir("apps/web/src");
    f.trap("apps/api/.env");
    let keys = |start: &str, top: &str| {
        let found = load(&f.root, &f.dir(start), Some(Path::new(top)), None).unwrap();
        found.map(|f| {
            f.example
                .keys
                .iter()
                .map(|k| k.to_string())
                .collect::<Vec<_>>()
        })
    };
    // apps/api has none of its own, and the root's is another project's.
    assert_eq!(keys("apps/api/src", "apps/api"), None);
    assert_eq!(keys("apps/web/src", "apps/web").unwrap(), ["WEB_KEY"]);
    // From outside the project's folder (--project): only that folder.
    assert_eq!(keys("", "apps/web").unwrap(), ["WEB_KEY"]);
    assert_eq!(keys("apps/api/src", "apps/web").unwrap(), ["WEB_KEY"]);
    // A recorded folder that is gone has no file.
    assert_eq!(keys("", "apps/gone"), None);
}

#[test]
fn start_must_be_inside_the_checkout() {
    let f = Fixture::new();
    let err = find(&f.root, &f.outside, None, None).unwrap_err();
    assert!(matches!(err, RepoError::OutsideCheckout { .. }), "{err:?}");
}

#[test]
fn configured_path_wins() {
    let f = Fixture::new();
    f.write(".env.example", "ROOT_KEY=\n");
    f.write("config/example.env", "CONFIGURED=\n");
    f.write("config/.env.dev.example", "DEV_EXAMPLE=\n");
    f.trap("config/.env");

    for rel in ["config/example.env", "./config/example.env"] {
        let (path, keys) = f.keys("src", Some(rel)).unwrap().unwrap();
        assert_eq!(path, f.root.join("config/example.env"), "{rel}");
        assert_eq!(keys, ["CONFIGURED"]);
    }
    let (_, keys) = f
        .keys("", Some("config/.env.dev.example"))
        .unwrap()
        .unwrap();
    assert_eq!(keys, ["DEV_EXAMPLE"]);

    let err = f.keys("", Some("config/missing.example")).unwrap_err();
    assert!(matches!(err, RepoError::OverrideMissing { .. }), "{err:?}");
}

#[test]
fn configured_path_must_stay_inside() {
    let f = Fixture::new();
    fs::write(f.outside.join(".env.example"), "OUTSIDE=1\n").unwrap();
    let abs = f.outside.join(".env.example");

    for rel in [
        "../outside/.env.example",
        "a/../../outside/.env.example",
        "",
    ] {
        let err = f.keys("", Some(rel)).unwrap_err();
        assert!(
            matches!(err, RepoError::OverrideNotRelative { .. }),
            "{rel}: {err:?}"
        );
    }
    let err = f.keys("", Some(abs.to_str().unwrap())).unwrap_err();
    assert!(
        matches!(err, RepoError::OverrideNotRelative { .. }),
        "{err:?}"
    );

    // A symlink inside the checkout that points out of it.
    symlink(&abs, f.root.join("linked.example")).unwrap();
    let err = f.keys("", Some("linked.example")).unwrap_err();
    assert!(matches!(err, RepoError::Escapes { .. }), "{err:?}");
    // A symlinked directory is no different.
    symlink(&f.outside, f.root.join("out")).unwrap();
    let err = f.keys("", Some("out/.env.example")).unwrap_err();
    assert!(matches!(err, RepoError::Escapes { .. }), "{err:?}");
}

#[test]
fn real_env_files_are_refused_by_name() {
    let f = Fixture::new();
    for rel in [
        ".env",
        ".env.local",
        "apps/.env.production",
        ".ENV.STAGING",
        ".Env.Test",
        ".env.example.bak",
    ] {
        f.trap(rel);
        let err = f.keys("", Some(rel)).unwrap_err();
        assert!(
            matches!(err, RepoError::RealEnvFile { .. }),
            "{rel}: {err:?}"
        );
        assert_no_canary(&f.canary, &err.to_string());
    }

    // An allowed name that resolves to a real env file.
    symlink(f.root.join(".env"), f.root.join("innocent.example")).unwrap();
    let err = f.keys("", Some("innocent.example")).unwrap_err();
    assert!(matches!(err, RepoError::RealEnvFile { .. }), "{err:?}");

    // The same trick on a discovered .env.example is refused, not followed
    // and not skipped.
    symlink(f.root.join(".env.local"), f.dir("web").join(".env.example")).unwrap();
    let err = f.keys("web", None).unwrap_err();
    assert!(matches!(err, RepoError::RealEnvFile { .. }), "{err:?}");

    // read() checks names on its own too.
    let err = read(&f.root.join(".env")).unwrap_err();
    assert!(matches!(err, RepoError::RealEnvFile { .. }), "{err:?}");
}

#[test]
fn env_file_names() {
    for name in [
        ".env",
        ".env.local",
        ".env.",
        ".ENV",
        ".env.example.bak",
        ".env.prod",
    ] {
        assert!(is_real_env_file(OsStr::new(name)), "{name}");
    }
    for name in [
        ".env.example",
        ".env.prod.example",
        ".ENV.EXAMPLE",
        "env.example",
        "example.env",
        ".envrc",
        "env",
    ] {
        assert!(!is_real_env_file(OsStr::new(name)), "{name}");
    }
}

#[test]
fn other_env_file_names() {
    for name in [
        ".dev.env",
        "production.env",
        "example.env",
        "Cloudflare.ENV",
        ".dev.vars",
        ".dev.vars.staging",
    ] {
        assert!(is_other_env_file(OsStr::new(name)), "{name}");
    }
    for name in [
        // Real env files, which `onboard` takes by itself.
        ".env",
        ".env.local",
        ".env.example",
        "production.env.example",
        ".dev.env.sample",
        ".dev.vars.example",
        "env",
        ".envrc",
        "dev.vars",
        "environment.ts",
    ] {
        assert!(!is_other_env_file(OsStr::new(name)), "{name}");
    }
}

#[test]
fn read_refuses_odd_files() {
    let f = Fixture::new();

    // A FIFO must not block.
    let fifo = f.root.join(".env.example");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap();
    assert!(status.success());
    let err = f.keys("", None).unwrap_err();
    assert!(matches!(err, RepoError::NotAFile { .. }), "{err:?}");
    fs::remove_file(&fifo).unwrap();

    // A directory.
    fs::create_dir(&fifo).unwrap();
    assert!(matches!(f.keys("", None), Err(RepoError::NotAFile { .. })));
    fs::remove_dir(&fifo).unwrap();

    // read() itself refuses a symlink.
    f.write("real.example", "A=1\n");
    symlink(f.root.join("real.example"), f.root.join("link.example")).unwrap();
    assert!(matches!(
        read(&f.root.join("link.example")),
        Err(RepoError::NotAFile { .. })
    ));

    f.write("big.example", &"A=1\n".repeat((MAX_SIZE / 4 + 1) as usize));
    assert!(matches!(
        f.keys("", Some("big.example")),
        Err(RepoError::TooLarge { .. })
    ));

    let p = f.root.join("latin1.example");
    fs::write(&p, b"A=caf\xe9\n").unwrap();
    assert!(matches!(
        f.keys("", Some("latin1.example")),
        Err(RepoError::NotUtf8 { .. })
    ));
}

#[test]
fn parse_problems_come_back_with_the_keys() {
    let f = Fixture::new();
    f.write(
        ".env.example",
        "GOOD=1\nnot valid\nOPEN=\"never closed\nHIDDEN=1\n",
    );
    let found = load(&f.root, &f.root, None, None).unwrap().unwrap();
    let keys: Vec<_> = found.example.keys.iter().map(|k| k.as_str()).collect();
    assert_eq!(keys, ["GOOD", "OPEN"]);
    let lines: Vec<_> = found.example.bad_lines.iter().map(|b| b.line).collect();
    assert_eq!(lines, [2, 3]);
}
