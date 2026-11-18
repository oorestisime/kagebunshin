//! Asking git which checkout a directory is in and what its remotes are.
//!
//! git runs as a subprocess, so `url.<base>.insteadOf` rewrites, worktrees
//! and `GIT_DIR` behave exactly as they do for the user. Only read-only
//! commands are used: `rev-parse --show-toplevel`, `remote get-url` and
//! `ls-files`.

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::remote::RemoteId;

#[derive(Debug, thiserror::Error)]
pub enum GitError {
    #[error("cannot run git: {0}")]
    Spawn(io::Error),
    #[error("{} is not inside a git checkout", dir.display())]
    NotARepo { dir: PathBuf },
    #[error("git {command} failed: {message}")]
    Failed {
        command: &'static str,
        /// The first line of git's stderr, shortened.
        message: String,
    },
    #[error("git {command} printed output that is not UTF-8")]
    NotUtf8 { command: &'static str },
}

/// A checkout's top-level directory and its network remotes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkout {
    /// The worktree root, as `git rev-parse --show-toplevel` prints it.
    pub root: PathBuf,
    /// Every URL of every remote, normalized, without duplicates, in the
    /// order git lists them. Local-path remotes are left out.
    pub remotes: Vec<RemoteId>,
}

impl Checkout {
    /// Where `dir` is relative to the checkout root, for matching a
    /// project's `path`. Both are canonicalised first, so a symlinked
    /// working directory (macOS's `/var`, say) still lands inside the root
    /// git printed. `None` when `dir` is not inside it.
    pub fn subdir(&self, dir: &Path) -> Option<PathBuf> {
        let canon = |p: &Path| p.canonicalize().unwrap_or_else(|_| p.to_owned());
        canon(dir)
            .strip_prefix(canon(&self.root))
            .ok()
            .map(Path::to_owned)
    }
}

/// How to run git.
#[derive(Debug, Clone)]
pub struct Git {
    program: OsString,
    envs: Vec<(OsString, OsString)>,
}

impl Default for Git {
    fn default() -> Self {
        Self {
            program: "git".into(),
            envs: Vec::new(),
        }
    }
}

impl Git {
    /// Sets an extra environment variable for every git command, e.g. to
    /// isolate tests from the user's git config.
    pub fn env(mut self, key: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        self.envs.push((key.into(), value.into()));
        self
    }

    /// The checkout containing `dir`.
    pub fn checkout(&self, dir: &Path) -> Result<Checkout, GitError> {
        const TOPLEVEL: &str = "rev-parse --show-toplevel";
        let root = match self.run(dir, TOPLEVEL, &["rev-parse", "--show-toplevel"]) {
            Ok(out) => PathBuf::from(out.trim_end_matches('\n')),
            Err(GitError::Failed { message, .. }) if message.contains("not a git repository") => {
                return Err(GitError::NotARepo { dir: dir.into() });
            }
            Err(e) => return Err(e),
        };

        let mut remotes = Vec::new();
        for name in self.run(&root, "remote", &["remote"])?.lines() {
            let urls = self.run(
                &root,
                "remote get-url",
                &["remote", "get-url", "--all", "--", name],
            )?;
            for url in urls.lines() {
                // Local paths and anything else that is not a network
                // remote cannot identify a project.
                if let Ok(id) = RemoteId::from_url(url.trim())
                    && !remotes.contains(&id)
                {
                    remotes.push(id);
                }
            }
        }
        Ok(Checkout { root, remotes })
    }

    /// The files git tracks in the checkout at `root`, relative to it.
    pub fn tracked_files(&self, root: &Path) -> Result<Vec<PathBuf>, GitError> {
        let out = self.run(root, "ls-files", &["ls-files", "-z"])?;
        Ok(out
            .split('\0')
            .filter(|f| !f.is_empty())
            .map(PathBuf::from)
            .collect())
    }

    /// The files of the checkout at `root` that git tracks or would: not
    /// those it ignores. Relative to it.
    pub fn files(&self, root: &Path) -> Result<Vec<PathBuf>, GitError> {
        let args = ["ls-files", "-z", "-co", "--exclude-standard"];
        let out = self.run(root, "ls-files", &args)?;
        Ok(out
            .split('\0')
            .filter(|f| !f.is_empty())
            .map(PathBuf::from)
            .collect())
    }

    fn run(&self, dir: &Path, command: &'static str, args: &[&str]) -> Result<String, GitError> {
        let out = Command::new(&self.program)
            .arg("-C")
            .arg(dir)
            .args(args)
            .envs(self.envs.iter().map(|(k, v)| (k, v)))
            // Keep git's messages in English, so "not a git repository" can
            // be recognised.
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .output()
            .map_err(GitError::Spawn)?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let first = stderr.lines().next().unwrap_or("").trim();
            let mut message: String = first.chars().take(200).collect();
            if message.is_empty() {
                message = format!("exited with {}", out.status);
            }
            return Err(GitError::Failed { command, message });
        }
        String::from_utf8(out.stdout).map_err(|_| GitError::NotUtf8 { command })
    }
}
