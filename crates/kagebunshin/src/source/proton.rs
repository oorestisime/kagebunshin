//! The `proton` provider: Proton Pass "API key" items, read through Proton's
//! own `pass-cli`, which is never bundled (`kagebunshin connect proton`
//! offers Proton's installer).
//!
//! An API key item is a `custom` item with a field named `API key`, which
//! holds the environment variable name, and one named `Secret`, which holds
//! the value (both names matched without regard to case). The title is free
//! text. Every other item, and a custom item without both fields, is
//! ignored. A key's name is `<vault>/<KEY>`: a project file selects one with
//! `secret = "widget/API_TOKEN"`, or a vault's keys with `prefix =
//! "widget/"`. Keys in the `global` vault belong to no project, so a prefix
//! never picks them up: each is added with its own `secret`. A key's stable
//! id, what its origin records and a sensitive mark is keyed by, is
//! `<share id>/<item id>`.
//!
//! `pass-cli` runs with its session in kagebunshin's own data directory
//! (`$XDG_DATA_HOME/kagebunshin/proton`, else
//! `~/.local/share/kagebunshin/proton`), never the user's own login. It logs
//! in with the personal access token `connect proton` saved in the local
//! store, passed only in its environment, never as an argument. Sessions
//! last two hours: a call that fails while the session no longer works logs
//! in again and is retried once. Only the daemon runs `pass-cli`, one call
//! at a time. `connect proton` logs in with a new token in a staging
//! directory beside the session (`proton.staging`), and swaps it in only
//! once the token is saved, so a refused token never touches the session
//! in use.
//!
//! The variable name lives inside the item, so learning a key's name reads
//! the whole item, value included. [`ProtonSource::names`] keeps those
//! values, as [`SecretValue`]s, only until the resolver has checked the
//! names and asks for them; nothing else sees them.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::Value;
use zeroize::Zeroizing;

use super::{Backend, Entry, Health, Listed, ProviderStatus, Source, SourceError};
use crate::config::{Select, SourceSpec};
use crate::secret::SecretValue;
use crate::store::Store;
use crate::types::{KeyName, Origin, Provider};

/// Runs this `pass-cli` instead of the one on `PATH`.
pub const PASS_CLI_ENV: &str = "KAGEBUNSHIN_PASS_CLI";
/// `connect proton` reads the token from here before stdin or the terminal.
pub const TOKEN_ENV: &str = "KAGEBUNSHIN_PROTON_TOKEN";
/// How `pass-cli` takes a personal access token.
const PAT_ENV: &str = "PROTON_PASS_PERSONAL_ACCESS_TOKEN";
/// Where `pass-cli` keeps its session key. Passed through when set; `fs`
/// otherwise, so a daemon without a desktop keyring can still log in.
const KEY_PROVIDER_ENV: &str = "PROTON_PASS_KEY_PROVIDER";
/// Keys in this vault are added to a project one at a time.
pub const GLOBAL_SCOPE: &str = "global/";
/// Proton's official installer, which `connect proton` offers to run.
pub const INSTALLER: &str = "curl -fsSL https://proton.me/download/pass-cli/install.sh | bash";

const ITEM_TYPE: &str = "custom";
const NAME_FIELD: &str = "api key";
const VALUE_FIELD: &str = "secret";
const CONNECT_HINT: &str = "run `kagebunshin connect proton`";
/// Why `connect proton` failed when `pass-cli` would not log in.
pub const REFUSED: &str = "Proton refused the token";
/// An empty file in every session directory kagebunshin makes, by which
/// `uninstall --purge` knows the directory is its own.
pub const SESSION_MARKER: &str = ".kagebunshin-session";

/// One `pass-cli` call at a time, so two fetches never log in at once, and
/// `connect proton` never stages or swaps a session under a fetch. Only the
/// daemon runs `pass-cli`, so this lock in its process covers every call.
static CALLS: Mutex<()> = Mutex::new(());

/// How to run `pass-cli`: which binary, with which session directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassCli {
    pub bin: PathBuf,
    /// `None` when neither `XDG_DATA_HOME` nor `HOME` is set.
    pub session_dir: Option<PathBuf>,
    pub key_provider: String,
}

impl PassCli {
    /// From `KAGEBUNSHIN_PASS_CLI`, `XDG_DATA_HOME`, `HOME` and
    /// `PROTON_PASS_KEY_PROVIDER`.
    pub fn from_env() -> Self {
        let var = |k| std::env::var_os(k).filter(|v| !v.is_empty());
        let data = var("XDG_DATA_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .or_else(|| var("HOME").map(|h| PathBuf::from(h).join(".local/share")));
        Self {
            bin: var(PASS_CLI_ENV).map_or_else(|| "pass-cli".into(), PathBuf::from),
            session_dir: data.map(|d| d.join("kagebunshin/proton")),
            key_provider: var(KEY_PROVIDER_ENV)
                .and_then(|v| v.into_string().ok())
                .unwrap_or_else(|| "fs".into()),
        }
    }

    /// The binary that would run, if it is there.
    pub fn installed(&self) -> Option<PathBuf> {
        let runnable = |p: &Path| p.is_file().then(|| p.to_owned());
        if self.bin.components().count() > 1 {
            return runnable(&self.bin);
        }
        std::env::split_paths(&std::env::var_os("PATH")?)
            .find_map(|dir| runnable(&dir.join(&self.bin)))
    }

    fn command(&self, dir: &Path, args: &[&str]) -> Command {
        let mut c = Command::new(&self.bin);
        c.args(args)
            .env_remove(PAT_ENV)
            .env_remove(TOKEN_ENV)
            .env("PROTON_PASS_SESSION_DIR", dir)
            .env(KEY_PROVIDER_ENV, &self.key_provider)
            .env(
                "PROTON_PASS_AGENT_REASON",
                "kagebunshin reads API keys for a project environment",
            )
            .env("NO_COLOR", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        c
    }

    fn live(&self) -> Result<&Path, SourceError> {
        self.session_dir.as_deref().ok_or_else(|| {
            provider("cannot place the pass-cli session: neither XDG_DATA_HOME nor HOME is set")
        })
    }

    /// The session directory, created 0700 if it is missing.
    fn dir(&self) -> Result<&Path, SourceError> {
        let dir = self.live()?;
        make_dir(dir)?;
        Ok(dir)
    }

    /// Runs one call in the session; its stdout, or why it failed.
    fn run(
        &self,
        args: &[&str],
        token: Option<&SecretValue>,
    ) -> Result<Zeroizing<Vec<u8>>, Failed> {
        let dir = self.dir().map_err(Failed::Setup)?;
        self.run_in(dir, args, token)
    }

    /// Runs one call with its session in `dir`. `token` is set only for
    /// `login`, and only in the environment.
    fn run_in(
        &self,
        dir: &Path,
        args: &[&str],
        token: Option<&SecretValue>,
    ) -> Result<Zeroizing<Vec<u8>>, Failed> {
        let mut cmd = self.command(dir, args);
        if let Some(t) = token {
            cmd.env(PAT_ENV, t.expose());
        }
        let out = cmd.output().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Failed::Missing
            } else {
                Failed::Setup(provider(format!("cannot run {}: {e}", self.bin.display())))
            }
        })?;
        let stdout = Zeroizing::new(out.stdout);
        if out.status.success() {
            return Ok(stdout);
        }
        Err(Failed::Exit {
            message: format!(
                "pass-cli {} failed ({}): {}",
                args.first().unwrap_or(&""),
                out.status,
                redact(&String::from_utf8_lossy(&out.stderr), token)
            ),
        })
    }

    /// Logs in afresh with `token`.
    fn login(&self, token: &SecretValue) -> Result<(), SourceError> {
        let _ = self.run(&["logout", "--force"], None);
        self.run(&["login"], Some(token))
            .map(drop)
            .map_err(|f| match f {
                Failed::Exit { message } => {
                    tracing::warn!(%message, "pass-cli login failed");
                    SourceError::NeedsLogin {
                        what: "proton".into(),
                        hint: "Proton refused the saved token (expired or revoked?): create a new \
                           personal access token and run `kagebunshin connect proton`"
                            .into(),
                    }
                }
                other => other.into(),
            })
    }

    /// Runs `args` in the current session, logging in again once if the
    /// call fails while the session does not work.
    pub fn call(
        &self,
        token: &SecretValue,
        args: &[&str],
    ) -> Result<Zeroizing<Vec<u8>>, SourceError> {
        let _one = CALLS.lock().unwrap_or_else(|e| e.into_inner());
        match self.run(args, None) {
            Ok(out) => Ok(out),
            Err(Failed::Exit { message }) => {
                if self.run(&["info"], None).is_ok() {
                    return Err(provider(message));
                }
                self.login(token)?;
                self.run(args, None).map_err(SourceError::from)
            }
            Err(other) => Err(other.into()),
        }
    }

    /// Logs in with `token` in a fresh staging directory beside the
    /// session (`proton.staging`) and counts the vaults it reads: what
    /// `connect proton` checks before it saves the token. The session is
    /// not touched; [`Staged::swap`] makes the staging one the session.
    /// Not safe to run twice at once: the daemon runs one at a time.
    pub fn stage(&self, token: &SecretValue) -> Result<Staged, SourceError> {
        let _one = CALLS.lock().unwrap_or_else(|e| e.into_inner());
        let live = self.live()?.to_owned();
        let staged = Staged {
            dir: beside(&live, "staging"),
            live,
            vaults: 0,
            swapped: false,
        };
        // What a failed connect left: a staging session is never in use.
        // An old one with no live one is the session of the saved token,
        // so it goes back. With both, the live one stays and the old one
        // goes: the token is saved only once its session is live, and a
        // failed save puts the old session back, so a live session beside
        // an old one is the saved token's, or else one of the new token's
        // that could be neither moved out nor removed. The live session is
        // never removed here: it is the only one known to work.
        remove_dir(&staged.dir)?;
        let old = beside(&staged.live, "old");
        if old.symlink_metadata().is_ok() {
            if staged.live.symlink_metadata().is_err() {
                rename(&old, &staged.live).map_err(|e| {
                    provider(format!(
                        "cannot put the previous session {} back: {e}",
                        old.display()
                    ))
                })?;
            } else {
                remove_dir(&old)?;
            }
        }
        make_dir(&staged.dir)?;
        self.run_in(&staged.dir, &["login"], Some(token))
            .map_err(|f| match f {
                Failed::Exit { message } => {
                    tracing::warn!(%message, "pass-cli login with a new token failed");
                    SourceError::NeedsLogin {
                        what: "proton".into(),
                        hint: "check the token, or create a new personal access token in \
                               Proton Pass and run `kagebunshin connect proton` again"
                            .into(),
                    }
                }
                other => other.into(),
            })?;
        let out = self.run_in(&staged.dir, &["vault", "list", "--output", "json"], None)?;
        let mut staged = staged;
        staged.vaults = vaults(&out)?.len();
        Ok(staged)
    }
}

/// A session logged in with a new token, beside the live one; see
/// [`PassCli::stage`]. Dropped without [`Staged::swap`], it is removed and
/// the live session stays as it was.
#[derive(Debug)]
pub struct Staged {
    live: PathBuf,
    dir: PathBuf,
    /// How many vaults the new token reads.
    pub vaults: usize,
    swapped: bool,
}

impl Staged {
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Makes the staging session the live one, then runs `save` (which
    /// saves the token), with no `pass-cli` call in between: the live
    /// session is moved aside (`proton.old`), the staging one moved in.
    /// Only once `save` succeeds is the old one removed. If a move fails
    /// (the outer error) or `save` does (the inner one), the old session
    /// is put back, so the live session always matches the saved token.
    /// If even that fails, the old session stays in `proton.old`, and the
    /// next [`PassCli::stage`] sorts it out.
    pub fn swap_then<T, E>(
        mut self,
        save: impl FnOnce() -> Result<T, E>,
    ) -> Result<Result<T, E>, SourceError> {
        let _one = CALLS.lock().unwrap_or_else(|e| e.into_inner());
        let old = beside(&self.live, "old");
        let had_live = match rename(&self.live, &old) {
            Ok(()) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => {
                return Err(provider(format!(
                    "cannot move the session {} aside: {e}",
                    self.live.display()
                )));
            }
        };
        let restore = |what: String| -> SourceError {
            if !had_live {
                return provider(what);
            }
            match rename(&old, &self.live) {
                Ok(()) => provider(format!("{what}; the previous session is back in place")),
                Err(e) => provider(format!(
                    "{what}, and the previous session cannot be put back ({e}): it is in {}",
                    old.display()
                )),
            }
        };
        if let Err(e) = rename(&self.dir, &self.live) {
            return Err(restore(format!("cannot move the new session in: {e}")));
        }
        match save() {
            Ok(saved) => {
                // The staging directory is now the live one.
                self.swapped = true;
                if had_live && let Err(e) = remove_dir(&old) {
                    tracing::warn!(error = %e, "could not remove the previous pass-cli session");
                }
                Ok(Ok(saved))
            }
            Err(e) => {
                // The new session back to staging, which drop removes, or
                // else removed, so the old one can go back.
                if rename(&self.live, &self.dir).is_err()
                    && let Err(gone) = remove_dir(&self.live)
                {
                    self.swapped = true;
                    tracing::warn!(error = %gone, "could not take the new pass-cli session out; the previous one is left aside");
                    return Ok(Err(e));
                }
                let back = restore("the token was not saved".into());
                tracing::warn!(error = %back, "rolled back the pass-cli session swap");
                Ok(Err(e))
            }
        }
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        if !self.swapped
            && let Err(e) = remove_dir(&self.dir)
        {
            // The next `stage` removes it first.
            tracing::warn!(error = %e, "could not remove the staging pass-cli session");
        }
    }
}

/// `std::fs::rename`, which tests can make fail once per destination.
fn rename(from: &Path, to: &Path) -> std::io::Result<()> {
    #[cfg(test)]
    {
        let mut faults = faults::RENAMES.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(at) = faults.iter().position(|p| p == to) {
            faults.remove(at);
            return Err(std::io::Error::other("injected fault"));
        }
    }
    std::fs::rename(from, to)
}

#[cfg(test)]
pub(crate) mod faults {
    use std::path::PathBuf;
    use std::sync::Mutex;

    /// Each entry fails one rename onto that path.
    pub static RENAMES: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

    pub fn fail_rename_onto(to: impl Into<PathBuf>) {
        RENAMES.lock().unwrap().push(to.into());
    }
}

/// `<session>.<what>`, beside the session directory.
fn beside(live: &Path, what: &str) -> PathBuf {
    let mut name = live.as_os_str().to_owned();
    name.push(".");
    name.push(what);
    name.into()
}

/// Creates the session directory `dir` 0700 if it is missing, and only
/// then marks it as kagebunshin's: a directory already there is left
/// unmarked, whatever is in it.
fn make_dir(dir: &Path) -> Result<(), SourceError> {
    use std::os::unix::fs::DirBuilderExt;
    let err = |e: std::io::Error| provider(format!("cannot create {}: {e}", dir.display()));
    if let Some(parent) = dir.parent() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(err)?;
    }
    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        // create_new is O_CREAT|O_EXCL, which never follows a symlink.
        Ok(()) => std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.join(SESSION_MARKER))
            .map(drop)
            .map_err(err),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(err(e)),
    }
}

/// Removes `dir` and everything in it, if it is there.
fn remove_dir(dir: &Path) -> Result<(), SourceError> {
    match std::fs::remove_dir_all(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(provider(format!("cannot remove {}: {e}", dir.display()))),
    }
}

/// Midnight UTC of a `YYYY-MM-DD` date, in Unix seconds.
pub fn parse_date(s: &str) -> Option<u64> {
    let mut parts = s.splitn(3, '-');
    let (y, m, d) = (parts.next()?, parts.next()?, parts.next()?);
    if (y.len(), m.len(), d.len()) != (4, 2, 2) {
        return None;
    }
    let (y, m, d): (i64, u32, u32) = (y.parse().ok()?, m.parse().ok()?, d.parse().ok()?);
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let days_in = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1..=12).contains(&m) || d == 0 || d > days_in[m as usize - 1] {
        return None;
    }
    // Days from 1970-01-01, after Howard Hinnant's days_from_civil.
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (i64::from(m) + 9) % 12;
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86_400).ok()
}

/// The `YYYY-MM-DD` (UTC) of Unix seconds `secs`.
pub fn format_date(secs: u64) -> String {
    // Howard Hinnant's civil_from_days.
    let z = (secs / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

enum Failed {
    Missing,
    Setup(SourceError),
    Exit { message: String },
}

impl From<Failed> for SourceError {
    fn from(f: Failed) -> Self {
        match f {
            Failed::Missing => SourceError::Provider {
                what: "proton".into(),
                message: "pass-cli is not installed; run `kagebunshin connect proton`".into(),
            },
            Failed::Setup(e) => e,
            Failed::Exit { message } => provider(message),
        }
    }
}

fn provider(message: impl Into<String>) -> SourceError {
    SourceError::Provider {
        what: "proton".into(),
        message: message.into(),
    }
}

/// `pass-cli`'s stderr for an error message: one line, short, with the
/// token and anything that looks like one taken out.
fn redact(stderr: &str, token: Option<&SecretValue>) -> String {
    let mut s = stderr.split_whitespace().collect::<Vec<_>>().join(" ");
    if let Some(t) = token.filter(|t| !t.is_empty()) {
        s = s.replace(t.expose(), "<token>");
    }
    let s: Vec<&str> = s
        .split(' ')
        .map(|w| if w.contains("pst_") { "<token>" } else { w })
        .collect();
    let s = s.join(" ");
    match s.char_indices().nth(300) {
        Some((i, _)) => format!("{}…", &s[..i]),
        None => s,
    }
}

fn json(out: &[u8], what: &str) -> Result<Value, SourceError> {
    serde_json::from_slice(out)
        .map_err(|e| provider(format!("pass-cli {what}: unexpected output: {e}")))
}

/// `(name, share id)` of every vault.
fn vaults(out: &[u8]) -> Result<Vec<(String, String)>, SourceError> {
    let v = json(out, "vault list")?;
    let list = v.get("vaults").unwrap_or(&v);
    let Some(list) = list.as_array() else {
        return Err(provider(
            "pass-cli vault list: unexpected output: no list of vaults",
        ));
    };
    Ok(list
        .iter()
        .filter_map(|v| {
            Some((
                str_at(v, "name")?.to_owned(),
                str_at(v, "share_id")?.to_owned(),
            ))
        })
        .collect())
}

fn str_at<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key)?.as_str()
}

/// Every `(field name, text)` in an item, wherever it sits: custom
/// sections, extra fields.
fn fields<'a>(v: &'a Value, out: &mut Vec<(&'a str, &'a str)>) {
    match v {
        Value::Object(map) => {
            let name = map.get("name").or(map.get("title")).and_then(Value::as_str);
            let text = map
                .get("content")
                .and_then(|c| c.get("Text").or(c.get("Hidden")))
                .or(map.get("value"))
                .and_then(Value::as_str);
            if let (Some(name), Some(text)) = (name, text) {
                out.push((name, text));
            }
            map.values().for_each(|v| fields(v, out));
        }
        Value::Array(a) => a.iter().for_each(|v| fields(v, out)),
        _ => {}
    }
}

/// One API key item.
pub struct Key {
    /// `<vault>/<KEY>`.
    pub name: String,
    /// The item's title, free text.
    pub title: Option<String>,
    pub key: KeyName,
    pub origin: Origin,
    value: SecretValue,
}

/// Every API key item in every vault the token can read, by name.
fn index(cli: &PassCli, token: &SecretValue) -> Result<Vec<Key>, SourceError> {
    let mut keys = Vec::new();
    let out = cli.call(token, &["vault", "list", "--output", "json"])?;
    for (vault, share) in vaults(&out)? {
        let out = cli.call(
            token,
            &[
                "item",
                "list",
                "--share-id",
                &share,
                "--filter-type",
                ITEM_TYPE,
                "--output",
                "json",
            ],
        )?;
        let list = json(&out, "item list")?;
        let items = list
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for item in &items {
            let (Some(id), Some(kind)) = (str_at(item, "id"), str_at(item, "item_type")) else {
                continue;
            };
            let trashed =
                str_at(item, "state").is_some_and(|s| s.to_ascii_lowercase().contains("trash"));
            if !kind.eq_ignore_ascii_case(ITEM_TYPE) || trashed {
                continue;
            }
            let share = str_at(item, "share_id").unwrap_or(&share);
            let out = cli.call(
                token,
                &[
                    "item",
                    "view",
                    "--share-id",
                    share,
                    "--item-id",
                    id,
                    "--output",
                    "json",
                ],
            )?;
            let view = json(&out, "item view")?;
            let mut found = Vec::new();
            fields(&view, &mut found);
            let field = |want: &str| {
                found
                    .iter()
                    .find(|(n, _)| n.trim().eq_ignore_ascii_case(want))
                    .map(|(_, t)| *t)
            };
            let (Some(name), Some(value)) = (field(NAME_FIELD), field(VALUE_FIELD)) else {
                continue;
            };
            let origin = Origin::new(Provider::Proton, format!("{share}/{id}"));
            let Ok(key) = name.trim().parse::<KeyName>() else {
                // The field itself is not shown, in case a value was pasted
                // where the name belongs.
                tracing::warn!(item = %origin, "skipping a Proton API key whose name is not a valid environment variable name");
                continue;
            };
            let name = format!("{vault}/{key}");
            keys.push(Key {
                // Its ids say which item it is; people see its name.
                origin: origin.named(&name),
                name,
                title: str_at(item, "title").map(str::to_owned),
                key,
                value: SecretValue::new(value.to_owned()),
            });
        }
    }
    keys.sort_by(|a, b| (&a.name, &a.origin).cmp(&(&b.name, &b.origin)));
    Ok(keys)
}

/// The saved token, or why there is none.
fn token(store: Option<&Store>) -> Result<&SecretValue, SourceError> {
    let store = store.ok_or_else(|| SourceError::NoStore {
        what: "proton".into(),
    })?;
    store
        .proton_token()
        .map(|t| &t.token)
        .ok_or_else(|| SourceError::NeedsLogin {
            what: "proton".into(),
            hint: CONNECT_HINT.into(),
        })
}

/// Runs `f` with the token off the async threads; `pass-cli` blocks.
async fn with_token<T: Send + 'static>(
    cli: &PassCli,
    store: Option<&Arc<Store>>,
    f: impl FnOnce(&PassCli, &SecretValue) -> Result<T, SourceError> + Send + 'static,
) -> Result<T, SourceError> {
    let (cli, store) = (cli.clone(), store.cloned());
    tokio::task::spawn_blocking(move || f(&cli, token(store.as_deref())?))
        .await
        .map_err(|e| provider(format!("pass-cli call stopped: {e}")))?
}

/// Every API key the token reads, read once and shared by the sources of
/// one backend. Reading them takes a `pass-cli` call for each vault and
/// each item, so an environment with several Proton sources reads them
/// once, not once for each source.
type Account = Arc<tokio::sync::OnceCell<Arc<Vec<Key>>>>;

pub struct ProtonBackend {
    cli: PassCli,
    /// The local store as the daemon decrypted it, holding the token.
    store: Option<Arc<Store>>,
    /// What its sources read. A backend is made for one request, so this
    /// is never older than the request it serves.
    account: Account,
}

impl ProtonBackend {
    pub fn new(cli: PassCli, store: Option<Arc<Store>>) -> Self {
        Self {
            cli,
            store,
            account: Account::default(),
        }
    }
}

#[async_trait]
impl Backend for ProtonBackend {
    fn provider(&self) -> Provider {
        Provider::Proton
    }

    async fn list(&self, prefix: &str) -> Result<Vec<Listed>, SourceError> {
        let keys = with_token(&self.cli, self.store.as_ref(), index).await?;
        Ok(keys
            .into_iter()
            .filter(|k| k.name.starts_with(prefix))
            .map(|k| Listed {
                id: k.origin,
                name: k.name,
                title: k.title,
                keys: vec![k.key],
                plain: false,
                unread: None,
            })
            .collect())
    }

    async fn status(&self) -> ProviderStatus {
        let expires = self
            .store
            .as_deref()
            .and_then(Store::proton_token)
            .and_then(|t| t.expires);
        let health = match with_token(&self.cli, self.store.as_ref(), |cli, t| {
            cli.call(t, &["info"])
        })
        .await
        {
            Ok(_) => Health::Ok,
            Err(SourceError::NoStore { .. }) => Health::NotConnected {
                hint: "create the local store with `kagebunshin store init`, then run \
                       `kagebunshin connect proton`"
                    .into(),
            },
            Err(SourceError::NeedsLogin { hint, .. }) if hint == CONNECT_HINT => {
                Health::NotConnected { hint }
            }
            Err(SourceError::NeedsLogin { hint, .. }) => Health::NeedsLogin { hint },
            Err(e) => Health::Failed {
                message: e.to_string(),
            },
        };
        ProviderStatus {
            provider: Provider::Proton,
            detail: "personal access token".into(),
            health,
            expires,
        }
    }

    fn source(&self, spec: &SourceSpec) -> Box<dyn Source> {
        Box::new(ProtonSource {
            cli: self.cli.clone(),
            store: self.store.clone(),
            select: spec.select.clone(),
            optional: spec.optional,
            account: self.account.clone(),
        })
    }
}

pub struct ProtonSource {
    cli: PassCli,
    store: Option<Arc<Store>>,
    select: Select,
    optional: bool,
    /// What its backend's sources read; see [`Account`].
    account: Account,
}

impl ProtonSource {
    /// The account's API keys: read now if no source of this backend has
    /// yet. A read that fails is not kept, so the next source tries again.
    async fn keys(&self) -> Result<Arc<Vec<Key>>, SourceError> {
        self.account
            .get_or_try_init(|| async {
                with_token(&self.cli, self.store.as_ref(), index)
                    .await
                    .map(Arc::new)
            })
            .await
            .cloned()
    }

    fn picks(&self, keys: &[Key]) -> Result<Vec<String>, SourceError> {
        let has = |n: &str| keys.iter().any(|k| k.name == n);
        let named = |names: Vec<&String>| {
            names
                .into_iter()
                .map(|n| {
                    if has(n) {
                        Ok(n.clone())
                    } else {
                        Err(SourceError::NotFound { name: n.clone() })
                    }
                })
                .collect()
        };
        match &self.select {
            Select::Secret { name, .. } => named(vec![name]),
            Select::Secrets(names) => named(names.iter().collect()),
            Select::Prefix(p) => {
                let mut found: Vec<String> = keys
                    .iter()
                    .filter(|k| k.name.starts_with(p.as_str()) && !k.name.starts_with(GLOBAL_SCOPE))
                    .map(|k| k.name.clone())
                    .collect();
                found.dedup();
                if found.is_empty() && !self.optional {
                    return Err(SourceError::NoMatch {
                        what: self.describe(),
                    });
                }
                Ok(found)
            }
        }
    }
}

#[async_trait]
impl Source for ProtonSource {
    fn describe(&self) -> String {
        let (kind, what) = match &self.select {
            Select::Secret { name, .. } => ("secret", name.clone()),
            Select::Secrets(names) => ("secrets", names.join(",")),
            Select::Prefix(p) => ("prefix", p.clone()),
        };
        format!("proton {kind} {what}")
    }

    async fn names(&self) -> Result<Vec<String>, SourceError> {
        self.picks(&self.keys().await?)
    }

    async fn fetch(&self, names: &[String]) -> Result<Vec<Entry>, SourceError> {
        let keys = self.keys().await?;
        let rename = match &self.select {
            Select::Secret { key, .. } => key.clone(),
            _ => None,
        };
        let mut out = Vec::new();
        for name in names {
            let mut any = false;
            for k in keys.iter().filter(|k| &k.name == name) {
                any = true;
                out.push(Entry {
                    key: rename.clone().unwrap_or_else(|| k.key.clone()),
                    value: SecretValue::new(k.value.expose().to_owned()),
                    origin: k.origin.clone(),
                });
            }
            if !any {
                return Err(SourceError::NotFound { name: name.clone() });
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::ReadAll;
    use crate::store::ProtonToken;
    use crate::test_support::{Canary, FakePassCli, assert_no_canary};

    fn store(token: &str) -> Arc<Store> {
        let mut st = Store::default();
        st.set_proton_token(ProtonToken {
            token: SecretValue::new(token.into()),
            expires: Some(1_000),
        });
        Arc::new(st)
    }

    fn spec(select: Select) -> SourceSpec {
        SourceSpec::new(Provider::Proton, select, false)
    }

    fn secret(name: &str) -> Select {
        Select::Secret {
            name: name.into(),
            key: None,
        }
    }

    /// Vaults `widget` and `global`, with API keys among other items.
    fn fake(c: &Canary) -> (tempfile::TempDir, FakePassCli) {
        let dir = tempfile::tempdir().unwrap();
        let fake = FakePassCli::new(dir.path(), &format!("pst_{}::key", c.value()));
        fake.vault("widget", "S1")
            .vault("global", "S2")
            .api_key(
                "S1",
                "i1",
                "Stripe test key",
                "API key",
                "STRIPE_KEY",
                &format!("stripe-{}", c.value()),
            )
            .api_key(
                "S1",
                "i2",
                "free text",
                "api KEY",
                "DB_URL",
                &format!("db-{}", c.value()),
            )
            // A login with the same field names, a note, and a custom item
            // without a Secret field: all ignored.
            .item(
                "S1",
                "i3",
                "login",
                serde_json::json!({"extra_fields": [
                    {"name": "API key", "content": {"Text": "LOGIN_KEY"}},
                    {"name": "Secret", "content": {"Hidden": c.value()}},
                ]}),
            )
            .item("S1", "i4", "note", serde_json::json!({"note": c.value()}))
            .item(
                "S1",
                "i5",
                "custom",
                serde_json::json!({"sections": [{"section_fields": [
                    {"name": "API key", "content": {"Text": "HALF"}},
                ]}]}),
            )
            .api_key(
                "S2",
                "g1",
                "shared",
                "API key",
                "OPENAI_KEY",
                &format!("openai-{}", c.value()),
            );
        (dir, fake)
    }

    #[tokio::test]
    async fn reads_only_api_key_items_and_keeps_global_out_of_prefixes() {
        let c = Canary::new();
        let (_d, fake) = fake(&c);
        let backend = ProtonBackend::new(fake.cli(), Some(store(&fake.token)));

        let listed = backend.list("").await.unwrap();
        let names: Vec<(&str, &str)> = listed
            .iter()
            .map(|l| (l.name.as_str(), l.id.location.as_str()))
            .collect();
        assert_eq!(
            names,
            [
                ("global/OPENAI_KEY", "S2/g1"),
                ("widget/DB_URL", "S1/i2"),
                ("widget/STRIPE_KEY", "S1/i1"),
            ]
        );
        assert_no_canary(&c, &format!("{listed:?}"));

        let entries = backend
            .source(&spec(Select::Prefix(String::new())))
            .read_all()
            .await
            .unwrap();
        let got: Vec<(String, String, String)> = entries
            .iter()
            .map(|e| {
                (
                    e.key.to_string(),
                    e.value.expose().to_owned(),
                    e.origin.id(),
                )
            })
            .collect();
        assert_eq!(
            got,
            [
                (
                    "DB_URL".into(),
                    format!("db-{}", c.value()),
                    "proton:S1/i2".into()
                ),
                (
                    "STRIPE_KEY".into(),
                    format!("stripe-{}", c.value()),
                    "proton:S1/i1".into()
                ),
            ],
            "global keys never come in through a prefix"
        );
        // Shown by name; the ids stay what a mark is keyed by.
        let shown: Vec<String> = entries.iter().map(|e| e.origin.to_string()).collect();
        assert_eq!(shown, ["proton:widget/DB_URL", "proton:widget/STRIPE_KEY"]);

        let one = backend
            .source(&spec(Select::Secret {
                name: "global/OPENAI_KEY".into(),
                key: Some("OPENAI_API_KEY".parse().unwrap()),
            }))
            .read_all()
            .await
            .unwrap();
        assert_eq!(one[0].key.as_str(), "OPENAI_API_KEY");
        assert_eq!(one[0].value.expose(), format!("openai-{}", c.value()));

        let missing = backend
            .source(&spec(secret("widget/NOPE")))
            .read_all()
            .await
            .unwrap_err();
        assert_eq!(missing.to_string(), "secret widget/NOPE does not exist");
        let empty = backend
            .source(&spec(Select::Prefix("other/".into())))
            .read_all()
            .await
            .unwrap_err();
        assert!(matches!(empty, SourceError::NoMatch { .. }), "{empty}");

        let calls = fake.calls();
        assert!(!calls.contains("token-in-env"), "{calls}");
        assert!(!calls.contains(c.value()), "the token is never an argument");
        assert_eq!(fake.env(), format!("{} fs", fake.session_dir().display()));
    }

    /// The sources of one backend read the account once between them: an
    /// environment with two Proton sources does not list every vault and
    /// view every item twice. Another backend, as another request makes,
    /// reads it again.
    #[tokio::test]
    async fn the_sources_of_one_backend_read_the_account_once() {
        let c = Canary::new();
        let (_d, fake) = fake(&c);
        let listings = || fake.calls().matches("vault list").count();
        // Logged in first, so a read is one listing.
        let first = ProtonBackend::new(fake.cli(), Some(store(&fake.token)));
        first.list("").await.unwrap();
        let before = listings();

        let backend = ProtonBackend::new(fake.cli(), Some(store(&fake.token)));
        let stripe = backend.source(&spec(secret("widget/STRIPE_KEY")));
        let db = backend.source(&spec(secret("widget/DB_URL")));
        let (a, b) = tokio::join!(stripe.read_all(), db.read_all());
        assert_eq!(
            a.unwrap()[0].value.expose(),
            format!("stripe-{}", c.value())
        );
        assert_eq!(b.unwrap()[0].value.expose(), format!("db-{}", c.value()));
        assert_eq!(listings(), before + 1, "{}", fake.calls());

        let again = ProtonBackend::new(fake.cli(), Some(store(&fake.token)));
        let db = again.source(&spec(secret("widget/DB_URL")));
        db.read_all().await.unwrap();
        assert_eq!(listings(), before + 2, "{}", fake.calls());

        // A read that fails is not kept: the next source reads again.
        let failing = ProtonBackend::new(fake.cli(), Some(store("pst_wrong::key")));
        fake.expire();
        let first = failing.source(&spec(secret("widget/DB_URL")));
        assert!(first.read_all().await.is_err());
        let failed = listings();
        let second = failing.source(&spec(secret("widget/DB_URL")));
        assert!(second.read_all().await.is_err());
        assert!(listings() > failed, "{}", fake.calls());
    }

    #[tokio::test]
    async fn an_expired_session_logs_in_again_once() {
        let c = Canary::new();
        let (_d, fake) = fake(&c);
        let backend = ProtonBackend::new(fake.cli(), Some(store(&fake.token)));
        backend.list("").await.unwrap();
        assert_eq!(fake.logins(), 1, "the first call logs in");
        backend.list("").await.unwrap();
        assert_eq!(fake.logins(), 1, "the session is reused");

        fake.expire();
        let entries = backend
            .source(&spec(secret("widget/DB_URL")))
            .read_all()
            .await
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            fake.logins(),
            2,
            "logged in again after the session expired"
        );
        assert!(fake.calls().contains("logout --force"));

        // A token Proton no longer takes: needs login, naming no token.
        let wrong = ProtonBackend::new(fake.cli(), Some(store(&format!("pst_other{}", c.value()))));
        fake.expire();
        let e = wrong.list("").await.unwrap_err();
        assert!(matches!(e, SourceError::NeedsLogin { .. }), "{e}");
        assert_no_canary(&c, &format!("{e} {e:?} {}", e.hint().unwrap_or("")));
        let status = wrong.status().await;
        assert!(
            matches!(status.health, Health::NeedsLogin { .. }),
            "{status:?}"
        );
        assert_eq!(status.expires, Some(1_000));
        assert_no_canary(&c, &format!("{status:?}"));
    }

    #[tokio::test]
    async fn without_a_token_or_pass_cli_it_says_what_to_run() {
        let c = Canary::new();
        let (_d, fake) = fake(&c);
        let none = ProtonBackend::new(fake.cli(), Some(Arc::new(Store::default())));
        let status = none.status().await;
        assert_eq!(
            status.health,
            Health::NotConnected {
                hint: CONNECT_HINT.into()
            }
        );
        let e = none.list("").await.unwrap_err();
        assert_eq!(e.hint(), Some(CONNECT_HINT));

        let missing = PassCli {
            bin: fake.root().join("no-such-pass-cli"),
            ..fake.cli()
        };
        let e = ProtonBackend::new(missing, Some(store(&fake.token)))
            .list("")
            .await
            .unwrap_err();
        assert!(e.to_string().contains("pass-cli is not installed"), "{e}");
    }

    /// Only a session directory kagebunshin creates is marked as its own.
    #[test]
    fn marks_only_the_session_directories_it_creates() {
        let tmp = tempfile::tempdir().unwrap();
        let made = tmp.path().join("data/proton");
        make_dir(&made).unwrap();
        assert!(
            made.join(SESSION_MARKER)
                .symlink_metadata()
                .unwrap()
                .is_file()
        );
        let there = tmp.path().join("there");
        std::fs::create_dir(&there).unwrap();
        std::fs::write(there.join("notes.txt"), "mine").unwrap();
        make_dir(&there).unwrap();
        assert!(there.join(SESSION_MARKER).symlink_metadata().is_err());
    }

    #[test]
    fn dates_round_trip() {
        assert_eq!(parse_date("1970-01-01"), Some(0));
        assert_eq!(parse_date("2026-01-01"), Some(1_767_225_600));
        for d in ["2024-02-29", "2026-12-31", "2000-03-01"] {
            assert_eq!(format_date(parse_date(d).unwrap() + 3_600), d);
        }
        for bad in [
            "2026-02-29",
            "2026-13-01",
            "2026-1-01",
            "tomorrow",
            "2026-00-10",
        ] {
            assert_eq!(parse_date(bad), None, "{bad}");
        }
    }

    #[test]
    fn redacts_tokens_from_errors() {
        let t = SecretValue::new("sekrit".into());
        assert_eq!(
            redact("bad token sekrit\nor pst_abc::k given", Some(&t)),
            "bad token <token> or <token> given"
        );
    }
}
