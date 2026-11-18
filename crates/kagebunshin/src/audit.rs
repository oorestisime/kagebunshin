//! The audit log: what was asked of kagebunshin, by whom, and what it
//! decided. One JSON object per line in
//! `$XDG_STATE_HOME/kagebunshin/audit.jsonl` (else
//! `~/.local/state/kagebunshin/audit.jsonl`), mode 0600, moved to
//! `audit.jsonl.1` once it reaches [`MAX_BYTES`].
//!
//! An [`Event`] holds names only: no field can hold a value, a passphrase
//! or a program's arguments. The daemon writes the requests it answers; the CLI
//! writes the config edits it makes itself.
//!
//! An ordinary `run`, one that needed no approval, is not in that file but
//! in `runs.jsonl` beside it ([`AuditLog::runs`]), kept and moved aside the
//! same way. So however many of them there are, they push nothing out of
//! the audit log.

use std::ffi::OsString;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::ipc::protocol::{Caller, RemotePeer};
use crate::types::{EnvName, ProjectName};

pub const FILE: &str = "audit.jsonl";
/// The log of ordinary runs, beside [`FILE`].
pub const RUNS_FILE: &str = "runs.jsonl";
/// The size at which a log is moved to its `.1`, replacing the one before.
pub const MAX_BYTES: u64 = 10 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allowed,
    Denied,
    /// A request waited for approval in the app, and none came in time.
    TimedOut,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Unix seconds.
    pub time: u64,
    /// The request, such as `run` or `unlock`, or the CLI command, such as
    /// `project add-source`.
    pub action: String,
    pub decision: Decision,
    /// Why it was denied: the error message, which names no values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The calling process. Every caller gets the same policy, so the log
    /// cannot tell an agent from a person; the pid and its start time can.
    pub uid: u32,
    pub pid: i32,
    pub start_time: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<ProjectName>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<EnvName>,
    /// Key names, or `section.KEY` for the local store, or secret names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<String>,
    /// The program `run` starts, as the CLI named it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
    /// The source `project add-source` added, or what an edit named.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// A caller on another machine: its node, machine, user and tags, as
    /// tailscaled identified it. Its pid and start time are then 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<crate::ipc::protocol::RemotePeer>,
}

impl Event {
    pub fn new(action: impl Into<String>, decision: Decision, caller: &Caller) -> Self {
        Self {
            time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            action: action.into(),
            decision,
            reason: None,
            uid: caller.uid,
            pid: caller.pid,
            start_time: caller.start_time.0,
            project: None,
            env: None,
            keys: Vec::new(),
            program: None,
            target: None,
            remote: caller.remote.as_ref().map(RemotePeer::named),
        }
    }
}

/// Records a configuration edit this CLI process made. Only a warning when
/// it cannot: the edit is already written. Called only by CLI commands.
pub fn record_edit(
    action: &str,
    project: &ProjectName,
    env: Option<&EnvName>,
    keys: Vec<String>,
    target: Option<String>,
) {
    let pid = std::process::id() as i32;
    let caller = Caller {
        uid: crate::sys::effective_uid(),
        gid: 0,
        pid,
        start_time: crate::sys::process_start(pid).unwrap_or(crate::sys::ProcStart(0)),
        remote: None,
    };
    let mut event = Event::new(action, Decision::Allowed, &caller);
    event.project = Some(project.clone());
    event.env = env.cloned();
    event.keys = keys;
    event.target = target;
    if let Err(e) = AuditLog::from_env().and_then(|log| log.append(&event)) {
        crate::cli::error::warn(&format!("cannot record this in the audit log: {e}"));
    }
}

#[derive(Debug, Clone)]
pub struct AuditLog {
    path: PathBuf,
    max_bytes: u64,
}

impl AuditLog {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            max_bytes: MAX_BYTES,
        }
    }

    pub fn from_env() -> io::Result<Self> {
        Self::resolve(|k| std::env::var_os(k))
    }

    /// `$XDG_STATE_HOME/kagebunshin/audit.jsonl` when it is absolute, else
    /// `$HOME/.local/state/kagebunshin/audit.jsonl`.
    pub fn resolve(env: impl Fn(&str) -> Option<OsString>) -> io::Result<Self> {
        let var = |k: &str| env(k).map(PathBuf::from).filter(|p| p.is_absolute());
        let dir = match (var("XDG_STATE_HOME"), var("HOME")) {
            (Some(state), _) => state,
            (None, Some(home)) => home.join(".local/state"),
            (None, None) => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "neither XDG_STATE_HOME nor HOME is set to an absolute path",
                ));
            }
        };
        Ok(Self::new(dir.join("kagebunshin").join(FILE)))
    }

    /// For tests of rotation.
    pub fn with_max_bytes(mut self, max_bytes: u64) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The log of ordinary runs beside this one, `runs.jsonl`.
    #[must_use]
    pub fn runs(&self) -> Self {
        Self {
            path: self.path.with_file_name(RUNS_FILE),
            max_bytes: self.max_bytes,
        }
    }

    fn rotated(&self) -> PathBuf {
        let mut name = self.path.clone().into_os_string();
        name.push(".1");
        name.into()
    }

    /// Appends one line, moving a full log aside first. Holds a lock file
    /// next to the log meanwhile, so the daemon and CLI processes never
    /// interleave lines or rotate under each other.
    pub fn append(&self, event: &Event) -> io::Result<()> {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        let dir = self.path.parent().unwrap_or(Path::new("."));
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        let open = |path: &Path, append: bool| {
            fs::OpenOptions::new()
                .write(true)
                .append(append)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .open(path)
        };
        let lock = open(&dir.join("audit.lock"), false)?;
        lock.lock()?;
        match fs::metadata(&self.path) {
            Ok(m) if m.len() >= self.max_bytes => fs::rename(&self.path, self.rotated())?,
            _ => {}
        }
        let mut line = serde_json::to_vec(event).map_err(io::Error::other)?;
        line.push(b'\n');
        open(&self.path, true)?.write_all(&line)
    }

    /// Every event, oldest first, and how many lines could not be read.
    pub fn read(&self) -> io::Result<(Vec<Event>, usize)> {
        let mut events = Vec::new();
        let mut unreadable = 0;
        for path in [self.rotated(), self.path.clone()] {
            let file = match fs::File::open(&path) {
                Ok(f) => f,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };
            for line in io::BufReader::new(file).lines() {
                match serde_json::from_str(&line?) {
                    Ok(event) => events.push(event),
                    Err(_) => unreadable += 1,
                }
            }
        }
        Ok((events, unreadable))
    }
}

/// `secs` since the epoch as `2026-11-11 09:26:13Z`.
pub fn utc(secs: u64) -> String {
    let (days, rest) = (secs / 86_400, secs % 86_400);
    // Days to a civil date, after Howard Hinnant's `civil_from_days`.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}Z",
        rest / 3600,
        rest / 60 % 60,
        rest % 60
    )
}

/// The day of `secs` since the epoch in this machine's time zone, as
/// `14 Nov`, with the year when it is not `now`'s. For what a person reads
/// as a date: the log itself stays in UTC.
pub fn day(secs: u64, now: u64) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let date = |secs: u64| {
        crate::sys::local_date(secs).or_else(|| {
            let utc = utc(secs);
            Some((
                utc.get(0..4)?.parse().ok()?,
                utc.get(5..7)?.parse().ok()?,
                utc.get(8..10)?.parse().ok()?,
            ))
        })
    };
    let Some((year, month, day)) = date(secs) else {
        return utc(secs);
    };
    let month = (month as usize)
        .checked_sub(1)
        .and_then(|m| MONTHS.get(m))
        .copied()
        .unwrap_or("?");
    if date(now).is_some_and(|(y, ..)| y == year) {
        format!("{day} {month}")
    } else {
        format!("{day} {month} {year}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// The day is this machine's, so it is read back, not written out.
    #[test]
    fn day_names_the_year_only_when_it_is_another() {
        const NOV_14_2026: u64 = 1_794_657_600; // noon UTC
        let (_, _, d) = crate::sys::local_date(NOV_14_2026).unwrap();
        assert!((13..=15).contains(&d), "{d}");
        assert_eq!(
            day(NOV_14_2026, NOV_14_2026 + 4 * 86_400),
            format!("{d} Nov")
        );
        assert_eq!(
            day(NOV_14_2026, NOV_14_2026 + 90 * 86_400),
            format!("{d} Nov 2026")
        );
    }

    fn event(action: &str) -> Event {
        Event::new(
            action,
            Decision::Allowed,
            &crate::test_support::this_process(),
        )
    }

    #[test]
    fn appends_private_lines_and_rotates() {
        let tmp = tempfile::tempdir().unwrap();
        let log = AuditLog::new(tmp.path().join("state/kagebunshin").join(FILE)).with_max_bytes(1);
        log.append(&event("lock")).unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(log.path()), 0o600);
        assert_eq!(mode(log.path().parent().unwrap()), 0o700);
        // Over the limit, so each append moves the last one aside.
        log.append(&event("unlock")).unwrap();
        log.append(&event("run")).unwrap();
        let (events, unreadable) = log.read().unwrap();
        let actions: Vec<_> = events.iter().map(|e| e.action.as_str()).collect();
        assert_eq!(actions, ["unlock", "run"]);
        assert_eq!(unreadable, 0);
        assert_eq!(mode(&log.rotated()), 0o600);
    }

    /// The runs log is a file of its own: filling it moves nothing out of
    /// the audit log.
    #[test]
    fn runs_rotate_apart_from_the_audit_log() {
        let tmp = tempfile::tempdir().unwrap();
        let log = AuditLog::new(tmp.path().join(FILE)).with_max_bytes(1);
        let runs = log.runs();
        assert_eq!(runs.path(), tmp.path().join(RUNS_FILE));
        log.append(&event("unlock")).unwrap();
        for _ in 0..3 {
            runs.append(&event("run")).unwrap();
        }
        let actions = |log: &AuditLog| -> Vec<String> {
            let (events, _) = log.read().unwrap();
            events.into_iter().map(|e| e.action).collect()
        };
        assert_eq!(actions(&log), ["unlock"]);
        assert!(!log.rotated().exists());
        assert_eq!(actions(&runs), ["run", "run"]);
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(runs.path()), 0o600);
        assert_eq!(mode(&runs.rotated()), 0o600);
    }

    #[test]
    fn unreadable_lines_are_counted() {
        let tmp = tempfile::tempdir().unwrap();
        let log = AuditLog::new(tmp.path().join(FILE));
        log.append(&event("lock")).unwrap();
        fs::OpenOptions::new()
            .append(true)
            .open(log.path())
            .unwrap()
            .write_all(b"not json\n")
            .unwrap();
        let (events, unreadable) = log.read().unwrap();
        assert_eq!((events.len(), unreadable), (1, 1));
    }

    #[test]
    fn resolves_the_state_dir() {
        let env = |vars: &'static [(&'static str, &'static str)]| {
            move |k: &str| {
                vars.iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| OsString::from(v))
            }
        };
        let path = |vars| AuditLog::resolve(env(vars)).map(|l| l.path().to_owned());
        assert_eq!(
            path(&[("XDG_STATE_HOME", "/s"), ("HOME", "/h")]).unwrap(),
            Path::new("/s/kagebunshin/audit.jsonl")
        );
        assert_eq!(
            path(&[("XDG_STATE_HOME", "rel"), ("HOME", "/h")]).unwrap(),
            Path::new("/h/.local/state/kagebunshin/audit.jsonl")
        );
        assert!(path(&[]).is_err());
    }

    #[test]
    fn formats_utc() {
        assert_eq!(utc(0), "1970-01-01 00:00:00Z");
        assert_eq!(utc(951_782_400), "2000-02-29 00:00:00Z");
        assert_eq!(utc(1_794_389_173), "2026-11-11 09:26:13Z");
    }
}
