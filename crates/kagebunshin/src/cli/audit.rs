//! `kagebunshin audit`: reads the audit log the daemon and the CLI write.
//! The log holds names only, so reading it needs no daemon and no unlock.

use std::time::{SystemTime, UNIX_EPOCH};

use super::{CliError, Exit, plural, print_json, print_line};
use crate::audit::{AuditLog, Decision, Event, utc};
use crate::config::schema::duration_secs;

pub fn parse_since(s: &str) -> Result<u64, String> {
    match duration_secs(s) {
        Some(Some(secs)) => Ok(secs),
        Some(None) => Err("too long".into()),
        None => Err("a whole number followed by s, m, h or d, e.g. 1d".into()),
    }
}

pub fn show(json: bool, since: Option<u64>) -> Result<(), CliError> {
    let fail = |e: std::io::Error| {
        CliError::new(
            Exit::Failure,
            "audit",
            format!("cannot read the audit log: {e}"),
        )
    };
    let log = AuditLog::from_env().map_err(fail)?;
    let (mut events, unreadable) = log.read().map_err(fail)?;
    if let Some(secs) = since {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let from = now.saturating_sub(secs);
        events.retain(|e| e.time >= from);
    }
    if json {
        return print_json(&serde_json::json!({
            "path": log.path(),
            "events": events,
            "unreadable": unreadable,
        }));
    }
    if unreadable > 0 {
        eprintln!(
            "warning: {unreadable} {} of {} could not be read",
            plural(unreadable, "line", "lines"),
            log.path().display()
        );
    }
    for event in &events {
        print_line(&line(event))?;
    }
    Ok(())
}

/// `2026-11-11 09:26:13Z denied run widget/dev pid 41 ...`
pub fn line(e: &Event) -> String {
    let mut out = format!(
        "{} {:<7} {}",
        utc(e.time),
        match e.decision {
            Decision::Allowed => "allowed",
            Decision::Denied => "denied",
            Decision::TimedOut => "timeout",
        },
        e.action
    );
    match (&e.project, &e.env) {
        (Some(p), Some(env)) => out.push_str(&format!(" {p}/{env}")),
        (Some(p), None) => out.push_str(&format!(" {p}")),
        (None, Some(env)) => out.push_str(&format!(" env {env}")),
        (None, None) => {}
    }
    match &e.remote {
        Some(r) => {
            out.push_str(&format!(" machine {} user {}", r.machine, r.user));
            if !r.tags.is_empty() {
                out.push_str(&format!(" tags {}", r.tags.join(",")));
            }
        }
        None => out.push_str(&format!(" pid {}", e.pid)),
    }
    if let Some(p) = &e.program {
        out.push_str(&format!(" program {p}"));
    }
    if !e.keys.is_empty() {
        out.push_str(&format!(" keys {}", e.keys.join(",")));
    }
    if let Some(t) = &e.target {
        out.push_str(&format!(" ({t})"));
    }
    if let Some(r) = &e.reason {
        out.push_str(&format!(": {r}"));
    }
    out
}
