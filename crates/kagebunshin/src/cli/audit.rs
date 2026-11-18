//! `kagebunshin audit`: reads the audit log the daemon and the CLI write,
//! and with `--all` the runs log beside it. The logs hold names only, so
//! reading them needs no daemon and no unlock.

use std::collections::BTreeSet;

use super::{CliError, Exit, plural, print_json, print_line};
use crate::audit::{AuditLog, Decision, Event, utc};
use crate::config::schema::duration_secs;
use crate::source::unix_now;
use crate::types::{EnvName, ProjectName};

/// Which events `audit` lists.
#[derive(Debug, Default)]
pub struct Filter {
    /// Only events this many seconds old or newer.
    pub since: Option<u64>,
    /// The runs log too.
    pub all: bool,
    pub action: Option<String>,
    pub project: Option<ProjectName>,
    pub env: Option<EnvName>,
}

impl Filter {
    fn keeps(&self, e: &Event, now: u64) -> bool {
        self.since
            .is_none_or(|secs| e.time >= now.saturating_sub(secs))
            && self.action.as_ref().is_none_or(|a| *a == e.action)
            && self
                .project
                .as_ref()
                .is_none_or(|p| e.project.as_ref() == Some(p))
            && self.env.as_ref().is_none_or(|v| e.env.as_ref() == Some(v))
    }
}

pub fn parse_since(s: &str) -> Result<u64, String> {
    match duration_secs(s) {
        Some(Some(secs)) => Ok(secs),
        Some(None) => Err("too long".into()),
        None => Err("a whole number followed by s, m, h or d, e.g. 1d".into()),
    }
}

pub fn show(json: bool, filter: &Filter) -> Result<(), CliError> {
    let fail = |e: std::io::Error| {
        CliError::new(
            Exit::Failure,
            "audit",
            format!("cannot read the audit log: {e}"),
        )
    };
    let log = AuditLog::from_env().map_err(fail)?;
    let runs = filter.all.then(|| log.runs());
    let mut events = Vec::new();
    let mut unreadable = Vec::new();
    for log in std::iter::once(&log).chain(&runs) {
        let (more, bad) = log.read().map_err(fail)?;
        events.extend(more);
        unreadable.push((log.path(), bad));
    }
    let now = unix_now();
    events.retain(|e| filter.keeps(e, now));
    // The two logs as one, in the order things happened; the sort is
    // stable, so each log's own order holds within a second.
    events.sort_by_key(|e| e.time);
    if json {
        let mut out = serde_json::json!({
            "path": log.path(),
            "events": events,
            "unreadable": unreadable.iter().map(|(_, n)| n).sum::<usize>(),
        });
        if let Some(runs) = &runs {
            out["runs_path"] = serde_json::json!(runs.path());
        }
        return print_json(&out);
    }
    for (path, n) in unreadable {
        if n > 0 {
            eprintln!(
                "warning: {n} {} of {} could not be read",
                plural(n, "line", "lines"),
                path.display()
            );
        }
    }
    for event in &events {
        print_line(&line(event))?;
    }
    Ok(())
}

/// How much kagebunshin was used: the runs that were handed their values.
#[derive(Debug, PartialEq, Eq, serde::Serialize)]
pub struct Usage {
    /// Counted from this time on, in Unix seconds.
    pub since: u64,
    pub count: usize,
    /// How many projects they were in.
    pub projects: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last: Option<LastRun>,
}

#[derive(Debug, PartialEq, Eq, serde::Serialize)]
pub struct LastRun {
    pub time: u64,
    pub project: ProjectName,
    pub env: EnvName,
}

/// The window [`usage`] counts over.
const USAGE_SECS: u64 = 86_400;

/// The runs of the last day, in every project or in the environment `of`
/// alone; `None` when the logs cannot be read. An approved run is in the
/// audit log and an ordinary one in the runs log, so it reads both.
pub fn usage(of: Option<(&ProjectName, &EnvName)>) -> Option<Usage> {
    let log = AuditLog::from_env().ok()?;
    let (mut events, _) = log.read().ok()?;
    events.extend(log.runs().read().ok()?.0);
    Some(usage_of(&events, of, unix_now().saturating_sub(USAGE_SECS)))
}

fn usage_of(events: &[Event], of: Option<(&ProjectName, &EnvName)>, since: u64) -> Usage {
    let runs = events.iter().filter_map(|e| {
        let (project, env) = (e.project.as_ref()?, e.env.as_ref()?);
        (e.action == "run"
            && e.decision == Decision::Allowed
            && e.time >= since
            && of.is_none_or(|of| of == (project, env)))
        .then_some((e.time, project, env))
    });
    let (mut count, mut projects, mut last) = (0, BTreeSet::new(), None);
    for (time, project, env) in runs {
        count += 1;
        projects.insert(project);
        if last.as_ref().is_none_or(|l: &LastRun| time >= l.time) {
            last = Some(LastRun {
                time,
                project: project.clone(),
                env: env.clone(),
            });
        }
    }
    Usage {
        since,
        count,
        projects: projects.len(),
        last,
    }
}

impl Usage {
    /// `runs in the last day: 13 in 2 projects, last at 2026-11-18
    /// 14:41:07Z (widget/dev)`; without the projects when `one` environment
    /// was counted.
    pub fn line(&self, one: bool) -> String {
        let mut out = "runs in the last day: ".to_owned();
        let Some(last) = &self.last else {
            out.push_str("none");
            return out;
        };
        out.push_str(&self.count.to_string());
        if !one {
            out.push_str(&format!(
                " in {} {}",
                self.projects,
                plural(self.projects, "project", "projects")
            ));
        }
        out.push_str(&format!(", last at {}", utc(last.time)));
        if !one {
            out.push_str(&format!(" ({}/{})", last.project, last.env));
        }
        out
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn event(time: u64, action: &str, decision: Decision, at: Option<(&str, &str)>) -> Event {
        let mut e = Event::new(action, decision, &crate::test_support::this_process());
        e.time = time;
        if let Some((project, env)) = at {
            e.project = Some(project.parse().unwrap());
            e.env = Some(env.parse().unwrap());
        }
        e
    }

    #[test]
    fn usage_counts_the_runs_that_got_their_values() {
        use Decision::{Allowed, Denied};
        let events = [
            event(50, "run", Allowed, Some(("widget", "dev"))),
            event(100, "run", Allowed, Some(("widget", "dev"))),
            event(130, "run", Allowed, Some(("gadget", "dev"))),
            event(120, "run", Allowed, Some(("widget", "prod"))),
            event(140, "run", Denied, Some(("widget", "prod"))),
            event(150, "get", Allowed, Some(("widget", "dev"))),
            event(160, "unlock", Allowed, None),
        ];
        let all = usage_of(&events, None, 100);
        assert_eq!((all.count, all.projects), (3, 2));
        assert_eq!(
            all.line(false),
            "runs in the last day: 3 in 2 projects, last at 1970-01-01 00:02:10Z (gadget/dev)"
        );

        let (widget, dev) = ("widget".parse().unwrap(), "dev".parse().unwrap());
        let one = usage_of(&events, Some((&widget, &dev)), 100);
        assert_eq!((one.count, one.projects), (1, 1));
        assert_eq!(
            one.line(true),
            "runs in the last day: 1, last at 1970-01-01 00:01:40Z"
        );

        let none = usage_of(&events, None, 200);
        assert_eq!((none.count, none.projects, &none.last), (0, 0, &None));
        assert_eq!(none.line(false), "runs in the last day: none");
        assert_eq!(none.line(true), "runs in the last day: none");
    }

    #[test]
    fn a_filter_keeps_what_every_part_of_it_names() {
        let e = event(900, "run", Decision::Allowed, Some(("widget", "dev")));
        let keeps = |f: Filter| f.keeps(&e, 1000);
        assert!(keeps(Filter::default()));
        assert!(keeps(Filter {
            since: Some(100),
            action: Some("run".into()),
            project: Some("widget".parse().unwrap()),
            env: Some("dev".parse().unwrap()),
            ..Filter::default()
        }));
        assert!(!keeps(Filter {
            since: Some(99),
            ..Filter::default()
        }));
        assert!(!keeps(Filter {
            action: Some("get".into()),
            ..Filter::default()
        }));
        assert!(!keeps(Filter {
            project: Some("gadget".parse().unwrap()),
            ..Filter::default()
        }));
        assert!(!keeps(Filter {
            env: Some("prod".parse().unwrap()),
            ..Filter::default()
        }));
        // An event about no project is not one project's.
        let unlock = event(900, "unlock", Decision::Allowed, None);
        assert!(
            !Filter {
                project: Some("widget".parse().unwrap()),
                ..Filter::default()
            }
            .keeps(&unlock, 1000)
        );
    }
}
