//! The lists of secrets a checkout's GitHub Actions workflows name: which
//! secrets a deploy loads, in which order, and for which environment.
//!
//! No YAML is parsed; a workflow is read line by line, so that every list
//! has a line to point at. A list is the secret names (of those a provider
//! listed, found whole as [`super::facts::mentions`] finds them) on one
//! line and on the lines right after it: a comma-separated variable, the
//! lines of an action's input, a YAML sequence, one `--secret-id` after
//! another. A line that starts a new `key:` and names secrets starts a new
//! list, as does a new job, a blank line or a line naming none. Comments
//! are not read.
//!
//! What the workflow calls the environment is, in this order: the
//! environment word in the file's name (`deploy-dev.yml`), unless its jobs
//! name several `environment:`s; the job's `environment:`; the environment
//! word in the job's id; the one in the workflow's `name:`; the one
//! environment word among the segments of the listed names. An environment
//! word is one of [`PROD_NAMES`] or [`NON_PROD_NAMES`].

use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::facts::{MAX_FILE_SIZE, MAX_NAMES, find_whole};
use crate::daemon::resolve::{NON_PROD_NAMES, PROD_NAMES};

/// A list of secrets a workflow names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SecretList {
    /// The workflow, relative to the checkout root.
    pub file: PathBuf,
    /// The line of the list's first name, from 1.
    pub line: usize,
    /// What the workflow calls the environment, lower-cased; `None` when
    /// it does not say.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<String>,
    /// The folder the workflow's commands run in (its first
    /// `working-directory`), relative to the checkout root.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dir: Option<PathBuf>,
    /// In the workflow's order.
    pub names: Vec<String>,
}

impl SecretList {
    /// `FILE:LINE`.
    pub fn at(&self) -> String {
        format!("{}:{}", self.file.display(), self.line)
    }
}

/// The lists of `names` in the workflows among `files` (relative to
/// `root`, as git lists the tracked ones), by file, then by line.
pub fn secret_lists(root: &Path, files: &[PathBuf], names: &[String]) -> Vec<SecretList> {
    let names = &names[..names.len().min(MAX_NAMES)];
    let mut out = Vec::new();
    for rel in files.iter().filter(|f| is_workflow(f)) {
        let path = root.join(rel);
        if fs::symlink_metadata(&path).map_or(true, |m| !m.is_file() || m.len() > MAX_FILE_SIZE) {
            continue;
        }
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        out.extend(lists_in(rel, &text, names));
    }
    out
}

fn is_workflow(rel: &Path) -> bool {
    rel.parent() == Some(Path::new(".github/workflows"))
        && rel.extension().is_some_and(|e| e == "yml" || e == "yaml")
}

struct Job {
    id: String,
    environment: Option<String>,
}

struct Run {
    line: usize,
    job: Option<usize>,
    names: Vec<String>,
}

fn lists_in(file: &Path, text: &str, names: &[String]) -> Vec<SecretList> {
    let here: Vec<&str> = names
        .iter()
        .map(String::as_str)
        .filter(|n| !n.is_empty() && text.contains(n))
        .collect();
    if here.is_empty() {
        return Vec::new();
    }
    let mut title: Option<String> = None;
    let mut dir: Option<PathBuf> = None;
    let mut jobs: Vec<Job> = Vec::new();
    let mut in_jobs = false;
    let mut job_indent: Option<usize> = None;
    let mut job: Option<usize> = None;
    // The indent of an `environment:` whose name is on a line below it.
    let mut environment_at: Option<usize> = None;
    let mut runs: Vec<Run> = Vec::new();
    let mut run: Option<Run> = None;

    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim_end();
        let content = line.trim_start();
        if content.starts_with('#') {
            continue;
        }
        if content.is_empty() {
            runs.extend(run.take());
            continue;
        }
        let indent = line.len() - content.len();
        if indent == 0 {
            in_jobs = content.starts_with("jobs:");
            job_indent = None;
            job = None;
            if let Some(v) = value(content, "name") {
                title = Some(v);
            }
        } else if in_jobs
            && job_indent.is_none_or(|j| j == indent)
            && let Some(id) = content.strip_suffix(':')
        {
            job_indent = Some(indent);
            job = Some(jobs.len());
            jobs.push(Job {
                id: id.to_owned(),
                environment: None,
            });
            environment_at = None;
        }
        if dir.is_none()
            && let Some(v) = value(content, "working-directory")
        {
            dir = folder(&v);
        }
        if let Some(j) = job.and_then(|j| jobs.get_mut(j)) {
            if let Some(v) = value(content, "environment") {
                environment_at = v.is_empty().then_some(indent);
                if let Some(name) = env_name(&v) {
                    j.environment = Some(name);
                }
            } else if let Some(at) = environment_at {
                if indent <= at {
                    environment_at = None;
                } else if let Some(v) = value(content, "name") {
                    j.environment = env_name(&v);
                    environment_at = None;
                }
            }
        }

        let mut found: Vec<(usize, &str)> = here
            .iter()
            .filter_map(|n| find_whole(content, n).map(|at| (at, *n)))
            .collect();
        if found.is_empty() {
            runs.extend(run.take());
            continue;
        }
        found.sort_unstable();
        if run.as_ref().is_some_and(|r| r.job != job) || starts_key(content) {
            runs.extend(run.take());
        }
        let r = run.get_or_insert(Run {
            line: i + 1,
            job,
            names: Vec::new(),
        });
        for (_, n) in found {
            if !r.names.iter().any(|x| x == n) {
                r.names.push(n.to_owned());
            }
        }
    }
    runs.extend(run);

    let mut environments: Vec<&str> = jobs
        .iter()
        .filter_map(|j| j.environment.as_deref())
        .collect();
    environments.sort_unstable();
    environments.dedup();
    let of_file = (environments.len() < 2)
        .then(|| {
            file.file_stem()
                .and_then(|s| env_word(&s.to_string_lossy()))
        })
        .flatten();
    runs.into_iter()
        .map(|r| {
            let job = r.job.and_then(|j| jobs.get(j));
            let env = of_file
                .clone()
                .or_else(|| job.and_then(|j| j.environment.clone()))
                .or_else(|| job.and_then(|j| env_word(&j.id)))
                .or_else(|| title.as_deref().and_then(env_word))
                .or_else(|| env_segment(&r.names));
            SecretList {
                file: file.to_owned(),
                line: r.line,
                env,
                dir: dir.clone(),
                names: r.names,
            }
        })
        .collect()
}

/// The value of `key: value` on a line (after a sequence's `- `), without
/// quotes or a trailing comment; empty when the line ends at the colon.
/// `None` for another key, and for a `${{ }}` expression, which says
/// nothing here.
fn value(content: &str, key: &str) -> Option<String> {
    let c = content.strip_prefix("- ").unwrap_or(content).trim_start();
    let rest = c.strip_prefix(key)?.strip_prefix(':')?;
    if !rest.is_empty() && !rest.starts_with(' ') {
        return None;
    }
    let v = rest.split(" #").next().unwrap_or(rest).trim();
    let v = v.trim_matches(['"', '\'']);
    (!v.contains("${{")).then(|| v.to_owned())
}

/// Whether the line starts a mapping key (`KEY: ...`, after a sequence's
/// `- `), as opposed to carrying on a block of text or a sequence.
fn starts_key(content: &str) -> bool {
    let c = content.strip_prefix("- ").unwrap_or(content).trim_start();
    let key: &str = c.split(':').next().unwrap_or_default();
    let after = &c[key.len()..];
    !key.is_empty()
        && key
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || "_-.".contains(ch))
        && (after == ":" || after.starts_with(": "))
}

/// `v` as an environment's name: lower-cased, if it then is one.
fn env_name(v: &str) -> Option<String> {
    let v = v.to_ascii_lowercase();
    let ok = v.len() <= 64
        && v.starts_with(|c: char| c.is_ascii_alphanumeric())
        && v.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
    ok.then_some(v)
}

fn is_env_word(word: &str) -> bool {
    PROD_NAMES
        .iter()
        .chain(&NON_PROD_NAMES)
        .any(|w| word.eq_ignore_ascii_case(w))
}

/// The last environment word among the words of `text`: `dev` in
/// `api-deploy-dev` and in `Deploy the API (Dev)`.
fn env_word(text: &str) -> Option<String> {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .rfind(|w| is_env_word(w))
        .map(str::to_ascii_lowercase)
}

/// The environment word among the `/` and `.` segments of `names`, when
/// they carry only one: `dev` for `acme/dev/api` and `sentry`.
fn env_segment(names: &[String]) -> Option<String> {
    let mut words: Vec<String> = names
        .iter()
        .flat_map(|n| n.split(['/', '.']))
        .filter(|s| is_env_word(s))
        .map(str::to_ascii_lowercase)
        .collect();
    words.sort_unstable();
    words.dedup();
    match &words[..] {
        [one] => Some(one.clone()),
        _ => None,
    }
}

/// A `working-directory` as a folder below the checkout root; `None` for
/// the root itself and for anything that is not plainly below it.
fn folder(v: &str) -> Option<PathBuf> {
    let v = v.trim_start_matches("./").trim_end_matches('/');
    let plain = !v.is_empty()
        && v != "."
        && !v.starts_with('/')
        && v.split('/').all(|part| !part.is_empty() && part != "..");
    plain.then(|| PathBuf::from(v))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NAMES: [&str; 8] = [
        "acme/dev/api",
        "acme/dev/db",
        "acme/dev/queue",
        "acme/staging/api",
        "acme/staging/db",
        "acme/prod/api",
        "acme/prod/db",
        "sentry",
    ];

    fn lists(file: &str, text: &str) -> Vec<SecretList> {
        let names: Vec<String> = NAMES.iter().map(|n| (*n).to_owned()).collect();
        lists_in(Path::new(file), text, &names)
    }

    /// Each list as `LINE ENV: NAMES`.
    fn shown(lists: &[SecretList]) -> Vec<String> {
        lists
            .iter()
            .map(|l| {
                format!(
                    "{} {}: {}",
                    l.line,
                    l.env.as_deref().unwrap_or("-"),
                    l.names.join(" ")
                )
            })
            .collect()
    }

    #[test]
    fn a_variable_holding_a_list_is_read_in_its_order() {
        let text = "name: Deploy (Dev)\n\
                    defaults:\n  run:\n    working-directory: ./apps/api\n\
                    env:\n  REGION: eu-west-1\n  LOADS: acme/dev/queue,sentry, acme/dev/api\n\
                    jobs:\n  build:\n    steps:\n      - run: ./load \"${{ env.LOADS }}\"\n";
        let l = lists(".github/workflows/api-deploy-dev.yml", text);
        assert_eq!(shown(&l), ["7 dev: acme/dev/queue sentry acme/dev/api"]);
        assert_eq!(l[0].dir.as_deref(), Some(Path::new("apps/api")));
        assert_eq!(l[0].at(), ".github/workflows/api-deploy-dev.yml:7");
    }

    #[test]
    fn an_actions_input_a_sequence_and_a_script_are_lists_too() {
        let input = "jobs:\n  deploy:\n    environment: staging\n    steps:\n      - uses: acme/get-secrets@v2\n        with:\n          secret-ids: |\n            acme/staging/db\n            API, acme/staging/api\n          parse-json-secrets: true\n";
        assert_eq!(
            shown(&lists(".github/workflows/ship.yml", input)),
            ["8 staging: acme/staging/db acme/staging/api"]
        );
        let sequence = "jobs:\n  deploy:\n    env:\n      LOADS:\n        - acme/dev/db\n        - acme/dev/api\n";
        assert_eq!(
            shown(&lists(".github/workflows/ship.yml", sequence)),
            ["5 dev: acme/dev/db acme/dev/api"]
        );
        let script = "name: deploy\njobs:\n  deploy:\n    steps:\n      - run: |\n          aws secretsmanager get-secret-value --secret-id acme/prod/api\n          aws secretsmanager get-secret-value --secret-id \"acme/prod/db\"\n          echo done\n";
        assert_eq!(
            shown(&lists(".github/workflows/ship.yml", script)),
            ["6 prod: acme/prod/api acme/prod/db"]
        );
    }

    #[test]
    fn each_key_each_job_and_each_gap_starts_a_list() {
        let text = "env:\n  A: acme/dev/api,acme/dev/db\n  B: acme/staging/api,acme/staging/db\n\
                    jobs:\n  one:\n    steps:\n      - run: |\n          load acme/dev/queue\n\n          load acme/dev/db\n          # load acme/prod/db\n          load acme/dev/api\n  two:\n    env:\n      C: sentry\n";
        assert_eq!(
            shown(&lists(".github/workflows/ci.yml", text)),
            [
                "2 dev: acme/dev/api acme/dev/db",
                "3 staging: acme/staging/api acme/staging/db",
                "8 dev: acme/dev/queue",
                "10 dev: acme/dev/db acme/dev/api",
                "15 -: sentry",
            ]
        );
    }

    #[test]
    fn the_environment_is_what_the_workflow_calls_it() {
        // The file's name, over a job's `environment:`.
        let one = "jobs:\n  deploy:\n    environment: production\n    env:\n      LOADS: acme/prod/api,sentry\n";
        assert_eq!(
            shown(&lists(".github/workflows/deploy-prod.yml", one)),
            ["5 prod: acme/prod/api sentry"]
        );
        // Jobs naming several: each job's own, written out or under `name:`.
        let several = "jobs:\n  a:\n    environment: Staging\n    env:\n      LOADS: acme/staging/api,sentry\n  b:\n    environment:\n      name: production\n      url: https://example.com\n    env:\n      LOADS: acme/prod/api,sentry\n";
        assert_eq!(
            shown(&lists(".github/workflows/test-and-deploy.yml", several)),
            [
                "5 staging: acme/staging/api sentry",
                "11 production: acme/prod/api sentry"
            ]
        );
        // The job's id, then the workflow's name.
        let by_job = "name: Ship (QA)\nenv:\n  LOADS: sentry\njobs:\n  deploy-rc:\n    env:\n      LOADS: sentry,acme/dev/api\n";
        assert_eq!(
            shown(&lists(".github/workflows/ship.yml", by_job)),
            ["3 qa: sentry", "7 rc: sentry acme/dev/api"]
        );
        // An expression says nothing; names of two environments neither.
        let none = "jobs:\n  deploy:\n    environment: ${{ inputs.target }}\n    env:\n      LOADS: acme/dev/api,acme/prod/api\n";
        assert_eq!(
            shown(&lists(".github/workflows/ship.yml", none)),
            ["5 -: acme/dev/api acme/prod/api"]
        );
    }

    #[test]
    fn only_tracked_workflows_are_read() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let write = |rel: &str, text: &str| {
            let path = root.join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        };
        write(".github/workflows/a.yml", "env:\n  L: acme/dev/api\n");
        write(".github/workflows/b.yaml", "env:\n  L: acme/dev/db\n");
        write(".github/workflows/untracked.yml", "env:\n  L: sentry\n");
        write(".github/actions/x/action.yml", "env:\n  L: sentry\n");
        write("deploy.yml", "env:\n  L: sentry\n");
        let files: Vec<PathBuf> = [
            ".github/actions/x/action.yml",
            ".github/workflows/a.yml",
            ".github/workflows/b.yaml",
            ".github/workflows/gone.yml",
            "deploy.yml",
        ]
        .iter()
        .map(PathBuf::from)
        .collect();
        let names: Vec<String> = NAMES.iter().map(|n| (*n).to_owned()).collect();
        let found = secret_lists(root, &files, &names);
        assert_eq!(shown(&found), ["2 dev: acme/dev/api", "2 dev: acme/dev/db"]);
    }

    #[test]
    fn a_working_directory_is_a_folder_below_the_root() {
        assert_eq!(folder("./apps/api/"), Some(PathBuf::from("apps/api")));
        assert_eq!(folder("apps"), Some(PathBuf::from("apps")));
        for no in [".", "./", "/srv/app", "../other", "apps//api", ""] {
            assert_eq!(folder(no), None, "{no}");
        }
    }
}
