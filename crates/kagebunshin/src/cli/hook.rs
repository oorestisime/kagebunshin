//! `kagebunshin hook`: what Claude Code and OpenCode run when a session
//! starts and before a file is written, and `hook install`, which sets that
//! up for one agent.
//!
//! Both events read the agent's JSON on stdin and answer in Claude Code's
//! hook format; the OpenCode plugin speaks it too, so the checks live here
//! once. They fail open: anything that goes wrong (no config, not a git
//! checkout, unreadable input) prints nothing and exits 0, so a broken
//! setup never stops the agent. The only refusal is writing a real env
//! file (`.env`, `.env.*` but not `*.example`) in a registered project,
//! with a file tool or a shell command that plainly does so.

use std::io::Read;
use std::path::{Path, PathBuf};

use clap::{Subcommand, ValueEnum};
use serde::Deserialize;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::{CliError, Exit, print_json, print_line};
use crate::config::{ConfigDir, Git, MatchError, Registry};
use crate::types::ProjectName;

#[derive(Debug, Subcommand)]
pub enum HookAction {
    /// Set up the hooks for a coding agent
    ///
    /// claude adds them to ~/.claude/settings.json, keeping everything else
    /// in it; opencode writes the plugin ~/.config/opencode/plugins/kagebunshin.js.
    /// Running it again replaces them; `kagebunshin uninstall` removes them.
    Install {
        #[arg(value_enum)]
        agent: Agent,
    },
    /// Run by the agent when a session starts: tells it how this folder gets its secrets
    SessionStart,
    /// Run by the agent before a tool call: refuses writing a .env file in a registered project
    PreToolUse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Agent {
    /// Claude Code
    Claude,
    /// OpenCode
    Opencode,
}

/// The two events, as `kagebunshin hook <EVENT>` names them.
const EVENTS: [&str; 2] = ["session-start", "pre-tool-use"];

/// Claude Code's tools that write a file at `tool_input.file_path`.
const WRITE_TOOLS: [&str; 3] = ["Write", "Edit", "MultiEdit"];

/// Claude Code's shell tool, whose `tool_input.command` is checked for
/// plain writes to an env file.
const SHELL_TOOL: &str = "Bash";

pub fn run(json: bool, socket: Option<PathBuf>, action: HookAction) -> Result<(), CliError> {
    match action {
        HookAction::SessionStart => session_start(socket),
        HookAction::PreToolUse => pre_tool_use(),
        HookAction::Install { agent } => install(json, agent),
    }
}

/// The part of the agent's input the checks use. Anything else, the
/// contents of a file being written included, is ignored.
#[derive(Debug, Default, Deserialize)]
struct Event {
    cwd: Option<PathBuf>,
    tool_name: Option<String>,
    #[serde(default)]
    tool_input: ToolInput,
}

#[derive(Debug, Default, Deserialize)]
struct ToolInput {
    file_path: Option<PathBuf>,
    command: Option<String>,
}

fn read_input() -> Event {
    // A write's input holds the file's contents, which may be secrets.
    let mut text = Zeroizing::new(String::new());
    if std::io::stdin().read_to_string(&mut text).is_err() {
        return Event::default();
    }
    serde_json::from_str(&text).unwrap_or_default()
}

/// The project `dir`, or the closest folder above it that exists, is in.
fn project_at(dir: &Path) -> Option<ProjectName> {
    let config = ConfigDir::from_env().ok()?;
    let registry = Registry::load(&config).ok()?;
    let dir = dir.ancestors().find(|d| d.is_dir())?;
    let (project, _) = registry.resolve(&Git::default(), dir).ok()?;
    Some(project.name.clone())
}

fn session_start(socket: Option<PathBuf>) -> Result<(), CliError> {
    let input = read_input();
    let Some(cwd) = input.cwd.or_else(|| std::env::current_dir().ok()) else {
        return Ok(());
    };
    let context = match project_at(&cwd) {
        Some(project) => {
            let mut text = format!(
                "kagebunshin: this folder is in project {project}, registered with kagebunshin. \
                 Its secrets come from kagebunshin, not from a .env file: run commands that need \
                 them as `kagebunshin run -- COMMAND` (`--env ENV` for another environment). \
                 Writing a .env file here is refused. The kagebunshin skill has the rest."
            );
            let state = daemon_state(socket);
            let done = state.is_none() && proven(&project);
            if let Some(state) = state {
                text.push(' ');
                text.push_str(&state);
            }
            if !done {
                text.push(' ');
                text.push_str(NEXT);
            }
            text
        }
        None => match per_folder(&cwd).or_else(|| unregistered(&cwd)) {
            Some(text) => text,
            None => return Ok(()),
        },
    };
    print_json(&json!({
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": context,
        }
    }))
}

const NEXT: &str = "It has not been shown to work yet: run `kagebunshin next` and do what it says.";

/// Whether the default environment of `project` has a proof that still
/// holds: a `run --strict` that exited 0 since its sources last changed.
/// Read from the files, without asking the daemon.
fn proven(project: &ProjectName) -> bool {
    let proofs = || {
        let registry = Registry::load(&ConfigDir::from_env().ok()?).ok()?;
        let settings = registry.env(registry.project(project)?, None).ok()?;
        let log = crate::audit::AuditLog::from_env().ok()?;
        crate::daemon::proof::Proofs::beside(log.path()).get(&settings)
    };
    proofs().is_some()
}

/// For a folder of a checkout whose projects each claim a folder of their
/// own, none of them this one (the root of a repository of several apps):
/// which folders those are.
fn per_folder(cwd: &Path) -> Option<String> {
    let registry = Registry::load(&ConfigDir::from_env().ok()?).ok()?;
    let dir = cwd.ancestors().find(|d| d.is_dir())?;
    let Err(MatchError::NoPathMatches { projects, .. }) = registry.resolve(&Git::default(), dir)
    else {
        return None;
    };
    let list = projects
        .iter()
        .map(|(name, path)| format!("{name} ({path})"))
        .collect::<Vec<_>>()
        .join(", ");
    let mut text = format!(
        "kagebunshin: this repository has one kagebunshin project per folder: {list}. Their \
         secrets come from kagebunshin, not from a .env file: in one of those folders, run \
         commands that need them as `kagebunshin run -- COMMAND` (`--env ENV` for another \
         environment). Writing a .env file there is refused. The kagebunshin skill has the rest."
    );
    if !projects.iter().all(|(name, _)| proven(name)) {
        text.push_str(
            " Not all of them have been shown to work yet: run `kagebunshin next` and do what \
             it says.",
        );
    }
    Some(text)
}

/// For a folder in no project: how to start, if it has an env file or an
/// example of one, or is the root of a repository whose apps have, else
/// nothing.
fn unregistered(cwd: &Path) -> Option<String> {
    let start = "kagebunshin: kagebunshin is installed on this machine and can hold this \
                 checkout's secrets instead of a .env file.";
    if let Some(file) = crate::repo::env_file_with_values(cwd) {
        return Some(format!(
            "{start} {file} here has values: do not read it. They are moved into kagebunshin \
             with the human's approval; to set the project up, starting with that, run \
             `kagebunshin next` and do what it says."
        ));
    }
    let any_env_file = std::fs::read_dir(cwd).ok()?.any(|e| {
        e.ok()
            .and_then(|e| e.file_name().into_string().ok())
            .is_some_and(|n| {
                let n = n.to_ascii_lowercase();
                n == ".env" || n.starts_with(".env.")
            })
    });
    if any_env_file {
        return Some(format!(
            "{start} To set the project up, run `kagebunshin next` and do what it says."
        ));
    }
    if !cwd.join(".git").exists() {
        return None;
    }
    let apps = crate::repo::facts::read(cwd).apps;
    (apps.len() > 1).then(|| {
        let dirs: Vec<_> = (apps.iter())
            .map(|a| a.dir.to_string_lossy().into_owned())
            .collect();
        format!(
            "{start} This repository has several apps ({}), each its own project: do not read \
             their .env files; to set them up, run `kagebunshin next` and do what it says.",
            dirs.join(", ")
        )
    })
}

/// A sentence for a daemon that is not running or is locked, as a short
/// `status` finds it; `None` when it is unlocked or anything goes wrong.
fn daemon_state(socket: Option<PathBuf>) -> Option<String> {
    use crate::ipc::client::{Client, ClientError};
    use crate::ipc::protocol::{Request, Response};

    let socket = match socket {
        Some(p) => p,
        None => crate::ipc::paths::default_socket_path().ok()?,
    };
    let mut client = match Client::connect(&socket, std::time::Duration::from_secs(1)) {
        Ok(c) => c,
        Err(ClientError::NotRunning { .. }) => {
            return Some(format!(
                "The kagebunshin daemon is not running, so `kagebunshin run` fails until the \
                 human starts it: {}.",
                super::error::start_daemon_hint()
            ));
        }
        Err(_) => return None,
    };
    match client.request(Request::Status { facts: None }) {
        Ok(Response::Status(s)) if s.locked => Some(
            "The kagebunshin daemon is locked, so `kagebunshin run` fails until the human \
             unlocks it with `kagebunshin unlock`."
                .to_owned(),
        ),
        _ => None,
    }
}

fn pre_tool_use() -> Result<(), CliError> {
    let input = read_input();
    let cwd = input.cwd.or_else(|| std::env::current_dir().ok());
    let files = match (input.tool_name.as_deref(), input.tool_input) {
        (
            Some(tool),
            ToolInput {
                file_path: Some(file),
                ..
            },
        ) if WRITE_TOOLS.contains(&tool) => vec![match &cwd {
            Some(cwd) => cwd.join(file),
            None => file,
        }],
        (
            Some(SHELL_TOOL),
            ToolInput {
                command: Some(command),
                ..
            },
        ) => shell_targets(&command, cwd.as_deref()),
        _ => return Ok(()),
    };
    let Some((file, project)) = files.into_iter().find_map(|file| {
        if !file.file_name().is_some_and(crate::repo::is_real_env_file) {
            return None;
        }
        let project = file.parent().and_then(project_at)?;
        Some((file, project))
    }) else {
        return Ok(());
    };
    print_json(&json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": format!(
                "kagebunshin: {} is in project {project}, whose secrets come from kagebunshin, \
                 so writing a .env file there is refused. Run the command that needs the \
                 secrets as `kagebunshin run -- COMMAND` instead; to add or change a secret, \
                 ask the human.",
                file.display()
            ),
        }
    }))
}

/// The files a shell command plainly creates or overwrites: the targets of
/// `>` and `>>`, of `cp`, `mv`, `install` and `ln` (the last argument, or a
/// file in it when it is a folder), and of `tee` and `touch`. Relative ones
/// are taken from `cwd`, after a `cd DIR` earlier in the command. A guard
/// against the common accident, not a shell parser: quoting is undone, but
/// `sh -c`, variables, globs and the like are not looked into.
fn shell_targets(command: &str, cwd: Option<&Path>) -> Vec<PathBuf> {
    let mut base = cwd.map(Path::to_path_buf);
    let mut targets = Vec::new();
    for words in simple_commands(command) {
        let mut args: Vec<String> = Vec::new();
        let mut words = words.into_iter();
        while let Some(word) = words.next() {
            match word {
                Word::Redirect => {
                    if let Some(Word::Text(t)) = words.next() {
                        targets.extend(resolve(&t, base.as_deref()));
                    }
                }
                Word::Input => {
                    words.next();
                }
                Word::Text(t) => args.push(t),
            }
        }
        // `FOO=bar cp ...`
        let args: Vec<&str> = args
            .iter()
            .map(String::as_str)
            .skip_while(|a| a.split_once('=').is_some_and(|(k, _)| is_name(k)))
            .collect();
        let Some((program, args)) = args.split_first() else {
            continue;
        };
        let operands = || {
            let mut after_dashes = false;
            args.iter().copied().filter(move |a| {
                if after_dashes {
                    return true;
                }
                if *a == "--" {
                    after_dashes = true;
                    return false;
                }
                !a.starts_with('-')
            })
        };
        match program.rsplit('/').next().unwrap_or(program) {
            "cd" => {
                base = match operands().collect::<Vec<_>>().as_slice() {
                    [dir] => resolve(dir, base.as_deref()),
                    _ => None,
                };
            }
            "tee" | "touch" => {
                targets.extend(operands().filter_map(|a| resolve(a, base.as_deref())));
            }
            "cp" | "mv" | "install" | "ln" => {
                let operands: Vec<&str> = operands().collect();
                let target_dir = args.iter().enumerate().find_map(|(i, a)| {
                    a.strip_prefix("--target-directory=")
                        .or_else(|| (*a == "-t").then(|| args.get(i + 1).copied()).flatten())
                });
                let (sources, dir) = match (target_dir, operands.split_last()) {
                    (Some(dir), _) => (operands.as_slice(), resolve(dir, base.as_deref())),
                    (None, Some((last, sources))) => {
                        let Some(target) = resolve(last, base.as_deref()) else {
                            continue;
                        };
                        if !target.is_dir() {
                            targets.push(target);
                            continue;
                        }
                        (sources, Some(target))
                    }
                    (None, None) => continue,
                };
                let Some(dir) = dir else { continue };
                targets.extend(
                    sources
                        .iter()
                        .filter_map(|s| Path::new(s).file_name())
                        .map(|name| dir.join(name)),
                );
            }
            _ => {}
        }
    }
    targets
}

/// A word of a shell command, quoting undone, or a redirect, whose target
/// is the next word.
#[derive(Debug, PartialEq, Eq)]
enum Word {
    Text(String),
    /// `>`, `>>`, `>|`, `&>`: the next word is written.
    Redirect,
    /// `<`, `<<`, `<<<`, `>&`: the next word is read, or names a descriptor.
    Input,
}

/// The command's simple commands, split at `;`, `&&`, `||`, `|`, `&`,
/// newlines and parentheses.
fn simple_commands(command: &str) -> Vec<Vec<Word>> {
    let mut commands = vec![Vec::new()];
    let mut word: Option<String> = None;
    let mut chars = command.chars().peekable();
    fn end(word: &mut Option<String>, commands: &mut [Vec<Word>]) {
        if let (Some(w), Some(c)) = (word.take(), commands.last_mut()) {
            c.push(Word::Text(w));
        }
    }
    let push = |commands: &mut Vec<Vec<Word>>, w: Word| {
        if let Some(c) = commands.last_mut() {
            c.push(w);
        }
    };
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                let w = word.get_or_insert_with(String::new);
                for c in chars.by_ref() {
                    if c == '\'' {
                        break;
                    }
                    w.push(c);
                }
            }
            '"' => {
                let w = word.get_or_insert_with(String::new);
                while let Some(c) = chars.next() {
                    match c {
                        '"' => break,
                        '\\' => {
                            if let Some(c) = chars.next() {
                                w.push(c);
                            }
                        }
                        c => w.push(c),
                    }
                }
            }
            '\\' => {
                if let Some(c) = chars.next() {
                    word.get_or_insert_with(String::new).push(c);
                }
            }
            '>' => {
                // `2>`: the digits name a descriptor, not a word.
                if word
                    .as_deref()
                    .is_some_and(|w| w.bytes().all(|b| b.is_ascii_digit()))
                {
                    word = None;
                }
                end(&mut word, &mut commands);
                if chars.next_if(|c| *c == '&').is_some() {
                    push(&mut commands, Word::Input);
                } else {
                    chars.next_if(|c| *c == '>' || *c == '|');
                    push(&mut commands, Word::Redirect);
                }
            }
            '<' => {
                end(&mut word, &mut commands);
                while chars.next_if(|c| *c == '<').is_some() {}
                push(&mut commands, Word::Input);
            }
            '&' if chars.peek() == Some(&'>') => {
                end(&mut word, &mut commands);
                chars.next();
                chars.next_if(|c| *c == '>');
                push(&mut commands, Word::Redirect);
            }
            ';' | '&' | '|' | '\n' | '(' | ')' => {
                end(&mut word, &mut commands);
                chars.next_if(|n| (c == '&' || c == '|') && *n == c);
                commands.push(Vec::new());
            }
            c if c.is_whitespace() => end(&mut word, &mut commands),
            c => word.get_or_insert_with(String::new).push(c),
        }
    }
    end(&mut word, &mut commands);
    commands
}

/// `word` as a path: absolute, under HOME for `~/`, else from `base`.
/// `None` when it cannot be told: variables, globs, no base.
fn resolve(word: &str, base: Option<&Path>) -> Option<PathBuf> {
    if word.is_empty() || word.contains(['$', '*', '?', '[', '`']) {
        return None;
    }
    if let Some(rest) = word.strip_prefix("~/") {
        return std::env::var_os("HOME").map(|h| Path::new(&h).join(rest));
    }
    let path = Path::new(word);
    if path.is_absolute() {
        return Some(path.to_owned());
    }
    if word.starts_with('~') {
        return None;
    }
    base.map(|b| b.join(path))
}

/// A shell variable name, as in `NAME=value`.
fn is_name(s: &str) -> bool {
    s.chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn failed(message: impl Into<String>) -> CliError {
    CliError::new(Exit::Failure, "hooks", message.into())
}

/// Where each agent's hook config lives: Claude Code's settings file and
/// the OpenCode plugin.
pub(super) fn paths() -> Result<(PathBuf, PathBuf), CliError> {
    let var = |k: &str| {
        std::env::var_os(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
    };
    let home = var("HOME").ok_or_else(|| failed("HOME is not set to an absolute path"))?;
    let config_home = var("XDG_CONFIG_HOME").unwrap_or_else(|| home.join(".config"));
    Ok((
        home.join(".claude/settings.json"),
        config_home.join("opencode/plugins/kagebunshin.js"),
    ))
}

fn install(json: bool, agent: Agent) -> Result<(), CliError> {
    let exe = std::env::current_exe()
        .map_err(|e| failed(format!("cannot tell where this binary is: {e}")))?;
    let exe = exe
        .to_str()
        .ok_or_else(|| failed(format!("{} is not UTF-8", exe.display())))?;
    let (claude, opencode) = paths()?;
    let (path, text, name) = match agent {
        Agent::Claude => {
            let path = real(&claude);
            let mut doc = read_settings(&path)?.unwrap_or_else(|| json!({}));
            add_claude(&mut doc, exe)?;
            let mut text = serde_json::to_string_pretty(&doc).map_err(|e| failed(e.to_string()))?;
            text.push('\n');
            (path, text, "Claude Code")
        }
        Agent::Opencode => (opencode, opencode_plugin(exe), "OpenCode"),
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| failed(format!("cannot create {}: {e}", dir.display())))?;
    }
    crate::atomic::write_private(&path, text.as_bytes())
        .map_err(|e| failed(format!("cannot write {}: {e}", path.display())))?;
    if json {
        return print_json(&json!({ "agent": name, "path": path }));
    }
    print_line(&format!("installed the {name} hooks in {}", path.display()))
}

/// A settings file through its symlink, so a link into a dotfiles
/// repository is kept.
fn real(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_owned())
}

/// The settings file, or `None` if there is none (or it is empty).
fn read_settings(path: &Path) -> Result<Option<Value>, CliError> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(failed(format!("cannot read {}: {e}", path.display()))),
    };
    if text.trim().is_empty() {
        return Ok(None);
    }
    let doc: Value = serde_json::from_str(&text).map_err(|e| {
        failed(format!(
            "cannot read {}: {e}; it was left as it was",
            path.display()
        ))
    })?;
    if !doc.is_object() {
        return Err(failed(format!(
            "{} is not a JSON object; it was left as it was",
            path.display()
        )));
    }
    Ok(Some(doc))
}

/// `exe`, quoted for `sh`.
fn shell_quote(exe: &str) -> String {
    format!("'{}'", exe.replace('\'', r"'\''"))
}

/// One of the hooks `add_claude` writes, by its command.
fn is_ours(hook: &Value) -> bool {
    hook["command"].as_str().is_some_and(|c| {
        c.contains("kagebunshin") && EVENTS.iter().any(|e| c.ends_with(&format!(" hook {e}")))
    })
}

/// Takes kagebunshin's hooks out of Claude Code settings, and the groups,
/// events and `hooks` table that only held them. True if any were there.
fn remove_claude_hooks(doc: &mut Value) -> bool {
    let Some(hooks) = doc.get_mut("hooks").and_then(Value::as_object_mut) else {
        return false;
    };
    let mut changed = false;
    for event in ["SessionStart", "PreToolUse"] {
        let Some(groups) = hooks.get_mut(event).and_then(Value::as_array_mut) else {
            continue;
        };
        groups.retain_mut(|g| {
            let Some(list) = g.get_mut("hooks").and_then(Value::as_array_mut) else {
                return true;
            };
            let before = list.len();
            list.retain(|h| !is_ours(h));
            if list.len() == before {
                return true;
            }
            changed = true;
            !list.is_empty()
        });
        if groups.is_empty() {
            hooks.remove(event);
        }
    }
    if changed
        && hooks.is_empty()
        && let Some(doc) = doc.as_object_mut()
    {
        doc.remove("hooks");
    }
    changed
}

/// Replaces kagebunshin's hooks in Claude Code settings with ones that run
/// `exe`, keeping everything else.
fn add_claude(doc: &mut Value, exe: &str) -> Result<(), CliError> {
    remove_claude_hooks(doc);
    let hook = |event: &str| {
        json!({
            "type": "command",
            "command": format!("{} hook {event}", shell_quote(exe)),
            "timeout": 10,
        })
    };
    let bad = || {
        failed(
            "the `hooks` in the Claude Code settings are not in the form it documents; they were left as they were",
        )
    };
    let hooks = doc
        .as_object_mut()
        .ok_or_else(bad)?
        .entry("hooks")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(bad)?;
    for (event, group) in [
        ("SessionStart", json!({ "hooks": [hook("session-start")] })),
        (
            "PreToolUse",
            json!({
                "matcher": format!("{}|{SHELL_TOOL}", WRITE_TOOLS.join("|")),
                "hooks": [hook("pre-tool-use")],
            }),
        ),
    ] {
        hooks
            .entry(event)
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .ok_or_else(bad)?
            .push(group);
    }
    Ok(())
}

/// Whether the Claude Code settings at `path` have kagebunshin's hooks.
pub(super) fn has_claude_hooks(path: &Path) -> bool {
    read_settings(&real(path))
        .ok()
        .flatten()
        .is_some_and(|mut doc| remove_claude_hooks(&mut doc))
}

/// Takes kagebunshin's hooks out of the Claude Code settings at `path`,
/// leaving the rest of the file as it was.
pub(super) fn remove_claude(path: &Path) -> Result<(), CliError> {
    let path = real(path);
    let Some(mut doc) = read_settings(&path)? else {
        return Ok(());
    };
    if !remove_claude_hooks(&mut doc) {
        return Ok(());
    }
    let mut text = serde_json::to_string_pretty(&doc).map_err(|e| failed(e.to_string()))?;
    text.push('\n');
    crate::atomic::write_private(&path, text.as_bytes())
        .map_err(|e| failed(format!("cannot write {}: {e}", path.display())))
}

/// The OpenCode plugin: the session-start context in every model request
/// of a session, and the `.env` check on every edit and shell permission,
/// both through `exe`. A shell call is checked whole, in its own working
/// folder, as Claude Code hands it over.
fn opencode_plugin(exe: &str) -> String {
    let exe = Value::from(exe);
    format!(
        r#"// Written by `kagebunshin hook install opencode`; `kagebunshin uninstall`
// removes it. It runs `kagebunshin hook` with the input Claude Code hooks
// get, so the checks live in kagebunshin.
import {{ spawnSync }} from "node:child_process"
import path from "node:path"

const KAGEBUNSHIN = {exe}

function hook(event, input) {{
  try {{
    const run = spawnSync(KAGEBUNSHIN, ["hook", event], {{
      input: JSON.stringify(input),
      encoding: "utf8",
      timeout: 10000,
    }})
    if (run.status !== 0 || !run.stdout) return undefined
    return JSON.parse(run.stdout).hookSpecificOutput
  }} catch {{
    return undefined
  }}
}}

export default {{
  id: "kagebunshin",
  async setup(ctx) {{
    const dir = ctx.location.directory
    const context = hook("session-start", {{ cwd: dir }})?.additionalContext
    if (context) {{
      await ctx.session.hook("context", (event) => {{
        event.system.push({{ type: "text", text: context }})
      }})
    }}
    // A shell permission lists the call's simple commands one by one, with
    // its `cd`s and its working folder left out, so it cannot say which
    // folder a relative `.env` is in. The call can: keep it from the tool
    // hook, which runs first, and check that instead.
    const shells = new Map()
    await ctx.tool.hook("execute.before", (event) => {{
      if (event.tool !== "shell" || typeof event.input?.command !== "string") return
      if (shells.size >= 64) shells.delete(shells.keys().next().value)
      shells.set(event.id, event.input)
    }})
    await ctx.tool.hook("execute.after", (event) => {{
      shells.delete(event.id)
    }})
    await ctx.permission.hook("evaluate", (event) => {{
      let inputs = []
      if (event.action === "edit") {{
        inputs = event.resources
          .filter((file) => /^\.env/i.test(path.basename(file)))
          .map((file) => ({{ cwd: dir, tool_name: "Write", tool_input: {{ file_path: path.resolve(dir, file) }} }}))
      }} else if (event.action === "shell") {{
        const call = shells.get(event.source?.id)
        const cwd = typeof call?.workdir === "string" ? path.resolve(dir, call.workdir) : dir
        inputs = (call ? [call.command] : event.resources)
          .filter((command) => /\.env/i.test(command))
          .map((command) => ({{ cwd, tool_name: "Bash", tool_input: {{ command }} }}))
      }}
      for (const input of inputs) {{
        const out = hook("pre-tool-use", input)
        if (out?.permissionDecision === "deny") {{
          event.effect = "deny"
          event.message = out.permissionDecisionReason
          return
        }}
      }}
    }})
  }},
}}
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Installing twice leaves one copy, keeps the user's own settings and
    /// hooks, and removing takes out only kagebunshin's.
    #[test]
    fn claude_settings_keep_everything_else() {
        let user = json!({
            "model": "opus",
            "hooks": {
                "PreToolUse": [{
                    "matcher": "Bash",
                    "hooks": [{ "type": "command", "command": "my-check" }],
                }],
            },
        });
        let mut doc = user.clone();
        add_claude(&mut doc, "/opt/it's/kagebunshin").unwrap();
        add_claude(&mut doc, "/opt/it's/kagebunshin").unwrap();
        assert_eq!(doc["model"], "opus");
        let pre = doc["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 2, "{doc}");
        assert_eq!(pre[1]["matcher"], "Write|Edit|MultiEdit|Bash");
        assert_eq!(
            pre[1]["hooks"][0]["command"],
            r"'/opt/it'\''s/kagebunshin' hook pre-tool-use"
        );
        assert_eq!(doc["hooks"]["SessionStart"].as_array().unwrap().len(), 1);

        assert!(remove_claude_hooks(&mut doc));
        assert_eq!(doc, user);
        assert!(!remove_claude_hooks(&mut doc));

        let mut doc = json!({ "model": "opus" });
        add_claude(&mut doc, "/bin/kagebunshin").unwrap();
        remove_claude_hooks(&mut doc);
        assert_eq!(doc, json!({ "model": "opus" }));

        let mut doc = json!({ "hooks": [] });
        assert_eq!(
            add_claude(&mut doc, "/bin/kagebunshin").unwrap_err().code,
            "hooks"
        );
    }

    /// The env files among what each command writes, as names relative to
    /// the folder it runs in.
    fn written_env_files(command: &str) -> Vec<String> {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().join("repo");
        std::fs::create_dir_all(cwd.join("sub")).unwrap();
        shell_targets(command, Some(&cwd))
            .into_iter()
            .filter(|p| p.file_name().is_some_and(crate::repo::is_real_env_file))
            .map(|p| {
                p.strip_prefix(&cwd)
                    .map_or_else(|_| p.display().to_string(), |r| r.display().to_string())
            })
            .collect()
    }

    #[test]
    fn shell_writes_of_env_files_are_found() {
        for (command, want) in [
            ("cp .env.example .env", vec![".env"]),
            ("echo \"A=1\" > .env", vec![".env"]),
            ("echo A=1 >>.env.local", vec![".env.local"]),
            ("printf 'A=1' 2> err.log 1>'.env'", vec![".env"]),
            ("make &> .env", vec![".env"]),
            ("cat <<EOF > .env", vec![".env"]),
            ("mv -f old .env.production", vec![".env.production"]),
            ("install -m 600 x sub/.env", vec!["sub/.env"]),
            ("ln -s ../shared/.env .env", vec![".env"]),
            ("ln -s ../shared/.env sub", vec!["sub/.env"]),
            ("cp -t sub backup/.env", vec!["sub/.env"]),
            (
                "echo A | tee -a .env .env.local",
                vec![".env", ".env.local"],
            ),
            ("touch .env", vec![".env"]),
            ("cd sub && cp ../.env.example .env", vec!["sub/.env"]),
            ("npm ci; FOO=1 cp a .env || true", vec![".env"]),
            ("cp a \\.env", vec![".env"]),
            ("cp a /tmp/x/.env", vec!["/tmp/x/.env"]),
        ] {
            assert_eq!(written_env_files(command), want, "{command}");
        }
    }

    #[test]
    fn reading_or_mentioning_an_env_file_is_not_a_write() {
        for command in [
            "cat .env",
            "grep FOO .env.example",
            "git add .env.example",
            "cp .env.example sub/.env.example",
            "echo hi > .env.example",
            "diff .env .env.example 2>&1",
            "source .env && npm test",
            "cmd < .env > out.txt",
            "cp a $DIR/.env",
            "cp a .env*",
            "sh -c 'cp a .env'",
            "",
        ] {
            assert!(written_env_files(command).is_empty(), "{command}");
        }
    }

    #[test]
    fn the_plugin_names_the_binary_as_a_js_string() {
        let js = opencode_plugin("/opt/a \"b\"/kagebunshin");
        assert!(
            js.contains(r#"const KAGEBUNSHIN = "/opt/a \"b\"/kagebunshin""#),
            "{js}"
        );
    }
}
