//! What an approval prompt says of a request, in words: the same in the
//! app's window and on the paired phone's page, so a person reads one
//! account of a request wherever they answer it.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::protocol::{ApprovalPrompt, ApprovalReason, ImportNames};
use crate::types::KeyName;

/// The shells whose `-c SCRIPT` a prompt shows as the command.
const SHELLS: [&str; 6] = ["sh", "bash", "zsh", "dash", "ksh", "fish"];

/// The coding agents a prompt names when one is among the processes a
/// caller descends from: the process's name, and what to call it.
const AGENTS: [(&str, &str); 9] = [
    ("claude", "Claude Code"),
    ("opencode", "OpenCode"),
    ("codex", "Codex"),
    ("cursor-agent", "Cursor"),
    ("gemini", "Gemini CLI"),
    ("aider", "Aider"),
    ("amp", "Amp"),
    ("goose", "Goose"),
    ("copilot", "GitHub Copilot"),
];

/// What a request asks a person to type: "the value of KEY", or "3 values".
pub fn values_of(keys: &[KeyName]) -> String {
    match keys {
        [one] => format!("the value of {one}"),
        many => format!("{} values", many.len()),
    }
}

/// How many files `sections` come from, as "3 env files".
pub fn import_files(sections: &[ImportNames]) -> String {
    let files: BTreeSet<&PathBuf> = sections.iter().flat_map(|s| &s.files).collect();
    match files.len() {
        1 => "1 env file".to_owned(),
        n => format!("{n} env files"),
    }
}

/// The script of a command that hands one to a shell (`sh -c SCRIPT`,
/// `bash -lc SCRIPT`), with the shell as it was called and what follows
/// the script: the script is what runs, so it is what a person reads.
pub fn shell_script(argv: &[String]) -> Option<(String, &str, &[String])> {
    let (program, rest) = argv.split_first()?;
    let name = Path::new(program).file_name()?.to_str()?;
    if !SHELLS.contains(&name) {
        return None;
    }
    // Options only before `-c` or a bundle ending in it, such as `-lc`.
    let at = rest
        .iter()
        .position(|a| !a.starts_with('-') || a.ends_with('c'))?;
    let flag = &rest[at];
    if !flag.starts_with('-') || flag.starts_with("--") {
        return None;
    }
    let script = rest.get(at + 1)?;
    Some((format!("{name} {flag}"), script, &rest[at + 2..]))
}

/// A prompt in words. Names only, as the prompt itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Words {
    /// What is asked, in one line.
    pub title: String,
    /// What `command` is: a command, or a script and the shell it is
    /// handed to.
    pub command_label: String,
    /// The command line, or the script of one that hands a shell a script.
    pub command: String,
    /// What it wants, above the prompt's keys.
    pub wants: String,
    /// Above who asks.
    pub asked_label: &'static str,
    /// Who asks: a coding agent, a process or a machine.
    pub who: String,
    /// Where, following `who` on its line.
    pub place: String,
    /// How the request got here: the processes it descends from, or what
    /// another machine reports.
    pub detail: String,
    /// Why it waits for a person; empty where the title says it all.
    pub why: String,
    /// What approving does.
    pub trust: &'static str,
}

impl Words {
    #[expect(clippy::too_many_lines, reason = "one arm for each kind of prompt")]
    pub fn of(prompt: &ApprovalPrompt) -> Self {
        let of = format!("{}/{}", prompt.project, prompt.env);
        let (asks_for, why) = match &prompt.reason {
            // Why is what the line above the passphrase says: not said twice.
            ApprovalReason::Import { sections, .. } => (
                format!("to import {} into the local store", import_files(sections)),
                String::new(),
            ),
            ApprovalReason::Type { .. } => (
                format!("you to type {} for {of}", values_of(&prompt.keys)),
                String::new(),
            ),
            ApprovalReason::Keys => (
                format!("sensitive values of {of}"),
                // A secret's mark holds in every environment that reads it.
                match prompt.secrets.as_slice() {
                    [] => format!(
                        "These values are marked sensitive one by one. {of} itself is not marked."
                    ),
                    [one] => format!(
                        "Secret {one} is marked sensitive wherever it is read. {of} itself is \
                         not marked."
                    ),
                    many => format!(
                        "Secrets {} are marked sensitive wherever they are read. {of} itself is \
                         not marked.",
                        many.iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                },
            ),
            ApprovalReason::Marked => (
                format!("{of}, marked sensitive"),
                format!("{of} is marked sensitive: every value it sets takes a person's approval."),
            ),
            ApprovalReason::Waiting { why } => (
                format!("{of}, which looks like production"),
                format!(
                    "{of} looks like production ({why}) and nobody has decided whether it is. \
                     Approving does not decide that: do it afterwards on the Projects page, in \
                     \u{201c}waits for your decision\u{201d}."
                ),
            ),
        };
        let writes = matches!(
            prompt.reason,
            ApprovalReason::Import { .. } | ApprovalReason::Type { .. }
        );
        // Another machine's command line and folder are only what it says;
        // tailscaled vouches for the machine and user, nothing more.
        let title = match &prompt.remote {
            _ if writes => format!("A command asks {asks_for}"),
            Some(r) => format!("Machine {} asks for {asks_for}", r.machine),
            None => format!("A command asks for {asks_for}"),
        };
        let reported = if prompt.remote.is_some() {
            " (as the remote machine reports it)"
        } else {
            ""
        };

        // The command: a script handed to a shell is shown as the script.
        let (command_label, command) = match shell_script(&prompt.argv) {
            Some((shell, script, [])) => (format!("Script, run by {shell}{reported}"), script),
            Some((shell, script, more)) => (
                format!(
                    "Script, run by {shell} with the arguments {}{reported}",
                    more.join(" ")
                ),
                script,
            ),
            None => (format!("Command{reported}"), prompt.command.as_str()),
        };

        // The keys. For a whole environment the daemon has not read it yet:
        // they are the ones the command expects (the checkout's .env.example,
        // or the one asked for), not ones known to be set. With no
        // .env.example it gets every key: those the daemon knows of, if any.
        const UNLISTED: &str = "no .env.example here lists the ones it needs";
        let wants = match (&prompt.reason, prompt.keys.len()) {
            (ApprovalReason::Import { sections, .. }, _) => {
                let keys: usize = sections.iter().map(|s| s.keys.len()).sum();
                format!(
                    "Writes {keys} {}, by name; the values are read from the files",
                    if keys == 1 { "key" } else { "keys" }
                )
            }
            // Locked, the daemon cannot say which keys have a value now.
            (ApprovalReason::Type { unlock, .. }, n) => format!(
                "{}{}",
                if n == 1 {
                    "Type its value, on one line"
                } else {
                    "Type the values, one line each. A key left empty stays as it is"
                },
                if *unlock {
                    ". One that has a value now gets the new one"
                } else {
                    ""
                }
            ),
            (ApprovalReason::Keys, 1) => "Wants 1 value marked sensitive".to_owned(),
            (ApprovalReason::Keys, n) => format!("Wants {n} values marked sensitive"),
            (_, 0) if prompt.every_key => format!("Wants every key {of} sets: {UNLISTED}"),
            (_, 1) if prompt.every_key => format!("Wants the one key {of} sets: {UNLISTED}"),
            (_, n) if prompt.every_key => format!("Wants all {n} keys {of} sets: {UNLISTED}"),
            (_, 0) => format!("Wants every value {of} sets"),
            (_, 1) => format!("Wants every value {of} sets. It expects this key"),
            (_, n) => format!("Wants every value {of} sets. It expects these {n} keys"),
        };

        // Who asks, in one line, and under it how the request got here.
        // Process names are what the processes call themselves, which the
        // label says.
        let agent = prompt
            .parents
            .iter()
            .find_map(|name| AGENTS.iter().find(|(process, _)| process == name))
            .map(|(_, agent)| *agent);
        let (who, place, detail, asked_label) = if let Some(r) = &prompt.remote {
            let mut detail = format!("in {} there, as it reports", prompt.cwd.display());
            if !r.tags.is_empty() {
                detail.push_str(&format!(" \u{00b7} tags {}", r.tags.join(", ")));
            }
            (
                format!("Machine {}", r.machine),
                format!(", user {}", r.user),
                detail,
                "Asked by",
            )
        } else {
            let pid = format!("pid {}", prompt.pid);
            let chain: Vec<&str> = prompt.parents.iter().rev().map(String::as_str).collect();
            (
                agent.unwrap_or("A process").to_owned(),
                format!(" in {}", prompt.cwd.display()),
                if chain.is_empty() {
                    pid
                } else {
                    format!("{} \u{00b7} {pid}", chain.join(" \u{203a} "))
                },
                if chain.is_empty() {
                    "Asked by"
                } else {
                    "Asked by (names as the processes give them)"
                },
            )
        };

        let trust = match &prompt.reason {
            ApprovalReason::Import { unlock: true, .. } => {
                "Approving writes these values to the local store, which takes its \
                 passphrase, and unlocks kagebunshin. The files stay where they are. It \
                 covers this one request."
            }
            ApprovalReason::Import { unlock: false, .. } => {
                "Approving writes these values to the local store, which takes its \
                 passphrase. The files stay where they are. It covers this one request."
            }
            ApprovalReason::Type { unlock: true, .. } => {
                "Saving writes what you typed to the local store, which takes its \
                 passphrase, and unlocks kagebunshin. The command is told which keys were \
                 set, never a value."
            }
            ApprovalReason::Type { unlock: false, .. } => {
                "Saving writes what you typed to the local store, which takes its \
                 passphrase. The command is told which keys were set, never a value."
            }
            ApprovalReason::Keys | ApprovalReason::Marked | ApprovalReason::Waiting { .. } => {
                "Approving trusts this command: it gets the values and can print, save or \
                 send them anywhere. It covers this one request."
            }
        };

        Self {
            title,
            command_label,
            command: command.to_owned(),
            wants,
            asked_label,
            who,
            place,
            detail,
            why,
            trust,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A script handed to a shell is the command a person reads, with the
    /// shell named beside it; anything else is not one.
    #[test]
    fn a_script_handed_to_a_shell_is_shown_as_the_command() {
        let argv = |words: &[&str]| words.iter().map(|w| (*w).to_owned()).collect::<Vec<_>>();
        let script = |words: &[&str]| {
            let argv = argv(words);
            shell_script(&argv).map(|(shell, script, more)| (shell, script.to_owned(), more.len()))
        };
        assert_eq!(
            script(&["/bin/bash", "-lc", "make deploy"]),
            Some(("bash -lc".into(), "make deploy".into(), 0))
        );
        assert_eq!(
            script(&["sh", "-e", "-c", "echo $0", "name"]),
            Some(("sh -c".into(), "echo $0".into(), 1))
        );
        for not_a_script in [
            &["bash", "deploy.sh", "-c"][..],
            &["bash", "-c"],
            &["bash", "--rcfile", "x"],
            &["npm", "-c", "x"],
            &[],
        ] {
            assert_eq!(script(not_a_script), None, "{not_a_script:?}");
        }
    }
}
