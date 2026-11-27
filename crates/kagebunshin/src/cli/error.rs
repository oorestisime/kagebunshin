//! Stable exit codes and the error shape the CLI prints.
//!
//! Scripts and agents branch on these, so codes are only ever added, never
//! renumbered. With `--json`, errors go to stderr as one line of
//! `{"code": ..., "message": ..., "hint": ..., "who": ..., "tell": ...}`;
//! `code` is a stable string and `hint` is `null` when there is none. `who`
//! is `"agent"` when the caller can fix it itself, `"human"` when it takes
//! the passphrase, the app, a browser login or a decision, and `null` when
//! that is not known; `tell` is, for a human step, one sentence to pass on
//! to them as it is. Warnings go to stderr as one line of
//! `{"warning": ...}` each.
//!
//! | exit | meaning                                        |
//! |------|------------------------------------------------|
//! | 0    | success                                        |
//! | 1    | failure not covered below                      |
//! | 2    | usage error (bad flags or arguments)           |
//! | 3    | the daemon is not running                      |
//! | 4    | the CLI and daemon builds differ               |
//! | 5    | refused until a human acts: locked, permission |
//! |      | denied, unsafe socket, a sensitive environment |
//! |      | or key, approval denied or not given           |
//! | 6    | the command is not implemented yet             |

use std::io::{self, Write};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::Serialize;

use crate::daemon::broker::UNLOCK_TELL;
use crate::ipc::client::ClientError;
use crate::ipc::protocol::{ErrorCode, Who};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    Success,
    Failure,
    Usage,
    DaemonNotRunning,
    BuildMismatch,
    Refused,
    NotImplemented,
}

impl Exit {
    pub const ALL: [Exit; 7] = [
        Exit::Success,
        Exit::Failure,
        Exit::Usage,
        Exit::DaemonNotRunning,
        Exit::BuildMismatch,
        Exit::Refused,
        Exit::NotImplemented,
    ];

    pub fn code(self) -> u8 {
        match self {
            Exit::Success => 0,
            Exit::Failure => 1,
            Exit::Usage => 2,
            Exit::DaemonNotRunning => 3,
            Exit::BuildMismatch => 4,
            Exit::Refused => 5,
            Exit::NotImplemented => 6,
        }
    }
}

impl From<Exit> for ExitCode {
    fn from(e: Exit) -> Self {
        ExitCode::from(e.code())
    }
}

#[derive(Debug, Serialize)]
pub struct CliError {
    #[serde(skip)]
    pub exit: Exit,
    pub code: &'static str,
    pub message: String,
    pub hint: Option<String>,
    /// Who can fix it, when that is known.
    pub who: Option<Who>,
    /// For a human step: one sentence the caller can pass on as it is.
    pub tell: Option<String>,
}

impl CliError {
    pub fn new(exit: Exit, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            exit,
            code,
            message: message.into(),
            hint: None,
            who: None,
            tell: None,
        }
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    /// Only a human can fix it, by doing `tell`.
    pub fn human(mut self, tell: impl Into<String>) -> Self {
        self.who = Some(Who::Human);
        self.tell = Some(tell.into());
        self
    }

    /// The caller can fix it itself, as the hint says.
    pub fn agent(mut self) -> Self {
        self.who = Some(Who::Agent);
        self
    }

    /// The daemon is locked, and only a human can unlock it.
    pub fn locked() -> Self {
        Self::new(Exit::Refused, "locked", "the daemon is locked")
            .with_hint(UNLOCK_TELL)
            .human(UNLOCK_TELL)
    }

    pub fn not_implemented(command: &str) -> Self {
        Self::new(
            Exit::NotImplemented,
            "not_implemented",
            format!("`kagebunshin {command}` is not implemented yet"),
        )
    }

    /// Writes the error to stderr and returns the process exit code.
    pub fn report(&self, json: bool) -> ExitCode {
        let mut err = io::stderr().lock();
        let _ = if json {
            let line = serde_json::to_string(self).unwrap_or_else(|_| {
                r#"{"code":"internal","message":"cannot encode error","hint":null,"who":null,"tell":null}"#.into()
            });
            writeln!(err, "{line}")
        } else {
            write!(err, "{}", self.text())
        };
        self.exit.into()
    }

    /// The text form: the message, then the hint, then what to ask the
    /// human, each on its own line.
    fn text(&self) -> String {
        let mut out = format!("kagebunshin: {}\n", self.message);
        if let Some(hint) = self
            .hint
            .as_ref()
            .filter(|h| Some(*h) != self.tell.as_ref())
        {
            out.push_str(&format!("hint: {hint}\n"));
        }
        if let (Some(Who::Human), Some(tell)) = (self.who, &self.tell) {
            out.push_str(&format!("ask the human: {tell}\n"));
        }
        out
    }
}

/// Whether this process was given `--json`; set once, at the start.
static JSON: AtomicBool = AtomicBool::new(false);

pub fn set_json_output(json: bool) {
    JSON.store(json, Ordering::Relaxed);
}

pub fn json_output() -> bool {
    JSON.load(Ordering::Relaxed)
}

/// Prints a warning to stderr: as one line of `{"warning": ...}` with
/// `--json`, else as `warning: ...`.
pub fn warn(warning: &str) {
    if json_output() {
        let line = serde_json::json!({ "warning": warning });
        eprintln!("{line}");
    } else {
        eprintln!("warning: {warning}");
    }
}

/// How to start the daemon on this OS. Kept next to the error that needs it
/// so the wording stays in one place.
pub fn start_daemon_hint() -> String {
    let service = start_daemon_command();
    format!(
        "run `kagebunshin daemon install` once, or start an installed one with `{service}`, \
         or run `kagebunshin daemon` in another terminal"
    )
}

/// What to do about a daemon that does not answer. On a machine with no
/// `store`, nothing is set up yet, and `setup` does all of it. Where its
/// service is `installed`, `setup` starts it again and unlocks it, whether
/// it stopped or was never loaded. With a store and no service it is one
/// started by hand.
fn not_running_hint(store: bool, installed: bool) -> String {
    if store && installed {
        "the daemon's service is installed and not running: run `kagebunshin setup` in a \
         terminal; it starts the daemon again, asking for the store passphrase, and unlocks it"
            .into()
    } else if store {
        start_daemon_hint()
    } else {
        "kagebunshin is not set up on this machine: run `kagebunshin setup` in a terminal; it \
         creates the local store, asking for its new passphrase, and starts and unlocks the daemon"
            .into()
    }
}

/// The command that starts the installed daemon service on this OS.
pub fn start_daemon_command() -> &'static str {
    #[cfg(target_os = "linux")]
    let service = "systemctl --user start kagebunshin";
    #[cfg(target_os = "macos")]
    let service = "launchctl kickstart gui/$(id -u)/io.github.oorestisime.kagebunshin";
    service
}

impl From<ClientError> for CliError {
    fn from(e: ClientError) -> Self {
        let message = e.to_string();
        match e {
            ClientError::NotRunning { .. } => {
                let store =
                    crate::config::ConfigDir::from_env().is_ok_and(|d| d.store_file().exists());
                let installed = super::units::unit_path().is_ok_and(|p| p.exists());
                let hint = not_running_hint(store, installed);
                CliError::new(Exit::DaemonNotRunning, "daemon_not_running", message)
                    .with_hint(hint.clone())
                    .human(hint)
            }
            ClientError::InsecureDir(_) | ClientError::ForeignDaemon { .. } => {
                CliError::new(Exit::Refused, "insecure_socket", message)
            }
            ClientError::Timeout(_) => CliError::new(Exit::Failure, "daemon_timeout", message)
                .with_hint("the daemon may be stuck; restart it"),
            ClientError::Frame(_) | ClientError::Connect { .. } | ClientError::UnexpectedReply => {
                CliError::new(Exit::Failure, "daemon_io", message)
            }
            ClientError::ConnectRemote { .. } => {
                CliError::new(Exit::Failure, "remote_unreachable", message).with_hint(
                    "on that machine, run `kagebunshin remote enable` and `kagebunshin status`; \
                     it listens once its daemon has been unlocked, while Tailscale is up there",
                )
            }
            ClientError::Remote { .. } => CliError::new(Exit::Failure, "remote_io", message)
                .with_hint("try again; `kagebunshin status` on that machine shows its endpoint"),
            ClientError::NotADaemon { .. } => {
                CliError::new(Exit::Failure, "remote_unreachable", message).with_hint(
                    "is that the machine, and is `[remote] port` the same on both? Something \
                     between the two machines may have answered instead",
                )
            }
            ClientError::BadToken => CliError::new(Exit::Usage, "usage", message).with_hint(
                "set it to the token `kagebunshin remote grant` or `remote rotate` printed on \
                 the other machine",
            ),
            ClientError::Daemon(w) => {
                let (exit, code) = match w.code {
                    ErrorCode::BuildMismatch => (Exit::BuildMismatch, "build_mismatch"),
                    ErrorCode::PermissionDenied => (Exit::Refused, "permission_denied"),
                    ErrorCode::BadRequest => (Exit::Failure, "bad_request"),
                    ErrorCode::Internal => (Exit::Failure, "internal"),
                    ErrorCode::Locked => (Exit::Refused, "locked"),
                    ErrorCode::SensitiveEnv => (Exit::Refused, "sensitive_env"),
                    ErrorCode::NotApproved => (Exit::Refused, "not_approved"),
                    ErrorCode::NoApp => (Exit::Refused, "no_app"),
                    ErrorCode::NoProject => (Exit::Failure, "no_project"),
                    ErrorCode::Config => (Exit::Failure, "config"),
                    ErrorCode::SourceFailed => (Exit::Failure, "source_failed"),
                    ErrorCode::PassphraseRequired => (Exit::Failure, "passphrase_required"),
                    ErrorCode::WrongPassphrase => (Exit::Failure, "wrong_passphrase"),
                    ErrorCode::NoStore => (Exit::Failure, "no_store"),
                    ErrorCode::StoreExists => (Exit::Failure, "store_exists"),
                    ErrorCode::Store => (Exit::Failure, "store"),
                    ErrorCode::NoKey => (Exit::Failure, "no_key"),
                };
                // A daemon on this machine that runs another build, as one
                // does between an upgrade and `setup`. Daemons before this
                // one said to restart it, and not how.
                let other_machine = w.hint.as_deref() == Some(crate::ipc::remote::SAME_RELEASE);
                if w.code == ErrorCode::BuildMismatch && w.who.is_none() && !other_machine {
                    return CliError::new(exit, code, w.message)
                        .with_hint(crate::ipc::server::SAME_BUILD)
                        .human(crate::ipc::server::SAME_BUILD);
                }
                CliError {
                    exit,
                    code,
                    message: w.message,
                    hint: w.hint,
                    who: w.who,
                    tell: w.tell,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The documented table. Changing a number here breaks scripts.
    #[test]
    fn exit_code_table_is_stable() {
        let table: Vec<(Exit, u8)> = Exit::ALL.iter().map(|e| (*e, e.code())).collect();
        assert_eq!(
            table,
            [
                (Exit::Success, 0),
                (Exit::Failure, 1),
                (Exit::Usage, 2),
                (Exit::DaemonNotRunning, 3),
                (Exit::BuildMismatch, 4),
                (Exit::Refused, 5),
                (Exit::NotImplemented, 6),
            ]
        );
    }

    #[test]
    fn json_shape() {
        let e = CliError::new(Exit::Failure, "x", "m");
        assert_eq!(
            serde_json::to_value(&e).unwrap(),
            serde_json::json!({"code": "x", "message": "m", "hint": null, "who": null, "tell": null})
        );
        let e = e.with_hint("h");
        assert_eq!(serde_json::to_value(&e).unwrap()["hint"], "h");
        let v = serde_json::to_value(e.human("t")).unwrap();
        assert_eq!((&v["who"], &v["tell"]), (&"human".into(), &"t".into()));
        let v = serde_json::to_value(CliError::new(Exit::Failure, "x", "m").agent()).unwrap();
        assert_eq!(
            (&v["who"], &v["tell"]),
            (&"agent".into(), &serde_json::Value::Null)
        );
    }

    #[test]
    fn text_asks_the_human_after_the_hint() {
        let e = CliError::new(Exit::Refused, "x", "m")
            .with_hint("h")
            .human("t");
        assert_eq!(e.text(), "kagebunshin: m\nhint: h\nask the human: t\n");
        // A hint that says the same as the tell is not printed twice.
        let e = CliError::new(Exit::Refused, "x", "m")
            .with_hint("t")
            .human("t");
        assert_eq!(e.text(), "kagebunshin: m\nask the human: t\n");
        // An agent's fix is just the hint.
        let e = CliError::new(Exit::Failure, "x", "m")
            .with_hint("h")
            .agent();
        assert_eq!(e.text(), "kagebunshin: m\nhint: h\n");
    }

    #[test]
    fn locked_is_a_refusal_for_a_human() {
        let e = CliError::locked();
        assert_eq!(
            (e.exit, e.code, e.who),
            (Exit::Refused, "locked", Some(Who::Human))
        );
        assert_eq!(e.tell.as_deref(), Some(UNLOCK_TELL));
        let wire = crate::ipc::protocol::WireError::new(ErrorCode::Locked, "the daemon is locked")
            .human(UNLOCK_TELL);
        let e = CliError::from(ClientError::Daemon(wire));
        assert_eq!((e.exit, e.who), (Exit::Refused, Some(Who::Human)));
    }

    /// A daemon that does not answer is to be started, with the service
    /// manager's own command; on a machine with no store there is nothing
    /// to start yet, and `setup` is the one thing to run.
    #[test]
    fn not_running_hint_names_the_service_manager_or_setup() {
        let socket = "/x/kagebunshind.sock".into();
        let e = CliError::from(ClientError::NotRunning { socket });
        assert_eq!((e.exit, e.who), (Exit::DaemonNotRunning, Some(Who::Human)));
        assert_eq!(e.hint, e.tell);

        // A store and no service: a daemon started by hand.
        let hint = not_running_hint(true, false);
        #[cfg(target_os = "linux")]
        assert!(hint.contains("systemctl --user"), "{hint}");
        #[cfg(target_os = "macos")]
        assert!(hint.contains("launchctl"), "{hint}");
        // No store, or a service that is not running: `setup`.
        for hint in [not_running_hint(false, false), not_running_hint(true, true)] {
            assert!(
                hint.contains("run `kagebunshin setup` in a terminal"),
                "{hint}"
            );
            assert!(!hint.contains("daemon install"), "{hint}");
        }
        assert!(not_running_hint(true, true).contains("is installed and not running"));
    }

    /// A daemon of another build says so; what to do about it on this
    /// machine is `setup`, whatever that daemon said, and on another
    /// machine what that one says.
    #[test]
    fn a_build_mismatch_is_fixed_with_setup() {
        let mismatch = |hint: &str| {
            let wire = crate::ipc::protocol::WireError::new(
                ErrorCode::BuildMismatch,
                "client build a does not match b",
            )
            .with_hint(hint);
            CliError::from(ClientError::Daemon(wire))
        };
        let e = mismatch("restart the daemon so the CLI and daemon run the same build");
        assert_eq!((e.exit, e.who), (Exit::BuildMismatch, Some(Who::Human)));
        let tell = e.tell.unwrap();
        assert!(
            tell.contains("run `kagebunshin setup` in a terminal"),
            "{tell}"
        );
        assert_eq!(e.hint.as_deref(), Some(tell.as_str()));
        let e = mismatch(crate::ipc::remote::SAME_RELEASE);
        assert_eq!(
            (e.who, e.hint.as_deref()),
            (None, Some(crate::ipc::remote::SAME_RELEASE))
        );
    }
}
