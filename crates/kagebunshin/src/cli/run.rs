//! `kagebunshin run`: a command with the project's secrets in its
//! environment.
//!
//! The child gets this process's environment, less the control variables
//! below, plus the injected keys; an injected key replaces a variable of the
//! same name, with a warning.
//!
//! When stdout and stderr are both terminals the CLI execs the command, so
//! the process the daemon handed the values to is the one that holds them.
//! Otherwise it starts the command, relays the piped streams with secret
//! values masked (see [`super::mask`]), forwards SIGTERM and SIGHUP, and ends
//! the way the child did: same exit status, or same signal.
//!
//! `--strict` always starts the command and waits for it, so that when it
//! exits 0 the CLI can tell this machine's daemon, which keeps it as the
//! environment's proof (see [`crate::daemon::proof`]).
//!
//! `Command::env` keeps its own copies of the values, which are not zeroed.

use std::ffi::OsString;
use std::io::{self, IsTerminal, Read, Write};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Command, ExitCode, ExitStatus, Stdio};

use zeroize::Zeroizing;

use super::mask::Mask;
use super::{CliError, Exit, connect_to, gather, plural, unexpected};
use crate::ipc::protocol::{Request, Response};
use crate::sys;
use crate::types::{EnvName, ProjectName};

const CHUNK: usize = 8 * 1024;

pub fn run(
    socket: Option<PathBuf>,
    remote: Option<String>,
    env: Option<EnvName>,
    project: Option<ProjectName>,
    strict: bool,
    command: Vec<OsString>,
) -> Result<ExitCode, CliError> {
    #[expect(
        clippy::expect_used,
        reason = "gather(_, _, true, _) never returns None"
    )]
    let facts = gather(env, project, true, remote.is_some())?.expect("required facts");
    let no_example = facts.example_keys.is_none();
    // For the proof; another machine's daemon keeps none for this one.
    let prove = (strict && remote.is_none()).then(|| (socket.clone(), facts.clone()));
    let mut client = connect_to(socket, remote.as_deref())?;
    // Its name only, for the audit log: arguments can hold anything. The
    // whole command line is for an approval prompt, which the log leaves out.
    let program = Some(command[0].to_string_lossy().into_owned());
    let request = Request::RunEnv {
        facts,
        program,
        command: command
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect(),
    };
    let Response::RunEnv(reply) = client.request(request)? else {
        return Err(unexpected());
    };
    drop(client);
    for w in &reply.warnings {
        warn(w);
    }
    if no_example {
        let n = reply.vars.len();
        warn(&format!(
            "no .env.example found, so every key the environment has is passed ({n} {}); \
             `kagebunshin project example` writes one from the keys the code reads, to pass \
             only those",
            plural(n, "key", "keys")
        ));
    }
    let mut short = Vec::new();
    if !reply.missing.is_empty() {
        let n = reply.missing.len();
        let names: Vec<&str> = reply.missing.iter().map(|k| k.as_str()).collect();
        short.push(format!(
            "{n} {} in .env.example {} not set by any source: {}",
            plural(n, "key", "keys"),
            plural(n, "is", "are"),
            names.join(", ")
        ));
    }
    if strict && !short.is_empty() {
        return Err(CliError::new(
            Exit::Failure,
            "missing_keys",
            short.join("; "),
        ));
    }
    for message in &short {
        warn(message);
    }

    #[expect(clippy::expect_used, reason = "clap requires at least one argument")]
    let (program, args) = command.split_first().expect("clap requires a command");
    let mut cmd = Command::new(program);
    cmd.args(args);
    // A remote grant's token gets every environment the grant covers; the
    // command gets this one's values and no more.
    cmd.env_remove(crate::ipc::protocol::REMOTE_TOKEN_ENV);
    for var in &reply.vars {
        if std::env::var_os(var.key.as_str()).is_some() {
            warn(&format!(
                "{} replaces the value already in the environment",
                var.key
            ));
        }
        cmd.env(var.key.as_str(), var.value.expose());
    }
    let not_run = |e: io::Error| {
        CliError::new(
            Exit::Failure,
            "exec",
            format!("cannot run {}: {e}", program.to_string_lossy()),
        )
    };

    let (out_tty, err_tty) = (io::stdout().is_terminal(), io::stderr().is_terminal());
    if out_tty && err_tty && prove.is_none() {
        // Only returns on failure.
        return Err(not_run(cmd.exec()));
    }

    // A plain setting from the project file is not secret: masking `3000`
    // would mangle the output for nothing.
    let mask = Mask::new(
        reply
            .vars
            .iter()
            .filter(|v| !v.plain)
            .map(|v| (v.key.as_str(), v.value.expose())),
        reply.mask_min_len,
    );
    drop(reply);
    if !out_tty {
        cmd.stdout(Stdio::piped());
    }
    if !err_tty {
        cmd.stderr(Stdio::piped());
    }
    let mut child = cmd.spawn().map_err(not_run)?;
    drop(cmd);
    if let Err(e) = sys::forward_signals_to(child.id()) {
        warn(&format!("cannot forward signals to the command: {e}"));
    }
    let (stdout, stderr) = (child.stdout.take(), child.stderr.take());
    let status = std::thread::scope(|s| {
        if let Some(from) = stdout {
            s.spawn(|| relay(from, io::stdout(), &mask));
        }
        if let Some(from) = stderr {
            s.spawn(|| relay(from, io::stderr(), &mask));
        }
        child.wait()
    });
    drop(mask);
    let status = status.map_err(|e| {
        CliError::new(
            Exit::Failure,
            "exec",
            format!("cannot wait for the command: {e}"),
        )
    })?;
    if let Some((socket, facts)) = prove.filter(|_| status.success()) {
        let program = program.to_string_lossy().into_owned();
        let told = connect_to(socket, None)
            .and_then(|mut c| Ok(c.request(Request::Proven { facts, program })?));
        if let Err(e) = told {
            warn(&format!("cannot record that the run worked: {}", e.message));
        }
    }
    Ok(exit_like(status))
}

/// Ends the way the child did: same exit status, or same signal.
pub(super) fn exit_like(status: ExitStatus) -> ExitCode {
    match (status.code(), status.signal()) {
        (Some(code), _) => ExitCode::from(code as u8),
        (None, Some(sig)) => sys::exit_by_signal(sig),
        (None, None) => Exit::Failure.into(),
    }
}

/// Copies `from` to `to`, masked, until `from` ends. If `to` fails (say a
/// closed pipe), stops reading, so the child sees its output closed too.
fn relay(mut from: impl Read, mut to: impl Write, mask: &Mask) {
    let mut buf = Zeroizing::new(vec![0u8; CHUNK]);
    let mut out = Vec::with_capacity(2 * CHUNK);
    let mut stream = mask.stream();
    loop {
        let n = match from.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        out.clear();
        stream.push(&buf[..n], &mut out);
        if to.write_all(&out).and_then(|()| to.flush()).is_err() {
            return;
        }
    }
    out.clear();
    stream.finish(&mut out);
    let _ = to.write_all(&out).and_then(|()| to.flush());
}

/// A warning on stderr; with `--json`, as one line of `{"warning": ...}`.
fn warn(message: &str) {
    if super::error::json_output() {
        super::error::warn(message);
    } else {
        let _ = writeln!(io::stderr(), "kagebunshin: warning: {message}");
    }
}
