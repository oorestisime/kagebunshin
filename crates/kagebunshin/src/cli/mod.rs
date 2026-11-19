//! The `kagebunshin` command line.
//!
//! A command without an implementation would exit with
//! [`Exit::NotImplemented`]; every command has one now.
//!
//! Only `get` prints a value; `run` passes values to the command it runs.
//! The CLI reads a value only for `store set`, from the terminal or a pipe,
//! and passphrases only from the terminal; none is ever an argument. It
//! gathers facts about where it runs (the checkout's remotes and the keys in
//! its `.env.example`) and the daemon picks the project from them.

// Warnings go straight to stderr; stdout goes through `print_line` and `print_json`.
#![allow(clippy::print_stderr, reason = "the CLI's output layer")]
// Doc comments on the clap types are --help text, printed as written.
#![allow(
    clippy::doc_markdown,
    reason = "clap help text is plain text, not Markdown"
)]

pub mod audit;
mod connect;
mod desktop;
mod draft;
pub mod edit;
pub mod error;
mod example;
mod hook;
mod mask;
mod next;
mod onboard;
mod project;
mod remote;
mod run;
mod uninstall;
mod units;

use std::ffi::OsString;
use std::io::{self, IsTerminal, Read, Write};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use crate::config::{ConfigDir, Git, GitError, ProjectPath, Registry};
use crate::daemon;
use crate::ipc::client::{Client, ClientError, DEFAULT_TIMEOUT};
use crate::ipc::paths;
use crate::ipc::protocol::{
    BUILD_ID, DiffReport, ErrorCode, Facts, Fix, MarkTarget, PhoneStatus, Request, Response,
    StatusReport, StoreListing, SyncReport, Who, WireSecret,
};
use crate::repo;
use crate::repo::env_example::ExampleValues;
use crate::source::{Health, ProviderStatus};
use crate::store::{Change, Section};
use crate::types::{EnvName, KeyName, Origin, ProjectName, Provider, shell_quote};
pub use error::{CliError, Exit};

#[derive(Debug, Parser)]
#[command(
    name = "kagebunshin",
    bin_name = "kagebunshin",
    version = BUILD_ID,
    about = "A local secrets broker for developers and coding agents",
    propagate_version = true
)]
pub struct Cli {
    /// Print machine-readable JSON; errors go to stderr as JSON
    #[arg(long, global = true)]
    pub json: bool,

    /// Daemon socket [default: $KAGEBUNSHIN_SOCKET, else a per-user runtime dir]
    #[arg(long, global = true, value_name = "PATH")]
    pub socket: Option<PathBuf>,

    /// Environment to use instead of the project's default
    #[arg(long, global = true, value_name = "ENV")]
    pub env: Option<EnvName>,

    /// Project to use instead of the one for this folder; it must claim this
    /// checkout's remotes
    // Its own id: subcommands have a positional `project` too.
    #[arg(
        long = "project",
        id = "project_flag",
        global = true,
        value_name = "NAME"
    )]
    pub project: Option<ProjectName>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run a command with the project's secrets in its environment
    ///
    /// Injects the keys `.env.example` lists, or every key without one. When
    /// output is piped, secret values in it are masked.
    Run {
        /// Fail if a key in .env.example is not set by any source
        #[arg(long)]
        strict: bool,
        /// Ask machine MACHINE's daemon over Tailscale instead of this one's,
        /// sending its grant's token from KAGEBUNSHIN_REMOTE_TOKEN; with
        /// --project, outside a git checkout too
        #[arg(long = "machine", value_name = "MACHINE")]
        remote: Option<String>,
        /// The command and its arguments; put `--` first if they include flags
        #[arg(required = true, trailing_var_arg = true, value_name = "COMMAND")]
        command: Vec<OsString>,
    },
    /// Print the next step toward a working setup of this checkout
    ///
    /// Says who takes it (you, or the human) and the exact command, then
    /// every step waiting on the human with the sentence to pass on. Run it
    /// and do what it says until it says done. With several checkouts, one
    /// step for them all: their env files go in with one `onboard`, which
    /// the human approves once.
    Next {
        /// Checkout folders [default: the current folder]
        #[arg(value_name = "DIR")]
        dirs: Vec<PathBuf>,
    },
    /// Show the daemon and where each key comes from
    Status {
        /// Ask machine MACHINE's daemon over Tailscale instead of this one's,
        /// sending its grant's token from KAGEBUNSHIN_REMOTE_TOKEN; with
        /// --project, outside a git checkout too
        #[arg(long = "machine", value_name = "MACHINE")]
        remote: Option<String>,
    },
    /// Show keys that are missing, overridden or changed
    ///
    /// Keys missing from every source are listed; extra and overridden keys
    /// are counted per secret unless --verbose.
    Diff {
        /// List every extra and overridden key
        #[arg(long)]
        verbose: bool,
        /// Ask machine MACHINE's daemon over Tailscale instead of this one's,
        /// sending its grant's token from KAGEBUNSHIN_REMOTE_TOKEN; with
        /// --project, outside a git checkout too
        #[arg(long = "machine", value_name = "MACHINE")]
        remote: Option<String>,
    },
    /// Refresh cached values from their sources
    ///
    /// Without a project, every environment the daemon has cached.
    Sync {
        /// Only this project
        project: Option<ProjectName>,
        /// Only this environment of it [default: --env, else the default env]
        #[arg(value_name = "ENV")]
        environment: Option<EnvName>,
    },
    /// Unlock the daemon and the local store
    Unlock,
    /// Lock the daemon and the local store, dropping every value held in memory
    Lock,
    /// Print one value (human callers only: asks for the store passphrase)
    Get {
        /// The key to print
        key: KeyName,
    },
    /// Set kagebunshin up once for this user: config, store, daemon
    ///
    /// Creates the config directory and the local store, asking for its new
    /// passphrase (or, if the store exists, for its passphrase), installs and
    /// starts the daemon as a user service, and unlocks it. On a Linux
    /// desktop with the app installed, it also adds the app to the launcher
    /// and starts it in the tray at login, as `app install` does; the first
    /// time, when it creates the store, it starts the app in the tray now
    /// too. Running it again reinstalls the service, restarts an app that
    /// is running, and unlocks. Projects never ask for the
    /// passphrase; only unlocking after a reboot or the idle timeout does.
    Setup {
        /// Do not install the service or the app's launcher and login
        /// entries; unlock a daemon already running
        #[arg(long)]
        no_service: bool,
    },
    /// Remove kagebunshin from this machine: the service, skills and binaries
    ///
    /// Lists every path first, then asks at the terminal. The app's launcher
    /// and login entries go too, and the app is ended. --purge also removes
    /// the config, the store, the audit log and the socket. Nothing
    /// in ~/.aws or in your repositories is touched, and binaries installed
    /// with cargo are left to `cargo uninstall`.
    Uninstall {
        /// Also remove the config directory, the local store and the audit log
        #[arg(long)]
        purge: bool,
        /// Only list what would be removed
        #[arg(long)]
        dry_run: bool,
    },
    /// Open the window: each project's keys by environment, marks and the audit log
    ///
    /// Starts `kagebunshin-app`, from the directory this binary is in, else
    /// from PATH, and returns. The app stays in the tray once its window is
    /// closed, where requests for values marked sensitive wait for approval;
    /// run again, this shows the window of the app that is running.
    /// Revealing a value and changing a sensitive mark there ask for the
    /// store passphrase.
    ///
    /// Where the daemon is a systemd user service, the app is one beside
    /// it, `kagebunshin-app.service`: restarted if it fails, and
    /// `journalctl --user -u kagebunshin-app` has what it printed.
    #[command(args_conflicts_with_subcommands = true)]
    App {
        /// Start in the tray, with no window, as at login
        #[arg(long, conflicts_with = "quit")]
        hidden: bool,
        /// End the app that is running
        #[arg(long)]
        quit: bool,
        #[command(subcommand)]
        action: Option<AppAction>,
    },
    /// Print instructions that teach a coding agent to set up and use kagebunshin
    ///
    /// Markdown for AGENTS.md, or with --skill an OpenCode skill file:
    /// `kagebunshin init --agent --skill > ~/.config/opencode/skills/kagebunshin/SKILL.md`
    Init {
        /// For a coding agent (the only kind of init so far)
        #[arg(long, required = true)]
        agent: bool,
        /// As an OpenCode skill (SKILL.md, with its front matter)
        #[arg(long)]
        skill: bool,
    },
    /// Agent hooks: tell a session in a registered project how to run
    /// commands, and refuse writing a .env file there
    ///
    /// `install.sh` runs `hook install` for each agent it finds; the agent
    /// runs the other two.
    Hook {
        #[command(subcommand)]
        action: hook::HookAction,
    },
    /// Create projects and add environments and sources, without editing TOML
    Project {
        #[command(subcommand)]
        action: project::ProjectAction,
    },
    /// Connect a provider: set up its credentials and check they work
    Connect {
        #[command(subcommand)]
        provider: connect::ConnectProvider,
    },
    /// List what the providers can read: names, ids and keys, never values
    ///
    /// Without --provider: AWS Secrets Manager, and the local store and
    /// Proton Pass when they are set up and the daemon is unlocked. A
    /// provider that cannot be listed is a warning then, not a failure.
    List {
        /// Only this provider
        #[arg(long, value_enum)]
        provider: Option<project::SourceProvider>,
        /// Only names that start with this, e.g. widget/dev/
        #[arg(long, default_value = "", hide_default_value = true)]
        prefix: String,
        /// Also read each AWS secret's key names, never its values
        ///
        /// The daemon reads every AWS secret listed (GetSecretValue), keeps
        /// only the key names, or that a secret is a plain string, and
        /// records the lookup in the audit log. Secrets marked sensitive or
        /// that look like production are listed without their keys.
        #[arg(long)]
        keys: bool,
        #[command(flatten)]
        aws: AwsArgs,
    },
    /// Find names or keys that contain TEXT, ignoring case (never values)
    Search {
        /// What to look for, e.g. stripe
        text: String,
        /// Only this provider
        #[arg(long, value_enum)]
        provider: Option<project::SourceProvider>,
        /// Only names that start with this
        #[arg(long, default_value = "", hide_default_value = true)]
        prefix: String,
        /// Also match AWS secrets' key names, which reads every AWS secret
        /// under the prefix (see `list --keys`)
        #[arg(long)]
        keys: bool,
        #[command(flatten)]
        aws: AwsArgs,
    },
    /// Look up AWS Secrets Manager secret names (never values)
    Aws {
        #[command(subcommand)]
        action: project::AwsAction,
    },
    /// Install a mapping file someone handed you into ~/.config/kagebunshin/projects/
    Import {
        /// The mapping file to install
        file: PathBuf,
        /// The project's name [default: the file's name, without .toml]
        #[arg(long, value_name = "NAME")]
        name: Option<ProjectName>,
    },
    /// Start using kagebunshin in these checkouts, with one passphrase
    ///
    /// For each app of each checkout [default: the current folder]: an env
    /// file with values (./.env) goes into the local store, for a new
    /// project whose environment [default: --env, else the default env]
    /// reads the store's [<project>.<env>]; an app with none is drafted and
    /// installed as `project draft --apply` does; one a project already
    /// claims is left as it is. Then each project's state, as `kagebunshin
    /// next` sees it, and the line to paste into your agent. Asks for the
    /// store passphrase once, only to unlock the daemon or to import, and
    /// at the end whether to delete the imported files. Values are read
    /// from the files, never printed. A folder that is not a git checkout
    /// with a remote is skipped.
    ///
    /// Before the passphrase is asked for, each app is listed with what
    /// is done for it. --exclude APP leaves an app out, by its folder or
    /// by its project's name: no project, nothing imported. It stays out
    /// when its checkout is onboarded again, until its own folder is
    /// named.
    ///
    /// Without a terminal, as an agent runs it, the import waits for a
    /// person to approve it in the kagebunshin app, which lists each file,
    /// where it goes and its key names, and takes the passphrase there;
    /// with the app closed it fails with `no_app` and imports nothing. The
    /// imported files are then kept unless --delete-env is given.
    ///
    /// An app's own env file is one named .env or .env.*, the first with
    /// values. A file with values under any other name (.dev.env,
    /// production.env, a second .env.*) is named at the end and imported
    /// with `--file PATH`, into the project of the app it is in, for --env:
    /// a new project, or an existing one's environment, which is added if
    /// the project does not have it.
    Onboard {
        /// Checkout folders, or app folders in one
        #[arg(value_name = "DIR")]
        dirs: Vec<PathBuf>,
        /// Import this env file instead, whatever its name; may repeat
        #[arg(long = "file", value_name = "PATH", conflicts_with = "dirs")]
        files: Vec<PathBuf>,
        /// The project's name, with one folder or --file [default: from the folder's name]
        #[arg(long, value_name = "NAME")]
        name: Option<ProjectName>,
        /// Leave this app out, by its folder or its project's name; may repeat
        #[arg(long, value_name = "APP", conflicts_with = "files")]
        exclude: Vec<String>,
        /// Delete the imported env files without asking
        #[arg(long, conflicts_with = "keep_env")]
        delete_env: bool,
        /// Keep the imported env files without asking (also with --json)
        #[arg(long)]
        keep_env: bool,
    },
    /// Write a copy of a project's mapping file (no secret values) to hand to someone
    Export {
        /// The project whose mapping file to copy
        project: ProjectName,
        /// Write to this file instead of stdout
        #[arg(short, long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
    /// Manage the local encrypted store
    ///
    /// Passphrases are read from the terminal, never from arguments.
    Store {
        #[command(subcommand)]
        action: StoreAction,
    },
    /// Mark an environment, a secret or a store key sensitive
    ///
    /// A marked value is handed out only once a human approves that request
    /// in the app. Takes no passphrase, so an agent can run it; the daemon
    /// must be unlocked. The mark holds at once and is in the audit log.
    /// Only a human removes one, in the app, with the store passphrase.
    Mark {
        #[command(subcommand)]
        target: MarkAction,
    },
    /// Show the audit log
    ///
    /// What was asked of kagebunshin, by whom, and what it decided: names,
    /// never values. Read from $XDG_STATE_HOME/kagebunshin/audit.jsonl, and
    /// with --all from runs.jsonl beside it, which has the runs that needed
    /// no approval. Here --project and --env list the events of one project
    /// or environment.
    Audit {
        /// Only events this recent, such as 1h or 7d
        #[arg(long, value_parser = audit::parse_since, value_name = "DURATION")]
        since: Option<u64>,
        /// Also the runs that needed no approval
        #[arg(long)]
        all: bool,
        /// Only this request or command, such as run or unlock
        #[arg(long, value_name = "ACTION")]
        action: Option<String>,
    },
    /// Run the daemon in the foreground or as a service, or check on it
    Daemon {
        #[command(subcommand)]
        action: Option<DaemonAction>,
    },
    /// Let other machines on your tailnet use this daemon, and say which
    ///
    /// Off until `remote enable`. Then machines a grant names may ask for
    /// run, status and diff with `--machine <this machine>` and the grant's
    /// token; values marked sensitive still need approving in the app here.
    Remote {
        #[command(subcommand)]
        action: remote::RemoteAction,
    },
}

#[derive(Debug, Subcommand)]
pub enum StoreAction {
    /// Create the store, choosing its passphrase, and unlock the daemon with it
    Init,
    /// Set keys; each value is read from the terminal, or from stdin if piped
    ///
    /// One key takes all of piped stdin as its value. Several keys take one
    /// line of piped stdin each, in order, and are written in one update.
    ///
    /// With no terminal to ask for the passphrase at, as when a coding
    /// agent runs it, the open app asks a person for each value and the
    /// passphrase instead; stdin is not read, and the command prints only
    /// which keys were set.
    Set {
        /// The section, <project>.<env>
        section: Section,
        /// The keys to set
        #[arg(required = true, value_name = "KEY")]
        keys: Vec<KeyName>,
    },
    /// Remove a key
    Unset {
        /// The section, <project>.<env>
        section: Section,
        /// The key to remove
        key: KeyName,
    },
    /// Remove every section of a project that is gone
    ///
    /// What `project remove` leaves in the store: the values its
    /// environments read from it. Refused while the project is still
    /// there. With the daemon unlocked the sections are named before the
    /// passphrase is asked for.
    Clear {
        /// The removed project
        project: ProjectName,
    },
    /// List sections and key names (never values)
    List,
    /// Change the passphrase
    Passwd,
}

#[derive(Debug, Subcommand)]
pub enum MarkAction {
    /// Mark an environment, and the secrets only its sources read
    ///
    /// A secret an environment that is not marked reads too is left
    /// unmarked, unless its name looks like production.
    Env {
        /// The project
        project: ProjectName,
        /// The environment
        #[arg(value_name = "ENV")]
        environment: EnvName,
    },
    /// Mark one secret, wherever it is read
    Secret {
        /// Its provider; a `file` secret is marked key by key, with `mark key`
        #[arg(value_enum)]
        provider: project::SourceProvider,
        /// Its name there (for proton: vault/KEY)
        #[arg(value_name = "NAME")]
        location: String,
    },
    /// Mark one key of the local store
    Key {
        /// The section, <project>.<env>
        section: Section,
        /// The key
        key: KeyName,
    },
}

#[derive(Debug, Subcommand)]
pub enum AppAction {
    /// Add the app to the launcher and start it in the tray at login (Linux)
    ///
    /// Writes a launcher entry, a login entry that starts the app with
    /// --hidden, and its icon. Both entries run this binary's `app` on the
    /// socket this command resolves. An app that is running is restarted,
    /// on the binary found now. `setup` does this too. A file of the same
    /// name that kagebunshin did not write is left alone.
    Install,
    /// Remove the launcher entry, the login entry and the icon
    Uninstall,
}

#[derive(Debug, Subcommand)]
pub enum DaemonAction {
    /// Run the daemon in the foreground (the default)
    Run,
    /// Check that the daemon is up and answering
    Ping,
    /// Show the caller identity the daemon sees for this process
    Whoami,
    /// Run the daemon as a user service, started now and at login
    ///
    /// Writes a systemd user unit (Linux) or a launchd agent (macOS) that
    /// runs this binary on the socket this command resolves, then starts
    /// it. The daemon starts locked, so reinstalling locks it.
    Install {
        /// Only write the unit; do not start it
        #[arg(long)]
        files_only: bool,
    },
    /// Stop the user service and remove its unit
    Uninstall {
        /// Only remove the unit; do not stop the service
        #[arg(long)]
        files_only: bool,
    },
    /// Show whether the service is installed and the daemon answers
    Status,
}

/// The AWS profile and region `list` and `search` use.
#[derive(Debug, clap::Args)]
pub struct AwsArgs {
    /// The AWS profile [default: the one this checkout's project reads AWS with, else `[aws]` in config.toml, else the ambient configuration]
    #[arg(long, value_parser = project::parse_profile)]
    profile: Option<crate::config::Profile>,
    /// The AWS region [default: this checkout's project's, else `[aws]` in config.toml, else the profile's]
    #[arg(long, value_parser = project::parse_region)]
    region: Option<crate::config::Region>,
}

impl AwsArgs {
    /// These, or, where neither is given, what the first AWS source of this
    /// checkout's environment uses: an agent looking for a missing key
    /// looks where its project already reads. Outside a project, or in one
    /// with no AWS source, they stay empty and the daemon's defaults apply.
    fn or_here(mut self, env: Option<EnvName>, project: Option<ProjectName>) -> Self {
        if self.profile.is_some() || self.region.is_some() {
            return self;
        }
        let here = || aws_here(&gather_checked(env, project, false, false).ok()?.0?);
        if let Some(aws) = here() {
            self.profile = aws.profile;
            self.region = aws.region;
        }
        self
    }
}

/// The profile and region the first AWS source of `facts`' environment
/// reads with, as the project file has it now.
fn aws_here(facts: &Facts) -> Option<crate::config::AwsSettings> {
    let registry = Registry::load(&ConfigDir::from_env().ok()?).ok()?;
    let found = registry.find(facts.place()).ok()?;
    let settings = registry.env(found.project, facts.env.as_ref()).ok()?;
    let source = settings
        .sources
        .into_iter()
        .find(|s| s.provider == Provider::AwsSm)?;
    Some(source.aws)
}

impl Command {
    fn name(&self) -> &'static str {
        match self {
            Command::Run { .. } => "run",
            Command::Next { .. } => "next",
            Command::Status { .. } => "status",
            Command::Diff { .. } => "diff",
            Command::Sync { .. } => "sync",
            Command::Unlock => "unlock",
            Command::Lock => "lock",
            Command::Get { .. } => "get",
            Command::Init { .. } => "init",
            Command::Hook { .. } => "hook",
            Command::Setup { .. } => "setup",
            Command::Uninstall { .. } => "uninstall",
            Command::App { .. } => "app",
            Command::Project { .. } => "project",
            Command::List { .. } => "list",
            Command::Search { .. } => "search",
            Command::Aws { .. } => "aws",
            Command::Connect { .. } => "connect",
            Command::Import { .. } => "import",
            Command::Onboard { .. } => "onboard",
            Command::Export { .. } => "export",
            Command::Store { .. } => "store",
            Command::Mark { .. } => "mark",
            Command::Audit { .. } => "audit",
            Command::Daemon { .. } => "daemon",
            Command::Remote { .. } => "remote",
        }
    }
}

/// The `kagebunshin` binary.
pub fn main() -> ExitCode {
    // Values pass through this process too. Best effort: nothing here can
    // stop the command, and the daemon warns about its own.
    let _ = crate::sys::harden_process();
    run(std::env::args_os())
}

pub fn run(args: impl IntoIterator<Item = OsString>) -> ExitCode {
    let args: Vec<OsString> = args.into_iter().collect();
    let cli = match Cli::try_parse_from(&args) {
        Ok(cli) => cli,
        Err(e) if !e.use_stderr() => {
            // --help and --version.
            let _ = e.print();
            return ExitCode::SUCCESS;
        }
        Err(e) if wants_json(&args) => {
            error::set_json_output(true);
            let rendered = e.render().to_string();
            let first = rendered.lines().next().unwrap_or_default();
            let message = first.strip_prefix("error: ").unwrap_or(first);
            return CliError::new(Exit::Usage, "usage", message)
                .with_hint("run `kagebunshin --help`")
                .report(true);
        }
        Err(e) => {
            let _ = e.print();
            return Exit::Usage.into();
        }
    };
    let json = cli.json;
    error::set_json_output(json);
    let result = match cli.command {
        Command::Run {
            strict,
            remote,
            command,
        } => run::run(cli.socket, remote, cli.env, cli.project, strict, command),
        command => dispatch(Cli { command, ..cli }).map(|()| ExitCode::SUCCESS),
    };
    match result {
        Ok(code) => code,
        Err(e) => project::steer_unknown_project(e).report(json),
    }
}

/// `--json` before any `--`. Used only when parsing failed.
fn wants_json(args: &[OsString]) -> bool {
    args.iter()
        .skip(1)
        .take_while(|a| *a != "--")
        .any(|a| a == "--json")
}

fn dispatch(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Command::Daemon { action } => match action.unwrap_or(DaemonAction::Run) {
            DaemonAction::Run => daemon::run(daemon::Options { socket: cli.socket })
                .map_err(|e| CliError::new(Exit::Failure, "daemon_failed", e.to_string())),
            DaemonAction::Ping => {
                let mut client = connect(cli.socket)?;
                expect(client.request(Request::Ping)?, |r| {
                    matches!(r, Response::Pong)
                })?;
                if cli.json {
                    print_json(&serde_json::json!({ "pong": true }))
                } else {
                    print_line("pong")
                }
            }
            DaemonAction::Install { files_only } => {
                units::install(cli.json, cli.socket, files_only)
            }
            DaemonAction::Uninstall { files_only } => units::uninstall(cli.json, files_only),
            DaemonAction::Status => units::status(cli.json, cli.socket),
            DaemonAction::Whoami => {
                let mut client = connect(cli.socket)?;
                let Response::Whoami(me) = client.request(Request::Whoami)? else {
                    return Err(unexpected());
                };
                if cli.json {
                    print_json(&me)
                } else {
                    print_line(&format!(
                        "uid={} gid={} pid={} start_time={}",
                        me.uid, me.gid, me.pid, me.start_time.0
                    ))
                }
            }
        },
        Command::Next { dirs } => next::run(cli.json, cli.socket, cli.env, cli.project, dirs),
        Command::Status { remote } => {
            let (facts, bad_lines, values) =
                gather_checked(cli.env, cli.project, false, remote.is_some())?;
            let mut client = connect_to(cli.socket, remote.as_deref())?;
            let Response::Status(mut report) = client.request(Request::Status {
                facts: facts.clone(),
            })?
            else {
                return Err(unexpected());
            };
            // Only what the environment on show shares.
            let on_show = report
                .env
                .as_ref()
                .map(|e| (e.project.clone(), e.env.clone()));
            report
                .shared
                .retain(|s| on_show.as_ref().is_some_and(|(p, e)| s.of(p, e)));
            // A plain setting goes in this machine's project file.
            if let (None, Some(env)) = (&remote, report.env.as_mut()) {
                let more = set_var_fixes(&env.project, &env.env, &env.missing, &values);
                env.fixes.extend(more);
            }
            // Another machine says nothing about its providers.
            let providers = if remote.is_some() {
                Vec::new()
            } else {
                let Response::Providers { providers } = client.request(Request::Providers {
                    facts: facts.clone(),
                    every: false,
                })?
                else {
                    return Err(unexpected());
                };
                providers
            };
            // What `next` would list for the human; this machine's only.
            let human = match (&remote, &facts) {
                (None, Some(facts)) => next::left_for_human(&report, facts),
                _ => Vec::new(),
            };
            // How much this machine's daemon was used; another's logs are
            // not here to read.
            let runs = match &remote {
                Some(_) => None,
                None => audit::usage(report.env.as_ref().map(|e| (&e.project, &e.env))),
            };
            #[derive(serde::Serialize)]
            struct Out<'a> {
                #[serde(flatten)]
                report: &'a StatusReport,
                providers: &'a [ProviderStatus],
                #[serde(skip_serializing_if = "Vec::is_empty")]
                human: Vec<next::HumanJson<'a>>,
                #[serde(skip_serializing_if = "Option::is_none")]
                runs: Option<&'a audit::Usage>,
            }
            let text = render_status(&report, &providers, &human, runs.as_ref());
            let out = Out {
                report: &report,
                providers: &providers,
                human: next::human_json(&human),
                runs: runs.as_ref(),
            };
            print_report(cli.json, &out, text, &bad_lines)
        }
        Command::Diff { verbose, remote } => {
            let (facts, bad_lines, values) =
                gather_checked(cli.env, cli.project, true, remote.is_some())?;
            #[expect(
                clippy::expect_used,
                reason = "gather_checked(_, _, true, _) never returns None"
            )]
            let facts = facts.expect("required facts");
            let mut client = connect_to(cli.socket, remote.as_deref())?;
            let Response::Diff(mut report) = client.request(Request::Diff { facts })? else {
                return Err(unexpected());
            };
            if remote.is_none() {
                let more = set_var_fixes(&report.project, &report.env, &report.missing, &values);
                report.fixes.extend(more);
            }
            print_report(cli.json, &report, render_diff(&report, verbose), &bad_lines)?;
            // A key on a line that could not be read may be missing too, so
            // those lines fail `diff` as missing keys do.
            match (report.missing.len(), bad_lines.len()) {
                (0, 0) => Ok(()),
                (0, n) => Err(CliError::new(
                    Exit::Failure,
                    "env_example_unreadable",
                    format!(
                        "{n} {} of .env.example could not be read, so a key on {} may be missing",
                        plural(n, "line", "lines"),
                        plural(n, "it", "them")
                    ),
                )),
                (n, _) => Err(CliError::new(
                    Exit::Failure,
                    "missing_keys",
                    format!(
                        "{n} {} in .env.example {} not set by any source",
                        plural(n, "key", "keys"),
                        plural(n, "is", "are")
                    ),
                )),
            }
        }
        Command::Sync {
            project,
            environment,
        } => {
            let env = match (environment, cli.env) {
                (Some(a), Some(b)) if a != b => {
                    return Err(usage(format!("two environments given: {a} and --env {b}")));
                }
                (a, b) => a.or(b),
            };
            let project = match (project, cli.project) {
                (Some(a), Some(b)) if a != b => {
                    return Err(usage(format!("two projects given: {a} and --project {b}")));
                }
                (a, b) => a.or(b),
            };
            if project.is_none() && env.is_some() {
                return Err(usage("name the project whose environment to sync"));
            }
            let mut client = connect(cli.socket)?;
            let Response::Sync(report) = client.request(Request::Sync { project, env })? else {
                return Err(unexpected());
            };
            if cli.json {
                print_json(&report)?;
            } else {
                print_line(&render_sync(&report))?;
            }
            // Report the first failure; every one is in the output above.
            match report.refreshed.into_iter().find_map(|s| s.error) {
                Some(w) => Err(ClientError::Daemon(w).into()),
                None => Ok(()),
            }
        }
        Command::Lock | Command::Unlock => {
            let unlock = matches!(cli.command, Command::Unlock);
            let mut client = connect(cli.socket.clone())?;
            let reply = if unlock {
                // Ask for the passphrase only if the daemon needs it: there
                // is a store and the daemon is locked.
                match client.request(Request::Unlock { passphrase: None }) {
                    Err(ClientError::Daemon(w)) if w.code == ErrorCode::PassphraseRequired => {
                        let passphrase = Some(prompt("Passphrase for the local store: ")?);
                        // Over a new connection, as in `get`.
                        connect(cli.socket)?.request(Request::Unlock { passphrase })?
                    }
                    other => other?,
                }
            } else {
                client.request(Request::Lock)?
            };
            let Response::LockState { locked, warnings } = reply else {
                return Err(unexpected());
            };
            if cli.json {
                let mut out = serde_json::json!({ "locked": locked });
                if !warnings.is_empty() {
                    out["warnings"] = warnings.into();
                }
                print_json(&out)
            } else {
                for w in &warnings {
                    eprintln!("warning: {w}");
                }
                print_line(if locked { "locked" } else { "unlocked" })
            }
        }
        Command::Store { action } => store(cli.socket, cli.json, action),
        Command::Mark { target } => mark(cli.socket, cli.json, cli.env, target),
        Command::Setup { no_service } => setup(cli.socket, cli.json, no_service),
        Command::Audit { since, all, action } => audit::show(
            cli.json,
            &audit::Filter {
                since,
                all,
                action,
                project: cli.project,
                env: cli.env,
            },
        ),
        Command::Import { file, name } => project::import(cli.json, &file, name),
        Command::Onboard {
            dirs,
            files,
            name,
            exclude,
            delete_env,
            keep_env,
        } => {
            let answer = (delete_env || keep_env).then_some(delete_env);
            let wanted = onboard::Wanted {
                dirs,
                files,
                name,
                exclude,
            };
            onboard::onboard(cli.socket, cli.json, cli.env, wanted, answer)
        }
        Command::Export { project, output } => project::export(cli.json, &project, output),
        Command::Get { key } => get(cli.socket, cli.env, cli.project, cli.json, key),
        Command::Uninstall { purge, dry_run } => {
            uninstall::uninstall(cli.json, cli.socket, purge, dry_run)
        }
        Command::App {
            action: Some(AppAction::Install),
            ..
        } => desktop::install(cli.json, cli.socket),
        Command::App {
            action: Some(AppAction::Uninstall),
            ..
        } => desktop::uninstall(cli.json),
        Command::App {
            hidden,
            quit,
            action: None,
        } => app(cli.socket, hidden, quit),
        Command::Project { .. } if cli.project.is_some() => Err(usage(
            "--project does not apply to project commands; name the project as their argument",
        )),
        Command::Project {
            action: project::ProjectAction::Remove { project },
        } => project::remove(cli.socket, cli.json, &project),
        Command::Project {
            action: project::ProjectAction::Facts { path },
        } => draft::facts(cli.socket, cli.json, path.as_deref()),
        Command::Project {
            action: project::ProjectAction::Example { path },
        } => example::example(cli.json, path.as_deref()),
        Command::Project {
            action: project::ProjectAction::Apply { file, name, check },
        } => draft::apply(cli.socket, cli.json, &file, name.as_ref(), check),
        Command::Project {
            action:
                project::ProjectAction::Draft {
                    path,
                    name,
                    output,
                    apply,
                },
        } => draft::draft(
            cli.socket,
            cli.json,
            path.as_deref(),
            name.as_ref(),
            output.as_deref(),
            apply,
        ),
        Command::Project { action } => project::manage(cli.socket, cli.json, cli.env, action),
        Command::List {
            provider,
            prefix,
            keys,
            aws,
        } => list(
            cli.socket,
            cli.json,
            provider,
            prefix,
            None,
            keys,
            aws.or_here(cli.env, cli.project),
        ),
        Command::Search {
            text,
            provider,
            prefix,
            keys,
            aws,
        } => list(
            cli.socket,
            cli.json,
            provider,
            prefix,
            Some(text),
            keys,
            aws.or_here(cli.env, cli.project),
        ),
        Command::Aws { action } => project::aws(cli.json, action),
        Command::Connect { provider } => connect::connect(cli.socket, cli.json, provider),
        Command::Init { agent: _, skill } => {
            let body = include_str!("agent.md");
            if skill {
                print_line(format!("{SKILL_HEADER}\n{body}").trim_end())
            } else {
                print_line(body.trim_end())
            }
        }
        Command::Remote { action } => remote::manage(cli.socket, cli.json, cli.env, action),
        Command::Hook { action } => hook::run(cli.json, cli.socket, action),
        other @ Command::Run { .. } => Err(CliError::not_implemented(other.name())),
    }
}

const APP: &str = "kagebunshin-app";

/// `app`: starts the app in the tray if none runs, which returns once it
/// answers, then has the one that runs show its window, or with `quit`
/// end. With `hidden` the tray is all.
fn app(socket: Option<PathBuf>, hidden: bool, quit: bool) -> Result<(), CliError> {
    use std::os::unix::process::CommandExt;
    let bin = find_app().ok_or_else(no_app)?;
    let socket = units::socket(socket)?;
    if !quit && !desktop::answers(&socket) {
        desktop::start(&bin, &socket)?;
    }
    if hidden {
        return Ok(());
    }
    // The app tells the one that runs, and ends. The desktop's activation
    // token, which lets the window take focus, goes with the environment.
    let mut cmd = std::process::Command::new(&bin);
    cmd.arg("--socket").arg(&socket);
    if quit {
        cmd.arg("--quit");
    }
    let e = cmd.exec();
    Err(CliError::new(
        Exit::Failure,
        "no_app",
        format!("cannot start {}: {e}", bin.display()),
    ))
}

/// The window's binary, for this process: see [`app_path`].
fn find_app() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok();
    let dir = exe.as_deref().and_then(Path::parent);
    app_path(dir, std::env::var_os("PATH").as_deref())
}

fn no_app() -> CliError {
    CliError::new(
        Exit::Failure,
        "no_app",
        format!("cannot find {APP} next to this binary or on PATH"),
    )
    .with_hint(
        "install.sh installs it with the CLI; from source, \
         `cargo install --locked --git https://github.com/oorestisime/kagebunshin kagebunshin-app`",
    )
}

/// The window's binary: next to this one, as a release installs them, else
/// the first on `path`.
fn app_path(dir: Option<&Path>, path: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    let is_exe = |p: &Path| {
        use std::os::unix::fs::PermissionsExt;
        p.metadata()
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    };
    dir.into_iter()
        .map(Path::to_path_buf)
        .chain(path.into_iter().flat_map(std::env::split_paths))
        .map(|d| d.join(APP))
        .find(|p| is_exe(p))
}

/// Asks for the store passphrase only once the daemon is known to be
/// unlocked, then prints the value and a newline.
///
/// Whatever is sent after a prompt goes over a new connection, here and
/// wherever else the CLI asks the daemon something first: the daemon closes
/// a connection left idle, and a person may take longer than that to type.
fn get(
    socket: Option<PathBuf>,
    env: Option<EnvName>,
    project: Option<ProjectName>,
    json: bool,
    key: KeyName,
) -> Result<(), CliError> {
    #[expect(
        clippy::expect_used,
        reason = "gather(_, _, true, _) never returns None"
    )]
    let facts = gather(env, project, true, false)?.expect("required facts");
    let Response::Status(status) =
        connect(socket.clone())?.request(Request::Status { facts: None })?
    else {
        return Err(unexpected());
    };
    if status.locked {
        return Err(CliError::locked());
    }
    let passphrase = prompt("Passphrase for the local store: ")?;
    let Response::Value { value } = connect(socket)?.request(Request::Get {
        facts,
        key,
        passphrase,
    })?
    else {
        return Err(unexpected());
    };
    let line = if json {
        #[derive(serde::Serialize)]
        struct Out<'a> {
            value: &'a str,
        }
        let s = serde_json::to_string(&Out {
            value: value.expose(),
        });
        Zeroizing::new(s.map_err(output_error)?)
    } else {
        Zeroizing::new(value.expose().to_owned())
    };
    let mut out = io::stdout().lock();
    out.write_all(line.as_bytes())
        .and_then(|()| out.write_all(b"\n"))
        .and_then(|()| out.flush())
        .map_err(output_error)
}

fn store(socket: Option<PathBuf>, json: bool, action: StoreAction) -> Result<(), CliError> {
    let req = match action {
        StoreAction::List => {
            let mut client = connect(socket)?;
            let Response::StoreList(listing) = client.request(Request::StoreList)? else {
                return Err(unexpected());
            };
            return if json {
                print_json(&listing)
            } else {
                print_line(&render_store_list(&listing))
            };
        }
        StoreAction::Init => return store_init(socket, json),
        StoreAction::Clear { project } => return store_clear(socket, json, &project),
        StoreAction::Set { section, keys } => {
            let mut seen = std::collections::BTreeSet::new();
            if let Some(twice) = keys.iter().find(|k| !seen.insert(*k)) {
                return Err(usage(format!("{twice} is given twice")));
            }
            // A value typed after the key would otherwise become a key name,
            // which is shown wherever keys are listed.
            if keys.len() > 1
                && let Some(lower) = keys
                    .iter()
                    .position(|k| k.as_str().chars().any(|c| c.is_ascii_lowercase()))
            {
                return Err(usage(format!(
                    "argument {} has lower-case letters; a value is never an argument, and to set \
                     several keys at once each must be upper case; set a lower-case key on its own \
                     with `kagebunshin store set {section} <KEY>`",
                    lower + 2
                )));
            }
            let passphrase = match prompt("Passphrase for the local store: ") {
                Ok(passphrase) => passphrase,
                // As when an agent runs this: a person types the values,
                // and the passphrase, into the app.
                Err(e) if e.code == "no_terminal" => {
                    return store_ask(socket, json, section, keys);
                }
                Err(e) => return Err(e),
            };
            match <[KeyName; 1]>::try_from(keys) {
                Ok([key]) => {
                    let value = read_value(&key)?;
                    Request::StoreSet {
                        section,
                        key,
                        value,
                        passphrase,
                        sensitive: false,
                    }
                }
                Err(keys) => Request::StoreSetMany {
                    sections: vec![(section, read_values(keys)?)],
                    passphrase,
                },
            }
        }
        StoreAction::Unset { section, key } => Request::StoreUnset {
            section,
            key,
            passphrase: prompt("Passphrase for the local store: ")?,
        },
        StoreAction::Passwd => Request::StorePasswd {
            passphrase: prompt("Current passphrase: ")?,
            new_passphrase: new_passphrase("New passphrase: ")?,
        },
    };
    store_change(socket, json, req)
}

/// `mark`: adds a sensitive mark with no passphrase. There is no command
/// to remove one.
fn mark(
    socket: Option<PathBuf>,
    json: bool,
    env: Option<EnvName>,
    target: MarkAction,
) -> Result<(), CliError> {
    let target = match target {
        MarkAction::Env {
            project,
            environment,
        } => {
            if let Some(given) = env.filter(|given| given != &environment) {
                return Err(usage(format!(
                    "two environments given: {environment} and --env {given}"
                )));
            }
            MarkTarget::Env {
                project,
                env: environment,
            }
        }
        MarkAction::Secret { provider, location } => MarkTarget::Secret {
            secret: Origin::new(provider.provider(), location),
        },
        MarkAction::Key { section, key } => MarkTarget::Key { section, key },
    };
    store_change(socket, json, Request::AddMark { target })
}

/// Sends a request that changes the store and says what it did.
fn store_change(socket: Option<PathBuf>, json: bool, req: Request) -> Result<(), CliError> {
    let mut client = connect(socket)?;
    let Response::Store { change, locked } = client.request(req)? else {
        return Err(unexpected());
    };
    if json {
        return print_json(&serde_json::json!({ "change": change, "locked": locked }));
    }
    let what = match change {
        Change::Created => "created the local store",
        Change::Added => "added",
        Change::Replaced => "replaced",
        Change::Removed => "removed",
        Change::Rekeyed => "changed the passphrase",
        Change::Marked => "marked sensitive",
        Change::Unmarked => "no longer marked sensitive",
        Change::Enabled => "turned the remote endpoint on",
        Change::Disabled => "turned the remote endpoint off",
    };
    print_line(what)
}

/// `store set` with no terminal: the app asks a person for the value of
/// each of `keys` and for the passphrase, and writes them. No value comes
/// through here; this says which keys were set, which of those had a value
/// before, and which the person left empty.
fn store_ask(
    socket: Option<PathBuf>,
    json: bool,
    section: Section,
    keys: Vec<KeyName>,
) -> Result<(), CliError> {
    let mut client = connect(socket)?;
    let names = |keys: &[KeyName]| {
        let names: Vec<&str> = keys.iter().map(KeyName::as_str).collect();
        names.join(", ")
    };
    // Only said when it will wait: with the app closed the daemon refuses
    // at once, and says how to go on.
    if matches!(
        client.request(Request::Status { facts: None }),
        Ok(Response::Status(status)) if status.app
    ) {
        eprintln!(
            "waiting for a person to type, in the kagebunshin app, the {} of {} for [{section}] \
             of the local store: its window has a field for each key and takes the store's \
             passphrase",
            plural(keys.len(), "value", "values"),
            names(&keys)
        );
    }
    let Response::StoreTyped {
        set,
        replaced,
        left,
        locked,
        ..
    } = client.request(Request::StoreAsk {
        section: section.clone(),
        keys,
        cwd: std::env::current_dir().unwrap_or_default(),
        command: std::env::args().collect(),
    })?
    else {
        return Err(unexpected());
    };
    if json {
        return print_json(&serde_json::json!({
            "section": section,
            "set": set,
            "replaced": replaced,
            "left": left,
            "locked": locked,
        }));
    }
    let mut line = format!("set {} in [{section}], typed in the app", names(&set));
    if !replaced.is_empty() {
        line.push_str(&format!(
            "; {} replaced the {} already there",
            names(&replaced),
            plural(replaced.len(), "value", "values")
        ));
    }
    if !left.is_empty() {
        line.push_str(&format!(
            "; {} {} left empty there and {} as before",
            names(&left),
            plural(left.len(), "was", "were"),
            plural(left.len(), "is", "are"),
        ));
    }
    print_line(&line)
}

/// `store clear PROJECT`: removes every section of a project that is gone,
/// which `project remove` leaves. Refused while the project is there: its
/// environments read those values, and this may be their only copy. With
/// the daemon unlocked, what goes is named before the passphrase is asked
/// for, and nothing is asked when there is nothing.
fn store_clear(socket: Option<PathBuf>, json: bool, project: &ProjectName) -> Result<(), CliError> {
    let config = |e: &dyn std::fmt::Display| CliError::new(Exit::Failure, "config", e.to_string());
    let dir = ConfigDir::from_env().map_err(|e| config(&e))?;
    let registry = Registry::load(&dir).map_err(|e| config(&e))?;
    if registry.project(project).is_some() {
        return Err(CliError::new(
            Exit::Refused,
            "config",
            format!(
                "project {project} is still there, and its environments read these values; \
                 nothing was removed"
            ),
        )
        .with_hint(format!(
            "`kagebunshin project remove {project}` removes the project; \
             `kagebunshin store unset SECTION KEY` removes one key"
        )));
    }
    let listed = connect(socket.clone())?.request(Request::StoreList);
    let sections: Option<Vec<(Section, usize)>> = match listed {
        Ok(Response::StoreList(l)) => Some(
            l.sections
                .into_iter()
                .filter(|s| s.section.project == *project)
                .map(|s| (s.section, s.keys.len()))
                .collect(),
        ),
        Ok(_) => return Err(unexpected()),
        // Locked: the write itself says whether anything is there.
        Err(ClientError::Daemon(w)) if w.code == ErrorCode::Locked => None,
        Err(e) => return Err(e.into()),
    };
    let named = sections.as_ref().map(|sections| {
        let each: Vec<String> = sections
            .iter()
            .map(|(s, n)| format!("[{s}] ({n} {})", plural(*n, "key", "keys")))
            .collect();
        each.join(", ")
    });
    if let Some(named) = &named {
        if named.is_empty() {
            return Err(store_error(crate::store::StoreError::NoSection {
                project: project.clone(),
            }));
        }
        eprintln!("this removes {named} from the local store");
    }
    // With no terminal, as when an agent runs this, it is a person's.
    let passphrase = prompt("Passphrase for the local store: ").map_err(|e| {
        if e.code != "no_terminal" {
            return e;
        }
        e.human(format!(
            "Please run `kagebunshin store clear {project}` in a terminal; it asks for the store \
             passphrase and removes the values project {project} left in the local store."
        ))
    })?;
    // Over a new connection, as in `get`.
    let Response::Store { change, locked } = connect(socket)?.request(Request::StoreClear {
        project: project.clone(),
        passphrase,
    })?
    else {
        return Err(unexpected());
    };
    if json {
        return print_json(&serde_json::json!({
            "change": change,
            "locked": locked,
            "sections": sections.map(|sections| {
                let names: Vec<String> = sections.iter().map(|(s, _)| s.to_string()).collect();
                names
            }),
        }));
    }
    print_line(&match named {
        Some(named) => format!("removed {named}"),
        None => format!("removed every section of project {project}"),
    })
}

/// Creates the store here rather than in the daemon: until it exists there
/// is no passphrase to tell a human from an agent, so the daemon creates
/// none. Writing it takes access to the config directory, not just the
/// socket. One sitting: the daemon is then locked and unlocked with the new
/// store, so `unlock` does not ask again.
fn store_error(e: crate::store::StoreError) -> CliError {
    let code = match e {
        crate::store::StoreError::Exists { .. } => "store_exists",
        _ => "store",
    };
    CliError::new(Exit::Failure, code, e.to_string())
}

/// The config directory, created private if it is not there. Whether it
/// was created.
fn config_dir() -> Result<(ConfigDir, bool), CliError> {
    let dir =
        ConfigDir::from_env().map_err(|e| CliError::new(Exit::Failure, "config", e.to_string()))?;
    let created = !dir.path().exists();
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir.path())
        .map_err(|e| {
            CliError::new(
                Exit::Failure,
                "config",
                format!("{}: {e}", dir.path().display()),
            )
        })?;
    Ok((dir, created))
}

/// Locks the daemon, so a session without the store ends, and unlocks it
/// with `passphrase`. Whether a daemon answered.
fn relock(socket: Option<PathBuf>, passphrase: WireSecret) -> Result<bool, CliError> {
    let Ok(mut client) = connect(socket) else {
        return Ok(false);
    };
    client.request(Request::Lock)?;
    client.request(Request::Unlock {
        passphrase: Some(passphrase),
    })?;
    Ok(true)
}

fn store_init(socket: Option<PathBuf>, json: bool) -> Result<(), CliError> {
    let dir =
        ConfigDir::from_env().map_err(|e| CliError::new(Exit::Failure, "config", e.to_string()))?;
    let file = crate::store::StoreFile::new(dir.store_file());
    if file.exists().map_err(store_error)? {
        return Err(store_error(crate::store::StoreError::Exists {
            path: file.path().to_owned(),
        }));
    }
    let passphrase = new_passphrase("New passphrase for the local store: ")?;
    config_dir()?;
    file.create(&WireSecret::new(passphrase.expose().to_owned()).into_passphrase())
        .map_err(store_error)?;
    // Without a daemon the store is still created; `unlock` opens it later.
    let locked = !relock(socket, passphrase)?;
    if json {
        return print_json(&serde_json::json!({ "change": Change::Created, "locked": locked }));
    }
    print_line(if locked {
        "created the local store"
    } else {
        "created the local store; the daemon is unlocked"
    })
}

/// `setup`: the config directory, the store, the service, unlocked, and
/// the app in the launcher and at login. Each step that is already done is
/// left as it is, but the service is reinstalled, which restarts it on this
/// binary.
fn setup(socket: Option<PathBuf>, json: bool, no_service: bool) -> Result<(), CliError> {
    let (dir, created_dir) = config_dir()?;
    let file = crate::store::StoreFile::new(dir.store_file());
    let existed = file.exists().map_err(store_error)?;
    let passphrase = if existed {
        let p = prompt("Passphrase for the local store: ")?;
        // Checked here, before the service is touched.
        file.open(&WireSecret::new(p.expose().to_owned()).into_passphrase())
            .map_err(store_error)?;
        p
    } else {
        let p = new_passphrase("New passphrase for the local store: ")?;
        file.create(&WireSecret::new(p.expose().to_owned()).into_passphrase())
            .map_err(store_error)?;
        p
    };
    let unit = if no_service {
        None
    } else {
        Some(units::write_unit(socket.clone(), true)?)
    };
    let socket = socket.or_else(|| unit.as_ref().map(|u| u.socket.clone()));
    // A service just started may take a moment to listen.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let unlocked = loop {
        if relock(
            socket.clone(),
            WireSecret::new(passphrase.expose().to_owned()),
        )? {
            break true;
        }
        if unit.is_none() || std::time::Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    };
    if !unlocked {
        let store = if existed { "exists" } else { "is created" };
        return Err(CliError::new(
            Exit::DaemonNotRunning,
            "daemon_not_running",
            format!(
                "the local store {store}, but the daemon did not answer, so it is still locked"
            ),
        )
        .with_hint(error::start_daemon_hint())
        .human(error::start_daemon_hint()));
    }
    // Only beside the service, and only where the app is installed too.
    // The daemon is set up by now, so a file that cannot be written warns.
    // An app that runs is one started on the build before this: it is
    // restarted, as the daemon was. With none running, one is started only
    // by the setup that made the store: after that, an app that is not
    // running is one its person ended.
    let (launcher, app_restarted, app_started) = if unit.is_some() && cfg!(target_os = "linux") {
        match desktop::write(socket.clone()) {
            Ok(files) => {
                let socket = units::socket(socket)?;
                let restarted = desktop::restarted(&socket);
                let started = !restarted && !existed && desktop::started_first(&socket);
                (files, restarted, started)
            }
            Err(e) if e.code == "no_app" => (Vec::new(), false, false),
            Err(e) => {
                error::warn(&e.message);
                (Vec::new(), false, false)
            }
        }
    } else {
        (Vec::new(), false, false)
    };
    if json {
        return print_json(&serde_json::json!({
            "config_dir": dir.path(),
            "store": if existed { "existing" } else { "created" },
            "unit": unit.as_ref().map(|u| &u.unit),
            "launcher": launcher,
            "app_restarted": app_restarted,
            "app_started": app_started,
        }));
    }
    let path = dir.path().display();
    print_line(&if created_dir {
        format!("created {path}")
    } else {
        format!("using {path}")
    })?;
    print_line(if existed {
        "the local store exists; its passphrase is right"
    } else {
        "created the local store"
    })?;
    if let Some(u) = &unit {
        print_line(&format!(
            "wrote {} and started the daemon",
            u.unit.display()
        ))?;
    }
    print_line("the daemon is unlocked")?;
    for f in launcher.iter().filter(|f| f.reason.is_some()) {
        let why = f.reason.unwrap_or_default();
        print_line(&format!("left alone {} ({why})", f.path.display()))?;
    }
    if launcher.iter().any(|f| f.reason.is_none()) {
        print_line(if app_restarted {
            "added the app to the launcher and restarted it: it is in the tray, \
             and starts there at login"
        } else if app_started {
            "added the app to the launcher and started it: it is in the tray, \
             and starts there at login"
        } else {
            "added the app to the launcher; it starts in the tray at login \
             (now: `kagebunshin app --hidden`)"
        })?;
    }
    // With no project yet: how the first ones start.
    if Registry::load(&dir).is_ok_and(|r| r.projects().next().is_some()) {
        return Ok(());
    }
    print_line(&format!(
        "\nnext: name the folders of the projects to start with\n  kagebunshin onboard DIR…\n\
         then, in each, paste this line into your coding agent:\n  {}",
        onboard::PASTE
    ))
}

/// The front matter that makes the agent instructions an OpenCode skill.
const SKILL_HEADER: &str = "---
name: kagebunshin
description: Use kagebunshin to get a project's secrets: set up which secrets a repository uses (AWS Secrets Manager, Proton Pass or the local store) and run commands, such as tests, with them in their environment, without ever seeing or printing a value.
---
";

/// Reads a passphrase from the controlling terminal, without echo. Never
/// from stdin, so a piped value cannot be taken for the passphrase.
pub(super) fn prompt(label: &str) -> Result<WireSecret, CliError> {
    rpassword::prompt_password(label)
        .map(WireSecret::new)
        .map_err(|e| {
            CliError::new(
                Exit::Failure,
                "no_terminal",
                format!("cannot read a passphrase from the terminal: {e}"),
            )
            .with_hint("run this in an interactive terminal")
        })
}

/// A new passphrase, typed twice. Empty is refused here rather than after a
/// round trip to the daemon.
fn new_passphrase(label: &str) -> Result<WireSecret, CliError> {
    let first = prompt(label)?;
    if first == WireSecret::new(String::new()) {
        return Err(CliError::new(
            Exit::Failure,
            "store",
            "the passphrase must not be empty",
        ));
    }
    if prompt("Confirm: ")? != first {
        return Err(CliError::new(
            Exit::Failure,
            "store",
            "the passphrases do not match",
        ));
    }
    Ok(first)
}

/// The value for `store set`: typed at the terminal without echo, or all of
/// stdin when it is piped, less one trailing newline.
fn read_value(key: &KeyName) -> Result<WireSecret, CliError> {
    read_secret(&format!("Value for {key}: "))
}

/// The values for `store set` with several keys: each typed at the terminal
/// without echo, in turn, or one line of piped stdin each, in order. A
/// value with a line break has to be set on its own.
fn read_values(keys: Vec<KeyName>) -> Result<Vec<(KeyName, WireSecret)>, CliError> {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        return keys
            .into_iter()
            .map(|k| Ok((k.clone(), read_value(&k)?)))
            .collect();
    }
    let mut buf = Zeroizing::new(String::new());
    stdin.lock().read_to_string(&mut buf).map_err(|e| {
        CliError::new(
            Exit::Failure,
            "stdin",
            format!("cannot read stdin as UTF-8 text: {e}"),
        )
    })?;
    one_value_per_line(&buf, keys)
}

/// `text` split into one value per key, in order: one line each, a final
/// line break and any `\r` before a line break dropped. The message names
/// counts, never a value.
fn one_value_per_line(
    text: &str,
    keys: Vec<KeyName>,
) -> Result<Vec<(KeyName, WireSecret)>, CliError> {
    let text = text.strip_suffix('\n').unwrap_or(text);
    let lines: Vec<&str> = text.split('\n').collect();
    if lines.len() != keys.len() {
        return Err(CliError::new(
            Exit::Failure,
            "stdin",
            format!(
                "stdin has {} {}, but {} keys were given: pipe one value per line, in the order of the keys",
                lines.len(),
                plural(lines.len(), "line", "lines"),
                keys.len()
            ),
        ));
    }
    Ok(keys
        .into_iter()
        .zip(lines)
        .map(|(k, line)| {
            let value = line.strip_suffix('\r').unwrap_or(line);
            (k, WireSecret::new(value.to_owned()))
        })
        .collect())
}

/// A secret from stdin when it is not a terminal (one trailing newline
/// dropped), else at a hidden prompt.
pub(super) fn read_secret(label: &str) -> Result<WireSecret, CliError> {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        return prompt(label);
    }
    let mut buf = zeroize::Zeroizing::new(Vec::new());
    stdin
        .lock()
        .read_to_end(&mut buf)
        .map_err(|e| CliError::new(Exit::Failure, "stdin", format!("cannot read stdin: {e}")))?;
    if buf.ends_with(b"\n") {
        buf.pop();
        if buf.ends_with(b"\r") {
            buf.pop();
        }
    }
    let value = String::from_utf8(std::mem::take(&mut *buf)).map_err(|e| {
        // Zero the rejected bytes too.
        drop(zeroize::Zeroizing::new(e.into_bytes()));
        CliError::new(Exit::Failure, "stdin", "the value on stdin is not UTF-8")
    })?;
    Ok(WireSecret::new(value))
}

/// Where the CLI runs, for the daemon to pick a project and environment.
/// `None` outside a git checkout, unless `required`.
///
/// For another machine's daemon (`remote`), `--project` is enough: its
/// grant decides what this machine may use, so the folder need not be a
/// checkout, nor git be installed. The facts are then of the folder alone.
///
/// The `.env.example` is the project file's `env_example` when the
/// configuration loads and claims this checkout, else the nearest one, not
/// above the project's `path`. Only key names leave this function; [`repo`]
/// never opens a real env file.
fn gather(
    env: Option<EnvName>,
    project: Option<ProjectName>,
    required: bool,
    remote: bool,
) -> Result<Option<Facts>, CliError> {
    gather_checked(env, project, required, remote).map(|(facts, ..)| facts)
}

/// [`gather`], plus the `.env.example` lines that could not be read (a key
/// on one of them is in no list the daemon sees) and its values that are
/// not empty, which stay here: they are only for [`set_var_fixes`].
fn gather_checked(
    env: Option<EnvName>,
    project: Option<ProjectName>,
    required: bool,
    remote: bool,
) -> Result<
    (
        Option<Facts>,
        Vec<repo::env_example::BadLine>,
        ExampleValues,
    ),
    CliError,
> {
    let cwd = std::env::current_dir()
        .map_err(|e| CliError::new(Exit::Failure, "cwd", format!("no working directory: {e}")))?;
    gather_at(cwd, env, project, required, remote)
}

/// [`gather_checked`] for folder `cwd` instead of the working directory.
fn gather_at(
    cwd: PathBuf,
    env: Option<EnvName>,
    project: Option<ProjectName>,
    required: bool,
    remote: bool,
) -> Result<
    (
        Option<Facts>,
        Vec<repo::env_example::BadLine>,
        ExampleValues,
    ),
    CliError,
> {
    let checkout = match Git::default().checkout(&cwd) {
        Ok(c) => c,
        Err(GitError::NotARepo { .. } | GitError::Spawn(_)) if remote && project.is_some() => {
            crate::config::Checkout {
                root: cwd.clone(),
                remotes: Vec::new(),
            }
        }
        Err(GitError::NotARepo { .. }) if !required => {
            return Ok((None, Vec::new(), ExampleValues::default()));
        }
        // A machine that only asks another's daemon needs no git.
        Err(GitError::Spawn(_)) if !required && remote => {
            return Ok((None, Vec::new(), ExampleValues::default()));
        }
        Err(e) => {
            return Err(
                CliError::new(Exit::Failure, "no_project", e.to_string()).with_hint(if remote {
                    "run this inside a git checkout of the project, or name the project with \
                     `--project`"
                } else {
                    "run this inside a git checkout; kagebunshin identifies a project by its \
                     git remote"
                }),
            );
        }
    };
    let subdir = checkout.subdir(&cwd).filter(|d| !d.as_os_str().is_empty());
    let (configured, top) = local_project(&checkout, subdir.as_deref(), project.as_ref());
    if let Some(top) = &top
        && !checkout.root.join(top.as_path()).is_dir()
    {
        error::warn(&format!(
            "the project's path {top} is not a folder of this checkout; \
             check it with kagebunshin project show"
        ));
    }
    let found = repo::load(
        &checkout.root,
        &cwd,
        top.as_ref().map(ProjectPath::as_path),
        configured.as_deref(),
    )
    .map_err(|e| CliError::new(Exit::Failure, "env_example", e.to_string()))?;
    let (example_keys, bad_lines, values) = match found {
        Some(f) => (Some(f.example.keys), f.example.bad_lines, f.example.values),
        None => (None, Vec::new(), ExampleValues::default()),
    };
    let env_file = crate::repo::env_file_with_values(&cwd);
    let facts = Facts {
        cwd,
        remotes: checkout.remotes,
        subdir,
        root: Some(checkout.root),
        project,
        env,
        example_keys,
        example_values: values.keys().cloned().collect(),
        env_file,
    };
    Ok((Some(facts), bad_lines, values))
}

/// For each of `missing` that `.env.example` gives a value, the command
/// that sets it as a plain setting. Only a suggestion: the value may be a
/// placeholder, or a secret.
pub(super) fn set_var_fixes(
    project: &ProjectName,
    env: &EnvName,
    missing: &[KeyName],
    values: &ExampleValues,
) -> Vec<Fix> {
    missing
        .iter()
        .filter_map(|k| Some((k, values.get(k)?)))
        .map(|(k, v)| Fix {
            command: format!(
                "kagebunshin project set-var {project} {env} {k} {}",
                shell_quote(v)
            ),
            note: "only if .env.example's value is the real setting, not a placeholder; a \
                   secret belongs in the store or a provider"
                .into(),
            who: Who::Agent,
        })
        .collect()
}

/// The `env_example` and `path` of the project this checkout matches, if
/// the configuration loads and one does; the daemon reports why not.
fn local_project(
    checkout: &crate::config::Checkout,
    subdir: Option<&Path>,
    project: Option<&ProjectName>,
) -> (Option<PathBuf>, Option<ProjectPath>) {
    let Some(registry) = ConfigDir::from_env()
        .ok()
        .and_then(|dir| Registry::load(&dir).ok())
    else {
        return (None, None);
    };
    let place = crate::config::Place {
        remotes: &checkout.remotes,
        subdir,
        root: Some(&checkout.root),
        project,
    };
    match registry.find(place) {
        Ok(found) => (
            found.project.file.env_example.clone(),
            found.project.file.path.clone(),
        ),
        Err(_) => (None, None),
    }
}

/// Prints `report` as JSON, with any `bad_lines` beside its fields, or as
/// `text` with a warning on stderr for each bad line: its number and
/// problem, never its text.
fn print_report(
    json: bool,
    report: &impl serde::Serialize,
    text: String,
    bad_lines: &[repo::env_example::BadLine],
) -> Result<(), CliError> {
    if json {
        #[derive(serde::Serialize)]
        struct Out<'a, R> {
            #[serde(flatten)]
            report: &'a R,
            #[serde(skip_serializing_if = "<[_]>::is_empty")]
            bad_lines: &'a [repo::env_example::BadLine],
        }
        return print_json(&Out { report, bad_lines });
    }
    print_line(&text)?;
    for b in bad_lines {
        eprintln!("warning: .env.example {b}");
    }
    Ok(())
}

fn plural<'a>(n: usize, one: &'a str, many: &'a str) -> &'a str {
    if n == 1 { one } else { many }
}

/// `list` and `search`: names, ids and keys from the daemon, never values.
fn list(
    socket: Option<PathBuf>,
    json: bool,
    provider: Option<project::SourceProvider>,
    prefix: String,
    search: Option<String>,
    keys: bool,
    aws: AwsArgs,
) -> Result<(), CliError> {
    if prefix.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(CliError::new(
            Exit::Usage,
            "usage",
            "--prefix must not contain whitespace or control characters",
        ));
    }
    let mut client = connect(socket)?;
    let Response::Listed {
        items, warnings, ..
    } = client.request(Request::List {
        provider: provider.map(project::SourceProvider::provider),
        prefix,
        search,
        aws: crate::source::aws_sm::AwsSettings {
            profile: aws.profile,
            region: aws.region,
        },
        keys,
    })?
    else {
        return Err(unexpected());
    };
    if json {
        return print_json(&serde_json::json!({ "items": items, "warnings": warnings }));
    }
    // The provider, not its raw id, which only --json shows; a title
    // column only when an item has one.
    let rows: Vec<[String; 4]> = items
        .iter()
        .map(|l| {
            let keys = match (&l.unread, l.plain) {
                (Some(why), _) => format!("({why})"),
                (None, true) => "(a plain string, not JSON)".to_owned(),
                (None, false) => l
                    .keys
                    .iter()
                    .map(KeyName::as_str)
                    .collect::<Vec<_>>()
                    .join(", "),
            };
            [
                l.name.clone(),
                l.title.clone().unwrap_or_default(),
                l.id.provider.as_str().to_owned(),
                keys,
            ]
        })
        .collect();
    let mut out = format!("{} {}", rows.len(), plural(rows.len(), "match", "matches"));
    if items.iter().any(|l| l.title.is_some()) {
        out.push_str(&table(&rows));
    } else {
        let rows: Vec<[String; 3]> = rows.into_iter().map(|[n, _, p, k]| [n, p, k]).collect();
        out.push_str(&table(&rows));
    }
    print_line(&out)?;
    for w in &warnings {
        eprintln!("warning: {w}");
    }
    Ok(())
}

fn render_providers(out: &mut String, providers: &[ProviderStatus]) {
    if providers.is_empty() {
        return;
    }
    out.push_str(
        "
providers:",
    );
    let rows: Vec<[String; 3]> = providers
        .iter()
        .map(|p| {
            let health = match &p.health {
                Health::Ok => "ok".to_owned(),
                Health::Locked => "locked: run `kagebunshin unlock`".to_owned(),
                Health::NotConnected { hint } => format!("not connected: {hint}"),
                Health::NeedsLogin { hint } => format!("needs login: {hint}"),
                Health::Failed { message } => format!("failed: {message}"),
            };
            [p.provider.as_str().to_owned(), p.detail.clone(), health]
        })
        .collect();
    out.push_str(&table(&rows));
}

/// What `status` says about the phone that approves requests and the
/// page it does that on.
fn render_phone(out: &mut String, p: &PhoneStatus) {
    if let Some(phone) = &p.paired {
        let name = &phone.name;
        match (&p.url, &p.problem) {
            (Some(url), _) => out.push_str(&format!("\nphone: {name} approves at {url}")),
            (None, Some(why)) => out.push_str(&format!(
                "\nphone: {name} is paired, its page is not served: {why}"
            )),
            (None, None) => out.push_str(&format!(
                "\nphone: {name} is paired, its page is not served yet"
            )),
        }
        out.push_str(&match (phone.notifies, &phone.untold) {
            (true, None) => "\n  notifications: on".to_owned(),
            (true, Some(why)) => format!("\n  notifications: on, but {why}"),
            (false, Some(why)) => format!("\n  notifications: off: {why}"),
            (false, None) => "\n  notifications: off (turn them on on its page, opened from the \
                              phone's home screen)"
                .to_owned(),
        });
        if let Some(last) = &p.last {
            out.push_str(&format!(
                "\n  last answered there: {} {}/{} at {}",
                if last.approved { "approved" } else { "denied" },
                last.project,
                last.env,
                crate::audit::utc(last.time)
            ));
        }
    }
    if let Some(pairing) = &p.pairing {
        out.push_str(&format!(
            "\nphone: pairing {}, for {} more",
            pairing.name,
            match pairing.left {
                s if s < 60 => format!("{s}s"),
                s => format!("{}m", s / 60),
            }
        ));
    }
}

fn render_status(
    r: &StatusReport,
    providers: &[ProviderStatus],
    human: &[next::Step],
    runs: Option<&audit::Usage>,
) -> String {
    let mut out = format!("daemon: {}", if r.locked { "locked" } else { "unlocked" });
    let now = crate::source::unix_now();
    for e in &r.expiring {
        out.push_str(&format!("\nwarning: {}", e.warning(now)));
    }
    render_providers(&mut out, providers);
    if let Some(remote) = &r.remote {
        remote::render(&mut out, remote, now);
    }
    if let Some(phone) = &r.phone {
        render_phone(&mut out, phone);
    }
    let Some(env) = &r.env else {
        if let Some(runs) = runs {
            out.push_str(&format!("\n{}", runs.line(false)));
        }
        if r.locked {
            out.push_str("\nrun `kagebunshin unlock` to see where each key comes from");
        }
        return out;
    };
    out.push_str(&format!("\nproject: {}\nenv: {}", env.project, env.env));
    if !env.example {
        out.push_str("\n.env.example: none found");
    }
    let rows: Vec<[String; 3]> = env
        .keys
        .iter()
        .map(|k| {
            let overrides = k.overridden.iter().map(ToString::to_string);
            let mut notes: Vec<String> = overrides.map(|o| format!("overrides {o}")).collect();
            if env.example && !k.in_example {
                notes.push("not in .env.example".into());
            }
            if k.sensitive {
                notes.push("sensitive".into());
            }
            [k.key.to_string(), k.origin.to_string(), notes.join("; ")]
        })
        .collect();
    let mut rows = rows;
    for v in &env.vars {
        let mut notes = vec![format!("= {}", shell_quote(&v.value))];
        if env.example && !v.in_example {
            notes.push("not in .env.example".into());
        }
        rows.push([v.key.to_string(), "project file".into(), notes.join("; ")]);
    }
    rows.sort_by(|a, b| a[0].cmp(&b[0]));
    out.push_str(&format!(
        "\n{} {}",
        rows.len(),
        plural(rows.len(), "key", "keys")
    ));
    out.push_str(&table(&rows));
    if !env.missing.is_empty() {
        out.push_str("\nmissing (in .env.example, set by no source):");
        for k in &env.missing {
            out.push_str(&format!("\n  {k}"));
        }
    }
    render_shared(&mut out, r, env);
    render_fixes(&mut out, &env.fixes);
    // A fix printed just above is not printed again.
    let human: Vec<_> = human
        .iter()
        .filter(|h| {
            !env.fixes
                .iter()
                .any(|f| Some(&f.command) == h.command.as_ref())
        })
        .collect();
    if !human.is_empty() {
        out.push_str("\nleft for the human:");
        for h in human {
            match &h.command {
                Some(c) => out.push_str(&format!("\n  {}: {c}", h.what)),
                None => out.push_str(&format!("\n  {}", h.what)),
            }
        }
    }
    if let Some(proof) = env.proof.as_ref().filter(|_| env.missing.is_empty()) {
        out.push_str(&format!("\n{}", next::proof_line(proof, now)));
    }
    // Of one environment, said only when there were some: an environment
    // being set up has none yet.
    if let Some(runs) = runs.filter(|r| r.count > 0) {
        out.push_str(&format!("\n{}", runs.line(true)));
    }
    for w in &env.warnings {
        out.push_str(&format!("\nwarning: {w}"));
    }
    out
}

/// The secrets of `env` that other environments read too, and what marking
/// `env` sensitive does to each: a secret's mark holds in every
/// environment that reads it.
fn render_shared(out: &mut String, r: &StatusReport, env: &crate::ipc::protocol::EnvStatus) {
    let rows: Vec<[String; 3]> = r
        .shared
        .iter()
        .filter(|s| s.of(&env.project, &env.env))
        .map(|s| {
            let with: Vec<String> = s.with.iter().map(ToString::to_string).collect();
            let note = if s.sensitive {
                "sensitive: each of them needs approval for its keys"
            } else if s.stays_unmarked() {
                ""
            } else if s.production {
                "marked with it: its name looks like production"
            } else {
                "marked with it: none of them is open"
            };
            [
                s.name(),
                format!("also read by {}", with.join(", ")),
                note.to_owned(),
            ]
        })
        .collect();
    if rows.is_empty() {
        return;
    }
    out.push_str(&format!(
        "\nshared with other environments (marking {} sensitive leaves these unmarked unless \
         noted; a human can mark them as well in the app):",
        env.env
    ));
    out.push_str(&table(&rows));
}

/// The commands that would fill in what is missing, those the caller can
/// run first, then those for a human. A note several commands in a row
/// share is printed once, after the last of them.
fn render_fixes(out: &mut String, fixes: &[Fix]) {
    if fixes.is_empty() {
        return;
    }
    out.push_str("\nto fill in what is missing:");
    for (who, title) in [(Who::Agent, "you can run"), (Who::Human, "ask the human")] {
        let group: Vec<&Fix> = fixes.iter().filter(|f| f.who == who).collect();
        if group.is_empty() {
            continue;
        }
        out.push_str(&format!("\n  {title}:"));
        for (i, f) in group.iter().enumerate() {
            out.push_str(&format!("\n    {}", f.command));
            if group.get(i + 1).is_none_or(|next| next.note != f.note) {
                out.push_str(&format!("\n      ({})", f.note));
            }
        }
    }
}

fn render_diff(r: &DiffReport, verbose: bool) -> String {
    let mut out = format!("project: {}\nenv: {}", r.project, r.env);
    if !r.example {
        out.push_str("\n.env.example: none found, so no keys are missing or extra");
    }
    let list = |out: &mut String, title: &str, keys: &[crate::types::KeyName]| {
        if !keys.is_empty() {
            out.push_str(&format!("\n{title}:"));
            for k in keys {
                out.push_str(&format!("\n  {k}"));
            }
        }
    };
    list(
        &mut out,
        "missing (in .env.example, set by no source)",
        &r.missing,
    );
    let extra = "extra (set by a source, not in .env.example)";
    if verbose {
        list(&mut out, extra, &r.extra);
    } else if !r.extra.is_empty() {
        let n = r.extra.len();
        out.push_str(&format!("\n{extra}: {n} {}", plural(n, "key", "keys")));
        let rows: Vec<[String; 2]> = r
            .extra_by_origin
            .iter()
            .map(|c| {
                let n = c.keys;
                [
                    c.origin.to_string(),
                    format!("{n} {}", plural(n, "key", "keys")),
                ]
            })
            .collect();
        out.push_str(&table(&rows));
    }
    if !r.conflicts.is_empty() && !verbose {
        // One line per winner and what it overrides.
        let mut counts: Vec<([String; 2], usize)> = Vec::new();
        for c in &r.conflicts {
            let lost: Vec<String> = c.overridden.iter().map(ToString::to_string).collect();
            let row = [
                c.origin.to_string(),
                format!("overrides {}", lost.join(", ")),
            ];
            match counts.iter_mut().find(|(r, _)| *r == row) {
                Some((_, n)) => *n += 1,
                None => counts.push((row, 1)),
            }
        }
        let n = r.conflicts.len();
        out.push_str(&format!(
            "\nconflicts (set by more than one source, the last wins): {n} {}",
            plural(n, "key", "keys")
        ));
        let rows: Vec<[String; 3]> = counts
            .into_iter()
            .map(|([origin, lost], n)| [origin, format!("{n} {}", plural(n, "key", "keys")), lost])
            .collect();
        out.push_str(&table(&rows));
    } else if !r.conflicts.is_empty() {
        out.push_str("\nconflicts (set by more than one source, the last wins):");
        let rows: Vec<[String; 3]> = r
            .conflicts
            .iter()
            .map(|c| {
                let lost: Vec<String> = c.overridden.iter().map(ToString::to_string).collect();
                [
                    c.key.to_string(),
                    c.origin.to_string(),
                    format!("overrides {}", lost.join(", ")),
                ]
            })
            .collect();
        out.push_str(&table(&rows));
    }
    if r.missing.is_empty() && r.extra.is_empty() && r.conflicts.is_empty() {
        out.push_str("\nno differences");
    }
    render_fixes(&mut out, &r.fixes);
    for w in &r.warnings {
        out.push_str(&format!("\nwarning: {w}"));
    }
    out
}

fn render_store_list(l: &StoreListing) -> String {
    if l.sections.is_empty() {
        return "the local store is empty".into();
    }
    let mut out = String::new();
    for (i, s) in l.sections.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&format!("[{}]", s.section));
        for k in &s.keys {
            let mark = if s.sensitive.contains(k) {
                " (sensitive)"
            } else {
                ""
            };
            out.push_str(&format!("\n  {k}{mark}"));
        }
    }
    out
}

fn render_sync(r: &SyncReport) -> String {
    if r.refreshed.is_empty() {
        // Nothing was read yet, or the last read failed: neither is kept.
        return "nothing is cached, so the next command reads every source afresh".into();
    }
    let mut lines = Vec::new();
    for s in &r.refreshed {
        match (&s.error, s.keys) {
            (Some(e), _) => lines.push(format!("{} {}: failed: {}", s.project, s.env, e.message)),
            (None, Some(n)) => lines.push(format!(
                "{} {}: {n} {}",
                s.project,
                s.env,
                plural(n, "key", "keys")
            )),
            (None, None) => lines.push(format!("{} {}: synced", s.project, s.env)),
        }
        for w in &s.warnings {
            lines.push(format!("warning: {w}"));
        }
    }
    lines.join("\n")
}

/// Rows indented two spaces, columns padded; trailing blanks trimmed.
fn table<const N: usize>(rows: &[[String; N]]) -> String {
    let width = |i: usize| rows.iter().map(|r| r[i].chars().count()).max().unwrap_or(0);
    let widths: Vec<usize> = (0..N).map(width).collect();
    rows.iter()
        .map(|row| {
            let mut line = String::from("\n");
            for (cell, w) in row.iter().zip(&widths) {
                line.push_str(&format!("  {cell:<w$}"));
            }
            line.trim_end().to_owned()
        })
        .collect()
}

pub(super) fn connect(socket: Option<PathBuf>) -> Result<Client, CliError> {
    let socket = match socket {
        Some(p) => {
            paths::check_socket_path(&p).map_err(usage)?;
            p
        }
        None => paths::default_socket_path().map_err(usage)?,
    };
    Ok(Client::connect(&socket, DEFAULT_TIMEOUT)?)
}

/// This machine's daemon, or machine `remote`'s remote endpoint.
pub(super) fn connect_to(
    socket: Option<PathBuf>,
    remote: Option<&str>,
) -> Result<Client, CliError> {
    match remote {
        Some(machine) => remote::client(machine),
        None => connect(socket),
    }
}

fn usage(e: impl std::fmt::Display) -> CliError {
    CliError::new(Exit::Usage, "usage", e.to_string())
}

pub(super) fn unexpected() -> CliError {
    CliError::new(
        Exit::Failure,
        "daemon_io",
        "unexpected reply from the daemon",
    )
}

fn expect(r: Response, ok: impl Fn(&Response) -> bool) -> Result<(), CliError> {
    if ok(&r) { Ok(()) } else { Err(unexpected()) }
}

fn print_line(s: &str) -> Result<(), CliError> {
    writeln!(io::stdout(), "{s}").map_err(output_error)
}

fn print_json(v: &impl serde::Serialize) -> Result<(), CliError> {
    let s = serde_json::to_string(v).map_err(output_error)?;
    print_line(&s)
}

fn output_error(e: impl std::fmt::Display) -> CliError {
    CliError::new(Exit::Failure, "output", format!("cannot write output: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn command_tree_is_valid() {
        Cli::command().debug_assert();
    }

    /// One snapshot per command, so a change to the CLI surface shows up in
    /// review as a diff of its help text.
    #[test]
    fn help_snapshots() {
        let mut root = Cli::command();
        root.build();
        insta::assert_snapshot!("help", root.render_help().to_string());
        for sub in root.get_subcommands() {
            let name = sub.get_name().to_owned();
            if name == "help" {
                continue;
            }
            insta::assert_snapshot!(
                format!("help_{name}"),
                sub.clone().render_help().to_string()
            );
            for nested in sub.get_subcommands().filter(|s| s.get_name() != "help") {
                let n = nested.get_name();
                let text = nested.clone().render_help().to_string();
                insta::assert_snapshot!(format!("help_{name}_{n}"), text);
            }
        }
    }

    /// For another machine's daemon a named project needs no checkout:
    /// the facts are the folder's, its `.env.example` included. With no
    /// name, and for this machine's daemon, a checkout it is.
    #[test]
    fn a_remote_request_with_a_project_needs_no_checkout() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_owned();
        std::fs::write(dir.join(".env.example"), "A=\nB=\n").unwrap();
        let widget = || Some("widget".parse::<ProjectName>().unwrap());

        let (facts, bad, _) = gather_at(dir.clone(), None, widget(), true, true).unwrap();
        let facts = facts.unwrap();
        assert!(facts.remotes.is_empty() && facts.subdir.is_none() && bad.is_empty());
        assert_eq!(facts.project, widget());
        let keys: Vec<String> = (facts.example_keys.unwrap().iter())
            .map(ToString::to_string)
            .collect();
        assert_eq!(keys, ["A", "B"]);

        let e = gather_at(dir.clone(), None, None, true, true).unwrap_err();
        assert!(e.message.ends_with("is not inside a git checkout"), "{e:?}");
        assert!(e.hint.unwrap().contains("`--project`"));
        let e = gather_at(dir.clone(), None, widget(), true, false).unwrap_err();
        assert!(!e.hint.unwrap().contains("--project"));
        // `status` asks for no environment there.
        let (facts, ..) = gather_at(dir, None, None, false, true).unwrap();
        assert!(facts.is_none());
    }

    #[test]
    fn the_app_is_found_next_to_the_cli_then_on_path() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let (here, on_path, empty) = (
            tmp.path().join("bin"),
            tmp.path().join("path"),
            tmp.path().join("empty"),
        );
        for d in [&here, &on_path, &empty] {
            std::fs::create_dir(d).unwrap();
        }
        for (d, mode) in [(&here, 0o755), (&on_path, 0o755), (&empty, 0o644)] {
            std::fs::write(d.join(APP), "").unwrap();
            std::fs::set_permissions(d.join(APP), std::fs::Permissions::from_mode(mode)).unwrap();
        }
        let path = std::env::join_paths([&empty, &on_path]).unwrap();
        assert_eq!(app_path(Some(&here), Some(&path)), Some(here.join(APP)));
        assert_eq!(app_path(Some(&empty), Some(&path)), Some(on_path.join(APP)));
        assert_eq!(app_path(None, None), None);
    }

    #[test]
    fn parses_global_flags_after_the_subcommand() {
        let cli = Cli::try_parse_from(["kagebunshin", "status", "--json", "--env", "dev"]).unwrap();
        assert!(cli.json);
        assert_eq!(cli.env.unwrap().as_str(), "dev");
        assert!(Cli::try_parse_from(["kagebunshin", "status", "--env", "Not Valid"]).is_err());
    }

    #[test]
    fn run_takes_everything_after_the_separator() {
        let cli = Cli::try_parse_from(["kagebunshin", "run", "--", "npm", "--json", "-x"]).unwrap();
        let Command::Run { command, .. } = cli.command else {
            panic!()
        };
        assert_eq!(command, ["npm", "--json", "-x"]);
        assert!(!cli.json, "--json after -- belongs to the child command");
    }

    /// What the environment shares, and what marking it does to each.
    #[test]
    fn status_shows_what_an_environment_shares() {
        use crate::ipc::protocol::{EnvStatus, KeyStatus};
        use crate::types::{Origin, Provider};
        let origin = Origin::new(Provider::AwsSm, "widget/dev");
        let status = StatusReport {
            locked: false,
            env: Some(EnvStatus {
                project: "widget".parse().unwrap(),
                env: "dev".parse().unwrap(),
                example: true,
                keys: ["API_URL", "TOKEN"]
                    .map(|k| KeyStatus {
                        key: k.parse().unwrap(),
                        origin: origin.clone(),
                        overridden: Vec::new(),
                        in_example: true,
                        sensitive: false,
                    })
                    .into(),
                vars: Vec::new(),
                missing: Vec::new(),
                skipped: Vec::new(),
                fixes: Vec::new(),
                warnings: Vec::new(),
                acknowledged: false,
                proof: None,
            }),
            expiring: Vec::new(),
            remote: None,
            waiting: Vec::new(),
            acknowledged: Vec::new(),
            shared: Vec::new(),
            app: false,
            phone: None,
        };
        let text = render_status(&status, &[], &[], None);
        assert!(!text.contains("shared with"), "{text}");

        let shared = |name: &str, prefix, open: &[&str], sensitive, production| {
            crate::ipc::protocol::SharedSecret {
                project: "widget".parse().unwrap(),
                env: "dev".parse().unwrap(),
                secret: Origin::new(Provider::AwsSm, name),
                prefix,
                with: vec!["widget.qa".parse().unwrap(), "shop.prod".parse().unwrap()],
                open: open.iter().map(|s| s.parse().unwrap()).collect(),
                sensitive,
                production,
            }
        };
        let status = StatusReport {
            shared: vec![
                shared("mail", false, &["widget.qa"], false, false),
                shared("tools/", true, &["widget.qa"], false, false),
                shared("sentry", false, &[], true, false),
                shared("acme/prod/db", false, &["widget.qa"], false, true),
                shared("ledger", false, &[], false, false),
            ],
            ..status
        };
        let text = render_status(&status, &[], &[], None);
        let at = text.find("\nshared with other environments").unwrap();
        let rows: Vec<&str> = text[at..].lines().skip(2).take(5).collect();
        let with = "also read by widget.qa, shop.prod";
        assert_eq!(
            rows,
            [
                format!("  aws_sm:mail          {with}"),
                format!("  aws_sm:tools/*       {with}"),
                format!(
                    "  aws_sm:sentry        {with}  sensitive: each of them needs approval for \
                     its keys"
                ),
                format!(
                    "  aws_sm:acme/prod/db  {with}  marked with it: its name looks like \
                     production"
                ),
                format!("  aws_sm:ledger        {with}  marked with it: none of them is open"),
            ],
            "{text}"
        );
    }

    #[test]
    fn several_piped_values_are_one_per_line() {
        let keys = || -> Vec<KeyName> { ["A", "B"].map(|k| k.parse().unwrap()).into() };
        for text in ["one\ntwo", "one\ntwo\n", "one\r\ntwo\r\n"] {
            let got: Vec<(String, String)> = one_value_per_line(text, keys())
                .unwrap()
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.expose().to_owned()))
                .collect();
            assert_eq!(
                got,
                [("A".into(), "one".into()), ("B".into(), "two".into())],
                "{text:?}"
            );
        }
        // An empty line is an empty value.
        let got = one_value_per_line("\ntwo\n", keys()).unwrap();
        assert_eq!(got[0].1.expose(), "");
        let c = crate::test_support::Canary::new();
        for text in [c.value().to_owned(), format!("{0}\n{0}\n{0}\n", c.value())] {
            let err = one_value_per_line(&text, keys()).unwrap_err();
            assert_eq!(err.code, "stdin");
            assert!(
                err.message.contains("but 2 keys were given"),
                "{}",
                err.message
            );
            crate::test_support::assert_no_canary(&c, &err.message);
        }
    }

    #[test]
    fn status_and_diff_list_missing_keys_and_their_fix() {
        use crate::ipc::protocol::EnvStatus;
        let missing: Vec<KeyName> = ["DB_URL", "STRIPE_KEY"].map(|k| k.parse().unwrap()).into();
        let fix = |command: &str, note: &str, who| Fix {
            command: command.into(),
            note: note.into(),
            who,
        };
        let fixes = vec![
            fix(
                "kagebunshin store set shop.dev DB_URL STRIPE_KEY",
                "it asks",
                Who::Human,
            ),
            fix(
                "kagebunshin project set-var shop dev PORT 3000",
                "if real",
                Who::Agent,
            ),
            fix(
                "kagebunshin project set-var shop dev LOG info",
                "if real",
                Who::Agent,
            ),
        ];
        let status = StatusReport {
            locked: false,
            env: Some(EnvStatus {
                project: "shop".parse().unwrap(),
                env: "dev".parse().unwrap(),
                example: true,
                keys: Vec::new(),
                vars: Vec::new(),
                missing: missing.clone(),
                skipped: Vec::new(),
                fixes: fixes.clone(),
                warnings: Vec::new(),
                acknowledged: false,
                proof: None,
            }),
            expiring: Vec::new(),
            remote: None,
            waiting: Vec::new(),
            acknowledged: Vec::new(),
            shared: Vec::new(),
            app: false,
            phone: None,
        };
        let text = render_status(&status, &[], &[], None);
        assert!(
            text.ends_with(
                "0 keys\nmissing (in .env.example, set by no source):\n  DB_URL\n  STRIPE_KEY\n\
                 to fill in what is missing:\n  \
                 you can run:\n    \
                 kagebunshin project set-var shop dev PORT 3000\n    \
                 kagebunshin project set-var shop dev LOG info\n      \
                 (if real)\n  \
                 ask the human:\n    \
                 kagebunshin store set shop.dev DB_URL STRIPE_KEY\n      \
                 (it asks)"
            ),
            "{text}"
        );
        let diff = DiffReport {
            project: "shop".parse().unwrap(),
            env: "dev".parse().unwrap(),
            example: true,
            missing,
            extra: Vec::new(),
            extra_by_origin: Vec::new(),
            conflicts: Vec::new(),
            skipped: Vec::new(),
            fixes,
            warnings: Vec::new(),
        };
        let text = render_diff(&diff, false);
        assert!(
            text.contains("ask the human:\n    kagebunshin store set shop.dev DB_URL STRIPE_KEY"),
            "{text}"
        );
    }

    #[test]
    fn status_shows_a_plain_setting_with_its_value() {
        use crate::ipc::protocol::{EnvStatus, VarStatus};
        let var = |k: &str, v: &str, in_example| VarStatus {
            key: k.parse().unwrap(),
            value: v.into(),
            in_example,
        };
        let status = StatusReport {
            locked: false,
            env: Some(EnvStatus {
                project: "shop".parse().unwrap(),
                env: "dev".parse().unwrap(),
                example: true,
                keys: Vec::new(),
                vars: vec![
                    var("GREETING", "hi there", false),
                    var("PORT", "3000", true),
                ],
                missing: Vec::new(),
                skipped: Vec::new(),
                fixes: Vec::new(),
                warnings: Vec::new(),
                acknowledged: false,
                proof: None,
            }),
            expiring: Vec::new(),
            remote: None,
            waiting: Vec::new(),
            acknowledged: Vec::new(),
            shared: Vec::new(),
            app: false,
            phone: None,
        };
        let text = render_status(&status, &[], &[], None);
        let rows: Vec<&str> = text
            .lines()
            .skip_while(|l| !l.ends_with("2 keys"))
            .collect();
        assert!(rows[1].starts_with("  GREETING  project file"), "{text}");
        assert!(
            rows[1].ends_with("= 'hi there'; not in .env.example"),
            "{text}"
        );
        assert!(rows[2].ends_with("project file  = 3000"), "{text}");
    }

    #[test]
    fn status_names_the_paired_phone_and_its_page() {
        use crate::ipc::protocol::{PhoneAnswer, PhonePairingView, PhoneView};
        let said = |p: PhoneStatus| {
            let mut out = String::new();
            render_phone(&mut out, &p);
            out
        };
        let none = PhoneStatus {
            paired: None,
            url: None,
            problem: None,
            pairing: None,
            last: None,
        };
        assert_eq!(said(none.clone()), "");
        let paired = PhoneStatus {
            paired: Some(PhoneView {
                name: "phone".into(),
                node: "nPHONE".into(),
                paired: 100,
                seen: None,
                notifies: false,
                untold: None,
            }),
            ..none.clone()
        };
        const OFF: &str = "\n  notifications: off (turn them on on its page, opened from the \
                           phone's home screen)";
        assert_eq!(
            said(paired.clone()),
            format!("\nphone: phone is paired, its page is not served yet{OFF}")
        );
        assert_eq!(
            said(PhoneStatus {
                problem: Some("Tailscale is Stopped, not Running".into()),
                ..paired.clone()
            }),
            format!(
                "\nphone: phone is paired, its page is not served: Tailscale is Stopped, not \
                 Running{OFF}"
            )
        );
        let notified = |notifies: bool, untold: Option<&str>| {
            let mut status = PhoneStatus {
                url: Some("https://self.example.ts.net:47318".into()),
                ..paired.clone()
            };
            if let Some(phone) = &mut status.paired {
                (phone.notifies, phone.untold) = (notifies, untold.map(Into::into));
            }
            said(status)
        };
        assert_eq!(
            notified(true, None),
            "\nphone: phone approves at https://self.example.ts.net:47318\
             \n  notifications: on"
        );
        assert_eq!(
            notified(true, Some("the last notification was not sent: no route")),
            "\nphone: phone approves at https://self.example.ts.net:47318\
             \n  notifications: on, but the last notification was not sent: no route"
        );
        assert_eq!(
            notified(false, Some("the phone no longer takes them")),
            "\nphone: phone approves at https://self.example.ts.net:47318\
             \n  notifications: off: the phone no longer takes them"
        );
        assert_eq!(
            said(PhoneStatus {
                url: Some("https://self.example.ts.net:47318".into()),
                last: Some(PhoneAnswer {
                    id: 4,
                    project: "widget".parse().unwrap(),
                    env: "dev".parse().unwrap(),
                    approved: false,
                    time: 130,
                }),
                // Another phone is being paired in its place.
                pairing: Some(PhonePairingView {
                    name: "other".into(),
                    left: 599,
                }),
                ..paired
            }),
            format!(
                "\nphone: phone approves at https://self.example.ts.net:47318{OFF}\
                 \n  last answered there: denied widget/dev at 1970-01-01 00:02:10Z\
                 \nphone: pairing other, for 9m more"
            )
        );
        assert_eq!(
            said(PhoneStatus {
                pairing: Some(PhonePairingView {
                    name: "phone".into(),
                    left: 42,
                }),
                ..none
            }),
            "\nphone: pairing phone, for 42s more"
        );
    }

    #[test]
    fn a_missing_key_with_an_example_value_suggests_set_var() {
        let (p, e) = ("shop".parse().unwrap(), "dev".parse().unwrap());
        let missing: Vec<KeyName> = ["PORT", "GREETING", "DB_URL"]
            .map(|k| k.parse().unwrap())
            .into();
        let values =
            crate::repo::env_example::parse("PORT=3000\nGREETING=\"it's me\"\nOTHER=x\n").values;
        let got: Vec<String> = set_var_fixes(&p, &e, &missing, &values)
            .into_iter()
            .map(|f| f.command)
            .collect();
        assert_eq!(
            got,
            [
                "kagebunshin project set-var shop dev PORT 3000",
                r"kagebunshin project set-var shop dev GREETING 'it'\''s me'",
            ]
        );
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote("https://a.b/c?d"), "'https://a.b/c?d'");
        assert_eq!(shell_quote("a=b,c"), "a=b,c");
        assert_eq!(shell_quote("$HOME"), "'$HOME'");
    }

    #[test]
    fn json_detection_stops_at_the_separator() {
        let a = |v: &[&str]| v.iter().map(OsString::from).collect::<Vec<_>>();
        assert!(wants_json(&a(&["kb", "--json", "bogus"])));
        assert!(!wants_json(&a(&["kb", "run", "--", "--json"])));
    }
}
