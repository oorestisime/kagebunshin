//! `connect`: sets a provider up so sources can read from it, and checks
//! that they can.
//!
//! `connect aws` picks a profile from the AWS configuration, logs in with
//! the AWS CLI if its credentials are missing or expired, checks that it
//! can list secrets, and saves it as `[aws]` in `config.toml`: the profile
//! and region every AWS source uses unless it, its environment or its
//! project names its own.
//!
//! `connect proton` saves a Proton Pass personal access token in the local
//! store, after checking that `pass-cli` logs in with it. The token comes
//! from `$KAGEBUNSHIN_PROTON_TOKEN`, else stdin when that is not a
//! terminal, else a hidden prompt; never an argument. The store passphrase
//! is asked at the terminal, as for every store write. The daemon does the
//! rest, one connect at a time: it checks the passphrase, logs in with the
//! token beside its own session, saves the token, and only then makes that
//! session the one it uses. A wrong passphrase or a refused token changes
//! neither.

use std::io::{BufRead, BufReader, IsTerminal, Write};
use std::path::PathBuf;

use clap::Subcommand;

use super::edit::config;
use super::{print_json, print_line};
use crate::cli::{CliError, Exit};
use crate::config::schema::{Profile, Region};
use crate::config::{AwsSettings, ConfigDir};
use crate::ipc::protocol::{Request, Response, WireSecret};
use crate::secret::SecretValue;
use crate::source::Health;
use crate::source::aws_sm::connect as aws_connect;
use crate::source::proton::{self, PassCli};

#[derive(Debug, Subcommand)]
pub enum ConnectProvider {
    /// Pick an AWS profile, log in if needed, check it can list secrets, and make it the default
    ///
    /// Without --profile: the only profile in your AWS configuration, else
    /// the one you pick at the terminal. AWS sources that name no profile
    /// of their own (nor their environment or project) use it.
    Aws {
        /// The profile, instead of asking
        #[arg(long, value_parser = super::project::parse_profile)]
        profile: Option<Profile>,
        /// The region, instead of the profile's own
        #[arg(long, value_parser = super::project::parse_region)]
        region: Option<Region>,
    },
    /// Save a Proton Pass personal access token in the local store, after checking it logs in
    ///
    /// The token is read from $KAGEBUNSHIN_PROTON_TOKEN, else from stdin
    /// when it is not a terminal, else at a hidden prompt; never from an
    /// argument. The store passphrase is asked at the terminal. The daemon
    /// runs pass-cli ($KAGEBUNSHIN_PASS_CLI, else the one on PATH) with its
    /// own session in $XDG_DATA_HOME/kagebunshin/proton, never your own
    /// login, and switches to the new token's session only once the token
    /// is saved: a wrong passphrase or a refused token changes neither. If
    /// pass-cli is missing, this offers to run Proton's installer.
    Proton {
        /// When the token expires (YYYY-MM-DD, as Proton shows it), so status warns 14 days before
        #[arg(long, value_parser = parse_date)]
        expires: Option<u64>,
    },
}

pub(super) fn parse_date(s: &str) -> Result<u64, String> {
    proton::parse_date(s).ok_or_else(|| format!("{s:?} is not a date like 2026-12-31"))
}

pub fn connect(
    socket: Option<PathBuf>,
    json: bool,
    provider: ConnectProvider,
) -> Result<(), CliError> {
    match provider {
        ConnectProvider::Aws { profile, region } => aws(json, profile, region),
        ConnectProvider::Proton { expires } => proton(socket, json, expires),
    }
}

fn proton(socket: Option<PathBuf>, json: bool, expires: Option<u64>) -> Result<(), CliError> {
    let cli = PassCli::from_env();
    if cli.installed().is_none() {
        install_pass_cli(&cli)?;
    }
    let token = match std::env::var(proton::TOKEN_ENV) {
        Ok(t) if !t.is_empty() => SecretValue::new(t),
        _ => super::read_secret("Proton Pass personal access token: ")?.into_value(),
    };
    if token.expose().trim().is_empty() {
        return Err(failed("proton", "the token is empty"));
    }
    let passphrase = super::prompt("Passphrase for the local store: ")?;
    eprintln!("checking the token with pass-cli, through the daemon");
    // The daemon checks the passphrase, logs in with the token beside its
    // session, saves the token and only then swaps the new session in.
    let mut client = super::connect(socket)?;
    let reply = client
        .request(Request::ProtonConnect {
            token: WireSecret::new(token.expose().to_owned()),
            expires,
            passphrase,
        })
        .map_err(|e| {
            let e = CliError::from(e);
            if e.code == "source_failed" && e.message == proton::REFUSED {
                CliError {
                    code: "needs_login",
                    ..e
                }
            } else {
                e
            }
        })?;
    let Response::ProtonConnected { change, vaults, .. } = reply else {
        return Err(super::unexpected());
    };
    if json {
        return print_json(&serde_json::json!({
            "provider": "proton",
            "vaults": vaults,
            "change": change,
            "expires": expires,
        }));
    }
    print_line(&format!(
        "connected Proton Pass: the token reads {vaults} vault{}; it is saved in the local store",
        if vaults == 1 { "" } else { "s" }
    ))?;
    if expires.is_none() {
        print_line("give --expires YYYY-MM-DD to be warned before the token expires")?;
    }
    Ok(())
}

/// Offers Proton's installer at the terminal; without one, says how to
/// install instead.
fn install_pass_cli(cli: &PassCli) -> Result<(), CliError> {
    let missing = || {
        failed(
            "pass_cli",
            format!(
                "pass-cli is not installed ({} not found)",
                cli.bin.display()
            ),
        )
        .with_hint(format!(
            "install it with `{}` or `brew install protonpass/tap/pass-cli`, or point {} at it",
            proton::INSTALLER,
            proton::PASS_CLI_ENV
        ))
    };
    if !std::io::stdin().is_terminal()
        || !confirm(&format!(
            "pass-cli is not installed. Run Proton's installer ({})? [y/N] ",
            proton::INSTALLER
        ))?
    {
        return Err(missing());
    }
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(proton::INSTALLER)
        .status()
        .map_err(|e| failed("pass_cli", format!("cannot run the installer: {e}")))?;
    if !status.success() {
        return Err(failed(
            "pass_cli",
            format!("the pass-cli installer failed ({status})"),
        ));
    }
    if cli.installed().is_none() {
        return Err(missing());
    }
    Ok(())
}

fn failed(code: &'static str, message: impl Into<String>) -> CliError {
    CliError::new(Exit::Failure, code, message.into())
}

fn aws(json: bool, profile: Option<Profile>, region: Option<Region>) -> Result<(), CliError> {
    let profiles = aws_connect::profiles();
    let interactive = std::io::stdin().is_terminal();
    let profile = if let Some(p) = profile {
        if let Some(set) = &profiles
            && set.get_profile(p.as_str()).is_none()
        {
            return Err(failed(
                "aws_profile",
                format!("AWS profile {p} is not in your AWS configuration"),
            )
            .with_hint("see `aws configure list-profiles`"));
        }
        p
    } else {
        let mut names = aws_connect::profile_names(profiles.as_ref());
        match names.len() {
            0 => {
                return Err(failed("aws_profile", "no AWS profiles are configured")
                    .with_hint(
                        "set one up with `aws configure sso` or `aws configure`, then run this again",
                    ));
            }
            1 => names.remove(0),
            _ if interactive => names.swap_remove(choose("AWS profile", &names)?),
            _ => {
                return Err(CliError::new(
                    Exit::Usage,
                    "usage",
                    format!("several AWS profiles: {}", names.join(", ")),
                )
                .with_hint("pick one with --profile"));
            }
        }
        .try_into()
        .map_err(|e: &str| failed("aws_profile", e))?
    };
    let settings = AwsSettings {
        profile: Some(profile.clone()),
        region,
    };

    let check = || aws_connect::check(&profile, settings.region.as_ref());
    let mut health = check();
    if let Health::NeedsLogin { hint } = &health {
        if !interactive {
            return Err(failed(
                "needs_login",
                format!("the credentials of AWS profile {profile} are missing or expired"),
            )
            .with_hint(hint.clone())
            .human(hint.clone()));
        }
        let mut login = aws_connect::login_command(profiles.as_ref(), &profile);
        let args: Vec<String> = login
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        eprintln!("logging in: aws {}", args.join(" "));
        let status = login.status().map_err(|e| {
            failed("aws_cli", format!("cannot run the AWS CLI: {e}"))
                .with_hint("install it: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html")
        })?;
        if !status.success() {
            return Err(failed(
                "needs_login",
                format!("aws login failed ({status})"),
            ));
        }
        health = check();
    }
    match health {
        Health::Ok => {}
        Health::NeedsLogin { hint } => {
            return Err(failed(
                "needs_login",
                format!("the credentials of AWS profile {profile} are still missing or expired"),
            )
            .with_hint(hint.clone())
            .human(hint));
        }
        Health::NotConnected { hint } => {
            return Err(failed("aws", "AWS is not connected").with_hint(hint));
        }
        // AWS reads no store, so this does not happen.
        Health::Locked => return Err(failed("aws", "the daemon is locked")),
        Health::Failed { message } => {
            return Err(failed(
                "aws",
                format!("AWS profile {profile} cannot list secrets: {message}"),
            ));
        }
    }

    let dir = ConfigDir::from_env().map_err(config)?;
    let written = aws_connect::save(&dir, &settings).map_err(config)?;
    if json {
        return print_json(&serde_json::json!({
            "provider": "aws_sm",
            "profile": profile.as_str(),
            "region": settings.region.as_ref().map(Region::as_str),
            "written": written,
        }));
    }
    print_line(&format!(
        "connected AWS profile {profile}{}; AWS sources that name no profile now use it",
        settings
            .region
            .as_ref()
            .map(|r| format!(" in {r}"))
            .unwrap_or_default()
    ))
}

fn no_terminal(e: std::io::Error) -> CliError {
    failed("no_terminal", format!("cannot ask at the terminal: {e}"))
        .with_hint("run this in an interactive terminal, or give the choice as a flag")
}

/// Asks at the controlling terminal, returning the line typed.
fn ask(question: &str) -> Result<String, CliError> {
    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(no_terminal)?;
    tty.write_all(question.as_bytes()).map_err(no_terminal)?;
    let mut answer = String::new();
    BufReader::new(tty)
        .read_line(&mut answer)
        .map_err(no_terminal)?;
    Ok(answer.trim().to_owned())
}

/// A numbered menu at the terminal; the index picked.
fn choose(what: &str, options: &[String]) -> Result<usize, CliError> {
    let mut menu = String::new();
    for (i, o) in options.iter().enumerate() {
        menu.push_str(&format!("  {}) {o}\n", i + 1));
    }
    let answer = ask(&format!("{menu}{what} [1-{}]: ", options.len()))?;
    match answer.parse::<usize>() {
        Ok(n) if (1..=options.len()).contains(&n) => Ok(n - 1),
        _ => Err(CliError::new(
            Exit::Usage,
            "usage",
            format!("no such choice: {answer:?}"),
        )),
    }
}

/// Anything but y or yes is a no.
pub(super) fn confirm(question: &str) -> Result<bool, CliError> {
    Ok(matches!(
        ask(question)?.to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}
