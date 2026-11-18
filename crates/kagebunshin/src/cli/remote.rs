//! `--machine <MACHINE>` and `kagebunshin remote`: using another machine's
//! daemon over the tailnet, and letting other machines use this one's.
//!
//! The client side asks this machine's tailscaled which peer is `MACHINE`
//! and connects to its tailnet address on `[remote] port` (this machine's
//! `config.toml`, the same port by default). Where there is no tailscaled
//! to ask, as in a sandbox that reaches the tailnet through a proxy, a full
//! `MagicDNS` name is looked up like any other name. Who may use that
//! endpoint is the other daemon's call, by the identity its tailscaled
//! gives this one and by the grant's token, which this side reads from
//! `KAGEBUNSHIN_REMOTE_TOKEN`.

use std::net::{SocketAddr, ToSocketAddrs};

use clap::Subcommand;

use super::{CliError, Exit, connect, print_json, print_line, prompt, unexpected, usage};
use crate::config::{Config, ConfigDir, parse_config};
use crate::ipc::client::{Client, DEFAULT_TIMEOUT};
use crate::ipc::protocol::{REMOTE_TOKEN_ENV, RemoteStatus, Request, Response};
use crate::store::Change;
use crate::tailnet::{self, Tailscaled};
use crate::types::{EnvName, ProjectName};

#[derive(Debug, Subcommand)]
pub enum RemoteAction {
    /// Let machines this one grants use it over Tailscale (asks for the passphrase)
    ///
    /// The daemon then listens on this machine's tailnet address only, on
    /// `[remote] port` in config.toml, while Tailscale is running. Other
    /// machines get nothing until `remote grant` names them.
    Enable,
    /// Stop listening for other machines (asks for the passphrase)
    Disable,
    /// Let a machine on this tailnet use a project's environments remotely
    ///
    /// The machine is named as Tailscale names it (the first label of its
    /// MagicDNS name, or the whole name); the grant holds its node id, so
    /// another machine renamed to it later gets nothing. Prints the grant's
    /// token, once: the machine sends it with every request, from
    /// KAGEBUNSHIN_REMOTE_TOKEN, and nothing here keeps it. Granting the
    /// same machine and project again replaces the earlier grant and its
    /// token. Asks for the passphrase.
    Grant {
        /// The machine, e.g. laptop or laptop.example.ts.net
        machine: String,
        /// The project it may use
        project: ProjectName,
        /// The environments of that project it may use
        #[arg(required = true, value_name = "ENV")]
        envs: Vec<EnvName>,
        /// The last day the grant lasts (YYYY-MM-DD, UTC) [default: no end]
        #[arg(long, value_parser = parse_until, value_name = "DATE")]
        until: Option<u64>,
    },
    /// Give a machine's grant for a project a new token, ending the old one
    ///
    /// Prints the new token, once. Asks for the passphrase.
    Rotate {
        /// The machine, as its grant names it, or its node id
        machine: String,
        /// The project the grant is for
        project: ProjectName,
    },
    /// Take a machine's grants away: the one for a project, or every one
    Revoke {
        /// The machine, as its grant names it, or its node id
        machine: String,
        /// Only the grant for this project
        project: Option<ProjectName>,
    },
}

/// The end of `DATE`, UTC: a grant until a day lasts through it.
fn parse_until(s: &str) -> Result<u64, String> {
    super::connect::parse_date(s).map(|start| start + 24 * 60 * 60)
}

pub fn manage(
    socket: Option<std::path::PathBuf>,
    json: bool,
    env: Option<EnvName>,
    action: RemoteAction,
) -> Result<(), CliError> {
    let passphrase = || prompt("Passphrase for the local store: ");
    let rotating = matches!(action, RemoteAction::Rotate { .. });
    let req = match action {
        RemoteAction::Enable | RemoteAction::Disable => Request::RemoteEnable {
            enabled: matches!(action, RemoteAction::Enable),
            passphrase: passphrase()?,
        },
        RemoteAction::Grant {
            machine,
            project,
            envs,
            until,
        } => {
            if env.is_some() {
                return Err(usage(
                    "--env does not apply to remote grant; name the environments as its arguments",
                ));
            }
            Request::RemoteGrant {
                machine,
                project,
                envs,
                expires: until,
                passphrase: passphrase()?,
            }
        }
        RemoteAction::Rotate { machine, project } => Request::RemoteRotate {
            machine,
            project,
            passphrase: passphrase()?,
        },
        RemoteAction::Revoke { machine, project } => Request::RemoteRevoke {
            machine,
            project,
            passphrase: passphrase()?,
        },
    };
    let mut client = connect(socket)?;
    let (change, locked) = match client.request(req)? {
        Response::Store { change, locked } => (change, locked),
        Response::RemoteGranted {
            change,
            locked,
            machine,
            token,
        } => {
            if json {
                return print_json(&serde_json::json!({
                    "change": change,
                    "locked": locked,
                    "machine": machine,
                    "token": token.expose(),
                }));
            }
            let what = match change {
                _ if rotating => "gave the grant a new token, ending any it had",
                Change::Added => "granted",
                _ => "replaced the earlier grant and its token",
            };
            return print_line(&granted(what, &machine, token.expose()));
        }
        _ => return Err(unexpected()),
    };
    if json {
        return print_json(&serde_json::json!({ "change": change, "locked": locked }));
    }
    print_line(match change {
        Change::Enabled => {
            "turned the remote endpoint on; `kagebunshin status` shows where it listens"
        }
        Change::Disabled => "turned the remote endpoint off",
        Change::Added => "granted",
        Change::Replaced => "replaced the earlier grant",
        Change::Removed => "revoked",
        _ => "done",
    })
}

/// What `remote grant` and `remote rotate` say: the token, this once, and
/// what to do with it.
fn granted(what: &str, machine: &str, token: &str) -> String {
    format!(
        "{what}; machine {machine}'s token, shown this once (the store keeps only its hash):\n\n  \
         {token}\n\n\
         On {machine}, put it in the environment of whatever runs kagebunshin there:\n\n  \
         export {REMOTE_TOKEN_ENV}={token}\n\n\
         then `kagebunshin status --machine <this machine's name on the tailnet> --project \
         <project>` there shows what it may use. `kagebunshin remote rotate` gives the grant a \
         new token."
    )
}

/// Machine `machine`'s remote endpoint: the peer this machine's tailscaled
/// names so, at its IPv4 tailnet address, or without a tailscaled the
/// address its full name has. Sends the token in `KAGEBUNSHIN_REMOTE_TOKEN`.
pub fn client(machine: &str) -> Result<Client, CliError> {
    let (addr, host) = address(machine)?;
    let token = std::env::var(REMOTE_TOKEN_ENV).ok();
    let token = token.as_deref().map(str::trim).filter(|t| !t.is_empty());
    Ok(Client::connect_remote(
        machine,
        addr,
        &host,
        token,
        DEFAULT_TIMEOUT,
    )?)
}

/// Where `machine`'s endpoint is, and the name to call it in a request.
fn address(machine: &str) -> Result<(SocketAddr, String), CliError> {
    let port = config()?.remote.port;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError::new(Exit::Failure, "runtime", e.to_string()))?;
    let name = machine.trim_end_matches('.').to_ascii_lowercase();
    let status = match runtime.block_on(async { tailnet::status(&Tailscaled::new()).await }) {
        Ok(status) if status.running() => status,
        // No Tailscale daemon to ask: a full name is looked up as any
        // other, which is how a tailnet reached through a proxy answers.
        _ if name.contains('.') => return resolve(machine, &name, port),
        Ok(status) => {
            return Err(CliError::new(
                Exit::Failure,
                "remote_unreachable",
                format!(
                    "Tailscale is not running on this machine ({})",
                    status.state
                ),
            )
            .with_hint("start Tailscale here, then try again"));
        }
        Err(e) => {
            return Err(CliError::new(
                Exit::Failure,
                "remote_unreachable",
                format!("cannot ask Tailscale where machine {machine} is: {e}"),
            )
            .with_hint(
                "is Tailscale installed and running on this machine? Where it is not, give the \
                 machine's full MagicDNS name, like laptop.example.ts.net",
            ));
        }
    };
    let not_found = |message: String| CliError::new(Exit::Usage, "no_such_machine", message);
    let peer = match status.peers_named(machine).as_slice() {
        [peer] => (*peer).clone(),
        [] => {
            return Err(not_found(format!(
                "no other machine on this tailnet is named {machine}"
            ))
            .with_hint("`tailscale status` lists them"));
        }
        _ => {
            return Err(not_found(format!(
                "more than one machine on this tailnet is named {machine}"
            ))
            .with_hint("give its full MagicDNS name"));
        }
    };
    let ip = peer.ip().ok_or_else(|| {
        CliError::new(
            Exit::Failure,
            "remote_unreachable",
            format!("Tailscale gives machine {machine} no IPv4 tailnet address"),
        )
    })?;
    Ok((SocketAddr::new(ip, port), ip.to_string()))
}

/// The address the name `name` has, IPv4 first, as the endpoint listens.
fn resolve(machine: &str, name: &str, port: u16) -> Result<(SocketAddr, String), CliError> {
    let unreachable = |why: String| {
        CliError::new(
            Exit::Failure,
            "remote_unreachable",
            format!("cannot find machine {machine}: {why}"),
        )
        .with_hint(
            "with no Tailscale daemon on this machine, MACHINE is the other machine's full \
             MagicDNS name, which this machine must be able to look up",
        )
    };
    let mut found: Vec<SocketAddr> = (name, port)
        .to_socket_addrs()
        .map_err(|e| unreachable(e.to_string()))?
        .collect();
    found.sort_by_key(|a| !a.is_ipv4());
    match found.first() {
        Some(addr) => Ok((*addr, name.to_owned())),
        None => Err(unreachable("the name has no address".into())),
    }
}

/// `config.toml` alone: a broken project file has nothing to do with
/// another machine's endpoint.
fn config() -> Result<Config, CliError> {
    let failed = |e: String| CliError::new(Exit::Failure, "config", e);
    let dir = ConfigDir::from_env().map_err(|e| failed(e.to_string()))?;
    let path = dir.config_file();
    match std::fs::read_to_string(&path) {
        Ok(text) => parse_config(&path, &text).map_err(|e| failed(e.to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
        Err(e) => Err(failed(format!("cannot read {}: {e}", path.display()))),
    }
}

/// What `status` says about the remote endpoint.
pub fn render(out: &mut String, r: &RemoteStatus, now: u64) {
    match (r.enabled, &r.listening, &r.problem) {
        (None | Some(false), _, _) => return,
        (Some(true), Some(addr), _) => out.push_str(&format!("\nremote: listening on {addr}")),
        (Some(true), None, Some(p)) => out.push_str(&format!("\nremote: on, not listening: {p}")),
        (Some(true), None, None) => out.push_str("\nremote: on, not listening yet"),
    }
    for g in &r.grants {
        let envs: Vec<String> = g.envs.iter().map(ToString::to_string).collect();
        let until = match g.expires {
            Some(end) if end <= now => " (expired)".to_owned(),
            Some(end) => format!(" until {}", crate::source::proton::format_date(end - 1)),
            None => String::new(),
        };
        // Made before grants had tokens: nothing gets through with it.
        let token = if g.token {
            ""
        } else {
            " (no token; grant it again for one)"
        };
        out.push_str(&format!(
            "\n  {} may use {} {}{until}{token}",
            g.machine,
            g.project,
            envs.join(", ")
        ));
    }
}
