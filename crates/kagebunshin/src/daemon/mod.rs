//! `kagebunshind`: the only process that fetches and holds secret values.
//!
//! It binds the socket, identifies callers, and keeps the lock state and the
//! cache of resolved environments ([`broker`]); [`resolve`] turns an
//! environment's sources into values. It also owns the local store: every
//! read and write of `store.age` goes through it. It refuses sensitive environments, and
//! no request returns a value.

pub mod broker;
pub mod proof;
pub mod resolve;
pub mod shared;
#[cfg(test)]
mod tests;

use std::io::{self, IsTerminal};
use std::path::PathBuf;
use std::sync::Arc;

use tokio::signal::unix::{SignalKind, signal};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

pub use broker::{Daemon, LoadRegistry};
pub use resolve::{EnvValues, Providers, ResolveError, SourceFactory};

use crate::audit::AuditLog;
use crate::config::{ConfigDir, ConfigError, Registry};
use crate::ipc::paths::{self, PathError};
use crate::ipc::protocol::BUILD_ID;
use crate::ipc::server::{Server, ServerConfig, ServerError};
use crate::store::StoreFile;

/// Log filter, in `tracing_subscriber::EnvFilter` syntax. Defaults to `info`.
pub const LOG_ENV: &str = "KAGEBUNSHIN_LOG";

#[derive(Debug, Default)]
pub struct Options {
    /// Overrides the default socket path.
    pub socket: Option<PathBuf>,
}

#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error(transparent)]
    Path(#[from] PathError),
    #[error(transparent)]
    Server(#[from] ServerError),
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("runtime: {0}")]
    Runtime(#[from] io::Error),
    #[error("cannot find a place for the audit log: {0}")]
    Audit(io::Error),
}

/// Runs the daemon in the foreground until SIGTERM or SIGINT.
pub fn run(opts: Options) -> Result<(), DaemonError> {
    init_tracing();
    if let Err(e) = crate::sys::harden_process() {
        warn!(error = %e, "cannot turn off core dumps");
    }
    let socket = match opts.socket {
        Some(p) => p,
        None => paths::default_socket_path()?,
    };
    let config_dir = ConfigDir::from_env()?;
    let server = Server::bind(ServerConfig::new(socket))?;
    info!(socket = %server.socket_path().display(), build = BUILD_ID, "kagebunshind listening");
    // Project files are read again on every request; a broken one is
    // reported then too, so it is only a warning here.
    if let Err(e) = Registry::load(&config_dir) {
        warn!(error = %e, "the configuration does not load");
    }
    let store = StoreFile::new(config_dir.store_file());
    let audit = AuditLog::from_env().map_err(DaemonError::Audit)?;
    info!(path = %audit.path().display(), "audit log");
    let proofs = proof::Proofs::beside(audit.path());
    let tailnet: Arc<dyn crate::tailnet::LocalApi> = Arc::new(crate::tailnet::Tailscaled::new());
    let daemon = Daemon::new(
        Box::new(move || Registry::load(&config_dir)),
        Arc::new(Providers::new()),
        store,
    )
    .with_audit(audit)
    .with_proofs(proofs)
    .with_tailnet(tailnet.clone());
    let remote_cfg = server.config();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let mut term = signal(SignalKind::terminate())?;
        let mut int = signal(SignalKind::interrupt())?;
        let shutdown = async move {
            tokio::select! {
                _ = term.recv() => {}
                _ = int.recv() => {}
            }
        };
        // Off until the store says otherwise; it ends with the runtime.
        tokio::spawn(crate::ipc::remote::supervise(
            daemon.clone(),
            tailnet.clone(),
            remote_cfg.clone(),
            crate::ipc::remote::POLL,
            std::future::pending(),
        ));
        // Off until a phone is paired; it ends with the runtime too.
        tokio::spawn(crate::ipc::phone::supervise(
            daemon.clone(),
            tailnet,
            remote_cfg,
            crate::ipc::remote::POLL,
            std::future::pending(),
        ));
        server.serve(daemon, shutdown).await
    })?;
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_env(LOG_ENV).unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(io::stderr)
        .with_ansi(io::stderr().is_terminal())
        .try_init();
}
