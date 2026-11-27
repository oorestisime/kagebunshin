//! The daemon's socket server.
//!
//! `Server::bind` does everything that can fail on startup, synchronously and
//! before any runtime exists: private directory, single-daemon lock, stale
//! socket cleanup, bind, 0600 permissions. `Server::serve` then answers
//! connections until shutdown.
//!
//! Each connection is identified from kernel peer credentials (uid, gid, pid)
//! plus the caller's process start time, read immediately after `accept` so a
//! later pid reuse cannot be mistaken for the same caller. Callers running as
//! a different uid are refused.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::future::Future;
use std::io;
use std::os::fd::AsFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixListener as StdUnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{UnixListener, UnixStream};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use super::frame::{FrameError, read_frame_async, write_frame_async};
use super::paths::{self, DirError, PathError};
use super::protocol::{
    BUILD_ID, Caller, ErrorCode, Request, RequestFrame, Response, ResponseFrame, WireError,
};
use crate::daemon::Daemon;
use crate::sys::{self, PeerCred};

/// What a caller of another build on this machine is told to do: `setup`
/// restarts the daemon on the build it is run from.
pub const SAME_BUILD: &str = "the CLI and the daemon are different builds, as after an upgrade: \
     run `kagebunshin setup` in a terminal; it restarts the daemon on this build, asking for the \
     store passphrase, and unlocks it";

pub struct ServerConfig {
    pub socket_path: PathBuf,
    pub build_id: String,
    /// How long a new connection has to send `Hello`.
    pub handshake_timeout: Duration,
    /// How long a connection may sit idle between requests, and the deadline
    /// for writing a response.
    pub idle_timeout: Duration,
    /// How often the remote endpoint writes to a reply that is not ready.
    pub heartbeat: Duration,
}

impl ServerConfig {
    pub fn new(socket_path: PathBuf) -> Self {
        Self {
            socket_path,
            build_id: BUILD_ID.to_owned(),
            handshake_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(60),
            heartbeat: super::remote::HEARTBEAT,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error(transparent)]
    Path(#[from] PathError),
    #[error(transparent)]
    Dir(#[from] DirError),
    #[error("another kagebunshind is already running (lock held on {path})")]
    AlreadyRunning { path: PathBuf },
    #[error("{path} exists and is not a socket; refusing to replace it")]
    NotASocket { path: PathBuf },
    #[error("{path} is owned by uid {owner}; refusing to replace it")]
    ForeignSocket { path: PathBuf, owner: u32 },
    #[error("{path}: {source}")]
    Io { path: PathBuf, source: io::Error },
}

fn io_err(path: &Path) -> impl FnOnce(io::Error) -> ServerError + '_ {
    move |source| ServerError::Io {
        path: path.into(),
        source,
    }
}

/// Holds the single-daemon lock and removes the socket file on drop.
struct SocketGuard {
    socket_path: PathBuf,
    _lock: File,
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        // We hold the lock, so the file at this path can only be ours.
        let _ = fs::remove_file(&self.socket_path);
    }
}

pub struct Server {
    listener: StdUnixListener,
    guard: SocketGuard,
    cfg: Arc<ServerConfig>,
    uid: u32,
}

impl Server {
    pub fn bind(cfg: ServerConfig) -> Result<Self, ServerError> {
        let uid = sys::effective_uid();
        let path = cfg.socket_path.clone();
        paths::check_socket_path(&path)?;
        paths::ensure_private_dir(paths::socket_dir(&path), uid)?;

        let lock_path = lock_path_for(&path);
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&lock_path)
            .map_err(io_err(&lock_path))?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(ServerError::AlreadyRunning { path: lock_path });
            }
            Err(TryLockError::Error(e)) => return Err(io_err(&lock_path)(e)),
        }

        // With the lock held, anything at the socket path is left over from a
        // daemon that died without cleaning up.
        match fs::symlink_metadata(&path) {
            Ok(meta) if !meta.file_type().is_socket() => {
                return Err(ServerError::NotASocket { path });
            }
            Ok(meta) if meta.uid() != uid => {
                return Err(ServerError::ForeignSocket {
                    path,
                    owner: meta.uid(),
                });
            }
            Ok(_) => {
                warn!(socket = %path.display(), "removing stale socket");
                fs::remove_file(&path).map_err(io_err(&path))?;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(io_err(&path)(e)),
        }

        let listener = StdUnixListener::bind(&path).map_err(io_err(&path))?;
        let guard = SocketGuard {
            socket_path: path.clone(),
            _lock: lock,
        };
        // The directory is already 0700; this is belt and braces.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).map_err(io_err(&path))?;
        listener.set_nonblocking(true).map_err(io_err(&path))?;

        Ok(Self {
            listener,
            guard,
            cfg: Arc::new(cfg),
            uid,
        })
    }

    pub fn socket_path(&self) -> &Path {
        &self.guard.socket_path
    }

    /// Its settings, which the remote endpoint shares.
    pub fn config(&self) -> Arc<ServerConfig> {
        self.cfg.clone()
    }

    /// Answers connections until `shutdown` completes, with `daemon`
    /// answering the requests that involve its state. Must run inside a
    /// tokio runtime. Removes the socket file when it returns.
    pub async fn serve(self, daemon: Daemon, shutdown: impl Future<Output = ()>) -> io::Result<()> {
        let Server {
            listener,
            guard,
            cfg,
            uid,
        } = self;
        let listener = UnixListener::from_std(listener)?;
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                () = &mut shutdown => break,
                accepted = listener.accept() => match accepted {
                    Ok((stream, _)) => {
                        tokio::spawn(handle_connection(stream, cfg.clone(), uid, daemon.clone()));
                    }
                    Err(e) => warn!(error = %e, "accept failed"),
                },
            }
        }
        info!("shutting down");
        drop(guard);
        Ok(())
    }
}

/// `<socket>.lock`, next to the socket in the same private directory.
pub fn lock_path_for(socket: &Path) -> PathBuf {
    let mut name = socket.file_name().unwrap_or_default().to_owned();
    name.push(".lock");
    socket.with_file_name(name)
}

/// Same-user only. Peer credentials narrow who can talk to the daemon; they do
/// not make the socket private to one program.
pub fn authorize_peer(daemon_uid: u32, peer: &PeerCred) -> Result<(), WireError> {
    if peer.uid == daemon_uid {
        Ok(())
    } else {
        Err(WireError::new(
            ErrorCode::PermissionDenied,
            "the daemon only serves processes running as its own user",
        ))
    }
}

fn identify(stream: &UnixStream, daemon_uid: u32) -> Result<Caller, WireError> {
    let denied = |what: &str, e: io::Error| {
        WireError::new(
            ErrorCode::PermissionDenied,
            format!("cannot identify the caller: {what}: {e}"),
        )
    };
    let peer = sys::peer_cred(stream.as_fd()).map_err(|e| denied("peer credentials", e))?;
    authorize_peer(daemon_uid, &peer)?;
    let start_time = sys::process_start(peer.pid).map_err(|e| denied("process start time", e))?;
    Ok(Caller {
        uid: peer.uid,
        gid: peer.gid,
        pid: peer.pid,
        start_time,
        remote: None,
    })
}

async fn handle_connection(
    stream: UnixStream,
    cfg: Arc<ServerConfig>,
    daemon_uid: u32,
    daemon: Daemon,
) {
    let (mut rd, mut wr) = stream.into_split();
    let caller = match identify(rd.as_ref(), daemon_uid) {
        Ok(c) => c,
        Err(e) => {
            warn!(reason = %e.message, "refused connection");
            let _ = reply(&mut wr, &cfg, 0, Response::Error(e)).await;
            return;
        }
    };
    debug!(pid = caller.pid, "connection");
    if let Err(e) = session(&mut rd, &mut wr, &cfg, &caller, &daemon).await {
        debug!(pid = caller.pid, error = %e, "connection ended");
    }
}

/// Answers one connection's requests, `Hello` first, until it closes or
/// sits idle.
async fn session<R, W>(
    rd: &mut R,
    wr: &mut W,
    cfg: &ServerConfig,
    caller: &Caller,
    daemon: &Daemon,
) -> Result<(), FrameError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let first: RequestFrame = match timeout(cfg.handshake_timeout, read_frame_async(rd)).await {
        Err(_) => return Ok(()),
        Ok(Err(e @ FrameError::Decode { .. })) => {
            reply(wr, cfg, 0, bad_request(&e.to_string())).await?;
            return Err(e);
        }
        Ok(r) => r?,
    };
    match first.body {
        Request::Hello { build } if build == cfg.build_id => {
            let hello = Response::Hello {
                build: cfg.build_id.clone(),
            };
            reply(wr, cfg, first.id, hello).await?;
        }
        Request::Hello { build } => {
            let mut client: String = build.chars().take(64).collect();
            if client.len() < build.len() {
                client.push('…');
            }
            let err = WireError::new(
                ErrorCode::BuildMismatch,
                format!(
                    "client build {client} does not match daemon build {}",
                    cfg.build_id
                ),
            )
            .with_hint(SAME_BUILD)
            .human(SAME_BUILD);
            return reply(wr, cfg, first.id, Response::Error(err)).await;
        }
        _ => {
            return reply(
                wr,
                cfg,
                first.id,
                bad_request("the first message must be hello"),
            )
            .await;
        }
    }

    loop {
        let req: RequestFrame = match timeout(cfg.idle_timeout, read_frame_async(rd)).await {
            Err(_) | Ok(Err(FrameError::Closed)) => return Ok(()),
            Ok(Err(e @ FrameError::Decode { .. })) => {
                reply(wr, cfg, 0, bad_request(&e.to_string())).await?;
                return Err(e);
            }
            Ok(r) => r?,
        };
        let body = match req.body {
            Request::Hello { .. } => bad_request("hello was already sent"),
            Request::Ping => Response::Pong,
            Request::Whoami => Response::Whoami(caller.clone()),
            other => daemon.handle_from(other, caller).await,
        };
        reply(wr, cfg, req.id, body).await?;
    }
}

fn bad_request(message: &str) -> Response {
    Response::Error(WireError::new(ErrorCode::BadRequest, message))
}

async fn reply<W: AsyncWrite + Unpin>(
    wr: &mut W,
    cfg: &ServerConfig,
    id: u64,
    body: Response,
) -> Result<(), FrameError> {
    let frame = ResponseFrame { id, body };
    match timeout(cfg.idle_timeout, write_frame_async(wr, &frame)).await {
        Ok(r) => r,
        Err(_) => Err(FrameError::Io(io::ErrorKind::TimedOut.into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn other_uids_are_refused() {
        let peer = PeerCred {
            uid: 1001,
            gid: 1001,
            pid: 5,
        };
        assert!(authorize_peer(1001, &peer).is_ok());
        let err = authorize_peer(1000, &peer).unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
    }

    #[test]
    fn lock_file_sits_next_to_the_socket() {
        assert_eq!(
            lock_path_for(Path::new("/run/user/1/kagebunshin/kagebunshind.sock")),
            Path::new("/run/user/1/kagebunshin/kagebunshind.sock.lock")
        );
    }
}
