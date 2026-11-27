//! The synchronous client used by the CLI.
//!
//! To this machine's daemon: a plain std socket with read/write deadlines,
//! as the CLI makes a handful of round trips and exits, so it does not need
//! a runtime. Before connecting it checks that the socket directory is
//! private to this user, and after connecting that the listening process
//! runs as this user, so a socket planted by someone else is never trusted.
//!
//! To another machine's remote endpoint (see [`super::remote`]): each
//! request is an HTTP `POST` on its own connection, driven to its end on a
//! small runtime, with the same deadlines.

use std::io;
use std::net::SocketAddr;
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::{self, HeaderValue};
use hyper_util::rt::TokioIo;
use zeroize::Zeroizing;

use super::frame::{FrameError, MAX_FRAME, decode, encode_json, read_frame, write_frame};
use super::paths::{self, DirError};
use super::protocol::{
    APPROVAL_TIMEOUT, BUILD_ID, REMOTE_TOKEN_ENV, Request, RequestFrame, Response, ResponseFrame,
    WireError,
};
use super::remote::{BUILD_HEADER, HEARTBEAT, PATH};
use crate::sys;

/// Per-request deadline for both the write and the reply.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// The deadline instead for requests that may wait on providers over the
/// network: `connect proton` logs `pass-cli` in and lists vaults, and a
/// fetch may log in again; both can take longer than [`DEFAULT_TIMEOUT`].
pub const PROVIDER_TIMEOUT: Duration = Duration::from_secs(60);

/// How long to wait for `req`, given the deadline for local requests:
/// at least [`PROVIDER_TIMEOUT`] for those that may reach a provider, and
/// [`APPROVAL_TIMEOUT`] on top for those that may wait for approval.
/// `status` without facts reports only the daemon's own state.
pub fn deadline(req: &Request, local: Duration) -> Duration {
    match req {
        Request::RunEnv { .. }
        | Request::Get { .. }
        | Request::StoreImport { .. }
        | Request::StoreAsk { .. } => {
            local.max(PROVIDER_TIMEOUT + APPROVAL_TIMEOUT)
        }
        Request::ProtonConnect { .. }
        | Request::RemoteGrant { .. }
        // Both ask Tailscale which machines there are.
        | Request::Phones
        | Request::PhonePair { .. }
        | Request::Status { facts: Some(_) }
        | Request::Diff { .. }
        | Request::CheckProject { .. }
        | Request::Sync { .. }
        | Request::List { .. }
        | Request::Providers { .. }
        | Request::WaitApprovals { .. }
        | Request::Inspect { .. }
        // It asks Proton what the environment's sources read.
        | Request::AddMark { .. }
        | Request::Reveal { .. } => local.max(PROVIDER_TIMEOUT),
        Request::Status { facts: None }
        | Request::Hello { .. }
        | Request::Ping
        | Request::Whoami
        | Request::Lock
        | Request::Unlock { .. }
        | Request::StoreSet { .. }
        | Request::StoreSetMany { .. }
        | Request::StoreMark { .. }
        | Request::MarkEnv { .. }
        | Request::AcknowledgeEnv { .. }
        | Request::AcknowledgeEnvs { .. }
        | Request::MarkSecret { .. }
        | Request::UnmarkSecrets { .. }
        | Request::StoreUnset { .. }
        | Request::StoreClear { .. }
        | Request::StorePasswd { .. }
        | Request::Approve { .. }
        | Request::ApproveStanding { .. }
        | Request::EndStanding { .. }
        | Request::RemoteEnable { .. }
        | Request::RemoteRevoke { .. }
        | Request::RemoteRotate { .. }
        | Request::PhonePairStop
        | Request::PhoneUnpair { .. }
        | Request::Proven { .. }
        | Request::StoreList => local,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("the daemon is not running (no socket at {socket})")]
    NotRunning { socket: PathBuf },
    #[error("refusing to use the socket directory: {0}")]
    InsecureDir(#[source] DirError),
    #[error("the process listening on {socket} runs as uid {uid}, not as this user")]
    ForeignDaemon { socket: PathBuf, uid: u32 },
    #[error("the daemon did not answer within {0:?}")]
    Timeout(Duration),
    #[error("lost the connection to the daemon: {0}")]
    Frame(#[source] FrameError),
    #[error("cannot connect to {socket}: {source}")]
    Connect { socket: PathBuf, source: io::Error },
    #[error("cannot connect to machine {machine}'s remote endpoint at {addr}: {source}")]
    ConnectRemote {
        machine: String,
        addr: SocketAddr,
        source: io::Error,
    },
    /// The connection to another machine's remote endpoint broke, or what
    /// came over it was not HTTP.
    #[error("lost the connection to machine {machine}'s remote endpoint: {reason}")]
    Remote { machine: String, reason: String },
    /// Something answered, but not with one of the daemon's replies: not a
    /// kagebunshin daemon, or something in between answering for it.
    #[error(
        "what answered for machine {machine} at {addr} (HTTP {status}) is not a kagebunshin \
         daemon's reply"
    )]
    NotADaemon {
        machine: String,
        addr: SocketAddr,
        status: u16,
    },
    /// The token to send is not one a header can carry.
    #[error("{REMOTE_TOKEN_ENV} does not hold a remote grant's token")]
    BadToken,
    /// An error the daemon reported, including a build mismatch.
    #[error(transparent)]
    Daemon(WireError),
    #[error("unexpected reply from the daemon")]
    UnexpectedReply,
}

/// How long a reply from another machine may say nothing at all: it gets a
/// newline every [`HEARTBEAT`] while the daemon works on it.
const SILENCE: Duration = Duration::from_secs(4 * HEARTBEAT.as_secs());

/// Another machine's remote endpoint: where it is, what to call it, and
/// what to send it. Each request is its own connection.
struct RemoteEnd {
    machine: String,
    addr: SocketAddr,
    /// The `Host` to name: how the caller reached it, with its port.
    host: HeaderValue,
    /// `Bearer <token>`, when there is a token to send.
    authorization: Option<HeaderValue>,
    runtime: tokio::runtime::Runtime,
    silence: Duration,
}

/// The daemon on this machine, or another machine's remote endpoint.
enum End {
    Local(UnixStream),
    Remote(Box<RemoteEnd>),
}

pub struct Client {
    end: End,
    next_id: u64,
    /// The deadline for local requests; see [`deadline`].
    local: Duration,
    /// The deadline of the request in flight.
    timeout: Duration,
}

impl Client {
    /// Connects and performs the `Hello` handshake. `timeout` is the
    /// deadline for local requests; see [`deadline`].
    pub fn connect(socket: &Path, timeout: Duration) -> Result<Self, ClientError> {
        let uid = sys::effective_uid();
        match paths::check_private_dir(paths::socket_dir(socket), uid) {
            Ok(()) => {}
            Err(DirError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                return Err(ClientError::NotRunning {
                    socket: socket.into(),
                });
            }
            Err(e) => return Err(ClientError::InsecureDir(e)),
        }

        let stream = UnixStream::connect(socket).map_err(|source| match source.kind() {
            // No socket file, or a stale one nobody is listening on.
            io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => ClientError::NotRunning {
                socket: socket.into(),
            },
            _ => ClientError::Connect {
                socket: socket.into(),
                source,
            },
        })?;
        let connect_err = |source| ClientError::Connect {
            socket: socket.into(),
            source,
        };
        let daemon = sys::peer_cred(stream.as_fd()).map_err(connect_err)?;
        if daemon.uid != uid {
            return Err(ClientError::ForeignDaemon {
                socket: socket.into(),
                uid: daemon.uid,
            });
        }
        let mut client = Self {
            end: End::Local(stream),
            next_id: 1,
            local: timeout,
            timeout,
        };
        let build = BUILD_ID.to_owned();
        match client.request(Request::Hello { build })? {
            Response::Hello { .. } => Ok(client),
            _ => Err(ClientError::UnexpectedReply),
        }
    }

    /// Machine `machine`'s remote endpoint at `addr`, named `host` in each
    /// request, which carries `token` if there is one. Nothing is sent
    /// yet: every request connects, says its build and is answered. Who
    /// may use the endpoint is that machine's daemon's call, by the
    /// identity tailscaled gives this one and by the token.
    pub fn connect_remote(
        machine: &str,
        addr: SocketAddr,
        host: &str,
        token: Option<&str>,
        timeout: Duration,
    ) -> Result<Self, ClientError> {
        let connect_err = |source| ClientError::ConnectRemote {
            machine: machine.to_owned(),
            addr,
            source,
        };
        let host = HeaderValue::from_str(&format!("{host}:{}", addr.port()))
            .map_err(|e| connect_err(io::Error::new(io::ErrorKind::InvalidInput, e)))?;
        let authorization = token
            .map(|token| {
                let mut value = HeaderValue::from_str(&format!("Bearer {token}"))
                    .map_err(|_| ClientError::BadToken)?;
                value.set_sensitive(true);
                Ok(value)
            })
            .transpose()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(connect_err)?;
        Ok(Self {
            end: End::Remote(Box::new(RemoteEnd {
                machine: machine.to_owned(),
                addr,
                host,
                authorization,
                runtime,
                silence: SILENCE,
            })),
            next_id: 1,
            local: timeout,
            timeout,
        })
    }

    /// For a remote endpoint: gives up on a reply that says nothing for
    /// `silence`.
    #[cfg(test)]
    pub(crate) fn with_silence(mut self, silence: Duration) -> Self {
        if let End::Remote(end) = &mut self.end {
            end.silence = silence;
        }
        self
    }

    /// Sends one request and waits for its reply. Daemon-side errors come back
    /// as `ClientError::Daemon`.
    pub fn request(&mut self, body: Request) -> Result<Response, ClientError> {
        self.timeout = deadline(&body, self.local);
        let stream = match &mut self.end {
            End::Local(stream) => stream,
            End::Remote(end) => {
                let (total, connect) = (self.timeout, self.local);
                let reply = end.runtime.block_on(async {
                    tokio::time::timeout(total, end.exchange(&body, connect))
                        .await
                        .unwrap_or(Err(ClientError::Timeout(total)))
                })?;
                return match reply {
                    Response::Error(e) => Err(ClientError::Daemon(e)),
                    reply => Ok(reply),
                };
            }
        };
        let timeouts = stream
            .set_read_timeout(Some(self.timeout))
            .and_then(|()| stream.set_write_timeout(Some(self.timeout)));
        timeouts.map_err(|e| ClientError::Frame(FrameError::Io(e)))?;
        let id = self.next_id;
        self.next_id += 1;
        let frame = RequestFrame { id, body };
        let timeout = self.timeout;
        write_frame(stream, &frame).map_err(|e| frame_error(e, timeout))?;
        let reply: ResponseFrame = read_frame(stream).map_err(|e| frame_error(e, timeout))?;
        match reply.body {
            Response::Error(e) => Err(ClientError::Daemon(e)),
            _ if reply.id != id => Err(ClientError::UnexpectedReply),
            body => Ok(body),
        }
    }
}

fn frame_error(e: FrameError, timeout: Duration) -> ClientError {
    match e {
        FrameError::Io(io)
            if matches!(
                io.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            ClientError::Timeout(timeout)
        }
        e => ClientError::Frame(e),
    }
}

impl RemoteEnd {
    fn lost(&self, reason: impl ToString) -> ClientError {
        ClientError::Remote {
            machine: self.machine.clone(),
            reason: reason.to_string(),
        }
    }

    /// One request and its reply, on a connection of its own.
    async fn exchange(&self, req: &Request, connect: Duration) -> Result<Response, ClientError> {
        let connect_err = |source| ClientError::ConnectRemote {
            machine: self.machine.clone(),
            addr: self.addr,
            source,
        };
        let stream = tokio::time::timeout(connect, tokio::net::TcpStream::connect(self.addr))
            .await
            .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()))
            .map_err(connect_err)?;
        self.exchange_on(stream, req).await
    }

    async fn exchange_on<S>(&self, stream: S, req: &Request) -> Result<Response, ClientError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|e| self.lost(e))?;
        // It carries the bytes while this function waits for them.
        let connection = tokio::spawn(connection);
        let _stop = AbortOnDrop(connection.abort_handle());

        let body = encode_json(req).map_err(ClientError::Frame)?;
        let mut http = hyper::Request::new(Full::new(Bytes::from_owner(body)));
        *http.method_mut() = hyper::Method::POST;
        *http.uri_mut() = hyper::Uri::from_static(PATH);
        let headers = http.headers_mut();
        headers.insert(header::HOST, self.host.clone());
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        headers.insert(
            BUILD_HEADER,
            HeaderValue::from_str(BUILD_ID).map_err(|e| self.lost(e))?,
        );
        if let Some(authorization) = &self.authorization {
            headers.insert(header::AUTHORIZATION, authorization.clone());
        }

        let reply = sender.send_request(http).await.map_err(|e| self.lost(e))?;
        let status = reply.status().as_u16();
        let mut incoming = reply.into_body();
        // At its full size from the start: growing it would leave copies of
        // the values in it behind.
        let mut body = Zeroizing::new(Vec::with_capacity(MAX_FRAME));
        loop {
            let frame = tokio::time::timeout(self.silence, incoming.frame())
                .await
                .map_err(|_| self.lost(format!("nothing arrived for {:?}", self.silence)))?;
            let Some(frame) = frame else { break };
            let frame = frame.map_err(|e| self.lost(e))?;
            let Some(data) = frame.data_ref() else {
                continue;
            };
            // The newlines of a reply that is not ready yet.
            if body.is_empty() && data.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            if body.len() + data.len() > MAX_FRAME {
                return Err(ClientError::Frame(FrameError::TooLarge(
                    body.len() + data.len(),
                )));
            }
            body.extend_from_slice(data);
        }
        decode(&body).map_err(|_| ClientError::NotADaemon {
            machine: self.machine.clone(),
            addr: self.addr,
            status,
        })
    }
}

/// Stops a task when the request it serves is over.
struct AbortOnDrop(tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}
