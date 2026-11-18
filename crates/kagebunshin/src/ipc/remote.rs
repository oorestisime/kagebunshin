//! The remote endpoint: the daemon's requests over HTTP on this machine's
//! tailnet address, for machines a grant names.
//!
//! [`supervise`] keeps at most one listener, and only while all of these
//! hold: the store turns the endpoint on, tailscaled answers, its backend
//! is `Running`, it gives this machine an IPv4 tailnet address, and a plain
//! bind to exactly that address succeeds. There is no fallback address:
//! never `0.0.0.0`, `::` or localhost. It asks tailscaled again every
//! [`POLL`], and when the store changes, and drops the listener, with the
//! connections it accepted, as soon as one of those stops holding or the
//! address changes. A listener whose address went away does not fail on
//! Linux, so it has to be dropped.
//!
//! A request is `POST /v1` whose body is one [`Request`] as JSON, and the
//! reply's body is one [`Response`] as JSON; one request to a connection.
//! While the daemon works on a request, which for a `run` that waits for
//! approval can be half an hour, the reply's body gets a newline every
//! [`HEARTBEAT`], so nothing between the two machines takes the silence
//! for a dead connection; JSON allows any number of them before a value.
//! The caller hanging up ends the request, and with it a prompt it was
//! waiting on. A caller that stalls is dropped: one that does not finish
//! its request within the daemon's deadlines, and any connection older
//! than [`LONGEST`].
//!
//! Each connection is identified by asking tailscaled who its peer is.
//! A peer it cannot name, and this machine itself, are refused whatever
//! they send; the rest become a [`Caller::remote`], carrying the hash of
//! the token in the request's `Authorization: Bearer` header, and the
//! daemon decides what that caller may do (see `Daemon::handle_from`).
//!
//! It speaks plain HTTP: between two machines the tailnet encrypts it.
//! A web page open on a machine of the tailnet is kept out three ways: a
//! request must name this machine as its `Host` (so a name an attacker
//! points at this address gets nothing), must not carry an `Origin`, and
//! no reply allows cross-origin reads.

use std::convert::Infallible;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full, Limited, StreamBody};
use hyper::body::{Body as _, Frame, Incoming};
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use super::frame::{self, FrameError, MAX_FRAME};
use super::protocol::{
    APPROVAL_TIMEOUT, Caller, ErrorCode, RemotePeer, Request, Response, WireError,
};
use super::server::ServerConfig;
use crate::daemon::Daemon;
use crate::store::TokenHash;
use crate::tailnet::{self, LocalApi};

/// How often the supervisor asks tailscaled whether anything changed.
pub const POLL: Duration = Duration::from_secs(5);

/// The path requests are posted to.
pub const PATH: &str = "/v1";

/// The request header that carries the caller's build, which must be the
/// daemon's.
pub const BUILD_HEADER: &str = "kagebunshin-build";

/// How often a reply that is not ready yet gets a newline.
pub const HEARTBEAT: Duration = Duration::from_secs(15);

/// How long a connection may last: its one request can wait for approval
/// in the app, and then has to be fetched and sent.
pub const LONGEST: Duration = Duration::from_secs(APPROVAL_TIMEOUT.as_secs() + 5 * 60);

type Body = UnsyncBoxBody<Bytes, Infallible>;

/// Where the endpoint should listen, this machine's node there, and the
/// names it answers to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Want {
    addr: SocketAddr,
    node: String,
    /// What a request's `Host` may name, in lower case: the address, this
    /// machine's `MagicDNS` name, and that name's first label.
    hosts: Vec<String>,
}

impl Want {
    pub(crate) fn new(ip: IpAddr, port: u16, node: String, dns_name: &str) -> Self {
        let mut hosts = vec![ip.to_string()];
        let dns = dns_name.trim_end_matches('.').to_ascii_lowercase();
        if let Some(label) = dns.split('.').next().filter(|l| !l.is_empty()) {
            hosts.push(label.to_owned());
            if label != dns {
                hosts.push(dns.clone());
            }
        }
        Self {
            addr: SocketAddr::new(ip, port),
            node,
            hosts,
        }
    }

    /// Whether a request's `Host` names this endpoint: one of its names,
    /// and its port if it gives one. A browser sent here under a name of
    /// an attacker's fails this, whatever address that name has.
    fn serves(&self, host: Option<&HeaderValue>) -> bool {
        let Some(host) = host.and_then(|h| h.to_str().ok()) else {
            return false;
        };
        let (name, port) = match host.rsplit_once(':') {
            Some((name, port)) if port.bytes().all(|b| b.is_ascii_digit()) => (name, Some(port)),
            _ => (host, None),
        };
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        port.is_none_or(|p| p.parse() == Ok(self.addr.port())) && self.hosts.contains(&name)
    }
}

/// Where the endpoint should listen now; `Err(None)` when it is off, or
/// `Err(Some(why))` when it is on but cannot.
async fn wanted(daemon: &Daemon, api: &dyn LocalApi) -> Result<Want, Option<String>> {
    if daemon.remote_enabled() != Some(true) {
        return Err(None);
    }
    let port = daemon.remote_port().map_err(Some)?;
    let status = tailnet::status(api)
        .await
        .map_err(|e| Some(e.to_string()))?;
    if !status.running() {
        return Err(Some(format!(
            "Tailscale is {}, not Running",
            if status.state.is_empty() {
                "in an unknown state"
            } else {
                &status.state
            }
        )));
    }
    let ip = status
        .listen_ip()
        .filter(|ip| !ip.is_unspecified() && !ip.is_loopback())
        .ok_or_else(|| Some("Tailscale gives this machine no IPv4 tailnet address".to_owned()))?;
    if status.node.is_empty() {
        return Err(Some("Tailscale does not name this machine's node".into()));
    }
    Ok(Want::new(ip, port, status.node, &status.dns_name))
}

/// Runs the remote endpoint until `shutdown` completes.
pub async fn supervise(
    daemon: Daemon,
    api: Arc<dyn LocalApi>,
    cfg: Arc<ServerConfig>,
    poll: Duration,
    shutdown: impl Future<Output = ()>,
) {
    tokio::pin!(shutdown);
    // Dropping the task's future drops its connections.
    let mut current: Option<(Want, tokio::task::JoinHandle<()>)> = None;
    loop {
        let want = wanted(&daemon, api.as_ref()).await;
        let keep = matches!((&current, &want), (Some((have, _)), Ok(w)) if have == w);
        if !keep {
            if let Some((have, task)) = current.take() {
                task.abort();
                info!(addr = %have.addr, "the remote endpoint stopped listening");
            }
            match want {
                Ok(want) => match TcpListener::bind(want.addr).await {
                    Ok(listener) => {
                        info!(addr = %want.addr, "the remote endpoint is listening");
                        daemon.set_remote_listening(Some(want.addr), None);
                        let task = tokio::spawn(accept(
                            listener,
                            Arc::new(want.clone()),
                            api.clone(),
                            cfg.clone(),
                            daemon.clone(),
                        ));
                        current = Some((want, task));
                    }
                    Err(e) => {
                        warn!(addr = %want.addr, error = %e, "the remote endpoint cannot listen");
                        daemon.set_remote_listening(
                            None,
                            Some(format!("cannot listen on {}: {e}", want.addr)),
                        );
                    }
                },
                Err(problem) => {
                    if let Some(p) = &problem {
                        debug!(problem = %p, "the remote endpoint does not listen");
                    }
                    daemon.set_remote_listening(None, problem);
                }
            }
        }
        tokio::select! {
            () = &mut shutdown => break,
            () = tokio::time::sleep(poll) => {}
            () = daemon.remote_changed() => {}
        }
    }
    if let Some((_, task)) = current {
        task.abort();
    }
    daemon.set_remote_listening(None, None);
}

async fn accept(
    listener: TcpListener,
    at: Arc<Want>,
    api: Arc<dyn LocalApi>,
    cfg: Arc<ServerConfig>,
    daemon: Daemon,
) {
    let mut connections = JoinSet::new();
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                while connections.try_join_next().is_some() {}
                let (at, api, cfg, daemon) = (at.clone(), api.clone(), cfg.clone(), daemon.clone());
                connections.spawn(async move {
                    connection(stream, peer, &at, api.as_ref(), &cfg, &daemon).await;
                });
            }
            Err(e) => {
                warn!(error = %e, "remote accept failed");
                // Out of descriptors, say: do not spin.
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// Answers the one request of a remote connection from `peer`, once
/// tailscaled names it. `at` is where this endpoint listens.
pub(crate) async fn connection<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    peer: SocketAddr,
    at: &Want,
    api: &dyn LocalApi,
    cfg: &ServerConfig,
    daemon: &Daemon,
) {
    let identity = identify(api, peer, &at.node).await;
    match &identity {
        Ok(r) => debug!(machine = %r.machine, user = %r.user, "remote connection"),
        Err(e) => info!(%peer, reason = %e.message, "refused a remote connection"),
    }
    let service = service_fn(|req| {
        let identity = &identity;
        async move { Ok::<_, Infallible>(answer(req, identity, at, cfg, daemon).await) }
    });
    let served = http1::Builder::new()
        .keep_alive(false)
        // A reply's body goes out from the buffer it was encoded into,
        // which is zeroed after, not through a copy of it.
        .writev(true)
        .timer(TokioTimer::new())
        .header_read_timeout(cfg.handshake_timeout)
        .serve_connection(TokioIo::new(stream), service);
    match tokio::time::timeout(LONGEST, served).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => debug!(%peer, error = %e, "remote connection ended"),
        Err(_) => info!(%peer, "dropped a remote connection older than {LONGEST:?}"),
    }
}

/// The reply to one HTTP request from the peer `identity` names.
async fn answer(
    req: hyper::Request<Incoming>,
    identity: &Result<RemotePeer, WireError>,
    at: &Want,
    cfg: &ServerConfig,
    daemon: &Daemon,
) -> hyper::Response<Body> {
    let peer = match identity {
        Ok(peer) => peer,
        Err(e) => return fixed(StatusCode::FORBIDDEN, &Response::Error(e.clone())),
    };
    let refuse = |status: StatusCode, code, message: &str| {
        info!(
            machine = %peer.machine,
            status = status.as_u16(),
            reason = message,
            "refused a remote request"
        );
        fixed(status, &Response::Error(WireError::new(code, message)))
    };
    let headers = req.headers();
    if !at.serves(headers.get(header::HOST)) {
        return refuse(
            StatusCode::MISDIRECTED_REQUEST,
            ErrorCode::PermissionDenied,
            "the request's Host is not a name of this machine on its tailnet",
        );
    }
    if headers.contains_key(header::ORIGIN) {
        return refuse(
            StatusCode::FORBIDDEN,
            ErrorCode::PermissionDenied,
            "the remote endpoint does not answer web pages",
        );
    }
    if req.uri().path() != PATH {
        return refuse(
            StatusCode::NOT_FOUND,
            ErrorCode::BadRequest,
            "requests are posted to /v1",
        );
    }
    if req.method() != Method::POST {
        let mut reply = refuse(
            StatusCode::METHOD_NOT_ALLOWED,
            ErrorCode::BadRequest,
            "requests are posted to /v1",
        );
        reply
            .headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static("POST"));
        return reply;
    }
    if let Err(e) = same_build(headers, cfg) {
        let status = match e.code {
            ErrorCode::BuildMismatch => StatusCode::CONFLICT,
            _ => StatusCode::BAD_REQUEST,
        };
        return fixed(status, &Response::Error(e));
    }
    let token = match bearer(headers) {
        Ok(token) => token,
        Err(e) => return fixed(StatusCode::BAD_REQUEST, &Response::Error(e)),
    };
    let too_large = |len: usize| {
        refuse(
            StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::BadRequest,
            &FrameError::TooLarge(len).to_string(),
        )
    };
    // What it says it will send, before any of it is read.
    let declared = usize::try_from(req.body().size_hint().lower()).unwrap_or(usize::MAX);
    if declared > MAX_FRAME {
        return too_large(declared);
    }
    let whole = Limited::new(req.into_body(), MAX_FRAME).collect();
    let body = match tokio::time::timeout(cfg.idle_timeout, whole).await {
        Ok(Ok(body)) => body.to_bytes(),
        Ok(Err(e)) if e.is::<http_body_util::LengthLimitError>() => {
            return too_large(MAX_FRAME + 1);
        }
        Ok(Err(_)) => {
            return refuse(
                StatusCode::BAD_REQUEST,
                ErrorCode::BadRequest,
                "the request's body did not arrive whole",
            );
        }
        Err(_) => {
            return refuse(
                StatusCode::REQUEST_TIMEOUT,
                ErrorCode::BadRequest,
                "the request's body did not arrive in time",
            );
        }
    };
    let request: Request = match frame::decode(&body) {
        Ok(request) => request,
        Err(e) => {
            return refuse(
                StatusCode::BAD_REQUEST,
                ErrorCode::BadRequest,
                &e.to_string(),
            );
        }
    };
    let caller = Caller::remote(RemotePeer {
        token,
        ..peer.clone()
    });
    match request {
        Request::Hello { .. } => fixed(
            StatusCode::OK,
            &Response::Hello {
                build: cfg.build_id.clone(),
            },
        ),
        Request::Ping => fixed(StatusCode::OK, &Response::Pong),
        Request::Whoami => fixed(StatusCode::OK, &Response::Whoami(caller)),
        other => {
            let daemon = daemon.clone();
            let work = async move { encoded(&daemon.handle_from(other, &caller).await) };
            json(StatusCode::OK, waiting(work, cfg.heartbeat))
        }
    }
}

/// Refuses a caller whose build is not this daemon's: the two would not
/// agree on what the requests mean.
fn same_build(headers: &HeaderMap, cfg: &ServerConfig) -> Result<(), WireError> {
    let build = headers
        .get(BUILD_HEADER)
        .and_then(|b| b.to_str().ok())
        .ok_or_else(|| {
            WireError::new(
                ErrorCode::BadRequest,
                format!("the request has no {BUILD_HEADER} header"),
            )
        })?;
    if build == cfg.build_id {
        return Ok(());
    }
    let mut client: String = build.chars().take(64).collect();
    if client.len() < build.len() {
        client.push('…');
    }
    Err(WireError::new(
        ErrorCode::BuildMismatch,
        format!(
            "client build {client} does not match daemon build {}",
            cfg.build_id
        ),
    )
    .with_hint("install the same kagebunshin release on both machines"))
}

/// The hash of the token in `Authorization: Bearer <token>`; `None` for a
/// request without that header. The token itself goes no further.
fn bearer(headers: &HeaderMap) -> Result<Option<TokenHash>, WireError> {
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return Ok(None);
    };
    value
        .to_str()
        .ok()
        .and_then(|v| v.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
        .map(|(_, token)| token.trim())
        .filter(|token| !token.is_empty())
        .map(|token| Some(TokenHash::of(token)))
        .ok_or_else(|| {
            WireError::new(
                ErrorCode::BadRequest,
                "the Authorization header is not `Bearer <token>`",
            )
        })
}

/// `reply` as a body, zeroed once sent: it may carry values. One too large
/// to send becomes an error that says so.
fn encoded(reply: &Response) -> Bytes {
    let buf = frame::encode_json(reply).or_else(|e| {
        frame::encode_json(&Response::Error(WireError::new(
            ErrorCode::Internal,
            format!("cannot send the reply: {e}"),
        )))
    });
    match buf {
        Ok(buf) => Bytes::from_owner(buf),
        Err(_) => Bytes::from_static(
            br#"{"kind":"error","code":"internal","message":"cannot send the reply","hint":null}"#,
        ),
    }
}

/// A reply that is known already.
fn fixed(status: StatusCode, reply: &Response) -> hyper::Response<Body> {
    json(status, Full::new(encoded(reply)).boxed_unsync())
}

fn json(status: StatusCode, body: Body) -> hyper::Response<Body> {
    let mut reply = hyper::Response::new(body);
    *reply.status_mut() = status;
    let headers = reply.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    reply
}

/// The body of a reply still being worked on: a newline every `beat`
/// until `work` gives it. Dropped with the connection, which drops `work`.
fn waiting(work: impl Future<Output = Bytes> + Send + 'static, beat: Duration) -> Body {
    let work: Pin<Box<dyn Future<Output = Bytes> + Send>> = Box::pin(work);
    let frames = futures::stream::unfold(Some(work), move |work| async move {
        let mut work = work?;
        tokio::select! {
            biased;
            reply = &mut work => Some((Ok(Frame::data(reply)), None)),
            () = tokio::time::sleep(beat) => {
                Some((Ok(Frame::data(Bytes::from_static(b"\n"))), Some(work)))
            }
        }
    });
    StreamBody::new(frames).boxed_unsync()
}

/// Who `peer` is, as tailscaled says; refused when it cannot say, and for
/// this machine's own node `me`.
async fn identify(api: &dyn LocalApi, peer: SocketAddr, me: &str) -> Result<RemotePeer, WireError> {
    let id = tailnet::whois(api, peer).await.map_err(|e| {
        WireError::new(
            ErrorCode::PermissionDenied,
            format!("cannot identify the caller on the tailnet: {e}"),
        )
    })?;
    if id.node == me {
        return Err(WireError::new(
            ErrorCode::PermissionDenied,
            "the remote endpoint does not serve this machine itself",
        )
        .with_hint("on this machine, use kagebunshin without --machine"));
    }
    Ok(RemotePeer {
        node: id.node,
        machine: id.machine,
        user: id.user,
        tags: id.tags,
        token: None,
    })
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::Path;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::config::schema::DEFAULT_REMOTE_PORT;
    use crate::config::{Config, Registry};
    use crate::daemon::Providers;
    use crate::ipc::protocol::BUILD_ID;
    use crate::store::{Passphrase, STORE_FILE, StoreFile};
    use crate::tailnet::fake::FakeTailnet;

    const LAPTOP: &str = "100.64.0.9:41000";
    const HOST: &str = "self.example.ts.net:47317";

    /// A daemon with no projects whose store turns the endpoint on (or
    /// off), unlocked, on `tailnet`.
    async fn daemon(dir: &Path, enabled: bool, tailnet: &Arc<FakeTailnet>) -> Daemon {
        let file = StoreFile::new(dir.join(STORE_FILE)).with_test_work_factor();
        let pass = Passphrase::new("pw".into());
        file.create(&pass).unwrap();
        file.update(&pass, None, |st| {
            st.set_remote_enabled(enabled);
            Ok(())
        })
        .unwrap();
        let registry = Registry::new(Config::default(), Vec::new()).unwrap();
        let d = Daemon::new(
            Box::new(move || Ok(registry.clone())),
            Arc::new(Providers::new()),
            file,
        )
        .with_tailnet(tailnet.clone());
        d.unlock(Some(pass)).await.unwrap();
        d
    }

    fn cfg() -> ServerConfig {
        ServerConfig::new("/nonexistent/kagebunshin-test/sock".into())
    }

    /// Where [`FakeTailnet`]'s own machine listens.
    fn at() -> Want {
        Want::new(
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
            DEFAULT_REMOTE_PORT,
            "nSELF".into(),
            "self.example.ts.net.",
        )
    }

    /// A tailnet whose tailscaled names [`LAPTOP`] as the machine laptop.
    fn named() -> Arc<FakeTailnet> {
        let tailnet = Arc::new(FakeTailnet::running(&[("nLAPTOP", "laptop")]));
        tailnet.set_whois(
            LAPTOP.parse().unwrap(),
            Ok(("nLAPTOP", "laptop", "dev@example.com", &[])),
        );
        tailnet
    }

    /// `req` as the client sends it.
    fn post(req: &Request) -> hyper::Request<Full<Bytes>> {
        let body = serde_json::to_vec(req).unwrap();
        hyper::Request::builder()
            .method(Method::POST)
            .uri(PATH)
            .header(header::HOST, HOST)
            .header(BUILD_HEADER, BUILD_ID)
            .body(Full::new(Bytes::from(body)))
            .unwrap()
    }

    fn status() -> hyper::Request<Full<Bytes>> {
        post(&Request::Status { facts: None })
    }

    struct Reply {
        status: StatusCode,
        headers: HeaderMap,
        body: Bytes,
    }

    impl Reply {
        fn said(&self) -> Response {
            serde_json::from_slice(&self.body)
                .unwrap_or_else(|e| panic!("{e}: {:?}", String::from_utf8_lossy(&self.body)))
        }

        fn error(&self) -> WireError {
            match self.said() {
                Response::Error(e) => e,
                other => panic!("{other:?}"),
            }
        }
    }

    /// Sends `req` on a connection from `peer`; what comes back.
    async fn send(
        peer: &str,
        tailnet: &FakeTailnet,
        d: &Daemon,
        cfg: &ServerConfig,
        req: hyper::Request<Full<Bytes>>,
    ) -> Reply {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let at = at();
        let serve = connection(server, peer.parse().unwrap(), &at, tailnet, cfg, d);
        let talk = async {
            let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(client))
                .await
                .unwrap();
            let conn = tokio::spawn(conn);
            let reply = sender.send_request(req).await.unwrap();
            let (head, body) = reply.into_parts();
            let body = body.collect().await.unwrap().to_bytes();
            drop(sender);
            conn.abort();
            Reply {
                status: head.status,
                headers: head.headers,
                body,
            }
        };
        let ((), reply) = tokio::join!(serve, talk);
        // Nothing here is a web page's to read.
        assert!(
            !reply
                .headers
                .keys()
                .any(|h| h.as_str().starts_with("access-control-")),
            "{:?}",
            reply.headers
        );
        assert_eq!(reply.headers[header::CONTENT_TYPE], "application/json");
        assert_eq!(reply.headers[header::CACHE_CONTROL], "no-store");
        reply
    }

    /// The bytes `raw` gets back, sent as they are from the machine laptop.
    async fn send_raw(tailnet: &FakeTailnet, d: &Daemon, cfg: &ServerConfig, raw: &str) -> String {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let at = at();
        let serve = connection(server, LAPTOP.parse().unwrap(), &at, tailnet, cfg, d);
        let talk = async {
            client.write_all(raw.as_bytes()).await.unwrap();
            let mut reply = Vec::new();
            let _ = client.read_to_end(&mut reply).await;
            String::from_utf8_lossy(&reply).into_owned()
        };
        let ((), reply) = tokio::join!(serve, talk);
        reply
    }

    /// A peer tailscaled cannot name, and this machine itself, are refused
    /// whatever they send; a peer it names is a remote caller, which
    /// without a grant gets nothing.
    #[tokio::test]
    async fn connections_are_identified_by_tailscaled() {
        let tmp = tempfile::tempdir().unwrap();
        let tailnet = Arc::new(FakeTailnet::running(&[("nLAPTOP", "laptop")]));
        let d = daemon(tmp.path(), true, &tailnet).await;
        let cfg = cfg();

        // Unknown to tailscaled (it answers 404), or no tailscaled at all.
        let reply = send(LAPTOP, &tailnet, &d, &cfg, status()).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN);
        let e = reply.error();
        assert_eq!(e.code, ErrorCode::PermissionDenied);
        assert!(
            e.message
                .starts_with("cannot identify the caller on the tailnet"),
            "{e:?}"
        );
        tailnet.set_whois(LAPTOP.parse().unwrap(), Err(404));
        let reply = send(LAPTOP, &tailnet, &d, &cfg, status()).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN);
        assert!(reply.error().message.contains("404"));
        // Not even what a request with nothing right about it would learn.
        let mut wrong = status();
        *wrong.method_mut() = Method::GET;
        *wrong.uri_mut() = hyper::Uri::from_static("/");
        wrong.headers_mut().clear();
        let reply = send(LAPTOP, &tailnet, &d, &cfg, wrong).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN);

        // This machine's own node, at whatever address.
        tailnet.set_whois(
            LAPTOP.parse().unwrap(),
            Ok(("nSELF", "self", "me@example.com", &[])),
        );
        let reply = send(LAPTOP, &tailnet, &d, &cfg, status()).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN);
        assert_eq!(
            reply.error().message,
            "the remote endpoint does not serve this machine itself"
        );

        // Named: the daemon decides.
        tailnet.set_whois(
            LAPTOP.parse().unwrap(),
            Ok(("nLAPTOP", "laptop", "tagged-devices", &["tag:ci"])),
        );
        let reply = send(LAPTOP, &tailnet, &d, &cfg, status()).await;
        assert_eq!(reply.status, StatusCode::OK);
        let e = reply.error();
        assert_eq!(e.code, ErrorCode::PermissionDenied);
        assert_eq!(e.message, "machine laptop has no remote grant");
        let build = BUILD_ID.to_owned();
        let reply = send(LAPTOP, &tailnet, &d, &cfg, post(&Request::Hello { build })).await;
        assert!(matches!(reply.said(), Response::Hello { build } if build == BUILD_ID));
        let reply = send(LAPTOP, &tailnet, &d, &cfg, post(&Request::Ping)).await;
        assert_eq!(reply.said(), Response::Pong);

        // What it sent as its token is not said back, nor its hash.
        let mut whoami = post(&Request::Whoami);
        whoami.headers_mut().insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer kbr_a-token"),
        );
        let reply = send(LAPTOP, &tailnet, &d, &cfg, whoami).await;
        let text = String::from_utf8_lossy(&reply.body).into_owned();
        assert!(!text.contains("token"), "{text}");
        let Response::Whoami(me) = reply.said() else {
            panic!("{text}");
        };
        let peer = me.remote.unwrap();
        assert_eq!(
            (
                peer.node.as_str(),
                peer.machine.as_str(),
                peer.user.as_str()
            ),
            ("nLAPTOP", "laptop", "tagged-devices")
        );
        assert_eq!(peer.tags, ["tag:ci"]);
        assert_eq!(me.pid, 0);
    }

    /// A request is a `POST` to the one path, from this daemon's build,
    /// with one request as its body.
    #[tokio::test]
    async fn a_request_is_a_post_of_json_from_the_same_build() {
        let tmp = tempfile::tempdir().unwrap();
        let tailnet = named();
        let d = daemon(tmp.path(), true, &tailnet).await;
        let cfg = cfg();

        for method in [Method::GET, Method::PUT, Method::DELETE, Method::OPTIONS] {
            let mut req = status();
            *req.method_mut() = method.clone();
            let reply = send(LAPTOP, &tailnet, &d, &cfg, req).await;
            assert_eq!(reply.status, StatusCode::METHOD_NOT_ALLOWED, "{method}");
            assert_eq!(reply.headers[header::ALLOW], "POST");
            assert_eq!(reply.error().code, ErrorCode::BadRequest);
        }
        for path in ["/", "/v1/", "/v2", "/v1/status"] {
            let mut req = status();
            *req.uri_mut() = path.parse().unwrap();
            let reply = send(LAPTOP, &tailnet, &d, &cfg, req).await;
            assert_eq!(reply.status, StatusCode::NOT_FOUND, "{path}");
            assert_eq!(reply.error().message, "requests are posted to /v1");
        }

        let mut req = status();
        req.headers_mut().remove(BUILD_HEADER);
        let reply = send(LAPTOP, &tailnet, &d, &cfg, req).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        assert_eq!(
            reply.error().message,
            "the request has no kagebunshin-build header"
        );
        let mut req = status();
        let other = "x".repeat(200);
        req.headers_mut()
            .insert(BUILD_HEADER, HeaderValue::from_str(&other).unwrap());
        let reply = send(LAPTOP, &tailnet, &d, &cfg, req).await;
        assert_eq!(reply.status, StatusCode::CONFLICT);
        let e = reply.error();
        assert_eq!(e.code, ErrorCode::BuildMismatch);
        assert_eq!(
            e.message,
            format!(
                "client build {}… does not match daemon build {BUILD_ID}",
                "x".repeat(64)
            )
        );
        assert_eq!(
            e.hint.as_deref(),
            Some("install the same kagebunshin release on both machines")
        );

        for body in ["", "{", "[]", r#"{"op":"no_such_request"}"#, "\u{0}"] {
            let mut req = status();
            *req.body_mut() = Full::new(Bytes::from(body));
            let reply = send(LAPTOP, &tailnet, &d, &cfg, req).await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{body:?}");
            assert_eq!(reply.error().code, ErrorCode::BadRequest, "{body:?}");
        }
    }

    /// A body over the frame limit is refused: one that says so before it
    /// is read, and one that does not once it is. One that never arrives
    /// is given up on.
    #[tokio::test]
    async fn a_request_too_large_or_too_slow_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let tailnet = named();
        let d = daemon(tmp.path(), true, &tailnet).await;
        let cfg = ServerConfig {
            idle_timeout: Duration::from_millis(50),
            ..cfg()
        };
        let head =
            format!("POST {PATH} HTTP/1.1\r\nHost: {HOST}\r\n{BUILD_HEADER}: {BUILD_ID}\r\n");

        let declared = format!("{head}Content-Length: {}\r\n\r\n", MAX_FRAME + 1);
        let reply = send_raw(&tailnet, &d, &cfg, &declared).await;
        assert!(reply.starts_with("HTTP/1.1 413 "), "{reply}");
        assert!(reply.contains("exceeds the 1048576-byte limit"), "{reply}");

        let chunk = "a".repeat(64 * 1024);
        let mut chunked = format!("{head}Transfer-Encoding: chunked\r\n\r\n");
        for _ in 0..=MAX_FRAME / chunk.len() {
            chunked.push_str(&format!("{:x}\r\n{chunk}\r\n", chunk.len()));
        }
        let reply = send_raw(&tailnet, &d, &cfg, &chunked).await;
        assert!(reply.starts_with("HTTP/1.1 413 "), "{reply}");

        let stalled = format!("{head}Content-Length: 10\r\n\r\n{{");
        let reply = send_raw(&tailnet, &d, &cfg, &stalled).await;
        assert!(reply.starts_with("HTTP/1.1 408 "), "{reply}");
        assert!(reply.contains("did not arrive in time"), "{reply}");

        // And one that never finishes its headers.
        let cfg = ServerConfig {
            handshake_timeout: Duration::from_millis(50),
            ..cfg
        };
        let reply = send_raw(&tailnet, &d, &cfg, "POST /v1 HTTP/1.1\r\nHost: ").await;
        assert!(!reply.contains("200"), "{reply}");
    }

    /// The endpoint answers to this machine's names on the tailnet and to
    /// no other: a web page can make a browser on the tailnet send here
    /// under a name of its own, which gets nothing. A request a web page
    /// sent says where it came from, and gets nothing either.
    #[tokio::test]
    async fn a_web_page_gets_nothing() {
        let at = at();
        assert_eq!(
            at.hosts,
            ["100.64.0.1", "self", "self.example.ts.net"],
            "what it answers to"
        );
        let serves = |host: &str| at.serves(Some(&HeaderValue::from_str(host).unwrap()));
        for host in [
            "100.64.0.1:47317",
            "100.64.0.1",
            "self:47317",
            "self",
            "self.example.ts.net:47317",
            "SELF.Example.TS.net:47317",
            "self.example.ts.net.:47317",
            "self.example.ts.net",
        ] {
            assert!(serves(host), "{host}");
        }
        for host in [
            "",
            ":47317",
            "evil.example:47317",
            "evil.example",
            "self.example.ts.net.evil.example:47317",
            "notself.example.ts.net:47317",
            "self.example.ts.net:80",
            "self.example.ts.net:",
            "100.64.0.9:47317",
            "localhost:47317",
            "127.0.0.1:47317",
            "self.example:47317",
            "[fd7a:115c:a1e0::1]:47317",
        ] {
            assert!(!serves(host), "{host}");
        }
        assert!(!at.serves(None));
        // A machine with no name on the tailnet answers to its address.
        let bare = Want::new(at.addr.ip(), at.addr.port(), "nSELF".into(), "");
        assert_eq!(bare.hosts, ["100.64.0.1"]);

        let tmp = tempfile::tempdir().unwrap();
        let tailnet = named();
        let d = daemon(tmp.path(), true, &tailnet).await;
        let cfg = cfg();
        for host in [Some("evil.example:47317"), None] {
            let mut req = status();
            req.headers_mut().remove(header::HOST);
            if let Some(host) = host {
                req.headers_mut()
                    .insert(header::HOST, HeaderValue::from_static(host));
            }
            let reply = send(LAPTOP, &tailnet, &d, &cfg, req).await;
            assert_eq!(reply.status, StatusCode::MISDIRECTED_REQUEST, "{host:?}");
            assert_eq!(reply.error().code, ErrorCode::PermissionDenied);
        }
        // From a page, even one that names this machine and is on it; a
        // browser's question before it sends is answered the same.
        for (method, origin) in [
            (Method::POST, "https://evil.example"),
            (Method::POST, "http://self.example.ts.net:47317"),
            (Method::POST, "null"),
            (Method::OPTIONS, "https://evil.example"),
        ] {
            let mut req = status();
            *req.method_mut() = method;
            req.headers_mut()
                .insert(header::ORIGIN, HeaderValue::from_static(origin));
            let reply = send(LAPTOP, &tailnet, &d, &cfg, req).await;
            assert_eq!(reply.status, StatusCode::FORBIDDEN, "{origin}");
            assert_eq!(
                reply.error().message,
                "the remote endpoint does not answer web pages"
            );
        }
    }

    /// The token is whatever follows `Bearer`, kept as its hash; anything
    /// else in that header is refused, and no header is no token.
    #[tokio::test]
    async fn the_token_comes_as_a_bearer() {
        let with = |value: &'static str| {
            let mut headers = HeaderMap::new();
            headers.insert(header::AUTHORIZATION, HeaderValue::from_static(value));
            bearer(&headers)
        };
        assert_eq!(bearer(&HeaderMap::new()), Ok(None));
        let token = Some(TokenHash::of("kbr_abc"));
        for value in ["Bearer kbr_abc", "bearer kbr_abc", "BEARER  kbr_abc "] {
            assert_eq!(with(value), Ok(token), "{value}");
        }
        assert_ne!(with("Bearer kbr_abd"), Ok(token));
        for value in ["Bearer", "Bearer ", "Basic a2JyX2FiYw==", "kbr_abc", ""] {
            let e = with(value).unwrap_err();
            assert_eq!(e.code, ErrorCode::BadRequest, "{value}");
            assert!(!e.message.contains("kbr_abc"), "{e:?}");
        }

        let tmp = tempfile::tempdir().unwrap();
        let tailnet = named();
        let d = daemon(tmp.path(), true, &tailnet).await;
        let mut req = status();
        req.headers_mut().insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic a2JyX2FiYw=="),
        );
        let reply = send(LAPTOP, &tailnet, &d, &cfg(), req).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        assert_eq!(
            reply.error().message,
            "the Authorization header is not `Bearer <token>`"
        );
    }

    /// A reply that is not ready gets a newline every beat, then the reply:
    /// still one JSON value, and never silent for long.
    #[tokio::test(start_paused = true)]
    async fn a_reply_that_takes_long_is_kept_alive() {
        let beat = Duration::from_secs(15);
        let work = async move {
            tokio::time::sleep(beat * 3 + Duration::from_secs(1)).await;
            encoded(&Response::Pong)
        };
        let mut body = waiting(work, beat);
        let mut frames = Vec::new();
        let mut at = Vec::new();
        let start = tokio::time::Instant::now();
        while let Some(frame) = body.frame().await {
            frames.push(frame.unwrap().into_data().unwrap());
            at.push(start.elapsed().as_secs());
        }
        assert_eq!(frames[..3], [b"\n"; 3].map(|b| Bytes::from_static(b)));
        assert_eq!(at, [15, 30, 45, 46]);
        let whole = frames.concat();
        assert_eq!(
            serde_json::from_slice::<Response>(&whole).unwrap(),
            Response::Pong
        );

        // Ready at once: no newline before it.
        let mut body = waiting(async { encoded(&Response::Pong) }, beat);
        let first = body.frame().await.unwrap().unwrap().into_data().unwrap();
        assert_eq!(first, encoded(&Response::Pong));
        assert!(body.frame().await.is_none());
    }

    /// Where it would listen: nowhere while the store turns it off, while
    /// tailscaled does not answer or is not Running, or gives no address;
    /// otherwise exactly this machine's IPv4 tailnet address.
    #[tokio::test]
    async fn it_listens_only_on_the_tailnet_address_while_running() {
        let tailnet = Arc::new(FakeTailnet::running(&[]));
        let off_dir = tempfile::tempdir().unwrap();
        let off = daemon(off_dir.path(), false, &tailnet).await;
        assert_eq!(wanted(&off, tailnet.as_ref()).await, Err(None));

        let tmp = tempfile::tempdir().unwrap();
        let d = daemon(tmp.path(), true, &tailnet).await;
        let want = wanted(&d, tailnet.as_ref()).await.unwrap();
        assert_eq!(want, at());
        assert_eq!(
            want.addr,
            SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
                DEFAULT_REMOTE_PORT
            )
        );
        assert_eq!(want.node, "nSELF");

        for state in ["Stopped", "NeedsLogin", "Starting", ""] {
            tailnet.set_status(state, &[]);
            let why = wanted(&d, tailnet.as_ref()).await.unwrap_err().unwrap();
            assert!(why.contains("not Running"), "{state}: {why}");
        }
        tailnet.set(
            "/localapi/v0/status",
            Ok(serde_json::json!({
                "BackendState": "Running",
                "Self": { "ID": "nSELF", "TailscaleIPs": ["fd7a:115c:a1e0::1"] },
            })
            .to_string()
            .into_bytes()),
        );
        let why = wanted(&d, tailnet.as_ref()).await.unwrap_err().unwrap();
        assert!(why.contains("no IPv4 tailnet address"), "{why}");
        tailnet.clear();
        assert!(wanted(&d, tailnet.as_ref()).await.unwrap_err().is_some());
    }

    /// The supervisor binds exactly the tailnet address, with no fallback:
    /// where that address is not this machine's, as in this test, it does
    /// not listen and says why; once Tailscale stops, it says that.
    #[tokio::test]
    async fn the_supervisor_reports_why_it_does_not_listen() {
        let tmp = tempfile::tempdir().unwrap();
        let tailnet = Arc::new(FakeTailnet::running(&[]));
        let d = daemon(tmp.path(), true, &tailnet).await;
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(supervise(
            d.clone(),
            tailnet.clone(),
            Arc::new(cfg()),
            Duration::from_millis(10),
            async {
                let _ = stopped.await;
            },
        ));
        let report = |d: &Daemon| {
            let d = d.clone();
            async move {
                let Response::Status(r) = d.handle(Request::Status { facts: None }).await else {
                    panic!("status");
                };
                r.remote.unwrap()
            }
        };
        let mut seen = None;
        for _ in 0..200 {
            tokio::time::sleep(Duration::from_millis(5)).await;
            seen = report(&d).await.problem;
            if seen.is_some() {
                break;
            }
        }
        let problem = seen.unwrap();
        assert!(
            problem.starts_with("cannot listen on 100.64.0.1:47317"),
            "{problem}"
        );
        assert_eq!(report(&d).await.listening, None);

        tailnet.set_status("Stopped", &[]);
        let mut seen = String::new();
        for _ in 0..200 {
            tokio::time::sleep(Duration::from_millis(5)).await;
            seen = report(&d).await.problem.unwrap_or_default();
            if seen.contains("not Running") {
                break;
            }
        }
        assert_eq!(seen, "Tailscale is Stopped, not Running");
        stop.send(()).unwrap();
        task.await.unwrap();
        assert_eq!(report(&d).await.problem, None);
    }
}
