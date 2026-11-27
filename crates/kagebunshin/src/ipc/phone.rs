//! The approval page: a small web page on this machine's tailnet address,
//! for the paired phone to answer a waiting request from.
//!
//! [`supervise`] keeps at most one listener, and only while a phone is
//! paired or being paired, which the daemon knows only while unlocked: a
//! locked daemon serves nothing. As for the remote endpoint, tailscaled
//! must answer, be `Running` and give this machine an IPv4 tailnet
//! address, and the listener binds exactly that address. It is dropped,
//! with its connections, as soon as one of those stops holding.
//!
//! It speaks HTTPS, because a browser makes and uses a passkey only on a
//! page it reached that way, under a name. The name is this machine's
//! `MagicDNS` name and the certificate is the one tailscaled has issued
//! for it. That certificate shows nothing about who serves the page (see
//! [`tailnet::certificate`]); what an approval rests on is the passkey.
//!
//! Who asks is what tailscaled says of the connection's address, as for
//! the remote endpoint. Only the paired phone and the one being paired
//! get anything, asked again on every request. A page of another site
//! open on that phone is kept out: a request must name this page's
//! address as its `Host`, one that changes anything must come from this
//! page (`Origin`, exactly), and no reply allows cross-origin reads.
//!
//! The page is three files with no script or style in the HTML, so the
//! reply's `Content-Security-Policy` lets the browser run and load only
//! what this listener serves. What the page then sends is not trusted
//! for anything: an approval counts when [`Daemon::phone_approve`] finds
//! the paired passkey's signature on it.

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Body as _, Incoming};
use hyper::header::{self, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use super::prompt::Words;
use super::protocol::{RemotePeer, StandingView};
use super::server::ServerConfig;
use crate::daemon::Daemon;
use crate::daemon::broker::phone::{Answered, PhoneError, page_site};
use crate::source::unix_now;
use crate::tailnet::{self, LocalApi};
use crate::types::{EnvName, KeyName, ProjectName};
use crate::webauthn::{self, Site};

/// How long the page's state is held back while nothing changes.
pub const HOLD: Duration = Duration::from_secs(25);

/// How long a connection lasts before it is closed after its request;
/// the page opens another.
const LONGEST: Duration = Duration::from_mins(10);

/// The largest body the page sends: a passkey's answer, a few hundred
/// bytes.
const MAX_BODY: usize = 16 * 1024;

/// How often tailscaled is asked for the certificate again, so the one
/// it renewed is the one served.
const CERT_EVERY: Duration = Duration::from_hours(12);

/// How long after tailscaled gave no certificate it is asked again:
/// having one issued is not to be tried every few seconds.
const CERT_RETRY: Duration = Duration::from_mins(5);

/// What the browser may do with the page: load and run only what this
/// listener serves, and talk only to it.
const POLICY: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; \
                      connect-src 'self'; manifest-src 'self'; worker-src 'self'; \
                      base-uri 'none'; \
                      form-action 'none'; frame-ancestors 'none'";

const PAGE: &str = include_str!("phone/page.html");
const STYLE: &str = include_str!("phone/page.css");
const SCRIPT: &str = include_str!("phone/page.js");
const WORKER: &str = include_str!("phone/sw.js");
const ICON: &[u8] = include_bytes!("phone/icon.png");
const MANIFEST: &str = r##"{"name":"Kagebunshin","short_name":"Kagebunshin","start_url":"/","scope":"/","display":"standalone","background_color":"#0b0b0d","theme_color":"#0b0b0d","icons":[{"src":"/icon.png","sizes":"180x180","type":"image/png"}]}"##;

type Body = Full<Bytes>;

/// Where the page should be served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Want {
    addr: SocketAddr,
    site: Site,
}

impl Want {
    /// What a request's `Host` must be: the page's name and port.
    fn host(&self) -> &str {
        self.site.origin.trim_start_matches("https://")
    }

    /// Whether a request's `Host` is this page's. A browser sent here
    /// under a name of an attacker's fails this.
    fn serves(&self, host: Option<&HeaderValue>) -> bool {
        host.and_then(|h| h.to_str().ok())
            .is_some_and(|h| h.eq_ignore_ascii_case(self.host()))
    }

    /// This machine, as the page names it.
    fn machine(&self) -> &str {
        self.site.name.split('.').next().unwrap_or_default()
    }
}

/// Where the page should be served now; `Err(None)` when no phone is
/// paired or being paired, or `Err(Some(why))` when one is but it cannot.
async fn wanted(daemon: &Daemon, api: &dyn LocalApi) -> Result<Want, Option<String>> {
    if daemon.phone_nodes().is_empty() {
        return Err(None);
    }
    let port = daemon.phone_port().map_err(Some)?;
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
    let site = page_site(&status, port).map_err(Some)?;
    Ok(Want {
        addr: SocketAddr::new(ip, port),
        site,
    })
}

/// What a TLS connection is accepted with, from tailscaled's PEM: the
/// private key, then the certificate and the chain above it.
fn acceptor(pem: &[u8]) -> Result<TlsAcceptor, String> {
    let key = PrivateKeyDer::from_pem_slice(pem).map_err(|e| format!("its private key: {e}"))?;
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<_, _>>()
        .map_err(|e| format!("its certificates: {e}"))?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| e.to_string())?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// The certificate for the page's name, from tailscaled, which has it
/// issued the first time: that can take a minute.
async fn certified(api: &dyn LocalApi, want: &Want) -> Result<TlsAcceptor, String> {
    let name = &want.site.name;
    let pem = tailnet::certificate(api, name)
        .await
        .map_err(|e| format!("Tailscale gives no HTTPS certificate for {name}: {e}"))?;
    acceptor(&pem)
        .map_err(|e| format!("the HTTPS certificate Tailscale gave for {name} cannot be used: {e}"))
}

/// The listener while it runs.
struct Serving {
    want: Want,
    task: tokio::task::JoinHandle<()>,
    /// What new connections are accepted with.
    tls: watch::Sender<TlsAcceptor>,
    /// When tailscaled is asked for the certificate again.
    again: Instant,
}

/// Runs the approval page until `shutdown` completes.
pub async fn supervise(
    daemon: Daemon,
    api: Arc<dyn LocalApi>,
    cfg: Arc<ServerConfig>,
    poll: Duration,
    shutdown: impl Future<Output = ()>,
) {
    tokio::pin!(shutdown);
    // Dropping the task's future drops its connections.
    let mut current: Option<Serving> = None;
    // The place tailscaled gave no certificate for, until when it is not
    // asked again, and what it said.
    let mut refused: Option<(Want, Instant, String)> = None;
    loop {
        let want = wanted(&daemon, api.as_ref()).await;
        match (&mut current, want) {
            (Some(serving), Ok(want)) if serving.want == want => {
                if Instant::now() >= serving.again {
                    match certified(api.as_ref(), &want).await {
                        Ok(tls) => {
                            serving.tls.send_replace(tls);
                            serving.again = Instant::now() + CERT_EVERY;
                        }
                        // The one it has is good for a while yet.
                        Err(e) => {
                            debug!(problem = %e, "the approval page keeps its certificate");
                            serving.again = Instant::now() + CERT_RETRY;
                        }
                    }
                }
            }
            (_, want) => {
                if let Some(old) = current.take() {
                    old.task.abort();
                    info!(addr = %old.want.addr, "the approval page stopped listening");
                }
                match want {
                    Ok(want) => {
                        current = start(want, &daemon, &api, &cfg, &mut refused).await;
                    }
                    Err(problem) => {
                        if let Some(p) = &problem {
                            debug!(problem = %p, "the approval page does not listen");
                        }
                        daemon.set_phone_serving(None, problem);
                    }
                }
            }
        }
        tokio::select! {
            () = &mut shutdown => break,
            () = tokio::time::sleep(poll) => {}
            () = daemon.phone_woken() => {}
        }
    }
    if let Some(serving) = current {
        serving.task.abort();
    }
    daemon.set_phone_serving(None, None);
}

/// Starts listening at `want`, and tells the daemon where, or why not.
async fn start(
    want: Want,
    daemon: &Daemon,
    api: &Arc<dyn LocalApi>,
    cfg: &Arc<ServerConfig>,
    refused: &mut Option<(Want, Instant, String)>,
) -> Option<Serving> {
    if let Some((at, until, why)) = refused
        && *at == want
        && Instant::now() < *until
    {
        daemon.set_phone_serving(None, Some(why.clone()));
        return None;
    }
    let tls = match certified(api.as_ref(), &want).await {
        Ok(tls) => tls,
        Err(why) => {
            warn!(problem = %why, "the approval page has no certificate");
            daemon.set_phone_serving(None, Some(why.clone()));
            *refused = Some((want, Instant::now() + CERT_RETRY, why));
            return None;
        }
    };
    *refused = None;
    let listener = match TcpListener::bind(want.addr).await {
        Ok(listener) => listener,
        Err(e) => {
            warn!(addr = %want.addr, error = %e, "the approval page cannot listen");
            daemon.set_phone_serving(None, Some(format!("cannot listen on {}: {e}", want.addr)));
            return None;
        }
    };
    info!(addr = %want.addr, url = %want.site.origin, "the approval page is listening");
    daemon.set_phone_serving(Some(want.site.origin.clone()), None);
    let (tls, certs) = watch::channel(tls);
    let task = tokio::spawn(accept(
        listener,
        certs,
        Arc::new(want.clone()),
        api.clone(),
        cfg.clone(),
        daemon.clone(),
    ));
    Some(Serving {
        want,
        task,
        tls,
        again: Instant::now() + CERT_EVERY,
    })
}

async fn accept(
    listener: TcpListener,
    certs: watch::Receiver<TlsAcceptor>,
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
                let tls = certs.borrow().clone();
                let (at, api, cfg, daemon) = (at.clone(), api.clone(), cfg.clone(), daemon.clone());
                connections.spawn(async move {
                    let hello = tokio::time::timeout(cfg.handshake_timeout, tls.accept(stream));
                    match hello.await {
                        Ok(Ok(stream)) => {
                            connection(stream, peer, &at, api.as_ref(), &cfg, &daemon).await;
                        }
                        Ok(Err(e)) => debug!(%peer, error = %e, "no TLS with the approval page"),
                        Err(_) => debug!(%peer, "TLS with the approval page took too long"),
                    }
                });
            }
            Err(e) => {
                warn!(error = %e, "approval page accept failed");
                // Out of descriptors, say: do not spin.
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// Answers the requests of a connection from `peer`, once tailscaled
/// names it. `at` is where the page is served.
pub(crate) async fn connection<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    peer: SocketAddr,
    at: &Want,
    api: &dyn LocalApi,
    cfg: &ServerConfig,
    daemon: &Daemon,
) {
    let identity = identify(api, peer).await;
    match &identity {
        Ok(r) => debug!(machine = %r.machine, "approval page connection"),
        Err(e) => info!(%peer, reason = %e, "refused a connection to the approval page"),
    }
    let service = service_fn(|req| {
        let identity = &identity;
        async move { Ok::<_, Infallible>(answer(req, identity, at, cfg, daemon).await) }
    });
    let served = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(cfg.idle_timeout)
        .serve_connection(TokioIo::new(stream), service);
    tokio::pin!(served);
    let ended = tokio::select! {
        ended = served.as_mut() => ended,
        () = tokio::time::sleep(LONGEST) => {
            // After the request it is answering, if any.
            served.as_mut().graceful_shutdown();
            match tokio::time::timeout(HOLD + cfg.idle_timeout, served).await {
                Ok(ended) => ended,
                Err(_) => Ok(()),
            }
        }
    };
    if let Err(e) = ended {
        debug!(%peer, error = %e, "approval page connection ended");
    }
}

/// Who `peer` is, as tailscaled says.
async fn identify(api: &dyn LocalApi, peer: SocketAddr) -> Result<RemotePeer, String> {
    let id = tailnet::whois(api, peer)
        .await
        .map_err(|e| format!("cannot identify this device on the tailnet: {e}"))?;
    Ok(RemotePeer {
        node: id.node,
        machine: id.machine,
        user: id.user,
        tags: id.tags,
        token: None,
    })
}

/// What `/state` says: [`crate::daemon::broker::phone::PhonePage`] as the
/// page reads it.
#[derive(Serialize)]
struct State<'a> {
    /// This machine.
    machine: &'a str,
    /// Unix seconds, by this machine's clock: what `recent` is timed by.
    now: u64,
    version: u64,
    paired: bool,
    /// The daemon tells this phone of a request that waits.
    notified: bool,
    pairing: Option<u64>,
    prompts: Vec<Waiting>,
    recent: Vec<Answered>,
    /// The approvals that stand, each with the seconds it has left.
    standing: Vec<StandingView>,
}

/// A waiting request: its names, and what the app's prompt says of it.
#[derive(Serialize)]
struct Waiting {
    id: u64,
    project: ProjectName,
    env: EnvName,
    keys: Vec<KeyName>,
    /// Seconds until it is denied unanswered.
    left: u64,
    /// Whether the phone can approve it.
    here: bool,
    words: Words,
}

#[derive(Deserialize)]
struct Seen {
    /// The version of the state the page shows, to wait for another.
    #[serde(default)]
    seen: Option<u64>,
}

#[derive(Deserialize)]
struct Id {
    id: u64,
}

/// What the phone's browser gave for its notifications, as
/// [`crate::webpush::Subscription`] takes it.
#[derive(Deserialize)]
struct Subscribed {
    endpoint: String,
    p256dh: String,
    auth: String,
}

/// The request to approve, and whether its approval is to be left
/// standing.
#[derive(Deserialize)]
struct Begin {
    id: u64,
    #[serde(default)]
    standing: bool,
}

/// An environment whose standing approvals are to end.
#[derive(Deserialize)]
struct Ending {
    project: ProjectName,
    env: EnvName,
}

/// A passkey just made; both base64url.
#[derive(Deserialize)]
struct Made {
    client_data: String,
    auth_data: String,
}

/// A passkey's approval of request `id`; the rest base64url.
#[derive(Deserialize)]
struct Signed {
    id: u64,
    client_data: String,
    auth_data: String,
    signature: String,
}

/// The reply to one HTTP request from the peer `identity` names.
async fn answer(
    req: hyper::Request<Incoming>,
    identity: &Result<RemotePeer, String>,
    at: &Want,
    cfg: &ServerConfig,
    daemon: &Daemon,
) -> hyper::Response<Body> {
    let peer = match identity {
        Ok(peer) => peer,
        Err(e) => return refuse(StatusCode::FORBIDDEN, e),
    };
    let refused = |status: StatusCode, message: &str| {
        info!(
            machine = %peer.machine,
            status = status.as_u16(),
            reason = message,
            "refused a request to the approval page"
        );
        refuse(status, message)
    };
    let headers = req.headers();
    if !at.serves(headers.get(header::HOST)) {
        return refused(
            StatusCode::MISDIRECTED_REQUEST,
            "the request's Host is not this page's address",
        );
    }
    if !daemon.phone_nodes().contains(&peer.node) {
        return refused(StatusCode::FORBIDDEN, &PhoneError::NotPaired.to_string());
    }
    let path = req.uri().path().to_owned();
    if req.method() == Method::GET {
        return match path.as_str() {
            "/" => file("text/html; charset=utf-8", PAGE.as_bytes()),
            "/page.css" => file("text/css; charset=utf-8", STYLE.as_bytes()),
            "/page.js" => file("text/javascript; charset=utf-8", SCRIPT.as_bytes()),
            "/sw.js" => file("text/javascript; charset=utf-8", WORKER.as_bytes()),
            "/icon.png" => file("image/png", ICON),
            "/manifest.webmanifest" => file("application/manifest+json", MANIFEST.as_bytes()),
            _ => refuse(StatusCode::NOT_FOUND, "there is no such page"),
        };
    }
    if req.method() != Method::POST {
        let mut reply = refuse(
            StatusCode::METHOD_NOT_ALLOWED,
            "not a request this page makes",
        );
        reply
            .headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static("GET, POST"));
        return reply;
    }
    // Only this page asks for anything or answers a request: a browser
    // says which page a POST comes from, and another site's cannot lie.
    if headers.get(header::ORIGIN).and_then(|o| o.to_str().ok()) != Some(&at.site.origin) {
        return refused(
            StatusCode::FORBIDDEN,
            "the request does not come from this page",
        );
    }
    let declared = usize::try_from(req.body().size_hint().lower()).unwrap_or(usize::MAX);
    if declared > MAX_BODY {
        return refused(StatusCode::PAYLOAD_TOO_LARGE, "the request is too large");
    }
    let whole = Limited::new(req.into_body(), MAX_BODY).collect();
    let body = match tokio::time::timeout(cfg.idle_timeout, whole).await {
        Ok(Ok(body)) => body.to_bytes(),
        Ok(Err(e)) if e.is::<http_body_util::LengthLimitError>() => {
            return refused(StatusCode::PAYLOAD_TOO_LARGE, "the request is too large");
        }
        Ok(Err(_)) => {
            return refused(
                StatusCode::BAD_REQUEST,
                "the request's body did not arrive whole",
            );
        }
        Err(_) => {
            return refused(
                StatusCode::REQUEST_TIMEOUT,
                "the request's body did not arrive in time",
            );
        }
    };
    match asked(&path, &body, peer, at, daemon).await {
        Ok(reply) => reply,
        Err(Refusal::Request(message)) => refused(StatusCode::BAD_REQUEST, message),
        Err(Refusal::Path) => refuse(StatusCode::NOT_FOUND, "there is no such page"),
        Err(Refusal::Phone(e)) => {
            let status = match &e {
                PhoneError::Locked => StatusCode::SERVICE_UNAVAILABLE,
                PhoneError::Gone => StatusCode::GONE,
                PhoneError::NoChallenge => StatusCode::CONFLICT,
                PhoneError::Push(_) => StatusCode::BAD_REQUEST,
                PhoneError::Failed(_) => StatusCode::INTERNAL_SERVER_ERROR,
                PhoneError::NotPaired
                | PhoneError::NotPairing
                | PhoneError::NoStanding
                | PhoneError::DeskOnly
                | PhoneError::Passkey(_) => StatusCode::FORBIDDEN,
            };
            refused(status, &e.to_string())
        }
    }
}

/// Why a POST is not answered.
enum Refusal {
    /// What it sent is not what the page sends.
    Request(&'static str),
    Path,
    Phone(PhoneError),
}

impl From<PhoneError> for Refusal {
    fn from(e: PhoneError) -> Self {
        Self::Phone(e)
    }
}

fn parsed<'a, T: Deserialize<'a>>(body: &'a [u8]) -> Result<T, Refusal> {
    serde_json::from_slice(body)
        .map_err(|_| Refusal::Request("the request is not one this page makes"))
}

fn bytes(text: &str) -> Result<Vec<u8>, Refusal> {
    webauthn::decode(text).ok_or(Refusal::Request("the request is not one this page makes"))
}

/// What the page's POST to `path` gets from the paired phone, or the one
/// being paired, `peer`.
async fn asked(
    path: &str,
    body: &[u8],
    peer: &RemotePeer,
    at: &Want,
    daemon: &Daemon,
) -> Result<hyper::Response<Body>, Refusal> {
    let done = || Ok(json(StatusCode::OK, &serde_json::json!({})));
    match path {
        "/state" => {
            let Seen { seen } = parsed(body)?;
            if let Some(seen) = seen {
                daemon.phone_page_wait(seen, HOLD).await;
            }
            // The pairing may have ended, or the phone been unpaired,
            // while this waited.
            if !daemon.phone_nodes().contains(&peer.node) {
                return Err(PhoneError::NotPaired.into());
            }
            let page = daemon.phone_page(&peer.node);
            let prompts = (page.prompts.into_iter())
                .map(|p| Waiting {
                    words: Words::of(&p.prompt),
                    id: p.prompt.id,
                    project: p.prompt.project,
                    env: p.prompt.env,
                    keys: p.prompt.keys,
                    left: p.prompt.left.unwrap_or_default(),
                    here: p.here,
                })
                .collect();
            Ok(json(
                StatusCode::OK,
                &State {
                    machine: at.machine(),
                    now: unix_now(),
                    version: page.version,
                    paired: page.paired,
                    notified: page.notified,
                    pairing: page.pairing,
                    prompts,
                    recent: page.recent,
                    standing: page.standing,
                },
            ))
        }
        "/pair/begin" => {
            let begin = daemon.phone_pair_begin(&peer.node)?;
            Ok(json(
                StatusCode::OK,
                &serde_json::json!({
                    "challenge": webauthn::encode(&begin.challenge),
                    "name": begin.name,
                }),
            ))
        }
        "/pair/finish" => {
            let made: Made = parsed(body)?;
            let (client, auth) = (bytes(&made.client_data)?, bytes(&made.auth_data)?);
            (daemon.phone_pair_finish(&at.site, peer, &client, &auth)).await?;
            done()
        }
        "/approve/begin" => {
            let Begin { id, standing } = parsed(body)?;
            let begin = daemon.phone_approve_begin(&peer.node, id, standing)?;
            Ok(json(
                StatusCode::OK,
                &serde_json::json!({
                    "challenge": webauthn::encode(&begin.challenge),
                    "credential": begin.credential,
                }),
            ))
        }
        "/approve/finish" => {
            let signed: Signed = parsed(body)?;
            let (client, auth) = (bytes(&signed.client_data)?, bytes(&signed.auth_data)?);
            let signature = bytes(&signed.signature)?;
            daemon.phone_approve(&at.site, peer, signed.id, &client, &auth, &signature)?;
            done()
        }
        "/deny" => {
            let Id { id } = parsed(body)?;
            daemon.phone_deny(peer, id)?;
            done()
        }
        "/standing/end" => {
            let Ending { project, env } = parsed(body)?;
            daemon.phone_end_standing(peer, &project, &env)?;
            done()
        }
        "/push/key" => {
            let key = daemon.phone_push_key(&peer.node)?;
            Ok(json(StatusCode::OK, &serde_json::json!({ "key": key })))
        }
        "/push/subscribe" => {
            let said: Subscribed = parsed(body)?;
            daemon.phone_push_subscribe(peer, &said.endpoint, &said.p256dh, &said.auth)?;
            done()
        }
        _ => Err(Refusal::Path),
    }
}

/// A reply with what every reply carries.
fn reply(
    status: StatusCode,
    kind: &'static str,
    cache: &'static str,
    body: Bytes,
) -> hyper::Response<Body> {
    let mut reply = hyper::Response::new(Full::new(body));
    *reply.status_mut() = status;
    let headers = reply.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(kind));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(POLICY),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    reply
}

/// One of the page's files. Asked for again each time, so a new build's
/// page is the one shown.
fn file(kind: &'static str, body: &'static [u8]) -> hyper::Response<Body> {
    reply(StatusCode::OK, kind, "no-cache", Bytes::from_static(body))
}

fn json(status: StatusCode, said: &impl Serialize) -> hyper::Response<Body> {
    let body =
        serde_json::to_vec(said).unwrap_or_else(|_| br#"{"error":"cannot say it"}"#.to_vec());
    reply(status, "application/json", "no-store", Bytes::from(body))
}

/// A refusal, in words the page shows.
fn refuse(status: StatusCode, message: &str) -> hyper::Response<Body> {
    json(status, &serde_json::json!({ "error": message }))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use hyper::header::HeaderMap;
    use serde_json::{Value, json};

    use super::*;
    use crate::config::schema::DEFAULT_PHONE_PORT;
    use crate::config::{Config, Registry, RemoteId, parse_project};
    use crate::daemon::Providers;
    use crate::daemon::push::PushState;
    use crate::ipc::protocol::{Caller, Facts, Request, Response, WireSecret};
    use crate::store::{Passphrase, STORE_FILE, StoreFile};
    use crate::tailnet::fake::FakeTailnet;
    use crate::types::Provider;
    use crate::webauthn::fake::FakePasskey;
    use crate::webpush::fake::{FakeBrowser, FakePush};

    const PHONE: &str = "100.64.0.9:52000";
    const TABLET: &str = "100.64.0.8:52000";
    const HOST: &str = "self.example.ts.net:47318";
    const ORIGIN: &str = "https://self.example.ts.net:47318";

    /// A key and a certificate for `self.example.ts.net`, made for these
    /// tests and used nowhere else, as tailscaled gives them: the key,
    /// then the certificate.
    const PEM: &[u8] = include_bytes!("phone/test-cert.pem");

    const WIDGET: &str = r#"
schema = 1
remotes = ["git@github.com:acme/widget.git"]

[envs.dev]
"#;

    /// A tailnet with a phone and a tablet, whose tailscaled names
    /// [`PHONE`] and [`TABLET`] as them.
    fn tailnet() -> Arc<FakeTailnet> {
        let tailnet = Arc::new(FakeTailnet::default());
        tailnet.set_peers(
            "Running",
            &[("nPHONE", "phone", "iOS"), ("nTABLET", "tablet", "android")],
        );
        tailnet.set_whois(
            PHONE.parse().unwrap(),
            Ok(("nPHONE", "phone", "dev@example.com", &[])),
        );
        tailnet.set_whois(
            TABLET.parse().unwrap(),
            Ok(("nTABLET", "tablet", "dev@example.com", &[])),
        );
        tailnet
    }

    fn pw(s: &str) -> WireSecret {
        WireSecret::new(s.into())
    }

    /// A daemon with the project widget, unlocked (passphrase pw), on
    /// `tailnet`. Its store holds S in dev, marked sensitive, so reading
    /// it waits for approval.
    async fn daemon(dir: &Path, tailnet: &Arc<FakeTailnet>) -> Daemon {
        let file = StoreFile::new(dir.join(STORE_FILE)).with_test_work_factor();
        let pass = Passphrase::new("pw".into());
        file.create(&pass).unwrap();
        let project = parse_project(Path::new("/cfg/projects/widget.toml"), WIDGET).unwrap();
        let config = Config {
            default_provider: Provider::File,
            ..Config::default()
        };
        let registry = Registry::new(config, vec![project]).unwrap();
        let d = Daemon::new(
            Box::new(move || Ok(registry.clone())),
            Arc::new(Providers::new()),
            file,
        )
        .with_tailnet(tailnet.clone())
        .with_push(
            Arc::new(FakePush::default()),
            PushState::new(dir.join(crate::daemon::push::FILE)),
        );
        d.unlock(Some(pass)).await.unwrap();
        let set = d
            .handle(Request::StoreSet {
                section: "widget.dev".parse().unwrap(),
                key: "S".parse().unwrap(),
                value: pw("v"),
                passphrase: pw("pw"),
                sensitive: true,
            })
            .await;
        assert!(matches!(set, Response::Store { .. }), "{set:?}");
        d
    }

    fn cfg() -> ServerConfig {
        ServerConfig::new("/nonexistent/kagebunshin-test/sock".into())
    }

    /// Where the page of [`FakeTailnet`]'s own machine is served.
    fn at() -> Want {
        Want {
            addr: "100.64.0.1:47318".parse().unwrap(),
            site: Site::new("self.example.ts.net", DEFAULT_PHONE_PORT),
        }
    }

    fn get(path: &str) -> hyper::Request<Full<Bytes>> {
        hyper::Request::builder()
            .uri(path)
            .header(header::HOST, HOST)
            .body(Full::default())
            .unwrap()
    }

    /// `body` as the page sends it.
    fn post(path: &str, body: &Value) -> hyper::Request<Full<Bytes>> {
        hyper::Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(header::HOST, HOST)
            .header(header::ORIGIN, ORIGIN)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body.to_string())))
            .unwrap()
    }

    struct Reply {
        status: StatusCode,
        headers: HeaderMap,
        body: Bytes,
    }

    impl Reply {
        fn said(&self) -> Value {
            serde_json::from_slice(&self.body)
                .unwrap_or_else(|e| panic!("{e}: {:?}", String::from_utf8_lossy(&self.body)))
        }

        /// The refusal's words.
        fn error(&self) -> String {
            self.said()["error"].as_str().unwrap().to_owned()
        }
    }

    /// What `req` gets over `io`.
    async fn talk<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
        io: S,
        req: hyper::Request<Full<Bytes>>,
    ) -> Reply {
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
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
    }

    /// Sends `req` on a connection from `peer`; what comes back.
    async fn send(
        peer: &str,
        tailnet: &FakeTailnet,
        d: &Daemon,
        req: hyper::Request<Full<Bytes>>,
    ) -> Reply {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let (at, cfg) = (at(), cfg());
        let serve = connection(server, peer.parse().unwrap(), &at, tailnet, &cfg, d);
        let ((), reply) = tokio::join!(serve, talk(client, req));
        // No reply is another site's to read, and each says what the
        // browser may do with it.
        assert!(
            !reply
                .headers
                .keys()
                .any(|h| h.as_str().starts_with("access-control-")),
            "{:?}",
            reply.headers
        );
        assert_eq!(reply.headers[header::CONTENT_SECURITY_POLICY], POLICY);
        assert_eq!(reply.headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        reply
    }

    /// What the paired phone's page gets for `body` posted to `path`.
    async fn page(tailnet: &FakeTailnet, d: &Daemon, path: &str, body: Value) -> Reply {
        send(PHONE, tailnet, d, post(path, &body)).await
    }

    async fn state(tailnet: &FakeTailnet, d: &Daemon) -> Value {
        let reply = page(tailnet, d, "/state", json!({})).await;
        assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
        reply.said()
    }

    /// Starts pairing the phone, on this machine.
    async fn pairing(d: &Daemon) {
        let r = d
            .handle(Request::PhonePair {
                machine: "phone".into(),
                passphrase: pw("pw"),
            })
            .await;
        assert!(matches!(r, Response::PhonePairing { .. }), "{r:?}");
    }

    /// Pairs the phone over the page, with a new passkey.
    async fn paired(tailnet: &FakeTailnet, d: &Daemon) -> FakePasskey {
        pairing(d).await;
        let passkey = FakePasskey::new();
        let begin = page(tailnet, d, "/pair/begin", json!({})).await.said();
        let challenge = webauthn::decode(begin["challenge"].as_str().unwrap()).unwrap();
        let (client, auth) = passkey.create(&at().site, &challenge);
        let made = json!({
            "client_data": webauthn::encode(&client),
            "auth_data": webauthn::encode(&auth),
        });
        let reply = page(tailnet, d, "/pair/finish", made).await;
        assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
        passkey
    }

    /// Asks for the sensitive S while the app is open, so it waits for a
    /// person; the asking, and the id of its prompt.
    async fn asking(d: &Daemon) -> (tokio::task::JoinHandle<Response>, u64) {
        asking_as(d, crate::test_support::this_process()).await
    }

    /// [`asking`], by `caller`.
    async fn asking_as(d: &Daemon, caller: Caller) -> (tokio::task::JoinHandle<Response>, u64) {
        let app = tokio::spawn({
            let d = d.clone();
            async move { d.handle(Request::WaitApprovals { known: Vec::new() }).await }
        });
        tokio::task::yield_now().await;
        let asked = tokio::spawn({
            let d = d.clone();
            async move {
                let get = Request::Get {
                    facts: Facts {
                        cwd: "/src/widget".into(),
                        remotes: vec![
                            RemoteId::from_url("https://github.com/acme/widget").unwrap(),
                        ],
                        subdir: None,
                        root: None,
                        project: None,
                        env: Some("dev".parse().unwrap()),
                        example_keys: None,
                        example_values: Vec::new(),
                        env_file: None,
                    },
                    key: "S".parse().unwrap(),
                    passphrase: pw("pw"),
                };
                d.handle_from(get, &caller).await
            }
        });
        let Response::Approvals { pending } = app.await.unwrap() else {
            panic!("not approvals");
        };
        (asked, pending[0].id)
    }

    /// What the page sends to approve request `id` with `passkey`.
    async fn approval(tailnet: &FakeTailnet, d: &Daemon, passkey: &FakePasskey, id: u64) -> Value {
        let begin = page(tailnet, d, "/approve/begin", json!({ "id": id })).await;
        assert_eq!(begin.status, StatusCode::OK, "{:?}", begin.body);
        let begin = begin.said();
        assert_eq!(begin["credential"], webauthn::encode(&passkey.credential));
        let challenge = webauthn::decode(begin["challenge"].as_str().unwrap()).unwrap();
        let (client, auth, signature) = passkey.get(&at().site, &challenge);
        json!({
            "id": id,
            "client_data": webauthn::encode(&client),
            "auth_data": webauthn::encode(&auth),
            "signature": webauthn::encode(&signature),
        })
    }

    /// The page is for the paired phone and the one being paired, as
    /// tailscaled names the connection: nobody else gets even its files,
    /// and nobody gets them under another name.
    #[tokio::test]
    async fn only_the_phone_gets_the_page() {
        let tmp = tempfile::tempdir().unwrap();
        let tailnet = tailnet();
        let d = daemon(tmp.path(), &tailnet).await;

        // No phone is paired or being paired.
        let reply = send(PHONE, &tailnet, &d, get("/")).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN);
        assert_eq!(
            reply.error(),
            "this phone is not paired with kagebunshin on this computer"
        );
        assert!(!String::from_utf8_lossy(&reply.body).contains("<html"));

        pairing(&d).await;
        for (path, kind, has) in [
            ("/", "text/html; charset=utf-8", "<script src=\"/page.js\""),
            ("/page.css", "text/css; charset=utf-8", "--bg"),
            ("/page.js", "text/javascript; charset=utf-8", "'use strict'"),
            (
                "/sw.js",
                "text/javascript; charset=utf-8",
                "showNotification",
            ),
            ("/icon.png", "image/png", "PNG"),
            (
                "/manifest.webmanifest",
                "application/manifest+json",
                "\"display\":\"standalone\"",
            ),
        ] {
            let reply = send(PHONE, &tailnet, &d, get(path)).await;
            assert_eq!(reply.status, StatusCode::OK, "{path}");
            assert_eq!(reply.headers[header::CONTENT_TYPE], kind, "{path}");
            assert_eq!(reply.headers[header::CACHE_CONTROL], "no-cache", "{path}");
            assert!(String::from_utf8_lossy(&reply.body).contains(has), "{path}");
        }
        // The page holds no script or style of its own, which the policy
        // every reply carries would not run.
        assert!(!PAGE.contains("<style") && !PAGE.contains("style=\""));
        assert_eq!(PAGE.matches("<script").count(), 1);
        assert!(serde_json::from_str::<Value>(MANIFEST).is_ok());

        // Another machine of the tailnet, one tailscaled cannot name, and
        // this phone under a name that is not the page's.
        for peer in [TABLET, "100.64.0.7:52000"] {
            for path in ["/", "/page.js", "/icon.png"] {
                let reply = send(peer, &tailnet, &d, get(path)).await;
                assert_eq!(reply.status, StatusCode::FORBIDDEN, "{peer} {path}");
            }
            let reply = send(peer, &tailnet, &d, post("/state", &json!({}))).await;
            assert_eq!(reply.status, StatusCode::FORBIDDEN, "{peer}");
        }
        for host in [
            "evil.example:47318",
            "self.example.ts.net",
            "self.example.ts.net:47317",
            "100.64.0.1:47318",
        ] {
            let mut req = get("/");
            req.headers_mut()
                .insert(header::HOST, HeaderValue::from_static(host));
            let reply = send(PHONE, &tailnet, &d, req).await;
            assert_eq!(reply.status, StatusCode::MISDIRECTED_REQUEST, "{host}");
        }

        let reply = send(PHONE, &tailnet, &d, get("/nothing")).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND);
        let mut put = post("/state", &json!({}));
        *put.method_mut() = Method::PUT;
        let reply = send(PHONE, &tailnet, &d, put).await;
        assert_eq!(reply.status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(reply.headers[header::ALLOW], "GET, POST");

        // Locked, the daemon knows of no phone.
        d.lock();
        let reply = send(PHONE, &tailnet, &d, get("/")).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN);
    }

    /// Whatever asks or answers comes from this page: a browser says
    /// which page a POST is from, and another site's is refused before
    /// its body is read.
    #[tokio::test]
    async fn only_this_page_asks_or_answers() {
        let tmp = tempfile::tempdir().unwrap();
        let tailnet = tailnet();
        let d = daemon(tmp.path(), &tailnet).await;
        paired(&tailnet, &d).await;
        let (asked, id) = asking(&d).await;

        for origin in [
            None,
            Some("https://evil.example"),
            Some("http://self.example.ts.net:47318"),
            Some("https://self.example.ts.net"),
            Some("https://self.example.ts.net:47317"),
            Some("null"),
        ] {
            for (path, body) in [("/state", json!({})), ("/deny", json!({ "id": id }))] {
                let mut req = post(path, &body);
                match origin {
                    Some(o) => req
                        .headers_mut()
                        .insert(header::ORIGIN, HeaderValue::from_static(o)),
                    None => req.headers_mut().remove(header::ORIGIN),
                };
                let reply = send(PHONE, &tailnet, &d, req).await;
                assert_eq!(reply.status, StatusCode::FORBIDDEN, "{origin:?} {path}");
                assert_eq!(reply.error(), "the request does not come from this page");
            }
        }
        assert_eq!(state(&tailnet, &d).await["prompts"][0]["id"], id);

        // What the page would not send.
        let reply = page(&tailnet, &d, "/deny", json!({ "id": "one" })).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        let reply = page(&tailnet, &d, "/approve/finish", json!({ "id": id })).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        let not_base64 = json!({
            "id": id, "client_data": "{}", "auth_data": "++", "signature": "",
        });
        let reply = page(&tailnet, &d, "/approve/finish", not_base64).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        let reply = page(&tailnet, &d, "/nothing", json!({})).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND);
        let large = json!({ "id": id, "more": "x".repeat(MAX_BODY) });
        let reply = page(&tailnet, &d, "/deny", large).await;
        assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE);

        // None of it answered the request.
        assert!(!asked.is_finished());
        let reply = page(&tailnet, &d, "/deny", json!({ "id": id })).await;
        assert_eq!(reply.status, StatusCode::OK);
        assert!(matches!(asked.await.unwrap(), Response::Error(_)));
    }

    /// The paired phone asks which key to subscribe to and hands over
    /// what its browser gave for notifications; the page then says it is
    /// told of requests. Nobody else does either, and what is not a
    /// browser's is refused.
    #[tokio::test]
    async fn the_phone_allows_notifications_over_the_page() {
        let tmp = tempfile::tempdir().unwrap();
        let tailnet = tailnet();
        let d = daemon(tmp.path(), &tailnet).await;
        paired(&tailnet, &d).await;
        assert_eq!(state(&tailnet, &d).await["notified"], false);

        let reply = page(&tailnet, &d, "/push/key", json!({})).await;
        assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
        let key = reply.said()["key"].as_str().unwrap().to_owned();
        // An uncompressed P-256 point, as `applicationServerKey` takes it.
        let point = webauthn::decode(&key).unwrap();
        assert_eq!((point.len(), point[0]), (65, 4));
        let again = page(&tailnet, &d, "/push/key", json!({})).await.said();
        assert_eq!(again["key"], key);

        let browser = FakeBrowser::new();
        let given = |endpoint: &str| json!({ "endpoint": endpoint, "p256dh": browser.p256dh(), "auth": browser.auth() });
        for (body, why) in [
            (
                json!({ "endpoint": browser.endpoint }),
                "not what the page sends",
            ),
            (given("https://push.example.com/one"), "not a push service"),
            (given("http://web.push.apple.com/one"), "not HTTPS"),
            (
                json!({ "endpoint": browser.endpoint, "p256dh": "AAAA", "auth": browser.auth() }),
                "not a key",
            ),
        ] {
            let reply = page(&tailnet, &d, "/push/subscribe", body).await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{why}");
        }
        for path in ["/push/key", "/push/subscribe"] {
            let req = post(path, &given(&browser.endpoint));
            let reply = send(TABLET, &tailnet, &d, req).await;
            assert_eq!(reply.status, StatusCode::FORBIDDEN, "{path}");
        }
        assert_eq!(state(&tailnet, &d).await["notified"], false);

        let reply = page(&tailnet, &d, "/push/subscribe", given(&browser.endpoint)).await;
        assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
        assert_eq!(reply.said(), json!({}));
        assert_eq!(state(&tailnet, &d).await["notified"], true);

        // Locked, the daemon knows of no phone to take them from.
        d.lock();
        let reply = page(&tailnet, &d, "/push/key", json!({})).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN);
    }

    /// The page says what stands and ends it, for the paired phone only,
    /// and asks to leave standing only an approval whose prompt offers it.
    #[tokio::test]
    async fn the_page_lists_and_ends_what_stands() {
        let tmp = tempfile::tempdir().unwrap();
        let tailnet = tailnet();
        let d = daemon(tmp.path(), &tailnet).await;
        paired(&tailnet, &d).await;
        assert_eq!(state(&tailnet, &d).await["standing"], json!([]));

        // Asked by a process no agent stands behind.
        let nobody = crate::test_support::Orphan::start();
        let (asked, id) = asking_as(&d, nobody.caller()).await;
        let begin = json!({ "id": id, "standing": true });
        let reply = page(&tailnet, &d, "/approve/begin", begin).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN);
        assert_eq!(reply.error(), "that request is approved for itself only");
        assert!(!asked.is_finished());
        let reply = page(&tailnet, &d, "/deny", json!({ "id": id })).await;
        assert_eq!(reply.status, StatusCode::OK);
        asked.await.unwrap();

        let ending = json!({ "project": "widget", "env": "dev" });
        let reply = page(&tailnet, &d, "/standing/end", ending.clone()).await;
        assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
        let reply = send(TABLET, &tailnet, &d, post("/standing/end", &ending)).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN);
        let reply = page(
            &tailnet,
            &d,
            "/standing/end",
            json!({ "project": "not a name" }),
        )
        .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    }

    /// The phone pairs over the page with a passkey it makes, is shown a
    /// waiting request in the app's words, and approves it with that
    /// passkey's signature.
    #[tokio::test]
    async fn the_phone_pairs_and_approves_over_the_page() {
        let tmp = tempfile::tempdir().unwrap();
        let tailnet = tailnet();
        let d = daemon(tmp.path(), &tailnet).await;

        pairing(&d).await;
        let before = state(&tailnet, &d).await;
        assert_eq!(before["machine"], "self");
        assert_eq!(before["paired"], false);
        assert!(before["pairing"].as_u64().unwrap() > 0, "{before}");
        assert_eq!(before["prompts"], json!([]));
        // Nothing to approve with until it is paired.
        let reply = page(&tailnet, &d, "/approve/begin", json!({ "id": 1 })).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN);

        let begin = page(&tailnet, &d, "/pair/begin", json!({})).await.said();
        // The passkey is named for the phone that holds it.
        assert_eq!(begin["name"], "phone");
        let challenge = webauthn::decode(begin["challenge"].as_str().unwrap()).unwrap();
        let passkey = FakePasskey::new();
        // A passkey made on another page is not taken.
        let other = Site::new("self.example.ts.net", 443);
        let (client, auth) = passkey.create(&other, &challenge);
        let made = |client: &[u8], auth: &[u8]| {
            json!({
                "client_data": webauthn::encode(client),
                "auth_data": webauthn::encode(auth),
            })
        };
        let reply = page(&tailnet, &d, "/pair/finish", made(&client, &auth)).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN);
        assert_eq!(state(&tailnet, &d).await["paired"], false);
        let begin = page(&tailnet, &d, "/pair/begin", json!({})).await.said();
        let challenge = webauthn::decode(begin["challenge"].as_str().unwrap()).unwrap();
        let (client, auth) = passkey.create(&at().site, &challenge);
        let reply = page(&tailnet, &d, "/pair/finish", made(&client, &auth)).await;
        assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
        assert_eq!(reply.said(), json!({}));
        // Once: the pairing is over.
        let reply = page(&tailnet, &d, "/pair/begin", json!({})).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN);

        let now = state(&tailnet, &d).await;
        assert_eq!(now["paired"], true);
        assert_eq!(now["pairing"], Value::Null);
        assert_eq!(now["recent"], json!([]));

        // The page's question is held back until something changes: here,
        // a request starts waiting.
        let seen = json!({ "seen": now["version"] });
        let (held, (asked, id)) = tokio::join!(page(&tailnet, &d, "/state", seen), asking(&d));
        let held = held.said();
        assert_ne!(held["version"], now["version"]);
        let [prompt] = &held["prompts"].as_array().unwrap()[..] else {
            panic!("{held}")
        };
        assert_eq!(prompt["id"], id);
        assert_eq!(prompt["project"], "widget");
        assert_eq!(prompt["env"], "dev");
        assert_eq!(prompt["keys"], json!(["S"]));
        assert_eq!(prompt["here"], true);
        assert!(prompt["left"].as_u64().unwrap() > 0, "{prompt}");
        let words = &prompt["words"];
        assert!(
            words["title"]
                .as_str()
                .unwrap()
                .contains("sensitive values of widget/dev"),
            "{words}"
        );
        for said in [
            "command_label",
            "command",
            "wants",
            "asked_label",
            "who",
            "trust",
        ] {
            assert!(!words[said].as_str().unwrap().is_empty(), "{said}: {words}");
        }
        // What the page is headed with, and its one line of what is asked.
        assert_eq!(
            words["question"],
            "Hand sensitive values of widget/dev to this command?"
        );
        assert_eq!(words["summary"], "1 key marked sensitive: S");
        assert_eq!(words["command_plain"], true);
        // Names only: no value is on the page.
        assert!(!held.to_string().contains("\"v\""), "{held}");

        // Without a challenge of its own, a signature is nothing; a
        // request that does not wait has none.
        let reply = page(&tailnet, &d, "/approve/begin", json!({ "id": id + 1 })).await;
        assert_eq!(reply.status, StatusCode::GONE);
        let mut signed = approval(&tailnet, &d, &passkey, id).await;
        let good = signed["signature"].take();
        signed["signature"] = json!(webauthn::encode(b"not a signature"));
        let reply = page(&tailnet, &d, "/approve/finish", signed.clone()).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN);
        // The challenge is spent with it.
        signed["signature"] = good;
        let reply = page(&tailnet, &d, "/approve/finish", signed).await;
        assert_eq!(reply.status, StatusCode::CONFLICT);
        assert!(!asked.is_finished());

        let signed = approval(&tailnet, &d, &passkey, id).await;
        let reply = page(&tailnet, &d, "/approve/finish", signed.clone()).await;
        assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
        let r = asked.await.unwrap();
        assert!(matches!(r, Response::Value { .. }), "{r:?}");

        let after = state(&tailnet, &d).await;
        assert_eq!(after["prompts"], json!([]));
        let last = &after["recent"][0];
        assert_eq!(
            (&last["id"], &last["outcome"], &last["by"]),
            (&json!(id), &json!("approved"), &json!("phone"))
        );
        assert!(after["now"].as_u64().unwrap() >= last["time"].as_u64().unwrap());
        // Answered: neither again.
        let reply = page(&tailnet, &d, "/approve/finish", signed).await;
        assert_eq!(reply.status, StatusCode::CONFLICT);
        let reply = page(&tailnet, &d, "/deny", json!({ "id": id })).await;
        assert_eq!(reply.status, StatusCode::GONE);

        // The tablet, on the same tailnet, sees and answers nothing.
        let (asked, id) = asking(&d).await;
        let reply = send(TABLET, &tailnet, &d, post("/deny", &json!({ "id": id }))).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN);
        assert!(!asked.is_finished());
        let reply = page(&tailnet, &d, "/deny", json!({ "id": id })).await;
        assert_eq!(reply.status, StatusCode::OK);
        assert!(matches!(asked.await.unwrap(), Response::Error(_)));
        let after = state(&tailnet, &d).await;
        assert_eq!(after["recent"][0]["outcome"], "denied");
        assert_eq!(after["recent"][0]["by"], "phone");

        // Unpaired on this machine, the phone gets nothing more.
        let r = d
            .handle(Request::PhoneUnpair {
                passphrase: pw("pw"),
            })
            .await;
        assert!(matches!(r, Response::Store { .. }), "{r:?}");
        let reply = page(&tailnet, &d, "/state", json!({})).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN);
    }

    /// The page is served where tailscaled says this machine is, under
    /// the name it has a certificate for, and only while a phone is
    /// paired or being paired and the daemon unlocked.
    #[tokio::test]
    async fn the_page_is_wanted_only_for_a_phone() {
        let tmp = tempfile::tempdir().unwrap();
        let tailnet = tailnet();
        let d = daemon(tmp.path(), &tailnet).await;
        assert_eq!(wanted(&d, tailnet.as_ref()).await, Err(None));

        pairing(&d).await;
        let want = wanted(&d, tailnet.as_ref()).await.unwrap();
        assert_eq!(want, at());
        assert_eq!(want.host(), HOST);
        assert_eq!(want.site.origin, ORIGIN);
        assert_eq!(want.machine(), "self");

        tailnet.set_peers("Stopped", &[]);
        let why = wanted(&d, tailnet.as_ref()).await.unwrap_err().unwrap();
        assert_eq!(why, "Tailscale is Stopped, not Running");
        tailnet.clear();
        assert!(wanted(&d, tailnet.as_ref()).await.unwrap_err().is_some());

        d.lock();
        assert_eq!(wanted(&d, tailnet.as_ref()).await, Err(None));
    }

    /// A browser reaches the page over TLS with the certificate
    /// tailscaled gives, key first, and is then named by its address.
    #[tokio::test]
    async fn the_page_is_served_over_tls_with_tailscaleds_certificate() {
        use rustls::pki_types::ServerName;
        use tokio::net::TcpSocket;

        let tmp = tempfile::tempdir().unwrap();
        let tailnet = tailnet();
        let d = daemon(tmp.path(), &tailnet).await;
        pairing(&d).await;
        tailnet.set(
            "/localapi/v0/cert/self.example.ts.net?type=pair",
            Ok(PEM.to_vec()),
        );
        let tls = certified(tailnet.as_ref(), &at()).await.unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = listener.local_addr().unwrap();
        let (_tls, certs) = watch::channel(tls);
        let api: Arc<dyn LocalApi> = tailnet.clone();
        let task = tokio::spawn(accept(
            listener,
            certs,
            Arc::new(at()),
            api,
            Arc::new(cfg()),
            d.clone(),
        ));

        // The browser trusts the certificate's issuer: here, itself.
        let mut roots = rustls::RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(PEM) {
            roots.add(cert.unwrap()).unwrap();
        }
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

        let from = |tailnet: &Arc<FakeTailnet>, node: &'static str| {
            let (tailnet, connector) = (tailnet.clone(), connector.clone());
            async move {
                let socket = TcpSocket::new_v4().unwrap();
                socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
                tailnet.set_whois(
                    socket.local_addr().unwrap(),
                    Ok((node, "a-machine", "dev@example.com", &[])),
                );
                let tcp = socket.connect(server).await.unwrap();
                let name = ServerName::try_from("self.example.ts.net").unwrap();
                let stream = connector.connect(name, tcp).await.unwrap();
                assert_eq!(stream.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
                talk(stream, get("/")).await
            }
        };
        let reply = from(&tailnet, "nPHONE").await;
        assert_eq!(reply.status, StatusCode::OK);
        assert!(String::from_utf8_lossy(&reply.body).contains("<html"));
        let reply = from(&tailnet, "nTABLET").await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN);
        task.abort();

        // What tailscaled gives must hold a key and a certificate.
        let pem = std::str::from_utf8(PEM).unwrap();
        let (key, cert) = pem.split_at(pem.find("-----BEGIN CERTIFICATE").unwrap());
        for (part, problem) in [(key, "its certificates"), (cert, "its private key")] {
            tailnet.set(
                "/localapi/v0/cert/self.example.ts.net?type=pair",
                Ok(part.as_bytes().to_vec()),
            );
            let Err(why) = certified(tailnet.as_ref(), &at()).await else {
                panic!("{problem}")
            };
            assert!(
                why.starts_with(
                    "the HTTPS certificate Tailscale gave for self.example.ts.net cannot be used"
                ),
                "{why}"
            );
        }
    }

    /// The supervisor says why the page is not served: tailscaled gives
    /// no certificate, or, with one, the tailnet address is not this
    /// machine's, as in this test. It binds exactly that address.
    #[tokio::test]
    async fn the_supervisor_reports_why_the_page_is_not_served() {
        async fn problem(d: &Daemon, tailnet: &Arc<FakeTailnet>) -> String {
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
            let status = || async {
                let Response::Status(r) = d.handle(Request::Status { facts: None }).await else {
                    panic!("status");
                };
                r.phone.unwrap()
            };
            let mut seen = None;
            for _ in 0..200 {
                tokio::time::sleep(Duration::from_millis(5)).await;
                seen = status().await.problem;
                if seen.is_some() {
                    break;
                }
            }
            assert_eq!(status().await.url, None);
            stop.send(()).unwrap();
            task.await.unwrap();
            assert_eq!(status().await.problem, None);
            seen.unwrap()
        }

        let tmp = tempfile::tempdir().unwrap();
        let tailnet = tailnet();
        let d = daemon(tmp.path(), &tailnet).await;
        pairing(&d).await;
        let why = problem(&d, &tailnet).await;
        assert!(
            why.starts_with("Tailscale gives no HTTPS certificate for self.example.ts.net"),
            "{why}"
        );
        tailnet.set(
            "/localapi/v0/cert/self.example.ts.net?type=pair",
            Ok(PEM.to_vec()),
        );
        let why = problem(&d, &tailnet).await;
        assert!(
            why.starts_with("cannot listen on 100.64.0.1:47318"),
            "{why}"
        );
    }
}
