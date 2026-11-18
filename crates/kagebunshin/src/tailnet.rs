//! The local Tailscale daemon, as the remote endpoint asks it: whether
//! this machine is on its tailnet and at which address, and who the peer
//! of a connection is.
//!
//! Both come from tailscaled's `LocalAPI`, plain HTTP on a local socket:
//! `GET /localapi/v0/status` and `GET /localapi/v0/whois?addr=<ip:port>`.
//! Only a 200 counts; anything else (no socket, a refusal, a timeout, a
//! peer tailscaled does not know) is an error, and every caller treats an
//! error as "no": no listener, no identity, no access.
//!
//! Where the `LocalAPI` is depends on the platform:
//!
//! - Linux: the Unix socket `/run/tailscale/tailscaled.sock` (or under
//!   `/var/run`).
//! - macOS, the App Store app: TCP on 127.0.0.1, with the port and a token
//!   in the name of a `sameuserproof-<port>-<token>` file the `IPNExtension`
//!   process holds open, found with `lsof`.
//! - macOS, the standalone app: TCP on 127.0.0.1, the port in the target
//!   of the `/Library/Tailscale/ipnport` symlink and the token in
//!   `/Library/Tailscale/sameuserproof-<port>`.
//! - macOS, the open-source tailscaled: the Unix socket
//!   `/var/run/tailscaled.socket`.
//!
//! On TCP the token goes as Basic auth with an empty user. These are the
//! places Tailscale's own CLI looks, in the same order.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};
use zeroize::Zeroizing;

/// How long one `LocalAPI` request may take, connecting included.
pub const LOCALAPI_TIMEOUT: Duration = Duration::from_secs(3);

/// The most of a `LocalAPI` reply read; `/status` lists every peer.
const MAX_REPLY: usize = 16 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum TailnetError {
    #[error("cannot find the Tailscale daemon's local API")]
    NotFound,
    #[error("the Tailscale daemon's local API: {0}")]
    Io(#[from] std::io::Error),
    #[error("the Tailscale daemon's local API did not answer within {LOCALAPI_TIMEOUT:?}")]
    Timeout,
    #[error("the Tailscale daemon's local API answered {0}")]
    Status(u16),
    #[error("the Tailscale daemon's local API gave a reply that does not parse: {0}")]
    Parse(String),
}

/// A `LocalAPI`: the body of a `GET` that answered 200. A trait so tests can
/// stand in for tailscaled.
#[async_trait]
pub trait LocalApi: Send + Sync {
    async fn get(&self, path: &str) -> Result<Vec<u8>, TailnetError>;
}

/// This machine as tailscaled reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfStatus {
    /// `BackendState`: `Running` once on the tailnet.
    pub state: String,
    /// The node's stable id.
    pub node: String,
    /// Its `MagicDNS` name, with the dot at its end; empty without one.
    pub dns_name: String,
    pub ips: Vec<IpAddr>,
    pub peers: Vec<Peer>,
}

impl SelfStatus {
    pub fn running(&self) -> bool {
        self.state == "Running"
    }

    /// The address the remote endpoint listens on: this machine's IPv4
    /// tailnet address.
    pub fn listen_ip(&self) -> Option<IpAddr> {
        self.ips.iter().copied().find(IpAddr::is_ipv4)
    }

    /// The peers named `machine`: by the first label of their `MagicDNS`
    /// name or the full name, or by host name, ignoring case.
    pub fn peers_named(&self, machine: &str) -> Vec<&Peer> {
        let want = machine.trim_end_matches('.').to_ascii_lowercase();
        let by_dns: Vec<&Peer> = self
            .peers
            .iter()
            .filter(|p| {
                let dns = p.dns_name.trim_end_matches('.').to_ascii_lowercase();
                dns == want || dns.split('.').next() == Some(want.as_str())
            })
            .collect();
        if !by_dns.is_empty() {
            return by_dns;
        }
        self.peers
            .iter()
            .filter(|p| p.host_name.eq_ignore_ascii_case(&want))
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub node: String,
    /// The first label of its `MagicDNS` name.
    pub machine: String,
    pub dns_name: String,
    pub host_name: String,
    pub ips: Vec<IpAddr>,
}

impl Peer {
    /// The address to reach its remote endpoint on: its IPv4 tailnet
    /// address, as this machine's endpoint listens on.
    pub fn ip(&self) -> Option<IpAddr> {
        self.ips.iter().copied().find(IpAddr::is_ipv4)
    }
}

/// Who the peer of a connection is, as tailscaled says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The node's stable id.
    pub node: String,
    /// The first label of its `MagicDNS` name.
    pub machine: String,
    /// The login of the user who owns it; `tagged-devices` for a tagged one.
    pub user: String,
    pub tags: Vec<String>,
}

pub async fn status(api: &dyn LocalApi) -> Result<SelfStatus, TailnetError> {
    parse_status(&api.get("/localapi/v0/status").await?)
}

pub async fn whois(api: &dyn LocalApi, peer: SocketAddr) -> Result<Identity, TailnetError> {
    // A SocketAddr prints as `1.2.3.4:5` or `[::1]:5`; only the brackets
    // need escaping in a query.
    let addr = peer
        .to_string()
        .replace('[', "%5B")
        .replace(']', "%5D")
        .replace(':', "%3A");
    parse_whois(&api.get(&format!("/localapi/v0/whois?addr={addr}")).await?)
}

fn first_label(dns: &str) -> String {
    dns.split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
}

fn parse_status(body: &[u8]) -> Result<SelfStatus, TailnetError> {
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Raw {
        backend_state: String,
        #[serde(rename = "Self")]
        me: Option<RawNode>,
        #[serde(default)]
        peer: Option<std::collections::BTreeMap<String, RawNode>>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct RawNode {
        #[serde(rename = "ID", default)]
        id: String,
        #[serde(default)]
        host_name: String,
        #[serde(rename = "DNSName", default)]
        dns_name: String,
        #[serde(default)]
        tailscale_i_ps: Option<Vec<IpAddr>>,
    }
    let raw: Raw = serde_json::from_slice(body).map_err(|e| TailnetError::Parse(e.to_string()))?;
    let me = raw.me;
    let peers = raw
        .peer
        .unwrap_or_default()
        .into_values()
        .filter(|p| !p.id.is_empty())
        .map(|p| Peer {
            machine: first_label(&p.dns_name),
            node: p.id,
            dns_name: p.dns_name,
            host_name: p.host_name,
            ips: p.tailscale_i_ps.unwrap_or_default(),
        })
        .collect();
    Ok(SelfStatus {
        state: raw.backend_state,
        node: me.as_ref().map(|m| m.id.clone()).unwrap_or_default(),
        dns_name: me.as_ref().map(|m| m.dns_name.clone()).unwrap_or_default(),
        ips: me.and_then(|m| m.tailscale_i_ps).unwrap_or_default(),
        peers,
    })
}

fn parse_whois(body: &[u8]) -> Result<Identity, TailnetError> {
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Raw {
        node: RawNode,
        user_profile: RawUser,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct RawNode {
        #[serde(rename = "StableID")]
        stable_id: String,
        #[serde(default)]
        name: String,
        #[serde(default)]
        computed_name: String,
        #[serde(default)]
        tags: Option<Vec<String>>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct RawUser {
        login_name: String,
    }
    let raw: Raw = serde_json::from_slice(body).map_err(|e| TailnetError::Parse(e.to_string()))?;
    let machine = match first_label(&raw.node.name) {
        m if m.is_empty() => raw.node.computed_name.to_ascii_lowercase(),
        m => m,
    };
    if raw.node.stable_id.is_empty() || machine.is_empty() {
        return Err(TailnetError::Parse(
            "the peer has no node id or name".into(),
        ));
    }
    Ok(Identity {
        node: raw.node.stable_id,
        machine,
        user: raw.user_profile.login_name,
        tags: raw.node.tags.unwrap_or_default(),
    })
}

/// Where a `LocalAPI` is.
#[derive(Clone, PartialEq, Eq)]
enum Endpoint {
    Unix(PathBuf),
    /// 127.0.0.1, with Basic auth.
    Tcp {
        port: u16,
        token: Zeroizing<String>,
    },
}

/// tailscaled on this machine. Remembers where it found the `LocalAPI`, and
/// looks again when that stops answering.
#[derive(Default)]
pub struct Tailscaled {
    found: Mutex<Option<Endpoint>>,
}

impl Tailscaled {
    pub fn new() -> Self {
        Self::default()
    }

    fn found(&self) -> std::sync::MutexGuard<'_, Option<Endpoint>> {
        self.found.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[async_trait]
impl LocalApi for Tailscaled {
    async fn get(&self, path: &str) -> Result<Vec<u8>, TailnetError> {
        let known = self.found().clone();
        if let Some(endpoint) = known {
            match request(&endpoint, path).await {
                // Only a failure to reach it means it may have moved.
                Err(TailnetError::Io(_) | TailnetError::Timeout) => {}
                other => return other,
            }
        }
        let endpoint = discover().await.ok_or(TailnetError::NotFound)?;
        *self.found() = Some(endpoint.clone());
        request(&endpoint, path).await
    }
}

async fn discover() -> Option<Endpoint> {
    if cfg!(target_os = "macos") {
        if let Some(e) = app_store_endpoint().await {
            return Some(e);
        }
        if let Some(e) = standalone_endpoint(Path::new("/Library/Tailscale")) {
            return Some(e);
        }
        return unix_endpoint(&["/var/run/tailscaled.socket"]);
    }
    unix_endpoint(&[
        "/run/tailscale/tailscaled.sock",
        "/var/run/tailscale/tailscaled.sock",
    ])
}

fn unix_endpoint(paths: &[&str]) -> Option<Endpoint> {
    use std::os::unix::fs::FileTypeExt;
    paths
        .iter()
        .map(PathBuf::from)
        .find(|p| std::fs::metadata(p).is_ok_and(|m| m.file_type().is_socket()))
        .map(Endpoint::Unix)
}

/// The standalone macOS app: `<dir>/ipnport` links to the port, and
/// `<dir>/sameuserproof-<port>` holds the token.
fn standalone_endpoint(dir: &Path) -> Option<Endpoint> {
    let target = std::fs::read_link(dir.join("ipnport")).ok()?;
    let port_str = target.to_str()?;
    let port: u16 = port_str.parse().ok()?;
    let token = std::fs::read_to_string(dir.join(format!("sameuserproof-{port_str}"))).ok()?;
    let token = Zeroizing::new(token.trim().to_owned());
    (!token.is_empty()).then_some(Endpoint::Tcp { port, token })
}

/// The App Store macOS app: the port and token are in the name of a file
/// the `IPNExtension` process of this user holds open.
async fn app_store_endpoint() -> Option<Endpoint> {
    let out = tokio::time::timeout(
        LOCALAPI_TIMEOUT,
        tokio::process::Command::new("lsof")
            .args([
                "-n",
                "-a",
                &format!("-u{}", crate::sys::effective_uid()),
                "-c",
                "IPNExtension",
                "-F",
            ])
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    parse_lsof(&String::from_utf8_lossy(&out.stdout))
}

fn parse_lsof(out: &str) -> Option<Endpoint> {
    const MARK: &str = ".tailscale.ipn.macos/sameuserproof-";
    out.lines().find_map(|line| {
        let (_, after) = line.split_once(MARK)?;
        let (port, token) = after.split_once('-')?;
        let port = port.parse().ok()?;
        (!token.is_empty()).then(|| Endpoint::Tcp {
            port,
            token: Zeroizing::new(token.to_owned()),
        })
    })
}

async fn request(endpoint: &Endpoint, path: &str) -> Result<Vec<u8>, TailnetError> {
    let exchange = async {
        match endpoint {
            Endpoint::Unix(p) => exchange(UnixStream::connect(p).await?, path, None).await,
            Endpoint::Tcp { port, token } => {
                let stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, *port)).await?;
                exchange(stream, path, Some(token)).await
            }
        }
    };
    tokio::time::timeout(LOCALAPI_TIMEOUT, exchange)
        .await
        .map_err(|_| TailnetError::Timeout)?
}

/// One HTTP/1.0 `GET`, read to the end. No `Origin` or `Referer`: the
/// `LocalAPI` refuses a request that carries either.
async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    path: &str,
    token: Option<&Zeroizing<String>>,
) -> Result<Vec<u8>, TailnetError> {
    let mut head = Zeroizing::new(format!(
        "GET {path} HTTP/1.0\r\nHost: local-tailscaled.sock\r\n"
    ));
    if let Some(token) = token {
        head.push_str("Authorization: Basic ");
        head.push_str(&base64(format!(":{}", token.as_str()).as_bytes()));
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await?;
    stream.flush().await?;
    let mut reply = Vec::new();
    (&mut stream)
        .take(MAX_REPLY as u64 + 1)
        .read_to_end(&mut reply)
        .await?;
    if reply.len() > MAX_REPLY {
        return Err(TailnetError::Parse("the reply is too large".into()));
    }
    parse_reply(reply)
}

fn parse_reply(mut reply: Vec<u8>) -> Result<Vec<u8>, TailnetError> {
    let end = reply
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| TailnetError::Parse("no end of headers".into()))?;
    let head = String::from_utf8_lossy(&reply[..end]);
    let status_line = head.lines().next().unwrap_or_default();
    let code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| TailnetError::Parse("no status line".into()))?;
    if code != 200 {
        return Err(TailnetError::Status(code));
    }
    if head
        .lines()
        .any(|l| l.to_ascii_lowercase().starts_with("transfer-encoding:"))
    {
        return Err(TailnetError::Parse("a chunked reply".into()));
    }
    Ok(reply.split_off(end + 4))
}

/// Standard base64, padded.
fn base64(bytes: &[u8]) -> Zeroizing<String> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Zeroizing::new(String::with_capacity(bytes.len().div_ceil(3) * 4));
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i)) as usize & 63] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A stand-in for tailscaled, for tests: canned replies by path prefix.
#[cfg(test)]
pub mod fake {
    use super::*;
    use std::collections::BTreeMap;

    #[derive(Default)]
    pub struct FakeTailnet {
        replies: Mutex<BTreeMap<String, Result<Vec<u8>, u16>>>,
    }

    impl FakeTailnet {
        /// This machine, `self`, running at 100.64.0.1, with the given peers.
        pub fn running(peers: &[(&str, &str)]) -> Self {
            let fake = Self::default();
            fake.set_status("Running", peers);
            fake
        }

        pub fn set_status(&self, state: &str, peers: &[(&str, &str)]) {
            let peers: serde_json::Map<String, serde_json::Value> = peers
                .iter()
                .map(|(node, name)| {
                    (
                        format!("nodekey:{node}"),
                        serde_json::json!({
                            "ID": node,
                            "HostName": name,
                            "DNSName": format!("{name}.example.ts.net."),
                            "TailscaleIPs": ["100.64.0.9"],
                        }),
                    )
                })
                .collect();
            let body = serde_json::json!({
                "BackendState": state,
                "Self": {
                    "ID": "nSELF",
                    "HostName": "self",
                    "DNSName": "self.example.ts.net.",
                    "TailscaleIPs": ["100.64.0.1", "fd7a:115c:a1e0::1"],
                },
                "Peer": peers,
            });
            self.set("/localapi/v0/status", Ok(body.to_string().into_bytes()));
        }

        /// What `whois` says of `peer`.
        pub fn set_whois(&self, peer: SocketAddr, reply: Result<(&str, &str, &str, &[&str]), u16>) {
            let path = format!(
                "/localapi/v0/whois?addr={}",
                peer.to_string().replace(':', "%3A")
            );
            let reply = reply.map(|(node, name, user, tags)| {
                serde_json::json!({
                    "Node": {
                        "StableID": node,
                        "Name": format!("{name}.example.ts.net."),
                        "ComputedName": name,
                        "Tags": if tags.is_empty() { serde_json::Value::Null } else { serde_json::json!(tags) },
                    },
                    "UserProfile": { "LoginName": user },
                })
                .to_string()
                .into_bytes()
            });
            self.set(&path, reply);
        }

        pub fn set(&self, path: &str, reply: Result<Vec<u8>, u16>) {
            self.replies.lock().unwrap().insert(path.to_owned(), reply);
        }

        /// tailscaled goes away: every request fails.
        pub fn clear(&self) {
            self.replies.lock().unwrap().clear();
        }
    }

    #[async_trait]
    impl LocalApi for FakeTailnet {
        async fn get(&self, path: &str) -> Result<Vec<u8>, TailnetError> {
            match self.replies.lock().unwrap().get(path) {
                Some(Ok(body)) => Ok(body.clone()),
                Some(Err(code)) => Err(TailnetError::Status(*code)),
                None => Err(TailnetError::NotFound),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::FakeTailnet;
    use super::*;

    #[test]
    fn base64_matches_the_standard() {
        assert_eq!(base64(b"").as_str(), "");
        assert_eq!(base64(b":").as_str(), "Og==");
        assert_eq!(base64(b":ab").as_str(), "OmFi");
        assert_eq!(base64(b":abcd").as_str(), "OmFiY2Q=");
        assert_eq!(base64(b"hello world").as_str(), "aGVsbG8gd29ybGQ=");
    }

    #[test]
    fn only_a_200_is_a_reply() {
        let ok = b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{}".to_vec();
        assert_eq!(parse_reply(ok).unwrap(), b"{}");
        for code in [400, 403, 404, 500] {
            let r = format!("HTTP/1.0 {code} X\r\n\r\nno").into_bytes();
            assert!(matches!(parse_reply(r), Err(TailnetError::Status(c)) if c == code));
        }
        assert!(parse_reply(b"garbage".to_vec()).is_err());
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}".to_vec();
        assert!(parse_reply(chunked).is_err());
    }

    #[test]
    fn status_parses_tailscaleds_shape() {
        let body = br#"{"Version":"1.102.3","BackendState":"Running",
            "TailscaleIPs":["100.64.0.1","fd7a:115c:a1e0::1"],
            "Self":{"ID":"nW765","HostName":"box","DNSName":"box.tail5.ts.net.",
                    "TailscaleIPs":["100.64.0.1","fd7a:115c:a1e0::1"]},
            "Peer":{"nodekey:ab":{"ID":"nMAC","HostName":"Air","DNSName":"laptop-air.tail5.ts.net.",
                    "TailscaleIPs":["100.70.0.2"]}}}"#;
        let st = parse_status(body).unwrap();
        assert!(st.running());
        assert_eq!(st.node, "nW765");
        assert_eq!(st.listen_ip(), Some("100.64.0.1".parse().unwrap()));
        assert_eq!(st.peers_named("laptop-air")[0].node, "nMAC");
        assert_eq!(st.peers_named("LAPTOP-AIR.tail5.ts.net.")[0].node, "nMAC");
        assert_eq!(st.peers_named("air")[0].node, "nMAC", "by host name");
        assert!(st.peers_named("box").is_empty(), "never this machine");

        let stopped = parse_status(br#"{"BackendState":"Stopped","Self":null}"#).unwrap();
        assert!(!stopped.running());
        assert_eq!(stopped.listen_ip(), None);
    }

    #[test]
    fn whois_parses_tailscaleds_shape() {
        let body = br#"{"Node":{"ID":1,"StableID":"nMAC","Name":"laptop-air.tail5.ts.net.",
            "ComputedName":"laptop-air","Tags":["tag:ci"],"Addresses":["100.70.0.2/32"]},
            "UserProfile":{"ID":2,"LoginName":"tagged-devices","DisplayName":"Tagged Devices"},
            "CapMap":null}"#;
        let id = parse_whois(body).unwrap();
        assert_eq!(
            id,
            Identity {
                node: "nMAC".into(),
                machine: "laptop-air".into(),
                user: "tagged-devices".into(),
                tags: vec!["tag:ci".into()],
            }
        );
        assert!(
            parse_whois(br#"{"Node":{"StableID":""},"UserProfile":{"LoginName":"x"}}"#).is_err()
        );
        assert!(parse_whois(b"{}").is_err());
    }

    #[test]
    fn lsof_gives_the_app_stores_port_and_token() {
        let out = "p123\nfcwd\nn/\nf5\nn/Users/me/Library/Group Containers/\
                   io.tailscale.ipn.macos/sameuserproof-49152-abcdef0123\n";
        let Some(Endpoint::Tcp { port, token }) = parse_lsof(out) else {
            panic!("no endpoint");
        };
        assert_eq!((port, token.as_str()), (49152, "abcdef0123"));
        assert!(parse_lsof("p1\nn/tmp/other\n").is_none());
        assert!(parse_lsof("n/x.tailscale.ipn.macos/sameuserproof-notaport-t\n").is_none());
    }

    #[test]
    fn the_standalone_app_needs_a_port_and_a_token() {
        let dir = tempfile::tempdir().unwrap();
        assert!(standalone_endpoint(dir.path()).is_none());
        std::os::unix::fs::symlink("49200", dir.path().join("ipnport")).unwrap();
        assert!(standalone_endpoint(dir.path()).is_none(), "no token file");
        std::fs::write(dir.path().join("sameuserproof-49200"), "  \n").unwrap();
        assert!(standalone_endpoint(dir.path()).is_none(), "an empty token");
        std::fs::write(dir.path().join("sameuserproof-49200"), "tok\n").unwrap();
        let Some(Endpoint::Tcp { port, token }) = standalone_endpoint(dir.path()) else {
            panic!("no endpoint");
        };
        assert_eq!((port, token.as_str()), (49200, "tok"));
    }

    #[tokio::test]
    async fn the_request_has_no_origin_and_sends_the_token() {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let serve = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let n = server.read(&mut buf).await.unwrap();
            server
                .write_all(b"HTTP/1.0 200 OK\r\n\r\n{\"ok\":1}")
                .await
                .unwrap();
            drop(server);
            String::from_utf8(buf[..n].to_vec()).unwrap()
        });
        let token = Zeroizing::new("tok".to_owned());
        let body = exchange(client, "/localapi/v0/status", Some(&token))
            .await
            .unwrap();
        assert_eq!(body, b"{\"ok\":1}");
        let sent = serve.await.unwrap();
        assert!(sent.starts_with("GET /localapi/v0/status HTTP/1.0\r\n"));
        assert!(sent.contains("Host: local-tailscaled.sock\r\n"));
        assert!(sent.contains(&format!(
            "Authorization: Basic {}\r\n",
            base64(b":tok").as_str()
        )));
        let lower = sent.to_ascii_lowercase();
        assert!(!lower.contains("origin:") && !lower.contains("referer:"));
    }

    #[tokio::test]
    async fn whois_asks_for_the_peer_and_fails_closed() {
        let fake = FakeTailnet::running(&[]);
        let peer: SocketAddr = "100.64.0.9:5000".parse().unwrap();
        assert!(matches!(
            whois(&fake, peer).await,
            Err(TailnetError::NotFound)
        ));
        fake.set_whois(peer, Err(404));
        assert!(matches!(
            whois(&fake, peer).await,
            Err(TailnetError::Status(404))
        ));
        fake.set_whois(peer, Ok(("nB", "buildbox", "me@example.com", &[])));
        let id = whois(&fake, peer).await.unwrap();
        assert_eq!((id.node.as_str(), id.machine.as_str()), ("nB", "buildbox"));
    }
}
