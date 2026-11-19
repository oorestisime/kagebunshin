//! The part of Web Push the approval page needs: telling the paired phone,
//! through its browser's push service, that a request waits.
//!
//! A phone that allowed notifications gives the page a subscription: an
//! address at its browser's push service, a public key and a shared
//! secret. A message for it is encrypted to those (RFC 8291, the
//! `aes128gcm` content encoding of RFC 8188), so the push service carries
//! it without being able to read it, and is sent with a token signed by
//! this machine's own key (VAPID, RFC 8292), which is the key the phone
//! subscribed to: the push service takes messages for that subscription
//! from nobody else.
//!
//! The address is the one thing here that the phone chooses and this
//! machine then connects to, so only the push services of the browsers a
//! phone has are taken ([`SERVICES`]), over HTTPS on the usual port.
//!
//! What a message says is names: see `daemon::broker::phone`. The push
//! service learns that this machine sent that phone something, when, and
//! how long it was.

use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use aws_lc_rs::aead::{AES_128_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::agreement::{self, ECDH_P256, PrivateKey, UnparsedPublicKey};
use aws_lc_rs::hkdf::{self, HKDF_SHA256, Salt};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::{self, HeaderValue};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use zeroize::Zeroizing;

use crate::webauthn::{decode, encode};

/// The push services a subscription may be at: Apple's (Safari, and every
/// browser on an iPhone), Google's (Chrome and what is built on it),
/// Mozilla's and Microsoft's. A host is one of these or under one.
/// `jmt17.google.com` is the one Chromium builds that are not Chrome
/// subscribe at, and some Chrome on Android.
pub const SERVICES: [&str; 5] = [
    "push.apple.com",
    "fcm.googleapis.com",
    "jmt17.google.com",
    "push.services.mozilla.com",
    "notify.windows.com",
];

/// The longest address of a subscription: they are a few hundred bytes.
const MAX_ENDPOINT: usize = 2048;

/// An uncompressed P-256 point: `0x04`, x, y.
const KEY_LEN: usize = 65;

/// The secret a subscription shares with whoever may send to it.
const AUTH_LEN: usize = 16;

const SALT_LEN: usize = 16;

/// The record size a message says it has: one record, of at most this.
/// Every push service takes a body this long.
const RECORD: u32 = 4096;

/// What comes before the ciphertext: the salt, the record size, the
/// length of the sender's public key, and that key.
const HEAD: usize = SALT_LEN + 4 + 1 + KEY_LEN;

/// AES-GCM's tag.
const TAG: usize = 16;

/// The longest text of a message: what is left of a record after the
/// head, the byte that ends the text, and the tag.
pub const MAX_TEXT: usize = RECORD as usize - HEAD - 1 - TAG;

/// How long a token for a push service holds. They ask for a day at
/// most; one is made for each message.
const TOKEN_LIFE: Duration = Duration::from_hours(1);

/// Who sends: where a push service's operator finds whom to ask.
const SENDER: &str = env!("CARGO_PKG_REPOSITORY");

/// How long sending one message may take, connecting included.
const SEND_TIMEOUT: Duration = Duration::from_secs(20);

/// How much of what a push service says in refusing is kept.
const MAX_SAID: usize = 200;

/// Why a message cannot be made or a subscription taken. No message holds
/// anything the phone sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PushError {
    #[error(
        "its notifications do not come from a push service this knows (Apple's, Google's, \
         Mozilla's or Microsoft's)"
    )]
    Endpoint,
    #[error("what the page sent is not what a browser gives for notifications")]
    Keys,
    #[error("the notification is too long to send")]
    TooLong,
    #[error("this machine's key for notifications cannot be used")]
    Key,
    #[error("the notification cannot be encrypted")]
    Crypto,
}

/// Where a phone's browser takes messages for it, as the page gave it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subscription {
    /// At the push service; whoever knows it and holds the key the phone
    /// subscribed to can send there.
    endpoint: String,
    /// The phone's public key for messages, base64url.
    p256dh: String,
    /// The secret it shares with the sender, base64url.
    auth: String,
}

impl fmt::Debug for Subscription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Subscription")
            .field("service", &self.service())
            .finish_non_exhaustive()
    }
}

impl Subscription {
    /// What the page gave, if it is what a browser gives and the address
    /// is at a push service this knows.
    pub fn new(endpoint: &str, p256dh: &str, auth: &str) -> Result<Self, PushError> {
        place(endpoint)?;
        let key = decode(p256dh).ok_or(PushError::Keys)?;
        if key.len() != KEY_LEN || key[0] != 0x04 {
            return Err(PushError::Keys);
        }
        if decode(auth).ok_or(PushError::Keys)?.len() != AUTH_LEN {
            return Err(PushError::Keys);
        }
        Ok(Self {
            endpoint: endpoint.to_owned(),
            p256dh: p256dh.to_owned(),
            auth: auth.to_owned(),
        })
    }

    /// The host of its push service; empty for one that was not checked.
    pub fn service(&self) -> String {
        place(&self.endpoint)
            .map(|(host, _)| host)
            .unwrap_or_default()
    }
}

/// The host and the path of a subscription's address, if it is at a push
/// service this knows.
fn place(endpoint: &str) -> Result<(String, String), PushError> {
    if endpoint.len() > MAX_ENDPOINT {
        return Err(PushError::Endpoint);
    }
    let uri: hyper::Uri = endpoint.parse().map_err(|_| PushError::Endpoint)?;
    let authority = uri.authority().ok_or(PushError::Endpoint)?;
    if uri.scheme_str() != Some("https")
        || !matches!(authority.port_u16(), None | Some(443))
        || authority.as_str().contains('@')
    {
        return Err(PushError::Endpoint);
    }
    let host = authority.host().to_ascii_lowercase();
    let known = SERVICES.iter().any(|service| {
        host.strip_suffix(service)
            .is_some_and(|under| under.is_empty() || under.ends_with('.'))
    });
    if !known {
        return Err(PushError::Endpoint);
    }
    let path = uri
        .path_and_query()
        .map_or("/", hyper::http::uri::PathAndQuery::as_str);
    Ok((host, path.to_owned()))
}

/// This machine's key for push messages: the one a phone subscribes to,
/// and the only one its push service then takes messages from.
pub struct Vapid {
    pair: EcdsaKeyPair,
}

impl fmt::Debug for Vapid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vapid").finish_non_exhaustive()
    }
}

impl Vapid {
    /// A new key, and what [`Self::from_pkcs8`] reads it from.
    pub fn generate() -> Result<(Self, Zeroizing<Vec<u8>>), PushError> {
        let pair =
            EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).map_err(|_| PushError::Key)?;
        let written = pair.to_pkcs8v1().map_err(|_| PushError::Key)?;
        let written = Zeroizing::new(written.as_ref().to_vec());
        Ok((Self { pair }, written))
    }

    pub fn from_pkcs8(written: &[u8]) -> Result<Self, PushError> {
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, written)
            .map(|pair| Self { pair })
            .map_err(|_| PushError::Key)
    }

    /// The public half, base64url: what a phone subscribes to.
    pub fn public(&self) -> String {
        encode(self.pair.public_key().as_ref())
    }

    /// What a message to the push service at `audience` is authorized
    /// with, at `now` (Unix seconds): a token saying whom it is for, until
    /// when and who sends, signed by this key, then the key.
    fn authorization(&self, audience: &str, now: u64) -> Result<String, PushError> {
        let claims = serde_json::json!({
            "aud": audience,
            "exp": now + TOKEN_LIFE.as_secs(),
            "sub": SENDER,
        });
        let signed = format!(
            "{}.{}",
            encode(br#"{"typ":"JWT","alg":"ES256"}"#),
            encode(claims.to_string().as_bytes())
        );
        let signature = self
            .pair
            .sign(&SystemRandom::new(), signed.as_bytes())
            .map_err(|_| PushError::Key)?;
        Ok(format!(
            "vapid t={signed}.{}, k={}",
            encode(signature.as_ref()),
            self.public()
        ))
    }
}

/// A push message as it is sent: where, with what, and its body.
#[derive(Clone, PartialEq, Eq)]
pub struct Message {
    /// The push service.
    pub host: String,
    /// The subscription there.
    pub path: String,
    pub authorization: String,
    /// The seconds the push service keeps it for a phone it cannot reach.
    pub ttl: u64,
    /// The text, encrypted to the subscription.
    pub body: Vec<u8>,
}

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Message")
            .field("host", &self.host)
            .field("ttl", &self.ttl)
            .field("len", &self.body.len())
            .finish_non_exhaustive()
    }
}

impl Message {
    /// `text` for `to`, signed with `key` at `now` (Unix seconds), kept
    /// by the push service for `ttl` if the phone cannot be reached.
    pub fn new(
        key: &Vapid,
        to: &Subscription,
        text: &[u8],
        ttl: Duration,
        now: u64,
    ) -> Result<Self, PushError> {
        let (host, path) = place(&to.endpoint)?;
        let phone = decode(&to.p256dh).ok_or(PushError::Keys)?;
        let auth = Zeroizing::new(decode(&to.auth).ok_or(PushError::Keys)?);
        // A key and a salt of its own for each message.
        let sender = PrivateKey::generate(&ECDH_P256).map_err(|_| PushError::Crypto)?;
        let mut salt = [0u8; SALT_LEN];
        getrandom::fill(&mut salt).map_err(|_| PushError::Crypto)?;
        Ok(Self {
            authorization: key.authorization(&format!("https://{host}"), now)?,
            body: seal(&sender, &salt, &phone, &auth, text)?,
            ttl: ttl.as_secs(),
            host,
            path,
        })
    }
}

/// How many bytes of key are derived.
struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// HKDF with SHA-256: `N` bytes from `secret`, salted, for `info`.
fn derive<const N: usize>(
    salt: &[u8],
    secret: &[u8],
    info: &[u8],
) -> Result<Zeroizing<[u8; N]>, PushError> {
    let mut out = Zeroizing::new([0u8; N]);
    Salt::new(HKDF_SHA256, salt)
        .extract(secret)
        .expand(&[info], Len(N))
        .and_then(|key| key.fill(&mut *out))
        .map_err(|_| PushError::Crypto)?;
    Ok(out)
}

/// `text` as a push message's body (RFC 8291): encrypted for the
/// subscription whose public key is `phone` and whose secret is `auth`,
/// with the sender's key `sender` and `salt`, both made for this message.
fn seal(
    sender: &PrivateKey,
    salt: &[u8; SALT_LEN],
    phone: &[u8],
    auth: &[u8],
    text: &[u8],
) -> Result<Vec<u8>, PushError> {
    if text.len() > MAX_TEXT {
        return Err(PushError::TooLong);
    }
    let public = sender.compute_public_key().map_err(|_| PushError::Crypto)?;
    let public = public.as_ref();
    if public.len() != KEY_LEN {
        return Err(PushError::Crypto);
    }
    let mut info = Vec::with_capacity(14 + 2 * KEY_LEN);
    info.extend_from_slice(b"WebPush: info\0");
    info.extend_from_slice(phone);
    info.extend_from_slice(public);
    // What only the two ends can work out, bound to both their keys and
    // to the subscription's secret.
    let shared = agreement::agree(
        sender,
        UnparsedPublicKey::new(&ECDH_P256, phone),
        PushError::Keys,
        |secret| derive::<32>(auth, secret, &info),
    )?;
    let key = derive::<16>(salt, &*shared, b"Content-Encoding: aes128gcm\0")?;
    let nonce = derive::<12>(salt, &*shared, b"Content-Encoding: nonce\0")?;

    let mut body = Vec::with_capacity(HEAD + text.len() + 1 + TAG);
    body.extend_from_slice(salt);
    body.extend_from_slice(&RECORD.to_be_bytes());
    body.push(KEY_LEN as u8);
    body.extend_from_slice(public);
    // The one record: the text, then the byte that says it is the last.
    let mut record = Vec::with_capacity(text.len() + 1 + TAG);
    record.extend_from_slice(text);
    record.push(0x02);
    let key = UnboundKey::new(&AES_128_GCM, &*key).map_err(|_| PushError::Crypto)?;
    LessSafeKey::new(key)
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(*nonce),
            Aad::empty(),
            &mut record,
        )
        .map_err(|_| PushError::Crypto)?;
    body.extend_from_slice(&record);
    Ok(body)
}

/// What a push service did with a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    /// It took it, to pass on.
    Taken,
    /// It has no such subscription any more: the phone dropped it, or
    /// the page was removed from it.
    Gone,
    /// It refused, with this status, saying this.
    Refused(u16, String),
}

impl Delivery {
    fn of(status: u16, said: &[u8]) -> Self {
        match status {
            200..=299 => Self::Taken,
            404 | 410 => Self::Gone,
            _ => {
                let said: String = String::from_utf8_lossy(said)
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(MAX_SAID)
                    .collect();
                Self::Refused(status, said)
            }
        }
    }
}

/// What sends a message. A trait so tests can stand in for the push
/// services.
#[async_trait]
pub trait PushService: Send + Sync {
    /// What the push service did with it, or why it was not reached.
    async fn send(&self, message: Message) -> Result<Delivery, String>;
}

/// The push services, over HTTPS, checked against the certificate
/// authorities this machine trusts.
#[derive(Default)]
pub struct Https {
    /// Made at the first message: reading the authorities takes a moment.
    tls: tokio::sync::OnceCell<tokio_rustls::TlsConnector>,
}

impl Https {
    pub fn new() -> Self {
        Self::default()
    }

    async fn connector(&self) -> Result<&tokio_rustls::TlsConnector, String> {
        self.tls
            .get_or_try_init(|| async {
                tokio::task::spawn_blocking(connector)
                    .await
                    .map_err(|e| e.to_string())?
            })
            .await
    }

    async fn deliver(&self, message: Message) -> Result<Delivery, String> {
        let tls = self.connector().await?;
        let host = message.host.clone();
        let name = rustls::pki_types::ServerName::try_from(host.clone())
            .map_err(|e| format!("{host} is not a name: {e}"))?;
        let stream = tokio::net::TcpStream::connect((host.as_str(), 443))
            .await
            .map_err(|e| format!("cannot connect to {host}: {e}"))?;
        let stream = tls
            .connect(name, stream)
            .await
            .map_err(|e| format!("no TLS with {host}: {e}"))?;
        send_on(stream, message).await
    }
}

#[async_trait]
impl PushService for Https {
    async fn send(&self, message: Message) -> Result<Delivery, String> {
        let host = message.host.clone();
        tokio::time::timeout(SEND_TIMEOUT, self.deliver(message))
            .await
            .unwrap_or_else(|_| Err(format!("{host} did not answer in {SEND_TIMEOUT:?}")))
    }
}

/// What connections to a push service are made with.
fn connector() -> Result<tokio_rustls::TlsConnector, String> {
    let found = rustls_native_certs::load_native_certs();
    let mut roots = rustls::RootCertStore::empty();
    let (taken, _) = roots.add_parsable_certificates(found.certs);
    if taken == 0 {
        let why = found
            .errors
            .first()
            .map(|e| format!(": {e}"))
            .unwrap_or_default();
        return Err(format!(
            "this machine has no certificate authorities to check a push service with{why}"
        ));
    }
    let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(tokio_rustls::TlsConnector::from(std::sync::Arc::new(
        config,
    )))
}

/// Ends the task that carries a connection once its request is done.
struct AbortOnDrop(tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Sends `message` on `stream`, a connection to its push service.
async fn send_on<S>(stream: S, message: Message) -> Result<Delivery, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let lost = |e: &dyn fmt::Display| format!("the connection to {} failed: {e}", message.host);
    let value = |text: &str| HeaderValue::from_str(text).map_err(|e| lost(&e));
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| lost(&e))?;
    let connection = tokio::spawn(connection);
    let _stop = AbortOnDrop(connection.abort_handle());

    let mut http = hyper::Request::new(Full::new(Bytes::from(message.body)));
    *http.method_mut() = hyper::Method::POST;
    *http.uri_mut() = message.path.parse().map_err(|e| lost(&e))?;
    let headers = http.headers_mut();
    headers.insert(header::HOST, value(&message.host)?);
    headers.insert(header::AUTHORIZATION, value(&message.authorization)?);
    headers.insert(
        header::CONTENT_ENCODING,
        HeaderValue::from_static("aes128gcm"),
    );
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert("ttl", HeaderValue::from(message.ttl));
    // It waits for a person: the phone is to show it now.
    headers.insert("urgency", HeaderValue::from_static("high"));

    let reply = sender.send_request(http).await.map_err(|e| lost(&e))?;
    let status = reply.status().as_u16();
    let mut incoming = reply.into_body();
    let mut said = Vec::new();
    while said.len() < 4 * MAX_SAID
        && let Some(frame) = incoming.frame().await
    {
        let frame = frame.map_err(|e| lost(&e))?;
        if let Some(data) = frame.data_ref() {
            said.extend_from_slice(data);
        }
    }
    Ok(Delivery::of(status, &said))
}

/// For tests: a push service that keeps what it is sent, and a phone's
/// subscription that reads it.
#[cfg(test)]
pub mod fake {
    use std::sync::Mutex;

    use super::*;

    /// A push service that answers every message the same way.
    pub struct FakePush {
        pub sent: Mutex<Vec<Message>>,
        answer: Mutex<Result<Delivery, String>>,
    }

    impl Default for FakePush {
        fn default() -> Self {
            Self {
                sent: Mutex::new(Vec::new()),
                answer: Mutex::new(Ok(Delivery::Taken)),
            }
        }
    }

    impl FakePush {
        pub fn answering(&self, answer: Result<Delivery, String>) {
            *self.answer.lock().unwrap() = answer;
        }

        pub fn sent(&self) -> Vec<Message> {
            self.sent.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl PushService for FakePush {
        async fn send(&self, message: Message) -> Result<Delivery, String> {
            self.sent.lock().unwrap().push(message);
            self.answer.lock().unwrap().clone()
        }
    }

    /// What a phone's browser keeps of a subscription.
    pub struct FakeBrowser {
        key: PrivateKey,
        auth: [u8; AUTH_LEN],
        pub endpoint: String,
    }

    impl Default for FakeBrowser {
        fn default() -> Self {
            Self::new()
        }
    }

    impl FakeBrowser {
        pub fn new() -> Self {
            let mut auth = [0u8; AUTH_LEN];
            getrandom::fill(&mut auth).unwrap();
            Self {
                key: PrivateKey::generate(&ECDH_P256).unwrap(),
                auth,
                endpoint: "https://web.push.apple.com/QOne-subscription".into(),
            }
        }

        pub fn p256dh(&self) -> String {
            encode(self.key.compute_public_key().unwrap().as_ref())
        }

        pub fn auth(&self) -> String {
            encode(&self.auth)
        }

        pub fn subscription(&self) -> Subscription {
            Subscription::new(&self.endpoint, &self.p256dh(), &self.auth()).unwrap()
        }

        /// The text of a message's body, as the browser reads it.
        pub fn read(&self, body: &[u8]) -> Vec<u8> {
            open(&self.key, &self.auth, body)
        }
    }

    /// The text of `body`, for the subscription whose key is `phone` and
    /// whose secret is `auth`.
    pub fn open(phone: &PrivateKey, auth: &[u8], body: &[u8]) -> Vec<u8> {
        let (salt, rest) = body.split_at(SALT_LEN);
        assert_eq!(rest[..4], RECORD.to_be_bytes());
        assert_eq!(usize::from(rest[4]), KEY_LEN);
        let (sender, sealed) = rest[5..].split_at(KEY_LEN);
        let public = phone.compute_public_key().unwrap();
        let mut info = b"WebPush: info\0".to_vec();
        info.extend_from_slice(public.as_ref());
        info.extend_from_slice(sender);
        let shared = agreement::agree(
            phone,
            UnparsedPublicKey::new(&ECDH_P256, sender),
            PushError::Keys,
            |secret| derive::<32>(auth, secret, &info),
        )
        .unwrap();
        let key = derive::<16>(salt, &*shared, b"Content-Encoding: aes128gcm\0").unwrap();
        let nonce = derive::<12>(salt, &*shared, b"Content-Encoding: nonce\0").unwrap();
        let key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &*key).unwrap());
        let mut sealed = sealed.to_vec();
        let text = key
            .open_in_place(
                Nonce::assume_unique_for_key(*nonce),
                Aad::empty(),
                &mut sealed,
            )
            .unwrap();
        assert_eq!(text.last(), Some(&0x02));
        text[..text.len() - 1].to_vec()
    }
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::signature::{self, ECDSA_P256_SHA256_FIXED};

    use super::fake::{FakeBrowser, open};
    use super::*;
    use crate::test_support::{Canary, assert_no_canary};

    fn raw(text: &str) -> Vec<u8> {
        decode(&text.replace(' ', "")).unwrap()
    }

    /// RFC 8291, section 5 and appendix A.
    #[test]
    fn a_message_is_encrypted_as_the_rfc_says() {
        let sender = PrivateKey::from_private_key(
            &ECDH_P256,
            &raw("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"),
        )
        .unwrap();
        let salt: [u8; SALT_LEN] = raw("DGv6ra1nlYgDCS1FRnbzlw").try_into().unwrap();
        let phone = raw("BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcx \
             aOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4");
        let auth = raw("BTBZMqHH6r4Tts7J_aSIgg");
        let text = b"When I grow up, I want to be a watermelon";

        let body = seal(&sender, &salt, &phone, &auth, text).unwrap();
        assert_eq!(
            encode(&body),
            "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml\
             mlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPT\
             pK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN"
        );

        // And the receiver of the example reads it.
        let receiver = PrivateKey::from_private_key(
            &ECDH_P256,
            &raw("q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94"),
        )
        .unwrap();
        assert_eq!(open(&receiver, &auth, &body), text);
    }

    #[test]
    fn each_message_has_a_key_and_a_salt_of_its_own() {
        let (key, _) = Vapid::generate().unwrap();
        let browser = FakeBrowser::new();
        let to = browser.subscription();
        let wait = Duration::from_mins(2);
        let one = Message::new(&key, &to, b"a request waits", wait, 1_800_000_000).unwrap();
        let two = Message::new(&key, &to, b"a request waits", wait, 1_800_000_000).unwrap();
        assert_ne!(one.body, two.body);
        assert_ne!(one.body[..HEAD], two.body[..HEAD]);
        assert_eq!(browser.read(&one.body), b"a request waits");
        assert_eq!(browser.read(&two.body), b"a request waits");
        assert_eq!(one.body.len(), HEAD + 15 + 1 + TAG);
        assert_eq!((one.host.as_str(), one.ttl), ("web.push.apple.com", 120));
        assert_eq!(one.path, "/QOne-subscription");
    }

    #[test]
    fn a_message_that_does_not_fit_one_record_is_refused() {
        let (key, _) = Vapid::generate().unwrap();
        let to = FakeBrowser::new().subscription();
        let wait = Duration::from_mins(2);
        let fits = Message::new(&key, &to, &vec![b'a'; MAX_TEXT], wait, 0).unwrap();
        assert_eq!(fits.body.len(), RECORD as usize);
        assert_eq!(
            Message::new(&key, &to, &vec![b'a'; MAX_TEXT + 1], wait, 0).unwrap_err(),
            PushError::TooLong
        );
    }

    #[test]
    fn the_token_is_signed_by_the_key_the_phone_subscribed_to() {
        let (key, written) = Vapid::generate().unwrap();
        let again = Vapid::from_pkcs8(&written).unwrap();
        assert_eq!(again.public(), key.public());
        assert_eq!(decode(&key.public()).unwrap().len(), KEY_LEN);
        assert_eq!(Vapid::from_pkcs8(b"not a key").unwrap_err(), PushError::Key);

        let said = again
            .authorization("https://web.push.apple.com", 1_800_000_000)
            .unwrap();
        let (token, public) = said
            .strip_prefix("vapid t=")
            .unwrap()
            .split_once(", k=")
            .unwrap();
        assert_eq!(public, key.public());
        let parts: Vec<&str> = token.split('.').collect();
        let [head, claims, signature] = parts.as_slice() else {
            panic!("a token has three parts");
        };
        let head: serde_json::Value = serde_json::from_slice(&decode(head).unwrap()).unwrap();
        assert_eq!(head, serde_json::json!({"typ": "JWT", "alg": "ES256"}));
        let said: serde_json::Value = serde_json::from_slice(&decode(claims).unwrap()).unwrap();
        assert_eq!(
            said,
            serde_json::json!({
                "aud": "https://web.push.apple.com",
                "exp": 1_800_003_600u64,
                "sub": "https://github.com/oorestisime/kagebunshin",
            })
        );
        // r and s, 32 bytes each: not the ASN.1 a certificate has.
        let signature = decode(signature).unwrap();
        assert_eq!(signature.len(), 64);
        let signed = &token[..token.rfind('.').unwrap()];
        signature::UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, decode(public).unwrap())
            .verify(signed.as_bytes(), &signature)
            .unwrap();
    }

    #[test]
    fn only_a_known_push_service_over_https_is_taken() {
        for (endpoint, host, path) in [
            (
                "https://web.push.apple.com/QAbc-123_x",
                "web.push.apple.com",
                "/QAbc-123_x",
            ),
            (
                "https://fcm.googleapis.com/fcm/send/abc:def",
                "fcm.googleapis.com",
                "/fcm/send/abc:def",
            ),
            (
                "https://jmt17.google.com/fcm/send/abc:def",
                "jmt17.google.com",
                "/fcm/send/abc:def",
            ),
            (
                "https://updates.push.services.mozilla.com:443/wpush/v2/gAAAA",
                "updates.push.services.mozilla.com",
                "/wpush/v2/gAAAA",
            ),
            (
                "https://WNS2-par02p.notify.windows.com/w/?token=AwYAAAC",
                "wns2-par02p.notify.windows.com",
                "/w/?token=AwYAAAC",
            ),
        ] {
            assert_eq!(
                place(endpoint),
                Ok((host.into(), path.into())),
                "{endpoint}"
            );
        }
        for endpoint in [
            "http://web.push.apple.com/QAbc",
            "https://web.push.apple.com:8443/QAbc",
            "https://desk.example.ts.net/QAbc",
            "https://100.64.0.1/QAbc",
            "https://localhost/QAbc",
            "https://evilpush.apple.com/QAbc",
            "https://www.google.com/fcm/send/abc",
            "https://jmt18.google.com/fcm/send/abc",
            "https://push.apple.com.example.com/QAbc",
            "https://web.push.apple.com@example.com/QAbc",
            "https://example.com@web.push.apple.com/QAbc",
            "https:///QAbc",
            "web.push.apple.com/QAbc",
            "/QAbc",
            "",
        ] {
            assert_eq!(place(endpoint), Err(PushError::Endpoint), "{endpoint}");
        }
        let long = format!("https://web.push.apple.com/{}", "a".repeat(MAX_ENDPOINT));
        assert_eq!(place(&long), Err(PushError::Endpoint));
    }

    #[test]
    fn a_subscription_is_what_a_browser_gives() {
        let browser = FakeBrowser::new();
        let (endpoint, key, auth) = (&browser.endpoint, browser.p256dh(), browser.auth());
        assert!(Subscription::new(endpoint, &key, &auth).is_ok());
        assert_eq!(
            Subscription::new("https://example.com/x", &key, &auth).unwrap_err(),
            PushError::Endpoint
        );
        for (key, auth) in [
            ("", auth.as_str()),
            ("not base64url!", auth.as_str()),
            (&key[..key.len() - 2], auth.as_str()),
            // A compressed point.
            (&encode(&[0x02; KEY_LEN]), auth.as_str()),
            (key.as_str(), ""),
            (key.as_str(), &auth[..auth.len() - 2]),
            (key.as_str(), key.as_str()),
        ] {
            assert_eq!(
                Subscription::new(endpoint, key, auth).unwrap_err(),
                PushError::Keys
            );
        }
        // A point that is not on the curve is found when a message is made.
        let off = encode(&[0x04; KEY_LEN]);
        let to = Subscription::new(endpoint, &off, &auth).unwrap();
        let (vapid, _) = Vapid::generate().unwrap();
        assert_eq!(
            Message::new(&vapid, &to, b"x", Duration::ZERO, 0).unwrap_err(),
            PushError::Keys
        );
    }

    #[test]
    fn nothing_of_a_subscription_or_a_key_is_written_out() {
        let canary = Canary::new();
        let endpoint = format!("https://web.push.apple.com/{}", canary.value());
        let browser = FakeBrowser::new();
        let to = Subscription::new(&endpoint, &browser.p256dh(), &browser.auth()).unwrap();
        let shown = format!("{to:?}");
        assert_no_canary(&canary, &shown);
        assert!(!shown.contains(&browser.auth()), "{shown}");
        assert!(shown.contains("web.push.apple.com"), "{shown}");

        let (key, written) = Vapid::generate().unwrap();
        assert!(!format!("{key:?}").contains(&encode(&written)));
        let message = Message::new(&key, &to, b"x", Duration::ZERO, 0).unwrap();
        let shown = format!("{message:?}");
        assert_no_canary(&canary, &shown);
        assert!(!shown.contains("vapid"), "{shown}");
    }

    /// A push service on the other end of `send_on`, answering `status`
    /// and `said`: what it was asked.
    async fn pushed(
        message: Message,
        status: u16,
        said: &'static str,
    ) -> (Result<Delivery, String>, hyper::Request<Bytes>) {
        use hyper::service::service_fn;
        let (client, server) = tokio::io::duplex(64 * 1024);
        let (asked, got) = tokio::sync::oneshot::channel();
        let asked = std::sync::Mutex::new(Some(asked));
        let service = tokio::spawn(async move {
            let serve = service_fn(|req: hyper::Request<hyper::body::Incoming>| {
                let asked = asked.lock().unwrap().take();
                async move {
                    let (parts, body) = req.into_parts();
                    let body = body.collect().await.unwrap().to_bytes();
                    if let Some(asked) = asked {
                        let _ = asked.send(hyper::Request::from_parts(parts, body));
                    }
                    let mut reply =
                        hyper::Response::new(Full::new(Bytes::from_static(said.as_bytes())));
                    *reply.status_mut() = hyper::StatusCode::from_u16(status).unwrap();
                    Ok::<_, std::convert::Infallible>(reply)
                }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(server), serve)
                .await;
        });
        let delivery = send_on(client, message).await;
        let asked = got.await.unwrap();
        service.abort();
        (delivery, asked)
    }

    #[tokio::test]
    async fn a_message_is_posted_as_a_push_service_takes_it() {
        let (key, _) = Vapid::generate().unwrap();
        let browser = FakeBrowser::new();
        let to = browser.subscription();
        let message = Message::new(&key, &to, b"hello", Duration::from_secs(90), 0).unwrap();
        let (delivery, asked) = pushed(message.clone(), 201, "").await;
        assert_eq!(delivery, Ok(Delivery::Taken));
        assert_eq!(asked.method(), hyper::Method::POST);
        assert_eq!(asked.uri().to_string(), "/QOne-subscription");
        let header = |name: &str| asked.headers().get(name).unwrap().to_str().unwrap();
        assert_eq!(header("host"), "web.push.apple.com");
        assert_eq!(header("ttl"), "90");
        assert_eq!(header("urgency"), "high");
        assert_eq!(header("content-encoding"), "aes128gcm");
        assert_eq!(header("content-length"), message.body.len().to_string());
        assert_eq!(header("authorization"), message.authorization);
        assert!(header("authorization").starts_with("vapid t="));
        assert_eq!(browser.read(asked.body()), b"hello");
    }

    #[tokio::test]
    async fn what_a_push_service_answers_is_told_apart() {
        let (key, _) = Vapid::generate().unwrap();
        let to = FakeBrowser::new().subscription();
        let message = Message::new(&key, &to, b"hello", Duration::ZERO, 0).unwrap();
        for (status, said, delivery) in [
            (200, "", Delivery::Taken),
            (404, "", Delivery::Gone),
            (410, "{\"reason\":\"Unregistered\"}", Delivery::Gone),
            (
                403,
                "{\"reason\":\"BadJwtToken\"}\n",
                Delivery::Refused(403, "{\"reason\":\"BadJwtToken\"}".into()),
            ),
            (500, "", Delivery::Refused(500, String::new())),
        ] {
            let (got, _) = pushed(message.clone(), status, said).await;
            assert_eq!(got, Ok(delivery), "{status}");
        }
        let long = "x".repeat(5000);
        let Delivery::Refused(413, said) = Delivery::of(413, long.as_bytes()) else {
            panic!("a refusal");
        };
        assert_eq!(said.len(), MAX_SAID);
    }
}
