//! The part of `WebAuthn` the approval page needs: taking the passkey a
//! phone made for this site when it was paired, and checking that an
//! approval is that passkey's signature over one challenge, made on this
//! site with the person verified (Face ID, a fingerprint, the phone's
//! code).
//!
//! Only what a phone's passkey does: an ES256 key (ECDSA on P-256 with
//! SHA-256), no attestation. A passkey of another kind is refused when it
//! is made, so the store never holds one this cannot check.
//!
//! What is checked, each time: the page's `clientDataJSON` says the right
//! ceremony, this challenge and exactly this origin (scheme, name and
//! port); the authenticator's data is for this site's name and says the
//! person was present and verified. For an approval the signature over
//! both is then checked with the paired key, which is what makes the rest
//! true. When a passkey is made nothing signs it (there is no
//! attestation), so that it comes from the phone rests on who the daemon
//! let reach the page; see `ipc::phone`.

use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// The bytes of a challenge: random, used once.
pub const CHALLENGE_LEN: usize = 32;

/// An uncompressed P-256 point: `0x04`, x, y.
pub const KEY_LEN: usize = 65;

/// The longest passkey id an authenticator may give.
const MAX_CREDENTIAL: usize = 1023;

/// `rpIdHash`, flags and the signature counter.
const AUTH_DATA_HEAD: usize = 32 + 1 + 4;
/// The person was present.
const FLAG_PRESENT: u8 = 0x01;
/// The person was verified.
const FLAG_VERIFIED: u8 = 0x04;
/// A new passkey follows.
const FLAG_ATTESTED: u8 = 0x40;

/// An ES256 public key as an authenticator writes it: a COSE map of key
/// type EC2, algorithm ES256, curve P-256, then x and y. CTAP2 fixes the
/// order and the encoding, so every such key has these bytes around its
/// two coordinates.
const COSE_HEAD: [u8; 10] = [0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
const COSE_MID: [u8; 3] = [0x22, 0x58, 0x20];
const COSE_LEN: usize = COSE_HEAD.len() + 32 + COSE_MID.len() + 32;

/// Base64url without padding, as `WebAuthn` writes bytes in JSON.
pub fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The bytes of base64url text without padding; `None` for anything else.
pub fn decode(text: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(text).ok()
}

/// The site passkeys are made for and used on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Site {
    /// Its name, which a passkey is tied to: this machine's `MagicDNS`
    /// name, in lower case, without the dot at its end.
    pub name: String,
    /// `https://<name>:<port>`: where the page is, and the only origin an
    /// approval may come from.
    pub origin: String,
}

impl Site {
    pub fn new(name: &str, port: u16) -> Self {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        Self {
            origin: format!("https://{name}:{port}"),
            name,
        }
    }
}

/// Why a passkey or an approval is refused. No message holds anything the
/// phone sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WebauthnError {
    #[error("what the page sent is not what a passkey gives")]
    Malformed,
    #[error("it is not for this request")]
    Challenge,
    #[error("it was not made on this page")]
    Origin,
    #[error("it is for another site")]
    Site,
    #[error("the phone did not verify the person holding it")]
    Unverified,
    #[error("the passkey is not of a kind this can check (ES256)")]
    Unsupported,
    #[error("the signature is not the paired passkey's")]
    Signature,
}

/// A passkey as made: what the store keeps of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Passkey {
    pub credential: Vec<u8>,
    pub key: [u8; KEY_LEN],
}

/// Which ceremony the page ran.
#[derive(Clone, Copy)]
enum Ceremony {
    Create,
    Get,
}

/// Checks the page's account of a ceremony: its kind, `challenge`, and
/// that it ran on `site` and not inside another site's page.
fn check_client(
    site: &Site,
    ceremony: Ceremony,
    challenge: &[u8],
    client_data: &[u8],
) -> Result<(), WebauthnError> {
    #[derive(Deserialize)]
    struct ClientData {
        #[serde(rename = "type")]
        kind: String,
        challenge: String,
        origin: String,
        #[serde(default, rename = "crossOrigin")]
        cross_origin: bool,
    }
    let data: ClientData =
        serde_json::from_slice(client_data).map_err(|_| WebauthnError::Malformed)?;
    let kind = match ceremony {
        Ceremony::Create => "webauthn.create",
        Ceremony::Get => "webauthn.get",
    };
    if data.kind != kind {
        return Err(WebauthnError::Malformed);
    }
    if decode(&data.challenge).as_deref() != Some(challenge) {
        return Err(WebauthnError::Challenge);
    }
    if data.origin != site.origin || data.cross_origin {
        return Err(WebauthnError::Origin);
    }
    Ok(())
}

/// Checks the head of the authenticator's data: made for `site`, with the
/// person present and verified. Gives the flags and what follows the head.
fn check_authenticator<'a>(
    site: &Site,
    auth_data: &'a [u8],
) -> Result<(u8, &'a [u8]), WebauthnError> {
    let (head, rest) = auth_data
        .split_at_checked(AUTH_DATA_HEAD)
        .ok_or(WebauthnError::Malformed)?;
    if head[..32] != Sha256::digest(site.name.as_bytes())[..] {
        return Err(WebauthnError::Site);
    }
    let flags = head[32];
    if flags & FLAG_PRESENT == 0 || flags & FLAG_VERIFIED == 0 {
        return Err(WebauthnError::Unverified);
    }
    Ok((flags, rest))
}

/// The passkey a phone made on `site` for `challenge`: `client_data` is
/// the page's `clientDataJSON` and `auth_data` the authenticator data of
/// its reply.
///
/// Nothing signs these, so they are only as good as the connection they
/// came over; the checks keep out a passkey made for something else or of
/// a kind [`verify`] could not check.
pub fn register(
    site: &Site,
    challenge: &[u8],
    client_data: &[u8],
    auth_data: &[u8],
) -> Result<Passkey, WebauthnError> {
    check_client(site, Ceremony::Create, challenge, client_data)?;
    let (flags, rest) = check_authenticator(site, auth_data)?;
    if flags & FLAG_ATTESTED == 0 {
        return Err(WebauthnError::Malformed);
    }
    // The authenticator's model (16 bytes), the id's length, the id, the key.
    let (len, rest) = rest
        .get(16..)
        .and_then(|r| r.split_at_checked(2))
        .ok_or(WebauthnError::Malformed)?;
    let len = usize::from(u16::from_be_bytes([len[0], len[1]]));
    if len == 0 || len > MAX_CREDENTIAL {
        return Err(WebauthnError::Malformed);
    }
    let (credential, cose) = rest.split_at_checked(len).ok_or(WebauthnError::Malformed)?;
    let cose = cose.get(..COSE_LEN).ok_or(WebauthnError::Unsupported)?;
    let (head, rest) = cose.split_at(COSE_HEAD.len());
    let (x, rest) = rest.split_at(32);
    let (mid, y) = rest.split_at(COSE_MID.len());
    if head != COSE_HEAD || mid != COSE_MID {
        return Err(WebauthnError::Unsupported);
    }
    let mut key = [0u8; KEY_LEN];
    key[0] = 0x04;
    key[1..33].copy_from_slice(x);
    key[33..].copy_from_slice(y);
    Ok(Passkey {
        credential: credential.to_vec(),
        key,
    })
}

/// Checks an approval: `signature` is `key`'s over `auth_data` and
/// `client_data`, which say `challenge` was answered on `site` with the
/// person verified.
pub fn verify(
    site: &Site,
    challenge: &[u8],
    key: &[u8],
    client_data: &[u8],
    auth_data: &[u8],
    signature: &[u8],
) -> Result<(), WebauthnError> {
    check_client(site, Ceremony::Get, challenge, client_data)?;
    check_authenticator(site, auth_data)?;
    let mut signed = Vec::with_capacity(auth_data.len() + 32);
    signed.extend_from_slice(auth_data);
    signed.extend_from_slice(&Sha256::digest(client_data));
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, key)
        .verify(&signed, signature)
        .map_err(|_| WebauthnError::Signature)
}

/// A phone's passkey, for tests: what the page would send for a ceremony.
#[cfg(test)]
pub mod fake {
    use super::*;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};

    pub struct FakePasskey {
        pair: EcdsaKeyPair,
        pub credential: Vec<u8>,
    }

    impl Default for FakePasskey {
        fn default() -> Self {
            Self::new()
        }
    }

    impl FakePasskey {
        pub fn new() -> Self {
            Self {
                pair: EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).unwrap(),
                credential: b"a passkey's id!!".to_vec(),
            }
        }

        /// The public key, as the store keeps it.
        pub fn key(&self) -> Vec<u8> {
            self.pair.public_key().as_ref().to_vec()
        }

        pub fn client_data(kind: &str, origin: &str, challenge: &[u8]) -> Vec<u8> {
            serde_json::json!({
                "type": kind,
                "challenge": encode(challenge),
                "origin": origin,
                "crossOrigin": false,
            })
            .to_string()
            .into_bytes()
        }

        /// The authenticator's data for `name` with `flags`, without a key.
        pub fn auth_data(name: &str, flags: u8) -> Vec<u8> {
            let mut data = Sha256::digest(name.as_bytes()).to_vec();
            data.push(flags);
            data.extend_from_slice(&[0, 0, 0, 0]);
            data
        }

        /// What making this passkey on `site` sends: `clientDataJSON` and
        /// the authenticator's data.
        pub fn create(&self, site: &Site, challenge: &[u8]) -> (Vec<u8>, Vec<u8>) {
            let mut data = Self::auth_data(&site.name, 0x45);
            data.extend_from_slice(&[0u8; 16]);
            data.extend_from_slice(&(self.credential.len() as u16).to_be_bytes());
            data.extend_from_slice(&self.credential);
            let key = self.key();
            data.extend_from_slice(&COSE_HEAD);
            data.extend_from_slice(&key[1..33]);
            data.extend_from_slice(&COSE_MID);
            data.extend_from_slice(&key[33..]);
            (
                Self::client_data("webauthn.create", &site.origin, challenge),
                data,
            )
        }

        /// The signature over `auth_data` and `client_data`.
        pub fn sign(&self, auth_data: &[u8], client_data: &[u8]) -> Vec<u8> {
            let mut signed = auth_data.to_vec();
            signed.extend_from_slice(&Sha256::digest(client_data));
            self.pair
                .sign(&SystemRandom::new(), &signed)
                .unwrap()
                .as_ref()
                .to_vec()
        }

        /// What approving `challenge` on `site` sends: `clientDataJSON`,
        /// the authenticator's data and the signature.
        pub fn get(&self, site: &Site, challenge: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
            let client = Self::client_data("webauthn.get", &site.origin, challenge);
            let data = Self::auth_data(&site.name, 0x05);
            let signature = self.sign(&data, &client);
            (client, data, signature)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::FakePasskey;
    use super::*;

    fn site() -> Site {
        Site::new("Self.Example.ts.net.", 47318)
    }

    #[test]
    fn a_site_is_its_name_and_port() {
        let s = site();
        assert_eq!(s.name, "self.example.ts.net");
        assert_eq!(s.origin, "https://self.example.ts.net:47318");
    }

    #[test]
    fn base64url_has_no_padding() {
        assert_eq!(encode(&[0xfb, 0xff]), "-_8");
        assert_eq!(decode("-_8"), Some(vec![0xfb, 0xff]));
        assert_eq!(decode("-_8="), None);
        assert_eq!(decode("+/8"), None);
    }

    #[test]
    fn a_passkey_is_taken_as_a_phone_writes_it() {
        let passkey = FakePasskey::new();
        let (client, data) = passkey.create(&site(), b"challenge");
        let made = register(&site(), b"challenge", &client, &data).unwrap();
        assert_eq!(made.credential, passkey.credential);
        assert_eq!(made.key.to_vec(), passkey.key());
        assert_eq!(made.key[0], 0x04);

        // Extensions may follow the key.
        let mut longer = data.clone();
        longer.extend_from_slice(&[0xa0]);
        assert!(register(&site(), b"challenge", &client, &longer).is_ok());
    }

    #[test]
    fn a_passkey_made_for_anything_else_is_refused() {
        let passkey = FakePasskey::new();
        let s = site();
        let (client, data) = passkey.create(&s, b"challenge");
        let refused = |client: &[u8], data: &[u8]| register(&s, b"challenge", client, data);

        assert_eq!(
            register(&s, b"another", &client, &data),
            Err(WebauthnError::Challenge)
        );
        let get = FakePasskey::client_data("webauthn.get", &s.origin, b"challenge");
        assert_eq!(refused(&get, &data), Err(WebauthnError::Malformed));
        // Another port of this machine is another origin.
        for origin in [
            "https://self.example.ts.net:47319",
            "https://self.example.ts.net",
            "http://self.example.ts.net:47318",
            "https://evil.example:47318",
        ] {
            let c = FakePasskey::client_data("webauthn.create", origin, b"challenge");
            assert_eq!(refused(&c, &data), Err(WebauthnError::Origin), "{origin}");
        }
        let framed = serde_json::json!({
            "type": "webauthn.create",
            "challenge": encode(b"challenge"),
            "origin": s.origin,
            "crossOrigin": true,
        })
        .to_string();
        assert_eq!(
            refused(framed.as_bytes(), &data),
            Err(WebauthnError::Origin)
        );

        let other = Site::new("other.example.ts.net", 47318);
        let (_, elsewhere) = passkey.create(&other, b"challenge");
        assert_eq!(refused(&client, &elsewhere), Err(WebauthnError::Site));

        // Present but not verified: no Face ID was asked for.
        let mut unverified = data.clone();
        unverified[32] = 0x41;
        assert_eq!(
            refused(&client, &unverified),
            Err(WebauthnError::Unverified)
        );
        // No new passkey in it.
        let mut bare = data.clone();
        bare[32] = 0x05;
        assert_eq!(refused(&client, &bare), Err(WebauthnError::Malformed));
        // An RSA key, say: not the bytes of an ES256 one.
        let mut rsa = data.clone();
        let at = rsa.len() - COSE_LEN;
        rsa[at + 4] = 0x39;
        assert_eq!(refused(&client, &rsa), Err(WebauthnError::Unsupported));

        for cut in [0, 10, AUTH_DATA_HEAD, AUTH_DATA_HEAD + 17, data.len() - 1] {
            assert!(refused(&client, &data[..cut]).is_err(), "cut at {cut}");
        }
        assert_eq!(refused(b"not json", &data), Err(WebauthnError::Malformed));
    }

    #[test]
    fn an_approval_is_the_paired_keys_signature_over_this_challenge() {
        let passkey = FakePasskey::new();
        let s = site();
        let key = passkey.key();
        let (client, data, signature) = passkey.get(&s, b"challenge");
        assert_eq!(
            verify(&s, b"challenge", &key, &client, &data, &signature),
            Ok(())
        );

        // Another request's challenge, though the signature is good.
        assert_eq!(
            verify(&s, b"another", &key, &client, &data, &signature),
            Err(WebauthnError::Challenge)
        );
        // Another passkey.
        let other = FakePasskey::new();
        assert_eq!(
            verify(&s, b"challenge", &other.key(), &client, &data, &signature),
            Err(WebauthnError::Signature)
        );
        // Signed, but on another port of this machine: a page someone
        // else serves under its name.
        let elsewhere = Site::new("self.example.ts.net", 8443);
        let (c2, d2, s2) = passkey.get(&elsewhere, b"challenge");
        assert_eq!(
            verify(&s, b"challenge", &key, &c2, &d2, &s2),
            Err(WebauthnError::Origin)
        );
        // Signed without verifying the person.
        let c3 = FakePasskey::client_data("webauthn.get", &s.origin, b"challenge");
        let d3 = FakePasskey::auth_data(&s.name, 0x01);
        let s3 = passkey.sign(&d3, &c3);
        assert_eq!(
            verify(&s, b"challenge", &key, &c3, &d3, &s3),
            Err(WebauthnError::Unverified)
        );
        // Making a passkey is not approving.
        let c4 = FakePasskey::client_data("webauthn.create", &s.origin, b"challenge");
        let s4 = passkey.sign(&data, &c4);
        assert_eq!(
            verify(&s, b"challenge", &key, &c4, &data, &s4),
            Err(WebauthnError::Malformed)
        );
        // Anything changed after signing.
        let mut flipped = data.clone();
        flipped[33] ^= 1;
        assert_eq!(
            verify(&s, b"challenge", &key, &client, &flipped, &signature),
            Err(WebauthnError::Signature)
        );
        assert_eq!(
            verify(&s, b"challenge", &key, &client, &data, b""),
            Err(WebauthnError::Signature)
        );
        assert_eq!(
            verify(&s, b"challenge", b"not a key", &client, &data, &signature),
            Err(WebauthnError::Signature)
        );
    }

    /// What a browser's own authenticator gave the approval page, served
    /// on `localhost` (Chromium's virtual one: its key was never kept):
    /// the checks hold for bytes no code here made.
    #[test]
    fn a_browsers_passkey_checks_out() {
        let bytes = |text: &str| decode(text).unwrap();
        let site = Site {
            name: "localhost".into(),
            origin: "http://localhost:18520".into(),
        };
        let made = bytes("46eMABW4CwGw9MXBSfjG32NYWK2vpqeoKOwx3w8AP6k");
        let passkey = register(
            &site,
            &made,
            &bytes(
                "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiNDZlTUFCVzRDd0d3OU1YQlNmakczMk5ZV0sydnBxZW9LT3d4M3c4QVA2ayIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MTg1MjAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
            ),
            &bytes(
                "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAQECAwQFBgcIAQIDBAUGBwgAIN7SWNsarn5SNRFuDmpktDjGumkN45-AYNRqa_kvieLcpQECAyYgASFYIHhVJ3FxnR2L1O8U1jIbwD6jnuaKjil97fB9mfYyeI3fIlggbKrOs9BDIUFrnACKwNIsfPpCtloqGrGkN64csJmtgI8",
            ),
        )
        .unwrap();
        assert_eq!(passkey.credential.len(), 32);

        let asked = bytes("H8vg2DOfRRQ-FFnqaMMPK4g6_IKi8O2QUrtq8uoGXI8");
        let client = bytes(
            "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiSDh2ZzJET2ZSUlEtRkZucWFNTVBLNGc2X0lLaThPMlFVcnRxOHVvR1hJOCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MTg1MjAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
        );
        let auth = bytes("SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAg");
        let signature = bytes(
            "MEYCIQCJxXnU1BctyGdqTpeQjHgTAUsFB36vC38IKKZ-Hs5STgIhAMGR6JUlNvv6cak8XJS7hMnjR2YauPlRfpuE58yb0vHS",
        );
        assert_eq!(
            verify(&site, &asked, &passkey.key, &client, &auth, &signature),
            Ok(())
        );
        assert_eq!(
            verify(&site, &made, &passkey.key, &client, &auth, &signature),
            Err(WebauthnError::Challenge)
        );
        let mut other = signature.clone();
        *other.last_mut().unwrap() ^= 1;
        assert_eq!(
            verify(&site, &asked, &passkey.key, &client, &auth, &other),
            Err(WebauthnError::Signature)
        );
    }
}
