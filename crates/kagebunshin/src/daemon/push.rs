//! What the daemon keeps to notify the paired phone: this machine's key
//! for push messages, and the phone's subscription.
//!
//! Kept in `push.json` beside the audit log, for this user alone to read.
//! It is not in the local store, because the phone subscribes on its own,
//! after it is paired, when nobody is there to give the passphrase a
//! write of the store takes. So the passphrase does not guard it: whoever
//! reads it can send that phone notifications in this machine's name, and
//! whoever writes it can have this machine's sent elsewhere, or nowhere.
//! A notification approves nothing: the page shows what the daemon says
//! is waiting, and an approval is the passkey's signature.
//!
//! The subscription is kept with the node and the passkey of the phone
//! that gave it, and is used for that phone only: pairing another, or the
//! same one again, leaves it unused. A file that cannot be read holds
//! nothing, and is replaced: the key is made again and the phone
//! subscribes again.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use serde::{Deserialize, Serialize};
use tracing::warn;
use zeroize::Zeroizing;

use crate::webauthn::{decode, encode};
use crate::webpush::{Subscription, Vapid};

/// Its file, beside the audit log.
pub const FILE: &str = "push.json";

#[derive(Default, Serialize, Deserialize)]
struct Stored {
    /// This machine's key for push messages: PKCS#8, base64url. Made when
    /// a phone first asks what to subscribe to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    phone: Option<Held>,
}

/// A subscription, and the paired phone it is for.
#[derive(Serialize, Deserialize)]
struct Held {
    /// The phone's node on the tailnet.
    node: String,
    /// The id of its passkey, as the store has it.
    credential: String,
    subscription: Subscription,
}

pub struct PushState {
    path: PathBuf,
    /// What the file holds; held across each change of it.
    stored: Mutex<Stored>,
}

impl PushState {
    /// What the file at `path` holds, or nothing if there is none or it
    /// cannot be read.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let stored = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|_| {
                warn!(path = %path.display(), "the notifications file is not one; starting afresh");
                Stored::default()
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Stored::default(),
            Err(e) => {
                warn!(path = %path.display(), error = %e, "cannot read the notifications file");
                Stored::default()
            }
        };
        Self {
            path,
            stored: Mutex::new(stored),
        }
    }

    /// `push.json` in the directory of `audit_log`.
    pub fn beside(audit_log: &Path) -> Self {
        Self::new(audit_log.with_file_name(FILE))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn stored(&self) -> MutexGuard<'_, Stored> {
        self.stored.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self, stored: &Stored) -> Result<(), String> {
        let failed = |e: io::Error| format!("cannot write {}: {e}", self.path.display());
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).map_err(failed)?;
        }
        let json = serde_json::to_vec_pretty(stored)
            .map_err(io::Error::other)
            .map_err(failed)?;
        crate::atomic::write_private(&self.path, &json).map_err(failed)
    }

    /// This machine's key for push messages, made and kept the first time.
    /// One that cannot be used is replaced, and the subscription made for
    /// it dropped: a push service takes nothing for it from another key.
    pub fn key(&self) -> Result<Vapid, String> {
        let mut stored = self.stored();
        let kept = (stored.key.as_deref())
            .and_then(decode)
            .map(Zeroizing::new)
            .and_then(|written| Vapid::from_pkcs8(&written).ok());
        if let Some(key) = kept {
            return Ok(key);
        }
        let (key, written) = Vapid::generate().map_err(|e| e.to_string())?;
        let next = Stored {
            key: Some(encode(&written)),
            phone: None,
        };
        self.write(&next)?;
        *stored = next;
        Ok(key)
    }

    /// Keeps `subscription` for the phone whose node is `node` and whose
    /// passkey's id is `credential`, in place of any other. Not before
    /// [`Self::key`] made the key it was given for.
    pub fn hold(
        &self,
        node: &str,
        credential: &str,
        subscription: Subscription,
    ) -> Result<(), String> {
        let mut stored = self.stored();
        if stored.key.is_none() {
            return Err("the phone has not asked for this machine's key for notifications".into());
        }
        let next = Stored {
            key: stored.key.clone(),
            phone: Some(Held {
                node: node.to_owned(),
                credential: credential.to_owned(),
                subscription,
            }),
        };
        self.write(&next)?;
        *stored = next;
        Ok(())
    }

    /// The subscription of the phone whose node is `node` and whose
    /// passkey's id is `credential`, if that phone gave one.
    pub fn held_for(&self, node: &str, credential: &str) -> Option<Subscription> {
        (self.stored().phone.as_ref())
            .filter(|held| held.node == node && held.credential == credential)
            .map(|held| held.subscription.clone())
    }

    /// Drops the subscription: all of them, or only `this` one, which a
    /// newer one may have replaced meanwhile. Whether one was dropped.
    pub fn forget(&self, this: Option<&Subscription>) -> bool {
        let mut stored = self.stored();
        let is_it = (stored.phone.as_ref())
            .is_some_and(|held| this.is_none_or(|this| held.subscription == *this));
        if !is_it {
            return false;
        }
        let next = Stored {
            key: stored.key.clone(),
            phone: None,
        };
        // Dropped for this run even if the file keeps it: it is then
        // found unused again, and dropped again.
        if let Err(e) = self.write(&next) {
            warn!(error = %e, "cannot drop the phone's notifications from their file");
        }
        *stored = next;
        true
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use crate::webpush::fake::FakeBrowser;

    /// The key is made once and is the same after a restart; the file is
    /// this user's alone.
    #[test]
    fn the_key_is_made_once_and_kept_private() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("state/push.json");
        let state = PushState::new(&path);
        let public = state.key().unwrap().public();
        assert_eq!(state.key().unwrap().public(), public);
        assert_eq!(PushState::new(&path).key().unwrap().public(), public);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    /// A subscription is used only for the phone that gave it, survives a
    /// restart, and is dropped when asked, or when it is the one named.
    #[test]
    fn a_subscription_is_kept_for_the_phone_that_gave_it() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("push.json");
        let state = PushState::new(&path);
        let browser = FakeBrowser::new();
        // Given for no key of this machine, it could not be sent to.
        assert!(
            state
                .hold("nPHONE", "cred", browser.subscription())
                .is_err()
        );
        state.key().unwrap();
        (state.hold("nPHONE", "cred", browser.subscription())).unwrap();
        assert_eq!(
            state.held_for("nPHONE", "cred"),
            Some(browser.subscription())
        );
        assert_eq!(state.held_for("nTABLET", "cred"), None);
        assert_eq!(state.held_for("nPHONE", "another"), None);
        assert_eq!(
            PushState::new(&path).held_for("nPHONE", "cred"),
            Some(browser.subscription())
        );

        // Another one replaced it meanwhile: it stays.
        let other = FakeBrowser::new().subscription();
        assert!(!state.forget(Some(&other)));
        assert!(state.held_for("nPHONE", "cred").is_some());
        assert!(state.forget(Some(&browser.subscription())));
        assert_eq!(state.held_for("nPHONE", "cred"), None);
        assert_eq!(PushState::new(&path).held_for("nPHONE", "cred"), None);
        assert!(!state.forget(None));
    }

    /// A file that is not one, or whose key is not one, holds nothing: a
    /// new key is made, and the subscription made for the old is dropped.
    #[test]
    fn a_broken_file_or_key_is_replaced() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("push.json");
        std::fs::write(&path, "not json").unwrap();
        let state = PushState::new(&path);
        assert_eq!(state.held_for("nPHONE", "cred"), None);
        state.key().unwrap();
        (state.hold("nPHONE", "cred", FakeBrowser::new().subscription())).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        let mut json: serde_json::Value = serde_json::from_str(&text).unwrap();
        json["key"] = "AAAA".into();
        std::fs::write(&path, json.to_string()).unwrap();
        let state = PushState::new(&path);
        assert!(state.held_for("nPHONE", "cred").is_some());
        state.key().unwrap();
        assert_eq!(state.held_for("nPHONE", "cred"), None);
    }
}
