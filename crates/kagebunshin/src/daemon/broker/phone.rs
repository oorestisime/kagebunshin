//! The paired phone: pairing it, and answering a request from it.
//!
//! A phone is a machine on the tailnet and a passkey it made on the
//! approval page (`ipc::phone`). Both are in the local store, so pairing
//! and unpairing take the passphrase, and nothing here is known while the
//! daemon is locked.
//!
//! Pairing starts on this machine, with the passphrase and the name of
//! one phone. For [`PHONE_PAIRING`] the page then lets that phone make a
//! passkey, and the daemon keeps the passphrase to write the store with
//! once it has; a lock, a stop or the time running out drops it.
//!
//! An approval from the phone is a signature by that passkey over a
//! challenge made for one waiting request and used once, checked by
//! [`webauthn::verify`]. It takes no passphrase, so it answers only a
//! request that hands values out: one that writes the store (an import,
//! typed values) is approved in the app, which has the passphrase the
//! write needs. Denying takes no proof anywhere.

use std::collections::VecDeque;
use std::sync::Weak;
use std::time::Duration;

use serde::Serialize;
use tokio::time::Instant;
use tracing::{info, warn};

use super::{Approvals, Daemon, Inner, Phase, Reply};
use crate::audit::{Decision, Event};
use crate::daemon::resolve::ResolveError;
use crate::ipc::protocol::{
    ApprovalPrompt, ApprovalReason, Caller, PHONE_PAIRING, PhoneAnswer, PhoneChoice,
    PhonePairingView, PhoneStatus, PhoneView, RemotePeer, Response,
};
use crate::source::unix_now;
use crate::store::{PairedPhone, Passphrase};
use crate::tailnet::{self, Peer, SelfStatus};
use crate::types::{EnvName, ProjectName};
use crate::webauthn::{self, CHALLENGE_LEN, Site, WebauthnError};

/// How long the phone has to sign an approval's challenge: long enough
/// for Face ID, short enough that an unused one is soon worth nothing.
const CHALLENGE_LIFE: Duration = Duration::from_mins(2);

/// How many answered requests the page lists.
const RECENT: usize = 10;

/// A pairing going on. Kept in the session, so a lock drops it and the
/// passphrase with it.
pub(super) struct Pairing {
    node: String,
    name: String,
    /// Writes the store once the phone has made its passkey.
    passphrase: Passphrase,
    until: Instant,
    /// What the passkey being made must be for; used once.
    challenge: Option<[u8; CHALLENGE_LEN]>,
}

/// The approval page as the daemon knows it, apart from what the store
/// and the session hold.
#[derive(Default)]
pub(super) struct Phone {
    /// Where the page is served, while it is.
    url: Option<String>,
    /// Why it is not, while it should be.
    problem: Option<String>,
    /// When the paired phone last asked for the page's state.
    seen: Option<u64>,
    last: Option<PhoneAnswer>,
    /// The approval being made on the phone: for one request, used once.
    challenge: Option<Challenge>,
    /// The requests answered since the daemon started, newest first.
    recent: VecDeque<Answered>,
}

struct Challenge {
    id: u64,
    bytes: [u8; CHALLENGE_LEN],
    until: Instant,
}

/// Where a request was answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Place {
    /// In the app, on this machine.
    Desk,
    Phone,
}

/// How a request that waited for approval ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Approved,
    Denied,
    TimedOut,
    /// It stopped waiting first: its caller ended, or the app closed.
    Ended,
}

/// A request that waited for approval, once it no longer does. Names only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Answered {
    pub id: u64,
    pub project: ProjectName,
    pub env: EnvName,
    pub command: String,
    pub outcome: Outcome,
    /// Where a person answered it; none when nobody did.
    pub by: Option<Place>,
    /// Unix seconds.
    pub time: u64,
}

/// What the approval page shows the phone that asks. Names only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PhonePage {
    /// Changes whenever anything below may have; see
    /// [`Daemon::phone_page_wait`].
    pub version: u64,
    /// This phone is the paired one.
    pub paired: bool,
    /// The seconds this phone has left to make its passkey, while it is
    /// being paired.
    pub pairing: Option<u64>,
    /// The requests waiting, oldest first; for the paired phone only.
    pub prompts: Vec<PagePrompt>,
    /// The requests answered since the daemon started, newest first; for
    /// the paired phone only.
    pub recent: Vec<Answered>,
}

/// A waiting request as the page shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PagePrompt {
    #[serde(flatten)]
    pub prompt: ApprovalPrompt,
    /// Whether the phone can approve it. One that writes the store takes
    /// the passphrase, in the app.
    pub here: bool,
}

/// What the page needs to make the phone's passkey.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairBegin {
    pub challenge: [u8; CHALLENGE_LEN],
    /// The phone's name on the tailnet, which names the passkey.
    pub name: String,
}

/// What the page needs to sign an approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApproveBegin {
    pub challenge: [u8; CHALLENGE_LEN],
    /// The paired passkey's id, base64url.
    pub credential: String,
}

/// Why the page is refused. The text is shown on the phone, and none of
/// it holds anything the phone sent.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PhoneError {
    #[error("kagebunshin is locked on your computer")]
    Locked,
    #[error("this phone is not paired with kagebunshin on this computer")]
    NotPaired,
    #[error("no pairing is going on for this phone; start one in the kagebunshin app")]
    NotPairing,
    #[error("that request is not waiting any more")]
    Gone,
    #[error("that request takes the passphrase: approve it in the app on your computer")]
    DeskOnly,
    #[error("that took too long; try again")]
    NoChallenge,
    #[error("not accepted: {0}")]
    Passkey(#[from] WebauthnError),
    #[error("{0}")]
    Failed(String),
}

/// Whether the phone can approve a prompt that waits for `reason`: only
/// one that hands values out.
fn on_phone(reason: &ApprovalReason) -> bool {
    match reason {
        ApprovalReason::Keys | ApprovalReason::Marked | ApprovalReason::Waiting { .. } => true,
        ApprovalReason::Import { .. } | ApprovalReason::Type { .. } => false,
    }
}

fn challenge() -> Result<[u8; CHALLENGE_LEN], PhoneError> {
    let mut bytes = [0u8; CHALLENGE_LEN];
    getrandom::fill(&mut bytes)
        .map_err(|e| PhoneError::Failed(format!("cannot make a challenge: {e}")))?;
    Ok(bytes)
}

/// The page's address on this machine: `https://name:port`, or why there
/// is none.
pub(crate) fn page_site(status: &SelfStatus, port: u16) -> Result<Site, String> {
    match status.cert_name() {
        Some(name) => Ok(Site::new(&name, port)),
        None if status.dns_name.is_empty() => {
            Err("this machine has no MagicDNS name, which the approval page is served under".into())
        }
        None => Err(
            "this tailnet does not give its machines HTTPS certificates, which the approval \
             page needs"
                .into(),
        ),
    }
}

/// Ends the pairing that lasts until `until` once that comes, so its
/// passphrase is not kept past it.
async fn end_pairing(inner: Weak<Inner>, until: Instant) {
    tokio::time::sleep_until(until).await;
    let Some(inner) = inner.upgrade() else { return };
    {
        let mut st = inner.state();
        let Phase::Unlocked(session) = &mut st.phase else {
            return;
        };
        if session.pairing.as_ref().is_none_or(|p| p.until != until) {
            return;
        }
        session.pairing = None;
    }
    info!("a phone pairing ran out of time");
    inner.phone_changed();
}

impl Inner {
    /// The page's supervisor and whoever waits for its state look again.
    fn phone_changed(&self) {
        self.phone_woken.notify_one();
        self.phone_seq.send_modify(|n| *n += 1);
    }
}

impl Approvals {
    /// The prompt of request `id`, while it waits.
    fn prompt(&self, id: u64) -> Option<&ApprovalPrompt> {
        self.pending.get(&id).map(|(p, ..)| p)
    }
}

impl Daemon {
    /// The paired phone, while the daemon is unlocked.
    fn paired_phone(&self) -> Option<PairedPhone> {
        self.unlocked_store()
            .flatten()
            .and_then(|st| st.phone().cloned())
    }

    /// The phone being paired and the seconds it has left.
    fn pairing(&self) -> Option<(String, String, u64)> {
        let now = Instant::now();
        match &self.inner.state().phase {
            Phase::Unlocked(session) => {
                session.pairing.as_ref().filter(|p| now < p.until).map(|p| {
                    (
                        p.node.clone(),
                        p.name.clone(),
                        p.until.duration_since(now).as_secs(),
                    )
                })
            }
            Phase::Locked => None,
        }
    }

    async fn tailnet_status(&self, what: &str) -> Result<SelfStatus, ResolveError> {
        let api =
            self.inner.tailnet.clone().ok_or_else(|| {
                ResolveError::Internal("this daemon does not ask Tailscale".into())
            })?;
        tailnet::status(api.as_ref())
            .await
            .map_err(|e| ResolveError::Provider {
                message: format!("cannot ask Tailscale {what}: {e}"),
                hint: Some("is Tailscale installed and running on this machine?".into()),
            })
    }

    /// [`Request::Phones`](crate::ipc::protocol::Request::Phones).
    pub(super) async fn phones(&self) -> Result<Response, ResolveError> {
        let status = self
            .tailnet_status("which phones are on this tailnet")
            .await?;
        let mut phones: Vec<PhoneChoice> = (status.peers.iter())
            .filter(|p| p.is_phone() && !p.machine.is_empty())
            .map(|p| PhoneChoice {
                name: p.machine.clone(),
                node: p.node.clone(),
                os: p.os.clone(),
            })
            .collect();
        phones.sort_by(|a, b| (&a.name, &a.node).cmp(&(&b.name, &b.node)));
        Ok(Response::Phones { phones })
    }

    /// [`Request::PhonePair`](crate::ipc::protocol::Request::PhonePair):
    /// `machine` is a phone's name or node id.
    pub(super) async fn phone_pair(
        &self,
        machine: &str,
        passphrase: Passphrase,
    ) -> Result<Response, ResolveError> {
        // The page is served only while unlocked, and the pairing lives in
        // the session.
        if self.is_locked() {
            return Err(ResolveError::Locked);
        }
        let passphrase = self.prove_human(passphrase).await?;
        let status = self
            .tailnet_status(&format!("which machine {machine} is"))
            .await?;
        let by_node: Vec<&Peer> = status.peers.iter().filter(|p| p.node == machine).collect();
        let named = if by_node.is_empty() {
            status.peers_named(machine)
        } else {
            by_node
        };
        let peer = match named.as_slice() {
            [peer] if !peer.machine.is_empty() => *peer,
            [] | [_] => {
                return Err(ResolveError::Config(format!(
                    "no other machine on this tailnet is named {machine}"
                )));
            }
            _ => {
                return Err(ResolveError::Config(format!(
                    "more than one machine on this tailnet is named {machine}; \
                     give its full MagicDNS name"
                )));
            }
        };
        if !peer.is_phone() {
            return Err(ResolveError::Config(format!(
                "{} is not a phone or a tablet, as Tailscale tells it",
                peer.machine
            )));
        }
        let port = self.phone_port().map_err(ResolveError::Config)?;
        let site = page_site(&status, port).map_err(|message| ResolveError::Provider {
            message,
            hint: Some(
                "turn on MagicDNS and HTTPS certificates for the tailnet in Tailscale's admin \
                 console, under DNS, then try again"
                    .into(),
            ),
        })?;
        let until = Instant::now() + PHONE_PAIRING;
        {
            let mut st = self.inner.state();
            let Phase::Unlocked(session) = &mut st.phase else {
                return Err(ResolveError::Locked);
            };
            session.pairing = Some(Box::new(Pairing {
                node: peer.node.clone(),
                name: peer.machine.clone(),
                passphrase,
                until,
                challenge: None,
            }));
        }
        tokio::spawn(end_pairing(std::sync::Arc::downgrade(&self.inner), until));
        self.inner.phone_changed();
        info!(phone = %peer.machine, "pairing a phone");
        Ok(Response::PhonePairing {
            name: peer.machine.clone(),
            url: site.origin,
            seconds: PHONE_PAIRING.as_secs(),
        })
    }

    /// [`Request::PhonePairStop`](crate::ipc::protocol::Request::PhonePairStop).
    pub(super) fn phone_pair_stop(&self) -> Response {
        if let Phase::Unlocked(session) = &mut self.inner.state().phase {
            session.pairing = None;
        }
        self.inner.phone_changed();
        Response::PhonePairStopped
    }

    /// What `status` says of the page; none when no phone is paired or
    /// being paired, which is all that is known while locked.
    pub(super) fn phone_status(&self) -> Option<Box<PhoneStatus>> {
        let paired = self.paired_phone();
        let pairing = self.pairing();
        if paired.is_none() && pairing.is_none() {
            return None;
        }
        let p = self.inner.phone();
        Some(Box::new(PhoneStatus {
            paired: paired.map(|phone| PhoneView {
                name: phone.name,
                node: phone.node,
                paired: phone.paired,
                seen: p.seen,
            }),
            url: p.url.clone(),
            problem: p.problem.clone(),
            pairing: pairing.map(|(_, name, left)| PhonePairingView { name, left }),
            last: p.last.clone(),
        }))
    }

    /// Remembers how the request `prompt` showed ended: `reply` is a
    /// person's answer, or none when it ended without one, having timed
    /// out or not.
    pub(super) fn note_answer(
        &self,
        prompt: &ApprovalPrompt,
        reply: Option<&Reply>,
        timed_out: bool,
    ) {
        let (outcome, by) = match reply {
            Some(Reply::Desk(Some(_))) => (Outcome::Approved, Some(Place::Desk)),
            Some(Reply::Desk(None)) => (Outcome::Denied, Some(Place::Desk)),
            Some(Reply::Phone(true)) => (Outcome::Approved, Some(Place::Phone)),
            Some(Reply::Phone(false)) => (Outcome::Denied, Some(Place::Phone)),
            None if timed_out => (Outcome::TimedOut, None),
            None => (Outcome::Ended, None),
        };
        let time = unix_now();
        {
            let mut p = self.inner.phone();
            if by == Some(Place::Phone) {
                p.last = Some(PhoneAnswer {
                    id: prompt.id,
                    project: prompt.project.clone(),
                    env: prompt.env.clone(),
                    approved: outcome == Outcome::Approved,
                    time,
                });
            }
            p.recent.push_front(Answered {
                id: prompt.id,
                project: prompt.project.clone(),
                env: prompt.env.clone(),
                command: prompt.command.clone(),
                outcome,
                by,
                time,
            });
            p.recent.truncate(RECENT);
        }
        self.inner.phone_seq.send_modify(|n| *n += 1);
    }

    /// The nodes the page is for now: the paired phone and the one being
    /// paired. None while the daemon is locked.
    pub fn phone_nodes(&self) -> Vec<String> {
        let mut nodes: Vec<String> = self.paired_phone().map(|p| p.node).into_iter().collect();
        if let Some((node, ..)) = self.pairing()
            && !nodes.contains(&node)
        {
            nodes.push(node);
        }
        nodes
    }

    /// Waits until [`Self::phone_nodes`] may have changed.
    pub async fn phone_woken(&self) {
        self.inner.phone_woken.notified().await;
    }

    /// The port `[phone] port` in `config.toml` names, or why it cannot
    /// be read.
    pub fn phone_port(&self) -> Result<u16, String> {
        self.registry()
            .map(|r| r.config.phone.port)
            .map_err(|e| format!("the configuration does not load: {e}"))
    }

    /// What the page's supervisor found: where the page is served, or why
    /// it is not.
    pub fn set_phone_serving(&self, url: Option<String>, problem: Option<String>) {
        let mut p = self.inner.phone();
        p.url = url;
        p.problem = problem;
    }

    fn phone_version(&self) -> u64 {
        // Both only grow, so their sum changes when either does.
        *self.inner.approvals_changed.borrow() + *self.inner.phone_seq.borrow()
    }

    /// What the page shows the phone whose node is `node`.
    pub fn phone_page(&self, node: &str) -> PhonePage {
        // Before looking, so a change after it gives another version.
        let version = self.phone_version();
        let paired = self.paired_phone().is_some_and(|p| p.node == node);
        let pairing = (self.pairing())
            .filter(|(n, ..)| n == node)
            .map(|(.., left)| left);
        let (prompts, recent) = if paired {
            let prompts = (self.inner.approvals().prompts().into_iter())
                .map(|prompt| PagePrompt {
                    here: on_phone(&prompt.reason),
                    prompt,
                })
                .collect();
            let mut p = self.inner.phone();
            p.seen = Some(unix_now());
            (prompts, p.recent.iter().cloned().collect())
        } else {
            (Vec::new(), Vec::new())
        };
        PhonePage {
            version,
            paired,
            pairing,
            prompts,
            recent,
        }
    }

    /// Waits, for at most `wait`, until the page's state is no longer the
    /// one whose version is `seen`.
    pub async fn phone_page_wait(&self, seen: u64, wait: Duration) {
        // Before looking, so no change after it is missed.
        let mut approvals = self.inner.approvals_changed.subscribe();
        let mut phone = self.inner.phone_seq.subscribe();
        let until = Instant::now() + wait;
        while self.phone_version() == seen {
            let changed = async {
                tokio::select! {
                    c = approvals.changed() => c.is_ok(),
                    c = phone.changed() => c.is_ok(),
                }
            };
            if !matches!(tokio::time::timeout_at(until, changed).await, Ok(true)) {
                return;
            }
        }
    }

    /// The page starts making the passkey of the phone being paired, whose
    /// node is `node`.
    pub fn phone_pair_begin(&self, node: &str) -> Result<PairBegin, PhoneError> {
        let bytes = challenge()?;
        let mut st = self.inner.state();
        let Phase::Unlocked(session) = &mut st.phase else {
            return Err(PhoneError::Locked);
        };
        let pairing = (session.pairing.as_mut())
            .filter(|p| p.node == node && Instant::now() < p.until)
            .ok_or(PhoneError::NotPairing)?;
        pairing.challenge = Some(bytes);
        Ok(PairBegin {
            challenge: bytes,
            name: pairing.name.clone(),
        })
    }

    /// The phone `peer`, being paired, made its passkey on `site`: pairs
    /// it, writing the store with the passphrase the pairing started with.
    /// `client_data` and `auth_data` are what [`webauthn::register`] takes.
    pub async fn phone_pair_finish(
        &self,
        site: &Site,
        peer: &RemotePeer,
        client_data: &[u8],
        auth_data: &[u8],
    ) -> Result<(), PhoneError> {
        let (passphrase, name, until, challenge) = {
            let mut st = self.inner.state();
            let Phase::Unlocked(session) = &mut st.phase else {
                return Err(PhoneError::Locked);
            };
            let pairing = (session.pairing.as_mut())
                .filter(|p| p.node == peer.node && Instant::now() < p.until)
                .ok_or(PhoneError::NotPairing)?;
            let challenge = pairing.challenge.take().ok_or(PhoneError::NoChallenge)?;
            (
                pairing.passphrase.copy(),
                pairing.name.clone(),
                pairing.until,
                challenge,
            )
        };
        let caller = Caller::remote(peer.named());
        let passkey = match webauthn::register(site, &challenge, client_data, auth_data) {
            Ok(passkey) => passkey,
            Err(e) => {
                self.phone_event("phone paired", Decision::Denied, &caller, |event| {
                    event.reason = Some(e.to_string());
                });
                return Err(e.into());
            }
        };
        let phone = PairedPhone {
            name: name.clone(),
            node: peer.node.clone(),
            credential: webauthn::encode(&passkey.credential),
            key: webauthn::encode(&passkey.key),
            paired: unix_now(),
        };
        let change = self
            .store_update(passphrase, None, move |st| Ok(st.pair_phone(phone)))
            .await
            .map_err(|e| PhoneError::Failed(format!("cannot save the pairing: {e}")))?;
        // This pairing is done; one started meanwhile goes on.
        if let Phase::Unlocked(session) = &mut self.inner.state().phase
            && session.pairing.as_ref().is_some_and(|p| p.until == until)
        {
            session.pairing = None;
        }
        info!(phone = %name, ?change, "paired a phone");
        self.phone_event("phone paired", Decision::Allowed, &caller, |_| {});
        self.inner.phone_changed();
        Ok(())
    }

    /// The paired phone, if `node` is it.
    fn paired_as(&self, node: &str) -> Result<PairedPhone, PhoneError> {
        if self.is_locked() {
            return Err(PhoneError::Locked);
        }
        (self.paired_phone())
            .filter(|p| p.node == node)
            .ok_or(PhoneError::NotPaired)
    }

    /// The paired phone, whose node is `node`, starts approving request
    /// `id`: a challenge for that request alone.
    pub fn phone_approve_begin(&self, node: &str, id: u64) -> Result<ApproveBegin, PhoneError> {
        let phone = self.paired_as(node)?;
        let here = (self.inner.approvals().prompt(id))
            .map(|p| on_phone(&p.reason))
            .ok_or(PhoneError::Gone)?;
        if !here {
            return Err(PhoneError::DeskOnly);
        }
        let bytes = challenge()?;
        self.inner.phone().challenge = Some(Challenge {
            id,
            bytes,
            until: Instant::now() + CHALLENGE_LIFE,
        });
        Ok(ApproveBegin {
            challenge: bytes,
            credential: phone.credential,
        })
    }

    /// The paired phone `peer` approves request `id` with its passkey's
    /// signature over the challenge [`Self::phone_approve_begin`] gave for
    /// it; the rest is what [`webauthn::verify`] takes. The challenge is
    /// spent whether or not the signature holds.
    pub fn phone_approve(
        &self,
        site: &Site,
        peer: &RemotePeer,
        id: u64,
        client_data: &[u8],
        auth_data: &[u8],
        signature: &[u8],
    ) -> Result<(), PhoneError> {
        let phone = self.paired_as(&peer.node)?;
        let challenge = (self.inner.phone().challenge.take())
            .filter(|c| c.id == id && Instant::now() < c.until)
            .ok_or(PhoneError::NoChallenge)?;
        let key = webauthn::decode(&phone.key).ok_or_else(|| {
            PhoneError::Failed("the paired phone's key in the local store is not one".into())
        })?;
        if let Err(e) = webauthn::verify(
            site,
            &challenge.bytes,
            &key,
            client_data,
            auth_data,
            signature,
        ) {
            warn!(phone = %peer.machine, id, reason = %e, "refused an approval from the phone");
            let prompt = self.inner.approvals().prompt(id).cloned();
            self.phone_event(
                "phone approve",
                Decision::Denied,
                &Caller::remote(peer.named()),
                |event| {
                    event.reason = Some(e.to_string());
                    if let Some(p) = prompt {
                        (event.project, event.env) = (Some(p.project), Some(p.env));
                    }
                },
            );
            return Err(e.into());
        }
        self.phone_answer(peer, id, true)
    }

    /// The paired phone `peer` denies request `id`. As in the app, a
    /// denial takes no proof.
    pub fn phone_deny(&self, peer: &RemotePeer, id: u64) -> Result<(), PhoneError> {
        self.paired_as(&peer.node)?;
        self.phone_answer(peer, id, false)
    }

    fn phone_answer(&self, peer: &RemotePeer, id: u64, approved: bool) -> Result<(), PhoneError> {
        let prompt = (self.inner.approvals().prompt(id).cloned()).ok_or(PhoneError::Gone)?;
        if approved && !on_phone(&prompt.reason) {
            return Err(PhoneError::DeskOnly);
        }
        // Before it counts, as the prompt itself was recorded before it
        // was shown. A denial that cannot be recorded still denies.
        if let Some(log) = &self.inner.audit {
            let action = if approved {
                "phone approve"
            } else {
                "phone deny"
            };
            let mut event = Event::new(action, Decision::Allowed, &Caller::remote(peer.named()));
            (event.project, event.env) = (Some(prompt.project.clone()), Some(prompt.env.clone()));
            event.keys = prompt.keys.iter().map(ToString::to_string).collect();
            if let Err(e) = log.append(&event) {
                warn!(error = %e, path = %log.path().display(), "cannot write the audit log");
                if approved {
                    return Err(PhoneError::Failed(format!(
                        "an approval counts only once the audit log records it, and {} cannot \
                         be written",
                        log.path().display()
                    )));
                }
            }
        }
        let waiting = self.inner.approvals().pending.remove(&id);
        let Some((_, _, reply)) = waiting else {
            return Err(PhoneError::Gone);
        };
        // Fails only if the request stopped waiting just now; it is then
        // refused anyway.
        let _ = reply.send(Reply::Phone(approved));
        self.inner.approvals_changed.send_modify(|n| *n += 1);
        info!(id, approved, phone = %peer.machine, "answered an approval on the phone");
        Ok(())
    }

    /// Records something the phone did that is not a request's answer. The
    /// log failing does not undo it.
    fn phone_event(
        &self,
        action: &str,
        decision: Decision,
        caller: &Caller,
        fill: impl FnOnce(&mut Event),
    ) {
        let Some(log) = &self.inner.audit else {
            return;
        };
        let mut event = Event::new(action, decision, caller);
        fill(&mut event);
        if let Err(e) = log.append(&event) {
            warn!(error = %e, path = %log.path().display(), "cannot write the audit log");
        }
    }
}
