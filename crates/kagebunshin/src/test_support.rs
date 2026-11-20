//! Test helpers shared by unit and integration tests. Not part of the API.
//!
//! A `Canary` is a freshly generated fake secret. Tests put it wherever a real
//! value would flow and then assert it never shows up in output, logs or error
//! messages.
//!
//! [`FakeSources`] stands in for every provider: a map from secret name to
//! keys, shared with the test so values can change between fetches.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    reason = "test helpers; compiled into the library only so integration tests can share them"
)]

use std::collections::BTreeMap;
use std::hash::{BuildHasher, RandomState};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use async_trait::async_trait;
use tokio::sync::{oneshot, watch};

use crate::config::{AwsSettings, Config, Registry, Select, SourceSpec};
use crate::daemon::{Daemon, SourceFactory};
use crate::ipc::protocol::Caller;
use crate::ipc::server::{Server, ServerConfig, ServerError};
use crate::secret::SecretValue;
use crate::source::{Backend, Entry, Health, Listed, ProviderStatus, Source, SourceError};
use crate::store::{STORE_FILE, Store, StoreFile};
use crate::types::{Origin, Provider};

pub struct Canary(String);

impl Canary {
    pub fn new() -> Self {
        // RandomState is seeded from OS randomness; good enough for a test marker.
        let a = RandomState::new().hash_one(0u8);
        let b = RandomState::new().hash_one(1u8);
        Self(format!("kbcanary{a:016x}{b:016x}"))
    }

    pub fn value(&self) -> &str {
        &self.0
    }
}

impl Default for Canary {
    fn default() -> Self {
        Self::new()
    }
}

/// Panics if `haystack` contains the canary. The panic message never prints the
/// haystack itself, so a failure does not spread the value further.
#[track_caller]
pub fn assert_no_canary(canary: &Canary, haystack: &str) {
    if let Some(at) = haystack.find(canary.value()) {
        panic!(
            "canary value leaked at byte {at} of a {}-byte string",
            haystack.len()
        );
    }
}

/// The caller the daemon would see for process `pid` of this user.
pub fn caller_for(pid: i32) -> Caller {
    Caller {
        uid: crate::sys::effective_uid(),
        gid: 0,
        pid,
        start_time: crate::sys::process_start(pid).expect("a live process"),
        remote: None,
    }
}

/// The caller the daemon would see for this process.
pub fn this_process() -> Caller {
    caller_for(std::process::id() as i32)
}

/// An in-process daemon on its own thread and runtime, stopped on drop.
/// Everything it logs, at every level, is kept for [`TestDaemon::logs`].
pub struct TestDaemon {
    socket: PathBuf,
    stop: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
    logs: Arc<Mutex<Vec<u8>>>,
}

#[derive(Clone)]
struct LogSink(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl TestDaemon {
    /// Binds `<dir>/kb/kagebunshind.sock`. `dir` should be a fresh temp dir.
    pub fn start(dir: &Path) -> Result<Self, ServerError> {
        Self::start_with(ServerConfig::new(dir.join("kb").join("kagebunshind.sock")))
    }

    /// A daemon with no projects.
    pub fn start_with(cfg: ServerConfig) -> Result<Self, ServerError> {
        let empty = || Registry::new(Config::default(), Vec::new());
        // Next to the socket, so in the caller's temp dir; never created.
        let store = StoreFile::new(cfg.socket_path.with_file_name(STORE_FILE));
        let daemon = Daemon::new(Box::new(empty), Arc::new(FakeSources::default()), store);
        Self::start_with_daemon(cfg, daemon)
    }

    pub fn start_with_daemon(cfg: ServerConfig, daemon: Daemon) -> Result<Self, ServerError> {
        let server = Server::bind(cfg)?;
        let socket = server.socket_path().to_owned();
        let (stop, stopped) = oneshot::channel::<()>();
        let logs = Arc::new(Mutex::new(Vec::new()));
        let sink = LogSink(logs.clone());
        let thread = std::thread::spawn(move || {
            let subscriber = tracing_subscriber::fmt()
                .with_max_level(tracing::Level::TRACE)
                .with_ansi(false)
                .with_writer(move || sink.clone())
                .finish();
            // A current-thread runtime: every task logs on this thread.
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("test runtime");
            tracing::subscriber::with_default(subscriber, || {
                rt.block_on(server.serve(daemon, async {
                    let _ = stopped.await;
                }))
            })
            .expect("serve");
        });
        Ok(Self {
            socket,
            stop: Some(stop),
            thread: Some(thread),
            logs,
        })
    }

    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// What the daemon has logged so far.
    pub fn logs(&self) -> String {
        String::from_utf8_lossy(&self.logs.lock().unwrap()).into_owned()
    }
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[derive(Debug, Clone)]
enum FakeSecret {
    Keys(Vec<(String, String)>),
    /// A plain string, not a JSON object: read whole only with `key`.
    Plain(String),
    Fail,
}

/// A [`SourceFactory`] for every provider, backed by an in-memory map from
/// secret name to keys; it ignores the local store. A secret's keys come out in the order given; a
/// prefix reads matching secrets in name order and, like the AWS source,
/// fails when it matches nothing unless the source is optional. A `key` on
/// a single-secret selector is ignored, except by a plain-string secret
/// ([`FakeSources::set_plain`]). Values are copied when a fetch
/// starts, so a fetch held at a [`Gate`] returns what was set before it.
pub struct FakeSources {
    secrets: Mutex<BTreeMap<String, FakeSecret>>,
    /// Sources made to fetch with, counted so tests see how many fetches
    /// started.
    fetches: Arc<AtomicUsize>,
    /// Secrets whose values were read, counted once per read.
    reads: Arc<AtomicUsize>,
    /// What fetches starting now wait on.
    gate: Mutex<watch::Receiver<bool>>,
    /// Keeps the always-open gate's channel alive.
    open: watch::Sender<bool>,
}

impl Default for FakeSources {
    fn default() -> Self {
        let open = watch::Sender::new(true);
        Self {
            secrets: Mutex::default(),
            fetches: Arc::default(),
            reads: Arc::default(),
            gate: Mutex::new(open.subscribe()),
            open,
        }
    }
}

/// Holds the fetches that started while it was current; see
/// [`FakeSources::hold`].
pub struct Gate(watch::Sender<bool>);

impl Gate {
    pub fn open(&self) {
        self.0.send_replace(true);
    }
}

impl FakeSources {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Sets secret `name` to these keys and values.
    pub fn set(&self, name: &str, keys: &[(&str, &str)]) -> &Self {
        let keys = keys
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        self.put(name, FakeSecret::Keys(keys))
    }

    /// Sets secret `name` to a plain string, which only a single-secret
    /// selector with `key` reads; under a prefix it is left out.
    pub fn set_plain(&self, name: &str, value: &str) -> &Self {
        self.put(name, FakeSecret::Plain(value.to_owned()))
    }

    /// Makes reading secret `name` fail with access denied.
    pub fn fail(&self, name: &str) -> &Self {
        self.put(name, FakeSecret::Fail)
    }

    fn put(&self, name: &str, secret: FakeSecret) -> &Self {
        self.secrets.lock().unwrap().insert(name.to_owned(), secret);
        self
    }

    /// How many source fetches have started.
    pub fn fetches(&self) -> usize {
        self.fetches.load(Ordering::SeqCst)
    }

    /// How many secret values have been read, over all fetches.
    pub fn reads(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }

    /// Fetches that start from now on wait until the returned gate opens,
    /// or until [`Self::pass`] if the gate is dropped unopened.
    pub fn hold(&self) -> Gate {
        let gate = watch::Sender::new(false);
        *self.gate.lock().unwrap() = gate.subscribe();
        Gate(gate)
    }

    /// Fetches that start from now on do not wait.
    pub fn pass(&self) {
        *self.gate.lock().unwrap() = self.open.subscribe();
    }
}

#[async_trait]
impl SourceFactory for FakeSources {
    /// Every provider reads the same fake secrets.
    async fn backend(
        &self,
        provider: Provider,
        _aws: &AwsSettings,
        _store: Option<&Arc<Store>>,
    ) -> Result<Box<dyn Backend>, SourceError> {
        Ok(Box::new(FakeBackend {
            provider,
            secrets: self.secrets.lock().unwrap().clone(),
            fetches: self.fetches.clone(),
            reads: self.reads.clone(),
            gate: self.gate.lock().unwrap().clone(),
        }))
    }
}

struct FakeBackend {
    provider: Provider,
    secrets: BTreeMap<String, FakeSecret>,
    fetches: Arc<AtomicUsize>,
    reads: Arc<AtomicUsize>,
    gate: watch::Receiver<bool>,
}

#[async_trait]
impl Backend for FakeBackend {
    fn provider(&self) -> Provider {
        self.provider
    }

    async fn list(&self, prefix: &str) -> Result<Vec<Listed>, SourceError> {
        Ok(self
            .secrets
            .iter()
            .filter(|(n, _)| n.starts_with(prefix))
            .map(|(name, s)| Listed {
                id: Origin::new(self.provider, name.clone()),
                name: name.clone(),
                title: None,
                keys: match s {
                    FakeSecret::Keys(keys) => keys
                        .iter()
                        .map(|(k, _)| k.parse().expect("fake key names are valid"))
                        .collect(),
                    FakeSecret::Plain(_) | FakeSecret::Fail => Vec::new(),
                },
                plain: false,
                unread: None,
            })
            .collect())
    }

    async fn status(&self) -> ProviderStatus {
        ProviderStatus {
            provider: self.provider,
            detail: "fake".into(),
            health: Health::Ok,
            expires: None,
        }
    }

    fn source(&self, spec: &SourceSpec) -> Box<dyn Source> {
        self.fetches.fetch_add(1, Ordering::SeqCst);
        Box::new(FakeSource {
            spec: spec.clone(),
            secrets: self.secrets.clone(),
            reads: self.reads.clone(),
            gate: self.gate.clone(),
        })
    }
}

struct FakeSource {
    spec: SourceSpec,
    secrets: BTreeMap<String, FakeSecret>,
    reads: Arc<AtomicUsize>,
    gate: watch::Receiver<bool>,
}

#[async_trait]
impl Source for FakeSource {
    fn describe(&self) -> String {
        crate::daemon::resolve::describe(&self.spec)
    }

    async fn names(&self) -> Result<Vec<String>, SourceError> {
        // A gate dropped unopened closes its channel, which also lets the
        // fetch through.
        let _ = self.gate.clone().wait_for(|open| *open).await;
        Ok(match &self.spec.select {
            Select::Secret { name, .. } => vec![name.clone()],
            Select::Secrets(names) => names.clone(),
            Select::Prefix(p) => {
                let names: Vec<String> = self
                    .secrets
                    .keys()
                    .filter(|n| n.starts_with(p.as_str()))
                    .cloned()
                    .collect();
                if names.is_empty() && !self.spec.optional {
                    return Err(SourceError::NoMatch {
                        what: self.describe(),
                    });
                }
                names
            }
        })
    }

    async fn fetch(&self, names: &[String]) -> Result<Vec<Entry>, SourceError> {
        self.reads.fetch_add(names.len(), Ordering::SeqCst);
        let mut out = Vec::new();
        for name in names {
            let name = name.clone();
            match self.secrets.get(&name) {
                None => return Err(SourceError::NotFound { name }),
                Some(FakeSecret::Fail) => return Err(SourceError::AccessDenied { name }),
                Some(FakeSecret::Plain(v)) => match &self.spec.select {
                    Select::Secret { key: Some(key), .. } => out.push(Entry {
                        key: key.clone(),
                        value: SecretValue::new(v.clone()),
                        origin: Origin::new(self.spec.provider, name.clone()),
                    }),
                    Select::Prefix(_) => {}
                    _ => {
                        return Err(SourceError::Malformed {
                            name,
                            problem: crate::source::Problem::NotAnObject,
                        });
                    }
                },
                Some(FakeSecret::Keys(keys)) => {
                    for (k, v) in keys {
                        out.push(Entry {
                            key: k.parse().expect("fake key names are valid"),
                            value: SecretValue::new(v.clone()),
                            origin: Origin::new(self.spec.provider, name.clone()),
                        });
                    }
                }
            }
        }
        Ok(out)
    }
}

/// For tests that change process-wide settings: in the test process, runs
/// the test `name` (its full path, e.g. `secret::tests::x`) again in a child
/// process, checks it passed, and returns false; in that child, returns
/// true, so the caller goes on with the test body.
pub fn in_child(name: &str) -> bool {
    in_child_with(name, &[])
}

/// [`in_child`], with `vars` set in the child's environment.
pub fn in_child_with(name: &str, vars: &[(&str, &std::ffi::OsStr)]) -> bool {
    const CHILD: &str = "KAGEBUNSHIN_TEST_CHILD";
    if std::env::var_os(CHILD).is_some() {
        return true;
    }
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([name, "--exact", "--test-threads=1", "--nocapture"])
        .env(CHILD, "1")
        .envs(vars.iter().copied())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("1 passed"),
        "{name} failed in a child process:\n{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    false
}

/// In a child process from [`in_child`]: lowers `RLIMIT_MEMLOCK` to 0 and
/// says whether that stops memory being locked. It does not on macOS,
/// which does not enforce the limit.
pub fn without_locked_memory() -> bool {
    crate::sys::set_memlock_limit(0).unwrap();
    let enforced = crate::sys::LockedPages::new(1).is_err();
    if !enforced {
        println!("RLIMIT_MEMLOCK is not enforced here; skipping");
    }
    enforced
}

/// A fake `pass-cli`: a shell script that answers from JSON files under its
/// root, as Proton's would. It logs every call (`calls`), and every call
/// but `login` that sees a token in its environment (`token-in-env`).
/// `login` takes only [`FakePassCli::token`] and starts a session in
/// `PROTON_PASS_SESSION_DIR`; every other call but `logout` fails without
/// one. [`FakePassCli::expire`] ends the session at the next call.
pub struct FakePassCli {
    root: PathBuf,
    pub token: String,
    vaults: Mutex<Vec<serde_json::Value>>,
    items: Mutex<BTreeMap<String, Vec<serde_json::Value>>>,
    /// As `items`, each with its content: what `--show-secrets` lists.
    whole: Mutex<BTreeMap<String, Vec<serde_json::Value>>>,
}

const FAKE_PASS_CLI: &str = r#"#!/bin/sh
F="$(dirname "$0")"
echo "$*" >> "$F/calls"
if [ -n "$PROTON_PASS_PERSONAL_ACCESS_TOKEN" ] && [ "$1" != login ]; then
  echo "token-in-env $1" >> "$F/calls"
fi
printf '%s %s' "$PROTON_PASS_SESSION_DIR" "$PROTON_PASS_KEY_PROVIDER" > "$F/env"
S="$PROTON_PASS_SESSION_DIR/session"
if [ -e "$F/expire" ]; then rm -f "$F/expire" "$S"; fi
case "$1" in
  login)
    if [ "$PROTON_PASS_PERSONAL_ACCESS_TOKEN" != "$(cat "$F/token")" ]; then
      echo "error: invalid or expired personal access token" >&2; exit 1
    fi
    touch "$S"; echo login >> "$F/logins"; exit 0;;
  logout) rm -f "$S"; exit 0;;
esac
[ -e "$S" ] || { echo "error: session expired, log in again" >&2; exit 1; }
cmd=$1; sub=$2; share=; item=; whole=
while [ $# -gt 0 ]; do
  case "$1" in
    --share-id) share=$2; shift;;
    --item-id) item=$2; shift;;
    --show-secrets) whole=1;;
  esac
  shift
done
if [ -n "$whole" ] && [ -e "$F/agent" ]; then
  echo "error: --show-secrets is not allowed with agent sessions" >&2; exit 1
fi
case "$cmd $sub" in
  "info "*) echo "logged in";;
  "vault list") cat "$F/vaults.json";;
  "item list")
    if [ -n "$whole" ]; then list="$F/whole-$share.json"; else list="$F/items-$share.json"; fi
    cat "$list" 2>/dev/null || echo '{"items":[],"folders":[]}';;
  "item view") cat "$F/item-$share-$item.json" || exit 1;;
  *) echo "error: unknown command $cmd $sub" >&2; exit 2;;
esac
"#;

impl FakePassCli {
    /// The fake in `root`, an empty directory, taking only `token`.
    pub fn new(root: &Path, token: &str) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let bin = root.join("pass-cli");
        std::fs::write(&bin, FAKE_PASS_CLI).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(root.join("token"), token).unwrap();
        let fake = Self {
            root: root.to_owned(),
            token: token.to_owned(),
            vaults: Mutex::default(),
            items: Mutex::default(),
            whole: Mutex::default(),
        };
        fake.write("vaults.json", &serde_json::json!({ "vaults": [] }));
        fake
    }

    fn write(&self, file: &str, json: &serde_json::Value) {
        std::fs::write(self.root.join(file), json.to_string()).unwrap();
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn bin(&self) -> PathBuf {
        self.root.join("pass-cli")
    }

    pub fn session_dir(&self) -> PathBuf {
        self.root.join("session")
    }

    /// How the daemon would run it, with its session under the root.
    pub fn cli(&self) -> crate::source::proton::PassCli {
        crate::source::proton::PassCli {
            bin: self.bin(),
            session_dir: Some(self.session_dir()),
            key_provider: "fs".into(),
            listing: crate::source::proton::Listing::default(),
        }
    }

    pub fn vault(&self, name: &str, share: &str) -> &Self {
        let mut v = self.vaults.lock().unwrap();
        v.push(serde_json::json!({ "name": name, "vault_id": format!("v-{share}"), "share_id": share }));
        self.write("vaults.json", &serde_json::json!({ "vaults": *v }));
        self
    }

    /// An item of type `kind` whose type-specific content is `content`.
    pub fn item(&self, share: &str, id: &str, kind: &str, content: serde_json::Value) -> &Self {
        self.item_with(share, id, kind, content, serde_json::json!([]))
    }

    /// As [`Self::item`], with the fields `extra` beside its content.
    fn item_with(
        &self,
        share: &str,
        id: &str,
        kind: &str,
        content: serde_json::Value,
        extra: serde_json::Value,
    ) -> &Self {
        let title = format!("item {id}");
        let mut items = self.items.lock().unwrap();
        let list = items.entry(share.to_owned()).or_default();
        list.push(serde_json::json!({
            "id": id, "share_id": share, "vault_id": format!("v-{share}"),
            "state": "Active", "flags": 0, "title": title, "item_type": kind,
        }));
        self.write(
            &format!("items-{share}.json"),
            &serde_json::json!({ "items": list, "folders": [] }),
        );
        let variant = match kind {
            "login" => "Login",
            "note" => "Note",
            _ => "Custom",
        };
        // Listed with its content, an item has no `item_type` or `title`
        // of its own: the content says both.
        let mut whole = self.whole.lock().unwrap();
        let list = whole.entry(share.to_owned()).or_default();
        list.push(serde_json::json!({
            "id": id, "share_id": share, "vault_id": format!("v-{share}"),
            "content": {
                "title": title, "note": "", "item_uuid": id,
                "content": { variant: content.clone() }, "extra_fields": extra.clone(),
            },
            "state": "Active", "flags": [],
        }));
        self.write(
            &format!("whole-{share}.json"),
            &serde_json::json!({ "items": list, "folders": [] }),
        );
        self.write(
            &format!("item-{share}-{id}.json"),
            &serde_json::json!({ "item": {
                "id": id, "share_id": share,
                "content": {
                    "title": title, "note": "", "content": { variant: content },
                    "extra_fields": extra,
                },
            }}),
        );
        self
    }

    /// An API key item as Proton Pass's own template makes one: nothing in
    /// the custom content, and both fields beside it, hidden, among others.
    pub fn template_key(&self, share: &str, id: &str, key: &str, value: &str) -> &Self {
        self.item_with(
            share,
            id,
            "custom",
            serde_json::json!({ "sections": [] }),
            serde_json::json!([
                { "name": "API key", "content": { "Hidden": key } },
                { "name": "Secret", "content": { "Hidden": value } },
                { "name": "Expiry Date", "content": { "Timestamp": 0 } },
                { "name": "Permissions", "content": { "Text": "" } },
            ]),
        )
    }

    /// An API key item: a custom item whose `name_field` holds `key` and
    /// whose `Secret` field holds `value`; `title` is free text.
    pub fn api_key(
        &self,
        share: &str,
        id: &str,
        title: &str,
        name_field: &str,
        key: &str,
        value: &str,
    ) -> &Self {
        self.item(
            share,
            id,
            "custom",
            serde_json::json!({ "title_note": title, "sections": [{ "section_name": "Key", "section_fields": [
                { "name": name_field, "content": { "Text": key } },
                { "name": "Secret", "content": { "Hidden": value } },
            ]}]}),
        )
    }

    /// From now on the session is an agent's, which may not list items
    /// with their content.
    pub fn agent(&self) {
        std::fs::write(self.root.join("agent"), "").unwrap();
    }

    /// Ends the session at the next call, as two hours passing would.
    pub fn expire(&self) {
        std::fs::write(self.root.join("expire"), "").unwrap();
    }

    /// Makes `login` refuse every token, as revoking it in Proton would.
    pub fn revoke(&self) {
        std::fs::write(self.root.join("token"), "revoked").unwrap();
    }

    fn read(&self, file: &str) -> String {
        std::fs::read_to_string(self.root.join(file)).unwrap_or_default()
    }

    /// Every call's arguments, one per line.
    pub fn calls(&self) -> String {
        self.read("calls")
    }

    pub fn logins(&self) -> usize {
        self.read("logins").lines().count()
    }

    /// `PROTON_PASS_SESSION_DIR` and `PROTON_PASS_KEY_PROVIDER` of the last
    /// call.
    pub fn env(&self) -> String {
        self.read("env")
    }
}
