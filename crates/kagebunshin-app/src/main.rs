//! A window onto the kagebunshin daemon: each project's keys, one
//! environment at a time, and where each comes from, the sources of each
//! environment in order, and of the machine its providers, its remote
//! endpoint with the grants to other machines, the phone paired to approve
//! requests, and the audit log. Values
//! stay hidden: one shows only when a person reveals it with the store's
//! passphrase, and only until it is hidden.
//!
//! It edits project files the way the CLI does, through
//! [`kagebunshin::cli::edit`]: adding, removing and reordering sources. It
//! locks, unlocks and resyncs through the daemon, and marks environments,
//! secrets and store keys sensitive there: the marks live in the encrypted
//! store, so each change takes the passphrase. It is the only place marks
//! change. Removing a sensitive mark is confirmed in the window first. An
//! environment marked sensitive, which the daemon hands to no one, shows
//! here once the passphrase is typed; one whose name looks like production
//! loads only when clicked.
//!
//! While it runs, `run` and `get` requests for values marked sensitive
//! wait here for approval: a dialog shows the command and its caller, and
//! the passphrase approves that one request; without the app they are
//! refused. A phone paired here, with the passphrase, can answer them too.
//!
//! It runs as one process for each daemon, with an icon in the tray
//! ([`shell`]). Closing the window leaves it there: nothing typed or
//! revealed outlives the window, and the request it was asking about is
//! denied. Each request is announced with a notification and waits in the
//! window, which is left where it is: opening it is the person's. Quit, in
//! the tray's menu, ends the process. Where there is no tray (macOS, no
//! session bus) closing the window ends it, as it did before.
//!
//! `kagebunshin app [--socket PATH]` opens it, or shows the one that runs;
//! `--hidden` starts it in the tray alone, as at login, and `--quit` ends
//! the one that runs. `cargo run -p kagebunshin-app [-- --socket PATH]`
//! does the same; `-- --snap out.png --scene unlocked --theme dark` renders
//! a scene headless, with no tray and nothing left running.

#![allow(
    clippy::large_types_passed_by_value,
    reason = "Paint, the theme bundle every view function takes, is Copy and passed by value"
)]

mod aws;
mod catalog;
mod daemon;
mod machine;
mod shell;

use std::collections::{BTreeSet, VecDeque};
use std::path::PathBuf;

use kagebunshin::audit::AuditLog;
use kagebunshin::cli::edit::{self, NewSource};
use kagebunshin::config::schema::{Profile, Region};
use kagebunshin::config::{ConfigDir, RemoteId};
use kagebunshin::daemon::resolve::{ACKNOWLEDGE_HINT, prod_like_profile};
use kagebunshin::ipc::paths::{default_socket_path, ensure_private_dir, socket_dir};
use kagebunshin::ipc::prompt::{Words, import_files, values_of};
use kagebunshin::ipc::protocol::{
    ApprovalPrompt, ApprovalReason, Fix, GrantView, ImportInto, ImportNames, KeyStatus, Proof,
    REMOTE_TOKEN_ENV, SharedSecret, Who, WireSecret,
};
use kagebunshin::source::aws_sm::read_with;
use kagebunshin::source::{Health, ProviderStatus};
use kagebunshin::store::Section;
use kagebunshin::types::{EnvName, KeyName, Origin, ProjectName, Provider};
use rune::tok::{self, TextStyle, Theme, radius, space, type_};
use rune::{
    Align, AppSpec, Color, Cx, El, Pixels, ScrollSpec, Shape, Span, TextEdit, Tx, Waker, canvas,
    col, el, row, text, text_input,
};

use crate::catalog::{Catalog, EnvView, ProjectView, SourceView};
use crate::daemon::{
    Approval, ApprovalAnswer, Approver, EnvReport, Grant, Mark, Problem, SocketClient, Worker,
};
use crate::machine::{
    Change, Column, Conn, Detail, Edit, Effect, Event, Machine, Marked, Notice, Pending, Purpose,
    Selection, Sharing, Shown, Unmarking, Unmarks, step,
};

/// The window's text, a size up from Rune's defaults.
const BODY: TextStyle = TextStyle::new(14.0, 400.0);
const TITLE: TextStyle = TextStyle::new(16.0, 600.0);
/// What a screen with nothing else on it is headed by.
const HEADLINE: TextStyle = TextStyle::new(20.0, 600.0);

#[expect(
    clippy::struct_excessive_bools,
    reason = "independent toggles of the window's views"
)]
struct App {
    catalog: Catalog,
    machine: Machine,
    worker: Option<Worker>,
    /// Where the daemon listens; `None` with why it could not be worked out.
    socket: Result<PathBuf, String>,
    /// Where project files are edited, or why they cannot be.
    config: Result<ConfigDir, String>,
    /// Off for scenes and tests: a fixed state, no daemon thread.
    live: bool,
    view: View,
    /// The environment of the project on show whose keys and sources are
    /// listed; see [`chosen`].
    env: Option<EnvName>,
    /// Filters the keys, by name.
    search: TextEdit,
    /// Only the keys in this state, if one is picked.
    filter: Option<Filter>,
    /// The keys as one list rather than grouped by secret.
    flat: bool,
    /// The key groups whose fold differs from how a list opens (see
    /// [`FOLD_FROM`]), by their id.
    flipped: BTreeSet<String>,
    form: AddForm,
    /// The store's passphrase as it is typed; secure, and cleared once sent.
    passphrase: TextEdit,
    /// What the passphrase field is up for.
    asking: Asking,
    /// The audit log, as read when Activity was opened.
    activity: Result<Activity, String>,
    /// Activity lists the lines about this project alone.
    activity_of: Option<ProjectName>,
    /// The setup warnings are listed.
    warnings_open: bool,
    /// Wakes the window from another thread; `None` until it is set up.
    waker: Option<Waker>,
    proton: TokenForm,
    /// Connecting AWS: the profile and region typed.
    aws_profile: TextEdit,
    aws_region: TextEdit,
    /// The profiles in the AWS configuration, as read when Providers opened.
    aws_profiles: Vec<String>,
    /// The last AWS login or connect started here.
    login: Option<aws::Login>,
    /// Watches for requests that need approval, and answers them.
    approver: Option<Approver>,
    /// The requests waiting for approval; the first is asked about.
    approvals: Vec<ApprovalPrompt>,
    /// The passphrase typed to approve one; secure, and cleared once sent.
    approval_passphrase: TextEdit,
    /// The values typed for the keys of the request asked about, when it
    /// asks for them: one field per key, in its order, secure. Kept until
    /// the daemon takes the answer, so a wrong passphrase costs no
    /// retyping, and cleared with the request.
    approval_values: Vec<TextEdit>,
    /// An answer is on its way to the daemon.
    answering: bool,
    /// Why the last answer failed.
    approval_error: Option<String>,
    /// The window's clock when `approvals` came, which is when each one's
    /// `left` was counted.
    approvals_at: f64,
    /// Seconds until the request asked about is denied unanswered, as the
    /// clock counts them down; `None` before the first tick, and from a
    /// daemon that does not say.
    approval_left: Option<u64>,
    /// Every key of the request asked about is listed, not the first few.
    approval_all_keys: bool,
    /// Whether the request asked about shows how it got here, why it
    /// waits and what approving does.
    approval_details: bool,
    /// What the app that runs reaches outside its window; none in scenes,
    /// tests and headless runs.
    desk: Option<Box<dyn Desk>>,
    /// The address a phone opens to be paired and its QR code, drawn once
    /// for each pairing.
    code: Option<(String, Pixels)>,
}

/// The desktop, as far as a request that waits needs it.
trait Desk {
    /// Tells the person, outside the window, that `prompt` waits.
    fn notify(&self, prompt: &ApprovalPrompt);
    /// A waker that runs `f` on the window's thread as it is called, where
    /// a plain wake leaves it to the next frame's poll.
    fn at_once(&self, f: fn(&mut App, &mut Tx) -> bool) -> Waker;
}

/// The window of the process that stays: in the tray, or where there is
/// none, for as long as its window is open.
struct Resident(rune::AppHandle<App>);

impl Desk for Resident {
    /// It stays up for as long as the request can wait.
    fn notify(&self, prompt: &ApprovalPrompt) {
        shell::notify(
            "kagebunshin: approval needed",
            &notice(prompt),
            std::time::Duration::from_secs(prompt.left.unwrap_or(120)),
        );
    }

    fn at_once(&self, f: fn(&mut App, &mut Tx) -> bool) -> Waker {
        let handle = self.0.clone();
        std::sync::Arc::new(move || handle.update_if(f))
    }
}

/// What the notification for `prompt` says: the program, the project and
/// the environment. Not the arguments: a notification outlives the
/// request in the desktop's history, and the window shows them.
fn notice(prompt: &ApprovalPrompt) -> String {
    let program = prompt
        .argv
        .first()
        .and_then(|a| std::path::Path::new(a).file_name()?.to_str())
        .map_or_else(|| "A command".to_owned(), |name| format!("`{name}`"));
    match &prompt.reason {
        ApprovalReason::Import { sections, .. } => {
            return format!(
                "{program} asks to import {} into the local store. Approve or deny it in the \
                 window.",
                import_files(sections)
            );
        }
        ApprovalReason::Type { .. } => {
            return format!(
                "{program} asks you to type {} for {}/{}. Type or deny it in the window.",
                values_of(&prompt.keys),
                prompt.project,
                prompt.env
            );
        }
        _ => {}
    }
    format!(
        "{program} asks for sensitive values of {}/{}. Approve or deny it in the window.",
        prompt.project, prompt.env
    )
}

/// An empty, hidden field for each key `prompt` asks a person to type the
/// value of, the first one focused; none for any other request.
fn value_fields(prompt: Option<&ApprovalPrompt>) -> Vec<TextEdit> {
    let Some(prompt) = prompt.filter(|p| matches!(p.reason, ApprovalReason::Type { .. })) else {
        return Vec::new();
    };
    let mut fields: Vec<TextEdit> = (prompt.keys.iter())
        .map(|_| TextEdit::new("").secure())
        .collect();
    if let Some(first) = fields.first_mut() {
        first.focused = true;
    }
    fields
}

/// Empties the fields values are typed into, and the passphrase's.
fn clear_answer(s: &mut App) {
    s.approval_passphrase.clear();
    for field in &mut s.approval_values {
        field.clear();
    }
}

/// Connecting Proton Pass: the token, secure and cleared once sent, and
/// when it expires.
struct TokenForm {
    open: bool,
    token: TextEdit,
    expires: TextEdit,
    error: Option<String>,
}

impl TokenForm {
    fn new() -> Self {
        Self {
            open: false,
            token: TextEdit::new("").secure(),
            expires: TextEdit::new(""),
            error: None,
        }
    }
}

/// What the main pane shows: something of the project on show, in the
/// environment chosen, or something of the machine.
#[derive(Debug, Clone, PartialEq, Eq)]
enum View {
    /// The environment's keys, a row each.
    Keys,
    /// One key of the environment.
    Key(KeyName),
    /// The environment's sources, where they are edited.
    Sources,
    /// The machine's audit log, of every project or of one.
    Activity,
    /// The machine's providers, AWS, Proton Pass and the local store:
    /// whether each can read, where each is used, and connecting them.
    Providers,
    /// The machine's remote endpoint: whether it listens, and the machines
    /// let in, each with a new token or revoked from here.
    Remote,
    /// The phone that approves requests away from this computer: the one
    /// paired, pairing one and removing it.
    Phone,
}

/// The audit log as Activity lists it.
#[derive(Default)]
struct Activity {
    /// Newest first: the project a line is about, and the line as
    /// `kagebunshin audit` prints it.
    lines: Vec<(Option<ProjectName>, String)>,
    /// How many lines of the log could not be read.
    unreadable: usize,
}

/// The states the keys can be narrowed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Filter {
    /// Set by more than one source.
    Conflicts,
    Sensitive,
    /// In `.env.example`, but no source sets it.
    Missing,
    NotInExample,
}

impl Filter {
    const ALL: [(Filter, &'static str, &'static str); 4] = [
        (Filter::Conflicts, "kb-filter-conflicts", "Conflicts"),
        (Filter::Sensitive, "kb-filter-sensitive", "Sensitive"),
        (Filter::Missing, "kb-filter-missing", "Missing"),
        (
            Filter::NotInExample,
            "kb-filter-extra",
            "Not in .env.example",
        ),
    ];

    /// The state, to end "No key of dev is".
    fn state(self) -> &'static str {
        match self {
            Filter::Conflicts => "set by more than one source",
            Filter::Sensitive => "marked sensitive",
            Filter::Missing => "missing",
            Filter::NotInExample => "left out of .env.example",
        }
    }

    /// Whether `name` is in this state in column `c`.
    fn matches(self, c: &Column, name: &KeyName) -> bool {
        let Detail::Loaded(EnvReport::Resolved {
            keys,
            missing,
            vars,
            ..
        }) = &c.detail
        else {
            return false;
        };
        let k = keys.iter().find(|k| &k.key == name);
        let var = vars.iter().find(|v| &v.key == name);
        match self {
            Filter::Conflicts => k.is_some_and(|k| !k.overridden.is_empty()),
            Filter::Sensitive => k.is_some_and(|k| k.sensitive),
            Filter::Missing => k.is_none() && missing.iter().flatten().any(|m| m == name),
            Filter::NotInExample => {
                missing.is_some()
                    && (k.is_some_and(|k| !k.in_example) || var.is_some_and(|v| !v.in_example))
            }
        }
    }
}

/// The add-source form.
struct AddForm {
    open: bool,
    /// AWS Secrets Manager, Proton Pass or the local store.
    provider: Provider,
    /// AWS and Proton: one secret, rather than a prefix.
    one: bool,
    name: TextEdit,
    profile: TextEdit,
    region: TextEdit,
    optional: bool,
}

impl AddForm {
    fn new() -> Self {
        Self {
            open: false,
            provider: Provider::AwsSm,
            one: false,
            name: TextEdit::new(""),
            profile: TextEdit::new(""),
            region: TextEdit::new(""),
            optional: false,
        }
    }
}

impl App {
    /// Nothing loaded, nothing live, no edits.
    fn blank() -> Self {
        Self {
            catalog: Catalog::default(),
            machine: Machine::default(),
            worker: None,
            socket: Err("not live".into()),
            config: Err("this window is a fixed scene; it changes nothing".into()),
            live: false,
            view: View::Keys,
            env: None,
            search: TextEdit::new(""),
            filter: None,
            flat: false,
            flipped: BTreeSet::new(),
            form: AddForm::new(),
            passphrase: TextEdit::new("").secure(),
            asking: Asking::No,
            activity: Ok(Activity::default()),
            activity_of: None,
            warnings_open: false,
            waker: None,
            proton: TokenForm::new(),
            aws_profile: TextEdit::new(""),
            aws_region: TextEdit::new(""),
            aws_profiles: Vec::new(),
            login: None,
            approver: None,
            approvals: Vec::new(),
            approval_passphrase: TextEdit::new("").secure(),
            approval_values: Vec::new(),
            answering: false,
            approval_error: None,
            approvals_at: 0.0,
            approval_left: None,
            approval_all_keys: false,
            approval_details: false,
            desk: None,
            code: None,
        }
    }

    fn idle(&self) -> bool {
        self.machine.pending == Pending::None
    }
}

fn init() -> App {
    let cwd = std::env::current_dir().unwrap_or_else(|_| "/".into());
    let config = ConfigDir::from_env();
    let catalog = match &config {
        Ok(dir) => Catalog::load(dir, &cwd),
        Err(e) => Catalog {
            problem: Some(Problem::new(e.to_string())),
            cwd,
            ..Catalog::default()
        },
    };
    App {
        catalog,
        socket: socket_arg(rune::extra_args()),
        config: config.map_err(|e| e.to_string()),
        live: true,
        ..App::blank()
    }
}

/// `--socket PATH`, else the CLI's default.
fn socket_arg(args: &[String]) -> Result<PathBuf, String> {
    match args.iter().position(|a| a == "--socket") {
        Some(i) => args
            .get(i + 1)
            .map(PathBuf::from)
            .ok_or_else(|| "--socket needs a path".into()),
        None => default_socket_path().map_err(|e| e.to_string()),
    }
}

fn setup(s: &mut App, waker: Waker) {
    if !s.live {
        return;
    }
    let socket = match &s.socket {
        Ok(socket) => socket.clone(),
        Err(e) => {
            s.machine.conn = Conn::Down(Problem::new(e.clone()));
            return;
        }
    };
    s.waker = Some(waker.clone());
    let client = || {
        Box::new(SocketClient {
            socket: socket.clone(),
        })
    };
    match Worker::spawn(client(), waker.clone()) {
        Ok(worker) => s.worker = Some(worker),
        Err(problem) => {
            s.machine.conn = Conn::Down(problem);
            return;
        }
    }
    // A wake's poll waits for the window's next frame, and a window open
    // on another workspace is drawn none until someone looks at it: its
    // request would go unannounced. In the tray, what the approver learns
    // is taken in as it lands.
    let heard = match &s.desk {
        Some(desk) => desk.at_once(hear),
        None => waker,
    };
    match Approver::spawn(client(), client(), heard) {
        Ok(approver) => s.approver = Some(approver),
        Err(problem) => {
            s.machine.conn = Conn::Down(problem);
            return;
        }
    }
    // Opened in a project's checkout: show it.
    let here = s.catalog.here.as_ref().map(|h| h.project.clone());
    if let Some(project) = here {
        show(s, &project, None);
    }
}

fn poll(s: &mut App, now: f64, tx: &mut Tx) -> bool {
    let approvals = take_approvals(s, now) | count_down(s, now, tx);
    let login = s.login.as_ref().is_some_and(aws::Login::fresh);
    if login && matches!(s.login.as_ref().and_then(aws::Login::outcome), Some(Ok(_))) {
        reload(s);
        send(s, Event::CheckProviders, Some(tx));
    }
    let Some(worker) = &s.worker else {
        return login || approvals;
    };
    let answers = worker.answers();
    let noticed = s.machine.notice.is_some();
    let mut effects: Vec<Effect> = step(&mut s.machine, Event::Due { now })
        .into_iter()
        .collect();
    // A notice that timed out is gone without an effect.
    let faded = noticed != s.machine.notice.is_some();
    let changed = login || approvals || faded || !answers.is_empty() || !effects.is_empty();
    for (attempt, answer) in answers {
        effects.extend(step(
            &mut s.machine,
            Event::Answer {
                attempt,
                answer,
                now,
            },
        ));
    }
    apply(s, effects, Some(tx));
    changed
}

/// [`take_approvals`] with no frame to poll in: `setup` says when.
fn hear(s: &mut App, tx: &mut Tx) -> bool {
    take_approvals(s, tx.clock())
}

/// Takes in what the approver learned: whether anything did. The dialog
/// opens focused, and each request is asked about with an empty field.
fn take_approvals(s: &mut App, now: f64) -> bool {
    let Some(approver) = &s.approver else {
        return false;
    };
    let updates = approver.updates();
    if updates.is_empty() {
        return false;
    }
    let asked = s.approvals.first().map(|p| p.id);
    for update in updates {
        match update {
            Approval::Waiting(pending) => {
                s.approvals = pending;
                s.approvals_at = now;
            }
            Approval::Answered(Ok(pending)) => {
                s.answering = false;
                s.approval_error = None;
                s.approvals = pending;
                s.approvals_at = now;
            }
            Approval::Answered(Err(problem)) => {
                s.answering = false;
                s.approval_error = Some(problem.message);
            }
        }
    }
    if s.approvals.first().map(|p| p.id) != asked {
        s.approval_error = None;
        clear_answer(s);
        s.approval_values = value_fields(s.approvals.first());
        // Values are typed first, where a request asks for them.
        s.approval_passphrase.focused = !s.approvals.is_empty() && s.approval_values.is_empty();
        s.approval_all_keys = false;
        s.approval_details = false;
        s.approval_left = None;
        announce(s);
    }
    true
}

/// Counts down the time left to answer the request asked about, a second
/// at a time: whether what is shown changed. The daemon does the denying;
/// this only shows when.
fn count_down(s: &mut App, now: f64, tx: &mut Tx) -> bool {
    let Some(total) = s.approvals.first().and_then(|p| p.left) else {
        return false;
    };
    let passed = (now - s.approvals_at).max(0.0);
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "whole seconds of a clock that only runs forward"
    )]
    let left = total.saturating_sub(passed as u64);
    if left > 0 {
        tx.wake_at(s.approvals_at + passed.floor() + 1.0);
    }
    s.approval_left.replace(left) != Some(left)
}

/// Sends a notification for the request now asked about, whatever the
/// window is doing. The window is not brought up: one that opens under
/// the person's hands takes the keyboard from what they were typing.
fn announce(s: &mut App) {
    if let (Some(desk), Some(prompt)) = (&s.desk, s.approvals.first()) {
        desk.notify(prompt);
    }
}

/// The window closes, and where there is a tray the app stays: nothing
/// typed or revealed outlives the window, and the request it was asking
/// about is denied, as when closing the window ended the app.
fn on_close(s: &mut App, tx: &mut Tx) {
    send(s, Event::Conceal, Some(tx));
    send(s, Event::Forget, Some(tx));
    send(s, Event::Cancel, Some(tx));
    s.passphrase.clear();
    s.proton = TokenForm::new();
    deny(s, tx);
}

/// Approves the request asked about with the passphrase typed, moving it
/// out of the field, which is cleared. One that asks for values is sent
/// those typed, for at least one key; they stay in their fields until the
/// daemon takes them. Enter in a value's field, the passphrase not typed
/// yet, moves there.
fn approve(s: &mut App, tx: &mut Tx) {
    answer(s, tx, false);
}

/// Approves the request asked about and leaves the approval standing.
fn approve_standing(s: &mut App, tx: &mut Tx) {
    answer(s, tx, true);
}

/// Approves the request asked about with what is typed; `standing` leaves
/// the approval standing, where the request offers that.
fn answer(s: &mut App, _: &mut Tx, standing: bool) {
    let (Some(approver), Some(prompt)) = (&s.approver, s.approvals.first()) else {
        return;
    };
    if s.answering {
        return;
    }
    let typing = matches!(prompt.reason, ApprovalReason::Type { .. });
    let values: Vec<(KeyName, WireSecret)> = (prompt.keys.iter())
        .zip(&s.approval_values)
        .filter(|(_, field)| typing && !field.text.is_empty())
        .map(|(key, field)| (key.clone(), WireSecret::new(field.text.clone())))
        .collect();
    if typing && values.is_empty() {
        s.approval_error = Some("Type a value for at least one key first.".into());
        return;
    }
    if s.approval_passphrase.text.is_empty() {
        for field in &mut s.approval_values {
            field.focused = false;
        }
        s.approval_passphrase.focused = true;
        return;
    }
    let passphrase = WireSecret::new(std::mem::take(&mut s.approval_passphrase.text));
    s.approval_passphrase.clear();
    approver.answer(ApprovalAnswer {
        id: prompt.id,
        passphrase: Some(passphrase),
        values,
        standing: standing && prompt.standing.is_some(),
    });
    s.answering = true;
    s.approval_error = None;
}

fn deny(s: &mut App, _: &mut Tx) {
    let (Some(approver), Some(prompt)) = (&s.approver, s.approvals.first()) else {
        return;
    };
    if s.answering {
        return;
    }
    approver.answer(ApprovalAnswer::deny(prompt.id));
    clear_answer(s);
    s.answering = true;
    s.approval_error = None;
}

/// Hands jobs to the worker and timers to the window, and makes edits.
fn apply(s: &mut App, effects: impl IntoIterator<Item = Effect>, mut tx: Option<&mut Tx>) {
    let mut queue: VecDeque<Effect> = effects.into_iter().collect();
    while let Some(effect) = queue.pop_front() {
        match effect {
            Effect::Run(attempt, job) => {
                if let Some(w) = &s.worker {
                    w.send(attempt, job);
                }
            }
            Effect::WakeAt(due) => {
                if let Some(tx) = tx.as_deref_mut() {
                    tx.wake_at(due.0);
                }
            }
            Effect::Edit(edit) => {
                let result = write(s, &edit);
                if result.is_ok() {
                    reload(s);
                    if matches!(edit, Edit::AddSource { .. }) {
                        s.form = AddForm::new();
                    }
                }
                queue.extend(step(&mut s.machine, Event::Edited { edit, result }));
            }
        }
    }
    asking(s);
    draw_code(s);
}

/// Draws the QR code of the pairing's address when a pairing starts, and
/// drops it when the pairing is over.
fn draw_code(s: &mut App) {
    let url = s.machine.pairing.as_ref().map(|p| p.url.as_str());
    if url == s.code.as_ref().map(|(of, _)| of.as_str()) {
        return;
    }
    // An address too long for a code is still shown as text.
    s.code = url.and_then(|url| Some((url.to_owned(), qr_code(url)?)));
}

/// `text` as a QR code, dark on white whatever the theme, which is what
/// cameras read best, with the quiet border the standard asks for.
fn qr_code(text: &str) -> Option<Pixels> {
    use qrcodegen::{QrCode, QrCodeEcc};
    /// Modules of white around the code.
    const QUIET: usize = 4;
    /// Pixels to a module's side: enough that scaling it keeps its edges.
    const DOT: usize = 8;
    let code = QrCode::encode_text(text, QrCodeEcc::Medium).ok()?;
    let modules = usize::try_from(code.size()).ok()?;
    let side = (modules + 2 * QUIET) * DOT;
    let mut rgba = vec![0xff_u8; side * side * 4];
    for y in 0..modules {
        for x in 0..modules {
            if !code.get_module(i32::try_from(x).ok()?, i32::try_from(y).ok()?) {
                continue;
            }
            for row in 0..DOT {
                let start = (((y + QUIET) * DOT + row) * side + (x + QUIET) * DOT) * 4;
                for pixel in rgba[start..start + DOT * 4].as_chunks_mut::<4>().0 {
                    pixel[..3].fill(0);
                }
            }
        }
    }
    let side = u32::try_from(side).ok()?;
    let pixels = Pixels::new();
    pixels.set(side, side, rgba);
    Some(pixels)
}

/// What the passphrase field is up for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Asking {
    No,
    /// The locked screen, which asks for it to unlock.
    Locked,
    /// A prompt over the window.
    Prompt,
}

/// The passphrase field opens empty and focused, and closes cleared.
fn asking(s: &mut App) {
    let asking = match s.machine.pending {
        Pending::Passphrase(_) => Asking::Prompt,
        Pending::None if locked_screen(s) => Asking::Locked,
        _ => Asking::No,
    };
    if asking != s.asking {
        s.asking = asking;
        s.passphrase.clear();
        s.passphrase.focused = asking != Asking::No;
    }
}

/// Whether the locked screen is on show: it takes the place of a
/// project's keys while the daemon is locked, as there are none to show.
/// Sources, Providers, Remote, Phone and Activity need no values and stay
/// as they are, and so does the first screen of an install with no project
/// yet.
fn locked_screen(s: &App) -> bool {
    s.machine.conn == (Conn::Up { locked: true })
        && matches!(s.view, View::Keys | View::Key(_))
        && !first_screen(s)
}

/// Whether the first screen is on show: there is no project yet, so it
/// says how to set the first ones up in place of the projects, the tabs
/// and what they open on. See [`first_steps`].
fn first_screen(s: &App) -> bool {
    s.catalog.projects.is_empty() && s.catalog.problem.is_none()
}

/// Unlocks from the locked screen with the passphrase typed, moving it out
/// of the field, which is cleared. With none typed it asks the daemon to
/// unlock without one, which is enough where there is no local store.
fn unlock(s: &mut App, tx: &mut Tx) {
    match s.machine.pending {
        Pending::Passphrase(_) => submit_passphrase(s, tx),
        Pending::None => {
            let typed = std::mem::take(&mut s.passphrase.text);
            s.passphrase.clear();
            let passphrase = (!typed.is_empty()).then(|| WireSecret::new(typed));
            send(s, Event::Unlock(passphrase), Some(tx));
        }
        _ => {}
    }
}

/// Makes an edit to a project file: what it warned about, or why it failed.
fn write(s: &App, edit: &Edit) -> Result<Vec<String>, (&'static str, Problem)> {
    let dir = s
        .config
        .as_ref()
        .map_err(|e| ("config", Problem::new(e.clone())))?;
    let result = match edit {
        Edit::RemoveSource {
            project,
            env,
            index,
        } => edit::remove_source(dir, project, env, *index),
        Edit::MoveSource {
            project,
            env,
            from,
            to,
        } => edit::move_source(dir, project, env, *from, *to),
        Edit::AddSource {
            project,
            env,
            source,
        } => edit::add_source(dir, project, env, source),
    };
    result.map(|e| e.warnings).map_err(|e| {
        let problem = Problem {
            message: e.message,
            hint: e.hint,
            unreachable: false,
        };
        (e.code, problem)
    })
}

/// The add-source form, as a source to add.
fn new_source(f: &AddForm) -> Result<NewSource, String> {
    let given = |t: &TextEdit| Some(t.text.trim().to_owned()).filter(|t| !t.is_empty());
    let name = given(&f.name);
    let (prefix, secret) = match (f.provider, f.one) {
        (Provider::File, _) => (None, name),
        (_, false) => (Some(name.ok_or("name the prefix to read")?), None),
        (_, true) => (None, Some(name.ok_or("name the secret to read")?)),
    };
    let aws = |t: &TextEdit| given(t).filter(|_| f.provider == Provider::AwsSm);
    Ok(NewSource {
        provider: f.provider,
        prefix,
        secrets: secret.into_iter().collect(),
        key: None,
        profile: aws(&f.profile).map(Profile::try_from).transpose()?,
        region: aws(&f.region).map(Region::try_from).transpose()?,
        optional: f.optional,
    })
}

fn send(s: &mut App, event: Event, tx: Option<&mut Tx>) {
    let effects = step(&mut s.machine, event);
    apply(s, effects, tx);
}

/// A change a person asked for.
fn ask(s: &mut App, change: Change, tx: &mut Tx) {
    send(s, Event::Ask(change), Some(tx));
}

/// Sends the passphrase typed, moving it out of the field, which is cleared;
/// with the Proton Pass token typed, the same way, if that is what it is
/// for.
fn submit_passphrase(s: &mut App, tx: &mut Tx) {
    if s.passphrase.text.is_empty() {
        return;
    }
    let passphrase = WireSecret::new(std::mem::take(&mut s.passphrase.text));
    s.passphrase.clear();
    let event = match s.machine.pending {
        Pending::Passphrase(Purpose::ConnectProton { .. }) => {
            let token = WireSecret::new(std::mem::take(&mut s.proton.token.text));
            s.proton = TokenForm::new();
            Event::ConnectProton { token, passphrase }
        }
        _ => Event::Passphrase(passphrase),
    };
    send(s, event, Some(tx));
}

/// Asks for the passphrase to save the Proton Pass token typed, once it and
/// its expiry, if one is given, read right.
fn connect_proton(s: &mut App, tx: &mut Tx) {
    if s.proton.token.text.trim().is_empty() {
        s.proton.error = Some("Paste the token first.".into());
        return;
    }
    let date = s.proton.expires.text.trim();
    let expires = if date.is_empty() {
        None
    } else if let Some(e) = kagebunshin::source::proton::parse_date(date) {
        Some(e)
    } else {
        s.proton.error = Some(format!("{date:?} is not a date like 2026-12-31."));
        return;
    };
    s.proton.error = None;
    ask(s, Change::ConnectProton { expires }, tx);
}

/// Checks an AWS profile, logs it in if it needs it, and with `save` makes
/// it the default.
fn aws_login(s: &mut App, profile: Profile, region: Option<Region>, save: bool) {
    if s.login.as_ref().is_some_and(|l| l.outcome().is_none()) {
        return;
    }
    let Some(waker) = s.waker.clone() else {
        s.machine.notice = Some(Notice::Failed(Problem::new(
            "this window is a fixed scene; it changes nothing",
        )));
        return;
    };
    s.machine.notice = None;
    match aws::Login::start(profile, region, save, s.config.clone(), waker) {
        Ok(login) => s.login = Some(login),
        Err(problem) => s.machine.notice = Some(Notice::Failed(problem)),
    }
}

/// `connect aws` with the profile and region typed.
fn connect_aws(s: &mut App, _: &mut Tx) {
    let given = |t: &TextEdit| Some(t.text.trim().to_owned()).filter(|t| !t.is_empty());
    let profile = match given(&s.aws_profile).map(Profile::try_from) {
        Some(Ok(p)) => p,
        Some(Err(e)) => {
            s.machine.notice = Some(Notice::Failed(Problem::new(e)));
            return;
        }
        None => {
            s.machine.notice = Some(Notice::Failed(Problem::new("Name the AWS profile.")));
            return;
        }
    };
    if !s.aws_profiles.is_empty() && !s.aws_profiles.iter().any(|p| p == profile.as_str()) {
        s.machine.notice = Some(Notice::Failed(
            Problem::new(format!(
                "AWS profile {profile} is not in your AWS configuration"
            ))
            .with_hint("see `aws configure list-profiles`"),
        ));
        return;
    }
    let region = match given(&s.aws_region).map(Region::try_from).transpose() {
        Ok(r) => r,
        Err(e) => {
            s.machine.notice = Some(Notice::Failed(Problem::new(e)));
            return;
        }
    };
    aws_login(s, profile, region, true);
}

fn add_source(s: &mut App, tx: &mut Tx) {
    let (Some(shown), View::Sources) = (&s.machine.shown, &s.view) else {
        return;
    };
    let Some(c) = chosen(s, shown) else {
        return;
    };
    let (project, env) = (shown.project.clone(), c.sel.env.clone());
    match new_source(&s.form) {
        Ok(source) => ask(
            s,
            Change::Edit(Edit::AddSource {
                project,
                env,
                source,
            }),
            tx,
        ),
        Err(why) => {
            let problem = Problem::new(format!("cannot add the source: {why}"));
            s.machine.notice = Some(Notice::Failed(problem));
        }
    }
}

/// Reads the configuration again.
fn reload(s: &mut App) {
    if let Ok(dir) = &s.config {
        let cwd = s.catalog.cwd.clone();
        s.catalog = Catalog::load(dir, &cwd);
    }
}

/// Shows a project: the keys of its default environment, with every
/// environment asked about at once unless its name looks like production.
/// Such a one is asked about once the daemon says it was acknowledged as
/// not production.
fn show(s: &mut App, project: &ProjectName, tx: Option<&mut Tx>) {
    let Some(p) = s.catalog.projects.iter().find(|p| &p.name == project) else {
        return;
    };
    let columns = p
        .envs
        .iter()
        .map(|e| {
            let sel = Selection {
                project: p.name.clone(),
                env: e.name.clone(),
                facts: s.catalog.facts(p, &e.name),
            };
            (sel, prod_like_profile(e.name.as_str()).is_none())
        })
        .collect();
    let default = p.envs.iter().find(|e| e.default).or(p.envs.first());
    s.env = default.map(|e| e.name.clone());
    s.view = View::Keys;
    s.form = AddForm::new();
    // What narrowed another project's keys would hide this one's.
    s.filter = None;
    s.search = TextEdit::new("");
    let effects = step(
        &mut s.machine,
        Event::Show {
            project: project.clone(),
            columns,
        },
    );
    apply(s, effects, tx);
}

/// Switches the main pane, hiding a revealed value or a grant's new
/// token, and ending a phone's pairing, on the way out.
fn go(s: &mut App, view: View, tx: &mut Tx) {
    if view != s.view && matches!(s.view, View::Key(_)) {
        send(s, Event::Conceal, Some(tx));
    }
    if view != s.view && matches!(s.view, View::Remote | View::Phone) {
        send(s, Event::Forget, Some(tx));
    }
    if view == View::Phone {
        send(s, Event::CheckPhones, Some(tx));
        // What is said of the phone is no older than the look at it.
        send(s, Event::Probe, Some(tx));
    }
    if view == View::Activity && s.live {
        s.activity = activity();
    }
    if view == View::Providers {
        if s.live {
            s.aws_profiles = aws_profiles();
        }
        send(s, Event::CheckProviders, Some(tx));
    }
    if view != View::Sources {
        s.form = AddForm::new();
    }
    s.view = view;
    asking(s);
}

/// The environment whose keys and sources are listed: the one chosen, or
/// the first where the project has none of that name.
fn chosen<'a>(s: &App, shown: &'a Shown) -> Option<&'a Column> {
    let named = s.env.as_ref().and_then(|env| shown.column(env));
    named.or(shown.columns.first())
}

/// Chooses the environment to list. A key's page is of one environment:
/// from there it goes back to the keys.
fn choose(s: &mut App, env: EnvName, tx: &mut Tx) {
    s.env = Some(env);
    if matches!(s.view, View::Key(_)) {
        go(s, View::Keys, tx);
    }
}

/// Opens the sources of `env` of `project`.
fn open_sources(s: &mut App, project: &ProjectName, env: EnvName, tx: &mut Tx) {
    show(s, project, Some(tx));
    s.env = Some(env);
    go(s, View::Sources, tx);
}

/// The profiles in the AWS configuration, sorted.
fn aws_profiles() -> Vec<String> {
    let set = kagebunshin::source::aws_sm::connect::profiles();
    kagebunshin::source::aws_sm::connect::profile_names(set.as_ref())
}

/// How many log lines Activity shows.
const ACTIVITY: usize = 500;

/// The audit log, newest first, as `kagebunshin audit` prints it.
fn activity() -> Result<Activity, String> {
    let log = AuditLog::from_env().map_err(|e| e.to_string())?;
    let (events, unreadable) = log.read().map_err(|e| e.to_string())?;
    let lines = events
        .iter()
        .rev()
        .map(|e| (e.project.clone(), kagebunshin::cli::audit::line(e)))
        .collect();
    Ok(Activity { lines, unreadable })
}

fn refresh(s: &mut App, tx: &mut Tx) {
    reload(s);
    if s.view == View::Activity && s.live {
        s.activity = activity();
    }
    if s.view == View::Providers && s.live {
        s.aws_profiles = aws_profiles();
    }
    // Environments added or removed: show the project afresh.
    let changed = s.machine.shown.as_ref().and_then(|shown| {
        let p = s.catalog.projects.iter().find(|p| p.name == shown.project);
        let now: Vec<_> = p.iter().flat_map(|p| &p.envs).map(|e| &e.name).collect();
        let was: Vec<_> = shown.columns.iter().map(|c| &c.sel.env).collect();
        (now != was).then(|| shown.project.clone())
    });
    match changed {
        Some(project) => {
            show(s, &project, Some(tx));
            send(s, Event::Refresh, Some(tx));
        }
        None => send(s, Event::Refresh, Some(tx)),
    }
}

/// Colours for the window, picked once per frame.
#[derive(Clone, Copy)]
struct Paint {
    t: Theme,
    hair: f32,
    info: Color,
    good: Color,
    warn: Color,
    sensitive: Color,
}

fn view(s: &App, cx: &mut Cx<App>) -> El {
    let dark = cx.system_dark();
    let p = Paint {
        t: tok::theme(dark),
        hair: 1.0 / cx.env().scale,
        info: tok::accent(0, dark),
        good: tok::accent(4, dark),
        warn: tok::accent(3, dark),
        sensitive: tok::accent(2, dark),
    };
    let mut window = col()
        .key("kb-window")
        .role("window")
        .w_full()
        .h_full()
        .fill(p.t.bg)
        .child(header(p, s, cx.titlebar_inset()));
    if let Conn::Down(problem) = &s.machine.conn {
        window = window.child(
            problem_box(p, "kb-conn-problem", problem)
                .mx(space::S6)
                .mb(space::S3),
        );
    }
    // The first screen has the window to itself: there is no project to list.
    let sidebar = (!first_screen(s)).then(|| sidebar(p, s));
    window = window.child(
        row()
            .key("kb-body")
            .grow(1.0)
            .w_full()
            .px(space::S6)
            .pb(space::S6)
            .gap(space::S6)
            .children(sidebar)
            .child(main_pane(p, s)),
    );
    // A request waiting for approval comes first; dismissing it denies it.
    if let Some(prompt) = s.approvals.first() {
        return window.child(overlay_wide(approval_prompt(p, s, prompt), 560.0, deny));
    }
    match &s.machine.pending {
        Pending::Confirm { question, change } => {
            let yes = match change {
                Change::RotateGrant { .. } => "New token",
                Change::RevokeGrant(_) => "Revoke",
                _ => "Remove",
            };
            window.child(overlay(confirm(p, question, yes), cancel))
        }
        Pending::Sharing(sharing) => window.child(overlay(sharing_prompt(p, sharing), cancel)),
        Pending::Unmarking(unmarking) => {
            window.child(overlay(unmarking_prompt(p, unmarking), cancel))
        }
        Pending::Unmarks(unmarks) => window.child(overlay(unmarks_prompt(p, unmarks), cancel)),
        // The locked screen has the field to unlock with.
        Pending::Passphrase(Purpose::Unlock) if locked_screen(s) => window,
        Pending::Passphrase(purpose) => window.child(overlay(
            passphrase_prompt(p, purpose, &s.passphrase),
            cancel,
        )),
        Pending::None | Pending::Running(_) => window,
    }
}

fn cancel(s: &mut App, tx: &mut Tx) {
    send(s, Event::Cancel, Some(tx));
}

/// A dialog over the window, which takes the keyboard until it closes, or
/// is dismissed.
fn overlay(dialog: El, dismiss: fn(&mut App, &mut Tx)) -> El {
    overlay_wide(dialog, 440.0, dismiss)
}

/// [`overlay`] with the dialog `width` wide. A dialog taller than the
/// window is held to the window's height: a part of it that scrolls and
/// may shrink then gives way.
fn overlay_wide(dialog: El, width: f32, dismiss: fn(&mut App, &mut Tx)) -> El {
    col()
        .key("kb-overlay")
        .pin(Some(0.0), Some(0.0), Some(0.0), Some(0.0))
        .fill(Color::BLACK.alpha(0.4))
        .padding(space::S3)
        .center()
        .child(
            dialog
                .w(width)
                .min_h(0.0)
                .shrink()
                .padding(space::S6)
                .gap(space::S3)
                .modal_tx(false, dismiss),
        )
}

/// How many keys an approval prompt shows before "N more".
const SHOWN_KEYS: usize = 12;

/// Colours for reading a command line or a shell script: the word in
/// command position bold, options, quoted words and operators each in a
/// colour. For the eye only; it decides nothing.
fn command_spans(p: Paint, line: &str) -> Vec<Span> {
    let operator = |c: u8| matches!(c, b';' | b'|' | b'&' | b'(' | b')');
    let bytes = line.as_bytes();
    let mut spans = Vec::new();
    // Whether the next word names what runs.
    let mut command = true;
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_whitespace() {
            command |= c == b'\n';
            i += 1;
            continue;
        }
        let start = i;
        if operator(c) {
            while i < bytes.len() && operator(bytes[i]) {
                i += 1;
            }
            spans.push(Span::new(start, i).color(p.t.text_secondary));
            command = true;
            continue;
        }
        let (mut quote, mut quoted) = (None, false);
        while i < bytes.len() {
            let c = bytes[i];
            match quote {
                Some(q) if c == q => quote = None,
                Some(b'"') | None if c == b'\\' => i += 1,
                None if c == b'"' || c == b'\'' => (quote, quoted) = (Some(c), true),
                None if c.is_ascii_whitespace() || operator(c) => break,
                Some(_) | None => {}
            }
            i += 1;
        }
        // A backslash may have stepped past the end or into a character.
        i = i.min(bytes.len());
        while !line.is_char_boundary(i) {
            i += 1;
        }
        let word = &line[start..i];
        // `NAME=value` before a command sets its environment.
        let assigns = word.split_once('=').is_some_and(|(name, _)| {
            !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        });
        if command && !assigns {
            spans.push(Span::new(start, i).bold());
            command = false;
        } else if word.starts_with('-') {
            spans.push(Span::new(start, i).color(p.info));
        } else if quoted {
            spans.push(Span::new(start, i).color(p.good));
        }
    }
    spans
}

/// `secs` as a countdown shows it: `4:07`.
fn countdown(secs: u64) -> String {
    format!("{}:{:02}", secs / 60, secs % 60)
}

/// A part of the approval prompt: a small label, and under it `body`.
fn part(p: Paint, key: &str, label: impl Into<String>, body: El) -> El {
    col()
        .key(key)
        .w_full()
        .gap(space::S1)
        .child(
            text(label.into())
                .font(type_::LABEL)
                .color(p.t.text_secondary)
                .wrap(),
        )
        .child(body)
}

/// A key's name, as a chip; `replaced` when what is asked would replace
/// its value.
fn key_chip(p: Paint, key: &KeyName, replaced: bool) -> El {
    let chip = el().h(22.0).px(space::S2).center().radius(radius::SM);
    let chip = if replaced {
        chip.fill(p.warn.alpha(0.16)).border(p.hair, p.warn)
    } else {
        chip.fill(p.t.control_track)
    };
    chip.child(
        text(key.as_str())
            .font(type_::MONO_CAPTION.mono())
            .color(p.t.text),
    )
}

/// What an import writes, section by section: where to and whether that
/// is new, the files, the key names, and which values it replaces. No
/// value: the daemon sends none.
fn import_list(p: Paint, s: &App, sections: &[ImportNames], unlock: bool) -> El {
    let mut list = col().w_full().gap(space::S3);
    for (i, names) in sections.iter().enumerate() {
        let to = names.section.to_string();
        let new = match names.into {
            ImportInto::NewProject => ", a new project".to_owned(),
            ImportInto::NewEnv => {
                format!(", a new environment of project {}", names.section.project)
            }
            ImportInto::Existing => String::new(),
        };
        // Locked, the daemon cannot see whether it has keys already.
        let unless = if unlock && names.if_empty {
            " \u{00b7} skipped if it already has keys"
        } else {
            ""
        };
        let files: Vec<String> = (names.files.iter())
            .map(|f| f.display().to_string())
            .collect();
        let n = names.keys.len();
        let all = s.approval_all_keys || n <= SHOWN_KEYS;
        let mut chips = row().w_full().flex_wrap().gap(space::S1).children(
            (names.keys.iter())
                .take(if all { n } else { SHOWN_KEYS })
                .map(|k| key_chip(p, k, names.replaces.contains(k))),
        );
        if n > SHOWN_KEYS {
            let label = if all {
                "Show fewer".to_owned()
            } else {
                format!("{} more", n - SHOWN_KEYS)
            };
            chips = chips.child(
                button(p, &format!("kb-approval-more-{i}"), &label, true, |s, _| {
                    s.approval_all_keys = !s.approval_all_keys;
                })
                .h(22.0),
            );
        }
        let mut one = col()
            .key(format!("kb-approval-section-{i}"))
            .w_full()
            .gap(space::S1)
            .child(
                text(format!("[{to}]{new}{unless}"))
                    .key(format!("kb-approval-into-{i}"))
                    .font(BODY)
                    .color(p.t.text)
                    .spans(vec![Span::new(0, to.len() + 2).bold().mono()])
                    .wrap(),
            )
            .child(
                text(format!("from {}", files.join(", ")))
                    .key(format!("kb-approval-files-{i}"))
                    .font(type_::MONO_CAPTION.mono())
                    .color(p.t.text_secondary)
                    .wrap(),
            )
            .child(chips);
        if !names.replaces.is_empty() {
            let replaced: Vec<&str> = names.replaces.iter().map(KeyName::as_str).collect();
            one = one.child(
                text(format!(
                    "Replaces the {} it has now for {}",
                    if replaced.len() == 1 {
                        "value"
                    } else {
                        "values"
                    },
                    replaced.join(", ")
                ))
                .key(format!("kb-approval-replaces-{i}"))
                .font(BODY)
                .color(p.warn)
                .wrap(),
            );
        }
        list = list.child(one);
    }
    list
}

/// The fields a request asks a person to type values into: each key's
/// name, beside it whether what is typed replaces a value, and under it
/// its hidden field. No value comes from the daemon.
fn value_list(p: Paint, s: &App, keys: &[KeyName], replaces: &[KeyName]) -> El {
    let mut list = col().w_full().gap(space::S2);
    for (i, (key, edit)) in keys.iter().zip(&s.approval_values).enumerate() {
        let replaced = replaces.contains(key);
        let label = format!("The value of {key}");
        let field = text_input(edit, BODY)
            .single_line()
            .placeholder(
                if replaced {
                    "A new value, or empty to keep the one there"
                } else {
                    "Its value"
                },
                p.t.text_secondary,
            )
            .key(format!("kb-approval-value-{i}"))
            .label(label)
            .px(space::S2)
            .py(space::S1)
            .radius(radius::MD)
            .fill(p.t.control_track)
            // The field is drawn for a key the request has; the fallback
            // only keeps a stale one from panicking.
            .on_edit(move |s: &mut App| match s.approval_values.get_mut(i) {
                Some(field) => field,
                None => &mut s.approval_passphrase,
            })
            .secure()
            .on_submit(approve)
            .w_full();
        let mut name = row()
            .w_full()
            .gap(space::S2)
            .items_center()
            .child(key_chip(p, key, replaced));
        if replaced {
            name = name.child(
                text("has a value now, which this replaces")
                    .key(format!("kb-approval-replaces-{i}"))
                    .font(type_::LABEL)
                    .color(p.warn),
            );
        }
        list = list.child(col().w_full().gap(space::S1).child(name).child(field));
    }
    list
}

/// Asks to approve a request the daemon holds back, in as little as a
/// person answers it from: who asks, the question, the command and one
/// line of what it gets; the passphrase approves it. How the request got
/// here, why it waits and what approving does are a click away, under
/// Details, and so is every key of a long list. For an import into the
/// local store, what it writes in place of that line; for values to type
/// into it, a field for each: those say what approving writes as well.
fn approval_prompt(p: Paint, s: &App, prompt: &ApprovalPrompt) -> El {
    let import = match &prompt.reason {
        ApprovalReason::Import { sections, unlock } => Some((sections, *unlock)),
        _ => None,
    };
    let typing = match &prompt.reason {
        ApprovalReason::Type { replaces, unlock } => Some((replaces, *unlock)),
        _ => None,
    };
    // A request that hands values out; the others write the store.
    let hands_out = import.is_none() && typing.is_none();
    // Nothing is approved without the passphrase: the button is dimmed
    // until one is typed. Enter in a field still leads to it.
    let ready = !s.answering && !s.approval_passphrase.text.is_empty();
    // What it says is the phone's page's too: see `Words`.
    let Words {
        title: _,
        question,
        summary,
        command_label,
        command_plain,
        command: shown,
        wants,
        asked_label,
        who,
        place,
        detail,
        why,
        trust,
        standing_label,
        standing,
    } = Words::of(prompt);
    let shown = shown.as_str();
    let command = col()
        .w_full()
        .max_h(132.0)
        .scroll(ScrollSpec {
            stick_bottom: false,
        })
        .padding(space::S3)
        .radius(radius::MD)
        .fill(p.t.bg)
        .border(p.hair, p.t.card_border)
        .child(
            text(shown)
                .key("kb-approval-command-line")
                .font(BODY.mono())
                .color(p.t.text)
                .spans(command_spans(p, shown))
                .w_full()
                .wrap(),
        );
    // Labelled only where the label says something: a script handed to a
    // shell, or a command line another machine reports.
    let command = if command_plain {
        col().key("kb-approval-command").w_full().child(command)
    } else {
        part(p, "kb-approval-command", command_label, command)
    };

    let n = prompt.keys.len();
    let all = s.approval_all_keys || n <= SHOWN_KEYS;
    let mut chips = row().w_full().flex_wrap().gap(space::S1).children(
        prompt
            .keys
            .iter()
            .take(if all { n } else { SHOWN_KEYS })
            .map(|k| key_chip(p, k, false)),
    );
    if n > SHOWN_KEYS {
        let label = if all {
            "Show fewer".to_owned()
        } else {
            format!("{} more", n - SHOWN_KEYS)
        };
        chips = chips.child(
            button(p, "kb-approval-more", &label, true, |s, _| {
                s.approval_all_keys = !s.approval_all_keys;
            })
            .h(22.0),
        );
    }

    let left = s.approval_left.or(prompt.left);
    let mut head = row().w_full().gap(space::S3).items_center().child(
        text(format!("{who}{place}"))
            .key("kb-approval-who")
            .font(type_::LABEL)
            .color(p.t.text_secondary)
            .spans(vec![Span::new(0, who.len()).bold().color(p.t.text)])
            .truncate()
            .grow(1.0),
    );
    if let Some(left) = left {
        head = head.child(
            text(format!("denied in {}", countdown(left)))
                .key("kb-approval-left")
                .font(type_::LABEL)
                .color(if left <= 30 {
                    p.warn
                } else {
                    p.t.text_secondary
                })
                .a11y_hidden(),
        );
    }

    let quiet = |key: &str, what: &str| {
        text(what)
            .key(key)
            .font(type_::LABEL)
            .color(p.t.text_secondary)
            .wrap()
    };
    let toggle = button(
        p,
        "kb-approval-toggle",
        if s.approval_details {
            "Hide details"
        } else {
            "Details"
        },
        true,
        |s, tx| {
            s.approval_details = !s.approval_details;
            // Looking is not answering: what is typed next still goes to
            // the passphrase, where no value is asked for first.
            if s.approval_values.is_empty() {
                s.approval_passphrase.focused = true;
                tx.focus("kb-approval-field", false);
            }
        },
    )
    .h(22.0);
    // The line under the command: what it gets, or for a request that
    // writes the store what approving does, with the way to the rest.
    let line = row()
        .w_full()
        .gap(space::S3)
        .items_center()
        .child(if hands_out {
            quiet("kb-approval-summary", &summary).grow(1.0)
        } else {
            quiet("kb-approval-trust", trust).grow(1.0)
        })
        .child(toggle);

    // The part that gives way, and scrolls, when the window is too short
    // for it all: the question, the passphrase and the buttons stay put.
    let mut body = col()
        .key("kb-approval-body")
        .w_full()
        .min_h(0.0)
        .shrink()
        .scroll(ScrollSpec {
            stick_bottom: false,
        })
        .scroll_edge_fade(24.0)
        .gap(space::S3)
        .child(command);
    body = match (import, typing) {
        (Some((sections, unlock)), _) => body.child(part(
            p,
            "kb-approval-import",
            wants.clone(),
            import_list(p, s, sections, unlock),
        )),
        (None, Some((replaces, _))) => body.child(part(
            p,
            "kb-approval-values",
            wants.clone(),
            value_list(p, s, &prompt.keys, replaces),
        )),
        (None, None) => body,
    };
    body = body.child(line);
    if s.approvals.len() > 1 {
        body = body.child(quiet(
            "kb-approval-queue",
            &format!("{} more waiting after this one", s.approvals.len() - 1),
        ));
    }
    if s.approval_details {
        let mut details = col().key("kb-approval-details").w_full().gap(space::S3);
        // With no key known there is still what it gets to say.
        if hands_out && n > 0 {
            details = details.child(part(p, "kb-approval-keys", wants, chips));
        } else if hands_out {
            details = details.child(quiet("kb-approval-keys", &wants));
        }
        details = details.child(part(
            p,
            "kb-approval-caller",
            asked_label,
            text(detail)
                .key("kb-approval-parents")
                .font(type_::MONO_CAPTION.mono())
                .color(p.t.text_secondary)
                .wrap(),
        ));
        if !why.is_empty() {
            details = details.child(part(
                p,
                "kb-approval-why",
                "Why it asks",
                quiet("kb-approval-why-text", &why),
            ));
        }
        if hands_out {
            details = details.child(part(
                p,
                "kb-approval-approving",
                "Approving",
                quiet("kb-approval-trust", trust),
            ));
        }
        if !standing.is_empty() {
            details = details.child(quiet("kb-approval-standing-text", &standing));
        }
        body = body.child(details);
    }

    let mut d = card(p)
        .key("kb-approval")
        .role("dialog")
        .label("Approve")
        .child(head)
        .child(
            text(question)
                .key("kb-approval-question")
                .font(TITLE)
                .color(p.t.text)
                .wrap(),
        )
        .child(body);
    if let Some(error) = &s.approval_error {
        d = d.child(
            text(error)
                .key("kb-approval-error")
                .font(BODY)
                .color(p.warn)
                .wrap(),
        );
    }
    d.child(
        field(
            p,
            "kb-approval-field",
            &s.approval_passphrase,
            "Passphrase",
            |s| &mut s.approval_passphrase,
        )
        .w_full()
        .secure()
        .on_submit(approve),
    )
    .child(
        row()
            .w_full()
            .gap(space::S3)
            .items_center()
            .child(button(p, "kb-approval-deny", "Deny", !s.answering, deny))
            .child(
                text(if typing.is_some() {
                    "Esc denies \u{00b7} Enter saves"
                } else {
                    "Esc denies \u{00b7} Enter approves"
                })
                .font(type_::LABEL)
                .color(p.t.text_secondary)
                .a11y_hidden()
                .grow(1.0),
            )
            // Beside the one that approves once, and never what Enter does.
            .children((!standing_label.is_empty()).then(|| {
                button(
                    p,
                    "kb-approval-standing",
                    &standing_label,
                    ready,
                    approve_standing,
                )
            }))
            .child(
                button(
                    p,
                    "kb-approval-ok",
                    if typing.is_some() { "Save" } else { "Approve" },
                    ready,
                    approve,
                )
                .fill(p.good.alpha(if ready { 0.28 } else { 0.08 }))
                .border(p.hair, p.good.alpha(if ready { 1.0 } else { 0.3 }))
                .default_button(),
            ),
    )
}

fn confirm(p: Paint, question: &str, yes: &str) -> El {
    card(p)
        .key("kb-confirm")
        .role("dialog")
        .label("Confirm")
        .child(text(question).font(BODY).color(p.t.text).wrap())
        .child(
            row()
                .gap(space::S2)
                .justify_end()
                .child(
                    button(p, "kb-confirm-no", "Cancel", true, |s, tx| {
                        send(s, Event::Cancel, Some(tx));
                    })
                    .default_button(),
                )
                .child(
                    button(p, "kb-confirm-yes", yes, true, |s, tx| {
                        send(s, Event::Confirm, Some(tx));
                    })
                    .fill(p.warn.alpha(0.24)),
                ),
        )
}

/// The environments in `sections`, in a sentence.
fn sections(sections: &[Section]) -> String {
    let names: Vec<String> = sections.iter().map(ToString::to_string).collect();
    names.join(", ")
}

/// One secret to tick in a prompt: its `name`, and under it `readers`, the
/// environments that read it too, if any do. Pressing it sends
/// [`Event::Also`].
fn tick_row(
    p: Paint,
    key: String,
    label: String,
    on: bool,
    secret: &Origin,
    name: String,
    readers: Option<String>,
) -> El {
    let secret = secret.clone();
    let tick = el()
        .w(16.0)
        .h(16.0)
        .center()
        .radius(radius::SM)
        .fill(if on {
            p.t.indicator.alpha(0.28)
        } else {
            p.t.control_track
        })
        .border(p.hair, if on { p.t.indicator } else { p.t.card_border })
        .child(
            text(if on { "\u{2713}" } else { "" })
                .font(type_::LABEL)
                .color(p.t.text)
                .a11y_hidden(),
        );
    row()
        .key(key)
        .role("checkbox")
        .label(label)
        .checked(on)
        .focusable(true)
        .w_full()
        .gap(space::S2)
        .padding(space::S1)
        .radius(radius::MD)
        .hover(p.t.hover)
        .press(p.t.press)
        .on_press_tx(move |s: &mut App, tx| {
            send(s, Event::Also(secret.clone()), Some(tx));
        })
        .child(tick)
        .child(
            col()
                .gap(space::S1)
                .grow(1.0)
                .shrink()
                .child(text(name).font(BODY.mono()).color(p.t.text).wrap())
                .children(readers.map(|readers| {
                    text(readers)
                        .font(type_::LABEL)
                        .color(p.t.text_secondary)
                        .wrap()
                })),
        )
}

/// Who else reads a marked secret, and which of them ask for approval
/// whatever becomes of its mark: those marked sensitive themselves, or
/// waiting for a decision.
fn readers_of_marked(shared: &SharedSecret) -> String {
    let (open, kept): (Vec<Section>, Vec<Section>) = shared
        .with
        .iter()
        .cloned()
        .partition(|s| shared.open.contains(s));
    let still = if kept.len() == 1 {
        "which still asks for approval"
    } else {
        "which still ask for approval"
    };
    match (open.is_empty(), kept.is_empty()) {
        (_, true) => format!("also read by {}", sections(&open)),
        (true, false) => format!("also read by {}, {still}", sections(&kept)),
        (false, false) => format!(
            "also read by {}, and by {}, {still}",
            sections(&open),
            sections(&kept)
        ),
    }
}

/// Before an environment is acknowledged as not production: the marked
/// secrets it reads, which stay marked unless ticked. None is ticked to
/// begin with.
fn unmarking_prompt(p: Paint, unmarking: &Unmarking) -> El {
    let of = format!("{} / {}", unmarking.project, unmarking.env);
    let n = unmarking.marked.len();
    let mut list = col().gap(space::S2).w_full();
    for (i, shared) in unmarking.marked.iter().enumerate() {
        list = list.child(tick_row(
            p,
            format!("kb-unmarking-{i}"),
            format!("Unmark {}", shared.name()),
            unmarking.unmark.contains(&shared.secret),
            &shared.secret,
            shared.name(),
            Some(readers_of_marked(shared)),
        ));
    }
    card(p)
        .key("kb-unmarking")
        .role("dialog")
        .label("Marked secrets")
        .child(
            text(format!("{of} is not production"))
                .font(TITLE)
                .color(p.t.text)
                .wrap(),
        )
        .child(
            text(format!(
                "It reads {}, so it goes on asking for approval for {} keys. Tick one to \
                 remove its mark: then agents read its keys without approval, in every \
                 environment that reads it and is not marked sensitive itself.",
                if n == 1 {
                    "1 secret that is marked sensitive".to_owned()
                } else {
                    format!("{n} secrets that are marked sensitive")
                },
                if n == 1 { "its" } else { "their" },
            ))
            .key("kb-unmarking-why")
            .font(BODY)
            .color(p.t.text_secondary)
            .wrap(),
        )
        .child(
            col()
                .key("kb-unmarking-list")
                .w_full()
                .max_h(280.0)
                .scroll(ScrollSpec {
                    stick_bottom: false,
                })
                .child(list),
        )
        .child(
            row()
                .gap(space::S2)
                .justify_end()
                .child(button(p, "kb-unmarking-no", "Cancel", true, |s, tx| {
                    send(s, Event::Cancel, Some(tx));
                }))
                .child(
                    button(
                        p,
                        "kb-unmarking-yes",
                        &match unmarking.unmark.len() {
                            0 => "Acknowledge, unmark nothing".to_owned(),
                            1 => "Acknowledge and unmark 1 secret".to_owned(),
                            n => format!("Acknowledge and unmark {n} secrets"),
                        },
                        true,
                        |s, tx| {
                            send(s, Event::Confirm, Some(tx));
                        },
                    )
                    .default_button(),
                ),
        )
}

/// Before secrets are unmarked from an environment's keys: every marked
/// secret its keys come from, the one asked for ticked, and who else reads
/// each. The ticked are unmarked with one passphrase.
fn unmarks_prompt(p: Paint, unmarks: &Unmarks) -> El {
    let mut list = col().gap(space::S2).w_full();
    for (i, marked) in unmarks.marked.iter().enumerate() {
        let name = match &marked.shared {
            Some(shared) => shared.name(),
            None => marked.secret.to_string(),
        };
        list = list.child(tick_row(
            p,
            format!("kb-unmarks-{i}"),
            format!("Unmark {name}"),
            unmarks.unmark.contains(&marked.secret),
            &marked.secret,
            name,
            marked.shared.as_ref().map(readers_of_marked),
        ));
    }
    let n = unmarks.unmark.len();
    card(p)
        .key("kb-unmarks")
        .role("dialog")
        .label("Unmark secrets")
        .child(text("Unmark secrets").font(TITLE).color(p.t.text).wrap())
        .child(
            text(
                "Agents then read a secret's keys without approval, in every environment that \
                 reads it and is not marked sensitive itself. Tick each to unmark: they take \
                 one passphrase together.",
            )
            .key("kb-unmarks-why")
            .font(BODY)
            .color(p.t.text_secondary)
            .wrap(),
        )
        .child(
            col()
                .key("kb-unmarks-list")
                .w_full()
                .max_h(280.0)
                .scroll(ScrollSpec {
                    stick_bottom: false,
                })
                .child(list),
        )
        .child(
            row()
                .gap(space::S2)
                .justify_end()
                .child(button(p, "kb-unmarks-no", "Cancel", true, |s, tx| {
                    send(s, Event::Cancel, Some(tx));
                }))
                .child(
                    button(
                        p,
                        "kb-unmarks-yes",
                        &match n {
                            0 => "Unmark".to_owned(),
                            1 => "Unmark 1 secret".to_owned(),
                            n => format!("Unmark {n} secrets"),
                        },
                        n > 0,
                        |s, tx| {
                            send(s, Event::Confirm, Some(tx));
                        },
                    )
                    .default_button(),
                ),
        )
}

/// Before an environment is marked sensitive: the secrets it shares with
/// open environments, which stay unmarked unless ticked, and those marked
/// all the same because their names look like production.
fn sharing_prompt(p: Paint, sharing: &Sharing) -> El {
    let of = format!("{} / {}", sharing.project, sharing.env);
    let mut d = card(p)
        .key("kb-sharing")
        .role("dialog")
        .label("Shared secrets")
        .child(
            text(format!("Mark {of} sensitive"))
                .font(TITLE)
                .color(p.t.text)
                .wrap(),
        );
    let mut list = col().gap(space::S2).w_full();
    if !sharing.open.is_empty() {
        let n = sharing.open.len();
        d = d.child(
            text(format!(
                "Other environments read {} too. {} unmarked, so those environments go on \
                 running without approval. Tick one to mark it as well: then every \
                 environment that reads it asks for approval for its keys.",
                if n == 1 {
                    "1 of its secrets".to_owned()
                } else {
                    format!("{n} of its secrets")
                },
                if n == 1 { "It stays" } else { "They stay" },
            ))
            .key("kb-sharing-why")
            .font(BODY)
            .color(p.t.text_secondary)
            .wrap(),
        );
        for (i, shared) in sharing.open.iter().enumerate() {
            list = list.child(tick_row(
                p,
                format!("kb-sharing-{i}"),
                format!("Mark {} as well", shared.name()),
                sharing.also.contains(&shared.secret),
                &shared.secret,
                shared.name(),
                Some(format!("also read by {}", sections(&shared.open))),
            ));
        }
    }
    if !sharing.production.is_empty() {
        list = list.child(
            text(
                "Marked with it although other environments read them, because their names \
                 look like production:",
            )
            .key("kb-sharing-production")
            .font(BODY)
            .color(p.t.text_secondary)
            .wrap(),
        );
        for shared in &sharing.production {
            list = list.child(
                col()
                    .gap(space::S1)
                    .w_full()
                    .padding(space::S1)
                    .child(text(shared.name()).font(BODY.mono()).color(p.t.text).wrap())
                    .child(
                        text(format!("also read by {}", sections(&shared.open)))
                            .font(type_::LABEL)
                            .color(p.t.text_secondary)
                            .wrap(),
                    ),
            );
        }
    }
    let ticked = sharing.also.len();
    d.child(
        col()
            .key("kb-sharing-list")
            .w_full()
            .max_h(280.0)
            .scroll(ScrollSpec {
                stick_bottom: false,
            })
            .child(list),
    )
    .child(
        row()
            .gap(space::S2)
            .justify_end()
            .child(button(p, "kb-sharing-no", "Cancel", true, |s, tx| {
                send(s, Event::Cancel, Some(tx));
            }))
            .child(
                button(
                    p,
                    "kb-sharing-yes",
                    &match ticked {
                        0 => "Mark sensitive".to_owned(),
                        1 => "Mark it and 1 secret".to_owned(),
                        n => format!("Mark it and {n} secrets"),
                    },
                    true,
                    |s, tx| {
                        send(s, Event::Confirm, Some(tx));
                    },
                )
                .default_button(),
            ),
    )
}

fn passphrase_prompt(p: Paint, purpose: &Purpose, edit: &TextEdit) -> El {
    let (why, ok) = match purpose {
        Purpose::Unlock => ("to unlock it".to_owned(), "Unlock"),
        Purpose::Inspect(env) => (
            format!("to show environment {env}, marked sensitive"),
            "Show",
        ),
        Purpose::Reveal { env, key } => (format!("to reveal {key} of {env}"), "Reveal"),
        Purpose::ConnectProton { .. } => ("to save the Proton Pass token".to_owned(), "Connect"),
        Purpose::Acknowledge {
            project,
            env,
            acknowledged: true,
            unmark,
        } => (
            format!(
                "to acknowledge environment {env} of {project} as not production{}",
                match unmark.len() {
                    0 => String::new(),
                    1 => ", and unmark 1 secret it reads".to_owned(),
                    n => format!(", and unmark {n} secrets it reads"),
                }
            ),
            "Acknowledge",
        ),
        Purpose::Acknowledge {
            project,
            env,
            acknowledged: false,
            ..
        } => (
            format!("to take back that environment {env} of {project} is not production"),
            "Take back",
        ),
        Purpose::AcknowledgeAll(envs) => (
            format!(
                "to acknowledge {} environments as not production",
                envs.len()
            ),
            "Acknowledge",
        ),
        Purpose::Mark { mark, sensitive } => {
            let what = match mark {
                Mark::Key { section, key } => format!("key {key} of [{section}]"),
                Mark::Env { project, env, also } if also.is_empty() => {
                    format!("environment {env} of {project}")
                }
                Mark::Env { project, env, also } => format!(
                    "environment {env} of {project}, and with it {} shared secret{}",
                    also.len(),
                    if also.len() == 1 { "" } else { "s" }
                ),
                Mark::Secret(secret) => format!("secret {secret}"),
            };
            // A secret's mark is not one environment's.
            let wherever = match mark {
                Mark::Secret(_) if *sensitive => ", in every environment that reads it",
                _ => "",
            };
            (
                format!(
                    "to {} {what} sensitive{wherever}",
                    if *sensitive { "mark" } else { "unmark" }
                ),
                if *sensitive { "Mark" } else { "Unmark" },
            )
        }
        Purpose::Unmark(secrets) => {
            let what = match secrets.as_slice() {
                [secret] => format!("secret {secret}"),
                many => format!("{} secrets", many.len()),
            };
            (format!("to unmark {what}"), "Unmark")
        }
        Purpose::RotateGrant(grant) => (
            format!(
                "to give machine {}'s grant for {} a new token",
                grant.machine, grant.project
            ),
            "New token",
        ),
        Purpose::RevokeGrant(grant) => (
            format!(
                "to revoke machine {}'s grant for {}",
                grant.machine, grant.project
            ),
            "Revoke",
        ),
        Purpose::PairPhone(phone) => (format!("to let {} approve requests", phone.name), "Pair"),
        Purpose::UnpairPhone(name) => (format!("to remove {name}, the paired phone"), "Remove"),
    };
    card(p)
        .key("kb-passphrase")
        .role("dialog")
        .label("Passphrase")
        .child(
            text(format!("The local store's passphrase, {why}."))
                .font(BODY)
                .color(p.t.text)
                .wrap(),
        )
        .child(
            field(p, "kb-passphrase-field", edit, "Passphrase", |s| {
                &mut s.passphrase
            })
            .w_full()
            .secure()
            .on_submit(submit_passphrase),
        )
        .child(
            row()
                .gap(space::S2)
                .justify_end()
                .child(button(p, "kb-passphrase-no", "Cancel", true, |s, tx| {
                    send(s, Event::Cancel, Some(tx));
                }))
                .child(button(p, "kb-passphrase-ok", ok, true, submit_passphrase).default_button()),
        )
}

/// A button; one not `enabled` shows dimmed and does nothing.
fn button(
    p: Paint,
    key: &str,
    label: &str,
    enabled: bool,
    f: impl Fn(&mut App, &mut Tx) + 'static,
) -> El {
    let color = if enabled {
        p.t.text
    } else {
        p.t.text_secondary
    };
    let b = el()
        .key(key)
        .role("button")
        .label(label)
        .focusable(true)
        .h(26.0)
        .px(space::S3)
        .center()
        .radius(radius::MD)
        .fill(p.t.control_track)
        .disabled(!enabled)
        .child(text(label).font(type_::LABEL).color(color).a11y_hidden());
    if enabled {
        b.hover(p.t.hover).press(p.t.press).on_press_tx(f)
    } else {
        b
    }
}

/// One of a set of buttons, `on` when picked.
fn choice(p: Paint, key: &str, label: &str, on: bool, f: fn(&mut AddForm)) -> El {
    button(p, key, label, true, move |s, _| f(&mut s.form))
        .checked(on)
        .fill(if on {
            p.t.indicator.alpha(0.28)
        } else {
            p.t.control_track
        })
        .border(
            p.hair,
            if on {
                p.t.indicator
            } else {
                Color::TRANSPARENT
            },
        )
}

fn field(
    p: Paint,
    key: &str,
    edit: &TextEdit,
    placeholder: &str,
    access: fn(&mut App) -> &mut TextEdit,
) -> El {
    text_input(edit, BODY)
        .single_line()
        .placeholder(placeholder, p.t.text_secondary)
        .key(key)
        .label(placeholder)
        .px(space::S2)
        .py(space::S1)
        .radius(radius::MD)
        .fill(p.t.control_track)
        .on_edit(access)
}

/// The bar across the top. On macOS the window's own buttons are drawn
/// over its start, `lights` points in: the name begins past them.
fn header(p: Paint, s: &App, lights: f32) -> El {
    let conn = &s.machine.conn;
    let idle = s.machine.pending == Pending::None;
    let lock = match conn {
        // The locked screen has its own.
        Conn::Up { locked: true } if locked_screen(s) => None,
        Conn::Up { locked: true } => Some(button(p, "kb-lock", "Unlock", idle, |s, tx| {
            send(s, Event::Unlock(None), Some(tx));
        })),
        _ => Some(button(
            p,
            "kb-lock",
            "Lock",
            idle && matches!(conn, Conn::Up { .. }),
            |s, tx| send(s, Event::Lock, Some(tx)),
        )),
    };
    let (label, color) = match conn {
        Conn::Unknown => ("Connecting…", p.t.text_secondary),
        Conn::Up { locked: true } => ("Locked", p.warn),
        Conn::Up { locked: false } => ("Unlocked", p.good),
        Conn::Down(_) => ("Daemon unreachable", p.warn),
    };
    row()
        .key("kb-header")
        .h(HEADER)
        .w_full()
        .pl(space::S6.max(lights + space::S3))
        .pr(space::S6)
        .center_y()
        .justify_between()
        .child(
            row()
                .gap(space::S2)
                .center_y()
                .child(seal(22.0).key("kb-seal"))
                .child(text("kagebunshin").font(TITLE).color(p.t.text)),
        )
        .child(
            row()
                .gap(space::S3)
                .center_y()
                .child(badge("kb-conn", label, color).label(label))
                .children(lock)
                .child(button(p, "kb-refresh", "Refresh", true, refresh)),
        )
}

fn badge(key: impl Into<String>, label: &str, color: Color) -> El {
    el().key(key)
        .h(18.0)
        .px(space::S2)
        .center()
        .radius(radius::SM)
        .fill(color.alpha(0.16))
        .child(text(label).font(type_::LABEL).color(color))
}

/// The seal: the launcher icon's dark tile with the shadow clone on it in
/// silver, `side` points across, the same in a light window as a dark one.
fn seal(side: f32) -> El {
    // The launcher icon's colours: packaging/icons/kagebunshin.svg.
    let shade = |r: u8, g: u8, b: u8| {
        rune::color::hex(&format!("#{r:02x}{g:02x}{b:02x}")).unwrap_or(Color::BLACK)
    };
    let (top, bottom) = (shade(0x2a, 0x2f, 0x39), shade(0x0e, 0x10, 0x16));
    let (silver, edge) = (shade(0xf4, 0xf5, 0xfa), shade(0x47, 0x4d, 0x5a));
    let layers = shell::layers();
    let span = |of: fn(&(f32, f32)) -> f32| {
        let all = || layers.iter().flat_map(|(outline, _)| outline).map(of);
        (
            all().fold(f32::INFINITY, f32::min),
            all().fold(f32::NEG_INFINITY, f32::max),
        )
    };
    let ((left, right), (up, down)) = (span(|p| p.0), span(|p| p.1));
    let (wide, high) = ((right - left).max(1.0), (down - up).max(1.0));
    // An opening shows the tile, which no shape can cut: it is painted in
    // the tile's shade where the figure's middle lies.
    let open = top.mix(bottom, 0.5);
    let figure = layers.iter().fold(Shape::new(), |shape, (outline, solid)| {
        let points: Vec<[f32; 2]> = outline.iter().map(|(x, y)| [x - left, y - up]).collect();
        shape.fill(points, if *solid { silver } else { open })
    });
    let height = side * 0.66;
    el().size(side, side)
        .radius(side * 0.236)
        .gradient(top, bottom)
        .border(1.0, edge)
        .center()
        .a11y_hidden()
        .child(canvas(figure.view_box(wide, high)).size(height * wide / high, height))
}

fn card(p: Paint) -> El {
    col()
        .padding(space::S3)
        .gap(space::S2)
        .fill(p.t.card)
        .radius(radius::LG)
        .border(p.hair, p.t.card_border)
}

fn heading(p: Paint, title: &str) -> El {
    text(title).font(type_::SECTION).color(p.t.text_secondary)
}

/// Puts the notice away. One that only says a change was made also goes
/// by itself; a failure, or one with warnings, stays until this or the
/// next change.
fn dismiss(p: Paint) -> El {
    button(p, "kb-notice-dismiss", "Dismiss", true, |s, tx| {
        send(s, Event::Dismiss, Some(tx));
    })
}

fn problem_box(p: Paint, key: &str, problem: &Problem) -> El {
    let mut b = card(p)
        .key(key)
        .border(p.hair, p.warn)
        .child(text(&problem.message).font(BODY).color(p.t.text).wrap());
    if let Some(hint) = &problem.hint {
        b = b.child(
            text(format!("hint: {hint}"))
                .font(BODY)
                .color(p.t.text_secondary)
                .wrap(),
        );
    }
    b
}

fn project_row(
    p: Paint,
    project: &ProjectView,
    label: &str,
    grouped: bool,
    shown: Option<&ProjectName>,
    here: Option<&ProjectName>,
) -> El {
    let on = shown == Some(&project.name);
    let name = project.name.clone();
    let mut r = row()
        .key(format!("kb-project-{}", project.name))
        .role("button")
        .label(project.name.as_str())
        .checked(on)
        .focusable(true)
        .h(32.0)
        .px(space::S2)
        .gap(space::S2)
        .center_y()
        .radius(radius::MD)
        .fill(if on { p.t.press } else { Color::TRANSPARENT })
        .hover(p.t.hover)
        .on_press_tx(move |s: &mut App, tx| show(s, &name, Some(tx)));
    if grouped {
        r = r.pl(space::S6);
    }
    r = r.child(text(label).font(BODY).color(p.t.text).truncate().grow(1.0));
    if here == Some(&project.name) {
        r = r.child(badge("kb-here", "here", p.info));
    }
    r
}

/// What the window lists of the machine itself, under the projects.
fn machine_row(p: Paint, key: &str, label: &str, to: View, on: bool) -> El {
    row()
        .key(key)
        .role("button")
        .label(label)
        .checked(on)
        .focusable(true)
        .h(32.0)
        .px(space::S2)
        .center_y()
        .radius(radius::MD)
        .fill(if on { p.t.press } else { Color::TRANSPARENT })
        .hover(p.t.hover)
        .on_press_tx(move |s: &mut App, tx| go(s, to.clone(), tx))
        .child(
            text(label)
                .font(BODY)
                .color(p.t.text)
                .grow(1.0)
                .a11y_hidden(),
        )
}

/// The projects, and under them what is the machine's and no project's:
/// its providers, the machines let in remotely, the phone that approves
/// and its audit log.
fn sidebar(p: Paint, s: &App) -> El {
    let of_machine = matches!(
        s.view,
        View::Activity | View::Providers | View::Remote | View::Phone
    );
    // A project is the one on show only while something of it is.
    let shown = s.machine.shown.as_ref().map(|sh| &sh.project);
    let shown = shown.filter(|_| !of_machine);
    let here = s.catalog.here.as_ref().map(|h| &h.project);
    let mut list = card(p).key("kb-projects").padding(space::S1).gap(0.0);
    let machine = card(p)
        .key("kb-machine")
        .padding(space::S1)
        .gap(0.0)
        .child(machine_row(
            p,
            "kb-nav-providers",
            "Providers",
            View::Providers,
            s.view == View::Providers,
        ))
        .child(machine_row(
            p,
            "kb-nav-remote",
            "Remote agents",
            View::Remote,
            s.view == View::Remote,
        ))
        .child(machine_row(
            p,
            "kb-nav-phone",
            "Phone",
            View::Phone,
            s.view == View::Phone,
        ))
        .child(machine_row(
            p,
            "kb-nav-activity",
            "Activity",
            View::Activity,
            s.view == View::Activity,
        ));
    let side = col()
        .key("kb-sidebar")
        .w(200.0)
        .h_full()
        .gap(space::S2)
        .scroll(ScrollSpec {
            stick_bottom: false,
        })
        .child(heading(p, "Projects"));
    let with_machine = |side: El| {
        side.child(heading(p, "This machine").mt(space::S3))
            .child(machine)
    };
    if let Some(problem) = &s.catalog.problem {
        return with_machine(side.child(problem_box(p, "kb-config-problem", problem)));
    }
    // Projects that share a remote, a monorepo's, are grouped under it and
    // labelled by their folder.
    let mut groups: Vec<(Option<&RemoteId>, Vec<&ProjectView>)> = Vec::new();
    for project in &s.catalog.projects {
        let remote = project.remotes.first();
        match groups.iter_mut().find(|(r, _)| r.is_some() && *r == remote) {
            Some((_, members)) => members.push(project),
            None => groups.push((remote, vec![project])),
        }
    }
    for (i, (remote, members)) in groups.iter().enumerate() {
        let grouped = members.len() > 1;
        if grouped && let Some(remote) = remote {
            list = list.child(
                text(remote.to_string())
                    .key(format!("kb-group-{i}"))
                    .font(type_::LABEL)
                    .color(p.t.text_secondary)
                    .truncate()
                    .px(space::S2)
                    .pt(space::S2),
            );
        }
        for project in members {
            let label = match (&project.path, grouped) {
                (_, false) => project.name.to_string(),
                (Some(path), true) => path.rsplit('/').next().unwrap_or(path).to_owned(),
                (None, true) => "whole repo".to_owned(),
            };
            list = list.child(project_row(p, project, &label, grouped, shown, here));
        }
    }
    with_machine(side.child(list))
}

fn main_pane(p: Paint, s: &App) -> El {
    let mut body = col().gap(space::S3).w_full();
    // From EXPIRY_WARNING_DAYS out, until a new token is saved.
    if !s.machine.expiring.is_empty() {
        let now = kagebunshin::source::unix_now();
        let mut banner = card(p).key("kb-expiry").border(p.hair, p.warn);
        for e in &s.machine.expiring {
            let w = e.warning(now);
            let mut chars = w.chars();
            let w: String = chars
                .next()
                .into_iter()
                .flat_map(char::to_uppercase)
                .chain(chars)
                .collect();
            banner = banner.child(text(format!("⚠ {w}")).font(BODY).color(p.t.text).wrap());
        }
        body = body.child(banner);
    }
    if !s.machine.standing.is_empty() {
        body = body.child(standing_card(p, s));
    }
    if !s.machine.waiting.is_empty() {
        body = body.child(waiting_card(p, s));
    }
    let warnings = setup_warnings(s);
    if !warnings.is_empty() {
        body = body.child(warning_banner(p, s, &warnings));
    }
    let locked = locked_screen(s);
    match &s.machine.notice {
        // The locked screen says it is locked, and shows what failed itself.
        Some(Notice::Done { warnings, .. }) if locked && warnings.is_empty() => {}
        Some(Notice::Failed(_)) if locked => {}
        Some(Notice::Done { message, warnings }) => {
            let mut n = card(p).key("kb-notice").border(p.hair, p.good).child(
                row()
                    .w_full()
                    .gap(space::S2)
                    .center_y()
                    .child(text(message).font(BODY).color(p.t.text).wrap().grow(1.0))
                    .child(dismiss(p)),
            );
            for w in warnings {
                n = n.child(text(w).font(BODY).color(p.warn).wrap());
            }
            body = body.child(n);
        }
        Some(Notice::Failed(problem)) => {
            body = body.child(
                problem_box(p, "kb-notice-problem", problem)
                    .child(row().justify_end().child(dismiss(p))),
            );
        }
        None => {}
    }
    let shown = s.machine.shown.as_ref();
    let of_project = !matches!(
        s.view,
        View::Activity | View::Providers | View::Remote | View::Phone
    );
    if let Some(shown) = shown
        && of_project
        && !locked
    {
        body = body.child(project_header(p, s, shown));
    }
    let first = first_screen(s);
    if first {
        body = body.grow(1.0);
    } else if let Some(shown) = shown
        && of_project
    {
        body = body.child(tabs(p, s, shown));
    }
    body = match (&s.view, shown) {
        _ if first => body.child(first_steps(p)),
        _ if locked => body.child(locked_view(p, s)),
        (View::Activity, _) => body.child(activity_view(p, s)),
        (View::Providers, _) => body.child(providers_view(p, s)),
        (View::Remote, _) => body.child(remote_view(p, s)),
        (View::Phone, _) => body.child(phone_view(p, s)),
        (_, None) => body.child(
            text("Pick a project.")
                .key("kb-pick")
                .font(BODY)
                .color(p.t.text_secondary),
        ),
        (View::Keys, Some(shown)) => body.child(keys_view(p, s, shown)),
        (View::Key(key), Some(shown)) => body.child(key_view(p, s, shown, key)),
        (View::Sources, Some(shown)) => body.child(sources_view(p, s, shown)),
    };
    // `shrink` keeps the pane to the window's width whatever is in it: text
    // wraps or is cut, and nothing is pushed off the right edge.
    col().key("kb-main").grow(1.0).shrink().h_full().child(
        col()
            .key("kb-detail")
            .grow(1.0)
            .w_full()
            .scroll(ScrollSpec {
                stick_bottom: false,
            })
            .child(body),
    )
}

/// The setup warnings, at the top: the first in full and the rest on
/// request, with what can be done about them.
fn warning_banner(p: Paint, s: &App, warnings: &[String]) -> El {
    let n = warnings.len();
    let mut first = row().gap(space::S2).center_y().w_full().child(
        text(format!("⚠ {}", warnings[0]))
            .font(BODY)
            .color(p.t.text)
            .wrap()
            .grow(1.0),
    );
    if n > 1 {
        let label = if s.warnings_open {
            "Show fewer".to_owned()
        } else {
            format!("{} more", n - 1)
        };
        first = first.child(
            button(p, "kb-warnings", &label, true, |s, _| {
                s.warnings_open = !s.warnings_open;
            })
            .checked(s.warnings_open),
        );
    }
    let mut banner = card(p)
        .key("kb-setup-banner")
        .border(p.hair, p.warn)
        .fill(p.warn.alpha(0.08))
        .child(first);
    if s.warnings_open {
        for w in &warnings[1..] {
            banner = banner.child(text(format!("⚠ {w}")).font(BODY).color(p.t.text).wrap());
        }
    }
    let ack: Vec<EnvName> = to_acknowledge(s)
        .into_iter()
        .filter(|env| !waits(s, env))
        .collect();
    if !ack.is_empty() {
        let mut r = row().gap(space::S2).center_y();
        for env in ack {
            r = r.child(acknowledge_button(p, s, &env, true));
        }
        banner = banner.child(r);
    }
    banner
}

/// The project on show: its name, where it is checked out, and how many
/// keys its environments set.
/// The locked screen: the passphrase, and what locked means. See
/// [`locked_screen`].
fn locked_view(p: Paint, s: &App) -> El {
    let pending = &s.machine.pending;
    let running = matches!(pending, Pending::Running(_));
    let mut c = card(p)
        .key("kb-locked-screen")
        .w(440.0)
        .padding(space::S6)
        .gap(space::S3)
        .child(masthead(
            p,
            "Locked",
            "No agent or command gets a value until you unlock: each request is refused and \
             told to ask you.",
            "kb-locked-means",
        ))
        .child(
            field(p, "kb-unlock-field", &s.passphrase, "Passphrase", |s| {
                &mut s.passphrase
            })
            .w_full()
            .mt(space::S2)
            .secure()
            .on_submit(unlock),
        );
    if *pending == Pending::Passphrase(Purpose::Unlock) {
        c = c.child(
            text("The local store has a passphrase: type it to unlock.")
                .key("kb-unlock-needed")
                .font(BODY)
                .color(p.warn)
                .wrap(),
        );
    }
    if let Some(Notice::Failed(problem)) = &s.machine.notice {
        c = c.child(problem_box(p, "kb-notice-problem", problem));
    }
    c = c.child(
        row()
            .w_full()
            .gap(space::S3)
            .center_y()
            .justify_between()
            .child(
                text("Or run `kagebunshin unlock` in a terminal.")
                    .font(type_::LABEL)
                    .color(p.t.text_secondary),
            )
            .child(
                button(
                    p,
                    "kb-unlock",
                    if running {
                        "Unlocking\u{2026}"
                    } else {
                        "Unlock"
                    },
                    !running,
                    unlock,
                )
                .fill(p.info.alpha(0.28))
                .border(p.hair, p.info)
                .default_button(),
            ),
    );
    row().w_full().justify_center().pt(space::S6).child(c)
}

fn project_header(p: Paint, s: &App, shown: &Shown) -> El {
    let project = s.catalog.projects.iter().find(|x| x.name == shown.project);
    let mut place: Vec<String> = project
        .and_then(|x| x.remotes.first())
        .map(|r| r.to_string())
        .into_iter()
        .collect();
    if let Some(path) = project.and_then(|x| x.path.as_ref()) {
        place.push(path.clone());
    }
    let mut names = BTreeSet::new();
    for c in &shown.columns {
        if let Detail::Loaded(EnvReport::Resolved { keys, vars, .. }) = &c.detail {
            names.extend(keys.iter().map(|k| &k.key));
            names.extend(vars.iter().map(|v| &v.key));
        }
    }
    let mut facts = place;
    let n = names.len();
    if shown.columns.iter().any(status_known) {
        facts.push(format!("{n} key{}", if n == 1 { "" } else { "s" }));
    }
    col()
        .key("kb-project-head")
        .gap(space::S1)
        .child(
            text(shown.project.as_str())
                .key("kb-title")
                .font(TITLE)
                .color(p.t.text),
        )
        .child(
            text(facts.join(" · "))
                .key("kb-project-facts")
                .font(BODY.mono())
                .color(p.t.text_secondary)
                .truncate(),
        )
}

/// The environments of the project on show, one of them chosen, and what
/// is listed of it: its keys or its sources.
fn tabs(p: Paint, s: &App, shown: &Shown) -> El {
    let at = chosen(s, shown).map(|c| &c.sel.env);
    let mut envs = row()
        .key("kb-envs")
        .flex_wrap()
        .gap(space::S1)
        .padding(2.0)
        .radius(radius::MD)
        .fill(p.t.control_track);
    for c in &shown.columns {
        let env = c.sel.env.clone();
        let on = at == Some(&env);
        let default = s
            .catalog
            .env(&shown.project, &env)
            .is_some_and(|(_, e)| e.default);
        let to = env.clone();
        let mut one = row()
            .key(format!("kb-env-{env}"))
            .role("button")
            .label(env_label(&env, default))
            .checked(on)
            .focusable(true)
            .h(26.0)
            .px(space::S3)
            .gap(space::S2)
            .center_y()
            .radius(radius::MD)
            .fill(if on {
                p.t.indicator.alpha(0.28)
            } else {
                Color::TRANSPARENT
            })
            .hover(p.t.hover)
            .on_press_tx(move |s: &mut App, tx| choose(s, to.clone(), tx))
            .child(
                text(env.as_str())
                    .key("kb-env-name")
                    .font(type_::LABEL)
                    .color(p.t.text)
                    .a11y_hidden(),
            );
        if default {
            one = one.child(
                text("default")
                    .font(type_::LABEL)
                    .color(p.t.text_secondary)
                    .a11y_hidden(),
            );
        }
        if c.marked() == Some(true) {
            one = one.child(badge("kb-env-sensitive", "sensitive", p.sensitive));
        }
        // What an environment not on show would otherwise hide.
        match &c.detail {
            Detail::Failed(_) => one = one.child(badge("kb-env-failed", "failed", p.warn)),
            Detail::Loaded(EnvReport::Resolved { missing, .. }) => {
                let n = missing.iter().flatten().count();
                if n > 0 {
                    one = one.child(badge("kb-env-missing", &format!("{n} missing"), p.warn));
                }
            }
            _ => {}
        }
        envs = envs.child(one);
    }
    let tab = |key: &str, label: &str, on: bool, to: View| {
        button(p, key, label, true, move |s, tx| go(s, to.clone(), tx))
            .checked(on)
            .fill(if on {
                p.t.indicator.alpha(0.28)
            } else {
                Color::TRANSPARENT
            })
    };
    row()
        .key("kb-tabs")
        .w_full()
        .flex_wrap()
        .gap(space::S3)
        .center_y()
        .child(envs)
        .child(
            row()
                .gap(space::S1)
                .center_y()
                .child(tab(
                    "kb-nav-keys",
                    "Keys",
                    matches!(s.view, View::Keys | View::Key(_)),
                    View::Keys,
                ))
                .child(tab(
                    "kb-nav-sources",
                    "Sources",
                    s.view == View::Sources,
                    View::Sources,
                )),
        )
}

/// The approvals that stand: who gets which environment without being
/// asked, for how long, and the button that ends it. Ending takes no
/// passphrase: it only tightens.
fn standing_card(p: Paint, s: &App) -> El {
    let mut c = card(p).key("kb-standing");
    for (i, stands) in s.machine.standing.iter().enumerate() {
        let (project, env) = (stands.project.clone(), stands.env.clone());
        c = c.child(
            row()
                .w_full()
                .gap(space::S3)
                .center_y()
                .child(
                    text(format!(
                        "{} gets {}/{} without asking, for {} more",
                        stands.holder,
                        stands.project,
                        stands.env,
                        time_left(stands.left)
                    ))
                    .key(format!("kb-standing-{i}"))
                    .font(BODY)
                    .color(p.t.text)
                    .wrap()
                    .grow(1.0),
                )
                .child(button(
                    p,
                    &format!("kb-standing-end-{i}"),
                    "End now",
                    true,
                    move |s, tx| {
                        let (project, env) = (project.clone(), env.clone());
                        send(s, Event::EndStanding { project, env }, Some(tx));
                    },
                )),
        );
    }
    c
}

/// What the configuration of the project on show could do better: the
/// daemon's warnings for each environment, and the catalog's problems.
fn setup_warnings(s: &App) -> Vec<String> {
    let Some(shown) = &s.machine.shown else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for c in &shown.columns {
        let env = &c.sel.env;
        if let Some((_, e)) = s.catalog.env(&shown.project, env)
            && let Some(problem) = &e.problem
        {
            out.push(format!("{env}: {problem}"));
        }
        if let Detail::Loaded(EnvReport::Resolved { warnings, .. }) = &c.detail {
            // A wait the decision card above already lists is not repeated.
            out.extend(
                warnings
                    .iter()
                    .filter(|w| !(w.ends_with(ACKNOWLEDGE_HINT) && waits(s, env)))
                    .map(|w| format!("{env}: {w}")),
            );
        }
    }
    out.dedup();
    out
}

/// Whether `env` of the project on show is in the decision card.
fn waits(s: &App, env: &EnvName) -> bool {
    s.machine.shown.as_ref().is_some_and(|shown| {
        s.machine
            .waiting
            .iter()
            .any(|w| w.project == shown.project && &w.env == env)
    })
}

/// Every environment, of every project, that looks like production and
/// waits for a human decision, each with its two choices: mark it
/// sensitive, or acknowledge it is not production. With more than one,
/// all can be acknowledged under one passphrase.
fn waiting_card(p: Paint, s: &App) -> El {
    let waiting = &s.machine.waiting;
    let n = waiting.len();
    let mut head = row().gap(space::S2).center_y().w_full().child(
        text(if n == 1 {
            "1 environment waits for your decision".to_owned()
        } else {
            format!("{n} environments wait for your decision")
        })
        .font(type_::SECTION)
        .color(p.t.text)
        .grow(1.0),
    );
    if n > 1 {
        let all = Change::AcknowledgeAll(
            waiting
                .iter()
                .map(|w| Section {
                    project: w.project.clone(),
                    env: w.env.clone(),
                })
                .collect(),
        );
        head = head.child(button(
            p,
            "kb-waiting-all",
            "Acknowledge all as not production",
            s.idle(),
            move |s, tx| ask(s, all.clone(), tx),
        ));
    }
    let mut card = card(p)
        .key("kb-waiting")
        .border(p.hair, p.warn)
        .fill(p.warn.alpha(0.08))
        .child(head)
        .child(
            text(if n == 1 {
                "It looks like production. Until you decide, an agent gets its values only \
                 when you approve its request here. Mark it sensitive to keep it so, or \
                 acknowledge it is not production to let agents read it freely."
            } else {
                "They look like production. Until you decide, an agent gets their values \
                 only when you approve its request here. Mark one sensitive to keep it so, or \
                 acknowledge it is not production to let agents read it freely."
            })
            .font(BODY)
            .color(p.t.text_secondary)
            .wrap(),
        );
    for w in waiting {
        let id = format!("{}-{}", w.project, w.env);
        let mark = Change::Mark {
            mark: Mark::Env {
                project: w.project.clone(),
                env: w.env.clone(),
                also: Vec::new(),
            },
            sensitive: true,
        };
        let ack = Change::Acknowledge {
            project: w.project.clone(),
            env: w.env.clone(),
            acknowledged: true,
        };
        card = card.child(
            row()
                .key(format!("kb-waiting-{id}"))
                .gap(space::S2)
                .center_y()
                .w_full()
                .child(
                    col()
                        .gap(space::S1)
                        .grow(1.0)
                        .child(
                            text(format!("{} / {}", w.project, w.env))
                                .font(BODY.mono())
                                .color(p.t.text),
                        )
                        .child(text(&w.why).font(BODY).color(p.t.text_secondary).wrap()),
                )
                .child(button(
                    p,
                    &format!("kb-waiting-mark-{id}"),
                    "Mark sensitive",
                    s.idle(),
                    move |s, tx| ask(s, mark.clone(), tx),
                ))
                .child(button(
                    p,
                    &format!("kb-waiting-ack-{id}"),
                    "Not production",
                    s.idle(),
                    move |s, tx| ask(s, ack.clone(), tx),
                )),
        );
    }
    card
}

/// The environments on show the daemon warned look like production, and
/// which a person may acknowledge are not.
fn to_acknowledge(s: &App) -> Vec<EnvName> {
    let Some(shown) = &s.machine.shown else {
        return Vec::new();
    };
    shown
        .columns
        .iter()
        .filter(|c| {
            matches!(&c.detail, Detail::Loaded(EnvReport::Resolved { warnings, .. })
                if warnings.iter().any(|w| w.ends_with(ACKNOWLEDGE_HINT)))
        })
        .map(|c| c.sel.env.clone())
        .collect()
}

/// Says a column's environment is acknowledged as not production, if it
/// is, with the button that takes that back.
fn acknowledged_row(p: Paint, s: &App, c: &Column) -> Option<El> {
    let Detail::Loaded(EnvReport::Resolved {
        acknowledged: true, ..
    }) = &c.detail
    else {
        return None;
    };
    let env = &c.sel.env;
    Some(
        row()
            .key("kb-acknowledged")
            .w_full()
            .gap(space::S2)
            .center_y()
            .child(
                text(format!(
                    "{env} looks like production and is acknowledged as not: agents get its \
                     values without your approval."
                ))
                .font(BODY)
                .color(p.t.text_secondary)
                .wrap()
                .grow(1.0),
            )
            .child(acknowledge_button(p, s, env, false)),
    )
}

/// Acknowledges `env` of the project on show as not production, or with
/// `acknowledged` false takes that back.
fn acknowledge_button(p: Paint, s: &App, env: &EnvName, acknowledged: bool) -> El {
    let Some(shown) = &s.machine.shown else {
        return el();
    };
    let change = Change::Acknowledge {
        project: shown.project.clone(),
        env: env.clone(),
        acknowledged,
    };
    let (key, label) = if acknowledged {
        (
            format!("kb-acknowledge-{env}"),
            format!("{env} is not production"),
        )
    } else {
        (format!("kb-unacknowledge-{env}"), "Take back".to_owned())
    };
    button(p, &key, &label, s.idle(), move |s, tx| {
        ask(s, change.clone(), tx);
    })
}

/// The key column's width for `names`: the longest, in the mono face, and
/// room for the sensitive badge when a key has one.
fn key_width(names: &BTreeSet<&KeyName>, badge: bool) -> f32 {
    let longest = names.iter().map(|n| n.as_str().len()).max().unwrap_or(0);
    let longest = f32::from(u16::try_from(longest).unwrap_or(u16::MAX));
    let w = longest * 8.6 + if badge { 84.0 } else { 0.0 } + space::S3;
    w.max(160.0)
}

/// A list with more groups than this opens with them folded: a list of
/// secrets to pick from, where one with fewer opens showing its keys.
const FOLD_FROM: usize = 12;

/// A group of an environment's keys: the keys one secret sets.
struct Group<'a> {
    id: String,
    /// The secret's name, or what else holds the keys together.
    title: String,
    /// The secret's provider; none for a group that is not a secret's.
    provider: Option<&'static str>,
    /// The secrets whose keys these are; none for a group that is not a
    /// secret's.
    secrets: Vec<&'a Origin>,
    names: Vec<&'a KeyName>,
}

/// `names` grouped by the secret that sets each in environment `c`, in the
/// order the secrets load (a later one wins). Secrets of one source that
/// set a single key each share a group, so a source of one-value secrets
/// reads as a list of keys and not of headers. Plain settings and keys no
/// source sets come last.
fn groups<'a>(s: &App, shown: &Shown, c: &'a Column, names: &[&'a KeyName]) -> Vec<Group<'a>> {
    // Where a secret loads: its source and its place in that source's
    // list. A prefix names no order, so its secrets go by name.
    type Place = (usize, usize);
    let env = &c.sel.env;
    let sources = sources_of(s, shown, env);
    let mut secrets: Vec<(Place, &Origin, Vec<&'a KeyName>)> = Vec::new();
    let mut missing = Vec::new();
    let mut plain = Vec::new();
    for &name in names {
        let Some(k) = status(c, name) else {
            let is_var = matches!(&c.detail, Detail::Loaded(EnvReport::Resolved { vars, .. })
                if vars.iter().any(|v| &v.key == name));
            if is_var {
                plain.push(name);
            } else {
                missing.push(name);
            }
            continue;
        };
        if let Some((_, _, keys)) = secrets.iter_mut().find(|(_, o, _)| *o == &k.origin) {
            keys.push(name);
            continue;
        }
        let place = sources
            .iter()
            .enumerate()
            .find_map(|(i, x)| reads(x, &k.origin).map(|at| (i, at)))
            .unwrap_or((usize::MAX, usize::MAX));
        secrets.push((place, &k.origin, vec![name]));
    }
    secrets.sort_by(|(a, x, _), (b, y, _)| a.cmp(b).then_with(|| x.shown().cmp(y.shown())));

    let mut out: Vec<Group<'a>> = Vec::new();
    let mut i = 0;
    while i < secrets.len() {
        // One source's secrets: those with several keys each, then the rest
        // together.
        let source = secrets[i].0.0;
        let end = secrets[i..]
            .iter()
            .position(|(p, ..)| p.0 != source)
            .map_or(secrets.len(), |n| i + n);
        let of_source = &secrets[i..end];
        let singles: Vec<_> = of_source.iter().filter(|(.., k)| k.len() == 1).collect();
        let together = singles.len() > 1;
        for (_, origin, keys) in of_source {
            if together && keys.len() == 1 {
                continue;
            }
            out.push(Group {
                id: origin.id(),
                title: origin.shown().to_owned(),
                provider: Some(origin.provider.as_str()),
                secrets: vec![origin],
                names: keys.clone(),
            });
        }
        if together {
            let title = match sources.get(source) {
                Some(x) if x.locations.len() == 1 => x.locations[0].clone(),
                _ => "secrets of one key".to_owned(),
            };
            out.push(Group {
                id: format!("{env}-{source}"),
                title,
                provider: Some(singles[0].1.provider.as_str()),
                secrets: singles.iter().map(|(_, origin, _)| *origin).collect(),
                names: singles
                    .iter()
                    .flat_map(|(.., k)| k.iter().copied())
                    .collect(),
            });
        }
        i = end;
    }
    if !plain.is_empty() {
        out.push(Group {
            id: "vars".into(),
            title: "Plain settings (project file)".into(),
            provider: None,
            secrets: Vec::new(),
            names: plain,
        });
    }
    if !missing.is_empty() {
        out.push(Group {
            id: "missing".into(),
            title: "Set by no source".into(),
            provider: None,
            secrets: Vec::new(),
            names: missing,
        });
    }
    out
}

/// Whether secret `origin` is marked sensitive, as far as the keys it sets
/// in environment `c` say.
fn marked_secret(c: &Column, origin: &Origin) -> bool {
    matches!(&c.detail, Detail::Loaded(EnvReport::Resolved { keys, .. })
        if keys.iter().any(|k| &k.origin == origin && k.sensitive))
}

/// The provider's secrets marked sensitive that set keys of environment
/// `c`, each with who else reads it: what unmarking one from its group
/// lists, so the others go with the same passphrase. A store section is no
/// such secret: its keys are marked one by one.
fn marked_secrets(s: &App, shown: &Shown, c: &Column) -> Vec<Marked> {
    let Detail::Loaded(EnvReport::Resolved { keys, .. }) = &c.detail else {
        return Vec::new();
    };
    let marked: BTreeSet<&Origin> = keys
        .iter()
        .filter(|k| k.sensitive && k.origin.provider != Provider::File)
        .map(|k| &k.origin)
        .collect();
    marked
        .into_iter()
        .map(|secret| Marked {
            secret: secret.clone(),
            shared: shared_as(s, &shown.project, &c.sel.env, secret).cloned(),
        })
        .collect()
}

/// The button that unmarks `secrets`, after listing them among the marked
/// secrets of environment `c` to tick more. It sits beside the `sensitive`
/// tag it removes: on a group's header, or on a key's row.
fn unmark_button(
    p: Paint,
    s: &App,
    shown: &Shown,
    c: &Column,
    id: &str,
    secrets: Vec<Origin>,
) -> El {
    let label = if secrets.len() == 1 {
        "Unmark secret…"
    } else {
        "Unmark secrets…"
    };
    let unmarks = Unmarks {
        marked: marked_secrets(s, shown, c),
        unmark: secrets,
    };
    button(
        p,
        &format!("kb-unmark-{id}"),
        label,
        s.idle(),
        move |s, tx| {
            send(s, Event::Unmark(unmarks.clone()), Some(tx));
        },
    )
}

/// What the header of group `g` does about its secrets' marks: unmarks
/// them where the header says they are marked, or marks its one secret.
/// Nothing for store keys, each marked by itself on its page, for a group
/// that is no secret's, or for one of several secrets of which some are
/// marked: there each marked key's row has the button.
fn group_action(p: Paint, s: &App, shown: &Shown, c: &Column, g: &Group) -> Option<El> {
    let secrets: Vec<&Origin> = g
        .secrets
        .iter()
        .copied()
        .filter(|o| o.provider != Provider::File)
        .collect();
    let id = g.id.replace('/', ":");
    if !secrets.is_empty() && secrets.iter().all(|o| marked_secret(c, o)) {
        let secrets = secrets.into_iter().cloned().collect();
        return Some(unmark_button(p, s, shown, c, &id, secrets));
    }
    let [secret] = secrets.as_slice() else {
        return None;
    };
    let change = Change::Mark {
        mark: Mark::Secret((*secret).clone()),
        sensitive: true,
    };
    Some(button(
        p,
        &format!("kb-mark-{id}"),
        "Mark secret",
        s.idle(),
        move |s, tx| ask(s, change.clone(), tx),
    ))
}

/// What the daemon said of secret `origin` as `env` of `project` reads it,
/// if other environments read it too: by its name, or under a prefix all
/// of which they read.
fn shared_as<'a>(
    s: &'a App,
    project: &ProjectName,
    env: &EnvName,
    origin: &Origin,
) -> Option<&'a SharedSecret> {
    // A source names a secret as it is shown, which for a Proton key is not
    // its id.
    let same = |sh: &SharedSecret| {
        sh.secret.provider == origin.provider && sh.secret.location == origin.shown()
    };
    let covers = |sh: &SharedSecret| {
        same(sh)
            || (sh.prefix
                && sh.secret.provider == origin.provider
                && origin.shown().starts_with(sh.secret.location.as_str()))
    };
    let mine = || s.machine.shared.iter().filter(|sh| sh.of(project, env));
    // Its own name says more than a prefix it falls under.
    mine()
        .find(|sh| same(sh))
        .or_else(|| mine().find(|sh| covers(sh)))
}

/// The sources of `env` in the project shown, in order.
fn sources_of<'a>(s: &'a App, shown: &Shown, env: &EnvName) -> &'a [SourceView] {
    s.catalog
        .env(&shown.project, env)
        .map(|(_, e)| e.sources.as_slice())
        .unwrap_or_default()
}

/// Where in source `x`'s list the secret `origin` is, if `x` reads it; a
/// prefix reads everything under it and gives no place. A source names a
/// secret as it is shown.
fn reads(x: &SourceView, origin: &Origin) -> Option<usize> {
    if x.provider != origin.provider.as_str() {
        return None;
    }
    x.locations
        .iter()
        .position(|l| l == origin.shown())
        .or_else(|| {
            let under = |l: &String| x.select == "prefix" && origin.shown().starts_with(l.as_str());
            x.locations.iter().any(under).then_some(usize::MAX)
        })
}

/// The line a person pastes into their coding agent, word for word.
const PASTE_LINE: &str =
    "Set up kagebunshin here: run `kagebunshin next` and do what it says until it says done.";

/// A command to run, or a line to paste: a block in a face that can be
/// selected, with the button that copies it inside.
fn command_row(p: Paint, key: &str, command: &str) -> El {
    let copied = command.to_owned();
    row()
        .key(key)
        .w_full()
        .gap(space::S2)
        .center_y()
        .py(space::S2)
        .pl(space::S3)
        .pr(space::S2)
        .radius(radius::MD)
        // A shade off whatever it lies on, a card or the window, light or dark.
        .fill(p.t.text.alpha(0.05))
        .border(p.hair, p.t.card_border)
        .child(
            text(command)
                .font(BODY.mono())
                .color(p.t.text)
                .selectable(true)
                .wrap()
                .grow(1.0),
        )
        .child(button(
            p,
            &format!("{key}-copy"),
            "Copy",
            true,
            move |_, tx| tx.copy(copied.clone()),
        ))
}

/// The first screen's width.
const NARROW: f32 = 560.0;

/// The seal over a title and a line under it, centred: what opens the
/// first screen and the locked one.
fn masthead(p: Paint, title: &str, line: &str, line_key: &str) -> El {
    col()
        .w_full()
        .items_center()
        .gap(space::S2)
        .child(seal(56.0).mb(space::S2))
        .child(text(title).key("kb-title").font(HEADLINE).color(p.t.text))
        .child(
            text(line)
                .key(line_key)
                .font(BODY)
                .color(p.t.text_secondary)
                .align(Align::Center)
                .w_full()
                .wrap(),
        )
}

/// With no project yet, the first screen: what kagebunshin is, and the
/// two steps that set up the first projects. The window is open, so the
/// agent can do the import and this window asks before it is written;
/// the terminal's way is under them.
fn first_steps(p: Paint) -> El {
    let step = |n: &str, title: &str, what: &str| {
        row()
            .w_full()
            .gap(space::S3)
            .child(
                el().size(22.0, 22.0)
                    .radius(11.0)
                    .center()
                    .fill(p.t.control_off)
                    .child(text(n).font(type_::LABEL).color(p.t.text)),
            )
            .child(
                col()
                    .grow(1.0)
                    .shrink()
                    .gap(space::S2)
                    .child(text(title).font(TITLE).color(p.t.text))
                    .child(text(what).font(BODY).color(p.t.text_secondary).wrap()),
            )
    };
    let several = "For several checkouts at once, name them: kagebunshin next DIR…";
    let command = several.find("kagebunshin").unwrap_or(several.len());
    let first = step(
        "1",
        "Tell your coding agent",
        "Paste this into your coding agent, in a checkout to set up. It imports the checkout's \
         .env, drafts the project and tells you what only you can do.",
    );
    let second = step(
        "2",
        "Approve the import here",
        "Keep this window open. Before anything is written it lists each file and key by \
         name here, and takes the store passphrase once.",
    );
    let indent = 22.0 + space::S3;
    let steps = card(p)
        .w_full()
        .padding(space::S6)
        .gap(space::S3)
        .child(first)
        .child(
            col()
                .w_full()
                .pl(indent)
                .gap(space::S2)
                .child(command_row(p, "kb-first-paste", PASTE_LINE))
                .child(
                    text(several)
                        .font(type_::LABEL)
                        .color(p.t.text_secondary)
                        .spans(vec![Span::new(command, several.len()).mono()])
                        .wrap(),
                ),
        )
        .child(el().w_full().h(p.hair).my(space::S2).fill(p.t.separator))
        .child(second);
    let by_hand = row()
        .w_full()
        .gap(space::S3)
        .center_y()
        .child(
            text("Or do it yourself, in a terminal:")
                .font(type_::LABEL)
                .color(p.t.text_secondary),
        )
        .child(command_row(p, "kb-first-onboard", "kagebunshin onboard DIR…").grow(1.0));
    let screen = col()
        .key("kb-first-steps")
        .w(NARROW)
        .gap(space::S6)
        .child(masthead(
            p,
            "Set up your projects",
            "A secrets broker between your coding agents and your secrets. Agents get what \
             they need; what you mark sensitive needs you.",
            "kb-first-what",
        ))
        .child(col().w_full().gap(space::S3).child(steps).child(by_hand));
    // In the middle of what is left of the window, and from the top of it
    // where the window is too short.
    col().w_full().grow(1.0).center().child(screen)
}

/// Of an environment with every key set: whether a run proved it, and when.
fn proof_line(proof: Option<&Proof>, now: u64) -> String {
    match proof {
        Some(proof) => format!(
            "every key set; {} ran with them on {}",
            proof.program,
            kagebunshin::audit::day(proof.time, now)
        ),
        None => "every key set, not yet proven by a run".to_owned(),
    }
}

/// What is left for environment `c`: the commands for the person, one line
/// for what their agent does, and secrets a source skipped. Nothing for an
/// environment with nothing left.
fn left_card(p: Paint, c: &Column) -> Option<El> {
    let Detail::Loaded(EnvReport::Resolved {
        fixes,
        skipped,
        missing,
        ..
    }) = &c.detail
    else {
        return None;
    };
    // The daemon names a fix only for a store section or a skipped
    // secret; `next` tells the agent how to find a key no source sets.
    let for_agent = fixes.iter().any(|f| f.who == Who::Agent)
        || (missing.as_ref().is_some_and(|m| !m.is_empty())
            && !fixes.iter().any(|f| f.who == Who::Human));
    if !for_agent && fixes.is_empty() && skipped.is_empty() {
        return None;
    }
    let env = &c.sel.env;
    let mut card = card(p).key(format!("kb-left-{env}")).child(
        text(format!("Left to set up in {env}"))
            .font(type_::SECTION)
            .color(p.t.text),
    );
    let human: Vec<&Fix> = fixes.iter().filter(|f| f.who == Who::Human).collect();
    if !human.is_empty() {
        card = card.child(
            text(if human.len() == 1 {
                "For you, in a terminal in this checkout:"
            } else {
                "For you, in a terminal in this checkout, in turn:"
            })
            .font(BODY)
            .color(p.t.text_secondary),
        );
    }
    for (i, f) in human.iter().enumerate() {
        let mut note: Vec<char> = f.note.chars().collect();
        if let Some(first) = note.first_mut() {
            *first = first.to_ascii_uppercase();
        }
        card = card.child(
            col()
                .gap(space::S1)
                .w_full()
                .child(command_row(p, &format!("kb-fix-{env}-{i}"), &f.command))
                .child(
                    text(format!("{}.", note.into_iter().collect::<String>()))
                        .font(BODY)
                        .color(p.t.text_secondary)
                        .wrap(),
                ),
        );
    }
    if for_agent {
        card = card
            .child(
                text(
                    "Your coding agent can do the rest. If it is not on it already, paste \
                     this into it, in this checkout:",
                )
                .font(BODY)
                .color(p.t.text_secondary)
                .wrap(),
            )
            .child(command_row(p, &format!("kb-paste-{env}"), PASTE_LINE));
    }
    if !skipped.is_empty() {
        card = card.child(
            text(format!(
                "Skipped, as not JSON objects: {}",
                skipped.join(", ")
            ))
            .key(format!("kb-skipped-{env}"))
            .font(BODY)
            .color(p.t.text_secondary)
            .wrap(),
        );
    }
    Some(card)
}

/// For a project a run has proved, opened in its checkout: the env file
/// still there, with the same values in plain text.
fn kept_env_card(p: Paint, shown: &Shown) -> Option<El> {
    let c = shown.columns.iter().find(|c| {
        matches!(
            &c.detail,
            Detail::Loaded(EnvReport::Resolved { missing, proof: Some(_), .. })
                if missing.as_ref().is_none_or(Vec::is_empty)
        )
    })?;
    let file = c.sel.facts.env_file.as_ref()?;
    let path = kagebunshin::types::shell_quote(&c.sel.facts.cwd.join(file).to_string_lossy());
    Some(
        card(p)
            .key("kb-kept-env")
            .child(text("Left for you").font(type_::SECTION).color(p.t.text))
            .child(
                text(format!(
                    "{file} in this checkout still holds values in plain text, and {} now gets \
                     its secrets from kagebunshin. Delete it once nothing in it is still needed:",
                    c.sel.project
                ))
                .font(BODY)
                .color(p.t.text_secondary)
                .wrap(),
            )
            .child(command_row(p, "kb-kept-env-rm", &format!("rm {path}"))),
    )
}

/// An environment that does not list its keys yet, or is marked sensitive:
/// what it is, and the buttons that list them or lift the mark. Nothing
/// for one that is open and loaded.
fn env_card(p: Paint, s: &App, shown: &Shown, c: &Column) -> Option<El> {
    let env = c.sel.env.clone();
    let load = |label: &str, enabled| {
        let env = env.clone();
        button(
            p,
            &format!("kb-load-{env}"),
            label,
            enabled,
            move |s, tx| send(s, Event::Load(env.clone()), Some(tx)),
        )
    };
    let says = |title: String, what: &str| {
        card(p)
            .key("kb-env-card")
            .child(text(title).font(type_::SECTION).color(p.t.text))
            .child(
                text(what)
                    .key("kb-env-what")
                    .font(BODY)
                    .color(p.t.text_secondary)
                    .wrap(),
            )
    };
    if c.marked() == Some(true) {
        let listed = status_known(c);
        let change = Change::Mark {
            mark: Mark::Env {
                project: shown.project.clone(),
                env: env.clone(),
                also: Vec::new(),
            },
            sensitive: false,
        };
        let mut buttons = row().gap(space::S2).center_y();
        if !listed {
            buttons = buttons.child(load("Show keys…", s.idle()));
        }
        buttons = buttons.child(button(
            p,
            "kb-env-unmark",
            "Unmark environment…",
            s.idle(),
            move |s, tx| ask(s, change.clone(), tx),
        ));
        let what = if listed {
            "An agent gets its values only when you approve the request here."
        } else {
            "An agent gets its values only when you approve the request here. Its keys are \
             listed when you ask."
        };
        return Some(says(format!("{env} is sensitive"), what).child(buttons));
    }
    match &c.detail {
        Detail::Idle => Some(
            says(
                format!("{env} is not loaded"),
                if waits(s, &env) {
                    "It looks like production and waits for your decision, so its keys are \
                     fetched only when you ask."
                } else {
                    "Its name looks like production, so its keys are fetched only when you ask."
                },
            )
            .child(row().child(load("Load keys", true))),
        ),
        Detail::Failed(problem) => {
            let problem = Problem {
                message: format!("{env}: {}", problem.message),
                ..problem.clone()
            };
            Some(
                col()
                    .gap(space::S2)
                    .child(problem_box(p, &format!("kb-problem-{env}"), &problem))
                    .child(row().child(load("Retry", true))),
            )
        }
        _ => None,
    }
}

/// The keys of the environment chosen, a row each: the key, and where it
/// comes from. A row opens the key's page.
fn keys_view(p: Paint, s: &App, shown: &Shown) -> El {
    let note = |key: &str, msg: &str| {
        text(msg)
            .key(key)
            .font(BODY)
            .color(p.t.text_secondary)
            .wrap()
    };
    let Some(c) = chosen(s, shown) else {
        return note("kb-no-envs", "This project has no environment.");
    };
    let env = &c.sel.env;
    let mut out = col().gap(space::S3);
    for left in left_card(p, c).into_iter().chain(kept_env_card(p, shown)) {
        out = out.child(left);
    }
    out = out.children(env_card(p, s, shown, c));
    out = out.children(acknowledged_row(p, s, c));
    let Detail::Loaded(EnvReport::Resolved {
        keys,
        missing,
        vars,
        proof,
        ..
    }) = &c.detail
    else {
        if matches!(c.detail, Detail::Loading(_)) {
            out = out.child(if matches!(s.machine.conn, Conn::Down(_)) {
                note("kb-keys-down", "Waiting for the daemon.")
            } else {
                note("kb-loading", &format!("Loading {env}…"))
            });
        }
        return out;
    };

    // The search gives way to the buttons, and they wrap to a second line
    // in a window too narrow for one.
    let mut tools = row()
        .key("kb-key-tools")
        .w_full()
        .flex_wrap()
        .gap(space::S2)
        .center_y()
        .child(
            field(p, "kb-search", &s.search, "Search keys…", |s| {
                &mut s.search
            })
            .grow(1.0)
            .shrink()
            .min_w(140.0)
            .max_w(240.0),
        );
    for (f, key, label) in Filter::ALL {
        let on = s.filter == Some(f);
        // One that is on must not pass for a button: it is in the accent
        // colour, and says with its cross that pressing it takes it off.
        let (fill, edge, color) = if on {
            (p.info.alpha(0.16), p.info, p.info)
        } else {
            (Color::TRANSPARENT, p.t.card_border, p.t.text)
        };
        let shown = if on {
            format!("{label} ×")
        } else {
            label.to_owned()
        };
        tools = tools.child(
            el().key(key)
                .role("button")
                .label(label)
                .focusable(true)
                .checked(on)
                .h(26.0)
                .px(space::S3)
                .center()
                .radius(radius::MD)
                .fill(fill)
                .border(p.hair, edge)
                .hover(p.t.hover)
                .press(p.t.press)
                .on_press_tx(move |s: &mut App, _| {
                    s.filter = if s.filter == Some(f) { None } else { Some(f) };
                })
                .child(text(shown).font(type_::LABEL).color(color).a11y_hidden()),
        );
    }
    let query = s.search.text.trim().to_lowercase();
    let mut all: BTreeSet<&KeyName> = keys.iter().map(|k| &k.key).collect();
    all.extend(missing.iter().flatten());
    all.extend(vars.iter().map(|v| &v.key));
    let total = all.len();
    let key_w = key_width(&all, keys.iter().any(|k| k.sensitive));
    let names: Vec<&KeyName> = all
        .iter()
        .copied()
        .filter(|k| k.as_str().to_lowercase().contains(&query))
        .filter(|k| s.filter.is_none_or(|f| f.matches(c, k)))
        .collect();

    let label = |t: &str| text(t).font(type_::LABEL).color(p.t.text_secondary);
    let mut head = row()
        .key("kb-grid-head")
        .w_full()
        .h(36.0)
        .px(space::S3)
        .gap(space::S2)
        .center_y()
        .child(label("key").w(key_w))
        .child(label("comes from").grow(1.0));
    // Fewer than all are listed: how many, where the list starts.
    if names.len() < total {
        let of = if total == 1 { "key" } else { "keys" };
        head = head.child(
            text(format!("{} of {total} {of}", names.len()))
                .key("kb-narrowed")
                .font(type_::LABEL)
                .color(p.info),
        );
    }
    let line = || el().h(p.hair).w_full().fill(p.t.card_border).a11y_hidden();
    // A key's row: the whole of it opens the key's page. `tag` says the
    // key is sensitive where its group's header does not, and `act` puts
    // the button that unmarks its secret beside that.
    let key_row = |name: &KeyName, tag: bool, act: bool| {
        let k = status(c, name);
        let mut key = row().w(key_w).gap(space::S2).center_y().child(
            text(name.as_str())
                .font(BODY.mono())
                .color(p.t.text)
                .grow(1.0),
        );
        let tagged = tag && k.is_some_and(|k| k.sensitive);
        if tagged {
            key = key.child(badge("kb-key-sensitive", "sensitive", p.sensitive));
        }
        // A store key is unmarked on its page, as it is marked by itself.
        let action = k
            .filter(|k| act && tagged && k.origin.provider != Provider::File)
            .map(|k| unmark_button(p, s, shown, c, name.as_str(), vec![k.origin.clone()]));
        // What opens the page is apart from that button, as a group's
        // header is from its own.
        let whole = move |r: El| {
            let mut whole = row().w_full().gap(space::S2).center_y().child(r);
            if action.is_some() {
                whole = whole.pr(space::S3);
            }
            whole.children(action)
        };
        let r = row()
            .key(format!("kb-key-{name}"))
            .grow(1.0)
            .shrink()
            .h(32.0)
            .px(space::S3)
            .gap(space::S2)
            .center_y()
            .child(key);
        let Some(k) = k else {
            // Nothing to open: no source sets it.
            let state = |t: &str| text(t).font(BODY).color(p.warn).grow(1.0);
            return whole(
                r.child(if let Some(v) = vars.iter().find(|v| &v.key == name) {
                    // A plain setting of the project file: not secret, so its
                    // value.
                    text(&v.value)
                        .key("kb-var-value")
                        .font(BODY.mono())
                        .color(p.t.text)
                        .truncate()
                        .grow(1.0)
                } else {
                    state("○ missing")
                }),
            );
        };
        let to = name.clone();
        let mut r = r
            .role("button")
            .label(format!("{name} in {env}"))
            .focusable(true)
            .hover(p.t.hover)
            .press(p.t.press)
            .on_press_tx(move |s: &mut App, tx| go(s, View::Key(to.clone()), tx))
            .child(
                text(k.origin.shown())
                    .key("kb-from")
                    .font(BODY.mono())
                    .color(p.t.text_secondary)
                    .truncate()
                    .grow(1.0)
                    .a11y_hidden(),
            );
        // Set by more than one source: the others lose to this one.
        if !k.overridden.is_empty() {
            r = r.child(
                text(format!("overrides {}", k.overridden.len()))
                    .key("kb-conflict")
                    .font(type_::LABEL)
                    .color(p.warn),
            );
        }
        whole(r.child(text("›").font(BODY).color(p.t.text_secondary).a11y_hidden()))
    };
    let mut grid = card(p).key("kb-grid").padding(0.0).gap(0.0).child(head);
    tools = tools.child(el().grow(1.0));
    if s.flat {
        for name in &names {
            grid = grid.child(line()).child(key_row(name, true, false));
        }
    } else {
        let groups = groups(s, shown, c, &names);
        // A search or a filter shows what it found; otherwise a long list
        // opens folded, and a click flips a group either way.
        let narrowed = !query.is_empty() || s.filter.is_some();
        let many = groups.len() > FOLD_FROM;
        let folded = |id: &str| !narrowed && many != s.flipped.contains(id);
        if !narrowed && groups.len() > 1 {
            let open = groups.iter().any(|g| !folded(&g.id));
            // Folding all leaves none flipped in a list that opens folded,
            // and all of them in one that opens unfolded.
            let flip: BTreeSet<String> = if open == many {
                BTreeSet::new()
            } else {
                groups.iter().map(|g| g.id.clone()).collect()
            };
            tools = tools.child(button(
                p,
                "kb-fold-all",
                if open { "Fold all" } else { "Unfold all" },
                true,
                move |s, _| s.flipped.clone_from(&flip),
            ));
        }
        for g in groups {
            let folded = folded(&g.id);
            let id = g.id.clone();
            let n = g.names.len();
            let count = format!("{n} key{}", if n == 1 { "" } else { "s" });
            // A mark is on a whole secret; in a group of several secrets
            // each key says so itself.
            let marked = g
                .names
                .iter()
                .all(|name| status(c, name).is_some_and(|k| k.sensitive));
            // The header folds the group; the button at its end is apart
            // from that, so pressing one is not pressing the other.
            let mut fold = row()
                .key(format!("kb-secret-{}", g.id.replace('/', ":")))
                .role("button")
                .label(format!("{}, {count}", g.title))
                .focusable(true)
                .grow(1.0)
                .shrink()
                .h(32.0)
                .px(space::S3)
                .gap(space::S2)
                .center_y()
                .hover(p.t.hover)
                .on_press_tx(move |s: &mut App, _| {
                    if !s.flipped.remove(&id) {
                        s.flipped.insert(id.clone());
                    }
                })
                .child(
                    text(if folded { "▸" } else { "▾" })
                        .font(type_::LABEL)
                        .color(p.t.text_secondary)
                        .a11y_hidden(),
                )
                .child(
                    text(&g.title)
                        .font(BODY.mono())
                        .color(p.t.text)
                        .truncate()
                        .a11y_hidden(),
                );
            let about = match g.provider {
                Some(provider) => format!("{provider} · {count}"),
                None => count,
            };
            fold = fold.child(
                text(about)
                    .font(type_::LABEL)
                    .color(p.t.text_secondary)
                    .a11y_hidden(),
            );
            // Read by other environments too; as with the mark, a group of
            // several secrets says so if all are.
            let with: Vec<&[Section]> = g
                .secrets
                .iter()
                .map(|o| shared_as(s, &shown.project, env, o).map_or(&[][..], |sh| &sh.with))
                .collect();
            if !with.is_empty() && with.iter().all(|w| !w.is_empty()) {
                let with: BTreeSet<&Section> = with.into_iter().flatten().collect();
                let with: Vec<String> = with.iter().map(ToString::to_string).collect();
                fold = fold.child(
                    badge("kb-secret-shared", "shared", p.info)
                        .help(format!("also read by {}", with.join(", "))),
                );
            }
            if marked {
                fold = fold.child(badge("kb-secret-sensitive", "sensitive", p.sensitive));
            }
            let header = row()
                .w_full()
                .pr(space::S3)
                .gap(space::S2)
                .center_y()
                .fill(p.t.bg)
                .child(fold)
                .children(group_action(p, s, shown, c, &g));
            grid = grid.child(line()).child(header);
            if !folded {
                for name in g.names {
                    grid = grid.child(line()).child(key_row(name, !marked, true));
                }
            }
        }
    }
    tools = tools.child(
        button(
            p,
            "kb-flat",
            if s.flat {
                "Group by secret"
            } else {
                "Flat list"
            },
            true,
            |s, _| s.flat = !s.flat,
        )
        .checked(s.flat),
    );
    if total > 0 && names.is_empty() {
        let typed = s.search.text.trim();
        let what = match (s.filter, typed.is_empty()) {
            (Some(f), true) => format!("No key of {env} is {}.", f.state()),
            (Some(f), false) => format!(
                "No key of {env} with “{typed}” in its name is {}.",
                f.state()
            ),
            (None, _) => format!("No key of {env} has “{typed}” in its name."),
        };
        grid = grid.child(line()).child(
            row()
                .key("kb-no-match")
                .w_full()
                .h(44.0)
                .px(space::S3)
                .gap(space::S3)
                .center_y()
                .child(
                    text(what)
                        .font(BODY)
                        .color(p.t.text_secondary)
                        .truncate()
                        .grow(1.0),
                )
                .child(button(p, "kb-show-all", "Show all keys", true, |s, _| {
                    s.filter = None;
                    s.search = TextEdit::new("");
                })),
        );
    }
    out = out.child(tools).child(grid);
    if missing.as_ref().is_none_or(Vec::is_empty) {
        let now = kagebunshin::source::unix_now();
        out = out.child(note(
            &format!("kb-proof-{env}"),
            &format!("{env}: {}", proof_line(proof.as_ref(), now)),
        ));
    }
    if total == 0 {
        out = out.child(note("kb-no-keys", "No keys."));
    }
    out
}

/// What a column says of `key`, once it has resolved.
fn status<'a>(c: &'a Column, key: &KeyName) -> Option<&'a KeyStatus> {
    match &c.detail {
        Detail::Loaded(EnvReport::Resolved { keys, .. }) => keys.iter().find(|k| &k.key == key),
        _ => None,
    }
}

fn status_known(c: &Column) -> bool {
    matches!(c.detail, Detail::Loaded(EnvReport::Resolved { .. }))
}

/// An environment's name, saying when it is the project's default.
fn env_label(env: &EnvName, default: bool) -> String {
    if default {
        format!("{env} (default)")
    } else {
        env.to_string()
    }
}

/// The mark a key's value can take: a store key on its own, a provider's
/// secret as a whole, in every environment that reads it.
fn key_mark(k: &KeyStatus) -> Option<(Change, &'static str)> {
    let sensitive = !k.sensitive;
    if k.origin.provider == Provider::File {
        k.origin.location.parse::<Section>().ok().map(|section| {
            let mark = Mark::Key {
                section,
                key: k.key.clone(),
            };
            let label = if k.sensitive {
                "Unmark key"
            } else {
                "Mark key"
            };
            (Change::Mark { mark, sensitive }, label)
        })
    } else {
        let mark = Mark::Secret(k.origin.clone());
        let label = if k.sensitive {
            "Unmark secret"
        } else {
            "Mark secret"
        };
        Some((Change::Mark { mark, sensitive }, label))
    }
}

fn key_view(p: Paint, s: &App, shown: &Shown, key: &KeyName) -> El {
    let Some(c) = chosen(s, shown) else {
        return col();
    };
    let env = &c.sel.env;
    let idle = s.idle();
    let unlocked = s.machine.conn == (Conn::Up { locked: false });
    let k = status(c, key);
    let title = row()
        .w_full()
        .gap(space::S3)
        .center_y()
        .child(button(p, "kb-back", "‹ Keys", true, |s, tx| {
            go(s, View::Keys, tx);
        }))
        .child(
            text(format!("{} / {env} / {key}", shown.project))
                .key("kb-title")
                .font(TITLE)
                .color(p.t.text)
                .truncate(),
        );

    let revealed = s
        .machine
        .revealed
        .as_ref()
        .filter(|r| &r.env == env && &r.key == key);
    let mut value = row().w_full().gap(space::S2).center_y();
    value = if let Some(r) = revealed {
        value
            .child(
                text(r.value.expose())
                    .key("kb-value")
                    .font(BODY.mono())
                    .color(p.t.text)
                    .wrap()
                    .grow(1.0),
            )
            .child(button(p, "kb-hide", "Hide", true, |s, tx| {
                send(s, Event::Conceal, Some(tx));
            }))
    } else {
        let (env, key) = (env.clone(), key.clone());
        value
            .child(
                text("••••••••••••")
                    .key("kb-masked")
                    .font(BODY.mono())
                    .color(p.t.text_secondary)
                    .grow(1.0),
            )
            .child(button(
                p,
                "kb-reveal",
                "Reveal…",
                idle && unlocked && k.is_some(),
                move |s, tx| {
                    let ask = Event::Reveal {
                        env: env.clone(),
                        key: key.clone(),
                    };
                    send(s, ask, Some(tx));
                },
            ))
    };
    let value = card(p)
        .key("kb-value-card")
        .child(heading(p, "Value"))
        .child(value)
        .child(
            text("Revealing asks for the store's passphrase, and is in the audit log.")
                .font(BODY)
                .color(p.t.text_secondary)
                .wrap(),
        );

    let mut origin = card(p).key("kb-origin");
    match k {
        Some(k) => {
            origin = origin.child(heading(p, "Set by")).child(
                text(k.origin.to_string())
                    .key("kb-winner")
                    .font(BODY.mono())
                    .color(p.t.text),
            );
            if !k.overridden.is_empty() {
                origin = origin.child(heading(p, "Overriding, earliest first"));
                for (i, o) in k.overridden.iter().enumerate() {
                    origin = origin.child(
                        text(o.to_string())
                            .key(format!("kb-overridden-{i}"))
                            .font(BODY.mono())
                            .color(p.t.text_secondary),
                    );
                }
            }
        }
        None => {
            origin = origin.child(
                text(format!("No source of {env} sets {key}."))
                    .font(BODY)
                    .color(p.t.text_secondary),
            );
        }
    }

    let mut sources = card(p)
        .key("kb-key-sources")
        .child(heading(p, "Sources, in order: a later one wins"));
    if let Some((_, e)) = s.catalog.env(&shown.project, env) {
        for (i, source) in e.sources.iter().enumerate() {
            sources = sources.child(source_row(p, i, source));
        }
    }

    let env_marked = c.marked();
    let mut marks = card(p).key("kb-marks").child(heading(p, "Sensitive marks")).child(
        text("Agents are handed nothing marked sensitive. Only you change marks, here, with the passphrase.")
            .font(BODY)
            .color(p.t.text_secondary)
            .wrap(),
    );
    if let Some(marked) = env_marked {
        let change = Change::Mark {
            mark: Mark::Env {
                project: shown.project.clone(),
                env: env.clone(),
                also: Vec::new(),
            },
            sensitive: !marked,
        };
        let label = if marked {
            "Unmark environment"
        } else {
            "Mark environment"
        };
        let what = if marked { "marked" } else { "not marked" };
        marks = marks.child(
            row()
                .gap(space::S2)
                .center_y()
                .child(
                    text(format!("Environment {env}: {what}"))
                        .font(BODY)
                        .color(p.t.text)
                        .grow(1.0),
                )
                .child(button(p, "kb-env-mark", label, idle, move |s, tx| {
                    ask(s, change.clone(), tx);
                })),
        );
    }
    if let Some((change, label)) = k.and_then(key_mark) {
        let what = if k.is_some_and(|k| k.sensitive) {
            "marked"
        } else {
            "not marked"
        };
        marks = marks.child(
            row()
                .gap(space::S2)
                .center_y()
                .child(
                    text(format!("Its value: {what}"))
                        .font(BODY)
                        .color(p.t.text)
                        .grow(1.0),
                )
                .child(button(p, "kb-key-mark", label, idle, move |s, tx| {
                    ask(s, change.clone(), tx);
                })),
        );
    }
    // A secret's mark holds wherever it is read: say so, and where.
    if let Some(k) = k.filter(|k| k.origin.provider != Provider::File) {
        let shared = shared_as(s, &shown.project, env, &k.origin);
        let with = shared.map(|sh| sections(&sh.with));
        let note = match (k.sensitive, env_marked == Some(true), with) {
            (true, false, Some(with)) => Some(format!(
                "Secret {} is marked sensitive, so {env} asks for approval for its keys \
                 although {env} itself is not marked. So do the others that read it: {with}.",
                k.origin
            )),
            (true, false, None) => Some(format!(
                "Secret {} is marked sensitive, so {env} asks for approval for its keys \
                 although {env} itself is not marked.",
                k.origin
            )),
            (true, true, Some(with)) => Some(format!(
                "Secret {} is marked too, so the others that read it ask for approval for \
                 its keys: {with}.",
                k.origin
            )),
            (false, _, Some(with)) => Some(format!(
                "Secret {} is also read by {with}. Marking it makes each of them ask for \
                 approval for its keys.",
                k.origin
            )),
            _ => None,
        };
        if let Some(note) = note {
            marks = marks.child(
                text(note)
                    .key("kb-key-shared")
                    .font(BODY)
                    .color(p.t.text_secondary)
                    .wrap(),
            );
        }
    }
    col()
        .key("kb-key")
        .gap(space::S3)
        .child(title)
        .child(value)
        .child(origin)
        .child(sources)
        .child(marks)
}

/// The sources of the environment chosen, in the order they load.
fn sources_view(p: Paint, s: &App, shown: &Shown) -> El {
    let Some(column) = chosen(s, shown) else {
        return col();
    };
    let env = &column.sel.env;
    let idle = s.idle();
    let resync = env.clone();
    let top = row()
        .w_full()
        .gap(space::S2)
        .center_y()
        .child(heading(p, "Sources, in order: a later one wins").grow(1.0))
        .child(button(
            p,
            "kb-resync",
            "Resync",
            idle && s.machine.conn == (Conn::Up { locked: false }),
            move |s, tx| send(s, Event::Resync(resync.clone()), Some(tx)),
        ));
    let mut out = col().gap(space::S3).child(top);
    if let Some(said) = acknowledged_row(p, s, column) {
        out = out.child(said);
    } else if to_acknowledge(s).contains(env) {
        out = out.child(
            row()
                .key("kb-unacknowledged")
                .gap(space::S2)
                .center_y()
                .child(
                    text(
                        "This environment looks like production and waits for your decision: \
                         until you mark it sensitive or acknowledge it is not, agents get its \
                         values only with your approval.",
                    )
                    .wrap()
                    .font(BODY)
                    .color(p.warn)
                    .grow(1.0),
                )
                .child(acknowledge_button(p, s, env, true)),
        );
    }
    if let Some((_, e)) = s.catalog.env(&shown.project, env) {
        out = out.child(sources(p, s, &shown.project, e, idle));
    }
    out
}

fn sources(p: Paint, s: &App, project: &ProjectName, env: &EnvView, idle: bool) -> El {
    let mut c = card(p).key("kb-sources");
    if let Some(problem) = &env.problem {
        c = c.child(text(problem).font(BODY).color(p.warn).wrap());
    }
    let n = env.sources.len();
    for (i, source) in env.sources.iter().enumerate() {
        if i > 0 {
            c = c.child(el().h(p.hair).w_full().fill(p.t.separator).a11y_hidden());
        }
        let mut r = source_row(p, i, source);
        if env.default_source {
            r = r.child(
                text("The default source: add one to read something else.")
                    .font(BODY)
                    .color(p.t.text_secondary),
            );
        } else {
            let at = |change: Change| move |s: &mut App, tx: &mut Tx| ask(s, change.clone(), tx);
            let (project, env) = (project.clone(), env.name.clone());
            let up = Change::Edit(Edit::MoveSource {
                project: project.clone(),
                env: env.clone(),
                from: i,
                to: i.saturating_sub(1),
            });
            let down = Change::Edit(Edit::MoveSource {
                project: project.clone(),
                env: env.clone(),
                from: i,
                to: i + 1,
            });
            let remove = Change::Edit(Edit::RemoveSource {
                project,
                env,
                index: i,
            });
            r = r.child(
                row()
                    .gap(space::S2)
                    .child(button(
                        p,
                        &format!("kb-source-{i}-up"),
                        "Earlier",
                        idle && i > 0,
                        at(up),
                    ))
                    .child(button(
                        p,
                        &format!("kb-source-{i}-down"),
                        "Later",
                        idle && i + 1 < n,
                        at(down),
                    ))
                    .child(button(
                        p,
                        &format!("kb-source-{i}-remove"),
                        "Remove",
                        idle,
                        at(remove),
                    )),
            );
        }
        c = c.child(r);
    }
    let add = if s.form.open {
        add_form(p, &s.form, idle)
    } else {
        row().child(button(p, "kb-add-source", "Add source", idle, |s, _| {
            s.form.open = true;
            s.form.name.focused = true;
        }))
    };
    col().gap(space::S2).child(c).child(add)
}

/// The audit log, of every project or narrowed to one.
fn activity_view(p: Paint, s: &App) -> El {
    let mut out = col()
        .key("kb-activity")
        .gap(space::S3)
        .child(text("Activity").key("kb-title").font(TITLE).color(p.t.text));
    out = out.child(
        text("This machine's audit log, newest first: what was handed out, changed or refused. It holds names, never values.")
            .font(BODY)
            .color(p.t.text_secondary)
            .wrap(),
    );
    let log = match &s.activity {
        Err(e) => {
            return out.child(problem_box(
                p,
                "kb-activity-problem",
                &Problem::new(format!("cannot read the audit log: {e}")),
            ));
        }
        Ok(log) => log,
    };
    let note = |key: &str, msg: String| {
        text(msg)
            .key(key)
            .font(BODY)
            .color(p.t.text_secondary)
            .wrap()
    };
    if log.unreadable > 0 {
        let n = log.unreadable;
        let lines = if n == 1 {
            "1 line"
        } else {
            &format!("{n} lines")
        };
        out = out.child(note(
            "kb-activity-unreadable",
            format!("{lines} of the log could not be read."),
        ));
    }
    if log.lines.is_empty() {
        return out.child(note("kb-activity-empty", "Nothing logged yet.".to_owned()));
    }
    // The projects the log is about, to narrow it to one.
    let projects: BTreeSet<&ProjectName> =
        log.lines.iter().filter_map(|(p, _)| p.as_ref()).collect();
    if !projects.is_empty() {
        let pick = |key: String, label: &str, of: Option<ProjectName>| {
            let on = s.activity_of == of;
            button(p, &key, label, true, move |s, _| {
                s.activity_of.clone_from(&of);
            })
            .checked(on)
            .fill(if on {
                p.t.indicator.alpha(0.28)
            } else {
                Color::TRANSPARENT
            })
        };
        let mut of = row()
            .key("kb-activity-of")
            .w_full()
            .flex_wrap()
            .gap(space::S1)
            .center_y()
            .child(pick("kb-activity-all".to_owned(), "All projects", None));
        for name in projects {
            of = of.child(pick(
                format!("kb-activity-of-{name}"),
                name.as_str(),
                Some(name.clone()),
            ));
        }
        out = out.child(of);
    }
    let of = s.activity_of.as_ref();
    let mut lines = log
        .lines
        .iter()
        .filter(|(project, _)| of.is_none() || project.as_ref() == of)
        .take(ACTIVITY)
        .peekable();
    if lines.peek().is_none() {
        return out.child(note(
            "kb-activity-empty",
            "Nothing logged about this project.".to_owned(),
        ));
    }
    let mut c = card(p).key("kb-activity-log").gap(space::S1);
    for (i, (_, line)) in lines.enumerate() {
        c = c.child(
            text(line)
                .key(format!("kb-activity-{i}"))
                .font(BODY.mono())
                .color(p.t.text)
                .wrap(),
        );
    }
    out.child(c)
}

/// As wide as a page of the machine's reads comfortably: in a wide window
/// a row's count would sit far from its name.
const PAGE: f32 = 920.0;

/// Each provider: whether it can read, what reads from it, and connecting it.
fn providers_view(p: Paint, s: &App) -> El {
    let checking = s.machine.providers.asking.is_some();
    let mut out = col().key("kb-providers").max_w(PAGE).gap(space::S3).child(
        row()
            .w_full()
            .gap(space::S3)
            .center_y()
            .child(
                text("Providers")
                    .key("kb-title")
                    .font(TITLE)
                    .color(p.t.text),
            )
            .child(el().grow(1.0))
            .child(button(
                p,
                "kb-providers-check",
                if checking {
                    "Checking…"
                } else {
                    "Check again"
                },
                !checking,
                |s, tx| send(s, Event::CheckProviders, Some(tx)),
            )),
    );
    out = out.child(
        text("Where secrets are read from. Each says whether it can read now and which environments read from it. Values never pass through this window.")
            .font(BODY)
            .color(p.t.text_secondary)
            .wrap(),
    );
    let statuses: &[ProviderStatus] = match &s.machine.providers.last {
        Some(Ok(list)) => list,
        Some(Err(problem)) => {
            out = out.child(problem_box(p, "kb-providers-problem", problem));
            &[]
        }
        None => &[],
    };
    for provider in [Provider::AwsSm, Provider::Proton, Provider::File] {
        out = out.child(provider_card(p, s, provider, statuses));
    }
    out
}

/// The remote endpoint: whether it listens, and each machine let in, which
/// is given a new token or revoked from here. Letting one in is the
/// command line's: it asks tailscaled which machine a name is.
fn remote_view(p: Paint, s: &App) -> El {
    let mut out = col()
        .key("kb-remote")
        .max_w(PAGE)
        .gap(space::S3)
        .child(
            text("Remote agents")
                .key("kb-title")
                .font(TITLE)
                .color(p.t.text),
        )
        .child(
            text("Machines on your tailnet that may run commands with secrets from this one. Each is let in for environments of one project, and has to be that machine and send its grant's token.")
                .font(BODY)
                .color(p.t.text_secondary)
                .wrap(),
        );
    let locked = s.machine.conn == (Conn::Up { locked: true });
    let remote = s.machine.remote.as_ref();
    let note = |msg: &str| text(msg).font(BODY).color(p.t.text_secondary).wrap();

    let mut endpoint = card(p)
        .key("kb-remote-endpoint")
        .child(heading(p, "Endpoint"));
    let state = |label: &str, color, detail: Option<&str>| {
        let mut r =
            row()
                .w_full()
                .gap(space::S2)
                .center_y()
                .child(badge("kb-remote-state", label, color));
        if let Some(detail) = detail {
            r = r.child(
                text(detail)
                    .font(BODY.mono())
                    .color(p.t.text)
                    .truncate()
                    .grow(1.0),
            );
        }
        r
    };
    let on = match remote.map(|r| (r.enabled, &r.listening, &r.problem)) {
        None => {
            endpoint = endpoint.child(note("Not known yet."));
            false
        }
        Some((None, ..)) => {
            endpoint = endpoint.child(note("Whether it is on shows once the daemon is unlocked."));
            false
        }
        Some((Some(false), ..)) => {
            endpoint = endpoint
                .child(state("off", p.info, None))
                .child(note("No other machine can reach this one. To turn it on:"))
                .child(command_row(
                    p,
                    "kb-remote-enable",
                    "kagebunshin remote enable",
                ));
            false
        }
        Some((Some(true), Some(addr), _)) => {
            endpoint = endpoint.child(state("listening", p.good, Some(addr)));
            true
        }
        Some((Some(true), None, problem)) => {
            endpoint = endpoint.child(state("not listening", p.warn, None));
            if let Some(problem) = problem {
                endpoint = endpoint.child(note(problem));
            }
            true
        }
    };
    out = out.child(endpoint);

    if let Some(new) = &s.machine.token {
        let copied = new.token.expose().to_owned();
        out = out.child(
            card(p)
                .key("kb-token")
                .border(p.hair, p.good)
                .child(heading(
                    p,
                    &format!(
                        "New token of machine {} for {}",
                        new.grant.machine, new.grant.project
                    ),
                ))
                // One long word: on a line of its own, cut short in a
                // narrow window, where Copy still takes all of it.
                .child(
                    text(new.token.expose())
                        .key("kb-token-value")
                        .font(BODY.mono())
                        .color(p.t.text)
                        .selectable(true)
                        .truncate(),
                )
                .child(note(&format!(
                    "Shown this once: only its hash is kept. On that machine, set it as {REMOTE_TOKEN_ENV} where kagebunshin runs."
                )))
                .child(
                    row()
                        .gap(space::S2)
                        .justify_end()
                        .child(button(p, "kb-token-copy", "Copy", true, move |_, tx| {
                            tx.copy(copied.clone());
                        }))
                        .child(button(p, "kb-token-done", "Done", true, |s, tx| {
                            send(s, Event::Forget, Some(tx));
                        })),
                ),
        );
    }

    let mut grants = card(p).key("kb-grants").child(heading(p, "Grants"));
    let list: &[GrantView] = remote.map_or(&[], |r| &r.grants);
    if locked {
        grants = grants.child(note("Grants show once the daemon is unlocked."));
    } else if list.is_empty() {
        grants = grants.child(note("No machine is let in."));
    }
    let idle = s.machine.pending == Pending::None;
    let now = kagebunshin::source::unix_now();
    for (i, g) in list.iter().enumerate() {
        grants = grants.child(grant_row(p, i, g, now, idle));
    }
    if !locked && on {
        grants = grants
            .child(note(
                "To let a machine in, or change what one may use, which gives it a new token:",
            ))
            .child(command_row(
                p,
                "kb-remote-grant",
                "kagebunshin remote grant MACHINE PROJECT ENV…",
            ));
    }
    out.child(grants)
}

/// One grant: who may use what and until when, and the buttons that give
/// it a new token or end it.
fn grant_row(p: Paint, i: usize, g: &GrantView, now: u64, idle: bool) -> El {
    let key = format!("kb-grant-{i}");
    let envs: Vec<&str> = g.envs.iter().map(EnvName::as_str).collect();
    let mut top = row()
        .w_full()
        .gap(space::S2)
        .center_y()
        .child(text(&g.machine).font(BODY.mono()).color(p.t.text))
        .child(text("may use").font(BODY).color(p.t.text_secondary))
        .child(
            text(format!("{} {}", g.project, envs.join(", ")))
                .font(BODY.mono())
                .color(p.t.text)
                .truncate()
                .grow(1.0),
        );
    match g.expires {
        Some(end) if end <= now => {
            top = top.child(badge(format!("{key}-ended"), "ended", p.warn));
        }
        Some(end) => {
            top = top.child(
                text(format!(
                    "until {}",
                    kagebunshin::source::proton::format_date(end - 1)
                ))
                .font(BODY)
                .color(p.t.text_secondary),
            );
        }
        None => {}
    }
    if !g.token {
        top = top.child(badge(format!("{key}-no-token"), "no token", p.warn));
    }
    let (rotate, revoke) = (Grant::from(g), Grant::from(g));
    let replacing = g.token;
    top = top
        .child(button(
            p,
            &format!("{key}-rotate"),
            "New token",
            idle,
            move |s, tx| {
                let grant = rotate.clone();
                ask(s, Change::RotateGrant { grant, replacing }, tx);
            },
        ))
        .child(button(
            p,
            &format!("{key}-revoke"),
            "Revoke",
            idle,
            move |s, tx| {
                ask(s, Change::RevokeGrant(revoke.clone()), tx);
            },
        ));
    let mut r = col().key(key).gap(space::S1).child(top);
    if !g.token {
        r = r.child(
            text("Made before grants had tokens: nothing gets through with it until it has one.")
                .font(BODY)
                .color(p.t.text_secondary)
                .wrap(),
        );
    }
    r
}

/// A length of time left, in the unit that says it shortest.
fn time_left(seconds: u64) -> String {
    match seconds {
        s if s < 60 => format!("{s} s"),
        s => format!("{} min", s.div_ceil(60)),
    }
}

/// Phone: the phone that approves requests away from this computer, the
/// way in for one being paired, and the phones on the tailnet that could
/// be.
fn phone_view(p: Paint, s: &App) -> El {
    let mut out = col()
        .key("kb-phone")
        .max_w(PAGE)
        .gap(space::S3)
        .child(
            text("Phone")
                .key("kb-title")
                .font(TITLE)
                .color(p.t.text),
        )
        .child(
            text("A phone on your tailnet can approve requests while you are away from this computer. This machine serves it a page that no other device is given, and the phone approves one request at a time with a passkey, which asks for your face or fingerprint. Unlocking, and anything that is typed, stay at this computer.")
                .font(BODY)
                .color(p.t.text_secondary)
                .wrap(),
        );
    let note = |msg: &str| text(msg).font(BODY).color(p.t.text_secondary).wrap();
    let status = s.machine.phone.as_deref();
    let paired = status.and_then(|st| st.paired.as_ref());
    let pairing = s.machine.pairing.as_ref();
    // One change at a time, and none while a phone is on its way in.
    let idle = s.machine.pending == Pending::None && pairing.is_none();

    let mut now = card(p)
        .key("kb-phone-paired")
        .child(heading(p, "Paired phone"));
    match (&s.machine.conn, paired) {
        (Conn::Up { locked: true }, _) => {
            now = now.child(note("The paired phone shows once the daemon is unlocked."));
        }
        (Conn::Up { locked: false }, None) => {
            now = now.child(note(
                "No phone is paired: requests are approved at this computer only.",
            ));
        }
        (_, None) => now = now.child(note("Not known yet.")),
        (_, Some(phone)) => {
            let name = phone.name.clone();
            now = now.child(
                row()
                    .w_full()
                    .gap(space::S2)
                    .center_y()
                    .child(text(&phone.name).font(BODY.mono()).color(p.t.text))
                    .child(
                        text(format!("paired {}", kagebunshin::audit::utc(phone.paired)))
                            .font(BODY)
                            .color(p.t.text_secondary)
                            .truncate()
                            .grow(1.0),
                    )
                    .child(button(
                        p,
                        "kb-phone-remove",
                        "Remove",
                        idle,
                        move |s, tx| {
                            ask(s, Change::UnpairPhone(name.clone()), tx);
                        },
                    )),
            );
            let page = |key: &str, label: &str, color, detail: Option<&str>| {
                let mut r = row()
                    .w_full()
                    .gap(space::S2)
                    .center_y()
                    .child(badge(key, label, color));
                if let Some(detail) = detail {
                    r = r.child(
                        text(detail)
                            .font(BODY.mono())
                            .color(p.t.text)
                            .selectable(true)
                            .truncate()
                            .grow(1.0),
                    );
                }
                r
            };
            let (url, problem) = status.map_or((None, None), |st| {
                (st.url.as_deref(), st.problem.as_deref())
            });
            now = match (url, problem) {
                (Some(url), _) => {
                    now.child(page("kb-phone-page", "page served", p.good, Some(url)))
                }
                (None, Some(problem)) => now
                    .child(page("kb-phone-page", "page not served", p.warn, None))
                    .child(note(problem)),
                (None, None) => {
                    now.child(page("kb-phone-page", "page not served yet", p.info, None))
                }
            };
            let told = |label: &str, color| page("kb-phone-notifies", label, color, None);
            now = match (phone.notifies, phone.untold.as_deref()) {
                (true, None) => now.child(told("notifications on", p.good)).child(note(
                    "It is told of each request it can approve, so one waits for it even while this app is closed.",
                )),
                (true, Some(why)) => now
                    .child(told("notifications on", p.warn))
                    .child(note(&format!("The last one did not go out: {why}."))),
                (false, why) => now.child(told("notifications off", p.info)).child(note(&format!(
                    "{}To be told of a request there, add the page to the phone's home screen, open it from there and turn notifications on.",
                    why.map(|why| format!("The last one did not go out: {why}. "))
                        .unwrap_or_default()
                ))),
            };
            let last = status.and_then(|st| st.last.as_ref());
            now = now.child(note(&match (last, phone.seen) {
                (Some(last), _) => format!(
                    "Last answered there: {} {}/{} at {}.",
                    if last.approved { "approved" } else { "denied" },
                    last.project,
                    last.env,
                    kagebunshin::audit::utc(last.time)
                ),
                (None, Some(seen)) => format!(
                    "It last opened the page at {}, and has answered nothing since the daemon started.",
                    kagebunshin::audit::utc(seen)
                ),
                (None, None) => "It has not opened the page since the daemon started.".to_owned(),
            }));
        }
    }
    out = out.child(now);

    if let Some(pairing) = pairing {
        let left = status
            .and_then(|st| st.pairing.as_ref())
            .map(|going| going.left);
        let copied = pairing.url.clone();
        let mut steps = col().gap(space::S2).grow(1.0).shrink().child(
            text(format!(
                "On {}, point the camera at this code, or open the address, and make the approval key there.",
                pairing.phone.name
            ))
            .font(BODY)
            .color(p.t.text)
            .wrap(),
        );
        steps = steps
            .child(
                text(&pairing.url)
                    .key("kb-pairing-url")
                    .font(BODY.mono())
                    .color(p.t.text)
                    .selectable(true)
                    .truncate(),
            )
            .child(note(&match left {
                Some(left) => format!(
                    "No other device is given the page. It waits {} more, and stops when this view is left.",
                    time_left(left)
                ),
                None => "No other device is given the page. It stops when this view is left."
                    .to_owned(),
            }))
            .child(
                row()
                    .gap(space::S2)
                    .child(button(p, "kb-pairing-copy", "Copy", true, move |_, tx| {
                        tx.copy(copied.clone());
                    }))
                    .child(button(p, "kb-pairing-stop", "Stop", true, |s, tx| {
                        send(s, Event::Forget, Some(tx));
                    })),
            );
        let mut body = row().w_full().gap(space::S3);
        if let Some((_, code)) = &s.code {
            body = body.child(
                el().key("kb-pairing-code")
                    .label("QR code of the address")
                    .size(184.0, 184.0)
                    .radius(radius::MD)
                    .pixels(code),
            );
        }
        out = out.child(
            card(p)
                .key("kb-pairing")
                .border(p.hair, p.good)
                .child(heading(p, &format!("Pairing {}", pairing.phone.name)))
                .child(body.child(steps)),
        );
        return out;
    }

    let mut choices = card(p).key("kb-phones").child(heading(
        p,
        if paired.is_some() {
            "Pair another phone"
        } else {
            "Pair a phone"
        },
    ));
    if let Some(going) = status.and_then(|st| st.pairing.as_ref()) {
        // Started from another window of this daemon.
        choices = choices.child(note(&format!(
            "{} is being paired, for {} more.",
            going.name,
            time_left(going.left)
        )));
    }
    match (&s.machine.conn, &s.machine.phones.last) {
        (Conn::Up { locked: true }, _) => {
            choices = choices.child(note("A phone is paired once the daemon is unlocked."));
        }
        (_, None) => {
            choices = choices.child(note("Asking Tailscale which phones are on this tailnet…"));
        }
        (_, Some(Err(problem))) => {
            choices = choices.child(text(&problem.message).font(BODY).color(p.t.text).wrap());
            if let Some(hint) = &problem.hint {
                choices = choices.child(note(&format!("hint: {hint}")));
            }
        }
        (_, Some(Ok(phones))) if phones.is_empty() => {
            choices = choices.child(note(
                "No phone or tablet is on this tailnet. Install Tailscale on the phone, sign it in to this tailnet, then press Refresh.",
            ));
        }
        (_, Some(Ok(phones))) => {
            if paired.is_some() {
                choices = choices.child(note(
                    "One phone approves at a time: the one paired now does until the new one has made its key.",
                ));
            }
            for (i, phone) in phones.iter().enumerate() {
                let key = format!("kb-phone-{i}");
                let choice = phone.clone();
                let again = paired.is_some_and(|now| now.node == phone.node);
                choices = choices.child(
                    row()
                        .key(key.clone())
                        .w_full()
                        .gap(space::S2)
                        .center_y()
                        .child(text(&phone.name).font(BODY.mono()).color(p.t.text))
                        .child(
                            text(&phone.os)
                                .font(BODY)
                                .color(p.t.text_secondary)
                                .truncate()
                                .grow(1.0),
                        )
                        .child(button(
                            p,
                            &format!("{key}-pair"),
                            if again { "Pair again" } else { "Pair" },
                            idle,
                            move |s, tx| {
                                ask(s, Change::PairPhone(choice.clone()), tx);
                            },
                        )),
                );
            }
        }
    }
    out.child(choices)
}

/// One provider: what it is, then its parts under their own headings.
fn provider_card(p: Paint, s: &App, provider: Provider, statuses: &[ProviderStatus]) -> El {
    let id = provider.as_str();
    let mine: Vec<&ProviderStatus> = statuses
        .iter()
        .filter(|st| st.provider == provider)
        .collect();
    // What is below is the last answer until the new one is in.
    let mut title = row().gap(space::S2).center_y().child(heading(p, "Status"));
    if s.machine.checking(provider) {
        title = title.child(badge(
            format!("kb-status-{id}-checking"),
            "checking…",
            p.info,
        ));
    }
    let mut status = col()
        .key(format!("kb-status-{id}"))
        .gap(space::S2)
        .child(title);
    if mine.is_empty() {
        status = status.child(
            text(unchecked(s, provider))
                .font(BODY)
                .color(p.t.text_secondary)
                .wrap(),
        );
    }
    for (i, st) in mine.iter().enumerate() {
        status = status.child(status_row(p, s, provider, i, st));
    }
    if provider == Provider::AwsSm {
        status = status.children(aws_log(p, s));
    }
    let mut c = card(p)
        .key(format!("kb-provider-{id}"))
        .gap(16.0)
        .child(
            col()
                .gap(space::S1)
                .child(text(provider_title(provider)).font(TITLE).color(p.t.text))
                .child(
                    text(provider_about(provider))
                        .font(BODY)
                        .color(p.t.text_secondary)
                        .wrap(),
                ),
        )
        .child(status);
    c = c.children(used_by(p, s, provider));
    // A token is saved: connecting another replaces it.
    let saved = mine
        .iter()
        .any(|st| !matches!(st.health, Health::NotConnected { .. } | Health::Locked));
    match provider {
        Provider::AwsSm => c.child(aws_connect(p, s)),
        Provider::Proton => c.child(proton_connect(p, s, saved)),
        Provider::File => c,
    }
}

fn provider_title(provider: Provider) -> &'static str {
    match provider {
        Provider::AwsSm => "AWS Secrets Manager",
        Provider::Proton => "Proton Pass",
        Provider::File => "Local store",
    }
}

fn provider_about(provider: Provider) -> &'static str {
    match provider {
        Provider::AwsSm => "Secrets in AWS, read with the credentials of an AWS profile.",
        Provider::Proton => {
            "Items in Proton Pass vaults, read by pass-cli with a personal access token."
        }
        Provider::File => "Values kept on this machine, encrypted with your passphrase.",
    }
}

/// What to say of a provider the daemon reported nothing about: it checks
/// one only when an environment reads from it, a default profile is set or
/// a token is saved.
fn unchecked(s: &App, provider: Provider) -> &'static str {
    let locked = s.machine.conn == (Conn::Up { locked: true });
    match (&s.machine.providers.last, provider) {
        (None, _) if s.machine.providers.asking.is_some() => "Checking…",
        (None | Some(Err(_)), _) => "Not checked.",
        (Some(Ok(_)), Provider::AwsSm) => {
            "Nothing to check: no environment reads from it and no default profile is set."
        }
        (Some(Ok(_)), Provider::Proton) if locked => {
            "No environment reads from it. Whether a token is saved shows once the daemon is unlocked."
        }
        (Some(Ok(_)), Provider::Proton) => {
            "Not connected: no token is saved, and no environment reads from it."
        }
        (Some(Ok(_)), Provider::File) => "Nothing to check: no environment reads from it.",
    }
}

fn status_row(p: Paint, s: &App, provider: Provider, i: usize, st: &ProviderStatus) -> El {
    let key = format!("kb-provider-{}-{i}", provider.as_str());
    let (label, color, hint) = match &st.health {
        Health::Ok => ("can read", p.good, None),
        Health::NotConnected { hint } => ("not connected", p.warn, Some(hint.as_str())),
        Health::NeedsLogin { hint } => ("needs login", p.warn, Some(hint.as_str())),
        Health::Locked => ("locked", p.info, None),
        Health::Failed { message } => ("failed", p.warn, Some(message.as_str())),
    };
    let mut top = row().w_full().gap(space::S2).center_y().child(badge(
        format!("{key}-health"),
        label,
        color,
    ));
    if !st.detail.is_empty() {
        top = top.child(
            text(&st.detail)
                .font(BODY.mono())
                .color(p.t.text)
                .truncate()
                .grow(1.0),
        );
    }
    if let Some(at) = st.expires {
        top = top.child(
            text(format!(
                "expires {}",
                kagebunshin::source::proton::format_date(at)
            ))
            .font(BODY)
            .color(p.t.text_secondary),
        );
    }
    // A profile whose login ran out is logged in from its own row.
    let login = (matches!(st.health, Health::NeedsLogin { .. }))
        .then(|| {
            aws_read_with(s)
                .into_iter()
                .find(|(name, ..)| *name == st.detail)
        })
        .flatten();
    if let Some((_, profile, region)) = login {
        let running = s.login.as_ref().is_some_and(|l| l.outcome().is_none());
        top = top.child(button(
            p,
            &format!("kb-aws-login-{profile}"),
            "Log in",
            !running,
            move |s, _| aws_login(s, profile.clone(), region.clone(), false),
        ));
    }
    let mut r = col().key(key).gap(space::S1).child(top);
    if let Some(hint) = hint {
        r = r.child(text(hint).font(BODY).color(p.t.text_secondary).wrap());
    }
    r
}

/// The environments that read from `provider`, each with how much it reads
/// and not what: a row opens the environment's sources, which name them.
/// `None` when none does.
fn used_by(p: Paint, s: &App, provider: Provider) -> Option<El> {
    let plural = |n: usize, one: &str, many: &str| match n {
        0 => None,
        1 => Some(format!("1 {one}")),
        n => Some(format!("{n} {many}")),
    };
    let key = format!("kb-used-{}", provider.as_str());
    let mut rows = Vec::new();
    for project in &s.catalog.projects {
        for env in &project.envs {
            let mine: Vec<&SourceView> = env
                .sources
                .iter()
                .filter(|x| x.provider == provider.as_str())
                .collect();
            if mine.is_empty() {
                continue;
            }
            let count = |prefix: bool| -> usize {
                let of = mine.iter().filter(|x| (x.select == "prefix") == prefix);
                of.map(|x| x.locations.len()).sum()
            };
            let named = if provider == Provider::File {
                plural(count(false), "section", "sections")
            } else {
                plural(count(false), "secret", "secrets")
            };
            let mut reads: Vec<String> = named
                .into_iter()
                .chain(plural(count(true), "prefix", "prefixes"))
                .collect();
            let profiles: BTreeSet<&str> =
                mine.iter().filter_map(|x| x.profile.as_deref()).collect();
            if !profiles.is_empty() {
                let profiles: Vec<&str> = profiles.into_iter().collect();
                reads.push(format!("profile {}", profiles.join(", ")));
            }
            let of = format!("{} / {}", project.name, env.name);
            let (to, at) = (project.name.clone(), env.name.clone());
            rows.push(
                row()
                    .key(format!("{key}-{}-{}", project.name, env.name))
                    .role("button")
                    .label(format!("Sources of {of}"))
                    .focusable(true)
                    .w_full()
                    .h(28.0)
                    .px(space::S2)
                    .gap(space::S3)
                    .center_y()
                    .radius(radius::MD)
                    .hover(p.t.hover)
                    .press(p.t.press)
                    .on_press_tx(move |s: &mut App, tx| open_sources(s, &to, at.clone(), tx))
                    .child(text(of).font(BODY.mono()).color(p.t.text).a11y_hidden())
                    .child(
                        text(reads.join(" · "))
                            .font(BODY)
                            .color(p.t.text_secondary)
                            .truncate()
                            .grow(1.0),
                    )
                    .child(text("›").font(BODY).color(p.t.text_secondary).a11y_hidden()),
            );
        }
    }
    if rows.is_empty() {
        return None;
    }
    let title = match rows.len() {
        1 => "Read by 1 environment".to_owned(),
        n => format!("Read by {n} environments"),
    };
    Some(
        col()
            .key(key)
            .gap(space::S1)
            .child(heading(p, &title))
            .children(rows),
    )
}

/// What AWS is read with on this machine, each once: the status name the
/// daemon gives it, then the profile and region to log in with. The
/// profile and region each source names, and the default.
fn aws_read_with(s: &App) -> Vec<(String, Profile, Option<Region>)> {
    let sources = (s.catalog.projects.iter())
        .flat_map(|p| &p.envs)
        .flat_map(|e| &e.sources)
        .filter(|x| x.provider == Provider::AwsSm.as_str())
        .map(|x| (x.profile.clone(), x.region.clone()));
    let mut out: Vec<(String, Profile, Option<Region>)> = Vec::new();
    for (profile, region) in sources.chain([s.catalog.aws.clone()]) {
        let name = read_with(profile.as_deref(), region.as_deref());
        let Some(Ok(profile)) = profile.map(Profile::try_from) else {
            continue;
        };
        let Ok(region) = region.map(Region::try_from).transpose() else {
            continue;
        };
        if !out.iter().any(|(n, ..)| *n == name) {
            out.push((name, profile, region));
        }
    }
    out
}

/// The default profile, and connecting another.
fn aws_connect(p: Paint, s: &App) -> El {
    let running = s.login.as_ref().is_some_and(|l| l.outcome().is_none());
    let (profile, region) = &s.catalog.aws;
    let now = if profile.is_none() && region.is_none() {
        "None is set: a source that names no profile reads with your ambient AWS configuration. \
         Connecting a profile checks it can read, logs it in if it needs it, and makes it the \
         default."
            .to_owned()
    } else {
        format!(
            "A source that names no profile reads with {}. Connecting another checks it can \
             read, logs it in if it needs it, and makes it the default.",
            read_with(profile.as_deref(), region.as_deref())
        )
    };
    let mut c = col()
        .key("kb-aws-connect-form")
        .gap(space::S2)
        .child(heading(p, "Default profile"))
        .child(
            text(now)
                .key("kb-aws-default")
                .font(BODY)
                .color(p.t.text_secondary)
                .wrap(),
        )
        .child(
            row()
                .w_full()
                .gap(space::S2)
                .child(
                    field(p, "kb-aws-profile", &s.aws_profile, "AWS profile", |s| {
                        &mut s.aws_profile
                    })
                    .grow(1.0),
                )
                .child(
                    field(
                        p,
                        "kb-aws-region",
                        &s.aws_region,
                        "Region (default: the profile's)",
                        |s| &mut s.aws_region,
                    )
                    .grow(1.0),
                )
                .child(
                    button(p, "kb-aws-connect", "Connect", !running, connect_aws).default_button(),
                ),
        );
    if !s.aws_profiles.is_empty() {
        c = c.child(
            text(format!(
                "In your AWS configuration: {}",
                s.aws_profiles.join(", ")
            ))
            .font(BODY)
            .color(p.t.text_secondary)
            .wrap(),
        );
    }
    c
}

/// What `aws sso login` printed for the login asked for here, and how it
/// ended.
fn aws_log(p: Paint, s: &App) -> Option<El> {
    let login = s.login.as_ref()?;
    let mut log = card(p).key("kb-aws-log").gap(space::S1);
    for (i, line) in login.lines().iter().enumerate() {
        log = log.child(
            text(line)
                .key(format!("kb-aws-log-{i}"))
                .font(BODY.mono())
                .color(p.t.text)
                .wrap(),
        );
    }
    match login.outcome() {
        None => {
            log = log.child(row().justify_end().child(button(
                p,
                "kb-aws-cancel",
                "Cancel",
                true,
                |s, _| {
                    if let Some(l) = &s.login {
                        l.cancel();
                    }
                },
            )));
        }
        Some(Ok(done)) => {
            log = log.child(text(done).font(BODY).color(p.good).wrap());
        }
        Some(Err(problem)) => log = log.child(problem_box(p, "kb-aws-problem", &problem)),
    }
    Some(log)
}

fn proton_connect(p: Paint, s: &App, saved: bool) -> El {
    let f = &s.proton;
    if !f.open {
        return row().child(button(
            p,
            "kb-proton-open",
            if saved {
                "Replace the token…"
            } else {
                "Connect a token…"
            },
            s.idle(),
            |s, _| s.proton.open = true,
        ));
    }
    let mut c = col()
        .key("kb-proton-form")
        .gap(space::S2)
        .child(
            text("A Proton Pass personal access token. kagebunshin checks pass-cli logs in with it, then saves it in the local store.")
                .font(BODY)
                .color(p.t.text_secondary)
                .wrap(),
        )
        .child(
            row()
                .w_full()
                .gap(space::S2)
                .child(
                    field(p, "kb-proton-token", &f.token, "Token", |s| &mut s.proton.token)
                        .secure()
                        .grow(1.0),
                )
                .child(
                    field(
                        p,
                        "kb-proton-expires",
                        &f.expires,
                        "Expires (YYYY-MM-DD, optional)",
                        |s| &mut s.proton.expires,
                    )
                    .grow(1.0),
                ),
        );
    if let Some(e) = &f.error {
        c = c.child(
            text(e)
                .key("kb-proton-error")
                .font(BODY)
                .color(p.warn)
                .wrap(),
        );
    }
    c.child(
        row()
            .gap(space::S2)
            .justify_end()
            .child(button(p, "kb-proton-cancel", "Cancel", true, |s, _| {
                s.proton = TokenForm::new();
            }))
            .child(
                button(p, "kb-proton-connect", "Connect", s.idle(), connect_proton)
                    .default_button(),
            ),
    )
}

fn add_form(p: Paint, f: &AddForm, idle: bool) -> El {
    let file = f.provider == Provider::File;
    let mut form = card(p).key("kb-add-form").gap(space::S3).child(
        row()
            .gap(space::S2)
            .child(choice(
                p,
                "kb-add-aws",
                "AWS Secrets Manager",
                f.provider == Provider::AwsSm,
                |f| f.provider = Provider::AwsSm,
            ))
            .child(choice(
                p,
                "kb-add-proton",
                "Proton Pass",
                f.provider == Provider::Proton,
                |f| f.provider = Provider::Proton,
            ))
            .child(choice(p, "kb-add-file", "Local store", file, |f| {
                f.provider = Provider::File;
            })),
    );
    let placeholder = if file {
        "Store section (default: <project>.<env>)"
    } else {
        form = form.child(
            row()
                .gap(space::S2)
                .child(choice(
                    p,
                    "kb-add-prefix",
                    "Every secret under a prefix",
                    !f.one,
                    |f| f.one = false,
                ))
                .child(choice(p, "kb-add-one", "One secret", f.one, |f| {
                    f.one = true;
                })),
        );
        match (f.provider, f.one) {
            (Provider::Proton, true) => "Vault and API key, e.g. global/OPENAI_KEY",
            (Provider::Proton, false) => "Vault, e.g. acme/",
            (_, true) => "Secret name, e.g. acme/dev/api",
            (_, false) => "Prefix, e.g. acme/dev/",
        }
    };
    form = form.child(field(p, "kb-add-name", &f.name, placeholder, |s| &mut s.form.name).w_full());
    if f.provider == Provider::AwsSm {
        form = form.child(
            row()
                .w_full()
                .gap(space::S2)
                .child(
                    field(
                        p,
                        "kb-add-profile",
                        &f.profile,
                        "AWS profile (default: the environment's)",
                        |s| &mut s.form.profile,
                    )
                    .grow(1.0),
                )
                .child(
                    field(
                        p,
                        "kb-add-region",
                        &f.region,
                        "Region (default: the profile's)",
                        |s| &mut s.form.region,
                    )
                    .grow(1.0),
                ),
        );
    }
    form.child(
        row()
            .gap(space::S2)
            .center_y()
            .child(choice(
                p,
                "kb-add-optional",
                "Optional: skip it if it fails",
                f.optional,
                |f| f.optional = !f.optional,
            ))
            .child(el().grow(1.0))
            .child(button(p, "kb-add-cancel", "Cancel", true, |s, _| {
                s.form = AddForm::new();
            }))
            .child(button(p, "kb-add-ok", "Add", idle, add_source).default_button()),
    )
}

fn source_row(p: Paint, i: usize, s: &SourceView) -> El {
    let mut top = row()
        .gap(space::S2)
        .center_y()
        .child(
            text(format!("{}. {} {}", i + 1, s.provider, s.select))
                .font(type_::LABEL)
                .color(p.t.text),
        )
        .child(
            text(s.locations.join(", "))
                .font(BODY.mono())
                .color(p.t.text)
                .truncate()
                .grow(1.0),
        );
    if s.optional {
        top = top.child(badge("kb-optional", "optional", p.info));
    }
    let mut r = col()
        .key(format!("kb-source-{i}"))
        .gap(space::S1)
        .child(top);
    let mut aws = Vec::new();
    if let Some(profile) = &s.profile {
        aws.push(format!("profile {profile}"));
    }
    if let Some(region) = &s.region {
        aws.push(format!("region {region}"));
    }
    if !aws.is_empty() {
        r = r.child(text(aws.join(" · ")).font(BODY).color(p.t.text_secondary));
    }
    r
}

/// Scenes: fixed states for snapshots, with no daemon.
#[allow(
    clippy::unwrap_used,
    clippy::wildcard_imports,
    reason = "fixtures: constant names that always parse, built from the whole app"
)]
mod scenes {
    use kagebunshin::daemon::resolve::waiting_message;
    use kagebunshin::ipc::protocol::{
        Facts, KeyStatus, PhoneAnswer, PhoneChoice, PhonePairingView, PhoneStatus, PhoneView,
        RemoteStatus, VarStatus, WaitingEnv,
    };
    use kagebunshin::types::Provider;

    use super::*;
    use crate::catalog::{Here, ProjectView};
    use crate::daemon::{NewToken, Pairing};
    use crate::machine::{Phones, Revealed};

    pub fn catalog() -> Catalog {
        let source = |provider, select, locations: &[&str]| SourceView {
            provider,
            select,
            locations: locations.iter().map(|l| (*l).to_owned()).collect(),
            optional: false,
            profile: None,
            region: None,
        };
        let env = |name: &str, default, sources| EnvView {
            name: name.parse().unwrap(),
            default,
            sources,
            default_source: false,
            problem: None,
        };
        let dev = vec![
            SourceView {
                profile: Some("acme-dev".into()),
                region: Some("eu-west-1".into()),
                ..source("aws_sm", "prefix", &["acme/dev/"])
            },
            SourceView {
                optional: true,
                ..source("file", "secret", &["widget.dev"])
            },
        ];
        let prod = vec![SourceView {
            profile: Some("acme-prod".into()),
            ..source("aws_sm", "prefix", &["acme/prod/"])
        }];
        Catalog {
            projects: vec![
                ProjectView {
                    name: "billing".parse().unwrap(),
                    remotes: vec!["github.com/acme/billing".parse().unwrap()],
                    path: None,
                    envs: vec![env(
                        "dev",
                        true,
                        vec![source("file", "secret", &["billing.dev"])],
                    )],
                },
                ProjectView {
                    name: "shop".parse().unwrap(),
                    remotes: vec!["github.com/acme/shop".parse().unwrap()],
                    path: None,
                    envs: vec![env(
                        "dev",
                        true,
                        vec![source("file", "secret", &["shop.dev"])],
                    )],
                },
                ProjectView {
                    name: "shop-api".parse().unwrap(),
                    remotes: vec!["github.com/acme/shop".parse().unwrap()],
                    path: Some("apps/api".into()),
                    envs: vec![env(
                        "dev",
                        true,
                        vec![source("file", "secret", &["shop-api.dev"])],
                    )],
                },
                ProjectView {
                    name: "widget".parse().unwrap(),
                    remotes: vec!["github.com/acme/widget".parse().unwrap()],
                    path: None,
                    envs: vec![env("dev", true, dev), env("prod", false, prod)],
                },
            ],
            problem: None,
            here: Some(Here {
                project: "widget".parse().unwrap(),
                cwd: "/src/widget".into(),
                subdir: None,
                example_keys: Some(vec!["API_KEY".parse().unwrap()]),
                env_file: None,
            }),
            cwd: "/src/widget".into(),
            aws: (None, None),
        }
    }

    fn selection(env: &str) -> Selection {
        Selection {
            project: "widget".parse().unwrap(),
            env: env.parse().unwrap(),
            facts: Facts {
                cwd: "/src/widget".into(),
                remotes: vec!["github.com/acme/widget".parse().unwrap()],
                subdir: None,
                root: None,
                project: None,
                env: Some(env.parse().unwrap()),
                example_keys: None,
                example_values: Vec::new(),
                env_file: None,
            },
        }
    }

    pub fn report() -> EnvReport {
        let origin = |provider, location: &str| Origin::new(provider, location);
        let key =
            |name: &str, o: Origin, overridden: Vec<Origin>, in_example, sensitive| KeyStatus {
                key: name.parse().unwrap(),
                origin: o,
                overridden,
                in_example,
                sensitive,
            };
        EnvReport::Resolved {
            keys: vec![
                key(
                    "API_KEY",
                    origin(Provider::AwsSm, "acme/dev/api"),
                    Vec::new(),
                    true,
                    false,
                ),
                key(
                    "DATABASE_URL",
                    origin(Provider::File, "widget.dev"),
                    vec![origin(Provider::AwsSm, "acme/dev/db")],
                    true,
                    false,
                ),
                key(
                    "STRIPE_SECRET",
                    origin(Provider::AwsSm, "acme/dev/stripe"),
                    Vec::new(),
                    true,
                    true,
                ),
                key(
                    "DEBUG_TOKEN",
                    origin(Provider::File, "widget.dev"),
                    Vec::new(),
                    false,
                    false,
                ),
            ],
            missing: Some(vec!["SENTRY_DSN".parse().unwrap()]),
            vars: Vec::new(),
            warnings: vec![
                // As `status` says it of the environment.
                waiting_message(
                    &"widget".parse().unwrap(),
                    &"dev".parse().unwrap(),
                    "source aws_sm prefix acme/prod/ reads acme/prod/, which has the segment prod",
                ),
            ],
            acknowledged: false,
            skipped: Vec::new(),
            fixes: Vec::new(),
            proof: None,
        }
    }

    fn base(s: &mut App, conn: Conn, dev: Detail, prod: Detail) {
        *s = App::blank();
        s.catalog = catalog();
        s.machine.conn = conn;
        let column = |env, detail| Column {
            sel: selection(env),
            detail,
            inspected: false,
        };
        s.machine.shown = Some(Shown {
            project: "widget".parse().unwrap(),
            columns: vec![column("dev", dev), column("prod", prod)],
        });
    }

    pub fn unlocked(s: &mut App) {
        base(
            s,
            Conn::Up { locked: false },
            Detail::Loaded(report()),
            Detail::Idle,
        );
    }

    /// After an agent's setup: dev lacks a value only the person can type,
    /// and a secret a source skipped is the agent's to add; prod has every
    /// key set, and a run proved it.
    pub fn left(s: &mut App) {
        let var = |key: &str, value: &str| VarStatus {
            key: key.parse().unwrap(),
            value: value.into(),
            in_example: true,
        };
        let mut dev = report();
        if let EnvReport::Resolved {
            vars,
            missing,
            warnings,
            skipped,
            fixes,
            ..
        } = &mut dev
        {
            *missing = Some(vec![
                "SENTRY_DSN".parse().unwrap(),
                "SIGNING_KEY".parse().unwrap(),
            ]);
            warnings.clear();
            *skipped = vec!["acme/dev/signing".into()];
            *vars = vec![
                var("LOG_LEVEL", "debug"),
                var(
                    "PUBLIC_URL",
                    "https://widget-dev.acme.example/app/with/a/rather/long/path",
                ),
            ];
            *fixes = vec![
                Fix {
                    command: "kagebunshin project add-source widget dev --provider aws_sm \
                              --secret acme/dev/signing --key NAME --profile acme-dev"
                        .into(),
                    note: "secret acme/dev/signing is not a JSON object, so it was skipped; \
                           this adds its whole string as one key, if NAME is replaced with the \
                           key's name"
                        .into(),
                    who: Who::Agent,
                },
                Fix {
                    command: "kagebunshin store set widget.dev SENTRY_DSN".into(),
                    note: "it asks for the store passphrase, then each value".into(),
                    who: Who::Human,
                },
            ];
        }
        let mut prod = report();
        if let EnvReport::Resolved {
            keys,
            vars,
            missing,
            warnings,
            proof,
            ..
        } = &mut prod
        {
            for k in keys.iter_mut() {
                k.origin.location = k.origin.location.replace("dev", "prod");
                k.overridden.clear();
            }
            for (name, location) in [
                ("SENTRY_DSN", "acme/prod/sentry"),
                ("SIGNING_KEY", "acme/prod/signing"),
            ] {
                keys.push(KeyStatus {
                    key: name.parse().unwrap(),
                    origin: Origin::new(Provider::AwsSm, location),
                    overridden: Vec::new(),
                    in_example: true,
                    sensitive: false,
                });
            }
            keys.sort_by(|a, b| a.key.cmp(&b.key));
            *vars = vec![
                var("LOG_LEVEL", "info"),
                var("PUBLIC_URL", "https://widget.acme.example"),
            ];
            *missing = Some(Vec::new());
            warnings.clear();
            *proof = Some(Proof {
                time: 1_794_650_000,
                program: "./test.sh".into(),
            });
        }
        base(
            s,
            Conn::Up { locked: false },
            Detail::Loaded(dev),
            Detail::Loaded(prod),
        );
    }

    /// Prod is marked sensitive, so its keys wait for the passphrase.
    pub fn sensitive(s: &mut App) {
        base(
            s,
            Conn::Up { locked: false },
            Detail::Loaded(report()),
            Detail::Loaded(EnvReport::Sensitive),
        );
        s.env = Some("prod".parse().unwrap());
    }

    /// Prod looks like production and was acknowledged as not: its keys
    /// are read as any other's, under a line that says so.
    pub fn acknowledged(s: &mut App) {
        let mut prod = report();
        if let EnvReport::Resolved {
            acknowledged,
            warnings,
            ..
        } = &mut prod
        {
            *acknowledged = true;
            warnings.clear();
        }
        base(
            s,
            Conn::Up { locked: false },
            Detail::Loaded(report()),
            Detail::Loaded(prod),
        );
        s.env = Some("prod".parse().unwrap());
    }

    /// The last sensitive secret of dev was just unmarked while the keys
    /// were narrowed to the sensitive ones: none is left to list.
    pub fn no_match(s: &mut App) {
        let mut dev = report();
        if let EnvReport::Resolved { keys, .. } = &mut dev {
            for k in keys {
                k.sensitive = false;
            }
        }
        base(
            s,
            Conn::Up { locked: false },
            Detail::Loaded(dev),
            Detail::Idle,
        );
        s.filter = Some(Filter::Sensitive);
        s.machine.notice = Some(Notice::Done {
            message: "Unmarked acme/dev/stripe.".into(),
            warnings: Vec::new(),
        });
    }

    /// The keys of dev narrowed to the missing ones.
    pub fn filtered(s: &mut App) {
        unlocked(s);
        s.filter = Some(Filter::Missing);
    }

    /// Prod is marked sensitive, and its keys were asked for.
    pub fn sensitive_shown(s: &mut App) {
        left(s);
        s.env = Some("prod".parse().unwrap());
        if let Some(shown) = &mut s.machine.shown {
            shown.columns[1].inspected = true;
        }
    }

    /// Dev reads secrets of several keys each, most of them marked
    /// sensitive, and the mail one is read by another project too.
    pub fn marks(s: &mut App) {
        let mut dev = report();
        if let EnvReport::Resolved {
            keys,
            missing,
            warnings,
            ..
        } = &mut dev
        {
            keys.clear();
            for (secret, names, sensitive) in [
                (
                    "acme/dev/analytics",
                    ["ANALYTICS_ID", "ANALYTICS_KEY"],
                    true,
                ),
                ("acme/dev/errors", ["ERRORS_DSN", "ERRORS_ENV"], true),
                ("acme/dev/mail", ["MAIL_FROM", "MAIL_KEY"], true),
                ("acme/dev/maps", ["MAPS_ID", "MAPS_KEY"], false),
            ] {
                keys.extend(names.map(|name| KeyStatus {
                    key: name.parse().unwrap(),
                    origin: Origin::new(Provider::AwsSm, secret),
                    overridden: Vec::new(),
                    in_example: true,
                    sensitive,
                }));
            }
            *missing = Some(Vec::new());
            warnings.clear();
        }
        base(
            s,
            Conn::Up { locked: false },
            Detail::Loaded(dev),
            Detail::Idle,
        );
        s.machine.shared = vec![SharedSecret {
            project: "widget".parse().unwrap(),
            env: "dev".parse().unwrap(),
            secret: Origin::new(Provider::AwsSm, "acme/dev/mail"),
            prefix: false,
            with: vec!["shop.qa".parse().unwrap()],
            open: vec!["shop.qa".parse().unwrap()],
            sensitive: true,
            production: false,
        }];
    }

    /// Asked to unmark one of them, and another ticked to go with it.
    pub fn unmarks(s: &mut App) {
        marks(s);
        let shown = s.machine.shown.as_ref().unwrap();
        let unmarks = Unmarks {
            marked: marked_secrets(s, shown, &shown.columns[0]),
            unmark: vec![Origin::new(Provider::AwsSm, "acme/dev/errors")],
        };
        step(&mut s.machine, Event::Unmark(unmarks));
        step(
            &mut s.machine,
            Event::Also(Origin::new(Provider::AwsSm, "acme/dev/mail")),
        );
    }

    pub fn locked(s: &mut App) {
        base(
            s,
            Conn::Up { locked: true },
            Detail::Loaded(EnvReport::Locked),
            Detail::Idle,
        );
        s.asking = Asking::Locked;
        s.passphrase.focused = true;
    }

    /// Locked, and the passphrase typed was wrong.
    pub fn locked_wrong(s: &mut App) {
        locked(s);
        s.machine.notice = Some(Notice::Failed(Problem::new(
            "wrong passphrase for the local store",
        )));
    }

    pub fn down(s: &mut App) {
        let problem = Problem {
            message: "the daemon is not running (no socket at /run/user/1000/kagebunshin/kagebunshind.sock)"
                .into(),
            hint: Some(kagebunshin::cli::error::start_daemon_hint()),
            unreachable: true,
        };
        base(
            s,
            Conn::Down(problem),
            Detail::Loading(rune::machine::Attempt::default()),
            Detail::Idle,
        );
    }

    pub fn error(s: &mut App) {
        let problem = Problem::new("aws_sm acme/dev/: the SSO session has expired")
            .with_hint("run `aws sso login --profile acme-dev`, then Refresh");
        base(
            s,
            Conn::Up { locked: false },
            Detail::Failed(problem),
            Detail::Idle,
        );
    }

    pub fn empty(s: &mut App) {
        *s = App::blank();
        s.machine.conn = Conn::Up { locked: false };
    }

    /// Asked to confirm removing a secret's mark.
    pub fn confirm(s: &mut App) {
        key(s);
        step(
            &mut s.machine,
            Event::Ask(Change::Mark {
                mark: Mark::Secret(Origin::new(Provider::AwsSm, "acme/dev/stripe")),
                sensitive: false,
            }),
        );
    }

    /// Asked for the passphrase, to show an environment marked sensitive.
    pub fn passphrase(s: &mut App) {
        sensitive(s);
        s.machine.pending = Pending::Passphrase(Purpose::Inspect("prod".parse().unwrap()));
        s.asking = Asking::Prompt;
        s.passphrase.focused = true;
    }

    /// One key, its value hidden.
    pub fn key(s: &mut App) {
        unlocked(s);
        s.view = View::Key("DATABASE_URL".parse().unwrap());
    }

    /// One key, its value revealed.
    pub fn revealed(s: &mut App) {
        key(s);
        s.machine.revealed = Some(Revealed {
            env: "dev".parse().unwrap(),
            key: "DATABASE_URL".parse().unwrap(),
            value: WireSecret::new("postgres://dev.example/widget".into()),
        });
    }

    /// An environment's sources, after an edit that warned.
    pub fn sources(s: &mut App) {
        unlocked(s);
        s.view = View::Sources;
        s.machine.notice = Some(Notice::Done {
            message: "Moved source 2 to 1.".into(),
            warnings: vec![
                // As `project add-source` says it.
                waiting_message(
                    &"widget".parse().unwrap(),
                    &"dev".parse().unwrap(),
                    "aws_sm prefix acme/prod/ has the segment prod",
                ),
            ],
        });
    }

    /// Adding a source.
    pub fn adding(s: &mut App) {
        sources(s);
        s.machine.notice = None;
        s.form.open = true;
        s.form.one = true;
        s.form.name = TextEdit::new("acme/dev/extra");
    }

    pub fn activity(s: &mut App) {
        unlocked(s);
        s.view = View::Activity;
        let line = |project: &str, line: &str| (project.parse().ok(), line.to_owned());
        s.activity = Ok(Activity {
            lines: vec![
                line(
                    "widget",
                    "2026-11-11 09:31:02Z allowed reveal widget/dev DATABASE_URL pid 812",
                ),
                line(
                    "widget",
                    "2026-11-11 09:26:13Z denied run widget/prod pid 41",
                ),
                line("shop", "2026-11-11 09:22:51Z allowed run shop/dev pid 40"),
                line(
                    "widget",
                    "2026-11-11 09:20:40Z allowed run widget/dev pid 39",
                ),
            ],
            unreadable: 0,
        });
    }

    /// Providers, AWS ready and a Proton Pass token about to expire.
    pub fn providers(s: &mut App) {
        unlocked(s);
        s.view = View::Providers;
        s.aws_profiles = vec!["acme-dev".into(), "acme-prod".into()];
        s.machine.providers.asked = true;
        s.machine.providers.last = Some(Ok(vec![
            ProviderStatus {
                provider: Provider::AwsSm,
                detail: "profile acme-dev, region eu-west-1".into(),
                health: Health::Ok,
                expires: None,
            },
            ProviderStatus {
                provider: Provider::AwsSm,
                detail: "profile acme-prod".into(),
                health: Health::NeedsLogin {
                    hint: "run `aws sso login --profile acme-prod`".into(),
                },
                expires: None,
            },
            ProviderStatus {
                provider: Provider::Proton,
                detail: "personal access token".into(),
                health: Health::Ok,
                expires: Some(1_795_000_000),
            },
            ProviderStatus {
                provider: Provider::File,
                detail: "local store".into(),
                health: Health::Ok,
                expires: None,
            },
        ]));
    }

    /// A key read from Proton Pass, marked sensitive: it goes by the name
    /// a source selects it by, never by the ids that say which item it is.
    pub fn proton(s: &mut App) {
        unlocked(s);
        proton_key(s);
    }

    /// Adds a Proton source and its one key, marked sensitive, to dev.
    fn proton_key(s: &mut App) -> KeyStatus {
        let key = KeyStatus {
            key: "MAIL_TOKEN".parse().unwrap(),
            origin: Origin::new(
                Provider::Proton,
                "Qm9nVXNoYXJlSWRfbm9ib2R5X3JlYWRzPT0=/aXRlbV9pZF9ub2JvZHlfcmVhZHNfZWl0aGVyPT0=",
            )
            .named("agents/MAIL_TOKEN"),
            overridden: Vec::new(),
            in_example: true,
            sensitive: true,
        };
        let dev = s.catalog.projects.iter_mut().find_map(|p| {
            (p.name.as_str() == "widget")
                .then(|| p.envs.iter_mut().find(|e| e.name.as_str() == "dev"))
                .flatten()
        });
        if let Some(dev) = dev {
            dev.sources.push(SourceView {
                provider: "proton",
                select: "secret",
                locations: vec!["agents/MAIL_TOKEN".into()],
                optional: false,
                profile: None,
                region: None,
            });
        }
        let column = s
            .machine
            .shown
            .as_mut()
            .and_then(|sh| sh.columns.first_mut());
        if let Some(Detail::Loaded(EnvReport::Resolved { keys, .. })) =
            column.map(|c| &mut c.detail)
        {
            keys.push(key.clone());
        }
        key
    }

    /// An agent's `run` waits for approval of that Proton key.
    pub fn approval_proton(s: &mut App) {
        approval(s);
        let item = proton_key(s);
        s.approvals[0].keys = vec![item.key];
        s.approvals[0].secrets = vec![item.origin];
    }

    /// Remote: the endpoint listening, and two machines let in, one by a
    /// grant made before grants had tokens.
    pub fn remote(s: &mut App) {
        unlocked(s);
        s.view = View::Remote;
        let grant = |machine: &str, project: &str, envs: &[&str], expires, token| GrantView {
            machine: machine.into(),
            node: format!("n{machine}"),
            project: project.parse().unwrap(),
            envs: envs.iter().map(|e| e.parse().unwrap()).collect(),
            expires,
            token,
        };
        s.machine.remote = Some(RemoteStatus {
            enabled: Some(true),
            listening: Some("100.64.0.1:47317".into()),
            problem: None,
            grants: vec![
                grant("buildbot", "widget", &["dev", "rc"], None, true),
                grant("laptop", "shop", &["dev"], Some(4_102_444_800), false),
            ],
        });
    }

    /// Remote, a grant just given a new token.
    pub fn remote_token(s: &mut App) {
        remote(s);
        let grants = &mut s.machine.remote.as_mut().unwrap().grants;
        grants[1].token = true;
        s.machine.token = Some(NewToken {
            grant: Grant::from(&grants[1]),
            token: WireSecret::new(format!("kbr_{}", "0123456789abcdef".repeat(4))),
        });
    }

    /// The approval page's address in every scene.
    pub const PAGE_URL: &str = "https://self.example.ts.net:47318";

    fn phone_choice(name: &str, os: &str) -> PhoneChoice {
        PhoneChoice {
            name: name.into(),
            node: format!("n{name}"),
            os: os.into(),
        }
    }

    /// Phone: none paired, and the tailnet's two that could be.
    pub fn phone_none(s: &mut App) {
        unlocked(s);
        s.view = View::Phone;
        s.machine.phones = Phones {
            asked: true,
            asking: None,
            last: Some(Ok(vec![
                phone_choice("pocket", "iOS"),
                phone_choice("tablet", "android"),
            ])),
        };
    }

    /// Phone: one paired, its page served, and a request answered there.
    pub fn phone(s: &mut App) {
        phone_none(s);
        s.machine.phone = Some(Box::new(PhoneStatus {
            paired: Some(PhoneView {
                name: "pocket".into(),
                node: "npocket".into(),
                paired: 1_795_046_400,
                seen: Some(1_795_100_000),
                notifies: true,
                untold: None,
            }),
            url: Some(PAGE_URL.into()),
            problem: None,
            pairing: None,
            last: Some(PhoneAnswer {
                id: 7,
                project: "widget".parse().unwrap(),
                env: "dev".parse().unwrap(),
                approved: true,
                time: 1_795_100_060,
            }),
        }));
    }

    /// Phone: one on its way in, with the code it scans.
    pub fn phone_pairing(s: &mut App) {
        phone_none(s);
        s.machine.phone = Some(Box::new(PhoneStatus {
            paired: None,
            url: Some(PAGE_URL.into()),
            problem: None,
            pairing: Some(PhonePairingView {
                name: "pocket".into(),
                left: 540,
            }),
            last: None,
        }));
        s.machine.pairing = Some(Pairing {
            phone: phone_choice("pocket", "iOS"),
            url: PAGE_URL.into(),
        });
        draw_code(s);
    }

    /// Providers being asked about again: each says so by its last answer.
    pub fn providers_checking(s: &mut App) {
        providers(s);
        step(&mut s.machine, Event::CheckProviders);
    }

    /// An agent's `run` waits for approval.
    pub fn approval(s: &mut App) {
        unlocked(s);
        s.approvals = vec![ApprovalPrompt {
            id: 1,
            project: "widget".parse().unwrap(),
            env: "dev".parse().unwrap(),
            keys: vec!["STRIPE_SECRET".parse().unwrap()],
            reason: ApprovalReason::default(),
            command: "npm run deploy -- --dry-run".into(),
            argv: ["npm", "run", "deploy", "--", "--dry-run"]
                .map(Into::into)
                .into(),
            pid: 4242,
            cwd: "/src/widget".into(),
            parents: ["zsh", "claude", "zsh", "kitty"].map(Into::into).into(),
            left: Some(272),
            remote: None,
            secrets: vec![Origin::new(Provider::AwsSm, "acme/shared/stripe")],
            every_key: false,
            // A coding agent stands behind it: the approval can stand.
            standing: Some(kagebunshin::ipc::protocol::StandingOffer {
                seconds: 900,
                holder: "Claude Code".into(),
            }),
        }];
        s.approval_passphrase.focused = true;
    }

    /// An approval was left standing: the agent it is for gets that
    /// environment without asking, until it ends or is ended.
    pub fn standing(s: &mut App) {
        unlocked(s);
        s.machine.standing = vec![kagebunshin::ipc::protocol::StandingView {
            project: "widget".parse().unwrap(),
            env: "prod".parse().unwrap(),
            holder: "Claude Code".into(),
            left: 700,
        }];
    }

    /// An agent's `run` in an environment that looks like production,
    /// which nobody has decided about yet, waits for approval.
    pub fn approval_waiting(s: &mut App) {
        waiting(s);
        s.approvals = vec![ApprovalPrompt {
            id: 2,
            project: "widget".parse().unwrap(),
            env: "prod".parse().unwrap(),
            keys: vec![
                "DATABASE_URL".parse().unwrap(),
                "STRIPE_KEY".parse().unwrap(),
            ],
            reason: ApprovalReason::Waiting {
                why: "source aws_sm secret acme/prod/db reads acme/prod/db, which has the segment prod"
                    .into(),
            },
            command: "./test.sh".into(),
            argv: vec!["./test.sh".into()],
            pid: 5151,
            cwd: "/src/widget".into(),
            parents: ["bash", "opencode"].map(Into::into).into(),
            left: Some(24),
            remote: None,
            secrets: Vec::new(),
            every_key: false,
            standing: None,
        }];
        s.approval_passphrase.focused = true;
    }

    /// A script handed to a shell asks for an environment a person marked
    /// sensitive: the script is the command, however long it is.
    pub fn approval_script(s: &mut App) {
        approval_waiting(s);
        let script = "set -euo pipefail; export NODE_ENV=production && npx prisma migrate deploy \
                      --schema ./packages/database/prisma/schema.prisma && node \
                      ./scripts/backfill.js --batch-size 500 --since \"2026-01-01 00:00\" | tee \
                      /tmp/backfill-$(date +%s).log; curl -fsS \
                      https://hooks.example.com/services/deployments/notify?channel=releases&\
                      status=done";
        let prompt = &mut s.approvals[0];
        prompt.reason = ApprovalReason::Marked;
        prompt.argv = vec!["bash".into(), "-lc".into(), script.into()];
        prompt.command = format!("bash -lc {script:?}");
        prompt.left = Some(300);
    }

    /// A request for an environment whose checkout expects 40 keys, the
    /// first few listed.
    pub fn approval_many(s: &mut App) {
        approval_waiting(s);
        let prompt = &mut s.approvals[0];
        prompt.reason = ApprovalReason::Marked;
        prompt.keys = (1..=40)
            .map(|i| format!("SERVICE_{i}_API_TOKEN").parse().unwrap())
            .collect();
        prompt.left = Some(300);
    }

    /// The same with every key listed.
    pub fn approval_many_open(s: &mut App) {
        approval_many(s);
        s.approval_details = true;
        s.approval_all_keys = true;
    }

    /// A request with its details shown: the keys, how it got here, why
    /// it waits and what approving does.
    pub fn approval_details(s: &mut App) {
        approval(s);
        s.approval_details = true;
    }

    /// A request from a checkout with no .env.example, for an environment
    /// marked sensitive that the daemon holds: every key it sets.
    pub fn approval_every_key(s: &mut App) {
        approval_waiting(s);
        let prompt = &mut s.approvals[0];
        prompt.reason = ApprovalReason::Marked;
        prompt.keys = [
            "ANALYTICS_ID",
            "AUTH_SECRET",
            "DATABASE_URL",
            "MAIL_TOKEN",
            "QUEUE_URL",
            "SENTRY_DSN",
            "SESSION_KEY",
            "SIGNING_KEY",
            "STORAGE_BUCKET",
            "STORAGE_KEY",
            "STRIPE_KEY",
            "STRIPE_WEBHOOK_SECRET",
            "UPLOAD_TOKEN",
        ]
        .iter()
        .map(|k| k.parse().unwrap())
        .collect();
        prompt.every_key = true;
        prompt.left = Some(300);
    }

    /// The same before the daemon has read the environment: it cannot say
    /// which keys those are.
    pub fn approval_every_key_unread(s: &mut App) {
        approval_every_key(s);
        s.approvals[0].keys.clear();
    }

    /// An agent's `onboard` of three checkouts waits for approval to
    /// import their env files: a new project each, one into an
    /// environment that has keys.
    pub fn approval_import(s: &mut App) {
        unlocked(s);
        s.approvals = vec![import_prompt(false)];
        s.approval_passphrase.focused = true;
    }

    /// The same while locked: the passphrase unlocks too, and the daemon
    /// cannot say which sections have keys.
    pub fn approval_import_locked(s: &mut App) {
        locked(s);
        s.passphrase.focused = false;
        s.approvals = vec![import_prompt(true)];
        s.approval_passphrase.focused = true;
    }

    fn import_prompt(unlock: bool) -> ApprovalPrompt {
        let keys = |keys: &[&str]| keys.iter().map(|k| k.parse().unwrap()).collect();
        let names = |section: &str, file: &str, into, keys, replaces| ImportNames {
            section: section.parse().unwrap(),
            files: vec![file.into()],
            keys,
            into,
            replaces: if unlock { Vec::new() } else { replaces },
            if_empty: into != ImportInto::Existing,
        };
        ApprovalPrompt {
            id: 1,
            project: "widget".parse().unwrap(),
            env: "dev".parse().unwrap(),
            keys: Vec::new(),
            reason: ApprovalReason::Import {
                sections: vec![
                    names(
                        "widget.dev",
                        "/src/widget/.env",
                        ImportInto::NewProject,
                        keys(&["DATABASE_URL", "STRIPE_SECRET", "SESSION_KEY", "SENTRY_DSN"]),
                        Vec::new(),
                    ),
                    names(
                        "gadget-web.dev",
                        "/src/gadget/apps/web/.env.local",
                        ImportInto::NewProject,
                        keys(&["NEXT_PUBLIC_API_URL", "AUTH_SECRET"]),
                        Vec::new(),
                    ),
                    names(
                        "billing.staging",
                        "/src/billing/staging.env",
                        ImportInto::Existing,
                        keys(&["DATABASE_URL", "LEDGER_TOKEN", "WEBHOOK_SECRET"]),
                        keys(&["DATABASE_URL"]),
                    ),
                ],
                unlock,
            },
            command: "kagebunshin onboard /src/widget /src/gadget /src/billing".into(),
            argv: [
                "kagebunshin",
                "onboard",
                "/src/widget",
                "/src/gadget",
                "/src/billing",
            ]
            .map(Into::into)
            .into(),
            pid: 4242,
            cwd: "/src".into(),
            parents: ["zsh", "claude", "zsh", "kitty"].map(Into::into).into(),
            left: Some(272),
            remote: None,
            secrets: Vec::new(),
            every_key: false,
            standing: None,
        }
    }

    /// An agent's `store set`, with no terminal, asks for values to be
    /// typed: one of the keys has a value now.
    pub fn approval_type(s: &mut App) {
        unlocked(s);
        s.approvals = vec![type_prompt(false)];
        s.approval_values = value_fields(s.approvals.first());
    }

    /// The same while locked: saving unlocks too, and the daemon cannot
    /// say which keys have a value.
    pub fn approval_type_locked(s: &mut App) {
        locked(s);
        s.passphrase.focused = false;
        s.approvals = vec![type_prompt(true)];
        s.approval_values = value_fields(s.approvals.first());
    }

    fn type_prompt(unlock: bool) -> ApprovalPrompt {
        let keys = |keys: &[&str]| keys.iter().map(|k| k.parse().unwrap()).collect();
        ApprovalPrompt {
            id: 1,
            project: "widget".parse().unwrap(),
            env: "dev".parse().unwrap(),
            keys: keys(&["STRIPE_SECRET", "SESSION_KEY", "SENTRY_DSN"]),
            reason: ApprovalReason::Type {
                replaces: if unlock {
                    Vec::new()
                } else {
                    keys(&["SESSION_KEY"])
                },
                unlock,
            },
            command: "kagebunshin store set widget.dev STRIPE_SECRET SESSION_KEY SENTRY_DSN".into(),
            argv: [
                "kagebunshin",
                "store",
                "set",
                "widget.dev",
                "STRIPE_SECRET",
                "SESSION_KEY",
                "SENTRY_DSN",
            ]
            .map(Into::into)
            .into(),
            pid: 4242,
            cwd: "/src/widget".into(),
            parents: ["zsh", "claude", "zsh", "kitty"].map(Into::into).into(),
            left: Some(272),
            remote: None,
            secrets: Vec::new(),
            every_key: false,
            standing: None,
        }
    }

    /// After an upgrade: environments that look like production wait for
    /// a decision, in this project and others.
    pub fn waiting(s: &mut App) {
        unlocked(s);
        let w = |project: &str, env: &str, why: &str| WaitingEnv {
            project: project.parse().unwrap(),
            env: env.parse().unwrap(),
            why: why.into(),
        };
        s.machine.waiting = vec![
            w(
                "billing",
                "production",
                "its name has the segment production",
            ),
            w("gadget", "rc", "its name has the segment rc"),
            // The one the report's warning is about, so the banner leaves
            // it to this list.
            w(
                "widget",
                "dev",
                "source aws_sm prefix acme/prod/ reads acme/prod/, which has the segment prod",
            ),
            w(
                "widget",
                "prod",
                "source aws_sm secret acme/prod/db reads acme/prod/db, which has the segment prod",
            ),
        ];
    }

    /// A project as an agent sets one up from a team's cloud account: one
    /// source that lists forty secrets, a few keys in each, and three
    /// environments.
    pub fn many(s: &mut App) {
        const SECRETS: [&str; 40] = [
            "dev/app",
            "errors",
            "dev/http",
            "dev/partners",
            "dev/mail",
            "dev/db",
            "dev/warehouse",
            "newsletter",
            "analytics",
            "dev/bank",
            "dev/cloud",
            "dev/payments",
            "social",
            "dev/crm",
            "dev/maps",
            "dev/identity",
            "dev/print",
            "dev/books",
            "dev/llm",
            "dev/cards",
            "dev/detector",
            "dev/payroll",
            "dev/giving",
            "dev/treasury",
            "dev/blog",
            "dev/ledger",
            "dev/rewards",
            "mobile",
            "dev/chat",
            "dev/captcha",
            "dev/search",
            "dev/queue",
            "dev/cache",
            "dev/sms",
            "dev/video",
            "dev/storage",
            "cdn",
            "photos",
            "dev/flags",
            "dev/jobs",
        ];
        waiting(s);
        s.machine.waiting.truncate(2);
        let widget = s
            .catalog
            .projects
            .iter_mut()
            .find(|p| p.name.as_str() == "widget")
            .unwrap();
        widget.envs[0].sources = vec![SourceView {
            provider: "aws_sm",
            select: "secrets",
            locations: SECRETS.iter().map(|l| (*l).to_owned()).collect(),
            optional: false,
            profile: Some("acme".into()),
            region: None,
        }];
        let mut rc = widget.envs[1].clone();
        rc.name = "rc".parse().unwrap();
        widget.envs.push(rc);
        let keys = SECRETS
            .iter()
            .take(24)
            .flat_map(|secret| {
                let stem = secret.rsplit('/').next().unwrap().to_uppercase();
                ["API_KEY", "HOST", "SECRET"].map(|part| KeyStatus {
                    key: format!("{stem}_{part}").parse().unwrap(),
                    origin: Origin::new(Provider::AwsSm, *secret),
                    overridden: Vec::new(),
                    in_example: true,
                    sensitive: *secret == "dev/payments",
                })
            })
            .collect();
        let shown = s.machine.shown.as_mut().unwrap();
        shown.columns[0].detail = Detail::Loaded(EnvReport::Resolved {
            keys,
            missing: Some(Vec::new()),
            vars: Vec::new(),
            warnings: Vec::new(),
            acknowledged: false,
            skipped: Vec::new(),
            fixes: Vec::new(),
            proof: None,
        });
        shown.columns.push(Column {
            sel: selection("rc"),
            detail: Detail::Idle,
            inspected: false,
        });
    }

    /// What widget's environments share: dev and prod both read the mail
    /// and error secrets and everything under `acme/tools/`; qa, of
    /// another project, reads the mail secret too.
    pub fn shared() -> Vec<SharedSecret> {
        let one = |env: &str, name: &str, prefix, with: &[&str], open: &[&str], production| {
            let sections = |names: &[&str]| names.iter().map(|n| n.parse().unwrap()).collect();
            SharedSecret {
                project: "widget".parse().unwrap(),
                env: env.parse().unwrap(),
                secret: Origin::new(Provider::AwsSm, name),
                prefix,
                with: sections(with),
                open: sections(open),
                sensitive: false,
                production,
            }
        };
        let mut all = Vec::new();
        for (env, other) in [("dev", "widget.prod"), ("prod", "widget.dev")] {
            // Prod waits for a decision, so it is not open to dev.
            let open: &[&str] = if env == "prod" { &[other] } else { &[] };
            all.push(one(
                env,
                "acme/mail",
                false,
                &["shop.qa", other],
                &["shop.qa"],
                false,
            ));
            all.push(one(env, "acme/errors", false, &[other], open, false));
            all.push(one(env, "acme/tools/", true, &[other], open, false));
            all.push(one(env, "acme/prod/flags", false, &[other], open, true));
        }
        all
    }

    /// Asked to mark an environment whose secrets others read too, one of
    /// them ticked to mark as well.
    pub fn sharing(s: &mut App) {
        waiting(s);
        s.machine.shared = shared();
        step(
            &mut s.machine,
            Event::Ask(Change::Mark {
                mark: Mark::Env {
                    project: "widget".parse().unwrap(),
                    env: "prod".parse().unwrap(),
                    also: Vec::new(),
                },
                sensitive: true,
            }),
        );
        step(
            &mut s.machine,
            Event::Also(Origin::new(Provider::AwsSm, "acme/errors")),
        );
    }

    /// What gadget's rc reads that is marked sensitive: the mail and
    /// error secrets, which dev reads too, and the ledger, which only prod
    /// does besides.
    pub fn marked() -> Vec<SharedSecret> {
        let one = |name: &str, with: &[&str], open: &[&str]| {
            let sections = |names: &[&str]| names.iter().map(|n| n.parse().unwrap()).collect();
            SharedSecret {
                project: "gadget".parse().unwrap(),
                env: "rc".parse().unwrap(),
                secret: Origin::new(Provider::AwsSm, name),
                prefix: false,
                with: sections(with),
                open: sections(open),
                sensitive: true,
                production: false,
            }
        };
        let both: &[&str] = &["gadget.dev", "gadget.prod"];
        vec![
            one("acme/mail", both, &["gadget.dev"]),
            one("acme/errors", both, &["gadget.dev"]),
            one("acme/ledger", &["gadget.prod"], &[]),
        ]
    }

    /// Asked to acknowledge as not production an environment that reads
    /// marked secrets, one of them ticked to unmark.
    pub fn unmarking(s: &mut App) {
        waiting(s);
        s.machine.shared = marked();
        step(
            &mut s.machine,
            Event::Ask(Change::Acknowledge {
                project: "gadget".parse().unwrap(),
                env: "rc".parse().unwrap(),
                acknowledged: true,
            }),
        );
        step(
            &mut s.machine,
            Event::Also(Origin::new(Provider::AwsSm, "acme/mail")),
        );
    }

    /// A key of a secret marked sensitive that another environment reads
    /// too, in an environment that is not marked itself.
    pub fn shared_key(s: &mut App) {
        key(s);
        s.machine.shared = vec![SharedSecret {
            sensitive: true,
            ..shared().remove(1)
        }];
        s.machine.shared[0].secret = Origin::new(Provider::AwsSm, "acme/dev/stripe");
        s.view = View::Key("STRIPE_SECRET".parse().unwrap());
    }

    type Scene = (&'static str, fn(&mut App));

    pub const ALL: &[Scene] = &[
        ("unlocked", unlocked),
        ("left", left),
        ("sensitive", sensitive),
        ("sensitive-shown", sensitive_shown),
        ("acknowledged", acknowledged),
        ("no-match", no_match),
        ("filtered", filtered),
        ("marks", marks),
        ("unmarks", unmarks),
        ("locked", locked),
        ("locked-wrong", locked_wrong),
        ("down", down),
        ("error", error),
        ("empty", empty),
        ("confirm", confirm),
        ("passphrase", passphrase),
        ("key", key),
        ("revealed", revealed),
        ("sources", sources),
        ("adding", adding),
        ("activity", activity),
        ("providers", providers),
        ("providers-checking", providers_checking),
        ("remote", remote),
        ("remote-token", remote_token),
        ("phone", phone),
        ("phone-none", phone_none),
        ("phone-pairing", phone_pairing),
        ("proton", proton),
        ("approval", approval),
        ("approval-details", approval_details),
        ("standing", standing),
        ("approval-proton", approval_proton),
        ("approval-waiting", approval_waiting),
        ("approval-script", approval_script),
        ("approval-many", approval_many),
        ("approval-many-open", approval_many_open),
        ("approval-every-key", approval_every_key),
        ("approval-every-key-unread", approval_every_key_unread),
        ("approval-import", approval_import),
        ("approval-import-locked", approval_import_locked),
        ("approval-type", approval_type),
        ("approval-type-locked", approval_type_locked),
        ("waiting", waiting),
        ("sharing", sharing),
        ("unmarking", unmarking),
        ("shared-key", shared_key),
        ("many", many),
    ];
}

const SIZE: (f32, f32) = (980.0, 640.0);

/// The height of the bar across the top.
const HEADER: f32 = 48.0;

/// The window's frame. On macOS it has no title bar of its own: the bar
/// across the top is it, with the window's buttons centred in its height
/// (they are 14 points tall). Elsewhere the desktop frames the window, and
/// a snapshot is drawn as that unless `--chrome` asks for the Mac's.
fn chrome() -> rune::Chrome {
    if cfg!(target_os = "macos") || std::env::args().any(|a| a == "--chrome") {
        rune::Chrome {
            traffic_lights: Some((16.0, (HEADER - 14.0) / 2.0)),
            ..rune::Chrome::DEFAULT
        }
    } else {
        rune::Chrome {
            full_size_content: false,
            ..rune::Chrome::DEFAULT
        }
    }
}

fn main() -> std::process::ExitCode {
    rune::set_app_id("io.github.oorestisime.kagebunshin");
    let spec = AppSpec::<App> {
        scenes: scenes::ALL,
        // Names, commands and scripts in the system's monospace font.
        families: ("Inter", "ui-monospace"),
        setup: Some(setup),
        poll: Some(poll),
        ..AppSpec::new("kagebunshin", SIZE, init, view)
    };
    // A scene, a snapshot or a script: one window that ends when it is
    // done, with no tray and without reaching for a running app.
    if rune::is_headless() {
        rune::App::new(spec).chrome(chrome()).run();
        return std::process::ExitCode::SUCCESS;
    }
    match resident(spec) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            say(&e);
            std::process::ExitCode::FAILURE
        }
    }
}

/// A line on stderr, for whoever started the app from a terminal.
#[expect(
    clippy::print_stderr,
    reason = "the app's only words outside its window: why it did not start"
)]
fn say(line: &str) {
    eprintln!("kagebunshin-app: {line}");
}

/// Runs as the one process that stays in the tray, or hands what this
/// launch was for to the one that does.
fn resident(spec: AppSpec<App>) -> Result<(), String> {
    use shell::{Ask, Claim};
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flag = |name: &str| args.iter().any(|a| a == name);
    let ask = if flag("--quit") {
        Ask::Quit
    } else {
        Ask::Show {
            token: shell::activation_token(|k| std::env::var(k).ok()),
        }
    };
    let claim = socket_arg(&args).and_then(|socket| {
        let dir = socket_dir(&socket);
        ensure_private_dir(dir, kagebunshin::sys::effective_uid()).map_err(|e| e.to_string())?;
        shell::claim(dir, &ask).map_err(|e| format!("{}: {e}", dir.display()))
    });
    let instance = match claim {
        Ok(Claim::Told) => return Ok(()),
        Ok(Claim::NoneRuns) => {
            say("the app is not running");
            return Ok(());
        }
        Ok(Claim::First(instance)) => Some(instance),
        Err(e) if ask == Ask::Quit => return Err(format!("cannot reach a running app: {e}")),
        // The window says what is wrong with the socket; it opens anyway.
        Err(e) => {
            say(&format!("cannot tell whether the app already runs: {e}"));
            None
        }
    };

    let app = rune::App::new(spec).chrome(chrome()).on_close(on_close);
    let handle = app.handle();
    let show = {
        let handle = handle.clone();
        move |token: Option<String>| handle.activate(token.unwrap_or_default())
    };
    let quit = {
        let handle = handle.clone();
        move || handle.quit()
    };
    // A click on a notification of the app's shows its window: on macOS,
    // where the app posts them itself.
    rune_notify::on_click({
        let show = show.clone();
        move |_| show(None)
    });
    let tray = shell::tray(show.clone(), quit.clone());
    let left = instance.as_ref().map(shell::Instance::socket);
    if let Some(instance) = instance {
        instance
            .serve(move |ask| match ask {
                Ask::Show { token } => show(token),
                Ask::Quit => quit(),
            })
            .map_err(|e| format!("cannot start the thread that hears later launches: {e}"))?;
    }
    // Without a tray nothing would bring a closed window back, so closing
    // it ends the app, and it never starts hidden.
    let app = match &tray {
        Ok(_) if flag("--hidden") => app.windowless(),
        Ok(_) => app.keep_running(),
        Err(_) => app,
    };
    // With no tray too: a window that is open may be under another, and a
    // request is announced wherever the window is.
    let desk = Some(Box::new(Resident(handle)) as Box<dyn Desk>);
    let result = app.init(move || App { desk, ..init() }).try_run();
    drop(tray);
    if let Some(socket) = left {
        let _ = std::fs::remove_file(socket);
    }
    result
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use rune::{Env, Runtime};

    use super::*;

    /// Taller than the window opens, so what the tests press is on screen
    /// without scrolling.
    const TALL: (f32, f32) = (SIZE.0, 1400.0);
    use crate::daemon::FakeClient;
    use kagebunshin::ipc::client::ClientError;
    use kagebunshin::ipc::protocol::{ErrorCode, Request, Response, StatusReport, WireError};

    fn fixed(scene: fn(&mut App)) -> App {
        let mut s = App::blank();
        scene(&mut s);
        s
    }

    /// [`fixed`], with the request asked about showing its details.
    fn detailed(scene: fn(&mut App)) -> App {
        let mut s = fixed(scene);
        s.approval_details = true;
        s
    }

    fn runtime(s: App) -> Runtime<App> {
        let mut rt = Runtime::new(s, view, TALL, Env::new(true, 2.0));
        rt.frame(0.0);
        rt
    }

    fn texts(rt: &Runtime<App>) -> String {
        rt.elements()
            .into_iter()
            .filter_map(|e| e.text.or(e.label))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn click(rt: &mut Runtime<App>, key: &str) {
        let (x, y) = rt.find(key).unwrap_or_else(|| panic!("no {key}"));
        rt.pointer_down(x, y);
        rt.pointer_up(x, y);
        // Long enough for what comes and goes to settle, well short of the
        // next probe.
        rt.frame(0.5);
    }

    /// Polls a live window until `done`, for at most five seconds.
    fn until(rt: &mut Runtime<App>, done: impl Fn(&App) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !done(&rt.state) {
            assert!(Instant::now() < deadline, "no answer");
            rt.frame(1.0 / 60.0);
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn live(scene: fn(&mut App), fake: &FakeClient) -> Runtime<App> {
        live_on(scene, Box::new(fake.clone()))
    }

    fn live_on(scene: fn(&mut App), daemon: Box<dyn crate::daemon::DaemonClient>) -> Runtime<App> {
        let mut s = fixed(scene);
        let waker: Waker = Arc::new(|| {});
        s.worker = Some(Worker::spawn(daemon, waker).unwrap());
        let mut rt = Runtime::new(s, view, TALL, Env::new(true, 2.0));
        rt.poll = Some(poll);
        rt.frame(0.0);
        rt
    }

    fn up(locked: bool) -> Response {
        Response::Status(StatusReport {
            locked,
            env: None,
            expiring: Vec::new(),
            remote: None,
            waiting: Vec::new(),
            acknowledged: Vec::new(),
            shared: Vec::new(),
            app: false,
            phone: None,
            standing: Vec::new(),
        })
    }

    #[test]
    fn every_scene_renders_in_both_themes() {
        for (name, scene) in scenes::ALL {
            for dark in [false, true] {
                let mut rt = Runtime::new(fixed(*scene), view, TALL, Env::new(dark, 2.0));
                rt.frame(0.0);
                assert!(rt.find("kb-refresh").is_some(), "{name}");
            }
        }
    }

    /// What is left: the person's commands with their notes, one line with
    /// what to paste for the agent's (not its commands), what a source
    /// skipped, and for an environment with every key set, the proof.
    #[test]
    fn what_is_left_shows_the_persons_commands_and_the_proof() {
        let mut rt = runtime(fixed(scenes::left));
        let all = texts(&rt);
        for shown in [
            "Left to set up in dev",
            "kagebunshin store set widget.dev SENTRY_DSN",
            "It asks for the store passphrase, then each value.",
            PASTE_LINE,
            "Skipped, as not JSON objects: acme/dev/signing",
        ] {
            assert!(all.contains(shown), "{shown}: {all}");
        }
        assert!(!all.contains("add-source widget dev"), "{all}");
        assert!(rt.find("kb-proof-dev").is_none());
        // What is left is of the environment on show.
        click(&mut rt, "kb-env-prod");
        let all = texts(&rt);
        assert!(
            all.contains("prod: every key set; ./test.sh ran with them on"),
            "{all}"
        );
        assert!(rt.find("kb-left-prod").is_none());
        assert!(rt.find("kb-left-dev").is_none());

        // Nothing left and no run yet: a single quiet line.
        let mut s = fixed(scenes::left);
        if let Some(shown) = &mut s.machine.shown {
            shown.columns.swap(0, 1);
            if let Detail::Loaded(EnvReport::Resolved { proof, .. }) = &mut shown.columns[0].detail
            {
                *proof = None;
            }
            shown.columns.truncate(1);
        }
        let rt = runtime(s);
        assert!(texts(&rt).contains("prod: every key set, not yet proven by a run"));
        assert!(rt.find("kb-left-prod").is_none());

        // A key no source sets has no fix from the daemon, but `next`
        // tells the agent where to look: the paste line still shows.
        let mut s = fixed(scenes::left);
        if let Some(shown) = &mut s.machine.shown
            && let Detail::Loaded(EnvReport::Resolved { fixes, skipped, .. }) =
                &mut shown.columns[0].detail
        {
            fixes.clear();
            skipped.clear();
        }
        let rt = runtime(s);
        assert!(rt.find("kb-left-dev/kb-paste-dev").is_some());
    }

    /// An env file still in the checkout of a project a run has proved is
    /// the person's to delete; one in a project not yet proved is not.
    #[test]
    fn a_kept_env_file_is_left_for_the_person_once_proven() {
        let kept = |s: &mut App| {
            for c in s.machine.shown.iter_mut().flat_map(|sh| &mut sh.columns) {
                c.sel.facts.env_file = Some(".env".into());
            }
        };
        let rt = runtime(fixed(scenes::left));
        assert!(rt.find("kb-kept-env").is_none());

        let mut s = fixed(scenes::left);
        kept(&mut s);
        let rt = runtime(s);
        assert!(rt.find("kb-kept-env/kb-kept-env-rm").is_some());
        assert!(texts(&rt).contains("rm /src/widget/.env"));

        let mut s = fixed(scenes::left);
        kept(&mut s);
        if let Some(shown) = &mut s.machine.shown {
            shown.columns.truncate(1);
        }
        assert!(runtime(s).find("kb-kept-env").is_none());
    }

    /// A plain setting of the project file is not secret: its row shows
    /// the value it has in the environment, and opens nothing.
    #[test]
    fn a_plain_setting_shows_its_value() {
        let mut rt = runtime(fixed(scenes::left));
        assert!(rt.find("kb-key-LOG_LEVEL/kb-var-value").is_some());
        let all = texts(&rt);
        assert!(all.contains("\ndebug\n"), "{all}");
        // Once the row said only where it came from.
        assert!(!all.contains("\nproject file\n"), "{all}");
        click(&mut rt, "kb-key-LOG_LEVEL");
        assert_eq!(rt.state.view, View::Keys);

        click(&mut rt, "kb-env-prod");
        let all = texts(&rt);
        for shown in ["\ninfo\n", "\nhttps://widget.acme.example\n"] {
            assert!(all.contains(shown), "{shown}: {all}");
        }
        assert!(!all.contains("\ndebug\n"), "{all}");
    }

    /// With no project yet the window is the first screen and nothing
    /// else: the seal, the line for the agent, that the import is approved
    /// here, and the terminal's way; no project list and no tabs, and all
    /// of it inside the window, locked as well. Once there are projects,
    /// the list is back, with the machine's providers and audit log under
    /// it, and it asks for a project to be picked.
    #[test]
    fn with_no_project_the_window_says_how_to_start() {
        let locked = |s: &mut App| {
            scenes::empty(s);
            s.machine.conn = Conn::Up { locked: true };
        };
        for scene in [scenes::empty as fn(&mut App), locked] {
            // The window as it opens, not the tall one of the other tests.
            let mut rt = Runtime::new(fixed(scene), view, SIZE, Env::new(true, 2.0));
            rt.frame(0.0);
            assert!(rt.find("kb-first-steps/kb-first-onboard").is_some());
            assert!(rt.find("kb-first-steps/kb-first-paste").is_some());
            let all = texts(&rt);
            for shown in [
                "kagebunshin onboard DIR…",
                PASTE_LINE,
                "kagebunshin next DIR…",
                "Approve the import here",
            ] {
                assert!(all.contains(shown), "{shown}: {all}");
            }
            assert!(!all.contains("project init"), "{all}");
            for gone in ["kb-sidebar", "kb-tabs", "kb-pick", "kb-locked-screen"] {
                assert!(rt.find(gone).is_none(), "{gone}");
            }
            for key in ["kb-seal", "kb-lock", "kb-first-steps", "kb-first-onboard"] {
                let ([_, y, _, h], _) = rt.presented(key).unwrap();
                assert!(y >= 0.0 && y + h <= SIZE.1, "{key} at {y}, {h} high");
            }
        }

        let rt = runtime(fixed(|s| {
            scenes::empty(s);
            s.catalog = scenes::catalog();
        }));
        assert!(rt.find("kb-first-steps").is_none());
        for back in [
            "kb-sidebar/kb-projects",
            "kb-sidebar/kb-machine/kb-nav-providers",
            "kb-sidebar/kb-machine/kb-nav-activity",
            "kb-pick",
        ] {
            assert!(rt.find(back).is_some(), "{back}");
        }
        // The environments are a project's: none is on show.
        assert!(rt.find("kb-tabs").is_none());
    }

    /// A Proton key goes by the name a source selects it by, in the list
    /// and where a request for it waits; the ids that say which item it is
    /// are drawn nowhere. It loads with its source, not apart from it.
    #[test]
    fn a_proton_key_is_shown_by_name_never_by_its_ids() {
        for scene in [scenes::proton as fn(&mut App), scenes::approval_proton] {
            let all = texts(&runtime(detailed(scene)));
            assert!(all.contains("agents/MAIL_TOKEN"), "{all}");
            assert!(!all.contains("Qm9n") && !all.contains("aXRl"), "{all}");
        }
        let rt = runtime(fixed(scenes::proton));
        assert!(rt.find("kb-key-MAIL_TOKEN/kb-from").is_some());
        let all = texts(&rt);
        assert!(!all.contains("secrets of one key"), "{all}");
        let all = texts(&runtime(detailed(scenes::approval_proton)));
        assert!(
            all.contains("Secret proton:agents/MAIL_TOKEN is marked sensitive"),
            "{all}"
        );
    }

    /// A row per key of the environment on show: where each is set, never
    /// its value. The project opens on its default environment.
    #[test]
    fn the_keys_show_names_and_origins_never_values() {
        let rt = runtime(fixed(scenes::unlocked));
        assert!(rt.find("kb-key-API_KEY/kb-from").is_some());
        assert!(rt.find("kb-key-STRIPE_SECRET/kb-key-sensitive").is_some());
        assert!(
            rt.find("kb-key-SENTRY_DSN").is_some(),
            "missing keys get a row"
        );
        assert!(rt.find("kb-key-DATABASE_URL/kb-conflict").is_some());
        assert!(rt.find("kb-key-API_KEY/kb-conflict").is_none());
        let all = texts(&rt);
        assert!(all.contains("dev (default)"), "{all}");
        assert!(all.contains("acme/dev/api"), "{all}");
        assert!(all.contains("overrides 1"), "{all}");
        assert!(all.contains("○ missing"), "{all}");
        assert!(
            all.contains("⚠ dev: environment dev of project widget looks like production"),
            "{all}"
        );
        assert!(rt.find("kb-setup-banner").is_some());
        // Prod waits to be asked for, and none of its keys is listed.
        assert!(rt.find("kb-load-prod").is_none());
        assert!(!all.contains("acme/prod/api"), "{all}");
    }

    /// One environment's keys at a time: the switch says which, and what
    /// the others would otherwise hide. The whole of a key's row opens its
    /// page, and choosing another environment there goes back to the keys.
    #[test]
    fn the_environment_is_chosen_from_a_switch() {
        let mut rt = runtime(fixed(scenes::left));
        assert!(
            rt.find("kb-tabs/kb-envs/kb-env-dev/kb-env-missing")
                .is_some()
        );
        assert!(rt.find("kb-env-prod/kb-env-missing").is_none());
        assert!(rt.find("kb-key-SIGNING_KEY/kb-from").is_none());
        click(&mut rt, "kb-env-prod");
        assert_eq!(rt.state.env, Some("prod".parse().unwrap()));
        assert!(rt.find("kb-key-SIGNING_KEY/kb-from").is_some());
        assert!(texts(&rt).contains("acme/prod/signing"));

        // Anywhere along the row, not only on the key's name.
        let ([x, y, w, h], _) = rt.presented("kb-key-SIGNING_KEY").unwrap();
        let (x, y) = (x + w - 4.0, y + h / 2.0);
        rt.pointer_down(x, y);
        rt.pointer_up(x, y);
        rt.frame(0.5);
        assert_eq!(rt.state.view, View::Key("SIGNING_KEY".parse().unwrap()));
        assert!(texts(&rt).contains("widget / prod / SIGNING_KEY"));
        click(&mut rt, "kb-env-dev");
        assert_eq!(rt.state.view, View::Keys);
        assert_eq!(rt.state.env, Some("dev".parse().unwrap()));

        // Sources stay on show from one environment to the next.
        click(&mut rt, "kb-nav-sources");
        click(&mut rt, "kb-env-prod");
        assert_eq!(rt.state.view, View::Sources);
        assert!(texts(&rt).contains("acme/prod/"));

        // An environment that failed says so where it is chosen from.
        let rt = runtime(fixed(|s| {
            scenes::error(s);
            s.env = Some("prod".parse().unwrap());
        }));
        assert!(rt.find("kb-env-dev/kb-env-failed").is_some());
    }

    /// A secret's mark is lifted and set where the list says it is
    /// marked: on its group's header, or on the key's row in a group of
    /// several secrets. Unmarking lists the environment's marked secrets
    /// first, so more go with the same passphrase.
    #[test]
    fn a_secret_is_unmarked_and_marked_from_its_group() {
        let origin = |name: &str| Origin::new(Provider::AwsSm, name);
        let mut rt = runtime(fixed(scenes::marks));
        for marked in ["analytics", "errors", "mail"] {
            let group = format!("kb-secret-aws_sm:acme:dev:{marked}/kb-secret-sensitive");
            assert!(rt.find(&group).is_some(), "{marked}");
            let button = format!("kb-unmark-aws_sm:acme:dev:{marked}");
            assert!(rt.find(&button).is_some(), "{marked}");
        }
        assert!(rt.find("kb-unmark-aws_sm:acme:dev:maps").is_none());
        assert!(rt.find("kb-mark-aws_sm:acme:dev:errors").is_none());
        // The header says it, so its keys do not.
        assert!(rt.find("kb-key-sensitive").is_none());

        // The button is not the header: the group stays unfolded.
        click(&mut rt, "kb-unmark-aws_sm:acme:dev:errors");
        assert!(rt.state.flipped.is_empty());
        let ticked = |rt: &Runtime<App>| match &rt.state.machine.pending {
            Pending::Unmarks(unmarks) => unmarks.unmark.clone(),
            other => panic!("{other:?}"),
        };
        assert_eq!(ticked(&rt), [origin("acme/dev/errors")]);
        let all = texts(&rt);
        for listed in [
            "aws_sm:acme/dev/analytics",
            "aws_sm:acme/dev/errors",
            "aws_sm:acme/dev/mail",
            "also read by shop.qa",
            "Unmark 1 secret",
        ] {
            assert!(all.contains(listed), "{listed}: {all}");
        }
        assert!(!all.contains("aws_sm:acme/dev/maps"), "{all}");
        click(&mut rt, "kb-unmarks-2");
        assert_eq!(
            ticked(&rt),
            [origin("acme/dev/errors"), origin("acme/dev/mail")]
        );
        click(&mut rt, "kb-unmarks-yes");
        assert!(texts(&rt).contains("to unmark 2 secrets"));
        click(&mut rt, "kb-passphrase-no");

        // With none ticked there is nothing to ask the passphrase for.
        click(&mut rt, "kb-unmark-aws_sm:acme:dev:errors");
        click(&mut rt, "kb-unmarks-1");
        click(&mut rt, "kb-unmarks-yes");
        assert!(matches!(rt.state.machine.pending, Pending::Unmarks(_)));
        click(&mut rt, "kb-unmarks-no");
        assert_eq!(rt.state.machine.pending, Pending::None);

        click(&mut rt, "kb-mark-aws_sm:acme:dev:maps");
        assert_eq!(
            rt.state.machine.pending,
            Pending::Passphrase(Purpose::Mark {
                mark: Mark::Secret(origin("acme/dev/maps")),
                sensitive: true,
            })
        );
        assert!(texts(&rt).contains(
            "to mark secret aws_sm:acme/dev/maps sensitive, in every environment that reads it"
        ));

        // Secrets of one key each share a group: the marked one's row
        // says so, and has the button. A store key is marked on its page.
        let mut rt = runtime(fixed(scenes::unlocked));
        assert!(rt.find("kb-unmark-dev-0").is_none());
        assert!(rt.find("kb-mark-dev-0").is_none());
        assert!(rt.find("kb-mark-file:widget.dev").is_none());
        assert!(rt.find("kb-unmark-API_KEY").is_none());
        click(&mut rt, "kb-unmark-STRIPE_SECRET");
        assert_eq!(ticked(&rt), [origin("acme/dev/stripe")]);
        assert_eq!(rt.state.view, View::Keys, "the button is not the row");
        click(&mut rt, "kb-unmarks-no");
        // The flat list is a list: no buttons.
        click(&mut rt, "kb-flat");
        assert!(rt.find("kb-key-STRIPE_SECRET/kb-key-sensitive").is_some());
        assert!(rt.find("kb-unmark-STRIPE_SECRET").is_none());
    }

    /// The ticked secrets go to the daemon in one request, with the
    /// passphrase typed once.
    #[test]
    fn several_secrets_are_unmarked_with_one_passphrase() {
        let fake = FakeClient::default();
        fake.reply(Ok(up(false)));
        let mut rt = live(scenes::unmarks, &fake);
        click(&mut rt, "kb-unmarks-yes");
        rt.paste("pw");
        rt.frame(0.0);
        click(&mut rt, "kb-passphrase-ok");
        assert!(rt.state.passphrase.text.is_empty());
        until(&mut rt, |_| {
            fake.asked
                .lock()
                .unwrap()
                .iter()
                .any(|r| matches!(r, Request::UnmarkSecrets { .. }))
        });
        let asked = fake.asked.lock().unwrap();
        assert!(asked.iter().any(|r| matches!(
            r,
            Request::UnmarkSecrets { secrets, passphrase }
                if secrets.iter().map(ToString::to_string).collect::<Vec<_>>()
                    == ["aws_sm:acme/dev/errors", "aws_sm:acme/dev/mail"]
                    && passphrase.expose() == "pw"
        )));
    }

    /// Projects of one monorepo sit under its remote, each named by its
    /// folder; a project on its own keeps its name.
    #[test]
    fn the_sidebar_groups_a_monorepos_projects() {
        let rt = runtime(fixed(scenes::unlocked));
        let all = texts(&rt);
        assert!(
            rt.find("kb-sidebar/kb-projects/kb-group-1").is_some(),
            "{all}"
        );
        assert!(all.contains("github.com/acme/shop"), "{all}");
        let lines: Vec<&str> = all.lines().collect();
        assert!(lines.contains(&"whole repo"), "{all}");
        assert!(lines.contains(&"api"), "{all}");
        assert!(rt.find("kb-project-shop-api").is_some());
        assert!(rt.find("kb-sidebar/kb-projects/kb-group-0").is_none());
        assert!(all.contains("billing"), "{all}");
    }

    /// Keys are grouped by the secret that sets them, under its name; a
    /// group folds away, and the flat list and the filters narrow what
    /// shows.
    #[test]
    fn keys_group_by_secret_and_filter() {
        let mut rt = runtime(fixed(scenes::unlocked));
        // The prefix's secrets set one key each and share a group.
        assert!(rt.find("kb-secret-dev-0").is_some());
        assert!(rt.find("kb-secret-file:widget.dev").is_some());
        assert!(rt.find("kb-secret-missing").is_some());
        let all = texts(&rt);
        assert!(all.contains("acme/dev/, 2 keys"), "{all}");
        assert!(all.contains("aws_sm · 2 keys"), "{all}");
        // One of its two secrets is marked: the key says so, not the group.
        assert!(rt.find("kb-secret-dev-0/kb-secret-sensitive").is_none());
        assert!(rt.find("kb-fold-all").is_some());
        click(&mut rt, "kb-secret-dev-0");
        assert!(rt.find("kb-key-API_KEY").is_none());
        assert!(rt.find("kb-key-DATABASE_URL").is_some());
        click(&mut rt, "kb-secret-dev-0");
        assert!(rt.find("kb-key-API_KEY").is_some());

        click(&mut rt, "kb-fold-all");
        assert!(rt.find("kb-key-API_KEY").is_none());
        assert!(rt.find("kb-key-DATABASE_URL").is_none());
        assert!(texts(&rt).contains("Unfold all"));
        click(&mut rt, "kb-fold-all");
        assert!(rt.find("kb-key-DATABASE_URL").is_some());

        click(&mut rt, "kb-flat");
        assert!(rt.find("kb-secret-dev-0").is_none());
        assert!(rt.find("kb-fold-all").is_none());
        assert!(rt.find("kb-key-API_KEY").is_some());

        let only = |rt: &Runtime<App>| -> Vec<&str> {
            [
                "API_KEY",
                "DATABASE_URL",
                "STRIPE_SECRET",
                "DEBUG_TOKEN",
                "SENTRY_DSN",
            ]
            .into_iter()
            .filter(|k| rt.find(&format!("kb-key-{k}")).is_some())
            .collect()
        };
        assert!(rt.find("kb-narrowed").is_none());
        click(&mut rt, "kb-filter-conflicts");
        assert_eq!(only(&rt), ["DATABASE_URL"]);
        // The filter that is on says so, and how much it left.
        let all = texts(&rt);
        assert!(all.contains("1 of 5 keys"), "{all}");
        assert!(all.contains("Conflicts ×"), "{all}");
        assert!(!all.contains("Sensitive ×"), "{all}");
        click(&mut rt, "kb-filter-sensitive");
        assert_eq!(only(&rt), ["STRIPE_SECRET"]);
        click(&mut rt, "kb-filter-missing");
        assert_eq!(only(&rt), ["SENTRY_DSN"]);
        click(&mut rt, "kb-filter-extra");
        assert_eq!(only(&rt), ["DEBUG_TOKEN"]);
        click(&mut rt, "kb-filter-extra");
        assert_eq!(only(&rt).len(), 5);
        assert!(rt.find("kb-narrowed").is_none());
        // A search narrows as a filter does.
        rt.update(|s, _| s.search = TextEdit::new("stripe"));
        rt.frame(0.0);
        assert!(texts(&rt).contains("1 of 5 keys"));
    }

    /// A project of forty secrets opens as a list of them, folded, each
    /// under its own name, and nothing leaves the window: the row of every
    /// secret, the environments and the buttons stay in view.
    #[test]
    fn a_large_project_opens_folded_and_keeps_to_the_window() {
        let mut rt = runtime(fixed(scenes::many));
        let within = |rt: &Runtime<App>, key: &str| {
            let (r, _) = rt.presented(key).unwrap_or_else(|| panic!("no {key}"));
            assert!(r[0] >= 0.0 && r[0] + r[2] <= SIZE.0, "{key} at {r:?}");
        };
        for key in [
            "kb-main",
            "kb-grid",
            "kb-env-rc",
            "kb-fold-all",
            "kb-flat",
            "kb-secret-aws_sm:dev:app",
        ] {
            within(&rt, key);
        }
        let all = texts(&rt);
        assert!(all.contains("dev/app, 3 keys"), "{all}");
        assert!(!all.contains("dev/app, errors"), "{all}");
        assert!(all.contains("Unfold all"), "{all}");
        assert!(rt.find("kb-key-APP_API_KEY").is_none());
        // A marked secret says so while folded.
        assert!(
            rt.find("kb-secret-aws_sm:dev:payments/kb-secret-sensitive")
                .is_some()
        );
        assert!(
            rt.find("kb-secret-aws_sm:dev:app/kb-secret-sensitive")
                .is_none()
        );

        click(&mut rt, "kb-secret-aws_sm:dev:app");
        assert!(rt.find("kb-key-APP_API_KEY").is_some());
        assert!(rt.find("kb-key-ERRORS_API_KEY").is_none());
        within(&rt, "kb-key-APP_API_KEY");

        // A search shows what it found, unfolded.
        click(&mut rt, "kb-secret-aws_sm:dev:app");
        rt.update(|s, _| s.search.text = "errors".into());
        rt.frame(0.5);
        assert!(rt.find("kb-key-ERRORS_HOST").is_some());
        assert!(rt.find("kb-secret-aws_sm:dev:app").is_none());
        assert!(rt.find("kb-fold-all").is_none());
    }

    /// From 14 days before a saved token expires, a banner says so and
    /// how to replace it.
    #[test]
    fn an_expiring_token_shows_a_banner() {
        let rt = runtime(fixed(scenes::unlocked));
        assert!(rt.find("kb-expiry").is_none());

        let mut s = fixed(scenes::unlocked);
        s.machine.expiring = vec![kagebunshin::ipc::protocol::TokenExpiry {
            provider: Provider::Proton,
            expires: kagebunshin::source::unix_now() + 3 * 86_400 + 3_600,
        }];
        let rt = runtime(s);
        assert!(rt.find("kb-expiry").is_some());
        let all = texts(&rt);
        assert!(
            all.contains("⚠ The Proton Pass token expires in 3 days"),
            "{all}"
        );
        assert!(all.contains("`kagebunshin connect proton`"), "{all}");
    }

    #[test]
    fn search_filters_the_keys() {
        let mut s = fixed(scenes::unlocked);
        s.search = TextEdit::new("stripe");
        let rt = runtime(s);
        assert!(rt.find("kb-key-STRIPE_SECRET").is_some());
        assert!(rt.find("kb-key-API_KEY").is_none());

        let mut s = fixed(scenes::unlocked);
        s.search = TextEdit::new("nothing");
        let rt = runtime(s);
        assert!(rt.find("kb-no-match").is_some());
    }

    /// An environment that looks like production says so in place of its
    /// keys and loads them when asked; one marked sensitive takes the
    /// passphrase, and can be unmarked from there, listed or not.
    #[test]
    fn prod_loads_on_click_and_a_sensitive_one_takes_the_passphrase() {
        let mut rt = runtime(fixed(scenes::unlocked));
        click(&mut rt, "kb-env-prod");
        assert!(texts(&rt).contains("prod is not loaded"));
        assert!(rt.find("kb-grid").is_none());
        click(&mut rt, "kb-env-card/kb-load-prod");
        let shown = rt.state.machine.shown.as_ref().unwrap();
        let prod = shown.column(&"prod".parse().unwrap()).unwrap();
        assert!(matches!(prod.detail, Detail::Loading(_)));
        assert!(rt.find("kb-loading").is_some());

        let mut rt = runtime(fixed(scenes::sensitive));
        assert!(rt.find("kb-env-prod/kb-env-sensitive").is_some());
        assert!(texts(&rt).contains("prod is sensitive"));
        assert!(rt.find("kb-grid").is_none());
        click(&mut rt, "kb-load-prod");
        assert_eq!(
            rt.state.machine.pending,
            Pending::Passphrase(Purpose::Inspect("prod".parse().unwrap()))
        );
        assert!(texts(&rt).contains("to show environment prod"));
        click(&mut rt, "kb-passphrase-no");
        click(&mut rt, "kb-env-unmark");
        assert!(rt.find("kb-confirm").is_some());

        // Once listed, it still says it is sensitive, over its keys.
        let mut rt = runtime(fixed(scenes::sensitive_shown));
        assert!(rt.find("kb-env-card/kb-load-prod").is_none());
        assert!(rt.find("kb-env-card/kb-env-unmark").is_some());
        assert!(rt.find("kb-key-API_KEY").is_some());
        click(&mut rt, "kb-env-unmark");
        assert!(rt.find("kb-confirm").is_some());

        // One that failed says why, and is asked again.
        let mut rt = runtime(fixed(scenes::error));
        assert!(texts(&rt).contains("dev: aws_sm acme/dev/: the SSO session has expired"));
        click(&mut rt, "kb-load-dev");
        let shown = rt.state.machine.shown.as_ref().unwrap();
        assert!(matches!(shown.columns[0].detail, Detail::Loading(_)));
    }

    #[test]
    fn problems_show_their_hints() {
        let rt = runtime(fixed(scenes::down));
        assert!(rt.find("kb-conn-problem").is_some());
        assert!(texts(&rt).contains("hint: run `kagebunshin daemon install`"));

        let rt = runtime(fixed(scenes::error));
        assert!(rt.find("kb-problem-dev").is_some());
        assert!(texts(&rt).contains("hint: run `aws sso login --profile acme-dev`"));

        let rt = runtime(fixed(scenes::locked));
        assert!(rt.find("kb-locked-screen").is_some());
    }

    /// Locked, the keys give way to the passphrase and what locked means:
    /// no grid, search or filters, and the projects still listed. What is
    /// typed is masked, sent once and cleared; a wrong passphrase is said
    /// on the same screen, which then asks again.
    #[test]
    fn locked_shows_the_passphrase_instead_of_the_keys() {
        let wrong = || {
            Err(ClientError::Daemon(WireError::new(
                ErrorCode::WrongPassphrase,
                "wrong passphrase for the local store",
            )))
        };
        let fake = FakeClient::default();
        fake.reply(Ok(up(true)));
        let mut rt = live(scenes::locked, &fake);
        until(&mut rt, |_| !fake.asked.lock().unwrap().is_empty());
        let all = texts(&rt);
        assert!(
            all.contains("No agent or command gets a value until you unlock"),
            "{all}"
        );
        for gone in [
            "kb-grid",
            "kb-key-tools",
            "kb-lock",
            "kb-project-head",
            "kb-passphrase",
        ] {
            assert!(rt.find(gone).is_none(), "{gone}");
        }
        for kept in ["kb-project-billing", "kb-nav-sources", "kb-nav-activity"] {
            assert!(rt.find(kept).is_some(), "{kept}");
        }
        assert!(rt.state.passphrase.focused);

        fake.reply(wrong());
        rt.paste("correct horse");
        rt.frame(0.0);
        assert!(!texts(&rt).contains("horse"));
        click(&mut rt, "kb-unlock");
        assert!(rt.state.passphrase.text.is_empty());
        assert!(texts(&rt).contains("Unlocking"), "{}", texts(&rt));
        click(&mut rt, "kb-unlock");
        until(&mut rt, |s| s.machine.pending == Pending::None);
        rt.frame(0.0);
        let unlocks = || {
            let asked = fake.asked.lock().unwrap();
            asked
                .iter()
                .filter_map(|r| match r {
                    Request::Unlock { passphrase } => {
                        Some(passphrase.as_ref().map(|p| p.expose().to_owned()))
                    }
                    _ => None,
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(unlocks(), [Some("correct horse".to_owned())], "sent once");
        assert!(rt.find("kb-notice-problem").is_some());
        assert!(rt.find("kb-locked-screen").is_some());
        assert!(rt.state.passphrase.focused);

        fake.reply(Ok(Response::LockState {
            locked: false,
            warnings: Vec::new(),
        }));
        rt.paste("right");
        rt.frame(0.0);
        click(&mut rt, "kb-unlock");
        until(&mut rt, |s| s.machine.conn == Conn::Up { locked: false });
        rt.frame(0.0);
        assert_eq!(unlocks().len(), 2);
        assert!(rt.find("kb-locked-screen").is_none());
        assert!(rt.find("kb-lock").is_some());
        assert!(rt.state.passphrase.text.is_empty());
    }

    /// With nothing typed the daemon is asked to unlock without a
    /// passphrase, enough where there is no local store; if it needs one,
    /// the locked screen says so and takes it, with no prompt over it.
    #[test]
    fn unlocking_with_nothing_typed_asks_whether_a_passphrase_is_needed() {
        let fake = FakeClient::default();
        fake.reply(Ok(up(true)))
            .reply(Err(ClientError::Daemon(WireError::new(
                ErrorCode::PassphraseRequired,
                "the store is locked",
            ))))
            .reply(Ok(Response::LockState {
                locked: false,
                warnings: Vec::new(),
            }));
        let mut rt = live(scenes::locked, &fake);
        until(&mut rt, |_| !fake.asked.lock().unwrap().is_empty());
        click(&mut rt, "kb-unlock");
        until(&mut rt, |s| {
            s.machine.pending == Pending::Passphrase(Purpose::Unlock)
        });
        rt.frame(0.0);
        assert!(rt.find("kb-unlock-needed").is_some());
        assert!(rt.find("kb-passphrase").is_none());
        assert!(rt.state.passphrase.focused);
        rt.paste("pw");
        rt.frame(0.0);
        click(&mut rt, "kb-unlock");
        until(&mut rt, |s| s.machine.conn == Conn::Up { locked: false });
        let asked = fake.asked.lock().unwrap();
        let sent: Vec<_> = asked
            .iter()
            .filter_map(|r| match r {
                Request::Unlock { passphrase } => Some(passphrase.is_some()),
                _ => None,
            })
            .collect();
        assert_eq!(sent, [false, true]);
    }

    /// Sources, Providers and Activity need no values, so they stay while
    /// locked, with Unlock in the header asking in a prompt; Keys is the
    /// locked screen again.
    #[test]
    fn what_needs_no_values_stays_while_locked() {
        let mut rt = runtime(fixed(scenes::locked));
        click(&mut rt, "kb-nav-sources");
        assert!(rt.find("kb-locked-screen").is_none());
        assert!(rt.find("kb-sources").is_some());
        assert!(!rt.state.passphrase.focused);
        click(&mut rt, "kb-nav-activity");
        assert!(rt.find("kb-activity").is_some());
        assert!(rt.find("kb-lock").is_some());
        rt.update(|s, _| s.machine.pending = Pending::Passphrase(Purpose::Unlock));
        rt.frame(0.5);
        assert!(rt.find("kb-passphrase").is_some());
        click(&mut rt, "kb-passphrase-no");
        // Back to the project: its keys are the locked screen again.
        click(&mut rt, "kb-project-widget");
        assert!(rt.find("kb-locked-screen").is_some());
        assert!(rt.state.passphrase.focused);

        // An install with no project yet keeps its first screen.
        let mut s = fixed(scenes::empty);
        s.machine.conn = Conn::Up { locked: true };
        let rt = runtime(s);
        assert!(rt.find("kb-locked-screen").is_none());
        assert!(rt.find("kb-lock").is_some());
    }

    /// A live window on the fake daemon: probes on the first frame, and asks
    /// about a project's environments when it is picked, with the example
    /// only for the checkout it was opened in.
    #[test]
    fn picking_a_project_asks_the_daemon_about_it() {
        let fake = FakeClient::default();
        fake.reply(Ok(up(true))).reply(Ok(up(true)));
        let mut rt = live(
            |s| {
                scenes::empty(s);
                s.catalog = scenes::catalog();
            },
            &fake,
        );
        click(&mut rt, "kb-project-billing");
        until(&mut rt, |s| {
            s.machine.shown.as_ref().is_some_and(|sh| {
                sh.columns
                    .iter()
                    .any(|c| matches!(c.detail, Detail::Loaded(_)))
            })
        });
        assert!(rt.find("kb-locked-screen").is_some());
        let asked = std::mem::take(&mut *fake.asked.lock().unwrap());
        let envs: Vec<_> = asked
            .iter()
            .filter_map(|r| match r {
                Request::Status { facts: Some(f) } => Some(f.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(envs.len(), 1, "{asked:?}");
        assert_eq!(
            envs[0].remotes,
            vec!["github.com/acme/billing".parse().unwrap()]
        );
        assert_eq!(
            envs[0].example_keys, None,
            "billing isn't the checkout here"
        );
    }

    /// The value shows in the key view once the passphrase is typed, and is
    /// gone once hidden or once the view is left.
    #[test]
    fn a_revealed_value_shows_only_until_it_is_hidden() {
        let value = "postgres://dev.example/widget";
        let fake = FakeClient::default();
        let revealed = || {
            Ok(Response::Value {
                value: WireSecret::new(value.into()),
            })
        };
        fake.reply(Ok(up(false)))
            .reply(revealed())
            .reply(revealed());
        let mut rt = live(scenes::key, &fake);
        assert!(rt.find("kb-masked").is_some());
        for leave in ["kb-hide", "kb-back"] {
            click(&mut rt, "kb-reveal");
            assert!(texts(&rt).contains("to reveal DATABASE_URL of dev"));
            rt.paste("pw");
            rt.frame(0.0);
            click(&mut rt, "kb-passphrase-ok");
            until(&mut rt, |s| s.machine.revealed.is_some());
            rt.frame(0.0);
            assert!(rt.find("kb-value").is_some());
            assert!(texts(&rt).contains(value));
            click(&mut rt, leave);
            // Past any exit transition, which would still draw it.
            rt.frame(0.5);
            assert_eq!(rt.state.machine.revealed, None);
            assert!(!texts(&rt).contains(value), "{leave}");
            if leave == "kb-back" {
                assert!(rt.find("kb-grid").is_some());
            }
        }
        let asked = fake.asked.lock().unwrap();
        let reveals = asked
            .iter()
            .filter(
                |r| matches!(r, Request::Reveal { passphrase, .. } if passphrase.expose() == "pw"),
            )
            .count();
        assert_eq!(reveals, 2, "{asked:?}");
    }

    /// The Proton Pass token never shows, goes to the daemon once with the
    /// passphrase, and is cleared from the form as it goes.
    #[test]
    fn a_proton_token_is_masked_and_cleared_once_sent() {
        let canary = kagebunshin::test_support::Canary::new();
        let fake = FakeClient::default();
        fake.reply(Ok(up(false)))
            .reply(Ok(Response::ProtonConnected {
                change: kagebunshin::store::Change::Replaced,
                locked: false,
                vaults: 2,
            }));
        let mut rt = live(scenes::providers, &fake);
        click(&mut rt, "kb-proton-open");
        click(&mut rt, "kb-proton-token");
        rt.paste(canary.value());
        rt.frame(0.0);
        assert_eq!(rt.state.proton.token.text, canary.value());
        kagebunshin::test_support::assert_no_canary(&canary, &texts(&rt));
        click(&mut rt, "kb-proton-expires");
        rt.paste("2026-12-31");
        click(&mut rt, "kb-proton-connect");
        assert!(texts(&rt).contains("to save the Proton Pass token"));
        rt.paste("pw");
        rt.frame(0.0);
        click(&mut rt, "kb-passphrase-ok");
        assert!(rt.state.proton.token.text.is_empty());
        assert!(!rt.state.proton.open);
        until(
            &mut rt,
            |s| matches!(&s.machine.notice, Some(Notice::Done { message, .. }) if message.contains("2 vaults")),
        );
        kagebunshin::test_support::assert_no_canary(&canary, &texts(&rt));
        let asked = fake.asked.lock().unwrap();
        let sent: Vec<_> = asked
            .iter()
            .filter_map(|r| match r {
                Request::ProtonConnect {
                    token,
                    expires,
                    passphrase,
                } => Some((
                    token.expose() == canary.value(),
                    *expires,
                    passphrase.expose(),
                )),
                _ => None,
            })
            .collect();
        let expires = kagebunshin::source::proton::parse_date("2026-12-31");
        assert_eq!(sent, [(true, expires, "pw")]);
    }

    /// A warning that an environment looks like production offers to
    /// acknowledge it is not, which takes the passphrase.
    #[test]
    fn acknowledging_an_environment_sends_the_passphrase() {
        let fake = FakeClient::default();
        fake.reply(Ok(up(false)));
        let mut rt = live(
            |s| {
                scenes::sources(s);
                let shown = s.machine.shown.as_mut().unwrap();
                shown.columns[0].detail = Detail::Loaded(EnvReport::Resolved {
                    keys: Vec::new(),
                    missing: None,
                    vars: Vec::new(),
                    warnings: vec![format!(
                        "environment dev looks like production; {ACKNOWLEDGE_HINT}"
                    )],
                    acknowledged: false,
                    skipped: Vec::new(),
                    fixes: Vec::new(),
                    proof: None,
                });
            },
            &fake,
        );
        assert!(rt.find("kb-unacknowledged").is_some());
        click(&mut rt, "kb-acknowledge-dev");
        assert!(texts(&rt).contains("as not production"));
        rt.paste("pw");
        rt.frame(0.0);
        click(&mut rt, "kb-passphrase-ok");
        until(&mut rt, |_| {
            fake.asked
                .lock()
                .unwrap()
                .iter()
                .any(|r| matches!(r, Request::AcknowledgeEnv { .. }))
        });
        let asked = fake.asked.lock().unwrap();
        assert!(asked.iter().any(|r| matches!(
            r,
            Request::AcknowledgeEnv { project, env, acknowledged: true, passphrase, .. }
                if project.as_str() == "widget" && env.as_str() == "dev" && passphrase.expose() == "pw"
        )));
    }

    /// Every environment waiting for a decision is listed once, from any
    /// project, with its two choices; all can be acknowledged under one
    /// passphrase.
    #[test]
    fn waiting_environments_are_decided_from_one_list() {
        let mut rt = runtime(fixed(scenes::waiting));
        // widget/dev is in the list, so its warning is not repeated.
        assert!(rt.find("kb-setup-banner").is_none());
        click(&mut rt, "kb-waiting-mark-gadget-rc");
        assert_eq!(
            rt.state.machine.pending,
            Pending::Passphrase(Purpose::Mark {
                mark: Mark::Env {
                    project: "gadget".parse().unwrap(),
                    env: "rc".parse().unwrap(),
                    also: Vec::new(),
                },
                sensitive: true,
            })
        );
        click(&mut rt, "kb-passphrase-no");
        click(&mut rt, "kb-waiting-ack-widget-prod");
        assert!(matches!(
            &rt.state.machine.pending,
            Pending::Passphrase(Purpose::Acknowledge { project, env, acknowledged: true, .. })
                if project.as_str() == "widget" && env.as_str() == "prod"
        ));
        click(&mut rt, "kb-passphrase-no");

        // What the list shows is not repeated in the project's banner.
        let mut s = fixed(scenes::waiting);
        if let Some(shown) = &mut s.machine.shown {
            shown.columns[1].detail = Detail::Loaded(EnvReport::Resolved {
                keys: Vec::new(),
                missing: None,
                vars: Vec::new(),
                warnings: vec![format!("environment prod waits; {ACKNOWLEDGE_HINT}")],
                acknowledged: false,
                skipped: Vec::new(),
                fixes: Vec::new(),
                proof: None,
            });
        }
        assert!(!texts(&runtime(s)).contains("environment prod waits"));

        // One speaks of it in the singular, with no button for all.
        let mut s = fixed(scenes::waiting);
        s.machine.waiting.truncate(1);
        let rt = runtime(s);
        let all = texts(&rt);
        assert!(
            all.contains("1 environment waits for your decision"),
            "{all}"
        );
        assert!(all.contains("It looks like production"), "{all}");
        assert!(!all.contains("They look"), "{all}");
        assert!(rt.find("kb-waiting-all").is_none());

        let fake = FakeClient::default();
        fake.reply(Ok(up(false)));
        let mut rt = live(scenes::waiting, &fake);
        click(&mut rt, "kb-waiting-all");
        assert!(texts(&rt).contains("to acknowledge 4 environments as not production"));
        rt.paste("pw");
        rt.frame(0.0);
        click(&mut rt, "kb-passphrase-ok");
        until(&mut rt, |_| {
            fake.asked
                .lock()
                .unwrap()
                .iter()
                .any(|r| matches!(r, Request::AcknowledgeEnvs { .. }))
        });
        let asked = fake.asked.lock().unwrap();
        assert!(asked.iter().any(|r| matches!(
            r,
            Request::AcknowledgeEnvs { envs, passphrase }
                if envs.iter().map(ToString::to_string).collect::<Vec<_>>()
                    == ["billing.production", "gadget.rc", "widget.dev", "widget.prod"]
                    && passphrase.expose() == "pw"
        )));
    }

    #[test]
    fn the_passphrase_is_masked_and_cleared_once_sent() {
        let mut rt = runtime(fixed(scenes::passphrase));
        rt.paste("correct horse battery");
        rt.frame(0.0);
        assert_eq!(rt.state.passphrase.text, "correct horse battery");
        assert!(!texts(&rt).contains("horse"));
        click(&mut rt, "kb-passphrase-ok");
        assert!(rt.state.passphrase.text.is_empty());
        assert_eq!(rt.state.machine.pending, Pending::None);
        assert!(rt.find("kb-passphrase").is_none());
    }

    /// The dialog shows what is asked for and by whom; the passphrase is
    /// masked and sent once, a wrong one keeps the dialog up saying so,
    /// and denying sends none.
    #[test]
    fn an_approval_shows_the_request_and_sends_the_passphrase_once() {
        let (approver, sent, feed) = crate::daemon::Approver::fake();
        let mut s = fixed(scenes::approval);
        s.approver = Some(approver);
        let mut rt = runtime(s);
        rt.poll = Some(poll);
        // What a person answers from: who asks, the question, the command
        // and what it gets, in one line.
        let all = texts(&rt);
        for shown in [
            "Claude Code in /src/widget",
            "Hand sensitive values of widget/dev to this command?",
            "npm run deploy -- --dry-run",
            "1 key marked sensitive: STRIPE_SECRET",
            "denied in 4:32",
        ] {
            assert!(all.contains(shown), "{shown}: {all}");
        }
        let behind = [
            "Wants 1 value marked sensitive",
            "acme/shared/stripe is marked sensitive wherever it is read. widget/dev itself is \
             not marked.",
            "Asked by (names as the processes give them)",
            "kitty \u{203a} zsh \u{203a} claude \u{203a} zsh \u{00b7} pid 4242",
            "Approving trusts this command",
        ];
        for hidden in behind {
            assert!(!all.contains(hidden), "{hidden}: {all}");
        }
        // With no passphrase typed there is nothing to approve with.
        click(&mut rt, "kb-approval-ok");
        assert!(sent.try_recv().is_err());
        assert!(!rt.state.answering);
        // The rest is a click away, and goes again with another. Looking
        // leaves what is typed next going to the passphrase.
        click(&mut rt, "kb-approval-toggle");
        let all = texts(&rt);
        for shown in behind {
            assert!(all.contains(shown), "{shown}: {all}");
        }
        click(&mut rt, "kb-approval-toggle");
        assert!(!texts(&rt).contains("Approving trusts this command"));
        assert!(rt.state.approval_passphrase.focused);
        rt.paste("correct horse");
        rt.frame(0.0);
        assert!(!texts(&rt).contains("horse"));
        click(&mut rt, "kb-approval-ok");
        assert!(rt.state.approval_passphrase.text.is_empty());
        let sent_one = sent.try_recv().unwrap();
        assert_eq!(
            (sent_one.id, sent_one.passphrase.unwrap().expose()),
            (1, "correct horse")
        );
        assert!(sent_one.values.is_empty());
        click(&mut rt, "kb-approval-ok");
        assert!(sent.try_recv().is_err(), "sent once");

        feed.send(crate::daemon::Approval::Answered(Err(Problem::new(
            "wrong passphrase",
        ))))
        .unwrap();
        rt.frame(0.1);
        assert!(rt.find("kb-approval-error").is_some());
        assert!(rt.find("kb-approval").is_some());

        click(&mut rt, "kb-approval-deny");
        let denied = sent.try_recv().unwrap();
        assert_eq!((denied.id, denied.passphrase.is_none()), (1, true));
        feed.send(crate::daemon::Approval::Answered(Ok(Vec::new())))
            .unwrap();
        rt.frame(0.1);
        assert!(rt.find("kb-approval").is_none());
        assert!(!rt.state.answering);
    }

    /// A request a coding agent stands behind has a second button, which
    /// approves it and leaves the approval standing; Enter and Approve
    /// approve once, as ever. A request nobody stands behind has none.
    #[test]
    fn an_approval_is_left_standing_from_its_own_button() {
        let (approver, sent, _feed) = crate::daemon::Approver::fake();
        let mut s = fixed(scenes::approval);
        s.approver = Some(approver);
        let mut rt = runtime(s);
        rt.poll = Some(poll);
        assert!(texts(&rt).contains("For 15 min"));
        // What it does is with the rest, a click away.
        assert!(!texts(&rt).contains("without asking"));
        click(&mut rt, "kb-approval-toggle");
        let all = texts(&rt);
        let says = "what Claude Code runs gets these values of widget/dev without asking";
        assert!(all.contains(says), "{all}");

        // Nothing without the passphrase.
        click(&mut rt, "kb-approval-standing");
        assert!(sent.try_recv().is_err());
        click(&mut rt, "kb-approval-field");
        rt.paste("correct horse");
        rt.frame(0.0);
        click(&mut rt, "kb-approval-standing");
        let answer = sent.try_recv().unwrap();
        assert_eq!(
            (
                answer.id,
                answer.passphrase.unwrap().expose(),
                answer.standing
            ),
            (1, "correct horse", true)
        );

        // Approve, and Enter, approve the one request.
        let (approver, sent, _feed) = crate::daemon::Approver::fake();
        let mut s = fixed(scenes::approval);
        s.approver = Some(approver);
        let mut rt = runtime(s);
        rt.paste("correct horse");
        rt.frame(0.0);
        click(&mut rt, "kb-approval-ok");
        assert!(!sent.try_recv().unwrap().standing);

        let rt = runtime(fixed(scenes::approval_waiting));
        assert!(rt.find("kb-approval-standing").is_none());
        assert!(!texts(&rt).contains("For 15 min"));
    }

    /// What stands is listed above everything, with who it is for and the
    /// time left, and ended from there with no passphrase.
    #[test]
    fn what_stands_is_listed_and_ended() {
        let rt = runtime(fixed(scenes::unlocked));
        assert!(rt.find("kb-standing").is_none());

        // The daemon says what stands with each probe.
        let mut probed = fixed(scenes::standing);
        let Response::Status(mut report) = up(false) else {
            unreachable!()
        };
        report.standing = std::mem::take(&mut probed.machine.standing);
        let fake = FakeClient::default();
        fake.reply(Ok(Response::Status(report)))
            .reply(Ok(Response::StandingEnded { ended: 1 }))
            .reply(Ok(up(false)));
        let mut rt = live(scenes::unlocked, &fake);
        until(&mut rt, |s| !s.machine.standing.is_empty());
        rt.frame(0.1);
        let all = texts(&rt);
        let says = "Claude Code gets widget/prod without asking, for 12 min more";
        assert!(all.contains(says), "{all}");
        click(&mut rt, "kb-standing-end-0");
        assert!(rt.state.machine.standing.is_empty());
        assert!(rt.find("kb-standing").is_none());
        until(&mut rt, |_| fake.asked.lock().unwrap().len() >= 3);
        let asked = fake.asked.lock().unwrap();
        assert_eq!(
            asked[1],
            Request::EndStanding {
                project: "widget".parse().unwrap(),
                env: "prod".parse().unwrap(),
            }
        );
        assert_eq!(asked[2], Request::Status { facts: None });
    }

    /// A desktop that records what it is asked to do.
    #[derive(Clone, Default)]
    struct FakeDesk {
        did: std::rc::Rc<std::cell::RefCell<Vec<String>>>,
    }

    impl FakeDesk {
        fn took(&self) -> Vec<String> {
            std::mem::take(&mut self.did.borrow_mut())
        }
    }

    impl Desk for FakeDesk {
        fn notify(&self, prompt: &ApprovalPrompt) {
            self.did
                .borrow_mut()
                .push(format!("notify {}/{}", prompt.project, prompt.env));
        }

        fn at_once(&self, _: fn(&mut App, &mut Tx) -> bool) -> Waker {
            Arc::new(|| {})
        }
    }

    /// The app in the tray, with the daemon's requests
    /// fed by hand.
    fn in_tray() -> (
        Runtime<App>,
        FakeDesk,
        std::sync::mpsc::Receiver<crate::daemon::ApprovalAnswer>,
        std::sync::mpsc::Sender<crate::daemon::Approval>,
    ) {
        let (approver, sent, feed) = crate::daemon::Approver::fake();
        let desk = FakeDesk::default();
        let mut s = fixed(scenes::unlocked);
        s.approver = Some(approver);
        s.desk = Some(Box::new(desk.clone()));
        let mut rt = runtime(s);
        rt.poll = Some(poll);
        (rt, desk, sent, feed)
    }

    fn prompts(ids: &[u64]) -> Vec<ApprovalPrompt> {
        let mut s = App::blank();
        scenes::approval(&mut s);
        ids.iter()
            .map(|&id| ApprovalPrompt {
                id,
                ..s.approvals[0].clone()
            })
            .collect()
    }

    /// Each request is announced as its turn comes, and only then; the
    /// window is asked for nothing.
    #[test]
    fn each_request_is_announced_as_its_turn_comes() {
        use crate::daemon::Approval;
        let (mut rt, desk, sent, feed) = in_tray();
        feed.send(Approval::Waiting(prompts(&[1]))).unwrap();
        rt.frame(0.1);
        assert_eq!(desk.took(), ["notify widget/dev"]);
        assert!(rt.find("kb-approval").is_some());

        // A second one waits its turn: nothing new until the first is done.
        feed.send(Approval::Waiting(prompts(&[1, 2]))).unwrap();
        rt.frame(0.2);
        assert_eq!(desk.took(), Vec::<String>::new());

        click(&mut rt, "kb-approval-deny");
        assert_eq!(sent.try_recv().unwrap().id, 1);
        feed.send(Approval::Answered(Ok(prompts(&[2])))).unwrap();
        rt.frame(1.0);
        assert_eq!(desk.took(), ["notify widget/dev"]);

        click(&mut rt, "kb-approval-deny");
        assert_eq!(sent.try_recv().unwrap().id, 2);
        feed.send(Approval::Answered(Ok(Vec::new()))).unwrap();
        rt.frame(2.0);
        assert_eq!(desk.took(), Vec::<String>::new());
    }

    /// A window open on another workspace is drawn no frame: its request
    /// is taken in and announced without one, and once only.
    #[test]
    fn a_request_is_announced_before_any_frame() {
        use crate::daemon::Approval;
        let (mut rt, desk, _sent, feed) = in_tray();
        feed.send(Approval::Waiting(prompts(&[1]))).unwrap();
        assert!(rt.update_if(hear));
        assert_eq!(desk.took(), ["notify widget/dev"]);
        rt.frame(0.1);
        assert_eq!(desk.took(), Vec::<String>::new());
        assert!(rt.find("kb-approval").is_some());
    }

    /// Closing the window denies the request it asked about and forgets
    /// what was typed and revealed; the app stays for the next request.
    #[test]
    fn closing_the_window_denies_the_request_and_forgets_what_it_held() {
        use crate::daemon::Approval;
        let (mut rt, desk, sent, feed) = in_tray();
        feed.send(Approval::Waiting(prompts(&[7]))).unwrap();
        rt.frame(0.1);
        desk.took();
        rt.paste("correct horse");
        rt.frame(0.2);
        rt.state.machine.revealed = Some(crate::machine::Revealed {
            env: "dev".parse().unwrap(),
            key: "DATABASE_URL".parse().unwrap(),
            value: WireSecret::new("postgres://dev.example/widget".into()),
        });
        rt.state.passphrase.text = "half typed".into();
        rt.state.proton.token.text = "token".into();
        assert!(rt.state.machine.revealed.is_some());

        rt.update(on_close);
        let denied = sent.try_recv().unwrap();
        assert_eq!((denied.id, denied.passphrase.is_none()), (7, true));
        assert_eq!(rt.state.machine.revealed, None);
        assert!(rt.state.approval_passphrase.text.is_empty());
        assert!(rt.state.passphrase.text.is_empty());
        assert!(rt.state.proton.token.text.is_empty());

        // The next request is announced like any other.
        feed.send(Approval::Answered(Ok(prompts(&[8])))).unwrap();
        rt.frame(1.0);
        assert_eq!(desk.took(), ["notify widget/dev"]);
    }

    /// A request for an environment as a whole says why it waits, and that
    /// the keys are what the command asks for, not keys marked sensitive;
    /// one that waits for a decision says where that decision is made.
    #[test]
    fn an_approval_for_a_whole_environment_says_why() {
        let all = texts(&runtime(detailed(scenes::approval_waiting)));
        for shown in [
            "Hand widget/prod to this command?",
            "2 keys: DATABASE_URL, STRIPE_KEY",
            "Wants every value widget/prod sets. It expects these 2 keys",
            "DATABASE_URL",
            "STRIPE_KEY",
            "widget/prod looks like production (source aws_sm secret acme/prod/db reads \
             acme/prod/db, which has the segment prod) and nobody has decided whether it is",
            "Approving does not decide that: do it afterwards on the Projects page",
            "OpenCode in /src/widget",
            "denied in 0:24",
        ] {
            assert!(all.contains(shown), "{shown}: {all}");
        }
        assert!(!all.contains("marked sensitive"), "{all}");

        let mut s = detailed(scenes::approval_waiting);
        s.approvals[0].reason = ApprovalReason::Marked;
        let all = texts(&runtime(s));
        assert!(all.contains("Hand widget/prod to this command?"), "{all}");
        assert!(
            all.contains("widget/prod is marked sensitive: every value it sets"),
            "{all}"
        );
        assert!(!all.contains("Approving does not decide"), "{all}");
    }

    /// A script handed to a shell is the command a person reads, with the
    /// shell named beside it.
    #[test]
    fn a_script_handed_to_a_shell_is_shown_as_the_command() {
        let rt = runtime(fixed(scenes::approval_script));
        let all = texts(&rt);
        assert!(all.contains("Script, run by bash -lc"), "{all}");
        let line = rt
            .elements()
            .into_iter()
            .find(|e| e.key.as_deref() == Some("kb-approval-command-line"))
            .and_then(|e| e.text)
            .unwrap();
        assert!(line.starts_with("set -euo pipefail; export"), "{line}");
        assert!(line.ends_with("status=done"), "{line}");
    }

    /// The colours of a command follow its words: what runs, options and
    /// quoted words; a line that ends mid-quote or mid-escape, or holds
    /// other than ASCII, is coloured as far as it goes.
    #[test]
    fn a_command_is_coloured_by_its_words() {
        let p = Paint {
            t: tok::theme(true),
            hair: 0.5,
            info: tok::accent(0, true),
            good: tok::accent(4, true),
            warn: tok::accent(3, true),
            sensitive: tok::accent(2, true),
        };
        let coloured = |line: &str| {
            command_spans(p, line)
                .into_iter()
                .map(|s| line[s.start as usize..s.end as usize].to_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            coloured("NODE_ENV=production npx prisma --schema \"a b\" | tee out.log; ls"),
            ["npx", "--schema", "\"a b\"", "|", "tee", ";", "ls"]
        );
        let line = "run --flag";
        let spans = command_spans(p, line);
        assert_eq!(spans[0].weight, Span::new(0, 3).bold().weight);
        assert_eq!(spans[1].color, Some(p.info));
        for odd in [
            "echo \"unfinished",
            "echo \\",
            "caf\u{e9} \\\u{e9}",
            "\u{1f512} 'x",
        ] {
            coloured(odd);
        }
    }

    /// The notification names the program, the project and the
    /// environment, and none of the arguments.
    #[test]
    fn a_notification_names_the_program_not_its_arguments() {
        let mut prompt = prompts(&[1]).remove(0);
        prompt.argv = ["/usr/bin/psql", "postgres://admin:hunter2@db.example/prod"]
            .map(Into::into)
            .into();
        assert_eq!(
            notice(&prompt),
            "`psql` asks for sensitive values of widget/dev. Approve or deny it in the window."
        );
        prompt.argv.clear();
        assert!(notice(&prompt).starts_with("A command asks for"));
    }

    /// The time left is counted down from when the request came, and a new
    /// request starts from its own.
    #[test]
    fn the_time_left_counts_down() {
        use crate::daemon::Approval;
        let (mut rt, _desk, _sent, feed) = in_tray();
        feed.send(Approval::Waiting(prompts(&[1]))).unwrap();
        rt.frame(0.1);
        assert!(texts(&rt).contains("denied in 4:32"), "{}", texts(&rt));
        for _ in 0..5 {
            rt.frame(0.5);
        }
        assert!(texts(&rt).contains("denied in 4:30"), "{}", texts(&rt));
        for _ in 0..600 {
            rt.frame(0.5);
        }
        assert!(texts(&rt).contains("denied in 0:00"), "{}", texts(&rt));

        let mut next = prompts(&[2]);
        next[0].left = Some(60);
        feed.send(Approval::Answered(Ok(next))).unwrap();
        rt.frame(0.1);
        assert!(texts(&rt).contains("denied in 1:00"), "{}", texts(&rt));
    }

    /// From a checkout with no .env.example the request is for every key,
    /// and says so: how many where the daemon knows them.
    #[test]
    fn an_approval_with_no_example_says_it_is_for_every_key() {
        let all = texts(&runtime(detailed(scenes::approval_every_key)));
        for shown in [
            "All 13 keys widget/prod sets: ",
            "Wants all 13 keys widget/prod sets: no .env.example here lists the ones it needs",
            "ANALYTICS_ID",
            "1 more",
        ] {
            assert!(all.contains(shown), "{shown}: {all}");
        }
        assert!(!all.contains("It expects"), "{all}");

        let all = texts(&runtime(detailed(scenes::approval_every_key_unread)));
        for shown in [
            "Every key widget/prod sets",
            "Wants every key widget/prod sets: no .env.example here lists the ones it needs",
        ] {
            assert!(all.contains(shown), "{shown}: {all}");
        }
    }

    /// Many keys are listed a few at first; with all of them listed the
    /// dialog still fits the window, its buttons in reach.
    #[test]
    fn many_keys_fold_and_the_dialog_stays_in_the_window() {
        // Closed, a long list is two names and a count.
        let all = texts(&runtime(fixed(scenes::approval_many)));
        let summed = "40 keys: SERVICE_1_API_TOKEN, SERVICE_2_API_TOKEN and 38 more";
        assert!(all.contains(summed), "{all}");
        assert!(!all.contains("SERVICE_3_API_TOKEN"), "{all}");

        let mut rt = Runtime::new(
            detailed(scenes::approval_many),
            view,
            SIZE,
            Env::new(true, 2.0),
        );
        rt.frame(0.0);
        let all = texts(&rt);
        assert!(all.contains("It expects these 40 keys"), "{all}");
        assert!(all.contains("SERVICE_12_API_TOKEN"), "{all}");
        assert!(!all.contains("SERVICE_13_API_TOKEN"), "{all}");
        assert!(all.contains("28 more"), "{all}");

        click(&mut rt, "kb-approval-more");
        let all = texts(&rt);
        assert!(all.contains("SERVICE_40_API_TOKEN"), "{all}");
        assert!(all.contains("Show fewer"), "{all}");
        for key in [
            "kb-approval",
            "kb-approval-field",
            "kb-approval-ok",
            "kb-approval-deny",
        ] {
            let ([_, y, _, h], _) = rt.presented(key).unwrap();
            assert!(y >= 0.0 && y + h <= SIZE.1, "{key} at {y}, {h} high");
        }
    }

    /// An import into the local store is asked about by what it writes:
    /// each section and whether it is new, its files, its key names and
    /// the values it replaces. Locked, it says the passphrase unlocks too,
    /// and which sections are skipped if they turn out to have keys.
    #[test]
    fn an_import_lists_what_it_writes() {
        let rt = runtime(fixed(scenes::approval_import));
        let all = texts(&rt);
        for shown in [
            "Import 3 env files into the local store?",
            "kagebunshin onboard /src/widget /src/gadget /src/billing",
            "Writes 9 keys, by name; the values are read from the files",
            "[widget.dev], a new project",
            "from /src/widget/.env",
            "[gadget-web.dev], a new project",
            "from /src/gadget/apps/web/.env.local",
            "NEXT_PUBLIC_API_URL",
            "[billing.staging]",
            "Replaces the value it has now for DATABASE_URL",
            "Claude Code in /src",
            "Approving writes these values to the local store, which takes its passphrase. The \
             files stay where they are.",
        ] {
            assert!(all.contains(shown), "{shown}: {all}");
        }
        for not_shown in [
            "skipped if",
            "unlocks",
            "Wants",
            "trusts this command",
            "Why it asks",
        ] {
            assert!(!all.contains(not_shown), "{not_shown}: {all}");
        }
        assert!(rt.find("kb-approval-keys").is_none());
        assert_eq!(
            notice(&rt.state.approvals[0]),
            "`kagebunshin` asks to import 3 env files into the local store. Approve or deny it \
             in the window."
        );

        let all = texts(&runtime(fixed(scenes::approval_import_locked)));
        for shown in [
            "[widget.dev], a new project \u{00b7} skipped if it already has keys",
            "[billing.staging]",
            "Approving writes these values to the local store, which takes its passphrase, and \
             unlocks kagebunshin.",
        ] {
            assert!(all.contains(shown), "{shown}: {all}");
        }
        assert!(!all.contains("Replaces"), "{all}");
        assert!(!all.contains("[billing.staging] \u{00b7}"), "{all}");
    }

    /// A request for values to type has a hidden field for each key and
    /// says which it replaces. What is typed is sent with the passphrase,
    /// the keys left empty are not, and it stays in its fields until the
    /// daemon takes it: a wrong passphrase costs no retyping.
    #[test]
    fn values_are_typed_into_the_prompt_and_sent_with_the_passphrase() {
        use crate::daemon::Approval;
        let (approver, sent, feed) = crate::daemon::Approver::fake();
        let mut s = fixed(scenes::approval_type);
        s.approver = Some(approver);
        let mut rt = runtime(s);
        rt.poll = Some(poll);
        let all = texts(&rt);
        for shown in [
            "Type 3 values for widget/dev?",
            "kagebunshin store set widget.dev STRIPE_SECRET SESSION_KEY SENTRY_DSN",
            "Type the values, one line each. A key left empty stays as it is",
            "has a value now, which this replaces",
            "Claude Code in /src/widget",
            "Saving writes what you typed to the local store, which takes its passphrase. The \
             command is told which keys were set, never a value.",
        ] {
            assert!(all.contains(shown), "{shown}: {all}");
        }
        for not_shown in ["Wants", "trusts this command", "unlocks", "Why it asks"] {
            assert!(!all.contains(not_shown), "{not_shown}: {all}");
        }
        assert!(rt.find("kb-approval-keys").is_none());
        assert!(rt.find("kb-approval-replaces-0").is_none());
        assert!(rt.find("kb-approval-replaces-1").is_some());
        assert_eq!(
            notice(&rt.state.approvals[0]),
            "`kagebunshin` asks you to type 3 values for widget/dev. Type or deny it in the \
             window."
        );

        // Nothing typed: nothing is sent, and it says why.
        click(&mut rt, "kb-approval-field");
        rt.paste("correct horse");
        rt.frame(0.0);
        click(&mut rt, "kb-approval-ok");
        assert!(sent.try_recv().is_err());
        assert!(texts(&rt).contains("Type a value for at least one key first."));

        // The first field is the one focused; the second is left empty.
        rt.state.approval_passphrase.clear();
        click(&mut rt, "kb-approval-value-0");
        rt.paste("sk_test_CANARY");
        click(&mut rt, "kb-approval-value-2");
        rt.paste("https://CANARY@sentry.example/1");
        rt.frame(0.0);
        assert!(!texts(&rt).contains("CANARY"));
        // With no passphrase yet the button does nothing, and Enter in a
        // value's field moves to the passphrase.
        click(&mut rt, "kb-approval-ok");
        assert!(sent.try_recv().is_err());
        assert!(!rt.state.approval_passphrase.focused);
        rt.key(rune::KeyEvent {
            key: rune::Key::Enter,
            mods: rune::Mods::default(),
        });
        rt.frame(0.0);
        assert!(sent.try_recv().is_err());
        assert!(rt.state.approval_passphrase.focused);
        assert!(rt.state.approval_values.iter().all(|f| !f.focused));
        rt.paste("wrong horse");
        rt.frame(0.0);
        click(&mut rt, "kb-approval-ok");
        let answer = sent.try_recv().unwrap();
        assert_eq!(
            (answer.id, answer.passphrase.unwrap().expose()),
            (1, "wrong horse")
        );
        let values: Vec<(&str, &str)> = (answer.values.iter())
            .map(|(k, v)| (k.as_str(), v.expose()))
            .collect();
        assert_eq!(
            values,
            [
                ("STRIPE_SECRET", "sk_test_CANARY"),
                ("SENTRY_DSN", "https://CANARY@sentry.example/1")
            ]
        );

        // Refused: the values are still there, the passphrase is not.
        feed.send(Approval::Answered(Err(Problem::new("wrong passphrase"))))
            .unwrap();
        rt.frame(0.1);
        assert!(rt.find("kb-approval-error").is_some());
        assert!(rt.state.approval_passphrase.text.is_empty());
        assert_eq!(rt.state.approval_values[0].text, "sk_test_CANARY");
        click(&mut rt, "kb-approval-field");
        rt.paste("correct horse");
        rt.frame(0.0);
        click(&mut rt, "kb-approval-ok");
        assert_eq!(sent.try_recv().unwrap().values.len(), 2);

        // Taken: the fields go with the request.
        feed.send(Approval::Answered(Ok(Vec::new()))).unwrap();
        rt.frame(0.1);
        assert!(rt.find("kb-approval").is_none());
        assert!(rt.state.approval_values.is_empty());

        // The next one starts empty, and denying it empties its fields.
        let mut next = rt.state.approvals.first().cloned();
        assert_eq!(next.take(), None);
        let mut again = App::blank();
        scenes::approval_type(&mut again);
        let prompt = ApprovalPrompt {
            id: 2,
            ..again.approvals[0].clone()
        };
        feed.send(Approval::Waiting(vec![prompt])).unwrap();
        rt.frame(0.2);
        assert_eq!(rt.state.approval_values.len(), 3);
        assert!(rt.state.approval_values[0].focused);
        assert!(!rt.state.approval_passphrase.focused);
        rt.paste("typed, then denied");
        click(&mut rt, "kb-approval-deny");
        let denied = sent.try_recv().unwrap();
        assert_eq!((denied.id, denied.passphrase.is_none()), (2, true));
        assert!(denied.values.is_empty());
        assert!(rt.state.approval_values.iter().all(|f| f.text.is_empty()));

        // Locked: saving unlocks too, and no key is known to have a value.
        let all = texts(&runtime(fixed(scenes::approval_type_locked)));
        for shown in [
            "A key left empty stays as it is. One that has a value now gets the new one",
            "which takes its passphrase, and unlocks kagebunshin. The command is told which \
             keys were set, never a value.",
        ] {
            assert!(all.contains(shown), "{shown}: {all}");
        }
        assert!(!all.contains("which this replaces"), "{all}");

        // One key: named in the title.
        let mut s = fixed(scenes::approval_type);
        s.approvals[0].keys.truncate(1);
        s.approval_values = value_fields(s.approvals.first());
        let all = texts(&runtime(s));
        assert!(
            all.contains("Type the value of STRIPE_SECRET for widget/dev?"),
            "{all}"
        );
        assert!(all.contains("Type its value, on one line"), "{all}");
    }

    /// Another machine's request names the machine and its user, and says
    /// its command line is only what that machine reports.
    #[test]
    fn a_remote_approval_names_the_machine() {
        let mut s = detailed(scenes::approval);
        s.approvals[0].pid = 0;
        s.approvals[0].parents.clear();
        s.approvals[0].remote = Some(kagebunshin::ipc::protocol::RemotePeer {
            node: "nLAPTOP".into(),
            machine: "laptop".into(),
            user: "dev@example.com".into(),
            tags: Vec::new(),
            token: None,
        });
        let all = texts(&runtime(s));
        for shown in [
            "Hand sensitive values of widget/dev to a command on machine laptop?",
            "Command (as the remote machine reports it)",
            "Machine laptop, user dev@example.com",
            "in /src/widget there, as it reports",
        ] {
            assert!(all.contains(shown), "{shown}: {all}");
        }
        assert!(!all.contains("pid 0"), "{all}");
        assert!(!all.contains("names as the processes give them"), "{all}");
    }

    #[test]
    fn unmarking_waits_for_the_confirm_dialog() {
        let mut rt = runtime(fixed(scenes::confirm));
        assert!(texts(&rt).contains("acme/dev/stripe"));
        click(&mut rt, "kb-confirm-no");
        assert!(rt.find("kb-confirm").is_none());
        assert_eq!(rt.state.machine.notice, None);
    }

    /// Marking an environment asks for the passphrase, then goes to the
    /// daemon; unmarking it is confirmed first.
    #[test]
    fn marking_an_env_takes_the_passphrase() {
        let mut rt = runtime(fixed(scenes::key));
        click(&mut rt, "kb-env-mark");
        let Pending::Passphrase(Purpose::Mark { mark, sensitive }) = &rt.state.machine.pending
        else {
            panic!("{:?}", rt.state.machine.pending)
        };
        assert!(*sensitive);
        assert_eq!(
            *mark,
            Mark::Env {
                project: "widget".parse().unwrap(),
                env: "dev".parse().unwrap(),
                also: Vec::new(),
            }
        );
        assert!(rt.find("kb-passphrase").is_some());

        // Seen with the passphrase, as it is marked: unmarking is confirmed.
        let mut s = fixed(scenes::key);
        if let Some(shown) = &mut s.machine.shown {
            shown.columns[0].inspected = true;
        }
        let mut rt = runtime(s);
        click(&mut rt, "kb-env-mark");
        assert!(rt.find("kb-confirm").is_some());
    }

    /// Marking an environment whose secrets open ones read too shows them
    /// first: they stay unmarked unless ticked, and the ticked ones go to
    /// the daemon with the mark. One whose name looks like production is
    /// listed as marked all the same, with nothing to tick.
    #[test]
    fn marking_an_env_shows_what_it_shares_first() {
        let errors = Origin::new(Provider::AwsSm, "acme/errors");
        // The daemon says what is shared with what waits, in one answer.
        let fake = FakeClient::default();
        fake.reply(Ok(Response::Status(StatusReport {
            locked: false,
            env: None,
            expiring: Vec::new(),
            remote: None,
            waiting: fixed(scenes::waiting).machine.waiting,
            acknowledged: Vec::new(),
            shared: scenes::shared(),
            app: false,
            phone: None,
            standing: Vec::new(),
        })));
        let mut rt = live(scenes::waiting, &fake);
        until(&mut rt, |s| !s.machine.shared.is_empty());
        click(&mut rt, "kb-waiting-mark-widget-prod");
        assert!(rt.find("kb-passphrase").is_none());
        let all = texts(&rt);
        assert!(
            all.contains("Other environments read 3 of its secrets too"),
            "{all}"
        );
        assert!(all.contains("aws_sm:acme/tools/*"), "{all}");
        assert!(all.contains("also read by shop.qa"), "{all}");
        assert!(all.contains("their names look like production"), "{all}");
        assert!(all.contains("Mark sensitive"), "{all}");

        click(&mut rt, "kb-sharing-0");
        click(&mut rt, "kb-sharing-1");
        click(&mut rt, "kb-sharing-0");
        let Pending::Sharing(sharing) = &rt.state.machine.pending else {
            panic!("{:?}", rt.state.machine.pending)
        };
        assert_eq!(sharing.also, std::slice::from_ref(&errors));
        assert!(texts(&rt).contains("Mark it and 1 secret"));

        click(&mut rt, "kb-sharing-yes");
        assert!(rt.find("kb-sharing").is_none());
        let all = texts(&rt);
        assert!(
            all.contains(
                "to mark environment prod of widget, and with it 1 shared secret sensitive"
            ),
            "{all}"
        );
        rt.paste("pw");
        rt.frame(0.0);
        click(&mut rt, "kb-passphrase-ok");
        let sent = |r: &Request| matches!(r, Request::MarkEnv { .. });
        until(&mut rt, |_| fake.asked.lock().unwrap().iter().any(sent));
        let asked = fake.asked.lock().unwrap();
        assert!(asked.iter().any(|r| matches!(
            r,
            Request::MarkEnv { project, env, sensitive: true, also, passphrase }
                if project.as_str() == "widget" && env.as_str() == "prod"
                    && *also == [errors.clone()] && passphrase.expose() == "pw"
        )));
        drop(asked);

        // Cancelled, nothing is asked for; one that shares nothing with an
        // open environment goes straight to the passphrase.
        let mut s = fixed(scenes::waiting);
        s.machine.shared = scenes::shared();
        let mut rt = runtime(s);
        click(&mut rt, "kb-waiting-mark-widget-prod");
        click(&mut rt, "kb-sharing-no");
        assert_eq!(rt.state.machine.pending, Pending::None);
        click(&mut rt, "kb-waiting-mark-gadget-rc");
        assert!(rt.find("kb-sharing").is_none());
        assert!(rt.find("kb-passphrase").is_some());
    }

    /// Acknowledging an environment that reads marked secrets shows them
    /// first, none ticked: they stay marked unless ticked, and the ticked
    /// ones go to the daemon with the acknowledgement.
    #[test]
    fn acknowledging_an_env_offers_to_unmark_what_it_reads() {
        let mail = Origin::new(Provider::AwsSm, "acme/mail");
        let fake = FakeClient::default();
        fake.reply(Ok(Response::Status(StatusReport {
            locked: false,
            env: None,
            expiring: Vec::new(),
            remote: None,
            waiting: fixed(scenes::waiting).machine.waiting,
            acknowledged: Vec::new(),
            shared: scenes::marked(),
            app: false,
            phone: None,
            standing: Vec::new(),
        })));
        let mut rt = live(scenes::waiting, &fake);
        until(&mut rt, |s| !s.machine.shared.is_empty());
        click(&mut rt, "kb-waiting-ack-gadget-rc");
        assert!(rt.find("kb-passphrase").is_none());
        let Pending::Unmarking(unmarking) = &rt.state.machine.pending else {
            panic!("{:?}", rt.state.machine.pending)
        };
        assert!(unmarking.unmark.is_empty());
        let all = texts(&rt);
        assert!(all.contains("gadget / rc is not production"), "{all}");
        assert!(
            all.contains("It reads 3 secrets that are marked sensitive"),
            "{all}"
        );
        assert!(
            all.contains(
                "also read by gadget.dev, and by gadget.prod, which still asks for approval"
            ),
            "{all}"
        );
        assert!(
            all.contains("also read by gadget.prod, which still asks for approval"),
            "{all}"
        );
        assert!(all.contains("Acknowledge, unmark nothing"), "{all}");

        click(&mut rt, "kb-unmarking-0");
        click(&mut rt, "kb-unmarking-2");
        click(&mut rt, "kb-unmarking-2");
        assert!(texts(&rt).contains("Acknowledge and unmark 1 secret"));
        click(&mut rt, "kb-unmarking-yes");
        assert!(rt.find("kb-unmarking").is_none());
        let all = texts(&rt);
        assert!(
            all.contains(
                "to acknowledge environment rc of gadget as not production, and unmark 1 \
                 secret it reads"
            ),
            "{all}"
        );
        rt.paste("pw");
        rt.frame(0.0);
        click(&mut rt, "kb-passphrase-ok");
        let sent = |r: &Request| matches!(r, Request::AcknowledgeEnv { .. });
        until(&mut rt, |_| fake.asked.lock().unwrap().iter().any(sent));
        let asked = fake.asked.lock().unwrap();
        assert!(asked.iter().any(|r| matches!(
            r,
            Request::AcknowledgeEnv { project, env, acknowledged: true, unmark, passphrase }
                if project.as_str() == "gadget" && env.as_str() == "rc"
                    && *unmark == [mail.clone()] && passphrase.expose() == "pw"
        )));
        drop(asked);

        // Cancelled, nothing is asked for; with nothing ticked only the
        // acknowledgement is; one that reads no marked secret goes straight
        // to the passphrase.
        let mut s = fixed(scenes::waiting);
        s.machine.shared = scenes::marked();
        let mut rt = runtime(s);
        click(&mut rt, "kb-waiting-ack-gadget-rc");
        click(&mut rt, "kb-unmarking-no");
        assert_eq!(rt.state.machine.pending, Pending::None);
        click(&mut rt, "kb-waiting-ack-gadget-rc");
        click(&mut rt, "kb-unmarking-yes");
        assert!(matches!(
            &rt.state.machine.pending,
            Pending::Passphrase(Purpose::Acknowledge { unmark, .. }) if unmark.is_empty()
        ));
        click(&mut rt, "kb-passphrase-no");
        click(&mut rt, "kb-waiting-ack-widget-prod");
        assert!(rt.find("kb-unmarking").is_none());
        assert!(rt.find("kb-passphrase").is_some());
    }

    /// A secret other environments read too says so in the grid, and its
    /// key says why it asks for approval in an environment not marked.
    #[test]
    fn a_shared_secret_says_so() {
        let mut s = fixed(scenes::unlocked);
        s.flat = false;
        let rt = runtime(s);
        assert!(rt.find("kb-secret-shared").is_none());

        // Dev reads everything under acme/dev/, and so does another.
        let mut s = fixed(scenes::unlocked);
        s.machine.shared = vec![SharedSecret {
            project: "widget".parse().unwrap(),
            env: "dev".parse().unwrap(),
            secret: Origin::new(Provider::AwsSm, "acme/dev/"),
            prefix: true,
            with: vec!["shop.qa".parse().unwrap()],
            open: vec!["shop.qa".parse().unwrap()],
            sensitive: false,
            production: false,
        }];
        let rt = runtime(s);
        assert!(rt.find("kb-secret-shared").is_some(), "{}", texts(&rt));

        let rt = runtime(fixed(scenes::shared_key));
        let all = texts(&rt);
        assert!(
            all.contains(
                "Secret aws_sm:acme/dev/stripe is marked sensitive, so dev asks for approval \
                 for its keys although dev itself is not marked. So do the others that read \
                 it: widget.prod."
            ),
            "{all}"
        );
    }

    #[test]
    fn sources_list_in_order_with_their_profile() {
        let mut rt = runtime(fixed(scenes::unlocked));
        click(&mut rt, "kb-nav-sources");
        assert_eq!(rt.state.view, View::Sources);
        assert!(texts(&rt).contains("profile acme-dev · region eu-west-1"));
        click(&mut rt, "kb-env-prod");
        assert!(texts(&rt).contains("acme/prod/"));
    }

    /// Activity is the machine's log: every project's lines, or one's.
    #[test]
    fn activity_lists_the_audit_log_of_all_projects_or_one() {
        let mut rt = runtime(fixed(scenes::activity));
        assert!(rt.find("kb-activity-3").is_some());
        let all = texts(&rt);
        assert!(all.contains("denied run widget/prod"), "{all}");
        assert!(all.contains("allowed run shop/dev"), "{all}");
        // It is no project's, so none is the one on show.
        assert!(rt.find("kb-tabs").is_none());
        assert!(all.contains("\nActivity\n"), "{all}");

        click(&mut rt, "kb-activity-of-shop");
        assert!(rt.find("kb-activity-0").is_some());
        assert!(rt.find("kb-activity-1").is_none());
        let all = texts(&rt);
        assert!(all.contains("allowed run shop/dev"), "{all}");
        assert!(!all.contains("widget/prod"), "{all}");
        click(&mut rt, "kb-activity-all");
        assert!(rt.find("kb-activity-3").is_some());

        let mut s = fixed(scenes::activity);
        if let Ok(log) = &mut s.activity {
            log.unreadable = 2;
        }
        s.activity_of = Some("billing".parse().unwrap());
        let rt = runtime(s);
        let all = texts(&rt);
        assert!(
            all.contains("2 lines of the log could not be read."),
            "{all}"
        );
        assert!(all.contains("Nothing logged about this project."), "{all}");
    }

    /// A provider lists the environments that read from it with how much
    /// each reads, not every secret's name; a row opens that
    /// environment's sources, where they are named.
    #[test]
    fn a_provider_counts_what_reads_from_it() {
        let mut rt = runtime(fixed(scenes::providers));
        let all = texts(&rt);
        assert!(all.contains("1 prefix · profile acme-dev"), "{all}");
        assert!(all.contains("1 prefix · profile acme-prod"), "{all}");
        assert!(!all.contains("acme/dev/"), "{all}");
        assert!(rt.find("kb-tabs").is_none());
        click(&mut rt, "kb-used-aws_sm-widget-prod");
        assert_eq!(rt.state.view, View::Sources);
        assert_eq!(rt.state.env, Some("prod".parse().unwrap()));
        assert!(texts(&rt).contains("acme/prod/"));

        // Forty secrets of one source are a count.
        let mut rt = runtime(fixed(scenes::many));
        click(&mut rt, "kb-nav-providers");
        let all = texts(&rt);
        assert!(all.contains("40 secrets · profile acme"), "{all}");
        assert!(!all.contains("dev/warehouse"), "{all}");
    }

    /// Each provider has its status under its own heading: what was
    /// checked, a login on the profile whose login ran out and on no
    /// other, and what the default profile is.
    #[test]
    fn a_provider_says_what_was_checked_and_what_reads_by_default() {
        let rt = runtime(fixed(scenes::providers));
        let all = texts(&rt);
        for said in [
            "can read",
            "needs login",
            "Read by 2 environments",
            "Replace the token…",
            "None is set: a source that names no profile reads with your ambient AWS",
        ] {
            assert!(all.contains(said), "{said}: {all}");
        }
        assert!(rt.find("kb-aws-login-acme-prod").is_some());
        assert!(rt.find("kb-aws-login-acme-dev").is_none());
        // Proton Pass is read by no environment of the scene: no such part.
        assert!(rt.find("kb-used-aws_sm").is_some());
        assert!(rt.find("kb-used-proton").is_none());

        let mut s = fixed(scenes::providers);
        s.catalog.aws = (Some("acme-dev".into()), Some("eu-west-1".into()));
        let all = texts(&runtime(s));
        assert!(
            all.contains(
                "A source that names no profile reads with profile acme-dev, region eu-west-1."
            ),
            "{all}"
        );

        // Nothing reported: why, which while locked is not "no token".
        let mut s = fixed(scenes::providers);
        s.machine.conn = Conn::Up { locked: true };
        s.machine.providers.last = Some(Ok(Vec::new()));
        let all = texts(&runtime(s));
        assert!(all.contains("shows once the daemon is unlocked"), "{all}");
        assert!(!all.contains("no token is saved"), "{all}");
        assert!(all.contains("Connect a token…"), "{all}");
        assert!(!all.contains("Replace the token…"), "{all}");

        // Unlocked, it is that no token is saved.
        let mut s = fixed(scenes::providers);
        s.machine.providers.last = Some(Ok(Vec::new()));
        let all = texts(&runtime(s));
        assert!(
            all.contains("Not connected: no token is saved, and no environment reads from it."),
            "{all}"
        );

        let mut s = fixed(scenes::providers);
        s.machine.providers.last = None;
        assert!(texts(&runtime(s)).contains("Not checked."));
    }

    /// A notice that only says a change was made goes by itself; one with
    /// a warning, or a failure, stays until it is put away.
    #[test]
    fn a_notice_goes_by_itself_unless_it_warns_or_failed() {
        use crate::machine::NOTICE_FOR;

        let probes = |fake: &FakeClient| {
            for _ in 0..4 {
                fake.reply(Ok(up(false)));
            }
        };
        let fake = FakeClient::default();
        probes(&fake);
        let mut rt = live(scenes::no_match, &fake);
        assert!(texts(&rt).contains("Unmarked acme/dev/stripe."));
        rt.frame(NOTICE_FOR - 0.5);
        assert!(rt.find("kb-notice").is_some());
        rt.frame(1.0);
        assert_eq!(rt.state.machine.notice, None);
        assert!(rt.find("kb-notice").is_none());

        let fake = FakeClient::default();
        probes(&fake);
        let mut rt = live(scenes::sources, &fake);
        rt.frame(NOTICE_FOR + 1.0);
        assert!(rt.find("kb-notice").is_some());
        click(&mut rt, "kb-notice-dismiss");
        assert_eq!(rt.state.machine.notice, None);
        assert!(rt.find("kb-notice").is_none());

        rt.update(|s, _| {
            s.machine.notice = Some(Notice::Failed(Problem::new("wrong passphrase")));
        });
        rt.frame(NOTICE_FOR + 1.0);
        assert!(rt.find("kb-notice-problem").is_some());
        click(&mut rt, "kb-notice-dismiss");
        assert!(rt.find("kb-notice-problem").is_none());
    }

    /// A filter or a search that leaves no key says which did and offers
    /// every key back; neither follows to another project.
    #[test]
    fn a_filter_that_empties_the_list_says_so_and_stays_with_its_project() {
        let mut rt = runtime(fixed(scenes::no_match));
        assert!(texts(&rt).contains("No key of dev is marked sensitive."));
        assert!(rt.find("kb-key-API_KEY").is_none());
        click(&mut rt, "kb-show-all");
        assert_eq!(rt.state.filter, None);
        assert!(rt.find("kb-no-match").is_none());
        assert!(rt.find("kb-key-API_KEY").is_some());

        click(&mut rt, "kb-filter-missing");
        assert!(rt.find("kb-key-SENTRY_DSN").is_some());
        rt.update(|s, _| s.search = TextEdit::new("stripe"));
        rt.frame(0.0);
        let all = texts(&rt);
        assert!(
            all.contains("No key of dev with “stripe” in its name is missing."),
            "{all}"
        );
        rt.update(|s, _| s.filter = None);
        rt.update(|s, _| s.search = TextEdit::new("nothing"));
        rt.frame(0.0);
        let all = texts(&rt);
        assert!(
            all.contains("No key of dev has “nothing” in its name."),
            "{all}"
        );

        rt.update(|s, _| s.filter = Some(Filter::Sensitive));
        click(&mut rt, "kb-project-billing");
        assert_eq!(rt.state.filter, None);
        assert!(rt.state.search.text.is_empty());
    }

    /// An environment acknowledged as not production shows its keys under
    /// a line that says so, with the button that takes it back; the same
    /// line heads its sources.
    #[test]
    fn an_acknowledged_environment_says_so_above_its_keys() {
        let mut rt = runtime(fixed(scenes::acknowledged));
        let all = texts(&rt);
        assert!(
            all.contains("prod looks like production and is acknowledged as not"),
            "{all}"
        );
        assert!(rt.find("kb-key-API_KEY").is_some());
        click(&mut rt, "kb-nav-sources");
        assert!(rt.find("kb-acknowledged").is_some());
        click(&mut rt, "kb-nav-keys");
        // Dev does not look like production: nothing to say.
        click(&mut rt, "kb-env-dev");
        assert!(rt.find("kb-acknowledged").is_none());
        click(&mut rt, "kb-env-prod");
        click(&mut rt, "kb-unacknowledge-prod");
        let all = texts(&rt);
        assert!(
            all.contains("to take back that environment prod of widget is not production"),
            "{all}"
        );
    }

    /// An environment whose name looks like production is asked about by
    /// itself once the daemon says it was acknowledged as not production.
    #[test]
    fn an_acknowledged_environment_loads_without_being_asked() {
        let fake = FakeClient::default();
        let Response::Status(report) = up(false) else {
            unreachable!()
        };
        fake.reply(Ok(Response::Status(StatusReport {
            acknowledged: vec!["widget.prod".parse().unwrap()],
            ..report
        })));
        let mut rt = live(scenes::unlocked, &fake);
        until(&mut rt, |s| {
            let prod = &s.machine.shown.as_ref().unwrap().columns[1];
            prod.detail != Detail::Idle
        });
        let asked = fake.asked.lock().unwrap();
        assert!(
            asked.iter().any(|r| matches!(
                r,
                Request::Status { facts: Some(f) } if f.env.as_ref().is_some_and(|e| e.as_str() == "prod")
            )),
            "{asked:?}"
        );
        drop(asked);

        // Waiting or marked sensitive, it is the person's to load.
        let fake = FakeClient::default();
        fake.reply(Ok(up(false)));
        let mut rt = live(scenes::unlocked, &fake);
        until(&mut rt, |s| s.machine.conn == Conn::Up { locked: false });
        rt.frame(0.5);
        click(&mut rt, "kb-env-prod");
        let all = texts(&rt);
        assert!(all.contains("prod is not loaded"), "{all}");
        let asked = fake.asked.lock().unwrap();
        assert_eq!(asked.len(), 1, "{asked:?}");
    }

    /// What a probe says while the scene's endpoint listens, with its
    /// grants after `change`.
    fn remote_up(change: impl Fn(&mut Vec<GrantView>)) -> Response {
        let Response::Status(report) = up(false) else {
            unreachable!()
        };
        let mut remote = fixed(scenes::remote).machine.remote;
        change(&mut remote.as_mut().unwrap().grants);
        Response::Status(StatusReport { remote, ..report })
    }

    #[test]
    fn remote_shows_the_endpoint_and_who_is_let_in() {
        let rt = runtime(fixed(scenes::remote));
        let all = texts(&rt);
        for shown in [
            "listening",
            "100.64.0.1:47317",
            "buildbot",
            "widget dev, rc",
            "shop dev",
            "until 2099-12-31",
            "no token",
            "Made before grants had tokens: nothing gets through with it until it has one.",
            "kagebunshin remote grant MACHINE PROJECT ENV…",
        ] {
            assert!(all.contains(shown), "{shown}: {all}");
        }
        assert!(rt.find("kb-grant-0-no-token").is_none());
        assert!(rt.find("kb-token").is_none());

        // Locked, the daemon says nothing of who is let in.
        let mut s = fixed(scenes::remote);
        s.machine.conn = Conn::Up { locked: true };
        s.machine.remote.as_mut().unwrap().grants.clear();
        let rt = runtime(s);
        let all = texts(&rt);
        assert!(
            all.contains("Grants show once the daemon is unlocked."),
            "{all}"
        );
        assert!(rt.find("kb-remote-grant").is_none());

        // Off, it says how it is turned on, and not how a machine is let in.
        let mut s = fixed(scenes::remote);
        let remote = s.machine.remote.as_mut().unwrap();
        (remote.enabled, remote.listening) = (Some(false), None);
        remote.grants.clear();
        let rt = runtime(s);
        let all = texts(&rt);
        assert!(all.contains("kagebunshin remote enable"), "{all}");
        assert!(all.contains("No machine is let in."), "{all}");
        assert!(rt.find("kb-remote-grant").is_none());

        // On and not listening, it says why.
        let mut s = fixed(scenes::remote);
        let remote = s.machine.remote.as_mut().unwrap();
        remote.listening = None;
        remote.problem = Some("Tailscale is not running".into());
        let all = texts(&runtime(s));
        assert!(all.contains("not listening"), "{all}");
        assert!(all.contains("Tailscale is not running"), "{all}");
    }

    /// A grant's new token is asked for by its node id, shows once, and is
    /// gone when it is put away, the view is left or the window closes.
    #[test]
    fn a_grant_gets_a_new_token_that_shows_until_it_is_put_away() {
        let token = "kbr_0123456789abcdef0123456789abcdef";
        let granted = || {
            Ok(Response::RemoteGranted {
                change: kagebunshin::store::Change::Replaced,
                locked: false,
                machine: "laptop".into(),
                token: WireSecret::new(token.into()),
            })
        };
        let fake = FakeClient::default();
        fake.reply(Ok(remote_up(|_| {})))
            .reply(granted())
            .reply(Ok(remote_up(|g| g[1].token = true)));
        let mut rt = live(scenes::remote, &fake);
        until(&mut rt, |s| s.machine.conn == Conn::Up { locked: false });
        rt.frame(0.1);

        // It has no token: nothing ends, so nothing to confirm.
        click(&mut rt, "kb-grant-1-rotate");
        assert!(rt.find("kb-confirm").is_none());
        let all = texts(&rt);
        assert!(
            all.contains("to give machine laptop's grant for shop a new token"),
            "{all}"
        );
        rt.paste("pw");
        rt.frame(0.6);
        click(&mut rt, "kb-passphrase-ok");
        until(&mut rt, |s| {
            s.machine.token.is_some()
                && s.machine.remote.as_ref().is_some_and(|r| r.grants[1].token)
        });
        rt.frame(0.7);
        let all = texts(&rt);
        assert!(
            all.contains("New token of machine laptop for shop"),
            "{all}"
        );
        assert!(all.contains(token), "{all}");
        assert!(all.contains(REMOTE_TOKEN_ENV), "{all}");
        assert!(rt.find("kb-grant-1-no-token").is_none());
        {
            let asked = fake.asked.lock().unwrap();
            assert!(
                asked.iter().any(|r| matches!(
                    r,
                    Request::RemoteRotate { machine, project, passphrase }
                        if machine == "nlaptop"
                            && project.as_str() == "shop"
                            && passphrase.expose() == "pw"
                )),
                "{asked:?}"
            );
        }
        click(&mut rt, "kb-token-done");
        assert_eq!(rt.state.machine.token, None);
        assert!(!texts(&rt).contains(token));

        // It has one now, which a new one would end: that is asked first.
        click(&mut rt, "kb-grant-1-rotate");
        let all = texts(&rt);
        assert!(
            all.contains("The one it has stops working at once."),
            "{all}"
        );
        assert!(all.contains("New token"), "{all}");
        click(&mut rt, "kb-confirm-no");
        assert_eq!(rt.state.machine.pending, Pending::None);

        let held = || {
            let grant = Grant::from(&fixed(scenes::remote).machine.remote.unwrap().grants[1]);
            Some(crate::daemon::NewToken {
                grant,
                token: WireSecret::new(token.into()),
            })
        };
        rt.state.machine.token = held();
        click(&mut rt, "kb-nav-providers");
        assert_eq!(rt.state.machine.token, None);
        click(&mut rt, "kb-nav-remote");
        assert!(!texts(&rt).contains(token));
        rt.state.machine.token = held();
        rt.update(on_close);
        assert_eq!(rt.state.machine.token, None);
    }

    #[test]
    fn a_grant_is_revoked_once_confirmed_with_the_passphrase() {
        let fake = FakeClient::default();
        fake.reply(Ok(remote_up(|_| {})))
            .reply(Ok(Response::Store {
                change: kagebunshin::store::Change::Removed,
                locked: false,
            }))
            .reply(Ok(remote_up(|g| drop(g.remove(0)))));
        let mut rt = live(scenes::remote, &fake);
        until(&mut rt, |s| s.machine.conn == Conn::Up { locked: false });
        rt.frame(0.1);

        click(&mut rt, "kb-grant-0-revoke");
        let all = texts(&rt);
        assert!(
            all.contains("Revoke machine buildbot's grant for widget?"),
            "{all}"
        );
        // Nothing is asked of the daemon until it is confirmed.
        click(&mut rt, "kb-confirm-yes");
        let all = texts(&rt);
        assert!(
            all.contains("to revoke machine buildbot's grant for widget"),
            "{all}"
        );
        assert_eq!(fake.asked.lock().unwrap().len(), 1);
        rt.paste("pw");
        rt.frame(0.6);
        click(&mut rt, "kb-passphrase-ok");
        until(&mut rt, |s| {
            s.machine
                .remote
                .as_ref()
                .is_some_and(|r| r.grants.len() == 1)
        });
        rt.frame(0.7);
        let all = texts(&rt);
        assert!(
            all.contains("Revoked machine buildbot's grant for widget."),
            "{all}"
        );
        assert!(!all.contains("buildbot may"), "{all}");
        assert!(rt.find("kb-grant-1").is_none());
        let asked = fake.asked.lock().unwrap();
        assert!(
            asked.iter().any(|r| matches!(
                r,
                Request::RemoteRevoke { machine, project: Some(project), passphrase }
                    if machine == "nbuildbot"
                        && project.as_str() == "widget"
                        && passphrase.expose() == "pw"
            )),
            "{asked:?}"
        );
    }

    #[test]
    fn phone_shows_the_paired_phone_and_those_that_could_be() {
        let rt = runtime(fixed(scenes::phone));
        let all = texts(&rt);
        for shown in [
            "Paired phone",
            "pocket",
            "paired 2026-11-19 00:00:00Z",
            "page served",
            scenes::PAGE_URL,
            "Last answered there: approved widget/dev at 2026-11-19 14:54:20Z.",
            "Pair another phone",
            "One phone approves at a time: the one paired now does until the new one has made its key.",
            "tablet",
            "android",
            "Pair again",
        ] {
            assert!(all.contains(shown), "{shown}: {all}");
        }
        assert!(rt.find("kb-phone-remove").is_some());
        assert!(rt.find("kb-pairing").is_none());

        // None paired: nothing to remove, and each phone can be.
        let rt = runtime(fixed(scenes::phone_none));
        let all = texts(&rt);
        assert!(
            all.contains("No phone is paired: requests are approved at this computer only."),
            "{all}"
        );
        assert!(all.contains("Pair a phone"), "{all}");
        assert!(!all.contains("Pair again"), "{all}");
        assert!(rt.find("kb-phone-remove").is_none());
        assert!(rt.find("kb-phone-0-pair").is_some());
        assert!(rt.find("kb-phone-1-pair").is_some());

        // One on its way in: its code and address, and no other to pick.
        let rt = runtime(fixed(scenes::phone_pairing));
        let all = texts(&rt);
        for shown in [
            "Pairing pocket",
            scenes::PAGE_URL,
            "QR code of the address",
            "It waits 9 min more, and stops when this view is left.",
        ] {
            assert!(all.contains(shown), "{shown}: {all}");
        }
        assert!(rt.find("kb-pairing-code").is_some());
        assert!(rt.find("kb-phones").is_none());

        // The page is not served: it says why, or that it is not yet.
        let mut s = fixed(scenes::phone);
        let status = s.machine.phone.as_mut().unwrap();
        status.url = None;
        status.last = None;
        let all = texts(&runtime(s));
        assert!(all.contains("page not served yet"), "{all}");
        assert!(
            all.contains(
                "It last opened the page at 2026-11-19 14:53:20Z, and has answered nothing since the daemon started."
            ),
            "{all}"
        );
        let mut s = fixed(scenes::phone);
        let status = s.machine.phone.as_mut().unwrap();
        status.url = None;
        status.problem = Some("Tailscale is not running".into());
        let all = texts(&runtime(s));
        assert!(all.contains("page not served"), "{all}");
        assert!(all.contains("Tailscale is not running"), "{all}");

        // Tailscale knows of no phone, or could not be asked.
        let mut s = fixed(scenes::phone_none);
        s.machine.phones.last = Some(Ok(Vec::new()));
        let all = texts(&runtime(s));
        assert!(
            all.contains("No phone or tablet is on this tailnet."),
            "{all}"
        );
        let mut s = fixed(scenes::phone_none);
        s.machine.phones.last = Some(Err(Problem {
            hint: Some("start Tailscale".into()),
            ..Problem::new("Tailscale is not running")
        }));
        let all = texts(&runtime(s));
        assert!(all.contains("Tailscale is not running"), "{all}");
        assert!(all.contains("hint: start Tailscale"), "{all}");

        // Locked, the daemon cannot read which phone is paired.
        let mut s = fixed(scenes::phone);
        s.machine.conn = Conn::Up { locked: true };
        s.machine.phone = None;
        let rt = runtime(s);
        let all = texts(&rt);
        assert!(
            all.contains("The paired phone shows once the daemon is unlocked."),
            "{all}"
        );
        assert!(
            all.contains("A phone is paired once the daemon is unlocked."),
            "{all}"
        );
        assert!(rt.find("kb-phone-0-pair").is_none());
    }

    /// A daemon as far as the phone goes: it answers by what it is asked,
    /// since a pairing is probed for every second.
    #[derive(Clone, Default)]
    struct PhoneDaemon {
        /// Whether pocket is paired, and whether one is being paired.
        state: Arc<std::sync::Mutex<(bool, bool)>>,
        asked: Arc<std::sync::Mutex<Vec<Request>>>,
    }

    impl PhoneDaemon {
        fn paired() -> Self {
            let daemon = Self::default();
            daemon.state.lock().unwrap().0 = true;
            daemon
        }

        fn asked(&self, what: impl Fn(&Request) -> bool) -> usize {
            self.asked
                .lock()
                .unwrap()
                .iter()
                .filter(|r| what(r))
                .count()
        }
    }

    impl crate::daemon::DaemonClient for PhoneDaemon {
        fn request(&mut self, req: Request) -> Result<Response, ClientError> {
            let mut state = self.state.lock().unwrap();
            let store = |change| Response::Store {
                change,
                locked: false,
            };
            let reply = match &req {
                Request::Status { .. } => {
                    let Response::Status(report) = up(false) else {
                        unreachable!()
                    };
                    let mut phone = fixed(scenes::phone_pairing).machine.phone.unwrap();
                    phone.paired = fixed(scenes::phone)
                        .machine
                        .phone
                        .and_then(|p| p.paired)
                        .filter(|_| state.0);
                    if !state.1 {
                        phone.pairing = None;
                    }
                    // It says nothing of a phone when there is none.
                    let phone = (state.0 || state.1).then_some(phone);
                    Response::Status(StatusReport { phone, ..report })
                }
                Request::Phones => {
                    let phones = fixed(scenes::phone_none).machine.phones.last;
                    Response::Phones {
                        phones: phones.unwrap().unwrap(),
                    }
                }
                Request::PhonePair { .. } => {
                    state.1 = true;
                    Response::PhonePairing {
                        name: "pocket".into(),
                        url: scenes::PAGE_URL.into(),
                        seconds: 600,
                    }
                }
                Request::PhonePairStop => {
                    state.1 = false;
                    Response::PhonePairStopped
                }
                Request::PhoneUnpair { .. } => {
                    state.0 = false;
                    store(kagebunshin::store::Change::Removed)
                }
                _ => {
                    return Err(ClientError::NotRunning {
                        socket: "/fake/kagebunshind.sock".into(),
                    });
                }
            };
            self.asked.lock().unwrap().push(req);
            Ok(reply)
        }
    }

    /// A phone is paired from its row with the passphrase and no question
    /// first. The way in shows until the phone is in, and is ended when it
    /// is stopped, the view is left or the window closes: the daemon keeps
    /// the passphrase for as long as it lasts.
    #[test]
    fn a_phone_is_paired_from_its_row_and_its_way_in_ends_when_put_away() {
        let daemon = PhoneDaemon::default();
        let stops = |daemon: &PhoneDaemon| daemon.asked(|r| *r == Request::PhonePairStop);
        let mut rt = live_on(scenes::phone_none, Box::new(daemon.clone()));
        until(&mut rt, |s| s.machine.conn == Conn::Up { locked: false });
        rt.frame(0.1);
        let pair = |rt: &mut Runtime<App>| {
            click(rt, "kb-phone-0-pair");
            assert!(rt.find("kb-confirm").is_none());
            let all = texts(rt);
            assert!(all.contains("to let pocket approve requests"), "{all}");
            rt.paste("pw");
            rt.frame(0.6);
            click(rt, "kb-passphrase-ok");
            until(rt, |s| {
                s.machine.pairing.is_some()
                    && s.machine
                        .phone
                        .as_ref()
                        .is_some_and(|p| p.pairing.is_some())
            });
            rt.frame(0.7);
        };

        pair(&mut rt);
        let all = texts(&rt);
        for shown in [
            "Pairing pocket",
            scenes::PAGE_URL,
            "It waits 9 min more, and stops when this view is left.",
        ] {
            assert!(all.contains(shown), "{shown}: {all}");
        }
        assert!(rt.find("kb-pairing-code").is_some());
        assert!(rt.find("kb-phones").is_none());
        assert_eq!(
            daemon.asked(|r| matches!(
                r,
                Request::PhonePair { machine, passphrase }
                    if machine == "npocket" && passphrase.expose() == "pw"
            )),
            1
        );

        click(&mut rt, "kb-pairing-stop");
        assert_eq!(rt.state.machine.pairing, None);
        assert!(rt.find("kb-pairing").is_none());
        until(&mut rt, |_| stops(&daemon) == 1);

        pair(&mut rt);
        click(&mut rt, "kb-nav-providers");
        assert_eq!(rt.state.machine.pairing, None);
        until(&mut rt, |_| stops(&daemon) == 2);
        click(&mut rt, "kb-nav-phone");
        assert!(rt.find("kb-pairing").is_none());

        pair(&mut rt);
        rt.update(on_close);
        assert_eq!(rt.state.machine.pairing, None);
        until(&mut rt, |_| stops(&daemon) == 3);
        // The passphrase typed for it is not kept in its field either.
        rt.frame(0.5);

        // The phone makes its key: the way in is put away, and it is said.
        pair(&mut rt);
        *daemon.state.lock().unwrap() = (true, false);
        until(&mut rt, |s| s.machine.pairing.is_none());
        rt.frame(0.1);
        let all = texts(&rt);
        for shown in [
            "Paired pocket: it approves requests now.",
            "page served",
            "Pair another phone",
            "Pair again",
        ] {
            assert!(all.contains(shown), "{shown}: {all}");
        }
        assert!(rt.find("kb-pairing").is_none());
        assert!(rt.find("kb-phone-remove").is_some());
        // It was not stopped: it ended by itself.
        assert_eq!(stops(&daemon), 3);
    }

    #[test]
    fn the_paired_phone_is_removed_once_confirmed_with_the_passphrase() {
        let daemon = PhoneDaemon::paired();
        let unpairs = |daemon: &PhoneDaemon| {
            daemon.asked(
                |r| matches!(r, Request::PhoneUnpair { passphrase } if passphrase.expose() == "pw"),
            )
        };
        let mut rt = live_on(scenes::phone, Box::new(daemon.clone()));
        until(&mut rt, |s| s.machine.conn == Conn::Up { locked: false });
        rt.frame(0.1);

        click(&mut rt, "kb-phone-remove");
        let all = texts(&rt);
        assert!(
            all.contains(
                "Remove pocket? Requests will be approved at this computer only, until a phone is paired again."
            ),
            "{all}"
        );
        // Nothing is asked of the daemon until it is confirmed.
        click(&mut rt, "kb-confirm-yes");
        let all = texts(&rt);
        assert!(all.contains("to remove pocket, the paired phone"), "{all}");
        assert_eq!(unpairs(&daemon), 0);
        rt.paste("pw");
        rt.frame(0.6);
        click(&mut rt, "kb-passphrase-ok");
        until(&mut rt, |s| s.machine.phone.is_none());
        rt.frame(0.7);
        let all = texts(&rt);
        for shown in [
            "Removed pocket: requests are approved at this computer only.",
            "No phone is paired: requests are approved at this computer only.",
            "Pair a phone",
        ] {
            assert!(all.contains(shown), "{shown}: {all}");
        }
        assert!(rt.find("kb-phone-remove").is_none());
        assert_eq!(unpairs(&daemon), 1);
    }
}
