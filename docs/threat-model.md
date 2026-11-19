# Threat model

kagebunshin is scoped, audited delivery, not invisibility. It controls
which values reach which command and records what it decided. It cannot
hide a value from code that has been handed it, and it runs as the same
user as the local agents it serves.

## Two boundaries

- **Locally, the boundary is soft.** An agent on your machine runs as you.
  It cannot get a marked value through kagebunshin without your
  passphrase, but it can use your AWS profile or SSO session
  directly, without kagebunshin, and do most of what you can. What holds
  it back there is IAM and the agent's own cooperation; kagebunshin's part
  is keeping values out of files and context, and writing everything
  down.
- **For a remote caller, the boundary is hard.** An agent on another
  machine that reaches the daemon over the [remote
  endpoint](config.md#the-remote-endpoint) has none of your credentials
  and cannot edit your config or store. It gets what its machine's grant
  allows, through `run`, `status` and `diff` only, and a marked value only
  once you approve it, here or on your paired phone.

## What it protects, and from whom

**The assets:** secret values in AWS Secrets Manager and the local store,
and the marks that say which of them agents may have.

**The adversary it is built for:** a coding agent that is careless,
confused or prompt-injected, running as your user, that uses the tools it
is given: shell commands, file reads and writes, and `kagebunshin` itself.
Against that agent kagebunshin:

- keeps values out of files (no `.env`), out of the agent's own
  environment, and out of `status`, `diff`, `audit`, errors and logs;
- hands out a marked environment, secret or key only once you approve
  that one request: in the app, with the store passphrase, or on the
  [phone you paired](#the-paired-phone), with its passkey;
- keeps human-only actions (`get`, `unlock`, store writes) behind the
  store passphrase;
- masks values in the piped output of `run`, so a stray `printenv` in a
  test log does not land in the agent's context;
- records every sensitive hand-out and every refused request; Known
  limitations lists what it leaves out.

**Out of scope:**

- A local process that deliberately attacks you as your user. It can read
  `/proc/<pid>/environ` of the commands `run` starts, edit project files,
  ptrace processes that are not hardened, and
  replace binaries on your `PATH`. Separating it needs a different user, a
  sandbox, or a VM.
- Root, the kernel, and anyone with your unlocked desktop.
- What a command does with a value once `run` gave it to it.
- Your AWS permissions. kagebunshin can refuse to hand out a value, but if
  the profile an agent-facing environment uses can read production, the
  split rests on marks and names alone. Make it rest on IAM: give dev a
  profile that cannot read production.

The sections below say where each control stops.

## Sensitive values

What needs you is decided by explicit marks, see
[project-files.md](project-files.md#sensitive-environments-and-secrets):

- **Where marks live:** in the encrypted local store, not in project files.
  Changing one takes the store passphrase, which proves a human, so a
  process that can write the configuration directory, an agent included,
  cannot unmark anything. Removing a mark, and acknowledging an
  environment as not production, happen only in the app. A `sensitive` flag
  in a project file can add a mark, never remove one: it is copied into
  the store at unlock, so deleting the flag later changes nothing.
- **Adding a mark takes no passphrase:** `kagebunshin mark` lets any
  caller, an agent included, mark an environment, a secret or a store key.
  It only ever adds, so the worst a misbehaving caller does is mark too
  much, which costs you approvals and an unmark in the app. It is refused
  where it would undo your decision: an environment you acknowledged as
  not production, a secret you allowed agents to read. Each is in the
  audit log with the caller. The mark holds in the running daemon at once.
  The store file cannot be written without the passphrase, so the mark
  also waits in `<store>.marks`, a plain list of names (never values)
  beside the store, until the next unlock or change in the app writes it
  into the store and deletes the list. The list is not trusted: it can
  only add marks, and one that does not parse adds nothing. Until it is
  in the store, such a mark is weaker than one you made: a process of
  yours that deletes the list drops it at the next unlock. An environment
  named like production then waits for your decision again, as before it
  was marked; a secret or key marked this way is unmarked again. What you
  marked with the passphrase is in the store and is not touched.
- **Environment level:** a marked environment. `status` and `diff` are
  refused, and nothing from it is fetched or cached until a hand-out is
  approved.
- **Secret level:** a marked secret of any provider but `file`, wherever
  it is read, or a marked store key. These are fetched and cached like
  other values, so `status` and `diff` can describe them. Only the winning
  origin counts.
- **Handing one out:** `get` and `run` wait until you approve that one
  request in the app, where a prompt names the caller, the command, the
  keys and why it asks (marked, or waiting for your decision), and takes
  the store passphrase. Denied, not approved within `approval_timeout`
  (five minutes unless `config.toml` sets it, at most thirty), or asked
  while the app is not running, the request is refused; so is one still
  waiting when the app ends or its window is closed on it. A
  [paired phone](#the-paired-phone) that allowed notifications is told
  of the request too, and it then waits for the phone with the app
  closed.
  An app that sits in the tray is running: the request waits in its
  window, which you open. The notification it sends names the program, the project and
  the environment, never the program's arguments or a key.
  The command line is what the caller says it will run, and the names of
  the processes it was started through (shown so you can tell an agent
  from your own shell) are what those processes call themselves: both
  help you recognise a request, and neither is proof of what runs.
  For an environment refused as a whole, the keys are those the
  checkout's `.env.example` lists. With no such file the command gets
  every key, and the prompt says so: it names them all when the daemon
  knows them (an environment waiting for your decision is read before it
  asks; a marked one only if this session already holds it), and
  otherwise says only that it is every key, as a marked environment is
  not read before you approve. The caller is told no name it did not ask
  for. Where the prompt named them, a key added while it was shown voids
  the approval. `kagebunshin project example` writes the file, so that
  the request is for the keys the app reads.
  `run` stays all or nothing: a partly injected environment could look
  like a working one, so the whole command waits. If the environment, its
  sources or its marked keys changed while the prompt was shown, nothing
  is handed out. The prompt is never in the caller's terminal, where an
  agent could read the passphrase.
- **Approving trusts the command.** A script an agent wrote can print or
  send on the value it was given; the prompt says so.
- **When marks apply:** they are read at hand-out time from the unlocked
  store, so a new mark applies at once, without a `sync`.
- **Removing a mark:** it is confirmed in the app's window and takes the
  passphrase.

Name matching (`prod`, `production` and `rc` segments, plus
`sensitive_source_patterns`) decides what happens when nobody decided: an
environment it matches, neither marked nor acknowledged as not production,
is treated as marked until a human chooses one in the app. This changes the
default for a forgotten mark. It adds no boundary against a process that
can use the AWS profile directly: that process reads the secret without
asking kagebunshin. It is a net for typos and forgotten marks, not a
guarantee:

- `-`, `_`, `+` and `@` are not separators, so `widget-prod` does not
  match. Add patterns such as `*-prod*` for names like that.
- A name says nothing about permissions. A secret named `widget/dev/db` can
  hold production credentials, and the AWS profile an environment uses may
  be able to read production secrets whatever the names say. Separating
  names is not separating IAM. Only IAM keeps an agent's profile from
  reaching production.

## One policy for every caller

Any process of the user can reach the socket, and nothing about a
connection shows that a human is asking. So every caller gets the same
policy, and what only a human may do takes the store passphrase in the
request:

| Request | Policy |
|---|---|
| status, diff, run, lock | allowed |
| sync, store list, list | allowed: no values, nothing loosened |
| unlock | the passphrase, when a store exists |
| store set | the passphrase, at the terminal or typed with the values in the app |
| store unset, clear, passwd | the passphrase |
| store import (`onboard`) | the passphrase, at the terminal or with approval in the app |
| adding a sensitive mark | allowed: it only tightens |
| removing a mark, acknowledging an environment | the passphrase |
| get | the passphrase |
| inspect, reveal (the app) | the passphrase |
| a value marked sensitive, to get or run | approval in the app, with the passphrase, or on the paired phone, with its passkey |
| status, diff of an environment marked sensitive | refused |

`status` and `diff` may name a `store set` command for keys no source
sets. It names keys only; the human runs it, with the passphrase, and
types each value at a prompt or pipes them in, never as an argument. Run
with no terminal, as an agent runs it, it sends the key names and no
value, and the daemon asks in the app: the prompt names the caller, the
section, each key and, while unlocked, the keys that have a value now,
and takes the values and the passphrase, which does the write and unlocks
a locked daemon. The values go from the app to the daemon; the caller is
told which keys were set, which had a value before and which were left
empty.
Denied, not answered in time, or asked while the app is not open, nothing
is written. So an agent can ask for a key to be set or replaced, but what
it is set to, and whether, is the person's with the passphrase. A caller
on another machine cannot ask.

`onboard` writes the values of env files to the store. Run at a terminal
it asks for the passphrase there. Run with no terminal, as an agent runs
it, it sends the values with no passphrase and the daemon holds them until
you approve the import in the app, as it does a sensitive hand-out: the
prompt names the caller, each file, the section it goes to and whether
that is new, each key, and the keys whose value it would replace, never a
value, and takes the passphrase, which does the write and unlocks a locked
daemon. Denied, not approved in time, or asked while the app is not open,
nothing is written and no project file is left behind. Both the question
and how it ended are in the audit log, by key name. So an agent can start
an import, of files it could read anyway, but only a person with the
passphrase lets it into the store; the files stay where they are, and
deleting them is yours to do.

An agent works with what any caller may do: it runs commands with the
values of environments that are not sensitive, and anything marked waits
for you. There is no per-agent scope locally: an agent can `run` any
environment that is not sensitive, in any project. Keep what agents must
not read behind a sensitive mark, and what they must not reach behind IAM.

The app is how a human sees what is sensitive. Inspect lists the keys and
origins of an environment marked sensitive, and reveal returns one value,
sensitive or not. Both take the passphrase in the request and are always
audited, reveal as a hand-out. The window holds a revealed value until it is
hidden, another project is shown, the key view is left or the daemon locks.

The daemon creates no store: before one exists there is no passphrase to
tell a human from an agent. `kagebunshin setup` (or `store init`) writes
the store file itself and then unlocks the daemon with it, so creating one takes write
access to the config directory, not just the socket. A same-user agent that
has that access can still create the store first if none exists, so create
it, with `setup`, before running agents.

`list --keys` lets any caller learn the key names inside AWS secrets. To
do so the daemon reads each secret's value with the caller's AWS profile
(`GetSecretValue`, which shows in the account's own audit trail, such as
CloudTrail, as a read by that profile), keeps the key names, and drops and
zeroes the value. It reads no secret marked sensitive and none whose name
or profile looks like production, and none while locked, when the marks
are not known. The lookup is always recorded, with the names of the
secrets read. Key names are not secret here, but they do say what a
secret holds.

`project apply`, even with `--check`, has the daemon read every secret
the file names, with the file's profiles, as `status` would; those reads
show in the provider's own audit trail, such as CloudTrail. The daemon
hands back names and origins only, drops and zeroes the values, and
caches nothing, so a file that is never installed leaves nothing behind.
It does not read an environment marked sensitive, and one that looks
like production is reported as waiting, as in `status`. The dry run is
always recorded. Installing needs no passphrase: an agent can make the
same change with the `project` commands one at a time. A replacement
cannot remove a mark or acknowledgement, which live in the store, and is
refused when it would move a project that has them.

`project draft` reads key names as `list --keys` does, for every secret
each usable profile lists (up to 200 per profile), so it reads more
secrets than the file it writes names; the same marks and production
rules apply, and nothing reaches the CLI but names. With `--apply` it then
installs as `project apply` does, but never replaces a project that
already claims the folder. An environment a deploy workflow lists for
production is drafted and installed too; it waits for a decision like any
environment that looks like production, and the keys of a secret that
looks like production are still not read.

`project facts` runs in the CLI, not the daemon, so it reads what the
caller can already read: it opens the checkout's real env files to see
which keys have a value, and drops the values in zeroing buffers without
showing them. It asks the daemon only for names (`ListSecrets`) and sends
nothing else anywhere.

The audit log records the caller's pid and uid. It cannot tell an agent
from a person; the pid can.

## Remote callers

The remote endpoint is off until you turn it on, which takes the
passphrase; see [config.md](config.md#the-remote-endpoint). Then:

- The daemon listens on this machine's tailnet address only, never on all
  interfaces, and never falls back to another address. Tailscale encrypts
  the connection and authenticates the peer.
- Each connection is identified by asking the local tailscaled who the
  peer is. A peer it cannot identify is refused, and so is this machine.
- A grant names a machine by its Tailscale node id, a project and its
  environments, and may end on a date. Grants live in the store, so adding
  or widening one takes the passphrase. No grant, no access.
- A grant has a token, and a request is answered only with both: the
  node Tailscale names and that grant's token. So a mistake in the
  tailnet, such as an ACL wider than meant or a node id handed to another
  machine, does not let a machine in by itself, and neither does a leaked
  token used from another machine. The token is random (256 bits), shown
  once when the grant is made or rotated, and the store keeps only its
  hash. It opens what its grant covers and nothing else: it is not the
  passphrase, and a remote caller cannot unlock, read the store or change
  a grant with it. A grant with no token lets nothing through.
- Requests are HTTP on the tailnet address: `POST` only, to one path,
  with a `Host` that names this machine's tailnet address or name. One
  that carries an `Origin`, as a browser's does, is refused, and no reply
  allows cross-origin reads, so a web page open on a granted machine
  cannot use the endpoint, and it has no token to send either.
- The grant, not a checkout, decides which project a machine gets. The
  git remotes it reports are its word only, so `--project` picks any
  project a grant of its names, from any folder, and no other.
- A remote caller may `run`, `status` and `diff`; never `get`, `unlock`,
  store writes, project edits or grants. A locked daemon refuses it, and
  its requests do not keep the daemon unlocked.
- A marked value goes through the same approval in the app here. The
  prompt names the machine and its user. Each machine has at most one
  prompt waiting.
- The audit log records the machine, its user and tags with each request
  it answers, never its token or the token's hash. What is refused before
  a request is read, such as a peer tailscaled cannot identify, a wrong
  `Host` or another build, goes only to the daemon's own log.

What it does not cover:

- The command line a remote caller shows is what it reported; nothing
  here can check it, and the prompt labels it that way. Approving trusts
  that machine to run what it said.
- Values sent to a remote command live on that machine, in its
  environment, as they would locally.
- Anyone who controls a granted machine has its token too, and is that
  machine as far as the daemon can tell. Your tailnet's admin can stand in
  for the machine but still needs its token.
- The token is kept by whoever runs kagebunshin on the other machine, in
  its environment. `run` does not pass it on to the command it starts,
  but anything else that reads that environment or its configuration
  reads the token.
- There is no TLS. Tailscale encrypts between the two machines, so
  nothing on the networks between them reads a request, a token or a
  value. Where the caller is not on the tailnet itself and reaches it
  through a proxy, the hop from the caller to that proxy is plain HTTP:
  whoever runs or can watch that hop sees the token and the values.
- Only IPv4 tailnet addresses are used. The endpoint ran between two
  Linux machines on a real tailnet before it moved to HTTP, and only in
  tests since; it has not been tested on macOS.

## The paired phone

A phone can approve a hand-out of marked values in place of the
passphrase typed in the app; see
[config.md](config.md#the-approval-page). That is a second way to show a
person is there, so this is what it rests on:

- **Which device.** The daemon serves the approval page on this
  machine's tailnet address only, and asks the local tailscaled who each
  connection is, on every request. Only the paired phone's node, and
  while a pairing lasts the node being paired, gets anything, the page
  itself included. A locked daemon serves nothing.
- **Which key.** Pairing starts on this machine with the passphrase and
  names one phone. For ten minutes that phone may make a passkey on the
  page; its public key and the phone's node id are then written to the
  store. Changing either takes the passphrase, like a grant.
- **Which request.** To approve, the page asks the daemon for a
  challenge: 32 random bytes made for one waiting request, good for two
  minutes and used once, spent even when the signature is wrong. The
  phone signs it with the passkey, and the daemon checks the signature
  with the paired key, and that what was signed names this challenge,
  the page's exact address (name and port) and a person verified by the
  phone. Nothing else the page sends is trusted.
- **What it approves.** Hand-outs only: a `run` or `get` of marked
  values. What writes the store or loosens anything (unlocking, imports,
  typed values, removing a mark, grants) takes the passphrase at this
  computer, and the phone has none. The paired phone can deny any
  request, with no proof, as closing the app's window does.
- **What is recorded.** Each answer from the phone and each pairing is in
  the audit log with the phone and its user as Tailscale names them. An
  approval counts only once it is recorded. A signature that does not
  hold is recorded as a denied `phone approve`.
- **Notifications.** A phone that allowed them is told of a request it
  can approve through its browser's push service. A notification
  approves nothing and answers nothing: it opens the page, which shows
  what the daemon says is waiting, and an approval is still the
  passkey's signature. The message is encrypted to the phone and signed
  with a key of this machine's that the phone subscribed to. The address
  to send to is the one thing the phone chooses and this machine then
  connects to, so only Apple's, Google's, Mozilla's and Microsoft's push
  services are taken, over HTTPS.
- **The browser.** A request must name the page's address as its `Host`,
  one that changes anything must come from the page itself (`Origin`,
  exactly), and no reply allows cross-origin reads, so another site open
  on the phone cannot use the page. The page loads and runs only what
  the daemon serves it.

What it does not cover:

- An approval on the phone takes no passphrase. Whoever holds the phone
  and can pass its check, your face, a fingerprint or the phone's code,
  approves hand-outs while the daemon is unlocked. They cannot unlock it,
  and they get no value: the values go to the command on this machine.
- What "verified" means is the phone's word. The passkey is made with no
  attestation, so the daemon does not know what holds it: the phone's own
  passwords app asks for your face each time, and a password manager that
  holds passkeys decides for itself what it asks. Check that yours asks.
- A passkey that syncs is on your other devices too, and with whoever
  holds that account. It is refused from any device but the paired one,
  which Tailscale vouches for; someone with both a copy of the passkey
  and control of your tailnet is the phone as far as the daemon can tell.
  The signature counter is not checked: a synced passkey does not count.
- The page's HTTPS shows nothing about who serves it. The certificate is
  tailscaled's, which gives it and its key to any process of a user it
  trusts, so a local agent running as you may have them. A page it serves
  under this machine's name on another port gets signatures that name
  that address, which the daemon refuses, and it cannot reach the real
  page as the phone: the daemon sees this machine asking. It can take
  the page's port before the daemon does, which `status` and the app
  say, or move `[phone] port`, and the phone then finds no page where it
  was.
- While a pairing lasts, the daemon keeps the passphrase in memory to
  write the store once the phone has made its key: for at most ten
  minutes, less when the app's Phone view is left, the pairing is stopped
  or the daemon locks.
- The page shows the phone what the app shows: project, environment and
  key names, the command line and who asks, for what waits and for the
  last ten answers. Anyone holding the unlocked phone on your tailnet
  reads them.
- A notification shows on the phone's lock screen what the page's title
  says and the program's name: project, environment, and for a remote
  request the machine. The push service cannot read it, but learns that
  this machine sent that phone a message, when, and how long it was.
- What notifying takes is outside the store, in `push.json`, for this
  user alone to read: the phone gives it when nobody is there to type
  the passphrase. A local process running as you can read it and send
  that phone notifications in this machine's name, or rewrite it so that
  this machine's go elsewhere or nowhere. It gains no approval by
  either. With notifications on, a request waits for the phone while the
  app is closed, for `approval_timeout` at most, where it was refused at
  once before.
- Any app on the paired phone that reaches the page reads what it shows
  and can deny a request or change where notifications go, as the phone;
  it cannot approve without the passkey.
- Tailscale's HTTPS puts this machine's tailnet name in the public
  certificate logs.
- This build of the page has run only in tests and a desktop browser
  with a software passkey, where a notification sent through Google's
  push service arrived. An earlier prototype of the same design approved
  requests from a real iPhone and notified it through Apple's.

## Known limitations

- Values are kept in locked, dump-excluded memory where kagebunshin
  controls the buffer, but some copies are out of its hands (AWS SDK,
  `serde_json`, `age` and `execve` buffers), and values fall back to
  ordinary memory when `RLIMIT_MEMLOCK` runs out unless `strict_memory` is
  set. See [memory.md](memory.md).

- The daemon runs as the same user as a local agent, and the project files
  are plain files that user owns. Marks are not in them, but an agent can
  edit `projects/<name>.toml` directly, for example to point an
  environment that is not marked at a new source. Marking an environment
  also marks the origins of its sources, so copying them elsewhere still
  hits the mark; a secret the marks never named does not. Nor does a
  secret that an open environment read too when the mark was made: it is
  left unmarked, unless its name looks like production or you ticked it,
  so it can be read through that environment or copied on from it. An
  agent can make a secret shared that way before you mark, by adding it to
  an open environment; the app lists what is shared before it takes the
  passphrase, which is where to catch it. For `file` and
  Proton sources, that covers only the store keys and Proton items they
  read when the environment was marked: one added later is not covered
  until you mark it, or the environment again. Closing all of this needs
  config the agent cannot write, such as another user or a signed config.
- Some decoded secret bytes are freed without being zeroed. serde_json's
  decode buffer for a Secrets Manager JSON secret is not zeroed. Neither is
  the age crate's decryption buffer for the store (`age` 0.11
  `primitives/stream.rs:204`). The copies kagebunshin owns are zeroed.

- Removing values from TOML parse errors depends on serde's current error wording (`invalid type: …, expected …`, `unknown variant …`); if serde rewords those messages, a value from a config or project file could appear in an error.

- `run` hands values to a process; from there they are ordinary
  environment variables. The process, its children, and any same-user
  process that can read its `/proc/<pid>/environ` (or `ps eww` on macOS)
  can see them.
- Masking covers only the piped stdout and stderr of `run`. Output to a
  terminal is not masked, values shorter than `masking.min_len` are not
  masked, and an encoded, split or transformed value (base64, hex, a
  substring) gets through.
- A plain setting (`[envs.<env>.vars]`, `project set-var`) is not a
  secret: anyone, an agent too, can write it, `status` shows it, and `run`
  injects it unmasked. It never wins over a source that sets the same key,
  so it cannot replace a secret, but a secret put in one by mistake is
  plain text in the project file and in output. The audit log records the
  edit, and lists the key among a recorded `run`'s keys like any other;
  never its value.
- Removing a mark is confirmed in the app's window before the passphrase is
  asked for. The confirmation proves nothing, since a same-user process can
  drive the window; it guards against slips. The passphrase is the check.
- A value revealed in the app is drawn on screen like any text, and stays
  in the window's memory until it is hidden. A screen recorder or a process
  that reads the app's memory can see it. Hiding the window to the tray
  clears revealed values and a typed passphrase.
- A same-user process can ask the running app to show its window or to
  quit, over a socket in the daemon's private folder. Neither hands out
  anything: with the app gone, requests for marked values are refused.
- The audit log is a plain file the user owns, written by the daemon and
  the CLI. A same-user process can edit or delete it, and edits made to
  project files directly, without the CLI, are not recorded. The program
  name recorded for a `run` is what the caller sent. A successful local
  `run` of values that are not marked is recorded in `runs.jsonl` beside
  it instead, and goes ahead when that file cannot be written: it is a
  record of use, not a control. Not recorded: the connection's own
  `hello`, `ping` and `whoami`; remote connections refused before a
  request (see Remote callers); and locks from the idle timeout.
- The daemon as a service runs with the service manager's environment, not
  your shell's; see [config.md](config.md#the-daemon-as-a-service).
