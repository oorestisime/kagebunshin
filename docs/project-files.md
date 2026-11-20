# Project files

Each project has one mapping file, `projects/<name>.toml`, in the config
directory (`$KAGEBUNSHIN_CONFIG_DIR`, else `$XDG_CONFIG_HOME/kagebunshin`,
else `~/.config/kagebunshin`). It holds names, never secret values; the
only values in it are plain settings that are not secret (see below).

You don't have to write it by hand. These commands write it, keeping
comments, and check the result loads before replacing the file:

    kagebunshin project init <name> [--remote URL]... [--env ENV] [--profile P] [--path DIR]
    kagebunshin project add-env <project> <env> [--profile P]
    kagebunshin project add-source <project> <env> --provider aws_sm|file|proton
        [--prefix P | --secret NAME... | --secret NAME --key KEY] [--profile P] [--region R] [--optional]
    kagebunshin project set <project> --profile P            # with --env ENV, that environment's
    kagebunshin project set-source <project> <env> <N>|--all [--profile P] [--region R]
    kagebunshin project remove-source <project> <env> <N>    # N from 1, as `show` lists them
    kagebunshin project move-source <project> <env> <N> --to <M>
    kagebunshin project dedupe <project> <env>               # drop exact duplicate sources
    kagebunshin project set-var <project> <env> <KEY> <VALUE>  # a plain setting, not a secret
    kagebunshin project unset-var <project> <env> <KEY>
    kagebunshin project show <project>
    kagebunshin project list                                 # every project, its folder, envs, providers
    kagebunshin project remove <project>                     # delete its file; store keys stay
    kagebunshin project facts [--path DIR]                   # what the checkout says, names only
    kagebunshin project apply FILE [--name NAME] [--check]   # check a whole file, then install it
    kagebunshin project draft [--path DIR] [--name NAME] [-o FILE] [--apply]  # draft one from the checkout
    kagebunshin list [--provider aws_sm|file|proton] [--prefix P] [--keys] [--profile P] [--region R]
    kagebunshin search <TEXT> [--provider ...] [--keys]     # names and keys, never values
    kagebunshin connect aws [--profile P] [--region R]   # the default AWS profile, checked
    kagebunshin connect proton [--expires YYYY-MM-DD]    # a Proton Pass token, checked and saved

`project init` takes the git remotes of the checkout it runs in unless
`--remote` is given. The first `add-source` replaces an environment's
default source. `--secret` given more than once writes one `secrets`
list, read in order; `--key` takes exactly one. `set-source` changes the
profile or region of `aws_sm` sources only, and like `add-source` says
when the result looks like production. `project remove` is refused while
an environment of the project is marked sensitive or acknowledged as not
production, or while the daemon is locked or stopped and so cannot say;
it drops the values the daemon cached for the project and leaves its
values in the local store, naming their sections and the command that
removes them: `kagebunshin store clear <project>`, which asks for the
passphrase and is refused while the project is still there
(`kagebunshin store unset <project>.<env> KEY` removes one key). `project init` in a folder whose `.env` has values notes that
`kagebunshin onboard` can move them in, which fills a project
that claims the checkout when the environment reads only the local
store's empty `[<project>.<env>]`. `kagebunshin onboard DIR…` takes
several checkouts with one passphrase prompt: each app with an env file
holding values gets a new project reading the store, with the values
moved in; each other app is drafted and installed as `project draft
--apply` does; an app a project already claims is left alone, and so is
one `--exclude APP` names, by its folder or its project's name, which
stays left out until `onboard` is given its own folder. The apps and what
is done for each are listed before the passphrase is asked for. It ends
with each project's state as `kagebunshin next` sees it (ready, needs
your agent, needs you) and the line to paste into the agent; `--name`
names the project when one folder is given. Run with no terminal, as an
agent runs it, the passphrase is typed in the app instead, whose window
lists what is imported; see [agents.md](agents.md#start-your-checkouts). An app's env file is one
named `.env` or `.env.<something>`; the other files with values in the
checkout (names ending `.env`, `.dev.vars`, and an app's env files after
its first) are named at the end, each with the command that imports it.
`kagebunshin onboard --file PATH… --env ENV` imports such a file into
the local store's `[<project>.<env>]` for the project of the app the file
is in (`--name` says which when it is in none): a new project when no
project claims the app, a new environment when the project has none of
that name, and otherwise over what the section holds, saying which keys
it replaced. It is refused when the environment exists and does not read
its own section. `kagebunshin init --agent` prints
instructions that teach a coding agent to use these (`--skill` for an
OpenCode skill file).

`list` shows the keys of local-store sections and Proton keys, which are
known without reading a value. An AWS secret's keys are inside its value,
so `list --keys` has the daemon read each AWS secret listed, keep only its
key names (or note that it is a plain string, not a JSON object), and drop
the value; the audit log records the lookup with the secrets read. Secrets
marked sensitive, and those whose name or AWS profile looks like
production, are listed without their keys and with why; while the daemon
is locked none are read. `search` matches key names too, AWS ones only
with `--keys`, which reads every AWS secret under the prefix.

`kagebunshin project facts [--path DIR]` prints what the checkout says,
names only (`--json` too): its apps (the root and folders up to four
levels down with a `.env.example` or a real env file; dependency, build
and hidden folders are skipped),
the keys of each `.env.example` and env file and whether each has a value
(never the value), the projects that claim the checkout, the providers
connected, which AWS profiles can list secrets now (a profile that looks
like production is not asked), and which of the secret names those
profiles list appear, whole and letter for letter, in the files git
tracks (real env files, binary files and files over 256 KiB are skipped;
at most 2000 files and 500 names, with a note when a cap is hit), in the
order the checkout first names them. Of those names it also gives the
lists in the workflows under `.github/workflows`: what a deploy loads, in
its order. No YAML is parsed. A list is the names found whole on one line
and the lines right after it: a comma-separated variable, an action's
input lines, a YAML sequence, or `--secret-id` commands one after the
other. A blank line, a line naming none, a new `key:` or a new job ends
it. Each list comes with its file and line, the environment it is for
when the workflow says so (an environment word such as `dev`, `rc` or
`prod` in the file name, the job's `environment:`, the job id, the
workflow's `name:`, or the one such word among the names' own segments),
and the workflow's first `working-directory`. Only `.env.example` is read
as an example; `.env.sample` and the like count as real env files. Listing
names fetches no value.

`kagebunshin project apply FILE [--name NAME] [--check]` installs a whole
project file in one step, or nothing. It loads the file as `import` does
(the name is the file's, unless `--name`), then has the daemon resolve
every environment in a dry run: the values are read, compared and
dropped, and nothing is cached or installed. It reports, per environment,
names and origins only: the keys set and where from, the keys of
`.env.example` that are missing (with a `project set-var` command when the
example gives a value) and those set but not in it, keys two sources set
and which wins, skipped secrets, and whether it looks like
production, in which case its values wait for a human once installed. An
environment marked sensitive in the store is not read. `--check` stops
there. Without it, a file whose every environment resolves is installed;
missing keys do not stop it, a source that is not optional failing does.
A project of the same name, or one claiming the same remote and folder,
is replaced, and what changes is listed source by source. Marks and
acknowledgements live in the store, so a replacement keeps them; for a
project that has any, a replacement that renames it, changes the remotes
or folder it claims, or drops a decided environment is refused, as is one
that drops a `sensitive` flag the old file has (flags reach the store only
at the next unlock). Values cached for the old file are dropped.

`kagebunshin project draft [--path DIR] [--name NAME] [-o FILE] [--apply]`
writes a project file for the app at `DIR` (default: the working
directory) from its facts and the key names `list --keys` gives for the
secrets each usable AWS profile lists. The name is the checkout folder's,
`<checkout>-<app folder>` for an app below the root.

An environment whose secrets a workflow lists is drafted as the workflow
has it: the same secrets, in the same order, since a later source wins a
key two hold. A workflow is the app's when its `working-directory` is in
the app's folder (the deepest app wins); one that names no folder is the
only app's, or the root app's. Each environment a workflow names becomes
one `[envs.<name>]`, also one that looks like production, which then waits
for a decision as any such environment does. When several lists are for
one environment the longest is taken, and a list naming a secret it lacks
becomes an open point. A list that names no environment counts for the
default one. A listed secret that is a plain string becomes a source only
when its name says which key it holds; one the profile does not list is an
open point. Keys of `.env.example` the listed secrets do not hold are
offered from the profile's other secrets as open points, not added. A
secret the checkout names that no workflow loads is written as a
`# found and unused:` comment and not added.

The default environment with no list is drafted by key names, and the
file says its order is a guess. The sources are, in this order of choice:

- the secrets the checkout's tracked files name that hold a key of
  `.env.example` (all of them when the example has no keys), in the order
  the checkout first names them;
- then, one at a time, the secret holding the most keys still not covered,
  unless another secret holds as many of the same keys: such a tie is
  left open;
- then a plain-string secret for a key, only when its last name segment,
  upper-cased with `-` and `.` as `_`, is exactly that key (`acme/dev/stripe-key`
  for `STRIPE_KEY`) and no other plain string looks like the same key.

Secrets under one prefix become a `prefix` source when there are at least
two and every secret under it was chosen. In a guessed order a secret
that looks like production, or whose keys were not read, is never chosen;
the ones the checkout names are listed as `# left out:` comments. What the draft
cannot decide is written under the environment as `# open:` comments, each
followed by the commands that settle it, those only a human can run marked
`(human)`: a tie, AWS profiles that each fit, a key `.env.example` gives a
value (`project set-var`), keys nothing holds (a `file` source and
`store set`). An app with an env file holding values
and nothing else to go on gets no draft: `kagebunshin onboard` imports it
there instead, with a person's approval. The file goes to stdout (or `-o FILE`), and a report to
stderr. `--apply` installs it as `project apply` does, one project per app
when the checkout has several and no `--path` is given; it refuses an app
that a project already claims, and names the `project draft -o FILE` and
`project apply FILE` commands that replace it on purpose. An environment
other than the default one that a workflow gave is installed even when it
cannot be read now; `status` then says why.

An environment whose names look like production waits for a human decision
(see below).

```toml
schema = 1
remotes = ["git@github.com:acme/widget.git"]
profile = "widget-dev"          # AWS profile for aws_sm sources (optional)

# No sources: the default provider's convention. With the default
# `default_provider = "file"` that is the local store's [widget.dev] section,
# read as empty until something is stored there.
[envs.dev]

[envs.qa]
profile = "widget-qa"           # over the project's, for this env's aws_sm sources

# Sources apply in order; a later source wins for a key both set.
[[envs.qa.sources]]
provider = "file"               # bare: the local store's [widget.qa] section

[[envs.qa.sources]]
provider = "aws_sm"
prefix = "widget/qa/"           # profile widget-qa, region from the AWS config

[[envs.qa.sources]]
provider = "aws_sm"
secret = "platform/qa/shared"   # a JSON object; its fields become keys
profile = "platform"            # this source only
region = "eu-west-3"

[[envs.qa.sources]]
provider = "aws_sm"
secret = "widget/qa/stripe"
key = "STRIPE_SECRET_KEY"       # the whole string is this one key
optional = true                 # a failure is a warning, not an error

# Plain settings, not secrets: the lowest layer (see below).
[envs.qa.vars]
PORT = "3000"
LOG_LEVEL = "info"

[envs.staging]
```

A project file holds no sensitive marks; a flag in it only adds one to the
store (see below).

## One project per app

In a repository with several apps, give each its own project with
`path`, the app's folder relative to the repository root:

```toml
# projects/acme-api.toml
schema = 1
remotes = ["git@github.com:acme/monorepo.git"]
path = "apps/api"

# projects/acme-web.toml
schema = 1
remotes = ["git@github.com:acme/monorepo.git"]
path = "apps/web"
```

`project init acme-api --path apps/api` writes it. `--path` is relative to
the current folder and must be an existing folder inside the checkout,
not its root.

The project for a folder is picked among those that claim one of the
checkout's remotes (any remote, so a fork with `origin` and `upstream`
works through either): the one whose `path` is the longest that contains
the folder, compared folder by folder after resolving symlinks, so
`apps/api` does not contain `apps/api-v2`. A project without `path`
covers the whole repository and answers where no `path` does, with a
warning when projects with a `path` exist, since a mistyped `path` would
otherwise fall back to it unnoticed. Two projects tied for the folder are
an error, and so is `path = ""`. The CLI, the daemon and the app all pick
the project the same way.

`--project NAME`, on every command but `project`, picks a project by name
instead, for example to run an app's command from the repository root;
it must still claim the checkout's remotes. `project list` shows which
folder each project covers.

Without `env_example`, the nearest `.env.example` is looked for from the
current folder up to the project's `path`, not above it, so one app never
picks up another's. From outside the `path` (with `--project`), only the
`path` itself is looked in.

### An app with no `.env.example`

`run` then passes every key the environment sets, with a warning, and a
request that needs approval is for all of them. `kagebunshin project
example` (`--path DIR` for another folder) writes the file from the names
the app's code reads. It goes in the project's folder: its `path`, else
the checkout's root. The files searched are those git tracks or would, in
that folder and not in another app's below it (a folder another project
has as its `path`, or one with a `.env.example` or an env file of its
own). Nothing is run, no env file is opened, and folders of
dependencies and build output are skipped. It finds:

- JavaScript and TypeScript, and Svelte, Vue and Astro files: `env.KEY`,
  `env["KEY"]` and `env.get("KEY")` on anything called `env`
  (`process.env`, `import.meta.env`, `Bun.env`, `Deno.env`, a Worker's
  `env`), `const { KEY } = process.env`, and the property names of a typed
  env module, a file called `env.*`. Only names in capitals.
- Python: `os.environ["KEY"]`, `os.environ.get("KEY")`, `os.getenv("KEY")`.
- Rust: `env::var("KEY")`, `env::var_os("KEY")`, `env!("KEY")`,
  `option_env!("KEY")`.
- A Wrangler config: the names of `secrets.required`. Its `vars` and its
  bindings are left out, as the config gives a Worker those itself.

Names the operating system, the toolchain or the host sets (`PATH`,
`NODE_ENV`, `CI`, `VERCEL_URL`, Vite's `DEV` and `MODE`, and the like) are
left out. A key read through a variable, a settings class or another
language is not found, and a name in a comment is: check the file against
the code. It is written once, as `NAME=` lines with no values, and is then
an ordinary `.env.example` to edit and commit. With no key found, or a
file already there, nothing is written.

### Splitting a project

Splitting one project into one per app keeps every **secret** mark (on an
AWS secret or a Proton key): those are keyed by the secret itself, so they
apply to any project that reads it. It does not carry over what is keyed
by project name: an **environment** mark (`<project>.<env>`), an
environment acknowledged as not production, and the local store's
`[<project>.<env>]` sections and the marks on their keys. Mark the new
projects' environments again in the app, and set the store keys again
under the new sections with `kagebunshin store set` (and mark them again),
before deleting the old project.

## Sources

A source sets exactly one of `secret`, `secrets` (a list) or `prefix`. A
`file` source may set none of them and then reads its env's
`[<project>.<env>]` section. `key` works only with `secret`.

An environment's own `[<project>.<env>]` section reads as empty while it
does not exist in the store yet, whether a `file` source reads it or the
environment has no sources under `default_provider = "file"`. So a project
can be checked before anything is stored: `status` and `diff` list the keys
`.env.example` names, and the command that fills them in, for a human:

```text
missing (in .env.example, set by no source):
  API_KEY
  DB_PASSWORD
to fill in what is missing:
  ask the human:
    kagebunshin store set widget.dev API_KEY DB_PASSWORD
      (it asks for the store passphrase, then each value)
```

`store set` with several keys asks for each value in turn, or reads one
value per line of stdin. Run with no terminal, as an agent runs it, it
asks for them in the app instead (see [agents.md](agents.md)). A `file` source that is written out in the
project file still needs its section: a missing one is an error.

An `aws_sm` secret without `key` must be a JSON object. Under a `prefix`,
one that is not is skipped with a warning, so a mixed prefix still reads
the rest; `status` and `diff` name it (`skipped` in `--json`) and the
command that adds it as one key, such as
`kagebunshin project add-source widget dev --provider aws_sm --secret
widget/dev/token --key NAME`. A key of `.env.example` it would have set
stays missing, so `run --strict` fails on it. Once another source reads
that secret by name, the prefix no longer reports it. A secret named on
its own, without `key`, that is not a JSON object is an error.

A secret under a `prefix` that is binary, or that the login may not read,
is skipped with a warning too, and the rest is read; a prefix none of whose
secrets the login may read is an error. Named on its own, either is an
error, as is a secret marked for deletion or a profile that is not in your
AWS configuration; each says what to run.

## Plain settings

`[envs.<env>.vars]` holds settings that are not secret, as strings:
`PORT = "3000"`. `project set-var` and `unset-var` write them; no
passphrase is needed, and an agent may run them. They are the lowest
layer: a key that any source sets, readable or not, takes the source's
value, so a plain setting never shadows a secret. `run` injects them like
any other key but does not mask their values in the command's output;
`status` shows each one with origin `project file` and its value. A key
of `.env.example` set only by a plain setting is not missing. They are
read from the project file on every request, so an edit needs no `sync`.

A plain setting is never sensitive and marks nothing sensitive. Do not put
a secret in one: the project file is plain text, and the value is shown
and left unmasked.

When a key of `.env.example` is missing and the example gives it a value
on one line,
`status` and `diff` (not with `--remote`) suggest the command, for example
`kagebunshin project set-var widget dev PORT 3000`. The example's value is
never used by itself: it is often a placeholder such as `changeme`, and
using one would hide a missing secret.

## AWS profile and region

`profile` and `region` are allowed only on `aws_sm` sources (and `profile`
also at project and env level, where it only affects `aws_sm` sources).

- Profile: the source's own, else the env's, else the project's, else the
  one `kagebunshin connect aws` saved as `[aws]` in `config.toml`. A source
  with a profile uses only that profile's credentials (static keys, SSO,
  assumed roles); `AWS_ACCESS_KEY_ID` and other ambient credentials are
  ignored for it. With none set, the ambient AWS configuration is used
  (`AWS_PROFILE`, the default profile, environment credentials).
- Region: the source's own, else `[aws]`'s, else whatever the AWS
  configuration chain picks for that profile (`AWS_REGION`, then the
  profile's `region`).

`kagebunshin connect aws` lists the profiles in your AWS configuration and
asks which one to use (or takes `--profile`), runs `aws login --profile P`
(`aws sso login` for an SSO profile) when its credentials are missing or
expired, checks that it can list secrets, and only then writes:

```toml
[aws]
profile = "widget-dev"
region = "eu-west-1"            # only with --region
```

Without a terminal it never asks or logs in: it fails with the command to
run instead.

Every AWS source gets a client for its own profile and region, so one env can
read from several accounts and one daemon can serve several profiles at once.
When credentials are missing or expired the error names the source with its
profile and region, and the hint names each failing profile once (``run `aws
sso login --profile platform` ``), or says the ambient/default credentials
failed when the source has no profile.

## Proton Pass

A `proton` source reads Proton Pass "API key" items: custom items with a
field named `API key`, which holds the environment variable name, and one
named `Secret`, which holds the value. The item title is free text. Other
item types, and custom items without both fields, are ignored. A key is
named `<vault>/<KEY>`:

```toml
[[envs.dev.sources]]
provider = "proton"
prefix = "widget/"              # every API key in the vault widget

[[envs.dev.sources]]
provider = "proton"
secret = "global/OPENAI_KEY"    # one key from the shared vault global
key = "OPENAI_API_KEY"          # optional: under another name
```

Keys in the `global` vault belong to no project, so a prefix never picks
them up and `prefix = "global/"` does not load: add each with its own
`secret`.

`kagebunshin connect proton` saves a Proton Pass personal access token in
the local store, after checking that `pass-cli` logs in with it. The token
comes from `$KAGEBUNSHIN_PROTON_TOKEN`, else stdin when it is not a
terminal, else a hidden prompt; never an argument. The store passphrase is
asked at the terminal, as for every store write. `--expires` records when
the token expires, as Proton shows it: from 14 days before, while the
daemon is unlocked, `status` warns and the app shows a banner.

kagebunshin runs Proton's own `pass-cli` (`$KAGEBUNSHIN_PASS_CLI`, else the
one on `PATH`; it is not bundled, and `connect proton` offers Proton's
installer when it is missing). It runs with its own session in
`$XDG_DATA_HOME/kagebunshin/proton` (else
`~/.local/share/kagebunshin/proton`), never your own `pass-cli` login, and
with `PROTON_PASS_KEY_PROVIDER` as you set it, else `fs`. The token reaches
`pass-cli` only in its environment, when logging in. Sessions last two
hours; a call that fails on an expired session logs in again and is
retried once.

Reading Proton takes one `pass-cli` call for the vaults and one for each
vault, which lists its items with their content; each call is a round
trip to Proton, so the first read of an environment takes a second or
two. A session that may not list items with their content, as an
agent's may not, views each item instead, a call for each. An
environment reads the account once, however many Proton sources it has. What it read stays
cached until the daemon locks, `kagebunshin sync` runs, a secret is
marked or unmarked, or another token is connected; storing a value in
the local store does not make a Proton or AWS environment read again.

## Sensitive environments and secrets

What is refused is decided by explicit marks. Every mark lives in the
encrypted local store, not in project files, so changing one takes the
store's passphrase, and an agent that can write project files cannot
unmark anything.

Marks are set and removed in the app (`kagebunshin app`); removing one is
confirmed in the window too, and several secrets can be unmarked at once,
with one passphrase. A mark can also be added from the command
line, with no passphrase, so an agent can mark what is production:

```sh
kagebunshin mark env widget prod            # the environment, as the app marks it
kagebunshin mark secret aws_sm acme/prod/db # one secret, wherever it is read
kagebunshin mark key widget.dev STRIPE_KEY  # one key of the local store
```

Such a mark holds at once and is in the audit log with who asked. No
command removes a mark or acknowledges an environment as not production,
and a mark added this way never goes against a decision made with the
passphrase: marking an environment acknowledged as not production is
refused. The store file cannot be written
without the passphrase, so until the next unlock or change in the app the
mark waits in a list of names beside it, `<store>.marks`; see
[threat-model.md](threat-model.md#sensitive-values).

- **An environment** (`<project>.<env>`). The daemon refuses it before
  reading any source. Marking it also marks what only it reads, so
  copying those sources into another environment or project still hits a
  mark: each AWS secret and prefix it names, and
  the Proton items and the keys of other store sections it reads at that
  moment. That last part is a snapshot: a Proton item or store key added
  later is not marked until you mark it, or the environment again. The
  environment's own section stays covered by its mark.

  A secret that an open environment reads too is **shared**, and stays
  unmarked: marking it would make that other environment ask for
  approval, which nobody decided. Open means neither marked sensitive nor
  waiting for a decision. The app lists the shared secrets before it takes
  the passphrase, and you can tick any of them to mark it all the same.
  Three things hold whatever is shared: a secret whose name looks like
  production (below) is marked with the environment; a mark
  that is there stays; and you can mark a shared secret later, on its
  own. What is shared is read from the project files, without asking a
  provider: a prefix is shared with an environment that reads the same
  prefix or a wider one, a secret named on its own with one that names it
  or reads a prefix over it. `kagebunshin status` and the app show which
  secrets of an environment are shared, and with what.
- **One secret,** of any provider but `file`. The mark is on the secret,
  not on a source, so it holds in every environment that reads it. An AWS
  secret named by full ARN is compared by its secret name, so a mark on
  `widget/qa/payroll` matches `secret =
  "arn:aws:secretsmanager:…:secret:widget/qa/payroll-AbCdEf"`. A Proton
  key is marked by its item, so the mark survives renaming its vault,
  and is shown by its `<vault>/<KEY>` all the same: in the app, in
  `status` and `diff`, in a refusal and in the audit log. `mark secret
  proton <vault>/<KEY>` asks Proton Pass which item that is, and refuses a
  name it does not have. In `--json` a Proton origin's `location` is the
  item's ids and its `name` the `<vault>/<KEY>`.
- **One local-store key.** A `file` secret is a store section, so its keys
  are marked one by one.

A secret is marked whole, as its provider grants access to it whole; to
keep one key of a JSON secret back, move it to its own secret. There is
no per-key list.

A project file can still add a mark, never remove one. `sensitive = true`
on an environment, or `sensitive = ["<secret>", …]` on an `aws_sm` source,
is copied into the store at the next unlock (an environment as marking it
in the app does, shared secrets left unmarked, though its Proton
sources are marked along with it only once you mark it there). From then on the store decides: deleting
the flag, or setting it `false`, changes nothing. Unlock fails if there is
no store to copy them into. A project file with `sensitive_keys` does not
load.

A key is sensitive when the value that wins for it comes from a marked
secret or store key. A marked value that a later source overrides does not
count, because it is not the one handed out. `run` and `get` hand out a
sensitive key only once you approve that one request in the app, where a
prompt names the keys, the command, the caller and why it asks, and takes
the store passphrase. `run` stays all or nothing: if any key it would inject is
sensitive, the whole command waits. Denied, not approved within five
minutes (`approval_timeout` in `config.toml`), or asked while the app is
not open, it is refused with exit 5; so is one still waiting when the app
closes. A [paired phone](config.md#the-approval-page) can approve it too,
and one that is notified keeps it waiting with the app closed. A refusal says how it ended and what was asked for.


### Production-like names wait for a human decision

An environment looks like production when its name, a name one of its
sources reads, or the AWS profile a source uses looks like production.
Secrets marked sensitive one by one are not counted. A secret's own name
outweighs its profile's: a source whose every name has a `dev`,
`development`, `local`, `qa`, `sandbox`, `stage`, `staging`, `test` or
`testing` segment, and does not itself look like production, is not
counted for its profile (`dev/aws` read with profile `acme-prod`). A name
looks like
production when any of its `/` or `.` segments is `prod`, `production` or
`rc`, ignoring case (`widget/prod`, `widget.prod.db`, `x/RC/y`), or when it
matches a `sensitive_source_patterns` glob in `config.toml`. An ARN is
checked by its secret name. `*` matches any run of characters, and a glob
must match the whole name, ignoring case.

`-`, `_`, `+` and `@` do not separate segments, so `widget-prod` does not
match the built-in rule. Add a pattern such as `"*-prod*"` if your names
look like that. Profile names are split on `-` and `_` as well, so
`acme-prod` and `prod_admin` match.

Until a human decides, such an environment is sensitive by rule: the
daemon treats it exactly as if it were marked, with no mark written.
`run` and `get` hand out its values only once a human approves that
request, in the app or on a paired phone, and are refused with exit 5
otherwise. The daemon
decides this when it resolves, so a project file written by hand is
treated the same. The human decides in the app, which lists every waiting
environment of every project, with the store passphrase:

- **Mark it sensitive.** Nothing changes for agents, and the wait ends:
  it is now a marked environment. This one needs no human: an environment
  named `prod` or `production` is no question, so `kagebunshin next` has
  the agent mark it with `kagebunshin mark env`, and the refusal names
  that command.
- **Acknowledge it is not production.** It becomes a normal environment
  that agents read freely. Several can be acknowledged at once, with one
  passphrase. This marks nothing, and unmarks nothing by itself: a secret
  it reads that is marked sensitive, because a marked environment reads it
  too, still asks for approval for its keys. The app lists those secrets
  before the passphrase, none ticked, and unmarks the ones you tick in the
  same write. An unmarked secret is read freely by every environment that
  reads it and is not marked itself.

Both are kept in the encrypted store, so an agent cannot make either
choice. Name matching has false positives: an environment called `rc`
that is only a test system still waits, and each such environment costs
one acknowledgement.

`status`, `diff`, `project show` and `project list` keep working on a
waiting environment and say that it waits and what the two choices are,
and so does `unlock`. `add-env`, `add-source` and `set-source` say so when
what they wrote looks like production, once per profile rather than once
per source.

### Duplicate sources

Two sources of one environment that read the same secret or prefix, with
the same provider, profile and region, are duplicates. `add-source` refuses
an exact copy of a source already there. `status` and `diff` warn about the
rest: exact copies point to `project dedupe`, which removes them without
changing what resolves; copies that differ only in `optional` point to
`project remove-source`.
